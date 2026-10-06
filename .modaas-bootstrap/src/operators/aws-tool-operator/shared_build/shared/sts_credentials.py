"""
Cross-account role assumption for Registry backings (a design note `roleArn`).

`crds/registry-v1beta1-crd.yaml:97` documents `roleArn` under a
`backing: agentcore` Registry's `spec.parameters` as "cross-account role for
Registry access", and `operators/shared/backings/agentcore.py` repeated it in
its docstring. Nothing implemented it: the backing read only `registryName` and
`region`, and no `assume_role` call existed anywhere in the backing or in
`registry_client.py`. A Registry CR declaring `roleArn` was silently served with
the operator's own IRSA identity — the write either failed with AccessDenied or,
worse, succeeded against the operator's *own* account's registry, which is a
wrong-catalog write wearing a cross-account costume.

This module supplies the missing leg, and only that leg:

  * `assume_role_credentials` — one `sts:AssumeRole` per validity window,
    cached until `Expiration` minus `EXPIRY_SKEW_SECONDS`.
  * `assumed_role_client` — a long-lived boto3 client built from those
    credentials, cached per (service, role, region, session name) and rebuilt
    only when the credentials behind it go stale.

Why an explicit cache rather than botocore's `RefreshableCredentials`: the two
layers would each hold their own staleness threshold (botocore's advisory
refresh fires at T-900s, ours at T-300s), so the outer cache would keep handing
back credentials the inner one had already decided to replace. One cache with
one threshold is both correct and directly testable.

Failures are NOT cached: a throttled or transiently-denied AssumeRole must not
pin an operator into a failing state until the next restart.

Dual-import note (team convention): this module is imported as
`operators.shared.sts_credentials` from the repo tree and as
`shared.sts_credentials` from the `shared_build/shared` pod snapshot. It imports
nothing from `operators.*` itself, so both spellings work unchanged.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

logger = logging.getLogger("modaas.sts_credentials")

DEFAULT_SESSION_NAME = "modaas-registry"

# Refresh this far ahead of the stated expiry. A registry write that starts
# inside the window must still be signable when it reaches AWS.
EXPIRY_SKEW_SECONDS = 300

# Used only when STS returns no Expiration (stubs, or an SDK shape change).
FALLBACK_TTL_SECONDS = 900

_CREDENTIAL_CACHE: dict[tuple, tuple[dict, datetime]] = {}
_CLIENT_CACHE: dict[tuple, tuple[Any, datetime]] = {}


class AssumeRoleFailed(Exception):
    """sts:AssumeRole failed. Carries the role ARN so the log names the target."""


def _utcnow() -> datetime:
    """Indirection so tests can freeze the clock without patching datetime."""
    return datetime.now(timezone.utc)


def _import_boto3():
    """Indirection so tests can inject a stub module."""
    import boto3  # noqa: PLC0415

    return boto3


def _default_sts_client(region: str):
    """Build an STS client with the operator's own (IRSA) identity."""
    return _import_boto3().client("sts", region_name=region)


def reset_caches() -> None:
    """Drop both caches. For tests, and for an operator that has been told its
    credentials are no longer valid."""
    _CREDENTIAL_CACHE.clear()
    _CLIENT_CACHE.clear()


def _is_fresh(expiry: datetime, now: datetime) -> bool:
    return expiry - now > timedelta(seconds=EXPIRY_SKEW_SECONDS)


def assume_role_credentials(
    role_arn: str,
    region: str,
    *,
    session_name: Optional[str] = None,
    sts_client=None,
) -> dict:
    """Return temporary credentials for `role_arn`, cached until near expiry.

    Returns a dict with AccessKeyId / SecretAccessKey / SessionToken /
    Expiration (a timezone-aware datetime).

    Raises AssumeRoleFailed — the caller decides whether that is fatal. The
    registry path surfaces it rather than falling back to its own identity,
    because an operator-identity write to a cross-account registry is a
    wrong-catalog write, not a degraded one.
    """
    session = session_name or DEFAULT_SESSION_NAME
    key = (role_arn, region, session)
    now = _utcnow()

    cached = _CREDENTIAL_CACHE.get(key)
    if cached is not None and _is_fresh(cached[1], now):
        return cached[0]

    client = sts_client if sts_client is not None else _default_sts_client(region)
    try:
        resp = client.assume_role(RoleArn=role_arn, RoleSessionName=session)
    except Exception as e:  # noqa: BLE001 — re-raised as a named domain error
        # Deliberately not cached: a throttle must not pin the operator.
        raise AssumeRoleFailed(
            f"sts:AssumeRole failed for {role_arn} in {region} "
            f"(session={session}): {type(e).__name__}: {e}"
        ) from e

    creds = dict(resp.get("Credentials") or {})
    expiry = creds.get("Expiration")
    if not isinstance(expiry, datetime):
        expiry = now + timedelta(seconds=FALLBACK_TTL_SECONDS)
        creds["Expiration"] = expiry
        logger.warning(
            "sts:AssumeRole for %s returned no Expiration; assuming %ss",
            role_arn, FALLBACK_TTL_SECONDS,
        )
    elif expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
        creds["Expiration"] = expiry

    _CREDENTIAL_CACHE[key] = (creds, expiry)
    logger.info(
        "Assumed %s in %s (session=%s, expires %s)",
        role_arn, region, session, expiry.isoformat(),
    )
    return creds


def assumed_role_client(
    service: str,
    role_arn: str,
    region: str,
    *,
    session_name: Optional[str] = None,
    sts_client=None,
    boto3_module=None,
):
    """Return a boto3 client for `service` signing as `role_arn`.

    The client is cached and reused while its credentials are fresh — a boto3
    client per reconcile leaks connection pools (the pattern this repo already
    fixed once for the registry control client), so the rebuild happens at
    credential expiry, not per call.
    """
    session = session_name or DEFAULT_SESSION_NAME
    key = (service, role_arn, region, session)
    now = _utcnow()

    cached = _CLIENT_CACHE.get(key)
    if cached is not None and _is_fresh(cached[1], now):
        return cached[0]

    creds = assume_role_credentials(
        role_arn, region, session_name=session, sts_client=sts_client,
    )
    boto3 = boto3_module if boto3_module is not None else _import_boto3()
    client = boto3.client(
        service,
        region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
    _CLIENT_CACHE[key] = (client, creds["Expiration"])
    return client
