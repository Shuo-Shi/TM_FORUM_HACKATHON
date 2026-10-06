"""C2 -- establish an attributable caller from a SigV4-signed request (LC-3).

## The ceiling, stated first because everything here follows from it

The signature CANNOT be recomputed. AWS's signing documentation derives the
signing key as HMAC-SHA256("AWS4" + SecretAccessKey, ...) and states "AWS then
replicates this process and verifies the signature". The secret is the caller's;
MoDaaS does not hold it, and holding it would defeat the purpose of a signing SDK.

So this module does not answer "is this signature valid". It answers "is this
request well-formed, fresh, and attributable" -- and SAYS WHICH of those it
managed, via the `verification` level. An unverifiable claim reported as verified
is the defect class this project rates below an honest refusal.

`ai-gateway-pod/sigv4_auth.py:14-19` reached the same conclusion and documents
it; this module ports that reasoning rather than overturning it.

## The replay bound this module does NOT close (AR-4a)

`x-amz-content-sha256` carries the hash of the body the caller signed, and no
rule here reads it. So inside the +/-5 minute window an adversary holding a
captured Authorization header can replay it AGAINST A SUBSTITUTED BODY -- a
different tool, different arguments -- and this module still reports
`account-resolved`.

That matters more here than it did in the incumbent: the incumbent's decision
did not depend on the body at all (a constant `action: invoke`), while authorize.py
promotes body content to policy input. Comparing the body hash would raise the
cost of a naive replay and close nothing against an adversary who can forge the
header, since the hash is an input to a signature nothing verifies.

The transport control this bound leans on is currently INERT: STATUS.md records
zero istio-proxy sidecars on these pods.

## What is deliberately absent: AR-4's scope check

SR-8 gates it on a right-hand side that does not exist -- ToolConfig declares no
`region` field, so a ToolConfig-backed asset has nothing to compare a
credential's scope against. `region` and `service` are parsed and carried
through, so nothing is lost when AR-4 lands.
"""
from __future__ import annotations

import datetime as _dt
import logging
import re
from dataclasses import dataclass
from enum import Enum

import config
from reasons import Reason, Refusal

log = logging.getLogger("authz-gateway.identity")

_ALGORITHM = "AWS4-HMAC-SHA256"
_REPLAY_WINDOW_S = 5 * 60          # AWS standard skew tolerance
_AMZ_DATE_FMT = "%Y%m%dT%H%M%SZ"

_CREDENTIAL_RE = re.compile(
    r"Credential=(?P<access_key>[A-Z0-9]{16,128})/"
    r"(?P<date>\d{8})/"
    r"(?P<region>[a-z0-9-]+)/"
    r"(?P<service>[a-z0-9-]+)/aws4_request"
)
_SIGNATURE_RE = re.compile(r"Signature=(?P<sig>[a-f0-9]{64})")
_SIGNED_HEADERS_RE = re.compile(r"SignedHeaders=(?P<sh>[a-zA-Z0-9;-]+)")


class Verification(str, Enum):
    """How strongly the caller was established.

    An enum rather than a string because a typo in a string comparison silently
    downgrades a policy check to always-false, which fails OPEN for a policy
    requiring the stronger level.

    Neither member is named `verified`. The GetAccessKeyInfo reference states the
    operation "does not indicate the state of the access key. The key might be
    active, inactive, or deleted. Active keys might not have permissions to
    perform an operation." So ACCOUNT_RESOLVED means an account was derived --
    not that the key is live or entitled.

    A third level cannot exist here: `cryptographic` would require recomputing
    the signature, which requires the caller's secret.
    """

    STRUCTURAL = "structural"
    ACCOUNT_RESOLVED = "account-resolved"
    # W4-B: a Keycloak RS256 JWT whose signature we verified against the
    # realm's JWKS. The docstring's "cryptographic cannot exist" reasoning was
    # SigV4-scoped (we lack the caller's secret); for OIDC we hold the public
    # key, so signature verification IS this level. SigV4 callers never carry
    # this value.
    CRYPTOGRAPHIC = "cryptographic"


@dataclass(frozen=True)
class Identity:
    """C2's output and C3's principal input."""

    principal_id: str          # aws:<accessKey> -- the audit primary key
    access_key: str
    region: str                # parsed and carried; NOT compared (AR-4 deferred)
    service: str
    signed_headers: tuple[str, ...]
    verification: Verification
    account: str | None = None
    degraded: bool = False     # STRUCTURAL because STS was unreachable, not
                               # because identity mode is off -- two states that
                               # otherwise read identically to a policy and an
                               # operator


def is_sigv4(authorization: str | None) -> bool:
    return bool(authorization) and authorization.startswith(_ALGORITHM)


def parse_authorization(authorization: str) -> dict[str, str | tuple[str, ...]]:
    """AR-2: all three components must parse, or refuse.

    Partial acceptance is how a forged header gets treated as a weak-but-present
    credential. There is no such state.
    """
    cred = _CREDENTIAL_RE.search(authorization)
    sig = _SIGNATURE_RE.search(authorization)
    sh = _SIGNED_HEADERS_RE.search(authorization)
    if not (cred and sig and sh):
        missing = [
            name
            for name, m in (("Credential", cred), ("Signature", sig), ("SignedHeaders", sh))
            if not m
        ]
        raise Refusal(Reason.SIGV4_MALFORMED, f"missing or malformed: {', '.join(missing)}")
    return {
        "access_key": cred.group("access_key"),
        "date": cred.group("date"),
        "region": cred.group("region"),
        "service": cred.group("service"),
        "signature": sig.group("sig"),
        "signed_headers": tuple(sh.group("sh").split(";")),
    }


def validate_timestamp(amz_date: str | None, now: _dt.datetime | None = None) -> None:
    """AR-3 -- the load-bearing check in this module.

    Since the signature cannot be recomputed, the timestamp is the ONLY thing
    between a captured header and indefinite replay. Removing it would leave a
    credential that never expires.
    """
    if not amz_date:
        raise Refusal(Reason.SIGV4_TIMESTAMP_MISSING, "x-amz-date absent")
    try:
        stamped = _dt.datetime.strptime(amz_date, _AMZ_DATE_FMT).replace(
            tzinfo=_dt.timezone.utc
        )
    except ValueError:
        raise Refusal(Reason.SIGV4_TIMESTAMP_MISSING, f"unparseable x-amz-date: {amz_date}")

    current = now or _dt.datetime.now(_dt.timezone.utc)
    skew = abs((current - stamped).total_seconds())
    if skew > _REPLAY_WINDOW_S:
        raise Refusal(
            Reason.SIGV4_TIMESTAMP_SKEW,
            f"x-amz-date is {skew:.0f}s from now, outside the "
            f"{_REPLAY_WINDOW_S}s replay window",
        )


def establish(
    authorization: str | None,
    amz_date: str | None,
    account_resolver=None,
    now: _dt.datetime | None = None,
) -> Identity:
    """Steps 1-4 are pure functions of the headers; step 5 is the only I/O.

    `account_resolver` is a callable returning `{"account": ...}`, None for a
    rejected key, or raising `_Unreachable` for an outage -- the AR-5 vs AR-6
    distinction. Injected so this module's tests need no AWS at all.

    NOTE: host is read from the `:authority` pseudo-header by the caller, not
    here, and it is used in no comparison (SR-2a): the hook rewrites a forwarded
    HOST into the authority and sets it from the caller's own Host, so the value
    is attacker-chosen.
    """
    base, access_key = _structural(authorization, amz_date, now=now)

    if account_resolver is None:
        return Identity(verification=Verification.STRUCTURAL, **base)  # type: ignore[arg-type]

    try:
        resolved = account_resolver(access_key)
    except _Unreachable:
        return _degraded(base)

    return _from_resolution(resolved, base, access_key)


async def establish_async(
    authorization: str | None,
    amz_date: str | None,
    account_resolver=None,
    now: _dt.datetime | None = None,
) -> Identity:
    """`establish` with an AWAITABLE resolver, for the async request path.

    Steps 1-4 are shared with the sync version verbatim -- the split is only
    around the single I/O call, so no rule can hold on one path and not the
    other. It exists because the sync resolver blocks the event loop, which made
    both concurrency knobs describe capacity nothing could reach (see
    sts_lookup.resolve_async for the measurement).
    """
    base, access_key = _structural(authorization, amz_date, now=now)

    if account_resolver is None:
        return Identity(verification=Verification.STRUCTURAL, **base)  # type: ignore[arg-type]

    try:
        resolved = await account_resolver(access_key)
    except _Unreachable:
        return _degraded(base)

    return _from_resolution(resolved, base, access_key)


def _reject_unverified_sigv4() -> bool:
    """Whether this deployment accepts an unverifiable SigV4 header as identity.

    Read from the module on every call, not imported by value: a value captured
    at import would make a deployment-time override invisible and every test of
    this rule pass against a setting production never read.

    ANYTHING other than the two documented values behaves as `reject`. `account`
    is the permissive setting, so a typo must not land there. It degrades one
    identity class rather than raising at import and crash-looping the pod over a
    misspelled env var -- JWT and API-key callers keep working either way.
    """
    mode = config.SIGV4_IDENTITY_MODE
    if mode == "account":
        return False
    if mode != "reject":
        log.error(
            "SIGV4_IDENTITY_MODE=%r is not 'account' or 'reject'; refusing SigV4 "
            "callers (a posture typo must not select the permissive setting)", mode,
        )
    return True


def _structural(
    authorization: str | None, amz_date: str | None, now: _dt.datetime | None = None
) -> tuple[dict, str]:
    """Steps 1-4: pure functions of the headers, no I/O. Shared by both paths."""
    if not is_sigv4(authorization):
        raise Refusal(Reason.NO_SIGV4_CREDENTIAL, "no AWS4-HMAC-SHA256 Authorization header")

    if _reject_unverified_sigv4():
        # Gated BEFORE parse and freshness, deliberately. In this mode no SigV4
        # header is accepted whatever its shape, so reporting SigV4Malformed for
        # a broken one would imply a well-formed one would have been accepted.
        # One mode, one reason. The cost: a genuinely malformed header no longer
        # gets the more specific diagnostic, which matters less than the refusal
        # naming its actual cause.
        raise Refusal(
            Reason.SIGV4_UNVERIFIED_IDENTITY_REJECTED,
            "SIGV4_IDENTITY_MODE=reject: this signature is not verified here "
            "(the signing key derives from the caller's secret, which MoDaaS does "
            "not hold), so SigV4 is not accepted as identity. Present a Keycloak "
            "JWT or an issued API key.",
        )

    parsed = parse_authorization(authorization)          # AR-2
    validate_timestamp(amz_date, now=now)                # AR-3
    # AR-4 (scope match) deliberately absent -- see the module docstring.

    access_key = str(parsed["access_key"])
    return (
        dict(
            principal_id=f"aws:{access_key}",
            access_key=access_key,
            region=str(parsed["region"]),
            service=str(parsed["service"]),
            signed_headers=parsed["signed_headers"],
        ),
        access_key,
    )


def _degraded(base: dict) -> Identity:
    """AR-6: an outage is NOT an answer about the caller. Degrade the level and
    continue to authorization, where policy still runs. This is not fail-open --
    no allow decision is made here, and a policy requiring ACCOUNT_RESOLVED
    denies it."""
    return Identity(
        verification=Verification.STRUCTURAL,
        degraded=True,
        **base,  # type: ignore[arg-type]
    )


def _from_resolution(resolved, base: dict, access_key: str) -> Identity:
    if not resolved:
        # AR-5: a rejection IS an answer about the caller.
        raise Refusal(Reason.SIGV4_UNKNOWN_PRINCIPAL, f"STS rejected {access_key}")

    return Identity(
        verification=Verification.ACCOUNT_RESOLVED,
        account=resolved.get("account"),
        **base,  # type: ignore[arg-type]
    )


class _Unreachable(Exception):
    """The resolver could not reach STS -- no answer either way. Distinct from
    returning None, which is a negative answer about the caller."""
