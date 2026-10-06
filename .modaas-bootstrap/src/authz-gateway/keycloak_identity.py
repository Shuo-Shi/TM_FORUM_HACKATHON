"""W4-B -- Keycloak-JWT caller identity for the ext_authz doorman (a design note).

One principal namespace shared with SigV4 and the API-key bootstrap tier:
    ServiceIdentity::"<azp claim, verbatim>"   (fallback: sub)

Design constraints encoded here, all coordinator-verified live 2026-09-02:
- The odari realm's issuer claim mirrors the requesting host, so the expected
  issuer comes ONLY from MODAAS_OIDC_ISSUER. Never derived, never defaulted to
  a guessable value.
- JWKS is fetched from MODAAS_OIDC_JWKS_URL, cached with a TTL: identity
  checks must not add a Keycloak round-trip per request.
- No network at import time (kopf/uvicorn workers import this module).
- Keycloak being DOWN is JwksUnavailable (the caller may be fine; we cannot
  know -- FailClosed at the app layer with a distinct reason), never conflated
  with an INVALID token (JwtRefusal: the caller is wrong).
"""
from __future__ import annotations

import logging
import os
import threading
import time as _time

import jwt as _pyjwt
from jwt import PyJWKClient  # noqa: F401  (import check; we hand-roll caching)

from identity import Identity, Verification

log = logging.getLogger("authz.keycloak")

_LEEWAY_S = 60
_JWKS_TTL_S = 300

BOOTSTRAP_PRINCIPAL = 'ServiceIdentity::"bootstrap-key"'


class JwtRefusal(Exception):
    """The token is present and WRONG (expired, bad issuer, bad signature)."""


class JwksUnavailable(Exception):
    """Keycloak's JWKS could not be fetched; token validity is UNKNOWN."""


# ── JWKS cache: module-level, TTL'd, lock-guarded ─────────────────────────
_jwks_lock = threading.Lock()
_jwks_state: dict = {"fetched_at": 0.0, "keys": None, "url": None}


def _jwks_cache_clear() -> None:
    with _jwks_lock:
        _jwks_state.update(fetched_at=0.0, keys=None, url=None)


def _fetch_jwks(url: str) -> dict:
    """Isolated for tests. httpx is already a service dependency."""
    import httpx

    resp = httpx.get(url, timeout=3.0)
    resp.raise_for_status()
    return resp.json()


def _jwks(url: str) -> dict:
    now = _time.monotonic()
    with _jwks_lock:
        fresh = (
            _jwks_state["keys"] is not None
            and _jwks_state["url"] == url
            and now - _jwks_state["fetched_at"] < _JWKS_TTL_S
        )
        if fresh:
            return _jwks_state["keys"]
    try:
        keys = _fetch_jwks(url)
    except Exception as exc:  # noqa: BLE001 -- ANY fetch failure is "unavailable"
        raise JwksUnavailable(f"JWKS fetch failed: {exc}") from exc
    with _jwks_lock:
        _jwks_state.update(fetched_at=now, keys=keys, url=url)
    return keys


# ── dispatch predicate ────────────────────────────────────────────────────
def looks_like_jwt(authorization: str | None) -> bool:
    """Bearer credential with exactly three dot-separated segments = JWT.

    agw API keys are opaque single tokens; SigV4 starts AWS4-HMAC-SHA256.
    """
    if not authorization or not authorization.startswith("Bearer "):
        return False
    return authorization[7:].count(".") == 2


# ── identity establishment ────────────────────────────────────────────────
def establish_from_jwt(authorization: str) -> Identity:
    token = authorization[7:]
    issuer = os.environ.get("MODAAS_OIDC_ISSUER")
    jwks_url = os.environ.get("MODAAS_OIDC_JWKS_URL")
    if not issuer or not jwks_url:
        # Misconfiguration is an availability problem, not the caller's fault.
        raise JwksUnavailable("MODAAS_OIDC_ISSUER / MODAAS_OIDC_JWKS_URL unset")

    audience = os.environ.get("MODAAS_OIDC_AUDIENCE") or None

    try:
        header = _pyjwt.get_unverified_header(token)
    except _pyjwt.PyJWTError as exc:
        raise JwtRefusal(f"malformed token header: {exc}") from exc

    keys = _jwks(jwks_url)
    key = None
    for jwk in keys.get("keys", []):
        if jwk.get("kid") == header.get("kid"):
            key = _pyjwt.algorithms.RSAAlgorithm.from_jwk(jwk)
            break
    if key is None:
        # kid rotation: one forced refresh before refusing.
        _jwks_cache_clear()
        keys = _jwks(jwks_url)
        for jwk in keys.get("keys", []):
            if jwk.get("kid") == header.get("kid"):
                key = _pyjwt.algorithms.RSAAlgorithm.from_jwk(jwk)
                break
    if key is None:
        raise JwtRefusal(f"no JWKS key matches kid={header.get('kid')!r}")

    try:
        claims = _pyjwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            issuer=issuer,
            audience=audience,
            leeway=_LEEWAY_S,
            options={"verify_aud": audience is not None},
        )
    except _pyjwt.ExpiredSignatureError as exc:
        raise JwtRefusal(f"token expired: {exc}") from exc
    except _pyjwt.InvalidIssuerError as exc:
        raise JwtRefusal(f"issuer mismatch: {exc}") from exc
    except _pyjwt.PyJWTError as exc:
        raise JwtRefusal(f"token invalid: {exc}") from exc

    subject = claims.get("azp") or claims.get("sub")
    which = "azp" if claims.get("azp") else "sub"
    if not subject:
        raise JwtRefusal("token carries neither azp nor sub")
    log.info("jwt identity established via %s principal=%s", which, subject)

    return Identity(
        principal_id=f'ServiceIdentity::"{subject}"',
        access_key="",
        region="",
        service="keycloak-oidc",
        signed_headers=(),
        verification=Verification.CRYPTOGRAPHIC,
    )


def bootstrap_identity() -> Identity:
    """The API-key tier: ONE shared low-privilege principal BY DESIGN (a design note).

    The gateway's own apiKeyAuthentication already validated the key before
    this service ever saw the request; keys are door access, Keycloak clients
    are identity. Per-party identity lives in the JWT class.
    """
    return Identity(
        principal_id=BOOTSTRAP_PRINCIPAL,
        access_key="",
        region="",
        service="agw-apikey",
        signed_headers=(),
        verification=Verification.STRUCTURAL,
    )


# ── W4-D: doorman-side API-key validation (bootstrap tier) ────────────────
# Live finding (2026-09-02): agw's apiKeyAuthentication consumed the
# Authorization header before ext_authz -- the doorman never saw ANY
# credential on the main listener, and a partner JWT died at the key gate.
# The doorman therefore owns key validation itself: it reads the SAME
# agw-apikeys Secret (via the K8s API, raw httpx against the in-cluster
# endpoint -- no kubernetes client dependency), caches SHA-256 digests
# (never plaintext), compares digests via set membership (equal-length
# hashes; no length or prefix oracle).
import hashlib as _hashlib

_key_lock = threading.Lock()
_key_state: dict = {"fetched_at": 0.0, "digests": None}
_KEYS_TTL_S = 60


def _key_cache_clear() -> None:
    with _key_lock:
        _key_state.update(fetched_at=0.0, digests=None)


def _fetch_agw_keys() -> set:
    """Read agw-apikeys via the in-cluster K8s API with the pod SA token."""
    import base64 as _b64

    import httpx

    ns = os.environ.get("MODAAS_APIKEY_SECRET_NAMESPACE", "agentgateway-system")
    name = os.environ.get("MODAAS_APIKEY_SECRET_NAME", "agw-apikeys")
    token = open("/var/run/secrets/kubernetes.io/serviceaccount/token").read()
    resp = httpx.get(
        f"https://kubernetes.default.svc/api/v1/namespaces/{ns}/secrets/{name}",
        headers={"Authorization": f"Bearer {token}"},
        verify="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        timeout=3.0,
    )
    resp.raise_for_status()
    data = resp.json().get("data", {})
    return {_b64.b64decode(v).decode() for v in data.values()}


def _key_digests() -> set:
    now = _time.monotonic()
    with _key_lock:
        if _key_state["digests"] is not None and now - _key_state["fetched_at"] < _KEYS_TTL_S:
            return _key_state["digests"]
    try:
        keys = _fetch_agw_keys()
    except Exception as exc:  # noqa: BLE001
        raise JwksUnavailable(f"api-key store unavailable: {exc}") from exc
    digests = {_hashlib.sha256(k.encode()).hexdigest() for k in keys}
    with _key_lock:
        _key_state.update(fetched_at=now, digests=digests)
    return digests


def establish_from_api_key(authorization: str) -> Identity:
    """Validate an opaque Bearer key against the gateway key store and map to
    the single shared bootstrap principal (a design note: keys are door access)."""
    presented = authorization[7:]
    digest = _hashlib.sha256(presented.encode()).hexdigest()
    if digest not in _key_digests():
        raise JwtRefusal("api key not recognized")
    return bootstrap_identity()
