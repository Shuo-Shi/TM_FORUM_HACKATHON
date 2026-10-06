"""Enforcement-path capability check.

R2 fix (dataplane cutover, owner direction 2026-09-01)
-----------------------------------------------------------
This module used to GET ``/v1/capabilities`` on the previous dataplane and
refuse ModelConfig approval when the response did not advertise the CR's
``enforcer.kind`` (a design note version-skew guard). That component is RETIRED and
upstream agentgateway v1.4.1 exposes no capabilities contract — left as-was,
every ``enforcer.kind: external | bedrockGuardrailExternal`` approval fails
closed forever with ``GatewayVersionSkew`` against a host that no longer
exists.

What the guard must actually establish did not change: *the enforcement the
CR declares can really happen at call time* (a design note/a design note truthfulness).
On the agentgateway dataplane those kinds are realized by the ``ext_authz``
hook calling **modaas-authz**, which consults **modaas-pdp** (a design note/a design note).
So the truthful probe targets those two services' own health endpoints:

  - ``modaas-authz``  → ``GET /healthz``  (authz-gateway/app.py:50)
  - ``modaas-pdp``    → ``GET /ready``    (pdp/server.py:153 — readiness
    includes the policy store, which /healthz does not assert)

``bedrockGuardrail`` (the non-external kind) is enforced by the
AgentgatewayModel's own guardrail binding inside the dataplane; the operator
itself programs that CR, so there is no separate component to probe — it is
always "supported" here and its truthfulness is carried by the programming
path (agentgateway_route.py) plus a design note verifiers.

Fail-closed semantics are PRESERVED: if either enforcement component is
unreachable, external kinds are refused with the same
``ProvisioningFailed("GatewayVersionSkew")`` the call sites already raise.
RBAC note: probing HTTP /healthz needs no new permissions, unlike reading
Gateway/AgentgatewayPolicy status (the operator SA has neither — verified
live with ``kubectl auth can-i`` on eks-cluster-modaas, 2026-09-01), and
AgentgatewayModel carries no status subresource to inspect.

Env overrides (defaults are the in-cluster Service DNS, verified live):
  MODAAS_AUTHZ_HEALTH_URL   default http://modaas-authz.modaas-system.svc.cluster.local:8080/healthz
  MODAAS_PDP_READY_URL      default http://modaas-pdp.modaas-system.svc.cluster.local:8080/ready
  MODAAS_GATEWAY_CAP_TTL    probe cache seconds (default 60)
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger("GatewayCapability")


_AUTHZ_HEALTH_URL = os.environ.get(
    "MODAAS_AUTHZ_HEALTH_URL",
    "http://modaas-authz.modaas-system.svc.cluster.local:8080/healthz",
)
_PDP_READY_URL = os.environ.get(
    "MODAAS_PDP_READY_URL",
    "http://modaas-pdp.modaas-system.svc.cluster.local:8080/ready",
)
_CACHE_TTL_S = int(os.environ.get("MODAAS_GATEWAY_CAP_TTL", "60"))

# Kinds whose enforcement rides the ext_authz hook -> authz-gateway -> PDP.
_EXTERNAL_KINDS = frozenset({"external", "bedrockGuardrailExternal"})
# Kinds enforced inside the dataplane by the operator-programmed
# AgentgatewayModel guardrail binding — nothing external to probe.
_NATIVE_KINDS = frozenset({"bedrockGuardrail", "none"})


@dataclass
class Capabilities:
    """Snapshot of the enforcement path's probed state.

    Field names are preserved from the retired /v1/capabilities shape so
    existing tests/log consumers keep working; ``enforcer_kinds`` now means
    "kinds whose enforcement path answered its health probe".
    """

    contract_version: str = "agentgateway+ext_authz"
    enforcer_kinds: list[str] = field(default_factory=list)
    formats: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    fetched_at: float = 0.0
    error: str | None = None

    def supports_enforcer(self, kind: str) -> bool:
        return kind in self.enforcer_kinds

    @property
    def is_stale(self) -> bool:
        return (time.time() - self.fetched_at) > _CACHE_TTL_S

    @property
    def is_usable(self) -> bool:
        return self.error is None and bool(self.enforcer_kinds)


_cache: Capabilities | None = None


def _probe(url: str) -> str | None:
    """Return None on 2xx, else a short error string. Never raises."""
    try:
        r = httpx.get(url, timeout=2.0)
        r.raise_for_status()
        return None
    except Exception as e:  # noqa: BLE001 - condensed into the reason string
        return f"{type(e).__name__}: {e}"


def get_capabilities(force_refresh: bool = False) -> Capabilities:
    """Probe the enforcement components, cached for _CACHE_TTL_S seconds.

    Never raises. On probe failure returns a Capabilities whose
    ``enforcer_kinds`` contains only the native kinds and whose ``error``
    names the failing component — callers keep their fail-closed policy for
    external kinds.
    """
    global _cache
    if not force_refresh and _cache and not _cache.is_stale:
        return _cache

    kinds = sorted(_NATIVE_KINDS)
    errors: list[str] = []
    endpoints = []

    authz_err = _probe(_AUTHZ_HEALTH_URL)
    pdp_err = _probe(_PDP_READY_URL)
    if authz_err:
        errors.append(f"modaas-authz unhealthy ({_AUTHZ_HEALTH_URL}): {authz_err}")
    if pdp_err:
        errors.append(f"modaas-pdp not ready ({_PDP_READY_URL}): {pdp_err}")
    if not authz_err and not pdp_err:
        kinds = sorted(_NATIVE_KINDS | _EXTERNAL_KINDS)
        endpoints = [_AUTHZ_HEALTH_URL, _PDP_READY_URL]

    _cache = Capabilities(
        enforcer_kinds=kinds,
        endpoints=endpoints,
        fetched_at=time.time(),
        error="; ".join(errors) or None,
    )
    if errors:
        logger.warning("enforcement-path probe degraded: %s", _cache.error)
    else:
        logger.info(
            "enforcement-path probe healthy: kinds=%s", _cache.enforcer_kinds
        )
    return _cache


def check_enforcer_supported(enforcer_kind: str) -> tuple[bool, str]:
    """True if the declared enforcer.kind can actually be enforced right now.

    Returns (supported, reason). Semantics preserved from the retired probe:
    external kinds FAIL CLOSED when their enforcement path (authz-gateway +
    PDP) does not answer health — operators refuse approval on False.
    Native kinds are enforced by the operator-programmed AgentgatewayModel
    itself and always pass here.
    """
    if enforcer_kind in _NATIVE_KINDS:
        return True, f"dataplane-native-{enforcer_kind}"

    caps = get_capabilities()
    if enforcer_kind in caps.enforcer_kinds:
        return True, f"enforcement-path-healthy-{enforcer_kind}"
    return False, (
        f"enforcer.kind={enforcer_kind!r} needs the ext_authz enforcement path "
        f"(modaas-authz + modaas-pdp) and it is not healthy: {caps.error}. "
        f"Fail-closed per a design note/a design note — fix the enforcement components, "
        f"then re-reconcile."
    )
