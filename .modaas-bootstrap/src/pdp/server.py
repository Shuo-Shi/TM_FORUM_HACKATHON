"""MoDaaS in-cluster PDP — FastAPI entry point.

Implements the API contract from a design note:

    POST /decide                -> Cedar evaluation, ALLOW/DENY response
    GET  /healthz               -> liveness (process up + watcher thread alive)
    GET  /ready                 -> readiness (ConfigMap watcher has seen the
                                   cluster at least once; loadedPolicies
                                   may legitimately be 0 at first install)
    GET  /policies/{policy_id}  -> readback so the operator can poll for
                                   "policy hot-loaded" before stamping
                                   AgentConfig.status.agentPolicy.pdpReady=true

Process model: single FastAPI app, 2 uvicorn workers (per Dockerfile).
The CedarEvaluator + PolicyWatcher are module globals shared across
worker processes only at the FastAPI dependency level — uvicorn fork
isolates them, which is fine because each worker maintains its own
identical view of the cluster's ConfigMaps.

a design note fail-closed posture is enforced at three layers:

1. CedarEvaluator: missing policy_id → DENY (cedar_evaluator.py)
2. Cedar engine: no permit matches → DENY (Cedar default-deny)
3. Server: 200 + decision=DENY on evaluator errors (this file)

We never return 5xx for evaluation outcomes — that would invite
PEP-side fail-open if the PEP treats 5xx as "skip enforcement". The
PEP MUST treat unreachable PDP as DENY on its own (a design note §Failure
Modes); the server's job is to always answer with a decision.
"""
from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from cedar_evaluator import CedarEvaluator
from policy_watcher import PolicyWatcher

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("modaas-pdp")

VERSION = os.environ.get("PDP_VERSION", "v0.7.0-dev")

app = FastAPI(title="MoDaaS PDP", version=VERSION)

_evaluator = CedarEvaluator()
_watcher: Optional[PolicyWatcher] = None
_started_at = time.time()


# ---------------------------------------------------------------------------
# Wire models — a design note API contract.
# ---------------------------------------------------------------------------


class EntityRef(BaseModel):
    model_config = ConfigDict(extra="allow")  # attributes are pass-through
    type: str = Field(..., min_length=1)
    id: str = Field(..., min_length=1)
    attributes: Optional[dict[str, Any]] = None


class DecideRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policyId: str = Field(..., min_length=1)
    principal: EntityRef
    action: EntityRef
    resource: EntityRef
    context: Optional[dict[str, Any]] = Field(default_factory=dict)


class DecideResponse(BaseModel):
    decision: str
    policyId: str
    evaluatedAt: str
    policyVersion: Optional[str] = None
    matchedPolicy: Optional[str] = None
    reason: Optional[str] = None
    # C-1/C-2 fix (authz-gateway code-generation review, 2026-08-21): a permit
    # can fire cleanly while a SIBLING forbid clause type-errors (e.g. a `>`
    # comparison against the wrong type) — Cedar treats an erroring clause as
    # "doesn't apply" rather than blocking, so decision stays ALLOW and
    # cedar_evaluator.py's evaluate() also nulls `reason` on the ALLOW branch.
    # Without this field an allow that only happened because a clause failed
    # to evaluate is wire-indistinguishable from a genuine permit.
    # authz-gateway/pdp_client.py._interpret() already refuses on a non-empty
    # `errors` list; until this field existed that check was correctly
    # written but structurally unreachable.
    errors: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Lifecycle.
# ---------------------------------------------------------------------------


@app.on_event("startup")
def _startup() -> None:
    global _watcher
    # PDP_DISABLE_WATCHER is the unit-test escape hatch — production never
    # sets it. Live cluster + dev shells leave it unset.
    if os.environ.get("PDP_DISABLE_WATCHER") == "1":
        log.warning("PDP_DISABLE_WATCHER=1 — running without ConfigMap watcher")
        return
    _watcher = PolicyWatcher(_evaluator)
    try:
        _watcher.start()
    except Exception as exc:
        # If we can't reach the API server at startup, log loudly and let
        # liveness probes mark the pod unhealthy. We do NOT crash the
        # process here because the watcher has its own retry loop and
        # transient API outages shouldn't kill the pod.
        log.error("watcher start failed: %s", exc)


@app.on_event("shutdown")
def _shutdown() -> None:
    if _watcher is not None:
        _watcher.stop()


# ---------------------------------------------------------------------------
# Endpoints.
# ---------------------------------------------------------------------------


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    """Liveness probe.

    "Up" is binary: process accepting HTTP. The watcher having errors is
    visible via /ready and metrics, not /healthz — kubelet will not
    restart a pod just because it's struggling to read ConfigMaps.
    """
    return {
        "status": "ok",
        "version": VERSION,
        "uptimeSeconds": int(time.time() - _started_at),
    }


@app.get("/ready")
def ready() -> dict[str, Any]:
    """Readiness probe.

    a design note explicitly allows /ready=200 with `loadedPolicies=0` at first
    install — the PDP can be ready before any AgentConfig has been
    admitted. What matters is that the watcher process is alive and able
    to react to ConfigMap events.

    We return 200 + an honest snapshot. K8s readinessProbe defaults to
    treating 2xx as "ready". A future iteration could fail-closed (503
    when watcher thread is dead) but for v1 we keep ready always-200 so
    we don't add a new failure mode at the probe boundary.
    """
    watcher_alive = (
        _watcher is not None
        and _watcher._thread is not None
        and _watcher._thread.is_alive()
    )
    return {
        "status": "ok",
        "loadedPolicies": _evaluator.loaded_policy_count(),
        "watcherAlive": watcher_alive,
        "version": VERSION,
    }


@app.get("/policies/{policy_id:path}")
def get_policy(policy_id: str) -> dict[str, Any]:
    """Operator-side hot-load probe.

    Per a design note: "PDP exposes GET /policies/{policyId} for readiness
    check; operator polls."

    We use `:path` so policyId values like
    `modaas/components/agentconfig/support-bot` round-trip through HTTP
    without forcing the operator to URL-encode slashes.
    """
    payload = _evaluator.get_policy(policy_id)
    if payload is None:
        raise HTTPException(status_code=404, detail=f"policy_id={policy_id} not loaded")
    return payload


@app.post("/decide", response_model=DecideResponse)
def decide(req: DecideRequest) -> DecideResponse:
    """Evaluate one principal-action-resource-context against `policyId`.

    Behaviors:
      * matched permit (and no forbid)  → ALLOW
      * matched forbid                  → DENY (with matchedPolicy)
      * no permit matched               → DENY (Cedar default-deny)
      * policyId not loaded             → DENY (fail-closed)
      * cedar evaluator error           → DENY (fail-closed)
    """
    started = time.time()
    result = _evaluator.evaluate(
        policy_id=req.policyId,
        principal={"type": req.principal.type, "id": req.principal.id,
                   "attributes": req.principal.attributes or {}},
        action={"type": req.action.type, "id": req.action.id,
                "attributes": req.action.attributes or {}},
        resource={"type": req.resource.type, "id": req.resource.id,
                  "attributes": req.resource.attributes or {}},
        context=req.context or {},
    )
    payload = _evaluator.get_policy(req.policyId)
    policy_version = payload.get("policyVersion") if payload else None

    response = DecideResponse(
        decision=result.decision,
        policyId=req.policyId,
        evaluatedAt=datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        policyVersion=policy_version,
        matchedPolicy=result.matched_policy,
        reason=result.reason,
        errors=result.errors,
    )
    elapsed_ms = (time.time() - started) * 1000.0
    # T2 (sprint-2026-09-ga-hardening): traceId/actionId ride in the OPEN
    # `context` dict authz-gateway's authorize.py populates (build_decide_
    # request) -- no DecideRequest schema change, since context already
    # accepts arbitrary keys (see the class docstring above). Absent for a
    # caller of /decide that predates T2 or bypasses authz-gateway, hence the
    # "-" fallback rather than a KeyError.
    ctx = req.context or {}
    log.info(
        "decide policy_id=%s decision=%s matched=%s latency_ms=%.2f "
        "trace_id=%s action_id=%s",
        req.policyId, response.decision, response.matchedPolicy or "-",
        elapsed_ms, ctx.get("traceId", "-"), ctx.get("actionId", "-"),
    )
    return response
