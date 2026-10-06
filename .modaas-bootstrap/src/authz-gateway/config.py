"""Configuration knobs for authz-gateway, in one place so a gate can check them.

Four of these feed one memory calculation (SC-1), and three replace a default
that was previously invisible:

    buffers  = MAX_IN_FLIGHT      x 256 KB x 4.6   <- measured peak multiplier
    uvicorn  = LIMIT_CONCURRENCY  x ~160 KB        <- h11 buffers before the app
    cache    = CACHE_MAX_ENTRIES  x ~400 B
    threads  = STS_EXECUTOR_SIZE  x ~38 KB

At the values below that derives to ~120 MB, against a 384Mi limit (~3x, because
every input is a small number of measurements). loop/verify/G60.sh checks the
deployed limit against this arithmetic; raising a knob without raising the limit
reintroduces the OOM-then-cold-cache cascade the shed path exists to prevent.
"""
from __future__ import annotations

import os


def _int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


def _float(name: str, default: float) -> float:
    return float(os.environ.get(name, default))


# --- the four memory knobs -------------------------------------------------
# App-side in-flight bound. Enforced by shed.py BEFORE the body is read.
MAX_IN_FLIGHT = _int("MAX_IN_FLIGHT", 32)

# uvicorn's own bound. Load-bearing: h11_impl.py accumulates cycle.body in the
# protocol loop regardless of whether the ASGI app calls receive(), so this is
# the only bound on that buffer. HIGH_WATER_LIMIT caps it per connection at
# ~64-160 KB, but the count of connections is bounded only here.
LIMIT_CONCURRENCY = _int("LIMIT_CONCURRENCY", 128)

# Identity cache size. Generous on purpose: at 5000 entries this is under 2 MB
# against 37 MB of buffers, so bounding it costs nothing while leaving it
# unbounded is the SC-1b defect.
CACHE_MAX_ENTRIES = _int("CACHE_MAX_ENTRIES", 5000)

# Replaces anyio's silent default of 40, which capped concurrent cold lookups
# invisibly regardless of MAX_IN_FLIGHT.
STS_EXECUTOR_SIZE = _int("STS_EXECUTOR_SIZE", 32)

# --- the timeout budget ----------------------------------------------------
# The hook's own default is 2s and is pinned to 1900ms by a backend-timeout
# AgentgatewayPolicy (spec.backend.http.requestTimeout). This service's budget
# sits under that so ITS deadline fires first and can attach a reason; if the
# hook wins the race the refusal is a bare 403 with no reason (RL-7).
REQUEST_BUDGET_S = _float("REQUEST_BUDGET_S", 1.75)

# Total elapsed for the STS lookup, not per attempt: botocore retries are
# per-call, so a per-attempt bound times max_attempts can outlive the budget.
STS_TOTAL_BUDGET_S = _float("STS_TOTAL_BUDGET_S", 0.30)
STS_MAX_ATTEMPTS = _int("STS_MAX_ATTEMPTS", 2)

# Identity cache TTL. Inherited from sigv4_auth.py:126 rather than re-derived;
# it bounds how long a revoked key still resolves.
CACHE_TTL_S = _float("CACHE_TTL_S", 300.0)

# --- endpoints -------------------------------------------------------------
AWS_REGION = os.environ.get("AWS_REGION", "us-west-2")

# Regional, explicitly. botocore can default to the global STS endpoint, and a
# cross-region hop inside a 300ms bound is a silent latency defect.
STS_ENDPOINT_URL = os.environ.get(
    "STS_ENDPOINT_URL", f"https://sts.{AWS_REGION}.amazonaws.com"
)

PDP_URL = os.environ.get("PDP_URL", "http://modaas-pdp.modaas-system.svc.cluster.local:8080")

# Identity verification depth. "identity" adds the STS account lookup; note it
# proves an account can be derived, NOT that the key is active or entitled.
VERIFICATION_MODE = os.environ.get("VERIFICATION_MODE", "identity")

# --- the evidence chain (a design note) -------------------------------------------
#
# Where decision records go. EMPTY BY DEFAULT and that is deliberate: the chart
# ships `otelCollector.enabled: false`, so a default endpoint here would make
# every install attempt a POST to a Service that does not exist -- 1024 queued
# records and a climbing drop counter on a cluster that never asked for the
# collector. evidence_emit.enabled is False while this is empty, and the skip is
# counted rather than silent.
#
# Accepts either form the OTLP spec defines: a BASE url
# (OTEL_EXPORTER_OTLP_ENDPOINT semantics, `/v1/logs` appended) or the full logs
# url (OTEL_EXPORTER_OTLP_LOGS_ENDPOINT semantics, used as given).
EVIDENCE_OTLP_ENDPOINT = os.environ.get("MODAAS_EVIDENCE_OTLP_ENDPOINT", "")

# Stamped onto every record as `service.namespace`. The collector's
# k8sattributes stamp is what a READER trusts (it comes from the connection IP,
# not the payload); this is for a human reading a raw log line.
EVIDENCE_SERVICE_NAMESPACE = os.environ.get("MODAAS_NAMESPACE", "modaas-system")

# The queue bound. At ~700 bytes per record this is under 1 MB against the
# 384Mi limit, so it does not enter the SC-1 arithmetic above. It exists to make
# an export outage bounded and COUNTED rather than unbounded: an unbounded queue
# behind a dead collector is the memory-growth primitive this repo has already
# fixed twice (AGENTS.md: "any in-memory cache in a long-running operator needs
# TTL + max-entries").
EVIDENCE_QUEUE_MAX = _int("MODAAS_EVIDENCE_QUEUE_MAX", 1024)

# Records per POST. Caps the body size of one export so a backlog drains in
# several bounded requests rather than one that the collector may reject whole.
EVIDENCE_BATCH_SIZE = _int("MODAAS_EVIDENCE_BATCH_SIZE", 64)

# How long a record may sit before export. This is the auditor's visible lag on
# the decision half of the timeline; the collector adds its own batch timeout
# (5s in the chart) on top.
EVIDENCE_FLUSH_INTERVAL_S = _float("MODAAS_EVIDENCE_FLUSH_INTERVAL_S", 2.0)

# Export timeout. Off the request path entirely (the drain thread owns it), so it
# is NOT bounded by REQUEST_BUDGET_S and must not be derived from it.
EVIDENCE_TIMEOUT_S = _float("MODAAS_EVIDENCE_TIMEOUT_S", 2.0)

# --- whether an UNVERIFIED SigV4 header counts as identity at all ----------
#
# identity.py cannot verify a SigV4 signature -- the signing key derives from the
# caller's secret, which MoDaaS does not hold. So neither value below is
# "verify": the choice is whether to ACCEPT an unverifiable attribution as
# identity, or refuse the caller and say why.
#
#   account  today's behaviour, and the default. Shape + freshness + (in
#            VERIFICATION_MODE=identity) an STS account lookup. A header with a
#            real-format access key id, a fresh x-amz-date and 64 hex zeros
#            where the signature goes is accepted and reported as
#            `account-resolved`. Demonstrated in
#            tests/test_sigv4_identity_mode.py, not merely asserted.
#   reject   refuse every SigV4 caller at identity, with
#            SigV4UnverifiedIdentityRejected. a design note point 3's position. Narrows
#            ONE class: Keycloak JWTs (verified against the realm JWKS) and the
#            API-key bootstrap tier are dispatched earlier and unaffected.
#
# The default is UNCHANGED behaviour because flipping it refuses every SigV4
# caller on the live cluster; which one ships is the owner's decision. Anything
# other than these two values behaves as `reject`, because a typo in a posture
# knob must never land on the permissive setting.
#
# Read through the module (`config.SIGV4_IDENTITY_MODE`) rather than imported by
# value, so a deployment-time override and a test override behave identically.
SIGV4_IDENTITY_MODE = os.environ.get("SIGV4_IDENTITY_MODE", "account")
