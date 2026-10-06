"""
a design note Registry health timer.

Periodically probes each Registry CR's backing and writes:
  * status.phase: Ready | Degraded | Unreachable | Unknown
  * status.lastProbed: ISO timestamp
  * status.recordCount: observed APPROVED records
  * status.message: human-readable detail on failure
  * status.driftCount: orphan records detected (W3.D)

Registered as a kopf timer on the `registries.oda.tmforum.org` kind so
any of the 3 asset operators can own it (co-located; Kopf peer election
prevents duplicate probes across replicas).

W3.D drift detection runs every DRIFT_CHECK_INTERVAL ticks (default 5)
to amortize cost of K8s API calls verifying Component existence.

This module is imported at operator startup to register the handler.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

try:
    import kopf
except ImportError:
    kopf = None  # type: ignore  # Allow unit tests without kopf installed

logger = logging.getLogger("registry_health")

GROUP = "oda.tmforum.org"
VERSION = "v1beta1"
PLURAL = "registries"

# Probe interval — keep conservative to avoid hitting AWS rate limits
PROBE_INTERVAL_SEC = int(os.environ.get("MODAAS_REGISTRY_HEALTH_INTERVAL", "300"))
PROBE_INITIAL_DELAY = 30

# W3.D: Run drift detection every Nth probe tick (default 5 = ~25 min at 300s)
DRIFT_CHECK_INTERVAL = int(os.environ.get("MODAAS_DRIFT_CHECK_INTERVAL", "5"))

# Per-registry tick counter for drift scheduling
_drift_tick_counters: dict[str, int] = {}


def _kopf_timer_decorator(func):
    """Apply kopf.timer only when kopf is available (skip in unit tests)."""
    if kopf is not None:
        return kopf.timer(GROUP, VERSION, PLURAL, interval=PROBE_INTERVAL_SEC,
                          initial_delay=PROBE_INITIAL_DELAY, idle=60, retries=3)(func)
    return func


@_kopf_timer_decorator
async def probe_registry_health(spec, name, namespace, patch, **_):
    """Probe a Registry CR's backing and write health status."""
    try:
        backing_kind = spec.get("backing", "")
        params = spec.get("parameters", {}) or {}

        # Only health-probe our own controller's registries
        controller = spec.get("controller", "")
        if controller != "aws-model-operator.modaas":
            # Ignore other controllers' registries (like IngressClass filtering)
            return

        # Import backing dispatch
        import sys, os as _os
        shared_root = _os.path.abspath(
            _os.path.join(_os.path.dirname(__file__), "..", "..")
        )
        if shared_root not in sys.path:
            sys.path.insert(0, shared_root)
        from operators.shared.backings import get_backing, UnknownBacking

        try:
            backing = get_backing(backing_kind)
        except UnknownBacking as e:
            _write_status(patch, "Unknown", 0, str(e)[:200])
            return {"error": "unknown_backing", "kind": backing_kind}

        # Probe: try a cheap .search(query="", filters={}) call
        try:
            records = backing.search("", {}, params)
            count = len([r for r in records if r.get("state") == "APPROVED"])
            phase = "Ready"
            message = ""

            # W3.D: Drift detection on every Nth tick
            drift_result = _maybe_run_drift_check(
                name, namespace, records
            )
            if drift_result and drift_result["driftCount"] > 0:
                phase = "Degraded"
                message = (
                    f"drift: {drift_result['driftCount']} orphan record(s) "
                    f"without backing Component"
                )
                patch.status["driftCount"] = drift_result["driftCount"]
                patch.status["orphans"] = drift_result["orphans"][:5]
            else:
                # Clear stale drift fields
                patch.status["driftCount"] = 0
                patch.status.setdefault("orphans", [])
                if drift_result is not None:
                    patch.status["orphans"] = []

            _write_status(patch, phase, count, message)
            logger.info(
                f"Registry {namespace}/{name} health: {phase}, records={count}"
            )
            return {"phase": phase, "recordCount": count}
        except Exception as e:
            _write_status(patch, "Unreachable", 0, f"{type(e).__name__}: {str(e)[:200]}")
            logger.warning(f"Registry {namespace}/{name} unreachable: {e}")
            return {"error": "unreachable"}

    except Exception as e:
        logger.error(f"probe_registry_health failed for {namespace}/{name}: "
                     f"{type(e).__name__}: {e}", exc_info=True)
        return {"error": str(e)}


def probe_registry_health_sync(
    backing, parameters: dict, registry_name: str, namespace: str
) -> dict:
    """PF06: Testable health probe that returns phase/message/recordCount.

    Distinguishes TMF639ReadOnlyEndpoint (phase=ReadOnly) from general
    unreachability (phase=Unreachable) and DEGRADED records (phase=Degraded).
    Called by the kopf timer above and directly from unit tests.
    """
    from operators.shared.tmf639_client import TMF639ReadOnlyEndpoint, TMF639Unreachable

    try:
        records = backing.search("", {}, parameters)
        approved = [r for r in records if r.get("state") == "APPROVED"]
        degraded = [r for r in records if r.get("state") == "DEGRADED"]
        count = len(approved)
        if degraded:
            return {
                "phase": "Degraded",
                "recordCount": count,
                "message": f"{len(degraded)} records in DEGRADED state",
            }
        return {"phase": "Ready", "recordCount": count, "message": ""}
    except TMF639ReadOnlyEndpoint as e:
        return {
            "phase": "ReadOnly",
            "recordCount": 0,
            "message": f"Canvas RI returned 405 (read-only): {str(e)[:200]}",
        }
    except TMF639Unreachable as e:
        return {
            "phase": "Unreachable",
            "recordCount": 0,
            "message": f"TMF639 unreachable: {str(e)[:200]}",
        }
    except Exception as e:
        logger.warning(f"Registry {namespace}/{registry_name} probe error: {e}")
        return {
            "phase": "Unreachable",
            "recordCount": 0,
            "message": f"{type(e).__name__}: {str(e)[:200]}",
        }


def _maybe_run_drift_check(
    registry_name: str, namespace: str, records: list[dict]
) -> dict | None:
    """W3.D: Run drift detection if this is the Nth tick for this registry.

    Returns drift result dict or None if skipped this tick.
    """
    global _drift_tick_counters
    key = f"{namespace}/{registry_name}"
    _drift_tick_counters[key] = _drift_tick_counters.get(key, 0) + 1

    if _drift_tick_counters[key] % DRIFT_CHECK_INTERVAL != 0:
        return None

    try:
        from kubernetes import client as k8s_client, config as k8s_config
        from operators.shared.registry_drift import detect_drift

        # Load in-cluster config (operator runs inside the cluster)
        try:
            k8s_config.load_incluster_config()
        except k8s_config.ConfigException:
            k8s_config.load_kube_config()

        components_api = k8s_client.CustomObjectsApi()
        return detect_drift(records, components_api)
    except Exception as e:
        logger.warning(
            "Drift check failed for %s/%s: %s", namespace, registry_name, e
        )
        return None


def _write_status(patch, phase: str, count: int, message: str) -> None:
    """Update Registry CR status fields. Safe under no-change idempotency."""
    patch.status["phase"] = phase
    patch.status["lastProbed"] = datetime.now(timezone.utc).isoformat()
    patch.status["recordCount"] = count
    # Always set message (empty string clears any stale message from previous probe)
    patch.status["message"] = message[:1024] if message else ""
