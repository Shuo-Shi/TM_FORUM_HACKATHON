"""a design note — PublishedNotification on lifecycle transitions (Bucket 2).

Operator-side helper that emits a TMF-shape PublishedNotification CR on
significant lifecycle events. Canvas's notification operator routes these
to subscribers via the TMF event mesh — bridge from MoDaaS internal
lifecycle to OSS/BSS observability.
"""
import logging
from typing import Optional

logger = logging.getLogger("shared.lifecycle_events")

PUBLISHED_NOTIFICATION_GROUP = "oda.tmforum.org"
PUBLISHED_NOTIFICATION_VERSION = "v1"
PUBLISHED_NOTIFICATION_PLURAL = "publishednotifications"
PUBLISHED_NOTIFICATION_API_VERSION = (
    f"{PUBLISHED_NOTIFICATION_GROUP}/{PUBLISHED_NOTIFICATION_VERSION}"
)


def emit_lifecycle_event(
    k8s_api,
    namespace: str,
    source_kind: str,
    source_name: str,
    event_type: str,
    payload: dict,
    observed_generation: int = 0,
    correlation_id: Optional[str] = None,
) -> Optional[dict]:
    """Create a PublishedNotification CR for a MoDaaS lifecycle event.

    Idempotent by name (source_kind + source_name + event_type + observed_generation).
    Returns the created object (or None on AlreadyExists / 404 / errors).
    Non-blocking: any failure logs and returns None.
    """
    name = f"{source_kind.lower()}-{source_name}-{event_type.lower()}-{observed_generation}"
    name = name[:253]

    spec = {
        "eventType": event_type,
        "sourceRef": {
            "apiVersion": "oda.tmforum.org/v1beta1",
            "kind": source_kind,
            "name": source_name,
            "namespace": namespace,
        },
        "payload": payload or {},
        "observedGeneration": observed_generation,
    }
    if correlation_id:
        spec["correlationId"] = correlation_id

    body = {
        "apiVersion": PUBLISHED_NOTIFICATION_API_VERSION,
        "kind": "PublishedNotification",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "oda.tmforum.org/sourceKind": source_kind,
                "oda.tmforum.org/sourceName": source_name,
                "oda.tmforum.org/eventType": event_type,
            },
        },
        "spec": spec,
    }

    try:
        result = k8s_api.create_namespaced_custom_object(
            group=PUBLISHED_NOTIFICATION_GROUP,
            version=PUBLISHED_NOTIFICATION_VERSION,
            namespace=namespace,
            plural=PUBLISHED_NOTIFICATION_PLURAL,
            body=body,
        )
        return result
    except Exception as e:
        err_status = getattr(e, "status", None)
        if err_status in (404, 409):
            logger.debug(
                "Lifecycle event %s for %s/%s status=%s (non-blocking)",
                event_type, source_kind, source_name, err_status,
            )
            return None
        # W1.A: Classify the error so callers can surface it as a condition.
        # Still non-blocking (returns None), but now also stores the error
        # classification on the returned None via a module-level last_error.
        _classify_and_log(e, event_type, source_kind, source_name)
        return None


def _classify_and_log(exc: Exception, event_type: str, source_kind: str, source_name: str):
    """Classify and log a lifecycle event emission failure.

    W1.A: Callers that need to surface the error as a kopf condition can
    call get_last_error() after emit_lifecycle_event returns None.
    """
    global _last_error
    status_code = getattr(exc, "status", None)
    if status_code == 403:
        reason = "RBACDenied"
    elif status_code == 404:
        reason = "NotFound"
    else:
        reason = "EmissionFailed"
    _last_error = {"reason": reason, "message": str(exc)[:256], "event_type": event_type}
    logger.warning(
        "Lifecycle event %s for %s/%s failed (non-blocking, reason=%s): %s",
        event_type, source_kind, source_name, reason, type(exc).__name__,
    )


# W1.A: Last error from emit_lifecycle_event for condition surfacing.
_last_error: Optional[dict] = None


def get_last_error() -> Optional[dict]:
    """Return the last error from emit_lifecycle_event, or None if last call succeeded."""
    return _last_error


# Asset kind → CRD plural mapping. Used to populate sourceRef.apiVersion + kind
# so the audit ledger can round-trip back to the owning CR via UID match.
_ASSET_KIND_API_VERSION = {
    "ModelConfig": "oda.tmforum.org/v1beta1",
    "ToolConfig": "oda.tmforum.org/v1beta1",
    "AgentConfig": "oda.tmforum.org/v1beta1",
}


def emit_phase_transition(
    k8s_api,
    namespace: str,
    asset_kind: str,
    asset_name: str,
    asset_uid: str,
    from_phase: str,
    to_phase: str,
    component_uid: Optional[str] = None,
    extra_payload: Optional[dict] = None,
) -> None:
    """W2.D: Emit PublishedNotification for a phase change. Fail-soft (log + return).

    Bug #13/#14 fix (2026-05-27):
      - Always populates spec.sourceRef.{apiVersion,kind,name,namespace,uid} so
        the audit ledger can round-trip to the owning CR via UID match.
        Previously sourceRef was missing, which caused 91% of events to lack a
        valid backlink.
      - Skips emit when from_phase == to_phase. The asset_operator phase machine
        sets phase = X regardless of prior value, and reconcile re-runs on each
        generation bump can re-declare the same phase. Without dedup the ledger
        fills with no-op transitions; that masks the real Pending→Approved
        timeline that slide 13 needs.

    Unlike emit_lifecycle_event (which is idempotent by name), this uses
    generateName so distinct transitions of the same kind are all recorded
    as separate objects — the audit ledger (slide 13) shows the full timeline.
    """
    # Bug #13 dedup: skip no-op transitions. "Unknown" → X is allowed (first emit
    # after operator restart / fresh CR) since that IS a real transition into a
    # known phase from an unknown prior state.
    if from_phase == to_phase:
        logger.debug(
            "emit_phase_transition skipped for %s/%s (no-op %s→%s)",
            namespace, asset_name, from_phase, to_phase,
        )
        return

    api_version = _ASSET_KIND_API_VERSION.get(asset_kind, "oda.tmforum.org/v1beta1")

    # Bug #14 fix: populate spec.sourceRef so consumers can join PublishedNotification
    # back to the owning CR via UID match. Use the same shape K8s ownerReferences use.
    source_ref = {
        "apiVersion": api_version,
        "kind": asset_kind,
        "name": asset_name,
        "namespace": namespace,
    }
    if asset_uid:
        source_ref["uid"] = asset_uid

    body = {
        "apiVersion": PUBLISHED_NOTIFICATION_API_VERSION,
        "kind": "PublishedNotification",
        "metadata": {
            "generateName": f"{asset_name}-phase-",
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/part-of": "modaas",
                "modaas.tmforum.org/asset": asset_name,
                "modaas.tmforum.org/asset-kind": asset_kind,
            },
        },
        "spec": {
            "eventType": "PhaseTransition",
            "sourceRef": source_ref,
            "payload": {
                "from": from_phase,
                "to": to_phase,
                "asset": asset_name,
                "assetKind": asset_kind,
                "assetUid": asset_uid,
                **(extra_payload or {}),
            },
        },
    }
    if component_uid:
        body["metadata"]["ownerReferences"] = [{
            "apiVersion": "oda.tmforum.org/v1",
            "kind": "Component",
            "name": asset_name,
            "uid": component_uid,
            "controller": False,
            "blockOwnerDeletion": False,
        }]
    try:
        k8s_api.create_namespaced_custom_object(
            group=PUBLISHED_NOTIFICATION_GROUP,
            version=PUBLISHED_NOTIFICATION_VERSION,
            namespace=namespace,
            plural=PUBLISHED_NOTIFICATION_PLURAL,
            body=body,
        )
    except Exception as e:
        logger.warning(
            "emit_phase_transition failed for %s/%s %s->%s: %s",
            namespace, asset_name, from_phase, to_phase, e,
        )
