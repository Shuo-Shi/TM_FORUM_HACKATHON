"""a design note — SubscribedNotification cascade (Bucket 2 — pre-DTW directive).

MoDaaS subscribes to Component lifecycle events via Canvas's
SubscribedNotification CR. On Component retirement, MoDaaS cascades:
  - Mark dependent ModelConfigs as Retired (or Failed)
  - Pause dependent AgentConfigs
  - Surface a TMF-shape PublishedNotification for the cascade itself

Two helpers:
  ensure_subscription(): creates the SubscribedNotification CR (one per
    operator install; idempotent)
  cascade_on_component_retired(): given a Component name, mark its
    owned MoDaaS CRs Retired (called by the operator's event handler)
"""
import logging
from typing import Optional

logger = logging.getLogger("shared.subscribed_notification")

SUBSCRIBED_NOTIFICATION_GROUP = "oda.tmforum.org"
SUBSCRIBED_NOTIFICATION_VERSION = "v1"
SUBSCRIBED_NOTIFICATION_PLURAL = "subscribednotifications"
SUBSCRIBED_NOTIFICATION_API_VERSION = (
    f"{SUBSCRIBED_NOTIFICATION_GROUP}/{SUBSCRIBED_NOTIFICATION_VERSION}"
)


def ensure_subscription(
    k8s_api,
    namespace: str,
    subscription_name: str,
    callback_url: str,
    event_filter: Optional[dict] = None,
) -> Optional[dict]:
    """Create (or no-op) a SubscribedNotification CR for MoDaaS to listen on
    Component lifecycle events.

    Typical usage: operator startup creates one subscription per cluster.
    """
    body = {
        "apiVersion": SUBSCRIBED_NOTIFICATION_API_VERSION,
        "kind": "SubscribedNotification",
        "metadata": {
            "name": subscription_name,
            "namespace": namespace,
            "labels": {"app.kubernetes.io/managed-by": "modaas"},
        },
        "spec": {
            "callback": callback_url,
            "filter": event_filter or {
                "sourceKind": "Component",
                "eventTypes": ["Retired", "Failed"],
            },
        },
    }

    try:
        return k8s_api.create_namespaced_custom_object(
            group=SUBSCRIBED_NOTIFICATION_GROUP,
            version=SUBSCRIBED_NOTIFICATION_VERSION,
            namespace=namespace,
            plural=SUBSCRIBED_NOTIFICATION_PLURAL,
            body=body,
        )
    except Exception as e:
        status = getattr(e, "status", None)
        if status in (404, 409):
            logger.debug(
                "SubscribedNotification %s status=%s (non-blocking)",
                subscription_name, status,
            )
            return None
        logger.warning(
            "SubscribedNotification %s failed (non-blocking): %s",
            subscription_name, type(e).__name__,
        )
        return None


def cascade_on_component_retired(
    k8s_api,
    namespace: str,
    component_name: str,
    component_uid: str,
) -> dict:
    """Cascade-retire MoDaaS CRs owned by a retiring Component.

    Returns a summary dict {"retired": [...], "paused": [...], "errors": [...]}
    Non-blocking: per-CR failures collected but not raised.

    Algorithm:
      1. List ModelConfigs / ToolConfigs / AgentConfigs in the namespace
      2. For each whose ownerReferences contains component_uid:
         - ModelConfig / ToolConfig: spec.paused=true (operator transitions
           to phase=Paused; admin re-purposes)
         - AgentConfig: spec.paused=true (no further A2A traffic)
      3. Collect actions taken
    """
    summary = {"retired": [], "paused": [], "errors": []}

    for kind, plural in (
        ("ModelConfig", "modelconfigs"),
        ("ToolConfig", "toolconfigs"),
        ("AgentConfig", "agentconfigs"),
    ):
        try:
            crs = k8s_api.list_namespaced_custom_object(
                group="oda.tmforum.org",
                version="v1beta1",
                namespace=namespace,
                plural=plural,
            )
        except Exception as e:
            summary["errors"].append(f"list {kind}: {type(e).__name__}")
            continue

        for cr in crs.get("items") or []:
            meta = cr.get("metadata") or {}
            owners = meta.get("ownerReferences") or []
            if not any(o.get("uid") == component_uid for o in owners):
                continue
            cr_name = meta.get("name", "")
            try:
                # Patch spec.paused=true; operator picks it up and transitions phase.
                k8s_api.patch_namespaced_custom_object(
                    group="oda.tmforum.org",
                    version="v1beta1",
                    namespace=namespace,
                    plural=plural,
                    name=cr_name,
                    body={"spec": {"paused": True}},
                )
                summary["paused"].append(f"{kind}/{cr_name}")
            except Exception as e:
                summary["errors"].append(f"pause {kind}/{cr_name}: {type(e).__name__}")

    logger.info(
        "Component %s retired: cascaded %d MoDaaS CRs (paused), %d errors",
        component_name, len(summary["paused"]), len(summary["errors"]),
    )
    return summary
