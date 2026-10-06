"""a design note — Component ownerReferences for MoDaaS CRs (Bucket 2).

When a ModelConfig / ToolConfig / AgentConfig has annotation
  oda.tmforum.org/owningComponent: <component-name>
the operator looks up that Component in the same namespace and stamps
ownerReferences on the asset CR. This makes MoDaaS assets first-class
sub-resources of TMF Components.
"""
import logging
from typing import Optional

logger = logging.getLogger("shared.component_owner")

OWNING_COMPONENT_ANNOTATION = "oda.tmforum.org/owningComponent"
COMPONENT_GROUP = "oda.tmforum.org"
COMPONENT_VERSION = "v1"
COMPONENT_PLURAL = "components"
COMPONENT_API_VERSION = f"{COMPONENT_GROUP}/{COMPONENT_VERSION}"


SKIP_COMPONENT_ANNOTATION = "oda.tmforum.org/skipComponent"


def ensure_component(k8s_api, namespace: str, source_kind: str,
                     source_name: str, source_uid: str,
                     description: str = None,
                     additional_metadata: dict = None) -> dict:
    """Idempotent create-or-get of a Canvas Component CR (W2.A).

    Returns the Component dict (existing or newly-created).
    Operator should stamp the asset CR's ownerReferences with the returned uid.

    Ownership direction (a design note): the Component's ownerReferences point back
    to the SOURCE asset (i.e., the ASSET owns the Component). Deleting the
    asset cascades to the Component, not the other way around. This is the
    inverse of the conventional Canvas reading where Component is the
    lifecycle root. The choice is intentional: the asset CR is the source of
    truth (governance contract, CEL admission, immutability, status); the
    Component is a Canvas-facing projection. See
    `docs/design/a design note-Component-Ownership-Direction.md` for the full
    rationale, blast-radius analysis, and rejected alternatives.

    Raises ApiException if Component get/create fails for non-404 reasons —
    caller is expected to surface as a kopf condition (W1.A pattern).
    """
    from kubernetes.client.exceptions import ApiException

    try:
        existing = k8s_api.get_namespaced_custom_object(
            COMPONENT_GROUP, COMPONENT_VERSION, namespace, COMPONENT_PLURAL, source_name,
        )
        if existing:
            return existing
    except ApiException as e:
        if e.status != 404:
            raise

    body = {
        "apiVersion": COMPONENT_API_VERSION,
        "kind": "Component",
        "metadata": {
            "name": source_name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/part-of": "modaas",
                "oda.tmforum.org/asset-kind": source_kind,
            },
            "annotations": dict(additional_metadata or {}),
            "ownerReferences": [
                {
                    "apiVersion": f"{COMPONENT_GROUP}/v1beta1",
                    "kind": source_kind,
                    "name": source_name,
                    "uid": source_uid,
                    "controller": True,
                    "blockOwnerDeletion": True,
                }
            ],
        },
        "spec": {
            "componentName": source_name,
            "type": f"modaas-{source_kind.lower()}",
            "description": description or f"MoDaaS-managed {source_kind}: {source_name}",
        },
    }
    return k8s_api.create_namespaced_custom_object(
        COMPONENT_GROUP, COMPONENT_VERSION, namespace, COMPONENT_PLURAL, body,
    )


def build_owner_reference(meta: dict, k8s_custom_api) -> Optional[dict]:
    """Build a Component ownerReference for a MoDaaS CR, if annotated.

    Returns an owner reference dict, or None if no annotation is set or
    the referenced Component is missing.
    """
    annotations = (meta or {}).get("annotations") or {}
    component_name = annotations.get(OWNING_COMPONENT_ANNOTATION)
    if not component_name:
        return None

    namespace = meta.get("namespace") or "components"

    try:
        component = k8s_custom_api.get_namespaced_custom_object(
            COMPONENT_GROUP,
            COMPONENT_VERSION,
            namespace,
            COMPONENT_PLURAL,
            component_name,
        )
    except Exception as e:
        logger.warning(
            "Component %s/%s not found for ownerReference: %s",
            namespace, component_name, type(e).__name__,
        )
        return None

    component_meta = component.get("metadata") or {}
    uid = component_meta.get("uid")
    if not uid:
        logger.warning("Component %s/%s has no uid; skipping ownerReference", namespace, component_name)
        return None

    return {
        "apiVersion": COMPONENT_API_VERSION,
        "kind": "Component",
        "name": component_meta.get("name", component_name),
        "uid": uid,
        "controller": False,
        "blockOwnerDeletion": True,
    }
