"""a design note — Per-Asset IdentityConfig provisioning (Bucket 2).

Replaces stubbed KeycloakReady condition with a real Canvas IdentityConfig
CR per ModelConfig / ToolConfig / AgentConfig. Canvas's
identityconfig-operator-keycloak then provisions Keycloak client + roles.

Naming convention (mirrors v1 model_operator's stubbed condition message):
  IdentityConfig.metadata.name = modaas-{kind-lower}-{source-name}
  Roles (Canvas CRD field: componentRole, array of {name, description}):
    modaas-{kind-lower}-{source-name}-consumer  — agents that may invoke
    modaas-{kind-lower}-{source-name}-admin     — governance ops

Schema note (verified against live identityconfigs.oda.tmforum.org/v1 CRD on
<cluster>, 2026-05-27): the only fields the API server accepts under
`spec` are: `canvasSystemRole` (string), `componentRole` (array of
{name, description}), `partyRoleAPI`, `permissionSpecificationSetAPI`.
Unknown fields (`identityProvider`, `client`, `roles`) are silently pruned —
that was the OPEN-2 bug: spec landed empty because every field we wrote was
unknown to the schema. `identityProvider` / `listenerRegistered` are
populated in `status` by Canvas's identityconfig-operator-keycloak.
"""
import logging
from typing import Optional

logger = logging.getLogger("shared.identity_config")

IDENTITY_CONFIG_GROUP = "oda.tmforum.org"
IDENTITY_CONFIG_VERSION = "v1"
IDENTITY_CONFIG_PLURAL = "identityconfigs"
IDENTITY_CONFIG_API_VERSION = f"{IDENTITY_CONFIG_GROUP}/{IDENTITY_CONFIG_VERSION}"


def _build_spec(base_name: str, source_kind: str, source_name: str) -> dict:
    """Spec shape accepted by Canvas's identityconfigs.oda.tmforum.org/v1 CRD.

    Only `canvasSystemRole` and `componentRole` are populated; the optional
    *API fields are omitted (no TMF API exposed by MoDaaS-governed assets).
    """
    return {
        "canvasSystemRole": "Admin",
        "componentRole": [
            {
                "name": f"{base_name}-consumer",
                "description": f"Agent role to invoke {source_kind} {source_name}",
            },
            {
                "name": f"{base_name}-admin",
                "description": f"Governance role to manage {source_kind} {source_name}",
            },
        ],
    }


def ensure_identity_config(
    k8s_api,
    namespace: str,
    source_kind: str,
    source_name: str,
    owner_reference: Optional[dict] = None,
) -> Optional[dict]:
    """Create (or patch-to-fill if exists) an IdentityConfig CR for the asset.

    Returns the created/patched/existing object, or None on errors. Non-blocking.

    On 409 (already exists), the existing resource is patched so that
    `spec.canvasSystemRole` and `spec.componentRole` are populated even if a
    prior version of this code created the CR with an empty/wrong spec
    (OPEN-2 from DEPLOY-5 evidence).
    """
    base_name = f"modaas-{source_kind.lower()}-{source_name}"
    base_name = base_name[:253]

    spec = _build_spec(base_name, source_kind, source_name)

    body = {
        "apiVersion": IDENTITY_CONFIG_API_VERSION,
        "kind": "IdentityConfig",
        "metadata": {
            "name": base_name,
            "namespace": namespace,
            "labels": {
                "oda.tmforum.org/sourceKind": source_kind,
                "oda.tmforum.org/sourceName": source_name,
                "app.kubernetes.io/managed-by": "modaas",
            },
        },
        "spec": spec,
    }
    if owner_reference is not None:
        body["metadata"]["ownerReferences"] = [owner_reference]

    try:
        return k8s_api.create_namespaced_custom_object(
            group=IDENTITY_CONFIG_GROUP,
            version=IDENTITY_CONFIG_VERSION,
            namespace=namespace,
            plural=IDENTITY_CONFIG_PLURAL,
            body=body,
        )
    except Exception as e:
        status = getattr(e, "status", None)
        if status == 409:
            # Already exists — patch spec so legacy empty-spec resources get
            # filled in. Use merge-patch semantics; do NOT touch metadata/labels
            # to avoid clobbering Canvas-set ownership or finalizers.
            try:
                return k8s_api.patch_namespaced_custom_object(
                    group=IDENTITY_CONFIG_GROUP,
                    version=IDENTITY_CONFIG_VERSION,
                    namespace=namespace,
                    plural=IDENTITY_CONFIG_PLURAL,
                    name=base_name,
                    body={"spec": spec},
                )
            except Exception as patch_err:  # noqa: BLE001
                logger.warning(
                    "IdentityConfig for %s/%s exists but patch failed (non-blocking): %s",
                    source_kind, source_name, type(patch_err).__name__,
                )
                return None
        if status == 404:
            logger.debug(
                "IdentityConfig CRD not installed (404) for %s/%s — non-blocking",
                source_kind, source_name,
            )
            return None
        logger.warning(
            "IdentityConfig for %s/%s failed (non-blocking): %s",
            source_kind, source_name, type(e).__name__,
        )
        return None
