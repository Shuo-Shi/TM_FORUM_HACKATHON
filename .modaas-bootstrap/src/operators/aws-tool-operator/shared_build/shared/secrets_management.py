"""a design note — SecretsManagement-backed credentials (Bucket 2 — pre-DTW directive).

Optional credential backend: K8s Secret (default, simple) or Vault via
Canvas SecretsManagement (enterprise). When a credentialRef declares
backend=vault, MoDaaS asks Canvas's SecretsManagement to materialize the
Vault path as a K8s Secret in the cluster, then any operator/gateway code
that reads Secrets continues to work unchanged.

Request shape (passed to ensure_secrets_management):
  credentialRef:
    backend: vault
    secretsManagementRef:
      name: modaas-databricks-creds
      namespace: components       # optional, defaults to caller's namespace
    path: /secret/data/modaas/databricks-modaas-sp
    keys: [client_id, client_secret]

Backend = k8sSecret → no-op (caller reads K8s Secret directly).
Backend = vault    → ensure SecretsManagement CR exists; Canvas materializes.
"""
import logging
from typing import Optional

logger = logging.getLogger("shared.secrets_management")

SECRETS_MANAGEMENT_GROUP = "oda.tmforum.org"
SECRETS_MANAGEMENT_VERSION = "v1"
SECRETS_MANAGEMENT_PLURAL = "secretsmanagements"
SECRETS_MANAGEMENT_API_VERSION = (
    f"{SECRETS_MANAGEMENT_GROUP}/{SECRETS_MANAGEMENT_VERSION}"
)


def ensure_secrets_management(
    k8s_api,
    namespace: str,
    source_name: str,
    credential_ref: dict,
    owner_reference: Optional[dict] = None,
) -> Optional[dict]:
    """Materialize a Vault-backed credential into a K8s Secret via Canvas
    SecretsManagement, if credentialRef.backend=vault.

    Returns the SecretsManagement CR (or None for k8sSecret backend / no-op /
    errors). Caller continues to read the K8s Secret named in credentialRef.
    Non-blocking.
    """
    backend = (credential_ref or {}).get("backend", "k8sSecret")
    if backend == "k8sSecret":
        # No-op: caller reads K8s Secret directly. Default behavior.
        return None
    if backend != "vault":
        logger.warning("Unsupported credentialRef.backend=%s for %s", backend, source_name)
        return None

    smref = credential_ref.get("secretsManagementRef") or {}
    sm_name = smref.get("name")
    sm_namespace = smref.get("namespace", namespace)
    vault_path = credential_ref.get("path")
    keys = credential_ref.get("keys") or []
    if not sm_name or not vault_path:
        logger.warning(
            "vault-backed credentialRef for %s missing secretsManagementRef.name or path",
            source_name,
        )
        return None

    body = {
        "apiVersion": SECRETS_MANAGEMENT_API_VERSION,
        "kind": "SecretsManagement",
        "metadata": {
            "name": sm_name,
            "namespace": sm_namespace,
            "labels": {
                "oda.tmforum.org/sourceName": source_name,
                "app.kubernetes.io/managed-by": "modaas",
            },
        },
        "spec": {
            "vault": {
                "path": vault_path,
                "keys": keys,
            },
            "materializeAs": {
                "kind": "Secret",
                "name": sm_name,
                "namespace": namespace,
            },
        },
    }
    if owner_reference is not None:
        body["metadata"]["ownerReferences"] = [owner_reference]

    try:
        return k8s_api.create_namespaced_custom_object(
            group=SECRETS_MANAGEMENT_GROUP,
            version=SECRETS_MANAGEMENT_VERSION,
            namespace=sm_namespace,
            plural=SECRETS_MANAGEMENT_PLURAL,
            body=body,
        )
    except Exception as e:
        status = getattr(e, "status", None)
        if status in (404, 409):
            logger.debug(
                "SecretsManagement for %s status=%s (non-blocking)", source_name, status,
            )
            return None
        logger.warning(
            "SecretsManagement for %s failed (non-blocking): %s",
            source_name, type(e).__name__,
        )
        return None
