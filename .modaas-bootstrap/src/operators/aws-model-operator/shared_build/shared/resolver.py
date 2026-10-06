"""
MoDaaS Registry resolver (a design note).

Translates an asset CR's `spec.registryRef` (name + namespace) into a
(backing_kind, parameters) tuple that the operator can dispatch on.

Resolution chain:
  1. registryRef.name provided → look up that Registry CR via K8s API
  2. No registryRef → find annotated default Registry in modaas-system
  3. No default Registry found → raise NoRegistryConfigured

Controller filtering: only Registries whose `spec.controller` is in the calling
operator's accepted set are resolved. Others raise UnsupportedController (same
pattern as IngressClass / GatewayClass).

`spec.controller` names the controller IMPLEMENTATION, not one binary — exactly
as IngressClass's `spec.controller` is `k8s.io/ingress-nginx` for every replica
and every deployment of nginx-ingress. The MoDaaS AWS reference implementation
is three cooperating operators over one shared catalog, so each of them accepts
a SET of names:

  * REFERENCE_IMPL_CONTROLLER — the shipped implementation-level identity, which
    every live Registry carries and which `spec.controller`'s immutability CEL
    makes impossible to rename in place. All three operators accept it.
  * its own CONTROLLER_BY_RECORD_TYPE entry, so a deployment that wants
    per-operator Registries can have them.
  * anything in the MODAAS_REGISTRY_CONTROLLERS env var (comma-separated), for a
    sibling operator adopting a differently-named Registry without a rebuild.

Before this, the module-level default applied to all three operators, so the
tool and agent operators raised UnsupportedController for every Registry and
a design note dispatch was model-only in practice. See
`operators/shared/tests/test_controller_identity.py`.
"""
from __future__ import annotations

import logging
import os
from typing import Iterable, Optional, Union

logger = logging.getLogger("modaas.resolver")

DEFAULT_REGISTRY_NAMESPACE = "modaas-system"
DEFAULT_REGISTRY_NAME = "default"
DEFAULT_ANNOTATION = "modaas.tmforum.org/is-default-registry"

# The AWS reference implementation's identity. Named for the model operator for
# historical reasons (it shipped first); it denotes the three-operator
# implementation as a whole, and live Registries carry it.
REFERENCE_IMPL_CONTROLLER = "aws-model-operator.modaas"

# Back-compat alias. Imported by existing tests and by sibling code.
MODAAS_CONTROLLER = REFERENCE_IMPL_CONTROLLER

# Optional per-operator identities, for deployments that want a Registry scoped
# to one asset kind.
CONTROLLER_BY_RECORD_TYPE = {
    "model": "aws-model-operator.modaas",
    "tool": "aws-tool-operator.modaas",
    "agent": "aws-agent-operator.modaas",
}

# Comma-separated extra controller names this operator should claim.
CONTROLLERS_ENV = "MODAAS_REGISTRY_CONTROLLERS"


def controllers_for(record_type: Optional[str] = None) -> tuple[str, ...]:
    """Return the controller names an operator handling `record_type` accepts.

    Order is deterministic (own identity first, then the reference-impl name,
    then env additions) and duplicate-free, so error messages are stable.
    """
    accepted: list[str] = []
    own = CONTROLLER_BY_RECORD_TYPE.get(record_type or "")
    for name in (own, REFERENCE_IMPL_CONTROLLER):
        if name and name not in accepted:
            accepted.append(name)
    for extra in os.environ.get(CONTROLLERS_ENV, "").split(","):
        extra = extra.strip()
        if extra and extra not in accepted:
            accepted.append(extra)
    return tuple(accepted)

GROUP = "oda.tmforum.org"
VERSION = "v1beta1"
PLURAL = "registries"


class RegistryNotFound(Exception):
    """The named Registry CR does not exist."""


class NoRegistryConfigured(Exception):
    """No registryRef given AND no default Registry CR annotated."""


class UnsupportedController(Exception):
    """The Registry CR is owned by a different controller."""


def resolve_registry(
    registry_ref: Optional[dict],
    *,
    controller: Union[str, Iterable[str]] = MODAAS_CONTROLLER,
    k8s_client=None,
) -> tuple[str, dict]:
    """Resolve an asset CR's registryRef into (backing_kind, parameters).

    Args:
        registry_ref: spec.registryRef from the asset CR, or None.
        controller: controller identifier(s) this caller accepts. A single
            string (the sibling-operator call shape) or an iterable of names
            (use `controllers_for(record_type)`).
        k8s_client: kubernetes.client.CustomObjectsApi() — injected for tests.

    Returns:
        (backing_kind: str, parameters: dict)

    Raises:
        RegistryNotFound, NoRegistryConfigured, UnsupportedController.
    """
    if k8s_client is None:
        from kubernetes import client as _k8s_client
        k8s_client = _k8s_client.CustomObjectsApi()

    name = (registry_ref or {}).get("name")
    ns = (registry_ref or {}).get("namespace", DEFAULT_REGISTRY_NAMESPACE)

    if name:
        reg = _get_registry(k8s_client, name, ns)
        if reg is None:
            raise RegistryNotFound(f"Registry '{name}' not found in ns '{ns}'")
    else:
        # Find annotated default in modaas-system
        reg = _find_default_registry(k8s_client, DEFAULT_REGISTRY_NAMESPACE)
        if reg is None:
            raise NoRegistryConfigured(
                f"No registryRef and no Registry CR annotated "
                f"'{DEFAULT_ANNOTATION}=true' in '{DEFAULT_REGISTRY_NAMESPACE}'"
            )

    accepted = (controller,) if isinstance(controller, str) else tuple(controller)

    spec = reg.get("spec", {})
    registry_controller = spec.get("controller")
    if registry_controller not in accepted:
        raise UnsupportedController(
            f"Registry '{reg['metadata']['name']}' is owned by "
            f"controller='{registry_controller}' (we accept {list(accepted)})"
        )

    backing_kind = spec.get("backing")
    parameters = spec.get("parameters", {})
    return backing_kind, parameters


def _get_registry(k8s_client, name: str, namespace: str) -> Optional[dict]:
    """Fetch a Registry CR by name. Returns None on 404."""
    try:
        return k8s_client.get_namespaced_custom_object(
            group=GROUP, version=VERSION,
            namespace=namespace, plural=PLURAL, name=name,
        )
    except Exception as e:
        # 404 on not-found
        status = getattr(e, "status", None)
        if status == 404:
            return None
        # Re-raise other API errors
        raise


def _find_default_registry(k8s_client, namespace: str) -> Optional[dict]:
    """Find the Registry CR annotated as default in the given namespace."""
    try:
        resp = k8s_client.list_namespaced_custom_object(
            group=GROUP, version=VERSION,
            namespace=namespace, plural=PLURAL,
        )
    except Exception as e:
        logger.warning(f"list_namespaced_custom_object failed: {e}")
        return None

    for item in resp.get("items", []):
        annotations = (item.get("metadata", {}) or {}).get("annotations", {}) or {}
        if annotations.get(DEFAULT_ANNOTATION) == "true":
            return item
    return None
