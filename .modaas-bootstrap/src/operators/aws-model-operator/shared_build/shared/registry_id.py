"""Registry-ID resolution for asset workloads (a design note).

An agent that self-resolves its aliases at boot needs the id of the AgentCore
registry its CR publishes to. That id used to be a literal default in
`aws-agent-operator`: `os.environ.get("REGISTRY_ID", "<one account's id>")`.
Any cluster that did not set REGISTRY_ID shipped a foreign registry id into
every managed AgentCore Runtime, and nothing on the CR said so.

Resolution order, and the reason for it:

  1. the Registry CR the asset actually uses (`spec.registryRef`). This is the
     only source that is per-asset and already the declared contract — a design note
     makes Registry a first-class backing selector, and its lifecycle handler
     caches the resolved id on `status.registryId` (adopt mode mirrors
     `spec.adoptRegistryId`). If the CR says which catalog, believe the CR.
  2. the operator's own `REGISTRY_ID` env, for a cluster with one catalog that
     predates registryRef.
  3. nothing. Return `None` and a reason. The caller MUST NOT substitute a
     guess: an agent pointed at the wrong registry fails in a way that looks
     like a permissions problem, three layers away from the cause.

Pure: the Registry read is injected, so this is unit-testable with no cluster.
"""
from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("modaas.registry_id")

GROUP = "oda.tmforum.org"
VERSION = "v1beta1"
PLURAL = "registries"
DEFAULT_REGISTRY_NAMESPACE = "modaas-system"

#: Backing kind whose records are addressed by an AgentCore `registryId`.
AGENTCORE_BACKING = "agentcore"

SOURCE_REGISTRY_CR = "registryCR"
SOURCE_ENV = "operatorEnv"
SOURCE_NONE = "unresolved"


def resolve_registry_id(
    registry_ref: Optional[dict],
    *,
    k8s_client=None,
    env_value: Optional[str] = None,
) -> tuple[Optional[str], str, str]:
    """Resolve the registry id to hand a workload.

    Args:
        registry_ref: the asset's ``spec.registryRef`` (``{name, namespace}``)
            or None.
        k8s_client: object exposing
            ``get(group, version, plural, name, namespace=None)`` — the
            operator's read-only CR reader. None skips step 1.
        env_value: the operator's ``REGISTRY_ID`` env value, or None.

    Returns:
        ``(registry_id | None, source, reason)``. ``source`` is one of
        ``registryCR`` / ``operatorEnv`` / ``unresolved``. ``reason`` is always
        populated enough to put on a status condition — including on success,
        where it names the source so an operator can see WHICH catalog won.
    """
    notes: list[str] = []
    name = (registry_ref or {}).get("name")

    if name and k8s_client is not None:
        namespace = (registry_ref or {}).get("namespace") or DEFAULT_REGISTRY_NAMESPACE
        registry_id, note = _from_registry_cr(k8s_client, name, namespace)
        if registry_id:
            return registry_id, SOURCE_REGISTRY_CR, note
        notes.append(note)

    if env_value:
        notes.append("resolved from the operator's REGISTRY_ID env")
        return env_value, SOURCE_ENV, "; ".join(notes)

    notes.append(
        "no registry id available: set spec.registryRef to a Registry CR whose "
        "status.registryId is populated, or set REGISTRY_ID on the operator "
        "Deployment. REGISTRY_ID is NOT injected into the workload."
    )
    return None, SOURCE_NONE, "; ".join(notes)


def _from_registry_cr(k8s_client, name: str, namespace: str) -> tuple[Optional[str], str]:
    """Read ``status.registryId`` / ``spec.adoptRegistryId`` off a Registry CR."""
    try:
        registry = k8s_client.get(GROUP, VERSION, PLURAL, name, namespace=namespace)
    except Exception as exc:  # noqa: BLE001 — any read failure is a fallthrough
        status = getattr(exc, "status", None)
        detail = f"HTTP {status}" if status else type(exc).__name__
        return None, (
            f"Registry '{name}' in '{namespace}' read failed ({detail})"
        )

    spec = (registry or {}).get("spec") or {}
    backing = spec.get("backing")
    if backing and backing != AGENTCORE_BACKING:
        return None, (
            f"Registry '{name}' has backing '{backing}', which has no AgentCore "
            f"registryId to publish (only '{AGENTCORE_BACKING}' does)"
        )

    registry_id = ((registry or {}).get("status") or {}).get("registryId")
    if registry_id:
        return registry_id, f"resolved from Registry '{name}'.status.registryId"

    adopted = spec.get("adoptRegistryId")
    if adopted:
        return adopted, f"resolved from Registry '{name}'.spec.adoptRegistryId"

    return None, (
        f"Registry '{name}' carries no registryId yet (status.registryId unset "
        f"and no spec.adoptRegistryId)"
    )
