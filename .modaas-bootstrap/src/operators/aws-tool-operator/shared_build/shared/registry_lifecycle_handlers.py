"""
MoDaaS Registry CR lifecycle handlers (a design note follow-up, T9).

Prior to this module, `registries.oda.tmforum.org` had exactly ONE kopf
registration in the entire codebase: `registry_health.probe_registry_health`,
a `@kopf.timer`. There was no `@kopf.on.create` / `@kopf.on.update` /
`@kopf.on.delete` for the Registry kind anywhere across the three operators
(verified: `grep -rn "@kopf\\." operators/*/ --include="*.py" | grep -i
registr` returns only the timer). Because kopf only installs its
finalizer-protection machinery on a resource kind once `@kopf.on.delete` is
registered for it, Registry CRs had NO finalizer -- `kubectl delete
registry/x` would remove the K8s object immediately with no chance for this
operator (or any operator) to react, regardless of what the cloud-side
registry or its records looked like.

This module is the first `on.create` / `on.update` / `on.delete` for the
Registry kind. Registering `@kopf.on.delete` is what causes kopf to add its
finalizer to new/reconciled Registry CRs automatically -- no manual
`metadata.finalizers` array manipulation is needed or done here, matching
the convention already used by all three asset operators' own
`@kopf.on.delete` handlers (model_operator.py:1094, tool_operator.py:1142,
agent_operator.py:1482 -- none of which hand-roll a finalizer string either).

Adopt-mode vs managed-mode mirrors tool_operator.py's ToolConfig convention
exactly (status["managed"], fail-safe `is not True` check at delete time --
see tool_operator.py::deprovision_backend). A Registry CR adopts a
pre-existing cloud registry via `spec.adoptRegistryId`; the operator then
never creates, updates (beyond CR status), or deletes that cloud registry.

Imported at operator startup the same way registry_health is:
    from operators.shared import registry_lifecycle_handlers  # noqa: F401
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

try:
    import kopf
except ImportError:
    kopf = None  # type: ignore  # unit tests run without kopf installed

from operators.shared.registry_lifecycle import (
    RegistryCloudNotFound,
    RegistryDeletionBlocked,
    delete_managed_registry,
    make_control_client,
    resolve_registry_id,
    update_approval_configuration,
)

logger = logging.getLogger("registry_lifecycle_handlers")

GROUP = "oda.tmforum.org"
VERSION = "v1beta1"
PLURAL = "registries"

# Same controller-filter convention as resolver.py / registry_health.py --
# only react to Registry CRs this operator owns.
OWNED_CONTROLLER = "aws-model-operator.modaas"


def _kopf_on(event: str):
    """Apply the matching kopf.on.<event> decorator only when kopf is
    importable (mirrors registry_health.py's `_kopf_timer_decorator` no-op
    pattern for unit-test environments without kopf installed)."""

    def _decorator(func):
        if kopf is not None:
            handler = getattr(kopf.on, event)
            return handler(GROUP, VERSION, PLURAL, retries=5)(func)
        return func

    return _decorator


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seed_conditions(patch, status) -> None:
    """Copy the live status.conditions into the patch before any upsert.

    Same contract as AssetOperator._seed_conditions (kept local so this module
    stays importable without the asset operator's dependencies). `_set_condition`
    below upserts into `patch.status["conditions"]`, and a kopf patch starts
    empty, so without this a handler that sets one condition sends a one-element
    list and the apiserver replaces the CR's list with it.
    Sensor: operators/shared/tests/test_handlers_keep_conditions.py
    """
    if patch.status.get("conditions"):
        return
    existing = list((status or {}).get("conditions") or [])
    if existing:
        patch.status["conditions"] = existing


def _set_condition(patch_status: dict, cond_type: str, cond_status: str,
                    reason: str, message: str) -> None:
    """Upsert one condition, preserving conditions this call did not touch.

    Mirrors asset_operator.py::AssetOperator._set_condition byte-for-byte in
    shape (type/status/reason/message/lastTransitionTime) and in the same
    upsert-not-replace discipline that module's docstring calls out as the
    fix for a real prior bug (a handler that sets one condition previously
    wiped every other condition because a status patch REPLACES the list).
    Registry CRs did not have any condition-writing handler before this
    module, so there is no pre-existing list to preserve on CREATE, but the
    UPDATE and DELETE handlers below run on a CR that the timer probe may
    have already patched (status.phase/lastProbed/recordCount/message are
    plain fields, not conditions, so no overlap risk there either way).
    """
    conds = list(patch_status.get("conditions") or [])
    cond = {
        "type": cond_type, "status": cond_status, "reason": reason,
        "message": message, "lastTransitionTime": _now_iso(),
    }
    for i, c in enumerate(conds):
        if c.get("type") == cond_type:
            conds[i] = cond
            patch_status["conditions"] = conds
            return
    conds.append(cond)
    patch_status["conditions"] = conds


def _is_adopt_mode(spec: dict) -> bool:
    """A Registry CR is in adopt mode iff spec.adoptRegistryId is set and
    non-empty. Mirrors tool_operator.py's `adoptTargetId` field convention
    (agentCoreGateway.adoptTargetId -> read-only, operator never creates,
    updates, or deletes the backing resource)."""
    return bool((spec.get("adoptRegistryId") or "").strip())


def _registry_name(spec: dict) -> Optional[str]:
    return (spec.get("parameters") or {}).get("registryName")


@_kopf_on("create")
async def on_registry_create(spec, patch, name, namespace, status=None, **_):
    """CREATE: stamp status.managed so delete-time logic (this module and
    any future consumer of the field) never has to guess adopt-vs-managed
    from spec shape alone. status.managed=False for adopt mode, True
    otherwise -- same boolean semantics as ToolConfig's status.managed.

    This handler does NOT call CreateRegistry. a design note's existing dispatch
    (backings/agentcore.py via the asset operators) creates cloud registries
    today as a side effect of the FIRST asset record being published to a
    Registry that resolves to a not-yet-existing cloud registry name
    (registry_client.py::_ensure_registry falls through to create when no
    matching name is found in ListRegistries -- see that method's
    docstring). Duplicating registry creation here would race that path.
    T9's scope is Get/Update/Delete lifecycle completion, not Create.
    """
    if spec.get("controller") != OWNED_CONTROLLER:
        return  # not ours (IngressClass-style filter, same as registry_health)
    _seed_conditions(patch, status)

    managed = not _is_adopt_mode(spec)
    patch.status["managed"] = managed
    if _is_adopt_mode(spec):
        _set_condition(
            patch.status, "RegistryAdopted", "True", "AdoptRegistryIdSet",
            f"adopting pre-existing cloud registry (adoptRegistryId="
            f"{spec.get('adoptRegistryId')!r}); operator will not create, "
            f"update, or delete the backing cloud registry",
        )
    logger.info(
        "on_registry_create %s/%s: managed=%s", namespace, name, managed,
    )
    return {"managed": managed}


@_kopf_on("update")
async def on_registry_update(spec, status, patch, name, namespace, **_):
    """UPDATE: reconcile spec.parameters.approvalConfiguration.autoApproval
    against the cloud registry via UpdateRegistry, for MANAGED registries
    only. Adopt-mode registries never get an UpdateRegistry call -- the
    operator does not own the cloud-side config of a registry it did not
    create, matching the same "read-only" stance tool_operator.py takes for
    adopted Gateway targets (adopt mode there also skips all write calls,
    not just delete).

    spec.controller and spec.backing are immutable at admission (CRD CEL in
    registry-v1beta1-crd.yaml), so this handler never needs to detect or
    reject a re-home attempt -- the API server already rejected it before
    this handler runs.
    """
    if spec.get("controller") != OWNED_CONTROLLER:
        return
    _seed_conditions(patch, status)

    if _is_adopt_mode(spec):
        logger.info(
            "on_registry_update %s/%s: adopt mode, skipping UpdateRegistry",
            namespace, name,
        )
        return {"skipped": "adopt-mode"}

    approval_cfg = (spec.get("parameters") or {}).get("approvalConfiguration")
    if approval_cfg is None or "autoApproval" not in approval_cfg:
        # Nothing to reconcile -- most Registry CRs never set this key.
        return {"skipped": "no-approvalConfiguration"}

    registry_name = _registry_name(spec)
    if not registry_name:
        _set_condition(
            patch.status, "ApprovalConfigSynced", "False", "NoRegistryName",
            "spec.parameters.registryName is required to resolve the cloud "
            "registry for an UpdateRegistry call",
        )
        return {"error": "no-registry-name"}

    try:
        client = make_control_client((spec.get("parameters") or {}).get("region"))
        registry_id = (status or {}).get("registryId") or resolve_registry_id(
            client, registry_name
        )
        if registry_id is None:
            raise RegistryCloudNotFound(
                f"no cloud registry named {registry_name!r} yet -- it may "
                f"not have been created by the first-record-publish path yet"
            )
        result = update_approval_configuration(
            client, registry_id=registry_id,
            auto_approval=bool(approval_cfg["autoApproval"]),
        )
    except RegistryCloudNotFound as e:
        _set_condition(
            patch.status, "ApprovalConfigSynced", "False", "RegistryNotYetCreated",
            str(e)[:1024],
        )
        return {"error": "registry-not-found"}
    except Exception as e:
        logger.warning(
            "on_registry_update %s/%s: UpdateRegistry failed: %s",
            namespace, name, e,
        )
        _set_condition(
            patch.status, "ApprovalConfigSynced", "False",
            type(e).__name__, str(e)[:1024],
        )
        return {"error": str(e)}

    patch.status["registryId"] = result.registry_id
    _set_condition(
        patch.status, "ApprovalConfigSynced", "True", "UpdateRegistryApplied",
        f"autoApproval={approval_cfg['autoApproval']}",
    )
    logger.info(
        "on_registry_update %s/%s: approvalConfiguration synced "
        "(autoApproval=%s)", namespace, name, approval_cfg["autoApproval"],
    )
    return {"approvalConfiguration": result.approval_configuration}


@_kopf_on("delete")
async def on_registry_delete(spec, status, patch, name, namespace, **_):
    """DELETE: cascade to DeleteRegistry for MANAGED registries with zero
    APPROVED records. Registering this handler is what causes kopf to
    attach its finalizer to Registry CRs (see module docstring) -- before
    this module existed, Registry CRs had no finalizer and deleted
    instantly with no cloud-side reaction.

    Three exits, in priority order:
      1. adopt mode                    -> return immediately, no cloud call
      2. records remain (blocked)       -> set a DeletionBlocked condition
                                           with the count on the CR, then
                                           raise kopf.TemporaryError so kopf
                                           requeues the delete instead of
                                           removing the finalizer; the CR
                                           stays present until records are
                                           cleared
      3. zero records / already absent -> DeleteRegistry, finalizer released

    Record deletion is explicitly out of scope for this task (sprint card:
    "record deletion is NOT this task's job") -- case 2 blocks and waits
    for whatever process (human, or the existing per-record deprecate path)
    clears the records, then the NEXT delete-retry (kopf's automatic
    backoff-retry on TemporaryError) succeeds via case 3.

    Takes `patch` (unlike the other two asset operators' on.delete
    handlers, which are typically fire-and-forget cleanup with no need to
    leave status behind on a CR that is about to disappear) specifically
    for case 2: a BLOCKED delete leaves the CR present, so the condition it
    writes is genuinely visible to `kubectl get registry -o yaml` for
    whoever needs to go clear the records.
    """
    if spec.get("controller") != OWNED_CONTROLLER:
        return
    _seed_conditions(patch, status)

    if _is_adopt_mode(spec):
        logger.info(
            "on_registry_delete %s/%s: adopt mode (adoptRegistryId=%s) -- "
            "leaving cloud registry intact, operator never created it",
            namespace, name, spec.get("adoptRegistryId"),
        )
        return {"skipped": "adopt-mode"}

    managed = (status or {}).get("managed", True)  # fail-safe default, mirrors
    # tool_operator.py::deprovision_backend's `managed = status.get("managed", True)`
    # comment verbatim: "default True for backward compat" for CRs that predate
    # this handler and never got status.managed stamped by on_registry_create.
    if managed is not True:
        logger.info(
            "on_registry_delete %s/%s: status.managed=%r (adopt-mode signal "
            "via status rather than spec) -- skipping DeleteRegistry",
            namespace, name, managed,
        )
        return {"skipped": "adopt-mode-via-status"}

    registry_name = _registry_name(spec)
    if not registry_name:
        logger.warning(
            "on_registry_delete %s/%s: no spec.parameters.registryName -- "
            "cannot resolve a cloud registry to delete; releasing finalizer "
            "without a cloud-side call (nothing to clean up)",
            namespace, name,
        )
        return {"skipped": "no-registry-name"}

    client = make_control_client((spec.get("parameters") or {}).get("region"))
    registry_id = (status or {}).get("registryId")

    try:
        result = delete_managed_registry(
            client, registry_id=registry_id, registry_name=registry_name,
        )
    except RegistryDeletionBlocked as e:
        logger.info(
            "on_registry_delete %s/%s: BLOCKED -- %d record(s) remain on "
            "registry_id=%s; requeueing delete (kopf backoff)",
            namespace, name, e.record_count, e.registry_id,
        )
        # Best-effort status write. Per kopf's own documented pattern for
        # this exact situation (nolar/kopf issue #693 -- "since there is no
        # traditional return value [when raising TemporaryError], one has
        # to accept the patch argument to the handler and add values in
        # that mapping to have them set"), kopf applies `patch` even when
        # the handler goes on to raise TemporaryError/PermanentError.
        patch.status["deletionBlockedReason"] = (
            f"{e.record_count} record(s) remain on registry '{e.registry_id}'"
        )
        patch.status["deletionBlockedRecordCount"] = e.record_count
        _set_condition(
            patch.status, "DeletionBlocked", "True", "RecordsRemain",
            str(e)[:1024],
        )
        if kopf is not None:
            # TemporaryError keeps the finalizer in place and retries later
            # instead of failing the delete permanently.
            raise kopf.TemporaryError(
                f"DeletionBlocked: {e.record_count} record(s) remain on "
                f"registry '{e.registry_id}'; delete or deprecate them first",
                delay=60,
            )
        raise

    if result.already_absent:
        logger.info(
            "on_registry_delete %s/%s: cloud registry already absent -- "
            "idempotent success",
            namespace, name,
        )
    else:
        logger.info(
            "on_registry_delete %s/%s: DeleteRegistry succeeded for "
            "registry_id=%s",
            namespace, name, result.registry_id,
        )
    return {"deleted": result.deleted, "already_absent": result.already_absent}
