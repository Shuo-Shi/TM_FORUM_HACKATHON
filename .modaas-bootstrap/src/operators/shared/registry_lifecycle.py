"""
MoDaaS Registry CRD lifecycle (a design note §"what does NOT change" follow-up, T9).

a design note shipped the Registry CRD as a data-only backing-selector (create +
resolve). This module completes the missing lifecycle legs that a design note did
not scope:

  * delete_managed_registry  -- cascade a Registry CR delete into
    bedrock-agentcore-control DeleteRegistry, blocked while APPROVED records
    remain (record deletion itself is out of scope -- see class docstring).
  * update_approval_configuration -- UpdateRegistry PATCH for the one
    documented-mutable field, spec.parameters.approvalConfiguration
    .autoApproval.
  * resolve_registry_id -- name -> registryId lookup, mirroring the private
    resolver already proven in aws-model-operator/registry_client.py
    (_AwsRegistry._ensure_registry) so this module has no import-time
    dependency on registry_client.py (Lane C's exclusive file this sprint;
    see sprint-2026-09-ga-hardening.md Lane D card).

Rule 15 discipline: every parameter name below was read directly off the
pinned botocore (1.43.86) service model for bedrock-agentcore-control, not
guessed:
    GetRegistryRequest     { registryId (required) }
    UpdateRegistryRequest  { registryId (required), name, description
                              {optionalValue}, authorizerConfiguration,
                              approvalConfiguration {optionalValue:
                              {autoApproval: bool}} }
    DeleteRegistryRequest  { registryId (required) }
    ListRegistryRecords    { registryId (required), maxResults, nextToken,
                              name, status, descriptorType }
    ListRegistries         { maxResults, nextToken, status, authorizerType }
                            -> registries[].{name, registryId, registryArn,
                              status, statusReason, ...}
Note the UpdateRegistry `approvalConfiguration` and `description` members
are each wrapped in an "Updated<Field>" structure with a single
`optionalValue` member -- an explicit-nullable pattern that lets a caller
distinguish "leave unchanged" (omit the wrapper) from "set to null"
(wrapper present, optionalValue absent). This module only ever sets
`optionalValue`, never omits-to-null.

This module intentionally does NOT import registry_client.py, backings/, or
resolver.py. It is dispatched into from a new kopf handler module
(registry_lifecycle_handlers.py) that already has spec/status/patch and
does its own Registry-CR-scoped resolution.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

from operators.shared.aws_region import resolve_region

logger = logging.getLogger("modaas.registry_lifecycle")

#: a design note: the capability, not the service name. Same id registry_client.py
#: asks for, so one table edit relocates both.
REGISTRY_CAPABILITY = "registry.control"

# Same pagination cap used by list_registries in registry_client.py --
# kept local so this module has zero import coupling to Lane C's file.
_LIST_PAGE_SIZE = 50


def _aws_clients():
    """The a design note capability factory, canonical spelling first (in-tree) then
    the pod-snapshot spelling. Two distinct module objects would mean two
    distinct client caches."""
    try:
        from operators.shared import aws_clients  # noqa: PLC0415
    except ImportError:  # pragma: no cover - pod snapshot path
        from shared import aws_clients  # noqa: PLC0415
    return aws_clients


class RegistryLifecycleError(Exception):
    """Base class for lifecycle-specific failures (not generic boto3 errors)."""


class RegistryCloudNotFound(RegistryLifecycleError):
    """The Registry CR's spec.parameters.registryName has no matching cloud
    registry. Distinct from a boto3 ResourceNotFoundException so callers can
    treat "already gone" as an idempotent success on delete."""


class RegistryDeletionBlocked(RegistryLifecycleError):
    """DeleteRegistry precondition failed: APPROVED records remain.

    Record deletion is explicitly NOT this module's job (sprint card, T9
    goal statement) -- the caller (kopf on.delete handler) surfaces this as
    a status condition + requeues; a human or a follow-on task deletes the
    records first.
    """

    def __init__(self, registry_id: str, record_count: int):
        self.registry_id = registry_id
        self.record_count = record_count
        super().__init__(
            f"registry '{registry_id}' still has {record_count} record(s); "
            "delete or deprecate them before the cloud registry can be deleted"
        )


@dataclass
class RegistryDeleteResult:
    """Outcome of delete_managed_registry -- deliberately does not raise on
    the already-absent case so on.delete handlers can no-op cleanly."""

    deleted: bool
    registry_id: Optional[str] = None
    record_count: int = 0
    already_absent: bool = False


@dataclass
class RegistryUpdateResult:
    registry_id: str
    approval_configuration: dict = field(default_factory=dict)
    status: str = ""


def resolve_registry_id(control_client, registry_name: str) -> Optional[str]:
    """Name -> registryId via ListRegistries pagination.

    Mirrors the resolution proven in
    aws-model-operator/registry_client.py::_AwsRegistry._ensure_registry,
    reimplemented here (not imported) per the sprint's file-boundary rule --
    registry_client.py is Lane C's exclusive file this sprint.

    Returns None (not an exception) when no cloud registry with that name
    exists -- callers decide idempotent-success vs. hard-error per their
    own semantics (delete treats None as already_absent; update surfaces
    RegistryCloudNotFound).
    """
    paginator = control_client.get_paginator("list_registries")
    for page in paginator.paginate(maxResults=_LIST_PAGE_SIZE):
        for r in page.get("registries", []):
            if r.get("name") == registry_name:
                return r.get("registryId")
    return None


def count_approved_records(control_client, registry_id: str) -> int:
    """Count APPROVED records in a registry via paginated ListRegistryRecords.

    Filters server-side rather than fetching everything and filtering
    client-side, since a registry's record count is unbounded.

    a design note PR 2: the standalone service replaced the flat `status` /
    `descriptorType` / `name` request members with a `filters` list of
    `{name, values}`, where `name` is one of `name | status | recordType` and
    `values` is a 1-element list (the model caps FilterValues at min=1, max=1).
    Sending `status="APPROVED"` here is a ParamValidationError, and — worse —
    catching it and falling back to an unfiltered list would silently turn a
    "zero APPROVED records" precondition into "some number of records of any
    status", which is the gate that protects DeleteRegistry.
    """
    paginator = control_client.get_paginator("list_registry_records")
    count = 0
    for page in paginator.paginate(
        registryId=registry_id,
        filters=[{"name": "status", "values": ["APPROVED"]}],
        maxResults=_LIST_PAGE_SIZE,
    ):
        count += len(page.get("registryRecords", []))
    return count


def delete_managed_registry(
    control_client,
    *,
    registry_id: Optional[str] = None,
    registry_name: Optional[str] = None,
) -> RegistryDeleteResult:
    """Cascade-delete a MANAGED (operator-created) cloud registry.

    Precondition: zero APPROVED records. If records remain, raises
    RegistryDeletionBlocked so the caller can set a DeletionBlocked
    condition with the count and requeue -- record deletion is a separate
    concern (owned by the existing per-record deprecate/delete paths in
    registry_client.py, not this task).

    Callers MUST NOT call this for adopt-mode Registries (spec.backing
    pre-exists, was not created by this operator) -- that gate lives in the
    kopf handler (registry_lifecycle_handlers.py), mirroring
    tool_operator.py's `managed is not True` fail-safe check, BEFORE this
    function is ever invoked. This function has no adopt-mode awareness by
    design: it always deletes if the precondition is met, so the caller is
    the single place that decides whether cloud deletion should happen at
    all.

    Exactly one of registry_id / registry_name must be provided.
    """
    if not registry_id and not registry_name:
        raise ValueError("delete_managed_registry requires registry_id or registry_name")

    if registry_id is None:
        registry_id = resolve_registry_id(control_client, registry_name)
        if registry_id is None:
            logger.info(
                "delete_managed_registry: no cloud registry named %r "
                "(already absent -- idempotent success)",
                registry_name,
            )
            return RegistryDeleteResult(deleted=False, already_absent=True)

    record_count = count_approved_records(control_client, registry_id)
    if record_count > 0:
        raise RegistryDeletionBlocked(registry_id, record_count)

    try:
        control_client.delete_registry(registryId=registry_id)
    except Exception as e:
        # ResourceNotFoundException class name varies by botocore generation;
        # check by name rather than importing a specific exception class,
        # matching the defensive style already used in tool_operator.py's
        # deprovision_backend (catch-log-continue on the cloud-side call).
        if type(e).__name__ in ("ResourceNotFoundException", "ValidationException"):
            logger.info(
                "delete_managed_registry: registry_id=%s already absent "
                "on delete call (%s) -- idempotent success",
                registry_id, type(e).__name__,
            )
            return RegistryDeleteResult(
                deleted=False, registry_id=registry_id,
                record_count=record_count, already_absent=True,
            )
        raise

    logger.info("delete_managed_registry: deleted registry_id=%s (0 records)", registry_id)
    return RegistryDeleteResult(deleted=True, registry_id=registry_id, record_count=0)


def update_approval_configuration(
    control_client,
    *,
    registry_id: str,
    auto_approval: bool,
) -> RegistryUpdateResult:
    """UpdateRegistry PATCH for spec.parameters.approvalConfiguration.autoApproval.

    Only this single field is treated as mutable-after-create for a managed
    Registry. spec.controller and spec.backing are immutable by CRD CEL
    (registry-v1beta1-crd.yaml x-kubernetes-validations) -- re-homing a
    Registry's owning operator or backing store is a create-new operation,
    not an in-place PATCH, so this module deliberately exposes no path to
    change those.

    The UpdateRegistryRequest.approvalConfiguration member is wrapped in an
    UpdatedApprovalConfiguration structure with a single `optionalValue`
    member (verified against the pinned botocore service model -- this is
    NOT a guess). We always populate optionalValue; the omit-wrapper-for-
    null-out path is not used since callers always supply an explicit bool.

    a design note PR 2: inside that wrapper the boolean `autoApproval` became
    `autoApprovalRules`, a list of an enum whose only member is `APPROVE_ALL`.
    The boolean still reads naturally at the call site (and on the Registry CR),
    so it is translated here rather than pushed out to every caller:
    True -> ["APPROVE_ALL"], False -> [] (the model allows min=0).
    """
    resp = control_client.update_registry(
        registryId=registry_id,
        approvalConfiguration={
            "optionalValue": {
                "autoApprovalRules": ["APPROVE_ALL"] if auto_approval else []
            }
        },
    )
    return RegistryUpdateResult(
        registry_id=resp.get("registryId", registry_id),
        approval_configuration=resp.get("approvalConfiguration", {}) or {},
        status=resp.get("status", ""),
    )


def get_registry(control_client, registry_id: str) -> dict:
    """Thin GetRegistry wrapper -- exists so handler code has one call site
    to mock, and so a future caller does not need to remember the verified
    param name (`registryId`, not `registryIdentifier`) a second time."""
    return control_client.get_registry(registryId=registry_id)


def make_control_client(region: Optional[str] = None):
    """Registry control-plane client, via the a design note capability factory.

    Previously this duplicated `boto3.client("bedrock-agentcore-control", ...)`
    "intentionally per the sprint's file-boundary instruction" -- one of the
    seven places the service name was typed out, and one of the places that
    would have had to be found by grep when Registry's operations moved to the
    standalone `agent-registry-control` service. The capability id is the same
    one registry_client.py asks for, so both resolve through one table.
    """
    return _aws_clients().client(
        REGISTRY_CAPABILITY,
        resolve_region(region),
    )
