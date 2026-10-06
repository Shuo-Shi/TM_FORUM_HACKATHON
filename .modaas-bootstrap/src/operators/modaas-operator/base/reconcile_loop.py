"""Shared reconcile loop for MoDaaS v2 AssetConfig operator.

This is the heart of the operator: on every AssetConfig create/update it:
  1. Honors spec.paused
  2. Dispatches to the right plugin via registry.get(kind, provider)
  3. Validates cross-asset dependencies
  4. Calls plugin.provision() and merges the ProvisionResult into status
  5. Writes the registry record (if the plugin emits one)
  6. Transitions phase to Approved

On delete (finalizer-driven), it calls plugin.deprovision() and deprecates
the registry record.

Plugin code is 100% business logic. The base class owns the contract."""

import datetime as dt
import logging
import os
from dataclasses import asdict

import boto3
import kopf

from base.provider import (
    AssetProvider,
    ProvisionResult,
    ProvisioningFailed,
    ReconcileContext,
    Condition,
)
from base.k8s_client import KubeClient, DependencyResolver, GROUP, V2_VERSION, ASSETCONFIGS_PLURAL
from base.registry_client import RegistryClient, build_registry_record
from providers import registry

logger = logging.getLogger("base.reconcile")

FINALIZER = f"{GROUP}/assetconfig-finalizer"
MIGRATION_ANNOTATION = "modaas.tmforum.org/migrated-from"


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _stamp_condition(patch, cond: Condition):
    """Merge a condition into status.conditions[] (upsert-by-type)."""
    existing = list(patch.status.get("conditions", []) or [])
    for i, c in enumerate(existing):
        if c.get("type") == cond.type:
            if c.get("status") != cond.status:
                existing[i] = {
                    "type": cond.type,
                    "status": cond.status,
                    "reason": cond.reason,
                    "message": cond.message,
                    "lastTransitionTime": _now_iso(),
                }
            else:
                existing[i]["reason"] = cond.reason
                existing[i]["message"] = cond.message
            patch.status["conditions"] = existing
            return
    existing.append({
        "type": cond.type,
        "status": cond.status,
        "reason": cond.reason,
        "message": cond.message,
        "lastTransitionTime": _now_iso(),
    })
    patch.status["conditions"] = existing


def _stamp_common(patch, meta, spec):
    patch.status["kind"] = spec.get("kind")
    patch.status["provider"] = spec.get("provider")
    patch.status["observedGeneration"] = meta.get("generation", 1)
    patch.status["lastReconciled"] = _now_iso()


def _days_until_retirement(retire_iso: str | None) -> int | None:
    if not retire_iso:
        return None
    try:
        retire = dt.date.fromisoformat(retire_iso)
    except ValueError:
        return None
    return (retire - dt.date.today()).days


def _build_ctx(namespace: str, name: str, spec: dict) -> ReconcileContext:
    """Construct the ReconcileContext handed to a plugin."""
    k8s = KubeClient()
    # Region resolution: plugin-specific typed block may carry region, else spec-level,
    # else env default. Plugins can override via ctx.boto3_client with explicit region.
    region = (
        spec.get(spec.get("kind", ""), {}).get("awsBedrock", {}).get("region") or
        spec.get(spec.get("kind", ""), {}).get("region") or
        os.environ.get("AWS_REGION", "us-west-2")
    )
    return ReconcileContext(
        namespace=namespace,
        name=name,
        region=region,
        aws_session=boto3.Session(),
        k8s=k8s,
        dependency_resolver=DependencyResolver(k8s, namespace),
        logger=logger,
    )


def _validate_dependencies(spec: dict, ctx: ReconcileContext) -> list[dict]:
    """Ensure every spec.dependsOn[*] ref points to an Approved AssetConfig.

    Returns dependencyStatus[] for status. Raises ProvisioningFailed if any
    dependency is missing or not Approved."""
    deps_status = []
    for dep in spec.get("dependsOn", []) or []:
        kind = dep.get("kind")
        name = dep.get("name")
        try:
            phase = ctx.dependency_resolver.phase_of(kind, name)
        except LookupError as e:
            raise ProvisioningFailed("DependencyMissing", str(e))
        deps_status.append({"ref": {"kind": kind, "name": name}, "phase": phase})
        if phase != "Approved":
            raise ProvisioningFailed(
                "DependencyNotApproved",
                f"{kind}/{name} is in phase={phase}, must be Approved",
            )
    return deps_status


def reconcile(spec, status, meta, namespace, name, patch, **_):
    """Primary reconcile handler for AssetConfig v2alpha1 create/update/resume."""
    annotations = (meta.get("annotations") or {})
    if MIGRATION_ANNOTATION in annotations:
        logger.debug(f"[skip-migration-mirror] {namespace}/{name} owned by v1 operator")
        return

    # 0. Common stamping
    _stamp_common(patch, meta, spec)

    kind = spec.get("kind")
    provider = spec.get("provider")

    # Pause
    if spec.get("paused"):
        patch.status["phase"] = "Paused"
        patch.status["reason"] = "SpecPaused"
        _stamp_condition(patch, Condition("ReconcilePaused", "True", "SpecPaused", "spec.paused=true"))
        return {"message": "paused"}

    # 1. Plugin lookup
    try:
        plugin: AssetProvider = registry.get(kind, provider)
    except LookupError as e:
        patch.status["phase"] = "Failed"
        patch.status["reason"] = "UnsupportedProvider"
        _stamp_condition(patch, Condition("Approved", "False", "UnsupportedProvider", str(e)))
        return {"error": str(e)}

    # 2. Build ReconcileContext
    ctx = _build_ctx(namespace, name, spec)

    # 3. Optional plugin-level validation
    validation_errors = plugin.validate_spec(spec)
    if validation_errors:
        msg = "; ".join(validation_errors)
        patch.status["phase"] = "Failed"
        patch.status["reason"] = "ValidationFailed"
        _stamp_condition(patch, Condition("Approved", "False", "ValidationFailed", msg))
        return {"error": msg}

    # 4. Dependency validation (cross-asset governance — Req 41)
    try:
        dep_status = _validate_dependencies(spec, ctx)
    except ProvisioningFailed as e:
        patch.status["phase"] = "Failed"
        patch.status["reason"] = e.reason
        _stamp_condition(patch, Condition("DependenciesResolved", "False", e.reason, e.message))
        return {"error": f"{e.reason}: {e.message}"}
    patch.status["dependencyStatus"] = dep_status
    if dep_status:
        _stamp_condition(patch, Condition(
            "DependenciesResolved", "True", "AllApproved",
            f"{len(dep_status)} deps satisfied",
        ))

    # 5. Plugin provisioning
    patch.status["phase"] = "Configuring"
    try:
        result: ProvisionResult = plugin.provision(spec, status or {}, ctx)
    except ProvisioningFailed as e:
        patch.status["phase"] = "Failed"
        patch.status["reason"] = e.reason
        _stamp_condition(patch, Condition("Provisioned", "False", e.reason, e.message))
        return {"error": f"{e.reason}: {e.message}"}
    except Exception as e:
        # Unexpected — log and re-raise so kopf backs off
        logger.exception(f"{plugin._log_prefix(ctx)} unexpected provision error: {e}")
        raise

    # 6. Apply ProvisionResult to status
    patch.status["resources"] = [r.to_dict() for r in result.resources]
    for cond in result.conditions:
        _stamp_condition(patch, cond)
    if result.plugin_status:
        patch.status["pluginStatus"] = result.plugin_status
    _stamp_condition(patch, Condition("Provisioned", "True", "BackendReady", "Provider backend ready"))

    # 7. Registry projection
    if plugin.emits_registry_record:
        try:
            record = build_registry_record(
                kind=kind,
                provider=provider,
                name=name,
                description=spec.get("description", ""),
                governance=spec.get("governance", {}),
                plugin_metadata=result.registry_metadata or {},
            )
            rc = RegistryClient(region=ctx.region)
            rc.put_record(record)
            patch.status["registryRecordId"] = record["name"]
            _stamp_condition(patch, Condition(
                "RegistryRegistered", "True", "Registered",
                f"Record {record['name']} APPROVED",
            ))
        except Exception as e:
            logger.exception(f"{plugin._log_prefix(ctx)} registry write failed: {e}")
            patch.status["phase"] = "Failed"
            patch.status["reason"] = "RegistryRegistrationFailed"
            _stamp_condition(patch, Condition(
                "RegistryRegistered", "False", "RegistryFailed", str(e)[:200]
            ))
            return {"error": f"registry failed: {e}"}

    # 8. Retirement
    retire_days = _days_until_retirement(spec.get("governance", {}).get("retirementDate"))
    if retire_days is not None:
        patch.status["daysUntilRetirement"] = retire_days
        if retire_days <= 0 and plugin.supports_retire:
            _stamp_condition(patch, Condition(
                "RetirementDue", "True", "PastRetirement",
                f"retired {-retire_days} days ago",
            ))
            if plugin.emits_registry_record:
                RegistryClient(region=ctx.region).deprecate(patch.status.get("registryRecordId", ""))
            patch.status["phase"] = "Retired"
            return {"message": "retired"}
        elif retire_days <= 30:
            _stamp_condition(patch, Condition(
                "RetirementDue", "True", "ApproachingRetirement",
                f"retiring in {retire_days} days",
            ))

    # 9. Final phase
    patch.status["phase"] = "Approved"
    patch.status["reason"] = "Approved"
    _stamp_condition(patch, Condition("Approved", "True", "AllStepsComplete",
                                      f"{kind}/{provider} asset ready"))

    logger.info(f"{plugin._log_prefix(ctx)} reconciled → Approved")
    return {"message": "reconciled"}


def on_delete(spec, status, meta, namespace, name, **_):
    """Deletion handler — call plugin.deprovision and deprecate registry record."""
    if MIGRATION_ANNOTATION in (meta.get("annotations") or {}):
        return  # owned by v1

    kind = spec.get("kind")
    provider = spec.get("provider")
    try:
        plugin = registry.get(kind, provider)
    except LookupError:
        logger.warning(f"on_delete {namespace}/{name}: no plugin for {kind}/{provider}, skipping")
        return

    ctx = _build_ctx(namespace, name, spec)

    # Deprovision AWS resources first
    try:
        plugin.deprovision(status or {}, ctx)
    except Exception as e:
        logger.exception(f"{plugin._log_prefix(ctx)} deprovision error (continuing): {e}")

    # Deprecate registry record
    if plugin.emits_registry_record and (status or {}).get("registryRecordId"):
        try:
            RegistryClient(region=ctx.region).deprecate(status["registryRecordId"])
        except Exception as e:
            logger.warning(f"registry deprecate failed: {e}")

    logger.info(f"{plugin._log_prefix(ctx)} deleted")
