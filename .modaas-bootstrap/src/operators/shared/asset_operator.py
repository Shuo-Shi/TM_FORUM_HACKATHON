"""AssetOperator — Abstract base class for MoDaaS asset lifecycle operators.

Shared reconciliation logic for ModelConfig, ToolConfig, and AgentConfig.
Subclasses implement provision_backend() and deprovision_backend() for
provider-specific work. The base class owns the governance contract:
state machine, generation stamping, condition management, registry
registration, pause/retirement handling.

Lifecycle ordering (bug #17 fix preserved):
  provision_backend() FIRST → status written → _register_in_registry() AFTER phase=Approved

a design note (2026-05-30) — Pending → Reviewing → Approved governance gate. The
reconcile path inserts a ``Reviewing`` phase between structural validation
(a design note / a design note / a design note) and provisioning. ``status.governance.approvals[]``
is materialized from operator-side annotations (mechanism-agnostic submission
per §4) and the ``check_approval_satisfied`` predicate gates the transition
to Approved.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone, date
import logging

# Finding #1: single source of truth for registry record-name construction.
# Fallback import covers both the in-repo package context (operators.shared.*)
# and the flattened shared_build/shared/ snapshot the deployed operators run.
try:
    from operators.shared.registry_naming import registry_record_id, asset_id_from_spec
except ImportError:  # pragma: no cover - deployed snapshot path
    from registry_naming import registry_record_id, asset_id_from_spec

logger = logging.getLogger("AssetOperator")

# a design note annotation keys — mechanism-agnostic submission surface. Any
# kubectl-tier writer with adequate K8s RBAC may set these. The operator
# materializes a single approval record into status.governance.approvals[]
# on the next reconcile.
APPROVAL_ANN_APPROVER = "modaas.tmforum.org/approver"
APPROVAL_ANN_ATTESTATION = "modaas.tmforum.org/approval-attestation"
APPROVAL_ANN_ROLE = "modaas.tmforum.org/approver-role"
APPROVAL_ANN_SIGNATURE = "modaas.tmforum.org/approval-signature"



def _record_state(record: dict) -> str:
    """Read a registry record's lifecycle state.

    The bedrock-agentcore ListRegistryRecords response names this field **status**:
        {"name": "aws-bedrock_g04-loop-probe", "status": "DEPRECATED", "recordId": "...", ...}
    This code read `state`, a key the API never returns, so every lookup fell through to the
    "UNKNOWN" default. Consequences: status.registryApprovalStatus never reflected reality and the
    drift comparison `match.get("state") != "APPROVED"` was decided by a missing key rather than by
    the record — drift detection was blind against the real API.
    Precedence is `status` then `state`: the API field wins, and `state` remains a fallback for
    older fixtures that used it.
    """
    for key in ("status", "state"):
        v = record.get(key)
        if v:
            return str(v)
    return "UNKNOWN"


class ProvisioningFailed(Exception):
    """Raised by provision_backend() when provider-specific work fails."""
    def __init__(self, reason: str, message: str = ""):
        self.reason = reason
        self.message = message
        super().__init__(message or reason)


class AssetOperator(ABC):

    # ── a design note Registry dispatch (feature-flagged via MODAAS_REGISTRY_DISPATCH) ──
    def _dispatch_enabled(self) -> bool:
        """Check feature flag. Default 'legacy' = zero behavior change."""
        import os
        return os.environ.get("MODAAS_REGISTRY_DISPATCH", "legacy").lower() == "enabled"

    def _resolve_registry_or_legacy(self, spec: dict):
        """Return (backing, params, backing_kind) via resolver, or None to signal
        legacy path.

        Resolution-error surfacing (R4 fix): a *named* `spec.registryRef` that
        points at a Registry CR which does not exist (RegistryNotFound) is an
        operator-authoring error — a typo or a dangling reference. Previously
        every resolver exception (including RegistryNotFound) was swallowed into
        the legacy default-registry fallback, so an asset would silently publish
        its discovery records to the wrong catalog with no signal. We now record
        a named-ref resolution error on the instance so the reconcile body can
        surface a `RegistryResolved=False` status condition (fail-soft,
        non-blocking — a design note observe-don't-teardown) and skip the silent
        legacy write.

        Other failure modes (NoRegistryConfigured = no ref + no annotated
        default; UnsupportedController = ref owned by a sibling operator; import
        errors) legitimately mean "this operator should use its legacy path" and
        keep returning None without setting the error flag.
        """
        # Cleared on every call; set only when a *named* ref fails to resolve.
        self._last_registry_resolution_error = None
        if not self._dispatch_enabled():
            return None
        # Add shared module to sys.path (kept outside the resolver try so an
        # import failure still falls through to legacy, as before).
        try:
            import sys, os
            shared_root = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..")
            )
            if shared_root not in sys.path:
                sys.path.insert(0, shared_root)
            from operators.shared.resolver import (
                controllers_for,
                resolve_registry,
                RegistryNotFound,
            )
            from operators.shared.backings import get_backing
        except Exception as e:
            import logging
            logging.getLogger("AssetOperator").warning(
                f"a design note dispatch import failed (falling back to legacy): "
                f"{type(e).__name__}: {e}"
            )
            return None
        try:
            # Controller filter is per-operator (Goal 4). Passing nothing here
            # meant every operator filtered on the resolver's module default —
            # the model operator's name — so a Registry scoped to the tool or
            # agent operator could never be claimed by it.
            backing_kind, params = resolve_registry(
                spec.get("registryRef"),
                controller=controllers_for(self.record_type),
            )
            backing = get_backing(backing_kind)
            return backing, params, backing_kind
        except RegistryNotFound as e:
            # Named ref points at a Registry that does not exist. Do NOT fall
            # back to the legacy default — that would silently re-home records.
            ref_name = (spec.get("registryRef") or {}).get("name")
            self._last_registry_resolution_error = (ref_name, str(e))
            import logging
            logging.getLogger("AssetOperator").warning(
                f"a design note registryRef '{ref_name}' does not resolve "
                f"(RegistryResolved=False, fail-soft): {e}"
            )
            return None
        except Exception as e:
            import logging
            logging.getLogger("AssetOperator").warning(
                f"a design note dispatch failed (falling back to legacy): "
                f"{type(e).__name__}: {e}"
            )
            return None

    @property
    @abstractmethod
    def record_type(self) -> str:
        """Registry record type: 'model', 'tool', or 'agent'."""

    @property
    @abstractmethod
    def resource_plural(self) -> str:
        """K8s resource plural: 'modelconfigs', 'toolconfigs', 'agentconfigs'."""

    @abstractmethod
    def provision_backend(self, spec: dict, status: dict) -> dict:
        """Provider-specific provisioning. Returns dict merged into status."""

    @abstractmethod
    def deprovision_backend(self, status: dict) -> None:
        """Provider-specific cleanup on delete."""

    def should_reconcile(self, meta: dict, status: dict) -> bool:
        """Reconcile when generation advanced, OR when a a design note approval
        annotation is pending on a not-yet-Approved CR.

        Generation-only gating misses annotation-borne approvals: a
        `modaas.tmforum.org/approver` annotation does NOT bump
        metadata.generation, so a CR parked in `Reviewing` would otherwise sit
        until the next spec change or the 5-min resync timer before the
        attestation is materialized. Treating a pending approval annotation as a
        reconcile trigger makes the gate clear promptly on annotate."""
        if status.get("observedGeneration") != meta.get("generation"):
            return True
        return self._has_pending_approval_annotation(meta, status)

    def _has_pending_approval_annotation(self, meta: dict, status: dict) -> bool:
        """True when an approver annotation is present but not yet recorded in
        status.governance.approvals[] (and the CR is not already Approved).

        Cheap predicate used by should_reconcile so an annotation-only change
        still triggers a reconcile. The full materialization + role validation
        happens in _materialize_approval_from_annotations during reconcile."""
        if (status or {}).get("phase") == "Approved":
            return False
        annotations = (meta or {}).get("annotations") or {}
        approver = annotations.get(APPROVAL_ANN_APPROVER)
        if not approver:
            return False
        annotated_role = annotations.get(APPROVAL_ANN_ROLE)
        attestation = annotations.get(APPROVAL_ANN_ATTESTATION, "")
        existing = ((status or {}).get("governance") or {}).get("approvals") or []
        for record in existing:
            if (
                isinstance(record, dict)
                and record.get("subject") == approver
                and (annotated_role is None or record.get("role") == annotated_role)
                and record.get("attestation") == attestation
            ):
                return False  # already materialized — nothing pending
        return True

    def reconcile(self, spec: dict, status: dict, meta: dict, patch) -> dict:
        """Main reconciliation loop. Returns result dict."""
        self._seed_conditions(patch, status)
        # Bug #11/#12: ALWAYS stamp lastReconciled so the field reflects when
        # the controller last looked at the CR — even when generation is
        # unchanged and we early-return as a no-op. Adopt-mode CRs (managed
        # entirely outside the operator's spec) otherwise show
        # `lastReconciled` 20+ days stale, which falsely signals a dead
        # operator on `kubectl get`.
        patch.status["lastReconciled"] = datetime.now(timezone.utc).isoformat()

        # Idempotency: skip if generation unchanged
        if not self.should_reconcile(meta, status):
            return {"message": "no-op: generation unchanged"}

        _prev_phase = (status or {}).get("phase", "Unknown")

        # Pause handling
        if spec.get("paused"):
            return self._handle_paused(patch, meta, status, spec)

        # a design note grandfather (§7): pre-existing Approved CRs do NOT back-rev
        # to Reviewing on first a design note reconcile. _approval_satisfied checks
        # status.phase == "Approved" first, so calling here BEFORE we
        # overwrite status.phase preserves grandfather semantics.
        previously_approved = (status or {}).get("phase") == "Approved"

        # ── a design note §4 Reviewing gate ──
        # Materialize any pending annotation-borne approval into
        # status.governance.approvals[] so the predicate sees it.
        # TODO(a design note §4): v0 trusts the K8s RBAC of whoever annotated; full
        # Keycloak JWT verification (signature + iss + aud + role membership)
        # is post-DTW. For now subject + role from the annotation are taken
        # at face value, audit trail is the K8s API audit log.
        self._materialize_approval_from_annotations(spec, status, meta, patch)

        # Phase: Pending
        patch.status["phase"] = "Pending"
        self._emit_phase_change(meta, status, _prev_phase, "Pending")
        patch.status["reason"] = "Provisioning"

        # a design note approval gate: when approval is required AND not yet
        # satisfied, park the CR in Reviewing. Skip the gate when this CR
        # was already Approved before a design note rolled out (grandfather).
        # Gate evaluation is delegated to operators.shared.governance.approval
        # so the predicate is testable as a pure function.
        if not previously_approved and not self._approval_satisfied(spec, status, patch):
            patch.status["phase"] = "Reviewing"
            self._emit_phase_change(meta, status, "Pending", "Reviewing")
            # Stamp awaitingSince once; preserve across reconciles when
            # already present (the wall-clock "we entered Reviewing at" time).
            existing_governance = (status or {}).get("governance") or {}
            awaiting_since = existing_governance.get("awaitingSince")
            if not awaiting_since:
                awaiting_since = datetime.now(timezone.utc).isoformat()
            governance_patch = dict(patch.status.get("governance") or {})
            governance_patch["awaitingSince"] = awaiting_since
            patch.status["governance"] = governance_patch
            expected_role = self._default_approver_role(spec)
            self._set_condition(
                patch,
                "ApprovalRequired",
                "True",
                "AwaitingHuman",
                f"Awaiting attestation from role={expected_role!r}",
            )
            patch.status["reason"] = "AwaitingApproval"
            self._stamp(patch, meta)
            return {"message": "awaiting approval", "phase": "Reviewing"}

        # Approval satisfied (or grandfathered) — clear awaitingSince so a
        # later operator restart doesn't think we're still waiting.
        if not previously_approved:
            existing_governance = dict((status or {}).get("governance") or {})
            existing_governance["awaitingSince"] = None
            patch.status["governance"] = {
                **(patch.status.get("governance") or {}),
                **existing_governance,
                "awaitingSince": None,
            }
            self._set_condition(
                patch,
                "ApprovalRequired",
                "False",
                "ApprovalSatisfied",
                "Approval predicate satisfied; advancing to provisioning",
            )

        # Provision backend
        try:
            backend_status = self.provision_backend(spec, status)
        except ProvisioningFailed as e:
            patch.status["phase"] = "Failed"
            self._emit_phase_change(meta, status, "Pending", "Failed")
            patch.status["reason"] = e.reason
            self._set_condition(patch, "Provisioned", "False", e.reason, str(e))
            self._stamp(patch, meta)
            return {"error": e.reason}

        # Merge backend status
        for k, v in (backend_status or {}).items():
            patch.status[k] = v
        self._set_condition(patch, "Provisioned", "True", "BackendReady", "Backend provisioned")

        # Register in registry (AFTER provisioning — bug #17 fix)
        try:
            record_id = self._register_in_registry(spec, patch.status, meta)
            patch.status["registryRecordId"] = record_id
            self._set_condition(patch, "RegistryRegistered", "True", "Registered",
                                f"Record {record_id}")
        except Exception as e:
            self._set_condition(patch, "RegistryRegistered", "False", "RegistryFailed", str(e)[:200])
            patch.status["phase"] = "Failed"
            self._emit_phase_change(meta, status, "Pending", "Failed")
            patch.status["reason"] = "RegistryRegistrationFailed"
            self._stamp(patch, meta)
            return {"error": f"registry failed: {e}"}

        # Phase: Approved
        patch.status["phase"] = "Approved"
        self._emit_phase_change(meta, status, "Pending", "Approved")
        patch.status["reason"] = "Approved"

        # a design note — emit ApprovalRecorded PublishedNotification on the
        # Reviewing → Approved transition. Best-effort, fail-soft.
        if not previously_approved:
            self._emit_approval_notification(spec, patch.status, meta)

        # Project into Canvas TMF639 Resource Inventory (a design note) — best-effort,
        # truthful, observable. AgentCore Registry is authoritative; the TMF639
        # projection is a peer view so TMF-aligned consumers can discover this
        # asset. Failure to project NEVER fails reconcile. The TMF639Projected
        # condition is stamped True/False+reason so the integration state is
        # visible in `kubectl describe` (AGENTS.md Coherence Rule 19/16).
        self._project_and_stamp_tmf639(spec, patch, "Approved")

        # Retirement check
        self._check_retirement(spec, patch)

        self._stamp(patch, meta)
        return {"message": "reconciled"}

    def cleanup(self, spec: dict, status: dict) -> None:
        """Deletion handler."""
        self.deprovision_backend(status)
        try:
            self._deprecate_in_registry(spec, status)
        except Exception as e:
            logger.warning(f"Registry deprecation failed: {e}")
        # Best-effort TMF639 delete (a design note)
        try:
            self._tmf639_delete(spec)
        except Exception as e:
            logger.warning(f"TMF639 delete failed: {e}")

    def _handle_paused(self, patch, meta, status=None, spec=None) -> dict:
        self._seed_conditions(patch, status)
        _prev = (status or {}).get("phase", "Unknown")
        patch.status["phase"] = "Paused"
        self._emit_phase_change(meta, status, _prev, "Paused")
        patch.status["reason"] = "SpecPaused"
        self._set_condition(patch, "ReconcilePaused", "True", "SpecPaused", "spec.paused=true")
        self._project_pause_to_registry(patch, spec, status)
        self._stamp(patch, meta)
        return {"message": "paused"}

    def _project_pause_to_registry(self, patch, spec, status) -> None:
        """Reflect a pause in the external Registry, not just in K8s.

        Without this the two systems disagree: the CR reads Paused while the
        Registry record still reads its creation-time state, so a consumer
        discovering the asset through the Registry sees it as live. Measured
        before the fix: CR paused at 20:11:38 while record 8TZt395sxPEW still
        reported status=DRAFT updatedAt=20:07:33.

        Best-effort and non-fatal: a Registry outage must not block the pause
        taking effect in-cluster, so the outcome is surfaced as a condition
        instead of raising.

        DESIGN CORRECTED (F71). This used to call deprecate(), i.e. set the record to DEPRECATED.
        Probing the live API showed DEPRECATED is TERMINAL —
            "Cannot update registry record in DEPRECATED status (terminal state)"
        — and that no caller-settable reversible state exists: from DRAFT the only accepted targets
        are DRAFT, UPDATING and DEPRECATED (PENDING_APPROVAL is rejected as "Invalid target status").
        So deprecating on pause permanently burned the record, unpause had no choice but to mint a
        replacement, and one fixture asset accumulated 16 same-named records.

        A pause is reversible, so it must not be written as a terminal state. Pause is enforced where
        it actually matters — the gateway refuses a paused asset on BOTH planes
        (alias_resolver.py for models, mcp_proxy.governance_refusal for tools) — and the registry is a
        catalog, not the enforcement point. The projection therefore records the pause in the record's
        METADATA and leaves the lifecycle state intact. DEPRECATED is now reserved for retirement,
        which is genuinely terminal.
        """
        if not spec:
            return
        provider = spec.get("provider") or "unknown"
        try:
            record_name = registry_record_id(provider, asset_id_from_spec(spec))
            # Two registration paths exist and BOTH must be covered, or pause
            # projection silently depends on a feature flag:
            #   * a design note dispatch  — active when MODAAS_REGISTRY_DISPATCH=enabled
            #                        AND a Registry CR resolves.
            #   * legacy client    — the default (MODAAS_REGISTRY_DISPATCH=legacy),
            #                        which is what actually wrote this record.
            paused_meta = {
                "modaasServingState": "PAUSED",
                "modaasPausedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "modaasPauseReason": "spec.paused=true",
            }
            dispatch = self._resolve_registry_or_legacy(spec)
            if dispatch is not None:
                backing, params, backing_kind = dispatch
                backing.annotate(record_name, paused_meta, params)
                via = f"dispatch:{backing_kind}"
            else:
                from .registry_client import _default_region, get_client  # noqa: PLC0415
                # Spec-declared region wins; otherwise the deployment's, never a
                # literal (same defect class as the orphan scan above).
                region = ((spec.get("awsBedrock") or {}).get("region")
                          or (spec.get("awsSageMaker") or {}).get("region")
                          or _default_region())
                get_client(region).annotate(record_name, paused_meta)
                via = "legacy"
            self._set_condition(
                patch, "RegistryPauseProjected", "True", "ServingStatePaused",
                f"Registry record {record_name} marked servingState=PAUSED via {via} "
                f"(lifecycle state left intact — DEPRECATED is terminal, see F71)",
            )
        except Exception as exc:  # noqa: BLE001 - pause must still apply locally
            self._set_condition(
                patch, "RegistryPauseProjected", "False", "ProjectionFailed",
                f"pause applied in-cluster but NOT projected to Registry: {exc}",
            )

    # ------------------------------------------------------------------ #
    # a design note — governance approval gate                                   #
    # ------------------------------------------------------------------ #

    def _asset_id(self, spec: dict) -> str:
        """Return spec.alias / toolName / agentName, whichever is set."""
        return (
            spec.get("alias")
            or spec.get("toolName")
            or spec.get("agentName")
            or "unknown"
        )

    def _default_approver_role(self, spec: dict) -> str:
        """a design note/a design note canonical approver role name.

        Resolves spec.governance.approval.approverRole when the operator
        wants the SHIPPED value; falls back to ``modaas-<kind>-<alias>-admin``.
        Used in conditions/messages so kubectl describe shows the role
        operators expect to see in approvals[].role.
        """
        try:
            from operators.shared.governance.approval import (
                _resolve_expected_role,
            )
        except ImportError:
            try:
                from shared.governance.approval import _resolve_expected_role
            except ImportError:
                from .governance.approval import _resolve_expected_role
        return _resolve_expected_role(spec, self.record_type, self._asset_id(spec))

    def _approval_satisfied(self, spec: dict, status: dict, patch=None) -> bool:
        """Delegate to the pure-function predicate so unit tests can exercise
        the gate logic without a kopf patch fixture.
        """
        try:
            from operators.shared.governance.approval import (
                check_approval_satisfied,
            )
        except ImportError:
            try:
                from shared.governance.approval import check_approval_satisfied
            except ImportError:
                from .governance.approval import check_approval_satisfied
        # Merge any pending status changes from `patch` so an approval just
        # materialized this reconcile pass is visible to the predicate.
        merged_status = dict(status or {})
        if patch is not None:
            patched = patch.status.get("governance") if hasattr(patch, "status") else None
            if patched:
                merged_status["governance"] = {
                    **(merged_status.get("governance") or {}),
                    **patched,
                }
        return check_approval_satisfied(
            spec, merged_status, self.record_type, self._asset_id(spec)
        )

    def _materialize_approval_from_annotations(
        self, spec: dict, status: dict, meta: dict, patch
    ) -> bool:
        """Read a design note annotations off the CR and append to status.governance.approvals[].

        Mechanism-agnostic submission per a design note §4: any kubectl-tier write
        the requesting user is RBAC-authorized for is accepted. This function
        does NOT introduce any HTTP endpoint, CLI plugin, or UI.

        Annotations honored:
          modaas.tmforum.org/approver           — required, becomes record.subject
          modaas.tmforum.org/approver-role      — optional, defaults to spec
                                                  governance.approval.approverRole
          modaas.tmforum.org/approval-attestation — optional rationale text
          modaas.tmforum.org/approval-signature — optional bearer token / signature

        v0 role validation: the function trusts the K8s RBAC of whoever set
        the annotation. Full Keycloak JWT verification is out of scope per
        a design note §4 and tracked as post-DTW.

        Returns True when an approval record was appended.
        """
        annotations = (meta or {}).get("annotations") or {}
        approver = annotations.get(APPROVAL_ANN_APPROVER)
        if not approver:
            return False

        # Skip duplicate materialization: same subject + role already present.
        existing_governance = (status or {}).get("governance") or {}
        existing = existing_governance.get("approvals") or []

        attestation = annotations.get(APPROVAL_ANN_ATTESTATION, "")
        # Truncate attestation defensively (§3 schema bounds at 2048 chars).
        if attestation and len(attestation) > 2048:
            attestation = attestation[:2048]

        annotated_role = annotations.get(APPROVAL_ANN_ROLE)
        expected_role = annotated_role or self._default_approver_role(spec)

        # TODO(a design note §4): v0 trusts K8s RBAC; replace with Keycloak JWT
        # verification (signature + iss + aud + realm-role membership) once
        # the post-DTW endpoint pipeline lands.

        for record in existing:
            if (
                isinstance(record, dict)
                and record.get("subject") == approver
                and record.get("role") == expected_role
                and record.get("attestation") == attestation
            ):
                # Already materialized — no-op.
                return False

        new_record = {
            "subject": approver,
            "role": expected_role,
            "attestation": attestation,
            "signature": annotations.get(APPROVAL_ANN_SIGNATURE, ""),
            "at": datetime.now(timezone.utc).isoformat(),
        }
        appended = list(existing) + [new_record]
        # Preserve any other governance fields (awaitingSince, etc.) the
        # current reconcile may have already written into the patch.
        merged = {
            **(existing_governance or {}),
            **(patch.status.get("governance") or {}),
            "approvals": appended,
        }
        patch.status["governance"] = merged
        logger.info(
            "a design note: materialized approval subject=%s role=%s asset=%s/%s",
            approver, expected_role, self.record_type, self._asset_id(spec),
        )
        return True

    def _emit_approval_notification(self, spec: dict, status: dict, meta: dict) -> None:
        """Emit a PublishedNotification of type ApprovalRecorded.

        Reuses the a design note/a design note emission path so the audit ledger captures
        approval events alongside other lifecycle transitions. Fail-soft —
        a notification emission failure must NOT break reconcile.
        """
        try:
            try:
                from shared.lifecycle_events import emit_lifecycle_event
            except ModuleNotFoundError:
                import sys as _sys, os as _os
                _shared_root = _os.path.abspath(
                    _os.path.join(_os.path.dirname(__file__), "..")
                )
                if _shared_root not in _sys.path:
                    _sys.path.insert(0, _shared_root)
                from shared.lifecycle_events import emit_lifecycle_event
            import kubernetes as _k8s
            try:
                _k8s.config.load_incluster_config()
            except _k8s.config.config_exception.ConfigException:
                _k8s.config.load_kube_config()
            kind_map = {"model": "ModelConfig", "tool": "ToolConfig", "agent": "AgentConfig"}
            asset_kind = kind_map.get(self.record_type, "Unknown")
            governance = (status or {}).get("governance") or {}
            approvals = governance.get("approvals") or []
            payload = {
                "asset": self._asset_id(spec),
                "assetKind": asset_kind,
                "approvalCount": len(approvals),
                "approvers": [
                    a.get("subject") for a in approvals if isinstance(a, dict)
                ],
                "approverRole": self._default_approver_role(spec),
            }
            emit_lifecycle_event(
                k8s_api=_k8s.client.CustomObjectsApi(),
                namespace=meta.get("namespace", "components"),
                source_kind=asset_kind,
                source_name=meta.get("name", "unknown"),
                event_type="ApprovalRecorded",
                payload=payload,
                observed_generation=meta.get("generation", 0),
            )
        except Exception as e:
            logger.warning(
                "a design note: ApprovalRecorded emission failed (fail-soft): %s", e
            )

    def _emit_phase_change(self, meta: dict, status: dict, from_phase: str, to_phase: str) -> None:
        """W2.D — emit PublishedNotification on phase transition. Fail-soft."""
        try:
            try:
                from shared.lifecycle_events import emit_phase_transition
            except ModuleNotFoundError:
                import sys as _sys, os as _os
                _shared_root = _os.path.abspath(
                    _os.path.join(_os.path.dirname(__file__), "..")
                )
                if _shared_root not in _sys.path:
                    _sys.path.insert(0, _shared_root)
                from shared.lifecycle_events import emit_phase_transition
            import kubernetes as _k8s
            try:
                _k8s.config.load_incluster_config()
            except _k8s.config.config_exception.ConfigException:
                _k8s.config.load_kube_config()
            _kind_map = {"model": "ModelConfig", "tool": "ToolConfig", "agent": "AgentConfig"}
            asset_kind = _kind_map.get(self.record_type, "Unknown")
            emit_phase_transition(
                k8s_api=_k8s.client.CustomObjectsApi(),
                namespace=meta.get("namespace", "components"),
                asset_kind=asset_kind,
                asset_name=meta.get("name", "unknown"),
                asset_uid=meta.get("uid", ""),
                from_phase=from_phase,
                to_phase=to_phase,
                component_uid=(status or {}).get("componentRef", {}).get("uid")
                              if isinstance((status or {}).get("componentRef"), dict) else None,
            )
        except Exception:
            pass  # fail-soft — never break reconcile for notification emission

    def _check_retirement(self, spec: dict, patch) -> None:
        retire_date = (spec.get("governance") or {}).get("retirementDate")
        days = self._days_until_retirement(retire_date)
        if days is None:
            return
        patch.status["daysUntilRetirement"] = days
        if days <= 0:
            self._set_condition(patch, "RetirementDue", "True", "PastRetirement",
                                f"Past retirement by {-days} days")
        elif days <= 30:
            self._set_condition(patch, "RetirementDue", "True", "ApproachingRetirement",
                                f"Retirement in {days} days")

    def _build_registry_metadata(self, spec: dict, status: dict) -> dict:
        """Hook: subclasses override to provide rich metadata for registry records.

        Default returns minimal metadata with componentRef when present in status.
        Override in ModelOperator/ToolOperator/AgentOperator for kind-specific fields.
        """
        md = {}
        if status.get("componentRef"):
            md["componentRef"] = status["componentRef"]
        return md

    def _register_in_registry(self, spec: dict, status: dict, meta: dict | None = None) -> str:
        """Project the asset into the Registry and return its record NAME.

        `meta` is the CR's metadata. It is optional so every existing caller and
        test keeps working, but when supplied it carries the CR's `uid` and
        `generation` into the record — the audit identity a design note PR 2 added, so an
        approval in the Registry says which CR revision authorised it rather than
        only which alias it was for.
        """
        provider = spec.get("provider", "unknown")
        # Finding #1: build the registry record name via the single canonical
        # builder. BOTH halves are normalized (provider AND asset_id) so the
        # result always satisfies the CRD status.registryRecordId pattern, even
        # when agentName carries underscores/uppercase. asset_id (raw) is still
        # used for the human-facing description.
        asset_id = asset_id_from_spec(spec)
        record_name = registry_record_id(provider, asset_id)
        record = {
            "recordType": self.record_type,
            "name": record_name,
            "description": spec.get("description") or f"{self.record_type} {asset_id} ({provider})",
            "version": str(status.get("observedGeneration", 1)),
            "state": "APPROVED",
            "metadata": self._build_registry_metadata(spec, status),
            # Audit identity (a design note PR 2). Empty string rather than absent when
            # unknown, so the registry record's statusReason reads
            # "CR uid unknown" instead of silently omitting the field — an audit
            # trail that can be silently incomplete is not one.
            "crUid": (meta or {}).get("uid", ""),
            "generation": str(
                (meta or {}).get("generation", status.get("observedGeneration", 1))
            ),
        }
        # a design note Registry dispatch path (feature-flagged)
        dispatch = self._resolve_registry_or_legacy(spec)
        if dispatch is not None:
            backing, params, backing_kind = dispatch
            resp = backing.put_record(record, params)
            # Stamp status.registryBackingRef for observability
            status["registryBackingRef"] = {
                "name": (spec.get("registryRef") or {}).get("name", "default"),
                "backing": backing_kind,
                "recordId": resp.get("recordId", record_name),
                "observedAt": datetime.now(timezone.utc).isoformat(),
            }
            self._publish_registry_audit_identity(status, resp)
            # T8: statusReason from get_registry_record, when the backing's
            # underlying client captured one, is surfaced onto both the
            # backing ref (so it's visible next to the recordId it explains)
            # and a dedicated condition (so it participates in `kubectl get
            # ... -o wide`/condition-based tooling the same way other
            # registry-facing signals do).
            #
            # Condition type is "RegistryStatusReasonObserved", NOT
            # "RegistryApprovalStatus" — the latter name is already taken by
            # the pre-existing FLAT status field status.registryApprovalStatus
            # (enum APPROVED|DRAFT|DEPRECATED|MISSING|UNKNOWN, see
            # _resync_registry_state below). That field answers "what state
            # is the record in"; this condition answers "why", carried as
            # AWS's own statusReason text. Reusing the name would have two
            # different registry-derived signals sharing one label.
            status_reason = resp.get("statusReason")
            if status_reason:
                status["registryBackingRef"]["statusReason"] = status_reason
                self._set_status_condition(
                    status, "RegistryStatusReasonObserved", "True", "Observed",
                    status_reason[:512],
                )
            self._set_status_condition(
                status, "RegistryResolved", "True", "Resolved",
                f"registryRef resolved to backing '{backing_kind}'",
            )
            return resp.get("name", record_name)
        # R4 fix: a named registryRef that does not resolve is surfaced as a
        # fail-soft condition; we do NOT silently write to the legacy default
        # registry (that would re-home the asset's discovery records).
        if self._last_registry_resolution_error is not None:
            ref_name, msg = self._last_registry_resolution_error
            self._set_status_condition(
                status, "RegistryResolved", "False", "RegistryRefNotFound",
                f"spec.registryRef '{ref_name}' does not resolve to a Registry "
                f"CR; discovery records were NOT published to the default "
                f"registry. Fix the reference. ({msg})"[:512],
            )
            # Fail-soft (a design note): do not block the asset; surface and skip write.
            return record_name
        # Legacy path (unchanged) — no named ref, or resolver disabled.
        from .registry_client import get_client  # noqa: PLC0415
        region = self._get_region(spec)
        resp = get_client(region).put_record(record)
        # 2026-09-05 truthfulness: registry_client now reports the REAL final
        # record status. Surface a failed/deferred approval as a condition so
        # a DRAFT-stuck record is visible on the CR instead of silently
        # claimed APPROVED (live defect: SubmitRegistryRecordForApproval
        # AccessDenied left every record DRAFT while status said registered).
        if resp.get("submitFailed"):
            self._set_status_condition(
                status, "RegistryApprovalPending", "True", "SubmitFailedOrPending",
                f"registry record {resp.get('recordId','?')} status="
                f"{resp.get('state','?')} — record created but not APPROVED "
                f"(check operator IAM SubmitRegistryRecordForApproval + registry "
                f"approvalConfiguration)"[:512],
            )
        # T8: same statusReason surfacing as the a design note path above, applied
        # here too so a CR on the legacy path (no named registryRef) is not
        # left worse-observed than one on the newer dispatch path. Same
        # condition-type naming rationale as above (RegistryStatusReasonObserved,
        # not RegistryApprovalStatus — that name is the pre-existing flat field).
        status_reason = resp.get("statusReason")
        if status_reason:
            status.setdefault("registryBackingRef", {})["statusReason"] = status_reason
            self._set_status_condition(
                status, "RegistryStatusReasonObserved", "True", "Observed",
                status_reason[:512],
            )
        self._publish_registry_audit_identity(status, resp)
        return resp.get("name", record_name)

    @staticmethod
    def _publish_registry_audit_identity(status: dict, resp: dict) -> None:
        """Surface the SERVICE-assigned record id and the minted approval id.

        Why these are NEW fields rather than a repurposed `status.registryRecordId`
        (a design note open question 3, and the one place PR 2 deviates from its brief):
        `registryRecordId` is schema-constrained to
        `^[a-z][a-z0-9-]*_[a-z][a-z0-9-]*$` — the `<provider>_<alias>` convention
        Finding #1 unified across all three CRDs. A real AWS record id is exactly
        12 mixed-case alphanumerics (`RegistryRecordId` in the service model), so
        writing one into that field would be REJECTED by the apiserver and fail
        the whole status patch. Loosening the pattern to accept both would leave
        one field meaning two different things depending on the record's age, which
        is worse for an audit trail than two fields that each mean one thing.

        So: `registryRecordId` stays the convention key (what MoDaaS asked for),
        `registryRecordUid` is what the service assigned (what actually exists),
        and `registryApprovalId` identifies this approval projection.
        """
        record_uid = resp.get("recordId")
        if record_uid:
            status["registryRecordUid"] = record_uid
        approval_id = resp.get("approvalId")
        if approval_id:
            status["registryApprovalId"] = approval_id

    def _deprecate_in_registry(self, spec: dict, status: dict) -> None:
        provider = spec.get("provider", "unknown")
        # Finding #1: same canonical builder as _register_in_registry so the
        # deprecate key matches exactly what was written.
        record_name = registry_record_id(provider, asset_id_from_spec(spec))
        # a design note Registry dispatch path (feature-flagged)
        dispatch = self._resolve_registry_or_legacy(spec)
        if dispatch is not None:
            backing, params, _kind = dispatch
            backing.deprecate(record_name, params)
            return
        # Legacy path (unchanged)
        from .registry_client import get_client  # noqa: PLC0415
        region = self._get_region(spec)
        client = get_client(region)
        if hasattr(client, "deprecate"):
            client.deprecate(record_name)

    def _get_region(self, spec: dict) -> str:
        """Extract region from provider-specific blocks.

        2026-09-05: the fallback follows the deployment environment
        (MODAAS_REGISTRY_REGION > AWS_REGION > legacy us-west-2). The old
        hardcoded us-west-2 fallback sent every agent/tool record (no
        awsBedrock block) to the wrong-region registry on us-east-1 clusters.
        A spec-declared region still wins.
        """
        import os
        env_default = (
            os.environ.get("MODAAS_REGISTRY_REGION")
            or os.environ.get("AWS_REGION")
            or "us-west-2"
        )
        if "awsBedrock" in spec:
            return spec["awsBedrock"].get("region", env_default)
        return env_default

    @staticmethod
    def _days_until_retirement(retire_iso: str | None) -> int | None:
        if not retire_iso:
            return None
        try:
            return (date.fromisoformat(retire_iso) - date.today()).days
        except ValueError:
            return None

    @staticmethod
    def _stamp(patch, meta):
        patch.status["observedGeneration"] = meta.get("generation", 0)
        patch.status["lastReconciled"] = datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _seed_conditions(patch, status) -> None:
        """Copy existing status.conditions into the patch so upserts MERGE instead of replacing.

        Must be called once at the start of any handler that sets conditions. Without it a handler
        that touches one condition erases all the others (see _set_condition).
        """
        if patch.status.get("conditions"):
            return
        existing = list((status or {}).get("conditions") or [])
        if existing:
            patch.status["conditions"] = existing

    @staticmethod
    def _set_condition(patch, cond_type, cond_status, reason, message):
        """Upsert one condition, preserving the ones this handler did not touch.

        This read `patch.status.get("conditions", [])` — the PATCH, which starts EMPTY. A handler that
        set a single condition therefore sent a one-element array, and because a status patch REPLACES
        the list, every condition written by another code path was silently erased. The resync timer
        sets only TMF639Projected, so each time it fired it wiped RegistryRegistered, Provisioned,
        IdentityProvisioned and the rest. Consumers and verifiers saw a partial, time-dependent view of
        governance state — which is how a verifier came to look "flaky" while reporting a true fact.

        `_seed_conditions()` pre-populates the patch from live status at the start of a handler; this
        also falls back to `patch.status["_existingConditions"]` if a caller seeded it that way.
        """
        now = datetime.now(timezone.utc).isoformat()
        cond = {"type": cond_type, "status": cond_status, "reason": reason,
                "message": message, "lastTransitionTime": now}
        conds = patch.status.get("conditions", [])
        for i, c in enumerate(conds):
            if c.get("type") == cond_type:
                conds[i] = cond
                patch.status["conditions"] = conds
                return
        conds.append(cond)
        patch.status["conditions"] = conds

    @staticmethod
    def _set_status_condition(status, cond_type, cond_status, reason, message):
        """Upsert a condition onto a plain status dict (not a kopf patch object).

        Used by paths that hold `status` (which IS `patch.status` at the call
        site) rather than the kopf `patch` wrapper. Mirrors `_set_condition`."""
        now = datetime.now(timezone.utc).isoformat()
        cond = {"type": cond_type, "status": cond_status, "reason": reason,
                "message": message, "lastTransitionTime": now}
        conds = status.get("conditions", [])
        for i, c in enumerate(conds):
            if c.get("type") == cond_type:
                conds[i] = cond
                status["conditions"] = conds
                return
        conds.append(cond)
        status["conditions"] = conds

    def record_observed_path(self, patch, k8s_api, alias: str, status_field: str) -> None:
        """Observe the agentgateway dataplane's Accepted condition for `alias`, writing
        `patch.status[status_field]` only when it is genuinely True.

        Replaces the a design note spec-echo (`status.enforcedAt` used to mirror
        `spec.safety.enforcer.enforcedAt` unconditionally) with a real
        observation of whether the dataplane actually accepted the route.
        Fail-soft at every branch: never raises, never clears
        `status_field` on a transient non-accept (BR-3) — it either writes
        the observed value on a confirmed accept, or leaves the field
        untouched and reports why via the `ObservedPathRead` condition.
        """
        try:
            from operators.shared.agentgateway_route import (
                AGW_GROUP, AGW_VERSION, AGW_MODELS_PLURAL, gateway_ref,
            )
        except ImportError:
            from shared.agentgateway_route import (
                AGW_GROUP, AGW_VERSION, AGW_MODELS_PLURAL, gateway_ref,
            )
        from kubernetes.client.exceptions import ApiException

        ns, _, _ = gateway_ref()
        try:
            agw_model = k8s_api.get_namespaced_custom_object(
                group=AGW_GROUP, version=AGW_VERSION, namespace=ns,
                plural=AGW_MODELS_PLURAL, name=alias,
            )
        except ApiException as e:
            if e.status == 404:
                self._set_condition(patch, "ObservedPathRead", "False", "NotFound",
                                     f"No AgentgatewayModel named {alias!r} found")
            else:
                self._set_condition(patch, "ObservedPathRead", "False", "AgentgatewayModelReadError",
                                     f"AgentgatewayModel read failed: {str(e)[:256]}")
            return

        parents = (agw_model.get("status") or {}).get("parents") or []
        if not parents:
            self._set_condition(patch, "ObservedPathRead", "False", "NotYetAccepted",
                                 "AgentgatewayModel exists but carries no parent status yet")
            return

        conditions = parents[0].get("conditions") or []
        accepted = next((c for c in conditions if c.get("type") == "Accepted"), None)

        if accepted and accepted.get("status") == "True":
            patch.status[status_field] = "self"
            self._set_condition(patch, "ObservedPathRead", "True", "Accepted",
                                 "Dataplane accepted the route")
        else:
            reason = (accepted or {}).get("reason", "NotAccepted")
            message = (accepted or {}).get("message", "Accepted condition missing or not True")
            self._set_condition(patch, "ObservedPathRead", "False", reason, message)
            # Deliberately does NOT write patch.status[status_field] here —
            # BR-3's "never clear on a transient non-accept" rule.

    # ---------------------------------------------------------------- #
    # TMF639 Resource Inventory integration (a design note)                    #
    # ---------------------------------------------------------------- #
    @staticmethod
    def _provider_and_asset_id(spec: dict) -> tuple[str, str]:
        """Extract provider + asset_id (alias/toolName/agentName) from spec."""
        import re
        provider = spec.get("provider", "unknown")
        provider_norm = re.sub(r"[^a-z0-9-]", "-", provider.lower()).strip("-") or "unknown"
        asset_id = (
            spec.get("alias")
            or spec.get("toolName")
            or spec.get("agentName")
            or "unknown"
        )
        return provider_norm, asset_id

    def _dual_write_tmf639(self, spec: dict, status: dict, phase: str) -> str | None:
        """Project the asset into TMF639 Resource Inventory.

        Best-effort — raises on unreachable endpoint but the reconcile
        loop catches and logs without failing the CR.
        """
        try:
            from operators.shared.tmf639_client import TMF639Client
        except ImportError:
            logger.debug("tmf639_client not available — skipping TMF639 dual-write")
            return None

        provider_norm, asset_id = self._provider_and_asset_id(spec)
        asset_type = self.record_type.capitalize()  # 'model' -> 'Model'
        governance = spec.get("governance") or {}

        metadata = {
            "registryRecordId": status.get("registryRecordId", ""),
            "generation": status.get("observedGeneration", 0),
        }
        # Include provider-specific hints
        if "awsBedrock" in spec:
            metadata["awsBedrock.modelId"] = (spec.get("awsBedrock") or {}).get("modelId", "")
            metadata["awsBedrock.region"] = (spec.get("awsBedrock") or {}).get("region", "")
        if "agentCoreGateway" in spec:
            metadata["agentCoreGateway"] = "enabled"
        if "awsAgentCore" in spec:
            metadata["awsAgentCore.runtimeName"] = (spec.get("awsAgentCore") or {}).get("runtimeName", "")

        client = TMF639Client()
        resource = client.upsert_asset(
            asset_type=asset_type,
            asset_name=asset_id,
            provider=provider_norm,
            phase=phase,
            governance=governance,
            metadata=metadata,
        )
        return (resource or {}).get("id")

    def _project_and_stamp_tmf639(self, spec: dict, patch, phase: str) -> None:
        """Project the asset into Canvas TMF639 Resource Inventory and stamp a
        TRUTHFUL, OBSERVABLE TMF639Projected condition.

        Single source of truth for TMF639 projection used by BOTH the
        spec-change reconcile path and the timer-driven resync path
        (resync_from_registry). Steady-state Approved CRs early-return at
        should_reconcile() on every spec-unchanged reconcile, so the reconcile
        path alone would leave TMF639Projected blank forever on existing CRs
        (AGENTS.md Coherence Rule 16 — time-bearing/projection status owes a
        path that runs on resync, not only on create/update). Calling this from
        the periodic timer makes the condition appear and stay current.

        Outcome discrimination (no fabrication — Coherence Rule 19):
          - real POST/PATCH 2xx  → TMF639Projected=True/Projected (+ resource id)
          - HTTP 405 (read-only) → TMF639Projected=False/TMF639ReadOnly
                                   (the canonical Canvas 1.2.x state: inventory
                                    accepts only reads from external producers;
                                    write projection awaits the TMF630 /hub
                                    event path, a design note)
          - outage / other 5xx   → TMF639Projected=False/TMF639Unreachable

        Best-effort: never raises. AgentCore Registry remains authoritative.
        """
        try:
            tmf_id = self._dual_write_tmf639(spec, patch.status, phase)
            if tmf_id:
                patch.status["tmf639ResourceId"] = tmf_id
            self._set_condition(
                patch, "TMF639Projected", "True", "Projected",
                f"Resource {tmf_id}" if tmf_id else "Projected",
            )
        except Exception as e:
            # Discriminate read-only endpoint (expected in Canvas 1.2.x) from
            # genuine outages. Read-only is NOT a failure — it is the canonical
            # Canvas behavior until the TMF630 /hub event projection lands.
            err_class = type(e).__name__
            if err_class == "TMF639ReadOnlyEndpoint":
                logger.info(
                    "TMF639 endpoint is read-only (HTTP 405); direct POST is "
                    "rejected by Canvas Resource Inventory v5. Projection "
                    "pending the TMF630 /hub event path (a design note, greenfield)."
                )
                self._set_condition(
                    patch, "TMF639Projected", "False", "TMF639ReadOnly",
                    "Canvas Resource Inventory v5 accepts only reads from "
                    "external producers; write projection pending TMF630 "
                    "event hub (a design note).",
                )
            else:
                logger.warning(f"TMF639 projection failed (best-effort): {e}")
                self._set_condition(
                    patch, "TMF639Projected", "False", "TMF639Unreachable",
                    str(e)[:200],
                )

    def _tmf639_delete(self, spec: dict) -> bool:
        try:
            from operators.shared.tmf639_client import TMF639Client
        except ImportError:
            return False
        provider_norm, asset_id = self._provider_and_asset_id(spec)
        return TMF639Client().delete_asset(asset_id, provider_norm)

    # ---------------------------------------------------------------- #
    # K8s-idiomatic resync (a design note)                                     #
    # ---------------------------------------------------------------- #
    def resync_from_registry(self, spec: dict, status: dict, patch) -> dict:
        """Timer-driven reconcile: read Registry, write status fields.

        Called by kopf @timer every 5 minutes. This is the K8s-idiomatic
        pattern: controller keeps status up-to-date with the external
        truth store even when nothing changes in the spec.

        Writes to status:
          - registryApprovalStatus: APPROVED | DRAFT | DEPRECATED | MISSING | UNKNOWN
          - registryLastObserved: ISO timestamp of this check
          - driftDetected: True if CR phase contradicts registry state
          - driftReason: short human explanation if drifted

        Returns a dict summarizing what was observed (for logs/tests).
        """
        self._seed_conditions(patch, status)
        # Finding #1: build the resync search key with the SAME canonical builder
        # the writer used, so the key matches the stored record name for
        # underscore/uppercase assets (clears that cause of false-MISSING). Note:
        # this does NOT address the separate registry-routing false-MISSING (resync
        # querying the default registry instead of the asset's registryBackingRef).
        record_name = registry_record_id(spec.get("provider", "unknown"), asset_id_from_spec(spec))

        now_iso = datetime.now(timezone.utc).isoformat()
        patch.status["registryLastObserved"] = now_iso

        # a design note Batch H: dispatch-aware search
        dispatch = self._resolve_registry_or_legacy(spec)
        try:
            if dispatch is not None:
                backing, params, _kind = dispatch
                results = backing.search(record_name, {}, params)
            else:
                from .registry_client import get_client  # noqa: PLC0415
                region = self._get_region(spec)
                client = get_client(region)
                results = client.search(query=record_name, filters={})
            match = next((r for r in results if r.get("name") == record_name), None)
        except Exception as e:
            logger.warning(f"Registry lookup failed during resync: {e}")
            patch.status["registryApprovalStatus"] = "UNKNOWN"
            patch.status["driftDetected"] = False
            patch.status["driftReason"] = f"Registry unreachable: {str(e)[:100]}"
            return {"observed": "unreachable"}

        if match is None:
            patch.status["registryApprovalStatus"] = "MISSING"
            patch.status["driftDetected"] = True
            patch.status["driftReason"] = (
                "Registry record not found — expected APPROVED. "
                "Either deleted externally or never registered."
            )
            return {"observed": "missing"}

        # Record exists — stamp state
        patch.status["registryApprovalStatus"] = _record_state(match)

        # Drift: CR thinks it's Approved but registry says otherwise
        drift = False
        drift_reason = ""
        if _record_state(match) != "APPROVED" and status.get("phase") == "Approved":
            drift = True
            drift_reason = (
                f"CR phase=Approved but registry state={match.get('state')}"
            )

        patch.status["driftDetected"] = drift
        patch.status["driftReason"] = drift_reason

        # a design note — refresh the TMF639 projection + condition on the periodic
        # timer so TMF639Projected is observable on steady-state Approved CRs
        # (the spec-change reconcile path early-returns on unchanged generation
        # and never re-projects). Only Approved assets belong in the inventory.
        # Best-effort: never raises, never affects the resync return value.
        if status.get("phase") == "Approved":
            self._project_and_stamp_tmf639(spec, patch, "Approved")

        return {"observed": _record_state(match), "drift": drift}

    def scan_orphans(self, k8s_cr_names, provider_prefix: str = None) -> list:
        """List Registry records with no matching CR (orphan detection).

        Called by kopf @timer every 1 hour. For each orphan found,
        logs a warning (K8s Event wiring happens in the kopf handler).

        Args:
            k8s_cr_names: iterable of CR names currently in K8s (from a lister)
            provider_prefix: optional prefix filter. If set, only records starting
                with "<provider-prefix>_" are considered for orphan detection.
                Use this to scope scan to records owned by this operator.

        Returns the sorted list of orphan registry record names.
        """
        # a design note Batch H: dispatch-aware orphan scan
        # When flag enabled, resolve default Registry and use backing; else legacy
        dispatch = self._resolve_registry_or_legacy({"registryRef": None})  # default
        if dispatch is not None:
            backing, params, _kind = dispatch
            class _BackingClient:
                def __init__(self, b, p):
                    self._b = b; self._p = p
                def search(self, query="", filters=None):
                    return self._b.search(query, filters or {}, self._p)
            client = _BackingClient(backing, params)
        else:
            from .registry_client import _default_region, get_client  # noqa: PLC0415
            # Cluster-scope means the DEPLOYMENT's registry region. A literal
            # "us-west-2" here sent every hourly ListRegistries from a us-east-1
            # event into a region its SCP denies (2026-09-27, event 3b1b4424)
            # while the reconcile path, which reads the env, wrote correctly.
            client = get_client(_default_region())

        try:
            # AgentCore Registry uses descriptorType=CUSTOM for all MoDaaS records.
            # Orphan scan needs all APPROVED records regardless of our internal type.
            records = client.search(query="", filters={})
        except Exception as e:
            # Raised, not swallowed: returning [] here made every timer log
            # "Orphan scan clean ... all Registry records accounted for" after a
            # scan that read nothing (events 3b1b4424 and 8acc8261, 2026-09-27).
            logger.warning(f"Registry list failed during orphan scan: {e}")
            raise

        registry_names = {r["name"] for r in records if "name" in r}
        if provider_prefix:
            # Only records prefixed with this provider belong to this operator
            registry_names = {n for n in registry_names if n.startswith(f"{provider_prefix}_")}

        # Registry record names are "<provider-norm>_<asset-id>".
        # For orphan detection we compare the <asset-id> suffix against
        # the K8s CR names (which in our demo equal the asset-id).
        cr_set = set(k8s_cr_names or [])
        orphan_names = []
        for rec_name in sorted(registry_names):
            _, _, asset_id = rec_name.partition("_")
            if asset_id and asset_id not in cr_set:
                orphan_names.append(rec_name)

        for orphan in orphan_names:
            logger.warning(
                f"Registry orphan detected: record_type={self.record_type} "
                f"record_name={orphan} — no matching CR found in cluster."
            )
        return orphan_names
