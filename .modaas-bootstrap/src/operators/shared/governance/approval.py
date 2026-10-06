"""a design note governance approval predicate.

Pure functions, no I/O, no kopf, no kubernetes-client dependencies. The
AssetOperator base wraps these with phase-machine transitions and
PublishedNotification emission; tests exercise the predicates directly
with synthetic spec/status dicts.

Three responsibilities:

1. ``derive_approval_required(spec)`` — apply a design note's default-flip rule:
   ``spec.governance.approval.required`` defaults to ``spec.safety.required``
   when unset. Safety-required assets opt INTO approval gating; non-safety
   assets opt OUT (preserving the legacy auto-approve behavior).

2. ``default_approver_role(record_type, asset_id)`` — emit the canonical FQN
   role name ``modaas-<kind>-<alias>-admin``. a design note IdentityConfig
   provisioning already creates this Keycloak role; a design note canonicalizes
   the format. Used as the fallback when ``spec.governance.approval.approverRole``
   is unset.

3. ``check_approval_satisfied(spec, status, record_type=None, asset_id=None)``
   — the predicate AssetOperator delegates to. Returns True iff the asset
   is eligible to advance to Approved per its declared approval contract.

   Decision tree (a design note §4):
     - status.phase already "Approved"           → True (grandfather; same
                                                          shape as a design note
                                                          cascade-observability:
                                                          enforce-at-first-approval,
                                                          observe-after-approval)
     - approval.required == False                → True (auto-approve)
     - approval.required == True AND
       len(matching_role_approvals) >= required  → True
     - otherwise                                 → False
"""
from __future__ import annotations

from typing import Optional


def derive_approval_required(spec: dict) -> bool:
    """Resolve the effective ``approval.required`` per a design note default-flip.

    Logic:
      - explicit ``spec.governance.approval.required`` value wins
      - otherwise default to ``spec.safety.required`` (False if unset)

    Returns True if a human attestation MUST be present before the asset
    can advance to Approved.
    """
    governance = spec.get("governance") or {}
    approval = governance.get("approval") or {}
    if "required" in approval:
        return bool(approval["required"])
    safety = spec.get("safety") or {}
    return bool(safety.get("required", False))


def default_approver_role(record_type: str, asset_id: str) -> str:
    """Compute the canonical approver role per a design note.

    Pattern: ``modaas-<kind>-<alias>-admin`` where ``<kind>`` is the lowercase
    CRD kind (modelconfig / toolconfig / agentconfig) and ``<alias>`` is the
    asset's stable identifier (spec.alias / spec.toolName / spec.agentName).
    a design note IdentityConfig provisions this role in the canvas-keycloak realm;
    a design note reads it as the default approver authority.
    """
    kind_map = {"model": "modelconfig", "tool": "toolconfig", "agent": "agentconfig"}
    kind_token = kind_map.get(record_type or "", record_type or "asset").lower()
    alias = (asset_id or "unknown").lower()
    return f"modaas-{kind_token}-{alias}-admin"


def _resolve_expected_role(
    spec: dict,
    record_type: Optional[str],
    asset_id: Optional[str],
) -> str:
    """Pull spec.governance.approval.approverRole or fall back to default."""
    governance = spec.get("governance") or {}
    approval = governance.get("approval") or {}
    explicit = approval.get("approverRole")
    if explicit:
        return explicit
    # Resolve asset_id from spec when caller didn't pass one.
    if not asset_id:
        asset_id = (
            spec.get("alias")
            or spec.get("toolName")
            or spec.get("agentName")
            or "unknown"
        )
    return default_approver_role(record_type or "asset", asset_id)


def check_approval_satisfied(
    spec: dict,
    status: dict,
    record_type: Optional[str] = None,
    asset_id: Optional[str] = None,
) -> bool:
    """Return True iff the asset is eligible to advance to Approved.

    Grandfather rule (a design note §7): if ``status.phase`` is already ``"Approved"``,
    bypass the gate. This is identical in shape to a design note cascade-observability:
    enforce at first approval, observe afterward. Without the bypass every
    pre-a design note Approved CR would back-rev to Reviewing on the first reconcile
    after the operator picks up a design note.

    Parameters
    ----------
    spec : dict
        ``CR.spec`` dictionary.
    status : dict
        ``CR.status`` dictionary.
    record_type : str | None
        Internal short name: ``"model"`` / ``"tool"`` / ``"agent"``. Used to
        compute the default approver role.
    asset_id : str | None
        Asset alias (spec.alias / toolName / agentName). When None, the
        function falls back to spec lookup.
    """
    # Grandfather pattern — already-Approved CRs do not re-evaluate the gate.
    if (status or {}).get("phase") == "Approved":
        return True

    if not derive_approval_required(spec):
        # Non-safety-required default OR explicit opt-out → auto-approve.
        return True

    governance = (spec or {}).get("governance") or {}
    approval = governance.get("approval") or {}
    required_count = int(approval.get("requiredApprovals", 1))
    if required_count < 1:
        # Defensive: a non-positive count would silently auto-approve. Coerce.
        required_count = 1

    expected_role = _resolve_expected_role(spec, record_type, asset_id)

    approvals = ((status or {}).get("governance") or {}).get("approvals") or []
    valid = [
        a
        for a in approvals
        if isinstance(a, dict)
        and a.get("role") == expected_role
        and a.get("subject")  # subject must be present (audit completeness)
    ]
    return len(valid) >= required_count
