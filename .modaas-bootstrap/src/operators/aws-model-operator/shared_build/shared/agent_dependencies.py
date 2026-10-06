"""AgentConfig cross-asset dependency logic — a design note + a design note.

`dependsOn` semantics are a property of the AgentConfig KIND, not of a hosting
provider, so both agent operators (aws-agent-operator for awsAgentCore,
k8s-agent-operator for kubernetesPod) need the identical gate.
`project.md`'s Forbidden list bans forking shared logic per operator, so this is
the single home.

Semantics are lifted unchanged from aws-agent-operator/agent_operator.py
(`check_dependency_health` :109-149, `_validate_dependencies` :151-224) so
integration can repoint that operator here with no behaviour change. Read those
docstrings for the full rationale; the two load-bearing rules are:

  * `validate_dependencies` is an ADMISSION gate, not a steady-state gate. It
    hard-fails only on the FIRST provision attempt. Once an AgentConfig reached
    phase=Approved, transient dep state (a ToolConfig briefly Reviewing during a
    schema-drift re-approval) must NOT knock the agent offline -- that cascade is
    the anti-pattern a design note rejects. A MISSING dep always fails, at any phase:
    the governance record is broken, not transient.
  * `check_dependency_health` OBSERVES the same graph on a timer and returns a
    reason for the DependencyHealthy condition. It never pauses anything.
"""
from __future__ import annotations

from operators.shared.asset_operator import ProvisioningFailed

# a design note composition truthfulness. Imported at module load so a sibling operator
# that does not bundle shared/composition still gets the dependency gate -- it
# just does not get the safety-attestation refusal. Tests monkeypatch this to
# None to exercise that path.
try:  # pragma: no cover - exercised via the monkeypatched None path
    from operators.shared.composition import check_safety_enforcement_composable as \
        _composition_check
except ImportError:  # pragma: no cover - only when shared/composition is absent
    _composition_check = None

_KINDS = (("models", "modelconfigs"), ("tools", "toolconfigs"))
_GROUP = "oda.tmforum.org"
_VERSION = "v1beta1"


def validate_dependencies(spec: dict, k8s, status: dict | None = None) -> None:
    """Refuse INITIAL approval until every declared dependency is Approved.

    Raises ProvisioningFailed; returns None when the composition is admissible.
    """
    previously_approved = (status or {}).get("phase") == "Approved"
    deps = spec.get("dependsOn") or {}

    for model_ref in deps.get("models") or []:
        cr = _get_or_refuse(k8s, "modelconfigs", "ModelConfig", model_ref)
        if not previously_approved and cr.get("status", {}).get("phase") != "Approved":
            raise ProvisioningFailed(
                "DependencyNotApproved", f"ModelConfig '{model_ref}' not Approved")
        # a design note: only on INITIAL approval, matching DependencyNotApproved above.
        if _composition_check is not None and not previously_approved:
            violation = _composition_check(spec, cr)
            if violation is not None:
                raise ProvisioningFailed(violation.reason, violation.message)

    for tool_ref in deps.get("tools") or []:
        cr = _get_or_refuse(k8s, "toolconfigs", "ToolConfig", tool_ref)
        if not previously_approved and cr.get("status", {}).get("phase") != "Approved":
            raise ProvisioningFailed(
                "DependencyNotApproved", f"ToolConfig '{tool_ref}' not Approved")


def check_dependency_health(spec: dict, k8s) -> tuple[bool, str]:
    """Observe the dependsOn graph. Returns (healthy, reason).

    Unhealthy states, in priority order: missing, paused, retired, failed,
    not-approved. Returns on the FIRST unhealthy dependency -- the condition
    carries one reason, so walking the rest would cost API calls for a message
    nobody reads.
    """
    deps = spec.get("dependsOn") or {}
    for kind, plural in _KINDS:
        for dep_name in deps.get(kind) or []:
            try:
                cr = k8s.get(_GROUP, _VERSION, plural, dep_name)
            except Exception:
                return False, f"DependencyMissing: {plural}/{dep_name} not found"
            dep_spec = cr.get("spec") or {}
            dep_status = cr.get("status") or {}
            if dep_spec.get("paused"):
                return False, f"DependencyPaused: {plural}/{dep_name}"
            dep_phase = dep_status.get("phase")
            if dep_phase == "Retired":
                return False, f"DependencyRetired: {plural}/{dep_name}"
            if dep_phase == "Failed":
                return False, f"DependencyFailed: {plural}/{dep_name}"
            if dep_phase != "Approved":
                return False, (f"DependencyNotApproved: {plural}/{dep_name} "
                               f"phase={dep_phase}")
    return True, "AllDepsHealthy"


def _get_or_refuse(k8s, plural: str, kind: str, name: str) -> dict:
    try:
        return k8s.get(_GROUP, _VERSION, plural, name)
    except Exception:
        raise ProvisioningFailed("DependencyMissing", f"{kind} '{name}' not found")
