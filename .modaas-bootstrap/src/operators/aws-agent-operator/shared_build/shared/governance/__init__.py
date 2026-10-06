"""a design note — Governance Approval Gate (Pending → Reviewing → Approved).

Pure-function predicates for evaluating approval state. Operator-side gate
applied between structural validation (a design note, a design note, a design note) and Approved
phase transition. The gate refuses to advance to Approved until a signed
attestation from the role declared in spec.governance.approval.approverRole
appears in status.governance.approvals[].

Auto-approval is opt-in per asset: spec.governance.approval.required defaults
to spec.safety.required, so safety-required assets need human attestation
while non-safety-required assets continue auto-approving.

ATTESTATION-BASED, like a design note: MoDaaS trusts whoever the K8s API
authenticates as having the approver role. Full Keycloak JWT verification
is post-DTW (see a design note §4 "Approval submission mechanism").
"""
from .approval import (  # noqa: F401
    check_approval_satisfied,
    default_approver_role,
    derive_approval_required,
)

__all__ = [
    "check_approval_satisfied",
    "default_approver_role",
    "derive_approval_required",
]
