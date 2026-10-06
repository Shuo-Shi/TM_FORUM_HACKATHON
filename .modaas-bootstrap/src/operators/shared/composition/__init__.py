"""Composition truthfulness invariant (a design note).

Control-plane module: enforces that AgentConfig CRs can only reach Approved
when their spec.safety ATTESTATION matches the safety contracts declared
by their dependsOn upstream CRs (ModelConfig, ToolConfig).

Parallel to a design note's intra-CR CEL truthfulness (refuses safety.required=true
+ enforcer.kind=none within one ModelConfig), this is the inter-CR version
for AgentConfig → ModelConfig compositions.

ATTESTATION-BASED: AgentConfig author declares enforces=true + enforcerKind.
MoDaaS trusts the declaration at admission time (like Kubernetes trusts Pod
resource limits as declarations). Runtime integrity is a separate concern.

NEVER reaches into the data plane. NEVER injects env vars. NEVER modifies
runtime containers. Only refuses compositions whose declarations would be
falsified at invocation time.
"""
# Relative imports — works whether this package is imported as
# `shared.composition` (from sys.path=shared_build) or as
# `operators.shared.composition` (from sys.path=/operator, the container
# layout).
from .checks import (  # noqa: F401
    Violation,
    check_safety_enforcement_composable,
)

__all__ = [
    "Violation",
    "check_safety_enforcement_composable",
]
