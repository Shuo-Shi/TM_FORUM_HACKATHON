"""Composition checks (a design note).

The core insight: an AgentConfig composing a ModelConfig with
safety.required=true must itself ATTEST to enforcing that safety. If the
AgentConfig does not declare safety.enforces=true with a matching
enforcerKind, approving the composition would be falsifying the
ModelConfig's safety contract at runtime.

This is symmetric with ModelConfig's own truthfulness invariant (a design note
CEL refuses required=true + enforcer.kind=none intra-CR): here we refuse
required=true in upstream without enforces=true in downstream.

The check is ATTESTATION-based, not capability-inspection-based. MoDaaS
doesn't probe or introspect runtime behavior — it takes the AgentConfig
author at their declared word. If the agent code doesn't honor the
attestation, that's a runtime integrity concern, not a composition
truthfulness concern. (Kubernetes itself works this way: Pod resource
limits are declarations the OS kernel enforces; at admission time, the
declaration alone is what's validated.)

Checks NEVER look at the data plane. Pure functions over CR specs.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Violation:
    """A composition violation — admission/reconcile-time refusal reason."""
    dimension: str          # "safety", "scope", ... (for future expansion)
    reason: str             # short machine-readable code, becomes status.reason
    message: str            # human-readable, appears in kubectl describe


def _effective_enforcer_kind(model_cr: dict) -> str:
    """Resolve the model's effective enforcer.kind with a design note back-compat.

    If no explicit enforcer block, infer from legacy inline awsBedrock.guardrails.
    """
    safety = (model_cr.get("spec") or {}).get("safety") or {}
    enforcer_decl = safety.get("enforcer") or {}
    kind = enforcer_decl.get("kind")
    if kind:
        return kind
    has_legacy_guardrails = bool(
        ((model_cr.get("spec") or {}).get("awsBedrock") or {}).get("guardrails")
    )
    return "bedrockGuardrail" if has_legacy_guardrails else "none"


def check_safety_enforcement_composable(
    agent_spec: dict,
    model_cr: dict,
) -> Optional[Violation]:
    """Refuse if the composition would falsify the model's safety contract.

    The rule (attestation model):
      model.spec.safety.required=true
        ⇒ agent.spec.safety.enforces=true AND
           agent.spec.safety.enforcerKind == model.spec.safety.enforcer.kind

    Returns None if composition is truthful, Violation otherwise.
    """
    model_safety = (model_cr.get("spec") or {}).get("safety") or {}
    model_name = (model_cr.get("metadata") or {}).get("name", "<unknown>")

    if not model_safety.get("required"):
        # Model doesn't require safety enforcement — any AgentConfig composes.
        return None

    # From here, model requires safety. AgentConfig must attest.
    agent_safety = agent_spec.get("safety") or {}
    enforces = agent_safety.get("enforces", False)
    model_kind = _effective_enforcer_kind(model_cr)

    if not enforces:
        return Violation(
            dimension="safety",
            reason="EnforcementNotDeclared",
            message=(
                f"ModelConfig '{model_name}' declares safety.required=true "
                f"with enforcer.kind={model_kind}, but AgentConfig does not "
                f"attest safety enforcement. Add spec.safety.enforces=true "
                f"with spec.safety.enforcerKind={model_kind} to the "
                f"AgentConfig (and ensure the agent runtime actually honors "
                f"it — MoDaaS trusts your attestation)."
            ),
        )

    agent_kind = agent_safety.get("enforcerKind")
    if agent_kind != model_kind:
        return Violation(
            dimension="safety",
            reason="EnforcerKindMismatch",
            message=(
                f"ModelConfig '{model_name}' requires enforcer.kind={model_kind}, "
                f"but AgentConfig attests to enforcerKind={agent_kind!r}. "
                f"The agent must enforce the same kind the model declares."
            ),
        )

    # Composition is truthful — approve.
    return None
