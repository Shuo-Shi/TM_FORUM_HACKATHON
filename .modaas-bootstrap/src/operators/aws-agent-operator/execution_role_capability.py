"""Does this execution role hold capability the gateway is supposed to hold?

Review goal 1(a)/(a2) + P2-6; a design note §1. MoDaaS's claim is that agentgateway is
the only door to a governed model or tool. That claim is only true if the
workload cannot open the door itself -- i.e. if the AgentCore Runtime's
execution role cannot invoke Bedrock or an AgentCore Gateway directly. The
operator neither mints that role nor constrained it: `roleArn` is caller-
supplied, and `iam_inspection.inspect_role` was advisory and ran in adopt mode
only.

Why `iam:SimulatePrincipalPolicy` and not more policy parsing:
`iam_inspection` reads ATTACHED MANAGED policies. It cannot see inline role
policies, permissions boundaries, or an organization SCP -- so a role whose
Bedrock grant is inline reads as clean. Simulate answers the actual question
("would IAM allow this principal to call this action") across every policy type
IAM evaluates, in one call.

`bedrock:Converse` is deliberately absent from the action list: Converse and
ConverseStream are authorized by `bedrock:InvokeModel` /
`InvokeModelWithResponseStream`. Adding a Converse action would look like
broader coverage and add none.

Fail-closed: a simulation that cannot be performed returns an "undetermined"
reason, never an empty (i.e. clean-looking) result. The caller refuses on it.
"""
from __future__ import annotations

import logging

logger = logging.getLogger("AgentOperator.ExecutionRoleCapability")

#: Actions that must live with the gateway's role, not the workload's.
GOVERNED_CAPABILITY_ACTIONS: tuple[str, ...] = (
    "bedrock:InvokeModel",
    "bedrock:InvokeModelWithResponseStream",
    "bedrock-agentcore:InvokeGateway",
)

#: IAM's word for "this principal may perform the action".
_ALLOWED_DECISION = "allowed"


def check_execution_role_capability(
    iam_client,
    role_arn: str,
    *,
    actions: tuple[str, ...] = GOVERNED_CAPABILITY_ACTIONS,
) -> tuple[list[str], str]:
    """Simulate `actions` against `role_arn`.

    Returns:
        ``(allowed_actions, undetermined_reason)``.

        * ``allowed_actions`` non-empty -> the role can bypass the perimeter.
        * ``undetermined_reason`` non-empty -> the check could not be performed;
          treat as NOT verified. Never treat this as clean.
        * both empty -> the role holds none of the actions.
    """
    try:
        resp = iam_client.simulate_principal_policy(
            PolicySourceArn=role_arn,
            ActionNames=list(actions),
        )
    except Exception as exc:  # noqa: BLE001 — every failure mode is "unknown"
        logger.warning("simulate_principal_policy(%s) failed: %s", role_arn, exc)
        return [], (
            f"could not determine whether {role_arn} can invoke a governed asset "
            f"directly: iam:SimulatePrincipalPolicy failed ({type(exc).__name__}: "
            f"{exc}). Grant iam:SimulatePrincipalPolicy to the operator role, or "
            f"use a role the operator can simulate."
        )

    results = resp.get("EvaluationResults")
    if not results:
        return [], (
            f"iam:SimulatePrincipalPolicy returned no EvaluationResults for "
            f"{role_arn}; capability is unverified"
        )

    allowed = [
        r.get("EvalActionName", "")
        for r in results
        if r.get("EvalDecision") == _ALLOWED_DECISION
    ]
    return [a for a in allowed if a], ""


def capability_finding(allowed_actions: list[str], role_arn: str) -> dict:
    """An `iam_inspection`-shaped finding for `status.riskFindings`."""
    return {
        "severity": "HIGH",
        "code": "EXECUTION_ROLE_CAN_INVOKE_DIRECTLY",
        "message": (
            f"Execution role {role_arn} is allowed to call "
            f"{', '.join(allowed_actions)} directly, so this agent can bypass the "
            f"MoDaaS perimeter (agentgateway + Cedar) entirely."
        ),
    }


def unverified_finding(reason: str, role_arn: str) -> dict:
    """An `iam_inspection`-shaped finding for the undetermined case."""
    return {
        "severity": "MEDIUM",
        "code": "EXECUTION_ROLE_CAPABILITY_UNVERIFIED",
        "message": f"{role_arn}: {reason}",
    }
