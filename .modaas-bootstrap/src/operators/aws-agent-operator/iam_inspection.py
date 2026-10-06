"""IAM trust/policy inspection for AgentCore execution roles (#5).

Surfaces IAM posture as advisory `status.riskFindings[]`. Called for BOTH
hosting modes since 2026-09-26 (review goal 1(a2): managed mode, where MoDaaS
creates the runtime and asserts ownership, previously never looked at the role).

This module remains advisory in both modes -- it reports, it does not decide.
The blocking decision lives in `execution_role_capability.py`, which asks IAM
directly (`iam:SimulatePrincipalPolicy`) whether the role can invoke Bedrock or
an AgentCore Gateway, and which the MANAGED path refuses on. Two reasons the
split matters: this module reads only ATTACHED MANAGED policies (an inline
Bedrock grant is invisible to it), and a refusal must be based on IAM's own
evaluation rather than on a policy-document heuristic.

Risk patterns flagged:
  - Trust policy Principal='*' (anyone can assume the role)
  - Trust policy missing aws:SourceAccount condition
  - bedrock:InvokeModel with Resource='*' (can invoke any model)
  - iam:PassRole without condition (role can impersonate anything)
"""
import json
import logging
from typing import Any

logger = logging.getLogger("AgentOperator.IAMInspection")


def inspect_role(iam_client, role_arn: str) -> list[dict]:
    """Inspect an IAM role's trust policy and attached policies for risk patterns.

    Returns a list of risk findings, each with:
      - severity: "HIGH" | "MEDIUM" | "LOW"
      - code: machine-readable risk code
      - message: human-readable description
    """
    findings: list[dict] = []
    role_name = role_arn.split("/")[-1] if "/" in role_arn else role_arn

    # 1. Inspect trust policy
    try:
        role_resp = iam_client.get_role(RoleName=role_name)
        trust_doc = role_resp.get("Role", {}).get("AssumeRolePolicyDocument", {})
        findings.extend(_check_trust_policy(trust_doc))
    except Exception as e:
        logger.warning(f"get_role({role_name}) failed: {e}")
        findings.append({
            "severity": "LOW",
            "code": "IAM_ROLE_INACCESSIBLE",
            "message": f"Could not inspect role {role_name}: {e}",
        })
        return findings

    # 2. Inspect attached managed policies
    try:
        attached = iam_client.list_attached_role_policies(RoleName=role_name)
        for policy in attached.get("AttachedPolicies", []):
            policy_arn = policy["PolicyArn"]
            try:
                pol_resp = iam_client.get_policy(PolicyArn=policy_arn)
                version_id = pol_resp["Policy"]["DefaultVersionId"]
                ver_resp = iam_client.get_policy_version(
                    PolicyArn=policy_arn, VersionId=version_id
                )
                doc = ver_resp["PolicyVersion"]["Document"]
                if isinstance(doc, str):
                    doc = json.loads(doc)
                findings.extend(_check_policy_document(doc, policy_arn))
            except Exception as e:
                logger.warning(f"get_policy_version({policy_arn}) failed: {e}")
    except Exception as e:
        logger.warning(f"list_attached_role_policies({role_name}) failed: {e}")

    return findings


def _check_trust_policy(doc: dict) -> list[dict]:
    """Check trust policy for overly permissive principals."""
    findings = []
    if isinstance(doc, str):
        doc = json.loads(doc)

    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", {})
        # Check for wildcard principal
        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
            findings.append({
                "severity": "HIGH",
                "code": "TRUST_WILDCARD_PRINCIPAL",
                "message": "Trust policy allows any AWS principal to assume this role (Principal='*')",
            })
        # Check for missing aws:SourceAccount condition
        condition = stmt.get("Condition", {})
        has_source_account = any(
            "aws:SourceAccount" in (cond_block or {})
            for cond_block in condition.values()
        )
        if not has_source_account and _is_service_principal(principal):
            findings.append({
                "severity": "MEDIUM",
                "code": "TRUST_MISSING_SOURCE_ACCOUNT",
                "message": "Trust policy for service principal missing aws:SourceAccount condition (confused deputy risk)",
            })
    return findings


def _check_policy_document(doc: dict, policy_arn: str) -> list[dict]:
    """Check policy document for overly permissive actions/resources."""
    findings = []
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        # bedrock:InvokeModel with Resource='*'
        for action in actions:
            if _matches_action(action, "bedrock:InvokeModel") and "*" in resources:
                findings.append({
                    # HIGH, not MEDIUM (review P2-6 / a design note §1): "the gateway is
                    # the sole Bedrock holder" is the whole enforcement claim, and
                    # a role that can invoke any model defeats it. Advisory
                    # severity said the opposite.
                    "severity": "HIGH",
                    "code": "BEDROCK_INVOKE_WILDCARD",
                    "message": f"Policy {policy_arn}: bedrock:InvokeModel with Resource='*' (can invoke any model)",
                })
                break

        # iam:PassRole without condition
        for action in actions:
            if _matches_action(action, "iam:PassRole"):
                condition = stmt.get("Condition", {})
                if not condition:
                    findings.append({
                        "severity": "MEDIUM",
                        "code": "PASSROLE_NO_CONDITION",
                        "message": f"Policy {policy_arn}: iam:PassRole without condition (can impersonate any role)",
                    })
                break
    return findings


def _is_service_principal(principal: Any) -> bool:
    """Check if principal is a service (e.g., bedrock.amazonaws.com)."""
    if isinstance(principal, dict):
        svc = principal.get("Service", "")
        if isinstance(svc, list):
            return len(svc) > 0
        return bool(svc)
    return False


def _matches_action(action: str, target: str) -> bool:
    """Check if an IAM action matches a target (case-insensitive, wildcard-aware)."""
    action_lower = action.lower()
    target_lower = target.lower()
    if action_lower == "*":
        return True
    if "*" in action_lower:
        prefix = action_lower.replace("*", "")
        return target_lower.startswith(prefix)
    return action_lower == target_lower
