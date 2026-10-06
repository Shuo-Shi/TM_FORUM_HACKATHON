"""D-8: operator-reconciled IAM model allowlist — "IAM follows governance".

The gateway dataplane role (Pod Identity, sa modaas-agw) carries
``foundation-model/*`` wildcards across three regions: at the IAM layer ANY
Bedrock model is invocable regardless of MoDaaS governance (live probe,
2026-09-05). This module pins a **Deny-NotResource** inline policy on that
role to exactly the APPROVED ModelConfigs' ARNs:

- Deny always wins: layering this policy can only narrow access, never
  widen it, and the pre-existing Allow policy stays untouched.
- ``NotResource`` covers every ARN off the approved list for the invoke
  actions only — guardrail actions are deliberately excluded.
- Empty approved list ⇒ deny-all invokes (fail-closed).
- Reconcile is compute-the-world + idempotent put: approve adds an ARN,
  pause/retire removes it. Revocation reaches the AWS API layer, not just
  the gateway route table.

Enabled by env ``MODAAS_IAM_ALLOWLIST_ROLE`` (the role NAME to manage).
Unset ⇒ feature off, zero behavior change (self-paced installs where the
operator has no IAM write grant).
"""
from __future__ import annotations

import json
import logging
import os

log = logging.getLogger("ModelOperator")


def _aws_clients():
    """The a design note capability factory, canonical spelling first (in-tree) then
    the pod-snapshot spelling — two module objects would mean two caches."""
    try:
        from operators.shared import aws_clients  # noqa: PLC0415
    except ImportError:  # pragma: no cover - pod snapshot path
        from shared import aws_clients  # noqa: PLC0415
    return aws_clients


POLICY_NAME = "modaas-model-allowlist"
INVOKE_ACTIONS = [
    "bedrock:InvokeModel",
    "bedrock:InvokeModelWithResponseStream",
    "bedrock:Converse",
    "bedrock:ConverseStream",
]
# The regions the gateway's Allow policy spans (probed live); the deny list
# mirrors them so an approved model is usable exactly where it was before.
REGIONS = ("us-east-1", "us-east-2", "us-west-2")
# Impossible-by-construction ARN: keeps NotResource non-empty (IAM rejects
# an empty list) while matching nothing, so an empty approved set denies
# every real model ARN.
_FAIL_CLOSED_PLACEHOLDER = "arn:aws:bedrock:us-east-1::foundation-model/modaas-fail-closed-placeholder"


def arns_for_model(model_id: str, account: str) -> list[str]:
    """Every ARN an approved model may legitimately be invoked through:
    its foundation-model ARN per region plus the account-scoped ``us.``
    cross-region inference-profile ARNs the gateway rewrites to."""
    arns = [f"arn:aws:bedrock:{r}::foundation-model/{model_id}" for r in REGIONS]
    arns += [
        f"arn:aws:bedrock:{r}:{account}:inference-profile/us.{model_id}"
        for r in REGIONS
    ]
    return arns


def build_allowlist_policy(model_ids: list[str], account: str) -> dict:
    """Deterministic Deny-NotResource document for the approved set."""
    not_resources: list[str] = []
    for mid in sorted(set(model_ids)):
        not_resources.extend(arns_for_model(mid, account))
    if not not_resources:
        not_resources = [_FAIL_CLOSED_PLACEHOLDER]
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ModaasApprovedModelsOnly",
                "Effect": "Deny",
                "Action": list(INVOKE_ACTIONS),
                "NotResource": sorted(not_resources),
            }
        ],
    }


def _approved_model_ids(list_modelconfigs) -> list[str]:
    """Extract resolvedModelId from every Approved, unpaused ModelConfig."""
    ids = []
    for mc in list_modelconfigs:
        status = mc.get("status") or {}
        spec = mc.get("spec") or {}
        if status.get("phase") != "Approved" or spec.get("paused"):
            continue
        mid = status.get("resolvedModelId")
        if mid:
            ids.append(mid)
    return ids


def reconcile_allowlist(list_modelconfigs, *, iam_client=None,
                        sts_client=None) -> str | None:
    """Compute the approved set and idempotently pin the role policy.

    Returns a short outcome string for condition/log surfacing, or None
    when the feature is disabled. Never raises — an IAM failure must not
    block model reconciliation (observe-and-surface, a design note)."""
    role = os.environ.get("MODAAS_IAM_ALLOWLIST_ROLE", "")
    if not role:
        return None
    try:
        # a design note: by capability, through the one factory. Injected clients still
        # win — every test in this module supplies its own. The local MUST be
        # named `aws_clients`: that name is what the Rule-23 static guard
        # recognises as the factory rather than as a boto3 session.
        aws_clients = _aws_clients()
        iam = iam_client or aws_clients.client("iam")
        sts = sts_client or aws_clients.client("sts")
        account = sts.get_caller_identity()["Account"]
        model_ids = _approved_model_ids(list_modelconfigs)
        desired = build_allowlist_policy(model_ids, account)
        try:
            cur = iam.get_role_policy(RoleName=role, PolicyName=POLICY_NAME)
            current = cur.get("PolicyDocument")
        except Exception:
            current = None
        if current == desired:
            return f"allowlist in sync ({len(model_ids)} models)"
        iam.put_role_policy(
            RoleName=role, PolicyName=POLICY_NAME,
            PolicyDocument=json.dumps(desired),
        )
        log.info(
            "IAM model allowlist reconciled on %s: %d approved models %s",
            role, len(model_ids), sorted(set(model_ids)),
        )
        return f"allowlist updated ({len(model_ids)} models)"
    except Exception as exc:  # noqa: BLE001 — observe-and-surface
        log.warning("IAM model allowlist reconcile failed: %s", exc)
        return f"allowlist reconcile failed: {str(exc)[:200]}"
