"""Bug #17 — CloudTrail correlation via aws_request_id.

H5 audit finding: 3 sampled assets had no CloudTrail evidence linking the
operator's API calls to the lifecycle events. CloudTrail rows include the
RequestId; matching it back to the operator's log stream proves the call was
made by MoDaaS (vs. drift from a console operator).

This module provides one helper:

    log_aws_response(response, action, **context)

Call it immediately after a boto3 API response. It pulls
ResponseMetadata.RequestId off the response and emits a structured INFO log
that downstream observability (CloudWatch Logs Insights, OTel) can join with
CloudTrail records.

Design notes:
- Fail-soft: a malformed response (or None) MUST NOT raise. The caller is
  almost always inside a reconcile loop where logging is best-effort.
- The returned RequestId is also surfaced so callers can stamp it on a kopf
  condition or status field if they want CR-level traceability.
- Ninety-day CloudTrail retention is independent of this module; we add the
  *correlation key* so future evidence pulls have a canonical join column.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger("shared.aws_request_id")


def extract_request_id(response: Any) -> Optional[str]:
    """Pull ResponseMetadata.RequestId off a boto3 response.

    Returns None on any structural mismatch — never raises.
    """
    if not isinstance(response, dict):
        return None
    meta = response.get("ResponseMetadata")
    if not isinstance(meta, dict):
        return None
    rid = meta.get("RequestId")
    if isinstance(rid, str) and rid:
        return rid
    return None


def log_aws_response(
    response: Any,
    action: str,
    *,
    resource: Optional[str] = None,
    asset: Optional[str] = None,
    extra: Optional[dict] = None,
) -> Optional[str]:
    """Emit a structured INFO log with aws_request_id + action context.

    Parameters
    ----------
    response : the boto3 response dict (must carry ResponseMetadata.RequestId)
    action : the API action name (e.g. "create_registry_record")
    resource : optional resource identifier (e.g. registry record ARN)
    asset : optional CR name (e.g. "claude-sonnet-noc")
    extra : optional dict of additional fields to log

    Returns
    -------
    str | None : the captured RequestId, or None if extraction failed.
    Callers can stamp this onto a kopf condition for CR-level traceability.
    """
    request_id = extract_request_id(response)
    fields = {
        "aws_request_id": request_id or "unknown",
        "action": action,
    }
    if resource:
        fields["resource"] = resource
    if asset:
        fields["asset"] = asset
    if extra:
        for k, v in extra.items():
            # Don't allow extra to clobber the canonical fields above.
            if k not in fields:
                fields[k] = v

    # CloudWatch Logs Insights joins this line with CloudTrail via aws_request_id.
    # Format: "aws_call action=<action> aws_request_id=<id> ..."
    parts = [f"{k}={v}" for k, v in fields.items()]
    logger.info("aws_call %s", " ".join(parts))
    return request_id
