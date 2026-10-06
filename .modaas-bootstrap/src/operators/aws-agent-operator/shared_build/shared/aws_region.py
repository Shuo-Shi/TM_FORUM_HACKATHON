"""Single resolver for the AWS region an operator calls.

Why this exists: the operators used to read ``AWS_REGION`` with a hardcoded
``"us-west-2"`` fallback while the Helm chart sets ``AWS_DEFAULT_REGION``.
The chart value never reached those calls, so on any non-us-west-2 cluster the
operator silently called the wrong Region (reviewer finding, 2026-10-02: every
``agentCoreGateway`` ToolConfig failed with an SCP ``AccessDenied`` on
``us-west-2`` in a ``us-east-1`` account).

Precedence (first non-empty wins):
  1. an explicit value from the CR spec, when the caller passes one
  2. ``AWS_REGION``
  3. ``AWS_DEFAULT_REGION``
Nothing else. There is no silent default: if none is set the operator raises
``RegionUnresolved`` so the misconfiguration is visible at the first AWS call
instead of surfacing as an unrelated ``AccessDenied`` in a Region nobody chose.
"""
from __future__ import annotations

import os

_ENV_KEYS = ("AWS_REGION", "AWS_DEFAULT_REGION")


class RegionUnresolved(RuntimeError):
    """No region in the CR spec and neither AWS_REGION nor AWS_DEFAULT_REGION is set."""


def resolve_region(spec_region: str | None = None) -> str:
    if spec_region:
        return spec_region
    for key in _ENV_KEYS:
        value = (os.environ.get(key) or "").strip()
        if value:
            return value
    raise RegionUnresolved(
        "AWS region not configured: set AWS_REGION or AWS_DEFAULT_REGION on the "
        "operator Deployment (the Helm chart sets AWS_DEFAULT_REGION from "
        "global.aws.region). Refusing to guess a Region."
    )
