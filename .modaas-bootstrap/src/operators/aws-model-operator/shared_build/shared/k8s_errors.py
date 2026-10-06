"""K8s exception -> status-condition reason.

Single home for a classifier that is currently copy-pasted into all three aws-*
operators (`_classify_k8s_error` at model_operator.py:1458,
tool_operator.py:665, agent_operator.py:1113). k8s-agent-operator imports this;
integration can repoint the three siblings without a behaviour change.

Why this exists at all: a condition reason is what an operator reads off
`kubectl describe` when a governed asset is stuck. "Unknown" tells them nothing,
so this function never returns it -- an unmapped HTTP status keeps its code
(`HTTP418`) and a non-HTTP exception keeps its type name.
"""
from __future__ import annotations

_BY_STATUS = {
    403: "RBACDenied",
    404: "NotFound",
    409: "Conflict",
    422: "Invalid",
}


def classify(exc: Exception) -> str:
    """Return a short, stable, greppable reason string for ``exc``."""
    status = getattr(exc, "status", None)
    if isinstance(status, int) and not isinstance(status, bool):
        mapped = _BY_STATUS.get(status)
        if mapped:
            return mapped
        if 500 <= status <= 599:
            return "ServerError"
        return f"HTTP{status}"
    if isinstance(exc, ImportError):
        # Covers ModuleNotFoundError, which is the shape the operators' lazy
        # `from shared.X import Y` fallbacks actually raise.
        return "ImportFailed"
    return type(exc).__name__
