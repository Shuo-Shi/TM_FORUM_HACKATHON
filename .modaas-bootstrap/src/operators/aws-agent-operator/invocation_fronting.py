"""a design note point 3 — the `InvocationFronted` condition model.

Pure functions only. `aws-agent-operator` does the reading (`get_resource_policy`
on the runtime and the endpoint, a `get` on the HTTPRoute); this module decides
what the reading MEANS and produces a `(status, reason, message)` triple for
`_set_condition`. Integration call sites are listed in LANE_REPORT.md §5.

Why a condition rather than a hard refusal
------------------------------------------
a design note's cascade-observability shape: the operator observes and surfaces, it
does not tear an already-Approved asset down for a transient AWS-side state.
`InvocationFronted=False` with a specific reason is the visibility surface. Any
tightening that REFUSES (admission or approval) belongs behind an owner decision
because it can reject an already-Approved population — LANE_REPORT.md §4 lists
the CRD fields that decision needs.

Reason ordering is a security decision, not cosmetic
----------------------------------------------------
When several things are wrong at once, the reported reason is the most dangerous
one. `route_present=True` with no resource policy means the runtime is reachable
DIRECTLY by anything holding an identity-based allow — the exact bypass a design note
exists to close. `RouteMissing` with correct policies means callers cannot reach
the agent through MoDaaS: an availability problem, not a governance hole. So
policy gaps are reported before route gaps.
"""
import json
from typing import Any, Dict, Optional, Tuple

try:
    from shared.agentcore_resource_policy import (
        DEFAULT_ENDPOINT_NAME,
        InvocationFrontingConfigError,
        render_invocation_fronting_policies,
    )
except ModuleNotFoundError:  # pragma: no cover - repo-root import path
    from operators.shared.agentcore_resource_policy import (  # type: ignore
        DEFAULT_ENDPOINT_NAME,
        InvocationFrontingConfigError,
        render_invocation_fronting_policies,
    )

# Re-exported deliberately. `InvocationFrontingConfigError` is raised from
# whichever of the two import paths resolved first, and the dual-import shape
# means `operators.shared.agentcore_resource_policy` and
# `shared.agentcore_resource_policy` can be two distinct module objects with two
# distinct exception CLASSES — so an `except` against the other spelling misses
# silently. This is the same module-identity hazard
# `operators/aws-agent-operator/tests/conftest.py` documents for
# `asset_operator` / `ProvisioningFailed`. Callers (agent_operator.py, plan 1.19)
# must catch the class re-exported HERE.

CONDITION_TYPE = "InvocationFronted"


class Reason:
    """Condition `reason` values. Stable, greppable, position-independent."""

    FRONTED = "InvocationFronted"
    NOT_REQUESTED = "FrontingNotRequested"
    RUNTIME_ARN_UNKNOWN = "RuntimeArnUnknown"
    RUNTIME_POLICY_MISSING = "RuntimePolicyMissing"
    RUNTIME_POLICY_MISMATCH = "RuntimePolicyMismatch"
    ENDPOINT_POLICY_MISSING = "EndpointPolicyMissing"
    ENDPOINT_POLICY_MISMATCH = "EndpointPolicyMismatch"
    ROUTE_MISSING = "RouteMissing"


def _as_policy_dict(value: Any) -> Optional[dict]:
    """Normalize an observed policy to a dict.

    `get_resource_policy` returns `response['policy']` as a JSON STRING
    (resource-based-policies.html's boto3 example prints it directly), while a
    freshly rendered desired policy is a dict. Accept both; return None for
    anything unparseable so the caller reports a mismatch rather than raising on
    the reconcile path.
    """
    if isinstance(value, dict):
        return value
    if isinstance(value, (str, bytes)):
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _canonical(policy: dict) -> Optional[tuple]:
    """A comparison key that ignores statement and action ORDER.

    AWS echoes back what was PUT, so a naive `==` would usually work — but a
    policy edited by hand, or re-serialized by another tool, would read as
    permanent drift and the operator would re-PUT the same document on every
    reconcile. Order-insensitive comparison keeps drift meaning drift.
    """
    statements = policy.get("Statement")
    if not isinstance(statements, list):
        return None
    canon = []
    for stmt in statements:
        if not isinstance(stmt, dict):
            return None
        action = stmt.get("Action")
        actions = tuple(sorted(action)) if isinstance(action, list) else (action,)
        canon.append((
            stmt.get("Sid"),
            stmt.get("Effect"),
            json.dumps(stmt.get("Principal"), sort_keys=True),
            actions,
            stmt.get("Resource"),
            json.dumps(stmt.get("Condition"), sort_keys=True),
        ))
    return (policy.get("Version"), tuple(sorted(canon, key=repr)))


def policies_equivalent(desired: Any, observed: Any) -> bool:
    """True when two policy documents say the same thing.

    Either side may be a dict or a JSON string. Anything unparseable, or absent,
    is not equivalent — never equivalent-by-default, which would report a
    governed-looking agent whose policy nobody could read.
    """
    a, b = _as_policy_dict(desired), _as_policy_dict(observed)
    if a is None or b is None:
        return False
    ca, cb = _canonical(a), _canonical(b)
    if ca is None or cb is None:
        return False
    return ca == cb


def desired_fronting_state(
    *,
    runtime_arn: Optional[str],
    gateway_role_arn: str,
    endpoint_name: str = DEFAULT_ENDPOINT_NAME,
) -> Optional[Dict[str, dict]]:
    """The two policies this agent SHOULD carry, or None when not yet knowable.

    Returns None only when the runtime ARN is absent — an AgentConfig that has
    not finished provisioning. A malformed ARN or a malformed gateway role raises
    (`InvocationFrontingConfigError` from the renderer): those are configuration
    errors, and swallowing them would leave the agent unfronted and silent.
    """
    if not (runtime_arn or "").strip():
        return None
    return render_invocation_fronting_policies(
        runtime_arn, gateway_role_arn, endpoint_name=endpoint_name)


def evaluate_invocation_fronted(
    *,
    fronting_requested: bool,
    desired: Optional[Dict[str, dict]],
    observed_runtime_policy: Any,
    observed_endpoint_policy: Any,
    route_present: bool,
) -> Tuple[str, str, str]:
    """Decide the `InvocationFronted` condition from observed state.

    Args:
        fronting_requested: whether this AgentConfig asks to be fronted (see
            LANE_REPORT.md §4 for the spec field that carries it).
        desired: `desired_fronting_state(...)` output, or None when the runtime
            ARN is not yet known.
        observed_runtime_policy: `get_resource_policy(runtime ARN)['policy']`,
            or None when AWS reports no policy (ResourceNotFoundException).
        observed_endpoint_policy: the same for the endpoint ARN.
        route_present: whether the AgentgatewayBackend + HTTPRoute pair exists.

    Returns:
        `(status, reason, message)` for `_set_condition`. `status` is the string
        `"True"`/`"False"` the CRD's condition schema expects, not a bool.
    """
    if not fronting_requested:
        return (
            "False",
            Reason.NOT_REQUESTED,
            "Invocation fronting not requested for this AgentConfig; callers may "
            "reach the runtime directly (a design note point 3 not applied).",
        )

    if desired is None:
        return (
            "False",
            Reason.RUNTIME_ARN_UNKNOWN,
            "Invocation fronting requested but status.agentRuntimeArn is not set "
            "yet; nothing to front until the runtime is provisioned.",
        )

    runtime_arn = desired["runtime"]["resourceArn"]
    endpoint_arn = desired["endpoint"]["resourceArn"]

    # Policy gaps first: a present route over an unprotected runtime is the
    # bypassable state (see module docstring).
    # `None` means AWS reported no policy at all (ResourceNotFoundException).
    # A present-but-unreadable value is NOT "missing" — it falls through to the
    # mismatch branch, because something is attached and it is not ours.
    if observed_runtime_policy is None:
        return (
            "False",
            Reason.RUNTIME_POLICY_MISSING,
            f"No resource-based policy on {runtime_arn}; any principal with an "
            "identity-based bedrock-agentcore:InvokeAgentRuntime allow can "
            "invoke this agent directly, bypassing agentgateway.",
        )
    if not policies_equivalent(desired["runtime"]["policy"], observed_runtime_policy):
        return (
            "False",
            Reason.RUNTIME_POLICY_MISMATCH,
            f"The resource-based policy on {runtime_arn} is not the "
            "gateway-only policy MoDaaS declares; direct invocation may be "
            "permitted.",
        )

    if observed_endpoint_policy is None:
        return (
            "False",
            Reason.ENDPOINT_POLICY_MISSING,
            f"No resource-based policy on {endpoint_arn}. InvokeAgentRuntime is "
            "authorized against BOTH the runtime and the endpoint, so the "
            "runtime policy alone does not withhold the capability.",
        )
    if not policies_equivalent(desired["endpoint"]["policy"], observed_endpoint_policy):
        return (
            "False",
            Reason.ENDPOINT_POLICY_MISMATCH,
            f"The resource-based policy on {endpoint_arn} is not the "
            "gateway-only policy MoDaaS declares.",
        )

    if not route_present:
        return (
            "False",
            Reason.ROUTE_MISSING,
            "Capability is withheld (both resource policies match) but no "
            "agentgateway route serves this agent, so the /agents/<alias>/"
            "invocations perimeter path is unreachable.",
        )

    return (
        "True",
        Reason.FRONTED,
        f"agentgateway is the only principal that may invoke {runtime_arn}, and "
        "the perimeter route is served.",
    )


__all__ = [
    "CONDITION_TYPE",
    "InvocationFrontingConfigError",
    "Reason",
    "policies_equivalent",
    "desired_fronting_state",
    "evaluate_invocation_fronted",
]
