"""a design note point 3 — render the AgentCore resource-based policies that make
agentgateway the only principal able to invoke a governed AgentCore agent.

Zero I/O, zero Kubernetes, zero boto3: every function here is a pure
transformation from (runtime ARN, gateway role ARN) to policy documents. The
caller (`aws-agent-operator`, wired in plan 1.19) is the only thing that talks
to `bedrock-agentcore-control put_resource_policy`.

Why TWO policies, not one
-------------------------
`InvokeAgentRuntime` is authorized hierarchically. From
docs.aws.amazon.com/bedrock-agentcore/latest/devguide/resource-based-policies.html
(fetched 2026-09-26), "Hierarchical authorization for agent runtime and
endpoint":

    "When authorizing runtime API operations such as InvokeAgentRuntime and
    InvokeAgentRuntimeCommand, AWS evaluates both identity-based and
    resource-based policies for both the agent runtime and the agent endpoint
    being invoked."

    "To provide cross-account access to a principal, you must create
    resource-based policies granting access for both the agent runtime and the
    agent endpoint. If either resource denies access or lacks an explicit allow
    statement, the request will be denied."

So `render_invocation_fronting_policies` returns two documents keyed by the ARN
each must be attached to. Attaching only the runtime policy is the failure mode
this module's shape exists to prevent.

Why the deny statement carries Principal `*`
--------------------------------------------
The Allow-only form is not capability withholding: any principal in the account
with an identity-based `bedrock-agentcore:InvokeAgentRuntime` allow can still
invoke the runtime, because "Either Policy Can Allow". The explicit deny keyed
on `aws:PrincipalArn` is what closes that, and AWS's own guidance for exactly
this scenario uses it — .../runtime-oauth.html#runtime-restrict-iam-gateway,
"Restrict IAM (SigV4) inbound invocation to your gateway":

    "Allow that role, and add an explicit Deny for every other principal so that
    no other identity can invoke the runtime even with a permissive
    identity-based policy."

    "An explicit Deny always overrides any Allow, including identity-based
    policies in the same account."

`Resource` is never `*`
-----------------------
    '"Resource": "*" is not supported and will result in a validation error.'
    "The Resource field in the policy document must contain the exact ARN of the
    resource to which the policy is attached."

Both are enforced here by construction and by refusal, not by comment.

Scope note (what this module does NOT do)
-----------------------------------------
This is the SigV4-inbound realization (option (a) in LANE_REPORT.md §1). A
runtime configured with `authorizerConfiguration.customJWTAuthorizer` is an
OAuth runtime, and AWS requires a wildcard PRINCIPAL there — "The wildcard
principal ("Principal": "*") is required for OAuth authentication" — which this
module deliberately refuses to render. A JWT-inbound runtime therefore needs a
different renderer, not a parameter on this one; see LANE_REPORT.md §1 for why
option (a) is the recommendation.
"""
import re
from typing import Dict, List

# The one action the gateway is granted. agentgateway's native AgentCore
# backend calls InvokeAgentRuntime (crates/agentgateway/src/aws.rs:
# `AwsService::AgentCore(_) => "bedrock-agentcore"` signing service, path
# asserted `starts_with("/runtimes/")` / `ends_with("/invocations")`), so
# nothing else needs granting. Least privilege by default.
INVOCATION_ACTION = "bedrock-agentcore:InvokeAgentRuntime"

# Every action that INVOKES the agent, from the "Agent Runtime actions" list in
# resource-based-policies.html. Denying only INVOCATION_ACTION would leave the
# five siblings reachable — the capability would not be withheld, which is the
# single defect class a design note exists to close.
#
# Deliberately EXCLUDED, and why: `StopRuntimeSession` and `GetAgentCard` are
# session management and introspection, not invocation. Denying them to every
# non-gateway principal would also deny the operator, which reads the agent
# card into `status.agentCardUrl`. Scope the deny to invocation.
DENIED_INVOCATION_ACTIONS: List[str] = [
    "bedrock-agentcore:InvokeAgentRuntime",
    "bedrock-agentcore:InvokeAgentRuntimeForUser",
    "bedrock-agentcore:InvokeAgentRuntimeCommand",
    "bedrock-agentcore:InvokeAgentRuntimeCommandShell",
    "bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStream",
    "bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStreamForUser",
]

DEFAULT_ENDPOINT_NAME = "DEFAULT"

SID_ALLOW = "ModaasAllowOnlyAgentgatewayRole"
SID_DENY = "ModaasDenyEveryOtherPrincipal"

# Partition-tolerant (`aws`, `aws-us-gov`, `aws-cn`) to match the pattern
# agentgateway itself uses for a role ARN
# (controller/api/v1alpha1/agentgateway: `^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+$`).
_RUNTIME_ARN_RE = re.compile(
    r"^arn:aws[a-z-]*:bedrock-agentcore:[a-z0-9-]+:\d{12}:runtime/[A-Za-z0-9_.-]+$"
)
_ROLE_ARN_RE = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:role/.+$")
_ENDPOINT_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class InvocationFrontingConfigError(ValueError):
    """A policy could not be rendered from the supplied inputs.

    Raised rather than returning a best-effort document: a malformed ARN or a
    wildcard principal would render a policy that either fails AWS validation
    or silently grants what this module exists to withhold. Refuse loudly.
    """


def _require_runtime_arn(runtime_arn: str) -> str:
    arn = (runtime_arn or "").strip()
    if "/endpoint/" in arn:
        raise InvocationFrontingConfigError(
            f"'{arn}' is an agent ENDPOINT ARN; pass the runtime ARN and let "
            "endpoint_arn_for derive the endpoint."
        )
    if not _RUNTIME_ARN_RE.match(arn):
        raise InvocationFrontingConfigError(
            f"'{runtime_arn}' is not an AgentCore runtime ARN. Expected "
            "arn:aws:bedrock-agentcore:<region>:<account>:runtime/<id>."
        )
    return arn


def _require_role_arn(gateway_role_arn: str) -> str:
    role = (gateway_role_arn or "").strip()
    if not _ROLE_ARN_RE.match(role):
        raise InvocationFrontingConfigError(
            f"'{gateway_role_arn}' is not an IAM role ARN. The agentgateway "
            "principal must be a concrete role ARN — a wildcard or a bare role "
            "name would produce a policy that grants what this module exists "
            "to withhold."
        )
    return role


def _require_policy_resource(resource_arn: str) -> str:
    res = (resource_arn or "").strip()
    if res == "*" or not res.startswith("arn:"):
        raise InvocationFrontingConfigError(
            f"'{resource_arn}' is not a usable policy Resource. AWS rejects "
            '\'"Resource": "*"\' with a validation error and requires the exact '
            "ARN of the resource the policy is attached to."
        )
    return res


def endpoint_arn_for(runtime_arn: str, endpoint_name: str = DEFAULT_ENDPOINT_NAME) -> str:
    """Derive the agent-endpoint ARN whose policy an invocation is also
    evaluated against.

    `InvokeAgentRuntime`'s `qualifier` URI parameter is optional — "If not
    specified, Amazon Bedrock AgentCore uses the default endpoint of the agent
    runtime" (API_InvokeAgentRuntime) — so `DEFAULT` is the endpoint an
    unqualified call resolves to, and therefore the default here.
    """
    arn = _require_runtime_arn(runtime_arn)
    name = (endpoint_name or "").strip()
    if not _ENDPOINT_NAME_RE.match(name):
        raise InvocationFrontingConfigError(
            f"'{endpoint_name}' is not a usable endpoint name."
        )
    return f"{arn}/endpoint/{name}"


def render_gateway_only_policy(resource_arn: str, gateway_role_arn: str) -> dict:
    """One resource-based policy document: allow the gateway role, deny all else.

    `resource_arn` is written verbatim into every statement's `Resource`, which
    is what AWS requires of the document attached to that resource.
    """
    res = _require_policy_resource(resource_arn)
    role = _require_role_arn(gateway_role_arn)
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": SID_ALLOW,
                "Effect": "Allow",
                "Principal": {"AWS": role},
                "Action": INVOCATION_ACTION,
                "Resource": res,
            },
            {
                "Sid": SID_DENY,
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": list(DENIED_INVOCATION_ACTIONS),
                "Resource": res,
                "Condition": {"ArnNotEquals": {"aws:PrincipalArn": role}},
            },
        ],
    }


def render_invocation_fronting_policies(
    runtime_arn: str,
    gateway_role_arn: str,
    endpoint_name: str = DEFAULT_ENDPOINT_NAME,
) -> Dict[str, dict]:
    """Both documents the hierarchical-authorization rule requires.

    Returns ``{"runtime": {"resourceArn": ..., "policy": {...}},
               "endpoint": {"resourceArn": ..., "policy": {...}}}`` — each entry
    carries the ARN it must be attached to, so a caller cannot put the runtime
    document on the endpoint (the mistake that leaves one of the two resources
    without an explicit allow and denies every request).
    """
    rt = _require_runtime_arn(runtime_arn)
    ep = endpoint_arn_for(rt, endpoint_name)
    role = _require_role_arn(gateway_role_arn)
    return {
        "runtime": {"resourceArn": rt, "policy": render_gateway_only_policy(rt, role)},
        "endpoint": {"resourceArn": ep, "policy": render_gateway_only_policy(ep, role)},
    }


__all__ = [
    "INVOCATION_ACTION",
    "DENIED_INVOCATION_ACTIONS",
    "DEFAULT_ENDPOINT_NAME",
    "InvocationFrontingConfigError",
    "endpoint_arn_for",
    "render_gateway_only_policy",
    "render_invocation_fronting_policies",
]
