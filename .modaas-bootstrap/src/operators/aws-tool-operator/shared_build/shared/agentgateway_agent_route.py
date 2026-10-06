"""a design note point 3 — front an AgentConfig's invocations with agentgateway.

Emits the two Kubernetes objects that put agentgateway in front of an AgentCore
Runtime agent, and publishes the resulting perimeter URL into the CR's status.
Companion to `shared/agentcore_resource_policy.py`, which withholds the
capability on the AWS side; a route without that policy is ergonomics, not
enforcement (a design note point 5).

Pure emission — no boto3, no Rust changes, the same class of work
`agentgateway_route.py` (ModelConfig) and `agentgateway_mcp_backend.py`
(ToolConfig) already do. Every upstream field used here exists in agentgateway
v1.4.1, the deployed chart version per AGENTS.md.

Two objects, not one
--------------------
`AgentgatewayBackend` has no `parentRefs` field, so it cannot attach to a
listener by itself; a companion `HTTPRoute` is what receives traffic. Same
structure `agentgateway_mcp_backend.py` established for MCP targets.

    AgentgatewayBackend.spec.aws.agentCore.{agentRuntimeArn, qualifier}
      referenced by
    HTTPRoute.spec.rules[].backendRefs[] (group agentgateway.dev,
                                          kind AgentgatewayBackend)

Why the native `aws.agentCore` backend rather than a `static` host
-----------------------------------------------------------------
`crates/agentgateway/src/aws.rs` at the pinned upstream:

  * `AwsService::AgentCore(_) => "bedrock-agentcore"` — the SigV4 signing
    service name is a compile-time constant for this backend, so the answer to
    "can upstream agentgateway sign SigV4 to bedrock-agentcore
    InvokeAgentRuntime?" is yes, by configuration alone.
  * `region()`, `get_host()`, `get_path()` delegate to `AgentCoreConfig`, whose
    own test asserts host `bedrock-agentcore.us-east-1.amazonaws.com` (region
    taken from the ARN) and a path that `starts_with("/runtimes/")` and
    `ends_with("/invocations")`.

So the backend derives host, region, path and signing service from the runtime
ARN. A `static` backend would need all four supplied by hand plus a URLRewrite
filter — more surface, more drift, and it would lose the typed
`agentRuntimeArn` field.

Why the `http` listener
-----------------------
`deploy/agentgateway/gateway-modaas-agw.yaml` gives `llm` (:8081) and `llm-tls`
(:8443) an `allowedRoutes.kinds` list containing ONLY
`agentgateway.dev/AgentgatewayModel`. Gateway API will not attach an HTTPRoute
to a listener that does not list its kind — `attachedRoutes` stays 0 and the
path answers 404 (the defect `agentgateway_route.py`'s own docstring records
for AgentgatewayModel, in the opposite direction). `http` (:8080) sets no
`kinds` restriction and so accepts HTTPRoute by Gateway API's
default-kind-by-protocol semantics, it is the listener the existing
`/mcp/{alias}` tool routes already attach to, and — decisively — the a design note
identity hook `deploy/agentgateway/agentgatewaypolicy-authz-hook.yaml` targets
`sectionName: llm` AND `sectionName: http`, so a route on `http` inherits
identity + Cedar authorization with `failureMode: FailClosed` without any new
policy object.

One caveat the hook forces, and it is NOT optional: the doorman
(`authz-gateway/app.py`) routes are `/authz`, `/authz/{rest}`, `/mcp/{rest}`
and `/v1/{rest}`. A check arriving at `/agents/...` would 404, and the hook
turns that 404 into the CALLER's response. So the doorman needs the prefix
registered and the alias extracted from it; that pure function ships in
`authz-gateway/agent_invocation_path.py` in this lane and its two-line wiring is
listed in LANE_REPORT.md §5.
"""
import logging
from typing import Optional, Tuple

try:
    from shared.agentgateway_route import gateway_ref
    from shared.agentcore_resource_policy import (
        DEFAULT_ENDPOINT_NAME,
        InvocationFrontingConfigError,
        _require_role_arn,
        _require_runtime_arn,
    )
    from shared.perimeter_url import compute_and_publish_perimeter_url
except ModuleNotFoundError:  # pragma: no cover - repo-root import path
    from operators.shared.agentgateway_route import gateway_ref  # type: ignore
    from operators.shared.agentcore_resource_policy import (  # type: ignore
        DEFAULT_ENDPOINT_NAME,
        InvocationFrontingConfigError,
        _require_role_arn,
        _require_runtime_arn,
    )
    from operators.shared.perimeter_url import (  # type: ignore
        compute_and_publish_perimeter_url,
    )

logger = logging.getLogger("shared.agentgateway_agent_route")

AGW_GROUP = "agentgateway.dev"
AGW_VERSION = "v1alpha1"
AGW_BACKENDS_PLURAL = "agentgatewaybackends"

HTTPROUTE_GROUP = "gateway.networking.k8s.io"
HTTPROUTE_VERSION = "v1"
HTTPROUTE_PLURAL = "httproutes"

# Hardcoded, not read from MODAAS_AGW_LISTENER: that variable defaults to `llm`,
# which cannot accept an HTTPRoute (see module docstring). Matching
# `agentgateway_mcp_backend.build_mcp_httproute`, which hardcodes the same value
# for the same reason.
INVOCATION_LISTENER_SECTION = "http"

# The dialect and path live in shared/wire_format_registry.py; re-exported here
# so callers have one import. AGENT_INVOCATION_PATH_TEMPLATE is READ from the
# registry rather than restated, so the two cannot drift.
AGENT_INVOCATION_WIRE_FORMAT = "agentcore-invocations"

try:
    from shared.wire_format_registry import gateway_path_for as _gateway_path_for
except ModuleNotFoundError:  # pragma: no cover
    from operators.shared.wire_format_registry import (  # type: ignore
        gateway_path_for as _gateway_path_for,
    )

AGENT_INVOCATION_PATH_TEMPLATE = _gateway_path_for(AGENT_INVOCATION_WIRE_FORMAT)

# Every host shape that is the RAW AgentCore surface rather than the MoDaaS
# perimeter: the control/data plane host `bedrock-agentcore.<region>.amazonaws.com`
# and the AgentCore Gateway host `<id>.gateway.bedrock-agentcore.<region>.amazonaws.com`
# (both spelled out in docs/.../runtime-oauth.html). Substring matching is
# sufficient and deliberate — any URL carrying this host bypasses MoDaaS.
_RAW_AGENTCORE_HOST_MARKER = "bedrock-agentcore."


def _backend_name(alias: str) -> str:
    return f"{alias}-agentcore-backend"


def _route_name(alias: str) -> str:
    return f"{alias}-invocation-route"


def invocation_path_for(alias: str) -> str:
    """The stable perimeter path for this alias's invocations."""
    return AGENT_INVOCATION_PATH_TEMPLATE.format(alias=alias)


def is_raw_agentcore_url(url: str) -> bool:
    """True when `url` points at AgentCore directly rather than at the gateway.

    Coherence Rule 13: `status.endpoint` is the governance perimeter URL, never
    the upstream. A raw AgentCore URL in that field tells every status-driven
    discovery client to go around the perimeter.
    """
    return _RAW_AGENTCORE_HOST_MARKER in (url or "")


def build_agentcore_backend(
    alias: str,
    runtime_arn: str,
    qualifier: Optional[str] = None,
    assume_role_arn: Optional[str] = None,
) -> dict:
    """Build the AgentgatewayBackend that proxies to this agent's runtime.

    Args:
        alias: AgentConfig alias — names the object and the perimeter path.
        runtime_arn: `status.agentRuntimeArn`. Refused unless it is a real
            AgentCore runtime ARN: `agentRuntimeArn` is `+required` upstream, so
            an empty or malformed value fails at apply time with a CEL error
            that is far from its cause.
        qualifier: AgentCore endpoint name/version. Omitted when None, which
            AgentCore resolves to the DEFAULT endpoint.
        assume_role_arn: when supplied, emit
            `spec.policies.auth.aws.assumeRole.roleArn` so the gateway signs as
            that role instead of its ambient IRSA identity. The resource policy
            must then name the SAME role — use
            `gateway_principal_for_backend` to get it from one place.
    """
    arn = _require_runtime_arn(runtime_arn)
    ns, _, _ = gateway_ref()

    agent_core: dict = {"agentRuntimeArn": arn}
    if qualifier:
        agent_core["qualifier"] = qualifier

    body: dict = {
        "apiVersion": f"{AGW_GROUP}/{AGW_VERSION}",
        "kind": "AgentgatewayBackend",
        "metadata": {
            "name": _backend_name(alias),
            "namespace": ns,
            "labels": {
                "modaas.io/managed-by": "aws-agent-operator",
                "modaas.io/alias": alias,
            },
        },
        # ExactlyOneOf=ai;static;dynamicForwardProxy;mcp;aws;a2a — `aws` only.
        "spec": {"aws": {"agentCore": agent_core}},
    }

    if assume_role_arn:
        # AwsAssumeRole.roleArn is `+required` with pattern
        # ^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+$ — validate before emitting so
        # the refusal names the field rather than surfacing as a CEL rejection.
        role = _require_role_arn(assume_role_arn)
        body["spec"]["policies"] = {"auth": {"aws": {"assumeRole": {"roleArn": role}}}}

    return body


def endpoint_name_for_backend(backend_body: dict) -> str:
    """The AgentCore endpoint this backend's traffic actually reaches.

    Exists so the endpoint RESOURCE POLICY and the ROUTE cannot disagree: a
    policy attached to `.../endpoint/DEFAULT` while the backend carries
    `qualifier: v3` protects an endpoint nobody calls, and the one that is
    called has no explicit allow — which, per the hierarchical-authorization
    rule, denies every request.
    """
    ac = ((backend_body.get("spec") or {}).get("aws") or {}).get("agentCore") or {}
    return ac.get("qualifier") or DEFAULT_ENDPOINT_NAME


def gateway_principal_for_backend(backend_body: dict, ambient_role_arn: str) -> str:
    """The IAM principal the gateway will actually invoke the runtime as.

    Single source for the resource policy's `Principal` and the deny statement's
    `aws:PrincipalArn` condition. Without this, a backend configured with
    `assumeRole` and a policy naming the IRSA role produce a pair that looks
    correct in review and denies 100% of traffic in production.
    """
    auth = (
        ((backend_body.get("spec") or {}).get("policies") or {}).get("auth") or {}
    ).get("aws") or {}
    assumed = (auth.get("assumeRole") or {}).get("roleArn")
    return _require_role_arn(assumed or ambient_role_arn)


def build_agent_invocation_httproute(alias: str) -> dict:
    """Build the HTTPRoute attaching the `http` listener to this alias's backend.

    No URLRewrite filter: agentgateway's AgentCore backend builds the upstream
    path from the ARN itself (`aws.rs` `get_path()`), so rewriting here would
    double-rewrite. PathPrefix (not Exact) mirrors the `/mcp/{alias}` convention
    and tolerates the trailing segments an SDK may append.
    """
    ns, gw, _ = gateway_ref()
    return {
        "apiVersion": f"{HTTPROUTE_GROUP}/{HTTPROUTE_VERSION}",
        "kind": "HTTPRoute",
        "metadata": {
            "name": _route_name(alias),
            "namespace": ns,
            "labels": {
                "modaas.io/managed-by": "aws-agent-operator",
                "modaas.io/alias": alias,
            },
        },
        "spec": {
            "parentRefs": [{
                "name": gw,
                "namespace": ns,
                "sectionName": INVOCATION_LISTENER_SECTION,
            }],
            "rules": [{
                "matches": [{
                    "path": {"type": "PathPrefix", "value": invocation_path_for(alias)},
                }],
                "backendRefs": [{
                    "name": _backend_name(alias),
                    "group": AGW_GROUP,
                    "kind": "AgentgatewayBackend",
                }],
            }],
        },
    }


def emit_agent_invocation_route(
    k8s_api,
    alias: str,
    runtime_arn: str,
    qualifier: Optional[str] = None,
    assume_role_arn: Optional[str] = None,
    apply_fn=None,
) -> str:
    """Create or update the AgentgatewayBackend + HTTPRoute pair.

    Returns ``'skipped'`` when no runtime ARN is known yet (an AgentConfig
    mid-provision; the next reconcile emits), or ``'applied'``. A runtime ARN
    that is present but malformed RAISES rather than skipping — silently not
    fronting a governed agent is the outcome a design note exists to prevent.
    """
    if not (runtime_arn or "").strip():
        logger.info(
            "invocation fronting skipped for alias=%s: no runtime ARN yet", alias)
        return "skipped"

    backend_body = build_agentcore_backend(
        alias, runtime_arn, qualifier=qualifier, assume_role_arn=assume_role_arn)
    route_body = build_agent_invocation_httproute(alias)
    ns = backend_body["metadata"]["namespace"]

    if apply_fn is None:
        try:
            from shared.istio_vs_authz import _apply_with_drift_check as apply_fn  # type: ignore
        except ModuleNotFoundError:  # pragma: no cover
            from operators.shared.istio_vs_authz import _apply_with_drift_check as apply_fn  # type: ignore

    apply_fn(k8s_api, AGW_GROUP, AGW_VERSION, ns, AGW_BACKENDS_PLURAL, backend_body)
    apply_fn(k8s_api, HTTPROUTE_GROUP, HTTPROUTE_VERSION, ns, HTTPROUTE_PLURAL, route_body)
    return "applied"


def delete_agent_invocation_route(k8s_api, alias: str) -> bool:
    """Withdraw the route so a deleted/paused AgentConfig stops being served.

    Route first, then Backend — matching `agentgateway_mcp_backend`'s teardown
    order. Absent is success for either object.
    """
    from kubernetes.client.exceptions import ApiException
    ns, _, _ = gateway_ref()
    for group, version, plural, name in (
        (HTTPROUTE_GROUP, HTTPROUTE_VERSION, HTTPROUTE_PLURAL, _route_name(alias)),
        (AGW_GROUP, AGW_VERSION, AGW_BACKENDS_PLURAL, _backend_name(alias)),
    ):
        try:
            k8s_api.delete_namespaced_custom_object(
                group=group, version=version, namespace=ns, plural=plural, name=name)
        except ApiException as e:
            if e.status != 404:
                raise
    return True


def publish_invocation_perimeter_url(
    *,
    alias: str,
    status_patch,
    k8s_api=None,
    fallback_url: Optional[str] = None,
) -> Tuple[str, str]:
    """Publish the fronted-invocation perimeter URL into status.

    Delegates to `perimeter_url.compute_and_publish_perimeter_url` — Coherence
    Rule 22's single writer — with this dialect's wire format, then refuses if
    the resolved URL is the raw AgentCore host. The refusal writes nothing:
    a half-written status block advertising a bypass is worse than an absent
    endpoint, which the CRD's own CEL surfaces.

    Does NOT touch `status.upstreamEndpoint`; per Coherence Rule 13 that field
    is the caller's (the raw runtime ARN / invoke URL, for diagnostics only).
    """
    probe: dict = {}
    scope, url = compute_and_publish_perimeter_url(
        alias=alias,
        wire_format=AGENT_INVOCATION_WIRE_FORMAT,
        status_patch=probe,
        fallback_url=fallback_url,
        k8s_api=k8s_api,
    )
    if is_raw_agentcore_url(url):
        raise InvocationFrontingConfigError(
            f"refusing to publish '{url}' as the perimeter URL for alias "
            f"'{alias}': it names the raw AgentCore host, so a client honouring "
            "status.endpoint would bypass agentgateway, the Cedar PDP and the "
            "guardrail (Coherence Rule 13). Check MODAAS_PUBLIC_GATEWAY_HOST / "
            "MODAAS_VPC_GATEWAY_HOST."
        )
    for key, value in probe.items():
        status_patch[key] = value
    return scope, url


__all__ = [
    "AGENT_INVOCATION_WIRE_FORMAT",
    "AGENT_INVOCATION_PATH_TEMPLATE",
    "AGW_GROUP",
    "AGW_VERSION",
    "AGW_BACKENDS_PLURAL",
    "HTTPROUTE_GROUP",
    "HTTPROUTE_VERSION",
    "HTTPROUTE_PLURAL",
    "INVOCATION_LISTENER_SECTION",
    "build_agentcore_backend",
    "build_agent_invocation_httproute",
    "endpoint_name_for_backend",
    "gateway_principal_for_backend",
    "invocation_path_for",
    "is_raw_agentcore_url",
    "emit_agent_invocation_route",
    "delete_agent_invocation_route",
    "publish_invocation_perimeter_url",
]
