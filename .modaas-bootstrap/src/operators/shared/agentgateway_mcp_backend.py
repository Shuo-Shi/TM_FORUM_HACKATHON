"""Program agentgateway's native MCP proxying for a `custom`-provider ToolConfig.

U12 (tool-server-fixture): the third of `unit-of-work.md`'s four named blockers
(the fourth, an unclaimed `custom` ToolConfig never reconciling, was already
resolved by U7). agentgateway already ships a full, pre-built MCP proxying
stack (routing, transport, auth, RBAC — `crates/agentgateway/src/mcp/`,
verified at the pinned commit `34610af2edfc0d775820da76ef91839311a2bb93`); this
module is pure Kubernetes-object emission, zero Rust changes, the same class
of work `agentgateway_route.py` already does for ModelConfig.

Two objects, not one — `AgentgatewayBackend` has no `parentRefs` field
(unlike `AgentgatewayModel`, which attaches directly to a Gateway listener),
so it needs a companion `HTTPRoute` to actually receive traffic. Verified
against agentgateway's own end-to-end test fixture
(`controller/test/e2e/testdata/mcp/static.yaml`):

  AgentgatewayBackend.spec.mcp.targets[].static.{host,port,protocol}
    referenced by
  HTTPRoute.spec.rules[].backendRefs[] (group: agentgateway.dev, kind: AgentgatewayBackend)

A new sibling module, not an extension of `agentgateway_route.py` — that
module's own docstring and naming (`AGW_MODELS_PLURAL`, `build_agentgateway_model`)
are ModelConfig-specific throughout; a Backend+Route pair for ToolConfig is a
structurally different CR pair, not a variant of the same one.
"""
from typing import Optional
from urllib.parse import urlsplit

try:
    from shared.agentgateway_route import gateway_ref
except ModuleNotFoundError:  # pragma: no cover - deployed snapshot path
    from agentgateway_route import gateway_ref

AGW_GROUP = "agentgateway.dev"
AGW_VERSION = "v1alpha1"
AGW_BACKENDS_PLURAL = "agentgatewaybackends"

HTTPROUTE_GROUP = "gateway.networking.k8s.io"
HTTPROUTE_VERSION = "v1"
HTTPROUTE_PLURAL = "httproutes"

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _backend_name(alias: str) -> str:
    return f"{alias}-mcp-backend"


def _route_name(alias: str) -> str:
    return f"{alias}-mcp-route"


def _parse_base_url(base_url: str) -> Optional[tuple]:
    """`spec.custom.baseUrl` -> (host, port, protocol) for
    `AgentgatewayBackend.spec.mcp.targets[].static`. Returns None for an
    unparseable URL (caller reports the skip on a condition, matching
    `agentgateway_route.py`'s own `build_agentgateway_model` convention of
    returning None rather than raising for an unroutable CR).
    """
    parsed = urlsplit(base_url)
    if not parsed.hostname:
        return None
    port = parsed.port or _DEFAULT_PORTS.get(parsed.scheme, 80)
    # StreamableHTTP matches this fixture's own FastMCP server (nfr-design
    # SD-1); a future tool server using SSE would need this parameterized.
    return (parsed.hostname, port, "StreamableHTTP")


def build_agentgateway_backend(alias: str, spec: dict) -> Optional[dict]:
    """Build the AgentgatewayBackend body, or None when `spec.custom.baseUrl`
    is absent/unparseable. Only `provider: custom` ToolConfigs reach this —
    `agentCoreGateway` is routed by AWS's own managed Gateway, not this path.
    """
    base_url = ((spec.get("custom") or {}).get("baseUrl") or "").strip()
    if not base_url:
        return None
    parsed = _parse_base_url(base_url)
    if parsed is None:
        return None
    host, port, protocol = parsed

    ns, _, _ = gateway_ref()
    return {
        "apiVersion": f"{AGW_GROUP}/{AGW_VERSION}",
        "kind": "AgentgatewayBackend",
        "metadata": {
            "name": _backend_name(alias),
            "namespace": ns,
            "labels": {
                "modaas.io/managed-by": "aws-tool-operator",
                "modaas.io/alias": alias,
            },
        },
        "spec": {
            "mcp": {
                "targets": [{
                    "name": alias,
                    "static": {"host": host, "port": port, "protocol": protocol},
                }],
            },
        },
    }


def build_mcp_httproute(alias: str) -> dict:
    """Build the HTTPRoute attaching the existing `http` listener
    (`gateway-modaas-agw.yaml` — no `allowedRoutes.kinds` restriction there,
    so it already accepts HTTPRoute per Gateway API's default-kind-by-
    protocol semantics) to this alias's AgentgatewayBackend, matching every
    other governed asset's `/mcp/{alias}` perimeter shape.
    """
    ns, gw, _ = gateway_ref()
    return {
        "apiVersion": f"{HTTPROUTE_GROUP}/{HTTPROUTE_VERSION}",
        "kind": "HTTPRoute",
        "metadata": {
            "name": _route_name(alias),
            "namespace": ns,
            "labels": {
                "modaas.io/managed-by": "aws-tool-operator",
                "modaas.io/alias": alias,
            },
        },
        "spec": {
            "parentRefs": [{
                "name": gw,
                "namespace": ns,
                "sectionName": "http",
            }],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": f"/mcp/{alias}"}}],
                "backendRefs": [{
                    "name": _backend_name(alias),
                    "group": AGW_GROUP,
                    "kind": "AgentgatewayBackend",
                }],
            }],
        },
    }


def emit_agentgateway_backend(k8s_api, alias: str, spec: dict, apply_fn=None) -> str:
    """Create or update the AgentgatewayBackend + HTTPRoute pair.

    Returns 'skipped' (no baseUrl / unroutable), 'applied' (both objects
    written), or propagates whatever apply_fn raises.
    """
    backend_body = build_agentgateway_backend(alias, spec)
    if backend_body is None:
        return "skipped"
    route_body = build_mcp_httproute(alias)

    ns = backend_body["metadata"]["namespace"]
    if apply_fn is None:
        try:
            from shared.istio_vs_authz import _apply_with_drift_check as apply_fn  # type: ignore
        except ModuleNotFoundError:
            from operators.shared.istio_vs_authz import _apply_with_drift_check as apply_fn  # type: ignore
    apply_fn(k8s_api, AGW_GROUP, AGW_VERSION, ns, AGW_BACKENDS_PLURAL, backend_body)
    apply_fn(k8s_api, HTTPROUTE_GROUP, HTTPROUTE_VERSION, ns, HTTPROUTE_PLURAL, route_body)
    return "applied"


def delete_agentgateway_backend(k8s_api, alias: str) -> bool:
    """Remove both objects so a deleted/paused ToolConfig stops being
    served. Absent is success for either object, matching
    `agentgateway_route.py`'s own `delete_agentgateway_model` convention.
    """
    from kubernetes.client.exceptions import ApiException
    ns, _, _ = gateway_ref()
    # Route first, then Backend — deleting the Backend while the Route still
    # references it is harmless either order, but matching the create order
    # (Backend, Route) reversed is the conventional teardown sequence.
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
