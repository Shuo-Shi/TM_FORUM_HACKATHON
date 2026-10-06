"""Route `provider: agentCoreGateway` ToolConfig tools through agentgateway.

Lane H / plan task 1.12, requirement R11: a tool call to an AgentCore Gateway
target must cross the MoDaaS perimeter so Cedar authorization (a design note/a design note
via the `ext_authz` hook) and metering apply. Design authority: a design note
(capability interposition — agentgateway with authz is the single enforcement
and metering point; enforce by withholding capability).

Before this module, `agentCoreGateway` was the one governed asset class whose
published perimeter URL had no dataplane behind it: `tool_operator.py`
publishes `status.endpoint = <agw>/mcp/{alias}` for every ToolConfig
(`wire_format_registry` maps `agentCoreGateway -> agentcore-mcp -> /mcp/{alias}`),
but `emit_agentgateway_backend` was gated to `provider == "custom"`, so no
`AgentgatewayBackend` or `HTTPRoute` existed for an `agentCoreGateway` alias
and that URL answered 404. Agents reached the AWS gateway directly instead,
bypassing enforcement.

Why a sibling module rather than a branch inside `agentgateway_mcp_backend`:
that module's target is an in-cluster MCP server addressed from
`spec.custom.baseUrl` with no backend auth and no TLS. This one addresses an
AWS-managed HTTPS endpoint that requires outbound SigV4 with a specific
signing service. The HTTPRoute half IS shared — `build_mcp_httproute` is
imported, not re-derived, so both providers serve one perimeter shape and the
backend object name cannot drift from the route's `backendRefs[].name`.

## Upstream contract (agentgateway), verified by reading source

Pinned commit `34610af2edfc0d775820da76ef91839311a2bb93`; every field below
re-confirmed present in the DEPLOYED tag `v1.4.1`.

* `AgentgatewayBackend.spec.mcp.targets[].static.policies` is a
  `BackendSimple` carrying `{tcp, tls, http, tunnel, auth}`
  (`controller/api/v1alpha1/agentgateway/agentgateway_backend_types.go:724-730`
  -> `agentgateway_policy_types.go:182-203`). `policies` itself has no
  at-most-one-of CEL rule, so `tls` and `auth` may both be set.
* `BackendAuth.aws` is an `AwsAuth{secretRef, assumeRole, serviceName,
  region}` (`agentgateway_policy_types.go:1508-1512`, `:2029-2056`). Its own
  doc comment names `bedrock-agentcore` as an example signing service, so
  this use is anticipated upstream.
* SigV4 is applied on the MCP upstream path. `McpHttpClient::call`
  (`crates/agentgateway/src/mcp/upstream/client.rs:45-82`) forwards the
  target's `backend_policies` into
  `PolicyClient::call_with_explicit_policies`
  (`crates/agentgateway/src/proxy/httpproxy.rs:4206-4219`) ->
  `internal_call_with_policies` (`:4238`) -> `make_backend_call` (`:1999`),
  whose non-LLM branch calls `auth::apply_late_backend_auth`
  (`:2521-2530`) -> `aws::sign_request`. AWS is deliberately deferred to the
  late hook: `apply_backend_auth_kind` treats `BackendAuthKind::Aws(_)` as a
  no-op with the comment "We handle this in 'apply_late_backend_auth' since
  it must come at the end (due to request signing)"
  (`crates/agentgateway/src/http/auth/mod.rs:259-261`).
* `sign_request` signs the real body bytes, not UNSIGNED-PAYLOAD
  (`aws.rs:634` `SignableBody::Bytes`), and normalizes the scheme to https
  for the canonical request (`aws.rs:626`), which is what makes the MCP
  client's hardcoded `http://` URI
  (`crates/agentgateway/src/mcp/upstream/streamablehttp.rs:30-35`) sign
  correctly against an HTTPS endpoint.

Two upstream defaults are silent traps, and both are why `serviceName` and
`region` are written explicitly here rather than left unset:

* `signing_service_name` falls back to `"bedrock"` (`aws.rs:543-553`) —
  wrong service, rejected signature, no local error.
* the region falls back to the gateway pod's ambient AWS region
  (`aws.rs:583-595`) — signs for wherever the pod runs. Same defect class as
  b7ec8dcc on the ModelConfig side; per a design note as amended there, refuse
  rather than serve an invented region.

## AWS contract

* AgentCore Gateway accepts SigV4 inbound: `authorizerType` valid values are
  `CUSTOM_JWT | AWS_IAM | NONE | AUTHENTICATE_ONLY`
  (API_GatewaySummary), and "IAM identity - Authorizes through the
  credentials of the AWS IAM identity trying to access the gateway"
  (devguide `gateway-inbound-auth.html`).
* The invoking principal needs `bedrock-agentcore:InvokeGateway` on
  `arn:aws:bedrock-agentcore:{region}:{account}:gateway/{gatewayId}`
  (same page).
* `PutResourcePolicy` supports Gateway ("This feature is currently available
  only for AgentCore Runtime and Gateway"), and `InvokeGateway` is listed
  under its Gateway actions — so the gateway can be made reachable by the
  perimeter principal ONLY.

`render_gateway_resource_policy` renders that document. It does not apply it:
applying is an AWS write and belongs to a separate reconcile step that
surfaces a `PerimeterEnforced=False` condition until it succeeds. Nothing in
this module performs I/O against AWS.
"""
from typing import Optional

try:
    from shared.agentgateway_mcp_backend import (
        AGW_BACKENDS_PLURAL,
        AGW_GROUP,
        AGW_VERSION,
        HTTPROUTE_GROUP,
        HTTPROUTE_PLURAL,
        HTTPROUTE_VERSION,
        _backend_name,
        _route_name,
        build_mcp_httproute,
    )
    from shared.agentgateway_route import gateway_ref
except ModuleNotFoundError:  # pragma: no cover - repo-tree / snapshot paths
    # Dual-import convention: a shared module must import as `operators.shared.X`
    # from the repo tree AND as `shared.X` from the pod snapshot. A module
    # implementing only one path breaks only in the deployed image — the a design note
    # silent class.
    try:
        from operators.shared.agentgateway_mcp_backend import (  # type: ignore
            AGW_BACKENDS_PLURAL,
            AGW_GROUP,
            AGW_VERSION,
            HTTPROUTE_GROUP,
            HTTPROUTE_PLURAL,
            HTTPROUTE_VERSION,
            _backend_name,
            _route_name,
            build_mcp_httproute,
        )
        from operators.shared.agentgateway_route import gateway_ref  # type: ignore
    except ModuleNotFoundError:
        from agentgateway_mcp_backend import (  # type: ignore
            AGW_BACKENDS_PLURAL,
            AGW_GROUP,
            AGW_VERSION,
            HTTPROUTE_GROUP,
            HTTPROUTE_PLURAL,
            HTTPROUTE_VERSION,
            _backend_name,
            _route_name,
            build_mcp_httproute,
        )
        from agentgateway_route import gateway_ref  # type: ignore

#: SigV4 signing service for AgentCore. Upstream's default is ``bedrock``
#: (aws.rs:543-553), which AgentCore Gateway rejects — never leave unset.
SIGNING_SERVICE = "bedrock-agentcore"

#: MCP endpoint path on an AgentCore Gateway:
#: ``https://<id>.gateway.bedrock-agentcore.<region>.amazonaws.com/mcp``.
GATEWAY_MCP_PATH = "/mcp"

#: AgentCore Gateway serves HTTPS only.
GATEWAY_PORT = 443

#: The single IAM action the perimeter principal needs
#: (devguide gateway-inbound-auth.html, IAM-based inbound authorization).
INVOKE_ACTION = "bedrock-agentcore:InvokeGateway"


class PerimeterConfigError(Exception):
    """The operator's own configuration cannot produce a correct perimeter.

    Distinct from a CR-shape gap (which returns ``None`` so the caller can
    surface ``ProviderNotRoutable``): this is raised when the deployment does
    not declare something that must never be guessed — the signing region,
    the AWS account, or the perimeter's IAM principal. Guessing any of them
    produces a signature or a policy that is wrong in a way no local check
    would catch.
    """


def agentcore_gateway_host(gateway_identifier: str, region: str) -> str:
    """AgentCore Gateway MCP hostname for ``gateway_identifier`` in ``region``.

    Raises ``PerimeterConfigError`` for an empty identifier or region rather
    than rendering a host that resolves to the wrong place (or to nothing).
    """
    if not (gateway_identifier or "").strip():
        raise PerimeterConfigError(
            "AgentCore Gateway identifier is required to address the MCP endpoint; "
            "set spec.agentCoreGateway.gatewayIdentifier or wait for "
            "status.gatewayIdentifier to be published by managed-mode provisioning."
        )
    if not (region or "").strip():
        raise PerimeterConfigError(
            "AgentCore Gateway signing region is required and must not be defaulted "
            "(upstream would otherwise sign with the gateway pod's ambient region — "
            "agentgateway aws.rs:583-595). Set AWS_REGION on the operator."
        )
    return f"{gateway_identifier}.gateway.{SIGNING_SERVICE}.{region}.amazonaws.com"


def gateway_arn(gateway_identifier: str, region: str, account_id: str) -> str:
    """ARN of the AgentCore Gateway, for the resource policy's ``Resource``."""
    if not (account_id or "").strip():
        raise PerimeterConfigError(
            "AWS account id is required to build the AgentCore Gateway ARN; "
            "set MODAAS_AWS_ACCOUNT_ID on the operator."
        )
    # agentcore_gateway_host validates identifier + region with the same
    # refuse-rather-than-invent contract; call it for that validation.
    agentcore_gateway_host(gateway_identifier, region)
    return f"arn:aws:{SIGNING_SERVICE}:{region}:{account_id}:gateway/{gateway_identifier}"


def resolve_gateway_identifier(spec: dict, status: Optional[dict] = None) -> str:
    """Declaration first, observation second (a design note).

    Adopt mode declares the gateway in ``spec.agentCoreGateway``; managed
    mode creates it, so the identifier only ever appears in status. Matches
    the precedence `tool_operator.py:123-124` already uses.
    """
    declared = ((spec.get("agentCoreGateway") or {}).get("gatewayIdentifier") or "").strip()
    if declared:
        return declared
    return ((status or {}).get("gatewayIdentifier") or "").strip()


def build_agentcore_mcp_backend(
    alias: str,
    spec: dict,
    status: Optional[dict] = None,
    region: Optional[str] = None,
) -> Optional[dict]:
    """Build the ``AgentgatewayBackend`` that proxies ``/mcp/{alias}`` to the
    AWS-managed AgentCore Gateway, signing outbound with SigV4.

    Returns ``None`` when the CR names no gateway (a CR-shape gap; the caller
    surfaces ``ProviderNotRoutable``). Raises ``PerimeterConfigError`` when
    ``region`` is absent (a deployment misconfig, a different condition
    reason) — the two causes are deliberately not collapsed.
    """
    gateway_identifier = resolve_gateway_identifier(spec, status)
    if not gateway_identifier:
        return None
    host = agentcore_gateway_host(gateway_identifier, region or "")

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
                    # `static.host`, not `backendRef`: v1.4.1 CEL rejects
                    # "mcp target policies may not be used with backendRef",
                    # and the policies are the whole point here.
                    "static": {
                        "host": host,
                        "port": GATEWAY_PORT,
                        "protocol": "StreamableHTTP",
                        "path": GATEWAY_MCP_PATH,
                        "policies": {
                            # Empty object = originate TLS with the system
                            # trust store, SNI inferred from the destination
                            # (BackendSimple.TLS doc comment). Required
                            # because the MCP client builds an http:// URI.
                            "tls": {},
                            "auth": {
                                "aws": {
                                    "serviceName": SIGNING_SERVICE,
                                    "region": region,
                                },
                            },
                        },
                    },
                }],
            },
        },
    }


def build_agentcore_mcp_httproute(alias: str) -> dict:
    """The perimeter route. Reused verbatim from the `custom`-provider path so
    both ToolConfig providers serve one shape and the backend object name
    cannot drift from ``backendRefs[].name``."""
    return build_mcp_httproute(alias)


def emit_agentcore_mcp_backend(
    k8s_api,
    alias: str,
    spec: dict,
    status: Optional[dict] = None,
    region: Optional[str] = None,
    apply_fn=None,
) -> str:
    """Create or update the ``AgentgatewayBackend`` + ``HTTPRoute`` pair.

    Returns ``'skipped'`` (CR names no gateway) or ``'applied'``; propagates
    whatever ``apply_fn`` raises, and ``PerimeterConfigError`` when the
    signing region is absent.
    """
    backend_body = build_agentcore_mcp_backend(alias, spec, status=status, region=region)
    if backend_body is None:
        return "skipped"
    route_body = build_agentcore_mcp_httproute(alias)

    ns = backend_body["metadata"]["namespace"]
    if apply_fn is None:
        try:
            from shared.istio_vs_authz import _apply_with_drift_check as apply_fn  # type: ignore
        except ModuleNotFoundError:  # pragma: no cover - repo-tree import path
            from operators.shared.istio_vs_authz import _apply_with_drift_check as apply_fn  # type: ignore
    apply_fn(k8s_api, AGW_GROUP, AGW_VERSION, ns, AGW_BACKENDS_PLURAL, backend_body)
    apply_fn(k8s_api, HTTPROUTE_GROUP, HTTPROUTE_VERSION, ns, HTTPROUTE_PLURAL, route_body)
    return "applied"


def delete_agentcore_mcp_backend(k8s_api, alias: str) -> bool:
    """Withdraw both objects so a paused/retired ToolConfig stops serving.

    Absent is success; any other API error propagates. Route first so the
    perimeter stops accepting traffic before its backend disappears.
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


def render_gateway_resource_policy(
    *,
    gateway_identifier: str,
    region: str,
    account_id: str,
    principal_arn: str,
) -> dict:
    """Render the AgentCore Gateway resource policy that makes the gateway
    reachable by the perimeter principal ONLY.

    The principal is the agentgateway dataplane's IRSA role — the identity
    that signs the outbound request — never the calling agent's. An agent
    that tries to reach the AWS gateway directly then fails at AWS, so the
    perimeter cannot be walked around rather than merely being the
    recommended path (a design note: enforce by withholding capability).

    This function only renders. Applying it is ``PutResourcePolicy``, an AWS
    write that belongs to a separate reconcile step reporting
    ``PerimeterEnforced``.
    """
    principal = (principal_arn or "").strip()
    if not principal:
        raise PerimeterConfigError(
            "Perimeter principal ARN is required to render the AgentCore Gateway "
            "resource policy; set MODAAS_AGW_SIGNING_ROLE_ARN to the agentgateway "
            "dataplane's IRSA role ARN."
        )
    if not principal.startswith("arn:") or (
        ":iam::" not in principal and ":sts::" not in principal
    ):
        raise PerimeterConfigError(
            f"Perimeter principal must be an IAM/STS role ARN, got {principal!r}. "
            "A wildcard or account-root principal would leave the AWS gateway "
            "reachable around the perimeter."
        )
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "ModaasPerimeterOnlyInvoke",
            "Effect": "Allow",
            "Principal": {"AWS": [principal]},
            "Action": [INVOKE_ACTION],
            "Resource": [gateway_arn(gateway_identifier, region, account_id)],
        }],
    }


def perimeter_enforcement_state(
    *,
    gateway_identifier: str,
    region: str,
    account_id: str,
    principal_arn: str,
) -> tuple:
    """``(status, reason, message)`` for the ``PerimeterEnforced`` condition.

    Never returns ``"True"``. Nothing in this module calls
    ``PutResourcePolicy``, so claiming enforcement here would be exactly the
    "declared but not enforced" defect ``loop/METHOD-positive-controls.md``
    names as this project's dominant class. The best honest answer is
    ``ResourcePolicyPending`` with the rendered document in the message, so an
    operator can see what WOULD be applied and apply it out of band.
    """
    if not (gateway_identifier or "").strip():
        return ("False", "ProviderNotRoutable",
                "No AgentCore Gateway identifier in spec or status; nothing to lock down.")
    if not (region or "").strip():
        return ("False", "PerimeterMisconfigured",
                "AWS_REGION is not set on the operator; refusing to build a gateway ARN "
                "for a guessed region.")
    if not (principal_arn or "").strip():
        return ("False", "SigningPrincipalUnknown",
                "MODAAS_AGW_SIGNING_ROLE_ARN is not set; the agentgateway dataplane's "
                "IRSA role ARN is required to scope the gateway to the perimeter.")
    if not (account_id or "").strip():
        return ("False", "AccountIdUnknown",
                "MODAAS_AWS_ACCOUNT_ID is not set; required to build the AgentCore "
                "Gateway ARN for the resource policy.")
    try:
        policy = render_gateway_resource_policy(
            gateway_identifier=gateway_identifier, region=region,
            account_id=account_id, principal_arn=principal_arn)
    except PerimeterConfigError as e:
        return ("False", "SigningPrincipalInvalid", str(e)[:256])
    arn = policy["Statement"][0]["Resource"][0]
    return ("False", "ResourcePolicyPending",
            f"Rendered resource policy allowing only {principal_arn} to "
            f"{INVOKE_ACTION} on {arn}; not applied (PutResourcePolicy is an AWS "
            f"write owned by a separate reconcile step).")


__all__ = [
    "GATEWAY_MCP_PATH",
    "GATEWAY_PORT",
    "INVOKE_ACTION",
    "PerimeterConfigError",
    "SIGNING_SERVICE",
    "agentcore_gateway_host",
    "build_agentcore_mcp_backend",
    "build_agentcore_mcp_httproute",
    "delete_agentcore_mcp_backend",
    "emit_agentcore_mcp_backend",
    "gateway_arn",
    "perimeter_enforcement_state",
    "render_gateway_resource_policy",
    "resolve_gateway_identifier",
]
