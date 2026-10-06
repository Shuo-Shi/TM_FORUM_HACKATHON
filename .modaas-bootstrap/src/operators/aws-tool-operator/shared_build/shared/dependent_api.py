"""a design note — DependentAPI generation (Bucket 2 — pre-DTW).

Two patterns:
1. ToolConfig → TMF API wrapping (ensure_dependent_api): creates DependentAPI
   for a ToolConfig that wraps a TMF API spec URL.
2. Per-asset per-wire-format (ensure_dependent_api_for_wire_format): each
   operator emits one DependentAPI per (asset, wire_format). Canvas's
   canvas-depapi-op resolves DependentAPI to a VirtualService URL.
   Operator reads status.implementation.url and writes to asset
   status.globalResourceEndpoint (W1.C field).

This is the layered governance story: Canvas wires the network path,
MoDaaS overlays the AI contract.

endpoint-publication-fix (U3, BR-4): ``compute_all_endpoints`` and
``fallback_perimeter_url`` used to read the module-private
``WIRE_FORMAT_GATEWAY_PATH`` dict via ``.get(wire_format, "/v1/chat/completions")``
— a silent default that quietly resolved an unrecognized wire format to the
OpenAI-compat path instead of surfacing an error (the exact defect Addendum 1
named for Bedrock's path, reached through a second, independent caller).
Both functions now call ``wire_format_registry.gateway_path_for``, which
raises ``UnknownWireFormatError`` instead of defaulting. ``WIRE_FORMAT_GATEWAY_PATH``
itself is left in place, unread by either function, per U1's own decision not
to delete the old module-level dicts outright until every reader is migrated.
"""
import logging
from typing import Dict, List, Optional

try:  # pragma: no cover — import path varies by deployment shape
    from shared.wire_format_registry import gateway_path_for
except ModuleNotFoundError:  # pragma: no cover
    from operators.shared.wire_format_registry import gateway_path_for  # type: ignore

logger = logging.getLogger("shared.dependent_api")

DEPENDENT_API_GROUP = "oda.tmforum.org"
DEPENDENT_API_VERSION = "v1"
DEPENDENT_API_PLURAL = "dependentapis"
DEPENDENT_API_API_VERSION = f"{DEPENDENT_API_GROUP}/{DEPENDENT_API_VERSION}"

# ── Provider → wire format mapping ──────────────────────────────────────── #
# Each provider may expose multiple wire formats (e.g., bedrock-runtime for
# model invocation, bedrock-converse for the Converse API).
PROVIDER_WIRE_FORMATS: Dict[str, List[str]] = {
    "aws-bedrock": ["bedrock-runtime"],
    "aws-sagemaker": ["sagemaker-runtime"],
    "aws-agentcore": ["agentcore-runtime"],
    "awsAgentCore": ["agentcore-runtime"],
    "agentCoreGateway": ["agentcore-mcp"],
    "azure-openai": ["openai-compat"],
    "google-vertex": ["vertex-ai"],
    "nvidia-nim": ["openai-compat"],
    "ollama": ["openai-compat"],
    "custom": ["openai-compat"],
}


def wire_formats_for_provider(provider: str) -> List[str]:
    """Return the list of wire formats a given provider exposes."""
    return PROVIDER_WIRE_FORMATS.get(provider, ["openai-compat"])


def get_resolved_url(dep_api: Optional[dict]) -> Optional[str]:
    """Extract resolved URL from DependentAPI status.implementation.url.

    Canvas canvas-depapi-op writes this field once it provisions the
    VirtualService / network path.
    """
    if dep_api is None:
        return None
    status = dep_api.get("status") or {}
    impl = status.get("implementation") or {}
    return impl.get("url") or None


# ── Mesh-internal perimeter URL fallback ────────────────────────────────── #
# Per CLAUDE.md coherence rule 13: status.endpoint = governance perimeter URL.
# When Canvas DependentAPI hasn't resolved (no public DNS yet), the
# mesh-internal URL through the AI Gateway is still the canonical perimeter.
# CRD CEL hard-rejects status updates where phase=Approved + globalResourceEndpoint
# unset, so this fallback is required, not optional.

import os as _os

# Dataplane cutover (owner direction 2026-09-01): the dataplane is
# agentgateway (DATAPLANE-DIRECTION.md §9.1). The perimeter host is the
# Gateway's own Service, created by the agentgateway controller per Gateway.
_GATEWAY_BASE_DEFAULT = "http://modaas-agw.agentgateway-system.svc.cluster.local"

# wire_format → gateway listener port. The Gateway has two listeners
# (deploy/agentgateway/gateway-modaas-agw.yaml): `http` :8080 carries
# HTTPRoute traffic (MCP tools); `llm` :8081 carries AgentgatewayModel
# LLM routes. The previous dataplane served everything on :80, so the
# old URL builder had no port concept; agentgateway needs one.
WIRE_FORMAT_GATEWAY_PORT: Dict[str, int] = {
    "bedrock-runtime": 8081,
    "bedrock-runtime-stream": 8081,
    "sagemaker-runtime": 8081,
    "openai-compat": 8081,
    "vertex-ai": 8081,
    "agentcore-runtime": 8080,
    "agentcore-mcp": 8080,
    # Lane I (plan 1.15): agent invocation fronting rides the `http` listener,
    # because `llm`/`llm-tls` restrict allowedRoutes.kinds to AgentgatewayModel
    # and so cannot accept the HTTPRoute this dialect needs. Explicit rather
    # than relying on the `.get(wire_format, 8080)` default, so a future change
    # to that default cannot silently republish this dialect on another port.
    "agentcore-invocations": 8080,
}

# W4-A (sprint-2026-09-ga-hardening.md) — TLS listener perimeter-scheme
# override, requirement #42.
#
# MODAAS_PERIMETER_SCHEME / MODAAS_PERIMETER_PORT let the coordinator (W4-D,
# live, post-listener-verification per Rule 17) flip the PUBLIC-scope
# published URL from http to https without a code change, once the
# llm-tls :8443 listener demonstrably answers. Deliberately scoped to the
# public endpoint only:
#   - mesh always stays http (mTLS terminates at the sidecar — see the
#     module's existing mesh-scope contract in compute_all_endpoints).
#   - vpc already publishes https:// unconditionally (see
#     compute_all_endpoints below) and is untouched by this override.
# Requirement #42's own must-not-haves: never publish https:// before the
# listener is live. That is why the default is "http" — flipping the env
# var is a deploy-time decision for whoever owns the live cluster, not a
# code-time one for this lane.
_VALID_PERIMETER_SCHEMES = ("http", "https")


def _resolve_perimeter_scheme_override() -> Optional[str]:
    """Read MODAAS_PERIMETER_SCHEME and validate it.

    Returns "http" or "https" when the env var is set to one of those
    values, or None when unset (caller keeps existing MODAAS_PUBLIC_GATEWAY_SCHEME
    behavior unchanged). An unrecognized non-empty value is NOT allowed to
    propagate into a published URL — this fails closed to "http" and logs a
    warning naming the bad value, so a typo in a Helm value shows up in
    operator logs instead of silently minting a malformed scheme.
    """
    raw = _os.environ.get("MODAAS_PERIMETER_SCHEME")
    if raw is None or raw == "":
        return None
    if raw not in _VALID_PERIMETER_SCHEMES:
        logger.warning(
            "MODAAS_PERIMETER_SCHEME=%r is not one of %s — falling back to "
            "'http' (fail-closed; requirement #42 must-not-haves: never "
            "publish https:// unless the value is explicitly recognized)",
            raw,
            _VALID_PERIMETER_SCHEMES,
        )
        return "http"
    return raw


def _resolve_perimeter_port_override() -> Optional[int]:
    """Read MODAAS_PERIMETER_PORT and validate it as a positive integer.

    Returns None when unset (caller keeps the existing WIRE_FORMAT_GATEWAY_PORT
    map behavior for the public scope). A non-integer or non-positive value
    is treated as unset (with a warning) rather than raising — a bad port
    override should not crash the reconcile loop.
    """
    raw = _os.environ.get("MODAAS_PERIMETER_PORT")
    if raw is None or raw == "":
        return None
    try:
        port = int(raw)
    except ValueError:
        logger.warning(
            "MODAAS_PERIMETER_PORT=%r is not an integer — ignoring override",
            raw,
        )
        return None
    if port <= 0:
        logger.warning(
            "MODAAS_PERIMETER_PORT=%r is not a positive port number — "
            "ignoring override",
            raw,
        )
        return None
    return port


def _with_port(base: str, wire_format: str) -> str:
    """Append the wire-format listener port unless the base already pins one.

    An operator override (MODAAS_GATEWAY_URL / MODAAS_MESH_GATEWAY_HOST)
    that carries an explicit :port is respected as-is — the operator knows
    its topology better than the default map does.
    """
    hostpart = base.rsplit("/", 1)[-1]
    if ":" in hostpart:
        return base
    return f"{base}:{WIRE_FORMAT_GATEWAY_PORT.get(wire_format, 8080)}"


def fallback_perimeter_url(asset_alias: str, wire_format: str) -> str:
    """Build the mesh-internal gateway URL for an asset/wire_format pair.

    Used when Canvas canvas-depapi-op has not yet written status.implementation.url.
    Returns a fully-qualified http:// URL into the agentgateway dataplane
    (Gateway modaas-agw, agentgateway-system).

    Per a design note: this URL IS the governance perimeter; agents that read it
    automatically honor the perimeter. Canvas resolution adds public DNS later.

    endpoint-publication-fix (U3, BR-4): path lookup migrated to
    ``gateway_path_for`` — raises ``UnknownWireFormatError`` for a wire
    format with no gateway path, rather than silently defaulting to the
    OpenAI-compat path.
    """
    base = _os.environ.get("MODAAS_GATEWAY_URL", _GATEWAY_BASE_DEFAULT).rstrip("/")
    base = _with_port(base, wire_format)
    template = gateway_path_for(wire_format)
    path = template.format(alias=asset_alias)
    return f"{base}{path}"


# ── a design note layer 2: multi-scope endpoint computation ─────────────────────── #
# Operator emits all reachable scopes (mesh / vpc / public) so consumers
# downstream can pick the one whose network reachability matches their
# environment. AgentCore Runtime in PUBLIC mode cannot reach
# `*.svc.cluster.local`; it needs the public ELB DNS or a PrivateLink VPC
# host. Earlier we emitted only the mesh URL — managed agents silently
# bypassed MoDaaS or failed DNS. This helper closes that gap.

# Default candidate (namespace, service-name) pairs to probe when looking up
# the Istio ingress LoadBalancer. Order matters — first hit wins. The first
# entry is the upstream Istio default (istio-system/istio-ingressgateway);
# subsequent entries cover clusters where the gateway was installed under
# a different name/namespace (e.g., the Sail-operator pattern that puts the
# gateway in its own istio-ingress namespace as svc/istio-ingress, used on
# our development cluster). Operators MAY override the entire list
# via MODAAS_ISTIO_LB_NAMESPACE + MODAAS_ISTIO_LB_SERVICE, in which case
# only that one candidate is probed.
_ISTIO_LB_CANDIDATES: tuple = (
    # ai-gateway retirement: the agentgateway Gateway's own LoadBalancer
    # Service is the public perimeter now — probe it FIRST. The Istio
    # ingress candidates below remain as fallbacks for clusters where the
    # Gateway Service is ClusterIP and Istio still fronts public traffic.
    ("agentgateway-system", "modaas-agw"),
    ("istio-system", "istio-ingressgateway"),  # upstream Istio default
    ("istio-ingress", "istio-ingress"),        # Sail-operator / <cluster> layout
    ("istio-system", "istio-ingress"),
    ("istio-ingress", "istio-ingressgateway"),
)


def _candidate_istio_lb_lookups() -> tuple:
    """Return the ordered (namespace, service-name) pairs to probe.

    If MODAAS_ISTIO_LB_NAMESPACE and MODAAS_ISTIO_LB_SERVICE are both set,
    return only that single override candidate. Otherwise return the default
    list of well-known layouts.
    """
    ns = _os.environ.get("MODAAS_ISTIO_LB_NAMESPACE")
    name = _os.environ.get("MODAAS_ISTIO_LB_SERVICE")
    if ns and name:
        return ((ns, name),)
    return _ISTIO_LB_CANDIDATES


def _resolve_istio_lb_dns(k8s_api=None) -> Optional[str]:
    """Look up the Istio ingress LoadBalancer Service hostname (ELB DNS).

    Probes a small list of well-known (namespace, service-name) candidates
    (see _ISTIO_LB_CANDIDATES) and returns the first LoadBalancer hostname
    it finds. Operators on non-default cluster layouts can pin the lookup
    via env vars MODAAS_ISTIO_LB_NAMESPACE + MODAAS_ISTIO_LB_SERVICE.

    Returns None if no candidate has a LoadBalancer ingress yet, no service
    matches, or the kubernetes client isn't importable. The k8s_api
    parameter is accepted for symmetry with other helpers but isn't used
    directly — we always use CoreV1Api for Services.

    Why multi-candidate: 2026-05-27 incident — operator was hardcoded to
    istio-system/istio-ingressgateway and silently fell back to mesh-only
    on clusters where Sail or Helm chose a different name/namespace.
    """
    try:
        from kubernetes import client as _k8s_client
    except Exception as e:  # pragma: no cover - import failure path
        logger.debug("Istio LB DNS resolve: kubernetes client unavailable: %s", e)
        return None
    core = _k8s_client.CoreV1Api()
    last_err: Optional[Exception] = None
    for ns, name in _candidate_istio_lb_lookups():
        try:
            svc = core.read_namespaced_service(name=name, namespace=ns)
        except Exception as e:
            last_err = e
            logger.debug("Istio LB DNS probe %s/%s skipped: %s", ns, name, e)
            continue
        lb = getattr(getattr(svc, "status", None), "load_balancer", None)
        ingress_list = getattr(lb, "ingress", None) if lb else None
        if not ingress_list:
            logger.debug("Istio LB DNS probe %s/%s: no ingress yet", ns, name)
            continue
        first = ingress_list[0]
        host = getattr(first, "hostname", None) or getattr(first, "ip", None)
        if host:
            logger.debug("Istio LB DNS resolved via %s/%s: %s", ns, name, host)
            return host
    if last_err is not None:
        logger.debug("Istio LB DNS resolve: no candidate matched (last err: %s)", last_err)
    return None


def compute_all_endpoints(
    asset_alias: str,
    wire_format: str,
    k8s_api=None,
) -> Dict[str, Optional[str]]:
    """Compute mesh + vpc + public URLs for one asset/wire_format pair.

    Scopes:
      mesh   — always available — http(s)://<mesh-host><wire-path>.
               Default mesh host is the in-cluster Service DNS for the
               agentgateway Gateway (modaas-agw). Override with
               MODAAS_MESH_GATEWAY_HOST.
      vpc    — populated when MODAAS_VPC_GATEWAY_HOST is set (PrivateLink /
               internal NLB hostname for AWS-managed agent VPCs).
      public — populated when MODAAS_PUBLIC_GATEWAY_HOST is set, OR
               auto-resolved from svc/istio-ingressgateway LoadBalancer DNS
               in istio-system if k8s_api is supplied.

    Each scope returns a fully-qualified URL with the wire-format path; mesh
    is http (mTLS terminates at sidecar), vpc + public are https. Scopes
    that can't be resolved come back as None — the caller decides whether
    to omit them from status, choose a fallback, or fail.

    endpoint-publication-fix (U3, BR-4): path lookup migrated to
    ``gateway_path_for`` — raises ``UnknownWireFormatError`` for a wire
    format with no gateway path, rather than silently defaulting to the
    OpenAI-compat path (the original Addendum 1 defect).
    """
    template = gateway_path_for(wire_format)
    path = template.format(alias=asset_alias)

    mesh_host = _os.environ.get(
        "MODAAS_MESH_GATEWAY_HOST",
        "modaas-agw.agentgateway-system.svc.cluster.local",
    )
    vpc_host = _os.environ.get("MODAAS_VPC_GATEWAY_HOST")  # may be None
    public_host = _os.environ.get("MODAAS_PUBLIC_GATEWAY_HOST")
    if not public_host:
        public_host = _resolve_istio_lb_dns(k8s_api)

    public_scheme = _os.environ.get("MODAAS_PUBLIC_GATEWAY_SCHEME", "http")
    perimeter_scheme_override = _resolve_perimeter_scheme_override()
    if perimeter_scheme_override is not None:
        public_scheme = perimeter_scheme_override

    mesh_base = _with_port(f"http://{mesh_host}", wire_format) if mesh_host else None

    public_port_override = _resolve_perimeter_port_override()
    if public_port_override is not None and public_host:
        public_base = f"{public_scheme}://{public_host}:{public_port_override}"
    else:
        public_base = (
            _with_port(f"{public_scheme}://{public_host}", wire_format)
            if public_host else None
        )
    return {
        "mesh":   f"{mesh_base}{path}" if mesh_base else None,
        "vpc":    f"https://{vpc_host}{path}" if vpc_host else None,
        "public": f"{public_base}{path}" if public_base else None,
    }


# Scope preference order for the canonical (legacy) endpoint field.
# Public is preferred because it's reachable from AWS-managed agent VPCs
# (AgentCore Runtime, Lambda) and from on-cluster pods alike. Mesh is
# the fallback of last resort — only in-cluster pods can resolve it.
_SCOPE_PREFERENCE: tuple = ("public", "vpc", "mesh")


def pick_best_endpoint(
    endpoints: Dict[str, Optional[str]],
) -> tuple:
    """Pick (scope, url) for the broadest scope where url is non-None.

    Order: public > vpc > mesh. Returns ("mesh", mesh_url_or_None) when
    no scope resolved — callers should still write a mesh URL because the
    CRD CEL hard-rejects status updates with phase=Approved + empty
    globalResourceEndpoint, and mesh is the always-on default.
    """
    for scope in _SCOPE_PREFERENCE:
        url = endpoints.get(scope)
        if url:
            return scope, url
    return "mesh", endpoints.get("mesh")


# ── Pattern 1: ToolConfig → TMF API wrapping ─────────────────────────── #

def ensure_dependent_api(
    k8s_api,
    namespace: str,
    tool_name: str,
    api_type: str,
    specification_url: str,
    api_version: Optional[str] = None,
    owner_reference: Optional[dict] = None,
) -> Optional[dict]:
    """Create a Canvas DependentAPI for a ToolConfig that wraps a TMF API.

    Args:
      k8s_api: kubernetes CustomObjectsApi
      namespace: where the ToolConfig + DependentAPI live
      tool_name: ToolConfig.spec.toolName
      api_type: 'openapi' (most common) | 'asyncapi' | 'graphql'
      specification_url: URL to the OpenAPI/AsyncAPI spec (e.g. TMF620)
      api_version: optional spec version (e.g. "4.0.0")
      owner_reference: ToolConfig as owner so DependentAPI cascades

    Returns the created object, or None on errors / already-exists.
    Non-blocking.
    """
    name = f"modaas-tool-{tool_name}-depapi"[:253]

    body = {
        "apiVersion": DEPENDENT_API_API_VERSION,
        "kind": "DependentAPI",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "oda.tmforum.org/toolName": tool_name,
                "app.kubernetes.io/managed-by": "modaas",
            },
        },
        "spec": {
            "name": tool_name,
            "apiType": api_type,
            # Canvas DependentAPI v1 schema: specification is a single object
            # with {url, version}. (v1beta3/v1beta4 used array-of-strings; v1
            # storage version normalized to the object form.)
            "specification": {"url": specification_url, **({"version": api_version} if api_version else {})},
        },
    }
    if owner_reference is not None:
        body["metadata"]["ownerReferences"] = [owner_reference]

    try:
        return k8s_api.create_namespaced_custom_object(
            group=DEPENDENT_API_GROUP,
            version=DEPENDENT_API_VERSION,
            namespace=namespace,
            plural=DEPENDENT_API_PLURAL,
            body=body,
        )
    except Exception as e:
        status = getattr(e, "status", None)
        if status in (404, 409):
            logger.debug("DependentAPI for tool %s status=%s (non-blocking)", tool_name, status)
            return None
        logger.warning("DependentAPI for tool %s failed (non-blocking): %s", tool_name, type(e).__name__)
        return None


# ── Pattern 2: Per-asset per-wire-format emission ────────────────────── #

def ensure_dependent_api_for_wire_format(
    k8s_api,
    namespace: str,
    asset_name: str,
    asset_uid: str,
    provider: str,
    wire_format: str,
    owner_reference: Optional[dict] = None,
) -> Optional[dict]:
    """Create or get DependentAPI for (asset, wire_format). Idempotent.

    Each MoDaaS asset operator calls this per wire format at reconcile time.
    Canvas's canvas-depapi-op resolves the DependentAPI to a VirtualService
    and writes status.implementation.url. The operator reads that URL and
    writes it to asset.status.globalResourceEndpoint.

    Args:
      k8s_api: kubernetes CustomObjectsApi
      namespace: CR namespace
      asset_name: ModelConfig/ToolConfig/AgentConfig .metadata.name
      asset_uid: .metadata.uid of the source asset
      provider: spec.provider value (drives wire format selection)
      wire_format: specific wire format (e.g., 'bedrock-runtime')
      owner_reference: optional Component owner for cascade

    Returns the DependentAPI object (existing or newly created).
    """
    name = f"modaas-{asset_name}-{wire_format}"[:253]

    # Try to get existing first (idempotent)
    try:
        existing = k8s_api.get_namespaced_custom_object(
            group=DEPENDENT_API_GROUP,
            version=DEPENDENT_API_VERSION,
            namespace=namespace,
            plural=DEPENDENT_API_PLURAL,
            name=name,
        )
        return existing
    except Exception as get_err:
        get_status = getattr(get_err, "status", None)
        if get_status != 404:
            logger.warning(
                "DependentAPI get for %s/%s unexpected error: %s",
                asset_name, wire_format, get_err,
            )
            return None

    # Does not exist — create
    body = {
        "apiVersion": DEPENDENT_API_API_VERSION,
        "kind": "DependentAPI",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "oda.tmforum.org/asset-name": asset_name,
                "oda.tmforum.org/wire-format": wire_format,
                "app.kubernetes.io/managed-by": "modaas",
            },
            "annotations": {
                "modaas.oda.tmforum.org/source-uid": asset_uid,
                "modaas.oda.tmforum.org/provider": provider,
            },
        },
        "spec": {
            "name": f"{asset_name}/{wire_format}",
            "apiType": "openapi",
            # Canvas DependentAPI v1 schema: specification is a single object
            # with {url, version}. Use a placeholder URL until a real spec
            # exists for the wire-format.
            "specification": {
                "url": f"https://oda.tmforum.org/specifications/{wire_format}.openapi.yaml",
                "version": "1.0.0",
            },
        },
    }
    if owner_reference is not None:
        body["metadata"]["ownerReferences"] = [owner_reference]

    try:
        return k8s_api.create_namespaced_custom_object(
            group=DEPENDENT_API_GROUP,
            version=DEPENDENT_API_VERSION,
            namespace=namespace,
            plural=DEPENDENT_API_PLURAL,
            body=body,
        )
    except Exception as e:
        status_code = getattr(e, "status", None)
        if status_code == 409:
            # Race — another reconcile created it. Fetch and return.
            try:
                return k8s_api.get_namespaced_custom_object(
                    group=DEPENDENT_API_GROUP,
                    version=DEPENDENT_API_VERSION,
                    namespace=namespace,
                    plural=DEPENDENT_API_PLURAL,
                    name=name,
                )
            except Exception:
                pass
        logger.warning(
            "DependentAPI create for %s/%s failed: %s",
            asset_name, wire_format, type(e).__name__,
        )
        return None
