"""W4.D: Istio ServiceEntry per-provider + Sidecar egress lockdown."""
import re
from typing import Optional

from kubernetes.client.exceptions import ApiException

ISTIO_NETWORKING_GROUP = "networking.istio.io"
ISTIO_NETWORKING_VERSION = "v1"

#: Per-provider FQDN templates emitted into the Istio ServiceEntry spec.
#:
#: F5 evidence (2026-05-27 Class-F policy verifier) showed the live
#: ServiceEntry had hosts=[] and `bedrock-runtime` was not listed. Two
#: defects compounded:
#:   1. ``aws-sagemaker`` host was wrong: SageMaker runtime is
#:      ``runtime.sagemaker.<region>.amazonaws.com`` (per
#:      the dataplane boto3 client), NOT
#:      ``sagemaker-runtime.<region>.amazonaws.com`` (which is the
#:      Java/CLI service-name alias and never resolves via DNS).
#:   2. ``aws-bedrock`` only listed Bedrock data-plane runtime. The
#:      operator + gateway also call Bedrock control-plane (guardrails)
#:      at ``bedrock.<region>.amazonaws.com`` and AgentCore Gateway MCP
#:      endpoints at ``*.gateway.bedrock-agentcore.<region>.amazonaws.com``
#:      (per the MCP proxy path). Without these hosts in the
#:      ServiceEntry, REGISTRY_ONLY mode silently denies them.
#:
#: Wildcard hosts are valid in Istio ServiceEntry (resolution=DNS), per
#: https://istio.io/latest/docs/reference/config/networking/service-entry/.
PROVIDER_HOSTS_TEMPLATE = {
    "aws-bedrock": [
        "bedrock-runtime.{region}.amazonaws.com",
        "bedrock.{region}.amazonaws.com",
    ],
    "aws-sagemaker": [
        "runtime.sagemaker.{region}.amazonaws.com",
        "sagemaker.{region}.amazonaws.com",
    ],
    "agentCoreGateway": [
        "bedrock-agentcore.{region}.amazonaws.com",
        "bedrock-agentcore-control.{region}.amazonaws.com",
        "*.gateway.bedrock-agentcore.{region}.amazonaws.com",
    ],
    "openai-direct": ["api.openai.com"],
    "anthropic-direct": ["api.anthropic.com"],
    "azure-openai": ["*.openai.azure.com"],
    "google-vertex": [
        "{region}-aiplatform.googleapis.com",
        "aiplatform.googleapis.com",
    ],
}


def hosts_for_provider(provider: str, region: str = "us-west-2") -> list[str]:
    """Return resolved hostnames for a given provider + region."""
    templates = PROVIDER_HOSTS_TEMPLATE.get(provider, [])
    return [t.format(region=region) for t in templates]


def service_entry_name_for(provider: str, region: str = "us-west-2") -> str:
    """Return the RFC 1123-normalized ServiceEntry name the operator emits.

    Exposed so call sites (operator status conditions, observability tooling)
    can name the actual emitted resource without re-implementing the
    normalization rule. Mirrors the name computed inside
    :func:`emit_egress_for_provider`.
    """
    return f"egress-{_rfc1123(provider)}-{_rfc1123(region)}"


def _rfc1123(s: str) -> str:
    """Coerce a string to a valid RFC 1123 subdomain segment.

    K8s resource names must be lowercase alphanumeric, '-' or '.', and start
    + end with an alphanumeric character. Provider keys like ``agentCoreGateway``
    are camelCase by design (they're CRD enum values), so the operator must
    normalize them before using them as a resource-name segment. Without this,
    the API server returns 422 with FieldValueInvalid on metadata.name.
    """
    s = re.sub(r"[^a-z0-9.-]", "-", s.lower())
    return re.sub(r"^-+|-+$", "", s) or "x"


def emit_egress_for_provider(
    k8s_api,
    namespace: str,
    provider: str,
    region: str = "us-west-2",
    owner_reference: Optional[dict] = None,
):
    """Emit ServiceEntry allowing egress to provider's host(s).

    Idempotent: if the ServiceEntry already exists, returns early.
    """
    hosts = hosts_for_provider(provider, region)
    if not hosts:
        return  # unknown provider; skip silently

    # Resource name must be RFC 1123 — lowercase + dash-separated. Provider keys
    # are camelCase enum values (e.g. agentCoreGateway), so normalize.
    name = f"egress-{_rfc1123(provider)}-{_rfc1123(region)}"
    try:
        existing = k8s_api.get_namespaced_custom_object(
            group=ISTIO_NETWORKING_GROUP,
            version=ISTIO_NETWORKING_VERSION,
            namespace=namespace,
            plural="serviceentries",
            name=name,
        )
        if existing:
            return existing
    except ApiException as e:
        if e.status != 404:
            raise

    body = {
        "apiVersion": f"{ISTIO_NETWORKING_GROUP}/{ISTIO_NETWORKING_VERSION}",
        "kind": "ServiceEntry",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/part-of": "modaas",
                "modaas.tmforum.org/provider": provider,
            },
        },
        "spec": {
            "hosts": hosts,
            "ports": [{"number": 443, "name": "https", "protocol": "HTTPS"}],
            "location": "MESH_EXTERNAL",
            "resolution": "DNS",
        },
    }
    if owner_reference:
        body["metadata"]["ownerReferences"] = [owner_reference]

    return k8s_api.create_namespaced_custom_object(
        group=ISTIO_NETWORKING_GROUP,
        version=ISTIO_NETWORKING_VERSION,
        namespace=namespace,
        plural="serviceentries",
        body=body,
    )


def emit_sidecar_egress_lockdown(
    k8s_api,
    namespace: str,
    workload_selector: Optional[dict] = None,
):
    """Emit Sidecar resource with outboundTrafficPolicy=REGISTRY_ONLY.

    Forces mesh egress to only resolve hosts in mesh registry (ServiceEntries
    + cluster services). Default deny for arbitrary external hosts.
    """
    name = "egress-lockdown"
    try:
        existing = k8s_api.get_namespaced_custom_object(
            group=ISTIO_NETWORKING_GROUP,
            version=ISTIO_NETWORKING_VERSION,
            namespace=namespace,
            plural="sidecars",
            name=name,
        )
        if existing:
            return existing
    except ApiException as e:
        if e.status != 404:
            raise

    body = {
        "apiVersion": f"{ISTIO_NETWORKING_GROUP}/{ISTIO_NETWORKING_VERSION}",
        "kind": "Sidecar",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {"app.kubernetes.io/part-of": "modaas"},
        },
        "spec": {
            "outboundTrafficPolicy": {"mode": "REGISTRY_ONLY"},
        },
    }
    if workload_selector:
        body["spec"]["workloadSelector"] = {"labels": workload_selector}

    return k8s_api.create_namespaced_custom_object(
        group=ISTIO_NETWORKING_GROUP,
        version=ISTIO_NETWORKING_VERSION,
        namespace=namespace,
        plural="sidecars",
        body=body,
    )
