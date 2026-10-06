"""Program agentgateway from a MoDaaS CR.

Emits an ``AgentgatewayModel`` per approved ModelConfig so the agentgateway dataplane serves the same
alias, the same backing model and the same guardrail the CR declares. This is step 1 of the
ai-gateway-pod retirement path in ``docs/DATAPLANE-DIRECTION.md``.

Three upstream behaviours are load-bearing here and were each found by reading agentgateway source
rather than documentation:

1. ``spec.provider`` is REQUIRED and provider-specific config must agree with it. CEL rejects the object
   otherwise: "bedrock must be set if and only if provider is Bedrock" and "exactly one of the fields in
   [provider virtualModel] must be set".

2. There is NO alias -> upstream-model field. ``effectiveModelName()``
   (controller/pkg/agentgateway/translator/model_collections.go:657) returns ``match.model`` and sends
   that same string to the provider, so a MoDaaS alias reaches Bedrock verbatim and is rejected with
   "The provided model identifier is invalid." A CEL body transformation rewriting ``model`` is the
   available mapping mechanism, so that is what we emit. Upstream gap, tracked as W5.

3. The Gateway listener must explicitly list this kind in ``allowedRoutes.kinds``, and the controller
   must run with ``AGW_ENABLE_AGENTGATEWAY_MODELS=true`` (the API is upstream-experimental, default off).
   Neither is emitted here — both are cluster-level install concerns, asserted by G06 instead.
"""
import logging
from typing import Optional

logger = logging.getLogger("shared.agentgateway_route")

AGW_GROUP = "agentgateway.dev"
AGW_VERSION = "v1alpha1"
AGW_MODELS_PLURAL = "agentgatewaymodels"

# MoDaaS provider string -> agentgateway spec.provider enum value.
_PROVIDER_MAP = {
    "aws-bedrock": "Bedrock",
    "bedrock": "Bedrock",
    "openai": "OpenAI",
    "anthropic": "Anthropic",
}


def agentgateway_enabled() -> bool:
    """On by default: agentgateway is the sole MoDaaS dataplane.

    MODAAS_PROGRAM_AGENTGATEWAY=false remains available as an emergency
    kill-switch for route programming (e.g. gateway maintenance windows).
    """
    import os
    return os.getenv("MODAAS_PROGRAM_AGENTGATEWAY", "true").lower() in ("1", "true", "yes")


def gateway_ref() -> tuple:
    """(namespace, gateway name, listener sectionName) for the agentgateway Gateway."""
    import os
    return (
        os.getenv("MODAAS_AGW_NAMESPACE", "agentgateway-system"),
        os.getenv("MODAAS_AGW_GATEWAY", "modaas-agw"),
        os.getenv("MODAAS_AGW_LISTENER", "llm"),
    )


def _parent_refs() -> list:
    """W4 residual fix: emit one parentRef per listener section in
    MODAAS_AGW_SECTIONS (comma-separated; default 'llm,llm-tls') so the http
    and https listeners serve the same governed route set. Backward
    compatible: MODAAS_AGW_LISTENER still wins when SECTIONS is unset AND
    LISTENER was explicitly set to something else."""
    import os
    ns, gw, listener = gateway_ref()
    sections_env = os.getenv("MODAAS_AGW_SECTIONS")
    if sections_env:
        sections = [x.strip() for x in sections_env.split(",") if x.strip()]
    elif os.getenv("MODAAS_AGW_LISTENER"):
        sections = [listener]
    else:
        sections = ["llm", "llm-tls"]
    return [{
        "group": "gateway.networking.k8s.io",
        "kind": "Gateway",
        "name": gw,
        "sectionName": sec,
    } for sec in sections]


def build_agentgateway_model(alias: str, spec: dict, status: dict) -> Optional[dict]:
    """Build the AgentgatewayModel body, or None when the CR is not routable.

    Returns None rather than raising for an unmapped provider: an unsupported provider must not fail the
    whole reconcile, and F55 established that a silently-successful no-op is also unacceptable — the
    caller reports the skip on a condition.
    """
    provider_raw = (spec.get("provider") or "aws-bedrock").strip()
    provider = _PROVIDER_MAP.get(provider_raw.lower())
    if not provider:
        return None

    ns, gw, listener = gateway_ref()
    body = {
        "apiVersion": f"{AGW_GROUP}/{AGW_VERSION}",
        "kind": "AgentgatewayModel",
        "metadata": {
            "name": alias,
            "namespace": ns,
            "labels": {
                "modaas.io/managed-by": "aws-model-operator",
                "modaas.io/alias": alias,
            },
        },
        "spec": {
            "parentRefs": _parent_refs(),
            "provider": provider,
            "match": {"model": alias},
        },
    }

    if provider == "Bedrock":
        # The CR's DECLARED region is the truth. `spec.awsBedrock.region` is
        # `required` in the v1beta1 schema, so for a Bedrock ModelConfig it is
        # always present.
        #
        # The chain here used to begin `status.get("region") or
        # spec.get("region") or ...`. Neither is a declared field: the CRD's
        # status has 40 properties and the only region among them is
        # `guardrailRegion`, and there is no top-level `spec.region` either. The
        # API server strips an undeclared status write (Coherence Rule 20), so
        # both reads can only return a value when a test hands the function a
        # dict it built itself -- which is exactly how the precedence bug
        # survived: the tests pre-set the very keys that shadow the real one, so
        # the production path was never exercised. Same shape as the R3
        # ai-gateway fallback in agent_operator.py.
        #
        # Consequence on a live cluster (found 2026-09-20 running Module 7 on a
        # us-west-2 cluster with a CR declaring us-east-1): whichever region
        # reached `status` won over the declaration, so the gateway invoked
        # Bedrock in one region carrying a guardrail id registered in another.
        region = (spec.get("awsBedrock") or {}).get("region")
        if not region:
            # No guessed default. The old chain ended `or "us-west-2"`, which
            # published a route to a region nobody declared -- a plausible value
            # standing in for absent data, on the request path. A Bedrock CR
            # without a region cannot be served correctly, so it is not served.
            logger.warning(
                "agentgateway_route: alias=%s is provider=%s with no "
                "spec.awsBedrock.region; refusing to publish a route rather "
                "than guessing a region", alias, provider_raw,
            )
            return None

        bedrock: dict = {"region": region}
        gid = status.get("guardrailId")
        if gid:
            # AgentgatewayModel.spec.bedrock carries ONE region, verified
            # against the live CRD (keys: guardrail{identifier,version},
            # region) -- the guardrail has no region of its own and resolves in
            # bedrock.region. So a guardrail registered in a different region
            # than the model cannot be expressed here at all.
            #
            # The three ways out, and why this one: emitting the model's region
            # and dropping the guardrail would serve the model with its safety
            # enforcement silently gone, which a design note's truthfulness invariant
            # forbids outright -- a control that does not exist is the one
            # defect class this project will not ship. Emitting the guardrail's
            # region instead would resolve the guardrail and send the invoke to
            # a region that may not host the model. Publishing nothing leaves
            # the alias unserved and visible, with no ungoverned path.
            gr_region = status.get("guardrailRegion") or region
            if gr_region != region:
                logger.warning(
                    "agentgateway_route: alias=%s has guardrail %s registered "
                    "in %s but the model declares %s, and "
                    "AgentgatewayModel.spec.bedrock carries one region for "
                    "both; refusing to publish a route that would either "
                    "invoke the wrong region or serve the model with its "
                    "guardrail silently dropped",
                    alias, gid, gr_region, region,
                )
                return None
            bedrock["guardrail"] = {
                "identifier": gid,
                "version": status.get("guardrailVersion") or "DRAFT",
            }
        body["spec"]["bedrock"] = bedrock

    # The alias -> upstream model rewrite (see module docstring, point 2).
    model_id = (status.get("resolvedModelId") or status.get("modelId")
                or (spec.get("bedrock") or {}).get("modelId") or spec.get("modelId"))
    if model_id and model_id != alias:
        body["spec"].setdefault("policies", {})["transformations"] = [
            {"field": "model", "expression": f"'{model_id}'"}
        ]
    return body


def emit_agentgateway_model(k8s_api, alias: str, spec: dict, status: dict,
                            apply_fn=None) -> str:
    """Create or update the AgentgatewayModel. Returns 'created' | 'updated' | 'skipped'."""
    body = build_agentgateway_model(alias, spec, status)
    if body is None:
        return "skipped"
    ns = body["metadata"]["namespace"]
    if apply_fn is None:
        try:
            from shared.istio_vs_authz import _apply_with_drift_check as apply_fn  # type: ignore
        except ModuleNotFoundError:
            from operators.shared.istio_vs_authz import _apply_with_drift_check as apply_fn  # type: ignore
    apply_fn(k8s_api, AGW_GROUP, AGW_VERSION, ns, AGW_MODELS_PLURAL, body)
    return "applied"


def delete_agentgateway_model(k8s_api, alias: str) -> bool:
    """Remove the route so a deleted/paused CR stops being served. Absent is success."""
    from kubernetes.client.exceptions import ApiException
    ns, _, _ = gateway_ref()
    try:
        k8s_api.delete_namespaced_custom_object(
            group=AGW_GROUP, version=AGW_VERSION, namespace=ns,
            plural=AGW_MODELS_PLURAL, name=alias)
        return True
    except ApiException as e:
        if e.status == 404:
            return True
        raise
