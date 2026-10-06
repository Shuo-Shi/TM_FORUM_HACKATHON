"""W4.C: Per-asset Istio VirtualService + AuthorizationPolicy emission.

VirtualService routes path-prefix /<asset-name>/* to the dataplane service.
AuthorizationPolicy gates that path on the per-asset realm role
``modaas-<kind-lower>-<asset>-consumer`` — the fully-qualified name that
``shared.identity_config.ensure_identity_config`` declares on the Canvas
IdentityConfig (and that Canvas's identityconfig-operator-keycloak provisions
into Keycloak). Prior to fix/wave-2b-identity-authz the AuthZ generator
emitted the short alias ``<asset>-consumer``, mismatching the IC FQN and
rejecting every JWT-bearing request (Bug B4 from Wave 2 review).

Replaces the earlier global require-model-consumer AuthorizationPolicy with
per-asset rules; the cluster-wide RequestAuthentication still verifies the JWT
issuer + signature.
"""
import os
from typing import Optional
from kubernetes.client.exceptions import ApiException


def _consumer_role_fqn(kind: str, asset_name: str) -> str:
    """Return the fully-qualified consumer role name.

    MUST match the ``componentRole[0].name`` value emitted by
    ``shared.identity_config.ensure_identity_config`` for the same
    (kind, asset_name) pair.
    """
    return f"modaas-{kind.lower()}-{asset_name}-consumer"

ISTIO_NETWORKING_GROUP = "networking.istio.io"
ISTIO_NETWORKING_VERSION = "v1"
ISTIO_SECURITY_GROUP = "security.istio.io"
ISTIO_SECURITY_VERSION = "v1"


def _normalize(value):
    """Recursively normalize a spec subtree for stable equality comparison.

    Coerces ``None`` -> missing-key (drops keys whose value is None) so that
    ``{"a": None}`` compares equal to ``{}`` — K8s server occasionally drops
    or surfaces nulls inconsistently in different API versions. Recurses into
    nested dicts and lists. Strings, ints, bools left as-is.

    NOTE on lists: order is preserved (lists are NOT sorted). Istio
    ``rules[].when[].values`` is order-sensitive for the OR-of-roles check,
    and ``rules[].to[].operation.paths`` is logically a set but Istio compiles
    it order-independently. We accept the false-positive of "operator re-orders
    paths" triggering a REPLACE — REPLACE is idempotent, so the cost is one
    extra K8s write per re-order.
    """
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    return value


def _spec_drift(existing: dict, desired: dict) -> bool:
    """Return True if existing object's spec drifts from desired in a field
    MoDaaS owns.

    Compared keys: http (VS), rules / selector / action (AuthZ),
    hosts / gateways (VS contract surface). Other fields kubernetes mutates
    (resourceVersion, managedFields, etc.) are ignored.

    Comparison is a **deep equality** check on each owned key after
    ``_normalize()`` strips None-valued keys recursively. This catches drift
    buried any number of levels deep — including the canonical Wave 2B bug
    where ``rules[0].when[0].values[0]`` was the stale short-form
    ``<alias>-consumer`` while ``rules[0].when[0].key`` and the rest of the
    spec matched. Python's native ``!=`` is already deep over dict/list, but
    server-side null-elision could leak a False through if existing had
    ``{...}`` and desired had ``{..., "extra": None}``; ``_normalize`` makes
    that an explicit equivalence rather than relying on K8s never emitting
    nulls.
    """
    existing_spec = (existing or {}).get("spec") or {}
    desired_spec = (desired or {}).get("spec") or {}
    if not existing_spec:
        return True
    # Owned keys = whatever the DESIRED spec carries. The desired body is
    # built entirely by MoDaaS emitters, so every key present in it is
    # MoDaaS-owned by construction; keys only the server adds are absent
    # from desired and therefore ignored.
    #
    # This replaces a hardcoded Istio key list ("http", "rules", "selector",
    # "action", "hosts", "gateways"). That list was correct for
    # VirtualService/AuthorizationPolicy but this helper is ALSO the apply
    # path for AgentgatewayModel (emit_agentgateway_model imports it), whose
    # spec has NONE of those keys -- so AgentgatewayModel drift was NEVER
    # detected and a changed transform (e.g. resolvedModelId gaining the
    # us. inference-profile prefix) never propagated to the live route,
    # while the operator reported "applied". Found live 2026-09-01: the CR
    # status carried us.anthropic... and the route still rewrote to the
    # bare id, 400ing every invocation.
    for k in desired_spec:
        if _normalize(existing_spec.get(k)) != _normalize(desired_spec.get(k)):
            return True
    return False


def _apply_with_drift_check(k8s_api, group, version, namespace, plural, body):
    """Get-or-create-or-reconcile a custom object.

    Behavior:
      1. GET. If 404 → CREATE.
      2. If existing object's owned spec fields drift from desired → REPLACE
         (preserves resourceVersion). This is the path that fixes Wave 2B
         AuthZ realm-role staleness: AuthorizationPolicies on cluster created
         with the old short-form ``<alias>-consumer`` will get re-templated to
         ``modaas-{kind}-{alias}-consumer`` on the next reconcile.
      3. No drift → return existing (idempotent no-op).

    409 from CREATE → re-GET (TOCTOU race fallback). 409 from REPLACE →
    re-GET and let the next reconcile try again.
    """
    name = body["metadata"]["name"]
    existing = None
    try:
        existing = k8s_api.get_namespaced_custom_object(
            group=group, version=version, namespace=namespace,
            plural=plural, name=name,
        )
    except ApiException as e:
        if e.status != 404:
            raise

    if existing is None:
        try:
            return k8s_api.create_namespaced_custom_object(
                group=group, version=version, namespace=namespace, plural=plural, body=body,
            )
        except ApiException as e:
            if e.status == 409:
                return k8s_api.get_namespaced_custom_object(
                    group=group, version=version, namespace=namespace,
                    plural=plural, name=name,
                )
            raise

    if not _spec_drift(existing, body):
        return existing

    rv = (existing.get("metadata") or {}).get("resourceVersion")
    new_body = dict(body)
    new_body["metadata"] = dict(body.get("metadata") or {})
    if rv:
        new_body["metadata"]["resourceVersion"] = rv
    try:
        return k8s_api.replace_namespaced_custom_object(
            group=group, version=version, namespace=namespace,
            plural=plural, name=name, body=new_body,
        )
    except ApiException as e:
        if e.status == 409:
            return k8s_api.get_namespaced_custom_object(
                group=group, version=version, namespace=namespace,
                plural=plural, name=name,
            )
        raise


# Backward-compat alias: existing callers reference _get_or_create.
_get_or_create = _apply_with_drift_check


def emit_per_asset_istio(k8s_api, namespace: str, asset_name: str,
                         asset_uid: str, owner_reference: Optional[dict] = None,
                         kind: Optional[str] = None):
    """Emit VirtualService + AuthorizationPolicy for per-asset access scoping.

    Args:
        k8s_api: kubernetes.client.CustomObjectsApi instance
        namespace: namespace for the Istio resources
        asset_name: name of the ModelConfig/ToolConfig/AgentConfig CR
        asset_uid: UID of the asset CR
        owner_reference: optional ownerReference dict (from Component CR)
        kind: CRD kind ("ModelConfig" | "ToolConfig" | "AgentConfig"). REQUIRED
            for the AuthorizationPolicy realm-role binding to match the
            IdentityConfig FQN (Bug B4 / fix/wave-2b-identity-authz). When
            omitted, falls back to the legacy short alias for backward
            compatibility with pre-fix tests; production callers MUST pass it.
    """
    if kind:
        consumer_role = _consumer_role_fqn(kind, asset_name)
    else:
        # Backward-compat: legacy short alias. Logs a warning so we surface
        # remaining call sites that haven't been updated.
        import logging
        logging.getLogger("shared.istio_vs_authz").warning(
            "emit_per_asset_istio called without kind= for asset %s; "
            "falling back to legacy short consumer-role alias. JWT-bearing "
            "requests will be rejected unless callers are updated.",
            asset_name,
        )
        consumer_role = f"{asset_name}-consumer"
    vs_body = {
        "apiVersion": f"{ISTIO_NETWORKING_GROUP}/{ISTIO_NETWORKING_VERSION}",
        "kind": "VirtualService",
        "metadata": {
            "name": f"{asset_name}-vs",
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/part-of": "modaas",
                "modaas.tmforum.org/asset": asset_name,
            },
        },
        "spec": {
            "hosts": ["*"],
            "gateways": [_public_istio_gateway()],
            "http": [{
                "match": [{"uri": {"prefix": f"/{asset_name}/"}}],
                "route": [{
                    "destination": {
                        # Route to the current dataplane Service; the
                        # drift-checked apply below corrects any stale host.
                        # Istio-fronted per-asset path to the agentgateway
                        # dataplane's llm listener, not the retired pod.
                        # This emitter is why every live per-asset
                        # VirtualService still pointed at the previous dataplane host even
                        # after the endpoint publication was fixed.
                        "host": _vs_destination_host(),
                        "port": {"number": _vs_destination_port()},
                    },
                }],
            }],
        },
    }
    if owner_reference:
        vs_body["metadata"]["ownerReferences"] = [owner_reference]

    authz_body = {
        "apiVersion": f"{ISTIO_SECURITY_GROUP}/{ISTIO_SECURITY_VERSION}",
        "kind": "AuthorizationPolicy",
        "metadata": {
            "name": f"{asset_name}-authz",
            # F45: MUST be the GATEWAY's namespace, not the asset's. An Istio
            # AuthorizationPolicy only selects workloads in its own namespace, so a policy
            # emitted here with a stale workload selector while the gateway runs in
            # canvas-system selects NOTHING and enforces NOTHING — it reads as governance in
            # review while being inert. The VirtualService above already targets
            # canvas-system explicitly; the policy must agree.
            "namespace": _gateway_namespace(),
            "labels": {
                "app.kubernetes.io/part-of": "modaas",
                "modaas.tmforum.org/asset": asset_name,
            },
        },
        "spec": {
            "selector": {"matchLabels": _authz_selector_labels()},
            "action": "ALLOW",
            "rules": [{
                # F45: the real governed routes are dialect-shaped. The previous pattern
                # "/{asset}/*" matched none of them, so even a correctly-placed policy would
                # not have covered a single live request path.
                "to": [{"operation": {"paths": _asset_route_paths(asset_name)}}],
                "when": [{
                    "key": "request.auth.claims[realm_access][roles]",
                    "values": [consumer_role],
                }],
            }],
        },
    }
    if owner_reference:
        authz_body["metadata"]["ownerReferences"] = [owner_reference]

    _get_or_create(k8s_api, ISTIO_NETWORKING_GROUP, ISTIO_NETWORKING_VERSION,
                   namespace, "virtualservices", vs_body)
    _get_or_create(k8s_api, ISTIO_SECURITY_GROUP, ISTIO_SECURITY_VERSION,
                   # The AuthorizationPolicy body targets the GATEWAY namespace (F45: a policy only
                   # selects workloads in its own namespace), so the get/create/replace calls must
                   # target that same namespace. Passing the asset's namespace here while the body
                   # said canvas-system meant the operator read and wrote different objects.
                   _gateway_namespace(), "authorizationpolicies", authz_body)

def _authz_selector_labels() -> dict:
    """Workload selector for the per-asset AuthorizationPolicy.

    Dataplane cutover (2026-09-01): the policy used to select the
    previous dataplane's workload label -- post-cutover that selects
    NOTHING, so the per-asset authorization silently guarded no workload.
    Default is the agentgateway Gateway's pods (Gateway API label, verified
    live); override for custom topologies.
    """
    import json
    raw = os.environ.get("MODAAS_AUTHZ_SELECTOR_LABELS")
    if raw:
        return json.loads(raw)
    return {"gateway.networking.k8s.io/gateway-name": "modaas-agw"}


def _vs_destination_host() -> str:
    return os.environ.get(
        "MODAAS_VS_DESTINATION_HOST",
        "modaas-agw.agentgateway-system.svc.cluster.local",
    )


def _vs_destination_port() -> int:
    return int(os.environ.get("MODAAS_VS_DESTINATION_PORT", "8081"))


def _public_istio_gateway() -> str:
    """Istio Gateway resource fronting the per-asset public path.

    Kept env-overridable: the legacy default named the retired component;
    deployments still running that Istio Gateway keep working via override.
    """
    return os.environ.get(
        "MODAAS_PUBLIC_ISTIO_GATEWAY", "canvas-system/modaas-public"
    )


def _gateway_namespace() -> str:
    """Namespace scope for perimeter Istio resources (F45).

    An AuthorizationPolicy is only applied to workloads in its OWN namespace, so this must
    match the gateway deployment, not the asset. Overridable for non-default topologies.
    """
    import os
    return os.environ.get("MODAAS_CANVAS_NAMESPACE", "canvas-system")


def _asset_route_paths(asset_name: str) -> list:
    """The real per-dialect route paths for an asset (F45).

    Kept provider-agnostic on purpose: an enterprise deployment terminates several dialects and
    the policy must cover every one, or the uncovered dialect is an unguarded hole.
    """
    return [
        f"/bedrock/model/{asset_name}/converse",
        f"/bedrock/model/{asset_name}/invoke",
        f"/sagemaker/endpoints/{asset_name}/invocations",
        f"/mcp/{asset_name}/*",
        f"/{asset_name}/*",  # retained for backward compatibility
    ]


def per_asset_authz_enabled() -> bool:
    """Gate for emitting the per-asset AuthorizationPolicy (default OFF).

    DELIBERATELY off by default: the policy is ALLOW conditioned on
    request.auth.claims[realm_access][roles], and those claims are populated ONLY by an Istio
    RequestAuthentication. With zero RequestAuthentication resources in the cluster the condition
    can never be satisfied, so enabling this without one DENIES all traffic to the gateway.
    Enable only after a RequestAuthentication bound to the Keycloak issuer/JWKS is in place and a
    real token issuer exists (identityconfig READY, not listenerRegistered=false).
    """
    import os
    return os.environ.get("MODAAS_PER_ASSET_AUTHZ", "false").lower() in ("true", "1", "yes")
