"""Body builders for the three objects k8s-agent-operator owns.

Pure functions: dict in, dict out, no K8s client. The operator does the reads
and the writes; this module decides what the objects should look like.

Naming and label parity with the a design note graft this replaces
(aws-agent-operator/agent_operator.py:552-1037) is a MIGRATION requirement, not
cosmetics -- a design note's order is install -> adopt without restarting -> remove the
graft, and adoption only works if the names and the selector match exactly.
"""
from __future__ import annotations

import copy

from operators.shared.sdk_redirect import (credential_env_from_secret,
                                           env_vars_for_dependencies,
                                           env_vars_for_tool_provider)

from withholding import RESERVED_ENV_NAMES

MANAGED_BY = "k8s-agent-operator"
#: What the a design note graft stamped. Read at adoption; never written.
LEGACY_MANAGED_BY = "aws-agent-operator"

DEFAULT_SERVICE_ACCOUNT = "modaas-agent-default"
DEFAULT_PORT = 8080
DEFAULT_REPLICAS = 1
DEFAULT_RESOURCES = {
    "requests": {"cpu": "100m", "memory": "128Mi"},
    "limits": {"cpu": "500m", "memory": "512Mi"},
}
#: istiod ports a sidecar needs before it can warm a workload certificate.
#: Without these a new pod in a policy-restricted namespace never becomes Ready
#: ("failed to sign CSR: Unavailable"), which looks harmless until the next
#: deploy -- measured 2026-09-08 on three agent pods.
ISTIOD_PORTS = (15012, 15010, 443)
DNS_NAMESPACE = "kube-system"


def resource_name(agent_name: str) -> str:
    """``agent-<agentName>`` — identical to the graft (agent_operator.py:564)."""
    return f"agent-{agent_name}"


def network_policy_name(agent_name: str) -> str:
    return f"{resource_name(agent_name)}-egress"


def labels_for(agent_name: str) -> dict:
    name = resource_name(agent_name)
    return {
        "app.kubernetes.io/name": name,
        "app.kubernetes.io/managed-by": MANAGED_BY,
        "app.kubernetes.io/part-of": "modaas-canvas",
        "oda.tmforum.org/asset-kind": "AgentConfig",
        "oda.tmforum.org/asset-name": agent_name,
        "modaas.tmforum.org/hosting-provider": "kubernetesPod",
    }


def _kp(spec: dict) -> dict:
    return spec.get("kubernetesPod") or {}


def _port(spec: dict) -> int:
    return int(_kp(spec).get("port", DEFAULT_PORT))


def _int_or_default(value, default: int) -> int:
    """`or default` would turn a legitimate 0 into the default. replicas: 0 is a
    legal CRD value meaning scale-to-zero; defaulting it would start a pod the
    operator asked to stop."""
    return default if value is None else int(value)


def build_env(*, spec: dict, agent_name: str, region: str, registry_id: str,
              gateway_url: str, resolved_models, resolved_tools,
              credential_secret: str, credential_secret_key: str) -> list[dict]:
    """Compose the pod's env block. Later layers override earlier ones.

    1. legacy back-compat (REGION, REGISTRY_ID, MODEL_ALIAS, TOOL_ALIAS) — kept
       byte-identical to the graft so existing containers work across migration.
    2. a design note SDK redirect, per resolved ModelConfig provider.
    3. U12 tool MCP URL, per resolved ToolConfig provider.
    4. a hardening note perimeter credential, as a secretKeyRef (never a literal).
    5. user-supplied spec.kubernetesPod.env — minus the perimeter-owned names.

    REQ-001: only standard SDK env var names are emitted. No MODAAS_* name ever
    enters an agent container.
    """
    deps = spec.get("dependsOn") or {}
    env: dict[str, dict] = {
        "REGION": {"name": "REGION", "value": region},
        "REGISTRY_ID": {"name": "REGISTRY_ID", "value": registry_id},
    }
    model_alias = (deps.get("models") or [None])[0]
    tool_alias = (deps.get("tools") or [None])[0]
    if model_alias:
        env["MODEL_ALIAS"] = {"name": "MODEL_ALIAS", "value": model_alias}
    if tool_alias:
        env["TOOL_ALIAS"] = {"name": "TOOL_ALIAS", "value": tool_alias}

    for name, value in env_vars_for_dependencies(list(resolved_models), gateway_url).items():
        env[name] = {"name": name, "value": value}

    for dep in resolved_tools:
        provider = dep.get("provider")
        if not provider:
            continue
        for name, value in env_vars_for_tool_provider(
                provider, gateway_url=gateway_url, asset_alias=dep.get("alias", "")).items():
            env[name] = {"name": name, "value": value}

    for entry in credential_env_from_secret(credential_secret, credential_secret_key):
        env[entry["name"]] = entry

    # User env last, so it wins -- except on the perimeter-owned names, which the
    # operator refuses outright (withholding.reserved_env_collisions). Dropping
    # them here too is defence in depth: a caller that skips the refusal check
    # still cannot produce an ungoverned pod.
    for entry in _kp(spec).get("env") or []:
        if not isinstance(entry, dict) or not entry.get("name"):
            continue
        if entry["name"] in RESERVED_ENV_NAMES:
            continue
        env[entry["name"]] = dict(entry)

    return list(env.values())


def build_deployment_body(spec: dict, namespace: str, agent_name: str,
                          owner_references: list, env_block: list,
                          *, pod_template_managed_by: str | None = None) -> dict:
    """The apps/v1 Deployment.

    ``pod_template_managed_by`` pins the pod template's managed-by label. At
    adoption it is set to whatever the existing template already carries, so the
    ownership handover is a metadata-only change and the pods do not roll
    (a design note's "adopts existing pod agents without restarting them").
    """
    kp = _kp(spec)
    name = resource_name(agent_name)
    labels = labels_for(agent_name)
    pod_labels = dict(labels)
    if pod_template_managed_by:
        pod_labels["app.kubernetes.io/managed-by"] = pod_template_managed_by

    resources = kp.get("resources") or {}
    requests = resources.get("requests") or {}
    limits = resources.get("limits") or {}
    pull_secrets = [{"name": s["name"]} for s in (kp.get("imagePullSecrets") or [])
                    if isinstance(s, dict) and s.get("name")]

    pod_spec = {
        "serviceAccountName": kp.get("serviceAccountName") or DEFAULT_SERVICE_ACCOUNT,
        # Owner decision 2026-09-26: a pod agent holds no credential it did not
        # get from the perimeter, and that includes its own Kubernetes API token.
        # The agent container talks to agentgateway, never to the apiserver, so
        # there is no documented need to keep the automount on.
        #
        # This suppresses the kubelet's automatic mount at
        # /var/run/secrets/kubernetes.io/serviceaccount/ ("If you don't want the
        # kubelet to automatically mount a ServiceAccount's API credentials, you
        # can opt out ... by setting automountServiceAccountToken: false"), and
        # the pod-level value wins over the ServiceAccount's ("If both the
        # ServiceAccount and the Pod's .spec specify a value ..., the Pod spec
        # takes precedence") --
        # kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
        # (fetched 2026-09-26).
        #
        # MIGRATION CONSEQUENCE, stated because it is real: the a design note graft's
        # pod template has no such field, so adopting a graft-created agent is a
        # genuine template change and its pods roll once. That roll IS the
        # enforcement -- preserving the old template to avoid it (the way the
        # managed-by label is preserved) would leave the token mounted inside a
        # pod MoDaaS reports as governed.
        "automountServiceAccountToken": False,
        "containers": [{
            "name": "agent",
            "image": kp["containerImage"],
            "imagePullPolicy": "IfNotPresent",
            "ports": [{"containerPort": _port(spec), "name": "http"}],
            "env": env_block,
            "resources": {
                "requests": {
                    "cpu": requests.get("cpu", DEFAULT_RESOURCES["requests"]["cpu"]),
                    "memory": requests.get(
                        "memory", DEFAULT_RESOURCES["requests"]["memory"]),
                },
                "limits": {
                    "cpu": limits.get("cpu", DEFAULT_RESOURCES["limits"]["cpu"]),
                    "memory": limits.get(
                        "memory", DEFAULT_RESOURCES["limits"]["memory"]),
                },
            },
        }],
    }
    if pull_secrets:
        pod_spec["imagePullSecrets"] = pull_secrets

    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace, "labels": labels,
                     "ownerReferences": owner_references},
        "spec": {
            "replicas": _int_or_default(kp.get("replicas"), DEFAULT_REPLICAS),
            # IMMUTABLE on a Deployment. Identical to the graft's selector, which
            # is what makes in-place adoption possible at all.
            "selector": {"matchLabels": {"app.kubernetes.io/name": name}},
            "template": {"metadata": {"labels": pod_labels}, "spec": pod_spec},
        },
    }


def build_service_body(spec: dict, namespace: str, agent_name: str,
                       owner_references: list) -> dict:
    """The ClusterIP Service. Label set omits hosting-provider, per the graft."""
    name = resource_name(agent_name)
    labels = {k: v for k, v in labels_for(agent_name).items()
              if k != "modaas.tmforum.org/hosting-provider"}
    port = _port(spec)
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name, "namespace": namespace, "labels": labels,
                     "ownerReferences": owner_references},
        "spec": {
            "type": "ClusterIP",
            "selector": {"app.kubernetes.io/name": name},
            "ports": [{"name": "http", "port": port, "targetPort": port,
                       "protocol": "TCP"}],
        },
    }


def build_network_policy_body(spec: dict, namespace: str, agent_name: str,
                              owner_references: list, *, gateway_namespace: str,
                              istiod_namespace: str | None = None) -> dict:
    """a design note's egress control: DNS, the gateway, optionally istiod. Nothing else.

    There is deliberately no 0.0.0.0/0 rule and no intra-namespace rule. The
    omission IS the control -- the same construction the namespace-wide
    components-egress-governed-only policy uses, narrowed to one agent.

    Kubernetes NetworkPolicies are additive-union across policies selecting the
    same pod, so this cannot TIGHTEN a broader policy that already allows more.
    Its value is that it holds when no namespace policy exists, and that it is
    the per-asset artifact status.kubernetesPod.networkPolicyName points at.
    """
    labels = {k: v for k, v in labels_for(agent_name).items()
              if k != "app.kubernetes.io/name"}
    labels["modaas.io/control"] = "bypass-prevention"

    egress: list[dict] = [
        {"to": [_ns(DNS_NAMESPACE)],
         "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]},
        {"to": [_ns(gateway_namespace)]},
    ]
    if istiod_namespace:
        egress.append({"to": [_ns(istiod_namespace)],
                       "ports": [{"protocol": "TCP", "port": p} for p in ISTIOD_PORTS]})

    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": network_policy_name(agent_name), "namespace": namespace,
                     "labels": labels, "ownerReferences": owner_references},
        "spec": {
            "podSelector": {
                "matchLabels": {"app.kubernetes.io/name": resource_name(agent_name)}},
            "policyTypes": ["Egress"],
            "egress": egress,
        },
    }


def _ns(name: str) -> dict:
    return {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": name}}}


# ── adoption ──────────────────────────────────────────────────────────────

_MANAGED_BY = "app.kubernetes.io/managed-by"


def adopted_from(existing: dict | None) -> str | None:
    """Who managed this Deployment before us, when that is not us."""
    if not existing:
        return None
    current = ((existing.get("metadata") or {}).get("labels") or {}).get(_MANAGED_BY)
    return current if current and current != MANAGED_BY else None


def plan_deployment_patch(existing: dict | None, desired: dict) -> tuple[dict, bool]:
    """Decide what to send, and whether the pod-template label converges now.

    Returns ``(body, pod_template_labels_converged)``.

    A Deployment's ``spec.template`` is what drives a rollout. Correcting the
    pod template's managed-by label on an otherwise-identical Deployment would
    restart every governed agent the moment this operator is installed, which
    fails a design note's migration requirement as written. So when the rest of the
    template already matches, the existing label is preserved and the divergence
    is reported (``False``) rather than fixed eagerly; when the template differs
    for a real reason, the label rides along in the roll that is happening anyway.

    The comparison is a full desired-vs-existing template diff with the label
    excluded -- the same shape as the drift-checked applies in
    operators/shared/istio_vs_authz.py, which exist because a hardcoded
    owned-key list let a corrected transform silently never propagate.
    """
    if not existing:
        return desired, True

    existing_tmpl_raw = (existing.get("spec") or {}).get("template") or {}
    if _strip_managed_by(existing_tmpl_raw) != _strip_managed_by(
            (desired.get("spec") or {}).get("template") or {}):
        return desired, True

    existing_label = (
        (existing_tmpl_raw.get("metadata") or {}).get("labels") or {}).get(_MANAGED_BY)
    body = copy.deepcopy(desired)
    labels = body["spec"]["template"]["metadata"]["labels"]
    if existing_label:
        labels[_MANAGED_BY] = existing_label
    else:
        labels.pop(_MANAGED_BY, None)
    return body, existing_label == MANAGED_BY


def _strip_managed_by(template: dict) -> dict:
    out = copy.deepcopy(template)
    labels = (out.get("metadata") or {}).get("labels")
    if isinstance(labels, dict):
        labels.pop(_MANAGED_BY, None)
    return out
