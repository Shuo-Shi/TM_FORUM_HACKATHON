"""kind=agent, provider=kubernetes plugin.

Port of v1 aws-agent-operator kubernetes path. Creates Istio
VirtualService + RequestAuthentication + AuthorizationPolicy + Keycloak
realm role for A2A-authenticated K8s-hosted agents.

Keycloak client omitted from v2 MVP — plug in later via a shared helper.
For MVP this plugin creates Istio resources only and logs a warning if
Keycloak wiring isn't present."""

import logging
import os

from base.provider import (
    AssetProvider, ProvisionResult, ProvisioningFailed,
    ResourceRef, Condition, ReconcileContext,
)
from providers.registry import register


logger = logging.getLogger("providers.agent.kubernetes")

COMPONENTS_NS = os.environ.get("COMPONENT_NAMESPACE", "components")


@register
class KubernetesAgentProvider(AssetProvider):
    kind = "agent"
    provider = "kubernetes"

    def provision(self, spec: dict, status: dict, ctx: ReconcileContext) -> ProvisionResult:
        agent = spec["agent"]
        hosting = (agent.get("hosting") or {}).get("kubernetes") or {}
        agent_name = agent.get("agentName", ctx.name)
        role_name = f"agent-{agent_name}-consumer"

        # Istio resources — idempotent create-or-skip
        vs_name = f"{agent_name}-vs"
        ra_name = f"{agent_name}-ra"
        ap_name = f"{agent_name}-ap"

        # Check existing
        resources: list[ResourceRef] = []
        existing_vs = False
        try:
            ctx.k8s.get("networking.istio.io", "v1beta1", "virtualservices",
                        vs_name, ctx.namespace)
            existing_vs = True
        except Exception:
            pass

        if not existing_vs:
            try:
                vs_body = {
                    "apiVersion": "networking.istio.io/v1beta1",
                    "kind": "VirtualService",
                    "metadata": {"name": vs_name, "namespace": ctx.namespace},
                    "spec": {
                        "hosts": [f"{agent_name}.{ctx.namespace}.svc.cluster.local"],
                        "http": [
                            {"match": [{"uri": {"prefix": "/.well-known/agent.json"}}],
                             "route": [{"destination": {"host":
                                f"{agent_name}.{ctx.namespace}.svc.cluster.local"}}]},
                            {"match": [{"uri": {"prefix": "/a2a"}}],
                             "route": [{"destination": {"host":
                                f"{agent_name}.{ctx.namespace}.svc.cluster.local"}}]},
                        ],
                    },
                }
                ctx.k8s.create("networking.istio.io", "v1beta1", "virtualservices",
                               vs_body, ctx.namespace)

                ra_body = {
                    "apiVersion": "security.istio.io/v1beta1",
                    "kind": "RequestAuthentication",
                    "metadata": {"name": ra_name, "namespace": ctx.namespace},
                    "spec": {"jwtRules": [{"issuer": "modaas-keycloak",
                                            "audiences": [agent_name]}]},
                }
                ctx.k8s.create("security.istio.io", "v1beta1",
                               "requestauthentications", ra_body, ctx.namespace)

                ap_body = {
                    "apiVersion": "security.istio.io/v1beta1",
                    "kind": "AuthorizationPolicy",
                    "metadata": {"name": ap_name, "namespace": ctx.namespace},
                    "spec": {
                        "rules": [{"when": [{"key": "request.auth.claims[realm_access][roles]",
                                              "values": [role_name]}]}],
                    },
                }
                ctx.k8s.create("security.istio.io", "v1beta1",
                               "authorizationpolicies", ap_body, ctx.namespace)
            except Exception as e:
                raise ProvisioningFailed("IstioCreateFailed", str(e))

        resources.extend([
            ResourceRef(kind="IstioVirtualService", identifier=vs_name, managed=True),
            ResourceRef(kind="IstioRequestAuthentication", identifier=ra_name, managed=True),
            ResourceRef(kind="IstioAuthorizationPolicy", identifier=ap_name, managed=True),
        ])

        logger.info(f"[{ctx.namespace}/{ctx.name}] Istio resources ready")
        logger.warning(f"[{ctx.namespace}/{ctx.name}] Keycloak role '{role_name}' "
                       f"NOT YET CREATED in v2 MVP — add manually or wait for Keycloak plugin")

        agent_card_url = (
            f"http://{agent_name}.{ctx.namespace}.svc/.well-known/agent.json"
        )

        return ProvisionResult(
            resources=resources,
            conditions=[
                Condition("IstioConfigured", "True", "IstioReady",
                          "VirtualService + RequestAuthentication + AuthorizationPolicy created"),
            ],
            registry_metadata={
                "deploymentRef": hosting.get("deploymentRef", agent_name),
                "port": hosting.get("port", 8080),
                "agentCardUrl": agent_card_url,
                "agentCard": agent.get("agentCard", {}),
                "requiredRole": role_name,
            },
            plugin_status={
                "virtualServiceName": vs_name,
                "agentCardUrl": agent_card_url,
                "hostingProvider": "kubernetes",
            },
        )

    def deprovision(self, status: dict, ctx: ReconcileContext) -> None:
        for r in status.get("resources", []) or []:
            name = r.get("identifier")
            kind = r.get("kind")
            if not r.get("managed") or not name:
                continue
            group = version = plural = None
            if kind == "IstioVirtualService":
                group, version, plural = "networking.istio.io", "v1beta1", "virtualservices"
            elif kind == "IstioRequestAuthentication":
                group, version, plural = "security.istio.io", "v1beta1", "requestauthentications"
            elif kind == "IstioAuthorizationPolicy":
                group, version, plural = "security.istio.io", "v1beta1", "authorizationpolicies"
            if group:
                try:
                    ctx.k8s.delete(group, version, plural, name, ctx.namespace)
                    logger.info(f"deleted {kind}/{name}")
                except Exception as e:
                    logger.warning(f"delete {kind}/{name} failed: {e}")
