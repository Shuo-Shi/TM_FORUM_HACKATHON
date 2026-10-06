"""Kubernetes client wrapper + cross-asset dependency resolver."""

import logging
from typing import Any

from kubernetes import client, config

logger = logging.getLogger("base.k8s")

GROUP = "oda.tmforum.org"
V2_VERSION = "v2alpha1"
ASSETCONFIGS_PLURAL = "assetconfigs"


class KubeClient:
    """Thin wrapper around kubernetes.client.CustomObjectsApi.

    Provides namespace-scoped CRUD for AssetConfig CRs and generic Istio /
    custom resources that plugins need to create."""

    def __init__(self):
        try:
            config.load_incluster_config()
        except Exception:
            config.load_kube_config()
        self._custom = client.CustomObjectsApi()
        self._core = client.CoreV1Api()

    # ── AssetConfig CR operations ──
    def get_asset(self, namespace: str, name: str) -> dict:
        return self._custom.get_namespaced_custom_object(
            GROUP, V2_VERSION, namespace, ASSETCONFIGS_PLURAL, name
        )

    def list_assets(self, namespace: str, kind: str | None = None) -> list[dict]:
        items = self._custom.list_namespaced_custom_object(
            GROUP, V2_VERSION, namespace, ASSETCONFIGS_PLURAL
        ).get("items", [])
        if kind is None:
            return items
        return [cr for cr in items if cr.get("spec", {}).get("kind") == kind]

    # ── Generic CR operations for Istio / others that plugins create ──
    def get(self, group: str, version: str, plural: str, name: str, namespace: str) -> dict:
        return self._custom.get_namespaced_custom_object(group, version, namespace, plural, name)

    def create(self, group: str, version: str, plural: str, body: dict, namespace: str) -> dict:
        return self._custom.create_namespaced_custom_object(group, version, namespace, plural, body)

    def delete(self, group: str, version: str, plural: str, name: str, namespace: str) -> None:
        self._custom.delete_namespaced_custom_object(group, version, namespace, plural, name)


class DependencyResolver:
    """Resolve spec.dependsOn references.

    Given a (kind, name) ref, fetch the target AssetConfig CR and surface
    its status.resources[] for downstream use. Used primarily by agent
    plugins that need to discover a model's resolvedModelId or a tool's
    gatewayTargetId at provision time."""

    def __init__(self, k8s: KubeClient, namespace: str):
        self._k8s = k8s
        self._ns = namespace

    def resolve(self, kind: str, name: str) -> dict:
        """Fetch the referenced AssetConfig. Raises if missing or wrong kind."""
        try:
            cr = self._k8s.get_asset(self._ns, name)
        except client.ApiException as e:
            if e.status == 404:
                raise LookupError(f"{kind}/{name} not found in namespace {self._ns}")
            raise
        actual_kind = cr.get("spec", {}).get("kind")
        if actual_kind != kind:
            raise LookupError(
                f"expected kind={kind} for {name}, got kind={actual_kind}"
            )
        return cr

    def resources_of(self, kind: str, name: str) -> list[dict]:
        """Convenience: return status.resources[] of the referenced asset."""
        cr = self.resolve(kind, name)
        return cr.get("status", {}).get("resources", []) or []

    def phase_of(self, kind: str, name: str) -> str:
        cr = self.resolve(kind, name)
        return cr.get("status", {}).get("phase", "")
