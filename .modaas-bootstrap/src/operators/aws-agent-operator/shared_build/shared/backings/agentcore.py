"""
AgentCore Registry backing (a design note).

Wraps the existing aws-model-operator/registry_client.py behind the
RegistryBacking Protocol. Parameters come from Registry.spec.parameters:
  - registryName (required): AWS Agent Registry name (e.g. modaas-canvas-registry)
  - region (default: us-west-2)
  - roleArn (optional): cross-account role for Registry access

All three are passed EXPLICITLY to registry_client.get_client(). This module
previously set `MODAAS_REGISTRY_NAME` and `AWS_DEFAULT_REGION` in os.environ
before each call and relied on the client reading them back. That was a
process-global write in a process that reconciles many assets, with two
consequences:

  * Cross-CR bleed. `_AwsRegistry._ensure_registry()` re-resolves the target
    registry on every call, so the registry name in force was whichever call set
    it last. Asset A's record could be written into asset B's registry.
  * Contamination past the registry. `AWS_DEFAULT_REGION` is read by unrelated
    code in the same process (`operators/shared/registry_lifecycle.py` uses it
    as the boto3 region fallback), so a Registry CR's `parameters.region`
    silently re-pointed the registry-lifecycle client too.

Both are closed by making the registry name and region properties of the
client rather than of the process. See
`operators/shared/tests/test_agentcore_backing_no_global_env.py` and
`operators/aws-model-operator/tests/test_registry_client_explicit_registry_name.py`.
"""
from __future__ import annotations

import logging

logger = logging.getLogger("modaas.backings.agentcore")

# Mirrors registry_client.DEFAULT_REGISTRY_NAME / _default_region()'s last
# resort. Kept local so the backing can resolve parameters without importing the
# client module at module scope.
DEFAULT_REGISTRY_NAME = "modaas-canvas-registry"
DEFAULT_REGION = "us-west-2"


class AgentCoreBacking:
    """RegistryBacking that delegates to the existing registry_client module.

    One client instance per (region, registryName, roleArn) — obtained from
    registry_client.get_client(), which caches on exactly that key.
    """

    def put_record(self, record: dict, parameters: dict) -> dict:
        return self._client(parameters).put_record(record)

    def search(self, query: str, filters: dict, parameters: dict) -> list[dict]:
        return self._client(parameters).search(query, filters)

    def deprecate(self, name: str, parameters: dict) -> None:
        self._client(parameters).deprecate(name)

    def annotate(self, name: str, metadata: dict, parameters: dict) -> None:
        """Merge metadata into the record, preserving its lifecycle state (F71)."""
        self._client(parameters).annotate(name, metadata)

    # -- internals --
    def _client(self, parameters: dict):
        """Resolve Registry.spec.parameters into a registry client.

        Every value travels as an argument. Nothing is written to os.environ.
        """
        parameters = parameters or {}
        registry_name = parameters.get("registryName") or DEFAULT_REGISTRY_NAME
        region = parameters.get("region") or DEFAULT_REGION
        # An empty string is "not configured", not "assume the empty role".
        role_arn = parameters.get("roleArn") or None
        return self._get_client(
            region, registry_name=registry_name, role_arn=role_arn,
        )

    @staticmethod
    def _get_client(region: str, *, registry_name: str, role_arn: str | None = None):
        """Return a registry_client instance via the module's get_client().

        S8/P9 (2026-09-26): this used to scan the three operator directories for
        a `registry_client.py`, insert the first one found into sys.path, and
        import the bare name — so the CANONICAL shared backing reached into a
        SIBLING operator's directory in-tree, and bound to whatever copy the
        image happened to carry in a pod. The client is now shared, and a
        relative import resolves inside this package: `operators.shared` in-tree,
        `shared` in the shared_build snapshot. One module object, one
        `_client_cache`, one `_AwsRegistry` class, either way.
        """
        from ..registry_client import get_client as _get_client_impl  # noqa: PLC0415
        return _get_client_impl(
            region, registry_name=registry_name, role_arn=role_arn,
        )
