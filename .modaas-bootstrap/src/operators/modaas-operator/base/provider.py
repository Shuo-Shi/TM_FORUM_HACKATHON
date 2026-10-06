"""Base classes for MoDaaS v2 provider plugins.

Every asset provider plugin extends AssetProvider and implements:
  - provision(spec, status, ctx) -> ProvisionResult
  - deprovision(status, ctx) -> None
  - validate_spec(spec) -> list[str]  (optional, default: no extra validation)
  - registry_metadata(spec, status) -> dict  (optional, default: pluginStatus)

See docs/v2/Provider-Plugin-Contract.md for the full contract.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import ClassVar, Any


@dataclass
class ResourceRef:
    """One AWS resource owned or imported by an AssetConfig CR.

    Matches status.resources[] in the CRD. Used both for the status ledger
    and for cross-asset dependency resolution."""

    kind: str                           # "BedrockFoundationModel" | "AgentRegistryRecord" | ...
    identifier: str | None = None       # primary id
    resolvedIdentifier: str | None = None  # resolved form (us.-prefix, etc.)
    arn: str | None = None
    managed: bool = True                # False = imported reference, don't delete on deprovision
    extras: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class Condition:
    """One status.conditions[] entry."""

    type: str
    status: str                         # "True" | "False" | "Unknown"
    reason: str = ""
    message: str = ""


@dataclass
class ProvisionResult:
    """Return value of AssetProvider.provision().

    The shared reconcile loop reads this and writes it into the CR status +
    registry record. Plugins should never touch patch.status directly."""

    resources: list[ResourceRef] = field(default_factory=list)
    conditions: list[Condition] = field(default_factory=list)
    registry_metadata: dict = field(default_factory=dict)
    plugin_status: dict = field(default_factory=dict)


class ProvisioningFailed(Exception):
    """Raised by a plugin when provisioning cannot proceed.

    The reason/message land in the CR's status.reason/conditions. Phase stays
    Failed. Operator requeues after backoff (standard kopf behavior)."""

    def __init__(self, reason: str, message: str = ""):
        self.reason = reason
        self.message = message or reason
        super().__init__(f"{reason}: {message}" if message else reason)


@dataclass
class ReconcileContext:
    """Read-only environment handed to every plugin call.

    Plugins use this to construct boto3 clients, resolve cross-asset
    dependencies, read/write K8s objects. Plugins MUST NOT hold references
    across calls — a fresh ReconcileContext is built each reconcile."""

    namespace: str
    name: str
    region: str
    aws_session: Any                   # boto3.Session
    k8s: Any                           # KubeClient wrapper
    dependency_resolver: Any           # DependencyResolver
    logger: Any                        # logging.Logger

    def boto3_client(self, service: str):
        """Regional boto3 client."""
        return self.aws_session.client(service, region_name=self.region)


class AssetProvider(ABC):
    """Abstract base for all asset provider plugins.

    A plugin is identified by the (kind, provider) class attributes. The
    plugin registry maps that pair to a concrete class. Plugins are
    stateless — a fresh instance is created per reconcile."""

    kind: ClassVar[str]
    provider: ClassVar[str]

    supports_pause: ClassVar[bool] = True
    supports_retire: ClassVar[bool] = True
    emits_registry_record: ClassVar[bool] = True

    def validate_spec(self, spec: dict) -> list[str]:
        """Optional custom validation beyond CEL. Return error messages
        (empty list means valid). Default: no extra validation."""
        return []

    @abstractmethod
    def provision(self, spec: dict, status: dict, ctx: ReconcileContext) -> ProvisionResult:
        """Create or update AWS resources. MUST be idempotent."""
        ...

    @abstractmethod
    def deprovision(self, status: dict, ctx: ReconcileContext) -> None:
        """Delete managed AWS resources. Called on CR deletion or provider
        change. Iterate status.resources[] where managed==true."""
        ...

    def registry_metadata(self, spec: dict, status: dict) -> dict:
        """Project kind+provider-specific metadata into the registry record.
        Default implementation: return pluginStatus verbatim."""
        return status.get("pluginStatus", {})

    def _log_prefix(self, ctx: ReconcileContext) -> str:
        return f"[{self.kind}/{self.provider}] {ctx.namespace}/{ctx.name}"
