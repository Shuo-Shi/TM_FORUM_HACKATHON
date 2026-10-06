"""a design note Mechanism 1 — one capability-keyed table for every AWS client.

**Why this module exists.** On 2026-09-26 a Workshop Studio participant account
could not list Registries: `bedrock-agentcore-control.ListRegistries` returned
`AccessDeniedException` for all three roles. The Registry API had not been
withdrawn — it had *moved*. botocore 1.43.84 shipped a standalone
`agent-registry-control` service (`endpointPrefix agent-registry-control`,
`signingName agent-registry`, `apiVersion 2025-12-01`) carrying the same 15
operation names with different request and response shapes, and
`ListRegistries` on the standalone service succeeded in the same account with
the same role. `docs/analysis/Operator-GA-Drift-Evaluation-2026-09-01.md` missed
it because it diffed only services the operators already named.

The repo had `"bedrock-agentcore-control"` typed out at 7 call sites and no
single place that could answer "which service serves Registry?" — so a service
move was a repo-wide grep instead of a one-line edit, and a denied call looked
like a permissions problem instead of a relocation.

**What this module is.** A declarative table keyed by *capability* — what MoDaaS
needs done — rather than by botocore service name. Each entry carries the
service that serves it today, the operations MoDaaS actually calls, the
successor services to re-check when a call is denied, the account classes the
capability must work in, and a read-only probe for the a design note canary.

Callers ask for a capability:

    from operators.shared.aws_clients import client
    ctrl = client("registry.control", region)

Not for a service string. A relocation edits `CAPABILITIES` and nothing else.

**Invariants, each with a test.**

* `called_operations` names are verified to exist in the *pinned* botocore
  service model (`tests/test_aws_clients.py`). Coherence Rule 15's incident was
  three weeks of a verifier walking operation names that had never existed;
  botocore is the authority and it is already installed.
* Clients are cached per (capability, region, endpoint_url, role) — a boto3
  client per reconcile leaks connection pools, a bug this repo already fixed
  once in `registry_client.py`.
* The `role_arn` path delegates to `operators/shared/sts_credentials.py` (which
  owns credential caching and the expiry threshold) and never falls back to the
  operator's own identity. A cross-account Registry write served with the
  operator's IRSA identity is a wrong-catalog write, not a degraded one.

**Dual-import note (team convention).** Imported as
`operators.shared.aws_clients` from the repo tree and as `shared.aws_clients`
from the `shared_build/shared` pod snapshot. Every internal import here is lazy
and tries both spellings, so both work unchanged.

sim: a design note (docs/design/a design note-AWS-API-Evolution-Discipline.md)
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Optional

# Account classes a capability can be required to work in. "workshop-studio" is
# a vended-account class with its own role set (WSParticipantRole, WSOpsRole)
# and its own service-permission surface -- the class where the Registry
# relocation first showed itself as an AccessDenied.
ACCOUNT_CLASS_STANDARD = "standard"
ACCOUNT_CLASS_WORKSHOP = "workshop-studio"


class UnknownCapability(KeyError):
    """Asked for a capability id that is not in the table."""


@dataclass(frozen=True)
class Capability:
    """One thing MoDaaS needs AWS to do, and how it is served today.

    `service` is the botocore service name — the ONLY place a service string is
    written down. `successors` is what to try when `service` denies or drops an
    operation; `predecessors` records where the capability came from, so an
    audit can tell a relocation from a new dependency.

    `iam_prefix` is the IAM action prefix, which is botocore's `signingName` and
    NOT always the service name: the standalone Registry service's endpoint
    prefix is `agent-registry-control` while its actions are `agent-registry:*`.

    `probe` is `(boto3_method_name, kwargs)` for a read-only call the canary can
    make, or None when the service exposes no parameterless read operation.
    """

    id: str
    service: str
    api_version: Optional[str] = None
    called_operations: tuple[str, ...] = ()
    successors: tuple[str, ...] = ()
    predecessors: tuple[str, ...] = ()
    account_classes: tuple[str, ...] = (ACCOUNT_CLASS_STANDARD,)
    iam_prefix: str = ""
    probe: Optional[tuple[str, dict]] = None
    note: str = ""


# ─────────────────────────── the table ──────────────────────────────────────
# Ordering note: `registry.control` and `agentcore.control` name the SAME
# botocore service today. That is the point -- they are different capabilities
# that happen to share a service, and only one of them has moved. Collapsing
# them into one string is what made the relocation a repo-wide grep.
CAPABILITIES: dict[str, Capability] = {
    "registry.control": Capability(
        id="registry.control",
        # a design note PR 2: RELOCATED. The standalone service is where the Registry
        # API lives as of botocore 1.43.84 ("AWS Agent Registry becomes Generally
        # Available"). `bedrock-agentcore-control` is retained as the predecessor
        # so an audit can tell a relocation from a new dependency, and so the
        # canary can still explain a denial against the old service.
        service="agent-registry-control",
        api_version="2025-12-01",
        called_operations=(
            "list_registries",
            "create_registry",
            "get_registry",
            "update_registry",
            "delete_registry",
            "list_registry_records",
            "create_registry_record",
            "get_registry_record",
            "update_registry_record",
            "update_registry_record_status",
            "submit_registry_record_for_approval",
            "delete_registry_record",
        ),
        # Nothing further to fall back to: this IS the successor. Left empty
        # rather than pointed back at the predecessor — a canary that retried the
        # service the API left would report a relocation in the wrong direction.
        successors=(),
        predecessors=("bedrock-agentcore-control",),
        account_classes=(ACCOUNT_CLASS_STANDARD, ACCOUNT_CLASS_WORKSHOP),
        # NOT the service name: signingName is `agent-registry`, so the IAM
        # actions are `agent-registry:*` where the legacy service's were
        # `bedrock-agentcore:*`. An IAM policy carried over unchanged from the
        # legacy service grants nothing here.
        iam_prefix="agent-registry",
        probe=("list_registries", {}),
        note=(
            "Relocated from bedrock-agentcore-control (a design note PR 2). Shapes "
            "differ: descriptorType->recordType (new enum), descriptors members "
            "renamed (custom/mcp/a2a -> custom/mcpServer/a2aAgentCard), "
            "custom.inlineContent->custom.data, CreateRegistry's authorizerType "
            "moved under discoveryConfiguration, approvalConfiguration.autoApproval "
            "-> autoApprovalRules, UpdateRegistryRecordStatus.statusReason now "
            "required, ListRegistryRecords summaries carry no descriptors."
        ),
    ),
    "registry.discovery": Capability(
        id="registry.discovery",
        # a design note PR 2: RELOCATED. The legacy data plane (`bedrock-agentcore`) never
        # carried a registry search at all, which is why registry_client
        # substituted a control-plane list. The standalone discovery service has a
        # real one — and, unlike the control plane's ListRegistryRecords, its
        # summaries carry `descriptors`, so a search no longer needs an N+1 Get
        # per record to recover the TMF639 metadata.
        service="agent-registry",
        api_version="2025-12-01",
        # list_* enumerates (maxResults <= 100, nextToken); search_* is top-k
        # semantic (maxResults <= 20, no token) and is never used to enumerate.
        called_operations=("list_discoverable_registry_records",
                           "search_discoverable_registry_records"),
        successors=(),
        predecessors=("bedrock-agentcore",),
        account_classes=(ACCOUNT_CLASS_STANDARD, ACCOUNT_CLASS_WORKSHOP),
        iam_prefix="agent-registry",
        # Every discovery operation requires a registryId (or `entries`), so there
        # is no parameterless read to probe. The canary says NO_PROBE rather than
        # inventing a registry id — which would fail for reasons unrelated to the
        # capability.
        probe=None,
        note=(
            "Discovery search requires registryIds, so no parameterless probe "
            "exists. Reachability is exercised by the search path itself "
            "(registry_client._AwsRegistry.search) and by "
            "tools/registry_standalone_smoke.py."
        ),
    ),
    "agentcore.control": Capability(
        id="agentcore.control",
        service="bedrock-agentcore-control",
        api_version="2023-06-05",
        called_operations=(
            "create_agent_runtime",
            "update_agent_runtime",
            "get_agent_runtime",
            "delete_agent_runtime",
            "get_gateway",
            "create_gateway_target",
            "get_gateway_target",
            "delete_gateway_target",
            "list_gateway_targets",
        ),
        # Runtime/Gateway/Identity did NOT move with Registry. Deliberately
        # empty: a wrong successor here would send a Runtime call at the
        # Registry service.
        successors=(),
        account_classes=(ACCOUNT_CLASS_STANDARD, ACCOUNT_CLASS_WORKSHOP),
        iam_prefix="bedrock-agentcore",
        probe=("list_agent_runtimes", {}),
    ),
    "agentcore.data": Capability(
        id="agentcore.data",
        service="bedrock-agentcore",
        api_version="2024-02-28",
        called_operations=(),
        successors=(),
        account_classes=(ACCOUNT_CLASS_STANDARD,),
        iam_prefix="bedrock-agentcore",
        probe=None,
        note="Reached through the agentgateway dataplane, not by the operators.",
    ),
    "bedrock.control": Capability(
        id="bedrock.control",
        service="bedrock",
        api_version="2023-04-20",
        called_operations=(
            "get_foundation_model",
            "get_imported_model",
            "list_guardrails",
            "create_guardrail",
            "update_guardrail",
            "create_guardrail_version",
            "delete_guardrail",
            "list_tags_for_resource",
            "tag_resource",
        ),
        successors=(),
        account_classes=(ACCOUNT_CLASS_STANDARD, ACCOUNT_CLASS_WORKSHOP),
        iam_prefix="bedrock",
        probe=("list_guardrails", {"maxResults": 1}),
    ),
    "bedrock.runtime": Capability(
        id="bedrock.runtime",
        service="bedrock-runtime",
        api_version="2023-09-30",
        called_operations=("apply_guardrail",),
        successors=(),
        account_classes=(ACCOUNT_CLASS_STANDARD, ACCOUNT_CLASS_WORKSHOP),
        iam_prefix="bedrock",
        probe=("list_async_invokes", {"maxResults": 1}),
    ),
    "sagemaker.control": Capability(
        id="sagemaker.control",
        service="sagemaker",
        api_version="2017-07-24",
        called_operations=("describe_endpoint", "describe_endpoint_config"),
        successors=(),
        account_classes=(ACCOUNT_CLASS_STANDARD,),
        iam_prefix="sagemaker",
        probe=("list_endpoints", {"MaxResults": 1}),
    ),
    "iam": Capability(
        id="iam",
        service="iam",
        api_version="2010-05-08",
        called_operations=(
            "get_role",
            "get_role_policy",
            "put_role_policy",
            "list_attached_role_policies",
        ),
        successors=(),
        account_classes=(ACCOUNT_CLASS_STANDARD, ACCOUNT_CLASS_WORKSHOP),
        iam_prefix="iam",
        probe=("list_account_aliases", {}),
    ),
    "sts": Capability(
        id="sts",
        service="sts",
        api_version="2011-06-15",
        called_operations=("get_caller_identity", "assume_role"),
        successors=(),
        account_classes=(ACCOUNT_CLASS_STANDARD, ACCOUNT_CLASS_WORKSHOP),
        iam_prefix="sts",
        probe=("get_caller_identity", {}),
    ),
}


# ─────────────────────────── table accessors ────────────────────────────────
def capability(cap_id: str) -> Capability:
    """Return the Capability for `cap_id`.

    Raises UnknownCapability listing the valid ids — a typo'd capability should
    say what the alternatives are, not just fail.
    """
    try:
        return CAPABILITIES[cap_id]
    except KeyError:
        raise UnknownCapability(
            f"unknown capability {cap_id!r}; known: {', '.join(sorted(CAPABILITIES))}"
        ) from None


def service_for(cap_id: str) -> str:
    return capability(cap_id).service


def successors_for(cap_id: str) -> tuple[str, ...]:
    return capability(cap_id).successors


def called_operations(cap_id: str) -> tuple[str, ...]:
    return capability(cap_id).called_operations


def services_in_use() -> tuple[str, ...]:
    """Every botocore service any capability names today, de-duplicated.

    The a design note drift sensor's input: diff only these, plus look for successors
    among services NOT in this set.
    """
    return tuple(sorted({c.service for c in CAPABILITIES.values()}))


# ─────────────────────────── client construction ────────────────────────────
_CLIENTS: dict[tuple, Any] = {}


def _import_boto3():
    """Indirection so tests can inject a stub module (the pattern
    `sts_credentials._import_boto3` already established here)."""
    import boto3  # noqa: PLC0415

    return boto3


def _assumed_role_client(service: str, role_arn: str, region: str, **kwargs):
    """Delegate to `operators/shared/sts_credentials.py`.

    Credential caching, the T-300s refresh threshold, and the decision not to
    cache failures all live there. Re-implementing any of it here would give the
    two layers two thresholds — the exact hazard that module's docstring
    rejects.

    Canonical spelling first: when both are importable (any in-tree run) they
    are DISTINCT module objects with distinct caches, so preferring the
    canonical one keeps a single binding.
    """
    try:
        from operators.shared.sts_credentials import assumed_role_client  # noqa: PLC0415
    except ImportError:  # pragma: no cover - pod snapshot path
        from shared.sts_credentials import assumed_role_client  # noqa: PLC0415
    return assumed_role_client(service, role_arn, region, **kwargs)


def default_region() -> str:
    """AWS_REGION beats AWS_DEFAULT_REGION beats us-west-2.

    The last-resort constant is deliberately the same one
    `registry_client._default_region` uses, so a caller that omits `region` and
    a caller that goes through the registry resolve identically. The live defect
    behind that ordering: operators on a us-east-1 cluster ran with a hardcoded
    us-west-2 and wrote every record to the wrong region's registry.
    """
    return (
        os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or "us-west-2"
    )


def client(
    cap_id: str,
    region: Optional[str] = None,
    *,
    role_arn: Optional[str] = None,
    endpoint_url: Optional[str] = None,
):
    """Return a cached boto3 client for `cap_id`.

    `region` defaults to the environment. `endpoint_url` is for VPC/FIPS/custom
    control-plane overrides. `role_arn` routes through sts_credentials for
    cross-account access (a design note `Registry.spec.parameters.roleArn`); an empty
    string means "not configured", not "assume the empty role".
    """
    cap = capability(cap_id)
    region = region or default_region()
    role_arn = role_arn or None

    key = (cap.id, cap.service, region, endpoint_url, role_arn)
    cached = _CLIENTS.get(key)
    if cached is not None:
        return cached

    if role_arn:
        # Not cached locally: sts_credentials caches per credential window and
        # rebuilds at expiry. Caching here too would pin a client past the
        # expiry that module is tracking.
        return _assumed_role_client(cap.service, role_arn, region)

    kwargs: dict[str, Any] = {"region_name": region}
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url
    built = _import_boto3().client(cap.service, **kwargs)
    _CLIENTS[key] = built
    return built


def reset_caches() -> None:
    """Drop the client cache. For tests, and for an operator that has been told
    its credentials are no longer valid."""
    _CLIENTS.clear()
