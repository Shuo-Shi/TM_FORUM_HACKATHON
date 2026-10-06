"""Agent Registry client adapter.

Wraps the AWS Agent Registry GA API behind a minimal Protocol so
operator/demo code is insulated from API shape churn. Swap via
MODAAS_REGISTRY_MODE env:
  real   → the `registry.control` capability (a design note; see aws_clients.py for
           which botocore service serves it) (default)
  stub   → in-memory dict (offline/CI)

a design note PR 2 — relocated to the standalone AWS Agent Registry service. The
`registry.control` capability now resolves to `agent-registry-control`
(apiVersion 2025-12-01, signingName `agent-registry`) and `registry.discovery`
to `agent-registry`. This was NOT a service-name swap; every payload and every
response read changed. Verified against the service model, not inferred
(Coherence Rule 15 / the Verify-Before-Assert block), and each mapping below has
a contract test in `operators/shared/tests/test_aws_payload_contracts.py`:

  legacy (bedrock-agentcore-control)   standalone (agent-registry-control)
  ────────────────────────────────────  ──────────────────────────────────────
  descriptorType (required)             recordType (required), new enum
    MCP|A2A|CUSTOM|AGENT_SKILLS           MCP|AGENT|CUSTOM|SKILL|GATEWAY
  descriptors.{mcp,a2a,custom,          descriptors.{mcpServer,a2aAgentCard,
    agentSkills}                          agentSkillsDefinition,custom,http,agui}
  custom.inlineContent                  custom.data
  a2a.agentCard.inlineContent           a2aAgentCard.data (+dataSchemaVersion)
  mcp.server / mcp.tools                mcpServer.data (+additionalData.tools)
  CreateRegistry authorizerType         discoveryConfiguration.authorizerType
  approvalConfiguration.autoApproval    approvalConfiguration.autoApprovalRules
  UpdateRegistryRecordStatus            statusReason now REQUIRED
  CreateRegistry -> registryArn ONLY    unchanged (see _id_from_arn)
  CreateRegistryRecord -> recordArn     unchanged (see _id_from_arn)
  ListRegistryRecords summaries         NO descriptors at all

MoDaaS asset kind -> recordType + descriptor member (a design note Appendix A):

  ModelConfig → CUSTOM  · descriptors.custom.data        = TMF639 JSON string
  ToolConfig  → MCP     · descriptors.mcpServer.data     = TMF639 JSON string
  AgentConfig → AGENT   · descriptors.a2aAgentCard.data  = TMF639 JSON string

Why MoDaaS's own TMF639 projection rather than a spec-shaped A2A AgentCard or
MCP server document: the legacy service content-validated native descriptors
(live ValidationExceptions 2026-09-04 — "does not match any supported version"
for a2a.agentCard, and MCP descriptors rejecting inlineContent outright), which
is why every kind had collapsed to CUSTOM there. The standalone service takes an
opaque `data` string plus an explicit `dataSchemaVersion`, so the projection can
be carried under the NATIVE member while declaring its own schema version —
which is what these mappings do. `DESCRIPTOR_SCHEMA_VERSION` is that declaration.
Live-verified per kind by `tools/registry_standalone_smoke.py`.

Read paths (search, annotate, adopt) tolerate the legacy shapes as well as the
new ones, because records written before the relocation still exist in
long-lived registries.

sim: a design note (docs/design/a design note-AWS-API-Evolution-Discipline.md)
sim: sprint-2026-09-ga-hardening.md Lane C (owner sprint directive 2026-09-01)
"""
import json
import os
import time as _time
import uuid
from collections import OrderedDict
from typing import Protocol

# Bug #17 — CloudTrail correlation. log_aws_response captures
# ResponseMetadata.RequestId on each boto3 response so log streams join
# back to CloudTrail rows via aws_request_id. Imported lazily-tolerant:
# tests that patch boto3.client return MagicMocks without ResponseMetadata,
# so log_aws_response is a no-op in that path.
try:
    from shared.aws_request_id import log_aws_response
except ImportError:
    # In-tree run from operator dir without shared on path: define no-op fallback.
    # The real path is exercised in production where shared is on PYTHONPATH.
    def log_aws_response(response, action, **_kw):  # type: ignore[no-redef]
        return None


#: a design note: the capability this module needs, NOT a botocore service name. The
#: service that serves it is declared once in operators/shared/aws_clients.py.
#: Registry's operations moved from `bedrock-agentcore-control` to a standalone
#: `agent-registry-control` service at botocore 1.43.84 while Runtime/Gateway
#: stayed put, which is why the two are separate capabilities rather than one
#: shared string.
REGISTRY_CAPABILITY = "registry.control"

#: The discovery-plane capability (`agent-registry`). Used by search(), whose
#: response summaries carry `descriptors` — unlike the control plane's, which
#: carry none at all on the standalone service.
DISCOVERY_CAPABILITY = "registry.discovery"

#: `SearchDiscoverableRegistryRecords.searchQuery` is required, so a
#: "list everything" search needs a token that matches broadly. `*` is the
#: conventional match-all and MoDaaS filters client-side afterwards anyway (by
#: `_kind`, by features, by the caller's own query), so a narrow server-side
#: query would only risk dropping records the caller asked for.
SEARCH_MATCH_ALL = "*"

#: Discovery LIST page size. `ListDiscoverableRegistryRecords` accepts
#: maxResults <= 100 and pages by nextToken. `SearchDiscoverableRegistryRecords`
#: is a top-k semantic search (maxResults <= 20, NO nextToken) and was the wrong
#: primitive for "every record in this registry": live on 2026-09-27 it refused
#: maxResults=100 with a ValidationException on every call, and a passing call
#: would have truncated any registry past 20 records -- this client filters
#: client-side, so record 21 would read as MISSING (false drift).
_LIST_PAGE_SIZE = 100

# Env-configurable registry ID. Auto-created on first real-mode call if unset.
REGISTRY_ENV = "MODAAS_REGISTRY_ID"
DEFAULT_REGISTRY_NAME = "modaas-canvas-registry"

# Cache configuration (env-overridable for testing)
CACHE_TTL_SECONDS = int(os.environ.get("MODAAS_REGISTRY_CACHE_TTL", "300"))  # 5 min
CACHE_MAX_ENTRIES = int(os.environ.get("MODAAS_REGISTRY_CACHE_MAX", "100"))

# ── a design note PR 2: asset kind -> recordType -> descriptor member ────────────
# record["recordType"] is set by AssetOperator.record_type on every operator
# ("model" | "tool" | "agent") and flows unchanged into the record dict passed
# to put_record. The standalone service's `recordType` enum is
# [MCP, AGENT, CUSTOM, SKILL, GATEWAY] -- note AGENT and SKILL, where the legacy
# service had A2A and AGENT_SKILLS.
_RECORD_TYPE_BY_ASSET_KIND = {
    "model": "CUSTOM",   # no native "model" kind exists; a design note's TMF639 projection
    "tool": "MCP",
    "agent": "AGENT",
}

# The NATIVE `descriptors` union member for each recordType. Read off the service
# model: legacy {mcp, a2a, custom, agentSkills} became
# {mcpServer, a2aAgentCard, agentSkillsDefinition, custom, http, agui}.
#
# MoDaaS does NOT write these, and the reason is measured rather than assumed —
# see PROJECTION_MEMBER below. The map is retained because the read paths must
# recognise them (a record synchronised from a URL, or written by another
# producer, legitimately carries one) and because it is the target the day MoDaaS
# composes genuine MCP / A2A documents.
NATIVE_MEMBER_BY_RECORD_TYPE = {
    "CUSTOM": "custom",
    "MCP": "mcpServer",
    "AGENT": "a2aAgentCard",
    "SKILL": "agentSkillsDefinition",
}

#: Where MoDaaS's TMF639 projection goes, for EVERY asset kind.
#:
#: Measured live in the event account on 2026-09-26 (evidence:
#: docs/evidence/2026-09-26-registry-standalone-smoke.txt). PR 2's first attempt
#: carried the projection under the native member with an explicit
#: `dataSchemaVersion`, on the assumption that `data` is opaque and the version is
#: the producer's own declaration. The service refused:
#:
#:   mcpServer,    dataSchemaVersion="tmforum-tmf639-modaas-1.0"
#:     -> "Schema version '...' is not supported for descriptor type 'mcp'."
#:   mcpServer,    no dataSchemaVersion
#:     -> "mcp.server data does not match any supported version"
#:   a2aAgentCard, dataSchemaVersion="0.3.0"
#:     -> "Schema validation failed: content is not in compliance with schema
#:         version '0.3' for descriptor type 'a2a'."   (version accepted, content not)
#:   a2aAgentCard, every other version tried (0.2.5, 0.2.6, 1.0, v1, 0.1.0)
#:     -> "not supported for descriptor type 'a2a'."
#:
#: So the standalone service content-validates native descriptors exactly as the
#: legacy one did, and it is right to: MoDaaS's TMF639 projection is not an MCP
#: server document and not an A2A AgentCard, so declaring it as one would be a
#: false claim. `custom` takes `{data}` with no version and no content check,
#: which is what an opaque projection actually needs.
PROJECTION_MEMBER = "custom"

# Members that accept `dataSchemaVersion` alongside `data`. `custom` does NOT
# (its shape is `{data}` only), so sending one there is a ParamValidationError.
_MEMBERS_WITH_SCHEMA_VERSION = frozenset({"mcpServer", "a2aAgentCard", "agentSkillsDefinition"})

#: The schema version MoDaaS would declare for a native document it composed
#: itself. Unused by the projection paths (see PROJECTION_MEMBER) and kept so the
#: value has one home when native composition lands.
DESCRIPTOR_SCHEMA_VERSION = "tmforum-tmf639-modaas-1.0"

# Reverse-lookup order for reading content off an existing record. New members
# first, then the legacy ones, because long-lived registries hold records written
# before the relocation. Deterministic so a record carrying both resolves the
# same way every time.
_DESCRIPTOR_READ_ORDER = (
    PROJECTION_MEMBER,
    # native members: not written by MoDaaS, but a URL-synchronised record or one
    # written by another producer carries them.
    "mcpServer",
    "a2aAgentCard",
    "agentSkillsDefinition",
    # legacy members, still present on pre-relocation records
    "mcp",
    "a2a",
    "agentSkills",
)


def _record_type_for(asset_kind: str) -> str:
    """MoDaaS asset kind -> the service's `recordType`.

    Unknown/missing kind falls back to CUSTOM: an opaque projection under a
    generic kind is always accepted, where guessing a native kind may not be.
    """
    return _RECORD_TYPE_BY_ASSET_KIND.get(asset_kind, "CUSTOM")


def _descriptor_member_for(record_type: str) -> str:
    """The member MoDaaS's projection is WRITTEN to — `custom`, for every kind.

    Takes `record_type` anyway, and ignores it, because the pairing is the thing a
    reader needs to see: `recordType` and the descriptor member are INDEPENDENT on
    this service (measured — recordType=MCP with descriptors.custom is accepted and
    round-trips), so the kind stays visible in `recordType` while the projection
    rides under the member that does not content-validate.
    """
    return PROJECTION_MEMBER


def native_member_for(record_type: str) -> str:
    """The member a GENUINE native document for `record_type` would go under.

    Not used by the projection paths. It is what `_build_descriptors` would target
    once the operators compose real MCP server documents / A2A AgentCards, and it
    is the reason those member names are still written down.
    """
    return NATIVE_MEMBER_BY_RECORD_TYPE.get(record_type, PROJECTION_MEMBER)


def _descriptor_payload(member: str, data: str) -> dict:
    """The descriptor body for `member`.

    `custom` is `{data}`; the native kinds add `dataSchemaVersion` so a consumer
    can tell what `data` holds without guessing. Sending `dataSchemaVersion` to
    `custom` is a ParamValidationError, which is why this is a lookup and not an
    unconditional dict.
    """
    payload = {"data": data}
    if member in _MEMBERS_WITH_SCHEMA_VERSION:
        payload["dataSchemaVersion"] = DESCRIPTOR_SCHEMA_VERSION
    return payload


def _build_descriptors(asset_kind: str, data: str) -> dict:
    """`descriptors` for CreateRegistryRecord.

    One descriptor per record. The legacy service enforced that explicitly
    ("<KIND> descriptor type can't have other descriptors", live 2026-09-04);
    the standalone service's union shape makes it the natural form anyway, and
    skills already travel inside the TMF639 projection.
    """
    member = _descriptor_member_for(_record_type_for(asset_kind))
    return {member: _descriptor_payload(member, data)}


def _descriptor_payload_for_update(member: str, data: str) -> dict:
    """The descriptor body for UpdateRegistryRecord, leaf-wrapped.

    THREE levels of `optionalValue`, not two — the level the legacy service did
    not have. Each LEAF field is itself an `Updated<Field>` structure carrying a
    single `optionalValue`, so `data` is `{"optionalValue": "<json>"}` and not the
    bare string:

        descriptors
          └ optionalValue
              └ <member>
                  └ optionalValue
                      └ data
                          └ optionalValue: "<json string>"

    Read off `UpdatedDescriptorData` in the service model. A bare string here is a
    `ParamValidationError` ("Invalid type for parameter …data, type: str, valid
    types: dict") — caught by the contract test, which is exactly the class of
    mistake that would otherwise have shipped and failed on the first live pause.
    """
    payload: dict = {"data": {"optionalValue": data}}
    if member in _MEMBERS_WITH_SCHEMA_VERSION:
        payload["dataSchemaVersion"] = {"optionalValue": DESCRIPTOR_SCHEMA_VERSION}
    return payload


def _build_descriptors_for_update(asset_kind: str, data: str) -> dict:
    """`descriptors` for UpdateRegistryRecord.

    The wrapper means "patch this" at every level: omit it to leave unchanged,
    supply an empty object to remove, supply `optionalValue` to set. This module
    only ever sets.
    """
    member = _descriptor_member_for(_record_type_for(asset_kind))
    return {
        "optionalValue": {
            member: {"optionalValue": _descriptor_payload_for_update(member, data)}
        }
    }


def _extract_inline_content(existing: dict) -> str:
    """Read the JSON projection off an existing record.

    Tolerant of the standalone `data` shape AND every legacy shape, because a
    long-lived registry holds records written before the relocation:

      standalone: <member>.data
      legacy:     custom.inlineContent
                  a2a.agentCard.inlineContent
                  agentSkills.{skillMd,skillDefinition}.inlineContent

    Returns "{}" when nothing is populated, matching the prior behaviour of
    defaulting to an empty dict rather than raising — a malformed descriptor must
    not block a pause.
    """
    descriptors = (existing or {}).get("descriptors") or {}
    for member in _DESCRIPTOR_READ_ORDER:
        block = descriptors.get(member)
        if not block:
            continue
        if block.get("data"):
            return block["data"]
        if block.get("inlineContent"):  # legacy flat shape
            return block["inlineContent"]
        for nested_key in ("agentCard", "skillMd", "skillDefinition"):  # legacy nested
            nested = block.get(nested_key)
            if nested and (nested.get("data") or nested.get("inlineContent")):
                return nested.get("data") or nested["inlineContent"]
    return "{}"


def _descriptor_member_in_use(existing: dict) -> str:
    """Which descriptor member an existing record's content is stored under.

    Used by annotate(), which must write back to the member the record ALREADY
    uses rather than the one its asset kind would imply — otherwise a
    pre-relocation record stored under `custom` gains a second, contradictory
    descriptor under `mcpServer`. Defaults to "custom" only when nothing is
    populated.
    """
    descriptors = (existing or {}).get("descriptors") or {}
    for member in _DESCRIPTOR_READ_ORDER:
        block = descriptors.get(member)
        if block and (block.get("data") or block.get("inlineContent")
                      or any(block.get(k) for k in ("agentCard", "skillMd", "skillDefinition"))):
            return member
    return "custom"


def _unused_version(base: str, taken: set[str]) -> str:
    """`base` if free, else `base.N` for the smallest N not in `taken`.

    The CR's observedGeneration is the version of record; a re-created CR
    starts again at generation 1 while its predecessor's tombstone holds "1",
    so the new incarnation gets "1.2", "1.3", ... Deterministic, so two
    reconciles pick the same answer.
    """
    if base not in taken:
        return base
    n = 2
    while f"{base}.{n}" in taken:
        n += 1
    return f"{base}.{n}"


def _id_from_arn(arn: str, kind: str) -> str:
    """Extract a registry or record id from its ARN.

    Needed because neither `CreateRegistry` nor `CreateRegistryRecord` returns an
    id — both respond with the ARN only (true on the legacy service too, where
    `_ensure_registry` read `resp["registryId"]` and would have raised KeyError
    the first time a registry actually had to be created; it never fired because
    the live registries already existed).

    ARN shapes, from the service model's own patterns:
      registry  arn:aws:agent-registry:<region>:<account>:registry/<12-16 alnum>
      record    …:registry/<12-16 alnum>/record/<12 alnum>
    """
    if not arn:
        return ""
    if kind == "record":
        return arn.rsplit("/record/", 1)[-1] if "/record/" in arn else arn.rsplit("/", 1)[-1]
    tail = arn.split(":registry/", 1)[-1] if ":registry/" in arn else arn
    return tail.split("/", 1)[0]


#: `UpdateRegistryRecordStatusRequest.statusReason` is capped at 255 characters by
#: the service model. Truncating here rather than letting AWS refuse the call
#: keeps an over-long CR uid from blocking an approval.
STATUS_REASON_MAX = 255

#: `RegistryRecordStatus`, verbatim from the service model. Used to decide whether
#: a status a response hands back is real — reporting an unrecognised value as the
#: record's state would be the a design note truthfulness failure in reverse.
RECORD_STATUSES = frozenset({
    "DRAFT", "PENDING_APPROVAL", "APPROVED", "REJECTED", "DEPRECATED",
    "CREATING", "UPDATING", "CREATE_FAILED", "UPDATE_FAILED",
})

#: A registry answers record calls only when READY. CreateRegistry returns while
#: it is CREATING (about a minute on a fresh account, event 8acc8261, 2026-09-27),
#: so `_ensure_registry` polls GetRegistry until READY: at most
#: REGISTRY_READY_MAX_POLLS calls, REGISTRY_READY_POLL_S apart (5 minutes).
REGISTRY_READY_POLL_S = 5.0
REGISTRY_READY_MAX_POLLS = 60
_REGISTRY_TRANSITIONAL = frozenset({"CREATING", "UPDATING"})


def approval_status_reason(approval: dict) -> str:
    """The audit line written into the record's own `statusReason`.

    Deliberately human-readable and greppable: an operator reading
    `aws agent-registry-control get-registry-record` sees which approval id, which
    CR uid and which generation produced this state, without joining to anything.
    """
    text = (
        f"MoDaaS approval {approval.get('approvalId', '')} · "
        f"CR uid {approval.get('crUid') or 'unknown'} · "
        f"generation {approval.get('crGeneration', '')} · "
        f"recordVersion {approval.get('recordVersion', '')}"
    )
    return text[:STATUS_REASON_MAX]


def mint_approval_id() -> str:
    """A fresh, unique identifier for one approval projection.

    The owner's audit ask: every approval written to the Registry must be
    individually identifiable, so two approvals of the same alias are
    distinguishable and a re-approval after a spec change is not mistaken for the
    first one. uuid4 hex — not derived from the alias or the generation, because
    a derived id collides exactly when the audit most needs it not to.
    """
    return uuid.uuid4().hex



class _TTLCache:
    """LRU cache with per-entry TTL and max-entries eviction."""

    def __init__(self, ttl: int = CACHE_TTL_SECONDS, max_entries: int = CACHE_MAX_ENTRIES):
        self._ttl = ttl
        self._max = max_entries
        self._store: OrderedDict[str, tuple[str, float]] = OrderedDict()

    def get(self, key: str) -> str | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, ts = entry
        if _time.monotonic() - ts > self._ttl:
            del self._store[key]
            return None
        self._store.move_to_end(key)
        return value

    def put(self, key: str, value: str) -> None:
        if key in self._store:
            self._store.move_to_end(key)
        self._store[key] = (value, _time.monotonic())
        while len(self._store) > self._max:
            self._store.popitem(last=False)

def _current_registry_name() -> str:
    """Read MODAAS_REGISTRY_NAME from env at call time, fall back to default.

    Legacy fallback only. a design note dispatch passes the name explicitly via
    get_client(registry_name=...); AgentCoreBacking no longer writes this
    variable (it was a process-global write in a multi-asset reconcile loop —
    see operators/shared/backings/agentcore.py).
    """
    return os.environ.get("MODAAS_REGISTRY_NAME", DEFAULT_REGISTRY_NAME)


def _aws_clients():
    """The a design note capability factory, under whichever spelling resolves.

    Canonical first: when both spellings are importable (any in-tree run) they
    are DISTINCT module objects with distinct client caches. Preferring the
    canonical one keeps a single binding. See
    operators/shared/tests/conftest.py for the same hazard and remedy on
    rate_resolver.
    """
    try:
        from operators.shared import aws_clients  # noqa: PLC0415
    except ImportError:  # pragma: no cover - pod snapshot path
        from shared import aws_clients  # noqa: PLC0415
    return aws_clients


def _assumed_role_control_client(role_arn: str, region: str):
    """Control-plane client signing as `role_arn` (a design note cross-account).

    Goes through the a design note capability factory, which resolves
    `registry.control` to its current botocore service and delegates the
    credential half to operators/shared/sts_credentials.py (which caches both
    the credentials and the client and rebuilds only at credential expiry).

    No fall-back to the operator's own identity on failure. A cross-account
    Registry served with the operator's IRSA identity is a wrong-catalog write,
    not a degraded one, so AssumeRoleFailed propagates to the caller.
    """
    return _aws_clients().client(
        REGISTRY_CAPABILITY, region, role_arn=role_arn
    )



class RegistryClient(Protocol):
    def put_record(self, record: dict) -> dict: ...
    def search(self, query: str, filters: dict) -> list[dict]: ...
    def deprecate(self, name: str) -> None: ...

    def annotate(self, name: str, metadata: dict) -> None:
        """Merge metadata into an existing record WITHOUT changing its lifecycle state.

        Needed because DEPRECATED is terminal in the AgentCore Registry (F71), so a reversible
        condition such as "paused" cannot be expressed as a status transition. It is expressed as
        record metadata instead, leaving the record a valid catalog entry that can be un-paused.
        """
        ...


# ──────────────────────────── Stub (offline / CI) ───────────────────────────
class _StubRegistry:
    def __init__(self) -> None:
        self._records: list[dict] = []

    def put_record(self, record: dict) -> dict:
        record.setdefault("state", "APPROVED")
        self._records = [r for r in self._records if r["name"] != record["name"]]
        self._records.append(record)
        return record

    def search(self, query: str, filters: dict) -> list[dict]:
        def match(r: dict) -> bool:
            if r.get("state") != "APPROVED":
                return False
            if filters.get("recordType") and r.get("recordType") != filters["recordType"]:
                return False
            need = set(filters.get("features", []))
            have = set(r.get("metadata", {}).get("capabilities", {}).get("features", []))
            if need and not need.issubset(have):
                return False
            if query:
                hay = f"{r.get('name','')} {r.get('description','')} {r.get('metadata',{})}".lower()
                if query.lower() not in hay:
                    return False
            return True
        return [r for r in self._records if match(r)]

    def deprecate(self, name: str) -> None:
        for r in self._records:
            if r.get("name") == name:
                r["state"] = "DEPRECATED"

    def annotate(self, name: str, metadata: dict) -> None:
        for r in self._records:
            if r.get("name") == name:
                r.setdefault("metadata", {}).update(metadata)


# ──────────────────────────── Real (AWS Agent Registry) ─────────────────────
class _AwsRegistry:
    """Real AWS Agent Registry.

    Control plane: the `registry.control` capability (create/update records).
    Discovery:     the `registry.discovery` capability (search). Its response
                   summaries carry `descriptors`, which the control plane's do
                   NOT on the standalone service — so search prefers it and falls
                   back to list+get. a design note records both capabilities and the
                   service each resolves to.
    """
    def __init__(
        self,
        region: str,
        registry_name: str | None = None,
        role_arn: str | None = None,
    ) -> None:
        self._region = region
        # Explicit registry name beats the MODAAS_REGISTRY_NAME env var. The
        # env path predates a design note dispatch: AgentCoreBacking wrote the variable
        # immediately before each call, so in a process reconciling many assets
        # the name in force was whichever call set it last and a record could
        # land in another asset's registry. A name carried ON THE CLIENT cannot
        # be re-pointed by an unrelated reconcile. env stays supported for
        # legacy callers that pass no name.
        self._registry_name = registry_name
        # a design note Registry.spec.parameters.roleArn — cross-account Registry
        # access. Empty string is "not configured", not "assume the empty role".
        self._role_arn = role_arn or None
        self._control_static = None
        self._discovery_static = None
        if not self._role_arn:
            # a design note: by capability, not by service name. The factory caches per
            # (capability, region), so the connection-pool-per-reconcile leak
            # this line used to guard against is still guarded against.
            self._control = _aws_clients().client(REGISTRY_CAPABILITY, region)
            self._discovery = _aws_clients().client(DISCOVERY_CAPABILITY, region)
        # Per-registry-name cache with TTL + LRU eviction (fix #3).
        # Prevents unbounded growth and ensures renames are picked up
        # within CACHE_TTL_SECONDS without requiring operator restart.
        self._registry_id_by_name = _TTLCache()

    # `_control` is a property so the assumed-role path can refresh expired
    # credentials without every call site (15 of them) learning about roles, and
    # so existing tests that build the object via __new__ and assign
    # `reg._control = <mock>` keep working unchanged (the setter stores it).
    @property
    def _control(self):
        role_arn = getattr(self, "_role_arn", None)
        if role_arn:
            return _assumed_role_control_client(role_arn, self._region)
        return getattr(self, "_control_static", None)

    @_control.setter
    def _control(self, value) -> None:
        self._control_static = value

    # Same property/setter shape as `_control`, for the same two reasons: the
    # assumed-role path refreshes on access, and a test can assign a double.
    #
    # Deliberately NOT lazily constructed on first use. A client built on demand
    # inside search() would make every offline unit test that forgot to inject one
    # reach for real AWS credentials — measured at ~2.3s and a live network
    # attempt before this was made eager. Built in __init__ (where `_control` is)
    # or supplied by a test; an object built via `__new__` has no discovery client
    # and search() takes the documented control-plane fallback.
    @property
    def _discovery(self):
        role_arn = getattr(self, "_role_arn", None)
        if role_arn:
            return _aws_clients().client(
                DISCOVERY_CAPABILITY, self._region, role_arn=role_arn
            )
        return getattr(self, "_discovery_static", None)

    @_discovery.setter
    def _discovery(self, value) -> None:
        self._discovery_static = value

    def _ensure_registry(self) -> str:
        """Return registry ID for this client's registry name.

        Name resolution: explicit `registry_name` (a design note dispatch, passed from
        Registry.spec.parameters) beats MODAAS_REGISTRY_NAME beats
        DEFAULT_REGISTRY_NAME.

        CRITICAL (Batch L follow-up, 2026-05-06): this method must re-resolve
        per call when the registry name changes. Previously it cached the
        first-resolved id in self._registry_id, which broke multi-registry
        dispatch — records for spec.registryRef.name=eaco-agents were written
        to modaas-canvas-registry because the client cached the default
        registry id on first call.

        Now keyed by (current registry name) -> id with per-name cache so
        repeat calls for the same registry don't re-list.
        """
        target_name = getattr(self, "_registry_name", None) or _current_registry_name()
        cached = self._registry_id_by_name.get(target_name)
        if cached:
            return cached

        rid = os.environ.get(REGISTRY_ENV)
        if rid:
            # Explicit override — honor it, but also record which name it's for
            self._registry_id_by_name.put(target_name, rid)
            return rid

        # Look for an existing one named target_name
        for page in self._control.get_paginator("list_registries").paginate():
            for r in page.get("registries", []):
                if r.get("name") == target_name:
                    self._wait_registry_ready(r["registryId"], r.get("status"))
                    self._registry_id_by_name.put(target_name, r["registryId"])
                    return r["registryId"]

        # Create. Two payload members moved on the standalone service:
        #   authorizerType                     -> discoveryConfiguration.authorizerType
        #   approvalConfiguration.autoApproval -> approvalConfiguration.autoApprovalRules
        # (a list of an enum whose only member is APPROVE_ALL). The old spellings
        # are ParamValidationErrors here.
        resp = self._control.create_registry(
            name=target_name,
            description="MoDaaS Canvas model + agent + tool catalog",
            discoveryConfiguration={"authorizerType": "AWS_IAM"},
            approvalConfiguration={"autoApprovalRules": ["APPROVE_ALL"]},
        )
        # CreateRegistry responds with registryArn ONLY — no registryId. Reading
        # resp["registryId"] here was a latent KeyError that never fired because
        # the live registries already existed, so the create branch was dead.
        registry_id = resp.get("registryId") or _id_from_arn(
            resp.get("registryArn", ""), "registry"
        )
        # Bug #17 — capture aws_request_id for CloudTrail correlation
        log_aws_response(resp, "create_registry", resource=registry_id,
                         asset=target_name)
        if not registry_id:
            raise RuntimeError(
                "create_registry returned neither registryId nor a parseable "
                f"registryArn: {resp!r}"
            )
        self._wait_registry_ready(registry_id)
        self._registry_id_by_name.put(target_name, registry_id)
        return registry_id

    def _wait_registry_ready(self, registry_id: str, status: str | None = None) -> None:
        """Return once the registry is READY; raise if it failed or never gets there.

        CreateRegistry returns while the registry is still CREATING, and record
        calls against it fail with `ConflictException: Registry is not in READY
        state` until it is READY -- about a minute on a fresh account (event
        8acc8261, 2026-09-27, where the first approved ModelConfig went to Failed
        for good). `status` is the one a ListRegistries summary already carries,
        so a READY registry costs no extra call. Bounded: REGISTRY_READY_MAX_POLLS
        GetRegistry calls, REGISTRY_READY_POLL_S apart.
        """
        reason = None
        for attempt in range(REGISTRY_READY_MAX_POLLS + 1):
            if status == "READY":
                return
            if status is not None and status not in _REGISTRY_TRANSITIONAL:
                raise RuntimeError(
                    f"registry {registry_id} is {status}, not READY"
                    + (f": {reason}" if reason else ""))
            if attempt == REGISTRY_READY_MAX_POLLS:
                break
            if attempt:
                _time.sleep(REGISTRY_READY_POLL_S)
            resp = self._control.get_registry(registryId=registry_id)
            status = resp.get("status") if isinstance(resp, dict) else None
            reason = resp.get("statusReason") if isinstance(resp, dict) else None
            if not isinstance(status, str):
                # A GetRegistry answer with no status says nothing about
                # readiness. Proceed as before this wait existed instead of
                # polling for five minutes on a shape we cannot read.
                import logging  # noqa: PLC0415
                logging.getLogger("ModelOperator").warning(
                    f"registry {registry_id}: GetRegistry returned no status; "
                    f"not waiting for READY")
                return
        raise RuntimeError(
            f"registry {registry_id} still {status} after {REGISTRY_READY_MAX_POLLS} "
            f"polls {REGISTRY_READY_POLL_S:.0f}s apart; not READY")

    def put_record(self, record: dict) -> dict:
        """Create or update a registry record under its asset-kind-native
        descriptor (CUSTOM/custom for models, MCP/mcpServer for tools,
        AGENT/a2aAgentCard for agents — see `_build_descriptors`).

        Returns a normalized dict matching the stub shape (name, recordType,
        state, metadata) plus:
          recordId      — the identifier the SERVICE assigned (12 alphanumerics),
                          not a locally-derived name. This is what makes an
                          approval individually traceable.
          approvalId    — the minted id for THIS approval projection
          statusReason  — when the service supplied one (T8), so callers can put
                          it on a CR condition without a second round trip
        """
        registry_id = self._ensure_registry()
        # a design note: idempotency + uniqueness. _find_record returns the canonical
        # (non-DEPRECATED, most-recent) match; _deprecate_stragglers cleans up
        # any other non-DEPRECATED records sharing the same alias so each
        # reconcile drives toward exactly one APPROVED per alias.
        existing = self._find_record(registry_id, record["name"])
        self._deprecate_stragglers(registry_id, record["name"], keep=existing)
        asset_kind = record.get("recordType", "model")
        # Kind recoverability (2026-09-05, C-31 follow-through): the service's
        # own recordType no longer round-trips MoDaaS's kind for models (CUSTOM
        # is shared with anything else generic), so the kind is persisted inside
        # the projection as "_kind". Non-invasive: one extra key in the JSON.
        _meta = dict(record.get("metadata", {}) or {})
        _meta.setdefault("_kind", asset_kind)
        # T8: provenance-anchor the record to the CR's observedGeneration.
        # record["version"] is already populated by AssetOperator as
        # str(status.get("observedGeneration", 1)) — reused as-is here, not
        # re-derived, so there is a single source of truth for the value.
        record_version = record.get("version", "1.0")
        # Audit identity (a design note PR 2, owner's "unique identifier tracking" ask).
        # Every write carries a fresh approvalId plus the CR's uid and generation,
        # so two approvals of the same alias are distinguishable and a
        # re-approval after a spec change is not mistaken for the first one.
        approval = {
            "approvalId": mint_approval_id(),
            "crUid": record.get("crUid", ""),
            "crGeneration": str(record.get("generation", record_version)),
            "recordVersion": record_version,
        }
        _meta["_approval"] = approval
        desc_json = json.dumps(_meta)

        if existing and existing.get("status") != "DEPRECATED":
            # UpdateRegistryRecord double-wraps in 'optionalValue' at multiple levels
            # (AWS API pattern to distinguish "change this" from "leave unchanged").
            update_resp = self._control.update_registry_record(
                registryId=registry_id, recordId=existing["recordId"],
                recordType=_record_type_for(asset_kind),
                descriptors=_build_descriptors_for_update(asset_kind, desc_json),
                recordVersion=record_version,
            )
            log_aws_response(update_resp, "update_registry_record",
                             resource=existing["recordId"], asset=record["name"])
            record_id = existing["recordId"]
        else:
            # A deleted CR leaves a DEPRECATED tombstone under the same name
            # (DEPRECATED is terminal; vended accounts also deny
            # DeleteRegistryRecord), and the service refuses a second record
            # with the same name AND version. The reviewer's lab and event
            # f9457a26 both hit it: delete + re-apply of a ToolConfig ended in
            # phase=Failed / RegistryFailed "A record with name ... and version
            # '1' already exists". Mint the new incarnation under a version no
            # tombstone holds, and if the service still objects, bump again.
            taken = self._versions_taken(registry_id, record["name"])
            record_version = _unused_version(record_version, taken)
            approval["recordVersion"] = record_version
            _meta["_approval"] = approval
            desc_json = json.dumps(_meta)
            conflict_exc = getattr(self._control.exceptions, "ConflictException", None)
            for attempt in range(6):
                try:
                    resp = self._control.create_registry_record(
                        registryId=registry_id,
                        name=record["name"],
                        description=record.get("description", ""),
                        # `descriptorType` is gone; `recordType` is required and its enum
                        # is different (AGENT/SKILL, not A2A/AGENT_SKILLS).
                        recordType=_record_type_for(asset_kind),
                        descriptors=_build_descriptors(asset_kind, desc_json),
                        recordVersion=record_version,
                    )
                    break
                except Exception as e:  # noqa: BLE001 -- only ConflictException is retried
                    if conflict_exc is None or not isinstance(e, conflict_exc) or attempt == 5:
                        raise
                    taken.add(record_version)
                    record_version = _unused_version(record_version, taken)
                    approval["recordVersion"] = record_version
                    _meta["_approval"] = approval
                    desc_json = json.dumps(_meta)
            # CreateRegistryRecord responds with recordArn + status; no recordId.
            # Taken from the create response rather than a follow-up list, to
            # avoid the race the previous comment here warned about.
            record_id = resp.get("recordId") or _id_from_arn(
                resp.get("recordArn", ""), "record"
            )
            log_aws_response(resp, "create_registry_record",
                             resource=record_id, asset=record["name"])

        # Auto-approval still requires explicit submit (a design note bonus finding).
        # Use recordId from create response, not a subsequent list call, to avoid race.
        # Also: AWS creates the record in CREATING state first; wait briefly for DRAFT.
        status_reason = None
        submit_ok = False
        if record_id:
            import time
            for _ in range(8):  # up to ~8s
                try:
                    cur = self._control.get_registry_record(
                        registryId=registry_id, recordId=record_id
                    )
                    # T8: capture statusReason from whichever poll iteration
                    # last succeeded, so callers get the freshest available
                    # reason without an extra round trip.
                    status_reason = cur.get("statusReason") or status_reason
                    if cur.get("status") in ("DRAFT", "APPROVED", "PENDING_APPROVAL"):
                        break
                    time.sleep(1)
                except Exception:
                    time.sleep(1)
            try:
                submit_resp = self._control.submit_registry_record_for_approval(
                    registryId=registry_id, recordId=record_id
                )
                log_aws_response(submit_resp, "submit_registry_record_for_approval",
                                 resource=record_id, asset=record["name"])
                submit_ok = True
            except self._control.exceptions.ValidationException:
                submit_ok = True  # Already submitted/approved
            except Exception as e:
                import logging
                logging.getLogger("ModelOperator").warning(
                    f"Submit for approval failed for {record['name']}: {e}"
                )
        # Truthfulness (2026-09-05, a design note class): report the REAL final
        # record status. The previous hardcoded "APPROVED" masked a live
        # AccessDenied on SubmitRegistryRecordForApproval — CRs claimed
        # registered-approved while every record sat DRAFT.
        final_status = None
        submit_failed = False
        if record_id:
            try:
                final = self._control.get_registry_record(
                    registryId=registry_id, recordId=record_id
                )
                final_status = final.get("status")
                status_reason = final.get("statusReason") or status_reason
            except Exception:
                pass
        # An approval the operator is projecting from the CR needs to reach the
        # record even when the registry does not auto-approve. UpdateRegistryRecordStatus
        # requires `statusReason` on the standalone service, and that requirement
        # is the audit trail: the reason carries the approval id, the CR uid and
        # the generation, so the record itself says which CR revision approved it.
        #
        # Gated on `submit_ok`. If SubmitRegistryRecordForApproval was REFUSED
        # (the live AccessDenied that a design note's truthfulness rule was written for),
        # forcing the status afterwards would be the operator trying to walk around
        # a permissions boundary — and would report APPROVED for a record the
        # registry never accepted. A refused submit stays refused.
        if record_id and submit_ok and final_status in ("DRAFT", "PENDING_APPROVAL"):
            final_status, status_reason = self._project_approval(
                registry_id, record_id, record["name"], approval, final_status, status_reason
            )
        if final_status not in ("APPROVED",):
            submit_failed = True
            import logging
            logging.getLogger("ModelOperator").warning(
                f"Registry record {record['name']} finished put_record in "
                f"status={final_status!r} (not APPROVED) — surfacing real state."
            )
        result = {
            **record,
            "state": final_status or "UNKNOWN",
            "recordId": record_id,
            "approvalId": approval["approvalId"],
        }
        if submit_failed:
            result["submitFailed"] = True
        if status_reason:
            result["statusReason"] = status_reason
        return result

    def _project_approval(
        self, registry_id: str, record_id: str, name: str,
        approval: dict, current_status: str | None, status_reason: str | None,
    ) -> tuple[str | None, str | None]:
        """Drive a submitted record to APPROVED, carrying the audit identity.

        Best-effort by design: a registry whose approval policy requires a human
        reviewer will refuse this, and that refusal is correct — the record stays
        PENDING_APPROVAL and put_record reports the real state (the a design note
        truthfulness rule). What must never happen is an approval reaching the
        registry with no way to tell WHICH CR revision authorised it, which is
        what an empty or generic statusReason would leave behind.
        """
        import logging

        try:
            resp = self._control.update_registry_record_status(
                registryId=registry_id,
                recordId=record_id,
                status="APPROVED",
                statusReason=approval_status_reason(approval),
            )
            log_aws_response(resp, "update_registry_record_status",
                             resource=record_id, asset=name,
                             extra={"new_status": "APPROVED",
                                    "approval_id": approval["approvalId"]})
            # Only a status the service's own enum recognises counts as evidence.
            # Anything else (a shape change, or a double that answers every
            # attribute) is not an approval and must not be reported as one.
            observed = resp.get("status")
            return (
                observed if observed in RECORD_STATUSES else current_status,
                resp.get("statusReason") or status_reason,
            )
        except Exception as e:  # noqa: BLE001 — a refused approval is real state
            logging.getLogger("ModelOperator").info(
                "approval projection for %s left the record at %s (%s: %s)",
                name, current_status, type(e).__name__, e,
            )
            return current_status, status_reason

    def _candidate_records(self, registry_id: str) -> list[dict]:
        """Records with their descriptors, for `search`.

        Two paths, and the ordering matters:

        1. `agent-registry.ListDiscoverableRegistryRecords`, paginated — its
           summaries carry `descriptors` (required in the response shape), so
           the walk returns both the record list AND the projections. Not the
           SEARCH operation: that is top-k semantic (maxResults <= 20, no
           token) and truncates silently.
        2. `list_registry_records` + `get_registry_record` per candidate —
           the fallback. Needed because the control plane's summaries carry NO
           descriptors at all on the standalone service, so the previous
           list-only implementation would have read every projection as empty and
           silently returned metadata-free results.

        The fallback is not dead weight: discovery only serves records in a
        registry configured for it, so an adopted registry without a
        discoveryConfiguration reaches path 2 — as does any caller holding a
        client with no discovery half (see the `_discovery` property).
        """
        discovery = self._discovery
        if discovery is not None:
            try:
                records: list[dict] = []
                token = None
                while True:
                    kwargs = {"registryId": registry_id, "maxResults": _LIST_PAGE_SIZE}
                    if token:
                        kwargs["nextToken"] = token
                    resp = discovery.list_discoverable_registry_records(**kwargs)
                    records.extend(resp.get("registryRecords") or [])
                    token = resp.get("nextToken")
                    if not token:
                        break
                if records:
                    return records
            except Exception as e:  # noqa: BLE001 — discovery is optional per registry
                import logging
                logging.getLogger("ModelOperator").info(
                    "discovery list unavailable for registry %s (%s: %s) — "
                    "falling back to list+get on the control plane",
                    registry_id, type(e).__name__, e,
                )

        hydrated: list[dict] = []
        for page in self._control.get_paginator("list_registry_records").paginate(
            registryId=registry_id
        ):
            for summary in page.get("registryRecords", []):
                if summary.get("status") != "APPROVED":
                    continue
                try:
                    full = self._control.get_registry_record(
                        registryId=registry_id, recordId=summary["recordId"]
                    )
                except Exception:  # noqa: BLE001 — one unreadable record is not fatal
                    continue
                hydrated.append({**summary, **full})
        return hydrated

    def search(self, query: str, filters: dict) -> list[dict]:
        registry_id = self._ensure_registry()
        results = []
        for r in self._candidate_records(registry_id):
            if r.get("status") != "APPROVED":
                continue
            # Tolerant of both the standalone `data` shape and every legacy
            # shape — a long-lived registry holds records from before the move.
            meta = {}
            try:
                meta = json.loads(_extract_inline_content(r))
            except (json.JSONDecodeError, TypeError, KeyError):
                pass
            # Kind filter. `_kind` inside the projection is authoritative because
            # a model record's recordType (CUSTOM) is shared with anything else
            # generic. Records written before `_kind` existed fall back to the
            # service's own recordType — and to the legacy `descriptorType`,
            # which pre-relocation records still carry.
            rt = filters.get("recordType")
            if rt:
                marked = meta.get("_kind")
                if marked is not None:
                    if marked != rt:
                        continue
                else:
                    observed = r.get("recordType") or r.get("descriptorType")
                    if observed != _record_type_for(rt):
                        continue
            # Feature subset filter
            need = set(filters.get("features", []))
            have = set(meta.get("capabilities", {}).get("features", []))
            if need and not need.issubset(have):
                continue
            if query and query.lower() not in json.dumps(meta).lower() + r.get("name", "").lower():
                continue
            results.append({
                "name": r["name"],
                "recordType": r.get("recordType") or r.get("descriptorType"),
                "state": r["status"],
                "metadata": meta,
            })
        return results

    def deprecate(self, name: str) -> None:
        """One-way transition to DEPRECATED (per AWS Agent Registry docs, terminal)."""
        registry_id = self._ensure_registry()
        existing = self._find_record(registry_id, name)
        if not existing:
            return
        if existing.get("status") == "DEPRECATED":
            return  # Already terminal — no-op
        deprecate_resp = self._control.update_registry_record_status(
            registryId=registry_id, recordId=existing["recordId"],
            status="DEPRECATED",
            statusReason="Model retired per governance.retirementDate",
        )
        log_aws_response(deprecate_resp, "update_registry_record_status",
                         resource=existing["recordId"], asset=name,
                         extra={"new_status": "DEPRECATED"})

    def annotate(self, name: str, metadata: dict) -> None:
        """Merge metadata into the record's inline descriptor, preserving lifecycle state.

        DEPRECATED is terminal (F71), so a reversible "paused" cannot be a status transition. This
        rewrites the descriptor JSON with the extra keys merged in and leaves status alone, so the
        record stays a valid catalog entry and no duplicate has to be minted on unpause.

        annotate is not told the asset's kind, so it writes back through whichever
        descriptor member the EXISTING record already carries content under (via
        `_descriptor_member_in_use`) rather than the one the kind would imply.
        That keeps a pre-relocation record stored under `custom` from gaining a
        second, contradictory descriptor under `mcpServer`.

        a design note PR 2 — it now re-reads the record with GetRegistryRecord first.
        `_find_record` returns a LIST summary, and on the standalone service
        `ListRegistryRecords` summaries carry no `descriptors` at all. Merging into
        that summary would have produced `{paused: true}` and nothing else, i.e.
        silently erased the TMF639 projection on every pause. This is a
        read-modify-write and it has to read the thing it is modifying.
        """
        registry_id = self._ensure_registry()
        existing = self._find_record(registry_id, name)
        if not existing:
            import logging
            logging.getLogger("ModelOperator").info(
                "annotate: no record named %s — nothing to mark", name
            )
            return
        record_id = existing["recordId"]
        full = existing
        try:
            full = self._control.get_registry_record(
                registryId=registry_id, recordId=record_id
            )
        except Exception as e:  # noqa: BLE001
            import logging
            logging.getLogger("ModelOperator").warning(
                "annotate: could not re-read %s (%s: %s) — refusing to write a "
                "descriptor built from a list summary, which would erase the "
                "projection", name, type(e).__name__, e,
            )
            return
        current: dict = {}
        try:
            raw = _extract_inline_content(full)
            if raw:
                current = json.loads(raw)
        except Exception:  # noqa: BLE001 - a malformed descriptor must not block the pause
            current = {}
        current.update(metadata)
        member = _descriptor_member_in_use(full)
        resp = self._control.update_registry_record(
            registryId=registry_id, recordId=record_id,
            descriptors={"optionalValue": {member: {"optionalValue":
                _descriptor_payload_for_update(member, json.dumps(current))}}},
        )
        log_aws_response(resp, "update_registry_record", resource=record_id, asset=name)

    def _versions_taken(self, registry_id: str, name: str) -> set[str]:
        """Every recordVersion already used under `name`, tombstones included."""
        taken: set[str] = set()
        try:
            for page in self._control.get_paginator("list_registry_records").paginate(registryId=registry_id):
                for r in page.get("registryRecords", []):
                    if r.get("name") == name and r.get("recordVersion"):
                        taken.add(str(r["recordVersion"]))
        except Exception:  # noqa: BLE001 -- listing is best-effort; the create retry covers the rest
            pass
        return taken

    def _find_record(self, registry_id: str, name: str) -> dict | None:
        """Return the canonical record for `name`.

        a design note: prefer a non-DEPRECATED match. AWS does not guarantee status
        order in pagination; the prior implementation returned the first
        match across pages, which let put_record fall into the create branch
        whenever a DEPRECATED record happened to surface first — minting
        unbounded duplicate APPROVED records (witness: 20 APPROVED for
        `agentcoregateway_test-tool`). Among non-DEPRECATED candidates,
        prefer the most-recently-created so we converge on a single
        canonical record. Returns None only when no records match the name
        OR all matches are DEPRECATED (and we want to mint a fresh one).
        """
        candidates: list[dict] = []
        for page in self._control.get_paginator("list_registry_records").paginate(registryId=registry_id):
            for r in page.get("registryRecords", []):
                if r.get("name") == name:
                    candidates.append(r)
        if not candidates:
            return None
        live = [c for c in candidates if c.get("status") != "DEPRECATED"]
        if live:
            live.sort(key=lambda c: c.get("createdAt") or "", reverse=True)
            return live[0]
        return None  # all DEPRECATED — caller should mint a new APPROVED

    def _deprecate_stragglers(
        self, registry_id: str, name: str, keep: dict | None
    ) -> None:
        """a design note self-heal: remove any duplicate records sharing `name` other than `keep`.

        Duplicates are DELETED, not deprecated (F71/F70). Deprecating them looked like convergence
        but was not: DEPRECATED is terminal, so each pass left a permanent tombstone and the record
        count only ever grew — one fixture alias reached 17 records, 16 of them tombstones. A
        duplicate is not a retired asset; it is an artifact of a non-idempotent write path and should
        not survive in the catalog at all.

        Also sweeps duplicate DEPRECATED tombstones, otherwise the pile created before this fix would
        never drain and the one-record-per-asset invariant could never be reached.

        Failures here are best-effort — they must not block reconcile. Each cycle re-runs this, so
        transient errors converge.
        """
        if keep is None:
            return
        keep_id = keep.get("recordId")
        for page in self._control.get_paginator("list_registry_records").paginate(registryId=registry_id):
            for r in page.get("registryRecords", []):
                if r.get("name") != name:
                    continue
                if r.get("recordId") == keep_id:
                    continue
                # Found a duplicate — DELETE it. Deprecating would leave a terminal tombstone that
                # can never be cleaned, which is how the 17-record pile accumulated.
                try:
                    self._control.delete_registry_record(
                        registryId=registry_id, recordId=r["recordId"],
                    )
                except Exception as e:
                    import logging
                    logging.getLogger("ModelOperator").warning(
                        f"a design note duplicate cleanup failed for {name} "
                        f"recordId={r.get('recordId')}: {e}"
                    )


# ──────────────────────────── Singleton cache ──────────────────────────────
_client_cache: dict[tuple[str, str, str | None, str | None], RegistryClient] = {}


def _default_region() -> str:
    """Resolve the registry region: MODAAS_REGISTRY_REGION beats AWS_REGION
    beats the legacy us-west-2 constant.

    Live defect 2026-09-05: operators on eks-cluster-modaas (us-east-1) ran
    with the hardcoded us-west-2 default and silently wrote every record to
    the OLD earlier registry in the wrong region. The registry region must
    follow the deployment environment, not a constant.
    """
    import os
    return (
        os.environ.get("MODAAS_REGISTRY_REGION")
        or os.environ.get("AWS_REGION")
        or "us-west-2"
    )


def get_client(
    region: str | None = None,
    *,
    registry_name: str | None = None,
    role_arn: str | None = None,
) -> RegistryClient:
    """Return a cached registry client.

    `region` stays positional for the legacy call shape `get_client(region)`.
    `registry_name` and `role_arn` come from a a design note Registry CR's
    spec.parameters and are part of the cache key — two Registries that differ
    in either must not share a client, or the explicit name buys nothing.
    """
    mode = os.environ.get("MODAAS_REGISTRY_MODE", "real").lower()
    if region is None:
        region = _default_region()
    key = (mode, region, registry_name, role_arn)
    if key not in _client_cache:
        _client_cache[key] = (
            _StubRegistry() if mode == "stub"
            else _AwsRegistry(region, registry_name=registry_name, role_arn=role_arn)
        )
    return _client_cache[key]
