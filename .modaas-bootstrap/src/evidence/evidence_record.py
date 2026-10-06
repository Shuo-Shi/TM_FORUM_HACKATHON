"""One evidence record: the unit of the MoDaaS evidence chain (a design note point 4).

## What this module is for, in one sentence

An auditor must be able to reconstruct **who / what / authorized / result** for
one run, joined by one key, with the *authorized* half attested by the platform
rather than by the party being audited. This module is the shape that makes that
checkable instead of aspirational.

## The two rules that are not conveniences

1. `phase: decision` requires `attested_by == "modaas-authz"`. a design note point 4
   names `modaas-authz` the sole writer of decision records, and the DD's
   acceptance criteria require a reader to reject one written by anything else.
   A contract that could not express the requirement would leave the reader
   nothing to enforce.

2. A non-decision record may NOT carry `decision`, `matched_policy` or
   `policy_version`. Those are the platform's fields. An agent-written `intent`
   record carrying `decision: ALLOW` would launder the exact fact a design note's
   "Options considered" rejects taking from the agent, and a ledger rendering it
   next to the platform's own records would be worse than having no record at
   all. Refused, not dropped: dropping it makes a forgery attempt invisible.

## Why validation returns a list rather than raising

Two callers, two needs. `evidence-service`'s write API wants every problem with
a participant's record in one 400 response (a lab participant fixing one field
at a time per round-trip is the shape the workshop already complains about).
`parse()` wants a hard failure. `validate()` is the list; `parse()` is the raise.

## What is deliberately NOT here

Tamper evidence -- hash chaining, signatures, write-once storage -- is out of
scope by a design note point 9, stated as participant-challenge scope for the event and
the named next step for the platform. `attested_by` records a CLAIM about the
writer; the collector's `k8sattributes` stamp (a design note point 5, "write
integrity") is what makes the claim checkable, and it lives in the pipeline
rather than in the record.
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import re
from enum import Enum
from typing import Any

SCHEMA_VERSION = "modaas.evidence/v1"

# `attested_by` values with a defined meaning. Not a closed enum: a community
# sink or a future attestor (an approver workflow, an OSS/BSS bridge) is a
# legitimate writer, and closing the set would make adding one a contract bump.
# What IS closed is which value may write a decision -- see ATTESTOR_PLATFORM.
ATTESTOR_PLATFORM = "modaas-authz"   # the ONLY writer of phase: decision
ATTESTOR_SELF = "agent"              # the agent's own account of itself
ATTESTOR_APPROVER = "approver"       # a human attestation (a design note / a design note pt 7)

# Sentinel for "this test fixture wants the field omitted". Exported because the
# suite builds records by overriding a template, and `None` is a legal value for
# `matched_policy` (Cedar's "no clause matched") so it cannot double as absence.
_ABSENT = object()

_TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_ZERO_TRACE_ID = "0" * 32
# Canonical dashed form only, matching `tracectx._UUID_RE` in authz-gateway so
# the id this contract accepts is exactly the id that service mints. NOT
# `uuid.UUID()`: that constructor also accepts braces, a `urn:uuid:` prefix and
# the 32-hex undashed form, which the JSON Schema half cannot reproduce with a
# pattern -- and a validator pair that disagrees on what an action id is has no
# join key at all for a non-Python participant.
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
# The three governed-asset CRDs, plus `Evidence`.
#
# `Evidence` is NOT a CRD and names no governed asset: it is the fronted evidence
# service itself (a design note point 5). It has to be expressible because "every read and
# write crosses the authz hook" makes a read of the audit trail a governed action
# in its own right, and a decision record is written for it -- the DD's "reads are
# themselves recorded". Surfaced by the authz-gateway wiring: without this value
# every approver read produced a record the contract refused, so the one control
# that closes the unauthenticated-read gap left no evidence of itself.
_ASSET_KINDS = ("Model", "Tool", "Agent", "Evidence")
_DECISIONS = ("ALLOW", "DENY")


class Phase(str, Enum):
    """The five phases of one governed run (a design note point 5).

    `str` mixin so a value serialises straight into a log attribute and a JSON
    body without a cast, matching `reasons.Reason` in authz-gateway.
    """

    INTENT = "intent"
    INVOCATION = "invocation"
    DECISION = "decision"
    RESULT_INSPECTION = "result-inspection"
    APPROVAL = "approval"


class InvalidRecord(ValueError):
    """`parse()` refused. Carries every problem, not the first one."""


# Fields only the platform may write, with the reason each is reserved. Read by
# `validate()` and by the reader's write-integrity check, so the two cannot
# disagree about which fields an agent is allowed to assert.
PLATFORM_ONLY_FIELDS: dict[str, str] = {
    "decision": (
        "whether the call was authorized is the one fact an auditor must not "
        "take from the party being audited (a design note, Options considered)"
    ),
    "matched_policy": (
        "which Cedar clause fired is the PDP's answer; an agent asserting it "
        "would be asserting the policy corpus' behaviour"
    ),
    "policy_version": (
        "binds the decision to the policy generation that produced it; only the "
        "writer that read the policy can state it"
    ),
}

_FIELDS_REQUIRED_ALWAYS = ("schema_version", "phase", "ts", "correlation_id", "actor",
                           "attested_by")
# The decision record's field list is a design note point 4, verbatim, minus the ones
# already required of every phase.
_FIELDS_REQUIRED_FOR_DECISION = ("action_id", "principal", "asset", "decision")


@dataclasses.dataclass(frozen=True)
class EvidenceRecord:
    """One record. Frozen: a reader holding evidence must not be able to edit it
    in place and then render what it edited."""

    phase: Phase
    ts: str
    correlation_id: str
    actor: str
    attested_by: str
    schema_version: str = SCHEMA_VERSION
    trace_id: str | None = None
    action_id: str | None = None
    principal: str | None = None
    asset_kind: str | None = None
    asset_alias: str | None = None
    registry_record_id: str | None = None
    policy_id: str | None = None
    policy_version: str | None = None
    decision: str | None = None
    matched_policy: str | None = None
    reason: str | None = None
    # Workflow position, NOT time order (a design note point 9). Kept as a string
    # because participants number steps "3", "3a" and "retry-3" and coercing
    # that to an int would make a reader sort on a lie.
    step: str | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """The wire form. Absent fields are OMITTED rather than sent as null, so
        "the writer did not know this" and "the writer knows it is empty" stay
        distinguishable -- `matched_policy: null` is Cedar's real answer when no
        clause matched, and it must not read the same as a missing field."""
        out: dict[str, Any] = {
            "schema_version": self.schema_version,
            "phase": self.phase.value if isinstance(self.phase, Phase) else self.phase,
            "ts": self.ts,
            "correlation_id": self.correlation_id,
        }
        if self.trace_id is not None:
            out["trace_id"] = self.trace_id
        if self.action_id is not None:
            out["action_id"] = self.action_id
        out["actor"] = self.actor
        out["attested_by"] = self.attested_by
        if self.principal is not None:
            out["principal"] = self.principal
        if self.asset_kind is not None or self.asset_alias is not None:
            asset: dict[str, str] = {}
            if self.asset_kind is not None:
                asset["kind"] = self.asset_kind
            if self.asset_alias is not None:
                asset["alias"] = self.asset_alias
            out["asset"] = asset
        for name in ("registry_record_id", "policy_id", "policy_version", "decision",
                     "matched_policy", "reason", "step", "detail"):
            value = getattr(self, name)
            if value is not None:
                out[name] = value
        return out

    def to_attributes(self) -> dict[str, str]:
        """The flat, prefixed projection a log backend can filter on.

        CloudWatch Logs Insights and every other sink query on flat keys, so the
        nested `asset` object is flattened here rather than at each sink. The
        `modaas.evidence.` prefix is load-bearing twice: the collector's
        evidence filter selects on `modaas.evidence.schema_version` (so an
        unrelated application log on the same OTLP endpoint never lands in the
        audit pipeline), and a reader can tell a MoDaaS attribute from a
        `k8s.*` stamp the collector added.
        """
        flat = dict(self.to_dict())
        asset = flat.pop("asset", None) or {}
        for key, value in asset.items():
            flat[f"asset.{key}"] = value
        return {f"modaas.evidence.{k}": str(v) for k, v in flat.items() if v is not None}


def now_ts() -> str:
    """RFC3339 UTC, seconds precision, `Z` suffix.

    Seconds rather than microseconds: the workshop's ledger already renders
    second-precision timestamps to approvers and matching it keeps a rendered
    timeline column-aligned. Ordering inside one second is not something this
    contract claims -- a design note point 9 says readers sort by `ts`, and two records
    in the same second are genuinely unordered by this key.
    """
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(ts: str) -> _dt.datetime | None:
    """RFC3339 -> aware datetime, or None if it does not parse as an INSTANT.

    A naive timestamp returns None rather than an assumed-UTC datetime: `ts` is
    the sort key readers use, and silently assuming a zone would order records
    from two zones wrongly with nothing failing.
    """
    if not isinstance(ts, str) or not ts:
        return None
    try:
        parsed = _dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


def sort_key(record: "EvidenceRecord") -> tuple[float, str]:
    """Time order (a design note point 9), with the action id as a stable tie-break.

    NOT `step`: step is workflow position, so sorting by it renders a retried
    step before the attempt that caused the retry. An unparseable `ts` sorts
    first rather than raising -- `validate()` already refuses one, and a reader
    handed a legacy record should still render it somewhere visible.
    """
    parsed = parse_ts(record.ts)
    return (parsed.timestamp() if parsed else float("-inf"), record.action_id or "")


def is_platform_attested(record: "EvidenceRecord") -> bool:
    """True only for a decision record written by `modaas-authz`.

    This is what `/timeline` marks as platform-attested. Everything else is a
    claim by its writer, and the rendering must not blur the two.
    """
    phase = record.phase.value if isinstance(record.phase, Phase) else record.phase
    return phase == Phase.DECISION.value and record.attested_by == ATTESTOR_PLATFORM


_KNOWN_FIELDS = frozenset(
    {"schema_version", "phase", "ts", "correlation_id", "trace_id", "action_id",
     "actor", "attested_by", "principal", "asset", "registry_record_id",
     "policy_id", "policy_version", "decision", "matched_policy", "reason",
     "step", "detail"}
)


def validate(raw: Any) -> list[str]:
    """Every problem with `raw`, as human-readable strings. [] means valid."""
    if not isinstance(raw, dict):
        return ["record must be a JSON object"]

    errors: list[str] = []

    unknown = sorted(set(raw) - _KNOWN_FIELDS)
    if unknown:
        errors.append(
            f"unknown field(s) {unknown}: the evidence contract is versioned, so a "
            f"writer's private key would make two deployments disagree silently"
        )

    if raw.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            f"schema_version must be {SCHEMA_VERSION!r}, got "
            f"{raw.get('schema_version')!r}"
        )

    phase = raw.get("phase")
    phases = {p.value for p in Phase}
    if phase not in phases:
        errors.append(f"phase must be one of {sorted(phases)}, got {phase!r}")

    if parse_ts(raw.get("ts")) is None:
        errors.append(
            f"ts must be an RFC3339 instant WITH a timezone (readers sort by it), "
            f"got {raw.get('ts')!r}"
        )

    for field in _FIELDS_REQUIRED_ALWAYS:
        if field in ("schema_version", "phase", "ts"):
            continue                      # reported above with their own message
        if not raw.get(field):
            errors.append(f"{field} is required on every phase")

    trace_id = raw.get("trace_id")
    if trace_id is not None:
        if not isinstance(trace_id, str) or not _TRACE_ID_RE.match(trace_id):
            errors.append(f"trace_id must be 32 lowercase hex chars, got {trace_id!r}")
        elif trace_id == _ZERO_TRACE_ID:
            errors.append(
                "trace_id is the reserved all-zero value, which W3C defines as "
                "invalid -- a record carrying it claims a join that cannot exist"
            )

    action_id = raw.get("action_id")
    if action_id is not None:
        if not isinstance(action_id, str) or not _UUID_RE.match(action_id):
            errors.append(
                f"action_id must be a UUID in canonical dashed form, got {action_id!r}"
            )

    errors.extend(_validate_asset(raw.get("asset")))
    errors.extend(_validate_verdict(raw, phase))
    return errors


def _validate_asset(asset: Any) -> list[str]:
    if asset is None:
        return []
    if not isinstance(asset, dict):
        return ["asset must be an object with kind and alias"]
    errors: list[str] = []
    unknown = sorted(set(asset) - {"kind", "alias"})
    if unknown:
        errors.append(f"asset carries unknown key(s) {unknown}")
    kind = asset.get("kind")
    if kind is not None and kind not in _ASSET_KINDS:
        errors.append(f"asset.kind must be one of {list(_ASSET_KINDS)}, got {kind!r}")
    if not asset.get("alias"):
        errors.append("asset.alias is required when asset is present")
    return errors


def _validate_verdict(raw: dict, phase: Any) -> list[str]:
    """The two rules from the module docstring."""
    errors: list[str] = []
    is_decision = phase == Phase.DECISION.value

    if is_decision:
        for field in _FIELDS_REQUIRED_FOR_DECISION:
            if raw.get(field) in (None, "", {}):
                errors.append(f"{field} is required on a decision record (a design note point 4)")
        if raw.get("attested_by") != ATTESTOR_PLATFORM:
            errors.append(
                f"attested_by must be {ATTESTOR_PLATFORM!r} on a decision record: "
                f"a design note point 4 makes it the sole writer, and a reader rejects a "
                f"decision written by anything else"
            )
        decision = raw.get("decision")
        if decision is not None and decision not in _DECISIONS:
            errors.append(
                f"decision must be one of {list(_DECISIONS)}, got {decision!r}"
            )
    else:
        for field, why in PLATFORM_ONLY_FIELDS.items():
            if field in raw:
                errors.append(f"{field} may only appear on a decision record: {why}")
        if raw.get("attested_by") == ATTESTOR_PLATFORM:
            # Surfaced by evidence-service's timeline tests: the rendering was
            # already safe (its marker derives from `is_platform_attested`, which
            # requires the decision phase), but the CLAIM was writable. modaas-authz
            # writes decision records and nothing else, so `attested_by:
            # modaas-authz` on any other phase is a false claim about the writer --
            # and a reader that trusted the field directly rather than going
            # through `is_platform_attested` would render it as platform evidence.
            errors.append(
                f"attested_by {ATTESTOR_PLATFORM!r} is valid only on a decision "
                f"record: it writes no other phase, so the claim cannot be true"
            )
    return errors


def parse(raw: Any) -> EvidenceRecord:
    """`raw` -> EvidenceRecord, or raise `InvalidRecord` listing every problem."""
    errors = validate(raw)
    if errors:
        raise InvalidRecord("; ".join(errors))
    asset = raw.get("asset") or {}
    return EvidenceRecord(
        schema_version=raw["schema_version"],
        phase=Phase(raw["phase"]),
        ts=raw["ts"],
        correlation_id=raw["correlation_id"],
        actor=raw["actor"],
        attested_by=raw["attested_by"],
        trace_id=raw.get("trace_id"),
        action_id=raw.get("action_id"),
        principal=raw.get("principal"),
        asset_kind=asset.get("kind"),
        asset_alias=asset.get("alias"),
        registry_record_id=raw.get("registry_record_id"),
        policy_id=raw.get("policy_id"),
        policy_version=raw.get("policy_version"),
        decision=raw.get("decision"),
        matched_policy=raw.get("matched_policy"),
        reason=raw.get("reason"),
        step=raw.get("step"),
        detail=raw.get("detail"),
    )
