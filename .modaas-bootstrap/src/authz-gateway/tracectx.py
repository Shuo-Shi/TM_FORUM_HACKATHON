"""W3C traceparent + actionId evidence chain (T2, sprint-2026-09-ga-hardening).

## What this closes

integrations/servicenow/contract/ServiceNow-Integration-API.md §3 (pre-T2) named the gap
directly: `actionId` was not implemented anywhere in MoDaaS, and a caller
that fails to propagate `traceparent` produces spans that cannot be joined
to the ticket, the gateway decision, or the model invocation. This module is
the generation point and carrier for both halves of that join key.

## Why a hand-rolled parser rather than opentelemetry-api

Two reasons, both load-bearing rather than stylistic:

1. app.py's own MD-0 note already states the cluster's OTel collector exports
   only to `debug` and no trace store exists — there is no span exporter to
   feed. Pulling in the OTel SDK to parse one header and log two IDs would add
   a dependency this service does not use for its stated purpose.
2. `traceparent` and `baggage` are both fixed-grammar strings (W3C Trace
   Context, w3.org/TR/trace-context). identity.py already establishes the
   pattern for this codebase: parse a wire format with a narrow, testable
   pure function rather than a general-purpose library, because the
   general-purpose library's job (full span lifecycle) is not the job this
   service has.

## The two IDs and where each is born

- `traceId`: the middle 32 hex chars of an inbound `traceparent`. NEVER
  minted here — if the caller sent no traceparent, `trace_id` is absent from
  the decision context entirely rather than fabricated, because a synthesized
  trace-id that did not originate at the actual caller would be evidence of a
  join that never happened.
- `actionId`: minted with `uuid4()` at the FIRST governed touch — this
  service, in `authorize_request` — only when the caller sent none. Carried
  onward via the W3C `baggage` header as `modaas-action-id=<uuid>` so a
  second hop (the PDP) sees the SAME action, not a new one it would
  otherwise have to mint for itself.

## Fail-open by design, deliberately asymmetric with the rest of this service

Every other module here fails closed (identity.py, pdp_client.py, shed.py).
This one does not, and that asymmetry is intentional: a malformed
`traceparent` or `baggage` header is a caller who cannot be joined to their
own evidence chain, not a caller who should be refused the call they are
otherwise authorized to make. `parse_traceparent` and `parse_baggage_action_id`
return `None` on anything that does not parse; nothing here raises `Refusal`.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

# W3C Trace Context, https://www.w3.org/TR/trace-context/#traceparent-header
#   version "-" trace-id "-" parent-id "-" trace-flags
# version is pinned to "00" here (the only version in the current spec); a
# different version's field count / meaning is not guaranteed compatible, so
# an unrecognised version is treated as unparseable rather than guessed at.
_TRACEPARENT_RE = re.compile(
    r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$"
)

# all-zero trace-id / parent-id are explicitly invalid per the spec (they are
# the values a broken instrumentation library emits when it fails to
# generate a real one) — reject them the same as a structurally bad header.
_INVALID_TRACE_ID = "0" * 32
_INVALID_PARENT_ID = "0" * 16

BAGGAGE_ACTION_KEY = "modaas-action-id"

# a design note point 1: "The run's business correlation id (`fault-...`) is carried in
# `baggage` and in every record." It is the key an approver already searches by
# (`GET /timeline?cid=`), so the decision record this service writes must carry
# the CALLER's value wherever the caller sent one -- inventing our own would
# produce a record that joins to nothing the agent wrote.
BAGGAGE_CORRELATION_KEY = "modaas-correlation-id"

# The correlation id is caller-supplied and lands in a log attribute on every
# governed call. Unbounded it is a cheap way to inflate the audit sink, so it is
# truncated rather than refused -- a refusal here would turn a cosmetic abuse
# into a denial of the call, and tracectx.py fails open by design (see the
# module docstring).
_MAX_CORRELATION_ID_LEN = 256

# W3C Baggage value grammar (w3.org/TR/baggage, "baggage-octet"): printable
# US-ASCII except space, DQUOTE, comma, semicolon and backslash. Enforced for the
# correlation id because it is written, unquoted, into the gateway's per-call
# access-log line (deploy/agentgateway/agentgatewaypolicy-access-log.yaml): a
# space would let a caller append a forged `gen_ai.usage.input_tokens=0` field to
# the one record a spend control trusts because the caller does not write it.
_BAGGAGE_VALUE_RE = re.compile(r"^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]+$")

# baggage member syntax (RFC-ish, W3C Baggage spec section 3.1.1): a
# comma-separated list of "key=value" pairs, each optionally followed by
# ";property" metadata this service does not use and passes through
# unexamined by simply not looking past the first "=".
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


@dataclass(frozen=True)
class TraceContext:
    """The evidence-chain identifiers for one request.

    `trace_id` is None when the caller sent no (or an unparseable)
    traceparent — never fabricated (see module docstring). `action_id` is
    always populated by the time this leaves `resolve()`: either the
    caller's own (echoed forward) or freshly minted here.
    """

    trace_id: str | None
    action_id: str
    action_id_minted: bool  # True: this service minted it. False: caller sent it.
    # a design note point 1. Always non-empty by the time this leaves `resolve()`: the
    # caller's `modaas-correlation-id` baggage member, else the trace id, else
    # the action id. The evidence contract requires it on every record, so an
    # absent one would make the decision record unwritable -- and a record that
    # cannot be written is a decision an auditor cannot see.
    correlation_id: str = ""


def parse_traceparent(traceparent: str | None) -> str | None:
    """Extract the 32-hex-char trace-id from a W3C `traceparent` header.

    Returns None for anything absent or structurally invalid — including a
    well-formed header carrying the reserved all-zero trace-id, which W3C
    defines as invalid rather than as a valid trace-id of zero.
    """
    if not traceparent:
        return None
    m = _TRACEPARENT_RE.match(traceparent.strip())
    if not m:
        return None
    trace_id = m.group(1)
    if trace_id == _INVALID_TRACE_ID:
        return None
    if m.group(2) == _INVALID_PARENT_ID:
        return None
    return trace_id


def parse_baggage_action_id(baggage: str | None) -> str | None:
    """Pull `modaas-action-id` out of a W3C `baggage` header, if present.

    Only a syntactically-valid UUID is accepted as an echoed actionId — a
    caller sending a non-UUID value under this key gets a freshly minted
    actionId instead of having an unstructured string carried into the audit
    trail as if it were the join key.
    """
    value = parse_baggage_member(baggage, BAGGAGE_ACTION_KEY)
    if value is None:
        return None
    return value.lower() if _UUID_RE.match(value) else None


def parse_baggage_member(baggage: str | None, key: str) -> str | None:
    """The value of one W3C `baggage` member, or None.

    Shared by both baggage keys this service reads so the two cannot disagree
    about the grammar. Member metadata (`;ttl=60`) is dropped: this service does
    not use it, and carrying it into a record would make the id fail to match
    the same run's agent-written records.
    """
    if not baggage:
        return None
    for member in baggage.split(","):
        member = member.strip()
        if not member or "=" not in member:
            continue
        member_key, _, rest = member.partition("=")
        if member_key.strip() != key:
            continue
        return rest.split(";", 1)[0].strip()
    return None


def parse_baggage_correlation_id(baggage: str | None) -> str | None:
    """Pull `modaas-correlation-id` out of a W3C `baggage` header, if present.

    NOT shape-validated the way the actionId is: a business correlation id is
    the customer's own key (`fault-4471`, a ServiceNow number, a trouble-ticket
    id) and this service has no grounds to define its format. Only bounded, see
    `_MAX_CORRELATION_ID_LEN`, and held to the W3C baggage value grammar
    (`_BAGGAGE_VALUE_RE`): a value outside it is not a baggage value, so it is
    treated as absent and the trace id stands in, as for a non-UUID action id.
    """
    value = parse_baggage_member(baggage, BAGGAGE_CORRELATION_KEY)
    if not value:
        return None
    value = value[:_MAX_CORRELATION_ID_LEN]
    return value if _BAGGAGE_VALUE_RE.match(value) else None


def resolve(traceparent: str | None, baggage: str | None) -> TraceContext:
    """The FIRST governed touch's evidence-chain decision.

    - traceId: parsed from `traceparent`, or None (never minted).
    - actionId: the caller's own (from `baggage`) if present and a valid
      UUID; otherwise a fresh `uuid4()`, minted here because this service is
      the first governed touch on the request path (app.py's docstring: C2
      identity, then C3 authorize — nothing upstream of this on the governed
      path establishes an actionId today).
    """
    trace_id = parse_traceparent(traceparent)
    caller_action_id = parse_baggage_action_id(baggage)
    action_id = caller_action_id if caller_action_id is not None else str(uuid.uuid4())
    # correlationId (a design note point 1): the caller's own, else the trace id, else
    # the action id. The fallbacks are ORDERED by how many parties share the
    # key: a business id the agent also writes joins the most records, a trace
    # id joins this run's platform records, an action id joins this call alone.
    correlation_id = (
        parse_baggage_correlation_id(baggage) or trace_id or action_id
    )
    return TraceContext(
        trace_id=trace_id,
        action_id=action_id,
        action_id_minted=caller_action_id is None,
        correlation_id=correlation_id,
    )


def baggage_header_value(action_id: str, existing_baggage: str | None = None) -> str:
    """The `baggage` header value to send onward to the PDP.

    Carries `modaas-action-id=<uuid>` so the PDP sees the SAME action this
    service established, not one it would otherwise have to mint itself.
    Preserves any OTHER baggage members the caller sent (this service is not
    the only party who may want cross-cutting attributes to survive the
    hop) — it only ever adds or replaces its own key, per W3C baggage
    semantics where a later member with the same key overrides an earlier
    one when parsed left-to-right; here we exclude any incoming
    `modaas-action-id` member explicitly rather than relying on override
    order, so there is exactly one on the wire.
    """
    members = [f"{BAGGAGE_ACTION_KEY}={action_id}"]
    if existing_baggage:
        for member in existing_baggage.split(","):
            member = member.strip()
            if not member:
                continue
            key = member.split("=", 1)[0].strip()
            if key == BAGGAGE_ACTION_KEY:
                continue  # replaced by the entry above, not duplicated
            members.append(member)
    return ",".join(members)
