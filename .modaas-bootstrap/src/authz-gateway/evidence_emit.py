"""The decision record this service writes (a design note point 4), emitted over OTLP.

## Why modaas-authz is the writer and the PDP is not

a design note point 4, owner decision 2026-09-26: "`modaas-authz` writes one decision
record per governed call. It is where the action id is minted and it holds the
principal, asset and trace id together with the PDP's answer. The PDP stays a
pure decision point on the fail-closed path." The PDP has the verdict and
nothing else -- no principal, no trace id, no asset alias -- so a PDP-written
record would need a second join to be readable, and the PDP would acquire an
export path on the fail-closed enforcement path. Neither is worth it.

## The asymmetry with every other module in this service

`identity.py`, `pdp_client.py` and `shed.py` fail CLOSED. This one cannot, and
the reason is a design note point 6: "Nothing on the enforcement path depends on the
evidence store ... so a sink outage does not stop governed traffic." A collector
outage refusing governed traffic would make the audit trail a new, unannounced
single point of failure for every governed call -- the exact objection a design note
raises against the rejected "PDP writes decisions into the workshop ledger"
option. `tracectx.py` has the same posture for the same kind of reason.

So the rule here is: **`emit_decision()` never raises and never blocks**, and
every loss is counted. "Records were lost" and "no governed calls happened" look
identical in a sink; the counters are the only thing that tells them apart.

## What is deliberately NOT retried

A failed batch is dropped and counted, not requeued. Retrying at the head would
wedge every later record behind a poison batch, and the resulting loss would be
attributed to volume (`dropped_queue_full` climbing) rather than to the failure
that caused it. The collector's own `sending_queue` is where retry belongs --
it is one hop closer to the sink and it is configured for it (a design note §8).

## Why no OpenTelemetry SDK

Same reasoning as `tracectx.py`'s: the SDK's job is the full log/span lifecycle,
and the job here is to serialise a handful of records and POST them. The
encoding lives in `evidence/otlp.py`, shared with `evidence-service`, so the
writer and the reader cannot drift. `httpx` is already a dependency of this
image for the PDP call.
"""
from __future__ import annotations

import dataclasses
import logging
import threading
from collections import deque
from typing import Any, Callable

import config
from evidence import evidence_record as er
from evidence import otlp

log = logging.getLogger("authz-gateway.evidence")

# The asset a decision record names when the call was refused BEFORE the asset
# was resolved (a malformed credential, an unreadable CR store). The contract
# requires an asset on a decision record, and writing nothing would hide exactly
# the refusals an operator most wants to see. A reserved alias is honest: it says
# "the platform refused this call before it identified an asset".
UNRESOLVED_ASSET = "-unresolved-"

Poster = Callable[[str, dict[str, Any]], int]


def _httpx_poster(url: str, payload: dict[str, Any], timeout_s: float = 2.0) -> int:
    """The default transport. Returns the HTTP status; raises on transport error.

    A fresh client per batch rather than a shared pool: this runs on the drain
    thread at most once per `flush_interval_s`, so pooling saves nothing
    measurable, and a shared `httpx.Client` reachable from two threads is a
    failure mode this service has already paid for once elsewhere.
    """
    import httpx

    resp = httpx.post(url, json=payload, timeout=timeout_s)
    return resp.status_code


class EvidenceEmitter:
    """A bounded, non-blocking OTLP log exporter for evidence records."""

    def __init__(
        self,
        endpoint: str | None,
        resource_attributes: dict[str, str],
        max_queue: int = 1024,
        batch_size: int = 64,
        flush_interval_s: float = 2.0,
        timeout_s: float = 2.0,
        poster: Poster | None = None,
    ) -> None:
        self.endpoint = _logs_url(endpoint)
        self.resource_attributes = dict(resource_attributes)
        self.max_queue = max_queue
        self.batch_size = batch_size
        self.flush_interval_s = flush_interval_s
        self.timeout_s = timeout_s
        self._poster: Poster = poster or (
            lambda url, payload: _httpx_poster(url, payload, timeout_s)
        )
        # A plain deque WITHOUT maxlen, bounded by an explicit length check.
        # `maxlen` evicts the OLDEST on overflow, which rewrites a history a
        # partially-read timeline already references.
        self._queue: deque[er.EvidenceRecord] = deque()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self.counters: dict[str, int] = {
            "enqueued": 0,
            "exported": 0,
            "dropped_queue_full": 0,
            "dropped_export_failed": 0,
            "dropped_invalid": 0,
            "skipped_disabled": 0,
        }

    @property
    def enabled(self) -> bool:
        """False when no collector endpoint is configured.

        The chart ships `otelCollector.enabled: false`, so "no collector here" is
        a normal deployment state and must be distinguishable from a failure --
        hence its own counter rather than a silent discard.
        """
        return bool(self.endpoint)

    def emit(self, record: er.EvidenceRecord) -> bool:
        """Enqueue one record. NO I/O, never blocks, never raises.

        Returns False when the record was not accepted. The caller does not act
        on it -- but an always-True return would leave the counter as the only
        signal, and a signal nothing can observe in a test is not one.
        """
        if not self.enabled:
            self._bump("skipped_disabled")
            return False
        with self._lock:
            if len(self._queue) >= self.max_queue:
                self.counters["dropped_queue_full"] += 1
                return False
            self._queue.append(record)
            self.counters["enqueued"] += 1
        return True

    def pending(self) -> int:
        with self._lock:
            return len(self._queue)

    def drain_once(self) -> int:
        """Export at most `batch_size` records. Returns the number EXPORTED.

        The synchronous half of the worker loop, so a test can assert the
        transport behaviour without racing a thread. Returns 0 on failure (the
        batch is dropped and counted), which is why the return value is
        "exported" and not "dequeued".
        """
        with self._lock:
            batch = [self._queue.popleft() for _ in range(min(self.batch_size,
                                                              len(self._queue)))]
        if not batch:
            return 0

        payload = otlp.to_otlp_logs(batch, self.resource_attributes)
        try:
            status = self._poster(self.endpoint, payload)
        except Exception as exc:  # noqa: BLE001 -- any transport failure is a drop
            self._drop_batch(batch, f"{type(exc).__name__}: {exc}")
            return 0
        if status >= 400:
            self._drop_batch(batch, f"collector returned {status}")
            return 0
        with self._lock:
            self.counters["exported"] += len(batch)
        return len(batch)

    def _drop_batch(self, batch: list[er.EvidenceRecord], why: str) -> None:
        with self._lock:
            self.counters["dropped_export_failed"] += len(batch)
        # WARNING, not ERROR: the governed calls themselves all succeeded or were
        # refused on their own merits. What was lost is evidence, and an operator
        # needs to know -- but paging on it would train them to ignore it.
        log.warning(
            "dropped %d evidence record(s): %s (total dropped=%d)",
            len(batch), why, self.counters["dropped_export_failed"],
        )

    def _bump(self, name: str) -> None:
        with self._lock:
            self.counters[name] += 1

    # --- the drain thread --------------------------------------------------

    def start(self) -> None:
        """Start the drain thread. Idempotent.

        Idempotent because the Dockerfile runs uvicorn and a lazily-initialised
        module global can be touched concurrently by the first two requests; two
        drain threads on one deque would double-post some batches and the
        duplicate would look like a replayed decision.
        """
        if not self.enabled:
            return
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stopping.clear()
            self._thread = threading.Thread(
                target=self._run, name="evidence-emitter", daemon=True
            )
            self._thread.start()

    def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                while self.drain_once():
                    pass
            except Exception as exc:  # noqa: BLE001
                # drain_once already swallows transport failures; this catches a
                # defect in the encoder. Logged and the loop continues -- a dead
                # drain thread fills the queue and the loss then reports as
                # `dropped_queue_full`, blaming volume for a code bug.
                log.error("evidence drain loop error: %s: %s", type(exc).__name__, exc)
            self._stopping.wait(self.flush_interval_s)

    def stop(self) -> None:
        """Stop draining, flushing whatever is pending first.

        The flush matters on a rolling restart: `maxUnavailable: 0` surges a new
        replica and terminates the old one, and the old one's queue holds
        decisions for calls that already happened.
        """
        self._stopping.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=self.flush_interval_s + self.timeout_s)
            self._thread = None
        if self.enabled:
            while self.drain_once():
                pass


def _logs_url(endpoint: str | None) -> str:
    """`<base>` -> `<base>/v1/logs`, and a URL that already names it is left alone.

    Both forms reach here from the environment: the OTLP spec makes
    `OTEL_EXPORTER_OTLP_ENDPOINT` a BASE url to which the signal path is
    appended, while `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` is the full url. Posting
    a base URL unmodified 404s every batch and the failure reads as a network
    problem.
    """
    if not endpoint:
        return ""
    trimmed = endpoint.rstrip("/")
    if trimmed.endswith("/v1/logs"):
        return trimmed
    return trimmed + "/v1/logs"


# --- the process-wide emitter app.py uses ---------------------------------

_emitter: EvidenceEmitter | None = None
_emitter_lock = threading.Lock()


def get_emitter() -> EvidenceEmitter:
    """The process's emitter, built from `config` on first use.

    Lazy rather than module-level so importing this module in a test (or in a
    tool) does not open a socket or read the environment at import time, matching
    `pdp_client`'s client handling.
    """
    global _emitter
    with _emitter_lock:
        if _emitter is None:
            _emitter = EvidenceEmitter(
                endpoint=config.EVIDENCE_OTLP_ENDPOINT,
                resource_attributes={
                    # The name a reader looks for when asking which workload
                    # emitted a record. (It does NOT name the CloudWatch stream:
                    # the pinned collector writes "{ServiceName}" literally, so
                    # the chart uses one literal stream, modaas-evidence.)
                    "service.name": "modaas-authz",
                    "service.namespace": config.EVIDENCE_SERVICE_NAMESPACE,
                },
                max_queue=config.EVIDENCE_QUEUE_MAX,
                batch_size=config.EVIDENCE_BATCH_SIZE,
                flush_interval_s=config.EVIDENCE_FLUSH_INTERVAL_S,
                timeout_s=config.EVIDENCE_TIMEOUT_S,
            )
            _emitter.start()
        return _emitter


def set_emitter_for_tests(emitter: EvidenceEmitter) -> None:
    global _emitter
    with _emitter_lock:
        _emitter = emitter


def reset_for_tests() -> None:
    global _emitter
    with _emitter_lock:
        existing, _emitter = _emitter, None
    if existing is not None:
        existing.stop()


def counters_snapshot() -> dict[str, int]:
    """The counters, for a metrics scrape or a log line.

    a design note point 6 requires the loss be VISIBLE; a counter on an object nothing
    can read is not visible.
    """
    return dict(get_emitter().counters)


def emit_decision(
    *,
    correlation_id: str,
    trace_id: str | None,
    action_id: str,
    principal: str,
    asset_kind: str | None,
    asset_alias: str | None,
    registry_record_id: str | None,
    policy_id: str | None,
    policy_version: str | None,
    decision: str,
    matched_policy: str | None,
    reason: str | None,
    actor: str | None = None,
    detail: str | None = None,
) -> None:
    """Write one decision record. Never raises.

    Called from BOTH of `app.py`'s terminal paths -- the ALLOW response and
    `_refuse` -- so a raise here would convert a reasoned 403 into a 500, the
    emitter making this service worse at the one thing it exists to document.

    `policy_id` / `matched_policy` / `policy_version` are omitted when the call
    was refused before Cedar saw it. Writing a policy id on a record whose
    refusal never reached the PDP would claim a policy decided something it
    never evaluated, which is the forgery the contract exists to prevent --
    whoever commits it, including us.
    """
    try:
        raw: dict[str, Any] = {
            "schema_version": er.SCHEMA_VERSION,
            "phase": er.Phase.DECISION.value,
            "ts": er.now_ts(),
            "correlation_id": correlation_id,
            "action_id": action_id,
            "actor": actor or principal,
            "attested_by": er.ATTESTOR_PLATFORM,
            "principal": principal,
            "asset": {
                "kind": asset_kind or "Model",
                "alias": asset_alias or UNRESOLVED_ASSET,
            },
            "decision": decision,
        }
        if trace_id:
            raw["trace_id"] = trace_id
        if registry_record_id:
            raw["registry_record_id"] = registry_record_id
        if policy_id:
            raw["policy_id"] = policy_id
        if policy_version:
            raw["policy_version"] = policy_version
        if matched_policy:
            raw["matched_policy"] = matched_policy
        if reason:
            raw["reason"] = reason
        if detail:
            # AR-11: a cross-tool call carries the ROUTE alias here while
            # `asset.alias` carries the CALLED tool. The evidence contract
            # (evidence/evidence_record.py) is a versioned, strict schema that
            # refuses unknown top-level fields, so the route alias rides in the
            # contract's existing free-form `detail` field rather than a new
            # one -- both aliases are in the record, no contract bump.
            raw["detail"] = detail
        record = er.parse(raw)
    except Exception as exc:  # noqa: BLE001 -- an unwritable record is not a 500
        emitter = get_emitter()
        emitter._bump("dropped_invalid")
        log.error("could not build a decision record: %s", exc)
        return

    get_emitter().emit(record)


@dataclasses.dataclass
class DecisionDraft:
    """What app.py knows so far about the call it is deciding.

    ## Why a mutable accumulator and not local variables

    `app.py` resolves the pieces of a decision record at four different points
    (trace context, identity, asset, PDP verdict) and BOTH of its terminal paths
    -- the ALLOW response and the `except Refusal` branch -- must write a record
    from whatever was resolved by then. Reading locals in an `except` block works
    only when the raise happened after they were bound; a refusal at identity
    would hit `NameError` on the asset name and turn a reasoned 403 into a 500.
    An object constructed BEFORE the `try` cannot have that failure mode.

    ## Why the defaults are what they are

    `principal` defaults to `"unknown"` rather than empty: the contract requires
    a non-empty principal on a decision record, and a refusal at identity has no
    principal by definition. `"unknown"` is the truthful value -- the platform
    refused a caller it could not identify -- and it keeps the record writable,
    which is what makes the refusal visible to an auditor at all.
    """

    correlation_id: str
    action_id: str
    trace_id: str | None = None
    principal: str = "unknown"
    asset_kind: str | None = None
    asset_alias: str | None = None
    registry_record_id: str | None = None
    policy_id: str | None = None
    # AR-11: the /mcp/<alias> listener a cross-tool call entered on. `asset_alias`
    # holds the CALLED tool (the asset the call is credited to); `route_alias`
    # holds the route, so both are visible in the record. None (and omitted from
    # the record) for every same-tool call, which keeps those records unchanged.
    route_alias: str | None = None

    def record_allow(self, verdict: dict[str, Any] | None) -> None:
        """Write the ALLOW record. Called after the PDP has answered."""
        verdict = verdict or {}
        self._write(
            decision="ALLOW",
            policy_version=verdict.get("policyVersion"),
            matched_policy=verdict.get("matchedPolicy"),
            reason=None,
            policy_id=verdict.get("policyId") or self.policy_id,
        )

    def record_deny(self, reason: str, verdict: dict[str, Any] | None) -> None:
        """Write the DENY record for any refusal this service returns.

        `verdict` is present only when the PDP actually answered (`Refusal`
        carries it from `pdp_client`). When it is absent the policy fields are
        omitted: a refusal at identity, a malformed body or an unreachable PDP
        never reached Cedar, and naming a policy on such a record would claim a
        policy decided something it never evaluated.
        """
        if verdict:
            self._write(
                decision="DENY",
                policy_version=verdict.get("policyVersion"),
                matched_policy=verdict.get("matchedPolicy"),
                reason=reason,
                policy_id=verdict.get("policyId") or self.policy_id,
            )
        else:
            self._write(
                decision="DENY", policy_version=None, matched_policy=None,
                reason=reason, policy_id=None,
            )

    def _write(
        self,
        *,
        decision: str,
        policy_version: str | None,
        matched_policy: str | None,
        reason: str | None,
        policy_id: str | None,
    ) -> None:
        emit_decision(
            correlation_id=self.correlation_id,
            trace_id=self.trace_id,
            action_id=self.action_id,
            principal=self.principal,
            asset_kind=self.asset_kind,
            asset_alias=self.asset_alias,
            registry_record_id=self.registry_record_id,
            policy_id=policy_id,
            policy_version=policy_version,
            decision=decision,
            matched_policy=matched_policy,
            reason=reason,
            detail=(f"route_alias={self.route_alias}" if self.route_alias else None),
        )
