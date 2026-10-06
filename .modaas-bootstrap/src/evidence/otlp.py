"""OTLP logs encoding and decoding for the evidence contract (a design note point 5).

## One shape, three services

`modaas-authz` encodes a decision record. `evidence-service` encodes a
participant's `POST /records`. `evidence-service` decodes whatever the sink gives
back. Those are three call sites for one wire shape, so the shape lives here and
nowhere else -- a writer and a reader that disagree produce records that land in
the sink and render as an empty timeline, with nothing failing anywhere.

## Why OTLP/HTTP JSON and not the protobuf, and no OTel SDK

The same reasoning `tracectx.py` already applies in this repo: the SDK's job is
the full span/log lifecycle, and the job here is "serialise a handful of records
and POST them". OTLP/HTTP JSON is a documented, stable encoding
(opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding) that `httpx` can post
with no new dependency in three images. The one subtlety the JSON encoding
imposes is that 64-bit integers are strings -- `timeUnixNano` below -- because a
consumer parsing JSON numbers into a double would quietly lose nanoseconds.

## The envelope on the way back

A sink stores an OTLP log record by serialising it. The `awscloudwatchlogs`
exporter's serialization (verified 2026-09-26 in
`exporter/awscloudwatchlogsexporter/exporter.go`: `logToCWLog` builds a
`cwLogBody` and `json.Marshal`s it) is:

    {"body": <raw body>, "severity_number": .., "severity_text": "..",
     "trace_id": "..", "span_id": "..", "attributes": {..},
     "scope": {"name": ..}, "resource": {..}}

all keys `omitempty` and snake_case. `decode_log_envelope` reads that shape, and
also the two degenerate forms a different sink may produce: a body already
parsed into an object, and a bare record with no envelope (the workshop's jsonl
ledger). Nothing here is AWS-specific -- it is the faithful projection of an
OTLP log record, which is what a design note point 5's "sinks are pluggable" requires.

## Write integrity

`Attestor.accepts` is the reader-side half of "readers accept `phase: decision`
only from `modaas-authz`". It checks the `resource` stamp the collector's
`k8sattributes` processor wrote from the CONNECTION IP -- a value the payload
cannot choose. See `tests/test_evidence_otlp.py`'s module docstring for the
service-account key that does not exist in that processor and what is checked
instead.
"""
from __future__ import annotations

import dataclasses
import json
from typing import Any

from evidence import evidence_record as er

SCOPE_NAME = "modaas.evidence"

# SEVERITY_NUMBER_INFO in the OTLP logs data model. Evidence records are not
# diagnostics: every one is a fact about a governed call, so they all carry the
# same severity and a sink filtering on severity never drops half the trail.
_SEVERITY_NUMBER = 9
_SEVERITY_TEXT = "INFO"

# The resource attributes the collector's k8sattributes processor is configured
# to extract, and therefore the only ones a reader may rely on. The chart-side
# half of this coupling is asserted in deploy/tests/test_evidence_chart.py; a
# key added here without adding it to the processor config yields an empty stamp
# and refuses every decision record.
STAMP_KEYS: tuple[str, ...] = (
    "k8s.namespace.name", "k8s.deployment.name", "k8s.pod.name",
)


def _kv(attributes: dict[str, str]) -> list[dict[str, Any]]:
    return [{"key": k, "value": {"stringValue": str(v)}} for k, v in attributes.items()]


def to_otlp_logs(
    records: list[er.EvidenceRecord], resource_attributes: dict[str, str]
) -> dict[str, Any]:
    """One OTLP/HTTP `ExportLogsServiceRequest` body for a batch of records.

    An empty batch produces `{"resourceLogs": []}` rather than a one-element
    list with no log records, so a caller can cheaply decide not to POST.
    """
    if not records:
        return {"resourceLogs": []}

    log_records: list[dict[str, Any]] = []
    for record in records:
        payload = record.to_dict()
        parsed = er.parse_ts(record.ts)
        # An unparseable ts cannot reach here through `parse()`, but the emitter
        # is a best-effort path and must not raise on the way to the queue.
        nanos = int(parsed.timestamp() * 1_000_000_000) if parsed else 0
        entry: dict[str, Any] = {
            "timeUnixNano": str(nanos),
            "observedTimeUnixNano": str(nanos),
            "severityNumber": _SEVERITY_NUMBER,
            "severityText": _SEVERITY_TEXT,
            # The WHOLE record, so a sink configured with `raw_log: true`
            # (message = body alone) loses nothing.
            "body": {"stringValue": json.dumps(payload, sort_keys=False)},
            "attributes": _kv(record.to_attributes()),
        }
        if record.trace_id:
            # a design note point 8: the same key the traces pipeline carries, so a
            # trace viewer can badge the governed hop. Omitted rather than
            # zero-filled when absent -- an all-zero traceId is OTLP's "no
            # trace" and would render as one shared trace joining every
            # unjoinable call.
            entry["traceId"] = record.trace_id
        log_records.append(entry)

    return {
        "resourceLogs": [
            {
                "resource": {"attributes": _kv(resource_attributes)},
                "scopeLogs": [
                    {
                        "scope": {"name": SCOPE_NAME, "version": er.SCHEMA_VERSION},
                        "logRecords": log_records,
                    }
                ],
            }
        ]
    }


@dataclasses.dataclass(frozen=True)
class DecodedRecord:
    """One record read back out of a sink, with the stamp it arrived under."""

    record: er.EvidenceRecord
    stamp: dict[str, str]


def decode_log_envelope(
    message: str | bytes | dict, problems: list[str] | None = None
) -> DecodedRecord | None:
    """A stored log message -> `DecodedRecord`, or None if it is not evidence.

    Returns None rather than raising. One malformed line on a shared log stream
    must not empty an approver's timeline, which is what an exception on the
    read path would do. Pass `problems` to collect the reason each skipped
    message was skipped -- silent skipping is right for the hot path and useless
    when the question is why a timeline is empty.
    """
    envelope = _load(message)
    if envelope is None:
        _note(problems, f"message is not JSON: {str(message)[:120]!r}")
        return None

    if isinstance(envelope, dict) and "body" in envelope:
        raw = _load(envelope["body"]) if not isinstance(envelope["body"], dict) \
            else envelope["body"]
        stamp_source = envelope.get("resource") or {}
    else:
        raw = envelope            # a bare record, no envelope (jsonl sinks)
        stamp_source = {}

    if not isinstance(raw, dict):
        _note(problems, "log body is not a JSON object")
        return None

    errors = er.validate(raw)
    if errors:
        _note(problems, "; ".join(errors))
        return None

    stamp = {
        key: str(stamp_source[key])
        for key in STAMP_KEYS
        if isinstance(stamp_source, dict) and stamp_source.get(key) is not None
    }
    return DecodedRecord(record=er.parse(raw), stamp=stamp)


def _load(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    if not isinstance(value, str):
        return None
    try:
        return json.loads(value)
    except ValueError:
        return None


def _note(problems: list[str] | None, message: str) -> None:
    if problems is not None:
        problems.append(message)


@dataclasses.dataclass(frozen=True)
class Attestor:
    """Which workload's stamp makes a `phase: decision` record admissible.

    Configuration, not a literal: a deployment that renames the doorman or runs
    it in another namespace must be able to say so, and a hardcoded pair would
    silently refuse every decision record there -- emptying the one half of the
    timeline that is not self-reported.
    """

    namespace: str
    deployment: str

    def accepts(self, decoded: DecodedRecord | None) -> bool:
        """True when this record may be rendered as evidence.

        Non-decision phases are accepted unstamped: they are claims by their
        writer and the timeline renders them as such. Only the decision phase
        carries the platform's own attestation, and only there does the stamp
        decide admission.
        """
        if decoded is None:
            return False
        if not er.is_platform_attested(decoded.record):
            return True
        return (
            decoded.stamp.get("k8s.namespace.name") == self.namespace
            and decoded.stamp.get("k8s.deployment.name") == self.deployment
        )
