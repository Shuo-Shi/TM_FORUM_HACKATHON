#!/usr/bin/env python3
"""evaluate.py - stateless control test for controls 7, 9, and 16.

Examples:
    python3 evaluate.py 7 fault-1791231916-58a47b --register ~/starter/register.yaml
    python3 evaluate.py 9 fault-1791231916-58a47b --register ~/starter/register.yaml
    python3 evaluate.py 16 fault-1791231916-58a47b --register ~/starter/register.yaml
    python3 evaluate.py all fault-1791231916-58a47b --json
    python3 evaluate.py 9 --from 2026-10-05T19:50:00Z --to 2026-10-05T20:05:00Z

Reads:
  - register.yaml
  - gateway-log.json and optional archive/gateway.log
  - optional baseline-*.json for Control 9 baseline provenance

Writes one content-hashed verdict record per evaluation to:
  ~/evidence/verdicts/

Exit codes:
  0 = all evaluated controls PASS
  1 = at least one BREACH
  2 = NO EVIDENCE or configuration error
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

HOME = Path.home()
KV = re.compile(r'(\S+?)=("(?:[^"\\]|\\.)*"|\S*)')


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------
def _scalar(value: str):
    value = value.strip().strip('"\'')
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    try:
        return float(value) if "." in value else int(value)
    except ValueError:
        return value


def _load_register(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(f"register not found: {path}")

    text = path.read_text()
    if yaml is not None:
        doc = yaml.safe_load(text) or {}
        return {
            str(control["control_id"]): control
            for control in doc.get("controls", [])
        }

    # Limited fallback for top-level control fields plus one nested map level.
    # Installing PyYAML is strongly recommended for the full register schema.
    controls, current, subsection, subsection_indent = {}, None, None, None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        if stripped.startswith("- control_id:"):
            if current:
                controls[str(current["control_id"])] = current
            current = {
                "control_id": str(_scalar(stripped.split(":", 1)[1]))
            }
            subsection = None
            continue

        if current is None or ":" not in stripped:
            continue

        key, value = stripped.split(":", 1)
        if subsection is not None and indent > subsection_indent:
            current[subsection][key] = _scalar(value)
            continue

        subsection = None
        if value.strip() == "":
            subsection, subsection_indent = key, indent
            current[key] = {}
        else:
            current[key] = _scalar(value)

    if current:
        controls[str(current["control_id"])] = current
    return controls


def _threshold(control: dict) -> dict:
    threshold = dict(control.get("threshold") or {})
    threshold.setdefault("limit", control.get("observation_limit"))
    threshold.setdefault("version", control.get("version"))
    threshold.setdefault("effective_date", control.get("version_date"))
    threshold.setdefault(
        "exception_tolerance", control.get("exception_tolerance", 0)
    )
    return threshold


def _owner(control: dict) -> str:
    return (
        (control.get("governance") or {}).get("owner")
        or control.get("owner")
        or "?"
    )


def _required_threshold_fields(control_id: str) -> tuple[str, ...]:
    common = ("version", "effective_date")
    if control_id == "7":
        return common + (
            "coverage_limit",
            "gap_limit_ms",
            "violating_gap_allowance_percent",
        )
    if control_id == "9":
        return common + ("baseline_value", "drift_limit_percent")
    if control_id == "16":
        return common + ("limit",)
    return common


# ---------------------------------------------------------------------------
# Evidence loading
# ---------------------------------------------------------------------------
def _parse_ts(value: str) -> datetime:
    value = str(value).strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _record_timestamp(record: dict) -> datetime | None:
    candidates = (
        record.get("_ts"),
        record.get("timestamp"),
        record.get("time"),
    )
    for candidate in candidates:
        if candidate:
            try:
                return _parse_ts(candidate)
            except (TypeError, ValueError):
                pass

    raw = str(record.get("_raw") or "")
    if raw:
        first = raw.split("\t", 1)[0].strip()
        try:
            return _parse_ts(first)
        except (TypeError, ValueError):
            pass
    return None


def _from_gateway_line(line: str) -> dict:
    record = {key: value.strip('"') for key, value in KV.findall(line)}
    record["_ts"] = line.split("\t", 1)[0].strip()
    record["_raw"] = line
    return record


def _gateway_dedup_key(record: dict) -> str:
    action_id = record.get("modaas.action_id")
    if action_id:
        return f"action:{action_id}"
    return "fallback:" + "|".join(
        str(record.get(field) or "")
        for field in (
            "modaas.run_id",
            "trace.id",
            "span.id",
            "_ts",
            "http.path",
            "mcp.method.name",
        )
    )


def _load_gateway(evidence_dir: Path) -> list[dict]:
    """Load gateway evidence while preserving incomplete records.

    Records missing action IDs are retained so Control 7 can identify them as
    coverage gaps. Records are de-duplicated using action ID when available and
    a composite fallback key otherwise.
    """
    seen: set[str] = set()
    records: list[dict] = []

    def add(record: dict):
        key = _gateway_dedup_key(record)
        if key not in seen:
            seen.add(key)
            records.append(record)

    path = evidence_dir / "gateway-log.json"
    if path.exists():
        try:
            doc = json.loads(path.read_text())
            source = doc.get("records", []) if isinstance(doc, dict) else doc
            for item in source:
                if not isinstance(item, dict):
                    continue
                parsed = _from_gateway_line(item["_raw"]) if item.get("_raw") else dict(item)
                # Preserve parsed JSON fields not represented in _raw.
                for key, value in item.items():
                    parsed.setdefault(key, value)
                add(parsed)
        except (ValueError, KeyError, TypeError):
            pass

    archive = evidence_dir / "archive" / "gateway.log"
    if archive.exists():
        for line in archive.read_text().splitlines():
            if "modaas.run_id=" in line:
                add(_from_gateway_line(line))

    return records


def _load_baseline(evidence_dir: Path, explicit_path: str | None):
    files = (
        [explicit_path]
        if explicit_path
        else sorted(glob.glob(str(evidence_dir / "baseline-*.json")))
    )
    if not files:
        return None, None
    selected = Path(files[-1])
    try:
        return json.loads(selected.read_text()), str(selected)
    except (OSError, ValueError):
        return None, str(selected)


def _load_runs(evidence_dir: Path) -> dict:
    runs = {}
    path = evidence_dir / "run-ids.txt"
    if path.exists():
        for line in path.read_text().splitlines():
            parts = [part.strip() for part in line.split(",")]
            if len(parts) >= 2 and parts[0]:
                runs[parts[0]] = parts[1]
    return runs


# ---------------------------------------------------------------------------
# Shared metric helpers
# ---------------------------------------------------------------------------
def _duration_ms(value) -> float | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    try:
        if text.endswith("ms"):
            return float(text[:-2])
        if text.endswith("us") or text.endswith("µs"):
            return float(text[:-2]) / 1000.0
        if text.endswith("s"):
            return float(text[:-1]) * 1000.0
        return float(text)
    except (TypeError, ValueError):
        return None


def _run_records(evidence: dict, run_id: str) -> list[dict]:
    return [
        record
        for record in evidence["gw"]
        if record.get("modaas.run_id") == run_id
    ]


def _unique(values) -> list[str]:
    return list(dict.fromkeys(str(value) for value in values if value))


# ---------------------------------------------------------------------------
# Control 16: per-run token spend cap
# ---------------------------------------------------------------------------
def _control_16_token_spend(evidence: dict, run_id: str, threshold: dict):
    records = _run_records(evidence, run_id)
    token_calls = [
        record
        for record in records
        if record.get("gen_ai.usage.input_tokens") is not None
        or record.get("gen_ai.usage.output_tokens") is not None
    ]

    if not token_calls:
        return "NO EVIDENCE", {
            "message": f"No token-bearing gateway records found for run {run_id}"
        }

    total = 0
    invalid_token_records = 0
    for record in token_calls:
        try:
            total += int(record.get("gen_ai.usage.input_tokens", 0) or 0)
            total += int(record.get("gen_ai.usage.output_tokens", 0) or 0)
        except (TypeError, ValueError):
            invalid_token_records += 1

    try:
        limit = float(threshold["limit"])
    except (KeyError, TypeError, ValueError):
        return "NO EVIDENCE", {"message": "Control 16 threshold.limit is invalid"}

    verdict = "PASS" if total <= limit else "BREACH"
    return verdict, {
        "measured_value": total,
        "unit": "tokens",
        "threshold_limit": limit,
        "record_count": len(token_calls),
        "invalid_record_count": invalid_token_records,
        "call_ids": _unique(
            record.get("modaas.action_id") for record in token_calls
        ),
    }


# ---------------------------------------------------------------------------
# Control 7: event completeness and timing-gap compliance
# ---------------------------------------------------------------------------
def _control_7_event_recording(evidence: dict, run_id: str, threshold: dict):
    records = _run_records(evidence, run_id)
    if not records:
        return "NO EVIDENCE", {
            "message": f"No gateway records found for run {run_id}"
        }

    valid_records = 0
    missing_records = []
    trace_ids = set()
    timestamps: list[datetime] = []

    for index, record in enumerate(records):
        action_id = record.get("modaas.action_id")
        trace_id = record.get("trace.id") or record.get("modaas.trace_id")
        has_run_id = bool(record.get("modaas.run_id"))
        has_trace_id = bool(trace_id)
        has_action_id = bool(action_id)

        if trace_id:
            trace_ids.add(str(trace_id))

        if has_run_id and has_trace_id and has_action_id:
            valid_records += 1
        else:
            missing_records.append(
                {
                    "record_index": index,
                    "action_id": action_id,
                    "missing_fields": [
                        name
                        for name, present in (
                            ("modaas.run_id", has_run_id),
                            ("trace.id/modaas.trace_id", has_trace_id),
                            ("modaas.action_id", has_action_id),
                        )
                        if not present
                    ],
                }
            )

        timestamp = _record_timestamp(record)
        if timestamp is not None:
            timestamps.append(timestamp)

    coverage_percent = (valid_records / len(records)) * 100.0

    try:
        coverage_limit = float(threshold["coverage_limit"])
        gap_limit_ms = float(threshold["gap_limit_ms"])
        gap_allowance_percent = float(
            threshold["violating_gap_allowance_percent"]
        )
    except (KeyError, TypeError, ValueError):
        return "NO EVIDENCE", {
            "message": (
                "Control 7 requires numeric coverage_limit, gap_limit_ms, "
                "and violating_gap_allowance_percent"
            )
        }

    timestamps.sort()
    gaps_ms = [
        (timestamps[index] - timestamps[index - 1]).total_seconds() * 1000.0
        for index in range(1, len(timestamps))
    ]
    violating_gap_values = [gap for gap in gaps_ms if gap >= gap_limit_ms]

    total_gaps = len(gaps_ms)
    violating_gaps = len(violating_gap_values)
    violating_gap_percent = (
        violating_gaps / total_gaps * 100.0 if total_gaps else None
    )

    coverage_ok = coverage_percent >= coverage_limit
    timestamps_complete = len(timestamps) == len(records)
    gap_testable = total_gaps > 0 and timestamps_complete
    gap_ok = (
        gap_testable
        and violating_gap_percent is not None
        and violating_gap_percent <= gap_allowance_percent
    )

    verdict = "PASS" if coverage_ok and gap_ok else "BREACH"
    notes = []
    if not timestamps_complete:
        notes.append(
            f"timestamp coverage incomplete: {len(timestamps)}/{len(records)} records"
        )
    if total_gaps == 0:
        notes.append("gap test unavailable: fewer than two parseable timestamps")

    return verdict, {
        "measured_value": {
            "coverage_percent": round(coverage_percent, 2),
            "violating_gap_percent": (
                round(violating_gap_percent, 2)
                if violating_gap_percent is not None
                else None
            ),
        },
        "coverage_percent": round(coverage_percent, 2),
        "coverage_limit": coverage_limit,
        "total_records": len(records),
        "valid_records": valid_records,
        "missing_record_count": len(missing_records),
        "missing_records": missing_records,
        "timestamp_count": len(timestamps),
        "total_gaps": total_gaps,
        "violating_gaps": violating_gaps,
        "violating_gap_percent": (
            round(violating_gap_percent, 2)
            if violating_gap_percent is not None
            else None
        ),
        "gap_limit_ms": gap_limit_ms,
        "gap_allowance_percent": gap_allowance_percent,
        "max_gap_ms": round(max(gaps_ms), 3) if gaps_ms else None,
        "violating_gap_values_ms": [
            round(value, 3) for value in violating_gap_values
        ],
        "trace_count": len(trace_ids),
        "call_ids": _unique(
            record.get("modaas.action_id") for record in records
        ),
        "message": "; ".join(notes),
    }


# ---------------------------------------------------------------------------
# Control 9: latency degradation against a frozen baseline
# ---------------------------------------------------------------------------
def _baseline_latency_ms(
    baseline: dict | None,
    run_id: str,
    threshold: dict,
    scenario: str | None,
) -> tuple[float | None, str]:
    """Resolve baseline with explicit file values preferred over register values.

    Supported baseline JSON examples:
      {"average_request_duration_ms": 1500}
      {"latency_baseline_ms": 1500}
      {"controls": {"9": {"baseline_value": 1500}}}
      {"scenarios": {"S1": {"average_request_duration_ms": 1500}}}
    """
    if isinstance(baseline, dict):
        if scenario:
            scenario_doc = (baseline.get("scenarios") or {}).get(scenario)
            if isinstance(scenario_doc, dict):
                for key in ("average_request_duration_ms", "latency_baseline_ms", "baseline_value"):
                    if scenario_doc.get(key) is not None:
                        try:
                            return float(scenario_doc[key]), f"baseline file scenario {scenario}"
                        except (TypeError, ValueError):
                            pass

        control_doc = (baseline.get("controls") or {}).get("9")
        if isinstance(control_doc, dict):
            for key in ("average_request_duration_ms", "latency_baseline_ms", "baseline_value"):
                if control_doc.get(key) is not None:
                    try:
                        return float(control_doc[key]), "baseline file control 9"
                    except (TypeError, ValueError):
                        pass

        for key in ("average_request_duration_ms", "latency_baseline_ms", "baseline_value"):
            if baseline.get(key) is not None:
                try:
                    return float(baseline[key]), "baseline file"
                except (TypeError, ValueError):
                    pass

    try:
        return float(threshold["baseline_value"]), "register threshold"
    except (KeyError, TypeError, ValueError):
        return None, "missing"


def _control_9_drift(evidence: dict, run_id: str, threshold: dict):
    records = _run_records(evidence, run_id)
    if not records:
        return "NO EVIDENCE", {
            "message": f"No gateway records found for run {run_id}"
        }

    duration_records = []
    for record in records:
        measured = _duration_ms(record.get("duration"))
        if measured is not None:
            duration_records.append((record, measured))

    if not duration_records:
        return "NO EVIDENCE", {
            "message": f"No duration measurements found for run {run_id}"
        }

    current_average_ms = sum(item[1] for item in duration_records) / len(
        duration_records
    )
    scenario = evidence.get("runs", {}).get(run_id)
    baseline_ms, baseline_source = _baseline_latency_ms(
        evidence.get("baseline"), run_id, threshold, scenario
    )
    if baseline_ms is None or baseline_ms <= 0:
        return "NO EVIDENCE", {
            "message": "No valid positive Control 9 latency baseline"
        }

    try:
        drift_limit_percent = float(threshold["drift_limit_percent"])
    except (KeyError, TypeError, ValueError):
        return "NO EVIDENCE", {
            "message": "Control 9 drift_limit_percent is invalid"
        }

    # Signed latency change: negative is improvement; positive is degradation.
    drift_percent = (
        (current_average_ms - baseline_ms) / baseline_ms
    ) * 100.0
    verdict = "PASS" if drift_percent <= drift_limit_percent else "BREACH"

    interpretation = (
        f"{abs(drift_percent):.2f}% latency improvement versus baseline"
        if drift_percent < 0
        else f"{drift_percent:.2f}% latency degradation versus baseline"
    )

    return verdict, {
        "measured_value": round(current_average_ms, 2),
        "unit": "ms average latency",
        "baseline_value": round(baseline_ms, 2),
        "baseline_source": baseline_source,
        "current_value": round(current_average_ms, 2),
        "drift_percent": round(drift_percent, 2),
        "drift_limit_percent": drift_limit_percent,
        "interpretation": interpretation,
        "record_count": len(duration_records),
        "scenario": scenario,
        "call_ids": _unique(
            record.get("modaas.action_id") for record, _ in duration_records
        ),
        "message": (
            f"baseline source: {baseline_source}"
            + (
                f" ({evidence.get('baseline_file')})"
                if baseline_source.startswith("baseline file")
                and evidence.get("baseline_file")
                else ""
            )
        ),
    }


_METRICS = {
    "7": _control_7_event_recording,
    "9": _control_9_drift,
    "16": _control_16_token_spend,
}


# ---------------------------------------------------------------------------
# Verdict records and output
# ---------------------------------------------------------------------------
def _jsonable(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    return value


def _write_verdict(
    out_dir: Path,
    control_id: str,
    entry: dict,
    threshold: dict,
    run_id: str,
    window,
    verdict: str,
    result: dict,
) -> tuple[Path, dict]:
    record = {
        "control_id": control_id,
        "control_name": entry.get("name"),
        "run_id": run_id,
        "window_utc": window,
        "verdict": verdict,
        "measured_value": result.get("measured_value"),
        "threshold": threshold,
        "threshold_version": threshold.get("version"),
        "effective_date": threshold.get("effective_date"),
        "owner": _owner(entry),
        "evidence_ids": result.get("call_ids", []),
        "evidence_count": result.get(
            "record_count", result.get("total_records")
        ),
        "result": result,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }
    canonical = json.dumps(record, sort_keys=True, default=_jsonable).encode()
    record["sha256"] = hashlib.sha256(canonical).hexdigest()

    out_dir.mkdir(parents=True, exist_ok=True)
    safe_run_id = re.sub(r"[^A-Za-z0-9_.-]", "_", run_id)
    path = out_dir / (
        f"v-{control_id}-{safe_run_id}-{record['sha256'][:12]}.json"
    )
    path.write_text(json.dumps(record, indent=2, default=_jsonable))
    return path, record


def _print_result(
    control_id: str,
    entry: dict,
    threshold: dict,
    run_id: str,
    window,
    verdict: str,
    result: dict,
    verdict_file: Path,
):
    print(f"CONTROL_ID        : {control_id}")
    print(f"CONTROL_NAME      : {entry.get('name', '?')}")
    print(f"RUN_ID            : {run_id}")
    if window:
        print(f"WINDOW_UTC        : {window[0]} -> {window[1]}")
    print()
    print(f"THRESHOLD_VERSION : {threshold.get('version')}")
    print(f"EFFECTIVE_DATE    : {threshold.get('effective_date')}")
    print(f"OWNER             : {_owner(entry)}")

    if control_id == "7":
        print(f"COVERAGE_LIMIT    : {threshold.get('coverage_limit')}")
        print(f"GAP_LIMIT_MS      : {threshold.get('gap_limit_ms')}")
        print(
            "GAP_ALLOWANCE_PCT : "
            f"{threshold.get('violating_gap_allowance_percent')}"
        )
    elif control_id == "9":
        print(f"BASELINE_VALUE    : {result.get('baseline_value', threshold.get('baseline_value'))}")
        print(f"DRIFT_LIMIT_PCT   : {threshold.get('drift_limit_percent')}")
    elif control_id == "16":
        print(f"TOKEN_LIMIT       : {threshold.get('limit')}")

    print()
    print(f"VERDICT           : {verdict}")

    ordered_fields = (
        ("measured_value", "MEASURED_VALUE"),
        ("unit", "UNIT"),
        ("coverage_percent", "COVERAGE_PERCENT"),
        ("total_records", "TOTAL_RECORDS"),
        ("valid_records", "VALID_RECORDS"),
        ("missing_record_count", "MISSING_RECORDS"),
        ("timestamp_count", "TIMESTAMP_COUNT"),
        ("total_gaps", "TOTAL_GAPS"),
        ("violating_gaps", "VIOLATING_GAPS"),
        ("max_gap_ms", "MAX_GAP_MS"),
        ("violating_gap_percent", "VIOLATING_GAP_PCT"),
        ("trace_count", "TRACE_COUNT"),
        ("current_value", "CURRENT_VALUE"),
        ("drift_percent", "DRIFT_PERCENT"),
        ("interpretation", "INTERPRETATION"),
        ("record_count", "EVIDENCE_COUNT"),
    )
    for key, label in ordered_fields:
        if key in result and result[key] is not None:
            print(f"{label:<18}: {result[key]}")

    if result.get("call_ids"):
        print(f"EVIDENCE_IDS      : {', '.join(result['call_ids'])}")
    if result.get("message"):
        print(f"NOTE              : {result['message']}")
    print(f"VERDICT_FILE      : {verdict_file}")
    print("-" * 78)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate controls 7, 9, and 16 by run or UTC window."
    )
    parser.add_argument("control_id", help="7, 9, 16, or all")
    parser.add_argument("run_id", nargs="?", help="run/correlation ID")
    parser.add_argument("--from", dest="frm", help="UTC window start")
    parser.add_argument("--to", dest="to", help="UTC window end")
    parser.add_argument(
        "--evidence-dir", default=str(HOME / "evidence")
    )
    parser.add_argument(
        "--register",
        default=str(Path(__file__).with_name("register.yaml")),
    )
    parser.add_argument("--baseline", default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if not args.run_id and not (args.frm and args.to):
        print("provide a run_id, or both --from and --to", file=sys.stderr)
        return 2

    if args.control_id != "all" and args.control_id not in _METRICS:
        print("control_id must be 7, 9, 16, or all", file=sys.stderr)
        return 2

    register_path = Path(args.register).expanduser()
    evidence_dir = Path(args.evidence_dir).expanduser()

    try:
        controls = _load_register(register_path)
    except (OSError, ValueError, KeyError) as exc:
        print(f"cannot load register: {exc}", file=sys.stderr)
        return 2

    control_ids = list(_METRICS) if args.control_id == "all" else [args.control_id]
    baseline, baseline_file = _load_baseline(evidence_dir, args.baseline)
    evidence = {
        "gw": _load_gateway(evidence_dir),
        "runs": _load_runs(evidence_dir),
        "baseline": baseline,
        "baseline_file": baseline_file,
    }

    window = (args.frm, args.to) if args.frm else None
    if args.run_id:
        run_ids = [args.run_id]
    else:
        try:
            lower, upper = _parse_ts(args.frm), _parse_ts(args.to)
        except (TypeError, ValueError) as exc:
            print(f"invalid UTC window: {exc}", file=sys.stderr)
            return 2

        run_ids = sorted(
            {
                record["modaas.run_id"]
                for record in evidence["gw"]
                if record.get("modaas.run_id")
                and (timestamp := _record_timestamp(record)) is not None
                and lower <= timestamp <= upper
            }
        )
        if not run_ids:
            print(
                f"VERDICT: NO EVIDENCE - no runs found in window "
                f"{args.frm} -> {args.to}"
            )
            return 2

    out_dir = evidence_dir / "verdicts"
    worst_exit = 0
    output_records = []

    for control_id in control_ids:
        entry = controls.get(control_id)
        if entry is None:
            print(
                f"control {control_id} not found in {register_path}",
                file=sys.stderr,
            )
            worst_exit = max(worst_exit, 2)
            continue

        threshold = _threshold(entry)
        required = _required_threshold_fields(control_id)
        missing = [
            field
            for field in required
            if threshold.get(field) in (None, "")
        ]
        if missing:
            print(
                f"control {control_id}: configuration error - missing "
                f"{', '.join(missing)}",
                file=sys.stderr,
            )
            worst_exit = max(worst_exit, 2)
            continue

        evaluator = _METRICS[control_id]
        for run_id in run_ids:
            verdict, result = evaluator(evidence, run_id, threshold)
            verdict_file, verdict_record = _write_verdict(
                out_dir,
                control_id,
                entry,
                threshold,
                run_id,
                window,
                verdict,
                result,
            )
            output_records.append(verdict_record)
            worst_exit = max(
                worst_exit,
                {"PASS": 0, "BREACH": 1}.get(verdict, 2),
            )
            if not args.json:
                _print_result(
                    control_id,
                    entry,
                    threshold,
                    run_id,
                    window,
                    verdict,
                    result,
                    verdict_file,
                )

    if args.json:
        print(json.dumps(output_records, indent=2, default=_jsonable))
    return worst_exit


if __name__ == "__main__":
    sys.exit(main())
