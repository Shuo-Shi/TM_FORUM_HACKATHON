#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from datetime import datetime
import re

try:
    import yaml
except ImportError:
    yaml = None


def _load_register(path: Path) -> dict:
    text = path.read_text()
    if yaml is not None:
        doc = yaml.safe_load(text)
        controls = {str(c['control_id']): c for c in doc.get('controls', [])}
        return controls

    controls, cur = {}, None
    for raw in text.splitlines():
        line = raw.split('#', 1)[0].rstrip()
        if not line.strip():
            continue
        if line.lstrip().startswith('- control_id:'):
            if cur:
                controls[str(cur['control_id'])] = cur
            cur = {'control_id': line.split(':', 1)[1].strip().strip('"\'')}
        elif cur is not None and ':' in line:
            k, v = line.strip().split(':', 1)
            cur[k] = v.strip().strip('"\'')
    if cur:
        controls[str(cur['control_id'])] = cur
    return controls


def _load_evidence(evidence_dir: Path) -> dict:
    out = {}
    for name in ('tmf639', 'cr-status', 'approvals', 'gateway-log', 'registry', 'otel-traces'):
        p = evidence_dir / f'{name}.json'
        try:
            out[name] = json.loads(p.read_text())
        except FileNotFoundError:
            out[name] = None
    return out


def _get_threshold(control: dict) -> dict:
    return control.get('threshold', {})


def _control_16_token_spend(evidence: dict, run_id: str, control: dict):
    gw = evidence.get('gateway-log') or {'records': []}

    records = [
        r for r in gw.get('records', [])
        if r.get('modaas.run_id') == run_id
    ]

    if not records:
        return 'NO EVIDENCE', {
            'message': f'No gateway-log record found for run {run_id}'
        }

    total = 0
    call_ids = []

    for r in records:
        try:
            total += int(r.get('gen_ai.usage.input_tokens', 0))
            total += int(r.get('gen_ai.usage.output_tokens', 0))
        except (TypeError, ValueError):
            pass

        aid = r.get('modaas.action_id')
        if aid:
            call_ids.append(aid)

    th = _get_threshold(control)
    limit = th.get('limit')

    try:
        limit = float(limit)
    except (TypeError, ValueError):
        return 'BREACH', {
            'message': f'register.yaml has no numeric threshold.limit (got {limit!r})'
        }

    verdict = 'PASS' if total <= limit else 'BREACH'

    return verdict, {
        'measured_value': total,
        'threshold_limit': limit,
        'record_count': len(records),
        'call_ids': call_ids,
    }

def _control_7_event_recording(evidence: dict, run_id: str, control: dict):
    """
    Control 7 - Automatic event recording

    Measures:
      - Event recording coverage
      - Traceability (run_id / trace.id / action_id)
      - Gap timing compliance
    """

    gw = evidence.get("gateway-log") or {"records": []}

    records = [
        r for r in gw.get("records", [])
        if r.get("modaas.run_id") == run_id
    ]

    if not records:
        return "NO EVIDENCE", {
            "message": f"No gateway-log record found for run {run_id}"
        }

    valid_records = 0
    missing_records = []

    call_ids = []
    trace_ids = set()

    timestamps = []

    for idx, r in enumerate(records):

        action_id = r.get("modaas.action_id")
        trace_id = r.get("trace.id")

        if action_id:
            call_ids.append(action_id)

        if trace_id:
            trace_ids.add(trace_id)

        has_run_id = bool(r.get("modaas.run_id"))
        has_trace_id = bool(trace_id)
        has_action_id = bool(action_id)

        if has_run_id and has_trace_id and has_action_id:
            valid_records += 1
        else:
            missing_records.append(idx)

        # Extract timestamp from _raw
        raw = r.get("_raw", "")

        try:
            ts = raw.split("\t", 1)[0]
            timestamps.append(
                datetime.fromisoformat(
                    ts.replace("Z", "+00:00")
                )
            )
        except Exception:
            pass

    #
    # Coverage check
    #
    coverage_pct = (
        valid_records / len(records)
    ) * 100

    #
    # Gap check
    #
    timestamps.sort()

    total_gaps = 0
    violating_gaps = 0

    th = _get_threshold(control)

    gap_limit_ms = float(
        th.get("gap_limit_ms", 5)
    )

    for i in range(1, len(timestamps)):

        gap_ms = (
            timestamps[i] - timestamps[i - 1]
        ).total_seconds() * 1000

        total_gaps += 1

        if gap_ms > gap_limit_ms:
            violating_gaps += 1

    violating_gap_pct = (
        (violating_gaps / total_gaps) * 100
        if total_gaps > 0
        else 0
    )

    #
    # Thresholds
    #
    try:
        coverage_limit = float(
            th.get("coverage_limit")
        )

        violating_gap_allowance = float(
            th.get(
                "violating_gap_allowance_percent"
            )
        )

    except (TypeError, ValueError):

        return "BREACH", {
            "message":
                "register.yaml missing "
                "coverage_limit or "
                "violating_gap_allowance_percent"
        }

    coverage_ok = (
        coverage_pct >= coverage_limit
    )

    gap_ok = (
        violating_gap_pct
        <= violating_gap_allowance
    )

    verdict = (
        "PASS"
        if coverage_ok and gap_ok
        else "BREACH"
    )

    return verdict, {
        "coverage_percent": round(
            coverage_pct, 2
        ),
        "total_records": len(records),
        "valid_records": valid_records,
        "missing_record_count": len(
            missing_records
        ),

        "total_gaps": total_gaps,
        "violating_gaps": violating_gaps,
        "violating_gap_percent": round(
            violating_gap_pct, 2
        ),
        "gap_limit_ms": gap_limit_ms,

        "trace_count": len(trace_ids),
        "call_ids": call_ids
    }

def _control_9_drift_and_performance(
        evidence: dict,
        run_id: str,
        control: dict):
    """
    Control 9 - Drift and Performance

    Measures relative performance drift against a
    frozen baseline.

    Drift % =
        ((baseline - current) / baseline) * 100

    PASS if drift <= configured drift limit.
    """

    gw = evidence.get("gateway-log") or {"records": []}

    records = [
        r for r in gw.get("records", [])
        if r.get("modaas.run_id") == run_id
    ]

    if not records:
        return "NO EVIDENCE", {
            "message": f"No gateway-log record found for run {run_id}"
        }

    durations_ms = []
    call_ids = []

    for r in records:

        duration = r.get("duration")

        if duration:
            try:
                if duration.endswith("ms"):
                    durations_ms.append(
                        float(duration.replace("ms", ""))
                    )

            except (TypeError, ValueError):
                pass

        action_id = r.get("modaas.action_id")
        if action_id:
            call_ids.append(action_id)

    if not durations_ms:
        return "NO EVIDENCE", {
            "message": (
                f"No duration measurements found "
                f"for run {run_id}"
            )
        }

    current_avg_ms = (
        sum(durations_ms) / len(durations_ms)
    )

    th = _get_threshold(control)

    try:
        baseline_ms = float(
            th.get("baseline_value")
        )

        drift_limit_pct = float(
            th.get("drift_limit_percent")
        )

    except (TypeError, ValueError):

        return "BREACH", {
            "message":
                "register.yaml missing baseline_value "
                "or drift_limit_percent"
        }

    drift_pct = (
        (current_avg_ms - baseline_ms)
        / baseline_ms
    ) * 100

    verdict = (
        "PASS"
        if drift_pct <= drift_limit_pct
        else "BREACH"
    )

    return verdict, {
        "baseline_value": round(baseline_ms, 2),
        "current_value": round(current_avg_ms, 2),
        "drift_percent": round(drift_pct, 2),
        "threshold_limit": drift_limit_pct,
        "window_count": len(durations_ms),
        "call_ids": call_ids
    }

_METRICS = {
    '16': _control_16_token_spend,
    '7': _control_7_event_recording,
    '9': _control_9_drift_and_performance,
}


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument('control_id')
    p.add_argument('run_id')
    p.add_argument('--evidence-dir', default=str(Path.home() / 'evidence'))
    p.add_argument('--register', default=str(Path(__file__).with_name('register.yaml')))
    args = p.parse_args(argv)

    controls = _load_register(Path(args.register))
    entry = controls.get(str(args.control_id))

    if entry is None:
        print(f'control {args.control_id} not found', file=sys.stderr)
        return 2

    th = entry.get('threshold', {})

    if not th.get('version'):
        print('BREACH: threshold version missing')
        return 1

    if not th.get('effective_date'):
        print('BREACH: threshold effective_date missing')
        return 1
    
    if args.control_id == "16":
        if not th.get("limit"):
            print("BREACH: threshold limit missing")
            return 1

    if args.control_id == "7":

        if not th.get("coverage_limit"):
            print("BREACH: coverage_limit missing")
            return 1

        if not th.get("gap_limit_ms"):
            print("BREACH: gap_limit_ms missing")
            return 1

        if not th.get("violating_gap_allowance_percent"):
            print("BREACH: violating_gap_allowance_percent missing")
            return 1

    if args.control_id == "9":
        if not th.get("baseline_value"):
            print("BREACH: baseline_value missing")
            return 1

        if not th.get("drift_limit_percent"):
            print("BREACH: drift_limit_percent missing")
            return 1

    fn = _METRICS.get(str(args.control_id))
    if fn is None:
        print(f'No evaluator implemented for control {args.control_id}')
        return 2

    owner = entry.get("governance", {}).get("owner", "?")

    evidence = _load_evidence(Path(args.evidence_dir))

    verdict, result = fn(evidence, args.run_id, entry)

    print(f'CONTROL_ID        : {args.control_id}')
    print(f'CONTROL_NAME      : {entry.get("name", "?")}')
    print(f'RUN_ID            : {args.run_id}')
    print()
    print(f'THRESHOLD_VERSION : {th.get("version")}')
    print(f'EFFECTIVE_DATE    : {th.get("effective_date")}')
    if args.control_id == "7":
        print(f'COVERAGE_LIMIT : {th.get("coverage_limit")}')
        print(f'GAP_LIMIT_MS : {th.get("gap_limit_ms")}')
        print(
            f'GAP_ALLOWANCE_PCT : '
            f'{th.get("violating_gap_allowance_percent")}'
        )
    elif args.control_id == "9":
        print(
            f'BASELINE_VALUE    : '
            f'{th.get("baseline_value")}'
        )
        print(
            f'DRIFT_LIMIT_PCT   : '
            f'{th.get("drift_limit_percent")}'
        )
    else:
        print(f'LIMIT             : {th.get("limit")}')
    print(f'OWNER             : {owner}')
    print()
    print(f'VERDICT           : {verdict}')

    if isinstance(result, dict):
        if 'measured_value' in result:
            print(f'MEASURED_VALUE    : {result["measured_value"]}')

        if 'coverage_percent' in result:
            print(
                f'COVERAGE_PERCENT : '
                f'{result["coverage_percent"]}'
            )

        if 'total_records' in result:
            print(
                f'TOTAL_RECORDS    : '
                f'{result["total_records"]}'
            )

        if 'valid_records' in result:
            print(
                f'VALID_RECORDS    : '
                f'{result["valid_records"]}'
            )

        if 'missing_record_count' in result:
            print(
                f'MISSING_RECORDS  : '
                f'{result["missing_record_count"]}'
            )
        if 'total_gaps' in result:
            print(f'TOTAL_GAPS        : {result["total_gaps"]}')

        if 'violating_gaps' in result:
            print(f'VIOLATING_GAPS    : {result["violating_gaps"]}')

        if 'gap_limit_ms' in result:
            print(f'GAP_LIMIT_MS      : {result["gap_limit_ms"]}')

        if 'violating_gap_percent' in result:
            print(
                f'VIOLATING_GAP_PCT : '
                f'{result["violating_gap_percent"]}'
            )
        if 'trace_count' in result:
            print(
                f'TRACE_COUNT : '
                f'{result["trace_count"]}'
            )
        if 'baseline_value' in result:
            print(
                f'BASELINE_VALUE   : '
                f'{result["baseline_value"]}'
            )

        if 'current_value' in result:
            print(
                f'CURRENT_VALUE    : '
                f'{result["current_value"]}'
            )

        if 'drift_percent' in result:
            print(
                f'DRIFT_PERCENT    : '
                f'{result["drift_percent"]}'
            )

        if 'window_count' in result:
            print(
                f'WINDOW_COUNT     : '
                f'{result["window_count"]}'
            )
        if 'record_count' in result:
            print(f'EVIDENCE_COUNT    : {result["record_count"]}')
        if result.get('call_ids'):
            print(f'CALL_IDS          : {", ".join(result["call_ids"])}')
        if result.get('message'):
            print(result['message'])

    return {'PASS': 0, 'NO EVIDENCE': 2}.get(verdict, 1)


if __name__ == '__main__':
    sys.exit(main())
