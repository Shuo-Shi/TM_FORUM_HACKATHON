#!/usr/bin/env python3
"""evaluate.py - stateless control test for controls 7, 9 and 16.

    python3 evaluate.py 16 fault-1791229889-88ce59
    python3 evaluate.py 9  --from 2026-10-05T19:50:00Z --to 2026-10-05T20:05:00Z
    python3 evaluate.py all fault-1791229889-88ce59 --json

Reads only: register.yaml (thresholds), gateway evidence (pull-evidence.sh's
gateway-log.json and/or the archived gateway.log), the ledger records, the
frozen baseline and run-ids.txt. Writes one hashed verdict file per evaluation
to ~/evidence/verdicts/. Window times are UTC.
Exit codes: 0 PASS, 1 BREACH, 2 NO EVIDENCE / config error.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

HOME = Path.home()
KV = re.compile(r'(\S+?)=("(?:[^"\\]|\\.)*"|\S*)')  # split on the FIRST '=' only
DISP = re.compile(r'disposition=([a-z-]+)')
AGENTS = ['customer-experience-agent', 'it-resolution-agent', 'network-resolution-agent']
PHASES = ['intent', 'invocation', 'result-inspection']


# --------------------------------------------------------------------------
# Register
# --------------------------------------------------------------------------
def _scalar(v: str):
    v = v.strip().strip('"\'')
    try:
        return float(v) if '.' in v else int(v)
    except ValueError:
        return v


def _load_register(path: Path) -> dict:
    text = path.read_text()
    if yaml is not None:
        doc = yaml.safe_load(text)
        return {str(c['control_id']): c for c in doc.get('controls', [])}

    # Fallback parser: list of controls with at most one level of nested maps
    # (threshold:, governance:), so the tool runs on a bare Python install.
    controls, cur, sub, sub_indent = {}, None, None, None
    for raw in text.splitlines():
        line = raw.split('#', 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        s = line.strip()
        if s.startswith('- control_id:'):
            if cur:
                controls[str(cur['control_id'])] = cur
            cur, sub = {'control_id': str(_scalar(s.split(':', 1)[1]))}, None
            continue
        if cur is None or ':' not in s:
            continue
        k, v = s.split(':', 1)
        if sub is not None and indent > sub_indent:
            cur[sub][k] = _scalar(v)
            continue
        sub = None
        if v.strip() == '':
            sub, sub_indent = k, indent
            cur[k] = {}
        else:
            cur[k] = _scalar(v)
    if cur:
        controls[str(cur['control_id'])] = cur
    return controls


def _threshold(control: dict) -> dict:
    """Accept the nested schema (threshold: {limit, version, effective_date})
    and the flat starter-kit schema (observation_limit, version, version_date)."""
    th = dict(control.get('threshold') or {})
    th.setdefault('limit', control.get('observation_limit'))
    th.setdefault('version', control.get('version'))
    th.setdefault('effective_date', control.get('version_date'))
    th.setdefault('exception_tolerance', control.get('exception_tolerance', 0))
    return th


def _owner(control: dict) -> str:
    return (control.get('governance') or {}).get('owner') or control.get('owner') or '?'


# --------------------------------------------------------------------------
# Evidence (pure reads)
# --------------------------------------------------------------------------
def _parse_ts(s: str) -> datetime:
    s = re.sub(r'(\.\d+)?(Z|[+-]\d\d:\d\d)?$', '', str(s).strip())
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)


def _load_gateway(evidence_dir: Path) -> list:
    """Gateway records from pull-evidence.sh (gateway-log.json) and from the
    archive (archive/gateway.log), de-duplicated by modaas.action_id."""
    seen, recs = set(), []

    def add(d):
        aid = d.get('modaas.action_id')
        if aid and aid not in seen:
            seen.add(aid)
            recs.append(d)

    def from_line(line):
        d = {k: v.strip('"') for k, v in KV.findall(line)}
        d['_ts'] = line.split('\t', 1)[0].strip()
        return d

    p = evidence_dir / 'gateway-log.json'
    if p.exists():
        try:
            doc = json.loads(p.read_text())
            for r in (doc.get('records', []) if isinstance(doc, dict) else doc):
                d = from_line(r['_raw']) if r.get('_raw') else dict(r)
                add(d)
        except (ValueError, KeyError):
            pass

    p = evidence_dir / 'archive' / 'gateway.log'
    if p.exists():
        for line in p.read_text().splitlines():
            if 'modaas.run_id=' in line:
                add(from_line(line))
    return recs


def _load_ledger(evidence_dir: Path) -> list:
    """Ledger records: archived snapshot first, live audit-store read as fallback."""
    raw = ''
    p = evidence_dir / 'archive' / 'ledger-records.json'
    if p.exists():
        raw = p.read_text()
    else:
        try:
            raw = subprocess.run(
                ['kubectl', 'get', '--raw',
                 '/api/v1/namespaces/components/services/audit-store:8080/proxy/records'],
                capture_output=True, text=True, timeout=20).stdout
        except Exception:
            raw = ''
    try:
        j = json.loads(raw)
        return j if isinstance(j, list) else j.get('records', [j])
    except ValueError:
        out = []
        for line in raw.splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
        return [r for r in out if isinstance(r, dict)]


def _load_runs(evidence_dir: Path) -> dict:
    runs = {}
    p = evidence_dir / 'run-ids.txt'
    if p.exists():
        for line in p.read_text().splitlines():
            parts = line.strip().split(',')
            if len(parts) >= 2:
                runs[parts[0]] = parts[1]
    return runs


def _load_baseline(evidence_dir: Path, path: str | None):
    files = [path] if path else sorted(glob.glob(str(evidence_dir / 'baseline-*.json')))
    return (json.loads(Path(files[-1]).read_text()), files[-1]) if files else (None, None)


def _alias_map() -> dict:
    try:
        out = subprocess.run(['kubectl', 'get', 'modelconfig', '-n', 'components', '-o', 'json'],
                             capture_output=True, text=True, timeout=20).stdout
        return {m['spec']['alias']: m['spec']['modelId'] for m in json.loads(out)['items']}
    except Exception:
        return {}


def _phase(r: dict) -> str:
    return str(r.get('phase') or r.get('type') or '').lower().replace('_', '-')


def _actor(r: dict) -> str:
    return str(r.get('actor') or r.get('agent') or '')


def _rid(r: dict) -> str:
    return str(r.get('record_id') or r.get('id') or r.get('action_id') or r.get('ts') or '?')


# --------------------------------------------------------------------------
# Metrics: (evidence, run_id, threshold) -> (verdict, result dict)
# --------------------------------------------------------------------------
def _limit(th):
    lim = float(th['limit'])
    return lim * (1 + float(th.get('exception_tolerance') or 0))


def _control_16_token_spend(ev, run_id, th):
    calls = [g for g in ev['gw'] if g.get('modaas.run_id') == run_id and g.get('listener') == 'llm']
    if not calls:
        return 'NO EVIDENCE', {'message': f'No gateway llm record found for run {run_id}'}
    total = 0
    for g in calls:
        try:
            total += int(g.get('gen_ai.usage.input_tokens', 0)) + int(g.get('gen_ai.usage.output_tokens', 0))
        except (TypeError, ValueError):
            pass
    lim = _limit(th)
    return ('PASS' if total <= lim else 'BREACH'), {
        'measured_value': f'{total} tokens across {len(calls)} model calls',
        'record_count': len(calls),
        'call_ids': [g['modaas.action_id'] for g in calls],
    }


def _control_7_event_recording(ev, run_id, th):
    led = [r for r in ev['ledger'] if r.get('correlation_id') == run_id]
    if not led:
        return 'NO EVIDENCE', {'message': f'No ledger records found for run {run_id}'}
    have = {(_actor(r), _phase(r)) for r in led}
    checks = {f'{a}:{p}': (a, p) in have for a in AGENTS for p in PHASES}
    inv = [r for r in led if _phase(r) == 'invocation']
    guarded = [r for r in inv if 'guardrail' in str(r.get('detail', '')).lower()]
    checks[f'guardrail verdict on every invocation ({len(guarded)}/{len(inv)})'] = (
        bool(inv) and len(guarded) == len(inv))
    checks['cross-domain negotiation recorded'] = any('negotiation' in _phase(r) for r in led)    
    gw_ids = {g['modaas.action_id'] for g in ev['gw'] if g.get('modaas.run_id') == run_id}
    claimed = [r.get('action_id') for r in inv if r.get('action_id')]
    checks['ledger action_ids found at gateway'] = all(a in gw_ids for a in claimed)

    score = sum(checks.values()) / len(checks)
    failed = [k for k, v in checks.items() if not v]
    return ('PASS' if score >= _limit(th) else 'BREACH'), {
        'measured_value': f'coverage {score:.2f} ({sum(checks.values())}/{len(checks)} checks)',
        'record_count': len(led),
        'call_ids': [_rid(r) for r in led],
        'message': ('failed: ' + '; '.join(failed)) if failed else '',
    }


def _control_9_drift(ev, run_id, th):
    base = ev['baseline']
    if not base:
        return 'NO EVIDENCE', {'message': 'No frozen baseline (~/evidence/baseline-*.json)'}
    calls = [g for g in ev['gw'] if g.get('modaas.run_id') == run_id and g.get('listener') == 'llm']
    led = [r for r in ev['ledger'] if r.get('correlation_id') == run_id]
    if not calls or not led:
        return 'NO EVIDENCE', {'message': f'Missing gateway or ledger evidence for run {run_id}'}

    allowed = {ev['alias_map'].get(a, a) for a in base.get('agents', {}).values() if a}
    drifted = sorted({g.get('gen_ai.request.model') for g in calls} - allowed)
    found = [(_actor(r), m.group(1)) for r in led for m in [DISP.search(json.dumps(r))] if m]
    disp = next((d for a, d in found if 'network' in a), found[-1][1] if found else None)
    scen = ev['runs'].get(run_id)
    expected = base.get('expected', {}).get(scen)

    ok_model = not drifted
    ok_disp = expected is None or disp == expected
    score = (ok_model + ok_disp) / 2
    return ('PASS' if score >= _limit(th) else 'BREACH'), {
        'measured_value': (f'models {"match baseline" if ok_model else "DRIFT: " + ", ".join(drifted)}; '
                           f'disposition {disp} vs expected {expected} ({scen or "scenario unknown"})'),
        'record_count': len(calls) + len(led),
        'call_ids': [g['modaas.action_id'] for g in calls],
        'message': f'baseline file: {ev["baseline_file"]}',
    }


_METRICS = {
    '16': _control_16_token_spend,
    '7': _control_7_event_recording,
    '9': _control_9_drift,
}


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------
def _print(cid, entry, th, run_id, window, verdict, result, verdict_file):
    print(f'CONTROL_ID        : {cid}')
    print(f'CONTROL_NAME      : {entry.get("name", "?")}')
    print(f'RUN_ID            : {run_id}')
    if window:
        print(f'WINDOW (UTC)      : {window[0]} -> {window[1]}')
    print()
    print(f'THRESHOLD_VERSION : {th.get("version")}')
    print(f'EFFECTIVE_DATE    : {th.get("effective_date")}')
    print(f'LIMIT             : {th.get("limit")}')
    print(f'OWNER             : {_owner(entry)}')
    print()
    print(f'VERDICT           : {verdict}')
    if result.get('measured_value') is not None:
        print(f'MEASURED_VALUE    : {result["measured_value"]}')
    if 'record_count' in result:
        print(f'EVIDENCE_COUNT    : {result["record_count"]}')
    if result.get('call_ids'):
        print(f'EVIDENCE_IDS      : {", ".join(result["call_ids"])}')
    if result.get('message'):
        print(f'NOTE              : {result["message"]}')
    print(f'VERDICT_FILE      : {verdict_file}')
    print('-' * 70)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description='Control test: verdict per control per run or window.')
    p.add_argument('control_id', help='16, 7, 9 or all')
    p.add_argument('run_id', nargs='?', help='correlation / run id')
    p.add_argument('--from', dest='frm', help='window start, UTC (2026-10-05T19:50:00Z)')
    p.add_argument('--to', help='window end, UTC')
    p.add_argument('--evidence-dir', default=str(HOME / 'evidence'))
    p.add_argument('--register', default=str(HOME / 'register.yaml'))
    p.add_argument('--baseline', default=None)
    p.add_argument('--json', action='store_true')
    args = p.parse_args(argv)

    if not args.run_id and not (args.frm and args.to):
        print('give a run_id, or --from and --to', file=sys.stderr)
        return 2

    reg_path = Path(args.register)
    if not reg_path.is_file():
        print(f'no register at {reg_path}', file=sys.stderr)
        return 2
    controls = _load_register(reg_path)

    ids = list(_METRICS) if args.control_id == 'all' else [str(args.control_id)]
    evd = Path(args.evidence_dir)
    baseline, baseline_file = _load_baseline(evd, args.baseline)
    ev = {'gw': _load_gateway(evd), 'ledger': _load_ledger(evd), 'runs': _load_runs(evd),
          'baseline': baseline, 'baseline_file': baseline_file,
          'alias_map': _alias_map() if '9' in ids else {}}

    window = (args.frm, args.to) if args.frm else None
    if args.run_id:
        runs = [args.run_id]
    else:
        lo, hi = _parse_ts(args.frm), _parse_ts(args.to)
        runs = sorted({g['modaas.run_id'] for g in ev['gw']
                       if g.get('modaas.run_id', '').startswith('fault-') and g.get('_ts')
                       and lo <= _parse_ts(g['_ts']) <= hi})
        if not runs:
            print(f'VERDICT: NO EVIDENCE - no runs found in window {args.frm} -> {args.to}')
            return 2

    out_dir = evd / 'verdicts'
    out_dir.mkdir(parents=True, exist_ok=True)
    worst, results = 0, []

    for cid in ids:
        entry = controls.get(cid)
        if entry is None:
            print(f'control {cid} not found in {reg_path}', file=sys.stderr)
            worst = 2
            continue
        th = _threshold(entry)
        missing = [k for k in ('version', 'effective_date', 'limit') if th.get(k) in (None, '')]
        if missing:
            print(f'control {cid}: BREACH - threshold missing {", ".join(missing)}')
            worst = max(worst, 1)
            continue
        fn = _METRICS.get(cid)
        if fn is None:
            print(f'No evaluator implemented for control {cid}')
            worst = 2
            continue

        for run_id in runs:
            verdict, result = fn(ev, run_id, th)
            rec = {'control_id': cid, 'control_name': entry.get('name'), 'run_id': run_id,
                   'window_utc': window, 'verdict': verdict,
                   'measured_value': result.get('measured_value'),
                   'threshold_limit': th.get('limit'), 'threshold_version': th.get('version'),
                   'effective_date': th.get('effective_date'), 'owner': _owner(entry),
                   'evidence_ids': result.get('call_ids', []), 'note': result.get('message', ''),
                   'evaluated_at': datetime.now(timezone.utc).isoformat()}
            rec['sha256'] = hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()
            vf = out_dir / f'v-{cid}-{run_id}-{rec["sha256"][:12]}.json'
            vf.write_text(json.dumps(rec, indent=2))
            results.append(rec)
            worst = max(worst, {'PASS': 0, 'BREACH': 1}.get(verdict, 2))
            if not args.json:
                _print(cid, entry, th, run_id, window, verdict, result, vf)

    if args.json:
        print(json.dumps(results, indent=2))
    return worst


if __name__ == '__main__':
    sys.exit(main())
