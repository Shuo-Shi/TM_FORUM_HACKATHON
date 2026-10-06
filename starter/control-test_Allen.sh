#!/usr/bin/env bash
# control-test_Allen
# Run governed fault scenarios repeatedly, pull evidence, evaluate Controls 7/9/16,
# and preserve raw + normalized measurements for threshold calibration.
set -uo pipefail

RUNNER="${RUNNER:-/tmp/run-reference.sh}"
PULL_EVIDENCE="${PULL_EVIDENCE:-$HOME/starter/pull-evidence.sh}"
EVALUATOR="${EVALUATOR:-$HOME/starter/evaluate_revB.py}"
REGISTER="${REGISTER:-$HOME/starter/register.yaml}"
RUNS_PER_SCENARIO="${RUNS_PER_SCENARIO:-20}"
RUN_TIMEOUT="${RUN_TIMEOUT:-600}"
COOLDOWN_SECONDS="${COOLDOWN_SECONDS:-5}"
MAX_MODEL_CALLS="${MAX_MODEL_CALLS:-10}"
CONTROLS="${CONTROLS:-7 9 16}"
OUTPUT_ROOT="${OUTPUT_ROOT:-$HOME/evidence/control-test-allen-$(date -u +%Y%m%dT%H%M%SZ)}"

SCENARIOS=(
  "S1-fronthaul-degradation"
  "S2-transport-congestion"
  "S3-restricted-change"
)

usage() {
  cat <<'EOF'
Usage:
  bash control-test_Allen.sh [options]

Options:
  --runs-per-scenario N   Runs for each scenario. Default: 20 (60 total)
  --controls "7 9 16"    Space-separated control IDs
  --timeout SECONDS       Timeout for each scenario runner. Default: 600
  --cooldown SECONDS      Delay between runs. Default: 5
  --output DIR            Output directory
  --runner FILE           run-reference.sh path
  --register FILE         register.yaml path
  --evaluator FILE        evaluate_revB.py path
  --pull-evidence FILE    pull-evidence.sh path
  --max-model-calls N     Abort campaign if a run exceeds this count. Default: 10
  -h, --help              Show help

Environment variables with the same names may also be used.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runs-per-scenario) RUNS_PER_SCENARIO="$2"; shift 2 ;;
    --controls) CONTROLS="$2"; shift 2 ;;
    --timeout) RUN_TIMEOUT="$2"; shift 2 ;;
    --cooldown) COOLDOWN_SECONDS="$2"; shift 2 ;;
    --output) OUTPUT_ROOT="$2"; shift 2 ;;
    --runner) RUNNER="$2"; shift 2 ;;
    --register) REGISTER="$2"; shift 2 ;;
    --evaluator) EVALUATOR="$2"; shift 2 ;;
    --pull-evidence) PULL_EVIDENCE="$2"; shift 2 ;;
    --max-model-calls) MAX_MODEL_CALLS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

require_file() {
  [[ -f "$1" ]] || { echo "ERROR: file not found: $1" >&2; exit 2; }
}
require_file "$RUNNER"
require_file "$PULL_EVIDENCE"
require_file "$EVALUATOR"
require_file "$REGISTER"
[[ "$RUNS_PER_SCENARIO" =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: runs must be a positive integer" >&2; exit 2; }

mkdir -p "$OUTPUT_ROOT"/{runner,evidence,evaluation,gateway}
REGISTER_SHA256=$(sha256sum "$REGISTER" | awk '{print $1}')
STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

cat > "$OUTPUT_ROOT/campaign.json" <<EOF
{
  "campaign": "control-test_Allen",
  "started_at_utc": "$STARTED_AT",
  "runs_per_scenario": $RUNS_PER_SCENARIO,
  "total_planned_runs": $((RUNS_PER_SCENARIO * ${#SCENARIOS[@]})),
  "controls": "${CONTROLS}",
  "register": "${REGISTER}",
  "register_sha256": "${REGISTER_SHA256}",
  "runner": "${RUNNER}",
  "evaluator": "${EVALUATOR}",
  "max_model_calls": $MAX_MODEL_CALLS
}
EOF
cp "$REGISTER" "$OUTPUT_ROOT/register.snapshot.yaml"

JSONL="$OUTPUT_ROOT/measurements.jsonl"
CSV="$OUTPUT_ROOT/measurements.csv"
RUN_INDEX="$OUTPUT_ROOT/runs.csv"
printf 'campaign_run,scenario,iteration,run_id,trace_id,runner_exit,model_calls,status,runner_log,evidence_file\n' > "$RUN_INDEX"
printf 'scenario,iteration,run_id,trace_id,control_id,evaluator_exit,verdict,metric_name,measured_value,threshold_value,comparison,output_file\n' > "$CSV"
: > "$JSONL"

campaign_run=0
abort_campaign=0

for scenario in "${SCENARIOS[@]}"; do
  for iteration in $(seq 1 "$RUNS_PER_SCENARIO"); do
    campaign_run=$((campaign_run + 1))
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    base=$(printf '%03d_%s_%02d_%s' "$campaign_run" "$scenario" "$iteration" "$stamp")
    runner_log="$OUTPUT_ROOT/runner/${base}.log"

    echo
    echo "[$campaign_run/$((RUNS_PER_SCENARIO * ${#SCENARIOS[@]}))] scenario=$scenario iteration=$iteration"
    echo "Running with timeout=${RUN_TIMEOUT}s ..."

    set +e
    timeout --signal=TERM --kill-after=20s "${RUN_TIMEOUT}s" \
      bash "$RUNNER" "$scenario" >"$runner_log" 2>&1
    runner_exit=$?
    set -e

    run_id=$(sed -n 's/^correlation_id:[[:space:]]*//p' "$runner_log" | head -1)
    [[ -n "$run_id" ]] || run_id=$(sed -n 's/^export CID=//p' "$runner_log" | head -1)
    trace_id=$(sed -n 's/^trace_id:[[:space:]]*//p' "$runner_log" | head -1)

    if [[ -z "$run_id" ]]; then
      status="NO_RUN_ID"
      printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$campaign_run" "$scenario" "$iteration" "" "$trace_id" "$runner_exit" "0" "$status" "$runner_log" "" >> "$RUN_INDEX"
      echo "ERROR: no run ID found; see $runner_log" >&2
      abort_campaign=1
      break
    fi

    gateway_file="$OUTPUT_ROOT/gateway/${run_id}.log"
    kubectl -n agentgateway-system logs deploy/modaas-agw --since=2h 2>/dev/null \
      | grep -F "modaas.run_id=\"$run_id\"" > "$gateway_file" || true
    model_calls=$(grep -c 'listener=llm' "$gateway_file" || true)

    evidence_file="$OUTPUT_ROOT/evidence/${run_id}.txt"
    set +e
    bash "$PULL_EVIDENCE" "$run_id" >"$evidence_file" 2>&1
    pull_exit=$?
    set -e

    status="COLLECTED"
    [[ $runner_exit -eq 0 ]] || status="RUNNER_FAILED"
    [[ $pull_exit -eq 0 ]] || status="EVIDENCE_PULL_FAILED"

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$campaign_run" "$scenario" "$iteration" "$run_id" "$trace_id" "$runner_exit" "$model_calls" "$status" "$runner_log" "$evidence_file" >> "$RUN_INDEX"

    if (( model_calls > MAX_MODEL_CALLS )); then
      echo "SAFETY ABORT: run $run_id generated $model_calls model calls; limit=$MAX_MODEL_CALLS" >&2
      echo "Do not continue until the AgentCore session is confirmed stopped." >&2
      abort_campaign=1
    fi

    for control in $CONTROLS; do
      eval_file="$OUTPUT_ROOT/evaluation/${run_id}.control-${control}.txt"
      set +e
      python3 "$EVALUATOR" "$control" "$run_id" --register "$REGISTER" >"$eval_file" 2>&1
      eval_exit=$?
      set -e

      python3 - "$eval_file" "$JSONL" "$CSV" "$scenario" "$iteration" "$run_id" "$trace_id" "$control" "$eval_exit" <<'PY'
import csv, json, re, sys
from pathlib import Path

out_file, jsonl_file, csv_file, scenario, iteration, run_id, trace_id, control, exit_code = sys.argv[1:]
text = Path(out_file).read_text(errors="replace")

def first(patterns, default=""):
    for pattern in patterns:
        m = re.search(pattern, text, flags=re.I | re.M)
        if m:
            return m.group(1).strip().strip('"\'')
    return default

verdict = first([
    r'^\s*(?:verdict|status|result)\s*[:=]\s*([A-Za-z_-]+)',
    r'\b(PASS|FAIL|INDETERMINATE|ERROR)\b',
], "UNKNOWN")
metric = first([
    r'^\s*(?:metric|metric_name)\s*[:=]\s*([^\n]+)',
    r'"metric_name"\s*:\s*"([^"]+)"',
], "")
measured = first([
    r'^\s*(?:measured|measured_value|actual|metric_value|value)\s*[:=]\s*([^\s,}]+)',
    r'"(?:measured_value|actual|metric_value)"\s*:\s*([^,}\n]+)',
], "")
threshold = first([
    r'^\s*(?:threshold|threshold_value|limit)\s*[:=]\s*([^\s,}]+)',
    r'"(?:threshold_value|limit)"\s*:\s*([^,}\n]+)',
], "")
comparison = first([
    r'^\s*(?:comparison|operator)\s*[:=]\s*([^\s,}]+)',
    r'"comparison"\s*:\s*"([^"]+)"',
], "")

record = {
    "scenario": scenario,
    "iteration": int(iteration),
    "run_id": run_id,
    "trace_id": trace_id,
    "control_id": str(control),
    "evaluator_exit": int(exit_code),
    "verdict": verdict,
    "metric_name": metric,
    "measured_value": measured,
    "threshold_value": threshold,
    "comparison": comparison,
    "output_file": out_file,
    "raw_output": text,
}
with open(jsonl_file, "a", encoding="utf-8") as f:
    f.write(json.dumps(record, ensure_ascii=False) + "\n")
with open(csv_file, "a", encoding="utf-8", newline="") as f:
    csv.writer(f).writerow([
        scenario, iteration, run_id, trace_id, control, exit_code,
        verdict, metric, measured, threshold, comparison, out_file,
    ])
PY

      echo "  control=$control exit=$eval_exit output=$eval_file"
    done

    if (( abort_campaign )); then
      break
    fi
    sleep "$COOLDOWN_SECONDS"
  done
  if (( abort_campaign )); then
    break
  fi
done

python3 - "$JSONL" "$OUTPUT_ROOT/summary.md" <<'PY'
import json, statistics, sys
from collections import defaultdict
from pathlib import Path

jsonl, output = sys.argv[1:]
records = [json.loads(line) for line in Path(jsonl).read_text().splitlines() if line.strip()]
groups = defaultdict(list)
for r in records:
    groups[(r["scenario"], r["control_id"])].append(r)

lines = [
    "# control-test_Allen summary",
    "",
    "This report preserves evaluator outputs for threshold calibration. "
    "Do not automatically change register.yaml from these observations; review distributions, "
    "remove failed/runaway runs, and date the chosen baseline and threshold before scored runs.",
    "",
    "| Scenario | Control | Evaluations | PASS | FAIL | Numeric measured values | Min | Median | P95 | Max |",
    "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
]
for (scenario, control), items in sorted(groups.items()):
    passed = sum(str(x.get("verdict", "")).upper() == "PASS" for x in items)
    failed = sum(str(x.get("verdict", "")).upper() == "FAIL" for x in items)
    nums = []
    for x in items:
        try:
            nums.append(float(str(x.get("measured_value", "")).strip('%')))
        except Exception:
            pass
    if nums:
        nums.sort()
        p95 = nums[min(len(nums)-1, max(0, round(0.95 * len(nums) + 0.5) - 1))]
        stats = [f"{min(nums):g}", f"{statistics.median(nums):g}", f"{p95:g}", f"{max(nums):g}"]
    else:
        stats = ["", "", "", ""]
    lines.append(f"| {scenario} | {control} | {len(items)} | {passed} | {failed} | {len(nums)} | " + " | ".join(stats) + " |")

lines += [
    "",
    "## Files",
    "",
    "- `runs.csv`: one row per scenario run",
    "- `measurements.csv`: normalized evaluator fields when detectable",
    "- `measurements.jsonl`: full raw evaluator output plus normalized fields",
    "- `register.snapshot.yaml`: exact register used for the campaign",
    "- `campaign.json`: campaign settings and register SHA-256",
    "- `runner/`, `gateway/`, `evidence/`, `evaluation/`: source artifacts",
]
Path(output).write_text("\n".join(lines) + "\n")
PY

echo
echo "Campaign output: $OUTPUT_ROOT"
echo "Summary:         $OUTPUT_ROOT/summary.md"
echo "Measurements:    $OUTPUT_ROOT/measurements.csv"
echo "Raw JSONL:       $OUTPUT_ROOT/measurements.jsonl"

if (( abort_campaign )); then
  echo "Campaign stopped by safety guard or missing run ID." >&2
  exit 3
fi
