#!/usr/bin/env bash
# controlctl.sh
# Unified CLI for Trustworthy AI hackathon control testing.
#
# Expected supporting files:
#   /tmp/run-reference.sh
#   ~/starter/pull-evidence.sh
#   ~/starter/evaluate_revB.py
#   ~/starter/register.yaml
#   ~/starter/control-test_Allen.sh
#
# Examples:
#   controlctl health
#   controlctl run S2
#   controlctl evidence fault-1791297426-32a3ff
#   controlctl eval 9 fault-1791297426-32a3ff
#   controlctl eval-all fault-1791297426-32a3ff
#   controlctl campaign 1
#   controlctl campaign 20
#   controlctl campaign-eval latest
#   controlctl summary latest
#   controlctl calibrate latest
set -uo pipefail

PROGRAM_NAME="controlctl"
VERSION="1.0.0"

STARTER_DIR="${STARTER_DIR:-$HOME/starter}"
EVIDENCE_ROOT="${EVIDENCE_ROOT:-$HOME/evidence}"
RUNNER="${RUNNER:-/tmp/run-reference.sh}"
PULL_EVIDENCE="${PULL_EVIDENCE:-$STARTER_DIR/pull-evidence.sh}"
EVALUATOR="${EVALUATOR:-$STARTER_DIR/evaluate_revB.py}"
REGISTER="${REGISTER:-$STARTER_DIR/register.yaml}"
CAMPAIGN_SCRIPT="${CAMPAIGN_SCRIPT:-$STARTER_DIR/control-test_Allen.sh}"
NAMESPACE="${NAMESPACE:-components}"
GATEWAY_NAMESPACE="${GATEWAY_NAMESPACE:-agentgateway-system}"
GATEWAY_DEPLOYMENT="${GATEWAY_DEPLOYMENT:-modaas-agw}"
CONTROLS_DEFAULT="${CONTROLS_DEFAULT:-7 9 16}"
MAX_MODEL_CALLS_DEFAULT="${MAX_MODEL_CALLS_DEFAULT:-10}"
RUN_TIMEOUT_DEFAULT="${RUN_TIMEOUT_DEFAULT:-300}"

SCENARIO_S1="S1-fronthaul-degradation"
SCENARIO_S2="S2-transport-congestion"
SCENARIO_S3="S3-restricted-change"

info()  { printf '[INFO] %s\n' "$*"; }
warn()  { printf '[WARN] %s\n' "$*" >&2; }
error() { printf '[ERROR] %s\n' "$*" >&2; }
die()   { error "$*"; exit 2; }

usage() {
  cat <<'EOF'
controlctl.sh - Unified control testing CLI

Usage:
  controlctl.sh <command> [arguments]

Core commands:
  health
      Check required files, kubectl access, governed resources, agent status,
      image digests, and active AgentCore invocation processes.

  scenarios
      List supported scenario aliases and full scenario names.

  run <S1|S2|S3|full-scenario-name> [output-log]
      Run one scenario and save its transcript. The command prints the run ID
      and trace ID and performs a post-run model-call safety check.

  run-all
      Run S1, S2, and S3 once each. Stops if a run exceeds the model-call cap.

  evidence <run-id>
      Pull evidence for one run and save it under ~/evidence/manual/.

  eval <control-id> <run-id> [register-file]
      Pull current evidence, then evaluate one control.

  eval-all <run-id> [register-file]
      Pull current evidence once, then evaluate Controls 7, 9, and 16.

Campaign commands:
  campaign [runs-per-scenario]
      Launch control-test_Allen.sh. Default is 1 run per scenario.
      Use campaign 20 only after bounded safety tests pass.

  campaign-eval <campaign-dir|latest> [controls]
      Re-pull evidence and rerun evaluations for all safe, collected runs in a
      campaign. The controls argument is a quoted list such as "7 9 16".

  summary <campaign-dir|latest>
      Show campaign metadata, runs, normalized measurements, and summary.md.

  calibrate <campaign-dir|latest>
      Build threshold-calibration.csv and threshold-calibration.md from the
      campaign's measurements.jsonl, excluding failed and unsafe runs.

Inspection commands:
  runs <campaign-dir|latest>
      Display runs.csv in a readable format.

  measurements <campaign-dir|latest>
      Display measurements.csv in a readable format.

  gateway <run-id> [lookback]
      Show gateway records for a run. Default lookback: 2h.

  model-calls <run-id> [lookback]
      Count gateway model calls for a run. Default lookback: 2h.

  timeline <run-id>
      Read the audit-store timeline for a run.

  latest
      Print the newest control-test-allen campaign directory.

  version
      Print script version.

Examples:
  bash ~/starter/controlctl.sh health
  bash ~/starter/controlctl.sh run S2
  bash ~/starter/controlctl.sh eval 9 fault-1791297426-32a3ff
  bash ~/starter/controlctl.sh campaign 1
  bash ~/starter/controlctl.sh summary latest
  bash ~/starter/controlctl.sh campaign-eval latest "7 9 16"
  bash ~/starter/controlctl.sh calibrate latest

Environment overrides:
  STARTER_DIR, EVIDENCE_ROOT, RUNNER, PULL_EVIDENCE, EVALUATOR,
  REGISTER, CAMPAIGN_SCRIPT, NAMESPACE, GATEWAY_NAMESPACE,
  GATEWAY_DEPLOYMENT, CONTROLS_DEFAULT, MAX_MODEL_CALLS_DEFAULT,
  RUN_TIMEOUT_DEFAULT
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_file() {
  [[ -f "$1" ]] || die "required file not found: $1"
}

latest_campaign() {
  local latest
  latest=$(find "$EVIDENCE_ROOT" -maxdepth 1 -mindepth 1 -type d \
    -name 'control-test-allen-*' -printf '%T@ %p\n' 2>/dev/null \
    | sort -nr | head -1 | cut -d' ' -f2-)
  [[ -n "$latest" ]] || return 1
  printf '%s\n' "$latest"
}

resolve_campaign() {
  local requested="${1:-latest}"
  local resolved
  if [[ "$requested" == "latest" ]]; then
    resolved=$(latest_campaign) || die "no campaign directory found under $EVIDENCE_ROOT"
  else
    resolved="$requested"
  fi
  [[ -d "$resolved" ]] || die "campaign directory not found: $resolved"
  [[ -f "$resolved/runs.csv" ]] || die "runs.csv not found in: $resolved"
  printf '%s\n' "$resolved"
}

resolve_scenario() {
  case "${1:-}" in
    S1|s1|1|"$SCENARIO_S1") printf '%s\n' "$SCENARIO_S1" ;;
    S2|s2|2|"$SCENARIO_S2") printf '%s\n' "$SCENARIO_S2" ;;
    S3|s3|3|"$SCENARIO_S3") printf '%s\n' "$SCENARIO_S3" ;;
    *) return 1 ;;
  esac
}

extract_run_id() {
  local log_file="$1"
  local run_id
  run_id=$(sed -n 's/^correlation_id:[[:space:]]*//p' "$log_file" | head -1)
  [[ -n "$run_id" ]] || run_id=$(sed -n 's/^export CID=//p' "$log_file" | head -1)
  printf '%s\n' "$run_id"
}

extract_trace_id() {
  local log_file="$1"
  sed -n 's/^trace_id:[[:space:]]*//p' "$log_file" | head -1
}

model_call_count() {
  local run_id="$1"
  local lookback="${2:-2h}"
  kubectl -n "$GATEWAY_NAMESPACE" logs "deploy/$GATEWAY_DEPLOYMENT" \
    --since="$lookback" 2>/dev/null \
    | grep -F "modaas.run_id=\"$run_id\"" \
    | grep -c 'listener=llm' || true
}

safe_campaign_run_ids() {
  local campaign="$1"
  local max_calls="${2:-$MAX_MODEL_CALLS_DEFAULT}"
  python3 - "$campaign/runs.csv" "$max_calls" <<'PY'
import csv
import sys

path = sys.argv[1]
max_calls = int(sys.argv[2])

with open(path, newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        run_id = (row.get("run_id") or "").strip()
        status = (row.get("status") or "").strip()
        try:
            calls = int(row.get("model_calls") or 0)
        except ValueError:
            calls = 0
        if run_id.startswith("fault-") and status == "COLLECTED" and calls <= max_calls:
            print(run_id)
PY
}

all_campaign_run_ids() {
  local campaign="$1"
  python3 - "$campaign/runs.csv" <<'PY'
import csv
import sys

seen = set()
with open(sys.argv[1], newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        run_id = (row.get("run_id") or "").strip()
        if run_id.startswith("fault-") and run_id not in seen:
            seen.add(run_id)
            print(run_id)
PY
}

cmd_scenarios() {
  cat <<EOF
S1  $SCENARIO_S1
S2  $SCENARIO_S2
S3  $SCENARIO_S3
EOF
}

cmd_health() {
  local failed=0
  local file
  echo "controlctl health"
  echo "================="

  for cmd in bash python3 kubectl aws timeout sha256sum; do
    if command -v "$cmd" >/dev/null 2>&1; then
      printf 'PASS command  %s\n' "$cmd"
    else
      printf 'FAIL command  %s\n' "$cmd"
      failed=1
    fi
  done

  for file in "$RUNNER" "$PULL_EVIDENCE" "$EVALUATOR" "$REGISTER" "$CAMPAIGN_SCRIPT"; do
    if [[ -f "$file" ]]; then
      printf 'PASS file     %s\n' "$file"
    else
      printf 'FAIL file     %s\n' "$file"
      failed=1
    fi
  done

  if kubectl auth can-i get agentconfigs -n "$NAMESPACE" 2>/dev/null | grep -qx yes; then
    printf 'PASS kubectl  can read AgentConfigs in %s\n' "$NAMESPACE"
  else
    printf 'FAIL kubectl  cannot read AgentConfigs in %s\n' "$NAMESPACE"
    failed=1
  fi

  echo
  echo "Agents"
  kubectl get agentconfig \
    customer-experience-agent \
    it-resolution-agent \
    network-resolution-agent \
    -n "$NAMESPACE" \
    -o custom-columns='NAME:.metadata.name,PHASE:.status.phase,GEN:.metadata.generation,OBSERVED:.status.observedGeneration,IMAGE:.spec.awsAgentCore.containerUri' \
    2>/dev/null || {
      warn "could not read one or more reference AgentConfigs"
      failed=1
    }

  echo
  echo "Tools"
  kubectl get toolconfig \
    customer-records \
    runbook-lookup \
    network-twin \
    -n "$NAMESPACE" \
    -o custom-columns='NAME:.metadata.name,PHASE:.status.phase,ENDPOINT:.status.endpoint' \
    2>/dev/null || warn "could not read one or more reference ToolConfigs"

  echo
  echo "Active local AgentCore invocation processes"
  if ps -ef | grep -E '[a]sk_agent.py|[a]ws bedrock-agentcore invoke-agent-runtime'; then
    warn "active invocation processes found"
  else
    echo "None"
  fi

  echo
  echo "Register"
  if [[ -f "$REGISTER" ]]; then
    printf 'path:   %s\n' "$REGISTER"
    printf 'sha256: %s\n' "$(sha256sum "$REGISTER" | awk '{print $1}')"
  fi

  if (( failed )); then
    return 1
  fi
  return 0
}

cmd_run() {
  require_file "$RUNNER"
  require_command timeout
  require_command kubectl

  local requested="${1:-}"
  [[ -n "$requested" ]] || die "usage: controlctl run <S1|S2|S3|scenario> [output-log]"
  local scenario
  scenario=$(resolve_scenario "$requested") || die "unknown scenario: $requested"

  mkdir -p "$EVIDENCE_ROOT/manual/runner"
  local log_file="${2:-$EVIDENCE_ROOT/manual/runner/${scenario}-$(date -u +%Y%m%dT%H%M%SZ).log}"

  info "running scenario=$scenario"
  info "runner log=$log_file"

  set +e
  timeout --signal=TERM --kill-after=20s "${RUN_TIMEOUT_DEFAULT}s" \
    bash "$RUNNER" "$scenario" 2>&1 | tee "$log_file"
  local runner_exit=${PIPESTATUS[0]}
  set -e

  local run_id trace_id calls
  run_id=$(extract_run_id "$log_file")
  trace_id=$(extract_trace_id "$log_file")

  printf '\nrunner_exit=%s\n' "$runner_exit"
  printf 'run_id=%s\n' "$run_id"
  printf 'trace_id=%s\n' "$trace_id"

  if [[ -z "$run_id" ]]; then
    error "runner did not produce a run ID"
    return 1
  fi

  calls=$(model_call_count "$run_id" 30m)
  printf 'model_calls=%s\n' "$calls"

  if (( calls > MAX_MODEL_CALLS_DEFAULT )); then
    error "safety limit exceeded: model_calls=$calls limit=$MAX_MODEL_CALLS_DEFAULT"
    error "verify that the AgentCore runtime session has stopped before continuing"
    return 3
  fi

  return "$runner_exit"
}

cmd_run_all() {
  local scenario
  for scenario in S1 S2 S3; do
    echo
    echo "################################################################"
    echo "Running $scenario"
    echo "################################################################"
    cmd_run "$scenario" || return $?
  done
}

cmd_evidence() {
  require_file "$PULL_EVIDENCE"
  local run_id="${1:-}"
  [[ -n "$run_id" ]] || die "usage: controlctl evidence <run-id>"
  mkdir -p "$EVIDENCE_ROOT/manual/evidence"
  local output="$EVIDENCE_ROOT/manual/evidence/${run_id}.txt"
  info "pulling evidence for $run_id"
  set +e
  bash "$PULL_EVIDENCE" "$run_id" 2>&1 | tee "$output"
  local rc=${PIPESTATUS[0]}
  set -e
  printf 'evidence_file=%s\n' "$output"
  printf 'exit=%s\n' "$rc"
  return "$rc"
}

cmd_eval() {
  require_file "$PULL_EVIDENCE"
  require_file "$EVALUATOR"
  local control="${1:-}"
  local run_id="${2:-}"
  local register_file="${3:-$REGISTER}"
  [[ -n "$control" && -n "$run_id" ]] || die "usage: controlctl eval <control-id> <run-id> [register-file]"
  require_file "$register_file"

  mkdir -p "$EVIDENCE_ROOT/manual/evaluation" "$EVIDENCE_ROOT/manual/evidence"
  local evidence_file="$EVIDENCE_ROOT/manual/evidence/${run_id}.txt"
  local eval_file="$EVIDENCE_ROOT/manual/evaluation/${run_id}.control-${control}.txt"

  info "pulling current evidence for $run_id"
  set +e
  bash "$PULL_EVIDENCE" "$run_id" >"$evidence_file" 2>&1
  local pull_rc=$?
  set -e
  printf 'pull_evidence_exit=%s\n' "$pull_rc"

  info "evaluating control=$control run=$run_id register=$register_file"
  set +e
  python3 "$EVALUATOR" "$control" "$run_id" --register "$register_file" \
    2>&1 | tee "$eval_file"
  local eval_rc=${PIPESTATUS[0]}
  set -e
  printf 'evaluation_file=%s\n' "$eval_file"
  printf 'evaluation_exit=%s\n' "$eval_rc"
  return "$eval_rc"
}

cmd_eval_all() {
  require_file "$PULL_EVIDENCE"
  require_file "$EVALUATOR"
  local run_id="${1:-}"
  local register_file="${2:-$REGISTER}"
  [[ -n "$run_id" ]] || die "usage: controlctl eval-all <run-id> [register-file]"
  require_file "$register_file"

  mkdir -p "$EVIDENCE_ROOT/manual/evaluation" "$EVIDENCE_ROOT/manual/evidence"
  local evidence_file="$EVIDENCE_ROOT/manual/evidence/${run_id}.txt"
  local results_file="$EVIDENCE_ROOT/manual/evaluation/${run_id}.all-controls.txt"
  : > "$results_file"

  set +e
  bash "$PULL_EVIDENCE" "$run_id" >"$evidence_file" 2>&1
  local pull_rc=$?
  set -e
  info "evidence pull exit=$pull_rc file=$evidence_file"

  local overall=0 control eval_file eval_rc
  for control in $CONTROLS_DEFAULT; do
    eval_file="$EVIDENCE_ROOT/manual/evaluation/${run_id}.control-${control}.txt"
    {
      echo
      echo "============================================================"
      echo "RUN=$run_id CONTROL=$control"
      echo "============================================================"
    } | tee -a "$results_file"

    set +e
    python3 "$EVALUATOR" "$control" "$run_id" --register "$register_file" \
      2>&1 | tee "$eval_file" | tee -a "$results_file"
    eval_rc=${PIPESTATUS[0]}
    set -e
    printf 'evaluation_exit=%s\n' "$eval_rc" | tee -a "$results_file"
    (( eval_rc == 0 )) || overall=1
  done
  info "combined results=$results_file"
  return "$overall"
}

cmd_campaign() {
  require_file "$CAMPAIGN_SCRIPT"
  local runs="${1:-1}"
  [[ "$runs" =~ ^[1-9][0-9]*$ ]] || die "runs-per-scenario must be a positive integer"
  info "starting campaign with $runs runs per scenario"
  bash "$CAMPAIGN_SCRIPT" \
    --runs-per-scenario "$runs" \
    --controls "$CONTROLS_DEFAULT" \
    --timeout "$RUN_TIMEOUT_DEFAULT" \
    --max-model-calls "$MAX_MODEL_CALLS_DEFAULT"
}

cmd_campaign_eval() {
  require_file "$PULL_EVIDENCE"
  require_file "$EVALUATOR"
  local campaign
  campaign=$(resolve_campaign "${1:-latest}")
  local controls="${2:-$CONTROLS_DEFAULT}"
  local register_file="$REGISTER"
  require_file "$register_file"

  local output_dir="$campaign/rerun-evaluation-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$output_dir/evidence" "$output_dir/evaluation"
  local combined="$output_dir/results.txt"
  local index="$output_dir/results.csv"
  : > "$combined"
  printf 'run_id,control_id,pull_exit,evaluation_exit,output_file\n' > "$index"

  local safe_ids all_ids safe_count all_count
  safe_ids=$(safe_campaign_run_ids "$campaign")
  all_ids=$(all_campaign_run_ids "$campaign")
  safe_count=$(printf '%s\n' "$safe_ids" | sed '/^$/d' | wc -l)
  all_count=$(printf '%s\n' "$all_ids" | sed '/^$/d' | wc -l)
  info "campaign=$campaign"
  info "safe runs=$safe_count total runs=$all_count max-model-calls=$MAX_MODEL_CALLS_DEFAULT"

  [[ -n "$safe_ids" ]] || die "no safe collected runs found in $campaign/runs.csv"

  local run_id control pull_rc eval_rc eval_file
  while IFS= read -r run_id; do
    [[ -n "$run_id" ]] || continue
    info "pulling evidence run=$run_id"
    set +e
    bash "$PULL_EVIDENCE" "$run_id" >"$output_dir/evidence/${run_id}.txt" 2>&1
    pull_rc=$?
    set -e

    for control in $controls; do
      eval_file="$output_dir/evaluation/${run_id}.control-${control}.txt"
      {
        echo
        echo "============================================================"
        echo "RUN=$run_id CONTROL=$control"
        echo "============================================================"
      } | tee -a "$combined"

      set +e
      python3 "$EVALUATOR" "$control" "$run_id" --register "$register_file" \
        2>&1 | tee "$eval_file" | tee -a "$combined"
      eval_rc=${PIPESTATUS[0]}
      set -e
      printf 'evaluation_exit=%s\n' "$eval_rc" | tee -a "$combined"
      printf '%s,%s,%s,%s,%s\n' \
        "$run_id" "$control" "$pull_rc" "$eval_rc" "$eval_file" >> "$index"
    done
  done <<< "$safe_ids"

  info "campaign reevaluation complete"
  printf 'output_dir=%s\n' "$output_dir"
  printf 'results=%s\n' "$combined"
  printf 'index=%s\n' "$index"
}

cmd_summary() {
  local campaign
  campaign=$(resolve_campaign "${1:-latest}")
  echo "Campaign: $campaign"
  echo
  if [[ -f "$campaign/campaign.json" ]]; then
    echo "Campaign metadata"
    echo "-----------------"
    python3 -m json.tool "$campaign/campaign.json"
    echo
  fi
  if [[ -f "$campaign/summary.md" ]]; then
    echo "Summary"
    echo "-------"
    cat "$campaign/summary.md"
    echo
  fi
  echo "Runs"
  echo "----"
  if command -v column >/dev/null 2>&1; then
    column -s, -t < "$campaign/runs.csv"
  else
    cat "$campaign/runs.csv"
  fi
  echo
  if [[ -f "$campaign/measurements.csv" ]]; then
    echo "Measurements"
    echo "------------"
    if command -v column >/dev/null 2>&1; then
      column -s, -t < "$campaign/measurements.csv"
    else
      cat "$campaign/measurements.csv"
    fi
  fi
}

cmd_runs() {
  local campaign
  campaign=$(resolve_campaign "${1:-latest}")
  if command -v column >/dev/null 2>&1; then
    column -s, -t < "$campaign/runs.csv"
  else
    cat "$campaign/runs.csv"
  fi
}

cmd_measurements() {
  local campaign
  campaign=$(resolve_campaign "${1:-latest}")
  [[ -f "$campaign/measurements.csv" ]] || die "measurements.csv not found in $campaign"
  if command -v column >/dev/null 2>&1; then
    column -s, -t < "$campaign/measurements.csv"
  else
    cat "$campaign/measurements.csv"
  fi
}

cmd_gateway() {
  local run_id="${1:-}"
  local lookback="${2:-2h}"
  [[ -n "$run_id" ]] || die "usage: controlctl gateway <run-id> [lookback]"
  kubectl -n "$GATEWAY_NAMESPACE" logs "deploy/$GATEWAY_DEPLOYMENT" \
    --since="$lookback" \
    | grep -F "modaas.run_id=\"$run_id\"" || true
}

cmd_model_calls() {
  local run_id="${1:-}"
  local lookback="${2:-2h}"
  [[ -n "$run_id" ]] || die "usage: controlctl model-calls <run-id> [lookback]"
  model_call_count "$run_id" "$lookback"
}

cmd_timeline() {
  local run_id="${1:-}"
  [[ -n "$run_id" ]] || die "usage: controlctl timeline <run-id>"
  kubectl get --raw \
    "/api/v1/namespaces/$NAMESPACE/services/audit-store:8080/proxy/timeline?cid=$run_id"
}

cmd_calibrate() {
  local campaign
  campaign=$(resolve_campaign "${1:-latest}")
  [[ -f "$campaign/measurements.jsonl" ]] || die "measurements.jsonl not found in $campaign"

  local csv_out="$campaign/threshold-calibration.csv"
  local md_out="$campaign/threshold-calibration.md"

  python3 - "$campaign/runs.csv" "$campaign/measurements.jsonl" "$csv_out" "$md_out" "$MAX_MODEL_CALLS_DEFAULT" <<'PY'
import csv
import json
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path

runs_csv, measurements_jsonl, csv_out, md_out, max_calls = sys.argv[1:]
max_calls = int(max_calls)

safe_runs = set()
with open(runs_csv, newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        run_id = (row.get("run_id") or "").strip()
        status = (row.get("status") or "").strip()
        try:
            calls = int(row.get("model_calls") or 0)
        except ValueError:
            calls = 0
        if run_id.startswith("fault-") and status == "COLLECTED" and calls <= max_calls:
            safe_runs.add(run_id)

records = []
for line in Path(measurements_jsonl).read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    record = json.loads(line)
    if record.get("run_id") not in safe_runs:
        continue
    raw = str(record.get("measured_value", "")).strip().replace("%", "")
    try:
        value = float(raw)
    except ValueError:
        continue
    record["numeric_value"] = value
    records.append(record)

def percentile(values, p):
    if not values:
        return math.nan
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * p
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return ordered[low]
    weight = rank - low
    return ordered[low] * (1 - weight) + ordered[high] * weight

groups = defaultdict(list)
for record in records:
    key = (
        str(record.get("scenario", "")),
        str(record.get("control_id", "")),
        str(record.get("metric_name", "")),
        str(record.get("comparison", "")),
    )
    groups[key].append(record["numeric_value"])

rows = []
for (scenario, control, metric, comparison), values in sorted(groups.items()):
    values = sorted(values)
    minimum = min(values)
    median = statistics.median(values)
    p95 = percentile(values, 0.95)
    maximum = max(values)
    mean = statistics.mean(values)
    stddev = statistics.pstdev(values) if len(values) > 1 else 0.0

    # Suggestions are intentionally conservative and must be reviewed.
    # For <= metrics, add 20% headroom above healthy P95.
    # For >= metrics, place a 5% tolerance below healthy minimum.
    # Unknown comparison operators receive no automatic suggestion.
    if comparison in ("<=", "<"):
        suggested = p95 * 1.20
        method = "healthy P95 plus 20% headroom"
    elif comparison in (">=", ">"):
        suggested = minimum * 0.95
        method = "healthy minimum minus 5% tolerance"
    else:
        suggested = ""
        method = "manual review required"

    rows.append({
        "scenario": scenario,
        "control_id": control,
        "metric_name": metric,
        "comparison": comparison,
        "samples": len(values),
        "min": minimum,
        "mean": mean,
        "median": median,
        "p95": p95,
        "max": maximum,
        "stddev": stddev,
        "suggested_threshold": suggested,
        "suggestion_method": method,
    })

fieldnames = [
    "scenario", "control_id", "metric_name", "comparison", "samples",
    "min", "mean", "median", "p95", "max", "stddev",
    "suggested_threshold", "suggestion_method",
]
with open(csv_out, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

lines = [
    "# Threshold calibration report",
    "",
    f"Safe runs included: {len(safe_runs)}",
    f"Unsafe or failed runs excluded using model_calls <= {max_calls} and status=COLLECTED.",
    "",
    "Suggested thresholds are planning aids only. Review the raw evidence, preserve the dated register, and choose thresholds before scored runs.",
    "",
    "| Scenario | Control | Metric | Comparison | Samples | Min | Mean | Median | P95 | Max | Suggested | Method |",
    "|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
]
for row in rows:
    def fmt(value):
        if value == "":
            return ""
        if isinstance(value, (int, float)):
            return f"{value:.4f}".rstrip("0").rstrip(".")
        return str(value)
    lines.append(
        f"| {row['scenario']} | {row['control_id']} | {row['metric_name']} | "
        f"{row['comparison']} | {row['samples']} | {fmt(row['min'])} | "
        f"{fmt(row['mean'])} | {fmt(row['median'])} | {fmt(row['p95'])} | "
        f"{fmt(row['max'])} | {fmt(row['suggested_threshold'])} | "
        f"{row['suggestion_method']} |"
    )

if not rows:
    lines += [
        "",
        "No numeric measurements were available from safe runs. Inspect the raw evaluator outputs and measurements.jsonl field parsing.",
    ]

Path(md_out).write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"csv={csv_out}")
print(f"markdown={md_out}")
PY

  echo
  cat "$md_out"
}

main() {
  local command="${1:-help}"
  shift || true
  case "$command" in
    help|-h|--help) usage ;;
    version|--version) echo "$PROGRAM_NAME $VERSION" ;;
    health) cmd_health "$@" ;;
    scenarios) cmd_scenarios "$@" ;;
    run) cmd_run "$@" ;;
    run-all) cmd_run_all "$@" ;;
    evidence) cmd_evidence "$@" ;;
    eval) cmd_eval "$@" ;;
    eval-all) cmd_eval_all "$@" ;;
    campaign) cmd_campaign "$@" ;;
    campaign-eval) cmd_campaign_eval "$@" ;;
    summary) cmd_summary "$@" ;;
    calibrate) cmd_calibrate "$@" ;;
    runs) cmd_runs "$@" ;;
    measurements) cmd_measurements "$@" ;;
    gateway) cmd_gateway "$@" ;;
    model-calls) cmd_model_calls "$@" ;;
    timeline) cmd_timeline "$@" ;;
    latest) latest_campaign || die "no campaign directory found under $EVIDENCE_ROOT" ;;
    *) error "unknown command: $command"; echo; usage; exit 2 ;;
  esac
}

main "$@"
