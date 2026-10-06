#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# pull-evidence.sh <run-id> [output-dir] — pull the six standard surfaces
# named in the challenge brief (content/challenge-brief/index.en.md, "The
# build target") into ~/evidence/*.json for one run, so an audit-trail
# utility (or answer.py, next to this file) has something to read.
#
#   TMF639 Resource Inventory GET      -> tmf639.json
#   CR status + conditions              -> cr-status.json
#   Approval attestation annotations    -> approvals.json
#   Gateway request/response records    -> gateway-log.json
#   Registry records                    -> registry.json
#   OTEL traces (cross-component id)    -> otel-traces.json
#
# Every surface here is read-only (get/list/watch/logs), the same verbs the
# participant role is granted (see the IAM policy attached to your role).
# Nothing is applied, created, or deleted.
#
# Reads the gateway/cluster address the same way the modules do: from the
# cluster's own resources, never a hardcoded host or account id. Refuses to
# run against a cluster that is not this platform (no modaas namespaces).
#
# Usage:
#   bash pull-evidence.sh fault-1758900000
#   bash pull-evidence.sh fault-1758900000 /tmp/evidence-run1
#
# <run-id> is whatever correlation id or run id your run used (the reference
# scenario's is printed as "correlation_id:" by run-reference.sh; your own
# agent's is whatever you pass as correlation_id). It scopes the gateway-log
# and otel-traces surfaces; the other four are estate-wide by nature (a CR's
# status is not "for" one run) and are captured in full every time.
set -euo pipefail

RUN_ID="${1:-}"
OUT="${2:-$HOME/evidence}"
[ -n "$RUN_ID" ] || { echo "usage: $0 <run-id> [output-dir]" >&2; exit 2; }
mkdir -p "$OUT"

command -v kubectl >/dev/null || { echo "kubectl not found" >&2; exit 2; }
command -v aws >/dev/null || { echo "aws CLI not found" >&2; exit 2; }

# Refuse a cluster that is not this platform, rather than writing six files of
# misleading emptiness against someone else's kubeconfig.
for ns in components modaas-system agentgateway-system; do
  kubectl get namespace "$ns" >/dev/null 2>&1 || {
    echo "REFUSED: namespace '$ns' not found — this does not look like a MoDaaS workshop cluster." >&2
    echo "          Check KUBECONFIG / your current context: kubectl config current-context" >&2
    exit 2
  }
done

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
echo "run id     : $RUN_ID"
echo "output dir : $OUT"
echo "region     : $REGION"
echo

# ── 1. TMF639 Resource Inventory GET ──────────────────────────────────────
# The ODA Canvas's own standards-shaped estate view. Read through the API
# server's service proxy so no extra network path or credential is needed;
# the same proxy Module 7 (Reference Agents) uses to reach in-cluster ClusterIP
# services from a laptop.
echo "1/6 tmf639.json — TMF639 Resource Inventory"
kubectl get --raw \
  "/api/v1/namespaces/canvas/services/resource-inventory:80/proxy/tmf-api/resourceInventoryManagement/v5/resource" \
  > "$OUT/tmf639.json" 2> "$OUT/tmf639.err" \
  || echo "    note: resource-inventory unreachable — see $OUT/tmf639.err" >&2
echo "    $(wc -c < "$OUT/tmf639.json" 2>/dev/null || echo 0) bytes"

# ── 2. CR status + conditions ─────────────────────────────────────────────
# Lifecycle ground truth for every governed asset: phase, conditions, and (for
# models) the endpoint the gateway programmed. Whole-estate by nature — a
# ModelConfig's status is not scoped to one run — so this is a full snapshot,
# not filtered by run id.
echo "2/6 cr-status.json — ModelConfig/ToolConfig/AgentConfig status+conditions"
kubectl get modelconfig,toolconfig,agentconfig -n components -o json > "$OUT/cr-status.json" \
  || echo "    note: could not list governed CRs" >&2
echo "    $(python3 -c "import json,sys;print(len(json.load(open('$OUT/cr-status.json')).get('items',[])))" 2>/dev/null || echo '?') resources"

# ── 3. Approval attestation annotations ───────────────────────────────────
# Who approved each asset, and what they attested to. These live as
# annotations on the same CRs (modaas.tmforum.org/approver and
# .../approval-attestation — see Baseline Walkthrough step 2), pulled out on
# their own so a reader does not have to dig for them inside cr-status.json.
echo "3/6 approvals.json — approval attestation annotations"
python3 - "$OUT/cr-status.json" > "$OUT/approvals.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
out = []
for item in doc.get("items", []):
    ann = (item.get("metadata") or {}).get("annotations") or {}
    approver = ann.get("modaas.tmforum.org/approver")
    attestation = ann.get("modaas.tmforum.org/approval-attestation")
    out.append({
        "kind": item.get("kind"),
        "name": (item.get("metadata") or {}).get("name"),
        "approver": approver,
        "attestation": attestation,
        "phase": (item.get("status") or {}).get("phase"),
    })
json.dump(out, sys.stdout, indent=2)
print()
PY
echo "    $(python3 -c "import json;print(len(json.load(open('$OUT/approvals.json'))))" 2>/dev/null || echo '?') CRs, $(grep -c '"approver": "' "$OUT/approvals.json" 2>/dev/null || echo 0) with an approver recorded"

# ── 4. Gateway request/response records ───────────────────────────────────
# Who called what, and what the perimeter did about it: modaas.run_id,
# modaas.trace_id, modaas.action_id, gen_ai.* usage and cost, per call — the
# gateway's own structured request log (Baseline Walkthrough, "Token
# consumption, end to end"). Filtered to this run id; the pod's log buffer is
# bounded, so a run from long ago may have scrolled out.
echo "4/6 gateway-log.json — gateway request/response records for $RUN_ID"
LOG_POD=$(kubectl get pods -n agentgateway-system -l app.kubernetes.io/name=modaas-agw \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
[ -n "$LOG_POD" ] || LOG_POD=$(kubectl get pods -n agentgateway-system \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | grep -m1 modaas-agw || true)
if [ -n "$LOG_POD" ]; then
  kubectl logs "$LOG_POD" -n agentgateway-system --tail=50000 2>/dev/null \
    | grep -F "$RUN_ID" > "$OUT/gateway-log.raw.txt" || true
else
  : > "$OUT/gateway-log.raw.txt"
  echo "    note: no agentgateway pod found in agentgateway-system" >&2
fi
python3 - "$RUN_ID" "$OUT/gateway-log.raw.txt" > "$OUT/gateway-log.json" <<'PY'
import json, re, sys
run_id, path = sys.argv[1], sys.argv[2]
KV = re.compile(r'(\S+)=("(?:[^"\\]|\\.)*"|\S+)')
out = []
for line in open(path, errors="replace"):
    line = line.rstrip("\n")
    if run_id not in line:
        continue
    rec = {}
    for k, v in KV.findall(line):
        rec[k] = v.strip('"')
    rec["_raw"] = line
    out.append(rec)
json.dump({"run_id": run_id, "records": out}, sys.stdout, indent=2)
print()
PY
rm -f "$OUT/gateway-log.raw.txt"
echo "    $(python3 -c "import json;print(len(json.load(open('$OUT/gateway-log.json'))['records']))" 2>/dev/null || echo '?') matching line(s)"

# ── 5. Registry records ───────────────────────────────────────────────────
# Attested-subject cards for anything the operators registered (the
# AgentConfig/ToolConfig/ModelConfig status.registryRecordId this workshop
# uses). There is no separate discovery API on this platform version — the
# record id and its approval status live in the same CR status already
# captured in cr-status.json, so this file extracts just that slice.
echo "5/6 registry.json — registry records (registryRecordId, approval status)"
python3 - "$OUT/cr-status.json" > "$OUT/registry.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
out = []
for item in doc.get("items", []):
    st = item.get("status") or {}
    rid = st.get("registryRecordId")
    if not rid:
        continue
    out.append({
        "kind": item.get("kind"),
        "name": (item.get("metadata") or {}).get("name"),
        "registryRecordId": rid,
        "registryApprovalStatus": st.get("registryApprovalStatus"),
        "registryLastObserved": st.get("registryLastObserved"),
    })
json.dump(out, sys.stdout, indent=2)
print()
PY
echo "    $(python3 -c "import json;print(len(json.load(open('$OUT/registry.json'))))" 2>/dev/null || echo '?') registered asset(s)"

# ── 6. OTEL traces ────────────────────────────────────────────────────────
# Cross-component correlation on traceparent/trace_id. This workshop's
# collector exports spans to `debug` only (Module 8), so there is no X-Ray
# trace to fetch; the correlating record that survives is the audit
# ledger's own chain for this run id, read from the in-cluster store the
# reference agents write to. If your agents write elsewhere, point
# AUDIT_URL at your ledger instead.
echo "6/6 otel-traces.json — audit ledger timeline for $RUN_ID (see note in the file if traces are unavailable)"
AUDIT_URL="${AUDIT_URL:-}"
if [ -z "$AUDIT_URL" ]; then
  if kubectl get svc audit-store -n components >/dev/null 2>&1; then
    RAW=$(kubectl get --raw "/api/v1/namespaces/components/services/audit-store:8080/proxy/records?cid=${RUN_ID}" 2>/dev/null || true)
  else
    RAW=""
  fi
else
  RAW=$(curl -fsS "${AUDIT_URL%/}/records?cid=${RUN_ID}" 2>/dev/null || true)
fi
python3 - "$RUN_ID" > "$OUT/otel-traces.json" <<PY
import json, sys
run_id = sys.argv[1] if len(sys.argv) > 1 else "$RUN_ID"
raw = """$RAW"""
records = []
for line in raw.splitlines():
    line = line.strip()
    if not line:
        continue
    try:
        records.append(json.loads(line))
    except Exception:
        pass
json.dump({
    "run_id": run_id,
    "note": ("No dedicated OTEL trace backend on this platform build (the "
             "collector exports to debug only, see Module 8). This file "
             "carries the audit ledger's own correlated chain instead, "
             "joined on trace_id/action_id inside each record's detail."),
    "records": records,
}, sys.stdout, indent=2)
print()
PY
echo "    $(python3 -c "import json;print(len(json.load(open('$OUT/otel-traces.json'))['records']))" 2>/dev/null || echo '?') record(s)"

echo
echo "wrote 6 files to $OUT:"
ls -la "$OUT"/*.json
