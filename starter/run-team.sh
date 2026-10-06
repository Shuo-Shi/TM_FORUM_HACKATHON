#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# MVW fault-resolution scenario -- autonomous resolution across three domains.
#
#   fault injected -> Customer Experience agent (impact)
#   -> IT Resolution agent (incident disposition)
#   -> Network Resolution agent (diagnosis + NEGOTIATES with IT) -> disposition
#
# Every step leaves evidence in the audit repository: a 10-record correlated
# trail (intent / invocation+guardrail / result-inspection per agent, plus the
# IT<->network negotiation).
#
# Usage:
#   bash run-reference.sh                          # S1, the baseline
#   bash run-reference.sh S2-transport-congestion  # a specific scenario
#   bash run-reference.sh --list                   # what is available
#
# The scenario's symptoms are read from network-inventory.json, so the three
# scenarios are genuinely different inputs -- not the same fault relabelled.
# Two of them cannot be passed by resolving the fault. Grade any run with:
#   python3 score-run.py <correlation_id> <scenario_id> <timeline_file>
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# ask_agent.py lives in the starter kit (~/starter after Module 9) and is also
# installed on the IDE PATH by bootstrap (/usr/local/bin). Module 7 downloads
# this script to /tmp, where "../starter" does not exist (E7 2026-10-03:
# "cd: /tmp/../starter: No such file or directory" for every participant).
if [ -n "${STARTER_DIR:-}" ]; then STARTER="$STARTER_DIR"
elif [ -f "$HERE/../starter/ask_agent.py" ]; then STARTER="$(cd "$HERE/../starter" && pwd)"
elif [ -f "$HOME/starter/ask_agent.py" ]; then STARTER="$HOME/starter"
elif [ -f /usr/local/bin/ask_agent.py ]; then STARTER=/usr/local/bin
else echo "ERROR: ask_agent.py not found (set STARTER_DIR=/path/to/starter)"; exit 2; fi
DATA="${DATA:-/tmp/network-inventory.json}"
SCENARIO="${1:-S1-fronthaul-degradation}"

if [ ! -f "${DATA}" ]; then
  echo "ERROR: dataset not found at ${DATA}"
  echo "Fetch it first (the workshop page has the assetUrl), or set DATA=/path/to/network-inventory.json"
  exit 2
fi

if [ "${SCENARIO}" = "--list" ] || [ "${SCENARIO}" = "-l" ]; then
  python3 - "${DATA}" <<'PY'
import json, sys
for s in json.load(open(sys.argv[1]))['fault_scenarios']:
    print(f"  {s['id']:<26} {s['difficulty']:<10} expects {s['grading']['expect_disposition']}")
    print(f"    {s['title']}")
PY
  exit 0
fi

# CID: fault-<epoch>-<6hex>
CID="fault-$(date +%s)-$(od -An -N3 -tx1 /dev/urandom|tr -d ' \n')"
export CID
echo "export CID=${CID}"

# One W3C trace for the whole run, passed to all three agents.
TRACE_ID=$(python3 -c 'import uuid; print(uuid.uuid4().hex)')
RUN_TP="00-${TRACE_ID}-$(python3 -c 'import uuid; print(uuid.uuid4().hex[:16])')-01"

# Build the three agent payloads from the chosen scenario.
eval "$(python3 - "${DATA}" "${SCENARIO}" "${CID}" <<'PY'
import json, shlex, sys
data, sid, cid = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3]
scen = next((s for s in data['fault_scenarios'] if s['id'] == sid), None)
if scen is None:
    ids = ', '.join(s['id'] for s in data['fault_scenarios'])
    sys.exit(f"echo 'ERROR: unknown scenario {sid}. Available: {ids}'; exit 2")
sy = scen['symptoms']
constraints = sy.get('constraints', [])

cx = {"correlation_id": cid, "context": {
    "customers": [{"id": c.split()[0], "name": ' '.join(c.split()[1:])}
                  for c in sy.get('affected_customers', [])],
    "symptoms": sy, "operational_constraints": constraints}}
it = {"correlation_id": cid, "context": {
    "incident": {"id": "INC-" + cid[-4:], "severity": "P2",
                 "summary": scen['title'], "alarms": sy.get('alarms', [])},
    "symptoms": sy, "operational_constraints": constraints}}
nw = {"correlation_id": cid, "context": {
    "element": sy.get('element'), "telemetry": {
        "packet_loss_pct": sy.get('packet_loss_pct'),
        "latency_ms_p95": sy.get('latency_ms_p95')},
    "alarms": sy.get('alarms', []), "operational_constraints": constraints}}

print(f"CX_PAYLOAD={shlex.quote(json.dumps(cx))}")
print(f"IT_PAYLOAD={shlex.quote(json.dumps(it))}")
print(f"NW_PAYLOAD={shlex.quote(json.dumps(nw))}")
print(f"TITLE={shlex.quote(scen['title'])}")
print(f"DIFFICULTY={shlex.quote(scen['difficulty'])}")
print(f"EXPECTED={shlex.quote(scen['grading']['expect_disposition'])}")
PY
)"

echo "=== MVW fault-resolution scenario ==="
echo "scenario:       ${SCENARIO} (${DIFFICULTY})"
echo "fault:          ${TITLE}"
echo "correlation_id: ${CID}"
echo "trace_id:       ${TRACE_ID}"
if [ "${DIFFICULTY}" != "baseline" ]; then
  echo
  echo "NOTE: this is not the baseline. The graded disposition for this scenario"
  echo "      is '${EXPECTED}' -- resolving the fault may be the wrong answer."
fi
echo

echo "-- step block 1-3: Customer Experience agent --"
python3 "${STARTER}/ask_agent.py" customer-experience-agent "${CX_PAYLOAD}" \
  --cid "${CID}" --traceparent "${RUN_TP}" || true
echo

echo "-- step block 4-6: IT Resolution agent --"
python3 "${STARTER}/ask_agent.py" it-resolution-agent "${IT_PAYLOAD}" \
  --cid "${CID}" --traceparent "${RUN_TP}" || true
echo

echo "-- step block 7-9: Network Resolution agent --"
NW_OUT=$(python3 "${STARTER}/ask_agent.py" network-resolution-agent "${NW_PAYLOAD}" \
  --cid "${CID}" --traceparent "${RUN_TP}" 2>&1) || true
echo "${NW_OUT}"
echo

echo "-- step block 10: Network -> IT negotiation --"
NEG_PAYLOAD=$(NW_OUT="${NW_OUT}" python3 -c '
import json, os, sys
print(json.dumps({"negotiate": {"correlation_id": sys.argv[1], "traceparent": sys.argv[2],
                                "proposal": os.environ["NW_OUT"][-1500:]}}))' "${CID}" "${RUN_TP}")
python3 "${STARTER}/ask_agent.py" it-resolution-agent "${NEG_PAYLOAD}" \
  --cid "${CID}" --traceparent "${RUN_TP}" || true
echo

echo "=== scenario complete: correlation_id=${CID} ==="
echo
echo "Read the evidence:"
echo "  kubectl get --raw \"/api/v1/namespaces/components/services/audit-store:8080/proxy/timeline?cid=${CID}\""
echo
echo "Grade this run:"
echo "  kubectl get --raw \"/api/v1/namespaces/components/services/audit-store:8080/proxy/timeline?cid=${CID}\" > /tmp/chain.txt"
echo "  python3 score-run.py ${CID} ${SCENARIO} /tmp/chain.txt"
