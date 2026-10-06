#!/bin/bash
# End-to-end smoke test: apply CR, wait for Approved, verify Bedrock guardrail exists, cleanup.
set -euo pipefail
cd "$(dirname "$0")"
NS=components
NAME=claude-sonnet-smoke
REGION=us-west-2

echo "=== Apply test CR ==="
kubectl apply -f test-cr.yaml

echo "=== Wait for phase=Approved (up to 60s) ==="
for _ in $(seq 1 30); do
  phase=$(kubectl -n $NS get agc $NAME -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
  [[ "$phase" == "Approved" ]] && break
  [[ "$phase" == "Failed" ]] && { kubectl -n $NS get agc $NAME -o yaml; exit 1; }
  echo "   phase=$phase"; sleep 2
done

echo "=== Verify status fields ==="
kubectl -n $NS get agc $NAME -o jsonpath='{.status}' | python3 -m json.tool

GR_ID=$(kubectl -n $NS get agc $NAME -o jsonpath='{.status.guardrailId}')
GR_VER=$(kubectl -n $NS get agc $NAME -o jsonpath='{.status.guardrailVersion}')
[[ -n "$GR_ID" ]] || { echo "❌ guardrailId missing in status"; exit 1; }

echo
echo "=== Verify guardrail exists in Bedrock ==="
aws bedrock get-guardrail --guardrail-identifier "$GR_ID" --guardrail-version "$GR_VER" \
  --region $REGION --query '{id:guardrailId,version:version,status:status,name:name}' --output table

echo
echo "✅ Smoke test passed. Cleanup with: kubectl delete agc $NAME -n $NS"
