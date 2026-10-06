#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# new-tool.sh <alias> [--description "..."] [--agentcore-gateway --lambda <function-name>] [--dry-run]
#
# Scaffolds a governed MCP tool from mcp-tool-template/, deploys it to
# `components` (ConfigMap + Deployment + Service, like modaas-docs), writes
# and applies its ToolConfig, and prints the approve command plus a
# tools/list curl through the perimeter.
#
# --agentcore-gateway --lambda <function-name> declares a Lambda function you
# already created (name team-<slug>-...) as a tool on your account's AgentCore
# Gateway, and applies that ToolConfig. No in-cluster backend is deployed on
# this path. Needs MODAAS_GATEWAY_ID, REGION and ACCOUNT_ID in the environment
# (the platform writes them to your shell at install).
#
# --dry-run renders every manifest and runs `kubectl apply --dry-run=server`
# for both the workload objects and the ToolConfig, then stops: it deploys
# nothing and creates no backend pod.
#
# Every value this script needs comes from the cluster or the environment;
# nothing is hardcoded, and no account id appears in its output. Refuses to
# run against a cluster that is not this platform (no modaas namespaces).
#
# Usage:
#   bash new-tool.sh my-lookup-tool --description "Looks up widgets by id"
#   bash new-tool.sh my-lookup-tool --dry-run
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_DIR="$HERE/mcp-tool-template"

ALIAS="${1:-}"
[ -n "$ALIAS" ] || {
  echo "usage: $0 <alias> [--description \"...\"] [--agentcore-gateway --lambda <function-name>] [--dry-run]" >&2
  exit 2
}
shift

DESCRIPTION="A governed MCP tool"
AGENTCORE_GATEWAY=0
LAMBDA_FUNCTION=""
DRY_RUN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --description) DESCRIPTION="${2:-}"; shift 2 ;;
    --agentcore-gateway) AGENTCORE_GATEWAY=1; shift ;;
    --lambda) LAMBDA_FUNCTION="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done

if ! printf '%s' "$ALIAS" | grep -Eq '^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$'; then
  echo "alias '$ALIAS' must be a valid Kubernetes name: lowercase letters, digits and '-', starting with a letter" >&2
  exit 2
fi

command -v kubectl >/dev/null || { echo "kubectl not found" >&2; exit 2; }
if [ "$AGENTCORE_GATEWAY" = "1" ]; then
  [ -n "$LAMBDA_FUNCTION" ] || { echo "--agentcore-gateway needs --lambda <function-name>" >&2; exit 2; }
  for v in MODAAS_GATEWAY_ID REGION ACCOUNT_ID; do
    [ -n "${!v:-}" ] || { echo "$v is not set; open a new terminal (the platform exports it) or export it" >&2; exit 2; }
  done
  aws lambda get-function --function-name "$LAMBDA_FUNCTION" --region "$REGION" >/dev/null \
    || { echo "Lambda function '$LAMBDA_FUNCTION' not found in $REGION" >&2; exit 2; }
fi
for ns in components modaas-system agentgateway-system; do
  kubectl get namespace "$ns" >/dev/null 2>&1 || {
    echo "REFUSED: namespace '$ns' not found — this does not look like a MoDaaS workshop cluster." >&2
    exit 2
  }
done

TOOL_DIR="$HOME/tools/${ALIAS}"
mkdir -p "$TOOL_DIR"
echo "== 1. scaffolding from mcp-tool-template/ to $TOOL_DIR"
cp "$TEMPLATE_DIR/server.py" "$TOOL_DIR/server.py"
echo "   wrote $TOOL_DIR/server.py"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== 2. rendering deployment.yaml"
sed "s/__TOOL_ALIAS__/${ALIAS}/g" "$TEMPLATE_DIR/deployment.yaml" > "$WORK/deployment.yaml"
# Fill binaryData with the real server.py, base64-encoded, the same shape
# modaas-docs-mcp.yaml uses for its ConfigMap-mounted app.
SERVER_B64=$(base64 < "$TOOL_DIR/server.py" | tr -d '\n')
python3 - "$WORK/deployment.yaml" "$SERVER_B64" <<'PY'
import sys
path, b64 = sys.argv[1], sys.argv[2]
text = open(path).read()
marker = "binaryData: {}"
if marker not in text:
    sys.exit("template's ConfigMap has no 'binaryData: {}' placeholder to fill")
text = text.replace(marker, f"binaryData:\n  server.py: {b64}", 1)
open(path, "w").write(text)
PY
echo "   wrote $WORK/deployment.yaml"

echo "== 3. rendering toolconfig.yaml"
if [ "$AGENTCORE_GATEWAY" = "1" ]; then
  # The agentCoreGateway variant lives between two plain markers in the
  # template (AGENTCORE-GATEWAY-YAML-BEGIN/-END) as uncommented YAML, so it
  # can be extracted verbatim with no comment-stripping.
  LAMBDA_FUNCTION="$LAMBDA_FUNCTION" python3 - "$TEMPLATE_DIR/toolconfig.yaml" "$WORK/toolconfig.yaml" "$ALIAS" "$DESCRIPTION" <<'PY'
import sys
src, dst, alias, desc = sys.argv[1:5]
text = open(src).read()
_, _, rest = text.partition("# AGENTCORE-GATEWAY-YAML-BEGIN\n")
variant, _, _ = rest.partition("# AGENTCORE-GATEWAY-YAML-END")
if not variant.strip():
    sys.exit("could not find the AGENTCORE-GATEWAY-YAML-BEGIN/-END block in the template")
import os
rendered = (variant.replace("__TOOL_ALIAS__", alias).replace("__TOOL_DESCRIPTION__", desc)
            .replace("__LAMBDA_FUNCTION__", os.environ["LAMBDA_FUNCTION"])
            .replace("${MODAAS_GATEWAY_ID}", os.environ["MODAAS_GATEWAY_ID"])
            .replace("${REGION}", os.environ["REGION"]).replace("${ACCOUNT_ID}", os.environ["ACCOUNT_ID"]))
open(dst, "w").write(rendered)
PY
  echo "   wrote $WORK/toolconfig.yaml (Lambda $LAMBDA_FUNCTION on Gateway $MODAAS_GATEWAY_ID)"
else
  python3 - "$TEMPLATE_DIR/toolconfig.yaml" "$WORK/toolconfig.yaml" "$ALIAS" "$DESCRIPTION" <<'PY'
import sys
src, dst, alias, desc = sys.argv[1:5]
text = open(src).read()
first, _, _ = text.partition("---\n# OPTIONAL agentCoreGateway variant")
rendered = first.replace("__TOOL_ALIAS__", alias).replace("__TOOL_DESCRIPTION__", desc)
open(dst, "w").write(rendered)
PY
  echo "   wrote $WORK/toolconfig.yaml"
fi

if [ "$DRY_RUN" = "1" ]; then
  echo "== --dry-run: server-side validation only, nothing applied for real"
  if [ "$AGENTCORE_GATEWAY" != "1" ]; then
    echo "-- deployment.yaml --"
    kubectl apply --dry-run=server -f "$WORK/deployment.yaml"
  fi
  echo "-- toolconfig.yaml --"
  kubectl apply --dry-run=server -f "$WORK/toolconfig.yaml"
  echo "== --dry-run stopping here. Re-run without --dry-run to deploy for real."
  exit 0
fi

if [ "$AGENTCORE_GATEWAY" = "1" ]; then
  echo "== 4. no in-cluster backend on the Gateway path (your Lambda is the backend)"
  cp "$WORK/toolconfig.yaml" "$TOOL_DIR/toolconfig.agentcore-gateway.yaml"
  echo "== 5. applying the ToolConfig ${ALIAS}-agentcore"
  kubectl apply -f "$WORK/toolconfig.yaml"
else
  echo "== 4. applying the backend (ConfigMap, Service, Deployment)"
  kubectl apply -f "$WORK/deployment.yaml"
  echo "== 5. applying the ToolConfig"
  kubectl apply -f "$WORK/toolconfig.yaml"
fi

echo
echo "next:"
if [ "$AGENTCORE_GATEWAY" != "1" ]; then
  echo "  1. Wait for the backend pod to go Ready:"
  echo "     kubectl get pods -n components -l app.kubernetes.io/name=${ALIAS}-mcp"
fi
if [ "$AGENTCORE_GATEWAY" = "1" ]; then
  echo "  2. Watch the Gateway target appear (Provisioned=True), then approve and call it"
  echo "     the same way as the default path, using ToolConfig name ${ALIAS}-agentcore:"
  echo "     kubectl get toolconfig ${ALIAS}-agentcore -n components -o jsonpath='{.status.conditions[?(@.type==\"Provisioned\")].status}'"
fi
echo "  3. Approve the tool (it sits in Reviewing until a human attests):"
echo "     kubectl annotate toolconfig ${ALIAS} -n components \\"
echo "       \"modaas.tmforum.org/approver=\$(whoami)@workshop\" \\"
echo "       \"modaas.tmforum.org/approval-attestation=Reviewed: read-only, internal classification\" \\"
echo "       --overwrite"
echo "  4. Call it through the gateway (from inside the cluster - the token must not go over plain HTTP):"
echo "     TOKEN=\$(cat /tmp/modaas-token)"
echo "     kubectl run probe-${ALIAS} --rm -i --restart=Never --image=curlimages/curl:8.5.0 -n default \\"
echo "       --env=\"TOKEN=\$TOKEN\" -- sh -c '"
echo "       U=http://modaas-agw.agentgateway-system:8080/mcp/${ALIAS}"
echo "       curl -s -X POST \"\$U\" -H \"Authorization: Bearer \$TOKEN\" \\"
echo "         -H \"Content-Type: application/json\" \\"
echo "         -d '"'"'{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}'"'"'"
echo "     # then tools/list with the Mcp-Session-Id the initialize response returned"
