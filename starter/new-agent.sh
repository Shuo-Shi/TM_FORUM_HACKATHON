#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# new-agent.sh <name> <model-alias> [--skills a,b] [--tool alias] [--dry-run]
#
# Builds and declares a governed agent of your own, on AgentCore Runtime,
# using agent-template/ as the source and the same two scripts Module 9 uses:
#   1. copy agent-template/ to ~/agents/<name>/
#   2. build the arm64 image (build-agent-image.sh TARGET=agentcore)
#   3. generate the AgentConfig (make-agentcore-agents.py --name --model --image)
#   4. apply it, print the approve command and the invoke call
#
# Idempotent: re-running with the same name rebuilds and re-applies (the
# generator's own server-side dry run catches a bad declaration before
# anything real happens). Every step prints what it did and where the
# artifact landed.
#
# Every value this script needs — gateway host/key, ledger address, cluster
# details — comes from the environment or the cluster itself, the same as
# make-agentcore-agents.py's own Discovery class. Nothing is hardcoded, and
# no account id appears in any output this script prints.
#
# --dry-run renders the AgentConfig and runs `kubectl apply --dry-run=server`
# against it (the generator's own validation step), and stops there: it does
# NOT build an image or invoke CodeBuild. Use it to check a name, model and
# skills combination admits before spending a real build.
#
# Refuses to run against a cluster that is not this platform (no modaas
# namespaces) before touching anything.
#
# Usage:
#   bash new-agent.sh my-agent nemotron-super-120b --skills fault-resolution,rca
#   bash new-agent.sh my-agent nemotron-super-120b --tool modaas-docs --dry-run
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The two reference-impl scripts live next to the kit when it is downloaded
# into ~/starter (Module 9), or two levels up in a repo checkout.
if [ -z "${REFERENCE_IMPL:-}" ]; then
  if [ -f "$HERE/reference-impl/make-agentcore-agents.py" ]; then
    REFERENCE_IMPL="$HERE/reference-impl"
  else
    REFERENCE_IMPL="$(cd "$HERE/../.." && pwd)/static/reference-impl"
  fi
fi

NAME="${1:-}"; MODEL="${2:-}"
[ -n "$NAME" ] && [ -n "$MODEL" ] || {
  echo "usage: $0 <name> <model-alias> [--skills a,b] [--tool alias] [--role customer|it|network] [--dry-run]" >&2
  exit 2
}
shift 2

SKILLS="" TOOL="" ROLE="customer" DRY_RUN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --skills) SKILLS="${2:-}"; shift 2 ;;
    --tool) TOOL="${2:-}"; shift 2 ;;
    --role) ROLE="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
[ -n "$SKILLS" ] || SKILLS="custom"

command -v kubectl >/dev/null || { echo "kubectl not found" >&2; exit 2; }
for ns in components modaas-system agentgateway-system; do
  kubectl get namespace "$ns" >/dev/null 2>&1 || {
    echo "REFUSED: namespace '$ns' not found — this does not look like a MoDaaS workshop cluster." >&2
    exit 2
  }
done

AGENT_DIR="$HOME/agents/${NAME}"
mkdir -p "$AGENT_DIR"
echo "== 1. copying agent-template/ to $AGENT_DIR"
cp "$HERE/agent-template/agent.py" "$AGENT_DIR/agent.py"
cp "$HERE/agent-template/requirements.txt" "$AGENT_DIR/requirements.txt"
echo "   wrote $AGENT_DIR/agent.py, $AGENT_DIR/requirements.txt"

TOOL_ENV=""
if [ -n "$TOOL" ]; then
  echo "== looking up ToolConfig '$TOOL' for --tool"
  TOOL_PHASE=$(kubectl get toolconfig "$TOOL" -n components -o jsonpath='{.status.phase}' 2>/dev/null || true)
  if [ -z "$TOOL_PHASE" ]; then
    echo "REFUSED: no ToolConfig named '$TOOL' in namespace components (kubectl get toolconfig -n components)" >&2
    exit 2
  fi
  if [ "$TOOL_PHASE" != "Approved" ]; then
    echo "REFUSED: ToolConfig '$TOOL' is phase=$TOOL_PHASE, not Approved — approve it first (composition gate refuses an agent depending on an unapproved tool)" >&2
    exit 2
  fi
  # An AgentCore runtime sits in the VPC, outside the cluster: it cannot
  # resolve *.svc.cluster.local. It reaches agentgateway through the
  # gateway's load balancer, the same address the operator gives it in
  # OPENAI_BASE_URL, so the tool URL is the ToolConfig's public endpoint.
  TOOL_MESH=$(kubectl get toolconfig "$TOOL" -n components -o jsonpath='{.status.endpoints.public}' 2>/dev/null || true)
  [ -n "$TOOL_MESH" ] || TOOL_MESH=$(kubectl get toolconfig "$TOOL" -n components -o jsonpath='{.status.endpoint}' 2>/dev/null || true)
  if [ -z "$TOOL_MESH" ]; then
    echo "REFUSED: ToolConfig '$TOOL' has no endpoint in its status yet (status.endpoint)" >&2
    exit 2
  fi
  echo "   TOOL_MCP_URL=$TOOL_MESH TOOL_MCP_ALIAS=$TOOL"
  TOOL_ENV=1
fi

# Adds the tool variables to the generated file's environmentVariables map
# and validates the result server-side. Used by both the dry run and the
# real run, so a dry run proves the file the real run applies.
patch_tool_env() {
  python3 - "$1" "$TOOL_MESH" "$TOOL" <<'PY'
import sys
path, url, alias = sys.argv[1:4]
lines = open(path).read().split("\n")
for i, line in enumerate(lines):
    if line.strip() == "environmentVariables:":
        indent = " " * (len(line) - len(line.lstrip()) + 2)
        lines[i + 1:i + 1] = [f'{indent}TOOL_MCP_URL: "{url}"', f'{indent}TOOL_MCP_ALIAS: "{alias}"']
        break
else:
    sys.exit("could not find the environmentVariables block to patch")
open(path, "w").write("\n".join(lines))
PY
  kubectl apply --dry-run=server -f "$1" >/dev/null
  echo "   tool variables validated (server dry run): TOOL_MCP_URL=$TOOL_MESH"
}

if [ "$DRY_RUN" = "1" ]; then
  echo "== 2-3. --dry-run: generating the AgentConfig only (no image build, no CodeBuild)"
  OUT="/tmp/${NAME}-agentcore.dry-run.yaml"
  DRY_RUN_ARGS=(--name "$NAME" --model "$MODEL" --skills "$SKILLS" --role "$ROLE"
                --image "DRYRUN-PLACEHOLDER-IMAGE-URI" --out "$OUT")
  if python3 "$REFERENCE_IMPL/make-agentcore-agents.py" "${DRY_RUN_ARGS[@]}"; then
    echo "   wrote $OUT and validated it server-side (see above)"
  else
    rc=$?
    echo "   generator exited $rc — see its message above" >&2
    exit "$rc"
  fi
  if [ -n "$TOOL_ENV" ]; then
    patch_tool_env "$OUT"
  fi
  echo "== --dry-run stopping here. Re-run without --dry-run to build and apply for real."
  exit 0
fi

echo "== 2. building the arm64 image via build-agent-image.sh (this runs a real CodeBuild build)"
IMAGE_TAG="${NAME}"
URI_FILE="/tmp/${NAME}-image-uri"
TARGET=agentcore AGENT_SRC="$AGENT_DIR/agent.py" IMAGE_TAG="$IMAGE_TAG" \
  EXTRA_PIP='strands-agents[openai]==1.57.2 bedrock-agentcore==1.24.0 mcp==1.30.0 aws-opentelemetry-distro==0.21.0' \
  URI_FILE="$URI_FILE" bash "$REFERENCE_IMPL/build-agent-image.sh"
IMAGE_URI=$(cat "$URI_FILE")
echo "   image: $IMAGE_URI"

echo "== 3. generating the AgentConfig (make-agentcore-agents.py)"
OUT="/tmp/${NAME}-agentcore.yaml"
python3 "$REFERENCE_IMPL/make-agentcore-agents.py" --name "$NAME" --model "$MODEL" \
  --skills "$SKILLS" --role "$ROLE" --image "$IMAGE_URI" --out "$OUT"

if [ -n "$TOOL_ENV" ]; then
  echo "== adding --tool environment variables to the generated file"
  patch_tool_env "$OUT"
fi

echo "== 4. applying $OUT"
kubectl apply -f "$OUT"

echo
echo "next:"
echo "  1. Approve the agent (it sits in Reviewing until a human attests):"
echo "     kubectl annotate agentconfig ${NAME} -n components \\"
echo "       \"modaas.tmforum.org/approver=\$(whoami)@workshop\" \\"
echo "       \"modaas.tmforum.org/approval-attestation=Reviewed: governed gateway path only\" \\"
echo "       --overwrite"
echo "  2. Wait for the runtime and invoke it (through the AgentCore API, never a"
echo "     Bedrock or AgentCore host directly):"
echo "     ARN=\$(kubectl get agentconfig ${NAME} -n components -o jsonpath='{.status.agentRuntimeArn}')"
echo "     aws bedrock-agentcore invoke-agent-runtime --region \"\${AWS_REGION:-us-east-1}\" \\"
echo "       --agent-runtime-arn \"\$ARN\" --runtime-session-id \"${NAME}-\$(python3 -c 'import uuid; print(uuid.uuid4().hex)')\" \\"
echo "       --content-type application/json --accept application/json --cli-binary-format raw-in-base64-out \\"
echo "       --payload '{\"correlation_id\":\"probe-1\",\"context\":{\"question\":\"hello\"}}' /tmp/${NAME}-answer.json"
echo "       cat /tmp/${NAME}-answer.json"
