#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# bootstrap-platform.sh — install the AI-native ODA Canvas platform into this
# team's account, unattended, so every event ARRIVES with it deployed:
#   ODA Canvas -> Gateway API + agentgateway -> the five MoDaaS images
#   (built in this account by its own CodeBuild project) -> the modaas chart
#   (three operators, the four CRDs, authz-gateway, PDP).
#
# Launched by static/cfn/02-code-editor.yaml UserData AFTER cfn-signal, as a
# transient systemd unit running as ec2-user. It never gates the stack: the
# IDE is usable while this runs, and a failure here is reported, not fatal to
# the event.
#
# The commands are the facilitator guide's, run and measured live on event
# 0147c02d on 2026-09-25. Deliberate differences, each for unattended use:
#   - it waits for the cluster stack to finish, and for Ready nodes, before
#     touching the cluster (it does not rely on Workshop Studio's stack order);
#   - builds are polled by the IDs start-build returns (the IDE role has
#     BatchGetBuilds, not ListBuildsForProject), and an image already in ECR
#     at the pinned tag is not rebuilt;
#   - every step is idempotent (helm upgrade --install, kubectl apply), and
#     the ODA Canvas step is skipped when its release is already deployed, so
#     a re-run after a failure, or on a replacement IDE instance, converges
#     in minutes instead of redoing the whole install.
#
# Status, one line, readable without sudo:   ~/.modaas-bootstrap/status
#     RUNNING <step> | READY <utc> | FAILED <step>: <reason>
# Full log:                                  ~/.modaas-bootstrap/bootstrap.log
# CloudWatch: MoDaaS/Workshop PlatformReady (dimension StackName) = 1 | 0
#
# Re-run by hand, safe at any time:
#     bash ~/.modaas-bootstrap/bootstrap-platform.sh
set -Eeuo pipefail

DIR="$HOME/.modaas-bootstrap"
mkdir -p "$DIR"
LOG="$DIR/bootstrap.log"
STATUS="$DIR/status"
ENVF="$DIR/env"

# One run at a time. A second invocation while one is in flight exits quietly
# instead of racing it through helm.
exec 9>"$DIR/lock"
if ! flock -n 9; then
  echo "another bootstrap run holds $DIR/lock; see $STATUS"
  exit 0
fi

exec > >(tee -a "$LOG") 2>&1

# Inputs. UserData passes them on the first run and they are persisted, so a
# hand re-run needs no arguments.
if [ -f "$ENVF" ]; then
  # shellcheck disable=SC1090
  . "$ENVF"
fi
REGION="${REGION:-${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}}"
ASSETS_BUCKET="${ASSETS_BUCKET:-}"
ASSETS_PREFIX="${ASSETS_PREFIX:-}"
IDE_STACK="${IDE_STACK:-unknown}"
printf 'REGION=%q\nASSETS_BUCKET=%q\nASSETS_PREFIX=%q\nIDE_STACK=%q\n' \
  "$REGION" "$ASSETS_BUCKET" "$ASSETS_PREFIX" "$IDE_STACK" > "$ENVF"
export AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION"
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"

STEP="start"
T0=$(date +%s)
metric() {
  aws cloudwatch put-metric-data --region "$REGION" --namespace "MoDaaS/Workshop" \
    --metric-name PlatformReady --dimensions "StackName=$IDE_STACK" \
    --value "$1" >/dev/null 2>&1 || true
}
step() {
  STEP="$1"
  echo "RUNNING $STEP" > "$STATUS"
  printf '\n==> [%s +%ss] %s\n' "$(date -u +%H:%M:%S)" "$(( $(date +%s) - T0 ))" "$STEP"
}
fail() {
  echo "FAILED $STEP: $*" > "$STATUS"
  echo "FAILED $STEP: $*" >&2
  metric 0
  exit 1
}
trap 'fail "line $LINENO: $BASH_COMMAND"' ERR

echo "=== bootstrap-platform $(date -u +%FT%TZ) region=$REGION ide-stack=$IDE_STACK"

# Re-run after completion: step 17 installs the governance guardrail and step
# 18 narrows this IDE's cluster identity to a participant, so the platform
# steps (CRDs, RBAC, admission) are DENIED on a second pass by design -- the
# IDE is a participant now. A completed run is therefore final; say so and
# stop, instead of failing at step 6 (seen on event 486b9241). Set
# BOOTSTRAP_FORCE=1 to run anyway (facilitator with a restored identity).
if grep -q '^READY ' "$STATUS" 2>/dev/null && [ "${BOOTSTRAP_FORCE:-0}" != "1" ]; then
  echo "    platform already READY ($(cat "$STATUS")); this IDE is now a participant and"
  echo "    cannot re-run the platform steps. Nothing to do. (BOOTSTRAP_FORCE=1 overrides.)"
  exit 0
fi

# ---------------------------------------------------------------------------
step "1/18 wait for the cluster stack to finish"
# The cluster stack is the one carrying the ModaasSourceVersion parameter (the
# same discovery the facilitator guide uses). On event 0147c02d Workshop
# Studio created it before the IDE stack, but nothing here relies on that.
STACK_NAME=""
for _ in $(seq 1 120); do
  STACK_NAME=$(aws cloudformation describe-stacks --region "$REGION" \
    --query "Stacks[?Parameters[?ParameterKey=='ModaasSourceVersion']].StackName | [0]" \
    --output text 2>/dev/null || true)
  [ -n "$STACK_NAME" ] && [ "$STACK_NAME" != "None" ] && break
  STACK_NAME=""; sleep 30
done
[ -n "$STACK_NAME" ] || fail "no stack with a ModaasSourceVersion parameter after 60 min"
echo "    cluster stack: $STACK_NAME"
for _ in $(seq 1 120); do
  # A transient API error must not kill a 60-minute wait: read it as UNKNOWN
  # and poll again.
  ST=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" \
    --query 'Stacks[0].StackStatus' --output text 2>/dev/null || echo UNKNOWN)
  case "$ST" in
    CREATE_COMPLETE|UPDATE_COMPLETE) break ;;
    *_FAILED|*ROLLBACK*|DELETE_*)
      fail "cluster stack $STACK_NAME is $ST -- re-provision this team (Workshop Studio: Teams -> Actions -> Revalidate deployment)" ;;
  esac
  sleep 30
done
[ "$ST" = "CREATE_COMPLETE" ] || [ "$ST" = "UPDATE_COMPLETE" ] \
  || fail "cluster stack $STACK_NAME still $ST after 60 min"
echo "    $STACK_NAME is $ST"

# ---------------------------------------------------------------------------
step "2/18 derive the environment from the stack"
STACK_JSON=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" \
  --region "$REGION" --output json)
out() { printf '%s' "$STACK_JSON" | python3 -c \
  "import json,sys;print(next(o['OutputValue'] for o in json.load(sys.stdin)['Stacks'][0]['Outputs'] if o['OutputKey']=='$1'))"; }
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_HOST="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"
NODE_ROLE_ARN=$(out NodeRoleArn)   # read for the guard below; not passed to the chart (G55)
# The execution role every managed AgentCore Runtime agent runs as. The CR
# never names it (per design); the platform supplies it here, and the agent
# operator refuses with PlatformExecutionRoleUnset when it is empty -- which is
# what every event before 2026-09-27 did, because this line and its --set did
# not exist (discovery 1.20). tools/check-bootstrap-parity.py now fails if
# either goes missing again.
AGENTCORE_ROLE_ARN=$(out AgentCoreRuntimeRoleArn)
CLUSTER_NAME=$(out ClusterName)
BUILD_PROJECT=$(out ImageBuildProjectName)
SOURCE_ZIP=$(out SourceZipS3Uri)
MODAAS_SHA=$(printf '%s' "$STACK_JSON" | python3 -c \
  "import json,sys;print(next(p['ParameterValue'] for p in json.load(sys.stdin)['Stacks'][0]['Parameters'] if p['ParameterKey']=='ModaasSourceVersion'))")
for kv in "ACCOUNT_ID=$ACCOUNT_ID" "NODE_ROLE_ARN=$NODE_ROLE_ARN" "CLUSTER_NAME=$CLUSTER_NAME" \
          "AGENTCORE_ROLE_ARN=$AGENTCORE_ROLE_ARN" \
          "BUILD_PROJECT=$BUILD_PROJECT" "SOURCE_ZIP=$SOURCE_ZIP" "MODAAS_SHA=$MODAAS_SHA"; do
  case "$kv" in
    *=|*=None) fail "${kv%%=*} is empty -- every later step would silently misconfigure" ;;
    *) echo "    ok $kv" ;;
  esac
done

# ---------------------------------------------------------------------------
step "3/18 cluster access and Ready nodes"
aws eks update-kubeconfig --name "$CLUSTER_NAME" --region "$REGION" >/dev/null
if ! kubectl get ns >/dev/null 2>&1; then
  # UserData self-grants before cfn-signal, but only when it found the
  # cluster within its own 30-minute window. Grant here too; both calls are
  # no-ops when the entry already exists.
  ROLE_ARN=$(aws sts get-caller-identity --query Arn --output text \
    | sed -E 's|arn:aws:sts::([0-9]+):assumed-role/([^/]+)/.*|arn:aws:iam::\1:role/\2|')
  aws eks create-access-entry --cluster-name "$CLUSTER_NAME" --region "$REGION" \
    --principal-arn "$ROLE_ARN" --type STANDARD >/dev/null 2>&1 || true
  aws eks associate-access-policy --cluster-name "$CLUSTER_NAME" --region "$REGION" \
    --principal-arn "$ROLE_ARN" \
    --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy \
    --access-scope type=cluster >/dev/null 2>&1 || true
fi
for _ in $(seq 1 30); do kubectl get ns >/dev/null 2>&1 && break; sleep 10; done
kubectl get ns >/dev/null || fail "kubectl still cannot reach $CLUSTER_NAME"
for _ in $(seq 1 60); do
  [ "$(kubectl get nodes --no-headers 2>/dev/null | grep -c ' Ready ' || true)" -ge 1 ] && break
  sleep 15
done
kubectl wait --for=condition=Ready nodes --all --timeout=15m
kubectl get nodes --no-headers | sed 's/^/    /'

# ---------------------------------------------------------------------------
step "4/18 source tree (private pristine copy of the pinned zip)"
# Not ~/environment/modaas-aigateway: participants edit that tree in Modules
# 7 and 8, and a re-run must install exactly what the pin says.
SRC="$DIR/src"
aws s3 cp "$SOURCE_ZIP" "$DIR/src.zip" --region "$REGION" --only-show-errors
rm -rf "$SRC" && mkdir -p "$SRC" && unzip -oq "$DIR/src.zip" -d "$SRC" && rm -f "$DIR/src.zip"
[ -d "$SRC/deploy/helm/modaas" ] && [ -d "$SRC/deploy/agentgateway" ] \
  || fail "source zip lacks deploy/helm/modaas or deploy/agentgateway"
cd "$SRC"

# The workshop's own files (tool handlers, CRs, scripts, the helper) are NOT in
# the platform zip; they are staged one object at a time into the asset bucket
# (tools/stage-assets.sh enumerates exactly the ${ASSETS_PREFIX}<path> literals
# in this file, so every file named here is guaranteed staged; a directory
# copy would silently fetch nothing).
ASSETS="$DIR/assets"
fetch_asset() {  # fetch_asset <path-under-prefix>
  # The event's asset bucket is frozen at build-cut time, so a file already
  # fetched on an earlier run of this same event is current; skip it.
  [ -s "$ASSETS/$1" ] && return 0
  mkdir -p "$ASSETS/$(dirname "$1")"
  aws s3 cp "s3://${ASSETS_BUCKET}/${ASSETS_PREFIX}$1" "$ASSETS/$1" --region "$REGION" --only-show-errors \
    || fail "asset not staged: ${ASSETS_PREFIX}$1 (run tools/stage-assets.sh and cut a new build)"
}
[ -n "$ASSETS_BUCKET" ] || fail "ASSETS_BUCKET unset; cannot fetch workshop assets"
for a in \
  "${ASSETS_PREFIX}lambda/cluster-status/handler.py"    "${ASSETS_PREFIX}lambda/cluster-status/toolconfig.yaml" \
  "${ASSETS_PREFIX}lambda/cr-author/handler.py"         "${ASSETS_PREFIX}lambda/cr-author/toolconfig.yaml" \
  "${ASSETS_PREFIX}lambda/customer-records/handler.py"  "${ASSETS_PREFIX}lambda/customer-records/toolconfig.yaml" \
  "${ASSETS_PREFIX}lambda/evidence-lookup/handler.py"   "${ASSETS_PREFIX}lambda/evidence-lookup/toolconfig.yaml" \
  "${ASSETS_PREFIX}lambda/modaas-docs/handler.py"       "${ASSETS_PREFIX}lambda/modaas-docs/toolconfig.yaml" \
  "${ASSETS_PREFIX}lambda/network-twin/handler.py"      "${ASSETS_PREFIX}lambda/network-twin/toolconfig.yaml" \
  "${ASSETS_PREFIX}lambda/runbook-lookup/handler.py"    "${ASSETS_PREFIX}lambda/runbook-lookup/toolconfig.yaml" \
  "${ASSETS_PREFIX}data/customer-records.json" "${ASSETS_PREFIX}data/it-incidents.json" \
  "${ASSETS_PREFIX}data/network-inventory.json" "${ASSETS_PREFIX}data/twin-dataset.json" \
  "${ASSETS_PREFIX}kb/index.json" \
  "${ASSETS_PREFIX}crs/aws-knowledge-toolconfig.yaml" \
  "${ASSETS_PREFIX}crs/demo-nemotron-models.yaml" \
  "${ASSETS_PREFIX}crs/nemotron-super-120b-helper-modelconfig.yaml" \
  "${ASSETS_PREFIX}reference-impl/build-agent-image.sh" \
  "${ASSETS_PREFIX}reference-impl/make-agentcore-agents.py" \
  "${ASSETS_PREFIX}reference-impl/audit-store.py" \
  "${ASSETS_PREFIX}reference-impl/audit-store.yaml" \
  "${ASSETS_PREFIX}reference-impl/audit-store-agentcore.yaml" \
  "${ASSETS_PREFIX}agents/hackathon-helper/agent.py" \
  "${ASSETS_PREFIX}scripts/rbac/participant-builder.yaml" \
  "${ASSETS_PREFIX}scripts/rbac/governance-guardrail.yaml" \
  "${ASSETS_PREFIX}starter/ask-agent.sh" \
  "${ASSETS_PREFIX}starter/incluster" \
  "${ASSETS_PREFIX}starter/ask_agent.py" \
; do fetch_asset "${a#"${ASSETS_PREFIX}"}"; done
echo "    workshop assets fetched to $ASSETS"

# `ask-agent.sh <agent> "<question>"` is how every module and the helper intro
# tell participants to talk to a governed agent, from Getting Started onward,
# and no module downloads it first (new-tool.sh / new-agent.sh are fetched in
# their own modules). Put it on PATH now so the first command on the first
# page works. Both files, side by side: the shell wrapper execs the Python.
sudo install -m 0755 "$ASSETS/starter/ask-agent.sh" /usr/local/bin/ask-agent.sh
sudo install -m 0644 "$ASSETS/starter/ask_agent.py" /usr/local/bin/ask_agent.py
# `incluster NAME -- CMD` runs a probe pod inside the cluster. Module 2 Step 7
# defines it inline to teach it; Modules 5 and 6 then call it from whatever
# terminal the participant has open (E6 2026-10-03: a fresh terminal on the
# Call page got "incluster: command not found").
sudo install -m 0755 "$ASSETS/starter/incluster" /usr/local/bin/incluster
echo "    ask-agent.sh and incluster installed on PATH"

# ---------------------------------------------------------------------------
step "5/18 ODA Canvas"
if helm status canvas -n canvas -o json 2>/dev/null \
     | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)["info"]["status"]=="deployed" else 1)'; then
  echo "    canvas release already deployed -- skipping install-canvas.sh"
else
  [ -n "$ASSETS_BUCKET" ] || fail "ASSETS_BUCKET unset; cannot fetch install-canvas.sh"
  aws s3 cp "s3://${ASSETS_BUCKET}/${ASSETS_PREFIX}scripts/install-canvas.sh" \
    "$DIR/install-canvas.sh" --region "$REGION" --only-show-errors
  bash "$DIR/install-canvas.sh"
fi

# ---------------------------------------------------------------------------
step "6/18 Gateway API + agentgateway, then wait for Programmed"
# Order matters: the modaas chart references AgentgatewayPolicy
# unconditionally, so the agentgateway CRDs must exist first.
# --force-conflicts on both server-side applies: a re-run applies the same
# pinned manifests, and must take the fields back rather than stop on a
# conflict with the helm adoption below.
kubectl apply --server-side --force-conflicts -f \
  https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/standard-install.yaml >/dev/null
helm template agw-crds oci://cr.agentgateway.dev/charts/agentgateway-crds \
  --version 1.4.1 > "$DIR/agw-crds.yaml"
kubectl apply --server-side --force-conflicts -f "$DIR/agw-crds.yaml" >/dev/null
# Adopted into the modaas release: not a standalone release, and not skipped.
for CRD in $(kubectl get crds -o name | grep agentgateway.dev); do
  kubectl annotate "$CRD" meta.helm.sh/release-name=modaas \
    meta.helm.sh/release-namespace=modaas-system --overwrite >/dev/null
  kubectl label "$CRD" app.kubernetes.io/managed-by=Helm --overwrite >/dev/null
done
kubectl create namespace agentgateway-system --dry-run=client -o yaml | kubectl apply -f - >/dev/null
# agentgatewayModels.enabled belongs on THIS release, not the modaas chart.
helm upgrade --install agentgateway oci://cr.agentgateway.dev/charts/agentgateway \
  --version 1.4.1 -n agentgateway-system --skip-crds \
  --set agentgatewayModels.enabled=true
# G64 (2026-09-27): the perimeter key store is per event. The core ref's
# deploy/agentgateway/apikey-secret.yaml commits a literal key, and every event
# used it on an internet-facing listener: anyone who had read either repo held
# a valid credential for every event. Generate one per event; a re-run keeps
# the event's key, and replaces the committed eval literal if it finds it.
GW_KEY_B64=$(kubectl get secret agw-apikeys -n agentgateway-system \
  -o jsonpath='{.data.eval-key}' 2>/dev/null || true)
GW_KEY=""
[ -z "$GW_KEY_B64" ] || GW_KEY=$(printf '%s' "$GW_KEY_B64" | base64 -d)
case "$GW_KEY" in
  ""|agw-*-eval-key) GW_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(24))') ;;
esac
kubectl create secret generic agw-apikeys -n agentgateway-system \
  --from-literal=eval-key="$GW_KEY" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
for f in deploy/agentgateway/*.yaml; do
  # A top-level Secret is the committed key store; the event's is set above.
  grep -qE '^kind:[[:space:]]*Secret[[:space:]]*$' "$f" && continue
  kubectl apply -f "$f"
done
kubectl wait --for=condition=Programmed gateway/modaas-agw -n agentgateway-system --timeout=10m
echo "    modaas-agw address: $(kubectl get gateway modaas-agw -n agentgateway-system -o jsonpath='{.status.addresses[0].value}')"

# ---------------------------------------------------------------------------
step "7/18 build the five MoDaaS images in this account's CodeBuild"
IDS=""
for pair in \
  "aws-model-operator:operators/aws-model-operator" \
  "aws-tool-operator:operators/aws-tool-operator" \
  "aws-agent-operator:operators/aws-agent-operator" \
  "authz-gateway:authz-gateway" \
  "pdp:pdp" ; do
  REPO="${pair%%:*}"; SUBDIR="${pair#*:}"
  if aws ecr describe-images --repository-name "${STACK_NAME}-${REPO}" --region "$REGION" \
       --image-ids imageTag="$MODAAS_SHA" >/dev/null 2>&1; then
    echo "    $REPO:${MODAAS_SHA:0:12} already in ECR -- not rebuilding"
    continue
  fi
  ID=$(aws codebuild start-build --project-name "$BUILD_PROJECT" --region "$REGION" \
    --environment-variables-override \
      name=REPO_NAME,value="$REPO" \
      name=SUBDIR,value="$SUBDIR" \
      name=ECR_REPO_URI,value="${ECR_HOST}/${STACK_NAME}-${REPO}" \
    --query 'build.id' --output text)
  echo "    started $REPO -> $ID"
  IDS="$IDS $ID"
done
if [ -n "$IDS" ]; then
  for _ in $(seq 1 90); do
    # shellcheck disable=SC2086
    PENDING=$(aws codebuild batch-get-builds --ids $IDS --region "$REGION" \
      --query 'length(builds[?buildStatus==`IN_PROGRESS`])' --output text 2>/dev/null || echo unknown)
    [ "$PENDING" = "0" ] && break
    sleep 20
  done
  # shellcheck disable=SC2086
  BAD=$(aws codebuild batch-get-builds --ids $IDS --region "$REGION" \
    --query 'builds[?buildStatus!=`SUCCEEDED`].[id,buildStatus,logs.deepLink]' --output text)
  [ -z "$BAD" ] || fail "image build(s) did not succeed: $BAD"
  echo "    all builds SUCCEEDED"
fi

# Standard step, once per install: modaas-agw is created by the agentgateway
# controller and has been seen starting before its Pod Identity association is
# live. Marker-gated so a later re-run does not blip participants' traffic.
if [ ! -f "$DIR/agw-restarted" ]; then
  kubectl rollout restart deploy/modaas-agw -n agentgateway-system
  kubectl rollout status deploy/modaas-agw -n agentgateway-system --timeout=5m
  touch "$DIR/agw-restarted"
fi

# ---------------------------------------------------------------------------
step "8/18 the modaas chart, then verify"
PDP_DIGEST=$(aws ecr describe-images --repository-name "${STACK_NAME}-pdp" \
  --region "$REGION" --image-ids imageTag="$MODAAS_SHA" \
  --query "imageDetails[0].imageDigest" --output text)
case "$PDP_DIGEST" in sha256:*) ;; *) fail "PDP_DIGEST is '$PDP_DIGEST', not a sha256 digest" ;; esac
helm dependency update ./deploy/helm/modaas >/dev/null
# Two values are deliberately absent from this command. Comments stay ABOVE it:
# a comment line inside a backslash-continued command ends the command there
# (event 8acc8261, 2026-09-27: helm ran without --namespace and failed on every
# event built from ba752107; sensor tools/check-shell-continuations.py).
# - authzGateway.irsaRoleArn (G55, 2026-09-27): this cluster has no OIDC
#   provider and the node role is not a web-identity role, so annotating the
#   authz ServiceAccount with it only ever produced InvalidIdentityToken. With
#   sigv4IdentityMode=reject (values-workshop.yaml, D1) the gateway makes no AWS
#   call and needs no role at all.
# - registryMode (2026-09-27): the pinned platform calls the GA AWS Agent
#   Registry (agent-registry), so the chart's default `real` is right. Every
#   earlier event forced `stub` because the previous pin called the preview
#   namespace, which vended accounts refuse and which stops working on
#   30 October 2026.
helm upgrade --install modaas ./deploy/helm/modaas \
  -f ./deploy/helm/modaas/values-workshop.yaml \
  --set-string global.aws.accountId="$ACCOUNT_ID" \
  --set-string global.aws.region="$REGION" \
  --set operators.model.image.registry="$ECR_HOST" \
  --set operators.model.image.repository="${STACK_NAME}-aws-model-operator" \
  --set-string operators.model.image.tag="$MODAAS_SHA" \
  --set operators.tool.image.registry="$ECR_HOST" \
  --set operators.tool.image.repository="${STACK_NAME}-aws-tool-operator" \
  --set-string operators.tool.image.tag="$MODAAS_SHA" \
  --set operators.agent.image.registry="$ECR_HOST" \
  --set operators.agent.image.repository="${STACK_NAME}-aws-agent-operator" \
  --set-string operators.agent.image.tag="$MODAAS_SHA" \
  --set-string operators.agent.agentCoreRuntimeRoleArn="$AGENTCORE_ROLE_ARN" \
  --set authzGateway.image.registry="$ECR_HOST" \
  --set authzGateway.image.repository="${STACK_NAME}-authz-gateway" \
  --set-string authzGateway.image.tag="$MODAAS_SHA" \
  --set pdp.image.registry="$ECR_HOST" \
  --set pdp.image.repository="${STACK_NAME}-pdp" \
  --set-string pdp.image.digest="$PDP_DIGEST" \
  --set agentgateway.agentgatewayModels.enabled=true \
  --set-string gatewayCredential.bootstrapKey="$GW_KEY" \
  --namespace modaas-system --create-namespace
kubectl wait --for=condition=Available deploy --all -n modaas-system --timeout=10m

# The tool operator renders the AgentCore Gateway resource policy around the
# role modaas-agw signs with; the chart has no value for it, so hand it over
# here (re-applied on every run because helm upgrade would drop a bare patch).
AGW_SIGNING_ROLE_ARN=$(out AgentgatewayBedrockRoleArn 2>/dev/null || true)
if [ -n "$AGW_SIGNING_ROLE_ARN" ]; then
  kubectl set env deploy/aws-tool-operator -n modaas-system \
    MODAAS_AGW_SIGNING_ROLE_ARN="$AGW_SIGNING_ROLE_ARN" >/dev/null
  kubectl rollout status deploy/aws-tool-operator -n modaas-system --timeout=5m >/dev/null
  echo "    tool operator signing principal: $AGW_SIGNING_ROLE_ARN"
else
  echo "    WARNING: AgentgatewayBedrockRoleArn output missing; PerimeterEnforced will read SigningPrincipalUnknown"
fi

# Every operator must know its Region from the chart. A pod without
# AWS_DEFAULT_REGION would, before fa01d43e, silently call us-west-2.
for op in aws-model-operator aws-tool-operator aws-agent-operator; do
  got=$(kubectl get deploy "$op" -n modaas-system \
    -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="AWS_DEFAULT_REGION")].value}')
  [ "$got" = "$REGION" ] || fail "$op has AWS_DEFAULT_REGION='$got', expected '$REGION'"
done
echo "    operators pinned to region $REGION"
kubectl get deploy -n modaas-system --no-headers | sed 's/^/    /'
for crd in modelconfigs toolconfigs agentconfigs registries; do
  kubectl get crd "${crd}.oda.tmforum.org" >/dev/null || fail "CRD ${crd}.oda.tmforum.org missing"
done
echo "    4 MoDaaS CRDs present"
kubectl get gateway modaas-agw -n agentgateway-system \
  -o jsonpath='{.status.conditions[?(@.type=="Programmed")].status}' | grep -qx True \
  || fail "gateway modaas-agw is no longer Programmed"

# Pre-pull the two curl images the modules' probe pods use, onto every node.
# On a fresh cluster the first probe on each node pulls the image, and
# `kubectl run --rm -i` then attaches after curl has already printed, so the
# participant sees nothing: measured 2026-09-25 on event 5ad438ac, the two
# Module 5 refusal probes that each triggered a first pull printed nothing,
# while every probe on a node that already had the image printed its body.
# Best effort: a failed pre-pull costs a blank first probe, not the platform.
if kubectl apply -f - >/dev/null <<'YAML'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: modaas-prepull
  namespace: default
spec:
  selector:
    matchLabels: {app: modaas-prepull}
  template:
    metadata:
      labels: {app: modaas-prepull}
    spec:
      terminationGracePeriodSeconds: 0
      containers:
      - {name: curl-pinned, image: "curlimages/curl:8.5.0", command: ["sleep", "600"]}
YAML
then
  if kubectl rollout status ds/modaas-prepull -n default --timeout=5m >/dev/null; then
    echo "    probe images pre-pulled on every node"
  else
    echo "    WARNING: probe image pre-pull did not finish; first probes may print nothing"
  fi
  kubectl delete ds/modaas-prepull -n default --wait=false >/dev/null || true
else
  echo "    WARNING: could not create the pre-pull DaemonSet; first probes may print nothing"
fi

# ---------------------------------------------------------------------------
step "9/18 team identity"
# Derive the team slug from the Workshop Studio team number if available,
# else hash the account id. Write ConfigMap + /etc/profile.d export.
WS_TEAM_NUMBER=""
if command -v jq >/dev/null; then
  WS_TEAM_NUMBER=$(aws cloudformation describe-stacks --stack-name "$IDE_STACK" --region "$REGION" \
    --query "Stacks[0].Tags[?Key=='ws:team-number'].Value | [0]" --output text 2>/dev/null || true)
fi
if [ -n "$WS_TEAM_NUMBER" ] && [ "$WS_TEAM_NUMBER" != "None" ]; then
  TEAM="t$(printf '%02d' "$WS_TEAM_NUMBER")"
else
  TEAM="a$(printf '%s' "$ACCOUNT_ID" | sha256sum | cut -c1-4)"
fi
echo "    team slug: $TEAM"
kubectl create namespace modaas-system --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl create configmap workshop-identity -n modaas-system \
  --from-literal=team="$TEAM" --from-literal=event="$IDE_STACK" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
sudo tee /etc/profile.d/modaas-team.sh >/dev/null <<PROF
export TEAM="$TEAM"
PROF
export TEAM

# ---------------------------------------------------------------------------
step "10/18 AgentCore Gateway"
GATEWAY_ROLE_ARN=$(out AgentCoreGatewayServiceRoleArn 2>/dev/null || true)
if [ -z "$GATEWAY_ROLE_ARN" ] || [ "$GATEWAY_ROLE_ARN" = "None" ]; then
  fail "AgentCoreGatewayServiceRoleArn output missing from the cluster stack; every Gateway tool depends on it"
else
  EXISTING_GW=$(aws bedrock-agentcore-control list-gateways --region "$REGION" \
    --query "items[?name=='modaas-agw'].gatewayId | [0]" --output text 2>/dev/null || true)
  if [ -n "$EXISTING_GW" ] && [ "$EXISTING_GW" != "None" ]; then
    GW_STATUS=$(aws bedrock-agentcore-control get-gateway --region "$REGION" --gateway-identifier "$EXISTING_GW" --query status --output text)
    if [ "$GW_STATUS" = "FAILED" ]; then
      echo "    gateway $EXISTING_GW is FAILED ($(aws bedrock-agentcore-control get-gateway --region "$REGION" --gateway-identifier "$EXISTING_GW" --query 'statusReasons[0]' --output text | cut -c1-160)); deleting and recreating"
      aws bedrock-agentcore-control delete-gateway --region "$REGION" --gateway-identifier "$EXISTING_GW" >/dev/null
      for _ in $(seq 1 30); do
        aws bedrock-agentcore-control get-gateway --region "$REGION" --gateway-identifier "$EXISTING_GW" >/dev/null 2>&1 || break
        sleep 5
      done
      EXISTING_GW=""
    fi
  fi
  if [ -n "$EXISTING_GW" ] && [ "$EXISTING_GW" != "None" ]; then
    MODAAS_GATEWAY_ID="$EXISTING_GW"
    echo "    gateway already exists: $MODAAS_GATEWAY_ID"
  else
    # Control-plane API; the Gateway speaks MCP and authenticates callers
    # with SigV4 (same shape the reviewer kit proved live).
    MODAAS_GATEWAY_ID=$(aws bedrock-agentcore-control create-gateway --region "$REGION" \
      --name modaas-agw \
      --protocol-type MCP --authorizer-type AWS_IAM \
      --role-arn "$GATEWAY_ROLE_ARN" \
      --query 'gatewayId' --output text)
    echo "    created gateway: $MODAAS_GATEWAY_ID"
  fi
  # A gateway is usable only once READY; CREATING takes ~30 s, FAILED names its reason.
  for _ in $(seq 1 36); do
    GW_STATUS=$(aws bedrock-agentcore-control get-gateway --region "$REGION" --gateway-identifier "$MODAAS_GATEWAY_ID" --query status --output text)
    [ "$GW_STATUS" = "READY" ] && break
    [ "$GW_STATUS" = "FAILED" ] && break
    sleep 5
  done
  [ "$GW_STATUS" = "READY" ] || fail "gateway $MODAAS_GATEWAY_ID is $GW_STATUS: $(aws bedrock-agentcore-control get-gateway --region "$REGION" --gateway-identifier "$MODAAS_GATEWAY_ID" --query 'statusReasons' --output text)"
  echo "    gateway READY"
  MODAAS_GATEWAY_URL=$(aws bedrock-agentcore-control get-gateway --region "$REGION" \
    --gateway-identifier "$MODAAS_GATEWAY_ID" --query 'gatewayUrl' --output text)
  kubectl create configmap modaas-gateway -n modaas-system \
    --from-literal=gatewayId="$MODAAS_GATEWAY_ID" \
    --from-literal=gatewayUrl="$MODAAS_GATEWAY_URL" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  echo "    gateway URL: $MODAAS_GATEWAY_URL"
fi
# Participants declare their own Lambda tools against this Gateway, in this
# account and Region; put the three values in every shell alongside TEAM.
sudo tee -a /etc/profile.d/modaas-team.sh >/dev/null <<PROF
export MODAAS_GATEWAY_ID="$MODAAS_GATEWAY_ID"
export ACCOUNT_ID="$ACCOUNT_ID"
export REGION="$REGION"
PROF
export MODAAS_GATEWAY_ID ACCOUNT_ID REGION

# ---------------------------------------------------------------------------
step "11/18 collector exporters and gateway telemetry export"
# The chart's collector sends traces to the debug exporter and only the
# evidence pipeline to CloudWatch. For the workshop: traces -> X-Ray, the
# gateway's per-call access log -> CloudWatch /aws/modaas/gateway, evidence
# -> /modaas/evidence (unchanged). agentgateway is told to export both its
# spans and its access log to the collector over OTLP gRPC. Same shape that
# was applied by hand and measured on the previous event (O1-O3); the
# collector role already holds xray:PutTraceSegments and the two log groups.
COLLECTOR_CM="otel-collector-config"
kubectl get configmap "$COLLECTOR_CM" -n modaas-system >/dev/null || fail "collector ConfigMap $COLLECTOR_CM missing (chart changed?)"
kubectl create configmap "$COLLECTOR_CM" -n modaas-system --dry-run=client -o yaml \
  --from-file=config.yaml=/dev/stdin <<CFG | kubectl apply -f - >/dev/null
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318
processors:
  batch:
    timeout: 5s
    send_batch_size: 256
  # Governance telemetry carries alias, identity and verdict, never prompt or
  # completion content. Dropped here so no exporter can receive it.
  attributes/scrub-payloads:
    actions:
      - {key: gen_ai.prompt, action: delete}
      - {key: gen_ai.completion, action: delete}
      - {key: gen_ai.input.messages, action: delete}
      - {key: gen_ai.output.messages, action: delete}
      - {key: modaas.request.body, action: delete}
      - {key: modaas.response.body, action: delete}
  k8sattributes:
    auth_type: serviceAccount
    passthrough: false
    pod_association:
      - sources:
          - from: connection
    extract:
      metadata: [k8s.namespace.name, k8s.deployment.name, k8s.pod.name]
  # Evidence records (written by authz) go to the evidence sink only; every
  # other log record (the gateway access log) goes to the gateway log group.
  filter/evidence-only:
    error_mode: ignore
    logs:
      log_record:
        - 'attributes["modaas.evidence.schema_version"] == nil'
  filter/not-evidence:
    error_mode: ignore
    logs:
      log_record:
        - 'attributes["modaas.evidence.schema_version"] != nil'
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
exporters:
  debug:
    verbosity: basic
  awsxray:
    region: "$REGION"
  awscloudwatchlogs:
    log_group_name: "/modaas/evidence"
    log_stream_name: "modaas-evidence"
    region: "$REGION"
    log_retention: 30
  awscloudwatchlogs/gateway:
    log_group_name: "/aws/modaas/gateway"
    log_stream_name: "modaas-agw"
    region: "$REGION"
    log_retention: 7
service:
  extensions: [health_check]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [attributes/scrub-payloads, batch]
      exporters: [awsxray]
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [debug]
    logs/audit:
      receivers: [otlp]
      processors: [k8sattributes, filter/evidence-only, batch]
      exporters: [awscloudwatchlogs]
    logs/gateway:
      receivers: [otlp]
      processors: [attributes/scrub-payloads, filter/not-evidence, batch]
      exporters: [awscloudwatchlogs/gateway]
  telemetry:
    logs:
      level: info
CFG
kubectl rollout restart deploy/opentelemetry-collector -n modaas-system >/dev/null
kubectl rollout status deploy/opentelemetry-collector -n modaas-system --timeout=5m >/dev/null
echo "    collector exports traces to X-Ray, gateway log to /aws/modaas/gateway, evidence to /modaas/evidence"
# agentgateway -> collector. Tracing: every call (randomSampling true), the
# correlation id and model as span attributes. Access log: OTLP export of
# the same per-call line the shipped modaas-access-log policy shapes.
kubectl apply -f - >/dev/null <<YAML
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayPolicy
metadata:
  name: modaas-telemetry-export
  namespace: agentgateway-system
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: modaas-agw
  frontend:
    tracing:
      backendRef:
        name: opentelemetry-collector
        namespace: modaas-system
        port: 4317
      protocol: GRPC
      randomSampling: "true"
      clientSampling: "true"
      resources:
        - name: service.name
          expression: '"modaas-agw"'
      attributes:
        add:
          - name: modaas.run_id
            expression: 'extauthz.correlationId'
          - name: modaas.action_id
            expression: 'extauthz.actionId'
    accessLog:
      otlp:
        backendRef:
          name: opentelemetry-collector
          namespace: modaas-system
          port: 4317
        protocol: GRPC
YAML
for _ in $(seq 1 30); do
  ACC=$(kubectl get agentgatewaypolicy modaas-telemetry-export -n agentgateway-system -o jsonpath='{.status.ancestors[0].conditions[?(@.type=="Accepted")].status}' 2>/dev/null || true)
  ATT=$(kubectl get agentgatewaypolicy modaas-telemetry-export -n agentgateway-system -o jsonpath='{.status.ancestors[0].conditions[?(@.type=="Attached")].status}' 2>/dev/null || true)
  [ "$ACC" = "True" ] && [ "$ATT" = "True" ] && break
  sleep 2
done
echo "    telemetry export policy: Accepted=$ACC Attached=$ATT"
[ "$ACC" = "True" ] && [ "$ATT" = "True" ] || fail "modaas-telemetry-export not accepted/attached: $(kubectl get agentgatewaypolicy modaas-telemetry-export -n agentgateway-system -o jsonpath='{.status.ancestors[0].conditions[*].message}')"

# ---------------------------------------------------------------------------
step "12/18 telemetry tap"
# The telemetry tap is a small Python OTLP/HTTP receiver with a ring buffer
# of 5000 entries and GET endpoints /spans, /logs, /decisions.
# Expects static/scripts/telemetry-tap/ in the asset bucket.
TAP_DIR="$DIR/telemetry-tap"
if aws s3 cp "s3://${ASSETS_BUCKET}/${ASSETS_PREFIX}scripts/telemetry-tap/" "$TAP_DIR/" \
     --recursive --region "$REGION" --only-show-errors 2>/dev/null; then
  if [ -f "$TAP_DIR/deployment.yaml" ]; then
    kubectl apply -f "$TAP_DIR/deployment.yaml" -n modaas-system
    echo "    telemetry tap deployed"
  else
    echo "    telemetry tap not shipped in this build; the cockpit's live panels show their empty state"
  fi
else
  echo "    WARNING: telemetry tap assets not available; skipping"
fi

# ---------------------------------------------------------------------------
step "13/18 ceiling policy"
# Account-wide ceiling on the llm listener, values from the cluster stack's
# parameters. Same shape as the shipped modaas-llm-auth policy
# (traffic.rateLimit.local[]); where two policies set the same field the
# lower value wins, so this can only tighten what the chart ships.
TOKEN_CEILING=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" \
  --query "Stacks[0].Parameters[?ParameterKey=='TokenCeilingPerHour'].ParameterValue | [0]" --output text 2>/dev/null || true)
REQ_CEILING=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" \
  --query "Stacks[0].Parameters[?ParameterKey=='RequestCeilingPerMinute'].ParameterValue | [0]" --output text 2>/dev/null || true)
[ -n "$TOKEN_CEILING" ] && [ "$TOKEN_CEILING" != "None" ] || TOKEN_CEILING=2500000
[ -n "$REQ_CEILING" ] && [ "$REQ_CEILING" != "None" ] || REQ_CEILING=100
echo "    token ceiling: $TOKEN_CEILING/h, request ceiling: $REQ_CEILING/min"
kubectl apply -f - >/dev/null <<YAML
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayPolicy
metadata:
  name: modaas-ceiling
  namespace: agentgateway-system
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: modaas-agw
      sectionName: llm
  traffic:
    rateLimit:
      local:
        - requests: $REQ_CEILING
          unit: Minutes
        - tokens: $TOKEN_CEILING
          unit: Hours
YAML
for _ in $(seq 1 30); do
  ACC=$(kubectl get agentgatewaypolicy modaas-ceiling -n agentgateway-system -o jsonpath='{.status.ancestors[0].conditions[?(@.type=="Accepted")].status}' 2>/dev/null || true)
  [ "$ACC" = "True" ] && break; sleep 2
done
[ "$ACC" = "True" ] || fail "modaas-ceiling policy not accepted"
echo "    ceiling policy applied"

# ---------------------------------------------------------------------------
step "14/18 Lambda tools deploy"
# Deploy Lambda functions from static/lambda/*/ if they exist in the asset
# bucket, and apply ToolConfig CRs from static/crs/ with placeholder
# substitution. Lane B owns the file layout.
LAMBDA_DIR="$ASSETS/lambda"
for TOOL_DIR in "$LAMBDA_DIR"/*/; do
  TOOL_NAME=$(basename "$TOOL_DIR")
  FUNC_NAME="team-${TEAM}-${TOOL_NAME}"
  [ -f "$TOOL_DIR/handler.py" ] || fail "no handler.py for tool $TOOL_NAME"
  if aws lambda get-function --function-name "$FUNC_NAME" --region "$REGION" >/dev/null 2>&1; then
    echo "    $FUNC_NAME already exists"
    continue
  fi
  # Package handler + the data it reads (every handler is stdlib-only; the
  # data files sit beside handler.py in the zip and DATA_DIR/INDEX_PATH point
  # at the Lambda task root).
  PKG="/tmp/lambda-pkg-$TOOL_NAME"; rm -rf "$PKG"; mkdir -p "$PKG"; cp "$TOOL_DIR/handler.py" "$PKG/"
  case "$TOOL_NAME" in
    customer-records|runbook-lookup) cp "$ASSETS"/data/customer-records.json "$ASSETS"/data/it-incidents.json "$ASSETS"/data/network-inventory.json "$PKG/" ;;
    network-twin) cp "$ASSETS"/data/twin-dataset.json "$PKG/" ;;
    modaas-docs) cp "$ASSETS"/kb/index.json "$PKG/" ;;
  esac
  (cd "$PKG" && rm -f /tmp/"$TOOL_NAME".zip && zip -qr /tmp/"$TOOL_NAME".zip .)
  PARTICIPANT_ROLE_ARN=$(out ParticipantAppRoleArn 2>/dev/null || true)
  if [ -z "$PARTICIPANT_ROLE_ARN" ] || [ "$PARTICIPANT_ROLE_ARN" = "None" ]; then
    PARTICIPANT_ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/participant-app-role"
  fi
  AUDIT_LB=$(kubectl get svc audit-store-agentcore -n components -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || true)
  aws lambda create-function --function-name "$FUNC_NAME" --region "$REGION" \
    --runtime python3.12 --handler handler.handler \
    --role "$PARTICIPANT_ROLE_ARN" \
    --zip-file "fileb:///tmp/${TOOL_NAME}.zip" \
    --timeout 30 --memory-size 256 \
    --environment "Variables={DATA_DIR=/var/task,INDEX_PATH=/var/task/index.json,CLUSTER_NAME=${CLUSTER_NAME},AUDIT_URL=${AUDIT_LB:+http://$AUDIT_LB:8080},GATEWAY_LOG_GROUP=/aws/modaas/gateway,TEAM=${TEAM}}" \
    --tags "modaas:team=$TEAM,modaas:kind=tool,modaas:event=$IDE_STACK" \
    --query 'FunctionArn' --output text || fail "create-function $FUNC_NAME failed"
  aws lambda wait function-active-v2 --function-name "$FUNC_NAME" --region "$REGION"
  echo "    created $FUNC_NAME"
done
# Apply the governed tool declarations. Each Lambda tool ships its ToolConfig
# beside its handler (static/lambda/<tool>/toolconfig.yaml); the public
# aws-knowledge MCP server is declared under static/crs/. Placeholders
# ${TEAM} ${REGION} ${ACCOUNT_ID} ${MODAAS_GATEWAY_ID} are substituted here.
# A failed apply is a failed bootstrap: a tool that silently never exists is
# the kind of defect participants cannot diagnose.
[ -n "$MODAAS_GATEWAY_ID" ] || fail "no AgentCore Gateway id; step 10 must create one before tools can be declared"
subst() {
  sed -e "s|\${TEAM}|${TEAM}|g" -e "s|\${REGION}|${REGION}|g" \
      -e "s|\${ACCOUNT_ID}|${ACCOUNT_ID}|g" -e "s|\${MODAAS_GATEWAY_ID}|${MODAAS_GATEWAY_ID}|g" "$1"
}
# cluster-status (a platform Lambda on participant-app-role) reads governed CRs
# through the Kubernetes API. Its IAM side is in the IDE stack; the cluster
# side is this access entry in the modaas:participants group, whose
# ClusterRole (scripts/rbac/participant-builder.yaml) covers the MoDaaS CRDs.
# AmazonEKSViewPolicy is NOT enough: it stops at built-in kinds and returned
# 403 on modelconfigs (event 486b9241). Without the entry the tool answered
# "cannot reach EKS cluster".
PARTICIPANT_APP_ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/participant-app-role"
if ! aws eks describe-access-entry --cluster-name "$CLUSTER_NAME" --region "$REGION" \
     --principal-arn "$PARTICIPANT_APP_ROLE_ARN" >/dev/null 2>&1; then
  aws eks create-access-entry --cluster-name "$CLUSTER_NAME" --region "$REGION" \
    --principal-arn "$PARTICIPANT_APP_ROLE_ARN" --type STANDARD \
    --kubernetes-groups modaas:participants >/dev/null
else
  aws eks update-access-entry --cluster-name "$CLUSTER_NAME" --region "$REGION" \
    --principal-arn "$PARTICIPANT_APP_ROLE_ARN" --kubernetes-groups modaas:participants >/dev/null
fi
echo "    participant-app-role: Kubernetes group modaas:participants (cluster-status tool)"
TOOL_CRS=()
for cr in "$ASSETS"/lambda/*/toolconfig.yaml "$ASSETS"/crs/aws-knowledge-toolconfig.yaml; do
  [ -f "$cr" ] || continue
  subst "$cr" | kubectl apply -f - || fail "ToolConfig apply failed: $(basename "$(dirname "$cr")")/$(basename "$cr")"
  TOOL_CRS+=("$(subst "$cr" | kubectl create --dry-run=client -o jsonpath='{.metadata.name}' -f -)")
done
echo "    declared ${#TOOL_CRS[@]} ToolConfigs: ${TOOL_CRS[*]}"
# Approve as the platform. The operator reads these two annotations
# (operators/shared/asset_operator.py APPROVAL_ANN_*); any other key is ignored
# and the CR stays in Reviewing forever.
for NAME in "${TOOL_CRS[@]}"; do
  kubectl annotate toolconfig "$NAME" -n components \
    modaas.tmforum.org/approver=system-admin \
    "modaas.tmforum.org/approval-attestation=Approved by the workshop platform at install" \
    --overwrite >/dev/null
done
# Wait for the Gateway targets to exist. Approved is the gate; Provisioned is
# the AWS-side truth (target created, route programmed).
for NAME in "${TOOL_CRS[@]}"; do
  for _ in $(seq 1 30); do
    PH=$(kubectl get toolconfig "$NAME" -n components -o jsonpath='{.status.phase}' 2>/dev/null || true)
    PROV=$(kubectl get toolconfig "$NAME" -n components -o jsonpath='{.status.conditions[?(@.type=="Provisioned")].status}' 2>/dev/null || true)
    [ "$PROV" = "True" ] && [ "$PH" = "Approved" ] && break
    [ "$PH" = "Failed" ] && break
    sleep 10
  done
  REASON=$(kubectl get toolconfig "$NAME" -n components -o jsonpath='{.status.conditions[?(@.type=="Provisioned")].reason}' 2>/dev/null || true)
  echo "    $NAME: phase=$PH Provisioned=$PROV ${REASON:+($REASON)}"
  if [ "$PH" != "Approved" ] || [ "$PROV" != "True" ]; then
    FAILMSG=$(kubectl get toolconfig "$NAME" -n components -o jsonpath='{range .status.conditions[?(@.status=="False")]}{.type}:{.reason} {end}' 2>/dev/null || true)
    fail "ToolConfig $NAME is phase=$PH Provisioned=$PROV ($FAILMSG); see kubectl -n modaas-system logs deploy/aws-tool-operator"
  fi
done
echo "    ToolConfigs approved and provisioned"

# ---------------------------------------------------------------------------
step "15/18 demo ModelConfigs"
# Apply ModelConfig CRs with ${TEAM}- prefix substitution and approve.
for cr in "$ASSETS"/crs/*model*.yaml "$ASSETS"/crs/*Model*.yaml; do
  [ -f "$cr" ] || continue
  subst "$cr" | kubectl apply -f - || fail "ModelConfig apply failed: $(basename "$cr")"
  echo "    applied $(basename "$cr")"
done
# Approval is carried IN the manifest for the models the platform itself
# needs (nemotron-nano-3-30b for cost comparison, nemotron-super-120b-helper
# for the helper). nemotron-nano-9b and nemotron-super-120b are deliberately
# left in Reviewing: Module 5 teaches participants to attest to them, and a
# blanket annotate here made that lesson a no-op (E6 walk, 2026-10-03: all
# four read Approved before the participant touched anything).
PLATFORM_MODELS=$(kubectl get modelconfigs.oda.tmforum.org -n components \
  -o jsonpath='{range .items[?(@.metadata.annotations.modaas\.tmforum\.org/approver)]}{.metadata.name} {end}')
echo "    platform-approved ModelConfigs: ${PLATFORM_MODELS:-none}"
for mc in $PLATFORM_MODELS; do
  for _ in $(seq 1 30); do
    PH=$(kubectl get modelconfig "$mc" -n components -o jsonpath='{.status.phase}' 2>/dev/null || true)
    [ "$PH" = "Approved" ] && break
    [ "$PH" = "Failed" ] && break
    sleep 10
  done
  echo "    $mc: $PH"
  [ "$PH" = "Approved" ] || fail "ModelConfig $mc is $PH, not Approved; see kubectl -n modaas-system logs deploy/aws-model-operator"
done
echo "    ModelConfigs approved"

# ---------------------------------------------------------------------------
step "16/18 hackathon-helper"
# Participants build and declare the three reference agents themselves
# (the reference-agents module); the platform ships only the helper. Image:
# the same single-file CodeBuild path participants use. AgentConfig: the same
# generator participants use, in --helper mode, so subnets, security group,
# evidence-store address and token are discovered, never templated.
AGENT_BUILD="$ASSETS/reference-impl/build-agent-image.sh"
HELPER_SRC="$ASSETS/agents/hackathon-helper/agent.py"
HELPER_URI_FILE=/tmp/agent-image-uri-hackathon-helper
[ -f "$AGENT_BUILD" ] || fail "missing $AGENT_BUILD"
[ -f "$HELPER_SRC" ] || fail "missing $HELPER_SRC"
echo "    building the hackathon-helper image (CodeBuild, arm64)"
TARGET=agentcore AGENT_SRC="$HELPER_SRC" IMAGE_TAG="hackathon-helper" URI_FILE="$HELPER_URI_FILE" \
  AWS_REGION="$REGION" bash "$AGENT_BUILD" || fail "hackathon-helper image build failed"
[ -s "$HELPER_URI_FILE" ] || fail "build wrote no image URI to $HELPER_URI_FILE"
echo "    image: $(cat "$HELPER_URI_FILE")"
# The evidence store the agent writes to must exist before the generator can
# discover its address (participants apply it in the reference-agents module;
# the platform needs it earlier for the helper).
# Same three objects the reference-agents module creates, same idempotent
# commands, so a participant re-running that module changes nothing.
kubectl get secret audit-write-token -n components >/dev/null 2>&1 || \
  kubectl create secret generic audit-write-token -n components \
    --from-literal=token="$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')" >/dev/null
kubectl create configmap audit-store-app -n components \
  --from-file=store.py="$ASSETS/reference-impl/audit-store.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl apply -f "$ASSETS/reference-impl/audit-store.yaml" >/dev/null
kubectl apply -f "$ASSETS/reference-impl/audit-store-agentcore.yaml" >/dev/null
for _ in $(seq 1 30); do
  [ -n "$(kubectl get svc audit-store-agentcore -n components -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null)" ] && break
  sleep 10
done
kubectl rollout status deploy/audit-store -n components --timeout=300s >/dev/null
# evidence-lookup was packaged in step 14, before this store existed, so its
# AUDIT_URL was empty ("AUDIT_URL environment variable not set", event
# 486b9241). Now that the address is known, give it to the function.
AUDIT_LB=$(kubectl get svc audit-store-agentcore -n components -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || true)
# That store is an internal load balancer: a Lambda outside the VPC cannot
# reach it (30 s timeout, event 486b9241). Place the function in the cluster's
# private subnets with the cluster security group, the same addresses the
# generator gives AgentCore runtimes.
if [ -n "$AUDIT_LB" ]; then
  EVIDENCE_SUBNETS=$(python3 - "$ASSETS/reference-impl/make-agentcore-agents.py" "$REGION" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("mk", sys.argv[1]); mk = importlib.util.module_from_spec(spec); spec.loader.exec_module(mk)
d = mk.Discovery(sys.argv[2]); print(",".join(d.subnets()) + " " + d.security_group())
PY
  )
  EVIDENCE_SG="${EVIDENCE_SUBNETS##* }"; EVIDENCE_SUBNETS="${EVIDENCE_SUBNETS%% *}"
  aws lambda update-function-configuration --function-name "team-${TEAM}-evidence-lookup" --region "$REGION" \
    --timeout 60 \
    --vpc-config "SubnetIds=${EVIDENCE_SUBNETS},SecurityGroupIds=${EVIDENCE_SG}" \
    --environment "Variables={DATA_DIR=/var/task,INDEX_PATH=/var/task/index.json,CLUSTER_NAME=${CLUSTER_NAME},AUDIT_URL=http://${AUDIT_LB}:8080,GATEWAY_LOG_GROUP=/aws/modaas/gateway,TEAM=${TEAM}}" \
    >/dev/null && aws lambda wait function-updated-v2 --function-name "team-${TEAM}-evidence-lookup" --region "$REGION" \
    && echo "    evidence-lookup: in VPC (${EVIDENCE_SUBNETS}), AUDIT_URL=http://${AUDIT_LB}:8080" \
    || echo "    FAIL evidence-lookup: UpdateFunctionConfiguration did not apply -- the IT agent's evidence lookups will fail (check IDE role ec2:Describe* and the error above)"
  # Verify, do not trust the echo: the live function must carry AUDIT_URL.
  _live_audit=$(aws lambda get-function-configuration --function-name "team-${TEAM}-evidence-lookup" --region "$REGION" --query 'Environment.Variables.AUDIT_URL' --output text 2>/dev/null || true)
  [ -n "$_live_audit" ] && [ "$_live_audit" != "None" ] || echo "    FAIL evidence-lookup: live AUDIT_URL is empty"
else
  echo "    FAIL evidence-lookup: audit-store load balancer address not available after 300s; AUDIT_URL left empty"
fi
python3 "$ASSETS/reference-impl/make-agentcore-agents.py" --helper --team "$TEAM" \
  --region "$REGION" --out /tmp/hackathon-helper.generated.yaml \
  || fail "helper AgentConfig generation failed"
kubectl apply -f /tmp/hackathon-helper.generated.yaml || fail "helper AgentConfig apply failed"
rm -f /tmp/hackathon-helper.generated.yaml   # carries the evidence write token
kubectl annotate agentconfig hackathon-helper -n components \
  modaas.tmforum.org/approver=system-admin \
  "modaas.tmforum.org/approval-attestation=Approved by the workshop platform at install" \
  --overwrite >/dev/null
# The agent operator's terminal state is phase=Approved with Provisioned=True
# (status.agentRuntimeArn set); there is no "Ready" phase in the pinned
# operator. Waiting for one timed out on event 486b9241 with a healthy runtime.
for _ in $(seq 1 60); do
  PH=$(kubectl get agentconfig hackathon-helper -n components -o jsonpath='{.status.phase}' 2>/dev/null || true)
  PROV=$(kubectl get agentconfig hackathon-helper -n components -o jsonpath='{.status.conditions[?(@.type=="Provisioned")].status}' 2>/dev/null || true)
  [ "$PH" = "Approved" ] && [ "$PROV" = "True" ] && break
  [ "$PH" = "Failed" ] && break
  sleep 10
done
RUNTIME_ARN=$(kubectl get agentconfig hackathon-helper -n components -o jsonpath='{.status.agentRuntimeArn}' 2>/dev/null || true)
echo "    hackathon-helper: phase=$PH Provisioned=$PROV runtime=${RUNTIME_ARN:-<none>}"
if [ "$PH" != "Approved" ] || [ "$PROV" != "True" ]; then
  FAILMSG=$(kubectl get agentconfig hackathon-helper -n components -o jsonpath='{range .status.conditions[?(@.status=="False")]}{.type}:{.reason} {end}' 2>/dev/null || true)
  fail "hackathon-helper is phase=$PH Provisioned=$PROV ($FAILMSG); see kubectl -n modaas-system logs deploy/aws-agent-operator"
fi

# ---------------------------------------------------------------------------
step "17/18 RBAC and guardrail"
# Apply the participant builder RBAC and the governance guardrail.
for rbac in "$ASSETS"/scripts/rbac/*.yaml; do
  [ -f "$rbac" ] || continue
  kubectl apply -f "$rbac"
  echo "    applied $(basename "$rbac")"
done

# ---------------------------------------------------------------------------
step "18/18 switch IDE access entry"
# The IDE instance role was ClusterAdmin during bootstrap (it needed to
# install everything). Now that RBAC and guardrail are applied, switch it
# to AmazonEKSAdminPolicy + modaas:participants group so it matches the
# participant access entry.
IDE_ROLE_ARN=$(aws sts get-caller-identity --query Arn --output text \
  | sed -E 's|arn:aws:sts::([0-9]+):assumed-role/([^/]+)/.*|arn:aws:iam::\1:role/\2|')
# Remove the old ClusterAdmin policy association.
aws eks disassociate-access-policy --cluster-name "$CLUSTER_NAME" --region "$REGION" \
  --principal-arn "$IDE_ROLE_ARN" \
  --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy 2>/dev/null || true
# Update the entry to add the participant group.
aws eks update-access-entry --cluster-name "$CLUSTER_NAME" --region "$REGION" \
  --principal-arn "$IDE_ROLE_ARN" \
  --kubernetes-groups modaas:participants 2>/dev/null || true
# Associate the builder-level policy.
aws eks associate-access-policy --cluster-name "$CLUSTER_NAME" --region "$REGION" \
  --principal-arn "$IDE_ROLE_ARN" \
  --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSAdminPolicy \
  --access-scope type=cluster 2>/dev/null || true
echo "    IDE access entry switched to AmazonEKSAdminPolicy + modaas:participants"
# Verify: the IDE can still read the cluster.
kubectl get ns >/dev/null || echo "    WARNING: kubectl lost access after the switch"

# ---------------------------------------------------------------------------
ELAPSED=$(( $(date +%s) - T0 ))
echo "READY $(date -u +%FT%TZ) (${ELAPSED}s)" > "$STATUS"
metric 1
trap - ERR
printf '\n=== READY in %ss: ODA Canvas, agentgateway, MoDaaS, agents, RBAC (%s)\n' "$ELAPSED" "${MODAAS_SHA:0:12}"
