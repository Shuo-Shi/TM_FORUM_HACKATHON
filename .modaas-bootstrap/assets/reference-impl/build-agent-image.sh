#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# Build the reference-agent image inside the workshop account via CodeBuild.
# The account reaches no external registry (by design), so the image is built
# here from agent.py + a pinned public.ecr.aws python base. Pushes into the
# CFT's agent-operator repo under a distinct tag: the CodeBuild role is scoped
# to the CFT-created repos, so a new repo would be denied (hit live).
#
# TWO TARGETS, one agent.py. Same code, same evidence chain, different host:
#
#   TARGET=pod        (default)  x86_64, tag reference-agent-v5
#                                -> AgentConfig provider=kubernetesPod
#                                   (static/reference-impl/agents.yaml)
#   TARGET=agentcore             arm64,  tag reference-agent-v5-agentcore
#                                -> AgentConfig provider=awsAgentCore
#                                   (static/reference-impl/agents-agentcore.yaml)
#
# Why the second target exists at all: AgentCore Runtime accepts ARM64
# containers ONLY -- "Platform: Must be linux/arm64", plus /invocations POST,
# /ping GET, port 8080 (docs.aws.amazon.com/bedrock-agentcore/latest/devguide/
# runtime-http-protocol-contract.html and .../getting-started-custom.html).
# The x86_64 image the pod target produces is accepted by Kubernetes and
# REJECTED by the runtime, and the failure surfaces at CreateAgentRuntime /
# first invoke, not at build time -- which is exactly the kind of late failure
# this repo's validate-before-claim discipline exists to catch earlier.
#
# HOW arm64 is reached: by overriding the CodeBuild environment to a native
# ARM host (ARM_CONTAINER + aws/codebuild/amazonlinux-aarch64-standard:3.0,
# BUILD_GENERAL1_LARGE -- the ARM-supported compute size, per
# docs.aws.amazon.com/codebuild/latest/userguide/ec2-compute-images.html and
# .../APIReference/API_ProjectEnvironment.html), then building plainly there.
# The AgentCore docs show `docker buildx build --platform linux/arm64` because
# their example builds on an x86 laptop and needs emulation; building on an
# aarch64 host does not, and a native build has no dependency on which buildx
# driver the build image happens to ship. What proves the result is not a flag
# but the explicit architecture assertion in the buildspec below: if the
# image is not arm64, the build fails instead of pushing something the runtime
# will refuse later.
#
# The StartBuild overrides need no extra IAM: the console policy's
# CodeBuildForModaasImageBuilds statement allows codebuild:StartBuild on the
# project with no condition keys, and environment overrides are part of that
# same call.
#
# DRY_RUN=1 prints the buildspec and the exact StartBuild argv, then exits 0
# WITHOUT calling AWS at all -- so the buildspec can be reviewed, diffed, and
# checked in CI by reading it rather than by spending a build.
#   TARGET=agentcore DRY_RUN=1 AGENT_SRC=static/reference-impl/agent.py \
#     bash static/reference-impl/build-agent-image.sh
set -euo pipefail

TARGET="${TARGET:-pod}"
DRY_RUN="${DRY_RUN:-0}"
# Module 7 section 0 curls agent.py to /tmp/agent.py before calling this, so
# that stays the default. Overridable so a dry run can point at the repo copy.
AGENT_SRC="${AGENT_SRC:-/tmp/reference-agent/agent.py}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"

case "$TARGET" in
  pod)
    TAG="reference-agent-v5"
    WANT_ARCH="amd64"
    URI_FILE="${URI_FILE:-/tmp/agent-image-uri}"
    ENV_OVERRIDES=()
    # Standard library only: the pod path reaches its peer over cluster DNS.
    SDK_PIP=""
    SDK_ENV=""
    ENTRY='["python3", "/app/agent.py"]'
    ;;
  agentcore)
    TAG="reference-agent-v5-agentcore"
    WANT_ARCH="arm64"
    # A separate file, so building the AgentCore image does not overwrite the
    # URI Module 7 section 0's `sed` into agents.yaml reads. What goes in it is
    # the image's DIGEST reference (repo@sha256:...), not the tag: see the end
    # of this script.
    URI_FILE="${URI_FILE:-/tmp/agent-image-uri-agentcore}"
    ENV_OVERRIDES=(
      --environment-type-override ARM_CONTAINER
      --image-override aws/codebuild/amazonlinux-aarch64-standard:3.0
      --compute-type-override BUILD_GENERAL1_LARGE
      --privileged-mode-override
    )
    # On AgentCore the network agent reaches the IT agent through the
    # AgentCore API (agent.py negotiate_with_it), so this image needs boto3.
    # Same version the operators pin.
    #
    # And ADOT, so the agent's spans reach CloudWatch's generative AI
    # observability pages (AgentCore developer guide, observability-configure
    # .html: aws-opentelemetry-distro >= 0.18.0, run under
    # opentelemetry-instrument). agent.py builds its own spans on the run's
    # traceparent; ADOT's urllib and botocore instrumentations are switched off
    # because each would inject a second traceparent into calls agent.py
    # already carries one on (tools/test-agent-otel.py). The names are the
    # distro's entry-point names, not package names: the SQS one is "boto3".
    SDK_PIP="strands-agents[openai]==1.57.2 bedrock-agentcore==1.24.0 mcp==1.30.0 boto3==1.43.103 aws-opentelemetry-distro==0.21.0"
    SDK_ENV='ENV OTEL_PYTHON_DISABLED_INSTRUMENTATIONS=urllib,urllib3,botocore,boto3\n'
    ENTRY='["opentelemetry-instrument", "python3", "/app/agent.py"]'
    ;;
  *)
    echo "TARGET must be 'pod' or 'agentcore' (got '$TARGET')" >&2
    exit 2
    ;;
esac

# Your own agent (Module 8). IMAGE_TAG: the tag to push under. It is required
# when AGENT_SRC is not the reference agent.py, and may not be a reference
# tag: the reference runtimes can point at that tag, and an image pushed over
# it would replace theirs on their next restart. EXTRA_PIP: pip requirements
# your agent imports (e.g. the Strands SDK), installed with the image's own
# pins; each must be a plain requirement, name[extras]==version style.
REFERENCE_TAGS="reference-agent-v5 reference-agent-v5-agentcore"
if [ -n "${IMAGE_TAG:-}" ] || [ "$(basename "$AGENT_SRC")" != "agent.py" ]; then
  if [ -z "${IMAGE_TAG:-}" ]; then
    echo "IMAGE_TAG is required for your own agent ($AGENT_SRC is not the reference agent.py);" \
         "choose a tag of your own, e.g. IMAGE_TAG=my-agent-${TARGET}" >&2
    exit 2
  fi
  if ! printf '%s' "$IMAGE_TAG" | grep -Eq '^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$'; then
    echo "IMAGE_TAG '$IMAGE_TAG' is not a valid image tag (letters, digits, _ . -; at most 128)" >&2
    exit 2
  fi
  if [ "$(basename "$AGENT_SRC")" != "agent.py" ]; then
    for ref in $REFERENCE_TAGS; do
      if [ "$IMAGE_TAG" = "$ref" ]; then
        echo "IMAGE_TAG '$IMAGE_TAG' is a reference agent tag; pushing your agent under it" \
             "would replace the reference agents' image. Choose another tag." >&2
        exit 2
      fi
    done
  fi
  TAG="$IMAGE_TAG"
fi
PIP_WORDS="$SDK_PIP"
if [ -n "${EXTRA_PIP:-}" ]; then
  case "$EXTRA_PIP" in *$'\n'*|*$'\t'*|*$'\r'*)
    echo "EXTRA_PIP must be space-separated requirements on one line" >&2; exit 2 ;;
  esac
  for req in $EXTRA_PIP; do
    if ! printf '%s' "$req" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9,._-]+\])?((==|>=|<=|~=|!=|<|>)[A-Za-z0-9.*+!_-]+(,(==|>=|<=|~=|!=|<|>)[A-Za-z0-9.*+!_-]+)*)?$'; then
      echo "EXTRA_PIP: '$req' is not a plain pip requirement (name, [extras], version)" >&2
      exit 2
    fi
    PIP_WORDS="${PIP_WORDS:+$PIP_WORDS }'$req'"
  done
fi
SDK_LAYER=""
[ -n "$PIP_WORDS" ] && SDK_LAYER="RUN pip install --no-cache-dir ${PIP_WORDS}\n"
SDK_LAYER="${SDK_LAYER}${SDK_ENV}"

if [ "$DRY_RUN" = "1" ]; then
  # Placeholders, never real values: this path must not call AWS and must not
  # put a 12-digit account id into any output a reviewer might paste.
  STACK="${STACK:-eks-cluster}"
  ACCT="${ACCT:-DRYRUN-ACCOUNT}"
else
  CLUSTER=$(aws eks list-clusters --region "$REGION" --query 'clusters[0]' --output text)
  STACK="${STACK:-$(aws eks describe-cluster --name "$CLUSTER" --region "$REGION" \
    --query 'cluster.tags."aws:cloudformation:stack-name"' --output text)}"
  ACCT="${ACCT:-$(aws sts get-caller-identity --query Account --output text)}"
fi

[ -f "$AGENT_SRC" ] || { echo "agent source not found at $AGENT_SRC (set AGENT_SRC=)" >&2; exit 2; }

ECR_HOST="${ACCT}.dkr.ecr.${REGION}.amazonaws.com"
REPO="${STACK}-aws-agent-operator"
# gzip before base64: CodeBuild caps buildspecOverride at 25600 characters and
# agent.py alone is ~24.6 KB (base64 ~32.8 K). Plain base64 made every StartBuild
# fail with "Max buildspec length is 25600" (event b0525231, 2026-09-28).
AB64=$(gzip -9nc < "$AGENT_SRC" | base64 | tr -d '\n')
DB64=$(printf "FROM public.ecr.aws/docker/library/python:3.12-slim\nWORKDIR /app\n${SDK_LAYER}COPY agent.py /app/agent.py\nEXPOSE 8080\nENTRYPOINT ${ENTRY}\n" | base64 | tr -d '\n')
SPEC=$(python3 - "$AB64" "$DB64" "$ECR_HOST" "$REPO" "$TAG" "$WANT_ARCH" <<'PY'
import json, sys
a, d, h, r, t, arch = sys.argv[1:7]
img = f"{h}/{r}:{t}"
# Not an f-string: the Go template braces in --format would be eaten by one.
assert_arch = (
    'ARCH=$(docker image inspect ' + img + ' --format "{{.Architecture}}")'
    ' && echo "built architecture: $ARCH (want ' + arch + ')"'
    ' && [ "$ARCH" = "' + arch + '" ]'
    ' || { echo "FATAL: built $ARCH, this target requires ' + arch + '"; exit 1; }'
)
print(json.dumps({"version": "0.2", "phases": {
 "pre_build": {"commands": [
   "uname -m",
   f"aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin {h}"]},
 "build": {"commands": [
   "mkdir -p /tmp/ra && cd /tmp/ra",
   f"echo {a} | base64 -d | gunzip > agent.py",
   f"echo {d} | base64 -d > Dockerfile",
   f"docker build -t {img} .",
   assert_arch,
   f"docker push {img}"]}}}, separators=(",", ":")))
PY
)
if [ "${#SPEC}" -gt 25600 ]; then
  echo "FATAL: the buildspec is ${#SPEC} characters; CodeBuild accepts at most 25600" \
       "(agent source $(wc -c < "$AGENT_SRC" | tr -d ' ') bytes)" >&2
  exit 2
fi

if [ "$DRY_RUN" = "1" ]; then
  echo "=== TARGET=$TARGET  want_arch=$WANT_ARCH  agent_src=$AGENT_SRC ==="
  echo "=== buildspec (pretty) ==="
  printf '%s' "$SPEC" | python3 -m json.tool
  echo "=== aws codebuild start-build argv ==="
  # ${arr[@]+...} not "${arr[@]}": an empty array under `set -u` is an unbound
  # variable on bash 3.2 (what macOS ships), and TARGET=pod has no overrides.
  printf '%s\n' aws codebuild start-build --project-name "${STACK}-modaas-image-build" \
    ${ENV_OVERRIDES[@]+"${ENV_OVERRIDES[@]}"} --buildspec-override '<the JSON above>'
  echo "=== would publish ==="
  if [ "$TARGET" = "agentcore" ]; then
    echo "${ECR_HOST}/${REPO}@<digest ECR reports for :${TAG}>  -> ${URI_FILE}"
  else
    echo "${ECR_HOST}/${REPO}:${TAG}  -> ${URI_FILE}"
  fi
  exit 0
fi

BID=$(aws codebuild start-build --project-name "${STACK}-modaas-image-build" \
  ${ENV_OVERRIDES[@]+"${ENV_OVERRIDES[@]}"} \
  --buildspec-override "$SPEC" --query 'build.id' --output text)
echo "build: $BID"
while :; do
  S=$(aws codebuild batch-get-builds --ids "$BID" --query 'builds[0].buildStatus' --output text)
  [ "$S" != "IN_PROGRESS" ] && break
  sleep 20
done
[ "$S" = "SUCCEEDED" ] || { echo "build $S — check /aws/codebuild/${STACK}-modaas-image-build logs"; exit 1; }

if [ "$TARGET" != "agentcore" ]; then
  echo "${ECR_HOST}/${REPO}:${TAG}" | tee "$URI_FILE"
  exit 0
fi

# AgentCore gets the digest reference, and the digest alone.
#
# Not the tag: the tag is reused by every rebuild, so the AgentConfig the
# generator writes from it is the same after a rebuild, its generation does not
# move, the operator never calls UpdateAgentRuntime, and the runtime keeps the
# old image (measured on event b0525231, 2026-09-28). A digest changes with
# every build, so a rebuilt agent reaches its runtime on the next apply.
#
# Not tag plus digest: AgentCore accepts repo:tag@sha256:..., reports the
# runtime READY, and then never starts the container; every invoke times out
# with no log line (same event, same day). The AgentConfig CRD refuses that
# form at admission.
DIGEST=$(aws ecr describe-images --region "$REGION" --repository-name "$REPO" \
  --image-ids imageTag="$TAG" --query 'imageDetails[0].imageDigest' --output text)
case "$DIGEST" in
  sha256:*) ;;
  *) echo "FATAL: ECR reported no digest for ${REPO}:${TAG} (got '${DIGEST}'); nothing published to ${URI_FILE}" >&2
     exit 1 ;;
esac
echo "${ECR_HOST}/${REPO}@${DIGEST}" | tee "$URI_FILE"
