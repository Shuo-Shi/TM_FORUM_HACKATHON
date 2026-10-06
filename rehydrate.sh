#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# rehydrate.sh — restore every workshop shell variable after a CloudShell reset.
#
# WHY THIS EXISTS
#
# The whole workshop runs in AWS CloudShell, and a CloudShell session resets on
# idle. $HOME survives (so ~/bin/kubectl is still there) but the SHELL does not:
# every exported variable is gone, and PATH no longer includes ~/bin. The labs
# reference $REGION 26 times and $STACK_NAME 19 times across separate pages, so
# a participant who reconnects mid-workshop is running commands with empty
# variables.
#
# That fails in the worst possible way — quietly. An empty $REGION falls back to
# CloudShell's default rather than erroring. An empty $ECR_HOST yields an image
# ref like "/my-repo@sha256:..." that fails at pull time, pages away from the
# cause. Reported by a participant on 2026-09-21 who was re-pasting a hand-rolled
# version of this block after every reconnect.
#
# Everything below is DERIVED from the cluster and its CloudFormation stack, so
# there is nothing to remember and nothing to keep in sync by hand.
#
# USAGE — source it, do not execute it. Exports do not survive a subshell:
#   source ./rehydrate.sh
#
# Safe to run repeatedly. Read-only against AWS.

# Not set -e: this is sourced, and a non-zero exit would kill the caller's shell.

_rh_warn() { printf '  ! %s\n' "$*" >&2; }

# A missing --query result comes back as the four-character string "None", not
# empty. Assigning that is worse than assigning nothing: "--stack-name None"
# reaches the API and fails with a confusing error, so normalise it away.
_rh_val() { case "$1" in None|null|"") printf '' ;; *) printf '%s' "$1" ;; esac; }

# ── Region ────────────────────────────────────────────────────────────────
# CloudShell sets AWS_REGION itself; honour it, then fall back to the workshop's
# only deployable Region. Three names are exported because the content uses all
# three and some tools read only one of them.
export REGION="$(_rh_val "${AWS_REGION:-${AWS_DEFAULT_REGION:-}}")"
[ -z "$REGION" ] && REGION="us-east-1"
export REGION
export AWS_REGION="$REGION"
export AWS_DEFAULT_REGION="$REGION"

# ── PATH ──────────────────────────────────────────────────────────────────
# ~/bin persists across a reset; PATH does not. Re-add it, and only once.
case ":$PATH:" in
  *":$HOME/bin:"*) : ;;
  *) export PATH="$HOME/bin:$PATH" ;;
esac
command -v kubectl >/dev/null 2>&1 || _rh_warn \
  "kubectl not on PATH — re-run the install step in Module 4 section 0"

# ── Identity ──────────────────────────────────────────────────────────────
export ACCOUNT_ID="$(_rh_val "$(aws sts get-caller-identity \
  --query Account --output text 2>/dev/null)")"
if [ -z "$ACCOUNT_ID" ]; then
  _rh_warn "cannot reach STS — are you in CloudShell with credentials loaded?"
  return 1 2>/dev/null || exit 1
fi

# ── Cluster ───────────────────────────────────────────────────────────────
# Count first. The original one-liner took clusters[0], which silently picks one
# of several — fine in a vended account with exactly one cluster, wrong and
# invisible anywhere else.
_rh_clusters="$(aws eks list-clusters --region "$REGION" \
  --query 'clusters' --output text 2>/dev/null)"
_rh_count="$(printf '%s\n' "$_rh_clusters" | wc -w | tr -d ' ')"
if [ "$_rh_count" = "0" ]; then
  _rh_warn "no EKS cluster in $REGION — has the stack finished provisioning?"
  return 1 2>/dev/null || exit 1
fi
if [ "$_rh_count" != "1" ]; then
  _rh_warn "$_rh_count clusters in $REGION ($_rh_clusters) — using the first;"
  _rh_warn "set CLUSTER yourself if that is the wrong one"
fi
export CLUSTER="$(printf '%s\n' "$_rh_clusters" | awk '{print $1}')"

export STACK_NAME="$(_rh_val "$(aws eks describe-cluster --name "$CLUSTER" \
  --region "$REGION" \
  --query 'cluster.tags."aws:cloudformation:stack-name"' --output text 2>/dev/null)")"
if [ -z "$STACK_NAME" ]; then
  _rh_warn "cluster $CLUSTER carries no aws:cloudformation:stack-name tag —"
  _rh_warn "was it created outside the workshop CFT? Set STACK_NAME by hand."
fi

# ── Stack outputs and parameters ──────────────────────────────────────────
_rh_out() {
  _rh_val "$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" \
    --output text 2>/dev/null)"
}
if [ -n "$STACK_NAME" ]; then
  export CLUSTER_NAME="$(_rh_out ClusterName)"
  export NODE_ROLE_ARN="$(_rh_out NodeRoleArn)"
  export MODAAS_SHA="$(_rh_val "$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" --region "$REGION" \
    --query "Stacks[0].Parameters[?ParameterKey=='ModaasSourceVersion'].ParameterValue" \
    --output text 2>/dev/null)")"
fi
export ECR_HOST="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

# PDP_DIGEST only exists once CodeBuild has pushed the image. Before that, its
# absence is expected and not an error — so it is looked up quietly and reported
# as pending rather than printing an AWS CLI failure at people.
if [ -n "$MODAAS_SHA" ]; then
  export PDP_DIGEST="$(_rh_val "$(aws ecr describe-images \
    --repository-name "${STACK_NAME}-pdp" --region "$REGION" \
    --image-ids imageTag="$MODAAS_SHA" \
    --query 'imageDetails[0].imageDigest' --output text 2>/dev/null)")"
fi

# ── Kubeconfig ────────────────────────────────────────────────────────────
aws eks update-kubeconfig --name "$CLUSTER" --region "$REGION" >/dev/null 2>&1 \
  || _rh_warn "update-kubeconfig failed — check the cluster's aws-auth mapping"

# ── Report ────────────────────────────────────────────────────────────────
printf '\nRehydrated:\n'
printf '  REGION        %s\n' "$REGION"
printf '  ACCOUNT_ID    %s\n' "$ACCOUNT_ID"
printf '  CLUSTER       %s\n' "$CLUSTER"
printf '  STACK_NAME    %s\n' "${STACK_NAME:-<unset>}"
printf '  CLUSTER_NAME  %s\n' "${CLUSTER_NAME:-<unset>}"
printf '  NODE_ROLE_ARN %s\n' "${NODE_ROLE_ARN:-<unset>}"
printf '  ECR_HOST      %s\n' "$ECR_HOST"
printf '  MODAAS_SHA    %s\n' "${MODAAS_SHA:-<unset>}"
printf '  PDP_DIGEST    %s\n' "${PDP_DIGEST:-<pending — CodeBuild has not pushed it yet>}"
printf '\n'
kubectl get nodes 2>/dev/null || _rh_warn "kubectl cannot reach the cluster yet"

unset _rh_clusters _rh_count
