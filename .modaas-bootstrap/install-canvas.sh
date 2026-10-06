#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# install-canvas.sh — install TM Forum ODA Canvas (chart canvas-oda 1.2.5) on
# the EKS cluster this workshop's CFT provisioned, with every EKS-specific
# defect from docs/contributions/2026-08-09-oda-canvas-eks-deployment-fixes.md
# (the source repo, modaas-aigateway) applied inline.
#
# Order matters — this script encodes D3/D5/D6's ordering requirements
# directly, not just their existence:
#   1. Storage prerequisite (D5) — MUST exist before Canvas's postgres/mongo
#      PVCs are created, or they hang Pending and Keycloak never starts.
#      The aws-ebs-csi-driver addon is already installed by the CFT
#      (static/cfn/01-eks-cluster.yaml); this script only applies the
#      default gp3 StorageClass K8s object (CFN has no native
#      Kubernetes-object resource type).
#   2. istio-ingress (D6) — installed via Helm with the EXACT
#      name/namespace/type Canvas's prehook checks for. istioctl produces a
#      differently-named Service and Canvas's install fails at the prehook.
#   3. cert-manager ownership (D3) — Canvas installs its OWN cert-manager
#      via a subchart. Do NOT install cert-manager separately first, or the
#      annotation-ownership conflict in the doc's D3 section occurs. This
#      script does not touch cert-manager at all; Canvas's chart owns it.
#   4. Nested Helm dependencies (D2) — canvas-vault's own Chart.yaml
#      dependency on the HashiCorp vault chart is a file:// reference,
#      which `helm dependency build` does NOT recurse into. Build nested
#      deps before the umbrella chart, in every subchart directory.
#   5. Apply the D1 one-line patch to canvas-vault's post-install hook
#      BEFORE building charts, so the patched file is what gets packaged.
set -euo pipefail

CANVAS_TAG="canvas-oda-1.2.5"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "==> D10 fix (reported 2026-09-21): confirm kubectl can reach the cluster BEFORE"
echo "    doing five minutes of cluster-independent work"
# Everything from here to the D5 StorageClass step is local: a git clone, helm
# repo adds, dependency builds. None of it touches the cluster. So an unset
# kubeconfig used to surface ~5 minutes in, at the gp3 step, as:
#
#   The connection to the server localhost:8080 was refused
#
# which names a port nobody configured and reads like a broken script rather
# than a missing prerequisite. Reported from a live CloudShell run.
#
# The underlying reason it happens at all: the installer runs in Module 2 while
# `aws eks update-kubeconfig` lived in Module 4, two modules later. A participant
# following the workshop in order had no kubeconfig yet. The IDE hid this because
# its image preconfigures kubectl -- which is exactly why maintainer runs never
# hit it and a CloudShell user hit it immediately. Module 2 now sets it too; this
# block makes the script independent of which path the participant took.
if ! kubectl get nodes >/dev/null 2>&1; then
  echo "    kubectl cannot reach a cluster; configuring kubeconfig"
  REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"

  # The CFT names the cluster "${AWS::StackName}-modaas", so prefer that suffix.
  # `clusters[0]` is NOT safe here: an account with more than one cluster would
  # silently install Canvas into the wrong one, which is far worse than stopping.
  ALL=$(aws eks list-clusters --region "$REGION" --query 'clusters[]' --output text 2>/dev/null || true)
  MATCHED=$(printf '%s\n' $ALL | grep -- '-modaas$' || true)
  COUNT=$(printf '%s\n' $MATCHED | grep -c . || true)

  if [ "$COUNT" -ne 1 ]; then
    # fall back to a single unambiguous cluster of any name
    MATCHED="$ALL"
    COUNT=$(printf '%s\n' $MATCHED | grep -c . || true)
  fi

  if [ "$COUNT" -ne 1 ]; then
    echo "FAIL: cannot pick a cluster unambiguously in region $REGION." >&2
    echo "  Found: ${ALL:-<none>}" >&2
    echo "  Set the region and name explicitly, then re-run this script:" >&2
    echo "    export REGION=<your-region>" >&2
    echo "    aws eks update-kubeconfig --name <cluster> --region \"\$REGION\"" >&2
    echo "    kubectl get nodes" >&2
    exit 1
  fi

  CLUSTER=$(printf '%s\n' $MATCHED | grep . | head -1)
  aws eks update-kubeconfig --name "$CLUSTER" --region "$REGION" >/dev/null 2>&1 || true

  if ! kubectl get nodes >/dev/null 2>&1; then
    echo "FAIL: still cannot reach cluster $CLUSTER in $REGION after update-kubeconfig." >&2
    echo "  Run these and read the error they print:" >&2
    echo "    aws sts get-caller-identity" >&2
    echo "    aws eks update-kubeconfig --name $CLUSTER --region $REGION" >&2
    echo "    kubectl get nodes" >&2
    exit 1
  fi
  echo "    kubeconfig set for $CLUSTER in $REGION"
else
  echo "    kubectl already reaches a cluster: $(kubectl config current-context 2>/dev/null)"
fi

echo "==> Cloning canvas-oda at ${CANVAS_TAG}"
git clone --quiet --depth 1 --branch "$CANVAS_TAG" \
  https://github.com/tmforum-oda/oda-canvas.git "$WORKDIR/oda-canvas"
cd "$WORKDIR/oda-canvas/charts"

echo "==> D1 fix: canvas-vault post-install hook reads .aud instead of .iss"
# The projected ServiceAccount token's audience (aud) is read as if it were
# the issuer (iss). Silent on kind/minikube (both are
# https://kubernetes.default.svc there); on EKS the real issuer is
# https://oidc.eks.<region>.amazonaws.com/id/<hash>, so Vault's OIDC config
# write fails with "error checking oidc discovery URL". Fix is
# backward-compatible: .iss // .aud[0].
HOOK_FILE="canvas-vault/templates/post-install-hook.yaml"
if grep -q "jq -r '.aud\[0\]'" "$HOOK_FILE"; then
  sed "s/jq -r '.aud\[0\]'/jq -r '.iss \/\/ .aud[0]'/" "$HOOK_FILE" > "$HOOK_FILE.tmp" && mv "$HOOK_FILE.tmp" "$HOOK_FILE"
  echo "    patched: ${HOOK_FILE}"
else
  # A patch that does not apply must STOP the install, not warn and continue.
  # Continuing ships an unpatched Canvas: on EKS the projected token's audience
  # is read as if it were the issuer, Vault's OIDC config write fails with
  # "error checking oidc discovery URL", and the participant gets post-install-hook
  # pods in Error with canvas-smanop in CreateContainerConfigError. Warning-and-
  # proceeding is how that reaches a cluster looking like a successful install.
  echo "" >&2
  echo "FATAL: the canvas-vault's post-install hook patch did not apply." >&2
  echo "       Expected pattern not found in ${HOOK_FILE}." >&2
  echo "       Upstream chart version ${CANVAS_TAG} has probably changed the file." >&2
  echo "" >&2
  echo "       Installing unpatched would bring Canvas up with a broken Vault" >&2
  echo "       OIDC config on EKS. Inspect the file, port the .iss // .aud[0]" >&2
  echo "       change by hand, and update this script." >&2
  exit 1
fi

echo "==> D1b fix (live-discovered 2026-08-28): a SECOND, separate audience-detection"
echo "    job ships in secretsmanagement-operator's own preinst hook — the D1 fix"
echo "    above only patches canvas-vault's copy. Same root cause (.aud[0] read as"
echo "    if it were .iss), different subchart, so it needs its own patch or the"
echo "    canvas-smanop pod never gets the vault secret it depends on and Helm's"
echo "    --wait times out on canvas-smanop/compcrdwebhook/canvas-pdb-management-operator."
# NOTE: neither sed call in this file uses "sed -i" in any form (not
# "-i.bak", not bare "-i"). Two real, live-discovered bugs, both fixed
# 2026-08-28:
#   1. "sed -i.bak" leaves a second file inside templates/, and Helm
#      renders EVERY file under templates/ as a candidate template —
#      producing two colliding Job resources at render time. Confirmed via
#      `helm template` showing both preinst-autodetect-audience-job.yaml
#      AND its .bak sibling rendered as separate manifests.
#   2. Bare "sed -i 'script' file" (no suffix argument) is GNU-only syntax.
#      BSD/macOS sed parses the very next argument after -i as the backup
#      suffix, so "sed -i 's/a/b/' file" silently treats 's/a/b/' as the
#      suffix and then has no actual edit script — this script's earlier
#      "fix" for bug #1 broke silently on macOS for exactly this reason,
#      confirmed via `sed --version` reporting BSD sed on this machine.
# The portable fix used below (sed to stdout, redirect to a temp file
# outside the pattern space, then mv over the original) works identically
# on GNU and BSD sed and never leaves any extra file in templates/.
HOOK_FILE_2="secretsmanagement-operator/templates/preinst-autodetect-audience-job.yaml"
if grep -q "jq -r '.aud\[0\]'" "$HOOK_FILE_2"; then
  sed "s/jq -r '.aud\[0\]'/jq -r '.iss \/\/ .aud[0]'/" "$HOOK_FILE_2" > "$HOOK_FILE_2.tmp" && mv "$HOOK_FILE_2.tmp" "$HOOK_FILE_2"
  echo "    patched: ${HOOK_FILE_2}"
else
  # A patch that does not apply must STOP the install, not warn and continue.
  # Continuing ships an unpatched Canvas: on EKS the projected token's audience
  # is read as if it were the issuer, Vault's OIDC config write fails with
  # "error checking oidc discovery URL", and the participant gets post-install-hook
  # pods in Error with canvas-smanop in CreateContainerConfigError. Warning-and-
  # proceeding is how that reaches a cluster looking like a successful install.
  echo "" >&2
  echo "FATAL: the secretsmanagement-operator's preinst audience job patch did not apply." >&2
  echo "       Expected pattern not found in ${HOOK_FILE_2}." >&2
  echo "       Upstream chart version ${CANVAS_TAG} has probably changed the file." >&2
  echo "" >&2
  echo "       Installing unpatched would bring Canvas up with a broken Vault" >&2
  echo "       OIDC config on EKS. Inspect the file, port the .iss // .aud[0]" >&2
  echo "       change by hand, and update this script." >&2
  exit 1
fi

echo "==> D8 fix (reported 2026-09-21): add every Helm repo BEFORE resolving dependencies"
# `helm dependency build` is CACHE-ONLY. It never adds or refreshes a repo, so on
# a fresh CloudShell -- where the cache is empty -- resolution fails per subchart
# while the umbrella still prints "Saving 16 charts" and exits 0. The run looks
# partly successful and the install dies much later somewhere unrelated.
#
# The damaging one is `hashicorp`: canvas-vault depends on HashiCorp's vault
# chart, so without that repo the Vault engine is never vendored while
# canvas-vault's own wrapper templates (post-install hook, cronjobs, certificate)
# still deploy. The participant then sees no canvas-vault-hc-0, post-install-hook
# pods in Error, and canvas-smanop in CreateContainerConfigError complaining that
# secret "canvas-vault-hc-secrets" does not exist -- a deceptive partial install
# whose cause is four steps upstream. Reported from a live reproduce on
# a-01-eks-cluster-modaas after four hand-fixes.
#
# istio was already added below, AFTER the dependency build that needs it.
# Ordering was the whole bug.
#
# kong and apisix are deliberately NOT here. A live run added them by hand and an
# earlier version of this script copied that, on the reasoning that a participant
# cannot tell a harmless "no repository definition" error from the hashicorp one
# that silently breaks Vault. That reasoning was already obsolete: hashicorp is
# added above, and the canvas-vault artifact assertion below hard-fails loudly if
# its chart is ever missing. Adding the repos only vendored ~290K of Kong and
# APISIX charts for gateways that cannot render. The dependency-build loop skips
# those two subcharts instead, which removes the confusing errors without the
# pointless fetch.
for _repo in \
    "hashicorp|https://helm.releases.hashicorp.com" \
    "jetstack|https://charts.jetstack.io" \
    "bitnami|https://charts.bitnami.com/bitnami" \
    "istio|https://istio-release.storage.googleapis.com/charts" \
    "oda-canvas|https://tmforum-oda.github.io/oda-canvas" \
    "prometheus-community|https://prometheus-community.github.io/helm-charts" \
    "open-telemetry|https://open-telemetry.github.io/opentelemetry-helm-charts" \
    "jaegertracing|https://jaegertracing.github.io/helm-charts" ; do
  _name="${_repo%%|*}"; _url="${_repo##*|}"
  helm repo add "$_name" "$_url" --force-update >/dev/null 2>&1 \
    && echo "    repo: $_name" \
    || echo "    WARN: could not add repo $_name ($_url)"
done
helm repo update >/dev/null 2>&1 || true
unset _repo _name _url

# The umbrella has NESTED dependencies and stock `helm dependency build` resolves
# only the first level. The ODA Canvas install README recommends this plugin for
# exactly that. Absence is not fatal here because the loop below walks every
# subchart directory by hand, so this is best-effort.
if ! helm plugin list 2>/dev/null | grep -q resolve-deps; then
  helm plugin install --version main https://github.com/Noksa/helm-resolve-deps.git \
    >/dev/null 2>&1 && echo "    plugin: helm-resolve-deps" \
    || echo "    note: helm-resolve-deps unavailable; per-subchart loop below covers it"
fi

echo "==> D2 fix: build nested Helm dependencies before the umbrella chart"
# helm dependency build on canvas-oda packages canvas-vault's file://
# dependency AS-IS without recursing into it — canvas-vault's own
# dependency on the HashiCorp vault chart is silently dropped, and
# canvas-vault-hc's StatefulSet is never rendered.
for chart_dir in */; do
  if [ -f "${chart_dir}Chart.yaml" ]; then
    # Skip the two gateway subcharts the workshop never enables. Canvas ships
    # three interchangeable API-gateway operators for TMF ExposedAPI and only one
    # can be active: values.yaml has api-operator-istio enabled=true with
    # kong-gateway-install and apisix-gateway-install both enabled=false, and
    # kong's own subchart ships DisableIstioLB.yaml -- it REPLACES Istio rather
    # than complementing it. (None of this touches agentgateway, which is the
    # MoDaaS LLM/MCP dataplane on a different layer entirely; Canvas has no
    # concept of it.)
    #
    # Attempting them is pure waste in both directions. Without their repos,
    # helm emits two "no repository definition" error blocks that nothing in the
    # content explains, so participants reasonably ask whether the install broke.
    # With their repos added, it instead downloads and vendors kong-2.34.0.tgz
    # (199K) and apisix-2.7.0.tgz (91K) for code paths that cannot render.
    # Skipping gives a clean log AND no pointless fetch, with no extra external
    # repo on the critical path. Proven safe: the original live reproduce reached
    # all 18 pods Running with both of these unvendored.
    case "$chart_dir" in
      kong-gateway/|apisix-gateway/)
        echo "    skipped: ${chart_dir} (gateway disabled; Istio is the API operator)"
        continue ;;
    esac
    echo "    helm dependency build: ${chart_dir}"
    # `|| true` stays: a chart with no dependencies at all exits non-zero here,
    # and that is not a failure. The exit code cannot distinguish "nothing to
    # build" from "the build broke", so it is not the thing to check.
    (cd "$chart_dir" && helm dependency build --skip-refresh 2>&1 | sed 's/^/      /') || true
  fi
done
echo "    helm dependency build: canvas-oda (umbrella)"
helm dependency build --skip-refresh canvas-oda 2>&1 | sed 's/^/      /'

# ASSERT THE OUTCOME, NOT THE EXIT CODE (2026-09-21).
#
# The loop above swallowed every failure, and the one that matters is invisible
# without this check: if canvas-vault's nested HashiCorp vault dependency is not
# materialised, the whole install still "succeeds" and Canvas comes up WITHOUT a
# Vault server. What a participant then sees is canvas-vault-hc-cronjob and
# canvas-smanop stuck in CreateContainerConfigError and post-install-hook pods in
# Error, with no canvas-vault-hc-0 anywhere -- because the cronjob and hook render
# from canvas-vault's own templates while the server comes from the dropped
# subchart. Reported from a live install on 2026-09-21.
#
# The fix is to check that the artifact EXISTS rather than that a command
# returned zero, which is the same lesson as every other sensor corrected this
# week: an exit code reports whether something ran, not whether it worked.
if [ -d canvas-vault ]; then
  if ! ls canvas-vault/charts/vault-*.tgz >/dev/null 2>&1 \
     && [ ! -d canvas-vault/charts/vault ]; then
    echo "" >&2
    echo "FATAL: canvas-vault has no materialised 'vault' dependency after" >&2
    echo "       helm dependency build. Installing now would bring Canvas up" >&2
    echo "       with no Vault server: no canvas-vault-hc-0, post-install-hook" >&2
    echo "       pods in Error, and canvas-vault-hc-cronjob plus canvas-smanop" >&2
    echo "       in CreateContainerConfigError." >&2
    echo "" >&2
    echo "       Contents of canvas-vault/charts/:" >&2
    ls -la canvas-vault/charts/ 2>&1 | sed 's/^/         /' >&2
    echo "" >&2
    echo "       Usually a network or Helm-cache problem. Retry:" >&2
    echo "         cd $(pwd)/canvas-vault && helm dependency build" >&2
    echo "       then re-run this script." >&2
    exit 1
  fi
  echo "    verified: canvas-vault's nested vault dependency is present"
fi

echo "==> D5 fix: default gp3 StorageClass (aws-ebs-csi-driver addon already installed by the CFT)"
kubectl apply -f - <<'EOF'
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: gp3
  annotations:
    storageclass.kubernetes.io/is-default-class: "true"
provisioner: ebs.csi.aws.com
volumeBindingMode: WaitForFirstConsumer
parameters:
  type: gp3
  encrypted: "true"
EOF
# Un-default the legacy in-tree gp2 SC, if present, so Canvas's PVCs bind to
# gp3 and not to the decoy legacy provisioner (a present-but-non-provisioning
# default StorageClass passes naive "does a default SC exist" checks while
# never actually binding).
kubectl patch storageclass gp2 -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"false"}}}' 2>/dev/null || true

# ASSERT THE PROVISIONER EXISTS, NOT JUST THE StorageClass (2026-09-21).
#
# The comment above already names this failure class for gp2 -- "a
# present-but-non-provisioning default StorageClass passes naive checks while
# never actually binding" -- and then the gp3 apply above fell into the same
# trap one level up. `kubectl apply` on a StorageClass always succeeds; it is a
# declaration, not a capability. Nothing here checked that the provisioner the
# class names is actually present.
#
# Found on a live event: the cluster CFT stack hit a TRANSIENT
# AsgInstanceLaunchFailures on its NodeGroup and CloudFormation aborted the
# stack -- after creating vpc-cni and kube-proxy but BEFORE creating the
# aws-ebs-csi-driver addon. The ASG then recovered on its own and all three
# nodes joined Ready, so the cluster looked healthy and this script's header
# assumption ("aws-ebs-csi-driver addon already installed by the CFT") was
# quietly false. What followed, entirely from this one gap:
#
#   PVC data-canvas-postgresql-0   Pending -- "Waiting for a volume to be
#                                   created ... by the external provisioner
#                                   'ebs.csi.aws.com'"
#   canvas-postgresql-0            Pending
#   canvas-keycloak-0              CrashLoopBackOff -- cannot reach postgres
#   keycloak-config-cli hook       BackoffLimitExceeded after its fixed 120s wait
#   helm upgrade --install         failed
#
# The participant's error message was about Keycloak, four layers from the
# cause. Failing here instead costs seconds and names the real problem.
CSI_RUNNING=$(kubectl get pods -n kube-system -l app=ebs-csi-controller \
                --no-headers 2>/dev/null | grep -c Running || true)
if [ "${CSI_RUNNING:-0}" -lt 1 ]; then
  echo "" >&2
  echo "FATAL: StorageClass gp3 names provisioner ebs.csi.aws.com, but no" >&2
  echo "       ebs-csi-controller pod is Running in kube-system. Every PVC" >&2
  echo "       Canvas creates (postgresql, mongodb) will hang Pending, and the" >&2
  echo "       install will fail later inside Keycloak with a message about" >&2
  echo "       postgres that does not mention storage at all." >&2
  echo "" >&2
  echo "       Almost always means the cluster CFT stack did not finish: check" >&2
  echo "       whether the aws-ebs-csi-driver addon exists at all." >&2
  echo "" >&2
  echo "       Diagnose:" >&2
  echo "         aws eks list-addons --cluster-name <cluster>" >&2
  echo "         aws cloudformation describe-stacks --query \\" >&2
  echo "           \"Stacks[].[StackName,StackStatus]\" --output text" >&2
  echo "       Expect 5 addons; vpc-cni + kube-proxy alone means the stack" >&2
  echo "       aborted partway. A CREATE_FAILED cluster stack can still leave" >&2
  echo "       nodes Ready, so 'kubectl get nodes' is NOT evidence the" >&2
  echo "       environment is complete." >&2
  echo "" >&2
  echo "       Remedy: re-provision the event (Workshop Studio -> Teams ->" >&2
  echo "       Actions -> Revalidate deployment), or install the addon:" >&2
  echo "         aws eks create-addon --cluster-name <cluster> \\" >&2
  echo "           --addon-name aws-ebs-csi-driver" >&2
  exit 1
fi
echo "    verified: ebs-csi-controller is Running (gp3 can actually provision)"

echo "==> D6 fix: istio + istio-ingress via Helm with the exact name Canvas's prehook requires"
helm repo add istio https://istio-release.storage.googleapis.com/charts --force-update >/dev/null
helm repo update istio >/dev/null
helm upgrade --install istio-base istio/base -n istio-system --create-namespace --wait >/dev/null
helm upgrade --install istiod istio/istiod -n istio-system --wait >/dev/null
# MUST be named exactly "istio-ingress" in namespace "istio-ingress", type
# LoadBalancer, per charts/canvas-oda/templates/prehook.yaml:26-42. istioctl's
# default profile produces "istio-ingressgateway" in "istio-system" instead —
# Canvas's prehook check fails against that shape.
helm upgrade --install istio-ingress istio/gateway -n istio-ingress --create-namespace --wait >/dev/null
echo "    waiting for istio-ingress LoadBalancer to get an external address..."
for i in $(seq 1 60); do
  EXTERNAL_IP=$(kubectl get svc istio-ingress -n istio-ingress -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || true)
  [ -n "$EXTERNAL_IP" ] && break
  sleep 5
done
[ -n "${EXTERNAL_IP:-}" ] || { echo "FAIL: istio-ingress never got an external address after 5 minutes"; exit 1; }
echo "    istio-ingress external address: ${EXTERNAL_IP}"

echo "==> D3 note: Canvas owns cert-manager via its own subchart — NOT installed separately by this script"
echo "==> D4 note (was a FALSE claim until 2026-09-21): the cert-manager bootstrap"
echo "    race is NOT self-healing; it is repaired after the install, in D9 below"
# WHAT THIS NOTE USED TO SAY, and why it was wrong:
#
#   "a first-install cert-manager webhook CA-injection race is idempotent on
#    retry ... re-run helm upgrade --install, the retry succeeds"
#
# It is not idempotent. cert-manager-init ships its self-signed Issuers and its
# Certificates as hooks annotated `helm.sh/hook: post-install` -- post-install
# ONLY, with no post-upgrade. On a cold cluster the first one races
# cert-manager's own webhook CA injection and fails with
# "x509: certificate signed by unknown authority". cert-manager-init's
# values.yaml documents that exact error in a comment, so the chart authors know
# it happens. The resources are then never created -- and because every subsequent
# run of this script is a `helm upgrade`, post-install hooks are SKIPPED, so
# they are never recreated either. A retry does not heal it.
#
# What a participant actually sees downstream, all from this one cause:
#   canvas-vault-hc-0    ContainerCreating -- secret "canvasvault-tls" not found
#   certificate canvasvault-tls  Ready=False -- ClusterIssuer not found
#   vault post-install hook      Error / BackoffLimitExceeded
#   canvas-smanop                CreateContainerConfigError
#   compcrdwebhook               ContainerCreating -- secret "compcrdwebhook-secret" not found
#
# Reported 2026-09-21 from a live reproduce that needed four hand-fixes.
#
# WHY THE FIX IS AFTER THE INSTALL AND NOT BEFORE IT.
# Pre-creating these objects looks like the obvious move and is wrong. Helm's
# default hook deletion policy is `before-hook-creation`, so a pre-created
# object is deleted and recreated by the hook anyway -- buying nothing. And
# these five hooks carry `helm.sh/resource-policy: keep` with NO explicit
# delete policy, so if that keep suppresses the pre-delete, Helm's hook Create
# hits AlreadyExists and fails the whole install. Pre-creation is therefore
# either a no-op or a hard regression, depending on a Helm semantic this script
# should not have to bet on. Reconciling AFTER the install depends on no such
# semantic: it creates only what is genuinely absent, and it repairs a cluster
# that is ALREADY broken from an earlier run, which pre-creation cannot do.
#
# Narrow the race first, since a hook that succeeds needs no repair. This wait
# is best-effort by design -- D9 is the actual guarantee, so a timeout here is
# not a failure and must not exit.
kubectl wait --for=condition=Available --timeout=180s \
  deployment/canvas-cert-manager-webhook -n cert-manager >/dev/null 2>&1 \
  && echo "    cert-manager webhook Available before install (race narrowed)" \
  || echo "    note: cert-manager webhook not up yet; D9 below repairs whatever the hooks strand"

echo "==> D7 note (live-discovered 2026-08-28): three deployments"
echo "    (compcrdwebhook, canvas-pdb-management-operator, canvas-smanop) depend"
echo "    on Certificate/ClusterIssuer resources that are THEMSELVES"
echo "    post-install,post-upgrade hooks (pdb-management-operator/templates/"
echo "    certificate.yaml; canvas-vault's Certificate is applied inside its own"
echo "    post-install-hook.yaml Job). This is a genuine chart-design conflict"
echo "    with 'helm upgrade --install --wait': the wait blocks on these"
echo "    Deployments reaching Ready during the MAIN install phase, but the"
echo "    hooks that create their certs/secrets only run AFTER Helm judges the"
echo "    main phase complete — so --wait can never succeed for these three,"
echo "    regardless of retries or cert-manager CRD timing (both ruled out by"
echo "    direct live investigation before landing on this fix)."
echo ""
echo "==> Installing canvas-oda (without --wait; hook-dependent pods are polled below)"
helm upgrade --install canvas ./canvas-oda -n canvas --create-namespace --timeout 15m
INSTALL_EXIT=$?
if [ "$INSTALL_EXIT" -ne 0 ]; then
  echo "FAIL: helm upgrade --install returned $INSTALL_EXIT"
  exit "$INSTALL_EXIT"
fi

echo ""
echo "==> D9 fix (reported 2026-09-21): reconcile the cert-manager-init hooks that"
echo "    a cold-cluster CA race strands permanently (see the D4 note above)"
# Five cert-manager-init objects ship as `helm.sh/hook: post-install` with no
# post-upgrade: ClusterIssuer canvas-cert-manager-init-selfsigned-cluster,
# Issuer canvas/canvas-cert-manager-init-selfsigned, Issuer
# istio-ingress/istio-ingress-issuer, Certificate canvas/compcrdwebhook, and
# Certificate istio-ingress/istio-ingress-cert. If the first install's hook
# phase lost the race with cert-manager's webhook, none of them exist and no
# later run recreates them.
#
# The manifests are read back from the release itself rather than hardcoded
# here, so this tracks whatever chart version the participant actually resolved
# instead of drifting away from it. Only genuinely-absent objects are applied,
# which is why this is safe to run on every invocation.
HOOKS_FILE=$(mktemp)
if ! helm get hooks canvas -n canvas >"$HOOKS_FILE" 2>/dev/null; then
  echo "FAIL: helm get hooks canvas -n canvas failed; cannot reconcile cert-manager-init"
  rm -f "$HOOKS_FILE"
  exit 1
fi

RECONCILED=0
rm -rf /tmp/cmi-hooks /tmp/cmi-hooks.d.txt   # stale extracts from an earlier chart version
# Helpers exist because `nsarg="-n $ns"; kubectl get $nsarg` is NOT safe here: the
# reconcile loop below reads pipe-delimited records with IFS='|', and that IFS
# governs the word splitting of an unquoted expansion in the loop body too. The
# two-word string collapses into the single argument " canvas" (leading space),
# and kubectl rejects it with "namespace from the provided object does not match".
# Caught by server-dry-running all five real manifests: 4 of 5 failed this way,
# which would have converted an intermittent race into a deterministic install
# failure. Passing --namespace=VALUE as one token removes the splitting entirely.
_cmi_exists() { # kind ns name
  if [ -n "$2" ]; then kubectl get "$1" "$3" --namespace="$2" >/dev/null 2>&1
  else kubectl get "$1" "$3" >/dev/null 2>&1; fi
}
_cmi_apply() { # ns path
  if [ -n "$1" ]; then kubectl apply --namespace="$1" -f "$2"
  else kubectl apply -f "$2"; fi
}

python3 - "$HOOKS_FILE" <<'PYEOF' >/tmp/cmi-hooks.d.txt
import re, sys, os
docs = open(sys.argv[1]).read().split('\n---\n')
os.makedirs('/tmp/cmi-hooks', exist_ok=True)
n = 0
for d in docs:
    if 'charts/cert-manager-init/templates/' not in d:
        continue
    m = re.search(r'^kind:\s*(Certificate|Issuer|ClusterIssuer)\s*$', d, re.M)
    if not m:
        continue
    kind = m.group(1)
    name = re.search(r'^  name:\s*(\S+)\s*$', d, re.M)
    ns = re.search(r'^  namespace:\s*(\S+)\s*$', d, re.M)
    if not name:
        continue
    n += 1
    path = '/tmp/cmi-hooks/%02d.yaml' % n
    open(path, 'w').write(d.strip() + '\n')
    print('%s|%s|%s|%s' % (kind, name.group(1), ns.group(1) if ns else '', path))
PYEOF

if [ ! -s /tmp/cmi-hooks.d.txt ]; then
  echo "FAIL: found no cert-manager-init Certificate/Issuer hooks in the release manifests."
  echo "  The chart layout changed. Re-derive this block against:"
  echo "    helm get hooks canvas -n canvas | grep -n 'cert-manager-init/templates'"
  rm -f "$HOOKS_FILE"
  exit 1
fi

while IFS='|' read -r _kind _name _ns _path; do
  [ -n "$_kind" ] || continue
  if [ -n "$_ns" ]; then _label="$_ns/$_name"; else _label="$_name"; fi
  if _cmi_exists "$_kind" "$_ns" "$_name"; then
    echo "    present: $_kind $_label"
  else
    echo "    MISSING (hook was stranded): $_kind $_label -- applying"
    if _cmi_apply "$_ns" "$_path" >/dev/null 2>&1; then
      RECONCILED=$((RECONCILED + 1))
      echo "      applied: $_kind $_label"
    else
      echo "FAIL: could not apply $_kind $_label from the release's own hook manifest."
      echo "  Reproduce: kubectl apply --namespace=$_ns -f $_path"
      _cmi_apply "$_ns" "$_path" 2>&1 | sed 's/^/    /'
      rm -f "$HOOKS_FILE"
      exit 1
    fi
  fi
done < /tmp/cmi-hooks.d.txt
rm -f "$HOOKS_FILE"
echo "    reconciled $RECONCILED stranded object(s)"

# ASSERT THE OUTCOME, NOT THE EXIT CODE.
#
# Every kubectl apply above can succeed while the thing participants need --
# a usable TLS secret -- never materialises, because issuing is cert-manager's
# asynchronous job and an Issuer can exist in a NotReady state indefinitely.
# So gate on the SECRET, which is what compcrdwebhook actually mounts. Without
# this, the pod-readiness loop below reports the same failure 10 minutes later
# with no indication that certificate issuance is the cause.
echo "    waiting up to 3 minutes for cert-manager to issue compcrdwebhook-secret"
for i in $(seq 1 36); do
  if kubectl get secret compcrdwebhook-secret -n canvas >/dev/null 2>&1; then
    echo "    compcrdwebhook-secret present after $((i * 5))s"
    break
  fi
  sleep 5
done
if ! kubectl get secret compcrdwebhook-secret -n canvas >/dev/null 2>&1; then
  echo "FAIL: compcrdwebhook-secret still absent in namespace canvas after 3 minutes."
  echo "  The Issuer/Certificate exist but cert-manager has not issued. Inspect:"
  echo "    kubectl describe certificate compcrdwebhook -n canvas"
  echo "    kubectl get issuer,clusterissuer -A"
  echo "    kubectl logs -n cert-manager deploy/canvas-cert-manager --tail=50"
  kubectl describe certificate compcrdwebhook -n canvas 2>&1 | tail -20 | sed 's/^/    /'
  exit 1
fi

echo ""
echo "==> Waiting up to 10 minutes for ALL canvas pods to reach Ready"
echo "    (this covers the hook-dependent pods --wait could never satisfy above)"
for i in $(seq 1 60); do
  NOT_READY=$(kubectl get pods -n canvas --no-headers 2>/dev/null | awk '$3!="Completed" {split($2,a,"/"); if (a[1]!=a[2]) print $1}')
  if [ -z "$NOT_READY" ]; then
    echo "    all pods Ready."
    break
  fi
  echo "    ($i/60) still waiting on: $(echo "$NOT_READY" | tr '\n' ' ')"
  sleep 10
done
if [ -n "${NOT_READY:-}" ]; then
  echo "FAIL: pods still not Ready after 10 minutes: $NOT_READY"
  echo "  Check: kubectl describe pod <name> -n canvas"
  exit 1
fi

echo "==> Canvas install complete. Verify with: kubectl get pods -n canvas"
