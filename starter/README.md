<!-- Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. -->
<!-- SPDX-License-Identifier: MIT-0 -->
# Starter kit

Everything here reads the gateway host/key and the evidence ledger's address
from the cluster or the environment — nothing is hardcoded, no script
carries an account id, and every script refuses to run if the current
`kubectl` context is not this MoDaaS workshop cluster (it checks for the
`components`, `modaas-system` and `agentgateway-system` namespaces first).

Three paths, three commands each. Pick the one that matches what you're
building.

## Path 1 — an audit-trail utility (the challenge itself)

```bash
bash pull-evidence.sh <run-id>              # -> ~/evidence/*.json, the six standard surfaces
python3 answer.py <run-id>                  # the six auditor questions — fill in the stubs
python3 evaluate.py 16 <run-id>             # a control test with a verdict (control 16 is wired; see register.yaml)
```

Then, when you're ready to hand in:

```bash
bash submit.sh <your-team-name>             # zips evidence/ + register.yaml + gap-list.md + run-ids.txt, uploads, presigns
```

Copy `register.yaml` and `gap-list.md` into your working directory and fill
them in before running `submit.sh` — see the comments in each file.

## Path 2 — a new agent on AgentCore Runtime

```bash
bash new-agent.sh my-agent nemotron-nano-9b --skills fault-resolution --dry-run   # check it admits, no build
bash new-agent.sh my-agent nemotron-nano-9b --skills fault-resolution            # build + declare for real
kubectl annotate agentconfig my-agent -n components \
  modaas.tmforum.org/approver="$(whoami)@team" \
  modaas.tmforum.org/approval-attestation="Reviewed: governed gateway path only" --overwrite
```

`new-agent.sh` copies `agent-template/` to `~/agents/<name>/`, builds the
image through `static/reference-impl/build-agent-image.sh` (the same
CodeBuild path Module 9 uses — AgentCore Runtime accepts `linux/arm64`
images only, and only CodeBuild's role can push), generates the
AgentConfig with `static/reference-impl/make-agentcore-agents.py`, and
applies it. Pass `--tool <approved-toolconfig-alias>` to wire an MCP tool
client in automatically.

## Path 3 — a new governed MCP tool

```bash
bash new-tool.sh my-tool --description "What it does" --dry-run   # check it admits, deploys nothing
bash new-tool.sh my-tool --description "What it does"             # deploy + declare for real
kubectl annotate toolconfig my-tool -n components \
  modaas.tmforum.org/approver="$(whoami)@team" \
  modaas.tmforum.org/approval-attestation="Reviewed: read-only, internal classification" --overwrite
```

`new-tool.sh` scaffolds from `mcp-tool-template/`, deploys it to
`components` (ConfigMap + Deployment + Service, like `modaas-docs`), and
writes + applies the ToolConfig. Pass `--agentcore-gateway` to write the
`agentCoreGateway`-provider variant instead — that path needs a target ARN you
fill in yourself, so it is written to disk rather than applied automatically.

## Files

| File | What it is |
|---|---|
| `pull-evidence.sh` | Pulls the six standard surfaces the challenge brief names into `~/evidence/*.json` for one run id. |
| `answer.py` | Six stub functions, one per auditor question, reading `~/evidence`. Exits 1 while any are unimplemented. |
| `register.yaml` | Threshold document template — one entry per control (7, 9, 16). Copy it and fill in your own thresholds, dated before your assessed run. |
| `evaluate.py` | The control test tool: given a control id + run id, computes the measure from evidence, compares against `register.yaml`, returns PASS/BREACH with the call ids behind the number. |
| `gap-list.md` | Template for "what you could not close, and why" — scored on its own in the brief. |
| `submit.sh` | Packages your judgement-day artefacts, uploads to your team's evidence bucket, prints a short-lived presigned URL, keeps a local copy regardless. |
| `new-agent.sh` | Builds and declares a governed agent of your own on AgentCore Runtime. |
| `agent-template/` | The Strands/`BedrockAgentCoreApp` source `new-agent.sh` builds from. |
| `new-tool.sh` | Scaffolds, deploys and declares a governed MCP tool. |
| `mcp-tool-template/` | The MCP server + Kubernetes manifests + ToolConfig `new-tool.sh` renders. |
