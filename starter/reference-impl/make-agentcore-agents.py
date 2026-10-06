#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Write AgentConfigs for agents hosted on AgentCore Runtime, ready to apply.

Hosting an agent on AgentCore needs values from three places: the image you
built, your network (private subnets and the cluster security group), and the
evidence store (its VPC-internal address and write token). This script finds
them, writes the AgentConfig custom resources, and asks the API server to
validate them (a server-side dry run). You choose only a name, a model and
skills.

Usage
  python3 make-agentcore-agents.py
      the three reference agents (customer, IT, network), with the default model
  python3 make-agentcore-agents.py --name my-agent --model nemotron-super-120b \\
      --skills fault-resolution,rca [--role network]
      one agent of your own, built from the reference image unless --image is set

Options
  --model ALIAS   an Approved ModelConfig alias (default nemotron-super-120b)
  --image URI     container image (default: /tmp/agent-image-uri-agentcore,
                  written by build-agent-image.sh with TARGET=agentcore)
  --out FILE      where to write (default /tmp/agents-agentcore.generated.yaml)
  --region R      default $AWS_REGION, then $AWS_DEFAULT_REGION, then us-east-1
  --no-dry-run    skip the server-side validation

Before running: apply audit-store.yaml and audit-store-agentcore.yaml, and
approve the model. After: kubectl apply -f <out>, then approve each agent.
Re-run once it-resolution-agent is Approved so the network agent learns the IT
agent's runtime, then apply again.

Standard library only, so it runs anywhere python3, aws and kubectl do.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import json
import os
import re
import subprocess
import sys

NAMESPACE = "components"
DEFAULT_MODEL = "nemotron-super-120b"
DEFAULT_OUT = "/tmp/agents-agentcore.generated.yaml"
IMAGE_URI_FILE = "/tmp/agent-image-uri-agentcore"
ROLES = ("customer", "it", "network")

#: The workshop's helper agent: its own image, its own ModelConfig (a tighter
#: guardrail set and a smaller maxTokens than the reference model), and every
#: tool it is allowed to call. The agent derives each tool's perimeter URL from
#: the one the operator injects (AGENTCORE_GATEWAY_MCP_URL), so no URL is
#: written here.
HELPER_NAME = "hackathon-helper"
HELPER_MODEL = "nemotron-super-120b-helper"
HELPER_TOOLS = ("helper-docs", "aws-knowledge", "cluster-status", "cr-author", "evidence-lookup")
HELPER_IMAGE_URI_FILE = "/tmp/agent-image-uri-hackathon-helper"

#: name, role, STEP_BASE, description, skills, tool alias (same as agents.yaml).
REFERENCE = (
    ("customer-experience-agent", "customer", "0",
     "Surfaces customer impact of network faults; first domain of the TMF triad",
     ["fault-resolution", "customer-domain"], "customer-records"),
    ("it-resolution-agent", "it", "3",
     "Processes incidents, negotiates with network domain; second domain",
     ["fault-resolution", "it-domain"], "runbook-lookup"),
    ("network-resolution-agent", "network", "6",
     "Diagnoses faults, negotiates resolution with IT; third domain",
     ["fault-resolution", "network-domain"], "network-twin"),
)

# A Kubernetes name (DNS-1123 label) that also becomes a valid AgentCore
# runtime name once "-" turns into "_": must start with a letter; the operator
# keeps 40 characters of it.
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,38}[a-z0-9]$")


class InputError(ValueError):
    """Something the participant typed that would be refused later."""


class DiscoveryError(RuntimeError):
    """A value the script could not find, with what to do about it."""


# AgentCore Runtime places its network interfaces only in these Availability
# Zone IDs ("Supported Availability Zones", AgentCore developer guide, VPC
# page, read 2026-09-28). A subnet elsewhere fails the runtime at creation
# ("subnets are in unsupported availability zones"). IDs, not names: the
# name-to-ID mapping differs per account.
AGENTCORE_ZONES = {
    "us-east-1": {"use1-az1", "use1-az2", "use1-az4"},
    "us-east-2": {"use2-az1", "use2-az2", "use2-az3"},
    "us-west-1": {"usw1-az1", "usw1-az3"},
    "us-west-2": {"usw2-az1", "usw2-az2", "usw2-az3"},
}


def agentcore_subnets(pairs, region: str) -> list[str]:
    """The subnet ids, of (subnet id, AZ id) pairs, that AgentCore can use."""
    allowed = AGENTCORE_ZONES.get(region)
    if allowed is None:
        return [s for s, _ in pairs]
    keep = [s for s, az in pairs if az in allowed]
    if not keep:
        have = ", ".join(sorted({az for _, az in pairs}))
        raise DiscoveryError(
            f"none of the cluster's private subnets is in an Availability Zone AgentCore "
            f"supports in {region} (have {have}; supported {', '.join(sorted(allowed))})")
    return keep


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()
    except FileNotFoundError:
        raise DiscoveryError(f"{cmd[0]} is not installed or not on PATH")
    except subprocess.CalledProcessError as e:
        raise DiscoveryError(f"{' '.join(cmd[:4])} ... failed: {(e.stderr or e.stdout).strip()[:300]}")


class Discovery:
    """Reads the values from AWS and the cluster. Every method raises
    DiscoveryError with the fix, never a traceback."""

    def __init__(self, region: str | None = None):
        self._region = region or os.environ.get("AWS_REGION") or \
            os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
        self._cluster = None
        self._stack = None

    def region(self) -> str:
        return self._region

    def _aws(self, *args) -> str:
        return _run(["aws", *args, "--region", self._region, "--output", "text"])

    def cluster(self) -> str:
        if not self._cluster:
            name = self._aws("eks", "list-clusters", "--query", "clusters[0]")
            if not name or name == "None":
                raise DiscoveryError(f"no EKS cluster found in {self._region}; is --region right?")
            self._cluster = name
        return self._cluster

    def stack(self) -> str:
        if not self._stack:
            self._stack = self._aws("eks", "describe-cluster", "--name", self.cluster(), "--query",
                                    'cluster.tags."aws:cloudformation:stack-name"')
        return self._stack

    def subnets(self) -> list[str]:
        out = self._aws("cloudformation", "describe-stack-resources", "--stack-name", self.stack(),
                        "--query", "StackResources[?ResourceType=='AWS::EC2::Subnet' && "
                                   "starts_with(LogicalResourceId,'PrivateSubnet')].PhysicalResourceId")
        ids = out.split()
        if not ids:
            raise DiscoveryError(f"stack {self.stack()} has no PrivateSubnet* resources")
        zones = self._aws("ec2", "describe-subnets", "--subnet-ids", *ids,
                          "--query", "Subnets[].[SubnetId,AvailabilityZoneId]")
        pairs = [tuple(line.split()) for line in zones.splitlines() if line.strip()]
        return agentcore_subnets(pairs, self._region)

    def security_group(self) -> str:
        sg = self._aws("eks", "describe-cluster", "--name", self.cluster(), "--query",
                       "cluster.resourcesVpcConfig.clusterSecurityGroupId")
        if not sg.startswith("sg-"):
            raise DiscoveryError(f"cluster {self.cluster()} reported no security group")
        return sg

    def image(self, override: str | None = None) -> str:
        if override:
            return override
        try:
            with open(IMAGE_URI_FILE) as f:
                uri = f.read().strip()
        except OSError:
            uri = ""
        if not uri:
            raise DiscoveryError(
                f"no image: build it first (TARGET=agentcore bash build-agent-image.sh writes "
                f"{IMAGE_URI_FILE}) or pass --image")
        return uri

    def _kubectl(self, *args) -> str:
        return _run(["kubectl", "-n", NAMESPACE, *args])

    def audit_url(self) -> str:
        host = self._kubectl("get", "svc", "audit-store-agentcore", "-o",
                             "jsonpath={.status.loadBalancer.ingress[0].hostname}")
        if not host:
            raise DiscoveryError(
                "no address yet for Service audit-store-agentcore: apply audit-store-agentcore.yaml, "
                "wait one to three minutes, then re-run")
        return f"http://{host}:8080"

    def audit_token(self) -> str:
        raw = self._kubectl("get", "secret", "audit-write-token", "-o", "jsonpath={.data.token}")
        if not raw:
            raise DiscoveryError("Secret audit-write-token not found: apply the audit store first (Module 7)")
        return base64.b64decode(raw).decode()

    def it_runtime_arn(self) -> str | None:
        try:
            arn = self._kubectl("get", "agentconfig", "it-resolution-agent", "-o",
                                "jsonpath={.status.agentRuntimeArn}")
        except DiscoveryError:
            return None
        return arn or None

    def model_approved(self, alias: str) -> bool:
        try:
            phase = self._kubectl("get", "modelconfig", alias, "-o", "jsonpath={.status.phase}")
        except DiscoveryError:
            return False
        return phase == "Approved"


PLATFORM_APPROVAL = {
    # Platform-declared at install: approve in the same apply so the CR never
    # parks in Reviewing (annotating after apply races the creation reconcile).
    "modaas.tmforum.org/approver": "system-admin",
    "modaas.tmforum.org/approval-attestation": "Approved by the workshop platform at install",
}


def _agent_cr(d, *, name, role, step_base, description, skills, model, image,
              tool_alias=None, env_extra=None, approve=False) -> dict:
    env = {"AGENT_ROLE": role, "AGENT_NAME": name, "STEP_BASE": str(step_base),
           "AUDIT_URL": d.audit_url(), "AUDIT_WRITE_TOKEN": d.audit_token()}
    if tool_alias:
        env["TOOL_MCP_ALIAS"] = tool_alias
    env.update(env_extra or {})
    depends = {"models": [model]}
    if tool_alias:
        depends["tools"] = [tool_alias]
    return {
        "apiVersion": "oda.tmforum.org/v1beta1",
        "kind": "AgentConfig",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     **({"annotations": dict(PLATFORM_APPROVAL)} if approve else {})},
        "spec": {
            "agentName": name,
            "provider": "awsAgentCore",
            "networkMode": "VPC",
            "agentCard": {"description": description, "skills": list(skills),
                          "protocolBinding": "HTTP+JSON"},
            "awsAgentCore": {
                "containerUri": image,
                "region": d.region(),
                "protocolConfiguration": {"serverProtocol": "HTTP"},
                "lifecycleConfiguration": {"idleRuntimeSessionTimeout": 900, "maxLifetime": 3600},
                "networkModeConfig": {"subnets": d.subnets(), "securityGroups": [d.security_group()]},
                "environmentVariables": env,
            },
            "safety": {"enforces": True, "enforcerKind": "bedrockGuardrail"},
            "governance": {"approval": {"required": True, "requiredApprovals": 1}},
            "dependsOn": depends,
        },
    }


def _check_model(d, model):
    if not d.model_approved(model):
        raise InputError(f"ModelConfig {model!r} is not Approved in namespace {NAMESPACE}: apply and "
                         f"approve it first (kubectl -n {NAMESPACE} get modelconfig)")


def reference_agents(d, *, model=DEFAULT_MODEL, image=None) -> list[dict]:
    """The customer, IT and network reference agents."""
    img = d.image(image)
    it_arn = d.it_runtime_arn()
    docs = []
    for name, role, step, desc, skills, tool in REFERENCE:
        extra = {"IT_AGENT_RUNTIME_ARN": it_arn} if role == "network" and it_arn else None
        docs.append(_agent_cr(d, name=name, role=role, step_base=step, description=desc,
                              skills=skills, model=model, image=img,
                              tool_alias=tool, env_extra=extra))
    return docs


def own_agent(d, *, name, model, skills, role="customer", image=None, description=None) -> list[dict]:
    """One agent of the participant's own, from a name, a model and skills."""
    if not NAME_RE.match(name or ""):
        raise InputError(f"name {name!r}: use 2-40 lowercase letters, digits and '-', starting with a "
                         f"letter (it becomes the runtime name)")
    if role not in ROLES:
        raise InputError(f"role {role!r}: the reference image knows {', '.join(ROLES)}")
    skills = [s.strip() for s in (skills or []) if s.strip()]
    if not skills:
        raise InputError("give at least one skill (--skills a,b)")
    _check_model(d, model)
    return [_agent_cr(d, name=name, role=role, step_base="0",
                      description=description or f"{name}: {role}-role agent on AgentCore Runtime",
                      skills=skills, model=model, image=d.image(image))]


def helper_agent(d, *, image=None, team="") -> list[dict]:
    """The workshop's hackathon-helper, onboarded by bootstrap step 16."""
    _check_model(d, HELPER_MODEL)
    img = image or ""
    if not img:
        try:
            with open(HELPER_IMAGE_URI_FILE) as f:
                img = f.read().strip()
        except OSError:
            img = ""
        if not img:
            raise DiscoveryError(
                f"no helper image: build it first (TARGET=agentcore AGENT_SRC=.../hackathon-helper/agent.py "
                f"IMAGE_TAG=hackathon-helper URI_FILE={HELPER_IMAGE_URI_FILE} bash build-agent-image.sh) "
                f"or pass --image")
    # MODEL_ALIAS is reserved: the operator derives it from dependsOn.models
    # and rejects a declared one (DeclaredEnvInvalid, seen live 2026-10-03).
    env = {"AGENT_NAME": HELPER_NAME, "STEP_BASE": "0",
           "AUDIT_URL": d.audit_url(), "AUDIT_WRITE_TOKEN": d.audit_token()}
    if team:
        env["TEAM"] = team
    cr = _agent_cr(d, name=HELPER_NAME, role="customer", step_base="0",
                   description="Workshop assistant: explains MoDaaS architecture and the governed "
                               "path, diagnoses a team's own ModelConfig/ToolConfig/AgentConfig, "
                               "drafts CR edits; never builds the entry",
                   skills=["workshop-assistant", "documentation-search", "cr-authoring"],
                   model=HELPER_MODEL, image=img, env_extra=env, approve=True)
    cr["spec"]["dependsOn"]["tools"] = list(HELPER_TOOLS)
    cr["spec"]["awsAgentCore"]["environmentVariables"].pop("AGENT_ROLE", None)
    return [cr]


def _scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    return json.dumps(v)  # a double-quoted YAML scalar


def _emit(v, indent=0) -> list[str]:
    pad = "  " * indent
    lines = []
    for k, val in v.items():
        if isinstance(val, dict):
            lines.append(f"{pad}{k}:")
            lines += _emit(val, indent + 1)
        elif isinstance(val, list):
            lines.append(f"{pad}{k}: [{', '.join(_scalar(x) for x in val)}]")
        else:
            lines.append(f"{pad}{k}: {_scalar(val)}")
    return lines


def to_yaml(docs: list[dict]) -> str:
    return "\n".join("---\n" + "\n".join(_emit(d)) for d in docs) + "\n"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--name")
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--skills", default="")
    p.add_argument("--role", default="customer")
    p.add_argument("--image")
    p.add_argument("--out", default=DEFAULT_OUT)
    p.add_argument("--region")
    p.add_argument("--no-dry-run", action="store_true")
    p.add_argument("--helper", action="store_true",
                   help="write the hackathon-helper AgentConfig (bootstrap uses this)")
    p.add_argument("--team", default="", help="team slug for the helper's TEAM env var")
    a = p.parse_args(argv)
    d = Discovery(a.region)
    try:
        if a.helper:
            docs = helper_agent(d, image=a.image, team=a.team)
        elif a.name:
            docs = own_agent(d, name=a.name, model=a.model, skills=a.skills.split(","),
                             role=a.role, image=a.image)
        else:
            _check_model(d, a.model)
            docs = reference_agents(d, model=a.model, image=a.image)
    except (InputError, DiscoveryError) as e:
        print(f"make-agentcore-agents: {e}", file=sys.stderr)
        return 2
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    header = (f"# Generated by make-agentcore-agents.py at {stamp}.\n"
              "# Contains this event's audit write token in plain text: do not commit it.\n")
    with open(a.out, "w") as f:
        f.write(header + to_yaml(docs))
    print(f"wrote {len(docs)} AgentConfig(s) to {a.out}")
    net = [x for x in docs if x["spec"]["awsAgentCore"]["environmentVariables"].get("AGENT_ROLE") == "network"]
    if net and not any("IT_AGENT_RUNTIME_ARN" in x["spec"]["awsAgentCore"]["environmentVariables"] for x in net):
        print("note: it-resolution-agent has no runtime yet, so the network agent cannot negotiate with it. "
              "Re-run and re-apply once it-resolution-agent is Approved.")
    if not a.no_dry_run:
        try:
            print(_run(["kubectl", "apply", "--dry-run=server", "-f", a.out]))
        except DiscoveryError as e:
            print(f"make-agentcore-agents: the API server refused the file: {e}", file=sys.stderr)
            return 1
    print(f"next: kubectl apply -f {a.out}   then approve each agent (Module 7)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
