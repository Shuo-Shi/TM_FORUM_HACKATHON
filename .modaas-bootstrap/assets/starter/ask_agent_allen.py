#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Invoke an agent on AgentCore Runtime by its AgentConfig name.

Resolves region and runtime ARN from the AgentConfig's status, mints a
correlation id unless one is given, sends W3C traceparent + baggage so the
call joins the caller's trace, and prints structured output the shell
wrapper (ask-agent.sh) can eval.

Exit 0 on a governed refusal (the platform decided; the caller reads
disposition=refused). Non-zero on transport or permission failures.
"""
import argparse
import json
import os
import subprocess
import sys
import time
import textwrap
import uuid


def resolve_agent(name, namespace="components"):
    """Return (arn, region) from the AgentConfig's status."""
    try:
        raw = subprocess.check_output(
            ["kubectl", "get", "agentconfig", name, "-n", namespace,
             "-o", "jsonpath={.status.agentRuntimeArn}"],
            stderr=subprocess.PIPE, text=True).strip()
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"ERROR: cannot read AgentConfig {name}: {exc}", file=sys.stderr)
        sys.exit(2)
    if not raw:
        print(f"ERROR: AgentConfig {name} has no runtime ARN yet "
              "(status.agentRuntimeArn is empty). Is it Approved?", file=sys.stderr)
        sys.exit(2)
    parts = raw.split(":")
    region = parts[3] if len(parts) > 3 else os.environ.get("AWS_REGION", "us-east-1")
    return raw, region


def mint_cid(agent_name):
    return f"{agent_name}-{int(time.time())}-{uuid.uuid4().hex[:6]}"


def invoke(arn, region, payload_dict, cid, traceparent=None):
    """Call InvokeAgentRuntime. Returns (output_dict, exit_code)."""
    session_id = f"{cid}-{uuid.uuid4().hex}"[:256]
    payload_json = json.dumps(payload_dict)

    cmd = [
        "aws", "bedrock-agentcore", "invoke-agent-runtime",
        "--region", region,
        "--agent-runtime-arn", arn,
        "--runtime-session-id", session_id,
        "--content-type", "application/json",
        "--accept", "application/json",
        # AWS CLI v2 reads blob parameters as base64 unless told otherwise;
        # without this flag every call failed with 'Invalid base64' (event
        # 486b9241, 2026-10-03) and no module had ever run the command live.
        "--cli-binary-format", "raw-in-base64-out",
        "--payload", payload_json,
        "--cli-read-timeout", "180",
    ]
    if traceparent:
        cmd += ["--trace-parent", traceparent]
    cmd += ["--baggage", f"modaas-correlation-id={cid}"]

    outfile = f"/tmp/ask-agent-{cid}.json"
    cmd.append(outfile)

    try:
        subprocess.check_output(cmd, stderr=subprocess.PIPE, text=True)
    except subprocess.CalledProcessError as exc:
        stderr_text = (exc.stderr or "").strip()[:300]
        if "AccessDenied" in stderr_text:
            return {"error": stderr_text, "hint": "Your role may not call bedrock-agentcore:InvokeAgentRuntime."}, 3
        return {"error": stderr_text}, 1

    try:
        with open(outfile) as f:
            doc = json.load(f)
    except Exception as exc:
        return {"error": f"could not read response: {exc}"}, 1
    finally:
        try:
            os.remove(outfile)
        except OSError:
            pass

    output = doc.get("output", doc) if isinstance(doc, dict) else doc
    return output, 0


def main():
    parser = argparse.ArgumentParser(description="Invoke a governed agent on AgentCore Runtime")
    parser.add_argument("agent", help="AgentConfig name in namespace components")
    parser.add_argument("question", help="The question or context to send")
    parser.add_argument("--cid", default=None, help="Correlation id (minted if omitted)")
    parser.add_argument("--traceparent", default=None, help="W3C traceparent to continue")
    parser.add_argument("--namespace", default="components")
    args = parser.parse_args()

    arn, region = resolve_agent(args.agent, args.namespace)
    cid = args.cid or mint_cid(args.agent)

    traceparent = args.traceparent
    if not traceparent:
        trace_id = uuid.uuid4().hex
        parent_id = uuid.uuid4().hex[:16]
        traceparent = f"00-{trace_id}-{parent_id}-01"

    # payload = {"correlation_id": cid, "context": {"question": args.question}}
    payload = {
        "correlation_id": cid,
        "traceparent": traceparent,
        "context": {"question": args.question},
    }
    print(f"export CID={cid}")

    result, rc = invoke(arn, region, payload, cid, traceparent)

    if isinstance(result, dict):
        agent_name = result.get("agent", args.agent)
        disposition = result.get("disposition", "unknown")
        answer = result.get("answer", result.get("analysis", ""))
        error = result.get("error", "")

        # Human-readable transcript: the answer is the thing the participant
        # came for, so print it as a block, in full, with its own newlines
        # preserved -- not truncated onto one key/value line (E7 walk
        # 2026-10-04: "human friendly cli helper agent response output was
        # not taken care of"). Machine-readable fields stay at the bottom.
        label = "refused" if disposition == "refused" else "answer"
        width = 72
        print()
        print(f"{agent_name}  ·  {label}")
        print("-" * width)
        body = answer or error or "(no answer returned)"
        for para in str(body).replace("\r\n", "\n").split("\n"):
            print(textwrap.fill(para, width=width) if para.strip() and not para.startswith((" ", "\t")) else para)
        print("-" * width)
        if error and answer:
            print(f"error:          {error}")
        print(f"disposition:    {disposition}")
        print(f"correlation_id: {cid}")
        print(f"next:           score-run.py {cid}   # evidence for this run")

        if disposition == "refused":
            sys.exit(0)
    else:
        print(f"output: {result}")
        print(f"correlation_id: {cid}")

    sys.exit(rc)


if __name__ == "__main__":
    main()
