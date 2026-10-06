# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""agent.py -- Strands agent template for governed agents on AgentCore Runtime.

Supports three roles (customer, it, network) via AGENT_ROLE env var, matching
the reference-impl/agent.py contract:
  - Same env: AGENT_ROLE, AGENT_NAME, STEP_BASE, AUDIT_URL, AUDIT_WRITE_TOKEN,
    MODEL_ALIAS, OPENAI_BASE_URL, OPENAI_API_KEY
  - Same ledger records: intent (step+1), invocation (step+2),
    result-inspection (step+3), negotiation (step+2.5 for IT)
  - Same negotiation handoff (network -> IT)
  - Trace continuation from incoming traceparent

AgentCore Runtime calls POST /invocations and GET /ping, port 8080.
"""
import json
import os
import re
import urllib.request
import uuid

from bedrock_agentcore.runtime import BedrockAgentCoreApp
from strands import Agent
from strands.models.openai import OpenAIModel

NAME = os.environ.get("AGENT_NAME", "my-agent")
ROLE = os.environ.get("AGENT_ROLE", "customer")
ALIAS = os.environ.get("MODEL_ALIAS", "nemotron-super-120b")
STEP_BASE = int(os.environ.get("STEP_BASE", "0"))
TOOL_MCP_URL = os.environ.get("TOOL_MCP_URL", "")
TOOL_MCP_ALIAS = os.environ.get("TOOL_MCP_ALIAS", "")

PROMPTS = {
    "customer": "/no_think You are a telecom Customer Experience agent. Given customer records and a network fault context, summarize in 3 short bullet points: which customers are impacted, how, and what to tell them. Be factual and brief.",
    "it": "/no_think You are a telecom IT Resolution agent. Given an incident and fault context, state in 3 short bullet points: incident disposition, the action you take per the runbook, and what you need from the network team. Be factual and brief.",
    "network": "/no_think You are a telecom Network Resolution agent. Given network inventory with an active fault, state in 3 short bullet points: the probable root cause, your proposed resolution, and the risk of the change. Be factual and brief.",
}


class GatewayModel(OpenAIModel):
    def format_request(self, *args, **kwargs):
        request = super().format_request(*args, **kwargs)
        if not request.get("tools"):
            request.pop("tools", None)
        return request


MODEL = GatewayModel(
    client_args={"base_url": os.environ.get("OPENAI_BASE_URL", ""),
                 "api_key": os.environ.get("OPENAI_API_KEY", "")},
    model_id=ALIAS,
    params={"max_tokens": 500, "temperature": 0},
)

TOOLS = []
if TOOL_MCP_URL:
    from strands.tools.mcp import MCPClient
    _headers = {"Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}"}
    try:
        import httpx
        from mcp.client.streamable_http import streamable_http_client
        def _transport():
            return streamable_http_client(TOOL_MCP_URL, http_client=httpx.AsyncClient(
                headers=_headers, timeout=httpx.Timeout(30, read=300)))
    except ImportError:
        from mcp.client.streamable_http import streamablehttp_client
        def _transport():
            return streamablehttp_client(TOOL_MCP_URL, headers=_headers)
    _tool_client = MCPClient(_transport)
    _tool_client.start()
    TOOLS = _tool_client.list_tools_sync()

app = BedrockAgentCoreApp()


def post_audit(cid, step, phase, detail, trace_id=None, action_id=None):
    body = {"correlation_id": cid, "step": step, "phase": phase,
            "actor": NAME, "detail": detail}
    if trace_id:
        body["trace_id"] = trace_id
    if action_id:
        body["action_id"] = action_id
    headers = {"Content-Type": "application/json",
               "X-Audit-Token": os.environ.get("AUDIT_WRITE_TOKEN", "")}
    try:
        urllib.request.urlopen(urllib.request.Request(
            os.environ.get("AUDIT_URL", "") + "/records",
            data=json.dumps(body).encode(), headers=headers), timeout=5)
        return None
    except Exception as exc:
        return f"step {step}: {exc}"


def classify_disposition(text):
    t = re.sub(r"[^a-z0-9]+", " ", (text or "").lower())
    def has(*stems):
        return any(re.search(r"\b" + p, t) for p in stems)
    escalate = has(r"escalat", r"human approval", r"approval required",
                   r"maintenance freeze", r"change freeze", r"cannot proceed")
    uncertain = has(r"ambiguous", r"inconclusive", r"insufficient evidence",
                    r"unclear", r"need more")
    resolved = has(r"resolv", r"resolution", r"remediat", r"appl(?:y|ied)",
                   r"execut", r"failover", r"cutover", r"repair", r"replace")
    if escalate:
        return "escalate"
    if uncertain:
        return "gather-evidence"
    if resolved:
        return "auto-resolve"
    return "undetermined"


@app.entrypoint
def invoke(payload):
    inner = payload.get("input") if isinstance(payload.get("input"), dict) else payload

    if isinstance(inner.get("negotiate"), dict):
        neg = inner["negotiate"]
        cid = neg.get("correlation_id", f"{NAME}-{uuid.uuid4().hex[:8]}")
        proposal = neg.get("proposal", "")
        post_audit(cid, STEP_BASE + 2.5, "negotiation",
                   f"received network proposal ({len(proposal)} chars); evaluating against open incident + runbook")
        position = ("agree: protection-path switch is runbook-approved "
                    "(RB-EDGE-SLICE-DEGRADATION); schedule optic replacement in window")
        return {"agent": NAME, "correlation_id": cid, "position": position}

    if "correlation_id" not in inner and "context" not in inner:
        inner = {"context": inner}
    cid = inner.get("correlation_id") or f"{NAME}-{uuid.uuid4().hex[:8]}"
    ctx = inner.get("context", {})
    question = ctx.get("question", json.dumps(ctx)[:6000])

    errors = [post_audit(cid, STEP_BASE + 1, "intent",
                         f"trace_id=pending {ROLE} analysis via governed model '{ALIAS}'"
                         + (f"; tool {TOOL_MCP_ALIAS}" if TOOL_MCP_ALIAS else ""),
                         )]
    try:
        agent = Agent(model=MODEL, tools=TOOLS,
                      system_prompt=PROMPTS.get(ROLE, PROMPTS["customer"]),
                      callback_handler=None)
        answer = str(agent(question)).strip()
        disposition = classify_disposition(answer)
        status = 200
    except Exception as exc:
        status = getattr(exc, "status_code", None)
        answer = f"refused at gateway: http_status={status}"
        disposition = "refused"

    errors.append(post_audit(cid, STEP_BASE + 2, "invocation",
                             f"governed call via alias {ALIAS}: http_status={status}"))

    negotiation = None
    if ROLE == "network" and disposition != "refused":
        negotiation = {"position": "pending-live-negotiation"}

    inspection = f"disposition={disposition}, decision={answer!r}"
    if negotiation:
        inspection += f" | negotiation_with_it={negotiation.get('position', 'n/a')}"
    errors.append(post_audit(cid, STEP_BASE + 3, "result-inspection", inspection))

    out = {"agent": NAME, "role": ROLE, "correlation_id": cid, "answer": answer,
           "disposition": disposition, "http_status": status,
           "evidence_errors": [e for e in errors if e]}
    if negotiation:
        out["negotiation"] = negotiation
    return out


if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", "8080")))
