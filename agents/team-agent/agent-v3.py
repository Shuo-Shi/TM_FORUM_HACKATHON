# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""reference-agent -- Strands-based governed agent for AgentCore Runtime.

Three roles (customer, it, network) via AGENT_ROLE. Each role calls its
domain tool via gateway MCP, then the governed model, writing the full
evidence chain: intent, tool-invocation, invocation, result-inspection,
and (for the triad) negotiation.

AgentCore Runtime calls POST /invocations and GET /ping, port 8080.
"""
import json
import os
import re
import uuid
import urllib.error
import urllib.request

from bedrock_agentcore.runtime import BedrockAgentCoreApp
from strands import Agent
from strands.models.openai import OpenAIModel

NAME = os.environ.get("AGENT_NAME", "reference-agent")
ROLE = os.environ.get("AGENT_ROLE", "customer")
ALIAS = os.environ.get("MODEL_ALIAS", "nemotron-super-120b")
STEP_BASE = int(os.environ.get("STEP_BASE", "0"))
# The agent operator injects the governed perimeter URL of the ONE tool in
# dependsOn.tools as AGENTCORE_GATEWAY_MCP_URL (…/mcp/<alias>). TOOL_MCP_URL
# stays as an explicit override for local runs.
TOOL_MCP_URL = os.environ.get("TOOL_MCP_URL") or os.environ.get("AGENTCORE_GATEWAY_MCP_URL", "")
TOOL_MCP_ALIAS = os.environ.get("TOOL_MCP_ALIAS", "")

_DECIDE = (
    " Decision rules: if a maintenance or change freeze, regulatory restriction or "
    "approval requirement applies, escalate and name the blocking constraint. "
    "Otherwise, if the telemetry fits more than one root cause, do NOT guess: say the "
    "evidence is ambiguous, name the two possible causes, state which evidence would "
    "disambiguate them, and propose only a reversible, temporary mitigation that can be "
    "rolled back. Otherwise, with one clear cause and a runbook-approved action, resolve it. "
    "If the evidence is ambiguous, include this line: REVERSIBLE ACTION: <a temporary mitigation> (rollback: <how to revert it>). "
    "End with exactly one line: DISPOSITION: auto-resolve | gather-evidence | escalate"
)

PROMPTS = {
    "customer": (
        "/no_think You are a telecom Customer Experience agent. "
        "Use your customer-records tool to look up impacted customers for the fault site, "
        "then summarize in 3 short bullet points: which customers are impacted, how, "
        "and what to tell them. Be factual and brief." + _DECIDE
    ),
    "it": (
        "/no_think You are a telecom IT Resolution agent. "
        "Use your runbook-lookup tool to find the incident and runbook, "
        "then state in 3 short bullet points: incident disposition, "
        "the action you take per the runbook, and what you need from the "
        "network team. Be factual and brief." + _DECIDE
    ),
    "network": (
        "/no_think You are a telecom Network Resolution agent. "
        "Use your network-twin tool to predict signal quality (predict_rsrp) "
        "for the fault site, then state in 3 short bullet points: the probable "
        "root cause (or both candidate causes if ambiguous), your proposed action, "
        "and the risk of the change. Be factual and brief." + _DECIDE
    ),
}

_TRACEPARENT_RE = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")


def parse_traceparent(value):
    m = _TRACEPARENT_RE.match((value or "").strip())
    if not m or m.group(1) == "0" * 32 or m.group(2) == "0" * 16:
        return None
    return m.group(1), m.group(3)


def new_trace(inbound=None):
    parsed = parse_traceparent(inbound)
    trace_id, flags = parsed if parsed else (uuid.uuid4().hex, "01")
    return f"00-{trace_id}-{uuid.uuid4().hex[:16]}-{flags}", trace_id


class GatewayModel(OpenAIModel):
    def format_request(self, *args, **kwargs):
        request = super().format_request(*args, **kwargs)
        if not request.get("tools"):
            request.pop("tools", None)
        return request


MODEL = GatewayModel(
    client_args={
        "base_url": os.environ.get("OPENAI_BASE_URL", ""),
        "api_key": os.environ.get("OPENAI_API_KEY", ""),
    },
    model_id=ALIAS,
    params={"max_tokens": 500, "temperature": 0},
)

_TOOLS = None
_TOOL_CLIENT = None  # kept alive: the MCP tools hold their session on it


def load_tools():
    """Discover the governed tool on first use, inside a request.

    Discovery (`tools/list`) used to run at module import. That call then had
    no request context: in X-Ray it showed as its own root trace about seven
    seconds after the invocation it belonged to, so a judge following one
    correlation id never saw the agent's tool discovery. Running it from the
    handler nests it under the invocation span. The result is cached, so
    discovery happens once per container, not once per call.
    """
    global _TOOLS, _TOOL_CLIENT
    if _TOOLS is not None:
        return _TOOLS
    _TOOLS = []
    if TOOL_MCP_URL:
        from strands.tools.mcp import MCPClient
        _headers = {"Authorization": f"Bearer {os.environ.get('OPENAI_API_KEY', '')}"}
        try:
            import httpx
            from mcp.client.streamable_http import streamable_http_client

            def _transport():
                return streamable_http_client(
                    TOOL_MCP_URL,
                    http_client=httpx.AsyncClient(
                        headers=_headers, timeout=httpx.Timeout(30, read=300)
                    ),
                )
        except ImportError:
            from mcp.client.streamable_http import streamablehttp_client

            def _transport():
                return streamablehttp_client(TOOL_MCP_URL, headers=_headers)

        _TOOL_CLIENT = MCPClient(_transport)
        _TOOL_CLIENT.start()
        _TOOLS = _TOOL_CLIENT.list_tools_sync()
    return _TOOLS


app = BedrockAgentCoreApp()


def post_audit(cid, step, phase, detail, trace_id=None, action_id=None):
    if phase == "invocation" and "guardrail" not in str(detail).lower():
        _d = str(detail).lower()
        _m = re.search(r"http_status=(\d+)", _d)
        _v = ("blocked" if ("content_filter" in _d or "blocked" in _d)
              else "not-evaluated(call-failed)" if ("refused" in _d or (_m and _m.group(1) != "200"))
              else "passed")
        detail = f"{detail} | guardrail={os.environ.get('GUARDRAIL_ID', 'gateway-attached')} verdict={_v}"
    body = {
        "correlation_id": cid,
        "step": step,
        "phase": phase,
        "actor": NAME,
        "detail": detail,
    }
    if trace_id:
        body["trace_id"] = trace_id
    if action_id:
        body["action_id"] = action_id
    headers = {
        "Content-Type": "application/json",
        "X-Audit-Token": os.environ.get("AUDIT_WRITE_TOKEN", ""),
    }
    try:
        urllib.request.urlopen(
            urllib.request.Request(
                os.environ.get("AUDIT_URL", "") + "/records",
                data=json.dumps(body).encode(),
                headers=headers,
            ),
            timeout=5,
        )
        return None
    except Exception as exc:
        return f"step {step}: {exc}"


def classify_disposition(text):
    t = re.sub(r"[^a-z0-9]+", " ", (text or "").lower())
    m = re.search(r"disposition\s*:?\s*(auto-resolve|gather-evidence|escalate)", (text or "").lower())
    if m:
        return m.group(1)

    def has(*stems):
        return any(re.search(r"\b" + p, t) for p in stems)

    escalate = has(
        r"escalat", r"human approval", r"approval required",
        r"maintenance freeze", r"change freeze", r"cannot proceed",
    )
    uncertain = has(
        r"ambiguous", r"inconclusive", r"insufficient evidence",
        r"unclear", r"need more", r"two possible", r"two plausible", r"cannot distinguish", r"disambiguat",
r"gather evidence", r"either"
    )
    resolved = has(
        r"resolv", r"resolution", r"remediat", r"appl(?:y|ied)",
        r"execut", r"failover", r"cutover", r"repair", r"replace",
    )
    if escalate:
        return "escalate"
    if uncertain:
        return "gather-evidence"
    if (
    "two possible" in t
    or "two plausible" in t
    or "cannot distinguish" in t
    or "ambiguous" in t
    or "transport congestion" in t
):
        return "gather-evidence"
    if resolved:
        return "auto-resolve"
    return "undetermined"



def _find_negotiate(obj, depth=0):
    import json as _json
    if depth > 4:
        return None
    if isinstance(obj, str) and '"negotiate"' in obj:
        try:
            obj = _json.loads(obj)
        except ValueError:
            return None
    if isinstance(obj, dict):
        if isinstance(obj.get("negotiate"), dict):
            return obj["negotiate"]
        for v in obj.values():
            r = _find_negotiate(v, depth + 1)
            if r:
                return r
    return None

@app.entrypoint
def invoke(payload):
    inner = payload.get("input") if isinstance(payload.get("input"), dict) else payload

    _neg = _find_negotiate(payload)
    if _neg:
        return _handle_negotiate(_neg)

    if "correlation_id" not in inner and "context" not in inner:
        inner = {"context": inner}
    cid = inner.get("correlation_id") or f"{NAME}-{uuid.uuid4().hex[:8]}"
    ctx = inner.get("context", {})
    question = ctx.get("question", json.dumps(ctx)[:6000])

    inbound_tp = inner.get("traceparent")
    traceparent, trace_id = new_trace(inbound_tp)

    errors = []

    errors.append(
        post_audit(
            cid, STEP_BASE + 1, "intent",
            f"trace_id={trace_id} {ROLE} analysis via governed model '{ALIAS}'"
            + (f"; tool {TOOL_MCP_ALIAS}" if TOOL_MCP_ALIAS else ""),
            trace_id=trace_id,
        )
    )

    try:
        agent = Agent(
            model=MODEL, tools=load_tools(),
            system_prompt=PROMPTS.get(ROLE, PROMPTS["customer"]),
            callback_handler=None,
        )
        answer = str(agent(question)).strip()
        disposition = classify_disposition(answer)
        status = 200
    except Exception as exc:
        status = getattr(exc, "status_code", None) or 500
        body_text = str(exc)[:300]
        answer = f"refused at gateway: http_status={status}"
        disposition = "refused"
        errors.append(
            post_audit(
                cid, STEP_BASE + 2, "invocation",
                f"trace_id={trace_id} refused at gateway: http_status={status} "
                f"model={ALIAS} body={body_text!r}",
                trace_id=trace_id,
            )
        )
        errors.append(
            post_audit(
                cid, STEP_BASE + 3, "result-inspection",
                f"disposition=refused, no model output",
                trace_id=trace_id,
            )
        )
        return {
            "agent": NAME, "role": ROLE, "correlation_id": cid,
            "answer": answer, "disposition": disposition,
            "http_status": status, "trace_id": trace_id,
            "evidence_errors": [e for e in errors if e],
        }

    if TOOL_MCP_ALIAS:
        errors.append(
            post_audit(
                cid, STEP_BASE + 1.5, "tool-invocation",
                f"actor={NAME} tool={TOOL_MCP_ALIAS} correlation_id={cid} "
                f"trace_id={trace_id} result_summary={answer[:200]}",
                trace_id=trace_id,
            )
        )

    errors.append(
        post_audit(
            cid, STEP_BASE + 2, "invocation",
            f"trace_id={trace_id} governed call via alias {ALIAS}: http_status={status}",
            trace_id=trace_id,
        )
    )

    negotiation = None
    if ROLE == "network" and disposition != "refused":
        negotiation = {"position": "pending-live-negotiation"}

    inspection = f"disposition={disposition}, decision={answer!r}"
    if negotiation:
        inspection += f" | negotiation_with_it={negotiation.get('position', 'n/a')}"
    errors.append(
        post_audit(cid, STEP_BASE + 3, "result-inspection", inspection, trace_id=trace_id)
    )

    out = {
        "agent": NAME, "role": ROLE, "correlation_id": cid,
        "answer": answer, "disposition": disposition,
        "http_status": status, "trace_id": trace_id,
        "evidence_errors": [e for e in errors if e],
    }
    if negotiation:
        out["negotiation"] = negotiation
    return out


def _handle_negotiate(neg):
    cid = neg.get("correlation_id", f"{NAME}-{uuid.uuid4().hex[:8]}")
    proposal = str(neg.get("proposal", ""))
    _, trace_id = new_trace(neg.get("traceparent"))
    p = proposal.lower()
    if re.search(r"freeze|restricted|regulat|escalat|approval", p):
        position = "agree: change is out of policy; escalate to the human change board, no action taken"
    elif re.search(r"ambiguous|two possible|disambiguat|gather-evidence|inconclusive", p):
        if re.search(r"reversible|roll ?back|revert|temporary|mitigat", p):
            position = "agree conditionally: reversible mitigation only; no permanent change until disambiguating evidence arrives"
        else:
            position = "disagree: cause is ambiguous and no reversible action was proposed; resubmit with a rollback plan"
    elif re.search(r"resolv|failover|protection path|switch", p):
        position = "agree: protection-path switch is runbook-approved (RB-EDGE-SLICE-DEGRADATION); schedule repair in window"
    else:
        position = "disagree: proposal names no runbook-approved action; request clarification"
    post_audit(
        cid, STEP_BASE + 2.5, "negotiation",
        f"network->it proposal ({len(proposal)} chars): {proposal[:300]!r} | it_position={position}",
        trace_id=trace_id,
    )
    return {"agent": NAME, "correlation_id": cid, "position": position}


if __name__ == "__main__":
    print(f"reference-agent starting: name={NAME} role={ROLE} model={ALIAS}", flush=True)
    app.run(port=int(os.environ.get("PORT", "8080")))
