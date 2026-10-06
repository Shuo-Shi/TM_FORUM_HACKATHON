<!-- Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. -->
<!-- SPDX-License-Identifier: MIT-0 -->
# agent-template

The file `new-agent.sh` copies to `~/agents/<name>/agent.py` when you run it.
You do not need to touch anything here directly — run `new-agent.sh` from
`static/starter/` instead, which copies this template, builds it, declares
it, and prints the approve command. This directory exists so you can read
what you are about to run before you run it, and so you can copy it
elsewhere if you want to build outside the workshop's own tooling.

## Files

| File | Purpose |
|---|---|
| `agent.py` | The agent: a governed Strands agent, `BedrockAgentCoreApp`, model client pointed at the platform gateway by alias, evidence writes to the ledger. Same shape as Module 9's worked example. |
| `requirements.txt` | Pinned Python dependencies (Strands SDK, the AgentCore SDK). |
| `Dockerfile` | Reference only — `new-agent.sh` builds through `build-agent-image.sh`, not `docker build` directly (see the comment at the top of the Dockerfile for why). |

## What to change

Almost everything you'd want to customize is one of:

1. **The system prompt** (`PROMPT` in `agent.py`) — what your agent is for.
2. **The model alias** — passed as an argument to `new-agent.sh`, not edited here.
3. **A tool** — pass `--tool <alias>` to `new-agent.sh` and the template's
   `TOOL_MCP_URL`/`TOOL_MCP_ALIAS` environment variables wire an MCP client in
   automatically; no code change needed for the common case.
4. **Real logic beyond one model call** — edit `invoke()` in `agent.py`.
   Keep the three-record evidence pattern (`intent` → `invocation` →
   `result-inspection`) whatever you add: that is what the challenge's
   auditor questions and `score-run.py`-style grading both read.

Read Module 9 (Build Your Own Agent) for the full walkthrough of why each
piece is shaped the way it is.
