#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""server.py — starter-kit template for a governed MCP tool backend.

`new-tool.sh` copies this file (with TOOL_NAME substituted) into
~/tools/<alias>/server.py, then deploys it as a ConfigMap + Deployment +
Service in `components`, the same shape modaas-docs and demo-tool-backend
use (static/kb/modaas-docs-mcp.yaml, static/reference-impl/demo-tool-backend.yaml).

Stdlib only, deliberately boring, same as the reference backends: enough MCP
(Streamable HTTP, JSON-RPC 2.0) to be a real tool your ToolConfig can front,
and nothing more. Replace `EXAMPLE_TOOL` and the body of `call_tool()` with
your own logic; the JSON-RPC plumbing below does not need to change for a
single-tool backend.

MCP surface:
  POST /      initialize | tools/list | tools/call
  POST /mcp   the same handler (agentgateway's AgentgatewayBackend connects
              with no path; some MCP clients try /mcp first — serving both
              avoids a 404 nobody would diagnose quickly)
  GET  /healthz
"""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

PROTOCOL = "2024-11-05"
SERVER_NAME = os.environ.get("TOOL_NAME", "example-tool")

TOOLS = [
    {
        "name": "EXAMPLE_TOOL",
        "description": "Replace this description with what your tool actually does.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Replace with your real input."},
            },
            "required": ["query"],
        },
    },
]


def call_tool(name, args):
    """Replace this with your tool's real logic.

    Return {"content": [{"type": "text", "text": "..."}]} on success, or
    {"isError": True, "content": [...]} on a caller error (never raise —
    an unhandled exception here becomes a 500 the perimeter cannot explain
    to the caller as a tool-level refusal).
    """
    if name != "EXAMPLE_TOOL":
        return {"isError": True, "content": [{"type": "text", "text": f"unknown tool {name}"}]}
    query = (args or {}).get("query", "")
    if not query:
        return {"isError": True, "content": [{"type": "text", "text": "query is required"}]}
    result = {"echo": query, "note": "replace call_tool() with your real logic"}
    return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}


def handle(req):
    rid, method = req.get("id"), req.get("method")
    if method == "initialize":
        res = {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
               "serverInfo": {"name": SERVER_NAME, "version": "1.0.0"}}
    elif method == "tools/list":
        res = {"tools": TOOLS}
    elif method == "tools/call":
        p = req.get("params") or {}
        res = call_tool(p.get("name"), p.get("arguments"))
    elif method in ("notifications/initialized", "ping"):
        res = {}
    else:
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": f"method not found: {method}"}}
    return {"jsonrpc": "2.0", "id": rid, "result": res}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # the access log is noise; a call is proven by the ledger, not this log

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Mcp-Session-Id", SERVER_NAME)
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path.startswith("/healthz"):
            return self._json(200, {"ok": True})
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path.rstrip("/") not in ("", "/mcp"):
            return self._json(404, {"error": f"not found: {self.path}"})
        try:
            n = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(n))
        except Exception as e:
            return self._json(400, {"jsonrpc": "2.0", "id": None,
                                    "error": {"code": -32700, "message": str(e)}})
        self._json(200, handle(req))


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), H).serve_forever()
