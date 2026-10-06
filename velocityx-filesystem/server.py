#!/usr/bin/env python3

import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler

ROOT = "/home/ec2-user/environment/VelocityX"

TOOLS = [
    {
        "name": "read_file",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "write_file",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"}
            },
            "required": ["path", "content"]
        }
    },
    {
        "name": "list_directory",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"}
            }
        }
    }
]

def safe(path):
    full = os.path.abspath(os.path.join(ROOT, path.lstrip("/")))
    if not full.startswith(ROOT):
        raise Exception("outside workspace")
    return full

def call_tool(name, args):
    if name == "read_file":
        p = safe(args["path"])
        with open(p) as f:
            return {"content":[{"type":"text","text":f.read()}]}

    if name == "write_file":
        p = safe(args["path"])
        with open(p,"w") as f:
            f.write(args["content"])
        return {"content":[{"type":"text","text":"ok"}]}

    if name == "list_directory":
        p = safe(args.get("path","."))
        return {
            "content":[
                {
                    "type":"text",
                    "text":"\n".join(os.listdir(p))
                }
            ]
        }

    return {"isError":True}

class H(BaseHTTPRequestHandler):

    def send_json(self,obj):
        body=json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body)))
        self.send_header("Mcp-Session-Id","velocityx-filesystem")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path=="/healthz":
            return self.send_json({"ok":True})
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        n=int(self.headers.get("Content-Length",0))
        req=json.loads(self.rfile.read(n))

        method=req.get("method")

        if method=="initialize":
            return self.send_json({
                "jsonrpc":"2.0",
                "id":req.get("id"),
                "result":{
                    "capabilities":{"tools":{}},
                    "serverInfo":{
                        "name":"velocityx-filesystem"
                    }
                }
            })

        if method=="tools/list":
            return self.send_json({
                "jsonrpc":"2.0",
                "id":req.get("id"),
                "result":{"tools":TOOLS}
            })

        if method=="tools/call":
            p=req["params"]
            result=call_tool(
                p["name"],
                p.get("arguments",{})
            )

            return self.send_json({
                "jsonrpc":"2.0",
                "id":req.get("id"),
                "result":result
            })

HTTPServer(("0.0.0.0",8080),H).serve_forever()
