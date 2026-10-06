#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates.
# SPDX-License-Identifier: MIT-0

"""VelocityX filesystem MCP server.

Provides governed filesystem operations within one mounted workspace:

- read_file
- write_file
- list_directory

MCP surface, Streamable HTTP 2024-11-05:

  POST /       initialize | tools/list | tools/call
  POST /mcp    same handler
  GET  /healthz

Security boundaries:

- All paths are confined below WORKSPACE_ROOT.
- Relative and absolute-looking client paths are resolved inside the workspace.
- Symbolic-link escapes are rejected.
- Read and write payload sizes are limited.
- Directory writes are not allowed through write_file.
- Full file contents are not written to logs.
"""

import json
import os
import sys
import tempfile
from http.server import HTTPServer, BaseHTTPRequestHandler


PORT = int(os.environ.get("PORT", "8080"))
PROTOCOL = "2024-11-05"
SERVER_NAME = "velocityx-filesystem"
SERVER_VERSION = "1.0.0"

# This path must exist inside the Kubernetes container.
WORKSPACE_ROOT = os.path.realpath(
    os.environ.get("WORKSPACE_ROOT", "/workspace")
)

MAX_READ_BYTES = int(
    os.environ.get("MAX_READ_BYTES", str(1024 * 1024))
)

MAX_WRITE_BYTES = int(
    os.environ.get("MAX_WRITE_BYTES", str(1024 * 1024))
)

MAX_LIST_ENTRIES = int(
    os.environ.get("MAX_LIST_ENTRIES", "1000")
)


TOOLS = [
    {
        "name": "read_file",
        "description": (
            "Read a UTF-8 text file from the governed VelocityX workspace. "
            "The path must remain inside the configured workspace root."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Workspace-relative file path, for example "
                        "'IMPLEMENTATION_PLAN.md' or 'controls/control16.py'."
                    ),
                }
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "write_file",
        "description": (
            "Create or replace a UTF-8 text file inside the governed "
            "VelocityX workspace. Missing parent directories are created."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Workspace-relative destination path, for example "
                        "'register.yaml' or 'controls/control16.py'."
                    ),
                },
                "content": {
                    "type": "string",
                    "description": "Complete UTF-8 text content to write.",
                },
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_directory",
        "description": (
            "List files and subdirectories at a location inside the governed "
            "VelocityX workspace."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Workspace-relative directory path. Use '.' or omit "
                        "the field to list the workspace root."
                    ),
                }
            },
            "required": [],
            "additionalProperties": False,
        },
    },
]


def log(message):
    """Write one audit-friendly line to stdout."""
    sys.stdout.write("%s %s\n" % (SERVER_NAME, message))
    sys.stdout.flush()


def _err(message):
    """Return an MCP tool error result."""
    return {
        "isError": True,
        "content": [
            {
                "type": "text",
                "text": message,
            }
        ],
    }


def _ok(payload):
    """Return a successful MCP tool result."""
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(
                    payload,
                    indent=2,
                    ensure_ascii=False,
                    sort_keys=True,
                ),
            }
        ],
    }


def resolve_workspace_path(path):
    """Resolve a client path and reject workspace escapes.

    Both ordinary relative paths and absolute-looking paths are interpreted
    relative to WORKSPACE_ROOT. Symlink resolution is included in the check.
    """
    if path is None:
        path = "."

    if not isinstance(path, str):
        raise ValueError("'path' must be a string")

    path = path.strip()

    if not path:
        path = "."

    # Treat /foo/bar as foo/bar inside the governed workspace.
    relative_path = path.lstrip("/")

    candidate = os.path.realpath(
        os.path.join(WORKSPACE_ROOT, relative_path)
    )

    try:
        common = os.path.commonpath(
            [WORKSPACE_ROOT, candidate]
        )
    except ValueError:
        raise ValueError("path is outside the governed workspace")

    if common != WORKSPACE_ROOT:
        raise ValueError("path is outside the governed workspace")

    return candidate


def relative_display_path(path):
    """Return a stable path relative to the workspace."""
    relative = os.path.relpath(path, WORKSPACE_ROOT)

    if relative == ".":
        return "."

    return relative


def do_read_file(args):
    args = args or {}
    requested_path = args.get("path")

    if not requested_path:
        return _err("read_file requires a non-empty 'path'.")

    try:
        path = resolve_workspace_path(requested_path)
    except ValueError as exc:
        return _err(str(exc))

    if not os.path.exists(path):
        return _err(
            "file does not exist: %s"
            % relative_display_path(path)
        )

    if not os.path.isfile(path):
        return _err(
            "path is not a regular file: %s"
            % relative_display_path(path)
        )

    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return _err("could not inspect file: %s" % exc)

    if size > MAX_READ_BYTES:
        return _err(
            "file exceeds read limit: %d bytes; limit=%d"
            % (size, MAX_READ_BYTES)
        )

    try:
        with open(path, "r", encoding="utf-8") as handle:
            content = handle.read()
    except UnicodeDecodeError:
        return _err(
            "file is not valid UTF-8 text: %s"
            % relative_display_path(path)
        )
    except OSError as exc:
        return _err("could not read file: %s" % exc)

    log(
        "read_file path=%r bytes=%d"
        % (relative_display_path(path), size)
    )

    return _ok(
        {
            "path": relative_display_path(path),
            "size_bytes": size,
            "content": content,
        }
    )


def do_write_file(args):
    args = args or {}
    requested_path = args.get("path")
    content = args.get("content")

    if not requested_path:
        return _err("write_file requires a non-empty 'path'.")

    if not isinstance(content, str):
        return _err("write_file requires string 'content'.")

    content_bytes = content.encode("utf-8")

    if len(content_bytes) > MAX_WRITE_BYTES:
        return _err(
            "content exceeds write limit: %d bytes; limit=%d"
            % (len(content_bytes), MAX_WRITE_BYTES)
        )

    try:
        path = resolve_workspace_path(requested_path)
    except ValueError as exc:
        return _err(str(exc))

    if os.path.isdir(path):
        return _err(
            "destination is a directory: %s"
            % relative_display_path(path)
        )

    parent = os.path.dirname(path)

    try:
        os.makedirs(parent, exist_ok=True)
    except OSError as exc:
        return _err(
            "could not create parent directory: %s"
            % exc
        )

    # Re-check after creating the parent, including resolved symlinks.
    try:
        path = resolve_workspace_path(requested_path)
    except ValueError as exc:
        return _err(str(exc))

    temporary_path = None

    try:
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=".velocityx-write-",
            dir=os.path.dirname(path),
            text=True,
        )

        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary_path, path)
        temporary_path = None

    except OSError as exc:
        return _err("could not write file: %s" % exc)

    finally:
        if temporary_path and os.path.exists(temporary_path):
            try:
                os.unlink(temporary_path)
            except OSError:
                pass

    log(
        "write_file path=%r bytes=%d"
        % (
            relative_display_path(path),
            len(content_bytes),
        )
    )

    return _ok(
        {
            "path": relative_display_path(path),
            "size_bytes": len(content_bytes),
            "status": "written",
        }
    )


def do_list_directory(args):
    args = args or {}
    requested_path = args.get("path", ".")

    try:
        path = resolve_workspace_path(requested_path)
    except ValueError as exc:
        return _err(str(exc))

    if not os.path.exists(path):
        return _err(
            "directory does not exist: %s"
            % relative_display_path(path)
        )

    if not os.path.isdir(path):
        return _err(
            "path is not a directory: %s"
            % relative_display_path(path)
        )

    try:
        names = sorted(os.listdir(path))
    except OSError as exc:
        return _err("could not list directory: %s" % exc)

    truncated = len(names) > MAX_LIST_ENTRIES
    selected_names = names[:MAX_LIST_ENTRIES]
    entries = []

    for name in selected_names:
        entry_path = os.path.join(path, name)

        try:
            is_symlink = os.path.islink(entry_path)
            is_directory = os.path.isdir(entry_path)
            is_file = os.path.isfile(entry_path)

            if is_symlink:
                entry_type = "symlink"
            elif is_directory:
                entry_type = "directory"
            elif is_file:
                entry_type = "file"
            else:
                entry_type = "other"

            entry = {
                "name": name,
                "type": entry_type,
            }

            if is_file and not is_symlink:
                entry["size_bytes"] = os.path.getsize(entry_path)

            entries.append(entry)

        except OSError as exc:
            entries.append(
                {
                    "name": name,
                    "type": "unknown",
                    "error": str(exc),
                }
            )

    log(
        "list_directory path=%r entries=%d truncated=%s"
        % (
            relative_display_path(path),
            len(entries),
            truncated,
        )
    )

    return _ok(
        {
            "path": relative_display_path(path),
            "entries": entries,
            "entry_count": len(entries),
            "truncated": truncated,
        }
    )


def call_tool(name, args):
    """Dispatch one MCP tool call."""
    try:
        if name == "read_file":
            return do_read_file(args)

        if name == "write_file":
            return do_write_file(args)

        if name == "list_directory":
            return do_list_directory(args)

        return _err("unknown tool: %s" % name)

    except Exception as exc:
        # Avoid crashing the MCP server on one malformed tool call.
        log(
            "ERROR tool=%r type=%s message=%s"
            % (name, type(exc).__name__, exc)
        )
        return _err(
            "tool failed: %s: %s"
            % (type(exc).__name__, exc)
        )


def handle(req):
    """Handle one JSON-RPC request.

    Returns one JSON-RPC response dictionary, or None for a notification.
    """
    rid = req.get("id")
    method = req.get("method")

    if method == "initialize":
        result = {
            "protocolVersion": PROTOCOL,
            "capabilities": {
                "tools": {},
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION,
            },
        }

    elif method == "tools/list":
        result = {
            "tools": TOOLS,
        }

    elif method == "tools/call":
        params = req.get("params") or {}

        result = call_tool(
            params.get("name"),
            params.get("arguments") or {},
        )

    elif method == "ping":
        result = {}

    elif rid is None or str(method or "").startswith("notifications/"):
        # MCP notifications do not receive JSON-RPC responses.
        return None

    else:
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "error": {
                "code": -32601,
                "message": "method not found: %s" % method,
            },
        }

    return {
        "jsonrpc": "2.0",
        "id": rid,
        "result": result,
    }


class Handler(BaseHTTPRequestHandler):
    """Streamable HTTP MCP request handler."""

    def log_message(self, *args):
        # Suppress default HTTP access logs.
        pass

    def send_json(self, status_code, obj):
        body = json.dumps(
            obj,
            ensure_ascii=False,
        ).encode("utf-8")

        self.send_response(status_code)
        self.send_header(
            "Content-Type",
            "application/json",
        )
        self.send_header(
            "Content-Length",
            str(len(body)),
        )
        self.send_header(
            "Mcp-Session-Id",
            SERVER_NAME,
        )
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/healthz"):
            workspace_exists = os.path.isdir(WORKSPACE_ROOT)
            workspace_readable = os.access(
                WORKSPACE_ROOT,
                os.R_OK,
            )
            workspace_writable = os.access(
                WORKSPACE_ROOT,
                os.W_OK,
            )

            healthy = (
                workspace_exists
                and workspace_readable
                and workspace_writable
            )

            return self.send_json(
                200 if healthy else 503,
                {
                    "ok": healthy,
                    "workspace_root": WORKSPACE_ROOT,
                    "workspace_exists": workspace_exists,
                    "workspace_readable": workspace_readable,
                    "workspace_writable": workspace_writable,
                    "max_read_bytes": MAX_READ_BYTES,
                    "max_write_bytes": MAX_WRITE_BYTES,
                },
            )

        return self.send_json(
            404,
            {
                "error": "not found",
            },
        )

    def do_POST(self):
        if self.path.rstrip("/") not in ("", "/mcp"):
            return self.send_json(
                404,
                {
                    "error": "not found: %s" % self.path,
                },
            )

        try:
            content_length = int(
                self.headers.get("Content-Length", "0")
            )

            request_body = self.rfile.read(content_length)
            request = json.loads(request_body)

        except Exception as exc:
            return self.send_json(
                400,
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32700,
                        "message": str(exc),
                    },
                },
            )

        method = request.get("method")
        log(
            "request method=%r id=%r path=%r"
            % (
                method,
                request.get("id"),
                self.path,
            )
        )

        response = handle(request)

        if response is None:
            self.send_response(202)
            self.send_header(
                "Content-Length",
                "0",
            )
            self.send_header(
                "Mcp-Session-Id",
                SERVER_NAME,
            )
            self.end_headers()
            return

        self.send_json(200, response)


def serve_stdio():
    """Serve line-delimited JSON-RPC through stdin/stdout."""
    for line in sys.stdin:
        line = line.strip()

        if not line:
            continue

        try:
            request = json.loads(line)
        except Exception as exc:
            response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": str(exc),
                },
            }
        else:
            response = handle(request)

        if response is not None:
            sys.stdout.write(
                json.dumps(response) + "\n"
            )
            sys.stdout.flush()


if __name__ == "__main__":
    stdio = "--stdio" in sys.argv[1:]

    if stdio:
        # Keep diagnostic output away from the stdio JSON-RPC stream.
        log = lambda message: sys.stderr.write(
            "%s %s\n" % (SERVER_NAME, message)
        )

    workspace_exists = os.path.isdir(WORKSPACE_ROOT)

    log(
        "starting workspace=%r exists=%s"
        % (WORKSPACE_ROOT, workspace_exists)
    )

    if not workspace_exists:
        log(
            "ERROR workspace root is not mounted: %s"
            % WORKSPACE_ROOT
        )

    if stdio:
        serve_stdio()
    else:
        log(
            "listening on 0.0.0.0:%d"
            % PORT
        )

        HTTPServer(
            ("0.0.0.0", PORT),
            Handler,
        ).serve_forever()