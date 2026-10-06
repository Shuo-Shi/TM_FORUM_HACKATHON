#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""MVW audit repository -- 'a simple file store. Sophistication is not
required. Visibility is required.' (Tuesday contract, verbatim)
POST /records {json}  -> append to /data/audit-trail.jsonl
GET  /records         -> raw jsonl
GET  /records?cid=X   -> only records for correlation id X
GET  /timeline[?cid=X]-> human-readable rendering
GET  /healthz         -> ok

Write gate: if AUDIT_WRITE_TOKEN is set in the environment, POST /records must
carry a matching X-Audit-Token header or it is rejected 401. Reads stay open --
the forgery risk is on append, and the labs read the timeline from an
unauthenticated throwaway pod. Until 2026-09-19 this file ignored the variable
entirely while audit-store.yaml dutifully set it and the content promised
"unauthenticated POSTs return 401"; they returned 201, so the ledger every team
is graded on accepted forged records from anything that could reach the Service.
"""
import hmac
import json, os, time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
PATH = "/data/audit-trail.jsonl"
TOKEN = os.environ.get("AUDIT_WRITE_TOKEN", "")
def read_records(cid=None):
    if cid:
        cid = cid.strip()
    if not os.path.exists(PATH): return []
    out = []
    with open(PATH) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try: r = json.loads(line)
            except Exception: continue
            if cid and r.get("correlation_id") != cid: continue
            out.append(r)
    return out
def render(records):
    lines = ["AUDIT TRAIL -- %d records" % len(records), "=" * 64]
    for i, r in enumerate(records, 1):
        lines.append("%2d. [%s] %s | actor=%s | step=%s" % (
            i, r.get("ts", "?"), r.get("phase", "?").upper(),
            r.get("actor", "?"), r.get("step", "?")))
        lines.append("    correlation_id=%s" % r.get("correlation_id", "?"))
        detail = r.get("detail", "")
        if detail: lines.append("    %s" % str(detail)[:200])
    return "\n".join(lines) + "\n"
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body, ctype="text/plain"):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query)
        cid = (q.get("cid") or [None])[0]
        if u.path == "/healthz": return self._send(200, "ok")
        if u.path == "/records":
            recs = read_records(cid)
            return self._send(200, "\n".join(json.dumps(r) for r in recs) + "\n", "application/json")
        if u.path == "/timeline":
            recs = read_records(cid)
            if cid and not recs:
                all_recs = read_records(None)
                if all_recs:
                    cids = sorted(set(r.get("correlation_id", "?") for r in all_recs))
                    return self._send(200,
                        "0 records for cid '%s' (store has %d records; ids: %s)\n"
                        % (cid, len(all_recs), ", ".join(cids[:20])))
            return self._send(200, render(recs))
        return self._send(404, "not found")
    def do_POST(self):
        if urlparse(self.path).path != "/records": return self._send(404, "not found")
        # compare_digest, not ==, so a token cannot be recovered a byte at a
        # time from response timing. Cheap here; the habit is the point.
        # Compare as bytes: compare_digest on str raises TypeError for any
        # non-ASCII input, which an attacker can trigger with one header --
        # fail-closed, but as an unhandled traceback rather than a 401.
        if TOKEN:
            given = self.headers.get("X-Audit-Token", "").encode("utf-8", "replace")
            if not hmac.compare_digest(given, TOKEN.encode("utf-8")):
                return self._send(401, "unauthorized: X-Audit-Token missing or wrong")
        try:
            n = int(self.headers.get("Content-Length", 0))
            rec = json.loads(self.rfile.read(n))
            if not isinstance(rec, dict):
                raise ValueError("record must be a JSON object")
        except Exception as e:
            return self._send(400, "bad record: %s" % e)
        rec.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        rec["seq"] = int(time.time() * 1000)
        os.makedirs("/data", exist_ok=True)
        with open(PATH, "a") as f:
            f.write(json.dumps(rec) + "\n")
        self._send(201, json.dumps({"ok": True, "seq": rec["seq"]}), "application/json")
if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), H).serve_forever()
