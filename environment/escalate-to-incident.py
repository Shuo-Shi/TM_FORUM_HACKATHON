#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""escalate-to-incident.py — turn a MoDaaS evidence chain into a ServiceNow
incident.

The graded S3 scenario ends with disposition `escalate`. On a real network
that means a HUMAN takes over -- and humans work incident queues, not JSON
ledgers. This script closes that loop: it pulls the correlation-id's full
evidence chain from the audit store and opens a ServiceNow incident carrying
the chain as work notes, so the operator who picks it up sees exactly what
the agents saw, decided, and refused to do.

Works with any ServiceNow instance, including a free Personal Developer
Instance (developer.servicenow.com).

Usage:
  export SNOW_INSTANCE=devXXXXXX.service-now.com
  export SNOW_USER=admin
  export SNOW_PASS=...
  python3 escalate-to-incident.py --cid fault-1788864931 \
      [--audit-store http://audit-store.components:8080]

From outside the cluster, port-forward first:
  kubectl -n components port-forward svc/audit-store 8080:8080 &
  python3 escalate-to-incident.py --cid <cid> --audit-store http://localhost:8080
"""
import argparse
import base64
import json
import os
import re
import sys
import urllib.request


def fetch_chain(audit_store: str, cid: str) -> list:
    # The store returns JSONL -- one record per line, not an envelope.
    # (Verified against static/reference-impl/audit-store.py do_GET.)
    url = f"{audit_store}/records?cid={cid}"
    with urllib.request.urlopen(url, timeout=10) as r:
        text = r.read().decode()
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if not records:
        sys.exit(f"no evidence records for cid={cid} at {audit_store}")
    return records


def render_work_notes(cid: str, records: list) -> str:
    # Field names verified against agent.py post_audit() calls:
    # phase / actor / step / detail / disposition / correlation_id.
    lines = [f"MoDaaS evidence chain for correlation id {cid}",
             f"({len(records)} records, chronological)", ""]
    # By time, as the header says. `step` is the workflow position, and it
    # disagrees with time where agents overlap: the IT agent's negotiation
    # record (step 5.5) is written after the network agent's steps 7-8.
    for rec in sorted(records, key=lambda r: (str(r.get("ts", "")), r.get("step", 0))):
        ts = rec.get("ts", "?")
        actor = rec.get("actor") or rec.get("agent", "?")
        phase = rec.get("phase", "record").upper()
        disp = rec.get("disposition", "")
        detail = rec.get("detail", "")
        line = f"[{ts}] step {rec.get('step','?')} {actor} {phase}"
        if disp:
            line += f" disposition={disp}"
        lines.append(line)
        if detail:
            lines.append(f"    {str(detail)[:400]}")
    return "\n".join(lines)


DISPOSITION = re.compile(r"disposition=([\w-]+)")


def dispositions_of(records: list) -> set:
    """Dispositions as the agents recorded them.

    The reference agents write `disposition=<x>` inside the result-inspection
    `detail` string, not as a field of its own. Reading only a `disposition`
    field found nothing, and the incident then claimed every run had
    escalated, whatever the agents decided (found 2026-09-26).
    """
    found = set()
    for r in records:
        if r.get("disposition"):
            found.add(str(r["disposition"]))
        m = DISPOSITION.search(str(r.get("detail", "")))
        if m:
            found.add(m.group(1))
    return found


def incident_payload(cid: str, records: list) -> dict:
    dispositions = dispositions_of(records)
    agents = sorted({r.get("actor") or r.get("agent", "?") for r in records})
    return {
        "short_description":
            f"[MoDaaS] Agents escalated {cid} — human decision required",
        "description": (
            f"Autonomous agents ({', '.join(agents)}) evaluated fault {cid}. "
            f"Dispositions recorded: {', '.join(sorted(dispositions)) or 'none recorded'}. "
            "Full evidence chain in work notes."),
        "work_notes": render_work_notes(cid, records),
        "urgency": "2",
        "impact": "2",
        "category": "network",
        # correlation ties the incident back to the ledger, both directions
        "correlation_id": cid,
        "correlation_display": "modaas-evidence-chain",
    }


def create_incident(instance: str, user: str, pw: str, payload: dict) -> dict:
    req = urllib.request.Request(
        f"https://{instance}/api/now/table/incident",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": "Basic " + base64.b64encode(
                f"{user}:{pw}".encode()).decode(),
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)["result"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cid", required=True, help="correlation id (e.g. fault-…)")
    ap.add_argument("--audit-store",
                    default=os.environ.get("AUDIT_STORE",
                                           "http://audit-store.components:8080"))
    ap.add_argument("--dry-run", action="store_true",
                    help="print the incident this chain would file; call nothing")
    args = ap.parse_args()

    if args.dry_run:
        records = fetch_chain(args.audit_store, args.cid)
        print(f"evidence chain: {len(records)} records for {args.cid}")
        print(json.dumps(incident_payload(args.cid, records), indent=2))
        return

    instance = os.environ.get("SNOW_INSTANCE")
    user = os.environ.get("SNOW_USER")
    pw = os.environ.get("SNOW_PASS")
    if not all([instance, user, pw]):
        sys.exit("set SNOW_INSTANCE, SNOW_USER, SNOW_PASS (a free PDI works)")

    records = fetch_chain(args.audit_store, args.cid)
    print(f"evidence chain: {len(records)} records for {args.cid}")
    inc = create_incident(instance, user, pw, incident_payload(args.cid, records))
    print(f"incident created: {inc.get('number')}")
    print(f"  sys_id : {inc.get('sys_id')}")
    print(f"  url    : https://{instance}/nav_to.do?uri=incident.do?sys_id={inc.get('sys_id')}")


if __name__ == "__main__":
    main()
