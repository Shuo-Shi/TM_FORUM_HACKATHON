#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""evidence-lookup Lambda tool -- read-only evidence retrieval for a correlation ID.

Returns the ledger timeline from audit-store and gateway log lines from
CloudWatch Logs for a given run. Designed to run as a Lambda behind
AgentCore Gateway.

Env:
  AUDIT_URL           Base URL of the audit-store-agentcore internal LB
  GATEWAY_LOG_GROUP   CloudWatch log group for gateway logs
                      (default: /aws/modaas/gateway)
  AWS_REGION          region (default: us-east-1)
"""
import json
import os
import time
import urllib.request
import urllib.error


AUDIT_URL = os.environ.get("AUDIT_URL", "")
GATEWAY_LOG_GROUP = os.environ.get("GATEWAY_LOG_GROUP", "/aws/modaas/gateway")


def _fetch_timeline(correlation_id):
    """GET the ledger records from audit-store for a correlation ID.

    audit-store serves `/records?cid=X` as JSON Lines (one record per line);
    `/timeline` is the human-readable rendering and is not JSON. Reading the
    wrong one raised JSONDecodeError on every call (event 486b9241)."""
    url = f"{AUDIT_URL}/records?cid={correlation_id}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        text = resp.read().decode("utf-8", "replace")
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict):
            records.append(rec)
    return sorted(records, key=lambda r: r.get("step", 0))


def _query_gateway_logs(correlation_id, run_id=None):
    """Query CloudWatch Logs for gateway entries matching the correlation ID."""
    import boto3

    client = boto3.client("logs", region_name=os.environ.get("AWS_REGION", "us-east-1"))

    filter_pattern = f'"{correlation_id}"'
    if run_id:
        filter_pattern = f'"{correlation_id}" "{run_id}"'

    now_ms = int(time.time() * 1000)
    start_ms = now_ms - 24 * 60 * 60 * 1000  # last 24 hours

    paginator = client.get_paginator("filter_log_events")
    entries = []
    for page in paginator.paginate(
        logGroupName=GATEWAY_LOG_GROUP,
        filterPattern=filter_pattern,
        startTime=start_ms,
        endTime=now_ms,
    ):
        for ev in page.get("events", []):
            entry = _parse_log_entry(ev.get("message", ""))
            entry["timestamp"] = ev.get("timestamp")
            entry["logStreamName"] = ev.get("logStreamName", "")
            entries.append(entry)

    return entries


def _parse_log_entry(message):
    """Extract structured fields from a gateway log line."""
    entry = {"raw": message}
    try:
        data = json.loads(message)
        entry["model"] = data.get("model", "")
        entry["tokens_in"] = data.get("tokens_in", 0)
        entry["tokens_out"] = data.get("tokens_out", 0)
        entry["cost"] = data.get("cost", 0.0)
        entry["http_status"] = data.get("http_status", 0)
    except (json.JSONDecodeError, TypeError):
        # Non-JSON log line -- return raw text only
        pass
    return entry


def handler(event, context=None):
    """Lambda handler: retrieve evidence for a correlation ID."""
    params = event.get("parameters") or event.get("arguments") or event
    correlation_id = (params.get("correlation_id") or "").strip()
    run_id = (params.get("run_id") or "").strip() or None

    if not correlation_id:
        return {"error": "correlation_id is required"}

    if not AUDIT_URL:
        return {"error": "AUDIT_URL environment variable not set"}

    # Fetch ledger timeline from audit-store
    try:
        timeline = _fetch_timeline(correlation_id)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        timeline = []
        timeline_error = f"audit-store unreachable: {exc}"
    else:
        timeline_error = None

    # Extract trace_id from timeline records if present
    trace_id = ""
    for record in timeline:
        if record.get("trace_id"):
            trace_id = record["trace_id"]
            break

    # Fetch gateway logs from CloudWatch
    try:
        gateway_logs = _query_gateway_logs(correlation_id, run_id)
    except Exception as exc:
        gateway_logs = []
        gw_error = f"CloudWatch query failed: {exc}"
    else:
        gw_error = None

    result = {
        "correlation_id": correlation_id,
        "trace_id": trace_id,
        "timeline": timeline,
        "timeline_count": len(timeline),
        "gateway_logs": gateway_logs,
        "gateway_log_count": len(gateway_logs),
    }
    if run_id:
        result["run_id"] = run_id
    if timeline_error:
        result["timeline_error"] = timeline_error
    if gw_error:
        result["gateway_log_error"] = gw_error

    return result
