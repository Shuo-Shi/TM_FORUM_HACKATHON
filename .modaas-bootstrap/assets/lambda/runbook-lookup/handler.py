#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""runbook-lookup Lambda tool -- search runbook data from static/data.

Loads incident, customer, and network data from JSON files bundled in the
Lambda deployment package. Returns matching records for a query.

Env:
  DATA_DIR  directory containing it-incidents.json, customer-records.json,
            network-inventory.json (default: current directory)
"""
import json
import os
import re

DATA_DIR = os.environ.get("DATA_DIR", os.path.dirname(__file__) or ".")

_data_cache = {}


def _load(name):
    if name not in _data_cache:
        path = os.path.join(DATA_DIR, name)
        if os.path.exists(path):
            with open(path) as f:
                _data_cache[name] = json.load(f)
        else:
            _data_cache[name] = {}
    return _data_cache[name]


def _search_incidents(query):
    data = _load("it-incidents.json")
    incidents = data.get("incidents", [])
    q = query.lower()
    return [i for i in incidents if q in json.dumps(i).lower()][:10]


def _search_customers(query):
    data = _load("customer-records.json")
    customers = data.get("customers", [])
    q = query.lower()
    return [c for c in customers if q in json.dumps(c).lower()][:10]


def _search_network(query):
    data = _load("network-inventory.json")
    sites = data.get("sites", [])
    q = query.lower()
    results = []
    for site in sites:
        if q in json.dumps(site).lower():
            results.append({"id": site.get("id"), "type": site.get("type"),
                            "elements": len(site.get("elements", []))})
    return results[:10]


def _search_scenarios(query):
    data = _load("network-inventory.json")
    scenarios = data.get("fault_scenarios", [])
    q = query.lower()
    return [{"id": s["id"], "title": s["title"], "difficulty": s["difficulty"]}
            for s in scenarios if q in json.dumps(s).lower()][:10]


def handler(event, context):
    """Lambda handler for runbook-lookup tool."""
    params = event.get("parameters") or event.get("arguments") or event
    query = params.get("query", "")
    category = params.get("category", "all")

    if not query.strip():
        return {"error": "query is required"}

    results = {}
    if category in ("all", "incidents"):
        results["incidents"] = _search_incidents(query)
    if category in ("all", "customers"):
        results["customers"] = _search_customers(query)
    if category in ("all", "network"):
        results["network"] = _search_network(query)
    if category in ("all", "scenarios"):
        results["scenarios"] = _search_scenarios(query)

    total = sum(len(v) for v in results.values())
    return {"query": query, "category": category, "total_hits": total, "results": results}
