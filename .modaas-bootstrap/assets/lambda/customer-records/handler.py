# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""customer-records: look up customers impacted by a fault at a given site."""
import json
import os

DATA_DIR = os.environ.get("DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "data"))


def handler(event, context=None):
    params = event if isinstance(event, dict) else {}
    site = (params.get("site") or params.get("query") or "").strip()
    if not site:
        return {"error": "parameter 'site' or 'query' is required"}

    path = os.path.join(DATA_DIR, "customer-records.json")
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"error": f"data file not found: {path}"}

    matches = []
    for c in data.get("customers", []):
        if c.get("site", "").upper() == site.upper() or site.upper() in " ".join(
            c.get("services", [])
        ).upper():
            matches.append({
                "id": c["id"],
                "name": c["name"],
                "tier": c.get("tier", "standard"),
                "site": c.get("site", ""),
                "services": c.get("services", []),
                "open_complaints": c.get("open_complaints", []),
            })

    return {
        "query": site,
        "total_hits": len(matches),
        "customers": matches,
    }
