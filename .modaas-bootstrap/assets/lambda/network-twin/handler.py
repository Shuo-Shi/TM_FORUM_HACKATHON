# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""network-twin: predict RSRP / signal quality for a site using the digital twin dataset."""
import json
import os

DATA_DIR = os.environ.get("DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "data"))


def handler(event, context=None):
    params = event if isinstance(event, dict) else {}
    site = (params.get("site") or params.get("query") or "").strip()
    if not site:
        return {"error": "parameter 'site' or 'query' is required"}

    path = os.path.join(DATA_DIR, "twin-dataset.json")
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"error": f"twin dataset not found: {path}"}

    for s in data.get("sites", []):
        if s["id"].upper() == site.upper():
            return {
                "query": site,
                "site": s["id"],
                "prediction": s.get("prediction", {}),
                "elements": s.get("elements", []),
                "telemetry": s.get("telemetry", {}),
            }

    return {"query": site, "error": f"no twin data for site {site}"}
