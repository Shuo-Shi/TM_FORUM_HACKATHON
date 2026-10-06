"""
Drift detection between AgentCore records and Component CRs (W3.D).

Surfaces the case where a Component is deleted out-of-band but the AgentCore
record persists (orphan). Without W3.D, today's registry_health reports
phase: Ready when records are stale.

Usage: called from registry_health probe on every Nth tick to amortize cost.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

logger = logging.getLogger("modaas.registry_drift")

COMPONENT_GROUP = "oda.tmforum.org"
COMPONENT_VERSION = "v1beta1"
COMPONENT_PLURAL = "components"


def detect_drift(records: list[dict], components_api) -> dict:
    """For each record with a componentRef, verify the Component CR still exists.

    Returns:
        {driftCount: int, orphans: list[dict], phase: str, notes: str}

    404 on Component lookup -> orphan (drift).
    Non-404 errors (transient) -> logged, not counted as drift.
    Records without componentRef (legacy / pre-W3.C) -> skipped.
    """
    orphans: list[dict] = []
    notes: list[str] = []

    for record in records:
        comp_ref = _parse_component_ref(record)
        if comp_ref is None:
            # No componentRef on this record (legacy / pre-W3.C) — not drift
            continue
        try:
            components_api.get_namespaced_custom_object(
                group=COMPONENT_GROUP,
                version=COMPONENT_VERSION,
                namespace=comp_ref.get("namespace", "components"),
                plural=COMPONENT_PLURAL,
                name=comp_ref["name"],
            )
        except Exception as e:
            status_code = getattr(e, "status", None)
            if status_code == 404:
                orphans.append({
                    "name": record.get("name"),
                    "componentRef": comp_ref,
                })
            else:
                # Transient error — log but don't count as drift
                logger.warning(
                    "Drift check transient error for %s: %s",
                    record.get("name"), e,
                )
                notes.append(
                    f"transient error checking {record.get('name')}: "
                    f"{type(e).__name__}"
                )

    drift_count = len(orphans)
    return {
        "driftCount": drift_count,
        "orphans": orphans,
        "phase": "Degraded" if drift_count > 0 else "Ready",
        "notes": "; ".join(notes) if notes else "",
    }


def _parse_component_ref(record: dict) -> Optional[dict]:
    """Extract componentRef from AgentCore CUSTOM record's inlineContent.

    Returns None on missing / malformed / empty componentRef.
    """
    descriptors = record.get("descriptors") or {}
    custom = descriptors.get("custom") or {}
    inline_raw = custom.get("inlineContent", "{}")

    try:
        meta = json.loads(inline_raw)
    except (json.JSONDecodeError, TypeError):
        logger.debug(
            "Skipping drift check for %s: malformed inlineContent",
            record.get("name"),
        )
        return None

    cr = meta.get("componentRef")
    if not cr or not isinstance(cr, dict) or not cr.get("name"):
        return None
    return cr
