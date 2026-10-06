"""
TMF639 Resource Inventory backing (a design note + a design note).

Wraps the existing tmf639_client module (from a design note peer projection) as
a first-class RegistryBacking. Lets Registry CRs with `backing: tmf639`
use the TMF639 Resource Inventory v5 API as the asset-record store.

Parameters (from Registry.spec.parameters):
  - baseUrl (optional, defaults to cluster-internal Canvas URL)
  - timeout (optional, seconds, default 10)

NOTE: Canvas ODA 1.2.x Resource Inventory v5 is read-only from external
producers (405 on POST). Health probe will mark Ready/Degraded
accordingly. Full event-driven projection is future work (TMF630 events
via /hub — see a design note follow-up note).

This backing gracefully returns empty results when the backend is
unreachable or read-only, matching the fail-soft pattern of InMemoryBacking.
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger("modaas.backings.tmf639")


class TMF639Backing:
    """RegistryBacking that targets Canvas TMF639 Resource Inventory v5."""

    def put_record(self, record: dict, parameters: dict) -> dict:
        """Upsert via TMF639 POST/PATCH. Returns {recordId, name, state}."""
        client = self._get_client(parameters)
        name = record.get("name", "")
        record_type = record.get("recordType", "model")

        # Extract provider from the record name convention "<provider>_<alias>"
        provider, _, alias = name.partition("_")
        if not alias:
            alias = name

        try:
            resource = client.upsert_asset(
                asset_type=record_type.capitalize(),  # 'model' -> 'Model'
                asset_name=alias,
                provider=provider,
                phase=record.get("state", "APPROVED").capitalize(),
                governance=(record.get("metadata", {}) or {}).get("governance", {}),
                metadata=record.get("metadata", {}),
            )
            return {
                "name": name,
                "recordId": (resource or {}).get("id", name),
                "state": "APPROVED",
            }
        except Exception as e:
            # Fail-soft: return with an indicator but don't propagate
            logger.warning(f"TMF639Backing put_record best-effort failure: "
                           f"{type(e).__name__}: {str(e)[:200]}")
            return {"name": name, "recordId": "", "state": "DEGRADED"}

    def search(self, query: str, filters: dict, parameters: dict) -> list[dict]:
        """Read-only list. Returns canonical record dicts or [] on failure."""
        client = self._get_client(parameters)
        asset_type = (filters or {}).get("recordType")
        try:
            resources = client.list_assets(
                asset_type=asset_type.capitalize() if asset_type else None
            )
        except Exception as e:
            logger.warning(f"TMF639Backing search failure: {e}")
            return []

        out = []
        q = (query or "").lower()
        # PF02: Map resourceStatus from response to canonical state
        state_map = {
            "approved": "APPROVED",
            "paused": "PAUSED",
            "retired": "RETIRED",
            "deprecated": "DEPRECATED",
            "pending": "PENDING",
            "failed": "FAILED",
        }
        for r in resources or []:
            name = r.get("name") or ""
            # filter on name substring
            if q and q not in name.lower():
                continue
            res_status = (r.get("resourceStatus") or "").lower()
            state = state_map.get(res_status, "APPROVED")
            out.append({
                "name": name,
                "recordType": (r.get("category") or "").lower(),
                "state": state,
            })
        return out

    def deprecate(self, name: str, parameters: dict) -> None:
        """Delete from TMF639. No-op if not found."""
        client = self._get_client(parameters)
        provider, _, alias = name.partition("_")
        if not alias:
            alias = name
        try:
            client.delete_asset(alias, provider)
        except Exception as e:
            logger.warning(f"TMF639Backing deprecate failure (continuing): {e}")

    def annotate(self, name: str, metadata: dict, parameters: dict) -> None:
        """Not supported on this backing. Raises with the reason.

        `annotate` must merge metadata while leaving lifecycle state intact
        (pause is reversible — F71). Two things block an honest implementation
        here, and neither is a code gap:

          * Canvas ODA 1.2.x serves Resource Inventory v5 read-only to external
            producers — `upsert_asset` already raises TMF639ReadOnlyEndpoint on
            405 rather than fabricating success (see tmf639_client.upsert_asset).
          * A partial PATCH of `resourceCharacteristic` has merge-vs-replace
            semantics that have NOT been verified against a live v5 endpoint. A
            replace would silently drop every other characteristic on the
            resource, which is worse than refusing.

        So this raises `UnsupportedBackingOperation` and the caller surfaces the
        reason. It previously raised `AttributeError` — same outcome, no reason.
        Returning None would be worse than both: the caller would record
        `RegistryPauseProjected=True` for a projection that never happened
        (Coherence Rule 19).

        To implement: verify v5 PATCH characteristic semantics against a live
        endpoint, or route through the TMF630 `/hub` event path (a design note
        follow-up) which is the canonical write path for this inventory.
        """
        try:
            from operators.shared.backings import UnsupportedBackingOperation
        except ImportError:
            from shared.backings import UnsupportedBackingOperation
        raise UnsupportedBackingOperation(
            f"tmf639 backing cannot annotate '{name}': Canvas Resource Inventory "
            f"v5 is read-only to external producers, and partial PATCH of "
            f"resourceCharacteristic has unverified merge semantics. Pause is "
            f"enforced at the gateway regardless; the catalog projection is "
            f"pending the TMF630 /hub event path (a design note follow-up)."
        )

    # ---------------------------------------------------------------- #
    # Internals                                                          #
    # ---------------------------------------------------------------- #
    @staticmethod
    def _get_client(parameters: dict):
        """Return a TMF639Client configured from Registry.spec.parameters."""
        base_url = parameters.get("baseUrl") or parameters.get("endpoint")
        timeout = int(parameters.get("timeout", 10))

        # PF01: Consolidated import — no more sys.path walking
        from operators.shared.tmf639_client import TMF639Client
        return TMF639Client(base_url=base_url, timeout=timeout)
