"""
In-memory Registry backing for tests.

Implements RegistryBacking Protocol with a simple dict. Used by unit tests
that want to verify dispatch without hitting AWS.

a design note PR 2: ids are MINTED, not derived from the name. `f"inmem-{name}"` was
stable across every write, so two approvals of the same alias produced the same
id and a re-approval after a spec change was indistinguishable from the first.
A test double that cannot express the audit property under test silently makes
the property untestable — so this one mints a fresh id per write and per version,
matching the shape the real backing returns (a service-assigned identifier that
is unique per record, not a function of the alias).
"""
from __future__ import annotations

import uuid


class InMemoryBacking:
    """Dict-backed registry — test double."""

    def __init__(self) -> None:
        self._records: dict[str, dict] = {}

    @staticmethod
    def mint_record_id(name: str, version: str = "") -> str:
        """A unique id per record AND per version.

        `name` and `version` are carried in the id so a failing assertion reads
        legibly ("inmem-aws-bedrock_noc-llm-v3-a1b2c3d4" says what it is), while
        the random tail is what makes two approvals of the same alias distinct.
        """
        suffix = uuid.uuid4().hex[:8]
        stem = f"inmem-{name}"
        if version:
            stem = f"{stem}-v{version}"
        return f"{stem}-{suffix}"

    def put_record(self, record: dict, parameters: dict) -> dict:
        name = record["name"]
        record.setdefault("state", "APPROVED")
        # Always minted — never `setdefault` on a caller-supplied value and never
        # derived from the name alone. A stable id here is the defect this fixes.
        record["recordId"] = self.mint_record_id(name, str(record.get("version", "")))
        record.setdefault("approvalId", uuid.uuid4().hex)
        self._records[name] = record
        return record

    def search(self, query: str, filters: dict, parameters: dict) -> list[dict]:
        results = []
        q = (query or "").lower()
        rt = (filters or {}).get("recordType")
        for r in self._records.values():
            if r.get("state") != "APPROVED":
                continue
            if rt and r.get("recordType") != rt:
                continue
            if q and q not in r.get("name", "").lower():
                continue
            results.append(r)
        return results

    def deprecate(self, name: str, parameters: dict) -> None:
        if name in self._records:
            self._records[name]["state"] = "DEPRECATED"

    def annotate(self, name: str, metadata: dict, parameters: dict) -> None:
        """Merge metadata WITHOUT touching lifecycle state.

        Required by the Protocol and called on the a design note dispatch path by
        `AssetOperator._project_pause_to_registry`: pause is reversible, so it is
        recorded as metadata rather than as a state transition (DEPRECATED is
        terminal in the AgentCore Registry — F71). A record annotated as paused
        must therefore still be APPROVED and still be discoverable by search.
        No-op when the record does not exist.
        """
        record = self._records.get(name)
        if record is None:
            return
        record.setdefault("metadata", {}).update(metadata or {})

    # Test helpers (not in Protocol)
    def reset(self) -> None:
        self._records.clear()

    def all_records(self) -> list[dict]:
        return list(self._records.values())
