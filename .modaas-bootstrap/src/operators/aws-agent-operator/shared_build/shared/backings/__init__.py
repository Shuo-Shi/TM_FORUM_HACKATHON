"""
MoDaaS Registry Backing dispatch (a design note).

Backings implement the RegistryBacking Protocol — a minimal 3-method contract
that the asset operators call through. Each backing adapts the canonical
MoDaaS Record shape onto a specific store (AgentCore Registry, Canvas TMF639,
in-memory stub, future Backstage/Consul/etc.).

The asset operator dispatches via:
  1. resolve_registry(spec.registryRef)  →  (backing_kind, parameters_dict)
  2. get_backing(backing_kind)           →  RegistryBacking instance
  3. backing.put_record(record, parameters)
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class RegistryBacking(Protocol):
    """Minimal registry backing contract. All methods are synchronous.

    Implementations map the canonical MoDaaS record shape onto a backing
    system. The `parameters` dict is read from the Registry CR's
    spec.parameters — backing-specific config pass-through.
    """

    def put_record(self, record: dict, parameters: dict) -> dict:
        """Idempotent upsert. Returns the stored record (may gain backing-id
        fields like recordId). Raises provider-specific exceptions on
        unrecoverable failure (e.g. auth denied, schema mismatch).
        """
        ...

    def search(self, query: str, filters: dict, parameters: dict) -> list[dict]:
        """Read-only search. Returns canonical record dicts. Returns []
        on failure (fail-soft)."""
        ...

    def deprecate(self, name: str, parameters: dict) -> None:
        """Terminal transition. No-op if record doesn't exist. Raises
        on unrecoverable failure."""
        ...

    def annotate(self, name: str, metadata: dict, parameters: dict) -> None:
        """Merge metadata into a record WITHOUT changing its lifecycle state.

        DEPRECATED is terminal in the AgentCore Registry (F71), so a reversible condition such as
        "paused" cannot be a status transition. No-op if the record does not exist.
        """
        ...


class UnknownBacking(Exception):
    """Raised when a Registry.spec.backing value has no registered plugin."""


class UnsupportedBackingOperation(Exception):
    """A backing cannot perform a Protocol operation, and says why.

    Distinct from AttributeError on purpose. "This backing has no honest way to
    do that" is a capability statement the caller can surface as a reason; a
    missing attribute is a code defect. Before this existed, a backing without
    `annotate` raised AttributeError inside
    `AssetOperator._project_pause_to_registry`'s best-effort try, so the operator
    reported `RegistryPauseProjected=False` with a Python error where a reason
    belongs.

    Raise this rather than returning a silent success — per Coherence Rule 19, an
    emit that claims work it did not do is worse than a visible refusal.
    """


# Lazy-initialized dispatch dict — populated by `_register_default_backings()`
# on first access. Third-party sibling operators append their own entries
# by importing this module and calling REGISTRY_BACKINGS[key] = impl.
REGISTRY_BACKINGS: dict[str, RegistryBacking] = {}


def _ensure_initialized():
    """Populate REGISTRY_BACKINGS with reference backings. Idempotent
    AND self-healing — each call adds any missing known backing, so if
    a backing's import became available after first call, it still gets
    registered.
    """
    # agentcore
    if "agentcore" not in REGISTRY_BACKINGS:
        try:
            from operators.shared.backings.agentcore import AgentCoreBacking
            REGISTRY_BACKINGS["agentcore"] = AgentCoreBacking()
        except ImportError:
            pass
    # in-memory
    if "in-memory" not in REGISTRY_BACKINGS:
        try:
            from operators.shared.backings.in_memory import InMemoryBacking
            REGISTRY_BACKINGS["in-memory"] = InMemoryBacking()
        except ImportError:
            pass
    # TMF639 as first-class backing (a design note Batch J)
    if "tmf639" not in REGISTRY_BACKINGS:
        try:
            from operators.shared.backings.tmf639 import TMF639Backing
            REGISTRY_BACKINGS["tmf639"] = TMF639Backing()
        except ImportError as e:
            # tmf639_client not available in this operator image; skip
            import logging
            logging.getLogger("modaas.backings").warning(
                f"TMF639 backing not registered (tmf639_client unavailable): {e}"
            )


def get_backing(kind: str) -> RegistryBacking:
    """Return the backing registered under `kind`, or raise UnknownBacking."""
    _ensure_initialized()
    b = REGISTRY_BACKINGS.get(kind)
    if b is None:
        raise UnknownBacking(
            f"Registry backing '{kind}' is not registered. "
            f"Known backings: {sorted(REGISTRY_BACKINGS.keys())}. "
            f"Sibling operators register additional backings by appending "
            f"to REGISTRY_BACKINGS in operators/shared/backings.py."
        )
    return b
