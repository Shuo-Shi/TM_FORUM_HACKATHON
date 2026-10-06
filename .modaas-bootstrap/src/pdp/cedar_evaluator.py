"""Cedar policy evaluator wrapper for the in-cluster PDP.

a design note §"Pluggability" mandates Cedar as the v1 engine. We use the cedarpy
PyPI package (Python bindings around the Rust Cedar engine) so policy
evaluation is in-process — microsecond latency, no shell-out, no sidecar.

cedarpy version pinned in requirements.txt (4.x).

Authoritative API per `inspect.signature(cedarpy.is_authorized)`:

    is_authorized(request: dict, policies: str,
                  entities: str | List[dict],
                  schema: str | dict | None = None,
                  verbose: bool = False) -> AuthzResult

Where AuthzResult exposes:
    .decision  → cedarpy.Decision enum (Allow / Deny / NoDecision)
    .diagnostics.reasons → list[str] of matched policy IDs
    .diagnostics.errors  → list[str] of evaluation/parse errors

Cedar's default-deny semantics (per the language spec) means: if no
`permit` matches, the decision is Deny even with zero `forbid` policies.
This matches a design note's fail-closed posture explicitly:

    "PDP always boots with last-known-good policy snapshot. If startup
     fails ... PDP returns DENY for every decision until an operator
     reconcile lands valid policy. Never default-allow."
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any, Optional

import cedarpy

log = logging.getLogger("modaas-pdp.cedar")


@dataclass(frozen=True)
class EvalResult:
    """Result of evaluating one /decide request against one policy set."""

    decision: str  # "ALLOW" or "DENY"
    matched_policy: Optional[str]  # cedar policy ID (e.g. "policy1") if any
    reason: Optional[str]  # human-readable detail (esp. for DENY/errors)
    errors: list[str]  # parse / eval errors from cedar


class PolicyParseError(ValueError):
    """Raised when a Cedar policy text fails to parse during load."""


class CedarEvaluator:
    """Thread-safe holder of the current Cedar policy text per policyId.

    Hot-reload semantics (a design note §Failure Mode Invariants):
        "ConfigMap update → PDP attempts hot-reload. On parse failure,
         PDP keeps serving last-good policy AND emits a metric/span/log
         so operators see the failed reload. Never serve a half-loaded
         policy."

    The watcher calls .load_policy(policy_id, text) on add/update; failed
    parses raise PolicyParseError and the previous text remains active.
    """

    def __init__(self) -> None:
        # policyId -> (policy_text, version_tag)
        # version_tag is the ConfigMap resourceVersion (string) so the
        # watcher can prove a successful reload at a given generation.
        self._policies: dict[str, tuple[str, str]] = {}
        self._lock = threading.RLock()

    # --- policy lifecycle -------------------------------------------------

    def load_policy(self, policy_id: str, text: str, version: str = "") -> None:
        """Validate and install Cedar policy text for `policy_id`.

        Raises PolicyParseError on invalid Cedar syntax. On success, the
        policy is atomically swapped under the per-evaluator lock.

        We do not use cedarpy.validate_policies() because that requires
        a schema argument; for v1 the parse check is sufficient.
        """
        if not isinstance(text, str) or not text.strip():
            raise PolicyParseError(f"policy_id={policy_id} has empty policy text")

        # cedarpy.format_policies parses + reformats; if it raises, syntax is bad.
        try:
            cedarpy.format_policies(text)
        except Exception as exc:  # cedarpy raises a generic exception class
            raise PolicyParseError(
                f"policy_id={policy_id} failed Cedar parse: {exc}"
            ) from exc

        with self._lock:
            self._policies[policy_id] = (text, version)
        log.info(
            "loaded policy policy_id=%s version=%s bytes=%d",
            policy_id, version or "(none)", len(text),
        )

    def remove_policy(self, policy_id: str) -> None:
        with self._lock:
            self._policies.pop(policy_id, None)
        log.info("removed policy policy_id=%s", policy_id)

    def has_policy(self, policy_id: str) -> bool:
        with self._lock:
            return policy_id in self._policies

    def get_policy(self, policy_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            entry = self._policies.get(policy_id)
            if entry is None:
                return None
            text, version = entry
            return {
                "policyId": policy_id,
                "policyText": text,
                "policyVersion": version,
            }

    def loaded_policy_count(self) -> int:
        with self._lock:
            return len(self._policies)

    def loaded_policy_ids(self) -> list[str]:
        with self._lock:
            return sorted(self._policies.keys())

    # --- evaluation -------------------------------------------------------

    def evaluate(
        self,
        policy_id: str,
        principal: dict[str, Any],
        action: dict[str, Any],
        resource: dict[str, Any],
        context: dict[str, Any],
    ) -> EvalResult:
        """Evaluate one /decide request.

        a design note fail-closed: if `policy_id` is not loaded, return DENY.
        Caller (server.py) is responsible for translating that to the
        a design note `engine.kind=inCluster + connection-refused == DENY` case
        with appropriate HTTP status (we return 200 + decision=DENY here;
        the absence of policy is itself an enforcement event, not an
        error).
        """
        with self._lock:
            entry = self._policies.get(policy_id)

        if entry is None:
            return EvalResult(
                decision="DENY",
                matched_policy=None,
                reason=f"policy_id={policy_id} not loaded",
                errors=[],
            )

        policy_text, policy_version = entry

        cedar_request = {
            "principal": _format_entity_uid(principal),
            "action": _format_entity_uid(action),
            "resource": _format_entity_uid(resource),
            "context": context or {},
        }

        # O4-R-A fix: build a Cedar entity store from the request so policies
        # that key on principal/resource attributes (e.g.
        # `when { resource.dataClassification == "restricted" }`) resolve the
        # attribute cleanly. Previously we passed an empty entities list, so any
        # `resource.<attr>` access raised an evaluation error → the result fell
        # into the `errors` branch and collapsed to an ERROR-deny rather than a
        # clean `forbid` match. The PEP already emits dataClassification onto
        # resource.attributes (mcp_proxy.py); server.py forwards it here. We now
        # consume it. context.* paths still work for policies that key on
        # context (e.g. the dtw-demo-agent policy) — both are now supported.
        entities = _build_entity_store(principal, action, resource)
        try:
            result = cedarpy.is_authorized(cedar_request, policy_text, entities)
        except Exception as exc:  # cedarpy may raise on malformed request shape
            log.warning(
                "cedar eval threw policy_id=%s err=%s", policy_id, exc,
            )
            return EvalResult(
                decision="DENY",
                matched_policy=None,
                reason=f"cedar evaluator error: {exc}",
                errors=[str(exc)],
            )

        decision_str = _normalize_decision(result.decision)
        matched = list(result.diagnostics.reasons or [])
        errors = list(result.diagnostics.errors or [])

        # Default-deny path (no permit matched, no forbid matched, no errors):
        # decision is Deny per Cedar semantics. Surface a stable reason.
        reason: Optional[str]
        if decision_str == "ALLOW":
            reason = None
        elif matched:
            reason = f"matched {matched[0]}"
        elif errors:
            reason = f"cedar errors: {'; '.join(errors)}"
        else:
            reason = "default-deny: no permit policy matched"

        return EvalResult(
            decision=decision_str,
            matched_policy=matched[0] if matched else None,
            reason=reason,
            errors=errors,
        )


# ---------------------------------------------------------------------------
# Helpers (module-level so tests can exercise them directly).
# ---------------------------------------------------------------------------


def _format_entity_uid(entity: dict[str, Any]) -> str:
    """Format a {type, id} principal/action/resource block as Cedar UID.

    Cedar request expects strings shaped like `Type::"id"`. Our /decide
    JSON contract uses {type: "Agent", id: "support-bot"} per a design note.
    """
    if not isinstance(entity, dict):
        raise ValueError(f"entity must be dict, got {type(entity).__name__}")
    etype = entity.get("type")
    eid = entity.get("id")
    if not etype or not isinstance(etype, str):
        raise ValueError("entity missing 'type'")
    if eid is None or not isinstance(eid, str):
        raise ValueError("entity missing 'id'")
    # Cedar UIDs allow :: in the type for namespacing; just pass through.
    return f'{etype}::"{eid}"'


def _entity_dict(entity: dict[str, Any]) -> dict[str, Any]:
    """Build one cedarpy 4.x entity-store element from a /decide block.

    cedarpy expects entities shaped:
        {"uid": {"type": <str>, "id": <str>}, "attrs": {...}, "parents": []}

    Our /decide blocks are {type, id, attributes}. `attributes` maps to cedar's
    `attrs`; a missing/None attributes block becomes {} so the entity still
    exists in the store (existence is what lets `resource.<attr>` resolve
    instead of erroring — an absent attr then evaluates to a clean policy
    non-match rather than an evaluation error)."""
    etype = entity.get("type")
    eid = entity.get("id")
    if not etype or not isinstance(etype, str):
        raise ValueError("entity missing 'type'")
    if eid is None or not isinstance(eid, str):
        raise ValueError("entity missing 'id'")
    attrs = entity.get("attributes")
    if not isinstance(attrs, dict):
        attrs = {}
    return {"uid": {"type": etype, "id": eid}, "attrs": attrs, "parents": []}


def _build_entity_store(
    principal: dict[str, Any],
    action: dict[str, Any],
    resource: dict[str, Any],
) -> list[dict[str, Any]]:
    """Assemble the cedarpy entities list for principal, action, resource.

    The action entity carries no attributes in our contract but must still be
    declared so `action == Action::"invoke"` head constraints resolve."""
    return [
        _entity_dict(principal),
        _entity_dict(action),
        _entity_dict(resource),
    ]


def _normalize_decision(d: Any) -> str:
    """Map cedarpy.Decision enum value → uppercase 'ALLOW' / 'DENY'.

    cedarpy.Decision values: Allow, Deny, NoDecision.
    NoDecision (parse/eval error) collapses to DENY per fail-closed.
    """
    name = getattr(d, "name", str(d))
    if name == "Allow":
        return "ALLOW"
    return "DENY"
