"""The closed refusal vocabulary for authz-gateway (LC-7).

One enum so a code is greppable across this service's denials, the CR condition,
the printer column and the Event. That one-grep property is the whole reason a
closed set is worth having.

UNRECONCILED: this set overlaps the refusal-surface unit's PascalCase set and
nothing reconciles the two yet (recorded in functional-design/business-rules.md).
Two codes here are new and exist in no reconciled vocabulary:

    PolicyEngineTimeout  -- RL-7's reasoned slow-path refusal. Without it a slow
                            PDP produces the hook's bare 403 with no reason.
    CapacityExceeded     -- SC-1a's load shed, distinguishable from a policy
                            denial because they need different operator actions.

Keeping them in one module makes that gap a single import to fix rather than a
search across seven modules.
"""
from __future__ import annotations

from enum import Enum


class Reason(str, Enum):
    """Every refusal this service can emit. `str` mixin so the value serialises
    directly into a header, a span attribute and a JSON body without a cast."""

    # --- identity (C2) -----------------------------------------------------
    NO_SIGV4_CREDENTIAL = "NoSigV4Credential"
    SIGV4_MALFORMED = "SigV4Malformed"
    SIGV4_TIMESTAMP_MISSING = "SigV4TimestampMissing"
    SIGV4_TIMESTAMP_SKEW = "SigV4TimestampSkew"
    SIGV4_SCOPE_MISMATCH = "SigV4ScopeMismatch"
    SIGV4_UNKNOWN_PRINCIPAL = "SigV4UnknownPrincipal"
    # SIGV4_IDENTITY_MODE=reject. Distinct from SIGV4_UNKNOWN_PRINCIPAL on
    # purpose: that one means STS answered NO about a key, and reusing it here
    # would send an operator to the wrong system -- in this mode the key is
    # never looked up. The refusal is about what this deployment ACCEPTS as
    # identity, not about the caller's standing with AWS.
    SIGV4_UNVERIFIED_IDENTITY_REJECTED = "SigV4UnverifiedIdentityRejected"

    # --- authorization (C3) ------------------------------------------------
    ASSET_UNRESOLVED = "AssetUnresolved"
    NO_POLICY_BOUND = "NoPolicyBound"
    MALFORMED_TOOL_CALL = "MalformedToolCall"
    POLICY_DENIED = "PolicyDenied"
    POLICY_ENGINE_UNAVAILABLE = "PolicyEngineUnavailable"
    POLICY_ENGINE_TIMEOUT = "PolicyEngineTimeout"

    # --- capacity (LC-1) ---------------------------------------------------
    CAPACITY_EXCEEDED = "CapacityExceeded"


class Refusal(Exception):
    """A refusal carrying a reason a human can act on (NFR-7).

    `detail` is optional context (a policy id, the unmapped provider). It is
    never a substitute for `reason`: a refusal whose reason is generic converts
    a silent failure into an opaque one, which is a smaller improvement than it
    looks.

    `verdict` (a design note point 4) is the PDP's own answer, when the refusal WAS one
    -- `policyId`, `policyVersion`, `matchedPolicy`. It exists because the
    decision record has to attribute a denial to the clause that produced it, and
    before this field the DENY path discarded exactly that: `pdp_client` raised
    with only a reason string, so the one decision an auditor most wants
    attributed to a policy was the one whose attribution the code threw away.

    It is NOT part of `body()`. Returning `matchedPolicy` to a denied caller
    tells them which clause to work around, which is a capability this service
    exists to deny them.
    """

    def __init__(self, reason: Reason, detail: str | None = None,
                 status: int = 403, verdict: dict | None = None) -> None:
        super().__init__(f"{reason.value}: {detail}" if detail else reason.value)
        self.reason = reason
        self.detail = detail
        self.status = status
        self.verdict = verdict

    def body(self) -> dict:
        """The JSON the caller receives. Verified reachable on both ext_authz
        protocols: HTTP passes the authz response through as direct_response,
        and gRPC's DeniedHttpResponse carries a body."""
        out: dict = {"reason": self.reason.value}
        if self.detail:
            out["detail"] = self.detail
        return out
