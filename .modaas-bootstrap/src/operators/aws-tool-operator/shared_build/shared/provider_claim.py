"""Make an unclaimed provider VISIBLE instead of silently dropping the asset.

Each operator handles exactly one ``spec.provider`` value and previously returned bare when the
value did not match::

    if spec.get("provider") != PROVIDER:
        return          # no status, no event, no log

``spec.provider`` carries no enum on toolconfigs/agentconfigs, so the API accepts any string. The
result was that a CR with an unhandled provider was accepted by the API, ignored by the operator,
and reported by kopf as ``Creation is processed: 1 succeeded`` — the operator's own logs said
``Handler 'reconcile' succeeded`` in 7ms. A user saw a clean create and reasonably believed the
asset was governed. Nothing governed it.

That is the same failure class as the guardrail defect this project exists to remove (a control
that is present but not deciding), and it contradicts the provider-agnostic product claim.

This helper does not change WHICH providers are handled. It makes the boundary observable, so an
unhandled provider is a stated outcome rather than silence.
"""
from __future__ import annotations

from datetime import datetime, timezone

CONDITION_TYPE = "ProviderClaimed"
REASON = "UnsupportedProvider"


def mark_unclaimed(patch, status, submitted, supported) -> None:
    """Stamp a ProviderClaimed=False condition naming the submitted and supported providers.

    Only sets ``phase`` when no other controller has already set one, so this stays safe if a second
    operator legitimately claims the same kind for a different provider.
    """
    sub = str(submitted) if submitted not in (None, "") else "<unset>"
    msg = (
        f"No operator in this cluster handles spec.provider={sub!r}; "
        f"this controller handles {supported!r} only. The asset is NOT governed."
    )
    cond = {
        "type": CONDITION_TYPE,
        "status": "False",
        "reason": REASON,
        "message": msg,
        "lastTransitionTime": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    existing = [
        c for c in ((status or {}).get("conditions") or [])
        if isinstance(c, dict) and c.get("type") != CONDITION_TYPE
    ]
    patch.status["conditions"] = existing + [cond]
    if not (status or {}).get("phase"):
        # status.phase carries an enum (Pending/Reviewing/Approved/Active/Failed/Paused/Retired).
        # "Ignored" is NOT in it, and an out-of-enum value makes the API reject the whole patch —
        # which would reintroduce the silent drop this fix exists to remove (the same trap that
        # swallowed the operator's own scan_orphan_records status). "Failed" is in the enum and is
        # honest from the consumer's side: an asset no controller claims will never be governed.
        patch.status["phase"] = "Failed"
        patch.status["reason"] = REASON
