"""U10 (usage-and-cost): the first runtime importer of `rate_resolver.py`.

Joins a `ModelConfig`'s CR-declared `spec.costBasis` (hour/node/capex bases —
the three FR-6 names that agentgateway's own native cost catalog structurally
cannot represent; see `docs/design` / this unit's functional-design for the
verified reason) against a usage window to produce a named-source
`Attribution`, never a silent zero.

Deliberately does NOT: call any AWS API (no Cost Explorer, no CUR — no
billing-source client exists anywhere in this repo yet), schedule itself (no
cron, no operator timer), or write its result anywhere. A future caller owns
all three.
"""
from __future__ import annotations

from decimal import Decimal

try:
    from operators.shared.rate_resolver import (
        NOT_PRICED,
        Attribution,
        RateResolver,
        RateSheet,
        RateSource,
        effective_per_token,
    )
except ImportError:  # pragma: no cover - deployed snapshot path
    from rate_resolver import (
        NOT_PRICED,
        Attribution,
        RateResolver,
        RateSheet,
        RateSource,
        effective_per_token,
    )

_HOUR_CAPEX_BASES = ("perEndpointHour", "perNodeHour", "capex")


def build_enterprise_rate_sheet(model_configs: list[dict]) -> RateSheet:
    """One RateSheet from every ModelConfig CR carrying spec.costBasis with
    basis in {perEndpointHour, perNodeHour, capex}.

    Skips perToken entries entirely — a per-token CR-declared override has
    no CRD field to carry it (`crds/modelconfig-v1beta1-crd.yaml`'s
    `costBasis.rate` has no per-token sub-field), so there is nothing to
    read for that basis here regardless.

    A CR-declared rate maps onto `RateSource.ENTERPRISE_RATE_SHEET` — the
    closest existing tier (owner decision) — rather than a new RateSource
    value.
    """
    rates: dict[tuple[str, str], dict] = {}
    for mc in model_configs:
        spec = mc.get("spec") or {}
        cost_basis = spec.get("costBasis")
        if not cost_basis or cost_basis.get("basis") not in _HOUR_CAPEX_BASES:
            continue
        provider = spec.get("provider")
        model_id = spec.get("modelId")
        if not provider or not model_id:
            continue
        rate = cost_basis.get("rate") or {}
        per_hour = rate.get("perHour") or rate.get("capexAmortizedPerHour")
        if per_hour is None:
            # CEL requires one of these when basis is perEndpointHour/perNodeHour/
            # capex — defensive, not load-bearing.
            continue
        rates[(provider, model_id)] = {
            "basis": cost_basis["basis"],
            "perHour": per_hour,
            "currency": rate.get("currency", "USD"),
        }
    return RateSheet(RateSource.ENTERPRISE_RATE_SHEET, rates)


def attribute_hour_billed_asset(
    sheet: RateSheet,
    provider: str,
    model_id: str,
    tokens_served_in_window: int,
    hours_in_window: Decimal,
) -> Attribution:
    """Price one attribution window for an hour/node/capex-billed asset.

    `hours_in_window` and `tokens_served_in_window` are caller-supplied — the
    scheduling mechanism that computes them (and how often this function is
    called) is owned by whoever calls it, not this module.
    """
    resolver = RateResolver([sheet])
    rate = resolver.resolve(provider, model_id)
    if rate is None:
        return Attribution(
            None, None, None, None, NOT_PRICED,
            f"no declared or billing-sourced rate for {provider}/{model_id}",
        )
    infra_cost = rate.per_hour * hours_in_window
    attr = effective_per_token(infra_cost, tokens_served_in_window)
    # effective_per_token() is a pure post-hoc division with no Rate object to
    # name — its success branch leaves currency/source/basis as None. THIS
    # caller holds the resolved Rate, so it must patch the (mutable) result
    # before returning; reusing it unmodified would violate the requirement
    # that a priced Attribution always names its RateSource.
    if attr.status == "priced":
        attr.source = rate.source
        attr.basis = rate.basis
        attr.currency = rate.currency
    return attr
