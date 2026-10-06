"""Provider-neutral rate resolution for MoDaaS cost attribution.

Design: docs/DATAPLANE-DIRECTION.md §8. Gated by loop/verify/G45.sh.

The dataplane's job is USAGE. This module's job is turning usage into money, and it deliberately runs
OUTSIDE the request path — cost adds latency to every call for a number nobody reads synchronously, and
computing it inline turns a rate-sheet change into a dataplane deployment.

Two things drive every design choice here:

1. AN ENTERPRISE DOES NOT PAY LIST PRICE. Bedrock under an EDP/PPA, Azure under an EA/MACC, GCP under
   committed-use, or a direct vendor agreement are all discounted and contract-specific. A public
   catalogue produces numbers that are confidently wrong for exactly the customers this targets, and they
   lose the moment they are reconciled against an invoice. So precedence is:
       1. enterprise rate sheet     negotiated, any vendor            AUTHORITATIVE
       2. provider billing export   what was actually billed          RECONCILIATION
       3. public catalogue          list price                        BOOTSTRAP only
   Nothing here is AWS-specific; AWS is one instantiation of each role.

2. NOT ALL COST IS PER-TOKEN. Three of four classes cannot be priced per request even in principle:
       PER_TOKEN          managed APIs                       a rate exists
       PER_ENDPOINT_HOUR  SageMaker / Azure ML / Vertex       billed whether or not it serves
       PER_NODE_HOUR      vLLM / TGI / NIM on Kubernetes      node+GPU hours, plus idle
       CAPEX              on-prem                             amortisation, out of scope
   For the last three, effective per-token cost is a POST-HOC DIVISION whose denominator only the
   dataplane knows. `effective_per_token()` implements exactly that and refuses to invent a numerator.

An unpriceable model returns NOT_PRICED. It never returns 0 — a zero silently under-reports spend, and
agentgateway's own CostLookupStatus::Missing behaviour is the precedent.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal
from enum import Enum
from typing import Optional


class CostBasis(str, Enum):
    PER_TOKEN = "perToken"
    PER_ENDPOINT_HOUR = "perEndpointHour"
    PER_NODE_HOUR = "perNodeHour"
    CAPEX = "capex"


class RateSource(str, Enum):
    """Ordered by precedence; lower value wins."""
    ENTERPRISE_RATE_SHEET = "enterpriseRateSheet"
    PROVIDER_BILLING_EXPORT = "providerBillingExport"
    PUBLIC_CATALOGUE = "publicCatalogue"


PRECEDENCE = [
    RateSource.ENTERPRISE_RATE_SHEET,
    RateSource.PROVIDER_BILLING_EXPORT,
    RateSource.PUBLIC_CATALOGUE,
]

NOT_PRICED = "not_priced"


@dataclass(frozen=True)
class Rate:
    """One resolved rate. Amounts are Decimal — float rounding on money is a defect, not a nuance."""
    basis: CostBasis
    source: RateSource
    currency: str = "USD"
    input_per_1k: Optional[Decimal] = None   # PER_TOKEN
    output_per_1k: Optional[Decimal] = None  # PER_TOKEN
    per_hour: Optional[Decimal] = None       # PER_ENDPOINT_HOUR / PER_NODE_HOUR
    effective_from: Optional[date] = None
    sheet_version: Optional[str] = None


@dataclass
class UsageRecord:
    """What the dataplane must emit. Identity fields exist so this can be JOINED to an infrastructure
    cost record — without them, self-hosted spend cannot be attributed at all."""
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    caller_identity: Optional[str] = None
    asset_alias: Optional[str] = None
    cost_center: Optional[str] = None
    endpoint_identity: Optional[str] = None
    cached_tokens: int = 0
    duration_ms: Optional[int] = None
    extra: dict = field(default_factory=dict)


@dataclass
class Attribution:
    """Result. `status` is NOT_PRICED when no rate applies — never a silent zero."""
    amount: Optional[Decimal]
    currency: Optional[str]
    source: Optional[RateSource]
    basis: Optional[CostBasis]
    status: str = "priced"
    detail: str = ""


class RateSheet:
    """An enterprise-supplied, versioned, effective-dated, provider-neutral rate table.

    Keys are (provider, model) with a '*' wildcard on model so a negotiated blanket discount can be
    expressed without enumerating every model id.
    """

    def __init__(self, source: RateSource, rates: dict, version: str = "",
                 effective_from: Optional[date] = None, currency: str = "USD"):
        self.source = source
        self.version = version
        self.effective_from = effective_from
        self.currency = currency
        self._rates = {(p.lower(), m.lower()): v for (p, m), v in rates.items()}

    def lookup(self, provider: str, model: str) -> Optional[Rate]:
        for key in ((provider.lower(), model.lower()), (provider.lower(), "*")):
            spec = self._rates.get(key)
            if not spec:
                continue
            basis = CostBasis(spec.get("basis", CostBasis.PER_TOKEN))
            dec = lambda k: Decimal(str(spec[k])) if spec.get(k) is not None else None
            return Rate(
                basis=basis, source=self.source,
                currency=spec.get("currency", self.currency),
                input_per_1k=dec("inputPer1k"), output_per_1k=dec("outputPer1k"),
                per_hour=dec("perHour"),
                effective_from=self.effective_from, sheet_version=self.version,
            )
        return None


class RateResolver:
    """Resolves a rate across sheets by documented precedence. Later-registered sheets do NOT override
    a higher-precedence source — order of registration is irrelevant, which is the point."""

    def __init__(self, sheets: Optional[list] = None):
        self._sheets = list(sheets or [])

    def register(self, sheet: RateSheet) -> None:
        self._sheets.append(sheet)

    def resolve(self, provider: str, model: str) -> Optional[Rate]:
        for src in PRECEDENCE:
            for sheet in self._sheets:
                if sheet.source is not src:
                    continue
                r = sheet.lookup(provider, model)
                if r is not None:
                    return r
        return None

    def attribute(self, usage: UsageRecord) -> Attribution:
        """Price one usage record. PER_TOKEN only — the hour-based bases are a window division and are
        handled by `effective_per_token`, because a single request has no meaningful share of an
        endpoint-hour until the window is known."""
        rate = self.resolve(usage.provider, usage.model)
        if rate is None:
            return Attribution(None, None, None, None, NOT_PRICED,
                               f"no rate for provider={usage.provider} model={usage.model}")
        if rate.basis is not CostBasis.PER_TOKEN:
            return Attribution(
                None, rate.currency, rate.source, rate.basis, NOT_PRICED,
                f"{rate.basis.value} cannot be priced per request; use effective_per_token() over a window")
        if rate.input_per_1k is None or rate.output_per_1k is None:
            return Attribution(None, rate.currency, rate.source, rate.basis, NOT_PRICED,
                               "per-token rate incomplete")
        amount = (Decimal(usage.input_tokens) / 1000 * rate.input_per_1k
                  + Decimal(usage.output_tokens) / 1000 * rate.output_per_1k)
        return Attribution(amount, rate.currency, rate.source, rate.basis, "priced",
                           f"sheet={rate.sheet_version or 'unversioned'}")


def effective_per_token(infrastructure_cost: Decimal, tokens_served: int) -> Attribution:
    """The post-hoc division for endpoint-hour and node-hour billing.

    `infrastructure_cost` comes from the provider's billing export or the cluster cost model — the
    NUMERATOR is never inferred from gateway traffic, because an idle endpoint costs money and produces
    zero dataplane events. `tokens_served` is the dataplane's usage sum, and it is the only available
    denominator.

    Zero tokens over a window with real cost is NOT free: it is unattributable, and reporting 0 would
    hide idle spend. Returns NOT_PRICED so the caller must surface it.
    """
    if tokens_served <= 0:
        return Attribution(None, None, None, None, NOT_PRICED,
                           f"cost {infrastructure_cost} over 0 tokens served — idle, not free; "
                           "attribute to the endpoint/tenant, not to a request")
    return Attribution(Decimal(infrastructure_cost) / Decimal(tokens_served), None, None, None,
                       "priced", "effective per-token over window")
