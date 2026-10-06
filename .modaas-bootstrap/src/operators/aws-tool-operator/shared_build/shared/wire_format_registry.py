"""wire-format-registry (U1) — provider -> wire-format -> gateway-path lookup.

Absorbs the provider/wire-format mapping content that lived as two bare
module-level dicts in `dependent_api.py`
(`PROVIDER_WIRE_FORMATS`/`WIRE_FORMAT_GATEWAY_PATH`), each read via
`.get(key, "openai-compat")` / `.get(key, "/v1/chat/completions")`. That
silent default is the exact defect FR-4 exists to close: an unmapped
provider or wire format resolved quietly to the OpenAI-compat shape instead
of surfacing as an error, which is how a Databricks asset or a
`kubernetesPod` agent could have gone ungoverned without anyone noticing.

This module keeps the two mapping tables (now `_PROVIDER_DIALECTS` and
`_DIALECT_GATEWAY_PATH`, module-private) but replaces bare dict access with
four small functions that either return a real answer or raise:

  * `is_mapped(provider)` — membership check, never raises.
  * `dialects_for(provider)` — the wire formats a provider accepts, or
    raises `UnmappedProviderError`.
  * `gateway_path_for(wire_format)` — the gateway path template for a wire
    format, or raises `UnknownWireFormatError`.
  * `mapped_providers()` — the full mapped provider set, sorted, for the
    FR-3 coverage check and for building refusal messages.

Per this unit's scope (`unit-of-work.md` U1's "Owns" line): providers,
wire formats and gateway paths only. No Kubernetes, no CRs, no HTTP — this
module has zero I/O and is fully unit-testable without a cluster. It does
not modify `dependent_api.py`, and it is not wired into any operator by
this unit; that wiring belongs to the units that consume this API
(`refusal-path`/`refusal-surface`, `endpoint-publication-fix`,
`tool-provider-claim`).
"""
from typing import Dict, List


class UnmappedProviderError(Exception):
    """Raised by `dialects_for` when a provider has no wire-format mapping.

    Carries the caller's own provider value (quoted back verbatim) and the
    full mapped-provider set, so a caller formatting a refusal message never
    needs a second call to `mapped_providers()` to name the remedy.
    """

    def __init__(self, provider: str, mapped_providers: List[str]):
        self.provider = provider
        self.mapped_providers = mapped_providers
        super().__init__(
            f"Provider '{provider}' has no wire-format mapping. "
            f"Mapped providers: {', '.join(sorted(mapped_providers))}."
        )


class UnknownWireFormatError(Exception):
    """Raised by `gateway_path_for` when a wire format has no gateway path.

    The second instance of the same never-default rule as
    `UnmappedProviderError`, applied to wire formats rather than providers.
    Carries the caller's own wire-format value (quoted back verbatim) and
    the full set of known wire formats.
    """

    def __init__(self, wire_format: str, known_wire_formats: List[str]):
        self.wire_format = wire_format
        self.known_wire_formats = known_wire_formats
        super().__init__(
            f"Wire format '{wire_format}' has no gateway path mapping. "
            f"Known wire formats: {', '.join(sorted(known_wire_formats))}."
        )


# ── Provider -> wire format(s) ──────────────────────────────────────────── #
# BR-2's provider column. 12 entries: the 11 CRD-derived provider values
# (ModelConfig 8 + ToolConfig 2 + AgentConfig 2, `custom` shared across
# ModelConfig/ToolConfig so counted once) plus the legacy, non-CRD-admitted
# `aws-agentcore` (kebab-case) key carried forward for backward compatibility
# — see BR-1's reconciliation note. `aws-bedrock` carries two dialects
# (Converse + ConverseStream), the first real instance of FR-2's
# multi-dialect case; every other provider maps to exactly one wire format.
# Dataplane cutover (owner direction 2026-09-01; docs/DATAPLANE-DIRECTION.md): the deployed dataplane
# is UPSTREAM agentgateway v1.4.1 (verified: cr.agentgateway.dev/agentgateway
# :v1.4.1 on eks-cluster-modaas). Its llm listener serves the OpenAI Chat
# Completions wire shape at /v1/chat/completions; the Bedrock-native
# /model/{alias}/converse[-stream] paths answer 404 "route not found" (probed
# live 2026-09-01 with a valid API key). Publishing a bedrock-runtime dialect
# URL that 404s violates Coherence Rule 17, so aws-bedrock/aws-sagemaker
# providers are consumed via openai-compat on this dataplane — the
# AgentgatewayModel matches the body's `model` field (the alias) and rewrites
# it to the provider modelId. The bedrock-runtime[-stream] dialects and their
# /model/... paths remain DEFINED below for the modaas agentgateway fork
# (crates/llm/src/parse/bedrock_path.rs pins them) but no provider maps to
# them until that fork is the deployed dataplane.
_PROVIDER_DIALECTS: Dict[str, List[str]] = {
    "aws-bedrock": ["openai-compat"],
    "aws-sagemaker": ["openai-compat"],
    "aws-agentcore": ["agentcore-runtime"],
    "awsAgentCore": ["agentcore-runtime"],
    "agentCoreGateway": ["agentcore-mcp"],
    "azure-openai": ["openai-compat"],
    "google-vertex": ["vertex-ai"],
    "nvidia-nim": ["openai-compat"],
    "ollama": ["openai-compat"],
    "custom": ["openai-compat"],
    "databricks": ["openai-compat"],
    "kubernetesPod": ["agentcore-mcp"],
}

# ── Wire format -> gateway path template ────────────────────────────────── #
# BR-2's path column. Addendum 1 corrects the Bedrock paths to
# `/model/{alias}/converse` and `/model/{alias}/converse-stream` (replacing
# the old `/bedrock/model/{alias}/converse`). `kubernetesPod` reuses the
# already-implemented `agentcore-mcp` path rather than a new template — no
# new gateway-side surface. `.format(alias=...)` interpolation is the
# caller's job; this module returns the raw template string.
#
# CROSS-REPO CONTRACT (U9 bedrock-inbound, agentgateway-transition): the
# `bedrock-runtime`/`bedrock-runtime-stream` path shapes below are
# independently duplicated — not imported — in the Rust dataplane's inbound
# classifier at `crates/llm/src/parse/bedrock_path.rs` (agentgateway-modaas
# fork), which hardcodes the same `/model/...` prefix and `converse`/
# `converse-stream` operation tokens. That file's own test
# `bedrock_path_shape_matches_modaas_wire_format_registry_contract` pins the
# same values from the Rust side. There is no automated cross-repo check
# beyond these two pinned literals — if either shape changes, check the
# other side too.
_DIALECT_GATEWAY_PATH: Dict[str, str] = {
    # Reserved for the modaas agentgateway fork (bedrock_path.rs contract);
    # not reachable on upstream v1.4.1 — no provider maps here today.
    "bedrock-runtime": "/model/{alias}/converse",
    "bedrock-runtime-stream": "/model/{alias}/converse-stream",
    "sagemaker-runtime": "/sagemaker/endpoints/{alias}/invocations",
    "agentcore-runtime": "/mcp/{alias}",
    "agentcore-mcp": "/mcp/{alias}",
    # Lane I (plan 1.15) / a design note point 3 — agent INVOCATION fronting. Distinct
    # from `agentcore-runtime` on purpose: that dialect's /mcp/{alias} path is
    # the MCP-shaped surface an agent exposes as a tool, whereas this is
    # InvokeAgentRuntime fronted by agentgateway's native `aws.agentCore`
    # backend (AgentgatewayBackend.spec.aws.agentCore, v1.4.1). Added here
    # rather than as a second table inside
    # `shared/agentgateway_agent_route.py`, because a duplicate provider/path
    # map is exactly the defect FR-4 closed.
    #
    # ADDITIVE ONLY: no entry in `_PROVIDER_DIALECTS` maps to this dialect yet.
    # Repointing `awsAgentCore` from `agentcore-runtime` to this value changes
    # `status.endpoint` for every already-Approved AgentConfig, so it is an
    # owner decision taken at integration (plan 1.19), not a side effect of
    # registering the path.
    "agentcore-invocations": "/agents/{alias}/invocations",
    "openai-compat": "/v1/chat/completions",
    "vertex-ai": "/v1/chat/completions",
}


def is_mapped(provider: str) -> bool:
    """Return True if `provider` has a wire-format mapping, False otherwise.

    Pure membership check — never raises. This is the predicate BR-3 says a
    caller in another unit branches on before deciding whether to call
    `dialects_for` (expect a list) or handle the unmapped case (expect a
    refusal).
    """
    return provider in _PROVIDER_DIALECTS


def dialects_for(provider: str) -> List[str]:
    """Return every wire format `provider` accepts.

    Raises `UnmappedProviderError` when `provider` is not mapped — NEVER
    returns a default. Returns a copy of the stored list; mutating the
    returned list does not corrupt this module's internal table for
    subsequent callers.
    """
    if provider not in _PROVIDER_DIALECTS:
        raise UnmappedProviderError(provider, mapped_providers())
    return list(_PROVIDER_DIALECTS[provider])


def gateway_path_for(wire_format: str) -> str:
    """Return the gateway path template for `wire_format`.

    Raises `UnknownWireFormatError` when `wire_format` is not known — NEVER
    returns a default (the second instance of the same silent-fallback
    defect FR-4 closes, this time for wire formats rather than providers).
    The returned string is a template (e.g. `/model/{alias}/converse`);
    `.format(alias=...)` interpolation is the caller's job.
    """
    if wire_format not in _DIALECT_GATEWAY_PATH:
        raise UnknownWireFormatError(wire_format, sorted(_DIALECT_GATEWAY_PATH.keys()))
    return _DIALECT_GATEWAY_PATH[wire_format]


def mapped_providers() -> List[str]:
    """Return the full mapped-provider set, sorted for deterministic output.

    Used by the FR-3 coverage check and by `UnmappedProviderError` to name
    the remedy in a refusal message.
    """
    return sorted(_PROVIDER_DIALECTS.keys())
