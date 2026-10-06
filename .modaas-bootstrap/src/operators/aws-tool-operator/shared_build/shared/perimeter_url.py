"""a design note / a design note — Perimeter URL writer.

Single source of truth for publishing the MoDaaS Gateway perimeter URL into
ModelConfig / ToolConfig / AgentConfig status. Per CLAUDE.md coherence rule
13, ``status.endpoint`` is the governance perimeter URL agents MUST call —
never the upstream provider URL.

Why this lives in shared/:
  Phase-3 ``approve_*`` paths in all three operators must publish identical
  shape into status (``endpoint``, ``globalResourceEndpoint``, ``endpointScope``,
  ``endpoints``). Originally only ``aws-model-operator`` wrote the canonical
  ``status["endpoint"]`` via a local ``_perimeter_url`` block (see
  ``model_operator.py`` Phase-3 Approved branch). Tool + Agent operators
  wrote ``globalResourceEndpoint`` and ``endpointScope`` but left
  ``status["endpoint"]`` empty — leaving 12/14 governed assets with
  ``scope=public`` but ``endpoint=`` blank. Live witness 2026-05-27.

Contract:
  - Compute mesh/vpc/public URLs via ``compute_all_endpoints``.
  - Pick the broadest reachable scope via ``pick_best_endpoint``.
  - Fall back to the supplied ``fallback_url`` (typically the wire-format
    cluster.local URL) only when no public/vpc/mesh scope was resolved.
  - Write to ``patch.status``: ``endpoint``, ``globalResourceEndpoint``,
    ``endpointScope``, ``endpoints``.

The helper deliberately does NOT touch ``upstreamEndpoint`` — that's
provider-specific (raw Bedrock URL, Gateway MCP URL, AgentCore Runtime ARN)
and remains the caller's responsibility per coherence rule 13.

endpoint-publication-fix (U3, BR-2): the helper gains an optional
``all_wire_formats`` parameter. When supplied, in addition to its existing
behavior for the single, primary ``wire_format``, it also resolves +
picks-best for every entry in ``all_wire_formats`` and writes
``status_patch["dialectEndpoints"]`` — a per-dialect governed endpoint map
(FR-2's per-dialect discovery surface). When omitted (existing callers),
behavior is unchanged byte-for-byte and ``dialectEndpoints`` is not written
at all (not written as an empty dict).

W4-A (sprint-2026-09-ga-hardening.md, requirement #42): the PUBLIC-scope
scheme and port are now overridable via ``MODAAS_PERIMETER_SCHEME``
(default ``"http"``) and ``MODAAS_PERIMETER_PORT`` (default: unset, keeps
the existing per-wire-format port map). The override lives in
``dependent_api.compute_all_endpoints`` — this module is a thin caller and
has no scheme/port logic of its own — but is documented here because
callers of ``compute_and_publish_perimeter_url`` are the ones who observe
the effect. Default behavior (both vars unset) is byte-for-byte identical
to pre-W4-A. Flipping ``MODAAS_PERIMETER_SCHEME=https`` is a live-cluster
decision (W4-D, coordinator only, strictly after the TLS listener is
verified answering — Coherence Rule 17: never publish an unreachable
scheme). Mesh scope is never affected by this override; it stays http per
its own sidecar-mTLS contract.
"""

from typing import List, Optional, Tuple

try:  # pragma: no cover — import path varies by deployment shape
    from shared.dependent_api import compute_all_endpoints, pick_best_endpoint
except ModuleNotFoundError:  # pragma: no cover
    from operators.shared.dependent_api import (  # type: ignore
        compute_all_endpoints,
        pick_best_endpoint,
    )


def compute_and_publish_perimeter_url(
    *,
    alias: str,
    wire_format: str,
    status_patch,
    fallback_url: Optional[str] = None,
    k8s_api=None,
    all_wire_formats: Optional[List[str]] = None,
) -> Tuple[str, str]:
    """Resolve the broadest-reachable perimeter URL and publish to status.

    Args:
        alias: asset alias (used to render the wire-format path).
        wire_format: e.g. ``bedrock-runtime`` for ModelConfig,
            ``agentcore-mcp`` for ToolConfig, ``agentcore-runtime`` (or
            ``agentcore-mcp`` if the agent is exposed via Gateway) for
            AgentConfig.
        status_patch: dict-like (``patch.status`` from kopf) — the writer
            mutates ``endpoint``, ``globalResourceEndpoint``, ``endpointScope``,
            ``endpoints`` in place.
        fallback_url: URL to publish when ``compute_all_endpoints`` returns
            no resolvable scope. Typically the per-operator
            ``cluster.local`` gateway URL with the wire-format path appended.
            If both the resolver AND fallback come back empty, the helper
            writes empty strings (CRD CEL will hard-reject the status update;
            the caller should treat that as a setup error).
        k8s_api: kubernetes CustomObjectsApi for Istio LB DNS resolution.
        all_wire_formats: every wire format this asset's provider declares
            (typically ``wire_format_registry.dialects_for(provider)``). When
            supplied, the helper additionally writes
            ``status_patch["dialectEndpoints"]`` — one entry per wire
            format, each the best-reachable URL for that dialect alone
            (recomputed independently of the primary ``wire_format``'s
            entry, even when the same wire format appears in both). When
            ``None`` (the default), ``dialectEndpoints`` is not written.

    Returns:
        ``(scope, url)`` actually published. Useful for the caller to thread
        into Registry record metadata.
    """
    eps = compute_all_endpoints(alias, wire_format, k8s_api=k8s_api)
    best_scope, best_url = pick_best_endpoint(eps)
    chosen_url = best_url or fallback_url or ""

    status_patch["endpoint"] = chosen_url
    status_patch["globalResourceEndpoint"] = chosen_url
    status_patch["endpointScope"] = best_scope
    status_patch["endpoints"] = {k: v for k, v in eps.items() if v is not None}

    if all_wire_formats is not None:
        dialect_endpoints = {}
        for wf in all_wire_formats:
            wf_eps = compute_all_endpoints(alias, wf, k8s_api=k8s_api)
            _, wf_best_url = pick_best_endpoint(wf_eps)
            dialect_endpoints[wf] = wf_best_url or fallback_url or ""
        status_patch["dialectEndpoints"] = dialect_endpoints

    return best_scope, chosen_url


__all__ = ["compute_and_publish_perimeter_url"]
