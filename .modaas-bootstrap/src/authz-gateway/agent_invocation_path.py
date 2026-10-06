"""a design note point 3 — derive the governed asset from the `/agents/{alias}/invocations`
perimeter path.

The doorman's third asset-derivation shape, alongside the two `app.py` already
has: the llm branch reads the asset from the request BODY (the model alias), the
mcp branch reads it from the PATH (`/mcp/<asset>/...`). Agent invocations are
path-shaped like MCP, but carry their own Cedar policy-id prefix because the
governed asset is an AgentConfig rather than a ToolConfig.

Pure string handling. No FastAPI, no PDP, no Kubernetes — the two-line wiring
into `app.py` (a `@app.post("/agents/{rest:path}")` decorator and a branch in
`_asset_and_policy`) is listed in LANE_REPORT.md §5.

Why the doorman needs this at all: the a design note ext_authz hook targets
`sectionName: http` as well as `llm`, and forwards the caller's ORIGINAL path.
`app.py` records the consequence of an unmatched path — "a 404 here becomes the
caller's response (DirectResponse) ... every governed prefix must land here." So
a fronted agent route on the `http` listener without this derivation would fail
every invocation at the doorman, and it would look like an authorization
failure.
"""
import re

# Mirrors the `agentcore-invocations` gateway path template
# `/agents/{alias}/invocations` in operators/shared/wire_format_registry.py.
# Duplicated rather than imported: the doorman image does not ship
# operators/shared. Pinned from this side by
# tests/test_agent_invocation_path.py::test_path_segment_matches_the_published_perimeter_path.
AGENT_PATH_SEGMENT = "agents"

# The Cedar policy-id shape for an AgentConfig asset. Derivation convention is
# `modaas-<kind-lower>-<name>` — operators/shared/policy_projection.py
# `derive_policy_id` — which is also where the mcp branch's
# `modaas-toolconfig-<asset>` comes from.
_POLICY_ID_PREFIX = "modaas-agentconfig-"

# A CR alias, not arbitrary caller text. Accepting anything else would put
# caller-controlled characters into the Cedar resource id, and `..` would make a
# traversal segment look like an asset name.
_ALIAS_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")


def _alias_segment(path: str):
    """The raw alias segment of `/agents/<alias>/...`, or None.

    Split WITHOUT dropping empty segments, deliberately. Filtering empties first
    (the shape `app.py::_asset_and_policy` uses for `/mcp/...`) collapses
    `/agents//invocations` to `["agents", "invocations"]` and hands back
    `invocations` as the asset — a caller-chosen path yielding a
    governed-looking asset name that is not the agent. Positional indexing on
    the raw split cannot do that.
    """
    raw = (path or "").split("/")
    if len(raw) < 4 or raw[0] != "" or raw[1] != AGENT_PATH_SEGMENT:
        return None
    return raw[2] or None


def is_agent_invocation_path(path: str) -> bool:
    """True when `path` is the agent-invocation perimeter shape.

    Requires `/agents/<non-empty alias>/<something>` — `/agents`, `/agents/` and
    `/agents//invocations` name no asset and are not this shape.
    """
    return _alias_segment(path) is not None


def asset_and_policy_for_agent_path(
    path: str,
    header_asset: str = "",
    header_policy_id: str = "",
) -> tuple:
    """Resolve `(asset, policy_id)` for an agent-invocation check.

    Header precedence matches `app.py::_asset_and_policy`: an explicit
    `x-modaas-asset` / `x-modaas-policy-id` wins over the path.

    Returns `("", "")` when the path is not an agent-invocation path, or when
    the alias segment is not a usable CR alias. A blank asset makes the PDP
    decide against an unknown resource, which refuses — the correct fail-closed
    outcome for a path this function does not own. It never guesses an asset.
    """
    asset = (header_asset or "").strip()
    if not asset:
        candidate = _alias_segment(path)
        if candidate is None or not _ALIAS_RE.match(candidate):
            return ("", "")
        asset = candidate

    policy_id = (header_policy_id or "").strip() or f"{_POLICY_ID_PREFIX}{asset}"
    return (asset, policy_id)


__all__ = [
    "AGENT_PATH_SEGMENT",
    "is_agent_invocation_path",
    "asset_and_policy_for_agent_path",
]
