"""C3 -- translate a request plus an identity into a Cedar /decide call (LC-5).

A TRANSLATOR. It holds no policy and makes no decision; keeping it that way is
what preserves the PDP as the single policy engine.

## The fidelity this module exists for, and what the incumbent loses

`ai-gateway-pod/mcp_proxy.py:308` sends `action = {"type": "Action", "id":
"invoke"}` -- a literal -- with `context` carrying only `direction` and `path`.
No tool name and no arguments reach the PDP, so every tool on an asset is one
undifferentiated call and two callers differing only at tool level are
indistinguishable to policy.

The PDP already accepts more: `EntityRef` is `extra="allow"` with an open
`attributes` dict and `context` is an open dict. The capacity existed and was
unused. That is the whole reason this bridge exists rather than expressing tool
policy in the dataplane's own language -- and dropping the arguments would make
it pointless while still returning clean allows and denies.

## AR-10: the tool name goes in `context.toolName`, NOT `action.id`

The first draft put it in `action.id`, which would have broken a passing gate.
The live policy on `g11-authz-probe` -- the only governed asset carrying a
cedarPolicy -- pins the action in both clauses:

    permit ( principal == Agent::"g11-allowed", action == Action::"invoke", ... );
    forbid ( principal == Agent::"g11-denied",  action == Action::"invoke", ... );

Move `action.id` off `invoke` and neither clause matches: permit falls to Cedar
default-deny, forbid returns no matchedPolicy -- the string loop/verify/G11b.sh:35
asserts. `G11b` passes today.

This is NFR-4's warning one layer over: it requires a tightening rule be run
against the approved ASSET population, and nobody applied the same discipline to
the deployed POLICY corpus. Policies are live state too.

Carrying the tool in `context.toolName` costs nothing -- a policy wanting
per-tool granularity writes one more clause, and every existing policy keeps
matching.

## AR-11a: arguments must be coerced, and the naive coercion is worse

Cedar holds strings, ints, bools, lists and records. Not floats, not null. But
coercing a float to a decimal string does NOT fix it: a policy comparing
`context.arguments.temperature > 0.85` then compares a string to a number,
type-errors, the forbid does not fire, and the evaluator returns ALLOW with the
error discarded. Verified by execution -- an int argument correctly DENYs while
the coerced float silently ALLOWs.

So the coercion below is necessary and insufficient. The load-bearing fix is
AR-11c (an errored evaluation must not yield an allow), which lives in the PDP;
pdp_client.py refuses on a non-empty `errors` list the moment the PDP surfaces
one. Until then FR-8's per-argument criterion is not satisfiable, and that is a
scope statement rather than a caveat.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from identity import Identity
from reasons import Reason, Refusal

log = logging.getLogger("authz-gateway.authorize")

# Cedar's action stays `invoke`. See AR-10 above -- this constant is load-bearing
# and changing it breaks every policy that pins the action.
_ACTION_ID = "invoke"

_MCP_CALL = "tools/call"
_MCP_LIST = "tools/list"
# Streamable-HTTP MCP session lifecycle (spec 2024-11-05 / 2025-03-26). A client
# MUST send initialize, then the initialized notification, before tools/call;
# ping may arrive at any time. None of these names a tool. Until a hardening note (2026-09-20)
# promoted the identity hook onto the MCP listener, they were refused as
# MALFORMED_TOOL_CALL -- so the handshake itself was a 403 and no client could
# ever reach a tool through the doorman. They take the tool-less path tools/list
# takes: authenticated, decided by Cedar with toolName absent, never a bypass.
_MCP_SESSION = frozenset({"initialize", "notifications/initialized", "ping"})


def coerce_for_cedar(value: Any) -> Any:
    """Make a JSON value Cedar-representable.

    Cedar has no float and no null. An unrepresentable value makes the whole
    request fail to parse, which the evaluator collapses to DENY with a reason
    blaming itself -- so `{"temperature": 0.7}`, an ordinary Bedrock argument,
    would become an opaque refusal of a legitimate call.

    - float           -> its decimal STRING form, so the value survives for
                         equality and `like` (but NOT for numeric comparison --
                         see AR-11a in the module docstring)
    - None            -> dropped by the caller (a key with no value is omitted)
    - int/str/bool    -> unchanged
    - list/dict       -> recursed
    - anything else   -> str(), so an unexpected type degrades to a comparable
                         value rather than breaking the whole decision
    """
    if isinstance(value, bool):
        return value                      # before int: bool is an int subclass
    if isinstance(value, int):
        # Cedar's long is 64-bit; a larger value overflows rather than truncating.
        if -(2**63) <= value < 2**63:
            return value
        return str(value)
    if isinstance(value, float):
        return repr(value)                # 0.7 -> "0.7"
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        # Null-valued keys are OMITTED, which is why a policy forbidding on an
        # argument must guard with `has` (AR-11b) -- an absent key errors the
        # clause and it silently does not fire.
        return {k: coerce_for_cedar(v) for k, v in value.items() if v is not None}
    if isinstance(value, (list, tuple)):
        return [coerce_for_cedar(v) for v in value if v is not None]
    if value is None:
        return None
    return str(value)


def extract_tool_call(body: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
    """Pull the tool name and arguments out of the JSON-RPC body.

    In MCP, `tools/call` is the METHOD; the tool name and its arguments live in
    `params`. Nothing reads a tool name from the URL path because it is not
    there -- which is why the request body must be forwarded at all.
    """
    if not isinstance(body, dict):
        raise Refusal(Reason.MALFORMED_TOOL_CALL, "body is not a JSON object")

    method = body.get("method")
    if method == _MCP_LIST or method in _MCP_SESSION:
        # A discovery or session-lifecycle call has no single tool. FR-8 covers
        # per-caller discovery filtering, so this still needs a decision -- with
        # toolName absent.
        return None, {}

    if method == _MCP_CALL:
        params = body.get("params")
        if not isinstance(params, dict):
            raise Refusal(Reason.MALFORMED_TOOL_CALL, "tools/call without params")
        name = params.get("name")
        if not isinstance(name, str) or not name:
            raise Refusal(Reason.MALFORMED_TOOL_CALL, "tools/call without params.name")
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            raise Refusal(Reason.MALFORMED_TOOL_CALL, "params.arguments is not an object")
        return name, args

    # An unrecognised method is not a tool call we can reason about. Fail closed.
    raise Refusal(Reason.MALFORMED_TOOL_CALL, f"unsupported method {method!r}")


_CEDAR_REF = re.compile(r'^([A-Za-z][A-Za-z0-9]*)::"([^"]+)"$')


def build_decide_request(
    identity: Identity,
    asset_name: str,
    policy_id: str,
    tool_name: str | None,
    arguments: dict[str, Any],
    data_classification: str = "",
    method: str = _MCP_CALL,
    trace_id: str | None = None,
    action_id: str | None = None,
    resource_type: str = "Tool",
) -> dict[str, Any]:
    """The mapping. This is the unit's most consequential logic, because the
    current implementation loses here.

    `trace_id` / `action_id` (T2, sprint-2026-09-ga-hardening): the evidence-
    chain identifiers resolved by tracectx.py. They ride in `context` — the
    PDP's `DecideRequest.context` is an open dict (pdp/server.py) precisely so
    a caller can extend the decision's inputs without a wire-schema change —
    rather than as new top-level fields on this request, so a caller who sent
    neither (both None, the default) produces byte-identical output to before
    this parameter existed."""
    if not asset_name:
        raise Refusal(Reason.ASSET_UNRESOLVED, "no governed asset for this route")
    if not policy_id:
        # AR-9: absence of policy is not permission. Allowing here would make
        # forgetting to attach a policy indistinguishable from deliberately
        # allowing everything.
        raise Refusal(Reason.NO_POLICY_BOUND, f"no Cedar policy bound to {asset_name}")

    principal_attrs: dict[str, Any] = {
        # SR-1: the trust boundary as a first-class, policy-requirable attribute
        # rather than a docstring. A policy can demand account-resolved for a
        # sensitive tool, which is strictly more than the incumbent offers.
        "verification": identity.verification.value,
        "degraded": identity.degraded,
        "roles": [],
    }
    if identity.account:
        principal_attrs["account"] = identity.account

    context: dict[str, Any] = {
        "toolMethod": method,
        # AR-6's degradation, visible to policy: a caller attested only
        # structurally because STS was unreachable can be refused by a policy
        # that cares, and allowed by one that does not.
        "degraded": identity.degraded,
    }
    if tool_name is not None:
        context["toolName"] = tool_name          # AR-10: NOT action.id
    if arguments:
        context["arguments"] = coerce_for_cedar(arguments)   # AR-11a
    if data_classification:
        context["dataClassification"] = data_classification
    if trace_id:
        context["traceId"] = trace_id
    if action_id:
        context["actionId"] = action_id

    resource_attrs: dict[str, Any] = {}
    if data_classification:
        resource_attrs["dataClassification"] = data_classification

    return {
        "policyId": policy_id,
        # W4-D alignment: W4-B identities carry a full Cedar entity ref
        # (ServiceIdentity::"azp"); the wire wants type/id split -- sending
        # type=Agent with a ref-shaped id would never match any permit.
        # SigV4's "aws:<key>" keeps the legacy Agent type (regression-pinned).
        "principal": (
            {"type": _m.group(1), "id": _m.group(2), "attributes": principal_attrs}
            if (_m := _CEDAR_REF.match(identity.principal_id))
            else {"type": "Agent", "id": identity.principal_id, "attributes": principal_attrs}
        ),
        "action": {"type": "Action", "id": _ACTION_ID},   # pinned -- see AR-10
        "resource": {"type": resource_type, "id": asset_name, "attributes": resource_attrs},
        "context": context,
    }
