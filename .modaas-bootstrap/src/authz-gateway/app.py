"""authz-gateway -- the FastAPI surface the ext_authz hook calls.

One Deployment, two modules, one process (ADR-5): identity must precede
authorization because a policy decision needs a principal, and that ordering is
why they share a process rather than being two services. The shared failure
domain is a recorded cost, with attachment-phase splitting as the escape hatch.

## The request path

    ext_authz hook
      -> ShedMiddleware        refuse at capacity BEFORE the body is read
      -> deadline set ON ARRIVAL, so a queue wait counts against the budget
      -> identity.establish()  C2: parse, freshness, verification level
      -> authorize             C3: tool name + coerced args -> /decide
      -> 200 allow | 4xx refusal WITH A REASON

## Two properties that are easy to lose and load-bearing

`/healthz` touches NO dependency (SR-9/RD-3). An implementer reading
"fail-closed on every path" would reasonably add a readiness probe that checks
STS or the PDP -- and that would evict every replica on a dependency blip,
converting AR-6's deliberate DEGRADATION into a total governed-traffic stop. It
inverts the property RL-3 is built on. pdp/server.py:141-155 does the same thing
for the same reason.

Host comes from the `:authority` pseudo-header, never the `host` header, and NO
decision keys on it (SR-2a). The hook rewrites a forwarded HOST into the
authority and sets it from the caller's own Host, so the value is attacker-chosen.
"""
from __future__ import annotations

import json
import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import config
from authorize import build_decide_request, extract_tool_call
from deadline import Deadline
from identity import _Unreachable, establish_async
from reasons import Reason, Refusal
from shed import ShedMiddleware
from tracectx import TraceContext, baggage_header_value
from tracectx import resolve as resolve_trace_context

log = logging.getLogger("authz-gateway")

app = FastAPI(title="modaas-authz-gateway", docs_url=None, redoc_url=None)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Process liveness only. No STS call, no PDP call, no cache check.

    See the module docstring: a dependency-probing readiness probe would turn a
    dependency blip into a governed-traffic outage.
    """
    return {"status": "ok"}


def _account_resolver(deadline: Deadline):
    """Bind the request's deadline into the resolver establish_async expects.

    Imported lazily so identity.py's tests need no boto3 and no cachetools.

    The returned callable is a COROUTINE function. Both I/O calls on this path
    were measured blocking the event loop (~8x serialisation on 8 concurrent
    requests), which made MAX_IN_FLIGHT and STS_EXECUTOR_SIZE describe capacity
    nothing could reach -- so the async form is load-bearing, not stylistic.
    """
    import sts_lookup

    if config.VERIFICATION_MODE != "identity":
        return None                      # structural only, by configuration

    async def resolve(access_key: str):
        return await sts_lookup.resolve_async(access_key, deadline)

    return resolve


def _asset_and_policy_lenient(request: Request, model_alias: str) -> tuple[str, str]:
    """llm-shape requests carry the asset in the BODY (the model alias); the
    path is /v1/chat/completions and names no asset. Policy id follows the
    same derivation convention as _asset_and_policy's fallback."""
    asset = request.headers.get("x-modaas-asset", "") or model_alias
    policy_id = request.headers.get("x-modaas-policy-id", "") or f"model-{asset}"
    return asset, policy_id


def _asset_and_policy(request: Request) -> tuple[str, str]:
    """Resolve the governed asset and its Cedar policy id from the route.

    The hook forwards the original path, so the asset is a path segment. The
    policy id follows mcp_proxy.py's existing derivation so a CR that names its
    own policyId and one that does not behave identically here.
    """
    asset = request.headers.get("x-modaas-asset", "")
    if not asset:
        parts = [p for p in request.url.path.split("/") if p]
        # /mcp/<asset>/<rest...>
        if len(parts) >= 2 and parts[0] == "mcp":
            asset = parts[1]
    policy_id = request.headers.get(
        "x-modaas-policy-id", f"modaas-toolconfig-{asset}" if asset else ""
    )
    return asset, policy_id


# a design note point 5: the evidence service is fronted by agentgateway, so "every read
# and write crosses the authz hook". The reads are GET, and every other route here
# is POST-only -- an unmatched method on this hook is a 404 that becomes the
# CALLER's response (the W4-D finding recorded below), so an approver's read would
# fail as "not found" with no reason attached.
#
# The GET surface is deliberately only this prefix: the governed LLM and MCP paths
# are POST, and answering GET for them would decide a request shape the dataplane
# never sends.
EVIDENCE_PREFIX = "/evidence"
EVIDENCE_RESOURCE_TYPE = "Evidence"
EVIDENCE_ASSET = "evidence-service"
# A read of the audit trail and a write to it are different actions, and a
# deployment must be able to permit one without the other -- one policy id for both
# would make that inexpressible. Not derived from the path the way the MCP route
# derives its asset: that would yield `modaas-toolconfig-timeline`, which names no
# governed asset.
EVIDENCE_READ_POLICY = "modaas-evidence-read"
EVIDENCE_WRITE_POLICY = "modaas-evidence-write"


@app.get("/evidence/{rest:path}")
@app.post("/evidence/{rest:path}")
@app.post("/authz")
@app.post("/authz/{rest:path}")
@app.post("/mcp/{rest:path}")
# W4-D live finding: the agentgateway extAuth hook forwards the caller's
# ORIGINAL path, so llm-listener checks arrive at /v1/... -- a 404 here
# becomes the caller's response (DirectResponse). The check is path-shaped
# only for asset derivation; every governed prefix must land here.
@app.post("/v1/{rest:path}")
async def authorize_request(request: Request, rest: str = "") -> JSONResponse:
    """The ext_authz check. 200 allows; any 4xx refuses WITH A REASON (NFR-7).

    Verified reachable on both hook protocols: HTTP passes this response through
    as `direct_response`, and gRPC's DeniedHttpResponse carries a body.
    """
    # Set on ARRIVAL, not at call start -- so a request that queued for an
    # executor slot has that wait counted against it rather than reporting a
    # fast call after a slow wait (PR-2a).
    deadline = Deadline(config.REQUEST_BUDGET_S)

    # T2 (sprint-2026-09-ga-hardening): resolved BEFORE identity, deliberately.
    # traceId/actionId are evidence-chain plumbing, not a security boundary --
    # an unauthenticated or refused caller is exactly the case where knowing
    # WHICH request was refused matters most for a partner reconstructing an
    # incident, so this must not be short-circuited by a Refusal raised below.
    trace_ctx: TraceContext = resolve_trace_context(
        traceparent=request.headers.get("traceparent"),
        baggage=request.headers.get("baggage"),
    )
    log.info(
        "authz request received trace_id=%s action_id=%s action_id_minted=%s",
        trace_ctx.trace_id or "-", trace_ctx.action_id, trace_ctx.action_id_minted,
    )

    # a design note point 4: this service writes the decision record, and it must be
    # able to write one from whatever was resolved by the time a refusal fires.
    # Constructed BEFORE the try for that reason -- see DecisionDraft's docstring.
    import evidence_emit as _ev

    _evidence = _ev.DecisionDraft(
        correlation_id=trace_ctx.correlation_id,
        action_id=trace_ctx.action_id,
        trace_id=trace_ctx.trace_id,
    )

    try:
        # --- C2: who is this caller, and how strongly do we know? ----------
        # W4-B (a design note): three identity classes, one principal namespace.
        # Dispatch on the credential SHAPE: a three-segment Bearer is a
        # Keycloak JWT (odari); AWS4-HMAC-SHA256 is SigV4 (existing path,
        # untouched); any other Bearer is the API-key bootstrap tier -- the
        # gateway's own apiKeyAuthentication validated the key before this
        # hook ever ran, so it is door-access, not per-party identity.
        import keycloak_identity as _ki

        _authz_header = request.headers.get("authorization")
        if _ki.looks_like_jwt(_authz_header):
            try:
                identity = _ki.establish_from_jwt(_authz_header)
            except _ki.JwtRefusal as exc:
                raise Refusal(Reason.SIGV4_UNKNOWN_PRINCIPAL, f"jwt: {exc}")
            except _ki.JwksUnavailable as exc:
                # Keycloak down is NOT the caller's fault -- but FailClosed
                # means we refuse rather than guess (AR-6 discipline).
                raise Refusal(Reason.SIGV4_UNKNOWN_PRINCIPAL, f"idp-unavailable: {exc}")
            except Refusal:
                raise
            except Exception as exc:  # noqa: BLE001 -- W4-D live finding:
                # a missing crypto dependency raised AttributeError straight
                # through to a raw 500. ANY identity-path failure refuses.
                log.error("jwt identity path failed unexpectedly: %s: %s",
                          type(exc).__name__, exc)
                raise Refusal(Reason.SIGV4_UNKNOWN_PRINCIPAL,
                              f"identity-error: {type(exc).__name__}")
        elif _authz_header and _authz_header.startswith("Bearer "):
            # W4-D: the doorman VALIDATES the key itself (agw's key policy
            # retired from the llm section -- it consumed the Authorization
            # header before this hook ever saw it).
            try:
                identity = _ki.establish_from_api_key(_authz_header)
            except _ki.JwtRefusal as exc:
                raise Refusal(Reason.SIGV4_UNKNOWN_PRINCIPAL, f"api-key: {exc}")
            except _ki.JwksUnavailable as exc:
                raise Refusal(Reason.SIGV4_UNKNOWN_PRINCIPAL, f"key-store-unavailable: {exc}")
        else:
            identity = await establish_async(
                authorization=_authz_header,
                amz_date=request.headers.get("x-amz-date"),
                account_resolver=_account_resolver(deadline),
            )

        # The ATTESTED half of the record (a design note point 4): `principal` is what
        # the platform established, not the `actor` the caller named itself.
        _evidence.principal = identity.principal_id

        # --- C3: what are they asking to do, and does policy allow it? -----
        #
        # The body is parsed on its PRESENCE, never on a content-type header.
        # Gating on content-type was a real defect caught in review: without that
        # header the tool name and arguments silently vanished from the decision
        # and the call still returned 200 ALLOW -- a governed-looking call decided
        # on less than the caller sent, which is the exact failure this unit
        # exists to eliminate. Two reasons it was unsafe:
        #
        #   1. content-type is caller-supplied. Omitting it must never widen what
        #      is permitted, and here it did.
        #   2. It is not in the hook's allowedRequestHeaders list -- and that list
        #      REPLACES the default rather than adding to it -- so on the real
        #      dataplane the header would not arrive at all and every governed
        #      call would be decided without its arguments.
        import asset_attributes as _aa

        if request.url.path.startswith(EVIDENCE_PREFIX):
            # a design note point 5's fronted evidence service. Distinct from every other
            # route here in three ways, each of which would be a defect if it were
            # handled the same way:
            #
            #   * The BODY is not a tool call. A participant's `POST /records`
            #     carries an evidence record, and running it through
            #     extract_tool_call would refuse every write as MalformedToolCall.
            #   * `Evidence` is not a governed asset CRD, so there is no CR to
            #     read. Looking one up would be a 404 per read at best, and an
            #     AssetStoreUnavailable refusal of every approver read on a
            #     cluster where the ToolConfig RBAC is tight.
            #   * READ and WRITE are separate actions with separate policy ids, so
            #     a deployment can permit an approver to read the trail without
            #     permitting them to append to it.
            tool_name, arguments = None, {}
            asset = EVIDENCE_ASSET
            policy_id = (
                EVIDENCE_READ_POLICY if request.method == "GET"
                else EVIDENCE_WRITE_POLICY
            )
            _resource_type = EVIDENCE_RESOURCE_TYPE
            _data_class = ""
            _registry_record_id = ""
        else:
            # --- C3: what are they asking to do, and does policy allow it? -----
            #
            # The body is parsed on its PRESENCE, never on a content-type header.
            # Gating on content-type was a real defect caught in review: without
            # that header the tool name and arguments silently vanished from the
            # decision and the call still returned 200 ALLOW -- a governed-looking
            # call decided on less than the caller sent, which is the exact
            # failure this unit exists to eliminate. Two reasons it was unsafe:
            #
            #   1. content-type is caller-supplied. Omitting it must never widen
            #      what is permitted, and here it did.
            #   2. It is not in the hook's allowedRequestHeaders list -- and that
            #      list REPLACES the default rather than adding to it -- so on the
            #      real dataplane the header would not arrive at all and every
            #      governed call would be decided without its arguments.
            raw = await request.body()
            body: dict = {}
            if raw:
                try:
                    body = json.loads(raw)
                except ValueError:
                    raise Refusal(Reason.MALFORMED_TOOL_CALL, "body is not valid JSON")
                if not isinstance(body, dict):
                    raise Refusal(
                        Reason.MALFORMED_TOOL_CALL, "body is not a JSON object"
                    )

            # W4-B: the llm listener forwards OpenAI-shape bodies ({"model":
            # <alias>, "messages": [...]}). That is a governed MODEL invocation:
            # asset = the alias, no tool call. Only bodies carrying an MCP
            # "method" go through the tool-call extractor; anything else that
            # names neither shape keeps the existing malformed refusal.
            _cross_tool = False
            if body and "model" in body and "method" not in body:
                tool_name, arguments = None, {}
                asset = str(body["model"])
                if not asset:
                    raise Refusal(Reason.MALFORMED_TOOL_CALL, "empty model alias")
                _hdr_asset, policy_id = _asset_and_policy_lenient(request, asset)
                _resource_type = "Model"
            else:
                tool_name, arguments = extract_tool_call(body) if body else (None, {})
                asset, policy_id = _asset_and_policy(request)
                _resource_type = "Tool"
                # AR-11 (see authz-gateway/README.md): the policy evaluated is
                # the CALLED tool's, NOT the route's. MoDaaS fronts one shared
                # AgentCore Gateway, and the Gateway exposes EVERY target on
                # EVERY /mcp/<route> listener. So a tools/call arriving on
                # /mcp/<route-alias> can name a tool that belongs to a DIFFERENT
                # ToolConfig, and deriving asset+policy from the route alone made
                # a route whose policy has no toolName clause a door to every
                # tool on the gateway -- while crediting the call to the wrong
                # asset in evidence. The wire tool name is "<target>___<tool>"
                # and <target> is the called ToolConfig's alias; the route only
                # selects the listener, the called tool selects the policy, the
                # facts and the asset identity.
                if tool_name and "___" in tool_name:
                    called_alias = tool_name.split("___", 1)[0]
                    if called_alias and called_alias != asset:
                        expected_policy = f"modaas-toolconfig-{called_alias}"
                        override = request.headers.get("x-modaas-policy-id")
                        if override and override != expected_policy:
                            # An override may name a CR's own policyId, but it
                            # must NOT point at a different tool's policy than
                            # the one being called -- that re-opens the bypass
                            # through the header instead of the route.
                            raise Refusal(
                                Reason.MALFORMED_TOOL_CALL,
                                f"x-modaas-policy-id {override!r} does not name "
                                f"the called tool {called_alias!r}",
                            )
                        _evidence.route_alias = asset
                        asset = called_alias
                        policy_id = expected_policy
                        _cross_tool = True

            # D4: the resource's classification is read from the governed CR, NOT
            # from a request header. `x-modaas-data-class` used to decide this --
            # a caller-supplied attribute deciding that caller's authorization.
            # An unreadable CR store refuses (same stance as an unreadable key
            # store); a CR that declares no classification yields "" and the
            # attribute is simply omitted from the decide.
            try:
                # One read, two facts (a design note point 4): the classification the
                # decide needs and the Registry record id the decision record
                # needs. `asset_facts` shares the GET with `data_classification`,
                # so the audit field costs no extra API call on the hot path.
                _facts = _aa.asset_facts(_resource_type, asset)
            except _aa.AssetStoreUnavailable as exc:
                raise Refusal(
                    Reason.POLICY_ENGINE_UNAVAILABLE, f"asset-store-unavailable: {exc}"
                )
            # AR-11, fail closed: a cross-tool call names a tool reachable on the
            # wire that belongs to another ToolConfig. If that ToolConfig does
            # not exist here, refuse rather than fall through to the route's
            # policy -- the same stance the handler takes for an unresolved
            # asset. Only the cross-tool path checks this, so same-tool and model
            # paths are byte-identical.
            if _cross_tool and not _facts.exists:
                raise Refusal(
                    Reason.ASSET_UNRESOLVED,
                    f"called tool {asset!r} is not a governed ToolConfig",
                )
            _data_class = _facts.data_classification
            _registry_record_id = _facts.registry_record_id

        _evidence.asset_kind = _resource_type
        _evidence.asset_alias = asset
        _evidence.registry_record_id = _registry_record_id
        _evidence.policy_id = policy_id

        decide_request = build_decide_request(
            identity=identity,
            asset_name=asset,
            policy_id=policy_id,
            tool_name=tool_name,
            arguments=arguments,
            data_classification=_data_class,
            trace_id=trace_ctx.trace_id,
            action_id=trace_ctx.action_id,
            # W4-D: llm-shape bodies are governed MODEL invocations; the
            # resource entity type must match the projected permits
            # (Model::"<alias>"), or every decide would silently DENY.
            resource_type=_resource_type,
        )

        import pdp_client

        # T2: the SAME actionId this service established rides onward in
        # `baggage` so the PDP's decision log line joins to this request,
        # rather than the PDP having no evidence-chain key of its own.
        outbound_baggage = baggage_header_value(
            trace_ctx.action_id, existing_baggage=request.headers.get("baggage")
        )
        verdict = await pdp_client.decide_async(
            decide_request, deadline, baggage=outbound_baggage
        )

    except _Unreachable as exc:
        # AR-6 degradation escaping C2 means the lookup could not answer AND the
        # request could not proceed -- fail closed rather than guess.
        log.warning(
            "identity unresolvable: %s trace_id=%s action_id=%s",
            exc, trace_ctx.trace_id or "-", trace_ctx.action_id,
        )
        return _refuse(
            Refusal(Reason.SIGV4_UNKNOWN_PRINCIPAL, str(exc)), deadline, trace_ctx,
            _evidence,
        )
    except Refusal as exc:
        return _refuse(exc, deadline, trace_ctx, _evidence)

    # MD-1's span attributes ride on the response headers so the hook and any
    # trace of it carry them. NOTE (MD-0): the cluster's OTel collector exports
    # only to `debug` and no trace store exists, so these are emitted correctly
    # into a void until a backend lands. Worth emitting anyway -- it is the cheap
    # half, and it makes a backend useful on day one.
    #
    # x-modaas-action-id (T2): always present, minted or echoed. x-modaas-
    # trace-id (T2): present only when the caller sent a traceparent -- never
    # fabricated, per tracectx.py's module docstring.
    log.info(
        "authz request allowed trace_id=%s action_id=%s policy_id=%s",
        trace_ctx.trace_id or "-", trace_ctx.action_id, verdict.get("policyId"),
    )
    # a design note point 4, AFTER the PDP has answered: the record carries the verdict,
    # so it cannot be written before there is one. Wrapped because app.py must
    # not DEPEND on the emitter not raising -- a future defect there must not be
    # able to turn a governed ALLOW into a 500 (a design note point 6).
    _emit_decision_safely(_evidence.record_allow, verdict)

    response_headers = {
        "x-modaas-verification": identity.verification.value,
        "x-modaas-degraded": str(identity.degraded).lower(),
        "x-modaas-elapsed-ms": f"{deadline.elapsed() * 1000:.0f}",
        "x-modaas-action-id": trace_ctx.action_id,
        # a design note point 5: the attested identity, forwarded to the BACKEND by the
        # hook's `allowedResponseHeaders` (see hook_contract.
        # BACKEND_IDENTITY_HEADERS). evidence-service takes the caller's principal
        # from this header and never from the body. Emitted ONLY on an ALLOW: a
        # refused call established no principal, and emitting one would let a
        # backend behind a misconfigured hook attribute a refused request to
        # somebody.
        "x-modaas-principal": identity.principal_id,
        # The run id, for the gateway's access-log line (hook_contract.
        # CLIENT_ECHO_HEADERS). Always non-empty: tracectx.resolve falls back to
        # the trace id, then the action id.
        "x-modaas-correlation-id": trace_ctx.correlation_id,
    }
    if trace_ctx.trace_id:
        response_headers["x-modaas-trace-id"] = trace_ctx.trace_id
    return JSONResponse(
        {"decision": "ALLOW", "policyId": verdict.get("policyId")},
        status_code=200,
        headers=response_headers,
    )


def _emit_decision_safely(writer, verdict_or_reason, *rest) -> None:
    """Write a decision record without letting it change the response.

    The emitter is already written not to raise (`evidence_emit.emit_decision`
    catches its own construction failures). This wrapper means `app.py` does not
    DEPEND on that: a design note point 6 makes "a sink outage does not stop governed
    traffic" a property of the enforcement path, and a property that holds only
    because another module currently behaves is not one.
    """
    try:
        writer(verdict_or_reason, *rest)
    except Exception as exc:  # noqa: BLE001 -- evidence must never fail a call
        log.error("evidence emission failed: %s: %s", type(exc).__name__, exc)


def _refuse(
    exc: Refusal, deadline: Deadline, trace_ctx: TraceContext,
    evidence: "object | None" = None,
) -> JSONResponse:
    """Every refusal carries an actionable reason (NFR-7). A refusal without one
    converts a silent failure into an opaque one.

    `trace_ctx` (T2): a refused call is still joinable -- the caller's
    traceparent (if any) and the actionId this service established both ride
    on the refusal, the same as on an ALLOW, so the evidence chain does not go
    dark on the failure path.

    `evidence` (a design note point 4): the refusal is recorded too. A fail-closed
    outage that produced refusals and no records would look to an auditor
    exactly like no traffic, which is the one reading that must not be possible.
    `exc.verdict` is present only when the PDP answered, so a refusal at identity
    records DENY with a reason and claims no policy."""
    log.info(
        "refused: %s trace_id=%s action_id=%s",
        exc, trace_ctx.trace_id or "-", trace_ctx.action_id,
    )
    if evidence is not None:
        _emit_decision_safely(evidence.record_deny, exc.reason.value, exc.verdict)
    headers = {
        "x-modaas-reason": exc.reason.value,
        "x-modaas-elapsed-ms": f"{deadline.elapsed() * 1000:.0f}",
        "x-modaas-action-id": trace_ctx.action_id,
        "x-modaas-correlation-id": trace_ctx.correlation_id,
    }
    if trace_ctx.trace_id:
        headers["x-modaas-trace-id"] = trace_ctx.trace_id
    return JSONResponse(exc.body(), status_code=exc.status, headers=headers)


# Shed BEFORE the body is read. Wrapped last so it is outermost.
app.add_middleware(ShedMiddleware)
