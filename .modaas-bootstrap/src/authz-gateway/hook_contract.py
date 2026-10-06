"""The contract between this service and the ext_authz hook that calls it.

## Why this is a module and not three hand-written lists

`allowedRequestHeaders` REPLACES the hook's default rather than adding to it
(`ext_authz.rs:780-784` at the pinned upstream commit is an if/else), so every
header this service reads is withheld unless a policy names it. That list is
written in `deploy/agentgateway/agentgatewaypolicy-authz-hook.yaml`, mirrored in
`loop/fixtures/G60-authz-policy.yaml`, and checked by `loop/verify/G60.sh` and
`tests/test_hook_policy_contract.py`. G60's own header comment states the hazard
it was avoiding: "a second hand-maintained list would be a third place to forget
`authorization`". It then hand-maintained one anyway, as a grep alternation of
four literal strings -- which is why `traceparent` and `baggage` could be added
to `app.py` and stay invisible to the gate.

One declaration, two consumers, and a REASON attached to every entry. The reason
is not decoration: `host` is the counter-example that looks like it belongs and
does not (see FORBIDDEN), and a bare list gives a reader no way to know that.
"""
from __future__ import annotations

# Headers the hook MUST forward, each with the reason it is load-bearing. A
# header absent here that `app.py` reads is a silent capability loss; a header
# present here that nothing reads is an unnecessary widening.
REQUIRED_REQUEST_HEADERS: dict[str, str] = {
    "authorization": (
        "identity.py parses all three identity classes out of it (app.py:154); "
        "omitting it forwards everything EXCEPT the one header C2 needs, and "
        "every request is then refused for a credential that was never sent"
    ),
    "x-amz-date": (
        "validate_timestamp (identity.py:139) is the ONLY bound between a "
        "captured SigV4 header and indefinite replay"
    ),
    "x-amz-content-sha256": (
        "the body hash the caller signed; carried so AR-4a's replay bound can "
        "be closed without another policy change"
    ),
    "x-amz-security-token": (
        "session credentials (an assumed role, the common case for an agent on "
        "EKS or AgentCore) carry the key in this header"
    ),
    "traceparent": (
        "tracectx.resolve (app.py:135) derives the run's canonical trace id from "
        "it and NEVER mints one; without this header every decision logs "
        "trace_id=- and no auditor can join a decision to the run that caused it "
        "(a design note point 2)"
    ),
    "baggage": (
        "carries the caller's own modaas-action-id so this service echoes it "
        "rather than minting a second id for the same action (tracectx.py:151)"
    ),
}

# Headers that must NEVER be forwarded, and why. This list is the reason a
# "forward everything the code reads" rule cannot be used: three of these ARE
# read by app.py, as optional overrides, and forwarding them would let the
# caller choose its own authorization inputs.
FORBIDDEN_REQUEST_HEADERS: dict[str, str] = {
    "x-modaas-data-class": (
        "D4 deleted this exact mechanism -- a caller-supplied classification "
        "deciding that caller's authorization. The value now comes from the "
        "governed CR (asset_attributes.data_classification)"
    ),
    "x-modaas-asset": (
        "app.py:87/:99 accept it as an override for local testing; on the "
        "dataplane the asset MUST be derived from the body or the path, or a "
        "caller renames the resource its own decision is made against"
    ),
    "x-modaas-policy-id": (
        "same shape: a caller choosing which Cedar policy judges it"
    ),
    "host": (
        "cannot be obtained as a header at all -- the hook rewrites a forwarded "
        "HOST into the :authority pseudo-header and removes the header "
        "(http/mod.rs:157-166). Naming it yields nothing AND overwrites the "
        "authz call's destination authority with a caller-chosen value"
    ),
}

# The evidence-chain headers this service emits, mapped to the responseMetadata
# key the dataplane lifts them into. On the HTTP ext_authz protocol an ALLOW
# response's headers reach the BACKEND, never the client: `ext_authz.rs:835-873`
# copies `allowedResponseHeaders` into `req.headers_mut()` and returns
# `PolicyResponse::default()`, whose `response_headers` is None. So returning
# these to the caller takes two config halves that must name the same strings --
# `responseMetadata` (authz response -> the `extauthz` CEL variable) and a
# response `transformation` that sets the client header from `extauthz.<key>`.
#
# Refusals need neither half: a non-2xx authz response is returned to the client
# verbatim as a direct_response (`ext_authz.rs:924-930`), headers included.
CLIENT_ECHO_HEADERS: dict[str, str] = {
    "x-modaas-trace-id": "traceId",
    "x-modaas-action-id": "actionId",
    # The run id (2026-09-28): the caller's `modaas-correlation-id` baggage
    # member, else the trace id, else the action id (tracectx.resolve). Lifted
    # into extauthz.correlationId so the access-log policy can write it on the
    # gateway's per-call line: the only record that carries a call's tokens and
    # is not written by the caller. Always present, unlike the trace id.
    "x-modaas-correlation-id": "correlationId",
}

# Headers this service emits that must reach the BACKEND, with the reason each is
# load-bearing. On the HTTP ext_authz protocol `allowedResponseHeaders` is exactly
# this direction: `ext_authz.rs:835-873` copies the named headers from the authz
# ALLOW response into `req.headers_mut()`, i.e. into the upstream request.
#
# `x-modaas-principal` is the one that MATTERS: evidence-service takes the
# caller's attested identity from this header and never from the body, and without
# it every read and write there is a 401.
#
# Same one-declaration rule as the request list: a header this service emits that
# the policy does not forward is a silent capability loss with no code defect
# anywhere, which is exactly how `traceparent` stayed invisible for a sprint.
#
# SCOPE NOTE (and why the evidence route has its OWN AgentgatewayPolicy): these
# must be forwarded on the evidence route and NOT on the governed LLM route. The
# hook copies them into the upstream request, and the Bedrock path is SigV4-signed
# by the dataplane -- adding headers to a request whose signature is computed
# elsewhere is a risk worth not taking for a benefit no LLM backend wants.
# Upstream makes the narrower attachment possible: route-scoped traffic rules are
# chained AFTER gateway/listener rules (`store/binds.rs:960`) and ExtAuthz merges
# by replacement (`store/policy.rs:278-284`, `*self = policy.clone()`), so a
# route-targeted policy overrides the listener's for that route only.
BACKEND_IDENTITY_HEADERS: dict[str, str] = {
    "x-modaas-principal": (
        "evidence-service reads the attested principal from it and refuses "
        "without one; a body field would be the workshop ledger again, with the "
        "attribution set to whatever the writer typed"
    ),
    "x-modaas-action-id": (
        "lets the backend record its own work against the same action this hook "
        "decided, rather than minting a second id for one call"
    ),
    "x-modaas-trace-id": (
        "the run's canonical key, so a backend's records join to the same trace "
        "as the decision that admitted them"
    ),
}
