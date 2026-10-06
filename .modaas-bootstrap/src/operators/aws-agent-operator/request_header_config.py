"""AgentCore Runtime requestHeaderConfiguration (review goal 3).

`CreateAgentRuntime` and `UpdateAgentRuntime` both accept
`requestHeaderConfiguration`, a UNION whose single member is
`requestHeaderAllowlist`: the HTTP request headers AgentCore forwards into the
runtime. The operator never sent it, so no caller header reached a governed
agent -- including the two a design note needs for an evidence chain that joins the
caller's trace: `traceparent` and `baggage`.

API constraints, fetched 2026-09-26 from
https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_RequestHeaderConfiguration.html

    Array Members: Minimum number of 1 item. Maximum number of 20 items.
    Length Constraints: Minimum length of 1. Maximum length of 256.
    Pattern: [A-Za-z][A-Za-z0-9_-]{0,255}

Measured against the live service on 2026-09-28 (a fresh workshop account):

  * The service follows the API reference's pattern, not the narrower
    `(Authorization|X-Amzn-Bedrock-AgentCore-Runtime-Custom-...)` shape in the
    botocore model. `["traceparent", "baggage"]` was accepted by
    CreateAgentRuntime.
  * `Authorization` is conditional. The same call with the old default
    (`Authorization, traceparent, baggage`) was refused:

        ValidationException: Authorization header can be specified in
        requestHeaderAllowlist only when runtime is set up with
        customJWTAuthorizer for OAuth based authorization.

    Without a JWT authorizer the inbound request is SigV4-signed, and its
    Authorization header is the signature, which AgentCore does not hand to
    the container. So the default carries `Authorization` only when the
    caller declared `authorizerConfiguration.customJWTAuthorizer`, and a
    declared allowlist naming it without one is refused here, before the AWS
    call. Before this, every managed agent failed at create.
"""
from __future__ import annotations

import re

#: API bounds on `requestHeaderAllowlist`.
MAX_ALLOWLIST_ENTRIES = 20
MIN_ALLOWLIST_ENTRIES = 1
HEADER_NAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,255}$")

#: MoDaaS default: `traceparent`/`baggage`, so the evidence chain joins the
#: caller's trace instead of minting a fresh root span per hop (a design note).
MODAAS_DEFAULT_REQUEST_HEADER_ALLOWLIST: tuple[str, ...] = (
    "traceparent",
    "baggage",
)

#: Added to the default only when the runtime authenticates callers with a
#: customJWTAuthorizer, so a governed agent can carry the caller's bearer to
#: the assets it calls. AgentCore refuses it otherwise (module docstring).
AUTHORIZATION_HEADER = "Authorization"


class RequestHeaderConfigInvalid(ValueError):
    """A declared allowlist AWS would reject. Raised before the API call."""


def has_custom_jwt_authorizer(agentcore_cfg: dict) -> bool:
    """True when `authorizerConfiguration.customJWTAuthorizer` is an object.

    `authorizerConfiguration` is a union; only this member makes AgentCore
    forward an inbound Authorization header.
    """
    auth = (agentcore_cfg or {}).get("authorizerConfiguration")
    return isinstance(auth, dict) and isinstance(auth.get("customJWTAuthorizer"), dict)


def resolve_request_header_configuration(agentcore_cfg: dict) -> dict:
    """Return the `requestHeaderConfiguration` to send to AgentCore.

    A caller-declared block wins verbatim (Governance-vs-API-Passthrough
    principle: the operator forwards native capability, it does not curate it).
    Absent one, MoDaaS supplies :data:`MODAAS_DEFAULT_REQUEST_HEADER_ALLOWLIST`,
    plus :data:`AUTHORIZATION_HEADER` when a customJWTAuthorizer is declared.

    Raises:
        RequestHeaderConfigInvalid: the declared block violates a documented API
            bound, or names Authorization without a customJWTAuthorizer. Failing
            here names the offending entry; letting it reach AWS yields an
            opaque ValidationException on a create call.
    """
    jwt = has_custom_jwt_authorizer(agentcore_cfg)
    declared = (agentcore_cfg or {}).get("requestHeaderConfiguration")
    if declared is None:
        names = list(MODAAS_DEFAULT_REQUEST_HEADER_ALLOWLIST)
        if jwt:
            names.insert(0, AUTHORIZATION_HEADER)
        return {"requestHeaderAllowlist": names}

    if not isinstance(declared, dict):
        raise RequestHeaderConfigInvalid(
            "awsAgentCore.requestHeaderConfiguration must be an object with a "
            "requestHeaderAllowlist member"
        )

    allowlist = declared.get("requestHeaderAllowlist")
    if allowlist is None:
        raise RequestHeaderConfigInvalid(
            "requestHeaderConfiguration is a union whose only member is "
            "requestHeaderAllowlist; the block declares neither"
        )
    if not isinstance(allowlist, list):
        raise RequestHeaderConfigInvalid("requestHeaderAllowlist must be a list of header names")
    if len(allowlist) < MIN_ALLOWLIST_ENTRIES:
        raise RequestHeaderConfigInvalid(
            f"requestHeaderAllowlist requires at least {MIN_ALLOWLIST_ENTRIES} entry; "
            "omit the whole block to accept the MoDaaS default"
        )
    if len(allowlist) > MAX_ALLOWLIST_ENTRIES:
        raise RequestHeaderConfigInvalid(
            f"requestHeaderAllowlist admits at most {MAX_ALLOWLIST_ENTRIES} entries, "
            f"got {len(allowlist)}"
        )
    for name in allowlist:
        if not isinstance(name, str) or not HEADER_NAME_PATTERN.match(name):
            raise RequestHeaderConfigInvalid(
                f"requestHeaderAllowlist entry {name!r} violates the documented "
                f"header-name pattern {HEADER_NAME_PATTERN.pattern}"
            )
    if not jwt and any(n.lower() == AUTHORIZATION_HEADER.lower() for n in allowlist):
        raise RequestHeaderConfigInvalid(
            "requestHeaderAllowlist names Authorization, which AgentCore forwards "
            "only when the runtime authenticates callers with a JWT: set "
            "awsAgentCore.authorizerConfiguration.customJWTAuthorizer, or remove "
            "Authorization from the list. AgentCore refuses the create otherwise "
            "(ValidationException: Authorization header can be specified in "
            "requestHeaderAllowlist only when runtime is set up with "
            "customJWTAuthorizer)."
        )
    return declared
