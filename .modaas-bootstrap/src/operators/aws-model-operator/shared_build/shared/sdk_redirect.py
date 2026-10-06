"""a design note — Provider -> standard SDK env var mapping (REQ-001 universal onboarding).

REQ-001 invariant: MoDaaS imposes zero constraints on agent SDK / framework /
language. Operators redirect agent traffic to the MoDaaS Gateway by injecting
STANDARD SDK environment variables that the agent's existing client library
already honors. NO MoDaaS-prefixed env vars in this module.
"""
from typing import Optional


_PROVIDER_TO_ENV: dict[str, list[tuple[str, str]]] = {
    "aws-bedrock": [
        ("AWS_ENDPOINT_URL_BEDROCK_RUNTIME", "/bedrock"),
    ],
    "aws-sagemaker": [
        ("AWS_ENDPOINT_URL_SAGEMAKER_RUNTIME", "/sagemaker"),
    ],
    "azure-openai": [
        ("AZURE_OPENAI_ENDPOINT", "/azure-openai"),
    ],
    "google-vertex": [
        ("GOOGLE_API_BASE", "/vertex"),
        ("GOOGLE_GENAI_USE_VERTEXAI", "False"),
    ],
    "nvidia-nim": [
        ("NVIDIA_API_BASE", "/nim"),
    ],
    "ollama": [
        ("OLLAMA_HOST", "/ollama"),
    ],
    "vllm": [
        ("OPENAI_BASE_URL", "/v1"),
    ],
    "databricks": [
        ("OPENAI_BASE_URL", "/v1"),
    ],
    "anthropic-direct": [
        ("ANTHROPIC_BASE_URL", "/anthropic"),
    ],
    "openai-direct": [
        ("OPENAI_BASE_URL", "/v1"),
    ],
}


def _strip_trailing_slash(url: str) -> str:
    return url.rstrip("/")


# a hardening note — a redirected agent also needs a CREDENTIAL, not just a URL.
#
# Before this, operators injected AGENTCORE_GATEWAY_MCP_URL (and the model SDK
# base URLs) and nothing else. That was survivable only while the perimeter's
# MCP listener was anonymous. Once a design note's identity hook was promoted to both
# listeners (a hardening note), an unauthenticated agent gets a correct 403 from its own
# governance perimeter -- the URL was right and the call was still refused.
#
# The credential is sourced from a K8s Secret in the AGENT's namespace, never
# from a literal in the Deployment spec, and never cross-namespace: a
# secretKeyRef cannot read another namespace, so the perimeter's own
# agentgateway-system/agw-apikeys Secret is not addressable from here. The
# platform owner supplies a Secret in the component namespace (the chart can
# create it for demo installs); operators only reference it by name.
#
# Two env names are emitted for one credential because the agent reaches the
# perimeter over two wire protocols:
#   OPENAI_API_KEY               -- OpenAI-compatible model calls (/v1/...)
#   AGENTCORE_GATEWAY_MCP_TOKEN  -- MCP tool calls, pairs with ..._MCP_URL
# Both are bearer-shaped: the doorman validates either against the same key
# store and maps it to the shared bootstrap principal (a design note -- keys are door
# access, Keycloak clients are identity).
GATEWAY_CREDENTIAL_ENV_NAMES: tuple[str, ...] = (
    "OPENAI_API_KEY",
    "AGENTCORE_GATEWAY_MCP_TOKEN",
)


def credential_env_from_secret(
    secret_name: str,
    secret_key: str,
    *,
    env_names: tuple[str, ...] = GATEWAY_CREDENTIAL_ENV_NAMES,
) -> list[dict]:
    """K8s env entries sourcing the perimeter bearer credential from a Secret.

    Returns [] when either the Secret name or key is absent -- injecting a
    secretKeyRef to a Secret nobody created would make the agent Pod
    unschedulable (CreateContainerConfigError), which is a worse failure than
    the 403 it replaces. `optional: true` is set for the same reason: a missing
    Secret degrades to the pre-a hardening note behaviour (no credential -> honest 403),
    it does not wedge the Pod.
    """
    if not secret_name or not secret_key:
        return []
    return [
        {
            "name": env_name,
            "valueFrom": {
                "secretKeyRef": {
                    "name": secret_name,
                    "key": secret_key,
                    "optional": True,
                }
            },
        }
        for env_name in env_names
    ]


# ── THE AGENTCORE CREDENTIAL SEAM (review goal 1(c) / P0-1) ──────────────────
#
# `credential_env_from_secret` above cannot serve an AgentCore Runtime. That
# path emits K8s EnvVar entries with a `secretKeyRef`; AgentCore's
# `environmentVariables` is `EnvironmentVariablesMap` -- map<string,string>,
# max 50 entries, marked sensitive (botocore
# data/bedrock-agentcore-control/2023-06-05/service-2.json). There is no
# indirection to a Secret in that shape: whatever the operator puts there is a
# literal, and it travels through the AgentCore control-plane API call.
#
# So the AgentCore path has NO credential today, and a redirected agent is
# refused 403 by its own governance perimeter (the a design note identity hook on both
# agentgateway listeners). This function is the ONE place that changes when the
# owner picks a mechanism. The three candidates, with what each costs:
#
#   a) per-agent Keycloak client (a design note identity tier). Preferred in the
#      review: the agent gets its own principal, so a leaked value is scoped to
#      one agent and revocation is per-agent. Needs a client-provisioning step
#      in the operator and a client_credentials exchange inside the agent.
#   b) AgentCore workload identity. No secret material in the API call at all;
#      requires the perimeter to accept that identity, which is a design note open
#      question 3.
#   c) the shared bootstrap API key from `agw-apikeys`, read server-side by the
#      operator and passed as a literal. Cheapest, and the review names its
#      cost: plaintext in the control-plane call, one principal for every
#      agent, and revocation is all-or-nothing.
#
# Until 2026-09-28 this returned ({}, reason) unconditionally and the operator
# published PerimeterReachable=False with that reason. The owner then chose (c)
# for the workshop ("agentcore agents working now"), with (a) as the later
# production path. So (c) exists as an explicit, opt-in operator mode --
# `sharedKey` -- and everything else still returns ({}, reason).
#: Operator setting that picks the AgentCore credential mechanism. Unset (the
#: default) injects nothing and says so.
AGENTCORE_CREDENTIAL_MODE_ENV = "MODAAS_AGENTCORE_GATEWAY_CREDENTIAL"
#: Mode (c): the component namespace's gateway-key Secret, passed as a literal.
SHARED_KEY_MODE = "sharedKey"


def agentcore_gateway_credential_env(
    *, read_secret=None, environ=None,
) -> tuple[dict[str, str], str]:
    """Perimeter credential env for an AgentCore Runtime, and the reason.

    Args:
        read_secret: ``(namespace, name, key) -> str`` returning the decoded
            value of one Secret key. The operator supplies it; None injects
            nothing.
        environ: the operator's environment (default ``os.environ``).

    Returns:
        ``({env_name: value}, reason)`` using
        :data:`GATEWAY_CREDENTIAL_ENV_NAMES`, so the agent-visible names are
        identical to the pod path's. The reason never contains the value: it
        becomes a status condition message and a log line.
    """
    import os

    env = os.environ if environ is None else environ
    mode = (env.get(AGENTCORE_CREDENTIAL_MODE_ENV) or "").strip()
    if not mode:
        return {}, (
            "no gateway credential mechanism is configured for AgentCore Runtime "
            f"({AGENTCORE_CREDENTIAL_MODE_ENV} is unset; environmentVariables "
            "cannot hold a secretKeyRef, so the pod path's Secret indirection "
            "does not apply). A redirected agent will reach the perimeter "
            "unauthenticated and be refused 403. Set "
            f"{AGENTCORE_CREDENTIAL_MODE_ENV}={SHARED_KEY_MODE} (eval/workshop: "
            "one shared key, visible in the runtime's configuration); per-agent "
            "Keycloak clients (a design note) are the production path."
        )
    if mode != SHARED_KEY_MODE:
        return {}, (
            f"{AGENTCORE_CREDENTIAL_MODE_ENV}={mode!r} is not a supported mode; "
            f"the only one implemented is {SHARED_KEY_MODE!r}. No credential "
            "injected, so the agent will be refused 403 by the perimeter."
        )
    name = (env.get("MODAAS_GATEWAY_CREDENTIAL_SECRET") or "").strip()
    key = (env.get("MODAAS_GATEWAY_CREDENTIAL_SECRET_KEY") or "").strip()
    namespace = (
        env.get("MODAAS_GATEWAY_CREDENTIAL_NAMESPACE")
        or env.get("COMPONENT_NAMESPACE")
        or "components"
    ).strip()
    for var, val in (("MODAAS_GATEWAY_CREDENTIAL_SECRET", name),
                     ("MODAAS_GATEWAY_CREDENTIAL_SECRET_KEY", key)):
        if not val:
            return {}, (
                f"{SHARED_KEY_MODE} mode is on but {var} is unset, so there is "
                "no Secret to read. No credential injected (403 at the perimeter)."
            )
    if read_secret is None:
        return {}, f"{SHARED_KEY_MODE} mode is on but no Secret reader was supplied"
    where = f"{namespace}/{name}"
    try:
        value = read_secret(namespace, name, key)
    except Exception as exc:  # noqa: BLE001 -- surfaced, never swallowed
        return {}, (
            f"could not read Secret {where} key {key!r} "
            f"({type(exc).__name__}); no credential injected (403 at the perimeter)"
        )
    if not value:
        return {}, (
            f"Secret {where} has no non-empty key {key!r}; no credential injected "
            "(403 at the perimeter)"
        )
    return {n: value for n in GATEWAY_CREDENTIAL_ENV_NAMES}, (
        f"shared gateway key from Secret {where} ({SHARED_KEY_MODE} mode: one "
        "key for every agent, visible in the runtime's configuration)"
    )


def env_vars_for_provider(provider: str, gateway_url: str) -> dict[str, str]:
    out: dict[str, str] = {}
    pairs = _PROVIDER_TO_ENV.get(provider, [])
    base = _strip_trailing_slash(gateway_url)
    for env_name, path_or_value in pairs:
        if path_or_value.startswith("/"):
            out[env_name] = f"{base}{path_or_value}"
        else:
            out[env_name] = path_or_value
    return out


def env_vars_for_dependencies(
    deps_models: list[dict],
    gateway_url: str,
) -> dict[str, str]:
    out: dict[str, str] = {}
    seen_providers: set[str] = set()
    for dep in deps_models:
        provider = dep.get("provider") if isinstance(dep, dict) else None
        if not provider or provider in seen_providers:
            continue
        seen_providers.add(provider)
        out.update(env_vars_for_provider(provider, gateway_url))
    base = _strip_trailing_slash(gateway_url)
    out.setdefault("OPENAI_BASE_URL", f"{base}/v1")
    return out


def env_vars_for_tool_provider(
    provider: str,
    *,
    gateway_url: str = "",
    asset_alias: str = "",
) -> dict[str, str]:
    """Tool-provider env vars: the PERIMETER MCP URL, and nothing else.

    There is exactly one path. The agent is told
    ``{gateway_url}/mcp/{asset_alias}`` — an address on Gateway ``modaas-agw``,
    where the a design note identity hook and Cedar run — or it is told nothing.

    No fallback, by design (2026-09-26). This function used to take a positional
    ``mcp_url`` and, when ``gateway_url``/``asset_alias`` were absent, hand that
    raw value back as ``AGENTCORE_GATEWAY_MCP_URL``. In practice that value was a
    ``*.gateway.bedrock-agentcore.*`` address, so the "fallback" was a tool path
    that skipped the whole perimeter. Neither production caller used it, which is
    why it lived so long: dead code whose only effect, if revived, is an
    ungoverned URL. The parameter is gone so an old-shape call raises TypeError
    at the call site rather than silently succeeding.

    Refusal contract: with no ``gateway_url`` or no ``asset_alias`` this returns
    ``{}``. The agent then holds no tool URL at all — fail-closed and visible
    (the caller's DependencyHealthy condition carries the unresolved dependency,
    a design note) instead of fail-open and invisible.

    U12 (tool-server-fixture): "custom" joins "agentCoreGateway" here, not a
    parallel branch — both ToolConfig providers publish the identical
    /mcp/{alias}-shaped perimeter URL (tool_operator.py's own U12 fix makes
    this true for both), so the agent-facing env var is the same either way.
    Per a design note ("status.endpoint = governance perimeter URL, never
    upstream"), the agent is told THIS URL, never spec.custom.baseUrl
    directly — it never learns the tool server's real address.
    """
    if provider in ("agentCoreGateway", "custom") and gateway_url and asset_alias:
        base = mcp_listener_base(_strip_trailing_slash(gateway_url))
        return {"AGENTCORE_GATEWAY_MCP_URL": f"{base}/mcp/{asset_alias}"}
    return {}


def mcp_listener_base(base: str) -> str:
    """Re-point a perimeter base at the Gateway's MCP (`http`, :8080) listener.

    Both agent paths build the tool URL from the LLM base the operator already
    holds, which carries the `openai-compat` port (:8081, the `llm` listener).
    HTTPRoutes for /mcp/<alias> attach to the `http` listener on :8080, so a
    tool URL on :8081 is answered 404 "route not found" by agentgateway and the
    agent runs tool-less (reviewer finding #6, 2026-10-02; reproduced on the
    hackathon-helper AgentCore runtime, event 486b9241, 2026-10-03). Swap the
    port by wire format; leave a base with no port alone.
    """
    try:
        from shared.dependent_api import WIRE_FORMAT_GATEWAY_PORT
    except ImportError:
        from operators.shared.dependent_api import WIRE_FORMAT_GATEWAY_PORT
    llm_ports = {str(WIRE_FORMAT_GATEWAY_PORT.get(w)) for w in
                 ("openai-compat", "bedrock-runtime", "bedrock-runtime-stream", "sagemaker-runtime", "vertex-ai")}
    mcp_port = str(WIRE_FORMAT_GATEWAY_PORT.get("agentcore-mcp", 8080))
    scheme, _, rest = base.partition("://")
    hostport, slash, path = rest.partition("/")
    host, colon, port = hostport.rpartition(":")
    if colon and port in llm_ports:
        hostport = f"{host}:{mcp_port}"
    return f"{scheme}://{hostport}{slash}{path}" if scheme else f"{hostport}{slash}{path}"
