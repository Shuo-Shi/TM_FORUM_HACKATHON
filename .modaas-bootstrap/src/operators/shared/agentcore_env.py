"""Caller-declared environment for an AgentCore Runtime.

`spec.awsAgentCore.environmentVariables` forwards AgentCore's native
`environmentVariables` (Governance-vs-API-Passthrough principle) so an agent
can be told its own settings: its role, its evidence store, its step numbering.
Before it existed the awsAgentCore block had no env field at all, and an agent
hosted there could learn nothing the operator did not derive itself.

The operator keeps the perimeter. A declared name is refused when it would:
  * redirect the agent (the SDK base-URL names and any AWS_ENDPOINT_URL*),
  * replace its perimeter credential (GATEWAY_CREDENTIAL_ENV_NAMES),
  * hand it a provider credential, letting it reach a provider directly,
  * override a value the operator derives from the spec, or
  * collide with any name the operator injected for this particular agent.

Bounds are the API's: botocore bedrock-agentcore-control
`EnvironmentVariablesMap` max 50 entries, key 1..100, value 0..5000 characters
(read from botocore 1.43.103 on 2026-09-28). Values are plain text in the CR
and in the runtime's configuration.
"""
from __future__ import annotations

try:
    from shared.sdk_redirect import GATEWAY_CREDENTIAL_ENV_NAMES, _PROVIDER_TO_ENV
except ImportError:  # pragma: no cover - import-path variant
    from operators.shared.sdk_redirect import GATEWAY_CREDENTIAL_ENV_NAMES, _PROVIDER_TO_ENV

MAX_ENTRIES = 50
KEY_MAX = 100
VALUE_MAX = 5000

#: Same list as operators/k8s-agent-operator/withholding.py (a test keeps the
#: two equal): env names that hand a workload a PROVIDER credential.
PROVIDER_CREDENTIAL_ENV_NAMES: frozenset[str] = frozenset({
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "ANTHROPIC_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_AD_TOKEN",
    "GOOGLE_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "DATABRICKS_TOKEN",
    "NVIDIA_API_KEY",
})

#: Values aws-agent-operator derives from the spec for every managed runtime.
OPERATOR_DERIVED_ENV_NAMES: frozenset[str] = frozenset({
    "REGION", "REGISTRY_ID", "MODEL_ALIAS", "TOOL_ALIAS",
})

RESERVED_ENV_NAMES: frozenset[str] = frozenset(
    {name for pairs in _PROVIDER_TO_ENV.values() for name, _ in pairs}
    | {"AGENTCORE_GATEWAY_MCP_URL"}
    | set(GATEWAY_CREDENTIAL_ENV_NAMES)
    | PROVIDER_CREDENTIAL_ENV_NAMES
    | OPERATOR_DERIVED_ENV_NAMES
)
RESERVED_PREFIXES: tuple[str, ...] = ("AWS_ENDPOINT_URL",)


class DeclaredEnvInvalid(ValueError):
    """The declared block would weaken the perimeter or break an API bound."""


def _reserved(name: str, operator_env: dict) -> bool:
    return (
        name in RESERVED_ENV_NAMES
        or name in operator_env
        or any(name.startswith(p) for p in RESERVED_PREFIXES)
    )


def merge_declared_env(declared, operator_env: dict) -> dict:
    """Return the operator's env plus the caller's settings, or raise.

    Operator-owned names are refused rather than silently overridden in either
    direction: an override the operator won would drop the caller's intent
    without a word, and one the caller won would move the agent past its own
    perimeter while the CR stayed Approved.
    """
    if declared is None:
        return dict(operator_env)
    if not isinstance(declared, dict):
        raise DeclaredEnvInvalid(
            "awsAgentCore.environmentVariables must be a map of NAME: value")
    wrong_type = sorted(
        str(k) for k, v in declared.items()
        if not isinstance(k, str) or not isinstance(v, str))
    if wrong_type:
        raise DeclaredEnvInvalid(
            "awsAgentCore.environmentVariables values must be strings (quote "
            f"numbers): {', '.join(wrong_type)}")
    owned = sorted(k for k in declared if _reserved(k, operator_env))
    if owned:
        raise DeclaredEnvInvalid(
            f"awsAgentCore.environmentVariables may not set {', '.join(owned)}: "
            "the operator owns the gateway redirect, the gateway credential and "
            "the values it derives from the spec, and provider credentials would "
            "let the agent bypass the perimeter.")
    for k, v in declared.items():
        if not 1 <= len(k) <= KEY_MAX:
            raise DeclaredEnvInvalid(
                f"environment variable name {k[:40]!r}... is {len(k)} characters; "
                f"AgentCore allows 1..{KEY_MAX}")
        if len(v) > VALUE_MAX:
            raise DeclaredEnvInvalid(
                f"environment variable {k} is {len(v)} characters; AgentCore "
                f"allows at most {VALUE_MAX}")
    merged = {**declared, **operator_env}
    if len(merged) > MAX_ENTRIES:
        raise DeclaredEnvInvalid(
            f"{len(merged)} environment variables ({len(operator_env)} from the "
            f"operator, {len(declared)} declared); AgentCore allows at most "
            f"{MAX_ENTRIES}")
    return merged
