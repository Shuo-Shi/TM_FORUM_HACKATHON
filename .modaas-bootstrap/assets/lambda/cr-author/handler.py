# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""cr-author Lambda tool -- scaffold and patch ODA Canvas CRs.

Exposes two actions via the Lambda handler:
  scaffold  -> scaffold_cr(kind, name, fields) -> valid YAML with defaults
  patch     -> patch_cr(kind, current_yaml, changes) -> updated YAML + kubectl commands

Validates output against embedded CRD jsonschema definitions.
Lists CEL admission rules that cannot be checked at scaffold/patch time.
"""
import copy
import json
import os
import re

try:
    import jsonschema as _jsonschema
except ImportError:
    _jsonschema = None

API_VERSION = "oda.tmforum.org/v1beta1"
NAMESPACE = "components"

# ---------------------------------------------------------------------------
# Immutable fields enforced by CEL admission webhooks on the cluster.
# We can warn, but cannot truly enforce at scaffold/patch time.
# ---------------------------------------------------------------------------
IMMUTABLE_FIELDS = {
    "ModelConfig": ["spec.alias", "spec.provider"],
    "ToolConfig": ["spec.alias", "spec.provider", "spec.toolName"],
    "AgentConfig": ["spec.agentName", "spec.provider"],
}

# ---------------------------------------------------------------------------
# CEL rules we list but cannot evaluate outside the cluster
# ---------------------------------------------------------------------------
CEL_RULES = {
    "ModelConfig": [
        "spec.alias is immutable after creation",
        "spec.provider is immutable after creation",
    ],
    "ToolConfig": [
        "spec.alias is immutable after creation",
        "spec.provider is immutable after creation",
        "spec.toolName is immutable after creation",
    ],
    "AgentConfig": [
        "modelRef must appear in dependsOn.models",
        "spec.agentName is immutable after creation",
        "spec.provider is immutable after creation",
    ],
}

# ---------------------------------------------------------------------------
# Simplified CRD JSON-Schema definitions -- enough for validation.
# These mirror the v1beta1 ODA Canvas CRDs used by the workshop cluster.
# ---------------------------------------------------------------------------
_GOVERNANCE_SCHEMA = {
    "type": "object",
    "properties": {
        "approval": {
            "type": "object",
            "properties": {
                "required": {"type": "boolean"},
                "requiredApprovals": {"type": "integer", "minimum": 1},
            },
        },
        "dataClassification": {
            "type": "string",
            "enum": ["public", "internal", "confidential", "restricted"],
        },
        "owner": {"type": "string"},
    },
}

_ACCESS_SCHEMA = {
    "type": "object",
    "properties": {
        "allowedConsumers": {
            "type": "array",
            "items": {"type": "string"},
        },
        "cedarPolicy": {"type": "string"},
    },
}

_SAFETY_SCHEMA = {
    "type": "object",
    "properties": {
        "required": {"type": "boolean"},
        "enforces": {"type": "boolean"},
        "enforcerKind": {"type": "string"},
    },
}

CRD_SCHEMAS = {
    "ModelConfig": {
        "type": "object",
        "required": ["apiVersion", "kind", "metadata", "spec"],
        "properties": {
            "apiVersion": {"type": "string", "const": API_VERSION},
            "kind": {"type": "string", "const": "ModelConfig"},
            "metadata": {
                "type": "object",
                "required": ["name", "namespace"],
                "properties": {
                    "name": {"type": "string"},
                    "namespace": {"type": "string"},
                },
            },
            "spec": {
                "type": "object",
                "required": ["alias", "provider", "modelId"],
                "properties": {
                    "alias": {"type": "string"},
                    "provider": {"type": "string"},
                    "modelId": {"type": "string"},
                    "credentialProviderType": {
                        "type": "string",
                        "enum": ["NONE", "IAM_ROLE", "SECRET"],
                    },
                    "paused": {"type": "boolean"},
                    "awsBedrock": {
                        "type": "object",
                        "properties": {
                            "region": {"type": "string"},
                            "apiMode": {
                                "type": "string",
                                "enum": ["converse", "invoke"],
                            },
                            "guardrails": {
                                "type": "object",
                                "properties": {
                                    "guardrailId": {"type": "string"},
                                    "guardrailVersion": {"type": "string"},
                                },
                            },
                        },
                    },
                    "inferenceConfig": {
                        "type": "object",
                        "properties": {
                            "maxTokens": {"type": "integer"},
                            "temperature": {"type": "number"},
                        },
                    },
                    "costBasis": {
                        "type": "object",
                        "properties": {
                            "inputTokensPer1k": {"type": "number"},
                            "outputTokensPer1k": {"type": "number"},
                        },
                    },
                    "safety": _SAFETY_SCHEMA,
                    "governance": _GOVERNANCE_SCHEMA,
                    "access": _ACCESS_SCHEMA,
                },
            },
        },
    },
    "ToolConfig": {
        "type": "object",
        "required": ["apiVersion", "kind", "metadata", "spec"],
        "properties": {
            "apiVersion": {"type": "string", "const": API_VERSION},
            "kind": {"type": "string", "const": "ToolConfig"},
            "metadata": {
                "type": "object",
                "required": ["name", "namespace"],
                "properties": {
                    "name": {"type": "string"},
                    "namespace": {"type": "string"},
                },
            },
            "spec": {
                "type": "object",
                "required": ["alias", "provider", "toolName"],
                "properties": {
                    "alias": {"type": "string"},
                    "provider": {"type": "string"},
                    "toolName": {"type": "string"},
                    "toolType": {"type": "string"},
                    "description": {"type": "string"},
                    "credentialProviderType": {
                        "type": "string",
                        "enum": ["NONE", "IAM_ROLE", "SECRET"],
                    },
                    "gatewayIdentifier": {"type": "string"},
                    "tools": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "description": {"type": "string"},
                                "inputSchema": {"type": "object"},
                            },
                        },
                    },
                    "dataClassification": {
                        "type": "string",
                        "enum": ["public", "internal", "confidential", "restricted"],
                    },
                    "access": _ACCESS_SCHEMA,
                    "governance": _GOVERNANCE_SCHEMA,
                },
            },
        },
    },
    "AgentConfig": {
        "type": "object",
        "required": ["apiVersion", "kind", "metadata", "spec"],
        "properties": {
            "apiVersion": {"type": "string", "const": API_VERSION},
            "kind": {"type": "string", "const": "AgentConfig"},
            "metadata": {
                "type": "object",
                "required": ["name", "namespace"],
                "properties": {
                    "name": {"type": "string"},
                    "namespace": {"type": "string"},
                },
            },
            "spec": {
                "type": "object",
                "required": ["agentName", "provider"],
                "properties": {
                    "agentName": {"type": "string"},
                    "provider": {"type": "string"},
                    "networkMode": {
                        "type": "string",
                        "enum": ["public", "private"],
                    },
                    "agentCard": {
                        "type": "object",
                        "properties": {
                            "description": {"type": "string"},
                            "skills": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            "protocolBinding": {"type": "string"},
                        },
                    },
                    "awsAgentCore": {
                        "type": "object",
                        "properties": {
                            "containerUri": {"type": "string"},
                            "region": {"type": "string"},
                            "protocolConfiguration": {
                                "type": "object",
                                "properties": {
                                    "protocol": {"type": "string"},
                                },
                            },
                            "networkModeConfig": {
                                "type": "object",
                                "properties": {
                                    "vpcId": {"type": "string"},
                                    "subnetIds": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                    },
                                    "securityGroupIds": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                    },
                                },
                            },
                            "environmentVariables": {
                                "type": "object",
                                "additionalProperties": {"type": "string"},
                            },
                        },
                    },
                    "dependsOn": {
                        "type": "object",
                        "properties": {
                            "models": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            "tools": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                        },
                    },
                    "safety": _SAFETY_SCHEMA,
                    "governance": _GOVERNANCE_SCHEMA,
                },
            },
        },
    },
}

# ---------------------------------------------------------------------------
# Default values applied when scaffolding each kind
# ---------------------------------------------------------------------------
SCAFFOLD_DEFAULTS = {
    # Defaults mirror the shipped demo CRs (static/crs/*modelconfig*.yaml):
    # provider aws-bedrock, Nemotron on Bedrock, converse. The old default
    # `bedrockPassthrough` is not a MoDaaS provider and admission rejects it
    # (helper CLI run on E7, 2026-10-04).
    "ModelConfig": {
        "spec.provider": "aws-bedrock",
        "spec.modelId": "nvidia.nemotron-nano-9b-v2",
        "spec.credentialProviderType": "NONE",
        "spec.paused": False,
        "spec.awsBedrock.region": "us-east-1",
        "spec.awsBedrock.apiMode": "converse",
        "spec.awsBedrock.inferenceConfig.maxTokens": 800,
        # safety.required=true with no enforcer is a LyingDeclaration the
        # operator refuses (phase=Failed on E7, 2026-10-04); ship the same
        # minimal guardrail the demo CRs declare so the stub is admissible.
        "spec.awsBedrock.guardrails.contentPolicy.filters": [
            {"type": "PROMPT_ATTACK", "inputStrength": "HIGH", "outputStrength": "NONE"}
        ],
        "spec.safety.required": True,
        "spec.safety.enforcer.kind": "bedrockGuardrail",
        "spec.safety.enforcer.enforcedAt": "self",
        # Who may call the model. Without a grant no model-<alias> policy is
        # projected and every call is "PolicyDenied: policy not loaded".
        # bootstrap-key is the principal every API-key caller resolves to
        # (platform identity model); agents on the JWT path add their own ServiceIdentity.
        "spec.access.allowedConsumers": ["bootstrap-key"],
        "spec.governance.approval.required": True,
        "spec.governance.approval.requiredApprovals": 1,
        "spec.governance.dataClassification": "internal",
    },
    "ToolConfig": {
        "spec.provider": "agentCoreGateway",
        "spec.toolType": "mcp",
        "spec.credentialProviderType": "NONE",
        "spec.governance.approval.required": True,
        "spec.governance.approval.requiredApprovals": 1,
        "spec.governance.dataClassification": "internal",
    },
    "AgentConfig": {
        "spec.provider": "awsAgentCore",
        "spec.networkMode": "public",
        "spec.awsAgentCore.region": "us-east-1",
        "spec.safety.enforces": True,
        "spec.safety.enforcerKind": "bedrockGuardrail",
        "spec.governance.approval.required": True,
        "spec.governance.approval.requiredApprovals": 1,
    },
}

# Map of kind -> the spec field that mirrors metadata.name
_NAME_FIELD = {
    "ModelConfig": "spec.alias",
    "ToolConfig": "spec.alias",
    "AgentConfig": "spec.agentName",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _set_nested(d, path, value):
    """Set a dot-separated path inside a nested dict, creating intermediaries."""
    keys = path.split(".")
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    d[keys[-1]] = value


def _get_nested(d, path, default=None):
    """Read a dot-separated path from a nested dict."""
    keys = path.split(".")
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
        if d is default:
            return default
    return d


def _to_yaml_lines(obj, indent=0):
    """Minimal YAML serialiser -- no external dependency."""
    pad = "  " * indent
    lines = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, dict) and v:
                lines.append(f"{pad}{k}:")
                lines.extend(_to_yaml_lines(v, indent + 1))
            elif isinstance(v, list):
                if not v:
                    lines.append(f"{pad}{k}: []")
                elif all(not isinstance(i, dict) for i in v):
                    items = ", ".join(json.dumps(i) for i in v)
                    lines.append(f"{pad}{k}: [{items}]")
                else:
                    lines.append(f"{pad}{k}:")
                    for item in v:
                        if isinstance(item, dict):
                            # Items render at the key's indent + 1; the dash
                            # occupies two columns, so continuation keys are
                            # emitted at indent + 1 and the first key is
                            # hoisted onto the dash line (was indent + 2,
                            # which produced invalid YAML for list-of-dict).
                            sub = _to_yaml_lines(item, indent + 1)
                            if sub:
                                lines.append(f"{pad}- {sub[0].lstrip()}")
                                lines.extend(sub[1:])
                            else:
                                lines.append(f"{pad}- {{}}")
                        else:
                            lines.append(f"{pad}- {json.dumps(item)}")
            elif isinstance(v, bool):
                lines.append(f"{pad}{k}: {'true' if v else 'false'}")
            elif isinstance(v, (int, float)):
                lines.append(f"{pad}{k}: {v}")
            elif v is None:
                lines.append(f"{pad}{k}:  # FILL IN")
            else:
                val = str(v)
                if any(c in val for c in ":{}&*?|>!%@`") or val == "":
                    val = json.dumps(val)
                lines.append(f"{pad}{k}: {val}")
    return lines


def _dict_to_yaml(obj):
    """Convert a dict to a YAML string."""
    return "\n".join(["---"] + _to_yaml_lines(obj)) + "\n"


def _parse_yaml_or_json(text):
    """Best-effort parse of YAML or JSON text into a dict."""
    text = text.strip()
    if text.startswith("{"):
        return json.loads(text)
    # Minimal YAML parser: try the yaml module if available, else basic parse
    try:
        import yaml as yaml_mod
        return yaml_mod.safe_load(text)
    except ImportError:
        pass
    # Fallback: strip document separator and use json if it looks like json
    stripped = re.sub(r"^---\s*\n", "", text)
    if stripped.startswith("{"):
        return json.loads(stripped)
    raise ValueError("cannot parse input -- install PyYAML or pass JSON")


def _validate_against_schema(cr_dict, kind):
    """Validate a CR dict against the CRD JSON schema. Returns list of warnings."""
    schema = CRD_SCHEMAS.get(kind)
    if not schema:
        return [f"no schema for kind {kind}"]
    if _jsonschema is None:
        return ["jsonschema library not available -- skipping validation"]
    warnings = []
    try:
        _jsonschema.validate(instance=cr_dict, schema=schema)
    except _jsonschema.ValidationError as exc:
        warnings.append(f"schema: {exc.message}")
    except _jsonschema.SchemaError as exc:
        warnings.append(f"internal schema error: {exc.message}")
    return warnings


def _approval_command(kind, name):
    """Return the kubectl annotate command for governance approval."""
    return (
        f"kubectl -n {NAMESPACE} annotate {kind.lower()}/{name} "
        f"modaas.tmforum.org/approver=\"$(whoami)@team\" "
        f"modaas.tmforum.org/approval-attestation=\"Reviewed: <what you verified>\" --overwrite"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def scaffold_cr(kind, name, fields=None):
    """Scaffold a new CR YAML for the given kind.

    Returns dict with keys: yaml, commands, validation.
    """
    if kind not in CRD_SCHEMAS:
        return {"error": f"unknown kind: {kind}; use ModelConfig, ToolConfig, or AgentConfig"}

    cr = {
        "apiVersion": API_VERSION,
        "kind": kind,
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {},
    }

    # Apply defaults
    for path, val in SCAFFOLD_DEFAULTS.get(kind, {}).items():
        _set_nested(cr, path, val)

    # Set the name-mirroring spec field (alias or agentName)
    name_field = _NAME_FIELD[kind]
    _set_nested(cr, name_field, name)

    # ToolConfig gets toolName = name by default
    if kind == "ToolConfig":
        _set_nested(cr, "spec.toolName", name)

    # Apply caller-supplied fields (override defaults)
    if fields:
        for path, val in fields.items():
            _set_nested(cr, path, val)

    # Fill required fields that are still missing with None (-> # FILL IN comment)
    spec_schema = CRD_SCHEMAS[kind]["properties"]["spec"]
    for req_field in spec_schema.get("required", []):
        full_path = f"spec.{req_field}"
        if _get_nested(cr, full_path) is None:
            _set_nested(cr, full_path, None)

    # Validate
    validation = _validate_against_schema(cr, kind)
    validation.extend(
        f"CEL (not checked): {rule}" for rule in CEL_RULES.get(kind, [])
    )

    yaml_text = _dict_to_yaml(cr)

    # Build kubectl commands
    commands = [
        f"kubectl apply -f <file>.yaml",
        # Phase is authoritative; the route condition is what Module 5 waits on.
        # ModelConfig never emits a `Ready` condition.
        (f"kubectl -n {NAMESPACE} wait {kind.lower()}/{name} --for=condition=AgentgatewayRouteProgrammed --timeout=300s"
         if kind == "ModelConfig" else
         f"kubectl -n {NAMESPACE} wait {kind.lower()}/{name} --for=condition=Provisioned --timeout=300s"),
    ]
    if _get_nested(cr, "spec.governance.approval.required", False):
        commands.append(_approval_command(kind, name))

    return {"yaml": yaml_text, "commands": commands, "validation": validation}


def patch_cr(kind, current_yaml, changes):
    """Patch an existing CR with the given changes.

    Returns dict with keys: yaml, commands, validation.
    """
    if kind not in CRD_SCHEMAS:
        return {"error": f"unknown kind: {kind}; use ModelConfig, ToolConfig, or AgentConfig"}

    try:
        current = _parse_yaml_or_json(current_yaml)
    except Exception as exc:
        return {"error": f"could not parse current_yaml: {exc}"}

    if not isinstance(current, dict):
        return {"error": "current_yaml did not parse to a dict"}

    name = _get_nested(current, "metadata.name", "unknown")

    # Check immutable-field violations
    immutables = IMMUTABLE_FIELDS.get(kind, [])
    violations = []
    for path, new_val in changes.items():
        if path in immutables:
            old_val = _get_nested(current, path)
            if old_val is not None and old_val != new_val:
                violations.append(
                    f"cannot change {path}: immutable after creation "
                    f"(current={old_val!r}, requested={new_val!r})"
                )
    if violations:
        return {
            "error": "immutable field violation",
            "violations": violations,
            "validation": [
                f"CEL reject: {path} is immutable after creation"
                for path in (v.split(":")[0].replace("cannot change ", "").strip()
                             for v in violations)
            ],
        }

    # Apply changes
    patched = copy.deepcopy(current)
    for path, val in changes.items():
        _set_nested(patched, path, val)

    # Validate patched result
    validation = _validate_against_schema(patched, kind)
    validation.extend(
        f"CEL (not checked): {rule}" for rule in CEL_RULES.get(kind, [])
    )

    yaml_text = _dict_to_yaml(patched)

    # Build kubectl commands
    patch_body = {}
    for path, val in changes.items():
        _set_nested(patch_body, path, val)
    patch_cmd = (
        f"kubectl -n {NAMESPACE} patch {kind.lower()}/{name} "
        f"--type merge -p '{json.dumps(patch_body)}'"
    )
    cond = "AgentgatewayRouteProgrammed" if kind == "ModelConfig" else "Provisioned"
    wait_cmd = (
        f"kubectl -n {NAMESPACE} wait {kind.lower()}/{name} "
        f"--for=condition={cond} --timeout=300s"
    )
    commands = [patch_cmd, wait_cmd]

    # Include approval command if governance requires it
    needs_approval = _get_nested(
        patched, "spec.governance.approval.required", False
    )
    if needs_approval:
        commands.append(_approval_command(kind, name))

    return {"yaml": yaml_text, "commands": commands, "validation": validation}


# ---------------------------------------------------------------------------
# Lambda entry point
# ---------------------------------------------------------------------------
def handler(event, context=None):
    """Lambda handler dispatching to scaffold_cr or patch_cr."""
    params = event.get("parameters") or event.get("arguments") or event
    action = params.get("action", "scaffold")

    if action == "scaffold":
        kind = params.get("kind", "")
        name = params.get("name", "")
        fields = params.get("fields")
        if isinstance(fields, str):
            try:
                fields = json.loads(fields)
            except Exception:
                fields = {}
        if not kind or not name:
            return {"error": "kind and name are required for scaffold"}
        return scaffold_cr(kind, name, fields)

    elif action == "patch":
        kind = params.get("kind", "")
        current_yaml = params.get("current_yaml", "")
        changes = params.get("changes", {})
        if isinstance(changes, str):
            try:
                changes = json.loads(changes)
            except Exception:
                changes = {}
        if not kind or not current_yaml:
            return {"error": "kind and current_yaml are required for patch"}
        return patch_cr(kind, current_yaml, changes)

    return {"error": f"unknown action: {action}; use 'scaffold' or 'patch'"}
