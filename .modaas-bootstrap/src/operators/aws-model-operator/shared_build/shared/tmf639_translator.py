"""AgentCore CUSTOM record → TMF639 v5 LogicalResource translator.

Reverse direction of tmf639_client._build_resource. Used by the UI's
TMF639 read server (W3.A) to expose AgentCore-stored governance metadata in
TMF639-conformant wire format.

Architectural context: AgentCore is canonical store; TMF639 v5 is canonical
contract. This module is the bridge.
"""
import json
import logging
from typing import Optional

logger = logging.getLogger("modaas.tmf639_translator")


# AgentCore status → (TMF639 operationalState, resourceStatus)
_STATUS_MAP = {
    "APPROVED":   ("enabled",  "approved"),
    "PAUSED":     ("disabled", "paused"),
    "RETIRED":    ("disabled", "retired"),
    "DEPRECATED": ("disabled", "deprecated"),
    "PENDING":    ("disabled", "pending"),
    "VALIDATING": ("disabled", "pending"),
    "FAILED":     ("disabled", "failed"),
}


def agentcore_status_to_tmf639(status: str) -> tuple[str, str]:
    """Map AgentCore record status to (operationalState, resourceStatus) pair."""
    return _STATUS_MAP.get((status or "").upper(), ("disabled", "unknown"))


# Provider prefix → TMF639 category
_PROVIDER_PREFIX_TO_CATEGORY = {
    "aws-bedrock":       "Model",
    "aws-sagemaker":     "Model",
    "agentcoregateway":  "Tool",
    "awsagentcore":      "Agent",
    "a2a":               "Agent",
    "openai-direct":     "Model",
    "anthropic-direct":  "Model",
}


def _infer_category(name: str) -> str:
    """Derive TMF639 category from AgentCore record name's provider prefix."""
    if "_" not in name:
        return "Unknown"
    prefix = name.split("_", 1)[0]
    return _PROVIDER_PREFIX_TO_CATEGORY.get(prefix, "Unknown")


def _strip_prefix(name: str) -> str:
    """Strip provider_ prefix from display name."""
    if "_" not in name:
        return name
    return name.split("_", 1)[1]


def agentcore_record_to_tmf639(record: dict) -> dict:
    """Translate AgentCore CUSTOM record → TMF639 v5 LogicalResource.

    If inlineContent contains a TMF639-shaped object (forward translator output),
    use it directly. Otherwise, fall back to AgentCore-native fields.

    Never throws — malformed JSON or empty inlineContent both produce a valid
    minimal LogicalResource based on AgentCore-native fields.
    """
    name = record.get("name", "")
    inline = (record.get("descriptors") or {}).get("custom", {}).get("inlineContent", "{}")
    try:
        meta = json.loads(inline)
    except (json.JSONDecodeError, TypeError):
        logger.warning("Malformed inlineContent on record %s; falling back to AgentCore fields", name)
        meta = {}

    category = _infer_category(name)
    display_name = _strip_prefix(name)

    # If inlineContent is a TMF639-shaped Resource (forward translator output),
    # prefer its fields; otherwise build minimal from AgentCore status.
    if meta.get("@type") == "LogicalResource":
        # Forward translator's output — use it directly with name updated
        return {**meta, "name": display_name}

    op_state, res_status = agentcore_status_to_tmf639(record.get("status", ""))

    chars = []
    # Surface common metadata as resourceCharacteristic
    for k, v in (meta.get("capabilities") or {}).items():
        if isinstance(v, (str, int, float, bool)):
            chars.append({
                "name": f"capabilities.{k}",
                "value": v,
                "valueType": _infer_value_type(v),
            })
    # Governance characteristics
    for k, v in (meta.get("governance") or {}).items():
        if isinstance(v, (str, int, float, bool)):
            chars.append({
                "name": f"governance.{k}",
                "value": v,
                "valueType": _infer_value_type(v),
            })
    # safetyAttestation group (if present in inline metadata)
    safety = meta.get("safetyAttestation") or {}
    for k, v in safety.items():
        if isinstance(v, (str, int, float, bool)):
            chars.append({
                "name": f"safetyAttestation.{k}",
                "value": v,
                "valueType": _infer_value_type(v),
            })
    # componentRef group
    comp_ref = meta.get("componentRef") or {}
    for k, v in comp_ref.items():
        if isinstance(v, (str, int, float, bool)):
            chars.append({
                "name": f"componentRef.{k}",
                "value": v,
                "valueType": _infer_value_type(v),
            })

    return {
        "@type": "LogicalResource",
        "id": name,
        "name": display_name,
        "category": category,
        "description": record.get("description")
                       or meta.get("description")
                       or f"MoDaaS-governed {category}: {display_name}",
        "operationalState": op_state,
        "resourceStatus": res_status,
        "externalIdentifier": [
            {"externalIdentifierType": "modaas-registry-key", "id": name},
        ],
        "resourceCharacteristic": chars,
        "resourceSpecification": {
            "@type": "ResourceSpecificationRef",
            "name": f"MoDaaS-{category}",
            "category": category,
        },
    }


def _infer_value_type(value) -> str:
    """Infer TMF639 v5 valueType from Python value."""
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    return "string"
