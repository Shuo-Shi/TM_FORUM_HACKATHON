"""Single source of truth for AWS Agent Registry record-name (registryRecordId) construction.

Closes Finding #1 (2026-06-16). Before this module, four builder sites
(``asset_operator._register_in_registry`` / ``_deprecate_in_registry`` /
the resync key at ``_resync_registry_status``; and ``model_operator``'s own
separate builder) constructed the registry record name as
``f"{provider_norm}_{asset_id}"`` while normalizing ONLY the ``provider`` half
and leaving ``asset_id`` (``spec.alias`` / ``spec.toolName`` / ``spec.agentName``)
**raw**. Because ``spec.agentName`` admits underscores and uppercase
(``agentconfig`` pattern ``^[a-zA-Z0-9]([-_a-zA-Z0-9]*[a-zA-Z0-9])?$``), an agent
named e.g. ``noc_triage_agent`` produced ``awsagentcore_noc_triage_agent``, which
fails the AgentConfig ``status.registryRecordId`` pattern -> the API server
422-rejects the operator's status patch and the asset never reaches Approved
cleanly. ``gitlab/main`` (commit ``bcf62fa``) normalized the asset_id half; the
``tmf-crd-review-2026-06-12`` branch regressed it. This restores the normalizer
behind ONE canonical contract.

The implementation mirrors the proven v2 sanitizer at
``operators/modaas-operator/base/registry_client.py`` (``_sanitize_segment``):
lowercase -> ``_``->``-`` -> collapse runs -> strip -> ``x-`` prefix if the
segment does not start with a letter.

``CANONICAL_RECORD_ID`` is referenced VERBATIM by all three governed-asset CRDs'
``status.registryRecordId.pattern`` (modelconfig / toolconfig / agentconfig), so
the contract is single-sourced. The ``x-`` leading-alpha guard makes the
builder's output domain a SUBSET of the validator's accept-set BY CONSTRUCTION:
every value this module mints satisfies ``CANONICAL_RECORD_ID``. The roundtrip
test (``operators/shared/tests/test_record_name_normalization.py``) proves it.
"""

import re

# ONE canonical pattern. Both halves are leading-alpha. Referenced byte-identically
# by crds/{modelconfig,toolconfig,agentconfig}-v1beta1-crd.yaml
# status.registryRecordId.pattern. Do NOT diverge any of the three from this string
# without updating this constant and re-running the Class-C roundtrip verifier
# (tests/integration/verifiers/class_c_record_id_roundtrip.py).
CANONICAL_RECORD_ID = re.compile(r"^[a-z][a-z0-9-]*_[a-z][a-z0-9-]*$")

# The literal pattern string the CRDs must carry verbatim (regex source minus the
# compiled object), exposed so the contract verifier can assert byte-equality.
CANONICAL_RECORD_ID_PATTERN = r"^[a-z][a-z0-9-]*_[a-z][a-z0-9-]*$"


def _sanitize_segment(segment: str) -> str:
    """Normalize one segment (provider or asset_id) to a leading-alpha,
    lowercase, hyphen-only token fitting half of CANONICAL_RECORD_ID.

    Mirrors operators/modaas-operator/base/registry_client.py::_sanitize_segment.
    """
    s = (segment or "").lower().replace("_", "-")
    s = re.sub(r"[^a-z0-9-]", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    if not s or not s[0].isalpha():
        # Guarantee leading-alpha so the joined name satisfies CANONICAL_RECORD_ID
        # (also covers empty/digit-leading/all-stripped inputs).
        s = "x-" + s if s else "x"
    return s


def registry_record_id(provider: str, asset_id: str) -> str:
    """Build the canonical ``<provider>_<asset_id>`` registry record name.

    Both halves are sanitized identically; the result is validated against
    CANONICAL_RECORD_ID. The defensive ValueError should be unreachable given the
    sanitizer's leading-alpha guard — it exists to fail loudly rather than mint a
    name the API server would silently 422-reject on the status patch.
    """
    name = f"{_sanitize_segment(provider)}_{_sanitize_segment(asset_id)}"
    if not CANONICAL_RECORD_ID.match(name):  # pragma: no cover - defensive
        raise ValueError(f"constructed registryRecordId fails canonical pattern: {name!r}")
    return name


def asset_id_from_spec(spec: dict) -> str:
    """Resolve the raw asset identifier from a governed-asset spec.

    ModelConfig uses ``alias``, ToolConfig uses ``toolName``, AgentConfig uses
    ``agentName``. Returns the RAW value (callers that need a registry key must
    pass it through ``registry_record_id``; callers that need the human-facing
    identifier — TMF639 projection, metadata — use it as-is).
    """
    return (
        spec.get("alias")
        or spec.get("toolName")
        or spec.get("agentName")
        or "unknown"
    )
