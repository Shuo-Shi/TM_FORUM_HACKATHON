import time
"""shared/guardrails.py — single source of truth for Bedrock guardrail provisioning.

Used by:
  - aws-model-operator (a design note bedrockGuardrail path)
  - aws-model-operator (a design note bedrockGuardrailExternal path)
  - aws-tool-operator (a design note bedrockGuardrailExternal on tool boundaries) [future]

Idempotency contract:
  create_guardrail(alias, region, cfg) -> (guardrailId, version)
  - If guardrail named canvas-<alias> exists -> update + new version
  - Else -> create + first version

Translates CRD-friendly keys -> AWS Bedrock API keys:
  contentPolicy             -> contentPolicyConfig
  topicPolicy               -> topicPolicyConfig
  piiPolicy                 -> sensitiveInformationPolicyConfig (AWS rename)
  wordPolicy                -> wordPolicyConfig
  contextualGroundingPolicy -> contextualGroundingPolicyConfig
"""
import logging
from typing import Optional

from botocore.exceptions import ClientError

logger = logging.getLogger("shared.guardrails")

#: a design note capability ids. Control-plane guardrail provisioning and the
#: data-plane dry-run are DIFFERENT capabilities served by different services,
#: which is why they were two caches here before and two ids now.
CONTROL_CAPABILITY = "bedrock.control"
RUNTIME_CAPABILITY = "bedrock.runtime"


def _aws_clients():
    """The a design note capability factory, canonical spelling first (in-tree) then
    the pod-snapshot spelling — two module objects would mean two caches."""
    try:
        from operators.shared import aws_clients  # noqa: PLC0415
    except ImportError:  # pragma: no cover - pod snapshot path
        from shared import aws_clients  # noqa: PLC0415
    return aws_clients


def _bedrock_client(region: str, endpoint_url: Optional[str] = None):
    """Bedrock control-plane client for guardrail provisioning.

    The per-(region, endpoint_url) cache this function used to hold itself now
    lives in aws_clients, keyed on (capability, region, endpoint_url) — same
    cache shape, one implementation.
    """
    return _aws_clients().client(
        CONTROL_CAPABILITY, region, endpoint_url=endpoint_url
    )


def _bedrock_runtime_client(region: str, endpoint_url: Optional[str] = None):
    """Bedrock data-plane client for the guardrail dry-run (ApplyGuardrail).

    A separate capability from _bedrock_client on purpose: guardrail
    provisioning is a `bedrock` control-plane call, the dry-run is a
    `bedrock-runtime` data-plane one, and they can be permissioned, endpointed
    and relocated independently.
    """
    return _aws_clients().client(
        RUNTIME_CAPABILITY, region, endpoint_url=endpoint_url
    )


_POLICY_MAP: dict = {
    "contentPolicy": {"inner": {"filters": "filtersConfig"}},
    "topicPolicy": {"inner": {"topics": "topicsConfig"}},
    "piiPolicy": {
        "outerApi": "sensitiveInformationPolicyConfig",
        "inner": {"entities": "piiEntitiesConfig"},
    },
    "wordPolicy": {
        "inner": {
            "words": "wordsConfig",
            "managedWordLists": "managedWordListsConfig",
        },
    },
    "contextualGroundingPolicy": {"inner": {"filters": "filtersConfig"}},
    # T10 (sprint 2026-09 Lane E) — automatedReasoningPolicy has no CRD-vs-API
    # inner-key rename (unlike piiPolicy); the outer key alone differs, same
    # shape as contentPolicy/topicPolicy's outerApi-less entries but with an
    # explicit outerApi since the CRD-friendly name drops "Config" like every
    # other entry in this map. No "inner" translation needed: the AWS API's
    # automatedReasoningPolicyConfig takes policies (a list of policy ARN +
    # optional confidenceThreshold) verbatim from the CRD shape.
    "automatedReasoningPolicy": {
        "outerApi": "automatedReasoningPolicyConfig",
        "inner": {},
    },
}


def _translate_policy(policy: dict, inner_map: dict) -> dict:
    out = {k: v for k, v in policy.items() if k not in inner_map}
    for crd_inner, api_inner in inner_map.items():
        if crd_inner in policy:
            out[api_inner] = policy[crd_inner]
    return out


def _build_policy_kwargs(cfg: dict) -> dict:
    out: dict = {}
    for crd_key, spec in _POLICY_MAP.items():
        if cfg.get(crd_key):
            api_outer = spec.get("outerApi", f"{crd_key}Config")
            out[api_outer] = _translate_policy(cfg[crd_key], spec["inner"])
    return out


def _build_top_level_kwargs(cfg: dict) -> dict:
    """T10 — top-level (non-policy) CreateGuardrail/UpdateGuardrail kwargs.

    crossRegionConfig is a SIBLING of the policy configs on both APIs (verified
    against the installed botocore CreateGuardrail/UpdateGuardrail input shapes
    — both list crossRegionConfig alongside contentPolicyConfig etc, not nested
    under any policy), so it does not belong in _POLICY_MAP/_build_policy_kwargs;
    it is passed through verbatim (single required inner key,
    guardrailProfileIdentifier, no CRD-vs-API rename needed).
    """
    out: dict = {}
    if cfg.get("crossRegionConfig"):
        out["crossRegionConfig"] = dict(cfg["crossRegionConfig"])
    return out



TAG_CONFIG_HASH = "modaas-config-hash"
TAG_PUBLISHED_VERSION = "modaas-published-version"


def _config_fingerprint(kwargs: dict) -> str:
    """Stable hash of the guardrail config MoDaaS asked for.

    Only the request is hashed. Hashing the API's view instead would compare server-side defaults
    that were never requested, so every reconcile would look like a change and publish a version.
    """
    import hashlib
    import json as _json

    payload = _json.dumps(kwargs, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _read_state_tags(client, arn: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Return (configHash, publishedVersion) from guardrail tags, or (None, None).

    Never raises: a tag read failure must not block reconcile. It only costs one extra version.
    """
    if not arn:
        return None, None
    try:
        tags = client.list_tags_for_resource(resourceARN=arn).get("tags", [])
    except ClientError as e:
        logger.warning("could not read guardrail tags on %s: %s", arn, e)
        return None, None
    flat = {t.get("key"): t.get("value") for t in tags if isinstance(t, dict)}
    return flat.get(TAG_CONFIG_HASH), flat.get(TAG_PUBLISHED_VERSION)


def _write_state_tags(client, arn: Optional[str], cfg_hash: str, version: str) -> None:
    """Record the published config hash and version on the guardrail. Never raises."""
    if not arn:
        return
    try:
        client.tag_resource(
            resourceARN=arn,
            tags=[
                {"key": TAG_CONFIG_HASH, "value": cfg_hash},
                {"key": TAG_PUBLISHED_VERSION, "value": str(version)},
            ],
        )
    except ClientError as e:
        logger.warning("could not tag guardrail %s: %s", arn, e)

def create_guardrail(
    alias: str,
    region: str,
    cfg: dict,
    endpoint_url: Optional[str] = None,
) -> tuple[str, str]:
    """Create-or-update a Bedrock guardrail named canvas-<alias>.
    Returns (guardrailId, version) — version is always returned as a string.
    """
    client = _bedrock_client(region, endpoint_url)
    name = f"canvas-{alias}"

    common_kwargs = {
        "name": name,
        "description": f"MoDaaS guardrail for {alias}",
        "blockedInputMessaging":   cfg.get("blockedInputMessaging",   "Input blocked by policy."),
        "blockedOutputsMessaging": cfg.get("blockedOutputsMessaging", "Output blocked by policy."),
    }
    common_kwargs.update(_build_policy_kwargs(cfg))
    common_kwargs.update(_build_top_level_kwargs(cfg))

    # IDEMPOTENCY (G29). This previously called update_guardrail + create_guardrail_version on EVERY
    # reconcile, with no desired-vs-actual comparison. Bedrock caps versions per guardrail, so a
    # ModelConfig reconciled ~20 times — a normal week, since @kopf.on.resume fires for every CR on
    # operator startup — hit:
    #     ServiceQuotaExceededException ... CreateGuardrailVersion ... exceeded the service quota
    # and the asset became PERMANENTLY unreconcilable, stuck at phase=Pending/Provisioning. The
    # control that makes the model plane safe was also what bricked it.
    #
    # A new version is now published only when the desired config actually changes. The decision is
    # made from a hash carried in the guardrail's own tags rather than by diffing the API's response
    # against our request, because the API echoes back server-side defaults (tiers, etc.) that never
    # appear in the request and would make every comparison look like a change.
    cfg_hash = _config_fingerprint(common_kwargs)

    paginator = client.get_paginator("list_guardrails")
    for page in paginator.paginate():
        for gr in page.get("guardrails", []):
            if gr.get("name") == name:
                gr_id = gr["id"]
                gr_arn = gr.get("arn")
                prior_hash, prior_version = _read_state_tags(client, gr_arn)
                if prior_hash == cfg_hash and prior_version:
                    logger.info(
                        "guardrail %s config unchanged (hash %s) — reusing version %s, "
                        "not publishing a new one",
                        gr_id, cfg_hash[:12], prior_version,
                    )
                    return gr_id, str(prior_version)
                update_kwargs = dict(common_kwargs)
                update_kwargs["guardrailIdentifier"] = gr_id
                try:
                    client.update_guardrail(**update_kwargs)
                except ClientError as e:
                    logger.warning(f"update_guardrail failed for {gr_id}: {e}")
                ver_resp = client.create_guardrail_version(guardrailIdentifier=gr_id)
                version = str(ver_resp["version"])
                _write_state_tags(client, gr_arn, cfg_hash, version)
                return gr_id, version

    resp = client.create_guardrail(**common_kwargs)
    gr_id = resp["guardrailId"]
    ver_resp = client.create_guardrail_version(guardrailIdentifier=gr_id)
    version = str(ver_resp["version"])
    _write_state_tags(client, resp.get("guardrailArn"), cfg_hash, version)
    return gr_id, version


# ── T7 (sprint 2026-09 Lane E) — post-translation guardrail dry-run ──
#
# API choice: ApplyGuardrail (bedrock-runtime), NOT "InvokeGuardrailChecks".
#
# The sprint card and the dispatching task both name the target operation as
# InvokeGuardrailChecks. That operation does not exist: a scan of every
# installed bedrock* service model (bedrock, bedrock-agent,
# bedrock-agent-runtime, bedrock-agentcore, bedrock-agentcore-control,
# bedrock-data-automation, bedrock-data-automation-runtime, bedrock-runtime;
# boto3 1.42.93 / botocore 1.42.93) for any operation name containing
# "GuardrailChecks" or "InvokeGuardrail" returns zero matches. This is the
# exact failure class Coherence Rule 15 exists to prevent (CL-C C4 walked
# dead registry op names for 3 weeks before someone checked dir(client)) —
# so the check was done here via the real service model before writing any
# call, not inferred from the task text.
#
# ApplyGuardrail (bedrock-runtime.apply_guardrail) is the correct, existing
# operation for this purpose: it evaluates arbitrary "content" against a
# specific (guardrailIdentifier, guardrailVersion) WITHOUT invoking a model —
# exactly the "canary content against the ensured guardrail" dry-run this
# task asks for. Confirmed against the installed botocore's real input shape:
# required guardrailIdentifier, guardrailVersion, source ('INPUT'|'OUTPUT'),
# content (list of {text: {text: str}} blocks); output has action
# ('NONE'|'GUARDRAIL_INTERVENED') and actionReason. The bedrockGuardrailExternal
# enforcer path (a design note) already calls this exact API at runtime, so this
# dry-run exercises the identical wire contract the gateway depends on.
#
# Corroboration, not just the SDK scan: deploy/agentgateway/bedrock-irsa-
# permissions-policy.json's AgentgatewayBedrockGuardrail statement grants
# exactly bedrock:ApplyGuardrail + bedrock:GetGuardrail — never any
# "InvokeGuardrailChecks" action — so the IRSA grant the task says "already
# grants bedrock-runtime" is specifically scoped to ApplyGuardrail. There is
# no IAM action name to check for the other candidate; using it would be a
# runtime AccessDenied even with a corrected call.
_DRY_RUN_CANARY_TEXT = "modaas-guardrail-dry-run-canary"


def verify_guardrail_dry_run(
    guardrail_id: str,
    guardrail_version: str,
    region: str,
    endpoint_url: Optional[str] = None,
) -> tuple[bool, str, str]:
    """Detection-only post-translation check: does the ensured guardrail actually
    respond to ApplyGuardrail for (guardrail_id, guardrail_version)?

    Returns (verified, condition_status, reason):
      - verified=True,  status="True",    reason="DryRunPassed"      — guardrail answered normally
                                                                        (action NONE or GUARDRAIL_INTERVENED
                                                                        both count: intervening on canary
                                                                        content is a live, working guardrail —
                                                                        this checks reachability, not policy tuning)
      - verified=False, status="Unknown", reason="AccessDenied"      — IRSA/permissions gap; not a guardrail
                                                                        defect, must not read as broken
      - verified=False, status="False",   reason=<AWS error code>   — guardrail missing/dangling/misconfigured

    Never raises. This is a detection signal for the caller to fold into a
    status condition — it must not change, block, or weaken the existing
    fail-closed enforcement path (a design note/a design note already refuse approval when
    guardrail provisioning itself fails; this runs strictly AFTER that and
    only ever adds information, never denies what provisioning already
    allowed).
    """
    client = _bedrock_runtime_client(region, endpoint_url)
    # Live finding (wave-2 2026-09-02): a version created moments ago answers
    # ValidationException "... is in the CREATING state" for a short window.
    # Bounded retry inside the SAME classification structure; a persistent
    # transient is Unknown/VersionCreating — never False (broken).
    attempts = 3
    for attempt in range(attempts):
        try:
            resp = client.apply_guardrail(
                guardrailIdentifier=guardrail_id,
                guardrailVersion=guardrail_version,
                source="INPUT",
                content=[{"text": {"text": _DRY_RUN_CANARY_TEXT}}],
            )
            action = resp.get("action", "NONE")
            logger.info(
                "guardrail dry-run OK for %s/%s: action=%s",
                guardrail_id, guardrail_version, action,
            )
            return True, "True", "DryRunPassed"
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            message = e.response.get("Error", {}).get("Message", str(e))
            if "CREATING state" in message:
                if attempt < attempts - 1:
                    time.sleep(2 * (attempt + 1))
                    continue
                logger.warning(
                    "guardrail dry-run: %s/%s still CREATING after %d attempts",
                    guardrail_id, guardrail_version, attempts,
                )
                return False, "Unknown", "VersionCreating"
            if code in ("AccessDeniedException", "AccessDenied"):
                # Graceful, not a crash and not a False (broken-guardrail)
                # verdict: a permissions gap says nothing about guardrail
                # health. "Handle AccessDenied gracefully (Unknown + reason)."
                logger.warning(
                    "guardrail dry-run access denied for %s/%s: %s",
                    guardrail_id, guardrail_version, message,
                )
                return False, "Unknown", "AccessDenied"
            logger.warning(
                "guardrail dry-run failed for %s/%s: %s (%s)",
                guardrail_id, guardrail_version, message, code,
            )
            return False, "False", code
        except Exception as e:  # noqa: BLE001 — detection path must never raise into reconcile
            logger.warning(
                "guardrail dry-run raised unexpectedly for %s/%s: %s: %s",
                guardrail_id, guardrail_version, type(e).__name__, e,
            )
            return False, "Unknown", "DryRunError"
    return False, "Unknown", "DryRunError"  # loop exit safety (unreachable)
