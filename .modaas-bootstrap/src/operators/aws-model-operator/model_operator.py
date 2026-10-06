"""
AWS Bedrock Model Operator — ModelConfig v1beta1

Migrated from v1alpha1 (GEPA pass #1 → v1alpha2 → pass #2 → v1alpha3).
Changes vs v1alpha1 operator:
  - Reads `spec.awsBedrock.*` (typed block) instead of `spec.providerConfig.*`
  - Honors `spec.paused` → phase=Paused, skip reconcile
  - Writes status.observedGeneration, status.lastReconciled, status.reason
  - Writes status.daysUntilRetirement + RetirementDue condition
  - `safety.required` (intent) vs status.safetyEnabled (fact)
  - Structured `safety.policyRef` ({kind, name, namespace})

Stage 2 refactor: ModelOperator now extends AssetOperator base class.
kopf handlers remain thin — delegate to ModelOperator instance.
All existing behavior preserved (21 tests are the contract).
"""

import kopf

# a design note Batch I: Registry health timer (shared across operators).
# Kopf peer election prevents duplicate probes when multiple operators
# import this handler.
try:
    import sys, os as _os
    _shared_root = _os.path.abspath(
        _os.path.join(_os.path.dirname(__file__), "..", "..")
    )
    if _shared_root not in sys.path:
        sys.path.insert(0, _shared_root)
    from operators.shared import registry_health  # noqa: F401
    from operators.shared import registry_lifecycle_handlers  # noqa: F401  (T9)
except ImportError:
    pass
import logging
import os
# a design note: no `import boto3` here. Clients come from the capability factory in
# operators/shared/aws_clients.py; the exception types still come from botocore.
from botocore.exceptions import ClientError
from datetime import datetime, timezone, date
from operators.shared.asset_operator import AssetOperator, ProvisioningFailed

# Finding #1: single canonical registry record-name builder (shared with the
# base operator); replaces this module's separate f"{provider}_{alias}" dialect.
try:
    from operators.shared.registry_naming import registry_record_id
except ImportError:  # pragma: no cover - deployed snapshot path
    from registry_naming import registry_record_id

# W4.B: Operator-side OTel instrumentation
try:
    from operators.shared.operator_otel import traced
except ImportError:
    try:
        import sys as _s
        _s.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
        from operators.shared.operator_otel import traced
    except ImportError:
        def traced(*a, **kw):
            """No-op fallback when operator_otel not importable."""
            def _d(fn): return fn
            return _d

# a design note task #175: boto3 auto-instrumentation for CloudWatch GenAI Observability.
# Fail-soft: if opentelemetry-instrumentation-botocore isn't available, the
# operator runs unchanged. Spans are emitted via the OTLP exporter configured
# at runtime (OTEL_EXPORTER_OTLP_ENDPOINT env var) which targets the EKS
# amazon-cloudwatch-observability add-on collector.
try:
    from opentelemetry.instrumentation.botocore import BotocoreInstrumentor
    BotocoreInstrumentor().instrument()
except ImportError:
    pass

GROUP = "oda.tmforum.org"
VERSION = "v1beta1"
PLURAL = "modelconfigs"
PROVIDER = "aws-bedrock"

logger = logging.getLogger("ModelOperator")
logger.setLevel(int(os.environ.get("LOGGING", logging.INFO)))

# Cache one boto3 client per (region, endpoint_url) pair; operator SA
# credentials come from IRSA. endpoint_url is used for VPC/FIPS/custom
# control-plane overrides. Runtime endpoint overrides (for the AI Gateway
# Pod) live in spec.endpoint per the endpoint-placement postmortem
# (docs/archive/Endpoint-Field-Miss-Postmortem.md). The operator only reaches
# Bedrock's control plane (GetFoundationModel, CreateGuardrail, etc.);
# the Gateway Pod handles runtime calls and reads status.endpoint.
#: a design note capability id. The (region, endpoint_url) cache this module held now
#: lives in operators/shared/aws_clients.py, keyed on
#: (capability, region, endpoint_url) — same shape, one implementation, and one
#: place that knows which botocore service serves Bedrock's control plane.
BEDROCK_CAPABILITY = "bedrock.control"


def _aws_clients():
    """The a design note capability factory, canonical spelling first (in-tree) then
    the pod-snapshot spelling — two module objects would mean two caches."""
    try:
        from operators.shared import aws_clients  # noqa: PLC0415
    except ImportError:  # pragma: no cover - pod snapshot path
        from shared import aws_clients  # noqa: PLC0415
    return aws_clients


def _bedrock(region: str, endpoint_url: str | None = None):
    return _aws_clients().client(
        BEDROCK_CAPABILITY, region, endpoint_url=endpoint_url
    )


class ModelOperator(AssetOperator):
    """Concrete AssetOperator for ModelConfig — provisions Bedrock guardrails."""

    @property
    def record_type(self) -> str:
        return "model"

    @property
    def resource_plural(self) -> str:
        return "modelconfigs"

    def _build_registry_metadata(self, spec: dict, status: dict) -> dict:
        """W3.C: Rich metadata for model registry records.

        Populates invocation endpoint, capabilities, governance, safety attestation,
        and componentRef (from W2.A). Mirrors the metadata shape the module-level
        _register_in_registry builds for the kopf handler path.
        """
        md = super()._build_registry_metadata(spec, status)
        caps = spec.get("capabilities", {})
        md["invocation"] = {
            "endpoint": status.get("globalResourceEndpoint", ""),
            "alias": spec.get("alias", ""),
            "protocol": "openai-chat-completions-canvas",
        }
        md["capabilities"] = {
            "features": caps.get("features", []),
            "modalities": caps.get("modalities", []),
            "tier": caps.get("tier"),
        }
        if spec.get("governance"):
            md["governance"] = spec["governance"]
        if status.get("guardrailId"):
            md["safetyAttestation"] = {
                "enforcerKind": spec.get("safety", {}).get("enforcerKind"),
                "safetyEnabled": status.get("safetyEnabled", False),
                "guardrailId": status.get("guardrailId"),
            }
        return md

    def provision_backend(self, spec: dict, status: dict) -> dict:
        """Validate model in Bedrock and create guardrails if needed.

        a design note (2026-05-20): When provider=aws-sagemaker, dispatch to the
        onboard-only SageMaker provider. The SageMaker path validates an
        existing endpoint (no Create/Update/Delete) and then continues into
        the same a design note/a design note enforcer dispatch as Bedrock.

        Gap 9 refactor: Bedrock body lifted into _provision_bedrock so
        provision_backend is a thin dispatch shim parallel to the
        AssetOperator base contract.
        """
        provider = spec.get("provider")
        if provider == "aws-sagemaker":
            return self._provision_sagemaker(spec, status)
        return self._provision_bedrock(spec, status)

    def _attach_guardrail_dry_run(self, result: dict, region: str) -> None:
        """T7 (sprint 2026-09 Lane E) — post-translation guardrail dry-run.

        Detection only: stamps result["guardrailVerified"] (bool) +
        result["guardrailVerifiedReason"] (str) as ordinary status keys, the
        same way every other provision_backend()-computed field flows —
        provision_backend() has no `patch` in scope (only asset_operator.py's
        reconcile() does, via the backend_status merge loop at line ~304), so
        the actual GuardrailVerified condition is set by the kopf handler in
        reconcile() below, which already has patch and already performs this
        exact "read a plain field the backend computed, turn it into a
        condition" translation for AgentgatewayRouteProgrammed. No change to
        asset_operator.py's contract; no new parameter threaded through
        provision_backend()'s signature.

        Off by default (MODAAS_GUARDRAIL_DRY_RUN=true to enable) — same
        opt-in-second-call convention as MODAAS_PROGRAM_AGENTGATEWAY
        (shared/agentgateway_route.py:agentgateway_enabled). Discovered live
        while wiring this up: the six existing test files that reach
        _create_guardrail (test_guardrail_translation.py,
        test_model_lifecycle_transitions.py, test_model_operator.py,
        test_refusal_path.py, test_dd078_enforced_at.py,
        test_dd038_dispatch.py) mock only shared.guardrails._bedrock_client
        (the bedrock CONTROL-plane client used by create_guardrail) — none
        of them anticipated or mock the bedrock-runtime DATA-plane client
        this dry-run needs, so an always-on dry-run made those tests
        transitively issue a REAL ApplyGuardrail network call every run
        (confirmed: it reached AWS and got back a genuine ValidationException
        in ~0.3s, not a local failure — silently caught by verify_guardrail_
        dry_run's ClientError handler, so the suite stayed green while
        quietly depending on network reachability + ambient credentials).
        Gating behind an explicit flag keeps every existing unit test
        hermetic without editing six files' fixtures, and mirrors how this
        codebase already treats "new side-effecting call added to an
        established reconcile path old tests didn't expect."

        A no-op — leaves both keys unset — when this reconcile did not
        provision/attach a guardrail (guardrailId absent: enforcer.kind in
        {none, external, gatewayFilter}, or a bedrockGuardrailExternal BYO
        guardrailId with an empty guardrailVersion default of "DRAFT" is
        still verifiable, so BYO is exercised too).

        MUST NOT raise, block approval, or alter safetyEnabled/safety_fact —
        those are computed and finalized by the caller before this runs.
        """
        gr_id = result.get("guardrailId")
        gr_ver = result.get("guardrailVersion")
        if not gr_id or not gr_ver:
            return
        if os.environ.get("MODAAS_GUARDRAIL_DRY_RUN", "false").lower() not in ("1", "true", "yes"):
            return
        try:
            from shared.guardrails import verify_guardrail_dry_run as _dry_run
        except ModuleNotFoundError:
            import sys as _sys, os as _os
            _shared_root = _os.path.abspath(
                _os.path.join(_os.path.dirname(__file__), "..")
            )
            if _shared_root not in _sys.path:
                _sys.path.insert(0, _shared_root)
            from shared.guardrails import verify_guardrail_dry_run as _dry_run
        try:
            verified, cond_status, reason = _dry_run(gr_id, gr_ver, region)
        except Exception as e:  # noqa: BLE001 — detection path must never fail the reconcile
            logger.warning(
                "T7 guardrail dry-run raised unexpectedly for %s/%s: %s: %s",
                gr_id, gr_ver, type(e).__name__, e,
            )
            verified, cond_status, reason = False, "Unknown", "DryRunError"
        result["guardrailVerified"] = verified
        result["guardrailVerifiedStatus"] = cond_status
        result["guardrailVerifiedReason"] = reason

    def _provision_bedrock(self, spec: dict, status: dict) -> dict:
        """Bedrock provisioning path: foundation-model validate + a design note/a design note
        enforcer dispatch. Extracted from inline provision_backend body during
        Gap 9 refactor."""
        # ── Default path: aws-bedrock ──
        provider = spec.get("provider", "aws-bedrock")
        alias = spec["alias"]
        model_id = spec["modelId"]
        capabilities = spec.get("capabilities", {})
        bedrock_cfg = spec.get("awsBedrock", {})
        region = bedrock_cfg.get("region", "us-west-2")
        safety_intent = spec.get("safety", {}).get("required", False)
        guardrails = bedrock_cfg.get("guardrails")

        # a design note (2026-05-20) — status.endpoint semantic flip.
        # status.endpoint = MoDaaS Gateway URL agents call (governance perimeter).
        # status.upstreamEndpoint = raw Bedrock data plane URL (diagnostics only).
        # Agents MUST NOT call upstreamEndpoint directly — that bypasses MoDaaS.
        try:
            from shared.dependent_api import fallback_perimeter_url
            from shared.wire_format_registry import dialects_for, UnmappedProviderError
        except ModuleNotFoundError:
            from operators.shared.dependent_api import fallback_perimeter_url  # type: ignore
            from operators.shared.wire_format_registry import dialects_for, UnmappedProviderError  # type: ignore
        # Provider-aware path so SageMaker MCs publish /sagemaker/endpoints/<alias>/invocations.
        # U4 (refusal-path): re-raise as ProvisioningFailed so the caller's existing
        # phase=Failed/condition ceremony (asset_operator.py) handles the refusal.
        try:
            _wf = dialects_for(provider)[0]
        except UnmappedProviderError as e:
            raise ProvisioningFailed("ProviderNotRoutable", str(e))
        upstream_endpoint = spec.get("endpoint") or f"https://bedrock-runtime.{region}.amazonaws.com"
        # Operator uses default regional control-plane URL for all control-plane calls
        # (GetFoundationModel, CreateGuardrail). endpoint_url=None => boto3 resolves default.
        control_plane_url = None

        # Validate model
        # ─── M-4 Provisioned Throughput ARN pass-through ───
        # Per docs/archive/2026-05-06-Operator-Transparency-Audit.md §M-4. When the user
        # declares spec.awsBedrock.provisionedThroughputArn, that ARN is the actual
        # invocation identity — bedrock:InvokeModel and Converse accept a Provisioned
        # Throughput ARN in place of modelId. We still call get_foundation_model on
        # the declared modelId to validate the underlying base model is available
        # in-region, but the caller-facing resolvedModelId is the throughput ARN.
        provisioned_throughput_arn = bedrock_cfg.get("provisionedThroughputArn")

        # ─── Custom Model Import validation (a design note) ───
        # An imported model (Bedrock Custom Model Import) is NOT in the foundation-
        # model catalog, so GetFoundationModel raises ValidationException for it.
        # It must be validated with GetImportedModel instead. We take this branch
        # when the modelId is an imported-model ARN, or when the CR declares
        # apiMode: invokeModel (the wire format Qwen3 imports require — Bedrock has
        # no Converse support for them; the dataplane resolves Converse support per provider).
        # Imported models have no inferenceTypesSupported / inference-profile concept:
        # the modelId ARN IS the invocation identity, used verbatim by InvokeModel.
        is_imported = ("imported-model/" in model_id) or (bedrock_cfg.get("apiMode") == "invokeModel")
        if is_imported:
            try:
                _bedrock(region, control_plane_url).get_imported_model(modelIdentifier=model_id)
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("ResourceNotFoundException", "ValidationException"):
                    raise ProvisioningFailed(
                        "ModelNotFound",
                        f"imported model {model_id} not available in {region}: {code}")
                raise ProvisioningFailed(
                    "ImportedModelValidationError",
                    f"could not validate imported model {model_id} in {region}: {code}")
            invocation_model_id = provisioned_throughput_arn or model_id
        else:
            try:
                fm_resp = _bedrock(region, control_plane_url).get_foundation_model(modelIdentifier=model_id)
            except ClientError as e:
                raise ProvisioningFailed("ModelNotFound",
                                         f"{model_id} not available in {region}: {e.response['Error']['Code']}")

            # Resolve invocation ID:
            #   1. If provisionedThroughputArn declared → use it (M-4 transparent pass-through)
            #   2. Else if on-demand not supported but INFERENCE_PROFILE is → us.<modelId>
            #   3. Else → plain modelId
            inference_types = fm_resp.get("modelDetails", {}).get("inferenceTypesSupported", [])
            if provisioned_throughput_arn:
                invocation_model_id = provisioned_throughput_arn
            elif "ON_DEMAND" not in inference_types and "INFERENCE_PROFILE" in inference_types:
                invocation_model_id = f"us.{model_id}"
            else:
                invocation_model_id = model_id

        classifications = _classify_model(model_id, capabilities)
        model_type = classifications[0]

        result = {
            "resolvedModelId": invocation_model_id,
            "modelClassifications": classifications,
            "modelType": model_type,
            # R1 fix (dataplane cutover, 2026-09-01): "endpoint" is
            # intentionally ABSENT. compute_and_publish_perimeter_url is the
            # SINGLE writer of status.endpoint (Coherence Rule 22); this
            # backend result is merged over patch.status AFTER the perimeter
            # writer runs, so returning an endpoint here silently downgraded
            # the published public URL to the mesh fallback (and, on the
            # SageMaker path, to a dead host).
            "upstreamEndpoint": upstream_endpoint,  # diagnostics: raw Bedrock URL
        }

        # Safety: intent vs fact
        safety_fact = False

        # a design note — enforcer dispatch. Defaults to legacy bedrockGuardrail path
        # when absent. Truthfulness invariant enforced at reconcile-time:
        # refuse to approve if we cannot honor the declared kind.
        safety_spec = spec.get("safety", {}) or {}
        enforcer = safety_spec.get("enforcer") or {}
        enforcer_kind = enforcer.get("kind")

        # Backward compat: if no enforcer declared and we have inline
        # awsBedrock.guardrails, synthesize enforcer.kind=bedrockGuardrail.
        if not enforcer_kind:
            enforcer_kind = "bedrockGuardrail" if guardrails else "none"

        result["enforcerKind"] = enforcer_kind

        # a design note — enforcement DRIVER axis. `enforcedAt` names which driver
        # realizes the enforcer; `self` (default) = the MoDaaS AI Gateway, the
        # current behavior. CEL already refuses bedrockGuardrail + non-self at
        # admission; we mirror that here as defense-in-depth at reconcile.
        # status.enforcedAt is NOT echoed from spec here (U5/observed-path-status
        # removed that) — it is populated only by record_observed_path's genuine
        # dataplane observation, in the agentgateway block below.
        enforced_at = enforcer.get("enforcedAt", "self")
        if enforced_at != "self" and enforcer_kind == "bedrockGuardrail":
            raise ProvisioningFailed(
                "EnforcementDriverUnsupported",
                f"enforcer.kind=bedrockGuardrail (in-Converse) cannot be federated to "
                f"enforcedAt='{enforced_at}'; use bedrockGuardrailExternal or gatewayFilter (a design note)",
            )

        # Per-kind dispatch — the operator either provisions the backing, or
        # refuses approval with a clear reason.
        if enforcer_kind == "bedrockGuardrail":
            # AWS-native path. Provider must be aws-bedrock.
            if spec.get("provider") != "aws-bedrock":
                raise ProvisioningFailed(
                    "SafetyEnforcerUnsupported",
                    f"enforcer.kind=bedrockGuardrail requires provider=aws-bedrock, got '{spec.get('provider')}'",
                )
            if safety_intent and guardrails:
                gr_id, gr_ver = _create_guardrail(alias, region, guardrails, control_plane_url)
                result["guardrailId"] = gr_id
                result["guardrailVersion"] = gr_ver
                safety_fact = True
            elif safety_intent and not guardrails:
                raise ProvisioningFailed(
                    "NoGuardrailConfig",
                    "safety.required=true + enforcer.kind=bedrockGuardrail requires awsBedrock.guardrails",
                )
        elif enforcer_kind == "bedrockGuardrailExternal":
            # ── a design note (2026-05-20) — Provider-Agnostic Guardrail Enforcement ──
            # Bedrock guardrail invoked via ApplyGuardrail standalone API,
            # decoupled from model invocation. Works for ANY provider
            # (aws-sagemaker, ollama, vllm, databricks, etc.). The guardrail
            # itself is still a Bedrock control-plane resource — what differs
            # is HOW the gateway invokes it at request time.
            #
            # Modes:
            #   - inline awsBedrock.guardrails policy → operator provisions
            #   - BYO guardrailId in enforcer.bedrockGuardrailExternal.guardrailId
            #     → operator uses without provisioning
            #
            # Truthfulness invariant: gateway must advertise this kind on
            # /v1/capabilities; operator refuses approval otherwise (a design note).
            from gateway_capability import check_enforcer_supported
            supported, skew_reason = check_enforcer_supported("bedrockGuardrailExternal")
            if not supported:
                raise ProvisioningFailed("GatewayVersionSkew", skew_reason)

            ext_cfg = enforcer.get("bedrockGuardrailExternal") or {}
            byo_id = ext_cfg.get("guardrailId")

            # Region: prefer enforcer.bedrockGuardrailExternal.region; fall
            # back to awsBedrock.region (Bedrock is a regional control plane).
            gr_region = ext_cfg.get("region") or region
            apply_to = ext_cfg.get("applyTo") or ["input", "output"]

            if byo_id:
                # BYO guardrail — use the provided ID without provisioning
                result["guardrailId"] = byo_id
                result["guardrailVersion"] = ext_cfg.get("guardrailVersion", "DRAFT")
            elif guardrails:
                # Inline policy — provision via shared module.
                # Same sys.path shim as a design note batch I (lines 24-32) — operators/
                # is the parent of shared/, and aws-model-operator imports its
                # siblings via the operators-root parent path.
                try:
                    from shared.guardrails import create_guardrail as _shared_create
                except ModuleNotFoundError:
                    import sys as _sys, os as _os
                    _shared_root = _os.path.abspath(
                        _os.path.join(_os.path.dirname(__file__), "..")
                    )
                    if _shared_root not in _sys.path:
                        _sys.path.insert(0, _shared_root)
                    from shared.guardrails import create_guardrail as _shared_create
                gr_id, gr_ver = _shared_create(alias, gr_region, guardrails, control_plane_url)
                result["guardrailId"] = gr_id
                result["guardrailVersion"] = gr_ver
            else:
                raise ProvisioningFailed(
                    "NoGuardrailConfig",
                    "enforcer.kind=bedrockGuardrailExternal requires either "
                    "spec.awsBedrock.guardrails (inline policy) or "
                    "spec.safety.enforcer.bedrockGuardrailExternal.guardrailId (BYO)",
                )
            result["guardrailRegion"] = gr_region
            result["enforcerApplyTo"] = apply_to
            safety_fact = True

        elif enforcer_kind == "external":
            # Version-skew guard (#1): the operator may be on a newer image
            # than the gateway. Refuse approval if the gateway doesn't
            # advertise support for this enforcer kind. Fail-closed.
            from gateway_capability import check_enforcer_supported
            supported, reason = check_enforcer_supported("external")
            if not supported:
                raise ProvisioningFailed("GatewayVersionSkew", reason)

            # Customer-owned safety service. Operator does not provision —
            # just echoes endpoint config to status for gateway consumption.
            ext = enforcer.get("external") or {}
            endpoint_url = ext.get("endpoint")
            if not endpoint_url:
                raise ProvisioningFailed(
                    "SafetyEnforcerInvalid",
                    "enforcer.kind=external requires safety.enforcer.external.endpoint",
                )
            result["enforcerEndpoint"] = endpoint_url
            result["enforcerTimeoutMs"] = int(ext.get("timeoutMs", 500))
            result["enforcerFailOpen"] = bool(ext.get("failOpen", False))
            # safety_fact=True because we have a real enforcer (the external service)
            safety_fact = bool(safety_intent)

        elif enforcer_kind == "gatewayFilter":
            # Schema-reserved but not yet implemented by MoDaaS AI Gateway.
            # Truthfulness invariant: refuse approval rather than silently
            # advertise safety we cannot enforce.
            raise ProvisioningFailed(
                "SafetyEnforcerUnsupported",
                "enforcer.kind=gatewayFilter is not yet implemented by aws-model-operator. "
                "Use bedrockGuardrail (AWS-native), external (customer service), or "
                "wait for the gatewayFilter implementation.",
            )

        elif enforcer_kind == "none":
            # Opt-out of enforcement. Admission CEL rejects required=true + kind=none,
            # so reaching here means safety_intent must be false.
            if safety_intent:
                # Defense-in-depth; should already have been rejected at admission
                raise ProvisioningFailed(
                    "LyingDeclaration",
                    "safety.required=true cannot be combined with enforcer.kind=none",
                )
            safety_fact = False

        else:
            # Unknown kind — CRD enum should prevent this, but defend anyway
            raise ProvisioningFailed(
                "SafetyEnforcerUnsupported",
                f"enforcer.kind='{enforcer_kind}' is not recognized by aws-model-operator",
            )

        result["safetyEnabled"] = safety_fact
        self._attach_guardrail_dry_run(result, region)
        return result

    def _provision_sagemaker(self, spec: dict, status: dict) -> dict:
        """a design note — onboard-only SageMaker provisioning + a design note safety overlay.

        Steps:
          1. Validate endpoint via providers.sagemaker.provision (read-only).
          2. Run a design note/a design note enforcer dispatch. SageMaker has NO native
             guardrail, so kind=bedrockGuardrail is rejected. Valid kinds:
             bedrockGuardrailExternal, external, gatewayFilter, none.
        """
        # Lazy import to keep optional dependency
        try:
            from providers import sagemaker as sm_provider
        except ModuleNotFoundError:
            import sys as _sys, os as _os
            _here = _os.path.dirname(__file__)
            if _here not in _sys.path:
                _sys.path.insert(0, _here)
            from providers import sagemaker as sm_provider

        alias = spec["alias"]
        awssm = spec.get("awsSageMaker") or {}
        region = awssm.get("region", "us-west-2")
        guardrails_inline = (spec.get("awsBedrock") or {}).get("guardrails")
        safety_spec = spec.get("safety") or {}
        safety_intent = bool(safety_spec.get("required"))
        enforcer = safety_spec.get("enforcer") or {}
        enforcer_kind = enforcer.get("kind")

        # ── 1. Validate the SageMaker endpoint (onboard-only) ──
        result = sm_provider.provision(spec, status)

        # ── 2. Determine enforcer kind (with backward-compat default) ──
        # SageMaker has no native guardrail. If safety is intended without
        # an explicit enforcer kind, refuse — there's no legacy "use
        # awsBedrock.guardrails as in-Converse" fallback for SageMaker.
        if not enforcer_kind:
            enforcer_kind = "none"
        result["enforcerKind"] = enforcer_kind

        if enforcer_kind == "bedrockGuardrail":
            raise ProvisioningFailed(
                "SafetyEnforcerUnsupported",
                "enforcer.kind=bedrockGuardrail (in-Converse) is invalid for "
                "provider=aws-sagemaker (SageMaker has no native guardrail). "
                "Use bedrockGuardrailExternal (a design note) instead.",
            )

        if enforcer_kind == "bedrockGuardrailExternal":
            from gateway_capability import check_enforcer_supported
            supported, skew_reason = check_enforcer_supported("bedrockGuardrailExternal")
            if not supported:
                raise ProvisioningFailed("GatewayVersionSkew", skew_reason)

            ext_cfg = enforcer.get("bedrockGuardrailExternal") or {}
            byo_id = ext_cfg.get("guardrailId")
            gr_region = ext_cfg.get("region") or region
            apply_to = ext_cfg.get("applyTo") or ["input", "output"]

            if byo_id:
                result["guardrailId"] = byo_id
                result["guardrailVersion"] = ext_cfg.get("guardrailVersion", "DRAFT")
            elif guardrails_inline:
                try:
                    from shared.guardrails import create_guardrail as _shared_create
                except ModuleNotFoundError:
                    import sys as _sys, os as _os
                    _shared_root = _os.path.abspath(
                        _os.path.join(_os.path.dirname(__file__), "..")
                    )
                    if _shared_root not in _sys.path:
                        _sys.path.insert(0, _shared_root)
                    from shared.guardrails import create_guardrail as _shared_create
                gr_id, gr_ver = _shared_create(alias, gr_region, guardrails_inline)
                result["guardrailId"] = gr_id
                result["guardrailVersion"] = gr_ver
            else:
                raise ProvisioningFailed(
                    "NoGuardrailConfig",
                    "enforcer.kind=bedrockGuardrailExternal requires either "
                    "spec.awsBedrock.guardrails (inline policy) or "
                    "spec.safety.enforcer.bedrockGuardrailExternal.guardrailId (BYO)",
                )
            result["guardrailRegion"] = gr_region
            result["enforcerApplyTo"] = apply_to
            result["safetyEnabled"] = True

        elif enforcer_kind == "external":
            from gateway_capability import check_enforcer_supported
            supported, reason = check_enforcer_supported("external")
            if not supported:
                raise ProvisioningFailed("GatewayVersionSkew", reason)
            ext = enforcer.get("external") or {}
            endpoint_url = ext.get("endpoint")
            if not endpoint_url:
                raise ProvisioningFailed(
                    "SafetyEnforcerInvalid",
                    "enforcer.kind=external requires safety.enforcer.external.endpoint",
                )
            result["enforcerEndpoint"] = endpoint_url
            result["enforcerTimeoutMs"] = int(ext.get("timeoutMs", 500))
            result["enforcerFailOpen"] = bool(ext.get("failOpen", False))
            result["safetyEnabled"] = bool(safety_intent)

        elif enforcer_kind == "gatewayFilter":
            raise ProvisioningFailed(
                "SafetyEnforcerUnsupported",
                "enforcer.kind=gatewayFilter is reserved but not implemented",
            )

        elif enforcer_kind == "none":
            if safety_intent:
                raise ProvisioningFailed(
                    "LyingDeclaration",
                    "safety.required=true cannot combine with enforcer.kind=none "
                    "(use bedrockGuardrailExternal for SageMaker safety)",
                )
            result["safetyEnabled"] = False

        else:
            raise ProvisioningFailed(
                "SafetyEnforcerUnsupported",
                f"enforcer.kind='{enforcer_kind}' is not recognized for aws-sagemaker",
            )

        # T7's dry-run runs for SageMaker too: bedrockGuardrailExternal is the
        # only guardrail-bearing kind on this path (bedrockGuardrail is
        # rejected above), and it sets guardrailId/guardrailVersion the same
        # way the Bedrock path does — _attach_guardrail_dry_run() is a no-op
        # when neither key is present (none/external/gatewayFilter branches).
        self._attach_guardrail_dry_run(result, region)
        return result

    def deprovision_backend(self, status: dict) -> None:
        """Delete Bedrock guardrail if present (a design note/a design note cleanup).
        Onboard-only: do NOT touch SageMaker / external endpoints."""
        gr_id = (status or {}).get("guardrailId")
        if gr_id:
            # Control-plane URL is region-derived (no override in v1beta1)
            try:
                _bedrock("us-west-2", None).delete_guardrail(guardrailIdentifier=gr_id)
            except ClientError as e:
                logger.warning(f"Guardrail {gr_id} delete failed: {e.response['Error']['Code']}")


# Singleton instance
_model_operator = ModelOperator()



# ── a design note Registry dispatch helpers (Batch G, feature-flagged) ──
def _dispatch_enabled() -> bool:
    import os
    return os.environ.get("MODAAS_REGISTRY_DISPATCH", "legacy").lower() == "enabled"


def _registry_get_client(*args, **kwargs):
    """Single import site for the shared registry client (S8/P9, 2026-09-26).

    The client moved from this operator's own directory to
    `operators/shared/registry_client.py`, so the bare name is gone. Two rules
    this helper exists to keep:

      * ONE dual-import, not three. `operators.shared.*` resolves in-tree;
        `shared.*` is what the image has (the shared_build snapshot is copied to
        /operator/shared and there is no `operators` package alongside it).
        Spelled per call site, the two spellings could bind to two DISTINCT
        module objects with two `_client_cache` dicts.
      * Resolve `get_client` at CALL time. Roughly ten pre-existing suites patch
        `registry_client.get_client`; a module-scope binding captured at import
        would not see the patch.
    """
    try:
        from operators.shared.registry_client import get_client  # noqa: PLC0415
    except ImportError:  # pod image: shared_build snapshot, no `operators` pkg
        from shared.registry_client import get_client  # noqa: PLC0415
    return get_client(*args, **kwargs)


def _dispatch_put_record(record: dict, spec: dict, status: dict, region: str, record_name: str) -> str:
    """Dispatch put_record via a design note if flag enabled, else fall back to legacy."""
    if not _dispatch_enabled():
        resp = _registry_get_client(region).put_record(record)
        return resp.get("name", record_name)
    try:
        # Add shared module to path
        import sys, os as _os
        shared_root = _os.path.abspath(
            _os.path.join(_os.path.dirname(__file__), "..", "..")
        )
        if shared_root not in sys.path:
            sys.path.insert(0, shared_root)
        from operators.shared.resolver import controllers_for, resolve_registry
        from operators.shared.backings import get_backing
        from datetime import datetime, timezone

        backing_kind, params = resolve_registry(
            spec.get("registryRef"), controller=controllers_for("model"),
        )
        backing = get_backing(backing_kind)
        resp = backing.put_record(record, params)
        # Stamp status.registryBackingRef
        status["registryBackingRef"] = {
            "name": (spec.get("registryRef") or {}).get("name", "default"),
            "backing": backing_kind,
            "recordId": resp.get("recordId", record_name),
            "observedAt": datetime.now(timezone.utc).isoformat(),
        }
        return resp.get("name", record_name)
    except Exception as e:
        import logging
        logging.getLogger("ModelOperator").warning(
            f"a design note dispatch failed for {record_name} (falling back to legacy): "
            f"{type(e).__name__}: {e}"
        )
        resp = _registry_get_client(region).put_record(record)
        return resp.get("name", record_name)


def _dispatch_deprecate(record_name: str, spec: dict) -> bool:
    """Dispatch deprecate via a design note if flag enabled. Returns True if handled."""
    if not _dispatch_enabled():
        return False
    try:
        import sys, os as _os
        shared_root = _os.path.abspath(
            _os.path.join(_os.path.dirname(__file__), "..", "..")
        )
        if shared_root not in sys.path:
            sys.path.insert(0, shared_root)
        from operators.shared.resolver import controllers_for, resolve_registry
        from operators.shared.backings import get_backing
        backing_kind, params = resolve_registry(
            spec.get("registryRef"), controller=controllers_for("model"),
        )
        backing = get_backing(backing_kind)
        backing.deprecate(record_name, params)
        return True
    except Exception as e:
        import logging
        logging.getLogger("ModelOperator").warning(
            f"a design note dispatch failed on deprecate for {record_name}: "
            f"{type(e).__name__}: {e}"
        )
        return False


# ── kopf handlers (thin delegation) ──

@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    settings.watching.server_timeout = 60
    # B6.4 (2026-05-20) — Enable kopf peer election so multi-replica
    # deployment is safe. Required for the namespace migration runbook
    # (B2.1) which scales up new pods before scaling down old.
    # Default peering name: kopf-peering. Lock TTL: 60s.
    settings.peering.enabled = True
    settings.peering.lifetime = 60
    settings.peering.priority = 100
    logger.info(
        f"Model Operator started — watching {PLURAL}.{GROUP}/{VERSION} "
        f"(provider: {PROVIDER}, peering: enabled)"
    )


@kopf.on.resume(GROUP, VERSION, PLURAL, retries=5)
@kopf.on.create(GROUP, VERSION, PLURAL, retries=5)
@kopf.on.update(GROUP, VERSION, PLURAL, retries=5)
@traced("operator.model.reconcile", attrs={"operator.kind": "ModelConfig"})
async def reconcile(spec, status, meta, name, namespace, patch, body=None, **_):
    # a design note: aws-model-operator handles provider in {aws-bedrock, aws-sagemaker}.
    # Other providers (custom reconcilers, future) filter out via PROVIDER guard.
    if spec.get("provider") not in ("aws-bedrock", "aws-sagemaker"):
        try:
            from shared.provider_claim import mark_unclaimed
        except ModuleNotFoundError:
            import sys as _s, os as _o
            _r = _o.path.abspath(_o.path.join(_o.path.dirname(__file__), ".."))
            _r in _s.path or _s.path.insert(0, _r)
            from shared.provider_claim import mark_unclaimed
        mark_unclaimed(patch, status, spec.get("provider"), "aws-bedrock|aws-sagemaker")
        return

    # Seed the live conditions before this handler sets any. A status patch
    # REPLACES the whole list, and the blocks below write conditions before
    # the inner reconcile's own seed runs -- which then does nothing because
    # the patch already holds a list. Unseeded, a resume or annotation event on
    # an unchanged CR erased every condition the last full reconcile wrote.
    # After the ownership guard on purpose: mark_unclaimed seeds itself, and a
    # non-owner writing back its snapshot of another operator's conditions
    # would be a lost update of its own.
    # Sensor: operators/shared/tests/test_handlers_keep_conditions.py
    _model_operator._seed_conditions(patch, status)

    # ── a design note (W2.A) — Component emission (Bucket 2) ──
    # ── a design note — IdentityConfig provisioning (W2.B) ──
    # ── a design note — PublishedNotification (later, after phase=Approved) ──
    # W1.A: Each canvas-integration action gets its own try/except that
    # surfaces failures as kopf conditions (not just logger.warning).
    try:
        try:
            from shared.component_owner import ensure_component, SKIP_COMPONENT_ANNOTATION
            from shared.identity_config import ensure_identity_config
        except ModuleNotFoundError:
            import sys as _sys, os as _os
            _shared_root = _os.path.abspath(
                _os.path.join(_os.path.dirname(__file__), "..")
            )
            if _shared_root not in _sys.path:
                _sys.path.insert(0, _shared_root)
            from shared.component_owner import ensure_component, SKIP_COMPONENT_ANNOTATION
            from shared.identity_config import ensure_identity_config
        import kubernetes as _k8s
        try:
            _k8s.config.load_incluster_config()
        except _k8s.config.config_exception.ConfigException:
            _k8s.config.load_kube_config()
        _custom = _k8s.client.CustomObjectsApi()
    except Exception as _import_err:
        logger.warning("Bucket 2 imports failed for %s: %s", name, _import_err)
        _set_condition(
            patch, "OwnedByComponent", "False", "ImportFailed",
            f"Canvas integration modules unavailable: {str(_import_err)[:256]}",
        )
        _custom = None  # skip both a design note and a design note

    # a design note (W2.A): Operator-emitted Component CR per asset.
    # Separate try/except keeps W1.A's failure-visibility pattern.
    if _custom is not None:
        try:
            annotations = (meta or {}).get("annotations") or {}
            skipComponent = annotations.get(SKIP_COMPONENT_ANNOTATION, "").lower() == "true"
            if skipComponent:
                _set_condition(
                    patch, "OwnedByComponent", "False", "ComponentSkipped",
                    "oda.tmforum.org/skipComponent: true — Component emission skipped",
                )
            else:
                comp = ensure_component(
                    k8s_api=_custom,
                    namespace=namespace,
                    source_kind="ModelConfig",
                    source_name=name,
                    source_uid=meta.get("uid", ""),
                )
                comp_meta = comp.get("metadata") or {}
                comp_uid = comp_meta.get("uid", "")
                owner = {
                    "apiVersion": "oda.tmforum.org/v1",
                    "kind": "Component",
                    "name": comp_meta.get("name", name),
                    "uid": comp_uid,
                    "controller": False,
                    "blockOwnerDeletion": True,
                }
                existing = (meta or {}).get("ownerReferences") or []
                if not any(r.get("uid") == comp_uid for r in existing):
                    patch.metadata["ownerReferences"] = list(existing) + [owner]
                patch.status["componentRef"] = {
                    "name": comp_meta.get("name", name),
                    "namespace": namespace,
                    "uid": comp_uid,
                }
                _set_condition(
                    patch, "OwnedByComponent", "True", "ComponentLinked",
                    f"Owned by Component {comp_meta.get('name', name)}",
                )
        except Exception as _owner_err:
            _reason = _classify_k8s_error(_owner_err)
            _set_condition(
                patch, "OwnedByComponent", "False", _reason,
                f"Component emission failed: {str(_owner_err)[:256]}",
            )
            logger.warning("a design note Component emission failed for %s: %s", name, _owner_err)

    # a design note (W2.B): per-asset IdentityConfig — Component as owner for cascade-delete
    if _custom is not None:
        try:
            # W2.B: Use Component as owner_reference (from a design note above).
            # If a design note succeeded, componentRef is in patch.status.
            component_ref = (patch.status or {}).get("componentRef")
            if component_ref and component_ref.get("uid"):
                identity_owner = {
                    "apiVersion": "oda.tmforum.org/v1",
                    "kind": "Component",
                    "name": component_ref["name"],
                    "uid": component_ref["uid"],
                    "controller": True,
                    "blockOwnerDeletion": True,
                }
            else:
                identity_owner = None
            ensure_identity_config(
                k8s_api=_custom,
                namespace=namespace,
                source_kind="ModelConfig",
                source_name=name,
                owner_reference=identity_owner,
            )
            _set_condition(
                patch, "IdentityProvisioned", "True", "IdentityConfigCreated",
                f"IdentityConfig modaas-modelconfig-{name} provisioned via Canvas",
            )
        except Exception as _id_err:
            _reason = _classify_k8s_error(_id_err)
            _set_condition(
                patch, "IdentityProvisioned", "False", _reason,
                f"IdentityConfig provisioning failed: {str(_id_err)[:256]}",
            )
            logger.warning("a design note IdentityConfig failed for %s: %s", name, _id_err)

    # a design note (W2.C): Operator-emitted DependentAPI per wire format
    if _custom is not None:
        try:
            try:
                from shared.dependent_api import (
                    ensure_dependent_api_for_wire_format, get_resolved_url,
                )
                from shared.wire_format_registry import dialects_for, UnmappedProviderError
            except ModuleNotFoundError:
                from operators.shared.dependent_api import (
                    ensure_dependent_api_for_wire_format, get_resolved_url,
                )
                from operators.shared.wire_format_registry import dialects_for, UnmappedProviderError  # type: ignore
            provider = spec.get("provider", "")
            # U4 (refusal-path): catch BEFORE the broad except below, which would
            # otherwise misdiagnose this via _classify_k8s_error as a DependentAPI failure.
            try:
                wire_formats = dialects_for(provider)
            except UnmappedProviderError as e:
                patch.status["phase"] = "Failed"
                _model_operator._emit_phase_change(meta, status, status.get("phase", "Unknown"), "Failed")
                _set_condition(patch, "DependentAPIProvisioned", "False", "ProviderNotRoutable", str(e))
                for _f in ("endpoint", "globalResourceEndpoint", "endpoints", "endpointScope", "dialectEndpoints"):
                    patch.status.pop(_f, None)
                kopf.warn(body, reason="ProviderNotRoutable", message=str(e))
                return
            component_owner = None
            comp_ref = patch.status.get("componentRef") if hasattr(patch, "status") and patch.status else None
            if comp_ref:
                component_owner = {
                    "apiVersion": "oda.tmforum.org/v1",
                    "kind": "Component",
                    "name": comp_ref.get("name"),
                    "uid": comp_ref.get("uid"),
                    "controller": False,
                    "blockOwnerDeletion": True,
                }
            resolved_endpoint = None
            primary_wf = wire_formats[0]
            for wf in wire_formats:
                dep_api = ensure_dependent_api_for_wire_format(
                    k8s_api=_custom, namespace=namespace,
                    asset_name=name, asset_uid=meta.get("uid", ""),
                    provider=provider, wire_format=wf,
                    owner_reference=component_owner,
                )
                if resolved_endpoint is None:
                    url = get_resolved_url(dep_api)
                    if url:
                        resolved_endpoint = url
            if resolved_endpoint:
                patch.status["globalResourceEndpoint"] = resolved_endpoint
                patch.status["endpointScope"] = "public"
                _set_condition(
                    patch, "DependentAPIProvisioned", "True", "DependentAPICreated",
                    f"DependentAPI resolved: {resolved_endpoint}",
                )
            else:
                # a design note layer 2: emit all reachable scopes (mesh/vpc/public)
                # and pick the broadest as the canonical globalResourceEndpoint.
                # Auto-resolves Istio LoadBalancer ELB DNS for public scope so
                # AgentCore Runtime in PUBLIC mode can reach the gateway.
                try:
                    from shared.dependent_api import (
                        compute_all_endpoints, pick_best_endpoint,
                    )
                except ModuleNotFoundError:
                    from operators.shared.dependent_api import (
                        compute_all_endpoints, pick_best_endpoint,
                    )
                alias = spec.get("alias", name)
                _eps = compute_all_endpoints(alias, primary_wf, k8s_api=_custom)
                _best_scope, _best_url = pick_best_endpoint(_eps)
                patch.status["endpoints"] = {k: v for k, v in _eps.items() if v is not None}
                patch.status["globalResourceEndpoint"] = _best_url
                patch.status["endpointScope"] = _best_scope
                _set_condition(
                    patch, "DependentAPIProvisioned", "False", "ResolutionPending",
                    "DependentAPI created; awaiting Canvas canvas-depapi-op resolution",
                )
        except Exception as _dep_err:
            _reason = _classify_k8s_error(_dep_err)
            _set_condition(
                patch, "DependentAPIProvisioned", "False", _reason,
                f"DependentAPI emission failed: {str(_dep_err)[:256]}",
            )
            logger.warning("a design note DependentAPI failed for %s: %s", name, _dep_err)

    # ── W4.D: Egress allowlist for the asset's provider ──
    if "_custom" in dir() and _custom is not None:
        try:
            try:
                from shared.istio_egress import (
                    emit_egress_for_provider,
                    service_entry_name_for,
                )
            except ModuleNotFoundError:
                from operators.shared.istio_egress import (
                    emit_egress_for_provider,
                    service_entry_name_for,
                )
            provider = spec.get("provider", "")
            _egress_region = (spec.get("awsBedrock") or {}).get("region") \
                or (spec.get("awsSageMaker") or {}).get("region") \
                or "us-west-2"
            emit_egress_for_provider(
                k8s_api=_custom, namespace=namespace,
                provider=provider, region=_egress_region,
                owner_reference=None,
            )
            _se_name = service_entry_name_for(provider, _egress_region)
            _set_condition(patch, "EgressAllowlisted", "True", "ServiceEntryCreated",
                           f"ServiceEntry {_se_name} created for {provider} in {_egress_region}")
        except Exception as _eg_err:
            logger.warning("W4.D egress allowlist failed for %s: %s", name, _eg_err)
            _set_condition(patch, "EgressAllowlisted", "False", "EgressFailed",
                           f"Egress allowlist failed: {str(_eg_err)[:256]}")

    # ── Gap 9 refactor: delegate to AssetOperator base ──
    # Coherence Rule 22: publish provider-aware perimeter URL BEFORE
    # super().reconcile() so the base's _register_in_registry sees it in
    # patch.status when building registry metadata.
    try:
        from shared.perimeter_url import compute_and_publish_perimeter_url
        from shared.dependent_api import fallback_perimeter_url
        from shared.wire_format_registry import dialects_for, UnmappedProviderError
    except ModuleNotFoundError:
        from operators.shared.perimeter_url import compute_and_publish_perimeter_url  # type: ignore
        from operators.shared.dependent_api import fallback_perimeter_url  # type: ignore
        from operators.shared.wire_format_registry import dialects_for, UnmappedProviderError  # type: ignore
    _provider = spec.get("provider", "aws-bedrock")
    # U4 (refusal-path): no existing ceremony reachable here (runs before
    # _model_operator.reconcile()) — direct handling, abort this reconcile cycle.
    try:
        _wire_formats = dialects_for(_provider)
    except UnmappedProviderError as e:
        patch.status["phase"] = "Failed"
        _model_operator._emit_phase_change(meta, status, status.get("phase", "Unknown"), "Failed")
        _set_condition(patch, "Provisioned", "False", "ProviderNotRoutable", str(e))
        for _f in ("endpoint", "globalResourceEndpoint", "endpoints", "endpointScope", "dialectEndpoints"):
            patch.status.pop(_f, None)
        kopf.warn(body, reason="ProviderNotRoutable", message=str(e))
        return {"error": "ProviderNotRoutable"}
    _wf = _wire_formats[0]
    _alias = spec.get("alias", name)
    _fallback = fallback_perimeter_url(_alias, _wf)
    compute_and_publish_perimeter_url(
        alias=_alias,
        wire_format=_wf,
        status_patch=patch.status,
        fallback_url=_fallback,
        k8s_api=(_custom if _custom is not None else None),
        all_wire_formats=_wire_formats,
    )

    # Capture prior phase BEFORE delegating, for a design note lifecycle emission.
    _prev_phase = (status or {}).get("phase", "Unknown")

    # Delegate to AssetOperator base. Base handles:
    #   - idempotency / no-op early return
    #   - paused handling
    #   - phase=Pending
    #   - provision_backend dispatch (Bedrock vs SageMaker via Step 1 shim)
    #   - registry projection (a design note)
    #   - phase=Approved + retirement check + TMF639 dual-write
    # meta is a kopf.Body-like; pass as-is. patch is the kopf patch obj.
    _meta = dict(meta) if meta else {}
    _meta.setdefault("name", name)
    _meta.setdefault("namespace", namespace)
    _result = _model_operator.reconcile(spec, dict(status or {}), _meta, patch)

    # U4 (refusal-path): site 1's UnmappedProviderError->ProvisioningFailed
    # re-raise is caught by asset_operator.py's existing ceremony, which
    # returns {"error": e.reason} — read that here for the Warning Event,
    # since body is only in scope in this outer handler.
    # Code-review fix: patch.status["reason"] only ever holds the short
    # reason CODE ("ProviderNotRoutable" — asset_operator.py:300's
    # `patch.status["reason"] = e.reason`), so using it as the Warning
    # Event's own message just echoed the reason back at itself and never
    # named the provider or the remedy — violating BR-6 for this one site
    # while sites 2/3/4/5 (which call kopf.warn with str(e) directly) were
    # unaffected. The full text lives in the "Provisioned" condition's
    # message (asset_operator.py:301's `self._set_condition(patch,
    # "Provisioned", "False", e.reason, str(e))`) — read it from there.
    if isinstance(_result, dict) and _result.get("error") == "ProviderNotRoutable":
        _site1_msg = next(
            (c.get("message") for c in patch.status.get("conditions", [])
             if c.get("type") == "Provisioned" and c.get("reason") == "ProviderNotRoutable"),
            "Provider has no wire-format mapping",
        )
        kopf.warn(body, reason="ProviderNotRoutable", message=_site1_msg)

    # T7 (sprint 2026-09 Lane E) — translate the guardrail dry-run's scratch
    # fields (stamped by _attach_guardrail_dry_run via the ordinary
    # provision_backend()->backend_status merge in asset_operator.py) into a
    # GuardrailVerified status condition, then pop the scratch keys so they
    # don't ALSO persist as bare status.guardrailVerified* fields — the
    # condition is the one committed contract surface here, consistent with
    # how AgentgatewayRouteProgrammed/DependentAPIProvisioned/etc communicate
    # backend-verification outcomes elsewhere in this same handler. No CRD
    # schema change needed for this (Rule 20 is about NEW status.properties.<field>
    # keys; status.conditions[] is already declared as a typed, open-ended
    # array — see crds/modelconfig-v1beta1-crd.yaml's `conditions:` block —
    # so a new condition *type value* inside it needs no schema addition).
    _gr_verified_status = patch.status.pop("guardrailVerifiedStatus", None)
    if _gr_verified_status is not None:
        patch.status.pop("guardrailVerified", None)
        _gr_reason = patch.status.pop("guardrailVerifiedReason", "Unknown")
        _gr_id = patch.status.get("guardrailId", "?")
        _gr_ver = patch.status.get("guardrailVersion", "?")
        if _gr_verified_status == "True":
            _gr_msg = f"ApplyGuardrail dry-run succeeded for guardrail {_gr_id}/{_gr_ver}"
        elif _gr_reason == "AccessDenied":
            _gr_msg = (
                f"ApplyGuardrail dry-run denied (IRSA/permissions) for guardrail "
                f"{_gr_id}/{_gr_ver} — guardrail health unknown, not confirmed broken"
            )
        else:
            _gr_msg = f"ApplyGuardrail dry-run failed for guardrail {_gr_id}/{_gr_ver}: {_gr_reason}"
        _set_condition(patch, "GuardrailVerified", _gr_verified_status, _gr_reason, _gr_msg)

    # a design note — emit PublishedNotification when transitioning into Approved.
    if patch.status.get("phase") == "Approved" and _prev_phase != "Approved":
        _emit_lifecycle(
            name=name, namespace=namespace, event_type="Approved",
            payload={
                "alias": spec.get("alias"),
                "provider": _provider,
                "modelType": patch.status.get("modelType"),
                "safetyEnabled": patch.status.get("safetyEnabled", False),
                "phase": "Approved",
            },
            observed_generation=meta.get("generation", 1),
        )

        # W4.C — Per-asset Istio VS + AuthZ (runs once per Approved transition).
        # Pre-refactor this only ran on the Bedrock branch; the consolidation
        # extends it to SageMaker MCs as well.
        if _custom is not None:
            try:
                try:
                    from shared.istio_vs_authz import emit_per_asset_istio
                except ModuleNotFoundError:
                    from operators.shared.istio_vs_authz import emit_per_asset_istio
                _component_ref = patch.status.get("componentRef") if hasattr(patch.status, "get") else None
                _component_owner = None
                if _component_ref:
                    _component_owner = {
                        "apiVersion": "oda.tmforum.org/v1", "kind": "Component",
                        "name": _component_ref.get("name"), "uid": _component_ref.get("uid"),
                        "controller": False, "blockOwnerDeletion": True,
                    }
                emit_per_asset_istio(
                    k8s_api=_custom, namespace=namespace,
                    asset_name=name, asset_uid=meta.get("uid", ""),
                    owner_reference=_component_owner,
                    kind="ModelConfig",
                )
                _set_condition(patch, "IstioPerAssetProvisioned", "True", "IstioReady",
                               f"VirtualService + AuthorizationPolicy emitted for {name}")
            except Exception as _istio_err:
                logger.warning("W4.C Istio VS/AuthZ emission failed for %s: %s", name, _istio_err)
                _set_condition(patch, "IstioPerAssetProvisioned", "False", "IstioFailed",
                               f"Istio VS/AuthZ emission failed: {str(_istio_err)[:256]}")

    # Program the agentgateway dataplane from this CR. Step 1 of the ai-gateway-pod retirement path
    # (docs/DATAPLANE-DIRECTION.md): the alias, backing model and guardrail the CR declares are
    # projected as an AgentgatewayModel so agentgateway serves exactly what MoDaaS approved.
    #
    # CONVERGENT, not transition-triggered. The first version of this lived inside
    #   if phase == "Approved" and _prev_phase != "Approved"
    # so it only fired on the EDGE into Approved. An already-Approved CR never programmed a route, and
    # deleting the route out-of-band left it deleted forever. Route presence must be a function of
    # current phase, so it is re-applied on every reconcile while Approved and removed otherwise.
    #
    # Off unless MODAAS_PROGRAM_AGENTGATEWAY=true — ai-gateway-pod still serves Bedrock inbound and
    # inbound SigV4, so a second dataplane must never start being programmed silently.
    try:
        try:
            from shared.agentgateway_route import (
                agentgateway_enabled, emit_agentgateway_model, delete_agentgateway_model)
        except ModuleNotFoundError:
            from operators.shared.agentgateway_route import (
                agentgateway_enabled, emit_agentgateway_model, delete_agentgateway_model)
        if agentgateway_enabled():
            _merged = {**(status or {})}
            try:
                _merged.update({k: v for k, v in patch.status.items()})
            except Exception:
                pass
            _phase = _merged.get("phase") or patch.status.get("phase")
            if _phase == "Approved" and not spec.get("paused"):
                _agw = emit_agentgateway_model(_custom, alias=name, spec=spec, status=_merged)
                if _agw == "skipped":
                    # F55: an unhandled provider must not report success.
                    _set_condition(patch, "AgentgatewayRouteProgrammed", "False", "ProviderNotRoutable",
                                   f"provider {spec.get('provider')!r} has no agentgateway mapping")
                else:
                    _set_condition(patch, "AgentgatewayRouteProgrammed", "True", "RouteProgrammed",
                                   f"AgentgatewayModel/{name} applied")
                    # U5/observed-path-status: reached only when agentgateway_enabled() AND the
                    # provider is routable (both of record_observed_path's required gates are
                    # satisfied by this branch's own placement — no new gating code needed).
                    _model_operator.record_observed_path(patch, _custom, alias=name, status_field="enforcedAt")
            else:
                # Not servable -> the route must not exist. Mirrors the model/tool admission gate:
                # a paused or unapproved asset is refused, not quietly served by a second dataplane.
                delete_agentgateway_model(_custom, alias=name)
                _set_condition(patch, "AgentgatewayRouteProgrammed", "False", "NotServable",
                               f"phase={_phase} paused={bool(spec.get('paused'))}; route withdrawn")
    except Exception as _agw_err:
        logger.warning("agentgateway programming failed for %s: %s", name, _agw_err)
        _set_condition(patch, "AgentgatewayRouteProgrammed", "False", "ProgramFailed",
                       f"agentgateway programming failed: {str(_agw_err)[:256]}")

    # ── W4-C (option a, owner-decided 2026-09-02): resource-side grants ──
    # ModelConfig.spec.access.allowedConsumers -> Cedar permits in the PDP's
    # existing ConfigMap channel. Resource-side per a design note ("agentconfig-only
    # grants = the current footgun"): the MODEL owner authors access;
    # consumers never self-declare. Phase-driven like the agentgateway route:
    # projected while Approved+unpaused, WITHDRAWN otherwise -- a paused
    # model's grants must not linger in the PDP.
    # Gated on MODAAS_PROJECT_MODEL_GRANTS (same opt-in convention as
    # MODAAS_PROGRAM_AGENTGATEWAY / MODAAS_GUARDRAIL_DRY_RUN).
    try:
        if os.environ.get("MODAAS_PROJECT_MODEL_GRANTS", "false").lower() in ("1", "true", "yes"):
            try:
                from shared.policy_projection import (
                    ensure_policy_configmap, render_consumer_permits, delete_policy_configmap)
            except ModuleNotFoundError:
                from operators.shared.policy_projection import (  # type: ignore
                    ensure_policy_configmap, render_consumer_permits, delete_policy_configmap)
            import kubernetes as _k8s_pg
            try:
                _k8s_pg.config.load_incluster_config()
            except _k8s_pg.config.config_exception.ConfigException:
                _k8s_pg.config.load_kube_config()
            _core_pg = _k8s_pg.client.CoreV1Api()
            _merged_pg = {**(status or {})}
            try:
                _merged_pg.update({k: v for k, v in patch.status.items()})
            except Exception:
                pass
            _phase_pg = _merged_pg.get("phase") or patch.status.get("phase")
            _consumers = ((spec.get("access") or {}).get("allowedConsumers") or [])
            _grant_policy_id = f"model-{name}"  # MUST equal the doorman llm-shape derivation (app.py: model-<asset>)
            if _phase_pg == "Approved" and not spec.get("paused") and _consumers:
                _text = render_consumer_permits(name, list(_consumers))
                _pid = ensure_policy_configmap(
                    core_v1_api=_core_pg, source_kind="ModelConfig",
                    source_name=name, policy_id=_grant_policy_id, policy_text=_text)
                _set_condition(patch, "ModelGrantsProjected",
                               "True" if _pid else "False",
                               "GrantsProjected" if _pid else "ProjectionSkipped",
                               f"{len(dict.fromkeys(_consumers))} consumer grant(s) as policyId {_grant_policy_id}"
                               if _pid else "grant projection returned no policyId")
            else:
                delete_policy_configmap(_core_pg, _grant_policy_id)
                if _consumers:
                    _set_condition(patch, "ModelGrantsProjected", "False", "NotServable",
                                   f"phase={_phase_pg} paused={bool(spec.get('paused'))}; grants withdrawn")
    except ValueError as _pg_err:
        # Cedar-unsafe consumer string: surface loudly, never project.
        _set_condition(patch, "ModelGrantsProjected", "False", "InvalidConsumer",
                       str(_pg_err)[:256])
    except Exception as _pg_err:
        logger.warning("model grant projection failed for %s: %s", name, _pg_err)
        _set_condition(patch, "ModelGrantsProjected", "False", "ProjectionFailed",
                       str(_pg_err)[:256])

    return _result


# (legacy inline reconcile body removed in Gap 9 refactor; see git history at
# the commit just before this refactor for the original SageMaker + Bedrock
# inline bodies. The handler now delegates to AssetOperator.reconcile()
# via _model_operator.reconcile(...) above.)



def _agw_route_module():
    """Resolve shared/agentgateway_route.py under any of the three import roots
    the operators run with (container bare, repo-relative, package-relative).

    Returning the MODULE (not its functions) is deliberate: tests patch
    attributes on the resolved object, so they intercept the same module the
    handler uses no matter which name resolved first.
    """
    import importlib
    for name in ("shared.agentgateway_route",
                 "operators.shared.agentgateway_route",
                 "agentgateway_route"):
        try:
            return importlib.import_module(name)
        except ModuleNotFoundError:
            continue
    raise ModuleNotFoundError("agentgateway_route not importable")


@kopf.on.delete(GROUP, VERSION, PLURAL, retries=5)
async def cleanup(spec, status, name, **_):
    # Gap 9: thin delegation. Provider guard widened to include aws-sagemaker
    # so SageMaker MCs receive base-class deprovision/deprecate on delete
    # (the old guard checked == PROVIDER which silently leaked SageMaker
    # registry records).
    if spec.get("provider") not in ("aws-bedrock", "aws-sagemaker"):
        return
    logger.info(f"Cleaning up {name}: alias={spec.get('alias')}")
    # Route withdrawal on delete (2026-09-05, live gap): the PAUSE path
    # already withdraws the AgentgatewayModel; DELETE never did -- a deleted
    # model kept serving through the gateway. Withdraw before backend
    # teardown so no traffic window exists where the route points at a
    # deprovisioned backing.
    try:
        _agw = _agw_route_module()
        if _agw.agentgateway_enabled():
            import kubernetes as _k8s
            # delete_agentgateway_model(k8s_api, alias) -- the FIRST argument is a
            # CustomObjectsApi client, exactly as the pause path passes _custom.
            # (Passing the spec dict here silently no-ops: the failure is caught
            # below and the route survives the delete. Regression-tested.)
            _agw.delete_agentgateway_model(
                _k8s.client.CustomObjectsApi(), spec.get("alias") or name)
            logger.info(f"AgentgatewayModel withdrawn for {name}")
    except Exception as _agw_err:  # noqa: BLE001 -- observe-and-surface
        logger.warning(f"route withdrawal on delete failed for {name}: {_agw_err}")
    return _model_operator.cleanup(spec, status or {})


# ── helpers (preserved for backward compatibility with existing tests) ──
def _register_in_registry(alias: str, spec: dict, status: dict, region: str) -> str:
    """Project approved CR into an Agent Registry record (recordType=model, custom type).
    Returns the registry record id. Operator writes status.registryRecordId.

    Record key is provider-prefixed (a design note) and built via the single canonical
    registry_record_id() helper (Finding #1) so both halves are normalized and
    the result satisfies the CRD status.registryRecordId pattern — no separate
    naming dialect in this module."""
    caps = spec.get("capabilities", {})
    provider = spec.get("provider", "unknown")
    record_name = registry_record_id(provider, alias)
    record = {
        "recordType": "model",
        "name": record_name,
        "description": spec.get("description") or f"ModelConfig for {alias} ({spec.get('provider', 'unknown')})",
        "version": str(status.get("observedGeneration", 1)),
        "state": "APPROVED",
        "metadata": {
            "invocation": {
                "endpoint": status.get("globalResourceEndpoint", ""),
                "alias": alias,
                "protocol": "openai-chat-completions-canvas",
            },
            "capabilities": {
                "features": caps.get("features", []),
                "modalities": caps.get("modalities", []),
                "tier": caps.get("tier"),
                "regions": caps.get("regions", []),
                "minContextWindow": caps.get("minContextWindow"),
                "maxContextWindow": caps.get("maxContextWindow"),
            },
            "tmf639": {
                "lifecycleState": "active",
                "resourceSpecCharacteristic": [
                    {"name": "features", "value": caps.get("features", [])},
                    {"name": "tier",     "value": caps.get("tier")},
                    {"name": "provider", "value": spec.get("provider")},
                ],
            },
            "governance": spec.get("governance", {}),
            "resolvedModelId": status.get("resolvedModelId"),
            "safetyEnabled":   status.get("safetyEnabled", False),
            "guardrailId":     status.get("guardrailId"),
        },
    }
    # a design note dispatch (Batch G): use Registry CR if flag enabled, else legacy
    resp = _dispatch_put_record(record, spec, status, region, record_name)
    return resp


def _deprecate_in_registry(alias: str, region: str, provider: str = "aws-bedrock", spec: dict = None) -> None:
    # Finding #1: same canonical builder as _register_in_registry.
    record_name = registry_record_id(provider, alias)
    # a design note dispatch (Batch G)
    if _dispatch_deprecate(record_name, spec or {}):
        return
    client = _registry_get_client(region)
    if hasattr(client, "deprecate"):
        client.deprecate(record_name)
    else:
        records = client.search(query="", filters={"recordType": "model"})
        for r in records:
            if r.get("name") == record_name:
                r["state"] = "DEPRECATED"


def _create_guardrail(alias: str, region: str, cfg: dict, endpoint_url: str | None = None) -> tuple[str, str]:
    """Delegate to shared.guardrails.create_guardrail.

    This module used to carry its OWN copy of the create-or-update-then-publish logic, byte-for-byte
    equivalent to the shared one. The main call site used the local copy, so fixing the shared module
    (G29: stop publishing a guardrail version on every reconcile) changed nothing at runtime — the
    duplicate kept publishing and the ModelConfig kept marching toward
    ServiceQuotaExceededException. Collapsed to a single implementation so the two cannot diverge again.
    """
    try:
        from shared.guardrails import create_guardrail as _shared_create
    except ModuleNotFoundError:  # pragma: no cover - import-path shim used in-container
        import os as _o
        import sys as _s

        _r = _o.path.abspath(_o.path.join(_o.path.dirname(__file__), ".."))
        _r in _s.path or _s.path.insert(0, _r)
        from shared.guardrails import create_guardrail as _shared_create
    return _shared_create(alias, region, cfg, endpoint_url)


def _classify_model(model_id: str, capabilities: dict) -> list[str]:
    declared = capabilities.get("features") or []
    if declared:
        return list(declared)
    mid = model_id.lower()
    if "embed" in mid: return ["embedding"]
    if "rerank" in mid: return ["rerank"]
    if "chronos" in mid or "timegpt" in mid: return ["time-series"]
    if "image" in mid or "vision" in mid or "nova-canvas" in mid: return ["vision", "chat"]
    if "whisper" in mid or "audio" in mid: return ["audio"]
    return ["chat"]


def _days_until_retirement(retire_iso: str | None) -> int | None:
    if not retire_iso:
        return None
    try:
        return (date.fromisoformat(retire_iso) - date.today()).days
    except ValueError:
        return None


def _stamp(patch, meta):
    patch.status["observedGeneration"] = meta.get("generation", 0)
    patch.status["lastReconciled"] = datetime.now(timezone.utc).isoformat()


def _emit_lifecycle(name: str, namespace: str, event_type: str,
                    payload: dict, observed_generation: int) -> None:
    """a design note — emit PublishedNotification for a ModelConfig lifecycle event.
    Non-blocking; logs and continues on any failure."""
    try:
        try:
            from shared.lifecycle_events import emit_lifecycle_event
        except ModuleNotFoundError:
            import sys as _sys, os as _os
            _shared_root = _os.path.abspath(
                _os.path.join(_os.path.dirname(__file__), "..")
            )
            if _shared_root not in _sys.path:
                _sys.path.insert(0, _shared_root)
            from shared.lifecycle_events import emit_lifecycle_event
        import kubernetes as _k8s
        try:
            _k8s.config.load_incluster_config()
        except _k8s.config.config_exception.ConfigException:
            _k8s.config.load_kube_config()
        emit_lifecycle_event(
            k8s_api=_k8s.client.CustomObjectsApi(),
            namespace=namespace,
            source_kind="ModelConfig",
            source_name=name,
            event_type=event_type,
            payload=payload,
            observed_generation=observed_generation,
        )
    except Exception as e:
        logger.warning("a design note emit %s for %s failed (non-blocking): %s",
                       event_type, name, type(e).__name__)


def _classify_k8s_error(exc: Exception) -> str:
    """Classify a K8s/network exception into a condition reason string.

    W1.A: Surfaces the root cause category so kubectl describe shows WHY
    canvas integration failed, not just that it failed.
    """
    status_code = getattr(exc, "status", None)
    if status_code == 403:
        return "RBACDenied"
    if status_code == 404:
        return "NotFound"
    if status_code == 409:
        return "Conflict"
    if status_code == 422:
        return "ValidationFailed"
    exc_type = type(exc).__name__
    if "URL" in exc_type or "Connection" in exc_type or "Timeout" in exc_type:
        return "ProviderUnreachable"
    return "CanvasIntegrationError"


def _set_condition(patch, cond_type, cond_status, reason, message):
    now = datetime.now(timezone.utc).isoformat()
    cond = {"type": cond_type, "status": cond_status, "reason": reason,
            "message": message, "lastTransitionTime": now}
    conds = patch.status.get("conditions", [])
    for i, c in enumerate(conds):
        if c.get("type") == cond_type:
            conds[i] = cond
            patch.status["conditions"] = conds
            return
    conds.append(cond)
    patch.status["conditions"] = conds


# ── K8s-idiomatic resync timers (a design note) ────────────────────────────────── #

def _reconcile_iam_allowlist():
    """D-8: pin the gateway role's model allowlist to the approved set.

    Compute-the-world + idempotent — safe to call from every CR's timer;
    get_role_policy short-circuits when already in sync. Feature-flagged
    by MODAAS_IAM_ALLOWLIST_ROLE (see iam_model_allowlist)."""
    import os
    if not os.environ.get("MODAAS_IAM_ALLOWLIST_ROLE"):
        return
    try:
        from kubernetes import client as k8s_client
        from iam_model_allowlist import reconcile_allowlist
        mcs = k8s_client.CustomObjectsApi().list_cluster_custom_object(
            GROUP, VERSION, PLURAL
        ).get("items", [])
        outcome = reconcile_allowlist(mcs)
        if outcome and "failed" in outcome:
            logger.warning("D-8 allowlist: %s", outcome)
    except Exception as exc:  # noqa: BLE001 — observe-and-surface
        logger.warning("D-8 allowlist wiring error: %s", exc)


@kopf.timer(GROUP, VERSION, PLURAL, interval=300, idle=30, retries=3)
async def resync_from_registry(spec, status, patch, name, **_):
    """Every 5 minutes, read Registry + update status fields.

    Runs in addition to event-driven reconcile() — catches drift when
    external truth changes but K8s spec doesn't (e.g. someone deletes
    a Registry record out-of-band).
    """
    _reconcile_iam_allowlist()
    if spec.get("provider") != PROVIDER:
        return
    # Seeded after the ownership guard, before any write (see reconcile).
    _model_operator._seed_conditions(patch, status)
    try:
        # kopf may pass status as a Body-like dict-subclass; coerce to plain dict
        status_dict = dict(status) if status else {}
        result = _model_operator.resync_from_registry(spec, status_dict, patch)
        logger.info(f"resync {name}: {result}")
        return result
    except Exception as e:
        logger.error(f"resync_from_registry failed for {name}: {type(e).__name__}: {e}",
                     exc_info=True)
        return {"error": str(e)}


@kopf.timer(GROUP, VERSION, PLURAL, interval=3600, initial_delay=60, idle=60, retries=3)
async def scan_orphan_records(patch, **_):
    """Every 1 hour, scan for Registry records with no matching CR.

    This handler receives any CR's patch but we only use it for the
    trigger — the actual orphan scan is cluster-wide and logs warnings.
    """
    try:
        import kubernetes
        try:
            kubernetes.config.load_incluster_config()
        except kubernetes.config.config_exception.ConfigException:
            kubernetes.config.load_kube_config()
        custom = kubernetes.client.CustomObjectsApi()
        cr_list = custom.list_cluster_custom_object(
            group=GROUP, version=VERSION, plural=PLURAL,
        )
        cr_names = [it.get("spec", {}).get("alias")
                    for it in cr_list.get("items", [])
                    if it.get("spec", {}).get("alias")]
        orphans = _model_operator.scan_orphans(cr_names, provider_prefix="aws-bedrock")
        if orphans:
            logger.warning(f"Found {len(orphans)} orphan Registry records: {orphans}")
        else:
            logger.info(f"Orphan scan clean — {len(cr_names)} CRs, all Registry records accounted for")
        return {"orphans": orphans, "scanned_crs": len(cr_names)}
    except Exception as e:
        logger.error(f"scan_orphan_records failed: {type(e).__name__}: {e}", exc_info=True)
        return {"error": str(e)}
