"""kind=model, provider=aws-bedrock plugin.

Port of v1 aws-model-operator logic into the v2 plugin framework.
Owns Bedrock foundation model validation + optional guardrail creation +
Agent Registry projection of the model record.

v1 fixes (GEPA pass #4) preserved:
  - us.-prefix inference profile detection
  - status writes BEFORE registry write (handled by shared reconcile loop)
  - Registry metadata includes resolvedModelId, safetyEnabled, guardrailId
"""

import logging

from botocore.exceptions import ClientError

from base.provider import (
    AssetProvider, ProvisionResult, ProvisioningFailed,
    ResourceRef, Condition, ReconcileContext,
)
from providers.registry import register


logger = logging.getLogger("providers.model.aws_bedrock")


@register
class AwsBedrockModelProvider(AssetProvider):
    kind = "model"
    provider = "aws-bedrock"

    def validate_spec(self, spec: dict) -> list[str]:
        errors = []
        model_block = spec.get("model", {})
        aws = model_block.get("awsBedrock", {})

        if model_block.get("safety", {}).get("required"):
            has_inline = bool(aws.get("guardrails"))
            has_ref = bool(model_block.get("safety", {}).get("guardrailRef"))
            if not has_inline and not has_ref:
                errors.append(
                    "model.safety.required=true requires either "
                    "model.awsBedrock.guardrails (inline) or "
                    "model.safety.guardrailRef (reference another guardrail asset)"
                )
        return errors

    def provision(self, spec: dict, status: dict, ctx: ReconcileContext) -> ProvisionResult:
        model_block = spec["model"]
        aws = model_block.get("awsBedrock", {})
        region = aws.get("region", ctx.region)
        model_id = model_block["modelId"]
        alias = model_block.get("alias", ctx.name)

        bedrock = ctx.aws_session.client("bedrock", region_name=region)

        # ── 1. Validate foundation model exists + resolve us.-prefix ──
        try:
            fm_resp = bedrock.get_foundation_model(modelIdentifier=model_id)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            raise ProvisioningFailed(
                "ModelNotFound",
                f"{model_id} not available in {region}: {code}"
            )

        inference_types = fm_resp.get("modelDetails", {}).get("inferenceTypesSupported", [])
        if "ON_DEMAND" not in inference_types and "INFERENCE_PROFILE" in inference_types:
            resolved_id = f"us.{model_id}"
        else:
            resolved_id = model_id

        resources: list[ResourceRef] = [
            ResourceRef(
                kind="BedrockFoundationModel",
                identifier=model_id,
                resolvedIdentifier=resolved_id,
                managed=False,
                extras={"region": region},
            ),
        ]

        conditions: list[Condition] = [
            Condition("ModelValidated", "True", "ModelExists",
                      f"{model_id} validated in {region}"),
        ]

        # ── 2. Optional guardrail ──
        safety_intent = model_block.get("safety", {}).get("required", False)
        safety_fact = False
        guardrail_id: str | None = None
        guardrail_version: str | None = None

        if safety_intent:
            guardrail_ref = model_block.get("safety", {}).get("guardrailRef", {})
            if guardrail_ref.get("name"):
                # Reference — another AssetConfig of kind=guardrail owns the resource
                ref_name = guardrail_ref["name"]
                try:
                    ref_resources = ctx.dependency_resolver.resources_of("guardrail", ref_name)
                except LookupError as e:
                    raise ProvisioningFailed("GuardrailRefMissing", str(e))
                for r in ref_resources:
                    if r.get("kind") == "BedrockGuardrail":
                        guardrail_id = r.get("identifier")
                        guardrail_version = r.get("extras", {}).get("version", "DRAFT")
                        safety_fact = True
                        break
                if not guardrail_id:
                    raise ProvisioningFailed(
                        "GuardrailRefNotReady",
                        f"referenced guardrail {ref_name} has no BedrockGuardrail resource yet",
                    )
                resources.append(ResourceRef(
                    kind="BedrockGuardrail",
                    identifier=guardrail_id,
                    managed=False,
                    extras={"version": guardrail_version, "sourceRef": f"guardrail/{ref_name}"},
                ))
            elif aws.get("guardrails"):
                # Inline — plugin creates the guardrail directly
                guardrail_id, guardrail_version = self._create_inline_guardrail(
                    bedrock, alias, aws["guardrails"]
                )
                safety_fact = True
                resources.append(ResourceRef(
                    kind="BedrockGuardrail",
                    identifier=guardrail_id,
                    managed=True,
                    extras={"version": guardrail_version},
                ))

        conditions.append(Condition(
            "SafetyConfigured",
            "True",
            "SafetyEnabled" if safety_fact else "SafetyNotRequired",
            f"Guardrail {guardrail_id}" if safety_fact else "No safety required",
        ))

        # ── 3. Build endpoint ──
        endpoint = (
            model_block.get("endpoint") or
            f"https://bedrock-runtime.{region}.amazonaws.com"
        )

        # ── 4. Done. Return result for base reconcile loop. ──
        return ProvisionResult(
            resources=resources,
            conditions=conditions,
            registry_metadata={
                "resolvedModelId": resolved_id,
                "safetyEnabled": safety_fact,
                "guardrailId": guardrail_id,
                "guardrailVersion": guardrail_version,
                "endpoint": endpoint,
                "capabilities": model_block.get("capabilities", {}),
                "alias": alias,
            },
            plugin_status={
                "resolvedModelId": resolved_id,
                "safetyEnabled": safety_fact,
                "guardrailId": guardrail_id,
                "endpoint": endpoint,
                "alias": alias,
            },
        )

    def deprovision(self, status: dict, ctx: ReconcileContext) -> None:
        region = ctx.region
        for resource in status.get("resources", []) or []:
            if resource.get("kind") == "BedrockGuardrail" and resource.get("managed"):
                gr_id = resource.get("identifier")
                try:
                    ctx.aws_session.client("bedrock", region_name=region).delete_guardrail(
                        guardrailIdentifier=gr_id
                    )
                    logger.info(f"deleted Bedrock guardrail {gr_id}")
                except ClientError as e:
                    logger.warning(
                        f"delete_guardrail({gr_id}) failed: {e.response['Error']['Code']}"
                    )

    def _create_inline_guardrail(self, bedrock, alias: str, guardrail_spec: dict) -> tuple[str, str]:
        """Inline guardrail creation. Mirrors v1 aws-model-operator logic.

        If the user's guardrail_spec carries a `name` or `description`, operator's
        derived values take precedence to avoid kwarg collisions and to enforce
        a predictable MoDaaS naming pattern."""
        spec = {k: v for k, v in guardrail_spec.items() if k not in ("name", "description")}
        guardrail_name = f"modaas-{alias}-guardrail"
        try:
            resp = bedrock.create_guardrail(
                name=guardrail_name,
                description=f"MoDaaS-managed guardrail for {alias}",
                **spec,
            )
            gr_id = resp["guardrailId"]
            ver_resp = bedrock.create_guardrail_version(
                guardrailIdentifier=gr_id,
                description="v1 MoDaaS initial version",
            )
            return gr_id, ver_resp.get("version", "DRAFT")
        except ClientError as e:
            raise ProvisioningFailed(
                "GuardrailCreateFailed",
                f"create_guardrail({guardrail_name}): {e.response['Error']['Code']}",
            )
