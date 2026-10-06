"""kind=tool, provider=agentCoreGateway plugin.

Port of v1 aws-tool-operator logic. Creates a Gateway target on the given
Gateway. Supports Lambda-ARN backends (GATEWAY_IAM_ROLE creds) and HTTP
backends (OAUTH-credential providers — future)."""

import logging
import re

from botocore.exceptions import ClientError

from base.provider import (
    AssetProvider, ProvisionResult, ProvisioningFailed,
    ResourceRef, Condition, ReconcileContext,
)
from providers.registry import register


logger = logging.getLogger("providers.tool.agent_core_gateway")


@register
class AgentCoreGatewayToolProvider(AssetProvider):
    kind = "tool"
    provider = "agentCoreGateway"

    def validate_spec(self, spec: dict) -> list[str]:
        tool = spec.get("tool", {})
        gw_cfg = tool.get("agentCoreGateway") or {}
        errors = []
        if not gw_cfg.get("gateway"):
            errors.append("tool.agentCoreGateway.gateway is required")
        if not gw_cfg.get("mcpServer", {}).get("endpoint"):
            errors.append("tool.agentCoreGateway.mcpServer.endpoint is required "
                          "(Lambda ARN or HTTPS URL)")
        return errors

    def provision(self, spec: dict, status: dict, ctx: ReconcileContext) -> ProvisionResult:
        tool = spec["tool"]
        gw_cfg = tool["agentCoreGateway"]
        gateway_id = gw_cfg["gateway"]
        endpoint = gw_cfg["mcpServer"]["endpoint"]

        # Safe target name — same rule as v1 (hyphens only)
        target_name = re.sub(r"[_\s]+", "-", tool["toolName"]).strip("-").lower()
        target_name = re.sub(r"[^a-z0-9-]", "-", target_name)[:100]

        client = ctx.aws_session.client("bedrock-agentcore-control", region_name=ctx.region)

        # Idempotence: look for existing target by name
        existing_target_id = None
        for r in (status or {}).get("resources", []) or []:
            if r.get("kind") == "AgentCoreGatewayTarget":
                existing_target_id = r.get("identifier")
                break

        # Lambda vs OpenAPI dispatch
        if endpoint.startswith("arn:aws:lambda:"):
            target_config = {
                "mcp": {
                    "lambda": {
                        "lambdaArn": endpoint,
                        "toolSchema": self._build_tool_schema(tool),
                    }
                }
            }
            creds = [{"credentialProviderType": "GATEWAY_IAM_ROLE"}]
        else:
            # OpenAPI inline — requires OAUTH/API_KEY credential providers
            raise ProvisioningFailed(
                "HttpBackendNotSupported",
                "HTTP/OpenAPI backends require OAUTH credential provider wiring "
                "(not yet implemented in v2alpha1)",
            )

        try:
            if existing_target_id:
                client.update_gateway_target(
                    gatewayIdentifier=gateway_id,
                    targetId=existing_target_id,
                    name=target_name,
                    description=spec.get("description", "MoDaaS tool target"),
                    targetConfiguration=target_config,
                )
                target_id = existing_target_id
            else:
                resp = client.create_gateway_target(
                    gatewayIdentifier=gateway_id,
                    name=target_name,
                    description=spec.get("description", "MoDaaS tool target"),
                    targetConfiguration=target_config,
                    credentialProviderConfigurations=creds,
                )
                target_id = resp["targetId"]
        except ClientError as e:
            raise ProvisioningFailed(
                "GatewayTargetProvisionFailed",
                f"{e.response['Error']['Code']}: {e.response['Error']['Message']}",
            )

        mcp_url = f"https://{gateway_id}.gateway.bedrock-agentcore.{ctx.region}.amazonaws.com/mcp"

        return ProvisionResult(
            resources=[ResourceRef(
                kind="AgentCoreGatewayTarget",
                identifier=target_id,
                managed=True,
                extras={
                    "gatewayId": gateway_id,
                    "mcpUrl": mcp_url,
                    "lambdaArn": endpoint,
                    "targetName": target_name,
                },
            )],
            conditions=[
                Condition("GatewayTargetCreated", "True", "TargetReady",
                          f"target {target_id} on gateway {gateway_id}"),
            ],
            registry_metadata={
                "gatewayId": gateway_id,
                "targetId": target_id,
                "mcpUrl": mcp_url,
                "lambdaArn": endpoint,
                "toolName": tool["toolName"],
                "tools": tool.get("agentCoreGateway", {}).get("tools", []),
            },
            plugin_status={
                "gatewayId": gateway_id,
                "gatewayTargetId": target_id,
                "mcpUrl": mcp_url,
            },
        )

    def deprovision(self, status: dict, ctx: ReconcileContext) -> None:
        client = ctx.aws_session.client("bedrock-agentcore-control", region_name=ctx.region)
        for resource in status.get("resources", []) or []:
            if resource.get("kind") == "AgentCoreGatewayTarget" and resource.get("managed"):
                gw = resource.get("extras", {}).get("gatewayId")
                target_id = resource.get("identifier")
                if not gw or not target_id:
                    continue
                try:
                    client.delete_gateway_target(
                        gatewayIdentifier=gw, targetId=target_id,
                    )
                    logger.info(f"deleted gateway target {target_id}")
                except ClientError as e:
                    logger.warning(
                        f"delete_gateway_target({target_id}) failed: {e.response['Error']['Code']}"
                    )

    def _build_tool_schema(self, tool: dict) -> dict:
        """Build the inlinePayload tool schema AgentCore Gateway expects."""
        tools_list = tool.get("agentCoreGateway", {}).get("tools", [])
        inline = []
        for t in tools_list:
            entry = {
                "name": t["name"],
                "description": t.get("description", ""),
            }
            if t.get("inputSchema"):
                entry["inputSchema"] = t["inputSchema"]
            inline.append(entry)
        return {"inlinePayload": inline}
