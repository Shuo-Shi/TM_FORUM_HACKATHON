"""kind=agent, provider=awsAgentCore plugin.

Port of v1 aws-agent-operator awsAgentCore path. Manages AgentCore Runtime
lifecycle. Supports two modes:
  - IMPORT: hosting.awsAgentCore.agentRuntimeId → adopt existing runtime
  - MANAGED: hosting.awsAgentCore.{containerUri, roleArn} → operator creates

Env vars injected into the runtime from spec.dependsOn refs so the agent
can resolve aliases at boot (per GEPA pass #4 finding #4+#5)."""

import logging

from botocore.exceptions import ClientError

from base.provider import (
    AssetProvider, ProvisionResult, ProvisioningFailed,
    ResourceRef, Condition, ReconcileContext,
)
from providers.registry import register


logger = logging.getLogger("providers.agent.aws_agent_core")


@register
class AwsAgentCoreAgentProvider(AssetProvider):
    kind = "agent"
    provider = "awsAgentCore"

    def validate_spec(self, spec: dict) -> list[str]:
        agent = spec.get("agent", {})
        hosting = (agent.get("hosting") or {}).get("awsAgentCore") or {}
        errors = []
        has_import = bool(hosting.get("agentRuntimeId"))
        has_managed = bool(hosting.get("containerUri") and hosting.get("roleArn"))
        if not has_import and not has_managed:
            errors.append(
                "agent.hosting.awsAgentCore requires either agentRuntimeId (import) "
                "or containerUri+roleArn (managed)"
            )
        return errors

    def provision(self, spec: dict, status: dict, ctx: ReconcileContext) -> ProvisionResult:
        agent = spec["agent"]
        hosting = agent["hosting"]["awsAgentCore"]
        region = hosting.get("region", ctx.region)

        client = ctx.aws_session.client("bedrock-agentcore-control", region_name=region)

        # Import mode
        if hosting.get("agentRuntimeId") and not hosting.get("containerUri"):
            runtime_id = hosting["agentRuntimeId"]
            try:
                resp = client.get_agent_runtime(agentRuntimeId=runtime_id)
            except ClientError as e:
                raise ProvisioningFailed(
                    "RuntimeFetchFailed",
                    f"get_agent_runtime({runtime_id}): {e.response['Error']['Code']}",
                )
            if resp.get("status") not in ("READY", "CREATING", "UPDATING"):
                raise ProvisioningFailed(
                    "RuntimeNotHealthy",
                    f"AgentCore Runtime {runtime_id} status={resp.get('status')}",
                )
            return ProvisionResult(
                resources=[ResourceRef(
                    kind="AgentCoreRuntime",
                    identifier=runtime_id,
                    arn=resp.get("agentRuntimeArn"),
                    managed=False,
                    extras={"region": region, "mode": "import"},
                )],
                conditions=[
                    Condition("RuntimeReady", "True", "RuntimeImported",
                              f"adopted existing runtime {runtime_id}"),
                ],
                registry_metadata={
                    "agentRuntimeId": runtime_id,
                    "agentRuntimeArn": resp.get("agentRuntimeArn"),
                    "hostingMode": "import",
                    "agentCard": agent.get("agentCard", {}),
                },
                plugin_status={
                    "agentRuntimeId": runtime_id,
                    "agentRuntimeArn": resp.get("agentRuntimeArn"),
                    "hostingProvider": "awsAgentCore",
                    "managed": False,
                },
            )

        # Managed mode
        container_uri = hosting["containerUri"]
        role_arn = hosting["roleArn"]
        env_vars = self._build_env_vars(spec, ctx, region, hosting)

        existing_runtime_id: str | None = None
        for r in (status or {}).get("resources", []) or []:
            if r.get("kind") == "AgentCoreRuntime":
                existing_runtime_id = r.get("identifier")
                break

        agent_name = agent.get("agentName", ctx.name)
        safe_runtime_name = agent_name.replace("-", "_")[:40]
        artifact = {"containerConfiguration": {"containerUri": container_uri}}
        base_kwargs = {
            "agentRuntimeArtifact": artifact,
            "networkConfiguration": {"networkMode": "PUBLIC"},
            "roleArn": role_arn,
            "environmentVariables": env_vars,
        }

        try:
            if existing_runtime_id:
                logger.info(f"updating AgentCore Runtime {existing_runtime_id}")
                resp = client.update_agent_runtime(
                    agentRuntimeId=existing_runtime_id, **base_kwargs
                )
                runtime_id = existing_runtime_id
                runtime_arn = resp.get("agentRuntimeArn") or \
                              f"arn:aws:bedrock-agentcore:{region}::runtime/{runtime_id}"
            else:
                logger.info(f"creating AgentCore Runtime {safe_runtime_name}")
                resp = client.create_agent_runtime(
                    agentRuntimeName=safe_runtime_name, **base_kwargs
                )
                runtime_id = resp["agentRuntimeId"]
                runtime_arn = resp.get("agentRuntimeArn")
        except ClientError as e:
            raise ProvisioningFailed(
                "RuntimeProvisionFailed",
                f"{e.response['Error']['Code']}: {e.response['Error']['Message']}",
            )

        return ProvisionResult(
            resources=[ResourceRef(
                kind="AgentCoreRuntime",
                identifier=runtime_id,
                arn=runtime_arn,
                managed=True,
                extras={"region": region, "mode": "managed", "roleArn": role_arn},
            )],
            conditions=[
                Condition("RuntimeReady", "True", "RuntimeCreated",
                          f"operator-managed runtime {runtime_id}"),
            ],
            registry_metadata={
                "agentRuntimeId": runtime_id,
                "agentRuntimeArn": runtime_arn,
                "hostingMode": "managed",
                "containerUri": container_uri,
                "agentCard": agent.get("agentCard", {}),
            },
            plugin_status={
                "agentRuntimeId": runtime_id,
                "agentRuntimeArn": runtime_arn,
                "hostingProvider": "awsAgentCore",
                "managed": True,
            },
        )

    def deprovision(self, status: dict, ctx: ReconcileContext) -> None:
        for resource in status.get("resources", []) or []:
            if resource.get("kind") == "AgentCoreRuntime" and resource.get("managed"):
                runtime_id = resource.get("identifier")
                region = resource.get("extras", {}).get("region", ctx.region)
                try:
                    ctx.aws_session.client(
                        "bedrock-agentcore-control", region_name=region
                    ).delete_agent_runtime(agentRuntimeId=runtime_id)
                    logger.info(f"deleted AgentCore Runtime {runtime_id}")
                except ClientError as e:
                    logger.warning(
                        f"delete_agent_runtime({runtime_id}) failed: "
                        f"{e.response['Error']['Code']}"
                    )

    def _build_env_vars(self, spec: dict, ctx: ReconcileContext, region: str, hosting: dict) -> dict:
        """Inject alias refs so the agent can resolve from Registry at boot."""
        env = {
            "REGION": region,
            "REGISTRY_ID": hosting.get("registryId", "gvwfzhizslOETJSk"),
            "AGENT_NAME": spec["agent"].get("agentName", ctx.name),
        }
        for dep in spec.get("dependsOn", []) or []:
            dep_kind = dep.get("kind")
            dep_name = dep.get("name")
            if dep_kind == "model":
                env.setdefault("MODEL_ALIAS", dep_name)
                env.setdefault("MODEL_PROVIDER", "aws-bedrock")
            elif dep_kind == "tool":
                env.setdefault("TOOL_ALIAS", dep_name)
        if hosting.get("agentCoreGatewayMcpUrl"):
            env["AGENTCORE_GATEWAY_MCP_URL"] = hosting["agentCoreGatewayMcpUrl"]
        return env
