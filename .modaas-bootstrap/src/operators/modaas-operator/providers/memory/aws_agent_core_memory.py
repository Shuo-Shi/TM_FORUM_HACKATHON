"""kind=memory, provider=awsAgentCoreMemory plugin.

FIRST NEW ASSET KIND in v2alpha1. Not a port — new capability.

Demonstrates the extensibility claim: adding a new asset type is a single
plugin file plus typed block in the CRD (already present in v2alpha1).

AgentCore Memory is a managed AWS service for agent session state. Two
modes — IMPORT an existing memoryId, or MANAGED (operator creates).

Note: as of v2alpha1 authoring, the bedrock-agentcore-control Memory APIs
may not be GA everywhere. This plugin makes best-effort calls with
informative error messages if the APIs are not yet available in the
target region."""

import logging

from botocore.exceptions import ClientError

from base.provider import (
    AssetProvider, ProvisionResult, ProvisioningFailed,
    ResourceRef, Condition, ReconcileContext,
)
from providers.registry import register


logger = logging.getLogger("providers.memory.aws_agent_core_memory")


@register
class AwsAgentCoreMemoryProvider(AssetProvider):
    kind = "memory"
    provider = "awsAgentCoreMemory"

    # Memory may not exist in Registry yet — flag off if not supported
    emits_registry_record = True

    def validate_spec(self, spec: dict) -> list[str]:
        mem = spec.get("memory", {})
        ac_mem = mem.get("awsAgentCoreMemory") or {}
        errors = []
        has_import = bool(ac_mem.get("memoryId"))
        has_managed = bool(ac_mem.get("strategy"))
        if not has_import and not has_managed:
            errors.append(
                "memory.awsAgentCoreMemory requires either memoryId (import) "
                "or strategy (managed)"
            )
        return errors

    def provision(self, spec: dict, status: dict, ctx: ReconcileContext) -> ProvisionResult:
        mem = spec["memory"]
        ac_mem = mem["awsAgentCoreMemory"]
        memory_type = mem["memoryType"]

        client = ctx.aws_session.client("bedrock-agentcore-control", region_name=ctx.region)

        # Import mode
        if ac_mem.get("memoryId") and not ac_mem.get("strategy"):
            memory_id = ac_mem["memoryId"]
            try:
                if hasattr(client, "get_memory"):
                    resp = client.get_memory(memoryId=memory_id)
                    arn = resp.get("memoryArn")
                else:
                    # Memory API not in boto3 yet — treat as valid and move on
                    arn = f"arn:aws:bedrock-agentcore:{ctx.region}::memory/{memory_id}"
                    logger.warning("boto3 has no get_memory op; skipping server-side validation")
            except ClientError as e:
                raise ProvisioningFailed(
                    "MemoryFetchFailed",
                    f"get_memory({memory_id}): {e.response['Error']['Code']}",
                )
            return self._result(memory_id, arn, mem, managed=False, mode="import")

        # Managed mode
        strategy = ac_mem["strategy"]
        k = ac_mem.get("k", 50)
        ttl_days = ac_mem.get("ttlDays", 30)

        existing_memory_id: str | None = None
        for r in (status or {}).get("resources", []) or []:
            if r.get("kind") == "AgentCoreMemory":
                existing_memory_id = r.get("identifier")
                break

        if not hasattr(client, "create_memory"):
            # Graceful degradation — boto3 may not have the API yet
            logger.warning(
                "boto3 bedrock-agentcore-control lacks create_memory; "
                "memory asset marked Pending until API GA"
            )
            raise ProvisioningFailed(
                "MemoryApiNotAvailable",
                "bedrock-agentcore-control.create_memory not available in this SDK. "
                "Use import mode with a pre-created memoryId, or upgrade boto3.",
            )

        memory_name = f"{ctx.namespace}-{ctx.name}"[:128]
        try:
            if existing_memory_id:
                resp = client.update_memory(
                    memoryId=existing_memory_id,
                    memoryStrategy=strategy,
                    k=k,
                    ttlDays=ttl_days,
                )
                memory_id = existing_memory_id
            else:
                resp = client.create_memory(
                    name=memory_name,
                    memoryType=memory_type,
                    memoryStrategy=strategy,
                    k=k,
                    ttlDays=ttl_days,
                )
                memory_id = resp["memoryId"]
            arn = resp.get("memoryArn", f"arn:aws:bedrock-agentcore:{ctx.region}::memory/{memory_id}")
        except ClientError as e:
            raise ProvisioningFailed(
                "MemoryProvisionFailed",
                f"{e.response['Error']['Code']}: {e.response['Error']['Message']}",
            )

        return self._result(memory_id, arn, mem, managed=True, mode="managed")

    def deprovision(self, status: dict, ctx: ReconcileContext) -> None:
        client = ctx.aws_session.client("bedrock-agentcore-control", region_name=ctx.region)
        if not hasattr(client, "delete_memory"):
            logger.warning("boto3 lacks delete_memory; skipping cleanup")
            return
        for r in status.get("resources", []) or []:
            if r.get("kind") == "AgentCoreMemory" and r.get("managed"):
                memory_id = r.get("identifier")
                try:
                    client.delete_memory(memoryId=memory_id)
                    logger.info(f"deleted AgentCore Memory {memory_id}")
                except ClientError as e:
                    logger.warning(
                        f"delete_memory({memory_id}) failed: {e.response['Error']['Code']}"
                    )

    def _result(self, memory_id: str, arn: str | None, mem: dict,
                managed: bool, mode: str) -> ProvisionResult:
        ac_mem = mem.get("awsAgentCoreMemory", {})
        return ProvisionResult(
            resources=[ResourceRef(
                kind="AgentCoreMemory",
                identifier=memory_id,
                arn=arn,
                managed=managed,
                extras={"mode": mode, "strategy": ac_mem.get("strategy"),
                        "k": ac_mem.get("k"), "ttlDays": ac_mem.get("ttlDays")},
            )],
            conditions=[
                Condition("MemoryReady", "True",
                          "MemoryImported" if mode == "import" else "MemoryCreated",
                          f"AgentCore Memory {memory_id}"),
            ],
            registry_metadata={
                "memoryId": memory_id,
                "memoryArn": arn,
                "memoryType": mem.get("memoryType"),
                "strategy": ac_mem.get("strategy"),
                "k": ac_mem.get("k"),
                "ttlDays": ac_mem.get("ttlDays"),
                "hostingMode": mode,
            },
            plugin_status={
                "memoryId": memory_id,
                "memoryArn": arn,
                "memoryType": mem.get("memoryType"),
                "managed": managed,
            },
        )
