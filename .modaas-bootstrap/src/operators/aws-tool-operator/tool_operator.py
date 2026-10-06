"""AWS AgentCore Tool Operator — ToolConfig v1beta1

Concrete AssetOperator subclass that provisions AgentCore Gateway targets
for MCP tool servers. Watches ToolConfig CRDs with provider=agentCoreGateway.
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
    # Registry-CR lifecycle handlers are registered ONLY by the model
    # operator (single-registrar rule, wave-3 dedup 2026-09-02): with kopf
    # peering enabled only there, co-registering here fired every Registry
    # event 3x. Sensor: operators/shared/tests/test_registry_handler_single_owner.py
except ImportError:
    pass
import logging
import os
import socket as _socket
from operators.shared.asset_operator import AssetOperator, ProvisioningFailed

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
# Fail-soft if opentelemetry-instrumentation-botocore isn't installed.
try:
    from opentelemetry.instrumentation.botocore import BotocoreInstrumentor
    BotocoreInstrumentor().instrument()
except ImportError:
    pass

logger = logging.getLogger("ToolOperator")

GROUP = "oda.tmforum.org"
VERSION = "v1beta1"
PLURAL = "toolconfigs"
PROVIDER = "agentCoreGateway"
# U7 (tool-provider-claim): the two provider values this operator claims.
# "custom" is the CRD's own open-contract escape hatch (spec.custom block) —
# a deliberate, scoped exception to the sibling-operator framing in its own
# schema comment, since no sibling operator exists and there is no AWS
# resource to provision for it (see a design note discussion in this unit's design).
CLAIMED_PROVIDERS = (PROVIDER, "custom")


class ToolOperator(AssetOperator):

    @property
    def record_type(self) -> str:
        return "tool"

    @property
    def resource_plural(self) -> str:
        return "toolconfigs"

    def _build_registry_metadata(self, spec: dict, status: dict) -> dict:
        """W3.C: Rich metadata for tool registry records.

        Populates invocation (MCP endpoint), tools list, governance,
        and componentRef (from W2.A).
        """
        md = super()._build_registry_metadata(spec, status)
        acg = spec.get("agentCoreGateway", {})
        md["invocation"] = {
            "protocol": "mcp",
            "mcpEndpoint": status.get("globalResourceEndpoint", ""),
        }
        tools = acg.get("tools", [])
        if tools:
            md["tools"] = tools
        if spec.get("governance"):
            md["governance"] = spec["governance"]
        return md

    def _agentcore_client(self):
        import boto3
        if not hasattr(self, '_cached_ctrl'):
            from operators.shared.aws_region import resolve_region
            region = resolve_region()
            self._cached_ctrl = boto3.client("bedrock-agentcore-control", region_name=region)
        return self._cached_ctrl

    def provision_backend(self, spec: dict, status: dict) -> dict:
        # U7 (tool-provider-claim): "custom" has no AWS resource to
        # provision (the backend is externally hosted) — validate the one
        # field without which the tool is unusable, don't provision anything.
        if spec.get("provider") == "custom":
            custom = spec.get("custom", {}) or {}
            base_url = custom.get("baseUrl", "")
            if not base_url:
                raise ProvisioningFailed(
                    "CustomConfigIncomplete",
                    "spec.custom.baseUrl is required for provider=custom",
                )
            return {"managed": True, "backendKind": "custom"}

        if status.get("gatewayTargetId"):
            # Bug #15: re-probe tools each reconcile so observedTools tracks
            # any out-of-band schema changes; fall back to whatever was last
            # observed if the probe fails.
            existing_id = status["gatewayTargetId"]
            gw_id = (
                spec.get("agentCoreGateway", {}).get("gatewayIdentifier")
                or status.get("gatewayIdentifier")
                or ""
            )
            observed_tools = status.get("observedTools") or []
            if gw_id:
                try:
                    client = self._agentcore_client()
                    declared = (spec.get("agentCoreGateway", {}) or {}).get("tools", []) or []
                    observed_tools = self._read_target_tools(
                        client, gw_id, existing_id, declared
                    )
                except Exception as e:
                    logger.warning(
                        "Bug #15: tool re-probe failed for %s: %s — preserving prior observedTools",
                        existing_id, e,
                    )
            return {
                "gatewayTargetId": existing_id,
                "gatewayIdentifier": gw_id or status.get("gatewayIdentifier"),
                "managed": status.get("managed", True),
                "observedTools": observed_tools,
            }

        acg = spec.get("agentCoreGateway", {})
        mcp_srv = acg.get("mcpServer", {})
        gw_id = acg.get("gatewayIdentifier", "")
        adopt_target_id = acg.get("adoptTargetId", "").strip()
        tools = acg.get("tools", [])
        tool_name = spec.get("toolName", "unknown")

        # ════════════════════════════════════════════════════════════════════
        # ADOPT MODE (Batch L, 2026-05-06)
        # ════════════════════════════════════════════════════════════════════
        # Operator reads the existing target by ID and surfaces its observed
        # tools in status. NEVER creates, updates, or deletes the target.
        # Registry registration happens as usual (catalog + drift detection
        # still work). deprovision_backend() checks managed flag and skips
        # cleanup in adopt mode.
        # ════════════════════════════════════════════════════════════════════
        if adopt_target_id:
            if not gw_id:
                raise ProvisioningFailed(
                    "GatewayMissing",
                    "agentCoreGateway.adoptTargetId requires gatewayIdentifier "
                    "(which gateway hosts the adopted target)",
                )
            try:
                client = self._agentcore_client()
                target = client.get_gateway_target(
                    gatewayIdentifier=gw_id, targetId=adopt_target_id
                )
            except Exception as e:
                raise ProvisioningFailed(
                    "AdoptedTargetNotFound",
                    f"cannot read gateway target {adopt_target_id} in {gw_id}: {e}",
                )

            if target.get("status") != "READY":
                raise ProvisioningFailed(
                    "AdoptedTargetNotReady",
                    f"adopted target {adopt_target_id} status={target.get('status')}",
                )

            # Extract observed tools from the backing target for discovery/audit
            tc = target.get("targetConfiguration", {}) or {}
            mcp_cfg = tc.get("mcp", {}) or {}
            lambda_cfg = mcp_cfg.get("lambda", {}) or {}
            observed_tools = (
                lambda_cfg.get("toolSchema", {}).get("inlinePayload", []) or []
            )

            logger.info(
                "ADOPT mode — target=%s gateway=%s observed_tools=%d (operator is read-only)",
                adopt_target_id, gw_id, len(observed_tools),
            )
            return {
                "gatewayTargetId": adopt_target_id,
                "gatewayIdentifier": gw_id,
                "managed": False,
                "observedTools": observed_tools,
            }

        # ════════════════════════════════════════════════════════════════════
        # MANAGED MODE — operator creates the Gateway target
        # ════════════════════════════════════════════════════════════════════

        if not gw_id:
            raise ProvisioningFailed("GatewayMissing",
                                     "spec.agentCoreGateway.gatewayIdentifier is required "
                                     "(create an AgentCore Gateway first)")
        endpoint = mcp_srv.get("endpoint", "")
        transport = mcp_srv.get("transport", "streamable-http")

        # Early validation: explicit backing blocks must not be empty if declared.
        # (Better to return a specific error than fall through to NoToolsDeclared.)
        if "smithyModel" in acg and not (
            acg["smithyModel"].get("inlinePayload") or acg["smithyModel"].get("s3")
        ):
            raise ProvisioningFailed(
                "SmithyModelIncomplete",
                "spec.agentCoreGateway.smithyModel requires either inlinePayload or s3"
            )
        if "openApiSchema" in acg and not (
            acg["openApiSchema"].get("inlinePayload") or acg["openApiSchema"].get("s3")
        ):
            raise ProvisioningFailed(
                "OpenApiSchemaIncomplete",
                "spec.agentCoreGateway.openApiSchema requires either inlinePayload or s3"
            )

        # tools[] is REQUIRED for Lambda targets (we build a toolSchema from them).
        # It is OPTIONAL for any target that declares its own schema:
        #   - mcpServer: remote server declares tools via MCP handshake
        #   - apiGateway: Gateway infers tools from REST API + toolOverrides
        #   - smithyModel: Smithy model defines the tools
        #   - openApiSchema (explicit): OpenAPI spec declares operations-as-tools
        is_mcp_server = (
            (endpoint.startswith("https://") or endpoint.startswith("http://"))
            and transport in ("streamable-http", "sse")
        )
        has_self_describing_backing = (
            is_mcp_server
            or acg.get("apiGateway")
            or acg.get("smithyModel")
            or acg.get("openApiSchema")
        )
        if not tools and not has_self_describing_backing:
            raise ProvisioningFailed(
                "NoToolsDeclared",
                "spec.agentCoreGateway.tools must list at least one tool "
                "(except for mcpServer / apiGateway / smithyModel / openApiSchema "
                "targets, which declare tools via their own mechanism)"
            )

        try:
            import json
            client = self._agentcore_client()
            try:
                gw = client.get_gateway(gatewayIdentifier=gw_id)
                if gw.get("status") != "READY":
                    raise ProvisioningFailed("GatewayNotReady",
                                             f"Gateway {gw_id} status={gw.get('status')} "
                                             "(wait for READY)")
            except client.exceptions.ResourceNotFoundException:
                raise ProvisioningFailed("GatewayMissing",
                                         f"Gateway {gw_id} not found in account")

            target_name = tool_name.replace("_", "-")[:48]

            # ── IDEMPOTENCY: if a target with this name already exists in the
            # gateway, reuse it instead of creating a duplicate. Protects
            # customers from the "MoDaaS polluted my gateway with duplicate
            # targets" issue that surfaced in the 2026-05-05 canary exercise.
            existing_id = None
            try:
                for page in client.get_paginator("list_gateway_targets").paginate(
                    gatewayIdentifier=gw_id
                ):
                    for t in page.get("items", []):
                        if t.get("name") == target_name:
                            existing_id = t.get("targetId")
                            break
                    if existing_id:
                        break
            except Exception as e:
                logger.warning(f"list_gateway_targets probe failed, will attempt create: {e}")

            if existing_id:
                logger.info(
                    "IDEMPOTENT reuse — target name=%s already exists (id=%s), not re-creating",
                    target_name, existing_id,
                )
                # Bug #15: also project tools on the idempotent-reuse path.
                observed_tools = self._read_target_tools(
                    client, gw_id, existing_id, tools
                )
                return {
                    "gatewayTargetId": existing_id,
                    "gatewayIdentifier": gw_id,
                    "managed": True,
                    "observedTools": observed_tools,
                }

            # ─── T-2/T-6 credentialProviderConfigurations pass-through ───
            # Per docs/archive/2026-05-06-Operator-Transparency-Audit.md §T-2/T-6.
            # AgentCore Gateway accepts these credentialProviderType enum values:
            #   GATEWAY_IAM_ROLE        Gateway's own IAM role (default for Lambda)
            #   OAUTH                   Registered OAuth provider ARN
            #   API_KEY                 API key header/query param
            #   JWT_PASSTHROUGH         Caller's JWT is forwarded verbatim
            #   CALLER_IAM_CREDENTIALS  Caller's IAM credentials are forwarded
            #
            # MoDaaS CRD adds a virtual NONE value that represents "omit the
            # credentialProviderConfigurations array entirely" — used for public
            # no-auth MCP servers (e.g., aws-knowledge-mcp-server which accepts
            # anonymous requests).
            declared_cred_type = acg.get("credentialProviderType") or "GATEWAY_IAM_ROLE"
            cred_provider_block = acg.get("credentialProvider") or {}

            if declared_cred_type == "NONE":
                # Public / anonymous MCP target — omit credentialProviderConfigurations.
                # AgentCore Gateway does not send any auth; only valid for mcpServer
                # targets against servers that accept anonymous requests.
                base_kwargs = {
                    "gatewayIdentifier": gw_id,
                    "name": target_name,
                    "description": spec.get("description", f"MCP tool {tool_name}"),
                }
            else:
                cred_config = {"credentialProviderType": declared_cred_type}
                if declared_cred_type == "OAUTH" and "oauthCredentialProvider" in cred_provider_block:
                    cred_config["credentialProvider"] = {
                        "oauthCredentialProvider": cred_provider_block["oauthCredentialProvider"]
                    }
                elif declared_cred_type == "API_KEY" and "apiKeyCredentialProvider" in cred_provider_block:
                    cred_config["credentialProvider"] = {
                        "apiKeyCredentialProvider": cred_provider_block["apiKeyCredentialProvider"]
                    }

                # Special case: mcpServer targets with GATEWAY_IAM_ROLE require an explicit
                # iamCredentialProvider sub-block (AWS returns ValidationException otherwise).
                if is_mcp_server and declared_cred_type == "GATEWAY_IAM_ROLE":
                    cred_config.setdefault("credentialProvider", {})
                    cred_config["credentialProvider"]["iamCredentialProvider"] = {
                        "service": acg.get("iamService", "bedrock-agentcore"),
                    }

                base_kwargs = {
                    "gatewayIdentifier": gw_id,
                    "name": target_name,
                    "description": spec.get("description", f"MCP tool {tool_name}"),
                    "credentialProviderConfigurations": [cred_config],
                }

            # ═════════════════════════════════════════════════════════════════
            # Dispatch — this operator implements 5 of the targetConfiguration.mcp
# sub-kinds (apiGateway, lambda, mcpServer, openApiSchema, smithyModel).
# GA (botocore 1.43.x) has since expanded the surface: a 6th mcp sub-kind
# (connector — managed 3P connectors) and two NEW top-level kinds
# (http: agentcoreRuntime|passthrough|connector; inference: connector|
# provider). None are reachable from this dispatch; adding them is a
# scoped design decision, not a patch — inference.* overlaps ModelConfig's
# domain (see docs/analysis/Operator-GA-Drift-Evaluation-2026-09-01.md).
            # Operator must transparently expose ALL of them per:
            #   - docs/design/principles/Governance-vs-API-Passthrough-Principle.md
            #   - docs/archive/2026-05-06-Operator-Transparency-Audit.md (T-3, T-4, T-5)
            #
            # Two styles of declaration the operator supports:
            #
            #   A) EXPLICIT backing block (preferred for non-Lambda targets):
            #        spec.agentCoreGateway.apiGateway      → apiGateway target
            #        spec.agentCoreGateway.smithyModel     → smithyModel target
            #        spec.agentCoreGateway.openApiSchema   → openApiSchema target
            #
            #   B) ENDPOINT-INFERRED (backward compat + simplest for Lambda/MCP):
            #        mcpServer.endpoint = "arn:aws:lambda:*"  → lambda target
            #        mcpServer.endpoint = "http(s)://..."     → mcpServer target
            #                                                     (or openApiSchema if tools[] given)
            #
            # Explicit blocks win if present — an operator SHOULD NOT guess when
            # the user has told it what they want.
            # ═════════════════════════════════════════════════════════════════

            apigw_block = acg.get("apiGateway")
            smithy_block = acg.get("smithyModel")
            openapi_block = acg.get("openApiSchema")

            if apigw_block:
                # T-5: native apiGateway target — wraps an existing AWS API Gateway
                # REST API as governed MCP tools.
                target_config_inner = {
                    "restApiId": apigw_block["restApiId"],
                    "stage": apigw_block.get("stage", "prod"),
                }
                tool_config_block = apigw_block.get("apiGatewayToolConfiguration")
                if tool_config_block:
                    target_config_inner["apiGatewayToolConfiguration"] = tool_config_block
                base_kwargs["targetConfiguration"] = {
                    "mcp": {"apiGateway": target_config_inner}
                }

            elif smithy_block:
                # T-4: native smithyModel target. Supports inlinePayload + s3.
                smithy_target = {}
                if "inlinePayload" in smithy_block:
                    smithy_target["inlinePayload"] = smithy_block["inlinePayload"]
                if "s3" in smithy_block:
                    smithy_target["s3"] = smithy_block["s3"]
                if not smithy_target:
                    raise ProvisioningFailed(
                        "SmithyModelIncomplete",
                        "spec.agentCoreGateway.smithyModel requires either inlinePayload or s3"
                    )
                base_kwargs["targetConfiguration"] = {
                    "mcp": {"smithyModel": smithy_target}
                }

            elif openapi_block:
                # T-2 polish: explicit openApiSchema block — inlinePayload OR s3.
                oapi_target = {}
                if "inlinePayload" in openapi_block:
                    oapi_target["inlinePayload"] = openapi_block["inlinePayload"]
                if "s3" in openapi_block:
                    oapi_target["s3"] = openapi_block["s3"]
                if not oapi_target:
                    raise ProvisioningFailed(
                        "OpenApiSchemaIncomplete",
                        "spec.agentCoreGateway.openApiSchema requires either inlinePayload or s3"
                    )
                base_kwargs["targetConfiguration"] = {
                    "mcp": {"openApiSchema": oapi_target}
                }

            elif endpoint.startswith("arn:aws:lambda:"):
                base_kwargs["targetConfiguration"] = {
                    "mcp": {
                        "lambda": {
                            "lambdaArn": endpoint,
                            "toolSchema": {"inlinePayload": [
                                {
                                    "name": t["name"],
                                    "description": t.get("description", t["name"]),
                                    "inputSchema": t.get("inputSchema", {"type": "object"}),
                                }
                                for t in tools
                            ]},
                        }
                    }
                }
            elif endpoint.startswith("https://") or endpoint.startswith("http://"):
                # Transparent dispatch: https:// or http:// + MCP transport → native mcpServer.
                if is_mcp_server:
                    base_kwargs["targetConfiguration"] = {
                        "mcp": {"mcpServer": {"endpoint": endpoint}}
                    }
                else:
                    # Fallback: synthesize OpenAPI spec from CR tools[].
                    openapi_spec = self._build_openapi_spec(target_name, endpoint, tools)
                    base_kwargs["targetConfiguration"] = {
                        "mcp": {"openApiSchema": {"inlinePayload": json.dumps(openapi_spec)}}
                    }
            else:
                raise ProvisioningFailed(
                    "UnsupportedEndpoint",
                    f"endpoint must be an AWS Lambda ARN or https:// URL; got: {endpoint[:80]}"
                )

            resp = client.create_gateway_target(**base_kwargs)
            target_id = resp.get("targetId") or resp.get("gatewayTargetId")
        except ProvisioningFailed:
            raise
        except Exception as e:
            raise ProvisioningFailed("GatewayTargetCreateFailed", str(e))

        # Bug #15: project the target's tools to status.observedTools so
        # downstream consumers (drift detector, /v1/capabilities,
        # `kubectl get`, Registry record audit) can see the live tool set.
        # Adopt mode already populates observedTools from the read of the
        # adopted target; managed mode previously left it empty.
        observed_tools = self._read_target_tools(client, gw_id, target_id, tools)
        return {
            "gatewayTargetId": target_id,
            "gatewayIdentifier": gw_id,
            "managed": True,
            "observedTools": observed_tools,
        }

    def _read_target_tools(
        self, client, gw_id: str, target_id: str, declared_tools: list
    ) -> list:
        """Best-effort read-back of the Gateway target's tool list.

        For Lambda targets we created from `declared_tools`, AgentCore Gateway
        echoes the same toolSchema. For self-describing targets (mcpServer,
        smithyModel, openApiSchema, apiGateway) the Gateway resolves tools
        asynchronously — fall back to declared_tools if the schema isn't
        materialized yet. The 5-min resync timer will refresh whenever the
        Gateway catches up.
        """
        try:
            target = client.get_gateway_target(
                gatewayIdentifier=gw_id, targetId=target_id,
            )
        except Exception as e:
            logger.warning(
                "Bug #15: get_gateway_target after create failed for %s: %s — "
                "falling back to declared tools",
                target_id, e,
            )
            return list(declared_tools or [])

        tc = target.get("targetConfiguration", {}) or {}
        mcp_cfg = tc.get("mcp", {}) or {}
        lambda_cfg = mcp_cfg.get("lambda", {}) or {}
        from_lambda = lambda_cfg.get("toolSchema", {}).get("inlinePayload", []) or []
        if from_lambda:
            return from_lambda

        # Non-Lambda backings advertise tools via different paths; if AgentCore
        # surfaces them in any of these locations use them, else fall through.
        for surface_path in (
            ("mcpServer", "tools"),
            ("openApiSchema", "tools"),
            ("smithyModel", "tools"),
            ("apiGateway", "tools"),
        ):
            sub = mcp_cfg
            for key in surface_path:
                sub = (sub or {}).get(key) or {}
            if isinstance(sub, list) and sub:
                return sub

        return list(declared_tools or [])

    def check_schema_drift(self, spec: dict, status: dict) -> tuple[bool, str, list]:
        """Adopt-mode schema drift detection (#2 from adversarial review).

        For adopt-mode ToolConfigs, the backing Gateway target is owned by the
        customer and can change out-of-band — new tools added, existing tools
        removed, schemas edited. Our Registry record is frozen at reconcile
        time, so it can drift silently. This re-probes the Gateway and diffs.

        Returns (drift_detected, reason, current_tools).
        """
        managed = status.get("managed", True)
        if managed is True:
            return False, "NotAdoptMode", []

        adopt_cfg = spec.get("agentCoreGateway", {}) or {}
        target_id = adopt_cfg.get("adoptTargetId") or status.get("gatewayTargetId")
        gw_id = adopt_cfg.get("gatewayIdentifier") or status.get("gatewayIdentifier")
        if not target_id or not gw_id:
            return False, "NotAdoptMode", []

        try:
            target = self._agentcore_client().get_gateway_target(
                gatewayIdentifier=gw_id, targetId=target_id,
            )
        except Exception as e:
            return False, f"GatewayProbeFailed: {type(e).__name__}", []

        tc = target.get("targetConfiguration", {}) or {}
        mcp_cfg = tc.get("mcp", {}) or {}
        lambda_cfg = mcp_cfg.get("lambda", {}) or {}
        current = lambda_cfg.get("toolSchema", {}).get("inlinePayload", []) or []
        prev = status.get("observedTools") or []

        import json as _json
        def _sig(t):
            return {
                "name": t.get("name"),
                "description": t.get("description", ""),
                "inputSchema": _json.dumps(t.get("inputSchema") or {}, sort_keys=True),
            }
        cur_by_name = {t.get("name"): _sig(t) for t in current if t.get("name")}
        prev_by_name = {t.get("name"): _sig(t) for t in prev if t.get("name")}
        cur_names = set(cur_by_name.keys())
        prev_names = set(prev_by_name.keys())

        added = cur_names - prev_names
        removed = prev_names - cur_names
        changed = [n for n in cur_names & prev_names if cur_by_name[n] != prev_by_name[n]]

        if added:
            return True, f"AdoptedSchemaToolAdded: {sorted(added)[0]}", current
        if removed:
            return True, f"AdoptedSchemaToolRemoved: {sorted(removed)[0]}", current
        if changed:
            return True, f"AdoptedSchemaDetailChanged: {sorted(changed)[0]}", current
        return False, "AdoptedSchemaUnchanged", current

    @staticmethod
    def _build_openapi_spec(tool_name: str, backing_endpoint: str, tools: list) -> dict:
        """Synthesize a minimal OpenAPI 3.0 spec for the declared tools.
        AgentCore Gateway translates this into MCP tool definitions."""
        paths = {}
        for t in tools:
            name = t["name"]
            paths[f"/{name}"] = {
                "post": {
                    "operationId": name,
                    "summary": t.get("description", name),
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": t.get("inputSchema", {"type": "object"})
                            }
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "tool response",
                            "content": {
                                "application/json": {"schema": {"type": "object"}}
                            },
                        }
                    },
                }
            }
        return {
            "openapi": "3.0.0",
            "info": {"title": tool_name, "version": "1.0.0"},
            "servers": [{"url": backing_endpoint or "http://localhost:8080"}],
            "paths": paths,
        }

    def deprovision_backend(self, status: dict) -> None:
        target_id = (status or {}).get("gatewayTargetId")
        gw_id = (status or {}).get("gatewayIdentifier")
        managed = (status or {}).get("managed", True)  # default True for backward compat
        if not target_id:
            return
        # ── ADOPT MODE (Batch L): preserve the backing target on CR deletion.
        # The operator only cleans up resources IT created. Adopted targets
        # are customer-owned and must survive governance CR lifecycle.
        #
        # Fail-safe: ANY non-True value (False, None, missing-with-null, etc.)
        # is treated as adopt mode. Only explicit True cascades deletion.
        # Previously used `is False` which incorrectly treated None as managed.
        if managed is not True:
            logger.info(
                "ADOPT mode (managed=%r) — skipping delete_gateway_target for %s "
                "(gateway %s). Operator does not clean up resources it did not create.",
                managed, target_id, gw_id,
            )
            return
        try:
            self._agentcore_client().delete_gateway_target(
                gatewayIdentifier=gw_id or "", targetId=target_id)
            logger.info(f"delete_gateway_target succeeded for {target_id}")
        except Exception as e:
            logger.warning(f"delete_gateway_target failed for {target_id}: {e}")


# Singleton
_tool_operator = ToolOperator()


# ── W1.A: condition surfacing helpers ──

def _classify_k8s_error(exc: Exception) -> str:
    """Classify a K8s/network exception into a condition reason string."""
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
    from datetime import datetime, timezone
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


# ── a hardening note / a gap note: upstream host check ──
#
# A custom ToolConfig reached Approved with a backend host that did not exist
# (demo-crm-lookup, 2026-09-19): every call then died at the perimeter with
# "backends required DNS resolution which failed". The check below answers
# ONLY the question this pod can answer truthfully: does the host exist in DNS?
#
# It deliberately does NOT open a TCP connection. The chart's operator egress
# NetworkPolicy (templates/networkpolicy/operators.yaml) allows this pod DNS
# and TCP 443, nothing else, so a connect to a backend on 8080/8000 fails here
# even when the dataplane in agentgateway-system reaches it fine. The first
# version of this gate (d4fbacef, never shipped) probed TCP and would have
# held every custom ToolConfig the workshop ships in Reviewing.
#
# Only a definitive "no such host" blocks. A resolver timeout or other
# transient error is recorded as Unknown and does not block: it is not
# evidence the host is missing.
UPSTREAM_RECHECK_ANNOTATION = "modaas.tmforum.org/upstream-recheck"
_DNS_MISSING_ERRNOS = frozenset(
    getattr(_socket, n) for n in ("EAI_NONAME", "EAI_NODATA") if hasattr(_socket, n)
)


def _resolve_upstream_host(base_url: str) -> tuple:
    """Return (verdict, detail) for spec.custom.baseUrl's host.

    verdict is "resolved", "missing" (blocks Approved), or "unknown"
    (does not block). detail is safe to put in a condition message.
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(base_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as e:
        return "missing", f"baseUrl {base_url!r} is not a valid URL: {e}"
    if not host:
        return "missing", f"could not parse a host from baseUrl {base_url!r}"
    try:
        _socket.getaddrinfo(host, port, type=_socket.SOCK_STREAM)
        return "resolved", f"{host} resolves in cluster DNS"
    except _socket.gaierror as e:
        if e.errno in _DNS_MISSING_ERRNOS:
            return "missing", f"{host} does not exist in DNS ({e})"
        return "unknown", f"DNS lookup for {host} did not complete ({e}); not treated as missing"
    except Exception as e:  # noqa: BLE001 -- the check must never crash reconcile
        return "unknown", (f"DNS lookup for {host} failed unexpectedly "
                           f"({type(e).__name__}); not treated as missing")


# ── kopf handlers ──

@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    settings.watching.server_timeout = 60
    logger.info(f"Tool Operator started — watching {PLURAL}.{GROUP}/{VERSION}")


@kopf.on.resume(GROUP, VERSION, PLURAL, retries=5)
@kopf.on.create(GROUP, VERSION, PLURAL, retries=5)
@kopf.on.update(GROUP, VERSION, PLURAL, retries=5)
@traced("operator.tool.reconcile", attrs={"operator.kind": "ToolConfig"})
async def reconcile(spec, status, meta, name, namespace, patch, body=None, **_):
    if spec.get("provider") not in CLAIMED_PROVIDERS:
        try:
            from shared.provider_claim import mark_unclaimed
        except ModuleNotFoundError:
            import sys as _s, os as _o
            _r = _o.path.abspath(_o.path.join(_o.path.dirname(__file__), ".."))
            _r in _s.path or _s.path.insert(0, _r)
            from shared.provider_claim import mark_unclaimed
        mark_unclaimed(patch, status, spec.get("provider"), " or ".join(CLAIMED_PROVIDERS))
        return

    # Seed live conditions into the patch BEFORE this handler sets any: a
    # status patch replaces the whole list, and several conditions below are
    # written before the inner reconcile's own seed runs (and the a hardening note hold
    # skips the inner call entirely). Without this, one handler run erases
    # every condition an earlier run or the resync timer wrote. Contract:
    # AssetOperator._seed_conditions, "call once at the start of any handler
    # that sets conditions".
    _tool_operator._seed_conditions(patch, status)

    # ── W2.A: Operator-emitted Component CR per asset (Bucket 2) ──
    try:
        try:
            from shared.component_owner import ensure_component, SKIP_COMPONENT_ANNOTATION
        except ModuleNotFoundError:
            import sys as _sys, os as _os
            _shared_root = _os.path.abspath(
                _os.path.join(_os.path.dirname(__file__), "..")
            )
            if _shared_root not in _sys.path:
                _sys.path.insert(0, _shared_root)
            from shared.component_owner import ensure_component, SKIP_COMPONENT_ANNOTATION
        import kubernetes as _k8s
        try:
            _k8s.config.load_incluster_config()
        except _k8s.config.config_exception.ConfigException:
            _k8s.config.load_kube_config()
        _custom = _k8s.client.CustomObjectsApi()

        annotations = (meta or {}).get("annotations") or {}
        skipComponent = annotations.get(SKIP_COMPONENT_ANNOTATION, "").lower() == "true"
        if not skipComponent:
            comp = ensure_component(
                k8s_api=_custom,
                namespace=namespace,
                source_kind="ToolConfig",
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
    except Exception as _comp_err:
        logger.warning("W2.A Component emission failed for %s: %s", name, _comp_err)

    logger.info(f"Reconciling {name}: tool={spec.get('toolName')}")

    # ── a design note / a design note — Canvas integration (Bucket 2) ──
    # W1.A: Each canvas-integration action surfaces failures as conditions.
    _custom = None
    try:
        try:
            from shared.component_owner import build_owner_reference
            from shared.identity_config import ensure_identity_config
        except ModuleNotFoundError:
            import sys as _sys, os as _os
            _shared_root = _os.path.abspath(
                _os.path.join(_os.path.dirname(__file__), "..")
            )
            if _shared_root not in _sys.path:
                _sys.path.insert(0, _shared_root)
            from shared.component_owner import build_owner_reference
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

    if _custom is not None:
        try:
            owner = build_owner_reference(meta, _custom)
            if owner is not None:
                existing = (meta or {}).get("ownerReferences") or []
                if not any(r.get("uid") == owner["uid"] for r in existing):
                    patch.metadata["ownerReferences"] = list(existing) + [owner]
                _set_condition(
                    patch, "OwnedByComponent", "True", "ComponentLinked",
                    f"Owned by Component {owner['name']}",
                )
        except Exception as _owner_err:
            _reason = _classify_k8s_error(_owner_err)
            _set_condition(
                patch, "OwnedByComponent", "False", _reason,
                f"Component lookup failed: {str(_owner_err)[:256]}",
            )
            logger.warning("a design note Component ownerRef failed for %s: %s", name, _owner_err)

    # a design note (W2.B): per-asset IdentityConfig — Component as owner for cascade-delete
    if _custom is not None:
        try:
            # W2.B: Use Component as owner_reference (from W2.A above).
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
                source_kind="ToolConfig",
                source_name=name,
                owner_reference=identity_owner,
            )
            _set_condition(
                patch, "IdentityProvisioned", "True", "IdentityConfigCreated",
                f"IdentityConfig modaas-toolconfig-{name} provisioned via Canvas",
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
                # U12 (tool-server-fixture): dialects_for(provider) is still called
                # for its defensive purpose (U4's own refusal path — if the shared
                # registry stops recognizing a provider CLAIMED_PROVIDERS above still
                # claims, refuse loudly rather than silently misroute), but its
                # RETURN VALUE is not what this operator uses below. Every ToolConfig
                # is MCP-shaped regardless of provider: dialects_for("custom") would
                # return "openai-compat" (/v1/chat/completions — the model-shaped path
                # ModelConfig's own "custom" provider wants, a different CRD sharing
                # the same provider string), which is wrong for a tool. agentCoreGateway
                # already resolves correctly to "agentcore-mcp" (/mcp/{alias}); this
                # pins that same, correct wire format directly for both claimed
                # providers rather than deriving it per-provider. A future ToolConfig
                # provider that is NOT MCP-shaped would need this line revisited.
                dialects_for(provider)
                wire_formats = ["agentcore-mcp"]
            except UnmappedProviderError as e:
                patch.status["phase"] = "Failed"
                _tool_operator._emit_phase_change(meta, status, status.get("phase", "Unknown"), "Failed")
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
                # DependentAPI gave us a resolved (typically public) URL — publish
                # to BOTH endpoint and globalResourceEndpoint per a design note (status.endpoint
                # is the perimeter URL agents read). Helper keeps shape consistent
                # across model/tool/agent operators.
                try:
                    from shared.perimeter_url import compute_and_publish_perimeter_url
                except ModuleNotFoundError:
                    from operators.shared.perimeter_url import compute_and_publish_perimeter_url  # type: ignore
                alias = spec.get("alias", name)
                # When DependentAPI resolved we still call the shared helper so the
                # mesh/vpc/public endpoints map gets populated. Then override with
                # the resolved URL — Canvas's resolution wins over scope auto-probe.
                compute_and_publish_perimeter_url(
                    alias=alias, wire_format=primary_wf,
                    status_patch=patch.status, k8s_api=_custom,
                    all_wire_formats=wire_formats,
                )
                patch.status["endpoint"] = resolved_endpoint
                patch.status["globalResourceEndpoint"] = resolved_endpoint
                patch.status["endpointScope"] = "public"
                _set_condition(
                    patch, "DependentAPIProvisioned", "True", "DependentAPICreated",
                    f"DependentAPI resolved: {resolved_endpoint}",
                )
            else:
                # a design note layer 2: emit all reachable scopes (mesh/vpc/public)
                # and pick the broadest as the canonical perimeter URL.
                # Auto-resolves Istio LoadBalancer ELB DNS for public scope so
                # AgentCore Runtime in PUBLIC mode can reach the gateway.
                try:
                    from shared.perimeter_url import compute_and_publish_perimeter_url
                except ModuleNotFoundError:
                    from operators.shared.perimeter_url import compute_and_publish_perimeter_url  # type: ignore
                alias = spec.get("alias", name)
                _best_scope, _best_url = compute_and_publish_perimeter_url(
                    alias=alias, wire_format=primary_wf,
                    status_patch=patch.status, k8s_api=_custom,
                    all_wire_formats=wire_formats,
                )
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

    # W4.C: Per-asset Istio VirtualService + AuthorizationPolicy
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
                kind="ToolConfig",
            )
            _set_condition(patch, "IstioPerAssetProvisioned", "True", "IstioReady",
                           f"VirtualService + AuthorizationPolicy emitted for {name}")
        except Exception as _istio_err:
            _reason = _classify_k8s_error(_istio_err)
            _set_condition(patch, "IstioPerAssetProvisioned", "False", _reason,
                           f"Istio VS/AuthZ emission failed: {str(_istio_err)[:256]}")
            logger.warning("W4.C Istio VS/AuthZ failed for %s: %s", name, _istio_err)

    # W4.D: Egress allowlist for the tool's provider
    if _custom is not None:
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
            # ToolConfig has no agentCoreGateway.region field (CRD v1beta1);
            # the Gateway lives in the operator's own Region.
            from operators.shared.aws_region import resolve_region
            _egress_region = resolve_region()
            emit_egress_for_provider(
                k8s_api=_custom, namespace=namespace,
                provider=provider, region=_egress_region,
                owner_reference=None,
            )
            _se_name = service_entry_name_for(provider, _egress_region)
            _set_condition(patch, "EgressAllowlisted", "True", "ServiceEntryCreated",
                           f"ServiceEntry {_se_name} created for {provider} in {_egress_region}")
        except Exception as _eg_err:
            _reason = _classify_k8s_error(_eg_err)
            _set_condition(patch, "EgressAllowlisted", "False", _reason,
                           f"Egress allowlist failed: {str(_eg_err)[:256]}")
            logger.warning("W4.D egress allowlist failed for %s: %s", name, _eg_err)

    # ── a design note/a design note: PDP Cedar-policy projection (tool path enforcement) ──
    # ADDITIVE + GUARDED: only fires when the ToolConfig carries an inline
    # cedarPolicy (the grant-capable PRIMARY, per a design note). ToolConfigs without
    # it are untouched — default behavior is unchanged so merging cannot break
    # the live booth. Projects the policy text into a label-scoped ConfigMap in
    # modaas-system that the in-cluster PDP watcher hot-loads; the AI Gateway
    # tool path then calls POST <pdp>/decide (fail-closed, a design note). ConfigMaps
    # need CoreV1Api (not the CustomObjectsApi used above).
    _cedar_policy = ((spec.get("access") or {}).get("cedarPolicy") or "")
    if _cedar_policy.strip():
        try:
            try:
                from shared.policy_projection import (
                    ensure_policy_configmap,
                    resolve_policy_id,
                )
            except ModuleNotFoundError:
                from operators.shared.policy_projection import (  # type: ignore
                    ensure_policy_configmap,
                    resolve_policy_id,
                )
            import kubernetes as _k8s_pp
            try:
                _k8s_pp.config.load_incluster_config()
            except _k8s_pp.config.config_exception.ConfigException:
                _k8s_pp.config.load_kube_config()
            _core = _k8s_pp.client.CoreV1Api()

            _policy_id = resolve_policy_id(spec, "ToolConfig", name)
            _projected = ensure_policy_configmap(
                core_v1_api=_core,
                source_kind="ToolConfig",
                source_name=name,
                policy_id=_policy_id,
                policy_text=_cedar_policy,
            )
            if _projected:
                patch.status["access"] = {
                    **(patch.status.get("access") or {}),
                    "pdpPolicyId": _projected,
                }
                _set_condition(
                    patch, "PolicyProjected", "True", "PolicyConfigMapProjected",
                    f"Cedar policy projected to PDP as policyId {_projected}",
                )
            else:
                _set_condition(
                    patch, "PolicyProjected", "False", "ProjectionSkipped",
                    "Cedar policy projection returned no policyId (see operator logs)",
                )
        except Exception as _pp_err:
            _reason = _classify_k8s_error(_pp_err)
            _set_condition(
                patch, "PolicyProjected", "False", _reason,
                f"Cedar policy projection failed: {str(_pp_err)[:256]}",
            )
            logger.warning("a design note policy projection failed for %s: %s", name, _pp_err)

    # ── a hardening note / a gap note: hold a custom ToolConfig in Reviewing while its backend
    # host does not exist (see _resolve_upstream_host for why this is a DNS
    # check only). Runs before Approved and never demotes an Approved CR, so a
    # transient DNS blip cannot tear down a serving tool. When the host starts
    # resolving, resync_from_registry touches UPSTREAM_RECHECK_ANNOTATION and
    # the CR proceeds without re-attestation. Only the inner provisioning call
    # is skipped -- NOT the whole handler -- so the agentgateway block below
    # still withdraws any stale route for a CR held here.
    _h16_host_missing = False
    if spec.get("provider") == "custom" and (status or {}).get("phase") != "Approved":
        _custom_spec = spec.get("custom") or {}
        _base_url = _custom_spec.get("baseUrl") or ""
        if _custom_spec.get("skipReachabilityCheck"):
            _set_condition(
                patch, "UpstreamResolvable", "True", "CheckSkipped",
                "spec.custom.skipReachabilityCheck=true: the operator did not check the backend host",
            )
        elif _base_url:
            _verdict, _detail = _resolve_upstream_host(_base_url)
            if _verdict == "missing":
                _h16_host_missing = True
                _set_condition(patch, "UpstreamResolvable", "False", "HostNotFound", _detail)
                patch.status["phase"] = "Reviewing"
                patch.status["reason"] = "UpstreamUnreachable"
                _tool_operator._stamp(patch, meta)
                logger.warning("a hardening note: %s backend host missing, holding in Reviewing: %s",
                               name, _detail)
            elif _verdict == "resolved":
                _set_condition(
                    patch, "UpstreamResolvable", "True", "HostResolves",
                    f"{_detail}. Only DNS is checked from the operator; "
                    "the dataplane's own connection to the backend is not",
                )
            else:
                _set_condition(patch, "UpstreamResolvable", "Unknown", "LookupIncomplete", _detail)

    if _h16_host_missing:
        _result = {"message": "backend host does not exist", "phase": "Reviewing"}
    else:
        _result = _tool_operator.reconcile(spec, status or {}, meta, patch)

    # U12 (tool-server-fixture): program agentgateway's native MCP proxying for
    # a `custom`-provider ToolConfig — the call site `agentgateway_mcp_backend.py`
    # was written and unit-tested for but not yet wired (disclosed gap in that
    # unit's code-summary). Mirrors model_operator.py's own agentgateway block:
    # convergent on current phase (re-applied every reconcile while Approved,
    # withdrawn otherwise), gated by MODAAS_PROGRAM_AGENTGATEWAY=true.
    #
    # Lane H (plan task 1.12 / R11, a design note): this block now serves BOTH claimed
    # providers. It was scoped to provider=="custom" on the reasoning that
    # "agentCoreGateway tools are routed by AWS's own managed Gateway" — which
    # is precisely the bypass R11 closes. The DependentAPI block above
    # publishes `status.endpoint = <agw>/mcp/{alias}` for EVERY ToolConfig
    # (wire_format_registry maps agentCoreGateway -> agentcore-mcp ->
    # /mcp/{alias}), so an agentCoreGateway alias advertised a governed
    # perimeter URL with no route behind it: it 404'd, and agents reached the
    # AWS gateway directly, skipping the ext_authz Cedar decision (a design note/
    # a design note) and metering. Owner decision 2026-09-26.
    #
    # The two providers need different backends, not one parameterized backend:
    # `custom` addresses an in-cluster MCP server over plaintext with no
    # backend auth; `agentCoreGateway` addresses an AWS-managed HTTPS endpoint
    # requiring outbound SigV4 signed with service `bedrock-agentcore` by the
    # agentgateway pod's own IRSA identity. Hence two emit functions, one
    # shared HTTPRoute shape.
    _agw_provider = spec.get("provider")
    if _custom is not None and _agw_provider in CLAIMED_PROVIDERS:
        try:
            try:
                from shared.agentgateway_route import agentgateway_enabled
                from shared.agentgateway_mcp_backend import (
                    emit_agentgateway_backend, delete_agentgateway_backend,
                )
                from shared import agentcore_gateway_perimeter as _perimeter
            except ModuleNotFoundError:
                from operators.shared.agentgateway_route import agentgateway_enabled
                from operators.shared.agentgateway_mcp_backend import (
                    emit_agentgateway_backend, delete_agentgateway_backend,
                )
                from operators.shared import agentcore_gateway_perimeter as _perimeter
            if agentgateway_enabled():
                _merged = {**(status or {})}
                try:
                    _merged.update({k: v for k, v in patch.status.items()})
                except Exception:
                    pass
                _phase = _merged.get("phase") or patch.status.get("phase")
                _servable = _phase == "Approved" and not spec.get("paused")
                _is_acg = _agw_provider == PROVIDER
                if _servable and not _is_acg:
                    _agw = emit_agentgateway_backend(_custom, alias=name, spec=spec)
                    if _agw == "skipped":
                        _set_condition(
                            patch, "AgentgatewayRouteProgrammed", "False", "ProviderNotRoutable",
                            "spec.custom.baseUrl is absent or unparseable",
                        )
                    else:
                        _set_condition(
                            patch, "AgentgatewayRouteProgrammed", "True", "RouteProgrammed",
                            f"AgentgatewayBackend+HTTPRoute for {name} applied",
                        )
                elif _servable:
                    # Refuse rather than sign for an invented region: with
                    # AWS_REGION unset, agentgateway would fall back to the
                    # dataplane pod's ambient region (aws.rs:583-595) and the
                    # signature would be silently wrong. Same lesson as
                    # b7ec8dcc on the ModelConfig side.
                    # Same resolver as every boto3 call (spec > AWS_REGION >
                    # AWS_DEFAULT_REGION); the chart only sets the latter, so
                    # reading AWS_REGION here left every route unprogrammed
                    # (PerimeterMisconfigured on 8/8 tools, E4 2026-10-03).
                    try:
                        from operators.shared.aws_region import resolve_region as _rr
                    except ImportError:
                        from shared.aws_region import resolve_region as _rr
                    try:
                        _agw_region = _rr()
                    except Exception:
                        _agw_region = ""
                    if not _agw_region:
                        _set_condition(
                            patch, "AgentgatewayRouteProgrammed", "False",
                            "PerimeterMisconfigured",
                            "no AWS Region configured on the operator (AWS_REGION/AWS_DEFAULT_REGION); refusing to program a "
                            "SigV4 route that would sign for the dataplane pod's ambient region",
                        )
                    else:
                        _agw = _perimeter.emit_agentcore_mcp_backend(
                            _custom, alias=name, spec=spec, status=_merged,
                            region=_agw_region,
                        )
                        if _agw == "skipped":
                            _set_condition(
                                patch, "AgentgatewayRouteProgrammed", "False",
                                "ProviderNotRoutable",
                                "no AgentCore Gateway identifier in "
                                "spec.agentCoreGateway.gatewayIdentifier or "
                                "status.gatewayIdentifier",
                            )
                        else:
                            _set_condition(
                                patch, "AgentgatewayRouteProgrammed", "True", "RouteProgrammed",
                                f"AgentgatewayBackend+HTTPRoute for {name} applied "
                                f"(SigV4 to AgentCore Gateway in {_agw_region})",
                            )
                    # The AWS-side half of the perimeter: the gateway resource
                    # policy that makes it reachable by the dataplane principal
                    # ONLY. Rendered here, applied by a separate reconcile step
                    # — so this condition never reads True (a design note; the
                    # "declared but not enforced" class loop/ exists to catch).
                    _pe_status, _pe_reason, _pe_message = _perimeter.perimeter_enforcement_state(
                        gateway_identifier=_perimeter.resolve_gateway_identifier(spec, _merged),
                        region=_agw_region,
                        account_id=(os.environ.get("MODAAS_AWS_ACCOUNT_ID") or "").strip(),
                        principal_arn=(os.environ.get("MODAAS_AGW_SIGNING_ROLE_ARN") or "").strip(),
                    )
                    _set_condition(patch, "PerimeterEnforced", _pe_status,
                                   _pe_reason, _pe_message)
                else:
                    if _is_acg:
                        _perimeter.delete_agentcore_mcp_backend(_custom, alias=name)
                    else:
                        delete_agentgateway_backend(_custom, alias=name)
                    _withdrawn = (f"phase={_phase} paused={bool(spec.get('paused'))}; "
                                  f"route withdrawn")
                    _set_condition(
                        patch, "AgentgatewayRouteProgrammed", "False", "NotServable",
                        _withdrawn,
                    )
                    if _is_acg:
                        _set_condition(
                            patch, "PerimeterEnforced", "False", "NotServable", _withdrawn,
                        )
        except Exception as _agw_err:
            logger.warning("agentgateway MCP backend programming failed for %s: %s", name, _agw_err)
            _set_condition(
                patch, "AgentgatewayRouteProgrammed", "False", "ProgramFailed",
                f"agentgateway MCP backend programming failed: {str(_agw_err)[:256]}",
            )

    return _result


@kopf.on.delete(GROUP, VERSION, PLURAL, retries=5)
async def cleanup(spec, status, name, **_):
    # U7 (tool-provider-claim) review fix: this gate predates CLAIMED_PROVIDERS
    # and was never updated when "custom" became a second claimed value — a
    # deleted provider=custom ToolConfig was silently skipping
    # _tool_operator.cleanup() (no _deprecate_in_registry / _tmf639_delete),
    # leaking its Registry record forever with no cleanup path.
    if spec.get("provider") not in CLAIMED_PROVIDERS:
        return
    logger.info(f"Cleaning up {name}")
    _tool_operator.cleanup(spec, status or {})


# ── K8s-idiomatic resync timers (a design note) ────────────────────────────────── #

@kopf.timer(GROUP, VERSION, PLURAL, interval=300, idle=30, retries=3)
async def resync_from_registry(spec, status, patch, name, **_):
    """Every 5 minutes, read Registry + update status fields.

    Also runs adopt-mode schema drift detection (#2) — re-probes the Gateway
    target and diffs against status.observedTools. Drift surfaces in
    status.driftDetected + driftReason (shows in DRIFT printer column).
    """
    # U7 (tool-provider-claim) review fix: same stale-gate class as
    # cleanup() above — provider=custom ToolConfigs were never resynced.
    if spec.get("provider") not in CLAIMED_PROVIDERS:
        return
    # Seeded after the ownership guard, before any write (see reconcile).
    # Sensor: operators/shared/tests/test_handlers_keep_conditions.py
    _tool_operator._seed_conditions(patch, status)
    try:
        status_dict = dict(status) if status else {}

        # a hardening note / a gap note: a CR held in Reviewing because its backend host did not
        # exist is re-checked here. Once the host resolves, touch an annotation
        # so the create/update handler re-runs and the CR proceeds -- the
        # approval annotations are untouched, so no re-attestation is needed.
        if (spec.get("provider") == "custom"
                and status_dict.get("phase") == "Reviewing"
                and status_dict.get("reason") == "UpstreamUnreachable"):
            _base = (spec.get("custom") or {}).get("baseUrl") or ""
            if _base and _resolve_upstream_host(_base)[0] == "resolved":
                from datetime import datetime, timezone
                patch.metadata.annotations[UPSTREAM_RECHECK_ANNOTATION] = (
                    datetime.now(timezone.utc).isoformat())
                logger.info("a hardening note: %s backend host now resolves; re-running reconcile", name)

        result = _tool_operator.resync_from_registry(spec, status_dict, patch)

        drift, reason, _current = _tool_operator.check_schema_drift(spec, status_dict)
        if drift:
            logger.info(f"schema-drift {name}: {reason}")
            patch.status["driftDetected"] = True
            patch.status["driftReason"] = reason[:256]
        elif reason == "AdoptedSchemaUnchanged":
            if status_dict.get("driftDetected"):
                patch.status["driftDetected"] = False
                patch.status["driftReason"] = ""

        logger.info(f"resync {name}: {result} drift={reason}")
        return {**(result or {}), "drift_reason": reason}
    except Exception as e:
        logger.error(f"resync_from_registry failed for {name}: {type(e).__name__}: {e}",
                     exc_info=True)
        return {"error": str(e)}


@kopf.timer(GROUP, VERSION, PLURAL, interval=3600, initial_delay=60, idle=60, retries=3)
async def scan_orphan_records(patch, **_):
    """Every 1 hour, scan for Registry records with no matching ToolConfig CR."""
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
        cr_names = [it.get("spec", {}).get("toolName")
                    for it in cr_list.get("items", [])
                    if it.get("spec", {}).get("toolName")]
        # U7 (tool-provider-claim) review fix: registry_naming.py's sanitizer
        # prefixes a "custom"-provider record as "custom_<toolName>", not
        # "agentcoregateway_<toolName>" — scanning only the latter prefix made
        # every custom-provider orphan permanently invisible to this scan.
        orphans = []
        for _prefix in ("agentcoregateway", "custom"):
            orphans.extend(_tool_operator.scan_orphans(cr_names, provider_prefix=_prefix))
        if orphans:
            logger.warning(f"Found {len(orphans)} orphan Registry records: {orphans}")
        else:
            logger.info(f"Orphan scan clean — {len(cr_names)} CRs, all Registry records accounted for")
        return {"orphans": orphans, "scanned_crs": len(cr_names)}
    except Exception as e:
        logger.error(f"scan_orphan_records failed: {type(e).__name__}: {e}", exc_info=True)
        return {"error": str(e)}
