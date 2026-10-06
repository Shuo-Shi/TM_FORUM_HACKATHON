"""AWS Agent Operator — AgentConfig v1beta1

Concrete AssetOperator subclass that provisions AWS AgentCore Runtime
for agents declared via AgentConfig CRs. Watches AgentConfig CRDs.

As of a design note (2026-05-04), this operator ONLY supports the `awsAgentCore`
provider. The legacy `kubernetes` provider (Istio + Keycloak wrapper around
externally-deployed K8s pods) has been removed — the aws-agent-operator
is AWS-specific, and AgentCore Runtime is AWS's canonical agent hosting
target. Future community operators may add other hosting providers via
separate sibling operators.
"""

import logging
import os
import time
from operators.shared.asset_operator import AssetOperator, ProvisioningFailed
from operators.shared.aws_region import resolve_region

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

logger = logging.getLogger("AgentOperator")

COMPONENTS_NS = os.environ.get("COMPONENT_NAMESPACE", "components")

# AgentCore NetworkConfiguration.networkMode Valid Values (API reference fetched
# 2026-09-26). There is no PRIVATE: the CRD used to admit one, admission passed
# it, and AWS rejected the create call with an opaque ValidationException.
SUPPORTED_NETWORK_MODES = ("PUBLIC", "VPC")

# ── The one platform execution role (owner decision 2026-09-26, a design note Q1) ──
# Every MoDaaS-MANAGED AgentCore runtime executes as this single least-privilege
# role, supplied by the deployment (helm sets it from the AgentCoreRuntimeRoleArn
# stack output, described there as "no direct Bedrock or AgentCore Gateway
# access"). It is deliberately NOT read from the CR: the capability gate below is
# the reason agentgateway can be the only door to a governed asset, and a caller
# who names the execution role names their own capability, which turns "the
# perimeter is the only path" from a property into a request. Admission refuses
# spec.awsAgentCore.roleArn in managed mode; this constant is the replacement.
PLATFORM_EXECUTION_ROLE_ENV = "MODAAS_AGENTCORE_RUNTIME_ROLE_ARN"

# Cache boto3 clients per region to avoid per-reconcile connection pool churn
_ctrl_clients: dict[str, object] = {}
_iam_clients: dict[str, object] = {}

#: Bounded wait for a runtime to leave CREATING/UPDATING before deleting it
#: (10 minutes). Module constants so tests set them to zero instead of sleeping.
RUNTIME_SETTLE_POLL_S = 10.0
RUNTIME_SETTLE_MAX_POLLS = 60
_RUNTIME_BUSY_STATES = ("CREATING", "UPDATING")


class RuntimeStillBusy(Exception):
    """The runtime never left CREATING/UPDATING; kopf retries the delete."""


def _error_code(exc) -> str:
    return (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")


def _region_from_arn(arn) -> str:
    """arn:aws:bedrock-agentcore:<region>:<account>:runtime/<id> -> region."""
    parts = (arn or "").split(":")
    return parts[3] if len(parts) > 3 and parts[2] == "bedrock-agentcore" else ""


def _agentcore_ctrl(region: str):
    if region not in _ctrl_clients:
        import boto3
        _ctrl_clients[region] = boto3.client("bedrock-agentcore-control", region_name=region)
    return _ctrl_clients[region]


def _read_secret_value(namespace: str, name: str, key: str) -> str:
    """Decoded value of one key of one Secret. Used only by the AgentCore
    credential seam's sharedKey mode, whose RBAC (chart: a Role on that one
    Secret name) is the only secrets access this operator has. Raises on any
    read failure; the seam turns that into a condition reason."""
    import base64

    import kubernetes

    try:
        kubernetes.config.load_incluster_config()
    except kubernetes.config.config_exception.ConfigException:
        kubernetes.config.load_kube_config()
    secret = kubernetes.client.CoreV1Api().read_namespaced_secret(name, namespace)
    raw = (secret.data or {}).get(key)
    return base64.b64decode(raw).decode("utf-8") if raw else ""


def _iam_client():
    """Cached IAM client. IAM is global, so there is one.

    A named accessor (rather than `boto3.client("iam")` inline) is what lets the
    execution-role capability gate be exercised offline: unit tests patch this
    one symbol instead of patching boto3 for every service.
    """
    if "global" not in _iam_clients:
        import boto3
        _iam_clients["global"] = boto3.client("iam")
    return _iam_clients["global"]


class _K8sClient:
    """Thin wrapper around kubernetes.client for reading sibling CRs
    (ModelConfig, ToolConfig) during the cross-asset dependency gate.

    This is READ-ONLY use of the K8s API — the operator does NOT create
    Istio/Keycloak/Deployment resources (those were part of the removed
    kubernetes provider path; see a design note).
    """

    def __init__(self):
        from kubernetes import client, config
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        self._api = client.CustomObjectsApi()

    def get(self, group: str, version: str, plural: str, name: str, namespace: str = None) -> dict:
        ns = namespace or COMPONENTS_NS
        return self._api.get_namespaced_custom_object(group, version, ns, plural, name)


class AgentOperator(AssetOperator):

    @property
    def record_type(self) -> str:
        return "agent"

    @property
    def resource_plural(self) -> str:
        return "agentconfigs"

    def _k8s_client(self):
        return _K8sClient()

    def _build_registry_metadata(self, spec: dict, status: dict) -> dict:
        """W3.C: Rich metadata for agent registry records.

        Populates invocation (AgentCore Runtime ARN), agentCard, dependsOn,
        governance, and componentRef (from W2.A).
        """
        md = super()._build_registry_metadata(spec, status)
        md["invocation"] = {
            "protocol": "agentcore-runtime",
            "runtimeArn": status.get("agentRuntimeArn", ""),
        }
        if spec.get("agentCard"):
            md["agentCard"] = spec["agentCard"]
        if spec.get("dependsOn"):
            md["dependsOn"] = spec["dependsOn"]
        if spec.get("governance"):
            md["governance"] = spec["governance"]
        return md

    def check_dependency_health(self, spec: dict, k8s) -> tuple[bool, str]:
        """Post-approval dependency health check (a design note cascade observability).

        Unlike `_validate_dependencies` which is an admission gate, this runs on
        a timer AFTER the AgentConfig has reached phase=Approved. It walks the
        dependsOn graph and returns (healthy: bool, reason: str) reflecting the
        live state of upstream deps.

        This does NOT auto-pause the AgentConfig. That would be cascading
        enforcement, which a design note marks as manual recovery. Instead it flips a
        DependencyHealthy status condition so `kubectl get` shows blast radius.

        Unhealthy states (in priority order):
          - Dep CR missing         → DependencyMissing
          - Dep phase != Approved   → DependencyNotApproved
          - Dep spec.paused == true → DependencyPaused
          - Dep retired/retireBy < today → DependencyRetired

        Returns:
            (True,  "AllDepsHealthy")                 when all deps clean
            (False, "<reason>: <which-dep>")           on first unhealthy dep
        """
        deps = spec.get("dependsOn", {}) or {}
        for kind, plural in [("models", "modelconfigs"), ("tools", "toolconfigs")]:
            for dep_name in deps.get(kind, []) or []:
                try:
                    cr = k8s.get("oda.tmforum.org", "v1beta1", plural, dep_name)
                except Exception:
                    return False, f"DependencyMissing: {plural}/{dep_name} not found"
                dep_spec = cr.get("spec", {}) or {}
                dep_status = cr.get("status", {}) or {}
                if dep_spec.get("paused"):
                    return False, f"DependencyPaused: {plural}/{dep_name}"
                dep_phase = dep_status.get("phase")
                if dep_phase == "Retired":
                    return False, f"DependencyRetired: {plural}/{dep_name}"
                if dep_phase == "Failed":
                    return False, f"DependencyFailed: {plural}/{dep_name}"
                if dep_phase != "Approved":
                    return False, f"DependencyNotApproved: {plural}/{dep_name} phase={dep_phase}"
        return True, "AllDepsHealthy"

    def _validate_dependencies(self, spec: dict, k8s, status: dict | None = None):
        """Cross-asset dependency gate — refuses INITIAL approval until every
        ModelConfig and ToolConfig referenced in spec.dependsOn is itself in
        phase=Approved.

        This is MoDaaS's signature governance primitive (see a design note proposed to TMF).

        IMPORTANT — admission semantics (Fix #14):
        ------------------------------------------
        This gate is intentionally an ADMISSION gate, not a steady-state gate.
        It hard-fails only on the FIRST provision attempt (status.phase is empty
        or Pending). Once an AgentConfig has reached phase=Approved, subsequent
        re-reconciles tolerate transient dep state (e.g., a ToolConfig briefly
        transitioning Approved→Reviewing during a schema drift re-approval).

        Rationale (per a design note cascade policy):
          - Governance commitment is made at approval time. An agent can't reach
            Approved unless all declared deps were Approved at that moment.
          - After approval, dep posture is OBSERVED (via check_dependency_health
            timer → DependencyHealthy condition), not ENFORCED via teardown. That
            was the anti-pattern Madi flagged: one ToolConfig in Reviewing state
            would cascade-fail every AgentConfig that referenced it.
          - Terminal states (Failed/Retired) are still reflected in the
            DependencyHealthy condition — operators/admins can manually pause or
            retire affected agents. That's an explicit human decision, not an
            implicit runtime cascade.

        Missing deps (K8s get raising) always fail regardless of phase — if a
        referenced CR is gone, the governance record is broken.
        """
        previously_approved = (status or {}).get("phase") == "Approved"
        deps = spec.get("dependsOn", {})

        # a design note composition truthfulness — refuse to approve when upstream
        # ModelConfig declares safety.required=true but this AgentConfig does
        # not attest to enforcing it (spec.safety.enforces + enforcerKind).
        # Attestation-based: MoDaaS trusts the AgentConfig author's declaration
        # at admission; runtime integrity is a separate concern. Imported
        # lazily so operators that don't bundle shared/composition (e.g.,
        # future sibling operators) can opt out.
        try:
            from operators.shared.composition import check_safety_enforcement_composable
            _composition_enabled = True
        except ImportError:
            # Fallback path for unit tests running outside the container where
            # sys.path is set to include operators/ directly
            try:
                from shared.composition import check_safety_enforcement_composable
                _composition_enabled = True
            except ImportError:
                _composition_enabled = False

        for model_ref in deps.get("models", []):
            try:
                cr = k8s.get("oda.tmforum.org", "v1beta1", "modelconfigs", model_ref)
            except Exception:
                raise ProvisioningFailed("DependencyMissing", f"ModelConfig '{model_ref}' not found")
            if not previously_approved and cr.get("status", {}).get("phase") != "Approved":
                raise ProvisioningFailed("DependencyNotApproved", f"ModelConfig '{model_ref}' not Approved")
            # a design note composition check: refuse if AgentConfig does not attest
            # to the safety enforcement the ModelConfig requires. Only applied
            # on INITIAL approval — once Approved, tolerate transient drift
            # (matches the DependencyNotApproved semantics above).
            if _composition_enabled and not previously_approved:
                violation = check_safety_enforcement_composable(spec, cr)
                if violation is not None:
                    raise ProvisioningFailed(violation.reason, violation.message)
        for tool_ref in deps.get("tools", []):
            try:
                cr = k8s.get("oda.tmforum.org", "v1beta1", "toolconfigs", tool_ref)
            except Exception:
                raise ProvisioningFailed("DependencyMissing", f"ToolConfig '{tool_ref}' not found")
            if not previously_approved and cr.get("status", {}).get("phase") != "Approved":
                raise ProvisioningFailed("DependencyNotApproved", f"ToolConfig '{tool_ref}' not Approved")

    def provision_backend(self, spec: dict, status: dict) -> dict:
        """Provision AWS AgentCore Runtime as the agent's hosting backend.

        Flow:
          1. Validate cross-asset dependencies (dep gate)
          2. Dispatch on awsAgentCore mode (import vs managed)
          3. Project Agent Registry record on success

        a design note (2026-06-12) restores dual-provider hosting: awsAgentCore
        (AWS-managed AgentCore Runtime) and kubernetesPod (in-cluster
        Deployment + Service). This re-broadens what a design note narrowed for the
        Phase-2 ship, now that the hosting abstraction has stabilized. Both
        providers honor the same dependsOn gate, governance, and Registry
        projection; the kubernetesPod path is the open, vendor-neutral peer
        that lets any agent framework be hosted under MoDaaS governance
        without an AWS dependency.
        """
        # 1. Dependencies validated first — cross-asset dep gate.
        # Passes `status` so the gate is admission-only (Fix #14):
        # if the agent is already Approved, transient dep non-Approved states
        # (e.g., a ToolConfig in Reviewing during schema drift re-approval)
        # don't knock the agent offline. Dep health is reflected via the
        # DependencyHealthy status condition instead (a design note / check_dependency_health).
        k8s = self._k8s_client()
        self._validate_dependencies(spec, k8s, status)

        # 2. Provider dispatch (a design note awsAgentCore + a design note kubernetesPod).
        # CRD admission CEL enforces matching provider-block presence; we guard
        # defensively here so unit tests / older CRD versions can't slip past.
        provider = spec.get("provider")
        if provider == "awsAgentCore":
            return self._provision_awsagentcore(spec, status)
        if provider == "kubernetesPod":
            return self._provision_kubernetes_pod(spec, status)
        raise ProvisioningFailed(
            "UnsupportedProvider",
            f"Provider '{provider}' is not supported. aws-agent-operator supports "
            f"'awsAgentCore' (a design note) and 'kubernetesPod' (a design note). Future community "
            f"operators may add other providers via sibling operators (a design note)."
        )

    def _inspect_execution_role(self, role_arn: str) -> dict:
        """Inspect an AgentCore execution role: advisory findings + capability.

        Returns a dict with:
          findings          -- iam_inspection.inspect_role output, plus a
                               capability finding when one applies
          allowed_actions   -- governed actions the role may call DIRECTLY
                               (non-empty means this role can bypass the
                               perimeter); see execution_role_capability
          undetermined      -- non-empty when the capability could not be
                               decided. NEVER read as "clean".
          cap_status/reason/message -- scratch condition triple the module-level
                               handler turns into ExecutionRoleCapability.

        One helper for both hosting modes. Before this, inspection lived inline
        in the import branch only, which is why managed mode -- where MoDaaS
        creates the runtime and asserts ownership -- never looked at the role
        at all (review goal 1(a2), the inverse of the risk ordering).
        """
        from iam_inspection import inspect_role
        from execution_role_capability import (
            capability_finding,
            check_execution_role_capability,
            unverified_finding,
        )

        findings: list[dict] = []
        try:
            iam = _iam_client()
            findings = inspect_role(iam, role_arn)
        except Exception as e:  # noqa: BLE001 — advisory pass, never fatal here
            logger.warning("IAM inspection failed for %s: %s", role_arn, e)
            findings = [{
                "severity": "LOW",
                "code": "IAM_INSPECTION_FAILED",
                "message": str(e),
            }]
            return {
                "findings": findings,
                "allowed_actions": [],
                "undetermined": (
                    f"could not inspect {role_arn} ({type(e).__name__}: {e}); "
                    f"capability is unverified"
                ),
                "cap_status": "Unknown",
                "cap_reason": "InspectionFailed",
                "cap_message": str(e),
            }

        allowed, undetermined = check_execution_role_capability(iam, role_arn)
        if allowed:
            findings = findings + [capability_finding(allowed, role_arn)]
            return {
                "findings": findings,
                "allowed_actions": allowed,
                "undetermined": "",
                "cap_status": "False",
                "cap_reason": "CanInvokeDirectly",
                "cap_message": capability_finding(allowed, role_arn)["message"],
            }
        if undetermined:
            findings = findings + [unverified_finding(undetermined, role_arn)]
            return {
                "findings": findings,
                "allowed_actions": [],
                "undetermined": undetermined,
                "cap_status": "Unknown",
                "cap_reason": "Unverified",
                "cap_message": undetermined,
            }
        return {
            "findings": findings,
            "allowed_actions": [],
            "undetermined": "",
            "cap_status": "True",
            "cap_reason": "NoDirectInvokeCapability",
            "cap_message": (
                f"{role_arn} cannot call a governed asset directly; the perimeter "
                f"is the only path"
            ),
        }

    def _provision_awsagentcore(self, spec: dict, status: dict) -> dict:
        """Manage AgentCore Runtime lifecycle for the agent.

        Expects spec.awsAgentCore.{agentRuntimeId | containerUri, region}:
          - If agentRuntimeId is provided: adopt existing runtime (import mode).
            The execution role is OBSERVED from AWS.
          - If containerUri: create or update a runtime owned by this CR. The
            execution role is the single platform role from operator config
            (PLATFORM_EXECUTION_ROLE_ENV), never from the CR.

        Either way the role actually used is published as
        status.executionRoleArn.

        Environment variables injected into the runtime are derived from spec:
          MODEL_ALIAS, TOOL_ALIAS, REGISTRY_ID (resolved from the asset's
          Registry, never a literal) and the a design note SDK-redirect vars, including
          the PERIMETER MCP URL for each tool dep. The raw AgentCore Gateway URL
          is never forwarded (review P0-2).
        """
        from botocore.exceptions import ClientError

        agent_name = spec.get("agentName", "unknown")
        ac_cfg = spec.get("awsAgentCore", {})
        region = resolve_region(ac_cfg.get("region"))
        ctrl = _agentcore_ctrl(region)

        # Import mode: existing runtime ID supplied
        existing_id = ac_cfg.get("agentRuntimeId")
        if existing_id and not ac_cfg.get("containerUri"):
            try:
                resp = ctrl.get_agent_runtime(agentRuntimeId=existing_id)
                rt_status = resp.get("status")
                if rt_status not in ("READY", "CREATING", "UPDATING"):
                    raise ProvisioningFailed("RuntimeNotHealthy",
                                             f"AgentCore Runtime {existing_id} status={rt_status}")
                # IAM risk inspection (#5) — advisory in ADOPT mode, and
                # deliberately so: refusing here would flip already-Approved
                # adopted agents (the 5 EACO runtimes) to Failed, and the live
                # population cannot be enumerated from a worktree. The managed
                # branch below refuses; adopt surfaces
                # ExecutionRoleCapability=False. See LANE_REPORT.md.
                #
                # AWS is the ONLY source here. The CR's roleArn used to be a
                # fallback, which meant a caller could make the operator inspect
                # (and publish) a role the runtime does not actually assume — an
                # attestation about the wrong principal.
                role_arn = resp.get("roleArn")
                if role_arn:
                    insp = self._inspect_execution_role(role_arn)
                else:
                    insp = {
                        "findings": [],
                        "cap_status": "Unknown",
                        "cap_reason": "NoRoleObserved",
                        "cap_message": (
                            f"AgentCore Runtime {existing_id} reported no roleArn and the "
                            f"CR declares none; execution-role capability is unknown"
                        ),
                    }
                adopted = {
                    "agentRuntimeId": existing_id,
                    "agentRuntimeArn": resp.get("agentRuntimeArn"),
                    "hostingProvider": "awsAgentCore",
                    "managed": False,
                    "riskFindings": insp["findings"],
                    "executionRoleCapabilityStatus": insp["cap_status"],
                    "executionRoleCapabilityReason": insp["cap_reason"],
                    "executionRoleCapabilityMessage": insp["cap_message"],
                    # Adopt mode never writes the runtime's environmentVariables,
                    # so the operator cannot claim anything about whether this
                    # agent reaches the perimeter.
                    "perimeterReachableStatus": "Unknown",
                    "perimeterReachableReason": "EnvNotManaged",
                    "perimeterReachableMessage": (
                        "adopt mode: the operator does not manage this runtime's "
                        "environmentVariables, so it neither redirects the agent to the "
                        "perimeter nor supplies a credential"
                    ),
                }
                # Absent rather than empty-string when AWS reports no role: a
                # blank ARN in status reads as a fact about the runtime.
                if role_arn:
                    adopted["executionRoleArn"] = role_arn
                return adopted
            except ClientError as e:
                raise ProvisioningFailed("RuntimeFetchFailed",
                                         f"get_agent_runtime({existing_id}): {e}")

        # Managed mode: create or update the runtime
        container_uri = ac_cfg.get("containerUri")
        if not container_uri:
            raise ProvisioningFailed("ConfigIncomplete",
                                     "awsAgentCore provider requires either agentRuntimeId "
                                     "(import) or containerUri (managed).")

        # ── Local invariants first: never spend an AWS call on an incoherent spec ──
        net_mode = spec.get("networkMode", "PUBLIC")
        if net_mode not in SUPPORTED_NETWORK_MODES:
            raise ProvisioningFailed(
                "UnsupportedNetworkMode",
                f"spec.networkMode={net_mode!r} is not an AgentCore network mode. "
                f"Valid Values: {' | '.join(SUPPORTED_NETWORK_MODES)} "
                f"(NetworkConfiguration, AgentCore control-plane API). Admission now "
                f"refuses other values; this CR predates that CRD or bypassed admission.",
            )
        from request_header_config import (
            RequestHeaderConfigInvalid,
            resolve_request_header_configuration,
        )
        try:
            request_header_config = resolve_request_header_configuration(ac_cfg)
        except RequestHeaderConfigInvalid as e:
            raise ProvisioningFailed("RequestHeaderConfigInvalid", str(e))

        # ── The execution role comes from operator config, not the CR ──
        # Fail closed and loud when it is missing: the alternative is letting
        # create_agent_runtime pick whatever AWS defaults to, i.e. hosting a
        # governed agent under an unknown principal, which is precisely what the
        # capability gate below exists to make impossible.
        role_arn = (os.environ.get(PLATFORM_EXECUTION_ROLE_ENV) or "").strip()
        if not role_arn:
            raise ProvisioningFailed(
                "PlatformExecutionRoleUnset",
                f"managed AgentCore hosting needs the platform execution role and "
                f"{PLATFORM_EXECUTION_ROLE_ENV} is unset or empty. Set it on the "
                f"aws-agent-operator Deployment "
                f"(helm: --set-string operators.agent.agentCoreRuntimeRoleArn=<arn>, "
                f"value = the AgentCoreRuntimeRoleArn stack output). It is not read "
                f"from the CR by design: a caller-supplied role would let an agent "
                f"hold capability MoDaaS never granted it.",
            )

        # ── Capability interposition gate (a design note §1, review P2-6) ──
        # agentgateway can only be the sole door to a governed model or tool if
        # the workload cannot open it itself. A managed runtime is one MoDaaS
        # creates, so MoDaaS refuses to create it under a role that can invoke
        # Bedrock or an AgentCore Gateway directly -- and refuses equally when it
        # cannot PROVE the role cannot (fail closed: "unverified" must never read
        # as "clean", which is how warning-only inspection failed).
        insp = self._inspect_execution_role(role_arn)
        if insp["allowed_actions"]:
            raise ProvisioningFailed(
                "ExecutionRoleCanInvokeDirectly",
                f"Execution role {role_arn} is allowed to call "
                f"{', '.join(insp['allowed_actions'])} directly, so agent "
                f"'{agent_name}' could bypass the MoDaaS perimeter entirely. Remove "
                f"those grants (or add an explicit Deny) so only the gateway's role "
                f"holds them, then re-apply. Note bedrock:InvokeModel* also authorizes "
                f"Converse/ConverseStream.",
            )
        if insp["undetermined"]:
            raise ProvisioningFailed(
                "ExecutionRoleCapabilityUnverified",
                f"Refusing to create a runtime whose execution-role capability is "
                f"unverified: {insp['undetermined']} The operator's own role needs "
                f"iam:SimulatePrincipalPolicy for {role_arn}.",
            )

        # Derive env vars for the agent to self-resolve aliases via Registry
        deps = spec.get("dependsOn", {})
        env_vars = {"REGION": region}
        # ── REGISTRY_ID: from the asset's Registry, else the operator env, else
        # NOT AT ALL. The literal default that used to sit here shipped one
        # account's registry id into every runtime (review P3-9).
        try:
            from shared.registry_id import resolve_registry_id
        except ImportError:
            from operators.shared.registry_id import resolve_registry_id
        registry_id, registry_id_source, registry_id_reason = resolve_registry_id(
            spec.get("registryRef"),
            k8s_client=self._k8s_client() if hasattr(self, "_k8s_client") else None,
            env_value=os.environ.get("REGISTRY_ID"),
        )
        if registry_id:
            env_vars["REGISTRY_ID"] = registry_id
            registry_scratch = {
                "registryIdResolvedStatus": "True",
                "registryIdResolvedReason": (
                    "ResolvedFromRegistryCR" if registry_id_source == "registryCR"
                    else "ResolvedFromOperatorEnv"
                ),
                "registryIdResolvedMessage": registry_id_reason,
            }
        else:
            logger.warning(
                "REGISTRY_ID not injected for agent '%s': %s", agent_name, registry_id_reason
            )
            registry_scratch = {
                "registryIdResolvedStatus": "False",
                "registryIdResolvedReason": "Unresolved",
                "registryIdResolvedMessage": registry_id_reason,
            }
        model_alias = (deps.get("models") or [None])[0]
        tool_alias = (deps.get("tools") or [None])[0]
        # Legacy back-compat (aws-genie etc. still read these); a design note below
        # supersedes for new agents using standard SDKs.
        if model_alias:
            env_vars["MODEL_ALIAS"] = model_alias
        if tool_alias:
            env_vars["TOOL_ALIAS"] = tool_alias

        # ── a design note (2026-05-20) — standard SDK env-var injection ──
        # Resolve each model dep to its provider so we can pick the right
        # SDK env var (AWS_ENDPOINT_URL_BEDROCK_RUNTIME for aws-bedrock,
        # AWS_ENDPOINT_URL_SAGEMAKER_RUNTIME for aws-sagemaker, etc.).
        # The agent's existing client library reads these natively — zero
        # code change. REQ-001 invariant: never inject MODAAS_*-prefixed
        # env names; only documented vendor SDK env vars.
        #
        # Fail-mode taxonomy (Task #49):
        #   404 NotFound  → dep CR missing; skip injection for that alias
        #                   (a design note DependencyHealthy condition is the
        #                   visibility surface; runtime creation continues
        #                   so other deps still get redirected).
        #   403 Forbidden → operator RBAC missing 'get modelconfigs'; this
        #                   is a deployment bug, fail loud.
        #   Other ApiException / network → fail with DepResolveFailed; kopf
        #                   retries. Don't ship a half-injected env block.
        #
        # There is NO opt-out. spec.awsAgentCore.skipEnvInjection (Task #50) used
        # to skip this whole block; it is removed and refused at admission. An
        # opt-out from the perimeter redirect is a documented bypass, which
        # project.md forbids for a guardrail ("the litellm failure class is the
        # exact failure MoDaaS exists to eliminate").
        try:
            from shared.sdk_redirect import env_vars_for_dependencies
        except ImportError:
            from operators.shared.sdk_redirect import env_vars_for_dependencies
        from kubernetes.client.exceptions import ApiException

        # a design note layer 2: pick best-scope gateway URL for the AgentCore
        # Runtime. The runtime executes in an AWS-managed VPC and cannot
        # resolve cluster.local — prefer public ELB DNS, then VPC
        # PrivateLink host, then mesh as last resort. Operator-wide
        # MODAAS_GATEWAY_URL env override beats compute when set.
        try:
            from shared.dependent_api import (
                compute_all_endpoints, pick_best_endpoint,
            )
        except ImportError:
            from operators.shared.dependent_api import (
                compute_all_endpoints, pick_best_endpoint,
            )
        # Compute scope hosts only — strip the wire-format path so
        # env_vars_for_provider can append its own per-provider path.
        _scope_eps = compute_all_endpoints(
            asset_alias="_base_", wire_format="openai-compat",
            k8s_api=self._k8s_client() if hasattr(self, "_k8s_client") else None,
        )
        # Strip the path tail (everything from '/v1/chat/completions' on)
        # to recover the bare host base for sdk_redirect.
        def _strip_wire_path(url):
            if not url:
                return None
            # openai-compat path is '/v1/chat/completions' — strip it.
            marker = "/v1/chat/completions"
            idx = url.find(marker)
            return url[:idx] if idx >= 0 else url
        _bases = {k: _strip_wire_path(v) for k, v in _scope_eps.items()}
        _best_scope_inj, _best_base = pick_best_endpoint(_bases)
        _explicit_override = os.environ.get("MODAAS_GATEWAY_URL")
        if _explicit_override:
            modaas_gateway_url = _explicit_override
        else:
            # R4 fix (ai-gateway retirement): the literal fallback pointed
            # at the retired host. Latent today (compute_all_endpoints
            # always yields a mesh URL), but a latent dead default is how
            # R1 shipped -- use the shared source of truth instead.
            if not _best_base:
                try:
                    from shared.dependent_api import _GATEWAY_BASE_DEFAULT, _with_port
                except ImportError:
                    from operators.shared.dependent_api import _GATEWAY_BASE_DEFAULT, _with_port
                _best_base = _with_port(_GATEWAY_BASE_DEFAULT, "openai-compat")
            modaas_gateway_url = _best_base
            if _best_scope_inj == "mesh":
                logger.warning(
                    "a design note/a design note env var injection: best available scope "
                    "is 'mesh' for agent '%s'. AgentCore Runtime in PUBLIC "
                    "mode cannot resolve %s. Set MODAAS_PUBLIC_GATEWAY_HOST "
                    "or provision the Istio LoadBalancer to expose a public "
                    "ELB DNS, or set MODAAS_VPC_GATEWAY_HOST for PrivateLink.",
                    agent_name, modaas_gateway_url,
                )
        resolved_deps_models: list[dict] = []
        unresolved_aliases: list[str] = []
        k8s = self._k8s_client() if hasattr(self, "_k8s_client") else None
        for alias in deps.get("models") or []:
            if k8s is None:
                unresolved_aliases.append(alias)
                continue
            try:
                cr = k8s.get("oda.tmforum.org", "v1beta1", "modelconfigs", alias)
            except ApiException as e:
                if e.status == 404:
                    logger.info(
                        "a design note dep '%s' not found (404); skipping env injection for it. "
                        "DependencyHealthy condition will reflect the missing dep.",
                        alias,
                    )
                    unresolved_aliases.append(alias)
                    continue
                if e.status == 403:
                    raise ProvisioningFailed(
                        "OperatorRbacMissing",
                        f"Operator service account lacks 'get modelconfigs' (Forbidden) "
                        f"while resolving a design note dep '{alias}'. Fix the ClusterRoleBinding "
                        f"for the aws-agent-operator SA in modaas-system.",
                    )
                raise ProvisioningFailed(
                    "DepResolveFailed",
                    f"Kubernetes API returned {e.status} {e.reason} resolving "
                    f"modelconfig '{alias}' for a design note env injection.",
                )
            provider = (cr or {}).get("spec", {}).get("provider")
            if provider:
                resolved_deps_models.append({"alias": alias, "provider": provider})
            else:
                unresolved_aliases.append(alias)

        sdk_env = env_vars_for_dependencies(resolved_deps_models, modaas_gateway_url)
        env_vars.update(sdk_env)
        if unresolved_aliases:
            logger.warning(
                "a design note unresolved aliases (no provider injected): %s",
                unresolved_aliases,
            )

        # ── Tool deps: the PERIMETER MCP URL, not the raw AWS gateway ──
        # Review P0-2 / goal 1(g). This path used to inject
        # spec.awsAgentCore.agentCoreGatewayMcpUrl verbatim while the
        # kubernetesPod path routed the same env var through
        # env_vars_for_tool_provider -- so pod agents went to the governance
        # perimeter and AWS-native agents went straight to AWS. Same helper,
        # same fail-soft-per-alias tolerance as the models loop above; the
        # declared raw URL is no longer read (admission refuses it alongside
        # dependsOn.tools, and a design note makes status.endpoint the only URL an
        # agent is told).
        try:
            from shared.sdk_redirect import env_vars_for_tool_provider
        except ImportError:
            from operators.shared.sdk_redirect import env_vars_for_tool_provider
        for alias in deps.get("tools") or []:
            if k8s is None:
                unresolved_aliases.append(alias)
                continue
            try:
                cr = k8s.get("oda.tmforum.org", "v1beta1", "toolconfigs", alias)
                provider_name = (cr or {}).get("spec", {}).get("provider")
                if not provider_name:
                    continue
                env_vars.update(
                    env_vars_for_tool_provider(
                        provider_name,
                        gateway_url=modaas_gateway_url,
                        asset_alias=alias,
                    )
                )
            except Exception as _tool_err:  # noqa: BLE001 — per-alias fail-soft
                logger.info(
                    "a design note tool dep '%s' not resolved (%s); no MCP URL injected for it. "
                    "DependencyHealthy condition reflects the missing dep.",
                    alias, type(_tool_err).__name__,
                )

        # ── a hardening note on the AgentCore path: the credential behind that URL ──
        # One seam (operators/shared/sdk_redirect.agentcore_gateway_credential_env).
        # Empty today, so the operator publishes PerimeterReachable=False with
        # the seam's own reason rather than redirecting silently.
        try:
            from shared.sdk_redirect import agentcore_gateway_credential_env
        except ImportError:
            from operators.shared.sdk_redirect import agentcore_gateway_credential_env
        cred_env, cred_reason = agentcore_gateway_credential_env(
            read_secret=_read_secret_value)
        if cred_env:
            env_vars.update(cred_env)
            perimeter_scratch = {
                "perimeterReachableStatus": "True",
                "perimeterReachableReason": "CredentialInjected",
                "perimeterReachableMessage": (
                    f"redirected to {modaas_gateway_url} with a gateway credential"
                ),
            }
        else:
            logger.warning(
                "a hardening note (AgentCore path): agent '%s' is redirected to %s with no "
                "gateway credential -- %s",
                agent_name, modaas_gateway_url, cred_reason,
            )
            perimeter_scratch = {
                "perimeterReachableStatus": "False",
                "perimeterReachableReason": "GatewayCredentialUnavailable",
                "perimeterReachableMessage": cred_reason,
            }

        safe_runtime_name = agent_name.replace("-", "_")[:40]
        artifact = {"containerConfiguration": {"containerUri": container_uri}}

        # ── The caller's own settings (spec.awsAgentCore.environmentVariables) ──
        # Merged last so every operator-owned name is known; any collision with
        # one is refused, not resolved (see operators/shared/agentcore_env.py).
        try:
            from shared.agentcore_env import DeclaredEnvInvalid, merge_declared_env
        except ImportError:
            from operators.shared.agentcore_env import DeclaredEnvInvalid, merge_declared_env
        try:
            env_vars = merge_declared_env(ac_cfg.get("environmentVariables"), env_vars)
        except DeclaredEnvInvalid as e:
            raise ProvisioningFailed("DeclaredEnvInvalid", str(e))

        existing_runtime_id = status.get("agentRuntimeId")
        try:
            # A-4: networkConfiguration — pass networkModeConfig through when the
            # mode requires it (VPC). Per
            # docs/archive/2026-05-06-Operator-Transparency-Audit.md §A-4.
            # Governance-relevant: dataClassification=restricted + networkMode=PUBLIC
            # is a contradiction; restricted workloads should run in VPC mode with
            # declared subnets + security groups. `net_mode` was validated against
            # SUPPORTED_NETWORK_MODES above, before any AWS call.
            network_config = {"networkMode": net_mode}
            if net_mode == "VPC":
                nmc = ac_cfg.get("networkModeConfig")
                if nmc:
                    network_config["networkModeConfig"] = nmc

            base_kwargs = {
                "agentRuntimeArtifact": artifact,
                "networkConfiguration": network_config,
                "roleArn": role_arn,
                "environmentVariables": env_vars,
                # A-9 (review goal 3): the header allowlist AgentCore forwards
                # into the runtime. MoDaaS's default carries traceparent/baggage
                # so a design note's evidence chain joins the caller's trace instead of
                # minting a fresh root per hop; a caller-declared block wins.
                "requestHeaderConfiguration": request_header_config,
            }

            # ── Transparent pass-through of AgentCore Runtime optional blocks ──
            # Per docs/design/principles/Governance-vs-API-Passthrough-Principle.md and
            # docs/archive/2026-05-06-Operator-Transparency-Audit.md §A-5/A-6/A-8:
            # operator must transparently forward the native AgentCore Runtime
            # capabilities declared under spec.awsAgentCore.*. Implicit closed-world
            # dispatch was the class of gap we're closing.

            # A-5: authorizerConfiguration — typically used to point the runtime at
            # Keycloak or another customJWTAuthorizer. Closes the openai-hello
            # Keycloak-reachability gap: AgentCore Runtime can now trust the same
            # tokens the AI Gateway does.
            if "authorizerConfiguration" in ac_cfg:
                base_kwargs["authorizerConfiguration"] = ac_cfg["authorizerConfiguration"]

            # A-6: protocolConfiguration — declare whether the agent serves MCP,
            # HTTP, or A2A. AgentCore Runtime uses this to route incoming requests
            # correctly.
            if "protocolConfiguration" in ac_cfg:
                base_kwargs["protocolConfiguration"] = ac_cfg["protocolConfiguration"]

            # A-8: lifecycleConfiguration — idleRuntimeSessionTimeout + maxLifetime.
            # Governance-relevant: controls long-running agent session economics
            # and enforces bounded-lifetime for sensitive workloads.
            if "lifecycleConfiguration" in ac_cfg:
                base_kwargs["lifecycleConfiguration"] = ac_cfg["lifecycleConfiguration"]

            if existing_runtime_id:
                logger.info(f"Updating AgentCore Runtime {existing_runtime_id}")
                resp = ctrl.update_agent_runtime(agentRuntimeId=existing_runtime_id, **base_kwargs)
                runtime_id = existing_runtime_id
                runtime_arn = resp.get("agentRuntimeArn") or \
                              f"arn:aws:bedrock-agentcore:{region}::runtime/{runtime_id}"
            else:
                logger.info(f"Creating AgentCore Runtime {safe_runtime_name}")
                resp = ctrl.create_agent_runtime(agentRuntimeName=safe_runtime_name, **base_kwargs)
                runtime_id = resp.get("agentRuntimeId")
                runtime_arn = resp.get("agentRuntimeArn")
        except ClientError as e:
            raise ProvisioningFailed("RuntimeProvisionFailed", str(e))

        # Scratch condition triples (registryIdResolved*, perimeterReachable*,
        # executionRoleCapability*) ride the ordinary backend_status merge and are
        # popped into status.conditions by _translate_provision_scratch_conditions
        # in the module-level handler — the same mechanism T7 uses for
        # GuardrailVerified in model_operator.py. They are NOT declared status
        # properties and must not persist as bare fields (Coherence Rule 20).
        return {
            "agentRuntimeId": runtime_id,
            "agentRuntimeArn": runtime_arn,
            "hostingProvider": "awsAgentCore",
            "managed": True,
            # The platform role this runtime actually assumes. Published so an
            # operator can answer "what can this agent do?" from `kubectl get`
            # instead of from an assumption about which role the CR asked for.
            "executionRoleArn": role_arn,
            "riskFindings": insp["findings"],
            "executionRoleCapabilityStatus": insp["cap_status"],
            "executionRoleCapabilityReason": insp["cap_reason"],
            "executionRoleCapabilityMessage": insp["cap_message"],
            **registry_scratch,
            **perimeter_scratch,
        }


    # ── a design note kubernetesPod hosting provider (grafted from gitlab/main 2026-05-31) ──
    # Self-contained: provisions an in-cluster Deployment+Service for a
    # provider=kubernetesPod agent. The open, vendor-neutral hosting peer to
    # awsAgentCore — no AWS dependency. Methods only call each other + the
    # kubernetes apps/v1 + core/v1 APIs.


    def _kubernetes_pod_resource_name(self, agent_name: str) -> str:
        """Naming convention for the Deployment + Service backing a kubernetesPod-
        hosted agent. ``agent-<agentName>`` keeps assets discoverable via a
        consistent prefix and avoids collision with operator-internal workloads.
        """
        return f"agent-{agent_name}"

    def _build_kubernetes_pod_env(self, spec: dict, agent_name: str) -> list[dict]:
        """Compose the env block for a kubernetesPod-hosted agent.

        Order (later overrides earlier on key collision):
          1. Legacy back-compat (REGION, REGISTRY_ID, MODEL_ALIAS, TOOL_ALIAS,
             AGENTCORE_GATEWAY_MCP_URL when set).
          2. INVARIANT SDK redirect vars from each upstream ModelConfig provider.
             Mesh-scope gateway URL by default (a pod inside the cluster
             resolves cluster.local natively, unlike AgentCore Runtime in PUBLIC
             mode which requires the public ELB DNS bridge).
          3. User-supplied spec.kubernetesPod.env (additive; user keys win).

        Returns a list of K8s EnvVar dicts ready for a container spec.
        """
        kp_cfg = spec.get("kubernetesPod", {}) or {}
        deps = spec.get("dependsOn", {}) or {}
        region = resolve_region((spec.get("awsAgentCore") or {}).get("region"))
        env_map: dict[str, dict] = {}

        # 1. Legacy back-compat env (kept identical to awsAgentCore path so
        # agent-genie / strands-style containers work unchanged across providers).
        env_map["REGION"] = {"name": "REGION", "value": region}
        env_map["REGISTRY_ID"] = {
            "name": "REGISTRY_ID",
            "value": os.environ.get("REGISTRY_ID", "REDACTED-REGISTRY-ID"),
        }
        model_alias = (deps.get("models") or [None])[0]
        tool_alias = (deps.get("tools") or [None])[0]
        if model_alias:
            env_map["MODEL_ALIAS"] = {"name": "MODEL_ALIAS", "value": model_alias}
        if tool_alias:
            env_map["TOOL_ALIAS"] = {"name": "TOOL_ALIAS", "value": tool_alias}

        # 2. INVARIANT SDK redirect vars. Mesh-scope by default; allow override
        # via MODAAS_GATEWAY_URL exactly as the awsAgentCore path does, so
        # operators can target a public gateway in non-mesh deployments.
        try:
            from shared.sdk_redirect import env_vars_for_dependencies
        except ImportError:
            from operators.shared.sdk_redirect import env_vars_for_dependencies
        # R3 fix (ai-gateway retirement, 2026-09-01): this fallback pointed at
        # the RETIRED ai-gateway host, and the a design note tests pre-set
        # MODAAS_GATEWAY_URL so the fallback path was never exercised — which
        # is exactly why it shipped. Default now resolves through the shared
        # endpoint computation (agentgateway host + llm listener port), same
        # source of truth the perimeter writer uses.
        explicit_override = os.environ.get("MODAAS_GATEWAY_URL") or os.environ.get(
            "MODAAS_MESH_GATEWAY_URL"
        )
        if explicit_override:
            gateway_url = explicit_override
        else:
            try:
                from shared.dependent_api import _GATEWAY_BASE_DEFAULT, _with_port
            except ImportError:
                from operators.shared.dependent_api import _GATEWAY_BASE_DEFAULT, _with_port
            gateway_url = _with_port(_GATEWAY_BASE_DEFAULT, "openai-compat")
        # Resolve each dep's provider so we know which SDK env vars to emit.
        # Failures (404 dep / RBAC denied) are tolerated here — INVARIANT logic
        # in the awsAgentCore path is more elaborate because AgentCore Runtime
        # creation cannot retry independently. For kubernetesPod the operator
        # owns the Deployment lifecycle and re-reconciles cheaply on dep
        # changes, so we do best-effort resolution and rely on the
        # DependencyHealthy condition for visibility.
        resolved_deps: list[dict] = []
        try:
            k8s = self._k8s_client()
            for alias in deps.get("models") or []:
                try:
                    cr = k8s.get("oda.tmforum.org", "v1beta1", "modelconfigs", alias)
                    provider_name = (cr or {}).get("spec", {}).get("provider")
                    if provider_name:
                        resolved_deps.append({"alias": alias, "provider": provider_name})
                except Exception as _e:
                    logger.info(
                        "INVARIANT kubernetesPod env: skipping dep '%s' (resolve failed: %s)",
                        alias, type(_e).__name__,
                    )
        except Exception as _k8s_err:
            logger.warning(
                "INVARIANT kubernetesPod env: K8s client init failed (%s); skipping INVARIANT injection",
                _k8s_err,
            )

        sdk_env = env_vars_for_dependencies(resolved_deps, gateway_url)
        for k, v in sdk_env.items():
            env_map[k] = {"name": k, "value": v}

        # 2b. U12 (tool-server-fixture): env_vars_for_tool_provider gets its
        # first production caller here — same fail-soft-per-alias tolerance
        # as the models loop above (a 404'd tool dep skips injection for
        # that alias; DependencyHealthy is the visibility surface, not a
        # blocked reconcile). Both ToolConfig providers (agentCoreGateway,
        # custom) now publish the identical /mcp/{alias} perimeter shape
        # (tool_operator.py's own U12 fix), so this loop does not need to
        # branch on the resolved provider the way the models loop does —
        # it still reads it, matching the models loop's own convention, in
        # case a future ToolConfig provider needs different treatment.
        try:
            from shared.sdk_redirect import env_vars_for_tool_provider
        except ImportError:
            from operators.shared.sdk_redirect import env_vars_for_tool_provider
        try:
            k8s = self._k8s_client()
            for alias in deps.get("tools") or []:
                try:
                    cr = k8s.get("oda.tmforum.org", "v1beta1", "toolconfigs", alias)
                    provider_name = (cr or {}).get("spec", {}).get("provider")
                    if not provider_name:
                        continue
                    tool_env = env_vars_for_tool_provider(
                        provider_name, gateway_url=gateway_url, asset_alias=alias,
                    )
                    for k, v in tool_env.items():
                        env_map[k] = {"name": k, "value": v}
                except Exception as _e:
                    logger.info(
                        "INVARIANT kubernetesPod env: skipping tool dep '%s' (resolve failed: %s)",
                        alias, type(_e).__name__,
                    )
        except Exception as _k8s_err:
            logger.warning(
                "INVARIANT kubernetesPod env: K8s client init failed (%s); skipping tool injection",
                _k8s_err,
            )

        # 2c. a hardening note: the credential that makes 2b's URL usable. Injected as a
        # secretKeyRef (never a literal) from a Secret in the agent's own
        # namespace -- see sdk_redirect.credential_env_from_secret for why the
        # perimeter's own agw-apikeys Secret cannot be referenced directly.
        # Emitted BEFORE step 3 so a user-supplied env entry of the same name
        # still wins, exactly like the URL vars above.
        try:
            from shared.sdk_redirect import credential_env_from_secret
        except ImportError:
            from operators.shared.sdk_redirect import credential_env_from_secret
        cred_entries = credential_env_from_secret(
            os.environ.get("MODAAS_GATEWAY_CREDENTIAL_SECRET", ""),
            os.environ.get("MODAAS_GATEWAY_CREDENTIAL_SECRET_KEY", ""),
        )
        for entry in cred_entries:
            env_map[entry["name"]] = entry
        if not cred_entries:
            logger.info(
                "a hardening note: no gateway credential configured "
                "(MODAAS_GATEWAY_CREDENTIAL_SECRET unset) -- agent '%s' will "
                "reach the perimeter unauthenticated and be refused 403",
                agent_name,
            )

        # 3. User-supplied env wins over operator-injected defaults.
        for entry in kp_cfg.get("env", []) or []:
            if not isinstance(entry, dict) or not entry.get("name"):
                continue
            env_map[entry["name"]] = dict(entry)

        return list(env_map.values())

    def _build_deployment_body(
        self, spec: dict, namespace: str, agent_name: str,
        owner_references: list[dict],
    ) -> dict:
        """Construct the K8s Deployment body for a kubernetesPod-hosted agent."""
        kp_cfg = spec.get("kubernetesPod", {}) or {}
        resource_name = self._kubernetes_pod_resource_name(agent_name)
        port = int(kp_cfg.get("port", 8080))
        replicas = int(kp_cfg.get("replicas", 1))
        sa_name = kp_cfg.get("serviceAccountName") or "modaas-agent-default"
        image = kp_cfg["containerImage"]
        resources = kp_cfg.get("resources") or {}
        # Apply schema-style defaults defensively in case the apiserver
        # didn't (e.g. unit tests instantiating spec dicts directly).
        requests = resources.get("requests") or {}
        limits = resources.get("limits") or {}
        resource_req = {
            "requests": {
                "cpu": requests.get("cpu", "100m"),
                "memory": requests.get("memory", "128Mi"),
            },
            "limits": {
                "cpu": limits.get("cpu", "500m"),
                "memory": limits.get("memory", "512Mi"),
            },
        }
        image_pull_secrets = [
            {"name": s["name"]}
            for s in (kp_cfg.get("imagePullSecrets") or [])
            if isinstance(s, dict) and s.get("name")
        ]
        env_block = self._build_kubernetes_pod_env(spec, agent_name)
        labels = {
            "app.kubernetes.io/name": resource_name,
            "app.kubernetes.io/managed-by": "aws-agent-operator",
            "app.kubernetes.io/part-of": "modaas-canvas",
            "oda.tmforum.org/asset-kind": "AgentConfig",
            "oda.tmforum.org/asset-name": agent_name,
            "modaas.tmforum.org/hosting-provider": "kubernetesPod",
        }
        body = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": resource_name,
                "namespace": namespace,
                "labels": labels,
                "ownerReferences": owner_references,
            },
            "spec": {
                "replicas": replicas,
                "selector": {"matchLabels": {"app.kubernetes.io/name": resource_name}},
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "serviceAccountName": sa_name,
                        "containers": [
                            {
                                "name": "agent",
                                "image": image,
                                "imagePullPolicy": "IfNotPresent",
                                "ports": [{"containerPort": port, "name": "http"}],
                                "env": env_block,
                                "resources": resource_req,
                            }
                        ],
                    },
                },
            },
        }
        if image_pull_secrets:
            body["spec"]["template"]["spec"]["imagePullSecrets"] = image_pull_secrets
        return body

    def _build_service_body(
        self, spec: dict, namespace: str, agent_name: str,
        owner_references: list[dict],
    ) -> dict:
        """Construct the K8s Service body fronting a kubernetesPod-hosted agent."""
        kp_cfg = spec.get("kubernetesPod", {}) or {}
        resource_name = self._kubernetes_pod_resource_name(agent_name)
        port = int(kp_cfg.get("port", 8080))
        labels = {
            "app.kubernetes.io/name": resource_name,
            "app.kubernetes.io/managed-by": "aws-agent-operator",
            "app.kubernetes.io/part-of": "modaas-canvas",
            "oda.tmforum.org/asset-kind": "AgentConfig",
            "oda.tmforum.org/asset-name": agent_name,
        }
        return {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": resource_name,
                "namespace": namespace,
                "labels": labels,
                "ownerReferences": owner_references,
            },
            "spec": {
                "type": "ClusterIP",
                "selector": {"app.kubernetes.io/name": resource_name},
                "ports": [
                    {
                        "name": "http",
                        "port": port,
                        "targetPort": port,
                        "protocol": "TCP",
                    }
                ],
            },
        }

    def _apps_v1_api(self):
        """Lazy-init kubernetes.client.AppsV1Api with same fallback as _K8sClient."""
        from kubernetes import client, config
        try:
            config.load_incluster_config()
        except config.ConfigException:
            try:
                config.load_kube_config()
            except Exception:
                pass
        return client.AppsV1Api()

    def _core_v1_api(self):
        from kubernetes import client, config
        try:
            config.load_incluster_config()
        except config.ConfigException:
            try:
                config.load_kube_config()
            except Exception:
                pass
        return client.CoreV1Api()

    def _provision_kubernetes_pod(self, spec: dict, status: dict) -> dict:
        """INVARIANT — provision a Deployment + Service for a kubernetesPod-hosted agent.

        Idempotent: re-reconcile patches an existing Deployment when image,
        env, replicas, or resources change. The Service is largely immutable
        beyond port (which seldom changes); we patch when port differs.

        Returns status fields:
          - hostingProvider: "kubernetesPod"
          - managed: True (the operator always owns the Deployment+Service)
          - kubernetesPod: { deploymentName, serviceName, ready }
        """
        agent_name = spec.get("agentName", "unknown")
        kp_cfg = spec.get("kubernetesPod") or {}
        if not kp_cfg.get("containerImage"):
            raise ProvisioningFailed(
                "ConfigIncomplete",
                "INVARIANT: kubernetesPod provider requires spec.kubernetesPod.containerImage.",
            )
        namespace = COMPONENTS_NS
        resource_name = self._kubernetes_pod_resource_name(agent_name)

        # Owner references: Component (controller=true) + AgentConfig (controller=false).
        # Component ref lives on status.componentRef (populated by reconcile() W2.A
        # before provision_backend is called). AgentConfig ref is added by caller's
        # ensure_owner-ref helper if needed; we read meta.uid from spec where we
        # stash it before invocation.
        comp_ref = (status.get("componentRef") if isinstance(status, dict) else None) or {}
        owner_refs: list[dict] = []
        if comp_ref.get("uid"):
            owner_refs.append({
                "apiVersion": "oda.tmforum.org/v1",
                "kind": "Component",
                "name": comp_ref.get("name", agent_name),
                "uid": comp_ref["uid"],
                "controller": True,
                "blockOwnerDeletion": True,
            })
        # The reconciler stashes meta on spec under "_meta" (see reconcile wiring
        # below); fall back to no agentconfig ownerRef if absent.
        agentconfig_meta = spec.get("_meta") if isinstance(spec, dict) else None
        if agentconfig_meta and agentconfig_meta.get("uid"):
            owner_refs.append({
                "apiVersion": "oda.tmforum.org/v1beta1",
                "kind": "AgentConfig",
                "name": agentconfig_meta.get("name", agent_name),
                "uid": agentconfig_meta["uid"],
                "controller": False,
                "blockOwnerDeletion": True,
            })

        deploy_body = self._build_deployment_body(
            spec, namespace, agent_name, owner_refs,
        )
        service_body = self._build_service_body(
            spec, namespace, agent_name, owner_refs,
        )

        from kubernetes.client.exceptions import ApiException
        apps_api = self._apps_v1_api()
        core_api = self._core_v1_api()

        # ── Deployment: create or patch ──
        try:
            apps_api.read_namespaced_deployment(name=resource_name, namespace=namespace)
            try:
                apps_api.patch_namespaced_deployment(
                    name=resource_name, namespace=namespace, body=deploy_body,
                )
                logger.info("INVARIANT patched Deployment %s/%s", namespace, resource_name)
            except ApiException as e:
                raise ProvisioningFailed(
                    "DeploymentPatchFailed",
                    f"patch_namespaced_deployment({resource_name}) failed: {e.status} {e.reason}",
                )
        except ApiException as e:
            if e.status != 404:
                raise ProvisioningFailed(
                    "DeploymentReadFailed",
                    f"read_namespaced_deployment({resource_name}) failed: {e.status} {e.reason}",
                )
            try:
                apps_api.create_namespaced_deployment(namespace=namespace, body=deploy_body)
                logger.info("INVARIANT created Deployment %s/%s", namespace, resource_name)
            except ApiException as ce:
                raise ProvisioningFailed(
                    "DeploymentCreateFailed",
                    f"create_namespaced_deployment({resource_name}) failed: {ce.status} {ce.reason}",
                )

        # ── Service: create or patch (port-only updates) ──
        try:
            core_api.read_namespaced_service(name=resource_name, namespace=namespace)
            try:
                core_api.patch_namespaced_service(
                    name=resource_name, namespace=namespace, body=service_body,
                )
                logger.info("INVARIANT patched Service %s/%s", namespace, resource_name)
            except ApiException as e:
                # Service spec mutations are restricted; a 422 on selector/clusterIP
                # is a non-recoverable config issue worth surfacing.
                raise ProvisioningFailed(
                    "ServicePatchFailed",
                    f"patch_namespaced_service({resource_name}) failed: {e.status} {e.reason}",
                )
        except ApiException as e:
            if e.status != 404:
                raise ProvisioningFailed(
                    "ServiceReadFailed",
                    f"read_namespaced_service({resource_name}) failed: {e.status} {e.reason}",
                )
            try:
                core_api.create_namespaced_service(namespace=namespace, body=service_body)
                logger.info("INVARIANT created Service %s/%s", namespace, resource_name)
            except ApiException as ce:
                raise ProvisioningFailed(
                    "ServiceCreateFailed",
                    f"create_namespaced_service({resource_name}) failed: {ce.status} {ce.reason}",
                )

        # ── Readiness check (best-effort; first reconcile typically returns False) ──
        ready = False
        try:
            current = apps_api.read_namespaced_deployment_status(
                name=resource_name, namespace=namespace,
            )
            dep_status = getattr(current, "status", None)
            ready_replicas = getattr(dep_status, "ready_replicas", None) if dep_status else None
            spec_block = getattr(current, "spec", None)
            desired_replicas = getattr(spec_block, "replicas", None) if spec_block else None
            if ready_replicas is not None and desired_replicas is not None:
                ready = ready_replicas == desired_replicas and desired_replicas > 0
        except ApiException:
            ready = False

        return {
            "hostingProvider": "kubernetesPod",
            "managed": True,
            "kubernetesPod": {
                "deploymentName": resource_name,
                "serviceName": resource_name,
                "ready": ready,
            },
        }

    def _deprovision_kubernetes_pod(self, status: dict) -> None:
        """INVARIANT explicit teardown for kubernetesPod-hosted agents."""
        kp_status = status.get("kubernetesPod") or {}
        deploy_name = kp_status.get("deploymentName")
        service_name = kp_status.get("serviceName")
        namespace = COMPONENTS_NS
        if not deploy_name and not service_name:
            return

        from kubernetes.client.exceptions import ApiException
        if deploy_name:
            try:
                self._apps_v1_api().delete_namespaced_deployment(
                    name=deploy_name, namespace=namespace,
                )
                logger.info("INVARIANT deleted Deployment %s/%s", namespace, deploy_name)
            except ApiException as e:
                if e.status != 404:
                    logger.warning(
                        "INVARIANT delete Deployment %s/%s failed: %s %s",
                        namespace, deploy_name, e.status, e.reason,
                    )
        if service_name:
            try:
                self._core_v1_api().delete_namespaced_service(
                    name=service_name, namespace=namespace,
                )
                logger.info("INVARIANT deleted Service %s/%s", namespace, service_name)
            except ApiException as e:
                if e.status != 404:
                    logger.warning(
                        "INVARIANT delete Service %s/%s failed: %s %s",
                        namespace, service_name, e.status, e.reason,
                    )


# ─────────────────────────────────────────────────────────────────────────────
# kopf handler wiring — thin delegation to AgentOperator
# ─────────────────────────────────────────────────────────────────────────────

    def deprovision_backend(self, status: dict) -> None:
        """Clean up the agent's hosting backend.

        Dispatches on status.hostingProvider (a design note):
          - kubernetesPod: delete the in-cluster Deployment + Service
          - awsAgentCore (managed): delete the AgentCore Runtime

        Imported AgentCore runtimes (status.managed=False) are NOT deleted —
        they were pre-existing and their lifecycle is out of our scope.
        """
        if not status:
            return

        # a design note provider dispatch — kubernetesPod teardown is explicit
        # Deployment+Service deletion, owned by the asset's Component.
        if status.get("hostingProvider") == "kubernetesPod":
            self._deprovision_kubernetes_pod(status)
            return

        runtime_id = status.get("agentRuntimeId")
        if not runtime_id:
            return

        if not status.get("managed"):
            logger.info(f"AgentCore Runtime {runtime_id} was imported, not deleting")
            return

        import boto3
        from botocore.exceptions import ClientError
        region = resolve_region(_region_from_arn(status.get("agentRuntimeArn")))
        ctrl = _agentcore_ctrl(region)
        # A runtime in CREATING/UPDATING refuses DeleteAgentRuntime with a
        # ConflictException. Returning on that warning used to release the
        # finalizer and leak the runtime (billing, and holding its name so a
        # re-apply could not create it). Wait, bounded, then delete; raise if it
        # never settles so kopf keeps the finalizer and retries.
        for attempt in range(RUNTIME_SETTLE_MAX_POLLS + 1):
            last = attempt == RUNTIME_SETTLE_MAX_POLLS
            try:
                state = ctrl.get_agent_runtime(agentRuntimeId=runtime_id).get("status")
            except ClientError as e:
                if _error_code(e) == "ResourceNotFoundException":
                    logger.info(f"AgentCore Runtime {runtime_id} already gone")
                    return
                state = None  # cannot tell; let the delete answer
            if state in _RUNTIME_BUSY_STATES and not last:
                time.sleep(RUNTIME_SETTLE_POLL_S)
                continue
            if state in _RUNTIME_BUSY_STATES:
                break
            try:
                ctrl.delete_agent_runtime(agentRuntimeId=runtime_id)
                logger.info(f"Deleted AgentCore Runtime {runtime_id}")
                return
            except ClientError as e:
                code = _error_code(e)
                if code == "ResourceNotFoundException":
                    return
                if code == "ConflictException" and not last:
                    time.sleep(RUNTIME_SETTLE_POLL_S)
                    continue
                logger.warning(f"delete_agent_runtime({runtime_id}) failed: {e}")
                return
        raise RuntimeStillBusy(
            f"AgentCore Runtime {runtime_id} is still CREATING/UPDATING after "
            f"{RUNTIME_SETTLE_MAX_POLLS} checks {RUNTIME_SETTLE_POLL_S:g}s apart; "
            f"not deleted yet, so the delete will be retried")


# ─────────────────────────────────────────────────────────────────────────────
# kopf handler wiring — thin delegation to AgentOperator
# ─────────────────────────────────────────────────────────────────────────────
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

GROUP = "oda.tmforum.org"
VERSION = "v1beta1"
PLURAL = "agentconfigs"

_agent_operator = AgentOperator()


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


# ── provision-time scratch keys → status conditions ──
#
# `provision_backend`'s return dict is merged wholesale into `patch.status` by
# asset_operator.reconcile, and provisioning has no `patch` in scope. The
# established way to surface a provision-time verdict as a condition is
# therefore: stamp scratch keys in provision, pop them here, set the condition.
# model_operator.py's T7 GuardrailVerified translation is the precedent, and its
# reasoning applies unchanged -- status.conditions[] is already a declared,
# open-ended array, so a new condition TYPE needs no CRD change, whereas a new
# status.properties key would (Coherence Rule 20). The pop is what keeps the
# scratch keys from reaching the apiserver as undeclared fields.
#
# (prefix, condition type, declared boolean mirror or None)
_PROVISION_SCRATCH_CONDITIONS = (
    ("registryIdResolved", "RegistryIdResolved", None),
    ("perimeterReachable", "PerimeterReachable", "perimeterReachable"),
    ("executionRoleCapability", "ExecutionRoleCapability", None),
)


def _translate_provision_scratch_conditions(patch) -> None:
    """Turn provision-time scratch keys into conditions, and remove the scratch."""
    for prefix, cond_type, scalar_field in _PROVISION_SCRATCH_CONDITIONS:
        cond_status = patch.status.pop(f"{prefix}Status", None)
        reason = patch.status.pop(f"{prefix}Reason", "Unknown")
        message = patch.status.pop(f"{prefix}Message", "")
        if cond_status is None:
            continue
        _set_condition(patch, cond_type, cond_status, reason, message)
        if scalar_field:
            if cond_status in ("True", "False"):
                patch.status[scalar_field] = cond_status == "True"
            else:
                # A boolean cannot express Unknown; leave the scalar absent and
                # let the condition carry it, rather than publish a false claim.
                patch.status.pop(scalar_field, None)


def _set_dependency_healthy(patch, healthy: bool, reason: str = "", message: str = "") -> None:
    """Bug #10 (a design note) — mirror DependencyHealthy condition into a top-level
    scalar field so consumers don't need to walk the conditions array.

    Writes BOTH:
      - ``status.dependencyStatus.healthy`` — the schema-declared object field
        (CRD declares ``dependencyStatus`` as ``object`` with
        ``x-kubernetes-preserve-unknown-fields: true``, so arbitrary keys are
        retained by the apiserver). This is the durable, schema-correct path.
      - ``status.dependencyHealthy`` — the top-level convenience scalar named
        in a design note / external evidence. NOT currently in the CRD schema; the
        apiserver will silently drop it until a schema patch lands. Writing
        it here makes the operator forward-compatible: once schema declares
        it, the field will surface without further code change.

    Witness 2026-05-27: 7 Approved AgentConfigs had ``dependencyHealthy`` empty
    while ``conditions[type=DependencyHealthy].status`` was True — the timer
    populated only the condition, not any scalar mirror.

    Args:
        patch: kopf patch object whose ``.status`` dict accumulates writes.
        healthy: True/False — must mirror the condition's status string.
        reason: short reason code (matches condition ``.reason``).
        message: human-readable message (matches condition ``.message``).
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    # Schema-declared object — arbitrary keys preserved.
    dep_status = dict(patch.status.get("dependencyStatus") or {})
    dep_status["healthy"] = bool(healthy)
    if reason:
        dep_status["reason"] = reason
    if message:
        dep_status["message"] = message
    dep_status["lastObserved"] = now
    patch.status["dependencyStatus"] = dep_status
    # Top-level convenience scalar — apiserver drops if not in schema.
    patch.status["dependencyHealthy"] = bool(healthy)


@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    settings.watching.server_timeout = 60
    logger.info(f"Agent Operator started — watching {PLURAL}.{GROUP}/{VERSION} (awsAgentCore only)")


@kopf.on.resume(GROUP, VERSION, PLURAL, retries=5)
@kopf.on.create(GROUP, VERSION, PLURAL, retries=5)
@kopf.on.update(GROUP, VERSION, PLURAL, retries=5)
@traced("operator.agent.reconcile", attrs={"operator.kind": "AgentConfig"})
def reconcile(spec, status, meta, name, namespace, patch, body=None, **_):
    """Delegate to shared AssetOperator.reconcile() with canvas integration."""
    # Seed the live conditions before this handler sets any. A status patch
    # REPLACES the whole list, and the blocks below write a dozen conditions
    # before the inner reconcile's own seed runs -- which then does nothing,
    # because the patch already holds a list. Unseeded, every event on an
    # unchanged CR erased Provisioned (with the reason a create failed),
    # RegistryRegistered and ApprovalRequired.
    # Sensor: operators/shared/tests/test_handlers_keep_conditions.py
    _agent_operator._seed_conditions(patch, status)
    # a design note fix: stash the AgentConfig's own name+uid onto spec so
    # _provision_kubernetes_pod can add a second ownerReference (AgentConfig →
    # Deployment/Service) alongside the Component ownerRef. Previously the read
    # at spec["_meta"] was dead code (never set), so kubernetesPod-hosted agents
    # only got the Component-path cascade, not the direct AgentConfig ownerRef.
    if isinstance(spec, dict) and meta:
        spec["_meta"] = {"name": name, "uid": meta.get("uid")}
    # ── a design note / a design note — Canvas integration (Bucket 2) ──
    # W1.A: Each canvas-integration action surfaces failures as conditions.
    # W2.A: Replaces annotation-opt-in with operator-driven Component emission.
    _custom = None
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
        _custom = None  # skip W2.A through W4.D blocks

    # a design note (W2.A): Operator-emitted Component CR
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
                    source_kind="AgentConfig",
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
                source_kind="AgentConfig",
                source_name=name,
                owner_reference=identity_owner,
            )
            _set_condition(
                patch, "IdentityProvisioned", "True", "IdentityConfigCreated",
                f"IdentityConfig modaas-agentconfig-{name} provisioned via Canvas",
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
            # The consequential case: AgentConfig.spec.provider has no mark_unclaimed
            # guard anywhere in this operator, so an off-catalog provider string
            # reaches this call today, not just hypothetically.
            try:
                wire_formats = dialects_for(provider)
            except UnmappedProviderError as e:
                patch.status["phase"] = "Failed"
                _agent_operator._emit_phase_change(meta, status, status.get("phase", "Unknown"), "Failed")
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
                # to BOTH endpoint and globalResourceEndpoint per a design note. Helper
                # keeps shape consistent across model/tool/agent operators.
                try:
                    from shared.perimeter_url import compute_and_publish_perimeter_url
                except ModuleNotFoundError:
                    from operators.shared.perimeter_url import compute_and_publish_perimeter_url  # type: ignore
                alias = spec.get("alias", name)
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
                kind="AgentConfig",
            )
            _set_condition(patch, "IstioPerAssetProvisioned", "True", "IstioReady",
                           f"VirtualService + AuthorizationPolicy emitted for {name}")
        except Exception as _istio_err:
            _reason = _classify_k8s_error(_istio_err)
            _set_condition(patch, "IstioPerAssetProvisioned", "False", _reason,
                           f"Istio VS/AuthZ emission failed: {str(_istio_err)[:256]}")
            logger.warning("W4.C Istio VS/AuthZ failed for %s: %s", name, _istio_err)

    # W4.D: Egress allowlist for the agent's provider
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
            _egress_region = resolve_region((spec.get("awsAgentCore") or {}).get("region"))
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

    # Bug #10 (a design note): populate DependencyHealthy on every reconcile.
    # The kopf.timer-only path missed the Approved-already case (timer registered
    # late or skipped on adopt-mode CRs — see Bug #11/#12 timer-on-adopt fix).
    # Witness 2026-05-27: 7 Approved AgentConfigs with no DependencyHealthy
    # condition because the populator only fired on transitions.
    try:
        # a design note: dependency health is provider-agnostic (dependsOn semantics are
        # identical for awsAgentCore + kubernetesPod). Both hosting providers get
        # the DependencyHealthy condition — the open provider is not second-class.
        if spec.get("provider") in ("awsAgentCore", "kubernetesPod") and not spec.get("paused"):
            k8s_dh = _agent_operator._k8s_client()
            healthy, reason = _agent_operator.check_dependency_health(spec, k8s_dh)
            cond_reason = reason.split(":")[0] if reason else "Unknown"
            cond_msg = reason or ""
            _set_condition(
                patch,
                "DependencyHealthy",
                "True" if healthy else "False",
                cond_reason,
                cond_msg,
            )
            # Bug #10: mirror the condition into a top-level scalar so
            # `kubectl get agentconfig -o jsonpath='{.status.dependencyHealthy}'`
            # surfaces a non-empty value without walking conditions.
            _set_dependency_healthy(patch, healthy, cond_reason, cond_msg)
    except Exception as _dh_err:
        logger.warning(
            "DependencyHealthy populate failed inline for %s: %s", name, _dh_err
        )

    _result = _agent_operator.reconcile(spec, status, meta, patch)

    # Provision-time verdicts (registry-id resolution, perimeter reachability,
    # execution-role capability) become conditions here — see
    # _translate_provision_scratch_conditions. Must run AFTER reconcile, which is
    # what merges provision_backend's return dict into patch.status.
    _translate_provision_scratch_conditions(patch)

    return _result


@kopf.on.delete(GROUP, VERSION, PLURAL, retries=5)
def cleanup(spec, status, meta, name, namespace, **_):
    """Delegate to shared AssetOperator.cleanup()."""
    return _agent_operator.cleanup(spec, status)


# ── K8s-idiomatic resync timers (a design note) ────────────────────────────────── #

@kopf.timer(GROUP, VERSION, PLURAL, interval=300, idle=30, retries=3)
async def resync_from_registry(spec, status, patch, name, **_):
    """Every 5 minutes, read Registry + update status fields."""
    # a design note: registry projection is provider-agnostic — resync both providers.
    if spec.get("provider") not in ("awsAgentCore", "kubernetesPod"):
        return
    # Seeded here, after the ownership guard and before any write (see reconcile).
    _agent_operator._seed_conditions(patch, status)
    try:
        status_dict = dict(status) if status else {}
        result = _agent_operator.resync_from_registry(spec, status_dict, patch)
        logger.info(f"resync {name}: {result}")
        return result
    except Exception as e:
        logger.error(f"resync_from_registry failed for {name}: {type(e).__name__}: {e}",
                     exc_info=True)
        return {"error": str(e)}


@kopf.timer(GROUP, VERSION, PLURAL, interval=120, idle=15, retries=3)
async def check_dependency_health(spec, status, patch, name, **_):
    """a design note cross-asset observability — every 2 minutes, walk dependsOn and
    reflect dep health in status.conditions[type=DependencyHealthy].

    Does NOT pause this AgentConfig. Only surfaces upstream state so that
    `kubectl get agentconfig` shows blast radius when a model/tool is
    paused/retired/deleted. Manual recovery per a design note policy.

    Keeps every other condition. The Bug #10 fix switched this to
    `_set_condition` and said that merged into the existing list; it merged
    into the PATCH, which starts empty, so each run sent a one-element list and
    the apiserver replaced status.conditions with it. Measured 2026-09-28: three
    Failed AgentConfigs showed only DependencyHealthy, and the Provisioned=False
    message naming the create failure was gone. Seeding first is the fix.
    """
    # a design note: cross-asset dependency observability is provider-agnostic.
    if spec.get("provider") not in ("awsAgentCore", "kubernetesPod"):
        return
    # Skip if CR itself is paused (no upstream check needed)
    if spec.get("paused"):
        return
    _agent_operator._seed_conditions(patch, status)
    try:
        k8s = _agent_operator._k8s_client()
        healthy, reason = _agent_operator.check_dependency_health(spec, k8s)
        cond_reason = reason.split(":")[0] if reason else "Unknown"
        cond_msg = reason or ""
        _set_condition(
            patch,
            "DependencyHealthy",
            "True" if healthy else "False",
            cond_reason,
            cond_msg,
        )
        # Bug #10: mirror the condition into the top-level scalar.
        _set_dependency_healthy(patch, healthy, cond_reason, cond_msg)
        if not healthy:
            logger.info(f"dep-health {name}: UNHEALTHY — {reason}")
        return {"healthy": healthy, "reason": reason}
    except Exception as e:
        logger.error(f"check_dependency_health failed for {name}: {type(e).__name__}: {e}",
                     exc_info=True)
        return {"error": str(e)}


@kopf.timer(GROUP, VERSION, PLURAL, interval=3600, initial_delay=60, idle=60, retries=3)
async def scan_orphan_records(patch, **_):
    """Every 1 hour, scan for Registry records with no matching AgentConfig CR."""
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
        cr_names = [it.get("spec", {}).get("agentName")
                    for it in cr_list.get("items", [])
                    if it.get("spec", {}).get("agentName")]
        orphans = _agent_operator.scan_orphans(cr_names, provider_prefix="awsagentcore")
        if orphans:
            logger.warning(f"Found {len(orphans)} orphan Registry records: {orphans}")
        else:
            logger.info(f"Orphan scan clean — {len(cr_names)} CRs, all Registry records accounted for")
        return {"orphans": orphans, "scanned_crs": len(cr_names)}
    except Exception as e:
        logger.error(f"scan_orphan_records failed: {type(e).__name__}: {e}", exc_info=True)
        return {"error": str(e)}
