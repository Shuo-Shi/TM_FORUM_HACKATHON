"""k8s-agent-operator — AgentConfig v1beta1, provider=kubernetesPod.

The sibling operator a design note/a design note always called for and a design note skipped: one
hosting provider per operator. a design note §"Operator scope" resolves the graft by
moving pod hosting here, leaving aws-agent-operator with AgentCore Runtime only.
The CRD is unchanged -- it keeps a design note's open `provider` pattern, and each
operator claims only its own provider.

What this operator owns for a governed pod agent:

  * a Deployment and a ClusticIP Service named ``agent-<agentName>``,
  * a NetworkPolicy ``agent-<agentName>-egress`` -- a design note's withholding leg,
  * the a design note withholding checks, which REFUSE rather than warn,
  * Canvas-first emission (Component, IdentityConfig, DependentAPI) and the
    perimeter URL published to status.endpoint (a design note).

What it deliberately does NOT own: anything AWS. There is no boto3 import and no
AWS call on this path. Istio VirtualService/AuthorizationPolicy and egress
ServiceEntry emission are not carried over from the graft's host either -- a
pod's network posture is the NetworkPolicy above, and a ServiceEntry is inert in
a cluster with no istio-proxy sidecars.

Design note: K8S-OPERATOR.md at the repo root.
"""
from __future__ import annotations

import logging
import os

import kopf
from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes.client import ApiClient
from kubernetes.client.exceptions import ApiException

import pod_backend as pb
import withholding
from operators.shared.agent_dependencies import check_dependency_health as _dep_health
from operators.shared.agent_dependencies import validate_dependencies as _validate_deps
from operators.shared.asset_operator import AssetOperator, ProvisioningFailed
from operators.shared.component_owner import SKIP_COMPONENT_ANNOTATION
from operators.shared.component_owner import ensure_component as _shared_ensure_component
from operators.shared.dependent_api import ensure_dependent_api_for_wire_format as \
    _shared_ensure_dependent_api
from operators.shared.dependent_api import get_resolved_url as _shared_get_resolved_url
from operators.shared.identity_config import ensure_identity_config as \
    _shared_ensure_identity_config
from operators.shared.k8s_errors import classify as _classify
from operators.shared.perimeter_url import compute_and_publish_perimeter_url as \
    _shared_publish_perimeter_url
from operators.shared.wire_format_registry import UnmappedProviderError, dialects_for

# a design note: registry health probe timer, shared across operators. Registry-CR
# lifecycle handlers are registered ONLY by the model operator (single-registrar
# rule) -- do not import registry_lifecycle_handlers here.
from operators.shared import registry_health  # noqa: F401

try:
    from operators.shared.operator_otel import traced
except ImportError:  # pragma: no cover - OTel is optional at runtime
    def traced(*_a, **_kw):
        def _d(fn):
            return fn
        return _d

logger = logging.getLogger("K8sAgentOperator")

GROUP = "oda.tmforum.org"
VERSION = "v1beta1"
PLURAL = "agentconfigs"

#: The one provider this operator handles. Everything else is another
#: controller's asset (or nobody's -- see _another_controller_claimed).
CLAIMED_PROVIDER = "kubernetesPod"

COMPONENTS_NS = os.environ.get("COMPONENT_NAMESPACE", "components")
GATEWAY_NS_ENV = "MODAAS_GATEWAY_NAMESPACE"
ISTIOD_NS_ENV = "MODAAS_ISTIOD_NAMESPACE"
REQUIRE_NP_ENFORCEMENT_ENV = "MODAAS_REQUIRE_NETWORKPOLICY_ENFORCEMENT"


# ── config + API clients ──────────────────────────────────────────────────

def _load_kube_config() -> None:
    """In-cluster first, kubeconfig second, neither is not fatal here.

    kopf can start before either source resolves; the first real API call then
    fails with its own message, which is more useful than a traceback from
    module import.
    """
    try:
        k8s_config.load_incluster_config()
        return
    except k8s_config.ConfigException:
        pass
    try:
        k8s_config.load_kube_config()
    except Exception as exc:  # noqa: BLE001 - see docstring
        logger.warning("no kube config available (%s); API calls will fail loudly",
                       type(exc).__name__)


def _custom_objects_api():
    _load_kube_config()
    return k8s_client.CustomObjectsApi()


class _CRReader:
    """Read-only reader for sibling CRs (ModelConfig / ToolConfig).

    This operator never writes another asset's CR; the dependency gate and the
    provider resolution only read.
    """

    def __init__(self):
        self._api = _custom_objects_api()

    def get(self, group: str, version: str, plural: str, name: str,
            namespace: str | None = None) -> dict:
        return self._api.get_namespaced_custom_object(
            group, version, namespace or COMPONENTS_NS, plural, name)


def _gateway_url() -> str:
    """The perimeter base URL agents are redirected to.

    The graft's fallback here pointed at the RETIRED ai-gateway host and was
    never exercised because its tests pre-set the override. The default now comes
    from the same shared endpoint computation the perimeter writer uses.
    """
    override = os.environ.get("MODAAS_GATEWAY_URL") or os.environ.get(
        "MODAAS_MESH_GATEWAY_URL")
    if override:
        return override
    from operators.shared.dependent_api import _GATEWAY_BASE_DEFAULT, _with_port
    return _with_port(_GATEWAY_BASE_DEFAULT, "openai-compat")


# ── spec + meta, without mutating the spec ────────────────────────────────

class SpecWithMeta(dict):
    """The CR spec plus the CR's own name+uid, for the AgentConfig ownerReference.

    The graft stashed this as ``spec["_meta"]`` from the kopf handler, mutating
    the dict kopf owns. AssetOperator.reconcile only forwards ``spec`` to
    ``provision_backend``, so the value has to travel WITH the spec; a dict
    subclass carrying one extra attribute does that without mutation and without
    per-instance operator state (which would race across concurrently
    reconciled resources).

    ``patch`` travels the same way and for the same reason: the perimeter verdict
    is decided inside provision_backend (it must be, so nothing is created before
    it), but it has to be published as a condition, and AssetOperator.reconcile
    forwards only the spec. Storing it on the operator instance instead would
    race across concurrently reconciled resources. It is optional -- a caller
    holding no patch still gets the refusal, only not the condition.
    """

    def __init__(self, spec: dict, cr_meta: dict, patch=None):
        super().__init__(spec)
        self.cr_meta = dict(cr_meta or {})
        self.patch = patch


# ── the operator ──────────────────────────────────────────────────────────

class K8sAgentOperator(AssetOperator):

    @property
    def record_type(self) -> str:
        return "agent"

    @property
    def resource_plural(self) -> str:
        return PLURAL

    def _k8s_client(self):
        return _CRReader()

    # ── shared dependency logic (single home: operators/shared) ──

    def _validate_dependencies(self, spec: dict, k8s, status: dict | None = None):
        return _validate_deps(spec, k8s, status)

    def check_dependency_health(self, spec: dict, k8s):
        return _dep_health(spec, k8s)

    def _build_registry_metadata(self, spec: dict, status: dict) -> dict:
        """Registry record for a pod agent.

        ``invocation.endpoint`` is status.endpoint -- the PERIMETER URL, never the
        in-cluster Service DNS. Per a design note / Coherence Rule 13, a record pointing
        at agent-<name>.components.svc would hand consumers a route that bypasses
        every control this operator installed.
        """
        md = super()._build_registry_metadata(spec, status)
        md["invocation"] = {
            "protocol": dialects_for(CLAIMED_PROVIDER)[0],
            "endpoint": (status or {}).get("endpoint", ""),
        }
        for field in ("agentCard", "dependsOn", "governance"):
            if spec.get(field):
                md[field] = spec[field]
        return md

    # ── typed API clients ──

    def _apps_v1(self):
        _load_kube_config()
        return k8s_client.AppsV1Api()

    def _core_v1(self):
        _load_kube_config()
        return k8s_client.CoreV1Api()

    def _networking_v1(self):
        _load_kube_config()
        return k8s_client.NetworkingV1Api()

    def _apiextensions_v1(self):
        _load_kube_config()
        return k8s_client.ApiextensionsV1Api()

    # ── reads ──

    def _read_service_account(self, namespace: str, name: str) -> dict | None:
        """The SA the agent pod will run as, or None when it cannot be read.

        None means "unverified". Returning {} would read downstream as "no
        annotations", i.e. a false pass on a design note leg 1.
        """
        try:
            return _as_dict(self._core_v1().read_namespaced_service_account(
                name=name, namespace=namespace))
        except Exception as exc:  # noqa: BLE001 - any failure is 'unverified'
            logger.info("could not read ServiceAccount %s/%s (%s)",
                        namespace, name, _classify(exc))
            return None

    def _read_pods_for_service_account(self, namespace: str,
                                       sa_name: str) -> list[dict] | None:
        """Pods running as ``sa_name``, or None when the list could not be read.

        Filtering is client-side. ``spec.serviceAccountName`` as a pod field
        selector is an apiserver-supported-selector claim this code does not need
        to make, and the namespace this operator watches holds tens of pods, not
        thousands.

        None means "could not look", which withholding reports as `unverified`;
        [] means "looked, found none".
        """
        try:
            listed = _as_dict(self._core_v1().list_namespaced_pod(namespace=namespace))
        except Exception as exc:  # noqa: BLE001 - any failure is 'unverified'
            logger.info("could not list pods in %s (%s); Pod Identity posture unknown",
                        namespace, _classify(exc))
            return None
        return [p for p in listed.get("items") or []
                if ((p.get("spec") or {}).get("serviceAccountName")) == sa_name]

    def _list_crd_names(self) -> list[str] | None:
        """CRD names in the cluster, or None when the list could not be read.

        None means "could not look"; [] would mean "looked, found no enforcer".
        """
        try:
            listed = _as_dict(self._apiextensions_v1().list_custom_resource_definition())
            return [(i.get("metadata") or {}).get("name", "")
                    for i in listed.get("items") or []]
        except Exception as exc:  # noqa: BLE001 - see docstring
            logger.info("could not list CRDs (%s); NetworkPolicy enforcement unknown",
                        _classify(exc))
            return None

    def _read_deployment_dict(self, namespace: str, name: str) -> dict | None:
        """The existing Deployment as a camelCase dict, or None on 404.

        Anything other than 404 is re-raised: treating a 403 as "does not exist"
        would make the operator create a duplicate object it cannot see.
        """
        try:
            return _as_dict(self._apps_v1().read_namespaced_deployment(
                name=name, namespace=namespace))
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise

    def _deployment_readiness(self, namespace: str, name: str):
        """(readyReplicas, spec.replicas), or (None, None) when unknown."""
        try:
            dep = self._apps_v1().read_namespaced_deployment_status(
                name=name, namespace=namespace)
        except Exception as exc:  # noqa: BLE001 - readiness is best-effort
            logger.info("could not read Deployment status %s/%s (%s)",
                        namespace, name, _classify(exc))
            return None, None
        body = _as_dict(dep)
        return ((body.get("status") or {}).get("readyReplicas"),
                (body.get("spec") or {}).get("replicas"))

    def _resolve_dependency_providers(self, deps: dict | None):
        """([{alias, provider}], [{alias, provider}]) for models and tools.

        Best-effort per alias: the dependency GATE already refused an unapproved
        dep, so a transient read failure here must not block the Deployment this
        operator owns. DependencyHealthy is the visibility surface (a design note).
        """
        deps = deps or {}
        aliases = {"modelconfigs": list(deps.get("models") or []),
                   "toolconfigs": list(deps.get("tools") or [])}
        if not any(aliases.values()):
            return [], []
        try:
            reader = self._k8s_client()
        except Exception as exc:  # noqa: BLE001
            logger.warning("dependency resolution skipped: K8s client init failed (%s)",
                           _classify(exc))
            return [], []
        out: dict[str, list[dict]] = {"modelconfigs": [], "toolconfigs": []}
        for plural, names in aliases.items():
            for alias in names:
                try:
                    cr = reader.get(GROUP, VERSION, plural, alias)
                except Exception as exc:  # noqa: BLE001 - see docstring
                    logger.info("skipping %s/%s for env injection (%s)",
                                plural, alias, _classify(exc))
                    continue
                provider = ((cr or {}).get("spec") or {}).get("provider")
                if provider:
                    out[plural].append({"alias": alias, "provider": provider})
        return out["modelconfigs"], out["toolconfigs"]

    # ── provisioning ──

    def provision_backend(self, spec: dict, status: dict) -> dict:
        provider = spec.get("provider")
        if provider != CLAIMED_PROVIDER:
            raise ProvisioningFailed(
                "UnsupportedProvider",
                f"k8s-agent-operator hosts provider={CLAIMED_PROVIDER!r} only; got "
                f"{provider!r}. AgentCore Runtime hosting is aws-agent-operator's "
                f"(a design note); other providers arrive as sibling operators (a design note).")

        kp = spec.get("kubernetesPod") or {}
        if not kp.get("containerImage"):
            raise ProvisioningFailed(
                "ConfigIncomplete",
                f"provider={CLAIMED_PROVIDER} requires spec.kubernetesPod.containerImage.")

        self._validate_dependencies(spec, self._k8s_client(), status)

        # a design note: withhold capability BEFORE anything is created. A refusal after
        # the Deployment exists would leave an ungoverned pod running.
        user_env = kp.get("env") or []
        override = withholding.reserved_collision_refusal(
            withholding.reserved_env_collisions(user_env))
        if override:
            self._publish_perimeter_verdict(spec, False, *override)
            raise ProvisioningFailed(*override)

        agent_name = spec.get("agentName", "unknown")
        sa_name = kp.get("serviceAccountName") or pb.DEFAULT_SERVICE_ACCOUNT
        np_enabled = kp.get("networkPolicy", "enforce") != "off"
        allow_cloud_identity = bool(kp.get("allowServiceAccountCloudIdentity"))

        findings = [
            withholding.check_service_account_identity(
                self._read_service_account(COMPONENTS_NS, sa_name),
                allow_cloud_identity=allow_cloud_identity),
            # The SA object cannot show an EKS Pod Identity association; the pods
            # it already runs can. Read separately, reported separately.
            withholding.check_pod_identity_witness(
                self._read_pods_for_service_account(COMPONENTS_NS, sa_name),
                allow_cloud_identity=allow_cloud_identity),
            withholding.check_environment_credentials(user_env),
            withholding.check_network_policy_enforcement(self._list_crd_names())
            if np_enabled else withholding.network_policy_disabled_finding(),
        ]
        refusal = withholding.refusal_reason(
            findings,
            require_enforcement=os.environ.get(
                REQUIRE_NP_ENFORCEMENT_ENV, "").lower() == "true")
        if refusal:
            self._publish_perimeter_verdict(spec, False, *refusal)
            raise ProvisioningFailed(*refusal)
        # The message states what was actually established, leg by leg. It must
        # not read "egress only to the perimeter" on an asset that declared
        # networkPolicy: off -- capabilityWithheld already says the claim is not
        # whole, and the condition's message may not contradict it.
        self._publish_perimeter_verdict(
            spec, True, "PerimeterEnforced",
            f"agent pod runs as {sa_name} with no cloud identity and no "
            f"automounted ServiceAccount token; "
            + ("egress restricted to the perimeter and DNS"
               if np_enabled else
               "NO egress restriction (spec.kubernetesPod.networkPolicy: off)"))

        owner_refs = _owner_references(spec, status, agent_name)
        name = pb.resource_name(agent_name)
        env_block = self._compose_env(spec, agent_name)

        converged, adopted = self._apply_deployment(
            spec, agent_name, name, owner_refs, env_block)
        self._apply_service(spec, agent_name, name, owner_refs)
        np_name = self._apply_network_policy(
            spec, agent_name, owner_refs) if np_enabled else ""

        ready_replicas, desired_replicas = self._deployment_readiness(COMPONENTS_NS, name)
        ready = bool(ready_replicas is not None and desired_replicas
                     and ready_replicas == desired_replicas)

        kp_status = {
            "deploymentName": name,
            "serviceName": name,
            "networkPolicyName": np_name,
            "ready": ready,
            "capabilityWithheld": withholding.capability_withheld(findings),
            "withholdingFindings": findings,
            "podTemplateLabelsConverged": converged,
        }
        if adopted:
            kp_status["adoptedFrom"] = adopted
        return {"hostingProvider": CLAIMED_PROVIDER, "managed": True,
                "kubernetesPod": kp_status}

    @staticmethod
    def _publish_perimeter_verdict(spec, enforced: bool, reason: str,
                                   message: str) -> None:
        """Surface the perimeter verdict as PerimeterEnforced on the CR.

        A no-op when the caller attached no patch (SpecWithMeta.patch). The
        refusal itself never depends on this: provision_backend raises either
        way, so a missing patch loses the explanation, never the control.
        """
        patch_obj = getattr(spec, "patch", None)
        if patch_obj is None:
            return
        AssetOperator._set_condition(
            patch_obj, withholding.PERIMETER_CONDITION,
            "True" if enforced else "False", reason, message)

    def _compose_env(self, spec: dict, agent_name: str) -> list[dict]:
        models, tools = self._resolve_dependency_providers(spec.get("dependsOn"))
        return pb.build_env(
            spec=spec, agent_name=agent_name,
            region=os.environ.get("AWS_REGION", "us-west-2"),
            registry_id=os.environ.get("REGISTRY_ID", ""),
            gateway_url=_gateway_url(),
            resolved_models=models, resolved_tools=tools,
            credential_secret=os.environ.get("MODAAS_GATEWAY_CREDENTIAL_SECRET", ""),
            credential_secret_key=os.environ.get(
                "MODAAS_GATEWAY_CREDENTIAL_SECRET_KEY", ""),
        )

    def _apply_deployment(self, spec, agent_name, name, owner_refs, env_block):
        api = self._apps_v1()
        try:
            existing = self._read_deployment_dict(COMPONENTS_NS, name)
        except ApiException as exc:
            raise ProvisioningFailed(
                "DeploymentReadFailed",
                f"read_namespaced_deployment({name}) failed: {exc.status} {exc.reason}")

        desired = pb.build_deployment_body(
            spec, COMPONENTS_NS, agent_name, owner_refs, env_block)
        adopted = pb.adopted_from(existing)
        body, converged = pb.plan_deployment_patch(existing, desired)

        if existing is None:
            try:
                api.create_namespaced_deployment(namespace=COMPONENTS_NS, body=body)
            except ApiException as exc:
                raise ProvisioningFailed(
                    "DeploymentCreateFailed",
                    f"create_namespaced_deployment({name}) failed: "
                    f"{exc.status} {exc.reason}")
            logger.info("created Deployment %s/%s", COMPONENTS_NS, name)
            return converged, adopted
        try:
            api.patch_namespaced_deployment(
                name=name, namespace=COMPONENTS_NS, body=body)
        except ApiException as exc:
            raise ProvisioningFailed(
                "DeploymentPatchFailed",
                f"patch_namespaced_deployment({name}) failed: {exc.status} {exc.reason}")
        logger.info("patched Deployment %s/%s (adoptedFrom=%s converged=%s)",
                    COMPONENTS_NS, name, adopted, converged)
        return converged, adopted

    def _apply_service(self, spec, agent_name, name, owner_refs):
        api = self._core_v1()
        body = pb.build_service_body(spec, COMPONENTS_NS, agent_name, owner_refs)
        _create_or_patch(
            read=lambda: api.read_namespaced_service(name=name, namespace=COMPONENTS_NS),
            create=lambda: api.create_namespaced_service(
                namespace=COMPONENTS_NS, body=body),
            patch_=lambda: api.patch_namespaced_service(
                name=name, namespace=COMPONENTS_NS, body=body),
            kind="Service", name=name)

    def _apply_network_policy(self, spec, agent_name, owner_refs) -> str:
        api = self._networking_v1()
        np_name = pb.network_policy_name(agent_name)
        body = pb.build_network_policy_body(
            spec, COMPONENTS_NS, agent_name, owner_refs,
            gateway_namespace=os.environ.get(GATEWAY_NS_ENV, "agentgateway-system"),
            istiod_namespace=os.environ.get(ISTIOD_NS_ENV) or None)
        # A NetworkPolicy the operator failed to write is a withholding leg that
        # is NOT in place, so every failure here is a refusal, not a warning.
        _create_or_patch(
            read=lambda: api.read_namespaced_network_policy(
                name=np_name, namespace=COMPONENTS_NS),
            create=lambda: api.create_namespaced_network_policy(
                namespace=COMPONENTS_NS, body=body),
            patch_=lambda: api.patch_namespaced_network_policy(
                name=np_name, namespace=COMPONENTS_NS, body=body),
            kind="NetworkPolicy", name=np_name)
        return np_name

    # ── teardown ──

    def deprovision_backend(self, status: dict) -> None:
        status = status or {}
        if status.get("hostingProvider") not in (None, CLAIMED_PROVIDER):
            return
        kp = status.get("kubernetesPod") or {}
        np_name = kp.get("networkPolicyName")
        service_name = kp.get("serviceName")
        deploy_name = kp.get("deploymentName")
        if not (np_name or service_name or deploy_name):
            return
        # NetworkPolicy first: while the pods still exist, removing the egress
        # restriction last is the ordering that never widens their reach.
        if np_name:
            _delete(lambda: self._networking_v1().delete_namespaced_network_policy(
                name=np_name, namespace=COMPONENTS_NS), "NetworkPolicy", np_name)
        if deploy_name:
            _delete(lambda: self._apps_v1().delete_namespaced_deployment(
                name=deploy_name, namespace=COMPONENTS_NS), "Deployment", deploy_name)
        if service_name:
            _delete(lambda: self._core_v1().delete_namespaced_service(
                name=service_name, namespace=COMPONENTS_NS), "Service", service_name)


_operator = K8sAgentOperator()


# ── helpers ───────────────────────────────────────────────────────────────

def _as_dict(obj) -> dict:
    """A kubernetes client model (or a plain dict) as a camelCase dict.

    ``sanitize_for_serialization`` is the client's own public converter and is
    present in every version, unlike ``_preload_content=False`` plumbing. A dict
    passes through unchanged, which keeps tests able to hand plain dicts in.
    """
    return ApiClient().sanitize_for_serialization(obj)


def _owner_references(spec: dict, status: dict, agent_name: str) -> list[dict]:
    """Component (controller) + AgentConfig (non-controller).

    Both matter: the Component ref cascade-deletes when the Component goes, and
    the direct AgentConfig ref cascade-deletes when only the AgentConfig is
    removed. The graft shipped without the second one until a design note's late fix.
    """
    refs: list[dict] = []
    comp = (status or {}).get("componentRef") or {}
    if comp.get("uid"):
        refs.append({"apiVersion": "oda.tmforum.org/v1", "kind": "Component",
                     "name": comp.get("name", agent_name), "uid": comp["uid"],
                     "controller": True, "blockOwnerDeletion": True})
    cr_meta = getattr(spec, "cr_meta", None) or {}
    if cr_meta.get("uid"):
        refs.append({"apiVersion": f"{GROUP}/{VERSION}", "kind": "AgentConfig",
                     "name": cr_meta.get("name", agent_name), "uid": cr_meta["uid"],
                     "controller": False, "blockOwnerDeletion": True})
    return refs


def _create_or_patch(*, read, create, patch_, kind: str, name: str) -> None:
    try:
        read()
    except ApiException as exc:
        if exc.status != 404:
            raise ProvisioningFailed(
                f"{kind}ReadFailed",
                f"read {kind} {name} failed: {exc.status} {exc.reason}")
        try:
            create()
        except ApiException as cexc:
            raise ProvisioningFailed(
                f"{kind}CreateFailed",
                f"create {kind} {name} failed: {cexc.status} {cexc.reason}")
        logger.info("created %s %s/%s", kind, COMPONENTS_NS, name)
        return
    try:
        patch_()
    except ApiException as exc:
        raise ProvisioningFailed(
            f"{kind}PatchFailed",
            f"patch {kind} {name} failed: {exc.status} {exc.reason}")
    logger.info("patched %s %s/%s", kind, COMPONENTS_NS, name)


def _delete(call, kind: str, name: str) -> None:
    """Best-effort delete. Cleanup must not wedge on a 403 or a 404."""
    try:
        call()
        logger.info("deleted %s %s/%s", kind, COMPONENTS_NS, name)
    except ApiException as exc:
        if exc.status != 404:
            logger.warning("delete %s %s/%s failed: %s %s",
                           kind, COMPONENTS_NS, name, exc.status, exc.reason)


def _another_controller_claimed(status: dict | None) -> bool:
    """True when some other controller has already taken this asset.

    Two operators now watch `agentconfigs`, so each sees every AgentConfig. A
    non-owning operator that stamps ProviderClaimed=False on a
    correctly-governed asset reports on something it has no standing over, and
    because a status patch REPLACES the condition list the two writers would
    flap. So the unclaimed stamp is skipped when the asset is visibly owned.
    """
    status = status or {}
    hosting = status.get("hostingProvider")
    if hosting == CLAIMED_PROVIDER:
        return False
    if hosting:
        return True
    return any(isinstance(c, dict) and c.get("type") == "ProviderClaimed"
               and c.get("status") == "True"
               for c in status.get("conditions") or [])


# ── Canvas-first emission (a design note / a design note / a design note / a design note) ─────────────

def _ensure_component(api, namespace: str, name: str, uid: str):
    return _shared_ensure_component(k8s_api=api, namespace=namespace,
                                    source_kind="AgentConfig", source_name=name,
                                    source_uid=uid)


def _ensure_identity_config(api, namespace: str, name: str, *, owner_reference):
    return _shared_ensure_identity_config(
        k8s_api=api, namespace=namespace, source_kind="AgentConfig",
        source_name=name, owner_reference=owner_reference)


def _ensure_dependent_apis(api, *, namespace: str, name: str, uid: str, provider: str,
                           alias: str, status_patch, owner_reference):
    """Emit one DependentAPI per wire format and publish the perimeter URL.

    Raises UnmappedProviderError for a provider with no dialect -- the caller
    turns that into phase=Failed / ProviderNotRoutable rather than letting it be
    misdiagnosed as a DependentAPI failure.

    Returns the Canvas-resolved URL when canvas-depapi-op has resolved one, else
    None. Either way `compute_and_publish_perimeter_url` has written
    status.globalResourceEndpoint, which the agentconfigs status CEL REQUIRES
    before phase=Approved is accepted.
    """
    wire_formats = dialects_for(provider)
    resolved = None
    for wf in wire_formats:
        dep_api = _shared_ensure_dependent_api(
            k8s_api=api, namespace=namespace, asset_name=name, asset_uid=uid,
            provider=provider, wire_format=wf, owner_reference=owner_reference)
        if resolved is None:
            resolved = _shared_get_resolved_url(dep_api) or None
    _shared_publish_perimeter_url(
        alias=alias, wire_format=wire_formats[0], status_patch=status_patch,
        k8s_api=api, all_wire_formats=wire_formats)
    return resolved


def _emit_canvas_integration(*, patch_obj, status, spec, meta, name, namespace,
                             body=None) -> bool:
    """Component -> IdentityConfig -> DependentAPI + perimeter URL.

    Every step is fail-soft into a status condition (AGENTS.md Coherence Rule 19):
    a Canvas hiccup must not fail the asset, but it must be visible in
    `kubectl describe`. Returns False only for ProviderNotRoutable, which is a
    terminal contract error and stops the handler.
    """
    set_cond = AssetOperator._set_condition
    try:
        api = _custom_objects_api()
    except Exception as exc:  # noqa: BLE001 - degrade to a condition
        logger.warning("Canvas integration unavailable for %s: %s", name, exc)
        set_cond(patch_obj, "OwnedByComponent", "False", "ImportFailed",
                 f"Canvas integration unavailable: {str(exc)[:256]}")
        return True

    meta = meta or {}
    annotations = meta.get("annotations") or {}
    component_owner = None

    if annotations.get(SKIP_COMPONENT_ANNOTATION, "").lower() == "true":
        set_cond(patch_obj, "OwnedByComponent", "False", "ComponentSkipped",
                 f"{SKIP_COMPONENT_ANNOTATION}: true — Component emission skipped")
    else:
        try:
            comp_meta = (_ensure_component(
                api, namespace, name, meta.get("uid", "")) or {}).get("metadata") or {}
            comp_uid = comp_meta.get("uid", "")
            comp_name = comp_meta.get("name", name)
            existing = meta.get("ownerReferences") or []
            if not any(r.get("uid") == comp_uid for r in existing):
                patch_obj.metadata["ownerReferences"] = list(existing) + [{
                    "apiVersion": "oda.tmforum.org/v1", "kind": "Component",
                    "name": comp_name, "uid": comp_uid,
                    "controller": False, "blockOwnerDeletion": True}]
            patch_obj.status["componentRef"] = {
                "name": comp_name, "namespace": namespace, "uid": comp_uid}
            component_owner = {
                "apiVersion": "oda.tmforum.org/v1", "kind": "Component",
                "name": comp_name, "uid": comp_uid,
                "controller": True, "blockOwnerDeletion": True}
            set_cond(patch_obj, "OwnedByComponent", "True", "ComponentLinked",
                     f"Owned by Component {comp_name}")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Component emission failed for %s: %s", name, exc)
            set_cond(patch_obj, "OwnedByComponent", "False", _classify(exc),
                     f"Component emission failed: {str(exc)[:256]}")

    try:
        _ensure_identity_config(api, namespace, name, owner_reference=component_owner)
        set_cond(patch_obj, "IdentityProvisioned", "True", "IdentityConfigCreated",
                 f"IdentityConfig modaas-agentconfig-{name} provisioned via Canvas")
    except Exception as exc:  # noqa: BLE001
        logger.warning("IdentityConfig failed for %s: %s", name, exc)
        set_cond(patch_obj, "IdentityProvisioned", "False", _classify(exc),
                 f"IdentityConfig provisioning failed: {str(exc)[:256]}")

    # DependentAPI owner is non-controlling (the Component already controls it).
    dep_owner = dict(component_owner, controller=False) if component_owner else None
    try:
        resolved = _ensure_dependent_apis(
            api, namespace=namespace, name=name, uid=meta.get("uid", ""),
            provider=spec.get("provider", ""), alias=spec.get("alias", name),
            status_patch=patch_obj.status, owner_reference=dep_owner)
    except UnmappedProviderError as exc:
        # Caught BEFORE the broad handler below, which would otherwise classify a
        # contract error as a DependentAPI API failure. Stale endpoint fields are
        # cleared: advertising a route on a Failed asset is worse than silence.
        patch_obj.status["phase"] = "Failed"
        for field in ("endpoint", "globalResourceEndpoint", "endpoints",
                      "endpointScope", "dialectEndpoints"):
            patch_obj.status.pop(field, None)
        set_cond(patch_obj, "DependentAPIProvisioned", "False",
                 "ProviderNotRoutable", str(exc))
        if body is not None:
            kopf.warn(body, reason="ProviderNotRoutable", message=str(exc))
        return False
    except Exception as exc:  # noqa: BLE001
        logger.warning("DependentAPI failed for %s: %s", name, exc)
        set_cond(patch_obj, "DependentAPIProvisioned", "False", _classify(exc),
                 f"DependentAPI emission failed: {str(exc)[:256]}")
        return True

    if resolved:
        patch_obj.status["endpoint"] = resolved
        patch_obj.status["globalResourceEndpoint"] = resolved
        patch_obj.status["endpointScope"] = "public"
        set_cond(patch_obj, "DependentAPIProvisioned", "True", "DependentAPICreated",
                 f"DependentAPI resolved: {resolved}")
    else:
        set_cond(patch_obj, "DependentAPIProvisioned", "False", "ResolutionPending",
                 "DependentAPI created; awaiting Canvas canvas-depapi-op resolution")
    return True


def _populate_dependency_health(patch_obj, spec: dict, name: str) -> None:
    """Populate DependencyHealthy on every reconcile, not only on transitions.

    Bug #10's shape: the timer-only path missed the already-Approved case, and 7
    Approved AgentConfigs sat with no DependencyHealthy condition at all.
    """
    if spec.get("paused"):
        return
    try:
        healthy, reason = _operator.check_dependency_health(spec, _operator._k8s_client())
    except Exception as exc:  # noqa: BLE001 - observability must not fail reconcile
        logger.warning("DependencyHealthy populate failed for %s: %s", name, exc)
        return
    _write_dependency_health(patch_obj, healthy, reason)


def _write_dependency_health(patch_obj, healthy: bool, reason: str) -> None:
    cond_reason = reason.split(":")[0] if reason else "Unknown"
    AssetOperator._set_condition(
        patch_obj, "DependencyHealthy", "True" if healthy else "False",
        cond_reason, reason or "")
    patch_obj.status["dependencyStatus"] = {
        "healthy": bool(healthy), "reason": cond_reason, "message": reason or ""}
    patch_obj.status["dependencyHealthy"] = bool(healthy)


# ── kopf wiring ───────────────────────────────────────────────────────────

@kopf.on.startup()
def configure(settings, **_):
    settings.watching.server_timeout = 60
    logger.info("k8s-agent-operator started — watching %s.%s/%s, provider=%s only",
                PLURAL, GROUP, VERSION, CLAIMED_PROVIDER)


@kopf.on.resume(GROUP, VERSION, PLURAL, retries=5)
@kopf.on.create(GROUP, VERSION, PLURAL, retries=5)
@kopf.on.update(GROUP, VERSION, PLURAL, retries=5)
@traced("operator.k8sagent.reconcile", attrs={"operator.kind": "AgentConfig"})
def reconcile(spec, status, meta, name, namespace, patch, body=None, **_):
    if spec.get("provider") != CLAIMED_PROVIDER:
        if not _another_controller_claimed(status):
            from operators.shared.provider_claim import mark_unclaimed
            mark_unclaimed(patch, status, spec.get("provider"), CLAIMED_PROVIDER)
        return None

    # Seed live conditions before setting any: a status patch replaces the whole
    # list, so an unseeded handler erases what another path wrote.
    _operator._seed_conditions(patch, status)
    AssetOperator._set_condition(
        patch, "ProviderClaimed", "True", "ProviderClaimed",
        f"k8s-agent-operator claims spec.provider={CLAIMED_PROVIDER}")

    if not _emit_canvas_integration(patch_obj=patch, status=status, spec=spec,
                                    meta=meta, name=name, namespace=namespace,
                                    body=body):
        return None

    _populate_dependency_health(patch, spec, name)

    return _operator.reconcile(
        SpecWithMeta(spec, {"name": name, "uid": (meta or {}).get("uid")}, patch),
        status, meta, patch)


@kopf.on.delete(GROUP, VERSION, PLURAL, retries=5)
def cleanup(spec, status, meta, name, namespace, **_):
    if spec.get("provider") != CLAIMED_PROVIDER:
        return None
    return _operator.cleanup(spec, status)


@kopf.timer(GROUP, VERSION, PLURAL, interval=300, idle=30, retries=3)
async def resync_from_registry(spec, status, patch, name, **_):
    """Re-read the Registry record every 5 minutes (a design note resync timer)."""
    if spec.get("provider") != CLAIMED_PROVIDER:
        return None
    # Seeded after the ownership guard, before any write (see reconcile).
    _operator._seed_conditions(patch, status)
    try:
        result = _operator.resync_from_registry(spec, dict(status or {}), patch)
        logger.info("resync %s: %s", name, result)
        return result
    except Exception as exc:  # noqa: BLE001 - a timer must not crash the operator
        logger.error("resync_from_registry failed for %s: %s: %s",
                     name, type(exc).__name__, exc, exc_info=True)
        return {"error": str(exc)}


@kopf.timer(GROUP, VERSION, PLURAL, interval=120, idle=15, retries=3)
async def check_dependency_health(spec, status, patch, name, **_):
    """a design note cross-asset observability. Surfaces blast radius; pauses nothing.

    Seeds before writing: unseeded, each run replaced status.conditions with
    DependencyHealthy alone (the same defect measured on aws-agent-operator's
    timer on 2026-09-28).
    """
    if spec.get("provider") != CLAIMED_PROVIDER or spec.get("paused"):
        return None
    _operator._seed_conditions(patch, status)
    try:
        healthy, reason = _operator.check_dependency_health(
            spec, _operator._k8s_client())
    except Exception as exc:  # noqa: BLE001
        logger.error("check_dependency_health failed for %s: %s: %s",
                     name, type(exc).__name__, exc, exc_info=True)
        return {"error": str(exc)}
    _write_dependency_health(patch, healthy, reason)
    if not healthy:
        logger.info("dep-health %s: UNHEALTHY — %s", name, reason)
    return {"healthy": healthy, "reason": reason}
