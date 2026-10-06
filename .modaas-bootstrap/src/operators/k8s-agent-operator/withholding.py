"""a design note capability withholding for provider=kubernetesPod.

a design note's decision is that agentgateway + authz is made the only path to a
governed asset **by withholding capability from the workload, not by
redirecting it**. Its Kubernetes row names three mechanisms:

  1. no model or tool credentials in the pod's service account, Secrets or
     environment,
  2. NetworkPolicy egress only to the gateway (and DNS),
  3. the cluster must actually enforce NetworkPolicy.

Each is one "leg" here. Every leg returns a finding with an explicit result:

  pass        verified in place
  fail        verified absent -> the operator refuses the CR
  unverified  could not be checked -> reported, never silently treated as pass

The third value is the point of the module. `capability_withheld` is true only
when every leg passes, so a claim MoDaaS cannot substantiate is not made. That
is the inverse of the defect class `loop/METHOD-positive-controls.md` names
("declared but not enforced") -- and it is also why leg 3 reports rather than
refuses by default: refusing every asset on a cluster whose CNI this code failed
to recognise would make an unrecognised-but-working CNI indistinguishable from a
broken install. Operators who want fail-closed set
MODAAS_REQUIRE_NETWORKPOLICY_ENFORCEMENT=true.

All functions here are pure -- reads happen in the operator, decisions happen
here (same split as operators/shared/governance/approval.py).
"""
from __future__ import annotations

from operators.shared.sdk_redirect import (GATEWAY_CREDENTIAL_ENV_NAMES,
                                           _PROVIDER_TO_ENV)

LEG_SERVICE_ACCOUNT_IDENTITY = "serviceAccountIdentity"
LEG_ENVIRONMENT_CREDENTIALS = "environmentCredentials"
LEG_NETWORK_POLICY_ENFORCED = "networkPolicyEnforced"
LEG_POD_IDENTITY = "podIdentityAssociation"

REFUSAL_REASON = "CapabilityNotWithheld"
ENFORCEMENT_REFUSAL_REASON = "NetworkPolicyNotEnforced"
OVERRIDE_REFUSAL_REASON = "PerimeterEnvOverride"

#: The condition the refusal surfaces on. Owner decision 2026-09-26: a pod agent
#: reaches models and tools only through agentgateway, and an asset whose pod
#: could hold cloud credentials is refused with this condition set False. The
#: base class's Provisioned=False says the backend did not come up; this says
#: WHY, in the vocabulary of the control, so `kubectl describe` distinguishes a
#: perimeter refusal from an image pull or an API failure.
PERIMETER_CONDITION = "PerimeterEnforced"

# Annotations by which a ServiceAccount confers cloud identity on its pods. A
# pod that can obtain provider credentials can reach the provider without
# crossing the perimeter, which is the capability a design note withholds.
#
# Honest limit: this detects the PRESENCE of cloud identity, not what it can do.
# The precise check is iam:SimulatePrincipalPolicy (a design note leg 1), which needs an
# IAM permission this operator deliberately does not hold -- so the check is
# coarser than the AgentCore one, and coarse in the safe direction: it refuses a
# role that might be harmless rather than admitting one that might not be.
#
# There is deliberately NO Pod Identity entry here. An EKS Pod Identity
# association is an EKS Auth API resource and requires no annotation on the
# Kubernetes ServiceAccount, so an annotation key for it would be a detection
# that can never fire -- worse than no check, because it reads as coverage.
# What IS visible in the cluster is the witness EKS injects into the resulting
# pod; check_pod_identity_witness reads that.
# docs.aws.amazon.com/eks/latest/userguide/pod-id-how-it-works.html (2026-09-26)
CLOUD_IDENTITY_ANNOTATIONS: frozenset[str] = frozenset({
    "eks.amazonaws.com/role-arn",
    "azure.workload.identity/client-id",
    "iam.gke.io/gcp-service-account",
})

# The EKS Pod Identity witness, quoted from the AWS doc above: "When Amazon EKS
# starts a new pod that uses a service account with an EKS Pod Identity
# association, the cluster adds the following content to the Pod manifest" --
# these two env vars and the eks-pod-identity-token projected volume. Their
# presence on a pod means that pod can obtain AWS credentials from the node
# agent, i.e. reach a provider without crossing the perimeter.
POD_IDENTITY_ENV_NAMES: frozenset[str] = frozenset({
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
})
POD_IDENTITY_VOLUME_NAME = "eks-pod-identity-token"

# Env names that hand a workload a PROVIDER credential. Deliberately does NOT
# include OPENAI_API_KEY: that is the PERIMETER credential this operator injects
# (a hardening note). A user-supplied OPENAI_API_KEY is refused by the reserved-name check
# instead, with a message that says what is actually wrong.
PROVIDER_CREDENTIAL_ENV_NAMES: frozenset[str] = frozenset({
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "ANTHROPIC_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_AD_TOKEN",
    "GOOGLE_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "DATABRICKS_TOKEN",
    "NVIDIA_API_KEY",
})

# Env names the perimeter owns. Sourced from operators/shared/sdk_redirect.py
# rather than retyped, so the two cannot drift.
RESERVED_ENV_NAMES: frozenset[str] = frozenset(
    {name for pairs in _PROVIDER_TO_ENV.values() for name, _ in pairs}
    | {"AGENTCORE_GATEWAY_MCP_URL"}
    | set(GATEWAY_CREDENTIAL_ENV_NAMES)
)

# CRDs whose presence is evidence that some controller implements NetworkPolicy.
# The Kubernetes contract is explicit that a NetworkPolicy without one "will have
# no effect", so this is the difference between a control and a decoration.
NETWORK_POLICY_ENFORCEMENT_CRDS: tuple[str, ...] = (
    "policyendpoints.networking.k8s.io",     # Amazon VPC CNI
    "ciliumnetworkpolicies.cilium.io",       # Cilium
    "networkpolicies.crd.projectcalico.org",  # Calico
)


def _finding(leg: str, result: str, detail: str) -> dict:
    return {"leg": leg, "result": result, "detail": detail}


def check_service_account_identity(sa: dict | None, *,
                                   allow_cloud_identity: bool = False) -> dict:
    """Leg 1 — the pod's ServiceAccount must confer no cloud identity.

    ``sa`` is None when the read failed (403/404/broken client), which is
    `unverified`: an empty dict would read as "no annotations", i.e. a false pass.
    """
    if sa is None:
        return _finding(
            LEG_SERVICE_ACCOUNT_IDENTITY, "unverified",
            "could not read the pod ServiceAccount; cloud-identity posture unknown")
    meta = sa.get("metadata") or {}
    name = meta.get("name", "<unnamed>")
    found = sorted(set(meta.get("annotations") or {}) & CLOUD_IDENTITY_ANNOTATIONS)
    if found and not allow_cloud_identity:
        return _finding(
            LEG_SERVICE_ACCOUNT_IDENTITY, "fail",
            f"ServiceAccount {name} confers cloud identity via {', '.join(found)}; "
            f"a pod holding provider credentials can reach the provider without "
            f"crossing the MoDaaS perimeter. Set "
            f"spec.kubernetesPod.allowServiceAccountCloudIdentity=true to accept "
            f"this deliberately.")
    if found:
        return _finding(
            LEG_SERVICE_ACCOUNT_IDENTITY, "pass",
            f"ServiceAccount {name} confers cloud identity via {', '.join(found)}, "
            f"admitted by spec.kubernetesPod.allowServiceAccountCloudIdentity=true")
    return _finding(
        LEG_SERVICE_ACCOUNT_IDENTITY, "pass",
        f"SA {name} carries no cloud-identity annotation. This leg reads the SA "
        f"object only; an EKS Pod Identity association is not on it (see "
        f"{LEG_POD_IDENTITY}).")


def check_pod_identity_witness(pods, *, allow_cloud_identity: bool = False) -> dict:
    """Leg 4 — no pod of this ServiceAccount shows the EKS Pod Identity witness.

    Why this is a separate leg rather than part of leg 1: an EKS Pod Identity
    association is an EKS Auth API resource, not a Kubernetes object, and it puts
    no annotation on the ServiceAccount -- so leg 1's read cannot see it. The one
    piece of cluster-API-visible evidence is the injection EKS performs on the
    pod (POD_IDENTITY_ENV_NAMES / POD_IDENTITY_VOLUME_NAME). This leg reads that.

    Honest limits, both stated in the finding's detail rather than implied away:

    * it is POST-admission evidence. On a first create no pod exists yet, so the
      leg passes having examined zero pods. It becomes decisive from the next
      reconcile, and on the adoption path -- which is where a graft-created agent
      with an association would otherwise slip through unnoticed.
    * ``pods is None`` (read failed) is `unverified`, never pass. An empty list
      means "looked, found none"; None means "could not look".
    """
    if pods is None:
        return _finding(
            LEG_POD_IDENTITY, "unverified",
            "could not list the pods running as this ServiceAccount; an EKS Pod "
            "Identity association would be invisible either way")
    hits: list[str] = []
    for pod in pods:
        pod_name = ((pod.get("metadata") or {}).get("name")) or "<unnamed>"
        pod_spec = pod.get("spec") or {}
        for container in pod_spec.get("containers") or []:
            for entry in container.get("env") or []:
                if isinstance(entry, dict) and entry.get("name") in POD_IDENTITY_ENV_NAMES:
                    hits.append(f"{pod_name}: env {entry['name']}")
        for volume in pod_spec.get("volumes") or []:
            if isinstance(volume, dict) and volume.get("name") == POD_IDENTITY_VOLUME_NAME:
                hits.append(f"{pod_name}: volume {POD_IDENTITY_VOLUME_NAME}")
    if hits and not allow_cloud_identity:
        return _finding(
            LEG_POD_IDENTITY, "fail",
            f"EKS Pod Identity witness present ({'; '.join(sorted(hits))}); the "
            f"pod can obtain AWS credentials from the node agent and reach a "
            f"provider without crossing the MoDaaS perimeter. Delete the Pod "
            f"Identity association for this ServiceAccount, or set "
            f"spec.kubernetesPod.allowServiceAccountCloudIdentity=true to accept "
            f"this deliberately.")
    if hits:
        return _finding(
            LEG_POD_IDENTITY, "pass",
            f"EKS Pod Identity witness present ({'; '.join(sorted(hits))}), "
            f"admitted by spec.kubernetesPod.allowServiceAccountCloudIdentity=true")
    return _finding(
        LEG_POD_IDENTITY, "pass",
        f"{len(pods)} pod(s) of this ServiceAccount examined, none carrying the "
        f"EKS Pod Identity witness. Post-admission evidence: with 0 pods nothing "
        f"was ruled out, and an association added later is caught on the next "
        f"reconcile.")


def check_environment_credentials(env_entries) -> dict:
    """Leg 2 — no provider credential in the pod's environment.

    A secretKeyRef to a provider credential is the same capability as a literal,
    so detection is by NAME, not by whether a value is inline.
    """
    offenders = sorted({
        e["name"] for e in (env_entries or [])
        if isinstance(e, dict) and e.get("name") in PROVIDER_CREDENTIAL_ENV_NAMES
    })
    if offenders:
        return _finding(
            LEG_ENVIRONMENT_CREDENTIALS, "fail",
            f"spec.kubernetesPod.env declares provider credential(s) "
            f"{', '.join(offenders)}; the agent could call the provider directly.")
    return _finding(
        LEG_ENVIRONMENT_CREDENTIALS, "pass",
        "0 provider-credential env names in spec.kubernetesPod.env")


def check_network_policy_enforcement(crd_names) -> dict:
    """Leg 3 — some controller in this cluster implements NetworkPolicy."""
    if crd_names is None:
        return _finding(
            LEG_NETWORK_POLICY_ENFORCED, "unverified",
            "could not list CustomResourceDefinitions; NetworkPolicy enforcement "
            "unknown")
    present = [c for c in NETWORK_POLICY_ENFORCEMENT_CRDS if c in set(crd_names)]
    if present:
        return _finding(
            LEG_NETWORK_POLICY_ENFORCED, "pass",
            f"NetworkPolicy enforcement evidenced by {', '.join(present)}")
    return _finding(
        LEG_NETWORK_POLICY_ENFORCED, "unverified",
        "no NetworkPolicy-enforcing controller recognised (looked for "
        + ", ".join(NETWORK_POLICY_ENFORCEMENT_CRDS)
        + "); the policy is written but its effect is unproven")


def network_policy_disabled_finding() -> dict:
    """Leg 3 when the asset opted out via spec.kubernetesPod.networkPolicy=off.

    `fail`, not `unverified`: nothing was left unchecked -- the control was
    deliberately not installed, and `capability_withheld` must say so.

    `declaredOptOut` marks it as an EXPLICIT, auditable choice, which is what
    keeps `refusal_reason` from refusing it. Refusing would make the CRD field
    unusable; reporting `pass` would be a lie. The flag is the only honest third
    option, and it appears in status.kubernetesPod.withholdingFindings so an
    auditor sees exactly which asset opted out of which leg.
    """
    f = _finding(
        LEG_NETWORK_POLICY_ENFORCED, "fail",
        "spec.kubernetesPod.networkPolicy: off — no egress restriction was "
        "installed for this agent; it can reach anything the namespace allows")
    f["declaredOptOut"] = True
    return f


def reserved_env_collisions(env_entries) -> list[str]:
    """Perimeter-owned env names a user tried to supply."""
    return sorted({
        e["name"] for e in (env_entries or [])
        if isinstance(e, dict) and e.get("name") in RESERVED_ENV_NAMES
    })


def capability_withheld(findings) -> bool:
    """True only when every leg passed."""
    findings = list(findings or [])
    return bool(findings) and all(f.get("result") == "pass" for f in findings)


def refusal_reason(findings, *, require_enforcement: bool = False):
    """(reason, message) when provisioning must be refused, else None."""
    failed = [f for f in findings
              if f.get("result") == "fail" and not f.get("declaredOptOut")]
    if failed:
        legs = ", ".join(f["leg"] for f in failed)
        detail = " ".join(f.get("detail", "") for f in failed).strip()
        return REFUSAL_REASON, f"a design note withholding leg(s) not in place: {legs}. {detail}"
    if require_enforcement:
        unverified = [f for f in findings
                      if f.get("leg") == LEG_NETWORK_POLICY_ENFORCED
                      and f.get("result") == "unverified"]
        if unverified:
            return ENFORCEMENT_REFUSAL_REASON, (
                f"MODAAS_REQUIRE_NETWORKPOLICY_ENFORCEMENT=true and leg "
                f"{LEG_NETWORK_POLICY_ENFORCED} is unverified: "
                + unverified[0].get("detail", ""))
    return None


def reserved_collision_refusal(collisions):
    """(reason, message) for a user env entry that would override the perimeter."""
    if not collisions:
        return None
    return OVERRIDE_REFUSAL_REASON, (
        f"spec.kubernetesPod.env may not set perimeter-owned name(s) "
        f"{', '.join(collisions)}: overriding a redirect URL or the gateway "
        f"credential would point the agent past its own governance perimeter "
        f"while the CR stayed Approved.")
