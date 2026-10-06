"""a design note/a design note — Cedar policy projection to the in-cluster PDP (Bucket 2).

When a ToolConfig carries an inline Cedar policy (``spec.access.cedarPolicy``),
the operator projects that policy text into a label-scoped ConfigMap in
``modaas-system`` so the in-cluster PDP's ConfigMap watcher hot-loads it.
The AI Gateway then calls ``POST <pdp>/decide`` with the derived ``policyId``
on every tool invocation (a design note fail-closed PEP).

This is the shift-left mechanism: the operator owns the side-effect of moving
declarative policy text from the CR into the PDP's watch scope; no policy lives
in any container image and no separate deployment is needed (CLAUDE.md mission
constraints 1+3).

Watcher contract (verified against pdp/policy_watcher.py, 2026-06-11):
  * namespace:      modaas-system (PDP watches there)
  * label selector: app.kubernetes.io/part-of=modaas-pdp  (REQUIRED — the
                    watcher ignores ConfigMaps without this label; this keeps
                    arbitrary customer ConfigMaps out of the evaluator)
  * data key:       cedar.policy  (text/plain Cedar source)
  * policyId:       ConfigMap annotation modaas.tmforum.org/policy-id, falling
                    back to the ConfigMap name when the annotation is absent.

policyId derivation (a design note): when the CR sets
``spec.access.agentPolicy.engine.cedar.policyId`` that value wins; otherwise the
policyId is derived from the CR name as ``modaas-toolconfig-<name>`` (mirrors
the IdentityConfig naming convention in identity_config.py).

ADDITIVE + GUARDED: the caller only invokes this when ``spec.access.cedarPolicy``
is present, so existing ToolConfigs (no inline Cedar policy) are unaffected and
the live booth behavior is unchanged. All failures are non-blocking (fail-soft):
projection problems surface as a ``PolicyProjected=False`` condition, never a
reconcile abort — the tool path's own PDP call fail-closes per a design note if the
policy never lands.
"""
import logging
import re
from typing import Optional

logger = logging.getLogger("shared.policy_projection")

# Watcher contract constants — MUST track pdp/policy_watcher.py.
PDP_NAMESPACE = "modaas-system"
POLICY_LABEL_KEY = "app.kubernetes.io/part-of"
POLICY_LABEL_VALUE = "modaas-pdp"
POLICY_DATA_KEY = "cedar.policy"
POLICY_ID_ANNOTATION = "modaas.tmforum.org/policy-id"


def derive_policy_id(source_kind: str, source_name: str) -> str:
    """Default policyId when the CR does not set one explicitly (a design note).

    ``modaas-<kind-lower>-<source-name>`` — mirrors identity_config.py so the
    PDP policyId, the IdentityConfig name, and the ConfigMap name all share a
    stable, predictable shape.
    """
    return f"modaas-{source_kind.lower()}-{source_name}"[:253]


def resolve_policy_id(spec: dict, source_kind: str, source_name: str) -> str:
    """Return the effective policyId for this CR.

    Honors ``spec.access.agentPolicy.engine.cedar.policyId`` when set; otherwise
    derives from the CR name (a design note: "cedarPolicy present => policyId derived
    from CR name if not set").
    """
    access = (spec or {}).get("access") or {}
    agent_policy = access.get("agentPolicy") or {}
    cedar = (agent_policy.get("engine") or {}).get("cedar") or {}
    explicit = cedar.get("policyId")
    if explicit:
        return str(explicit)[:253]
    return derive_policy_id(source_kind, source_name)


def _configmap_name(policy_id: str) -> str:
    """ConfigMap name. K8s object names must be DNS-1123 subdomains; the
    policyId already follows that shape (modaas-<kind>-<name>), so reuse it.
    """
    return policy_id[:253]


def ensure_policy_configmap(
    core_v1_api,
    source_kind: str,
    source_name: str,
    policy_id: str,
    policy_text: str,
    owner_reference: Optional[dict] = None,
) -> Optional[str]:
    """Project the CR's inline Cedar policy into a label-scoped ConfigMap.

    The ConfigMap is created (or patched-to-current on conflict) in
    ``modaas-system`` carrying the ``app.kubernetes.io/part-of=modaas-pdp``
    label the PDP watcher requires, the ``cedar.policy`` data key, and the
    ``modaas.tmforum.org/policy-id`` annotation so the watcher's policyId
    resolution lands on the operator-chosen id rather than the ConfigMap name.

    Returns the policyId on success, or None on any error (non-blocking).

    Note: the ConfigMap lives in ``modaas-system`` next to the PDP, NOT in the
    asset CR's namespace. Cross-namespace ownerReferences are invalid in K8s, so
    ``owner_reference`` is honored ONLY when it points at an object in
    modaas-system; cross-namespace owners are dropped (the ConfigMap is then
    reaped by the watcher when the source policy disappears + by the
    label-scoped garbage collection sweep, not by cascade-delete).
    """
    if not policy_text or not str(policy_text).strip():
        logger.debug(
            "policy projection skipped for %s/%s — empty cedarPolicy",
            source_kind, source_name,
        )
        return None

    cm_name = _configmap_name(policy_id)

    metadata = {
        "name": cm_name,
        "namespace": PDP_NAMESPACE,
        "labels": {
            POLICY_LABEL_KEY: POLICY_LABEL_VALUE,
            "oda.tmforum.org/sourceKind": source_kind,
            "oda.tmforum.org/sourceName": source_name,
            "app.kubernetes.io/managed-by": "modaas",
        },
        "annotations": {
            POLICY_ID_ANNOTATION: policy_id,
        },
    }
    # ownerReferences only valid for owners in the SAME namespace (modaas-system).
    if owner_reference is not None and (owner_reference.get("namespace") in (None, PDP_NAMESPACE)):
        # Drop the namespace key if present — ownerReferences don't carry one.
        owner = {k: v for k, v in owner_reference.items() if k != "namespace"}
        metadata["ownerReferences"] = [owner]

    body = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": metadata,
        "data": {POLICY_DATA_KEY: str(policy_text)},
    }

    try:
        core_v1_api.create_namespaced_config_map(namespace=PDP_NAMESPACE, body=body)
        logger.info(
            "projected Cedar policy for %s/%s -> ConfigMap %s/%s (policyId=%s)",
            source_kind, source_name, PDP_NAMESPACE, cm_name, policy_id,
        )
        return policy_id
    except Exception as e:
        status = getattr(e, "status", None)
        if status == 409:
            # Already exists — patch data + annotation so policy edits propagate.
            # Do NOT touch ownerReferences/labels on patch to avoid clobbering
            # finalizers or pre-existing state.
            try:
                core_v1_api.patch_namespaced_config_map(
                    name=cm_name,
                    namespace=PDP_NAMESPACE,
                    body={
                        "metadata": {"annotations": {POLICY_ID_ANNOTATION: policy_id}},
                        "data": {POLICY_DATA_KEY: str(policy_text)},
                    },
                )
                logger.info(
                    "patched Cedar policy ConfigMap %s/%s (policyId=%s)",
                    PDP_NAMESPACE, cm_name, policy_id,
                )
                return policy_id
            except Exception as patch_err:  # noqa: BLE001
                logger.warning(
                    "policy ConfigMap %s exists but patch failed (non-blocking): %s",
                    cm_name, type(patch_err).__name__,
                )
                return None
        if status == 404:
            logger.debug(
                "namespace %s missing for policy projection of %s/%s (404) — non-blocking",
                PDP_NAMESPACE, source_kind, source_name,
            )
            return None
        logger.warning(
            "policy projection for %s/%s failed (non-blocking): %s: %s",
            source_kind, source_name, type(e).__name__,
            (getattr(e, "status", None), str(getattr(e, "reason", "")) or str(e)[:200]),
        )
        return None


# ── W4-C (option a, owner-decided 2026-09-02): resource-side model grants ──
_CONSUMER_SAFE = re.compile(r"^[A-Za-z0-9._:-]+$")


def render_consumer_permits(model_alias: str, consumers: list) -> str:
    """Render Cedar permits for ModelConfig.spec.access.allowedConsumers.

    Resource-side authoring per a design note's principle -- the model's owner
    grants access; consumers never self-declare. One permit per consumer:
        permit(principal == ServiceIdentity::"<azp>",
               action == Action::"invoke", resource == Model::"<alias>");

    Inputs are quoted into Cedar source, so both the alias and every consumer
    string are allowlist-validated -- a consumer named
    '"my", action == ...' must be a ValueError, never a policy.
    """
    if not consumers:
        return ""
    if not _CONSUMER_SAFE.match(model_alias or ""):
        raise ValueError(f"model alias not Cedar-safe: {model_alias!r}")
    seen, ordered = set(), []
    for c in consumers:
        c = str(c)
        if not _CONSUMER_SAFE.match(c):
            raise ValueError(f"consumer principal not Cedar-safe: {c!r}")
        if c not in seen:
            seen.add(c)
            ordered.append(c)
    lines = [f'// generated by MoDaaS (W4-C): resource-side grants for Model "{model_alias}"']
    for c in ordered:
        lines.append(
            f'permit(principal == ServiceIdentity::"{c}", '
            f'action == Action::"invoke", resource == Model::"{model_alias}");'
        )
    return "\n".join(lines) + "\n"


def delete_policy_configmap(core_v1_api, policy_id: str) -> bool:
    """Withdraw a projected policy (W4-C: paused/unapproved models must not
    leave grants lingering in the PDP). Idempotent: absent is success."""
    cm_name = _configmap_name(policy_id)
    try:
        core_v1_api.delete_namespaced_config_map(name=cm_name, namespace=PDP_NAMESPACE)
        logger.info("policy configmap %s withdrawn", cm_name)
        return True
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "status", None) == 404:
            return True
        logger.warning("policy configmap %s withdrawal failed: %s", cm_name, exc)
        return False
