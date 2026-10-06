"""ConfigMap watcher for the in-cluster PDP.

a design note §"Operator wiring":
    "PDP pod watches the PDP-side ConfigMaps and hot-loads policy text
     on change."

Watch scope:
    * namespace: modaas-system (configurable via PDP_NAMESPACE env)
    * label selector: app.kubernetes.io/part-of=modaas-pdp
    * data key: `cedar.policy` (text/plain Cedar source)
    * policyId: derived from ConfigMap annotation
                modaas.tmforum.org/policy-id, falling back to the
                ConfigMap name (so an operator-projected ConfigMap can
                be discovered without an annotation).

Why label-scoped: customer-owned ConfigMaps in modaas-system MUST NOT
be picked up unless they explicitly opt-in via the part-of label. This
prevents arbitrary policy text from random ConfigMaps reaching the
evaluator. The aws-agent-operator (BETA) is responsible for stamping
the label when projecting the customer's policy ConfigMap.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from typing import Optional

from kubernetes import client as k8s_client, config as k8s_config, watch as k8s_watch

from cedar_evaluator import CedarEvaluator, PolicyParseError

log = logging.getLogger("modaas-pdp.watcher")

POLICY_LABEL_KEY = "app.kubernetes.io/part-of"
POLICY_LABEL_VALUE = "modaas-pdp"
POLICY_DATA_KEY = "cedar.policy"
POLICY_ID_ANNOTATION = "modaas.tmforum.org/policy-id"


class PolicyWatcher:
    """Long-running ConfigMap watcher that drives a CedarEvaluator.

    The watcher runs in a background daemon thread (started via .start()).
    It calls evaluator.load_policy / evaluator.remove_policy as ConfigMaps
    appear / change / vanish.

    On any error in the watch loop we sleep `retry_seconds` and resume,
    rather than crashing the pod. K8s watch semantics already handle
    bookmark resumption; if the resourceVersion expires (HTTP 410) the
    next list() will rebuild the cache.
    """

    def __init__(
        self,
        evaluator: CedarEvaluator,
        namespace: Optional[str] = None,
        retry_seconds: float = 5.0,
        in_cluster: Optional[bool] = None,
    ) -> None:
        self._evaluator = evaluator
        self._namespace = namespace or os.environ.get("PDP_NAMESPACE", "modaas-system")
        self._retry_seconds = retry_seconds
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._in_cluster = in_cluster

    # --- lifecycle --------------------------------------------------------

    def start(self) -> None:
        """Load kube-config and spawn the watch thread (idempotent)."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._load_kubeconfig()
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="modaas-pdp-policy-watcher", daemon=True,
        )
        self._thread.start()
        log.info("policy watcher started namespace=%s", self._namespace)

    def stop(self, join_timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=join_timeout)

    def _load_kubeconfig(self) -> None:
        # Allow tests to skip k8s init by passing in_cluster=False explicitly.
        if self._in_cluster is False:
            return
        try:
            k8s_config.load_incluster_config()
            log.info("using in-cluster kubeconfig")
            return
        except Exception:
            pass
        # Fallback for local dev (kubectl context).
        k8s_config.load_kube_config()
        log.info("using local kubeconfig")

    # --- list/watch loop --------------------------------------------------

    def _run(self) -> None:
        api = k8s_client.CoreV1Api()
        label_selector = f"{POLICY_LABEL_KEY}={POLICY_LABEL_VALUE}"

        while not self._stop.is_set():
            try:
                # Bootstrap: list all matching ConfigMaps so the evaluator
                # has the full snapshot before we start watching.
                snapshot = api.list_namespaced_config_map(
                    namespace=self._namespace,
                    label_selector=label_selector,
                )
                seen: set[str] = set()
                for cm in snapshot.items:
                    pid = self._handle_upsert(cm)
                    if pid:
                        seen.add(pid)
                # Drop any locally cached policies the cluster no longer
                # has — this catches deletes that happened while we were
                # disconnected.
                for known in self._evaluator.loaded_policy_ids():
                    if known not in seen:
                        log.info("reaping stale policy_id=%s (not in snapshot)", known)
                        self._evaluator.remove_policy(known)

                # Now stream changes.
                resource_version = snapshot.metadata.resource_version
                self._watch_stream(api, label_selector, resource_version)
            except Exception as exc:
                log.warning(
                    "watch loop crashed namespace=%s err=%s — sleeping %.1fs",
                    self._namespace, exc, self._retry_seconds,
                )
                if self._stop.wait(self._retry_seconds):
                    return

    def _watch_stream(
        self,
        api: k8s_client.CoreV1Api,
        label_selector: str,
        resource_version: str,
    ) -> None:
        w = k8s_watch.Watch()
        try:
            for evt in w.stream(
                api.list_namespaced_config_map,
                namespace=self._namespace,
                label_selector=label_selector,
                resource_version=resource_version,
                timeout_seconds=600,
            ):
                if self._stop.is_set():
                    w.stop()
                    return
                etype = evt.get("type")
                obj = evt.get("object")
                if obj is None:
                    continue
                if etype in ("ADDED", "MODIFIED"):
                    self._handle_upsert(obj)
                elif etype == "DELETED":
                    self._handle_delete(obj)
        finally:
            w.stop()

    # --- per-event handlers ----------------------------------------------

    def _policy_id_for(self, cm: k8s_client.V1ConfigMap) -> str:
        annotations = (cm.metadata.annotations or {}) if cm.metadata else {}
        explicit = annotations.get(POLICY_ID_ANNOTATION)
        if explicit:
            return explicit
        return cm.metadata.name if cm.metadata else "unknown"

    def _handle_upsert(self, cm: k8s_client.V1ConfigMap) -> Optional[str]:
        if cm.metadata is None or cm.data is None:
            return None
        text = cm.data.get(POLICY_DATA_KEY)
        if not text:
            log.warning(
                "ConfigMap %s/%s has label but no '%s' key — ignored",
                self._namespace, cm.metadata.name, POLICY_DATA_KEY,
            )
            return None
        policy_id = self._policy_id_for(cm)
        version = cm.metadata.resource_version or ""
        try:
            self._evaluator.load_policy(policy_id, text, version=version)
            return policy_id
        except PolicyParseError as exc:
            # a design note: keep last-good policy, log the failure.
            log.error(
                "policy_id=%s parse failed at version=%s — keeping last-good: %s",
                policy_id, version, exc,
            )
            return policy_id if self._evaluator.has_policy(policy_id) else None

    def _handle_delete(self, cm: k8s_client.V1ConfigMap) -> None:
        if cm.metadata is None:
            return
        policy_id = self._policy_id_for(cm)
        self._evaluator.remove_policy(policy_id)
