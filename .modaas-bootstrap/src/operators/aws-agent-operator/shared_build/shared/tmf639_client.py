"""TMF639 v5 Resource Inventory Management client for MoDaaS.

Provides a thin adapter for operators to project ModelConfig/ToolConfig/AgentConfig
CRs into the TMF639 Resource Inventory API served by canvas-resource-inventory
in the `canvas` namespace.

Per a design note (2026-05-04), MoDaaS operators now DUAL-WRITE: each asset becomes
* a record in AWS AgentCore Registry (existing) — for AWS-native consumers
* a TMF639 Resource (new) — for TMF-compliant consumers

Canvas deploys Resource Inventory v5 at:
  http://resource-inventory.canvas.svc.cluster.local/tmf-api/resourceInventoryManagement/v5

Resources we write:
  POST /resource
  PATCH /resource/{id}
  DELETE /resource/{id}

Resource shape — we map MoDaaS fields to TMF639 v5 Resource:
  resourceSpecification.category = "Model" | "Tool" | "Agent"
  resourceSpecification.name     = <alias>
  resourceCharacteristic[]       = our governance metadata as key/value chars
  operationalState               = "enabled" | "disabled" (from phase)
  resourceStatus                 = phase (Pending/Approved/Paused/Retired)

If the TMF639 endpoint is unreachable, operations log + raise TMF639Unreachable.
Dual-write is best-effort — failure to write TMF639 does NOT block AgentCore
Registry write (AWS Registry remains authoritative for AWS-native flows).
"""
import json
import logging
import os
import urllib.request
import urllib.error

logger = logging.getLogger("TMF639Client")

TMF639_BASE_URL = os.environ.get(
    "TMF639_BASE_URL",
    "http://resource-inventory.canvas.svc.cluster.local/tmf-api/resourceInventoryManagement/v5"
)
TMF639_TIMEOUT = int(os.environ.get("TMF639_TIMEOUT", "10"))


class TMF639Unreachable(Exception):
    """Raised when TMF639 endpoint is unreachable or returns 5xx."""


class TMF639ReadOnlyEndpoint(TMF639Unreachable):
    """Raised when endpoint accepts reads but rejects writes (HTTP 405).

    This is the normal condition in Canvas ODA 1.2.x where Resource
    Inventory v5 is populated by Canvas itself, not by external producers.
    External producers should use TMF630 event notifications instead.
    """


class TMF639Client:
    """Writes CRD state to TMF639 v5 Resource Inventory.

    One instance per operator; safe to reuse across reconciles.
    """

    def __init__(self, base_url: str = None, timeout: int = None):
        self.base_url = (base_url or TMF639_BASE_URL).rstrip("/")
        self.timeout = timeout or TMF639_TIMEOUT

    # ------------------------------------------------------------------ #
    # Public API — operators call these                                  #
    # ------------------------------------------------------------------ #
    def upsert_asset(
        self,
        asset_type: str,   # "Model" | "Tool" | "Agent"
        asset_name: str,   # alias (e.g. "claude-sonnet45-smoke")
        provider: str,     # e.g. "aws-bedrock"
        phase: str,        # "Pending" | "Approved" | "Paused" | "Retired"
        governance: dict,  # {dataClassification, owner, costCenter, ...}
        metadata: dict,    # additional free-form metadata from the operator
    ) -> dict:
        """Create or update the TMF639 Resource representing this asset.

        TMF639 does not have native upsert — we:
          1. Search by externalId (our CR's registryRecordId-like key)
          2. If exists → PATCH; else → POST

        NOTE: Canvas ODA 1.2.x deploys Resource Inventory v5 as a read-only
        API from external producers' perspective — it rejects direct POST
        (405 Method Not Allowed). The canonical write path is TMF630 Events
        via /hub (greenfield; not yet implemented).

        HONESTY: this method does NOT fabricate a stub ID on 405. It raises
        TMF639ReadOnlyEndpoint, which the operator's reconcile loop catches
        and records as condition TMF639Projected=False/reason=TMF639ReadOnly.
        The truthful state — "Canvas inventory is read-only to direct POST;
        projection pending the TMF630 /hub event path (a design note)" — must be
        observable in `kubectl describe`. A stub success would falsely read
        as "projected" and is therefore not returned (see AGENTS.md Coherence
        Rule 19 — emit-without-truth is a contract violation).

        Returns the Resource dict (with id) on a real POST/PATCH success.
        Raises TMF639ReadOnlyEndpoint on 405 (read-only Canvas inventory),
        or TMF639Unreachable on outage / other 5xx.
        """
        external_id = f"{provider}_{asset_name}"
        resource_body = self._build_resource(
            asset_type=asset_type,
            asset_name=asset_name,
            provider=provider,
            phase=phase,
            governance=governance,
            metadata=metadata,
            external_id=external_id,
        )

        existing = self._find_by_external_id(external_id)
        if existing:
            return self._patch_resource(existing["id"], resource_body)
        return self._post_resource(resource_body)

    def delete_asset(self, asset_name: str, provider: str) -> bool:
        """Best-effort delete by externalId. Returns True if deleted, False if not found."""
        external_id = f"{provider}_{asset_name}"
        existing = self._find_by_external_id(external_id)
        if not existing:
            return False
        try:
            self._http("DELETE", f"/resource/{existing['id']}")
            return True
        except TMF639Unreachable:
            return False

    def list_assets(self, asset_type: str = None) -> list:
        """List TMF639 Resources, optionally filtered by category.

        Used for orphan-scan (Workstream C).
        """
        query = f"?resourceSpecification.category={asset_type}" if asset_type else ""
        try:
            resp = self._http("GET", f"/resource{query}")
            return resp if isinstance(resp, list) else []
        except TMF639Unreachable:
            return []

    # ------------------------------------------------------------------ #
    # Internals                                                          #
    # ------------------------------------------------------------------ #
    def _build_resource(
        self, asset_type, asset_name, provider, phase, governance, metadata, external_id
    ) -> dict:
        """Map MoDaaS fields into a TMF639 v5 Resource."""
        # PF05: Lifecycle phase fidelity — distinct resourceStatus per phase
        phase_map = {
            "Approved":   ("enabled",  "approved"),
            "Paused":     ("disabled", "paused"),
            "Retired":    ("disabled", "retired"),
            "Deprecated": ("disabled", "deprecated"),
            "Pending":    ("disabled", "pending"),
            "Validating": ("disabled", "pending"),
            "Failed":     ("disabled", "failed"),
        }
        op_state, res_status = phase_map.get(phase, ("disabled", "unknown"))

        chars = [
            {"name": "provider", "value": provider, "valueType": "string"},
            {"name": "phase", "value": phase, "valueType": "string"},
        ]
        for k, v in (governance or {}).items():
            if v is not None:
                chars.append({"name": f"governance.{k}", "value": str(v), "valueType": "string"})

        # PF03 + PF04: typed metadata emission with structured group expansion
        for k, v in (metadata or {}).items():
            if v is None:
                continue
            # PF04: Structured groups (safetyAttestation, componentRef)
            if k in ("safetyAttestation", "componentRef") and isinstance(v, dict):
                for sub_k, sub_v in v.items():
                    char = self._emit_char(f"{k}.{sub_k}", sub_v)
                    if char:
                        chars.append(char)
                continue
            # PF03: Typed scalar emission
            if isinstance(v, (str, int, float, bool)):
                char = self._emit_char(k, v)
                if char:
                    chars.append(char)

        return {
            "@type": "LogicalResource",
            "name": asset_name,
            "category": asset_type,
            "description": f"MoDaaS-governed {asset_type}: {asset_name}",
            "resourceStatus": res_status,
            "operationalState": op_state,
            "externalIdentifier": [{"externalIdentifierType": "modaas-registry-key", "id": external_id}],
            "resourceCharacteristic": chars,
            "resourceSpecification": {
                "@type": "ResourceSpecificationRef",
                "name": f"MoDaaS-{asset_type}",
                "category": asset_type,
            },
        }

    @staticmethod
    def _emit_char(name: str, value) -> dict | None:
        """PF03: Emit a typed resourceCharacteristic preserving native types."""
        if isinstance(value, bool):
            return {"name": name, "value": value, "valueType": "boolean"}
        if isinstance(value, int):
            return {"name": name, "value": value, "valueType": "integer"}
        if isinstance(value, float):
            return {"name": name, "value": value, "valueType": "number"}
        if isinstance(value, str):
            return {"name": name, "value": value, "valueType": "string"}
        return None  # complex types not emitted as flat chars

    def _find_by_external_id(self, external_id: str) -> dict | None:
        """Returns the Resource dict if one exists with matching externalIdentifier.id."""
        try:
            all_resources = self._http("GET", "/resource")
        except TMF639Unreachable:
            return None
        if not isinstance(all_resources, list):
            return None
        for r in all_resources:
            for ext in r.get("externalIdentifier", []) or []:
                if ext.get("id") == external_id:
                    return r
        return None

    def _post_resource(self, body: dict) -> dict:
        return self._http("POST", "/resource", body) or {}

    def _patch_resource(self, resource_id: str, body: dict) -> dict:
        return self._http("PATCH", f"/resource/{resource_id}", body) or {}

    def _http(self, method: str, path: str, body: dict = None) -> dict | list | None:
        url = f"{self.base_url}{path}"
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = resp.read()
                if not payload:
                    return None
                try:
                    return json.loads(payload)
                except json.JSONDecodeError:
                    return None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code == 405:
                # Canvas Resource Inventory v5 serves reads but not writes —
                # surface distinct exception so operators record a clear
                # TMF639ReadOnlyEndpoint condition.
                logger.info("TMF639 %s %s → HTTP 405 (read-only endpoint)", method, path)
                raise TMF639ReadOnlyEndpoint(
                    f"{method} {path} → 405 Method Not Allowed "
                    "(Canvas Resource Inventory v5 is read-only; "
                    "use TMF630 event hub for write projection)"
                )
            logger.warning("TMF639 %s %s → HTTP %s %s", method, path, e.code, e.reason)
            raise TMF639Unreachable(f"{method} {path} → {e.code}")
        except urllib.error.URLError as e:
            logger.warning("TMF639 %s %s → URLError %s", method, path, e.reason)
            raise TMF639Unreachable(f"{method} {path} → {e.reason}")
        except Exception as e:
            logger.warning("TMF639 %s %s → %s", method, path, e)
            raise TMF639Unreachable(f"{method} {path} → {e}")
