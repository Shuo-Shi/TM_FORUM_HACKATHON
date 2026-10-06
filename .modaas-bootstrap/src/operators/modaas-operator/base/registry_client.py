"""AWS Agent Registry client for MoDaaS v2.

Wraps bedrock-agentcore-control registry APIs. Record name scheme:
  <kind>_<provider>_<name>     e.g.  model_aws-bedrock_claude-sonnet45-smoke

This unifies v1's three different naming patterns:
  v1: aws-bedrock_<alias>        (ModelConfig)
      agentcoregateway_<name>    (ToolConfig)
      kubernetes_<name>          (AgentConfig)
  v2: <kind>_<provider>_<name>   (all kinds)

Search by kind becomes trivial."""

import json
import logging
import os
import re

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("base.registry")


# Pattern for registry record names — matches what AWS accepts AND what our
# v2alpha1 CRD status.registryRecordId validates.
#   <kind>_<provider>_<name>
#   each segment: lowercase letter followed by [a-z0-9-]*
_RECORD_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]*_[a-z][a-z0-9-]*_[a-z][a-z0-9-]*$")


def _sanitize_segment(segment: str) -> str:
    """Normalize to lowercase + replace underscores and disallowed chars with
    hyphens so the segment fits the registry name pattern."""
    s = segment.lower().replace("_", "-")
    s = re.sub(r"[^a-z0-9-]", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    if not s or not s[0].isalpha():
        s = "x-" + s
    return s


def build_record_name(kind: str, provider: str, name: str) -> str:
    """Build a registry record name and validate against the CRD pattern."""
    record_name = f"{_sanitize_segment(kind)}_{_sanitize_segment(provider)}_{_sanitize_segment(name)}"
    if not _RECORD_NAME_PATTERN.match(record_name):
        raise ValueError(f"constructed record name does not match pattern: {record_name}")
    return record_name


class RegistryClient:
    """AWS Agent Registry client (bedrock-agentcore-control).

    Singleton per region. One registry per region for v2.0."""

    def __init__(self, region: str | None = None):
        self._region = region or os.environ.get("AWS_REGION", "us-west-2")
        self._client = boto3.client("bedrock-agentcore-control", region_name=self._region)
        self._registry_id = os.environ.get("REGISTRY_ID", "gvwfzhizslOETJSk")

    def put_record(self, record: dict) -> dict:
        """Create or update a registry record. If a record of the same name
        already exists APPROVED, submit a new revision."""
        name = record["name"]

        # Does a record of this name already exist?
        existing = self._find_record_by_name(name)
        if existing is None:
            # Create (DRAFT) then submit for approval (APPROVED)
            body = dict(record)
            resp = self._client.create_registry_record(
                registryId=self._registry_id,
                name=body.pop("name"),
                description=body.pop("description", ""),
                descriptorType=body.pop("descriptorType", "CUSTOM"),
                descriptors=body.pop("descriptors"),
            )
            record_id = self._parse_record_id(resp)
            self._wait_for_state(record_id, wanted={"DRAFT", "APPROVED"})
            try:
                self._client.submit_registry_record_for_approval(
                    registryId=self._registry_id,
                    recordId=record_id,
                )
            except self._client.exceptions.ConflictException as ce:
                # Already APPROVED (race) or similar — log and continue
                logger.info(f"submit_for_approval conflict on {record_id}: {ce}")
            logger.info(f"registered new record {name} (id={record_id}) APPROVED")
            return {"recordId": record_id, "name": name, "status": "APPROVED"}
        else:
            # Update-in-place: new revision
            record_id = existing["recordId"]
            body = dict(record)
            self._client.update_registry_record(
                registryId=self._registry_id,
                recordId=record_id,
                description=body.get("description", ""),
                descriptors=body.get("descriptors"),
            )
            self._wait_for_state(record_id, wanted={"DRAFT", "APPROVED"})
            try:
                self._client.submit_registry_record_for_approval(
                    registryId=self._registry_id,
                    recordId=record_id,
                )
            except self._client.exceptions.ConflictException as ce:
                logger.info(f"submit_for_approval conflict on {record_id}: {ce}")
            logger.info(f"updated record {name} (id={record_id}) APPROVED")
            return {"recordId": record_id, "name": name, "status": "APPROVED"}

    @staticmethod
    def _parse_record_id(resp: dict) -> str:
        """Extract recordId from a create/update response.

        The AgentCore-control API returns recordArn but not always recordId
        as a top-level field. Parse from ARN tail:
          arn:aws:bedrock-agentcore:REGION:ACCOUNT:registry/REGISTRY_ID/record/RECORD_ID
        """
        if "recordId" in resp:
            return resp["recordId"]
        arn = resp.get("recordArn", "")
        if "/record/" in arn:
            return arn.rsplit("/record/", 1)[-1]
        raise ValueError(f"cannot parse recordId from response: {resp}")

    def _wait_for_state(self, record_id: str, wanted: set[str],
                        timeout_s: int = 30, poll_interval_s: float = 1.0) -> None:
        """Poll get_registry_record until status is in `wanted`.

        Newly-created records enter CREATING state; submit-for-approval
        requires DRAFT. Typical transition time is 1-3 seconds."""
        import time
        deadline = time.time() + timeout_s
        last_status = "UNKNOWN"
        while time.time() < deadline:
            try:
                resp = self._client.get_registry_record(
                    registryId=self._registry_id,
                    recordId=record_id,
                )
                last_status = resp.get("status", "UNKNOWN")
                if last_status in wanted:
                    return
            except ClientError as e:
                logger.warning(f"get_registry_record during wait failed: {e}")
            time.sleep(poll_interval_s)
        logger.warning(
            f"registry record {record_id} still in state {last_status} after {timeout_s}s; "
            f"proceeding anyway"
        )

    def deprecate(self, record_name: str) -> None:
        """Mark a record DEPRECATED (retirement cascade)."""
        existing = self._find_record_by_name(record_name)
        if existing is None:
            logger.warning(f"cannot deprecate {record_name}: not found")
            return
        try:
            self._client.update_registry_record_status(
                registryId=self._registry_id,
                recordId=existing["recordId"],
                status="DEPRECATED",
            )
            logger.info(f"deprecated record {record_name}")
        except ClientError as e:
            logger.warning(f"deprecate({record_name}) failed: {e}")

    def get_record_full(self, record_name: str) -> dict | None:
        """Fetch full record body (descriptors + inlineContent). Returns None
        if not found. Used by downstream resolvers (e.g., agent looking up
        model's resolvedModelId)."""
        existing = self._find_record_by_name(record_name)
        if existing is None:
            return None
        try:
            return self._client.get_registry_record(
                registryId=self._registry_id,
                recordId=existing["recordId"],
            )
        except ClientError as e:
            logger.warning(f"get_registry_record({record_name}) failed: {e}")
            return None

    def _find_record_by_name(self, record_name: str) -> dict | None:
        """Lookup record summary by name. Returns None if not found.

        list_registry_records returns summaries only (no descriptors); callers
        needing the full body should follow up with get_record_full()."""
        try:
            resp = self._client.list_registry_records(registryId=self._registry_id)
            for r in resp.get("registryRecords", []) or []:
                if r.get("name") == record_name and r.get("status") == "APPROVED":
                    return r
            return None
        except ClientError as e:
            logger.warning(f"list_registry_records failed: {e}")
            return None


def build_registry_record(
    kind: str,
    provider: str,
    name: str,
    description: str,
    governance: dict,
    plugin_metadata: dict,
) -> dict:
    """Build the record body the operator writes.

    inlineContent is JSON-encoded (registry stores as string). It contains:
      - kind + provider (first-class search filters)
      - governance (owner, costCenter, dataClass, retirement)
      - tmf639 metadata for ODA compatibility
      - provider-specific metadata from the plugin
    """
    record_name = build_record_name(kind, provider, name)

    inline = {
        "kind": kind,
        "provider": provider,
        "governance": governance,
        "tmf639": {
            "lifecycleState": "active",
            "resourceSpecCharacteristic": [
                {"name": "kind", "value": kind},
                {"name": "provider", "value": provider},
            ],
        },
        "providerSpecific": plugin_metadata,
    }

    return {
        "name": record_name,
        "description": description or f"MoDaaS {kind} ({provider}) — {name}",
        "descriptorType": "CUSTOM",
        "descriptors": {
            "custom": {
                "inlineContent": json.dumps(inline, default=str),
            },
        },
    }
