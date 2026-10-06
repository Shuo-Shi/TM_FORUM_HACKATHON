"""a design note — SageMaker provider reconciler (onboard-only).

Mission: MoDaaS onboards EXISTING SageMaker endpoints. It does NOT create,
update, or delete them. The customer's ML platform team owns endpoint
deployment lifecycle (CDK / SageMaker Studio / MLOps pipeline). MoDaaS adds:
  - Validation that the endpoint exists and is InService
  - Governance metadata (provenance, capabilities) projected to Registry
  - Safety overlays via a design note bedrockGuardrailExternal
  - Drift detection: surface external endpoint changes as governance signals

IAM scope (small):
  - aws-model-operator IRSA: sagemaker:DescribeEndpoint, DescribeEndpointConfig
    (read-only control plane). NO PassRole.
  - dataplane IRSA: sagemaker:InvokeEndpoint scoped to specific endpoint ARN.
"""
import logging
from typing import Optional, Tuple

from botocore.exceptions import ClientError

logger = logging.getLogger("providers.sagemaker")

#: a design note capability id. Control plane only — NOT sagemaker-runtime, which the
#: dataplane reaches with its own IRSA identity.
SAGEMAKER_CAPABILITY = "sagemaker.control"


def _aws_clients():
    """The a design note capability factory. Three spellings resolve in this repo:
    `operators.shared.*` in-tree, `shared.*` in the pod snapshot, and the bare
    module when the operator directory is sys.path[0]. Canonical first so all
    three share ONE client cache."""
    try:
        from operators.shared import aws_clients  # noqa: PLC0415
    except ImportError:  # pragma: no cover - pod snapshot path
        from shared import aws_clients  # noqa: PLC0415
    return aws_clients


def _sagemaker(region: str, endpoint_url: Optional[str] = None):
    """Cached sagemaker (control-plane) client. NOT sagemaker-runtime.

    The per-(region, endpoint_url) cache this function held now lives in
    aws_clients, keyed on (capability, region, endpoint_url) — same shape, one
    implementation.
    """
    return _aws_clients().client(
        SAGEMAKER_CAPABILITY, region, endpoint_url=endpoint_url
    )


def _provisioning_failed(reason: str, message: str = ""):
    from asset_operator import ProvisioningFailed
    return ProvisioningFailed(reason, message or reason)


def _normalize_variant(v: dict) -> dict:
    return {
        "variantName": v.get("VariantName"),
        "modelName": v.get("ModelName"),
        "instanceType": v.get("InstanceType"),
        "initialInstanceCount": v.get("InitialInstanceCount"),
    }


def _capture_endpoint_config_snapshot(client, endpoint_config_name: str) -> dict:
    try:
        cfg = client.describe_endpoint_config(EndpointConfigName=endpoint_config_name)
    except ClientError as e:
        logger.warning(
            "describe_endpoint_config failed for %s: %s",
            endpoint_config_name, e.response["Error"]["Code"],
        )
        return {"endpointConfigName": endpoint_config_name, "productionVariants": []}
    return {
        "endpointConfigName": endpoint_config_name,
        "productionVariants": [_normalize_variant(v) for v in cfg.get("ProductionVariants", [])],
    }


def provision(spec: dict, status: dict) -> dict:
    """Validate the SageMaker endpoint exists + is InService.
    Returns status fields to merge into the ModelConfig.
    Raises ProvisioningFailed for onboard-only invariant violations.
    """
    awssm = spec["awsSageMaker"]
    region = awssm["region"]
    endpoint_name = awssm["endpointName"]
    declared_arn = awssm.get("endpointArn")

    client = _sagemaker(region)

    try:
        resp = client.describe_endpoint(EndpointName=endpoint_name)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"].get("Message", "")
        if code in ("ValidationException", "ResourceNotFound"):
            raise _provisioning_failed(
                "EndpointNotFound",
                f"SageMaker endpoint '{endpoint_name}' not found in {region}: {msg}",
            )
        if code in ("AccessDeniedException", "AccessDenied"):
            raise _provisioning_failed(
                "EndpointAccessDenied",
                f"Operator IAM lacks DescribeEndpoint on {endpoint_name}: {msg}",
            )
        raise _provisioning_failed("EndpointDescribeFailed", f"{code}: {msg}")

    actual_status = resp.get("EndpointStatus", "")
    actual_arn = resp.get("EndpointArn", "")
    actual_cfg_name = resp.get("EndpointConfigName", "")

    if declared_arn and declared_arn != actual_arn:
        raise _provisioning_failed(
            "EndpointArnMismatch",
            f"spec.awsSageMaker.endpointArn={declared_arn!r} but actual ARN is {actual_arn!r}; "
            "onboard-only identity violation",
        )

    if actual_status != "InService":
        raise _provisioning_failed(
            "EndpointNotInService",
            f"SageMaker endpoint '{endpoint_name}' status={actual_status} (expected InService)",
        )

    snapshot = _capture_endpoint_config_snapshot(client, actual_cfg_name)

    # a design note (2026-05-20) — status.endpoint semantic flip.
    # status.endpoint = MoDaaS Gateway URL with /sagemaker/endpoints/<alias>/invocations.
    # status.upstreamEndpoint = native SageMaker InvokeEndpoint URL (diagnostics only).
    # Agents MUST call status.endpoint to honor MoDaaS governance / a design note
    # enforcement — but this provider does NOT compute that URL. R1 fix
    # (dataplane cutover, 2026-09-01): this function used to build its own
    # gateway_endpoint from MODAAS_GATEWAY_URL defaulting to the RETIRED
    # dataplane host and return it as "endpoint"; the base class then merged
    # backend_status over patch.status AFTER compute_and_publish_perimeter_url
    # had written the correct agentgateway URL — silently clobbering it back
    # to a dead host. Coherence Rule 22 names this exact defect class:
    # provider-specific reconcile paths MUST leave perimeter-URL publication
    # to compute_and_publish_perimeter_url, the single writer.
    upstream_endpoint = (
        spec.get("endpoint")
        or f"https://runtime.sagemaker.{region}.amazonaws.com/endpoints/{endpoint_name}/invocations"
    )

    return {
        "resolvedModelId": endpoint_name,
        # "endpoint" intentionally ABSENT — see R1 note above.
        "upstreamEndpoint": upstream_endpoint,
        "endpointArn": actual_arn,
        "endpointStatus": actual_status,
        "endpointConfigSnapshot": snapshot,
        "provider": "aws-sagemaker",
    }


def deprovision(status: dict, region: str) -> None:
    """Onboard-only cleanup: do NOT delete the SageMaker endpoint."""
    logger.info(
        "SageMaker deprovision (onboard-only): no SageMaker resource changes for endpoint=%s",
        status.get("endpointName") or status.get("resolvedModelId") or "unknown",
    )


def detect_drift(spec: dict, status: dict) -> Tuple[bool, str]:
    """Compare current endpoint config to the snapshot. Returns (drifted, reason).
    Surfaces external changes as a status condition; does NOT auto-correct.
    """
    awssm = spec["awsSageMaker"]
    region = awssm["region"]
    endpoint_name = awssm["endpointName"]
    snapshot = status.get("endpointConfigSnapshot") or {}
    snapshot_cfg_name = snapshot.get("endpointConfigName")
    snapshot_variants = snapshot.get("productionVariants") or []

    client = _sagemaker(region)
    try:
        ep_resp = client.describe_endpoint(EndpointName=endpoint_name)
    except ClientError as e:
        return True, f"describe_endpoint failed: {e.response['Error']['Code']}"

    current_cfg_name = ep_resp.get("EndpointConfigName", "")
    if snapshot_cfg_name and current_cfg_name != snapshot_cfg_name:
        return True, (
            f"endpointConfigName changed: {snapshot_cfg_name!r} -> {current_cfg_name!r}"
        )

    current_snapshot = _capture_endpoint_config_snapshot(client, current_cfg_name)
    current_variants = current_snapshot.get("productionVariants") or []

    snapshot_by_name = {v["variantName"]: v for v in snapshot_variants if v.get("variantName")}
    current_by_name = {v["variantName"]: v for v in current_variants if v.get("variantName")}

    for vname, snap_v in snapshot_by_name.items():
        cur_v = current_by_name.get(vname)
        if cur_v is None:
            return True, f"variant {vname!r} removed"
        if snap_v.get("instanceType") != cur_v.get("instanceType"):
            return True, (
                f"variant {vname!r} instanceType changed: "
                f"{snap_v.get('instanceType')!r} -> {cur_v.get('instanceType')!r}"
            )
        if snap_v.get("initialInstanceCount") != cur_v.get("initialInstanceCount"):
            return True, (
                f"variant {vname!r} initialInstanceCount changed: "
                f"{snap_v.get('initialInstanceCount')} -> {cur_v.get('initialInstanceCount')}"
            )
        if snap_v.get("modelName") != cur_v.get("modelName"):
            return True, (
                f"variant {vname!r} modelName changed: "
                f"{snap_v.get('modelName')!r} -> {cur_v.get('modelName')!r}"
            )
    for vname in current_by_name.keys() - snapshot_by_name.keys():
        return True, f"variant {vname!r} added"

    return False, "no drift detected"
