#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""cluster-status Lambda tool -- read-only list of ModelConfig/ToolConfig/AgentConfig.

Lists CRs in namespace components with phase and conditions. Designed to run
as a Lambda behind AgentCore Gateway.

NOTE: A Lambda function cannot directly reach the Kubernetes API (it runs
outside the cluster). Two alternatives:
  1. A small in-cluster read endpoint (e.g. a pod that watches CRDs and
     serves a cached snapshot over HTTP). The Lambda calls this endpoint.
  2. The Lambda uses the EKS API (describe-cluster + token) to reach the
     Kubernetes API server's public endpoint.

This implementation uses alternative 2: it fetches the EKS cluster endpoint
and token via boto3, then queries the Kubernetes API. If the EKS endpoint is
not reachable from Lambda (private cluster), fall back to returning a static
snapshot or an error explaining the architecture.

Env:
  CLUSTER_NAME    EKS cluster name
  AWS_REGION      region
"""
import json
import os
import base64
import urllib.request
import ssl


CLUSTER_NAME = os.environ.get("CLUSTER_NAME", "")
NAMESPACE = "components"
CRD_KINDS = ["modelconfigs", "toolconfigs", "agentconfigs"]


def _get_cluster_info():
    """Return (endpoint, ca_data) from EKS describe-cluster."""
    import boto3
    client = boto3.client("eks", region_name=os.environ.get("AWS_REGION", "us-east-1"))
    resp = client.describe_cluster(name=CLUSTER_NAME)
    cluster = resp["cluster"]
    return cluster["endpoint"], cluster["certificateAuthority"]["data"]


def _get_token():
    """Generate a bearer token for the EKS cluster using STS."""
    import boto3
    from botocore.signers import RequestSigner
    sts = boto3.client("sts", region_name=os.environ.get("AWS_REGION", "us-east-1"))
    service_id = sts.meta.service_model.service_id
    signer = RequestSigner(service_id, os.environ.get("AWS_REGION", "us-east-1"),
                           "sts", "v4", sts._request_signer._credentials, sts.meta.events)
    params = {"method": "GET", "url": f"https://sts.{os.environ.get('AWS_REGION', 'us-east-1')}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
              "body": {}, "headers": {"x-k8s-aws-id": CLUSTER_NAME}, "context": {}}
    url = signer.generate_presigned_url(params, region_name=os.environ.get("AWS_REGION", "us-east-1"),
                                        expires_in=60, operation_name="")
    token = "k8s-aws-v1." + base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    return token


def _list_crs(endpoint, token, ca_data, kind):
    """List CRs of a given kind from the Kubernetes API."""
    url = f"{endpoint}/apis/oda.tmforum.org/v1beta1/namespaces/{NAMESPACE}/{kind}"
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cadata=base64.b64decode(ca_data).decode())
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
        return json.loads(r.read())


def handler(event, context):
    """Lambda handler: list ModelConfig/ToolConfig/AgentConfig with phase+conditions."""
    params = event.get("parameters") or event.get("arguments") or event
    action = params.get("action", "list")
    if action == "get":
        cr_kind = params.get("kind", "")
        cr_name = params.get("name", "")
        if not cr_kind or not cr_name:
            return {"error": "kind and name are required for get action"}
        return get_cr(cr_kind, cr_name)
    kind_filter = params.get("kind", "").lower()

    if not CLUSTER_NAME:
        return {"error": "CLUSTER_NAME environment variable not set"}

    try:
        endpoint, ca_data = _get_cluster_info()
        token = _get_token()
    except Exception as exc:
        return {"error": f"cannot reach EKS cluster: {exc}"}

    results = []
    for kind in CRD_KINDS:
        if kind_filter and kind_filter not in kind:
            continue
        try:
            data = _list_crs(endpoint, token, ca_data, kind)
            for item in data.get("items", []):
                status = item.get("status") or {}
                results.append({
                    "kind": kind.rstrip("s"),
                    "name": item["metadata"]["name"],
                    "phase": status.get("phase", "Unknown"),
                    "conditions": [
                        {"type": c.get("type"), "status": c.get("status"), "reason": c.get("reason", "")}
                        for c in (status.get("conditions") or [])
                    ],
                })
        except Exception as exc:
            results.append({"kind": kind, "error": str(exc)})

    return {"namespace": NAMESPACE, "resources": results, "count": len(results)}


def _get_cr(endpoint, token, ca_data, kind, name):
    """Get a single CR by kind and name, returning full spec and status."""
    kind_plural = kind.lower() + "s"
    url = f"{endpoint}/apis/oda.tmforum.org/v1beta1/namespaces/{NAMESPACE}/{kind_plural}/{name}"
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cadata=base64.b64decode(ca_data).decode())
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
        return json.loads(r.read())


def get_cr(kind, name):
    """Retrieve a single CR with its live YAML including status."""
    if not CLUSTER_NAME:
        return {"error": "CLUSTER_NAME environment variable not set"}
    try:
        endpoint, ca_data = _get_cluster_info()
        token = _get_token()
    except Exception as exc:
        return {"error": f"cannot reach EKS cluster: {exc}"}
    try:
        item = _get_cr(endpoint, token, ca_data, kind, name)
        return {
            "kind": kind,
            "name": name,
            "apiVersion": item.get("apiVersion", ""),
            "metadata": item.get("metadata", {}),
            "spec": item.get("spec", {}),
            "status": item.get("status", {}),
        }
    except Exception as exc:
        return {"error": f"get {kind}/{name} failed: {exc}"}
