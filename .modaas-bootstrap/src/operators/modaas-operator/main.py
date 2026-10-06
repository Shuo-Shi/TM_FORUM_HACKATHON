"""MoDaaS v2 operator — single binary, plugin-driven AssetConfig reconciler.

Replaces v1's three operator binaries (aws-model-operator, aws-tool-operator,
aws-agent-operator). Kind+provider dispatch lives in providers/registry.py;
plugins self-register at import time."""

import logging
import os

import kopf

from base.k8s_client import GROUP, V2_VERSION, ASSETCONFIGS_PLURAL
from base import reconcile_loop

# Import plugins — side effect: @register registers each class
#   Model plugins
from providers.model import aws_bedrock as _  # noqa: F401
#   Tool plugins
from providers.tool import agent_core_gateway as _  # noqa: F401
#   Agent plugins
from providers.agent import aws_agent_core as _  # noqa: F401
from providers.agent import kubernetes as _  # noqa: F401
#   Memory plugins (new asset kind)
from providers.memory import aws_agent_core_memory as _  # noqa: F401

from providers import registry

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("modaas-operator")


@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    settings.watching.server_timeout = 60
    settings.persistence.finalizer = f"{GROUP}/assetconfig-finalizer"
    logger.info("=" * 60)
    logger.info("MoDaaS v2 operator starting")
    logger.info(f"  Watching: {ASSETCONFIGS_PLURAL}.{GROUP}/{V2_VERSION}")
    logger.info(f"  Registered plugins:")
    for kind, provider in registry.list_plugins():
        logger.info(f"    {kind:15s} / {provider}")
    logger.info("=" * 60)


@kopf.on.resume(GROUP, V2_VERSION, ASSETCONFIGS_PLURAL, retries=5)
@kopf.on.create(GROUP, V2_VERSION, ASSETCONFIGS_PLURAL, retries=5)
@kopf.on.update(GROUP, V2_VERSION, ASSETCONFIGS_PLURAL, retries=5)
def on_reconcile(spec, status, meta, namespace, name, patch, **kwargs):
    return reconcile_loop.reconcile(spec, status, meta, namespace, name, patch, **kwargs)


@kopf.on.delete(GROUP, V2_VERSION, ASSETCONFIGS_PLURAL)
def on_delete(spec, status, meta, namespace, name, **kwargs):
    return reconcile_loop.on_delete(spec, status, meta, namespace, name, **kwargs)
