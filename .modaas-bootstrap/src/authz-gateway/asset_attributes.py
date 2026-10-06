"""D4 — resource attributes come from the governed CR, never from the caller.

Defect this module closes (found while promoting a design note's identity hook, a hardening note):
`app.py` sourced `dataClassification` from the `x-modaas-data-class` REQUEST
HEADER. A caller-supplied header deciding a caller's own authorization is a
privilege-escalation primitive: present `internal` and a policy written to admit
only `internal` data admits you. It was masked, not safe -- the hook never
forwarded the header, so the attribute was always absent and any policy reading
it without a `has` guard errored to 403. The demo policy got a `has` guard as a
stopgap; this module removes the header as an input entirely.

The truth is `ToolConfig.spec.governance.dataClassification` (or the ModelConfig
equivalent), which only a governance operator with write access to the CR can
change.

Failure stance (matches the api-key store precedent in keycloak_identity.py):
an UNREACHABLE CR store raises, and app.py refuses -- deciding a governed call
on attributes we could not read is the defect class this service exists to
eliminate. A CR that simply does not DECLARE a classification is not a failure:
it returns "" and the attribute is omitted, which is the same shape as an asset
whose governance block is empty.

Read path is raw httpx against the in-cluster API with the Pod's SA token --
the same dependency-free pattern `_fetch_agw_keys` already uses, so this adds no
new client library to the doorman's hot path.
"""
import dataclasses
import logging
import os
import threading
import time as _time
from collections import OrderedDict

logger = logging.getLogger("authz.asset_attributes")


@dataclasses.dataclass(frozen=True)
class AssetFacts:
    """What one governed CR tells us, read in ONE API call.

    `registry_record_id` joined this module (a design note point 4/7) rather than
    getting its own read: it comes from the SAME object as the classification
    (`status.registryRecordId` beside `spec.governance.dataClassification`), and
    a second GET on the hot path for a field used only in the evidence record
    would be a measurable latency cost for an audit field.

    Empty strings, never None, so a caller can put the value straight into a
    decide request or a record without a None check -- and so "the CR declares
    none" and "we could not read" stay distinguishable: the second raises.

    `exists` is a THIRD fact from the same read: False only when the CR store
    answered 404 (the asset is not governed here). It defaults True so an
    off-cluster or unknown-resource-type read -- which cannot forge an answer --
    is treated as present, and so every positional `AssetFacts("x", "y")`
    construction keeps its meaning. A caller that must FAIL CLOSED on a missing
    asset (the cross-tool path in app.py) checks it; the ordinary paths ignore
    it, so their behaviour is unchanged. It is NOT the same as a declared-but-
    empty classification: a governed CR that declares no data class still
    exists.
    """

    data_classification: str = ""
    registry_record_id: str = ""
    exists: bool = True

_GROUP = "oda.tmforum.org"
_VERSION = "v1beta1"
_PLURAL_BY_RESOURCE_TYPE = {
    "Tool": "toolconfigs",
    "Model": "modelconfigs",
}

_TTL_S = 60
_MAX_ENTRIES = 512

_lock = threading.Lock()
# alias -> (fetched_at, AssetFacts). Bounded LRU: an unbounded dict keyed by
# caller-influenced alias is a memory-growth primitive (the same finding that
# produced the registry cache TTL fix).
_cache: "OrderedDict[tuple[str, str], tuple[float, AssetFacts]]" = OrderedDict()


class AssetStoreUnavailable(Exception):
    """The CR store could not be read. Caller must refuse, not guess."""


_SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
_disabled_logged = False


def _cache_clear() -> None:
    with _lock:
        _cache.clear()


def _namespace() -> str:
    return os.environ.get("MODAAS_ASSET_NAMESPACE", "components")


def _in_cluster() -> bool:
    """Is there a projected ServiceAccount token, i.e. are we a Pod?

    This distinction matters and is not pedantry. Two different conditions were
    initially collapsed into one:

      * NOT IN A CLUSTER (no token file): there is no CR store to read, because
        this process is a test runner or a laptop. Refusing every call here would
        make the doorman unrunnable outside Kubernetes, which is a worse outcome
        than omitting one attribute -- and omission cannot forge anything, which
        is the property D4 exists to establish.
      * IN A CLUSTER, READ FAILED (RBAC denied, API unreachable, garbage body):
        a governed call would be decided on attributes we could not read. That
        refuses, loudly. This is the case the api-key store precedent covers.

    The token file is always projected into a Pod, so its absence is a reliable
    signal of the first condition, not a symptom of the second.
    """
    return os.path.exists(_SA_TOKEN_PATH)


def _read_token() -> str:
    """The Pod's projected ServiceAccount token.

    Its own function so a test can supply one without faking the filesystem --
    the alternative is a test that must exist inside a cluster to exercise the
    read path at all.
    """
    try:
        return open(_SA_TOKEN_PATH).read()
    except OSError as exc:
        raise AssetStoreUnavailable(f"no service account token: {exc}") from exc


def _fetch_asset(plural: str, alias: str) -> AssetFacts:
    """ONE GET, both facts. See `AssetFacts` for why they share a read."""
    import httpx

    ns = _namespace()
    token = _read_token()

    url = (
        f"https://kubernetes.default.svc/apis/{_GROUP}/{_VERSION}"
        f"/namespaces/{ns}/{plural}/{alias}"
    )
    try:
        resp = httpx.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            verify="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            timeout=3.0,
        )
    except Exception as exc:  # noqa: BLE001 -- any transport failure is unavailable
        raise AssetStoreUnavailable(f"{plural}/{alias}: {exc}") from exc

    if resp.status_code == 404:
        # The asset is not governed here. Not an error: policy projection would
        # not have produced permits for it either, so the decide will DENY on
        # its own merits rather than on a fabricated attribute.
        logger.info("asset %s/%s not found in %s", plural, alias, ns)
        return AssetFacts(exists=False)
    if resp.status_code in (401, 403):
        raise AssetStoreUnavailable(
            f"{plural}/{alias}: RBAC denied ({resp.status_code}) -- the authz "
            "ServiceAccount needs get on {plural}"
        )
    if resp.status_code >= 400:
        raise AssetStoreUnavailable(f"{plural}/{alias}: HTTP {resp.status_code}")

    try:
        body = resp.json() or {}
    except ValueError as exc:
        raise AssetStoreUnavailable(f"{plural}/{alias}: non-JSON body") from exc
    spec = body.get("spec") or {}
    status = body.get("status") or {}
    return AssetFacts(
        data_classification=str(
            ((spec.get("governance") or {}).get("dataClassification")) or ""
        ),
        # `status.registryRecordId` is declared on all three governed-asset CRDs
        # (crds/{model,tool,agent}config-v1beta1-crd.yaml). A CR whose Registry
        # projection has not landed yet simply has none, and the evidence record
        # omits the field rather than carrying an empty one.
        registry_record_id=str(status.get("registryRecordId") or ""),
    )


def data_classification(resource_type: str, alias: str) -> str:
    """Classification declared by the governed CR, or "" if it declares none.

    Raises AssetStoreUnavailable when the store could not be read.

    Still returns a BARE STRING: its callers put the value straight into a Cedar
    decide request, and widening the return type to `AssetFacts` would have
    changed the decide payload silently. `asset_facts()` is the wider read.
    """
    return asset_facts(resource_type, alias).data_classification


def asset_facts(resource_type: str, alias: str) -> AssetFacts:
    """Everything one governed CR tells this service, from one cached read.

    Raises AssetStoreUnavailable when the store could not be read -- D4's stance,
    unchanged: deciding a governed call on attributes we could not read is the
    defect class this service exists to eliminate, and the registry record id
    riding along must not soften that to a warning.
    """
    plural = _PLURAL_BY_RESOURCE_TYPE.get(resource_type)
    if not plural or not alias:
        return AssetFacts()

    if not _in_cluster():
        global _disabled_logged
        if not _disabled_logged:
            logger.warning(
                "no ServiceAccount token at %s -- not running in a cluster, so "
                "resource classification cannot be resolved and is omitted from "
                "decide requests. Policies reading resource.dataClassification "
                "must use a `has` guard.",
                _SA_TOKEN_PATH,
            )
            _disabled_logged = True
        return AssetFacts()

    key = (plural, alias)
    now = _time.monotonic()
    with _lock:
        hit = _cache.get(key)
        if hit is not None and now - hit[0] < _TTL_S:
            _cache.move_to_end(key)
            return hit[1]

    value = _fetch_asset(plural, alias)

    with _lock:
        _cache[key] = (now, value)
        _cache.move_to_end(key)
        while len(_cache) > _MAX_ENTRIES:
            _cache.popitem(last=False)
    return value
