"""The one network call in C2: resolve an access key to an AWS account (LC-4).

Separate from identity.py because this is the only part of C2 that can fail for
a reason unrelated to the caller -- and that distinction is the whole of AR-6.
Keeping it here means identity.py's tests need no AWS at all.

## What this proves, and what it does not

`sts:GetAccessKeyInfo` returns the account ID a key belongs to. Its own API
reference states: "This operation does not indicate the state of the access key.
The key might be active, inactive, or deleted. Active keys might not have
permissions to perform an operation."

So a successful lookup means an account was DERIVED. It does not mean the key is
live, and it does not mean the caller is entitled to anything. That is why the
level it yields is named ACCOUNT_RESOLVED rather than `verified`, and why
`sigv4_auth.py:145-147`'s claim that STS "will fail with InvalidClientTokenId for
fabricated keys" overstates what the check buys.

## Three bounds, each answering a finding

1. TTLCache with max-entries (SC-1b). The module this ports from uses plain
   dicts with no eviction and caches negatives, so probing fabricated keys grows
   memory without limit -- and the access key ID is the only input needed. This
   is a named, already-fixed bug class in this repo (AGENTS.md:227), with the
   remedy already in-tree at alias_resolver.py:25.

2. A sized ThreadPoolExecutor (PR-2a). boto3 is synchronous and neither aioboto3
   nor aiobotocore is installed, so a sync call in a FastAPI `def` endpoint runs
   on anyio's default thread limiter -- capacity 40, capping concurrent cold
   lookups regardless of MAX_IN_FLIGHT and invisibly to any per-call timing.

3. A TOTAL-elapsed bound from the request deadline (PR-2/AR-6a). botocore's
   retries are per-attempt: a `legacy` policy with max_attempts=5 plus backoff
   can outlive a per-call timeout several times over. `max_attempts` is set
   explicitly for the same reason.

## The residual this accepts

LRU eviction under a probe flood displaces LEGITIMATE entries, degrading real
callers to STRUCTURAL until they re-resolve. That is strictly better than
unbounded growth and it is not zero harm: an attacker can cause a governance
degradation without causing an outage. The mitigation is a generous maxsize,
which the memory arithmetic shows is nearly free (5000 entries ~ 1.9 MB against
37 MB of buffers).
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from typing import Any

from cachetools import TTLCache

import config
from deadline import Deadline
from identity import _Unreachable

log = logging.getLogger("authz-gateway.sts")

# Positives AND negatives in one bounded cache. Negatives are cached so a
# forged-key probe does not hammer STS on every attempt; a negative is stored as
# an empty dict so a cache hit is distinguishable from a miss.
_cache: TTLCache = TTLCache(maxsize=config.CACHE_MAX_ENTRIES, ttl=config.CACHE_TTL_S)

# Explicitly sized rather than inheriting anyio's 40. A request holding a slot
# here is already counted in MAX_IN_FLIGHT, so this adds no memory term beyond
# the thread stacks (~38 KB each).
_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=config.STS_EXECUTOR_SIZE, thread_name_prefix="sts"
)

_client = None


def _sts_client():
    """Cached module-level client. A client per call leaks HTTP connection pools
    -- a pattern this repo already recorded and fixed once."""
    global _client
    if _client is None:
        import boto3
        from botocore.config import Config

        _client = boto3.client(
            "sts",
            region_name=config.AWS_REGION,
            endpoint_url=config.STS_ENDPOINT_URL,   # regional, not global
            config=Config(
                # Both halves matter. Without an explicit connect/read timeout
                # botocore defaults to 60s, which cannot fit any request budget.
                connect_timeout=config.STS_TOTAL_BUDGET_S,
                read_timeout=config.STS_TOTAL_BUDGET_S,
                # And without capping attempts, a per-attempt timeout times five
                # retries plus backoff outlives the total bound anyway.
                retries={"max_attempts": config.STS_MAX_ATTEMPTS, "mode": "standard"},
            ),
        )
    return _client


def cache_stats() -> dict[str, int]:
    """For the span attributes and for tests asserting the bound holds."""
    return {"entries": len(_cache), "maxsize": _cache.maxsize}


def reset_for_tests() -> None:
    _cache.clear()


def _lookup_uncached(access_key: str, client=None) -> dict[str, Any] | None:
    """One STS call. Returns the account dict, None for a rejection, or raises
    _Unreachable for an outage -- the AR-5 vs AR-6 distinction."""
    from botocore.exceptions import ClientError

    c = client if client is not None else _sts_client()
    try:
        resp = c.get_access_key_info(AccessKeyId=access_key)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("InvalidClientTokenId", "AccessDenied", "ValidationError"):
            # A negative ANSWER about the caller -> AR-5 denies.
            log.info("sts rejected access key: %s", code)
            return None
        # 5xx / throttling: no answer either way -> AR-6 degrades.
        raise _Unreachable(f"sts error {code}") from exc
    except Exception as exc:                       # network, DNS, timeout
        raise _Unreachable(str(exc)) from exc

    account = resp.get("Account")
    return {"account": account} if account else None


# A distinct miss sentinel, because `None` and `{}` are both MEANINGFUL values
# here (no-entry vs cached-negative) and neither can serve as the default.
_MISS = object()


def _cached(access_key: str):
    """One dict lookup, not `in` followed by `[]`.

    `key in cache` then `cache[key]` reads the clock TWICE, and a TTLCache entry
    whose expiry falls between the two reads is reported present and then raises
    KeyError. Reproduced deterministically with an injected timer: `in` returned
    True, `[]` raised. It is a narrow window, but it lands on a LEGITIMATE
    caller at random and surfaces as a bare 500 -- the hook allows only on
    `is_success()` (ext_authz.rs:835), so the request is refused with no
    x-modaas-reason, which is NFR-7's opaque-failure case exactly.

    `Cache.get` is a single `__getitem__` in a try/except, so it cannot split.
    """
    return _cache.get(access_key, _MISS)


def resolve(access_key: str, deadline: Deadline, client=None) -> dict[str, Any] | None:
    """Blocking resolve. Kept for tests and for any sync caller.

    NOTE: an async caller must use `resolve_async` -- `future.result()` here
    blocks the calling thread, and on the event loop that serialises every
    concurrent lookup. See resolve_async's docstring for the measurement.
    """
    cached = _cached(access_key)
    if cached is not _MISS:
        return cached or None                       # {} is a cached negative

    budget = _budget(deadline)
    future = _executor.submit(_lookup_uncached, access_key, client)
    try:
        # TOTAL elapsed, measured from the request's arrival via the deadline --
        # so a request that queued for an executor slot has that wait counted
        # against it rather than reporting a fast call after a slow wait.
        result = future.result(timeout=budget)
    except concurrent.futures.TimeoutError as exc:
        future.cancel()
        raise _Unreachable(f"sts lookup exceeded its {budget * 1000:.0f}ms share") from exc

    return _store(access_key, result)


async def resolve_async(
    access_key: str, deadline: Deadline, client=None
) -> dict[str, Any] | None:
    """The path app.py uses. Same three bounds, without blocking the event loop.

    ## Why this exists -- measured, not reasoned about

    boto3 is synchronous, so `future.result()` blocks whatever thread calls it.
    Called from an `async def` endpoint that thread is the ONLY event loop
    thread, so the sized executor buys nothing: eight concurrent cold lookups of
    200 ms each took

        1629 ms   observed
        1600 ms   if fully serialised   <- what the loop being blocked looks like
         200 ms   if overlapped         <- what the executor was sized for

    With the loop blocked, MAX_IN_FLIGHT is a fiction -- requests cannot be
    in flight concurrently at all -- and STS_EXECUTOR_SIZE describes a capacity
    nothing can reach. Both knobs, and PR-2a's whole basis, depended on this.

    `run_in_executor` submits to the SAME executor, so the sizing still holds;
    what changes is that the loop keeps running while the thread waits.
    """
    cached = _cached(access_key)
    if cached is not _MISS:
        return cached or None

    budget = _budget(deadline)
    loop = asyncio.get_running_loop()
    fut = loop.run_in_executor(_executor, _lookup_uncached, access_key, client)
    try:
        result = await asyncio.wait_for(fut, timeout=budget)
    except (asyncio.TimeoutError, concurrent.futures.TimeoutError) as exc:
        # The wrapper is cancelled; the THREAD runs to completion either way --
        # a running thread cannot be interrupted, exactly as future.cancel()
        # cannot. The bound is on how long the REQUEST waits, which is the bound
        # PR-2 asks for.
        raise _Unreachable(f"sts lookup exceeded its {budget * 1000:.0f}ms share") from exc

    return _store(access_key, result)


def _budget(deadline: Deadline) -> float:
    budget = deadline.spend(cap_s=config.STS_TOTAL_BUDGET_S)
    if budget <= 0:
        # No budget left. Degrading is right: this is not an answer about the
        # caller, and the request still faces policy in C3.
        raise _Unreachable("no budget remaining for the STS lookup")
    return budget


def _store(access_key: str, result: dict[str, Any] | None) -> dict[str, Any] | None:
    # Cache positives and negatives alike. The negative is what stops a probe
    # flood hammering STS; the bound on the cache is what stops it growing.
    _cache[access_key] = result or {}
    return result
