"""Deadline-bounded PDP client (LC-6).

## Why this replaces ai-gateway-pod/pdp_client.py rather than extending it

That module lives on the component being retired, and project policy forbids
adding capability there. The duplication is deliberate.

## Why BOTH bounds are required -- the measurement that produced this module

`urlopen(timeout=X)` and `httpx.Timeout(X)` are both PER-OPERATION timeouts: they
reset on every read. Measured against a stub dripping a 58-byte body one byte at
a time, each individual read comfortably inside the configured timeout:

    urlopen(timeout=1.5)                        ->  51.5 s
    httpx.Timeout(1.5)                          ->  15.0 s
    httpx + deadline checked across iter_bytes() ->   2.0 s   <- bounded

So a deadline checked BETWEEN reads is necessary. It is not sufficient. Measured
against a stub that sends headers and then goes silent INSIDE one read:

    deadline across reads only (read=None)      ->  15.06 s  <- the loop never
                                                                regains control
    deadline + per-attempt read timeout         ->   1.52 s  <- bounded

The deadline bounds the TOTAL across many small reads; the per-read timeout
bounds any SINGLE read. Neither covers the other's failure shape, and the drip
stub alone passes against an implementation that hangs for fifteen seconds.

`read` is set from `deadline.remaining()` rather than a constant: a fixed value
larger than the remaining budget would let one read outlive the deadline.

## Fail-closed, stated at the site

Unreachable, 5xx, an unknown verdict, or a deadline expiry all refuse. NFR-2
requires the posture written here rather than inherited -- the hook's own
FailureMode::Deny handles an unreachable AUTHZ SERVICE, which is a different
failure from an unreachable PDP behind a reachable authz service.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import httpx

import config
from deadline import Deadline
from reasons import Reason, Refusal

log = logging.getLogger("authz-gateway.pdp")

# Reused across requests: a client per call leaks connection pools.
_client: httpx.Client | None = None
_aclient: httpx.AsyncClient | None = None


def _http() -> httpx.Client:
    global _client
    if _client is None:
        _client = httpx.Client()
    return _client


def _ahttp() -> httpx.AsyncClient:
    global _aclient
    if _aclient is None:
        _aclient = httpx.AsyncClient()
    return _aclient


def reset_for_tests() -> None:
    global _client, _aclient
    if _client is not None:
        _client.close()
    _client = None
    # The async client's aclose() is a coroutine and this is a sync teardown.
    # Dropping the reference is enough here: the pool is closed when it is
    # collected, and a test process is short-lived. Not a pattern for prod code.
    _aclient = None


def _request_setup(payload, deadline, pdp_url):
    """URL, deadline pre-check and the two timeout halves. Shared by both paths
    so a bound cannot hold on one and not the other."""
    url = (pdp_url or config.PDP_URL).rstrip("/") + "/decide"
    deadline.check(Reason.POLICY_ENGINE_TIMEOUT)      # refuse rather than attempt

    remaining = deadline.remaining()
    # Both halves. `read` from the remaining budget, so no single read can
    # outlive the deadline the read loop enforces across reads.
    timeout = httpx.Timeout(
        connect=min(0.2, remaining), read=remaining, write=remaining, pool=remaining
    )
    return url, timeout


def _headers(baggage: str | None) -> dict[str, str]:
    """T2 (sprint-2026-09-ga-hardening): forward `baggage` to the PDP so the
    actionId minted at authz-gateway's first governed touch (tracectx.py)
    reaches the decision it governs, rather than the PDP having no join key
    for its own decision log line. Empty dict when absent — `httpx` treats
    that as "no extra headers," not as "clear the client's defaults."
    """
    return {"baggage": baggage} if baggage else {}


def _check_status(status_code: int) -> None:
    if status_code >= 500:
        raise Refusal(Reason.POLICY_ENGINE_UNAVAILABLE, f"pdp returned {status_code}")
    if status_code >= 400:
        # 4xx is a malformed request on our side. Fail closed: a request the PDP
        # will not evaluate is not an allowed request.
        raise Refusal(
            Reason.POLICY_ENGINE_UNAVAILABLE, f"pdp rejected the request ({status_code})"
        )


async def decide_async(
    payload: dict[str, Any],
    deadline: Deadline,
    pdp_url: str | None = None,
    client: httpx.AsyncClient | None = None,
    baggage: str | None = None,
) -> dict[str, Any]:
    """The path app.py uses. Same bounds, without blocking the event loop.

    `httpx.Client` is synchronous, so calling `decide` from an async endpoint
    blocks the only event loop thread. Measured against a stub delaying 200 ms:
    eight concurrent calls took 1691 ms where overlapping is 200 ms -- fully
    serialised. Unlike the STS lookup this is on EVERY request, so the whole
    service's throughput was one request at a time regardless of MAX_IN_FLIGHT.

    httpx ships a real async client, so this needs no thread: the deadline still
    bounds the total across reads and `read` still bounds any single read.

    `baggage` (T2): forwarded as the `baggage` header so the PDP's decision log
    line can carry the same actionId this service established or echoed.
    """
    url, timeout = _request_setup(payload, deadline, pdp_url)
    c = client if client is not None else _ahttp()

    try:
        async with c.stream(
            "POST", url, json=payload, timeout=timeout, headers=_headers(baggage)
        ) as resp:
            _check_status(resp.status_code)
            chunks: list[bytes] = []
            async for chunk in resp.aiter_bytes():
                deadline.check(Reason.POLICY_ENGINE_TIMEOUT)
                chunks.append(chunk)
            raw = b"".join(chunks)
    except Refusal:
        raise
    except httpx.TimeoutException as exc:
        raise Refusal(Reason.POLICY_ENGINE_TIMEOUT, f"pdp read timed out: {exc}") from exc
    except httpx.HTTPError as exc:
        raise Refusal(Reason.POLICY_ENGINE_UNAVAILABLE, f"pdp unreachable: {exc}") from exc

    return _interpret(raw)


def decide(
    payload: dict[str, Any],
    deadline: Deadline,
    pdp_url: str | None = None,
    client: httpx.Client | None = None,
    baggage: str | None = None,
) -> dict[str, Any]:
    """Blocking POST /decide, bounded by total elapsed time AND per read.

    Returns the parsed DecideResponse. Raises `Refusal` on deny, unavailability,
    timeout or an unknown verdict -- every terminal path is an explicit refusal
    with a reason (I-2).

    `baggage` (T2): forwarded as the `baggage` header, same contract as
    `decide_async`.

    NOTE: an async caller must use `decide_async` -- see its docstring.
    """
    url, timeout = _request_setup(payload, deadline, pdp_url)
    c = client if client is not None else _http()

    try:
        with c.stream(
            "POST", url, json=payload, timeout=timeout, headers=_headers(baggage)
        ) as resp:
            _check_status(resp.status_code)
            chunks: list[bytes] = []
            for chunk in resp.iter_bytes():
                # Checked BETWEEN reads: bounds the total across many small
                # reads, which the per-read timeout above cannot.
                deadline.check(Reason.POLICY_ENGINE_TIMEOUT)
                chunks.append(chunk)
            raw = b"".join(chunks)
    except Refusal:
        raise
    except httpx.TimeoutException as exc:
        # Bounds a single stalled read, which the deadline loop cannot.
        raise Refusal(Reason.POLICY_ENGINE_TIMEOUT, f"pdp read timed out: {exc}") from exc
    except httpx.HTTPError as exc:
        raise Refusal(Reason.POLICY_ENGINE_UNAVAILABLE, f"pdp unreachable: {exc}") from exc

    return _interpret(raw)


def _interpret(raw: bytes) -> dict[str, Any]:
    """Verdict interpretation, shared verbatim by both paths."""
    try:
        body = json.loads(raw)
    except ValueError as exc:
        raise Refusal(Reason.POLICY_ENGINE_UNAVAILABLE, "pdp returned unparseable JSON") from exc

    verdict = str(body.get("decision", "")).upper()
    if verdict == "ALLOW":
        # NOTE (SR-4 / AR-11c, closed 2026-08-23): cedar_evaluator.py populates
        # an `errors` list and nulls the reason on ALLOW; pdp/server.py's
        # DecideResponse now carries that `errors` field on the wire
        # (pdp/server.py DecideResponse + decide()), so an allow that only
        # happened because a sibling `forbid` clause type-errored is refused
        # here rather than passed through as a genuine permit.
        #
        # This client refuses on a non-empty `errors` list the moment the PDP
        # surfaces one — verified live end-to-end by
        # pdp/tests/test_decide.py::test_decide_allow_from_a_forbid_that_type_errors_still_surfaces_errors_on_the_wire.
        errors = body.get("errors") or []
        if errors:
            raise Refusal(
                Reason.POLICY_ENGINE_UNAVAILABLE,
                f"policy evaluation errored; an allow that depended on a clause "
                f"failing to evaluate is not an allow: {errors}",
                # a design note point 4: this IS a policy outcome, so the decision
                # record must attribute it to the policy rather than letting it
                # read as an infrastructure failure.
                verdict=body,
            )
        return body

    if verdict == "DENY":
        raise Refusal(
            Reason.POLICY_DENIED,
            body.get("reason") or f"denied by policy {body.get('policyId', '?')}",
            # a design note point 4: carried so `app.py` can write `matchedPolicy` and
            # `policyVersion` into the decision record. Before this, the PDP's
            # answer was discarded here and a denial was recorded with no clause.
            verdict=body,
        )

    # Neither ALLOW nor DENY: fail closed rather than guess.
    raise Refusal(Reason.POLICY_ENGINE_UNAVAILABLE, f"unknown verdict {verdict!r}")
