"""Load shedding before the body is read (LC-1).

## Why ASGI middleware rather than the two obvious mechanisms

Neither obvious mechanism does both jobs:

    uvicorn --limit-concurrency   bounds the buffer, but returns a HARDCODED
                                  503 with body b"Service Unavailable" -- no
                                  reason code, no header, nothing greppable
    a semaphore inside the handler carries a reason code, but ASGI has already
                                  read the body into memory by then

ASGI middleware sits earlier in the chain than either, so it bounds the app-side
buffer AND carries a reason. Measured: 429 with an x-modaas-reason header at
ZERO app-side bytes read.

## And it is necessary, not sufficient -- the correction

uvicorn accumulates the body independently of whether the app ever calls
receive(). `h11_impl.py`:

    elif isinstance(event, h11.Data):
        self.cycle.body += event.data
        if len(self.cycle.body) > HIGH_WATER_LIMIT:
            self.flow.pause_reading()

So a shed request still costs memory. It is BOUNDED, not unbounded --
HIGH_WATER_LIMIT is 65536, so per-connection accumulation caps around 64-160 KB
whatever the declared body size. But it is counted per CONNECTION, and the only
bound on connections is --limit-concurrency. That is why LIMIT_CONCURRENCY is a
sized knob in config.py rather than a far-outer net.

The test for this must assert BOTH layers: zero app-side bytes AND a bounded
uvicorn-side figure. Asserting only the first is what let the original claim
through.

## Why shedding at all

An OOM kill restarts the pod, which empties the in-process STS cache, which
degrades every subsequent caller to `structural` until it refills. So a memory
failure compounds into a governance degradation, while a shed request is one
refused call. Fail-closed under pressure, like every other path here.
"""
from __future__ import annotations

import asyncio
import json
import logging

import config
from reasons import Reason
from tracectx import resolve as resolve_trace_context

log = logging.getLogger("authz-gateway.shed")

_BODY = json.dumps({"reason": Reason.CAPACITY_EXCEEDED.value}).encode()


def _trace_headers(scope) -> list[tuple[bytes, bytes]]:
    """The evidence-chain ids for a request that never reaches the handler.

    A shed 429 IS a refusal by this service, and app.py's `_refuse` puts these
    ids on every other refusal precisely so the chain does not go dark on the
    failure path. Overload was the one class leaving with no join key -- the
    class an operator most needs to reconstruct, since a shed request is the
    symptom of a pressure event rather than of one caller's mistake.

    Derived from the ASGI SCOPE headers, never from the body: reading the body
    here would pay the memory this middleware exists to save, which is the
    property test_shed.py's discriminating arm asserts.
    """
    raw = scope.get("headers") or []
    traceparent = baggage = None
    for key, value in raw:
        # ASGI lower-cases header names, but a hand-built scope in a test may
        # not, and a case-sensitive read would silently find nothing.
        name = key.decode("latin-1").lower() if isinstance(key, bytes) else str(key).lower()
        if name == "traceparent":
            traceparent = value.decode("latin-1") if isinstance(value, bytes) else str(value)
        elif name == "baggage":
            baggage = value.decode("latin-1") if isinstance(value, bytes) else str(value)

    ctx = resolve_trace_context(traceparent=traceparent, baggage=baggage)
    out = [(b"x-modaas-action-id", ctx.action_id.encode()),
           (b"x-modaas-correlation-id", ctx.correlation_id.encode())]
    if ctx.trace_id:
        # Emitted ONLY when the caller sent a usable traceparent. An empty value
        # would make the hook's responseMetadata CEL lookup succeed and publish
        # an empty trace id to the caller as though a join existed.
        out.append((b"x-modaas-trace-id", ctx.trace_id.encode()))
    return out


class ShedMiddleware:
    """Refuse with a reason when in-flight requests exceed the bound.

    Pure ASGI rather than a Starlette `BaseHTTPMiddleware` subclass: the latter
    wraps the receive channel and would defeat the point of refusing before the
    body is read.
    """

    def __init__(self, app, max_in_flight: int | None = None) -> None:
        self.app = app
        self.max_in_flight = max_in_flight or config.MAX_IN_FLIGHT
        self._sem = asyncio.Semaphore(self.max_in_flight)
        self.shed_count = 0                       # for the span attribute

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        if self._sem.locked():
            # THE critical property: refuse without touching receive(), so the
            # app-side copy and the JSON parse (to which the x4.6 peak
            # multiplier applies) are never paid.
            self.shed_count += 1
            log.warning(
                "shed: %d in flight, cap %d", self.max_in_flight, self.max_in_flight
            )
            await send({
                "type": "http.response.start",
                "status": 429,
                "headers": [
                    (b"content-type", b"application/json"),
                    # Greppable, and distinguishable from a policy denial: a
                    # capacity refusal and a policy refusal need different
                    # operator actions.
                    (b"x-modaas-reason", Reason.CAPACITY_EXCEEDED.value.encode()),
                    # A capacity refusal is retryable; a policy denial is not.
                    (b"retry-after", b"1"),
                    # ...and it is joinable, like every other refusal here.
                    *_trace_headers(scope),
                ],
            })
            await send({"type": "http.response.body", "body": _BODY})
            return

        async with self._sem:
            await self.app(scope, receive, send)
