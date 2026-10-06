"""One request-scoped deadline that every outbound call spends from (LC-2).

Why a module rather than two per-call timeouts: two sequential calls with
independent budgets can each spend their full allowance and sum past the hook's
budget. That is the arithmetic failure PR-0 documented. A single deadline makes
over-spend structurally impossible -- the PDP gets what STS left, not a fixed
figure.

Why it is set on ARRIVAL rather than at call start: PR-2a's queue wait is
otherwise invisible. A request that waited 400ms for an executor slot has 400ms
less to spend, rather than reporting a fast call after a slow wait.

Why it is passed EXPLICITLY and never held in a ContextVar: measured, a
ContextVar set in a coroutine reads its default inside loop.run_in_executor(),
and running boto3 in a sized executor is exactly what sts_lookup.py does. A
ContextVar deadline would silently vanish on the one call path that most needs
bounding. tests/test_deadline.py asserts this so nobody "simplifies" it later.
"""
from __future__ import annotations

import time
from typing import Callable

from reasons import Reason, Refusal


class Deadline:
    """A monotonic budget, shared by every outbound call in one request.

    `clock` is injectable so tests need no sleeps.
    """

    def __init__(self, budget_s: float, clock: Callable[[], float] | None = None) -> None:
        self._clock = clock or time.monotonic
        self._started = self._clock()
        self._budget = budget_s

    @property
    def budget_s(self) -> float:
        return self._budget

    def elapsed(self) -> float:
        return self._clock() - self._started

    def remaining(self) -> float:
        """Seconds left. Clamped at zero -- a negative remaining is not a
        negative timeout, it is an expired deadline."""
        return max(0.0, self._budget - self.elapsed())

    def expired(self) -> bool:
        return self.remaining() <= 0.0

    def spend(self, cap_s: float | None = None) -> float:
        """The budget for the next call: whatever is left, optionally capped.

        `cap_s` is how the STS lookup takes its 300ms share without the PDP
        being able to spend it too.
        """
        left = self.remaining()
        return min(left, cap_s) if cap_s is not None else left

    def check(self, reason: Reason = Reason.POLICY_ENGINE_TIMEOUT) -> None:
        """Refuse rather than attempt a call with no budget.

        Called before each outbound call and between streamed reads. This is
        what turns "slow" into "refused with a reason" instead of the hook's
        bare 403 at its own timeout (RL-7).
        """
        if self.expired():
            raise Refusal(
                reason,
                f"deadline exceeded after {self.elapsed() * 1000:.0f}ms "
                f"of {self._budget * 1000:.0f}ms",
            )
