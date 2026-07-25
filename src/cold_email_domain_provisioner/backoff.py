"""Jittered backoff for the two things this tool has to wait on.

DNS propagation and Cloudflare's asynchronous registration both need polling.
Every wait is ``base + random(0, jitter)`` rather than a fixed interval, so
concurrent runs against a recovering service do not synchronise their retries.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import TypeVar

T = TypeVar("T")

DEFAULT_BASE_SECONDS = 20.0
DEFAULT_JITTER_SECONDS = 10.0


@dataclass(frozen=True)
class BackoffPolicy:
    """How long to wait between polls, and how many times to try."""

    attempts: int = 15
    base_seconds: float = DEFAULT_BASE_SECONDS
    jitter_seconds: float = DEFAULT_JITTER_SECONDS

    def __post_init__(self) -> None:
        if self.attempts < 1:
            raise ValueError("attempts must be at least 1")
        if self.base_seconds < 0 or self.jitter_seconds < 0:
            raise ValueError("base_seconds and jitter_seconds must be non-negative")

    @property
    def worst_case_seconds(self) -> float:
        """Upper bound on total waiting, useful for telling the operator up front."""
        return (self.attempts - 1) * (self.base_seconds + self.jitter_seconds)


def jittered_delay(policy: BackoffPolicy, rng: random.Random | None = None) -> float:
    """One delay: the base interval plus a random jitter in [0, jitter_seconds]."""
    source = rng or random
    return policy.base_seconds + source.uniform(0.0, policy.jitter_seconds)


def delays(policy: BackoffPolicy, rng: random.Random | None = None) -> Iterator[float]:
    """The delays between successive attempts — one fewer than ``attempts``."""
    for _ in range(policy.attempts - 1):
        yield jittered_delay(policy, rng)


def poll_until(
    probe: Callable[[], T | None],
    policy: BackoffPolicy,
    *,
    on_wait: Callable[[int, float], None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    rng: random.Random | None = None,
) -> T | None:
    """Call ``probe`` until it returns a non-``None`` value or attempts run out.

    ``on_wait`` receives the 1-based attempt number just completed and the
    delay about to be slept, so callers can report progress without this
    module knowing anything about the console.
    """
    delay_iter = delays(policy, rng)
    for attempt in range(1, policy.attempts + 1):
        result = probe()
        if result is not None:
            return result
        delay = next(delay_iter, None)
        if delay is None:
            break
        if on_wait is not None:
            on_wait(attempt, delay)
        sleep(delay)
    return None
