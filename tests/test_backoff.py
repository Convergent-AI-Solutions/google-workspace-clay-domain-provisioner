"""Unit tests for the polling helper — every wait carries jitter, never a fixed interval."""

from __future__ import annotations

import random

import pytest

from cold_email_domain_provisioner.backoff import (
    BackoffPolicy,
    delays,
    jittered_delay,
    poll_until,
)


def test_delay_is_never_below_the_base_or_above_base_plus_jitter() -> None:
    """Concurrent runs must not synchronise, but must still wait the base interval."""
    policy = BackoffPolicy(attempts=5, base_seconds=20, jitter_seconds=10)
    rng = random.Random(1234)
    for _ in range(200):
        delay = jittered_delay(policy, rng)
        assert 20.0 <= delay <= 30.0


def test_zero_jitter_gives_a_fixed_interval() -> None:
    """Jitter is configurable to zero for deterministic tests, not for production use."""
    policy = BackoffPolicy(attempts=3, base_seconds=5, jitter_seconds=0)
    assert list(delays(policy)) == [5.0, 5.0]


def test_there_is_one_fewer_delay_than_attempts() -> None:
    """The last attempt is not followed by a wait."""
    policy = BackoffPolicy(attempts=4, base_seconds=1, jitter_seconds=0)
    assert len(list(delays(policy))) == 3


@pytest.mark.parametrize(
    ("attempts", "base", "jitter"),
    [(0, 1, 1), (-1, 1, 1), (1, -1, 1), (1, 1, -1)],
)
def test_invalid_policies_are_rejected(attempts: int, base: float, jitter: float) -> None:
    """A zero-attempt or negative policy is a programming error, not a waiting strategy."""
    with pytest.raises(ValueError):
        BackoffPolicy(attempts=attempts, base_seconds=base, jitter_seconds=jitter)


def test_poll_returns_the_first_non_none_result_without_sleeping_again() -> None:
    """A record that already resolves must not incur a wait."""
    slept: list[float] = []
    result = poll_until(lambda: "ready", BackoffPolicy(attempts=5), sleep=slept.append)
    assert result == "ready"
    assert slept == []


def test_poll_retries_until_the_probe_succeeds() -> None:
    """DNS propagation is the normal case for a fresh record, not an error."""
    calls = {"n": 0}

    def probe() -> str | None:
        calls["n"] += 1
        return "ready" if calls["n"] == 3 else None

    slept: list[float] = []
    policy = BackoffPolicy(attempts=5, base_seconds=1, jitter_seconds=0)
    assert poll_until(probe, policy, sleep=slept.append) == "ready"
    assert len(slept) == 2


def test_poll_gives_up_and_returns_none_after_the_last_attempt() -> None:
    """Callers turn this into a message naming what is still missing."""
    policy = BackoffPolicy(attempts=3, base_seconds=1, jitter_seconds=0)
    slept: list[float] = []
    assert poll_until(lambda: None, policy, sleep=slept.append) is None
    assert len(slept) == 2


def test_worst_case_is_reported_for_the_operator() -> None:
    """The CLI tells the operator the upper bound before it starts waiting."""
    policy = BackoffPolicy(attempts=3, base_seconds=20, jitter_seconds=10)
    assert policy.worst_case_seconds == 60.0
