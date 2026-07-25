"""Property tests for candidate generation.

These hold for any seed, not just the hand-picked ones in ``test_suggest.py``.
"""

from __future__ import annotations

import pytest

pytest.importorskip("hypothesis", reason="hypothesis is an optional dev dependency")

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from google_workspace_clay_provisioner.suggest import (  # noqa: E402
    generate_candidates,
    is_valid_label,
    root_label,
)

#: Labels a registrar would accept: alphanumeric, no leading or trailing hyphen.
labels = st.from_regex(r"\A[a-z0-9]([a-z0-9-]{0,18}[a-z0-9])?\Z", fullmatch=True)


@settings(max_examples=200)
@given(label=labels, limit=st.integers(min_value=1, max_value=40))
def test_every_candidate_is_a_valid_dot_com(label: str, limit: int) -> None:
    """A generated name must be registrable, or the availability check is wasted."""
    for candidate in generate_candidates(f"{label}.com", limit=limit):
        assert candidate.domain.endswith(".com")
        assert is_valid_label(candidate.domain.removesuffix(".com"))


@settings(max_examples=200)
@given(label=labels, limit=st.integers(min_value=1, max_value=40))
def test_candidates_are_unique_and_within_the_limit(label: str, limit: int) -> None:
    """Duplicates would consume slots in the 20-domain availability batch."""
    domains = [c.domain for c in generate_candidates(f"{label}.com", limit=limit)]
    assert len(domains) == len(set(domains))
    assert len(domains) <= limit


@settings(max_examples=200)
@given(label=labels)
def test_the_seed_domain_is_never_a_candidate(label: str) -> None:
    """You already own the seed; offering it back is always wrong."""
    seed = f"{label}.com"
    assert all(candidate.domain != seed for candidate in generate_candidates(seed, limit=60))


@settings(max_examples=200)
@given(label=labels)
def test_generation_is_deterministic_for_any_seed(label: str) -> None:
    """A rerun must reproduce the same shortlist for auditability."""
    seed = f"{label}.com"
    assert generate_candidates(seed, limit=20) == generate_candidates(seed, limit=20)


@settings(max_examples=200)
@given(label=labels)
def test_root_label_is_idempotent(label: str) -> None:
    """Feeding a reduced label back in must not reduce it further."""
    assert root_label(root_label(f"{label}.com")) == label


@settings(max_examples=100)
@given(label=labels)
def test_no_hyphen_is_introduced_unless_allowed(label: str) -> None:
    """Hyphenated sending domains are opt-in, so the default must add no hyphen.

    A seed that already contains a hyphen carries it into every candidate, so
    the property is that the count does not grow, not that none is present.
    """
    seed_hyphens = label.count("-")
    for candidate in generate_candidates(f"{label}.com", limit=60, allow_hyphen=False):
        assert candidate.domain.count("-") == seed_hyphens
