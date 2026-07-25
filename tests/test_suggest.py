"""Unit tests for candidate generation — the only step that invents names."""

from __future__ import annotations

import pytest

from google_workspace_clay_provisioner.suggest import (
    generate_candidates,
    is_valid_label,
    root_label,
)


@pytest.mark.parametrize(
    ("seed", "expected"),
    [
        ("acme.com", "acme"),
        ("ACME.COM", "acme"),
        ("www.acme.com", "acme"),
        ("https://www.acme.com/pricing", "acme"),
        ("acme", "acme"),
        ("acme.com.au", "acme"),
        ("mail.acme.io", "acme"),
        ("someone@acme.com", "acme"),
        ("acme.com:443", "acme"),
    ],
)
def test_root_label_reduces_seeds_to_the_business_name(seed: str, expected: str) -> None:
    """A seed may arrive as a URL, hostname, or address; all reduce to one label."""
    assert root_label(seed) == expected


@pytest.mark.parametrize("seed", ["", "   ", ".", "..", "https://"])
def test_root_label_rejects_seeds_with_no_usable_label(seed: str) -> None:
    """An unusable seed raises rather than producing nonsense candidates."""
    with pytest.raises(ValueError):
        root_label(seed)


def test_generated_candidates_are_all_dot_com() -> None:
    """The tool only provisions .com, so every candidate must be .com."""
    candidates = generate_candidates("acme.com", limit=20)
    assert candidates
    assert all(candidate.domain.endswith(".com") for candidate in candidates)


def test_seed_domain_is_never_suggested() -> None:
    """Suggesting the domain you already own would waste a purchase check."""
    candidates = generate_candidates("acme.com", limit=50)
    assert all(candidate.domain != "acme.com" for candidate in candidates)


def test_candidates_are_unique() -> None:
    """A duplicate would consume one of the 20 slots in an availability batch."""
    domains = [candidate.domain for candidate in generate_candidates("acme.com", limit=50)]
    assert len(domains) == len(set(domains))


def test_generation_is_deterministic() -> None:
    """The same seed must give the same list, so a run can be reproduced."""
    first = generate_candidates("acme.com", limit=15)
    second = generate_candidates("acme.com", limit=15)
    assert first == second


def test_hyphenated_variants_are_opt_in() -> None:
    """Hyphenated sending domains read as throwaway, so they are off by default."""
    without = generate_candidates("acme.com", limit=50, allow_hyphen=False)
    assert all("-" not in candidate.domain for candidate in without)

    with_hyphens = generate_candidates("acme.com", limit=50, allow_hyphen=True)
    assert any("-" in candidate.domain for candidate in with_hyphens)


def test_limit_is_respected() -> None:
    """The availability check batches in twenties, so the limit must hold."""
    assert len(generate_candidates("acme.com", limit=5)) == 5
    assert generate_candidates("acme.com", limit=0) == []


def test_every_candidate_carries_the_rule_that_made_it() -> None:
    """The pattern is shown in the CLI table so a choice can be explained."""
    for candidate in generate_candidates("acme.com", limit=10):
        assert candidate.pattern


def test_long_seed_labels_do_not_produce_oversized_labels() -> None:
    """A DNS label caps at 63 characters; over-length candidates are dropped."""
    seed = "a" * 60
    for candidate in generate_candidates(f"{seed}.com", limit=50):
        assert is_valid_label(candidate.domain.removesuffix(".com"))
