"""Property test for the mailbox password generator.

The invariant matters because a Workspace admin can enforce a password strength
policy; a draw missing a character class would be rejected and mailbox creation
would fail intermittently.
"""

from __future__ import annotations

import pytest

pytest.importorskip("hypothesis", reason="hypothesis is an optional dev dependency")

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from google_workspace_clay_provisioner.google.users import (  # noqa: E402
    _PASSWORD_DIGITS,
    _PASSWORD_LOWER,
    _PASSWORD_SYMBOLS,
    _PASSWORD_UPPER,
    generate_password,
)


@settings(max_examples=300)
@given(length=st.integers(min_value=12, max_value=64))
def test_password_contains_every_required_class(length: int) -> None:
    """For any length >= 12 the result has an upper, lower, digit and symbol."""
    password = generate_password(length)

    assert len(password) == length
    assert any(c in _PASSWORD_UPPER for c in password)
    assert any(c in _PASSWORD_LOWER for c in password)
    assert any(c in _PASSWORD_DIGITS for c in password)
    assert any(c in _PASSWORD_SYMBOLS for c in password)


def test_password_rejects_too_short() -> None:
    """The 12-character floor is stricter than Workspace's default and is kept."""
    with pytest.raises(ValueError):
        generate_password(8)
