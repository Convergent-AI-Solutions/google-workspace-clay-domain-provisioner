"""Unit tests for the Clay import CSV and the manual-steps list."""

from __future__ import annotations

import csv
from pathlib import Path

from google_workspace_clay_provisioner.clay import (
    APP_PASSWORD_PLACEHOLDER,
    CLAY_SMTP_CSV_HEADERS,
    ClayMailboxRow,
    clay_steps,
    write_clay_csv,
)


def test_csv_round_trips_with_the_expected_header_set(tmp_path: Path) -> None:
    """The written CSV must read back with exactly the pinned header tuple."""
    path = write_clay_csv(
        tmp_path / "getexample.com.clay.csv",
        [ClayMailboxRow(email="connect@getexample.com", first_name="Connect", last_name="Team")],
    )

    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        assert tuple(reader.fieldnames or ()) == CLAY_SMTP_CSV_HEADERS
        rows = list(reader)

    assert len(rows) == 1
    assert rows[0]["email"] == "connect@getexample.com"
    assert rows[0]["smtp_username"] == "connect@getexample.com"


def test_the_password_column_ships_a_placeholder(tmp_path: Path) -> None:
    """The app password has no API, so the CSV must not invent a real secret."""
    path = write_clay_csv(
        tmp_path / "out.csv",
        [ClayMailboxRow(email="connect@getexample.com", first_name="C", last_name="T")],
    )

    text = path.read_text(encoding="utf-8")
    assert APP_PASSWORD_PLACEHOLDER in text


def test_warmup_and_daily_limit_are_serialised() -> None:
    """warmup_enabled renders as a lowercase bool and daily_limit as a string."""
    row = ClayMailboxRow(
        email="a@b.com", first_name="A", last_name="B", daily_limit=35, warmup_enabled=True
    ).as_row()

    assert row["warmup_enabled"] == "true"
    assert row["daily_limit"] == "35"


def test_clay_steps_puts_oauth_before_the_smtp_alternative_when_a_csv_exists() -> None:
    """OAuth is the recommended route, so it precedes the SMTP upload fallback."""
    steps = clay_steps("connect@getexample.com", Path("getexample.com.clay.csv"))

    oauth_index = next(i for i, s in enumerate(steps) if "OAuth" in s)
    smtp_index = next(i for i, s in enumerate(steps) if "SMTP" in s)
    assert oauth_index < smtp_index


def test_clay_steps_omits_the_smtp_step_without_a_csv() -> None:
    """With no CSV path there is nothing to upload, so the SMTP step is dropped."""
    steps = clay_steps("connect@getexample.com", None)

    assert not any("SMTP" in s for s in steps)
