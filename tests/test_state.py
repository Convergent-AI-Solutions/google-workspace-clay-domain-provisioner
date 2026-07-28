"""Unit tests for run state — the guard against paying twice for a domain."""

from __future__ import annotations

import json
from pathlib import Path

from google_workspace_clay_provisioner.state import (
    ORDERED_STEPS,
    STEP_MAILBOX,
    STEP_REGISTER,
    RunState,
    is_secret_key,
    scrub,
)


def test_missing_state_file_starts_empty(tmp_path: Path) -> None:
    """A first run has no state and must not fail on the absent file."""
    state = RunState.load(tmp_path, "example.com")
    assert state.steps == {}
    assert not state.is_done(STEP_REGISTER)


def test_marking_a_step_done_persists_it(tmp_path: Path) -> None:
    """Registration is non-refundable, so completion is written immediately."""
    state = RunState.load(tmp_path, "example.com")
    state.mark_done(STEP_REGISTER, domain="example.com", outcome="registered")

    reloaded = RunState.load(tmp_path, "example.com")
    assert reloaded.is_done(STEP_REGISTER)
    assert reloaded.detail(STEP_REGISTER)["outcome"] == "registered"


def test_a_skipped_step_is_not_done(tmp_path: Path) -> None:
    """Skipping DKIM must not read as having published it."""
    state = RunState.load(tmp_path, "example.com")
    state.mark_skipped("publish_dkim_record", "operator skipped")
    assert not state.is_done("publish_dkim_record")
    assert state.detail("publish_dkim_record")["reason"] == "operator skipped"


def test_passwords_are_never_written_to_state(tmp_path: Path) -> None:
    """The mailbox password is shown once in the terminal, never persisted here."""
    state = RunState.load(tmp_path, "example.com")
    state.mark_done(STEP_MAILBOX, email="connect@example.com", password="hunter2")

    written = (tmp_path / "example.com.json").read_text(encoding="utf-8")
    assert "hunter2" not in written
    assert "connect@example.com" in written


def test_nested_secrets_are_dropped_too() -> None:
    """A credential nested inside a detail dict must not slip through."""
    cleaned = scrub({"outer": {"api_token": "abc", "keep": 1}, "keep": 2})
    assert cleaned == {"outer": {"keep": 1}, "keep": 2}


def test_secret_key_detection_covers_the_common_names() -> None:
    """The filter is name-based, so the name list is the control."""
    for key in ("password", "smtp_password", "API_KEY", "client_secret", "private_key"):
        assert is_secret_key(key)
    assert not is_secret_key("email")


def test_a_corrupt_state_file_is_moved_aside(tmp_path: Path) -> None:
    """Silently treating corruption as "nothing done" could trigger a second purchase."""
    path = tmp_path / "example.com.json"
    path.write_text("{not json", encoding="utf-8")

    state = RunState.load(tmp_path, "example.com")
    assert state.steps == {}
    assert (tmp_path / "example.com.json.corrupt").is_file()


def test_a_second_corruption_does_not_crash(tmp_path: Path) -> None:
    """Path.replace overwrites on Windows too, and a suffixed name keeps both.

    Regression test: the previous Path.rename raised FileExistsError on Windows
    when a .json.corrupt file from an earlier corruption already existed,
    breaking every command including status.
    """
    path = tmp_path / "example.com.json"
    (tmp_path / "example.com.json.corrupt").write_text("first", encoding="utf-8")
    path.write_text("{not json again", encoding="utf-8")

    state = RunState.load(tmp_path, "example.com")

    assert state.steps == {}
    assert (tmp_path / "example.com.json.corrupt").is_file()

    # A third corruption in the same process must still be preserved: each
    # quarantine takes a unique suffix, so none is ever overwritten.
    path.write_text("{not json a third time", encoding="utf-8")
    RunState.load(tmp_path, "example.com")

    corrupt_siblings = list(tmp_path.glob("example.com.json.corrupt*"))
    assert len(corrupt_siblings) == 3


def test_a_failed_step_is_not_done(tmp_path: Path) -> None:
    """A failed verification must not read as a completed step."""
    state = RunState.load(tmp_path, "example.com")
    state.mark_failed("verify_dns_records", passed=False, failures=["DKIM"])

    assert not state.is_done("verify_dns_records")
    assert state.detail("verify_dns_records")["status"] == "failed"
    assert state.detail("verify_dns_records")["failures"] == ["DKIM"]


def test_summary_lists_every_step_in_run_order(tmp_path: Path) -> None:
    """The status command reports all seven steps, done or not."""
    state = RunState.load(tmp_path, "example.com")
    state.mark_done(STEP_REGISTER)
    summary = dict(state.summary())

    assert [step for step, _ in state.summary()] == list(ORDERED_STEPS)
    assert summary[STEP_REGISTER] == "done"
    assert summary[STEP_MAILBOX] == "pending"


def test_state_file_is_valid_json_with_a_timestamp(tmp_path: Path) -> None:
    """The file is read by humans during handover, so it must stay parseable."""
    state = RunState.load(tmp_path, "example.com")
    state.mark_done(STEP_REGISTER)

    payload = json.loads((tmp_path / "example.com.json").read_text(encoding="utf-8"))
    assert payload["domain"] == "example.com"
    assert payload["updated"]
