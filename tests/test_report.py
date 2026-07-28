"""Unit tests for the handoff checklist rendering."""

from __future__ import annotations

from google_workspace_clay_provisioner.dns_records import DnsRecordSpec
from google_workspace_clay_provisioner.report import RunSummary, render_checklist
from google_workspace_clay_provisioner.verify import CheckResult, VerificationReport


def _summary(**overrides: object) -> RunSummary:
    base: dict[str, object] = {
        "domain": "getexample.com",
        "mailbox": "connect@getexample.com",
        "records": (
            DnsRecordSpec(
                type="MX",
                name="getexample.com",
                content="smtp.google.com",
                priority=1,
                label="MX",
            ),
        ),
        "verification": None,
        "dkim_selector": "google",
    }
    base.update(overrides)
    return RunSummary(**base)  # type: ignore[arg-type]


def test_password_is_absent_unless_explicitly_supplied() -> None:
    """The checklist is a file on disk, so the password is off by default."""
    text = render_checklist(_summary())

    assert "Mailbox password" not in text


def test_password_appears_only_when_set() -> None:
    """When the operator asks for it, the password lands in the file."""
    text = render_checklist(_summary(mailbox_password="s3cr3t-value"))

    assert "Mailbox password" in text
    assert "s3cr3t-value" in text


def test_records_section_is_labelled_as_expected_not_published() -> None:
    """The table is config-derived, so it must not claim to report live state."""
    text = render_checklist(_summary())

    assert "## Expected records" in text
    assert "## Records published" not in text
    # It points the reader at Verification for what is actually live.
    assert "Verification" in text


def test_verification_results_render_as_a_table() -> None:
    """A run with verification shows each check's pass/FAIL result."""
    report = VerificationReport(
        domain="getexample.com",
        checks=(
            CheckResult("MX", True, "resolved"),
            CheckResult("DKIM", False, "no DKIM record with a p= key found"),
        ),
    )
    text = render_checklist(_summary(verification=report))

    assert "| MX | pass |" in text
    assert "| DKIM | FAIL |" in text
