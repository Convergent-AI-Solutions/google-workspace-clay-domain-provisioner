"""Unit tests for the verification judgements — pure, no resolver involved."""

from __future__ import annotations

from google_workspace_clay_provisioner.verify import (
    evaluate_dkim,
    evaluate_dmarc,
    evaluate_mx,
    evaluate_spf,
)

SAMPLE_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest" * 3


def test_mx_passes_when_the_expected_host_is_present() -> None:
    """The check is a subset test, so extra MX records do not fail it."""
    result = evaluate_mx(["smtp.google.com."], ["smtp.google.com"])
    assert result.passed


def test_mx_ignores_trailing_dots_and_case() -> None:
    """Resolvers return fully qualified names; the comparison must normalise."""
    assert evaluate_mx(["SMTP.Google.COM."], ["smtp.google.com"]).passed


def test_mx_fails_when_nothing_resolves() -> None:
    """No MX means the domain cannot receive, which blocks reply handling."""
    result = evaluate_mx([], ["smtp.google.com"])
    assert not result.passed
    assert "no MX records" in result.detail


def test_mx_fails_and_names_the_missing_host() -> None:
    """The operator needs to know which host is absent, not just that one is."""
    result = evaluate_mx(["mail.other.example"], ["smtp.google.com"])
    assert not result.passed
    assert "smtp.google.com" in result.detail


def test_spf_passes_on_one_record_with_the_google_include() -> None:
    """Exactly one SPF record carrying Google's include is the target state."""
    assert evaluate_spf(["v=spf1 include:_spf.google.com ~all"]).passed


def test_spf_ignores_unrelated_txt_records_at_the_apex() -> None:
    """The apex also holds the verification token; it must not confuse the check."""
    values = ["google-site-verification=abc", "v=spf1 include:_spf.google.com ~all"]
    assert evaluate_spf(values).passed


def test_spf_fails_when_two_records_are_present() -> None:
    """Two v=spf1 records is a permanent error under RFC 7208 — receivers see none."""
    values = ["v=spf1 include:_spf.google.com ~all", "v=spf1 include:other.example -all"]
    result = evaluate_spf(values)
    assert not result.passed
    assert "exactly one" in result.detail


def test_spf_fails_when_the_required_include_is_missing() -> None:
    """Without Google's include, Workspace mail is not authorised by SPF."""
    result = evaluate_spf(["v=spf1 include:other.example ~all"])
    assert not result.passed


def test_spf_fails_when_no_spf_record_exists() -> None:
    """An apex with only a verification token has no SPF at all."""
    assert not evaluate_spf(["google-site-verification=abc"]).passed


def test_dkim_passes_when_a_key_is_published() -> None:
    """A published p= key is the minimum for signed mail."""
    assert evaluate_dkim([f"v=DKIM1; k=rsa; p={SAMPLE_KEY}"]).passed


def test_dkim_compares_against_the_expected_key_when_given() -> None:
    """Matching the expected key catches a truncated paste, the common failure."""
    published = f"v=DKIM1; k=rsa; p={SAMPLE_KEY[:-10]}"
    result = evaluate_dkim([published], SAMPLE_KEY)
    assert not result.passed
    assert "truncated" in result.detail


def test_dkim_passes_when_the_published_key_matches_exactly() -> None:
    """The happy path: what was pasted is what resolves."""
    assert evaluate_dkim([f"v=DKIM1; k=rsa; p={SAMPLE_KEY}"], SAMPLE_KEY).passed


def test_dkim_fails_when_the_selector_has_no_record() -> None:
    """An empty selector lookup means Google will not find the key either."""
    result = evaluate_dkim([])
    assert not result.passed
    assert "no DKIM record" in result.detail


def test_dkim_detail_does_not_leak_the_whole_key() -> None:
    """Console output and checklists are shared; a truncated preview is enough."""
    result = evaluate_dkim([f"v=DKIM1; k=rsa; p={SAMPLE_KEY}"])
    assert SAMPLE_KEY not in "".join(result.found)


def test_dmarc_passes_and_reports_the_policy() -> None:
    """The policy in force is what an operator needs to see."""
    result = evaluate_dmarc(["v=DMARC1; p=none; rua=mailto:d@example.com"])
    assert result.passed
    assert "p=none" in result.detail


def test_dmarc_fails_when_the_policy_differs_from_the_expected_one() -> None:
    """A stale record from a previous run must not read as success."""
    result = evaluate_dmarc(["v=DMARC1; p=none"], "reject")
    assert not result.passed
    assert "expected p=reject" in result.detail


def test_dmarc_fails_on_two_records() -> None:
    """More than one DMARC record at _dmarc is invalid."""
    result = evaluate_dmarc(["v=DMARC1; p=none", "v=DMARC1; p=reject"])
    assert not result.passed


def test_dmarc_fails_when_the_policy_tag_is_absent() -> None:
    """A record without p= specifies nothing and is ignored by receivers."""
    result = evaluate_dmarc(["v=DMARC1; rua=mailto:d@example.com"])
    assert not result.passed
    assert "no p= policy tag" in result.detail


def test_dmarc_fails_when_no_record_exists() -> None:
    """Absence is the default state of a new domain and must be reported."""
    assert not evaluate_dmarc([]).passed
