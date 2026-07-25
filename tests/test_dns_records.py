"""Unit tests for the record builders — what the four records must say."""

from __future__ import annotations

import pytest

from google_workspace_clay_provisioner.dns_records import (
    LEGACY_MX_HOSTS,
    SINGLE_MX_HOST,
    dkim_public_key,
    dkim_record,
    dmarc_record,
    mx_records,
    normalize_dkim_value,
    normalize_txt_value,
    site_verification_record,
    spf_record,
)

SAMPLE_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest" * 3


def test_single_mx_mode_produces_one_record_pointing_at_google() -> None:
    """The current Google layout is a single host at priority 1."""
    records = mx_records("example.com", "single")
    assert len(records) == 1
    assert records[0].content == SINGLE_MX_HOST
    assert records[0].priority == 1


def test_legacy_mx_mode_produces_the_five_host_set() -> None:
    """Some estates standardise on the older five-record layout."""
    records = mx_records("example.com", "legacy")
    assert len(records) == len(LEGACY_MX_HOSTS)
    assert {record.priority for record in records} == {1, 5, 10}


def test_unknown_mx_mode_is_rejected() -> None:
    """A typo in the mode must fail loudly rather than publishing no MX at all."""
    with pytest.raises(ValueError, match="unknown MX mode"):
        mx_records("example.com", "gmail")  # type: ignore[arg-type]


def test_mx_records_require_a_priority() -> None:
    """An MX record without a priority is not valid DNS."""
    from google_workspace_clay_provisioner.dns_records import DnsRecordSpec

    with pytest.raises(ValueError, match="priority"):
        DnsRecordSpec(type="MX", name="example.com", content="smtp.google.com")


def test_spf_record_sits_at_the_apex_and_carries_the_google_include() -> None:
    """Google's SPF include is what authorises Workspace to send as the domain."""
    record = spf_record("example.com")
    assert record.name == "example.com"
    assert "include:_spf.google.com" in record.content
    assert record.match_prefix == "v=spf1"


def test_spf_record_rejects_a_value_that_is_not_spf() -> None:
    """Publishing a non-SPF value at the apex would silently break sending."""
    with pytest.raises(ValueError, match="must start with"):
        spf_record("example.com", "include:_spf.google.com ~all")


def test_dmarc_record_defaults_to_monitoring_only() -> None:
    """A new domain has no report history, so p=none is the safe starting policy."""
    record = dmarc_record("example.com")
    assert record.name == "_dmarc.example.com"
    assert record.content.startswith("v=DMARC1; p=none")


def test_dmarc_record_accepts_a_bare_report_address() -> None:
    """Operators type an email address; DMARC requires the mailto: URI form."""
    record = dmarc_record("example.com", rua="dmarc@example.com")
    assert "rua=mailto:dmarc@example.com" in record.content


def test_dmarc_record_does_not_repeat_an_existing_mailto_prefix() -> None:
    """A value already in URI form must not become mailto:mailto:."""
    record = dmarc_record("example.com", rua="mailto:dmarc@example.com")
    assert record.content.count("mailto:") == 1


def test_dmarc_pct_is_omitted_when_it_is_the_default() -> None:
    """pct=100 is the RFC default, so emitting it adds noise without meaning."""
    assert "pct=" not in dmarc_record("example.com", pct=100).content
    assert "pct=25" in dmarc_record("example.com", pct=25).content


@pytest.mark.parametrize("policy", ["off", "reject-all", ""])
def test_dmarc_rejects_an_invalid_policy(policy: str) -> None:
    """An invalid p= value makes receivers ignore the record entirely."""
    with pytest.raises(ValueError, match="policy must be one of"):
        dmarc_record("example.com", policy=policy)


@pytest.mark.parametrize("pct", [-1, 101])
def test_dmarc_rejects_an_out_of_range_percentage(pct: int) -> None:
    """pct is a percentage; out-of-range values are a configuration mistake."""
    with pytest.raises(ValueError, match="pct must be between"):
        dmarc_record("example.com", pct=pct)


def test_dkim_record_name_uses_the_selector() -> None:
    """Google looks for the key at <selector>._domainkey.<domain>."""
    record = dkim_record("example.com", SAMPLE_KEY, selector="google")
    assert record.name == "google._domainkey.example.com"
    assert record.match_prefix == "v=DKIM1"


def test_dkim_accepts_a_bare_public_key_and_adds_the_tags() -> None:
    """The Admin console sometimes shows only the key, not the whole record."""
    record = dkim_record("example.com", SAMPLE_KEY)
    assert record.content.startswith("v=DKIM1; k=rsa; p=")
    assert dkim_public_key(record.content) == SAMPLE_KEY


def test_dkim_accepts_a_full_record_unchanged_in_meaning() -> None:
    """Pasting the whole 'v=DKIM1; k=rsa; p=...' string must also work."""
    record = dkim_record("example.com", f"v=DKIM1; k=rsa; p={SAMPLE_KEY}")
    assert dkim_public_key(record.content) == SAMPLE_KEY


def test_dkim_strips_whitespace_from_a_wrapped_paste() -> None:
    """A key copied from the console arrives wrapped; whitespace breaks the signature."""
    wrapped = f"v=DKIM1; k=rsa; p={SAMPLE_KEY[:40]}\n  {SAMPLE_KEY[40:]}"
    assert dkim_public_key(normalize_dkim_value(wrapped)) == SAMPLE_KEY


def test_dkim_joins_a_value_split_into_quoted_strings() -> None:
    """A 2048-bit key exceeds one TXT string, so consoles present it quoted and split."""
    split = f'"v=DKIM1; k=rsa; p={SAMPLE_KEY[:30]}" "{SAMPLE_KEY[30:]}"'
    assert dkim_public_key(normalize_dkim_value(split)) == SAMPLE_KEY


def test_dkim_rejects_an_empty_value() -> None:
    """An empty paste must fail rather than publish a meaningless record."""
    with pytest.raises(ValueError, match="empty"):
        normalize_dkim_value("   ")


def test_normalize_txt_leaves_an_unquoted_value_alone() -> None:
    """Most TXT values arrive plain; normalisation must not mangle them."""
    assert normalize_txt_value("v=spf1 include:_spf.google.com ~all") == (
        "v=spf1 include:_spf.google.com ~all"
    )


def test_site_verification_record_sits_at_the_apex() -> None:
    """Google checks the ownership token at the zone apex."""
    record = site_verification_record("example.com", "google-site-verification=abc123")
    assert record.name == "example.com"
    assert record.match_prefix == "google-site-verification="


def test_site_verification_record_rejects_an_empty_token() -> None:
    """An empty token would overwrite nothing useful and verify nothing."""
    with pytest.raises(ValueError, match="empty"):
        site_verification_record("example.com", "")
