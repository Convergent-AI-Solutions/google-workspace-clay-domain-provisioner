"""Unit tests for record matching — what makes re-running a step safe.

``find_match`` decides whether a spec updates an existing record or creates a
new one. Getting it wrong either duplicates records or overwrites an unrelated
one, so it is tested directly against realistic Cloudflare payloads.
"""

from __future__ import annotations

from google_workspace_clay_provisioner.cloudflare.dns import find_match
from google_workspace_clay_provisioner.dns_records import (
    dkim_record,
    dmarc_record,
    mx_records,
    site_verification_record,
    spf_record,
)

SAMPLE_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest" * 3


def record(**fields: object) -> dict:
    """A Cloudflare DNS record payload with sensible defaults."""
    base = {"id": "rec1", "type": "TXT", "name": "example.com", "content": "", "ttl": 1}
    base.update(fields)
    return base


def test_spf_updates_the_existing_spf_record_not_the_verification_token() -> None:
    """Both live at the apex; matching on name alone would clobber the token."""
    existing = [
        record(id="token", content="google-site-verification=abc123"),
        record(id="spf", content="v=spf1 include:old.example ~all"),
    ]
    match = find_match(existing, spf_record("example.com"))
    assert match is not None
    assert match["id"] == "spf"


def test_verification_token_updates_the_token_not_the_spf_record() -> None:
    """The mirror image of the case above, and the reason match_prefix exists."""
    existing = [
        record(id="spf", content="v=spf1 include:_spf.google.com ~all"),
        record(id="token", content="google-site-verification=old"),
    ]
    spec = site_verification_record("example.com", "google-site-verification=new")
    match = find_match(existing, spec)
    assert match is not None
    assert match["id"] == "token"


def test_no_match_returns_none_so_the_record_is_created() -> None:
    """An empty zone must produce creates, not updates."""
    assert find_match([], spf_record("example.com")) is None


def test_dmarc_matches_only_at_the_dmarc_name() -> None:
    """A DMARC spec must not match a TXT record sitting at the apex."""
    apex_only = [record(id="spf", content="v=spf1 include:_spf.google.com ~all")]
    assert find_match(apex_only, dmarc_record("example.com")) is None

    at_dmarc = [record(id="dmarc", name="_dmarc.example.com", content="v=DMARC1; p=none")]
    match = find_match(at_dmarc, dmarc_record("example.com", policy="reject"))
    assert match is not None
    assert match["id"] == "dmarc"


def test_dkim_matches_at_the_selector_name() -> None:
    """The DKIM record lives under the selector, not at the apex."""
    existing = [
        record(
            id="dkim",
            name="google._domainkey.example.com",
            content=f"v=DKIM1; k=rsa; p={SAMPLE_KEY[:20]}",
        )
    ]
    match = find_match(existing, dkim_record("example.com", SAMPLE_KEY))
    assert match is not None
    assert match["id"] == "dkim"


def test_dkim_matches_a_record_stored_as_split_quoted_strings() -> None:
    """Cloudflare may return a long TXT value quoted and split; it still matches."""
    existing = [
        record(
            id="dkim",
            name="google._domainkey.example.com",
            content=f'"v=DKIM1; k=rsa; p={SAMPLE_KEY[:30]}" "{SAMPLE_KEY[30:]}"',
        )
    ]
    assert find_match(existing, dkim_record("example.com", SAMPLE_KEY)) is not None


def test_mx_matches_on_target_host_so_a_multi_host_set_survives() -> None:
    """The legacy layout has five MX records; each must find its own, not the first."""
    existing = [
        record(id="mx1", type="MX", content="aspmx.l.google.com", priority=1),
        record(id="mx2", type="MX", content="alt1.aspmx.l.google.com", priority=5),
    ]
    specs = mx_records("example.com", "legacy")
    matched_ids = {
        find_match(existing, spec)["id"]  # type: ignore[index]
        for spec in specs[:2]
    }
    assert matched_ids == {"mx1", "mx2"}


def test_mx_ignores_trailing_dots_when_matching() -> None:
    """Cloudflare may store the target fully qualified with a trailing dot."""
    existing = [record(id="mx", type="MX", content="smtp.google.com.", priority=1)]
    match = find_match(existing, mx_records("example.com", "single")[0])
    assert match is not None
    assert match["id"] == "mx"


def test_mx_for_a_host_not_yet_present_returns_none() -> None:
    """Switching from single to legacy must add the missing hosts, not edit one."""
    existing = [record(id="mx", type="MX", content="smtp.google.com", priority=1)]
    assert find_match(existing, mx_records("example.com", "legacy")[1]) is None


def test_matching_is_case_insensitive_on_name_and_type() -> None:
    """API responses vary in case; the match must not depend on it."""
    existing = [record(id="spf", name="EXAMPLE.COM", type="txt", content="v=spf1 -all")]
    match = find_match(existing, spf_record("example.com"))
    assert match is not None
    assert match["id"] == "spf"
