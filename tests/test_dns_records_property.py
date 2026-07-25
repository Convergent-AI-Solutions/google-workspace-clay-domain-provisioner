"""Property tests for the record builders and their normalisation.

The DKIM properties matter most: a key that survives normalisation with a
single altered character produces mail that fails authentication, and nothing
downstream would notice.
"""

from __future__ import annotations

import pytest

pytest.importorskip("hypothesis", reason="hypothesis is an optional dev dependency")

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from cold_email_domain_provisioner.dns_records import (  # noqa: E402
    DMARC_POLICIES,
    dkim_public_key,
    dkim_record,
    dmarc_record,
    mx_records,
    normalize_dkim_value,
    normalize_txt_value,
    spf_record,
)
from cold_email_domain_provisioner.verify import evaluate_dmarc, evaluate_mx  # noqa: E402

domains = st.from_regex(r"\A[a-z0-9]([a-z0-9-]{0,18}[a-z0-9])?\.com\Z", fullmatch=True)
base64_keys = st.text(
    alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    min_size=20,
    max_size=400,
).map(lambda text: text + "==")
policies = st.sampled_from(DMARC_POLICIES)
selectors = st.from_regex(r"\A[a-z0-9]{1,15}\Z", fullmatch=True)


@settings(max_examples=200)
@given(key=base64_keys)
def test_a_bare_key_round_trips_through_the_builder(key: str) -> None:
    """What the console shows must be exactly what lands in DNS."""
    assert dkim_public_key(normalize_dkim_value(key)) == key


@settings(max_examples=200)
@given(key=base64_keys)
def test_a_full_record_round_trips_through_the_builder(key: str) -> None:
    """Pasting the whole v=DKIM1 string must preserve the key byte for byte."""
    assert dkim_public_key(normalize_dkim_value(f"v=DKIM1; k=rsa; p={key}")) == key


@settings(max_examples=200)
@given(key=base64_keys, split=st.integers(min_value=1, max_value=19))
def test_a_key_split_into_quoted_strings_round_trips(key: str, split: int) -> None:
    """Long TXT values are presented split; joining them must not lose characters."""
    quoted = f'"v=DKIM1; k=rsa; p={key[:split]}" "{key[split:]}"'
    assert dkim_public_key(normalize_dkim_value(quoted)) == key


@settings(max_examples=200)
@given(key=base64_keys)
def test_normalisation_is_idempotent(key: str) -> None:
    """Re-normalising a stored value must not change it, or comparisons drift."""
    once = normalize_dkim_value(key)
    assert normalize_dkim_value(once) == once


@settings(max_examples=200)
@given(domain=domains, key=base64_keys, selector=selectors)
def test_dkim_record_name_is_always_under_the_selector(
    domain: str, key: str, selector: str
) -> None:
    """Google only looks under <selector>._domainkey, so the name is not optional."""
    record = dkim_record(domain, key, selector=selector)
    assert record.name == f"{selector}._domainkey.{domain}"


@settings(max_examples=200)
@given(domain=domains, policy=policies, pct=st.integers(min_value=0, max_value=100))
def test_dmarc_records_are_always_accepted_by_the_verifier(
    domain: str, policy: str, pct: int
) -> None:
    """Whatever the builder emits, the verifier must recognise as that policy."""
    record = dmarc_record(domain, policy=policy, pct=pct)
    assert evaluate_dmarc([record.content], policy).passed


@settings(max_examples=100)
@given(domain=domains, mode=st.sampled_from(["single", "legacy"]))
def test_published_mx_hosts_satisfy_their_own_verification(domain: str, mode: str) -> None:
    """The builder and the verifier must agree, or a correct run reports failure."""
    hosts = [spec.content for spec in mx_records(domain, mode)]  # type: ignore[arg-type]
    assert evaluate_mx(hosts, hosts).passed


@settings(max_examples=100)
@given(domain=domains)
def test_spf_records_always_sit_at_the_apex(domain: str) -> None:
    """SPF is only consulted at the envelope-sender domain itself."""
    assert spf_record(domain).name == domain


@settings(max_examples=200)
@given(text=st.text(max_size=200))
def test_txt_normalisation_never_raises(text: str) -> None:
    """Normalisation runs on whatever a resolver returns, so it must be total."""
    assert isinstance(normalize_txt_value(text), str)
