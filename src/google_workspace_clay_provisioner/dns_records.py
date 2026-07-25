"""Build the DNS record specifications for a Google Workspace sending domain.

Pure: this module decides *what* the records should say. Publishing them is
``cloudflare/dns.py``, and confirming the world can see them is ``verify.py``.

Each spec carries a ``match_prefix`` so the publisher can find and update the
right record when several TXT records share a name — the zone apex normally
holds an SPF record and a site-verification token at the same time, and
matching on name alone would overwrite one with the other.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

MxMode = Literal["single", "legacy"]

#: Google's current single-host mail route.
SINGLE_MX_HOST = "smtp.google.com"

#: The five-record set Google published before ``smtp.google.com``. Still valid;
#: kept because some operators standardise on it across an existing estate.
LEGACY_MX_HOSTS: tuple[tuple[str, int], ...] = (
    ("aspmx.l.google.com", 1),
    ("alt1.aspmx.l.google.com", 5),
    ("alt2.aspmx.l.google.com", 5),
    ("alt3.aspmx.l.google.com", 10),
    ("alt4.aspmx.l.google.com", 10),
)

DEFAULT_SPF_VALUE = "v=spf1 include:_spf.google.com ~all"
GOOGLE_SPF_INCLUDE = "include:_spf.google.com"
DEFAULT_DKIM_SELECTOR = "google"
DMARC_POLICIES = ("none", "quarantine", "reject")

SPF_PREFIX = "v=spf1"
DMARC_PREFIX = "v=DMARC1"
DKIM_PREFIX = "v=DKIM1"
SITE_VERIFICATION_PREFIX = "google-site-verification="

#: Cloudflare treats TTL 1 as "automatic", which is what a freshly registered
#: domain wants — short enough to correct a mistake quickly.
AUTOMATIC_TTL = 1

_QUOTED_CHUNK = re.compile(r'"([^"]*)"')


@dataclass(frozen=True)
class DnsRecordSpec:
    """One record to publish, in a form the Cloudflare DNS API accepts."""

    type: str
    name: str
    content: str
    priority: int | None = None
    ttl: int = AUTOMATIC_TTL
    match_prefix: str | None = None
    label: str = ""

    def __post_init__(self) -> None:
        if self.type == "MX" and self.priority is None:
            raise ValueError("MX records require a priority")
        if not self.name or not self.content:
            raise ValueError("record name and content are both required")


def normalize_txt_value(raw: str) -> str:
    """Join a TXT value that arrives as adjacent quoted strings.

    A 2048-bit DKIM key exceeds the 255-byte limit for a single TXT string, so
    resolvers and consoles present it split and quoted. The parts concatenate
    with no separator, which is what a verifier compares against.
    """
    text = raw.strip()
    chunks = _QUOTED_CHUNK.findall(text)
    if chunks:
        return "".join(chunks).strip()
    return text


def normalize_dkim_value(raw: str) -> str:
    """Accept either a full DKIM record or a bare public key, return the record.

    Google's Admin console presents the value with line breaks and sometimes
    without the leading tags, and whitespace inside the base64 key breaks the
    signature check. Whitespace is stripped from every tag value.
    """
    text = normalize_txt_value(raw)
    if not text:
        raise ValueError("DKIM value is empty")

    if text.lower().replace(" ", "").startswith("v=dkim1"):
        rebuilt = []
        for tag in (part.strip() for part in text.split(";")):
            if not tag:
                continue
            rebuilt.append(re.sub(r"\s+", "", tag))
        return "; ".join(rebuilt)

    key = re.sub(r"\s+", "", text)
    return f"{DKIM_PREFIX}; k=rsa; p={key}"


def dkim_public_key(value: str) -> str | None:
    """Extract the ``p=`` base64 key from a DKIM record, or ``None`` if absent."""
    for tag in normalize_txt_value(value).split(";"):
        cleaned = tag.strip()
        if cleaned.lower().startswith("p="):
            return re.sub(r"\s+", "", cleaned[2:])
    return None


def mx_records(domain: str, mode: MxMode = "single") -> list[DnsRecordSpec]:
    """MX records routing ``domain`` to Google, either the single host or the five."""
    if mode == "single":
        hosts: tuple[tuple[str, int], ...] = ((SINGLE_MX_HOST, 1),)
    elif mode == "legacy":
        hosts = LEGACY_MX_HOSTS
    else:
        raise ValueError(f"unknown MX mode: {mode!r} (expected 'single' or 'legacy')")

    return [
        DnsRecordSpec(
            type="MX",
            name=domain,
            content=host,
            priority=priority,
            label=f"MX {priority} {host}",
        )
        for host, priority in hosts
    ]


def spf_record(domain: str, value: str = DEFAULT_SPF_VALUE) -> DnsRecordSpec:
    """The single SPF TXT record at the zone apex.

    More than one ``v=spf1`` record on a name is a permanent error under
    RFC 7208, so this always produces exactly one and the publisher updates
    rather than adds.
    """
    cleaned = normalize_txt_value(value)
    if not cleaned.lower().startswith(SPF_PREFIX):
        raise ValueError(f"SPF value must start with {SPF_PREFIX!r}: {value!r}")
    return DnsRecordSpec(
        type="TXT",
        name=domain,
        content=cleaned,
        match_prefix=SPF_PREFIX,
        label="SPF",
    )


def dkim_record(
    domain: str,
    value: str,
    selector: str = DEFAULT_DKIM_SELECTOR,
) -> DnsRecordSpec:
    """The DKIM TXT record at ``<selector>._domainkey.<domain>``.

    ``value`` must come from the Google Admin console: Google generates the
    key pair, keeps the private half, and exposes the public half only there.
    There is no API for it, which is why this argument is required.
    """
    if not selector:
        raise ValueError("DKIM selector is required")
    return DnsRecordSpec(
        type="TXT",
        name=f"{selector}._domainkey.{domain}",
        content=normalize_dkim_value(value),
        match_prefix=DKIM_PREFIX,
        label=f"DKIM ({selector})",
    )


def dmarc_record(
    domain: str,
    *,
    policy: str = "none",
    rua: str | None = None,
    ruf: str | None = None,
    pct: int = 100,
    subdomain_policy: str | None = None,
) -> DnsRecordSpec:
    """The DMARC TXT record at ``_dmarc.<domain>``.

    ``policy`` defaults to ``none`` because a brand-new sending domain has no
    reputation and no report history yet; tighten to ``quarantine`` or
    ``reject`` once the aggregate reports show only your own mail passing.
    """
    if policy not in DMARC_POLICIES:
        raise ValueError(f"DMARC policy must be one of {DMARC_POLICIES}: {policy!r}")
    if subdomain_policy is not None and subdomain_policy not in DMARC_POLICIES:
        raise ValueError(f"DMARC subdomain policy must be one of {DMARC_POLICIES}")
    if not 0 <= pct <= 100:
        raise ValueError(f"DMARC pct must be between 0 and 100: {pct}")

    tags = [DMARC_PREFIX, f"p={policy}"]
    if subdomain_policy is not None:
        tags.append(f"sp={subdomain_policy}")
    if rua:
        tags.append(f"rua={_as_mailto(rua)}")
    if ruf:
        tags.append(f"ruf={_as_mailto(ruf)}")
    if pct != 100:
        tags.append(f"pct={pct}")

    return DnsRecordSpec(
        type="TXT",
        name=f"_dmarc.{domain}",
        content="; ".join(tags),
        match_prefix=DMARC_PREFIX,
        label="DMARC",
    )


def site_verification_record(domain: str, token: str) -> DnsRecordSpec:
    """The TXT record proving domain ownership to Google Site Verification."""
    cleaned = normalize_txt_value(token)
    if not cleaned:
        raise ValueError("site verification token is empty")
    return DnsRecordSpec(
        type="TXT",
        name=domain,
        content=cleaned,
        match_prefix=SITE_VERIFICATION_PREFIX,
        label="Google site verification",
    )


def _as_mailto(address: str) -> str:
    """Allow a bare address in config; DMARC requires the ``mailto:`` URI form."""
    cleaned = address.strip()
    return cleaned if cleaned.startswith("mailto:") else f"mailto:{cleaned}"
