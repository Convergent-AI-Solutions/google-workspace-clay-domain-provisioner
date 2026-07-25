"""Verify MX, SPF, DKIM and DMARC against public resolvers.

Deliberately does not read the records back from the Cloudflare API. Reading
your own control plane confirms what you asked for, not what a receiving mail
server will see. Every check here resolves through public recursive resolvers.

The ``evaluate_*`` functions are pure — they take the values a resolver
returned and judge them — so the judgement logic is testable without network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .backoff import BackoffPolicy, poll_until
from .dns_records import (
    DMARC_PREFIX,
    GOOGLE_SPF_INCLUDE,
    SPF_PREFIX,
    dkim_public_key,
    normalize_txt_value,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Callable, Sequence

DEFAULT_RESOLVERS: tuple[str, ...] = ("8.8.8.8", "1.1.1.1")


@dataclass(frozen=True)
class CheckResult:
    """The outcome of one record check."""

    name: str
    passed: bool
    detail: str
    found: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class VerificationReport:
    """All four checks for one domain."""

    domain: str
    checks: tuple[CheckResult, ...]

    @property
    def passed(self) -> bool:
        """True only when every check passed."""
        return all(check.passed for check in self.checks)

    @property
    def failures(self) -> tuple[CheckResult, ...]:
        """The checks that did not pass, for a concise error summary."""
        return tuple(check for check in self.checks if not check.passed)


def evaluate_mx(found: Sequence[str], expected_hosts: Sequence[str]) -> CheckResult:
    """Pass when every expected mail host appears in the resolved MX set."""
    normalised = {_normalise_host(host) for host in found}
    wanted = {_normalise_host(host) for host in expected_hosts}
    if not normalised:
        return CheckResult("MX", False, "no MX records resolved", tuple(found))

    missing = sorted(wanted - normalised)
    if missing:
        return CheckResult(
            "MX",
            False,
            f"missing expected mail host(s): {', '.join(missing)}",
            tuple(sorted(normalised)),
        )
    return CheckResult(
        "MX",
        True,
        f"{len(normalised)} mail host(s) resolved, all expected hosts present",
        tuple(sorted(normalised)),
    )


def evaluate_spf(found: Sequence[str], required_include: str = GOOGLE_SPF_INCLUDE) -> CheckResult:
    """Pass on exactly one SPF record that contains the required include.

    Two ``v=spf1`` records on one name is a permanent error under RFC 7208 —
    receivers treat it as no SPF at all — so this fails rather than warns.
    """
    spf_records = [
        value for value in map(normalize_txt_value, found) if value.lower().startswith(SPF_PREFIX)
    ]
    if not spf_records:
        return CheckResult("SPF", False, "no v=spf1 record found", tuple(found))
    if len(spf_records) > 1:
        return CheckResult(
            "SPF",
            False,
            f"{len(spf_records)} SPF records found; RFC 7208 permits exactly one",
            tuple(spf_records),
        )

    record = spf_records[0]
    if required_include and required_include.lower() not in record.lower():
        return CheckResult(
            "SPF",
            False,
            f"record does not contain {required_include!r}",
            (record,),
        )
    return CheckResult("SPF", True, "one SPF record, required include present", (record,))


def evaluate_dkim(found: Sequence[str], expected_public_key: str | None = None) -> CheckResult:
    """Pass when a DKIM record with a public key is present at the selector.

    When ``expected_public_key`` is supplied the keys must match exactly, which
    catches a truncated paste — the common failure with a 2048-bit key split
    across TXT strings.
    """
    keys = [key for key in (dkim_public_key(value) for value in found) if key]
    if not keys:
        return CheckResult("DKIM", False, "no DKIM record with a p= key found", tuple(found))

    if expected_public_key:
        wanted = expected_public_key.strip()
        if wanted not in keys:
            return CheckResult(
                "DKIM",
                False,
                "published key does not match the expected key (check for a truncated paste)",
                tuple(f"{key[:24]}... ({len(key)} chars)" for key in keys),
            )
    return CheckResult(
        "DKIM",
        True,
        f"DKIM key published ({len(keys[0])} chars)",
        (f"{keys[0][:24]}... ({len(keys[0])} chars)",),
    )


def evaluate_dmarc(found: Sequence[str], expected_policy: str | None = None) -> CheckResult:
    """Pass on exactly one DMARC record whose policy matches, when one is expected."""
    records = [
        value
        for value in map(normalize_txt_value, found)
        if value.lower().startswith(DMARC_PREFIX.lower())
    ]
    if not records:
        return CheckResult("DMARC", False, "no v=DMARC1 record found", tuple(found))
    if len(records) > 1:
        return CheckResult(
            "DMARC",
            False,
            f"{len(records)} DMARC records found; exactly one is permitted",
            tuple(records),
        )

    record = records[0]
    policy = _dmarc_tag(record, "p")
    if policy is None:
        return CheckResult("DMARC", False, "record has no p= policy tag", (record,))
    if expected_policy and policy.lower() != expected_policy.lower():
        return CheckResult(
            "DMARC",
            False,
            f"policy is p={policy}, expected p={expected_policy}",
            (record,),
        )
    return CheckResult("DMARC", True, f"one DMARC record, p={policy}", (record,))


@dataclass
class DnsLookup:
    """Thin resolver wrapper, pointed at public recursive resolvers.

    Constructed with ``configure=False`` so the machine's own resolver settings
    — which may be a split-horizon corporate resolver — cannot mask a record
    the public internet cannot see.
    """

    resolvers: Sequence[str] = DEFAULT_RESOLVERS
    timeout: float = 5.0

    def __post_init__(self) -> None:
        import dns.resolver  # imported here so pure evaluators need no dnspython

        self._resolver = dns.resolver.Resolver(configure=False)
        self._resolver.nameservers = list(self.resolvers)
        self._resolver.timeout = self.timeout
        self._resolver.lifetime = self.timeout * 2

    def txt(self, name: str) -> list[str]:
        """All TXT values at ``name``, each already joined from its parts."""
        return [
            "".join(part.decode("utf-8", "replace") for part in rdata.strings)
            for rdata in self._query(name, "TXT")
        ]

    def mx(self, name: str) -> list[str]:
        """The mail exchange hostnames at ``name``, without trailing dots."""
        return [str(rdata.exchange).rstrip(".").lower() for rdata in self._query(name, "MX")]

    def _query(self, name: str, record_type: str) -> list:
        import dns.resolver

        try:
            return list(self._resolver.resolve(name, record_type))
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
        ):
            return []


def verify_domain(
    lookup: DnsLookup,
    domain: str,
    *,
    expected_mx_hosts: Sequence[str],
    spf_include: str = GOOGLE_SPF_INCLUDE,
    dkim_selector: str = "google",
    expected_dkim_key: str | None = None,
    expected_dmarc_policy: str | None = None,
) -> VerificationReport:
    """Run all four checks once and return the report."""
    return VerificationReport(
        domain=domain,
        checks=(
            evaluate_mx(lookup.mx(domain), expected_mx_hosts),
            evaluate_spf(lookup.txt(domain), spf_include),
            evaluate_dkim(lookup.txt(f"{dkim_selector}._domainkey.{domain}"), expected_dkim_key),
            evaluate_dmarc(lookup.txt(f"_dmarc.{domain}"), expected_dmarc_policy),
        ),
    )


def verify_with_retry(
    lookup: DnsLookup,
    domain: str,
    policy: BackoffPolicy,
    *,
    on_wait: Callable[[int, float], None] | None = None,
    on_attempt: Callable[[VerificationReport], None] | None = None,
    **checks: object,
) -> VerificationReport:
    """Re-verify on a jittered interval until everything passes or attempts run out.

    Returns the last report either way — a caller wants the detail of what is
    still missing, not just a boolean. DNS propagation taking several minutes
    is normal and is not treated as an error until the budget is spent.
    """
    last: dict[str, VerificationReport] = {}

    def probe() -> VerificationReport | None:
        report = verify_domain(lookup, domain, **checks)  # type: ignore[arg-type]
        last["report"] = report
        if on_attempt is not None:
            on_attempt(report)
        return report if report.passed else None

    result = poll_until(probe, policy, on_wait=on_wait)
    return result or last["report"]


def _normalise_host(host: str) -> str:
    return host.strip().rstrip(".").lower()


def _dmarc_tag(record: str, tag: str) -> str | None:
    for part in record.split(";"):
        cleaned = part.strip()
        if cleaned.lower().startswith(f"{tag.lower()}="):
            return cleaned[len(tag) + 1 :].strip()
    return None
