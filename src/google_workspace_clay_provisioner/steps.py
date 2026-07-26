"""The seven provisioning steps, independent of how they are invoked.

Each function takes explicit configuration, reports progress through an
``echo`` callable, records completion in ``RunState``, and returns its result.
No function here reads the environment, prompts, or prints directly, so the CLI
owns all interaction and these stay straightforward to test.

Ordering constraints worth knowing before changing anything:

* Site verification needs the token record live in DNS *before* Google is asked
  to check it.
* The DKIM record cannot be built until a person has generated the key in the
  Admin console, because Google exposes the public key nowhere else.
* Verification reads public resolvers, so it is the only honest confirmation
  that the earlier writes took effect.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from . import dns_records as records_module
from .backoff import BackoffPolicy
from .clay import ClayMailboxRow, write_clay_csv
from .cloudflare import dns as cf_dns
from .cloudflare import registrar as cf_registrar
from .cloudflare.client import CloudflareClient
from .config import DnsConfig, MailboxConfig, RegistrantContact
from .dns_records import DnsRecordSpec
from .errors import GoogleError, ProvisionerError, PurchaseAborted
from .google import domains as gdomains
from .google import siteverify as gsiteverify
from .google import users as gusers
from .state import (
    STEP_CLAY,
    STEP_DKIM,
    STEP_DNS,
    STEP_MAILBOX,
    STEP_REGISTER,
    STEP_VERIFY_OWNERSHIP,
    STEP_VERIFY_RECORDS,
    STEP_WORKSPACE_DOMAIN,
    RunState,
)
from .suggest import Candidate, generate_candidates
from .verify import DnsLookup, VerificationReport, verify_with_retry

Echo = Callable[[str], None]


@dataclass(frozen=True)
class SuggestionRow:
    """A generated candidate paired with what Cloudflare says about it."""

    candidate: Candidate
    offer: cf_registrar.DomainOffer

    @property
    def is_available(self) -> bool:
        return self.offer.available is True


def suggest_domains(
    client: CloudflareClient,
    account_id: str,
    seed: str,
    *,
    limit: int = 20,
    allow_hyphen: bool = False,
    echo: Echo = lambda _: None,
) -> list[SuggestionRow]:
    """Generate candidates from ``seed`` and check each against the registry.

    Availability comes from ``domain-check``, which queries the registry
    directly, not from the cached search endpoint.
    """
    candidates = generate_candidates(seed, allow_hyphen=allow_hyphen, limit=limit)
    if not candidates:
        return []

    echo(f"Checking {len(candidates)} candidate domain(s) against the registry...")
    offers = cf_registrar.check_domains(client, account_id, [c.domain for c in candidates])
    return [
        SuggestionRow(candidate, offer)
        for candidate, offer in zip(candidates, offers, strict=True)
    ]


def purchase_domain(
    client: CloudflareClient,
    account_id: str,
    domain: str,
    state: RunState,
    *,
    registrant: RegistrantContact,
    years: int | None = None,
    confirmed: bool = False,
    dry_run: bool = False,
    policy: BackoffPolicy | None = None,
    echo: Echo = lambda _: None,
) -> str:
    """Register ``domain``. Refuses to spend money without ``confirmed``.

    Returns ``"registered"``, ``"already-owned"``, or ``"would-register"``.
    Ownership is checked first so a resumed run never pays twice.
    """
    if state.is_done(STEP_REGISTER):
        echo(f"{domain} was already registered by an earlier run.")
        return "already-owned"

    if cf_registrar.get_owned_domain(client, account_id, domain) is not None:
        echo(f"{domain} is already in this Cloudflare account.")
        state.mark_done(STEP_REGISTER, domain=domain, outcome="already-owned")
        return "already-owned"

    if dry_run:
        echo(f"[dry run] would register {domain}")
        return "would-register"
    if not confirmed:
        raise PurchaseAborted(
            f"registration of {domain} was not confirmed. This charges the "
            f"Cloudflare account and cannot be refunded."
        )

    payload = None if registrant.is_empty else registrant.to_payload()
    if payload is None:
        echo("Using the Cloudflare account's default registrant contact.")

    result = cf_registrar.register_domain(
        client, account_id, domain, registrant=payload, years=years
    )
    if result.pending:
        echo("Cloudflare accepted the registration (HTTP 202). Waiting for it to complete...")
        cf_registrar.wait_until_registered(
            client,
            account_id,
            domain,
            policy or BackoffPolicy(attempts=10, base_seconds=15, jitter_seconds=10),
            on_wait=lambda attempt, delay: echo(
                f"  not owned yet (attempt {attempt}); waiting {delay:.0f}s"
            ),
        )

    echo(f"{domain} is registered.")
    state.mark_done(STEP_REGISTER, domain=domain, outcome="registered")
    return "registered"


def add_workspace_domain(
    directory,
    domain: str,
    state: RunState,
    *,
    customer_id: str = "my_customer",
    dry_run: bool = False,
    echo: Echo = lambda _: None,
) -> str:
    """Add ``domain`` to Workspace as a secondary domain."""
    if state.is_done(STEP_WORKSPACE_DOMAIN):
        echo(f"{domain} is already a Workspace domain.")
        return "exists"

    action = gdomains.add_secondary_domain(
        directory, domain, customer_id=customer_id, dry_run=dry_run
    )
    echo(
        {
            "created": f"Added {domain} to Workspace as a secondary domain.",
            "exists": f"{domain} is already a Workspace domain.",
            "would-create": f"[dry run] would add {domain} as a secondary domain",
        }[action]
    )
    if action != "would-create":
        state.mark_done(STEP_WORKSPACE_DOMAIN, domain=domain, outcome=action)
    return action


def verify_domain_ownership(
    directory,
    site_verification,
    client: CloudflareClient,
    account_id: str,
    domain: str,
    state: RunState,
    *,
    customer_id: str = "my_customer",
    create_zone: bool = False,
    dry_run: bool = False,
    policy: BackoffPolicy | None = None,
    lookup: DnsLookup | None = None,
    echo: Echo = lambda _: None,
) -> str:
    """Publish Google's ownership token, wait for DNS, then verify.

    The wait is not optional: asking Google to verify before the token resolves
    fails, and repeated failures are rate-limited.

    A dry run returns before requesting a token. ``getToken`` is an authenticated
    Google call, so fetching one to describe a run nobody asked to perform would
    both need live credentials and consume a token that is never published.
    """
    if state.is_done(STEP_VERIFY_OWNERSHIP) or gdomains.is_verified(directory, domain, customer_id):
        echo(f"Ownership of {domain} is already verified.")
        state.mark_done(STEP_VERIFY_OWNERSHIP, domain=domain, outcome="already-verified")
        return "already-verified"

    if dry_run:
        _preview_ownership_verification(
            client, account_id, domain, create_zone=create_zone, echo=echo
        )
        return "would-verify"

    token = gsiteverify.get_dns_token(site_verification, domain)
    spec = records_module.site_verification_record(domain, token)

    zone_id = cf_dns.require_zone_id(client, account_id, domain, create_if_missing=create_zone)
    if zone_id is None:  # unreachable outside a dry run; require_zone_id raises instead
        raise ProvisionerError(f"no Cloudflare zone available for {domain}")
    outcome = cf_dns.upsert_record(client, zone_id, spec)
    echo(f"Ownership token record: {outcome.action} ({spec.name})")

    wait_policy = policy or BackoffPolicy(attempts=12, base_seconds=20, jitter_seconds=10)
    _await_txt(
        lookup or DnsLookup(),
        domain,
        spec.content,
        wait_policy,
        echo=echo,
        label="ownership token",
    )

    action = gsiteverify.verify_domain(site_verification, domain)
    echo(f"Google site verification: {action}")

    if not gdomains.is_verified(directory, domain, customer_id):
        raise GoogleError(
            f"Google verified the token but Workspace still reports {domain} as "
            f"unverified. Workspace can lag by a minute or two, so re-run this step."
        )
    echo(f"Workspace reports {domain} as verified.")
    state.mark_done(STEP_VERIFY_OWNERSHIP, domain=domain, outcome=action)
    return action


def create_mailbox(
    directory,
    domain: str,
    mailbox: MailboxConfig,
    state: RunState,
    *,
    dry_run: bool = False,
    echo: Echo = lambda _: None,
) -> tuple[str, str | None, str]:
    """Create the sending mailbox. Returns ``(email, password, action)``.

    The password is returned only when this call created the user, and is the
    caller's responsibility to surface — it is deliberately not persisted.
    """
    email = mailbox.address(domain)
    if state.is_done(STEP_MAILBOX):
        echo(f"{email} was already created by an earlier run.")
        return email, None, "exists"

    password = gusers.generate_password()
    action, issued = gusers.create_user(
        directory,
        email,
        given_name=mailbox.given_name,
        family_name=mailbox.family_name,
        password=password,
        change_password_at_next_login=mailbox.change_password_at_next_login,
        dry_run=dry_run,
    )
    echo(
        {
            "created": f"Created {email}.",
            "exists": f"{email} already exists.",
            "would-create": f"[dry run] would create {email}",
        }[action]
    )
    if action != "would-create":
        state.mark_done(STEP_MAILBOX, email=email, outcome=action)
    return email, issued, action


def publish_mail_records(
    client: CloudflareClient,
    account_id: str,
    domain: str,
    dns_config: DnsConfig,
    state: RunState,
    *,
    create_zone: bool = False,
    prune_stale_mx: bool = False,
    dry_run: bool = False,
    echo: Echo = lambda _: None,
) -> tuple[list[DnsRecordSpec], list[cf_dns.UpsertOutcome]]:
    """Publish MX, SPF and DMARC. DKIM is separate — it needs a human first."""
    specs = build_mail_specs(domain, dns_config)
    zone_id = cf_dns.require_zone_id(
        client, account_id, domain, create_if_missing=create_zone, dry_run=dry_run
    )
    if zone_id is None:
        echo(f"  [dry run] would create the Cloudflare zone for {domain} first")
        for spec in specs:
            echo(f"  [dry run] would create {spec.label or spec.type} at {spec.name}")
        return specs, []

    outcomes = cf_dns.apply_specs(client, zone_id, specs, dry_run=dry_run)
    for outcome in outcomes:
        echo(f"  {outcome.spec.label or outcome.spec.type}: {outcome.action}")

    if prune_stale_mx:
        expected = [spec.content for spec in specs if spec.type == "MX"]
        for pruned in cf_dns.prune_unexpected_mx(
            client, zone_id, domain, expected, dry_run=dry_run
        ):
            echo(f"  {pruned.spec.label}: {pruned.action}")

    if not dry_run:
        state.mark_done(
            STEP_DNS,
            domain=domain,
            mx_mode=dns_config.mx_mode,
            dmarc_policy=dns_config.dmarc_policy,
            record_count=len(specs),
        )
    return specs, outcomes


def build_mail_specs(domain: str, dns_config: DnsConfig) -> list[DnsRecordSpec]:
    """The MX, SPF and DMARC specs for ``domain`` — pure, for preview and tests."""
    specs = list(records_module.mx_records(domain, dns_config.mx_mode))
    specs.append(records_module.spf_record(domain, dns_config.spf_value))
    specs.append(
        records_module.dmarc_record(
            domain,
            policy=dns_config.dmarc_policy,
            rua=dns_config.dmarc_rua or None,
            pct=dns_config.dmarc_pct,
        )
    )
    return specs


def publish_dkim_record(
    client: CloudflareClient,
    account_id: str,
    domain: str,
    dkim_value: str,
    dns_config: DnsConfig,
    state: RunState,
    *,
    create_zone: bool = False,
    dry_run: bool = False,
    echo: Echo = lambda _: None,
) -> tuple[DnsRecordSpec, cf_dns.UpsertOutcome]:
    """Publish the DKIM TXT record from a value generated in the Admin console."""
    spec = records_module.dkim_record(domain, dkim_value, selector=dns_config.dkim_selector)
    zone_id = cf_dns.require_zone_id(
        client, account_id, domain, create_if_missing=create_zone, dry_run=dry_run
    )
    if zone_id is None:
        echo(f"  [dry run] would create the Cloudflare zone for {domain} first")
        outcome = cf_dns.UpsertOutcome(spec, "would-create")
        echo(f"  [dry run] would create {spec.label} at {spec.name}")
        return spec, outcome

    outcome = cf_dns.upsert_record(client, zone_id, spec, dry_run=dry_run)
    echo(f"  {spec.label}: {outcome.action} ({spec.name})")

    if not dry_run:
        key = records_module.dkim_public_key(spec.content)
        state.mark_done(
            STEP_DKIM,
            domain=domain,
            selector=dns_config.dkim_selector,
            key_length=len(key or ""),
        )
    return spec, outcome


def verify_records(
    domain: str,
    dns_config: DnsConfig,
    state: RunState,
    *,
    lookup: DnsLookup | None = None,
    expected_dkim_key: str | None = None,
    policy: BackoffPolicy | None = None,
    dry_run: bool = False,
    echo: Echo = lambda _: None,
) -> VerificationReport:
    """Check all four records against public resolvers, retrying on propagation.

    Resolving is read-only, so the checks themselves run in a dry run. The state
    write does not: recording a step during a preview would make a later real run
    skip it.
    """
    expected_hosts = [
        spec.content for spec in records_module.mx_records(domain, dns_config.mx_mode)
    ]
    wait_policy = policy or BackoffPolicy(attempts=10, base_seconds=20, jitter_seconds=10)

    report = verify_with_retry(
        lookup or DnsLookup(),
        domain,
        wait_policy,
        on_wait=lambda attempt, delay: echo(
            f"  records incomplete (attempt {attempt}); waiting {delay:.0f}s"
        ),
        expected_mx_hosts=expected_hosts,
        spf_include=records_module.GOOGLE_SPF_INCLUDE,
        dkim_selector=dns_config.dkim_selector,
        expected_dkim_key=expected_dkim_key,
        expected_dmarc_policy=dns_config.dmarc_policy,
    )

    for check in report.checks:
        echo(f"  {check.name}: {'pass' if check.passed else 'FAIL'} - {check.detail}")

    if not dry_run:
        state.mark_done(
            STEP_VERIFY_RECORDS,
            domain=domain,
            passed=report.passed,
            failures=[check.name for check in report.failures],
        )
    return report


def prepare_clay_import(
    domain: str,
    email: str,
    mailbox: MailboxConfig,
    state: RunState,
    *,
    output_dir: Path,
    daily_limit: int = 20,
    dry_run: bool = False,
    echo: Echo = lambda _: None,
) -> Path:
    """Write the Clay SMTP import CSV. The rest of step 7 is manual by necessity.

    Writing a file is a change to the operator's filesystem, so a dry run reports
    the path it would write and leaves the disk alone.
    """
    row = ClayMailboxRow(
        email=email,
        first_name=mailbox.given_name,
        last_name=mailbox.family_name,
        daily_limit=daily_limit,
        warmup_enabled=True,
    )
    path = output_dir / f"{domain}.clay.csv"
    if dry_run:
        echo(f"[dry run] would write {path}")
        return path

    write_clay_csv(path, [row])
    echo(f"Wrote {path}")
    state.mark_done(STEP_CLAY, domain=domain, csv=str(path))
    return path


def _preview_ownership_verification(
    client: CloudflareClient,
    account_id: str,
    domain: str,
    *,
    create_zone: bool,
    echo: Echo,
) -> None:
    """Describe the ownership-verification step without performing any part of it.

    Only reads: a zone lookup, so the preview can say whether the zone has to be
    created first. No Google call, so this works without live credentials.
    """
    echo(f"[dry run] would request a Google ownership token for {domain}")

    zone_id = cf_dns.get_zone_id(client, account_id, domain)
    if zone_id is None:
        if create_zone:
            echo(f"[dry run] no Cloudflare zone for {domain}; it would be created")
        else:
            echo(
                f"[dry run] no Cloudflare zone for {domain}; a real run would fail "
                f"here unless the create-zone option is set"
            )
    echo(f"[dry run] would publish the token as a TXT record at {domain}")
    echo("[dry run] would wait for it to resolve publicly, then ask Google to verify")


def _await_txt(
    lookup: DnsLookup,
    name: str,
    expected: str,
    policy: BackoffPolicy,
    *,
    echo: Echo,
    label: str,
) -> None:
    """Block until ``expected`` appears in the TXT values at ``name``."""
    from .backoff import poll_until

    def probe() -> bool | None:
        values = [records_module.normalize_txt_value(value) for value in lookup.txt(name)]
        return True if expected in values else None

    echo(f"Waiting for the {label} to resolve publicly (up to {policy.worst_case_seconds:.0f}s)...")
    found = poll_until(
        probe,
        policy,
        on_wait=lambda attempt, delay: echo(
            f"  not visible yet (attempt {attempt}); waiting {delay:.0f}s"
        ),
    )
    if not found:
        raise ProvisionerError(
            f"the {label} for {name} did not resolve within "
            f"{policy.worst_case_seconds:.0f}s. The record is published in "
            f"Cloudflare, so re-run this step rather than republishing."
        )
    echo(f"  {label} is visible.")
