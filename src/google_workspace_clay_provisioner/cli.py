"""Command-line interface for the Google Workspace and Clay sending-domain setup.

Every step is its own command so a failed or manual step can be re-run on its
own, and ``run`` chains them for a fresh domain. Nothing is organisation
specific: credentials and defaults come from flags, then the environment, then
an interactive prompt, in that order.

Two commands change state that cannot be undone — ``purchase`` spends money,
``workspace`` verifies a domain one-way — and both require explicit
confirmation unless ``--yes`` is passed.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer

from . import __version__, steps
from .backoff import BackoffPolicy
from .clay import clay_steps
from .cloudflare.client import CloudflareClient
from .config import (
    DnsConfig,
    MailboxConfig,
    Paths,
    RegistrantContact,
    env,
    load_env_file,
    resolvers_from_env,
)
from .dns_records import DEFAULT_DKIM_SELECTOR, DEFAULT_SPF_VALUE, dkim_public_key
from .errors import ConfigError, ProvisionerError
from .google import auth as gauth
from .report import RunSummary, dkim_console_instructions, write_checklist
from .state import STEP_DKIM, STEP_REGISTER, RunState
from .verify import DnsLookup

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Set up a cold-email sending domain and mailbox for Google Workspace "
    "and Clay: register the domain at Cloudflare, add it to Workspace as a "
    "secondary domain, create the mailbox, publish MX/SPF/DKIM/DMARC, verify "
    "against public resolvers, and prepare the Clay import.",
)


@dataclass
class CliContext:
    """Shared options and lazily built clients."""

    dry_run: bool = False
    paths: Paths = field(default_factory=Paths)
    resolvers: tuple[str, ...] = ()
    cf_token: str | None = None
    cf_account: str | None = None
    google_credentials: Path | None = None
    admin_email: str | None = None
    customer_id: str = "my_customer"
    assume_yes: bool = False
    _cloudflare: CloudflareClient | None = None
    _credentials: Any = None

    def cloudflare(self) -> CloudflareClient:
        """The Cloudflare client, prompting for the token on first use."""
        if self._cloudflare is None:
            token = self.cf_token or prompt_secret("Cloudflare API token")
            self.cf_token = token
            self._cloudflare = CloudflareClient(token)
        return self._cloudflare

    def account_id(self) -> str:
        """The Cloudflare account id, prompting if it was not supplied."""
        if not self.cf_account:
            self.cf_account = typer.prompt("Cloudflare account id")
        return self.cf_account

    def credentials(self, *, scopes: tuple[str, ...] = gauth.ADMIN_SCOPES) -> Any:
        """Google credentials, built once per invocation."""
        if self._credentials is None:
            path = self.google_credentials or Path(
                typer.prompt("Path to Google credentials JSON")
            ).expanduser()
            self.google_credentials = path
            if not path.is_file():
                raise ConfigError(f"Google credentials file not found: {path}")
            self._credentials = gauth.build_credentials(
                path, scopes=scopes, admin_email=self.admin_email
            )
        return self._credentials

    def directory(self) -> Any:
        """Admin SDK Directory client."""
        return gauth.directory_service(self.credentials())

    def site_verification(self) -> Any:
        """Site Verification client."""
        return gauth.site_verification_service(self.credentials())

    def lookup(self) -> DnsLookup:
        """Resolver pointed at the configured public nameservers."""
        return DnsLookup(resolvers=self.resolvers or resolvers_from_env())

    def state_for(self, domain: str) -> RunState:
        """Run state for ``domain``, creating the state directory if needed."""
        self.paths.ensure()
        return RunState.load(self.paths.state_dir, domain)


def handle_errors(command: Callable) -> Callable:
    """Turn an expected failure into a clean message and exit code 1."""

    @functools.wraps(command)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return command(*args, **kwargs)
        except ProvisionerError as exc:
            typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
            raise typer.Exit(1) from exc

    return wrapper


def echo(message: str) -> None:
    """Print a progress line."""
    typer.echo(message)


def prompt_secret(label: str) -> str:
    """Prompt for a credential without echoing it."""
    return typer.prompt(label, hide_input=True)


def _version_callback(value: bool) -> None:
    """Print the version and exit, so a bug report can name the build."""
    if value:
        typer.echo(f"gwclay {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
    env_file: Path = typer.Option(Path(".env"), help="Env file to load, if present."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Report actions without making them."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompts."),
    state_dir: Path = typer.Option(Path(".provisioner-state"), help="Where run state is kept."),
    output_dir: Path = typer.Option(Path("out"), help="Where CSV and checklist files are written."),
    cf_token: str | None = typer.Option(None, "--cf-token", help="Cloudflare API token."),
    cf_account: str | None = typer.Option(None, "--cf-account", help="Cloudflare account id."),
    google_credentials: Path | None = typer.Option(
        None, "--google-credentials", help="Service-account or OAuth client-secrets JSON."
    ),
    admin_email: str | None = typer.Option(
        None, "--admin-email", help="Workspace super admin to impersonate (service accounts)."
    ),
    customer_id: str | None = typer.Option(None, "--customer-id", help="Workspace customer id."),
    resolvers: str | None = typer.Option(
        None, "--resolvers", help="Comma-separated public resolvers used for verification."
    ),
) -> None:
    """Load configuration in flag, environment, prompt order."""
    load_env_file(env_file)
    ctx.obj = CliContext(
        dry_run=dry_run,
        assume_yes=yes,
        paths=Paths(state_dir=state_dir, output_dir=output_dir),
        resolvers=tuple(item.strip() for item in resolvers.split(",") if item.strip())
        if resolvers
        else resolvers_from_env(),
        cf_token=cf_token or env("CF_API_TOKEN"),
        cf_account=cf_account or env("CF_ACCOUNT_ID"),
        google_credentials=_optional_path(google_credentials or env("GOOGLE_CREDENTIALS")),
        admin_email=admin_email or env("GOOGLE_ADMIN_EMAIL"),
        customer_id=customer_id or env("GOOGLE_CUSTOMER_ID", "my_customer") or "my_customer",
    )


@app.command()
@handle_errors
def suggest(
    ctx: typer.Context,
    seed: str = typer.Argument(..., help="Your primary domain, e.g. example.com."),
    limit: int = typer.Option(20, help="How many candidates to generate."),
    allow_hyphen: bool = typer.Option(False, help="Include hyphenated variants."),
    available_only: bool = typer.Option(False, help="Hide taken and unknown results."),
) -> None:
    """Step 1: suggest .com domains related to SEED and check availability."""
    cli: CliContext = ctx.obj
    rows = steps.suggest_domains(
        cli.cloudflare(),
        cli.account_id(),
        seed,
        limit=limit,
        allow_hyphen=allow_hyphen,
        echo=echo,
    )
    if not rows:
        typer.echo("No candidates generated. Check the seed domain.")
        return

    shown = [row for row in rows if row.is_available] if available_only else rows
    typer.echo("")
    typer.echo(f"{'domain':<34} {'status':<10} {'price':<12} rule")
    typer.echo("-" * 74)
    for row in shown:
        colour = typer.colors.GREEN if row.is_available else None
        typer.secho(
            f"{row.candidate.domain:<34} {row.offer.availability_label:<10} "
            f"{row.offer.price_label:<12} {row.candidate.pattern}",
            fg=colour,
        )

    unknown = [row for row in rows if row.offer.available is None]
    if unknown:
        typer.echo("")
        typer.secho(
            f"{len(unknown)} domain(s) returned no availability field. The Registrar "
            f"API is in beta; confirm those in the Cloudflare dashboard before buying.",
            fg=typer.colors.YELLOW,
        )


@app.command()
@handle_errors
def purchase(
    ctx: typer.Context,
    domain: str = typer.Argument(..., help="The domain to register."),
    years: int | None = typer.Option(None, help="Registration term, if the API accepts one."),
) -> None:
    """Step 2: register DOMAIN with Cloudflare. Charges the account; not refundable."""
    cli: CliContext = ctx.obj
    state = cli.state_for(domain)
    registrant = RegistrantContact.from_env()

    if not cli.dry_run and not cli.assume_yes:
        typer.secho(
            f"About to register {domain}. This charges your Cloudflare account and "
            f"cannot be refunded.",
            fg=typer.colors.YELLOW,
        )
        typed = typer.prompt(f"Type {domain} to confirm")
        if typed.strip().lower() != domain.lower():
            typer.secho("Confirmation did not match. Nothing was registered.", fg=typer.colors.RED)
            raise typer.Exit(1)

    steps.purchase_domain(
        cli.cloudflare(),
        cli.account_id(),
        domain,
        state,
        registrant=registrant,
        years=years,
        confirmed=True,
        dry_run=cli.dry_run,
        echo=echo,
    )


@app.command()
@handle_errors
def workspace(
    ctx: typer.Context,
    domain: str = typer.Argument(..., help="The domain to add to Google Workspace."),
    create_zone: bool = typer.Option(
        False, help="Create the Cloudflare zone if the domain is registered elsewhere."
    ),
) -> None:
    """Step 3: add DOMAIN as a Workspace secondary domain and verify ownership."""
    cli: CliContext = ctx.obj
    state = cli.state_for(domain)
    directory = cli.directory()

    steps.add_workspace_domain(
        directory, domain, state, customer_id=cli.customer_id, dry_run=cli.dry_run, echo=echo
    )
    steps.verify_domain_ownership(
        directory,
        cli.site_verification(),
        cli.cloudflare(),
        cli.account_id(),
        domain,
        state,
        customer_id=cli.customer_id,
        create_zone=create_zone,
        dry_run=cli.dry_run,
        lookup=cli.lookup(),
        echo=echo,
    )


@app.command()
@handle_errors
def mailbox(
    ctx: typer.Context,
    domain: str = typer.Argument(..., help="The domain to create the mailbox on."),
    local_part: str | None = typer.Option(None, help="Mailbox local part, default connect."),
    given_name: str | None = typer.Option(None, help="Given name on the account."),
    family_name: str | None = typer.Option(None, help="Family name on the account."),
    assign_license: bool = typer.Option(
        False, help="Assign a Workspace licence to the new mailbox."
    ),
    product_id: str | None = typer.Option(None, help="Licence product id (with --assign-license)."),
    sku_id: str | None = typer.Option(None, help="Licence SKU id (with --assign-license)."),
) -> None:
    """Step 4: create the sending mailbox on DOMAIN."""
    cli: CliContext = ctx.obj
    state = cli.state_for(domain)
    config = _mailbox_config(local_part, given_name, family_name)
    scopes = _mailbox_scopes(assign_license, product_id, sku_id)

    directory = gauth.directory_service(cli.credentials(scopes=scopes))
    email, password, _ = steps.create_mailbox(
        directory, domain, config, state, dry_run=cli.dry_run, echo=echo
    )
    if password:
        typer.echo("")
        typer.secho(
            "Mailbox password (shown once, not saved anywhere):", fg=typer.colors.YELLOW
        )
        typer.secho(f"  {email}  {password}", bold=True)
        typer.echo("Put it in your password manager now.")

    if assign_license:
        steps.assign_mailbox_license(
            gauth.licensing_service(cli.credentials(scopes=scopes)),
            email,
            state,
            product_id=product_id,  # type: ignore[arg-type]
            sku_id=sku_id,  # type: ignore[arg-type]
            dry_run=cli.dry_run,
            echo=echo,
        )


@app.command()
@handle_errors
def records(
    ctx: typer.Context,
    domain: str = typer.Argument(..., help="The domain to publish records for."),
    mx_mode: str | None = typer.Option(
        None, help="single (smtp.google.com) or legacy (five hosts)."
    ),
    spf: str | None = typer.Option(None, help=f"SPF value, default: {DEFAULT_SPF_VALUE}"),
    dmarc_policy: str | None = typer.Option(None, help="none, quarantine or reject."),
    dmarc_rua: str | None = typer.Option(None, help="Aggregate report address."),
    dmarc_pct: int | None = typer.Option(
        None, help="Percentage of mail the DMARC policy applies to."
    ),
    prune_stale_mx: bool = typer.Option(
        False, help="Delete MX records not in the expected set. Destructive."
    ),
    create_zone: bool = typer.Option(False, help="Create the Cloudflare zone if absent."),
) -> None:
    """Step 5a: publish MX, SPF and DMARC. DKIM is the separate dkim command."""
    cli: CliContext = ctx.obj
    state = cli.state_for(domain)
    config = _dns_config(mx_mode, spf, dmarc_policy, dmarc_rua, None, dmarc_pct)

    typer.echo(f"Publishing mail records for {domain} (MX mode: {config.mx_mode})")
    steps.publish_mail_records(
        cli.cloudflare(),
        cli.account_id(),
        domain,
        config,
        state,
        create_zone=create_zone,
        prune_stale_mx=prune_stale_mx,
        dry_run=cli.dry_run,
        echo=echo,
    )


@app.command()
@handle_errors
def dkim(
    ctx: typer.Context,
    domain: str = typer.Argument(..., help="The domain to publish the DKIM record for."),
    value: str | None = typer.Option(
        None, help="The TXT value from the Admin console. Prompted for if omitted."
    ),
    selector: str | None = typer.Option(
        None, help=f"DKIM selector, default {DEFAULT_DKIM_SELECTOR}"
    ),
    create_zone: bool = typer.Option(False, help="Create the Cloudflare zone if absent."),
) -> None:
    """Step 5b: publish the DKIM record. The key must come from the Admin console."""
    cli: CliContext = ctx.obj
    state = cli.state_for(domain)
    config = _dns_config(None, None, None, None, selector)

    if not value:
        typer.echo(dkim_console_instructions(domain, config.dkim_selector))
        typer.echo("")
        value = typer.prompt("Paste the DKIM TXT value")

    spec, _ = steps.publish_dkim_record(
        cli.cloudflare(),
        cli.account_id(),
        domain,
        value,
        config,
        state,
        create_zone=create_zone,
        dry_run=cli.dry_run,
        echo=echo,
    )
    typer.echo("")
    typer.echo("Now return to the Admin console and click Start authentication.")
    typer.echo(f"Then confirm it resolves:  gwclay verify {domain}")
    _ = spec


@app.command()
@handle_errors
def verify(
    ctx: typer.Context,
    domain: str = typer.Argument(..., help="The domain to verify."),
    mx_mode: str | None = typer.Option(None, help="Which MX layout to expect."),
    dmarc_policy: str | None = typer.Option(None, help="Which DMARC policy to expect."),
    selector: str | None = typer.Option(None, help="DKIM selector to check."),
    attempts: int = typer.Option(10, help="Verification attempts before giving up."),
    once: bool = typer.Option(False, help="Check once and exit, without waiting."),
) -> None:
    """Step 6: verify MX, SPF, DKIM and DMARC against public resolvers."""
    cli: CliContext = ctx.obj
    state = cli.state_for(domain)
    config = _dns_config(mx_mode, None, dmarc_policy, None, selector)
    policy = BackoffPolicy(attempts=1 if once else attempts)

    typer.echo(f"Verifying {domain} against {', '.join(cli.lookup().resolvers)}")
    report = steps.verify_records(
        domain, config, state, lookup=cli.lookup(), policy=policy, dry_run=cli.dry_run, echo=echo
    )

    typer.echo("")
    if report.passed:
        typer.secho("All four records pass.", fg=typer.colors.GREEN)
        return
    failed = ", ".join(check.name for check in report.failures)
    typer.secho(f"Still failing: {failed}", fg=typer.colors.RED)
    raise typer.Exit(1)


@app.command()
@handle_errors
def clay(
    ctx: typer.Context,
    domain: str = typer.Argument(..., help="The provisioned domain."),
    local_part: str | None = typer.Option(None, help="Mailbox local part, default connect."),
    daily_limit: int = typer.Option(20, help="Starting daily send limit to record in the CSV."),
) -> None:
    """Step 7: write the Clay import CSV and list the remaining manual steps."""
    cli: CliContext = ctx.obj
    state = cli.state_for(domain)
    config = _mailbox_config(local_part, None, None)
    email = config.address(domain)

    path = steps.prepare_clay_import(
        domain,
        email,
        config,
        state,
        output_dir=cli.paths.output_dir,
        daily_limit=daily_limit,
        dry_run=cli.dry_run,
        echo=echo,
    )
    typer.echo("")
    typer.secho("Clay has no API for adding a sending account or enabling warmup.", bold=True)
    typer.echo("Finish these by hand:")
    for index, step in enumerate(clay_steps(email, path), start=1):
        typer.echo(f"  {index}. {step}")


@app.command()
@handle_errors
def status(
    ctx: typer.Context,
    domain: str = typer.Argument(..., help="The domain to report on."),
) -> None:
    """Show which steps have completed for DOMAIN."""
    cli: CliContext = ctx.obj
    state = cli.state_for(domain)
    typer.echo(f"{domain}")
    for step, step_status in state.summary():
        colour = {
            "done": typer.colors.GREEN,
            "failed": typer.colors.RED,
            "skipped": typer.colors.YELLOW,
            "pending": None,
        }.get(step_status)
        typer.secho(f"  {step:<26} {step_status}", fg=colour)


@app.command()
@handle_errors
def checklist(
    ctx: typer.Context,
    domain: str = typer.Argument(..., help="The provisioned domain."),
    local_part: str | None = typer.Option(None, help="Mailbox local part, default connect."),
    mx_mode: str | None = typer.Option(None, help="Which MX layout was published."),
    selector: str | None = typer.Option(None, help="DKIM selector in use."),
) -> None:
    """Write the handoff checklist for DOMAIN from current DNS state."""
    cli: CliContext = ctx.obj
    state = cli.state_for(domain)
    dns_config = _dns_config(mx_mode, None, None, None, selector)
    mailbox_config = _mailbox_config(local_part, None, None)

    specs = steps.build_mail_specs(domain, dns_config)
    # Read-only: the checklist reports state, it must not overwrite the recorded
    # verification result with a fresh single-attempt check.
    report = steps.verify_records(
        domain,
        dns_config,
        state,
        lookup=cli.lookup(),
        policy=BackoffPolicy(attempts=1),
        dry_run=cli.dry_run,
        record_state=False,
        echo=echo,
    )
    summary = RunSummary(
        domain=domain,
        mailbox=mailbox_config.address(domain),
        records=tuple(specs),
        verification=report,
        dkim_selector=dns_config.dkim_selector,
        clay_csv_path=cli.paths.output_dir / f"{domain}.clay.csv",
    )
    path = write_checklist(cli.paths.output_dir / f"{domain}-checklist.md", summary)
    typer.echo(f"Wrote {path}")


@app.command()
@handle_errors
def run(
    ctx: typer.Context,
    seed: str = typer.Argument(..., help="Your primary domain, used to suggest candidates."),
    domain: str | None = typer.Option(
        None, help="Skip suggestion and provision this domain directly."
    ),
    local_part: str | None = typer.Option(None, help="Mailbox local part, default connect."),
    mx_mode: str | None = typer.Option(None, help="single or legacy."),
    dmarc_policy: str | None = typer.Option(None, help="none, quarantine or reject."),
    dmarc_rua: str | None = typer.Option(None, help="Aggregate report address."),
    dmarc_pct: int | None = typer.Option(
        None, help="Percentage of mail the DMARC policy applies to."
    ),
    selector: str | None = typer.Option(None, help="DKIM selector."),
    daily_limit: int = typer.Option(
        20, help="Starting daily send limit to record in the Clay CSV."
    ),
    create_zone: bool = typer.Option(False, help="Create the Cloudflare zone if absent."),
    skip_purchase: bool = typer.Option(
        False,
        help="Skip registration for a domain registered outside Cloudflare. "
        "Pair with --create-zone so the DNS steps can create the zone.",
    ),
    assign_license: bool = typer.Option(
        False, help="Assign a Workspace licence to the new mailbox."
    ),
    product_id: str | None = typer.Option(None, help="Licence product id (with --assign-license)."),
    sku_id: str | None = typer.Option(None, help="Licence SKU id (with --assign-license)."),
    write_credentials: bool = typer.Option(
        False, help="Include the mailbox password in the checklist file."
    ),
) -> None:
    """Run every step in order, pausing where a person is required."""
    cli: CliContext = ctx.obj
    dns_config = _dns_config(mx_mode, None, dmarc_policy, dmarc_rua, selector, dmarc_pct)
    mailbox_config = _mailbox_config(local_part, None, None)
    scopes = _mailbox_scopes(assign_license, product_id, sku_id)

    target = domain or _choose_domain(cli, seed)
    state = cli.state_for(target)
    typer.echo("")

    _section("Step 2: register the domain")
    if skip_purchase:
        state.mark_skipped(STEP_REGISTER, "registered outside Cloudflare (--skip-purchase)")
        typer.echo("skipped: domain registered outside Cloudflare")
    elif not state.is_done(STEP_REGISTER):
        purchase(ctx, domain=target, years=None)
    else:
        typer.echo("already registered")

    _section("Step 3: Workspace secondary domain and ownership verification")
    directory = gauth.directory_service(cli.credentials(scopes=scopes))
    steps.add_workspace_domain(
        directory, target, state, customer_id=cli.customer_id, dry_run=cli.dry_run, echo=echo
    )
    steps.verify_domain_ownership(
        directory,
        cli.site_verification(),
        cli.cloudflare(),
        cli.account_id(),
        target,
        state,
        customer_id=cli.customer_id,
        create_zone=create_zone,
        dry_run=cli.dry_run,
        lookup=cli.lookup(),
        echo=echo,
    )

    _section("Step 4: sending mailbox")
    email, password, _ = steps.create_mailbox(
        directory, target, mailbox_config, state, dry_run=cli.dry_run, echo=echo
    )
    if password:
        typer.secho(f"  password for {email}: {password}", bold=True)
        typer.echo("  Save it now: it is not written to the run state.")

    if assign_license:
        steps.assign_mailbox_license(
            gauth.licensing_service(cli.credentials(scopes=scopes)),
            email,
            state,
            product_id=product_id,  # type: ignore[arg-type]
            sku_id=sku_id,  # type: ignore[arg-type]
            dry_run=cli.dry_run,
            echo=echo,
        )

    _section("Step 5a: MX, SPF and DMARC")
    specs, _ = steps.publish_mail_records(
        cli.cloudflare(),
        cli.account_id(),
        target,
        dns_config,
        state,
        create_zone=create_zone,
        dry_run=cli.dry_run,
        echo=echo,
    )

    _section("Step 5b: DKIM")
    typer.echo(dkim_console_instructions(target, dns_config.dkim_selector))
    typer.echo("")
    dkim_value = typer.prompt("Paste the DKIM TXT value (or type skip)")
    dkim_key = None
    if dkim_value.strip().lower() == "skip":
        state.mark_skipped(STEP_DKIM, "operator skipped at the prompt")
        typer.secho(
            "  DKIM skipped. Mail will send unsigned until you publish it.",
            fg=typer.colors.YELLOW,
        )
    else:
        dkim_spec, _ = steps.publish_dkim_record(
            cli.cloudflare(),
            cli.account_id(),
            target,
            dkim_value,
            dns_config,
            state,
            create_zone=create_zone,
            dry_run=cli.dry_run,
            echo=echo,
        )
        specs = [*specs, dkim_spec]
        dkim_key = dkim_public_key(dkim_spec.content)

    _section("Step 6: verify")
    report = steps.verify_records(
        target,
        dns_config,
        state,
        lookup=cli.lookup(),
        expected_dkim_key=dkim_key,
        dry_run=cli.dry_run,
        echo=echo,
    )

    _section("Step 7: prepare the Clay import")
    csv_path = steps.prepare_clay_import(
        target,
        email,
        mailbox_config,
        state,
        output_dir=cli.paths.output_dir,
        daily_limit=daily_limit,
        dry_run=cli.dry_run,
        echo=echo,
    )

    summary = RunSummary(
        domain=target,
        mailbox=email,
        records=tuple(specs),
        verification=report,
        dkim_selector=dns_config.dkim_selector,
        clay_csv_path=csv_path,
        mailbox_password=password if write_credentials else None,
        notes=(
            "Clay has no API for adding a sending account or enabling warmup; "
            "the last step is manual by necessity.",
        ),
    )
    path = write_checklist(cli.paths.output_dir / f"{target}-checklist.md", summary)

    typer.echo("")
    typer.secho(f"Done. Remaining manual steps are in {path}", fg=typer.colors.GREEN)
    if not report.passed:
        typer.secho(
            f"Verification is incomplete: {', '.join(c.name for c in report.failures)}. "
            f"Re-run: gwclay verify {target}",
            fg=typer.colors.YELLOW,
        )


def _choose_domain(cli: CliContext, seed: str) -> str:
    """Show availability for generated candidates and ask which to register."""
    rows = steps.suggest_domains(cli.cloudflare(), cli.account_id(), seed, echo=echo)
    available = [row for row in rows if row.is_available]
    if not available:
        raise ConfigError(
            "none of the generated candidates came back available. Re-run "
            "'suggest' with --limit raised or --allow-hyphen."
        )

    typer.echo("")
    for index, row in enumerate(available, start=1):
        typer.echo(f"  {index:>2}. {row.candidate.domain:<32} {row.offer.price_label}")
    typer.echo("")
    choice = typer.prompt("Choose a number, or type a domain", default="1")

    if choice.strip().isdigit():
        position = int(choice.strip())
        if not 1 <= position <= len(available):
            raise ConfigError(f"choice {position} is outside 1-{len(available)}")
        return available[position - 1].candidate.domain
    return choice.strip().lower()


def _section(title: str) -> None:
    typer.echo("")
    typer.secho(f"== {title}", bold=True)


def _mailbox_config(
    local_part: str | None, given_name: str | None, family_name: str | None
) -> MailboxConfig:
    base = MailboxConfig.from_env()
    return MailboxConfig(
        local_part=local_part or base.local_part,
        given_name=given_name or base.given_name,
        family_name=family_name or base.family_name,
        change_password_at_next_login=base.change_password_at_next_login,
    )


def _dns_config(
    mx_mode: str | None,
    spf: str | None,
    dmarc_policy: str | None,
    dmarc_rua: str | None,
    selector: str | None,
    dmarc_pct: int | None = None,
) -> DnsConfig:
    base = DnsConfig.from_env()
    return DnsConfig(
        mx_mode=mx_mode or base.mx_mode,  # type: ignore[arg-type]
        spf_value=spf or base.spf_value,
        dkim_selector=selector or base.dkim_selector,
        dmarc_policy=dmarc_policy or base.dmarc_policy,
        dmarc_rua=dmarc_rua or base.dmarc_rua,
        dmarc_pct=base.dmarc_pct if dmarc_pct is None else dmarc_pct,
    )


def _mailbox_scopes(
    assign_license: bool, product_id: str | None, sku_id: str | None
) -> tuple[str, ...]:
    """The Google scopes a mailbox run needs, plus licensing only when asked.

    Requesting the licensing scope only on demand keeps the consent minimal for
    the common case that does not assign a licence.
    """
    if not assign_license:
        return gauth.ADMIN_SCOPES
    if not (product_id and sku_id):
        raise ConfigError("--assign-license requires --product-id and --sku-id")
    return gauth.ADMIN_SCOPES + gauth.LICENSING_SCOPES


def _optional_path(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    return Path(value).expanduser()


if __name__ == "__main__":  # pragma: no cover
    app()
