"""Generate the per-domain handoff checklist.

Everything a person still has to do by hand ends up in one Markdown file, along
with the record values that were published, so the run is auditable after the
terminal output is gone.

The mailbox password is included only when the caller explicitly asks. It is
off by default, because the checklist is a plain file on disk.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .clay import clay_steps
from .dns_records import DnsRecordSpec
from .verify import VerificationReport


@dataclass(frozen=True)
class RunSummary:
    """What one provisioning run did, for the checklist."""

    domain: str
    mailbox: str
    records: tuple[DnsRecordSpec, ...]
    verification: VerificationReport | None
    dkim_selector: str
    clay_csv_path: Path | None = None
    mailbox_password: str | None = None
    notes: tuple[str, ...] = ()


def render_checklist(summary: RunSummary) -> str:
    """The Markdown checklist for a completed run."""
    stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Sending domain handoff: {summary.domain}",
        "",
        f"Generated {stamp}.",
        "",
        "## What was provisioned",
        "",
        f"- Domain: `{summary.domain}`",
        f"- Sending mailbox: `{summary.mailbox}`",
        f"- DKIM selector: `{summary.dkim_selector}`",
        "",
    ]

    if summary.mailbox_password:
        lines += [
            "## Mailbox password",
            "",
            f"`{summary.mailbox_password}`",
            "",
            "Move this into your password manager and delete this file. It is "
            "written here only because you passed the flag that asks for it.",
            "",
        ]

    lines += ["## Expected records", ""]
    if summary.records:
        lines += [
            "The record values this configuration expects. What actually "
            "resolves on public DNS is in the Verification section below — read "
            "that, not this table, to tell what is live.",
            "",
            "| Record | Name | Value |",
            "| --- | --- | --- |",
        ]
        for spec in summary.records:
            value = spec.content if len(spec.content) <= 80 else f"{spec.content[:77]}..."
            label = spec.label or spec.type
            lines.append(f"| {label} | `{spec.name}` | `{value}` |")
    else:
        lines.append("No records were configured for this run.")
    lines.append("")

    lines += ["## Verification", ""]
    if summary.verification is None:
        lines.append("Verification was not run.")
    else:
        lines += ["| Check | Result | Detail |", "| --- | --- | --- |"]
        for check in summary.verification.checks:
            mark = "pass" if check.passed else "FAIL"
            lines.append(f"| {check.name} | {mark} | {check.detail} |")
        if not summary.verification.passed:
            lines += [
                "",
                "DNS propagation is the usual cause of a fresh failure. Re-run "
                "the verify step before changing any record.",
            ]
    lines.append("")

    lines += ["## Still to do by hand", ""]
    for index, step in enumerate(clay_steps(summary.mailbox, summary.clay_csv_path), start=1):
        lines.append(f"{index}. {step}")
    lines.append("")

    if summary.notes:
        lines += ["## Notes", ""]
        lines += [f"- {note}" for note in summary.notes]
        lines.append("")

    return "\n".join(lines)


def write_checklist(path: Path, summary: RunSummary) -> Path:
    """Write the checklist to ``path`` and return it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_checklist(summary), encoding="utf-8")
    return path


def dkim_console_instructions(domain: str, selector: str) -> str:
    """The Admin console path for generating a DKIM key.

    Google generates the key pair, retains the private half, and shows the
    public half only in this screen. There is no API for it, and Workspace does
    not accept an imported key, so this step cannot be automated.
    """
    return (
        "Google has no API for DKIM key generation, so this part is manual:\n"
        "  1. Admin console: Apps > Google Workspace > Gmail > Authenticate email\n"
        f"  2. Select the domain {domain}\n"
        "  3. Generate new record. Choose a 2048-bit key and the selector "
        f"'{selector}'\n"
        "  4. Copy the TXT value it shows (the whole 'v=DKIM1; k=rsa; p=...' "
        "string, or just the key)\n"
        "  5. Paste it here. This tool publishes the TXT record and verifies it\n"
        "  6. Back in that same screen, click Start authentication once the "
        "record resolves"
    )
