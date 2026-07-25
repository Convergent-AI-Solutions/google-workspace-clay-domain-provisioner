"""Prepare the Clay import — the one step with no API.

Clay connects a sending mailbox in three ways, all through its own interface:
Google OAuth, Microsoft OAuth, or SMTP entered manually or uploaded as a CSV.
There is no documented REST endpoint for adding an email account or for turning
warmup on, so this module produces what a person needs to finish the job in a
couple of clicks and stops there.

Two honest limits, both restated in the generated checklist:

* **The CSV header set below is a starting point, not a verified contract.**
  Clay does not publish its SMTP upload schema. Reconcile these column names
  against the upload dialog the first time you use it, then pin whatever it
  actually wants.
* **The SMTP password cannot be filled in automatically.** Gmail SMTP needs an
  app password, app passwords require 2-step verification on the account, and
  Google exposes no API for creating one. The CSV therefore ships a placeholder.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

GMAIL_SMTP_HOST = "smtp.gmail.com"
GMAIL_SMTP_PORT = 587
GMAIL_IMAP_HOST = "imap.gmail.com"
GMAIL_IMAP_PORT = 993

APP_PASSWORD_PLACEHOLDER = "REPLACE_WITH_APP_PASSWORD"

#: Provisional. See the module docstring — confirm against Clay's upload dialog.
CLAY_SMTP_CSV_HEADERS: tuple[str, ...] = (
    "email",
    "first_name",
    "last_name",
    "smtp_host",
    "smtp_port",
    "smtp_username",
    "smtp_password",
    "imap_host",
    "imap_port",
    "imap_username",
    "imap_password",
    "daily_limit",
    "warmup_enabled",
)


@dataclass(frozen=True)
class ClayMailboxRow:
    """One mailbox as Clay's SMTP import expects it."""

    email: str
    first_name: str
    last_name: str
    daily_limit: int = 20
    warmup_enabled: bool = True
    smtp_password: str = APP_PASSWORD_PLACEHOLDER

    def as_row(self) -> dict[str, str]:
        """Flatten to the CSV column set."""
        return {
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "smtp_host": GMAIL_SMTP_HOST,
            "smtp_port": str(GMAIL_SMTP_PORT),
            "smtp_username": self.email,
            "smtp_password": self.smtp_password,
            "imap_host": GMAIL_IMAP_HOST,
            "imap_port": str(GMAIL_IMAP_PORT),
            "imap_username": self.email,
            "imap_password": self.smtp_password,
            "daily_limit": str(self.daily_limit),
            "warmup_enabled": "true" if self.warmup_enabled else "false",
        }


def write_clay_csv(path: Path, rows: list[ClayMailboxRow]) -> Path:
    """Write the SMTP import CSV and return its path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(CLAY_SMTP_CSV_HEADERS))
        writer.writeheader()
        for row in rows:
            writer.writerow(row.as_row())
    return path


def clay_steps(email: str, csv_path: Path | None) -> list[str]:
    """The manual steps left in Clay, in order."""
    steps = [
        "In Clay, open Campaigns, then Email accounts.",
        "Add the account. Google OAuth is the least error-prone route: sign in "
        f"as {email} and approve the Clay Sequencer app. A Workspace admin must "
        "authorise that app for the new domain, or the sign-in returns an "
        "access error.",
        "Turn on warmup for the account.",
        "Set the daily sending limit, and leave warmup on for as long as you "
        "intend to keep sending from this mailbox.",
    ]
    if csv_path is not None:
        steps.insert(
            2,
            "If you prefer SMTP over OAuth, generate an app password for the "
            f"mailbox first (Google account, Security, App passwords), put it in "
            f"{csv_path.name} in place of {APP_PASSWORD_PLACEHOLDER}, then upload "
            "that file. Check the column names against the upload dialog, because "
            "Clay does not publish this schema.",
        )
    return steps
