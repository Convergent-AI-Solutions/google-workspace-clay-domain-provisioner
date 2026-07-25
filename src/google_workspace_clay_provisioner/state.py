"""Per-domain run state, so a resumed run never repeats a paid or one-way step.

Domain registration is non-refundable and Workspace domain verification is
one-way, so every step records completion here before the next one starts. A
re-run reads this file and skips what is already done.

Secrets are never written. ``mark_done`` drops any detail whose key looks like
a credential, so a mailbox password cannot end up on disk through this path.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

STEP_REGISTER = "register_domain"
STEP_WORKSPACE_DOMAIN = "add_workspace_domain"
STEP_VERIFY_OWNERSHIP = "verify_domain_ownership"
STEP_MAILBOX = "create_mailbox"
STEP_DNS = "publish_dns_records"
STEP_DKIM = "publish_dkim_record"
STEP_VERIFY_RECORDS = "verify_dns_records"
STEP_CLAY = "prepare_clay_import"

ORDERED_STEPS: tuple[str, ...] = (
    STEP_REGISTER,
    STEP_WORKSPACE_DOMAIN,
    STEP_VERIFY_OWNERSHIP,
    STEP_MAILBOX,
    STEP_DNS,
    STEP_DKIM,
    STEP_VERIFY_RECORDS,
    STEP_CLAY,
)

#: Substrings that mark a detail value as a credential. Matching keys are
#: dropped before the state file is written.
_SECRET_KEY_HINTS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "api_key",
    "apikey",
    "private",
)


def is_secret_key(key: str) -> bool:
    """True when a detail key looks like it holds a credential."""
    lowered = key.lower()
    return any(hint in lowered for hint in _SECRET_KEY_HINTS)


def scrub(detail: dict[str, Any]) -> dict[str, Any]:
    """Drop credential-looking entries, recursively, before persisting."""
    cleaned: dict[str, Any] = {}
    for key, value in detail.items():
        if is_secret_key(key):
            continue
        cleaned[key] = scrub(value) if isinstance(value, dict) else value
    return cleaned


@dataclass
class RunState:
    """The record of what has been done for one domain."""

    domain: str
    path: Path
    steps: dict[str, dict[str, Any]]

    @classmethod
    def load(cls, state_dir: Path, domain: str) -> RunState:
        """Read existing state for ``domain``, or start an empty record."""
        path = state_dir / f"{domain}.json"
        if not path.is_file():
            return cls(domain=domain, path=path, steps={})
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            # A corrupt state file must not silently look like "nothing done" —
            # move it aside so the operator can see what happened.
            path.rename(path.with_suffix(".json.corrupt"))
            return cls(domain=domain, path=path, steps={})
        return cls(domain=domain, path=path, steps=raw.get("steps", {}))

    def save(self) -> None:
        """Write the state file, creating the directory if needed."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "domain": self.domain,
            "updated": datetime.now(UTC).isoformat(timespec="seconds"),
            "steps": self.steps,
        }
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def is_done(self, step: str) -> bool:
        """True when ``step`` has already completed for this domain."""
        return self.steps.get(step, {}).get("status") == "done"

    def detail(self, step: str) -> dict[str, Any]:
        """Whatever non-secret detail was recorded for ``step``."""
        return dict(self.steps.get(step, {}))

    def mark_done(self, step: str, **detail: Any) -> None:
        """Record ``step`` as complete and persist immediately."""
        self.steps[step] = {
            "status": "done",
            "at": datetime.now(UTC).isoformat(timespec="seconds"),
            **scrub(detail),
        }
        self.save()

    def mark_skipped(self, step: str, reason: str) -> None:
        """Record that ``step`` was deliberately not run, with the reason."""
        self.steps[step] = {
            "status": "skipped",
            "at": datetime.now(UTC).isoformat(timespec="seconds"),
            "reason": reason,
        }
        self.save()

    def summary(self) -> list[tuple[str, str]]:
        """Every step in run order with its status, for the ``status`` command."""
        return [(step, self.steps.get(step, {}).get("status", "pending")) for step in ORDERED_STEPS]
