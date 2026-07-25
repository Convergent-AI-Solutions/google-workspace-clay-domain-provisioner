"""Configuration, assembled from CLI flags, then environment, then prompt.

Nothing in here is specific to any organisation. Every value is supplied at
run time; the repository ships no defaults that identify a company, and no
credential ever reaches a committed file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .dns_records import DEFAULT_DKIM_SELECTOR, DEFAULT_SPF_VALUE, DMARC_POLICIES, MxMode
from .errors import ConfigError
from .verify import DEFAULT_RESOLVERS

ENV_PREFIX = "CEDP_"


def env(name: str, default: str | None = None) -> str | None:
    """Read a ``CEDP_``-prefixed environment variable, treating blank as unset."""
    value = os.environ.get(f"{ENV_PREFIX}{name}")
    if value is None or not value.strip():
        return default
    return value.strip()


def load_env_file(path: Path | None = None) -> None:
    """Load a ``.env`` file into the environment if one is present.

    Existing environment variables win, so an explicit export or a CI secret is
    never silently overridden by a file left on disk.
    """
    from dotenv import load_dotenv

    target = path or Path(".env")
    if target.is_file():
        load_dotenv(target, override=False)


@dataclass(frozen=True)
class CloudflareConfig:
    """Credentials for the Registrar and DNS APIs.

    One token can cover both if it carries Registrar write and Zone DNS edit.
    """

    api_token: str
    account_id: str

    @classmethod
    def from_env(cls) -> CloudflareConfig | None:
        token, account = env("CF_API_TOKEN"), env("CF_ACCOUNT_ID")
        if not token or not account:
            return None
        return cls(api_token=token, account_id=account)


@dataclass(frozen=True)
class GoogleConfig:
    """How to authenticate to the Workspace Admin SDK and Site Verification API.

    ``credentials_path`` points at either a service-account JSON with
    domain-wide delegation, or an OAuth client-secrets JSON. A service account
    must impersonate a super admin, which is what ``admin_email`` supplies.
    """

    credentials_path: Path
    admin_email: str | None = None
    customer_id: str = "my_customer"

    def __post_init__(self) -> None:
        if not self.credentials_path.is_file():
            raise ConfigError(f"Google credentials file not found: {self.credentials_path}")

    @classmethod
    def from_env(cls) -> GoogleConfig | None:
        path = env("GOOGLE_CREDENTIALS")
        if not path:
            return None
        return cls(
            credentials_path=Path(path).expanduser(),
            admin_email=env("GOOGLE_ADMIN_EMAIL"),
            customer_id=env("GOOGLE_CUSTOMER_ID", "my_customer") or "my_customer",
        )


@dataclass(frozen=True)
class RegistrantContact:
    """WHOIS registrant details for a Cloudflare registration.

    Optional as a whole: when a default registrant contact is configured on the
    Cloudflare account, the registration call omits the contacts block and
    Cloudflare applies the default.
    """

    first_name: str = ""
    last_name: str = ""
    organization: str = ""
    email: str = ""
    phone: str = ""
    address: str = ""
    city: str = ""
    state: str = ""
    postal_code: str = ""
    country: str = ""

    @property
    def is_complete(self) -> bool:
        """True when every field the registry requires is present."""
        required = (
            self.first_name,
            self.last_name,
            self.email,
            self.phone,
            self.address,
            self.city,
            self.postal_code,
            self.country,
        )
        return all(value.strip() for value in required)

    @property
    def is_empty(self) -> bool:
        """True when nothing was supplied, meaning "use the Cloudflare default"."""
        return not any(getattr(self, f.name).strip() for f in self.__dataclass_fields__.values())

    def to_payload(self) -> dict[str, str]:
        """The registrant object shape the Registrar API expects."""
        if not self.is_complete:
            raise ConfigError(
                "registrant contact is partly filled in; supply every field or none "
                "and rely on the Cloudflare account default contact"
            )
        if len(self.country.strip()) != 2:
            raise ConfigError(f"registrant country must be a 2-letter code: {self.country!r}")
        payload = {
            "first_name": self.first_name.strip(),
            "last_name": self.last_name.strip(),
            "email": self.email.strip(),
            "phone": self.phone.strip(),
            "address": self.address.strip(),
            "city": self.city.strip(),
            "state": self.state.strip(),
            "zip": self.postal_code.strip(),
            "country": self.country.strip().upper(),
        }
        if self.organization.strip():
            payload["organization"] = self.organization.strip()
        return payload

    @classmethod
    def from_env(cls) -> RegistrantContact:
        return cls(
            first_name=env("REGISTRANT_FIRST_NAME", "") or "",
            last_name=env("REGISTRANT_LAST_NAME", "") or "",
            organization=env("REGISTRANT_ORGANIZATION", "") or "",
            email=env("REGISTRANT_EMAIL", "") or "",
            phone=env("REGISTRANT_PHONE", "") or "",
            address=env("REGISTRANT_ADDRESS", "") or "",
            city=env("REGISTRANT_CITY", "") or "",
            state=env("REGISTRANT_STATE", "") or "",
            postal_code=env("REGISTRANT_POSTAL_CODE", "") or "",
            country=env("REGISTRANT_COUNTRY", "") or "",
        )


@dataclass(frozen=True)
class MailboxConfig:
    """The sending mailbox to create on the new domain."""

    local_part: str = "connect"
    given_name: str = "Connect"
    family_name: str = "Team"
    change_password_at_next_login: bool = False

    def __post_init__(self) -> None:
        if not self.local_part.strip():
            raise ConfigError("mailbox local part cannot be empty")

    def address(self, domain: str) -> str:
        """The full primary email address on ``domain``."""
        return f"{self.local_part.strip().lower()}@{domain}"

    @classmethod
    def from_env(cls) -> MailboxConfig:
        return cls(
            local_part=env("MAILBOX_LOCAL_PART", "connect") or "connect",
            given_name=env("MAILBOX_GIVEN_NAME", "Connect") or "Connect",
            family_name=env("MAILBOX_FAMILY_NAME", "Team") or "Team",
        )


@dataclass(frozen=True)
class DnsConfig:
    """What the four authentication records should say."""

    mx_mode: MxMode = "single"
    spf_value: str = DEFAULT_SPF_VALUE
    dkim_selector: str = DEFAULT_DKIM_SELECTOR
    dmarc_policy: str = "none"
    dmarc_rua: str = ""
    dmarc_pct: int = 100

    def __post_init__(self) -> None:
        if self.mx_mode not in ("single", "legacy"):
            raise ConfigError(f"mx_mode must be 'single' or 'legacy': {self.mx_mode!r}")
        if self.dmarc_policy not in DMARC_POLICIES:
            raise ConfigError(f"dmarc_policy must be one of {DMARC_POLICIES}")
        if not 0 <= self.dmarc_pct <= 100:
            raise ConfigError(f"dmarc_pct must be 0-100: {self.dmarc_pct}")

    @classmethod
    def from_env(cls) -> DnsConfig:
        raw_pct = env("DMARC_PCT", "100") or "100"
        try:
            pct = int(raw_pct)
        except ValueError as exc:
            raise ConfigError(f"{ENV_PREFIX}DMARC_PCT must be an integer: {raw_pct!r}") from exc
        return cls(
            mx_mode=env("MX_MODE", "single") or "single",  # type: ignore[arg-type]
            spf_value=env("SPF_VALUE", DEFAULT_SPF_VALUE) or DEFAULT_SPF_VALUE,
            dkim_selector=env("DKIM_SELECTOR", DEFAULT_DKIM_SELECTOR) or DEFAULT_DKIM_SELECTOR,
            dmarc_policy=env("DMARC_POLICY", "none") or "none",
            dmarc_rua=env("DMARC_RUA", "") or "",
            dmarc_pct=pct,
        )


@dataclass(frozen=True)
class Paths:
    """Where run state and generated artefacts land. Both are gitignored."""

    state_dir: Path = field(default_factory=lambda: Path(".provisioner-state"))
    output_dir: Path = field(default_factory=lambda: Path("out"))

    def ensure(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)


def resolvers_from_env() -> tuple[str, ...]:
    """Public resolvers to verify against, comma-separated in the environment."""
    raw = env("RESOLVERS")
    if not raw:
        return DEFAULT_RESOLVERS
    parsed = tuple(item.strip() for item in raw.split(",") if item.strip())
    return parsed or DEFAULT_RESOLVERS
