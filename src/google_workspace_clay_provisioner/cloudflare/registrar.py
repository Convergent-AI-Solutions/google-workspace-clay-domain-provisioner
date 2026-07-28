"""Cloudflare Registrar: availability check and registration.

The registration API entered beta in April 2026. Two consequences are handled
deliberately here:

* **Field names are read defensively.** ``_availability_of`` accepts several
  plausible key names rather than one, so a beta response-shape change
  degrades to "unknown availability" instead of silently reporting every
  domain as available.
* **Registration completion is confirmed by ownership, not by a beta status
  endpoint.** A 202 means "in progress", and rather than depend on a polling
  path that may still move, this polls the long-standing owned-domains
  endpoint until the domain appears.

Registration spends money and cannot be undone. Nothing in this module
registers anything without an explicit call to ``register_domain``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..backoff import BackoffPolicy, poll_until
from ..errors import CloudflareError
from .client import CloudflareClient

#: The check endpoint accepts at most 20 domains per call.
MAX_CHECK_BATCH = 20

_AVAILABLE_BOOL_KEYS = ("available", "is_available", "registrable", "can_register")
_AVAILABLE_STATUS_KEYS = ("availability", "status", "availability_status")
_AVAILABLE_TRUE = {"available", "registrable", "unregistered", "free"}
_AVAILABLE_FALSE = {"unavailable", "registered", "taken", "reserved", "not_available"}
_PRICE_KEYS = ("price", "registration_price", "registration_fee", "amount")
_DOMAIN_KEYS = ("domain_name", "domain", "name")


@dataclass(frozen=True)
class DomainOffer:
    """What Cloudflare says about one domain."""

    domain: str
    available: bool | None
    price: str | None = None
    currency: str | None = None
    tier: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def availability_label(self) -> str:
        """Human-readable availability, distinguishing unknown from unavailable."""
        if self.available is True:
            return "available"
        if self.available is False:
            return "taken"
        return "unknown"

    @property
    def price_label(self) -> str:
        """Price with currency when both are known."""
        if self.price is None:
            return "-"
        return f"{self.price} {self.currency}" if self.currency else str(self.price)


@dataclass(frozen=True)
class RegistrationResult:
    """The outcome of a registration attempt."""

    domain: str
    status_code: int
    completed: bool
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def pending(self) -> bool:
        """True when Cloudflare accepted the request but has not finished it."""
        return not self.completed


def check_domains(
    client: CloudflareClient,
    account_id: str,
    domains: list[str],
) -> list[DomainOffer]:
    """Authoritative availability, queried against the registry.

    Automatically split into batches of ``MAX_CHECK_BATCH``. Results keep the
    order the domains were supplied in, so a caller can zip them against its
    own candidate list.
    """
    if not domains:
        return []

    by_domain: dict[str, DomainOffer] = {}
    for batch in _batched(domains, MAX_CHECK_BATCH):
        result = client.post(
            f"/accounts/{account_id}/registrar/domain-check",
            json={"domains": list(batch)},
        )
        for item in _as_items(result):
            offer = _offer_from(item)
            if offer.domain:
                by_domain[offer.domain.lower()] = offer

    ordered = []
    for domain in domains:
        found = by_domain.get(domain.lower())
        ordered.append(found or DomainOffer(domain=domain, available=None))
    return ordered


def register_domain(
    client: CloudflareClient,
    account_id: str,
    domain: str,
    *,
    registrant: dict[str, str] | None = None,
    years: int | None = None,
) -> RegistrationResult:
    """Register ``domain``. Non-refundable once it succeeds.

    ``registrant`` may be omitted when the Cloudflare account has a default
    registrant contact configured, which is the recommended setup — it keeps
    WHOIS details out of this tool's configuration entirely.
    """
    body: dict[str, Any] = {"domain_name": domain}
    if registrant:
        body["contacts"] = {"registrant": registrant}
    if years is not None:
        body["years"] = years

    result, status = client.request(
        "POST",
        f"/accounts/{account_id}/registrar/registrations",
        json=body,
        expect=(200, 201, 202),
    )
    payload = result if isinstance(result, dict) else {}
    return RegistrationResult(
        domain=domain,
        status_code=status,
        completed=status in (200, 201),
        raw=payload,
    )


def get_owned_domain(
    client: CloudflareClient,
    account_id: str,
    domain: str,
) -> dict[str, Any] | None:
    """The account's record for ``domain``, or ``None`` if it does not own it."""
    result = client.get_optional(f"/accounts/{account_id}/registrar/domains/{domain}")
    return result if isinstance(result, dict) else None


def wait_until_registered(
    client: CloudflareClient,
    account_id: str,
    domain: str,
    policy: BackoffPolicy,
    *,
    on_wait: Any = None,
) -> dict[str, Any]:
    """Poll until the account owns ``domain``, on a jittered interval.

    Confirms the outcome of an asynchronous (202) registration by ownership
    rather than by a beta status field.
    """
    owned = poll_until(
        lambda: get_owned_domain(client, account_id, domain), policy, on_wait=on_wait
    )
    if owned is None:
        raise CloudflareError(
            f"{domain} did not appear as an owned domain within "
            f"{policy.worst_case_seconds:.0f}s. The registration may still be in "
            f"progress. Check the Cloudflare dashboard before retrying, because "
            f"a second attempt could register and charge twice."
        )
    return owned


def _offer_from(item: Any) -> DomainOffer:
    """Read one search/check entry, tolerating beta field-name differences."""
    if not isinstance(item, dict):
        return DomainOffer(domain=str(item), available=None)

    domain = ""
    for key in _DOMAIN_KEYS:
        value = item.get(key)
        if isinstance(value, str) and value:
            domain = value
            break

    price, currency = _price_of(item)
    tier = item.get("tier")
    return DomainOffer(
        domain=domain,
        available=_availability_of(item),
        price=price,
        currency=currency,
        tier=str(tier) if tier is not None else None,
        raw=item,
    )


def _availability_of(item: dict[str, Any]) -> bool | None:
    """Best-effort availability. ``None`` means the response did not say.

    Returning ``None`` rather than ``False`` matters: the CLI shows unknown
    separately, so a response-shape change surfaces as "check the dashboard"
    instead of hiding every available domain.
    """
    for key in _AVAILABLE_BOOL_KEYS:
        value = item.get(key)
        if isinstance(value, bool):
            return value
    for key in _AVAILABLE_STATUS_KEYS:
        value = item.get(key)
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in _AVAILABLE_TRUE:
                return True
            if lowered in _AVAILABLE_FALSE:
                return False
    return None


def _price_of(item: dict[str, Any]) -> tuple[str | None, str | None]:
    """Pull a displayable price and currency out of whatever shape is present."""
    currency = item.get("currency")
    for key in _PRICE_KEYS:
        value = item.get(key)
        if isinstance(value, dict):
            nested_currency = value.get("currency") or currency
            for nested_key in ("amount", "value", "price"):
                nested = value.get(nested_key)
                if isinstance(nested, (str, int, float)):
                    return str(nested), nested_currency
        elif isinstance(value, (str, int, float)):
            return str(value), currency
    return None, currency


def _as_items(result: Any) -> list[Any]:
    """Normalise a result that may be a list, or a dict wrapping a list."""
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        for key in ("results", "domains", "items", "suggestions"):
            value = result.get(key)
            if isinstance(value, list):
                return value
        return [result]
    return []


def _batched(items: list[str], size: int):
    for start in range(0, len(items), size):
        yield items[start : start + size]
