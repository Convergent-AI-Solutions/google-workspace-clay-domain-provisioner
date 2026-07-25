"""Add a secondary domain to Google Workspace and check its verification state.

A **secondary domain** is not a **domain alias**. An alias mirrors the
addresses of existing users on the primary domain; a secondary domain holds its
own separate users. A cold-email sending domain needs its own mailbox, so this
module uses ``domains().insert`` and never ``domainAliases().insert``.

Each user created on a secondary domain consumes a paid Workspace licence.
"""

from __future__ import annotations

from typing import Any

from ..errors import GoogleError
from .errors import http_error_message, is_not_found


def list_domain_names(service: Any, customer_id: str = "my_customer") -> list[str]:
    """Every domain on the Workspace account, primary and secondary."""
    try:
        response = service.domains().list(customer=customer_id).execute()
    except Exception as exc:  # noqa: BLE001 - normalised into GoogleError
        raise GoogleError(f"could not list Workspace domains: {http_error_message(exc)}") from exc
    return [
        str(item.get("domainName", "")).lower()
        for item in response.get("domains", [])
        if item.get("domainName")
    ]


def get_domain(
    service: Any, domain: str, customer_id: str = "my_customer"
) -> dict[str, Any] | None:
    """The Workspace record for ``domain``, or ``None`` when it is not present."""
    try:
        return service.domains().get(customer=customer_id, domainName=domain).execute()
    except Exception as exc:  # noqa: BLE001 - absence is an expected answer
        if is_not_found(exc):
            return None
        raise GoogleError(f"could not read domain {domain}: {http_error_message(exc)}") from exc


def add_secondary_domain(
    service: Any,
    domain: str,
    *,
    customer_id: str = "my_customer",
    dry_run: bool = False,
) -> str:
    """Add ``domain`` as a secondary domain. Returns what happened.

    Idempotent: an already-present domain returns ``"exists"`` rather than
    failing, so a resumed run passes straight through.
    """
    if get_domain(service, domain, customer_id) is not None:
        return "exists"
    if dry_run:
        return "would-create"

    try:
        service.domains().insert(customer=customer_id, body={"domainName": domain}).execute()
    except Exception as exc:  # noqa: BLE001 - normalised into GoogleError
        raise GoogleError(
            f"could not add {domain} as a secondary domain: {http_error_message(exc)}"
        ) from exc
    return "created"


def is_verified(service: Any, domain: str, customer_id: str = "my_customer") -> bool:
    """True when Workspace considers ownership of ``domain`` proven."""
    record = get_domain(service, domain, customer_id)
    return bool(record and record.get("verified"))
