"""Prove domain ownership to Google with a DNS TXT token.

Order matters and is not negotiable: fetch the token, publish it in DNS, wait
for it to resolve, then ask Google to verify. Calling verify before the record
is visible fails, and Google rate-limits repeated failed attempts.
"""

from __future__ import annotations

from typing import Any

from ..errors import GoogleError
from .errors import http_error_message

SITE_TYPE = "INET_DOMAIN"
VERIFICATION_METHOD = "DNS_TXT"


def get_dns_token(service: Any, domain: str) -> str:
    """The TXT value Google expects to find at the zone apex of ``domain``."""
    body = {
        "site": {"type": SITE_TYPE, "identifier": domain},
        "verificationMethod": VERIFICATION_METHOD,
    }
    try:
        response = service.webResource().getToken(body=body).execute()
    except Exception as exc:  # noqa: BLE001 - normalised into GoogleError
        raise GoogleError(
            f"could not get a verification token for {domain}: {http_error_message(exc)}"
        ) from exc

    token = response.get("token")
    if not token:
        raise GoogleError(f"Google returned no verification token for {domain}")
    return str(token)


def list_verified_domains(service: Any) -> set[str]:
    """Domains this identity has already verified."""
    try:
        response = service.webResource().list().execute()
    except Exception as exc:  # noqa: BLE001 - normalised into GoogleError
        raise GoogleError(f"could not list verified sites: {http_error_message(exc)}") from exc

    verified = set()
    for item in response.get("items", []):
        site = item.get("site", {})
        if site.get("type") == SITE_TYPE and site.get("identifier"):
            verified.add(str(site["identifier"]).lower())
    return verified


def verify_domain(service: Any, domain: str, *, dry_run: bool = False) -> str:
    """Ask Google to check the published token. Returns what happened.

    Idempotent: a domain already verified by this identity returns
    ``"already-verified"`` without another call.
    """
    if domain.lower() in list_verified_domains(service):
        return "already-verified"
    if dry_run:
        return "would-verify"

    body = {"site": {"type": SITE_TYPE, "identifier": domain}}
    try:
        service.webResource().insert(
            verificationMethod=VERIFICATION_METHOD, body=body
        ).execute()
    except Exception as exc:  # noqa: BLE001 - normalised into GoogleError
        raise GoogleError(
            f"verification of {domain} failed: {http_error_message(exc)}. "
            f"The token record is usually not yet visible to Google's resolvers, so "
            f"wait and re-run this step rather than requesting a new token."
        ) from exc
    return "verified"
