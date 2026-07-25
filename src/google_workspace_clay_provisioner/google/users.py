"""Create the sending mailbox on the new domain, and optionally assign a licence.

The generated password is returned to the caller and printed once. It is never
written to the run-state file, and the Clay export never contains it — SMTP to
Gmail needs an app password, which requires 2-step verification on the account
and has no API of its own, so that credential is created by hand regardless.
"""

from __future__ import annotations

import secrets
from typing import Any

from ..errors import GoogleError
from .errors import http_error_message, is_conflict, is_not_found

#: Excludes characters that are easily misread when a password is transcribed
#: by hand into the Workspace or Clay UI: I, l, 1, O, 0.
_PASSWORD_ALPHABET = (
    "ABCDEFGHJKLMNPQRSTUVWXYZ" "abcdefghijkmnopqrstuvwxyz" "23456789" "!@#$%^&*-_=+"
)
DEFAULT_PASSWORD_LENGTH = 20


def generate_password(length: int = DEFAULT_PASSWORD_LENGTH) -> str:
    """A cryptographically random password of ``length`` characters."""
    if length < 12:
        raise ValueError("password length must be at least 12 characters")
    return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(length))


def get_user(service: Any, email: str) -> dict[str, Any] | None:
    """The user record for ``email``, or ``None`` when it does not exist."""
    try:
        return service.users().get(userKey=email).execute()
    except Exception as exc:  # noqa: BLE001 - absence is an expected answer
        if is_not_found(exc):
            return None
        raise GoogleError(f"could not read user {email}: {http_error_message(exc)}") from exc


def create_user(
    service: Any,
    email: str,
    *,
    given_name: str,
    family_name: str,
    password: str,
    change_password_at_next_login: bool = False,
    dry_run: bool = False,
) -> tuple[str, str | None]:
    """Create ``email``. Returns ``(action, password)``.

    ``password`` comes back only when this call created the user, so a resumed
    run cannot mislead the operator into thinking it has fresh credentials for
    a mailbox that already existed.

    ``change_password_at_next_login`` defaults to False on purpose: a forced
    change blocks the mailbox from sending until a human signs in, which
    defeats the point of provisioning it unattended.
    """
    if get_user(service, email) is not None:
        return "exists", None
    if dry_run:
        return "would-create", None

    body = {
        "primaryEmail": email,
        "name": {"givenName": given_name, "familyName": family_name},
        "password": password,
        "changePasswordAtNextLogin": change_password_at_next_login,
    }
    try:
        service.users().insert(body=body).execute()
    except Exception as exc:  # noqa: BLE001 - normalised into GoogleError
        if is_conflict(exc):
            return "exists", None
        raise GoogleError(f"could not create user {email}: {http_error_message(exc)}") from exc
    return "created", password


def assign_license(
    service: Any,
    email: str,
    *,
    product_id: str,
    sku_id: str,
    dry_run: bool = False,
) -> str:
    """Assign a Workspace licence SKU to ``email``.

    Only needed when the Workspace account does not assign licences
    automatically. Product and SKU ids differ per edition, so both are supplied
    by the caller rather than guessed here.
    """
    if dry_run:
        return "would-assign"
    try:
        service.licenseAssignments().insert(
            productId=product_id, skuId=sku_id, body={"userId": email}
        ).execute()
    except Exception as exc:  # noqa: BLE001 - normalised into GoogleError
        if is_conflict(exc):
            return "already-assigned"
        raise GoogleError(
            f"could not assign licence {sku_id} to {email}: {http_error_message(exc)}"
        ) from exc
    return "assigned"
