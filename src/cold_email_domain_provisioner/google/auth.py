"""Authenticate to Google Workspace, by service account or by OAuth sign-in.

Two credential shapes are supported and detected from the file itself:

* **Service account with domain-wide delegation** — headless, suitable for CI.
  It must impersonate a super admin, because domain and user administration are
  not available to the service account's own identity.
* **OAuth client secrets** — opens a browser once, you sign in as the admin.
  Better for a one-off run on a workstation, since it needs no delegation setup
  in the Admin console.

Tokens are cached under the user's home directory, never in the repository.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..errors import ConfigError, GoogleError

DIRECTORY_DOMAIN_SCOPE = "https://www.googleapis.com/auth/admin.directory.domain"
DIRECTORY_USER_SCOPE = "https://www.googleapis.com/auth/admin.directory.user"
SITE_VERIFICATION_SCOPE = "https://www.googleapis.com/auth/siteverification"
LICENSING_SCOPE = "https://www.googleapis.com/auth/apps.licensing"

#: The scopes every run needs.
ADMIN_SCOPES: tuple[str, ...] = (
    DIRECTORY_DOMAIN_SCOPE,
    DIRECTORY_USER_SCOPE,
    SITE_VERIFICATION_SCOPE,
)

#: Added only when license assignment is requested, to keep the consent minimal.
LICENSING_SCOPES: tuple[str, ...] = (LICENSING_SCOPE,)

TOKEN_CACHE_DIR = Path.home() / ".cold-email-domain-provisioner"


def build_credentials(
    credentials_path: Path,
    *,
    scopes: tuple[str, ...] = ADMIN_SCOPES,
    admin_email: str | None = None,
):
    """Build credentials from ``credentials_path``, choosing the flow by file type."""
    try:
        payload = json.loads(credentials_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot read Google credentials file {credentials_path}: {exc}") from exc

    if payload.get("type") == "service_account":
        return _service_account_credentials(credentials_path, scopes, admin_email)
    if "installed" in payload or "web" in payload:
        return _oauth_credentials(credentials_path, scopes)

    raise ConfigError(
        f"{credentials_path} is neither a service-account key nor an OAuth "
        f"client-secrets file. Download one of those from the Google Cloud console."
    )


def build_service(name: str, version: str, credentials):
    """Build a discovery client with the discovery cache off.

    The cache emits noisy warnings under recent ``oauth2client``-free installs
    and buys nothing for a short-lived CLI run.
    """
    from googleapiclient.discovery import build

    return build(name, version, credentials=credentials, cache_discovery=False)


def directory_service(credentials):
    """The Admin SDK Directory API client."""
    return build_service("admin", "directory_v1", credentials)


def site_verification_service(credentials):
    """The Site Verification API client."""
    return build_service("siteVerification", "v1", credentials)


def licensing_service(credentials):
    """The Enterprise License Manager API client."""
    return build_service("licensing", "v1", credentials)


def _service_account_credentials(path: Path, scopes: tuple[str, ...], admin_email: str | None):
    from google.oauth2 import service_account

    if not admin_email:
        raise ConfigError(
            "a service account must impersonate a Workspace super admin: supply "
            "the admin email (CEDP_GOOGLE_ADMIN_EMAIL or --admin-email). The "
            "service account also needs these scopes authorised for domain-wide "
            f"delegation in the Admin console: {', '.join(scopes)}"
        )
    credentials = service_account.Credentials.from_service_account_file(
        str(path), scopes=list(scopes)
    )
    return credentials.with_subject(admin_email)


def _oauth_credentials(path: Path, scopes: tuple[str, ...]):
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow

    TOKEN_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    token_path = TOKEN_CACHE_DIR / "token.json"

    credentials = None
    if token_path.is_file():
        try:
            credentials = Credentials.from_authorized_user_file(str(token_path), list(scopes))
        except ValueError:
            credentials = None

    if credentials and credentials.valid:
        return credentials
    if credentials and credentials.expired and credentials.refresh_token:
        try:
            credentials.refresh(Request())
            token_path.write_text(credentials.to_json(), encoding="utf-8")
            return credentials
        except Exception as exc:  # noqa: BLE001 - any refresh failure falls back to re-consent
            raise GoogleError(f"cached Google token could not be refreshed: {exc}") from exc

    flow = InstalledAppFlow.from_client_secrets_file(str(path), list(scopes))
    credentials = flow.run_local_server(port=0)
    token_path.write_text(credentials.to_json(), encoding="utf-8")
    return credentials
