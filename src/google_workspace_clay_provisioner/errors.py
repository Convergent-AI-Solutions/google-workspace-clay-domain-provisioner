"""Exception types.

One base class so the CLI can turn any expected failure into a clean message
and a non-zero exit code, rather than a traceback.
"""


class ProvisionerError(Exception):
    """Base class for every expected failure in this tool."""


class ConfigError(ProvisionerError):
    """A required setting is missing, malformed, or contradictory."""


class CloudflareError(ProvisionerError):
    """The Cloudflare API returned an error, or a response we cannot read."""


class GoogleError(ProvisionerError):
    """A Google Workspace Admin SDK or Site Verification call failed."""


class VerificationTimeout(ProvisionerError):
    """A record or registration did not reach the expected state in time.

    Raised only after the configured attempts are exhausted; DNS propagation
    being slow is normal and is not by itself an error.
    """


class PurchaseAborted(ProvisionerError):
    """The operator did not confirm a non-refundable domain registration."""
