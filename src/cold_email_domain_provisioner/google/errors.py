"""Turn ``googleapiclient`` errors into readable messages.

``HttpError`` stringifies to a long URL-bearing blob. These helpers pull out
the status and the reason, and let callers treat "not found" as an answer
rather than a failure.
"""

from __future__ import annotations

import json
from typing import Any


def status_of(exc: Exception) -> int | None:
    """The HTTP status on a ``googleapiclient`` error, if it carries one."""
    response = getattr(exc, "resp", None)
    status = getattr(response, "status", None)
    if isinstance(status, int):
        return status
    status_code = getattr(exc, "status_code", None)
    return status_code if isinstance(status_code, int) else None


def is_not_found(exc: Exception) -> bool:
    """True for a 404, which several calls here treat as "does not exist yet"."""
    return status_of(exc) == 404


def is_conflict(exc: Exception) -> bool:
    """True for a 409, meaning the resource already exists."""
    return status_of(exc) == 409


def http_error_message(exc: Exception) -> str:
    """A short, readable description of a Google API failure."""
    status = status_of(exc)
    detail = _detail_from_content(getattr(exc, "content", None)) or str(exc)
    return f"HTTP {status}: {detail}" if status else detail


def _detail_from_content(content: Any) -> str | None:
    if not content:
        return None
    try:
        text = content.decode("utf-8") if isinstance(content, bytes) else str(content)
        payload = json.loads(text)
    except (ValueError, UnicodeDecodeError):
        return None

    error = payload.get("error") if isinstance(payload, dict) else None
    if not isinstance(error, dict):
        return None

    message = error.get("message")
    errors = error.get("errors")
    reason = ""
    if isinstance(errors, list) and errors and isinstance(errors[0], dict):
        reason = str(errors[0].get("reason", ""))
    if message and reason:
        return f"{message} ({reason})"
    return str(message) if message else None
