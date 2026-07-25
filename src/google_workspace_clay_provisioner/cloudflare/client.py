"""Minimal Cloudflare v4 API client.

Handles the one thing every Cloudflare call has in common: the
``{"success": bool, "errors": [...], "result": ...}`` envelope. Callers get the
``result`` payload or a ``CloudflareError`` carrying the API's own message.

The API token is never logged, and ``repr`` is overridden so it cannot leak
into a traceback.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..errors import CloudflareError

BASE_URL = "https://api.cloudflare.com/client/v4"
DEFAULT_TIMEOUT = 30.0


class CloudflareClient:
    """Authenticated Cloudflare v4 client with envelope handling."""

    def __init__(
        self,
        api_token: str,
        *,
        base_url: str = BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not api_token:
            raise CloudflareError("a Cloudflare API token is required")
        self._base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=self._base_url,
            timeout=timeout,
            headers={
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
            },
            transport=transport,
        )

    def __repr__(self) -> str:
        """Deliberately omits the token so it cannot surface in a traceback."""
        return f"CloudflareClient(base_url={self._base_url!r})"

    def __enter__(self) -> CloudflareClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        expect: tuple[int, ...] = (200, 201, 202),
    ) -> tuple[Any, int]:
        """Make a request and return ``(result, status_code)``.

        Registration returns 201 or 202 with different meanings, so the status
        code is returned alongside the payload rather than discarded.
        """
        try:
            response = self._client.request(method, path, json=json, params=params)
        except httpx.HTTPError as exc:
            raise CloudflareError(f"{method} {path} failed: {exc}") from exc

        payload = self._decode(response, method, path)
        if response.status_code not in expect or not payload.get("success", False):
            raise CloudflareError(
                f"{method} {path} returned {response.status_code}: "
                f"{describe_errors(payload) or response.text[:400]}"
            )
        return payload.get("result"), response.status_code

    def get(self, path: str, **kwargs: Any) -> Any:
        """GET, returning just the ``result`` payload."""
        return self.request("GET", path, **kwargs)[0]

    def post(self, path: str, **kwargs: Any) -> Any:
        """POST, returning just the ``result`` payload."""
        return self.request("POST", path, **kwargs)[0]

    def put(self, path: str, **kwargs: Any) -> Any:
        """PUT, returning just the ``result`` payload."""
        return self.request("PUT", path, **kwargs)[0]

    def delete(self, path: str, **kwargs: Any) -> Any:
        """DELETE, returning just the ``result`` payload."""
        return self.request("DELETE", path, **kwargs)[0]

    def get_optional(self, path: str, **kwargs: Any) -> Any | None:
        """GET that returns ``None`` on 404 instead of raising.

        Used for "does this exist yet" probes, where absence is an expected
        answer rather than a failure.
        """
        try:
            response = self._client.request("GET", path, **kwargs)
        except httpx.HTTPError as exc:
            raise CloudflareError(f"GET {path} failed: {exc}") from exc
        if response.status_code == 404:
            return None
        payload = self._decode(response, "GET", path)
        if response.status_code != 200 or not payload.get("success", False):
            raise CloudflareError(
                f"GET {path} returned {response.status_code}: "
                f"{describe_errors(payload) or response.text[:400]}"
            )
        return payload.get("result")

    @staticmethod
    def _decode(response: httpx.Response, method: str, path: str) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError as exc:
            raise CloudflareError(
                f"{method} {path} returned {response.status_code} with a non-JSON body: "
                f"{response.text[:200]}"
            ) from exc
        if not isinstance(payload, dict):
            raise CloudflareError(f"{method} {path} returned an unexpected JSON shape")
        return payload


def describe_errors(payload: dict[str, Any]) -> str:
    """Flatten Cloudflare's ``errors`` array into one readable line."""
    errors = payload.get("errors") or []
    parts = []
    for item in errors:
        if isinstance(item, dict):
            code, message = item.get("code"), item.get("message", "")
            parts.append(f"[{code}] {message}" if code else str(message))
        else:
            parts.append(str(item))
    return "; ".join(part for part in parts if part)
