"""
GoogleProvider subclass that keeps OAuth 2.1 sessions alive while they are used.

Problem
-------
FastMCP's OAuthProxy stores the upstream (Google) refresh token and the JTI
mappings that link FastMCP-issued tokens to it with a TTL derived from the
upstream ``refresh_expires_in``. Google never sends that field, so FastMCP
uses ``fallback_refresh_token_expiry_seconds`` counted from the *initial*
login (30 days in fastmcp 3.2, 1 year in 4.x). On refresh, Google does not
rotate the refresh token, so FastMCP keeps the original deadline instead of
extending it. When the deadline passes, the stored mappings expire, the next
refresh fails with ``invalid_grant`` and the MCP client (e.g. Claude) asks the
user to disconnect/reconnect — regardless of how actively it was used.

Fix
---
Google refresh tokens do not have a fixed lifetime: they stay valid until
revoked, or until unused for ~6 months. We:

* pass the configured window as ``fallback_refresh_token_expiry_seconds`` so
  the initial login gets it, and
* wrap the upstream OAuth client so that Google's token responses get a
  ``refresh_expires_in``. FastMCP then treats each
  refresh as extending the refresh-token lifetime, turning the fixed deadline
  into a sliding window.

If Google does report a lifetime (``refresh_token_expires_in``, used for
time-limited consent), that value is respected instead. The default window is
2 years: Google itself still revokes tokens that go unused for ~6 months, in
which case the refresh fails and the user reconnects, so a long local TTL is
harmless.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from auth.google_oauth_provider import GoogleProvider

logger = logging.getLogger(__name__)

REFRESH_TOKEN_TTL_DAYS_ENV = "WORKSPACE_MCP_OAUTH_REFRESH_TOKEN_TTL_DAYS"
DEFAULT_REFRESH_TOKEN_TTL_DAYS = 730  # 2 years


def get_refresh_token_ttl_seconds() -> int:
    """Sliding refresh-token lifetime in seconds (env-configurable)."""
    raw = os.getenv(REFRESH_TOKEN_TTL_DAYS_ENV, "").strip()
    if raw:
        try:
            days = int(raw)
            if days > 0:
                return days * 24 * 60 * 60
        except ValueError:
            pass
        logger.warning(
            "Ignoring invalid %s=%r; using %d days",
            REFRESH_TOKEN_TTL_DAYS_ENV,
            raw,
            DEFAULT_REFRESH_TOKEN_TTL_DAYS,
        )
    return DEFAULT_REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60


def _with_refresh_expiry(token: Any, ttl_seconds: int) -> Any:
    """Add ``refresh_expires_in`` to a parsed token response if missing."""
    if not isinstance(token, dict) or "access_token" not in token:
        return token
    if token.get("refresh_expires_in"):
        return token
    google_ttl = token.get("refresh_token_expires_in")
    try:
        google_ttl = int(google_ttl) if google_ttl else None
    except (TypeError, ValueError):
        google_ttl = None
    token["refresh_expires_in"] = google_ttl or ttl_seconds
    return token


class _SlidingRefreshUpstreamClient:
    """Wraps the upstream OAuth client and annotates its token responses.

    FastMCP documents that ``_create_upstream_oauth_client`` may return any
    object exposing ``fetch_token`` / ``refresh_token`` / ``client_secret`` /
    ``aclose``. Wrapping (instead of relying on a specific client class) keeps
    this working whether FastMCP uses authlib's client (3.x) or its own
    httpx2-based one (4.x).
    """

    def __init__(self, inner: Any, ttl_seconds: int) -> None:
        self._inner = inner
        self._ttl_seconds = ttl_seconds

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def fetch_token(self, *args: Any, **kwargs: Any) -> Any:
        token = await self._inner.fetch_token(*args, **kwargs)
        return _with_refresh_expiry(token, self._ttl_seconds)

    async def refresh_token(self, *args: Any, **kwargs: Any) -> Any:
        token = await self._inner.refresh_token(*args, **kwargs)
        return _with_refresh_expiry(token, self._ttl_seconds)

    async def aclose(self) -> None:
        await self._inner.aclose()


class SlidingRefreshGoogleProvider(GoogleProvider):
    """GoogleProvider whose refresh-token lifetime slides forward on each refresh."""

    def __init__(
        self, *args: Any, refresh_token_ttl_seconds: int | None = None, **kwargs: Any
    ):
        ttl = refresh_token_ttl_seconds or get_refresh_token_ttl_seconds()
        kwargs.setdefault("fallback_refresh_token_expiry_seconds", ttl)
        super().__init__(*args, **kwargs)
        self._refresh_token_ttl_seconds = ttl
        logger.info(
            "OAuth 2.1: sliding refresh-token lifetime enabled (%d days)",
            ttl // 86400,
        )

    def _create_upstream_oauth_client(self) -> Any:
        # Covers the initial authorization-code exchange (fetch_token) and every
        # upstream refresh, explicit and transparent (refresh_token).
        return _SlidingRefreshUpstreamClient(
            super()._create_upstream_oauth_client(), self._refresh_token_ttl_seconds
        )
