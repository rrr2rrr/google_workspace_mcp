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
* register authlib compliance hooks on the upstream OAuth client that add
  ``refresh_expires_in`` to Google's token responses. FastMCP then treats each
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

from authlib.integrations.httpx_client import AsyncOAuth2Client

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


def _make_refresh_expiry_hook(ttl_seconds: int):
    """Build an authlib compliance hook that adds ``refresh_expires_in``."""

    def hook(resp: Any) -> Any:
        # ``resp`` is an httpx / httpx2 Response depending on the authlib
        # version; rebuild it with the same class.
        if resp.status_code >= 400:
            return resp
        try:
            data: Any = resp.json()
        except ValueError:  # non-JSON body (json.JSONDecodeError is a ValueError)
            return resp
        if not isinstance(data, dict) or "access_token" not in data:
            return resp
        if data.get("refresh_expires_in"):
            return resp

        google_ttl = data.get("refresh_token_expires_in")
        try:
            google_ttl = int(google_ttl) if google_ttl else None
        except (TypeError, ValueError):
            google_ttl = None
        data["refresh_expires_in"] = google_ttl or ttl_seconds

        return type(resp)(
            status_code=resp.status_code,
            json=data,
            request=resp.request,
        )

    return hook


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

    def _create_upstream_oauth_client(self) -> AsyncOAuth2Client:
        client = super()._create_upstream_oauth_client()
        hook = _make_refresh_expiry_hook(self._refresh_token_ttl_seconds)
        # access_token_response: initial authorization-code exchange.
        # refresh_token_response: every upstream refresh (explicit and transparent).
        client.register_compliance_hook("access_token_response", hook)
        client.register_compliance_hook("refresh_token_response", hook)
        return client
