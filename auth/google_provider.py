"""
GoogleProvider subclass that keeps OAuth 2.1 sessions alive while they are used.

Problem
-------
FastMCP's OAuthProxy stores the upstream (Google) refresh token and the JTI
mappings that link FastMCP-issued tokens to it with a TTL derived from the
upstream ``refresh_expires_in``. Google never sends that field, so FastMCP
falls back to a fixed 30 days counted from the *initial* login. On refresh,
Google does not rotate the refresh token, so FastMCP keeps the original
deadline instead of extending it. Exactly 30 days after "Connect" the stored
mappings expire, the next refresh fails with ``invalid_grant`` and the MCP
client (e.g. Claude) asks the user to disconnect/reconnect — regardless of
how actively the connector was used.

Fix
---
Google refresh tokens do not have a fixed lifetime: they stay valid until
revoked, or until unused for ~6 months. We register authlib compliance hooks
on the upstream OAuth client that add ``refresh_expires_in`` to Google's
token responses (both the initial code exchange and every refresh). FastMCP
then treats each refresh as extending the refresh-token lifetime, turning the
hard 30-day cliff into a sliding window. If Google does report a lifetime
(``refresh_token_expires_in``, used for time-limited consent), that value is
respected instead.

FastMCP also hard-codes a 30-day TTL for the refresh-token mapping created at
initial login; ``exchange_authorization_code`` re-stores it with the real
lifetime.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from fastmcp.server.auth.providers.google import GoogleProvider
from mcp.server.auth.provider import AuthorizationCode
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

logger = logging.getLogger(__name__)

REFRESH_TOKEN_TTL_DAYS_ENV = "WORKSPACE_MCP_OAUTH_REFRESH_TOKEN_TTL_DAYS"
DEFAULT_REFRESH_TOKEN_TTL_DAYS = 180


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

    def hook(resp: httpx.Response) -> httpx.Response:
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

        return httpx.Response(
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
        super().__init__(*args, **kwargs)
        self._refresh_token_ttl_seconds = (
            refresh_token_ttl_seconds or get_refresh_token_ttl_seconds()
        )
        logger.info(
            "OAuth 2.1: sliding refresh-token lifetime enabled (%d days)",
            self._refresh_token_ttl_seconds // 86400,
        )

    def _create_upstream_oauth_client(self) -> AsyncOAuth2Client:
        client = super()._create_upstream_oauth_client()
        hook = _make_refresh_expiry_hook(self._refresh_token_ttl_seconds)
        # access_token_response: initial authorization-code exchange.
        # refresh_token_response: every upstream refresh (explicit and transparent).
        client.register_compliance_hook("access_token_response", hook)
        client.register_compliance_hook("refresh_token_response", hook)
        return client

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        token = await super().exchange_authorization_code(client, authorization_code)
        # On initial login FastMCP stores the refresh-token JTI mapping with a
        # hard-coded 30-day TTL, ignoring refresh_expires_in. Re-store it with
        # the refresh token's actual lifetime so a session that is not used
        # (no refresh) during its first 30 days still survives.
        if token.refresh_token:
            try:
                payload = self.jwt_issuer.verify_token(
                    token.refresh_token, expected_token_use="refresh"
                )
                jti = payload["jti"]
                ttl = int(payload["exp"] - time.time())
                mapping = await self._jti_mapping_store.get(key=jti)
                if mapping is not None and ttl > 0:
                    await self._jti_mapping_store.put(key=jti, value=mapping, ttl=ttl)
            except Exception as exc:  # noqa: BLE001 - best effort, never block login
                logger.warning(
                    "OAuth 2.1: could not extend initial refresh-token mapping TTL: %s",
                    exc,
                )
        return token
