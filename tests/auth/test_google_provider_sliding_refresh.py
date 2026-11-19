"""
Regression tests for the fixed-deadline OAuth 2.1 session cliff.

Simulates Google's token endpoint (which never returns ``refresh_expires_in``
and does not rotate refresh tokens) and drives FastMCP's real OAuthProxy code
paths: initial code exchange and refresh-token exchange.
"""

import time
from urllib.parse import parse_qs

import fastmcp.server.auth.oauth_proxy.proxy as proxy_module
import httpx2 as httpx  # authlib's httpx_client is built on httpx2
import pytest
from authlib.integrations.httpx_client import AsyncOAuth2Client
from fastmcp.server.auth.oauth_proxy.models import (
    DEFAULT_REFRESH_TOKEN_EXPIRY_SECONDS,
    ClientCode,
)
from fastmcp.server.auth.providers.google import GoogleProvider
from key_value.aio.stores.memory import MemoryStore
from mcp.server.auth.provider import AuthorizationCode
from mcp.shared.auth import OAuthClientInformationFull

from auth.google_provider import SlidingRefreshGoogleProvider

DAY = 24 * 60 * 60
SCOPES = ["openid", "https://www.googleapis.com/auth/userinfo.email"]


def _google_token_endpoint(request: httpx.Request) -> httpx.Response:
    form = parse_qs(request.content.decode())
    grant = form["grant_type"][0]
    body = {
        "access_token": f"ya29.{grant}-{time.time_ns()}",
        "expires_in": 3599,
        "scope": " ".join(SCOPES),
        "token_type": "Bearer",
    }
    if grant == "authorization_code":
        body["refresh_token"] = "1//google-refresh-token"
    # Google's refresh response has no refresh_token and no refresh_expires_in.
    return httpx.Response(200, json=body)


@pytest.fixture(autouse=True)
def mock_google(monkeypatch):
    transport = httpx.MockTransport(_google_token_endpoint)

    class MockedClient(AsyncOAuth2Client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(proxy_module, "AsyncOAuth2Client", MockedClient)


def _make_provider(cls):
    provider = cls(
        client_id="test-client.apps.googleusercontent.com",
        client_secret="test-secret-with-enough-entropy-123456",
        base_url="https://mcp.example.com",
        required_scopes=["openid"],
        valid_scopes=SCOPES,
        client_storage=MemoryStore(),
        jwt_signing_key="test-jwt-signing-key-0123456789",
    )
    provider.get_routes(mcp_path="/mcp")  # initializes the JWT issuer
    return provider


async def _connect(provider):
    """Run the upstream code exchange + FastMCP token issuance like a real login."""
    oauth_client = provider._create_upstream_oauth_client()
    idp_tokens = await oauth_client.fetch_token(
        url=provider._upstream_token_endpoint,
        code="google-auth-code",
        redirect_uri="https://mcp.example.com/auth/callback",
    )
    client = OAuthClientInformationFull(
        client_id="claude-client",
        redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
        scope=" ".join(SCOPES),
    )
    await provider._code_store.put(
        key="mcp-code",
        value=ClientCode(
            code="mcp-code",
            client_id=client.client_id,
            redirect_uri="https://claude.ai/api/mcp/auth_callback",
            code_challenge=None,
            code_challenge_method="S256",
            scopes=SCOPES,
            idp_tokens=dict(idp_tokens),
            expires_at=time.time() + 300,
            created_at=time.time(),
        ),
        ttl=300,
    )
    token = await provider.exchange_authorization_code(
        client,
        AuthorizationCode(
            code="mcp-code",
            scopes=SCOPES,
            expires_at=time.time() + 300,
            client_id=client.client_id,
            code_challenge="x",
            redirect_uri="https://claude.ai/api/mcp/auth_callback",
            redirect_uri_provided_explicitly=True,
        ),
    )
    return client, token


async def _upstream_for(provider, fastmcp_refresh_token):
    jti = provider.jwt_issuer.verify_token(
        fastmcp_refresh_token, expected_token_use="refresh"
    )["jti"]
    mapping, mapping_ttl = await provider._jti_mapping_store.ttl(key=jti)
    upstream = await provider._upstream_token_store.get(key=mapping.upstream_token_id)
    return upstream, mapping_ttl


async def _age_session(provider, fastmcp_refresh_token, remaining_seconds):
    """Pretend the session was created long ago: only `remaining_seconds` left."""
    upstream, _ = await _upstream_for(provider, fastmcp_refresh_token)
    upstream.refresh_token_expires_at = time.time() + remaining_seconds
    await provider._upstream_token_store.put(
        key=upstream.upstream_token_id, value=upstream, ttl=remaining_seconds
    )


async def _refresh(provider, client, fastmcp_refresh_token):
    rt = await provider.load_refresh_token(client, fastmcp_refresh_token)
    assert rt is not None
    return await provider.exchange_refresh_token(client, rt, SCOPES)


@pytest.mark.asyncio
async def test_baseline_google_provider_has_fixed_deadline():
    """Documents the upstream bug: refresh does not extend the session.

    If this starts failing after a FastMCP upgrade, upstream may have fixed
    sliding expiry and SlidingRefreshGoogleProvider may no longer be needed.
    """
    provider = _make_provider(GoogleProvider)
    client, token = await _connect(provider)
    upstream, _ = await _upstream_for(provider, token.refresh_token)
    assert upstream.refresh_token_expires_at - time.time() == pytest.approx(
        DEFAULT_REFRESH_TOKEN_EXPIRY_SECONDS, abs=60
    )

    await _age_session(provider, token.refresh_token, remaining_seconds=DAY)
    new = await _refresh(provider, client, token.refresh_token)
    upstream, mapping_ttl = await _upstream_for(provider, new.refresh_token)

    # Deadline is still 1 day away despite active use -> cliff.
    assert upstream.refresh_token_expires_at - time.time() == pytest.approx(DAY, abs=60)
    assert mapping_ttl == pytest.approx(DAY, abs=60)


@pytest.mark.asyncio
async def test_initial_login_uses_configured_lifetime(monkeypatch):
    monkeypatch.delenv("WORKSPACE_MCP_OAUTH_REFRESH_TOKEN_TTL_DAYS", raising=False)
    provider = _make_provider(SlidingRefreshGoogleProvider)
    _, token = await _connect(provider)
    upstream, mapping_ttl = await _upstream_for(provider, token.refresh_token)

    assert upstream.refresh_token_expires_at - time.time() == pytest.approx(
        730 * DAY, abs=60
    )
    assert mapping_ttl == pytest.approx(730 * DAY, abs=60)
    refresh_exp = provider.jwt_issuer.verify_token(
        token.refresh_token, expected_token_use="refresh"
    )["exp"]
    assert refresh_exp - time.time() == pytest.approx(730 * DAY, abs=60)


@pytest.mark.asyncio
async def test_refresh_slides_deadline_forward():
    provider = _make_provider(SlidingRefreshGoogleProvider)
    client, token = await _connect(provider)

    # Session is about to hit its deadline...
    await _age_session(provider, token.refresh_token, remaining_seconds=DAY)
    new = await _refresh(provider, client, token.refresh_token)
    upstream, mapping_ttl = await _upstream_for(provider, new.refresh_token)

    # ...but an actual refresh pushes it forward by the full window.
    assert upstream.refresh_token_expires_at - time.time() == pytest.approx(
        730 * DAY, abs=60
    )
    assert mapping_ttl == pytest.approx(730 * DAY, abs=60)
    assert upstream.refresh_token == "1//google-refresh-token"
    refresh_exp = provider.jwt_issuer.verify_token(
        new.refresh_token, expected_token_use="refresh"
    )["exp"]
    assert refresh_exp - time.time() == pytest.approx(730 * DAY, abs=60)

    # Chain keeps working on subsequent refreshes.
    newer = await _refresh(provider, client, new.refresh_token)
    assert newer.access_token


@pytest.mark.asyncio
async def test_ttl_env_override(monkeypatch):
    monkeypatch.setenv("WORKSPACE_MCP_OAUTH_REFRESH_TOKEN_TTL_DAYS", "90")
    provider = _make_provider(SlidingRefreshGoogleProvider)
    _, token = await _connect(provider)
    upstream, _ = await _upstream_for(provider, token.refresh_token)
    assert upstream.refresh_token_expires_at - time.time() == pytest.approx(
        90 * DAY, abs=60
    )


@pytest.mark.asyncio
async def test_google_reported_lifetime_is_respected(monkeypatch):
    """Time-limited consent: Google sends refresh_token_expires_in; keep it."""

    def endpoint(request):
        resp = _google_token_endpoint(request)
        body = resp.json()
        body["refresh_token_expires_in"] = 7 * DAY
        return httpx.Response(200, json=body)

    transport = httpx.MockTransport(endpoint)

    class MockedClient(AsyncOAuth2Client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(proxy_module, "AsyncOAuth2Client", MockedClient)
    provider = _make_provider(SlidingRefreshGoogleProvider)
    _, token = await _connect(provider)
    upstream, _ = await _upstream_for(provider, token.refresh_token)
    assert upstream.refresh_token_expires_at - time.time() == pytest.approx(
        7 * DAY, abs=60
    )


@pytest.mark.asyncio
async def test_error_responses_untouched(monkeypatch):
    def endpoint(request):
        return httpx.Response(
            400, json={"error": "invalid_grant", "error_description": "revoked"}
        )

    transport = httpx.MockTransport(endpoint)

    class MockedClient(AsyncOAuth2Client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(proxy_module, "AsyncOAuth2Client", MockedClient)
    provider = _make_provider(SlidingRefreshGoogleProvider)
    oauth_client = provider._create_upstream_oauth_client()
    with pytest.raises(Exception, match="invalid_grant"):
        await oauth_client.refresh_token(
            url=provider._upstream_token_endpoint, refresh_token="revoked"
        )
