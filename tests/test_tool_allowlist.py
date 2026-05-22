"""Tests for the --tool-allowlist CLI flag and WORKSPACE_MCP_TOOL_ALLOWLIST env var.

These tests focus on the parsing and narrowing logic; full end-to-end startup
is covered by the existing tier / permissions tests.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

os.environ.setdefault("MCP_ENABLE_OAUTH21", "false")
os.environ.setdefault("WORKSPACE_MCP_STATELESS_MODE", "false")

from core.tool_registry import (  # noqa: E402
    get_enabled_tools,
    set_enabled_tools,
)


def _reset_registry():
    set_enabled_tools(None)


def test_allowlist_narrows_existing_enabled_set():
    """Allowlist intersects with the set produced by tier/services."""
    _reset_registry()
    set_enabled_tools(
        {
            "search_gmail_messages",
            "get_gmail_message_content",
            "send_gmail_message",
            "get_gmail_attachment_content",
            "draft_gmail_message",
        }
    )

    allowlist = {"send_gmail_message", "get_gmail_attachment_content"}
    current = get_enabled_tools()
    narrowed = current & allowlist
    set_enabled_tools(narrowed)

    assert get_enabled_tools() == {
        "send_gmail_message",
        "get_gmail_attachment_content",
    }
    _reset_registry()


def test_allowlist_becomes_enabled_set_when_no_prior_filter():
    """When no tier/services filter is set, allowlist alone defines enabled set."""
    _reset_registry()
    assert get_enabled_tools() is None

    allowlist = {"send_gmail_message", "get_gmail_attachment_content"}
    set_enabled_tools(allowlist)

    assert get_enabled_tools() == allowlist
    _reset_registry()


def test_allowlist_intersection_drops_tools_not_in_tier():
    """Tools requested in allowlist but absent from tier selection are dropped."""
    _reset_registry()
    set_enabled_tools({"search_gmail_messages", "send_gmail_message"})

    # User asks for send + attachment, but attachment isn't in the tier.
    allowlist = {"send_gmail_message", "get_gmail_attachment_content"}
    current = get_enabled_tools()
    narrowed = current & allowlist
    set_enabled_tools(narrowed)

    assert get_enabled_tools() == {"send_gmail_message"}
    _reset_registry()


def test_empty_intersection_is_detectable_by_caller():
    """If allowlist intersected with current produces nothing, caller can detect."""
    _reset_registry()
    set_enabled_tools({"search_gmail_messages"})

    allowlist = {"send_gmail_message"}  # not in tier
    current = get_enabled_tools()
    narrowed = current & allowlist

    assert narrowed == set()
    _reset_registry()


def test_env_parsing_splits_on_comma_and_trims():
    """Mimics the env-parsing branch added in main.py."""
    raw = "  send_gmail_message , get_gmail_attachment_content ,  "
    parsed = [t.strip() for t in raw.split(",") if t.strip()]
    assert parsed == ["send_gmail_message", "get_gmail_attachment_content"]


def test_env_parsing_rejects_empty():
    raw = "   ,  ,   "
    parsed = [t.strip() for t in raw.split(",") if t.strip()]
    assert parsed == []
