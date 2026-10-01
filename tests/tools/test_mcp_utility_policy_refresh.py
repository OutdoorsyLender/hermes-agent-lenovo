"""MCP utility policy must survive lazy cache, live refresh, and pinned calls."""

from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock, patch

import pytest

from tools import mcp_schema_cache as cache
from tools import mcp_tool_registration as registration
from tools.mcp_tool_schema import _build_utility_schemas
from tools.registry import ToolRegistry


_NATIVE = {"name": "get_career_profile", "description": "Profile", "inputSchema": {"type": "object"}}
_ENABLED = {"command": "fixture", "tools": {"include": ["get_career_profile"],
                                         "resources": True, "prompts": True}}
_DISABLED = {"command": "fixture", "tools": {"include": ["get_career_profile"],
                                          "resources": False, "prompts": False}}
_NATIVE_NAME = "mcp__pathzeno_life__get_career_profile"
_UTILITIES = {f"mcp__pathzeno_life__{key}" for key in
              ("list_resources", "read_resource", "list_prompts", "get_prompt")}


def _names(registry):
    return set(registry.get_tool_names_for_toolset("mcp-pathzeno_life"))


def test_policy_change_invalidates_cached_manifest_without_unrelated_cache_churn(monkeypatch, tmp_path):
    monkeypatch.setattr(cache, "_cache_path", lambda: tmp_path / "mcp_schema_cache.json")
    original = cache.config_fingerprint(_ENABLED)
    cache.write_cache_entry("pathzeno_life", original, tools=[_NATIVE],
                            utility_tools=_build_utility_schemas("pathzeno_life"))
    assert cache.get_cached_entry("pathzeno_life", original) is not None
    for family in ("resources", "prompts"):
        changed = {**_ENABLED, "tools": {**_ENABLED["tools"], family: False}}
        assert cache.config_fingerprint(changed) != original
        assert cache.get_cached_entry("pathzeno_life", cache.config_fingerprint(changed)) is None
    assert cache.config_fingerprint(_DISABLED) != original
    assert cache.config_fingerprint({**_ENABLED, "timeout": 10}) == original


@pytest.fixture
def isolated_registry(monkeypatch):
    import tools.mcp_tool as core
    import tools.registry as registry_module

    registry = ToolRegistry()
    monkeypatch.setattr(registry_module, "registry", registry)
    for ledger in ("_servers", "_server_tool_scopes", "_lazy_server_configs",
                   "_lazy_server_fingerprints", "_lazy_server_tool_names",
                   "_mcp_tool_server_names", "_server_trust_levels", "_tool_read_only_hints"):
        monkeypatch.setattr(core, ledger, {})
    return registry


def test_cached_registration_exposes_only_selected_native_tool(isolated_registry):
    entry = {"tools": [_NATIVE], "utility_tools": _build_utility_schemas("pathzeno_life")}
    # A manifest from an older version, or an already-loaded cache, must not
    # turn stale utilities into a fresh session's advertised tools.
    registration._register_from_cache_sync("pathzeno_life", _DISABLED, entry)
    assert _names(isolated_registry) == {_NATIVE_NAME}


def test_live_refresh_removes_disabled_utilities_but_keeps_native(isolated_registry):
    from tools.mcp_tool import MCPServerTask
    server = cast(MCPServerTask, SimpleNamespace(name="pathzeno_life", session=MagicMock(),
                             initialize_result=None, _tools=[SimpleNamespace(**_NATIVE, annotations=None)],
                             tool_timeout=30, _registered_tool_names=[]))
    registration._register_server_tools("pathzeno_life", server, _ENABLED)
    assert _names(isolated_registry) == {_NATIVE_NAME} | _UTILITIES
    registration._register_server_tools("pathzeno_life", server, _DISABLED)
    assert _names(isolated_registry) == {_NATIVE_NAME}


def test_pinned_disabled_utility_cannot_reach_transport(monkeypatch, isolated_registry):
    from tools import mcp_tool_config, mcp_tool_discovery, mcp_tool_handlers

    registry = isolated_registry
    policy = {"pathzeno_life": _ENABLED}
    monkeypatch.setattr(mcp_tool_config, "_load_mcp_config", lambda: policy)
    with patch.object(mcp_tool_discovery, "_get_connected_server_for_call") as connect, \
         patch.object(mcp_tool_handlers, "_dispatch", return_value='{"result": "called"}') as transport:
        registration._register_from_cache_sync(
            "pathzeno_life", _ENABLED,
            {"tools": [_NATIVE], "utility_tools": _build_utility_schemas("pathzeno_life")})
        pinned = registry.get_schema("mcp__pathzeno_life__list_resources")
        assert pinned is not None
        policy = {"pathzeno_life": _DISABLED}
        # Keep the pinned schema/registry untouched: existing conversation
        # history and its prompt-cache prefix must not be rewritten.
        result = registry.dispatch(pinned["name"], {})
        assert isinstance(result, str) and '"error"' in result
        assert registry.get_schema(pinned["name"]) == pinned
        assert registry.get_schema(_NATIVE_NAME) is not None
        connect.assert_not_called()
        transport.assert_not_called()
