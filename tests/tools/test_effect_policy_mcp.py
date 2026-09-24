"""Effect-policy coverage for MCP registration and plugin-direct calls."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from hermes_cli.plugins import PluginContext, PluginManifest
from tools.effect_policy import EffectDescriptor, EffectKind, EffectMode, EffectPolicy
from tools import effect_policy_runtime as runtime
from tools import mcp_tool_handlers
from tools import mcp_tool_registration as registration


def _candidate(read_only_hint, *, trusted=False):
    tool = SimpleNamespace(
        name="operation",
        description="test",
        inputSchema={"type": "object", "properties": {}},
        annotations=SimpleNamespace(readOnlyHint=read_only_hint),
    )
    return registration._tool_candidates(
        "server",
        [tool],
        lambda _: True,
        30,
        trust_read_only_hints=trusted,
    )[0]


def test_mcp_candidate_does_not_trust_remote_read_only_hint_by_default():
    candidate = _candidate(True)

    assert candidate.effect_descriptor.effects[0].effect is EffectKind.MCP_MUTATE
    assert candidate.effect_descriptor.effects[0].mutability is runtime.Mutability.MUTATING


def test_mcp_candidate_binds_read_only_descriptor_from_exact_true_hint():
    candidate = _candidate(True, trusted=True)

    assert candidate.effect_descriptor == EffectDescriptor.static(
        runtime.EffectTemplate(
            effect=EffectKind.MCP_READ,
            resource=runtime.ResourceKind.MCP,
            mutability=runtime.Mutability.READ_ONLY,
        )
    )


@pytest.mark.parametrize("hint", [False, None, "true", 1])
def test_mcp_candidate_binds_mutating_descriptor_when_hint_is_not_exact_true(hint):
    candidate = _candidate(hint)

    assert candidate.effect_descriptor.mode is EffectMode.STATIC
    assert candidate.effect_descriptor.effects[0].effect is EffectKind.MCP_MUTATE
    assert candidate.effect_descriptor.effects[0].mutability is runtime.Mutability.MUTATING


def _plugin_context() -> PluginContext:
    manager = MagicMock()
    manager.home_path = None
    return PluginContext(PluginManifest(name="plug", key="plug"), manager)


def _configure_plugin_call(monkeypatch, *, read_only: bool, called: list[dict]):
    import hermes_cli.config as config_mod
    from tools.mcp_tool_schema import mcp_prefixed_tool_name
    from tools.registry import ToolRegistry, registry

    monkeypatch.setattr(
        config_mod,
        "load_config",
        lambda *a, **k: {"plugins": {"entries": {"plug": {"mcp_allowlist": ["server"]}}}},
    )
    local_registry = ToolRegistry()
    local_registry.register(
        name=mcp_prefixed_tool_name("server", "operation"),
        toolset="mcp-server",
        schema={"name": "operation"},
        handler=lambda args, **kwargs: called.append(args) or '{"result": "ok"}',
        effect_descriptor=registration._mcp_effect_descriptor(read_only=read_only),
    )
    monkeypatch.setattr(registry, "get_entry", local_registry.get_entry)
    monkeypatch.setattr(registry, "dispatch", local_registry.dispatch)


def test_plugin_direct_mcp_mutation_obeys_effect_policy(monkeypatch):
    called = []
    _configure_plugin_call(monkeypatch, read_only=False, called=called)
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(denied_effects=frozenset({EffectKind.MCP_MUTATE})),
    )

    with pytest.raises(PermissionError, match="effect policy"):
        _plugin_context().call_mcp("server", "operation", {"x": 1})

    assert called == []


def test_plugin_direct_mcp_rejects_policy_change_during_approval(monkeypatch):
    called = []
    _configure_plugin_call(monkeypatch, read_only=False, called=called)
    current_policy = {
        "value": EffectPolicy(
            approval_required_effects=frozenset({EffectKind.MCP_MUTATE})
        )
    }
    monkeypatch.setattr(runtime, "load_effect_policy", lambda: current_policy["value"])

    def approve_and_tighten(*args, **kwargs):
        current_policy["value"] = EffectPolicy(
            denied_effects=frozenset({EffectKind.MCP_MUTATE})
        )
        return {"approved": True}

    monkeypatch.setattr("tools.approval.request_tool_approval", approve_and_tighten)

    with pytest.raises(PermissionError, match="effect policy"):
        _plugin_context().call_mcp("server", "operation", {"x": 1})

    assert called == []


def test_plugin_direct_mcp_rejects_stale_tool_absent_from_profile_registry(monkeypatch):
    called = []
    _configure_plugin_call(monkeypatch, read_only=True, called=called)
    ctx = _plugin_context()
    monkeypatch.setattr("tools.registry.registry.get_entry", lambda *args, **kwargs: None)

    with pytest.raises(PermissionError, match="not registered"):
        ctx.call_mcp("server", "operation", {"x": 1})

    assert called == []


def test_plugin_direct_read_only_mcp_call_survives_mutation_deny(monkeypatch):
    called = []
    _configure_plugin_call(monkeypatch, read_only=True, called=called)
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(denied_effects=frozenset({EffectKind.MCP_MUTATE})),
    )

    result = _plugin_context().call_mcp("server", "operation", {"x": 1})

    assert result == {"ok": True, "result": "ok"}
    assert called == [{"x": 1}]
