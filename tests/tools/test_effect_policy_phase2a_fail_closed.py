"""Phase-2A fail-closed permit-issuance regressions."""

import threading

from tools.effect_policy import EffectKind, EffectPolicy, PolicyDecision
from tools.effect_policy_runtime import (
    authorize_and_issue_effect_permit,
    bind_issued_effect_permit,
)
from tools.registry import ToolRegistry


def _registry_with_computer_use() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        name="computer_use",
        toolset="computer_use",
        schema={"name": "computer_use", "description": "test"},
        handler=lambda *_args, **_kwargs: '{"ok": true}',
    )
    return registry


def test_permit_issuance_fails_closed_when_policy_resolution_raises(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools import registry as registry_module

    registry = _registry_with_computer_use()
    monkeypatch.setattr(registry_module, "registry", registry)
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: (_ for _ in ()).throw(RuntimeError("policy unavailable")),
    )

    result, permit = authorize_and_issue_effect_permit(
        "computer_use", {"action": "click"}
    )

    assert result.decision is PolicyDecision.DENY
    assert result.non_bypassable is True
    assert "policy unavailable" in result.reason
    assert permit is None


def test_permit_issuance_rejects_caller_args_changed_during_approval(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools import registry as registry_module

    registry = _registry_with_computer_use()
    monkeypatch.setattr(registry_module, "registry", registry)
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(
            approval_required_effects=frozenset({EffectKind.COMPUTER_CONTROL})
        ),
    )
    supplied = {"action": "click", "element": 1}

    def mutate_then_approve(*_args, **_kwargs):
        supplied["element"] = 2
        return {"approved": True}

    monkeypatch.setattr("tools.approval.request_tool_approval", mutate_then_approve)

    result, permit = authorize_and_issue_effect_permit("computer_use", supplied)

    assert result.decision is PolicyDecision.DENY
    assert result.non_bypassable is True
    assert "arguments changed" in result.reason
    assert permit is None


def test_cached_effect_approval_does_not_cross_registration_replacement(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools import registry as registry_module

    registry = ToolRegistry()
    executed = []
    registry.register(
        name="computer_use",
        toolset="computer_use",
        schema={"name": "computer_use", "description": "test"},
        handler=lambda *_args, **_kwargs: executed.append("old") or '{"ok": true}',
    )
    monkeypatch.setattr(registry_module, "registry", registry)
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(
            approval_required_effects=frozenset({EffectKind.COMPUTER_CONTROL})
        ),
    )
    cached = set()
    human_prompts = []

    def approval_cache(*_args, rule_key, **_kwargs):
        if rule_key not in cached:
            cached.add(rule_key)
            human_prompts.append(rule_key)
        return {"approved": True}

    monkeypatch.setattr("tools.approval.request_tool_approval", approval_cache)
    args = {"action": "click", "element": 1}
    result, permit = authorize_and_issue_effect_permit("computer_use", args)
    assert result.decision is PolicyDecision.ALLOW
    assert permit is not None

    registry.register(
        name="computer_use",
        toolset="computer_use",
        schema={"name": "computer_use", "description": "replacement"},
        handler=lambda *_args, **_kwargs: executed.append("new") or '{"ok": true}',
    )
    with bind_issued_effect_permit(permit):
        dispatched = registry.dispatch("computer_use", args)

    assert dispatched == '{"ok": true}'
    assert executed == ["new"]
    assert len(human_prompts) == 2
    assert human_prompts[0] != human_prompts[1]


def test_cached_effect_approval_does_not_cross_in_place_handler_change(monkeypatch):
    from tools import effect_policy_runtime as runtime

    registry = ToolRegistry()
    executed = []
    registry.register(
        name="computer_use",
        toolset="computer_use",
        schema={"name": "computer_use", "description": "test"},
        handler=lambda *_args, **_kwargs: executed.append("old") or '{"ok": true}',
    )
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(
            approval_required_effects=frozenset({EffectKind.COMPUTER_CONTROL})
        ),
    )
    cached = set()
    human_prompts = []

    def approval_cache(*_args, rule_key, **_kwargs):
        if rule_key not in cached:
            cached.add(rule_key)
            human_prompts.append(rule_key)
        return {"approved": True}

    monkeypatch.setattr("tools.approval.request_tool_approval", approval_cache)
    args = {"action": "click", "element": 1}
    assert registry.dispatch("computer_use", args) == '{"ok": true}'

    entry = registry.get_entry("computer_use")
    assert entry is not None
    entry.handler = (
        lambda *_args, **_kwargs: executed.append("new") or '{"ok": true}'
    )
    assert registry.dispatch("computer_use", args) == '{"ok": true}'

    assert executed == ["old", "new"]
    assert len(human_prompts) == 2
    assert human_prompts[0] != human_prompts[1]


def test_cached_approval_rotates_on_deregister_and_restore(monkeypatch):
    from tools import effect_policy_runtime as runtime

    registry = ToolRegistry()
    handler = lambda *_args, **_kwargs: '{"ok": true}'
    registry.register(
        name="computer_use",
        toolset="computer_use",
        schema={"name": "computer_use", "description": "first"},
        handler=handler,
    )
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(
            approval_required_effects=frozenset({EffectKind.COMPUTER_CONTROL})
        ),
    )
    human_prompts = []
    monkeypatch.setattr(
        "tools.approval.request_tool_approval",
        lambda *_args, rule_key, **_kwargs: human_prompts.append(rule_key)
        or {"approved": True},
    )
    args = {"action": "click", "element": 1}
    assert registry.dispatch("computer_use", args) == '{"ok": true}'

    first = registry.get_entry("computer_use")
    assert first is not None
    registry.deregister("computer_use")
    assert registry.get_entry("computer_use") is None
    registry.register(
        name="computer_use",
        toolset="computer_use",
        schema={"name": "computer_use", "description": "second"},
        handler=handler,
    )
    second = registry.get_entry("computer_use")
    assert second is not None
    assert registry.dispatch("computer_use", args) == '{"ok": true}'

    assert registry.restore_registration("computer_use", second, first)
    assert registry.dispatch("computer_use", args) == '{"ok": true}'
    assert len(human_prompts) == 3
    assert len(set(human_prompts)) == 3


def test_computer_handler_does_not_hold_registry_lock(monkeypatch):
    from tools import effect_policy_runtime as runtime

    registry = ToolRegistry()
    started = threading.Event()
    release = threading.Event()
    dummy_done = threading.Event()

    def computer_handler(*_args, **_kwargs):
        started.set()
        release.wait(2)
        return '{"ok": true}'

    registry.register(
        name="computer_use",
        toolset="computer_use",
        schema={"name": "computer_use", "description": "test"},
        handler=computer_handler,
    )
    registry.register(
        name="dummy",
        toolset="dummy",
        schema={"name": "dummy", "description": "test"},
        handler=lambda *_args, **_kwargs: dummy_done.set() or '{"ok": true}',
    )
    monkeypatch.setattr(runtime, "load_effect_policy", lambda: EffectPolicy())

    computer_thread = threading.Thread(
        target=lambda: registry.dispatch("computer_use", {"action": "wait"})
    )
    computer_thread.start()
    assert started.wait(1)
    dummy_thread = threading.Thread(target=lambda: registry.dispatch("dummy", {}))
    dummy_thread.start()
    try:
        assert dummy_done.wait(0.5)
    finally:
        release.set()
        computer_thread.join(2)
        dummy_thread.join(2)
    assert not computer_thread.is_alive()
    assert not dummy_thread.is_alive()
