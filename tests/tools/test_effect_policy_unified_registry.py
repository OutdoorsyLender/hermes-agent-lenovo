"""Unified final-dispatch effect-policy contracts.

These tests intentionally exercise the registry boundary directly so supported
plugin/internal dispatch APIs cannot bypass semantic authorization.
"""

from __future__ import annotations

import json

import pytest

from tools.effect_policy import (
    EffectDescriptor,
    EffectKind,
    EffectMode,
    EffectPolicy,
    EffectTemplate,
    Mutability,
    ResourceKind,
)
from tools.registry import ToolRegistry


def _parsed(value):
    return json.loads(value) if isinstance(value, str) else value


def _conditional(name: str) -> EffectDescriptor:
    return EffectDescriptor(
        mode=EffectMode.CONDITIONAL,
        resolver_key=name,
    )


def test_direct_registry_dispatch_denies_migrated_write_before_handler(monkeypatch):
    from tools import effect_policy_runtime as runtime

    registry = ToolRegistry()
    calls = []
    registry.register(
        name="write_file",
        toolset="file",
        schema={"name": "write_file", "description": "test"},
        handler=lambda args, **kwargs: calls.append(dict(args)) or '{"ok": true}',
        effect_descriptor=_conditional("write_file"),
    )
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(denied_effects=frozenset({EffectKind.WRITE})),
    )

    result = _parsed(registry.dispatch("write_file", {"path": "blocked.txt", "content": "x"}))

    assert result["error_type"] == "effect_policy_denied"
    assert calls == []


def test_unclassified_registered_tool_is_opaque_under_active_deny(monkeypatch):
    from tools import effect_policy_runtime as runtime

    registry = ToolRegistry()
    calls = []
    registry.register(
        name="plugin_mutator",
        toolset="plugin",
        schema={"name": "plugin_mutator", "description": "test"},
        handler=lambda args, **kwargs: calls.append(dict(args)) or '{"ok": true}',
    )
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(denied_effects=frozenset({EffectKind.NETWORK_WRITE})),
    )

    result = _parsed(registry.dispatch("plugin_mutator", {"target": "opaque"}))

    assert result["error_type"] == "effect_policy_denied"
    assert "opaque" in result["error"].lower()
    assert calls == []


def test_explicit_read_only_tool_remains_usable_with_invalid_policy(monkeypatch):
    from tools import effect_policy_runtime as runtime

    registry = ToolRegistry()
    calls = []
    registry.register(
        name="inventory_read",
        toolset="inventory",
        schema={"name": "inventory_read", "description": "test"},
        handler=lambda args, **kwargs: calls.append(dict(args)) or '{"ok": true}',
        effect_descriptor=EffectDescriptor(mode=EffectMode.READ_ONLY),
    )
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(valid=False, error="malformed policy"),
    )

    assert _parsed(registry.dispatch("inventory_read", {"query": "safe"})) == {"ok": True}
    assert calls == [{"query": "safe"}]


def test_static_mutation_descriptor_matches_dedicated_effect(monkeypatch):
    from tools import effect_policy_runtime as runtime

    registry = ToolRegistry()
    calls = []
    registry.register(
        name="remote_update",
        toolset="remote",
        schema={"name": "remote_update", "description": "test"},
        handler=lambda args, **kwargs: calls.append(dict(args)) or '{"ok": true}',
        effect_descriptor=EffectDescriptor(
            mode=EffectMode.STATIC,
            effects=(
                EffectTemplate(
                    effect=EffectKind.GITHUB_MUTATE,
                    resource=ResourceKind.GITHUB,
                    mutability=Mutability.MUTATING,
                ),
            ),
        ),
    )
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(denied_effects=frozenset({EffectKind.GITHUB_MUTATE})),
    )

    result = _parsed(registry.dispatch("remote_update", {"issue": 1}))

    assert result["error_type"] == "effect_policy_denied"
    assert calls == []


def test_replacement_without_descriptor_cannot_inherit_core_semantics(monkeypatch):
    from tools import effect_policy_runtime as runtime

    registry = ToolRegistry()
    calls = []
    registry.register(
        name="computer_use",
        toolset="computer_use",
        schema={"name": "computer_use", "description": "core"},
        handler=lambda args, **kwargs: calls.append("core") or '{"ok": true}',
        effect_descriptor=_conditional("computer_use"),
    )
    registry.register(
        name="computer_use",
        toolset="computer_use",
        schema={"name": "computer_use", "description": "replacement"},
        handler=lambda args, **kwargs: calls.append("replacement") or '{"ok": true}',
    )
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(denied_effects=frozenset({EffectKind.COMPUTER_CONTROL})),
    )

    result = _parsed(registry.dispatch("computer_use", {"action": "wait"}))

    assert result["error_type"] == "effect_policy_denied"
    assert calls == []


def test_descriptor_change_invalidates_bound_permit(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools import registry as registry_module

    registry = ToolRegistry()
    calls = []
    registry.register(
        name="plugin_tool",
        toolset="plugin",
        schema={"name": "plugin_tool", "description": "first"},
        handler=lambda args, **kwargs: calls.append("first") or '{"ok": true}',
        effect_descriptor=EffectDescriptor(mode=EffectMode.READ_ONLY),
    )
    monkeypatch.setattr(registry_module, "registry", registry)
    monkeypatch.setattr(runtime, "load_effect_policy", lambda: EffectPolicy())

    result, permit = runtime.authorize_and_issue_effect_permit("plugin_tool", {"value": 1})
    assert result.decision.value == "allow"
    assert permit is not None

    registry.register(
        name="plugin_tool",
        toolset="plugin",
        schema={"name": "plugin_tool", "description": "replacement"},
        handler=lambda args, **kwargs: calls.append("replacement") or '{"ok": true}',
        effect_descriptor=EffectDescriptor(mode=EffectMode.OPAQUE),
    )
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(denied_effects=frozenset({EffectKind.NETWORK_WRITE})),
    )

    with runtime.bind_issued_effect_permit(permit):
        dispatched = _parsed(registry.dispatch("plugin_tool", {"value": 1}))

    assert dispatched["error_type"] == "effect_policy_denied"
    assert calls == []


def test_conditional_resolver_failure_denies_even_with_empty_policy(monkeypatch):
    from tools import effect_policy_runtime as runtime

    registry = ToolRegistry()
    calls = []
    registry.register(
        name="broken_classifier",
        toolset="plugin",
        schema={"name": "broken_classifier", "description": "test"},
        handler=lambda args, **kwargs: calls.append(True) or '{"ok": true}',
        effect_descriptor=_conditional("missing-resolver"),
    )
    monkeypatch.setattr(runtime, "load_effect_policy", lambda: EffectPolicy())

    result = _parsed(registry.dispatch("broken_classifier", {}))

    assert result["error_type"] == "effect_policy_denied"
    assert calls == []


def test_cronjob_descriptor_distinguishes_list_from_run():
    from tools import effect_policy_runtime as runtime
    from tools.effect_policy import PolicyDecision

    descriptor = _conditional("cronjob_manage")
    policy = EffectPolicy(
        denied_effects=frozenset({EffectKind.PROCESS_EXECUTE}),
    )

    read_result = runtime.authorize_tool_call(
        "cronjob_manage",
        {"action": "list"},
        policy=policy,
        effect_descriptor=descriptor,
    )
    run_result = runtime.authorize_tool_call(
        "cronjob_manage",
        {"action": "run", "id": "job-1"},
        policy=policy,
        effect_descriptor=descriptor,
    )

    assert read_result.decision is PolicyDecision.ALLOW
    assert run_result.decision is PolicyDecision.DENY


def test_permit_rejects_target_identity_change_before_dispatch(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools import registry as registry_module
    from tools.effect_policy import CanonicalTarget, IdentityStatus, PolicyDecision

    registry = ToolRegistry()
    registry.register(
        name="write_file",
        toolset="file",
        schema={"name": "write_file", "description": "test"},
        handler=lambda _args, **_kwargs: '{"ok": true}',
        effect_descriptor=_conditional("write_file"),
    )
    monkeypatch.setattr(registry_module, "registry", registry)

    target = {"canonical": "C:/allowed/output.txt"}

    def resolver(_task_id):
        return lambda raw: CanonicalTarget(
            raw=raw,
            absolute=target["canonical"],
            canonical=target["canonical"],
            identity_status=IdentityStatus.PROVEN,
        )

    monkeypatch.setattr(runtime, "_task_target_resolver", resolver)
    monkeypatch.setattr(runtime, "load_effect_policy", lambda: EffectPolicy())
    args = {"path": "output.txt", "content": "x"}

    result, permit = runtime.authorize_and_issue_effect_permit("write_file", args)
    assert result.decision is PolicyDecision.ALLOW
    assert permit is not None

    target["canonical"] = "C:/protected/output.txt"
    identity = registry.snapshot_dispatch_identity("write_file")
    with runtime.bind_issued_effect_permit(permit):
        consumed = runtime.consume_effect_permit(
            "write_file",
            args,
            registration_identity=identity,
        )

    assert consumed is None


def test_final_admission_rejects_policy_change_inside_handler(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools.effect_policy import PolicyDecision

    registry = ToolRegistry()
    state = {"policy": EffectPolicy()}
    monkeypatch.setattr(runtime, "load_effect_policy", lambda: state["policy"])

    def handler(args, **_kwargs):
        state["policy"] = EffectPolicy(
            denied_effects=frozenset({EffectKind.PROCESS_EXECUTE}),
        )
        result = runtime.enforce_final_effect_admission(
            "terminal",
            args,
            effect_descriptor=_conditional("terminal"),
        )
        return json.dumps({"decision": result.decision.value})

    registry.register(
        name="terminal",
        toolset="terminal",
        schema={"name": "terminal", "description": "test"},
        handler=handler,
        effect_descriptor=_conditional("terminal"),
    )

    result = _parsed(registry.dispatch("terminal", {"command": "git status"}))

    assert result["decision"] == PolicyDecision.DENY.value


def test_direct_registry_cannot_adopt_policy_changed_during_final_capture(monkeypatch):
    from tools import effect_policy_runtime as runtime

    state = {"policy": EffectPolicy()}
    monkeypatch.setattr(runtime, "load_effect_policy", lambda: state["policy"])
    calls = []
    registry = ToolRegistry()
    registry.register(
        name="write_file",
        toolset="test",
        schema={"name": "write_file", "description": "test"},
        handler=lambda _args, **_kwargs: calls.append("called") or {"ok": True},
        effect_descriptor=_conditional("write_file"),
    )

    original_capture = runtime.capture_final_effect_admission

    def change_policy_before_capture(*args, **kwargs):
        state["policy"] = EffectPolicy(
            denied_effects=frozenset({EffectKind.WRITE})
        )
        return original_capture(*args, **kwargs)

    monkeypatch.setattr(
        runtime,
        "capture_final_effect_admission",
        change_policy_before_capture,
    )

    result = _parsed(
        registry.dispatch("write_file", {"path": "x", "content": "y"})
    )

    assert result["error_type"] == "effect_policy_stale_authorization"
    assert calls == []


def test_opaque_tool_requires_approval_when_protected_roots_exist():
    from tools.effect_policy import (
        CanonicalTarget,
        EffectDescriptor,
        EffectMode,
        EffectPolicy,
        IdentityStatus,
        PolicyDecision,
    )
    from tools.effect_policy_runtime import EffectContext, authorize_tool_call

    policy = EffectPolicy(
        protected_roots=(
            CanonicalTarget(
                raw="C:/protected",
                absolute="C:/protected",
                canonical="C:/protected",
                identity_status=IdentityStatus.PROVEN,
            ),
        )
    )
    result = authorize_tool_call(
        "unknown_plugin_tool",
        {},
        policy=policy,
        context=EffectContext(
            actor="model",
            profile="test",
            session_mode="interactive",
            execution_mode="local",
        ),
        effect_descriptor=EffectDescriptor(mode=EffectMode.OPAQUE),
    )

    assert result.decision is PolicyDecision.REQUIRE_HUMAN_APPROVAL


def test_approval_rule_binds_registration_scope_and_complete_effect_targets():
    from tools import effect_policy_runtime as runtime
    from tools.effect_policy import (
        CanonicalTarget,
        EffectKind,
        EffectRequest,
        IdentityStatus,
        Mutability,
        ResourceKind,
    )

    args = {"path": "same.txt", "content": "x"}

    def request(target):
        return EffectRequest(
            effect=EffectKind.WRITE,
            resource=ResourceKind.FILESYSTEM,
            mutability=Mutability.MUTATING,
            target=CanonicalTarget(
                raw="same.txt",
                absolute=target,
                canonical=target,
                identity_status=IdentityStatus.PROVEN,
            ),
            carrier="write_file",
            actor="model",
            profile="test",
            session_mode="interactive",
            execution_mode="local",
        )

    first = runtime._effect_approval_rule_key(
        "write_file",
        args,
        "approval required",
        "registration-a",
        [request("C:/one")],
    )
    second = runtime._effect_approval_rule_key(
        "write_file",
        args,
        "approval required",
        "registration-b",
        [request("C:/one")],
    )
    third = runtime._effect_approval_rule_key(
        "write_file",
        args,
        "approval required",
        "registration-a",
        [request("C:/two")],
    )

    assert len({first, second, third}) == 3


def test_effect_descriptor_rejects_mutable_effect_collections():
    from tools.effect_policy import (
        EffectDescriptor,
        EffectKind,
        EffectMode,
        EffectTemplate,
        Mutability,
        ResourceKind,
    )

    with pytest.raises(TypeError):
        EffectDescriptor(
            mode=EffectMode.STATIC,
            effects=[  # type: ignore[arg-type]
                EffectTemplate(
                    effect=EffectKind.WRITE,
                    resource=ResourceKind.FILESYSTEM,
                    mutability=Mutability.MUTATING,
                )
            ],
        )


def test_read_only_descriptor_honors_explicit_read_deny():
    from tools.effect_policy import (
        EffectDescriptor,
        EffectKind,
        EffectMode,
        EffectPolicy,
        PolicyDecision,
    )
    from tools.effect_policy_runtime import authorize_tool_call

    result = authorize_tool_call(
        "read_only_tool",
        {},
        policy=EffectPolicy(denied_effects=frozenset({EffectKind.READ})),
        effect_descriptor=EffectDescriptor(mode=EffectMode.READ_ONLY),
    )

    assert result.decision is PolicyDecision.DENY


def test_host_read_only_registration_survives_unrelated_mutation_deny(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools.effect_policy import EffectKind, EffectPolicy

    registry = ToolRegistry()
    calls = []
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(denied_effects=frozenset({EffectKind.NETWORK_WRITE})),
    )
    registry.register(
        name="skills_list",
        toolset="test",
        schema={"name": "skills_list"},
        handler=lambda args: calls.append(args) or "ok",
    )

    assert registry.dispatch("skills_list", {}) == "ok"
    assert calls == [{}]
