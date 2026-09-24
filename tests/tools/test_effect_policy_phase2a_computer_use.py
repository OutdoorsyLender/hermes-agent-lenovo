"""Phase-2A effect-policy contracts for destructive ``computer_use`` actions."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import model_tools
from tools.effect_policy import (
    EffectClassification,
    EffectKind,
    EffectPolicy,
    Mutability,
    PolicyDecision,
    PolicyResult,
    ResourceKind,
)
from tools.effect_policy_runtime import (
    EffectContext,
    authorize_and_issue_effect_permit,
    authorize_tool_call,
    bind_issued_effect_permit,
    effect_requests_for_tool,
)
from tools.registry import ToolRegistry


_DESTRUCTIVE_ACTIONS = (
    "click",
    "double_click",
    "right_click",
    "middle_click",
    "drag",
    "scroll",
    "type",
    "key",
    "set_value",
    "focus_app",
)
_READ_ONLY_ACTIONS = ("capture", "wait", "list_apps", "list_windows")


def _context(*, unattended: bool = False, bypass_requested: bool = False) -> EffectContext:
    return EffectContext(
        actor="coder",
        profile="coder",
        session_mode="cron" if unattended else "interactive",
        execution_mode="normal",
        unattended=unattended,
        bypass_requested=bypass_requested,
    )


def _register_computer_use(registry: ToolRegistry, handler, *, scope=None) -> None:
    registry.register(
        name="computer_use",
        toolset="computer_use",
        schema={"name": "computer_use", "description": "test"},
        handler=handler,
        scope=scope,
    )


def _parsed(result):
    return json.loads(result) if isinstance(result, str) else result


@pytest.mark.parametrize("action", _DESTRUCTIVE_ACTIONS)
def test_destructive_action_table_entries_emit_computer_control(action):
    requests = effect_requests_for_tool("computer_use", {"action": action}, context=_context())

    assert len(requests) == 1
    request = requests[0]
    assert request.effect is EffectKind.COMPUTER_CONTROL
    assert request.resource is ResourceKind.COMPUTER
    assert request.mutability is Mutability.MUTATING
    assert request.classification is EffectClassification.PRIVILEGED_OR_SECURITY_SENSITIVE
    assert request.carrier == f"computer_use:{action}"


@pytest.mark.parametrize("action", _READ_ONLY_ACTIONS)
def test_read_only_action_table_entries_preserve_compatibility(action):
    assert effect_requests_for_tool("computer_use", {"action": action}, context=_context()) == []


def test_read_only_capture_with_bring_to_front_is_control_effect():
    result = authorize_tool_call(
        "computer_use",
        {"action": "capture", "bring_to_front": True},
        policy=EffectPolicy(
            denied_effects=frozenset({EffectKind.COMPUTER_CONTROL}),
        ),
    )

    assert result.decision is PolicyDecision.DENY


def test_action_classification_is_exhaustive_against_runtime_and_schema():
    from tools.computer_use.schema import COMPUTER_USE_SCHEMA
    from tools.computer_use.tool import _ACTIONS

    classified = set(_DESTRUCTIVE_ACTIONS) | set(_READ_ONLY_ACTIONS)
    schema_actions = set(
        COMPUTER_USE_SCHEMA["parameters"]["properties"]["action"]["enum"]
    )

    assert classified == set(_ACTIONS) == schema_actions
    assert {
        action for action, spec in _ACTIONS.items() if spec.destructive
    } == set(_DESTRUCTIVE_ACTIONS)


@pytest.mark.parametrize("action", [None, "", "unknown", 7, ["click"]])
def test_unknown_or_malformed_action_fails_closed_even_with_empty_policy(action):
    result = authorize_tool_call(
        "computer_use",
        {"action": action},
        context=_context(),
        policy=EffectPolicy(),
    )

    assert result.decision is PolicyDecision.DENY
    assert result.non_bypassable is True
    assert "classification" in result.reason


def test_malformed_action_metadata_fails_closed(monkeypatch):
    from tools.computer_use import tool as computer_tool

    monkeypatch.setitem(
        computer_tool._ACTIONS,
        "click",
        SimpleNamespace(destructive="yes"),
    )

    result = authorize_tool_call(
        "computer_use",
        {"action": "click"},
        context=_context(),
        policy=EffectPolicy(),
    )

    assert result.decision is PolicyDecision.DENY
    assert result.non_bypassable is True
    assert "classification" in result.reason


def test_classifier_exception_fails_closed(monkeypatch):
    from tools import effect_policy_runtime as runtime

    def explode(*_args, **_kwargs):
        raise RuntimeError("classifier exploded")

    monkeypatch.setitem(runtime._EFFECT_ADAPTERS, "computer_use", explode)

    result = authorize_tool_call(
        "computer_use",
        {"action": "click"},
        context=_context(),
        policy=EffectPolicy(),
    )

    assert result.decision is PolicyDecision.DENY
    assert result.non_bypassable is True
    assert "classifier exploded" in result.reason


def test_computer_control_deny_overrides_bypass():
    result = authorize_tool_call(
        "computer_use",
        {"action": "click"},
        context=_context(bypass_requested=True),
        policy=EffectPolicy(denied_effects=frozenset({EffectKind.COMPUTER_CONTROL})),
    )

    assert result.decision is PolicyDecision.DENY
    assert result.non_bypassable is True


def test_computer_control_approval_uses_phase1_interactive_unattended_and_bypass_semantics():
    policy = EffectPolicy(
        approval_required_effects=frozenset({EffectKind.COMPUTER_CONTROL})
    )

    interactive = authorize_tool_call(
        "computer_use", {"action": "click"}, context=_context(), policy=policy
    )
    unattended = authorize_tool_call(
        "computer_use",
        {"action": "click"},
        context=_context(unattended=True),
        policy=policy,
    )
    bypassed = authorize_tool_call(
        "computer_use",
        {"action": "click"},
        context=_context(bypass_requested=True),
        policy=policy,
    )

    assert interactive.decision is PolicyDecision.REQUIRE_APPROVAL
    assert unattended.decision is PolicyDecision.DENY
    assert bypassed.decision is PolicyDecision.ALLOW


def test_invalid_policy_denies_destructive_action_but_keeps_read_only_compatibility():
    policy = EffectPolicy(valid=False, error="malformed test policy")

    destructive = authorize_tool_call(
        "computer_use", {"action": "click"}, context=_context(), policy=policy
    )
    read_only = authorize_tool_call(
        "computer_use", {"action": "capture"}, context=_context(), policy=policy
    )

    assert destructive.decision is PolicyDecision.DENY
    assert destructive.non_bypassable is True
    assert read_only.decision is PolicyDecision.ALLOW


def test_direct_registry_dispatch_denies_before_handler(monkeypatch):
    from tools import effect_policy_runtime as runtime

    registry = ToolRegistry()
    calls = []
    _register_computer_use(registry, lambda args, **kwargs: calls.append(args) or '{"ok": true}')
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(denied_effects=frozenset({EffectKind.COMPUTER_CONTROL})),
    )

    result = _parsed(registry.dispatch("computer_use", {"action": "click"}))

    assert result["error_type"] == "effect_policy_denied"
    assert calls == []


def test_direct_registry_dispatch_approval_executes_exactly_once(monkeypatch):
    from tools import effect_policy_runtime as runtime

    registry = ToolRegistry()
    calls = []
    _register_computer_use(registry, lambda args, **kwargs: calls.append(dict(args)) or '{"ok": true}')
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(
            approval_required_effects=frozenset({EffectKind.COMPUTER_CONTROL})
        ),
    )
    approvals = []
    monkeypatch.setattr(
        "tools.approval.request_tool_approval",
        lambda *args, **kwargs: approvals.append((args, kwargs)) or {"approved": True},
    )

    result = _parsed(registry.dispatch("computer_use", {"action": "click"}))

    assert result == {"ok": True}
    assert calls == [{"action": "click"}]
    assert len(approvals) == 1


def test_direct_registry_dispatch_denied_approval_does_not_execute(monkeypatch):
    from tools import effect_policy_runtime as runtime

    registry = ToolRegistry()
    calls = []
    _register_computer_use(registry, lambda *_args, **_kwargs: calls.append(True) or '{"ok": true}')
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(
            approval_required_effects=frozenset({EffectKind.COMPUTER_CONTROL})
        ),
    )
    monkeypatch.setattr(
        "tools.approval.request_tool_approval",
        lambda *args, **kwargs: {"approved": False, "message": "test denial"},
    )

    result = _parsed(registry.dispatch("computer_use", {"action": "click"}))

    assert result["error_type"] == "effect_policy_approval_required"
    assert calls == []


def test_direct_registry_dispatch_rejects_replacement_during_authorization(monkeypatch):
    from tools import effect_policy_runtime as runtime

    registry = ToolRegistry()
    calls = []
    _register_computer_use(registry, lambda *_args, **_kwargs: calls.append("old") or '{"ok": true}')

    def replace_then_allow(*_args, **_kwargs):
        _register_computer_use(
            registry,
            lambda *_args, **_kwargs: calls.append("new") or '{"ok": true}',
        )
        return PolicyResult(PolicyDecision.ALLOW, "approved old registration")

    monkeypatch.setattr(runtime, "enforce_tool_call", replace_then_allow)

    result = _parsed(registry.dispatch("computer_use", {"action": "click"}))

    assert result["error_type"] == "effect_policy_registration_changed"
    assert calls == []


def test_permit_is_bound_to_exact_registration_and_reauthorizes_replacement(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools import registry as registry_module

    registry = ToolRegistry()
    calls = []
    _register_computer_use(registry, lambda *_args, **_kwargs: calls.append("old") or '{"ok": true}')
    monkeypatch.setattr(registry_module, "registry", registry)
    decisions = iter(
        (
            PolicyResult(PolicyDecision.ALLOW, "initial approval"),
            PolicyResult(PolicyDecision.DENY, "replacement not approved", non_bypassable=True),
        )
    )
    monkeypatch.setattr(runtime, "enforce_tool_call", lambda *_args, **_kwargs: next(decisions))
    args = {"action": "click"}

    result, permit = authorize_and_issue_effect_permit(
        "computer_use", args, task_id="task", tool_call_id="call"
    )
    assert result.decision is PolicyDecision.ALLOW
    assert permit is not None
    _register_computer_use(registry, lambda *_args, **_kwargs: calls.append("new") or '{"ok": true}')

    with bind_issued_effect_permit(permit):
        dispatched = _parsed(
            registry.dispatch(
                "computer_use",
                args,
                task_id="task",
                tool_call_id="call",
            )
        )

    assert dispatched["error_type"] == "effect_policy_denied"
    assert calls == []


def test_permit_issuance_rejects_registration_changed_during_approval(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools import registry as registry_module

    registry = ToolRegistry()
    calls = []
    _register_computer_use(registry, lambda *_args, **_kwargs: calls.append("old") or '{"ok": true}')
    monkeypatch.setattr(registry_module, "registry", registry)

    def replace_then_allow(*_args, **_kwargs):
        _register_computer_use(
            registry,
            lambda *_args, **_kwargs: calls.append("new") or '{"ok": true}',
        )
        return PolicyResult(PolicyDecision.ALLOW, "approved old registration")

    monkeypatch.setattr(runtime, "enforce_tool_call", replace_then_allow)

    result, permit = authorize_and_issue_effect_permit(
        "computer_use", {"action": "click"}, task_id="task", tool_call_id="call"
    )

    assert result.decision is PolicyDecision.DENY
    assert result.non_bypassable is True
    assert "registration changed" in result.reason
    assert permit is None
    assert calls == []


def test_permit_reauthorizes_changed_arguments(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools import registry as registry_module

    registry = ToolRegistry()
    calls = []
    _register_computer_use(registry, lambda args, **_kwargs: calls.append(args) or '{"ok": true}')
    monkeypatch.setattr(registry_module, "registry", registry)
    decisions = iter(
        (
            PolicyResult(PolicyDecision.ALLOW, "initial approval"),
            PolicyResult(PolicyDecision.DENY, "changed args denied", non_bypassable=True),
        )
    )
    monkeypatch.setattr(runtime, "enforce_tool_call", lambda *_args, **_kwargs: next(decisions))

    result, permit = authorize_and_issue_effect_permit(
        "computer_use", {"action": "click"}, task_id="task", tool_call_id="call"
    )
    assert result.decision is PolicyDecision.ALLOW
    assert permit is not None

    with bind_issued_effect_permit(permit):
        dispatched = _parsed(
            registry.dispatch(
                "computer_use",
                {"action": "type", "text": "changed"},
                task_id="task",
                tool_call_id="call",
            )
        )

    assert dispatched["error_type"] == "effect_policy_denied"
    assert calls == []


def test_bound_permit_reaches_registry_once_without_duplicate_authorization(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools import registry as registry_module

    registry = ToolRegistry()
    calls = []
    _register_computer_use(registry, lambda args, **_kwargs: calls.append(args) or '{"ok": true}')
    monkeypatch.setattr(registry_module, "registry", registry)
    monkeypatch.setattr(model_tools, "registry", registry)
    authorizations = []
    monkeypatch.setattr(
        runtime,
        "enforce_tool_call",
        lambda *args, **kwargs: authorizations.append((args, kwargs))
        or PolicyResult(PolicyDecision.ALLOW, "approved"),
    )
    args = {"action": "click"}

    result, permit = authorize_and_issue_effect_permit(
        "computer_use", args, task_id="task", tool_call_id="call"
    )
    assert result.decision is PolicyDecision.ALLOW
    assert permit is not None

    with bind_issued_effect_permit(permit):
        dispatched = _parsed(
            model_tools.handle_function_call(
                "computer_use",
                args,
                task_id="task",
                tool_call_id="call",
                skip_pre_tool_call_hook=True,
                skip_tool_request_middleware=True,
                skip_tool_execution_middleware=True,
            )
        )

    assert dispatched == {"ok": True}
    assert calls == [args]
    assert len(authorizations) == 1


def test_execution_middleware_final_action_is_authorized_before_backend(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools.computer_use import tool as computer_tool

    backend_calls = []
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(denied_effects=frozenset({EffectKind.COMPUTER_CONTROL})),
    )
    monkeypatch.setattr(
        "hermes_cli.middleware.run_tool_execution_middleware",
        lambda name, args, next_call, **kwargs: next_call({"action": "click"}),
    )
    monkeypatch.setattr(
        computer_tool,
        "_get_backend",
        lambda **kwargs: backend_calls.append(kwargs),
    )

    result = _parsed(
        model_tools.handle_function_call(
            "computer_use",
            {"action": "capture"},
            skip_pre_tool_call_hook=True,
            skip_tool_request_middleware=True,
        )
    )

    assert result["error_type"] == "effect_policy_denied"
    assert backend_calls == []


def test_registry_policy_exception_fails_closed(monkeypatch):
    from tools import effect_policy_runtime as runtime

    registry = ToolRegistry()
    calls = []
    _register_computer_use(registry, lambda *_args, **_kwargs: calls.append(True) or '{"ok": true}')
    monkeypatch.setattr(
        runtime,
        "enforce_tool_call",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("policy crash")),
    )

    result = _parsed(registry.dispatch("computer_use", {"action": "click"}))

    assert result["error_type"] == "effect_policy_denied"
    assert "policy crash" in result["error"]
    assert calls == []


def test_plugin_context_direct_dispatch_cannot_bypass_policy(monkeypatch):
    from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
    from tools import effect_policy_runtime as runtime
    from tools import registry as registry_module

    registry = ToolRegistry()
    calls = []
    _register_computer_use(registry, lambda *_args, **_kwargs: calls.append(True) or '{"ok": true}')
    monkeypatch.setattr(registry_module, "registry", registry)
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(denied_effects=frozenset({EffectKind.COMPUTER_CONTROL})),
    )
    context = PluginContext(PluginManifest(name="phase2a-test", source="user"), PluginManager())

    result = _parsed(context.dispatch_tool("computer_use", {"action": "click"}))

    assert result["error_type"] == "effect_policy_denied"
    assert calls == []


def test_tool_call_wrapper_authorizes_underlying_computer_use(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools import tool_search
    from tools.computer_use import tool as computer_tool

    backend_calls = []
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(denied_effects=frozenset({EffectKind.COMPUTER_CONTROL})),
    )
    monkeypatch.setattr(model_tools, "get_tool_definitions", lambda **_kwargs: [])
    monkeypatch.setattr(
        tool_search,
        "resolve_underlying_call",
        lambda _args: ("computer_use", {"action": "click"}, None),
    )
    monkeypatch.setattr(
        tool_search,
        "scoped_deferrable_names",
        lambda _defs: frozenset({"computer_use"}),
    )
    monkeypatch.setattr(tool_search, "validate_deferred_call_args", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        computer_tool,
        "_get_backend",
        lambda **kwargs: backend_calls.append(kwargs),
    )

    result = _parsed(
        model_tools.handle_function_call(
            "tool_call",
            {"calls": [{"name": "computer_use", "arguments": {"action": "click"}}]},
            skip_pre_tool_call_hook=True,
            skip_tool_request_middleware=True,
            skip_tool_execution_middleware=True,
        )
    )

    assert result["error_type"] == "effect_policy_denied"
    assert backend_calls == []


def test_computer_use_revalidates_after_legacy_approval(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools.computer_use import tool as computer_tool
    from tools.effect_policy import EffectDescriptor, EffectMode

    current_policy = {"value": EffectPolicy()}
    backend_calls = []
    monkeypatch.setattr(runtime, "load_effect_policy", lambda: current_policy["value"])

    def approve_and_tighten(*args, **kwargs):
        current_policy["value"] = EffectPolicy(
            denied_effects=frozenset({EffectKind.COMPUTER_CONTROL})
        )
        return None

    monkeypatch.setattr(computer_tool, "_request_approval", approve_and_tighten)
    monkeypatch.setattr(
        computer_tool,
        "_get_backend",
        lambda **kwargs: backend_calls.append(kwargs),
    )
    registry = ToolRegistry()
    registry.register(
        name="computer_use",
        toolset="test",
        schema={"name": "computer_use", "description": "test"},
        handler=computer_tool.handle_computer_use,
        effect_descriptor=EffectDescriptor(
            mode=EffectMode.CONDITIONAL,
            resolver_key="computer_use",
        ),
    )

    result = _parsed(registry.dispatch("computer_use", {"action": "click"}))

    assert result["error_type"] == "effect_policy_stale_authorization"
    assert backend_calls == []
