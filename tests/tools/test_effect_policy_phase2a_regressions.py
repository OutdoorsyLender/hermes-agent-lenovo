"""Adversarial Phase-2A tests for authorization identity and TOCTOU."""

from __future__ import annotations

import json
from types import SimpleNamespace

import model_tools
from tools.effect_policy import EffectKind, EffectPolicy, PolicyDecision, PolicyResult
from tools.effect_policy_runtime import (
    authorize_and_issue_effect_permit,
    bind_issued_effect_permit,
)
from tools.registry import ToolRegistry


def _register(registry: ToolRegistry, handler) -> None:
    registry.register(
        name="computer_use",
        toolset="computer_use",
        schema={"name": "computer_use", "description": "test"},
        handler=handler,
    )


def _parsed(result):
    return json.loads(result) if isinstance(result, str) else result


def test_approval_time_caller_argument_mutation_cannot_change_executed_target(monkeypatch):
    from tools import effect_policy_runtime as runtime

    registry = ToolRegistry()
    executed = []
    _register(registry, lambda args, **_kwargs: executed.append(dict(args)) or '{"ok": true}')
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

    result = _parsed(registry.dispatch("computer_use", supplied))

    assert result == {"ok": True}
    assert executed == [{"action": "click", "element": 1}]


def test_direct_dispatch_rejects_policy_change_during_approval(monkeypatch):
    from tools import effect_policy_runtime as runtime

    registry = ToolRegistry()
    executed = []
    _register(registry, lambda *_args, **_kwargs: executed.append(True) or '{"ok": true}')
    policy = [
        EffectPolicy(
            approval_required_effects=frozenset({EffectKind.COMPUTER_CONTROL})
        )
    ]
    monkeypatch.setattr(runtime, "load_effect_policy", lambda: policy[0])

    def approve_then_deny(*_args, **_kwargs):
        policy[0] = EffectPolicy(
            denied_effects=frozenset({EffectKind.COMPUTER_CONTROL})
        )
        return {"approved": True}

    monkeypatch.setattr("tools.approval.request_tool_approval", approve_then_deny)

    result = _parsed(registry.dispatch("computer_use", {"action": "click"}))

    assert result["error_type"] == "effect_policy_stale_authorization"
    assert executed == []


def test_permit_reauthorizes_after_registration_aba(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools import registry as registry_module

    registry = ToolRegistry()
    executed = []
    _register(registry, lambda *_args, **_kwargs: executed.append("old") or '{"ok": true}')
    original = registry.get_entry("computer_use")
    monkeypatch.setattr(registry_module, "registry", registry)
    decisions = iter(
        (
            PolicyResult(PolicyDecision.ALLOW, "initial approval"),
            PolicyResult(PolicyDecision.DENY, "stale registration", non_bypassable=True),
        )
    )
    monkeypatch.setattr(runtime, "enforce_tool_call", lambda *_args, **_kwargs: next(decisions))
    args = {"action": "click"}
    result, permit = authorize_and_issue_effect_permit(
        "computer_use", args, task_id="task", session_id="session", tool_call_id="call"
    )
    assert result.decision is PolicyDecision.ALLOW
    assert permit is not None

    _register(registry, lambda *_args, **_kwargs: executed.append("new") or '{"ok": true}')
    replacement = registry.get_entry("computer_use")
    assert replacement is not None
    assert registry.restore_registration("computer_use", replacement, original)

    with bind_issued_effect_permit(permit):
        dispatched = _parsed(
            registry.dispatch(
                "computer_use",
                args,
                task_id="task",
                session_id="session",
                tool_call_id="call",
            )
        )

    assert dispatched["error_type"] == "effect_policy_denied"
    assert executed == []


def test_permit_reauthorizes_in_place_handler_change(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools import registry as registry_module

    registry = ToolRegistry()
    executed = []
    _register(registry, lambda *_args, **_kwargs: executed.append("old") or '{"ok": true}')
    monkeypatch.setattr(registry_module, "registry", registry)
    decisions = iter(
        (
            PolicyResult(PolicyDecision.ALLOW, "initial approval"),
            PolicyResult(PolicyDecision.DENY, "changed handler", non_bypassable=True),
        )
    )
    monkeypatch.setattr(runtime, "enforce_tool_call", lambda *_args, **_kwargs: next(decisions))
    args = {"action": "click"}
    result, permit = authorize_and_issue_effect_permit("computer_use", args)
    assert result.decision is PolicyDecision.ALLOW
    assert permit is not None

    active_entry = registry.get_entry("computer_use")
    assert active_entry is not None
    active_entry.handler = (
        lambda *_args, **_kwargs: executed.append("changed") or '{"ok": true}'
    )
    with bind_issued_effect_permit(permit):
        dispatched = _parsed(registry.dispatch("computer_use", args))

    assert dispatched["error_type"] == "effect_policy_denied"
    assert executed == []


def test_permit_reauthorizes_wrong_session(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools import registry as registry_module

    registry = ToolRegistry()
    executed = []
    _register(registry, lambda *_args, **_kwargs: executed.append(True) or '{"ok": true}')
    monkeypatch.setattr(registry_module, "registry", registry)
    decisions = iter(
        (
            PolicyResult(PolicyDecision.ALLOW, "initial approval"),
            PolicyResult(PolicyDecision.DENY, "wrong session", non_bypassable=True),
        )
    )
    monkeypatch.setattr(runtime, "enforce_tool_call", lambda *_args, **_kwargs: next(decisions))
    args = {"action": "click"}
    result, permit = authorize_and_issue_effect_permit(
        "computer_use", args, session_id="session-a"
    )
    assert result.decision is PolicyDecision.ALLOW
    assert permit is not None

    with bind_issued_effect_permit(permit):
        dispatched = _parsed(
            registry.dispatch("computer_use", args, session_id="session-b")
        )

    assert dispatched["error_type"] == "effect_policy_denied"
    assert executed == []


def test_mismatched_operation_deactivates_but_does_not_consume_permit(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools import registry as registry_module

    registry = ToolRegistry()
    _register(registry, lambda *_args, **_kwargs: '{"ok": true}')
    monkeypatch.setattr(registry_module, "registry", registry)
    monkeypatch.setattr(
        runtime,
        "enforce_tool_call",
        lambda *_args, **_kwargs: PolicyResult(PolicyDecision.ALLOW, "approved"),
    )
    result, permit = authorize_and_issue_effect_permit(
        "computer_use", {"action": "click"}
    )
    assert result.decision is PolicyDecision.ALLOW
    assert permit is not None

    with bind_issued_effect_permit(permit):
        consumed = runtime.consume_effect_permit(
            "computer_use",
            {"action": "type", "text": "different"},
            registration_identity=registry.snapshot_dispatch_identity("computer_use"),
        )
        assert consumed is None
        assert permit.attempt_id in runtime._effect_permits

    assert permit.attempt_id not in runtime._effect_permits


def test_effect_approval_unavailable_fails_closed_before_handler(monkeypatch):
    from tools import effect_policy_runtime as runtime

    registry = ToolRegistry()
    executed = []
    _register(registry, lambda *_args, **_kwargs: executed.append(True) or '{"ok": true}')
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(
            approval_required_effects=frozenset({EffectKind.COMPUTER_CONTROL})
        ),
    )
    monkeypatch.setattr(
        "tools.approval.request_tool_approval",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("approval unavailable")),
    )

    result = _parsed(registry.dispatch("computer_use", {"action": "click"}))

    assert result["error_type"] == "effect_policy_denied"
    assert "approval unavailable" in result["error"]
    assert executed == []


def test_existing_computer_approval_remains_defense_in_depth(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools.computer_use import tool as computer_tool

    registry = ToolRegistry()
    backend_requests = []
    _register(registry, computer_tool.handle_computer_use)
    monkeypatch.setattr(runtime, "load_effect_policy", lambda: EffectPolicy())
    monkeypatch.setattr(computer_tool, "_approval_callback", lambda *_args: "deny")
    monkeypatch.setattr(
        computer_tool,
        "_get_backend",
        lambda **kwargs: backend_requests.append(kwargs),
    )

    result = _parsed(registry.dispatch("computer_use", {"action": "click"}))

    assert result["error"] == "denied by user"
    assert backend_requests == []


def test_effect_denial_precedes_existing_computer_approval_and_backend(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools.computer_use import tool as computer_tool

    registry = ToolRegistry()
    approvals = []
    backend_requests = []
    _register(registry, computer_tool.handle_computer_use)
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(denied_effects=frozenset({EffectKind.COMPUTER_CONTROL})),
    )
    monkeypatch.setattr(
        computer_tool,
        "_approval_callback",
        lambda *_args: approvals.append(True) or "approve_once",
    )
    monkeypatch.setattr(
        computer_tool,
        "_get_backend",
        lambda **kwargs: backend_requests.append(kwargs),
    )

    result = _parsed(registry.dispatch("computer_use", {"action": "click"}))

    assert result["error_type"] == "effect_policy_denied"
    assert approvals == []
    assert backend_requests == []


def test_agent_executor_issues_session_bound_permit_consumed_at_registry(monkeypatch):
    from agent import tool_executor
    from tools import effect_policy_runtime as runtime
    from tools import registry as registry_module

    registry = ToolRegistry()
    executed = []
    _register(
        registry,
        lambda args, **kwargs: executed.append((dict(args), kwargs.get("session_id")))
        or '{"ok": true}',
    )
    monkeypatch.setattr(registry_module, "registry", registry)
    monkeypatch.setattr(model_tools, "registry", registry)
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
        lambda *_args, **_kwargs: approvals.append(True) or {"approved": True},
    )
    monkeypatch.setattr(tool_executor, "_pre_tool_block", lambda _agent, ref: (None, ref.args))
    monkeypatch.setattr(
        tool_executor,
        "_run_with_activity_heartbeat",
        lambda _agent, _name, callback: callback(),
    )
    agent = SimpleNamespace(
        session_id="session-agent",
        _current_turn_id="turn-agent",
        _current_api_request_id="request-agent",
        _tool_guardrails=SimpleNamespace(
            before_call=lambda _name, _args: SimpleNamespace(allows_execution=True)
        ),
    )
    args = {"action": "click", "element": 3}
    state = tool_executor._ManagedToolResult(
        result=None,
        args=dict(args),
        middleware_trace=[],
        blocked=False,
        dispatched=True,
    )
    ref = tool_executor._ToolCallRef(
        "computer_use", dict(args), "task-agent", "call-agent", []
    )

    result = tool_executor._dispatch_authorized_once(
        agent,
        state,
        ref,
        execute=lambda final_args: model_tools.handle_function_call(
            "computer_use",
            final_args,
            task_id="task-agent",
            session_id="session-agent",
            tool_call_id="call-agent",
            skip_pre_tool_call_hook=True,
            skip_tool_request_middleware=True,
            skip_tool_execution_middleware=True,
        ),
        scope_block=None,
        display_index=None,
        begin_execution=lambda callback=None: None,
        authorization_gate=None,
    )

    assert _parsed(result) == {"ok": True}
    assert approvals == [True]
    assert executed == [(args, "session-agent")]


def test_permit_reauthorizes_same_action_with_different_target(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools import registry as registry_module

    registry = ToolRegistry()
    executed = []
    _register(registry, lambda *_args, **_kwargs: executed.append(True) or '{"ok": true}')
    monkeypatch.setattr(registry_module, "registry", registry)
    decisions = iter(
        (
            PolicyResult(PolicyDecision.ALLOW, "element one approved"),
            PolicyResult(PolicyDecision.DENY, "element two denied", non_bypassable=True),
        )
    )
    monkeypatch.setattr(runtime, "enforce_tool_call", lambda *_args, **_kwargs: next(decisions))
    result, permit = authorize_and_issue_effect_permit(
        "computer_use", {"action": "click", "element": 1}
    )
    assert result.decision is PolicyDecision.ALLOW
    assert permit is not None

    with bind_issued_effect_permit(permit):
        dispatched = _parsed(
            registry.dispatch("computer_use", {"action": "click", "element": 2})
        )

    assert dispatched["error_type"] == "effect_policy_denied"
    assert executed == []


def test_forged_permit_handle_does_not_bypass_registry_policy(monkeypatch):
    from tools import effect_policy_runtime as runtime

    registry = ToolRegistry()
    executed = []
    _register(registry, lambda *_args, **_kwargs: executed.append(True) or '{"ok": true}')
    monkeypatch.setattr(
        runtime,
        "load_effect_policy",
        lambda: EffectPolicy(denied_effects=frozenset({EffectKind.COMPUTER_CONTROL})),
    )
    forged = runtime._EffectPermitHandle("not-issued")

    with bind_issued_effect_permit(forged):
        dispatched = _parsed(registry.dispatch("computer_use", {"action": "click"}))

    assert dispatched["error_type"] == "effect_policy_denied"
    assert executed == []


def test_consumed_permit_cannot_replay_at_registry(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools import registry as registry_module

    registry = ToolRegistry()
    executed = []
    _register(registry, lambda *_args, **_kwargs: executed.append(True) or '{"ok": true}')
    monkeypatch.setattr(registry_module, "registry", registry)
    decisions = iter(
        (
            PolicyResult(PolicyDecision.ALLOW, "approved once"),
            PolicyResult(PolicyDecision.DENY, "replay denied", non_bypassable=True),
        )
    )
    monkeypatch.setattr(runtime, "enforce_tool_call", lambda *_args, **_kwargs: next(decisions))
    args = {"action": "click"}
    result, permit = authorize_and_issue_effect_permit("computer_use", args)
    assert result.decision is PolicyDecision.ALLOW
    assert permit is not None

    with bind_issued_effect_permit(permit):
        first = _parsed(registry.dispatch("computer_use", args))
        replay = _parsed(registry.dispatch("computer_use", args))

    assert first == {"ok": True}
    assert replay["error_type"] == "effect_policy_denied"
    assert executed == [True]


def test_permit_reauthorizes_stale_effect_context(monkeypatch):
    from tools import effect_policy_runtime as runtime
    from tools import registry as registry_module

    registry = ToolRegistry()
    executed = []
    _register(registry, lambda *_args, **_kwargs: executed.append(True) or '{"ok": true}')
    monkeypatch.setattr(registry_module, "registry", registry)
    contexts = [
        runtime.EffectContext("actor", "profile", "interactive", "cli"),
        runtime.EffectContext("actor", "profile", "unattended", "cron", unattended=True),
    ]
    current = [contexts[0]]
    monkeypatch.setattr(runtime, "current_effect_context", lambda: current[0])
    decisions = iter(
        (
            PolicyResult(PolicyDecision.ALLOW, "interactive approval"),
            PolicyResult(PolicyDecision.DENY, "stale context", non_bypassable=True),
        )
    )
    monkeypatch.setattr(runtime, "enforce_tool_call", lambda *_args, **_kwargs: next(decisions))
    args = {"action": "click"}
    result, permit = authorize_and_issue_effect_permit("computer_use", args)
    assert result.decision is PolicyDecision.ALLOW
    assert permit is not None
    current[0] = contexts[1]

    with bind_issued_effect_permit(permit):
        dispatched = _parsed(registry.dispatch("computer_use", args))

    assert dispatched["error_type"] == "effect_policy_denied"
    assert executed == []
