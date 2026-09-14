"""Effect-policy integration tests for the agent's final-argument seam."""

from __future__ import annotations

import json
from types import SimpleNamespace

from agent import tool_executor
from tools.effect_policy import EffectPolicy
from tools.effect_policy_runtime import canonicalize_target


def test_agent_final_argument_seam_blocks_before_execute(monkeypatch, tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    denied = protected / "denied.txt"
    policy = EffectPolicy(protected_roots=(canonicalize_target(str(protected)),))
    executed = []
    starts = []
    emitted = []

    monkeypatch.setattr("tools.effect_policy_runtime.load_effect_policy", lambda: policy)
    monkeypatch.setattr(tool_executor, "_pre_tool_block", lambda agent, ref: (None, ref.args))
    monkeypatch.setattr(
        tool_executor,
        "_emit_terminal_post_tool_call",
        lambda *args, **kwargs: emitted.append(kwargs),
    )

    agent = SimpleNamespace(
        _tool_guardrails=SimpleNamespace(
            before_call=lambda name, args: SimpleNamespace(allows_execution=True)
        )
    )
    state = tool_executor._ManagedToolResult(
        result=None,
        args={"path": str(denied), "content": "payload"},
        middleware_trace=[],
        blocked=False,
        dispatched=True,
    )
    ref = tool_executor._ToolCallRef(
        "write_file",
        dict(state.args),
        "task",
        "call",
        [],
    )

    result = tool_executor._dispatch_authorized_once(
        agent,
        state,
        ref,
        execute=lambda args: executed.append(args),
        scope_block=None,
        display_index=None,
        begin_execution=lambda callback=None: starts.append(callback),
        authorization_gate=None,
    )

    body = json.loads(result)
    assert "Effect policy DENIED" in body["error"]
    assert state.blocked is True
    assert executed == []
    assert starts == [None]
    assert emitted[0]["status"] == "blocked"
    assert emitted[0]["error_type"] == "effect_policy_denied"


def test_effect_prompt_gate_binds_observability_before_authorization(monkeypatch, tmp_path):
    from tools import approval_context
    from tools import effect_policy_runtime

    monkeypatch.setattr(effect_policy_runtime, "load_effect_policy", lambda: EffectPolicy())
    real_issue = effect_policy_runtime.authorize_and_issue_effect_permit
    seen = []
    inside_gate = False

    def issue(*args, **kwargs):
        seen.append(
            (
                inside_gate,
                approval_context._approval_turn_id.get(),
                approval_context._approval_tool_call_id.get(),
                approval_context._approval_session_id.get(),
            )
        )
        return real_issue(*args, **kwargs)

    monkeypatch.setattr(effect_policy_runtime, "authorize_and_issue_effect_permit", issue)
    monkeypatch.setattr(tool_executor, "_pre_tool_block", lambda agent, ref: (None, ref.args))

    class Gate:
        def run(self, callback):
            nonlocal inside_gate
            inside_gate = True
            try:
                return callback()
            finally:
                inside_gate = False

    agent = SimpleNamespace(
        session_id="session-1",
        _current_turn_id="turn-1",
        _current_api_request_id="request-1",
        _tool_guardrails=SimpleNamespace(
            before_call=lambda name, args: SimpleNamespace(allows_execution=True)
        ),
    )
    state = tool_executor._ManagedToolResult(
        result=None,
        args={"path": str(tmp_path / "safe.txt"), "content": "payload"},
        middleware_trace=[],
        blocked=False,
        dispatched=True,
    )
    ref = tool_executor._ToolCallRef("write_file", dict(state.args), "default", "call-1", [])

    result = tool_executor._dispatch_authorized_once(
        agent,
        state,
        ref,
        execute=lambda args: {"ok": True},
        scope_block=None,
        display_index=None,
        begin_execution=lambda callback=None: None,
        authorization_gate=Gate(),
    )

    assert result == {"ok": True}
    assert seen == [(True, "turn-1", "call-1", "session-1")]


def test_agent_permit_is_minted_after_schema_coercion(monkeypatch, tmp_path):
    from tools import effect_policy_runtime

    monkeypatch.setattr(effect_policy_runtime, "load_effect_policy", lambda: EffectPolicy())
    monkeypatch.setattr(tool_executor, "_pre_tool_block", lambda agent, ref: (None, ref.args))
    monkeypatch.setattr(
        "tools.arg_coercion.coerce_tool_args",
        lambda name, args: {**args, "replace_all": False},
    )
    seen = []
    real_issue = effect_policy_runtime.authorize_and_issue_effect_permit

    def issue(name, args, **kwargs):
        seen.append(dict(args))
        return real_issue(name, args, **kwargs)

    monkeypatch.setattr(effect_policy_runtime, "authorize_and_issue_effect_permit", issue)
    agent = SimpleNamespace(
        _tool_guardrails=SimpleNamespace(
            before_call=lambda name, args: SimpleNamespace(allows_execution=True)
        )
    )
    args = {
        "mode": "replace",
        "path": str(tmp_path / "file.txt"),
        "old_string": "a",
        "new_string": "b",
        "replace_all": "false",
    }
    state = tool_executor._ManagedToolResult(
        result=None, args=args, middleware_trace=[], blocked=False, dispatched=True
    )
    ref = tool_executor._ToolCallRef("patch", args, "default", "call", [])

    result = tool_executor._dispatch_authorized_once(
        agent,
        state,
        ref,
        execute=lambda final_args: final_args,
        scope_block=None,
        display_index=None,
        begin_execution=lambda callback=None: None,
        authorization_gate=None,
    )

    assert seen[0]["replace_all"] is False
    assert result["replace_all"] is False
