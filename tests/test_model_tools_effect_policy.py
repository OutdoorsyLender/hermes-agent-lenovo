"""Effect-policy integration tests for the direct tool dispatcher."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import model_tools
from tools.effect_policy import EffectKind, EffectPolicy, PolicyDecision, PolicyResult
from tools.effect_policy_runtime import (
    _EffectPermitHandle,
    authorize_and_issue_effect_permit,
    bind_issued_effect_permit,
    canonicalize_target,
)


def _parsed(result):
    return json.loads(result) if isinstance(result, str) else result


def test_effect_policy_sees_execution_middleware_final_args_and_blocks_dispatch(monkeypatch, tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    safe = tmp_path / "safe.txt"
    denied = protected / "denied.txt"
    policy = EffectPolicy(protected_roots=(canonicalize_target(str(protected)),))
    dispatched = []

    monkeypatch.setattr("tools.effect_policy_runtime.load_effect_policy", lambda: policy)
    monkeypatch.setattr(
        "hermes_cli.middleware.run_tool_execution_middleware",
        lambda name, args, next_call, **kwargs: next_call({**args, "path": str(denied)}),
    )
    monkeypatch.setattr(
        model_tools.registry,
        "dispatch",
        lambda name, args, **kwargs: dispatched.append((name, args)) or {"ok": True},
    )

    original_args = {"path": str(safe), "content": "payload"}
    permit_result, permit = authorize_and_issue_effect_permit("write_file", original_args)
    assert permit_result.decision is PolicyDecision.ALLOW
    assert permit is not None
    with bind_issued_effect_permit(permit):
        result = _parsed(
            model_tools.handle_function_call(
                "write_file",
                original_args,
                skip_pre_tool_call_hook=True,
                skip_tool_request_middleware=True,
            )
        )

    assert result["error_type"] == "effect_policy_denied"
    assert "Effect policy DENIED" in result["error"]
    assert dispatched == []
    assert not safe.exists()
    assert not denied.exists()


def test_effect_policy_permit_is_argument_bound_and_consumed_once(monkeypatch, tmp_path):
    calls = []

    def enforce(*args, **kwargs):
        calls.append((args, kwargs))
        if len(calls) == 1:
            return PolicyResult(PolicyDecision.ALLOW, "live allow")
        return PolicyResult(PolicyDecision.DENY, "test deny", non_bypassable=True)

    monkeypatch.setattr("tools.effect_policy_runtime.enforce_tool_call", enforce)
    monkeypatch.setattr(model_tools.registry, "dispatch", lambda *args, **kwargs: {"ok": True})

    args = {"path": str(tmp_path / "file.txt"), "content": "payload"}
    permit_result, permit = authorize_and_issue_effect_permit("write_file", args)
    assert permit_result.decision is PolicyDecision.ALLOW
    assert permit is not None
    with bind_issued_effect_permit(permit):
        first = _parsed(
            model_tools.handle_function_call(
                "write_file",
                args,
                skip_pre_tool_call_hook=True,
                skip_tool_request_middleware=True,
                skip_tool_execution_middleware=True,
            )
        )
        second = _parsed(
            model_tools.handle_function_call(
                "write_file",
                args,
                skip_pre_tool_call_hook=True,
                skip_tool_request_middleware=True,
                skip_tool_execution_middleware=True,
            )
        )

    assert first == {"ok": True}
    assert second["error_type"] == "effect_policy_denied"
    assert len(calls) == 2


@pytest.mark.parametrize(
    ("dispatch_task_id", "dispatch_tool_call_id"),
    [("child", "call-1"), ("parent", "call-2")],
)
def test_effect_policy_permit_cannot_cross_call_identity(
    monkeypatch, tmp_path, dispatch_task_id, dispatch_tool_call_id
):
    calls = []

    def enforce(*args, **kwargs):
        calls.append((args, kwargs))
        if len(calls) == 1:
            return PolicyResult(PolicyDecision.ALLOW, "live allow")
        return PolicyResult(PolicyDecision.DENY, "task mismatch", non_bypassable=True)

    monkeypatch.setattr("tools.effect_policy_runtime.enforce_tool_call", enforce)
    monkeypatch.setattr(model_tools.registry, "dispatch", lambda *args, **kwargs: {"ok": True})
    args = {"path": str(tmp_path / "file.txt"), "content": "payload"}

    permit_result, permit = authorize_and_issue_effect_permit(
        "write_file", args, task_id="parent", tool_call_id="call-1"
    )
    assert permit_result.decision is PolicyDecision.ALLOW
    assert permit is not None
    with bind_issued_effect_permit(permit):
        result = _parsed(
            model_tools.handle_function_call(
                "write_file",
                args,
                task_id=dispatch_task_id,
                tool_call_id=dispatch_tool_call_id,
                skip_pre_tool_call_hook=True,
                skip_tool_request_middleware=True,
                skip_tool_execution_middleware=True,
            )
        )

    assert result["error_type"] == "effect_policy_denied"
    assert len(calls) == 2


def test_direct_missing_task_id_uses_carrier_default_workspace(monkeypatch, tmp_path):
    workspace = tmp_path / "default-workspace"
    workspace.mkdir()
    protected = tmp_path / "protected"
    protected.mkdir()
    seen = []
    monkeypatch.setattr(
        "tools.effect_policy_runtime.load_effect_policy",
        lambda: EffectPolicy(protected_roots=(canonicalize_target(str(protected)),)),
    )
    monkeypatch.setattr(
        "tools.file_tools_paths._resolve_path_for_task",
        lambda path, task_id: seen.append(task_id) or workspace / path,
    )
    dispatched = []
    monkeypatch.setattr(
        model_tools.registry,
        "dispatch",
        lambda *args, **kwargs: dispatched.append(kwargs) or {"ok": True},
    )

    result = _parsed(
        model_tools.handle_function_call(
            "write_file",
            {"path": "safe.txt", "content": "payload"},
            skip_pre_tool_call_hook=True,
            skip_tool_request_middleware=True,
            skip_tool_execution_middleware=True,
        )
    )

    assert result == {"ok": True}
    assert seen and set(seen) == {"default"}
    assert dispatched == [{
        "task_id": None,
        "session_id": None,
        "user_task": None,
        "tool_call_id": None,
    }]


def test_inner_policy_block_is_reported_as_blocked_to_observers():
    status, error_type, message = model_tools._tool_result_observer_fields(
        "write_file",
        '{"error":"denied","error_type":"effect_policy_denied"}',
    )

    assert status == "blocked"
    assert error_type == "effect_policy_denied"
    assert message == "denied"


def test_real_dispatch_loads_policy_and_leaves_protected_target_unchanged(tmp_path):
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override

    home = tmp_path / "hermes-home"
    protected = tmp_path / "protected"
    home.mkdir()
    protected.mkdir()
    target = protected / "blocked.txt"
    (home / "config.yaml").write_text(
        "security:\n"
        "  effect_policy:\n"
        "    protected_roots:\n"
        f"      - {json.dumps(str(protected))}\n",
        encoding="utf-8",
    )
    token = set_hermes_home_override(home)
    try:
        result = model_tools.handle_function_call(
            "write_file",
            {"path": str(target), "content": "must-not-be-written"},
            skip_pre_tool_call_hook=True,
            skip_tool_request_middleware=True,
            skip_tool_execution_middleware=True,
        )
    finally:
        reset_hermes_home_override(token)

    assert _parsed(result)["error_type"] == "effect_policy_denied"
    assert not target.exists()


@pytest.mark.parametrize(
    "config_text",
    [
        "security:\n  effect_policy: [\n",
        "security:\n  effect_policy: null\n",
        "security:\n  effect_policy:\n    denied_effects: [write]\n",
    ],
)
def test_real_dispatch_fails_closed_for_malformed_or_unknown_policy(config_text, tmp_path):
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override

    home = tmp_path / "hermes-home"
    home.mkdir()
    (home / "config.yaml").write_text(config_text, encoding="utf-8")
    target = tmp_path / "must-not-exist.txt"
    token = set_hermes_home_override(home)
    try:
        result = model_tools.handle_function_call(
            "write_file",
            {"path": str(target), "content": "must-not-be-written"},
            skip_pre_tool_call_hook=True,
            skip_tool_request_middleware=True,
            skip_tool_execution_middleware=True,
        )
    finally:
        reset_hermes_home_override(token)

    assert _parsed(result)["error_type"] == "effect_policy_denied"
    assert not target.exists()


@pytest.mark.parametrize(
    "managed_text",
    [
        "security:\n  effect_policy: [\n",
        "security:\n  effect_policy: null\n",
        "security:\n  effect_policy:\n    denied_effects: [write]\n",
    ],
)
def test_real_dispatch_fails_closed_for_malformed_managed_policy(monkeypatch, managed_text, tmp_path):
    from hermes_cli import managed_scope
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override

    home = tmp_path / "hermes-home"
    managed = tmp_path / "managed"
    home.mkdir()
    managed.mkdir()
    (home / "config.yaml").write_text("{}\n", encoding="utf-8")
    (managed / "config.yaml").write_text(managed_text, encoding="utf-8")
    monkeypatch.setenv("HERMES_MANAGED_DIR", str(managed))
    managed_scope.invalidate_managed_cache()
    target = tmp_path / "managed-policy-must-not-exist.txt"
    token = set_hermes_home_override(home)
    try:
        result = model_tools.handle_function_call(
            "write_file",
            {"path": str(target), "content": "must-not-be-written"},
            skip_pre_tool_call_hook=True,
            skip_tool_request_middleware=True,
            skip_tool_execution_middleware=True,
        )
    finally:
        reset_hermes_home_override(token)
        managed_scope.invalidate_managed_cache()

    assert _parsed(result)["error_type"] == "effect_policy_denied"
    assert not target.exists()


@pytest.mark.parametrize(
    "user_policy",
    [
        "    deny_effects: write\n",
        "    deny_effects: [not_a_real_effect]\n",
        "    protected_roots: [relative/path]\n",
    ],
)
def test_managed_override_cannot_hide_malformed_user_policy(monkeypatch, user_policy, tmp_path):
    from hermes_cli import managed_scope
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override

    home = tmp_path / "hermes-home"
    managed = tmp_path / "managed"
    home.mkdir()
    managed.mkdir()
    (home / "config.yaml").write_text(
        "security:\n  effect_policy:\n" + user_policy,
        encoding="utf-8",
    )
    (managed / "config.yaml").write_text(
        "security:\n"
        "  effect_policy:\n"
        "    protected_roots: []\n"
        "    deny_effects: []\n"
        "    require_approval_effects: []\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_MANAGED_DIR", str(managed))
    managed_scope.invalidate_managed_cache()
    target = tmp_path / "overridden-policy-must-not-exist.txt"
    token = set_hermes_home_override(home)
    try:
        result = model_tools.handle_function_call(
            "write_file",
            {"path": str(target), "content": "must-not-be-written"},
            skip_pre_tool_call_hook=True,
            skip_tool_request_middleware=True,
            skip_tool_execution_middleware=True,
        )
    finally:
        reset_hermes_home_override(token)
        managed_scope.invalidate_managed_cache()

    assert _parsed(result)["error_type"] == "effect_policy_denied"
    assert not target.exists()


@pytest.mark.parametrize("carrier", ["write", "replace", "update", "delete", "move"])
def test_real_dispatch_cannot_mutate_managed_effect_policy(monkeypatch, carrier, tmp_path):
    from hermes_cli import managed_scope
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override

    home = tmp_path / "hermes-home"
    managed = tmp_path / "managed"
    alias_dir = managed / "alias"
    home.mkdir()
    alias_dir.mkdir(parents=True)
    (home / "config.yaml").write_text("{}\n", encoding="utf-8")
    managed_config = managed / "config.yaml"
    original = "security:\n  effect_policy:\n    deny_effects: [yolo_or_bypass_enable]\n"
    managed_config.write_text(original, encoding="utf-8")
    alias = str(alias_dir / ".." / "config.yaml")
    destination = managed / "moved.yaml"
    monkeypatch.setenv("HERMES_MANAGED_DIR", str(managed))
    managed_scope.invalidate_managed_cache()
    token = set_hermes_home_override(home)
    try:
        if carrier == "write":
            tool_name = "write_file"
            args = {"path": alias, "content": "{}\n"}
        elif carrier == "replace":
            tool_name = "patch"
            args = {
                "mode": "replace",
                "path": alias,
                "old_string": "yolo_or_bypass_enable",
                "new_string": "read",
            }
        else:
            tool_name = "patch"
            operation = {
                "update": (
                    f"*** Update File: {alias}\n"
                    "@@\n"
                    "-    deny_effects: [yolo_or_bypass_enable]\n"
                    "+    deny_effects: [read]\n"
                ),
                "delete": f"*** Delete File: {alias}\n",
                "move": f"*** Move File: {alias} -> {destination}\n",
            }[carrier]
            args = {"mode": "patch", "patch": f"*** Begin Patch\n{operation}*** End Patch"}

        result = model_tools.handle_function_call(
            tool_name,
            args,
            skip_pre_tool_call_hook=True,
            skip_tool_request_middleware=True,
            skip_tool_execution_middleware=True,
        )
    finally:
        reset_hermes_home_override(token)
        managed_scope.invalidate_managed_cache()

    assert _parsed(result)["error_type"] == "effect_policy_denied"
    assert managed_config.read_text(encoding="utf-8") == original
    assert not destination.exists()


@pytest.mark.windows_only
@pytest.mark.parametrize("config_layer", ["user", "managed"])
def test_real_dispatch_cannot_mutate_config_through_windows_extended_path(
    monkeypatch, config_layer, tmp_path
):
    from hermes_cli import managed_scope
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override

    home = tmp_path / "hermes-home"
    managed = tmp_path / "managed"
    home.mkdir()
    managed.mkdir()
    original = "security:\n  effect_policy:\n    deny_effects: [yolo_or_bypass_enable]\n"
    user_config = home / "config.yaml"
    managed_config = managed / "config.yaml"
    user_config.write_text(original if config_layer == "user" else "{}\n", encoding="utf-8")
    if config_layer == "managed":
        managed_config.write_text(original, encoding="utf-8")
        monkeypatch.setenv("HERMES_MANAGED_DIR", str(managed))
    managed_scope.invalidate_managed_cache()
    target = user_config if config_layer == "user" else managed_config
    extended_target = "\\\\?\\" + str(target)
    token = set_hermes_home_override(home)
    try:
        result = model_tools.handle_function_call(
            "write_file",
            {"path": extended_target, "content": "{}\n"},
            skip_pre_tool_call_hook=True,
            skip_tool_request_middleware=True,
            skip_tool_execution_middleware=True,
        )
    finally:
        reset_hermes_home_override(token)
        managed_scope.invalidate_managed_cache()

    assert _parsed(result)["error_type"] == "effect_policy_denied"
    assert target.read_text(encoding="utf-8") == original


@pytest.mark.windows_only
@pytest.mark.parametrize("confirmation", ["mcp_reload_confirm", "destructive_slash_confirm"])
@pytest.mark.parametrize("current_value", [None, '"true"', "1"])
def test_confirmation_disable_is_denied_through_windows_case_alias(confirmation, current_value, tmp_path):
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override

    home = tmp_path / "Hermes-Home"
    home.mkdir()
    config_path = home / "config.yaml"
    approvals = "" if current_value is None else f"approvals:\n  {confirmation}: {current_value}\n"
    original = (
        approvals
        + "security:\n"
        "  effect_policy:\n"
        "    deny_effects:\n"
        "      - yolo_or_bypass_enable\n"
    )
    config_path.write_text(original, encoding="utf-8")
    candidate = (
        f"approvals:\n  {confirmation}: false\n"
        "security:\n"
        "  effect_policy:\n"
        "    deny_effects:\n"
        "      - yolo_or_bypass_enable\n"
    )
    token = set_hermes_home_override(home)
    try:
        result = model_tools.handle_function_call(
            "write_file",
            {"path": str(config_path).swapcase(), "content": candidate},
            skip_pre_tool_call_hook=True,
            skip_tool_request_middleware=True,
            skip_tool_execution_middleware=True,
        )
    finally:
        reset_hermes_home_override(token)

    assert _parsed(result)["error_type"] == "effect_policy_denied"
    assert config_path.read_text(encoding="utf-8") == original


def test_v4a_add_cannot_overwrite_existing_file_under_replace_deny(monkeypatch, tmp_path):
    target = tmp_path / "existing.txt"
    target.write_text("ORIGINAL", encoding="utf-8")
    monkeypatch.setattr(
        "tools.effect_policy_runtime.load_effect_policy",
        lambda: EffectPolicy(denied_effects=frozenset({EffectKind.REPLACE})),
    )

    result = model_tools.handle_function_call(
        "patch",
        {
            "mode": "patch",
            "patch": f"*** Begin Patch\n*** Add File: {target}\n+OVERWRITTEN\n*** End Patch",
        },
        skip_pre_tool_call_hook=True,
        skip_tool_request_middleware=True,
        skip_tool_execution_middleware=True,
    )

    assert _parsed(result)["error_type"] == "effect_policy_denied"
    assert target.read_text(encoding="utf-8") == "ORIGINAL"


def test_effect_permit_reauthorizes_when_live_policy_changes(monkeypatch, tmp_path):
    target = tmp_path / "newly-protected.txt"
    current_policy = {"value": EffectPolicy()}
    monkeypatch.setattr(
        "tools.effect_policy_runtime.load_effect_policy",
        lambda: current_policy["value"],
    )
    dispatched = []
    monkeypatch.setattr(
        model_tools.registry,
        "dispatch",
        lambda *args, **kwargs: dispatched.append((args, kwargs)) or {"ok": True},
    )
    args = {"path": str(target), "content": "must-not-be-written"}
    permit_result, permit = authorize_and_issue_effect_permit("write_file", args)
    assert permit_result.decision is PolicyDecision.ALLOW
    assert permit is not None

    current_policy["value"] = EffectPolicy(
        protected_roots=(canonicalize_target(str(tmp_path)),),
    )
    with bind_issued_effect_permit(permit):
        result = _parsed(
            model_tools.handle_function_call(
                "write_file",
                args,
                skip_pre_tool_call_hook=True,
                skip_tool_request_middleware=True,
                skip_tool_execution_middleware=True,
            )
        )

    assert result["error_type"] == "effect_policy_denied"
    assert dispatched == []
    assert not target.exists()


def test_direct_model_dispatch_rejects_policy_change_during_approval(monkeypatch, tmp_path):
    current_policy = {
        "value": EffectPolicy(
            approval_required_effects=frozenset({EffectKind.WRITE})
        )
    }
    monkeypatch.setattr(
        "tools.effect_policy_runtime.load_effect_policy",
        lambda: current_policy["value"],
    )
    dispatched = []
    monkeypatch.setattr(
        model_tools.registry,
        "dispatch",
        lambda *args, **kwargs: dispatched.append((args, kwargs)) or {"ok": True},
    )

    def approve_and_tighten(*args, **kwargs):
        current_policy["value"] = EffectPolicy(
            denied_effects=frozenset({EffectKind.WRITE})
        )
        return {"approved": True}

    monkeypatch.setattr("tools.approval.request_tool_approval", approve_and_tighten)
    result = _parsed(
        model_tools.handle_function_call(
            "write_file",
            {"path": str(tmp_path / "blocked.txt"), "content": "payload"},
            skip_pre_tool_call_hook=True,
            skip_tool_request_middleware=True,
            skip_tool_execution_middleware=True,
        )
    )

    assert result["error_type"] == "effect_policy_stale_authorization"
    assert dispatched == []


def test_effect_permit_cannot_be_self_issued_with_an_empty_policy(monkeypatch, tmp_path):
    args = {"path": str(tmp_path / "file.txt"), "content": "payload"}
    denied = PolicyResult(PolicyDecision.DENY, "live deny", non_bypassable=True)
    monkeypatch.setattr("tools.effect_policy_runtime.enforce_tool_call", lambda *a, **kw: denied)

    with pytest.raises(TypeError):
        authorize_and_issue_effect_permit("write_file", args, policy=EffectPolicy())
    result, permit = authorize_and_issue_effect_permit("write_file", args)

    assert result is denied
    assert permit is None


def test_forged_attempt_id_cannot_authorize_dispatch(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(
        "tools.effect_policy_runtime.enforce_tool_call",
        lambda *args, **kwargs: calls.append((args, kwargs))
        or PolicyResult(PolicyDecision.DENY, "forged", non_bypassable=True),
    )
    monkeypatch.setattr(model_tools.registry, "dispatch", lambda *args, **kwargs: {"ok": True})
    args = {"path": str(tmp_path / "file.txt"), "content": "payload"}

    with bind_issued_effect_permit(_EffectPermitHandle("attacker-chosen-attempt")):
        result = _parsed(
            model_tools.handle_function_call(
                "write_file",
                args,
                skip_pre_tool_call_hook=True,
                skip_tool_request_middleware=True,
                skip_tool_execution_middleware=True,
            )
        )

    assert result["error_type"] == "effect_policy_denied"
    assert len(calls) == 1


def test_non_json_arguments_cannot_receive_a_reusable_permit(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(
        "tools.effect_policy_runtime.enforce_tool_call",
        lambda *args, **kwargs: calls.append((args, kwargs))
        or PolicyResult(PolicyDecision.ALLOW, "allowed"),
    )

    args = {"path": Path(tmp_path / "safe.txt"), "content": "payload"}
    result, permit = authorize_and_issue_effect_permit("write_file", args)

    assert result.decision is PolicyDecision.ALLOW
    assert permit is None


def test_permit_is_revoked_when_agent_start_callback_fails(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from agent import tool_executor
    from tools import effect_policy_runtime

    monkeypatch.setattr(effect_policy_runtime, "load_effect_policy", lambda: EffectPolicy())
    monkeypatch.setattr(tool_executor, "_pre_tool_block", lambda agent, ref: (None, ref.args))
    agent = SimpleNamespace(
        _tool_guardrails=SimpleNamespace(
            before_call=lambda name, args: SimpleNamespace(allows_execution=True)
        )
    )
    args = {"path": str(tmp_path / "safe.txt"), "content": "payload"}
    state = tool_executor._ManagedToolResult(
        result=None, args=args, middleware_trace=[], blocked=False, dispatched=True
    )
    ref = tool_executor._ToolCallRef("write_file", args, "default", "call", [])
    before = len(effect_policy_runtime._effect_permits)

    with pytest.raises(RuntimeError, match="start failed"):
        tool_executor._dispatch_authorized_once(
            agent,
            state,
            ref,
            execute=lambda final_args: {"ok": True},
            scope_block=None,
            display_index=None,
            begin_execution=lambda callback=None: (_ for _ in ()).throw(RuntimeError("start failed")),
            authorization_gate=None,
        )

    assert len(effect_policy_runtime._effect_permits) == before
