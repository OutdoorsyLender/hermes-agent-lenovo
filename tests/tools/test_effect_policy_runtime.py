"""Runtime adapters from model tools to semantic effect requests."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from tools.effect_policy import (
    CanonicalTarget,
    EffectKind,
    EffectPolicy,
    IdentityStatus,
    PolicyDecision,
    RepositoryIdentity,
)
from tools.effect_policy_runtime import (
    _same_target_path,
    _write_target_effects,
    EffectContext,
    authorize_tool_call,
    canonicalize_target,
    effect_requests_for_tool,
    enforce_tool_call,
    load_effect_policy,
    repository_identity_for_path,
)


def _context(*, unattended: bool = False, bypass_requested: bool = False) -> EffectContext:
    return EffectContext(
        actor="coder",
        profile="coder",
        session_mode="cron" if unattended else "interactive",
        execution_mode="normal",
        unattended=unattended,
        bypass_requested=bypass_requested,
    )


def _protected(path) -> EffectPolicy:
    target = canonicalize_target(str(path))
    assert target.identity_status is IdentityStatus.PROVEN
    return EffectPolicy(protected_roots=(target,))


def test_write_and_v4a_patch_adapters_emit_target_semantics(tmp_path):
    source = tmp_path / "source.txt"
    destination = tmp_path / "destination.txt"
    deleted = tmp_path / "deleted.txt"
    patch = (
        "*** Begin Patch\n"
        f"*** Move File: {source} -> {destination}\n"
        f"*** Delete File: {deleted}\n"
        "*** End Patch"
    )

    write = effect_requests_for_tool(
        "write_file", {"path": str(source), "content": "x"}, context=_context()
    )
    operations = effect_requests_for_tool(
        "patch", {"mode": "patch", "patch": patch}, context=_context()
    )

    assert [request.effect for request in write] == [EffectKind.CREATE, EffectKind.WRITE]
    assert write[0].target and write[0].target.canonical == str(source.resolve())
    assert [request.effect for request in operations] == [EffectKind.MOVE, EffectKind.DELETE]
    assert operations[0].source and operations[0].source.canonical == str(source.resolve())
    assert operations[0].destination and operations[0].destination.canonical == str(destination.resolve())
    assert operations[1].target and operations[1].target.canonical == str(deleted.resolve())


@pytest.mark.parametrize("effect", [EffectKind.WRITE, EffectKind.TRUNCATE])
@pytest.mark.parametrize("mode", ["replace", "patch"])
def test_patch_whole_file_mutations_preserve_write_semantics(tmp_path, effect, mode):
    target = tmp_path / "target.txt"
    target.write_text("before", encoding="utf-8")
    args = (
        {"mode": "replace", "path": str(target), "old_string": "before", "new_string": "after"}
        if mode == "replace"
        else {
            "mode": "patch",
            "patch": (
                "*** Begin Patch\n"
                f"*** Update File: {target}\n"
                "@@\n-before\n+after\n"
                "*** End Patch"
            ),
        }
    )

    requests = effect_requests_for_tool("patch", args, context=_context())
    result = authorize_tool_call(
        "patch",
        args,
        context=_context(),
        policy=EffectPolicy(denied_effects=frozenset({effect})),
    )
    approval = authorize_tool_call(
        "patch",
        args,
        context=_context(),
        policy=EffectPolicy(approval_required_effects=frozenset({effect})),
    )

    assert effect in {request.effect for request in requests}
    assert result.decision is PolicyDecision.DENY
    assert approval.decision is PolicyDecision.REQUIRE_APPROVAL


def test_v4a_add_emits_create_and_write(tmp_path):
    target = tmp_path / "added.txt"
    patch = f"*** Begin Patch\n*** Add File: {target}\n+content\n*** End Patch"

    requests = effect_requests_for_tool(
        "patch",
        {"mode": "patch", "patch": patch},
        context=_context(),
    )

    assert {request.effect for request in requests} == {EffectKind.CREATE, EffectKind.WRITE}


def test_dangling_symlink_whole_file_write_emits_create(monkeypatch, tmp_path):
    link = str(tmp_path / "link.txt")
    missing_referent = str(tmp_path / "missing.txt")
    target = CanonicalTarget(
        raw=link,
        absolute=link,
        canonical=missing_referent,
        identity_status=IdentityStatus.PROVEN,
    )

    def fake_lstat(path):
        if path == missing_referent:
            raise FileNotFoundError(path)
        return type("StatResult", (), {"st_file_attributes": 0, "st_mode": stat.S_IFLNK})()

    monkeypatch.setattr("tools.effect_policy_runtime.os.lstat", fake_lstat)

    assert _write_target_effects(target) == (EffectKind.CREATE, EffectKind.WRITE)
    policy = EffectPolicy(denied_effects=frozenset({EffectKind.CREATE}))
    calls = (
        ("write_file", {"path": link, "content": "blocked"}),
        (
            "patch",
            {"mode": "patch", "patch": f"*** Begin Patch\n*** Add File: {link}\n+blocked\n*** End Patch"},
        ),
    )
    for tool_name, args in calls:
        result = authorize_tool_call(
            tool_name,
            args,
            context=_context(),
            policy=policy,
            target_resolver=lambda path: target,
        )
        assert result.decision is PolicyDecision.DENY


def test_protected_policy_blocks_write_and_patch_before_carrier(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    target = protected / "tracked.txt"
    policy = _protected(protected)

    write = authorize_tool_call(
        "write_file", {"path": str(target), "content": "x"}, context=_context(), policy=policy
    )
    patch = authorize_tool_call(
        "patch",
        {"mode": "replace", "path": str(target), "old_string": "a", "new_string": "b"},
        context=_context(),
        policy=policy,
    )

    assert write.decision is PolicyDecision.DENY
    assert patch.decision is PolicyDecision.DENY
    assert write.non_bypassable and patch.non_bypassable


def test_opaque_process_carriers_fail_closed_when_protected_roots_exist(tmp_path):
    policy = _protected(tmp_path / "protected")

    terminal = authorize_tool_call(
        "terminal",
        {"command": "wrapper --unknown-effect"},
        context=_context(bypass_requested=True),
        policy=policy,
    )
    python = authorize_tool_call(
        "execute_code",
        {"code": "opaque_mutation()"},
        context=_context(unattended=True, bypass_requested=True),
        policy=policy,
    )

    assert terminal.decision is PolicyDecision.REQUIRE_HUMAN_APPROVAL
    assert terminal.non_bypassable is True
    assert python.decision is PolicyDecision.DENY
    assert python.non_bypassable is True


def test_redirection_identity_from_resolver_is_used(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    real = protected / "tracked.txt"
    real.write_text("original", encoding="utf-8")
    link = tmp_path / "innocent.txt"
    try:
        link.symlink_to(real)
    except OSError:
        # Windows developer mode may be disabled.  The evaluator contract is
        # still exercised with the identity a reparse-aware resolver supplies.
        redirected = CanonicalTarget(
            raw=str(link),
            absolute=str(link.absolute()),
            canonical=str(real.resolve()),
            identity_status=IdentityStatus.PROVEN,
        )
    else:
        redirected = canonicalize_target(str(link))

    result = authorize_tool_call(
        "write_file",
        {"path": str(link), "content": "changed"},
        context=_context(),
        policy=_protected(protected),
        target_resolver=lambda _path: redirected,
    )

    assert result.decision is PolicyDecision.DENY
    assert real.read_text(encoding="utf-8") == "original"


def test_move_crossing_protected_boundary_checks_both_endpoints(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    outside = tmp_path / "outside.txt"
    inside = protected / "inside.txt"
    policy = _protected(protected)

    into = effect_requests_for_tool(
        "patch",
        {"mode": "patch", "patch": f"*** Begin Patch\n*** Move File: {outside} -> {inside}\n*** End Patch"},
        context=_context(),
    )[0]
    out = effect_requests_for_tool(
        "patch",
        {"mode": "patch", "patch": f"*** Begin Patch\n*** Move File: {inside} -> {outside}\n*** End Patch"},
        context=_context(),
    )[0]

    from tools.effect_policy import authorize_effect

    assert authorize_effect(into, policy).decision is PolicyDecision.DENY
    assert authorize_effect(out, policy).decision is PolicyDecision.DENY


def test_malformed_runtime_policy_is_explicitly_invalid(monkeypatch):
    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly",
        lambda: {"security": {"effect_policy": {"protected_roots": "not-a-list"}}},
    )

    policy = load_effect_policy()

    assert policy.valid is False
    assert "protected_roots" in (policy.error or "")


@pytest.mark.parametrize("raw", [None, False, 0, "", []])
def test_explicit_falsy_effect_policy_is_invalid(monkeypatch, raw):
    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly",
        lambda: {"security": {"effect_policy": raw}},
    )

    policy = load_effect_policy()

    assert policy.valid is False
    assert "mapping" in (policy.error or "")


@pytest.mark.parametrize("field", ["deny_effects", "require_approval_effects"])
def test_explicit_null_effect_list_is_invalid(monkeypatch, field):
    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly",
        lambda: {"security": {"effect_policy": {field: None}}},
    )

    policy = load_effect_policy()

    assert policy.valid is False
    assert field in (policy.error or "")


def test_explicit_human_approval_can_grant_one_opaque_process_call(monkeypatch, tmp_path):
    prompts = []
    monkeypatch.setattr(
        "tools.approval.request_non_bypassable_effect_approval",
        lambda **kwargs: prompts.append(kwargs) or {"approved": True},
    )

    result = enforce_tool_call(
        "terminal",
        {"command": "opaque-wrapper"},
        context=_context(bypass_requested=True),
        policy=_protected(tmp_path / "protected"),
    )

    assert result.decision is PolicyDecision.ALLOW
    assert len(prompts) == 1
    assert "opaque-wrapper" in prompts[0]["display_target"]


def test_relative_file_target_uses_the_task_workspace_not_process_cwd(monkeypatch, tmp_path):
    workspace = tmp_path / "worktree"
    workspace.mkdir()
    monkeypatch.setattr(
        "tools.file_tools_paths._resolve_path_for_task",
        lambda path, task_id: workspace / path,
    )

    request = effect_requests_for_tool(
        "write_file",
        {"path": "nested/file.txt", "content": "payload"},
        context=_context(),
        task_id="isolated-task",
    )[0]

    assert request.target is not None
    assert request.target.canonical == str((workspace / "nested/file.txt").resolve())


@pytest.mark.parametrize(
    ("tool_name", "args"),
    [
        ("terminal", {"command": "opaque-wrapper"}),
        ("execute_code", {"code": "opaque_mutation()"}),
        ("process_manage", {"action": "write", "session_id": "proc-1", "data": "x"}),
        ("process_manage", {"action": "submit", "session_id": "proc-1", "data": "x"}),
    ],
)
def test_opaque_effectful_process_carriers_cannot_bypass_any_semantic_deny(tool_name, args):
    policy = EffectPolicy(denied_effects=frozenset({EffectKind.CONFIG_WRITE}))

    result = authorize_tool_call(
        tool_name,
        args,
        context=_context(bypass_requested=True),
        policy=policy,
    )

    assert result.decision is PolicyDecision.DENY
    assert result.non_bypassable is True


@pytest.mark.parametrize("tool_name", ["terminal", "execute_code"])
def test_opaque_process_carriers_conservatively_require_configured_approval(tool_name):
    result = authorize_tool_call(
        tool_name,
        {"command": "opaque"} if tool_name == "terminal" else {"code": "opaque()"},
        context=_context(),
        policy=EffectPolicy(approval_required_effects=frozenset({EffectKind.DELETE})),
    )

    assert result.decision is PolicyDecision.REQUIRE_APPROVAL


def test_protected_root_precedence_beats_opaque_ordinary_approval_bypass(tmp_path):
    result = authorize_tool_call(
        "terminal",
        {"command": "opaque"},
        context=_context(bypass_requested=True),
        policy=EffectPolicy(
            protected_roots=(canonicalize_target(str(tmp_path / "protected")),),
            approval_required_effects=frozenset({EffectKind.DELETE}),
        ),
    )

    assert result.decision is PolicyDecision.REQUIRE_HUMAN_APPROVAL
    assert result.non_bypassable is True


@pytest.mark.parametrize("action", ["close", "kill", "handoff"])
def test_process_control_actions_are_semantically_effectful(action):
    result = authorize_tool_call(
        "process_manage",
        {"action": action, "session_id": "proc-1", "data": "purpose"},
        context=_context(bypass_requested=True),
        policy=EffectPolicy(denied_effects=frozenset({EffectKind.PROCESS_EXECUTE})),
    )

    assert result.decision is PolicyDecision.DENY
    assert result.non_bypassable is True


def test_process_manage_read_actions_remain_non_effectful():
    policy = EffectPolicy(denied_effects=frozenset({EffectKind.PROCESS_EXECUTE}))

    for action in ("list", "poll", "log", "wait"):
        result = authorize_tool_call(
            "process_manage",
            {"action": action, "session_id": "proc-1"},
            context=_context(),
            policy=policy,
        )
        assert result.decision is PolicyDecision.ALLOW


def test_write_file_emits_create_or_replace_truncate_write_semantics(tmp_path):
    created = tmp_path / "new.txt"
    replaced = tmp_path / "existing.txt"
    replaced.write_text("old", encoding="utf-8")

    create_effects = {
        request.effect
        for request in effect_requests_for_tool(
            "write_file", {"path": str(created), "content": "new"}, context=_context()
        )
    }
    replace_effects = {
        request.effect
        for request in effect_requests_for_tool(
            "write_file", {"path": str(replaced), "content": "new"}, context=_context()
        )
    }

    assert create_effects == {EffectKind.CREATE, EffectKind.WRITE}
    assert replace_effects == {EffectKind.REPLACE, EffectKind.TRUNCATE, EffectKind.WRITE}
    assert authorize_tool_call(
        "write_file",
        {"path": str(created), "content": "new"},
        context=_context(),
        policy=EffectPolicy(denied_effects=frozenset({EffectKind.CREATE})),
    ).decision is PolicyDecision.DENY
    assert authorize_tool_call(
        "write_file",
        {"path": str(replaced), "content": "new"},
        context=_context(),
        policy=EffectPolicy(denied_effects=frozenset({EffectKind.REPLACE})),
    ).decision is PolicyDecision.DENY


def test_write_file_and_v4a_add_emit_missing_parent_creation(tmp_path):
    parent = tmp_path / "missing" / "nested"
    target = parent / "file.txt"
    policy = EffectPolicy(denied_effects=frozenset({EffectKind.CREATE_DIRECTORY}))

    write_requests = effect_requests_for_tool(
        "write_file", {"path": str(target), "content": "new"}, context=_context()
    )
    patch_args = {
        "mode": "patch",
        "patch": (
            "*** Begin Patch\n"
            f"*** Add File: {target}\n"
            "+new\n"
            "*** End Patch"
        ),
    }
    patch_requests = effect_requests_for_tool("patch", patch_args, context=_context())

    for requests in (write_requests, patch_requests):
        directory = next(request for request in requests if request.effect is EffectKind.CREATE_DIRECTORY)
        assert directory.target is not None
        assert directory.target.canonical == str(parent.resolve())
    assert authorize_tool_call(
        "write_file",
        {"path": str(target), "content": "new"},
        context=_context(),
        policy=policy,
    ).decision is PolicyDecision.DENY
    assert authorize_tool_call(
        "patch", patch_args, context=_context(), policy=policy
    ).decision is PolicyDecision.DENY


def test_write_file_detects_active_config_and_bypass_policy_changes(monkeypatch, tmp_path):
    home = tmp_path / "profile"
    home.mkdir()
    config_path = home / "config.yaml"
    config_path.write_text("approvals:\n  mode: manual\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(home))

    requests = effect_requests_for_tool(
        "write_file",
        {"path": str(config_path), "content": "approvals:\n  mode: off\n"},
        context=_context(),
    )

    effects = {request.effect for request in requests}
    assert EffectKind.CONFIG_WRITE in effects
    assert EffectKind.APPROVAL_POLICY_CHANGE in effects
    assert EffectKind.YOLO_OR_BYPASS_ENABLE in effects


def test_removing_approval_deny_rule_is_bypass_enablement(monkeypatch, tmp_path):
    home = tmp_path / "profile"
    home.mkdir()
    config_path = home / "config.yaml"
    config_path.write_text(
        "approvals:\n  deny:\n    - 'git push *'\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(home))
    for content in ("approvals:\n  deny: []\n", "{}\n"):
        args = {"path": str(config_path), "content": content}
        effects = {
            request.effect
            for request in effect_requests_for_tool("write_file", args, context=_context())
        }
        result = authorize_tool_call(
            "write_file",
            args,
            context=_context(),
            policy=EffectPolicy(denied_effects=frozenset({EffectKind.YOLO_OR_BYPASS_ENABLE})),
        )

        assert EffectKind.YOLO_OR_BYPASS_ENABLE in effects
        assert result.decision is PolicyDecision.DENY


@pytest.mark.parametrize("mode", ["replace", "patch"])
def test_patch_detects_active_config_and_bypass_policy_changes(monkeypatch, tmp_path, mode):
    home = tmp_path / "profile"
    home.mkdir()
    config_path = home / "config.yaml"
    config_path.write_text("approvals:\n  mode: manual\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(home))
    if mode == "replace":
        args = {
            "mode": "replace",
            "path": str(config_path),
            "old_string": "manual",
            "new_string": "off",
        }
    else:
        args = {
            "mode": "patch",
            "patch": (
                "*** Begin Patch\n"
                f"*** Update File: {config_path}\n"
                "@@\n"
                "-  mode: manual\n"
                "+  mode: off\n"
                "*** End Patch"
            ),
        }

    effects = {
        request.effect
        for request in effect_requests_for_tool("patch", args, context=_context())
    }

    assert {
        EffectKind.CONFIG_WRITE,
        EffectKind.APPROVAL_POLICY_CHANGE,
        EffectKind.YOLO_OR_BYPASS_ENABLE,
    } <= effects
    for denied in (
        EffectKind.CONFIG_WRITE,
        EffectKind.APPROVAL_POLICY_CHANGE,
        EffectKind.YOLO_OR_BYPASS_ENABLE,
    ):
        result = authorize_tool_call(
            "patch",
            args,
            context=_context(),
            policy=EffectPolicy(denied_effects=frozenset({denied})),
        )
        assert result.decision is PolicyDecision.DENY


def test_unresolved_absolute_active_config_target_is_still_detected(monkeypatch, tmp_path):
    home = tmp_path / "profile"
    home.mkdir()
    config_path = home / "config.yaml"
    config_path.write_text("approvals:\n  mode: manual\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(home))
    unresolved = CanonicalTarget(
        raw=str(config_path),
        absolute=None,
        canonical=None,
        identity_status=IdentityStatus.UNKNOWN,
    )

    effects = {
        request.effect
        for request in effect_requests_for_tool(
            "write_file",
            {"path": str(config_path), "content": "approvals:\n  mode: off\n"},
            context=_context(),
            target_resolver=lambda path: unresolved,
        )
    }

    assert {
        EffectKind.CONFIG_WRITE,
        EffectKind.APPROVAL_POLICY_CHANGE,
        EffectKind.YOLO_OR_BYPASS_ENABLE,
    } <= effects


def test_missing_task_id_resolves_exactly_like_carrier_default(monkeypatch, tmp_path):
    workspace = tmp_path / "default-workspace"
    workspace.mkdir()
    seen = []

    def resolve(path, task_id):
        seen.append(task_id)
        return workspace / path

    monkeypatch.setattr("tools.file_tools_paths._resolve_path_for_task", resolve)

    request = effect_requests_for_tool(
        "write_file",
        {"path": "nested/file.txt", "content": "payload"},
        context=_context(),
        task_id=None,
    )[0]

    assert seen == ["default"]
    assert request.target is not None
    assert request.target.canonical == str((workspace / "nested/file.txt").resolve())


def test_relative_protected_roots_are_rejected(monkeypatch):
    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly",
        lambda: {"security": {"effect_policy": {"protected_roots": ["relative/repo"]}}},
    )

    policy = load_effect_policy()

    assert policy.valid is False
    assert "absolute" in (policy.error or "")


@pytest.mark.parametrize("root", [r"\protected", "/protected"])
@pytest.mark.windows_only
def test_windows_drive_relative_protected_roots_are_rejected(monkeypatch, root):
    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly",
        lambda: {"security": {"effect_policy": {"protected_roots": [root]}}},
    )

    policy = load_effect_policy()

    assert policy.valid is False
    assert "absolute" in (policy.error or "")


def test_protected_subdirectory_does_not_become_repository_wide_identity(monkeypatch):
    repository = RepositoryIdentity(
        worktree_root="C:/repo",
        common_dir="C:/repo/.git",
    )
    subdirectory = CanonicalTarget(
        raw="C:/repo/protected",
        absolute="C:/repo/protected",
        canonical="C:/repo/protected",
        identity_status=IdentityStatus.PROVEN,
        repository=repository,
    )
    monkeypatch.setattr("tools.effect_policy_runtime.canonicalize_target", lambda path: subdirectory)
    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly",
        lambda: {"security": {"effect_policy": {"protected_roots": ["C:/repo/protected"]}}},
    )

    policy = load_effect_policy()

    assert policy.valid is True
    assert policy.protected_roots == (subdirectory,)
    assert policy.protected_repositories == ()


def test_repository_root_still_derives_repository_wide_identity(monkeypatch):
    repository = RepositoryIdentity(
        worktree_root="C:/repo",
        common_dir="C:/repo/.git",
    )
    root = CanonicalTarget(
        raw="C:/repo",
        absolute="C:/repo",
        canonical="C:/repo",
        identity_status=IdentityStatus.PROVEN,
        repository=repository,
    )
    monkeypatch.setattr("tools.effect_policy_runtime.canonicalize_target", lambda path: root)
    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly",
        lambda: {"security": {"effect_policy": {"protected_roots": ["C:/repo"]}}},
    )

    policy = load_effect_policy()

    assert policy.valid is True
    assert policy.protected_repositories == (repository,)


@pytest.mark.macos_only
def test_macos_case_aliases_match_active_config_and_repository_root(monkeypatch):
    repository = RepositoryIdentity(
        worktree_root="/Users/Operator/Repo",
        common_dir="/Users/Operator/Repo/.git",
    )
    root = CanonicalTarget(
        raw="/users/operator/repo",
        absolute="/users/operator/repo",
        canonical="/users/operator/repo",
        identity_status=IdentityStatus.PROVEN,
        repository=repository,
    )
    def resolve(path):
        text = str(path)
        if text.casefold() == "/users/operator/repo":
            return root
        return CanonicalTarget(
            raw=text,
            absolute=text,
            canonical=text,
            identity_status=IdentityStatus.PROVEN,
        )

    monkeypatch.setattr("tools.effect_policy_runtime.canonicalize_target", resolve)
    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly",
        lambda: {"security": {"effect_policy": {"protected_roots": ["/users/operator/repo"]}}},
    )

    policy = load_effect_policy()
    config_target = CanonicalTarget(
        raw="/users/operator/.hermes/config.yaml",
        absolute="/users/operator/.hermes/config.yaml",
        canonical="/users/operator/.hermes/config.yaml",
        identity_status=IdentityStatus.PROVEN,
    )

    assert policy.protected_repositories == (repository,)
    assert _same_target_path(config_target, Path("/Users/Operator/.hermes/config.yaml"))


def test_repository_protection_covers_linked_common_directory_metadata():
    repository_root = Path(__file__).resolve().parents[2]
    protected_root = canonicalize_target(str(repository_root))
    assert protected_root.repository is not None
    policy = EffectPolicy(
        protected_roots=(protected_root,),
        protected_repositories=(protected_root.repository,),
    )
    common_dir = Path(protected_root.repository.common_dir)
    ref_target = common_dir / "refs" / "heads" / "effect-policy-probe"
    config_target = common_dir / "config"

    write = authorize_tool_call(
        "write_file",
        {"path": str(ref_target), "content": "not-dispatched"},
        context=_context(),
        policy=policy,
    )
    patch = authorize_tool_call(
        "patch",
        {
            "mode": "replace",
            "path": str(config_target),
            "old_string": "not-present",
            "new_string": "not-dispatched",
        },
        context=_context(),
        policy=policy,
    )

    assert write.decision is PolicyDecision.DENY
    assert patch.decision is PolicyDecision.DENY


def test_repository_identity_falls_back_for_git_without_path_format(monkeypatch, tmp_path):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if "--path-format=absolute" in command:
            return type(
                "Completed",
                (),
                {
                    "returncode": 0,
                    "stdout": f"--path-format=absolute\n{tmp_path}\n.git\n",
                    "stderr": "",
                },
            )()
        return type(
            "Completed",
            (),
            {"returncode": 0, "stdout": f"{tmp_path}\n.git\n", "stderr": ""},
        )()

    monkeypatch.setattr("tools.effect_policy_runtime.subprocess.run", run)

    repository = repository_identity_for_path(str(tmp_path))

    assert repository is not None
    assert Path(repository.common_dir) == (tmp_path / ".git").resolve()
    assert len(calls) == 2


def test_non_bypassable_approval_ignores_delegated_autoapprove_but_uses_selected_transport(monkeypatch):
    from agent.delegation_context import delegated_child_context
    from tools import approval
    from tools.delegate_tool_config import _subagent_auto_approve

    monkeypatch.setattr(approval, "_presence", lambda callback=None: (_subagent_auto_approve, True, False, False))
    monkeypatch.setattr(
        approval,
        "_present_with_selected_transport",
        lambda **kwargs: {"selected": False},
    )
    with delegated_child_context("child"):
        denied = approval.request_non_bypassable_effect_approval(
            description="identity unknown",
            display_target="<write_file> {\"path\":\"safe\"}",
        )
    assert denied["approved"] is False

    seen = []
    monkeypatch.setattr(
        approval,
        "_present_with_selected_transport",
        lambda **kwargs: seen.append(kwargs) or {
            "selected": True,
            "choice": "once",
            "failure": None,
            "fallback": None,
            "name": "fixture",
        },
    )
    with delegated_child_context("child"):
        approved = approval.request_non_bypassable_effect_approval(
            description="identity unknown",
            display_target="<write_file> {\"path\":\"safe\"}",
        )
    assert approved["approved"] is True
    assert seen[0]["allow_session"] is False
    assert seen[0]["allow_permanent"] is False

    persisted = []
    monkeypatch.setattr(approval, "_persist_choice", lambda *args, **kwargs: persisted.append(args))
    monkeypatch.setattr(
        approval,
        "_present_with_selected_transport",
        lambda **kwargs: {
            "selected": True,
            "choice": "always",
            "failure": None,
            "fallback": None,
            "name": "stale-client",
        },
    )
    with delegated_child_context("child"):
        stale_scope = approval.request_non_bypassable_effect_approval(
            description="identity unknown",
            display_target="<write_file> {\"path\":\"safe\"}",
        )
    assert stale_scope["approved"] is True
    assert persisted == []

    monkeypatch.setattr(
        approval,
        "_present_with_selected_transport",
        lambda **kwargs: {
            "selected": True,
            "choice": "deny",
            "failure": "timeout",
            "fallback": "builtin",
            "name": "fixture",
        },
    )
    with delegated_child_context("child"):
        fallback = approval.request_non_bypassable_effect_approval(
            description="identity unknown",
            display_target="<write_file> {\"path\":\"safe\"}",
        )
    assert fallback["approved"] is False


def test_non_bypassable_effect_prompt_contains_redacted_final_arguments(monkeypatch, tmp_path):
    prompted = []
    monkeypatch.setattr(
        "tools.approval.request_non_bypassable_effect_approval",
        lambda **kwargs: prompted.append(kwargs) or {"approved": True},
    )
    unknown = CanonicalTarget(
        raw="opaque",
        absolute=None,
        canonical=None,
        identity_status=IdentityStatus.UNKNOWN,
    )

    result = enforce_tool_call(
        "write_file",
        {"path": "opaque", "content": "api_key=sk-secret-value"},
        context=_context(),
        policy=_protected(tmp_path / "protected"),
        target_resolver=lambda path: unknown,
    )

    assert result.decision is PolicyDecision.ALLOW
    assert "write_file" in prompted[0]["display_target"]
    assert "opaque" in prompted[0]["display_target"]
    assert "«redacted:sk-…»" not in prompted[0]["display_target"]


def test_protected_roots_do_not_prompt_unrelated_typed_mutations(tmp_path):
    policy = _protected(tmp_path / "protected")

    for tool_name, args in (
        ("process_manage", {"action": "kill", "session_id": "proc-1"}),
        ("memory", {"action": "add", "content": "fact"}),
        ("skill_manage", {"operations": [{"action": "create", "name": "x"}]}),
    ):
        result = authorize_tool_call(tool_name, args, context=_context(), policy=policy)
        assert result.decision is PolicyDecision.ALLOW


def test_ordinary_approval_is_argument_bound_and_displays_redacted_target(monkeypatch, tmp_path):
    prompts = []
    monkeypatch.setattr(
        "tools.approval.request_tool_approval",
        lambda *args, **kwargs: prompts.append((args, kwargs)) or {"approved": False},
    )
    policy = EffectPolicy(approval_required_effects=frozenset({EffectKind.WRITE}))
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"

    for path in (first, second):
        enforce_tool_call(
            "write_file",
            {"path": str(path), "content": "secret=«redacted:sk-…»"},
            context=_context(),
            policy=policy,
        )

    displayed = json.loads(prompts[0][1]["display_target"])
    assert displayed["arguments"]["path"] == str(first)
    assert prompts[0][1]["rule_key"] != prompts[1][1]["rule_key"]
