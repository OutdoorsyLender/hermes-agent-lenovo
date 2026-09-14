"""Behavior contracts for the canonical semantic effect-policy evaluator."""

from __future__ import annotations

from dataclasses import replace

import pytest

from tools.effect_policy import (
    CanonicalTarget,
    EffectKind,
    EffectPolicy,
    EffectRequest,
    IdentityStatus,
    Mutability,
    PolicyDecision,
    RepositoryIdentity,
    ResourceKind,
    authorize_effect,
)


_REQUIRED_FILESYSTEM_EFFECTS = {
    "read", "create", "write", "append", "truncate", "replace", "rename", "move", "copy", "delete",
    "create_directory", "delete_directory", "create_symlink", "create_junction", "symlink_or_reparse_create",
    "permission_or_acl_change",
}
_REQUIRED_GIT_EFFECTS = {
    "read_repository", "write_worktree", "write_index", "create_commit", "create_ref", "update_ref",
    "delete_ref", "push", "force_push", "fetch", "reset", "clean", "worktree_add", "worktree_remove",
    "worktree_prune",
}
_REQUIRED_CONTROL_AND_EXTERNAL_EFFECTS = {
    "config_read", "config_write", "approval_policy_change", "yolo_or_bypass_enable", "skill_change",
    "memory_change", "mcp_configuration_change", "aws_read", "aws_mutate", "github_read", "github_mutate",
    "mcp_read", "mcp_mutate", "network_read", "network_write",
}


def _target(path: str, *, repository: RepositoryIdentity | None = None) -> CanonicalTarget:
    return CanonicalTarget(
        raw=path,
        absolute=path,
        canonical=path,
        identity_status=IdentityStatus.PROVEN,
        repository=repository,
    )


def _request(
    effect: EffectKind,
    *,
    target: CanonicalTarget | None = None,
    source: CanonicalTarget | None = None,
    destination: CanonicalTarget | None = None,
    carrier: str = "native_filesystem",
    unattended: bool = False,
    bypass_requested: bool = False,
) -> EffectRequest:
    return EffectRequest(
        actor="coder",
        profile="coder",
        session_mode="interactive",
        execution_mode="normal",
        effect=effect,
        resource=ResourceKind.FILESYSTEM,
        target=target,
        source=source,
        destination=destination,
        mutability=Mutability.MUTATING,
        carrier=carrier,
        unattended=unattended,
        bypass_requested=bypass_requested,
    )


def test_effect_taxonomy_covers_required_security_families():
    values = {effect.value for effect in EffectKind}
    assert _REQUIRED_FILESYSTEM_EFFECTS <= values
    assert _REQUIRED_GIT_EFFECTS <= values
    assert _REQUIRED_CONTROL_AND_EXTERNAL_EFFECTS <= values


@pytest.mark.parametrize(
    "carrier",
    ["bash:rm", "powershell:remove-item", "cmd:del", "python:os.remove", "python:pathlib.unlink", "node:fs.unlink", "native"],
)
def test_protected_delete_is_carrier_invariant_and_deny_beats_bypass(carrier):
    protected = _target("C:/protected/repo")
    request = _request(
        EffectKind.DELETE,
        target=_target("C:/protected/repo/tracked.txt"),
        carrier=carrier,
        unattended=True,
        bypass_requested=True,
    )

    result = authorize_effect(request, EffectPolicy(protected_roots=(protected,)))

    assert result.decision is PolicyDecision.DENY
    assert result.non_bypassable is True


def test_unknown_identity_for_possible_protected_mutation_fails_closed():
    protected = _target("C:/protected/repo")
    unknown = CanonicalTarget(
        raw="<unresolved-target>",
        absolute=None,
        canonical=None,
        identity_status=IdentityStatus.UNKNOWN,
    )
    policy = EffectPolicy(protected_roots=(protected,))

    interactive = authorize_effect(_request(EffectKind.WRITE, target=unknown), policy)
    unattended = authorize_effect(
        _request(EffectKind.WRITE, target=unknown, unattended=True, bypass_requested=True), policy
    )

    assert interactive.decision is PolicyDecision.REQUIRE_HUMAN_APPROVAL
    assert interactive.non_bypassable is True
    assert unattended.decision is PolicyDecision.DENY
    assert unattended.non_bypassable is True


def test_repository_policy_binds_common_git_identity_not_basename():
    protected_repo = RepositoryIdentity(
        worktree_root="C:/one/repo",
        common_dir="C:/git/storage/repo.git",
    )
    same_repo_other_worktree = RepositoryIdentity(
        worktree_root="D:/worktrees/task",
        common_dir="C:/git/storage/repo.git",
    )
    same_basename_different_repo = RepositoryIdentity(
        worktree_root="D:/other/repo",
        common_dir="D:/other/repo/.git",
    )
    policy = EffectPolicy(protected_repositories=(protected_repo,))
    base = EffectRequest(
        actor="coder",
        profile="coder",
        session_mode="interactive",
        execution_mode="normal",
        effect=EffectKind.UPDATE_REF,
        resource=ResourceKind.GIT_REPOSITORY,
        target=_target("D:/worktrees/task", repository=same_repo_other_worktree),
        mutability=Mutability.MUTATING,
        carrier="git",
    )

    same = authorize_effect(base, policy)
    different = authorize_effect(
        replace(base, target=_target("D:/other/repo", repository=same_basename_different_repo)), policy
    )

    assert same.decision is PolicyDecision.DENY
    assert different.decision is PolicyDecision.ALLOW


def test_move_and_copy_evaluate_source_and_destination_semantics():
    protected = _target("C:/protected/repo")
    policy = EffectPolicy(protected_roots=(protected,))
    inside = _target("C:/protected/repo/tracked.txt")
    outside = _target("C:/scratch/tracked.txt")

    move_out = authorize_effect(_request(EffectKind.MOVE, source=inside, destination=outside), policy)
    move_in = authorize_effect(_request(EffectKind.MOVE, source=outside, destination=inside), policy)
    copy_out = authorize_effect(_request(EffectKind.COPY, source=inside, destination=outside), policy)
    copy_in = authorize_effect(_request(EffectKind.COPY, source=outside, destination=inside), policy)

    assert move_out.decision is PolicyDecision.DENY
    assert move_in.decision is PolicyDecision.DENY
    assert copy_out.decision is PolicyDecision.ALLOW
    assert copy_in.decision is PolicyDecision.DENY


@pytest.mark.parametrize("effect", [EffectKind.CREATE_SYMLINK, EffectKind.CREATE_JUNCTION])
def test_link_creation_protects_the_destination_not_only_a_generic_target(effect):
    protected = _target("C:/protected/repo")
    request = _request(
        effect,
        source=_target("C:/scratch/source"),
        destination=_target("C:/protected/repo/link"),
        bypass_requested=True,
    )

    result = authorize_effect(request, EffectPolicy(protected_roots=(protected,)))

    assert result.decision is PolicyDecision.DENY
    assert result.non_bypassable is True


def test_resolved_redirection_to_protected_target_is_denied():
    protected = _target("C:/protected/repo")
    redirected = CanonicalTarget(
        raw="C:/scratch/innocent.txt",
        absolute="C:/scratch/innocent.txt",
        canonical="C:/protected/repo/AGENTS.md",
        identity_status=IdentityStatus.PROVEN,
    )

    result = authorize_effect(
        _request(EffectKind.REPLACE, target=redirected),
        EffectPolicy(protected_roots=(protected,)),
    )

    assert result.decision is PolicyDecision.DENY


def test_invalid_policy_denies_mutation_but_preserves_read_only_access():
    policy = EffectPolicy(valid=False, error="malformed protected root")
    write = _request(EffectKind.WRITE, target=_target("C:/scratch/file.txt"))
    read = replace(write, effect=EffectKind.READ, mutability=Mutability.READ_ONLY)

    assert authorize_effect(read, policy).decision is PolicyDecision.ALLOW
    assert authorize_effect(write, policy).decision is PolicyDecision.DENY


@pytest.mark.parametrize(
    "effect",
    [
        EffectKind.CREATE,
        EffectKind.WRITE,
        EffectKind.APPEND,
        EffectKind.TRUNCATE,
        EffectKind.REPLACE,
        EffectKind.MOVE,
        EffectKind.RENAME,
        EffectKind.DELETE,
        EffectKind.CREATE_DIRECTORY,
        EffectKind.CREATE_SYMLINK,
        EffectKind.CREATE_JUNCTION,
    ],
)
def test_every_filesystem_mutation_is_denied_for_a_protected_identity(effect):
    protected = _target("C:/protected/repo")
    request = _request(
        effect=effect,
        target=_target("C:/protected/repo/nested/target"),
        bypass_requested=True,
    )

    result = authorize_effect(request, EffectPolicy(protected_roots=(protected,)))

    assert result.decision is PolicyDecision.DENY
    assert result.non_bypassable is True


@pytest.mark.parametrize(
    "effect",
    [
        EffectKind.CONFIG_WRITE,
        EffectKind.APPROVAL_POLICY_CHANGE,
        EffectKind.YOLO_OR_BYPASS_ENABLE,
        EffectKind.SKILL_CHANGE,
        EffectKind.MEMORY_CHANGE,
        EffectKind.MCP_CONFIGURATION_CHANGE,
        EffectKind.UPDATE_REF,
        EffectKind.WORKTREE_REMOVE,
        EffectKind.RESET,
        EffectKind.AWS_MUTATE,
        EffectKind.GITHUB_MUTATE,
        EffectKind.NETWORK_WRITE,
    ],
)
def test_high_risk_semantic_denies_ignore_execution_mode_and_yolo(effect):
    policy = EffectPolicy(denied_effects=frozenset({effect}))
    request = replace(
        _request(effect=effect, target=None, bypass_requested=True, unattended=True),
        resource=ResourceKind.UNKNOWN,
    )

    assert authorize_effect(request, policy).decision is PolicyDecision.DENY


def test_windows_extended_and_case_variant_paths_match_the_same_root():
    protected = _target(r"C:\Users\Brand\ProtectedRepo")
    alternate = CanonicalTarget(
        raw=r"\\?\C:\USERS\BRAND\PROTECTEDREPO\nested\file.txt",
        absolute=r"\\?\C:\USERS\BRAND\PROTECTEDREPO\nested\file.txt",
        canonical=r"\\?\C:\USERS\BRAND\PROTECTEDREPO\nested\file.txt",
        identity_status=IdentityStatus.PROVEN,
    )

    result = authorize_effect(
        _request(effect=EffectKind.REPLACE, target=alternate),
        EffectPolicy(protected_roots=(protected,)),
    )

    assert result.decision is PolicyDecision.DENY


def test_delegated_parent_metadata_cannot_change_a_semantic_deny():
    effect = EffectKind.UPDATE_REF
    policy = EffectPolicy(denied_effects=frozenset({effect}))
    parent = replace(_request(effect=effect, target=None, bypass_requested=True), parent_operation=None)
    child = replace(parent, parent_operation="delegate_task:parent-call")

    assert authorize_effect(parent, policy) == authorize_effect(child, policy)


@pytest.mark.macos_only
def test_macos_case_alias_cannot_escape_protected_root():
    protected = _target("/Users/Operator/Protected")
    aliased = _target("/users/operator/protected/subtree/file.txt")

    result = authorize_effect(
        _request(effect=EffectKind.WRITE, target=aliased),
        EffectPolicy(protected_roots=(protected,)),
    )

    assert result.decision is PolicyDecision.DENY
