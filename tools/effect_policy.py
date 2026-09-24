"""Canonical semantic effect-policy types and deny-first evaluator.

This module is deliberately independent of command spelling.  Carriers translate an
operation into :class:`EffectRequest`; policy decisions depend on the effect, resource,
and resolved target identity.  Enforcement adapters live beside the carrier so this
module remains a small, deterministic security boundary.
"""

from __future__ import annotations

import ntpath
import os
import posixpath
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class EffectKind(str, Enum):
    # Filesystem.
    READ = "read"
    CREATE = "create"
    WRITE = "write"
    APPEND = "append"
    TRUNCATE = "truncate"
    REPLACE = "replace"
    COPY = "copy"
    MOVE = "move"
    RENAME = "rename"
    DELETE = "delete"
    CREATE_DIRECTORY = "create_directory"
    DELETE_DIRECTORY = "delete_directory"
    CREATE_SYMLINK = "create_symlink"
    CREATE_JUNCTION = "create_junction"
    SYMLINK_OR_REPARSE_CREATE = "symlink_or_reparse_create"
    PERMISSION_OR_ACL_CHANGE = "permission_or_acl_change"

    # Git.
    READ_REPOSITORY = "read_repository"
    WRITE_WORKTREE = "write_worktree"
    WRITE_INDEX = "write_index"
    CREATE_COMMIT = "create_commit"
    CREATE_REF = "create_ref"
    UPDATE_REF = "update_ref"
    DELETE_REF = "delete_ref"
    PUSH = "push"
    FORCE_PUSH = "force_push"
    FETCH = "fetch"
    RESET = "reset"
    CLEAN = "clean"
    WORKTREE_ADD = "worktree_add"
    WORKTREE_REMOVE = "worktree_remove"
    WORKTREE_PRUNE = "worktree_prune"

    # Process and Hermes control state.
    PROCESS_EXECUTE = "process_execute"
    CONFIG_READ = "config_read"
    CONFIG_WRITE = "config_write"
    APPROVAL_POLICY_CHANGE = "approval_policy_change"
    YOLO_OR_BYPASS_ENABLE = "yolo_or_bypass_enable"
    SKILL_CHANGE = "skill_change"
    MEMORY_CHANGE = "memory_change"
    MCP_CONFIGURATION_CHANGE = "mcp_configuration_change"
    COMPUTER_CONTROL = "computer_control"

    # External systems.
    AWS_READ = "aws_read"
    AWS_MUTATE = "aws_mutate"
    GITHUB_READ = "github_read"
    GITHUB_MUTATE = "github_mutate"
    MCP_READ = "mcp_read"
    MCP_MUTATE = "mcp_mutate"
    NETWORK_READ = "network_read"
    NETWORK_WRITE = "network_write"


class ResourceKind(str, Enum):
    FILESYSTEM = "filesystem"
    GIT_REPOSITORY = "git_repository"
    GIT_REF = "git_ref"
    PROCESS = "process"
    HERMES_CONFIG = "hermes_config"
    APPROVAL_POLICY = "approval_policy"
    SKILL = "skill"
    MEMORY = "memory"
    MCP = "mcp"
    AWS = "aws"
    GITHUB = "github"
    NETWORK = "network"
    COMPUTER = "computer"
    UNKNOWN = "unknown"


class Mutability(str, Enum):
    READ_ONLY = "read_only"
    MUTATING = "mutating"
    UNKNOWN = "unknown"


class EffectClassification(str, Enum):
    """Security classification attached to bounded semantic requests."""

    PRIVILEGED_OR_SECURITY_SENSITIVE = "privileged_or_security_sensitive"
    READ_ONLY_COMPATIBILITY = "read_only_compatibility"


class EffectMode(str, Enum):
    """How a registry registration declares semantic effects."""

    READ_ONLY = "read_only"
    STATIC = "static"
    CONDITIONAL = "conditional"
    OPAQUE = "opaque"


HOST_READ_ONLY_TOOL_NAMES = frozenset({
    "browser_vault_list",
    "feishu_doc_read",
    "read_terminal",
    "read_window_below",
    "session_search",
    "skill_view",
    "skills_list",
    "tool_describe",
    "tool_search",
})


@dataclass(frozen=True, slots=True)
class EffectTemplate:
    """Registration-owned effect independent of request targets."""

    effect: EffectKind
    resource: ResourceKind
    mutability: Mutability
    classification: EffectClassification | None = None


@dataclass(frozen=True, slots=True)
class EffectDescriptor:
    """Immutable security metadata bound to a tool registration.

    ``READ_ONLY`` is an explicit positive declaration. ``STATIC`` emits the
    supplied templates. ``CONDITIONAL`` invokes one host-owned resolver by key.
    ``OPAQUE`` represents authority whose eventual effects cannot be proven in
    process. Remote/plugin payloads may provide data, but never executable
    resolver callbacks.
    """

    mode: EffectMode
    effects: tuple[EffectTemplate, ...] = ()
    resolver_key: str | None = None
    version: int = 1

    @classmethod
    def static(cls, *effects: EffectTemplate) -> "EffectDescriptor":
        """Build a static descriptor while preserving tuple immutability."""
        return cls(mode=EffectMode.STATIC, effects=tuple(effects))

    def __post_init__(self) -> None:
        if not isinstance(self.mode, EffectMode):
            raise TypeError("effect descriptor mode must be an EffectMode")
        if not isinstance(self.effects, tuple):
            raise TypeError("effect descriptor effects must be an immutable tuple")
        if any(not isinstance(effect, EffectTemplate) for effect in self.effects):
            raise TypeError("effect descriptor effects must contain EffectTemplate values")
        if self.version != 1:
            raise ValueError("unsupported effect descriptor version")
        if self.mode is EffectMode.STATIC:
            if not self.effects:
                raise ValueError("static effect descriptors require at least one effect")
            if self.resolver_key is not None:
                raise ValueError("static effect descriptors cannot name a resolver")
        elif self.mode is EffectMode.CONDITIONAL:
            if not isinstance(self.resolver_key, str) or not self.resolver_key.strip():
                raise ValueError("conditional effect descriptors require a resolver key")
            if self.effects:
                raise ValueError("conditional effect descriptors cannot contain static effects")
        elif self.effects or self.resolver_key is not None:
            raise ValueError(f"{self.mode.value} effect descriptors cannot contain resolver metadata")


class IdentityStatus(str, Enum):
    PROVEN = "proven"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    REQUIRE_HUMAN_APPROVAL = "require_human_approval"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class RepositoryIdentity:
    """Stable repository identity plus the worktree that exposed it.

    ``common_dir`` is the identity key.  Separate linked worktrees therefore bind to
    one repository while unrelated repositories with the same basename do not.
    """

    worktree_root: str
    common_dir: str


@dataclass(frozen=True, slots=True)
class CanonicalTarget:
    raw: str
    absolute: str | None
    canonical: str | None
    identity_status: IdentityStatus
    repository: RepositoryIdentity | None = None
    repository_identity_status: IdentityStatus = IdentityStatus.UNKNOWN


@dataclass(frozen=True, slots=True)
class EffectRequest:
    actor: str
    profile: str
    session_mode: str
    execution_mode: str
    effect: EffectKind
    resource: ResourceKind
    mutability: Mutability
    carrier: str
    classification: EffectClassification | None = None
    target: CanonicalTarget | None = None
    source: CanonicalTarget | None = None
    destination: CanonicalTarget | None = None
    parent_operation: str | None = None
    unattended: bool = False
    bypass_requested: bool = False


@dataclass(frozen=True, slots=True)
class EffectPolicy:
    protected_roots: tuple[CanonicalTarget, ...] = ()
    protected_repositories: tuple[RepositoryIdentity, ...] = ()
    denied_effects: frozenset[EffectKind] = frozenset()
    approval_required_effects: frozenset[EffectKind] = frozenset()
    valid: bool = True
    error: str | None = None


@dataclass(frozen=True, slots=True)
class PolicyResult:
    decision: PolicyDecision
    reason: str
    non_bypassable: bool = False
    matched_target: CanonicalTarget | None = None


_MUTATES_SOURCE = frozenset({
    EffectKind.DELETE,
    EffectKind.RENAME,
    EffectKind.MOVE,
    EffectKind.DELETE_DIRECTORY,
    EffectKind.PERMISSION_OR_ACL_CHANGE,
})
_MUTATES_DESTINATION = frozenset({
    EffectKind.CREATE,
    EffectKind.WRITE,
    EffectKind.APPEND,
    EffectKind.REPLACE,
    EffectKind.RENAME,
    EffectKind.MOVE,
    EffectKind.COPY,
    EffectKind.CREATE_DIRECTORY,
    EffectKind.CREATE_SYMLINK,
    EffectKind.CREATE_JUNCTION,
    EffectKind.SYMLINK_OR_REPARSE_CREATE,
    EffectKind.PERMISSION_OR_ACL_CHANGE,
})


def _looks_windows_path(path: str) -> bool:
    value = str(path)
    return (
        os.name == "nt"
        or bool(ntpath.splitdrive(value)[0])
        or value.startswith(("\\\\", "//", "\\\\?\\"))
    )


def _path_key(path: str) -> str:
    """Comparison key preserving Windows drive/UNC identity on every host."""
    value = str(path)
    if _looks_windows_path(value):
        value = value.replace("/", "\\")
        if value.lower().startswith("\\\\?\\unc\\"):
            value = "\\\\" + value[8:]
        elif value.startswith("\\\\?\\"):
            value = value[4:]
        return ntpath.normcase(ntpath.normpath(value)).rstrip("\\")
    normalized = posixpath.normpath(value).rstrip("/") or "/"
    # Default macOS filesystems are case-insensitive. Conservatively folding on
    # every macOS volume may over-protect a case-sensitive volume, but avoids a
    # case-alias bypass on the overwhelmingly common APFS/HFS+ configuration.
    return normalized.casefold() if sys.platform == "darwin" else normalized


def _same_or_descendant(path: str, root: str) -> bool:
    path_key, root_key = _path_key(path), _path_key(root)
    if path_key == root_key:
        return True
    separator = "\\" if _looks_windows_path(root_key) else "/"
    return path_key.startswith(root_key.rstrip("\\/") + separator)


def _repository_matches(left: RepositoryIdentity, right: RepositoryIdentity) -> bool:
    return _path_key(left.common_dir) == _path_key(right.common_dir)


def _target_paths(target: CanonicalTarget) -> tuple[str, ...]:
    """Both identities matter: raw absolute catches unresolved traversal, canonical catches redirection."""
    return tuple(dict.fromkeys(p for p in (target.absolute, target.canonical) if p))


def _protected_match(
    target: CanonicalTarget,
    policy: EffectPolicy,
) -> CanonicalTarget | None:
    if target.repository is not None:
        for protected_repo in policy.protected_repositories:
            if _repository_matches(target.repository, protected_repo):
                return target
    # Git cannot discover repository identity by running from inside its own
    # common metadata directory. Match that directory explicitly so refs,
    # config, objects, and linked-worktree metadata remain repository-protected.
    for candidate in _target_paths(target):
        for protected_repo in policy.protected_repositories:
            if _same_or_descendant(candidate, protected_repo.common_dir):
                return target
    for candidate in _target_paths(target):
        for root in policy.protected_roots:
            for protected_path in _target_paths(root):
                if _same_or_descendant(candidate, protected_path):
                    return target
    return None


def _affected_targets(request: EffectRequest) -> Iterable[tuple[CanonicalTarget, bool]]:
    """Yield ``(target, mutates_target)`` for every side of an operation."""
    if request.source is not None:
        yield request.source, request.effect in _MUTATES_SOURCE
    if request.destination is not None:
        yield request.destination, request.effect in _MUTATES_DESTINATION
    if request.target is not None:
        yield request.target, request.mutability is not Mutability.READ_ONLY


def _unknown_identity_result(request: EffectRequest, reason: str) -> PolicyResult:
    # A non-interactive context cannot supply the explicit human authorization
    # required by an indeterminate protected mutation.
    decision = PolicyDecision.DENY if request.unattended else PolicyDecision.REQUIRE_HUMAN_APPROVAL
    return PolicyResult(decision, reason, non_bypassable=True)


def authorize_effect(request: EffectRequest, policy: EffectPolicy) -> PolicyResult:
    """Evaluate one semantic effect with unconditional deny precedence.

    Carrier and bypass fields are audit provenance only for hard denies and
    indeterminate protected targets.  They can never turn either decision into
    ``ALLOW``.
    """
    if not policy.valid:
        if request.mutability is Mutability.READ_ONLY:
            return PolicyResult(PolicyDecision.ALLOW, "read-only effect allowed while policy is invalid")
        return PolicyResult(
            PolicyDecision.DENY,
            f"effect policy is invalid: {policy.error or 'unknown policy error'}",
            non_bypassable=True,
        )

    if request.effect in policy.denied_effects:
        return PolicyResult(
            PolicyDecision.DENY,
            f"effect {request.effect.value} is explicitly denied",
            non_bypassable=True,
        )

    affected = tuple(_affected_targets(request))
    for target, mutates_target in affected:
        if not mutates_target:
            continue
        matched = _protected_match(target, policy)
        if matched is not None:
            return PolicyResult(
                PolicyDecision.DENY,
                f"{request.effect.value} would mutate a protected resource",
                non_bypassable=True,
                matched_target=matched,
            )

    filesystem_resources = {
        ResourceKind.FILESYSTEM,
        ResourceKind.HERMES_CONFIG,
        ResourceKind.APPROVAL_POLICY,
        ResourceKind.GIT_REPOSITORY,
        ResourceKind.GIT_REF,
    }
    filesystem_rule_relevant = (
        request.resource in filesystem_resources
        or (request.resource is ResourceKind.PROCESS and request.mutability is Mutability.UNKNOWN)
    )
    protected_policy_active = bool(
        filesystem_rule_relevant
        and (policy.protected_roots or policy.protected_repositories)
    )
    if protected_policy_active and request.mutability is not Mutability.READ_ONLY:
        for target, mutates_target in affected:
            if mutates_target and target.identity_status is not IdentityStatus.PROVEN:
                # Lexical containment is already checked above.  An unproven identity
                # cannot safely establish that redirection escapes a protected root.
                return _unknown_identity_result(
                    request,
                    f"cannot prove target identity for {request.effect.value}",
                )
        if request.resource in {ResourceKind.GIT_REPOSITORY, ResourceKind.GIT_REF}:
            repository_known = any(
                target.repository is not None for target, mutates_target in affected if mutates_target
            )
            if policy.protected_repositories and not repository_known:
                return _unknown_identity_result(request, "cannot prove repository identity")
        if policy.protected_repositories and request.resource in filesystem_resources:
            repository_unknown = any(
                mutates_target
                and target.repository is None
                and target.repository_identity_status is IdentityStatus.UNKNOWN
                for target, mutates_target in affected
            )
            if repository_unknown:
                return _unknown_identity_result(request, "cannot prove repository identity")
        if request.mutability is Mutability.UNKNOWN or not affected:
            return _unknown_identity_result(
                request,
                "mutation authority could reach a protected resource but no target identity is available",
            )

    if request.effect in policy.approval_required_effects:
        if request.bypass_requested:
            return PolicyResult(PolicyDecision.ALLOW, "ordinary approval bypass is active")
        if request.unattended:
            return PolicyResult(PolicyDecision.DENY, "approval-required effect is unattended")
        target = next((target for target, _mutates in affected), None)
        target_text = ""
        if target is not None:
            display = target.canonical or target.absolute or target.raw
            target_text = f" for {display}" if display else ""
        return PolicyResult(
            PolicyDecision.REQUIRE_APPROVAL,
            f"effect {request.effect.value} requires approval{target_text}",
            matched_target=target,
        )

    return PolicyResult(PolicyDecision.ALLOW, "no effect-policy rule matched")
