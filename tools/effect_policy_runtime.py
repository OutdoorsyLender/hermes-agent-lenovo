"""Runtime resolution and carrier adapters for :mod:`tools.effect_policy`.

Only adapters listed here are migrated.  An absent adapter is intentionally not
presented as unified enforcement; callers can enumerate ``MIGRATED_TOOL_EFFECTS``
when reporting coverage.
"""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import json
import math
import os
import stat
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Mapping, cast

from tools.effect_policy import (
    CanonicalTarget,
    EffectKind,
    EffectPolicy,
    EffectRequest,
    IdentityStatus,
    Mutability,
    PolicyDecision,
    PolicyResult,
    RepositoryIdentity,
    ResourceKind,
    authorize_effect,
)


@dataclass(frozen=True, slots=True)
class EffectContext:
    actor: str
    profile: str
    session_mode: str
    execution_mode: str
    unattended: bool = False
    bypass_requested: bool = False
    parent_operation: str | None = None


TargetResolver = Callable[[str], CanonicalTarget]


@dataclass(frozen=True, slots=True)
class _EffectPermitRecord:
    attempt_id: str
    tool_name: str
    args_digest: str
    task_id: str
    tool_call_id: str | None
    authorization_fingerprint: str


@dataclass(frozen=True, slots=True)
class _EffectPermitHandle:
    """Opaque handle whose id is useful only while held by the issuer registry."""

    attempt_id: str


_current_effect_attempt: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "current_effect_attempt",
    default=None,
)
_effect_permits: dict[str, _EffectPermitRecord] = {}
_effect_permits_lock = threading.Lock()


def _validate_json_value(value: object) -> None:
    """Reject argument shapes whose distinct values JSON could collapse."""
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("effect permit arguments must contain finite JSON numbers")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item)
        return
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("effect permit argument object keys must be strings")
        for item in value.values():
            _validate_json_value(item)
        return
    raise TypeError(f"effect permit arguments contain unsupported {type(value).__qualname__}")


def _args_digest(args: dict) -> str:
    _validate_json_value(args)
    encoded = json.dumps(
        args,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _effective_task_id(task_id: str | None) -> str:
    return str(task_id or "default")


def _policy_fingerprint(policy: EffectPolicy) -> str:
    def target_value(target: CanonicalTarget) -> dict[str, object]:
        repository = target.repository
        return {
            "raw": target.raw,
            "absolute": target.absolute,
            "canonical": target.canonical,
            "identity_status": target.identity_status.value,
            "repository_identity_status": target.repository_identity_status.value,
            "repository": None
            if repository is None
            else {"worktree_root": repository.worktree_root, "common_dir": repository.common_dir},
        }

    encoded = json.dumps(
        {
            "valid": policy.valid,
            "error": policy.error,
            "protected_roots": [target_value(target) for target in policy.protected_roots],
            "protected_repositories": [
                {"worktree_root": repo.worktree_root, "common_dir": repo.common_dir}
                for repo in policy.protected_repositories
            ],
            "denied_effects": sorted(effect.value for effect in policy.denied_effects),
            "approval_required_effects": sorted(
                effect.value for effect in policy.approval_required_effects
            ),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _authorization_fingerprint(policy: EffectPolicy, context: EffectContext) -> str:
    encoded = json.dumps(
        {
            "policy": _policy_fingerprint(policy),
            "actor": context.actor,
            "profile": context.profile,
            "session_mode": context.session_mode,
            "execution_mode": context.execution_mode,
            "unattended": context.unattended,
            "bypass_requested": context.bypass_requested,
            "parent_operation": context.parent_operation,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def authorize_and_issue_effect_permit(
    tool_name: str,
    args: dict,
    *,
    task_id: str | None = None,
    tool_call_id: str | None = None,
) -> tuple[PolicyResult, _EffectPermitHandle | None]:
    """Enforce the live policy, then issue one registry-backed dispatch permit.

    Deliberately no ``policy`` parameter exists: callers cannot mint by supplying
    an empty policy. Unit-level policy injection remains on :func:`enforce_tool_call`,
    which never issues a permit.
    """
    live_policy = load_effect_policy()
    live_context = current_effect_context()
    result = enforce_tool_call(
        tool_name,
        args,
        task_id=_effective_task_id(task_id),
        context=live_context,
        policy=live_policy,
    )
    if result.decision is not PolicyDecision.ALLOW:
        return result, None
    try:
        args_digest = _args_digest(args)
    except (TypeError, ValueError):
        # Re-authorize at the inner seam rather than trusting an incomplete or
        # collision-prone identity for a non-JSON argument.
        return result, None
    record = _EffectPermitRecord(
        attempt_id=uuid.uuid4().hex,
        tool_name=tool_name,
        args_digest=args_digest,
        task_id=_effective_task_id(task_id),
        tool_call_id=tool_call_id,
        authorization_fingerprint=_authorization_fingerprint(live_policy, live_context),
    )
    with _effect_permits_lock:
        _effect_permits[record.attempt_id] = record
    return result, _EffectPermitHandle(record.attempt_id)


def revoke_effect_permit(handle: _EffectPermitHandle | None) -> None:
    if not isinstance(handle, _EffectPermitHandle):
        return
    with _effect_permits_lock:
        _effect_permits.pop(handle.attempt_id, None)


@contextlib.contextmanager
def bind_issued_effect_permit(handle: _EffectPermitHandle | None):
    """Bind an issuer handle for the immediate nested dispatch and revoke on exit."""
    attempt_id = handle.attempt_id if isinstance(handle, _EffectPermitHandle) else ""
    token = _current_effect_attempt.set(attempt_id)
    try:
        yield
    finally:
        _current_effect_attempt.reset(token)
        revoke_effect_permit(handle)


def consume_effect_permit(
    tool_name: str,
    args: dict,
    *,
    task_id: str | None = None,
    tool_call_id: str | None = None,
) -> _EffectPermitRecord | None:
    """Atomically consume and validate an issuer-backed one-shot permit."""
    attempt_id = _current_effect_attempt.get()
    if not attempt_id:
        return None
    _current_effect_attempt.set(None)
    try:
        args_digest = _args_digest(args)
    except (TypeError, ValueError):
        with _effect_permits_lock:
            _effect_permits.pop(attempt_id, None)
        return None
    effective_task_id = _effective_task_id(task_id)
    live_authorization_fingerprint = _authorization_fingerprint(
        load_effect_policy(),
        current_effect_context(),
    )
    with _effect_permits_lock:
        permit = _effect_permits.get(attempt_id)
        if (
            permit is None
            or permit.attempt_id != attempt_id
            or permit.tool_name != tool_name
            or permit.args_digest != args_digest
            or permit.task_id != effective_task_id
            or permit.tool_call_id != tool_call_id
            or permit.authorization_fingerprint != live_authorization_fingerprint
        ):
            _effect_permits.pop(attempt_id, None)
            return None
        return _effect_permits.pop(attempt_id)


def _normal_path(path: str) -> str:
    normalized = os.path.normcase(os.path.normpath(path))
    if sys.platform == "win32":
        if normalized.startswith("\\\\?\\unc\\"):
            normalized = "\\\\" + normalized[8:]
        elif normalized.startswith("\\\\?\\"):
            normalized = normalized[4:]
        normalized = os.path.normcase(os.path.normpath(normalized))
    return normalized.casefold() if sys.platform == "darwin" else normalized


def _repository_identity_probe(path: str) -> tuple[RepositoryIdentity | None, IdentityStatus]:
    """Resolve Git identity and distinguish absence from lookup failure."""
    probe = Path(path)
    if not probe.is_dir():
        probe = probe.parent
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    if not probe.exists():
        return None, IdentityStatus.UNKNOWN
    command = [
        "git",
        "-C",
        str(probe),
        "rev-parse",
        "--path-format=absolute",
        "--show-toplevel",
        "--git-common-dir",
    ]

    def run_git(argv):
        return subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )

    legacy_paths = False
    try:
        completed = run_git(command)
        legacy_path_token = any(
            line.strip() == "--path-format=absolute" for line in completed.stdout.splitlines()
        )
        if (
            completed.returncode != 0 and "path-format" in completed.stderr.lower()
        ) or legacy_path_token:
            legacy_paths = True
            completed = run_git([part for part in command if part != "--path-format=absolute"])
    except (OSError, subprocess.SubprocessError):
        return None, IdentityStatus.UNKNOWN
    if completed.returncode != 0:
        if "not a git repository" in completed.stderr.lower():
            return None, IdentityStatus.NOT_APPLICABLE
        return None, IdentityStatus.UNKNOWN
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    if len(lines) != 2:
        return None, IdentityStatus.UNKNOWN
    common_dir = Path(lines[1])
    if legacy_paths and not common_dir.is_absolute():
        common_dir = (probe / common_dir).resolve(strict=False)
    return (
        RepositoryIdentity(
            worktree_root=_normal_path(lines[0]),
            common_dir=_normal_path(str(common_dir)),
        ),
        IdentityStatus.PROVEN,
    )


def repository_identity_for_path(path: str) -> RepositoryIdentity | None:
    """Resolve Git common-dir identity without relying on the caller's cwd."""
    return _repository_identity_probe(path)[0]


def canonicalize_target(raw: str, *, cwd: str | None = None) -> CanonicalTarget:
    """Resolve lexical, real/canonical, and repository identities for one path.

    ``Path.resolve(strict=False)`` follows existing symlink/junction/reparse
    components while retaining a usable identity for a not-yet-created leaf.
    Any resolution error is represented explicitly rather than guessed.
    """
    text = str(raw)
    try:
        expanded = Path(text).expanduser()
        if not expanded.is_absolute():
            expanded = Path(cwd or os.getcwd()) / expanded
        absolute = str(expanded.absolute())
        canonical = str(expanded.resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        return CanonicalTarget(
            raw=text,
            absolute=None,
            canonical=None,
            identity_status=IdentityStatus.UNKNOWN,
        )
    repository, repository_status = _repository_identity_probe(canonical)
    return CanonicalTarget(
        raw=text,
        absolute=absolute,
        canonical=canonical,
        identity_status=IdentityStatus.PROVEN,
        repository=repository,
        repository_identity_status=repository_status,
    )


def _task_target_resolver(task_id: str | None) -> TargetResolver:
    task_id = _effective_task_id(task_id)

    def _resolve(raw: str) -> CanonicalTarget:
        try:
            from tools.file_tools_paths import _resolve_path_for_task

            resolved = _resolve_path_for_task(raw, task_id)
        except Exception:
            return CanonicalTarget(
                raw=raw,
                absolute=None,
                canonical=None,
                identity_status=IdentityStatus.UNKNOWN,
            )
        return canonicalize_target(str(resolved))

    return _resolve


def current_effect_context() -> EffectContext:
    """Snapshot profile/session execution state for one policy request."""
    try:
        from hermes_constants import get_hermes_home, hermes_home_key

        home = Path(get_hermes_home())
        profile = home.name if home.parent.name.lower() == "profiles" else "default"
        actor = hermes_home_key()
    except Exception:
        actor = profile = "unknown"
    try:
        from tools import approval_context

        cron = approval_context._is_cron_approval_context()
        single = approval_context._is_single_query_approval_context()
        unattended_platform = approval_context._is_unattended_platform_approval_context()
        platform = approval_context._get_session_platform() or "cli"
    except Exception:
        cron = single = unattended_platform = False
        platform = "unknown"
    if cron:
        session_mode = "cron"
    elif single:
        session_mode = "single_query"
    elif unattended_platform:
        session_mode = "unattended"
    else:
        session_mode = platform
    try:
        from tools.approval import is_approval_bypass_active

        bypass = bool(is_approval_bypass_active())
    except Exception:
        bypass = False
    return EffectContext(
        actor=str(actor),
        profile=str(profile),
        session_mode=session_mode,
        execution_mode=platform,
        unattended=bool(cron or single or unattended_platform),
        bypass_requested=bypass,
    )


def _parse_effects(values: object, field: str) -> frozenset[EffectKind]:
    if not isinstance(values, list):
        raise ValueError(f"security.effect_policy.{field} must be a list")
    try:
        return frozenset(EffectKind(str(value).strip().lower()) for value in values)
    except ValueError as exc:
        raise ValueError(f"security.effect_policy.{field} contains an unknown effect") from exc


def _parse_protected_roots(values: object) -> tuple[CanonicalTarget, ...]:
    if not isinstance(values, list) or any(
        not isinstance(path, str) or not path.strip() for path in values
    ):
        raise ValueError("security.effect_policy.protected_roots must be a list of non-empty paths")
    root_paths = cast(list[str], values)
    if any(not Path(path).expanduser().is_absolute() for path in root_paths):
        raise ValueError("security.effect_policy.protected_roots entries must be absolute paths")
    roots = tuple(canonicalize_target(path) for path in root_paths)
    if any(root.identity_status is not IdentityStatus.PROVEN for root in roots):
        raise ValueError("a protected root could not be resolved")
    return roots


_EFFECT_POLICY_KEYS = frozenset({"protected_roots", "deny_effects", "require_approval_effects"})


def _validate_effect_policy_node(config: object, *, explicit: bool) -> Mapping[str, object]:
    """Validate one config layer before defaults can hide malformed explicit values."""
    if not isinstance(config, dict):
        if explicit:
            raise ValueError("config must be a mapping")
        return {}
    config_map = cast(Mapping[str, object], config)
    if "security" not in config_map:
        return {}
    security = config_map["security"]
    if not isinstance(security, dict):
        raise ValueError("security must be a mapping")
    security_map = cast(Mapping[str, object], security)
    if "effect_policy" not in security_map:
        return {}
    raw = security_map["effect_policy"]
    if not isinstance(raw, dict):
        raise ValueError("security.effect_policy must be a mapping")
    raw_map = cast(Mapping[str, object], raw)
    unknown = sorted(set(raw_map) - _EFFECT_POLICY_KEYS)
    if unknown:
        raise ValueError(f"security.effect_policy contains unknown keys: {', '.join(unknown)}")
    return raw_map


def _validate_effect_policy_fields(raw: Mapping[str, object]) -> None:
    """Validate every field explicitly present in one unmerged layer."""
    if "protected_roots" in raw:
        _parse_protected_roots(raw["protected_roots"])
    if "deny_effects" in raw:
        _parse_effects(raw["deny_effects"], "deny_effects")
    if "require_approval_effects" in raw:
        _parse_effects(raw["require_approval_effects"], "require_approval_effects")


def _read_managed_config_raw() -> Mapping[str, object]:
    """Read the managed overlay without its fail-open normalization."""
    from hermes_cli import managed_scope

    managed_dir = managed_scope.get_managed_dir()
    if managed_dir is None:
        return {}
    path = managed_dir / "config.yaml"
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    if not text.strip():
        return {}
    import yaml

    parsed = yaml.safe_load(text)
    if not isinstance(parsed, dict):
        raise ValueError("managed config.yaml must be a mapping")
    return cast(Mapping[str, object], parsed)


def load_effect_policy() -> EffectPolicy:
    """Load the active profile's semantic policy; malformed policy fails closed."""
    try:
        from hermes_cli.config import (
            get_active_config_parse_failure,
            load_config_readonly,
            read_raw_config_readonly,
        )

        config = load_config_readonly() or {}
        parse_failure = get_active_config_parse_failure()
        if parse_failure:
            raise ValueError(f"active config.yaml cannot be parsed: {parse_failure}")
        explicit_config = read_raw_config_readonly()
        parse_failure = get_active_config_parse_failure()
        if parse_failure:
            raise ValueError(f"active config.yaml cannot be parsed: {parse_failure}")
        explicit_raw = _validate_effect_policy_node(explicit_config, explicit=True)
        managed_raw = _validate_effect_policy_node(_read_managed_config_raw(), explicit=True)
        _validate_effect_policy_fields(explicit_raw)
        _validate_effect_policy_fields(managed_raw)
        raw = _validate_effect_policy_node(config, explicit=False)
        roots = _parse_protected_roots(raw.get("protected_roots", []))
        repositories = tuple(dict.fromkeys(
            root.repository
            for root in roots
            if (
                root.repository is not None
                and root.canonical is not None
                and _normal_path(root.canonical) == _normal_path(root.repository.worktree_root)
            )
        ))
        return EffectPolicy(
            protected_roots=roots,
            protected_repositories=repositories,
            denied_effects=_parse_effects(raw.get("deny_effects", []), "deny_effects"),
            approval_required_effects=_parse_effects(
                raw.get("require_approval_effects", []), "require_approval_effects"
            ),
        )
    except Exception as exc:
        return EffectPolicy(valid=False, error=str(exc))


def _request(
    context: EffectContext,
    effect: EffectKind,
    resource: ResourceKind,
    mutability: Mutability,
    carrier: str,
    *,
    target: CanonicalTarget | None = None,
    source: CanonicalTarget | None = None,
    destination: CanonicalTarget | None = None,
) -> EffectRequest:
    return EffectRequest(
        actor=context.actor,
        profile=context.profile,
        session_mode=context.session_mode,
        execution_mode=context.execution_mode,
        effect=effect,
        resource=resource,
        mutability=mutability,
        carrier=carrier,
        target=target,
        source=source,
        destination=destination,
        parent_operation=context.parent_operation,
        unattended=context.unattended,
        bypass_requested=context.bypass_requested,
    )


def _file_target(path: object, resolver: TargetResolver) -> CanonicalTarget:
    if not isinstance(path, (str, os.PathLike)) or not str(path):
        return CanonicalTarget(
            raw=str(path or ""),
            absolute=None,
            canonical=None,
            identity_status=IdentityStatus.UNKNOWN,
        )
    return resolver(str(path))


def _missing_parent_request(
    context: EffectContext,
    target: CanonicalTarget,
    carrier: str,
) -> EffectRequest | None:
    """Represent the observable parent creation performed by whole-file adds."""
    if target.identity_status is not IdentityStatus.PROVEN:
        return None
    path = target.canonical or target.absolute
    if not path:
        return None
    parent = Path(path).parent
    try:
        if parent.is_dir():
            return None
    except OSError:
        # Unknown parent state is already covered by target identity handling;
        # avoid claiming a directory creation that may not happen.
        return None
    return _request(
        context,
        EffectKind.CREATE_DIRECTORY,
        ResourceKind.FILESYSTEM,
        Mutability.MUTATING,
        carrier,
        target=canonicalize_target(str(parent)),
    )


def _patch_effects(
    args: dict,
    context: EffectContext,
    resolver: TargetResolver,
) -> list[EffectRequest]:
    mode = str(args.get("mode") or "replace").strip().lower()
    if mode != "patch":
        target = _file_target(args.get("path"), resolver)
        return [
            _request(
                context,
                effect,
                ResourceKind.FILESYSTEM,
                Mutability.MUTATING,
                "patch:replace",
                target=target,
            )
            for effect in (EffectKind.REPLACE, EffectKind.TRUNCATE, EffectKind.WRITE)
        ]
    from tools.patch_parser import OperationType, parse_v4a_patch

    operations, error = parse_v4a_patch(str(args.get("patch") or ""))
    if error or not operations:
        return [
            _request(
                context,
                EffectKind.WRITE,
                ResourceKind.FILESYSTEM,
                Mutability.UNKNOWN,
                "patch:v4a-unresolved",
            )
        ]
    effects_by_operation = {
        OperationType.UPDATE: (EffectKind.REPLACE, EffectKind.TRUNCATE, EffectKind.WRITE),
        OperationType.DELETE: (EffectKind.DELETE,),
        OperationType.MOVE: (EffectKind.MOVE,),
    }
    requests: list[EffectRequest] = []
    for operation in operations:
        effects = effects_by_operation.get(operation.operation)
        if operation.operation is OperationType.MOVE:
            requests.append(
                _request(
                    context,
                    EffectKind.MOVE,
                    ResourceKind.FILESYSTEM,
                    Mutability.MUTATING,
                    "patch:v4a",
                    source=_file_target(operation.file_path, resolver),
                    destination=_file_target(operation.new_path, resolver),
                )
            )
        else:
            operation_target = _file_target(operation.file_path, resolver)
            if operation.operation is OperationType.ADD:
                effects = _write_target_effects(operation_target)
            assert effects is not None
            requests.extend(
                _request(
                    context,
                    effect,
                    ResourceKind.FILESYSTEM,
                    Mutability.MUTATING,
                    "patch:v4a",
                    target=operation_target,
                )
                for effect in effects
            )
            if operation.operation is OperationType.ADD:
                parent_request = _missing_parent_request(
                    context,
                    operation_target,
                    "patch:v4a:add-parent",
                )
                if parent_request is not None:
                    requests.append(parent_request)
    return requests


def _write_target_effects(target: CanonicalTarget) -> tuple[EffectKind, ...]:
    """Whole-file writes create a leaf or replace and truncate an existing one."""
    uncertain = (EffectKind.CREATE, EffectKind.REPLACE, EffectKind.TRUNCATE, EffectKind.WRITE)
    if target.identity_status is not IdentityStatus.PROVEN:
        return uncertain
    paths = tuple(dict.fromkeys(path for path in (target.canonical, target.absolute) if path))
    for path in paths:
        try:
            stat_result = os.lstat(path)
            is_reparse = bool(
                getattr(stat_result, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            )
            if stat.S_ISLNK(stat_result.st_mode) or is_reparse:
                # The canonical referent was checked first. A lexical reparse
                # point with no existing referent is a create, not replacement
                # of the link itself.
                continue
            return (EffectKind.REPLACE, EffectKind.TRUNCATE, EffectKind.WRITE)
        except (FileNotFoundError, NotADirectoryError):
            continue
        except (OSError, ValueError):
            return uncertain
    return (EffectKind.CREATE, EffectKind.WRITE)


def _same_target_path(target: CanonicalTarget, path: Path) -> bool:
    active = canonicalize_target(str(path))
    target_paths = {_normal_path(value) for value in (target.absolute, target.canonical) if value}
    if target.raw and Path(target.raw).expanduser().is_absolute():
        target_paths.add(_normal_path(str(Path(target.raw).expanduser().absolute())))
    active_paths = {_normal_path(value) for value in (active.absolute, active.canonical) if value}
    return bool(target_paths & active_paths)


def _approval_config_projection(value: object) -> object:
    if not isinstance(value, dict):
        return None
    value_map = cast(Mapping[str, object], value)
    security_value = value_map.get("security")
    security = cast(Mapping[str, object], security_value) if isinstance(security_value, dict) else {}
    return {
        "approvals": value_map.get("approvals"),
        "command_allowlist": value_map.get("command_allowlist"),
        "security_approval": security.get("approval"),
        "effect_policy": security.get("effect_policy"),
    }


def _candidate_enables_approval_bypass(candidate: object, current: object) -> bool:
    if not isinstance(candidate, dict) or not isinstance(current, dict):
        return True
    candidate_map = cast(Mapping[str, object], candidate)
    current_map = cast(Mapping[str, object], current)
    approvals = candidate_map.get("approvals")
    current_approvals_value = current_map.get("approvals")
    current_approvals = (
        cast(Mapping[str, object], current_approvals_value)
        if isinstance(current_approvals_value, dict)
        else {}
    )
    if not isinstance(approvals, dict) and current_approvals:
        return True
    if isinstance(approvals, dict):
        approvals_map = cast(Mapping[str, object], approvals)
        if any(key not in approvals_map for key in current_approvals):
            return True
        bypass_values = {"approve", "off", "allow", "yes"}
        for key, setting in approvals_map.items():
            normalized = "off" if key == "mode" and setting is False else str(setting).strip().lower()
            changed = setting != current_approvals.get(key)
            if changed and (
                (key == "mode" and normalized == "off")
                or (str(key).endswith("_mode") and normalized in bypass_values)
            ):
                return True
        current_deny = current_approvals.get("deny")
        candidate_deny = approvals_map.get("deny")
        if isinstance(current_deny, list) and current_deny:
            if not isinstance(candidate_deny, list) or any(
                not any(rule == candidate_rule for candidate_rule in candidate_deny)
                for rule in current_deny
            ):
                return True
        for key in ("mcp_reload_confirm", "destructive_slash_confirm"):
            if bool(current_approvals.get(key, True)) and not bool(approvals_map.get(key, True)):
                return True
    if candidate_map.get("command_allowlist") != current_map.get("command_allowlist"):
        return bool(candidate_map.get("command_allowlist"))
    candidate_security_value = candidate_map.get("security")
    current_security_value = current_map.get("security")
    candidate_security = (
        cast(Mapping[str, object], candidate_security_value)
        if isinstance(candidate_security_value, dict)
        else {}
    )
    current_security = (
        cast(Mapping[str, object], current_security_value)
        if isinstance(current_security_value, dict)
        else {}
    )
    return candidate_security.get("effect_policy") != current_security.get("effect_policy")


def _active_config_effects(
    args: dict,
    context: EffectContext,
    target: CanonicalTarget,
    *,
    conservative: bool = False,
) -> list[EffectRequest]:
    try:
        from hermes_constants import get_hermes_home
        from hermes_cli import managed_scope

        config_targets = [(Path(get_hermes_home()) / "config.yaml", False)]
        managed_dir = managed_scope.get_managed_dir()
        if managed_dir is not None:
            config_targets.insert(0, (Path(managed_dir) / "config.yaml", True))
    except Exception:
        return []
    matched = next(
        ((path, managed) for path, managed in config_targets if _same_target_path(target, path)),
        None,
    )
    if matched is None:
        return []
    active_config, is_managed = matched
    conservative = conservative or is_managed
    carrier = "file_tool:managed_config" if is_managed else "file_tool:active_config"

    effects = [
        _request(
            context,
            EffectKind.CONFIG_WRITE,
            ResourceKind.HERMES_CONFIG,
            Mutability.MUTATING,
            carrier,
            target=target,
        )
    ]
    try:
        if conservative:
            raise ValueError("patch result is not reconstructed by the policy adapter")
        import yaml

        candidate = yaml.safe_load(str(args.get("content") or "")) or {}
        current = yaml.safe_load(active_config.read_text(encoding="utf-8")) or {}
        approval_changed = _approval_config_projection(candidate) != _approval_config_projection(current)
        bypass_enabled = _candidate_enables_approval_bypass(candidate, current)
    except Exception:
        approval_changed = bypass_enabled = True
    if approval_changed:
        effects.append(
            _request(
                context,
                EffectKind.APPROVAL_POLICY_CHANGE,
                ResourceKind.APPROVAL_POLICY,
                Mutability.MUTATING,
                carrier,
                target=target,
            )
        )
    if bypass_enabled:
        effects.append(
            _request(
                context,
                EffectKind.YOLO_OR_BYPASS_ENABLE,
                ResourceKind.APPROVAL_POLICY,
                Mutability.MUTATING,
                carrier,
                target=target,
            )
        )
    return effects


def _write_file_requests(
    tool_name: str, args: dict, context: EffectContext, resolver: TargetResolver
) -> list[EffectRequest]:
    target = _file_target(args.get("path"), resolver)
    requests = [
        _request(
            context,
            effect,
            ResourceKind.FILESYSTEM,
            Mutability.MUTATING,
            "file_tool",
            target=target,
        )
        for effect in _write_target_effects(target)
    ]
    parent_request = _missing_parent_request(context, target, "file_tool:parent")
    if parent_request is not None:
        requests.append(parent_request)
    requests.extend(_active_config_effects(args, context, target))
    return requests


def _patch_requests(
    tool_name: str, args: dict, context: EffectContext, resolver: TargetResolver
) -> list[EffectRequest]:
    requests = _patch_effects(args, context, resolver)
    # Patch application is intentionally not duplicated here. Any mutation
    # touching active config is conservative because a partial edit, add/delete,
    # or move can alter or remove approval controls.
    seen_targets: set[tuple[str | None, str | None, str]] = set()
    for request in tuple(requests):
        for target in (request.target, request.source, request.destination):
            if target is None:
                continue
            key = (target.absolute, target.canonical, target.raw)
            if key in seen_targets:
                continue
            seen_targets.add(key)
            requests.extend(_active_config_effects({}, context, target, conservative=True))
    return requests


def _process_carrier_requests(
    tool_name: str, args: dict, context: EffectContext, resolver: TargetResolver
) -> list[EffectRequest]:
    return [
        _request(
            context,
            EffectKind.PROCESS_EXECUTE,
            ResourceKind.PROCESS,
            Mutability.UNKNOWN,
            tool_name,
        )
    ]


def _process_manage_requests(
    tool_name: str, args: dict, context: EffectContext, resolver: TargetResolver
) -> list[EffectRequest]:
    action = str(args.get("action") or "").lower()
    if action not in {"write", "submit", "close", "kill", "handoff"}:
        return []
    return [
        _request(
            context,
            EffectKind.PROCESS_EXECUTE,
            ResourceKind.PROCESS,
            Mutability.UNKNOWN if action in {"write", "submit"} else Mutability.MUTATING,
            "process_stdin" if action in {"write", "submit"} else "process_control",
        )
    ]


def _memory_requests(
    tool_name: str, args: dict, context: EffectContext, resolver: TargetResolver
) -> list[EffectRequest]:
    action = str(args.get("action") or "").lower()
    if action not in {"add", "replace", "remove"} and not args.get("operations"):
        return []
    return [
        _request(
            context,
            EffectKind.MEMORY_CHANGE,
            ResourceKind.MEMORY,
            Mutability.MUTATING,
            "memory_tool",
        )
    ]


def _skill_requests(
    tool_name: str, args: dict, context: EffectContext, resolver: TargetResolver
) -> list[EffectRequest]:
    return [
        _request(
            context,
            EffectKind.SKILL_CHANGE,
            ResourceKind.SKILL,
            Mutability.MUTATING,
            "skill_manager",
        )
    ]


def _setup_mcp_requests(
    tool_name: str, args: dict, context: EffectContext, resolver: TargetResolver
) -> list[EffectRequest]:
    return [
        _request(
            context,
            EffectKind.MCP_CONFIGURATION_CHANGE,
            ResourceKind.MCP,
            Mutability.MUTATING,
            "setup_mcp",
        )
    ]


_EFFECT_ADAPTERS: dict[str, Callable[[str, dict, EffectContext, TargetResolver], list[EffectRequest]]] = {
    "write_file": _write_file_requests,
    "patch": _patch_requests,
    "terminal": _process_carrier_requests,
    "execute_code": _process_carrier_requests,
    "process_manage": _process_manage_requests,
    "memory": _memory_requests,
    "skill_manage": _skill_requests,
    "setup_mcp": _setup_mcp_requests,
}

MIGRATED_TOOL_EFFECTS = frozenset(_EFFECT_ADAPTERS)


def effect_requests_for_tool(
    tool_name: str,
    args: dict,
    *,
    context: EffectContext | None = None,
    task_id: str | None = None,
    target_resolver: TargetResolver | None = None,
) -> list[EffectRequest]:
    """Translate migrated tool calls into carrier-independent semantic effects."""
    context = context or current_effect_context()
    args = args if isinstance(args, dict) else {}
    target_resolver = target_resolver or _task_target_resolver(task_id)
    adapter = _EFFECT_ADAPTERS.get(tool_name)
    return adapter(tool_name, args, context, target_resolver) if adapter is not None else []


def authorize_tool_call(
    tool_name: str,
    args: dict,
    *,
    context: EffectContext | None = None,
    policy: EffectPolicy | None = None,
    task_id: str | None = None,
    target_resolver: TargetResolver | None = None,
) -> PolicyResult:
    """Resolve and evaluate every semantic effect of a migrated tool call."""
    active_policy = policy or load_effect_policy()
    effective_context = context or current_effect_context()
    process_action = str(args.get("action") or "").lower() if isinstance(args, dict) else ""
    opaque_semantic_carrier = (
        tool_name in {"terminal", "execute_code"}
        or (tool_name == "process_manage" and process_action in {"write", "submit"})
    )
    if active_policy.valid and active_policy.denied_effects and opaque_semantic_carrier:
        denied = ", ".join(sorted(effect.value for effect in active_policy.denied_effects))
        return PolicyResult(
            PolicyDecision.DENY,
            f"opaque {tool_name} authority could reach configured denied effects: {denied}",
            non_bypassable=True,
        )
    opaque_approval_result: PolicyResult | None = None
    if active_policy.valid and active_policy.approval_required_effects and opaque_semantic_carrier:
        effects = ", ".join(sorted(effect.value for effect in active_policy.approval_required_effects))
        if effective_context.bypass_requested:
            opaque_approval_result = PolicyResult(
                PolicyDecision.ALLOW,
                "ordinary approval bypass is active",
            )
        elif effective_context.unattended:
            opaque_approval_result = PolicyResult(
                PolicyDecision.DENY,
                f"opaque {tool_name} authority could reach unattended approval-required effects: {effects}",
            )
        else:
            opaque_approval_result = PolicyResult(
                PolicyDecision.REQUIRE_APPROVAL,
                f"opaque {tool_name} authority could reach approval-required effects: {effects}",
            )
    if (
        active_policy.valid
        and not active_policy.protected_roots
        and not active_policy.protected_repositories
        and not active_policy.denied_effects
        and not active_policy.approval_required_effects
    ):
        return PolicyResult(PolicyDecision.ALLOW, "effect policy has no active rules")
    requests = effect_requests_for_tool(
        tool_name,
        args,
        context=effective_context,
        task_id=task_id,
        target_resolver=target_resolver,
    )
    if not requests:
        return PolicyResult(PolicyDecision.ALLOW, "tool boundary has no migrated mutating effect")
    priority = {
        PolicyDecision.ALLOW: 0,
        PolicyDecision.REQUIRE_APPROVAL: 1,
        PolicyDecision.REQUIRE_HUMAN_APPROVAL: 2,
        PolicyDecision.DENY: 3,
    }
    results = [authorize_effect(request, active_policy) for request in requests]
    if opaque_approval_result is not None:
        results.append(opaque_approval_result)
    return max(results, key=lambda result: priority[result.decision])


def enforce_tool_call(
    tool_name: str,
    args: dict,
    *,
    context: EffectContext | None = None,
    policy: EffectPolicy | None = None,
    task_id: str | None = None,
    target_resolver: TargetResolver | None = None,
) -> PolicyResult:
    """Evaluate a tool effect and resolve approval decisions without widening deny.

    Semantic ``DENY`` is terminal.  A protected/unknown target uses a fresh,
    non-bypassable, one-operation human prompt.  Ordinary approval requirements
    keep the existing session/YOLO semantics.
    """
    result = authorize_tool_call(
        tool_name,
        args,
        context=context,
        policy=policy,
        task_id=task_id,
        target_resolver=target_resolver,
    )
    if result.decision in {PolicyDecision.ALLOW, PolicyDecision.DENY}:
        return result
    from agent.redact import redact_sensitive_text

    raw_details = json.dumps(
        {"tool": tool_name, "arguments": args},
        sort_keys=True,
        ensure_ascii=False,
        default=lambda value: f"<{type(value).__module__}.{type(value).__qualname__}>",
    )
    display_details = redact_sensitive_text(
        raw_details,
        force=True,
        redact_url_credentials=True,
    )[:8_000]
    if result.decision is PolicyDecision.REQUIRE_HUMAN_APPROVAL:
        from tools.approval import request_non_bypassable_effect_approval
        approval = request_non_bypassable_effect_approval(
            description=result.reason,
            display_target=display_details,
            pattern_key="semantic_effect_policy",
        )
        if approval.get("approved"):
            return PolicyResult(PolicyDecision.ALLOW, "human approved this effect once")
        return PolicyResult(
            PolicyDecision.REQUIRE_HUMAN_APPROVAL,
            str(approval.get("message") or result.reason),
            non_bypassable=True,
        )

    from tools.approval import request_tool_approval

    try:
        scope_digest = _args_digest(args)
    except (TypeError, ValueError):
        # Unsupported argument objects cannot share a persisted approval scope.
        scope_digest = uuid.uuid4().hex
    reason_digest = hashlib.sha256(result.reason.encode("utf-8")).hexdigest()[:12]

    approval = request_tool_approval(
        tool_name,
        result.reason,
        rule_key=f"effect_policy:{tool_name}:{reason_digest}:{scope_digest}",
        display_target=display_details,
    )
    if approval.get("approved"):
        return PolicyResult(PolicyDecision.ALLOW, "effect approval granted")
    return PolicyResult(
        PolicyDecision.REQUIRE_APPROVAL,
        str(approval.get("message") or result.reason),
    )


def effect_policy_block_message(result: PolicyResult) -> str | None:
    if result.decision is PolicyDecision.ALLOW:
        return None
    label = {
        PolicyDecision.DENY: "DENIED",
        PolicyDecision.REQUIRE_APPROVAL: "APPROVAL REQUIRED",
        PolicyDecision.REQUIRE_HUMAN_APPROVAL: "EXPLICIT HUMAN APPROVAL REQUIRED",
    }[result.decision]
    return f"Effect policy {label}: {result.reason}. The operation was not executed."
