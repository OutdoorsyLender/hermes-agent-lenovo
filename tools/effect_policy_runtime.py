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
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Iterable, Mapping, cast

from tools.effect_policy import (
    CanonicalTarget,
    EffectClassification,
    EffectDescriptor,
    EffectKind,
    EffectMode,
    EffectPolicy,
    EffectRequest,
    EffectTemplate,
    HOST_READ_ONLY_TOOL_NAMES,
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
    session_id: str
    tool_call_id: str | None
    authorization_fingerprint: str
    effects_digest: str
    effect_descriptor: EffectDescriptor | None = None
    normalized_action: str | None = None
    classification: EffectClassification | None = None
    mutability: Mutability | None = None
    # Phase 2A binds computer-control authorization to the exact handler
    # registration observed before policy/approval evaluation. Other migrated
    # tools retain their Phase-1 binding until their own bounded phase.
    registration_identity: object | None = None


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
_current_effect_admission: contextvars.ContextVar[_EffectPermitRecord | None] = (
    contextvars.ContextVar("current_effect_admission", default=None)
)


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


def _target_digest_value(target: CanonicalTarget | None) -> dict[str, object] | None:
    if target is None:
        return None
    repository = target.repository
    return {
        "raw": target.raw,
        "absolute": target.absolute,
        "canonical": target.canonical,
        "identity_status": target.identity_status.value,
        "repository_identity_status": target.repository_identity_status.value,
        "repository": None
        if repository is None
        else {
            "worktree_root": repository.worktree_root,
            "common_dir": repository.common_dir,
        },
    }


def _effect_requests_digest(requests: list[EffectRequest]) -> str:
    payload = [
        {
            "effect": request.effect.value,
            "resource": request.resource.value,
            "mutability": request.mutability.value,
            "carrier": request.carrier,
            "classification": (
                request.classification.value if request.classification is not None else None
            ),
            "target": _target_digest_value(request.target),
            "source": _target_digest_value(request.source),
            "destination": _target_digest_value(request.destination),
            "parent_operation": request.parent_operation,
        }
        for request in requests
    ]
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def snapshot_effect_args(args: dict) -> dict:
    """Return an isolated, lossless JSON snapshot for authorization and execution."""
    if not isinstance(args, dict):
        raise TypeError("effect-policy arguments must be an object")
    _validate_json_value(args)
    encoded = json.dumps(
        args,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    snapshot = json.loads(encoded)
    if not isinstance(snapshot, dict):  # pragma: no cover - guarded by the input check
        raise TypeError("effect-policy arguments must be an object")
    return snapshot


def _effective_task_id(task_id: str | None) -> str:
    return str(task_id or "default")


def _effective_session_id(session_id: str | None) -> str:
    return str(session_id or "")


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


def snapshot_effect_authorization() -> tuple[EffectPolicy, EffectContext, str]:
    """Capture the live policy/context pair and its stable authorization identity."""
    policy = load_effect_policy()
    context = current_effect_context()
    return policy, context, _authorization_fingerprint(policy, context)


def authorize_and_issue_effect_permit(
    tool_name: str,
    args: dict,
    *,
    task_id: str | None = None,
    session_id: str | None = None,
    tool_call_id: str | None = None,
    effect_descriptor: EffectDescriptor | None = None,
    approval_scope_id: str | None = None,
) -> tuple[PolicyResult, _EffectPermitHandle | None]:
    """Enforce live policy and issue a registration-bound one-shot permit.

    Deliberately no ``policy`` parameter exists: callers cannot mint by supplying
    an empty policy. Every JSON argument object is snapshotted before approval.
    Registered tools additionally bind the exact handler, descriptor, profile
    scope, and registration generation observed before authorization.
    """
    try:
        authorization_args = snapshot_effect_args(args)
        args_digest = _args_digest(authorization_args)
    except Exception as exc:
        # Non-JSON callers may still receive a one-shot live decision, but no
        # reusable permit can be minted from an ambiguous argument identity.
        try:
            result = enforce_tool_call(
                tool_name,
                args,
                task_id=_effective_task_id(task_id),
                approval_scope_id=approval_scope_id,
                effect_descriptor=effect_descriptor,
            )
        except Exception as policy_exc:
            result = PolicyResult(
                PolicyDecision.DENY,
                f"{tool_name} authorization snapshot failed: {exc}; "
                f"policy resolution also failed: {policy_exc}",
                non_bypassable=True,
            )
        return result, None

    registration_identity = None
    registry = None
    requested_effect_descriptor = effect_descriptor
    try:
        from tools.registry import registry as active_registry

        registry = active_registry
        registration_identity = registry.snapshot_dispatch_identity(tool_name)
        if registration_identity is not None:
            registered_descriptor = registration_identity.effect_descriptor
            if (
                requested_effect_descriptor is not None
                and requested_effect_descriptor != registered_descriptor
            ):
                return PolicyResult(
                    PolicyDecision.DENY,
                    f"{tool_name} requested descriptor does not match registration",
                    non_bypassable=True,
                ), None
            effect_descriptor = registered_descriptor
    except Exception as exc:
        return PolicyResult(
            PolicyDecision.DENY,
            f"{tool_name} registration snapshot failed: {exc}",
            non_bypassable=True,
        ), None

    try:
        live_policy = load_effect_policy()
        live_context = current_effect_context()
        initial_fingerprint = _authorization_fingerprint(live_policy, live_context)
        initial_effects_digest = _effect_requests_digest(
            effect_requests_for_tool(
                tool_name,
                authorization_args,
                context=live_context,
                task_id=_effective_task_id(task_id),
                effect_descriptor=effect_descriptor,
            )
        )
        result = enforce_tool_call(
            tool_name,
            authorization_args,
            task_id=_effective_task_id(task_id),
            context=live_context,
            policy=live_policy,
            approval_scope_id=(
                registration_identity.approval_scope_key
                if registration_identity is not None
                else approval_scope_id
            ),
            effect_descriptor=effect_descriptor,
        )
    except Exception as exc:
        return PolicyResult(
            PolicyDecision.DENY,
            f"{tool_name} policy resolution failed: {exc}",
            non_bypassable=True,
        ), None
    if result.decision is not PolicyDecision.ALLOW:
        return result, None

    try:
        arguments_unchanged = (
            _args_digest(authorization_args) == args_digest
            and _args_digest(args) == args_digest
        )
        final_context = current_effect_context()
        final_fingerprint = _authorization_fingerprint(
            load_effect_policy(), final_context
        )
        final_effects_digest = _effect_requests_digest(
            effect_requests_for_tool(
                tool_name,
                authorization_args,
                context=final_context,
                task_id=_effective_task_id(task_id),
                effect_descriptor=effect_descriptor,
            )
        )
    except Exception:
        arguments_unchanged = False
        final_fingerprint = ""
        final_effects_digest = ""
    if not arguments_unchanged:
        return PolicyResult(
            PolicyDecision.DENY,
            f"{tool_name} arguments changed during authorization",
            non_bypassable=True,
        ), None
    if final_fingerprint != initial_fingerprint:
        return PolicyResult(
            PolicyDecision.DENY,
            f"{tool_name} policy or context changed during authorization",
            non_bypassable=True,
        ), None
    if final_effects_digest != initial_effects_digest:
        return PolicyResult(
            PolicyDecision.DENY,
            f"{tool_name} resolved effects changed during authorization",
            non_bypassable=True,
        ), None
    if (
        registration_identity is not None
        and registry is not None
        and not registry.is_current_dispatch_identity(tool_name, registration_identity)
    ):
        return PolicyResult(
            PolicyDecision.DENY,
            f"{tool_name} registration changed during authorization",
            non_bypassable=True,
        ), None

    record = _EffectPermitRecord(
        attempt_id=uuid.uuid4().hex,
        tool_name=tool_name,
        args_digest=args_digest,
        task_id=_effective_task_id(task_id),
        session_id=_effective_session_id(session_id),
        tool_call_id=tool_call_id,
        authorization_fingerprint=initial_fingerprint,
        effects_digest=initial_effects_digest,
        effect_descriptor=effect_descriptor,
        registration_identity=registration_identity,
    )
    with _effect_permits_lock:
        _effect_permits[record.attempt_id] = record
    return result, _EffectPermitHandle(record.attempt_id)


def relay_effect_permit(record: _EffectPermitRecord) -> _EffectPermitHandle:
    """Create a fresh one-shot handle for the next, narrower dispatch seam."""
    relayed = replace(record, attempt_id=uuid.uuid4().hex)
    with _effect_permits_lock:
        _effect_permits[relayed.attempt_id] = relayed
    return _EffectPermitHandle(relayed.attempt_id)


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
    session_id: str | None = None,
    tool_call_id: str | None = None,
    registration_identity: object | None = None,
) -> _EffectPermitRecord | None:
    """Atomically consume and validate an issuer-backed one-shot permit."""
    attempt_id = _current_effect_attempt.get()
    if not attempt_id:
        return None
    try:
        args_digest = _args_digest(args)
    except (TypeError, ValueError):
        # Deactivate this binding, but leave the record for the owner to revoke:
        # a mismatched operation must not consume its permit.
        _current_effect_attempt.set(None)
        return None
    effective_task_id = _effective_task_id(task_id)
    effective_session_id = _effective_session_id(session_id)
    with _effect_permits_lock:
        candidate_permit = _effect_permits.get(attempt_id)
    if candidate_permit is None:
        _current_effect_attempt.set(None)
        return None
    try:
        live_context = current_effect_context()
        live_authorization_fingerprint = _authorization_fingerprint(
            load_effect_policy(),
            live_context,
        )
        effect_descriptor = candidate_permit.effect_descriptor
        live_effects_digest = _effect_requests_digest(
            effect_requests_for_tool(
                tool_name,
                args,
                context=live_context,
                task_id=effective_task_id,
                effect_descriptor=effect_descriptor,
            )
        )
    except Exception:
        _current_effect_attempt.set(None)
        return None
    with _effect_permits_lock:
        permit = _effect_permits.get(attempt_id)
        if (
            permit is None
            or permit.attempt_id != attempt_id
            or permit.tool_name != tool_name
            or permit.args_digest != args_digest
            or permit.task_id != effective_task_id
            or permit.session_id != effective_session_id
            or permit.tool_call_id != tool_call_id
            or permit.authorization_fingerprint != live_authorization_fingerprint
            or permit.effects_digest != live_effects_digest
            or permit.registration_identity != registration_identity
        ):
            _current_effect_attempt.set(None)
            return None
        _current_effect_attempt.set(None)
        return _effect_permits.pop(attempt_id)


def capture_final_effect_admission(
    tool_name: str,
    args: dict,
    *,
    task_id: str | None = None,
    session_id: str | None = None,
    tool_call_id: str | None = None,
    registration_identity: object | None = None,
) -> _EffectPermitRecord:
    """Capture the exact state admitted immediately before a handler call."""
    live_context = current_effect_context()
    descriptor = getattr(registration_identity, "effect_descriptor", None)
    return _EffectPermitRecord(
        attempt_id=uuid.uuid4().hex,
        tool_name=tool_name,
        args_digest=_args_digest(args),
        task_id=_effective_task_id(task_id),
        session_id=_effective_session_id(session_id),
        tool_call_id=tool_call_id,
        authorization_fingerprint=_authorization_fingerprint(
            load_effect_policy(), live_context
        ),
        effects_digest=_effect_requests_digest(
            effect_requests_for_tool(
                tool_name,
                args,
                context=live_context,
                task_id=_effective_task_id(task_id),
                effect_descriptor=descriptor,
            )
        ),
        registration_identity=registration_identity,
    )


@contextlib.contextmanager
def bind_final_effect_admission(admission: _EffectPermitRecord):
    """Expose one captured admission only to the synchronous handler call tree."""
    token = _current_effect_admission.set(admission)
    try:
        yield
    finally:
        _current_effect_admission.reset(token)


def enforce_final_effect_admission(
    tool_name: str,
    args: dict,
    *,
    task_id: str | None = None,
    session_id: str | None = None,
    tool_call_id: str | None = None,
    effect_descriptor: EffectDescriptor | None = None,
) -> PolicyResult:
    """Revalidate an admitted operation at its irreversible in-process seam.

    Direct internal callers without a registry admission receive a fresh live
    authorization rather than an implicit bypass. A bound admission never asks
    twice: any policy, context, argument, target, or descriptor drift denies and
    requires the caller to retry through the ordinary authorization path.
    """
    admission = _current_effect_admission.get()
    if admission is None:
        return enforce_tool_call(
            tool_name,
            args,
            task_id=task_id,
            effect_descriptor=effect_descriptor,
        )

    effective_task_id = _effective_task_id(task_id)
    effective_session_id = _effective_session_id(session_id)
    bound_descriptor = getattr(
        admission.registration_identity, "effect_descriptor", None
    )
    descriptor = effect_descriptor if effect_descriptor is not None else bound_descriptor
    try:
        live_context = current_effect_context()
        live_fingerprint = _authorization_fingerprint(
            load_effect_policy(), live_context
        )
        live_effects_digest = _effect_requests_digest(
            effect_requests_for_tool(
                tool_name,
                args,
                context=live_context,
                task_id=effective_task_id,
                effect_descriptor=descriptor,
            )
        )
        matches = (
            admission.tool_name == tool_name
            and admission.args_digest == _args_digest(args)
            and admission.task_id == effective_task_id
            and admission.session_id == effective_session_id
            and admission.tool_call_id == tool_call_id
            and admission.authorization_fingerprint == live_fingerprint
            and admission.effects_digest == live_effects_digest
            and (
                bound_descriptor is None
                or descriptor == bound_descriptor
            )
        )
    except Exception:
        matches = False
    if not matches:
        return PolicyResult(
            PolicyDecision.DENY,
            f"{tool_name} authorization became stale before execution",
            non_bypassable=True,
        )
    return PolicyResult(PolicyDecision.ALLOW, "final effect admission is current")


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
    classification: EffectClassification | None = None,
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
        classification=classification,
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


def _cronjob_requests(
    tool_name: str, args: dict, context: EffectContext, resolver: TargetResolver
) -> list[EffectRequest]:
    action = str(args.get("action") or "").strip().lower()
    if action == "list":
        return []
    if action in {"run", "run_now", "trigger"}:
        return [
            _request(
                context,
                EffectKind.PROCESS_EXECUTE,
                ResourceKind.PROCESS,
                Mutability.UNKNOWN,
                f"cronjob:{action}",
            )
        ]
    if action in {"create", "remove", "update", "pause", "resume"}:
        return [
            _request(
                context,
                EffectKind.CONFIG_WRITE,
                ResourceKind.HERMES_CONFIG,
                Mutability.MUTATING,
                f"cronjob:{action}",
            )
        ]
    raise ValueError(f"unknown cronjob_manage action: {action!r}")


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


def _computer_use_semantics(
    args: dict,
) -> tuple[str, EffectClassification, Mutability]:
    """Resolve the normalized action and authoritative core classification."""
    raw_action = args.get("action")
    if not isinstance(raw_action, str) or not (action := raw_action.strip().lower()):
        raise ValueError("computer_use action must be a non-empty string")

    from tools.computer_use.tool import _ACTIONS

    spec = _ACTIONS.get(action)
    if spec is None:
        raise ValueError(f"unknown computer_use action: {action!r}")
    if not isinstance(getattr(spec, "destructive", None), bool):
        raise ValueError(f"computer_use action {action!r} has malformed destructive metadata")
    visible_focus_change = bool(args.get("bring_to_front")) or (
        action == "focus_app" and bool(args.get("raise_window"))
    )
    if spec.destructive or visible_focus_change:
        return (
            action,
            EffectClassification.PRIVILEGED_OR_SECURITY_SENSITIVE,
            Mutability.MUTATING,
        )
    return action, EffectClassification.READ_ONLY_COMPATIBILITY, Mutability.READ_ONLY


def _computer_use_requests(
    tool_name: str, args: dict, context: EffectContext, resolver: TargetResolver
) -> list[EffectRequest]:
    """Classify the closed core action table; unknown metadata fails closed upstream."""
    action, classification, mutability = _computer_use_semantics(args)
    if mutability is Mutability.READ_ONLY:
        return []
    return [
        _request(
            context,
            EffectKind.COMPUTER_CONTROL,
            ResourceKind.COMPUTER,
            mutability,
            f"computer_use:{action}",
            classification=classification,
        )
    ]


_EFFECT_ADAPTERS: dict[str, Callable[[str, dict, EffectContext, TargetResolver], list[EffectRequest]]] = {
    "write_file": _write_file_requests,
    "patch": _patch_requests,
    "terminal": _process_carrier_requests,
    "execute_code": _process_carrier_requests,
    "process_manage": _process_manage_requests,
    "cronjob_manage": _cronjob_requests,
    "memory": _memory_requests,
    "skill_manage": _skill_requests,
    "setup_mcp": _setup_mcp_requests,
    "computer_use": _computer_use_requests,
}

MIGRATED_TOOL_EFFECTS = frozenset(_EFFECT_ADAPTERS)


def _effective_descriptor(
    tool_name: str,
    descriptor: EffectDescriptor | None,
) -> EffectDescriptor:
    if descriptor is not None:
        return descriptor
    if tool_name in _EFFECT_ADAPTERS:
        return EffectDescriptor(mode=EffectMode.CONDITIONAL, resolver_key=tool_name)
    if tool_name in HOST_READ_ONLY_TOOL_NAMES:
        return EffectDescriptor(mode=EffectMode.READ_ONLY)
    return EffectDescriptor(mode=EffectMode.OPAQUE)


def _request_from_template(
    template: EffectTemplate,
    *,
    tool_name: str,
    context: EffectContext,
) -> EffectRequest:
    return _request(
        context,
        template.effect,
        template.resource,
        template.mutability,
        f"{tool_name}:static",
        classification=template.classification,
    )


def effect_requests_for_tool(
    tool_name: str,
    args: dict,
    *,
    context: EffectContext | None = None,
    task_id: str | None = None,
    target_resolver: TargetResolver | None = None,
    effect_descriptor: EffectDescriptor | None = None,
) -> list[EffectRequest]:
    """Translate final tool arguments and immutable registration metadata."""
    context = context or current_effect_context()
    args = args if isinstance(args, dict) else {}
    target_resolver = target_resolver or _task_target_resolver(task_id)
    descriptor = _effective_descriptor(tool_name, effect_descriptor)
    if descriptor.mode is EffectMode.READ_ONLY:
        return [
            _request(
                context,
                EffectKind.READ,
                ResourceKind.UNKNOWN,
                Mutability.READ_ONLY,
                f"{tool_name}:read_only",
            )
        ]
    if descriptor.mode is EffectMode.STATIC:
        return [
            _request_from_template(template, tool_name=tool_name, context=context)
            for template in descriptor.effects
        ]
    if descriptor.mode is EffectMode.OPAQUE:
        return [
            _request(
                context,
                EffectKind.PROCESS_EXECUTE,
                ResourceKind.PROCESS,
                Mutability.UNKNOWN,
                f"{tool_name}:opaque",
            )
        ]
    if descriptor.mode is not EffectMode.CONDITIONAL:
        raise ValueError(f"unsupported effect descriptor mode: {descriptor.mode!r}")
    adapter = _EFFECT_ADAPTERS.get(str(descriptor.resolver_key))
    if adapter is None:
        raise ValueError(
            f"unknown host effect resolver: {descriptor.resolver_key!r}"
        )
    return adapter(tool_name, args, context, target_resolver)


def authorize_tool_call(
    tool_name: str,
    args: dict,
    *,
    context: EffectContext | None = None,
    policy: EffectPolicy | None = None,
    task_id: str | None = None,
    target_resolver: TargetResolver | None = None,
    effect_descriptor: EffectDescriptor | None = None,
) -> PolicyResult:
    """Resolve and evaluate every declared, conditional, or opaque effect."""
    active_policy = policy or load_effect_policy()
    effective_context = context or current_effect_context()
    descriptor = _effective_descriptor(tool_name, effect_descriptor)
    try:
        classified_requests = effect_requests_for_tool(
            tool_name,
            args,
            context=effective_context,
            task_id=task_id,
            target_resolver=target_resolver,
            effect_descriptor=descriptor,
        )
    except Exception as exc:
        return PolicyResult(
            PolicyDecision.DENY,
            f"{tool_name} classification failed: {exc}",
            non_bypassable=True,
        )
    process_action = str(args.get("action") or "").lower() if isinstance(args, dict) else ""
    resolver_key = descriptor.resolver_key if descriptor.mode is EffectMode.CONDITIONAL else None
    opaque_semantic_carrier = (
        descriptor.mode is EffectMode.OPAQUE
        or resolver_key in {"terminal", "execute_code"}
        or (resolver_key == "process_manage" and process_action in {"write", "submit"})
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
    requests = classified_requests
    if not requests:
        return PolicyResult(PolicyDecision.ALLOW, "declared read-only or compatibility operation")
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


def _effect_approval_rule_key(
    tool_name: str,
    args: dict,
    reason: str,
    approval_scope_id: str | None,
    requests: list[EffectRequest],
) -> str:
    """Bind cached approval to arguments, registration, and every resolved effect."""
    try:
        args_digest = _args_digest(args)
    except (TypeError, ValueError):
        args_digest = uuid.uuid4().hex
    reason_digest = hashlib.sha256(reason.encode("utf-8")).hexdigest()[:12]
    effects_digest = _effect_requests_digest(requests)
    bounded_scope = (
        approval_scope_id
        if isinstance(approval_scope_id, str) and approval_scope_id
        else uuid.uuid4().hex
    )
    return (
        f"effect_policy:{tool_name}:{reason_digest}:{args_digest}:"
        f"effects:{effects_digest}:registration:{bounded_scope}"
    )


def enforce_tool_call(
    tool_name: str,
    args: dict,
    *,
    context: EffectContext | None = None,
    policy: EffectPolicy | None = None,
    task_id: str | None = None,
    target_resolver: TargetResolver | None = None,
    approval_scope_id: str | None = None,
    effect_descriptor: EffectDescriptor | None = None,
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
        effect_descriptor=effect_descriptor,
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
        effective_context = context or current_effect_context()
        approval_requests = effect_requests_for_tool(
            tool_name,
            args,
            context=effective_context,
            task_id=task_id,
            target_resolver=target_resolver,
            effect_descriptor=effect_descriptor,
        )
        rule_key = _effect_approval_rule_key(
            tool_name,
            args,
            result.reason,
            approval_scope_id,
            approval_requests,
        )
    except Exception as exc:
        return PolicyResult(
            PolicyDecision.DENY,
            f"{tool_name} approval identity resolution failed: {exc}",
            non_bypassable=True,
        )

    approval = request_tool_approval(
        tool_name,
        result.reason,
        rule_key=rule_key,
        display_target=display_details,
    )
    if approval.get("approved"):
        return PolicyResult(PolicyDecision.ALLOW, "effect approval granted")
    return PolicyResult(
        PolicyDecision.REQUIRE_APPROVAL,
        str(approval.get("message") or result.reason),
    )


def effect_policy_error_type(result: PolicyResult) -> str:
    """Map a policy outcome to a stable external error contract."""
    if result.decision in {
        PolicyDecision.REQUIRE_APPROVAL,
        PolicyDecision.REQUIRE_HUMAN_APPROVAL,
    }:
        return "effect_policy_approval_required"
    reason = result.reason.casefold()
    if "changed since authorization" in reason or "stale" in reason:
        return "effect_policy_stale_authorization"
    return "effect_policy_denied"


def effect_policy_block_message(result: PolicyResult) -> str | None:
    if result.decision is PolicyDecision.ALLOW:
        return None
    label = {
        PolicyDecision.DENY: "DENIED",
        PolicyDecision.REQUIRE_APPROVAL: "APPROVAL REQUIRED",
        PolicyDecision.REQUIRE_HUMAN_APPROVAL: "EXPLICIT HUMAN APPROVAL REQUIRED",
    }[result.decision]
    return f"Effect policy {label}: {result.reason}. The operation was not executed."
