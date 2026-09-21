"""Auto-installation of LSP server binaries.

Installs go to a Hermes-owned staging dir, ``<root home>/lsp/bin/``, so the
user's global toolchain stays untouched.  That root is the *machine-level* home
(``get_default_hermes_root()``), not the active profile: the staging tree is a
re-downloadable binary cache, and a per-profile copy both duplicates the whole
``node_modules`` tree and leaves a profile with no server at all whenever only
one home was ever provisioned.  A profile-local ``lsp/`` (what pre-shared-root
Hermes wrote) still wins as a read override, and staging it writes beside itself
so the shared dir never delegates into one profile's private tree.  Strategies:
``auto`` (install with the best available package manager), ``manual`` / ``off``
(probe only; a missing binary skips the server and ``hermes lsp status`` reports
it).  Installs run synchronously the first time a server is needed, serialized
per-package; every failure path returns ``None`` so the tool layer falls back to
its in-process syntax checker.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from hermes_cli._subprocess_compat import windows_hide_flags
from hermes_constants import find_node_executable, hermes_home_key

logger = logging.getLogger("agent.lsp.install")


def _recipe(strategy: str, pkg: str, bin_name: str, **extra: Any) -> Dict[str, Any]:
    return {"strategy": strategy, "pkg": pkg, "bin": bin_name, **extra}


def _npm(pkg: str, bin_name: str, **extra: Any) -> Dict[str, Any]:
    return _recipe("npm", pkg, bin_name, **extra)


def _manual(bin_name: str) -> Dict[str, Any]:
    return _recipe("manual", "", bin_name)


# Recipe key → {strategy, pkg, bin[, extra_pkgs]}.  After install we look for
# ``bin`` in ``<root home>/lsp/bin/`` first, then on PATH.  ``extra_pkgs``
# are sibling npm packages a server needs in the same node_modules tree.
INSTALL_RECIPES: Dict[str, Dict[str, Any]] = {
    "pyright": _npm("pyright", "pyright-langserver"),
    # tsserver must be importable from the same node_modules tree or
    # initialize() fails with "Could not find a valid TypeScript installation".
    "typescript-language-server": _npm("typescript-language-server", "typescript-language-server", extra_pkgs=["typescript"]),
    "@vue/language-server": _npm("@vue/language-server", "vue-language-server"),
    "svelte-language-server": _npm("svelte-language-server", "svelteserver"),
    "@astrojs/language-server": _npm("@astrojs/language-server", "astro-ls"),
    "yaml-language-server": _npm("yaml-language-server", "yaml-language-server"),
    "bash-language-server": _npm("bash-language-server", "bash-language-server"),
    "intelephense": _npm("intelephense", "intelephense"),
    "dockerfile-language-server-nodejs": _npm("dockerfile-language-server-nodejs", "docker-langserver"),
    "gopls": _recipe("go", "golang.org/x/tools/gopls@latest", "gopls"),
    # Manual: rust-analyzer (via rustup) and clangd (ships with LLVM) are far too
    # heavy to bootstrap; LuaLS is platform-specific GitHub release binaries.
    "rust-analyzer": _manual("rust-analyzer"),
    "clangd": _manual("clangd"),
    "lua-language-server": _manual("lua-language-server"),
    # PowerShellEditorServices is a release-zip bundle driven by pwsh; we probe
    # the host so `hermes lsp status` reports its presence.
    "powershell": _manual("pwsh"),
}

_install_locks: Dict[str, threading.Lock] = {}
# Keyed by (package, active home): a result resolved from a profile-local tree belongs to that
# profile alone, and one process serves many profiles (multiplex gateway / Desktop serve / cron).
_install_results: Dict[tuple, Optional[str]] = {}
_install_lock_meta = threading.Lock()
_WINDOWS_WRAPPER_SUFFIXES = (".cmd", ".exe", ".bat")


def _is_windows() -> bool:
    return os.name == "nt"


def hermes_lsp_staging_root() -> Path:
    """The machine-level LSP staging root, ``<root home>/lsp``, shared by every profile.

    ``get_default_hermes_root()`` is the platform default home: ``<root>`` when
    ``HERMES_HOME=<root>/profiles/<name>`` and the home itself otherwise, so a box with a single
    home keeps exactly the path it had.  Profiles stay islands for config/sessions/secrets; this
    tree is a re-downloadable binary cache next to the npm/uv stores, not profile data.
    """
    from hermes_constants import get_default_hermes_root

    return get_default_hermes_root() / "lsp"


def hermes_lsp_bin_dir() -> Path:
    """The Hermes-owned shared ``bin/`` staging dir for LSP servers (the default write target)."""
    p = hermes_lsp_staging_root() / "bin"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _lsp_staging_roots() -> list[Path]:
    """Roots to READ, the active profile's own staging dir first, then the shared root.

    A profile-local ``lsp/`` is what pre-shared-root Hermes wrote, so a profile that already
    provisioned its own server keeps resolving it (it wins as an override); every other profile —
    including one created fresh with an empty ``lsp/`` — falls through to the shared root instead
    of re-downloading the tree.  Installs always go to the shared root; the only thing written
    under a profile-local dir is a shim for a server that already lives in that profile's own
    tree (see ``_bin_dir_for``).
    """
    from hermes_constants import get_hermes_home

    roots = [get_hermes_home() / "lsp", hermes_lsp_staging_root()]
    return list({os.path.normcase(str(r)): r for r in roots}.values())


def _bin_dir_for(target: Path) -> Path:
    """The ``bin/`` dir that owns ``target``: the staging root it lives under.

    A server resolved from a profile-local tree is staged into THAT profile's ``bin/``.  Writing
    the shared ``bin/`` shim from it left a shim delegating into one profile's private
    ``node_modules`` — which every other profile then resolved, and which breaks the moment that
    profile is updated or deleted.  Targets outside every staging root (PATH, toolchains) stage
    into the shared dir as before.
    """
    try:
        resolved = target.resolve()
    except OSError:
        resolved = target
    for root in _lsp_staging_roots():
        try:
            resolved.relative_to(root.resolve())
        except (OSError, ValueError):
            continue
        bin_dir = root / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        return bin_dir
    return hermes_lsp_bin_dir()


def _native_binary_candidates(base: Path) -> list[Path]:
    """Return the executable candidates for a staged binary, best first.

    On Windows the ``.cmd``/``.exe``/``.bat`` wrappers come BEFORE the bare name: npm
    writes an extensionless POSIX sh shim beside every ``.cmd``, and ``CreateProcess``
    cannot start that shim (``WinError 193``).  Preferring it — which the old ordering
    did — hands the LSP client a command that always fails to spawn.
    """
    if not _is_windows():
        return [base]
    cands: Dict[str, Path] = {}
    for c in (*(Path(str(base) + s) for s in _WINDOWS_WRAPPER_SUFFIXES), base):
        cands.setdefault(str(c).lower(), c)
    return list(cands.values())


def _runnable(staged: Path) -> bool:
    """True iff ``staged`` is a file this host can actually start.

    ``os.access(X_OK)`` is True for every existing file on Windows (there is no execute
    bit), so it cannot tell a real wrapper from npm's POSIX sh shim; the suffix is the
    only signal available there.
    """
    if not staged.exists():
        return False
    if _is_windows() and staged.suffix.lower() not in _WINDOWS_WRAPPER_SUFFIXES:
        return False
    return os.access(staged, os.X_OK)


def _first_existing(*bases: Path) -> Optional[Path]:
    """First platform-native candidate of any ``base`` that exists on disk."""
    return next((c for base in bases for c in _native_binary_candidates(base) if c.exists()), None)


def _npm_bin_binary(bin_name: str) -> Optional[Path]:
    """The npm-installed entry point for ``bin_name`` in a staging tree (``<root>/lsp``)."""
    for root in _lsp_staging_roots():
        found = _first_existing(root / "node_modules" / ".bin" / bin_name)
        if found is not None:
            return found
    return None


def _existing_binary(name: str) -> Optional[str]:
    """Probe every staging dir + PATH for a binary named ``name``."""
    for root in _lsp_staging_roots():
        for staged in _native_binary_candidates(root / "bin" / name):
            if _runnable(staged):
                return str(staged)
    suffixes = (".cmd", ".exe", ".bat", "") if _is_windows() else ("",)
    return next((p for s in suffixes if (p := shutil.which(f"{name}{s}"))), None)


def _install_cache_key(pkg: str) -> tuple:
    """Cache key for an install result: the package AND the active home.

    One process serves many profiles (multiplex gateway, Desktop ``serve``, cron ticker), and a
    result resolved from a profile-local staging tree is that profile's binary.  Keying by package
    alone handed profile two the private path profile one had resolved.
    """
    return (pkg, hermes_home_key())


def try_install(pkg: str, strategy: str = "auto") -> Optional[str]:
    """Try to install ``pkg``; return the binary path or ``None``.

    Only ``"auto"`` installs; ``"manual"``/``"off"`` just probe for an existing
    binary.  Results are cached per package and active home, and concurrent calls
    are serialized.
    """
    if strategy != "auto":
        return _existing_binary(INSTALL_RECIPES.get(pkg, {}).get("bin", pkg))
    key = _install_cache_key(pkg)
    if key in _install_results:
        return _install_results[key]
    with _install_lock_meta:
        lock = _install_locks.setdefault(pkg, threading.Lock())
    with lock:
        if key not in _install_results:
            _install_results[key] = _do_install(pkg)
        return _install_results[key]


def _do_install(pkg: str) -> Optional[str]:
    recipe = INSTALL_RECIPES.get(pkg)
    if recipe is None:
        return shutil.which(pkg)  # not in our registry — best-effort: just probe PATH
    strategy = recipe.get("strategy", "manual")
    bin_name = recipe.get("bin", pkg)
    if strategy == "npm" and (installed := _npm_bin_binary(bin_name)) is not None:
        # The staged shim is derived state; the package tree is the real artifact.  Re-stage
        # from it on every call so a shim written by an older staging (a copied POSIX sh
        # script, a shim whose relative target no longer resolves) is repaired rather than
        # handed back as a working binary — that loop is how install reports success while
        # the server stays unusable.
        return _link_into_bin(installed)
    if existing := _existing_binary(bin_name):
        return existing
    if strategy == "manual":
        logger.debug("[install] %s requires manual install (recipe=%s)", pkg, recipe)
        return None
    installer = _INSTALLERS.get(strategy)
    if installer is None:
        logger.warning("[install] unknown strategy %r for %s", strategy, pkg)
        return None
    return installer(recipe, bin_name)


def _run_installer(tool: str, pkg: str, cmd: list, *, timeout: int, env: Optional[dict] = None) -> bool:
    """Run one install subprocess; log and return False on non-zero exit or error."""
    try:
        proc = subprocess.run(
            cmd, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, env=env, stdin=subprocess.DEVNULL, creationflags=windows_hide_flags(),
        )
        if proc.returncode != 0:
            logger.warning("[install] %s install failed for %s: %s", tool, pkg, proc.stderr.strip()[:500])
            return False
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning("[install] %s install errored for %s: %s", tool, pkg, e)
        return False
    return True


_SHIM_MARKER = "@rem hermes-lsp-shim"


def _stage_windows_shim(target: Path) -> str:
    """Stage a ``.cmd`` in ``lsp/bin/`` that runs ``target`` by ABSOLUTE path; return its path.

    npm shims resolve their payload relative to their own directory (``%~dp0\\..``), so a
    link from the staging dir is only correct if the link keeps the shim's own directory —
    and it does not: this host has no symlink privilege (``WinError 1314``), and the copy
    fallback then pointed that relative path at ``lsp/<pkg>/lib/...``, a tree that does not
    exist, leaving a staged binary that fails at spawn.  Delegating by absolute path keeps
    the target's own resolution intact and works for ``.cmd``/``.bat``/``.exe`` alike.
    """
    name = target.name if target.suffix.lower() in _WINDOWS_WRAPPER_SUFFIXES else target.name + ".cmd"
    link = _bin_dir_for(target) / name
    body = f'{_SHIM_MARKER}\r\n@echo off\r\nCALL "{target}" %*\r\n'.encode("ascii", errors="replace")
    try:
        # Rewritten whenever it does not already delegate to this target, so a shim left
        # behind by an older (broken) staging is repaired instead of silently reused.
        if not link.is_file() or link.read_bytes() != body:
            link.write_bytes(body)
    except OSError as e:
        logger.warning("[install] could not stage %s: %s", link, e)
        return str(target)
    return str(link)


def _link_into_bin(target: Path) -> str:
    """Stage ``target`` into the ``bin/`` dir of the staging root it lives under; return the path to use."""
    if _is_windows():
        return _stage_windows_shim(target)
    link = _bin_dir_for(target) / target.name
    if not link.exists():
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            # Symlinks fail on some setups — copy instead.
            try:
                shutil.copy2(target, link)
            except OSError:
                return str(target)
    return str(link if link.exists() else target)


def _install_npm(pkg: str, bin_name: str, extra_pkgs: Optional[list] = None) -> Optional[str]:
    """``npm install --prefix <staging>`` then link ``node_modules/.bin/<bin_name>`` into ``lsp/bin/``."""
    # Managed npm first: $HERMES_HOME/node isn't on an arbitrary process's
    # PATH, so a bare which() would miss the Node that Hermes installed.
    npm = find_node_executable("npm")
    if npm is None:
        logger.info("[install] cannot install %s: no usable npm found", pkg)
        return None
    staging = hermes_lsp_bin_dir().parent  # <root home>/lsp/ — machine-level, shared by profiles
    install_targets = [pkg] + list(extra_pkgs or [])
    logger.info("[install] npm install --prefix %s %s", staging, " ".join(install_targets))
    cmd = [npm, "install", "--prefix", str(staging), "--silent", "--no-fund", "--no-audit", *install_targets]
    if not _run_installer("npm", pkg, cmd, timeout=300):
        return None
    found = _npm_bin_binary(bin_name)
    if found is not None:
        return _link_into_bin(found)
    logger.warning("[install] npm install for %s succeeded but bin %s not found", pkg, bin_name)
    return None


def _install_go(pkg: str, bin_name: str) -> Optional[str]:
    """Install a Go module to GOBIN=<staging>."""
    go = shutil.which("go")
    if go is None:
        logger.info("[install] cannot install %s: go not on PATH", pkg)
        return None
    staging = hermes_lsp_bin_dir()
    logger.info("[install] go install %s (GOBIN=%s)", pkg, staging)
    if not _run_installer("go", pkg, [go, "install", pkg], timeout=600, env={**os.environ, "GOBIN": str(staging)}):
        return None
    bin_path = (staging / bin_name).with_suffix(".exe") if _is_windows() else staging / bin_name
    if bin_path.exists():
        return str(bin_path)
    logger.warning("[install] go install for %s succeeded but bin %s not found", pkg, bin_name)
    return None


def _install_pip(pkg: str, bin_name: str) -> Optional[str]:
    """``pip install --target <staging>/python-packages`` then link the console script into ``lsp/bin/``."""
    pip_target = hermes_lsp_bin_dir().parent / "python-packages"
    pip_target.mkdir(parents=True, exist_ok=True)
    try:
        logger.info("[install] pip install --target %s %s", pip_target, pkg)
        from hermes_cli.tools_config import _pip_install

        proc = _pip_install(["--target", str(pip_target), "--quiet", pkg], timeout=300)
        if proc.returncode != 0:
            logger.warning("[install] pip install failed for %s: %s", pkg, (proc.stderr or "").strip()[:500])
            return None
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning("[install] pip install errored for %s: %s", pkg, e)
        return None
    # POSIX wheels write console scripts to bin/, native Windows to Scripts/.
    script_dirs = [pip_target / "bin"] + ([pip_target / "Scripts"] if _is_windows() else [])
    found = _first_existing(*(d / bin_name for d in script_dirs))
    return _link_into_bin(found) if found is not None else None


# strategy → installer(recipe, bin_name).  ``manual`` is handled before dispatch.
_INSTALLERS: Dict[str, Callable[[Dict[str, Any], str], Optional[str]]] = {
    "npm": lambda r, b: _install_npm(r["pkg"], b, extra_pkgs=r.get("extra_pkgs") or []),
    "go": lambda r, b: _install_go(r["pkg"], b),
    "pip": lambda r, b: _install_pip(r["pkg"], b),
}


def detect_status(pkg: str) -> str:
    """Return ``installed``, ``missing``, or ``manual-only`` (for ``hermes lsp status``; spawns nothing)."""
    recipe = INSTALL_RECIPES.get(pkg)
    if _existing_binary(recipe.get("bin", pkg) if recipe else pkg):
        return "installed"
    return "manual-only" if recipe and recipe.get("strategy") == "manual" else "missing"


__all__ = ["INSTALL_RECIPES", "try_install", "detect_status", "hermes_lsp_bin_dir", "hermes_lsp_staging_root"]
