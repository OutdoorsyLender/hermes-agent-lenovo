"""Profiles resolve LSP servers from the machine-level staging root.

Regression for the provisioning gap behind ``lsp[typescript] server unavailable: typescript not
found`` in worker profiles: pre-shared-root Hermes staged LSP binaries under the *active* home, so
a profile whose ``lsp/bin`` had never been provisioned reported every server as missing even when
the root home carried the whole tree — and the fix for "auto-install cannot find npm" was to
install the same ``node_modules`` tree again in each of them.

The invariants pinned here:

1. A profile with an empty ``lsp/`` still reports a server staged in the shared root as installed.
2. ``install_strategy: auto`` reuses the shared package tree instead of shelling out to npm —
   that is what makes a fresh profile work without a download (and without a usable npm).
3. The shared root WINS over a profile-local ``lsp/``, because a profile-local tree is leftover
   pre-shared-root state that nothing validates: researcher's copy carried ``typescript`` 7.0.2
   (the Go-native port, no ``lib/tsserver.js``) and silently beat the working shared one, so every
   ``.ts`` write in that profile came back with no diagnostics and only a spawn WARNING far away
   in the log.  A local tree is a *fallback* for a package the shared root does not carry, so a
   box that ever provisioned only a profile still works without re-downloading, and the copy that
   loses the resolution is logged once at INFO instead of disappearing silently.
4. Whatever a profile-local tree does supply stays *inside* the profile: it is neither cached into
   a sibling profile nor staged into the shared ``bin/``, both of which leaked one profile's
   private binary to every other profile in a process that serves several (multiplex gateway,
   Desktop ``serve``, cron).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest

from agent.lsp import install as install_mod


@pytest.fixture(autouse=True)
def _fresh_install_cache():
    """``try_install`` memoizes per (package, active home); a stale entry masks a leak."""
    install_mod._install_results.clear()
    install_mod._shadow_notice_seen.clear()
    yield
    install_mod._install_results.clear()
    install_mod._shadow_notice_seen.clear()


@pytest.fixture
def profile_home(tmp_path, monkeypatch):
    """A named profile home whose machine-level root is ``tmp_path`` (shared root ``tmp_path/lsp``)."""
    home = tmp_path / "profiles" / "builder"
    home.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    return home


def _stage(root: Path, name: str) -> Path:
    """Stage a server binary the way this host needs it (``.cmd`` wrapper on Windows)."""
    root.mkdir(parents=True, exist_ok=True)
    path = root / (f"{name}.cmd" if os.name == "nt" else name)
    path.write_text("@echo off\r\n" if os.name == "nt" else "#!/bin/sh\n")
    path.chmod(0o755)
    return path


def test_server_in_the_shared_root_resolves_for_a_fresh_profile(profile_home, tmp_path):
    staged = _stage(tmp_path / "lsp" / "bin", "typescript-language-server")

    assert install_mod.hermes_lsp_staging_root() == tmp_path / "lsp"
    assert install_mod.detect_status("typescript-language-server") == "installed"
    resolved = install_mod._existing_binary("typescript-language-server")
    assert resolved is not None and Path(resolved) == staged


def test_auto_install_reuses_the_shared_package_tree_without_running_npm(profile_home, tmp_path, monkeypatch):
    _stage(tmp_path / "lsp" / "node_modules" / ".bin", "typescript-language-server")

    def _no_npm(*_args, **_kwargs):
        pytest.fail("npm was invoked even though the shared staging root already has the package")

    monkeypatch.setattr(install_mod.subprocess, "run", _no_npm)

    resolved = install_mod._do_install("typescript-language-server")

    assert resolved is not None
    assert Path(resolved).parent == install_mod.hermes_lsp_bin_dir() == tmp_path / "lsp" / "bin"
    assert Path(resolved).exists()
    assert not (profile_home / "lsp").exists(), "the profile home must stay untouched"


def test_the_shared_root_wins_over_a_stale_profile_local_tree(profile_home, tmp_path, caplog):
    """A profile-local tree that cannot do the job must not shadow the shared one.

    This is researcher's shape: its own ``lsp/`` was provisioned by pre-shared-root Hermes and its
    ``typescript-language-server`` still resolves, so "the directory exists" is not a validity
    signal — only the shared root is install-owned and repairable.
    """
    _stage(profile_home / "lsp" / "bin", "typescript-language-server")
    shared = _stage(tmp_path / "lsp" / "bin", "typescript-language-server")

    with caplog.at_level(logging.INFO, logger="agent.lsp.install"):
        resolved = install_mod._existing_binary("typescript-language-server")
        install_mod._existing_binary("typescript-language-server")  # second probe: reported once

    assert resolved is not None and Path(resolved) == shared
    notices = [r for r in caplog.records if "resolves from" in r.getMessage()]
    assert len(notices) == 1, "the shadowed copy must be reported exactly once, not per probe"
    message = notices[0].getMessage()
    assert str(shared.parent.parent) in message, "the winning root must be named"
    assert str(profile_home / "lsp") in message, "the ignored copy must be named too"


def test_a_profile_local_tree_is_the_fallback_when_the_shared_root_lacks_the_server(profile_home, tmp_path):
    """Sharing is additive in the other direction too: no re-download for a profile that has it."""
    own = _stage(profile_home / "lsp" / "bin", "pyright-langserver")

    resolved = install_mod._existing_binary("pyright-langserver")

    assert resolved is not None and Path(resolved) == own


def _profile(tmp_path: Path, name: str) -> Path:
    home = tmp_path / "profiles" / name
    home.mkdir(parents=True)
    return home


def test_a_profile_local_fallback_is_not_cached_into_the_next_profile(tmp_path, monkeypatch):
    """Two profiles in ONE process must not share an install result.

    One process serves many profiles (multiplex gateway, Desktop ``serve``, cron ticker).  Caching
    the result by package alone handed profile two the private binary profile one had resolved
    from its own tree.  Both profiles here have their own tree and the shared root has neither, so
    each must get its own binary — the case where a package-keyed cache leaks in the open.
    """
    one, two = _profile(tmp_path, "one"), _profile(tmp_path, "two")
    own_one = _stage(one / "lsp" / "bin", "typescript-language-server")
    own_two = _stage(two / "lsp" / "bin", "typescript-language-server")

    monkeypatch.setenv("HERMES_HOME", str(one))
    first = install_mod.try_install("typescript-language-server")
    assert first is not None and Path(first) == own_one

    monkeypatch.setenv("HERMES_HOME", str(two))
    second = install_mod.try_install("typescript-language-server")
    assert second is not None and Path(second) == own_two


def test_a_profile_local_tree_is_staged_into_that_profile_not_the_shared_root(tmp_path, monkeypatch):
    """The shared ``bin/`` must never delegate into one profile's private tree.

    Staging a profile-local package tree into the shared ``bin/`` left a shim pointing at
    ``profiles/<one>/lsp/node_modules``, which every other profile then resolved — and which
    breaks the moment that profile is updated or deleted.  The shared root has no copy of the
    package here, which is the only case where the profile-local tree is read at all.
    """
    one = _profile(tmp_path, "one")
    own_tree = _stage(one / "lsp" / "node_modules" / ".bin", "typescript-language-server")

    monkeypatch.setenv("HERMES_HOME", str(one))
    resolved = install_mod.try_install("typescript-language-server")

    assert resolved is not None
    assert own_tree.exists()
    assert Path(resolved).parent == one / "lsp" / "bin"
    assert not (tmp_path / "lsp" / "bin").exists(), "the shared staging dir must stay free of a profile-specific shim"