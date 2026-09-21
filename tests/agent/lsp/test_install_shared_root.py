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
3. A profile that already provisioned its own tree keeps winning, so sharing is additive.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from agent.lsp import install as install_mod


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


def test_a_profile_own_staging_dir_keeps_winning(profile_home, tmp_path):
    own = _stage(profile_home / "lsp" / "bin", "pyright-langserver")
    _stage(tmp_path / "lsp" / "bin", "pyright-langserver")

    resolved = install_mod._existing_binary("pyright-langserver")
    assert resolved is not None and Path(resolved) == own