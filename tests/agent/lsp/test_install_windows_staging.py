"""Windows staging: the binary ``lsp/bin/`` hands the client must actually start.

npm's shims resolve their payload relative to their own directory (``%~dp0\\..``), and
``lsp/bin/`` is not that directory.  A symlink needs a privilege this host does not grant
(``WinError 1314``), so the staging fell back to a copy — which pointed that relative path
at ``lsp/<pkg>/lib/...``, a tree that does not exist, leaving a staged binary that fails
at spawn while ``hermes lsp install`` reported success.  npm also writes an extensionless
POSIX sh shim beside every ``.cmd``; selecting that one is the same failure by another
route (``WinError 193``: ``CreateProcess`` cannot start it).

Windows-only: both behaviours are ``CreateProcess`` semantics.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from agent.lsp import install as install_mod

pytestmark = pytest.mark.windows_only


def _npm_tree(home_lsp: Path) -> Path:
    """A miniature npm staging tree whose ``.bin`` shim resolves relative to itself."""
    bin_dir = home_lsp / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    (home_lsp / "node_modules" / "payload.txt").write_text("PAYLOAD-OK\n", encoding="utf-8")
    (bin_dir / "tool.cmd").write_bytes(b'@ECHO off\r\nTYPE "%~dp0\\..\\payload.txt"\r\n')
    # The extensionless POSIX sh shim npm writes beside it — unusable on this host.
    (bin_dir / "tool").write_bytes(b'#!/bin/sh\nexec cat "$(dirname "$0")/../payload.txt"\n')
    return bin_dir / "tool.cmd"


def _run(path) -> subprocess.CompletedProcess:
    return subprocess.run(["cmd.exe", "/c", str(path)], capture_output=True, text=True, timeout=60)


def test_staged_binary_delegates_by_absolute_path_and_repairs_a_stale_shim():
    home_lsp = install_mod.hermes_lsp_bin_dir().parent
    shim = _npm_tree(home_lsp)

    staged = install_mod.hermes_lsp_bin_dir() / "tool.cmd"
    shutil.copy2(shim, staged)  # exactly what the copy fallback used to leave behind
    assert _run(staged).returncode != 0, "a copy cannot resolve %~dp0\\.. any more"

    assert Path(install_mod._link_into_bin(shim)) == staged
    out = _run(staged)
    assert out.returncode == 0, out.stderr
    assert "PAYLOAD-OK" in out.stdout


def test_native_wrapper_is_preferred_over_the_posix_shim():
    shim = _npm_tree(install_mod.hermes_lsp_bin_dir().parent)
    assert install_mod._npm_bin_binary("tool") == shim
