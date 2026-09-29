"""The home-I/O guard must not treat distribution-root probing as Hermes state I/O.

A venv ``.pth`` can put the installed checkout on ``sys.path``. ``importlib.metadata`` then
walks that directory as a distribution search root and stats it (``FastPath.mtime`` ->
``os.stat(root)``). Under the guard that stat landed inside the real hermes home and was
refused, failing unrelated tests at fixture setup with
``TEST BUG: file I/O against the REAL hermes home: <installed checkout>``.

These tests pin both halves: the metadata probe is allowed, and the guard's actual purpose —
refusing state reads and writes under a real root — is untouched.
"""

from __future__ import annotations

import sys

import pytest

from tests.home_io_guard import HomeIOGuard


def _roots(fake_home):
    return lambda: (fake_home,)


@pytest.fixture
def fake_install(tmp_path, monkeypatch):
    """``<fake home>/hermes-agent`` on ``sys.path``, mirroring the venv ``.pth`` layout."""
    fake_home = tmp_path / "hermes-home"
    install_root = fake_home / "hermes-agent"
    dist_info = install_root / "hermes_agent-0.21.3.dist-info"
    dist_info.mkdir(parents=True)
    monkeypatch.setattr(sys, "path", [str(install_root), *sys.path])
    return fake_home, install_root, dist_info


def test_metadata_stat_of_a_sys_path_root_inside_the_home_is_allowed(fake_install):
    fake_home, install_root, dist_info = fake_install
    guard = HomeIOGuard(roots=_roots(fake_home))
    guard.check(str(install_root), metadata=True)  # the FastPath.mtime stat
    guard.check(str(dist_info), metadata=True)  # metadata discovery descends into it


def test_guard_still_refuses_state_io_under_a_real_root(fake_install):
    fake_home, install_root, _dist_info = fake_install
    guard = HomeIOGuard(roots=_roots(fake_home))
    with pytest.raises(AssertionError):
        guard.check(str(fake_home / "state.db"), metadata=True)
    # The allowance is metadata-only: writes, deletes and opens stay refused.
    with pytest.raises(AssertionError):
        guard.check(str(install_root), metadata=False)
    with pytest.raises(AssertionError):
        guard.check(str(install_root / "hermes_state.py"), metadata=False)


def test_a_path_outside_every_root_is_unaffected(tmp_path):
    fake_home = tmp_path / "hermes-home"
    (fake_home / "hermes-agent").mkdir(parents=True)
    guard = HomeIOGuard(roots=_roots(fake_home))
    guard.check(str(tmp_path / "elsewhere" / "state.db"), metadata=False)


def test_read_of_distribution_metadata_under_a_sys_path_root_is_allowed(fake_install):
    fake_home, install_root, dist_info = fake_install
    entry_points = dist_info / "entry_points.txt"
    entry_points.write_text("[console_scripts]\n", encoding="utf-8")
    guard = HomeIOGuard(roots=_roots(fake_home))
    guard.check(str(entry_points), metadata=False)  # importlib.metadata reading it
    with pytest.raises(AssertionError):
        guard.check(str(install_root / "hermes_state.py"), metadata=False)  # not dist metadata
    with pytest.raises(AssertionError):
        guard.check(str(entry_points), metadata=False, destructive=True)  # never a write