"""Regression: the first ``publishDiagnostics`` for a document is a verdict, not a seed.

A push-only server publishes once for a document it has never seen — in response to our
``didOpen`` — and does not necessarily publish again.  ``typescript-language-server``
behaves exactly that way for a file the edit just created: the write IS the ``didOpen``,
so the only diagnostics that will ever arrive for that content are the first push.

The client used to file the first push of every document as an untagged "seed" that no
waiter could ever be satisfied by (a leftover from the timestamp-based freshness model;
freshness is now tracked by document version, where an untagged push is simply a push
for a path nobody opened).  The result was the whole edit reporting no diagnostics at
all after waiting out the full ``lsp.wait_timeout``.

The contracts under test:

- diagnostics published in response to our ``didOpen`` satisfy a wait for that version;
- a diagnostic already present before the edit is not reported as introduced by it
  (the pre-write baseline can only be built from that same first push).
"""
from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest

from agent.lsp.servers import SERVERS, SpawnSpec

MOCK_SERVER = str(Path(__file__).parent / "_mock_lsp_server.py")

_swapped: list = []


@pytest.fixture(autouse=True)
def _restore_registry():
    """Put every swapped ``SERVERS`` entry back, whatever the test did."""
    yield
    for index, original in _swapped:
        SERVERS[index] = original
    _swapped.clear()


def _mock_ts_repo(monkeypatch, tmp_path: Path, script: str) -> Path:
    """Temp git workspace whose ``.ts`` files route to the mock language server.

    The registry entry is swapped with ``dataclasses.replace`` so every field we do not
    override — the extensions, the root policy, and any client configuration the entry
    carries — is the one ``typescript`` gets in production; the mock must exercise the
    same client setup the real server does.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    (repo / "package.json").write_text("{}", encoding="utf-8")
    monkeypatch.chdir(str(repo))

    index = next(i for i, srv in enumerate(SERVERS) if srv.server_id == "typescript")

    def _spawn(root: str, ctx) -> SpawnSpec:
        return SpawnSpec(
            command=[sys.executable, MOCK_SERVER], workspace_root=root, cwd=root,
            env={"MOCK_LSP_SCRIPT": script}, initialization_options={},
        )

    _swapped.append((index, SERVERS[index]))
    SERVERS[index] = replace(SERVERS[index], resolve_root=lambda fp, ws: ws, build_spawn=_spawn)
    return repo


def _service():
    from agent.lsp.manager import LSPService

    return LSPService(enabled=True, wait_mode="document", wait_timeout=1.0,
                      install_strategy="manual", idle_timeout=0)


def test_new_file_gets_the_verdict_published_for_its_didopen(monkeypatch, tmp_path):
    """``"stale"`` pushes on ``didOpen`` only — the sole verdict for a freshly created file."""
    repo = _mock_ts_repo(monkeypatch, tmp_path, "stale")
    target = repo / "new.ts"
    svc = _service()
    try:
        svc.snapshot_baseline(str(target))  # file does not exist yet — empty baseline
        target.write_text('const a: number = "x";\n', encoding="utf-8")
        diags = svc.get_diagnostics_sync(str(target))
    finally:
        svc.shutdown()

    assert [d.get("code") for d in diags] == ["MOCK001"]


def test_pre_existing_diagnostic_is_not_reported_as_introduced(monkeypatch, tmp_path):
    """The pre-edit baseline comes from the same first push, so an untouched error stays out."""
    repo = _mock_ts_repo(monkeypatch, tmp_path, "errors")
    target = repo / "old.ts"
    target.write_text("bad code\n", encoding="utf-8")
    svc = _service()
    try:
        svc.snapshot_baseline(str(target))
        target.write_text("bad code\n# unrelated change\n", encoding="utf-8")
        diags = svc.get_diagnostics_sync(str(target))
    finally:
        svc.shutdown()

    assert diags == []
