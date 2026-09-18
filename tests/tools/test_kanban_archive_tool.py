"""Model-tool coverage for preservation-safe Kanban archival."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def worker_env(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_PROFILE", "archive-worker")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    from hermes_cli import kanban_db as kb
    from hermes_cli import kanban_db_connect as kbc

    kb._INITIALIZED_PATHS.clear()
    kb.init_db()
    with kbc.connect_closing() as conn:
        worker = kb.create_task(conn, title="archive board hygiene", assignee="archive-worker")
        kb.claim_task(conn, worker)
        root = kb.create_task(conn, title="superseded root")
        child = kb.create_task(conn, title="stranded child", parents=[root])
        protected = kb.create_task(conn, title="current replacement")
        conn.execute("UPDATE tasks SET status = 'blocked' WHERE id IN (?, ?)", (root, child))
        conn.commit()
    monkeypatch.setenv("HERMES_KANBAN_TASK", worker)
    return root, child, protected


def test_kanban_archive_tool_is_orchestrator_only_and_commits_reviewed_set(
    worker_env, monkeypatch
):
    import tools.kanban_tools  # noqa: F401 -- registers the model tool
    from tools.registry import registry
    from hermes_cli import kanban_db as kb
    from hermes_cli import kanban_db_connect as kbc

    root, child, protected = worker_env
    args = {
        "action": "preflight",
        "task_ids": [root, child],
        "protected_task_ids": [protected],
    }
    worker_rejection = json.loads(registry.dispatch("kanban_archive", args))
    assert "orchestrator-only" in worker_rejection["error"]

    monkeypatch.delenv("HERMES_KANBAN_TASK")
    plan = json.loads(registry.dispatch("kanban_archive", args))
    assert plan["ok"] is True
    assert plan["task_ids"] == [child, root]
    assert len(plan["dependency_token"]) == 64

    result = json.loads(registry.dispatch("kanban_archive", {
        **args,
        "action": "commit",
        "reason": "SUPERSEDED_NO_EXECUTION",
        "superseded_by": [protected],
        "expected_dependency_token": plan["dependency_token"],
    }))
    assert result == {
        "ok": True,
        "archived_task_ids": [child, root],
        "count": 2,
        "workspace_preserved": True,
    }
    with kbc.connect_closing() as conn:
        assert [kb.get_task(conn, tid).status for tid in (root, child)] == [
            "archived",
            "archived",
        ]
