"""Preservation-safe atomic Kanban archival contracts."""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc
from hermes_cli import kanban_db_notify as kbn
from hermes_cli import kanban_db_workspace as kbw
from hermes_cli.kanban_ops import _cmd_gc


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    return home


def _blocked(conn, task_id: str) -> None:
    conn.execute("UPDATE tasks SET status = 'blocked' WHERE id = ?", (task_id,))
    conn.commit()


def _archive_safely(conn, task_id: str) -> None:
    _blocked(conn, task_id)
    plan = kb.plan_preservation_safe_archive(conn, [task_id])
    kb.archive_tasks_preservation_safe(
        conn,
        plan["task_ids"],
        reason="SUPERSEDED_NO_EXECUTION",
        expected_dependency_token=plan["dependency_token"],
    )


def _run_gc() -> None:
    assert _cmd_gc(
        argparse.Namespace(event_retention_days=30, log_retention_days=30)
    ) == 0


def test_atomic_archive_preserves_evidence_workspaces_and_dependency_state(kanban_home):
    with kbc.connect_closing() as conn:
        root = kb.create_task(conn, title="superseded root", body="root evidence")
        child = kb.create_task(conn, title="stranded child", body="child evidence", parents=[root])
        protected = kb.create_task(conn, title="protected current task")
        unrelated = kb.create_task(conn, title="unrelated todo")
        _blocked(conn, root)
        _blocked(conn, child)
        conn.execute("UPDATE tasks SET status = 'todo' WHERE id = ?", (unrelated,))
        conn.commit()

        kb.add_comment(conn, root, "operator", "retain this comment")
        kb._append_event(conn, root, "historical_receipt", {"receipt": "retain"})
        conn.execute(
            "INSERT INTO task_runs "
            "(task_id, profile, status, started_at, ended_at, outcome, summary) "
            "VALUES (?, 'archive-worker', 'done', 1, 2, 'completed', 'retain run')",
            (root,),
        )
        conn.commit()
        kbn.add_notify_sub(
            conn,
            task_id=root,
            platform="telegram",
            chat_id="retain-chat",
            notifier_profile="archive-worker",
        )
        evidence = kanban_home / "evidence.txt"
        evidence.write_text("retain this attachment", encoding="utf-8")
        kb.add_attachment(
            conn,
            root,
            filename="evidence.txt",
            stored_path=str(evidence),
            size=evidence.stat().st_size,
        )
        workspace = kanban_home / "preserved-workspace"
        workspace.mkdir()
        (workspace / "receipt.txt").write_text("retain workspace", encoding="utf-8")
        conn.execute(
            "UPDATE tasks SET workspace_kind = 'scratch', workspace_path = ? WHERE id = ?",
            (str(workspace), root),
        )
        conn.commit()

        before = {
            "links": conn.execute("SELECT COUNT(*) FROM task_links").fetchone()[0],
            "comments": conn.execute("SELECT COUNT(*) FROM task_comments").fetchone()[0],
            "runs": conn.execute("SELECT COUNT(*) FROM task_runs").fetchone()[0],
            "attachments": conn.execute("SELECT COUNT(*) FROM task_attachments").fetchone()[0],
            "subscriptions": conn.execute("SELECT COUNT(*) FROM kanban_notify_subs").fetchone()[0],
        }
        historical_event = conn.execute(
            "SELECT id, payload FROM task_events "
            "WHERE task_id = ? AND kind = 'historical_receipt'",
            (root,),
        ).fetchone()
        plan = kb.plan_preservation_safe_archive(
            conn,
            [root, child],
            protected_task_ids=[protected],
        )

        assert plan["task_ids"] == [child, root]
        archived = kb.archive_tasks_preservation_safe(
            conn,
            plan["task_ids"],
            reason="SUPERSEDED_NO_EXECUTION",
            superseded_by=[protected],
            protected_task_ids=[protected],
            expected_dependency_token=plan["dependency_token"],
        )

        assert archived == [child, root]
        assert [kb.get_task(conn, tid).status for tid in (root, child)] == ["archived", "archived"]
        assert kb.get_task(conn, unrelated).status == "todo"
        assert workspace.is_dir()
        assert (workspace / "receipt.txt").read_text(encoding="utf-8") == "retain workspace"
        assert evidence.read_text(encoding="utf-8") == "retain this attachment"
        assert {
            "links": conn.execute("SELECT COUNT(*) FROM task_links").fetchone()[0],
            "comments": conn.execute("SELECT COUNT(*) FROM task_comments").fetchone()[0],
            "runs": conn.execute("SELECT COUNT(*) FROM task_runs").fetchone()[0],
            "attachments": conn.execute("SELECT COUNT(*) FROM task_attachments").fetchone()[0],
            "subscriptions": conn.execute("SELECT COUNT(*) FROM kanban_notify_subs").fetchone()[0],
        } == before
        assert conn.execute(
            "SELECT id, payload FROM task_events WHERE id = ?",
            (historical_event["id"],),
        ).fetchone() == historical_event
        assert [kb.get_task(conn, tid).body for tid in (root, child)] == [
            "root evidence",
            "child evidence",
        ]
        archive_events = conn.execute(
            "SELECT task_id, payload FROM task_events WHERE kind = 'archived_preservation_safe' "
            "AND task_id IN (?, ?) ORDER BY id",
            (root, child),
        ).fetchall()
        assert [row["task_id"] for row in archive_events] == [child, root]
        assert all(
            json.loads(row["payload"]) == {
                "reason": "SUPERSEDED_NO_EXECUTION",
                "superseded_by": [protected],
                "workspace_preserved": True,
            }
            for row in archive_events
        )


def test_atomic_archive_fails_closed_on_drift_boundaries_protection_and_write_failure(
    kanban_home, monkeypatch
):
    with kbc.connect_closing() as conn:
        root = kb.create_task(conn, title="root")
        child = kb.create_task(conn, title="child", parents=[root])
        protected = kb.create_task(conn, title="protected")
        _blocked(conn, root)
        _blocked(conn, child)
        plan = kb.plan_preservation_safe_archive(
            conn, [root, child], protected_task_ids=[protected]
        )

        outside = kb.create_task(conn, title="new live child", parents=[root])
        with pytest.raises(ValueError, match="dependency state changed since preflight"):
            kb.archive_tasks_preservation_safe(
                conn,
                [root, child],
                reason="SUPERSEDED_NO_EXECUTION",
                protected_task_ids=[protected],
                expected_dependency_token=plan["dependency_token"],
            )
        assert [kb.get_task(conn, tid).status for tid in (root, child)] == ["blocked", "blocked"]

        with pytest.raises(ValueError, match="non-terminal children outside the archive set"):
            kb.plan_preservation_safe_archive(
                conn, [root, child], protected_task_ids=[protected]
            )
        with pytest.raises(ValueError, match="protected task"):
            kb.plan_preservation_safe_archive(
                conn, [protected], protected_task_ids=[protected]
            )
        with pytest.raises(ValueError, match="unknown protected task"):
            kb.plan_preservation_safe_archive(
                conn, [root, child], protected_task_ids=["t_missing"]
            )

        conn.execute("UPDATE tasks SET status = 'done' WHERE id = ?", (outside,))
        conn.commit()
        retry_plan = kb.plan_preservation_safe_archive(
            conn, [root, child], protected_task_ids=[protected]
        )
        with pytest.raises(ValueError, match="superseding task ids must be protected"):
            kb.archive_tasks_preservation_safe(
                conn,
                retry_plan["task_ids"],
                reason="SUPERSEDED_NO_EXECUTION",
                superseded_by=[outside],
                protected_task_ids=[protected],
                expected_dependency_token=retry_plan["dependency_token"],
            )
        assert [kb.get_task(conn, tid).status for tid in (root, child)] == [
            "blocked",
            "blocked",
        ]

        original_append = kb._append_event
        calls = 0

        def fail_second_event(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("injected event failure")
            return original_append(*args, **kwargs)

        monkeypatch.setattr(kb, "_append_event", fail_second_event)
        with pytest.raises(RuntimeError, match="injected event failure"):
            kb.archive_tasks_preservation_safe(
                conn,
                [root, child],
                reason="SUPERSEDED_NO_EXECUTION",
                protected_task_ids=[protected],
                expected_dependency_token=retry_plan["dependency_token"],
            )
        assert [kb.get_task(conn, tid).status for tid in (root, child)] == ["blocked", "blocked"]
        assert conn.execute(
            "SELECT COUNT(*) FROM task_events WHERE kind = 'archived_preservation_safe'"
        ).fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM tasks WHERE preserve_from_gc != 0"
        ).fetchone()[0] == 0

        run = conn.execute(
            "INSERT INTO task_runs (task_id, status, started_at) VALUES (?, 'running', 1)",
            (root,),
        ).lastrowid
        conn.execute("UPDATE tasks SET current_run_id = ? WHERE id = ?", (run, root))
        conn.commit()
        with pytest.raises(ValueError, match="active run"):
            kb.plan_preservation_safe_archive(
                conn, [root, child], protected_task_ids=[protected]
            )


def test_preservation_safe_scratch_archive_survives_gc_without_weakening_legacy_gc(
    kanban_home,
):
    scratch_root = kb.workspaces_root()
    safe_workspace = scratch_root / "safe"
    legacy_workspace = scratch_root / "legacy"
    for workspace, receipt in (
        (safe_workspace, "safe receipt"),
        (legacy_workspace, "legacy receipt"),
    ):
        workspace.mkdir(parents=True)
        (workspace / "receipt.txt").write_text(receipt, encoding="utf-8")

    with kbc.connect_closing() as conn:
        safe = kb.create_task(conn, title="safe", body="retain body")
        legacy = kb.create_task(conn, title="legacy")
        child = kb.create_task(conn, title="completed child", parents=[safe])
        with kb.write_txn(conn):
            conn.execute("UPDATE tasks SET status='done' WHERE id=?", (child,))
            conn.execute(
                "UPDATE tasks SET workspace_kind='scratch', workspace_path=? WHERE id=?",
                (str(safe_workspace), safe),
            )
            conn.execute(
                "UPDATE tasks SET status='archived', workspace_kind='scratch', workspace_path=? "
                "WHERE id=?",
                (str(legacy_workspace), legacy),
            )
        kb.add_comment(conn, safe, "operator", "retain comment")
        kb._append_event(conn, safe, "historical_receipt", {"retain": True})
        kb._append_event(conn, legacy, "historical_receipt", {"retain": False})
        evidence = kanban_home / "safe-evidence.txt"
        evidence.write_text("retain evidence", encoding="utf-8")
        kb.add_attachment(
            conn,
            safe,
            filename=evidence.name,
            stored_path=str(evidence),
            size=evidence.stat().st_size,
        )
        conn.execute(
            "INSERT INTO task_runs (task_id, profile, status, started_at, ended_at, outcome) "
            "VALUES (?, 'worker', 'done', 1, 2, 'completed')",
            (safe,),
        )
        conn.commit()
        _archive_safely(conn, safe)
        old = int(time.time()) - 40 * 24 * 3600
        with kb.write_txn(conn):
            conn.execute(
                "UPDATE task_events SET created_at=? WHERE task_id IN (?, ?)",
                (old, safe, legacy),
            )
        safe_event_ids = [
            row["id"]
            for row in conn.execute(
                "SELECT id FROM task_events WHERE task_id=? ORDER BY id", (safe,)
            )
        ]

    _run_gc()

    assert (safe_workspace / "receipt.txt").read_text(encoding="utf-8") == "safe receipt"
    assert not legacy_workspace.exists()
    assert evidence.read_text(encoding="utf-8") == "retain evidence"
    with kbc.connect_closing() as conn:
        assert kb.get_task(conn, safe).body == "retain body"
        assert conn.execute(
            "SELECT preserve_from_gc FROM tasks WHERE id=?", (safe,)
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT preserve_from_gc FROM tasks WHERE id=?", (legacy,)
        ).fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM task_comments WHERE task_id=?", (safe,)
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM task_runs WHERE task_id=?", (safe,)
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM task_links WHERE parent_id=?", (safe,)
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM task_attachments WHERE task_id=?", (safe,)
        ).fetchone()[0] == 1
        assert [
            row["id"]
            for row in conn.execute(
                "SELECT id FROM task_events WHERE task_id=? ORDER BY id", (safe,)
            )
        ] == safe_event_ids
        assert conn.execute(
            "SELECT COUNT(*) FROM task_events "
            "WHERE task_id=? AND kind='historical_receipt'",
            (legacy,),
        ).fetchone()[0] == 0
        with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
            conn.execute(
                "UPDATE tasks SET preserve_from_gc=2 WHERE id=?", (safe,)
            )


def test_preservation_safe_worktree_archive_is_excluded_from_gc_cleanup(
    kanban_home, monkeypatch
):
    safe_workspace = kanban_home / "safe-worktree"
    legacy_workspace = kanban_home / "legacy-worktree"
    for workspace in (safe_workspace, legacy_workspace):
        workspace.mkdir()
        (workspace / "receipt.txt").write_text(
            "retain until GC policy", encoding="utf-8"
        )

    with kbc.connect_closing() as conn:
        safe = kb.create_task(conn, title="safe worktree")
        legacy = kb.create_task(conn, title="legacy worktree")
        with kb.write_txn(conn):
            conn.execute(
                "UPDATE tasks SET workspace_kind='worktree', workspace_path=? WHERE id=?",
                (str(safe_workspace), safe),
            )
            conn.execute(
                "UPDATE tasks SET status='archived', workspace_kind='worktree', workspace_path=? "
                "WHERE id=?",
                (str(legacy_workspace), legacy),
            )
        _archive_safely(conn, safe)

    cleaned: list[str] = []

    def cleanup(task_id: str, path: str, branch_name=None) -> None:
        cleaned.append(task_id)
        shutil.rmtree(path)

    monkeypatch.setattr(kbw, "_cleanup_worktree_workspace", cleanup)
    _run_gc()

    assert safe_workspace.is_dir()
    assert (safe_workspace / "receipt.txt").is_file()
    assert not legacy_workspace.exists()
    assert cleaned == [legacy]


@pytest.mark.parametrize("workspace_kind", ["scratch", "worktree"])
def test_terminal_child_cleanup_preserves_preservation_safe_parent_workspace(
    kanban_home, monkeypatch, workspace_kind
):
    workspace = (
        kb.workspaces_root() / "safe-parent"
        if workspace_kind == "scratch"
        else kanban_home / "safe-parent-worktree"
    )
    workspace.mkdir(parents=True)
    receipt = workspace / "receipt.txt"
    receipt.write_text("retain parent evidence", encoding="utf-8")
    cleaned: list[str] = []

    if workspace_kind == "worktree":
        def cleanup(task_id: str, path: str, branch_name=None) -> None:
            cleaned.append(task_id)
            shutil.rmtree(path)

        monkeypatch.setattr(kbw, "_cleanup_worktree_workspace", cleanup)

    with kbc.connect_closing() as conn:
        parent = kb.create_task(conn, title="preservation-safe parent")
        child = kb.create_task(conn, title="terminal child", parents=[parent])
        with kb.write_txn(conn):
            conn.execute("UPDATE tasks SET status='done' WHERE id=?", (child,))
            conn.execute(
                "UPDATE tasks SET workspace_kind=?, workspace_path=? WHERE id=?",
                (workspace_kind, str(workspace), parent),
            )

        _archive_safely(conn, parent)
        assert conn.execute(
            "SELECT preserve_from_gc FROM tasks WHERE id=?", (parent,)
        ).fetchone()[0] == 1

        assert kb.archive_task(conn, child)
        assert conn.execute(
            "SELECT preserve_from_gc FROM tasks WHERE id=?", (parent,)
        ).fetchone()[0] == 1

    assert receipt.read_text(encoding="utf-8") == "retain parent evidence"
    assert cleaned == []


@pytest.mark.parametrize("workspace_kind", ["scratch", "worktree"])
def test_terminal_child_cleanup_still_reaps_legacy_parent_workspace(
    kanban_home, monkeypatch, workspace_kind
):
    workspace = (
        kb.workspaces_root() / "legacy-parent"
        if workspace_kind == "scratch"
        else kanban_home / "legacy-parent-worktree"
    )
    workspace.mkdir(parents=True)
    (workspace / "receipt.txt").write_text("legacy evidence", encoding="utf-8")
    cleaned: list[str] = []

    if workspace_kind == "worktree":
        def cleanup(task_id: str, path: str, branch_name=None) -> None:
            cleaned.append(task_id)
            shutil.rmtree(path)

        monkeypatch.setattr(kbw, "_cleanup_worktree_workspace", cleanup)

    with kbc.connect_closing() as conn:
        parent = kb.create_task(conn, title="legacy parent")
        child = kb.create_task(conn, title="active child", parents=[parent])
        with kb.write_txn(conn):
            conn.execute(
                "UPDATE tasks SET workspace_kind=?, workspace_path=? WHERE id=?",
                (workspace_kind, str(workspace), parent),
            )

        assert kb.archive_task(conn, parent)
        assert workspace.is_dir(), "active child must defer parent cleanup"
        assert kb.archive_task(conn, child)

    assert not workspace.exists()
    assert cleaned == ([parent] if workspace_kind == "worktree" else [])


@pytest.mark.parametrize("cleanup_mode", ["direct", "deferred"])
@pytest.mark.parametrize("workspace_kind", ["scratch", "worktree"])
def test_cleanup_and_preservation_safe_archive_have_one_serialized_winner(
    kanban_home, monkeypatch, cleanup_mode, workspace_kind
):
    workspace = (
        kb.workspaces_root() / f"race-{cleanup_mode}-{workspace_kind}"
        if workspace_kind == "scratch"
        else kanban_home / f"race-{cleanup_mode}-{workspace_kind}"
    )
    workspace.mkdir(parents=True)
    receipt = workspace / "receipt.txt"
    receipt.write_text("must not be deleted after preservation wins", encoding="utf-8")

    with kbc.connect_closing() as conn:
        parent = kb.create_task(conn, title="cleanup race parent")
        child = (
            kb.create_task(conn, title="cleanup race child", parents=[parent])
            if cleanup_mode == "deferred"
            else None
        )
        with kb.write_txn(conn):
            conn.execute(
                "UPDATE tasks SET status=?, workspace_kind=?, workspace_path=? WHERE id=?",
                (
                    "blocked" if child else "done",
                    workspace_kind,
                    str(workspace),
                    parent,
                ),
            )
            if child:
                conn.execute("UPDATE tasks SET status='done' WHERE id=?", (child,))

    cleanup_authorized = threading.Event()
    release_cleanup = threading.Event()
    cleanup_finished = threading.Event()
    archive_finished = threading.Event()
    errors: list[BaseException] = []
    archive_result: list[str] = []
    original_has_active = kbw._has_active_children

    def gated_has_active(conn, task_id: str) -> bool:
        if task_id == parent:
            cleanup_authorized.set()
            if not release_cleanup.wait(10):
                raise TimeoutError("cleanup race gate was not released")
        return original_has_active(conn, task_id)

    def destructive_worktree_cleanup(task_id: str, path: str, branch_name=None) -> None:
        shutil.rmtree(path)

    monkeypatch.setattr(kbw, "_has_active_children", gated_has_active)
    if workspace_kind == "worktree":
        monkeypatch.setattr(kbw, "_cleanup_worktree_workspace", destructive_worktree_cleanup)

    def cleanup() -> None:
        try:
            with kbc.connect_closing() as conn:
                if child:
                    assert kb.archive_task(conn, child)
                else:
                    kbw._cleanup_workspace(conn, parent)
        except BaseException as exc:  # pragma: no cover - assertion reports it
            errors.append(exc)
        finally:
            cleanup_finished.set()

    def archive_safely() -> None:
        try:
            with kbc.connect_closing() as conn:
                plan = kb.plan_preservation_safe_archive(conn, [parent])
                archive_result.extend(
                    kb.archive_tasks_preservation_safe(
                        conn,
                        plan["task_ids"],
                        reason="RACE_REGRESSION",
                        expected_dependency_token=plan["dependency_token"],
                    )
                )
        except (ValueError, RuntimeError):
            pass
        except BaseException as exc:  # pragma: no cover - assertion reports it
            errors.append(exc)
        finally:
            archive_finished.set()

    cleanup_thread = threading.Thread(target=cleanup)
    archive_thread = threading.Thread(target=archive_safely)
    cleanup_thread.start()
    assert cleanup_authorized.wait(10)
    archive_thread.start()
    try:
        # A cleanup holding authorization must either exclude the safe commit,
        # or lose to preservation before deleting any bytes.
        archive_finished.wait(0.2)
    finally:
        release_cleanup.set()
    assert cleanup_finished.wait(10)
    assert archive_finished.wait(10)
    cleanup_thread.join(timeout=1)
    archive_thread.join(timeout=1)
    assert not errors

    with kbc.connect_closing() as conn:
        marker = conn.execute(
            "SELECT preserve_from_gc FROM tasks WHERE id=?", (parent,)
        ).fetchone()[0]
    if archive_result:
        assert archive_result == [parent]
        assert marker == 1
        assert receipt.read_text(encoding="utf-8") == (
            "must not be deleted after preservation wins"
        )
    else:
        assert marker == 0
        assert not workspace.exists()


@pytest.mark.parametrize("cleanup_mode", ["direct", "deferred"])
@pytest.mark.parametrize("workspace_kind", ["scratch", "worktree"])
def test_preservation_commit_wins_before_cleanup_authorization(
    kanban_home, monkeypatch, cleanup_mode, workspace_kind
):
    workspace = (
        kb.workspaces_root() / f"preserve-wins-{cleanup_mode}-{workspace_kind}"
        if workspace_kind == "scratch"
        else kanban_home / f"preserve-wins-{cleanup_mode}-{workspace_kind}"
    )
    workspace.mkdir(parents=True)
    receipt = workspace / "receipt.txt"
    receipt.write_text("preservation won", encoding="utf-8")

    with kbc.connect_closing() as conn:
        parent = kb.create_task(conn, title="preservation winner")
        child = (
            kb.create_task(conn, title="cleanup trigger", parents=[parent])
            if cleanup_mode == "deferred"
            else None
        )
        with kb.write_txn(conn):
            conn.execute(
                "UPDATE tasks SET status='blocked', workspace_kind=?, workspace_path=? "
                "WHERE id=?",
                (workspace_kind, str(workspace), parent),
            )
            if child:
                conn.execute("UPDATE tasks SET status='done' WHERE id=?", (child,))
        plan = kb.plan_preservation_safe_archive(conn, [parent])

    archive_has_write_lock = threading.Event()
    release_archive = threading.Event()
    cleanup_finished = threading.Event()
    errors: list[BaseException] = []
    original_append = kb._append_event

    def gated_append(conn, task_id, kind, payload, **kwargs):
        result = original_append(conn, task_id, kind, payload, **kwargs)
        if task_id == parent and kind == "archived_preservation_safe":
            archive_has_write_lock.set()
            if not release_archive.wait(10):
                raise TimeoutError("archive race gate was not released")
        return result

    def destructive_worktree_cleanup(task_id: str, path: str, branch_name=None) -> None:
        shutil.rmtree(path)

    monkeypatch.setattr(kb, "_append_event", gated_append)
    if workspace_kind == "worktree":
        monkeypatch.setattr(kbw, "_cleanup_worktree_workspace", destructive_worktree_cleanup)

    def archive_safely() -> None:
        try:
            with kbc.connect_closing() as conn:
                kb.archive_tasks_preservation_safe(
                    conn,
                    plan["task_ids"],
                    reason="RACE_REGRESSION",
                    expected_dependency_token=plan["dependency_token"],
                )
        except BaseException as exc:  # pragma: no cover - assertion reports it
            errors.append(exc)

    def cleanup() -> None:
        try:
            with kbc.connect_closing() as conn:
                if child:
                    assert kb.archive_task(conn, child)
                else:
                    kbw._cleanup_workspace(conn, parent)
        except BaseException as exc:  # pragma: no cover - assertion reports it
            errors.append(exc)
        finally:
            cleanup_finished.set()

    archive_thread = threading.Thread(target=archive_safely)
    cleanup_thread = threading.Thread(target=cleanup)
    archive_thread.start()
    assert archive_has_write_lock.wait(10)
    cleanup_thread.start()
    try:
        assert not cleanup_finished.wait(0.2)
    finally:
        release_archive.set()
    archive_thread.join(timeout=10)
    cleanup_thread.join(timeout=10)
    assert not archive_thread.is_alive()
    assert not cleanup_thread.is_alive()
    assert not errors
    assert receipt.read_text(encoding="utf-8") == "preservation won"
    with kbc.connect_closing() as conn:
        markers = conn.execute(
            "SELECT preserve_from_gc, workspace_cleaned FROM tasks WHERE id=?",
            (parent,),
        ).fetchone()
    assert tuple(markers) == (1, 0)


def test_declined_worktree_cleanup_can_be_retried_without_disabling_preservation(
    kanban_home, monkeypatch
):
    workspace = kanban_home / "retry-worktree"
    workspace.mkdir()
    (workspace / "receipt.txt").write_text("retry me", encoding="utf-8")
    with kbc.connect_closing() as conn:
        task_id = kb.create_task(conn, title="retry worktree cleanup")
        with kb.write_txn(conn):
            conn.execute(
                "UPDATE tasks SET status='done', workspace_kind='worktree', "
                "workspace_path=? WHERE id=?",
                (str(workspace), task_id),
            )

    attempts = 0

    def cleanup(
        task_id: str, path: str, branch_name=None
    ) -> kbw.WorkspaceCleanupResult:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return kbw.WorkspaceCleanupResult.DECLINED_BEFORE_MUTATION
        shutil.rmtree(path)
        return kbw.WorkspaceCleanupResult.MUTATION_MAY_HAVE_STARTED

    monkeypatch.setattr(kbw, "_cleanup_worktree_workspace", cleanup)
    with kbc.connect_closing() as conn:
        kbw._cleanup_workspace(conn, task_id)
        first_markers = conn.execute(
            "SELECT preserve_from_gc, workspace_cleaned FROM tasks WHERE id=?",
            (task_id,),
        ).fetchone()
        assert tuple(first_markers) == (0, 0)
        assert workspace.is_dir()

        kbw._cleanup_workspace(conn, task_id)
        second_markers = conn.execute(
            "SELECT preserve_from_gc, workspace_cleaned FROM tasks WHERE id=?",
            (task_id,),
        ).fetchone()

    assert attempts == 2
    assert tuple(second_markers) == (0, 1)
    assert not workspace.exists()


def test_failed_worktree_remove_keeps_cleanup_intent_after_partial_mutation(
    kanban_home, monkeypatch
):
    workspace = kanban_home / "partial-worktree"
    workspace.mkdir()
    receipt = workspace / "receipt.txt"
    receipt.write_text("preservation evidence", encoding="utf-8")
    repo = kanban_home / "repo"
    (repo / ".git").mkdir(parents=True)

    with kbc.connect_closing() as conn:
        task_id = kb.create_task(conn, title="partial worktree cleanup")
        with kb.write_txn(conn):
            conn.execute(
                "UPDATE tasks SET status='done', workspace_kind='worktree', "
                "workspace_path=? WHERE id=?",
                (str(workspace), task_id),
            )

    from hermes_cli import worktree_ops

    monkeypatch.setattr(worktree_ops, "_worktree_is_dirty", lambda path: False)
    monkeypatch.setattr(worktree_ops, "_worktree_has_unpushed_commits", lambda path: False)
    monkeypatch.setattr(kbw, "_git_common_dir", lambda path: repo / ".git")

    def partial_remove(repo_root, *args, timeout):
        receipt.unlink()
        return SimpleNamespace(returncode=1, stderr="partial removal", stdout="")

    monkeypatch.setattr(kbw, "_git", partial_remove)

    with kbc.connect_closing() as conn:
        kbw._cleanup_workspace(conn, task_id)
        markers = tuple(
            conn.execute(
                "SELECT preserve_from_gc, workspace_cleaned FROM tasks WHERE id=?",
                (task_id,),
            ).fetchone()
        )
        with pytest.raises(ValueError, match="workspace cleanup"):
            kb.plan_preservation_safe_archive(conn, [task_id])

    assert markers == (0, 1)
    assert workspace.is_dir()
    assert not receipt.exists()


@pytest.mark.parametrize("replacement", ["same", "different"])
def test_workspace_path_setter_cannot_cancel_inflight_cleanup(
    kanban_home, monkeypatch, replacement
):
    workspace = kb.workspaces_root() / f"setter-race-{replacement}"
    workspace.mkdir(parents=True)
    receipt = workspace / "receipt.txt"
    receipt.write_text("preservation evidence", encoding="utf-8")
    other = kb.workspaces_root() / f"replacement-{replacement}"

    with kbc.connect_closing() as conn:
        task_id = kb.create_task(conn, title="setter cleanup race")
        with kb.write_txn(conn):
            conn.execute(
                "UPDATE tasks SET status='done', workspace_kind='scratch', "
                "workspace_path=? WHERE id=?",
                (str(workspace), task_id),
            )

    entered_delete = threading.Event()
    release_delete = threading.Event()
    original_rmtree = kbw.shutil.rmtree

    def gated_rmtree(path, *args, **kwargs):
        entered_delete.set()
        assert release_delete.wait(10)
        return original_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(kbw.shutil, "rmtree", gated_rmtree)
    errors: list[BaseException] = []

    def cleanup() -> None:
        try:
            with kbc.connect_closing() as conn:
                kbw._cleanup_workspace(conn, task_id)
        except BaseException as exc:  # pragma: no cover - assertion reports it
            errors.append(exc)

    cleanup_thread = threading.Thread(target=cleanup)
    cleanup_thread.start()
    assert entered_delete.wait(10)
    try:
        with kbc.connect_closing() as conn:
            target = workspace if replacement == "same" else other
            with pytest.raises(RuntimeError, match="cleanup already started"):
                kbw.set_workspace_path(conn, task_id, target)
            assert tuple(
                conn.execute(
                    "SELECT preserve_from_gc, workspace_cleaned FROM tasks WHERE id=?",
                    (task_id,),
                ).fetchone()
            ) == (0, 1)
            with pytest.raises(ValueError, match="workspace cleanup"):
                kb.plan_preservation_safe_archive(conn, [task_id])
    finally:
        release_delete.set()
        cleanup_thread.join(timeout=10)

    assert not cleanup_thread.is_alive()
    assert not errors
    assert not workspace.exists()
