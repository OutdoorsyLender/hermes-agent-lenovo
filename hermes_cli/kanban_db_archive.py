"""Atomic, preservation-safe archival for reviewed Kanban task sets.

This path deliberately does not reuse ``archive_task``: legacy archival
recomputes child readiness and removes managed workspaces after each task.
The operation here binds an explicit set to a preflight token, validates its
open dependency boundary, and changes every selected row in one transaction.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Iterable
from typing import Any


_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
_TERMINAL_STATUSES = frozenset({"done", "archived"})


def _ids(values: Iterable[str], *, label: str) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        task_id = str(value or "").strip()
        if not task_id:
            raise ValueError(f"{label} cannot contain a blank task id")
        if task_id not in seen:
            seen.add(task_id)
            result.append(task_id)
    return result


def _rows_for_ids(
    conn: sqlite3.Connection, task_ids: list[str]
) -> dict[str, sqlite3.Row]:
    placeholders = ",".join("?" for _ in task_ids)
    rows = conn.execute(
        f"SELECT t.id, t.status, t.current_run_id, t.workspace_cleaned, "
        f"r.status AS current_run_status "
        f"FROM tasks t LEFT JOIN task_runs r ON r.id = t.current_run_id "
        f"WHERE t.id IN ({placeholders})",
        task_ids,
    ).fetchall()
    return {row["id"]: row for row in rows}


def _archive_snapshot(
    conn: sqlite3.Connection,
    task_ids: list[str],
    protected_task_ids: list[str],
) -> tuple[dict[str, Any], dict[str, sqlite3.Row], list[sqlite3.Row]]:
    selected_rows = _rows_for_ids(conn, task_ids)
    missing = [task_id for task_id in task_ids if task_id not in selected_rows]
    if missing:
        raise ValueError("unknown archive task ids: " + ", ".join(missing))
    if protected_task_ids:
        protected_rows = _rows_for_ids(conn, protected_task_ids)
        missing_protected = [
            task_id for task_id in protected_task_ids if task_id not in protected_rows
        ]
        if missing_protected:
            raise ValueError(
                "unknown protected task ids: " + ", ".join(missing_protected)
            )

    placeholders = ",".join("?" for _ in task_ids)
    links = conn.execute(
        f"SELECT parent_id, child_id FROM task_links "
        f"WHERE parent_id IN ({placeholders}) OR child_id IN ({placeholders}) "
        "ORDER BY parent_id, child_id",
        (*task_ids, *task_ids),
    ).fetchall()
    related_ids = sorted(
        set(task_ids)
        | {row["parent_id"] for row in links}
        | {row["child_id"] for row in links}
    )
    related_rows = _rows_for_ids(conn, related_ids)
    snapshot = {
        "selected": sorted(task_ids),
        "protected": sorted(protected_task_ids),
        "tasks": [
            {
                "id": task_id,
                "status": related_rows[task_id]["status"],
                "current_run_id": related_rows[task_id]["current_run_id"],
                "current_run_status": related_rows[task_id]["current_run_status"],
                "workspace_cleaned": related_rows[task_id]["workspace_cleaned"],
            }
            for task_id in related_ids
        ],
        "links": [
            [row["parent_id"], row["child_id"]]
            for row in links
        ],
    }
    return snapshot, selected_rows, links


def _snapshot_token(snapshot: dict[str, Any]) -> str:
    encoded = json.dumps(
        snapshot,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _descendants_first(task_ids: list[str], links: list[sqlite3.Row]) -> list[str]:
    selected = set(task_ids)
    children: dict[str, list[str]] = {task_id: [] for task_id in task_ids}
    position = {task_id: index for index, task_id in enumerate(task_ids)}
    for row in links:
        parent_id, child_id = row["parent_id"], row["child_id"]
        if parent_id in selected and child_id in selected:
            children[parent_id].append(child_id)
    for values in children.values():
        values.sort(key=position.__getitem__)

    ordered: list[str] = []
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(task_id: str) -> None:
        if task_id in visiting:
            raise ValueError("archive task set contains a dependency cycle")
        if task_id in visited:
            return
        visiting.add(task_id)
        for child_id in children[task_id]:
            visit(child_id)
        visiting.remove(task_id)
        visited.add(task_id)
        ordered.append(task_id)

    for task_id in task_ids:
        visit(task_id)
    return ordered


def _validate_archive_snapshot(
    snapshot: dict[str, Any],
    selected_rows: dict[str, sqlite3.Row],
    links: list[sqlite3.Row],
) -> list[str]:
    selected = set(snapshot["selected"])
    protected = selected.intersection(snapshot["protected"])
    if protected:
        raise ValueError("archive set includes protected task ids: " + ", ".join(sorted(protected)))

    archived = sorted(
        task_id for task_id, row in selected_rows.items() if row["status"] == "archived"
    )
    if archived:
        raise ValueError("archive set contains already archived task ids: " + ", ".join(archived))
    running = sorted(
        task_id for task_id, row in selected_rows.items() if row["status"] == "running"
    )
    if running:
        raise ValueError("archive set contains running task ids: " + ", ".join(running))
    active_runs = sorted(
        task_id
        for task_id, row in selected_rows.items()
        if row["current_run_status"] == "running"
    )
    if active_runs:
        raise ValueError("archive set contains task ids with an active run: " + ", ".join(active_runs))
    cleaned_workspaces = sorted(
        task_id
        for task_id, row in selected_rows.items()
        if row["workspace_cleaned"]
    )
    if cleaned_workspaces:
        raise ValueError(
            "archive set contains task ids whose workspace cleanup already started: "
            + ", ".join(cleaned_workspaces)
        )

    status_by_id = {row["id"]: row["status"] for row in snapshot["tasks"]}
    open_boundary = sorted(
        (row["parent_id"], row["child_id"])
        for row in links
        if row["parent_id"] in selected
        and row["child_id"] not in selected
        and status_by_id[row["child_id"]] not in _TERMINAL_STATUSES
    )
    if open_boundary:
        rendered = ", ".join(f"{parent}->{child}" for parent, child in open_boundary)
        raise ValueError(
            "archive set has non-terminal children outside the archive set: " + rendered
        )

    return _descendants_first(list(snapshot["selected"]), links)


def plan_preservation_safe_archive(
    conn: sqlite3.Connection,
    task_ids: Iterable[str],
    *,
    protected_task_ids: Iterable[str] = (),
) -> dict[str, Any]:
    """Return a reviewed-set plan and dependency token without changing state.

    Execution must supply the token to :func:`archive_tasks_preservation_safe`.
    The token binds selected/protected IDs, statuses, active-run identities and
    every dependency edge incident to the selected set.
    """
    selected = _ids(task_ids, label="task_ids")
    if not selected:
        raise ValueError("at least one task id is required")
    protected = _ids(protected_task_ids, label="protected_task_ids")
    snapshot, selected_rows, links = _archive_snapshot(conn, selected, protected)
    ordered = _validate_archive_snapshot(snapshot, selected_rows, links)
    return {
        "task_ids": ordered,
        "protected_task_ids": protected,
        "dependency_token": _snapshot_token(snapshot),
    }


def archive_tasks_preservation_safe(
    conn: sqlite3.Connection,
    task_ids: Iterable[str],
    *,
    reason: str,
    expected_dependency_token: str,
    superseded_by: Iterable[str] = (),
    protected_task_ids: Iterable[str] = (),
) -> list[str]:
    """Archive an explicit reviewed set atomically without evidence cleanup.

    No task body, comment, prior event, run, dependency link, attachment,
    notification subscription, attachment file or workspace is removed. The
    operation never recomputes readiness; its closed-boundary check guarantees
    that archival cannot release a non-terminal child outside the set.
    """
    from hermes_cli import kanban_db as _kb

    selected = _ids(task_ids, label="task_ids")
    if not selected:
        raise ValueError("at least one task id is required")
    protected = _ids(protected_task_ids, label="protected_task_ids")
    successors = _ids(superseded_by, label="superseded_by")
    unprotected_successors = sorted(set(successors).difference(protected))
    if unprotected_successors:
        raise ValueError(
            "superseding task ids must be protected during preflight: "
            + ", ".join(unprotected_successors)
        )
    reason = str(reason or "").strip()
    if not reason:
        raise ValueError("archive reason is required")
    token = str(expected_dependency_token or "").strip().lower()
    if not _TOKEN_RE.fullmatch(token):
        raise ValueError("expected_dependency_token must be a 64-character SHA-256 token")

    with _kb.write_txn(conn):
        snapshot, selected_rows, links = _archive_snapshot(conn, selected, protected)
        if _snapshot_token(snapshot) != token:
            raise ValueError("dependency state changed since preflight")
        ordered = _validate_archive_snapshot(snapshot, selected_rows, links)
        missing_successors = [
            task_id for task_id in successors if _kb.get_task(conn, task_id) is None
        ]
        if missing_successors:
            raise ValueError("unknown superseding task ids: " + ", ".join(missing_successors))

        payload = {
            "reason": reason,
            "superseded_by": successors,
            "workspace_preserved": True,
        }
        for task_id in ordered:
            changed = conn.execute(
                "UPDATE tasks SET status = 'archived', claim_lock = NULL, "
                "claim_expires = NULL, worker_pid = NULL, preserve_from_gc = 1 "
                "WHERE id = ? AND status != 'archived' AND status != 'running' "
                "AND workspace_cleaned = 0",
                (task_id,),
            )
            if changed.rowcount != 1:
                raise RuntimeError(f"archive compare-and-swap failed for {task_id}")
            _kb._append_event(
                conn,
                task_id,
                "archived_preservation_safe",
                payload,
            )
    return ordered
