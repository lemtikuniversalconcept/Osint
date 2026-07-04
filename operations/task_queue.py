from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any

from operations.alerts import dispatch_pending_alerts
from operations.core import (
    DEFAULT_ORG_ID,
    add_brain_task,
    collect_all_sources,
    collect_from_source,
    db_connection,
    execute,
    generate_weekly_brief_file,
    now_iso,
    normalize_query,
    row_to_dict,
    rows,
    update_brain_task,
)


TASK_TYPES = {
    "collect_all",
    "collect_source",
    "repair_sources",
    "brief",
    "dispatch_alerts",
}

TASK_ALIASES = {
    "collect": "collect_all",
    "collection": "collect_all",
    "generate_brief": "brief",
    "briefs": "brief",
    "dispatch": "dispatch_alerts",
    "alerts": "dispatch_alerts",
    "repair": "repair_sources",
    "repair_sources": "repair_sources",
}

DEFAULT_POLL_SECONDS = int(os.getenv("LEMTIK_BRAIN_TASK_POLL_SECONDS", "5"))


@dataclass
class BrainTaskWorkerState:
    running: bool = False
    interval_seconds: int = DEFAULT_POLL_SECONDS
    org_id: str = DEFAULT_ORG_ID
    last_task_id: str = ""
    last_task_type: str = ""
    last_result: str = ""
    last_error: str = ""
    last_tick: str = ""


_worker_lock = threading.Lock()
_worker_thread: threading.Thread | None = None
_stop_event = threading.Event()
_state = BrainTaskWorkerState()


def _jsonish(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if not value:
        return {}
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return {}
    return value


def _is_missing_table_error(exc: Exception) -> bool:
    return exc.__class__.__name__ in {"UndefinedTable", "OperationalError"} and "brain_tasks" in str(exc).lower()


def brain_task_store_ready() -> bool:
    try:
        rows("select 1 from brain_tasks limit 1")
    except Exception as exc:
        if _is_missing_table_error(exc):
            return False
        raise
    return True


def _normalize_task_type(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9_]+", "_", value.strip().lower())
    return TASK_ALIASES.get(normalized, normalized)


def _task_result_to_json(result: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(result, default=str))


def queue_brain_task(
    *,
    org_id: str = DEFAULT_ORG_ID,
    task_type: str,
    payload: dict[str, Any] | None = None,
    priority: int = 5,
    requested_by: str = "",
) -> dict[str, Any]:
    task_type = _normalize_task_type(task_type)
    if task_type not in TASK_TYPES:
        raise ValueError(f"Unsupported brain task type: {task_type}")
    if not brain_task_store_ready():
        raise RuntimeError("brain_tasks table is missing. Run migrations/003_brain_tasks_queue.sql in Supabase first.")
    task_id = uuid.uuid4().hex[:12]
    add_brain_task(
        task_id=task_id,
        org_id=org_id,
        task_type=task_type,
        payload=payload or {},
        priority=priority,
        requested_by=requested_by,
    )
    return get_brain_task(task_id, org_id=org_id) or {
        "id": task_id,
        "org_id": org_id,
        "task_type": task_type,
        "status": "Pending",
        "priority": priority,
        "payload": payload or {},
        "requested_by": requested_by,
        "created_at": now_iso(),
    }


def get_brain_task(task_id: str, org_id: str | None = None) -> dict[str, Any] | None:
    filters = ["id = ?"]
    values: list[Any] = [task_id]
    if org_id:
        filters.append("org_id = ?")
        values.append(org_id)
    try:
        found = rows(
            f"select * from brain_tasks where {' and '.join(filters)} limit 1",
            tuple(values),
        )
    except Exception as exc:
        if _is_missing_table_error(exc):
            return None
        raise
    if not found:
        return None
    task = row_to_dict(found[0])
    task["payload"] = _jsonish(task.get("payload"))
    task["result"] = _jsonish(task.get("result"))
    return task


def list_brain_tasks(org_id: str = DEFAULT_ORG_ID, status: str = "", limit: int = 20) -> list[dict[str, Any]]:
    filters = ["org_id = ?"]
    values: list[Any] = [org_id]
    if status:
        filters.append("status = ?")
        values.append(status)
    try:
        tasks = rows(
            f"""
            select * from brain_tasks
            where {' and '.join(filters)}
            order by priority desc, created_at desc
            limit ?
            """,
            tuple(values + [limit]),
        )
    except Exception as exc:
        if _is_missing_table_error(exc):
            return []
        raise
    result: list[dict[str, Any]] = []
    for task in tasks:
        task_dict = row_to_dict(task)
        task_dict["payload"] = _jsonish(task_dict.get("payload"))
        task_dict["result"] = _jsonish(task_dict.get("result"))
        result.append(task_dict)
    return result


def _claim_task(task_id: str) -> bool:
    with db_connection() as con:
        cursor = con.cursor()
        cursor.execute(
            normalize_query(
                """
                update brain_tasks
                set status = ?, started_at = ?
                where id = ? and status = 'Pending'
                """
            ),
            ("Running", now_iso(), task_id),
        )
        updated = cursor.rowcount
        con.commit()
        return updated > 0


def _finish_task(task_id: str, status: str, *, result: dict[str, Any] | None = None, error: str = "") -> None:
    update_brain_task(
        task_id,
        status=status,
        result=_task_result_to_json(result or {}),
        error=error,
        finished_at=now_iso(),
    )


def _process_task(task: dict[str, Any]) -> dict[str, Any]:
    payload = task.get("payload") or {}
    if not isinstance(payload, dict):
        payload = {}
    org_id = str(task.get("org_id") or DEFAULT_ORG_ID)
    task_type = _normalize_task_type(str(task.get("task_type") or ""))
    extra_keywords = str(payload.get("extra_keywords") or "")
    source_id = payload.get("source_id")
    source_ids = payload.get("source_ids") or []
    days = int(payload.get("days") or 7)
    limit = int(payload.get("limit") or 20)

    if task_type == "collect_all":
        checked, created, skipped = collect_all_sources(extra_keywords, org_id)
        return {
            "task_type": task_type,
            "checked": checked,
            "created": created,
            "skipped": skipped,
        }

    if task_type == "collect_source":
        ids: list[int] = []
        if isinstance(source_ids, list):
            ids.extend(int(item) for item in source_ids if str(item).strip())
        if source_id not in {None, ""}:
            ids.insert(0, int(source_id))
        if not ids:
            checked, created, skipped = collect_all_sources(extra_keywords, org_id)
            return {
                "task_type": task_type,
                "mode": "fallback_collect_all",
                "checked": checked,
                "created": created,
                "skipped": skipped,
            }
        results: list[dict[str, Any]] = []
        for source in ids:
            checked, created, skipped = collect_from_source(int(source), extra_keywords, org_id)
            results.append(
                {
                    "source_id": int(source),
                    "checked": checked,
                    "created": created,
                    "skipped": skipped,
                }
            )
        return {"task_type": task_type, "sources": results}

    if task_type == "repair_sources":
        sources = [
            row_to_dict(row)
            for row in rows(
                """
                select id, name, url, credibility, last_checked_at, last_status, last_error
                from sources
                where org_id = ?
                and (last_checked_at = '' or last_checked_at is null or upper(coalesce(last_status, '')) = 'FAILED')
                order by
                  case when upper(coalesce(last_status, '')) = 'FAILED' then 0 else 1 end,
                  case when last_checked_at = '' or last_checked_at is null then 0 else 1 end,
                  credibility,
                  name
                """,
                (org_id,),
            )
        ]
        if not sources:
            checked, created, skipped = collect_all_sources(extra_keywords, org_id)
            return {
                "task_type": task_type,
                "mode": "fallback_collect_all",
                "checked": checked,
                "created": created,
                "skipped": skipped,
            }
        results: list[dict[str, Any]] = []
        for source in sources[: max(1, min(len(sources), 20))]:
            checked, created, skipped = collect_from_source(int(source["id"]), extra_keywords, org_id)
            results.append(
                {
                    "source_id": int(source["id"]),
                    "source": source["name"],
                    "checked": checked,
                    "created": created,
                    "skipped": skipped,
                }
            )
        return {"task_type": task_type, "sources": results}

    if task_type == "brief":
        path = generate_weekly_brief_file(days, org_id)
        return {"task_type": task_type, "days": days, "path": str(path)}

    if task_type == "dispatch_alerts":
        result = dispatch_pending_alerts(org_id, limit)
        return {"task_type": task_type, "limit": limit, "dispatch": result}

    raise ValueError(f"Unsupported brain task type: {task_type}")


def _worker_loop() -> None:
    while not _stop_event.is_set():
        task = get_next_pending_task()
        if task is None:
            _state.last_tick = now_iso()
            _stop_event.wait(max(1, _state.interval_seconds))
            continue
        if not _claim_task(str(task["id"])):
            continue
        try:
            result = _process_task(task)
            _state.last_task_id = str(task["id"])
            _state.last_task_type = str(task.get("task_type") or "")
            _state.last_result = json.dumps(result, default=str)[:1000]
            _state.last_error = ""
            _state.last_tick = now_iso()
            _finish_task(str(task["id"]), "Completed", result=result)
        except Exception as exc:
            message = str(exc)[:1000]
            _state.last_task_id = str(task["id"])
            _state.last_task_type = str(task.get("task_type") or "")
            _state.last_error = message
            _state.last_tick = now_iso()
            _finish_task(str(task["id"]), "Failed", error=message)


def get_next_pending_task(org_id: str | None = None) -> dict[str, Any] | None:
    if org_id:
        tasks = list_brain_tasks(org_id=org_id, status="Pending", limit=1)
    else:
        try:
            tasks = rows(
                """
                select * from brain_tasks
                where status = 'Pending'
                order by priority desc, created_at asc
                limit 1
                """,
            )
        except Exception as exc:
            if _is_missing_table_error(exc):
                return None
            raise
        tasks = [row_to_dict(task) for task in tasks]
    return tasks[0] if tasks else None


def start_brain_task_worker(org_id: str = DEFAULT_ORG_ID, interval_seconds: int | None = None) -> BrainTaskWorkerState:
    global _worker_thread
    with _worker_lock:
        if interval_seconds is not None:
            _state.interval_seconds = max(1, int(interval_seconds))
        _state.running = True
        _state.org_id = org_id or DEFAULT_ORG_ID
        _state.last_tick = now_iso()
        if _worker_thread is None or not _worker_thread.is_alive():
            _stop_event.clear()
            _worker_thread = threading.Thread(target=_worker_loop, name="lemtik-brain-task-worker", daemon=True)
            _worker_thread.start()
    return BrainTaskWorkerState(**_state.__dict__)


def stop_brain_task_worker() -> BrainTaskWorkerState:
    global _worker_thread
    with _worker_lock:
        _state.running = False
        _stop_event.set()
        _worker_thread = None
    return BrainTaskWorkerState(**_state.__dict__)


def brain_task_worker_state() -> BrainTaskWorkerState:
    return BrainTaskWorkerState(**_state.__dict__)
