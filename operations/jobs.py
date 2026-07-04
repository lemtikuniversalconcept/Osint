from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass
from typing import Callable

from operations.core import now_iso


@dataclass
class JobStatus:
    id: str
    name: str
    status: str
    started_at: str
    finished_at: str = ""
    result: str = ""
    error: str = ""


_jobs: dict[str, JobStatus] = {}
_lock = threading.Lock()


def start_job(name: str, target: Callable[[], str | None]) -> JobStatus:
    job = JobStatus(id=uuid.uuid4().hex[:12], name=name, status="Running", started_at=now_iso())
    with _lock:
        _jobs[job.id] = job

    def runner() -> None:
        try:
            result = target()
            with _lock:
                job.status = "Completed"
                job.result = result or "Completed."
                job.finished_at = now_iso()
        except Exception as exc:
            with _lock:
                job.status = "Failed"
                job.error = str(exc)[:500]
                job.finished_at = now_iso()

    thread = threading.Thread(target=runner, name=f"lemtik-job-{job.id}", daemon=True)
    thread.start()
    return job


def recent_jobs(limit: int = 8) -> list[JobStatus]:
    with _lock:
        jobs = sorted(_jobs.values(), key=lambda item: item.started_at, reverse=True)
        return [JobStatus(**job.__dict__) for job in jobs[:limit]]
