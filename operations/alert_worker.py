from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass

from operations.alerts import dispatch_pending_alerts
from operations.core import DEFAULT_ORG_ID, now_iso


@dataclass
class AlertWorkerState:
    enabled: bool = False
    running: bool = False
    interval_seconds: int = 60
    org_id: str = DEFAULT_ORG_ID
    last_run_at: str = ""
    last_result: str = "Not run yet"
    last_error: str = ""


state = AlertWorkerState()
_lock = threading.Lock()
_started = False
_stop = threading.Event()


def _configured_interval() -> int:
    raw = os.getenv("LEMTIK_ALERT_WORKER_INTERVAL_SECONDS", "60").strip()
    try:
        return max(10, int(raw))
    except ValueError:
        return 60


def _loop(org_id: str, interval_seconds: int, limit: int) -> None:
    with _lock:
        state.enabled = True
        state.running = True
        state.org_id = org_id
        state.interval_seconds = interval_seconds
        state.last_error = ""

    while not _stop.is_set():
        try:
            result = dispatch_pending_alerts(org_id, limit)
            with _lock:
                state.last_run_at = now_iso()
                state.last_result = f"Pending {result['pending']}, sent {result['sent']}, failed {result['failed']}."
                state.last_error = ""
        except Exception as exc:
            with _lock:
                state.last_run_at = now_iso()
                state.last_error = str(exc)[:500]
        _stop.wait(interval_seconds)

    with _lock:
        state.running = False
        state.enabled = False


def start_alert_worker(org_id: str = DEFAULT_ORG_ID, interval_seconds: int | None = None, limit: int = 20) -> AlertWorkerState:
    global _started
    with _lock:
        if _started and state.running:
            return AlertWorkerState(**state.__dict__)
        _started = True
        _stop.clear()

    interval = interval_seconds or _configured_interval()
    thread = threading.Thread(target=_loop, args=(org_id, interval, limit), name="lemtik-alert-worker", daemon=True)
    thread.start()
    return get_alert_worker_state()


def stop_alert_worker() -> AlertWorkerState:
    global _started
    _stop.set()
    _started = False
    with _lock:
        state.enabled = False
    return AlertWorkerState(**state.__dict__)


def get_alert_worker_state() -> AlertWorkerState:
    with _lock:
        return AlertWorkerState(**state.__dict__)
