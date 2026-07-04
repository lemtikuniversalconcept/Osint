from __future__ import annotations

import threading
import time
import base64
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
import os
import urllib.error
import urllib.request
from zoneinfo import ZoneInfo

from operations.alerts import dispatch_pending_alerts
from operations.core import collect_all_sources, generate_weekly_brief_file, now_iso


LAGOS_TZ = ZoneInfo("Africa/Lagos")
COLLECTION_HOURS = (0, 6, 12, 18)


@dataclass
class SchedulerState:
    enabled: bool = False
    last_collection_at: str = ""
    last_collection_result: str = "Not run yet"
    next_collection_at: str = ""
    last_weekly_brief_at: str = ""
    last_weekly_brief_path: str = ""
    last_email_result: str = "Resend email not configured"
    last_alert_dispatch_at: str = ""
    last_alert_dispatch_result: str = "Not run yet"
    last_error: str = ""


state = SchedulerState()
_started = False
_apscheduler = None
_lock = threading.Lock()


def next_collection_time(now: datetime | None = None) -> datetime:
    now = now or datetime.now(LAGOS_TZ)
    for hour in COLLECTION_HOURS:
        candidate = now.replace(hour=hour, minute=0, second=0, microsecond=0)
        if candidate > now:
            return candidate
    tomorrow = now + timedelta(days=1)
    return tomorrow.replace(hour=COLLECTION_HOURS[0], minute=0, second=0, microsecond=0)


def should_generate_weekly_brief(now: datetime, last_at: str) -> bool:
    if now.weekday() != 0 or now.hour != 7:
        return False
    if not last_at:
        return True
    try:
        previous = datetime.fromisoformat(last_at)
    except ValueError:
        return True
    return previous.date() != now.date()


def run_collection_once() -> None:
    try:
        checked, created, skipped = collect_all_sources()
        with _lock:
            state.last_collection_at = now_iso()
            state.last_collection_result = f"Checked {checked}, logged {created}, skipped {skipped}."
            state.last_error = ""
    except Exception as exc:
        with _lock:
            state.last_error = str(exc)[:500]


def run_weekly_brief_once() -> None:
    try:
        path = generate_weekly_brief_file()
        email_result = send_weekly_brief_email(path)
        with _lock:
            state.last_weekly_brief_at = now_iso()
            state.last_weekly_brief_path = str(path)
            state.last_email_result = email_result
            state.last_error = ""
    except Exception as exc:
        with _lock:
            state.last_error = str(exc)[:500]


def run_alert_dispatch_once() -> None:
    try:
        result = dispatch_pending_alerts(os.getenv("LEMTIK_DEFAULT_ORG_ID", "default"))
        with _lock:
            state.last_alert_dispatch_at = now_iso()
            state.last_alert_dispatch_result = f"Pending {result['pending']}, sent {result['sent']}, failed {result['failed']}."
            state.last_error = ""
    except Exception as exc:
        with _lock:
            state.last_error = str(exc)[:500]


def send_weekly_brief_email(path) -> str:
    api_key = os.getenv("RESEND_API_KEY", "").strip()
    recipients = [item.strip() for item in os.getenv("LEMTIK_BRIEF_EMAIL_TO", "").split(",") if item.strip()]
    sender = os.getenv("LEMTIK_BRIEF_EMAIL_FROM", "").strip()
    if not api_key or not recipients or not sender:
        return "Skipped email: set RESEND_API_KEY, LEMTIK_BRIEF_EMAIL_FROM, and LEMTIK_BRIEF_EMAIL_TO."

    payload = {
        "from": sender,
        "to": recipients,
        "subject": "Lemtik Security Weekly Intelligence Brief",
        "text": "Attached is the latest Lemtik Security weekly intelligence brief.",
        "attachments": [
            {
                "filename": path.name,
                "content": base64.b64encode(path.read_bytes()).decode("ascii"),
            }
        ],
    }
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            result = json.loads(response.read().decode("utf-8", errors="replace") or "{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        return f"Resend failed: HTTP {exc.code} {detail[:300]}"
    return f"Sent weekly brief via Resend to {len(recipients)} recipient(s). Email id: {result.get('id', 'unknown')}"


def _loop() -> None:
    with _lock:
        state.enabled = True
        state.next_collection_at = next_collection_time().isoformat()

    while True:
        now = datetime.now(LAGOS_TZ)
        next_run = next_collection_time(now)
        with _lock:
            state.next_collection_at = next_run.isoformat()
            last_weekly = state.last_weekly_brief_at

        if abs((next_run - now).total_seconds()) <= 60:
            run_collection_once()
            time.sleep(70)
            continue

        if should_generate_weekly_brief(now, last_weekly):
            run_weekly_brief_once()
            time.sleep(70)
            continue

        if now.minute % 5 == 0:
            run_alert_dispatch_once()
            time.sleep(70)
            continue

        time.sleep(30)


def start_apscheduler() -> bool:
    global _apscheduler
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except ImportError:
        return False

    scheduler = BackgroundScheduler(timezone="Africa/Lagos")
    scheduler.add_job(
        run_collection_once,
        "cron",
        hour="0,6,12,18",
        id="auto_collect",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        run_weekly_brief_once,
        "cron",
        day_of_week="mon",
        hour=7,
        minute=0,
        id="weekly_brief",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        run_alert_dispatch_once,
        "interval",
        minutes=5,
        id="alert_dispatch",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    _apscheduler = scheduler
    collection_job = scheduler.get_job("auto_collect")
    with _lock:
        state.enabled = True
        state.next_collection_at = collection_job.next_run_time.isoformat() if collection_job and collection_job.next_run_time else ""
        state.last_error = ""
    return True


def start_scheduler() -> None:
    global _started
    if _started:
        return
    _started = True
    if start_apscheduler():
        return
    thread = threading.Thread(target=_loop, name="lemtik-scheduler", daemon=True)
    thread.start()


def get_scheduler_state() -> SchedulerState:
    with _lock:
        return SchedulerState(**state.__dict__)
