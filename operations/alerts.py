from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from operations.core import execute, now_iso, row_to_dict, rows


ALERT_RETRY_MINUTES = int(os.getenv("LEMTIK_ALERT_RETRY_MINUTES", "15"))


def alert_recipients() -> list[str]:
    raw = os.getenv("LEMTIK_ALERT_EMAIL_TO", "").strip() or os.getenv("LEMTIK_BRIEF_EMAIL_TO", "").strip()
    return [item.strip() for item in raw.split(",") if item.strip()]


def send_resend_email(subject: str, text: str, recipients: list[str]) -> tuple[bool, str]:
    api_key = os.getenv("RESEND_API_KEY", "").strip()
    sender = os.getenv("LEMTIK_ALERT_EMAIL_FROM", "").strip() or os.getenv("LEMTIK_BRIEF_EMAIL_FROM", "").strip()
    if not api_key or not sender or not recipients:
        return False, "Resend alert email not configured."

    payload = {
        "from": sender,
        "to": recipients,
        "subject": subject,
        "text": text,
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
        return False, f"Resend failed: HTTP {exc.code} {detail[:300]}"
    except urllib.error.URLError as exc:
        return False, f"Resend failed: {exc.reason}"
    return True, f"Email id: {result.get('id', 'unknown')}"


def format_alert(alert: dict) -> str:
    payload = alert.get("payload") or {}
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            payload = {}

    lines = [
        "LEMTIK SECURITY ALERT",
        "",
        f"Severity: {alert.get('severity')}",
        f"Summary: {alert.get('summary')}",
    ]
    if payload.get("log_id"):
        lines.append(f"Log ID: {payload['log_id']}")
    if payload.get("source_url"):
        lines.append(f"Source: {payload['source_url']}")
    lines.extend(
        [
            "",
            "Recommended action: verify against an independent Tier A/B source and escalate to the client security manager if still credible.",
        ]
    )
    return "\n".join(lines)


def dispatch_pending_alerts(org_id: str, limit: int = 20) -> dict:
    retry_before = (datetime.now(timezone.utc).astimezone() - timedelta(minutes=ALERT_RETRY_MINUTES)).isoformat()
    pending = [row_to_dict(row) for row in rows(
        """
        select * from alert_events
        where org_id = ?
        and (
            status = 'Pending'
            or (status = 'Failed' and created_at <= ?)
        )
        order by created_at asc
        limit ?
        """,
        (org_id, retry_before, limit),
    )]
    recipients = alert_recipients()
    sent = 0
    failed = 0

    for alert in pending:
        ok, result = send_resend_email(
            f"Lemtik Security Alert - Severity {alert['severity']}",
            format_alert(alert),
            recipients,
        )
        if ok:
            execute(
                "update alert_events set status = ?, sent_at = ?, error = ? where id = ? and org_id = ?",
                ("Sent", now_iso(), result, alert["id"], org_id),
            )
            sent += 1
        else:
            execute(
                "update alert_events set status = ?, error = ? where id = ? and org_id = ?",
                ("Failed", result, alert["id"], org_id),
            )
            failed += 1

    return {"pending": len(pending), "sent": sent, "failed": failed}
