from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
import time
from typing import Any

from operations.core import row_to_dict, rows

_cache: dict[tuple[str, str, int], tuple[float, dict[str, Any]]] = {}
CACHE_TTL_SECONDS = int(os.getenv("LEMTIK_DASHBOARD_CACHE_SECONDS", "30"))


def since_iso(days: int) -> str:
    return (datetime.now(timezone.utc).astimezone() - timedelta(days=days)).isoformat()


def risk_rating(max_severity: int | None, high_count: int, recent_count: int) -> str:
    max_severity = int(max_severity or 0)
    if max_severity >= 5 or high_count >= 3:
        return "Red"
    if max_severity >= 4 or high_count >= 1 or recent_count >= 10:
        return "Orange"
    return "Green"


def dashboard_summary(org_id: str, days: int = 7) -> dict[str, Any]:
    since = since_iso(days)
    totals = row_to_dict(
        rows(
            """
            select
              count(*) as total,
              sum(case when severity >= 4 then 1 else 0 end) as high,
              sum(case when verified = 'Yes' then 1 else 0 end) as verified,
              max(severity) as max_severity,
              avg(confidence) as avg_confidence
            from incidents
            where org_id = ?
            and collected_at >= ?
            and status != 'Archived'
            """,
            (org_id, since),
        )[0]
    )
    totals = {key: (0 if value is None else value) for key, value in totals.items()}
    totals["risk_rating"] = risk_rating(totals.get("max_severity"), int(totals.get("high") or 0), int(totals.get("total") or 0))
    totals["days"] = days
    return totals


def category_breakdown(org_id: str, days: int = 7) -> list[dict[str, Any]]:
    return [
        row_to_dict(row)
        for row in rows(
            """
            select threat_category, count(*) as count, max(severity) as max_severity
            from incidents
            where org_id = ?
            and collected_at >= ?
            and status != 'Archived'
            group by threat_category
            order by count desc, max_severity desc
            """,
            (org_id, since_iso(days)),
        )
    ]


def latest_incidents(org_id: str, days: int = 7, limit: int = 20) -> list[dict[str, Any]]:
    return [
        row_to_dict(row)
        for row in rows(
            """
            select id, log_id, collected_at, source, source_url, summary,
                   threat_category, severity, location_relevance, geo_relevance,
                   verified, status, confidence, quality_score
            from incidents
            where org_id = ?
            and collected_at >= ?
            and status != 'Archived'
            order by severity desc, collected_at desc
            limit ?
            """,
            (org_id, since_iso(days), limit),
        )
    ]


def alert_summary(org_id: str, limit: int = 10) -> dict[str, Any]:
    counts = row_to_dict(
        rows(
            """
            select
              count(*) as total,
              sum(case when status = 'Pending' then 1 else 0 end) as pending,
              sum(case when status = 'Sent' then 1 else 0 end) as sent,
              sum(case when status = 'Failed' then 1 else 0 end) as failed
            from alert_events
            where org_id = ?
            """,
            (org_id,),
        )[0]
    )
    recent = [
        row_to_dict(row)
        for row in rows(
            """
            select id, incident_id, severity, summary, status, channels, created_at, sent_at, error
            from alert_events
            where org_id = ?
            order by created_at desc
            limit ?
            """,
            (org_id, limit),
        )
    ]
    return {"counts": {key: (0 if value is None else value) for key, value in counts.items()}, "recent": recent}


def latest_brief(org_id: str) -> dict[str, Any] | None:
    found = rows(
        """
        select id, title, window_days, risk_rating, generated_at, delivered_at, delivery_status
        from briefs
        where org_id = ?
        order by generated_at desc
        limit 1
        """,
        (org_id,),
    )
    return row_to_dict(found[0]) if found else None


def client_locations(org_id: str) -> list[dict[str, Any]]:
    return [
        row_to_dict(row)
        for row in rows(
            """
            select id, name, area, tier, contact
            from clients
            where org_id = ?
            order by name
            """,
            (org_id,),
        )
    ]


def heatmap(org_id: str, days: int = 30) -> list[dict[str, Any]]:
    return [
        row_to_dict(row)
        for row in rows(
            """
            select coalesce(nullif(location_relevance, ''), geo_relevance) as location,
                   geo_relevance,
                   count(*) as count,
                   max(severity) as max_severity,
                   avg(confidence) as avg_confidence
            from incidents
            where org_id = ?
            and collected_at >= ?
            and geo_relevance in ('Lagos', 'Nigeria', 'Client')
            and status != 'Archived'
            group by location, geo_relevance
            order by max_severity desc, count desc
            limit 50
            """,
            (org_id, since_iso(days)),
        )
    ]


def client_dashboard(org_id: str, days: int = 7) -> dict[str, Any]:
    return cached_client_dashboard(org_id, days)


def cached_client_dashboard(org_id: str, days: int = 7) -> dict[str, Any]:
    cache_key = ("client_dashboard", org_id, days)
    cached = _cache.get(cache_key)
    if cached and time.time() - cached[0] <= CACHE_TTL_SECONDS:
        return cached[1]
    payload = client_dashboard_uncached(org_id, days)
    _cache[cache_key] = (time.time(), payload)
    return payload


def client_dashboard_uncached(org_id: str, days: int = 7) -> dict[str, Any]:
    return {
        "org_id": org_id,
        "summary": dashboard_summary(org_id, days),
        "categories": category_breakdown(org_id, days),
        "latest_incidents": latest_incidents(org_id, days, 20),
        "alerts": alert_summary(org_id, 10),
        "latest_brief": latest_brief(org_id),
        "clients": client_locations(org_id),
        "heatmap": heatmap(org_id, 30),
    }
