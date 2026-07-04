from __future__ import annotations

import re
from typing import Any

from operations.analytics import client_dashboard, latest_brief, risk_rating, since_iso
from operations.core import row_to_dict, rows
from operations.intel import intelligence_packet
from operations.nlp import classify_text, extract_entities
from operations.task_queue import list_brain_tasks


def _question_tokens(value: str) -> list[str]:
    return [token for token in re.findall(r"[a-z0-9]+", value.lower()) if len(token) > 1]


def source_health(org_id: str) -> dict[str, Any]:
    sources = [
        row_to_dict(row)
        for row in rows(
            """
            select id, name, source_type, url, credibility, last_checked_at, last_status, last_error
            from sources
            where org_id = ?
            order by last_status, credibility, name
            """,
            (org_id,),
        )
    ]
    healthy = sum(1 for source in sources if str(source.get("last_status") or "").upper() == "OK")
    failed = sum(1 for source in sources if str(source.get("last_status") or "").upper() == "FAILED")
    stale = sum(1 for source in sources if not source.get("last_checked_at"))
    score = 100
    score -= min(stale * 10, 40)
    score -= min(failed * 15, 45)
    score = max(0, min(score, 100))
    return {
        "total": len(sources),
        "healthy": healthy,
        "failed": failed,
        "stale": stale,
        "score": score,
        "sources": sources[:30],
    }


def source_rollup(org_id: str, days: int = 7) -> list[dict[str, Any]]:
    since = since_iso(days)
    return [
        row_to_dict(row)
        for row in rows(
            """
            select source, count(*) as incidents, max(severity) as max_severity, avg(confidence) as avg_confidence
            from incidents
            where org_id = ?
            and collected_at >= ?
            group by source
            order by incidents desc, max_severity desc
            limit 20
            """,
            (org_id, since),
        )
    ]


def source_priority_plan(org_id: str, days: int = 7, limit: int = 20) -> list[dict[str, Any]]:
    since = since_iso(days)
    return [
        row_to_dict(row)
        for row in rows(
            """
            select
              s.id,
              s.name,
              s.source_type,
              s.url,
              s.credibility,
              s.last_checked_at,
              s.last_status,
              s.last_error,
              coalesce(i.incidents, 0) as incidents,
              coalesce(i.max_severity, 0) as max_severity,
              coalesce(i.avg_confidence, 0) as avg_confidence,
              (
                case when upper(coalesce(s.last_status, '')) = 'FAILED' then 50 else 0 end
                + case when coalesce(cast(s.last_checked_at as text), '') = '' then 25 else 0 end
                + case when s.credibility = 'A' then 12 when s.credibility = 'B' then 8 else 4 end
                + coalesce(i.incidents, 0) * 2
                + coalesce(i.max_severity, 0) * 7
                + coalesce(i.avg_confidence, 0) / 10
              ) as priority_score
            from sources s
            left join (
              select source, count(*) as incidents, max(severity) as max_severity, avg(confidence) as avg_confidence
              from incidents
              where org_id = ?
              and collected_at >= ?
              group by source
            ) i on i.source = s.name
            where s.org_id = ?
            order by priority_score desc, coalesce(i.incidents, 0) desc, s.credibility, s.name
            limit ?
            """,
            (org_id, since, org_id, limit),
        )
    ]


def collection_health(org_id: str) -> dict[str, Any]:
    runs = [
        row_to_dict(row)
        for row in rows(
            """
            select source_name, started_at, finished_at, checked_count, created_count,
                   skipped_count, status, error
            from collection_runs
            where org_id = ?
            order by started_at desc
            limit 25
            """,
            (org_id,),
        )
    ]
    failed = sum(1 for run in runs if str(run.get("status") or "").upper() != "OK")
    return {
        "total": len(runs),
        "ok": len(runs) - failed,
        "failed": failed,
        "recent": runs[:10],
    }


def task_queue_health(org_id: str) -> dict[str, Any]:
    tasks = list_brain_tasks(org_id=org_id, limit=50)
    pending = [task for task in tasks if str(task.get("status") or "").lower() == "pending"]
    running = [task for task in tasks if str(task.get("status") or "").lower() == "running"]
    failed = [task for task in tasks if str(task.get("status") or "").lower() == "failed"]
    completed = [task for task in tasks if str(task.get("status") or "").lower() == "completed"]
    return {
        "total": len(tasks),
        "pending": len(pending),
        "running": len(running),
        "failed": len(failed),
        "completed": len(completed),
        "recent": tasks[:10],
    }


def operational_snapshot(org_id: str) -> dict[str, Any]:
    health = source_health(org_id)
    runs = collection_health(org_id)
    queue = task_queue_health(org_id)
    plan = source_priority_plan(org_id, days=7, limit=10)
    stale_sources = [source for source in health["sources"] if not source.get("last_checked_at")]
    failed_sources = [source for source in health["sources"] if str(source.get("last_status") or "").upper() == "FAILED"]
    score = 100
    score -= min(health["stale"] * 8, 35)
    score -= min(health["failed"] * 12, 35)
    score -= min(runs["failed"] * 5, 20)
    score -= min(queue["pending"] // 5, 10)
    score = max(0, min(score, 100))
    if score >= 85:
        posture = "Healthy"
    elif score >= 60:
        posture = "Watch"
    else:
        posture = "Degraded"
    return {
        "posture": posture,
        "score": score,
        "source_health": health,
        "collection_health": runs,
        "task_queue_health": queue,
        "source_priority_plan": plan,
        "stale_sources": stale_sources[:10],
        "failed_sources": failed_sources[:10],
        "recommendations": [
            "Run collect_all if stale sources exist" if stale_sources else "Source coverage looks current",
            "Inspect failed collection runs" if runs["failed"] else "Collection history is clean",
            "Drain pending tasks" if queue["pending"] else "Task queue is clear",
            "Queue repair_sources for the highest-priority stale sources" if stale_sources or failed_sources else "No repair task needed",
        ],
    }


def _intent(question: str) -> str:
    tokens = set(_question_tokens(question))
    if tokens & {"brief", "summary", "report"}:
        return "brief"
    if tokens & {"source", "health", "sources"}:
        return "source_health"
    if tokens & {"heatmap", "map", "area", "location"}:
        return "area"
    if tokens & {"similar", "history", "pattern"}:
        return "similarity"
    if tokens & {"collect", "collection"}:
        return "collection"
    if tokens & {"task", "queue", "worker", "diagnose", "diagnostic"}:
        return "diagnostic"
    return "intel"


def brain_query(
    *,
    org_id: str,
    question: str,
    location: str = "",
    lookback_days: int = 180,
    recent_limit: int = 10,
    custom_keywords: list[str] | None = None,
) -> dict[str, Any]:
    custom_keywords = custom_keywords or []
    intent = _intent(question)
    classification = classify_text(question, custom_keywords=custom_keywords)
    entities = extract_entities(question)
    packet = intelligence_packet(
        org_id=org_id,
        incident_text=question,
        location=location,
        lookback_days=lookback_days,
        recent_limit=recent_limit,
        custom_keywords=custom_keywords,
        task=intent,
    )
    operations = operational_snapshot(org_id)
    return {
        "query": question,
        "intent": intent,
        "classification": classification,
        "entities": entities,
        "packet": packet,
        "source_health": operations["source_health"],
        "operations": operations,
        "source_rollup": source_rollup(org_id, min(lookback_days, 30)),
        "latest_brief": latest_brief(org_id),
        "dashboard": client_dashboard(org_id, min(lookback_days, 30)),
        "recommended_action": (
            "collect" if intent == "collection" else
            "brief" if intent == "brief" else
            "diagnose" if intent == "diagnostic" else
            "review" if int(classification.get("severity") or 1) >= 4 else
            "monitor"
        ),
        "risk_rating": risk_rating(
            packet["area_history"]["max_severity"],
            packet["area_history"]["high_severity_count"],
            packet["area_history"]["matched_count"],
        ),
    }


def brain_diagnostics(org_id: str) -> dict[str, Any]:
    operations = operational_snapshot(org_id)
    latest_tasks = list_brain_tasks(org_id=org_id, limit=10)
    return {
        "org_id": org_id,
        "operations": operations,
        "latest_tasks": latest_tasks,
        "source_rollup": source_rollup(org_id, days=7),
        "source_priority_plan": source_priority_plan(org_id, days=7, limit=20),
        "latest_brief": latest_brief(org_id),
        "dashboard": client_dashboard(org_id, 7),
    }
