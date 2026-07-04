from __future__ import annotations

from typing import Any

import json

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from operations.alerts import dispatch_pending_alerts
from operations.alert_worker import get_alert_worker_state, start_alert_worker, stop_alert_worker
from operations.brain import brain_diagnostics, brain_query, source_priority_plan
from operations.analytics import client_dashboard, heatmap
from operations.core import (
    DEFAULT_ORG_ID,
    STORAGE_MODE,
    SUPABASE_DB_URL,
    USE_POSTGRES,
    add_incident,
    collect_all_sources,
    collect_from_source,
    generate_weekly_brief_file,
    init_db,
    now_iso,
    row_to_dict,
    rows,
    weekly_report_markdown,
)
from operations.intel import intelligence_packet
from operations.nlp import classify_incident_payload, classify_text, nlp_status
from operations.scheduler import start_scheduler
from operations.task_queue import (
    brain_task_worker_state,
    get_brain_task,
    list_brain_tasks,
    queue_brain_task,
    start_brain_task_worker,
    stop_brain_task_worker,
)
from operations.security import AuthContext, allowed_org, audit_log, auth_required, authenticate_api_key


app = FastAPI(
    title="Lemtik Security Brain API",
    version="0.2.0",
    description="Classification, collection, alerting, and intelligence API for the Lemtik OSINT platform.",
)


class ClassifyRequest(BaseModel):
    text: str = Field(..., min_length=1)
    credibility: str = "B"
    verified: str | None = None
    custom_keywords: list[str] = Field(default_factory=list)


class IncidentRequest(BaseModel):
    org_id: str = DEFAULT_ORG_ID
    source: str
    source_url: str
    raw_content: str
    summary: str | None = None
    threat_category: str | None = None
    severity: int | None = Field(default=None, ge=1, le=5)
    location_relevance: str = ""
    geo_relevance: str | None = None
    verified: str = "No"
    verification_source: str = ""
    client_notified: str = "No"
    notification_method: str = ""
    status: str = "Monitoring"
    analyst: str = ""
    notes: str = ""
    matched_keywords: str | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    quality_score: int | None = Field(default=None, ge=0, le=100)
    credibility: str = "B"
    custom_keywords: list[str] = Field(default_factory=list)


class SourceRequest(BaseModel):
    extra_keywords: str = ""
    org_id: str = DEFAULT_ORG_ID


class BriefRequest(BaseModel):
    org_id: str = DEFAULT_ORG_ID
    days: int = Field(default=7, ge=1, le=90)


class AlertDispatchRequest(BaseModel):
    org_id: str = DEFAULT_ORG_ID
    limit: int = Field(default=20, ge=1, le=100)


class AlertWorkerRequest(BaseModel):
    org_id: str = DEFAULT_ORG_ID
    interval_seconds: int = Field(default=60, ge=10, le=3600)
    limit: int = Field(default=20, ge=1, le=100)


class IntelPacketRequest(BaseModel):
    org_id: str = DEFAULT_ORG_ID
    incident_text: str = Field(..., min_length=1)
    location: str = ""
    lookback_days: int = Field(default=180, ge=1, le=3650)
    recent_limit: int = Field(default=10, ge=1, le=50)
    task: str = "incident_assessment"
    custom_keywords: list[str] = Field(default_factory=list)


class BrainQueryRequest(BaseModel):
    org_id: str = DEFAULT_ORG_ID
    question: str = Field(..., min_length=1)
    location: str = ""
    lookback_days: int = Field(default=180, ge=1, le=3650)
    recent_limit: int = Field(default=10, ge=1, le=50)
    custom_keywords: list[str] = Field(default_factory=list)


class BrainTaskRequest(BaseModel):
    org_id: str = DEFAULT_ORG_ID
    task_type: str = Field(..., min_length=1)
    source_id: int | None = None
    source_ids: list[int] = Field(default_factory=list)
    extra_keywords: str = ""
    days: int = Field(default=7, ge=1, le=90)
    limit: int = Field(default=20, ge=1, le=100)
    priority: int = Field(default=5, ge=1, le=10)
    note: str = ""


class BrainTaskWorkerRequest(BaseModel):
    org_id: str = DEFAULT_ORG_ID
    interval_seconds: int = Field(default=5, ge=1, le=3600)


def require_auth(request: Request, x_api_key: str | None = Header(default=None)) -> AuthContext:
    if not auth_required():
        return AuthContext(org_id=DEFAULT_ORG_ID, authenticated=False)
    auth = authenticate_api_key(x_api_key)
    if auth is None:
        raise HTTPException(status_code=401, detail="valid X-API-Key header required")
    return auth


def route_org(requested_org_id: str, auth: AuthContext) -> str:
    try:
        return allowed_org(requested_org_id, auth)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def audit_request(request: Request, auth: AuthContext, org_id: str, action: str, resource_type: str = "", resource_id: str = "", metadata: dict | None = None) -> None:
    audit_log(
        org_id=org_id,
        actor=auth.key_name,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=request.client.host if request.client else "",
        user_agent=request.headers.get("user-agent", ""),
        metadata=json.dumps(metadata or {}),
    )


@app.on_event("startup")
def startup() -> None:
    init_db()
    start_scheduler()
    start_brain_task_worker()


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "lemtik-brain",
        "time": now_iso(),
        "storage": "supabase" if USE_POSTGRES else STORAGE_MODE,
        "supabase_configured": bool(SUPABASE_DB_URL),
    }


@app.get("/nlp/status")
def get_nlp_status() -> dict[str, Any]:
    return nlp_status()


@app.post("/classify")
def classify(request: Request, payload: ClassifyRequest, auth: AuthContext = Depends(require_auth)) -> dict[str, Any]:
    audit_request(request, auth, auth.org_id, "classify_text", "classification", metadata={"chars": len(payload.text)})
    return classify_text(
        payload.text,
        credibility=payload.credibility,
        verified=payload.verified,
        custom_keywords=payload.custom_keywords,
    )


@app.post("/incidents")
def create_incident(request: Request, payload_model: IncidentRequest, auth: AuthContext = Depends(require_auth)) -> dict[str, Any]:
    payload = payload_model.model_dump() if hasattr(payload_model, "model_dump") else payload_model.dict()
    payload["org_id"] = route_org(str(payload.get("org_id") or DEFAULT_ORG_ID), auth)
    data = classify_incident_payload(payload)
    data["collected_at"] = now_iso()
    created = add_incident({key: str(value) if value is not None else "" for key, value in data.items() if key != "nlp"})
    if not created:
        raise HTTPException(status_code=409, detail={"duplicate": True})
    audit_request(request, auth, payload["org_id"], "create_incident", "incident", metadata={"source": payload.get("source")})
    return {"ok": True, "classification": data["nlp"]}


@app.get("/incidents")
def list_incidents(
    request: Request,
    auth: AuthContext = Depends(require_auth),
    org_id: str = DEFAULT_ORG_ID,
    severity: int | None = Query(default=None, ge=1, le=5),
    category: str | None = None,
    days: int | None = Query(default=None, ge=1, le=365),
) -> dict[str, Any]:
    org_id = route_org(org_id, auth)
    filters = ["org_id = ?"]
    values: list[Any] = [org_id]
    if severity is not None:
        filters.append("severity = ?")
        values.append(severity)
    if category:
        filters.append("threat_category = ?")
        values.append(category)
    if days is not None:
        from datetime import datetime, timedelta, timezone

        since = (datetime.now(timezone.utc).astimezone() - timedelta(days=days)).isoformat()
        filters.append("collected_at >= ?")
        values.append(since)
    incidents = rows(
        f"select * from incidents where {' and '.join(filters)} order by severity desc, collected_at desc limit 200",
        tuple(values),
    )
    audit_request(request, auth, org_id, "list_incidents", "incident", metadata={"severity": severity, "category": category, "days": days})
    return {"incidents": [row_to_dict(row) for row in incidents]}


@app.get("/incidents/{incident_id}")
def get_incident(request: Request, incident_id: int, org_id: str = DEFAULT_ORG_ID, auth: AuthContext = Depends(require_auth)) -> dict[str, Any]:
    org_id = route_org(org_id, auth)
    found = rows("select * from incidents where id = ? and org_id = ?", (incident_id, org_id))
    if not found:
        raise HTTPException(status_code=404, detail="incident not found")
    audit_request(request, auth, org_id, "get_incident", "incident", str(incident_id))
    return row_to_dict(found[0])


@app.get("/sources")
def list_sources(request: Request, org_id: str = DEFAULT_ORG_ID, auth: AuthContext = Depends(require_auth)) -> dict[str, Any]:
    org_id = route_org(org_id, auth)
    audit_request(request, auth, org_id, "list_sources", "source")
    return {"sources": [row_to_dict(row) for row in rows("select * from sources where org_id = ? order by name", (org_id,))]}


@app.post("/sources/{source_id}/collect")
def collect_source(request: Request, source_id: int, payload: SourceRequest, auth: AuthContext = Depends(require_auth)) -> dict[str, int]:
    org_id = route_org(payload.org_id, auth)
    checked, created, skipped = collect_from_source(source_id, payload.extra_keywords, org_id)
    audit_request(request, auth, org_id, "collect_source", "source", str(source_id), {"checked": checked, "created": created, "skipped": skipped})
    return {"checked": checked, "created": created, "skipped": skipped}


@app.post("/collect")
def collect_all(request: Request, payload: SourceRequest, auth: AuthContext = Depends(require_auth)) -> dict[str, int]:
    org_id = route_org(payload.org_id, auth)
    checked, created, skipped = collect_all_sources(payload.extra_keywords, org_id)
    audit_request(request, auth, org_id, "collect_all_sources", "source", metadata={"checked": checked, "created": created, "skipped": skipped})
    return {"checked": checked, "created": created, "skipped": skipped}


@app.get("/briefs")
def get_brief(request: Request, org_id: str = DEFAULT_ORG_ID, days: int = Query(default=7, ge=1, le=90), auth: AuthContext = Depends(require_auth)) -> dict[str, Any]:
    org_id = route_org(org_id, auth)
    audit_request(request, auth, org_id, "get_brief", "brief", metadata={"days": days})
    return {"org_id": org_id, "days": days, "markdown": weekly_report_markdown(days, org_id)}


@app.post("/briefs/generate")
def generate_brief(request: Request, payload: BriefRequest, auth: AuthContext = Depends(require_auth)) -> dict[str, Any]:
    org_id = route_org(payload.org_id, auth)
    path = generate_weekly_brief_file(payload.days, org_id)
    audit_request(request, auth, org_id, "generate_brief", "brief", metadata={"days": payload.days, "path": str(path)})
    return {"path": str(path), "markdown": weekly_report_markdown(payload.days, org_id)}


@app.post("/alerts/dispatch")
def dispatch_alerts(request: Request, payload: AlertDispatchRequest, auth: AuthContext = Depends(require_auth)) -> dict[str, Any]:
    org_id = route_org(payload.org_id, auth)
    result = dispatch_pending_alerts(org_id, payload.limit)
    audit_request(request, auth, org_id, "dispatch_alerts", "alert", metadata=result)
    return result


@app.get("/alerts/worker")
def alert_worker_status(request: Request, org_id: str = DEFAULT_ORG_ID, auth: AuthContext = Depends(require_auth)) -> dict[str, Any]:
    org_id = route_org(org_id, auth)
    worker = get_alert_worker_state()
    audit_request(request, auth, org_id, "alert_worker_status", "alert_worker")
    return worker.__dict__


@app.post("/alerts/worker/start")
def start_alert_worker_endpoint(request: Request, payload: AlertWorkerRequest, auth: AuthContext = Depends(require_auth)) -> dict[str, Any]:
    org_id = route_org(payload.org_id, auth)
    worker = start_alert_worker(org_id, payload.interval_seconds, payload.limit)
    audit_request(request, auth, org_id, "start_alert_worker", "alert_worker", metadata={"interval_seconds": payload.interval_seconds, "limit": payload.limit})
    return worker.__dict__


@app.post("/alerts/worker/stop")
def stop_alert_worker_endpoint(request: Request, org_id: str = DEFAULT_ORG_ID, auth: AuthContext = Depends(require_auth)) -> dict[str, Any]:
    org_id = route_org(org_id, auth)
    worker = stop_alert_worker()
    audit_request(request, auth, org_id, "stop_alert_worker", "alert_worker")
    return worker.__dict__


@app.post("/intel/packet")
def intel_packet(request: Request, payload: IntelPacketRequest, auth: AuthContext = Depends(require_auth)) -> dict[str, Any]:
    org_id = route_org(payload.org_id, auth)
    packet = intelligence_packet(
        org_id=org_id,
        incident_text=payload.incident_text,
        location=payload.location,
        lookback_days=payload.lookback_days,
        recent_limit=payload.recent_limit,
        custom_keywords=payload.custom_keywords,
        task=payload.task,
    )
    audit_request(
        request,
        auth,
        org_id,
        "intel_packet",
        "intel",
        metadata={"task": payload.task, "lookback_days": payload.lookback_days, "recent_limit": payload.recent_limit},
    )
    return packet


@app.post("/brain/query")
def brain_query_endpoint(request: Request, payload: BrainQueryRequest, auth: AuthContext = Depends(require_auth)) -> dict[str, Any]:
    org_id = route_org(payload.org_id, auth)
    result = brain_query(
        org_id=org_id,
        question=payload.question,
        location=payload.location,
        lookback_days=payload.lookback_days,
        recent_limit=payload.recent_limit,
        custom_keywords=payload.custom_keywords,
    )
    audit_request(
        request,
        auth,
        org_id,
        "brain_query",
        "brain",
        metadata={"lookback_days": payload.lookback_days, "recent_limit": payload.recent_limit, "question_len": len(payload.question)},
    )
    return result


@app.get("/brain/diagnostics")
def brain_diagnostics_endpoint(
    request: Request,
    org_id: str = DEFAULT_ORG_ID,
    auth: AuthContext = Depends(require_auth),
) -> dict[str, Any]:
    org_id = route_org(org_id, auth)
    result = brain_diagnostics(org_id)
    audit_request(request, auth, org_id, "brain_diagnostics", "brain")
    return result


@app.get("/brain/source-plan")
def brain_source_plan_endpoint(
    request: Request,
    org_id: str = DEFAULT_ORG_ID,
    days: int = Query(default=7, ge=1, le=90),
    limit: int = Query(default=20, ge=1, le=50),
    auth: AuthContext = Depends(require_auth),
) -> dict[str, Any]:
    org_id = route_org(org_id, auth)
    result = {
        "org_id": org_id,
        "days": days,
        "limit": limit,
        "plan": source_priority_plan(org_id, days=days, limit=limit),
    }
    audit_request(request, auth, org_id, "brain_source_plan", "brain", metadata={"days": days, "limit": limit})
    return result


@app.post("/brain/tasks")
def queue_brain_task_endpoint(request: Request, payload: BrainTaskRequest, auth: AuthContext = Depends(require_auth)) -> dict[str, Any]:
    org_id = route_org(payload.org_id, auth)
    try:
        task = queue_brain_task(
            org_id=org_id,
            task_type=payload.task_type,
            payload={
                "source_id": payload.source_id,
                "source_ids": payload.source_ids,
                "extra_keywords": payload.extra_keywords,
                "days": payload.days,
                "limit": payload.limit,
                "note": payload.note,
            },
            priority=payload.priority,
            requested_by=auth.key_name,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    audit_request(
        request,
        auth,
        org_id,
        "queue_brain_task",
        "brain_task",
        metadata={"task_type": payload.task_type, "priority": payload.priority, "task_id": task.get("id", "")},
    )
    return task


@app.get("/brain/tasks")
def list_brain_tasks_endpoint(
    request: Request,
    org_id: str = DEFAULT_ORG_ID,
    status: str = "",
    limit: int = Query(default=20, ge=1, le=100),
    auth: AuthContext = Depends(require_auth),
) -> dict[str, Any]:
    org_id = route_org(org_id, auth)
    tasks = list_brain_tasks(org_id=org_id, status=status, limit=limit)
    audit_request(request, auth, org_id, "list_brain_tasks", "brain_task", metadata={"status": status, "limit": limit})
    return {"org_id": org_id, "tasks": tasks}


@app.get("/brain/tasks/item/{task_id}")
def get_brain_task_endpoint(
    request: Request,
    task_id: str,
    org_id: str = DEFAULT_ORG_ID,
    auth: AuthContext = Depends(require_auth),
) -> dict[str, Any]:
    org_id = route_org(org_id, auth)
    task = get_brain_task(task_id, org_id=org_id)
    if task is None:
        raise HTTPException(status_code=404, detail="brain task not found")
    audit_request(request, auth, org_id, "get_brain_task", "brain_task", resource_id=task_id)
    return task


@app.get("/brain/tasks/worker")
def brain_task_worker_status(request: Request, org_id: str = DEFAULT_ORG_ID, auth: AuthContext = Depends(require_auth)) -> dict[str, Any]:
    org_id = route_org(org_id, auth)
    audit_request(request, auth, org_id, "brain_task_worker_status", "brain_task_worker")
    return brain_task_worker_state().__dict__


@app.post("/brain/tasks/worker/start")
def brain_task_worker_start(
    request: Request,
    payload: BrainTaskWorkerRequest,
    auth: AuthContext = Depends(require_auth),
) -> dict[str, Any]:
    org_id = route_org(payload.org_id, auth)
    worker = start_brain_task_worker(org_id, payload.interval_seconds)
    audit_request(request, auth, org_id, "start_brain_task_worker", "brain_task_worker", metadata={"interval_seconds": payload.interval_seconds})
    return worker.__dict__


@app.post("/brain/tasks/worker/stop")
def brain_task_worker_stop(request: Request, org_id: str = DEFAULT_ORG_ID, auth: AuthContext = Depends(require_auth)) -> dict[str, Any]:
    org_id = route_org(org_id, auth)
    worker = stop_brain_task_worker()
    audit_request(request, auth, org_id, "stop_brain_task_worker", "brain_task_worker")
    return worker.__dict__


@app.post("/tasking/resolve")
def tasking_resolve(request: Request, payload: IntelPacketRequest, auth: AuthContext = Depends(require_auth)) -> dict[str, Any]:
    org_id = route_org(payload.org_id, auth)
    packet = intelligence_packet(
        org_id=org_id,
        incident_text=payload.incident_text,
        location=payload.location,
        lookback_days=payload.lookback_days,
        recent_limit=payload.recent_limit,
        custom_keywords=payload.custom_keywords,
        task=payload.task,
    )
    audit_request(
        request,
        auth,
        org_id,
        "tasking_resolve",
        "intel",
        metadata={"task": payload.task, "lookback_days": payload.lookback_days, "recent_limit": payload.recent_limit},
    )
    return packet


@app.get("/analytics/dashboard")
def dashboard(request: Request, org_id: str = DEFAULT_ORG_ID, auth: AuthContext = Depends(require_auth)) -> dict[str, Any]:
    org_id = route_org(org_id, auth)
    totals = rows(
        """
        select
          count(*) as total,
          sum(case when severity >= 4 then 1 else 0 end) as high,
          sum(case when verified = 'Yes' then 1 else 0 end) as verified,
          sum(case when geo_relevance = 'Lagos' then 1 else 0 end) as lagos,
          sum(case when geo_relevance = 'Nigeria' then 1 else 0 end) as nigeria,
          sum(case when geo_relevance = 'Client' then 1 else 0 end) as client
        from incidents where org_id = ?
        """,
        (org_id,),
    )[0]
    categories = rows(
        """
        select threat_category, count(*) as count
        from incidents where org_id = ?
        group by threat_category order by count desc
        """,
        (org_id,),
    )
    audit_request(request, auth, org_id, "analytics_dashboard", "analytics")
    return {"org_id": org_id, "totals": row_to_dict(totals), "categories": [row_to_dict(row) for row in categories]}


@app.get("/analytics/heatmap")
def analytics_heatmap(
    request: Request,
    org_id: str = DEFAULT_ORG_ID,
    days: int = Query(default=30, ge=1, le=365),
    auth: AuthContext = Depends(require_auth),
) -> dict[str, Any]:
    org_id = route_org(org_id, auth)
    locations = heatmap(org_id, days)
    audit_request(request, auth, org_id, "analytics_heatmap", "analytics", metadata={"days": days})
    return {"org_id": org_id, "days": days, "locations": locations}


@app.get("/client-dashboard")
def client_dashboard_endpoint(
    request: Request,
    org_id: str = DEFAULT_ORG_ID,
    days: int = Query(default=7, ge=1, le=90),
    auth: AuthContext = Depends(require_auth),
) -> dict[str, Any]:
    org_id = route_org(org_id, auth)
    payload = client_dashboard(org_id, days)
    audit_request(request, auth, org_id, "client_dashboard", "dashboard", metadata={"days": days})
    return payload


@app.get("/audit-logs")
def list_audit_logs(
    request: Request,
    org_id: str = DEFAULT_ORG_ID,
    limit: int = Query(default=100, ge=1, le=500),
    auth: AuthContext = Depends(require_auth),
) -> dict[str, Any]:
    org_id = route_org(org_id, auth)
    if auth.authenticated and auth.role not in {"admin", "analyst"}:
        raise HTTPException(status_code=403, detail="audit logs require admin or analyst role")
    logs = rows(
        """
        select * from audit_logs
        where org_id = ?
        order by created_at desc
        limit ?
        """,
        (org_id, limit),
    )
    audit_request(request, auth, org_id, "list_audit_logs", "audit_log", metadata={"limit": limit})
    return {"org_id": org_id, "audit_logs": [row_to_dict(row) for row in logs]}
