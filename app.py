#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import mimetypes
import os
import urllib.parse
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from operations.core import (
    DB_PATH,
    DEFAULT_ORG_ID,
    STORAGE_MODE,
    SUPABASE_DB_URL,
    USE_POSTGRES,
    add_client,
    add_incident,
    add_organisation,
    add_source,
    collect_all_sources,
    collect_from_source,
    export_incidents_csv,
    generate_weekly_brief_file,
    init_db,
    now_iso,
    row_to_dict,
    rows,
    weekly_report_markdown,
)
from operations.alerts import dispatch_pending_alerts
from operations.jobs import recent_jobs, start_job
from operations.nlp import classify_text
from operations.scheduler import get_scheduler_state, run_alert_dispatch_once, run_collection_once, run_weekly_brief_once, start_scheduler


ROOT = Path(__file__).resolve().parent
EXPORTS = ROOT / "data" / "exports"


def esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def parse_body(handler: BaseHTTPRequestHandler) -> dict[str, str]:
    length = int(handler.headers.get("content-length", "0"))
    raw = handler.rfile.read(length).decode("utf-8", errors="replace")
    parsed = urllib.parse.parse_qs(raw)
    return {key: values[-1] for key, values in parsed.items()}


def parse_json_body(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("content-length", "0"))
    if length == 0:
        return {}
    raw = handler.rfile.read(length).decode("utf-8", errors="replace")
    return json.loads(raw or "{}")


def query_params(path: str) -> dict[str, str]:
    parsed = urllib.parse.urlparse(path)
    query = urllib.parse.parse_qs(parsed.query)
    return {key: values[-1] for key, values in query.items()}


def api_org(params: dict[str, str] | None = None, data: dict | None = None) -> str:
    params = params or {}
    data = data or {}
    return str(data.get("org_id") or params.get("org_id") or DEFAULT_ORG_ID)


def layout(title: str, body: str, notice: str = "") -> bytes:
    notice_html = f"<div class='notice'>{esc(notice)}</div>" if notice else ""
    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)} - Lemtik OSINT</title>
  <link rel="stylesheet" href="/templates/style.css">
</head>
<body>
  <aside>
    <div class="brand">Lemtik Security</div>
    <nav>
      <a href="/">Dashboard</a>
      <a href="/incidents">Incidents</a>
      <a href="/sources">Sources</a>
      <a href="/clients">Clients</a>
      <a href="/collect">Collect</a>
      <a href="/automation">Automation</a>
      <a href="/report">Weekly Brief</a>
    </nav>
  </aside>
  <main>
    {notice_html}
    {body}
  </main>
</body>
</html>"""
    return page.encode("utf-8")


def redirect(location: str) -> tuple[int, list[tuple[str, str]], bytes]:
    return 303, [("Location", location)], b""


def dashboard() -> bytes:
    totals = rows(
        """
        select
          count(*) as total,
          sum(case when severity >= 4 then 1 else 0 end) as high,
          sum(case when verified = 'Yes' then 1 else 0 end) as verified,
          sum(case when quality_score < 55 then 1 else 0 end) as low_quality,
          sum(case when geo_relevance = 'Lagos' then 1 else 0 end) as lagos_items,
          sum(case when geo_relevance = 'Nigeria' then 1 else 0 end) as nigeria_items,
          sum(case when geo_relevance = 'Client' then 1 else 0 end) as client_items
        from incidents
        """
    )[0]
    latest = rows(
        """
        select id, log_id, collected_at, source, source_url, summary,
               threat_category, severity, location_relevance, verified,
               status, confidence, quality_score, geo_relevance
        from incidents
        where quality_score >= 55 and geo_relevance in ('Lagos', 'Nigeria', 'Client')
        order by collected_at desc limit 8
        """
    )
    by_category = rows(
        """
        select threat_category, count(*) as n from incidents
        where quality_score >= 55 and geo_relevance in ('Lagos', 'Nigeria', 'Client')
        group by threat_category order by n desc
        """
    )
    recent_runs = rows("select * from collection_runs order by id desc limit 5")
    cards = f"""
    <section class="metrics">
      <div><span>{totals['total'] or 0}</span><label>Total incidents</label></div>
      <div><span>{totals['high'] or 0}</span><label>High/Critical</label></div>
      <div><span>{totals['verified'] or 0}</span><label>Verified</label></div>
      <div><span>{totals['lagos_items'] or 0}/{totals['nigeria_items'] or 0}/{totals['client_items'] or 0}</span><label>Lagos/Nigeria/Client</label></div>
    </section>
    """
    cat = "".join(f"<li>{esc(r['threat_category'])}<b>{r['n']}</b></li>" for r in by_category)
    runs = "".join(
        f"<li>{esc(r['source_name'])}: {esc(r['status'])}<b>{esc(r['created_count'])}/{esc(r['checked_count'])}</b></li>"
        for r in recent_runs
    )
    recent = incident_table(latest)
    return layout(
        "Dashboard",
        f"""
        <header><h1>OSINT Operations Dashboard</h1><p>Public-source monitoring, verification, and reporting for Lagos security intelligence.</p></header>
        {cards}
        <section class="grid">
          <div class="panel"><h2>Threat categories</h2><ul class="split">{cat or '<li>No data yet<b>0</b></li>'}</ul></div>
          <div class="panel"><h2>Recent collection runs</h2><ul class="split">{runs or '<li>No collection runs yet<b>0</b></li>'}</ul></div>
        </section>
        <section class="panel"><h2>Latest incidents</h2>{recent}</section>
        """,
    )


def incident_table(incidents) -> str:
    if not incidents:
        return "<p class='empty'>No incidents logged yet.</p>"
    lines = [
        "<table><thead><tr><th>Log ID</th><th>Severity</th><th>Confidence</th><th>Geo</th><th>Category</th><th>Summary</th><th>Verified</th><th>Status</th></tr></thead><tbody>"
    ]
    for row in incidents:
        sev_class = "sev-high" if row["severity"] >= 4 else "sev-mid" if row["severity"] == 3 else "sev-low"
        lines.append(
            f"<tr><td>{esc(row['log_id'])}</td><td><span class='{sev_class}'>{esc(row['severity'])}</span></td>"
            f"<td>{esc(row['confidence'])}%</td>"
            f"<td>{esc(row['geo_relevance'])}</td>"
            f"<td>{esc(row['threat_category'])}</td><td><a href='{esc(row['source_url'])}' target='_blank'>{esc(row['summary'])}</a></td>"
            f"<td>{esc(row['verified'])}</td><td>{esc(row['status'])}</td></tr>"
        )
    lines.append("</tbody></table>")
    return "".join(lines)


def incidents_page(notice: str = "") -> bytes:
    incidents = rows(
        """
        select id, log_id, collected_at, source, source_url, summary,
               threat_category, severity, location_relevance, verified,
               status, confidence, quality_score, geo_relevance
        from incidents
        order by collected_at desc
        limit 250
        """
    )
    form = """
    <form method="post" class="panel form">
      <h2>Log incident</h2>
      <div class="fields">
        <label>Source<input name="source" required placeholder="e.g. Channels TV"></label>
        <label>Source URL<input name="source_url" required type="url"></label>
        <label>Category<select name="threat_category"><option>Physical</option><option>Cyber</option><option>Political</option><option>Macro</option></select></label>
        <label>Severity<select name="severity"><option>1</option><option>2</option><option selected>3</option><option>4</option><option>5</option></select></label>
        <label>Location relevance<input name="location_relevance" placeholder="Lekki, VI, Ajah"></label>
        <label>Geographic relevance<select name="geo_relevance"><option>Lagos</option><option>Nigeria</option><option>None</option><option selected>Unknown</option></select></label>
        <label>Verified<select name="verified"><option>No</option><option>Partial</option><option>Yes</option></select></label>
        <label>Verification source<input name="verification_source"></label>
        <label>Matched keywords<input name="matched_keywords"></label>
        <label>Confidence<input name="confidence" type="number" min="0" max="100" value="50"></label>
        <label>Quality score<input name="quality_score" type="number" min="0" max="100" value="80"></label>
        <label>Status<select name="status"><option>Monitoring</option><option>Active</option><option>Resolved</option><option>Archived</option></select></label>
        <label>Analyst<input name="analyst"></label>
        <label>Client notified<select name="client_notified"><option>No</option><option>Yes</option></select></label>
      </div>
      <label>Summary<textarea name="summary" required></textarea></label>
      <label>Raw content<textarea name="raw_content" required></textarea></label>
      <label>Notes<textarea name="notes"></textarea></label>
      <button type="submit">Save incident</button>
    </form>
    """
    export = "<p><a class='button' href='/export/incidents.csv'>Export CSV</a></p>"
    return layout("Incidents", f"<header><h1>Incident Log</h1>{export}</header>{form}<section class='panel'><h2>Latest 250 incidents</h2>{incident_table(incidents)}</section>", notice)


def sources_page(notice: str = "") -> bytes:
    sources = rows("select * from sources order by credibility, name")
    table = "<table><thead><tr><th>Name</th><th>Type</th><th>Credibility</th><th>Status</th><th>URL</th></tr></thead><tbody>"
    for row in sources:
        table += (
            f"<tr><td>{esc(row['name'])}</td><td>{esc(row['source_type'])}</td><td>{esc(row['credibility'])}</td>"
            f"<td>{esc(row['last_status'])}<br><small>{esc(row['last_error'])}</small></td>"
            f"<td><a href='{esc(row['url'])}' target='_blank'>{esc(row['url'])}</a></td></tr>"
        )
    table += "</tbody></table>"
    form = """
    <form method="post" class="panel form">
      <h2>Add source</h2>
      <div class="fields">
        <label>Name<input name="name" required></label>
        <label>URL<input name="url" type="url" required></label>
        <label>Type<select name="source_type"><option>News</option><option>Official</option><option>Social</option><option>Community</option><option>Research</option></select></label>
        <label>Credibility<select name="credibility"><option>A</option><option selected>B</option><option>C</option></select></label>
      </div>
      <label>Notes<textarea name="notes"></textarea></label>
      <button type="submit">Save source</button>
    </form>
    """
    return layout("Sources", f"<header><h1>Source Registry</h1></header>{form}<section class='panel'>{table}</section>", notice)


def clients_page(notice: str = "") -> bytes:
    clients = rows("select * from clients order by name")
    table = "<table><thead><tr><th>Name</th><th>Area</th><th>Tier</th><th>Contact</th></tr></thead><tbody>"
    for row in clients:
        table += f"<tr><td>{esc(row['name'])}</td><td>{esc(row['area'])}</td><td>{esc(row['tier'])}</td><td>{esc(row['contact'])}</td></tr>"
    table += "</tbody></table>"
    form = """
    <form method="post" class="panel form">
      <h2>Add client</h2>
      <div class="fields">
        <label>Name<input name="name" required></label>
        <label>Area<input name="area" required placeholder="Ikoyi, Lekki Phase 1"></label>
        <label>Tier<select name="tier"><option>Basic</option><option selected>Standard</option><option>Premium</option></select></label>
        <label>Contact<input name="contact" placeholder="security manager email/phone"></label>
      </div>
      <button type="submit">Save client</button>
    </form>
    """
    return layout("Clients", f"<header><h1>Clients</h1></header>{form}<section class='panel'>{table}</section>", notice)


def collect_page(notice: str = "") -> bytes:
    sources = rows("select * from sources order by name")
    options = "".join(f"<option value='{row['id']}'>{esc(row['name'])} - {esc(row['url'])}</option>" for row in sources)
    jobs = recent_jobs(5)
    job_rows = "".join(
        f"<tr><td>{esc(job.name)}</td><td>{esc(job.status)}</td><td>{esc(job.started_at)}</td><td>{esc(job.result or job.error)}</td></tr>"
        for job in jobs
    )
    form = f"""
    <form method="post" class="panel form">
      <h2>Collect from public source</h2>
      <p>This fetches a public webpage or RSS feed, searches the core threat keywords, and logs matching items for analyst verification.</p>
      <label>Source<select name="source_id"><option value="all">All sources</option>{options}</select></label>
      <label>Client/location keywords<textarea name="extra_keywords" placeholder="Lekki, Ikoyi, client company name"></textarea></label>
      <button type="submit">Run collection</button>
    </form>
    <section class="panel">
      <h2>Collection controls</h2>
      <p>Collection now runs in the background. Refresh Automation to see completion status.</p>
    </section>
    <section class="panel">
      <h2>Recent background jobs</h2>
      <table><thead><tr><th>Job</th><th>Status</th><th>Started</th><th>Result</th></tr></thead><tbody>{job_rows or '<tr><td colspan="4">No background jobs yet.</td></tr>'}</tbody></table>
    </section>
    """
    return layout("Collect", f"<header><h1>Collection</h1></header>{form}", notice)


def automation_page(notice: str = "") -> bytes:
    scheduler = get_scheduler_state()
    runs = rows("select * from collection_runs order by id desc limit 12")
    jobs = recent_jobs(8)
    run_rows = "".join(
        f"<tr><td>{esc(r['source_name'])}</td><td>{esc(r['status'])}</td><td>{esc(r['checked_count'])}</td>"
        f"<td>{esc(r['created_count'])}</td><td>{esc(r['skipped_count'])}</td><td>{esc(r['finished_at'])}</td></tr>"
        for r in runs
    )
    job_rows = "".join(
        f"<tr><td>{esc(job.name)}</td><td>{esc(job.status)}</td><td>{esc(job.started_at)}</td><td>{esc(job.finished_at or 'Running')}</td><td>{esc(job.result or job.error)}</td></tr>"
        for job in jobs
    )
    body = f"""
    <header><h1>Automation</h1><p>Scheduled collection runs every six hours on Africa/Lagos time. Weekly briefs are generated Monday at 07:00.</p></header>
    <section class="metrics">
      <div><span>{esc('On' if scheduler.enabled else 'Off')}</span><label>Scheduler</label></div>
      <div><span>{esc(scheduler.next_collection_at or 'Pending')}</span><label>Next collection</label></div>
      <div><span>{esc(scheduler.last_collection_at or 'Never')}</span><label>Last collection</label></div>
      <div><span>{esc(scheduler.last_weekly_brief_at or 'Never')}</span><label>Last weekly brief</label></div>
    </section>
    <section class="panel">
      <h2>Manual controls</h2>
      <form method="post" class="actions">
        <button name="action" value="collect" type="submit">Run collection now</button>
        <button name="action" value="brief" type="submit">Generate weekly brief</button>
        <button name="action" value="alerts" type="submit">Dispatch alerts</button>
      </form>
      <p>{esc(scheduler.last_collection_result)}</p>
      <p>{esc(scheduler.last_email_result)}</p>
      <p>{esc(scheduler.last_alert_dispatch_result)}</p>
      <p>{esc(scheduler.last_error)}</p>
    </section>
    <section class="panel">
      <h2>Recent collection runs</h2>
      <table><thead><tr><th>Source</th><th>Status</th><th>Checked</th><th>Logged</th><th>Skipped</th><th>Finished</th></tr></thead><tbody>{run_rows or '<tr><td colspan="6">No runs yet.</td></tr>'}</tbody></table>
    </section>
    <section class="panel">
      <h2>Recent background jobs</h2>
      <table><thead><tr><th>Job</th><th>Status</th><th>Started</th><th>Finished</th><th>Result</th></tr></thead><tbody>{job_rows or '<tr><td colspan="5">No background jobs yet.</td></tr>'}</tbody></table>
    </section>
    """
    return layout("Automation", body, notice)


def report_page() -> bytes:
    markdown = weekly_report_markdown()
    return layout(
        "Weekly Brief",
        f"""
        <header><h1>Weekly Intelligence Brief</h1><p>Generated from logged incidents. Review and edit before client delivery.</p></header>
        <p><a class="button" href="/download/weekly.md">Download Markdown</a></p>
        <pre class="report">{esc(markdown)}</pre>
        """,
    )


def api_dashboard(org_id: str) -> dict:
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
    categories = [row_to_dict(row) for row in rows(
        """
        select threat_category, count(*) as count
        from incidents where org_id = ?
        group by threat_category order by count desc
        """,
        (org_id,),
    )]
    return {"org_id": org_id, "totals": row_to_dict(totals), "categories": categories}


def api_heatmap(org_id: str, days: int) -> dict:
    since = (datetime.now(timezone.utc).astimezone() - timedelta(days=days)).isoformat()
    data = [row_to_dict(row) for row in rows(
        """
        select coalesce(nullif(location_relevance, ''), geo_relevance) as location,
               geo_relevance,
               count(*) as count,
               max(severity) as max_severity
        from incidents
        where org_id = ?
        and collected_at >= ?
        and geo_relevance in ('Lagos', 'Nigeria', 'Client')
        group by location, geo_relevance
        order by max_severity desc, count desc
        """,
        (org_id, since),
    )]
    return {"org_id": org_id, "days": days, "locations": data}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        init_db()
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        notice = urllib.parse.parse_qs(parsed_url.query).get("notice", [""])[0]
        if path.startswith("/api/"):
            self.handle_api_get(path)
        elif path == "/":
            self.respond(200, [], dashboard())
        elif path == "/incidents":
            self.respond(200, [], incidents_page(notice))
        elif path == "/sources":
            self.respond(200, [], sources_page(notice))
        elif path == "/clients":
            self.respond(200, [], clients_page(notice))
        elif path == "/collect":
            self.respond(200, [], collect_page(notice))
        elif path == "/automation":
            self.respond(200, [], automation_page(notice))
        elif path == "/report":
            self.respond(200, [], report_page())
        elif path == "/download/weekly.md":
            self.respond(200, [("Content-Disposition", "attachment; filename=weekly-brief.md")], weekly_report_markdown().encode())
        elif path == "/export/incidents.csv":
            EXPORTS.mkdir(parents=True, exist_ok=True)
            target = EXPORTS / "incidents.csv"
            export_incidents_csv(target)
            self.send_file(target)
        elif path.startswith("/templates/"):
            self.send_file(ROOT / path.lstrip("/"))
        else:
            self.respond(404, [], layout("Not found", "<h1>Not found</h1>"))

    def do_POST(self) -> None:
        init_db()
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/"):
            self.handle_api_post(path)
            return
        data = parse_body(self)
        if path == "/incidents":
            data["collected_at"] = now_iso()
            add_incident(data)
            self.finish_redirect("/incidents")
        elif path == "/sources":
            add_source(data)
            self.finish_redirect("/sources")
        elif path == "/clients":
            add_client(data)
            self.finish_redirect("/clients")
        elif path == "/collect":
            source_id = data.get("source_id", "all")
            extra_keywords = data.get("extra_keywords", "")

            def collect_job() -> str:
                if source_id == "all":
                    checked, created, skipped = collect_all_sources(extra_keywords)
                else:
                    checked, created, skipped = collect_from_source(int(source_id), extra_keywords)
                return f"Checked {checked}, logged {created}, skipped {skipped}."

            job = start_job("Manual collection", collect_job)
            notice = urllib.parse.quote(f"Collection started in background. Job {job.id}.")
            self.finish_redirect(f"/collect?notice={notice}")
        elif path == "/automation":
            if data.get("action") == "collect":
                job = start_job("Manual collection", lambda: (run_collection_once() or "Manual collection completed."))
                notice = urllib.parse.quote(f"Manual collection started. Job {job.id}.")
            elif data.get("action") == "brief":
                job = start_job("Weekly brief", lambda: (run_weekly_brief_once() or "Weekly brief generated and email attempted."))
                notice = urllib.parse.quote(f"Weekly brief started. Job {job.id}.")
            elif data.get("action") == "alerts":
                job = start_job("Alert dispatch", lambda: (run_alert_dispatch_once() or "Alert dispatch completed."))
                notice = urllib.parse.quote(f"Alert dispatch started. Job {job.id}.")
            else:
                notice = urllib.parse.quote("No automation action selected.")
            self.finish_redirect(f"/automation?notice={notice}")
        else:
            self.respond(404, [], layout("Not found", "<h1>Not found</h1>"))

    def do_PATCH(self) -> None:
        init_db()
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/"):
            self.handle_api_patch(path)
        else:
            self.respond_json(404, {"error": "not found"})

    def do_DELETE(self) -> None:
        init_db()
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/"):
            self.handle_api_delete(path)
        else:
            self.respond_json(404, {"error": "not found"})

    def handle_api_get(self, path: str) -> None:
        params = query_params(self.path)
        org_id = api_org(params=params)
        if path == "/api/health":
            self.respond_json(
                200,
                {
                    "ok": True,
                    "service": "lemtik-osint",
                    "time": now_iso(),
                    "storage": "supabase" if USE_POSTGRES else STORAGE_MODE,
                    "database": "supabase/postgres" if USE_POSTGRES else str(DB_PATH),
                    "supabase_configured": bool(SUPABASE_DB_URL),
                },
            )
        elif path == "/api/orgs":
            self.respond_json(200, {"organisations": [row_to_dict(r) for r in rows("select * from organisations order by name")]})
        elif path == "/api/incidents":
            filters = ["org_id = ?"]
            values: list[object] = [org_id]
            if params.get("severity"):
                filters.append("severity = ?")
                values.append(int(params["severity"]))
            if params.get("category"):
                filters.append("threat_category = ?")
                values.append(params["category"])
            if params.get("days"):
                since = (datetime.now(timezone.utc).astimezone() - timedelta(days=int(params["days"]))).isoformat()
                filters.append("collected_at >= ?")
                values.append(since)
            incidents = rows(
                f"select * from incidents where {' and '.join(filters)} order by severity desc, collected_at desc limit 200",
                tuple(values),
            )
            self.respond_json(200, {"incidents": [row_to_dict(r) for r in incidents]})
        elif path.startswith("/api/incidents/"):
            incident_id = path.rsplit("/", 1)[-1]
            found = rows("select * from incidents where id = ? and org_id = ?", (incident_id, org_id))
            self.respond_json(200 if found else 404, row_to_dict(found[0]) if found else {"error": "incident not found"})
        elif path == "/api/sources":
            self.respond_json(200, {"sources": [row_to_dict(r) for r in rows("select * from sources where org_id = ? order by name", (org_id,))]})
        elif path == "/api/clients":
            self.respond_json(200, {"clients": [row_to_dict(r) for r in rows("select * from clients where org_id = ? order by name", (org_id,))]})
        elif path == "/api/briefs":
            days = int(params.get("days", "7"))
            if params.get("stored") == "1":
                briefs = rows("select * from briefs where org_id = ? order by generated_at desc limit 50", (org_id,))
                self.respond_json(200, {"briefs": [row_to_dict(r) for r in briefs]})
            else:
                self.respond_json(200, {"org_id": org_id, "days": days, "markdown": weekly_report_markdown(days, org_id)})
        elif path == "/api/alerts":
            alerts = rows("select * from alert_events where org_id = ? order by created_at desc limit 100", (org_id,))
            self.respond_json(200, {"alerts": [row_to_dict(r) for r in alerts]})
        elif path == "/api/nlp/classify":
            text = params.get("text", "")
            if not text:
                self.respond_json(400, {"error": "text query parameter is required"})
                return
            custom_keywords = [kw.strip() for kw in params.get("custom_keywords", "").split(",") if kw.strip()]
            self.respond_json(200, classify_text(text, credibility=params.get("credibility", "B"), custom_keywords=custom_keywords))
        elif path == "/api/analytics/dashboard":
            self.respond_json(200, api_dashboard(org_id))
        elif path == "/api/analytics/heatmap":
            self.respond_json(200, api_heatmap(org_id, int(params.get("days", "30"))))
        else:
            self.respond_json(404, {"error": "api route not found"})

    def handle_api_post(self, path: str) -> None:
        data = parse_json_body(self)
        params = query_params(self.path)
        org_id = api_org(params=params, data=data)
        data["org_id"] = org_id
        if path == "/api/orgs":
            add_organisation(data)
            self.respond_json(201, {"ok": True})
        elif path == "/api/incidents":
            data["collected_at"] = data.get("collected_at") or now_iso()
            created = add_incident(data)
            self.respond_json(201 if created else 409, {"ok": created, "duplicate": not created})
        elif path == "/api/sources":
            add_source(data)
            self.respond_json(201, {"ok": True})
        elif path == "/api/clients":
            add_client(data)
            self.respond_json(201, {"ok": True})
        elif path.startswith("/api/sources/") and path.endswith("/collect"):
            source_id = int(path.split("/")[-2])
            checked, created, skipped = collect_from_source(source_id, data.get("extra_keywords", ""), org_id)
            self.respond_json(200, {"checked": checked, "created": created, "skipped": skipped})
        elif path == "/api/briefs/generate":
            days = int(data.get("days", 7))
            target = generate_weekly_brief_file(days, org_id)
            self.respond_json(201, {"path": str(target), "markdown": weekly_report_markdown(days, org_id)})
        elif path == "/api/alerts/dispatch":
            self.respond_json(200, dispatch_pending_alerts(org_id, int(data.get("limit", 20))))
        elif path == "/api/nlp/classify":
            text = str(data.get("text", ""))
            if not text:
                self.respond_json(400, {"error": "text is required"})
                return
            custom_keywords = data.get("custom_keywords") or []
            if isinstance(custom_keywords, str):
                custom_keywords = [kw.strip() for kw in custom_keywords.split(",") if kw.strip()]
            self.respond_json(
                200,
                classify_text(
                    text,
                    credibility=str(data.get("credibility") or "B"),
                    verified=data.get("verified"),
                    custom_keywords=custom_keywords,
                ),
            )
        else:
            self.respond_json(404, {"error": "api route not found"})

    def handle_api_patch(self, path: str) -> None:
        data = parse_json_body(self)
        params = query_params(self.path)
        org_id = api_org(params=params, data=data)
        if path.startswith("/api/incidents/"):
            incident_id = path.rsplit("/", 1)[-1]
            allowed = ["summary", "severity", "verified", "verification_source", "client_notified", "notification_method", "status", "analyst", "notes", "geo_relevance", "location_relevance"]
            updates = [(key, data[key]) for key in allowed if key in data]
            if not updates:
                self.respond_json(400, {"error": "no allowed fields supplied"})
                return
            set_sql = ", ".join(f"{key} = ?" for key, _ in updates)
            values = [value for _, value in updates] + [incident_id, org_id]
            rows(f"select id from incidents where id = ? and org_id = ?", (incident_id, org_id))
            from operations.core import execute
            execute(f"update incidents set {set_sql} where id = ? and org_id = ?", tuple(values))
            self.respond_json(200, {"ok": True})
        else:
            self.respond_json(404, {"error": "api route not found"})

    def handle_api_delete(self, path: str) -> None:
        params = query_params(self.path)
        org_id = api_org(params=params)
        if path.startswith("/api/sources/"):
            source_id = path.rsplit("/", 1)[-1]
            from operations.core import execute
            execute("delete from sources where id = ? and org_id = ?", (source_id, org_id))
            self.respond_json(200, {"ok": True})
        else:
            self.respond_json(404, {"error": "api route not found"})

    def finish_redirect(self, location: str) -> None:
        try:
            self.send_response(303)
            self.send_header("Location", location)
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError):
            return

    def send_file(self, path: Path) -> None:
        if not path.exists() or not path.is_file():
            self.respond(404, [], b"Not found")
            return
        mime = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        self.respond(200, [], path.read_bytes(), content_type=mime)

    def respond(self, status: int, headers: list[tuple[str, str]], body: bytes, content_type: str = "text/html; charset=utf-8") -> None:
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for key, value in headers:
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return

    def respond_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.respond(status, [], body, "application/json; charset=utf-8")

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"{self.address_string()} - {fmt % args}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Lemtik Security local OSINT operations tool")
    parser.add_argument("--host", default=os.getenv("LEMTIK_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("LEMTIK_PORT", "8765")))
    parser.add_argument("--no-scheduler", action="store_true", help="Disable background collection scheduler")
    args = parser.parse_args()
    init_db()
    if not args.no_scheduler:
        start_scheduler()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Lemtik OSINT running at http://{args.host}:{args.port}")
    print(f"Database: {'supabase/postgres' if USE_POSTGRES else DB_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nLemtik OSINT stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
