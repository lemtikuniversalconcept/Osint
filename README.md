# Lemtik Security OSINT Tool

Render-deployable OSINT service for public-source security monitoring, incident logging, verification tracking, weekly brief generation, and callable intelligence endpoints.

## Run

```bash
uvicorn brain_api:app --host 127.0.0.1 --port 8770
```

The local browser dashboard in `app.py` is still available for offline use, but the Render target is the FastAPI OSINT service in `brain_api.py`.

SQLite mode uses only Python standard-library modules. Supabase/Postgres mode requires `psycopg2-binary`.

## What It Does

- Maintains a local SQLite intelligence log in `data/lemtik_osint.sqlite3`.
- Stores source registry entries with credibility tiers A, B, and C.
- Stores client areas and service tiers.
- Logs incidents using the fields from `todo.md`.
- Estimates category, severity, quality score, and confidence from public-source text.
- Uses whole-word keyword matching to avoid substring false positives such as `bec` in `biscuits`.
- Applies Lagos/Nigeria geographic filtering before collected items enter the client-facing brief.
- Fetches public web pages or RSS feeds, prefers RSS feeds where available, and logs keyword matches for analyst verification.
- Filters low-value page chrome, JavaScript blocker pages, generic navigation text, and duplicate content.
- Tracks source health and recent collection runs.
- Runs scheduled auto-collection every six hours while the app server is running.
- Runs manual collection, brief generation, and alert dispatch as background jobs so the browser does not wait for long collection runs.
- Generates the weekly brief file automatically on Mondays at 07:00 Africa/Lagos time while the app server is running.
- Sends weekly brief email automatically through Resend when environment variables are configured.
- Exposes Phase 2 JSON API endpoints for incidents, sources, clients, briefs, and analytics.
- Exposes a FastAPI OSINT service for threat classification, entity extraction, collection, briefs, alerts, diagnostics, and queued tasks.
- Adds NLP-style enrichment with optional spaCy support and a rule-based fallback when model packages are not installed.
- Generates a weekly intelligence brief in Markdown with verification posture and analyst review queue.
- Exports the incident log as CSV.

## Operating Boundaries

This tool is for lawful OSINT only:

- Use public sources only.
- Do not access private accounts, private groups, protected systems, or leaked private databases.
- Treat auto-collected items as unverified until an analyst confirms them.
- Do not treat the confidence score as truth. It is a triage aid for analysts.
- Verify Severity 3+ incidents before client delivery.
- Escalate Severity 4-5 items through the immediate alert workflow in `todo.md`.

## Project Layout

```text
app.py                 Local browser server and routes
operations/core.py     Database, collection, classification, reports
operations/nlp.py      Entity extraction, threat scoring, classification enrichment
operations/intel.py    Tasking packet builder for the relationship API
operations/brain.py    OSINT query, diagnostics, and source planning
operations/scheduler.py Background collection and brief scheduler
operations/env.py       Local .env loader
brain_api.py           FastAPI OSINT service for Render deployment
templates/style.css    Dashboard styling
data/                  SQLite database and CSV exports
supabase.sql           Supabase schema bootstrap
tocheck.sql            Supabase verification queries
migrations/            SQL migration helpers
todo.md                Operating methodology
addoninfo.md           Additional OSINT notes
```

## Supabase

For a new empty Supabase project:

```bash
python3 -m pip install -r requirements.txt
```

Run `supabase.sql` in the Supabase SQL editor. Then run `tocheck.sql` to inspect tables, columns, indexes, triggers, functions, policies, RLS state, and seed counts.

Switch the app to Supabase in `.env`:

```bash
LEMTIK_STORAGE=supabase
SUPABASE_DB_URL=postgresql://postgres:<password>@db.<project-ref>.supabase.co:5432/postgres
SUPABASE_SSLMODE=require
POSTGRES_CONNECT_TIMEOUT=8
POSTGRES_POOL_MIN=1
POSTGRES_POOL_MAX=5
LEMTIK_API_KEYS=
```

The app still supports SQLite by setting `LEMTIK_STORAGE=sqlite`.

## Automation

The server starts the scheduler by default:

```bash
python3 app.py --host 127.0.0.1 --port 8765
```

To run without background automation:

```bash
python3 app.py --host 127.0.0.1 --port 8765 --no-scheduler
```

Optional weekly brief email delivery through Resend:

```bash
export RESEND_API_KEY="re_xxxxxxxxx"
export LEMTIK_BRIEF_EMAIL_FROM="briefs@lemtiksecurity.com"
export LEMTIK_BRIEF_EMAIL_TO="client@example.com,analyst@example.com"
```

Manual collection and automation buttons return immediately. Check the Automation page for background job status and collection-run results.

## Phase 2 API

The local server now exposes JSON endpoints under `/api`. Use `org_id=default` unless you create another organisation.

```text
GET  /api/health
GET  /api/orgs
POST /api/orgs
GET  /api/incidents?org_id=default&severity=&category=&days=
POST /api/incidents
PATCH /api/incidents/{id}
GET  /api/sources?org_id=default
POST /api/sources
DELETE /api/sources/{id}?org_id=default
POST /api/sources/{id}/collect
GET  /api/clients?org_id=default
POST /api/clients
GET  /api/briefs?org_id=default&days=7
GET  /api/briefs?org_id=default&stored=1
POST /api/briefs/generate
GET  /api/alerts?org_id=default
GET  /api/nlp/classify?text=Police%20arrested%20suspects%20in%20Lekki
POST /api/nlp/classify
GET  /api/analytics/dashboard?org_id=default
GET  /api/analytics/heatmap?org_id=default&days=30
```

## FastAPI Brain Service

Install dependencies inside the project virtualenv:

```bash
.venv/bin/python -m pip install -r requirements.txt
```

Run the Render-target OSINT API locally:

```bash
.venv/bin/uvicorn brain_api:app --host 127.0.0.1 --port 8770
```

Open the API docs:

```bash
http://127.0.0.1:8770/docs
```

## Render

Render uses the OSINT API service only. The service start command is:

```text
uvicorn brain_api:app --host 0.0.0.0 --port $PORT
```

See `api.md` for the endpoint contract and `push.md` for the GitHub and Render deployment steps.

API auth is optional for local development. To protect the FastAPI OSINT service, set:

```bash
LEMTIK_API_KEYS=your-long-random-key:default:admin:local-admin
```

Then send requests with:

```text
X-API-Key: your-long-random-key
```

For Supabase-backed API keys and audit history, run:

```text
migrations/002_api_security_audit.sql
```

For queued OSINT tasks and diagnostics, also run:

```text
migrations/003_brain_tasks_queue.sql
```

Core brain endpoints:

```text
GET  /health
POST /classify
GET  /incidents?org_id=default&severity=&category=&days=
POST /incidents
GET  /sources?org_id=default
POST /sources/{id}/collect
POST /collect
GET  /briefs?org_id=default&days=7
POST /briefs/generate
POST /alerts/dispatch
GET  /alerts/worker
POST /alerts/worker/start
POST /alerts/worker/stop
POST /intel/packet
POST /brain/query
GET  /brain/diagnostics
GET  /brain/source-plan
POST /brain/tasks
GET  /brain/tasks
GET  /brain/tasks/item/{task_id}
GET  /brain/tasks/worker
POST /brain/tasks/worker/start
POST /brain/tasks/worker/stop
POST /tasking/resolve
GET  /client-dashboard?org_id=default&days=7
GET  /analytics/dashboard?org_id=default
GET  /analytics/heatmap?org_id=default&days=30
GET  /audit-logs?org_id=default&limit=100
```

Queued brain tasks are the OSINT side of the relationship API handoff. Use them when the main system wants the brain to collect from specific sources, regenerate a brief, or dispatch pending alerts without blocking the request path.

Supported task types include `collect_all`, `collect_source`, `repair_sources`, `brief`, and `dispatch_alerts`. The queue also accepts aliases like `collect`, `repair`, `briefs`, and `alerts`.
