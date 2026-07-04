# GitHub and Render Push Steps

Work from your copied folder, not the original one.

## 1. Clean the copied folder

Run these in the copied project directory:

```bash
rm -rf .venv
find . -type d -name '__pycache__' -prune -exec rm -rf {} +
find . -name '*.pyc' -delete
```

If you want a fresh local state file out of the copy, remove the generated SQLite data too:

```bash
rm -f data/lemtik_osint.sqlite3
rm -f data/exports/*
```

## 2. Push to GitHub

```bash
git init
git add .
git commit -m "Prepare Lemtik OSINT for Render deployment"
git branch -M main
git remote add origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```

If the remote already exists:

```bash
git remote set-url origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```

## 3. Deploy on Render

Use the repository you just pushed and connect it in Render.

Render will read `render.yaml` and create the service with this start command:

```bash
uvicorn brain_api:app --host 0.0.0.0 --port $PORT
```

Render deployment path:

1. Open Render.
2. Create a new Blueprint instance or new Web Service from the GitHub repo.
3. Select the pushed repository and the `main` branch.
4. Let Render read `render.yaml`.
5. Add the environment variables below.
6. Deploy.

Set these environment variables in Render:

```bash
LEMTIK_STORAGE=supabase
SUPABASE_DB_URL=postgresql://postgres:<password>@db.<project-ref>.supabase.co:5432/postgres
SUPABASE_SSLMODE=require
POSTGRES_CONNECT_TIMEOUT=8
POSTGRES_POOL_MIN=1
POSTGRES_POOL_MAX=5
LEMTIK_DEFAULT_ORG_ID=default
LEMTIK_API_KEYS=your-long-random-key:default:admin:local-admin
RESEND_API_KEY=re_your_resend_api_key
LEMTIK_BRIEF_EMAIL_FROM=briefs@your-domain.com
LEMTIK_BRIEF_EMAIL_TO=client@example.com
LEMTIK_ALERT_EMAIL_FROM=alerts@your-domain.com
LEMTIK_ALERT_EMAIL_TO=security-manager@example.com
LEMTIK_ALERT_WORKER_INTERVAL_SECONDS=60
LEMTIK_ALERT_RETRY_MINUTES=15
LEMTIK_DASHBOARD_CACHE_SECONDS=30
LEMTIK_ENABLE_SPACY=0
LEMTIK_ENABLE_TRANSFORMERS=0
```

## 4. Run the Supabase SQL files

Run these in order on the empty Supabase project:

```text
migrations/001_supabase_schema.sql
migrations/002_api_security_audit.sql
migrations/003_brain_tasks_queue.sql
```

## 5. Verify after deploy

Open:

```text
https://<your-render-service>.onrender.com/health
https://<your-render-service>.onrender.com/brain/diagnostics
```

Then test one API call:

```bash
curl -s https://<your-render-service>.onrender.com/brain/query \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-long-random-key" \
  -d '{"org_id":"default","question":"What happened in Lekki?","lookback_days":180,"recent_limit":10}'
```
