# Lemtik Security — OSINT Platform Scaling Roadmap
### From SQLite Script to Africa's Premier Urban Intelligence Platform
**Classification:** Internal Engineering & Strategy
**Version:** 1.0
**Status:** Active Roadmap

---

## Executive Context

You have built a working v0.1 OSINT pipeline in Python — RSS ingestion, keyword detection,
severity scoring, deduplication, SQLite storage, and a weekly brief generator. That is a
real foundation. What you have not yet built is a platform that scales to 50 clients, 100
sources, real-time alerts, NLP-powered classification, and a multi-tenant SaaS architecture.

This document maps the full journey from where you are today to a platform that can
compete with what the global OSINT market — now exceeding $29 billion — is building.
The difference is you are building it for Lagos first, then Nigeria, then Africa.
That specificity is your moat. Generic platforms cannot outcompete you on local context.

---

## The Three Scaling Phases

```
Phase 1 — Stabilise (Now )
  Fix the current codebase. More sources. Better filtering.
  Scheduled auto-collection. First paying client.

Phase 2 — Productise 
  Multi-tenant SaaS. Client dashboards. API layer.
  Real-time alerts. NLP classification. PostgreSQL migration.

Phase 3 — Industrialise 
  Kafka pipeline. Elasticsearch. AI threat scoring.
  Dark web monitoring. Pan-Nigeria expansion.
  Government-grade platform.
```

---

## Phase 1 — Stabilise the Current Codebase

### 1.1 Fix False Positives 

Your current keyword matching is substring-based. "bec" matches "biscuits."
"strike" matches "airstrikes." This produces garbage intelligence.
Replace every keyword check with whole-word regex matching.

```python
import re

def keyword_matches(text: str, keywords: list[str]) -> list[str]:
    lower = text.lower()
    hits = []
    for kw in keywords:
        # Escape special chars, match whole words only
        pattern = r'(?<!\w)' + re.escape(kw) + r'(?!\w)'
        if re.search(pattern, lower):
            hits.append(kw)
    return hits
```

Impact: eliminates ~60% of current false positives immediately.

---

### 1.2 Geographic Relevance Filter (

Stories about Gaza, Iran, Ebonyi, and Sambisa are not Lagos intelligence.
Add a two-tier geographic filter before any item enters your database.

```python
NIGERIA_KEYWORDS = [
    "nigeria", "nigerian", "abuja", "lagos", "kano", "ibadan",
    "port harcourt", "enugu", "kaduna", "benin city", "onitsha",
    "aba", "warri", "zaria", "ilorin", "jos", "maiduguri",
    "efcc", "dss", "nsc", "npf", "police nigeria",
    "lasema", "lastma", "lawma",
]

LAGOS_KEYWORDS = [
    "lagos", "lekki", "victoria island", "vi", "ikoyi", "ajah",
    "ikeja", "surulere", "yaba", "oshodi", "alaba", "festac",
    "badagry", "ikorodu", "epe", "agege", "mushin", "isale eko",
    "apapa", "tin can", "maryland", "ojota", "mile 2",
    "sangotedo", "jakande", "chevron", "osapa", "igbo efon",
]

def geo_relevance_score(text: str, custom_keywords: list[str]) -> str:
    """Returns 'Lagos', 'Nigeria', 'None' """
    lower = text.lower()
    if any(kw in lower for kw in LAGOS_KEYWORDS + custom_keywords):
        return "Lagos"
    if any(kw in lower for kw in NIGERIA_KEYWORDS):
        return "Nigeria"
    return "None"
```

Items with geo_relevance = "None" are skipped entirely unless a
client-specific keyword matches. This alone makes your briefs
immediately more credible.

---

### 1.3 Scheduled Auto-Collection 

Stop requiring someone to click "Collect." Use APScheduler to run
collection automatically every 6 hours, 24/7.

```bash
pip install apscheduler
```

```python
# In your app startup
from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler(timezone="Africa/Lagos")

scheduler.add_job(
    collect_all_sources,
    'cron',
    hour='6,12,18,0',   # 6am, 12pm, 6pm, midnight Lagos time
    id='auto_collect',
    replace_existing=True
)

scheduler.add_job(
    generate_and_email_weekly_brief,
    'cron',
    day_of_week='mon',
    hour=7,
    minute=0,
    id='weekly_brief',
    replace_existing=True
)

scheduler.start()
```

---

### 1.4 Fix SSL Error for NPF and Government Sites 

Nigerian government websites often have certificate issues.
Create a lenient context only for known-problematic domains.

```python
import ssl

LENIENT_SSL_DOMAINS = [
    "npf.gov.ng", "lagosstate.gov.ng", "efccnigeria.org",
    "lasema.gov.ng", "lasg.gov.ng",
]

def fetch_public_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    use_lenient = any(domain in parsed.netloc for domain in LENIENT_SSL_DOMAINS)

    ctx = ssl.create_default_context()
    if use_lenient:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "LemtikSecurityOSINT/1.0 (public-source analyst tool)",
            "Accept": "text/html,application/rss+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )
    with urllib.request.urlopen(req, timeout=15, context=ctx) as response:
        return response.read(1_000_000).decode("utf-8", errors="replace")
```

---

### 1.5 Expand Source Coverage 

Add these RSS feeds to your DEFAULT_SOURCES immediately.
All are free, all are high-credibility Nigerian sources.

```python
EXPANDED_SOURCES = [
    # Tier A — Nigerian News
    ("Premium Times",     "News",     "https://www.premiumtimesng.com/feed",          "A"),
    ("The Nation",        "News",     "https://thenationonlineng.net/feed/",           "A"),
    ("Daily Trust",       "News",     "https://dailytrust.com/feed",                   "A"),
    ("Guardian Nigeria",  "News",     "https://guardian.ng/feed/",                     "A"),
    ("Thisday Live",      "News",     "https://www.thisdaylive.com/index.php/feed/",   "A"),

    # Tier A — Official
    ("EFCC Nigeria",      "Official", "https://efccnigeria.org/efcc/feed",             "A"),
    ("CBN Nigeria",       "Official", "https://www.cbn.gov.ng/rss/",                  "A"),

    # Tier B — Investigative
    ("SaharaReporters",   "News",     "https://saharareporters.com/rss.xml",           "B"),
    ("Peoples Gazette",   "News",     "https://gazettengr.com/feed/",                  "B"),
    ("HumAngle",          "News",     "https://humanglemedia.com/feed/",               "B"),

    # Tier B — Twitter via Nitter RSS (no API key needed)
    ("NigeriaPolice@X",  "Social",   "https://nitter.net/PoliceNG_Force/rss",         "B"),
    ("LASEMA@X",         "Social",   "https://nitter.net/LASG_LASEMA/rss",            "B"),
    ("LagosTraffic@X",   "Social",   "https://nitter.net/LagosTraffic/rss",           "B"),
    ("ChannelsTV@X",     "Social",   "https://nitter.net/channelstv/rss",             "B"),
]
```

**Why Nitter:** Twitter/X blocks direct scraping. Nitter is an open-source
frontend that exposes RSS feeds for any public Twitter account.
No API key, no cost. Use `nitter.net` or self-host a Nitter instance
for reliability.

---

### 1.6 Phase 1 Target State

By end of Month 3 your pipeline should:

| Metric | Current | Target |
|---|---|---|
| Sources monitored | 7 | 20+ |
| False positive rate | ~40% | <10% |
| Collection frequency | Manual | Every 6 hours |
| Geographic filtering | None | Lagos + Nigeria tiers |
| SSL failures | 1+ | 0 |
| Weekly briefs | Manual | Auto-generated + emailed |
| Paying clients | 0 | 1–2 |

---

## Phase 2 — Productise 

This phase converts your single-tenant Python script into a proper
multi-tenant SaaS platform. This is the architecture shift that
allows you to serve 50 clients simultaneously.

### 2.1 Migrate from SQLite to PostgreSQL

SQLite works for one user on one machine. The moment you have
multiple clients, concurrent writes, or deploy to a server,
you need PostgreSQL Supabase specifically.

**Migration path:**
- Provision a Supabase project (free tier)
- Use Alembic (Python migration tool) to recreate your schema in Postgres
- Update all `sqlite3` calls to use `psycopg2` or SQLAlchemy
- Add `org_id` foreign key to every table for multi-tenancy

```bash
pip install psycopg2-binary sqlalchemy alembic
```

**Multi-tenancy schema addition:**
Every table gets an `org_id` column. Every query filters by `org_id`.
Client A never sees Client B's data. This is the foundation of SaaS.

```sql
-- Add to every table
org_id UUID NOT NULL REFERENCES organisations(id),

-- Every query becomes
SELECT * FROM incidents
WHERE org_id = $1
AND collected_at >= $2
ORDER BY severity DESC;
```

---

### 2.2 Build the API Layer (FastAPI/Nodejs)

Replace your current Flask/web UI with a proper REST API.
This separates the backend from the frontend and allows you to
build a proper React dashboard later.

**Why FastAPI over Flask:**
- Automatic OpenAPI documentation (your clients can see your API)
- Native async support — critical for concurrent collection jobs
- Type safety via Pydantic — catches bugs before runtime
- 3x faster than Flask for I/O-heavy workloads

```bash
pip install fastapi uvicorn pydantic python-jose passlib
```

**Core API endpoints:**

Use Node js for auth and in app api and use Fatapi for the brain itself

```
POST   /auth/login
POST   /auth/register
GET    /auth/me

GET    /incidents?org_id=&severity=&category=&days=
POST   /incidents
GET    /incidents/{id}
PATCH  /incidents/{id}

GET    /sources?org_id=
POST   /sources
DELETE /sources/{id}
POST   /sources/{id}/collect

GET    /clients
POST   /clients
GET    /clients/{id}

GET    /briefs?org_id=&days=
POST   /briefs/generate
GET    /briefs/{id}/download

GET    /analytics/dashboard?org_id=
GET    /analytics/heatmap?org_id=&days=
```

---

### 2.3 Add NLP Classification (The Intelligence Upgrade)

This is the biggest upgrade in Phase 2. Instead of keyword matching,
you use a proper NLP model to classify threats. The difference:

- **Keyword matching:** "strike" matches "airstrikes" (wrong)
- **NLP classification:** understands context, extracts entities,
  determines actual threat relevance

**Tools — free and open source:**

```bash
pip install spacy transformers torch
python -m spacy download en_core_web_sm
```

**Named Entity Recognition (NER) — extract locations, organisations, people:**

```python
import spacy

nlp = spacy.load("en_core_web_sm")

def extract_entities(text: str) -> dict:
    doc = nlp(text)
    return {
        "locations": [ent.text for ent in doc.ents if ent.label_ in ("GPE", "LOC")],
        "organisations": [ent.text for ent in doc.ents if ent.label_ == "ORG"],
        "people": [ent.text for ent in doc.ents if ent.label_ == "PERSON"],
    }

# Usage
entities = extract_entities("Police arrested three suspects in Lekki Phase 1 after a robbery")
# Returns: {"locations": ["Lekki Phase 1"], "organisations": ["Police"], "people": []}
```

**Sentiment and Threat Scoring — use a pre-trained model:**

```python
from transformers import pipeline

# Load once at startup — do not load per request
threat_classifier = pipeline(
    "text-classification",
    model="distilbert-base-uncased-finetuned-sst-2-english",
    device=-1  # CPU (use 0 for GPU if available)
)

def classify_threat_sentiment(text: str) -> float:
    """Returns a 0.0–1.0 threat score"""
    result = threat_classifier(text[:512])[0]
    if result["label"] == "NEGATIVE":
        return round(result["score"], 3)
    return round(1.0 - result["score"], 3)
```

**Fine-tuning for Lagos (Month 6+):**
As you accumulate verified incidents, you build a labelled dataset
and fine-tune a model specifically on Nigerian security language.
"Agberos," "one-chance," "area boys" — these terms mean nothing
to a US-trained model. Your fine-tuned model will outperform
Recorded Future on Nigerian threat intelligence.
This is your long-term technical moat.

---

### 2.4 Real-Time Alert Pipeline

When a Severity 4–5 incident is detected, clients must know
within minutes, not the next morning's brief.

**Architecture:**

```
Collection job detects Severity 4+
    ↓
Publish to Redis Pub/Sub channel
    ↓
Alert worker picks up event
    ↓
Parallel dispatch:
    ├── WhatsApp (Bailey) → client security manager
    └── Email (Resend) → full alert PDF
```

```python
# requirements
pip install redis twilio resend

# Alert dispatcher
import redis
import json

redis_client = redis.from_url(os.getenv("REDIS_URL"))

def publish_alert(incident: dict) -> None:
    if incident["severity"] >= 4:
        redis_client.publish(
            "lemtik:alerts",
            json.dumps({
                "incident_id": incident["log_id"],
                "severity": incident["severity"],
                "summary": incident["summary"],
                "org_ids": get_affected_orgs(incident),
            })
        )

# Alert worker (runs as separate process)
def alert_worker():
    pubsub = redis_client.pubsub()
    pubsub.subscribe("lemtik:alerts")
    for message in pubsub.listen():
        if message["type"] == "message":
            alert = json.loads(message["data"])
            dispatch_whatsapp(alert)
            dispatch_sms(alert)
            dispatch_email(alert)
```

---

### 2.5 Next.js Frontend (The Client-Facing Dashboard)

Your current Python web UI is an internal analyst tool.
Paying clients need a proper branded dashboard.

Build a React frontend (per the main tech stack document) that connects
to your FastAPI backend. Key client-facing views:

**Client Dashboard:**
- Live feed of incidents relevant to their location
- Current week's risk rating (Red/Orange/Green)
- Recent alerts received
- Latest intelligence brief (download PDF)
- Incident map for their area

**Analyst Dashboard (internal):**
- All incidents across all clients
- Verification queue (Severity 3+ unverified)
- Source health monitoring
- Collection run history
- Brief generation and delivery

---

### 2.6 Phase 2 Target State

| Metric | Phase 1 End | Phase 2 Target |
|---|---|---|
| Architecture | SQLite + Python script | PostgreSQL + FastAPI + React |
| Clients | 1–2 | 10–15 |
| Sources | 20+ | 40+ |
| Classification | Keyword matching | NLP + entity extraction |
| Alerts | Manual | Real-time automated |
| Revenue | ₦150k–₦300k/month | ₦1.5M–₦3M/month |
| Team | 3–5 people | 6–10 people |

---

## Phase 3 — Industrialise (Month 9 → Month 24)

This is where Lemtik becomes infrastructure, not just a service.
The architecture at this phase is what enterprise and government
clients require.

### 3.1 Event Streaming with Apache Kafka

At scale, your collection pipeline produces thousands of items per hour
across dozens of sources. A synchronous Python loop cannot handle this.
You need an event streaming architecture.

**What Kafka does:**
Every collected item is published as an event. Multiple independent
workers consume events in parallel — one for NLP classification,
one for geo-filtering, one for alert detection, one for storage.
Each worker can be scaled independently.

```
Sources (RSS, scraper, social)
    ↓
Kafka Topic: raw_intelligence
    ↓
Consumer Group 1: NLP Classifier → Topic: classified_intelligence
Consumer Group 2: Geo Filter → Topic: filtered_intelligence
Consumer Group 3: Deduplicator → Topic: unique_intelligence
Consumer Group 4: Alert Detector → Topic: alerts
    ↓
Storage Workers → PostgreSQL + Elasticsearch
Alert Workers → WhatsApp + SMS + Email
```

**Setup with Docker Compose (development):**

```yaml
version: '3.8'
services:
  zookeeper:
    image: confluentinc/cp-zookeeper:7.5.0
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181

  kafka:
    image: confluentinc/cp-kafka:7.5.0
    depends_on: [zookeeper]
    ports:
      - "9092:9092"
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
      KAFKA_AUTO_CREATE_TOPICS_ENABLE: 'true'
```

```bash
pip install kafka-python confluent-kafka
```

**Production hosting:** Confluent Cloud free tier (no server management)
or Upstash Kafka (serverless, pay per message).

---

### 3.2 Elasticsearch for Intelligence Search

At 10,000+ incidents, PostgreSQL LIKE queries become slow.
Elasticsearch provides:
- Full-text search across all intelligence in milliseconds
- Fuzzy matching ("leki" finds "Lekki")
- Aggregations for heatmaps and trend analysis
- Near-real-time indexing

```bash
pip install elasticsearch
```

```python
from elasticsearch import Elasticsearch

es = Elasticsearch(os.getenv("ELASTICSEARCH_URL"))

# Index incident
es.index(
    index="lemtik_incidents",
    id=incident["log_id"],
    document={
        "summary": incident["summary"],
        "category": incident["threat_category"],
        "severity": incident["severity"],
        "location": incident["location_relevance"],
        "collected_at": incident["collected_at"],
        "geo_point": {
            "lat": incident.get("lat"),
            "lon": incident.get("lng"),
        }
    }
)

# Search
results = es.search(
    index="lemtik_incidents",
    query={
        "bool": {
            "must": [{"match": {"summary": "kidnapping"}}],
            "filter": [
                {"term": {"category": "Physical"}},
                {"range": {"severity": {"gte": 3}}}
            ]
        }
    }
)
```

**Hosting:** Elastic Cloud free trial, then $16/month.
Or self-host on a $6/month DigitalOcean droplet.

---

### 3.3 AI Threat Intelligence Layer

This is what separates Lemtik from every other Lagos security firm.
By Phase 3 you have 6–12 months of verified Nigerian threat data.
You use it to build models that no external vendor can replicate.

**Model 1 — Lagos Threat Classifier**
Fine-tuned on your own verified incident dataset.
Classifies incidents with far higher accuracy than generic NLP models.
Understands Nigerian pidgin, local place names, local criminal vocabulary.

```python
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
)

# Fine-tune on your verified incidents
# Your verified incidents become training data
# Labels: Physical / Cyber / Political / Macro / Irrelevant
```

**Model 2 — Predictive Risk Scoring**
Uses historical incident patterns to predict:
- Which areas will have elevated risk this weekend?
- Does a spike in political activity correlate with robbery increases?
- What is the 7-day risk forecast for a client's location?

Tools: scikit-learn for baseline models, Prophet for time-series forecasting.

```bash
pip install scikit-learn prophet
```

**Model 3 — Entity Network Mapping**
Links people, locations, organisations across incidents.
"Is this the same gang that robbed three estates in Lekki last month?"
Tool: NetworkX for graph analysis, Neo4j for production.

---

### 3.4 Dark Web Monitoring (Government-Grade Feature)

Criminal networks in Nigeria increasingly use Telegram private channels,
dark web forums, and encrypted messaging to coordinate.

**What this monitors:**
- Tor hidden services (.onion sites) mentioning Nigerian targets
- Paste sites (Pastebin, Ghostbin) with leaked Nigerian data
- Criminal Telegram channels (public ones you can join)
- Data breach marketplaces for leaked Nigerian credentials

**Tools:**
```bash
pip install stem requests[socks]  # Tor access
pip install telethon               # Telegram monitoring
```

**Important:** Dark web monitoring requires a dedicated secure environment
(separate VM, VPN, Tor), strict legal framework, and eventually a
security clearance arrangement with appropriate government bodies.
Do not build this until you have a legal team review.

---

### 3.5 Multi-Region Expansion Architecture

Lagos → Nigeria → West Africa.

When you expand beyond Lagos, your architecture must support:
- Per-city intelligence teams and source sets
- City-specific NLP models (Abuja threats ≠ Lagos threats)
- Cross-city pattern detection (kidnapping gang moving from Abuja to Lagos)
- Country-specific client isolation (Nigerian client cannot see Ghanaian data)

**Database partitioning strategy:**
```sql
-- Partition incidents by region for query performance
CREATE TABLE incidents_lagos PARTITION OF incidents
    FOR VALUES IN ('lagos');

CREATE TABLE incidents_abuja PARTITION OF incidents
    FOR VALUES IN ('abuja');

CREATE TABLE incidents_portHarcourt PARTITION OF incidents
    FOR VALUES IN ('port_harcourt');
```

---

### 3.6 Government-Grade Security Requirements

When you pitch Lagos State Government, they will ask about these.
Build them before the pitch, not after.

**ISO 27001 alignment** (
- Asset inventory
- Access control policy
- Incident response procedure
- Data classification policy
- Business continuity plan

**Data residency:**
All Nigerian data must stay in Nigeria or at minimum Africa.
Use AWS Africa (Cape Town) or Azure South Africa North region.
Do not store government client data on US servers.

**Audit logging:**
Every query, every export, every login logged immutably.
Government clients will ask "who saw this data and when?"

**Penetration testing:**
Before any government contract, commission a pentest.
Several Nigerian cybersecurity firms offer this.
Budget ₦500,000–₦1,500,000.

---

## Full Technology Stack by Phase

### Phase 1 — Current + Fixes
```
Language:       Python 3.11+
Web framework:  Flask (keep for now)
Database:       SQLite → migrate in Phase 2
Scheduling:     APScheduler
NLP:            Regex keyword matching → upgrade Phase 2
Scraping:       urllib + feedparser
Hosting:        Local / PythonAnywhere free tier
Cost:           ₦0/month
```

### Phase 2 — Productise
```
Language:       Python (backend) + TypeScript/React (frontend)
API:            FastAPI + Uvicorn
Database:       PostgreSQL (Supabase)
Cache/Queue:    Redis (Upstash)
NLP:            spaCy + HuggingFace Transformers
Search:         PostgreSQL full-text (upgrade to ES in Phase 3)
Alerts:         Redis Pub/Sub + Twilio + Termii + Resend
Scheduling:     APScheduler → Celery (when jobs exceed 10)
Hosting:        Railway (API) + Vercel (frontend) + Supabase (DB)
Cost:           ~$50/month (~₦75,000/month)
Revenue needed: 1 client at ₦150,000 covers it
```

### Phase 3 — Industrialise
```
Language:       Python + TypeScript + Go (high-performance scrapers)
API:            FastAPI (microservices)
Database:       PostgreSQL (Supabase Pro) + Elasticsearch
Streaming:      Apache Kafka (Confluent Cloud)
Cache:          Redis Cluster
NLP:            Fine-tuned Nigerian threat model (HuggingFace)
ML:             scikit-learn + Prophet (forecasting) + PyTorch (custom models)
Graph:          Neo4j (entity network mapping)
Monitoring:     Prometheus + Grafana
Hosting:        AWS Africa (Cape Town) — data residency compliance
CI/CD:          GitHub Actions + Docker + Kubernetes
Cost:           ~$500–$1,500/month
Revenue needed: 5+ enterprise clients
```

---

## Data Pipeline Architecture (Phase 3 Full View)

```
┌─────────────────────────────────────────────────────────────────┐
│                     COLLECTION LAYER                            │
│  RSS Scrapers │ Twitter/Nitter │ Telegram │ Web Crawlers │ HUMINT│
└──────────────────────────┬──────────────────────────────────────┘
                           │ raw events
┌──────────────────────────▼──────────────────────────────────────┐
│                   KAFKA EVENT BUS                               │
│   Topic: raw_intelligence (all collected items)                 │
│   Topic: classified (after NLP)                                 │
│   Topic: alerts (severity 4+)                                   │
└──────────┬─────────────────────────────┬───────────────────────┘
           │                             │
┌──────────▼──────────┐     ┌────────────▼────────────────────────┐
│  NLP PROCESSING     │     │      ALERT DISPATCHER               │
│  - Entity extraction│     │  - WhatsApp (Twilio)                │
│  - Threat scoring   │     │  - SMS (Termii)                     │
│  - Geo classification│    │  - Email (Resend)                   │
│  - Deduplication    │     │  - In-app (WebSocket)               │
└──────────┬──────────┘     └─────────────────────────────────────┘
           │ enriched events
┌──────────▼──────────────────────────────────────────────────────┐
│                     STORAGE LAYER                               │
│   PostgreSQL (structured data, multi-tenant, per-client)        │
│   Elasticsearch (full-text search, aggregations, heatmaps)      │
│   S3/Cloudinary (evidence files, report PDFs)                   │
└──────────┬──────────────────────────────────────────────────────┘
           │
┌──────────▼──────────────────────────────────────────────────────┐
│                   INTELLIGENCE LAYER                            │
│   Threat scoring models │ Predictive analytics │ Network graphs  │
│   Weekly brief generator │ Monthly report engine                 │
└──────────┬──────────────────────────────────────────────────────┘
           │
┌──────────▼──────────────────────────────────────────────────────┐
│                   PRESENTATION LAYER                            │
│   Client React Dashboard │ Analyst Dashboard │ API (partners)   │
│   PDF Reports │ WhatsApp Alerts │ Email Briefs                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Immediate Action Plan — Next 30 Days

| Week | Action | Owner | Cost |
|---|---|---|---|
| 1 | Implement whole-word keyword matching | Dev | ₦0 |
| 1 | Add geographic relevance filter | Dev | ₦0 |
| 1 | Fix SSL errors for gov sites | Dev | ₦0 |
| 2 | Add 15 new RSS sources + Nitter feeds | Dev | ₦0 |
| 2 | Implement APScheduler auto-collection | Dev | ₦0 |
| 2 | Add automated weekly brief email delivery | Dev | ₦0 |
| 3 | Produce 2 sample briefs for target clients | Founder | ₦0 |
| 3 | Approach 5 estate/corporate security managers | Founder | ₦0 |
| 4 | Close first paying client | Founder | — |
| 4 | Begin FastAPI migration plan | Dev | ₦0 |

**Total Month 1 infrastructure cost: ₦0**
**Target Month 1 revenue: ₦150,000 (one client)**

---

## Competitive Positioning

| Platform | Focus | Price | Lagos Coverage |
|---|---|---|---|
| Recorded Future | Global enterprise | $25,000+/year | Generic |
| Maltego | Investigation tool | $999/year | Generic |
| Brandwatch | Social media | $1,000+/month | Generic |
| Terra ArtemisOS | Physical infrastructure | Enterprise | Partial |
| **Lemtik Security** | **Urban Lagos intelligence** | **₦150k–₦400k/month** | **Native** |

The global OSINT market exceeded $29 billion in 2026. No major player
is building specifically for West African urban security. That is your
window. Close it before someone with more capital notices.

---

## Funding Path

You do not need external funding to reach Phase 2. Revenue funds it.

| Milestone | Revenue Needed | Unlock |
|---|---|---|
| Phase 1 complete | ₦0 | Free tools only |
| Phase 2 start | ₦150,000/month (1 client) | Covers all infra |
| Phase 2 complete | ₦1,500,000/month (10 clients) | Hire 2 analysts |
| Phase 3 start | ₦3,000,000/month (20 clients) | Kafka + ES infra |
| Seed funding round | ₦5,000,000+/month + 18 months data | $500k–$2M raise |

**Accelerators to target when you have 10+ clients and 12 months of data:**
- Y Combinator (has accepted Nigerian security startups)
- Antler Nigeria (Lagos-based, accepts pre-revenue)
- Techstars (has African program)
- Google for Startups Africa
- CcHUB Growth Capital

---

*Document version 1.0 — Lemtik Security Internal Engineering*
*The global OSINT market now exceeds $29B. Lagos is your beachhead.*
*Build for Lagos first. Scale to Nigeria. Then Africa.*