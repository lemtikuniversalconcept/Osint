from __future__ import annotations

import csv
import hashlib
import html
import json
import os
import re
import sqlite3
import ssl
import threading
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from operations.env import load_env_file


ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "data" / "lemtik_osint.sqlite3"
load_env_file()


def usable_database_url(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if any(marker in value for marker in ["<", ">", "project-ref", "db..supabase.co"]):
        return ""
    return value


DEFAULT_ORG_ID = os.getenv("LEMTIK_DEFAULT_ORG_ID", "default").strip() or "default"
STORAGE_MODE = os.getenv("LEMTIK_STORAGE", "sqlite").strip().lower()
SUPABASE_DB_URL = next(
    (
        url
        for url in [
            usable_database_url(os.getenv("SUPABASE_DB_URL", "")),
            usable_database_url(os.getenv("SUPABASE_POOLER_URL", "")),
            usable_database_url(os.getenv("DATABASE_URL", "")),
        ]
        if url
    ),
    "",
)
USE_POSTGRES = STORAGE_MODE in {"postgres", "supabase"} and bool(SUPABASE_DB_URL)
POSTGRES_CONNECT_TIMEOUT = int(os.getenv("POSTGRES_CONNECT_TIMEOUT", "8"))
POSTGRES_POOL_MIN = int(os.getenv("POSTGRES_POOL_MIN", "1"))
POSTGRES_POOL_MAX = int(os.getenv("POSTGRES_POOL_MAX", "5"))

_pg_pool = None
_pg_pool_lock = threading.Lock()
_init_lock = threading.Lock()
_initialized = False

THREAT_KEYWORDS = {
    "Physical": [
        "robbery",
        "robbers",
        "armed men",
        "gunmen",
        "shooting",
        "shot",
        "killed",
        "kidnap",
        "kidnapping",
        "abducted",
        "missing",
        "ransom",
        "one-chance",
        "one chance",
        "break-in",
        "burglary",
        "intruder",
        "area boys",
        "agberos",
        "cultists",
        "riot",
        "protest",
        "unrest",
        "clash",
        "violence",
        "looting",
        "explosion",
        "blast",
    ],
    "Cyber": [
        "fraud",
        "scam",
        "hacked",
        "phishing",
        "bec",
        "wire fraud",
        "sim swap",
        "account takeover",
        "impersonation",
        "data breach",
        "leaked",
        "exposed",
    ],
    "Political": [
        "strike",
        "shutdown",
        "election violence",
        "thugs",
        "political thuggery",
    ],
    "Macro": [
        "fuel scarcity",
        "fuel queue",
        "stampede",
        "flood",
        "flooding",
        "displaced",
        "evacuation",
        "cholera",
        "lassa fever",
    ],
}

DEFAULT_SOURCES = [
    ("Lagos Traffic", "Social", "https://nitter.net/LagosTraffic/rss", "B", "Nitter RSS mirror for public X posts."),
    ("LASEMA", "Official", "https://nitter.net/LASG_LASEMA/rss", "B", "Nitter RSS mirror for public X posts."),
    ("Nigeria Police Force", "Official", "https://www.npf.gov.ng/", "A", ""),
    ("Lagos State Government", "Official", "https://lagosstate.gov.ng/", "A", ""),
    ("Vanguard Nigeria", "News", "https://www.vanguardngr.com/feed/", "A", ""),
    ("The Punch", "News", "https://punchng.com/feed/", "A", ""),
    ("Channels TV", "News", "https://www.channelstv.com/feed/", "A", ""),
    ("Premium Times", "News", "https://www.premiumtimesng.com/feed", "A", ""),
    ("The Nation", "News", "https://thenationonlineng.net/feed/", "A", ""),
    ("Daily Trust", "News", "https://dailytrust.com/feed", "A", ""),
    ("Guardian Nigeria", "News", "https://guardian.ng/feed/", "A", ""),
    ("Thisday Live", "News", "https://www.thisdaylive.com/index.php/feed/", "A", ""),
    ("BusinessDay Nigeria", "News", "https://businessday.ng/feed/", "A", ""),
    ("Leadership News", "News", "https://leadership.ng/feed/", "A", ""),
    ("EFCC Nigeria", "Official", "https://efccnigeria.org/efcc/feed", "A", ""),
    ("CBN Nigeria", "Official", "https://www.cbn.gov.ng/rss/", "A", ""),
    ("SaharaReporters", "News", "https://saharareporters.com/rss.xml", "B", ""),
    ("Peoples Gazette", "News", "https://gazettengr.com/feed/", "B", ""),
    ("HumAngle", "News", "https://humanglemedia.com/feed/", "B", ""),
    ("NigeriaPolice@X", "Social", "https://nitter.net/PoliceNG_Force/rss", "B", "Nitter RSS mirror for public X posts."),
    ("ChannelsTV@X", "Social", "https://nitter.net/channelstv/rss", "B", "Nitter RSS mirror for public X posts."),
]

JUNK_PATTERNS = [
    "javascript is not available",
    "please enable javascript",
    "unsupported browser",
    "live tv 2023 elections",
    "privacy policy",
    "terms of service",
    "cookie policy",
]

NIGERIA_KEYWORDS = [
    "nigeria",
    "nigerian",
    "abuja",
    "lagos",
    "kano",
    "ibadan",
    "port harcourt",
    "enugu",
    "kaduna",
    "benin city",
    "onitsha",
    "aba",
    "warri",
    "zaria",
    "ilorin",
    "jos",
    "maiduguri",
    "efcc",
    "dss",
    "nsc",
    "npf",
    "police nigeria",
    "lasema",
    "lastma",
    "lawma",
]

LAGOS_KEYWORDS = [
    "lagos",
    "lekki",
    "victoria island",
    "vi",
    "ikoyi",
    "ajah",
    "ikeja",
    "surulere",
    "yaba",
    "oshodi",
    "alaba",
    "festac",
    "badagry",
    "ikorodu",
    "epe",
    "agege",
    "mushin",
    "isale eko",
    "apapa",
    "tin can",
    "maryland",
    "ojota",
    "mile 2",
    "sangotedo",
    "jakande",
    "chevron",
    "osapa",
    "igbo efon",
]

LENIENT_SSL_DOMAINS = [
    "npf.gov.ng",
    "lagosstate.gov.ng",
    "efccnigeria.org",
    "lasema.gov.ng",
    "lasg.gov.ng",
    "cbn.gov.ng",
]


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().replace(microsecond=0).isoformat()


def connect() -> sqlite3.Connection:
    if USE_POSTGRES:
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor
        except ImportError as exc:
            raise RuntimeError(
                "Postgres/Supabase mode requires psycopg2-binary. Install it or switch LEMTIK_STORAGE back to sqlite."
            ) from exc

        kwargs = {
            "sslmode": os.getenv("SUPABASE_SSLMODE", "require"),
            "cursor_factory": RealDictCursor,
            "connect_timeout": POSTGRES_CONNECT_TIMEOUT,
        }
        if os.getenv("LEMTIK_RLS_ORG_ID", "").strip():
            kwargs["options"] = f"-c app.org_id={os.getenv('LEMTIK_RLS_ORG_ID').strip()}"
        return psycopg2.connect(SUPABASE_DB_URL, **kwargs)

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def postgres_pool():
    global _pg_pool
    if _pg_pool is not None:
        return _pg_pool
    with _pg_pool_lock:
        if _pg_pool is not None:
            return _pg_pool
        try:
            from psycopg2.extras import RealDictCursor
            from psycopg2.pool import ThreadedConnectionPool
        except ImportError as exc:
            raise RuntimeError(
                "Postgres/Supabase mode requires psycopg2-binary. Install it or switch LEMTIK_STORAGE back to sqlite."
            ) from exc

        kwargs = {
            "sslmode": os.getenv("SUPABASE_SSLMODE", "require"),
            "cursor_factory": RealDictCursor,
            "connect_timeout": POSTGRES_CONNECT_TIMEOUT,
        }
        if os.getenv("LEMTIK_RLS_ORG_ID", "").strip():
            kwargs["options"] = f"-c app.org_id={os.getenv('LEMTIK_RLS_ORG_ID').strip()}"
        _pg_pool = ThreadedConnectionPool(POSTGRES_POOL_MIN, POSTGRES_POOL_MAX, SUPABASE_DB_URL, **kwargs)
        return _pg_pool


@contextmanager
def db_connection():
    if USE_POSTGRES:
        pool = postgres_pool()
        con = pool.getconn()
        try:
            yield con
        finally:
            pool.putconn(con)
        return

    with connect() as con:
        yield con


def normalize_query(query: str) -> str:
    if USE_POSTGRES:
        return query.replace("?", "%s")
    return query


def row_dict(row) -> dict:
    return dict(row)


def init_db() -> None:
    global _initialized
    if _initialized:
        return
    with _init_lock:
        if _initialized:
            return
        _init_db_uncached()
        _initialized = True


def _init_db_uncached() -> None:
    if USE_POSTGRES:
        seed_default_data()
        return

    with db_connection() as con:
        con.executescript(
            """
            create table if not exists organisations (
                id text primary key,
                name text not null,
                created_at text not null
            );

            create table if not exists clients (
                id integer primary key autoincrement,
                org_id text not null default 'default',
                name text not null unique,
                area text not null default '',
                tier text not null default 'Standard',
                contact text not null default '',
                created_at text not null
            );

            create table if not exists sources (
                id integer primary key autoincrement,
                org_id text not null default 'default',
                name text not null,
                source_type text not null,
                url text not null unique,
                credibility text not null default 'B',
                notes text not null default '',
                created_at text not null,
                last_checked_at text not null default '',
                last_status text not null default 'Never checked',
                last_error text not null default ''
            );

            create table if not exists incidents (
                id integer primary key autoincrement,
                org_id text not null default 'default',
                log_id text not null unique,
                collected_at text not null,
                source text not null,
                source_url text not null,
                raw_content text not null,
                summary text not null,
                threat_category text not null,
                severity integer not null check(severity between 1 and 5),
                location_relevance text not null default '',
                verified text not null default 'No',
                verification_source text not null default '',
                client_notified text not null default 'No',
                notification_method text not null default '',
                status text not null default 'Monitoring',
                analyst text not null default '',
                notes text not null default '',
                content_hash text not null default '',
                matched_keywords text not null default '',
                confidence integer not null default 50,
                quality_score integer not null default 50,
                geo_relevance text not null default 'Unknown'
            );

            create table if not exists collection_runs (
                id integer primary key autoincrement,
                org_id text not null default 'default',
                source_id integer not null,
                source_name text not null,
                started_at text not null,
                finished_at text not null,
                checked_count integer not null default 0,
                created_count integer not null default 0,
                skipped_count integer not null default 0,
                status text not null,
                error text not null default ''
            );

            create table if not exists briefs (
                id integer primary key autoincrement,
                org_id text not null default 'default',
                title text not null,
                window_days integer not null default 7,
                risk_rating text not null default 'Green',
                markdown text not null,
                generated_at text not null,
                delivered_at text,
                delivery_status text not null default 'Draft'
            );

            create table if not exists alert_events (
                id integer primary key autoincrement,
                org_id text not null default 'default',
                incident_id integer,
                severity integer not null,
                summary text not null,
                status text not null default 'Pending',
                channels text not null default 'email',
                payload text not null default '{}',
                created_at text not null,
                sent_at text,
                error text not null default ''
            );

            create table if not exists api_keys (
                id integer primary key autoincrement,
                org_id text not null default 'default',
                name text not null,
                key_hash text not null unique,
                role text not null default 'analyst',
                is_active integer not null default 1,
                created_at text not null,
                last_used_at text
            );

            create table if not exists audit_logs (
                id integer primary key autoincrement,
                org_id text not null default 'default',
                actor text not null default '',
                action text not null,
                resource_type text not null default '',
                resource_id text not null default '',
                ip_address text not null default '',
                user_agent text not null default '',
                metadata text not null default '{}',
                created_at text not null
            );

            create table if not exists brain_tasks (
                id text primary key,
                org_id text not null default 'default',
                task_type text not null,
                status text not null default 'Pending',
                priority integer not null default 5 check(priority between 1 and 10),
                payload text not null default '{}',
                result text not null default '{}',
                error text not null default '',
                requested_by text not null default '',
                created_at text not null,
                updated_at text not null default '',
                started_at text not null default '',
                finished_at text not null default ''
            );
            """
        )
        migrate(con)
        con.execute(
            insert_ignore_sql("organisations", ["id", "name", "created_at"], "(id)"),
            (DEFAULT_ORG_ID, "Lemtik Security", now_iso()),
        )
        for name, source_type, url, credibility, notes in DEFAULT_SOURCES:
            con.execute(
                insert_ignore_sql(
                    "sources",
                    ["org_id", "name", "source_type", "url", "credibility", "notes", "created_at"],
                    "(org_id, url)",
                ),
                (DEFAULT_ORG_ID, name, source_type, url, credibility, notes, now_iso()),
            )


def seed_default_data() -> None:
    with db_connection() as con:
        cursor = con.cursor()
        cursor.execute(
            normalize_query(insert_ignore_sql("organisations", ["id", "name", "created_at"], "(id)")),
            (DEFAULT_ORG_ID, "Lemtik Security", now_iso()),
        )
        cursor.executemany(
            normalize_query(
                insert_ignore_sql(
                    "sources",
                    ["org_id", "name", "source_type", "url", "credibility", "notes", "created_at"],
                    "(org_id, url)",
                )
            ),
            [(DEFAULT_ORG_ID, name, source_type, url, credibility, notes, now_iso()) for name, source_type, url, credibility, notes in DEFAULT_SOURCES],
        )
        con.commit()


def migrate(con: sqlite3.Connection) -> None:
    con.execute(
        "insert or ignore into organisations (id, name, created_at) values (?, ?, ?)",
        (DEFAULT_ORG_ID, "Lemtik Security", now_iso()),
    )
    existing = {row["name"] for row in con.execute("pragma table_info(sources)").fetchall()}
    for column, ddl in {
        "org_id": "alter table sources add column org_id text not null default 'default'",
        "last_checked_at": "alter table sources add column last_checked_at text not null default ''",
        "last_status": "alter table sources add column last_status text not null default 'Never checked'",
        "last_error": "alter table sources add column last_error text not null default ''",
    }.items():
        if column not in existing:
            con.execute(ddl)

    existing = {row["name"] for row in con.execute("pragma table_info(incidents)").fetchall()}
    for column, ddl in {
        "org_id": "alter table incidents add column org_id text not null default 'default'",
        "content_hash": "alter table incidents add column content_hash text not null default ''",
        "matched_keywords": "alter table incidents add column matched_keywords text not null default ''",
        "confidence": "alter table incidents add column confidence integer not null default 50",
        "quality_score": "alter table incidents add column quality_score integer not null default 50",
        "geo_relevance": "alter table incidents add column geo_relevance text not null default 'Unknown'",
    }.items():
        if column not in existing:
            con.execute(ddl)
    existing = {row["name"] for row in con.execute("pragma table_info(clients)").fetchall()}
    if "org_id" not in existing:
        con.execute("alter table clients add column org_id text not null default 'default'")
    existing = {row["name"] for row in con.execute("pragma table_info(collection_runs)").fetchall()}
    if "org_id" not in existing:
        con.execute("alter table collection_runs add column org_id text not null default 'default'")
    existing = {row["name"] for row in con.execute("pragma table_info(brain_tasks)").fetchall()}
    for column, ddl in {
        "org_id": "alter table brain_tasks add column org_id text not null default 'default'",
        "task_type": "alter table brain_tasks add column task_type text not null default 'collect_all'",
        "status": "alter table brain_tasks add column status text not null default 'Pending'",
        "priority": "alter table brain_tasks add column priority integer not null default 5",
        "payload": "alter table brain_tasks add column payload text not null default '{}'",
        "result": "alter table brain_tasks add column result text not null default '{}'",
        "error": "alter table brain_tasks add column error text not null default ''",
        "requested_by": "alter table brain_tasks add column requested_by text not null default ''",
        "created_at": "alter table brain_tasks add column created_at text not null default ''",
        "updated_at": "alter table brain_tasks add column updated_at text not null default ''",
        "started_at": "alter table brain_tasks add column started_at text not null default ''",
        "finished_at": "alter table brain_tasks add column finished_at text not null default ''",
    }.items():
        if column not in existing:
            con.execute(ddl)
    con.execute(
        """
        create table if not exists api_keys (
            id integer primary key autoincrement,
            org_id text not null default 'default',
            name text not null,
            key_hash text not null unique,
            role text not null default 'analyst',
            is_active integer not null default 1,
            created_at text not null,
            last_used_at text
        )
        """
    )
    con.execute(
        """
        create table if not exists audit_logs (
            id integer primary key autoincrement,
            org_id text not null default 'default',
            actor text not null default '',
            action text not null,
            resource_type text not null default '',
            resource_id text not null default '',
            ip_address text not null default '',
            user_agent text not null default '',
            metadata text not null default '{}',
            created_at text not null
        )
        """
    )
    con.execute(
        """
        create table if not exists brain_tasks (
            id text primary key,
            org_id text not null default 'default',
            task_type text not null,
            status text not null default 'Pending',
            priority integer not null default 5 check(priority between 1 and 10),
            payload text not null default '{}',
            result text not null default '{}',
            error text not null default '',
            requested_by text not null default '',
            created_at text not null,
            updated_at text not null default '',
            started_at text not null default '',
            finished_at text not null default ''
        )
        """
    )
    con.execute("drop index if exists idx_incidents_content_hash")
    con.execute("create unique index if not exists idx_incidents_org_content_hash on incidents(org_id, content_hash) where content_hash != ''")
    con.execute("create index if not exists idx_incidents_org_collected_at on incidents(org_id, collected_at)")
    con.execute("create index if not exists idx_incidents_org_severity on incidents(org_id, severity)")
    con.execute("create index if not exists idx_sources_org_status on sources(org_id, last_status)")
    con.execute("create index if not exists idx_collection_runs_org_finished on collection_runs(org_id, finished_at)")
    con.execute("create index if not exists idx_api_keys_org_active on api_keys(org_id, is_active)")
    con.execute("create index if not exists idx_audit_logs_org_created on audit_logs(org_id, created_at)")
    con.execute("create index if not exists idx_audit_logs_action_created on audit_logs(action, created_at)")
    con.execute("create index if not exists idx_brain_tasks_org_status_priority on brain_tasks(org_id, status, priority desc, created_at)")
    con.execute("create index if not exists idx_brain_tasks_task_type_created on brain_tasks(task_type, created_at)")
    for old_url, feed_url in [
        ("https://www.vanguardngr.com/", "https://www.vanguardngr.com/feed/"),
        ("https://punchng.com/", "https://punchng.com/feed/"),
        ("https://www.channelstv.com/", "https://www.channelstv.com/feed/"),
        ("https://x.com/LagosTraffic", "https://nitter.net/LagosTraffic/rss"),
        ("https://x.com/LASG_LASEMA", "https://nitter.net/LASG_LASEMA/rss"),
    ]:
        feed_exists = con.execute("select 1 from sources where url = ?", (feed_url,)).fetchone()
        if feed_exists:
            con.execute("delete from sources where url = ?", (old_url,))
        else:
            con.execute("update sources set url = ? where url = ?", (feed_url, old_url))
    con.execute(
        """
        delete from sources
        where name in ('LASEMA@X', 'LagosTraffic@X')
        and url in ('https://nitter.net/LASG_LASEMA/rss', 'https://nitter.net/LagosTraffic/rss')
        """
    )
    con.execute(
        """
        update incidents
        set geo_relevance = 'Nigeria', location_relevance = ''
        where geo_relevance = 'Lagos'
        and lower(location_relevance) = 'nigeria'
        """
    )


def add_brain_task(
    *,
    task_id: str,
    org_id: str,
    task_type: str,
    payload: dict[str, str],
    priority: int = 5,
    requested_by: str = "",
) -> None:
    started_at = None if USE_POSTGRES else ""
    finished_at = None if USE_POSTGRES else ""
    execute(
        """
        insert into brain_tasks
        (id, org_id, task_type, status, priority, payload, result, error, requested_by, created_at, updated_at, started_at, finished_at)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            task_id,
            org_id,
            task_type,
            "Pending",
            priority,
            json.dumps(payload),
            "{}",
            "",
            requested_by,
            now_iso(),
            now_iso(),
            started_at,
            finished_at,
        ),
    )


def update_brain_task(
    task_id: str,
    *,
    status: str | None = None,
    result: dict[str, str] | None = None,
    error: str = "",
    started_at: str | None = None,
    finished_at: str | None = None,
) -> None:
    fields: list[str] = []
    values: list[str] = []
    if status is not None:
        fields.append("status = ?")
        values.append(status)
    if result is not None:
        fields.append("result = ?")
        values.append(json.dumps(result))
    if error:
        fields.append("error = ?")
        values.append(error[:1000])
    if started_at is not None:
        fields.append("started_at = ?")
        values.append(started_at)
    if finished_at is not None:
        fields.append("finished_at = ?")
        values.append(finished_at)
    if not fields:
        return
    fields.append("updated_at = ?")
    values.append(now_iso())
    values.append(task_id)
    execute(f"update brain_tasks set {', '.join(fields)} where id = ?", tuple(values))


def rows(query: str, params: tuple = ()) -> list[sqlite3.Row]:
    with db_connection() as con:
        cursor = con.cursor()
        cursor.execute(normalize_query(query), params)
        fetched = cursor.fetchall()
        return [row_dict(row) for row in fetched]


def execute(query: str, params: tuple = ()) -> None:
    with db_connection() as con:
        cursor = con.cursor()
        cursor.execute(normalize_query(query), params)
        con.commit()


def row_to_dict(row: sqlite3.Row) -> dict:
    return dict(row)


def insert_ignore_sql(table: str, columns: list[str], conflict: str) -> str:
    placeholders = ", ".join(["?"] * len(columns))
    column_sql = ", ".join(columns)
    if USE_POSTGRES:
        return f"insert into {table} ({column_sql}) values ({placeholders}) on conflict {conflict} do nothing"
    return f"insert or ignore into {table} ({column_sql}) values ({placeholders})"


def next_log_id() -> str:
    row = rows("select count(*) as n from incidents")[0]
    return f"LEM-OSINT-{row['n'] + 1:04d}"


def clean_text(value: str) -> str:
    value = re.sub(r"<(script|style).*?</\1>", " ", value, flags=re.I | re.S)
    value = re.sub(r"<[^>]+>", " ", value)
    value = html.unescape(value)
    return re.sub(r"\s+", " ", value).strip()


def keyword_matches(text: str, keywords: list[str]) -> list[str]:
    lower = clean_text(text).lower()
    hits = []
    for keyword in keywords:
        pattern = r"(?<!\w)" + re.escape(keyword.lower()) + r"(?!\w)"
        if re.search(pattern, lower):
            hits.append(keyword)
    return hits


def geo_relevance_score(text: str, custom_keywords: list[str] | None = None) -> str:
    custom_keywords = custom_keywords or []
    if custom_keywords and keyword_matches(text, custom_keywords):
        return "Client"
    if keyword_matches(text, LAGOS_KEYWORDS):
        return "Lagos"
    if keyword_matches(text, NIGERIA_KEYWORDS):
        return "Nigeria"
    return "None"


def content_hash(source_url: str, content: str) -> str:
    normalized = re.sub(r"\W+", " ", clean_text(content).lower()).strip()
    return hashlib.sha256(f"{source_url}|{normalized[:1000]}".encode("utf-8")).hexdigest()


def quality_score(text: str) -> int:
    cleaned = clean_text(text)
    lower = cleaned.lower()
    score = 100
    if len(cleaned) < 80:
        score -= 45
    if len(cleaned) > 3500:
        score -= 20
    for pattern in JUNK_PATTERNS:
        if pattern in lower:
            score -= 70
    nav_words = sum(lower.count(word) for word in ["login", "subscribe", "advertise", "menu", "home", "live tv"])
    score -= min(nav_words * 4, 35)
    return max(0, min(score, 100))


def is_collectable_text(text: str) -> bool:
    return quality_score(text) >= 55


def detect_category(text: str) -> tuple[str, list[str]]:
    best_category = "Physical"
    best_hits: list[str] = []
    for category, keywords in THREAT_KEYWORDS.items():
        hits = keyword_matches(text, keywords)
        if len(hits) > len(best_hits):
            best_category = category
            best_hits = hits
    return best_category, best_hits


def estimate_severity(text: str, credibility: str = "B") -> int:
    score = 1
    if keyword_matches(text, ["kidnap", "abducted", "ransom", "shooting", "gunmen", "explosion", "riot"]):
        score = 3
    if keyword_matches(text, ["ongoing", "active", "currently", "avoid", "blocked", "evacuate"]):
        score += 1
    if keyword_matches(text, ["killed", "dead", "critical", "hostage", "imminent"]):
        score += 1
    if credibility == "A" and score < 4:
        score += 1
    return max(1, min(score, 5))


def estimate_confidence(credibility: str, verified: str, quality: int, hit_count: int) -> int:
    score = {"A": 72, "B": 58, "C": 42}.get(credibility, 50)
    if verified == "Yes":
        score += 18
    elif verified == "Partial":
        score += 8
    score += min(hit_count * 4, 12)
    score += (quality - 60) // 5
    return max(0, min(score, 100))


def summarize(text: str, limit: int = 220) -> str:
    text = clean_text(text)
    if len(text) <= limit:
        return text
    return text[: limit - 1].rsplit(" ", 1)[0] + "."


def add_incident(data: dict[str, str]) -> bool:
    severity = int(data.get("severity") or 1)
    raw_content = data.get("raw_content", "").strip()
    source_url = data.get("source_url", "").strip()
    digest = data.get("content_hash") or content_hash(source_url, raw_content)
    try:
        org_id = data.get("org_id", DEFAULT_ORG_ID)
        execute(
            """
            insert into incidents
            (org_id, log_id, collected_at, source, source_url, raw_content, summary,
             threat_category, severity, location_relevance, verified,
             verification_source, client_notified, notification_method, status,
             analyst, notes, content_hash, matched_keywords, confidence, quality_score,
             geo_relevance)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                org_id,
                next_log_id(),
                data.get("collected_at") or now_iso(),
                data.get("source", "").strip(),
                source_url,
                raw_content,
                data.get("summary", "").strip(),
                data.get("threat_category", "Physical"),
                severity,
                data.get("location_relevance", "").strip(),
                data.get("verified", "No"),
                data.get("verification_source", "").strip(),
                data.get("client_notified", "No"),
                data.get("notification_method", "").strip(),
                data.get("status", "Monitoring"),
                data.get("analyst", "").strip(),
                data.get("notes", "").strip(),
                digest,
                data.get("matched_keywords", "").strip(),
                int(data.get("confidence") or 50),
                int(data.get("quality_score") or quality_score(raw_content)),
                data.get("geo_relevance", "Unknown"),
            ),
        )
    except Exception as exc:
        if exc.__class__.__name__ not in {"IntegrityError", "UniqueViolation"}:
            raise
        return False
    if not USE_POSTGRES and severity >= 4:
        incident = rows("select id, log_id, summary, source_url from incidents where org_id = ? and content_hash = ?", (org_id, digest))
        if incident:
            enqueue_alert_event(org_id, incident[0]["id"], severity, data.get("summary", "").strip(), incident[0])
    return True


def enqueue_alert_event(org_id: str, incident_id: int, severity: int, summary: str, incident: dict) -> None:
    execute(
        """
        insert into alert_events
        (org_id, incident_id, severity, summary, status, channels, payload, created_at)
        values (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            org_id,
            incident_id,
            severity,
            summary,
            "Pending",
            "email",
            json.dumps({"log_id": incident.get("log_id"), "source_url": incident.get("source_url")}),
            now_iso(),
        ),
    )


def update_source_status(source_id: int, status: str, error: str = "") -> None:
    execute(
        """
        update sources
        set last_checked_at = ?, last_status = ?, last_error = ?
        where id = ?
        """,
        (now_iso(), status, error[:500], source_id),
    )


def add_source(data: dict[str, str]) -> None:
    execute(
        insert_ignore_sql(
            "sources",
            ["org_id", "name", "source_type", "url", "credibility", "notes", "created_at"],
            "(org_id, url)",
        ),
        (
            data.get("org_id", DEFAULT_ORG_ID),
            data.get("name", "").strip(),
            data.get("source_type", "News"),
            data.get("url", "").strip(),
            data.get("credibility", "B"),
            data.get("notes", "").strip(),
            now_iso(),
        ),
    )


def add_client(data: dict[str, str]) -> None:
    execute(
        insert_ignore_sql(
            "clients",
            ["org_id", "name", "area", "tier", "contact", "created_at"],
            "(org_id, name)",
        ),
        (
            data.get("org_id", DEFAULT_ORG_ID),
            data.get("name", "").strip(),
            data.get("area", "").strip(),
            data.get("tier", "Standard"),
            data.get("contact", "").strip(),
            now_iso(),
        ),
    )


def add_organisation(data: dict[str, str]) -> None:
    org_id = re.sub(r"[^a-z0-9_-]+", "-", data.get("id", "").strip().lower()).strip("-")
    if not org_id:
        org_id = re.sub(r"[^a-z0-9_-]+", "-", data.get("name", "org").strip().lower()).strip("-")
    execute(
        insert_ignore_sql("organisations", ["id", "name", "created_at"], "(id)"),
        (org_id or DEFAULT_ORG_ID, data.get("name", org_id).strip(), now_iso()),
    )


@dataclass
class CollectedItem:
    title: str
    url: str
    content: str


def fetch_public_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    use_lenient_ssl = any(domain in parsed.netloc for domain in LENIENT_SSL_DOMAINS)
    context = ssl.create_default_context()
    if use_lenient_ssl:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "LemtikSecurityOSINT/1.0 (+public-source analyst tool)",
            "Accept": "text/html,application/rss+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )
    with urllib.request.urlopen(req, timeout=15, context=context) as response:
        return response.read(1_000_000).decode("utf-8", errors="replace")


def discover_feed_url(url: str, body: str) -> str:
    if "<rss" in body[:500].lower() or "<feed" in body[:500].lower():
        return url
    match = re.search(
        r'<link[^>]+type=["\']application/(?:rss|atom)\+xml["\'][^>]+href=["\']([^"\']+)["\']',
        body,
        flags=re.I,
    )
    if match:
        return urllib.parse.urljoin(url, html.unescape(match.group(1)))
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme and parsed.netloc and not parsed.path.rstrip("/").endswith("feed"):
        return urllib.parse.urljoin(f"{parsed.scheme}://{parsed.netloc}", "/feed/")
    return url


def parse_feed_or_page(url: str, body: str) -> list[CollectedItem]:
    try:
        root = ET.fromstring(body)
        items = []
        for item in root.findall(".//item")[:25]:
            title = clean_text(item.findtext("title") or "Untitled")
            link = clean_text(item.findtext("link") or url)
            desc = clean_text(item.findtext("description") or "")
            items.append(CollectedItem(title, link, f"{title}. {desc}"))
        if items:
            return items
        atom_items = []
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        for entry in root.findall(".//atom:entry", ns)[:25]:
            title = clean_text(entry.findtext("atom:title", default="", namespaces=ns) or "Untitled")
            link_el = entry.find("atom:link", ns)
            link = link_el.attrib.get("href", url) if link_el is not None else url
            summary_text = entry.findtext("atom:summary", default="", namespaces=ns) or entry.findtext("atom:content", default="", namespaces=ns)
            atom_items.append(CollectedItem(title, urllib.parse.urljoin(url, link), f"{title}. {clean_text(summary_text)}"))
        if atom_items:
            return atom_items
    except ET.ParseError:
        pass

    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.I | re.S)
    title = clean_text(title_match.group(1)) if title_match else urllib.parse.urlparse(url).netloc
    return [CollectedItem(title, url, clean_text(body)[:5000])]


def collect_from_source(source_id: int, extra_keywords: str = "", org_id: str = DEFAULT_ORG_ID) -> tuple[int, int, int]:
    source = rows("select * from sources where id = ? and org_id = ?", (source_id, org_id))
    if not source:
        return (0, 0, 0)
    source = source[0]
    started = now_iso()
    checked = 0
    created = 0
    skipped = 0
    try:
        body = fetch_public_url(source["url"])
        feed_url = discover_feed_url(source["url"], body)
        if feed_url != source["url"]:
            body = fetch_public_url(feed_url)
    except Exception as exc:
        update_source_status(source_id, "Failed", str(exc))
        execute(
            """
            insert into collection_runs
            (org_id, source_id, source_name, started_at, finished_at, status, error)
            values (?, ?, ?, ?, ?, ?, ?)
            """,
            (org_id, source_id, source["name"], started, now_iso(), "Failed", str(exc)[:500]),
        )
        return (0, 0, 0)
    custom_keywords = [kw.strip().lower() for kw in extra_keywords.split(",") if kw.strip()]
    for item in parse_feed_or_page(source["url"], body):
        checked += 1
        item_quality = quality_score(item.content)
        if item_quality < 55:
            skipped += 1
            continue
        geo_relevance = geo_relevance_score(item.content, custom_keywords)
        custom_hits = keyword_matches(item.content, custom_keywords)
        if geo_relevance == "None" and not custom_hits:
            skipped += 1
            continue
        category, hits = detect_category(item.content)
        if not hits and not custom_hits:
            skipped += 1
            continue
        severity = estimate_severity(item.content, source["credibility"])
        verified = "Partial" if source["credibility"] == "A" else "No"
        confidence = estimate_confidence(source["credibility"], verified, item_quality, len(hits) + len(custom_hits))
        was_created = add_incident(
            {
                "source": source["name"],
                "org_id": org_id,
                "source_url": item.url,
                "raw_content": item.content,
                "summary": summarize(item.content),
                "threat_category": category,
                "severity": str(severity),
                "location_relevance": ", ".join(custom_hits),
                "geo_relevance": geo_relevance,
                "verified": verified,
                "verification_source": source["name"] if source["credibility"] == "A" else "",
                "status": "Monitoring",
                "notes": "Auto-collected from public source/feed. Analyst must verify before client reporting.",
                "matched_keywords": ", ".join(hits + custom_hits),
                "confidence": str(confidence),
                "quality_score": str(item_quality),
            }
        )
        if was_created:
            created += 1
        else:
            skipped += 1
    update_source_status(source_id, "OK", "")
    execute(
        """
        insert into collection_runs
        (org_id, source_id, source_name, started_at, finished_at, checked_count, created_count, skipped_count, status)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (org_id, source_id, source["name"], started, now_iso(), checked, created, skipped, "OK"),
    )
    return checked, created, skipped


def collect_all_sources(extra_keywords: str = "", org_id: str = DEFAULT_ORG_ID) -> tuple[int, int, int]:
    total_checked = 0
    total_created = 0
    total_skipped = 0
    for source in rows("select id from sources where org_id = ? order by credibility, name", (org_id,)):
        checked, created, skipped = collect_from_source(source["id"], extra_keywords, org_id)
        total_checked += checked
        total_created += created
        total_skipped += skipped
    return total_checked, total_created, total_skipped


def generate_weekly_brief_file(days: int = 7, org_id: str = DEFAULT_ORG_ID) -> Path:
    target_dir = ROOT / "data" / "exports"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{org_id}-weekly-brief.md"
    markdown = weekly_report_markdown(days, org_id)
    target.write_text(markdown, encoding="utf-8")
    save_brief_record(org_id, days, markdown)
    return target


def save_brief_record(org_id: str, days: int, markdown: str) -> None:
    risk_match = re.search(r"Week's risk rating:\s*(\w+)", markdown)
    risk_rating = risk_match.group(1) if risk_match else "Green"
    execute(
        """
        insert into briefs
        (org_id, title, window_days, risk_rating, markdown, generated_at, delivery_status)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            org_id,
            "Lemtik Security Weekly Intelligence Brief",
            days,
            risk_rating,
            markdown,
            now_iso(),
            "Draft",
        ),
    )


def weekly_report_markdown(days: int = 7, org_id: str = DEFAULT_ORG_ID) -> str:
    since = (datetime.now(timezone.utc).astimezone() - timedelta(days=days)).isoformat()
    incidents = rows(
        """
        select * from incidents
        where collected_at >= ?
        and status != 'Archived'
        and org_id = ?
        and quality_score >= 55
        and geo_relevance in ('Lagos', 'Nigeria', 'Client')
        order by severity desc, confidence desc, collected_at desc
        """,
        (since, org_id),
    )
    high = [i for i in incidents if i["severity"] >= 4]
    verified = [i for i in incidents if i["verified"] == "Yes"]
    review = [i for i in incidents if i["verified"] != "Yes" and i["severity"] >= 3]
    risk = "Red" if any(i["severity"] == 5 for i in incidents) else "Orange" if high else "Green"
    lines = [
        "# Lemtik Security Weekly Intelligence Brief",
        "",
        f"Generated: {now_iso()}",
        f"Window: last {days} days",
        f"Week's risk rating: {risk}",
        "",
        "## Executive Summary",
    ]
    if not incidents:
        lines.append("- No logged incidents in this period.")
    else:
        for incident in incidents[:5]:
            lines.append(
                f"- Severity {incident['severity']} {incident['threat_category']} "
                f"({incident['confidence']}% confidence): {incident['summary']}"
            )
    lines.extend(
        [
            "",
            "## Verification Posture",
            f"- Verified client-ready items: {len(verified)}",
            f"- Severity 3+ items still requiring independent verification: {len(review)}",
            f"- High/Critical items: {len(high)}",
            "",
            "## Threat Landscape",
        ]
    )
    for incident in incidents:
        lines.extend(
            [
                f"### {incident['log_id']} - Severity {incident['severity']}",
                f"- Source: {incident['source']} ({incident['source_url']})",
                f"- Category: {incident['threat_category']}",
                f"- Geographic relevance: {incident['geo_relevance']}",
                f"- Location relevance: {incident['location_relevance'] or 'General Lagos'}",
                f"- Verified: {incident['verified']}",
                f"- Confidence: {incident['confidence']}%",
                f"- Matched keywords: {incident['matched_keywords'] or 'None recorded'}",
                f"- Status: {incident['status']}",
                f"- Summary: {incident['summary']}",
                "",
            ]
        )
    if review:
        lines.append("## Analyst Verification Queue")
        for incident in review[:10]:
            lines.append(f"- {incident['log_id']}: verify `{incident['summary']}` against an independent Tier A/B source.")
        lines.append("")
    lines.extend(
        [
            "## Recommendations",
            "- Verify all Severity 3+ items against an independent source before client delivery.",
            "- Escalate Severity 4-5 incidents through the immediate alert workflow.",
            "- Review route, access-control, and staff movement guidance for affected areas.",
        ]
    )
    return "\n".join(lines)


def export_incidents_csv(path: Path) -> None:
    incidents = rows("select * from incidents order by collected_at desc")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if not incidents:
            writer.writerow(["No incidents"])
            return
        writer.writerow(incidents[0].keys())
        for incident in incidents:
            writer.writerow([incident[key] for key in incident.keys()])
