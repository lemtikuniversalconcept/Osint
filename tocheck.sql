-- Lemtik Security Supabase verification queries.
-- Run after supabase.sql and share the result if we need to inspect the project.

select 'tables' as section, table_name, table_type
from information_schema.tables
where table_schema = 'public'
order by table_name;

[
  {
    "section": "tables",
    "table_name": "alert_events",
    "table_type": "BASE TABLE"
  },
  {
    "section": "tables",
    "table_name": "audit_logs",
    "table_type": "BASE TABLE"
  },
  {
    "section": "tables",
    "table_name": "briefs",
    "table_type": "BASE TABLE"
  },
  {
    "section": "tables",
    "table_name": "clients",
    "table_type": "BASE TABLE"
  },
  {
    "section": "tables",
    "table_name": "collection_runs",
    "table_type": "BASE TABLE"
  },
  {
    "section": "tables",
    "table_name": "incidents",
    "table_type": "BASE TABLE"
  },
  {
    "section": "tables",
    "table_name": "organisations",
    "table_type": "BASE TABLE"
  },
  {
    "section": "tables",
    "table_name": "sources",
    "table_type": "BASE TABLE"
  }
]

select 'columns' as section, table_name, column_name, data_type, is_nullable, column_default
from information_schema.columns
where table_schema = 'public'
order by table_name, ordinal_position;

[
  {
    "section": "columns",
    "table_name": "alert_events",
    "column_name": "id",
    "data_type": "bigint",
    "is_nullable": "NO",
    "column_default": "nextval('alert_events_id_seq'::regclass)"
  },
  {
    "section": "columns",
    "table_name": "alert_events",
    "column_name": "org_id",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "alert_events",
    "column_name": "incident_id",
    "data_type": "bigint",
    "is_nullable": "YES",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "alert_events",
    "column_name": "severity",
    "data_type": "integer",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "alert_events",
    "column_name": "summary",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "alert_events",
    "column_name": "status",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "'Pending'::text"
  },
  {
    "section": "columns",
    "table_name": "alert_events",
    "column_name": "channels",
    "data_type": "ARRAY",
    "is_nullable": "NO",
    "column_default": "ARRAY[]::text[]"
  },
  {
    "section": "columns",
    "table_name": "alert_events",
    "column_name": "payload",
    "data_type": "jsonb",
    "is_nullable": "NO",
    "column_default": "'{}'::jsonb"
  },
  {
    "section": "columns",
    "table_name": "alert_events",
    "column_name": "created_at",
    "data_type": "timestamp with time zone",
    "is_nullable": "NO",
    "column_default": "now()"
  },
  {
    "section": "columns",
    "table_name": "alert_events",
    "column_name": "sent_at",
    "data_type": "timestamp with time zone",
    "is_nullable": "YES",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "alert_events",
    "column_name": "error",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "''::text"
  },
  {
    "section": "columns",
    "table_name": "audit_logs",
    "column_name": "id",
    "data_type": "bigint",
    "is_nullable": "NO",
    "column_default": "nextval('audit_logs_id_seq'::regclass)"
  },
  {
    "section": "columns",
    "table_name": "audit_logs",
    "column_name": "org_id",
    "data_type": "text",
    "is_nullable": "YES",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "audit_logs",
    "column_name": "table_name",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "audit_logs",
    "column_name": "record_id",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "audit_logs",
    "column_name": "action",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "audit_logs",
    "column_name": "old_data",
    "data_type": "jsonb",
    "is_nullable": "YES",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "audit_logs",
    "column_name": "new_data",
    "data_type": "jsonb",
    "is_nullable": "YES",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "audit_logs",
    "column_name": "actor",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "CURRENT_USER"
  },
  {
    "section": "columns",
    "table_name": "audit_logs",
    "column_name": "created_at",
    "data_type": "timestamp with time zone",
    "is_nullable": "NO",
    "column_default": "now()"
  },
  {
    "section": "columns",
    "table_name": "briefs",
    "column_name": "id",
    "data_type": "bigint",
    "is_nullable": "NO",
    "column_default": "nextval('briefs_id_seq'::regclass)"
  },
  {
    "section": "columns",
    "table_name": "briefs",
    "column_name": "org_id",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "briefs",
    "column_name": "title",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "briefs",
    "column_name": "window_days",
    "data_type": "integer",
    "is_nullable": "NO",
    "column_default": "7"
  },
  {
    "section": "columns",
    "table_name": "briefs",
    "column_name": "risk_rating",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "'Green'::text"
  },
  {
    "section": "columns",
    "table_name": "briefs",
    "column_name": "markdown",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "briefs",
    "column_name": "generated_at",
    "data_type": "timestamp with time zone",
    "is_nullable": "NO",
    "column_default": "now()"
  },
  {
    "section": "columns",
    "table_name": "briefs",
    "column_name": "delivered_at",
    "data_type": "timestamp with time zone",
    "is_nullable": "YES",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "briefs",
    "column_name": "delivery_status",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "'Draft'::text"
  },
  {
    "section": "columns",
    "table_name": "clients",
    "column_name": "id",
    "data_type": "bigint",
    "is_nullable": "NO",
    "column_default": "nextval('clients_id_seq'::regclass)"
  },
  {
    "section": "columns",
    "table_name": "clients",
    "column_name": "org_id",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "clients",
    "column_name": "name",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "clients",
    "column_name": "area",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "''::text"
  },
  {
    "section": "columns",
    "table_name": "clients",
    "column_name": "tier",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "'Standard'::text"
  },
  {
    "section": "columns",
    "table_name": "clients",
    "column_name": "contact",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "''::text"
  },
  {
    "section": "columns",
    "table_name": "clients",
    "column_name": "created_at",
    "data_type": "timestamp with time zone",
    "is_nullable": "NO",
    "column_default": "now()"
  },
  {
    "section": "columns",
    "table_name": "clients",
    "column_name": "updated_at",
    "data_type": "timestamp with time zone",
    "is_nullable": "NO",
    "column_default": "now()"
  },
  {
    "section": "columns",
    "table_name": "collection_runs",
    "column_name": "id",
    "data_type": "bigint",
    "is_nullable": "NO",
    "column_default": "nextval('collection_runs_id_seq'::regclass)"
  },
  {
    "section": "columns",
    "table_name": "collection_runs",
    "column_name": "org_id",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "collection_runs",
    "column_name": "source_id",
    "data_type": "bigint",
    "is_nullable": "YES",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "collection_runs",
    "column_name": "source_name",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "collection_runs",
    "column_name": "started_at",
    "data_type": "timestamp with time zone",
    "is_nullable": "NO",
    "column_default": "now()"
  },
  {
    "section": "columns",
    "table_name": "collection_runs",
    "column_name": "finished_at",
    "data_type": "timestamp with time zone",
    "is_nullable": "NO",
    "column_default": "now()"
  },
  {
    "section": "columns",
    "table_name": "collection_runs",
    "column_name": "checked_count",
    "data_type": "integer",
    "is_nullable": "NO",
    "column_default": "0"
  },
  {
    "section": "columns",
    "table_name": "collection_runs",
    "column_name": "created_count",
    "data_type": "integer",
    "is_nullable": "NO",
    "column_default": "0"
  },
  {
    "section": "columns",
    "table_name": "collection_runs",
    "column_name": "skipped_count",
    "data_type": "integer",
    "is_nullable": "NO",
    "column_default": "0"
  },
  {
    "section": "columns",
    "table_name": "collection_runs",
    "column_name": "status",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "collection_runs",
    "column_name": "error",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "''::text"
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "id",
    "data_type": "bigint",
    "is_nullable": "NO",
    "column_default": "nextval('incidents_id_seq'::regclass)"
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "org_id",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "log_id",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "collected_at",
    "data_type": "timestamp with time zone",
    "is_nullable": "NO",
    "column_default": "now()"
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "source",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "source_url",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "raw_content",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "summary",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "threat_category",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "severity",
    "data_type": "integer",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "location_relevance",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "''::text"
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "geo_relevance",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "'Unknown'::text"
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "verified",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "'No'::text"
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "verification_source",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "''::text"
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "client_notified",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "'No'::text"
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "notification_method",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "''::text"
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "status",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "'Monitoring'::text"
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "analyst",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "''::text"
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "notes",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "''::text"
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "content_hash",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "''::text"
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "matched_keywords",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "''::text"
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "confidence",
    "data_type": "integer",
    "is_nullable": "NO",
    "column_default": "50"
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "quality_score",
    "data_type": "integer",
    "is_nullable": "NO",
    "column_default": "50"
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "created_at",
    "data_type": "timestamp with time zone",
    "is_nullable": "NO",
    "column_default": "now()"
  },
  {
    "section": "columns",
    "table_name": "incidents",
    "column_name": "updated_at",
    "data_type": "timestamp with time zone",
    "is_nullable": "NO",
    "column_default": "now()"
  },
  {
    "section": "columns",
    "table_name": "organisations",
    "column_name": "id",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "organisations",
    "column_name": "name",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "organisations",
    "column_name": "created_at",
    "data_type": "timestamp with time zone",
    "is_nullable": "NO",
    "column_default": "now()"
  },
  {
    "section": "columns",
    "table_name": "organisations",
    "column_name": "updated_at",
    "data_type": "timestamp with time zone",
    "is_nullable": "NO",
    "column_default": "now()"
  },
  {
    "section": "columns",
    "table_name": "sources",
    "column_name": "id",
    "data_type": "bigint",
    "is_nullable": "NO",
    "column_default": "nextval('sources_id_seq'::regclass)"
  },
  {
    "section": "columns",
    "table_name": "sources",
    "column_name": "org_id",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "sources",
    "column_name": "name",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "sources",
    "column_name": "source_type",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "sources",
    "column_name": "url",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "sources",
    "column_name": "credibility",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "'B'::text"
  },
  {
    "section": "columns",
    "table_name": "sources",
    "column_name": "notes",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "''::text"
  },
  {
    "section": "columns",
    "table_name": "sources",
    "column_name": "created_at",
    "data_type": "timestamp with time zone",
    "is_nullable": "NO",
    "column_default": "now()"
  },
  {
    "section": "columns",
    "table_name": "sources",
    "column_name": "updated_at",
    "data_type": "timestamp with time zone",
    "is_nullable": "NO",
    "column_default": "now()"
  },
  {
    "section": "columns",
    "table_name": "sources",
    "column_name": "last_checked_at",
    "data_type": "timestamp with time zone",
    "is_nullable": "YES",
    "column_default": null
  },
  {
    "section": "columns",
    "table_name": "sources",
    "column_name": "last_status",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "'Never checked'::text"
  },
  {
    "section": "columns",
    "table_name": "sources",
    "column_name": "last_error",
    "data_type": "text",
    "is_nullable": "NO",
    "column_default": "''::text"
  }
]

select 'indexes' as section, tablename, indexname, indexdef
from pg_indexes
where schemaname = 'public'
order by tablename, indexname;

[
  {
    "section": "indexes",
    "tablename": "alert_events",
    "indexname": "alert_events_pkey",
    "indexdef": "CREATE UNIQUE INDEX alert_events_pkey ON public.alert_events USING btree (id)"
  },
  {
    "section": "indexes",
    "tablename": "alert_events",
    "indexname": "idx_alert_events_org_status",
    "indexdef": "CREATE INDEX idx_alert_events_org_status ON public.alert_events USING btree (org_id, status, created_at DESC)"
  },
  {
    "section": "indexes",
    "tablename": "audit_logs",
    "indexname": "audit_logs_pkey",
    "indexdef": "CREATE UNIQUE INDEX audit_logs_pkey ON public.audit_logs USING btree (id)"
  },
  {
    "section": "indexes",
    "tablename": "audit_logs",
    "indexname": "idx_audit_logs_org_created",
    "indexdef": "CREATE INDEX idx_audit_logs_org_created ON public.audit_logs USING btree (org_id, created_at DESC)"
  },
  {
    "section": "indexes",
    "tablename": "briefs",
    "indexname": "briefs_pkey",
    "indexdef": "CREATE UNIQUE INDEX briefs_pkey ON public.briefs USING btree (id)"
  },
  {
    "section": "indexes",
    "tablename": "briefs",
    "indexname": "idx_briefs_org_generated",
    "indexdef": "CREATE INDEX idx_briefs_org_generated ON public.briefs USING btree (org_id, generated_at DESC)"
  },
  {
    "section": "indexes",
    "tablename": "clients",
    "indexname": "clients_org_id_name_key",
    "indexdef": "CREATE UNIQUE INDEX clients_org_id_name_key ON public.clients USING btree (org_id, name)"
  },
  {
    "section": "indexes",
    "tablename": "clients",
    "indexname": "clients_pkey",
    "indexdef": "CREATE UNIQUE INDEX clients_pkey ON public.clients USING btree (id)"
  },
  {
    "section": "indexes",
    "tablename": "collection_runs",
    "indexname": "collection_runs_pkey",
    "indexdef": "CREATE UNIQUE INDEX collection_runs_pkey ON public.collection_runs USING btree (id)"
  },
  {
    "section": "indexes",
    "tablename": "collection_runs",
    "indexname": "idx_collection_runs_org_finished",
    "indexdef": "CREATE INDEX idx_collection_runs_org_finished ON public.collection_runs USING btree (org_id, finished_at DESC)"
  },
  {
    "section": "indexes",
    "tablename": "incidents",
    "indexname": "idx_incidents_org_category",
    "indexdef": "CREATE INDEX idx_incidents_org_category ON public.incidents USING btree (org_id, threat_category)"
  },
  {
    "section": "indexes",
    "tablename": "incidents",
    "indexname": "idx_incidents_org_collected_at",
    "indexdef": "CREATE INDEX idx_incidents_org_collected_at ON public.incidents USING btree (org_id, collected_at DESC)"
  },
  {
    "section": "indexes",
    "tablename": "incidents",
    "indexname": "idx_incidents_org_content_hash",
    "indexdef": "CREATE UNIQUE INDEX idx_incidents_org_content_hash ON public.incidents USING btree (org_id, content_hash) WHERE (content_hash <> ''::text)"
  },
  {
    "section": "indexes",
    "tablename": "incidents",
    "indexname": "idx_incidents_org_geo",
    "indexdef": "CREATE INDEX idx_incidents_org_geo ON public.incidents USING btree (org_id, geo_relevance)"
  },
  {
    "section": "indexes",
    "tablename": "incidents",
    "indexname": "idx_incidents_org_severity",
    "indexdef": "CREATE INDEX idx_incidents_org_severity ON public.incidents USING btree (org_id, severity DESC)"
  },
  {
    "section": "indexes",
    "tablename": "incidents",
    "indexname": "incidents_log_id_key",
    "indexdef": "CREATE UNIQUE INDEX incidents_log_id_key ON public.incidents USING btree (log_id)"
  },
  {
    "section": "indexes",
    "tablename": "incidents",
    "indexname": "incidents_pkey",
    "indexdef": "CREATE UNIQUE INDEX incidents_pkey ON public.incidents USING btree (id)"
  },
  {
    "section": "indexes",
    "tablename": "organisations",
    "indexname": "organisations_pkey",
    "indexdef": "CREATE UNIQUE INDEX organisations_pkey ON public.organisations USING btree (id)"
  },
  {
    "section": "indexes",
    "tablename": "sources",
    "indexname": "idx_sources_org_status",
    "indexdef": "CREATE INDEX idx_sources_org_status ON public.sources USING btree (org_id, last_status)"
  },
  {
    "section": "indexes",
    "tablename": "sources",
    "indexname": "sources_org_id_url_key",
    "indexdef": "CREATE UNIQUE INDEX sources_org_id_url_key ON public.sources USING btree (org_id, url)"
  },
  {
    "section": "indexes",
    "tablename": "sources",
    "indexname": "sources_pkey",
    "indexdef": "CREATE UNIQUE INDEX sources_pkey ON public.sources USING btree (id)"
  }
]

select 'triggers' as section, event_object_table as table_name, trigger_name, action_timing, event_manipulation
from information_schema.triggers
where trigger_schema = 'public'
order by event_object_table, trigger_name;

[
  {
    "section": "triggers",
    "table_name": "clients",
    "trigger_name": "trg_audit_clients",
    "action_timing": "AFTER",
    "event_manipulation": "INSERT"
  },
  {
    "section": "triggers",
    "table_name": "clients",
    "trigger_name": "trg_audit_clients",
    "action_timing": "AFTER",
    "event_manipulation": "UPDATE"
  },
  {
    "section": "triggers",
    "table_name": "clients",
    "trigger_name": "trg_audit_clients",
    "action_timing": "AFTER",
    "event_manipulation": "DELETE"
  },
  {
    "section": "triggers",
    "table_name": "clients",
    "trigger_name": "trg_clients_updated_at",
    "action_timing": "BEFORE",
    "event_manipulation": "UPDATE"
  },
  {
    "section": "triggers",
    "table_name": "incidents",
    "trigger_name": "trg_audit_incidents",
    "action_timing": "AFTER",
    "event_manipulation": "INSERT"
  },
  {
    "section": "triggers",
    "table_name": "incidents",
    "trigger_name": "trg_audit_incidents",
    "action_timing": "AFTER",
    "event_manipulation": "UPDATE"
  },
  {
    "section": "triggers",
    "table_name": "incidents",
    "trigger_name": "trg_audit_incidents",
    "action_timing": "AFTER",
    "event_manipulation": "DELETE"
  },
  {
    "section": "triggers",
    "table_name": "incidents",
    "trigger_name": "trg_incidents_high_severity_alert",
    "action_timing": "AFTER",
    "event_manipulation": "INSERT"
  },
  {
    "section": "triggers",
    "table_name": "incidents",
    "trigger_name": "trg_incidents_updated_at",
    "action_timing": "BEFORE",
    "event_manipulation": "UPDATE"
  },
  {
    "section": "triggers",
    "table_name": "sources",
    "trigger_name": "trg_audit_sources",
    "action_timing": "AFTER",
    "event_manipulation": "DELETE"
  },
  {
    "section": "triggers",
    "table_name": "sources",
    "trigger_name": "trg_audit_sources",
    "action_timing": "AFTER",
    "event_manipulation": "UPDATE"
  },
  {
    "section": "triggers",
    "table_name": "sources",
    "trigger_name": "trg_audit_sources",
    "action_timing": "AFTER",
    "event_manipulation": "INSERT"
  },
  {
    "section": "triggers",
    "table_name": "sources",
    "trigger_name": "trg_sources_updated_at",
    "action_timing": "BEFORE",
    "event_manipulation": "UPDATE"
  }
]

select 'functions' as section, proname as function_name, pg_get_function_arguments(p.oid) as arguments
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public'
order by proname;

[
  {
    "section": "functions",
    "function_name": "audit_row_change",
    "arguments": ""
  },
  {
    "section": "functions",
    "function_name": "current_org_id",
    "arguments": ""
  },
  {
    "section": "functions",
    "function_name": "enqueue_high_severity_alert",
    "arguments": ""
  },
  {
    "section": "functions",
    "function_name": "rls_auto_enable",
    "arguments": ""
  },
  {
    "section": "functions",
    "function_name": "set_updated_at",
    "arguments": ""
  }
]

select 'policies' as section, schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check
from pg_policies
where schemaname = 'public'
order by tablename, policyname;

[
  {
    "section": "policies",
    "schemaname": "public",
    "tablename": "alert_events",
    "policyname": "org_scope_all_alert_events",
    "permissive": "PERMISSIVE",
    "roles": "{public}",
    "cmd": "ALL",
    "qual": "((org_id = current_org_id()) OR (current_org_id() IS NULL))",
    "with_check": "((org_id = current_org_id()) OR (current_org_id() IS NULL))"
  },
  {
    "section": "policies",
    "schemaname": "public",
    "tablename": "audit_logs",
    "policyname": "org_scope_select_audit_logs",
    "permissive": "PERMISSIVE",
    "roles": "{public}",
    "cmd": "SELECT",
    "qual": "((org_id = current_org_id()) OR (current_org_id() IS NULL))",
    "with_check": null
  },
  {
    "section": "policies",
    "schemaname": "public",
    "tablename": "briefs",
    "policyname": "org_scope_all_briefs",
    "permissive": "PERMISSIVE",
    "roles": "{public}",
    "cmd": "ALL",
    "qual": "((org_id = current_org_id()) OR (current_org_id() IS NULL))",
    "with_check": "((org_id = current_org_id()) OR (current_org_id() IS NULL))"
  },
  {
    "section": "policies",
    "schemaname": "public",
    "tablename": "clients",
    "policyname": "org_scope_all_clients",
    "permissive": "PERMISSIVE",
    "roles": "{public}",
    "cmd": "ALL",
    "qual": "((org_id = current_org_id()) OR (current_org_id() IS NULL))",
    "with_check": "((org_id = current_org_id()) OR (current_org_id() IS NULL))"
  },
  {
    "section": "policies",
    "schemaname": "public",
    "tablename": "clients",
    "policyname": "org_scope_select_clients",
    "permissive": "PERMISSIVE",
    "roles": "{public}",
    "cmd": "SELECT",
    "qual": "((org_id = current_org_id()) OR (current_org_id() IS NULL))",
    "with_check": null
  },
  {
    "section": "policies",
    "schemaname": "public",
    "tablename": "collection_runs",
    "policyname": "org_scope_all_collection_runs",
    "permissive": "PERMISSIVE",
    "roles": "{public}",
    "cmd": "ALL",
    "qual": "((org_id = current_org_id()) OR (current_org_id() IS NULL))",
    "with_check": "((org_id = current_org_id()) OR (current_org_id() IS NULL))"
  },
  {
    "section": "policies",
    "schemaname": "public",
    "tablename": "incidents",
    "policyname": "org_scope_all_incidents",
    "permissive": "PERMISSIVE",
    "roles": "{public}",
    "cmd": "ALL",
    "qual": "((org_id = current_org_id()) OR (current_org_id() IS NULL))",
    "with_check": "((org_id = current_org_id()) OR (current_org_id() IS NULL))"
  },
  {
    "section": "policies",
    "schemaname": "public",
    "tablename": "sources",
    "policyname": "org_scope_all_sources",
    "permissive": "PERMISSIVE",
    "roles": "{public}",
    "cmd": "ALL",
    "qual": "((org_id = current_org_id()) OR (current_org_id() IS NULL))",
    "with_check": "((org_id = current_org_id()) OR (current_org_id() IS NULL))"
  }
]

select 'rls' as section, relname as table_name, relrowsecurity as rls_enabled, relforcerowsecurity as rls_forced
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public'
and relkind = 'r'
order by relname;

[
  {
    "section": "rls",
    "table_name": "alert_events",
    "rls_enabled": true,
    "rls_forced": false
  },
  {
    "section": "rls",
    "table_name": "audit_logs",
    "rls_enabled": true,
    "rls_forced": false
  },
  {
    "section": "rls",
    "table_name": "briefs",
    "rls_enabled": true,
    "rls_forced": false
  },
  {
    "section": "rls",
    "table_name": "clients",
    "rls_enabled": true,
    "rls_forced": false
  },
  {
    "section": "rls",
    "table_name": "collection_runs",
    "rls_enabled": true,
    "rls_forced": false
  },
  {
    "section": "rls",
    "table_name": "incidents",
    "rls_enabled": true,
    "rls_forced": false
  },
  {
    "section": "rls",
    "table_name": "organisations",
    "rls_enabled": true,
    "rls_forced": false
  },
  {
    "section": "rls",
    "table_name": "sources",
    "rls_enabled": true,
    "rls_forced": false
  }
]

select 'seed_counts' as section, 'organisations' as table_name, count(*)::text as count from public.organisations
union all
select 'seed_counts', 'sources', count(*)::text from public.sources
union all
select 'seed_counts', 'clients', count(*)::text from public.clients
union all
select 'seed_counts', 'incidents', count(*)::text from public.incidents
union all
select 'seed_counts', 'collection_runs', count(*)::text from public.collection_runs
union all
select 'seed_counts', 'briefs', count(*)::text from public.briefs
union all
select 'seed_counts', 'alert_events', count(*)::text from public.alert_events
union all
select 'seed_counts', 'audit_logs', count(*)::text from public.audit_logs;

[
  {
    "section": "seed_counts",
    "table_name": "organisations",
    "count": "1"
  },
  {
    "section": "seed_counts",
    "table_name": "sources",
    "count": "21"
  },
  {
    "section": "seed_counts",
    "table_name": "clients",
    "count": "0"
  },
  {
    "section": "seed_counts",
    "table_name": "incidents",
    "count": "0"
  },
  {
    "section": "seed_counts",
    "table_name": "collection_runs",
    "count": "0"
  },
  {
    "section": "seed_counts",
    "table_name": "briefs",
    "count": "0"
  },
  {
    "section": "seed_counts",
    "table_name": "alert_events",
    "count": "0"
  },
  {
    "section": "seed_counts",
    "table_name": "audit_logs",
    "count": "21"
  }
]