-- WARNING: This schema is for context only and is not meant to be run.
-- Table order and constraints may not be valid for execution.

CREATE TABLE public.organisations (
  id text NOT NULL,
  name text NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT organisations_pkey PRIMARY KEY (id)
);
CREATE TABLE public.clients (
  id bigint NOT NULL DEFAULT nextval('clients_id_seq'::regclass),
  org_id text NOT NULL,
  name text NOT NULL,
  area text NOT NULL DEFAULT ''::text,
  tier text NOT NULL DEFAULT 'Standard'::text,
  contact text NOT NULL DEFAULT ''::text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT clients_pkey PRIMARY KEY (id),
  CONSTRAINT clients_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organisations(id)
);
CREATE TABLE public.sources (
  id bigint NOT NULL DEFAULT nextval('sources_id_seq'::regclass),
  org_id text NOT NULL,
  name text NOT NULL,
  source_type text NOT NULL,
  url text NOT NULL,
  credibility text NOT NULL DEFAULT 'B'::text CHECK (credibility = ANY (ARRAY['A'::text, 'B'::text, 'C'::text])),
  notes text NOT NULL DEFAULT ''::text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  last_checked_at timestamp with time zone,
  last_status text NOT NULL DEFAULT 'Never checked'::text,
  last_error text NOT NULL DEFAULT ''::text,
  CONSTRAINT sources_pkey PRIMARY KEY (id),
  CONSTRAINT sources_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organisations(id)
);
CREATE TABLE public.incidents (
  id bigint NOT NULL DEFAULT nextval('incidents_id_seq'::regclass),
  org_id text NOT NULL,
  log_id text NOT NULL UNIQUE,
  collected_at timestamp with time zone NOT NULL DEFAULT now(),
  source text NOT NULL,
  source_url text NOT NULL,
  raw_content text NOT NULL,
  summary text NOT NULL,
  threat_category text NOT NULL CHECK (threat_category = ANY (ARRAY['Physical'::text, 'Cyber'::text, 'Political'::text, 'Macro'::text])),
  severity integer NOT NULL CHECK (severity >= 1 AND severity <= 5),
  location_relevance text NOT NULL DEFAULT ''::text,
  geo_relevance text NOT NULL DEFAULT 'Unknown'::text CHECK (geo_relevance = ANY (ARRAY['Lagos'::text, 'Nigeria'::text, 'Client'::text, 'None'::text, 'Unknown'::text])),
  verified text NOT NULL DEFAULT 'No'::text CHECK (verified = ANY (ARRAY['Yes'::text, 'No'::text, 'Partial'::text])),
  verification_source text NOT NULL DEFAULT ''::text,
  client_notified text NOT NULL DEFAULT 'No'::text CHECK (client_notified = ANY (ARRAY['Yes'::text, 'No'::text])),
  notification_method text NOT NULL DEFAULT ''::text,
  status text NOT NULL DEFAULT 'Monitoring'::text CHECK (status = ANY (ARRAY['Active'::text, 'Monitoring'::text, 'Resolved'::text, 'Archived'::text])),
  analyst text NOT NULL DEFAULT ''::text,
  notes text NOT NULL DEFAULT ''::text,
  content_hash text NOT NULL DEFAULT ''::text,
  matched_keywords text NOT NULL DEFAULT ''::text,
  confidence integer NOT NULL DEFAULT 50 CHECK (confidence >= 0 AND confidence <= 100),
  quality_score integer NOT NULL DEFAULT 50 CHECK (quality_score >= 0 AND quality_score <= 100),
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT incidents_pkey PRIMARY KEY (id),
  CONSTRAINT incidents_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organisations(id)
);
CREATE TABLE public.collection_runs (
  id bigint NOT NULL DEFAULT nextval('collection_runs_id_seq'::regclass),
  org_id text NOT NULL,
  source_id bigint,
  source_name text NOT NULL,
  started_at timestamp with time zone NOT NULL DEFAULT now(),
  finished_at timestamp with time zone NOT NULL DEFAULT now(),
  checked_count integer NOT NULL DEFAULT 0,
  created_count integer NOT NULL DEFAULT 0,
  skipped_count integer NOT NULL DEFAULT 0,
  status text NOT NULL,
  error text NOT NULL DEFAULT ''::text,
  CONSTRAINT collection_runs_pkey PRIMARY KEY (id),
  CONSTRAINT collection_runs_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organisations(id),
  CONSTRAINT collection_runs_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.sources(id)
);
CREATE TABLE public.briefs (
  id bigint NOT NULL DEFAULT nextval('briefs_id_seq'::regclass),
  org_id text NOT NULL,
  title text NOT NULL,
  window_days integer NOT NULL DEFAULT 7,
  risk_rating text NOT NULL DEFAULT 'Green'::text CHECK (risk_rating = ANY (ARRAY['Green'::text, 'Orange'::text, 'Red'::text])),
  markdown text NOT NULL,
  generated_at timestamp with time zone NOT NULL DEFAULT now(),
  delivered_at timestamp with time zone,
  delivery_status text NOT NULL DEFAULT 'Draft'::text,
  CONSTRAINT briefs_pkey PRIMARY KEY (id),
  CONSTRAINT briefs_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organisations(id)
);
CREATE TABLE public.alert_events (
  id bigint NOT NULL DEFAULT nextval('alert_events_id_seq'::regclass),
  org_id text NOT NULL,
  incident_id bigint,
  severity integer NOT NULL CHECK (severity >= 1 AND severity <= 5),
  summary text NOT NULL,
  status text NOT NULL DEFAULT 'Pending'::text CHECK (status = ANY (ARRAY['Pending'::text, 'Sent'::text, 'Failed'::text, 'Suppressed'::text])),
  channels ARRAY NOT NULL DEFAULT ARRAY[]::text[],
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  sent_at timestamp with time zone,
  error text NOT NULL DEFAULT ''::text,
  CONSTRAINT alert_events_pkey PRIMARY KEY (id),
  CONSTRAINT alert_events_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organisations(id),
  CONSTRAINT alert_events_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES public.incidents(id)
);
CREATE TABLE public.audit_logs (
  id bigint NOT NULL DEFAULT nextval('audit_logs_id_seq'::regclass),
  org_id text,
  table_name text NOT NULL,
  record_id text NOT NULL,
  action text NOT NULL,
  old_data jsonb,
  new_data jsonb,
  actor text NOT NULL DEFAULT CURRENT_USER,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT audit_logs_pkey PRIMARY KEY (id)
);
CREATE TABLE public.api_keys (
  id bigint NOT NULL DEFAULT nextval('api_keys_id_seq'::regclass),
  org_id text NOT NULL,
  name text NOT NULL,
  key_hash text NOT NULL UNIQUE,
  role text NOT NULL DEFAULT 'analyst'::text CHECK (role = ANY (ARRAY['admin'::text, 'analyst'::text, 'viewer'::text, 'collector'::text])),
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  last_used_at timestamp with time zone,
  CONSTRAINT api_keys_pkey PRIMARY KEY (id),
  CONSTRAINT api_keys_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organisations(id)
);