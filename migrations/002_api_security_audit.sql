-- Migration 002: API keys and audit logs for Phase 2 productisation.
-- Run this in Supabase SQL Editor after the base schema exists.

create table if not exists public.api_keys (
    id bigserial primary key,
    org_id text not null references public.organisations(id) on delete cascade,
    name text not null,
    key_hash text not null unique,
    role text not null default 'analyst' check (role in ('admin', 'analyst', 'viewer', 'collector')),
    is_active boolean not null default true,
    created_at timestamptz not null default now(),
    last_used_at timestamptz
);

create index if not exists idx_api_keys_org_active
    on public.api_keys(org_id, is_active);

create table if not exists public.audit_logs (
    id bigserial primary key,
    org_id text not null references public.organisations(id) on delete cascade,
    actor text not null default '',
    action text not null,
    resource_type text not null default '',
    resource_id text not null default '',
    ip_address text not null default '',
    user_agent text not null default '',
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);

create index if not exists idx_audit_logs_org_created
    on public.audit_logs(org_id, created_at desc);

create index if not exists idx_audit_logs_action_created
    on public.audit_logs(action, created_at desc);

alter table public.api_keys enable row level security;
alter table public.audit_logs enable row level security;

drop policy if exists "api_keys_app_access" on public.api_keys;
create policy "api_keys_app_access"
on public.api_keys
for all
using (public.current_org_id() is null or org_id = public.current_org_id())
with check (public.current_org_id() is null or org_id = public.current_org_id());

drop policy if exists "audit_logs_app_access" on public.audit_logs;
create policy "audit_logs_app_access"
on public.audit_logs
for all
using (public.current_org_id() is null or org_id = public.current_org_id())
with check (public.current_org_id() is null or org_id = public.current_org_id());
