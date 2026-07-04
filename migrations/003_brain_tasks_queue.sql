-- Migration 003: Brain task queue for OSINT collection, briefs, and alert dispatch.
-- Run this after the base schema and API security migration.

create table if not exists public.brain_tasks (
    id text primary key,
    org_id text not null references public.organisations(id) on delete cascade,
    task_type text not null,
    status text not null default 'Pending' check (status in ('Pending', 'Running', 'Completed', 'Failed')),
    priority integer not null default 5 check (priority between 1 and 10),
    payload jsonb not null default '{}'::jsonb,
    result jsonb not null default '{}'::jsonb,
    error text not null default '',
    requested_by text not null default '',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    started_at timestamptz,
    finished_at timestamptz
);

create index if not exists idx_brain_tasks_org_status_priority
    on public.brain_tasks(org_id, status, priority desc, created_at asc);

create index if not exists idx_brain_tasks_task_type_created
    on public.brain_tasks(task_type, created_at desc);

create index if not exists idx_brain_tasks_org_created
    on public.brain_tasks(org_id, created_at desc);

create or replace function public.touch_brain_tasks_updated_at()
returns trigger
language plpgsql
as $$
begin
    new.updated_at = now();
    return new;
end;
$$;

drop trigger if exists trg_touch_brain_tasks_updated_at on public.brain_tasks;
create trigger trg_touch_brain_tasks_updated_at
before update on public.brain_tasks
for each row
execute function public.touch_brain_tasks_updated_at();

alter table public.brain_tasks enable row level security;

drop policy if exists "brain_tasks_app_access" on public.brain_tasks;
create policy "brain_tasks_app_access"
on public.brain_tasks
for all
using (public.current_org_id() is null or org_id = public.current_org_id())
with check (public.current_org_id() is null or org_id = public.current_org_id());
