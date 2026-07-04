# Lemtik Supabase Migrations

Run `../supabase.sql` in the Supabase SQL editor for a new project.

`001_supabase_schema.sql` is a psql-friendly migration wrapper for local or CLI workflows.

After running the schema, run `../tocheck.sql` in Supabase and share the result if anything looks wrong.

Then apply `002_api_security_audit.sql` for API keys and audit logs, and `003_brain_tasks_queue.sql` for the queued OSINT task layer.
