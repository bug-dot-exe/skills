---
name: postgrest
description: PostgREST attack surface: row-level security gaps, JWT secret leak, schema introspection
depends_on: []
---

# Postgrest

PostgREST exposes Postgres tables as REST. All authz lives in Postgres RLS policies — gaps there mean direct SELECT/UPDATE/DELETE on tables.

## Common Bug Classes

- RLS policy missing for new tables — defaults to FULL access
- `PGRST_JWT_SECRET` reused across environments
- Schema introspection exposing table list and columns
- OpenAPI endpoint disclosing all routes

## Probe Targets

- GET `/` for OpenAPI spec
- Try basic CRUD on every discovered table without auth
- Forge JWT with `role` claim escalation

## Cross-References

`api_security`, `sql_injection`, `authentication_jwt`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
