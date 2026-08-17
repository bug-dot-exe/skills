---
name: hasura
description: Hasura attack surface: admin secret bypass, anonymous role over-permission, action webhook trust
depends_on: []
---

# Hasura

Hasura is GraphQL-on-Postgres. Bug surface: `x-hasura-admin-secret` leak (full DB access), anonymous role with too-broad SELECT, Action webhooks trusting client headers.

## Common Bug Classes

- `x-hasura-admin-secret` leaked via JS bundle or env exposure
- Anonymous role granted SELECT on sensitive tables
- Action webhooks trusting `x-hasura-user-id` from request headers
- Console (`/console`) exposed in prod

## Probe Targets

- POST to `/v1/graphql` with `x-hasura-admin-secret` brute
- Probe `/console`, `/v1/graphql`, `/v1alpha1/graphql`
- Test anonymous queries: `{ users { id email password_hash } }`

## Cross-References

`graphql_attacks`, `api_security`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
