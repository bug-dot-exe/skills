---
name: apollo
description: Apollo Server attack surface: introspection in prod, persisted queries, batching DoS
depends_on: []
---

# Apollo

Apollo is dominant GraphQL implementation (server + client). Distinct bugs: introspection enabled in production, persisted-query allowlist gaps, query batching DoS, federation cross-subgraph trust.

## Common Bug Classes

- Introspection enabled in production exposing schema
- Persisted query allowlist absent allowing arbitrary queries
- Batching DoS via `[{query: '...'}, {query: '...'}, ...]` of N queries
- Federation `__typename` confusion across subgraphs
- Apollo Studio embedded sandbox accessible in prod

## Probe Targets

- POST `{__schema {types {name}}}` to `/graphql`
- Send batched query array with 100+ items
- Probe `/graphql/sandbox`, `/graphql?sandbox=true`

## Cross-References

`graphql_attacks`, `api_security`, `resource_exhaustion_dos`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
