---
name: cloudflare-workers
description: Cloudflare Workers attack surface: KV/Durable Object trust, secret leak, sub-request loop
depends_on: []
---

# Cloudflare Workers

CF Workers run JavaScript at the edge. Bug surface: Workers trusting client input for KV/Durable Object keys, environment secrets leaked via `console.log` to Logpush, recursive sub-request loops causing DoS.

## Common Bug Classes

- Worker KV writes accepting attacker-controlled keys
- Durable Object methods without authz
- Secrets logged via `console.log` and shipped to Logpush sinks
- Sub-request recursion causing 50× amplification

## Probe Targets

- Probe Worker routes for KV access patterns
- Test Durable Object endpoints for cross-tenant access

## Cross-References

`api_security`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
