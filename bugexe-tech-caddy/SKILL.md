---
name: caddy
description: Caddy server attack surface: Caddyfile misconfig, automatic HTTPS abuse, JSON API exposure
depends_on: []
---

# Caddy

Caddy emphasizes automatic HTTPS and a JSON API. Misconfig surface: admin API exposed beyond localhost, Caddyfile reverse_proxy paths with traversal.

## Common Bug Classes

- Admin API (`:2019`) exposed beyond localhost — full config replacement
- Caddyfile `reverse_proxy` paths without strict normalization
- Automatic HTTPS issuing certs for unintended domains via DNS
- Verbose error pages in dev mode

## Probe Targets

- Probe `:2019/config/`, `:2019/load`
- Test `reverse_proxy` paths with traversal

## Cross-References

`api_security`, `path_traversal_lfi_rfi`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
