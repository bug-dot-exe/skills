---
name: nuxt
description: Nuxt 3 attack surface: server routes, useFetch SSR vs client mismatch, runtime config exposure
depends_on: []
---

# Nuxt

Nuxt 3 (Nitro server) layouts API endpoints under `/api/` (or custom). Server-only modules can leak secrets if `runtimeConfig.public` is misused. SSR/CSR parity issues create auth gaps.

## Common Bug Classes

- `runtimeConfig.public` accidentally containing private secrets — exposed to client
- Server routes (`/server/api/*.ts`) without auth middleware
- SSR fetch using server cookies; CSR using none — auth mismatch
- ISR/SWR cache poisoning analogous to Next.js

## Probe Targets

- Inspect `/_nuxt/*.js` chunks for runtimeConfig leaks
- Probe `/__nuxt_error` for stack traces
- Test `/api/*` server routes without auth

## Cross-References

`xss`, `spa_client_side`, `js_analysis`, `broken_function_level_authorization`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
