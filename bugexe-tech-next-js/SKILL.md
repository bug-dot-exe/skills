---
name: next-js
description: Next.js attack surface: middleware bypass, ISR cache poisoning, API route IDOR, Server Actions trust
depends_on: []
---

# Next Js

Next.js (App Router or Pages Router) is the dominant React framework. High-value targets: middleware (auth gates), API routes (`/api/*`), Server Actions (POST to encoded paths), Image Optimizer SSRF, and ISR cache poisoning.

## Common Bug Classes

- Middleware bypass via path normalization (`/admin/../api/admin`, double-encoding)
- Image Optimizer SSRF via `/_next/image?url=http://internal.host/`
- Server Actions accept any encoded action ID; missing auth → privilege escalation
- ISR cache poisoning via vary-header neglect on personalized routes
- API route IDOR — `/api/users/[id]` rarely scoped to caller
- `x-powered-by: Next.js` version disclosure → CVE matching
- RSC payload exposure via `?_rsc=1` query showing internal state

## Probe Targets

- Probe `/_next/image?url=http://localhost/` and `127.0.0.1` for SSRF
- Find Server Actions in HTML (`action="$ACTION_REF_<hash>"`) and POST without auth
- Test middleware bypass: `/.well-known/../admin`, URL-encoded `/`, mixed case
- Pull `__NEXT_DATA__` and `?_rsc=1` for hidden props/state
- Check for stale CVEs against the disclosed Next.js version

## Cross-References

`xss`, `ssrf`, `spa_client_side`, `js_analysis`, `open_redirect`, `broken_function_level_authorization`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
