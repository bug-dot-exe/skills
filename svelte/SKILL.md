---
name: svelte
description: Svelte attack surface: {@html} XSS, SvelteKit endpoint trust, SSR injection
depends_on: []
---

# Svelte

Svelte/SvelteKit compile to small bundles. The `{@html}` block renders raw HTML — primary XSS sink. SvelteKit form actions and load functions need server-side validation; client-side schemas are trivially bypassed.

## Common Bug Classes

- XSS via `{@html userContent}` in components
- SSR injection in SvelteKit `+page.server.ts` load functions concatenating untrusted data
- Form action endpoints accepting client-supplied IDs without ownership checks
- Zod/Valibot validation only on client-side, server trusts wire data

## Probe Targets

- Grep bundle for `{@html}` blocks and trace data origin
- Inspect `/_app/immutable/chunks/*.js` for hidden API routes
- Test SvelteKit `+server.ts` endpoints for IDOR and auth gaps

## Cross-References

`xss`, `spa_client_side`, `js_analysis`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
