---
name: ghost
description: Ghost CMS attack surface: Admin API auth, SSRF in webhook URLs, content-API key leak
depends_on: []
---

# Ghost

Ghost is a Node.js CMS for blogs/newsletters. Admin and Content APIs are separate; Content API keys are intentionally public, Admin API keys must be private.

## Common Bug Classes

- Admin API key leak via Members.js bundle
- SSRF in webhook destination URLs
- Content API leaking unpublished posts via direct slug access
- Email send abuse via newsletter infrastructure

## Probe Targets

- Inspect Members.js for API keys
- Probe `/ghost/api/admin/`, `/ghost/api/content/`
- Check member-only post access via `/p/<post-uuid>`

## Cross-References

`api_security`, `ssrf`, `information_disclosure`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
