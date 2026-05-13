---
name: contentful
description: Contentful attack surface: Delivery vs Preview API, Management API token leak, content tampering
depends_on: []
---

# Contentful

Contentful is hosted headless CMS. Three APIs (Delivery, Preview, Management). Management tokens are devastatingly powerful — should never appear client-side.

## Common Bug Classes

- Management API token leaked in JS bundle
- Preview API key exposing draft/unpublished content
- Webhook URLs without auth allowing tampering trigger

## Probe Targets

- Grep for `CFPAT-` prefix (Management token)
- Probe `/preview.contentful.com/spaces/<space>/entries`

## Cross-References

`api_security`, `public_credential_disclosure`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
