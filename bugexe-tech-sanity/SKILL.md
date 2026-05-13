---
name: sanity
description: Sanity.io attack surface: dataset CDN exposure, GROQ injection, write-token leak
depends_on: []
---

# Sanity

Sanity is a hosted headless CMS using GROQ query language. Bug surface: dataset accessible via public CDN, GROQ query injection in custom integrations, write tokens leaked to clients.

## Common Bug Classes

- Public dataset CDN URL exposing entire content database
- GROQ injection in custom Studio integrations
- Write tokens (`sanityClient` with `useCdn: false` and write token) leaked client-side

## Probe Targets

- Probe `https://<projectId>.api.sanity.io/v1/data/query/<dataset>?query=*`
- Search bundle for Sanity write tokens

## Cross-References

`api_security`, `public_credential_disclosure`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
