---
name: netlify
description: Netlify attack surface: function endpoint enum, build env exposure, Forms abuse
depends_on: []
---

# Netlify

Netlify hosts JAMstack sites. Bug surface: function endpoints under `/.netlify/functions/*` (auth missing), build-time env vars leaked, Netlify Forms accepting unfiltered input.

## Common Bug Classes

- Functions under `/.netlify/functions/<name>` without auth
- Build env vars baked into JS bundle (`process.env.SECRET`)
- Netlify Forms spam endpoints abused for arbitrary email
- Deploy preview URLs without auth

## Probe Targets

- Crawl `/.netlify/functions/` and probe each function
- Subdomain enum on `*.netlify.app` for deploy previews
- POST to `/__forms.html` and submission endpoints

## Cross-References

`api_security`, `information_disclosure`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
