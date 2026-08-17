---
name: gatsby
description: Gatsby attack surface: GraphQL data layer leak, build-time secrets, /public/ JSON dumps
depends_on: []
---

# Gatsby

Gatsby is static-site-generator-flavored React. Build outputs page-data JSON files containing full GraphQL query results — frequently leak unfiltered datasets.

## Common Bug Classes

- `/page-data/*/page-data.json` exposing full GraphQL query results
- Build-time secrets bundled into `static/` chunks (`.env.production`)
- Source maps shipped to production

## Probe Targets

- Crawl `/page-data/index/page-data.json` and walk `slug`-keyed children
- Diff client-side data vs server response for missing field-level auth
- Check `/static/*.js.map` accessibility

## Cross-References

`js_analysis`, `information_disclosure`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
