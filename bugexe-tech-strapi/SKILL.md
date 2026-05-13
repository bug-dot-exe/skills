---
name: strapi
description: Strapi attack surface: content-type API permissions, custom controller auth, plugin RCE
depends_on: []
---

# Strapi

Strapi is a Node.js headless CMS. Bug surface: content-type permissions misconfigured (anonymous role with too-broad access), custom controllers without auth, admin panel exposure.

## Common Bug Classes

- Anonymous / Public role with too many `find`/`findOne` permissions
- Custom controllers bypassing default policy chain
- Admin panel (`/admin`) exposed with default credentials
- Plugin marketplace plugins with known RCE

## Probe Targets

- Probe `/api/users`, `/api/articles`, `/admin`
- Test all content-types listed in `/api/`

## Cross-References

`api_security`, `broken_function_level_authorization`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
