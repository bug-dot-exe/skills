---
name: fastapi
description: FastAPI attack surface: pydantic validation gaps, OpenAPI exposure, dependency injection auth bypass
depends_on: []
---

# Fastapi

FastAPI generates OpenAPI specs automatically (typically `/docs`, `/openapi.json`). Pydantic validates body schemas but optional fields are easily missed. Dependency-injection auth (`Depends(get_user)`) must be applied per-route.

## Common Bug Classes

- Missing `Depends(get_current_user)` on endpoints — IDOR or unauth access
- Pydantic `Optional` fields accepting nulls that bypass downstream validation
- OpenAPI spec exposing internal endpoints, schemas, role enums
- Mass assignment when endpoints accept `**kwargs` or full Pydantic models with privileged fields
- JWT validation in middleware but not in `Depends` — inconsistent paths
- CORS open via `allow_origins=["*"]` with credentials

## Probe Targets

- Always pull `/openapi.json` / `/docs` / `/redoc` first
- Enumerate all paths from openapi.json, probe each unauth and per role
- Send full request body including suspected privileged fields (role, isAdmin, organizationId)
- Test `OPTIONS` for permissive CORS

## Cross-References

`api_security`, `broken_function_level_authorization`, `mass_assignment`, `cors_misconfiguration`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
