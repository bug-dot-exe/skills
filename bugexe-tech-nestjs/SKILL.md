---
name: nestjs
description: NestJS attack surface: Guard bypass, decorator metadata gaps, microservice transport, GraphQL resolver auth
depends_on: []
---

# Nestjs

NestJS is opinionated TypeScript Node.js framework on top of Express/Fastify. Auth via Guards (`@UseGuards(JwtAuthGuard)`) — must be applied per-route or per-controller; missing decorator = open route.

## Common Bug Classes

- Missing `@UseGuards()` on individual routes
- GraphQL resolvers bypassing REST guards entirely
- Microservice transport (`@MessagePattern`) without auth
- Pipe validation skipped in WebSocket gateway
- Verbose validation errors leaking schema

## Probe Targets

- Pull `/api/docs` (Swagger) or `/graphql` (Playground) for full schema
- Test all endpoints unauth then per-role
- Probe `/microservices/*` and WebSocket gateways

## Cross-References

`api_security`, `graphql_attacks`, `broken_function_level_authorization`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
