---
name: api_security
category: vulnerabilities
description: Test APIs against the OWASP API Security Top 10 (2023) — BOLA, broken authentication, broken object property level authorization, unrestricted resource consumption, BFLA, sensitive business flow abuse, SSRF, security misconfiguration, improper inventory, unsafe consumption of upstream APIs
depends_on: []
---

# API Security Testing

APIs are a higher-impact, often less-protected version of the app they back.
The UI rate-limits, filters, and validates — the raw API often doesn't. The
OWASP API Security Top 10 (2023 edition) codifies the ten recurring class
failures to test against every API-backed target.

## When to Use

- Target exposes REST / GraphQL / gRPC / WebSocket / SSE APIs
- Mobile app backend (API is always exposed even without web UI)
- Microservices architecture (internal APIs sometimes reachable)
- B2B product with public "developer" API tier
- Webhook receivers or machine-to-machine integrations

## Discovery Signals

Before testing, determine _what_ APIs exist. These 12 signals identify API attack surface.

| # | Signal | Where to Find | What It Reveals |
|---|--------|---------------|-----------------|
| 1 | JS bundle API calls | `grep -rE 'fetch\|axios\|XMLHttp' *.js` in devtools Sources | Full endpoint list, including admin/internal paths the UI hides |
| 2 | OpenAPI/Swagger spec | `/swagger.json`, `/openapi.json`, `/api-docs`, `/v2/api-docs` | Every route, parameter, and schema in one file |
| 3 | GraphQL introspection | `{__schema{types{name fields{name type{name}}}}}` | Full type graph — mutations, queries, subscriptions |
| 4 | Mobile app decompile | `apkleaks`, `jadx`, `frida` traffic intercept | Endpoints the web UI never calls; hardcoded API keys |
| 5 | `robots.txt` / `sitemap.xml` | Root path | Disallowed admin/api paths |
| 6 | Wayback Machine | `web.archive.org/cdx/search?url=api.target.com/*` | Deprecated endpoints still live; old Swagger specs |
| 7 | Error response fingerprint | Send malformed JSON, wrong Content-Type | Framework name + version (Spring, Express, Django, Rails) |
| 8 | Subdomain enumeration | `subfinder`, `amass`, CT logs | `api-dev.`, `staging-api.`, `internal-api.`, `api-v1.` subdomains |
| 9 | CORS preflight response | `OPTIONS` + `Origin: https://evil.com` | Whether the API reflects origins, reveals allowed methods |
| 10 | Response headers | `Server`, `X-Powered-By`, `X-Request-Id` | Infrastructure stack; load balancer; request tracing IDs |
| 11 | gRPC reflection | `grpc_cli ls target:443` or `grpcurl -plaintext target:443 list` | Service names, method signatures, message types |
| 12 | Debug/admin endpoints | `/actuator/*`, `/debug/pprof/`, `/_debug`, `/metrics`, `/healthz` | Exposed Golang pprof, Spring Actuator, internal monitoring |

## OWASP API Top 10 (2023)

### API1:2023 — Broken Object Level Authorization (BOLA / IDOR)

Server trusts the client's object ID without verifying ownership. Change
`GET /api/orders/123` to `/api/orders/124` -> someone else's order.

Test surface:
- Numeric IDs (123 -> 124), UUIDs (predictable? guessable from profile URL?)
- Base64-encoded IDs (decode, tamper, re-encode)
- Nested routes (`/users/A/posts/B` — does it check A owns B?)
- Indirect references (username in URL but ID in header)

Per-endpoint checklist:
- [ ] Test with a second account's IDs (horizontal BOLA)
- [ ] Test with unprivileged account's session + admin IDs (vertical)
- [ ] Test GUID prediction: v1 UUID reveals timestamp + MAC
- [ ] Test negative IDs (`/orders/-1`), zero, large (`/orders/99999999999`)
- [ ] Test alternate lookup: if `/orders/:id` is locked, is `/orders?id=` different?

### API2:2023 — Broken Authentication

Test surface:
- Login: brute force (rate limit bypass via header tweaks)
- JWT: alg=none, weak secret, kid injection, key confusion (RSA -> HS256)
- Password reset: predictable tokens, no expiry, reusable tokens
- OAuth/OIDC: redirect_uri validation, state parameter, PKCE enforcement
- Session: cookie attributes (HttpOnly, Secure, SameSite)
- MFA: see `two_factor_bypass.md`

### API3:2023 — Broken Object Property Level Authorization

Combo of classic "Mass Assignment" + "Excessive Data Exposure".
See `mass_assignment.md` for the deep dive on field-level attacks.

Mass Assignment — client sets fields it shouldn't:
```http
PUT /api/users/me
{"email":"me@ok.com", "role":"admin", "is_verified":true, "org_id":123}
```

Test: add every field from the GET response (or guessable: `role`,
`isAdmin`, `permissions`, `org_id`, `balance`, `discount`) to your PUT/PATCH.

Excessive Data Exposure — server returns fields the UI doesn't render:
```
GET /api/users/search?q=alice
-> [{"id":1, "email":"alice@...", "ssn":"...", "internal_notes":"..."}]
```

Look for: SSN, internal IDs, internal notes, password_hash,
secrets_token, feature_flags per user.

### API4:2023 — Unrestricted Resource Consumption

- No rate limit -> brute force
- Expensive query without cost control -> DoS
- Pagination abuse (`?page_size=1000000`)
- Batch endpoints allowing 10k ops per call
- Image/PDF processing (upload huge file or deeply nested ZIP/SVG bomb)
- GraphQL deep/nested queries

Checklist:
- [ ] Hammer rate-limit with different `X-Forwarded-For`, API keys, session rotation
- [ ] Test `?limit=N`, `?per_page=N`, `?size=N` with huge N
- [ ] Upload 1 GB file — how does server behave?
- [ ] Recursive / self-referencing inputs

### API5:2023 — Broken Function Level Authorization (BFLA)

Privileged functions reachable by unprivileged users. Like BOLA but about
ACTIONS not OBJECTS. See `broken_function_level_authorization.md` for deep dive.

Test surface:
- Admin panel endpoints (`/api/admin/*`) accessible without admin role?
- HTTP verbs: `GET /api/users` allowed, but `DELETE /api/users/1` checked?
- Alternate content-type: JSON-locked endpoint accepts XML with different
  auth path?
- Hidden params: `?admin=true`, `?debug=true`

Checklist:
- [ ] Enumerate all admin-looking routes from JS bundle (see `js_analysis.md`)
- [ ] Replay each admin call with non-admin session
- [ ] Try alternate verb on allowed endpoints
- [ ] Check for HTTP method override headers (`X-HTTP-Method-Override: DELETE`)

### API6:2023 — Unrestricted Access to Sensitive Business Flows

The API allows abuse of a legit flow at machine scale: ticket purchase bots, mass invite-code generation, fake review spam, loyalty point farming, competitor price crawling.

### API7:2023 — Server-Side Request Forgery (SSRF)

See `ssrf.md`. API-specific: webhook URLs, URL previews, image ingestion, OAuth callback metadata fetch, document import from URL, "Import from Notion/Google Doc/Confluence".

### API8:2023 — Security Misconfiguration

Test: verbose errors (stack traces, framework version), CORS `*` + credentials, CORS origin reflection, default creds on admin endpoints, directory listing, missing security headers, deprecated TLS.

Checklist:
- [ ] Malformed request -> stack trace? Framework version?
- [ ] `Origin: https://evil.com` reflected in CORS with credentials?
- [ ] `/actuator/*` (Spring), `/_debug`, `/metrics`, `/healthz`, `.well-known/*`
- [ ] Weird verbs: `OPTIONS *`, `TRACE`, `CONNECT`

### API9:2023 — Improper Inventory Management

Old + deprecated API versions still live. v1 may lack fixes shipped in v2.

Test surface:
- `api.target.com/v1/` vs `/v2/` vs `/beta/` vs `/internal/`
- Subdomain variants: `api-dev.target.com`, `staging-api.target.com`
- Swagger / OpenAPI specs at `/swagger.json`, `/openapi.json`, `/api-docs`,
  `/redoc`, `/graphql` (introspection)
- Legacy endpoints mentioned in older JS bundles (see `wayback_cdx_dorking.md`)

### API10:2023 — Unsafe Consumption of APIs

Target API blindly trusts upstream responses. Test: webhook receivers (validate signature?), third-party SSO (validate issuer/audience?), payment callbacks (signed?), shipping/address integrations, external identity providers, OAuth token introspection.

## API Versioning Exploitation Matrix

Old versions linger after new versions ship and rarely get security patches.

| # | Technique | Test | Signal |
|---|-----------|------|--------|
| 1 | Path version swap | `/v2/users/me` -> `/v1/users/me` | 200 OK on deprecated version with weaker auth or extra fields |
| 2 | Header version injection | `Accept: application/vnd.api.v1+json`, `Api-Version: 1` | Server respects version header over URL path |
| 3 | Beta/internal prefixes | `/beta/`, `/internal/`, `/staging/`, `/canary/` | Unreleased endpoints with incomplete auth |
| 4 | Query param override | `?version=1`, `?api_version=2019-01-01` (Stripe-style) | Downgrades to old behavior with known vulns |
| 5 | Subdomain variants | `api-v1.target.com`, `legacy-api.target.com` | Entire old API stack still running |
| 6 | Mobile-specific versions | `/mobile/v1/`, `/app/api/` | Parallel API with different auth checks |
| 7 | Old Swagger spec retrieval | Wayback Machine: `web.archive.org/*/api.target.com/swagger*` | Reveals endpoints removed from current docs but still live |
| 8 | Mixed-version request | v2 auth token against v1 endpoint | v1 trusts v2 token but skips v2 permission checks |

## Batch/Bulk Endpoint Abuse

Batch endpoints process multiple operations per HTTP request. Auth and rate limits are often enforced per-request, not per-operation.

| # | Technique | Payload Shape | What Breaks |
|---|-----------|---------------|-------------|
| 1 | GraphQL alias batching | `{ a1: deleteUser(id:1) { ok } a2: deleteUser(id:2) { ok } }` | Rate limit counts 1 request; 75+ mutations execute |
| 2 | JSON-RPC batch | `[{"method":"transfer","params":{"to":"X","amt":100}}, ...]` | Per-item auth skipped; one bad item poisons response |
| 3 | Array body on REST | `POST /api/users [{"role":"admin"},{"role":"admin"}]` | Framework binds each item without per-item field check |
| 4 | Bulk import/CSV | Upload CSV with 10k rows containing injected fields | Import pipeline skips field-level validation |
| 5 | Batch ID lookup | `GET /api/users?ids[]=1&ids[]=2&ids[]=999` | Returns objects caller cannot access individually |
| 6 | ORM array coercion | `?token[]=a&token[]=b` (Rails `find_by` -> SQL `IN`) | Tests N secret tokens per request; bypasses rate limit on attempts |
| 7 | GraphQL named-op batching | Multiple named operations in one document | Turbo Intruder + 75 ops/request = 7500+ ops in 40 seconds |

## Alternate API Surface Exploitation

The same resource often has multiple API surfaces with inconsistent authorization. ($1.5M Google VRP: Apps Script API leaked editors that UI/REST hid.)

| # | Pattern | Example | What Leaks |
|---|---------|---------|------------|
| 1 | UI vs raw API | UI hides field; API returns full model | Sensitive fields (SSN, tokens, internal notes) |
| 2 | REST vs GraphQL | REST endpoint locked; GraphQL query on same type open | Same data via different transport |
| 3 | RPC bridge services | `clients6.google.com` proxies internal RPCs | Internal support data, agent PII, operational metadata |
| 4 | Apps Script / SDK | Server-side SDK for same resource | Editor lists, owner info, internal metadata |
| 5 | Export/print/PDF | New export feature on existing model | Full model serialized without visibility filter |
| 6 | Slash commands / mentions | `/move <project>` resolves cross-tenant reference | Target model in validation response (runners_token) |
| 7 | Webhook/callback response | Webhook fires on event; response body unfiltered | Internal object state, internal IDs, timestamps |
| 8 | GCR-over-GCS (layered API) | Higher-layer API ignores lower-layer scope check | Write access despite read-only OAuth scope ($500K Google VRP) |

## Transitional Auth Flow Hunting

Step-up, recovery, and challenge flows sit between unauth and authed state. Engineers reason the user "almost" has a session and ship endpoints that trust a token alone.

| # | Flow Type | What to Test | $15K PayPal Pattern |
|---|-----------|-------------|---------------------|
| 1 | Password reset | Token-only endpoint without session binding | Endpoint returns email + plaintext password |
| 2 | MFA setup | QR code / TOTP secret in response without re-auth | TOTP secret leaks via unauthenticated XHR |
| 3 | Step-up challenge | Drop session cookie, keep only challenge token | Full profile data in response |
| 4 | Account merge/link | Social-login binding token replayable cross-user | Link attacker's social to victim's account |
| 5 | Email confirmation | Token in URL enumerable or batchable | Array coercion on token param (see Batch section) |
| 6 | Invitation preview | Pre-auth preview of shared resource | Private report title, doc content, team metadata |
| 7 | Device registration | Device trust token without user binding | Attacker's device becomes trusted for victim |

Test matrix per endpoint: no auth, partial auth (token only), stale token, replayed token, cross-user token.

## Meta-Resource IDOR

IDOR hunting typically targets data objects. Meta-resources (config, scope, settings, permissions) are consistently underexplored but equally vulnerable. ($12.5K H1: cross-tenant scope archive. $50K Google: cross-org master-API-key creation.)

| # | Meta-Resource | IDOR Primitive | Impact |
|---|---------------|----------------|--------|
| 1 | Program/project scope | Archive/unarchive foreign scope | Break program operations |
| 2 | Feature flags | Create/toggle flags on foreign org | Enable/disable features for victims |
| 3 | API keys / tokens | Create master-API-key in foreign org | Full administrative access |
| 4 | Team membership | Add/remove members in foreign team | Privilege escalation via team join |
| 5 | Webhook config | Register webhook on foreign project | Exfiltrate all events to attacker |
| 6 | Notification settings | Modify notification targets for foreign user | Redirect alerts to attacker |
| 7 | Export/backup config | Trigger export of foreign project data | Full data exfiltration |

For every "manage" UI action (archive, delete, hide, rename, configure, add-member), capture the request and test cross-tenant ID substitution.

## Defense-Bypass Pairs

| # | Defense | Bypass | Technique |
|---|---------|--------|-----------|
| 1 | Rate limit per IP | `X-Forwarded-For` / `X-Real-IP` rotation | Inject `X-Forwarded-For: {random_ip}` per request |
| 2 | Rate limit per request | Batch/array parameter coercion | `?token[]=a&token[]=b` — N attempts per request |
| 3 | CORS allowlist | Subdomain wildcard + XSS on any subdomain | `*.target.com` + XSS on `blog.target.com` |
| 4 | CSRF token | Cross-site WebSocket hijacking | WS handshake doesn't check Origin |
| 5 | JSON-only Content-Type | Send as `text/plain` or `application/xml` | Some frameworks parse body regardless of CT header |
| 6 | Field mask / projection | Undocumented boolean flag (`includeSuspended`) | Flag overrides mask; leaks protected fields ($1.3M Google VRP) |
| 7 | updateMask / FieldMask | `PATCH ?updateMask=status` on Google APIs | Self-promote status from PENDING to APPROVED ($50K) |
| 8 | Label/approval gate | Auto-label bot triggered by PR title regex | Bypass human-approval gate via automated label assignment |
| 9 | OAuth scope restriction | Access via layered API (GCR over GCS) | Higher-layer API ignores lower-layer scope |
| 10 | Per-endpoint auth | Sibling endpoint with same param, weaker check | `GetOrCreateSession` leaks ID; `CreateSession` uses it (two-IDOR chain) |

## Chain Patterns

High-bounty API bugs are almost always chains. Memorize these compound patterns.

| # | Chain | Bounty Signal | Steps |
|---|-------|---------------|-------|
| 1 | BOLA + BFLA | Escalate role via BFLA, then BOLA unrelated accounts | 1. Mass-assign role to admin 2. Access all accounts |
| 2 | Excessive exposure + SSRF | Leak internal URL from API response, SSRF to it | 1. API returns internal service URL 2. Fetch metadata via that URL |
| 3 | Deprecated version + missing auth | v1 endpoint lacks auth fix shipped in v2 | 1. Find v1 via Wayback 2. Replay without auth |
| 4 | Field mask bypass + cross-API replay | Leak internal ID via flag override, replay to weaker API | 1. `includeSuspended=true` leaks contentOwnerId 2. Query Content ID API for email ($1.3M) |
| 5 | Import deserialization + privilege escalation | Inject admin-only attribute via project import | 1. Export project 2. Set `template:true` in JSON 3. Re-import -> instance-wide escalation |
| 6 | IDOR leak + IDOR use (two-IDOR) | First IDOR leaks identifier, second uses it | 1. `GetOrCreate` leaks versionId 2. `CreateSession` forks private notebook ($50K) |
| 7 | Rate limit bypass + token brute force | Batch coercion amortizes token guessing by 100Kx | 1. `?token[]=a&token[]=b...` 2. IN-clause checks all; silent in logs |
| 8 | New feature + old model | Export/print bypasses per-field visibility filter | 1. Feature added 2. Uses raw model serialization 3. Hidden comments leak ($10K) |
| 9 | Webhook SSRF + AWS metadata | Webhook URL fetches cloud metadata | 1. Set webhook to `169.254.169.254` 2. Harvest IAM creds 3. Pivot to S3/internal |
| 10 | Auto-label + pwn-request | Automated label satisfies CI gate | 1. PR title triggers auto-label 2. Workflow runs attacker code 3. Token exfil ($10K) |

## Per-Endpoint Methodology

For every endpoint (see `js_analysis.md` for discovery):

1. **Auth scope** — unauth? User session? API key? Service-to-service?
2. **Object ownership (API1)** — test cross-account access
3. **Function scope (API5)** — replay with lower-privileged token
4. **Request body tampering (API3)** — add every conceivable hidden field
5. **Rate / scale (API4, API6)** — how fast can you call it?
6. **Error surface (API8)** — malformed JSON, wrong Content-Type, huge bodies
7. **Alternate endpoints (API9)** — is there a v1 / internal / debug version?
8. **Alternate surfaces** — same resource via GraphQL, SDK, export, slash-command?
9. **Meta-resource** — does this endpoint manage config/scope/permissions? Cross-tenant test.
10. **Batch capability** — does it accept arrays, bulk bodies, or GraphQL aliases?

## Key Commands

```bash
# Enumerate API paths
gau target.com | grep -E "/api/|/v[0-9]+/|graphql|rest/" | sort -u > api_urls.txt

# Pull every Swagger / OpenAPI spec
for p in swagger.json openapi.json openapi.yaml api-docs swagger.yaml v2/api-docs; do
  curl -s "https://target.com/$p" -o "spec_$(basename $p).txt"
done

# GraphQL introspection
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name type{name}}}}}"}'

# Mass assignment probe — dump current object, re-PUT with guessed fields
curl -s -b cookies "https://target.com/api/users/me" | \
  jq '. + {role:"admin",is_admin:true,org_id:1}' | \
  curl -X PUT "https://target.com/api/users/me" -b cookies \
    -H "Content-Type: application/json" -d @-

# BFLA — replay admin call with lower-priv token
while read url; do
  curl -s -o /dev/null -w "%{http_code} $url\n" \
    -H "Authorization: Bearer $LOW_PRIV" "$url"
done < admin_endpoints.txt

# Version probing — test v1 through v5 of every endpoint
while read url; do
  for v in v1 v2 v3 v4 v5 beta internal; do
    test_url=$(echo "$url" | sed "s|/v[0-9]*/|/$v/|")
    code=$(curl -s -o /dev/null -w "%{http_code}" -b cookies "$test_url")
    [ "$code" != "404" ] && echo "$code $test_url"
  done
done < api_urls.txt

# Debug endpoint scan
for ep in actuator actuator/env actuator/configprops debug/pprof \
  debug/pprof/cmdline _debug trace metrics healthz config .env; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$ep")
  [ "$code" != "404" ] && echo "$code /$ep"
done
```

## Tooling

| Need | Tool |
|------|------|
| API enumeration | `apkleaks`, `SecretFinder` on mobile apps |
| Automated fuzzing | `ffuf` with API wordlist, `restler-fuzzer` |
| OpenAPI replay | `apicheck`, `schemathesis` |
| GraphQL | `graphql-voyager`, `InQL`, `graphw00f` |
| Traffic capture | Caido, Burp |
| Mobile API capture | `mitmproxy` + `frida` |
| gRPC | `grpcurl`, `grpc_cli` |
| Batch attack | Turbo Intruder (Burp), `requests` with HTTP/2 |

## Tips

1. The mobile app is often the best API source — intercept via Frida / mitmproxy; mobile often calls endpoints the web UI doesn't
2. Chain BOLA x BFLA — escalate role via BFLA, then BOLA unrelated accounts via the new role
3. Test EACH HTTP verb on EACH endpoint — GET may be authorized, PATCH may not
4. Mass assignment trick: dump `/api/users/me`, add `role:admin`, re-PUT
5. Find API versioning — v1 lingers after v2 ships and rarely gets security patches
6. SSO / webhook signature checks — spoof the header, remove the signature (many accept unsigned as "legacy")
7. GraphQL requires different rules — see `graphql_attacks.md` for nested queries, batching, introspection bypass
8. Report sensitivity — BOLA with real user PII is instant Critical; don't exfil beyond proof-of-concept
9. Test every "we'll call your URL" feature for SSRF — webhooks, import-from-URL, image proxy, link unfurl, OAuth callbacks
10. New feature = new serializer. When a target ships export/print/PDF/API-v2, immediately test it against the most sensitive resource state
11. Alternate surfaces for the same resource (SDK, GraphQL, RPC bridge, export) almost never enforce identical authorization — test each independently
12. Pre-auth preview endpoints (invitation accept, share preview, challenge flow) leak the most data — test them with no session, token-only, and cross-user token

## Cross-References

- `idor.md` — deeper BOLA / IDOR patterns
- `authentication_jwt.md` — JWT attack surface (API2)
- `broken_function_level_authorization.md` — BFLA deep dive (API5)
- `mass_assignment.md` — mass assignment + excessive exposure (API3)
- `ssrf.md` — API7 methodology
- `rate_limiting_bypass.md` — API4 + rate limit bypass techniques
- `graphql_attacks.md` — GraphQL-specific variants (introspection, batching, DoS)
- `js_analysis.md` — endpoint discovery from frontend bundles
