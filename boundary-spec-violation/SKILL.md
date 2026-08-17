---
name: boundary-spec-violation
category: methodology
description: Differential testing, spec-compliance auditing, and type-boundary fuzzing — find bugs where implementations diverge from specs, environments diverge from each other, or inputs hit validation edges
depends_on: []
---

# Boundary, Differential & Spec-Compliance Testing

Three complementary attack strategies, one shared principle: **bugs live where
two things that should agree, don't.** Type boundaries (validation edges),
environment differentials (staging vs prod, REST vs GraphQL), and spec-compliance
gaps (implementation vs RFC/docs) are all instances of this.

## When to Use

- After surface discovery produces parameter inventory
- For any endpoint accepting structured input (JSON body, query params, form data)
- When multiple API versions, channels, or environments exist for the same action
- When API docs, RFCs, or spec pages describe behavior you can test against
- Whenever a documented limit or constraint exists in the API spec or UI
- When existing tests focused on attack payloads but not boundary values

## Inputs (all runtime-derived)

- **PARAMETERS** = union of:
  - OpenAPI schema parameter declarations
  - `arjun` parameter discovery results
  - Form fields extracted from frontend JS / HTML
  - Observed parameters in captured traffic
- **TYPE_OF(param)** = OpenAPI declared type | inferred from observed values
- **CONSTRAINTS_OF(param)** = union of:
  - OpenAPI schema fields: `minimum`, `maximum`, `maxLength`, `minLength`, `pattern`, `enum`
  - JS validation rules (extracted from form validators)
  - Server error messages disclosing limits ("must be less than X", "exceeds maximum of Y")
  - Documentation / API docs
- **SURFACES** = all channels for the same action (web, mobile API, GraphQL, REST, gRPC)
- **ENVIRONMENTS** = all reachable environments (prod, staging, dev, canary, beta, internal)
- **SPECS** = applicable RFCs, API docs, OAuth spec, payment processor docs, published limits

---

## Part 1: Type-Specific Boundary Sets (universal, no domain assumptions)

### Integer

```
[-1, 0, 1, MAX_INT, MAX_INT+1, MIN_INT, MIN_INT-1, 2**63, "0x1", "1e10"]
```

Why each:
- `-1`, `MIN_INT` — signed overflow / underflow
- `0` — division by zero, off-by-one boundary
- `MAX_INT+1` — unsigned overflow into negative
- `2**63` — Java/JS Number.MAX_SAFE_INTEGER boundary
- `"0x1"` — hex parsing differential
- `"1e10"` — scientific notation parsing differential

### Decimal / Float

```
[0, 0.0001, -0.0001, 0.5, 1e-308, 1e308, "Infinity", "NaN", "1.5e10"]
```

Why each:
- `0.0001` — sub-cent / sub-unit precision attacks (rounding-based theft)
- `1e-308`, `1e308` — float overflow
- `"Infinity"`, `"NaN"` — string-to-float coercion attacks

### String

```
[empty, "A"*MAX_LEN, "A"*(MAX_LEN+1), null_bytes, "../", control_chars, unicode_homoglyphs]
```

Why each:
- empty — null/empty handling
- MAX_LEN+1 — buffer overflow / length-validation bypass
- null_bytes — string termination attacks
- `"../"` — path traversal in any string field
- unicode_homoglyphs — visually-identical unicode bypassing equality checks

### ID (any parameter shaped like *_id, UUID, slug)

```
[own_id, peer_id, 0, 1, -1, MAX_INT, deleted_id, system_id_1, "00000000-0000-0000-0000-000000000000"]
```

Why each:
- `own_id` — baseline (should succeed)
- `peer_id` (from another principal in credential_inventory) — IDOR
- `0`, `-1` — boundary, often resolves to special record
- `system_id_1` — root account / system user (often ID 1)
- empty UUID — null handling

### Boolean

```
["true", "false", 1, 0, "yes", "no", "TRUE", "FALSE", null, "", "1", "0"]
```

Why each: boolean coercion differs across parsers — some accept "yes"/"no",
others only `true`/`false`, some flip on truthy strings.

### Enum / Choice

```
[each declared value, value_capitalization_variants, value_with_extra_whitespace, value_not_in_set, empty]
```

Why each: enum validation often case-sensitive; some parsers strip whitespace
revealing inconsistencies; "value not in set" sometimes silently accepted.

### Array

```
[empty, [single], [duplicate, duplicate], [null], [type_mismatch], [MAX_SIZE+1 items]]
```

Why each: array-handling bugs — duplicate handling, null entries, size limits.

### Object / Nested JSON

```
[empty, {extra_key: value}, deeply_nested_50_levels, circular_reference_attempt]
```

Why each: extra keys reveal mass assignment; deep nesting reveals parser
exhaustion; circular refs reveal serialization failures.

## Documented-Limit Boundary Test

If `CONSTRAINTS_OF(P)` reveals a documented limit `L`:

```
Test L-1, L, L+1, L*100, L*-1, 2*L
```

Especially:
- The limit boundary itself (L) — off-by-one bugs
- Just over (L+1) — validation skipped for "edge case"
- Massively over (L*100) — sometimes the validation is skipped entirely for absurd values that the dev didn't anticipate
- Negative (L*-1) — sign reversal

## Spec Violation Cases

Beyond boundaries, also test:

- **Type confusion**: send array where string expected, integer where boolean, object where primitive
- **Missing required field**: omit each declared-required parameter
- **Extra unknown fields**: add fields not in schema (mass assignment)
- **Duplicate fields**: same key twice in JSON body
- **Encoding variants**: URL-encoded inside JSON, double-encoded, base64-of-payload-as-string

---

## Part 2: Differential Testing

Same action, two paths. Where behavior differs = bug.

### Discovery Signals

| Signal | Where to Find | Why Vulnerable |
|--------|--------------|----------------|
| Multiple API versions (`/v1/`, `/v2/`) | URL paths, docs, changelogs | v1 often skips auth checks added to v2 |
| Deprecated endpoints still responding | API docs "deprecated" label, 404 vs 200 | Legacy code not updated with new security model |
| GraphQL + REST for same resource | Schema introspection + REST routes | Policy enforced at REST controller, not GraphQL resolver |
| Mobile API + Web API | Proxy traffic from app vs browser | Mobile clients often get weaker validation or extra fields |
| Staging/dev subdomains alive | `staging*`, `dev*`, `qa*`, `internal*` in subdomain enum | Weaker auth, real data, exposed debug tooling |
| Multiple parsers in request chain | `Server` header, error page stack traces | Parser A accepts what parser B rejects = smuggling |
| Feature flags / beta endpoints | JS bundles, `X-Feature-Flag` headers, A/B cookies | Beta paths may bypass established security middleware |
| Parallel codepaths for same logic | Changelog "rewrite" entries, dual implementations | Rewritten path may miss edge cases the original handled |
| OAuth `state` is structured JSON | Base64-decode or URL-decode the state param | Config channel inside anti-CSRF token = controllable input |
| Different Content-Type handling | Same endpoint, `application/json` vs `application/xml` | XML parser may allow XXE; form parser may skip JSON validation |
| Admin panel on alternate subdomain | `admin.*`, `biz.*`, `*-internal.*`, `*-app.*` | IP-trust auth bypassable via `X-Forwarded-For` spoofing |
| Expired SSL on subdomains | cert scan during recon | Abandoned infra with dev tooling (MailDev, phpMyAdmin) exposed |

### Environment Differential Matrix

| Env A | Env B | What Differs | Common Bug Class |
|-------|-------|-------------|-----------------|
| Production | `staging*.domain.com` | Auth config, debug endpoints, exposed admin panels | Unauth access to admin + real data (Shopify #1394982) |
| Production | `dev*.domain.com` | Dev email servers (MailDev/MailHog), weaker CORS | Credential harvest via captured password-reset emails (Automattic #1067547) |
| Production | Internal/VPN host | IP-based auth only, no token check | Header spoof bypass via `X-Forwarded-For` / `X-Real-IP` |
| REST API | GraphQL API | Authorization policy applied at controller vs resolver | Deactivated user reads data via GraphQL (GitLab #1192460) |
| Web client | Mobile API | Input validation strictness, extra params, different auth | Mobile API accepts params web client never sends (IDOR) |
| Current version | Deprecated/v1 API | Newer permission checks missing from legacy code | Deprecated `owners.query` bypasses view policy (Phabricator #1584409) |
| Browser-sent cookie | Server-parsed cookie | RFC6265 vs RFC2965 quoting rules | Cookie smuggling leaks HttpOnly session token (Ankur Sundara research) |
| Frontend URL parser | Backend URL parser | Slash normalization, path-param handling | `..;` traversal through reverse proxy to Tomcat (Informatica #1004007) |
| Primary feature surface | Newly launched feature | Scope/permission enforcement completeness | Scoped token accesses unscoped Project V2 data (GitHub #1711938) |
| Normal OAuth flow | OAuth with crafted `state` | State validation strictness, postMessage targetOrigin | OAuth code theft via `endsWith` bypass (Google #1017031168, $1M) |

### Environment Differential Test Procedure

```
1. Enumerate environments (subdomain brute: staging1-20, qa1-10, dev1-10,
   beta, canary, preview, internal, next, old, legacy + numeric suffixes)
2. For each non-prod env: test /admin/ /debug/ /metrics /graphql without auth;
   try prod creds; check for MailDev(:1080), phpMyAdmin, Kibana, Swagger UI;
   note expired SSL certs (signal of abandoned infra)
3. For each action on 2+ channels: capture on channel A, replay on channel B,
   diff auth checks / validation / response fields / error messages
```

### API Version Differential

| Version | Common Gap | Test Technique |
|---------|-----------|---------------|
| `/api/v1/*` when v2 is current | Missing permission checks, no rate limit, no input validation | Replay v2 requests against v1 path |
| Deprecated methods (marked in docs) | Not updated with security model changes | Call deprecated method, compare auth behavior to replacement |
| GraphQL deprecated fields | Resolver still active, no field-level auth | Query deprecated fields via introspection |
| Legacy REST while GraphQL is primary | REST handlers not maintained | Find REST routes via JS bundles, test auth |
| Beta/preview API versions | Incomplete middleware chain | Use `X-Api-Version` or version header to hit beta handlers |
| Internal API (same host, `/internal/` path) | Relies on network-level access control | Test from external with path traversal / header spoof |
| gRPC alongside REST | gRPC reflection enabled, different auth middleware | Use `grpcurl` to enumerate services, test without auth |
| WebSocket alongside HTTP | Different auth validation on upgrade | Send WS upgrade with expired/missing token |

### Channel Differential Test Procedure

```
For each state-changing action:
1. Identify all channels: REST endpoint, GraphQL mutation, mobile API call, WebSocket message
2. For EACH channel, test:
   a. Authentication: does it require the same token type/scope?
   b. Authorization: does it enforce the same role/permission?
   c. Input validation: does it reject the same invalid inputs?
   d. Rate limiting: does it enforce the same rate limit?
   e. CSRF protection: does it require the same CSRF token?
   f. Response filtering: does it return the same fields?
3. Any divergence in (a)-(f) = finding
```

---

## Part 3: Spec-Compliance Testing

Read the spec. Test the implementation. Divergence = bug.

### Spec Compliance Checklist

| Spec/RFC | Section to Check | Common Violation | Typical Impact |
|----------|-----------------|-----------------|---------------|
| OAuth 2.0 (RFC 6749) | `state` param validation | Missing, partial match, null-byte truncation, case-insensitive | CSRF on OAuth link = ATO (Streamlabs #1046630) |
| OAuth 2.0 (RFC 6749) | `redirect_uri` exact match | Substring match, open redirect on whitelisted page | Auth code theft via post-redirect leak (Facebook ATO series) |
| OAuth 2.0 | Token scope enforcement on new features | New API surface not scope-checked | Scoped token escalation (GitHub #1711938, $20k) |
| HTTP/1.1 (RFC 7230) | `Transfer-Encoding` vs `Content-Length` | Dual headers, tab-delimited TE, obfuscated `chunked` | Request smuggling (Acronis #1063493, Node.js CVEs) |
| HTTP/1.1 (RFC 7230) | Header field parsing (SP, HTAB, CRLF) | Space before colon accepted, bare CR, empty headers | Smuggling and cache poisoning (Google CDN #167211008) |
| RFC 6265 (Cookies) | Cookie name/value validation | Empty name, quoted-string fallback to RFC2965 | Cookie smuggling leaks HttpOnly tokens (Ankur Sundara) |
| RFC 3986 (URIs) | Path normalization | `..;`, `\/\`, `%2f`, double-encoding, backslash | WAF/proxy bypass to restricted paths (Informatica #1004007) |
| OpenAPI / Swagger | Declared vs actual parameters | Undeclared params accepted, declared limits not enforced | Mass assignment, limit bypass |
| CORS spec | `Access-Control-Allow-Origin` | Reflected origin, null origin, regex bypass | Cross-origin data theft |
| CSP spec | Directive enforcement | `unsafe-inline` present, missing `frame-ancestors` | XSS and clickjacking |
| `postMessage` API | `targetOrigin` validation | `endsWith` instead of exact host match, `*` origin | Cross-window data theft (Google #1017031168, $1M) |
| Rate limit docs | Claimed limit vs actual enforcement | Header says 100/min, actual allows 1000/min | Brute force, enumeration |

### OAuth Spec-Compliance Test Checklist

Highest-yield spec to test against. For each OAuth flow on target:

| Parameter | Mutation | What Breaks |
|-----------|---------|-------------|
| `state` | Remove entirely | CSRF if callback still succeeds |
| `state` | Empty string / attacker's own value | Session binding bypass |
| `state` | Append `%00` null byte | C-string truncation match (Streamlabs #1046630) |
| `state` | Case mutation / whitespace / double-encode | Lenient comparator bypass |
| `state` (JSON) | Modify non-CSRF fields (origin, redirect) | Config channel abuse (Google $1M) |
| `redirect_uri` | Add path / subdomain variation / URL-encode | Redirect to attacker domain |
| `redirect_uri` | Use whitelisted page that has open redirect | Post-redirect token leak (Facebook ATO) |
| Token scope | Narrow-scope token against new/beta features | Scope escalation (GitHub #1711938) |
| Token scope | Read-only token for write operations | Permission model gap |

### Parser Differential Test Procedure

When two parsers sit in the request chain (proxy+backend, WAF+app, CDN+origin):

```
1. Identify the two parsers (server headers, error pages, timing)
2. For each ambiguity point, construct input one parser accepts differently:
   - TE: tab-delimited, capitalization variants, trailing garbage after "chunked"
   - CL: duplicate headers, negative, leading zeros, +/- prefix
   - Cookie: quoted values with semicolons, empty names, RFC2965 syntax
   - URL path: ..;, //, \, %2f, %5c, null byte, unicode normalization
   - Host: port variation, duplicate Host, absolute-form URI
3. Detect differential: backend response through proxy, timing diff, leaked error
```

### Documentation-Reality Gap Tests

For each documented constraint, test actual enforcement:

| Documented Claim | Test | Finding If Divergent |
|-----------------|------|---------------------|
| Rate limit: N/min | Send 2x, 5x, 10x documented limit | Brute force / enumeration enabled |
| Permission: "admin only" | Call as regular user / guest | Broken access control |
| Field format: "email only" | Send non-email, special chars | Input validation bypass |
| Size limit: "max 1MB" | Send 2MB, 10MB, 100MB | DoS or upload bypass |
| Auth required | Call without token, expired token | Missing authentication |

---

## Part 4: Chain Patterns

| Chain | Steps | Severity Multiplier |
|-------|-------|-------------------|
| Deprecated endpoint + IDOR | Find v1 endpoint missing authz, swap user IDs | Medium -> High (auth bypass) |
| Staging env + credential reuse | Access staging admin, harvest creds, test on prod | Low -> Critical (prod ATO) |
| GraphQL/REST differential + deactivated user | Deactivated on REST, still active on GraphQL | Low -> High (zombie access) |
| OAuth state bypass + open redirect on redirect_uri | Null-byte state CSRF + post-redirect token leak | Medium -> Critical (full ATO) |
| Parser differential + cache poisoning | Smuggle request to poison CDN cache | Medium -> Critical (mass user impact) |
| Mobile API extra field + privilege escalation | Mobile endpoint returns role field, modify and replay | Medium -> High (privesc) |
| New feature + scoped token escalation | Narrow token accesses new feature without scope check | Low -> High (data breach) |
| Expired cert env + email capture + password reset | Staging MailDev -> capture reset tokens -> admin access | Info -> Critical (RCE chain) |

---

## Part 5: Pro Tips

- **Deprecated != removed.** If docs say "deprecated," assume it is live. Call it.
  Ghost endpoints miss 1-3 years of security patches.
- **New features are under-scoped.** Audit within 6 months of launch. Token scope,
  permission enforcement, and rate limiting are routinely incomplete at ship.
- **OAuth `state` shape tells you everything.** Opaque random = solid. Base64-JSON
  with multiple fields = every field is attacker-controlled. Decode it first.
- **`endsWith`/`startsWith` are not security functions.** Any origin validation using
  string suffix match is bypassable: `https://evil.com/legit.com` passes `endsWith('legit.com')`.
- **Numeric suffix brute.** `staging1-20`, `qa1-10`, `dev1-10`. One misconfigured instance is common.
- **One vuln host = test all siblings.** Infrastructure-level bugs (smuggling, missing
  auth) affect every host behind the same load balancer.
- **Read the changelog before testing.** Diffs tell you what was patched = test case for bypass.
- **Trigger resets on staging.** Exposed MailDev/MailHog (port 1080) + password reset = credential harvest.
- **GraphQL introspection = version diff.** Deprecated fields still resolve, nobody audited
  their auth since deprecation.
- **Cookie smuggling needs two things:** RFC2965 quoted-string parser (JVM: Jetty, Undertow)
  + reflected/rendered cookie value.

## Output Format

For each parameter or surface that produces unexpected behavior:

```
Endpoint: {METHOD} {path}
Parameter: {name}
Type: {declared_type}
Constraint: {documented_limit_or_none}
Test value: {value_sent}
Expected: {validation_or_4xx}
Observed: {actual_response}
Differential: {if applicable — channel A behavior vs channel B behavior}
Spec reference: {if applicable — RFC section or doc URL violated}
Evidence: {request} -> {response_excerpt}
```

## Anti-Patterns

- **Skip parameters not in OpenAPI**: hidden parameters (discovered via arjun)
  are the highest-yield. Always test them.
- **Test only "normal" payloads**: the boundary IS the test. If you're not
  sending MAX_INT or `1e308`, you're not boundary-testing.
- **Hardcode limits**: never hardcode any specific value as the
  expected ceiling. Read constraints from runtime state (OpenAPI,
  error messages, JS validation, response patterns).
- **Skip negative numbers**: any quantity-bearing field that accepts
  a negative value can invert intended semantics (increment instead of
  decrement, grant instead of revoke, add instead of remove, allow
  instead of deny). Always test negative on numeric fields.
- **Test only production**: staging, dev, and beta environments are separate
  attack surfaces with separate security postures. Test all reachable envs.
- **Assume GraphQL enforces REST's auth**: every new API layer must be
  independently tested for authorization. Policy parity between layers is rare.
- **Trust the docs**: documented limits, permissions, and rate limits are claims.
  Verify every claim you can test.

## Composability

This skill composes with:
- `variant_hunting` — once you find a boundary bug on one parameter, test
  the same parameter on sibling endpoints
- `auth_matrix_systematic` — boundary tests stack with auth gaps to produce
  higher-severity chains; channel differentials feed directly into auth matrix
- `negative_testing` — boundary testing IS a flavor of negative testing
- `web2_recon` — subdomain enumeration feeds environment differential testing
- `api_security_hunter` — API version differential testing is a core API audit technique
