---
name: trust-boundary-mapping
category: methodology
description: Systematic inter-system boundary auditing — find bugs at the seams where two components meet and their assumptions diverge
depends_on: []
---

# Trust Boundary Mapping

Bugs live at seams. When two systems meet — gateway and backend, CDN and origin, auth provider and app, queue and consumer — each makes assumptions the other does not enforce. Audit each system alone and you see nothing. Audit the boundary and you find account takeovers, auth bypasses, and cache poisoning chains.

This skill maps every inter-system boundary, identifies assumption divergence, and generates structural hypotheses for the root agent to dispatch.

## Output Contract

Append one JSON object per line to `target/boundary_map.jsonl`:

```json
{
  "input_source": "<HTTP-method> <path> <component (body|header|query|cookie|...)>",
  "boundary": "<system_A> -> <system_B> [-> <downstream>]",
  "sink": "<effect: persistence, trigger, propagation, response leak, routing decision>",
  "missing_check": "<auth | authz | schema | rate-limit | rebinding | normalization | verification>",
  "hypothesis": "<one-sentence structural prediction>",
  "evidence_paths": ["<artifact-derived observation>", "..."],
  "predicted_severity": "<critical | high | medium | low>",
  "test_brief": "<HTTP-shape test with parameter placeholders, no industry vocabulary>"
}
```

## Discovery Signals

Scan recon artifacts for these signals before mapping boundaries. Each signal reveals a seam.

| Signal | Where to Find | Why It Reveals a Boundary |
|---|---|---|
| `X-Forwarded-For`, `X-Real-IP`, `X-Original-URL` headers in responses | HAR captures, response headers | Backend trusts proxy-injected headers for security decisions (IP ACL, auth routing) |
| Different `Server` headers across subdomains | Recon subdomain scan, response fingerprinting | Multiple server technologies = multiple parsers with normalization divergence |
| CDN fingerprints (Cloudflare `cf-ray`, Akamai `x-akamai-*`, Fastly `x-served-by`) | Response headers, DNS CNAME | Caching layer creates cache-key vs origin-key disagreements |
| OAuth/OIDC redirect flows (`/authorize`, `/callback`, `/token`) | HAR captures, JS analysis | Auth provider and app disagree on what constitutes verified identity |
| Webhook registration endpoints | API docs, HAR captures, JS bundle strings | Inbound webhook = untrusted external system controlling internal state |
| AWS/GCP/Azure SDK signatures in JS bundles or errors | JS analysis, error messages | Direct cloud API access bypasses app-layer restrictions (Cognito, S3, Lambda) |
| GraphQL introspection or multiple API gateway paths (`/api/v1`, `/api/v2`, `/graphql`) | Endpoint enumeration | Version/gateway routing = parser differential between gateway and handler |
| `Content-Type` mismatches between request and processing | HAR captures (send JSON, receive XML error; send form, processed as JSON) | Parser selection divergence between proxy/WAF and backend |
| Internal service names in error messages (`upstream connect error`, `service unavailable: user-svc`) | Error responses, 502/503 pages | Leaks microservice topology for service-to-service boundary attacks |
| Message queue indicators (`x-amzn-requestid`, SQS/SNS ARNs, Kafka topic names in errors) | Response headers, error messages | Async boundary = deserialization trust gap + replay surface |
| Cookie domain scope mismatches (`.example.com` vs `app.example.com`) | HAR cookie headers, `Set-Cookie` attributes | Cookie set at parent domain is trusted by all subdomains including attacker-controlled ones |
| Multiple authentication mechanisms on same endpoint (cookie + bearer + API key) | HAR request headers, 401/403 responses | Auth fallback chains create precedence confusion and bypass paths |

## Boundary Type Matrix

Each row is a real boundary class. The "Divergence" column is the structural gap; "Bug Class" is what you file.

| System A | System B | Common Divergence | Bug Class | Test Technique |
|---|---|---|---|---|
| API gateway/proxy | Backend server | Path normalization: gateway decodes `%2F`, backend does not (or vice versa) | Auth bypass, path traversal | Send `GET /public/..%2Fprivate/secret` — if gateway routes to `/public/` but backend resolves to `/private/secret` |
| CDN/cache | Origin server | Cache key excludes headers/cookies that origin uses for content selection | Cache poisoning, cache deception | Fuzz unkeyed headers (`X-Forwarded-Host`, `X-Original-URL`, `Authorization: garbage`) on cached endpoints |
| Auth provider (Cognito/Auth0/Okta) | Application | Provider allows attribute changes (email, phone) that app UI restricts | Account takeover | Call provider API directly with user access token: `update-user-attributes` to change email, check if app respects `email_verified=false` |
| Reverse proxy (nginx) | Upstream app | Proxy honors upstream response headers (`X-Accel-Redirect`, `X-Sendfile`) from untrusted app | SSRF to internal routes | Control upstream response (webhook, app proxy, integration) and return `X-Accel-Redirect: /internal-only-path` |
| WAF/IDS | Backend | WAF validates request body with one parser; backend processes with another | WAF bypass → SQLi/XSS/RCE | JSON-in-multipart, chunked encoding, Unicode escapes, null bytes in parameter names |
| Message queue producer | Consumer service | Producer serializes untrusted user input; consumer deserializes without validation | Deserialization RCE, injection | If queue message format is visible (SQS body, Kafka topic), inject serialized payloads matching consumer's expected format |
| Payment processor | Application | Processor sends webhook with amount/currency/status; app trusts without HMAC verification | Payment bypass, double-spend | Replay captured webhook with modified `amount=0.01` or `status=paid`; check if app verifies webhook signature |
| Database | Application | DB truncates at column width, app validates at different length; collation folds characters | Truncation attacks, collation bypass | Register `admin   x` (spaces + padding to column width) → DB truncates to `admin`, collides with real admin |
| Cloud function trigger | Function handler | Event source not verified; function trusts event payload as authoritative | Privilege escalation, data injection | Invoke function directly with crafted event payload bypassing the expected trigger (API Gateway, S3, SNS) |
| Frontend SPA | Backend API | Frontend enforces field visibility/editability; API accepts any field in request body | Mass assignment, privilege escalation | Send raw API request including fields hidden in UI (`role`, `is_admin`, `price`, `verified`) |

## Header Trust Chain

Headers cross boundaries. Each hop may add, modify, or trust headers set by the previous hop. Attack the chain.

| Header | Typically Set By | Trusted By | Attack | Impact |
|---|---|---|---|---|
| `X-Forwarded-For` | Load balancer, CDN, proxy | Backend for IP-based ACL, rate limiting, geo-blocking | Spoof header from client: `X-Forwarded-For: 127.0.0.1` | Bypass IP allowlist, rate limit evasion, admin panel access |
| `X-Forwarded-Host` / `Host` | Client, proxy | Backend for link generation, password reset URLs, virtual host routing | Send `Host: attacker.com` | Password reset poisoning, cache key confusion, virtual host routing to internal apps |
| `X-Original-URL` / `X-Rewrite-URL` | Reverse proxy (IIS, nginx) | Backend for routing decisions | Inject header from client: `X-Original-URL: /admin` | Bypass front-end path-based access controls entirely |
| `X-Forwarded-Proto` | Load balancer | Backend for redirect generation, HSTS decisions | Spoof `X-Forwarded-Proto: http` to force HTTP redirects | Redirect loop, mixed content, cookie without Secure flag |
| `X-Accel-Redirect` | Trusted upstream app | nginx reverse proxy | Return header from attacker-controlled upstream (webhook, app proxy) | SSRF to nginx `internal` locations — health checks, admin, internal APIs |
| `Authorization` | Client | Backend AND cache layer | Send `Authorization: garbage` to cache endpoint | Cache poisoning if CDN treats `Authorization` presence as cache-bust but origin ignores invalid value |
| `Cookie` (quoted strings) | Browser | Server cookie parser | Set cookie value with unmatched quote: `"value; SESSIONID=stolen` | Cookie smuggling — RFC2965 parser reads across cookie boundaries, leaks HttpOnly values |
| `Content-Type` | Client | WAF (validates), backend (parses) | Send `Content-Type: application/json` but body is `x-www-form-urlencoded` | WAF validates wrong format, backend parses the real one — injection bypasses WAF |
| `Transfer-Encoding` / `Content-Length` | Client | Front-end proxy and backend (differently) | Conflicting `TE: chunked` + `CL: N` headers | HTTP request smuggling — front-end uses one, backend uses the other |
| `X-HTTP-Method-Override` | Client (convention) | Backend framework (Rails, Django, Spring) | Send `POST` with `X-HTTP-Method-Override: DELETE` | Bypass method-based access controls, CSRF token checks, WAF rules |

## Key Vulnerability Patterns

### 1. Parser Differential Exploitation

Two parsers on opposite sides of a boundary interpret the same byte stream differently. This is the single most productive boundary attack class.

**Hunt template** (from cookie smuggling, request smuggling, path traversal chains):
1. Identify the boundary (proxy-backend, browser-server, WAF-app, gateway-microservice)
2. Read both specs the parsers implement — look for deprecated features one side still supports
3. Craft inputs that are valid under both specs but parse to different meanings
4. Test: `..;`, `..%2F`, `%2E%2E/`, `//`, `\..`, null bytes, overlong UTF-8, mixed encoding

**Concrete fuzzing battery for path normalization at proxy-backend boundary:**
```
/public/..%2Fprivate/           # Encoded slash traversal
/public/..;/private/            # Tomcat path parameter confusion
/public/%2e%2e/private/         # Double-encoded dots
/public/./private/../private/   # Dot-segment normalization difference
/public\..\\private\            # Backslash on Windows backends
//private/                      # Double-slash collapse difference
/public;param=value/private/    # Semicolon parameter stripping
/PUBLIC/../../private/          # Case-sensitivity + traversal
```

### 2. Identity Provider Trust Gap

When the app delegates auth to an external IDP, the IDP's API surface is wider than the app's UI surface.

**Audit checklist:**
- Enumerate every IDP API operation (Cognito `UpdateUserAttributes`, Auth0 Management API, Okta User API)
- For each: does the app UI expose this operation? If no, call the IDP API directly with user's access token
- After attribute change: does the app check `email_verified`, `phone_verified`?
- Test identifier normalization collision: IDP stores case-sensitive, app looks up case-insensitive
- Test: register `Victim@email.com` (capital V) at IDP level, app normalizes to `victim@email.com` — collision with real victim

### 3. Cache Key Disagreement

The cache (CDN, Varnish, nginx proxy_cache) and the origin disagree on which request properties determine the response.

**3-step probe:**
1. Identify cached endpoints: responses with `Age`, `X-Cache: HIT`, `CF-Cache-Status: HIT`
2. Fuzz unkeyed inputs: add headers (`X-Forwarded-Host`, `X-Original-URL`), query params, `Authorization: anything`, cookies — if response changes but cache still serves it, you have a poisoning vector
3. Cache deception variant: append `.css` or `.js` to authenticated page URL — if CDN caches based on extension but origin serves the real page, victim's auth data is cached publicly

### 4. Webhook and Callback Verification Gaps

Any inbound webhook from an external system (payment, notification, CI/CD) is an untrusted input masquerading as a trusted internal event.

**Test sequence:**
1. Capture a legitimate webhook payload from HAR or logs
2. Replay to the webhook endpoint without the `X-Signature` / HMAC header — if accepted, no verification
3. Replay with modified payload (change amount, status, user ID) with original signature — if accepted, signature covers different fields than what the app reads
4. Test timing: send webhook before the triggering action completes — race between webhook processing and transaction state
5. Test idempotency: replay same webhook N times — if processed N times, duplicate charge/credit/action

### 5. Controlled-Upstream Response Injection

When the target proxies to an attacker-controlled upstream (app proxy, webhook echo, integration endpoint, OEmbed), test every response header the proxy honors.

| Proxy | Headers to Inject from Upstream | Effect |
|---|---|---|
| nginx | `X-Accel-Redirect`, `X-Accel-Buffering`, `X-Accel-Charset` | Internal redirect SSRF, response manipulation |
| Apache | `X-Sendfile` (if mod_xsendfile enabled) | Arbitrary file read from server filesystem |
| Any | `Set-Cookie`, `Cache-Control: public`, `Vary` manipulation | Cookie injection, cache poisoning, response splitting |
| Any | `Content-Type: text/html` with XSS payload body | Stored XSS via proxy reflection |

## Bypass Techniques

| Boundary Control | Bypass | Mechanism |
|---|---|---|
| IP allowlist via `X-Forwarded-For` | Add/prepend spoofed IP in header | Backend parses first or last value depending on implementation |
| Path-based auth at proxy | `..%2F`, `..;`, double-encoding | Proxy normalizes differently than backend; auth check sees `/public/`, backend resolves `/private/` |
| HMAC webhook signature | Replay with empty body + valid signature of empty body | Some HMAC implementations sign request body; empty body has a valid signature too |
| WAF blocking SQL injection | Switch `Content-Type` to `application/json` with SQL in JSON value | WAF only inspects form-encoded parameters, ignores JSON body |
| Cookie `HttpOnly` flag | Cookie smuggling via unmatched quote in RFC2965 parser | Server parser reads across cookie boundaries, reflects HttpOnly value in page output |
| CORS `Origin` check | `null` origin (sandboxed iframe, data URI) or subdomain takeover | `Access-Control-Allow-Origin: null` or wildcard subdomain match `*.example.com` |
| Rate limiting per IP | Rotate via `X-Forwarded-For` spoofing or IPv6 rotation | Rate limiter trusts proxy header; attacker sends new IP per request |
| CSP `script-src` | Subdomain takeover on CSP-allowed domain, JSONP endpoint, Angular template injection | CSP trusts a domain the attacker now controls |
| JWT signature verification | `alg: none`, `alg: HS256` with public key as HMAC secret, `kid` injection | Library accepts unsigned token or uses wrong key for verification |
| Kubernetes ingress external auth | `%2F`-encoded path traversal in URL | Auth service sees encoded path (prefix match passes), nginx routes decoded path (traversal resolves) |
| IDP email verification | Call IDP API directly to change email, skip verification | App checks auth but not `email_verified=false` flag from IDP response |
| API versioning access control | Request old API version that lacks new auth checks | `/api/v1/resource` still accessible after auth was added only to `/api/v2/resource` |

## Testing Methodology

### Phase 1: Boundary Discovery (read-only)

1. **Map the stack**: From HAR captures and response headers, identify every system in the request path (CDN, WAF, load balancer, API gateway, app server, database, cache, queue, external APIs)
2. **Identify controlled upstreams**: List every feature where user-controlled data becomes an upstream URL or response (webhooks, integrations, app proxies, OEmbed, URL preview)
3. **Extract header trust chain**: For each request, note which headers are set by infrastructure vs client-controllable
4. **Catalog auth boundaries**: Map every point where identity crosses systems (session cookie to API token, OAuth code to access token, JWT across microservices, IDP to app)

### Phase 2: Divergence Probing

For each boundary identified in Phase 1:
1. **Path normalization differential**: Send the fuzzing battery (section above) and compare what the front-end sees vs what the back-end processes
2. **Header trust audit**: For every `X-*` header in the trust chain, send it from the client — does the backend honor it?
3. **Content-Type confusion**: Send requests where Content-Type header disagrees with actual body format
4. **Auth provider API surface**: If external IDP detected, attempt direct API calls with user token
5. **Cache key probing**: On CDN-fronted endpoints, use Param Miner or manual header fuzzing to find unkeyed inputs

### Phase 3: Exploitation Chaining

Once a boundary divergence is confirmed:
1. **Assess postcondition**: What state does this divergence create? (Request to wrong backend, cached malicious response, identity confusion, unsigned webhook accepted)
2. **Map to chain targets**: Use the Chain Patterns table below to identify what this postcondition enables
3. **Build minimum viable PoC**: Demonstrate the full chain from boundary divergence to impact

## Chain Patterns

Boundary bugs compound. A single boundary divergence is often Medium; chained with a second boundary it becomes Critical.

| Chain | Steps | Typical Severity | Example |
|---|---|---|---|
| Path normalization → auth bypass → data access | 1. Encoded traversal bypasses gateway auth 2. Backend resolves to protected endpoint 3. Read/write sensitive data | Critical | nginx `%2F`-encoded path bypasses K8s external auth, routes to protected service |
| Cache poisoning → stored XSS → session theft | 1. Unkeyed header injects malicious content 2. CDN caches poisoned response 3. Victim loads cached page, JS executes | High-Critical | `X-Forwarded-Host` unkeyed, injected into `<base>` tag, CDN caches for all visitors |
| IDP attribute change → email collision → account takeover | 1. Call IDP API to change email to victim's (case variant) 2. App normalizes email case-insensitively 3. Login as attacker with victim's identity | Critical | Cognito `update-user-attributes` + Flickr case-insensitive email lookup |
| JWT leak → header trust → impersonation | 1. Extract internal JWT via path traversal 2. Use JWT to authenticate to internal service 3. Spoof identity header trusted by downstream | Critical | GitLab Workhorse JWT leak + Geo `Geo-GL-Id` header trust → push as any user |
| Webhook replay → payment bypass | 1. Capture webhook 2. Modify amount/status 3. Replay without signature check | High | Payment processor webhook accepted without HMAC verification, order marked as paid |
| Cookie smuggling → HttpOnly leak → session hijack | 1. Inject unmatched quote in non-HttpOnly cookie 2. RFC2965 parser reads across boundary 3. HttpOnly session token reflected in page | High | Jetty/Undertow quoted-string parsing leaks `JSESSIONID` via cookie value reflection |
| Subdomain takeover → cookie scope → session fixation | 1. Claim dangling subdomain 2. Set cookie on parent `.example.com` domain 3. Cookie sent to all subdomains including main app | High | Dangling CNAME on `old.example.com`, set session cookie scoped to `.example.com` |
| SSRF → cloud metadata → credential theft → lateral movement | 1. SSRF via integration URL (webhook, proxy) 2. Hit `169.254.169.254` 3. Extract IAM credentials 4. Access S3/RDS/internal APIs | Critical | Custom integration URL field → SSRF → AWS metadata → RDS credentials |
| Content-Type confusion → WAF bypass → injection | 1. Send SQL payload in JSON body 2. WAF only inspects form-encoded 3. Backend parses JSON, executes query | High | `Content-Type: application/json` with `{"search": "' OR 1=1--"}` bypasses form-param WAF rules |
| Parameter pollution → auth confusion → privilege escalation | 1. Duplicate parameter: `?role=user&role=admin` 2. Auth check reads first value 3. Backend uses last value | High | HPP where proxy/gateway takes first param, app framework takes last |
| Open redirect on trusted domain → OAuth token theft | 1. Find open redirect on app domain 2. Set as OAuth `redirect_uri` 3. Auth code or token sent to attacker-controlled destination via redirect | Critical | Open redirect on domain in OAuth allowlist → auth code interception |
| Deserialization via queue → RCE on consumer | 1. Inject crafted serialized object into queue message 2. Consumer deserializes without class allowlist 3. Gadget chain triggers code execution | Critical | Influence queue message content (via API that writes to queue) → consumer pops and deserializes |

## High-Value Boundary Targets

When time-constrained, prioritize these boundary surfaces. Ordered by historical payout density from corpus analysis.

| Priority | Boundary Surface | Why High-Value | First Test |
|---|---|---|---|
| 1 | Auth provider API vs app UI restrictions | Full ATO chains; IDP always exposes more than the UI | Call IDP API directly with user token to change email/phone |
| 2 | CDN/cache layer vs origin content selection | Mass impact (all visitors served poisoned page) | Fuzz unkeyed headers on cached endpoints |
| 3 | Proxy/gateway vs backend path normalization | Auth bypass with one request, no interaction needed | Send `..%2F` encoded traversal through proxy |
| 4 | Webhook/callback inbound from external service | Payment bypass, state manipulation; often no HMAC check | Replay captured webhook without signature header |
| 5 | Controlled upstream via integration/proxy feature | SSRF to internal routes; one header controls nginx routing | Return `X-Accel-Redirect: /internal` from controlled upstream |
| 6 | Cross-subdomain cookie scope | Session fixation at scale via dangling subdomain | Check `Set-Cookie` domain scope; look for takeable subdomains |
| 7 | Frontend-enforced field restrictions vs API | Mass assignment; UI hides fields API still accepts | Send hidden fields (`role`, `verified`, `price`) directly to API |
| 8 | Multi-parser request handling (WAF vs backend) | WAF bypass to injection; structural and repeatable | Switch Content-Type between form-encoded and JSON with same payload |

## Pro Tips

- **"What does the provider allow that the consumer restricts?"** — This single question finds IDP bypasses, cloud API bypasses, and any feature-as-SSRF pattern. Every external service the app integrates with has an API surface wider than what the app UI exposes.
- **Test the header, not the feature** — Do not just test the visible functionality. Inject every `X-*` header from the client. Headers "expected" to come from infrastructure (`X-Forwarded-For`, `X-Real-IP`, `X-Original-URL`) are often not stripped by the proxy, making them client-controllable.
- **Parser differentials are structural, not one-offs** — If you find one normalization divergence between proxy and backend, there are almost certainly more. Enumerate all encoding variants systematically: `%2F`, `%2E`, `%5C`, `%00`, overlong UTF-8, double-encoding.
- **Empty-body edge cases break HMAC** — Many HMAC webhook implementations have a valid signature for an empty body (HMAC of empty string). Test replay with `body={}` or `body=""` and the corresponding valid signature.
- **Cookie ordering is exploitable** — Browsers send cookies ordered by path-length (longest first) then age (oldest first). If you can set a cookie at a longer path, your value wins in servers that take the first match.
- **Cache-bust headers on cached endpoints** — Adding `Authorization: anything` to a cached endpoint sometimes makes the CDN pass-through to origin while still caching the response. Test `Authorization: garbage`, `Pragma: akamai-x-cache-on`, `X-Forwarded-Host: evil.com`.
- **Controlled upstreams are everywhere** — Webhooks, app proxies, OEmbed endpoints, URL previews, integration callbacks. Any feature that fetches a user-supplied URL and processes the response is a controlled-upstream primitive. Test what the proxy does with the response headers.
- **Deserialization across async boundaries is always suspect** — If a message queue sits between producer and consumer, the consumer almost never validates the schema of what it deserializes. If you can influence what goes into the queue, you control what comes out.

## Boundary Anti-Patterns (Code Smells)

When reviewing source or observing behavior, these patterns indicate a missing boundary check:

| Anti-Pattern | Signal | Likely Bug |
|---|---|---|
| `request.headers['X-Forwarded-For']` used in `if` statement | IP-based security decision trusting client-controllable header | Auth bypass, rate limit evasion |
| `email.lower()` at app layer but IDP stores case-sensitive | Identity lookup normalization mismatch | Account takeover via email collision |
| `proxy_pass` without `proxy_ignore_headers X-Accel-Redirect` | nginx trusts upstream response headers unconditionally | SSRF to internal locations |
| Webhook handler with no HMAC/signature verification | Inbound event accepted from any source | Payment bypass, state manipulation |
| `JSON.parse(body)` after WAF validated `application/x-www-form-urlencoded` | Content-Type vs actual body format mismatch | WAF bypass to injection |
| `jwt.decode(token)` without explicit algorithm parameter | Library may accept `alg: none` or algorithm confusion | Authentication bypass |
| Query parameter used in both auth check and data fetch without canonicalization | Same parameter parsed differently by two components | IDOR, auth bypass via HPP |

## Hard Rules

- DO NOT test exploits. You enumerate boundaries; root dispatches workers to test them.
- Be exhaustive — every input source x every sink — even ones that look obviously safe.
- Flag any boundary where you cannot determine the check. Root will dispatch a worker to verify.
- DO NOT include any industry vocabulary in `test_brief`. Use parameter placeholders (`<sensitive_workflow_event>`, `<victim_id>`, `<high_trust_field>`) regardless of the target's industry.

## Inputs to Read

- HAR captures: `target/ACTIVE/HAR/`
- JS analysis (if present): `target/ACTIVE/JS/`
- Endpoint rankings (if present): `target/ranked_endpoints.jsonl`
- Recon summary: `target/recon_summary.md` (or equivalent)

## Termination Criterion

Run until either:
- Every endpoint in `ranked_endpoints.jsonl` (top-N=30) has been considered as both an input source AND as a sink, OR
- 60 minutes of analysis time elapses (whichever comes first).

Submit `boundary_map.jsonl` and call `agent_finish`.
