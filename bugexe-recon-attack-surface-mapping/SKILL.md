---
name: attack_surface_mapping
category: reconnaissance
description: Systematic target mapping covering tech stack, endpoints, parameters, auth mechanisms, and trust boundaries
depends_on: []
---

# Attack Surface Mapping

Structured enumeration of every entry point, parameter, authentication gate, and trust boundary on the target. The goal is a complete inventory before any exploitation begins.

## When to Use

- Starting a new engagement or bounty target
- Target has multiple subdomains, APIs, or microservices
- You need a prioritized list of what to test first
- Scoping a large application with unknown architecture

## Methodology

### Phase 1: Tech Stack Identification

1. Fingerprint the web server, framework, and language from response headers
2. Check `X-Powered-By`, `Server`, `X-AspNet-Version`, `X-Generator` headers
3. Inspect HTML source for framework signatures (meta generators, CSS/JS paths, comment patterns)
4. Use Wappalyzer-style detection on common library paths (`/static/js/`, `/assets/`, `/vendor/`)
5. Check error pages (force 404, 500) for framework-specific templates

### Phase 2: Endpoint Discovery

1. Crawl the application with katana or a headless browser
2. Parse sitemap.xml, robots.txt for declared paths
3. Check common paths: `/api`, `/admin`, `/debug`, `/health`, `/status`, `/metrics`, `/graphql`
4. Fuzz directories with ffuf using a technology-specific wordlist
5. Extract endpoints from JavaScript files (see js_analysis skill)
6. Check for API documentation: `/swagger`, `/openapi.json`, `/api-docs`, `/redoc`

### Phase 3: Parameter Enumeration

1. For each endpoint, catalog all accepted parameters (query, body, header, cookie)
2. Identify parameter types: IDs (numeric, UUID), filenames, URLs, dates, JSON blobs
3. Note which parameters are reflected in responses (XSS surface)
4. Note which parameters control server-side resource access (SSRF/LFI surface)
5. Note which parameters reference other users or objects (IDOR surface)
6. Check for hidden parameters with tools like Arjun or param-miner

### Phase 4: Authentication Mechanism Analysis

1. Identify auth type: session cookies, JWT, OAuth, API keys, basic auth, SAML
2. Map the full auth flow: login, registration, password reset, MFA, session management
3. Check token storage (cookie flags, localStorage, sessionStorage)
4. Identify privilege levels and role-based access patterns
5. Note any API key or token exposure in URLs, headers, or JavaScript

### Phase 5: Trust Boundary Mapping

1. Identify boundaries between authenticated and unauthenticated zones
2. Map admin vs user vs guest access levels per endpoint
3. Identify cross-origin boundaries (CORS policy, postMessage handlers)
4. Note third-party integrations (payment, auth, storage) as trust boundaries
5. Map internal vs external service boundaries (backend APIs, microservices)

## Key Commands

```bash
# Tech stack fingerprinting via headers
httpx -u https://target.com -title -tech-detect -status-code -content-length -follow-redirects

# Crawl and collect endpoints
katana -u https://target.com -d 3 -jc -kf -ef css,png,jpg,svg -o endpoints.txt

# Directory fuzzing with ffuf
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -o dirs.json -of json

# Parameter discovery
arjun -u https://target.com/api/endpoint -m GET POST

# Extract unique paths from crawl results
cat endpoints.txt | unfurl paths | sort -u > unique_paths.txt
```

## What to Look For

- Endpoints returning different status codes for authenticated vs unauthenticated requests (access control surface)
- Parameters that accept URLs, file paths, or object identifiers (injection surface)
- API versioning inconsistencies (v1 may lack controls added in v2)
- Admin or internal endpoints accessible without proper authentication
- Verbose error messages leaking stack traces, file paths, or database info
- Inconsistent security headers across different application sections
- Third-party services exposing their own attack surface through the target

## Output Format

Document the attack surface as a prioritized inventory:

```
## Target: example.com

### Tech Stack
- Server: nginx/1.21, Backend: Node.js/Express, Frontend: React
- Auth: JWT (RS256), OAuth via Auth0

### High-Priority Endpoints
| Endpoint | Method | Auth | Parameters | Attack Surface |
|----------|--------|------|------------|----------------|
| /api/users/{id} | GET | JWT | id (numeric) | IDOR |
| /api/export | POST | JWT | url, format | SSRF |
| /admin/config | GET | Cookie | - | Auth bypass |

### Trust Boundaries
1. Public -> Authenticated (JWT validation at API gateway)
2. User -> Admin (role claim in JWT, checked per-endpoint)
3. Backend -> S3 (IAM role, no user input in bucket path)
```

---

## Advanced Surface Mapping Techniques

The following techniques extend the core methodology with systematic enumeration patterns from high-value disclosed reports. Standard mapping finds the obvious surfaces; these patterns find the surfaces that pay bounties.

### Multi-Surface Platform Mapping

Large targets expose multiple interaction surfaces beyond the primary web app. Map ALL of them before testing any.

1. **Enumerate every client surface**: web app, mobile app (iOS + Android), browser extension, desktop client, CLI tool, API (REST, GraphQL, gRPC), WebSocket endpoints, webhook receivers
2. **Map per-surface feature parity**: not every surface implements the same features. Create a matrix: feature vs surface vs implementation status. Gaps indicate incomplete access control (feature exists on web but not mobile = mobile API may lack authz checks)
3. **Identify admin/internal tools**: partner portals, developer consoles, admin panels, internal dashboards, support tools. These share backend infrastructure but have distinct (often weaker) access control
4. **Check cross-surface token acceptance**: authenticate via one surface (web), use that token against another surface's API (mobile backend). Shared auth infrastructure means a bug in any surface compromises all surfaces
5. **Map data flow across surfaces**: where does user data enter on Surface A and get rendered on Surface B? Cross-surface data flows are XSS and injection gold because sanitization is often per-surface, not centralized

### Archive and File-Format Processing Surface Identification

Every file parser is a vulnerability surface. Map every file format the target accepts and processes.

1. **Enumerate all upload endpoints**: form uploads, API uploads, drag-and-drop zones, import features, paste handlers, CLI upload commands
2. **Map accepted formats per endpoint**: test each endpoint with different file types and MIME types. Note which formats are parsed vs stored opaquely
3. **Identify server-side processing**: does the server extract archives, resize images, parse XML/SVG, execute macros, render PDFs, convert formats? Each processing step is an attack surface
4. **Map the processing pipeline**: file upload → validation → storage → processing → rendering. At each stage, what code touches the file? What assumptions does it make about content?
5. **Check format confusion**: upload a file with one extension but another format's content. Does the server process based on extension, MIME type, or magic bytes? Mismatches between detection and processing are exploitable

| File Format | Common Processing | Attack Surface |
|-------------|------------------|----------------|
| ZIP/TAR/RAR | Extraction | Path traversal (Zip Slip), symlink following |
| SVG | Rendering | XSS, SSRF (via `<use>`, `<image>`, `<foreignObject>`) |
| XML/XLSX/DOCX | Parsing | XXE, billion laughs DoS |
| PDF | Rendering/conversion | SSRF (via links), JS execution |
| Image (PNG/JPEG) | Resize/thumbnail | ImageMagick RCE, pixel flood DoS |
| Helm/Docker/OCI | Manifest parsing | Command injection, path traversal |

### Exhaustive HTTP Verb and Action Enumeration

Incomplete verb enforcement is one of the most common access control failures. Map EVERY verb against EVERY endpoint.

1. **Build the verb matrix**: for each discovered endpoint, test every HTTP method: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE, CONNECT. Record status codes for each
2. **Check method override headers**: even when the server rejects a verb, test `X-HTTP-Method-Override: DELETE`, `X-Method-Override: PUT`, `_method=PATCH` in the body
3. **Map destructive operations**: enumerate every destructive primitive across the application (delete, archive, unpublish, revoke, transfer, ban, merge). Each destructive operation needs IDOR testing with another user's resource ID
4. **Test PATCH-then-promote patterns**: for multi-step approval workflows (apply -> pending -> approved), enumerate all REST verbs on the pending-state resource. Can you PATCH a pending resource to change its approval status directly?
5. **Enumerate every action per resource**: for REST APIs, the resource noun is obvious but the action space is not. Beyond CRUD, check: export, import, clone, fork, share, transfer, archive, restore, merge, split

### OAuth Scope and Capability Mapping

OAuth clients on multi-product platforms have varying scope grants. Map every client and its capabilities.

1. **Enumerate OAuth clients**: for platforms with multiple first-party clients (Google, Meta, Microsoft, Apple), identify every `client_id` and its associated product
2. **Map scope grants per client**: each client has different scope permissions. A scope available to Client A but not Client B may be requestable by a malicious app mimicking Client A's flow
3. **Test cross-client token usage**: obtain a token from Client A's flow, use it against Client B's API. Check whether scope restrictions are enforced at the API level or only at the OAuth grant level
4. **Check token downscoping gaps**: when a token is issued with broad scopes, can specific scope restrictions be bypassed by using the token against an endpoint that does not check scopes?
5. **Audit `redirect_uri` per client**: each client's registered redirect URIs are an attack surface. Enumerate every redirect_uri host, every postMessage origin, and every cross-window navigation target per client

### GraphQL Introspection and Schema-Driven Testing

GraphQL APIs self-describe their attack surface. Use this to drive systematic enumeration.

1. **Run introspection query**: `{ __schema { types { name fields { name args { name type { name } } } } } }` — if introspection is enabled, you get the complete API schema for free
2. **Map mutation surface**: extract every mutation (state-changing operation). Each mutation is a write-path endpoint equivalent. Prioritize mutations that modify other users' data, change permissions, or handle financial operations
3. **Enumerate input types**: for each mutation, map every argument and its type. Object types with nested fields are parameter injection surfaces. Enum types reveal valid values that constrain fuzzing
4. **Test authorization per field**: GraphQL often has per-resolver authorization. Query the same object as different users — which fields return data vs null? Field-level access control gaps are GraphQL IDORs
5. **Check for disabled-but-present operations**: some schemas expose types/mutations that return errors when called but are still present in the schema. These may be admin-only or feature-flagged — test with elevated tokens
6. **Batch query abuse**: GraphQL allows multiple operations in a single request. Test for rate-limit bypass, authorization confusion, and timing attacks via batched queries

### Intermediate Account State Enumeration

Standard access control testing covers anonymous/user/admin. Real applications have many more states.

1. **Enumerate every account state**: anonymous, registered-unverified, verified, suspended, banned, deactivated, pending-approval, invited-not-accepted, trial-expired, payment-failed, MFA-pending, password-reset-pending
2. **Test access in each state**: for each intermediate state, test access to every authenticated endpoint. Suspended and deactivated accounts frequently retain partial API access
3. **Check state transition side effects**: when an account moves from state A to state B, what permissions change? What data becomes accessible or inaccessible? Are there race conditions in state transitions?
4. **Test post-deletion access**: after account deletion, can you still use cached tokens? Are the user's resources properly orphaned or can another user claim them?
5. **Map organization/team states**: beyond user states, organizations and teams have their own lifecycle (active, suspended, trial, archived). Test access control at the org level for each state

### Parser Differential and Cache Poisoning Surface Mapping

When multiple components parse the same request (CDN, WAF, load balancer, application server), disagreements between parsers are exploitable.

1. **Identify the parsing chain**: map every component that touches an HTTP request before it reaches application code. CDN → WAF → load balancer → reverse proxy → application server
2. **Test RFC-edge-case behavior per component**: send requests with ambiguous headers, duplicate headers, mixed-case methods, malformed content-length, chunked+content-length. Note where components disagree
3. **Map cacheable vs non-cacheable paths**: identify which responses are cached and by which component. Cache key composition (what headers/params are included) determines what can be poisoned
4. **Test path normalization disagreements**: `/api/./admin`, `/api/%2e/admin`, `/api/..;/admin` — does the CDN normalize differently than the application? Path confusion between components bypasses access control
5. **Check host header handling**: when `Host`, `X-Forwarded-Host`, and `:authority` disagree, which does each component trust? Host header disagreements enable cache poisoning and routing confusion
