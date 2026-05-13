---
name: idor
description: IDOR/BOLA testing for object-level authorization failures and cross-account data access
depends_on: []
---

# IDOR

Object-level authorization failures (BOLA/IDOR) lead to cross-account data exposure and unauthorized state changes across APIs, web, mobile, and microservices. Treat every object reference as untrusted until proven bound to the caller.

## Discovery Signals

Technology fingerprints indicating high IDOR probability:

| Signal | Where to Find | Why Vulnerable |
|---|---|---|
| Sequential integer IDs in URLs | URL paths, API responses | Trivially enumerable, no auth binding likely |
| GraphQL Relay global node IDs (`VXNlcjoxMjM=`) | API responses | Base64-decoded = `User:123`, swap numbers |
| API versioning (v1/v2/v3 endpoints) | Path scan | Older versions often lack authorization added later |
| `X-Total-Count` or pagination headers | API responses | Reveals total object count, cursor enumeration |
| Django REST Framework browsable API | Path scan | Schema exposure + object enumeration |
| Swagger/OpenAPI docs exposed | `/swagger.json`, `/api-docs` | Full endpoint + parameter schema |
| Background job IDs in responses | API responses, polling endpoints | Job result endpoints often skip auth |
| Shopify-style resource IDs (`gid://shopify/Product/123`) | API responses | Structured IDs reveal type and sequential number |
| Firebase Realtime DB / Firestore | JS bundle, network traffic | Rules often missing or set to public read |
| S3-style signed URLs | API responses | Predictable bucket/key structure, short expiry bypass |
| Multi-tenant header (`X-Tenant-ID`, org slug) | Request headers | Header-controlled tenant = trivial tenant switching |
| `expand`/`include`/`fields` query params | API responses | Relationship traversal often bypasses auth |

## ID Format Fingerprinting

| ID Format | Example | Exploitation Technique |
|---|---|---|
| Sequential integer | `12345` | Enumerate +/-1000 around known ID |
| UUIDv1 (time-based) | `6ba7b810-9dad-11d1-80b4-00c04fd430c8` | Extract timestamp + MAC, predict adjacent UUIDs |
| UUIDv4 (random) | `f47ac10b-58cc-4372-a567-0e02b2c3d479` | Not enumerable -- need leak source (logs, emails, API responses) |
| ULID | `01ARZ3NDEKTSV4RRFFQ69G5FAV` | First 10 chars = timestamp (ms precision), predictable within time window |
| Snowflake (Twitter/Discord) | `175928847299117063` | Encodes timestamp + worker + sequence, predictable in time window |
| Base64-encoded | `VXNlcjoxMjM=` -> `User:123` | Decode, modify inner value, re-encode |
| Hex-encoded | `7f000001` | Decode to integer, enumerate |
| Slug/username-based | `/users/john-doe/settings` | Enumerate via search/directory, no opacity |
| Hash-based (MD5/SHA) | `e99a18c428cb38d5f260853678922e03` | Check if hash of sequential input (e.g., MD5 of user ID) |
| Composite key | `org_123:user_456` | Modify each component independently |
| Signed token | `eyJhbGc...` (JWT-like) | Check for `alg:none`, weak secret, missing signature validation |

## Attack Surface

**Scope**
- Horizontal access: access another subject's objects of the same type
- Vertical access: access privileged objects/actions (admin-only, staff-only)
- Cross-tenant access: break isolation boundaries in multi-tenant systems
- Cross-service access: token or context accepted by the wrong service

**Reference Locations**
- Paths, query params, JSON bodies, form-data, headers, cookies
- JWT claims, GraphQL arguments, WebSocket messages, gRPC messages

**Identifier Forms**
- Integers, UUID/ULID/CUID, Snowflake, slugs
- Composite keys (e.g., `{orgId}:{userId}`)
- Opaque tokens, base64/hex-encoded blobs

**Relationship References**
- parentId, ownerId, accountId, tenantId, organization, teamId, projectId, subscriptionId

**Expansion/Projection Knobs**
- `fields`, `include`, `expand`, `projection`, `with`, `select`, `populate`
- Often bypass authorization in resolvers or serializers

## High-Value Targets

- Exports/backups/reporting endpoints (CSV/PDF/ZIP)
- Messaging/mailbox/notifications, audit logs, activity feeds
- Billing: invoices, payment methods, transactions, credits
- Healthcare/education records, HR documents, PII/PHI/PCI
- Admin/staff tools, impersonation/session management
- File/object storage keys (S3/GCS signed URLs, share links)
- Background jobs: import/export job IDs, task results
- Multi-tenant resources: organizations, workspaces, projects

## Reconnaissance

**Parameter Analysis**
- Pagination/cursors: `page[offset]`, `page[limit]`, `cursor`, `nextPageToken` (often reveal or accept cross-tenant/state)
- Directory/list endpoints as seeders: search/list/suggest/export often leak object IDs for secondary exploitation

**Enumeration Techniques**
- Alternate types: `{"id":123}` vs `{"id":"123"}`, arrays vs scalars, objects vs scalars
- Edge values: null/empty/0/-1/MAX_INT, scientific notation, overflows
- Duplicate keys/parameter pollution: `id=1&id=2`, JSON duplicate keys `{"id":1,"id":2}` (parser precedence)
- Case/aliasing: userId vs userid vs USER_ID; alt names like resourceId, targetId, account
- Path traversal-like in virtual file systems: `/files/user_123/../../user_456/report.csv`

**UUID/Opaque ID Sources**
- Logs, exports, JS bundles, analytics endpoints, emails, public activity
- Time-based IDs (UUIDv1, ULID) may be guessable within a window

## Key Vulnerabilities

### Horizontal & Vertical Access

- Swap object IDs between principals using the same token to probe horizontal access
- Repeat with lower-privilege tokens to probe vertical access
- Target partial updates (PATCH, JSON Patch/JSON Merge Patch) for silent unauthorized modifications

### Bulk & Batch Operations

- Batch endpoints (bulk update/delete) often validate only the first element; include cross-tenant IDs mid-array
- CSV/JSON imports referencing foreign object IDs (ownerId, orgId) may bypass create-time checks

### Secondary IDOR

- Use list/search endpoints, notifications, emails, webhooks, and client logs to collect valid IDs
- Fetch or mutate those objects directly
- Pagination/cursor manipulation to skip filters and pull other users' pages

### API Versioning IDOR

Many programs maintain multiple API versions. Authorization improvements often only apply to the latest:

```
# New version has proper auth
GET /api/v3/users/123/profile -> 403 Forbidden

# Old version still accessible, lacks auth
GET /api/v1/users/123/profile -> 200 OK (full profile data)
GET /api/v2/users/123/profile -> 200 OK (partial fix, still leaks)
```

For every endpoint blocked in the current API version, try replacing v3/v2 with v1/v0/beta/alpha/internal.

### Mass Assignment via Relationship Setters

Object update endpoints often accept relationship IDs that transfer ownership or access:

```json
// Normal profile update
// PUT /api/users/me
{"name": "Alice", "bio": "Hello"}

// Mass assignment -- set org ownership
// PUT /api/users/me
{"name": "Alice", "organization_id": "target_org_123"}

// Relationship injection via nested create
// POST /api/projects
{"name": "test", "team_id": "other_team_id", "owner_id": "admin_user_id"}
```

Parameter names to try: `owner_id`, `org_id`, `organization_id`, `team_id`, `group_id`, `parent_id`, `tenant_id`, `account_id`, `admin`, `role`, `permissions`, `is_admin`, `access_level`.

### Job/Task Objects

- Access job/task IDs from one user to retrieve results for another (`export/{jobId}/download`, `reports/{taskId}`)
- Cancel/approve someone else's jobs by referencing their task IDs

### File/Object Storage

- Direct object paths or weakly scoped signed URLs
- Attempt key prefix changes, content-disposition tricks, or stale signatures reused across tenants
- Replace share tokens with tokens from other tenants; try case/URL-encoding variations

### GraphQL

- Enforce resolver-level checks: do not rely on a top-level gate
- Verify field and edge resolvers bind the resource to the caller on every hop
- Abuse batching/aliases to retrieve multiple users' nodes in one request
- Global node patterns (Relay): decode base64 IDs and swap raw IDs
- Overfetching via fragments on privileged types

```graphql
# Relay node ID swap -- decode base64, change type/ID, re-encode
query { node(id: "VXNlcjoxMjM=") { ... on User { email ssn } } }

# Batch query to enumerate -- single request, multiple lookups
query {
  a: user(id: "1") { email }
  b: user(id: "2") { email }
  c: user(id: "3") { email }
}

# Connection traversal -- hop through relationships
query {
  organization(id: "org_1") {
    members { edges { node { email personalData { ssn } } } }
  }
}

# Mutation IDOR -- modify other users' data
mutation {
  updateUser(id: "other_user_id", input: { role: "admin" }) { id role }
}

# Subscription IDOR -- subscribe to other users' events
subscription { userActivity(userId: "other_user") { action data } }
```

### Microservices & Gateways

- Token confusion: token scoped for Service A accepted by Service B due to shared JWT verification but missing audience/claims checks
- Trust on headers: reverse proxies or API gateways injecting/trusting headers like `X-User-Id`, `X-Organization-Id`; try overriding or removing them
- Context loss: async consumers (queues, workers) re-process requests without re-checking authorization

### Multi-Tenant

- Probe tenant scoping through headers, subdomains, and path params (`X-Tenant-ID`, org slug)
- Try mixing org of token with resource from another org
- Test cross-tenant reports/analytics rollups and admin views which aggregate multiple tenants

### WebSocket

- Authorization per-subscription: ensure channel/topic names cannot be guessed (`user_{id}`, `org_{id}`)
- Subscribe/publish checks must run server-side, not only at handshake
- Try sending messages with target user IDs after subscribing to own channels

### gRPC

- Direct protobuf fields (`owner_id`, `tenant_id`) often bypass HTTP-layer middleware
- Validate references via grpcurl with tokens from different principals

### Integrations

- Webhooks/callbacks referencing foreign objects (e.g., `invoice_id`) processed without verifying ownership
- Third-party importers syncing data into wrong tenant due to missing tenant binding

## Side-Channel IDOR Detection

| Side Channel | What It Reveals | How to Detect |
|---|---|---|
| Response time difference | Object exists vs doesn't exist | Measure response time for valid ID vs random ID |
| Error message difference | `"User not found"` vs `"Access denied"` | Different errors confirm object existence |
| Response size difference | 0 bytes vs >0 bytes for denied resource | Compare Content-Length headers |
| HTTP status code | 404 vs 403 for different IDs | 403 = exists but no access, 404 = doesn't exist |
| ETag header | Different ETags for different objects | Confirms distinct objects even when body is denied |
| Rate limiting difference | Rate limited for valid ID but not invalid | Rate limit applied per-resource confirms existence |
| Cache headers | `X-Cache: HIT` vs `MISS` | Cached = recently accessed by owner |
| Redirect destination | Different redirect URLs per ID | Redirect reveals internal routing per object |

## Bypass Techniques

**Parser & Transport**
- Content-type switching: `application/json` <-> `application/x-www-form-urlencoded` <-> `multipart/form-data`
- Method tunneling: `X-HTTP-Method-Override`, `_method=PATCH`; or using GET on endpoints incorrectly accepting state changes
- JSON duplicate keys/array injection to bypass naive validators

**Parameter Pollution**
- Duplicate parameters in query/body to influence server-side precedence (`id=123&id=456`); try both orderings
- Mix case/alias param names so gateway and backend disagree (userId vs userid)

**Cache & Gateway**
- CDN/proxy key confusion: responses keyed without Authorization or tenant headers expose cached objects to other users
- Manipulate Vary and Accept headers
- Redirect chains and 304/206 behaviors can leak content across tenants

**Race Windows**
- Time-of-check vs time-of-use: change the referenced ID between validation and execution using parallel requests

**Blind Channels**
- Use differential responses (status, size, ETag, timing) to detect existence
- Error shape often differs for owned vs foreign objects
- HEAD/OPTIONS, conditional requests (`If-None-Match`/`If-Modified-Since`) can confirm existence without full content

**Extended Bypasses**

| Bypass | Technique | Example |
|---|---|---|
| Wrap ID in array | `{"id": [123]}` instead of `{"id": 123}` | Array parsing may skip auth check |
| Wildcard/glob | `GET /api/users/*/documents` | Some routers resolve wildcards |
| Negative ID | `GET /api/users/-1/profile` | Some systems map -1 to current/first user |
| Float ID | `{"id": 123.0}` or `{"id": 1.23e2}` | Type coercion may bypass integer-only validation |
| Unicode digits | Full-width or circled numerals | Unicode normalization may resolve to integers |
| HTTP method override | GET blocked, try `POST ?_method=GET` | Method-based auth, override via query param |
| GraphQL alias bypass | `a1: user(id:"1") { secret } a2: user(id:"2") { secret }` | Resolver auth checked once, aliases skip |
| Cursor manipulation | Modify opaque cursor (often base64 offset) | Decode cursor, change offset to access other pages |
| Nested relationship traversal | `GET /api/teams/123/members` | Auth on direct user endpoint but not via team relationship |
| `X-HTTP-Method-Override` | Override DELETE/PUT blocked at gateway | Gateway blocks method, backend accepts override |

## Chaining Attacks

- IDOR + CSRF: force victims to trigger unauthorized changes on objects you discovered
- IDOR + Stored XSS: pivot into other users' sessions through data you gained access to
- IDOR + SSRF: exfiltrate internal IDs, then access their corresponding resources
- IDOR + Race: bypass spot checks with simultaneous requests

## Testing Methodology

1. **Build matrix** - Subject x Object x Action matrix (who can do what to which resource)
2. **Obtain principals** - At least two: owner and non-owner (plus admin/staff if applicable)
3. **Collect IDs** - Capture at least one valid object ID per principal from list/search/export endpoints
4. **Cross-channel testing** - Exercise every action (R/W/D/Export) while swapping IDs, tokens, tenants
5. **Transport variation** - Test across web, mobile, API, GraphQL, WebSocket, gRPC
6. **Consistency check** - Same rule must hold regardless of transport, content-type, serialization, or gateway

## Validation

1. Demonstrate access to an object not owned by the caller (content or metadata)
2. Show the same request fails with appropriately enforced authorization when corrected
3. Prove cross-channel consistency: same unauthorized access via at least two transports (e.g., REST and GraphQL)
4. Document tenant boundary violations (if applicable)
5. Provide reproducible steps and evidence (requests/responses for owner vs non-owner)

## False Positives

- Public/anonymous resources by design
- Soft-privatized data where content is already public
- Idempotent metadata lookups that do not reveal sensitive content
- Correct row-level checks enforced across all channels
- Empty array / null returned for another user's resource -- silent enforcement, not exposure; compare against the owner's view to confirm the data is actually missing rather than just hidden from the response shape

## Impact

- Cross-account data exposure (PII/PHI/PCI)
- Unauthorized state changes (transfers, role changes, cancellations)
- Cross-tenant data leaks violating contractual and regulatory boundaries
- Regulatory risk (GDPR/HIPAA/PCI), fraud, reputational damage

## Pro Tips

1. Always test list/search/export endpoints first; they are rich ID seeders
2. Build a reusable ID corpus from logs, notifications, emails, and client bundles
3. Toggle content-types and transports; authorization middleware often differs per stack
4. In GraphQL, validate at resolver boundaries; never trust parent auth to cover children
5. In multi-tenant apps, vary org headers, subdomains, and path params independently
6. Check batch/bulk operations and background job endpoints; they frequently skip per-item checks
7. Inspect gateways for header trust and cache key configuration
8. Treat UUIDs as untrusted; obtain them via OSINT/leaks and test binding
9. Use timing/size/ETag differentials for blind confirmation when content is masked
10. Prove impact with precise before/after diffs and role-separated evidence
11. Always decode base64/hex IDs before testing -- many "opaque" IDs are just encoded integers
12. Test IDOR on background job result endpoints -- they almost never have auth
13. For multi-tenant apps, test cross-tenant via: header swap, subdomain swap, AND path parameter swap independently
14. Check if export/download endpoints (CSV, PDF, ZIP) skip object-level auth -- they frequently do
15. Use deleted/suspended account IDs -- authorization checks may not apply to inactive objects
16. When direct IDOR fails, try indirect: create an object that references the target ID (e.g., share, mention, tag)
17. Filter-vs-permission inversion: when UI shares a SUBSET of an object (one tab of a spreadsheet, one slide of a deck), the underlying API often returns the FULL object -- test the API directly ($1M)
18. Identifier-chain audit: for every RPC returning data gated on ID X, list ALL RPCs that produce X as output -- reverse-map the ID graph to find ungated paths ($500K)
19. Fork/clone/copy endpoints accepting a "source" or "based_on" ID rarely authorize caller against the source object -- test every copy-from primitive ($50K)
20. Cross-product integration endpoints are highest-yield IDOR targets on large platforms -- calls bridging two internal services often skip per-object auth ($7.5K)

## Tooling Workflow (USE THESE -- don't rely on ad-hoc mental tracking)

Bugdotexe ships a structured access-matrix tracker specifically for
BOLA/IDOR systematic enumeration:

1. **After every authenticated probe** call `record_access_probe(
   target, endpoint, method, role, status_code)`. Use the operator's
   role label from the credential inventory verbatim (not email
   prefixes, not invented labels).
2. **Every ~10 probes OR when you finish a surface**, call
   `get_access_matrix(target)` for the structured view of what each
   role can reach. Gaps are targets.
3. **For pattern-driven next steps**, call
   `get_authz_anomalies(target)` -- flags role-privilege inversions,
   tenant-scope breaks, and endpoints where lower-privilege roles
   unexpectedly reach higher-privilege resources.
4. **To prioritise the next probe**, call `suggest_variants(target,
   endpoint, role)` -- returns ranked candidate endpoint/role combos
   worth trying next based on the observed matrix.

The role-sweep submission gate (create_vulnerability_report) only
accepts reports once every operator-provided role has at least one
2xx/3xx probe. These tools are how you satisfy that gate efficiently.

## Summary

Authorization must bind subject, action, and specific object on every request, regardless of identifier opacity or transport. If the binding is missing anywhere, the system is vulnerable.
