---
name: broken-function-level-authorization
description: BFLA testing for action-level authorization failures across endpoints, admin functions, and API operations
depends_on: []
---

# Broken Function Level Authorization (BFLA)

BFLA is action-level authorization failure: callers invoke functions (endpoints, mutations, admin tools) they are not entitled to. It appears when enforcement differs across transports, gateways, roles, or when services trust client hints. Bind subject x action at the service that performs the action.

## Discovery Signals

Technology fingerprints indicating high BFLA probability:

| # | Signal | Where to Find | Why Vulnerable |
|---|--------|---------------|----------------|
| 1 | AIP-style Google APIs (`*-pa.googleapis.com`, `clients6.google.com`) | Network tab on Google products | Full CRUD exposed via PATCH+updateMask; field-level auth often missing |
| 2 | GraphQL introspection enabled | `/graphql?query={__schema{types{name}}}` | Admin mutations visible; resolver-level auth often inconsistent |
| 3 | gRPC server reflection on | `grpcurl -plaintext host:port list` | All service methods enumerable including admin RPCs |
| 4 | Management console on non-standard port (8443, 8080, 8083) | Port scan, Shodan/Censys | Admin panels frequently skip auth or use weaker auth than main app |
| 5 | Feature flag system in JS bundle | `grep -rE 'featureFlag\|feature_toggle\|launchDarkly' *.js` | UI-gated features with live backend endpoints |
| 6 | Multi-tier role system (viewer/editor/admin/owner) | App settings, team/org pages | Role-change endpoints are prime BFLA targets |
| 7 | Import/export functionality | Project settings, data management UI | Deserialization paths bypass admin-only attribute restrictions |
| 8 | Async job/worker endpoints | `/api/jobs/`, `/api/exports/`, polling endpoints | Job finalize/approve often skips re-authorization |
| 9 | Partner/vendor portal with approval workflow | Separate portal subdomain, application forms | Post-rejection sessions retain access; status fields self-mutable |
| 10 | CE/EE or open-core architecture | GitHub/GitLab enterprise, plugin systems | Auth split across layers; unhandled cases fall through to permissive defaults |
| 11 | `X-HTTP-Method-Override` or `_method` accepted | Response to OPTIONS, framework docs | Verb override bypasses method-specific middleware |
| 12 | Public Sentry DSN / error-tracking write keys | CSP headers, JS bundles, page source | Third-party tool source-fetch features become SSRF/action gadgets |

## Attack Surface

- Vertical authz: privileged/admin/staff-only actions reachable by basic users
- Feature gates: toggles enforced at edge/UI, not at core services
- Transport drift: REST vs GraphQL vs gRPC vs WebSocket with inconsistent checks
- Gateway trust: backends trust X-User-Id/X-Role injected by proxies/edges
- Background workers/jobs performing actions without re-checking authz

## High-Value Actions

- Role/permission changes, impersonation/sudo, invite/accept into orgs
- Approve/void/refund/credit issuance, price/plan overrides
- Export/report generation, data deletion, account suspension/reactivation
- Feature flag toggles, quota/grant adjustments, license/seat changes
- Security settings: 2FA reset, email/phone verification overrides

## Admin/Internal Endpoint Discovery Matrix

| # | Discovery Method | Pattern | Example | Hit Rate |
|---|-----------------|---------|---------|----------|
| 1 | Subdomain enum + admin-path brute | CT logs + SecLists admin-panels wordlist | `plus-website.shopifycloud.com/admin.php` exposed without auth ($2.9k) | High on large orgs |
| 2 | Port scan on known IP ranges | masscan/zmap for 8080,8083,8443,8888,9090 | Chronograf on Google IP port 8083, no auth ($50k) | High on cloud infra |
| 3 | JS bundle grep for hidden routes | `grep -rE '/admin\|/internal\|/staff\|/debug'` in webpack chunks | Mobile app revealing `/api/internal/admin/users` | High on SPAs |
| 4 | AIP/REST CRUD inference from create call | Capture POST, try GET/PATCH/DELETE on same resource path | Nest Pro PATCH `/v1/organizations/{id}?updateMask=status` ($50k) | High on Google APIs |
| 5 | GraphQL schema dump | Introspection query or Clairvoyance wordlist bruteforce | Admin mutations hidden from UI but present in schema | Medium-High |
| 6 | gRPC reflection enumeration | `grpcurl list` then `grpcurl describe` per service | Admin service methods visible via reflection | Medium |
| 7 | Partner/vendor portal recon | Search for `partnerdash.`, `portal.`, `vendors.` subdomains | Waze PartnerDash accessible post-rejection ($50k) | Medium |
| 8 | Config-file path probing | `/actuator`, `/debug`, `/.env`, `/server-status`, `/metrics` | Spring Boot actuator endpoints with management actions | Medium |
| 9 | Error page fingerprinting | Trigger 404/500 and inspect server/framework headers | Django debug mode, Rails info page, PHP `admin.php` | Medium |
| 10 | Mobile app binary analysis | Decompile APK/IPA, grep for API base URLs and endpoints | Preinstalled Samsung apps with internal API endpoints ($10k) | Medium |
| 11 | Wayback Machine / web archives | `web.archive.org/web/*/target.com/admin*` | Archived admin paths that are still live | Low-Medium |
| 12 | Cloud-specific metadata paths | `/.well-known/`, `/robots.txt`, sitemap.xml | Disallowed admin paths listed in robots.txt | Low-Medium |

## Role Escalation Techniques

| # | From Role | To Role | Technique | Real-World Example |
|---|-----------|---------|-----------|-------------------|
| 1 | Unauthenticated | Verified user | Self-approve via PATCH on status field with updateMask | Nest Pro self-approval via AIP PATCH ($50k) |
| 2 | Basic user | Admin | Mass assignment of `role`/`is_admin` in profile PATCH/PUT | Generic SaaS priv-esc via role field in body ($9k) |
| 3 | Rejected applicant | Approved partner | Post-rejection session retains API access | Waze PartnerDash post-rejection access ($50k) |
| 4 | Normal user | Template admin | Import/deserialize with `template: true` attribute | GitLab import injects instance-wide templated service ($11k) |
| 5 | Editor | Root SSH | Config-language injection in management console | GHES syslog-ng config injection to root ($10k) |
| 6 | Non-member | Project member | Template copy of restricted project via namespace bypass | GitLab custom template copies private data ($12k) |
| 7 | Advertiser | Page admin | Mutation endpoint accepts foreign page_id | Facebook Creative Hub post on any page ($30k) |
| 8 | Any authenticated | Cross-tenant admin | Swap org/tenant/program ID in management endpoint | HackerOne archive any program's scope ($12.5k) |
| 9 | Basic user | Staff context | Blind stored XSS via staff name field into internal console | Shopify blind XSS in staff name to internal tools ($3k) |
| 10 | Unconfirmed user | Any user (ATO) | Email change before confirmation + SSO account merge | Shopify email confirmation bypass to store takeover ($16k) |

## Hidden Endpoint Patterns

| # | Framework | Pattern | Default Path | Auth by Default? |
|---|-----------|---------|--------------|-----------------|
| 1 | Google AIP | PATCH with `updateMask` on any resource | `/v1/{collection}/{id}?updateMask={field}` | No (per-field auth often missing) |
| 2 | Spring Boot Actuator | Management/monitoring endpoints | `/actuator/env`, `/actuator/shutdown` | No (pre-2.x default) |
| 3 | Django | Admin interface auto-generated | `/admin/`, `/__debug__/` | Yes but often misconfigured |
| 4 | Rails | Action Cable WebSocket, Active Admin | `/cable`, `/admin` | Per-action, often inconsistent |
| 5 | PHP CMS (WordPress/Laravel) | Admin panels | `/wp-admin/`, `/admin.php`, `/nova` | Yes but exposed on wrong subdomain |
| 6 | Node.js/Express | Debug and status endpoints | `/debug`, `/status`, `/health`, `/metrics` | Rarely |
| 7 | GraphQL | Playground/explorer UI | `/graphql`, `/graphiql`, `/playground` | Introspection often unprotected |
| 8 | gRPC | Reflection service | `grpc.reflection.v1alpha.ServerReflection` | Rarely restricted |
| 9 | Kubernetes | Dashboard and API proxy | `kubectl proxy` on 8001, dashboard on 30000+ | No (proxy trusts localhost) |
| 10 | InfluxDB/Chronograf | Time-series admin UI | Port 8083, 8086, 8888 | No by default |

## Reconnaissance

### Surface Enumeration

- Admin/staff consoles and APIs, support tools, internal-only endpoints exposed via gateway
- Hidden buttons and disabled UI paths (feature-flagged) mapped to still-live endpoints
- GraphQL schemas: mutations and admin-only fields/types; gRPC service descriptors (reflection)
- Mobile clients often reveal extra endpoints/roles in app bundles or network logs

### Signals

- 401/403 on UI but 200 via direct API call; differing status codes across transports
- Actions succeed via background jobs when direct call is denied
- Changing only headers (role/org) alters access without token change

## Key Vulnerabilities

### Verb Drift and Aliases

- Alternate methods: GET performing state change; POST vs PUT vs PATCH differences; X-HTTP-Method-Override/_method
- Alternate endpoints performing the same action with weaker checks (legacy vs v2, mobile vs web)

### Edge vs Core Mismatch

- Edge blocks an action but core service RPC accepts it directly; call internal service via exposed API route or SSRF
- Gateway-injected identity headers override token claims; supply conflicting headers to test precedence

### Feature Flag Bypass

- Client-checked feature gates; call backend endpoints directly
- Admin-only mutations exposed but hidden in UI; invoke via GraphQL or gRPC tools

### Batch Job Paths

- Create export/import jobs where creation is allowed but finalize/approve lacks authz; finalize others' jobs
- Replay webhooks/background tasks endpoints that perform privileged actions without verifying caller

### Content-Type Paths

- JSON vs form vs multipart handlers using different middleware: send the action via the most permissive parser

### Import/Deserialization Privilege Escalation

- Modify admin-only attributes in export JSON (template, verified, is_admin, role, permissions) and reimport
- Any export/import feature that trusts attribute values from the serialized data without re-validating against the importing user's privilege level

## Defense-Bypass Pairs

| # | Defense | Bypass Technique | Real-World Basis |
|---|---------|-----------------|------------------|
| 1 | UI hides admin button | Direct API call to underlying endpoint | Universal; every UI-only gate |
| 2 | Input URL/IP blacklist on SSRF | HTTP 302 redirect from attacker server to internal IP | AppSheet SSRF fix bypass via redirect ($50k) |
| 3 | Role validated at create time | PATCH/PUT with mass-assigned role field post-creation | Nest Pro updateMask bypass ($50k) |
| 4 | Application rejection revokes access | Session/cookie persists after rejection status | Waze PartnerDash post-rejection ($50k) |
| 5 | CE/EE authorization prepend | Return nil/no-op for unhandled namespace type | GitLab user-namespace bypass ($12k) |
| 6 | CSRF token on main routes | Different content-type or sub-component endpoint skips CSRF | GHES management console CSRF bypass ($10k) |
| 7 | Per-mutation GraphQL auth | Alias/batch query smuggling, persisted query bypass | Admin field accessible via nested alias |
| 8 | Async job trusts creation auth | Job finalize/execute does not re-check at execution time (TOCTOU) | GitLab template export job ($12k) |
| 9 | Fixed-enum role validation | Array-vs-string parsing differential, type confusion | Send `["admin"]` instead of `"admin"` |
| 10 | Route-level middleware auth | Legacy/alternate route (`/v1/admin` vs `/v2/admin`) skips new middleware | Route shadowing on version drift |

## Advanced Techniques

### GraphQL

- Resolver-level checks per mutation/field; do not assume top-level auth covers nested mutations or admin fields
- Abuse aliases/batching to sneak privileged fields; persisted queries sometimes bypass auth transforms

```graphql
mutation Promote($id:ID!){
  a: updateUser(id:$id, role: ADMIN){ id role }
}
```

### gRPC

- Method-level auth via interceptors must enforce audience/roles; probe direct gRPC with tokens of lower role
- Reflection lists services/methods; call admin methods that the gateway hid

### WebSocket

- Handshake-only auth: ensure per-message authorization on privileged events (e.g., admin:impersonate)
- Try emitting privileged actions after joining standard channels

### Multi-Tenant

- Actions requiring tenant admin enforced only by header/subdomain; attempt cross-tenant admin actions by switching selectors with same token

### Microservices

- Internal RPCs trust upstream checks; reach them through exposed endpoints or SSRF; verify each service re-enforces authz

## Bypass Techniques

### Header Trust

- Supply X-User-Id/X-Role/X-Organization headers; remove or contradict token claims; observe which source wins

### Route Shadowing

- Legacy/alternate routes (e.g., /admin/v1 vs /v2/admin) that skip new middleware chains

### Idempotency and Retries

- Retry or replay finalize/approve endpoints that apply state without checking actor on each call

### Cache Key Confusion

- Cached authorization decisions at edge leading to cross-user reuse; test with Vary and session swaps

## Chain Patterns

| # | Chain | Severity Uplift | Example |
|---|-------|----------------|---------|
| 1 | Email confirmation bypass + SSO merge = ATO | Low to Critical | Shopify unconfirmed email change + account integration ($16k) |
| 2 | Import deserialization + admin attribute injection = instance-wide poisoning | Medium to Critical | GitLab service template injection via project import ($11k) |
| 3 | BFLA on status field + vendor impersonation = brand fraud | Medium to High | Nest Pro self-approval enables installer impersonation ($50k) |
| 4 | Post-rejection access + data enumeration = mass PII leak | Low to High | Waze partner data harvest including Google employee emails ($50k) |
| 5 | Config-language injection + daemon as root = RCE | Medium to Critical | GHES syslog-ng program() injection from editor role ($10k) |
| 6 | Multi-layer auth bypass + async TOCTOU + over-broad lookup = data exfil | Low to Critical | GitLab 3-flaw chain: namespace bypass + finder + async export ($12k) |
| 7 | Blind XSS in merchant field + internal admin render = session hijack | Low to High | Shopify staff name XSS fires in internal support console ($3k) |
| 8 | Patch-adjacent retest + state mutation before token consume = ATO | Medium to Critical | Shopify Part II: email change after verification dispatched ($15k) |
| 9 | CSRF bypass on management console + high-impact admin action = takeover | Medium to Critical | GHES CSRF + LDAP rebind or SSH key injection ($10k) |

## Testing Methodology

1. **Build Actor x Action matrix** - Unauth, basic, premium, staff/admin; enumerate actions per role
2. **Obtain tokens/sessions** - For each role
3. **Exercise every action** - Across all transports and encodings (JSON, form, multipart), including method overrides
4. **Vary headers and selectors** - Org/tenant/project; test behind gateway vs direct-to-service
5. **Include background flows** - Job creation/finalization, webhooks, queues; confirm re-validation
6. **Test import/export paths** - Modify admin-only attributes in export data and reimport
7. **Probe AIP/CRUD inference** - For every create endpoint, try GET/PATCH/DELETE with security-relevant field masks
8. **Retest after patches** - Enumerate adjacent mutation primitives that reach the same broken invariant

## Validation

1. Show a lower-privileged principal successfully invokes a restricted action (same inputs) while the proper role succeeds and another lower role fails
2. Provide evidence across at least two transports or encodings demonstrating inconsistent enforcement
3. Demonstrate that removing/altering client-side gates (buttons/flags) does not affect backend success
4. Include durable state change proof: before/after snapshots, audit logs, and authoritative sources

## False Positives

- Read-only endpoints mislabeled as admin but publicly documented
- Feature toggles intentionally open to all roles for preview/beta with clear policy
- Simulated environments where admin endpoints are stubbed with no side effects

## Impact

- Privilege escalation to admin/staff actions
- Monetary/state impact: refunds/credits/approvals without authorization
- Tenant-wide configuration changes, impersonation, or data deletion
- Compliance and audit violations due to bypassed approval workflows

## CI/CD and Supply-Chain BFLA

| # | Target | Technique | Real-World Example |
|---|--------|-----------|-------------------|
| 1 | Public OSS repo CI workflows | Fork repo, craft PR that leaks CI service-account token from build env | GCP magic-modules PR leaked 9+ project IAM token ($3.1M) |
| 2 | `pull_request_target` workflows | PR code runs with base repo secrets; exfil via webhook/log/comment | GitHub Actions privilege escalation class ("pwn request") |
| 3 | Shared CI service accounts | Single leaked token enumerates cross-project IAM (GCS, GKE, SA keys) | `gcloud projects list` returned 9 internal CI projects ($3.1M) |
| 4 | Label-gated CI workflows | Auto-label bots assign labels from attacker-controlled PR titles | Bypasses "approved" label gate on secret-bearing workflows |

## LLM-as-Privilege-Laundering

| # | Technique | What to Test | Real-World Example |
|---|-----------|-------------|-------------------|
| 1 | LLM content-fetch bypass | Prompt LLM to summarize paywalled/members-only content via URL ingestion | Gemini 2.5 Pro bypassed YouTube members-only paywall ($133k) |
| 2 | LLM internal-doc access | Ask LLM to retrieve/summarize content from internal systems it has service-tier access to | Any LLM with privileged backend access becomes an authz bypass |
| 3 | LLM credential laundering | LLM fetches via service credentials; user identity not propagated to content-fetch layer | Structurally identical to SSRF: server-side fetch with server-side creds |

## RPC Bridge and Internal Service Exploitation

| # | Signal | Technique | Real-World Example |
|---|--------|-----------|-------------------|
| 1 | `clients6.google.com` or `*.googleapis.com` with `internal` in path | Construct SAPISIDHASH from any Google cookie; call internal RPC methods | Real-time Support API leaked agent PII + customer data ($1.4M) |
| 2 | Bridge endpoint translates user-cookie to internal RPC | Neither bridge nor service enforces role check (mutual trust gap) | Classic "everyone assumed someone else was checking" ($1.4M) |
| 3 | `*.admin.*`, `*.support.*`, `*.ops.*` service paths | Probe with authenticated user tokens; watch for non-403 responses | Internal-tooling RPC services exposed via HTTP-RPC bridges |
| 4 | TLS cert CN on raw cloud IPs | Sweep cloud IP ranges with TLS-grab; CN reveals forgotten admin panels | Plastic SCM on Google IP via owlchemylabs.com CN ($50k) |
| 5 | First-run setup endpoints on deployed products | `/account/register`, `/setup`, `/install`, `/onboarding` on initialized servers | Register endpoint overwrites existing admin password ($50k) |

## Systematic Authorization Audit Patterns

| # | Pattern | Methodology | Real-World Basis |
|---|---------|-------------|------------------|
| 1 | Document-driven authorization testing | Read the platform's IAM docs. Extract the role-feature matrix. For each cell that says "role X cannot do Y," craft the API request and send it. Permission docs are the bug specification ($0-$50k) | Atlassian, Salesforce, Microsoft 365 |
| 2 | GraphQL side-effect-despite-error | For every GraphQL mutation that returns "access denied," check whether the side effect happened anyway. The auth check may run after the write. Verify with a second read request ($900) | Multiple SaaS platforms |
| 3 | Lifecycle-state x action matrix | For every lifecycle state (deactivate user, revoke key, suspend org, archive workspace, expire session), build a state-change x action matrix. Test whether suspended/revoked entities can still perform actions during grace periods or via cached sessions ($500) | SaaS lifecycle bugs |
| 4 | New-feature regression hunting | Subscribe to product changelogs and release notes. Test new features within 48h of release — new endpoints often lack the authorization middleware applied to established routes ($10k) | Consistent across all large targets |
| 5 | Marketplace app delegation gap | When marketplace apps (Atlassian/Salesforce/Slack integrations) expose config pages, test whether the app's permission check delegates to the host platform or uses its own weaker check. The app trusts "authenticated user" without verifying "admin of this workspace" ($3k) | Atlassian Connect apps |
| 6 | Decoupled-identifier OTP flows | When a verification flow sends a code to identifier A (phone) but grants access to resource B (email change), test whether the verification of A can be used to authorize actions on unrelated resource C ($3.25k) | OTP/2FA decoupling bugs |
| 7 | Auto-exposed framework default APIs | For WordPress REST, Django REST Framework, Rails scaffolds, Laravel API resources: test every default-generated endpoint with low-privilege tokens. Framework auto-exposure often outpaces per-endpoint auth configuration ($0-$5k) | WordPress, Django, Rails, Laravel |
| 8 | Stale session role enforcement | Capture a request while having elevated privileges. Downgrade or remove the role (or have admin revoke it). Replay the captured request — if the session/token is not revalidated against current role state, the old privilege persists ($0-$10k) | Multi-role SaaS platforms |
| 9 | Export/download cross-tenant | Test every export/download endpoint (CSV, PDF, report) with a foreign tenant/org identifier. Export endpoints often authorize "can this user export?" without checking "from which tenant?" ($0-$50k) | Multi-tenant SaaS |
| 10 | Admin-set policy parameters client-side | When admin configures per-user/per-org policies (invite restrictions, SSO enforcement, domain allowlists) and those parameters travel client-side in the invitation/signup flow, modify them in transit. The server often trusts the client-forwarded policy value ($0-$10k) | Invitation/SSO flows |
| 11 | Error response data leakage | When an API denies access, analyze the full error response — not just the status code. Auth-denied responses frequently include the requested resource data, internal IDs, user details, or schema information in the error body ($0-$5k) | AJAX/API endpoints across targets |
| 12 | Capability-URL revocation audit | For any content served via signed/hashed URLs, test the full lifecycle: capture URL while authorized, revoke access, replay the URL. Also test whether the URL can be transferred to another user/session ($0-$5k) | Signed-URL content delivery |

## Pro Tips

1. Start from the role matrix; test every action with basic vs admin tokens across REST/GraphQL/gRPC
2. Diff middleware stacks between routes; weak chains often exist on legacy or alternate encodings
3. Inspect gateways for identity header injection; never trust client-provided identity
4. Treat jobs/webhooks as first-class: finalize/approve must re-check the actor
5. For Google targets, always probe AIP PATCH with `updateMask` on security-relevant fields (status, role, tier, plan, verified, permissions)
6. After any fix lands, retest with adjacent mutation primitives that touch the same state -- patch-adjacent variant hunting is consistently high-yield
7. Import/export features are privilege escalation boundaries: tamper every serialized attribute that is normally admin-only
8. Meta-resource IDOR (archive/unarchive, scope config, program settings) is consistently underexplored vs data IDOR
9. When you find a management console on a non-standard port, probe for CSRF bypass -- multi-component admin consoles have cross-component CSRF asymmetries
10. Rejected/denied/suspended account states often retain API access -- always test post-rejection
11. For any SaaS with internal support tools, spray blind XSS in merchant-controlled fields (names, addresses, business names) and wait for callbacks from internal domains
12. Shared-primitive-different-route: when one route is patched, find other routes that call the same backend function with weaker authorization
13. For public OSS repos of target companies, enumerate CI workflows triggered on PRs from forks; `pull_request_target` + PR code checkout = attacker code with repo secrets ($3.1M)
14. Probe every LLM content-ingestion feature with paywalled/private URLs -- LLMs with service-tier access launder access controls when user identity is not propagated ($133k)
15. At companies with internal RPC architectures, inventory every bridge endpoint (`clients*.google.com`, `*.api.facebook.com/internal/`); match service paths against `internal`/`admin`/`support` keywords and probe for missing role checks ($1.4M)
16. Sweep cloud IP ranges with TLS-grab tools; certificate CN reveals forgotten admin panels of subsidiaries -- then test first-run setup endpoints (`/setup`, `/install`, `/account/register`) for state confusion that lets you reclaim admin ($50k)
17. For every privacy/visibility setting, enumerate EVERY API endpoint that touches the protected attribute and verify the setting is enforced at each -- search/filter endpoints often have weaker ACLs than direct-read endpoints ($500k)
18. **When you find one UI-only gate (disabled button that still works via API), immediately audit ALL similar gates in the app** -- UI-only enforcement is almost never a one-off; it signals a systemic pattern where the frontend is the authorization layer ($0-$50k)
19. **For multi-surface apps (web API, mobile API, TV API, legacy API), test the same restricted action on every surface** -- one surface often lags behind in authorization updates, especially mobile and legacy APIs ($0-$10k)
20. **For any multi-role application, enumerate every backend route by URL even if the UI hides it for the current role** -- build the complete route list from JS bundles, then replay every route with each role's token. Hidden routes are not protected routes ($0-$10k)
21. **Always click disabled UI elements** -- greyed-out buttons, links, and form fields should be tested via direct API calls or by removing the `disabled` attribute in DevTools. The backend rarely validates the UI state ($0-$5k)
22. **For registration endpoints that separate user tiers (admin/merchant/user), test whether the tier parameter is server-enforced** -- changing `role=user` to `role=admin` in the registration POST often works when tier assignment is client-driven ($0-$10k)

## Summary

Authorization must bind the actor to the specific action at the service boundary on every request and message. UI gates, gateways, or prior steps do not substitute for function-level checks.
