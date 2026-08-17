---
name: auth-matrix-systematic
category: methodology
description: Systematic role × endpoint × method authorization testing — every triplet is a potential authorization gap
depends_on: []
---

# Auth Matrix Systematic

Authorization gaps hide in the cells of the role × endpoint × method matrix.
Spot-checking misses gaps. The methodology: enumerate the matrix from runtime
state, then test every cell.

## When to Use

- Any target with multiple authentication primitives or roles
- Any target with multi-tenant resources
- After surface discovery has produced the endpoint inventory
- Before declaring "authorization is fine" on any reviewed component

## Inputs (all runtime-derived — never hardcoded)

- **PRINCIPALS** = `scan_config.credential_inventory.keys()` ∪ `{"anonymous"}`
  - Plus any principals discoverable via account creation (if registration is open)
- **ENDPOINTS** = union of:
  - OpenAPI / Swagger / GraphQL schema paths
  - Content-discovery results (ffuf, feroxbuster)
  - JS-extracted API calls (katana + bundle parsing)
  - Historical URLs (gau, waymore)
- **METHODS** = OpenAPI declared methods ∪ {GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS}

## Five Test Classes Per Cell (Endpoint, Method, Principal)

### 1. AUTH — Does the endpoint accept this principal's token?

For each principal P, hit (E, M):
- 200 / 2xx → endpoint allows P
- 401 → endpoint requires auth (P unauthorized at all)
- 403 → endpoint requires specific privilege P lacks
- 404 → resource hidden or missing (sometimes obfuscated 403)

Map the cell as `{ALLOW, AUTH_REQUIRED, FORBIDDEN, NOT_FOUND}`.

### 2. BOLA — Object-level authorization

Find any path or body parameter that looks like an object identifier
(numeric ID, UUID, slug). Substitute identifiers belonging to a different
principal:
- Request the object as P with own_id → baseline
- Request the same object as P with peer_id → expected 403/404
- If the response leaks data scoped to peer → BOLA finding

Test reads AND writes (DELETE, PATCH on peer's resource).

### 3. CREATE-IDOR — Authorization on resource creation

For each state-changing endpoint accepting an `owner_id`-shaped field
(user_id, target_id, owner_id, recipient_id, assignee_id, on_behalf_of):
- As P, create resource targeting P's own scope → baseline
- As P, create resource targeting peer's scope → expected 403
- If resource is created and persists in peer's scope → CREATE-IDOR finding

This is distinct from BOLA — many systems gate READ but not CREATE.

### 4. SCOPE-BYPASS — Documented limit ignored on alt endpoint

If endpoint E enforces a documented limit (rate, amount, count, size, frequency),
search for sibling endpoints performing the SAME state primitive with no
limit or different limit:
- Find the primitive (the underlying state mutation, e.g., "modify resource",
  "delete record", "promote entity", "trigger workflow")
- Enumerate all endpoints performing this primitive
- For principal P, test if any path bypasses the limit enforced on E

### 5. PRINCIPAL-ESCAPE — Cross-scope mutation

For principals scoped to a sub-resource (per-tenant, per-org, per-branch,
per-team, per-workspace), test if mutations leak out of scope:
- P scoped to scope A operates on scope B (different scope_id in path or body)
- Expected: 403; if 200, scope enforcement is missing

## Output Format

For each cell that produces an unexpected result, file:

```
Endpoint: {METHOD} {path}
Principal: {role}
Test class: {AUTH|BOLA|CREATE-IDOR|SCOPE-BYPASS|PRINCIPAL-ESCAPE}
Expected: {status_or_behavior}
Observed: {status_or_behavior}
Evidence: {request} → {response excerpt}
```

## Anti-Patterns

- **Spot-check only**: testing 3 endpoints × 2 roles and concluding authorization
  works is not the matrix. Aim for FULL coverage of discovered endpoints.
- **Skip method variations**: if E has GET + POST + DELETE, test all three.
- **Skip anonymous**: even with credentials, ALWAYS run the matrix as anonymous.
  Many endpoints accidentally allow unauthenticated access.
- **Hardcode role lists**: never assume a role taxonomy. Always derive from
  `credential_inventory` and discover via account creation.
- **Skip CREATE-IDOR**: this is the most-missed class. Read endpoints often
  enforce auth; create endpoints often forget the owner_id check.

## Coverage Self-Check

Before declaring authorization tested:
- [ ] Every (endpoint, method, principal) cell visited at least once
- [ ] Every endpoint with an `*_id` parameter tested for BOLA
- [ ] Every state-changing endpoint with an `owner_id`-shaped field tested for CREATE-IDOR
- [ ] Every principal tested for PRINCIPAL-ESCAPE on multi-tenant resources
- [ ] Anonymous principal tested against every endpoint

## Discovery Signals

Before building the matrix, scan for these signals that indicate high-yield auth testing targets:

| # | Signal | Where to Find | What It Means |
|---|--------|--------------|---------------|
| 1 | Multiple auth mechanisms (cookie, bearer, mTLS, basic, JWT) | Proxy logs, `Authorization` header variants | Auth inconsistency across mechanisms — test each path separately (report #270753280, $500k Google VRP) |
| 2 | `disabled` buttons in UI with no server-side enforcement | DOM inspection, browser devtools | Client-side-only gating — replay the request directly (report #519110144, $313k Google VRP) |
| 3 | GraphQL mutations with role-suggestive names | Schema introspection, `__schema` query | Missing per-mutation role checks — test each mutation from lowest role (report #1018094, Shopify) |
| 4 | `single=true`, `gid=`, `tab=`, `view=` in shared/published URLs | URL parameters on share/publish features | Filter-vs-permission inversion — negate the flag (report #924219904, $1M Google VRP) |
| 5 | Firebase/Cognito API key in client JS | JS bundle search for `apiKey`, `userPoolId` | Public signup → JWT with unverified email claim (report #372657152, $133k Google VRP) |
| 6 | OAuth scopes with vague descriptions ("Manage your printers") | OAuth consent screen, developer docs | Scope grants more API access than description implies (report #724829696, $313k Google VRP) |
| 7 | `X-Forwarded-For`, `X-Real-IP` in request headers | Proxy logs, header injection tests | Rate limiter or ACL keyed on spoofable header (report #252718947) |
| 8 | Multi-tier role names in API responses (`analyst`, `editor`, `admin`) | JSON response bodies, GraphQL enums | Per-action role check missing — lowest tier can call destructive actions (report #1014368010, Meta) |
| 9 | ACL/permission toggle in settings UI | Admin panel, configuration endpoints | Permission change may not propagate to serving layer (report #489003520, $133k Google VRP) |
| 10 | LLM/AI features that ingest user content by URL | AI Studio, copilot, summarization features | LLM fetches with service creds, bypassing user-level paywall (report #498166784, $133k Google VRP) |
| 11 | `status`, `state`, `approved` fields in PATCH/PUT responses | API response bodies, OpenAPI spec | Self-promotion via mass assignment on state fields (report #116404224, $50k Google VRP) |
| 12 | Cross-product integration features (export, share-to, embed) | Product feature matrix, "use in X" buttons | Integration endpoints leak identifiers or skip ACL (report #711198720, $313k Google VRP) |

## Auth Bypass Pattern Matrix

Patterns extracted from real disclosed reports — each row is a tested technique with a known payout:

| # | Pattern | Technique | Where to Test | Real Example |
|---|---------|-----------|---------------|--------------|
| 1 | Filter-vs-permission inversion | Negate client-side display flag (`single=false`) to widen server response scope | Any "publish subset" feature (tabs, slides, fields) | Google Sheets $1M — `single=true` was render filter, not authz (#924219904) |
| 2 | OAuth scope over-permission | Get token for innocuous scope, exhaustively call every API endpoint | Every OAuth provider with 10+ scopes | Google Cloud Print $313k — "Manage printers" scope read print job content (#724829696) |
| 3 | Unverified JWT email claim | Register via public Firebase/Cognito signup with victim's email, use unverified JWT | Any app trusting `email` claim without checking `email_verified` | Google partner portal $133k — Firebase `accounts:signUp` minted `@google.com` JWT (#372657152) |
| 4 | ACL propagation staleness | Change permission restrictive→permissive→restrictive, test between each | Any UI toggle for sharing/ACL/visibility | Google Apps Script $133k — deployment ACL change didn't invalidate serving cache (#489003520) |
| 5 | LLM confused deputy | Ask AI to summarize paywalled/restricted content by URL | Any LLM feature with URL ingestion | YouTube $133k — Gemini fetched members-only video with service creds (#498166784) |
| 6 | Lowest-role destructive action | As lowest role, replay admin's captured destructive request | Multi-tier role systems (Page roles, GitHub roles, IAM) | Meta — Analyst deactivated Page Shop; UI hid button but API accepted (#1014368010) |
| 7 | GraphQL mutation role bypass | Introspect schema, call privileged mutations from low-role session | Any SaaS with GraphQL + role-based staff accounts | Shopify $1.1k — `retailUserDataUpdate` callable by `Manage Locations` role (#1018094) |
| 8 | Cookie-based identity swap | Replace identity cookie (`UID`, `user_id`) with victim's numeric ID | Apps where cookie carries the identity-of-record | DoD — `UID2` cookie IDOR → password change → full ATO (#1004750) |
| 9 | Draft/pending state IDOR | Fetch non-published resource states (draft, scheduled, archived) cross-account | Any UGC platform with content lifecycle states | Meta — draft Facebook frames readable cross-account (#1044920083) |
| 10 | Disabled button bypass | Remove `disabled` attribute, submit the underlying API call | Every UI with grayed-out "Pro" or "Admin" features | Google $313k — disabled UI buttons had no server-side enforcement (#519110144) |
| 11 | Cross-product identifier leak | Follow integration/share/embed links, extract IDs from redirects and HTML source | Multi-product platforms (Google, Atlassian, Microsoft) | Google Forms $313k — edit ID leaked via cross-product helper redirect (#711198720) |
| 12 | Batch API field laundering | Chain sensitive-data-returning call with data-writing call in batch request | Any API supporting batch/chained requests | Facebook $24k — batch API leaked device trust cookie → full ATO (#3320995794) |
| 13 | CI/CD workflow trigger abuse | Submit PR to public repo with modified workflow that exfiltrates secrets | Public repos with GitHub Actions/CI configured | Google $3.1M — CI/CD trigger + permissions matrix on OSS repo (#716024320) |
| 14 | Internal API path exposure | Try `staging_dogfood`, `v1alpha`, `v1beta`, `internal` path prefixes | Any cloud API with versioned endpoints | Google $3.1M — `staging_dogfood` path retained internal fields (#139590656) |
| 15 | Identifier-chain entropy reduction | Map all RPCs that mint an identifier, check if minter lacks tenant scoping | Any API where object IDs gate access to sensitive data | Google $500k — chaining minter RPCs reduced ID entropy to brute-forceable (#373692928) |

## Role Confusion Matrix

Common role escalation paths observed across bug bounty programs:

| From Role | To Role | Technique | Condition |
|-----------|---------|-----------|-----------|
| Anonymous | Authenticated user | Public signup endpoint mints JWT with unverified claims | Firebase/Cognito API key exposed in client JS |
| Analyst/Viewer | Editor/Admin | Replay admin's captured mutation with viewer session | UI hides action but API accepts any Page member |
| Staff (limited perm) | Staff (POS/billing) | Call self-referencing mutation to toggle own permission flags | GraphQL mutation lacks per-field role check |
| OAuth app (narrow scope) | OAuth app (broad access) | Scope description understates actual API capabilities | Consent screen text ≠ backend enforcement |
| Tenant User A | Tenant User B | Substitute tenant/org ID in path or body parameter | Missing tenant-scoping on minter/resolver RPCs |
| Authenticated (post-2FA) | Authenticated (pre-2FA) | Change ACL to restrictive; cached session retains old permission | Permission propagation delay to serving layer |
| Low-tier plan | High-tier plan | Call gated API endpoint directly; UI blocks but server allows | Feature gating only in frontend JS |
| Device-trusted user | Any user's account | Steal device-trust cookie via batch API, use in recovery flow | Device trust token in API response body |

## Token / Session Attack Matrix

| Token Type | Attack | Technique | Impact |
|------------|--------|-----------|--------|
| Firebase ID JWT | Unverified email registration | `accounts:signUp` with victim email, no verification required | Auth as any `@domain.com` user (report #372657152) |
| OAuth access token | Scope capability audit | Get token for each scope, exhaustively test all API endpoints | Discover hidden API access beyond consent description |
| Session cookie | Identity parameter swap | Replace `UID`/`user_id` cookie value with victim's numeric ID | Full ATO when cookie is identity-of-record |
| Device trust cookie | Batch API extraction | Chain batch requests to leak device trust identifier | Account recovery bypass → ATO (report #3320995794) |
| Published URL token | Display filter negation | Modify `single=true` to `single=false` in shared URL | Access all tabs/slides/fields beyond intended subset |
| PRNG-generated ID | Predictability audit | Sample IDs across accounts, test for sequential/time-based patterns | Session hijack, IDOR at scale (report #326567424, $750k) |
| JWT with `alg` field | Algorithm confusion | Switch `RS256` → `HS256`, sign with public key as HMAC secret | Forge arbitrary JWTs (classic JWT attack) |
| API key in client JS | Direct API abuse | Extract key from JS bundle, call backend APIs directly | Bypass all client-side access controls |

## Pro Tips (Corpus-Evidenced)

1. **Audit OAuth scopes by API capability, not consent screen.** The consent screen is marketing copy. Get a token per scope and exhaustively call every endpoint — the divergence is where the bugs live. ($313k, report #724829696)

2. **Negate every client-side display flag in published/shared URLs.** `single=true`, `view=limited`, `tab=0` — these are often render filters, not authorization boundaries. ($1M, report #924219904)

3. **When an ACL change is made in a UI, verify propagation to the serving layer.** Toggle permissive→restrictive, then immediately test the old URL. Cache/CDN staleness is the bug. ($133k, report #489003520)

4. **For multi-tier roles, always test from the LOWEST tier.** Don't test admin→user; test analyst→admin. The lowest role is the one least tested by developers. (report #1014368010, Meta)

5. **Every `email` claim in a JWT needs an `email_verified` check.** If the IdP allows public signup, anyone can mint a JWT with any email. The fix-bypass opportunity: re-check after the original fix ships. ($133k, report #372657152)

6. **Cross-product integrations leak identifiers.** When Product A has a "use in Product B" button, the redirect/embed often includes the edit/admin identifier in a URL parameter or HTML source. ($313k, report #711198720)

7. **Batch/chained API requests can launder sensitive fields.** If a batch API lets request N+1 reference response fields from request N, any sensitive value in any API response becomes exfiltrable. ($24k, report #3320995794)

8. **Test every AI/LLM feature for confused-deputy access.** If the LLM fetches URLs with service credentials instead of user credentials, it bypasses every user-level access control. ($133k, report #498166784)

9. **Disabled UI buttons are smoke signals, not security boundaries.** Remove `disabled`, click, observe. Server-side enforcement is often missing entirely. ($313k, report #519110144)

10. **Map the identifier chain backwards.** For any high-entropy ID that gates access, find every RPC that *produces* that ID and check if the *input* to that RPC is tenant-scoped. ($500k, report #373692928)

## Composability

This skill composes with:
- `variant_hunting` — for each found gap, test variants on sibling endpoints
- `chain_building` — combine an auth gap with a state mutation for higher impact
- `cross_tenant_isolation` — when scope axis is detectable
