---
name: cross-tenant-isolation
category: methodology
description: Test isolation across the tenancy axis — every multi-tenant resource needs verified scope enforcement
depends_on: []
---

# Cross-Tenant Isolation

Multi-tenant systems must isolate state across the tenancy axis. The axis
varies: tenant, organization, workspace, branch, team, namespace, account,
project, customer scope. The methodology is universal: detect the axis,
enumerate principals belonging to different scopes, test crossing.

## When to Use

- Any target with multi-tenant architecture (most B2B SaaS, multi-tenant
  platforms with regulated or scoped data, multi-actor systems with
  shared state)
- After surface discovery has produced endpoint inventory
- When you have credentials for at least two principals with DIFFERENT scope IDs

## Inputs (all runtime-derived)

- **TENANT_AXIS_PATTERNS** — path patterns with a scope identifier in the URL:
  - `/{scope_label}/{id}/...` where `scope_label ∈ {tenant, org, workspace, branch, account, customer, namespace, project, team, space}`
  - Plus any custom path segment that pairs with an ID pattern
- **TENANT_AXIS_FIELDS** — response fields holding scope identifiers:
  - Field names matching `*_id` where:
    - The field name semantically suggests scope (`tenant_id`, `org_id`, `workspace_id`, `branch_id`)
    - Or, two principals in `credential_inventory` have DIFFERENT values for the same field (empirically scope-defining)
- **PRINCIPALS** = `scan_config.credential_inventory`, ideally with at least
  two principals having different scope IDs

## Detect The Tenancy Axis

### Method 1: URL-based detection

Collect all discovered endpoints. Look for paths matching:

```
/<segment>/{id_pattern}/<rest>
```

Where `<segment>` is a noun-like segment and `{id_pattern}` is `[0-9]+`,
`[a-f0-9-]{36}` (UUID), or `[a-z0-9]{8,}` (slug).

If many endpoints share the same `<segment>` prefix with varying IDs, that
segment is likely the scope axis. Examples (all generic):
- `/orgs/{id}/...`, `/workspaces/{id}/...`, `/projects/{id}/...`,
  `/spaces/{id}/...`, `/tenants/{id}/...`, `/teams/{id}/...`,
  `/branches/{id}/...`, `/accounts/{id}/...`, `/customers/{id}/...`

### Method 2: Field-based detection

If endpoints don't expose tenancy in URL, extract response bodies. For each
response, find fields ending in `_id` (or `_uuid`, `_slug`). Compare the
SAME field across responses for different principals:

```
Login as principal A → GET /me → response.profile.org_id = "abc"
Login as principal B → GET /me → response.profile.org_id = "xyz"
```

If two principals consistently have DIFFERENT values for `org_id`, then
`org_id` is the scope axis.

### Method 3: JWT/session claim inspection

Decode JWTs from credential_inventory. Compare claims across principals:

```
Principal A's JWT claims: { "sub": 123, "org": "abc", "scope": "premium" }
Principal B's JWT claims: { "sub": 456, "org": "xyz", "scope": "free" }
```

If a claim varies across principals, it's a candidate scope.

## Test Matrix Per Axis

Once axis is detected, enumerate cross-axis tests:

### Test 1: READ across the axis

```
For each (principal P with scope S) × (resource R scoped to S' ≠ S):
  GET resource_url(R) as P
  Expected: 403 or 404 (proper scope isolation)
  Observed: if 200 with R's data → cross-tenant read = bug
```

### Test 2: WRITE across the axis

```
For each (principal P with scope S) × (resource R scoped to S' ≠ S) × (write_method ∈ {POST, PUT, PATCH, DELETE}):
  Send write_method to resource_url(R) as P with valid body
  Expected: 403
  Observed: if 2xx and refetch confirms mutation → cross-tenant write = bug
```

### Test 3: LIST across the axis

```
For each (principal P) × (list_endpoint scoped to S' ≠ P's scope):
  GET list_endpoint as P with S' substituted in URL or filter param
  Expected: filtered to P's scope OR 403
  Observed: if returns S''s items → cross-tenant list = bug
```

### Test 4: CREATE-CROSS-TENANT

For state-changing endpoints with a body field that looks like a scope target
(`tenant_id`, `org_id`, `target_workspace_id`):

```
As principal P with scope S:
  POST {endpoint} { "tenant_id": "S'" }  ← S' ≠ S
  Expected: 403 (cannot create in S')
  Observed: if 2xx and resource appears in S' → cross-tenant create = bug
```

This is distinct from BOLA — many systems gate READ but not CREATE-with-arbitrary-tenant-id.

### Test 5: ROLE-WITHIN-SCOPE escape

If the system has both roles AND scope, test if a role bound to scope S
can operate on scope S':

```
Principal P has role X within scope S.
P attempts role X's operations on scope S'.
Expected: P unauthorized for S' regardless of role.
Observed: if P succeeds on S' → role-scope coupling broken
```

## Output Format

```
Tenancy axis: {scope_field_or_path_segment}
Test class: {READ | WRITE | LIST | CREATE-CROSS-TENANT | ROLE-WITHIN-SCOPE}
Principal scope: {own_scope_id}
Target scope: {peer_scope_id}
Endpoint: {METHOD} {path}
Expected: {403 | 404 | empty result}
Observed: {actual_status_and_body_excerpt}
Evidence: {request} → {response}
```

## Discovery Signals

| # | Signal | Where to Find | Why Vulnerable |
|---|--------|---------------|----------------|
| 1 | `org_id` / `tenant_id` / `workspace_id` in request body | Burp proxy history | Client-controlled scope identifier -- swap to cross-tenant (Report #1002197671) |
| 2 | B2B SaaS with "Business" or "Enterprise" tier | Pricing page, feature flags | Multi-tenant management endpoints often under-tested (Report #1063022: Uber cross-tenant IDOR) |
| 3 | GraphQL mutations accepting user/org ID params | Introspection, network logs | GraphQL operations may check response but not side effects (Report #1085042: Shopify Plus) |
| 4 | CORS with `Access-Control-Allow-Credentials: true` | Response headers | Credentialed cross-origin requests on multi-tenant platform (Report #1006524) |
| 5 | Invitation/join flow with token | Email links, signup flow | Token validates invitation but not acceptor-to-tenant binding (Report #1063022) |
| 6 | Role/permission assignment endpoint | Admin panel, API docs | Role scoped to tenant A operates on tenant B (Report #1004181607) |
| 7 | TLS certificate on raw IP (forgotten surface) | cert.sh, Shodan | Forgotten on-prem instances with admin access (Report #1004110336: $50K Plastic SCM) |
| 8 | Organizational secret in API response (API keys, tokens) | Burp response body | Secrets leaked via cross-org endpoint (Report #1087489: $50K GitHub token exposure) |
| 9 | Ad/marketing platform with campaign management | TikTok/FB/Google Ads | Every campaign endpoint is a cross-tenant IDOR candidate (Report #1018608) |
| 10 | Session listener iterating over accounts/tenants | WebSocket, event-stream | Session-scope leak: listener exposes cross-tenant data (Report #1061591) |
| 11 | FQDN-based tenant routing | Subdomain per tenant | Hostname normalization mismatch bypasses routing (Report #1086108) |
| 12 | Acquisition-integrated subdomain | WHOIS, crunchbase | Acquired company's domains share auth but not authz (Report #1089502) |

## Technique Matrix

| # | Technique | When | How |
|---|-----------|------|-----|
| 1 | Two-tenant signup + CRUD replay | Any B2B SaaS | Create two tenants, capture all requests from A, replay with B's IDs (Report #1063022) |
| 2 | Side-effect channel probing | GraphQL/API returns error | Check email/webhooks/audit logs despite 403 response (Report #1085042: Shopify Plus) |
| 3 | Invitation token binding test | Invite flow exists | Accept tenant B's invitation as tenant A user -- check if binding validates (Report #1063022) |
| 4 | Burp Match-and-Replace for tenant ID | High endpoint count | Auto-swap `org_id` in every request for passive cross-tenant testing |
| 5 | CORS credentialed request from subdomain | CORS headers observed | Subdomain with XSS or controlled content makes credentialed fetch (Report #1006524) |
| 6 | FQDN canonicalization bypass | Hostname-based tenant routing | Trailing dot, case, IDN, double-dot normalization (Report #1086108) |
| 7 | Role-scope decoupling test | Roles + tenants coexist | Role X in scope S attempts operations on scope S' (Test 5 above) |
| 8 | CREATE-with-foreign-tenant-id | State-changing endpoint with body | POST with `tenant_id: foreign_id` -- many systems gate READ but not CREATE (Test 4 above) |
| 9 | Ad platform endpoint enumeration | Marketing/ad product | Enumerate every campaign/ad-group/pixel endpoint with cross-account IDs (Report #1018608) |
| 10 | Acquisition subdomain audit | Target has acquired companies | Enumerate acquired domains, test auth sharing without authz sharing (Report #1089502) |

## Defense-Bypass Pairs

| Defense | Bypass | Example |
|---------|--------|---------|
| Response-level authorization check | Side effect executes before check | Email sent despite 403 response (Report #1085042: Shopify Plus) |
| Tenant ID validated in URL path | Tenant ID in body not validated | `POST /api/resources` with `{"org_id": "foreign"}` accepted |
| Role-based access control | Role not scoped to tenant | Manager of tenant A can manage tenant B (Report #1004181607) |
| CORS origin allowlist | Subdomain wildcard `*.target.com` | XSS on any subdomain = cross-tenant via CORS |
| FQDN string comparison for routing | Trailing dot `tenant.target.com.` | RFC-valid FQDN bypasses string equality (Report #1086108) |
| Invitation token validation | Acceptor-tenant binding missing | Token validates invitation but any user can accept (Report #1063022) |
| Webhook URL restricted to tenant | Sub-role can change webhook target | Exfiltrate transaction data to attacker URL (Report #1046697) |
| Sequential ID hidden behind UUID | UUID leaked in other endpoint | Cross-reference list endpoints to harvest foreign UUIDs |

## Chain Patterns

| Chain | Step 1 | Step 2 | Impact |
|-------|--------|--------|--------|
| Cross-tenant IDOR -> full ATO | Swap business ID in role-change endpoint | Escalate to admin of victim tenant | Complete tenant takeover (Report #1063022) |
| Side-effect leak -> targeted phishing | GraphQL mutation leaks victim PII via email | Use PII to craft spear-phish | Social engineering with confirmed identity |
| Invitation hijack -> persistent access | Accept foreign tenant invitation | Attacker now has legitimate access to victim org | Persistent insider access |
| Cross-tenant + missing audit trail | Modify foreign tenant data | No audit log of cross-tenant mutation | Undetectable data tampering |
| FQDN bypass + admin panel access | Normalization bypass reaches admin route | Admin of tenant A via tenant B's hostname | Cross-tenant admin access |
| Acquired-subdomain + SSO pivot | Authenticate via acquired company SSO | Access parent company resources without authz | Horizontal escalation via M&A debt |
| Secret leak + API abuse | Cross-org endpoint leaks API key | Use leaked key for tenant impersonation | $50K -- Report #1087489 |
| Webhook redirect + data exfil | Change webhook target to attacker URL | All transaction data forwarded to attacker | Financial data theft |

## Pro Tips from Corpus

1. **Cross-tenant IDOR is the highest-value bug class on B2B SaaS.** Always sign up for two tenants, map every endpoint with a tenant identifier, test every CRUD operation cross-tenant (Report #1063022).
2. **Don't trust the error response.** Side effects (emails, webhooks, audit entries, push notifications) may execute despite a 403 -- always check secondary channels (Report #1085042: Shopify Plus).
3. **Invitation flows are chronically weak.** Token validates the invitation but not the acceptor-tenant binding. Test: can user from tenant A accept tenant B's invite? (Report #1063022).
4. **FQDN normalization is an attack surface.** Trailing dot, case variations, IDN encoding -- anywhere hostnames are compared as strings for tenant routing (Report #1086108).
5. **Acquisition-driven subdomain enumeration pays.** Acquired companies share auth backends but not authorization boundaries (Report #1089502).
6. **Ad/marketing platforms have the densest IDOR surface.** Every campaign, ad group, pixel, and audience endpoint accepts a tenant-scoped ID (Report #1018608).
7. **Organizational secrets > personal secrets.** Cross-org API key/token exposure has disproportionate bounty value because it affects entire organizations (Report #1087489: $50K).
8. **CREATE-CROSS-TENANT is the most-missed test class.** Many systems gate READ but forget to validate `tenant_id` on creation endpoints (Test 4 above).

## Anti-Patterns

- **Assume the axis is `user_id`**: user-scope is one axis, but most multi-tenant bugs are at the ORG/TENANT/WORKSPACE axis, not per-user.
- **Skip CREATE-CROSS-TENANT**: this is the highest-yield class -- many systems forget to validate `tenant_id` on creation.
- **Test only READ**: cross-tenant WRITE bugs are far more impactful (data destruction, state mutation in another tenant).
- **Hardcode axis terminology**: never assume the axis is called "tenant" or "org" or "branch". Detect from runtime data.
- **Skip ROLE-WITHIN-SCOPE**: this catches the bug where "Manager of branch A can manage branch B" or "Editor of workspace A can edit workspace B".

## Composability

- `auth_matrix_systematic` -- cross-tenant tests are matrix cells with axis substitution
- `bola_systematic_enumeration` -- vocabulary skill for BOLA fundamentals
- `variant_hunting` -- once one cross-tenant gap found, test variants on every endpoint with the same axis
- `business_logic` -- vocabulary skill for non-cookie-cutter authorization logic
