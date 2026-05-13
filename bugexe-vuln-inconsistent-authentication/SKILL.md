---
name: inconsistent_authentication
description: Detect and exploit authentication inconsistencies across surfaces, versions, products, and flows — the class-level gap between where auth IS enforced and where it ISN'T, independent of any single-layer bypass
depends_on: []
---

# Inconsistent Authentication Mechanisms

Authentication inconsistency is a class-level vulnerability: the gap between surfaces
where auth IS enforced and where it ISN'T. This is separate from any single-layer bypass
(JWT alg:none, weak password). For JWT/OIDC/token-specific attacks, see
`authentication_jwt.md`. This skill covers the INCONSISTENCY — the architecture-level
problem of auth not being uniform across all access paths to the same resource.

## Core Principle

A system's effective authentication strength equals its WEAKEST acceptance path. If 9 of 10
endpoints require JWT and the 10th accepts a static API key, the system's auth is static-key
strength. The inconsistency itself is the vulnerability, because:
- Security review effort is divided across primitives
- Audit logs are split (harder to correlate incidents)
- Token rotation/revocation crosses system boundaries
- New engineers don't realize all paths exist
- Attackers only need to find ONE weak path

## Authentication Inconsistency Matrix

| # | Surface A (Enforced) | Surface B (Weak/Missing) | Gap | How to Find |
|---|---------------------|--------------------------|-----|-------------|
| 1 | Web app (full session + MFA) | Mobile API (bearer token, no MFA) | MFA bypass via mobile endpoint | Proxy mobile app; replay requests to API without MFA step |
| 2 | REST API v3 (JWT + audience check) | REST API v1 (basic auth, no audience) | Legacy version accepts weaker primitive | Replace `/v3/` with `/v1/` or `/v2/` or `/beta/` in every blocked request |
| 3 | Main product endpoints | Sub-property/partner portal | Custom auth with less hardening | Enumerate subdomains; test each login flow independently ($50K Waymo, $133K partner-companion) |
| 4 | HTML form login (CSRF + rate limit) | Direct REST `POST /token` (no CSRF, no rate limit) | Brute-force via API bypass of web protections | Find token endpoints in JS bundles or OpenAPI specs; brute directly |
| 5 | Primary auth (Firebase JWT signed) | `email_verified` claim not checked | Unverified email accepted as identity | Register with victim email via identityToolkit; JWT `email_verified:false` accepted ($133K Google) |
| 6 | UI-gated OAuth consent screen | Direct `POST /oauth/authorize` replay | Skip UI interstitial that gates unverified emails | Capture authorize request; replay without browser UI ($1.5K GitLab via Salesforce) |
| 7 | REST endpoint (auth required) | Same-service gRPC/WebSocket handler | Non-HTTP protocols skip auth middleware | Test gRPC reflection, WebSocket upgrade with no auth header |
| 8 | Production environment | Staging/dev environment on same infra | Staging accepts debug credentials or no auth | Enumerate `staging.`, `dev.`, `test.`, `sandbox.` subdomains |
| 9 | External-facing gateway (JWT validated) | Internal service (trusts `X-User-Id` header) | Direct backend access or header injection bypasses JWT | Test `X-User-Id` / `X-Forwarded-User` header spoofing; find direct backend via SSRF |
| 10 | Frontend permission check (disabled button) | Backend RPC (no role check) | Client-side auth masquerading as server-side | Remove `disabled` in DevTools; replay RPC ($313K Google Search Console) |
| 11 | Single-request auth (token per request) | Batch/bulk endpoint (token checked once for batch) | Per-item auth missing in batch | Include cross-tenant IDs mid-array in batch requests |
| 12 | Browser session (SameSite cookie) | CLI/SDK client (bearer token, no SameSite) | Different transport = different auth model | Test API with raw curl; no cookie protections apply |
| 13 | OAuth code flow (PKCE enforced) | Implicit flow still enabled | `response_type=token` bypasses PKCE | Force `response_type=token` in authorize URL |
| 14 | Password reset (requires reset token) | Naked write endpoint (`POST /savepassword`) | No state-machine binding | Find via JS analysis; POST directly with email + new password ($7.5K Facebook) |

## Defense-Bypass Pairs

| # | Defense | Bypass | Test |
|---|---------|--------|------|
| 1 | JWT required on all endpoints | Legacy static API key still accepted on same endpoints | Send request with `X-API-Key` instead of `Authorization: Bearer` |
| 2 | MFA on web login | Mobile/API login path skips MFA challenge | Authenticate via mobile API; use token on web endpoints |
| 3 | PKCE S256 on authorize flow | Server accepts absent `code_verifier` or `plain` method | Omit `code_verifier` entirely from token exchange |
| 4 | Rate limit on login (per IP) | Rate limit key is client-controlled `device_id` | Same `device_id` across N accounts; birthday-attack on OTP space ($10K Instagram) |
| 5 | Secondary auth check (Referer validation) | `Referer: http://127.0.0.1` or `Origin: null` bypasses | Send debug Referer/Origin values ($50K Google, $50K VirusTotal) |
| 6 | Auth on main domain | Sub-property uses separate, weaker auth system | Enumerate sub-properties of major targets; each may have custom auth ($50K Waymo careers) |
| 7 | Firebase JWT signature validation | Backend does not check `email_verified` claim | Register unverified email via public signUp endpoint ($133K Google) |
| 8 | Search Console owner-only export | `disabled` HTML attribute on button; server trusts UI | Remove attribute; server has no role check ($313K Search Console) |
| 9 | OAuth `redirect_uri` whitelist | Whitelisted host has open redirect or XSS on `continue=`/`next=` | Find any weakness on whitelisted host; chain for token theft ($750K Google) |
| 10 | Account lockout after N failures | Lockout per-account but not per-device; aggregate across accounts | Distribute brute-force across M accounts sharing OTP space |

## Chain Patterns

| # | Base Finding | Chain With | Combined Impact | Reference |
|---|-------------|-----------|-----------------|-----------|
| 1 | Auth missing on API v1 | IDOR on same endpoint | Full data access via legacy version + ID swap | Structural — always test v1 when v3 is blocked |
| 2 | Firebase unverified email accepted | Domain-based role check (`@company.com` = admin) | Impersonate any employee via public signUp | $133K Google partner-companion |
| 3 | Sub-property weak auth (email = login) | Main platform account linked by email | ATO on main platform via sub-property weakness | $50K Waymo: email + blank name = logged in |
| 4 | OAuth `email_verified` gap on IdP | RP merges accounts by email from SSO assertion | ATO on all downstream services via IdP confusion | $1.5K GitLab via Salesforce admin-created user |
| 5 | Host header reflected in reset URL | Victim clicks poisoned link | Token theft to full ATO | $5K-$50K across programs (oslo.io, DoD) |
| 6 | Activation token signing oracle | Session token uses same signing format | Mint session for any user via registration oracle | $50K VirusTotal: register username = target's serialized blob |
| 7 | Client-side disabled button bypass | Persistent integration (export to BigQuery) | Ongoing data exfil surviving access revocation | $313K Search Console |
| 8 | Identification-as-authentication | No ownership proof required (no OTP/link) | Submit victim email alone = logged in as victim | $50K Waymo, $7.5K Facebook /savepassword |
| 9 | XSS on SSO-trusted domain | Token theft via postMessage or fragment | Full ATO via first-party token exfiltration | $750K Google redirect_uri chain |
| 10 | Rate-limit key is client-controlled | Birthday-attack across N accounts | Mass ATO via OTP aggregation | $10K Instagram device_id inversion |

## Cross-Surface Auth Audit Methodology

1. **Inventory every authentication primitive** the target accepts on ANY endpoint: session cookie, JWT, static bearer, API key header, basic auth, query-param token, custom header, client certificate
2. **Map primitive to endpoint**: which endpoints accept which primitives? Build a matrix of `endpoint x primitive -> 200/401/403`
3. **Count primitives per endpoint**: any endpoint accepting 2+ primitives is a class-level finding (the inconsistency itself)
4. **Test revocation cross-primitive**: logout/revoke primitive A -> does primitive B still work? (It usually does)
5. **Test version regression**: for every blocked endpoint, try `/v1/`, `/v2/`, `/beta/`, `/alpha/`, `/internal/`, `/legacy/`
6. **Test transport regression**: for every REST-authed endpoint, try the same action via gRPC, WebSocket, GraphQL subscription, message queue consumer
7. **Test sub-property divergence**: enumerate subdomains; test each login flow independently; sub-properties of major companies run weaker auth
8. **Test flow shortcuts**: for multi-step flows (login -> MFA -> dashboard), skip intermediate steps; POST directly to final endpoints
9. **Test minimum-input paths**: on every auth form, submit bare minimum (email only, blank fields, drop headers); observe if access granted
10. **Test conditional security paths**: `Referer: http://127.0.0.1`, `Origin: null`, debug headers — these bypass secondary checks left from dev config

## Distinguishing from Single-Layer Bypass

| Single-Layer (file separately) | Inconsistency (this skill) |
|-------------------------------|---------------------------|
| JWT `alg:none` bypass | JWT endpoint AND static-key endpoint both work |
| Weak session entropy | Session auth AND API-key auth coexist |
| Missing rate limit on one endpoint | Rate limit on web but not API |
| XSS stealing one token type | Two token types with different revocation |

File BOTH when both apply — they require different fixes.

## Pro Tips

1. **`/swagger.json` and `/openapi.json` declare `securitySchemes`** for multiple auth types — that is a documented indicator of inconsistency. Confirm the server actually accepts each declared scheme.
2. **Spam the same endpoint with every primitive shape in parallel.** Same body, different auth headers. Same response on multiple primitives = same codepath accepting both = class-level finding.
3. **Check if logout on primitive A invalidates primitive B.** It usually does not — that IS the impact argument. Demonstrate cross-primitive session persistence.
4. **Sub-properties are where the money is.** `legal.thefacebook.com`, `careers.withwaymo.com`, `partner-companion.cloud.google` — custom auth stacks with less review than the main product. Subdomain enumeration is step one.
5. **Every multi-step auth flow has a shortcut.** Password reset state machines, MFA enrollment, step-up challenges — test each XHR endpoint with no auth, partial auth, stale token, cross-user token. The highest-paying ATO bugs live in transitional flows.
6. **When a fix is deployed, audit the fix itself.** The $133K Google partner-companion bug was a BYPASS of a prior fix. The fix added JWT validation but missed `email_verified`. Ask: what did the fix add, and what did it NOT add?
7. **API explorers and "Try it!" buttons** use your OAuth session but may bypass client-id restrictions. Google's API Explorer accepted YPP-tied accounts on APIs documented as CMS-only ($1.3M YouTube).
8. **Activation/invitation email tokens often share signing infrastructure with session tokens.** If you can control what gets signed (via registration username), you can mint session tokens for other users ($50K VirusTotal).
9. **Test identification vs authentication on every endpoint.** A public API key baked into an APK is identification, not authorization. If any endpoint treats it as auth for writes, that is a bypass ($50K Firebase Dynamic Links).
10. **Document the inconsistency as architecture, not as a single endpoint.** Map which primitives work where, show the revocation gap, show the audit-log split. The class-level framing elevates severity from "one endpoint missing auth" to "systemic authentication architecture failure."

## Summary

Authentication inconsistency is the gap between where auth IS and where it ISN'T — across API versions, transport protocols, product surfaces, UI vs backend, and authentication primitives. The system's effective strength equals its weakest acceptance path. Audit every path independently: version regression, transport regression, sub-property divergence, flow shortcuts, minimum-input paths, and conditional security bypasses. The finding is the inconsistency itself, not any single bypass.
