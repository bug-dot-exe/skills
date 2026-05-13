---
name: negative_testing
description: Systematic detection of absent security controls — missing authorization, validation, rate limiting, and audit logging through exhaustive negative probing
depends_on: []
---

# Negative Testing

Taint analysis and fuzzers find vulnerabilities where data flows from source to sink. But many critical security flaws are not present code — they are absent code. A missing authorization check, a missing rate limit, a missing input validation — the absence of a control — cannot be found by tracing data flow. This skill teaches systematic detection of what is NOT there.

## When to Use

- After endpoint discovery and initial recon, before deep vulnerability testing
- When the target has authenticated workflows with multiple roles or privilege levels
- When the target exposes API endpoints that accept user-controlled parameters
- As a foundation for coverage_matrix — negative testing populates the matrix with control-absence findings

---

## Phase 1: Access Matrix Construction

Build a matrix of (endpoint x method x auth context) and test every cell. The goal is to find endpoints that fail to enforce authorization at all.

### Step 1: Enumerate All Endpoints

Combine all discovery sources (proxy history, API docs, JS bundles, HTML forms, 404/405 probing, sitemap/robots.txt) into a deduplicated list of (method, path, known parameters).

### Step 2: Enumerate Authentication Contexts

Every test must be run from each context:

| Context | Description |
|---------|-------------|
| NONE | No authentication header/cookie |
| EXPIRED | Revoked or timed-out token/session |
| LOW_PRIV | Lowest-privilege authenticated account |
| SAME_PRIV | Different account at the same privilege level as the resource owner |
| ELEVATED | Higher privilege than standard (staff, moderator) |
| ADMIN | Highest-privilege account |

If the target supports API keys, OAuth scopes, or token types alongside session auth, treat each mechanism as a separate context axis.

### Step 3: Build and Execute the Matrix

For every (endpoint, method, context) triple:

1. Send the request with that context's credentials
2. Record HTTP status and response signature (success, error, redirect)
3. Compare against expectations: admin-only endpoints MUST reject NONE/EXPIRED/LOW_PRIV/SAME_PRIV; user-scoped endpoints MUST reject NONE/EXPIRED/SAME_PRIV; public endpoints should succeed from any context
4. Flag every cell where the response indicates unexpected success (200, 201, data returned)

### Step 4: Track Coverage

```
Access Matrix: [N]/[total] cells tested ([%]), [N] violations (unexpected success)
  NONE: [N] violations  EXPIRED: [N]  LOW_PRIV: [N]  SAME_PRIV: [N]
```

---

## Phase 2: Absent Validation Detection

For every input parameter, test whether ANY server-side validation exists. The goal is not to find a specific injection — it is to identify parameters accepted raw without any check.

### Step 1: Inventory All Parameters

From Phase 1 endpoints, extract every parameter with its location (path/query/body/header), observed type, and observed constraints.

### Step 2: Probe Each Parameter

For each parameter, send these probe values to detect whether the server validates at all:

| Probe Class | Values | What Absence Means |
|-------------|--------|-------------------|
| **Empty** | `""`, `null`, missing key | No presence check |
| **Type mismatch** | String where integer expected, array where string expected | No type enforcement |
| **Oversized** | 10x expected length, 1MB string in a name field | No length limit |
| **Boundary** | 0, -1, MAX_INT, MAX_INT+1 for numerics | No range validation |
| **Special chars** | `<>'";\|` `../` `{{` `${` | No character filtering |
| **Format violation** | `not-an-email` in email field, `abc` in date field | No format validation |

### Step 3: Classify Results

| Classification | Meaning | Finding? |
|----------------|---------|----------|
| **VALIDATED** | Server returns clear validation error (400) | No — control exists |
| **SILENTLY ACCEPTED** | Server returns 200 with invalid value stored/processed | Yes — no validation |
| **COERCED** | Server silently converts value (string "abc" becomes 0) | Potential — coercion can mask logic bugs |
| **IGNORED** | Server returns success but invalid value has no observable effect | Needs deeper investigation |

Flag every SILENTLY ACCEPTED parameter. Special attention to: ID parameters (IDOR signal), numeric parameters (overflow/arithmetic abuse), string parameters (injection surface).

### Step 4: Track Coverage

```
Validation: [N]/[total] parameters tested ([%]), [N] silently accepted, [N] coerced
```

---

## Phase 3: Missing Rate Limit Detection

Identify sensitive operations and test whether the target enforces any request throttling.

### Step 1: Identify Rate-Sensitive Operations

| Category | Why Rate Limiting is Required |
|----------|-------------------------------|
| Authentication (login, password reset, OTP verify) | Brute force prevention |
| Account creation (registration, invite) | Enumeration, spam |
| Secret generation (API key create, token refresh) | Resource exhaustion |
| Value-bearing state mutation | Quantity / allocation abuse |
| Resource creation (file upload, post creation) | Storage/compute exhaustion |
| Lookup by identifier (user search, email check) | Enumeration |

### Step 2: Execute Rapid Request Sequences

For each sensitive operation, send 50 identical requests in rapid succession. Record: how many succeed, response time trend, rate limit headers (X-RateLimit-*, Retry-After). If all 50 succeed with no throttling indicators: the control is absent.

### Step 3: Distinguish Rate Limit Granularity

If a rate limit IS detected, probe its granularity by rotating: source IP (per-IP only?), credentials (per-account only?), endpoint path aliases (per-path only?), HTTP method (per-method only?), query parameters (cache-based only?). Any single-axis rate limit is bypassable.

### Step 4: Track Coverage

```
Rate Limits: [N]/[total] sensitive ops tested, [N] unprotected, [N] weak (bypassable)
```

---

## Phase 4: Absent Audit Trail Testing

Detect sensitive operations that leave no observable trace.

### Step 1: Identify Auditable Operations

| Category | Operations |
|----------|-----------|
| Authentication events | Login, logout, failed login, password change, MFA enrollment/removal |
| Authorization changes | Role assignment, permission grant/revoke, group membership change |
| Data modification | Profile update, email change, account deletion, data export |
| Value-bearing state mutations | Quantity transfers, reversals, subscription changes, allocation adjustments |
| Administrative actions | User suspension, configuration change, feature toggle |
| Security events | API key creation/revocation, session invalidation, IP allowlist change |

### Step 2: Perform Each Operation and Check for Trail

For each auditable operation: perform it through the normal API, then check for observable evidence — email notifications, activity/audit log entries, admin dashboard entries, response headers (X-Request-Id, X-Trace-Id), account activity page. If NONE are observable: the audit trail is absent.

### Step 3: Track Coverage

```
Audit Trails: [N]/[total] auditable ops tested, [N] logged, [N] no observable trail
```

---

## Phase 5: Missing Security Headers

Check headers (CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy, Permissions-Policy) across ALL endpoint categories, not just the homepage. Sample from: API endpoints, error pages (404, 500), static assets, redirect responses (3xx), and auth endpoints. The most actionable finding is "header present on most endpoints but missing on specific ones" -- a middleware gap.

```
Security Headers: [N] endpoints sampled, [N] fully protected, [N] inconsistencies
```

---

## Phase 6: Absent CSRF Protection

For every state-changing endpoint, test whether the request succeeds without a CSRF token.

### Step 1: Identify State-Changing Endpoints

Filter Phase 1 endpoints to POST, PUT, PATCH, DELETE. Also include any GET that triggers a side effect.

### Step 2: Test Token Removal

For each state-changing endpoint: (1) capture a legitimate request with valid CSRF token, (2) replay with token removed, (3) replay with arbitrary token value, (4) replay with token from a different session. If any replay succeeds: the protection is absent.

### Step 3: Test Protection Mechanism Type

If CSRF protection IS detected, identify and probe the mechanism:

| Mechanism | Bypass to Test |
|-----------|---------------|
| Synchronizer token (hidden field) | Token reuse across sessions |
| Double-submit cookie | Cookie injection via subdomain |
| SameSite cookie attribute | Cross-origin from same-site subdomain |
| Custom header requirement | Check value validation vs presence-only check |
| Referer/Origin check | Referer suppression via Referrer-Policy |

```
CSRF: [N]/[total] state-changing endpoints tested, [N] unprotected, [N] weak
```

---

## Phase 7: Missing Object-Level Authorization (BOLA)

Systematically test whether every endpoint with an object identifier enforces ownership.

### Step 1: Inventory All ID Parameters

From the endpoint inventory, extract every parameter that references an object. Note the ID format (sequential integer, UUID, opaque token) — sequential IDs are trivially enumerable.

### Step 2: Test Every ID Parameter

Authenticate as user A, then for each ID parameter:

1. Access user A's own resource (baseline — should succeed)
2. Replace ID with user B's resource ID (should fail with 403 or 404)
3. Replace ID with a non-existent resource ID (should fail with 404)
4. Compare responses between steps 2 and 3: different errors (403 vs 404) leak object existence — an enumeration finding even if data is not returned

### Step 3: Test Beyond GET

BOLA is not limited to read operations. For each resource, test all methods:

| Method | Impact if Unprotected |
|--------|----------------------|
| GET | Data exposure |
| PUT/PATCH | Data tampering |
| DELETE | Data destruction |
| POST (sub-resource) | Privilege injection |

Do NOT stop at the first IDOR. Test ALL ID parameters across ALL endpoints.

```
BOLA: [N]/[total] ID params tested, [N] exposed, [N] write-exposed, [N] enumerable
```

---

## Phase 8: Coverage Reporting and Gap Handoff

After completing all phases, emit a consolidated report that drives the coordinator to spawn follow-up agents for uncovered areas.

### Consolidated Coverage Report

```
=== Negative Testing Coverage Report ===
Phase 1 - Access Matrix:    [N]/[N] cells ([%]), [N] violations
Phase 2 - Validation:       [N]/[N] params ([%]), [N] no validation
Phase 3 - Rate Limits:      [N]/[N] ops, [N] unprotected
Phase 4 - Audit Trails:     [N]/[N] ops, [N] no trail
Phase 5 - Security Headers: [N] sampled, [N] inconsistencies
Phase 6 - CSRF:             [N]/[N] endpoints, [N] unprotected
Phase 7 - BOLA:             [N]/[N] IDs, [N] exposed
Total absent controls: [N]
```

### Integration with Other Skills

| Discovery | Follow-Up | Skill |
|-----------|----------|-------|
| Missing authz (access matrix violations) | Deep exploitation of unprotected endpoints | auth_bypass_hunter |
| Unvalidated parameters | Injection testing on raw pass-through params | coverage_matrix |
| Missing rate limits on auth endpoints | Credential brute force campaigns | chain_building |
| BOLA on ID parameters | Systematic IDOR exploitation across all objects | coverage_matrix |
| Missing CSRF protection | Cross-site state manipulation | chain_building |
| Missing audit trails | Stealth exploitation chains (no detection) | chain_building |
| Absent security headers | XSS via missing CSP, clickjacking via missing X-Frame-Options | variant_hunting |

### Handoff Artifacts

1. **Control absence inventory** — every absent control with endpoint, type, and severity
2. **Untested gap list** — cells in each matrix that remain untested (for follow-up agent assignment)
3. **Validation map** — per-parameter classification (validated, silently accepted, coerced)
4. **BOLA exposure map** — per-resource authorization enforcement status across all methods

---

## Discovery Signals

| # | Signal | Where to Find | Why Vulnerable |
|---|--------|---------------|----------------|
| 1 | Different error text for "invalid user" vs "invalid pass" | Login response body/timing | Username enumeration oracle (Report #1069388) |
| 2 | `Integer.parseInt` / `Float.parseFloat` in stack trace | Error responses, 500 pages | Parse-without-catch -- malformed input crashes handler (Report #1061211) |
| 3 | CSRF token in form but no server validation | Replay with token removed | Three failure modes: missing, empty, wrong value (Report #1003468) |
| 4 | POST-reflected user input in HTML | Burp response, search results | POST-reflected XSS via auto-submitting hidden forms (Report #1003433) |
| 5 | Regex-based security filter | JS source, WAF response | Most permissive interpretation test (Report #1047447) |
| 6 | Geographic/physical-world data fields | API docs, form fields | Impossible values accepted: negative distances, 999 lat/lon (Report #1064149) |
| 7 | Domain-based filter/block | URL params, redirect logic | Trailing dot, case, FQDN normalization bypasses (Report #1068505) |
| 8 | CI/CD pipeline task execution | Build configs, webhook endpoints | Task-to-control-plane boundary leakage (Report #1032363324) |
| 9 | Session/cookie on login | Set-Cookie header | Session lifecycle not tested at every state transition (Report #1069392) |
| 10 | Mobile app storing "private" data locally | APK decompile, traffic intercept | Device-boundary trust assumption violation (Report #1038190877) |
| 11 | Internal tool accessible from external surface | Subdomain enum, JS bundles | Internal/external surface boundary leakage (Report #1026460314) |
| 12 | Automated tool returning no results | sqlmap/Intruder output | Tool failure -- switch to manual exploitation (Report #1066007) |

## Technique Matrix

| # | Technique | Target | How |
|---|-----------|--------|-----|
| 1 | Error message differential | Login, password reset, signup | Compare text/timing/status/length for valid vs invalid inputs (Report #1069388) |
| 2 | Parse-without-catch fuzzing | Every endpoint accepting typed input | Send malformed values to every parser: parseInt, JSON, date, float (Report #1061211) |
| 3 | Triple CSRF probe | Every state-changing endpoint | No token, empty token, wrong token -- observe each response (Report #1003468) |
| 4 | Negative response-code filtering | Parameter fuzzing | `--hc=400` finds valid params; `--mc=200` misses (Report #1068434) |
| 5 | Regex English translation | Any regex-based filter | Write regex as English, ask "most permissive input?" (Report #1047447) |
| 6 | Impossible value injection | Geo, quantity, date fields | Negative distance, 999 coordinates, dates in 1970/2099 (Report #1064149) |
| 7 | FQDN normalization sweep | Domain filters, CORS checks | Trailing dot, case, IDN, double-encoded, Unicode homoglyph (Report #1068505) |
| 8 | Session state matrix | Login, logout, password change | Test all state transitions for session invalidation (Report #1069392) |

## Defense-Bypass Pairs

| Defense | Bypass | Example |
|---------|--------|---------|
| Login error: "invalid credentials" (generic) | Timing differential still leaks user existence | 200ms for valid user + wrong pass vs 50ms for invalid user |
| Client-side type validation (JS) | Direct API request bypassing client | Send string where integer expected, observe server (Report #1038190877) |
| Regex denylist filter | Write regex as English, find permissive input | `[^a-z]` doesn't block uppercase, unicode, null bytes (Report #1047447) |
| CSRF token required | Empty string accepted as valid | Some frameworks check presence, not value (Report #1003468) |
| Rate limit after 100 requests | Rotate IP via proxy chain | Single-axis rate limit bypassable (Report #1068434) |
| Domain allowlist (string compare) | Trailing dot `domain.`, FQDN normalization | RFC allows trailing dot; string compare fails (Report #1068505) |
| Automated tool detects "no vuln" | Switch to manual exploitation | Tool failures are common; manual finds what tools miss (Report #1066007) |
| POST-only endpoint (no reflected XSS) | Auto-submitting hidden form | POST reflection is exploitable in practice (Report #1003433) |

## Chain Patterns

| Chain | Step 1 | Step 2 | Impact |
|-------|--------|--------|--------|
| Error oracle + credential brute | Enumerate valid usernames via error diff | Brute-force known users with common passwords | Account takeover |
| Missing CSRF + state mutation | Confirm no CSRF enforcement | Craft auto-submitting form for victim | Cross-site state manipulation |
| Parse crash + DoS | Send malformed input to crash handler | Repeat across all endpoints sharing parser | Application-wide DoS |
| Missing rate limit + OTP brute | Confirm no throttle on OTP verify | Brute 4-6 digit OTP in seconds | MFA bypass |
| Absent audit trail + stealth exploit | Confirm no logging on sensitive action | Chain with any other exploit | Undetectable attack |
| Missing validation + SQLi | Confirm parameter accepted raw | Inject SQL via unvalidated param | Data exfiltration |
| Domain normalization + SSRF | Bypass domain filter via trailing dot | Reach internal service | Internal network access |
| Session lifecycle gap + ATO | Password change doesn't invalidate sessions | Attacker's stolen session persists | Persistent access |

## Pro Tips from Corpus

1. **Use negative response-code filtering for fuzzing**, not positive-status filtering. `--hc=400` finds all valid parameters; `--mc=200` misses edge cases (Report #1068434).
2. **Error message differential is universal.** Test every login form for response text, timing, status code, and response length differences between valid and invalid inputs (Report #1069388).
3. **Parse-without-catch is a cross-language audit.** `Integer.parseInt`, `Float.parseFloat`, JSON parsers, date parsers, URL parsers -- all throw on malformed input. Enumerate every parser in the stack (Report #1061211).
4. **Write every regex as English** and ask "what's the most permissive input an attacker could construct that this regex allows?" (Report #1047447).
5. **Test geographic APIs with impossible values.** Coordinates outside valid ranges, negative distances, altitudes above atmosphere -- physical-world constraints are rarely enforced server-side (Report #1064149).
6. **When automated tools fail, switch to manual.** Tool failures often indicate interesting edge cases the tool cannot handle -- that is exactly where bugs live (Report #1066007).
7. **Session lifecycle has a test matrix.** Login, logout, password change, email change, MFA enroll/remove -- each trigger should invalidate other sessions. Test the full matrix (Report #1069392).
8. **Three CSRF probes per endpoint, minimum.** No token, empty token, wrong token. Different failures reveal different enforcement levels (Report #1003468).

## Common Failure Modes

| Failure | Why It Happens | Mitigation |
|---------|---------------|------------|
| Testing only the homepage for headers | Agent checks one page and declares present/absent | Sample from every endpoint category |
| Checking only GET for BOLA | Agent finds read-IDOR and stops | Always test PUT, PATCH, DELETE on every exposed resource |
| Accepting client-side validation as server-side | Agent sees a JS error and assumes server validates | Always send raw requests bypassing the client |
| Stopping rate limit tests at 10 requests | Agent sends a small burst and sees no limit | 50+ requests minimum; some limits trigger at higher thresholds |
| Treating 403 as "protected" without verifying | Agent sees 403 and moves on | Check if 403 is enforced consistently across all methods |
| Missing enumeration oracles | Agent sees 404 and assumes no BOLA | Compare error responses: "forbidden" vs "not found" leak object existence |
