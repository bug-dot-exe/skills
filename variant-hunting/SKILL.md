---
name: variant-hunting
category: methodology
description: After finding one bug, systematically hunt for variants across endpoints, parameters, and features
depends_on: []
---

# Variant Hunting

One confirmed bug signals the same class likely exists elsewhere. Developers repeat patterns. Variant hunting extracts maximum value from every finding.

## When to Use

- Immediately after confirming any vulnerability
- When you find a pattern that could repeat across the codebase
- When a fix is applied to one endpoint but similar endpoints remain untested

## Five Variant Dimensions

### 1. Same Bug, Other Endpoints

If IDOR on `GET /api/users/{id}/profile`, check `/settings`, `/billing`, `/files`, and all PUT/DELETE variants. List every endpoint sharing the same object type or parameter name.

### 2. Same Bug, Different Parameters

If mass assignment works by adding `role` to a PUT body, also try: `isAdmin`, `permissions`, `plan`, `tier`, `status`, `verified`. Try nested objects and array variants.

### 3. Same Bug Class, Different Features

If auth flow has a flaw, check all auth-adjacent flows: login, registration, password reset, email change, MFA, OAuth, API keys. Group features by category and test the entire group.

### 4. Same Bug, Different Auth States

| Original | Also Test |
|----------|-----------|
| IDOR as USER_A vs USER_B | IDOR as UNAUTH (highest severity variant) |
| Admin function as USER | Same function as UNAUTH |
| CSRF on user action | CSRF on admin action |

Always test the unauthenticated variant. It is often the highest severity version.

### 5. Bypass of the Fix

After a fix or partial control exists, test:
- Other content types (JSON vs form-data vs multipart)
- Alias fields (`id` vs `userId` vs `user_id`)
- Create vs update paths (validation on one but not the other)
- Client-side vs server-side enforcement
- Allowlist/blocklist edge cases (unicode, double encoding, case)
- REST vs GraphQL vs WebSocket equivalents

## Workflow

```
1. Confirm original finding

2. For each of the 5 dimensions:
   a. List variant candidates
   b. Test each with the same technique as the original
   c. Record: FOUND / CLEAN / BLOCKED

3. For each found variant:
   - Same root cause, same fix needed --> group with original
   - Different root cause or fix --> report separately
   - Higher severity than original --> lead with this variant
```

## Tracking

| Original | Dimension | Target | Result | Action |
|----------|-----------|--------|--------|--------|
| IDOR GET /users/{id} | Endpoint | GET /users/{id}/billing | FOUND-H | Lead variant |
| IDOR GET /users/{id} | Auth state | Same, UNAUTH | CLEAN | - |
| IDOR GET /users/{id} | Parameter | /users/{id}/files/{fid} | FOUND-H | Group |
| XSS /search?q= | Feature | /support?subject= | FOUND-M | Group |

## Discovery Signals

| # | Signal | Where to Find | Why Vulnerable |
|---|--------|---------------|----------------|
| 1 | Disclosed report marked "fixed" | Program's H1 hacktivity, changelog | Fix scoped to one endpoint, not data class (Report #1014913817: FB internal docs revisited) |
| 2 | `skip_*` / `force_*` / `bypass_*` boolean in API body | Burp request body, JS bundles | Client-controlled mode flag flips server behavior (Report #1018336: Shopify Chat $skip_customer_creation) |
| 3 | Multiple platform clients (web, mobile, iOS, Android) | App store, subdomain enum | Cross-variant feature parity gaps -- mobile API often lags web fixes (Report #1038372704) |
| 4 | Versioned API paths (`/v1/`, `/v2/`, `/api/beta/`) | Proxy history, JS base URLs | New version reimplements without porting security controls |
| 5 | Multi-step workflow with state transitions | Registration, payment, linking flows | State-machine bypass via direct endpoint invocation (Report #1036999089) |
| 6 | Patch confirmation email from program | H1 inbox, bug updates | Fix-bypass window: test within 30/60/90 days (Report #1010316) |
| 7 | OAuth/redirect params (`redirect_uri`, `state`, `next`) | Auth flow capture | Null-byte, encoding, and parser-confusion variants (Report #1046630) |
| 8 | Transfer-Encoding / Content-Length headers | Burp repeater | Header obfuscation variants -- tab, case, double header (Report #1063627: $50K smuggling) |
| 9 | Password confirmation step after fix | Intercepted response | Client-side-only enforcement -- response replay bypass (Report #1040373: Khan Academy) |
| 10 | SSRF filter blocking `localhost` | Error response on direct attempt | Redirect-following bypass, DNS rebinding, URL parser confusion (Report #369956352: $50K AppSheet) |
| 11 | Email-related flows (register, change, verify) | Account settings | Verification gap across flows -- one enforces, others don't (Report #1041173) |
| 12 | Rate-limit announced as "fixed" | Changelog, disclosed report | Timing-based retest with fixed-throttle Intruder (Report #1047124) |

## Technique Matrix

| # | Technique | When | How |
|---|-----------|------|-----|
| 1 | Response replay bypass | Fix adds client-side check | Capture success response, replay on fail path (Report #1040373) |
| 2 | Redirect-chain bypass | SSRF filter on input URL | Host own 302 redirector, point at internal target (Report #369956352) |
| 3 | Header obfuscation sweep | HTTP smuggling surface | Test tab, case, double-header, trailing space on TE (Report #1063627) |
| 4 | Boolean flag flip | `skip_*`/`force_*` in body | Invert every boolean, diff responses (Report #1018336) |
| 5 | Cross-client parity | Web fix confirmed | Replay via mobile API, m-dot, iOS, Android endpoints (Report #1038372704) |
| 6 | Direct-step invocation | Multi-step workflow | Call step 3 without completing steps 1-2 (Report #1036999089) |
| 7 | API version differential | v1 patched | Replay same request against /v2/, /beta/, /internal/ |
| 8 | Create-vs-update path | Create sanitizes input | Submit clean, then edit with payload (Report #1036995: Judge.me) |
| 9 | Data-class enumeration | One leak path patched | Map all code paths touching same backing data (Report #1014913817) |
| 10 | Timing-window retest | Rate limit "fixed" | Fixed-throttle Intruder with precise delay (Report #1047124) |

## Defense-Bypass Pairs

| Defense | Bypass | Example |
|---------|--------|---------|
| URL blacklist (localhost/RFC1918) | 302 redirect from attacker server | AppSheet SSRF $50K -- filter checked input, not redirect target |
| Client-side password confirmation | Response interception + replay | Khan Academy account linking bypass |
| TE header rejection | Tab/case/double-header obfuscation | Acronis HTTP smuggling via `TE\t:\tchunked` |
| Extension denylist | Double extension, case, null byte | `.PhP`, `.jpg.php`, `shell.php%00.jpg` |
| CSRF token validation | Empty string token, wrong-format token | Report #1003468: 3 failure modes per endpoint |
| Per-endpoint rate limit | Rotate IP, credential, path alias | Single-axis limits bypassable by rotating the other axis |
| Domain-based filter | Trailing dot, case, FQDN normalization | `domain.` vs `DOMAIN.COM` vs `domain.com.` (Report #1068505) |
| Input validation on create | Edit/update path has weaker validation | Judge.me review HTML injection via edit flow |

## Chain Patterns

| Chain | Step 1 | Step 2 | Impact |
|-------|--------|--------|--------|
| Fix bypass + SSRF | Confirm original fix blocks direct request | 302 redirect bypasses filter | Internal service access ($50K) |
| Response replay + ATO | Capture legitimate success response | Replay on victim's failed auth check | Persistent account takeover |
| Smuggling + session hijack | Tab-obfuscated TE header desync | Smuggled request captures next user's cookies | Session theft |
| Boolean flip + PII leak | Find `skip_customer_creation: true` | Flip to `false`, get name from email | Email-to-identity oracle |
| Create/update + stored XSS | Create clean review, pass validation | Edit with HTML payload via weaker path | Stored XSS on third-party stores |
| SSRF + port scan | Redirect bypass confirms SSRF | FFUF fuzz `?url=localhost:PORT` | Internal service enumeration |
| State bypass + privilege escalation | Skip MFA step via direct API call | Access admin-only operation without MFA | Full admin access |
| Cross-client + data leak | Web endpoint patched | Mobile API returns unredacted data | PII exposure |

## Pro Tips from Corpus

1. **Fix bypass is the highest-ROI hunt on mature programs.** Every disclosed report is a starting point for a follow-up. Set 30/60/90-day reminders after fix confirmation (Report #1010316).
2. **Attack the data class, not the endpoint.** When a leak path is patched, enumerate ALL paths to the same backing data -- versioned APIs, mobile endpoints, export, search indexes, share flows (Report #1014913817).
3. **Six layers before declaring SSRF safe:** direct target, DNS rebinding, 302 redirect, URL parser confusion, protocol smuggling, Unicode normalization (Report #369956352).
4. **Mine JSON bodies for mode flags.** `skip_*`, `force_*`, `bypass_*`, `is_admin` -- flip every boolean and diff the response. The class is "client-controlled mode flag" (Report #1018336).
5. **Always test the edit path separately from create.** Many apps sanitize on creation but not update. Submit clean, then edit with payload (Report #1036995).
6. **Test all three CSRF failure modes per endpoint:** no token, empty token, wrong-value token. Different failures reveal different backend behaviors (Report #1003468).
7. **Cross-client testing is mandatory.** Web, mobile web, iOS, Android -- each client may use different API paths with different authorization (Report #1038372704).
8. **Don't trust the response code.** Side effects (emails, audit logs, webhooks) may execute despite a 403/error response. Check all output channels (Report #1085042: Shopify Plus).

## When to Stop

- All 5 dimensions checked, last 5 variant tests clean, or time on variants exceeds 3x the original finding

## Persistence Before Dismissal

A single failed probe is not proof a vulnerability class is unreachable on a surface. Before you declare ANY class "disproven" on a given probe-point, test at least 6 variants along the dimensions that failed:

- **Input depth / size**: did you test 0, 1, small, boundary, large? If a deep payload was rejected, walk it DOWN — the rejection may be a resource limit, not a filter.
- **Encoding layer**: raw, single-escape, double-escape, Unicode variants (overlong, homoglyph, mixed-script), wrapped-in-container (one format embedded in another). Use whichever escape grammars the target protocol actually exposes.
- **Payload shape**: delimited vs undelimited, collection vs scalar, operator/structural-syntax vs literal, type coercion (string-as-number, boolean-as-1, null-as-missing).
- **Chained precondition**: every time a different probe finds a control-break, re-test previously-dismissed probes with that precondition assumed.

Extreme-first / extreme-only probing is an anti-pattern. A denial response at maximum depth may be hitting a resource-root boundary, not proving the filter works — smaller/simpler variants still land. Record each variant tested so the dismissal is auditable.

## Bidirectional-Sink Inspection

Every probe-point has two sides: an INPUT surface (what the agent sends) and an OUTPUT surface (what the target returns, and what downstream consumers render). When the agent tests only ONE direction and stops, it misses half the attack class on that surface.

For every probe-point where the primary hypothesis was "disproven":
- Run a secondary inspection of the OPPOSITE direction before moving on.
- If input-reachability failed: inspect what the endpoint DOES return for legitimate inputs — it may be an output-side sink (reflection, renders, forwards to another consumer).
- If output-reflection was clean: inspect what input variants CHANGE the output — side-channels still count.

A probe-point is not fully explored until both directions are tested independently.
