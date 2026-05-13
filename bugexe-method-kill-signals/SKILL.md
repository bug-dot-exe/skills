---
name: kill_signals
category: methodology
description: Criteria that KILL a finding before reporting to prevent wasted effort and invalid submissions
depends_on: []
---

# Kill Signals

A single kill signal is sufficient to drop a finding. Apply before writing any report.

## When to Use

- Before writing a report for any finding
- During triage when a finding feels uncertain

## Kill Criteria

| # | Signal | Kill When |
|---|--------|-----------|
| 1 | **Cannot Reproduce** | No reproduction after 3 retries with identical conditions |
| 2 | **Design Choice** | Behavior documented as intended in docs/changelogs/API specs AND no impact beyond stated design |
| 3 | **Out of Scope** | Asset excluded by program scope. Re-read scope rules before every submission |
| 4 | **Physical Access Required** | No remote exploitation path exists (no SSRF/XSS to bridge local-only access) |
| 5 | **Theoretical Only** | No concrete exploitation path demonstrated, only "could theoretically" |
| 6 | **Already Fixed** | Current production is not vulnerable. Test live, not cached versions |
| 7 | **Known Limitation** | Listed in program's known issues, accepted risks, or common exclusions (self-XSS, login CSRF, SPF/DKIM informational, clickjacking on non-state-changing pages) |
| 8 | **Duplicate** | Same root cause already reported or publicly disclosed. Check platform disclosures and CVE databases |
| 9 | **CORS on Bearer API** | API uses Authorization: Bearer tokens (not cookies). CORS misconfig is NOT exploitable — browsers don't send Bearer headers cross-origin automatically. Only report CORS if: (a) auth is cookie-based AND (b) Access-Control-Allow-Credentials: true AND (c) origin is reflected or wildcard. Bearer + CORS = automatic N/A |
| 10 | **Missing Headers on API** | Missing X-Frame-Options, HSTS, CSP on pure JSON API endpoints with no HTML rendering. These headers only matter for browser-rendered content |
| 11 | **Self-XSS** | XSS that only fires in the attacker's own session with no delivery mechanism (no CSRF to chain, no URL parameter reflection) |
| 12 | **Login/Logout CSRF** | CSRF on login or logout forms with no demonstrated impact beyond session fixation in a scenario requiring active MITM |
| 13 | **Rate Limit on Non-Sensitive** | Missing rate limiting on endpoints with no security impact (public search, static content). Only report rate limit issues on auth, password reset, OTP, or payment endpoints |

## Decision Flow

```
Suspicious behavior found?
  Can reproduce (3x)?      NO  --> KILL
  In scope?                 NO  --> KILL
  Documented as intended?   YES --> KILL
  Requires physical access? YES --> KILL
  Concrete attack path?     NO  --> KILL
  Fixed in production?      YES --> KILL
  Known limitation?         YES --> KILL
  Already reported?         YES --> KILL
  ALL PASS --> Proceed to validation
```

## Edge Cases

- A killed finding can revive if it chains with another finding (self-XSS + CSRF = live)
- "Theoretical" becomes "concrete" the moment you have a working PoC
- Design choice kills only apply when there is no security impact beyond the stated design

## Keep Digging Signals

The inverse of kill signals. These are patterns where findings LOOK dead but are not. Extracted from 63 paid reports where persistence turned $0 into $500-$10K.

### When to Keep Investigating vs. Abandon

| Signal | Action | Why |
|--------|--------|-----|
| Sanitizer blocks your payload but field is persisted | **KEEP DIGGING** -- enumerate every OTHER render surface for that field | Data persists before validation in draft/create flows; different renderers apply different escaping |
| Endpoint returns 403 on your verb | **KEEP DIGGING** -- try every other HTTP method (PATCH, DELETE, OPTIONS, HEAD) on the same path | Authorization is often enforced per-method, not per-path; PATCH frequently has weaker controls than PUT |
| Feature works as documented | **KEEP DIGGING** -- test the feature's interaction with every OTHER feature | Cross-feature state leaks are invisible in single-feature testing |
| Input is validated on submission | **KEEP DIGGING** -- check if validation runs on update/edit of the same field | Many apps validate on create but skip validation on update |
| Security setting works in normal flow | **KEEP DIGGING** -- exercise every other app feature while the setting is active | Settings that toggle privacy/security often fail when interacting with features added later |
| Response contains no reflected input | **TRY OOB** -- plant callback URLs in every text field, wait 24-48 hours | Backend processing pipelines (email, reports, exports, admin review) may render your input hours later |
| Endpoint is a static HTML file | **KEEP DIGGING** -- check inline JS for DOM sinks (location.hash, document.referrer, postMessage) | Static files with inline JS are overlooked because they "appear safe"; DOM sources bypass server-side filters |
| Third-party domain in program scope | **TEST OBVIOUS PARAMS** -- try `?s=`, `?q=`, `?search=`, `?query=`, `?filter=` with XSS payloads | Third-party/acquired domains often have weaker security than the main product |
| API returns "anonymized" data | **KEEP DIGGING** -- check for persistent identifiers across responses | Persistent IDs + data enrichment across endpoints = de-anonymization chain |

### Counter-Intuitive Signals

Things that LOOK safe but indicate exploitable state:

| What You See | What It Actually Means | Test |
|-------------|----------------------|------|
| Field is an enum in the UI dropdown | Backend may persist it as a free-text string | Send arbitrary string values via API/proxy, bypass UI constraints |
| App validates input with `sanitize(X)` then `validate(sanitize(X))` | If `store(X)` uses the ORIGINAL unsanitized value, the validation was theater | Intercept request, send raw payload -- the sanitize+validate may not affect what gets stored |
| Uninstall process completes cleanly | Session tokens, auth cookies, and credentials may persist on disk | Uninstall, reinstall, check if previous session is still valid without re-authentication |
| Error page returns plain text / JSON | Error content may still be injectable (reflected in API consumers, logs, admin panels) | Inject HTML/XSS payloads into error-triggering parameters |
| Admin/config interface exists | Admin interfaces are rarely XSS-tested ("only admins see it") | Test every config/settings field for stored XSS -- lower-priv user input may render in admin context |
| Security fix was deployed for a specific tag/payload | Fix likely blocklisted only that specific vector | Enumerate ALL other tags/payloads that survive the fix; sanitization patches are usually incomplete |
| Account deletion/logout handler exists | May not clean up ALL persistent state (cookies, tokens, alt-svc cache, HSTS entries, local storage) | Enumerate every piece of state created during account lifecycle, verify each is purged |

### Cross-Feature State Persistence Regression

For every privacy or security setting, apply this audit:

```
1. Enable the security setting (e.g., "hide online status", "disable tracking")
2. List every OTHER feature in the app
3. Exercise each feature while the setting is active
4. Check: does the feature LEAK the state the setting was supposed to hide?
5. Check: does the feature RESET the setting to its default?
```

This pattern catches regressions where a new feature was added without awareness of the security setting. The setting works in isolation; it fails when the new feature touches the same state.

**Real-world shape**: privacy setting "hide X" works perfectly until user opens Feature Y, which reads the same underlying data through a different code path that never checks the privacy toggle. Result: $2,940 privacy violation.

### Persist-Then-Validate Drift

Any time you see a multi-step write flow (draft -> enrich -> finalize):

| Step | What to Test |
|------|-------------|
| 1 | Does the draft/create step validate input as strictly as the finalize step? |
| 2 | If you inject a payload at draft creation, does it survive to finalization? |
| 3 | Is the draft accessible to other users before finalization? |
| 4 | Does editing a finalized object re-apply validation, or does the original raw input persist? |

The draft stage often persists data before full validation runs. If the draft is rendered anywhere (preview, notification, admin queue), the payload executes.

### Overlooked Parameter Testing

**The "obvious params on third-party domains" pattern**: Large programs include third-party services in scope. These services often have basic parameter-reflection XSS that the main product does not, because:
- Third-party security teams may be smaller or less mature
- Acquisitions bring legacy codebases with unpatched search/filter params
- Third-party domains are tested less frequently by other researchers

**Standard test sequence for third-party scope assets**:
1. Visit every page on the third-party domain
2. Identify every user-controllable parameter (`?s=`, `?q=`, `?search=`, `?query=`, `?filter=`, `?redirect=`, `?url=`, `?next=`, `?callback=`)
3. Test each with a basic reflection probe: `"><img src=x onerror=alert(1)>`
4. Check response for unescaped reflection -- third-party domains frequently lack WAF/CSP

### Persistent State Audit Checklist

For any application that stores state to disk (CLI tools, desktop apps, browser extensions, mobile apps):

| State Category | What to Check | Kill Signal Override |
|----------------|--------------|---------------------|
| Auth tokens | Persist after logout/uninstall? Readable by other local users? File permissions correct? | If tokens persist -> keep digging, not a kill |
| Cache files | Overwritten atomically or via rename? Race condition on parallel writes? | Parallel write corruption = data loss finding |
| Config files | Created with restrictive permissions on first run? Updated with same permissions? | Permission widening on update = privilege escalation |
| Cookie/session databases | Cleared on explicit "clear data" action? Contain entries from expired sessions? | Stale session entries = session persistence finding |
| Shared on-disk state | What happens when two instances write simultaneously? Last-write-wins = data loss | Concurrent write -> state corruption = keep digging |

### Fan-Out Rendering Map

For every persistent text field, trace where the string gets rendered:

```
Input field "Company Name"
  -> HTML page (escaped? which encoder?)
  -> Email subject line (header injection?)
  -> Email body (HTML injection?)
  -> PDF export (injection via PDF generator?)
  -> CSV export (formula injection?)
  -> API JSON response (consumed by what frontend?)
  -> Admin dashboard (different escaping rules?)
  -> Mobile push notification (truncated? raw?)
  -> Webhook payload (consumed by what integration?)
```

**Rule**: a persistent string that is safe in its primary render context is a finding if ANY downstream consumer renders it unsafely. "Plant once, hunt everywhere."

### Resource Asymmetry Test

For every state-persisting endpoint, compute:

| Metric | Question |
|--------|----------|
| Attacker cost per write | How cheap is it to store data? (API call, minimal payload, free tier) |
| Victim cost per cleanup | How expensive is it to undo? (manual review, admin action, database migration) |
| Amplification ratio | victim_cost / attacker_cost -- if > 100x, this is a DoS vector worth reporting |

A $0.001 API call that creates state requiring manual admin cleanup is a persistent DoS. The kill signal "no security impact" does not apply when the asymmetry is extreme.
