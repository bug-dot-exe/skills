# BB-Hunter Full Methodology — Strix Instruction Overlay

Inject this into Strix's instruction file to augment built-in skills with professional bug bounty methodology.

---

## PHASED WORKFLOW

Execute in order. Don't skip phases.

```
Scope/Policy → Recon → Map Attack Surface → Proxy+Browser → Test by Type → Chain → Report
```

| Phase | Action |
|-------|--------|
| **Scope** | Read in-scope, out-of-scope, rate limits. One out-of-scope request = potential ban. |
| **Recon** | Subdomains, ports, URLs, APIs, tech stack. Use proxy to capture, terminal for subfinder/httpx/katana. |
| **Map** | Endpoints, parameters, roles. Generate annotated sitemap. Score paths (see Campaign Scoring). |
| **Proxy+Browser** | Exercise every feature, every role. All traffic captured for replay. |
| **Test** | Systematic by vuln class. Use bypass tables below. Triage detections → confirm → exploit. |
| **Chain** | Every finding is a pivot. What does it unlock next? |
| **Report** | 7-Question Gate first. Then steps, impact, PoC. |

---

## PRINCIPLES

- **PoC or GTFO** — Never claim without working proof. Confirm input reaches sink, credentials attached.
- **Detection ≠ Finding** — Pattern match (DOM sink, CORS, SSRF param) = detection. Finding = confirmation.
- **Sibling Rule** — If 9 endpoints have auth, check the 10th. Missing middleware on siblings = ~30% of paid IDOR/auth.
- **A→B Signal** — Confirming bug A = developer made mistake elsewhere. Hunt B and C before writing. Time-box 20 min on B.
- **5-Minute Rule** — Surface shows nothing after 5 min → move on.
- **Impact-First** — "Worst thing if auth broken here?" Nothing valuable → skip. Admin/PII/funds → hunt there.

---

## 7-QUESTION GATE (Before ANY Report)

One wrong answer = KILL IT. Move on.

1. **Can attacker use RIGHT NOW?** Exact HTTP request, copy-paste ready. If not → KILL.
2. **Impact on program's accepted list?** Check exclusions. If excluded → KILL.
3. **In-scope asset?** Domain on list, production, not third-party. If not → KILL.
4. **Requires privileged access?** "Admin can do X" = KILL. "Non-admin does admin thing" = valid.
5. **Already known?** Search disclosed reports, changelog. If yes → KILL.
6. **Prove impact beyond "technically possible"?** XSS→cookie theft not alert(1). SSRF→internal data not DNS. IDOR→other user's data not 200. If not → DOWNGRADE.
7. **On NEVER SUBMIT list?** If yes without chain → KILL.

---

## NEVER SUBMIT (Standalone)

Missing CSP/HSTS/headers, SPF/DKIM/DMARC, GraphQL introspection alone, banner disclosure without CVE, clickjacking non-sensitive, tabnabbing, CSV injection no RCE, CORS wildcard no exfil PoC, logout CSRF, self-XSS, open redirect alone, OAuth client_secret mobile, SSRF DNS-only, host header alone no reset PoC, rate limit non-critical, session not invalidated, concurrent sessions, internal IP error, mixed content, SSL weak ciphers, HttpOnly/Secure alone, broken links, autocomplete password, pre-ATO.

---

## CONDITIONALLY VALID — Chain Required First

| Standalone | Chain To | Result |
|------------|----------|--------|
| Open redirect | OAuth redirect_uri → auth code theft | ATO Critical |
| CORS wildcard | Credentialed request exfils PII | High |
| CSRF | Sensitive action (transfer, delete) | High |
| SSRF DNS-only | Internal service + data returned | Medium |
| Host header injection | Password reset uses injected host | High |
| Self-XSS | CSRF triggers on victim | Medium |
| Subdomain takeover | OAuth redirect_uri at subdomain | Critical |
| GraphQL introspection | Auth bypass or IDOR on node() | High |

---

## BYPASS TABLES

### SSRF IP Bypass (11 techniques)

`2130706433` (decimal) | `0177.0.0.1` (octal) | `0x7f.0x0.0x0.0x1` (hex) | `127.1` (short) | `[::1]` (IPv6) | `[::ffff:127.0.0.1]` | DNS rebinding | Redirect chain (302 to internal) | `attacker.com#@internal` (parser confusion) | CNAME to internal | `[::ffff:0x7f000001]`

### Open Redirect (11 techniques, for OAuth)

`legit.com@evil.com` | `legit.com.evil.com` | `javascript:alert(1)` | `%252f%252fevil.com` | `legit.com\@evil.com` | `//evil.com` | `legit.com%00.evil.com` | Unicode IDN | `data:text/html,...` | `legit.com#@evil.com` | redirect_uri param

### File Upload (10 techniques)

Content-Type mismatch | .phtml .pHp .php5 .phar | shell.php.jpg | shell.php%00.jpg | Magic bytes | Polyglot | ../../../shell.php | Case .pHp | MIME sniffing

### IDOR Variants (8)

V1: Numeric ID swap | V2: UUID enum | V3: Indirect (export?report_id=other) | V4: ?user_id=other | V5: Method swap (DELETE not PUT) | V6: Old API /v1/ | V7: GraphQL node(id) | V8: WebSocket userId

### Sibling Rule

If /api/admin/users has auth, test: /api/admin/export, /api/admin/delete, /api/admin/reset, /api/admin/oauth/*

### Cloud Metadata

AWS: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
GCP: `http://metadata.google.internal/computeMetadata/v1/...` (Header: Metadata-Flavor: Google)
Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (Header: Metadata: true)

---

## CHAIN THINKING

| Initial | Bridge | Impact |
|---------|--------|--------|
| Open Redirect | OAuth redirect_uri | ATO |
| SSRF | 169.254.169.254 metadata | RCE/Infra |
| XSS stored | Admin renders content | PrivEsc |
| IDOR | PII → password reset | ATO |
| Subdomain takeover | Cookies *.domain.com | Session hijack |
| Race | Payment/transfer flow | Financial |
| Info disclosure | Enables further attack | 10-20x multiplier |

Two mediums chained = critical = $5k-$50k. Don't stop at standalone.

---

## CAMPAIGN SCORING

Test first: `/graphql` `/auth` `/admin` `/debug` (9) | `/api` `/upload` `/webhook` `/payment` (8) | `/user` `/search` `/export` `/invite` (7). +3 POST body, +2 query params, +2 versioned API.

---

## HIGH-ROI ATTACK PATHS

1. **URL parsing SSRF** — `allowed\@attacker`, `%5C`, userinfo. Test: image proxy, webhook, import.
2. **Unauthenticated admin/OAuth** — `/api/admin/oauth/*`, `server` param → SSRF.
3. **Forgotten subdomain + setup token** — Metabase /api/session/properties, Grafana /api/admin/settings.
4. **Weaponized patch** — After CVE patch, test patch with `?raw??`, double bypass chars.
5. **IDOR unauthenticated pages** — Application pages with tokens in URL, often no auth.

---

## DEEP FUNCTIONAL TESTING

Profile/settings (mass assign, XSS) | File upload (bypass) | Payment (race, negative, coupon) | Search (SQLi, XSS, SSRF) | API behind UI (IDOR, BFLA) | Invitations (priv esc) | Export (SSRF, XXE) | Webhooks (SSRF callback) | Password reset (token reuse) | Multi-step (skip, reorder) | Role switch (priv esc)

---

## SUBAGENT SKILL SELECTION

When spawning attacking subagents, pass skills matching surface:
- APIs: idor, mass_assignment, broken_function_level_authorization, sql_injection
- User input: xss, ssrf, path_traversal_lfi_rfi, insecure_file_uploads
- Auth: authentication_jwt, csrf, open_redirect
- Logic: business_logic, race_conditions
- Tech: strix-nextjs, strix-fastapi, strix-graphql, strix-supabase, strix-firebase-firestore

**Testing guidance:** For IDOR test V1-V8. For SSRF try decimal, octal, IPv6, redirect chain. For OAuth try @, subdomain, double encoding. Apply Sibling Rule to every /admin/ path.

---

## REPORT FORMAT

Title: `[Vuln Type] in [component] at [target] leads to [impact]`
Include: Raw HTTP request AND response. Exact repro. Impact in business language.
Formula: `[Vuln] allows [attacker action] affecting [who], enabling [concrete impact].`
NEVER: "could potentially" or "may allow"

---

## WHAT PAYS $0

Broken link hijacking, self-XSS no chain, missing headers alone, scanner output no PoC.

---

## RATE LIMITS

Respect program limits (e.g. ≤10 req/s). No brute-force.
