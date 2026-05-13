---
name: bb-hunter
description: Unified bug bounty hunting skill — phased workflow, bbrecon integration, Caido programmatic platform, Chrome/Playwright, strix-* vuln skills, chain thinking, reporting, H1 Brain, 7-Question Gate validation, claude-bug-bounty methodology (bypass tables, hunting rules, never-submit list), and multi-agent orchestration. Use for any bug bounty, security testing, or penetration testing task.
---

# BB Hunter

You **are** the agent. Execute the workflow yourself in Cursor using Caido, Chrome, terminal, and strix-* vuln-class skills. Single-agent by default; use multi-agent mode when the user wants parallel or coordinated subagents.

---

## 1. Phased Workflow

Execute in order. Don't skip phases.

```
Scope/Policy → Recon → Map Attack Surface → Proxy+Browser → Test by Type → Chain → Report
```

| Phase | Action |
|-------|--------|
| **Scope/Policy** | Load program policy (§3). Respect scope, rate limits, exclusions. |
| **Recon** | Subdomains, ports, URLs, APIs, tech stack, auth surfaces (§6). |
| **Map** | Endpoints, parameters, roles, trust boundaries, business flows. Generate annotated sitemap tree. Score fuzzing targets. |
| **Proxy+Browser** | Caido + Playwright. Exercise every feature, every role. Passive workflows detect patterns in real-time as you browse (§5). |
| **Test** | Systematic by vuln class. Use strix-* skills per type. Triage passive detections → confirm → exploit. Scanners after mapping. |
| **Chain** | Every finding is a pivot — what does it unlock next? (§8). Cross-reference cursor-mem for chain partners from prior sessions. |
| **Report** | Steps, impact, PoC per finding. The report is the product (§9). |

### Principles

- **Decompose first:** Attack surfaces, scope, approach (blackbox/greybox/whitebox). Clear objectives per sub-task.
- **PoC or GTFO:** Validated PoCs over "likely vulnerable" claims.
- **Persistent:** If one approach fails, try alternatives — encoding, different roles, chaining. Revisit with new info from other findings.
- **Parallel angles:** Recon + auth + injection can run concurrently when independent.
- **Detection ≠ Finding:** A pattern match (DOM sink, CORS header, SSRF param) is a detection. A finding requires confirmation that user input reaches the sink, credentials are attached, or the parameter is exploitable. Always triage detections before investigating.
- **Feedback loop:** Mark investigation outcomes as TP/FP. True positives strengthen detection; false positives refine filters. The system gets smarter over time.
- **Sibling Rule:** If 9 endpoints have auth, check the 10th. Missing middleware on sibling endpoints explains ~30% of paid IDOR/auth bugs. See [hunting-rules.md](hunting-rules.md).
- **A→B Signal:** Confirming bug A = signal the developer made the mistake elsewhere. Hunt for B and C before writing. Time-box 20 min on B. See [hunting-rules.md](hunting-rules.md).

### Time Discipline

| Activity | % Time |
|----------|--------|
| Active hunting | 50% |
| Recon (new + monitoring) | 25% |
| Report writing + follow-ups | 15% |
| Tool maintenance + learning | 10% |

The biggest mistake: 90%+ on active hunting with no structured recon. The second biggest: not writing the report immediately after the finding.

## 2. Tooling

### Caido (Proxy + Programmatic Platform)

Primary intercept proxy at `127.0.0.1:8080`. Not just a proxy — a programmable security platform with a full GraphQL API.

**Setup:**
```bash
# If project has ensure_caido.sh
./scripts/ensure_caido.sh
# Otherwise
caido --invisible --proxy-listen 127.0.0.1:8080 --no-open
```

**Manual UI usage:**
- **Intercept tab** — step through auth flows, modify tokens/IDs in real time before they hit the server.
- **Replay tab** — resend captured requests with modified parameters. This is where IDOR/BFLA/mass-assignment testing lives.
- **Automate tab** — define match-replace rules (e.g. swap `user_id` values, inject headers) and let Caido apply them to all traffic automatically.
- **HTTPQL filtering** — narrow the traffic view: `req.path.cont:/api/ AND resp.status.eq:200` to focus on interesting API responses. `req.method.eq:POST` to see only state-changing requests.
- **Search** — find all requests containing a specific parameter, token, or response pattern across the entire session.
- **Export** — save request/response pairs as curl commands or raw HTTP for reports and PoC scripts.

**Programmatic usage (Caido MCP / GraphQL API):**

When a Caido MCP server is available, use it instead of the UI for all repetitive or multi-step testing. Key operation categories:

| Category | Operations | When to use |
|----------|-----------|-------------|
| **Requests** | `list_by_httpql`, `view_request_by_id`, `view_response_by_id`, `edit_and_replay`, `sendRequest` | Query history, inspect traffic, surgical request modification |
| **Findings** | `create_findings_from_requests`, `list_findings`, `update_finding`, `export_findings` | Track and manage confirmed vulnerabilities |
| **Replay** | `send_to_replay`, `create_replay_collection`, `start_replay_task` | Organized testing sessions per vuln class |
| **Workflows** | `create`, `update`, `delete`, `toggle`, `run` | Passive detection rules, self-adapting detection |
| **Automate** | `create_automate_session`, `list_automate_sessions` | Programmatic fuzzing (Intruder-style) |
| **Scopes** | `create`, `update`, `list` | Programmatic scope control per target |
| **Tamper** | `create`, `update`, `toggle` | Request/response modification rules |
| **Sitemap** | `get_sitemap` (recursive) | Browse discovered attack surface |
| **Hosted Files** | `upload`, `list` | Push wordlists programmatically |

**Edit-and-replay pattern** — the single most useful programmatic operation. Takes a request ID + surgical edits (path, method, headers, body, find/replace) and replays the modified version while preserving all auth context (cookies, CSRF tokens, session headers):

```python
# IDOR test — change path, keep all auth
edit_and_replay(request_id="123", path="/api/user/999")

# Header injection — add X-Forwarded-For, strip CSRF
edit_and_replay(
    request_id="123",
    set_headers={"X-Forwarded-For": "127.0.0.1"},
    remove_headers=["X-CSRF-Token"],
    compact=True  # limit response to ~2000 chars for context window
)

# Body modification for mass assignment
edit_and_replay(
    request_id="123",
    body='{"name":"test","role":"admin","is_admin":true}',
    compact=True
)
```

**Context window management** — when processing many requests, control output size:
- `compact=True` — limit to ~2000 chars, omit raw request (for bulk analysis)
- `headers_only=True` — strip body entirely (for auth/header-focused testing)
- `max_body=N` — custom truncation threshold

For detailed Caido integration patterns (passive workflows, event bridge, self-adapting detection, investigation pipeline), see [caido-integration.md](caido-integration.md).

### Chrome (Playwright)

Always through Caido proxy so every request is captured.

```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(
        proxy={"server": "http://127.0.0.1:8080"},
        headless=False,  # headed for manual observation
        args=["--ignore-certificate-errors"]
    )
    ctx = browser.new_context(ignore_https_errors=True)
    page = ctx.new_page()
```

**Patterns:**
- **Multi-context** — open two browser contexts (attacker + victim) in the same script for access control testing.
- **Request interception** — `page.route("**/api/**", handler)` to modify requests programmatically before they leave the browser.
- **Cookie extraction** — `ctx.cookies()` to grab session tokens for use in curl/Python scripts.
- **Screenshot on action** — `page.screenshot(path="evidence/step3.png")` at each PoC step for report evidence.
- **Network logging** — `page.on("response", callback)` to capture API responses the UI doesn't show.

### Terminal Tools

| When | Use |
|------|-----|
| Quick single request | `curl` with `-v` flag. Copy from Caido's export. |
| Scripted multi-step exploit | Python `requests` + session persistence. |
| Scanning after surface mapped | `nuclei` with custom templates > defaults. |
| Content/param discovery | `ffuf` (wordlist matters more than tool), `arjun` for hidden params. |
| JS static analysis | `getJS` + `js-beautify` + pattern grep for secrets, DOM sinks, hidden routes. See [recon.md](recon.md). |
| Race conditions | Python `asyncio`/`threading`, Turbo Intruder, or Caido Automate. |
| Automated XSS/SSRF | Context-aware payload mutation + headless browser confirmation. See [caido-integration.md](caido-integration.md). |

**Auto-setup** (first time or when asked): If project has `scripts/auto_setup.sh`, run it. Otherwise: create `.env` with `PROXY=http://127.0.0.1:8080`, install Playwright, start Caido.

### Strix Vuln-Class Skills

`~/.codex/skills/strix-*` — specialized playbooks for each vulnerability type. Read the relevant skill before testing that class. For bypass techniques (SSRF 11 IP bypasses, OAuth 11 redirect bypasses, file upload 10 bypasses, IDOR 8 variants), see [bypass-tables.md](bypass-tables.md).

| Skill | When |
|-------|------|
| `strix-idor` | Object references in any API endpoint |
| `strix-xss` | User input rendered in HTML/JS |
| `strix-ssrf` | URL/webhook parameters, file imports |
| `strix-sql-injection` | Search, filters, sorting, any DB-backed input |
| `strix-authentication-jwt` | JWT/OIDC tokens in auth flow |
| `strix-business-logic` | Payments, workflows, state machines |
| `strix-race-conditions` | Any state-changing operation (credits, transfers, votes) |
| `strix-rce` | File upload, template rendering, deserialization |
| `strix-csrf` | State-changing POST/PUT/DELETE without tokens |
| `strix-mass-assignment` | API accepts JSON/form bodies |

Others: `strix-graphql`, `strix-xxe`, `strix-open-redirect`, `strix-path-traversal-lfi-rfi`, `strix-subdomain-takeover`, `strix-information-disclosure`, `strix-insecure-file-uploads`, `strix-broken-function-level-authorization`, `strix-supabase`, `strix-firebase-firestore`, `strix-nextjs`, `strix-fastapi`.

## 3. Program Policy

When the user names a target or program:

1. Look for a policy file in the project: `instructions.md`, `scope.md`, `POLICY.md`, `.cursor/program_policy.md` — use the first that exists.
2. If available, use H1 Brain: `hack(handle="program_handle")` to fetch scope.
3. Otherwise, ask the user for scope or suggest creating a policy file.

**Apply from policy:** in-scope assets, out-of-scope exclusions, rate limits, disclosure rules. All automated tools must throttle to stated limits (e.g. ≤10 req/s).

## 4. Target Selection & Attack Surface

### Picking a Program

```
EV/hr = (avg_bounty × probability_unique) / hours_per_finding
```

**5-minute program evaluation:**
1. Read the scope document — wildcard (`*.target.com`) = good. Single path = bad.
2. Check program stats — resolved reports, avg response time, bounty table.
3. Count active researchers — <100 active = sweet spot. >500 = grind.
4. Read disclosed reports — if all disclosures are P3/P4, the P1s may be untouched. If P1s are disclosed, the low-hanging fruit is gone.
5. Check the bounty table vs company size — a Fortune 500 paying $500 for criticals = walk away.

**Green flags:** Large wildcard scope, recently launched (first 48h = gold), fast triage, clear scope doc.
**Red flags:** Tiny scope, 30+ day triage, "we reserve the right to not pay", no safe harbor.

### Platforms
- **HackerOne** — signal/reputation, private invites based on signal
- **Bugcrowd** — VRT triage, priority queues
- **Intigriti** — EU-heavy, researcher tools
- **Direct** — security.txt, least competition, less legal protection

### Choosing Your Attack Surface

Don't spread thin. After recon, pick 1-2 surfaces and go deep.

**Decision framework:**
1. What did recon reveal? Lots of subdomains → web apps. API docs found → APIs. Mobile app in scope → mobile.
2. What's the competition likely ignoring? Everyone tests the main web app. Fewer touch the API, mobile, cloud infra, CI/CD.
3. What's your edge? If you're strong at API testing, go deep on APIs even if the web app looks juicier.

| Surface | Competition | Reward | Go deep when... |
|---------|------------|--------|-----------------|
| Web Apps | High | High (volume) | Large app with many features, less-tested subdomains |
| APIs (REST/GraphQL/gRPC) | Medium | High | API docs found, mobile app backend, microservices |
| Cloud (AWS/Azure/GCP) | Low | Very High | S3 buckets, cloud metadata accessible, infra in scope |
| Mobile (Android/iOS) | Low | High | Mobile app in scope, different API surface than web |
| CI/CD Pipelines | Very Low | High | GitHub org in scope, public repos, Actions workflows |

For detailed attack surface patterns, see [attack-surface.md](attack-surface.md). For program strategy, see [programs.md](programs.md).

## 5. Browser-Through-Proxy Testing

Playwright + Caido is not just for login. Use it to **exercise every feature** the target exposes — every workflow, every role, every state transition. All traffic is captured for replay, tampering, and analysis.

### Authentication & Session Setup

1. **Credentials** from `.env`: `PROGRAM_EMAIL`, `PROGRAM_PASSWORD` (or program-specific like `IMMERSIVE_EMAIL`).
2. **All browser traffic through Caido** — signup, login, and every action after.
3. **Coupon/promo** via `PROGRAM_COUPON` env var if the program provides one.
4. Use existing `scripts/<program>_signup_login.py` if present, or create one.
5. **Multiple accounts** — create at least 2 (attacker + victim) for access control testing. Different roles if the app has them (user, admin, moderator).

### Deep Functional Testing

After auth, drive the browser through every feature:

| What to exercise | Why |
|-----------------|-----|
| **Profile / settings** | Mass assignment, XSS in stored fields, CSRF on state changes |
| **File upload** | Extension bypass, content-type manipulation, path traversal, stored XSS via SVG/HTML |
| **Payment / transactions** | Race conditions, price manipulation, negative values, coupon replay |
| **Search / filters** | SQLi, XSS (reflected), SSRF via search-behind-the-scenes |
| **API calls behind UI actions** | IDOR (change IDs in captured requests), BFLA (replay admin actions as user) |
| **Invitations / sharing** | Privilege escalation, link token predictability, access after revoke |
| **Export / download** | SSRF, XXE (if XML/CSV), path traversal in filename param |
| **Notifications / webhooks** | SSRF via callback URL, blind XSS in notification render |
| **Password reset / 2FA** | Token reuse, rate limit bypass, brute-force OTP, flow skip |
| **Multi-step workflows** | Skip steps, reorder, replay, partial completion |
| **Role switching / impersonation** | Horizontal + vertical privilege escalation after role change |

### Workflow

1. **Crawl with browser** — click through every page, every button, every form. Caido captures everything. Passive workflows fire detections in real-time as you browse.
2. **Review captured traffic + detections** — look for interesting endpoints, parameters, hidden APIs, auth tokens in URLs. Check passive workflow findings for DOM sinks, CORS, SSRF params, JWT weaknesses.
3. **Triage detections** — a detection is not a finding. Confirm: does user input reach the DOM sink? Are credentials attached to the CORS response? Is the SSRF param actually fetched server-side? **Before writing any report:** run the 7-Question Gate ([triage-validation.md](triage-validation.md)). One wrong answer = kill it.
4. **Replay & tamper** — use edit-and-replay for surgical modification (preserves auth context). Test each as attacker account. Modify IDs, roles, amounts, headers.
5. **Automate repetitive tests** — write Python/curl scripts for IDOR sweeps, race conditions, parameter fuzzing. Use Caido Automate for Intruder-style fuzzing.
6. **Test as every role** — repeat critical flows as unauthenticated, low-priv, and cross-account.
7. **Store outcomes** — `cursor-mem observe` for confirmed findings, chain candidates, and false positives. This feeds the feedback loop and cross-session correlation.

## 6. Recon

Recon is continuous, not a one-time phase. The goal is not a list of subdomains — it's **finding the asset nobody else is looking at.**

### bbrecon (Primary Pipeline)

When the project has **bbrecon**, run it first:

```bash
./bbrecon run -d target.com
# Or: --only assets,post_assets for quick subdomain + API discovery
# Or: --resume to skip completed phases
```

Output: `output/<target>/` — ASSETS, LIVE, ACTIVE, CRAWLING, JS, ACTIVE/API, ACTIVE/PARAMS. Use `ACTIVE/JUICY/juicy.focus.live.txt` as primary crawl targets. See [bbrecon-integration.md](bbrecon-integration.md) for full path mapping.

### Manual Pipeline (fallback)

```
1. Asset Discovery     → subfinder, crt.sh, puredns, gotator
2. Resolution/Probing  → dnsx, httpx (tech-detect, status), naabu + nmap
3. Analysis            → gowitness, ffuf, linkfinder, arjun, waybackurls
4. Continuous Monitor  → diff against previous, alert on new, auto-scan
```

### What to actually look for in recon output

| Signal | Action |
|--------|--------|
| Subdomain with different tech stack (e.g. `staging.target.com` on Express while main is React) | Priority target — likely less hardened, different attack surface |
| Admin panel on non-standard port (8443, 8080, 9090) | Test default creds, auth bypass, direct API access |
| API docs exposed (`/swagger.json`, `/api-docs`, `/graphql`) | Map every endpoint, test auth on each |
| JavaScript bundles with internal paths/keys | Extract with `linkfinder`; test every endpoint found |
| Old endpoints from Wayback Machine still responding | "Deleted" features often still functional on backend |
| CNAME pointing to deprovisioned service | Subdomain takeover candidate |
| New subdomain not in previous scan | Nobody else has seen it yet — test immediately |
| Different response on same path with different `Host` header | Virtual host routing — enumerate more vhosts |

### Decision: When to stop recon and start testing

- You have a **map of live assets** with tech fingerprints.
- You've found at least one **interesting anomaly** (staging, admin, unusual port, API docs).
- Recon tools are returning **diminishing results** (same subs, same ports).
- **Time check:** don't spend more than 25% of a session on recon unless the scope is enormous.

Keep recon running in the background (monitoring mode) while you test.

**References:** [recon.md](recon.md) (manual commands); [bbrecon-integration.md](bbrecon-integration.md) (bbrecon workflow).

## 7. Attack Surface Mapping & Campaign Planning

After recon + initial browsing, generate a structured view of the target's surface.

**bbrecon input** — Use `ACTIVE/API/api_candidates.txt`, `CRAWLING/all.crawled.urls`, and `ACTIVE/PARAMS/all.params.txt` as seed URLs. Cross-reference with Caido sitemap.

### Annotated Sitemap

Build a tree of discovered paths annotated with findings, request counts, and coverage gaps:

```
target.com [5 findings] [23 JS sinks]
├── /api/v1/users [FINDING: IDOR] (28 req)
├── /api/graphql [FINDING: Introspection] (69 req)
├── /auth/callback [FINDING: Open redirect] (22 req)
├── /admin/ (3 req) ⚠️ LOW COVERAGE
└── /webhooks/configure (1 req) ⚠️ UNTESTED
```

Use Caido's sitemap API (`get_sitemap`) + finding cross-reference. Paths with <5 requests are undertested.

### Campaign Scoring

Score each path against priority patterns to decide fuzzing order:

| Path pattern | Score | Why |
|-------------|-------|-----|
| `/graphql`, `/auth`, `/admin`, `/debug` | 9 | Highest value targets |
| `/api/`, `/upload`, `/webhook`, `/payment` | 8 | Critical business logic |
| `/user`, `/search`, `/export`, `/invite` | 7 | Data access + collaboration |
| + POST body present | +3 | State-changing operation |
| + Query parameters | +2 | Parameter-based attacks |
| + Versioned API (`/v1/`) | +2 | Old versions lack controls |

Start fuzzing from highest-scored. Use Caido Automate for automated campaigns. For full details, see [caido-integration.md](caido-integration.md).

## 8. Chain Thinking

Every finding is a position. Ask: **what does this let me reach next?**

| Initial Finding | Bridge | Final Impact |
|----------------|--------|--------------|
| Open Redirect | OAuth redirect_uri manipulation | Account Takeover |
| SSRF | Cloud metadata 169.254.169.254 | RCE / Infra Compromise |
| XSS (stored) | Admin renders user content | Privilege Escalation |
| IDOR | PII → password reset | Account Takeover |
| Subdomain Takeover | Cookies scoped to *.domain.com | Session Hijack |
| Info Disclosure | Leaked data enables further attack | 10-20x severity multiplier |
| Race Condition | Payment/transfer/reward flow | Financial Impact |

A standalone medium = $500-$2k. Two mediums chained into a critical = $5k-$50k.

### When to chain vs submit

- **Chain:** You have a concrete next step and can validate it in <1 day.
- **Submit as-is:** The finding is already high/critical, or you've spent >1 day trying to escalate with no progress. Note chain potential in the impact section.
- **Never:** Sit on a P2 for weeks chasing a theoretical chain.

### Cross-session chain discovery

Before submitting a standalone medium, search cursor-mem for chain partners:
```bash
cursor-mem search "target.com"        # prior findings on same target
cursor-mem search "open redirect"     # same vuln class across targets
cursor-mem search "OAuth"             # related technique
```

CORS on session 1 + OAuth state fixation on session 3 = account takeover chain. Open redirect on subdomain A + OAuth flow on subdomain B = redirect_uri hijack. The knowledge vault makes connections you'd otherwise miss.

For detailed chain patterns, see [chains.md](chains.md).

## 9. Reporting

The report is the product, not the bug. Write for a competent developer who doesn't specialize in security.

**Before writing:** Run the 7-Question Gate and 4 Pre-Submission Gates ([triage-validation.md](triage-validation.md)). Check the NEVER SUBMIT list. For conditionally-valid findings (open redirect, CORS wildcard, etc.), build the chain first, then report.

### Structure
1. **Title** — `[Vuln Type] in [component] at [target] leads to [impact]`
2. **Summary** — what + impact in 2-3 sentences
3. **Repro steps** — exact URLs, payloads, copy-paste ready
4. **HTTP requests** — raw request AND response. Always. Screenshots supplement, never replace.
5. **Impact** — business language: who is affected, what data, what actions, what blast radius
6. **Suggested fix** — specific, not "validate input"

### Impact Framing

Same vuln, different payout:

**Weak:** "XSS on the settings page"

**Strong:** "Stored XSS in the user profile bio field allows an attacker to execute arbitrary JavaScript in the context of any user who views the profile. This enables session hijacking via cookie theft and account takeover. Affects all active users."

**Formula:** `[Vuln type] allows [attacker action] affecting [who/how many], enabling [concrete impact].`

### Severity Escalation (When Triage Undervalues)

This is where real money is lost. Steps in order:

1. **Reframe in business terms** — "This isn't just an open redirect, it enables full account takeover via OAuth token theft affecting all users who click the crafted link."
2. **Show the full chain** — demonstrate the complete attack path. If you haven't already, build the chain and update the report.
3. **Reference precedent** — link to similar reports on the same program rated higher. HackerOne Hacktivity search is your friend.
4. **Provide a realistic attack scenario** — describe exactly how a real attacker would weaponize this, step by step.
5. **Demonstrate the error differential** — if triage says "this doesn't work," show the server behavior that proves it does (e.g. different error messages for valid vs invalid inputs).

**Language that works:**
- "The impact is not [vuln class] in isolation, but rather [full attack scenario]"
- "An attacker with [minimal/no] authentication can [specific action] affecting [scope]"
- "This bypasses [specific control] designed to prevent [specific threat]"

### Handling "Needs More Info"

Triage asking for more info is not a rejection. Respond with:
1. Answer the specific question directly — don't deflect or argue.
2. Provide additional evidence (new screenshots, different PoC angle, server response diffs).
3. If they question the redirect_uri or transport, pivot to the architectural flaw (see the AppsFlyer pattern).
4. Stay professional. Adversarial tone gets reports closed.

### When to push back vs accept
- **Push back:** You have concrete evidence of higher impact, similar bugs rated higher on same program, triager misunderstood the finding.
- **Accept:** You've made your case clearly and they disagree on a judgment call. Severity difference is one level (medium vs high), not two. Arguing further damages the relationship.
- **Mediation:** HackerOne and Bugcrowd both have mediation. Use it only for clear misassessments, not borderline calls.

For report templates by vuln class, see [reporting.md](reporting.md).

## 10. Scan Modes

### Quick Mode
Time-boxed assessment. Speed over completeness. Go for high-impact wins.

**Test in priority order:**
1. Authentication bypass — login flaws, session issues, token weaknesses
2. Broken access control — IDOR, privilege escalation, missing auth
3. RCE — command injection, deserialization, SSTI
4. SQLi — auth endpoints, search, filters
5. SSRF — URL params, webhooks, integrations
6. Exposed secrets — hardcoded creds, API keys, config files

**Skip:** Exhaustive subdomain enum, full directory bruteforce, low-severity info disclosure, theoretical issues without PoC.

**Chaining in quick mode:** When a strong primitive is found (auth weakness, injection point), immediately attempt one high-impact pivot. Don't stop at "maybe" — turn it into a concrete exploit or move on.

### Standard Mode
Balanced assessment. Systematic by vuln class with full attack surface coverage.

**Phase breakdown:**
1. **Recon** — crawl thoroughly, enumerate endpoints/params, fingerprint tech, map user roles.
2. **Business logic analysis** — critical flows (payments, registration, data access), role boundaries, state transitions, trust boundaries.
3. **Systematic testing** — input validation (SQLi, XSS, command, SSTI), auth/session (brute-force protection, session handling, password reset), access control (horizontal + vertical, API vs UI consistency), business logic (multi-step bypass, race conditions, boundary conditions).
4. **Exploitation** — working PoC for every finding. Chain for maximum severity.
5. **Reporting** — all confirmed vulns with repro steps and remediation.

### Deep Mode
Maximum coverage. Finding what others miss. Every parameter, every endpoint, every edge case.

**What makes deep different:**
- **Exhaustive recon** — multiple wordlists, permutation-based subdomain discovery, full port scans, JS analysis on every asset.
- **Business logic deep dive** — map every user flow as a state machine. Document invariants (what rules should always hold). Test what happens when you violate each one.
- **Every input vector with every technique** — multiple injection types, encoding bypasses (double encoding, unicode, null bytes), boundary conditions, type confusion.
- **Advanced techniques** — HTTP request smuggling, cache poisoning/deception, prototype pollution, WebSocket testing, GraphQL batching/nesting.
- **Persistent retesting** — when initial attempts fail: research technology-specific bypasses, try alternative exploitation, test edge cases, revisit with info from other findings.
- **Chain everything** — treat every finding as a pivot. Continue until reaching maximum privilege / maximum data exposure / maximum control. Two mediums → critical is the goal.

## 11. Bounty Intelligence (From H1 Brain + Public Disclosures + Google VRP)

Use H1 Brain MCP tools + disclosed mega-bounty patterns to make data-driven decisions.

### Before Hunting a Target
```
hack(handle="program_handle")     — scope, briefing, disclosed reports, attack plan
search_programs(query="target")   — find the program
search_scopes(program="handle")   — in-scope assets
search_disclosed_reports(program="handle")  — what's been found before
get_disclosed_report(report_id=1679624)     — study mega-bounty technique in detail
```

### The Two Tiers of Findings

**Tier 1 — Chain for $10K+ (from public disclosures):**

| Playbook | Bounty | Core technique |
|----------|--------|----------------|
| Import/Export → Deserialization → RCE | $33,510 | Override `to_s`/`toString` on deserialized objects → inject into downstream protocols (Redis, SQL, LDAP). Patch bypass of CVE-2022-2884. |
| Protocol Switching (`file://`) | $22,300 | URL validator missing scheme allowlist → `file://` reads local git repos at predictable hashed paths |
| SQL Injection → Transaction Escape → Deserialize RCE | Undisclosed | `ROLLBACK; INSERT` escapes read-only transaction → inject YAML deserialization payload into paper_trail `object` column → trigger `reify` from another endpoint |
| SSRF in PDF/Report Generation | $25,000 | `<iframe>` in user content → server-side headless browser fetches `169.254.169.254` → AWS IAM creds |
| OAuth Response Mode Switching → ATO | Undisclosed | `response_mode=web_message` → `fragment`, tokens in URL → steal via XSS on sandbox domain + `window.name` |
| GCP SA Impersonation Chain → Admin | bugSWAT winner | Basic user → SSRF/SSTI → SA token → `serviceAccountTokenCreator` → impersonate JWT issuer → forge admin JWT |
| XSS → Cloud Shell RCE | S0 max | XSS on console.cloud.google.com → call Cloud Shell API → execute on customer instance |

**Tier 2 — Your current techniques ($100-$2K from personal reports):**

| Rank | Class | Avg Bounty | Key Technique |
|------|-------|-----------|---------------|
| 1 | **SSRF** | $1,500 | URL parsing differentials, unauthenticated admin endpoints |
| 2 | **Business Logic** | $1,050 | Weaponized patches, email domain escalation |
| 3 | **Unauthenticated Data Exposure** | $577 | Non-prod envs, setup tokens, onboarding flows |
| 4 | **Path Traversal / CVE** | $750 | Known CVEs on user deployments |
| 5 | **BFLA / Debug Endpoints** | $500 | Dev API routes, CSRF as only gate |

### The Upgrade Path: Tier 2 → Tier 1

| Your current finding | Chain it into | Expected improvement |
|---------------------|--------------|---------------------|
| SSRF (OAST proof only) | SSRF → cloud metadata → IAM creds → S3/Lambda | 2-5x bounty |
| XSS (`alert(1)`) | XSS → admin action → privilege escalation PoC | 3-10x bounty |
| Single-vuln finding | Chain two findings together | 3-5x bounty |
| "Missing auth" report | Full viewer → admin attack scenario via chain | 5-20x bounty |
| Avoiding cloud targets | GCP Cloud VRP with impersonation chains | 10-100x bounty |

### Google Cloud VRP Quick Reference

Bounties calculated by **privilege escalation delta** × **product tier**. S0 (cross-tenant, no permissions) minimum $7,500. Report quality 1.2x multiplier for exceptional, 0.8x for poor. Use Terraform with Google's sample configs. Cite Google's own docs to counter downgrade. Don't use AI to write reports.

**Highest-ROI GCP targets:** Service account impersonation chains, SSRF → metadata, XSS → Cloud Shell, CI/CD runner abuse on open-source repos.

### What pays $0 (avoid these)

| Pattern | Why it gets rejected |
|---------|---------------------|
| Broken link hijacking / repo takeover | Theoretical supply chain, no code execution |
| Self-XSS / HTML injection without chain | No victim interaction path |
| Missing security headers alone | Informational without chain |
| Scanner output without validation | Nuclei/Burp pasted without PoC = instant close |

**For full step-by-step playbooks (12 from your reports + 9 from public disclosures + Google VRP), see [bounty-intel.md](bounty-intel.md).**

## 12. Multi-Agent Mode (Optional)

When the user wants **parallel agents** or **coordinated subagents** (e.g. "multi-agent", "parallel agents", "coordinated assessment", large target):

### Architecture

```
Root Agent (you)
├── Recon Agent      — asset discovery, attack surface mapping
├── Attacking Agent  — vuln testing by type (IDOR, XSS, SSRF, etc.)
├── Validation Agent — confirm findings, build PoC, chain
└── Reporting Agent  — document findings, write reports
```

### Shared Context

**Path:** `output/<target>/.agent-context.json`

All agents read and write this file. Schema: `target`, `scope`, `phase`, `recon` (subdomains, live_urls, tech_stack, attack_surface), `findings`, `validated`, `reports`, `messages`. See `context-protocol.md` in this skill folder.

**Init:** `./.cursor/skills/bb-hunter/init-context.sh <target>`

### Your Role as Root

1. **Decompose** — Load scope, identify attack surfaces, create task list
2. **Spawn** — Launch subagents via `mcp_task` with `subagent_type: generalPurpose`
3. **Aggregate** — Collect outputs, merge into context, deduplicate
4. **Decide** — When to spawn next agent, when done

### Spawning Subagents

```
mcp_task(
  description: "Recon agent for example.com",
  prompt: "You are the Recon subagent. Target: example.com. Read output/example.com/.agent-context.json. Run bbrecon or subfinder/httpx. Update the recon section. Return: subdomain count, top 5 live URLs."
)
```

Inject prior context: attacking agent gets `recon.attack_surface`, `recon.live_urls`; validation gets `findings`; reporting gets `validated`.

### Subagent Instructions (inline)

**Recon:** Run bbrecon/subfinder/httpx. Populate `recon.subdomains`, `recon.live_urls`, `recon.tech_stack`, `recon.attack_surface`. Return summary.

**Attacking:** Test endpoints from attack_surface by vuln class. Use strix-* skills. Append to `findings`. Specify up to 5 skills in prompt: `SKILLS: idor,xss,ssrf,sql_injection,business_logic`. Return: RESULT_SUMMARY, FINDINGS, RECOMMENDATIONS, SUCCESS.

**Validation:** Confirm findings, build PoC, chain. Append to `validated`. Return summary.

**Reporting:** Document each validated finding. Append to `reports`. Return summary.

### Coordination Rules

1. **Recon first** — Attacking needs attack surface
2. **Parallel attacking** — Multiple attacking agents for different vuln classes if surface is large
3. **Validation after findings** — Spawn when attacking reports
4. **Reporting last** — After validation

**Principles:** Task independence, clear objectives, avoid duplication, hierarchical delegation, resource efficiency.

## References (bb-hunter skill folder)

| File | Content |
|------|---------|
| [triage-validation.md](triage-validation.md) | 7-Question Gate, 4 gates, NEVER SUBMIT list, conditionally-valid table |
| [hunting-rules.md](hunting-rules.md) | 17 hunting rules (Sibling Rule, A→B Signal, 5-min rule, etc.) |
| [bypass-tables.md](bypass-tables.md) | SSRF 11 IP bypasses, OAuth 11 redirect bypasses, file upload 10 bypasses, IDOR 8 variants |
| [chains.md](chains.md) | Chain patterns and escalation paths |
| [bounty-intel.md](bounty-intel.md) | Your paid reports + tier 1/2 playbooks |

## Source

Methodology synthesized from [bugbounty.info](https://bugbounty.info/), Strix agent playbooks, H1 Brain data, [claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) (7-Question Gate, bypass tables, hunting rules, triage-validation), and operational experience.
