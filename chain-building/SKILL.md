---
name: chain-building
category: methodology
description: Combining low-severity findings into high-impact exploit chains using postcondition-to-precondition matching extracted from 10,837 real bug bounty reports
depends_on: []
---

# Chain Building

Chaining connects one finding's postcondition to another finding's precondition. Two Low findings can become one Critical. The difference between a $500 payout and a $25,000 payout is often a single chain link.

## Postcondition-to-Precondition Map

After confirming any finding, consult this table. The "Enables" column tells you exactly what to test next.

| Finding Type | Postcondition (attacker gains) | Enables (precondition for) | Priority Chain Target |
|---|---|---|---|
| Open Redirect | Controlled redirect on trusted domain | OAuth token theft, SSO bypass, referer-based auth bypass | OAuth `redirect_uri`, login return URLs, SSO callback endpoints |
| SSRF | HTTP requests from server context | Cloud metadata access, internal API calls, firewall bypass, port scanning | `169.254.169.254`, internal services on `localhost`, `10.x`/`172.16.x`/`192.168.x` ranges |
| Info Disclosure (IDs) | Valid internal user/object identifiers | IDOR on any CRUD endpoint, password reset manipulation, targeted enumeration | Every endpoint accepting user IDs, object IDs, or sequential references |
| Info Disclosure (tokens/keys) | Session tokens, API keys, JWTs, signing secrets | Account takeover, API abuse, token forgery, signature bypass | Auth-protected endpoints, admin panels, internal APIs |
| Info Disclosure (source/config) | Application internals, file paths, framework versions, dependency list | Targeted CVE exploitation, credential harvesting from config, hidden endpoint discovery | Known CVEs for leaked versions, `.env` paths, database connection strings |
| XSS (reflected/stored) | JS execution in victim browser context | CSRF token theft and bypass, cookie exfiltration, admin action execution, keylogging | CSRF-protected state-changing endpoints, admin panels, payment flows |
| Self-XSS | JS execution in own session only | Nothing alone; needs login CSRF or session fixation to weaponize | Login endpoint CSRF protection, session fixation vectors, OAuth login flows |
| CRLF Injection | HTTP header injection in responses | Response splitting, cache poisoning, cookie injection, redirect injection | CDN/proxy cache layers, `Set-Cookie` scope, `Location` header |
| Path Traversal (read) | Arbitrary file read from server filesystem | Source code review for more bugs, credential harvesting, key extraction | `.env`, `config.yml`, `/etc/shadow`, SSH keys, application source, database configs |
| Path Traversal (write) | Arbitrary file write to server filesystem | Webshell upload, cron job injection, SSH key injection, config overwrite | Web root directories, `/var/spool/cron/`, `~/.ssh/authorized_keys`, app config paths |
| Race Condition | Timing-dependent state bypass or duplicate processing | Double-spend, coupon/credit/referral duplication, limit bypass, parallel state mutation | Financial operations, one-time-use tokens, inventory decrements, quota enforcement |
| Subdomain Takeover | Full control of a trusted subdomain | Cookie scope abuse on parent domain, CORS exploitation, CSP bypass, phishing | Parent domain cookies, CORS allowlists matching `*.example.com`, CSP `script-src` |
| GraphQL Introspection | Complete API schema including hidden types and mutations | Targeted IDOR on undocumented resolvers, hidden admin mutation exploitation | Sensitive resolvers (user/admin/billing), mutations with no authorization checks |
| CORS Misconfiguration | Cross-origin read access to API responses | Token/session exfiltration, PII theft, CSRF-equivalent state changes via API | Endpoints returning user-specific data, session tokens in responses, account details |
| Cache Poisoning | Attacker-controlled content served from cache | Mass XSS delivery, credential phishing at scale, SEO poisoning | High-traffic pages, CDN-cached static assets, shared cache keys |
| OAuth Misconfiguration | Token interception or authorization code theft | Account takeover via stolen auth code or access token | Token exchange endpoints, implicit flow fragments, state parameter validation |
| Host Header Injection | Controlled `Host` value in server-generated content | Password reset poisoning, cache key confusion, virtual host routing bypass | Password reset emails, link generation logic, reverse proxy routing |
| SQL Injection (blind) | Data extraction from backend database | Credential dumping, token/secret theft, schema reconnaissance | Auth tables, admin credentials, API keys stored in DB, session table |
| XXE | Server-side file read and/or outbound HTTP (SSRF) | Credential theft from config files, internal network access, SSRF chains | Same targets as SSRF + same targets as path traversal read |
| IDOR | Unauthorized access to other users' objects | Data exfiltration, unauthorized modifications, privilege escalation | State-changing operations on accessed objects, PII harvesting at scale |
| JWT Algorithm Confusion | Token forgery with chosen algorithm | Authentication bypass, role escalation, impersonation | Any endpoint validating JWTs, admin-only routes, API authorization |
| Prototype Pollution | Arbitrary property injection on JS objects | Gadget-dependent RCE, authentication bypass, template injection | Server-side template engines, child_process spawns, security-sensitive property checks |
| HTTP Request Smuggling | Desync between front-end and back-end request parsing | Request hijacking, cache poisoning, auth bypass for next user's request | Any endpoint behind a reverse proxy or load balancer |

## Pivot Moment Questions

After every confirmed finding, ask these questions before moving on. Each set maps to the finding type.

**After Open Redirect**: Does the app use OAuth or OIDC? Can `redirect_uri` include this endpoint as a path component? Does the redirect preserve URL fragments (`#access_token` in implicit flow)? Is the redirect domain in any CORS allowlist? Does a `Referer` header leak to the redirect destination? Can you chain with a `javascript:` scheme if the redirect is DOM-based?

**After SSRF**: What cloud provider hosts this app? Try metadata immediately: AWS `169.254.169.254/latest/meta-data/iam/security-credentials/`, GCP `metadata.google.internal/computeMetadata/v1/?recursive=true` with `Metadata-Flavor: Google`, Azure `169.254.169.254/metadata/instance?api-version=2021-02-01` with `Metadata: true`. Can you reach localhost services? Probe: 6379 (Redis), 9200 (Elasticsearch), 8500 (Consul), 2379 (etcd), 27017 (MongoDB), 11211 (Memcached), 5432 (PostgreSQL), 3306 (MySQL). Does `file://` work? Is the response body reflected back (full vs blind)? Can you use DNS rebinding to bypass allowlist?

**After Info Disclosure**: Are leaked IDs accepted by CRUD endpoints without ownership validation? Are leaked tokens/keys still valid and unexpired? Do leaked file paths reveal admin endpoints, debug routes, or internal APIs? Are leaked framework versions associated with known CVEs? Do leaked email addresses enable password reset enumeration? Are leaked internal hostnames reachable via SSRF?

**After XSS**: What state-changing endpoints exist that are CSRF-protected? Can you read CSRF tokens from the DOM or from API responses? Can you register a Service Worker for persistent access? Are there `postMessage` listeners accepting `*` origin? Can you pivot to admin sessions if the XSS fires in a shared context (support chat, CMS)? Can you exfiltrate `HttpOnly` cookies via TRACE method or error pages?

**After Race Condition**: What other financial operations use the same locking mechanism (or lack thereof)? Can the race window allow cross-user operations (user A's request processed with user B's state)? Does the race affect inventory, quota, balance, or credits beyond the tested resource? Can you amplify by parallelizing more requests (10, 50, 100)?

**After Subdomain Takeover**: Is the parent domain in any CORS `Access-Control-Allow-Origin` response? Can you set cookies scoped to the parent domain (`.example.com`)? Does CSP allow scripts from `*.example.com`? Is the subdomain referenced in any email SPF/DKIM records? Can you intercept OAuth callbacks if the subdomain was an allowed redirect?

**After Path Traversal**: Can you read `/proc/self/environ` for environment variables? Can you access cloud metadata via `file:///proc/net/fib_trie` for internal IPs, then chain with SSRF? If write: can you reach a web-accessible directory? Can you overwrite `.htaccess` or `web.config`?

**After SQL Injection**: Can you extract password hashes from the users table? Are there API keys, OAuth secrets, or encryption keys stored in DB? Can you read files via `LOAD_FILE()` (MySQL) or `COPY ... FROM` (PostgreSQL)? Can you write files for RCE via `INTO OUTFILE` or `COPY ... TO`?

**After IDOR**: Can you modify the accessed object (read IDOR to write IDOR)? Does the IDOR leak data (tokens, emails, keys) that enables a second attack? Can you chain with stored XSS by writing a payload into another user's profile? Does the IDOR affect financial objects (invoices, transfers, subscriptions)?

**After CORS Misconfiguration**: Does the vulnerable endpoint return session tokens, CSRF tokens, or API keys in its response? Can you combine with XSS on an allowed origin to pivot to a fully trusted cross-origin read? Does the CORS policy also allow `Access-Control-Allow-Credentials: true`?

**After JWT Weakness**: Can you forge tokens for admin or privileged roles? If `kid` is injectable, can you path-traverse to a known file (`/dev/null`, public key) for `HS256` signing? Does `jku` or `x5u` accept attacker-controlled URLs for key fetching? Does the `none` algorithm bypass work?

**After HTTP Request Smuggling**: Can you smuggle a request that poisons the cache for other users? Can you hijack the next user's request (steal their auth header)? Can you bypass front-end access controls (WAF, IP allowlist) to reach protected backend routes? Can you trigger request routing to a different virtual host?

**After Prototype Pollution**: Is the application using EJS, Pug, Handlebars, or Lodash server-side? Check `constructor.prototype` and `__proto__` paths. Can you set `shell`, `NODE_OPTIONS`, or environment properties that lead to `child_process` execution? Does the framework merge user input into template options?

## Real-World Chain Patterns

Fifteen specific patterns ranked by bounty impact. Every pattern has been paid on major platforms.

| # | Chain Name | Steps | Individual Severities | Chain Severity | Bounty Range |
|---|---|---|---|---|---|
| 1 | Open Redirect + OAuth Token Theft | Find open redirect on target domain, inject as OAuth `redirect_uri`, intercept auth code or token at attacker endpoint | Low + Low | Critical | $5K-$25K |
| 2 | SSRF + Cloud Metadata + IAM Escalation | Exploit SSRF to reach `169.254.169.254`, extract IAM credentials, authenticate to cloud APIs, access S3/GCS buckets or EC2 instances | Medium | Critical | $15K-$50K |
| 3 | Self-XSS + Login CSRF = Weaponized XSS | Confirm self-XSS in profile/settings field, verify login endpoint lacks CSRF protection, force victim to log into attacker account, self-XSS fires in victim browser | Info + Low | Medium | $1K-$5K |
| 4 | CRLF + Cache Poisoning + Mass XSS | Inject CRLF in response header, add malicious `X-Forwarded-Host` or body content, poison CDN cache, XSS served to all visitors | Low | High | $3K-$10K |
| 5 | GraphQL Introspection + Hidden Admin Mutations | Dump schema via introspection, identify admin-only mutations, test mutations without admin auth, execute privileged operations | Info | High/Critical | $5K-$20K |
| 6 | Subdomain Takeover + Cookie Scope + Session Hijack | Claim dangling subdomain (CNAME to deprovisioned service), set cookie scoped to `.example.com`, overwrite victim session cookie | Medium | High | $2K-$10K |
| 7 | Path Traversal + Source Code + Hardcoded Secrets | Read source via path traversal, find hardcoded API keys or DB credentials in config, authenticate to internal services or cloud | Medium | Critical | $10K-$50K |
| 8 | CORS Misconfiguration + Cross-Origin API + Data Theft | Confirm `Access-Control-Allow-Origin` reflects attacker origin with credentials, craft page that reads victim's API responses cross-origin, exfiltrate PII/tokens | Low | High | $3K-$15K |
| 9 | Race Condition + Double Spend | Identify financial operation without atomic locking, send parallel requests in same TCP connection (HTTP/2 single-packet attack), confirm duplicate credit/transfer | Medium | High | $2K-$10K |
| 10 | Host Header Poison + Password Reset + ATO | Inject attacker domain in Host header, trigger password reset for victim, victim clicks link pointing to attacker server, capture reset token | Low | High/Critical | $5K-$15K |
| 11 | XXE + SSRF + Internal API + Data Exfiltration | Exploit XXE for outbound HTTP to internal network, access internal APIs without auth, exfiltrate data via OOB channel or response | Medium | High/Critical | $5K-$25K |
| 12 | Prototype Pollution + RCE Gadget | Confirm prototype pollution via `__proto__` or `constructor.prototype`, identify gadget in server-side code (EJS, Pug, Handlebars, child_process), achieve code execution | Medium | Critical | $10K-$50K |
| 13 | IDOR + Stored XSS = Cross-Account Worm | Use IDOR to write attacker-controlled content to victim's profile/posts, inject stored XSS payload, XSS propagates to every viewer and replicates via same IDOR | Medium + Medium | Critical | $10K-$30K |
| 14 | SQL Injection (blind) + Admin Creds + Full Access | Extract admin password hash via boolean-based blind SQLi, crack hash offline, authenticate as admin, access full admin panel | High | Critical | $10K-$50K |
| 15 | Info Leak (email enum) + Password Reset Poisoning + ATO | Enumerate valid emails via registration/login timing, inject Host header in password reset, capture reset tokens when victims click | Info + Low | High | $5K-$15K |

## Chain Discovery Signals

When you observe any of these signals during testing, immediately pivot to the corresponding chain check.

| Signal Observed | Immediately Check |
|---|---|
| OAuth/OIDC flow present | Every open redirect for `redirect_uri` abuse; `state` parameter binding; token in fragment vs query |
| Cloud-hosted application (AWS/GCP/Azure) | Every SSRF for metadata endpoint access; check IMDSv1 vs v2 enforcement |
| CSRF protection on state-changing endpoints | Every XSS for CSRF token exfiltration from DOM or same-origin API calls |
| Login endpoint lacks CSRF protection | Every self-XSS anywhere in the application for login CSRF weaponization |
| CDN or caching layer detected | Every CRLF injection and unkeyed header for cache poisoning |
| Multiple subdomains in scope | DNS CNAME records for dangling references; NS delegation for takeover |
| GraphQL endpoint accessible | Introspection query; if disabled, try field suggestion bruteforce via error messages |
| File upload or document import | Path traversal in filename parameter; extension bypass; write-to-webroot check |
| Microservice architecture detected | Every SSRF for inter-service communication; internal API auth assumptions |
| Password reset functionality | Host header injection; token predictability; rate limiting on reset endpoint |
| JSON API endpoints | Prototype pollution via `__proto__` in JSON body; mass assignment; type juggling |
| XML parsing or SOAP | XXE with external entity; parameter entity for OOB exfiltration; XInclude |
| `.git` directory or source exposure | Hardcoded secrets in source; internal endpoint paths; dependency versions for CVEs |
| JWT authentication | Algorithm confusion (`none`, `HS256` when `RS256` expected); `kid` injection; `jku`/`x5u` URL manipulation |
| Rate limiting on sensitive operation | Race condition via parallel requests; HTTP/2 single-packet attack to bypass rate limit window |
| Webhook or callback URL input | SSRF via webhook destination; blind SSRF with OOB confirmation |
| PDF/image generation server-side | SSRF via HTML-to-PDF (wkhtmltopdf, Puppeteer); file read via `<img src="file:///etc/passwd">` |
| Email functionality (notifications, invites) | Header injection for phishing; HTML injection in email body; SMTP command injection |
| Multi-tenant architecture | Tenant isolation bypass; cross-tenant IDOR; shared resource namespace collisions |
| Mobile API (different from web) | Weaker auth enforcement; missing rate limits; verbose error messages leaking internals |
| Single Sign-On (SSO/SAML) | SAML response manipulation; XML signature wrapping; assertion replay across tenants |
| WebSocket endpoints | Origin check bypass; cross-site WebSocket hijacking; message injection |
| Import/export (CSV, XML, JSON) | Formula injection in CSV; XXE in XML import; deserialization in JSON/pickle import |

## Defense-Bypass Chaining Table

Each defense layer has known bypass vectors that create openings for downstream attacks.

| Defense Layer | Bypassed By | Creates Opening For |
|---|---|---|
| WAF / rate limiting | Request smuggling, chunked encoding, Unicode normalization, HTTP/2 desync, IP rotation | All application-layer injection and abuse attacks behind the WAF |
| CSRF tokens | XSS (reads token from DOM or API), subdomain cookie injection, clickjacking (if no X-Frame-Options) | Any state-changing action: password change, email change, fund transfer, admin operations |
| Same-Origin Policy | CORS misconfiguration, subdomain takeover, DNS rebinding, `postMessage` without origin check | Cross-origin data reads, session theft, API abuse from attacker-controlled page |
| Cloud IAM perimeter | SSRF to metadata endpoint, leaked credentials in source/logs, overly permissive instance roles | Full cloud resource access: S3 buckets, databases, secrets manager, other instances |
| Network segmentation | SSRF through an allowed outbound service, DNS rebinding, compromised jump host | Direct access to internal databases, admin panels, monitoring systems, message queues |
| Input validation / sanitization | Parser differentials (backend vs frontend), double encoding, null bytes, alternate encodings (UTF-7, UTF-16) | SQL injection, XSS, command injection, path traversal past validation layer |
| Session management | Token leak via referrer, XSS cookie theft, session fixation, JWT confusion | Account takeover, persistent unauthorized access, privilege escalation |
| CSP (Content Security Policy) | Script gadgets (Angular `ng-csp`), JSONP endpoints in allowlist, `base` tag injection, `unsafe-eval` in policy | Full XSS execution despite CSP; same impact as no CSP for the attack |
| API authentication | JWT algorithm confusion, leaked API keys, SSRF to internal unauthenticated API, BOLA/IDOR | Unauthorized API access, data exfiltration, privilege escalation, admin operations |
| 2FA / MFA | Response manipulation, backup code brute-force, OAuth flow bypass, session token before 2FA completion | Full account access bypassing second factor |

## Severity Multiplication Table

Chain severity is determined by the FINAL combined impact on the victim, not by averaging individual severities.

| Finding A | Finding B | Chain Impact | Chain Severity | Why |
|---|---|---|---|---|
| Low (open redirect) | Low (relaxed OAuth `redirect_uri` validation) | Account takeover via stolen OAuth token | Critical | Auth code/token theft gives full account control |
| Info (user ID disclosure) | Low (IDOR on sensitive endpoint) | Unauthorized cross-account data access | High | Leaked IDs remove the enumeration barrier; IDOR gives data access |
| Medium (SSRF, no sensitive response) | N/A (cloud metadata reachable) | Cloud infrastructure compromise via IAM credentials | Critical | IAM creds from metadata give access to all cloud resources |
| Info (self-XSS) | Low (login CSRF) | Stored XSS executing in victim context | Medium | Forces victim into attacker session where XSS fires |
| Medium (race condition) | Medium (financial endpoint) | Direct financial loss via duplicate transactions | High | Parallel requests cause double-credit or double-debit |
| Info (GraphQL introspection) | N/A (hidden mutation lacks auth) | Admin-level access via unauthenticated mutation | Critical | Schema knowledge + missing auth = full admin control |
| Low (CRLF injection) | N/A (CDN caches response) | Mass XSS via poisoned cache serving malicious content | High | Every visitor to the cached page receives the XSS payload |
| Low (Host header injection) | Low (password reset uses Host for link) | Account takeover via poisoned reset link | High/Critical | Victim clicks reset link, token sent to attacker domain |
| Medium (path traversal read) | N/A (config contains DB credentials) | Full database access via harvested credentials | Critical | File read to creds to database = complete data breach |
| Medium (XSS) | Medium (admin panel in same origin) | Admin account takeover via XSS in admin context | Critical | XSS in admin session can create new admin, exfil all data |
| Medium (IDOR write) | Medium (stored XSS) | Self-propagating cross-account XSS worm | Critical | Write XSS to other users' profiles; each victim spreads payload |

**Rule**: chain severity is NEVER lower than the highest individual finding. It is almost always HIGHER because the combined impact exceeds what either finding achieves alone.

## Methodology

### Step 1: Build Postcondition Inventory

After completing initial testing, list every confirmed finding with its postcondition. Use the Postcondition-to-Precondition Map above to identify what each finding gives the attacker.

| Finding | Severity | Postcondition (what attacker gains) | Map Lookup: Enables |
|---------|----------|-------------------------------------|---------------------|

Do not skip Low and Info findings. They are the most common chain starters.

### Step 2: Match Postconditions to Preconditions

For each postcondition in the inventory, check:
1. Does any other finding in the inventory need this postcondition to become exploitable?
2. Does the Postcondition-to-Precondition Map suggest a chain target that has not been tested yet?
3. Does any dismissed or "not impactful enough" finding become viable with this postcondition?

Draw directed edges: Finding A (postcondition) -> Finding B (precondition satisfied). Multiple findings can feed the same chain.

### Step 3: Validate Chain Feasibility

For each candidate chain, verify all four feasibility dimensions:

| Dimension | Validation Question | Fail Condition |
|---|---|---|
| Temporal | Does the postcondition persist long enough for step 2? | Token expires before use; cache TTL too short; session invalidated between steps |
| State | Is the state created by step 1 still intact when step 2 executes? | Server-side cleanup between requests; nonce consumed; one-time token |
| Scope | Does the postcondition apply in the same scope where step 2 needs it? | Cookie on wrong domain; token for wrong API; creds for wrong environment |
| Auth context | Does the attacker maintain needed access throughout the chain? | Step 1 requires auth but step 2 needs unauthenticated; session changes between steps |

If any dimension fails, look for a bypass or intermediate step. If none exists, the chain is not viable.

### Step 4: Execute End-to-End

Execute the complete chain in a single testing session. Each step must use the actual output of the previous step, not assumed values.

1. Execute Finding A. Capture the exact postcondition (token value, leaked ID, created state).
2. Feed that postcondition directly into Finding B's precondition.
3. Execute Finding B. Capture the final impact.
4. Document every HTTP request/response in sequence.

A chain that works in theory but has not been executed end-to-end is not a chain. It is speculation.

### Step 5: Assess Chain Severity

Use the Severity Multiplication Table above. Severity is determined by the FINAL impact of the complete chain, not by the weakest link.

## Precondition Composition (Re-Evaluate Dismissed Probes)

When any probe exposes a control-break -- an authorization check bypassed, a filter passed by accident, a routing observation, a state leak, a metadata/envelope effect -- that break becomes a NEW PRECONDITION for every attack class on every previously-dismissed probe-point.

**Rule:** after every new control-break finding, revisit the list of "disproven / out-of-reach / gated" probe-points and re-evaluate each one WITH the new precondition assumed. Attacks compose as a DAG, not as independent tests.

**Common failure mode:** a probe-point is dismissed as unreachable under the current privilege state. Later, a separate finding proves the privilege check can be skipped. The agent should then re-queue the dismissed probe-point for injection, logic, and transition-matrix testing AS IF the gate never existed.

A compositional blind spot is worth more than any single missed finding -- it blocks entire attack classes on otherwise-reachable surfaces.

## Reporting Chains

- Title reflects chain impact, not individual bugs: "Account Takeover via Open Redirect in OAuth Flow" not "Open Redirect on /callback"
- Description walks through the full attack sequence step by step, with numbered steps
- Each step includes its own HTTP request/response evidence
- Impact describes the combined outcome with concrete harm to users or the business
- Single PoC demonstrates the entire chain end-to-end
- Report as ONE finding, not separate findings. One chain report paying $15K beats two separate Lows paying $300 total.

## Chain Anti-Patterns (Do Not Waste Time On These)

| Anti-Pattern | Why It Fails | Instead |
|---|---|---|
| XSS + XSS = "bigger XSS" | Two XSS in the same origin do not compose; second adds no new capability | Chain XSS with a CSRF-protected action or admin session pivot |
| IDOR + IDOR on same object type | Two read IDORs on the same data are one finding, not a chain | Chain IDOR read with IDOR write, or IDOR with info disclosure |
| Info leak + info leak | Two info leaks that reveal the same type of data are duplicates | Chain info leak with an action that consumes the leaked data |
| SSRF + SSRF | Two SSRF endpoints reaching the same internal target are variants, not a chain | Chain SSRF with metadata access, internal API calls, or firewall bypass |
| Chain requires victim to visit attacker page AND enter credentials | Two high-interaction steps make likelihood too low for severity upgrade | One victim interaction step maximum for a credible chain |
| Theoretical chain with no tested link | "If A then B then C" without executing any step is speculation | Execute at least the first link to confirm the postcondition exists |

## Pro Tips

1. **Build the postcondition inventory FIRST.** Most agents find bugs and move on. The inventory is where chains become visible. A 10-minute inventory pass after initial testing routinely surfaces $5K+ chains.

2. **Low-severity findings are chain fuel, not waste.** An open redirect is $200 solo. Connected to OAuth, it is $15,000. Never dismiss a Low without checking the Postcondition Map.

3. **Check OAuth flows immediately after finding any redirect.** Open redirect to OAuth token theft is the single highest-value chain by median payout across public bug bounty data. Test it before anything else.

4. **SSRF on cloud equals automatic metadata escalation attempt.** Do not report bare SSRF. Spend 5 minutes hitting the metadata endpoint. The difference is Medium vs Critical and 10x the payout.

5. **Self-XSS is never "not a bug."** It is a chain component waiting for login CSRF. Check the login endpoint for CSRF protection before closing a self-XSS as informational.

6. **GraphQL introspection is a chain starter, not just reconnaissance.** After dumping the schema, test every mutation for authorization. Undocumented admin mutations without auth checks are common and pay Critical.

7. **Race conditions multiply across operations.** If you find a race on one financial endpoint, test every other financial endpoint with the same technique. Developers repeat the same locking mistakes.

8. **Time your chains.** Some postconditions expire: OAuth codes (60-600 seconds), CSRF tokens (session-bound), cache entries (TTL-dependent). Measure the window and note it in the report.

9. **Partial chains still upgrade severity.** If you can demonstrate steps 1-3 of a 4-step chain but step 4 requires victim interaction, report it with the interaction clearly noted. Partial chains with realistic victim actions still pay more than individual findings.

10. **Every dismissed finding is a chain candidate.** Before closing your testing session, review every finding you marked as low-impact or not-a-bug. Ask: "Does any other finding I have give me what this one needs?" This final review pass catches the chains that linear testing misses.

## Corpus-Derived Chaining Methodologies

Patterns extracted from 232 paid chain reports. These are the HOW behind the highest-paying chains -- reusable reasoning, not specific bugs.

### Identifier-Chain Auditing ($500K pattern)

For any RPC/API that returns sensitive data gated on an identifier:

| Step | Action |
|------|--------|
| 1 | List ALL RPCs that produce identifier X as output, given lower-privileged input |
| 2 | For each producer, check: does the consumer RPC validate that the caller who obtained X is the same caller presenting X? |
| 3 | If validation is caller-identity-blind (only checks "is X valid?", not "does caller own X?"), you have an IDOR chain |
| 4 | Trace the full path: low-priv input -> producer RPC -> identifier X -> consumer RPC -> sensitive data |

The key insight: most IDOR chains are not single-endpoint bugs. They are **identifier laundering** across an RPC graph where one endpoint mints an ID and another trusts it without ownership verification.

### Framework Convenience Feature SSRF Supply Chain ($500K pattern)

Framework auto-handling features (URL fetching, JSON parsing, file resolution, image processing) are SSRF supply chains:

| Signal | What to Test |
|--------|-------------|
| Framework auto-fetches URLs from user input (image URLs, webhook URLs, import URLs, avatar URLs) | Replace with internal targets: metadata endpoints, localhost services, internal DNS names |
| Framework auto-resolves file paths from user input | Inject `file://`, UNC paths, symlink-resolvable paths |
| Framework auto-parses remote JSON/XML/YAML | Host attacker-controlled document that redirects or contains XXE |
| Framework follows redirects transparently | Use redirect chain: external URL -> 302 -> internal target (bypasses allowlists) |

**Chain construction**: find the framework convenience feature (Low/Info), then pivot to cloud metadata or internal service access (Critical). The framework feature is the enabler; the internal access is the impact.

### Browser Extension Confused-Deputy Chains ($313K pattern)

Three components combine for maximum payout:

1. **Extension privilege audit**: For each pre-installed or popular extension, enumerate its `externally_connectable` manifest entry. If `matches` includes broad patterns or the target's domain, the extension accepts messages from web content.
2. **Message handler sink analysis**: Trace every `onMessage` / `onMessageExternal` handler. What privileged APIs does it invoke? (`tabs.executeScript`, `cookies.getAll`, `downloads.download`, `management.setEnabled`)
3. **Sandbox iframe bridge**: If the extension creates iframes or interacts with sandboxed pages, test whether a compromised iframe can send messages that the extension treats as trusted.

**Chain**: web page -> postMessage to extension -> extension executes privileged action -> data exfiltrated back to web page.

### Cross-Product Authorization Bypass Chains

When a target owns multiple products sharing auth infrastructure:

| Step | Technique |
|------|-----------|
| 1 | Enumerate ALL OAuth scopes/client_ids across every product in the ecosystem |
| 2 | For each scope, exhaustively enumerate which APIs it actually authorizes (not what the consent screen claims) |
| 3 | Test cross-product: does a token minted for Product A authorize actions on Product B? |
| 4 | Test scope escalation: does a narrow scope grant implicit access to a wider scope's APIs? |

This pattern produced findings where tokens from one product authorized admin actions on another product in the same ecosystem. The chain is: legitimate auth on Product A -> token reuse on Product B -> unauthorized access.

### The Enabling Finding Pattern

The highest-value chains follow a consistent structure:

```
[Finding B: Low/Info severity, easy to obtain]
         |
         v  (postcondition becomes precondition)
[Finding A: Previously blocked/dismissed]
         |
         v
[Combined impact: Critical]
```

**Enabling finding types ranked by chain frequency**:

| Enabler Category | What It Provides | Typical Chain Target |
|-----------------|-----------------|---------------------|
| Open redirect on trusted domain | Controlled redirect preserving trust context | OAuth token theft, referer-based auth bypass |
| ID/token disclosure from low-priv endpoint | Valid internal identifiers | IDOR on sensitive CRUD endpoints |
| Batch API field laundering | Cross-request data references | Extract fields from response A, inject into request B |
| Prototype pollution (no gadget yet) | Arbitrary property injection | Template engine RCE gadget, child_process env manipulation |
| Path traversal read (non-sensitive files) | Filesystem access primitive | Config file credential harvest, source code review for deeper bugs |
| CRLF / header injection | Response header control | Cache poisoning, cookie injection, redirect injection |

**Rule**: when you find an enabler, do NOT report it solo at Low severity. Spend 30 minutes searching for the chain target. The difference between a $200 report and a $50,000 report is that second step.

### Supply-Chain and Build-System Chains

| Chain Type | Steps | Bounty Range |
|------------|-------|-------------|
| Dependency confusion | Find internal package name (via error messages, JS bundles, lock files) -> register on public registry -> wait for install | $5K-$50K |
| Build-system poisoning | Inspect pom.xml/settings.xml/build.gradle for HTTP repos -> MITM artifact download -> inject code | $1K-$10K |
| IDE/tooling XXE | Inventory every file IDE parses on project-open (pom.xml, .csproj, .sln, manifest.json) -> inject XXE entity -> extract credentials | $5K-$50K |
| Package script privilege escalation | Extract .pkg/.msi/.deb -> find postinstall scripts running as root -> symlink race or TOCTOU | $5K-$10K |
| Cloud bootstrap state pre-emption | Identify deterministic S3/GCS bucket names created during cluster setup -> pre-create bucket -> inject malicious config | $2.5K-$50K |

### Integration Takeover Chains

For third-party integrations (Jira, Slack, GitHub, Stripe):

1. Map the multi-step OAuth-and-link flow between target and integration
2. For each step: can an attacker inject their own account/org into the flow?
3. Test: can a linked integration be hijacked by re-initiating the OAuth flow with attacker credentials?
4. Test: does unlinking the integration revoke all tokens, or do stale tokens persist?

**Chain**: hijack integration link -> attacker's account receives target's webhook data/API access -> data exfiltration via legitimate integration channel.

### Timing-Layer Disagreement Chains

When auditing any chain of HTTP-aware components (CDN -> LB -> WAF -> app server):

| Question | What Disagreement Enables |
|----------|--------------------------|
| Do all layers agree on Content-Length vs Transfer-Encoding? | Request smuggling |
| Do all layers handle connection timeouts identically? | Pause-based desync |
| Do all layers agree on chunked encoding termination? | CL.TE / TE.CL smuggling |
| Does the cache layer key on the same headers the backend uses for routing? | Cache poisoning via unkeyed headers |

**Chain**: timing disagreement (Low) -> request smuggling (Medium) -> cache poisoning persistence (High/Critical). One-shot socket attacks become persistent when a cache layer sits in front.
