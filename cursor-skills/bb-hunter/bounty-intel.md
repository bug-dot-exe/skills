# Bounty Intelligence Reference

Patterns extracted from real rewarded reports via H1 Brain — your own 17 reports ($10,581) plus publicly disclosed community reports. Every pattern below is backed by a report that paid.

## Your Portfolio Summary

17 reports, $10,581 total across 14 programs. Average: $622/report.

| Program | Reports | Total | Avg/Report | Best Vuln Type |
|---------|---------|-------|------------|----------------|
| replit | 3 | $3,500 | $1,167 | Business logic (weaponized patch), path traversal (CVE) |
| gravie_bbp | 1 | $2,000 | $2,000 | SSRF with URL parsing differential bypass |
| cambly | 1 | $1,000 | $1,000 | Exposed Metabase setup token on forgotten subdomain |
| superbet | 1 | $1,000 | $1,000 | Unauthenticated SSRF in OAuth helper endpoint |
| doordash | 1 | $931 | $931 | IDOR / PII exposure on unauthenticated pages |
| petco | 1 | $600 | $600 | Unauthenticated data exposure on non-prod env |
| found_bbp | 1 | $500 | $500 | BFLA on debug endpoints (CSRF bypass via public token) |
| hudapp_bbp | 2 | $300 | $150 | CloudFront/WAF bypass via direct origin IP |
| sourcegraph | 1 | $250 | $250 | Dependency confusion (unclaimed npm package) |
| college-board | 1 | $200 | $200 | S3 pre-signed URL generation without auth |
| duolingo | 1 | $100 | $100 | Business logic (email domain privilege escalation) |
| mergify | 1 | $100 | $100 | OAuth code leak via Referer to third-party JS |
| zoom | 1 | $100 | $100 | HTML injection in OAuth callback parameter |
| crypto | 1 | $0 | $0 | Broken link hijacking (N/A'd) |

## Replicable Attack Playbooks (From Your Reports)

Each playbook below is a step-by-step recipe extracted from a report that paid. Adapt to new targets.

### Playbook 1: URL Parsing Differential SSRF ($2,000 — Gravie #3556446)

**The technique:** Bypass string-based URL allowlists using backslash + userinfo delimiter (`allowed\@attacker`). The allowlist checks if the string *contains* the allowed host, but the HTTP client parses userinfo differently and fetches from the attacker host.

**Step-by-step:**
1. Find any feature that proxies/fetches URLs server-side (image proxy, URL preview, import, webhook)
2. Identify the allowlist (send disallowed host → observe error/block)
3. Test parsing differentials:
   - `https://allowed.com\@attacker.com/path` — backslash + userinfo
   - `https://allowed.com%5C@attacker.com/path` — URL-encoded backslash
   - `https://allowed.com:password@attacker.com/path` — full userinfo
   - `https://allowed.com%00@attacker.com/path` — null byte
   - `https://attacker.com#@allowed.com` — fragment as fake host
4. If the target base64-encodes URLs, encode the bypass URL and send
5. Prove impact: fetch from OAST server, then try cloud metadata, internal services

**Detection workflow trigger:** `url=`, `callback=`, `proxy=`, `fetch=`, `url-b64` parameters in any request.

**Report template signals:** Include both bypass technique AND impact proof. The Gravie report showed OAST callback + explained the parsing differential technically.

### Playbook 2: Unauthenticated SSRF in OAuth/Admin Endpoints ($1,000 — Superbet #3554919)

**The technique:** Find admin-namespaced endpoints that accept a `server` parameter for OAuth configuration. The endpoint makes server-side HTTPS requests to `https://{server}/oauth/token-request` without auth.

**Step-by-step:**
1. Discover admin/OAuth helper endpoints: `/api/admin/oauth/*`, `/oauth/configure`, `/admin/sso/*`
2. Check if they require auth — send without cookies/tokens
3. If accessible, look for parameters that control server destinations: `server`, `host`, `issuer`, `idp_url`
4. Provide your OAST domain as the server value
5. Confirm OAST receives callback with details (User-Agent reveals backend library, Auth header reveals creds)
6. Test internal reachability: `127.0.0.1:443`, `169.254.169.254:443` — observe timing differentials

**Detection workflow trigger:** `req.path.cont:/admin/ AND resp.status.ne:401 AND resp.status.ne:403`

**What made this pay $1,000:** Unauthenticated + admin-namespaced + SSRF with internal reachability proof + clean PoC script with `--test-internal` flag. Backend was Guzzle (PHP), which the OAST callback revealed via User-Agent.

### Playbook 3: Weaponized Patch Testing ($2,000 — Replit #3220054)

**The technique:** After a CVE is patched, test the patch itself. The mitigation for CVE-2025-30208 (Vite path traversal) introduced a new bug — requesting the patched path with `?raw??` caused the server to crash and enter a restart loop.

**Step-by-step:**
1. Monitor CVE disclosures and patch announcements for in-scope targets
2. Read the patch diff — understand what was changed and how
3. Test the exact patched code path with edge cases:
   - Double the bypass char: if `?raw` was blocked, try `?raw??`
   - Encode variants: `%3Fraw`, `?raw%3F`
   - Test what happens when the patch's validation throws an exception (crash → DoS)
4. Request the patched path repeatedly — observe if the server restarts (502 responses)
5. Calculate impact: $0.03/month AWS Lambda sustains indefinite service disruption

**Detection workflow trigger:** New CVEs affecting dependencies of in-scope targets (Vite, webpack, Next.js, etc.)

**Key insight:** The original Vite CVE (#3152300) paid $750. The patch bypass paid $2,000. Testing fixes is higher-value than testing features.

### Playbook 4: Known CVE on User-Deployed Assets ($750 × 2 — Replit #3152300, #3198399)

**The technique:** Replit users deploy Vite dev servers on `*.replit.app` and `*.replit.dev`. CVE-2025-30208 allows arbitrary file read via `/@fs/etc/passwd?raw??`.

**Step-by-step:**
1. Monitor CVE feeds for widely-used frameworks/tools (Vite, Next.js, Express, Rails)
2. Cross-reference with recon data: which in-scope targets use the affected software?
3. For PaaS/hosting platforms (Replit, Heroku, Vercel): user deployments are attack surface
4. Craft the exact CVE exploit path against a live deployment
5. Submit fast — first reporter wins

**Key insight:** Speed matters more than depth for CVE bugs. The same CVE filed against two different endpoint patterns (`*.replit.app` and `*.replit.dev`) paid $750 each.

### Playbook 5: Forgotten Subdomain with Setup Token ($1,000 — Cambly #3583689)

**The technique:** Metabase instance on forgotten subdomain (`transcriptmetrics.cambly.com`) exposed setup token via `/api/session/properties`, even though the instance was already initialized (`has-user-setup: true`).

**Step-by-step:**
1. During recon, fingerprint every subdomain's tech stack (httpx --tech-detect)
2. Look for analytics/BI tools: Metabase, Grafana, Redash, Kibana, Jupyter
3. Check default admin/setup endpoints:
   - Metabase: `/api/session/properties` (look for `setup-token` field)
   - Grafana: `/api/admin/settings`
   - Redash: `/setup`
   - Kibana: `/status`
4. If setup token exists, prove it's accepted: POST `/api/setup` with the token + intentionally invalid user fields (shows token gate bypassed without creating accounts)
5. Check `site-url` in the response — may reveal internal Cloud Run/GKE origins

**Detection workflow trigger:** `resp.body.cont:"setup-token" OR resp.body.cont:"setup_token" OR resp.body.cont:"initial-setup"`

**What made this pay $1,000 next-day:** Forgotten subdomain + exposed setup token + proof the token is valid (error differential: invalid token → "Token does not match" vs valid token → field validation errors only).

### Playbook 6: IDOR on Unauthenticated Pages ($931 — DoorDash #3401056)

**The technique:** Dasher application pages (`/dasher/application/<token>`) exposed phone numbers and emails without requiring login, plus allowed triggering SMS resends.

**Step-by-step:**
1. Look for onboarding/application/invitation flows with token-based URLs
2. Check if these pages load without authentication
3. If they do: what PII is visible? Phone, email, name, address?
4. Can you trigger actions? (resend SMS, resend email, modify application)
5. Is the token sequential or predictable? Demonstrate enumeration is theoretically possible without actually mass-enumerating
6. Quantify: "affects all users who have applied" + mention GDPR/CCPA

**Detection workflow trigger:** `req.path.regex:/\/(application|invite|onboard|signup)\/[a-zA-Z0-9]{10,}/ AND resp.status.eq:200`

### Playbook 7: Unauthenticated API on Non-Prod Environments ($600 — Petco #3558379)

**The technique:** QA and dev environments exposed customer data without authentication, even though the OpenAPI spec documented required auth.

**Step-by-step:**
1. During recon, enumerate subdomains for non-prod patterns: `qa-*`, `*-dev.*`, `staging.*`, `*-stg.*`, `*-uat.*`
2. Check if the OpenAPI/Swagger docs are accessible (they often list all endpoints)
3. Send requests without auth headers — compare behavior vs production
4. Read only a minimal response prefix (first 4096 bytes) to prove data exists without handling sensitive data
5. Extract JSON key schema from response (prove PII fields exist without printing values)
6. Hash the response prefix (SHA-256) for reproducibility evidence

**Detection workflow trigger:** `req.host.regex:/(qa|dev|staging|stg|uat)[.-]/ AND resp.status.eq:200 AND resp.header.cont:application/json`

**Key insight:** Non-prod environments often contain real customer data and lack auth enforcement. The Petco report read only 4096-byte prefixes and printed schema-only (key names, not values) — this responsible data handling builds trust with triage.

### Playbook 8: Debug/Dev Endpoint Exploitation ($500 — Found #3558367)

**The technique:** `/api/development/*` endpoints on staging allowed unauthenticated users to enumerate Linear teams and create issues. CSRF was the only gate, and the CSRF token could be obtained without auth from a public endpoint.

**Step-by-step:**
1. Content discovery with dev/debug wordlists: `/api/development/`, `/api/debug/`, `/api/internal/`, `/__dev/`, `/_debug/`
2. Check if these endpoints require auth
3. If CSRF is the only protection, find where the CSRF token is issued — often on a public page
4. With CSRF token in hand, demonstrate the sensitive action
5. Include a control check in your PoC: show that removing CSRF header → 403, proving CSRF is the only gate

**Detection workflow trigger:** `req.path.regex:/(development|debug|internal|_dev)/ AND resp.status.ne:404`

### Playbook 9: S3 Pre-Signed URL Abuse ($200 — College Board #3564700)

**The technique:** Higher Logic "filepicker" endpoint generated pre-signed S3 URLs without auth. The pre-signed URL pointed to the bucket root, enabling ListBucket + arbitrary file download.

**Step-by-step:**
1. Find file upload/download features that use S3 pre-signed URLs
2. Check if the URL-generation endpoint requires auth
3. If you get a pre-signed URL, check: does it scope to a specific object, or the bucket root?
4. If bucket root: GET the URL → ListBucketResult → enumerate all objects
5. Use `holdingPenKey` / object key parameter to get pre-signed URLs for specific objects
6. Download only first 8 bytes (`Range: bytes=0-7`) to prove file access without full exfil

**Detection workflow trigger:** `resp.body.cont:"X-Amz-Signature" OR resp.body.cont:"presigned" OR resp.body.cont:"s3.amazonaws.com"`

### Playbook 10: CloudFront/WAF Bypass ($150 × 2 — HudApp #3556481, #3556484)

**The technique:** The origin server was directly reachable by IP. CloudFront blocked injection payloads (403), but the same payloads sent directly to the origin IP with correct SNI/Host were processed normally (401 with app error, not WAF block).

**Step-by-step:**
1. Resolve the target domain to its IP address
2. Send a request directly to the IP with the original Host header: `curl --resolve target.com:443:$IP https://target.com/`
3. Compare responses: CDN path (blocked → 403) vs direct origin (processed → application error)
4. Test with injection payloads that the WAF blocks: SQLi, XSS, path traversal
5. If origin processes them: demonstrate the WAF bypass with both CDN and direct-origin requests

**Detection pattern:** During recon, check if origin IPs respond differently than CDN-fronted requests. Compare `Server` headers (CloudFront vs nginx/Apache).

### Playbook 11: Dependency Confusion ($250 — Sourcegraph #3494231)

**The technique:** `@sourcegraph/cody-web` listed `cody-ai` as a devDependency. The package didn't exist on public npm. Registering it at v99.9.9 meant any `npm install` would pull the attacker's package.

**Step-by-step:**
1. Find the target's package.json / requirements.txt / Gemfile
2. List all dependencies — especially unscoped internal names
3. Check if each dependency exists on the public registry (npm, PyPI, RubyGems)
4. If it doesn't exist: register it with a benign payload and high version number
5. Prove the attack: show that `npm install` would pull your package over the internal one
6. Offer to transfer the package to the target

**Detection:** Search GitHub org for `package.json`, `requirements.txt`. Look for unscoped internal-looking package names.

### Playbook 12: OAuth Code Leak via Referer ($100 — Mergify #3545612)

**The technique:** Third-party JS (tally.so) loaded on the OAuth callback page. The Referer header sent to tally.so included the full callback URL with `code` and `state` parameters.

**Step-by-step:**
1. Navigate to the OAuth callback URL with test parameters
2. Open Network tab — look for third-party requests (analytics, widgets, chat)
3. Check the Referer header on those requests — does it include sensitive query params?
4. Check Referrer-Policy header — `no-referrer-when-downgrade` leaks full URL to HTTPS destinations
5. Demonstrate with Playwright: script that navigates to callback URL and captures the Referer on the third-party request

**Detection workflow trigger:** `req.path.cont:/callback AND resp.body.regex:/(tally|segment|hotjar|intercom|hubspot|drift|crisp|freshdesk)/`

## Highest-Value Vulnerability Classes (Ranked by Your Data)

| Rank | Class | Avg Bounty | Reports | Key Technique |
|------|-------|-----------|---------|---------------|
| 1 | **SSRF** | $1,500 | 2 | URL parsing differentials, unauthenticated admin endpoints |
| 2 | **Business Logic** | $1,050 | 2 | Weaponized patches, email domain privilege escalation |
| 3 | **Unauthenticated Data Exposure** | $577 | 3 | Non-prod envs, onboarding flows, setup tokens |
| 4 | **Path Traversal / CVE** | $750 | 2 | Known CVEs on user deployments, speed = first reporter |
| 5 | **BFLA / Debug Endpoints** | $500 | 1 | Dev API routes, CSRF as only gate |
| 6 | **Dependency Confusion** | $250 | 1 | Unclaimed internal package names on public registries |
| 7 | **Cloud/CDN Misconfiguration** | $200 | 3 | WAF bypass via origin IP, S3 pre-signed URL abuse |
| 8 | **OAuth/Auth Leaks** | $100 | 2 | Referer header leaks, HTML injection in OAuth params |

## What Gets $0 / Informational / N/A

### Patterns That Get Rejected
- **Broken link hijacking** without actual code execution — theoretical supply chain risk = informational (#3370223, $0)
- **Scanner output without validation** — pasting nuclei/Burp results without PoC
- **Self-XSS** — fires in your own session only, no victim path
- **Missing security headers alone** — informational unless chained
- **HTML injection without chain** — paid only $100 at Zoom, most programs N/A it
- **Open redirect without chain** — low/informational unless → OAuth token theft
- **Business logic that's borderline** — Duolingo paid $100 then marked "informative" (they couldn't decide)

## Community Disclosed Reports — Mega-Bounty Playbooks

These are the $10K-$100K+ techniques from public HackerOne reports. Study the chain, not just the bug.

### Playbook A: Import/Export Feature → Deserialization → RCE ($33,510 — GitLab #1679624)

**The full chain:** GitHub import uses Sawyer library to recursively create Ruby objects from JSON. Attacker controls the JSON shape, overrides `to_s` and `bytesize` methods on Sawyer::Resource. Redis gem uses `to_s`/`bytesize` to format RESP commands → attacker injects arbitrary Redis commands. Combined with `Marshal.load` on `_gitlab_session` cookie → universal deserialization gadget → RCE.

**The key insight:** The patch for CVE-2022-2884 added validation to `Gitlab::Cache::Import::Caching` but missed another code path where Sawyer::Resource reaches Redis via `default_branch` → `change_head` → `branch_names_include?`. **Patch bypasses find the paths the fix missed.**

**Replicable technique:**
1. Find any import/export/migration feature that processes untrusted structured data (JSON, XML, YAML, archives)
2. Trace which libraries deserialize the data — Sawyer, Jackson, pickle, YAML, Marshal
3. Check if user-controlled object properties reach downstream systems (Redis, databases, template engines)
4. If `to_s`, `toString`, `__str__` can be overridden → injection into protocols that use string representation
5. Look for deserialization gadget chains in the dependency tree

**Where to hunt:** Any SaaS product with import functionality — project import, data import, CSV/JSON/XML upload, API response processing.

### Playbook B: Protocol Switching via Missing Scheme Restriction ($22,300 — GitLab #1685822)

**The full chain:** GitLab BulkImport uses `httpUrlToRepo` from the API response to fetch repos. `Gitlab::UrlBlocker.validate!` is called but **no allowed schemas are specified**, so `file://` is accepted. Attacker supplies `file://aw.rs/var/opt/gitlab/git-data/repositories/@hashed/<sha>.git` → clones any private repository on the server.

**The key insight:** URL validators that check host/IP but don't restrict protocol allow `file://` local file access. GitLab hashes project IDs to create predictable storage paths: `SHA256(project_id)` → `@hashed/xx/yy/full_hash.git`.

**Replicable technique:**
1. Find any URL validation that doesn't explicitly restrict to `http://` and `https://`
2. Test: `file:///etc/passwd`, `gopher://localhost:6379/`, `dict://localhost:6379/`, `ftp://internal/`
3. If the app stores data at predictable paths (hashed IDs, sequential paths), calculate paths from known IDs
4. Combine file read + predictable paths → read any stored data

### Playbook C: SQL Injection → Transaction Escape → Deserialization RCE (Undisclosed — HackerOne #1663299)

**The full chain:** HackerOne's internal `EXPLAIN ANALYZE` tool interpolates raw SQL. Attacker escapes the read-only transaction with `ROLLBACK;`, injects YAML deserialization payload into `user_versions` table via `INSERT`, then triggers `reify` method (paper_trail gem) on another page → YAML deserialization → RCE.

**The key insight:** Second-order attack — inject in one place (SQL tool), trigger from another (historic users page). The `ROLLBACK` + `INSERT` + `--` comment pattern escapes any transaction wrapper. The app inherently trusts serialized objects in the database.

**Replicable technique:**
1. Find any SQL execution feature (admin panels, debug tools, reporting, analytics)
2. Test transaction escape: `SELECT 1; ROLLBACK; INSERT INTO...`
3. Look for serialized/YAML/JSON columns in the database that get deserialized on read
4. Paper_trail, Audited, any "version history" gem stores serialized objects
5. Inject payload into serialized column, trigger deserialization from a different endpoint

**Where to hunt:** Internal/admin tools, debugging features, analytics engines, any tool that runs user-provided SQL.

### Playbook D: Stored XSS via New Feature Autocomplete ($13,950 — GitLab #1578400)

**The full chain:** GitLab 15.0.0 added Customer Relations feature. Contact first/last names rendered without sanitization in `/add_contacts` quick command autocomplete dropdown. `<script>alert(document.domain)</script>` in name field → XSS triggers when any user types the quick command.

**Replicable technique:**
1. Monitor target's release notes for NEW features (first release = least security review)
2. Find user-controlled "name" fields (first name, last name, company, team, project)
3. Check where those names render — autocomplete, dropdowns, search suggestions, notifications
4. Autocomplete/search suggestions often use `innerHTML` and bypass the main app's sanitization
5. Quick commands, keyboard shortcuts, slash commands — these render in popups with different sanitization

**Where to hunt:** Any app with autocomplete, tagging, mentions, quick commands, or contact/user management.

### Playbook E: SSRF in PDF/Report Generation ($25,000 — HackerOne Analytics)

**The full chain:** HackerOne's analytics reports feature generates PDFs from HTML templates. Attacker injects `<iframe src="http://169.254.169.254/...">` into report content. The PDF renderer (server-side headless browser) fetches the URL, including AWS metadata endpoint → temporary IAM credentials → infrastructure access.

**Replicable technique:**
1. Find any PDF/report/export generation feature (analytics, invoices, certificates, tickets)
2. Check if user content is rendered in the PDF (titles, descriptions, names, comments)
3. Inject: `<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">`, `<img src="http://OAST">`, `<link href="http://OAST">`
4. If server-side rendering (wkhtmltopdf, Puppeteer, Chrome headless), it fetches the URLs
5. Cloud metadata → IAM creds → S3/EC2/Lambda access

**Where to hunt:** Any feature that converts HTML to PDF, generates reports, renders email templates server-side, or creates document exports.

### Playbook F: OAuth Response Mode Switching → Account Takeover (Undisclosed — Reddit #1567186)

**The full chain:** Reddit's Apple Sign-In configured `response_mode=web_message` but didn't disable other modes. Attacker switches to `response_mode=fragment` + `response_type=code+id_token` → tokens land in URL fragment. Combined with XSS on `redditmedia.com` sandbox domain + `window.name` cross-origin trick → steal code + id_token → account takeover.

**Replicable technique:**
1. Identify the OAuth provider (Apple, Google, Microsoft, GitHub, etc.)
2. Capture the authorize request and note `response_mode` and `response_type`
3. Switch response_mode: `web_message` → `fragment`, `query` → `fragment`, try `form_post`
4. Switch response_type: `code` → `code+id_token`, `code` → `token`
5. If tokens land in fragment/query: find XSS on any subdomain of the redirect_uri domain
6. `window.name` trick: set `window.name` in parent, read it cross-origin after redirect

**Where to hunt:** Any app using social login (Apple, Google, Microsoft, Facebook Sign-In). Check every provider separately — each has different quirks.

## Google VRP Intelligence — The $100K+ Playbook

Google runs multiple VRP programs. Cloud VRP alone paid $1.6M at a single 5-week Bug Swat event in 2025.

### Programs & Max Bounties

| Program | Max Bounty | Key Surface |
|---------|-----------|-------------|
| **Chrome VRP** | $250,000 | V8, renderer, extension APIs |
| **Mobile VRP** | $300,000 | Android, top-tier apps |
| **Google/Alphabet VRP** | $151,515 | Web products, Workspace |
| **Cloud VRP** (GCP) | $101,010 | Several hundred cloud products |

### Cloud VRP — How Bounties Are Calculated

**Privilege escalation delta** is the core metric. The larger the gap between starting access and ending impact, the larger the payout.

| Severity | Definition | Min Payout |
|----------|-----------|------------|
| **S0** | Cross-tenant impact, no org permissions required | $7,500+ |
| **S1a** | Complete project/org takeover from authenticated user | High |
| **S1c** | Multi-service privilege escalation | Medium-High |
| **S1f** | Single-service privilege escalation | Medium |
| **S2** | Metadata leaks, limited-impact issues | Lower |

**Tier system:** Products are Tier 1 (Cloud Storage, GKE, IAM — max bounty), Tier 2, Tier 3A, Tier 3B. Severity × Tier = payout. Acquisitions start at Tier 3A, move up ~3 years post-acquisition.

**Report quality multiplier:** 1.2x for exceptional reports, 0.8x for poor quality. Google explicitly prefers concise reports over 20-page papers.

**Downgrades:** Prior access (uncommon starting permissions), user interaction (beyond normal product usage), low exploitability (few affected customers), uncommon configuration. If Google's docs recommend the config, cite them to counter downgrade.

### Playbook G: Service Account Impersonation Chain → Full Admin ($$$$ — Google SecOps SOAR, bugSWAT 2025 Winner)

**The full chain (from Jakub Domeracki's winning research):**

1. **Starting position:** Authenticated user with `Basic` role (can perform Manual Actions)
2. **Get SA token:** Use HTTPv2 integration's full SSRF (no link-local blocking) to fetch `http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token` → get `gke-init-python` service account OAuth token with `cloud-platform` scope
3. **Alternative path:** SSTI in TemplateEngine PowerUp (Jinja2, `subprocess.Popen` already imported) → code execution → same SA token
4. **Impersonation chain:** `gke-init-python` has project-wide `iam.serviceAccountTokenCreator` → can impersonate `secops-auth` service account
5. **JWT forgery:** `secops-auth` is the issuer of SOAR JWTs → sign arbitrary JWT with admin claims using `projects.serviceAccounts.signJwt` API
6. **Privilege escalation:** Exchange forged `SOAR_SIGNED_JWT` for `SIEMPLIFY_SIGNED_JWT` → full Administrator access

**Why this won "most creative":** Multiple researchers found individual pieces (SSRF, SSTI, SA token access) but couldn't prove impact. Jakub connected the dots: SA impersonation chain was the missing link that proved viewer → admin escalation. Google retroactively rewarded ALL researchers who had partial chains.

**Replicable technique for any cloud product:**
1. Get code execution or SSRF in any cloud-hosted product
2. Fetch metadata server → get service account token
3. Enumerate SA permissions: `gcloud iam service-accounts list`, `testIamPermissions()`
4. Check for `iam.serviceAccountTokenCreator` on other SAs → impersonation chain
5. Find what the target SA can do (sign JWTs? access other APIs? impersonate further?)
6. Map the full chain: starting role → SA token → impersonate → target permissions

**Key GCP patterns:**
- Default service accounts often have overly broad permissions
- Per-product service accounts (P4SA) can impersonate each other if IAM bindings are too permissive
- `cloud-platform` scope on an SA token = access to nearly all GCP APIs
- GKE Workload Identity Federation binds SAs to pods — compromise pod → get SA token

### Playbook H: XSS → Cloud Shell RCE (Google Cloud Console)

**The technique:** XSS on GCP Console can chain to RCE on customer instances via Cloud Shell. But you must demonstrate the full chain — theoretical maximum impact is not enough.

**Replicable technique:**
1. Find XSS on any `console.cloud.google.com` page
2. Chain to Cloud Shell: `fetch('/cloudshell/v1alpha1/...')` with RCE payload
3. The XSS → Cloud Shell → customer instance chain is S0 on Tier 1 = maximum payout
4. Delivery matters: exploiting an internal GCP ticketing flow (victim guaranteed to have permissions) rates higher than email link (requires clicking)

### Playbook I: CI/CD Self-Hosted Runner Attack ($13,337 — TensorFlow)

**The technique:** Google's open-source repos use non-ephemeral self-hosted runners for CI/CD. Fork PRs can modify workflows and execute on the self-hosted runner → `GITHUB_TOKEN` with write permissions → lateral movement.

**Replicable technique:**
1. Find the target org's GitHub repos (in scope for Google VRP: TensorFlow, Angular, Chromium, etc.)
2. Check `.github/workflows/` for `self-hosted` runner labels
3. Check if `pull_request_target` is used (runs in repo context, not fork context)
4. Fork the repo, modify workflow to exfiltrate `GITHUB_TOKEN` and environment secrets
5. Non-ephemeral runners allow persistence + secret theft from previous builds

### Google VRP Hunting Checklist (Updated)

| Target | What to test | Expected payout range |
|--------|-------------|----------------------|
| **GCP product integrations** | Service account impersonation chains, SSRF to metadata | $10K-$100K+ |
| **Cloud Console** | XSS → Cloud Shell RCE chain | $20K-$100K+ |
| **Google Accounts / GAIA** | Login CSRF, OAuth misconfig, response_mode switching | $3K-$15K |
| **Workspace apps** | Sharing bypass, XSS in rendering, API IDOR | $5K-$20K |
| **Open-source repos** | CI/CD runner attack, dependency confusion | $5K-$13K |
| **Firebase / Cloud Functions** | Security rules bypass, unauthenticated invocation | $3K-$10K |
| **Sandbox domains** | XSS on googleusercontent.com → cookie tossing → CSRF bypass | $5K-$20K |

### Google VRP Tips

- **Privilege escalation delta = payout.** Starting with viewer and ending with admin pays 10x more than starting with editor and ending with admin.
- **Use Terraform** with Google's sample configs to set up testing environments. Matches real customer deployments and counters "uncommon configuration" downgrade.
- **Map the full chain.** Partial findings get partial rewards (or nothing). The impersonation chain that Jakub found retroactively rewarded 10+ researchers who had partial chains.
- **Cite Google's own docs.** If the config is recommended in Google docs, it counters the "wacky configuration" downgrade.
- **Don't use AI to write reports.** Google explicitly calls this out as a quality downgrade trigger.
- **Concise > comprehensive.** Keep the report focused on what/how/why. Attach full research as supplement.

## Meta-Patterns Across All $10K+ Reports

### What the mega-bounty researchers do differently

1. **They chain, always.** A standalone XSS pays $3K. XSS → Cloud Shell → RCE on customer instance pays $50K+. A standalone SSRF pays $5K. SSRF → SA token → impersonation chain → admin pays $50K+.

2. **They target the fix, not the feature.** GitLab's $33K RCE was a patch bypass. Replit's $2K was a weaponized patch. The fix adds validation in one spot but misses another code path — find that path.

3. **They go where automation can't.** Import/export features, deserialization chains, protocol switching, OAuth response mode manipulation, service account impersonation — none of these are found by scanners.

4. **They understand the architecture.** The SA impersonation chain required understanding GKE Workload Identity, IAM bindings, and JWT signing. The GitLab RCE required understanding Sawyer's object creation, Redis RESP format, and paper_trail's reify method.

5. **They submit partial chains and iterate.** Multiple researchers submitted partial SA impersonation findings at the Bug Swat. When one researcher proved the full chain, ALL partial submissions got rewarded retroactively.

### Your personal trajectory: $600/avg → $5,000+/avg

| Current pattern | Upgrade to | Expected improvement |
|----------------|-----------|---------------------|
| Single-vuln findings | Chain two findings | 3-5x bounty |
| Surface-level recon | Deep architecture analysis | Find bugs automation misses |
| SSRF stopping at OAST proof | SSRF → metadata → IAM creds → S3/Lambda access | 2-5x bounty |
| XSS with `alert(1)` | XSS → admin action → privilege escalation PoC | 3-10x bounty |
| Reporting "missing auth" | Full attack scenario: viewer → admin via chain | 5-20x bounty |
| Avoiding cloud targets | GCP Cloud VRP with impersonation chains | 10-100x bounty |

## Report Quality — What Separates $100 from $100,000

### $10,000+ reports (from disclosed mega-bounty reports)

Every mega-bounty report had ALL of:
1. **Full chain demonstrated end-to-end** — not "this could lead to X" but "here's me doing X"
2. **Root cause analysis** pointing to the specific code path, line number, or architecture flaw
3. **Attack starting from lowest privilege** — viewer role, unauthenticated, basic user (maximizes impact delta)
4. **Proof of each step** — not just final impact, but evidence for every link in the chain
5. **Architecture diagram** or clear description of the trust boundaries crossed
6. **Remediation that addresses the root cause** — not "validate input" but "remove project-wide serviceAccountTokenCreator binding" or "add scheme whitelist to UrlBlocker.validate!"

### $1,000+ reports

Every $1,000+ report had:
1. **Standalone Python PoC script** with `argparse`, clean output, error handling
2. **Error differential proof** — showing different behavior for valid vs invalid inputs
3. **Remediation that's architecturally specific** (not "validate input" but "parse URL with stdlib, reject userinfo, block private IP ranges after DNS resolution, re-validate on redirects")
4. **Impact quantified** in business terms (affected users, regulatory exposure, financial impact)
5. **OAST/interaction proof** for blind vulns (not just "I believe the server makes a request")

### $100-$250 reports (what to avoid)

Reports in this range typically had:
1. Screenshot-heavy, light on raw HTTP
2. Single-step PoC (manual browser steps, no script)
3. Impact described generically ("attacker can do bad things")
4. No error differential — just "it works"

## Using H1 Brain During Hunting

### Pre-hunt intel
```
hack(handle="program_handle")
```
Returns: scope, disclosed reports, attack briefing. Use this FIRST before any testing.

### Research prior art
```
search_disclosed_reports(program="target_program", weakness="SSRF")
search_disclosed_reports(query="OAuth redirect")
get_disclosed_report(report_id=1679624)
```
Use disclosed reports for: severity precedent, impact framing, bypass techniques to reuse.

### After finding a vuln
```
search_disclosed_reports(weakness="IDOR", limit=10)
```
Find similar reports for: severity justification, report structure, remediation wording.

## Source
Generated from H1 Brain MCP data (17 personal reports), public HackerOne disclosed reports (#1679624 $33K RCE, #1685822 $22K file access, #1663299 SQLi→RCE, #1578400 $14K XSS, HackerOne $25K SSRF, Reddit ATO), Google Cloud VRP bugSWAT 2025 writeups (Jakub Domeracki SA impersonation chain), and Google VRP program documentation. Run `get_report_summary` to refresh personal data.
