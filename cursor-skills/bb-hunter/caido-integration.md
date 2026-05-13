# Caido Integration Patterns

Advanced Caido usage — passive detection, self-adapting workflows, automated triage, investigation pipeline, and feedback loops. Reference architecture inspired by trace37's mastermind-ai system.

The goal: a proxy that **thinks** — watches traffic in real-time, generates target-specific detection rules, routes confirmed signals to specialist investigation, and refines its own detection based on true/false positive feedback.

## Architecture Overview

```
Caido Core + Passive Workflows
  → Event Bridge (poll new findings, dedup, pre-filter)
    → Heuristic Layer (evaluate, generate ephemeral retest workflows)
      → Investigation Pipeline (queue, batch, dispatch to specialist skills)
        → Findings flow back to Caido + knowledge vault + notifications
```

Five layers, each progressively filtering signal from noise:

1. **Broad detection** — 50+ permanent passive workflows fire on every response
2. **Pre-filter** — skip known noise (CDN, analytics, tracking), dedup by title+host
3. **Heuristic retest** — ephemeral workflows tighten the pattern, confirm before escalating
4. **AI triage** — batch findings (5:1 ratio) for severity assessment
5. **Specialist investigation** — route confirmed signals to the right strix-* skill

## Passive Workflows (Broad Detection Net)

Caido passive workflows are directed graphs of typed nodes that fire on every intercepted request/response. They're the first detection layer — always on, covering every target.

### What to detect

| Category | Pattern | Why | Bounty Proof |
|----------|---------|-----|-------------|
| **DOM sinks** | `innerHTML`, `document.write`, `eval(`, `dangerouslySetInnerHTML` | Potential XSS — needs taint tracing to confirm | |
| **CORS** | Origin reflected in `Access-Control-Allow-Origin` + `Credentials: true` | Data theft if exploitable | |
| **SSRF params** | `url=`, `callback=`, `redirect=`, `webhook=`, `proxy=`, `fetch=`, `url-b64` | SSRF candidates | Gravie $2,000 |
| **Open redirect** | `302/301` with user-controlled `Location` header | Phishing + OAuth chain pivot | |
| **JWT weakness** | `alg:none`, weak HMAC, missing signature validation | Auth bypass | |
| **SSTI indicators** | Template syntax in responses (`{{`, `${`, `<%`) after injection | Code execution | |
| **Sensitive data** | `api_key`, `secret`, `token`, `credential`, `password` in responses | Info disclosure | |
| **GraphQL** | Introspection enabled, mutation endpoints, batching support | Auth bypass, DoS | |
| **Prototype pollution** | `__proto__`, `constructor.prototype` in JS responses | XSS/RCE via gadgets | |
| **Smuggling indicators** | `Transfer-Encoding` + `Content-Length` conflict, CL.TE patterns | Request smuggling | |
| **Host header** | Response varies with `Host` / `X-Forwarded-Host` manipulation | Cache poisoning, SSRF | |
| **CSP issues** | Weak or missing CSP, `unsafe-inline`, `unsafe-eval`, wildcard sources | XSS enabler | |
| **CSPT** | Client-side path traversal in JS routing / dynamic imports | Open redirect, data theft | |
| **WebSocket auth** | JWT/Bearer/token in WS handshake or messages | Session hijack | |
| **Setup tokens** | `setup-token`, `setup_token`, `initial-setup` in responses | Admin takeover | Cambly $1,000 |
| **Unauthenticated admin** | `/admin/`, `/actuator/`, `/debug/`, `/development/` returning 200 | BFLA, info disclosure | Found $500, Superbet $1,000 |
| **Non-prod environments** | `qa-*`, `*-dev.*`, `staging.*` subdomains responding with data | Data exposure without auth | Petco $600 |
| **S3 pre-signed URLs** | `X-Amz-Signature`, `presigned`, `s3.amazonaws.com` in responses | Bucket listing, file download | College Board $200 |
| **OAuth callback leaks** | Third-party JS on `/callback` pages + permissive Referrer-Policy | Auth code leak via Referer | Mergify $100 |
| **Origin IP exposure** | Different `Server` header on direct IP vs CDN (nginx vs CloudFront) | WAF bypass | HudApp $300 |
| **Token-based URLs** | `/application/<token>`, `/invite/<token>` returning 200 without auth | PII exposure, IDOR | DoorDash $931 |

### Workflow structure

Each workflow is a directed graph: HTTPQL matcher → scope filter → If/Else → JavaScript logic → finding creation (with dedup via `Check Finding`).

```
[HTTPQL Match] → [In Scope?] → [JS: extract + evaluate] → [Check Finding (dedup)] → [Create Finding]
```

Key: use `Check Finding` node to prevent duplicate findings for the same pattern on the same host. Without this, high-traffic sites flood findings.

### Workflow management via API

When Caido MCP is available, workflows become programmable:
```
create_workflow(name, kind="passive", definition={...})  # create new detection
update_workflow(id, definition={...})                     # refine detection
toggle_workflow(id, enabled=true/false)                   # enable/disable
delete_workflow(id)                                       # remove ephemeral ones
```

This is what enables self-adapting detection — the system creates, refines, and deletes its own workflows.

## Self-Adapting Workflows (Heuristic Layer)

Static workflows detect what you tell them to. Self-adapting workflows bridge the gap between "detection" and "finding."

### The problem

"This response contains `dangerouslySetInnerHTML`" tells you the technology exists. It doesn't tell you whether user input reaches that sink. "This response reflects the Origin header" doesn't mean credentials are attached. The gap between detection and confirmed finding is where most noise lives.

### The solution: ephemeral [MM] workflows

When a permanent workflow fires a detection:

1. **Evaluate** — is this worth retesting? Check against known patterns, target tech stack, prior findings
2. **Generate** — create a tighter, target-specific passive workflow prefixed `[MM]` that:
   - Narrows the HTTPQL match to the specific host/path
   - Adds deeper validation (e.g., CORS detection → check if credentials are actually attached)
   - Includes response body inspection (only when the path warrants the CPU cost)
3. **Monitor** — the ephemeral workflow watches for the tighter pattern
4. **Confirm or expire** — if the tighter pattern matches → escalate to investigation. If no match within TTL → delete the workflow

### Example: CORS detection → confirmation

```
Permanent workflow: "Origin reflected in ACAO header"
  → Fires on: example.com returns ACAO: https://evil.com

Ephemeral [MM] workflow generated:
  - Match: req.host.eq:example.com AND resp.header.cont:Access-Control-Allow-Credentials
  - JS node: verify Origin is fully reflected (not just subdomain match), 
             check credentials=true, check response contains sensitive data
  - If confirmed: create HIGH finding "CORS: credentials + full origin reflection on example.com"
  - TTL: 2 hours, then auto-delete
```

### Design principles

- Permanent workflows are **broad and cheap** — path/header matching, no body decode unless necessary
- Ephemeral workflows are **narrow and deep** — specific host, full body analysis, JS validation logic
- Body decoding is expensive — only decode when the path/headers suggest it's worth it
- Every ephemeral workflow has a TTL — delete if no confirmation within the window
- Confirmed findings from ephemeral workflows have much higher signal than raw permanent detections

## Event Bridge (Automated Triage Pipeline)

A persistent daemon that polls Caido for new findings and runs them through a multi-step pipeline.

### Pipeline stages

```
[Pre-filter] → [Dedup] → [AI Triage (batch)] → [Vault Write] → [Escalation Check] → [Notification]
```

1. **Pre-filter** — skip known noise domains (CDN assets, analytics, tracking pixels) and title patterns that are always false positives
2. **Dedup** — hash by title+host so the same finding type on the same host is only reviewed once. Maintain state across restarts (last N finding IDs)
3. **AI triage** — batch up to 5 findings per LLM call for severity assessment and one-line summaries. Cuts API cost ~5x vs 1:1 processing
4. **Vault write** — append triaged finding to daily investigation notes (Obsidian, markdown, or cursor-mem)
5. **Escalation check** — evaluate against escalation rules for deep investigation
6. **Notification** — push to mobile (ntfy.sh or similar) for MEDIUM+ findings

### Escalation rules

Map passive workflow findings to specialist skills with per-rule cooldowns:

| Detection | Route to | Cooldown | Notes |
|-----------|----------|----------|-------|
| DOM Sink Collector | `strix-xss` (via taint trace first) | 60s | Don't XSS-hunt raw sinks — trace source→sink path first |
| CORS Reality Check | `strix-csrf` / CORS specialist | 120s | Only if `origin reflected` + `credentials: true` |
| SSTI Indicator | `strix-rce` | 60s | Template syntax in response after controlled input |
| Open Redirect | `strix-open-redirect` | 120s | Also check OAuth chain potential |
| JWT Weakness | `strix-authentication-jwt` | 120s | `alg:none`, HS256 with weak key |
| SSRF Parameter | `strix-ssrf` | 60s | URL/callback/webhook params |
| GraphQL | `strix-graphql` | 120s | Introspection, mutations, batching |
| Prototype Pollution | Custom investigation | 120s | Need to find the gadget |
| Smuggling Indicator | Custom investigation | 120s | CL.TE / TE.CL differential |
| Sensitive Data | `strix-information-disclosure` | 60s | API keys, secrets, tokens in responses |
| WebSocket Auth | Custom investigation | 120s | JWT/Bearer in WS messages |

**Routing principle:** DOM sinks go to taint analysis first, not directly to XSS hunting. Detecting `innerHTML` in a response tells you the technology exists — it doesn't tell you whether user input reaches that sink. Always trace source→sink before exploitation.

### Cooldowns prevent re-investigation

Each escalation rule has a per-host cooldown. If CORS fires on `api.target.com` and the cooldown is 120s, the same host won't trigger another CORS investigation for 2 minutes. This prevents the same endpoint from spawning repeated investigations as the user browses.

## Investigation Pipeline

The flow from detection to specialist investigation.

### Queue management

When a finding passes triage:
1. **Batch** — group requests from the same host (up to 5 per batch) to give connected context
2. **Dedup** — hash `host + path + method + type + hunter` to avoid re-investigating the same endpoint
3. **Dispatch** — send to the appropriate specialist skill with full request context

### Manual sends bypass triage

When you explicitly send a request to investigation (right-click → investigate, or manual queue), it bypasses the triage gate entirely. You asked for it, so it gets investigated. Only auto-escalations from the event bridge go through the full triage pipeline.

### Persistent session context

The investigation session accumulates knowledge across requests. If it discovers that a target uses React with a specific GraphQL schema, that context persists for the next request from the same host. This is fundamentally different from spawning a fresh analysis per request.

Techniques for maintaining context:
- Use `cursor-mem observe` to store recon data, tech stack, findings per target
- Group investigations by host — findings on `api.target.com` inform future `api.target.com` investigations
- When a new host appears, check cursor-mem for prior context before starting fresh

## WebSocket Traffic Monitoring

WebSocket connections are a blind spot in most hunting workflows. HTTP passive workflows don't see WS messages.

### Patterns to detect in WS messages

| Pattern | Severity | Why |
|---------|----------|-----|
| JWT tokens (`eyJ...`) | HIGH | Auth token in message — replay, hijack |
| Bearer/access_token | HIGH | Same — extractable credential |
| API keys | MEDIUM | Service credential exposure |
| Admin/delete/promote actions | MEDIUM | Privileged state mutations over WS |
| Role/permission changes | MEDIUM | Authorization bypass vector |
| Payment/amount/price | MEDIUM | Financial manipulation |
| SQL statements | HIGH | Direct SQL in WS — injection likely |
| `exec`/`eval`/`system`/`popen` | HIGH | Command execution keywords |
| Internal URLs (localhost, 10.x, 127.x) | MEDIUM | Internal service exposure |
| `debug: true` | LOW | Debug mode active in production |

### Implementation

If Caido MCP supports WebSocket operations (`list_websocket_streams`, `get_websocket_message`):
1. Poll WS streams periodically
2. Fetch recent messages
3. Scan against pattern set (compiled regex for speed)
4. HIGH alerts escalate to investigation
5. MEDIUM+ alerts write to knowledge vault + notify
6. Maintain dedup state (last N message IDs) to avoid reprocessing

## Feedback Loop (Self-Improving Detection)

The system gets smarter over time through a feedback loop.

### How it works

```
Detection → Investigation → Outcome (TP/FP) → Refine detection
```

1. **True positive confirmed** → the detection rule that caught it gets a higher confidence weight. Consider making the ephemeral pattern permanent.
2. **False positive** → analyze why. Was the pattern too broad? Add exclusion. Was the context wrong? Tighten the HTTPQL match.
3. **Missed finding** (found manually, no workflow caught it) → create a new permanent workflow for the pattern.

### Practical implementation

- Tag findings with source workflow ID when creating them
- When closing investigation: mark as TP (true positive), FP (false positive), or noise
- Periodically review: which workflows produce the most TPs? Which produce the most FPs?
- Workflows with high FP rates → tighten or disable
- Workflows with high TP rates → ensure they're robust, consider adding variants

### Target-specific tuning

Different targets have different noise profiles:
- React app? Expect lots of `dangerouslySetInnerHTML` detections — most are framework usage, not vulns
- GraphQL API? Introspection detection fires once — after that, it's known state, not a new finding
- Legacy app with verbose errors? Sensitive data detections will flood — filter by actual secret patterns

Use target-specific profiles or per-host suppression lists to manage this.

## Knowledge Vault (Cross-Session State)

Findings, recon, and investigation state need to persist across sessions. Without this, every session starts cold.

### What to persist (via cursor-mem or markdown vault)

| Type | Content | Persistence |
|------|---------|-------------|
| **finding** | Confirmed vulnerabilities with PoC | Permanent |
| **recon** | Subdomains, endpoints, tech stack per target | Until stale (re-verify periodically) |
| **decision** | Why you chose this approach, what you tried, what failed | Permanent |
| **detection** | Which passive workflows are active, which are tuned per target | Permanent |
| **chain** | Partial chains — finding A exists, looking for finding B to complete | Permanent until resolved |
| **false_positive** | Known FPs per target — don't re-investigate | Permanent |

### Cross-finding correlation

The real power of persistent state: connecting findings across sessions.

- CORS misconfiguration found on session 1 + OAuth state fixation found on session 3 → chain candidate
- Open redirect on subdomain A + OAuth flow on subdomain B → redirect_uri hijack
- Info disclosure of internal paths on endpoint X + SSRF parameter on endpoint Y → internal access

When storing findings, always tag with target domain, vuln class, and potential chain partners. When starting a new investigation, search for prior findings on the same target that could chain.

### Using cursor-mem for this

```bash
# Store a finding with chain potential
cursor-mem observe <sid> finding "CORS: full origin reflection + credentials on api.target.com. Chain potential: OAuth token theft if redirect_uri accepts api.target.com"

# Before investigating a new target, check for prior context
cursor-mem search "target.com"

# Search by vuln class across all targets
cursor-mem search "CORS"
cursor-mem search "open redirect"
```

## Technology-Aware Detection Templates

When recon fingerprints a target's tech stack, generate detection workflows for technology-specific misconfigurations that the generic 50+ permanent workflows don't cover.

### Template library

| Tech | Detection | Severity | What it catches |
|------|-----------|----------|-----------------|
| **Spring Boot** | `/actuator/env` exposed | HIGH | Database credentials, API keys, Spring config |
| **Spring Boot** | `/actuator/health`, `/actuator/info`, `/actuator/mappings` | MEDIUM | Internal service topology, route map |
| **Django** | `You're seeing this error because you have DEBUG = True` | CRITICAL | Full settings dump, SQL queries, source code paths |
| **Django** | `django.contrib.admin` in response | MEDIUM | Admin panel location |
| **Laravel** | `Whoops\Handler\PrettyPageHandler` in response | CRITICAL | APP_KEY, database credentials, full stack trace |
| **Laravel** | `APP_DEBUG=true` indicators | HIGH | Detailed error pages with env vars |
| **WordPress** | `/wp-json/wp/v2/users` accessible | MEDIUM | User enumeration without auth |
| **WordPress** | `wp-config.php` backup variants | CRITICAL | Database creds, auth keys |
| **AEM** | `/crx/de`, `/crx/explorer`, `/system/console` | CRITICAL | Adobe Experience Manager admin consoles |
| **AEM** | `jcr:content` in response paths | MEDIUM | Content repository traversal |
| **Express/Node** | Stack trace with `node_modules/` paths | MEDIUM | Internal file structure, dependency versions |
| **Express/Node** | `X-Powered-By: Express` + verbose errors | LOW | Tech fingerprint + error info |
| **Tomcat** | `/manager/html`, `/host-manager` | CRITICAL | Tomcat Manager — default creds → RCE |
| **Tomcat** | Tomcat default error page with version | MEDIUM | Version disclosure for CVE matching |
| **PHP** | `phpinfo()` page accessible | HIGH | Full server config, loaded modules, env vars |
| **PHP** | `X-Powered-By: PHP/x.x.x` | LOW | Version disclosure |
| **Ruby/Rails** | `ActionController::RoutingError` with route dump | MEDIUM | Full route table disclosure |
| **Next.js** | `/_next/data/` with build ID enumeration | MEDIUM | Server-side data leak via getServerSideProps |
| **GraphQL** | Introspection + GraphiQL UI | HIGH | Full schema + interactive query interface |

### How to use

When `httpx` or Caido fingerprints the tech stack:
1. Check the template library for matching technology
2. Create ephemeral `[MM]` workflows for those patterns
3. As you browse, the workflows fire if the misconfiguration exists
4. Findings route to `strix-information-disclosure` or the tech-specific skill

### HTTPQL examples for tech detection

```
# Spring Actuator
req.path.cont:/actuator AND resp.status.eq:200

# Django debug
resp.body.cont:"You're seeing this error"

# Laravel Whoops
resp.body.cont:"Whoops\\Handler"

# Tomcat Manager
req.path.cont:/manager/html AND resp.status.ne:404

# WordPress user enum
req.path.cont:/wp-json/wp/v2/users AND resp.status.eq:200
```

## Traffic Interception Patterns

When intercepting live traffic (via plugin backend or passive workflow JS nodes), optimize for cost:

### Cheap path-based detection (runs on every response)

```javascript
const path = request.getPath();
const host = request.getHost();
const code = response.getCode();

// Auth endpoints — always interesting
if (path.includes("/oauth") || path.includes("/auth") || 
    path.includes("/token") || path.includes("/login") || 
    path.includes("/saml")) {
    // Log + flag for auth testing
}

// API versioned endpoints
if (path.match(/\/api\/v\d+/) || path.includes("/swagger") || 
    path.includes("/openapi")) {
    // Log + flag for API testing
}

// Admin/debug surface
if (path.includes("/admin") || path.includes("/debug") || 
    path.includes("/actuator") || path.includes("/console")) {
    // HIGH priority — immediate investigation
}
```

### Expensive body decoding (only when path warrants it)

```javascript
// Only decode body when path suggests it's worth the CPU cost
if (path.includes("/graphql")) {
    const body = response.getBody()?.toText() ?? "";
    if (body.includes("__schema") && body.includes("queryType")) {
        // GraphQL introspection enabled
    }
}

// Only check response headers for CORS when we see a relevant path
if (path.includes("/api/") || path.includes("/graphql")) {
    const acao = response.getHeader("Access-Control-Allow-Origin");
    const acac = response.getHeader("Access-Control-Allow-Credentials");
    if (acao && acac === "true") {
        // CORS with credentials — high value
    }
}
```

**Key optimization:** Response body decoding is expensive. Path/header matching is cheap. Always filter by path first, only decode body when you have reason to believe it's worth it.

## CRLF / Header Injection Detection

### Detection workflow

Permanent workflow watches for CRLF indicators:
- `%0d%0a` or `%0D%0A` in request parameters that appear in response headers
- `\r\n` in response headers that shouldn't be there
- Custom header appearing in response after injection in parameter

### Ephemeral retest pattern

```
Permanent: "CRLF Indicator — parameter value reflected in response header"
  → Fires on: response header contains a value from request query string

[MM] CRLF Retest:
  - Match: req.host.cont:"target.com" AND res.raw.regex:/\r\n.*injected/
  - Only fires if the specific injection payload appears in response headers
  - Confirmed: create HIGH finding "CRLF: header injection on target.com/path"
```

### What CRLF enables (chain potential)

- **HTTP response splitting** → cache poisoning → stored XSS
- **Header injection** → `Set-Cookie` injection → session fixation
- **XSS via header** → inject `Content-Type: text/html` → body interpreted as HTML

## CSPT (Client-Side Path Traversal) Detection

CSPT is an underexplored vuln class. The client-side code uses user input to construct paths for dynamic imports, API calls, or routing — allowing path traversal within the client application.

### Detection patterns

```
# Watch for client-side path construction with user input
resp.body.cont:"window.location" AND resp.body.cont:"../"
resp.body.cont:"import(" AND resp.body.cont:"location.hash"
resp.body.cont:"fetch(" AND resp.body.cont:"pathname"
```

### What to look for in JS

- `fetch("/api/" + userInput)` — path traversal to hit different API endpoints
- Dynamic `import()` with URL-derived path — load arbitrary JS modules
- Client-side routing that uses hash/query to determine which component to load
- `document.location.pathname` used in resource loading without sanitization

### CSPT chain patterns

| CSPT Variant | Chain with | Impact |
|-------------|-----------|--------|
| Path traversal in API call | Different API endpoint with different auth model | Auth bypass |
| Dynamic import traversal | Load attacker-controlled JS module | XSS / code execution |
| Route manipulation | Navigate to admin component client-side | UI-level privilege escalation |
| Resource path traversal | Load cross-origin resource | Data theft |

## Attack Surface Mapping

Generate an annotated sitemap tree from Caido's captured traffic, cross-referenced with findings and JS analysis results.

### Sitemap tree format

```
target.com [5 findings] [23 JS sinks]
├── /api/ (142 req)
│   ├── /api/v1/users [FINDING: IDOR] (28 req)
│   ├── /api/v1/search (45 req)
│   └── /api/graphql [FINDING: Introspection enabled] (69 req)
├── /auth/ (34 req)
│   ├── /auth/login (12 req)
│   └── /auth/callback [FINDING: Open redirect] (22 req)
├── /admin/ (3 req) ⚠️ LOW COVERAGE
└── /static/js/ (340 req)
```

### How to build it

1. **Query Caido sitemap** — `get_sitemap` (recursive) for the target domain
2. **Cross-reference findings** — map each finding to its sitemap path
3. **Annotate with coverage** — request count per path shows testing depth
4. **Flag low coverage** — paths with <5 requests are undertested
5. **Include JS analysis** — overlay DOM sink/source counts per path

### When to use

- **Returning to a target after a break** — instantly see what's been tested and what hasn't
- **During a session** — identify undertested surface areas
- **Before reporting** — verify you covered the critical paths
- **Planning fuzzing campaigns** — see which paths need automated testing

### HTTPQL for coverage gaps

```
# Paths seen but never tested with modified requests
req.host.eq:target.com AND req.path.cont:/api/v2/ AND req.method.eq:GET

# Endpoints that returned errors (potential for deeper testing)
req.host.eq:target.com AND resp.status.gte:400 AND resp.status.lte:499

# POST/PUT/DELETE endpoints (state-changing — priority)
req.host.eq:target.com AND req.method.ne:GET AND resp.status.lt:400
```

## Campaign Planner (Automated Fuzzing Prioritization)

Analyze the Caido sitemap to identify the highest-value fuzzing targets, scored by pattern matching.

### Priority scoring

| Pattern | Score | Tag | Reason |
|---------|-------|-----|--------|
| `/api/` | 8 | api | API endpoint — IDOR, injection, auth bypass |
| `/graphql` | 9 | graphql | Introspection, batch, IDOR, injection |
| `/(auth\|oauth)` | 9 | auth | Auth flow — bypass, token manipulation |
| `/(upload\|import)` | 8 | upload | File operation — upload bypass, path traversal |
| `/(admin\|debug)` | 9 | admin | Admin surface — auth bypass, info disclosure |
| `/(order\|payment)` | 8 | business | Payment flow — manipulation, race conditions |
| `/(user\|profile\|account)` | 7 | user | User data — IDOR, mass assignment |
| `/(search\|filter\|query)` | 7 | search | Search — SQLi, XSS, SSRF |
| `/(webhook\|callback\|notify)` | 8 | webhook | SSRF, callback manipulation |
| `/(export\|download\|report)` | 7 | export | SSRF, XXE, path traversal |
| `/(invite\|share\|team)` | 7 | collab | Privilege escalation, token predictability |
| POST body present | +3 | post | State-changing — mass assignment, injection |
| Query string parameters | +2 | params | Parameter-based attacks |
| JSON content-type | +2 | json | Mass assignment, injection |
| Versioned API (`/v1/`, `/v2/`) | +2 | versioned | Old versions lack newer security controls |

### Usage

1. After recon + initial browsing, review the sitemap
2. Score each path against the priority patterns
3. Start fuzzing from the highest-scored targets
4. Use Caido Automate (`create_automate_session`) to launch Intruder-style campaigns
5. Select wordlists based on the tag (api → IDOR wordlist, search → SQLi wordlist, upload → extension bypass list)

### Example output

```
1. [17] #################
   api.target.com/v1/signup/initiate
   [api] [auth] [versioned]
   - Versioned API — test for version-specific vulns
   - Registration — test mass assignment, bypass

2. [16] ################
   api.target.com/v1/account
   [api] [auth] [post] [json]
   - API endpoint — test IDOR, injection, auth bypass
   - POST body — test mass assignment, injection

3. [15] ###############
   target.com/graphql
   [graphql] [post] [json]
   - GraphQL — test introspection, batch, IDOR
```

## Automated XSS/SSRF Testing (Enigma-style)

Dedicated automated testing for XSS and SSRF that goes beyond passive detection — active mutation-based payload generation with real browser confirmation.

### XSS Testing Pipeline

1. **Context analysis** — determine where user input lands (HTML body, attribute, JS string, URL, CSS)
2. **Payload mutation** — generate context-aware payloads using mutation rules:
   - HTML context → `<img onerror=...>`, `<svg onload=...>`, event handlers
   - Attribute context → quote break + event handler, `javascript:` protocol
   - JS context → string break + expression, template literal injection
   - Each payload gets 5+ encoding variants (raw, HTML entity, URL encode, double encode, unicode)
3. **Browser confirmation** — load the reflected/stored page in headless Chromium, detect JS execution via dialog/console/network events
4. **Evidence capture** — screenshot + full request/response pair for report

### SSRF Testing Pipeline

1. **Identify parameters** — URL, webhook, callback, image, proxy, redirect parameters
2. **OOB canary tokens** — generate unique callback URLs (Burp Collaborator, interactsh, or custom OOB server)
3. **Payload ladder:**
   - Direct: `http://OOB_SERVER/canary_id`
   - Cloud metadata: `http://169.254.169.254/latest/meta-data/`
   - DNS rebinding: custom domain that resolves to internal IP after TTL
   - Protocol smuggling: `gopher://`, `dict://`, `file:///etc/passwd`
   - Redirect chain: external URL that 302s to internal target
4. **Blind detection** — poll OOB server for canary callbacks, correlate with request timing

### Integration pattern

When passive detection finds an SSRF parameter or a reflected input:
1. Auto-dispatch to the XSS/SSRF test pipeline
2. Pipeline runs asynchronously (30-120 seconds per test)
3. Results flow back as findings if confirmed
4. Failed tests log for manual review

### OOB callback watcher

A persistent service watching for out-of-band callbacks:
- DNS callbacks (unique subdomain per test)
- HTTP callbacks (unique path per test)
- Correlate callback timing with request dispatch to identify which parameter triggered it
- Critical for blind SSRF, blind XSS, blind XXE detection

## Real Hunt Session Walkthrough

The complete flow from first browse to confirmed finding.

### Step 1: Start Caido + Browse

Launch Caido with 50+ permanent passive workflows enabled. Open target in Playwright through proxy. Click through every feature — login, profile, search, settings, admin (if accessible), file upload, payment flow, API endpoints.

### Step 2: Detection

As you browse, permanent workflows fire on every response:
- "DOM Sink Collector" detects `dangerouslySetInnerHTML` in a React component response
- "CORS Reality Check" detects `Access-Control-Allow-Origin: *` on an API endpoint
- "SSRF Parameter" detects `callback_url` parameter in a webhook setup form
- "Sensitive Data" detects what looks like an API key in a JS bundle

All four create findings in Caido.

### Step 3: Pre-filter

Event bridge receives the findings. Pre-filter kicks in:
- API key in JS bundle → check if it's a well-known public key format (Firebase, Maps). If public, suppress. If secret format (AWS, Stripe), keep.
- CORS with `*` → no credentials, lower priority. Log but don't escalate yet.
- DOM sink → React app, expected. But worth retesting if user input reaches it.
- SSRF parameter → high value, keep.

### Step 4: Heuristic Retest

Workflow adapter creates ephemeral `[MM]` workflows:
- `[MM] React DOM Sink Retest` — scoped to this host, watching for `dangerouslySetInnerHTML` combined with reflected query parameters in the same response
- `[MM] Webhook SSRF Retest` — watching for the server making outbound requests when `callback_url` is set to an OOB canary

### Step 5: Confirmation

As you continue browsing:
- The `[MM] React DOM Sink Retest` fires — user input from search query appears in the same response as the DOM sink. Confirmed signal.
- The `[MM] Webhook SSRF Retest` — OOB canary receives a callback. Confirmed blind SSRF.

### Step 6: Escalation

Confirmed findings escalate:
- DOM sink with user input → dispatched to taint trace analysis. If source→sink path confirmed, dispatched to `strix-xss` with 5-rotor mutation testing.
- Blind SSRF → dispatched to `strix-ssrf`. Agent tries cloud metadata, internal port scan, protocol smuggling.

### Step 7: Investigation + Confirmation

- XSS investigation: taint trace confirms `location.search` → `dangerouslySetInnerHTML`. Mutation engine finds working payload. Browser confirms execution. Finding created with full evidence.
- SSRF investigation: cloud metadata returns 200 with IAM role name. Agent escalates to credential extraction. `sts:GetCallerIdentity` confirms valid creds.

### Step 8: Output + Cleanup

- Confirmed findings created in Caido with evidence (request/response pairs, screenshots)
- Findings written to knowledge vault with chain tags
- Mobile notification sent
- `[MM]` ephemeral workflows deleted
- Permanent workflows remain for next target
- cursor-mem updated with findings, tech stack, and chain candidates

## Putting It All Together

### During a hunt session

1. **Start Caido** with passive workflows enabled
2. **Browse the target** through Caido proxy (Playwright or manual)
3. **Passive workflows fire** — broad detections on every response
4. **Event bridge triages** — filters noise, batches AI triage, routes to specialists
5. **You investigate** — use edit-and-replay for surgical testing, strix-* skills for methodology
6. **Findings flow back** — confirmed vulns become Caido findings + vault entries
7. **Feedback refines detection** — mark TP/FP, tighten workflows, add new patterns
8. **Cross-session correlation** — check vault for chain partners, prior findings, known FPs

### Without Caido MCP (manual mode)

Even without the MCP server, apply the same mental model:
- Use Caido's built-in passive workflows for broad detection
- Manually review findings with the same triage mindset (pre-filter → dedup → severity)
- Use HTTPQL to query traffic for patterns you'd otherwise automate
- Store findings in cursor-mem for cross-session state
- Apply the same escalation logic: detection → taint trace/confirm → exploit

## Source

Architecture patterns from [trace37 labs: Caido × Mastermind AI](https://labs.trace37.com/blog/caido-ai-hunting-platform/), adapted for Cursor-based workflow with strix-* skills and cursor-mem.
