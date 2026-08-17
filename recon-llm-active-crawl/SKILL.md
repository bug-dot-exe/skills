---
name: recon-llm-active-crawl
category: reconnaissance
description: LLM-driven active web crawl. Replaces katana / gospider / hakrawler subprocess pipelines with a single-context BFS that fetches pages, parses links, follows JS calls, manages per-role sessions, and correlates findings across the crawl. Composable with content discovery, deep JS analysis, archive intel, information disclosure.
depends_on: []
---

# LLM-Driven Active Crawl

A traditional headless crawler (katana / gospider / hakrawler) is a black box
that returns a flat URL list. It cannot tell you that the bundle at `/static/main.js`
exposes an API at `/internal/v3/users` that the home page never links to, or
that the `/admin/login` page silently redirects when an unauthenticated session
hits it but returns a real form when a low-priv session does.

This skill runs the crawl **inside the agent context**. Every fetch, every
parsed link, every JS-extracted endpoint stays in the same memory. The agent
can decide path-by-path which routes to follow first, when to drop a useless
branch, and when to chain into deeper analysis (JS bundles, source maps,
archive snapshots) without serializing intermediate state to disk.

## When to Use

- Target is any HTTP(S) host: SPA, MPA, microservice gateway, internal admin panel.
- You need a complete, role-aware URL list - not just what an unauth crawler
  could reach.
- The target ships a JS bundle (almost everything modern does) and the
  user-clickable surface is a fraction of the real API surface.
- Existing wordlist fuzzing returned thin results - the real endpoints are
  buried in `fetch()` / `axios` calls, route definitions, lazy-loaded chunks,
  service workers, or `<form action>` attributes.
- You need per-role differential crawls (the unauth view differs from
  user view differs from admin view) and want a single artifact correlating
  all three.

## Why LLM-Driven Beats Subprocess Crawlers

| Property | katana / gospider | LLM-driven |
|---|---|---|
| Path prioritization | Depth-first or breadth-first by URL | Semantic - skip pagination loops, follow auth-gated routes |
| SPA route extraction | Headless-Chrome-only, brittle on heavy JS | Parses `Route` / `createBrowserRouter` / `routes:` definitions directly |
| Role-aware crawl | One pass per cookie jar, results disjoint | Per-role results live in same context, diff by hand |
| JS bundle correlation | Discards bundle bodies after URL extraction | Bundle becomes an artifact for `recon_deep_js_analysis` chain |
| Source map awareness | None | Detects `sourceMappingURL` and triggers recovery |
| Bot-detection adaptivity | Static UA, fixed pacing | Switches UA, slows down, follows redirect-to-login on detection |
| Service worker registration | Ignored | Parsed for `caches.match` and `fetch` listeners |
| Failure modes | Silent (empty file), hard exit on errors | Recovered via fallback (curl -> python requests -> playwright) |

## Methodology

The crawl is BFS with smart pruning. The agent maintains a frontier of
unvisited URLs, a visited set, and per-role cookie jars. Each iteration pops
a URL, fetches it (with the active role's session), parses every reference
out of the response, and pushes new URLs onto the frontier. Termination is
by frontier exhaustion, not by depth limit or time budget.

### Stage 1: Seed the Frontier

Fetch the canonical entry points. These are the same starting points a
human would type in:

```bash
# Root + canonical paths every web app exposes
SEEDS="/ /index.html /robots.txt /sitemap.xml /sitemap_index.xml
/security.txt /.well-known/security.txt
/.well-known/openid-configuration /.well-known/oauth-authorization-server
/.well-known/assetlinks.json /.well-known/apple-app-site-association
/api /api/v1 /api/v2 /api/v3 /api/swagger.json /api/openapi.json
/docs /swagger /swagger-ui.html /openapi.json
/admin /admin/login /login /signin /auth /sso
/graphql /graphiql /altair /playground
/health /healthz /status /metrics /actuator /actuator/env
/server-status /server-info /debug /trace /info
/package.json /composer.json /Gemfile /requirements.txt"

for path in $SEEDS; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 "$TARGET$path")
  [ "$STATUS" != "000" ] && [ "$STATUS" != "404" ] && \
    echo "[seed] $TARGET$path -> $STATUS"
done

# Mine robots.txt and sitemap.xml - Disallow is high-value (admin hides
# URLs they want unindexed; those URLs exist)
curl -sk "$TARGET/robots.txt" 2>/dev/null | \
  grep -iE "^(allow|disallow|sitemap):" | awk '{print $2}' | sort -u
curl -sk "$TARGET/sitemap.xml" 2>/dev/null | \
  grep -oE '<loc>[^<]+</loc>' | sed 's/<loc>//;s/<\/loc>//'
```

### Stage 2: HTML Reference Extraction

For every HTML response, parse out every URL-bearing attribute. Crawlers
that look only at `<a href>` miss the bulk of the surface.

```bash
# Single-pass HTML reference dump (run on each fetched body)
python3 - <<'PY'
import sys
from html.parser import HTMLParser

# Tag -> URL-bearing attributes
URL_ATTRS = {
    "a": ["href"], "form": ["action"], "script": ["src"], "link": ["href"],
    "iframe": ["src", "srcdoc"], "frame": ["src"],
    "img": ["src", "srcset", "data-src", "data-srcset"],
    "video": ["src", "poster"], "audio": ["src"], "source": ["src", "srcset"],
    "track": ["src"], "embed": ["src"], "object": ["data"],
    "area": ["href"], "base": ["href"],
    "input": ["formaction", "src"], "button": ["formaction"],
    "blockquote": ["cite"], "q": ["cite"], "ins": ["cite"], "del": ["cite"],
}

class URLExtractor(HTMLParser):
    def __init__(self): super().__init__(); self.urls = []
    def handle_starttag(self, tag, attrs):
        wanted = URL_ATTRS.get(tag, [])
        for k, v in attrs:
            if v and (k in wanted or k.startswith("data-")):
                self.urls.append((tag, k, v))

p = URLExtractor(); p.feed(sys.stdin.read())
for tag, attr, url in p.urls:
    print(f"{tag}\t{attr}\t{url}")
PY
```

Also scan `data-*` attributes - frontends stash endpoint URLs there for
AJAX hooks (`data-url`, `data-href`, `data-action`, `data-endpoint`,
`data-fetch`, `data-post-to`, `data-target-url`).

### Stage 3: Inline JS Reference Extraction

`<script>` blocks (inline and external) contain the runtime API surface.
Extract every fetch-shaped call regardless of framework:

```bash
# Inline + external JS - extract every URL literal that looks like an API call
python3 - <<'PY'
import sys, re
body = sys.stdin.read()
patterns = [
    (r'fetch\s*\(\s*[`"\']([^`"\'\)]+)[`"\']', "fetch"),
    (r'axios\.(get|post|put|patch|delete|head|options)\s*\(\s*[`"\']([^`"\']+)', "axios.method"),
    (r'axios\s*\(\s*\{\s*(?:url|method)[^}]*?[`"\']([^`"\']+)', "axios.config"),
    (r'baseURL\s*[:=]\s*[`"\']([^`"\']+)', "baseURL"),
    (r'\$\.(ajax|get|post|getJSON|getScript|load)\s*\(\s*[`"\']?([^`"\',\s]+)', "jquery"),
    (r'\.ajax\s*\(\s*\{\s*url\s*:\s*[`"\']([^`"\']+)', "jquery.config"),
    (r'XMLHttpRequest[^;]*?\.open\s*\(\s*[`"\'](?:[A-Z]+)[`"\'],\s*[`"\']([^`"\']+)', "xhr"),
    (r'new\s+Request\s*\(\s*[`"\']([^`"\']+)', "Request"),
    (r'new\s+WebSocket\s*\(\s*[`"\']([^`"\']+)', "websocket"),
    (r'new\s+EventSource\s*\(\s*[`"\']([^`"\']+)', "eventsource"),
    (r'serviceWorker\.register\s*\(\s*[`"\']([^`"\']+)', "service-worker"),
    (r'(?:gql|graphql)\s*[`"\']\s*(query|mutation|subscription)\s+(\w+)', "graphql"),
    (r'[`"\']\s*(https?://[^\s`"\'<>]+)\s*[`"\']', "abs-url"),
    (r'[`"\']\s*(/(?:api|v[0-9]+|admin|internal|graphql|rest|service|auth|sso)[^\s`"\'<>]*)\s*[`"\']', "rel-api-path"),
]
for pat, label in patterns:
    for m in re.finditer(pat, body):
        groups = [g for g in m.groups() if g]
        if groups: print(f"{label}\t{groups[-1]}")
PY
```

Capture both the URL value and the call site context - a `fetch("/api/users")`
inside a function called `loadAdminPanel` is more interesting than the
same URL inside `loadFooter`. Keep ~80 chars of surrounding source for
every match so later analysis can re-read it.

### Stage 4: SPA Framework Route Extraction

Modern SPAs declare their routes in a manifest the bundle never executes
on first page load. Extract them statically:

```bash
# React Router (5.x and 6.x), Vue, Angular, Svelte, Next, Solid, Tanstack
grep -rhoE '<Route[[:space:]]+path=["`][^"`]+' bundles/
grep -rhoE 'path:\s*["`][^"`]+' bundles/
grep -rhoP 'createBrowserRouter\s*\(\s*\[' bundles/
grep -rhoE 'routes:\s*\[' bundles/
grep -rhoE 'addRoute\s*\(\s*\{\s*path\s*:\s*["`][^"`]+' bundles/
grep -rhoP 'RouterModule\.(forRoot|forChild)\s*\(' bundles/
grep -rhoE 'loadChildren:\s*[`"\']([^`"\']+)' bundles/
grep -rhoE 'goto\s*\(\s*[`"\']([^`"\']+)' bundles/
grep -rhoE 'router\.push\s*\(\s*[`"\']([^`"\']+)' bundles/
grep -rhoE 'createRoute\s*\(\s*\{\s*path\s*:\s*[`"\']([^`"\']+)' bundles/
find bundles/ -name "+page.*" -o -name "+layout.*" -o -name "+server.*"

# Backend frameworks if accidentally served as static (Express/Hono/Fastify/Koa)
grep -rhoP '(app|router)\.(get|post|put|patch|delete|use)\s*\(\s*[`"\']([^`"\']+)' bundles/
grep -rhoP '\.route\s*\(\s*\{\s*method[^}]*?path[^}]*?[`"\']([^`"\']+)' bundles/
```

Each extracted route goes onto the frontier. Many SPA routes only render
client-side - the server returns the same `index.html` for any path - but
the route may correspond to an underlying API call.

### Stage 5: Build Artifact Mining

Modern bundlers leave breadcrumbs. Mine them:

```bash
# webpackJsonp / chunk maps - reveal lazy-loaded chunk filenames
grep -rhoE 'webpackJsonp[^=]*=\s*[^;]+' bundles/ | head
grep -rhoE '__webpack_require__\.e\s*\(\s*["`0-9]+' bundles/ | sort -u

# Vite chunk manifest
curl -sk "$TARGET/assets/manifest.json" 2>/dev/null | jq .
curl -sk "$TARGET/manifest.json" 2>/dev/null | jq .

# Lazy import paths
grep -rhoP 'import\s*\(\s*[`"\']([^`"\']+)[`"\']' bundles/ | \
  sed -E 's/.*import\(\s*["`]([^"`]+).*/\1/' | sort -u

# Public env vars baked into client bundles (frequent leak vector)
grep -rhoP '(NEXT_PUBLIC_|REACT_APP_|VITE_|VUE_APP_|GATSBY_|PUBLIC_|NUXT_PUBLIC_|EXPO_PUBLIC_)[A-Z0-9_]+' bundles/ | \
  sort -u

# Source map URLs - critical artifact, triggers deep analysis
grep -rhoE '//#\s*sourceMappingURL=[^\s]+' bundles/ | sort -u
```

Discovered chunks are added to the JS bundle list for `recon_deep_js_analysis`.
Discovered env-var names + values go into the secrets store.

### Stage 6: CSS, Service Worker, GraphQL Reference Extraction

These are the references most crawlers ignore:

```bash
# CSS imports - sometimes leak API URLs in url() / @import blocks
grep -rhoE 'url\s*\(\s*[`"\']?([^)`"\']+)' static_css/ | sort -u
grep -rhoE '@import\s+(?:url\s*\(\s*)?[`"\']?([^)`"\']+)' static_css/ | sort -u

# Service worker - paths cached/intercepted are paths in use
for sw in $(grep -rhoE 'serviceWorker\.register\s*\(\s*[`"\']([^`"\']+)' bundles/ | \
            sed -E 's/.*["`]([^"`]+).*/\1/' | sort -u); do
  curl -sk "$TARGET$sw" -o /tmp/sw.js
  grep -oE 'caches?\.(match|open|add|addAll|put)\s*\([^)]+' /tmp/sw.js
  grep -oE 'self\.addEventListener\s*\(\s*[`"\']fetch[`"\']' /tmp/sw.js
done

# GraphQL - inline query/mutation strings reveal schema; introspection if open
grep -rhoP '(?:gql|graphql|`)\s*\b(query|mutation|subscription)\s+(\w+)' bundles/
grep -rhoP 'operationName\s*[:=]\s*[`"\'](\w+)' bundles/
curl -sk -X POST "$TARGET/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name}}}}"}' | head -c 2000
```

### Stage 7: Per-Role Session Crawl

Static crawlers do one pass. The LLM-driven crawl runs the same BFS
multiple times with different sessions. Hidden admin endpoints often
return a `404` or `302 -> /login` for unauthenticated requests but a real
response for authenticated ones.

Login flow extraction:

```bash
# Identify the login form action and method
LOGIN_PAGE=$(curl -sk "$TARGET/login")
LOGIN_ACTION=$(echo "$LOGIN_PAGE" | \
  grep -oE '<form[^>]+action=["`][^"`]+["`]' | \
  head -1 | sed -E 's/.*action=["`]([^"`]+).*/\1/')
LOGIN_METHOD=$(echo "$LOGIN_PAGE" | \
  grep -oE '<form[^>]+method=["`][^"`]+["`]' | \
  head -1 | sed -E 's/.*method=["`]([^"`]+).*/\1/')

# Extract any CSRF token
CSRF=$(echo "$LOGIN_PAGE" | grep -oE 'name=["`](csrf|_token|authenticity_token|__RequestVerificationToken|csrf_token)["`][^>]*value=["`][^"`]+' | \
  sed -E 's/.*value=["`]([^"`]+).*/\1/' | head -1)

# Capture session via cookie jar
curl -sk -c "/tmp/session_${ROLE}.txt" -b "/tmp/session_${ROLE}.txt" \
  -X "$LOGIN_METHOD" "$LOGIN_ACTION" \
  -d "username=$USER&password=$PASS&csrf_token=$CSRF" \
  -o /tmp/login_response.html

# Verify session with a known authenticated endpoint
curl -sk -b "/tmp/session_${ROLE}.txt" "$TARGET/account" | head -c 500
```

Maintain one cookie jar per role:

| Role | Jar | Use |
|---|---|---|
| unauth | `/tmp/jar_unauth.txt` | First-pass crawl, baseline |
| user_a | `/tmp/jar_user_a.txt` | Standard user view |
| user_b | `/tmp/jar_user_b.txt` | Cross-tenant comparison (different account) |
| admin | `/tmp/jar_admin.txt` | Privileged view |
| service | `/tmp/jar_service.txt` | API-token / machine identity if available |

Re-run the entire BFS for each role. The diff between roles is the access
matrix - endpoints that return `200` for admin and `403` for user are the
exact targets for IDOR / privilege-escalation testing.

### Stage 8: CSRF, Token Refresh, and Session Renewal

Long crawls outlive a single session. Detect and handle:

```bash
# Per-page CSRF rotation - re-extract token from latest GET, replay on POST
extract_csrf() {
  grep -oE 'name=["`](csrf|_token|authenticity_token|csrf_token)["`][^>]*value=["`][^"`]+' "$1" | \
    sed -E 's/.*value=["`]([^"`]+).*/\1/' | head -1
}

# Detect session expiration (302 -> /login, 401, or login-form re-render)
check_session() {
  echo "$1" | grep -qE '(<form[^>]+(login|signin|auth)|"error":\s*"(unauthorized|expired)"|HTTP/1\.[01] 401)' \
    && return 1 || return 0
}

# JWT refresh: many SPAs hit /auth/refresh on 401 - capture and replay
```

When the session dies mid-crawl, re-auth and resume. Don't restart from
scratch - the visited set persists across re-auths.

### Stage 9: Bot-Detection / Rate-Limit Evasion

Defensive infrastructure pushes back. The crawl adapts rather than aborts:

```bash
# Rotate UAs (common ones matching real browsers - Chrome/Firefox/Safari/mobile)
UAS=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/17.2 Safari/605.1.15"
  "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Firefox/122.0"
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Mobile/15E148 Safari/604.1"
)

# Detect rate-limit signals
detect_throttle() {
  case "$1" in 429|503) echo "throttled"; return;; esac
  echo "$2" | grep -qiE '(retry-after|x-rate-limit|x-ratelimit-remaining: 0)' && echo "throttled"
}

# Detect bot-detection challenges (Cloudflare / Akamai / DataDome / hCaptcha)
detect_challenge() {
  local body="$1"
  echo "$body" | grep -qiE '(cf-chl-bypass|jschl-vc|akamai-bot-manager|datadome|hcaptcha|recaptcha|"challenge_required")'
}
```

When throttled: back off (sleep with jitter), reduce concurrency, switch
UA, re-fetch. When challenged: fall back to playwright (real browser
solves more challenges), re-establish session, continue. Never abort the
crawl on a single throttle hit.

### Stage 10: SPA-Aware Fallback to Playwright

When `curl` returns an empty `<div id="root"></div>` shell, the page
renders client-side. Render it instead:

```bash
# Use playwright (sandbox-installed) to render the page after JS executes
python3 - <<'PY'
import sys
from playwright.sync_api import sync_playwright

url = sys.argv[1]
jar = sys.argv[2] if len(sys.argv) > 2 else None
with sync_playwright() as p:
    b = p.chromium.launch(headless=True,
        args=["--disable-blink-features=AutomationControlled"])
    ctx = b.new_context(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121",
        viewport={"width": 1920, "height": 1080})
    if jar:
        for line in open(jar):
            if line.startswith("#") or not line.strip(): continue
            x = line.split("\t")
            if len(x) >= 7:
                ctx.add_cookies([{"name": x[5], "value": x[6],
                                  "domain": x[0], "path": x[2]}])
    page = ctx.new_page()
    seen = []
    page.on("request", lambda r: seen.append(r.url))
    page.goto(url, wait_until="networkidle", timeout=30000)
    print("=== HTML ==="); print(page.content())
    print("=== NETWORK ==="); [print(r) for r in sorted(set(seen))]
    b.close()
PY
```

Every URL the SPA fetched during render goes onto the frontier. Playwright
captures requests that static parsing can never see - dynamically computed
URLs, JIT-built query strings, fetches triggered by `setTimeout`.

### Stage 11: Response Body Disclosure Sweep

Every response body gets a final pass for inline information disclosure:

```bash
# Comments that mention internal hosts, TODOs, secrets
grep -hoE '<!--[^-]+-->' /tmp/responses/*.html | head -50
grep -hoE '/\*[^*]*\*/' /tmp/responses/*.{html,js} | head -50
grep -hoE '//\s*(TODO|FIXME|XXX|HACK|BUG|NOTE):[^\n]+' /tmp/responses/*.{html,js} | head

# Stack traces / debug pages
grep -hlE '(Traceback|java\.lang\.|System\.Exception|panic:|fatal error)' /tmp/responses/*

# Email / internal hostname leaks
grep -hoE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' /tmp/responses/* | sort -u
grep -hoE 'https?://(internal|admin|dev|staging|test|qa|preprod|api-internal|backend|legacy)[a-z0-9.-]+' /tmp/responses/* | sort -u
```

Findings here chain to `recon_information_disclosure` for triage.

## Frontier Management

The agent maintains four data structures across the crawl:

| Structure | Purpose |
|---|---|
| `frontier` | URLs to visit, ordered by priority (admin paths first, repetitive pagination last) |
| `visited` | URLs already fetched, keyed by (url, role) - same URL crawled per role |
| `discovered_endpoints` | Final output - one row per (url, method, role, status, content-type) |
| `extracted_artifacts` | JS bundles, source maps, secrets, internal hostnames - for chained skills |

Priority rules for the frontier:

1. Authentication-relevant paths first (`/login`, `/auth`, `/sso`, `/oauth`).
2. API roots next (`/api`, `/graphql`, `/rest`, paths under any of these).
3. Admin paths (`/admin`, `/internal`, `/manage`, `/console`, `/dashboard`).
4. Static asset paths last (`/assets`, `/static`, `/_next`) - only fetched
   when their content yields new endpoints (JS bundles do).
5. Pagination-ish URLs (`?page=N`, `?offset=N`, `?after=X`) get one
   sample, not the full sequence. The agent recognizes the pattern and
   prunes.

## Output Format

Every discovered URL gets one record. Aggregate into a single artifact:

```json
{
  "url": "https://target.example/api/v3/users/me",
  "method": "GET",
  "source_role": "user_a",
  "response_status": 200,
  "response_size": 1842,
  "content_type": "application/json",
  "discovered_via": "fetch-call-in-bundle:/static/main.HASH.js:L4823",
  "extracted_links": ["/api/v3/users/me/sessions"],
  "extracted_api_calls": [], "extracted_forms": [], "extracted_secrets": [],
  "auth_required": true,
  "differential": {"unauth": 401, "user_a": 200, "user_b": 200, "admin": 200}
}
```

The `differential` field is the access matrix - it directly drives IDOR
and privilege-escalation testing downstream.

## Composes With

| Skill | Direction | Glue |
|---|---|---|
| `recon_content_discovery` | Crawl seeds the wordlist - real paths > generic guesses. |
| `recon_deep_js_analysis` | Bundle URLs from Stage 5 trigger deep JS skill (sourcemap recovery, secret extraction). |
| `recon_information_disclosure` | Stage 11 findings feed disclosure triage. |
| `recon_archive_intel` | Compare current crawl URL set vs. historical archive snapshots - removed-but-still-live endpoints surface here. |
| `parameter_discovery` | Crawl-extracted endpoints become arjun's input. |
| `target_mapping` | Per-role differential matrix feeds the access-control matrix. |

## Pitfalls and Recoveries

| Pitfall | Symptom | Recovery |
|---|---|---|
| SPA renders client-side | curl gets `<div id="root"></div>` and nothing else | Fall back to playwright render (Stage 10) |
| CSRF token rotates per page | POST to discovered form returns 403 with `csrf_failure` | Re-extract token from latest GET, replay (Stage 8) |
| Session expires mid-crawl | Sudden 401 wave | Re-auth via login flow, resume from frontier (Stage 8) |
| Rate limit (429) | Streak of 429s, retry-after header | Back off with jitter, lower concurrency, rotate UA (Stage 9) |
| Bot-detection challenge | Cloudflare interstitial / hCaptcha | Switch to playwright with stealth args, re-establish session |
| Token-based auth (no cookie jar) | Auth header `Authorization: Bearer ...` instead | Capture token from login response, replay in Authorization header for every fetch |
| Redirects to login indefinitely | 302 -> /login -> 302 -> /login | Session dead - re-auth (Stage 8) before continuing |
| WebSocket auth in URL | `wss://?token=...` | Capture URL with token, treat as point-in-time artifact - token is short-lived |
| Self-referencing pagination | `?page=1&page=2&page=1...` | Detect query-param oscillation, prune (frontier priority rule 5) |
| Mixed-content HTTPS+HTTP | Some links are http://, target is https:// | Crawl both schemes - sometimes http:// has misconfigured handlers |

## Termination

The crawl ends when **no new URLs were added to the frontier in the last
three BFS depth levels**. This is not a depth cap - the BFS will keep
going to depth 20+ if every level keeps producing fresh references.
What matters is that the rate of new discoveries falls to zero across
multiple consecutive levels, indicating saturation.

For multi-role crawls, each role runs an independent BFS to saturation.
The crawl is complete when **every role's frontier is empty**. Rolemix
results then go through differential analysis (Stage 7).

For multi-protocol targets (HTTP + HTTPS coexisting), crawl both schemes
to saturation. Don't assume the HTTPS surface mirrors the HTTP surface -
HTTP often hosts forgotten admin tooling or health endpoints.

There is no time budget, no fetch budget, no breadth limit. Completeness
is the goal; speed is not. A 6-hour crawl that finds 4000 endpoints is
strictly better than a 6-minute crawl that finds 400.
