---
name: js-analysis
category: reconnaissance
description: First-pass JavaScript bundle triage — endpoint extraction, modern secret patterns, framework data stores, WASM discovery, dependency CVE mining, and client-side logic analysis. Pairs with js_deobfuscation (AST + source maps) and js_runtime_audit (DevTools / dynamic) for deep dives.
depends_on: []
---

# JavaScript Analysis

JavaScript bundles are a goldmine: API endpoints the UI never exposes, hardcoded credentials, internal route definitions, framework-injected SSR data, WASM modules with auth logic, and client-side validation that reveals server-side expectations.

This skill is the **breadth baseline**. For depth, see:
- `js_deobfuscation.md` — reconstruct original source from minified bundles (webcrack, source maps, AST)
- `js_runtime_audit.md` — dynamic / runtime analysis (DevTools, fetch monkey-patching, service workers)

## When to Use

- Target is any modern single-page app (React, Vue, Angular, Svelte, Next.js, Nuxt, Remix)
- Need to discover API endpoints not reachable from the UI
- Looking for hardcoded secrets, API keys, SDK configs, or JWTs in the bundle
- Mapping client-side routing to find hidden admin / debug pages
- Understanding client-side validation to craft server-side bypasses
- Dependency CVE hunting via shipped library versions

## Methodology

### Phase 1: Collect All JavaScript + Related Assets

```bash
# Crawl with katana — gets dynamic JS too
katana -u https://target.com -jc -d 3 -ef css,png,jpg,svg,woff2,ico \
  -silent | grep -E "\.(js|mjs|jsx|wasm|map)$" | sort -u > js_assets.txt

# Also pull from Wayback (historical JS often has secrets removed from current)
echo target.com | waybackurls | grep -E "\.js$" | sort -u >> js_assets.txt

# Download in parallel
mkdir -p js_dump && cd js_dump
cat ../js_assets.txt | xargs -P 10 -I {} sh -c \
  'curl -sL "{}" -o "$(echo "{}" | md5sum | cut -c1-12).js"'

# Also capture inline scripts from HTML
curl -s https://target.com | \
  python3 -c "import sys,re; [print(m) for m in re.findall(r'<script(?![^>]*src)[^>]*>(.*?)</script>', sys.stdin.read(), re.DOTALL)]" \
  > inline_scripts.js
```

Cap at ~50 MB total; anything larger probably contains embedded fonts/images.

### Phase 2: Extract Framework SSR Data Stores (Huge Leak Surface)

Server-side-rendered SPAs inline data into the HTML — often with auth tokens,
user profiles, and feature flags baked in.

```bash
# Next.js — __NEXT_DATA__ is the biggest SSR blob
curl -s https://target.com | python3 -c "
import sys, re, json
m = re.search(r'<script id=\"__NEXT_DATA__\" type=\"application/json\">(.*?)</script>', sys.stdin.read())
if m: print(json.dumps(json.loads(m.group(1)), indent=2))" > next_data.json

# Nuxt.js — window.__NUXT__
curl -s https://target.com | grep -oP 'window\.__NUXT__\s*=\s*\{.*?\}(?=;)' > nuxt_data.js

# SvelteKit — __sveltekit_<hash>
curl -s https://target.com | grep -oP '__sveltekit_[a-z0-9]+'

# Remix — window.__remixContext / window.__remixManifest
curl -s https://target.com | grep -oP 'window\.__remix(Context|Manifest|RouteModules)\s*=.*'

# React Query hydration
curl -s https://target.com | grep -oP '"dehydratedState":\s*\{.*?\}(?=,")'

# Redux preloaded state
curl -s https://target.com | grep -oP 'window\.__PRELOADED_STATE__\s*=.*?(?=;</)'

# Generic — any <script> tag with large JSON payload
curl -s https://target.com | \
  python3 -c "import sys,re,json; [print(json.dumps(json.loads(m), indent=2)[:2000]) for m in re.findall(r'<script[^>]*type=\"application/json\"[^>]*>(.*?)</script>', sys.stdin.read(), re.DOTALL)]"
```

### Phase 3: Extract API Endpoints

```bash
# Absolute + path-style URL patterns
cd js_dump
grep -rhoE '"(https?://|/)([a-zA-Z0-9_\-./]+)"' *.js | sort -u > endpoints_raw.txt

# API-flavored paths specifically
grep -rhoP '"(/api/|/v[0-9]+/|/graphql|/rest/|/internal/|/admin/|/service/)[^"\s]+"' *.js | \
  sort -u > endpoints_api.txt

# WebSocket + SSE
grep -rhoE '"(ws{1,2}://|wss?://)[^"]+"' *.js | sort -u > endpoints_ws.txt

# Route definitions per framework
grep -rhoP 'path:\s*"[^"]+"' *.js | sort -u         # React Router / Vue Router
grep -rhoP 'routes?:\s*\[[^\]]*path[^\]]*\]' *.js    # Angular route arrays
grep -rhoP '<Route\s+path="[^"]+"' *.js              # JSX React Router

# Fetch / axios / XHR call targets
grep -rhoP '(fetch|axios\.(get|post|put|patch|delete)|\.open\()\s*\(\s*["`][^"`]+' *.js | \
  sort -u > call_sites.txt
```

Automate via **LinkFinder** and **SecretFinder** for cleaner output:

```bash
# LinkFinder — endpoint extraction
pipx install linkfinder 2>/dev/null
python3 linkfinder.py -i https://target.com -o cli

# Or point at a local bundle
python3 linkfinder.py -i js_dump/main.js -o cli
```

### Phase 4: Modern Secret Patterns

Grep the bundle for **specific** known-prefix secret patterns — catches things
generic `api_key` patterns miss.

```bash
cd js_dump

# --- Cloud providers ---
grep -rhoE 'AKIA[0-9A-Z]{16}' *.js              # AWS access key
grep -rhoE 'ASIA[0-9A-Z]{16}' *.js              # AWS temp access key
grep -rhoE 'AIza[0-9A-Za-z_-]{35}' *.js         # Google API key
grep -rhoE 'ya29\.[0-9A-Za-z_-]+' *.js          # Google OAuth token

# --- Payments ---
grep -rhoE 'sk_live_[0-9a-zA-Z]{24,}' *.js      # Stripe secret live
grep -rhoE 'sk_test_[0-9a-zA-Z]{24,}' *.js      # Stripe secret test
grep -rhoE 'pk_live_[0-9a-zA-Z]{24,}' *.js      # Stripe publishable live
grep -rhoE 'rk_live_[0-9a-zA-Z]{24,}' *.js      # Stripe restricted
grep -rhoE 'whsec_[0-9a-zA-Z]{32,}' *.js        # Stripe webhook secret

# --- Comms / Collab ---
grep -rhoE 'xox[baprs]-[0-9]+-[0-9]+-[0-9a-zA-Z]+' *.js  # Slack token
grep -rhoE 'SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}' *.js  # SendGrid
grep -rhoE 'key-[0-9a-zA-Z]{32}' *.js           # Mailgun

# --- Git hosts ---
grep -rhoE 'gh[pousr]_[0-9A-Za-z]{36,}' *.js    # GitHub PAT / OAuth
grep -rhoE 'glpat-[0-9A-Za-z_-]{20}' *.js       # GitLab PAT

# --- SaaS telemetry / feature flags ---
grep -rhoE '"sentryDSN":\s*"[^"]+"' *.js        # Sentry DSN
grep -rhoE 'https://[0-9a-f]{32}@sentry\.io' *.js
grep -rhoE '"writeKey":\s*"[a-zA-Z0-9]{24,}"' *.js  # Segment write key
grep -rhoE 'phc_[a-zA-Z0-9]{43}' *.js           # PostHog
grep -rhoE 'sdk-[0-9a-f-]+' *.js                # LaunchDarkly client-side

# --- Firebase / Supabase ---
grep -rhoP 'apiKey:\s*"AIza[^"]+"' *.js         # Firebase API key (often in config block)
grep -rhoE 'projectId:\s*"[a-z0-9-]+"' *.js     # Firebase project
grep -rhoE 'https://[a-z0-9-]+\.supabase\.co' *.js  # Supabase URL
grep -rhoE '"SUPABASE_ANON_KEY":\s*"eyJ[^"]+"' *.js # Supabase anon JWT

# --- JWT tokens (3 base64 chunks dot-separated) ---
grep -rhoE 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' *.js | \
  sort -u > jwts.txt
# Decode headers quickly
while read -r j; do echo "$j" | cut -d. -f1 | base64 -d 2>/dev/null; echo "---"; done < jwts.txt | head -40

# --- Private keys embedded ---
grep -rhoE 'BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY' *.js
```

**Entropy-based discovery** (catches long random strings regardless of prefix):

```bash
# Use trufflehog or gitleaks on the directory
trufflehog filesystem --directory=js_dump --only-verified
gitleaks detect --source=js_dump --report-path=leaks.json --no-git
```

### Phase 5: Dependency / CVE Mining

Bundled libs often leak their versions — instant CVE hits.

```bash
# retire.js — signatures for JS libs with known vulns
retire --path=js_dump --outputformat=json --outputpath=retire.json
jq -r '.[] | select(.vulnerabilities) | "\(.file) — \(.component) \(.version) — \(.vulnerabilities[].identifiers.CVE // "CVE-?")"' retire.json

# Detect bundled package versions (webpack leaks these often)
grep -rhoP '"(react|vue|angular|lodash|jquery|axios)":\s*"[0-9.]+' *.js | sort -u

# Package.json leaked?
curl -s https://target.com/package.json 2>/dev/null | jq .
curl -s https://target.com/node_modules/package.json 2>/dev/null | jq .

# Internal NPM package names (dependency confusion targets)
grep -rhoP '"@[a-z0-9-]+/[a-z0-9-]+"' *.js | sort -u
grep -rhoP '"@(target|targetcorp|internal|private)-?[a-z0-9-]*/' *.js | sort -u
```

### Phase 6: Client-Side Logic & Auth Flow

```bash
# Role / permission checks (reveals privilege levels)
grep -rhoP '(isAdmin|is_admin|hasRole|hasPermission|role\s*===?|role:\s*")[^{;]+' *.js | \
  sort -u

# Feature flags (what features exist, possibly bypassable)
grep -rhoP '(enable|disable|show|allow)[A-Z][a-zA-Z]+\s*[:=]' *.js | sort -u

# Client-side validation (regex patterns = server-side expectations)
grep -rhoP 'new RegExp\([^)]+\)' *.js | sort -u
grep -rhoP '/\\[^/]+/[gimsuy]*\.test\(' *.js | sort -u

# Auth token storage (localStorage/sessionStorage/cookies)
grep -rhoP '(localStorage|sessionStorage)\.(setItem|getItem)\s*\(\s*["`][^"`]+["`]' *.js | \
  sort -u

# OAuth flows — redirect URIs often reveal the auth server
grep -rhoP '(redirect_uri|client_id|response_type|scope)\s*[:=]\s*["`][^"`]+["`]' *.js | \
  sort -u
```

### Phase 7: WebAssembly (WASM) Modules

Modern apps often push crypto, license checks, or even auth logic into WASM.

```bash
# Find WASM
grep -rhoE 'https?://[^"]+\.wasm' js_dump/*.js | sort -u
find . -name "*.wasm" -type f

# Inspect — wabt toolkit provides disassembly
pipx install wabt 2>/dev/null  # or: apt install wabt
wasm2wat input.wasm -o input.wat                 # disassemble
wasm-objdump -x input.wasm                        # headers + imports
wasm-decompile input.wasm -o input.dcmp           # higher-level pseudo-source

# Extract imported JS functions (reveals the JS/WASM contract)
wasm-objdump -x input.wasm | grep -E 'import|export'

# Look for embedded strings (endpoints, error messages, crypto constants)
strings input.wasm | grep -E '(https?://|/api/|error|key|secret)' | sort -u
```

For deeper WASM RE (AI-decompilation, pseudocode): see `js_deobfuscation.md`.

### Phase 8: Source Maps & Deobfuscation — Handoff

If the bundle is heavily minified and any of the above yields little signal,
escalate to `js_deobfuscation.md`:

```bash
# Quick source-map availability check (trigger the escalation)
while read url; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "${url}.map")
  [ "$code" = "200" ] && echo "[MAP] $url.map"
done < js_assets.txt
```

If any `.map` files are accessible → go to **js_deobfuscation.md Phase 1**.

## Tool Matrix

| Need | Tool | One-liner |
|------|------|-----------|
| URL / endpoint extraction | LinkFinder | `python3 linkfinder.py -i URL -o cli` |
| Secret scanning (pattern) | SecretFinder | `python3 SecretFinder.py -i URL -o cli` |
| Secret scanning (entropy + rules) | trufflehog | `trufflehog filesystem --directory=js_dump --only-verified` |
| Secret scanning (rules) | gitleaks | `gitleaks detect --source=js_dump --no-git` |
| Dependency CVEs | retire.js | `retire --path=js_dump --outputformat=json` |
| AST queries | semgrep | `semgrep --config auto js_dump/` |
| AST pattern match | ast-grep | `ast-grep --pattern 'fetch($URL)' --lang js` |
| WASM disassembly | wabt | `wasm2wat in.wasm -o in.wat` |
| Bundle deobfuscation | webcrack | `webcrack input.js -o unpacked/` (see js_deobfuscation) |

## What to Look For — Priority Order

1. **Source maps accessible** → entire original codebase (go to js_deobfuscation)
2. **Framework SSR data** (`__NEXT_DATA__` etc.) → user/auth state, env vars
3. **Hardcoded secrets with known prefixes** → immediate exploitability check
4. **Internal API endpoints** not in public UI → access-control testing
5. **Admin / debug routes** in router definitions → bypass / enumeration
6. **GraphQL endpoint + persisted queries** → schema reconstruction
7. **Bundled library CVEs** → direct vuln hits
8. **WebSocket / SSE endpoints** → auth / subscription abuse
9. **Client-side validation regex** → crafting server-side bypasses
10. **Internal NPM package names** → dependency confusion targets

## Tips

1. **Cache locally** — download bundles once, run every tool against the same files. Saves bandwidth and lets you diff across scans.
2. **Check historical JS too** — old Wayback snapshots often have credentials the dev rotated later.
3. **Every `.js.map` is a goldmine** — escalate to `js_deobfuscation.md` the moment you find one.
4. **Dynamic chunks > main bundle** — admin features are usually in lazy-loaded chunks named `admin.<hash>.js`, `debug.<hash>.js`. Trigger them by navigating to reveal.
5. **Monitor for changes** — re-run on a schedule; fresh deploys leak fresh secrets.
6. **Don't stop at grep** — if a bundle looks heavy but grep is quiet, it's obfuscated. Pivot to `js_deobfuscation.md`.
7. **For auth logic buried in WASM or obfuscation** — pivot to `js_runtime_audit.md` to hook runtime behavior instead of reading dead code.

## Tooling — SPA API surface capture

For SPAs (React/Vue/Vite/Angular), bugdotexe ships
`capture_spa_api_surface` — a browser harness that records every
`fetch()` / `XMLHttpRequest` / `WebSocket` URL the SPA actually hits
during an authenticated session. Two-step workflow:

1. Call `capture_spa_api_surface()` with no arguments → returns the
   JS harness to paste into the target's DevTools console BEFORE
   logging in.
2. Navigate the authenticated flows (login, each role's dashboard,
   admin pages, role-specific actions). When done, run
   `copy(JSON.stringify(window.__bdxCaptured))` in the console and
   call `capture_spa_api_surface(captured_dump=<json>,
   target_host=<host>, role=<operator_label>,
   register_in_matrix=True)` — the endpoints auto-register in the
   access matrix with the role you passed.

This is the ONLY reliable way to discover:
- Lazy-loaded admin chunks that static bundle grep misses
- WebSocket URLs (often carry auth tokens in the query — see
  websocket_security.md)
- Role-specific endpoints hidden behind client-side guards (backend
  still serves them; client just doesn't call them for lower-
  privilege users)

Use this on every SPA target before declaring the surface mapped.

## Corpus-Derived Hunting Patterns

Techniques from disclosed reports where JS analysis was the critical discovery step.

### WebView JS Bridge Exploitation

For every mobile app that exposes a WebView with a JS bridge:

1. Decompile and find `@JavascriptInterface` / `addJavascriptInterface` / `postMessage` handler / `WKScriptMessageHandler`
2. Map every method the bridge exposes — each is an attack surface callable from any page loaded in the WebView
3. If the WebView loads content from a domain where you can achieve XSS, every bridge method becomes callable from your XSS context
4. Check if bridge methods perform privileged operations (file read, token access, contact list, GPS) without verifying the calling origin

### postMessage Handler Audit

For every web target, search JS bundles for `addEventListener("message"` and `onmessage =`:

1. For each handler, check if it validates `event.origin` — many handlers accept messages from any origin
2. If the handler writes to DOM (`innerHTML`, `document.write`), reads/sets cookies, or calls `fetch()` with data from the message, it is exploitable cross-origin
3. Test by embedding the target page in an iframe on an attacker-controlled domain and sending a crafted `postMessage`

### XSSI via Cookie-Dependent JS Responses

For every `application/javascript` or `text/javascript` endpoint:

1. Request it twice — once with session cookies, once without
2. If the response differs (contains user-specific data when authenticated), it is a cross-site script inclusion (XSSI) target
3. An attacker page can include the script via `<script src="...">` and read the user's data via global variable or function hooking

### Dependency Confusion via Internal Package Names

Extract all internal npm package names from bundles:

1. Grep for `"@target-corp/`, `"@internal/`, `"@private-` patterns in `package.json` or webpack module maps
2. Check if each package name exists on the public npm registry
3. If not registered publicly, register it with a higher version number — the target's build pipeline may pull from the public registry instead of the private one

### OAuth/Redirect URL Parameter XSS

For every parameter named `return_url`, `next`, `redirect`, `continue`, `dest`, `callback`:

1. Test `javascript:alert(1)` — many URL validators check for `http://` but not `javascript:`
2. Test `javascript://target.com/%0aalert(1)` — the `://` fools validators expecting a protocol, the `%0a` breaks out of the comment
3. Test `data:text/html,<script>alert(1)</script>` for `src` and `iframe` injection points
