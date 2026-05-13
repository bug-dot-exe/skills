---
name: recon_deep_js_analysis
category: reconnaissance
description: Deep mining of JS bundles and source maps for hidden API endpoints, hardcoded secrets, internal hostnames, env vars, library CVEs, and recovered original source. Combines regex extraction, AST parsing, source-map recovery, and recursive multi-pass analysis. Pairs with js_analysis (breadth), js_deobfuscation (AST + webcrack), js_runtime_audit (DevTools).
depends_on: []
---

# Deep JS Analysis

JavaScript bundles ship far more than their authors intend. Every modern
SPA is a tarball of its own server-side imagination - inlined API URLs,
internal hostnames, environment variables, library versions, build
metadata, AWS keys, OAuth client secrets, JWT secrets, even full
unminified source code via dropped `.map` files. This skill mines all of
it in a single pass, recursively, until no new artifact surfaces.

The output of this skill is a single artifact bundle: every endpoint,
secret, internal hostname, library version, env var, and recovered
source file - all keyed by which bundle they came from and which
extraction method found them.

## When to Use

- The target ships any client-side JavaScript (almost any modern web
  target qualifies).
- After active crawl identifies bundles - this skill processes them.
- When source maps have been observed (the breadth `js_analysis`
  triggers a handoff here).
- When existing breadth grep returned thin results - the bundle is
  likely heavily minified or obfuscated, and AST + sourcemap are needed.
- When you need the full API surface a static `<a>` crawl can never
  reveal.

## Bundle Types and How to Detect Them

The extraction approach depends on the bundler. Detect first, then
adapt:

```bash
# Detect bundler from artifact patterns
detect_bundler() {
  local f="$1"
  # webpack
  grep -lE 'webpackJsonp|__webpack_require__|webpack/runtime' "$f" 2>/dev/null && echo "webpack"
  # Vite (esbuild output)
  grep -lE '__vitePreload|/@vite/|vite_legacy_polyfill' "$f" 2>/dev/null && echo "vite"
  # Rollup
  grep -lE 'ROLLUP_FILE_URL_|@@_HASHED' "$f" 2>/dev/null && echo "rollup"
  # esbuild
  grep -lE '__commonJS\s*\(\s*\{|__toCommonJS\s*\(' "$f" 2>/dev/null && echo "esbuild"
  # Parcel
  grep -lE 'parcelRequire' "$f" 2>/dev/null && echo "parcel"
  # Browserify
  grep -lE '\(function e\(t,n,r\)' "$f" 2>/dev/null && echo "browserify"
  # SystemJS
  grep -lE 'System\.register\s*\(' "$f" 2>/dev/null && echo "systemjs"
}
```

Each bundler exposes its module map differently - webpack via
`__webpack_modules__`, esbuild via `__commonJS({...})`, Vite via ESM
imports. Stage 5 (AST extraction) handles all of them.

## Methodology

### Stage 1: Bundle Enumeration

Get every JS / WASM / map URL on the target. Pull from active crawl,
HTML, JS-of-JS imports, build manifests:

```bash
mkdir -p bundles raw_html

# Source 1: active crawl output (already classified URLs)
jq -r '.url' crawl_output.jsonl 2>/dev/null | \
  grep -iE '\.(m?js|jsx?|tsx?|wasm|map)(\?|$)' > bundle_urls.txt

# Source 2: HTML script/link/source tags
grep -hoE '(src|href)=["`][^"`]+\.(m?js|map)["`]' raw_html/*.html | \
  sed -E 's/.*=["`]([^"`]+).*/\1/' >> bundle_urls.txt

# Source 3: build manifests (Vite / Next / webpack / Nuxt)
for m in manifest.json _next/build-manifest.json _next/app-build-manifest.json \
         assets/manifest.json _nuxt/manifest.json; do
  curl -sk "$TARGET/$m" 2>/dev/null | \
    jq -r '.. | strings? | select(test("\\.(m?js|wasm)$"))' >> bundle_urls.txt
done

# Source 4: webpack runtime chunk-filename function
grep -rhoE '__webpack_require__\.u\s*=\s*function' bundles/ 2>/dev/null
sort -u -o bundle_urls.txt bundle_urls.txt
```

### Stage 2: Bundle Download

```bash
# Download every bundle in parallel; preserve hash in filename
mkdir -p bundles
while read url; do
  hash=$(echo "$url" | md5sum | cut -c1-12)
  base=$(basename "$url" | sed 's/?.*//')
  curl -sk "$url" -o "bundles/${hash}_${base}" -H "Referer: $TARGET"
done < bundle_urls.txt

# Pretty-print every bundle for analysis
for f in bundles/*.js bundles/*.mjs; do
  [ -f "$f" ] && js-beautify -f "$f" -o "${f}.beautified" 2>/dev/null
done
```

`js-beautify` is sandbox-installed. If it's missing, fall back to
`prettier` or a Python AST round-trip. Beautified bundles are easier to
grep but the original is still useful for offset-preserving extraction.

### Stage 3: Source Map Recovery (Critical)

A `.map` file recovers the original unminified source - variable names,
comments, file structure, even TypeScript types. Always check before
running heavy regex extraction.

```bash
# Detect sourcemap URLs (inline or trailing) and fetch
for f in bundles/*.js bundles/*.mjs; do
  TRAILING=$(grep -hoE '//#\s*sourceMappingURL=[^\s]+' "$f" | tail -1 | \
             sed -E 's|.*sourceMappingURL=||')
  [ -z "$TRAILING" ] && continue
  BASE=$(echo "$f" | sed 's|^bundles/||;s|^[a-f0-9]\{12\}_||')
  case "$TRAILING" in
    http*) MAP="$TRAILING";;
    /*)    MAP="${TARGET}${TRAILING}";;
    *)     MAP="${TARGET}/$(dirname "$BASE")/${TRAILING}";;
  esac
  curl -sk "$MAP" -o "${f}.map" 2>/dev/null
  [ -s "${f}.map" ] && echo "[map] $MAP recovered"
done

# Also guess common sourcemap locations the bundle didn't disclose
for f in bundles/*.js; do
  for guess in "${f}.map" "/$(basename "$f").map" \
               "/static/$(basename "$f").map" \
               "/_next/static/chunks/$(basename "$f").map"; do
    curl -skI "$guess" 2>/dev/null | head -1 | grep -q "200" && \
      curl -sk "$guess" -o "${f}.map.guessed"
  done
done
```

Once a `.map` is downloaded, recover original source files:

```bash
# Source map is JSON with sources[] + sourcesContent[]
for m in bundles/*.map; do
  out="recovered/$(basename "$m" .map)"; mkdir -p "$out"
  python3 - <<PY
import json, os
m = json.load(open("$m"))
sources = m.get("sources", []); contents = m.get("sourcesContent") or []
for i, src in enumerate(sources):
    if i >= len(contents) or contents[i] is None: continue
    safe = src.replace("..", "__").replace("webpack://", "wp_").replace("//", "_").lstrip("/")
    p = os.path.join("$out", safe)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w").write(contents[i])
print(f"recovered {sum(1 for c in contents if c)} files")
PY
done
```

After recovery, **re-run the entire extraction pipeline against
`recovered/`**. The original source is ~10-100x more grep-friendly than
the minified bundle - secret patterns, endpoints, and internal logic
that were obscured by minification become trivially findable.

If the bundle ships maps with `sourcesContent: null` (sources referenced
but not embedded), try fetching named sources individually from the host
(`$TARGET${source_path}`).

### Stage 4: Regex Extraction (Broad Capture, Dedupe Later)

Run regex passes on every bundle (and recovered source). Capture aggressively;
filter false positives in Stage 6.

```bash
# Iterate over both raw bundles and recovered source
TARGET_DIRS="bundles recovered"

# Endpoints - every fetch-shaped or URL-literal pattern
for d in $TARGET_DIRS; do
  [ -d "$d" ] || continue
  grep -rhoE '"https?://[^"]+|`https?://[^`]+|/(api|v[0-9]+|graphql|admin|internal|service|auth|sso|rest|bff|backend|gateway|microservice)[^\s"`<>]*' "$d" 2>/dev/null
  grep -rhoE 'fetch\s*\(\s*[`"\'](https?://|/)[^`"\']+' "$d" 2>/dev/null
  grep -rhoE 'axios\.[a-z]+\s*\(\s*[`"\']' "$d" 2>/dev/null
  grep -rhoE 'baseURL\s*[:=]\s*[`"\']([^`"\']+)' "$d" 2>/dev/null
  grep -rhoE 'new\s+(Request|WebSocket|EventSource)\s*\(\s*[`"\']' "$d" 2>/dev/null
done | sort -u > endpoints_raw.txt
```

Secret extraction - prefix-based and entropy-based:

```bash
# Vendor-prefix tokens: AWS, Google, Stripe, Slack, SendGrid, Mailgun,
# Twilio, GitHub, GitLab, Sentry, Segment, PostHog, JWTs, PEM keys
PATTERNS=(
  'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}'
  'AIza[0-9A-Za-z_-]{35}|ya29\.[0-9A-Za-z_-]+'
  'sk_(live|test)_[0-9a-zA-Z]{24,}|pk_(live|test)_[0-9a-zA-Z]{24,}|rk_(live|test)_[0-9a-zA-Z]{24,}|whsec_[0-9a-zA-Z]{32,}'
  'xox[baprs]-[0-9]+-[0-9]+-[0-9a-zA-Z]+'
  'SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}'
  'key-[0-9a-zA-Z]{32}'
  'SK[0-9a-fA-F]{32}|AC[0-9a-fA-F]{32}'
  'gh[pousr]_[0-9A-Za-z]{36,}|glpat-[0-9A-Za-z_-]{20}'
  '"sentryDSN":\s*"[^"]+"|https://[0-9a-f]{32}@sentry\.io|"writeKey":\s*"[a-zA-Z0-9]{24,}"|phc_[a-zA-Z0-9]{43}'
  '-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY'
  'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
  '"[a-zA-Z_]+(api_?key|secret|token|password|passwd)[a-zA-Z_]*"\s*[:=]\s*"[a-zA-Z0-9_/+=-]{16,}"'
)
for pat in "${PATTERNS[@]}"; do
  for d in bundles recovered; do
    [ -d "$d" ] && grep -rhoE "$pat" "$d" 2>/dev/null
  done
done | sort -u > secrets_raw.txt

# Entropy-based catch-all
trufflehog filesystem --directory=bundles --only-verified --json 2>/dev/null > trufflehog_b.json
trufflehog filesystem --directory=recovered --only-verified --json 2>/dev/null > trufflehog_r.json
gitleaks detect --source=bundles --no-git --report-path=gitleaks_b.json 2>/dev/null
gitleaks detect --source=recovered --no-git --report-path=gitleaks_r.json 2>/dev/null
```

Internal hostnames, env vars, comments, deps, DB strings:

```bash
# Internal-looking hostnames + dev/staging/qa/preprod prefixes
grep -rhoE 'https?://(internal|admin|dev|staging|test|qa|preprod|backend|legacy|api-internal|svc|mesh|cluster|k8s)[a-z0-9.-]+' \
  bundles/ recovered/ 2>/dev/null | sort -u > hostnames_internal.txt

# Public client env vars (often leak more than intended)
grep -rhoE '(NEXT_PUBLIC_|REACT_APP_|VITE_|VUE_APP_|GATSBY_|PUBLIC_|NUXT_PUBLIC_|EXPO_PUBLIC_)[A-Z0-9_]+\s*[:=]\s*[`"\'][^`"\']+' \
  bundles/ recovered/ 2>/dev/null | sort -u > env_vars_client.txt

# Comments / NPM deps / DB strings
grep -rhoE '//\s*(TODO|FIXME|XXX|HACK|BUG|REMOVE|TEMP|DEBUG):[^\n]+' bundles/ recovered/
grep -rhoE '/\*[^*]*\*/' bundles/ recovered/ | grep -iE '(api|key|secret|password)'
grep -rhoE '"@[a-z0-9_-]+/[a-z0-9_-]+"' bundles/ recovered/ | sort -u > npm_deps.txt
grep -rhoE '(postgres|postgresql|mysql|mongodb|redis|amqp|ldap|kafka)://[^\s"`<>]+' \
  bundles/ recovered/ | sort -u > db_strings.txt
```

### Stage 5: AST Extraction (Higher Precision)

Regex catches the common patterns; AST catches the unusual ones. Parse
the bundle into an AST and walk it for call expressions:

```bash
# ast-grep - pattern match across the bundle (regex-immune to whitespace/obfuscation)
for pat in 'fetch($URL)' 'fetch($URL,$$$)' '$X.get($URL)' '$X.post($URL,$$$)' \
           'new WebSocket($URL)' 'new EventSource($URL)' \
           '{url:$URL,$$$}' '{baseURL:$URL,$$$}' '{endpoint:$URL,$$$}'; do
  ast-grep --pattern "$pat" --lang js bundles/ recovered/ 2>/dev/null
done

# Template literals - regex misses these because of nesting
ast-grep --pattern 'fetch(`$$$`)' --lang js bundles/ recovered/ 2>/dev/null
```

For deeper analysis, parse to JSON AST and walk programmatically:

```bash
# Babel parser via Node - accurate extraction with template-literal handling
node -e "
const fs=require('fs'),p=require('@babel/parser'),t=require('@babel/traverse').default;
const code=fs.readFileSync(process.argv[1],'utf8');
let ast; try { ast=p.parse(code,{sourceType:'unambiguous',
  plugins:['jsx','typescript','optionalChaining'], errorRecovery:true}); }
catch(e){console.error('parse fail:',e.message);process.exit(0);}
const out={fetches:[],strings:[],imports:[]};
t(ast,{
  CallExpression(x){
    const c=x.node.callee, n=c.name||(c.property&&c.property.name)||'';
    if(['fetch','get','post','put','delete','patch','request'].includes(n.toLowerCase())){
      const a=x.node.arguments[0];
      if(a&&a.type==='StringLiteral') out.fetches.push({method:n,url:a.value});
      else if(a&&a.type==='TemplateLiteral')
        out.fetches.push({method:n,template:a.quasis.map(q=>q.value.raw)});
    }
  },
  StringLiteral(x){if(/^(https?:\/\/|\/(api|v[0-9]+|admin|internal|graphql))/.test(x.node.value))
    out.strings.push(x.node.value);},
  ImportDeclaration(x){out.imports.push(x.node.source.value);},
});
console.log(JSON.stringify(out,null,2));
" \"\$bundle\" 2>/dev/null
```

If `@babel/parser` is unavailable, install via `npm i -g @babel/parser
@babel/traverse` or fall back to Python `esprima`. AST output dedupes
and structures data better than regex alone.

### Stage 6: Multi-Pass Recursive Extraction

The first pass surfaces obvious artifacts. The second pass uses what was
found to find more. Specifically:

1. **BaseURL re-contextualization** - if Stage 4/5 found
   `baseURL = "https://api-internal.target.example/v3"`, every relative
   path elsewhere in the bundle (`fetch("/users")`) is now an absolute
   endpoint (`https://api-internal.target.example/v3/users`). Re-walk
   the bundle prepending the discovered baseURL to every relative path.

2. **Discovered hostname expansion** - if `internal-api.target.example`
   was found, search every bundle (and recovered source) for additional
   paths under that hostname. Many bundles reference the same internal
   host from multiple components.

3. **Discovered env-var resolution** - if `NEXT_PUBLIC_API_URL` was
   found in the bundle and a separate config file disclosed its actual
   value, substitute the value everywhere the env-var token appears.

4. **Library-specific re-extraction** - if Stage 4 detected a known
   library (axios with a specific config, urql GraphQL client,
   apollo-client), use that library's API conventions to mine deeper.
   E.g., apollo-client uses `gql` template tags - extract every
   `gql\`...\`` body to recover GraphQL queries.

```bash
# Example: re-walk after baseURL discovery
BASE_URLS=$(grep -hoE 'baseURL\s*[:=]\s*[`"\']([^`"\']+)' bundles/ recovered/ | \
            sed -E 's/.*baseURL\s*[:=]\s*[`"\']([^`"\']+).*/\1/' | sort -u)

for base in $BASE_URLS; do
  # Find every relative path in the same bundle and combine
  grep -rhoE '[`"\']\s*(/[a-zA-Z0-9_/-]+)\s*[`"\']' bundles/ recovered/ | \
    tr -d '"`'"'" | awk -v b="$base" '{print b $0}' | sort -u
done >> endpoints_resolved.txt
```

Repeat until a pass yields zero new artifacts. The recursion typically
converges in 2-4 passes for moderately complex bundles, more for
deeply-modular SPAs.

### Stage 7: Library Version + CVE Mapping

Every bundled library leaks its version. Map versions to known CVEs:

```bash
# retire.js - known JS library vuln signatures
retire --path=bundles --outputformat=json --outputpath=retire_b.json 2>/dev/null
retire --path=recovered --outputformat=json --outputpath=retire_r.json 2>/dev/null
jq -r '.[] | select(.vulnerabilities) |
  "\(.file)\t\(.component) \(.version)\t\(.vulnerabilities[].identifiers.CVE // "?")"' \
  retire_b.json retire_r.json | sort -u > library_cves.txt

# Bundled package versions from package metadata
grep -rhoE '"(react|vue|angular|svelte|next|nuxt|remix|lodash|jquery|axios|moment|dayjs|date-fns|zod|yup|joi|jsonwebtoken|crypto-js|node-forge)"\s*:\s*"[~^]?[0-9.]+' \
  bundles/ recovered/ | sort -u > package_versions.txt

# package.json / package-lock / yarn.lock - sometimes shipped accidentally
for g in package.json static/package.json _next/package.json \
         package-lock.json yarn.lock pnpm-lock.yaml; do
  curl -sk "$TARGET/$g" -o "/tmp/pkg_$(basename "$g" | tr / _)" 2>/dev/null
done
```

### Stage 8: WebAssembly Mining

WASM modules carry crypto, license checks, sometimes auth logic.

```bash
mkdir -p wasm
grep -rhoE 'https?://[^"]+\.wasm|/[^"]+\.wasm' bundles/ recovered/ | sort -u > wasm_urls.txt
while read url; do
  case "$url" in
    http*) curl -sk "$url" -o "wasm/$(basename "$url")" ;;
    /*)    curl -sk "$TARGET$url" -o "wasm/$(basename "$url")" ;;
  esac
done < wasm_urls.txt

for w in wasm/*.wasm; do
  wasm2wat "$w" -o "${w}.wat" 2>/dev/null
  wasm-objdump -x "$w" > "${w}.objdump" 2>/dev/null
  wasm-decompile "$w" -o "${w}.dcmp" 2>/dev/null
  strings "$w" | grep -E '(https?://|/api/|/v[0-9]+/|key|secret|token|error)' | \
    sort -u > "${w}.strings"
done
```

### Stage 9: Obfuscation Detection and Recovery

When grep returns nothing but the bundle is megabytes, obfuscation is
the cause. Detect:

```bash
# Heuristics for obfuscation
for f in bundles/*.js; do
  size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f")
  vars=$(grep -oE '\b[a-zA-Z_$][a-zA-Z0-9_$]*\b' "$f" | sort -u | wc -l)
  short=$(grep -oE '\b[a-zA-Z_$][a-zA-Z0-9_$]{0,2}\b' "$f" | sort -u | wc -l)
  ratio=$(awk -v s="$short" -v v="$vars" 'BEGIN{print (v>0)?s/v:0}')
  hex=$(grep -oE '\\x[0-9a-fA-F]{2}' "$f" | wc -l)
  cc=$(grep -oE 'String\.fromCharCode\s*\(' "$f" | wc -l)
  echo "$f size=$size short_var_ratio=$ratio hex=$hex fromCharCode=$cc"
done
```

If `short_var_ratio > 0.7` or hex-escape density is high, hand off to
`js_deobfuscation` (webcrack, AST renaming). Re-run this entire skill
against the deobfuscated output.

### Stage 10: Runtime-Injected Secrets

Some keys aren't in the bundle - they're fetched at runtime from a
config endpoint and injected into globals. Watch for:

```bash
# Hints that runtime config is fetched + globals that hold it
grep -rhoE 'fetch\s*\(\s*[`"\'](/config|/env|/runtime-config|/_next/static/runtime-config)[`"\']' \
  bundles/ recovered/
grep -rhoE '(window|globalThis|self)\.(__ENV__|__CONFIG__|__SETTINGS__|RUNTIME_CONFIG|APP_CONFIG)' \
  bundles/ recovered/

# Try common runtime-config endpoints
for ep in /config /env /runtime-config /_next/static/runtime-config; do
  curl -sk "$TARGET$ep" 2>/dev/null | head -c 2000
done
```

Runtime-injected secrets are best captured by `recon_llm_active_crawl`
in concert - the crawl sees the config fetch and the response body.

## Output Format

```json
{
  "bundle_url": "https://target.example/_next/static/chunks/main-HASH.js",
  "bundle_local_path": "bundles/abc123_main-HASH.js",
  "source_map_recovered": true,
  "recovered_files": ["recovered/components/admin/UserList.tsx"],
  "endpoints": [
    {"url": "/api/v3/users/me/sessions", "method": "GET", "evidence": "fetch-call"},
    {"url": "https://internal-api.target.example/v3/admin/audit",
     "method": "POST", "evidence": "axios+baseURL-resolved"}
  ],
  "secrets": [{"type": "AWS_ACCESS_KEY", "value_redacted": "AKIA****"},
              {"type": "JWT", "decoded_header": {"alg": "HS256"}}],
  "internal_hostnames": ["internal-api.target.example"],
  "env_vars_client": [{"name": "NEXT_PUBLIC_API_URL", "value": "https://api.target.example/v3"}],
  "libraries_with_cves": [{"name": "lodash", "version": "4.17.4", "cve": "CVE-2019-10744"}],
  "internal_npm_deps": ["@target-internal/auth-sdk"],
  "wasm_modules": ["wasm/validator.wasm"],
  "obfuscation_detected": false
}
```

## Composes With

| Skill | Direction | Glue |
|---|---|---|
| `recon_llm_active_crawl` | Crawl discovers bundle URLs - this skill processes them. Crawl also captures runtime-config fetches that this skill flags as missing. |
| `recon_content_discovery` | Endpoints extracted here become input for content discovery (param + method enumeration on each). |
| `recon_information_disclosure` | Source maps, exposed `package.json`, internal hostnames are all disclosure findings. |
| `recon_archive_intel` | Historical bundles often have credentials the dev rotated later - run this skill against archive snapshots too. |
| `js_deobfuscation` | Stage 9 hands off to webcrack / AST renaming when obfuscation is detected. Re-run this skill on deobfuscated output. |
| `js_runtime_audit` | When obfuscation defeats static analysis, runtime audit captures live behavior - they cover complementary surfaces. |
| `github_dorking` / `gitlab_bitbucket_dorking` | Internal NPM package names from Stage 4 feed dependency-confusion search. |

## Pitfalls and Recoveries

| Pitfall | Symptom | Recovery |
|---|---|---|
| Heavily minified, no maps | `a`, `b`, `c` vars; grep empty | Stage 9 detects -> hand off to `js_deobfuscation` |
| Maps without `sourcesContent` | `null` content array | Try fetching named source paths from host (Stage 3) |
| Maps blocked by CDN | 403 on `.map` URL | Try alternate paths (`/static/`, `/_next/static/`); check archive |
| String concatenation | `"/api" + "/v3" + "/users"` | AST extraction (Stage 5) collapses via constant folding |
| Char-code construction | `String.fromCharCode(47,97,112,105)` | Run JS evaluator on each chunk to reduce |
| Base64-encoded secrets | `atob("ZXlKO...")` | Decode every `atob(` literal argument |
| Runtime-fetched config | Config endpoint hit at page load | Stage 10; capture via `recon_llm_active_crawl` network trace |
| Webpack module ID instability | IDs change across builds | Rely on path/name patterns, not IDs |
| 200+ chunks, hard to grep | Bundles split across many chunks | Process all in parallel; build cross-chunk index |
| Partial map coverage | Some chunks have maps, others don't | Process recovered + raw together (Stage 4) |
| AST parse failure | `@babel/parser` errors | `errorRecovery: true`; fall back to regex on failing file |
| Base URL is a function call | `baseURL: getApiUrl()` | Trace function definition; substitute env-var literal if returned |

## Termination

Process every discovered JS bundle. Run **regex AND AST** extraction on
every bundle. Attempt sourcemap recovery on every bundle. When a `.map`
is recovered, re-run the entire pipeline against the recovered source.

The recursive multi-pass loop (Stage 6) terminates when **a complete
pass yields zero new artifacts** - no new endpoint, no new secret, no
new hostname, no new env var. Until then, the loop continues.

Detected obfuscation (Stage 9) hands off to `js_deobfuscation`; re-enter
this skill on the deobfuscated output. The skill is idempotent.

Multi-snapshot scopes (current + archive bundles via
`recon_archive_intel`): process every snapshot. Old bundles often have
rotated-but-still-valid credentials.

No fetch budget, no time limit, no bundle-count cap. A single overlooked bundle can hide the entire admin API surface.
