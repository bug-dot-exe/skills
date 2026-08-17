---
name: recon-content-discovery
category: reconnaissance
description: Path, file, parameter, and method discovery. Source-derived first, wordlist as fallback. Replaces ffuf / dirsearch / arjun in isolation with a single-context pipeline that prefers real paths from crawl + JS + archive + leak data over generic guesses, then layers wordlist passes (small -> large -> framework-tuned -> extension-tuned) only after exhaustion.
depends_on: []
---

# Content Discovery

Wordlist fuzzing is the loudest, least efficient step in recon. Running a
1M-entry wordlist against a target before harvesting the paths the target
itself reveals through its HTML, JS bundles, sitemaps, and archive history
is wasted compute. **Source-derived discovery returns real paths.
Wordlist fuzzing returns guesses.** This skill orders the work so guesses
come last - and only after the cheap, accurate sources are exhausted.

The output of this skill is the discovered surface: every path the target
serves, every parameter each path accepts, and every HTTP method each path
permits. That surface is the input for every subsequent vulnerability
class skill.

## When to Use

- After active crawl (`recon_llm_active_crawl`) has saturated.
- After deep JS analysis (`recon_deep_js_analysis`) has dumped its
  endpoint extracts.
- After archive intel (`recon_archive_intel`) has produced historical paths.
- When the agent needs the parameter / method matrix per endpoint before
  invoking IDOR, SSRF, SSTI, command-injection, etc. skills.
- Whenever the surface still has unknowns - any 4xx / 5xx response that
  doesn't match the default-error fingerprint may hide a path.

## Source-Derived Priority

Run sources in order of confidence. Each stage feeds the next.

### Stage 1: Crawl-Derived Paths (Highest Confidence)

These are paths the application itself referenced. They exist with
certainty.

```bash
# From recon_llm_active_crawl output - extracted via <a>, <form>, <script>, etc.
jq -r '.url' crawl_output.jsonl 2>/dev/null | \
  awk -F/ 'NF>=4 {sub(/^[^/]*\/\/[^/]*/,""); print}' | \
  sort -u > paths_from_crawl.txt

# Sanity check
wc -l paths_from_crawl.txt
```

Every path here gets exercised against every method (Stage 7 below). No
wordlist needed for this set.

### Stage 2: JS Bundle Paths

JS bundles contain `fetch()` and `axios` calls the UI never triggers.
These paths are the API surface beyond the user-clickable surface.

```bash
# From recon_deep_js_analysis output
jq -r '.endpoints[]' js_extract.json 2>/dev/null > paths_from_js.txt

# Or extract directly if not yet run
mkdir -p bundles
for js in $(grep -oE 'src="[^"]+\.js[^"]*"' /tmp/responses/*.html | \
            sed -E 's/.*src="([^"]+)".*/\1/' | sort -u); do
  curl -sk "$js" -o "bundles/$(basename "$js" | tr '?&' '__')"
done

# Extract path-style URLs from bundles
grep -rhoE '"\s*(/[a-zA-Z0-9_/.-]+)\s*"' bundles/ | \
  grep -E '^"\s*/(api|v[0-9]+|graphql|admin|internal|service|auth|sso|rest|bff)' | \
  tr -d '"' | sort -u >> paths_from_js.txt
```

### Stage 3: Archive-Derived Paths

Web archives expose paths that exist now but are no longer linked, plus
paths that existed historically and may still respond.

```bash
# From recon_archive_intel - or pull live
gau --providers wayback,commoncrawl,otx,urlscan "$DOMAIN" 2>/dev/null | \
  awk -F/ 'NF>=4 {sub(/^[^/]*\/\/[^/]*/,""); print}' > paths_from_archive.txt

# Wayback CDX directly (often has paths gau misses)
curl -sk "https://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&output=text&fl=original&collapse=urlkey" \
  2>/dev/null | awk -F/ 'NF>=4 {sub(/^[^/]*\/\/[^/]*/,""); print}' \
  >> paths_from_archive.txt
sort -u -o paths_from_archive.txt paths_from_archive.txt
```

Archive paths are goldmines: deprecated API versions the team forgot to
take down, dev / staging leaks, debug paths that returned 500s.

### Stage 4: Code Leak Paths

GitHub / GitLab / Postman / Pastebin leaks often contain hardcoded
endpoint URLs. Pull from `recon_*_dorking` skills' outputs:

```bash
# From github_dorking / gitlab_bitbucket_dorking output
jq -r '.matches[].snippet' github_leaks.json 2>/dev/null | \
  grep -oE '"/[a-zA-Z0-9_/.?=-]+"' | tr -d '"' | sort -u > paths_from_leaks.txt

# From postman_workspace_dorking output
jq -r '.collections[].requests[].url' postman_leaks.json 2>/dev/null | \
  awk -F/ 'NF>=4 {sub(/^[^/]*\/\/[^/]*/,""); print}' | sort -u >> paths_from_leaks.txt

# From pastebin_dorking output
grep -hoE '"/[a-zA-Z0-9_/.?=-]+"' pastebin_dump/* 2>/dev/null | \
  tr -d '"' | sort -u >> paths_from_leaks.txt
```

### Stage 5: robots.txt + sitemap.xml + .well-known

Every web app explicitly publishes some of its surface:

```bash
# robots.txt - both Allow and Disallow
curl -sk "$TARGET/robots.txt" | grep -iE "^(allow|disallow|sitemap):" | \
  awk '{print $2}' | sort -u >> paths_from_published.txt

# sitemap.xml - recurse if it references other sitemaps
for sm in $(curl -sk "$TARGET/sitemap.xml" | grep -oE '<loc>[^<]+</loc>' | \
            sed 's/<loc>//;s/<\/loc>//' | sort -u); do
  curl -sk "$sm" | grep -oE '<loc>[^<]+</loc>' | sed 's/<loc>//;s/<\/loc>//'
done | awk -F/ 'NF>=4 {sub(/^[^/]*\/\/[^/]*/,""); print}' | sort -u \
  >> paths_from_published.txt

# .well-known - OAuth / OpenID / app-link metadata
for wk in security.txt openid-configuration oauth-authorization-server \
          assetlinks.json apple-app-site-association webfinger \
          host-meta change-password did.json mta-sts.txt; do
  curl -sk "$TARGET/.well-known/$wk" -o "/tmp/wk_$wk" 2>/dev/null
  [ -s "/tmp/wk_$wk" ] && echo "/.well-known/$wk"
done >> paths_from_published.txt
```

### Stage 6: Framework Default Paths

After fingerprinting the stack (from `recon_llm_active_crawl` headers,
HTML hints, cookie names), append framework-specific known paths:

| Stack | Defaults to probe |
|---|---|
| Laravel | `/storage/`, `/api/`, `/sanctum/csrf-cookie`, `/_ignition/health-check`, `/telescope`, `/horizon`, `/.env`, `/storage/logs/laravel.log` |
| Django | `/admin/`, `/api/v1/`, `/static/admin/`, `/media/`, `/__debug__/` |
| Rails | `/assets/`, `/rails/info/properties`, `/rails/info/routes`, `/rails/active_storage/`, `/rails/conductor/` |
| Express / Node | `/api/`, `/health`, `/healthz`, `/metrics`, `/debug`, `/admin` |
| Spring Boot | `/actuator/`, `/actuator/env`, `/actuator/heapdump`, `/actuator/loggers`, `/actuator/mappings`, `/actuator/beans`, `/actuator/threaddump` |
| WordPress | `/wp-admin/`, `/wp-login.php`, `/wp-json/wp/v2/users`, `/xmlrpc.php`, `/wp-content/uploads/`, `/wp-content/debug.log` |
| Drupal | `/user/login`, `/admin`, `/?q=admin`, `/sites/default/`, `/CHANGELOG.txt` |
| Joomla | `/administrator/`, `/index.php?option=com_users`, `/configuration.php` |
| ASP.NET | `/elmah.axd`, `/Trace.axd`, `/_vti_pnf/`, `/aspnet_client/`, `/web.config` |
| Symfony | `/_profiler/`, `/_wdt/`, `/app_dev.php`, `/_fragment` |
| Next.js / Nuxt / Strapi | `/_next/data/`, `/_next/static/chunks/`, `/__next/webpack-hmr`, `/_nuxt/`, `/api/_content/`, `/.tmp/data.db` |
| GraphQL | `/graphql`, `/graphiql`, `/altair`, `/playground`, `/v1/graphql`, `/api/graphql` |
| Jenkins / GitLab | `/script`, `/manage`, `/credentials/`, `/api/json`, `/api/v4/`, `/-/admin`, `/users/sign_in` |
| Tomcat / WebLogic | `/manager/html`, `/host-manager/`, `/examples/jsp/snp/snoop.jsp`, `/console/login/LoginForm.jsp`, `/wls-wsat/CoordinatorPortType` |
| Kubernetes Dashboard | `/api/v1/namespaces`, `/api/v1/pods`, `/healthz`, `/version` |

Append these only when the fingerprint matches. Probing Spring Boot
defaults against a Django app wastes requests.

## Wordlist Fallback

After Stages 1-6 are exhausted, run wordlists. Order matters:

### Stage 7a: Universal Small (~10k entries)

Quick first pass for common paths the target's published sources didn't
mention:

```bash
# SecLists - common.txt (~5k), raft-large-words.txt (~120k - skip for now)
ffuf -u "$TARGET/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,201,204,301,302,307,308,401,403,405,500 \
  -fs $(curl -sk -o /dev/null -w "%{size_download}" "$TARGET/RANDOM-$(date +%s)") \
  -t 30 -recursion -recursion-depth 2 \
  -o ffuf_universal_small.json -of json
```

The `-fs` filter excludes responses matching the default-404 size
(captured by hitting a guaranteed-404 URL and measuring the response).

### Stage 7b: Universal Large (~100k - 1M entries)

After small wordlist completes, run the big ones:

```bash
# raft-large-words (~120k)
ffuf -u "$TARGET/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
  -mc 200,201,204,301,302,307,308,401,403,405,500 \
  -fs $DEFAULT_404_SIZE -fw $DEFAULT_404_WORDS \
  -t 30 -o ffuf_universal_large.json -of json

# directory-list-2.3-medium (~220k) - high yield, slower
ffuf -u "$TARGET/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -mc 200,201,204,301,302,307,308,401,403,405,500 \
  -fs $DEFAULT_404_SIZE \
  -t 30 -o ffuf_directory_list.json -of json

# big.txt (~20k) - shorter but covers different ground
ffuf -u "$TARGET/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/big.txt \
  -mc 200,201,204,301,302,307,308,401,403,405,500 \
  -t 30 -o ffuf_big.json -of json
```

### Stage 7c: Framework-Tuned Wordlists

When the fingerprint matches a known stack, run its dedicated wordlist
in addition to (not instead of) the universal one:

```bash
# Pick wordlist by detected framework
case "$STACK" in
  laravel)  WL=/usr/share/seclists/Discovery/Web-Content/Laravel.fuzz.txt ;;
  django)   WL=/usr/share/seclists/Discovery/Web-Content/django.txt ;;
  rails)    WL=/usr/share/seclists/Discovery/Web-Content/RobotsDisallowed-Top1000.txt ;;
  spring)   WL=/usr/share/seclists/Discovery/Web-Content/spring-boot.txt ;;
  wordpress) WL=/usr/share/seclists/Discovery/Web-Content/CMS/wp_plugins.fuzz.txt ;;
  drupal)   WL=/usr/share/seclists/Discovery/Web-Content/CMS/drupal_temp_files.txt ;;
  iis)      WL=/usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt ;;
  apache)   WL=/usr/share/seclists/Discovery/Web-Content/apache.txt ;;
  jboss)    WL=/usr/share/seclists/Discovery/Web-Content/jboss.txt ;;
  lotus)    WL=/usr/share/seclists/Discovery/Web-Content/lotus_domino.txt ;;
esac

ffuf -u "$TARGET/FUZZ" -w "$WL" \
  -mc 200,201,204,301,302,307,308,401,403,405,500 \
  -t 30 -o "ffuf_${STACK}.json" -of json
```

### Stage 7d: Extension-Targeted Probing

For every directory found in Stages 1-7c, probe with extensions a
careless dev might have left behind:

```bash
EXTS="php php3 php4 php5 phtml asp aspx aspx.cs cfm cgi pl py rb js \
      json yaml yml xml html htm txt log sql sqlite db bak backup old \
      orig save swp swo swn tmp temp ~ inc include conf cfg config \
      ini env properties toml csv tar tar.gz tgz tar.bz2 zip rar 7z \
      dump sql.gz sql.bz2 csv.gz pem key crt p12 pfx jks war jar"

for dir in $(jq -r '.results[].url' ffuf_*.json | \
             awk -F/ '{print $4}' | sort -u); do
  for ext in $EXTS; do
    ffuf -u "$TARGET/$dir.$ext" \
      -mc 200,201,301,302,401,403 \
      -t 20 -o "ffuf_ext_${dir}_${ext}.json" -of json
  done
done

# Same idea for filename-based fuzzing on each directory
ffuf -u "$TARGET/$dir/FUZZ.${ext}" \
  -w /usr/share/seclists/Discovery/Web-Content/big.txt \
  -mc 200,201,301,302,401,403 -t 30
```

### Stage 7e: Extension-Suffix on Discovered Paths

Discovered paths may have backup / swap / old siblings:

```bash
SUFFIXES=".bak .old .orig .save .swp .swo .swn ~ .tmp .temp .bk .copy .backup"

while read p; do
  for s in $SUFFIXES; do
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 "$TARGET${p}${s}")
    [ "$CODE" = "200" ] && echo "$TARGET${p}${s}"
  done
done < discovered_paths.txt
```

## Parameter Discovery

For every discovered endpoint, find every parameter it accepts.

### Stage 8a: Archive + JS Parameter Extraction

```bash
# From archive URLs (real params the target actually used)
grep "?" paths_from_archive.txt | \
  awk -F? '{print $2}' | tr '&' '\n' | awk -F= '{print $1}' | \
  sort -u > params_from_archive.txt

# From JS bundles - object literals passed to fetch/axios
grep -rhoP '(params|data|body|query)\s*[:=]\s*\{[^}]+\}' bundles/ 2>/dev/null | \
  grep -oE '"[a-zA-Z_][a-zA-Z0-9_]*"' | tr -d '"' | sort -u > params_from_js.txt

# From form action+input pairs in HTML
grep -hoE 'name=["`][a-zA-Z_][a-zA-Z0-9_]*["`]' /tmp/responses/*.html | \
  sed -E 's/.*name=["`]([^"`]+).*/\1/' | sort -u > params_from_forms.txt
```

### Stage 8b: Wordlist Parameter Fuzzing

For each endpoint, brute-force unknown parameters. Source-derived first;
then a generic param wordlist:

```bash
# arjun on every discovered endpoint
while read endpoint; do
  arjun -u "$TARGET$endpoint" -m GET POST PUT PATCH \
    -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    -oJ "arjun_$(echo "$endpoint" | tr '/' '_').json" 2>/dev/null
done < discovered_endpoints.txt

# Targeted classes - inject one param at a time, watch for behavior change
TARGETED_PARAMS=(
  # IDOR / object reference
  id user_id uid account_id org_id team_id project_id file_id doc_id order_id
  invoice_id ticket_id session_id post_id comment_id record_id resource_id
  # SSRF / open redirect
  url redirect next return_to callback continue dest forward ref uri target
  image_url avatar_url proxy fetch_url import_from
  # File / path / injection / debug / format
  file path filename template include page view resource src image document
  upload export download attachment archive
  search query q filter sort cmd exec command input data raw eval
  debug test admin verbose trace log mode env config internal dev preview
  impersonate as_user role permission
  format output type content_type accept charset encoding lang locale
)

for p in "${TARGETED_PARAMS[@]}"; do
  # Compare baseline vs. with-param response sizes
  BASE=$(curl -sk "$TARGET$endpoint" -o /dev/null -w "%{size_download}")
  WITH=$(curl -sk "$TARGET$endpoint?$p=test" -o /dev/null -w "%{size_download}")
  [ "$BASE" != "$WITH" ] && echo "[diff] $endpoint?$p (size $BASE -> $WITH)"
done
```

### Stage 8c: Header Parameter Discovery

Some apps read params from headers, not query strings:

```bash
HEADERS=(
  "X-Forwarded-For: 127.0.0.1" "X-Real-IP: 127.0.0.1"
  "X-Forwarded-Host: localhost" "X-Original-URL: /admin"
  "X-Rewrite-URL: /admin" "X-Forwarded-Server: localhost"
  "X-HTTP-Method-Override: PUT" "X-Method-Override: DELETE"
  "X-Original-Method: PUT" "X-Cluster-Client-IP: 127.0.0.1"
  "Forwarded: for=127.0.0.1" "X-Custom-IP-Authorization: 127.0.0.1"
  "X-Originating-IP: 127.0.0.1" "X-Remote-IP: 127.0.0.1"
  "X-Tenant-Id: 1" "X-Account-Id: 1" "X-User-Id: 1"
  "X-Debug: true" "X-Debug-Mode: 1" "X-Trace: 1"
  "X-Test: true" "X-Internal: true"
)

for h in "${HEADERS[@]}"; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" -H "$h" "$TARGET$endpoint")
  echo "[$h] -> $STATUS"
done
```

## Method Discovery

For every discovered endpoint, enumerate every HTTP method:

```bash
# OPTIONS first - server may honestly disclose
curl -skX OPTIONS "$TARGET$endpoint" -i | grep -iE "^allow:"

# Brute-force every method - some servers ignore OPTIONS but accept the method
for m in GET POST PUT PATCH DELETE HEAD OPTIONS COPY MOVE LOCK UNLOCK \
         PROPFIND PROPPATCH MKCOL TRACE CONNECT SEARCH; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" -X "$m" --max-time 8 "$TARGET$endpoint")
  case "$STATUS" in
    200|201|204|301|302|307|308) echo "[ok] $m $endpoint -> $STATUS" ;;
    401|403)                     echo "[auth] $m $endpoint -> $STATUS" ;;
    405|501)                     ;;  # not allowed - skip
    *)                           echo "[odd] $m $endpoint -> $STATUS" ;;
  esac
done
```

PUT or DELETE on a "GET-only" endpoint sometimes succeeds - common
misconfiguration of REST routers, especially on `/api/users/{id}`-style
endpoints.

## Smart Filters

Status, size, and word-count filters cut through default-error noise:

```bash
# Find the default-404 fingerprint first
RANDOM_PATH="/__nonexistent_$(date +%s%N)__"
DEFAULT_STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET$RANDOM_PATH")
DEFAULT_SIZE=$(curl -sk -o /dev/null -w "%{size_download}" "$TARGET$RANDOM_PATH")
DEFAULT_WORDS=$(curl -sk "$TARGET$RANDOM_PATH" | wc -w)

# Now fuzz with filters tuned to ignore the default
ffuf -u "$TARGET/FUZZ" -w wordlist.txt \
  -mc 200,201,301,302,401,403 \
  -fs "$DEFAULT_SIZE" -fw "$DEFAULT_WORDS" \
  -t 30
```

For targets behind a wildcard responder (every path returns 200 with a
templated body), filter by *content* rather than status:

```bash
# Use response signature - hash the body, exclude the default
DEFAULT_BODY_HASH=$(curl -sk "$TARGET$RANDOM_PATH" | sha1sum | awk '{print $1}')

ffuf -u "$TARGET/FUZZ" -w wordlist.txt -mc all \
  -fr "$(curl -sk "$TARGET$RANDOM_PATH" | head -c 200 | tr -d '\n' | sed 's/[]\/$*.^|[]/\\&/g')"
```

## CDN / Cache Bypass

Discovered paths sometimes hit a cache that masks 404s. Vary the request
to bypass:

```bash
for path in $(cat wordlist.txt); do
  # Add noise to defeat simple URL-based caching
  curl -sk "$TARGET/$path?cb=$(date +%s%N)" -H "Cache-Control: no-cache" \
       -H "Pragma: no-cache" -H "X-Cache-Bust: $RANDOM" \
       -o "/tmp/r_$path" -w "%{http_code}\t%{size_download}\t/$path\n"
done
```

## Output Format

```json
{
  "path": "/api/v3/users/me/sessions",
  "status": 200,
  "size": 842,
  "words": 73,
  "method_supported": ["GET", "DELETE", "OPTIONS"],
  "parameters_discovered": [
    {"name": "active_only", "source": "archive"},
    {"name": "since", "source": "js-bundle"},
    {"name": "include_revoked", "source": "arjun"}
  ],
  "discovery_source": "crawl + js + archive",
  "framework_default": false,
  "extension_variants_found": ["/api/v3/users/me/sessions.json"]
}
```

## Composes With

| Skill | Direction | Glue |
|---|---|---|
| `recon_llm_active_crawl` | Seeds Stage 1 - the high-confidence path set. |
| `recon_deep_js_analysis` | Seeds Stage 2 - bundle-extracted endpoints. |
| `recon_archive_intel` | Seeds Stage 3 - historical paths. |
| `recon_information_disclosure` | Specific disclosure paths (`/.git/`, `/.env`, `/server-status`) feed into Stage 6 framework defaults. |
| `parameter_discovery` | Stage 8 invokes arjun-style logic - same primitive, this skill orders it. |
| `target_mapping` | Output drives the per-method, per-param attack matrix. |
| `nuclei_workflow` | Discovered paths feed nuclei templates that need a path list as input. |

## Pitfalls and Recoveries

| Pitfall | Symptom | Recovery |
|---|---|---|
| Wildcard responder | Every path 200 with templated body | Filter by content hash, not status (Smart Filters section) |
| Custom 404 returns 200 | "Not Found" page with HTTP 200 | Detect via baseline, filter by body content |
| WAF blocks fuzzing | 403 wave after first ~50 requests | Slow down, rotate UA, switch source IP, use crawl-derived only |
| CDN cached 404s | Same path returns 404 forever even after route added | Add cache-bust query (`?cb=$timestamp`), `Cache-Control: no-cache` |
| Rate limit | 429 streak | Reduce concurrency, jitter, retry-after-aware backoff |
| Server returns 200 for all `.bak` | Catch-all on extensions | Compare body sizes - real backup files are usually >10x bigger than the wildcard response |
| Path normalization | `/admin/` and `/admin` and `//admin/` may differ | Probe each variant - servers often differ in handling |
| Method override headers blocked | `X-HTTP-Method-Override` returns same status | Try `X-Method-Override`, `X-Original-Method`, `_method` POST body param |
| Param case sensitivity | `?ID=` 200, `?id=` 404 | Probe both cases for every discovered param |
| Multipart-only endpoints | `?param=x` ignored, `multipart/form-data` works | Re-fuzz with `-d "param=value"` and `-F "param=value"` separately |

## Termination

Content discovery runs every stage on every endpoint. Termination is when
**every source has been processed and every layered wordlist has run to
completion against every discovered directory**.

Specifically:

- Stages 1-6 (source-derived) all run before any wordlist.
- Stage 7a runs to completion before 7b. 7b before 7c. 7c before 7d.
- Stage 7e runs against the union of all discovered directories.
- Stage 8 (parameter discovery) runs against every discovered endpoint.
- Stage 9 (method enumeration) runs against every discovered endpoint.

No early-out for "found enough paths" or "wordlist 1 done." Every
wordlist's coverage differs; the union strictly beats any subset. The
agent loops until every (endpoint, method, param) cell of the matrix is
filled or tested-and-empty.

Multi-host scopes: the pipeline runs per host. Multi-protocol scopes
(HTTP and HTTPS): run both - they often have asymmetric handlers.

**Pro Tips (corpus-derived):** For Electron/CEF/desktop apps, probe for `--remote-debugging-port` and `--inspect` flags in launch args -- an exposed debug port is full RCE ($500K payouts). When an ACL/permission change returns success, always re-test enforcement AFTER the change completes -- staleness in cached authorization states is a recurring auth bypass class. For any "select from a configured list" UI, submit a value NOT in the list via Burp -- server-side validation of dropdown values is frequently missing.
