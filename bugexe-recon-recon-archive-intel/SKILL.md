---
name: Recon Archive Intel
category: reconnaissance
description: Methodology for harvesting historical URL/path/parameter intel from web archives (Wayback CDX, URLScan, OTX, Common Crawl, VirusTotal, HackerTarget, DNSDumpster) — operators, dedup, parameter mining, multi-archive cross-pollination
depends_on: []
---

# Recon Archive Intel

## Purpose

Web archives are time machines. Every public URL the target ever exposed is likely captured by at least one archive. This includes URLs that:

- Were published, indexed, then quietly retired (404 today, but the path is still in code).
- Existed only on dev/staging hosts that are now offline.
- Were surfaced briefly by a misconfiguration, captured, then re-locked.
- Carry parameter names the target's developers reuse on different endpoints today.
- Reveal endpoint conventions (`/api/v1/...`, `/_next/static/...`, `/wp-content/uploads/...`) that suggest framework-specific exploitation paths.

This skill replaces ad-hoc reliance on `gau`, `waymore`, and `waybackurls` subprocesses. The agent learns the methodology of querying each archive, deduplicating across archives, mining parameters, and cross-pollinating findings — applying the workflow via direct HTTP calls (`curl` / `python requests`) and reasoning over the results, not via a brittle subprocess wrapper.

## When to Use

- Immediately after subdomain enumeration: every confirmed hostname becomes an archive query.
- Before content discovery / directory fuzzing: archive URLs become the primary input wordlist.
- When a target's current site looks minimal — archives often expose the full history of an SPA where current state hides routes.
- When hunting parameter-handling bugs (IDOR, SSRF, SQLi, XSS): archived URLs reveal parameter names the developer used historically.
- When investigating a specific subdomain's lifecycle: archive timestamps show when it was first/last seen.
- When the live site has WAF/auth gates: archives may have captured pre-WAF/pre-auth versions of paths and full-response bodies.
- When mapping JavaScript bundles over time: archives capture old `.js` filenames whose source maps may still be hosted.

## Inputs

- `target_apex` — primary domain (e.g., `target.example`).
- `target_subdomains[]` — full subdomain inventory from prior recon.
- `urlscan_api_key` — required for unrestricted URLScan API. Without it, public search still works but with rate limits.
- `otx_api_key` — required for OTX AlienVault. Free, but requires registration.
- `virustotal_api_key` — required for VirusTotal Domain/URL endpoints. Free tier = 500 req/day at 4 req/min.
- `commoncrawl_index_id` — choice of which Common Crawl index version (e.g., `CC-MAIN-2026-15`); fall back to fetching the index list from `https://index.commoncrawl.org/collinfo.json` and using the latest 4-6 indexes.
- `hackertarget_no_key` — HackerTarget free tier requires no key but caps daily queries per IP.

## Methodology

### Stage 1: Wayback Machine CDX API (the historical anchor)

The CDX (Capture inDeX) API exposes every URL the Internet Archive has captured for a hostname. Endpoint:

```
https://web.archive.org/cdx/search/cdx
```

Required and useful query parameters:

| Param | What it does | Recommended value |
|---|---|---|
| `url` | URL pattern to match. Accepts `*.target.example/*` for full-path wildcard. | `*.target.example/*` for first sweep; `target.example/*` is a subset; `<subdomain>/*` for narrow per-host sweep |
| `output` | Output format | `json` for structured parsing |
| `fl` | Fields to return | `original,timestamp,statuscode,mimetype,length,digest` |
| `limit` | Max records | `100000` per request; paginate via `resumeKey` |
| `from` / `to` | Date range filter (YYYYMMDDhhmmss) | `from=20100101` `to=20261231` for full history |
| `filter` | Server-side filter | see below |
| `collapse` | Dedup field | `urlkey` for unique-URL dedup, `digest` for unique-content dedup |

Filter expressions (all may be repeated):

```
filter=statuscode:200            # only 200 OK captures
filter=!statuscode:[45]..        # exclude 4xx/5xx (regex; ! = negation)
filter=mimetype:text/html
filter=mimetype:application/json
filter=mimetype:text/javascript
filter=mimetype:application/.*   # all application/* mimetypes (binary, json, pdf, zip)
filter=urlkey:.*\.json           # only URLs ending .json
filter=original:.*\?.*           # only URLs with a querystring (parameter-bearing)
```

Recommended sweep sequence (run all of these — different filters surface different intent):

```
# 1. All HTML pages, dedup by URL
url=*.target.example/*&output=json&collapse=urlkey&filter=statuscode:200&filter=mimetype:text/html

# 2. All JSON endpoints (likely API responses)
url=*.target.example/*&output=json&collapse=urlkey&filter=mimetype:application/json

# 3. All JavaScript bundles (for source-map / endpoint mining)
url=*.target.example/*&output=json&collapse=urlkey&filter=mimetype:.*javascript

# 4. All parameter-bearing URLs (querystring is the gold)
url=*.target.example/*&output=json&collapse=urlkey&filter=original:.*\?.*

# 5. Recently captured (last 12 months) — likely still live
url=*.target.example/*&output=json&collapse=urlkey&from=20250101&to=20261231

# 6. Old captures (pre-WAF / pre-auth era)
url=*.target.example/*&output=json&collapse=urlkey&from=20100101&to=20180101&filter=statuscode:200

# 7. Anything with admin / internal / debug / test / dev / api / v1 / v2 / v3 in the path
url=*.target.example/*&output=json&collapse=urlkey&filter=urlkey:.*(admin|internal|debug|staging|test|dev|api/v[0-9]|graphql).*

# 8. Static dev artifacts that should never have been public
url=*.target.example/*&output=json&collapse=urlkey&filter=urlkey:.*(\.git|\.env|\.swp|\.bak|\.old|\.orig|\.backup|\.zip|\.tar|\.sql).*
```

Pagination: when a response includes `resumeKey`, append `&resumeKey=<value>` to fetch the next page. Continue until `resumeKey` is absent.

Per-capture lookup (when you want the actual content of an archived URL): the URL pattern is

```
https://web.archive.org/web/<timestamp>/<original_url>
```

For raw response without Wayback's framing, replace `/web/<timestamp>/` with `/web/<timestamp>id_/`.

### Stage 2: URLScan.io (visual + DOM-aware archive)

URLScan captures real browser-rendered DOM, screenshots, and full network requests for any URL submitted to it. Search endpoint:

```
GET https://urlscan.io/api/v1/search/?q=<query>&size=10000
```

Header (if you have a key):
```
API-Key: <urlscan_api_key>
```

Query language (Lucene-style):

```
domain:target.example
page.domain:target.example
page.url:target.example/admin
task.url:target.example
ip:198.51.100.42
asn:AS00000
hash:<sha256_of_response_body>
filename:*.js
filename:*.json
result.task.status:200
page.country:US
page.tlsValidDays:>30
date:>now-1y
```

Recommended sweep sequence:

```
# 1. All scans of the apex
q=domain:target.example&size=10000

# 2. All scans of every subdomain (loop)
for sub in target_subdomains: q=page.domain:<sub>&size=10000

# 3. Specific high-value path patterns
q=page.url:target.example/api*&size=10000
q=page.url:target.example/admin*&size=10000
q=page.url:target.example/_next/data*&size=10000
q=page.url:target.example/graphql*&size=10000

# 4. Filename-specific (pulls every captured JS/JSON)
q=domain:target.example AND filename:*.js&size=10000
q=domain:target.example AND filename:*.json&size=10000
q=domain:target.example AND filename:*.map&size=10000

# 5. By IP (pivot — every IP from prior recon)
for ip in known_ips: q=ip:<ip>&size=10000
```

For each result UUID, the full data and screenshot are at:

```
https://urlscan.io/api/v1/result/<uuid>/
https://urlscan.io/screenshots/<uuid>.png
https://urlscan.io/dom/<uuid>/
```

The full result includes the entire network log (every subresource request the browser made), which exposes JS-loaded API endpoints, third-party script origins, and asset CDNs.

### Stage 3: OTX AlienVault (threat-intel passive URL list)

```
GET https://otx.alienvault.com/api/v1/indicators/domain/target.example/url_list?limit=500&page=1
```

Header:
```
X-OTX-API-KEY: <otx_api_key>
```

Iterate `page=1..N` until the response `has_next` is false. Each page returns a `url_list` array of entries:

```json
{"url": "https://target.example/some/path", "date": "2026-04-01", "encoded": "..."}
```

OTX also exposes:
```
GET https://otx.alienvault.com/api/v1/indicators/domain/target.example/passive_dns?limit=500
GET https://otx.alienvault.com/api/v1/indicators/domain/target.example/general
GET https://otx.alienvault.com/api/v1/indicators/domain/target.example/malware
```

Loop the URL list endpoint for every subdomain too; OTX often has subdomain-specific records.

### Stage 4: Common Crawl Index (deep historical web crawl)

Common Crawl publishes monthly internet-wide crawls. Each is indexed at:

```
https://index.commoncrawl.org/<INDEX_ID>-index?url=*.target.example/*&output=json
```

Discover available indexes:

```
GET https://index.commoncrawl.org/collinfo.json
```

Pick the latest 4-6 (the most recent year) for primary coverage; older indexes for historical depth. For each chosen index, paginate:

```
?url=*.target.example/*&output=json&pageSize=1000&page=0
?url=*.target.example/*&output=json&pageSize=1000&page=1
...
```

Each record includes a WARC offset:

```json
{"urlkey":"example,target)/path","timestamp":"20260315120000","url":"https://target.example/path",
 "mime":"text/html","status":"200","digest":"...","length":"4096","offset":"1234567","filename":"crawl-data/.../warc.gz"}
```

To fetch the actual archived response, range-request the WARC file:

```
GET https://data.commoncrawl.org/<filename>
Range: bytes=<offset>-<offset+length-1>
```

This retrieves the gzipped WARC record containing the full HTTP response that was captured. Useful when the live URL is gone and you want to recover historical headers / body / forms.

### Stage 5: VirusTotal Domain / URL Intelligence

```
GET https://www.virustotal.com/api/v3/domains/target.example/urls?limit=40
```

Header:
```
x-apikey: <virustotal_api_key>
```

The response contains URLs VT has observed for the domain. Paginate via the `cursor` field returned in `meta.cursor`. Loop for every subdomain.

Other VT endpoints to query:

```
GET /api/v3/domains/target.example/subdomains      # subdomains VT knows
GET /api/v3/domains/target.example/historical_whois
GET /api/v3/domains/target.example/historical_ssl_certificates
GET /api/v3/domains/target.example/resolutions
GET /api/v3/domains/target.example/communicating_files  # files seen sending to/from this domain
GET /api/v3/domains/target.example/downloaded_files     # files served from this domain
GET /api/v3/domains/target.example/referrer_files       # files that reference this domain
```

The `communicating_files` and `downloaded_files` endpoints are particularly interesting — they may reveal that the target hosts an installer/binary/SDK that contained leaked endpoints, debug strings, or hardcoded credentials.

### Stage 6: HackerTarget (free-tier composite)

```
GET https://api.hackertarget.com/sitemap/?q=target.example
GET https://api.hackertarget.com/pagelinks/?q=target.example
GET https://api.hackertarget.com/extracturls/?q=target.example
GET https://api.hackertarget.com/hostsearch/?q=target.example
GET https://api.hackertarget.com/dnshost/?q=target.example
GET https://api.hackertarget.com/reverseiplookup/?q=<known_ip>
GET https://api.hackertarget.com/findshareddns/?q=<known_ip>
```

These endpoints return plain-text line-delimited results. Free tier = 50 queries/day per source IP. The agent must rotate calls or accept the cap.

### Stage 7: DNSDumpster Cross-Reference (passive DNS for archive intel context)

```
POST https://dnsdumpster.com/
form: csrfmiddlewaretoken=<...>&targetip=target.example
```

Returns DNS records (A/MX/TXT/NS) plus a list of hostnames seen historically. Useful for tying archive-discovered URLs back to historical IP infrastructure (an archive URL pointing to a now-dead subdomain may resolve historically to an IP that still hosts the new asset).

### Stage 8: Cross-Archive Dedup, Filter, and Pattern Extraction

After Stages 1-7, the agent has a raw URL list of likely 10K-1M entries (depending on target). Now process:

#### 8a. Canonicalize and dedup

For each URL:
- lowercase the host
- strip trailing slash from path (unless path is `/`)
- sort querystring keys alphabetically (so `?a=1&b=2` and `?b=2&a=1` match)
- drop fragment (`#...`)
- drop tracking parameters: `utm_*`, `fbclid`, `gclid`, `_ga`, `mc_*`, `ref`, `referrer`, `source`, `medium`, `campaign`

Dedup the resulting set.

#### 8b. Filter by status code (Wayback / Common Crawl provide this)

Keep `200`, `301`, `302`, `307`, `308` (live or formerly-live). Discard `404`, `410` (gone). Mark `403` separately — `403` means the URL was real and protected, which is exactly the bug-bounty interesting set.

#### 8c. Endpoint extraction patterns

Bucket each URL by path-pattern signal. The following patterns indicate high-value targets:

| Pattern | Meaning |
|---|---|
| `/api/`, `/api/v[0-9]+/`, `/v[0-9]+/` | REST API endpoint |
| `/graphql`, `/graphiql`, `/_graphql`, `/playground` | GraphQL endpoint |
| `/admin`, `/administrator`, `/cms`, `/wp-admin`, `/admin-panel` | Admin surface |
| `/internal`, `/private`, `/staff`, `/employee`, `/corp` | Internal-only |
| `/_next/`, `/_next/data/`, `/_next/static/` | Next.js — likely SSR API endpoints |
| `/__/`, `/__nuxt/`, `/_nuxt/`, `/_vercel/` | Build-tool paths |
| `/static/`, `/assets/`, `/dist/`, `/build/`, `/public/` | Static asset roots — check for source maps and accidentally-shipped files |
| `*.json`, `*.xml`, `*.swagger`, `*.openapi`, `/openapi.json`, `/swagger.json`, `/docs.json` | Schema / docs |
| `*.map` | Source maps — full source recovery |
| `/healthz`, `/health`, `/ready`, `/metrics`, `/status`, `/server-status`, `/server-info` | Operational endpoints |
| `/.git/`, `/.env`, `/.aws/`, `/.ssh/`, `/dump.sql`, `/backup`, `/.DS_Store` | Sensitive dotfile / backup |
| `/oauth`, `/auth/`, `/login`, `/sso`, `/saml`, `/oidc`, `/.well-known/` | Auth surface |
| `/upload`, `/file`, `/document`, `/attachment`, `/import`, `/export` | File handling |
| `/webhook`, `/callback`, `/notify`, `/event` | Inbound callback |

#### 8d. Parameter mining

Extract every querystring parameter from every URL. Build a frequency map:

```
{
  "id": 4321,
  "user_id": 982,
  "redirect": 411,
  "next": 392,
  "callback": 188,
  "url": 175,
  "file": 102,
  "path": 94,
  "page": 88,
  "filter": 71,
  "sort": 68,
  "debug": 51,
  "test": 42,
  "internal": 31,
  "admin": 22,
  ...
}
```

Output a deduplicated parameter list (high-frequency names first). This list feeds the parameter-discovery skill — fuzz current endpoints with these historical parameter names, since developers often reuse parameter naming conventions and a parameter that appeared on `/api/v1/foo` years ago may still be honored (and unvalidated) on `/api/v3/bar` today.

#### 8e. Cross-reference live state

For each archived URL flagged as high-value:

1. Issue a HEAD request to the live URL.
2. If `200`/`301`/`302`/`307`/`308` — URL is still live; promote to active-test queue.
3. If `403` — promote to access-control bypass queue.
4. If `404`/`410` — record but de-prioritize (path may still be guessable as a base for dirfuzz).
5. If `5xx` — promote to error-induction queue (server-side issue when handling old path).

## Search Operator / Pattern Cookbook

```
# Wayback CDX — find every archived form (POST endpoints often)
url=*.target.example/*&output=json&collapse=urlkey&filter=urlkey:.*(submit|create|update|delete|register|signup|login|reset).*

# Wayback CDX — find every URL with .map (source maps)
url=*.target.example/*&output=json&collapse=urlkey&filter=urlkey:.*\.map$

# Wayback CDX — find every URL with debug-related path
url=*.target.example/*&output=json&collapse=urlkey&filter=urlkey:.*(debug|trace|profiler|console|monitor|metrics).*

# URLScan — find target's external script dependencies (third-party JS imports)
q=domain:target.example AND task.url:*&size=10000  (then parse network log for hostname != target.example in scripts)

# OTX — historical malware findings on the target's domain (rare, but if hit, indicates compromise / deindexed dev hosts)
GET /api/v1/indicators/domain/target.example/malware

# Common Crawl — pull every captured robots.txt (history of disallow paths)
url=target.example/robots.txt&output=json    # one record per crawl, can fetch each WARC

# VirusTotal — communicating files (binaries that contact target.example) — may reveal SDK with leaked endpoints
GET /api/v3/domains/target.example/communicating_files

# HackerTarget extracturls — quick wide scan for any archive
GET /extracturls/?q=target.example
```

## Decision Tree

```
START
  │
  ├── target_apex provided?
  │     └── YES → for every (apex + subdomain) input, run Stage 1 with all 8 filter variants (paginated)
  │
  ├── urlscan_api_key configured?
  │     ├── YES → run Stage 2 with all 5 sweep variants
  │     └── NO  → run Stage 2 with the public search interface (rate-limited but works)
  │
  ├── otx_api_key configured?
  │     ├── YES → run Stage 3 across all 4 OTX endpoints, paginated to has_next=false
  │     └── NO  → record blocker; continue to other stages
  │
  ├── Always → fetch Common Crawl index list, pick latest 4-6 indexes, run Stage 4 paginated
  │
  ├── virustotal_api_key configured?
  │     ├── YES → run Stage 5 across all 7 VT endpoints, paginated
  │     └── NO  → record blocker; continue
  │
  ├── Always → run Stage 6 HackerTarget (rate-limited; queue if cap hit)
  ├── Always → run Stage 7 DNSDumpster
  │
  ├── Always → run Stage 8a-e (cross-archive dedup, status filter, pattern extraction, parameter mining, live-state cross-reference)
  │
  └── Output structured records + parameter list + endpoint pattern bucket
```

DO NOT skip any archive based on yield from another archive. Different archives capture different windows / different observers / different rendering states. A path that is in URLScan but not Wayback frequently exists, and vice versa.

## Pitfalls

- **Archive lag.** Wayback may be 1-90 days behind reality. URLScan sees only URLs someone submitted (so URLs known to humans). Common Crawl is monthly. OTX is event-triggered. None is real-time. The agent must cross-reference with live state in Stage 8e.
- **False positives from removed paths.** A captured URL from 2018 likely doesn't exist today. Status check (Stage 8e) is mandatory before declaring a finding.
- **Authentication gates not captured.** Wayback follows redirects and obeys robots.txt. Many archived pages are post-auth and won't be in archives. Don't assume archive coverage = full surface coverage.
- **Encoding / canonicalization drift.** The same logical URL can appear with different encoding (`%20` vs `+`, `?a=1&b=2` vs `?b=2&a=1`). Stage 8a is essential.
- **Tracking-parameter pollution.** Without stripping `utm_*`/`fbclid`/etc, dedup over-counts. The parameter mining step then surfaces tracking params as if they were real interface params.
- **Rate limits.** Each archive has independent limits. URLScan free tier ~ 100 req/day. VT free tier 500 req/day at 4 req/min. Common Crawl is unmetered but the WARC range fetches add up. HackerTarget free tier is harshest. Plan parallelism and order high-yield archives first.
- **Index-version skew (Common Crawl).** CC changes index ID monthly. An index URL hardcoded in a script becomes stale. Always re-fetch `collinfo.json` at run-time.
- **Fragment / SPA hash routing missed.** Many SPAs use `#/route` for client-side routing — Wayback strips fragments and never indexes per-route. The agent must extract routes from the captured JS bundle (Stage 1 filter 3 → fetch JS → parse routes), not rely on the URL list.
- **WARC offset must be exact.** Common Crawl range fetches MUST use the offset and length from the index record exactly. Off-by-one yields a corrupted gzip stream.
- **Subdomain vs apex queries.** Wayback's `url=*.target.example/*` includes the apex host AND every subdomain. URLScan's `domain:target.example` does NOT include subdomains (use `page.domain` per subdomain). Read each archive's docs once and don't assume parity.
- **Robots-respecting archives.** Some archives respect robots.txt at capture time, so a target with a strict robots.txt has a smaller archive footprint. This means absence of a path in the archive ≠ absence in reality.
- **Censorship / GDPR removals.** A small fraction of URLs are removed from Wayback by takedown request. If the archive history shows a sudden gap with no other explanation, suspect a removal.

## Output Format

Per-URL record:

```json
{
  "url": "https://target.example/api/v1/users/{id}",
  "url_canonical": "target.example/api/v1/users/{id}",
  "archive_sources": ["wayback", "urlscan", "commoncrawl"],
  "first_seen": "2018-03-04T12:00:00Z",
  "last_seen": "2026-03-15T08:00:00Z",
  "status_codes_observed": [200, 401, 403],
  "live_status": 403,
  "mimetype": "application/json",
  "parameters": ["id", "include", "fields", "expand"],
  "path_pattern_bucket": "api_v1",
  "high_value_signal": ["api", "id_param"],
  "warc_offset": null,
  "warc_filename": null,
  "urlscan_uuid": "abcdef-...",
  "screenshot_url": "https://urlscan.io/screenshots/abcdef-....png"
}
```

Aggregate output files:

```
all_urls.txt                # canonical-deduplicated URL list, one per line
parameters_frequency.json   # parameter name → count
parameters_topN.txt         # top 200 parameter names, one per line
endpoints_by_bucket.json    # bucket name → list of URLs
live_promote_queue.txt      # URLs whose live HEAD returned 200/301/302/307/308 — feed to active-test
live_403_queue.txt          # URLs returning 403 live — feed to access-control bypass tests
high_value_paths.txt        # URLs matching the high-value pattern dictionary in 8c
sourcemap_candidates.txt    # archived .map files — fetch live to see if recoverable
oauth_endpoints.txt
graphql_endpoints.txt
admin_endpoints.txt
api_endpoints.txt
```

## Composes With

- `recon_content_discovery` — `parameters_topN.txt` and `endpoints_by_bucket.json` directly become the wordlist input for path/parameter fuzzing on live endpoints.
- `recon_information_disclosure` — archived `.git`, `.env`, dump.sql, backup file paths frequently STILL serve content live; this skill's `sourcemap_candidates.txt` and `high_value_paths.txt` directly feed the disclosure-path enumeration.
- `recon_llm_active_crawl` — archive URLs become seed list for active crawling. The live-status data tells the active crawler which paths are still reachable vs which are 404.
- `recon_passive_subdomain` — archive results expose `<sub>.target.example` strings inside captured HTML/JSON that DNS-only enumeration missed.
- `recon_shodan_dorking` — favicon hashes and SSL cert subjects from Shodan can be cross-referenced against URLScan results to confirm asset ownership.
- `recon_deep_js_analysis` — archived JS bundles (`mimetype:.*javascript`) include older filenames whose source maps may have been left exposed; feed bundle URLs through JS analysis.

## Termination Policy

This skill terminates ONLY when ALL of the following are complete:

1. Stage 1 (Wayback CDX) has executed all 8 filter variants for the apex AND for every subdomain in `target_subdomains[]`. Each query has been paginated to exhaustion (no `resumeKey` returned).
2. Stage 2 (URLScan) has executed all 5 sweep variants for the apex; the per-subdomain query has been issued for every subdomain; the per-IP query has been issued for every IP in `known_ips[]`.
3. Stage 3 (OTX) has executed all 4 endpoints, paginated to `has_next=false`, for the apex AND every subdomain.
4. Stage 4 (Common Crawl) has fetched the latest collinfo.json, selected the 4-6 most recent indexes, and paginated each index for `url=*.target.example/*` to exhaustion.
5. Stage 5 (VirusTotal) has hit all 7 listed endpoints with full pagination via the `cursor` field, for apex AND every subdomain.
6. Stage 6 (HackerTarget) has issued each of the 7 listed endpoints. If the daily cap is hit mid-stage, the agent records the cap-hit and which queries are queued for the next day — the agent does NOT silently abandon the stage.
7. Stage 7 (DNSDumpster) has been run for the apex AND for every subdomain.
8. Stage 8 has been fully executed: dedup → status filter → pattern extraction → parameter mining → live-state cross-reference. Every flagged URL has had its live status checked.
9. All output files listed above are written and non-empty (or explicitly empty with a comment explaining why).

DO NOT terminate early because:
- One archive returns very few results (others may return millions).
- A single archive's API key is missing — degrade to keyless variants where possible and continue.
- The URL list "looks complete" — different archives have orthogonal coverage and the union is always larger than any one source.
- The target appears small — cross-pollination between archives almost always reveals more than direct enumeration suggests.
- Earlier recon found a lot of subdomains — every subdomain still gets its own per-archive sweep.

**Pro Tips (corpus-derived):** Archive-found ZIP/TAR paths are Zip Slip candidates -- test every archive-import feature with canonical path-traversal payloads. Historical `robots.txt` captures reveal Disallow paths that were REMOVED (meaning the content is now accessible but was once protected). VT `communicating_files` reveals binaries/SDKs that contacted the target domain -- these may contain hardcoded endpoints or credentials not visible in any web archive.
