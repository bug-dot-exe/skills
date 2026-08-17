---
name: wayback-cdx-dorking
category: reconnaissance
description: Archive.org Wayback Machine + CDX API + URLScan.io historical search for dead endpoints, deprecated APIs, forgotten parameters, and old JS source with leaked secrets
depends_on: []
---

# Wayback / CDX Dorking

The internet never forgets. Endpoints that the target deprecated last year still exist in the Internet Archive, sometimes still functional on the live server. Old JavaScript bundles contain secrets that were rotated in HEAD but are still live. Deleted admin pages' URLs reveal backend structure even if the pages are gone.

Historical recon finds bugs that live recon cannot.

## When to Use

- Always during initial recon on any web target
- After finding a modern endpoint — look for its predecessor (may have weaker auth)
- Hunting for deprecated API versions still running (`/api/v1/` after v2 was shipped)
- Looking for old JavaScript bundles with leaked secrets, old base URLs, feature flags
- Searching for parameters the target no longer uses publicly but still accepts server-side
- Finding admin / debug pages that were removed from the UI but not from the server

## Methodology

### Phase 1: Broad Historical Snapshot

1. Pull the complete CDX index for the target domain
2. Identify unique URL patterns, parameter names, and subdirectories
3. Flag URLs that no longer exist on live server (they may still be accessible, just unlinked)
4. Compare old vs new deployments — missing endpoints often reveal architecture changes

### Phase 2: Parameter Mining

Historical URLs are a goldmine for parameter discovery:

1. Extract all `?param=value` patterns from CDX results
2. Deduplicate parameter names across time
3. Test each parameter on the live server — many are accepted even if no longer exposed
4. Parameters named `debug`, `test`, `admin`, `internal`, `bypass` are high-value

### Phase 3: Historical JavaScript Analysis

Old JS bundles often leak what current ones don't:

1. Download every unique `.js` file from CDX (takes minutes, worth it)
2. Grep for secrets: `AKIA`, `sk_live`, `Bearer `, `api.*key`, `firebase`
3. Look for commented-out endpoints / feature flags
4. Extract original base URLs — may point to deprecated-but-live backends

### Phase 4: Dead Endpoint Revival

For every dead URL found:

1. Request the live server — does it 404, 500, or return content?
2. 500 errors often reveal stack traces with useful info
3. 403 means the endpoint still exists; look for auth bypass
4. 302 redirects may reveal new paths or session handling quirks

### Phase 5: Historical Subdomain Discovery

The CDX index is also an excellent subdomain source:

1. Query for `*.target.com` — returns all subdomains that hosted any content
2. Many subdomains exist historically that don't appear in modern passive sources
3. Legacy subdomains often have weaker security (stale WordPress, old auth)

## Key Queries

### Wayback CDX API

The CDX API is the programmatic interface to the Internet Archive. Free, no key required, rate limits are generous.

```bash
# All archived URLs for a domain (may be huge — add --limit)
curl -s "https://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=json&fl=original&collapse=urlkey&limit=10000" | jq -r '.[1:] | .[] | .[0]' | sort -u > wayback_urls.txt

# Unique endpoints only (dedupe + sort)
curl -s "https://web.archive.org/cdx/search/cdx?url=target.com/*&output=json&fl=original&collapse=urlkey" \
  | jq -r '.[1:] | .[] | .[0]' | sort -u > target_cdx.txt

# URLs with query parameters (for parameter discovery)
curl -s "https://web.archive.org/cdx/search/cdx?url=target.com/*&output=json&fl=original&filter=statuscode:200&collapse=urlkey" \
  | jq -r '.[1:] | .[] | .[0]' | grep '?' > target_cdx_with_params.txt

# Only JavaScript files (for JS mining)
curl -s "https://web.archive.org/cdx/search/cdx?url=target.com/*.js&output=json&fl=original&collapse=digest" \
  | jq -r '.[1:] | .[] | .[0]' | sort -u > target_js_urls.txt

# Status-code filter (only successful responses)
curl -s "https://web.archive.org/cdx/search/cdx?url=target.com/*&filter=statuscode:200&output=json&fl=original,timestamp,statuscode&collapse=urlkey"

# Date-range filter (deployment-change detection)
curl -s "https://web.archive.org/cdx/search/cdx?url=target.com/*&from=20230101&to=20240101&output=json&fl=original&collapse=urlkey"
```

### waybackurls CLI (ProjectDiscovery)

```bash
# All historical URLs for a domain
echo "target.com" | waybackurls > wayback.txt

# Multiple domains in parallel
cat domains.txt | waybackurls | sort -u > all_wayback.txt

# Combine with gau (GetAllUrls) for broader coverage
echo "target.com" | gau --providers wayback,commoncrawl,otx,urlscan > all_urls.txt

# Filter for interesting extensions
cat wayback.txt | grep -E "\.(json|xml|yml|conf|env|bak|old|sql|log|js\.map)$"
```

### Parameter extraction from CDX data

```bash
# Extract all unique query parameter NAMES
cat target_cdx.txt | grep -oP '\?[^"]*' | tr '&' '\n' | cut -d= -f1 | sort -u > params.txt

# Extract parameter=value pairs for inspiration
cat target_cdx.txt | grep -oP '\?[^"]*' | tr '&' '\n' | sort -u > param_samples.txt

# Top N most-used parameters (paramspider / unfurl style)
cat target_cdx.txt | unfurl format %q | tr '&' '\n' | cut -d= -f1 | sort | uniq -c | sort -rn | head -50
```

### URLScan.io historical search

URLScan captures full DOM + screenshots of every crawled page. Indexes searchable.

```bash
# All scans that touched the target
curl -s "https://urlscan.io/api/v1/search/?q=domain:target.com&size=10000" \
  | jq -r '.results[] | .page.url' | sort -u > urlscan_urls.txt

# Scans that returned specific error pages
curl -s "https://urlscan.io/api/v1/search/?q=domain:target.com AND page.status:500" | jq .

# Find subdomains from DOM-discovered URLs (often finds more than DNS)
curl -s "https://urlscan.io/api/v1/search/?q=domain:target.com&size=10000" \
  | jq -r '.results[] | .page.domain' | sort -u
```

### CommonCrawl index (complementary to Wayback)

```bash
# Get latest CC index URL
LATEST=$(curl -s https://index.commoncrawl.org/collinfo.json | jq -r '.[0]."cdx-api"')

# Query CC for target URLs (syntax similar to Wayback)
curl -s "${LATEST}?url=*.target.com&output=json&fl=url&limit=1000"
```

### Google cache / cachedview

Not historical per se but useful for recently-deleted content:

```
# Google cache (becoming unreliable but still works for some pages)
cache:target.com/admin

# Bing cache via cachedview.com (manual visit)
# https://cachedview.com/
```

## What to Look For

**Deprecated APIs Still Live**
- `/api/v1/*` endpoints after v2 was announced
- Internal admin routes that were removed from the frontend but not the backend
- OAuth endpoints with weaker security from pre-migration era
- GraphQL endpoints with introspection still enabled on old versions

**Parameter Discovery**
- Parameters named `debug`, `test`, `admin`, `role`, `is_admin`, `bypass_captcha`, `feature_*`
- Parameters with values that look like UUIDs or hashes (privilege escalation candidates)
- Parameters accepted on some endpoints but documented on none

**Historical JavaScript**
- Old API base URLs hard-coded into frontend bundles
- Feature flag values (may unlock features currently gated)
- AWS / GCP / Azure credentials that were rotated-in-HEAD but not in deployed JS
- Internal hostnames referenced in `<script>` src attributes
- `.map` source maps (complete original source code)

**Architecture Intelligence**
- Old admin panel URLs (e.g., `/admin-v1/`, `/beta-console/`, `/internal/`)
- Webhook URLs with embedded tokens
- Third-party integration endpoints that reveal partner relationships
- Error pages with stack traces or framework versions

## Validation

1. Always request the endpoint fresh — archived 200s may now 404
2. Compare response body between archive and live — if different, the endpoint changed
3. Unauthenticated archive access doesn't mean current endpoint is unauthenticated
4. Some endpoints are archived from logged-in sessions — you won't have the same view
5. Report with the archive URL + the live verification (curl command + response)

## Tips

1. **Always** run this skill first — it takes 30 seconds and shapes the rest of the hunt
2. Chain CDX output into `ffuf` with `-w` to fuzz every historical path against the live server
3. For each old JS file: run `SecretFinder` / `LinkFinder` on the downloaded bundle
4. Wildcard the target domain: `*.target.com/*` captures more than `target.com/*`
5. The `collapse=urlkey` parameter dedupes — skip it if you want every snapshot (each revision)
6. CDX is faster than scraping Wayback HTML — always use the API
7. Combine with `gau` for multi-source historical URL collection
8. Archive your own findings with `curl -s "https://web.archive.org/save/$URL"` so the program can't make them disappear
