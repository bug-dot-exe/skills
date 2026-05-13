---
name: URL Crawling & Historical Mining
category: reconnaissance
description: Comprehensive URL collection via active crawling (katana/gospider), historical archives (gau/waybackurls/waymore), and parameter extraction
depends_on: []
---

# URL Crawling & Historical Mining

## When to Use
- After live hosts are identified (httpx output)
- To discover endpoints before content fuzzing
- To find forgotten/legacy endpoints still accessible
- To extract parameters for injection testing

## Tool Chain (run in parallel)

### 1. Historical URL Archives

These sources find endpoints that active crawling misses — deleted pages, old API versions, dev endpoints accidentally exposed:

```bash
# gau — aggregates Wayback Machine, CommonCrawl, AlienVault OTX, URLScan
echo "$TARGET" | gau --providers wayback,commoncrawl,otx,urlscan --threads 5 | sort -u > urls_gau.txt

# waybackurls — direct Wayback Machine queries (sometimes finds URLs gau misses)
echo "$TARGET" | waybackurls 2>/dev/null | sort -u > urls_wayback.txt

# waymore — extended Wayback with built-in dedup and response code filtering
# Finds URLs from Wayback, CommonCrawl, VirusTotal, AlienVault
waymore -i "$TARGET" -mode U -oU urls_waymore.txt 2>/dev/null
```

### 2. Active Crawling (JS-rendered)

```bash
# katana — headless Chrome crawl, catches SPA routes invisible to curl
katana -u "$TARGET" -d 3 -jc -kf all -silent -o crawl_katana.txt

# gospider — fast link extraction with external source integration
gospider -s "$TARGET" -d 2 --other-source --include-subs -q | sort -u > crawl_gospider.txt

# hakrawler — lightweight alternative (if others unavailable)
echo "$TARGET" | hakrawler -d 2 -plain 2>/dev/null | sort -u > crawl_hakrawler.txt
```

### 3. Merge & Decompose

```bash
# Merge all sources
cat urls_gau.txt urls_wayback.txt urls_waymore.txt \
    crawl_katana.txt crawl_gospider.txt crawl_hakrawler.txt 2>/dev/null | \
  sort -u > all_urls.txt

# Deduplicate with uro (removes redundant URL variations)
cat all_urls.txt | uro 2>/dev/null > all_urls_deduped.txt || cp all_urls.txt all_urls_deduped.txt

# Extract components
cat all_urls_deduped.txt | unfurl -u paths 2>/dev/null | sort -u > unique_paths.txt
cat all_urls_deduped.txt | unfurl -u keys 2>/dev/null | sort -u > unique_params.txt
cat all_urls_deduped.txt | unfurl -u domains 2>/dev/null | sort -u > unique_domains.txt

# Filter interesting files
grep -iE "\.(js|json|xml|yml|yaml|env|bak|old|sql|log|conf|cfg|ini|properties|toml)$" \
  all_urls_deduped.txt > interesting_files.txt
grep -iE "\.(zip|tar|gz|7z|rar|dump|sql|csv)$" all_urls_deduped.txt > potential_backups.txt
```

### 4. Convert to Custom Wordlist for ffuf

```bash
# Historical paths become your best custom wordlist
# These are REAL paths that existed on the target — not generic guesses
cat unique_paths.txt | sed 's|^/||' > custom_wordlist.txt

# Combine with JS-extracted endpoints
cat js_endpoints.txt >> custom_wordlist.txt 2>/dev/null
sort -u -o custom_wordlist.txt custom_wordlist.txt

# Run ffuf with your target-aware wordlist
ffuf -u "$TARGET/FUZZ" -w custom_wordlist.txt \
  -mc 200,201,301,302,401,403,405,500 -t 30
```

### 5. Parameter Mining

```bash
# Parameters from historical URLs are high-value — the target actually used them
echo "=== Parameters discovered from historical URLs ==="
cat all_urls_deduped.txt | grep "?" | unfurl -u keypairs 2>/dev/null | sort | uniq -c | sort -rn | head -30

# High-value parameter patterns (test these for injection)
cat all_urls_deduped.txt | grep -oiE "(id|user_id|uid|redirect|url|file|path|cmd|query|search|template|callback|next|return|token)=[^&]*" | \
  sort | uniq -c | sort -rn | head -20
```

## Corpus-Derived Hunting Patterns

### Cloud Storage URL Extraction

Inspect every web app response (HTML, JSON, image/file links) for direct cloud-storage URLs:
- `https://*.s3.amazonaws.com/*`, `s3://*`
- `https://storage.googleapis.com/*`, `gs://*`
- `https://*.blob.core.windows.net/*`
If found, test: unauthenticated read, directory listing (append `?prefix=&delimiter=/`), write (PUT a test object). Cloud storage URLs discovered in historical archives are especially valuable -- the bucket may still exist with weaker permissions than the current app path.

### URL-Fetching Feature SSRF Discovery

For every URL discovered that contains a `url=`, `src=`, `fetch=`, `load=`, or `proxy=` parameter:
1. Test 6 layers of bypass before declaring it safe: direct internal IP, DNS rebinding, URL scheme confusion (`file://`, `gopher://`, `dict://`), redirect chain, IPv6 mapped addresses, and parser-specific tricks
2. Framework "convenience" features (auto-URL resolution, automatic JSON parsing from URLs) are an SSRF supply chain -- the developer may not realize the framework fetches user-controlled URLs server-side

### Validate-and-Use Mismatch Detection

When crawling reveals URLs that pass through a validation step before use:
1. Map the validation logic (regex, URL parser, allowlist)
2. Map the consumption logic (fetch, redirect, render)
3. If validation and consumption use DIFFERENT parsers, craft inputs that pass validation but are interpreted differently at consumption time
This pattern (parser differential) has produced $62K+ XSS bounties.

### Static Asset Path LFI Testing

Historical URL archives often reveal static-asset serving paths (`/static/`, `/assets/`, `/public/`). These paths are classic LFI surfaces that modern audits skip because they assume static handlers are safe. Test:
1. Path traversal: `/static/../../../etc/passwd`
2. Null-byte truncation on older stacks: `/static/file%00.html`
3. Encoding bypasses: double-encode, unicode normalization

### Archive Upload Path Traversal

For every URL path that suggests archive upload or import (ZIP, TAR, DOCX, XLSX):
1. Craft a test archive with `../` in the internal file paths (Zip Slip)
2. Upload and check whether extracted files land outside the expected directory
3. Test both the import UI and any API endpoint that accepts the same archive format

### Routing-Layer Character Fuzzing

When crawled URLs show routing inconsistencies (different responses for slight path variations), fuzz with unusual characters:
- `@`, `\`, `;`, `..`, `%00`, `%2f`, leading `-` in URL paths
- Monitor error responses for routing-layer signatures (nginx, Apache, cloud LB)
- Different error pages from the same host suggest multiple backends with parser differentials -- an HTTP request smuggling opportunity

### Authenticated Media Endpoint Exfiltration

For every authenticated media endpoint discovered in crawling (images, recordings, documents served via cookie auth):
1. Test whether the endpoint can be embedded cross-origin via `<img>`, `<audio>`, `<video>` tags
2. If embeddable, an attacker page can detect presence/absence of media (timing, load event, dimensions)
3. If the media endpoint accepts enumerable IDs, this becomes a brute-force data exfiltration primitive

## What Each Tool Finds That Others Miss

- **gau**: CommonCrawl + OTX URLs not in Wayback
- **waybackurls**: Raw Wayback snapshots, includes more historical depth
- **waymore**: Deduped superset + VirusTotal URLs
- **katana**: JS-rendered SPA routes, dynamic content, form actions
- **gospider**: Sitemap.xml, robots.txt links, external JS sources

## Key Insight

Historical URLs alone reveal 2-5x more endpoints than active crawling. Run `gau` first -- it's passive (no WAF triggers), fast, and finds endpoints the target may have removed but not secured.
