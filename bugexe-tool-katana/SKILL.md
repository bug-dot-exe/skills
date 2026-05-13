---
name: katana
description: Katana crawler syntax, depth/js/known-files behavior, and stable concurrency controls.
depends_on: []
---

# Katana CLI Playbook

Official docs:
- https://docs.projectdiscovery.io/opensource/katana/usage
- https://docs.projectdiscovery.io/opensource/katana/running
- https://github.com/projectdiscovery/katana

Canonical syntax:
`katana [flags]`

High-signal flags:
- `-u, -list <url|file>` target URL(s)
- `-d, -depth <n>` crawl depth
- `-jc, -js-crawl` parse JavaScript-discovered endpoints
- `-jsl, -jsluice` deeper JS parsing (memory intensive)
- `-kf, -known-files <all|robotstxt|sitemapxml>` known-file crawling mode
- `-proxy <http|socks5 proxy>` explicit proxy setting
- `-c, -concurrency <n>` concurrent fetchers
- `-p, -parallelism <n>` concurrent input targets
- `-rl, -rate-limit <n>` request rate limit
- `-timeout <seconds>` request timeout
- `-retry <n>` retry count
- `-ef, -extension-filter <list>` extension exclusions
- `-tlsi, -tls-impersonate` experimental JA3/TLS impersonation
- `-hl, -headless` enable hybrid headless crawling
- `-sc, -system-chrome` use local Chrome for headless mode
- `-ho, -headless-options <csv>` extra Chrome options (for example proxy-server)
- `-nos, -no-sandbox` run Chrome headless with no-sandbox
- `-noi, -no-incognito` disable incognito in headless mode
- `-cdd, -chrome-data-dir <dir>` persist browser profile/session
- `-xhr, -xhr-extraction` include XHR endpoints in JSONL output
- `-silent`, `-j, -jsonl`, `-o <file>` output controls

Agent-safe baseline for automation:
`mkdir -p crawl && katana -u https://target.tld -d 3 -jc -kf robotstxt -c 10 -p 10 -rl 50 -timeout 10 -retry 1 -ef png,jpg,jpeg,gif,svg,css,woff,woff2,ttf,eot,map -silent -j -o crawl/katana.jsonl`

Common patterns:
- Fast crawl baseline:
  `katana -u https://target.tld -d 3 -jc -silent`
- Deeper JS-aware crawl:
  `katana -u https://target.tld -d 5 -jc -jsl -kf all -c 10 -p 10 -rl 50 -o katana_urls.txt`
- Multi-target run with JSONL output:
  `katana -list urls.txt -d 3 -jc -silent -j -o katana.jsonl`
- Headless crawl with local Chrome:
  `katana -u https://target.tld -hl -sc -nos -xhr -j -o crawl/katana_headless.jsonl`
- Headless crawl through proxy:
  `katana -u https://target.tld -hl -sc -ho proxy-server=http://127.0.0.1:48080 -j -o crawl/katana_proxy.jsonl`

Critical correctness rules:
- `-kf` must be followed by one of `all`, `robotstxt`, or `sitemapxml`.
- Use documented `-hl` for headless mode.
- `-proxy` expects a single proxy URL string (for example `http://127.0.0.1:8080`).
- `-ho` expects comma-separated Chrome options (example: `-ho --disable-gpu,proxy-server=http://127.0.0.1:8080`).
- For `-kf`, keep depth at least `-d 3` so known files are fully covered.
- If writing to a file, ensure parent directory exists before `-o`.

Usage rules:
- Keep `-d`, `-c`, `-p`, and `-rl` explicit for reproducible runs.
- Use `-ef` early to reduce static-file noise before fuzzing.
- Prefer `-proxy` over environment proxy variables when proxying only Katana traffic.
- Use `-hc` only for one-time diagnostics, not routine crawling loops.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

Failure recovery:
- If crawl runs too long, lower `-d` and optionally add `-ct`.
- If memory spikes, disable `-jsl` and lower `-c/-p`.
- If headless fails with Chrome errors, drop `-sc` or install system Chrome.
- If output is noisy, tighten scope and add `-ef` filters.

If uncertain, query web_search with:
`site:docs.projectdiscovery.io katana <flag> usage`

## Corpus-Derived Advanced Techniques

### Cloud Storage URL Extraction

Crawl responses for direct cloud-storage URLs that may have misconfigured ACLs:
```bash
katana -u https://target.tld -d 5 -jc -jsl -kf all -j -o crawl/katana_full.jsonl -silent -c 10 -rl 50
# Extract cloud storage URLs from crawl output
cat crawl/katana_full.jsonl | jq -r '.response.body // empty' | \
  grep -oE 'https?://[a-zA-Z0-9.-]+(\.s3[.-][a-z0-9-]+\.amazonaws\.com|\.storage\.googleapis\.com|\.blob\.core\.windows\.net)[^ "'"'"']*' \
  | sort -u > cloud_buckets.txt
```
Every discovered bucket URL is a lead for anonymous list/read/write ACL testing.

### XSSI Detection via Cookie-Dependent JS Responses

Crawl all JS endpoints and compare authenticated vs anonymous responses:
```bash
# Authenticated crawl
katana -u https://target.tld -d 3 -jc -H 'Cookie: session=AUTH_TOKEN' \
  -j -o crawl/auth.jsonl -silent -c 10 -rl 50
# Anonymous crawl
katana -u https://target.tld -d 3 -jc \
  -j -o crawl/anon.jsonl -silent -c 10 -rl 50
# Diff: JS responses that differ between auth/anon contain user-specific data (XSSI candidates)
```

### XS-Leak Status-Code Probing

Discover endpoints that return different status codes based on authentication state:
```bash
katana -u https://target.tld -d 3 -jc -j -o crawl/katana.jsonl -silent
# Extract all discovered URLs, then probe status codes with/without auth
cat crawl/katana.jsonl | jq -r '.url' | sort -u > all_urls.txt
# Feed to httpx for authenticated vs anonymous status comparison
```
Endpoints that 200 for authed users and 403 for others can be used for deanonymization via cross-site resource inclusion.

### API Content-Type Sweep for Stored XSS

Crawl API endpoints and check for missing Content-Type or content-type sniffing:
```bash
katana -u https://api.target.tld -d 3 -jc -xhr -j -o crawl/api_crawl.jsonl -silent -c 10 -rl 50
# Check each API response for text/html or missing Content-Type
cat crawl/api_crawl.jsonl | jq -r 'select(.response.headers["content-type"] // "" | test("text/html|^$"))' > xss_candidates.jsonl
```
API endpoints returning `text/html` or no Content-Type header that also reflect user input are stored XSS vectors.

### Broken Link and Domain Takeover Sweep

Crawl documentation and marketing sites for external links with expired registrations:
```bash
katana -u https://docs.target.tld -d 5 -jc -kf all -j -o crawl/docs.jsonl -silent -c 10 -rl 50
# Extract external links
cat crawl/docs.jsonl | jq -r '.url' | grep -vE 'target\.tld' | sort -u > external_links.txt
# Check domain registration status
cat external_links.txt | cut -d/ -f3 | sort -u | while read d; do
  whois "$d" 2>/dev/null | grep -qi 'no match\|not found\|available' && echo "TAKEOVER: $d"
done
```
Also check: GitHub user/org names, npm package names, Docker Hub repos referenced in docs.

### Redirect Parameter Enumeration

Extract all URL-shaped parameters from crawl output for open redirect and SSRF testing:
```bash
katana -u https://target.tld -d 3 -jc -j -o crawl/katana.jsonl -silent
# Extract parameters with URL-like names
cat crawl/katana.jsonl | jq -r '.url' | grep -oE '[?&](next|redirect|url|return|continue|callback|dest|goto|target|path|ref|link)=[^&]*' | sort -u > redirect_params.txt
```

### Path Segment Injection Discovery

Identify dynamic path segments for injection testing:
```bash
katana -u https://target.tld -d 3 -jc -j -o crawl/katana.jsonl -silent
# Find paths with numeric/uuid segments (injectable candidates)
cat crawl/katana.jsonl | jq -r '.url' | grep -oE '/[0-9]+/|/[a-f0-9-]{36}/' | sort -u > path_segments.txt
```
Each dynamic path segment is a candidate for SQLi, IDOR, and path traversal testing.

### Rate-Limit Absence Detection

Identify state-changing endpoints that lack rate limiting:
```bash
katana -u https://target.tld -d 3 -jc -xhr -j -o crawl/katana.jsonl -silent
# Extract POST/PUT/DELETE endpoints from XHR data
cat crawl/katana.jsonl | jq -r 'select(.method != "GET") | .url' | sort -u > mutation_endpoints.txt
```
Each mutation endpoint should be tested for rate limiting by replaying the same request rapidly.
