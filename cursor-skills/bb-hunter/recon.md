# Recon Reference

Recon is continuous, not a one-time phase. The goal is not data — it's finding the asset nobody else is looking at.

## bbrecon (Preferred)

When the project has **bbrecon**, use it as the primary pipeline:

```bash
./bbrecon run -d target.com
```

**Key output paths** (under `output/<target>/`):

| Path | Use |
|------|-----|
| `LIVE/httpx.urls` | Crawl targets, param discovery input |
| `ACTIVE/JUICY/juicy.focus.live.txt` | Prioritized live URLs — start here |
| `ACTIVE/API/graphql_found.txt` | GraphQL endpoints |
| `ACTIVE/API/oauth_found.txt` | OAuth/OIDC discovery |
| `ACTIVE/PARAMS/all.params.txt` | Param URLs for IDOR/SSRF/XSS |
| `CRAWLING/all.crawled.urls` | Crawled URL surface |
| `JS/all.endpoints.urls` | Endpoints from JS bundles |

**Extend with bbrecon skills** when needed: `bbrecon-subdomain-deep`, `bbrecon-api-discovery`, `bbrecon-scope-expansion`, `bbrecon-parameter-discovery`. See [bbrecon-integration.md](bbrecon-integration.md).

---

## Asset Discovery (Manual)

### Subdomain Enumeration
```bash
# Passive (multiple sources)
subfinder -d target.com -all -o subs_passive.txt
amass enum -passive -d target.com -o subs_amass.txt
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u >> subs_passive.txt

# Active brute-force
puredns bruteforce wordlist.txt target.com -r resolvers.txt -o subs_brute.txt

# Permutation (finds staging-api, dev-internal, etc.)
gotator -sub subs_passive.txt -perm permutations.txt -depth 1 | puredns resolve -r resolvers.txt

# Merge and dedupe
cat subs_passive.txt subs_amass.txt subs_brute.txt | sort -u > all_subs.txt
```

### ASN & Reverse IP Lookup
```bash
# Find ASN for the target
whois -h whois.radb.net -- "-i origin $(whois target.com | grep -i origin | awk '{print $NF}')" | grep route

# Reverse IP — find other domains on same server
curl -s "https://api.hackertarget.com/reverseiplookup/?q=1.2.3.4"

# BGP/ASN range discovery
amass intel -asn 12345 -o asn_ranges.txt
```

### Cloud Range Discovery
```bash
# S3 bucket enumeration
s3scanner scan --bucket-file wordlist.txt
cloud_enum -k target -k targetcorp

# Azure blobs
python3 cloud_enum.py -k target --azure

# GCP buckets
gsutil ls gs://target-backup 2>/dev/null
```
Also check: `target-dev`, `target-staging`, `target-backup`, `target-logs`, `target-uploads`, `targetcorp`, company acquisitions.

### OSINT: Acquisitions & Mergers
When BigCorp acquires StartupCo, StartupCo's infra stays on original stack for years. Nobody patches it. It's in scope. Check Crunchbase, press releases, WHOIS history.

### Favicon Hash Search
```bash
# Calculate favicon hash, search Shodan for other hosts using same favicon
curl -s https://target.com/favicon.ico | python3 -c "import mmh3,sys,codecs; print(mmh3.hash(codecs.encode(sys.stdin.buffer.read(),'base64')))"
# Search: shodan.io → http.favicon.hash:<hash>
```
Finds staging servers, internal tools, forgotten instances running same app.

## Resolution & Probing

```bash
# DNS resolution
cat all_subs.txt | dnsx -silent -a -resp -o resolved.txt

# DNS zone transfer (often overlooked, occasionally works)
dig axfr @ns1.target.com target.com

# HTTP probing with tech detection
cat resolved.txt | httpx -title -tech-detect -status-code -follow-redirects -o live.txt

# Port scanning
naabu -list resolved.txt -top-ports 1000 -o ports.txt
# Deep scan on interesting hosts
nmap -sV -sC -p- -T4 target_host
```

## Analysis

### Screenshots
```bash
gowitness file -f live.txt --screenshot-path screenshots/
# ACTUALLY LOOK AT THEM — notice staging servers, admin panels, different tech stacks
# Sort by visual similarity to spot duplicates vs unique apps
```

### Content Discovery
```bash
# Wordlist selection matters more than tool
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302,403 -recursion -recursion-depth 2

# Multiple wordlists: SecLists, assetnote, target-specific from JS analysis
# 403 responses are interesting — try bypass: path traversal, HTTP method change, header injection
```

### JavaScript Analysis (Static + Dynamic)
Consistently one of the highest-value recon activities. Two approaches: endpoint extraction and deep static analysis.

#### Endpoint Extraction
```bash
# Extract endpoints from JS bundles
linkfinder -i https://target.com -d -o endpoints.txt
# Also: getJS to download all JS, then grep for patterns
getJS --url https://target.com --complete | tee js_files.txt
cat js_files.txt | xargs -I{} linkfinder -i {} -o cli
```

#### Deep JS Static Analysis (JXScout-style)

Crawl the target, download every JS file, beautify, and run pattern matching against a security-focused ruleset. This is a dedicated analysis pass, not just grepping — it finds DOM sinks, hardcoded secrets, debug endpoints, and internal paths that endpoint extractors miss.

**What to scan for (by severity):**

| Severity | Pattern Category | Examples |
|----------|-----------------|----------|
| CRITICAL | Hardcoded credentials | `aws_secret_access_key`, `AKIA...`, Firebase `apiKey` + `authDomain` combo, Stripe `sk_live_` |
| HIGH | DOM sinks with user input | `innerHTML` assigned from URL params, `document.write()` with `location.hash`, `eval()` with user data |
| HIGH | Debug/admin endpoints | `/debug/`, `/actuator/`, `/__admin`, `/graphiql`, `/_internal/` in route definitions |
| MEDIUM | API routes not in UI | Routes defined in JS but not linked from any page — hidden functionality |
| MEDIUM | Internal hostnames | `internal-api.corp.target.com`, `10.x.x.x`, staging/dev URLs |
| LOW | Developer comments | `TODO: remove before prod`, `HACK:`, `FIXME: auth bypass`, `temp password` |

**Noise control** — JS analysis generates massive output. Three layers to keep signal high:
1. **Severity filter** — only alert on HIGH+ matches. INFO/LOW log silently for manual review
2. **Dedup** — hash(`file + line + category`), skip if seen before
3. **Rate limit** — max 5 alerts per minute per target. Buffer overflow into batch send

```bash
# Manual JS analysis pipeline
getJS --url https://target.com --complete --output js_files/
# Beautify for readability
for f in js_files/*.js; do js-beautify -f "$f" -o "${f%.js}.pretty.js"; done

# Scan for secrets
grep -rEiH "(api_key|apikey|secret|password|firebase|stripe|admin|internal|staging|debug)" js_files/
grep -rEH "AKIA[0-9A-Z]{16}" js_files/
grep -rEH "sk_live_[a-zA-Z0-9]{24}" js_files/

# Scan for DOM sinks
grep -rEH "(innerHTML|outerHTML|document\.write|\.html\(|eval\(|setTimeout\(.*\+|Function\()" js_files/

# Scan for hidden routes
grep -rEH "(path:\s*['\"]\/|route\(['\"]\/|router\.(get|post|put|delete)\(['\"]\/)" js_files/

# Scan for internal URLs
grep -rEH "(localhost|127\.0\.0\.1|10\.\d+|172\.(1[6-9]|2\d|3[01])|192\.168|\.internal\.|\.corp\.)" js_files/
```

**Integration with passive workflows:** When Caido captures JS responses, passive workflows can trigger JXScout-style analysis automatically. DOM sink detections feed into the taint tracing pipeline — see [caido-integration.md](caido-integration.md) for the full flow.

### Parameter Discovery
```bash
# Hidden parameters not in HTML
arjun -u https://target.com/endpoint -m GET POST
# Burp Param Miner / Caido equivalent for in-proxy discovery

# Wordlist-based param fuzzing
ffuf -u "https://target.com/api/endpoint?FUZZ=value" -w params.txt -mc 200 -fs <baseline_size>
```

### API Endpoint Discovery
- Look for `/api/`, `/v1/`, `/v2/`, `/graphql`, `/rest/`, `/ws/` paths
- GraphQL introspection: `{__schema{types{name,fields{name}}}}`
- Mobile app traffic: proxy through Caido, capture all API calls
- Swagger/OpenAPI: `/swagger.json`, `/api-docs`, `/.well-known/openapi`, `/openapi.yaml`
- Look for API versioning — old versions (`/v1/`) often lack newer security controls

### Shodan / Censys / FOFA Dorking
```
# Shodan
hostname:"target.com"
ssl.cert.subject.cn:"target.com"
http.favicon.hash:<hash>
org:"Target Corp"

# Censys
services.tls.certificates.leaf.names: target.com
services.http.response.headers.server: "unusual-server"

# FOFA
host="target.com"
cert="target.com"
```
Finds: forgotten servers, non-standard ports, internal tools exposed to internet, staging/dev with same SSL cert.

### GitHub / GitLab / Postman Dorking
```
# GitHub — credentials and secrets
"target.com" password OR secret OR api_key OR token
org:targetorg filename:.env
org:targetorg extension:json "password"
org:targetorg "staging" OR "internal" OR "dev"
org:targetorg filename:config extension:yml

# GitLab (if target uses it)
# Search target's GitLab instance: gitlab.target.com/search?search=password&scope=blobs

# Postman public workspaces
# Search: postman.com/search?q=target.com
# Collections often contain: full API docs, auth tokens, internal endpoints, test credentials

# Trello public boards
site:trello.com "target.com"
```

### Wayback Machine Mining
```bash
# Endpoints removed from UI often still functional on backend
waybackurls target.com | sort -u > wayback_all.txt
cat wayback_all.txt | grep -E "\.(json|xml|js|php|asp|aspx)" > wayback_endpoints.txt
cat wayback_all.txt | grep -E "(api|admin|internal|debug|test|staging)" > wayback_interesting.txt
# Test each — "deleted" features are often just hidden from the UI
```

## Continuous Monitoring

```bash
# Diff against previous runs
diff <(sort old_subs.txt) <(sort new_subs.txt) | grep "^>" > new_assets.txt

# Alert on new assets → immediately test them (nobody else has seen them yet)
# Auto-scan new assets with Nuclei custom templates
nuclei -l new_assets.txt -t custom-templates/ -severity medium,high,critical

# Monitor certificate transparency logs for new subdomains
# sublert, certstream, or crt.sh polling on cron
```

Set up cron jobs or use tools like `notify` to alert on new findings. The researcher who sees the new subdomain first usually gets the bounty.

## Source
https://bugbounty.info/Recon/
