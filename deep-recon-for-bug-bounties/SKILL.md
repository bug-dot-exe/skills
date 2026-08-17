---
name: deep-recon-for-bug-bounties
category: reconnaissance
description: Multi-layer deep reconnaissance with parallel tool chains, historical URL mining, JS intelligence, and endpoint scoring
depends_on: []
---

# Deep Recon for Bug Bounties

## When to Use
- Bug bounty targets with broad scope (*.target.com)
- New programs where attack surface is unknown
- When fast_recon found the target is alive but you need full coverage

## Methodology: 6-Layer Recon Pyramid

### Layer 1: Subdomain Enumeration (run ALL in parallel)

```bash
# subfinder — passive multi-source
subfinder -d $DOMAIN -all -recursive -silent -o subs_subfinder.txt &

# Certificate Transparency (crt.sh)
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | \
  python3 -c "import sys,json;[print(x['name_value']) for x in json.load(sys.stdin)]" | \
  sed 's/\*\.//g' | sort -u > subs_crt.txt &

# Historical URL extraction (gau finds subdomains in Wayback/CommonCrawl)
echo $DOMAIN | gau --subs --providers wayback,commoncrawl,otx,urlscan 2>/dev/null | \
  unfurl -u domains 2>/dev/null | sort -u > subs_gau.txt &

# DNS brute-force (top subdomains)
for sub in www api app dev staging test qa admin portal dashboard \
  mail smtp ftp vpn cdn static assets upload docs wiki internal \
  beta demo sandbox auth sso login graphql ws jenkins jira git \
  gitlab ci deploy monitor metrics grafana kibana elastic debug; do
  host "$sub.$DOMAIN" 2>/dev/null | grep -q "has address" && echo "$sub.$DOMAIN"
done > subs_brute.txt &

wait
cat subs_*.txt | sort -u > all_subdomains.txt
echo "[+] $(wc -l < all_subdomains.txt) unique subdomains"
```

### Layer 2: Live Hosts + Tech Fingerprinting

```bash
httpx -l all_subdomains.txt -silent -status-code -title -tech-detect \
  -follow-redirects -random-agent -o live_hosts.json -json

# Non-standard ports (8080, 8443, 3000, 9090)
naabu -l all_subdomains.txt -top-ports 1000 -silent -o open_ports.txt
cat open_ports.txt | httpx -silent -status-code -title -tech-detect -json >> live_hosts.json
```

Tech stack from httpx drives wordlist selection in Layer 5.

### Layer 3: Historical URL Mining (the gold mine)

Every forgotten endpoint is a potential vulnerability:

```bash
# gau — Wayback, CommonCrawl, AlienVault OTX, URLScan
echo "$TARGET" | gau --providers wayback,commoncrawl,otx,urlscan --threads 5 | sort -u > urls_gau.txt

# waybackurls — dedicated Wayback Machine client
echo "$TARGET" | waybackurls | sort -u > urls_wayback.txt

# waymore — extended Wayback with dedup + filtering
waymore -i "$TARGET" -mode U -oU urls_waymore.txt 2>/dev/null

# Merge and decompose
cat urls_*.txt 2>/dev/null | sort -u > all_historical.txt
cat all_historical.txt | unfurl -u paths 2>/dev/null | sort -u > historical_paths.txt
cat all_historical.txt | unfurl -u keypairs 2>/dev/null | sort -u > historical_params.txt
cat all_historical.txt | grep -iE "\.(js|json|xml|yml|env|bak|old|sql|log|conf)$" > interesting_files.txt

echo "[+] $(wc -l < all_historical.txt) historical URLs"
echo "[+] $(wc -l < historical_paths.txt) unique paths → feed to ffuf as custom wordlist"
echo "[+] $(wc -l < historical_params.txt) unique parameters → test each for injection"
```

### Layer 4: Active Crawling + JS Intelligence

```bash
# katana — headless Chrome, catches SPA routes
katana -u "$TARGET" -d 3 -jc -kf all -silent -o crawl_katana.txt &

# gospider — fast Go crawler with form/link extraction
gospider -s "$TARGET" -d 2 --other-source --include-subs -q | sort -u > crawl_gospider.txt &
wait

# Collect all JS files
cat crawl_katana.txt crawl_gospider.txt all_historical.txt 2>/dev/null | \
  grep -iE "\.js(\?|$)" | sort -u > js_files.txt

# Extract API endpoints from JS
for js in $(head -50 js_files.txt); do
  curl -s "$js" 2>/dev/null | grep -oP '["'"'"'][/][a-zA-Z0-9_/\-\.]+["'"'"']' | tr -d '"'"'"''
done | sort -u > js_endpoints.txt

# Secret scanning in JS
for js in $(head -50 js_files.txt); do
  curl -s "$js" 2>/dev/null | grep -oiE \
    '(AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|sk_(live|test)_[a-zA-Z0-9]+|xox[bpoa]-[a-zA-Z0-9\-]+|api[_-]?key\s*[:=]\s*["'"'"'][a-zA-Z0-9_\-]{20,}["'"'"'])'
done > js_secrets.txt

echo "[+] $(wc -l < js_endpoints.txt) endpoints from JS"
[ -s js_secrets.txt ] && echo "[!] SECRETS FOUND in JS files — report immediately"
```

### Layer 5: Content Discovery with Target-Aware Wordlists

Select wordlists based on tech stack detected in Layer 2:

```bash
# Wordlist selection priority:
# 1. fuzz4bounty (curated for bounties): /usr/share/wordlists/fuzz4bounty/
# 2. Assetnote (tech-specific): /opt/wordlists/assetnote/{php,nodejs,java}.txt
# 3. SecLists: /usr/share/seclists/Discovery/Web-Content/
# 4. dirb fallback: /usr/share/wordlists/dirb/common.txt

# Tech-aware selection:
# PHP → fuzz4bounty + SecLists/PHP.fuzz.txt
# Node/Express → assetnote/nodejs.txt + api-endpoints.txt
# Java/Spring → spring-boot.txt + actuator paths
# Python/Django → django-specific paths
# Generic → api-endpoints.txt + raft-medium-directories.txt

WORDLIST="/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"

# ffuf — primary fuzzer
ffuf -u "$TARGET/FUZZ" -w "$WORDLIST" \
  -mc 200,201,301,302,401,403,405,500 -t 50 -o ffuf_results.json -of json

# SECOND PASS: use historical paths + JS endpoints as custom wordlist
sort -u historical_paths.txt js_endpoints.txt > custom_wordlist.txt
ffuf -u "$TARGET/FUZZ" -w custom_wordlist.txt \
  -mc 200,201,301,302,401,403,405,500 -t 30 -o ffuf_custom.json -of json

# Extensions fuzzing for discovered directories
ffuf -u "$TARGET/admin/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -e .php,.asp,.aspx,.jsp,.json,.yml,.bak,.old,.txt,.conf,.env \
  -mc 200,301,302,401,403,500 -t 30
```

### Layer 6: Parameter Discovery

```bash
# arjun — automated hidden parameter discovery
arjun -u "$TARGET/api/endpoint" -oJ arjun_params.json 2>/dev/null

# Manual high-value parameter probing
for param in id user_id account_id redirect url return_to file path cmd \
  exec debug admin role token key query search template include page callback; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/?$param=test123" --max-time 5)
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "[+] $param → HTTP $CODE"
done

# Use historical params discovered in Layer 3
while IFS='=' read -r key val; do
  echo "Discovered param: $key (sample value: $val)"
done < historical_params.txt | sort -u | head -50
```

## Corpus-Derived Hunting Patterns

### Platform-Within-Platform XSS-to-ATO

Identify subdomains where third-party content runs (canvas apps, slides, add-ons, marketplace iframes, embedded editors):
1. These subdomains have relaxed CSP because they render external content by design
2. Find XSS within the third-party container (often easier than the main app)
3. Chain with cookie scope or postMessage bridge to escalate to account takeover on the parent domain
This pattern has produced $126K+ in bounties.

### Redacted-Display Reconstruction Oracle

Anywhere a UI hides data but the underlying query layer can still search it:
1. Identify redacted fields (email addresses showing `j***@domain.com`, masked phone numbers)
2. Test whether the search/filter/sort API operates on the FULL unredacted value
3. If yes, binary-search/brute-force the redacted characters via search queries that match progressively more specific patterns

### Intermediate Account State Auditing

Enumerate every intermediate state an account can be in, and audit access for each:
1. Anonymous, pending-verification, verified-no-org, org-member, org-admin, suspended, deactivated, deleted-but-cached
2. For each state, test every API endpoint -- authorization checks often assume only "logged in" or "logged out" states
3. Accounts in transitional states (pending email verification, mid-password-reset) often have elevated permissions or missing checks

### Minimum-Input Authentication Probing

On any page asking for identifying information, submit the bare minimum:
1. Only email (no password), only username (no MFA)
2. Watch the response for: error message differences (user exists vs doesn't), redirect behavior changes, set-cookie differences
3. These information leaks are often the first step in an account takeover chain

### Batch API Field Laundering

When an API supports batch/chained requests where later requests reference fields from earlier responses:
1. Craft a batch where request 1 fetches a public resource containing internal IDs
2. Request 2 uses those IDs to access restricted resources
3. The batch endpoint may evaluate auth per-request but share response data across the batch

### Cross-Platform SSO Chain Analysis

When two applications share authentication:
1. Analyze every parameter in SSO redirect URLs for injection or substitution
2. Test whether tokens minted by platform A are accepted by platform B with different scopes
3. Check if the SSO flow leaks tokens via referrer, URL fragments, or postMessage to third parties

### Escalate Dismissed Findings

When an initial finding is dismissed or classified as low severity, use it as a foothold:
1. Combine with other low-severity findings for chain escalation
2. Use the confirmed behavior as an oracle for deeper testing (e.g., a confirmed info-disclosure becomes a parameter for SSRF testing)
3. Re-test after product updates -- fixes often introduce new variants

### Brand-Tier Subdomain XSS Hunting

For large organizations, enumerate brand-tier subdomains/properties:
1. `*.withgoogle.com`, `*.google.dev`, `*.area120.com` (or equivalent brand tiers)
2. These properties often use different tech stacks with less rigorous security review
3. Look for project name input fields, user-generated content rendering, or third-party library usage

## Endpoint Scoring (what to test first)

- **Score 5 (immediate)**: `/admin/*`, `/graphql`, 401/403 endpoints, endpoints with `?id=`
- **Score 4 (high)**: `/api/*` with params, `/auth/*`, `/upload/*`, `/webhook/*`, `/proxy/*`
- **Score 3 (medium)**: `/users/*`, `/search/*`, JS-discovered endpoints, Wayback-only endpoints
- **Score 2 (low)**: `/docs/*`, `/help/*`, `/status/*`
- **Skip**: `/static/*`, `/assets/*`, CSS, fonts, images

## Key Principle

Every hour of recon saves 3 hours of blind testing. Historical URLs reveal 2-5x more surface than crawling alone. JS analysis finds endpoints invisible to all crawlers.
