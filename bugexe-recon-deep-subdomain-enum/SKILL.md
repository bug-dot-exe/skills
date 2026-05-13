---
name: Deep Subdomain Enumeration
category: reconnaissance
description: Beyond surface-level subdomain discovery — permutation engines, mass DNS resolution, recursive expansion, VHost bruting, ASN walking, and certificate mining
depends_on: []
---

# Deep Subdomain Enumeration

## When to Use
- Bug bounty with wildcard scope (*.target.com)
- Surface-level subfinder/crt.sh returned <200 subdomains
- Target is a large organization with complex infrastructure
- You need to find internal/staging/dev subdomains that passive sources miss

## Why Surface-Level Is Not Enough

Surface tools (subfinder, crt.sh, gau) only find subdomains that were **publicly indexed**. They miss:
- Subdomains created after the last crawl
- Internal naming patterns (dev-api-v2, staging-payments-eu)
- Subdomains behind private DNS (never hit a public resolver)
- Deep subdomains (level 3+: us-east.api.internal.target.com)

## The Deep Pipeline (5 phases, ~5 minutes)

### Phase 1: Passive Aggregation (baseline, 60 seconds)

Run ALL passive sources in parallel to build the seed list:

```bash
# subfinder — 30+ passive sources
subfinder -d $DOMAIN -all -recursive -silent -o subs_subfinder.txt &

# crt.sh — Certificate Transparency logs
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | \
  jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u > subs_crt.txt &

# gau — extract subdomains from historical URL archives
echo $DOMAIN | gau --subs 2>/dev/null | unfurl -u domains 2>/dev/null | sort -u > subs_gau.txt &

# CHAOS — ProjectDiscovery's pre-indexed BB subdomain database
chaos -d $DOMAIN -silent -o subs_chaos.txt 2>/dev/null &

# SecurityTrails / Shodan (if API key available)
# curl -s "https://api.securitytrails.com/v1/domain/$DOMAIN/subdomains" \
#   -H "APIKEY: $ST_API_KEY" | jq -r '.subdomains[]' | sed "s/$/.${DOMAIN}/" > subs_st.txt &

wait
cat subs_*.txt 2>/dev/null | sort -u > seed_subs.txt
echo "[Phase 1] Seed: $(wc -l < seed_subs.txt) subdomains"
```

### Phase 2: Permutation Generation (the multiplier)

Take discovered subdomains and generate intelligent mutations. This is where you go from 200 → 2000+ candidates:

```bash
# alterx — pattern-based permutation (ProjectDiscovery)
# Learns naming patterns from your seed list and generates variants
# e.g., api.target.com → dev-api, staging-api, api-v2, api-internal, api-eu
cat seed_subs.txt | alterx -enrich -o permutations_alterx.txt 2>/dev/null &

# gotator — word-based permutation (prepend/append common infra words)
# Uses a word list of common prefixes/suffixes: dev, staging, test, internal, prod, etc.
PERM_WORDS="/tmp/perm_words.txt"
cat > "$PERM_WORDS" << 'WORDS'
dev
staging
stg
test
qa
uat
prod
internal
private
admin
api
app
beta
demo
sandbox
preview
canary
edge
legacy
old
new
v2
v3
eu
us
ap
east
west
WORDS

gotator -sub seed_subs.txt -perm "$PERM_WORDS" -depth 2 -mindup -adv 2>/dev/null \
  > permutations_gotator.txt &

# dnsgen — generate permutations from subdomain parts
# Splits subdomains into words, recombines with common patterns
cat seed_subs.txt | dnsgen - 2>/dev/null > permutations_dnsgen.txt &

wait
cat permutations_*.txt seed_subs.txt 2>/dev/null | sort -u > all_candidates.txt
echo "[Phase 2] Candidates: $(wc -l < all_candidates.txt) (from $(wc -l < seed_subs.txt) seeds)"
```

### Phase 3: Mass DNS Resolution (the filter)

Resolve candidates at high speed — only keep those with valid DNS records:

```bash
# Get fresh public resolvers (critical for accuracy)
curl -s "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt" \
  -o /tmp/resolvers.txt 2>/dev/null

# puredns — fastest resolver (wraps massdns, handles wildcards)
# Resolves millions of domains in seconds, auto-detects wildcard DNS
puredns resolve all_candidates.txt \
  -r /tmp/resolvers.txt \
  --write resolved_subs.txt \
  --write-wildcards wildcards.txt \
  2>/dev/null

# Fallback if puredns not available: dnsx
# cat all_candidates.txt | dnsx -silent -a -resp -retry 2 -r /tmp/resolvers.txt > resolved_subs.txt

echo "[Phase 3] Resolved: $(wc -l < resolved_subs.txt) live subdomains"
echo "[Phase 3] Wildcards detected: $(wc -l < wildcards.txt 2>/dev/null || echo 0)"
```

### Phase 4: Recursive Expansion (go deeper)

For any 3+ level subdomains found, enumerate one level deeper:

```bash
# Find multi-level subdomains worth expanding
grep -E "^([a-z0-9\-]+\.){3,}" resolved_subs.txt | \
  sed "s/^\([a-z0-9\-]*\)\.//" | sort -u > parent_subs.txt

# Run subfinder recursively on discovered parent zones
while read parent; do
  subfinder -d "$parent" -silent -all 2>/dev/null
done < parent_subs.txt | sort -u > recursive_subs.txt

# Resolve new discoveries
cat recursive_subs.txt | dnsx -silent -a 2>/dev/null >> resolved_subs.txt
sort -u -o resolved_subs.txt resolved_subs.txt

echo "[Phase 4] After recursion: $(wc -l < resolved_subs.txt) total"
```

### Phase 5: VHost Discovery + Certificate Mining

Find subdomains that share IPs but aren't in DNS (virtual hosts):

```bash
# Extract unique IPs from resolved subdomains
cat resolved_subs.txt | dnsx -silent -a -resp-only 2>/dev/null | sort -u > ips.txt

# Reverse DNS on discovered IPs (finds subdomains not in forward DNS)
cat ips.txt | dnsx -silent -ptr -resp-only 2>/dev/null | \
  grep "$DOMAIN" | sort -u > reverse_dns_subs.txt

# TLS certificate Subject Alternative Names (SAN) mining
# Connects to each IP on 443, extracts all SANs from the cert
for ip in $(head -50 ips.txt); do
  echo | openssl s_client -connect "$ip:443" -servername "$DOMAIN" 2>/dev/null | \
    openssl x509 -noout -text 2>/dev/null | \
    grep -oP "DNS:[a-zA-Z0-9\.\-]*$DOMAIN" | sed 's/DNS://'
done | sort -u > cert_san_subs.txt

# VHost brute-forcing on shared IPs (find internal virtual hosts)
# For each IP hosting multiple services:
for ip in $(head -20 ips.txt); do
  for vhost in admin internal staging dev api portal dashboard; do
    RESP=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $vhost.$DOMAIN" "https://$ip" -k --max-time 3)
    [ "$RESP" != "000" ] && [ "$RESP" != "404" ] && \
      echo "[VHost] $vhost.$DOMAIN @ $ip → HTTP $RESP"
  done
done

# Merge everything
cat resolved_subs.txt reverse_dns_subs.txt cert_san_subs.txt 2>/dev/null | \
  sort -u > final_subdomains.txt
echo "[Phase 5] Final: $(wc -l < final_subdomains.txt) subdomains"
```

## Quick One-Liner (if you're in a rush)

### Bundled passive enum (built-in, ~10-15s, 15 sources in parallel, no subprocess)

`passive_subdomains.py` ships with bug.exe and hits 15+ passive sources in
parallel with a single command:

```bash
# Plain stdout output (pipe-friendly for recon oneliners)
python /app/bugdotexe/tools/terminal/passive_subdomains.py $DOMAIN --quick --plain

# Full JSON with per-source stats
python /app/bugdotexe/tools/terminal/passive_subdomains.py $DOMAIN --quick

# Full mode (includes subfinder subprocess + wayback/commoncrawl archives, ~60s)
python /app/bugdotexe/tools/terminal/passive_subdomains.py $DOMAIN

# DNS-resolve to filter to live subdomains only
python /app/bugdotexe/tools/terminal/passive_subdomains.py $DOMAIN --quick --plain --resolve
```

Sources hit (no key required):
`crt.sh, hackertarget, rapiddns, alienvault, threatminer, urlscan, anubis,
commoncrawl*, wayback*, dnsdumpster*, certspotter, subdomain_center`
(*full mode only)

Keyed sources (gracefully skipped if env var unset):
`SECURITYTRAILS_API_KEY, VT_API_KEY, SHODAN_API_KEY, CENSYS_API_ID+SECRET,
CHAOS_API_KEY, LEAKIX_API_KEY, FULLHUNT_API_KEY`

### Pipe-chain oneliner (external tools, ~2 min, adds permutations + resolution)

```bash
python /app/bugdotexe/tools/terminal/passive_subdomains.py $DOMAIN --quick --plain | \
  tee seed.txt | alterx -enrich 2>/dev/null | dnsx -silent -a 2>/dev/null | \
  anew seed.txt | tee deep_subs.txt | wc -l
```

### Classic subfinder-only fallback (if bug.exe passive module is not available)

```bash
subfinder -d $DOMAIN -all -recursive -silent | tee seed.txt | \
  alterx -enrich 2>/dev/null | dnsx -silent -a 2>/dev/null | \
  anew seed.txt | tee deep_subs.txt | wc -l
```

## ASN-Based Discovery (for large orgs)

Find ALL IP ranges owned by the organization, then reverse-DNS them:

```bash
# Find the org's ASN
curl -s "https://api.bgpview.io/search?query_term=$DOMAIN" | \
  jq -r '.data.asns[].asn' 2>/dev/null

# Get all IP prefixes for the ASN
ASN="AS12345"  # replace with discovered ASN
curl -s "https://api.bgpview.io/asn/${ASN#AS}/prefixes" | \
  jq -r '.data.ipv4_prefixes[].prefix' 2>/dev/null > asn_ranges.txt

# Reverse DNS all IPs in those ranges (finds internal names)
cat asn_ranges.txt | mapcidr -silent 2>/dev/null | \
  dnsx -silent -ptr -resp-only 2>/dev/null | grep "$DOMAIN" | sort -u
```

## Tool Installation (if missing)

```bash
# ProjectDiscovery tools (Go-based, single binary)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest

# Community tools
go install -v github.com/d3mondev/puredns/v2@latest
go install -v github.com/Josue87/gotator@latest
pip3 install dnsgen

# Resolvers (always get fresh ones)
curl -s "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt" -o /tmp/resolvers.txt
```

## Corpus-Derived Hunting Patterns

Techniques from disclosed reports where subdomain-level discovery was the critical path to a bounty.

### Legacy/Internal Subdomain Hunting

Legacy and internal-flavored subdomains are where the highest-severity bugs live:

1. After enumeration, prioritize subdomains matching: `*-internal.*`, `*-staging.*`, `*-dev.*`, `*-admin.*`, `*-legacy.*`, `*-old.*`, `*-test.*`
2. For each, fingerprint the software running on it — legacy subdomains often run outdated software with known CVEs
3. Cross-reference against the target's version-update cadence — a subdomain running a version 2+ years old is a prime target

### OSS-Fingerprint IDOR Audit on Subdomains

When you discover a subdomain running identifiable open-source software:

1. Identify the software (Flagsmith, Sentry, Grafana, Airflow, Superset, etc.) from response headers, login page, or favicon
2. Read the software's API documentation — default API endpoints are often accessible without extra auth
3. Test for IDORs on the default API endpoints — self-hosted OSS deployments frequently rely on network-level access control instead of per-request auth

### Cookie-Tossing and Cross-Subdomain CSRF

When a target has multiple subdomains on the same parent domain:

1. Find a self-XSS or injection on ANY subdomain (even a low-severity one)
2. Use it to set a cookie on the parent domain (`.target.com`) that overrides CSRF tokens on higher-value subdomains
3. CSRF defenses based on cookies are bypassable when any sibling subdomain has an injection — audit CSRF on every API endpoint for origin-awareness, not just cookie-awareness

### Version-Banner Sweep + CVE Matching

For every resolved subdomain:

1. Capture HTTP response headers, specifically `Server`, `X-Powered-By`, `X-Version`, and custom version headers
2. Match against CVE databases — old versions of Jetty, Tomcat, Nginx, Apache, and application servers have well-documented exploits
3. The `Jetleak` pattern: even a single vulnerable header-parsing version on one subdomain is a valid finding

### Subdomain Takeover via Dangling DNS

After enumeration, check every CNAME for dangling references:

1. For each subdomain with a CNAME pointing to a cloud service (S3, CloudFront, Heroku, Azure, GitHub Pages, Fastly), verify the cloud resource still exists
2. If the resource was decommissioned but the DNS record remains, register the resource name to take over the subdomain
3. Check R2 custom domains, Vercel preview deploys, and Netlify sites — newer services have the same takeover risk

## Expected Yield

- Surface-level only: ~50-200 subdomains
- With permutation + resolution: **500-5000 subdomains**
- With recursion + VHost + ASN: **1000-10000+ subdomains**

The difference is where the bugs live. Dev/staging/internal subdomains typically have weaker security than production.
