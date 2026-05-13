---
name: bbrecon-subdomain-deep
description: Advanced subdomain enumeration for bug bounty recon. Use when running bbrecon assets phase, extending subdomain discovery beyond subfinder/amass, or when passive sources return few results. Covers permutation-based discovery (gotator/altdns), certificate transparency edge cases, wildcard handling, resolver selection, and juicy-target scoring.
---

# bbrecon Subdomain Deep Enumeration

Extends bbrecon's `assets_disc` with techniques that find subdomains others miss.

## When to Use

- Passive enum returns <50 subdomains for a large target
- Target has staging/dev/internal naming patterns
- Scope includes wildcards (`*.target.com`)
- Need to prioritize which subdomains to probe first

## Pipeline Integration

bbrecon writes to `ASSETS/all.passive.sub`, `ASSETS/all.active.sub`, `LIVE/all.live.sub`. This skill adds steps before or after the standard pipeline.

```bash
# Run bbrecon assets first
./bbrecon run -d target.com --only assets

# Then extend with deep enum (see below)
```

## 1. Permutation-Based Discovery

Finds `staging-api`, `dev-internal`, `api-v2` from known subs.

```bash
# Build permutation wordlist (common patterns)
cat <<EOF > permutations.txt
-staging
-dev
-api
-internal
-admin
-test
-demo
-backup
-old
-v2
-v1
-mobile
-app
-dashboard
EOF

# Run gotator (requires go) — outputs to stdout
gotator -sub ASSETS/all.passive.sub -perm permutations.txt -depth 1 -adv -md -silent 2>/dev/null | sort -u > .tmp/permuted.txt

# Resolve with puredns (suppress wildcards)
puredns resolve .tmp/permuted.txt -r resolvers.txt -w ASSETS/permuted.resolved.txt 2>/dev/null
```

**altdns** alternative:
```bash
altdns -i ASSETS/all.passive.sub -o .tmp/altdns_words.txt -w wordlist.txt
# wordlist: SecLists/Discovery/DNS/altdns-words.txt
puredns resolve .tmp/altdns_words.txt -r resolvers.txt -w ASSETS/altdns.resolved.txt
```

## 2. Certificate Transparency Edge Cases

crt.sh returns JSON; some entries have multiple names in `name_value` (newline-separated).

```bash
# Full extraction including SANs
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | tr '\n' ',' | tr ',' '\n' | sed 's/^\*\.//' | sort -u >> ASSETS/ct_subs.txt

# CertSpotter (if API key)
# curl -s "https://api.certspotter.com/v1/issuances?domain=target.com" | jq -r '.[].dns_names[]'
```

## 3. Wildcard Handling

When `*.target.com` resolves to same IP, filter noise.

```bash
# bbrecon uses ENABLE_WILDCARD_FILTER=1 by default
# Manual check: does random sub resolve?
RAND=$(head -c 16 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c 12)
dig +short "$RAND.target.com" @1.1.1.1
# If returns IP → wildcard. Exclude subs that match wildcard IP.
```

## 4. Resolver Selection

Faster resolvers = more throughput. Health-check before bulk resolve.

```bash
# Test resolver speed
for r in 1.1.1.1 8.8.8.8 9.9.9.9 208.67.222.222; do
  echo -n "$r: "; dig +short target.com @$r | head -1
done

# Use DNS_RESOLVER_FILE for custom list (bbrecon)
# lib/bbrecon_output.sh reads DNS_RESOLVERS or DNS_RESOLVER_FILE
```

## 5. Juicy Target Scoring

Prioritize subs with high-signal names. bbrecon's `assets_disc` already scores; extend with custom keywords.

```bash
# Add custom juicy keywords via env
export JUICY_EXTRA_KEYWORDS="grafana,jenkins,kibana,elastic,admin,api,v2,staging,dev,internal,debug,logs"

# Manual scoring: grep for high-value patterns
grep -iE "(admin|api|auth|staging|dev|internal|debug|grafana|jenkins|kibana|elastic|vpn|portal)" ASSETS/all.passive.sub | sort -u > ASSETS/juicy_manual.txt
```

## 6. Additional Passive Sources

When standard sources are exhausted:

| Source | Command / URL |
|-------|---------------|
| BufferOver | `curl -s "https://dns.bufferover.run/dns?q=.target.com"` |
| URLScan | `curl -s "https://urlscan.io/api/v1/search/?q=domain:target.com"` |
| SecurityTrails | API (key required) |
| VirusTotal | `vt domain subdomains target.com` (API) |
| HackerTarget | `curl -s "https://api.hackertarget.com/hostsearch/?q=target.com"` |
| Anubis | `curl -s "https://jldc.me/anubis/subdomains/target.com"` |

## 7. Merge and Dedupe

```bash
cat ASSETS/all.passive.sub ASSETS/permuted.resolved.txt ASSETS/ct_subs.txt 2>/dev/null | \
  sort -u | grep -E "\.target\.com$" > ASSETS/all.extended.sub
```

## Output Files (bbrecon convention)

- `ASSETS/all.extended.sub` — merged subdomains
- `ASSETS/juicy_manual.txt` — high-priority subs
- `LIVE/all.live.sub` — probe with httpx after merge

## References

- bbrecon: `modules/assets/assets_disc`
- bb-hunter: `recon.md` (base pipeline)
