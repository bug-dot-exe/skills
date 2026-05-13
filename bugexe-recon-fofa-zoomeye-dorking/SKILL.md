---
name: fofa_zoomeye_dorking
category: reconnaissance
description: FOFA, ZoomEye, Quake, and Odin — search engines with different crawl coverage than Shodan. Strong for APAC infrastructure, IoT, and fingerprint-based asset discovery
depends_on: []
---

# FOFA / ZoomEye / Quake Dorking

Shodan is great but not the only game in town. Chinese-origin search engines index parts of the internet that Shodan under-samples, particularly APAC infrastructure, IoT, ICS, and anything behind GFW-affected networks. They also have different fingerprint databases and often find assets Shodan misses entirely.

For any thorough recon, run Shodan queries through these engines too — yields 20-40% additional unique hits on average.

## When to Use

- Target has operations or customers in Asia (infrastructure often hosted in APAC)
- Shodan comes up thin on known subdomains
- Hunting IoT / embedded / ICS / medical devices (these engines specialize)
- Pivoting from a favicon hash or TLS cert — these engines have massive fingerprint DBs
- Need historical host data older than Shodan's coverage

## Methodology

### Phase 1: Pick the Right Engine per Scenario

| Scenario | Best Engine | Why |
|----------|-------------|-----|
| APAC infrastructure | **FOFA** | Largest APAC crawl, most comprehensive |
| IoT / ICS / embedded | **ZoomEye** | Deepest IoT banner database |
| Raw banner pivoting | **Quake** (`quake.360.net`) | Fast, good for product-version pivots |
| Fingerprint / hash-based | **FOFA** + **Odin** | Best favicon / cert / body hashing |
| Global general-purpose | **Shodan** / **Censys** (see shodan_dorking.md) | Primary |

### Phase 2: Layered Queries (all engines)

Start broad, narrow using fingerprints:

1. Domain-based: `domain="target.com"`
2. Cert-based: `cert="target.com"`
3. Org-based: `org="Target Corp"`
4. ASN-based: `asn="12345"`
5. Favicon-based: `icon_hash="-123456789"` (unique per brand)
6. Body-hash-based: `body="Target Corp internal tool"`

### Phase 3: Fingerprint Pivoting (highest ROI)

Find ONE asset the target owns → use its fingerprints to find all others:

1. Compute the target's public-site favicon hash (`mmh3` of base64 of favicon bytes)
2. Search every engine for that hash → finds all target properties (including staging, internal-exposed)
3. Extract TLS cert subject/issuer → search those → finds more properties
4. Extract unique HTML body string → search → catches misconfigured servers using default branding

### Phase 4: Historical Coverage

FOFA/ZoomEye/Quake have deep historical indexes (sometimes older than Shodan's):

1. Pull all historical hosts associated with the domain
2. Cross-reference with current DNS to find decommissioned-but-still-live hosts
3. Check for old SSL cert fingerprints (pre-cert-rotation services may still be running)

## Key Queries

### FOFA (`fofa.info`)

FOFA's syntax uses `=` for exact, `==` for case-sensitive, `!=` for negation. Boolean `&&` `||` `!`.

```
# Basic asset discovery
domain="target.com"
host="target.com"
cert="target.com"
org="Target Corp"
asn="12345"

# Subdomain-style
host=".target.com"              # leading-dot matches any subdomain

# Service + org
org="Target Corp" && port="22"
org="Target Corp" && protocol="https"

# Favicon hash (mmh3 of base64 of favicon) — single best pivot
icon_hash="1234567890"

# TLS cert-based search
cert="target.com"
cert.issuer="DigiCert Inc" && cert.subject=".target.com"
cert.is_valid=true && cert.is_match=true && cert="target.com"

# Body / title / header matching
title="Target Admin Panel"
body="Target Corp © 2025"
header="Server: TargetCustomServer"

# Version / CVE hunting
product="Apache" && version="2.4.49" && org="Target Corp"
product="OpenSSH" && banner="7." && org="Target Corp"

# Country / city filters
org="Target Corp" && country="CN"
org="Target Corp" && city="Tokyo"

# Time-based (FOFA's strong suit — historical)
domain="target.com" && after="2023-01-01"
domain="target.com" && before="2022-01-01"
```

### ZoomEye (`zoomeye.org`)

ZoomEye syntax uses `keyword:value` like Shodan.

```
# Core asset discovery
domain:"target.com"
ssl:"target.com"
hostname:"target.com"
org:"Target Corp"

# Service + version
app:"nginx" +version:"1.14" +org:"Target Corp"
app:"OpenSSH" +ver:"7." +org:"Target Corp"

# IoT / ICS
device:"webcam" +country:"CN"
device:"router" +org:"Target Corp"
service:"modbus" +org:"Target Corp"

# CVE-based hunting
cve:"CVE-2021-44228" +org:"Target Corp"    # Log4Shell

# Title / banner
title:"Target Admin"
banner:"Server: TargetCustom"

# Certificate
ssl.cert.subject:"target.com"
ssl.cert.issuer:"Let's Encrypt"

# Favicon — ZoomEye supports image-hash search
iconhash:"1234567890"
```

### Quake (`quake.360.net`)

Quake's syntax is close to Shodan/Censys but with different field names.

```
domain:"target.com"
host:"target.com"
org:"Target Corp"

# Services
service:"ssh" && country:"JP"
service:"http" && title:"Target Admin"

# Favicon
favicon:"1234567890"

# Certificate
cert:"target.com"
cert.subject:"target.com"

# ASN
asn:"12345"

# Product fingerprint
app:"Apache" && version:"2.4.49"
```

### Odin (`odin.io`)

Newer entrant, strong on fingerprint-based asset attribution. Free tier available.

```
domain:"target.com"
fingerprint:"nginx 1.14"
favicon_hash:"1234567890"
title:"Target"
```

## Computing a Favicon Hash (for pivoting)

The single most powerful query across all of these is `favicon_hash=<N>`. Compute it from the target's own favicon:

```python
# Python (works for FOFA + ZoomEye + Quake)
import mmh3, requests, codecs

r = requests.get("https://target.com/favicon.ico")
b64 = codecs.encode(r.content, 'base64').decode()  # base64 of raw bytes, NOT url-safe
hash_ = mmh3.hash(b64.encode())
print(hash_)  # use this value in icon_hash= / iconhash: / favicon:
```

```bash
# One-liner
curl -s https://target.com/favicon.ico | base64 | python3 -c "import mmh3,sys; print(mmh3.hash(sys.stdin.read().encode()))"
```

A matching `icon_hash` across all engines finds every server the target hosts that uses the same favicon — including forgotten admin panels, dev/staging, and mirror deployments.

## What to Look For

**Infrastructure Shodan Missed**
- APAC-hosted subsidiaries / partners
- Self-hosted IoT / ICS / cameras / routers behind enterprise networks
- Forgotten VPS instances (small cloud providers less-indexed by Shodan)

**Fingerprint Pivoting Wins**
- Favicon-hash matches on IP addresses not in the target's DNS (stealth infrastructure)
- TLS cert SAN values on external hosts (partners, CI runners, staging)
- Body-hash matches revealing default-branded admin panels the target forgot

**Version / CVE Intelligence**
- Outdated web servers, databases, routers
- Specific vulnerable product versions (`product` + `version` filters)
- Devices with exposed management interfaces

## Validation

1. All four engines have stale data — verify fingerprints with a live TLS handshake before reporting
2. Different engines disagree often; cross-reference 2-3 before relying on a finding
3. Some results are honeypots — be suspicious of hosts with too-easy findings
4. API keys required for most advanced features; free tiers are limited

## Tips

1. Run **Shodan + FOFA + ZoomEye** in parallel — each has 20-40% unique results
2. The single query `icon_hash=<N>` (FOFA) almost always beats 10 other queries combined for asset discovery
3. FOFA's free tier caps at 100-1000 results/day — use the API + pagination via `size=100&page=N`
4. Combine engines via `uncover` (ProjectDiscovery CLI):
   ```bash
   echo 'org:"Target Corp"' | uncover -e shodan,fofa,zoomeye,quake,censys -silent
   ```
5. Always check the target's scope — some programs disallow these engines
6. For sensitive targets, use the web UI (no key attribution) rather than APIs
7. Save results to JSON immediately — engine indexes turn over monthly
