---
name: bbrecon-scope-expansion
description: Expand bug bounty scope to find related in-scope assets. Use when program scope is narrow, when interpreting wildcards, or when hunting for assets competitors miss. Covers wildcard interpretation, ASN/cloud range expansion, acquisition/merger domains, app store backend discovery, and scope-to-asset correlation.
---

# bbrecon Scope Expansion

Turn narrow scope into a larger attack surface.

## When to Use

- Scope has `*.target.com` — enumerate what actually exists
- Scope lists specific paths — find related paths/subs
- Program acquired another company — old infra often in scope
- Mobile app in scope — find backend APIs
- Scope says "excluding X" — find edge cases

## 1. Wildcard Interpretation

`*.target.com` allows any subdomain. Prioritize by likelihood:

| Priority | Pattern | Why |
|----------|---------|-----|
| High | api, api-v2, api-staging | API surface |
| High | admin, dashboard, internal | Auth/access control |
| High | auth, login, sso | OAuth/OIDC |
| Medium | staging, dev, test, demo | Weaker controls |
| Medium | mobile, app, m | Mobile backend |
| Low | www, mail, cdn | Common, often hardened |

```bash
# From scope YAML, extract base domain
# config/scope.yml: allow: ["*.target.com"]
# Run subdomain enum, then filter to in-scope
subfinder -d target.com -silent | grep -E "\.target\.com$" > ASSETS/in_scope_subs.txt
```

## 2. ASN / IP Range Expansion

Other assets on same infrastructure may be in scope.

```bash
# Get ASN for target
whois target.com | grep -i origin
# Or: amass intel -whois -d target.com

# Find IP ranges for ASN
whois -h whois.radb.net -- "-i origin AS12345" | grep route

# Reverse DNS on IPs in range
# amass intel -asn 12345 -o asn_assets.txt
```

## 3. Acquisition / Merger Domains

Acquired companies keep old domains and infra. Check:

- Crunchbase acquisitions
- Press releases, Wikipedia
- WHOIS history (ViewDNS, WhoisHistory)
- Old SSL certs (crt.sh for acquired domain)

```bash
# If TargetCorp acquired StartupCo, add:
# startupco.com, *.startupco.com, legacy.startupco.com
# Often: startupco.com redirects to target.com but API stays at api.startupco.com
```

## 4. Mobile App Backend Discovery

Scope: "iOS app (App Store ID 123456)"

```bash
# Extract API base URL from app
# 1. Frida/SSL pinning bypass, proxy through Caido
# 2. Or: apktool/jadx on Android, extract strings
# 3. Or: class-dump on iOS binary

# Common patterns in app configs:
# api.target.com, api-v2.target.com, mobile.target.com
# Look for: baseURL, API_BASE, endpoint
```

## 5. Scope Path Expansion

Scope: `https://target.com/api/*` — find all API paths.

```bash
# From crawl
grep "target.com/api/" CRAWLING/all.crawled.urls | sed 's/?.*//' | sort -u

# From JS
grep -rE "/api/[a-zA-Z0-9/_-]+" JS/ | grep -oE "/api/[a-zA-Z0-9/_-]+" | sort -u

# From Wayback
waybackurls target.com | grep "/api/" | sed 's/?.*//' | sort -u
```

## 6. Excluded-Asset Edge Cases

Scope says "excluding blog.target.com". Check:

- `blog.target.com` vs `www.target.com/blog` — different apps?
- Subdomains of excluded: `admin.blog.target.com` — might be in scope
- CNAME: blog.target.com → external CDN — CDN in scope?

## 7. HackerOne / Bugcrowd Scope Sync

```bash
# bbrecon scope import
./bbrecon scope-sync --input exports/scope.csv --target-col target --scope-col in_scope --out config/scope.yml --merge

# Or use H1 Brain: search_scopes(program="handle")
```

## 8. Output Integration

- `config/scope.yml` — allow/deny lists
- `ASSETS/in_scope_subs.txt` — expanded subdomains
- `ASSETS/asn_assets.txt` — ASN-derived domains

## References

- bbrecon: config/scope.yml, modules/core/scope_sync.py
- bb-hunter: programs.md (scope evaluation)
- H1 Brain: search_scopes, fetch_program_scopes
