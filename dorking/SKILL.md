---
name: dorking
description: >
  Google/GitHub/Shodan/Censys dorking for bug bounty recon — sensitive file discovery,
  exposed credentials, admin panels, API keys, cloud misconfigs, subdomain enumeration,
  source code leaks. Trigger on "/dork", "google dork", "github dork", "shodan dork".
---

# Dorking Arsenal

You are a dorking specialist. You craft precise search queries across Google, GitHub, Shodan, Censys, and other search engines to discover exposed assets, leaked credentials, sensitive files, and attack surface for bug bounty targets.

## Usage

```
/dork target.com                    # run all dork categories against target
/dork target.com --google           # Google dorks only
/dork target.com --github           # GitHub dorks only
/dork target.com --shodan           # Shodan dorks only
/dork target.com --category creds   # specific category
/dork "Company Name"                # org-based dorking
```

---

## Phase 1 — Target Enumeration

Before dorking, gather target identifiers:
1. **Primary domain**: target.com
2. **Known subdomains**: *.target.com (from recon if available)
3. **Organization names**: "Target Inc", "Target Corp" (for GitHub/LinkedIn dorking)
4. **Known tech stack**: from recon output or Wappalyzer
5. **Known employees**: from LinkedIn (for GitHub account discovery)
6. **IP ranges**: from ASN lookup (for Shodan/Censys)

```bash
# ASN lookup
curl -s "https://api.bgpview.io/search?query_term=target.com" | jq '.data.asns'
# Or: whois -h whois.radb.net -- '-i origin AS12345'
```

---

## Phase 2 — Google Dorks

### Sensitive Files & Directories

```
site:target.com filetype:env
site:target.com filetype:log
site:target.com filetype:sql
site:target.com filetype:bak
site:target.com filetype:cfg
site:target.com filetype:conf
site:target.com filetype:ini
site:target.com filetype:yml
site:target.com filetype:yaml
site:target.com filetype:toml
site:target.com filetype:xml
site:target.com filetype:json
site:target.com filetype:csv
site:target.com filetype:xls OR filetype:xlsx
site:target.com filetype:doc OR filetype:docx
site:target.com filetype:pdf intext:"confidential" OR intext:"internal"
site:target.com filetype:pem OR filetype:key OR filetype:ppk
site:target.com filetype:jks OR filetype:p12 OR filetype:pfx
```

### Exposed Admin & Login Panels

```
site:target.com inurl:admin
site:target.com inurl:login
site:target.com inurl:signin
site:target.com inurl:dashboard
site:target.com inurl:portal
site:target.com inurl:panel
site:target.com inurl:cpanel
site:target.com inurl:phpmyadmin
site:target.com inurl:wp-admin
site:target.com inurl:administrator
site:target.com intitle:"index of /"
site:target.com intitle:"dashboard" intext:"welcome"
```

### Credentials & Secrets

```
site:target.com intext:"password" filetype:log
site:target.com intext:"api_key" OR intext:"apikey" OR intext:"api-key"
site:target.com intext:"secret_key" OR intext:"secretkey"
site:target.com intext:"access_token" OR intext:"bearer"
site:target.com intext:"jdbc:" OR intext:"mysql://" OR intext:"postgresql://"
site:target.com intext:"mongodb://" OR intext:"redis://"
site:target.com intext:"AWS_ACCESS_KEY" OR intext:"AKIA"
site:target.com intext:"sk_live_" OR intext:"pk_live_"
site:target.com intext:"-----BEGIN RSA PRIVATE KEY-----"
site:target.com intext:"-----BEGIN OPENSSH PRIVATE KEY-----"
```

### Error Messages & Debug

```
site:target.com intext:"SQL syntax" OR intext:"mysql_fetch"
site:target.com intext:"Warning:" filetype:php
site:target.com intext:"Fatal error:" filetype:php
site:target.com intext:"stack trace" OR intext:"traceback"
site:target.com intext:"debug" inurl:debug
site:target.com intitle:"phpinfo()"
site:target.com intext:"Django Debug" OR intext:"DEBUG = True"
site:target.com intext:"Laravel" intext:"APP_DEBUG=true"
site:target.com intext:"Whitelabel Error Page" (Spring Boot)
site:target.com inurl:.git
site:target.com inurl:.svn
site:target.com inurl:.DS_Store
```

### API & Swagger Docs

```
site:target.com inurl:api inurl:swagger
site:target.com inurl:api-docs
site:target.com inurl:graphql OR inurl:graphiql
site:target.com inurl:"/api/v1" OR inurl:"/api/v2"
site:target.com filetype:json inurl:openapi
site:target.com intitle:"Swagger UI"
site:target.com inurl:_api OR inurl:api_ OR inurl:/rest/
```

### Cloud Storage

```
site:s3.amazonaws.com "target"
site:blob.core.windows.net "target"
site:storage.googleapis.com "target"
site:digitaloceanspaces.com "target"
"target.com" site:pastebin.com
"target.com" site:trello.com
"target.com" site:jira.atlassian.net
```

### Subdomain Discovery via Google

```
site:*.target.com -www
site:*.*.target.com
site:target.com -www -blog -shop -mail
```

---

## Phase 3 — GitHub Dorks

### Credentials & Secrets

```
"target.com" password
"target.com" secret
"target.com" api_key
"target.com" apikey
"target.com" access_token
"target.com" token
"target.com" AWS_SECRET_ACCESS_KEY
"target.com" AKIA
"target.com" sk_live_
"target.com" client_secret
"target.com" authorization: Bearer
org:target password
org:target secret
org:target api_key
org:target AWS_ACCESS_KEY_ID
```

### Configuration Files

```
"target.com" filename:.env
"target.com" filename:.env.production
"target.com" filename:.env.staging
"target.com" filename:.env.local
"target.com" filename:wp-config.php
"target.com" filename:configuration.php
"target.com" filename:config.php
"target.com" filename:database.yml
"target.com" filename:.htpasswd
"target.com" filename:settings.py
"target.com" filename:application.properties
"target.com" filename:docker-compose.yml
"target.com" filename:Dockerfile
"target.com" filename:id_rsa
"target.com" filename:id_dsa
"target.com" filename:.npmrc _auth
"target.com" filename:.dockercfg auth
"target.com" filename:credentials
"target.com" filename:secret_token.rb
```

### Internal URLs & Infrastructure

```
"target.com" filename:.git-credentials
"target.com" "internal" OR "staging" OR "dev" OR "uat"
"target.com" inurl:vpn OR inurl:remote OR inurl:proxy
"target.com" extension:pem private
"target.com" extension:ppk
"target.com" "BEGIN RSA PRIVATE KEY"
"target.com" "BEGIN OPENSSH PRIVATE KEY"
org:target "jdbc:" OR "mysql://" OR "postgres://"
org:target "mongodb+srv://"
org:target language:Shell "curl" "password"
```

### Automation with gh CLI

```bash
# Search GitHub code for target secrets
gh search code "target.com password" --limit 20 --json path,repository,textMatches
gh search code "target.com api_key" --limit 20 --json path,repository,textMatches
gh search code "target.com secret" --limit 20 --json path,repository,textMatches
gh search code "org:targetorg filename:.env" --limit 20
gh search code "org:targetorg AWS_ACCESS" --limit 20

# Search commits (leaked then removed)
gh search commits "target.com password" --limit 20
gh search commits "target.com remove secret" --limit 20
gh search commits "target.com fix credentials" --limit 20
```

---

## Phase 4 — Shodan Dorks

```
# Basic target enumeration
hostname:target.com
org:"Target Inc"
ssl:"target.com"
ssl.cert.subject.cn:"target.com"
asn:AS12345

# Exposed services
hostname:target.com port:22,3389,5900
hostname:target.com port:3306,5432,27017,6379
hostname:target.com port:9200,9300    # Elasticsearch
hostname:target.com port:5601         # Kibana
hostname:target.com port:8080,8443    # Alt HTTP
hostname:target.com port:11211        # Memcached
hostname:target.com port:2375,2376    # Docker API

# Known vulnerable services
hostname:target.com "Server: Apache/2.4.49"    # Path traversal CVE-2021-41773
hostname:target.com "X-Jenkins"
hostname:target.com "X-Drupal-Cache"
hostname:target.com http.title:"GitLab"
hostname:target.com http.title:"Grafana"
hostname:target.com http.title:"Kibana"
hostname:target.com http.component:"wordpress"
hostname:target.com http.component:"jira"
hostname:target.com "MongoDB Server Information" port:27017

# Cloud & infra
org:"Amazon" hostname:target.com
org:"Google Cloud" hostname:target.com
org:"Microsoft Azure" hostname:target.com
```

---

## Phase 5 — Censys Dorks

```
# Certificate-based subdomain discovery
parsed.names: target.com
parsed.subject.common_name: target.com

# Service discovery
services.http.response.headers.server: "target"
services.tls.certificates.leaf.subject.common_name: "*.target.com"
```

---

## Phase 6 — Specialized Dorks

### Wayback Machine / Archive.org

```bash
# Find old/removed pages
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" | sort -u

# Find old API endpoints
curl -s "http://web.archive.org/cdx/search/cdx?url=target.com/api/*&output=text&fl=original&collapse=urlkey"

# Find removed files
curl -s "http://web.archive.org/cdx/search/cdx?url=target.com/*&output=text&fl=original,statuscode&collapse=urlkey" | grep " 200" | grep -E "\.(env|sql|bak|conf|log|json|xml)$"
```

### Postman / API Collections

```
site:postman.com "target.com"
site:postman.com "target" "api"
# Check: https://www.postman.com/explore/collections?q=target
```

### GitLab (self-hosted or gitlab.com)

```
site:gitlab.com "target.com"
site:gitlab.com "target.com" password
site:gitlab.com "target.com" token
```

### NPM / PyPI / Docker Hub

```
site:npmjs.com "target.com"
site:pypi.org "target.com"
site:hub.docker.com "target"
```

### Pastebin & Paste Sites

```
site:pastebin.com "target.com"
site:paste.ee "target.com"
site:pastie.org "target.com"
site:ghostbin.co "target.com"
site:ideone.com "target.com"
site:codebeautify.org "target.com"
```

---

## Output Format

Write results to `hunt/{target}/dorks/`:
- `google-dorks.md` — all Google results, categorized
- `github-dorks.md` — all GitHub results with repo links
- `shodan-dorks.md` — exposed services and ports
- `interesting-findings.md` — anything that looks exploitable

For each finding, note:
- **Source**: Google / GitHub / Shodan / Censys / Wayback
- **Query used**: exact dork
- **URL/Endpoint**: what was found
- **Severity**: Critical (creds) / High (admin panel) / Medium (info leak) / Low (info)
- **Next step**: what to test

---

## Integration with /hunt-deep

When called from `/hunt-deep`, the dorking output feeds into the recon-ranker:
- Exposed admin panels → auth-bypass-hunter
- Leaked API keys → api-security-hunter
- Exposed cloud storage → ssrf-deep-hunter
- Debug endpoints → business-logic hunting
- Old API versions → API versioning exploits

---

## Automation Script

```bash
#!/bin/bash
# Full dork sweep — save to run separately
TARGET=$1
OUT="hunt/$TARGET/dorks"
mkdir -p "$OUT"

echo "[*] GitHub dorking..."
for term in password secret api_key token AWS_ACCESS; do
  gh search code "$TARGET $term" --limit 10 --json path,repository 2>/dev/null >> "$OUT/github-dorks.json"
done

echo "[*] Wayback dorking..."
curl -s "http://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" | sort -u > "$OUT/wayback-urls.txt"

echo "[*] Certificate transparency..."
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sort -u > "$OUT/crt-subdomains.txt"

echo "[*] Done. Results in $OUT/"
```
