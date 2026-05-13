---
name: httpx
description: ProjectDiscovery httpx probing syntax, exact probe flags, and automation-safe output patterns.
depends_on: []
---

# httpx CLI Playbook

Official docs:
- https://docs.projectdiscovery.io/opensource/httpx/usage
- https://docs.projectdiscovery.io/opensource/httpx/running
- https://github.com/projectdiscovery/httpx

Canonical syntax:
`httpx [flags]`

High-signal flags:
- `-u, -target <url>` single target
- `-l, -list <file>` target list
- `-nf, -no-fallback` probe both HTTP and HTTPS
- `-nfs, -no-fallback-scheme` do not auto-switch schemes
- `-sc` status code
- `-title` page title
- `-server, -web-server` server header
- `-td, -tech-detect` technology detection
- `-fr, -follow-redirects` follow redirects
- `-mc <codes>` / `-fc <codes>` match or filter status codes
- `-path <path_or_file>` probe specific paths
- `-p, -ports <ports>` probe custom ports
- `-proxy, -http-proxy <url>` proxy target requests
- `-tlsi, -tls-impersonate` experimental TLS impersonation
- `-j, -json` JSONL output
- `-sr, -store-response` store request/response artifacts
- `-srd, -store-response-dir <dir>` custom directory for stored artifacts
- `-silent` compact output
- `-rl <n>` requests/second cap
- `-t <n>` threads
- `-timeout <seconds>` request timeout
- `-retries <n>` retry attempts
- `-o <file>` output file

Agent-safe baseline for automation:
`httpx -l hosts.txt -sc -title -server -td -fr -timeout 10 -retries 1 -rl 50 -t 25 -silent -j -o httpx.jsonl`

Common patterns:
- Quick live+fingerprint check:
  `httpx -l hosts.txt -sc -title -server -td -silent -o httpx.txt`
- Probe known admin paths:
  `httpx -l hosts.txt -path /,/login,/admin -sc -title -silent -j -o httpx_paths.jsonl`
- Probe both schemes explicitly:
  `httpx -l hosts.txt -nf -sc -title -silent`
- Vhost detection pass:
  `httpx -l hosts.txt -vhost -sc -title -silent -j -o httpx_vhost.jsonl`
- Proxy-instrumented probing:
  `httpx -l hosts.txt -sc -title -proxy http://127.0.0.1:48080 -silent -j -o httpx_proxy.jsonl`
- Response-storage pass for downstream content parsing:
  `httpx -l hosts.txt -fr -sr -srd recon/httpx_store -sc -title -server -cl -ct -location -probe -silent`

Critical correctness rules:
- For machine parsing, prefer `-j -o <file>`.
- Keep `-rl` and `-t` explicit for reproducible throughput.
- Use `-nf` when you need dual-scheme probing from host-only input.
- When using `-path` or `-ports`, keep scope tight to avoid accidental scan inflation.
- Use `-sr -srd <dir>` when later steps need raw response artifacts (JS/route extraction, grepping, replay).

Usage rules:
- Use `-silent` for pipeline-friendly output.
- Use `-mc/-fc` when downstream steps depend on specific response classes.
- Prefer `-proxy` flag over global proxy env vars when only httpx traffic should be proxied.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

Failure recovery:
- If too many timeouts occur, reduce `-rl/-t` and/or increase `-timeout`.
- If output is noisy, add `-fc` filters or `-fd` duplicate filtering.
- If HTTPS-only probing misses HTTP services, rerun with `-nf` (and avoid `-nfs`).

If uncertain, query web_search with:
`site:docs.projectdiscovery.io httpx <flag> usage`

## Corpus-Derived Advanced Techniques

### Platform Fingerprinting Pipeline

Fingerprint backend platforms to select targeted exploit checklists:
```bash
# Fingerprint with tech-detect + server headers for platform identification
httpx -l hosts.txt -sc -title -server -td -fr -favicon \
  -j -o fingerprint.jsonl -silent -rl 50 -t 25 -timeout 10
# Parse results for known platforms
cat fingerprint.jsonl | jq -r 'select(.tech | test("Firebase|Amplify|Supabase|Hasura|Auth0|Salesforce|ServiceNow|Flagsmith|Sentry"))' > platform_targets.jsonl
```
Each platform has known misconfiguration patterns. Firebase: test `/.json` read. Flagsmith: test IDOR on API keys. Salesforce Experience Cloud: test guest user API access.

### OSS Deployment Fingerprinting for IDOR

Identify self-hosted open-source software on subdomains, then audit known API patterns:
```bash
httpx -l subdomains.txt -sc -title -server -td -fr \
  -j -o oss_fingerprint.jsonl -silent -rl 50
# Filter for known OSS (Flagsmith, Sentry, GitLab, Grafana, Jenkins)
cat oss_fingerprint.jsonl | jq -r 'select(.title | test("Flagsmith|Sentry|Grafana|GitLab|Jenkins";  "i"))' > oss_targets.jsonl
```
Then read each project's API docs for authorization-bypass vectors.

### N-Day CVE Sweep

Maintain version fingerprints and cross-reference against advisory feeds:
```bash
# Fingerprint + version extraction
httpx -l hosts.txt -sc -server -td -fr -j -o versions.jsonl -silent
# Check against known CVEs: WPScan, NVD, CISA KEV, Nuclei templates
# For WordPress specifically:
httpx -l wp_hosts.txt -path /wp-login.php -sc -title -server -j -o wp_versions.jsonl -silent
```

### Subdomain Takeover Detection

Combine CNAME fingerprinting with httpx probing for dangling DNS:
```bash
# Probe subdomains and check for takeover indicators
httpx -l subdomains.txt -sc -title -cname -j -o cname_check.jsonl -silent
# Filter for known vulnerable patterns
cat cname_check.jsonl | jq -r 'select(.status_code==404 or .title==""|.title==null) | "\(.url) \(.cname)"' > takeover_candidates.txt
```
Check CNAMEs against known vulnerable services: Heroku, S3, GitHub Pages, Azure, Shopify, Fastly, Pantheon.

### Non-200 Response Body Inspection

Always examine response bodies on error codes for data leakage:
```bash
# Store all responses including errors for body analysis
httpx -l hosts.txt -path /api/user,/admin,/debug,/internal \
  -sc -cl -ct -title -fr -sr -srd recon/response_store \
  -j -o all_responses.jsonl -silent -rl 50
# Grep stored responses for leaked data
grep -rl 'password\|token\|secret\|api_key\|internal' recon/response_store/
```
302 redirects with leaked content in the body, 403 pages with partial data, and 500 errors with stack traces are all reportable.

### SMTP and Service Port Probing

Extend beyond HTTP to find exposed services:
```bash
# Probe non-standard ports
httpx -l hosts.txt -p 8080,8443,3000,4443,9090,8888,10250 \
  -sc -title -server -td -j -o alt_ports.jsonl -silent -rl 30
```

### Stack-Specific Dangerous Default Checks

After fingerprinting the stack, probe for known dangerous defaults:
```bash
# WordPress defaults
httpx -l wp_hosts.txt -path /xmlrpc.php,/wp-json/wp/v2/users,/wp-content/debug.log \
  -sc -title -j -o wp_defaults.jsonl -silent
# Java/Spring defaults
httpx -l java_hosts.txt -path /actuator,/actuator/env,/actuator/heapdump,/jolokia \
  -sc -title -j -o spring_defaults.jsonl -silent
# AEM/CRX defaults
httpx -l aem_hosts.txt -path /crx/de,/crx/explorer,/system/console,/bin/querybuilder.json \
  -sc -title -j -o aem_defaults.jsonl -silent
```
