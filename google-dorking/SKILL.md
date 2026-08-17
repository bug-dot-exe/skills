---
name: google-dorking
category: reconnaissance
description: Google dorking for exposed admin panels, config files, backups, debug pages, and sensitive data
depends_on: []
---

# Google Dorking

Use Google's search operators to find what the target accidentally exposed: admin panels, configuration files, database dumps, debug interfaces, and forgotten staging environments.

## When to Use

- Early reconnaissance to find exposed assets before active scanning
- Looking for forgotten subdomains, staging environments, or backup files
- Searching for leaked configuration files or credentials
- Finding exposed admin panels or debug interfaces
- Identifying third-party services and integrations used by the target

## Methodology

### Phase 1: Basic Target Enumeration

1. Map all indexed pages and subdomains with `site:` operator
2. Identify different web technologies across subdomains
3. Find login pages, admin panels, and restricted areas
4. Discover file types hosted on the domain

### Phase 2: Sensitive File Discovery

1. Search for configuration files (`.env`, `.config`, `web.config`, `.yml`)
2. Look for backup files (`.bak`, `.old`, `.sql`, `.zip`, `.tar.gz`)
3. Find log files that may contain credentials or session data
4. Search for documentation that reveals internal architecture

### Phase 3: Exposed Interfaces

1. Find admin panels, dashboards, and management interfaces
2. Look for debug endpoints, phpinfo pages, and status pages
3. Discover API documentation (Swagger, GraphQL Playground)
4. Find version control exposure (`.git`, `.svn`)

### Phase 4: Error and Debug Pages

1. Search for pages with stack traces or error details
2. Find database error messages revealing table/column names
3. Look for verbose error pages with file path disclosure

## Key Queries

```
# Subdomain and page enumeration
site:target.com
site:target.com -www
site:*.target.com

# Exposed admin panels
site:target.com inurl:admin
site:target.com inurl:login
site:target.com intitle:"admin" OR intitle:"dashboard" OR intitle:"panel"
site:target.com inurl:wp-admin OR inurl:wp-login

# Configuration and sensitive files
site:target.com filetype:env
site:target.com filetype:yml OR filetype:yaml
site:target.com filetype:xml inurl:config
site:target.com filetype:json "api_key" OR "apiKey" OR "secret"
site:target.com filetype:log
site:target.com filetype:sql

# Backup and old files
site:target.com filetype:bak OR filetype:old OR filetype:backup
site:target.com filetype:zip OR filetype:tar OR filetype:gz
site:target.com inurl:backup OR inurl:dump OR inurl:export
site:target.com ext:sql "INSERT INTO" OR "CREATE TABLE"

# Debug and status pages
site:target.com intitle:"phpinfo()"
site:target.com inurl:debug OR inurl:trace OR inurl:test
site:target.com intitle:"index of /" 
site:target.com inurl:status OR inurl:health OR inurl:metrics
site:target.com "server-status" OR "server-info"

# Error pages revealing internals
site:target.com "stack trace" OR "traceback"
site:target.com "sql syntax" OR "mysql_" OR "pg_"
site:target.com "fatal error" filetype:php
site:target.com "Exception in" OR "Error 500"

# API documentation exposure
site:target.com inurl:swagger OR inurl:api-docs OR inurl:openapi
site:target.com inurl:graphql OR inurl:graphiql OR inurl:playground

# Source code and version control
site:target.com inurl:.git
site:target.com filetype:js "password" OR "secret" OR "token"

# Third-party integration leaks
site:target.com "amazonaws.com" OR "s3.amazonaws.com"
site:target.com "firebase" OR "firebaseio.com"
site:target.com "storage.googleapis.com"

# Forgotten or staging environments
site:staging.target.com OR site:dev.target.com OR site:test.target.com
site:target.com inurl:staging OR inurl:dev OR inurl:sandbox
```

## What to Look For

- Configuration files with credentials, API keys, or database connection strings
- Admin panels accessible without authentication or with default credentials
- Backup files containing source code or database exports
- Debug/status pages exposing internal architecture, versions, or environment variables
- Error pages revealing file paths, database schemas, or stack traces
- API documentation showing all available endpoints and parameters
- Staging/dev environments with weaker security controls
- Directory listings exposing file structure

## Operator Reference

| Operator | Purpose | Example |
|----------|---------|---------|
| `site:` | Restrict to domain | `site:target.com` |
| `inurl:` | Match in URL path | `inurl:admin` |
| `intitle:` | Match in page title | `intitle:"index of"` |
| `filetype:` / `ext:` | Match file extension | `filetype:sql` |
| `"exact phrase"` | Exact string match | `"api_key"` |
| `-` | Exclude term | `site:target.com -www` |
| `OR` | Either term | `filetype:yml OR filetype:yaml` |
| `cache:` | Google's cached version | `cache:target.com/page` |

## Corpus-Derived Hunting Patterns

Techniques from high-bounty reports where Google dorking was the initial discovery vector.

### Cache Poisoning Discovery via Dorks

Cache poisoning is a top-tier bug class ($500K+ payouts). Google dorks find the prerequisites:

1. **Identify CDN-fronted targets**: `site:target.com` + check response headers for `X-Cache`, `CF-Cache-Status`, `Age`, `Via`
2. **Find cacheable endpoints that reflect headers**: for each cacheable URL, test `Host`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-Original-URL` — if any header value appears in the response body AND the response is cached, you have cache poisoning
3. **Web Cache Deception**: for every authenticated endpoint fronted by a CDN, test if appending `/anything.css` or `/..%2fstatic.js` causes the CDN to cache the authenticated response

```
# Find CDN-fronted properties for cache poisoning
site:target.com inurl:cdn OR inurl:cache OR inurl:static
site:target.com "via:" OR "x-cache:" OR "cf-cache-status:"
```

### CI/CD Workflow Dorking

Public CI/CD configurations are a recurring source of Critical/High findings:

```
# GitHub Actions with self-hosted runners (RCE vector)
site:github.com "target-org" "self-hosted" filetype:yml
site:github.com "target-org" "pull_request_target" filetype:yml

# Jenkins / GitLab CI exposure
site:target.com intitle:"Dashboard [Jenkins]"
site:target.com inurl:"-/ci/lint" OR inurl:"-/pipelines"

# CI job artifacts with secrets
site:target.com inurl:artifacts OR inurl:job-logs OR inurl:build-log
```

### Deserialization and Data Store Boundary Dorking

Internal data stores (Redis, Memcached, on-disk caches) often deserialize untrusted data:

```
# Exposed Memcached / Redis admin interfaces
site:target.com intitle:"memcached" OR intitle:"redis" OR intitle:"phpRedisAdmin"

# Exposed Celery / RQ / Resque dashboards (job queues often accept serialized payloads)
site:target.com intitle:"Celery Flower" OR intitle:"RQ Dashboard" OR inurl:resque
```

### CSP Bypass Discovery

For any site with Content Security Policy, dork for CSP bypass vectors:

```
# Find script-src domains that host JSONP or Angular
site:target.com "content-security-policy"
# Then for each script-src host: check if it serves AngularJS, jQuery with eval, or JSONP endpoints
```

### Kubernetes and Infrastructure Exposure

```
# Exposed K8s dashboards and API servers
site:target.com intitle:"Kubernetes Dashboard"
site:target.com inurl:"/api/v1/namespaces" OR inurl:"/api/v1/pods"

# Exposed Grafana/Prometheus/Kibana
site:target.com intitle:"Grafana" OR intitle:"Kibana" OR inurl:prometheus
```

## Tips

1. Use Google in an incognito window to avoid personalized results skewing findings
2. Combine operators for precision: `site:target.com filetype:env "DB_PASSWORD"`
3. Check Google Cache for pages that have since been taken down
4. Repeat periodically; new indexed pages appear as the target deploys
5. Respect rate limits; automated mass dorking can trigger CAPTCHAs
6. Cross-reference dork results with Wayback Machine for historical exposure
