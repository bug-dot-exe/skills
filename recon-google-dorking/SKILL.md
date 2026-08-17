---
name: recon-google-dorking
category: reconnaissance
description: Comprehensive Google dorking methodology — every operator, every dork category, layered query refinement. Methodology-first replacement for one-shot URL scrapers — exhaustive dork-tree walk for exposed admin panels, config leaks, debug pages, framework-specific exposures, and cloud bucket pivots.
trigger: starting passive recon on a target with a discoverable web surface; need to discover staging/dev environments, exposed admin panels, debug pages, leaked configs, framework-specific surfaces; cross-checking GitHub-found hostnames against live Google index; looking for cloud-bucket leaks via cross-domain dorks
composes_with: recon_yandex_dorking, recon_github_intel, recon_archive_intel, recon_information_disclosure, recon_passive_subdomain
depends_on: []
---

# Recon — Google Dorking (Deep)

## Purpose

Google's index is the largest passive surface available to a recon agent. Targets routinely leave admin panels, debug interfaces, configuration files, backup archives, framework default pages, and entire staging environments indexed by accident. Layered dorking — broad-then-narrow-then-specific — extracts that surface without sending a single packet to the target. Subprocess scrapers (`gau`, `waymore`, `waybackurls`) cover one slice of historical-URL data and stop. This skill is the methodology a reasoning agent uses to walk the entire dork tree: every operator, every category of dork, every framework, every cloud provider, every error-page signature — refining queries based on what previous queries returned, and never skipping a category because an early, broad query came back thin. Dorking finds bugs that no other recon stage finds.

## When to Use

- Starting passive recon on any target with a web surface
- Need to discover staging, dev, qa, sandbox, internal subdomains
- Looking for indexed config files, env files, backup archives, log files
- Hunting framework default pages (Jenkins, GitLab, Jira, Confluence, etc.)
- Seeking exposed cloud buckets via cross-domain `site:` dorks
- Confirming GitHub-leaked hostnames are live and indexed
- Mapping the full subdomain set Google has crawled (often broader than CT logs)
- Looking for debug interfaces, error pages, stack traces, API documentation pages
- Checking what cached pages still hold deleted-but-once-indexed content

## Inputs (runtime-derived)

- `target_root_domain` — primary apex from `--target` arg (`target.example`)
- `target_alt_domains` — subsidiary / acquisition domains discovered earlier
- `known_subdomains` — from prior recon (use as `site:` anchors AND exclusion seeds)
- `known_tech_stack` — Wappalyzer / fingerprinting hints from earlier scan
- `known_employees` — names for `intext:` author-style dorks, optional
- `extra_keywords` — internal product names, codename, internal portal names from job postings or marketing pages

## Methodology

### Stage 1 — Broad Surface Mapping

Build the universe of indexed pages on the target.

1. **Apex enumeration**: `site:target.example` — record total result count (Google strips after ~300, but the stated count gives a rough magnitude)
2. **Subdomain enumeration via wildcard**:
   - `site:*.target.example` — all subdomains Google sees
   - `site:*.target.example -www` — exclude main marketing site
   - `site:*.target.example -www -api` — peel off known surfaces
   - `site:*.target.example -www -api -blog -docs -support` — what's left is high-signal
3. **Apex variants**: `site:target.example | site:target-corp.example | site:target-internal.example` — discover sister domains
4. **TLD permutation**: if `target.com` is the primary, also probe `target.io`, `target.net`, `target.dev`, `target.app`, country TLDs relevant to discovered locale
5. **Deep-page mapping**: for the apex, enumerate `inurl:` segments — `/admin`, `/api`, `/v1`, `/v2`, `/auth`, `/login`, `/signup`, `/dashboard`, `/internal`, `/portal`, `/manage`, `/support`, `/help`, `/docs`, `/static`, `/assets`, `/uploads`, `/files`, `/download`, `/report`, `/preview`

Output: `subdomains_indexed.txt`, `paths_indexed.txt`, `apex_count.txt`.

### Stage 2 — Login & Auth Surface Discovery

Login pages are first-class targets — every login leads to an auth flow worth testing.

```
site:target.example inurl:login
site:target.example inurl:signin
site:target.example inurl:sign-in
site:target.example inurl:auth
site:target.example inurl:sso
site:target.example inurl:oauth
site:target.example inurl:saml
site:target.example inurl:account
site:target.example inurl:portal
site:target.example inurl:admin
site:target.example inurl:administrator
site:target.example inurl:manage
site:target.example inurl:dashboard
site:target.example inurl:console
site:target.example inurl:internal
site:target.example inurl:my-account
site:target.example inurl:profile
site:target.example inurl:settings
site:target.example intitle:"login"
site:target.example intitle:"sign in"
site:target.example intitle:"admin"
site:target.example intitle:"dashboard"
site:target.example intitle:"control panel"
site:target.example intitle:"administration"
site:target.example intitle:"members area"
site:target.example intitle:"staff"
```

For each result with a non-www subdomain, record the subdomain — it's a candidate for `recon_passive_subdomain` and `recon_information_disclosure`.

### Stage 3 — Sensitive-File Discovery

Config files, backups, dumps. Each is a separate dork.

```
# Environment files
site:target.example filetype:env
site:target.example ext:env
site:target.example inurl:.env

# Generic config
site:target.example filetype:cfg
site:target.example filetype:conf
site:target.example filetype:ini
site:target.example filetype:yml
site:target.example filetype:yaml
site:target.example filetype:json inurl:config
site:target.example filetype:xml inurl:config
site:target.example filetype:properties

# Cloud / Container manifests indexed
site:target.example filetype:tf
site:target.example filetype:tfstate
site:target.example filename:docker-compose.yml
site:target.example filename:Dockerfile
site:target.example filename:kubeconfig
site:target.example filename:values.yaml

# Backup files
site:target.example ext:bak
site:target.example ext:old
site:target.example ext:swp
site:target.example ext:tmp
site:target.example ext:save
site:target.example ext:orig
site:target.example ext:original

# Compressed / archive
site:target.example ext:zip
site:target.example ext:tar
site:target.example ext:tar.gz
site:target.example ext:tgz
site:target.example ext:rar
site:target.example ext:7z
site:target.example ext:gz

# Database dumps & SQL
site:target.example ext:sql
site:target.example ext:db
site:target.example ext:sqlite
site:target.example ext:mdb
site:target.example "INSERT INTO" filetype:sql
site:target.example "CREATE TABLE" filetype:sql
site:target.example "DROP TABLE" filetype:sql

# Logs
site:target.example ext:log
site:target.example filetype:log "error"
site:target.example filetype:log "stack"
site:target.example filetype:log "exception"

# Office and document leaks
site:target.example filetype:pdf "confidential"
site:target.example filetype:pdf "internal use only"
site:target.example filetype:pdf "do not distribute"
site:target.example filetype:doc OR filetype:docx OR filetype:rtf
site:target.example filetype:xls OR filetype:xlsx OR filetype:csv
site:target.example filetype:ppt OR filetype:pptx
site:target.example filetype:txt "password"

# Scripts and source
site:target.example filetype:sh "password"
site:target.example filetype:py "API_KEY"
site:target.example filetype:rb "AWS_SECRET"
site:target.example filetype:js "apiKey"
site:target.example filetype:ts "secret"
site:target.example filetype:php "mysql_connect"

# Version control exposure
site:target.example inurl:.git
site:target.example inurl:.git/config
site:target.example inurl:.svn
site:target.example inurl:.hg
site:target.example inurl:.bzr
```

### Stage 4 — Errors, Debug, Stack Traces

```
# Generic errors
site:target.example intext:"warning:" OR intext:"fatal error"
site:target.example intext:"stack trace"
site:target.example intext:"traceback (most recent call last)"
site:target.example intext:"exception in"
site:target.example intext:"error 500"

# Database / ORM
site:target.example intext:"sql syntax"
site:target.example "you have an error in your sql syntax"
site:target.example "ORA-" "error"
site:target.example "PG::" "error"
site:target.example "SQLSTATE"
site:target.example "ActiveRecord::"
site:target.example "Sequelize"

# Language-specific
site:target.example "Notice:" inurl:.php
site:target.example "Warning:" "include(" "failed to open"
site:target.example "PHP Parse error"
site:target.example "PHP Fatal error"
site:target.example "Whoops" filetype:html
site:target.example intext:"DEBUG = True"
site:target.example "Werkzeug" "DEBUGGER"
site:target.example "rails" "exception"
site:target.example "Spring Boot" "Whitelabel Error Page"
site:target.example ".NET unhandled exception"

# Path-disclosure errors
site:target.example "/var/www/" intext:"on line"
site:target.example "C:\\inetpub\\" intext:"line"
site:target.example "/home/" intext:".php on line"
```

### Stage 5 — Index Pages & Directory Listings

```
site:target.example intitle:"index of /"
site:target.example intitle:"index of" "parent directory"
site:target.example intitle:"index of" inurl:backup
site:target.example intitle:"index of" inurl:admin
site:target.example intitle:"index of" inurl:upload
site:target.example intitle:"index of" inurl:logs
site:target.example intitle:"index of" inurl:config
site:target.example intitle:"index of" inurl:.git
site:target.example intitle:"index of" "passwd"
site:target.example intitle:"index of" ".env"
site:target.example "Index of /" "Last modified" "Description"
```

### Stage 6 — API & Documentation Surfaces

```
# OpenAPI / Swagger
site:target.example inurl:swagger
site:target.example inurl:swagger-ui
site:target.example inurl:swagger.json
site:target.example inurl:swagger.yaml
site:target.example inurl:openapi.json
site:target.example inurl:openapi.yaml
site:target.example inurl:api/docs
site:target.example inurl:api-docs
site:target.example inurl:redoc
site:target.example inurl:rapi-doc
site:target.example intitle:"swagger ui"

# GraphQL
site:target.example inurl:graphql
site:target.example inurl:graphiql
site:target.example inurl:playground
site:target.example "GraphQL Playground"
site:target.example intext:"__schema"

# REST documentation portals
site:target.example inurl:apiary
site:target.example "API reference" inurl:docs
site:target.example "Postman" inurl:docs
site:target.example intitle:"API documentation"

# Spec leaks
site:target.example filetype:yaml "openapi:"
site:target.example filetype:json "swagger" "info"
site:target.example filetype:graphql

# Testing UIs (often forgotten on staging)
site:target.example "RapiDoc"
site:target.example inurl:rest
```

### Stage 7 — Framework-Specific Default Pages

Detect-then-dork: if `known_tech_stack` shows a framework, jump straight to its dorks; otherwise run the full set.

#### Spring Boot / Java
```
site:target.example inurl:actuator
site:target.example inurl:actuator/env
site:target.example inurl:actuator/health
site:target.example inurl:actuator/beans
site:target.example inurl:actuator/heapdump
site:target.example inurl:actuator/threaddump
site:target.example inurl:actuator/mappings
site:target.example "Whitelabel Error Page"
site:target.example "Spring Boot"
site:target.example inurl:hystrix
site:target.example intitle:"Hystrix Dashboard"
site:target.example inurl:jolokia
```

#### Django / Flask / FastAPI
```
site:target.example "DEBUG = True"
site:target.example "Django Version"
site:target.example "Werkzeug Powered Debugger"
site:target.example "Werkzeug" inurl:console
site:target.example "Flask" "DEBUG"
site:target.example "FastAPI" inurl:docs
site:target.example inurl:django-admin
site:target.example "Django administration"
site:target.example "Page not found" "Using the URLconf"
```

#### Laravel / PHP
```
site:target.example "Whoops, looks like something went wrong"
site:target.example "Laravel" "Whoops"
site:target.example inurl:_ignition
site:target.example inurl:laravel.log
site:target.example inurl:storage/logs
site:target.example "Stack trace" "Laravel"
site:target.example inurl:phpinfo.php
site:target.example intitle:"phpinfo()"
```

#### Express / Node / Next.js
```
site:target.example "X-Powered-By: Express"
site:target.example "Cannot GET /"
site:target.example inurl:_next/static
site:target.example "next-build-id"
site:target.example "Module not found" "Cannot find module"
```

#### Ruby on Rails
```
site:target.example "Action Controller" "Exception"
site:target.example "Rails.root"
site:target.example inurl:rails/info
site:target.example inurl:rails/info/properties
site:target.example inurl:rails/info/routes
site:target.example "We're sorry" "but something went wrong"
```

#### .NET / IIS
```
site:target.example "Server Error in" "Application"
site:target.example "Microsoft .NET Framework"
site:target.example inurl:Trace.axd
site:target.example inurl:elmah.axd
site:target.example "ASP.NET" "version"
site:target.example filetype:asmx
site:target.example "Internal Server Error" inurl:.aspx
site:target.example inurl:web.config
```

#### CI / CD platforms
```
site:target.example intitle:"Jenkins"
site:target.example inurl:jenkins
site:target.example inurl:job/ inurl:configure
site:target.example "Welcome to GitLab"
site:target.example inurl:gitlab
site:target.example "Bitbucket"
site:target.example "TeamCity"
site:target.example "Concourse"
site:target.example "Drone CI"
site:target.example "Argo CD"
```

#### Issue trackers / wikis
```
site:target.example "Atlassian Jira"
site:target.example inurl:jira
site:target.example inurl:secure/Dashboard
site:target.example "Confluence" inurl:wiki
site:target.example "Confluence" inurl:display
site:target.example inurl:rest/api
```

#### Monitoring / observability
```
site:target.example inurl:grafana
site:target.example "Grafana" intitle:"Login"
site:target.example "Kibana"
site:target.example inurl:_plugin/kibana
site:target.example "Prometheus" inurl:metrics
site:target.example inurl:metrics
site:target.example inurl:status
site:target.example inurl:health
site:target.example inurl:healthz
site:target.example inurl:readiness
site:target.example inurl:liveness
site:target.example "server-status"
site:target.example "server-info"
```

#### Mail / Messaging / Other
```
site:target.example "RabbitMQ Management"
site:target.example "Apache Kafka"
site:target.example inurl:console "Solr"
site:target.example inurl:elasticsearch
site:target.example inurl:_cat/
site:target.example inurl:phpmyadmin
site:target.example inurl:adminer
site:target.example "phpMyAdmin"
```

### Stage 8 — Cloud Bucket Cross-Domain Dorks

The target's content frequently sits in third-party cloud storage. Use Google to enumerate by content reference.

```
# AWS S3
site:s3.amazonaws.com "target.example"
site:s3.amazonaws.com inurl:target
site:s3-eu-west-1.amazonaws.com inurl:target
site:s3-us-west-2.amazonaws.com inurl:target
site:s3.us-east-2.amazonaws.com inurl:target

# Google Cloud Storage
site:storage.googleapis.com "target.example"
site:storage.googleapis.com inurl:target

# Azure Blob
site:blob.core.windows.net "target.example"
site:blob.core.windows.net inurl:target

# DigitalOcean Spaces
site:digitaloceanspaces.com "target.example"

# Cloudflare R2 / public buckets
site:r2.dev "target.example"

# Backblaze B2
site:backblazeb2.com inurl:target

# Wasabi
site:wasabisys.com inurl:target

# Generic cross-bucket via target keyword
"target" site:s3.amazonaws.com filetype:zip
"target" site:storage.googleapis.com filetype:csv
```

### Stage 9 — Targeted Indexed Subdomain Sweep

After Stages 1-8, you have a candidate subdomain set. Now dork PER subdomain to find what each one indexes that the apex doesn't.

For each `subdomain.target.example`:
```
site:subdomain.target.example
site:subdomain.target.example inurl:admin
site:subdomain.target.example filetype:env
site:subdomain.target.example intitle:"index of"
site:subdomain.target.example intext:"DEBUG"
```

Subdomain-specific framework dorks if the subdomain looks dev/staging:
```
site:dev.target.example "DEBUG = True"
site:staging.target.example inurl:swagger
site:qa.target.example intitle:"phpinfo()"
site:internal.target.example
site:test.target.example
site:sandbox.target.example
site:beta.target.example
site:preview.target.example
```

### Stage 10 — Cache & Snapshot Recovery

Pages that 404 today may live in Google's cache.

```
cache:target.example/admin
cache:dev.target.example/.env
```

For pages that have been removed but Google still references, the `cache:` operator returns Google's last-rendered copy. If `cache:` returns nothing, pivot to `recon_archive_intel` for archive.org / common-crawl recovery.

### Stage 11 — AROUND, Wildcard, & Phrase Refinement

When narrow queries return too many results, add structural refinements.

```
# AROUND(N) — proximity
"target" AROUND(5) "production"
"target.example" AROUND(3) "internal"
"admin" AROUND(2) "panel" site:target.example

# Wildcard *
"target.example/api/*/admin"
"https://*.target.example/_internal"

# Phrase
"target.example/.env"
"DATABASE_URL=postgres" site:target.example

# Negation chains
site:*.target.example -www -api -blog -docs -support -status -help
```

## Operator Reference (Comprehensive)

| Operator | What it does | When to use | Example |
|----------|-------------|-------------|---------|
| `site:` | Restrict to a domain | Always — anchor every dork | `site:target.example` |
| `inurl:` | Match in URL path | Find specific paths/segments | `inurl:admin` |
| `intitle:` | Match in `<title>` tag | Hunt page-type signatures | `intitle:"index of"` |
| `intext:` | Match in body text | Hunt error strings, leaked phrases | `intext:"stack trace"` |
| `allintext:` | All terms must be in body | Multi-keyword body search | `allintext:DEBUG password` |
| `allinurl:` | All terms must be in URL | Multi-keyword path | `allinurl:admin login` |
| `allintitle:` | All terms must be in title | Multi-keyword title | `allintitle:admin login` |
| `filetype:` | File extension match | Hunt specific filetypes | `filetype:env` |
| `ext:` | Same as filetype | Shorter alias | `ext:bak` |
| `link:` | Pages linking to URL (deprecated; partial) | Backlink discovery (limited) | `link:target.example` |
| `related:` | Pages similar to URL | Discover sister sites | `related:target.example` |
| `cache:` | Google's cached snapshot | Recover deleted pages | `cache:target.example/admin` |
| `daterange:` | Julian date range | Time-bounded indexing | `daterange:2459200-2459565` |
| `before:` / `after:` | Calendar date filters | Find recent / older pages | `after:2024-01-01` |
| `AROUND(N)` | Proximity (N words apart) | Co-occurrence dorks | `"admin" AROUND(3) "panel"` |
| `*` | Wildcard term | Pattern fill-in | `"target.example/api/*/v1"` |
| `-` | Exclude | Strip noise (`-www`) | `site:*.target.example -www` |
| `OR` / `\|` | Either term | Union of variants | `inurl:admin OR inurl:login` |
| `( )` | Grouping | Logic precedence | `(inurl:admin OR inurl:login) -inurl:demo` |
| `"phrase"` | Exact phrase | Anchor on string | `"DATABASE_URL=postgres"` |
| `define:` | Dictionary definition | Almost never useful for recon | `define:cors` |
| `info:` | Page info card | Quick metadata | `info:target.example` |

## Programmable Search Engine (PSE) and Scraping

For repeatable / scriptable execution:

1. **Custom Search API**: register at Google Cloud Console; create a Programmable Search Engine that searches the entire web; obtain a `cx` ID and `key` API key. Free quota: 100 queries/day; paid: $5 / 1000.
   ```
   curl -s "https://www.googleapis.com/customsearch/v1?key={KEY}&cx={CX}&q=site%3Atarget.example+filetype%3Aenv" | jq '.items[].link'
   ```
2. **No-API scraping**: with `curl`, set a realistic User-Agent and `Accept-Language`. Rotate exit IP if available. Pace queries (one every 10-15s) to avoid CAPTCHA.
   ```
   curl -s -A "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/123.0" \
        "https://www.google.com/search?q=site%3Atarget.example+filetype%3Aenv&num=100"
   ```
3. **HTML parsing**: extract `<a class="..." href="/url?q={URL}&...">` links; URL-decode the `q` param; deduplicate.
4. **Pagination**: `&start=10`, `&start=20`, ..., `&start=290`. Google caps around `start=290`.
5. **`num=100`**: passing `num=100` returns up to 100 results per page; some queries silently revert to 10.
6. **Locale anchors**: `&hl=en&gl=us` pins language and geographic node — useful when result mix differs across regions.

When Google issues a CAPTCHA: pause; rotate IP; lower query rate; resume after cooldown from the last unexecuted query.

## Layered Query Refinement (Methodology)

Three layers, executed in sequence per category.

### Layer 1 — Broad
Establish total surface. `site:target.example`, `site:*.target.example`, etc.

### Layer 2 — Narrow
Add one operator. `site:target.example inurl:admin`, `site:target.example filetype:env`, `site:target.example intitle:"index of"`.

### Layer 3 — Specific
Stack 2+ operators with phrase anchors. `site:target.example filetype:env "DB_PASSWORD"`, `site:target.example intitle:"index of" "passwd"`, `site:target.example inurl:.git/config "url ="`.

When Layer 3 returns 0 results, generate Layer 3 variants with synonyms and continue. `password` → `passwd`, `pwd`, `pass`, `secret`, `credential`. `admin` → `administrator`, `root`, `superuser`, `manager`, `console`, `control`.

## Decision Tree

```
Stage 1 (broad surface) — got result counts?
  ├─ Apex returns 0 results
  │    → target may be heavily de-indexed; pivot HARDER to recon_yandex_dorking and recon_archive_intel
  │    → still run all subsequent stages — even de-indexed targets leak via subdomains and cache
  └─ continue

Stage 2-7 — every category gets all three layers regardless of Layer 1 yield
  ├─ Layer 1 returns hits → still run Layer 2 + Layer 3 (specificity reveals what broad misses)
  └─ Layer 1 returns 0 → still run Layer 2 + Layer 3 (Google's relevance ranking can hide narrow matches behind broad noise)

Stage 8 (cloud) — always run; bucket leaks are independent of target's own index
Stage 9 (per-subdomain) — runs only after a candidate subdomain set exists
Stage 10 (cache) — runs against every URL discovered in Stages 1-9 that returns 404 today
Stage 11 (refinement) — runs whenever any Layer 3 returns >100 results (refine) or 0 results (synonym variants)

CAPTCHA?
  → cool down 5-15 min; rotate UA; lower query rate; resume from last query NOT YET executed.
  → never use CAPTCHA as a termination signal.

Empty result?
  → it is an answer, not a dead end. Record `{query, 0_results, timestamp}`. Move to next query.

Subdomain candidate from another stage?
  → return to Stage 9 with that subdomain.
```

## Common Dork Categories (target-agnostic checklist)

Per anchor / subdomain, verify each category has been swept:

- [ ] Broad surface (`site:` apex + wildcard)
- [ ] Login / auth pages (`inurl:login | signin | auth | admin`)
- [ ] Sensitive files (`filetype:env | conf | yaml | json | properties`)
- [ ] Backups (`ext:bak | old | swp | tar | zip | gz | rar | 7z`)
- [ ] Database dumps (`ext:sql | sqlite | mdb`)
- [ ] Logs (`ext:log` + error keywords)
- [ ] Office docs (`filetype:pdf | doc | docx | xls | xlsx | ppt | pptx | csv` + confidential keywords)
- [ ] Errors / debug (`intext:"stack trace" | "traceback" | "fatal error"`)
- [ ] Index pages (`intitle:"index of"`)
- [ ] API specs (`inurl:swagger | openapi | graphql | redoc | rapi-doc`)
- [ ] Spring Boot actuator
- [ ] Django / Flask / FastAPI debug
- [ ] Laravel / PHP debug
- [ ] Express / Node / Next.js
- [ ] Rails
- [ ] .NET / IIS
- [ ] Jenkins / GitLab / Bitbucket / TeamCity / Concourse / Drone / Argo
- [ ] Jira / Confluence
- [ ] Grafana / Kibana / Prometheus / metrics
- [ ] phpMyAdmin / Adminer / Solr / Elasticsearch
- [ ] Cloud buckets (S3 / GCS / Azure Blob / DO Spaces / R2 / B2 / Wasabi)
- [ ] Per-subdomain sweep (Stages 1-7 repeated against each interesting subdomain)
- [ ] Cache recovery for any 404'd URL
- [ ] AROUND / wildcard / phrase refinement for high-yield categories

## Pitfalls

- **CAPTCHA after N queries**: pace at 10-15s/query unauthenticated; longer if you hit a CAPTCHA. Cool down and resume from the last unexecuted query — CAPTCHA is a delay, not a termination signal.
- **Result count != actual matches**: Google reports estimated counts; the actual distinct URLs available are capped near 290-300 per query (paginate to `&start=290`). To dig past the cap, refine with a tighter operator stack so result count drops below the cap.
- **Regional index drift**: `&gl=us` vs `&gl=de` vs `&gl=in` produce different result sets for the same query. For targets with regional presence, run high-yield queries against multiple `gl` values.
- **JS-rendered pages don't index**: a fully-client-rendered SPA without SSR is invisible to Google's crawler. Pivot to `recon_archive_intel` (archive captures pre-render) and live JS analysis via `js_analysis`.
- **Captures of dynamic pages**: a page with personalized content may have an indexed snapshot from a logged-out crawl. The snapshot may differ from what a logged-in user sees today.
- **Link rot / dead URLs**: 60-90% of Layer 1 / Layer 2 results may 404 today; use `cache:` and `recon_archive_intel` to recover.
- **`link:` operator deprecation**: Google de-prioritized `link:` years ago; partial coverage at best. Use Yandex's `link:` instead (covered in `recon_yandex_dorking`).
- **`daterange:` requires Julian dates**: convert calendar → Julian (e.g., `2459200` ≈ `2020-12-09`). `before:` / `after:` are calendar-friendly alternatives.
- **Operator stacking limits**: stacking >5 operators sometimes silently drops the deepest one. Test critical queries by removing one operator at a time to verify all are honored.
- **Phrase escaping**: backslash inside `"phrase"` is not honored; URL-encode the entire phrase if it contains characters Google treats specially (`/`, `?`, `=`).
- **`filetype:` is content-type-driven**: a `.env` served as `text/plain` may return zero results under `filetype:env` but appear under `intext:".env"`. Always test both.
- **Personalized results**: agents should query in incognito-equivalent mode (no cookies, no user signals). The Custom Search API returns un-personalized results by default.

## Output Format

`recon/{target}/google_dorks.json` — append-mode, one record per executed query:

```json
{
  "stage": 3,
  "category": "sensitive_file",
  "layer": 2,
  "dork_query": "site:target.example filetype:env",
  "executed_at": "2026-05-03T10:14:00Z",
  "result_count": 47,
  "top_urls": [
    "https://dev.target.example/.env.staging",
    "https://target.example/api/.env.example",
    "..."
  ],
  "notable_findings": [
    {
      "url": "https://dev.target.example/.env.staging",
      "snippet": "DATABASE_URL=postgres://app:REDACTED@db-internal.target.example:5432/prod",
      "discovered_anchor": "db-internal.target.example",
      "feeds_skill": "recon_passive_subdomain"
    }
  ],
  "next_layer_queries": [
    "site:target.example filetype:env \"DB_PASSWORD\"",
    "site:target.example filetype:env \"AWS_SECRET\""
  ]
}
```

Aggregate `recon/{target}/dork_subdomain_pool.txt` (subdomain candidates discovered across stages) feeds back into Stage 9.

## Composes With

- **`recon_yandex_dorking`** — run the SAME Stage 2-8 dork lists against Yandex; result divergences are usually the high-value ones (different crawler reach).
- **`recon_github_intel`** — hostnames found in GitHub configs (Stage 2 axis B output) become Layer 3 phrase anchors here (`"db-internal.target.example" site:target.example`).
- **`recon_archive_intel`** — every 404'd URL discovered here goes to archive recovery; conversely, archived URLs' `inurl:` paths feed back as Layer 2 Google dorks.
- **`recon_information_disclosure`** — file dorks (env, conf, log, dumps) directly produce disclosure findings; this skill feeds the disclosure validation pipeline.
- **`recon_passive_subdomain`** — every `site:*.target.example` and Stage 9 sweep returns subdomain candidates that get DNS-resolved and probed.

## Termination Policy

The dork sweep terminates when ALL of the following are true:

- Stages 1-8 have been executed against every entry in `target_root_domain` plus `target_alt_domains`
- Each Stage 2-8 category has been swept at all three layers (broad / narrow / specific)
- Stage 7 has been executed for every framework on the framework list, regardless of `known_tech_stack` (the stack list is incomplete by definition)
- Stage 9 has been executed against every subdomain discovered in Stages 1-8
- Stage 10 (cache) has been attempted for every 404'd URL produced anywhere in Stages 1-9
- Stage 11 refinements have been generated for every Layer 3 query that returned >100 results (refine) and every Layer 3 that returned 0 (synonym variants)
- Per-subsidiary domain in `target_alt_domains` has had its own full Stage 1-9 pass

A CAPTCHA is a delay, not a termination. A zero-result is data, not a stop. The sweep is complete when the checklist is fully ticked across every anchor, not when an early query suggests "looks empty here".
