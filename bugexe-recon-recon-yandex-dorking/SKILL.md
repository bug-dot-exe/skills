---
name: recon_yandex_dorking
category: reconnaissance
description: Yandex search dorking — different crawler, different index, different deindex rules from Google. Methodology-first replacement for one-shot scrapers — exhaustive parallel pass to surface what Google misses, with operator-by-operator parity, divergence analysis, and cache snapshot recovery.
trigger: passive recon stage where Google dorking has been (or is being) run; need to catch pages Google de-indexed or never crawled; need older cached snapshots; target has eastern-european / Russian-locale presence; target sites that block Googlebot but not YandexBot
composes_with: recon_google_dorking, recon_github_intel, recon_archive_intel, recon_information_disclosure, recon_passive_subdomain
depends_on: []
---

# Recon — Yandex Dorking (Deep)

## Purpose

Yandex is the second-largest non-Chinese search index. Its crawler (YandexBot) reaches sites that block Googlebot, retains older snapshots Google has aged out, and indexes regional pages from eastern-european and CIS markets that Google deprioritizes. Many bug-bounty findings live in the divergence between Google and Yandex: pages that exist on the live target, pass health checks, host an exposed admin panel — and never appear in Google because of a stale `robots.txt`, a Cloudflare bot rule, or a deindex request that only propagated to Google. Running Yandex with the same dork tree as Google, then analyzing where the result sets disagree, surfaces those pages. Subprocess scrapers and one-engine-only recon miss them. This skill is the methodology a reasoning agent uses to walk the same dork tree on Yandex with operator-aware translation, capture divergence, and feed the divergence forward.

## When to Use

- Anytime `recon_google_dorking` is being run (Yandex runs in parallel)
- Target has any regional / eastern-european presence (cyrillic content, regional TLD, .ru / .by / .kz / .uz reach)
- Google returns suspiciously low result counts — Google may be deindexing
- Target site sets `User-agent: Googlebot \n Disallow: /` in robots.txt but is still publicly reachable (YandexBot crawls anyway if not explicitly excluded)
- Need older cached snapshots than Google retains (Yandex frequently caches 2-5x longer)
- Confirming GitHub-leaked hostnames against an alternate index (Stage 2 of `recon_google_dorking` may miss what Yandex sees)
- Cross-checking subdomain pool against an independent crawler

## Inputs (runtime-derived)

- `target_root_domain` — primary apex (`target.example`)
- `target_alt_domains` — subsidiary / acquisition domains
- `known_subdomains` — from prior recon
- `google_dork_results` — output from `recon_google_dorking` if available; used for divergence analysis
- `known_tech_stack` — Wappalyzer / fingerprinting hints
- `extra_keywords` — internal product names / codenames
- Optional `YANDEX_API_KEY` — XML-API key for unauthenticated quota uplift (free tier exists)

## Methodology

### Stage 1 — Operator Parity Mapping

Yandex's operators look like Google's, but several behave differently. Establish a working translation before generating queries.

| Concept | Google | Yandex | Notes |
|---------|--------|--------|-------|
| Domain anchor | `site:target.example` | `site:target.example` | Both. Yandex also accepts `host:` for stricter hostname match (no subdomain). |
| Wildcard subdomain | `site:*.target.example` | `host:target.example` (with `rhost:`) | Yandex's `rhost:` reverses-match: `rhost:example.target.*` |
| Path match | `inurl:admin` | `inurl:admin` or `url:*admin*` | Both work; `url:` is broader. |
| Title match | `intitle:"login"` | `title:login` | No space-quote needed in Yandex; spaces should be replaced with `+`. |
| Body match | `intext:"DEBUG"` | `text:DEBUG` | |
| Anchor match | (no operator) | `anchor:"target"` | Match in inbound link anchor text — unique Yandex capability. |
| Filetype | `filetype:env` | `mime:env` (and partial `domain:` quirks) | Yandex's `mime:` aligns more with content type than file extension; cross-validate by also `url:.env`. |
| Language | (n/a; `lr=` URL param) | `lang:en` | Filter by detected language. Useful to scope to English content of a Russian target's site. |
| Date | `daterange:` / `before:` / `after:` | `date:YYYYMMDD..YYYYMMDD` | Yandex date filter is via URL or via the `&within=N` param (within last N days). |
| Phrase | `"phrase"` | `"phrase"` or `! exact word` | Use `!word` for an EXACT inflectional match (no morphological expansion). |
| Negation | `-term` | `-term` or `~~term` (soft-negation) | |
| OR | `OR` / `\|` | `\|` only (case-insensitive) | `OR` alone is treated as a literal in Yandex; use `\|`. |
| Grouping | `( )` | `( )` | |
| Cache | `cache:url` | `https://yandexwebcache.net/yandbtm?url=URL` | Direct URL pattern; no operator. |
| Backlinks | `link:` (deprecated) | `link:` | Yandex still honors `link:` better than Google. |
| Related | `related:` | (limited) | Yandex's similar-page surface is in the SERP UI, not via operator. |
| Sentence | (n/a) | `<<phrase>>` | Match phrase within a sentence boundary — Yandex-only. |
| Site-region | `gl=us` URL param | `lr=N` URL param | `lr=213` = Moscow, `lr=10000` = global non-Russian. |

For every Google dork in `recon_google_dorking`, translate via this table before submitting. Do not assume Google syntax works as-is on Yandex.

### Stage 2 — Parallel Dork Sweep (Stages 1-7 of `recon_google_dorking`)

Mirror the entire Google sweep on Yandex. Same categories, translated operators.

#### Broad surface

```
site:target.example
site:target.example -site:www.target.example
host:target.example
host:*.target.example
rhost:example.target.*
```

#### Login / auth

```
site:target.example inurl:login
site:target.example url:*signin*
site:target.example title:login
site:target.example title:admin
site:target.example title:dashboard
site:target.example url:auth | url:sso | url:oauth | url:saml
site:target.example url:portal | url:console | url:internal
```

#### Sensitive files

```
site:target.example mime:env
site:target.example url:.env
site:target.example mime:cfg | mime:conf | mime:ini | mime:yml | mime:yaml
site:target.example mime:json url:config
site:target.example mime:properties
site:target.example mime:tf | mime:tfstate
site:target.example url:docker-compose.yml
site:target.example url:Dockerfile
site:target.example url:kubeconfig
site:target.example url:values.yaml

# Backups
site:target.example mime:bak | mime:old | mime:swp | mime:tmp | mime:save | mime:orig
site:target.example mime:zip | mime:tar | mime:gz | mime:rar | mime:7z
site:target.example mime:sql | mime:db | mime:sqlite | mime:mdb

# Logs
site:target.example mime:log
site:target.example mime:log text:error
site:target.example mime:log text:exception

# Office docs
site:target.example mime:pdf "confidential"
site:target.example mime:pdf "internal use only"
site:target.example mime:doc | mime:docx | mime:xls | mime:xlsx | mime:csv | mime:ppt | mime:pptx
site:target.example mime:txt text:password

# Source / scripts
site:target.example mime:sh text:password
site:target.example mime:py text:API_KEY
site:target.example mime:js text:apiKey
site:target.example mime:php text:mysql_connect

# VCS exposure
site:target.example url:.git | url:.svn | url:.hg
```

#### Errors / debug

```
site:target.example text:"stack trace"
site:target.example text:"Traceback (most recent call last)"
site:target.example text:"fatal error"
site:target.example text:"sql syntax"
site:target.example text:"ORA-"
site:target.example text:"PG::"
site:target.example text:"SQLSTATE"
site:target.example text:"Whoops" mime:html
site:target.example text:"DEBUG = True"
site:target.example text:"Werkzeug"
site:target.example text:"Spring Boot" text:"Whitelabel Error"
site:target.example text:".NET" text:"unhandled exception"
site:target.example text:"/var/www/" text:"on line"
site:target.example text:"C:\\inetpub\\" text:"line"
```

#### Index pages

```
site:target.example title:"index of /"
site:target.example title:"index of" text:"parent directory"
site:target.example title:"index of" url:backup
site:target.example title:"index of" url:upload
site:target.example title:"index of" url:logs
site:target.example title:"index of" url:config
site:target.example title:"index of" text:passwd
site:target.example title:"index of" text:".env"
```

#### API / docs surfaces

```
site:target.example url:swagger | url:swagger-ui | url:swagger.json | url:swagger.yaml
site:target.example url:openapi.json | url:openapi.yaml
site:target.example url:api/docs | url:api-docs | url:redoc | url:rapi-doc
site:target.example title:"swagger ui"
site:target.example url:graphql | url:graphiql | url:playground
site:target.example text:"GraphQL Playground"
site:target.example text:"__schema"
site:target.example mime:yaml text:"openapi:"
site:target.example mime:json text:"swagger" text:"info"
site:target.example mime:graphql
```

#### Framework defaults

Spring Boot:
```
site:target.example url:actuator
site:target.example url:actuator/env
site:target.example url:actuator/heapdump
site:target.example url:actuator/threaddump
site:target.example title:"Hystrix Dashboard"
site:target.example url:jolokia
```

Django / Flask / FastAPI:
```
site:target.example text:"DEBUG = True"
site:target.example text:"Django Version"
site:target.example text:"Werkzeug Powered Debugger"
site:target.example text:"Werkzeug" url:console
site:target.example url:django-admin
site:target.example text:"Page not found" text:"Using the URLconf"
site:target.example url:docs (FastAPI auto-docs)
```

Laravel / PHP:
```
site:target.example text:"Whoops, looks like something went wrong"
site:target.example text:"Laravel" text:"Whoops"
site:target.example url:_ignition
site:target.example url:laravel.log
site:target.example url:storage/logs
site:target.example url:phpinfo.php
site:target.example title:"phpinfo()"
```

Express / Node / Next.js:
```
site:target.example text:"X-Powered-By: Express"
site:target.example text:"Cannot GET /"
site:target.example url:_next/static
site:target.example text:"next-build-id"
```

Rails:
```
site:target.example text:"Action Controller" text:"Exception"
site:target.example text:"Rails.root"
site:target.example url:rails/info
site:target.example url:rails/info/routes
```

.NET / IIS:
```
site:target.example text:"Server Error in" text:"Application"
site:target.example text:"Microsoft .NET Framework"
site:target.example url:Trace.axd
site:target.example url:elmah.axd
site:target.example url:web.config
site:target.example mime:asmx
```

CI / CD:
```
site:target.example title:"Jenkins"
site:target.example url:jenkins
site:target.example url:job/ url:configure
site:target.example text:"Welcome to GitLab"
site:target.example url:gitlab
site:target.example text:"Bitbucket"
site:target.example text:"TeamCity" | text:"Concourse" | text:"Drone CI" | text:"Argo CD"
```

Issue trackers / wikis:
```
site:target.example text:"Atlassian Jira"
site:target.example url:jira
site:target.example url:secure/Dashboard
site:target.example text:"Confluence" url:wiki
site:target.example text:"Confluence" url:display
```

Monitoring / observability:
```
site:target.example url:grafana
site:target.example title:"Grafana" title:"Login"
site:target.example text:"Kibana"
site:target.example url:_plugin/kibana
site:target.example text:"Prometheus" url:metrics
site:target.example url:metrics | url:status | url:health | url:healthz | url:readiness | url:liveness
site:target.example text:"server-status" | text:"server-info"
```

Mail / messaging / databases:
```
site:target.example text:"RabbitMQ Management"
site:target.example text:"Apache Kafka"
site:target.example text:"Solr" url:console
site:target.example url:elasticsearch | url:_cat/
site:target.example url:phpmyadmin | url:adminer
site:target.example text:"phpMyAdmin"
```

### Stage 3 — Cloud Bucket Cross-Domain (Yandex Index)

Yandex indexes some cloud storage buckets Google misses (especially DigitalOcean Spaces and Backblaze B2 in regional buckets).

```
site:s3.amazonaws.com text:"target.example"
site:s3.amazonaws.com url:target
site:storage.googleapis.com text:"target.example"
site:storage.googleapis.com url:target
site:blob.core.windows.net text:"target.example"
site:blob.core.windows.net url:target
site:digitaloceanspaces.com text:"target.example"
site:r2.dev text:"target.example"
site:backblazeb2.com url:target
site:wasabisys.com url:target

# Cross-bucket via target keyword
"target" site:s3.amazonaws.com mime:zip
"target" site:storage.googleapis.com mime:csv
```

### Stage 4 — Per-Subdomain Sweep

For each subdomain candidate from prior recon, run Stage 2 categories scoped to that subdomain.

```
site:dev.target.example
site:staging.target.example
site:qa.target.example
site:internal.target.example
site:test.target.example
site:beta.target.example
site:preview.target.example
site:sandbox.target.example
```

For each: rotate the Stage 2 category list (login, sensitive file, errors, index, api, framework defaults).

### Stage 5 — Cache & Snapshot Recovery (Yandex Cache)

For URLs that 404 today, Yandex's cache often holds an older copy than Google's.

```
# URL-based access
https://yandexwebcache.net/yandbtm?url=https%3A%2F%2Ftarget.example%2Fadmin

# In-SERP "saved copy" link — the SERP itself shows a "сохранённая копия" link beside each result
```

For each 404'd URL discovered anywhere in the recon stack, attempt:
1. Yandex cache via `yandexwebcache.net`
2. If empty, fall through to `recon_archive_intel` for archive.org / common-crawl

### Stage 6 — Backlink and Anchor Discovery (Yandex-unique)

Yandex still honors `link:` and offers `anchor:`. Use them to find pages that LINK TO the target (revealing partner integrations, leak forums, third-party docs).

```
link:target.example
link:dev.target.example
link:internal.target.example

# Anchor text discovery — pages whose inbound link text mentions target
anchor:"target"
anchor:"target internal"
anchor:"target admin"

# Sentence-bound match
<<target.example admin>>
<<target internal portal>>
```

### Stage 7 — Language and Region Targeting

Yandex's `lang:` and `lr=` (region) parameters let you slice the index. Use to:

1. Find non-English content of an English target (foreign translations of internal docs)
2. Find Russian-language indexed copies of the target's content (sometimes leak via translation services)
3. Find regional content if target has CIS / Russian / Belarusian / Kazakh presence

```
site:target.example lang:en
site:target.example lang:ru
site:target.example lang:de
site:target.example lang:fr

# Region-anchored — &lr=213 (Moscow) etc.
# Issued via URL: https://yandex.com/search/?text=site%3Atarget.example&lr=213
```

### Stage 8 — Divergence Analysis (Google vs Yandex)

The highest-value step. Compare result sets per dork:

For each dork executed in BOTH `recon_google_dorking` AND this skill:

1. Collect Google's URL set: `G = google_dork_results[dork].top_urls`
2. Collect Yandex's URL set: `Y = yandex_dork_results[dork].top_urls`
3. Compute:
   - `Y \ G` — URLs Yandex found that Google did NOT
   - `G \ Y` — URLs Google found that Yandex did NOT
   - `G ∩ Y` — common
4. **The set `Y \ G` is the highest-value finding**. These are pages live on the target that Google has not indexed. Document each:
   - Why might Google miss it? (robots.txt rule? CDN bot block? deindex request? recently published? technical crawl issue?)
   - Is the page live now? (HEAD request — but only if active probing is in scope)
5. The set `G \ Y` indicates Yandex's coverage gap; rare but possible. Document but lower priority.
6. The intersection is "confirmed indexed both ways" — high confidence the page is real.

### Stage 9 — Yandex XML API (Programmatic)

For repeatable execution, use the Yandex XML search API.

1. Register at `https://xml.yandex.com` for an API key (or `https://xml.yandex.ru` for the Russian region).
2. Free tier: 1000 queries/month per IP-bound key; can be uplifted on request.
3. Submit query:
   ```
   curl -s "https://yandex.com/search/xml?folderid={FID}&apikey={KEY}&query=site%3Atarget.example+url%3A.env&lr=10000&l10n=en&filter=none&maxpassages=2&groupby=attr%3D.mode%3Ddeep.groups-on-page%3D10.docs-in-group%3D3"
   ```
4. Response is XML (`<searchresult>` → `<doc>` → `<url>`, `<title>`, `<headline>`); parse with `xmllint` / `xq` / `python -c "from xml.etree import ElementTree as ET; ..."`
5. Pagination via `&page=N` (0-indexed).
6. Set `&l10n=en` to receive locale-neutral results.

### Stage 10 — No-API Scraping Fallback

When no XML API key is available, scrape the SERP directly:

```
curl -s -A "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/123.0" \
     -H "Accept-Language: en-US,en;q=0.9" \
     "https://yandex.com/search/?text=site%3Atarget.example+url%3A.env"
```

Pace: 5-15s per query. CAPTCHA enforcement is more aggressive than Google's; expect to cool down 30+ minutes after a CAPTCHA. The endpoint that issues the CAPTCHA is `/search/?text=...&captcha=...` — when seen, switch to:
1. Wait the cooldown
2. Rotate exit IP if available
3. Reduce query rate by half
4. Resume from the last query NOT YET executed (not from the start)

CAPTCHA is a delay, never a termination — resume from the last unexecuted query.

## Operator Reference (Yandex-specific, comprehensive)

| Operator | What it does | When to use | Example |
|----------|-------------|-------------|---------|
| `site:` | Restrict to a domain (incl. subdomains) | Anchor every dork | `site:target.example` |
| `host:` | Restrict to exact hostname (NO subdomains) | Pin to specific host | `host:dev.target.example` |
| `rhost:` | Reverse-match hostname pattern | Subdomain wildcards | `rhost:example.target.*` |
| `domain:` | Match TLD (sometimes interpreted as `site:`) | TLD-bounded sweep | `domain:com` |
| `inurl:` / `url:` | Match URL substring | Find paths | `url:admin` |
| `title:` | Match `<title>` tag | Page-type signature | `title:login` |
| `text:` | Match body text | Hunt error strings | `text:"stack trace"` |
| `anchor:` | Match inbound link anchor text | Discover linkers (Yandex-unique) | `anchor:"target admin"` |
| `mime:` | Match content type / extension | Filetype hunt | `mime:env` |
| `lang:` | Restrict to language | Locale slice | `lang:en` |
| `date:` | Date range (`YYYYMMDD..YYYYMMDD`) | Time-bounded | `date:20240101..20240601` |
| `link:` | Pages linking to URL | Backlink discovery | `link:target.example` |
| `cat:` | Yandex catalog category | Niche; rarely useful | `cat:1234` |
| `"phrase"` | Exact phrase | String anchor | `"DATABASE_URL=postgres"` |
| `!word` | Exact non-morphological match | Precision | `!admin` (no `admins`, `administer`) |
| `!!word` | Strict morphological lock | Lock to root | `!!admin` |
| `*` | Wildcard within phrase | Pattern fill | `"target.example/api/*"` |
| `&` | Same-sentence AND | Sentence-scoped | `target & admin` |
| `&&` | Same-document AND | Document-scoped | `target && admin` |
| `\|` | OR | Union | `admin \| login` |
| `<<phrase>>` | Phrase within sentence | Cohesion match | `<<target admin>>` |
| `( )` | Grouping | Logic precedence | `(admin \| login) -demo` |
| `-term` | Exclude | Strip noise | `site:*.target.example -www` |
| `~~term` | Soft exclude (lower rank, not strip) | Demote | `~~test` |
| `/N` | Distance N words | Proximity | `target /3 admin` |

## Operator Quirks (read before running queries)

- `OR` (literal) does NOT work in Yandex. Use `\|`. `intitle:admin OR intitle:login` will return zero results in Yandex; use `title:admin \| title:login`.
- `intitle:` works as a partial alias for `title:` but `title:` is preferred and more reliable.
- `intext:` is `text:` in Yandex.
- `filetype:` is partial; `mime:` is the canonical Yandex form. Cross-validate with `url:.ext` to catch content served with mismatched MIME.
- Yandex's morphological expansion is on by default — `target` matches `targets`, `targeted`, etc. Use `!target` to lock to the exact form.
- Phrase escaping: backslashes are NOT honored inside `"phrase"`. URL-encode the entire phrase.
- The `lr=` URL parameter (region ID) sometimes overrides query relevance heavily; force `lr=10000` (global non-Russia) for neutral runs.

## Decision Tree

```
Stage 1 (operator parity) — translation table built?
  ├─ no → STOP and build it. Without this, every Yandex query is a wasted call.
  └─ yes → proceed

For every Google dork in `recon_google_dorking`:
  → translate to Yandex syntax via the table
  → submit to Yandex
  → record top_urls and result_count

Stage 8 (divergence) — comparing result sets?
  ├─ Y \ G is non-empty → INVESTIGATE every URL in Y \ G
  │     → why does Google miss it? robots? deindex? CDN block? bot rule?
  │     → these are the high-value findings of this skill
  └─ Y \ G is empty for ALL queries → unusual; verify Yandex queries are returning ANY results
       → if Yandex universally returns 0, the operator parity is broken; revisit Stage 1

CAPTCHA?
  → cool down 30+ min; resume from last unexecuted query; lower rate by half. CAPTCHA is a delay, not a termination signal.

Cache miss in Stage 5?
  → fall through to recon_archive_intel for the same URL.

Backlink hits in Stage 6 reveal external sites?
  → those external sites are recon targets in their own right (partner / integration recon).
  → feed them back into the sweep as new domain anchors.

Empty result on a query?
  → record `{query, 0_results, timestamp}`. Move on. Do not interpret as "category empty" — the operator translation may have edge cases.
```

## Pitfalls

- **CAPTCHA is aggressive**: Yandex enforces CAPTCHA at lower query rates than Google. Pace at 8-15s/query baseline; raise to 20s/query if CAPTCHAs trigger; on CAPTCHA, cool down and resume from the last unexecuted query — the sweep continues.
- **IP-region binding**: Yandex returns different result sets based on the requesting IP's geolocation. A query from a US IP may show different results than the same query from a German IP. Use `&lr=10000` to force a region-neutral result set; otherwise, document the IP's region in the output.
- **Morphological expansion**: a query for `target` returns matches for `targets`, `targeted`, `targeting`. To pin exact: `!target`. This matters most for credential keywords (`!password` vs `password` to avoid matches on `passwords`, `passworded`, etc.).
- **MIME mismatch**: a `.env` served as `application/octet-stream` won't match `mime:env`. Always run BOTH `mime:env` AND `url:.env` AND `text:".env"` for full coverage.
- **`OR` (literal)**: not honored. Always use `\|`.
- **`site:` includes subdomains**: same as Google. Use `host:exact.target.example` to pin a single hostname.
- **Date filter granularity**: `date:` filters by Yandex's first-indexed date for that page, NOT the page's `Last-Modified` header. A page first crawled in 2023 keeps that index date even if updated daily.
- **XML API rate limits**: free tier 1000 queries/month per key + per-IP. For sweeps that need higher throughput, request quota uplift from Yandex (free, but takes 1-3 business days). Without uplift, fall back to scraping at lower rate.
- **SERP HTML changes**: Yandex's SERP structure changes more frequently than Google's. CSS selectors / regex against the HTML break. Prefer XML API; if scraping, parse defensively (the `data-cid`, `data-counter` attributes are more stable than CSS class names).
- **Cyrillic-locked terms**: search terms in cyrillic alphabet match cyrillic content; the target may have english+cyrillic. For comprehensive sweep on a multilingual target, run the same dork in both alphabets.
- **`link:` retains better than Google but is still partial**: don't expect 100% backlink coverage. Cross-validate with majestic / ahrefs / openpagerank when a stronger backlink graph is needed.
- **Cache pages can drift**: the cached snapshot reflects Yandex's last crawl, which may be 6-24 months old. Always note the snapshot timestamp in the output record.

## Output Format

`recon/{target}/yandex_dorks.json` — append-mode, one record per executed query:

```json
{
  "stage": 2,
  "category": "sensitive_file",
  "google_equivalent": "site:target.example filetype:env",
  "yandex_query": "site:target.example mime:env | url:.env",
  "executed_at": "2026-05-03T10:31:00Z",
  "result_count": 18,
  "top_urls": [
    "https://staging.target.example/.env.staging",
    "https://target-internal.example/.env",
    "..."
  ],
  "google_top_urls": [
    "https://staging.target.example/.env.staging"
  ],
  "divergence": {
    "yandex_only": ["https://target-internal.example/.env"],
    "google_only": [],
    "intersection": ["https://staging.target.example/.env.staging"]
  },
  "notable_findings": [
    {
      "url": "https://target-internal.example/.env",
      "snippet": "DATABASE_URL=postgres://app:REDACTED@db-internal.target.example:5432/prod",
      "google_indexed": false,
      "feeds_skill": "recon_information_disclosure"
    }
  ]
}
```

Aggregate `recon/{target}/divergence_yandex_only.txt` (URLs only Yandex found) feeds urgently into validation and downstream skills.

## Composes With

- **`recon_google_dorking`** — primary partner. Every dork run on Google should be translated and run on Yandex. Stage 8 (divergence) is the integration point.
- **`recon_github_intel`** — GitHub-leaked hostnames become Yandex `host:` and `text:` anchors; Yandex sometimes indexes pages on hosts Google missed.
- **`recon_archive_intel`** — when Yandex cache (Stage 5) is empty, fall through to archive.org / common-crawl for snapshot recovery; conversely, Yandex cache may hold older snapshots than archive.org has retained.
- **`recon_information_disclosure`** — every divergence-only URL (in `divergence.yandex_only`) goes straight to disclosure validation.
- **`recon_passive_subdomain`** — Stage 4 per-subdomain sweep returns subdomain candidates that get added to the subdomain pool; `host:` and `rhost:` queries reveal hostname patterns.

## Termination Policy

The sweep terminates when ALL of the following are true:

- Stage 1 operator parity table has been validated against at least one known-positive on Yandex (`site:torproject.org` etc.) to confirm operator translation is working
- Every dork in the `recon_google_dorking` Stage 1-8 set has been translated and submitted to Yandex
- Every entry in `target_root_domain ∪ target_alt_domains` has had its full Stage 2-7 sweep
- Stage 3 (cloud cross-domain) has been swept for every cloud provider in the list
- Stage 4 (per-subdomain) has been swept for every subdomain in the candidate pool
- Stage 5 (cache recovery) has been attempted for every 404'd URL produced anywhere in the recon stack
- Stage 6 (backlink / anchor) has been swept for the apex AND each high-value subdomain
- Stage 7 (language / region) has been swept with at least three language values (`en`, target's primary regional language, `ru`)
- Stage 8 (divergence) has been computed against `recon_google_dorking` output for every dork that was run on both
- Every `Y \ G` entry from Stage 8 has been documented and tagged for downstream skills

CAPTCHAs delay; they do not terminate. Empty result sets are data, not stop conditions. The sweep is complete when the checklist is fully ticked across every anchor — not when an early Yandex query returns thin results, and not when divergence analysis on the first few queries shows no `Y \ G` URLs (later queries may diverge).
