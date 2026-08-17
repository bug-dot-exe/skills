---
name: fast-recon
category: reconnaissance
description: Rapid reconnaissance with quick-win checks to run first for immediate findings
depends_on: []
---

# Fast Recon

The fastest path to findings. Run these checks first on any new target before investing time in deep enumeration. Each check takes seconds and can yield immediate vulnerabilities or critical intelligence.

## When to Use

- First minutes on a new target
- Quick assessment of an application's security posture
- Need immediate wins before deeper testing
- Triaging multiple targets to find the weakest one

## Methodology

Run these checks in order of speed and impact. Stop and investigate any positive result.

### Tier 1: Instant Checks (< 30 seconds)

1. **robots.txt** -- reveals hidden paths, admin areas, API endpoints
2. **sitemap.xml** -- complete URL map the target wants indexed
3. **Security headers** -- missing headers indicate security maturity
4. **Server fingerprint** -- technology and version from response headers
5. **Error page** -- force a 404/500, check for stack traces and framework info

### Tier 2: Quick File Exposure (< 2 minutes)

1. **.env exposure** -- database credentials, API keys, secrets
2. **.git exposure** -- full source code if `/.git/HEAD` is accessible
3. **Common backup files** -- `.bak`, `.old`, `.swp` variants of known pages
4. **Debug endpoints** -- phpinfo, debug toolbar, profiler, trace
5. **Admin panels** -- default paths for common frameworks

### Tier 3: Configuration Leaks (< 5 minutes)

1. **CORS misconfiguration** -- test with arbitrary Origin header
2. **Cookie flags** -- missing Secure, HttpOnly, SameSite on session cookies
3. **HTTP methods** -- OPTIONS, TRACE, PUT, DELETE on main paths
4. **Version disclosure** -- X-Powered-By, Server, X-AspNet-Version
5. **Default credentials** -- if admin panel found, try common defaults

### Tier 4: Platform Fingerprint and Known-Misconfig Sweep (< 5 minutes)

Every modern web app uses an identifiable backend. Recognize the platform first, then run its known-misconfig checklist:

| Platform | Fingerprint Signal | First Check |
|----------|-------------------|-------------|
| Firebase | `firebaseapp.com`, `.firebaseio.com` in JS | Append `.json` to Realtime DB URL for open read |
| Salesforce Experience Cloud | `/s/` path prefix, Aura framework | Test `/s/contentdocument/ContentDocument/All` |
| WordPress | `/wp-content/`, `/wp-json/` | `GET /wp-json/wp/v2/users` for user enum |
| Spring Boot | `X-Application-Context` header | `GET /actuator`, `/actuator/env`, `/actuator/heapdump` |
| Laravel | `laravel_session` cookie | `GET /_ignition/health-check` |
| Django | `csrfmiddlewaretoken` | `GET /__debug__/` |
| Node/Express | `X-Powered-By: Express` | `GET /.env`, `GET /graphql` with introspection |
| AWS Amplify | `amplify` in JS bundle | Check Cognito identity pool for unauth role |
| Auth0 | `.auth0.com` in JS | Test `/.well-known/openid-configuration` for scope leak |
| Hasura | `hasura` in error messages | Test introspection on `/v1/graphql` |

### Tier 5: Self-Hosted OSS Instance Sweep (< 5 minutes)

Enumerate subdomains for fingerprints of self-hosted open-source software. For each identified instance, check its public CVE list and test known default credentials:

| Software | Fingerprint | Default Path | Common Vuln |
|----------|------------|-------------|-------------|
| Jenkins | `/login`, `X-Jenkins` header | `/script` (Groovy console) | Unauthenticated RCE |
| GitLab | `/users/sign_in` | `/api/v4/projects?private=true` | Import RCE, SSRF |
| Grafana | `/login`, Grafana title | `/api/admin/settings` | Auth bypass CVEs |
| Kibana | Kibana title, port 5601 | `/app/dev_tools#/console` | Open Elasticsearch |
| Sentry | `/_health/`, Sentry DSN | `/api/0/` | SSRF via event ingestion |
| Airflow | `/airflow/login` | `/api/v1/dags` | Unauthenticated DAG trigger |

## Key Commands

```bash
TARGET="https://target.com"

# === TIER 1: Instant Checks ===

# robots.txt
curl -s "${TARGET}/robots.txt"

# sitemap.xml
curl -s "${TARGET}/sitemap.xml" | head -50

# Security and server headers
curl -sI "${TARGET}" | grep -iE "server|x-powered|x-frame|strict-transport|content-security|x-content-type|x-xss|set-cookie"

# Force error pages
curl -s -o /dev/null -w "%{http_code}" "${TARGET}/thispagedoesnotexist123"
curl -s "${TARGET}/thispagedoesnotexist123" | head -30

# === TIER 2: Quick File Exposure ===

# .env file
curl -s -o /dev/null -w "%{http_code}" "${TARGET}/.env"
curl -s "${TARGET}/.env" | head -20

# .git exposure
curl -s -o /dev/null -w "%{http_code}" "${TARGET}/.git/HEAD"
curl -s "${TARGET}/.git/HEAD"
curl -s -o /dev/null -w "%{http_code}" "${TARGET}/.git/config"

# Common sensitive files
for file in .env .env.local .env.production .env.backup \
  .git/HEAD .git/config .svn/entries \
  .DS_Store .htaccess web.config \
  wp-config.php.bak wp-config.php~ \
  package.json composer.json Gemfile \
  server-status server-info \
  elmah.axd trace.axd; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/${file}")
  [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$code /${file}"
done

# Debug and admin endpoints
for path in /admin /admin/ /administrator /login /wp-admin /wp-login.php \
  /debug /phpinfo.php /info.php /test.php \
  /console /actuator /actuator/env /actuator/health \
  /_debug /debug/default/view /elmah.axd \
  /api /api/v1 /graphql /swagger /api-docs; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}${path}")
  [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$code ${path}"
done

# === TIER 3: Configuration Checks ===

# CORS check
curl -sI "${TARGET}" -H "Origin: https://evil.com" | grep -i "access-control"

# Cookie flags
curl -sI "${TARGET}" | grep -i "set-cookie"

# HTTP methods
curl -s -o /dev/null -w "%{http_code}" -X OPTIONS "${TARGET}/"
curl -sI -X OPTIONS "${TARGET}/" | grep -i "allow"
curl -s -o /dev/null -w "%{http_code}" -X TRACE "${TARGET}/"

# Technology-specific checks (if identified)
# WordPress
curl -s -o /dev/null -w "%{http_code}" "${TARGET}/wp-json/wp/v2/users"
# Laravel
curl -s -o /dev/null -w "%{http_code}" "${TARGET}/_ignition/health-check"
# Spring Boot
curl -s -o /dev/null -w "%{http_code}" "${TARGET}/actuator"
# Django
curl -s -o /dev/null -w "%{http_code}" "${TARGET}/__debug__/"
```

## What to Look For

| Check | Finding | Severity |
|-------|---------|----------|
| `.env` accessible | Credentials, API keys | Critical |
| `.git/HEAD` accessible | Full source code recovery | Critical |
| Stack trace in error page | Internal paths, versions, DB info | Medium-High |
| `robots.txt` with admin paths | Attack surface expansion | Info (recon value) |
| Missing security headers | CSP, HSTS, X-Frame-Options absent | Low-Medium |
| CORS reflects arbitrary origin | Cross-origin data theft | Medium-High |
| TRACE method enabled | Cross-site tracing potential | Low |
| Session cookie missing flags | Session hijack risk | Low-Medium |
| Default admin credentials | Full admin access | Critical |
| Actuator/debug endpoints open | Environment variables, heap dumps | High-Critical |

## Corpus-Derived Hunting Patterns

### WAF Parser-Differential Testing

When a WAF blocks vanilla XSS payloads, do NOT abandon. Fingerprint what exactly the WAF blocks:
1. Send `<` alone, then `<script`, then `<script>` -- find the minimum blocked token
2. Try HTML comment prefix: `<!--><script>` (bypasses comment-based WAF rules)
3. Try encoding differentials: the WAF may parse UTF-8 differently than the backend
4. Test whether the WAF only inspects GET parameters but passes POST bodies through

### Subdomain Takeover Two-Tier Audit

For every subdomain discovered:
- **Tier 1 (automated)**: fingerprint CNAME against known vulnerable SaaS providers (Heroku, GitHub Pages, AWS S3 website, Shopify, Fastly, Pantheon)
- **Tier 2 (manual)**: for CNAMEs pointing to custom services, verify the service is still claimed -- a dangling CNAME to any unclaimed resource is a takeover

### SMTP Server Hunting

Scan the target for ports 25, 465, 587, 2525. For each open port:
1. Attempt `EHLO` to fingerprint the server
2. Test open relay: `MAIL FROM:<test@test.com>` then `RCPT TO:<external@other.com>`
3. Test internal relay: `RCPT TO:<admin@target.com>` from unauthenticated session
4. Check for VRFY/EXPN commands leaking valid email addresses

### GraphQL Field-Level Auth Audit

For any GraphQL endpoint discovered:
1. Introspect schema (or fingerprint via union/inline-fragment errors if introspection blocked)
2. Build a "maximum query" requesting every field of every type
3. Diff the response against what the UI shows -- extra fields = authorization gap
4. Test nested object traversal: even if top-level access is denied, nested references may resolve

## Decision Tree After Fast Recon

```
.env exposed?           --> Extract creds, test cloud/DB access
.git exposed?           --> Dump repo, full source code review
Admin panel found?      --> Test default creds, then auth bypass
API docs found?         --> Full API endpoint enumeration
Stack traces in errors? --> Note tech stack, target error-handling bugs
Nothing found?          --> Proceed to deep recon (full crawl, fuzzing, JS analysis)
```

## Tips

1. Run this on every subdomain, not just the main domain
2. Try both HTTP and HTTPS; some checks differ between them
3. Check with and without trailing slashes; routing behavior may differ
4. Save all output; even a 403 on `/admin` confirms it exists
5. If you find `.git/HEAD`, use `git-dumper` to recover the full repository
6. Login/SSO subdomains are the highest-value XSS targets on every program -- they have privileged cookie scope and broad user reach
