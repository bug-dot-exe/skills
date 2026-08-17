---
name: recon-information-disclosure
category: reconnaissance
description: Methodology for hunting accidental exposure — version control dotdirs, env files, backup artifacts, debug endpoints, source maps, error-page induction, header leaks, HTML/JS comment mining, OPTIONS/TRACE method abuse — comprehensive path inventory + multi-encoding + live verification
depends_on: []
---

# Recon Information Disclosure

## Purpose

The most consequential recon findings are not exotic — they are accidents. Configuration files committed to a public webroot. Backup tarballs left on the server during a panic deployment. Source maps that recover the entire compiled SPA. Debug endpoints baked into a framework's default install. Error pages that print database connection strings. Verbose HTTP headers that name every middleware version. Comments in HTML and JavaScript that note "FIXME: bypass auth here for staging" — alongside the bypass code that nobody removed.

This skill teaches the agent the comprehensive set of disclosure surfaces, and the multi-method/multi-encoding workflow required to find them despite WAFs, framework defaults, and "hardened" configurations.

## When to Use

- Immediately after the live-host inventory is built — before any heavy fuzzing.
- Whenever the agent finds a host that returns `403` for a generic path — that is a "exists but blocked" signal worth probing with this skill's bypass techniques.
- Whenever the agent finds a JS bundle — the `.map` companion is the highest-value target in modern web apps.
- Whenever the agent finds an admin/internal hostname pattern (`admin.`, `internal.`, `staging.`, `dev.`).
- After a WAF block — many disclosure paths bypass WAFs because they look like static asset requests.
- When the application leaks any version banner — version-specific debug paths are a very fruitful follow-up.
- After a server-side error appears in normal traffic — induce more errors to harvest stack traces.

## Inputs

- `target_hosts[]` — every confirmed live host (apex, subdomains, IPs, distinct ports).
- `target_apex` — primary domain (used for known_path heuristics like wp-config relevance).
- `tech_fingerprints[]` — output from passive fingerprinting (e.g., `nginx`, `php`, `wordpress`, `nextjs`, `springboot`, `django`, `rails`). Drives which framework-specific paths to enumerate.
- `discovered_js_bundles[]` — minified JS URLs from prior recon. The skill checks each for an exposed `.map`.

## Methodology

### Stage 1: Path Inventory (the comprehensive disclosure-path catalog)

The agent maintains the following exhaustive path catalog. Every category below is enumerated against every host. NO category is skipped because the target "looks hardened" — hardened sites still leak in at least one category.

#### 1.1 Version control directories

```
/.git/HEAD
/.git/config
/.git/index
/.git/logs/HEAD
/.git/logs/refs/heads/main
/.git/logs/refs/heads/master
/.git/logs/refs/heads/develop
/.git/logs/refs/heads/staging
/.git/refs/heads/main
/.git/refs/heads/master
/.git/refs/heads/develop
/.git/refs/heads/release
/.git/packed-refs
/.git/description
/.git/hooks/pre-commit.sample
/.git/objects/info/packs
/.git/objects/pack/
/.git/info/exclude
/.gitignore
/.gitattributes
/.gitmodules
/.gitkeep
/.svn/entries
/.svn/wc.db
/.svn/format
/.svn/pristine/
/.hg/store/manifest.i
/.hg/store/00manifest.i
/.hg/hgrc
/.bzr/branch/branch.conf
/.bzr/checkout/dirstate
/CVS/Entries
/CVS/Repository
/CVS/Root
```

If `/.git/HEAD` returns 200, the entire repo is recoverable via tools that walk pack files; the agent should record this as a critical finding even before content extraction.

#### 1.2 Environment / config files

```
/.env
/.env.local
/.env.dev
/.env.development
/.env.staging
/.env.production
/.env.prod
/.env.test
/.env.example
/.env.sample
/.env.backup
/.env.bak
/.env.old
/.env~
/.envrc
/.aws/credentials
/.aws/config
/.npmrc
/.dockerenv
/.docker/config.json
/.kube/config
/.terraform/terraform.tfstate
/terraform.tfstate
/terraform.tfstate.backup
/config.json
/config.yml
/config.yaml
/config.xml
/config.php
/configuration.php
/configuration.yml
/configurations.json
/web.config
/wp-config.php
/wp-config.php.bak
/wp-config.php.old
/wp-config.php~
/wp-config-sample.php
/settings.py
/settings.json
/settings.yml
/secrets.yml
/secrets.json
/secrets.env
/local.yml
/local.yaml
/local.json
/database.yml
/database.json
/credentials.json
/credentials.yml
/private.key
/private.pem
/server.key
/server.pem
/id_rsa
/id_dsa
/id_ed25519
/.ssh/id_rsa
/.ssh/authorized_keys
/.ssh/known_hosts
```

#### 1.3 Backup files (every variant — many WAFs miss these)

For each high-value file (`index.php`, `config.php`, `wp-config.php`, `app.py`, `main.go`, `server.js`, etc.), enumerate every common backup suffix:

```
<file>~
<file>.bak
<file>.bak1
<file>.bak2
<file>.old
<file>.orig
<file>.original
<file>.swp
<file>.swo
<file>.tmp
<file>.save
<file>.copy
<file>.backup
<file>.disabled
<file>.dist
<file>.example
<file>.sample
<file>.bk
<file>.OLD
<file>.BAK
```

Plus archive backups at the webroot:

```
/backup.zip
/backup.tar.gz
/backup.tar
/backup.tgz
/backup.7z
/backup.rar
/backup.sql
/backup.sql.gz
/backup-<YYYYMMDD>.zip      # try last 90 days of dates
/backup-2026.zip
/backup-prod.zip
/backup-staging.zip
/backup-old.zip
/site.tar
/site.tar.gz
/site.zip
/site-backup.zip
/www.zip
/www.tar.gz
/htdocs.zip
/public_html.zip
/public_html.tar.gz
/dump.sql
/dump.sql.gz
/db.sql
/db.dump
/db.bak
/database.sql
/database.sql.gz
/data.sql
/sql.zip
/sql/dump.sql
/server.zip
/release.zip
/build.zip
/dist.zip
```

#### 1.4 Debug / dev / monitoring endpoints

```
/debug
/_debug
/__debug__/
/_profiler/
/__profiler__/
/_profiler/empty/search/results
/console
/_console
/admin/console
/admin/debug
/admin/system/info
/admin/info.php
/info.php
/phpinfo.php
/test.php
/info
/test
/dev
/staging
/_dev
/_staging
/swagger
/swagger-ui
/swagger-ui.html
/swagger/index.html
/swagger.json
/swagger.yaml
/swagger.yml
/api-docs
/api-docs.json
/openapi.json
/openapi.yaml
/v1/swagger
/v2/swagger
/v3/api-docs
/redoc
/graphql
/graphiql
/playground
/altair
/voyager
/__graphql
/actuator
/actuator/env
/actuator/health
/actuator/info
/actuator/metrics
/actuator/mappings
/actuator/beans
/actuator/configprops
/actuator/threaddump
/actuator/heapdump
/actuator/jolokia
/actuator/loggers
/actuator/auditevents
/actuator/httptrace
/actuator/conditions
/actuator/scheduledtasks
/actuator/sessions
/actuator/refresh
/actuator/restart
/actuator/shutdown
/jolokia
/jolokia/list
/manage
/manage/health
/manage/env
/manage/dump
/_next/static
/_next/data
/_next/build-manifest.json
/_next/server/pages-manifest.json
/_next/server/middleware-manifest.json
/_nuxt/
/__nuxt/
/_vercel/
/sentry
/_sentry
/sentry/api/0/
/_telescope
/telescope
/horizon
/_ignition
/ignition/health-check
/_xdebug
/xdebug
/_pinpoint
/_zipkin
/_jaeger
/_grafana
/_kibana
/_prometheus
/_metrics
/metrics
/api/metrics
/healthz
/readyz
/livez
/health
/ping
/version
/_version
/build
/build-info
/api/version
/.well-known/security.txt
/.well-known/openid-configuration
/.well-known/webfinger
/.well-known/host-meta
/.well-known/apple-app-site-association
/.well-known/assetlinks.json
/.well-known/dnt-policy.txt
```

#### 1.5 CI/CD artifacts

```
/.gitlab-ci.yml
/.gitlab-ci.yaml
/.github/workflows/main.yml
/.github/workflows/deploy.yml
/.github/dependabot.yml
/.github/CODEOWNERS
/Jenkinsfile
/jenkins.xml
/azure-pipelines.yml
/.azure-pipelines/
/.circleci/config.yml
/.travis.yml
/.travis.yaml
/buildspec.yml
/buildspec.yaml
/cloudbuild.yaml
/cloudbuild.yml
/bitbucket-pipelines.yml
/Dockerfile
/Dockerfile.dev
/Dockerfile.prod
/Dockerfile.local
/docker-compose.yml
/docker-compose.yaml
/docker-compose.dev.yml
/docker-compose.prod.yml
/docker-compose.override.yml
/Makefile
/makefile
/CHANGELOG.md
/CHANGES.md
/RELEASE_NOTES.md
/UPGRADE.md
/INSTALL.md
/.dockerignore
/.codeship/
/.tekton/
/sonar-project.properties
/.sonarqube/
```

#### 1.6 Source maps (highest-value modern leak)

For each `<bundle>.js` URL discovered:

```
GET <bundle>.js.map
GET <bundle>.map
```

Also try common bundler output paths:

```
/static/js/main.<hash>.js.map
/static/js/runtime-main.<hash>.js.map
/static/js/<chunk-id>.<hash>.chunk.js.map
/build/static/js/main.<hash>.js.map
/dist/main.<hash>.js.map
/dist/<bundle>.js.map
/_next/static/chunks/main-<hash>.js.map
/_next/static/chunks/pages/_app-<hash>.js.map
/_next/static/chunks/webpack-<hash>.js.map
/assets/index.<hash>.js.map
/assets/vendor.<hash>.js.map
```

If the JS bundle doesn't have a `.map` companion at the obvious URL, check the bundle's last bytes for a `//# sourceMappingURL=...` directive — it may point to a non-obvious location (or a base64-inlined map, which is a finding in itself).

#### 1.7 Robots.txt + sitemap.xml + security.txt mining

```
GET /robots.txt
GET /robots.txt.bak
GET /sitemap.xml
GET /sitemap_index.xml
GET /sitemap.xml.gz
GET /sitemap-1.xml
GET /sitemap-news.xml
GET /sitemap-images.xml
GET /sitemap-videos.xml
GET /humans.txt
GET /security.txt
GET /.well-known/security.txt
```

Parse `robots.txt` and extract every `Disallow:` line — these are the paths the developer specifically did NOT want indexed, which is exactly the set worth probing. Parse every URL inside `sitemap.xml` (and any chained sub-sitemaps).

#### 1.8 Server-status, server-info, status pages

```
/server-status
/server-status?auto
/server-info
/nginx_status
/stub_status
/nginx-status
/status
/status.json
/api/status
/api/health
/manage/status
/admin/status
/_stats
/stats
/stats.json
/varnishstat
/haproxy-stats
/haproxy?stats
```

#### 1.9 Common documentation and meta paths

```
/README
/README.md
/README.txt
/CHANGELOG
/CHANGELOG.md
/CHANGES
/INSTALL
/INSTALL.md
/UPGRADE
/UPGRADE.md
/HISTORY
/AUTHORS
/CONTRIBUTING.md
/SECURITY.md
/.gitlab/
/.github/
/.gitea/
/.bitbucket/
/docs/
/docs/internal/
/internal-docs/
/api-docs/
/.idea/workspace.xml
/.idea/modules.xml
/.idea/.idea.<projectname>.iml
/.idea/encodings.xml
/.vscode/settings.json
/.vscode/launch.json
/.project
/.classpath
/.factorypath
/composer.json
/composer.lock
/package.json
/package-lock.json
/yarn.lock
/pnpm-lock.yaml
/Gemfile
/Gemfile.lock
/requirements.txt
/Pipfile
/Pipfile.lock
/poetry.lock
/pyproject.toml
/go.mod
/go.sum
/Cargo.toml
/Cargo.lock
/build.gradle
/pom.xml
```

#### 1.10 Framework-specific (apply when fingerprint matches)

WordPress (`tech_fingerprints` includes `wordpress`):
```
/wp-content/uploads/
/wp-content/uploads/<YYYY>/<MM>/      # try last 24 months
/wp-content/debug.log
/wp-content/plugins/
/wp-content/themes/
/wp-config.php~
/wp-config.php.bak
/wp-config-sample.php
/xmlrpc.php
/wp-json/wp/v2/users
/wp-json/wp/v2/users?search=
/wp-json/wp/v2/posts?per_page=100
/wp-json/oembed/1.0/embed?url=
/wp-admin/install.php
/wp-admin/setup-config.php
/wp-cron.php
/?author=1
/?author=2
/?p=1
```

Drupal:
```
/CHANGELOG.txt
/changelog.txt
/MAINTAINERS.txt
/UPGRADE.txt
/sites/default/files/
/sites/default/private/
/user/login
/user/register
/admin
/admin/reports/status
/admin/reports/dblog
/?q=admin
/core/CHANGELOG.txt
/core/MAINTAINERS.txt
/core/INSTALL.txt
```

Laravel:
```
/.env
/storage/logs/laravel.log
/storage/logs/laravel-<YYYY-MM-DD>.log
/_ignition/health-check
/_ignition/execute-solution
/telescope
/horizon
```

Spring Boot:
```
/actuator/*
(see 1.4)
```

Next.js:
```
/_next/data/<buildId>/<page>.json
/_next/static/chunks/
/_next/static/<buildId>/_buildManifest.js
/_next/server/pages-manifest.json
```

Django:
```
/admin/
/admin/login/
/__debug__/
/static/admin/
/api/?format=api
```

Rails:
```
/rails/info
/rails/info/properties
/rails/info/routes
/rails/mailers
```

Express/Node:
```
/node_modules/
/package.json
/yarn.lock
```

Magento:
```
/app/etc/local.xml
/app/etc/env.php
/var/log/exception.log
/var/log/system.log
/admin/
/downloader/
```

Symfony:
```
/_profiler/
/_profiler/empty/search/results?limit=10
/_wdt/
/app_dev.php
/config.php
```

#### 1.11 Cloud-specific exposure paths

```
/.aws/credentials
/.aws/config
/.azure/credentials
/.gcp/credentials.json
/credentials.json
/service-account.json
/service-account-key.json
/cloud-config.yaml
/cloud-init.yaml
/user-data
/instance-identity/document
/.kube/config
/.minikube/profiles/
/.helm/
```

### Stage 2: Method Variation (per path)

For each path in Stage 1, the agent tries multiple HTTP methods. Many WAFs and reverse proxies only filter `GET`. The following methods often surface different responses:

```
GET <path>
HEAD <path>
OPTIONS <path>           # may reveal Allow: GET, POST, PUT, DELETE, PATCH
POST <path>              # framework may handle 405 differently from real 404
PUT <path>               # publishing-misconfigured server may accept upload
DELETE <path>
PATCH <path>
TRACE <path>             # XST — server echoes the request back
PROPFIND <path>          # WebDAV
MKCOL <path>             # WebDAV
COPY <path>              # WebDAV
MOVE <path>              # WebDAV
SEARCH <path>            # WebDAV
DEBUG <path>             # ASP.NET debug bridge
```

OPTIONS specifically is high-value: the response `Allow:` header lists every method the server has registered for that path. Many "hidden" admin actions are in fact `POST` or `PUT` endpoints whose existence is announced by OPTIONS.

### Stage 3: Encoding / Casing / Path Variation (WAF bypass surface)

For each path the agent tries multiple encoded variants when the raw form returns a WAF block (typically 403 with a CDN/WAF banner):

```
/.git/config                            # raw
/%2Egit/config                          # URL-encoded leading dot
/%2egit/config
/%2E%2E/.git/config                     # parent-traversal prefix
/.GIT/config                            # uppercase dir
/.Git/config                            # mixed case
/.git/CONFIG
/.git/Config
/.git/./config                          # current-dir-segment
/.git//config                           # double slash
/.git/%2Econfig
/%2e%2e/.git/config                     # double-dot
/.git%2Fconfig                          # encoded slash
/.git%2fconfig
/.git/config%00.png                     # null-byte legacy
/.git/config?.png                       # extension-trick
/.git/config;.png                       # semicolon-trick
/.git/config#.png                       # fragment trick
/.git/config%20                         # trailing space
/.git/config%09                         # trailing tab
/.git/config%0a                         # trailing newline
/..;/.git/config                        # path-parameter trick (Tomcat)
/;/.git/config
/;param/.git/config
//.git/config                           # leading double slash
/././.git/config
```

For very high-value paths (`.env`, `.git/config`, `wp-config.php`, source maps), enumerate all of the encoding variants. For lower-value paths, only enumerate when the raw path returns 403 (existence signal worth bypassing).

### Stage 4: Error-Page Induction

Trigger errors deliberately on every confirmed live endpoint to surface stack traces, framework banners, and middleware versions.

#### 4.1 Parameter-induced errors

For an endpoint `/api/v1/users?id=<id>` (or any parameter-bearing URL), substitute these probe values:

```
id=
id=null
id=undefined
id=NaN
id=Infinity
id=-1
id=0
id=1.1
id=1e99
id=true
id=false
id=[]
id=[object Object]
id={}
id={"$ne":1}                          # NoSQL injection probe (often bare 500 with stack)
id=' OR '1'='1
id="
id=<script>
id=../../etc/passwd
id=%00
id=A*4096                             # 4KB string
id=A*65536                            # 64KB string
id=A*1048576                          # 1MB string
```

Each often produces a different error class. Record the response body/headers per probe.

#### 4.2 Header-induced errors

Send malformed headers:

```
Content-Type: application/json    (with non-JSON body)
Content-Type: x-application/garbage
Host: localhost
Host: 127.0.0.1
Host: target.example:99999
X-Forwarded-For: ' OR 1=1--
X-Forwarded-Host: <script>
Range: bytes=0-
Range: bytes=0-,1-2-3
Range: bytes=-1-
Connection: close, close
Transfer-Encoding: chunked, identity
Content-Length: -1
Content-Length: 99999999999
```

Also try methods that the framework's router doesn't recognize (e.g., `PROPFIND` on a JSON API typically yields a stack trace from middleware).

#### 4.3 Body-induced errors

For JSON endpoints:

```
{"key": "value"                      # truncated JSON
{"key": value}                       # unquoted value
{"a": {"b": {"c": ...{"x": 1}...}}}  # 100-deep nested object
{"key": "AAAAAAAA..."}               # very long string value
{"key": [1,2,3,...]}                 # very long array (10000 elements)
{"$ne": 1}                           # NoSQL operator at top level
{"__proto__": {"polluted": true}}    # prototype pollution probe
```

For multipart/form endpoints:

```
- multipart with no boundary in Content-Type
- multipart with wrong boundary in body
- multipart filename with traversal: filename="../../../etc/passwd"
- multipart filename with null: filename="test\x00.png"
- multipart filename with very long name (4096 chars)
- multipart with content-type mismatched to filename extension
```

For XML endpoints:

```
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
<?xml version="1.0"?><foo                      # truncated XML
```

#### 4.4 URL-shape errors

```
GET <very long path: 4096 chars>
GET <path>?<very long querystring: 8KB>
GET <path with 1000 slashes between segments>
GET <path with %00 in middle>
GET <path with unicode in segment>
GET <path with high-byte: \xff\xfe\xfd>
```

### Stage 5: Verbose-Header Detection

For every confirmed live host, the agent inventories response headers that disclose stack/framework details. Save the full header list per host. Specifically flag the following, which are almost always disclosure findings on their own:

```
Server: Apache/2.4.41 (Ubuntu)
Server: nginx/1.18.0 (Ubuntu)
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.4.3
X-Powered-By: Express
X-Powered-By: ASP.NET
X-Powered-By: PleskLin
X-AspNet-Version: 4.0.30319
X-AspNetMvc-Version: 5.2
X-Generator: Drupal 9
X-Drupal-Cache: HIT
X-Drupal-Dynamic-Cache: HIT
X-Runtime: 0.123456                    # Rails
X-Application-Context: application:production:8080   # Spring
X-Symfony-Debug-Toolbar-Token: <token>
X-Debug-Token: <token>
X-Debug-Token-Link: /_profiler/<token>
X-Debug: 1
X-Sentry-ID: <id>
X-Backend-Server: <internal hostname>
X-Server-Hostname: <internal hostname>
X-Container: <container id>
X-Pod: <kubernetes pod>
X-Cluster: <cluster name>
X-Node: <node id>
X-Region: <region>
X-Internal-Trace-ID: <trace>
X-Request-ID: <request>
X-Trace-ID: <trace>
Via: <proxy chain>
X-Cache: HIT from <proxy>
X-Forwarded-Server: <internal hostname>
X-Real-IP: <leaked client IP>
```

The presence of `X-Debug-Token-Link: /_profiler/<token>` is a direct callable URL — fetching `/_profiler/<token>` exposes the entire request profile (Symfony) including config, env, queries, sessions.

### Stage 6: HTML / JS Comment Mining

For every captured HTML body, the agent extracts:

```python
import re
html_comments = re.findall(r'<!--(.+?)-->', body, flags=re.DOTALL)
```

For every captured JS body, the agent extracts:

```python
js_line_comments = re.findall(r'//.*', js_body)
js_block_comments = re.findall(r'/\*(.+?)\*/', js_body, flags=re.DOTALL)
```

Per comment, scan for high-signal substrings:

```
TODO
FIXME
HACK
XXX
WORKAROUND
TEMPORARY
TEMP
TEST
DEBUG
DISABLE
DISABLED
BYPASS
SKIP
INTERNAL
DO NOT COMMIT
DO NOT DEPLOY
REMOVE BEFORE PROD
REMOVE BEFORE PRODUCTION
DELETE ME
DEPRECATED
LEGACY
PASSWORD
PASSWD
SECRET
TOKEN
KEY
APIKEY
API_KEY
BEARER
AUTH
CREDENTIAL
LOGIN
ADMIN
ROOT
SUDO
PRIVATE
INTERNAL
LOCALHOST
127.0.0.1
10\.\d+\.\d+\.\d+              # RFC1918 IPv4
172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+
192\.168\.\d+\.\d+
::1
fe80::
http://localhost
http://internal
http://10.
http://192.168.
http://172.
git@<host>
.example.com                    # often left in commented-out code
```

Each match is recorded with the comment, file URL, and line number. Internal IPs and hostnames revealed in comments are themselves recon hits — feed them back to subdomain enum / port scan.

### Stage 7: Source Map Recovery

For each `.map` URL discovered live (Stage 1.6 hit):

```python
import json, base64, urllib.parse, urllib.request

resp = urllib.request.urlopen("https://target.example/static/js/main.<hash>.js.map")
sm = json.loads(resp.read())

# sources: list of original source paths (component file structure)
sources = sm.get("sources", [])
# sourcesContent: parallel list of original source code (full uncompiled source)
sources_content = sm.get("sourcesContent", [])

# Write each component to disk
for path, content in zip(sources, sources_content):
    safe = urllib.parse.quote(path, safe='')
    with open(f"recovered/{safe}", "w") as f:
        f.write(content or "")
```

A source map typically includes:
- File paths (revealing internal directory structure: `webpack:///./src/internal/admin/secrets.ts`)
- Full source code of every component
- Hardcoded constants (API base URLs, default tokens, feature-flag keys, environment names, internal hostnames)
- Function/variable names (which the minifier hid in the production bundle)
- Inline TODOs, FIXMEs, and original comments

Grep the recovered source for the same high-signal substrings as Stage 6.

### Stage 8: OPTIONS / TRACE / Method-Disclosure Sweep

For every confirmed live URL:

```
OPTIONS <url>          → record Allow: header value
TRACE <url>            → if 200 with body containing the request, mark as XST candidate
PROPFIND <url>         → record any 207 Multi-Status (WebDAV enabled)
MKCOL <url>/test/      → if 201, server allows directory creation (severe misconfig)
PUT <url>/test.txt     → if 201/204, server allows file write (severe)
COPY <url>             → if 201/204, server allows copy (often combined with MOVE)
DELETE <url>/test.txt  → only if PUT succeeded; clean up
SEARCH <url>           → record any 207 (WebDAV)
DEBUG <url>            → ASP.NET only; if 200, debug bridge enabled
```

Record the matrix of (URL × method) → status. Any method that returns a non-405 status on a path that would otherwise return 405 is a finding.

### Stage 9: 403-vs-404 Distinction (the existence signal)

For every path in the catalog that returned non-200, classify:

- `404` → path likely does not exist on this server.
- `403` → path EXISTS but is access-controlled. This is the highest-priority bypass surface: try Stages 2 + 3 (method variation + encoding variation) on every 403.
- `401` → path requires authentication. Note for auth-bypass testing later.
- `500` → path EXISTS and crashes the server. Try parameter substitution to harvest the stack trace.
- `301`/`302` redirect → follow once, but record the redirect target — sometimes it leaks an internal hostname.
- `405` → path exists but method is wrong; try Stage 2 method variation.

A `403` on `/.git/config` is functionally identical to a `200` for finding purposes — the WAF/server confirmed the path exists, which means the repo is on disk. Stages 2 + 3 frequently bypass the protection.

## Search Operator / Pattern Cookbook

```
# Quick screen of a host: hit the 30 highest-signal paths, multi-method
for path in [".git/config", ".env", "actuator", "swagger.json", "wp-config.php.bak",
             "_profiler/", "phpinfo.php", "robots.txt", ".aws/credentials",
             "_next/static/chunks/main.js.map", "static/js/main.js.map", "config.json",
             "backup.zip", "dump.sql", "package.json", "composer.json", "yarn.lock",
             "Dockerfile", ".dockerenv", "docker-compose.yml", ".gitlab-ci.yml",
             "Jenkinsfile", "manage/health", "actuator/env", "actuator/heapdump",
             "actuator/jolokia", "rails/info/routes", "_ignition/health-check",
             "telescope", "_debug"]:
   for method in ["GET", "HEAD", "OPTIONS", "POST"]:
       send method <host>/<path>

# WAF-bypass burst on a path that returned 403:
# encoding variants, casing variants, path-parameter tricks
for variant in ENCODING_VARIANTS:   # see Stage 3
   send GET <host>/<variant>

# Source-map sweep: every JS bundle URL in discovered_js_bundles
for js in discovered_js_bundles:
   try GET <js>.map
   try GET <js>+".map"
   parse last 200 bytes of <js> for "//# sourceMappingURL="

# Comment mine all captured HTML/JS bodies
grep -roP '<!--[\s\S]*?-->' captured_html/
grep -roP '/\*[\s\S]*?\*/' captured_js/
grep -roP '//.*$' captured_js/
```

## Decision Tree

```
START
  │
  ├── For each host in target_hosts:
  │   ├── Run Stage 1 path inventory (1.1 → 1.11) — every category, no skipping
  │   ├── For each path → Stage 2 method variation (GET/HEAD/OPTIONS/POST as baseline)
  │   ├── For each path that returned 403 → Stage 3 encoding/casing variation
  │   ├── For each parameter-bearing URL → Stage 4 error induction
  │   ├── Always → Stage 5 verbose-header detection (one HEAD/GET captures it)
  │   ├── For each captured HTML/JS body → Stage 6 comment mining
  │   ├── For each .map URL hit live → Stage 7 source map recovery
  │   ├── For each confirmed live URL → Stage 8 OPTIONS/TRACE/method sweep
  │   └── Stage 9 — classify all responses (200/403/404/401/500/redirect)
  │
  └── Aggregate findings → write per-host disclosure report
```

NO short-circuit. Each stage discovers a different class of disclosure. A path that returned `404` for `/.env` does not preclude `/.env.bak` from existing.

## Pitfalls

- **WAF blanket-403.** Many WAFs return 403 for every path in a denylist regardless of existence. Distinguish by comparing response sizes / timing — a real 403-on-existing returns a slightly different body than a synthetic 403-on-pattern-match. Use the encoding-variant Stage 3 on every WAF 403; many WAFs only normalize one encoding form.
- **CDN-cached 404 pollution.** A CDN may cache a 404 for a path the agent then can't re-test for. Add a cache-buster querystring (`?v=<random>`) to every probe. Also vary the `Accept` header — some CDNs cache by `Accept`.
- **Rate-limit by 429.** Bursty enumeration triggers rate limits. Throttle to <10 req/sec per host as the default; back off on 429.
- **Honeypot paths.** Some defenders deploy fake `/admin` or `/.env` that return believable content but log the requester. Don't treat first hit as victory — verify content authenticity (real `.env` parses as KEY=VALUE pairs; honeypot may be random text).
- **403 ≠ Existence on every server.** Some Apache configs return 403 for any path matching `/\..*` regardless of file existence. The existence signal is reliable on nginx/IIS but noisy on default Apache.
- **Backup-file false 200s.** A static-site server may return the index.html as the response body for `/backup.zip` (because of a fallback rewrite rule) — verify Content-Type and Content-Length match what a real binary backup would return. Tiny `Content-Length` (<10KB) on an alleged backup is suspicious.
- **Source map not at obvious URL.** Modern bundlers default to NOT writing the `sourceMappingURL` directive in production. The map may be at a separate hashed URL. Search the bundle's last 4KB for any `// sourceMappingURL` or `// sourceURL` directive — these are sometimes inlined.
- **Inlined base64 source maps.** A `sourceMappingURL=data:application/json;base64,...` directive embeds the entire source map inside the bundle — same data, requires base64 decoding to recover. Mark this as a finding (production bundles should never inline maps).
- **Verbose-header sanitization.** Some reverse proxies strip stack-trace headers but a backup origin (e.g., a non-default vhost) may not have the same proxy. After Stage 5, retry with `Host:` header set to a backup vhost name.
- **OPTIONS responses lying.** Some CORS middleware constructs the `Allow:` header dynamically and includes methods that aren't actually implemented. Validate with a direct request before reporting.
- **TRACE often blocked at edge.** Cloudflare/Akamai/Fastly typically block TRACE upstream. The XST finding only matters if the origin handles TRACE — try with a `Host:` header for the origin's internal name (sometimes leaks via Stage 5 / Stage 6).
- **Multi-encoded path normalization.** Some WAFs normalize `%2e` once but not twice; `%252e` (double-encoded) bypasses. Always include double-encoded variants.
- **Errors in non-default Accept.** Send `Accept: application/json`, `Accept: application/xml`, `Accept: text/plain`. Frameworks render different errors for different content negotiations — sometimes the JSON error reveals more than the HTML error.
- **Path-parameter dance.** Tomcat / JBoss / WebLogic accept `;param=value` in any path segment. `/admin;.png` may pass an extension-allowlist while still routing to `/admin`. Always test the path-parameter trick on 403-blocked paths.
- **Hidden by case-sensitivity.** Linux servers are case-sensitive; Windows servers are not. `/.GIT/CONFIG` may work on a Windows IIS server when `/.git/config` is denylisted by exact match.

## Output Format

Per-finding record:

```json
{
  "host": "target.example",
  "path": "/.git/config",
  "method": "GET",
  "encoding_variant": "raw",
  "status": 200,
  "response_size": 487,
  "content_type": "text/plain",
  "content_snippet": "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n...",
  "secrets_extracted": [],
  "category": "version_control_dotdir",
  "stage": "Stage 1.1",
  "severity_estimate": "critical",
  "validation": "git_config_format_match",
  "first_seen": "2026-05-03T18:14:00Z"
}
```

Per-host summary:

```
host: target.example
paths_probed_total: 1247
paths_200: 18
paths_403_existence_signal: 41
paths_500_error_induction: 6
paths_301_302_redirect: 22
verbose_headers: ["X-Powered-By: PHP/7.4.3", "X-Generator: Drupal 9", ...]
options_methods_per_path: { "/api/": "GET, POST, OPTIONS, HEAD", "/admin/": "GET, POST, PUT, DELETE, OPTIONS, HEAD" }
trace_xst_candidates: []
source_maps_recovered: 4
source_files_recovered: 1281
internal_ips_in_comments: ["10.0.13.42", "172.16.5.7"]
internal_hostnames_in_comments: ["target-internal.example", "auth-staging.example"]
high_signal_comments: ["// FIXME: skip auth check on staging — REMOVE BEFORE PROD", ...]
```

Aggregate cross-host:

```
critical_findings: 5
high_findings: 14
medium_findings: 38
informational_findings: 121
new_internal_hostnames_discovered: 23
new_internal_ips_discovered: 17
```

## Composes With

- `recon_content_discovery` — the Stage 1 path catalog functions as the wordlist for content-discovery fuzzing; the agent does not need to maintain a separate disclosure wordlist.
- `recon_archive_intel` — archived URLs from Wayback/URLScan that match disclosure-path patterns are highest-priority for Stage 9 live verification (archived `.git/config` may STILL be live).
- `recon_deep_js_analysis` — Stage 7 source-map recovery feeds the deep JS-analysis skill; recovered components contain endpoint constants and feature-flag defaults.
- `recon_passive_subdomain` — internal hostnames revealed by Stage 6 comment mining and Stage 7 source-map recovery feed back into subdomain enumeration as new candidates.
- `recon_shodan_dorking` — verbose-header values from Stage 5 (Server, X-Powered-By, X-Backend-Server) feed Shodan `product:`/`http.server:`/`http.html:` queries to find sibling assets running the same stack.
- `recon_port_service_analysis` — Stage 8's WebDAV / non-standard methods that succeed often correlate with non-standard ports; trigger a port re-scan when WebDAV is detected.

## Termination Policy

This skill terminates ONLY when ALL of the following are complete for EVERY host in `target_hosts[]`:

1. Stage 1 has executed every path in categories 1.1 through 1.9 (mandatory baseline).
2. Stage 1.10 (framework-specific) has executed for every framework in `tech_fingerprints[]`. If `tech_fingerprints[]` is empty, the agent runs the WordPress + Drupal + Spring + Next.js + Laravel sets as the universal baseline (these cover ~80% of common stacks).
3. Stage 1.11 (cloud-specific) has run.
4. Stage 2 (method variation) has been applied to every Stage 1 path with at least the GET/HEAD/OPTIONS/POST quartet.
5. Stage 3 (encoding variation) has been applied to every path that returned 403 in Stages 1-2.
6. Stage 4 (error induction) has been applied to every parameter-bearing endpoint discovered (the agent does not skip endpoints because earlier probes succeeded — the goal is exhaustive error harvesting).
7. Stage 5 (verbose-header detection) has been recorded for every host (one capture per host).
8. Stage 6 (comment mining) has been applied to every captured HTML and JS body.
9. Stage 7 (source-map recovery) has been attempted for every JS bundle URL discovered, including non-obvious sourceMappingURL directives.
10. Stage 8 (OPTIONS/TRACE/method sweep) has been applied to every confirmed live URL (cap at 100 URLs per host to avoid combinatorial explosion; if cap reached, the agent records the cap-hit and prioritizes URLs with parameters or distinctive paths).
11. Stage 9 has classified every Stage 1 response and produced the 403-bypass queue, the 500-induction queue, and the 401-auth-bypass queue.
12. Per-host and aggregate output files are written.

DO NOT terminate early because:
- The first few hosts produced lots of findings — every host needs the full pass; later hosts often expose what earlier hosts hid.
- The target appears "hardened" or "mature" — every appearance of hardening is itself a hypothesis to disprove with the catalog.
- A WAF is detected — that is the trigger for Stage 3 encoding variants, not a reason to stop.
- An earlier scan found a `.env` — that does not preclude a `.env.bak`, a `wp-config.php.bak`, a source map, or a debug endpoint.
- The agent has accumulated "enough" findings — bug-bounty disclosure work is exhaustive by definition; a missed source-map on host #14 is a missed entire codebase.
- The path catalog is "long" — it is meant to be long; the value of this skill is the totality of coverage, not a curated subset.
