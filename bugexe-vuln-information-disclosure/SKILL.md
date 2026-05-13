---
name: information-disclosure
description: Information disclosure testing covering error messages, debug endpoints, metadata leakage, and source exposure
depends_on: []
---

# Information Disclosure

Information leaks accelerate exploitation by revealing code, configuration, identifiers, and trust boundaries. Treat every response byte, artifact, and header as potential intelligence. Minimize, normalize, and scope disclosure across all channels.

## Discovery Signals

| Signal | Where to Find | Why Valuable |
|---|---|---|
| `X-Powered-By` or `Server` header with version | Response headers | Precise version leads to CVE lookup |
| `/.git/HEAD` returns `ref: refs/heads/` | Path scan | Full source code reconstruction possible |
| `/.env` returns 200 with key=value pairs | Path scan | Database creds, API keys, JWT secrets |
| `/debug/pprof` or `/actuator/env` returns 200 | Path scan | Runtime config, memory dumps, environment variables |
| `/__NEXT_DATA__` in page source with props | Page source | Server-side props leak internal IDs, feature flags, PII |
| Source maps (`.js.map`) accessible | Network traffic, path brute | Original source code, internal comments, API endpoints |
| GraphQL introspection returns schema | API probe | Full type system, hidden mutations, deprecated fields |
| `/swagger.json` or `/api-docs` returns schema | Path scan | Complete API surface including admin endpoints |
| Error response includes stack trace | Error triggering | File paths, framework version, function names |
| `phpinfo()` page accessible | Path scan (`/info.php`, `/phpinfo.php`) | Full server config, loaded modules, environment |
| Firebase `.json` endpoint returns data | Path scan (`/.json`) | Entire database readable if rules are open |
| AWS S3 bucket listing enabled | Cloud asset scan | File enumeration, potential credential exposure |

## Attack Surface

- Errors and exception pages: stack traces, file paths, SQL, framework versions
- Debug/dev tooling reachable in prod: debuggers, profilers, feature flags
- DVCS/build artifacts and temp/backup files: .git, .svn, .hg, .bak, .swp, archives
- Configuration and secrets: .env, phpinfo, appsettings.json, Docker/K8s manifests
- API schemas and introspection: OpenAPI/Swagger, GraphQL introspection, gRPC reflection
- Client bundles and source maps: webpack/Vite maps, embedded env, `__NEXT_DATA__`, static JSON
- Headers and response metadata: Server/X-Powered-By, tracing, ETag, Accept-Ranges, Server-Timing
- Storage/export surfaces: public buckets, signed URLs, export/download endpoints
- Observability/admin: /metrics, /actuator, /health, tracing UIs (Jaeger, Zipkin), Kibana, Admin UIs
- Directory listings and indexing: autoindex, sitemap/robots revealing hidden routes

## Endpoint Paths to Scan

| Stack | Endpoints to Check | What They Reveal |
|---|---|---|
| **Any** | `/.env`, `/.env.local`, `/.env.production`, `/.env.backup` | Credentials, API keys, database URLs |
| **Any** | `/robots.txt`, `/sitemap.xml`, `/crossdomain.xml`, `/clientaccesspolicy.xml` | Hidden paths, admin URLs, allowed domains |
| **Git** | `/.git/HEAD`, `/.git/config`, `/.git/index`, `/.gitignore` | Source reconstruction, remote URLs, ignored secrets |
| **Node.js** | `/package.json`, `/package-lock.json`, `/node_modules/` | Dependencies for CVE hunting, versions |
| **PHP** | `/info.php`, `/phpinfo.php`, `/test.php`, `/.htaccess`, `/wp-config.php.bak` | Full PHP config, rewrite rules, DB creds |
| **Java/Spring** | `/actuator/env`, `/actuator/health`, `/actuator/configprops`, `/actuator/mappings` | Environment vars, bean configs, all routes |
| **Django** | `/admin/`, `/api/__debug__/`, `/__debug__/` | Django debug toolbar, admin panel |
| **Rails** | `/rails/info/routes`, `/rails/info/properties` | All routes, Rails version |
| **ASP.NET** | `/elmah.axd`, `/trace.axd`, `/web.config` | Error logs, request traces, config |
| **WordPress** | `/wp-json/wp/v2/users`, `/xmlrpc.php`, `/wp-includes/version.php` | User enumeration, API access, version |
| **Firebase** | `/.json`, `/.json?shallow=true` | Entire database if rules misconfigured |
| **AWS** | `/.aws/credentials`, `/latest/meta-data/` (internal) | Cloud credentials |
| **Docker** | `/v2/_catalog`, `/.dockerenv`, `/proc/1/cgroup` | Container registry, container detection |

## Response Header Intelligence

| Header | What It Reveals | Severity |
|---|---|---|
| `Server: Apache/2.4.49` | Exact version (CVE-2021-41773 path traversal) | Medium-High |
| `X-Powered-By: PHP/7.4.3` | PHP version for CVE targeting | Low-Medium |
| `X-AspNet-Version: 4.0.30319` | .NET framework version | Low |
| `X-Request-Id: uuid` | Request tracing, potentially correlatable | Low |
| `Server-Timing: db;dur=23` | Database response time (timing oracle for blind injection) | Medium |
| `X-Debug-Token: abc123` | Symfony profiler token, visit `/_profiler/abc123` for full debug | High |
| `X-Amzn-RequestId` | Confirms AWS hosting, helps target metadata | Low |
| `X-Runtime: 0.034` | Execution time (timing oracle) | Low |
| `Via: 1.1 proxy.internal.corp` | Internal proxy hostname | Low-Medium |
| `X-Cache-Key: /path?user_id=123` | Cache key includes user data, enables cache poisoning | Medium |
| `CF-Ray: hex-IAD` | Cloudflare datacenter (IAD = Ashburn VA) | Info |
| `Set-Cookie: session=x; Domain=.corp.com` | Cookie scope reveals internal domain structure | Low |

## High-Value Surfaces

### Errors and Exceptions

- SQL/ORM errors: reveal table/column names, DBMS, query fragments
- Stack traces: absolute paths, class/method names, framework versions, developer emails
- Template engine probes: `{{7*7}}`, `${7*7}` identify templating stack
- JSON/XML parsers: type mismatches leak internal model names

### Error Message Classification

| Error Type | What to Extract | Next Step |
|---|---|---|
| SQL error with query fragment | Table/column names, DBMS type | SQLi targeting |
| Stack trace with file paths | Application root, framework, file structure | Path traversal, LFI |
| `ModuleNotFoundError: No module named 'xxx'` | Python dependency info | CVE lookup, dependency confusion |
| `undefined method 'xxx' for NilClass` | Ruby framework, potential nil pointer | Logic bug hunting |
| `ClassNotFoundException: com.xxx.yyy` | Java package structure, internal classes | Deserialization gadget chain |
| JSON parse error with partial body | Internal API response structure | API structure mapping |
| `ECONNREFUSED 127.0.0.1:xxxx` | Internal service ports | SSRF port targeting |
| Certificate error with hostname | Internal hostnames | SSRF, subdomain discovery |
| `Access denied for user 'xxx'@'yyy'` | Database username, host, DBMS | Credential spraying |
| Rate limit error with remaining count | Rate limit implementation details | Rate limit bypass |

### Debug and Env Modes

- Debug pages: Django DEBUG, Laravel Telescope, Rails error pages, Flask/Werkzeug debugger, ASP.NET customErrors Off
- Profiler endpoints: `/debug/pprof`, `/actuator`, `/_profiler`, custom `/debug` APIs
- Feature/config toggles exposed in JS or headers

### DVCS and Backups

- DVCS: `/.git/` (HEAD, config, index, objects), `.svn/entries`, `.hg/store` → reconstruct source and secrets
- Backups/temp: `.bak`/`.old`/`~`/`.swp`/`.swo`/`.tmp`/`.orig`, db dumps, zipped deployments
- Build artifacts: dist artifacts containing `.map`, env prints, internal URLs

#### .git Reconstruction Methodology

When `/.git/HEAD` returns content:

1. Read `/.git/HEAD` to get current branch ref
2. Read `/.git/config` to get remote URL (often has credentials in HTTPS remotes)
3. Read `/.git/index` and parse binary to get ALL tracked file paths
4. For each file path from index, compute blob hash and fetch from `/.git/objects/xx/xxxxxxx`
5. Alternatively use tools: `git-dumper`, `GitTools`, `dvcs-ripper` to automate
6. Read `/.git/logs/HEAD` to get commit history with author emails
7. Check for credential patterns in reconstructed source

### Configs and Secrets

- Classic: web.config, appsettings.json, settings.py, config.php, phpinfo.php
- Containers/cloud: Dockerfile, docker-compose.yml, Kubernetes manifests, service account tokens
- Credentials and connection strings; internal hosts and ports; JWT secrets

### API Schemas and Introspection

- OpenAPI/Swagger: `/swagger`, `/api-docs`, `/openapi.json` — enumerate hidden/privileged operations
- GraphQL: introspection enabled; field suggestions; error disclosure via invalid fields
- gRPC: server reflection exposing services/messages

### Client Bundles and Maps

- Source maps (`.map`) reveal original sources, comments, and internal logic
- Client env leakage: `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` variables; embedded secrets
- `__NEXT_DATA__` and pre-fetched JSON can include internal IDs, flags, or PII

#### JS Bundle Mining Patterns

Specific patterns to grep for in JavaScript bundles:

```
API_KEY, api_key, apiKey, API_SECRET, SECRET_KEY
NEXT_PUBLIC_, REACT_APP_, VITE_, VUE_APP_
firebase, firebaseConfig, apiKey.*firebase
aws-sdk, AWS_ACCESS_KEY, secretAccessKey
stripe.*pk_, stripe.*sk_
maps.googleapis.com/maps/api/js?key=
/api/internal/, /api/admin/, /api/v0/
localhost:, 127.0.0.1:, 10.0., 172.16., 192.168.
TODO, FIXME, HACK, XXX, password, secret
__INTERNAL__, __DEBUG__, __DEV__
```

Also search for source maps: append `.map` to every JS file URL. If source maps exist, they contain the complete original source code.

### Headers and Response Metadata

- Fingerprinting: Server, X-Powered-By, X-AspNet-Version
- Tracing: X-Request-Id, traceparent, Server-Timing, debug headers
- Caching oracles: ETag/If-None-Match, Last-Modified/If-Modified-Since, Accept-Ranges/Range

### Storage and Exports

- Public object storage: S3/GCS/Azure blobs with world-readable ACLs or guessable keys
- Signed URLs: long-lived, weakly scoped, re-usable across tenants
- Export/report endpoints returning foreign data sets or unfiltered fields

### Cloud Storage Misconfiguration Patterns

| Provider | Check | How |
|---|---|---|
| AWS S3 | Anonymous listing | `aws s3 ls s3://bucket-name --no-sign-request` |
| AWS S3 | Authenticated listing | `aws s3 ls s3://bucket-name` (with any AWS account) |
| GCS | Public listing | `curl https://storage.googleapis.com/bucket-name/` |
| Azure Blob | Container listing | `curl https://account.blob.core.windows.net/container?restype=container&comp=list` |
| Firebase | Database read | `curl https://project.firebaseio.com/.json` |
| Firebase | Storage listing | Check Firebase Storage rules for public read |
| DigitalOcean Spaces | Public listing | `curl https://space.region.digitaloceanspaces.com/` |

Bucket name sources: JS bundles, DNS CNAME records, error messages, API responses, CORS headers.

### Observability and Admin

- Metrics: Prometheus `/metrics` exposing internal hostnames, process args
- Health/config: `/actuator/health`, `/actuator/env`, Spring Boot info endpoints
- Tracing UIs: Jaeger/Zipkin/Kibana/Grafana exposed without auth

### Cross-Origin Signals

- Referrer leakage: missing/weak referrer policy leading to path/query/token leaks to third parties
- CORS: overly permissive Access-Control-Allow-Origin/Expose-Headers revealing data cross-origin; preflight error shapes

### File Metadata

- EXIF, PDF/Office properties: authors, paths, software versions, timestamps, embedded objects

## Key Vulnerabilities

### Differential Oracles

- Compare owner vs non-owner vs anonymous for the same resource
- Track: status, length, ETag, Last-Modified, Cache-Control
- HEAD vs GET: header-only differences can confirm existence
- Conditional requests: 304 vs 200 behaviors leak existence/state

### CDN and Cache Keys

- Identity-agnostic caches: CDN/proxy keys missing Authorization/tenant headers
- Vary misconfiguration: user-agent/language vary without auth vary leaks content
- 206 partial content + stale caches leak object fragments

### Cross-Channel Mirroring

- Inconsistent hardening between REST, GraphQL, WebSocket, and gRPC
- SSR vs CSR: server-rendered pages omit fields while JSON API includes them

## Triage Rubric

- **Critical**: Credentials/keys; signed URL secrets; config dumps; unrestricted admin/observability panels
- **High**: Versions with reachable CVEs; cross-tenant data; caches serving cross-user content
- **Medium**: Internal paths/hosts enabling LFI/SSRF pivots; source maps revealing hidden endpoints
- **Low**: Generic headers, marketing versions, intended documentation without exploit path

## Exploitation Chains

### Credential Extraction
- DVCS/config dumps exposing secrets (DB, SMTP, JWT, cloud)
- Keys → cloud control plane access

### Version to CVE
1. Derive precise component versions from headers/errors/bundles
2. Map to known CVEs and confirm reachability
3. Execute minimal proof targeting disclosed component

### Path Disclosure to LFI
1. Paths from stack traces/templates reveal filesystem layout
2. Use LFI/traversal to fetch config/keys

### Schema to Auth Bypass
1. Schema reveals hidden fields/endpoints
2. Attempt requests with those fields; confirm missing authorization

## Testing Methodology

1. **Build channel map** - Web, API, GraphQL, WebSocket, gRPC, mobile, background jobs, exports, CDN
2. **Establish diff harness** - Compare owner vs non-owner vs anonymous; normalize on status/body length/ETag/headers
3. **Trigger controlled failures** - Malformed types, boundary values, missing params, alternate content-types
4. **Enumerate artifacts** - DVCS folders, backups, config endpoints, source maps, client bundles, API docs
5. **Correlate to impact** - Versions→CVE, paths→LFI/RCE, keys→cloud access, schemas→auth bypass

## Validation

1. Provide raw evidence (headers/body/artifact) and explain exact data revealed
2. Determine intent: cross-check docs/UX; classify per triage rubric
3. Attempt minimal, reversible exploitation or present a concrete step-by-step chain
4. Show reproducibility and minimal request set
5. Bound scope (user, tenant, environment) and data sensitivity classification

## False Positives

- Intentional public docs or non-sensitive metadata with no exploit path
- Generic errors with no actionable details
- Redacted fields that do not change differential oracles
- Version banners with no exposed vulnerable surface and no chain
- Owner-visible-only details that do not cross identity/tenant boundaries

## Impact

- Accelerated exploitation of RCE/LFI/SSRF via precise versions and paths
- Credential/secret exposure leading to persistent external compromise
- Cross-tenant data disclosure through exports, caches, or mis-scoped signed URLs
- Privacy/regulatory violations and business intelligence leakage

## Pro Tips

1. Start with artifacts (DVCS, backups, maps) before payloads; artifacts yield the fastest wins
2. Normalize responses and diff by digest to reduce noise when comparing roles
3. Hunt source maps and client data JSON; they often carry internal IDs and flags
4. Probe caches/CDNs for identity-unaware keys; verify Vary includes Authorization/tenant
5. Treat introspection and reflection as configuration findings across GraphQL/gRPC
6. Mine observability endpoints last; they are noisy but high-yield in misconfigured setups
7. Chain quickly to a concrete risk and stop—proof should be minimal and reversible
8. Grep every JS bundle for API keys before anything else — automated tooling (trufflehog, gitleaks) misses client-side bundles
9. Always check `/.well-known/` — `security.txt`, `openid-configuration`, `assetlinks.json` reveal infrastructure
10. Compare authenticated vs unauthenticated responses byte-by-byte — even "identical" responses may differ in headers, revealing auth state
11. Check response headers on 404 pages — error handlers often leak more information than normal endpoints
12. Mine `<meta>` tags — generator, author, build version, commit hash often in HTML head
13. Search for internal documentation endpoints — `/docs`, `/help`, `/api/docs`, `/graphql/playground`, `/api-explorer`

## Summary

Information disclosure is an amplifier. Convert leaks into precise, minimal exploits or clear architectural risks.
