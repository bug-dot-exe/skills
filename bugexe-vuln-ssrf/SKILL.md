---
name: ssrf
description: SSRF testing for cloud metadata access, internal service discovery, and protocol smuggling
depends_on: []
---

# SSRF

Server-Side Request Forgery enables the server to reach networks and services the attacker cannot. Focus on cloud metadata endpoints, service meshes, Kubernetes, and protocol abuse to turn a single fetch into credentials, lateral movement, and sometimes RCE.

## Attack Surface

**Scope**
- Outbound HTTP/HTTPS fetchers (proxies, previewers, importers, webhook testers)
- Non-HTTP protocols via URL handlers (gopher, dict, file, ftp, smb wrappers)
- Service-to-service hops through gateways and sidecars (envoy/nginx)
- Cloud and platform metadata endpoints, instance services, and control planes

**Direct URL Params**
- `url=`, `link=`, `fetch=`, `src=`, `webhook=`, `avatar=`, `image=`, `callback=`, `redirect=`, `proxy=`, `source=`, `uri=`, `host=`, `dest=`, `target=`, `feed=`, `rss=`, `api_url=`, `endpoint=`, `load=`, `page=`, `file=`, `path=`, `data=`, `resource=`

**Header-Based Params**
- `Host`, `X-Forwarded-Host`, `X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`, `X-Real-IP`, `Forwarded`, `True-Client-IP`, `Referer`, `Origin`, `X-Forwarded-Server`

**Indirect Sources**
- Open Graph/link previews, PDF/image renderers, server-side analytics (Referer trackers)
- Import/export jobs, webhooks/callback verifiers, RSS/Atom feed fetchers
- Cookie values containing JSON with URL-like fields interpolated into backend API paths

**Protocol-Translating Services**
- PDF via wkhtmltopdf/Chrome headless, image pipelines, document parsers
- SSO validators, archive expanders, screenshot/PDF generation endpoints

**Less Obvious**
- GraphQL resolvers that fetch by URL, background crawlers
- Repository/package managers (git, npm, pip), calendar (ICS) fetchers
- CI/CD pipeline configs that fetch remote resources

## Discovery Signals

Technology fingerprints that indicate high SSRF probability:

| Signal | Where to Find | Why Vulnerable |
|---|---|---|
| WordPress `/xmlrpc.php` | Path scan | `pingback.ping` = unauthenticated blind SSRF on every install |
| Sentry instance (`/api/0/`, `sentrysid` cookie) | Headers, paths | Source-code scraping fetches arbitrary URLs by default |
| PlantUML renderer | Path scan, docs | `!include http://` directive = SSRF by design |
| Cloudflare Image Resizing `/cdn-cgi/image/` | URL paths | Origin restriction often missing = open SSRF proxy |
| Image proxy endpoints (`/icon`, `/favicon`, `/image-proxy`) | Path scan | Any service fetching icons/images for arbitrary domains |
| Celery Flower (`/flower/`, `/api/tasks`) | Path scan, ports | Exposed admin UI with task execution capability |
| Spring Actuator (`/actuator/env`, `/actuator/jolokia`) | Path scan | Environment secrets and JMX RCE |
| Grafana (`/api/datasources/proxy/{id}`) | Path scan | Datasource proxy = designed SSRF primitive |
| Angular Universal with `useAbsoluteUrl` | Framework fingerprint | SSR constructs outbound URLs from Host header |
| Next.js `_next/image` on Netlify | Framework + CDN | `@netlify/ipx` image optimization = server-side URL fetch |
| Headless browser screenshot/PDF endpoint | Feature scan | Renders attacker-controlled HTML in server-side network context |
| Kafka Connect (`/connectors`) | Port scan | `HttpSinkConnector` URL parameter = SSRF to internal services |
| AsciiDoctor rendering | Feature scan | `counter` macro can re-enable `kroki-fetch-diagram` = SSRF + file write |

## High-Value Targets

### AWS

- IMDSv1: `http://169.254.169.254/latest/meta-data/` → `/iam/security-credentials/{role}`, `/user-data`
- IMDSv2: requires token via PUT `/latest/api/token` with header `X-aws-ec2-metadata-token-ttl-seconds`, then include `X-aws-ec2-metadata-token` on subsequent GETs
- If sink cannot set headers or methods, seek intermediaries that can
- ECS/EKS task credentials: `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`

### GCP

- Endpoint: `http://metadata.google.internal/computeMetadata/v1/`
- Required header: `Metadata-Flavor: Google`
- **v1beta1 bypass**: `http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token` — does NOT require the `Metadata-Flavor` header. This is how Shopify's production cluster was rooted ($25K bounty).
- Recursive dump: `?recursive=true&alt=json` dumps all instance attributes including `kube-env` in one request
- Force JSON rendering: `?alt=json` coerces response to application/json for screenshot renderers

### Azure

- Endpoint: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
- Required header: `Metadata: true`
- MSI OAuth: `/metadata/identity/oauth2/token`

### Other Cloud Providers

- Alibaba: `http://100.100.100.200/latest/meta-data/` (different IP from standard)
- Oracle: `http://192.0.0.192/latest/`
- DigitalOcean/Hetzner: `http://169.254.169.254/metadata/v1/`

### Kubernetes

- Kubelet: 10250 (authenticated) and 10255 (deprecated read-only)
- Probe `/pods`, `/metrics`, exec/attach endpoints
- API server: `https://kubernetes.default.svc/`
- Service discovery: attempt cluster DNS names (`svc.cluster.local`)

### Internal Services

- Docker API: `http://localhost:2375/v1.24/containers/json`
- Redis/Memcached: `dict://localhost:11211/stat`, gopher payloads to Redis on 6379
- Elasticsearch/OpenSearch: `http://localhost:9200/_cat/indices`
- Message brokers/admin UIs: RabbitMQ, Kafka REST, Celery/Flower, Jenkins
- FastCGI/PHP-FPM: `gopher://localhost:9000/` (craft records for file write/exec)
- Prometheus: `http://localhost:9090/api/v1/targets` (service discovery)

## Key Vulnerabilities

### Protocol Exploitation

**Gopher** — speak raw text protocols (Redis/SMTP/IMAP/HTTP/FCGI). Use to craft multi-line payloads, schedule cron via Redis, or build FastCGI requests.

**File and Wrappers** — `file:///etc/passwd`, `file:///proc/self/environ`. Language-specific: `php://`, `expect://`, `jar:`, `netdoc:`, `smb://`.

### URL Parser Confusion

Exploits differential parsing between the allowlist validator and the HTTP client fetcher:

| Pattern | Example | How It Works |
|---|---|---|
| `@`-userinfo | `http://allowed@evil.com` | Validator sees `allowed` as host, HTTP client uses `evil.com` |
| Fragment `#` truncation | `http://evil.com/path#@allowed` | Fragment drops suffix, preventing server-appended path components |
| Dual Content-Type smuggling | Response: `Content-Type: image/png` + `Content-Type: text/html` | Proxy validates first header, browser renders second |
| `X-Forwarded-Host` override | `X-Forwarded-Host: allowed@target:port` | Backend honors forwarded header over Host for URL construction |
| Full-URI in request line | `GET http://evil.com/ HTTP/1.1` with `Host: target` | Frontend routes by Host, backend interprets full-URI path |
| Path segment regex bypass | `http://evil.com/allowed.co/path` | Regex `allowed\.co` lacks anchor, matches path segment |
| Trailing dot | `internal.` vs `internal` | DNS treats identically, string comparison does not |
| Default port inclusion | `http://evil.com:80` vs `http://evil.com` | Port normalization differs between validator and fetcher |
| Ideographic full stop | Unicode U+3002 instead of `.` | Some parsers normalize to ASCII dot, others don't |
| Schemeless URL | `//evil.com/path` | Some validators require scheme, fetcher auto-prepends |
| Percent-encoded host | `%65vil.com` → `evil.com` | Validator sees encoded form, fetcher decodes |
| Backslash as separator | `http://evil.com\@allowed` | Some parsers treat `\` as path separator |

### IP Address Encoding

| Encoding | Value for 127.0.0.1 | Bypass Mechanism |
|---|---|---|
| Decimal | `2130706433` | `filter_var` rejects → guard skips entirely → network stack resolves |
| Octal | `0177.0.0.1` | Same guard-skip as decimal |
| Hex | `0x7f000001` or `0x7f.0.0.1` | Same guard-skip |
| Compressed | `127.1` or `127.0.1` | Fewer octets bypass regex expecting 4 groups |
| IPv6 mapped | `[::ffff:127.0.0.1]` or `[::ffff:7f00:1]` | Bypasses IPv4-only filters |
| URL-encoded dots | `127%2e0%2e0%2e1` | Dot encoding bypasses string-match filters |
| Mixed notation | `0:0:0:0:0:ffff:127.0.0.1` | Long-form IPv6 bypasses pattern matchers |

**PHP-specific**: `filter_var(FILTER_VALIDATE_IP)` has a stricter view of "valid IP" than the network stack. If the guard returns early when `filter_var` returns false, ANY non-standard IP format bypasses the entire protection.

### DNS Rebinding

| Variant | Technique | Infrastructure Needed |
|---|---|---|
| rbndr.us | `7f000001.c0a80001.rbndr.us` alternates IPs per query | None |
| CNAME chain evasion | Unique DNS labels per query prevent resolver caching | Custom authoritative DNS |
| Resolution failure fall-through | DNS fails during validation → guard skips → client re-resolves | Intermittent DNS |
| Dual-IP authoritative | Custom DNS returns different A records by query counter | Custom authoritative DNS |
| nip.io/sslip.io | `127.0.0.1.nip.io` resolves to `127.0.0.1` | None |

### Redirect Abuse

- Allowlist applied pre-redirect only: 302 from attacker → internal host
- Go `http.Client` follows up to 10 redirects by default without re-validating
- Ruby `Kernel.Open` follows redirects without re-checking allowlist
- Multi-hop and protocol switches (http→file/gopher via custom clients)
- Whitelisted third-party domain returns 302 to internal IP

### Header and Method Control

- Some sinks reflect or allow CRLF-injection into the request line/headers
- If arbitrary headers/methods are possible, IMDSv2, GCP v1, and Azure become reachable

## Defense-Bypass Pairs

Specific defenses observed in the wild and the exact technique that defeated each:

| Defense | Bypass | Condition |
|---|---|---|
| String-match `localhost` blocklist | DNS-resolves-to-loopback domain (`evil.com` → `127.0.0.1`) | Any |
| PHP `filter_var(FILTER_VALIDATE_IP)` guard | Non-standard IP format (decimal/octal/hex) → guard skips entirely | PHP |
| DNS-rebinding-safe resolution (pin IP) | DNS failure fall-through → caller falls back to hostname → client re-resolves | DNS error path |
| GCP `Metadata-Flavor: Google` header requirement | `/v1beta1/` endpoint does not enforce header | GCP |
| HTTP client `CheckRedirect` policy | Go default follows 10 redirects without re-validating | Go |
| Host allowlist regex without anchors | Trusted domain as path segment: `evil.com/allowed.co/path` | Regex-based |
| AsciiDoctor attribute lock (`name!`) | `counter` macro ignores parse-time locks, re-enables attribute | AsciiDoctor |
| Domain whitelist on URL parameter | Redirect-following after whitelist check: initial URL passes, 302 to internal | Redirect following |
| IP blocklist on private ranges | CNAME chain with unique labels prevents resolver caching | Custom DNS |
| CDN origin allowlist (e.g., Cloudflare) | Allowlist not configured = default open | CDN default |
| SSRF filter on public API | Backend rendering worker in different trust zone lacks the filter | Multi-tier arch |

## Blind SSRF

- Use OAST (DNS/HTTP) to confirm egress
- Derive internal reachability from timing, response size, TLS errors, and ETag differences
- Build a port map by binary searching timeouts (short connect/read timeouts yield cleaner diffs)
- Error-message discriminators: tabulate distinct error messages → map to distinct network states (open/closed/filtered) → use as blind port scanner

## Chaining Attacks

### SSRF → Cloud Metadata → Cluster Takeover
Screenshot SSRF on headless browser → GCP metadata `/v1beta1/` (no header) → dump `kube-env` → extract kubelet client cert+key → kubectl list pods → describe pod to find secret name → read secret (SA token) → exec into pod as root. ($25K Shopify)

### SSRF → AWS IMDS → Cloud Account
DNS rebinding or filter bypass → `169.254.169.254/latest/meta-data/iam/security-credentials/` → temporary IAM credentials → AWS API access. (Multiple programs)

### SSRF → Internal API → Data Exfiltration
Path traversal in cookie → whitelisted redirect → internal subdomain → APK download → token extraction → complete app compromise. (H1 CTF chain)

### SSRF → Port Scan → Service Discovery → RCE
Blind SSRF + timing oracle → map internal ports → discover Redis/Docker/Jolokia → execute commands via protocol smuggling.

### SSRF via Kafka Connect → Jolokia → MBean → RCE
`HttpSinkConnector` URL → internal Jolokia JMX endpoint → load malicious MBean → arbitrary code execution.

### Angular Universal Host Header → Redirect → Cloud Metadata → IAM
Framework-level SSRF via Host header in SSR → redirect amplification → cloud metadata → cloud account compromise. ($500K+ class — every Angular Universal app affected)

## Internal Surface Enumeration

After confirming SSRF, execute these steps in order — do not stop at confirmation:

1. **Discover internal hostnames you don't already know** — query metadata service-discovery endpoints, read `/etc/hosts`, probe DNS for `*.internal`, `*.local`, `*.svc.cluster.local`
2. **Port-sweep each discovered host** — use timing differentials (open=fast RST, closed=timeout) on common ports: 80, 443, 8080, 8443, 6379, 9200, 5432, 3306, 27017, 2375, 10250, 9090
3. **Sweep well-known paths** — for each open port, probe `/admin`, `/debug`, `/metrics`, `/healthz`, `/api`, `/console`, `/v1/`, `/internal/`, `/_cat/indices`, `/pods`
4. **Pivot to authenticated context** — use cloud metadata credentials (IAM/SA tokens) or leaked service-to-service tokens to authenticate against discovered internal APIs
5. **Extract the prize** — read secrets, database contents, environment variables, or configuration that proves durable impact beyond "I can reach internal hosts"
6. **Write-side primitives if read alone is insufficient** — Redis `SET`/`CONFIG SET`, Docker container creation, FastCGI file write, cron job injection

**Anti-pattern: DO NOT file a report that lists hypothetical impacts.** "An attacker COULD access internal services" is not a finding — "attacker DID extract IAM credentials / DID read database records / DID execute commands" is a finding. Execute the chain or downgrade to informational.

## Testing Methodology

1. **Identify surfaces** — every user-influenced URL/host/path across web/mobile/API and background jobs
2. **Check discovery signals** — scan for technology fingerprints in the table above
3. **Establish oracle** — quiet OAST DNS/HTTP callbacks first
4. **Internal addressing** — pivot to loopback, RFC1918, link-local, IPv6, hostnames
5. **Protocol variations** — test gopher, file, dict where supported
6. **Parser differentials** — test URL confusion patterns from the table above
7. **Redirect behavior** — single-hop, multi-hop, protocol switches
8. **Header/method control** — can you influence request headers or HTTP method?
9. **High-value targets** — metadata (try v1beta1 first), kubelet, Redis, FastCGI, Docker

## Persistence & Retry Discipline

Never mark an endpoint "not vulnerable to SSRF" after 1-2 denials. A rejected payload means ONE payload shape failed — not that the endpoint is safe. Run the variant matrix below before dismissing.

**Variant matrix — try at least one from each row before concluding "safe":**

| Variant class | Examples |
|---|---|
| Parameter name | If `url=` fails, try: `link`, `src`, `target`, `dest`, `redirect`, `next`, `return`, `callback`, `webhook`, `host`, `proxy`, `fetch`, `preview`, `feed`, `image`, `avatar`, `import`, `source`, `uri`, `site` |
| Scheme | `http://`, `https://`, `//` (protocol-relative), `\\`, no-scheme, `file://`, `gopher://`, `dict://`, `ftp://`, `smb://`, `jar://`, `netdoc://` |
| Address encoding | `127.0.0.1`, `0.0.0.0`, `0x7f.0.0.1` (hex), `0177.0.0.1` (octal), `2130706433` (decimal), `127.1`, `[::1]`, `[::ffff:127.0.0.1]`, `localhost`, DNS rebinding hostname |
| URL parsing tricks | `@` auth embed (`http://allowed@internal`), `#` fragment drop, `?` query-string hide, double-slash `http://allowed/..\@internal`, userinfo `http://internal#@allowed`, URL-encoded `%2F`, double-encoded `%252F` |
| Redirect abuse | Submit a URL you control that 301/302 redirects to the internal target — server follows the redirect with no allowlist re-check on the second hop |
| DNS rebinding | Use `rbndr.us` (zero-infra: `7f000001.c0a80001.rbndr.us`) or `nip.io` (`127.0.0.1.nip.io`) |

**Guideline**: if N variant classes are available and time permits, try 3 classes × 3 payloads = 9 attempts before dismissing an endpoint.

**Also vary param location**: if body `url=` is blocked, try query string `?url=`, path parameter `/fetch/http:/...`, nested JSON `{"options":{"src":"..."}}`, cookie values, headers.

**False negatives that look like denials**:
- `200 OK` with empty body — backend may have fetched successfully and returned nothing (check OAST callback)
- `500 Internal Server Error` — often SSRF working but upstream target crashed/timed-out (internal service is there)
- Slow responses (>5s) — internal port probe with silent drops; use time-based inference
- `403 Forbidden` with no details — could be WAF, could be internal target rejecting our request. Test with OAST to differentiate.
- Status code differential: `400` = filter rejected before fetch; `404` = filter passed, fetch happened but target returned nothing. This single diagnostic distinguishes "filter blocked" from "filter passed."

## Validation

1. Prove an outbound server-initiated request occurred (OAST interaction or internal-only response differences)
2. Show access to non-public resources (metadata, internal admin, service ports) from the vulnerable service
3. Where possible, demonstrate minimal-impact credential access (short-lived token) or a harmless internal data read
4. Confirm reproducibility and document request parameters that control scheme/host/headers/method and redirect behavior

## False Positives

- Client-side fetches only (no server request)
- Strict allowlists with DNS pinning and no redirect following
- SSRF simulators/mocks returning canned responses without real egress
- Blocked egress confirmed by uniform errors across all targets and protocols
- OAST callbacks where the source IP matches the tester's machine, not the server

## Impact

- Cloud credential disclosure with subsequent control-plane/API access
- Access to internal control panels and data stores not exposed publicly
- Lateral movement into Kubernetes, service meshes, and CI/CD
- RCE via protocol abuse (FCGI, Redis), Docker daemon access, or scriptable admin interfaces

## Pro Tips

1. Prefer OAST callbacks first; then iterate on internal addressing and protocols
2. **Always try GCP v1beta1 before v1** — the header requirement bypass is the single highest-value SSRF technique
3. Test IPv6 and mixed-notation addresses; filters often ignore them
4. Observe library/client differences (curl, Java HttpClient, Node, Go); behavior changes across services
5. Redirects are leverage: control both the initial allowlisted host and the next hop
6. **Fingerprint the defense first**: identify what specific filter/guard is in place, then select the matching bypass from the Defense-Bypass table
7. Use tiny payloads and tight timeouts to map ports with minimal noise
8. When responses are masked, diff length/ETag/status and TLS error classes to infer reachability
9. Chain quickly to durable impact (short-lived tokens, harmless internal reads) and stop there
10. **After confirming SSRF, immediately pivot to cloud metadata** — this is the highest-value chain and the one that turns Medium into Critical
11. Treat PDF/report generation (wkhtmltopdf, headless Chrome, WeasyPrint) as SSRF surfaces with JS execution -- `<iframe src="http://169.254.169.254/...">` inside rendered HTML ($4K)
12. WebRTC TURN/STUN servers are SSRF surfaces: `TURN` relay requests let you bounce TCP to internal hosts via `XOR-PEER-ADDRESS` ($700)
13. SaaS tools ingested into internal networks (Sentry, Datadog, log forwarders) have server-side features that fetch from internal addresses -- audit the tool, not just the app ($3.5K)
14. Cross-platform path APIs are SSRF gadgets on Windows: `\\server\share` UNC paths in file:// URLs or path parameters reach internal SMB/WebDAV ($4.3K)

## Summary

Any feature that fetches remote content on behalf of a user is a potential tunnel to internal networks and control planes. Bind scheme/host/port/headers explicitly or expect an attacker to route through them.
