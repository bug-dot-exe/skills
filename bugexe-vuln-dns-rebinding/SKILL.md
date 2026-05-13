---
name: dns-rebinding
category: vulnerabilities
description: DNS rebinding to bypass IP allowlists, exploit TOCTOU between resolve-and-validate and resolve-and-fetch, and reach localhost-only services
depends_on: []
---

# DNS Rebinding

DNS rebinding turns a domain into a moving target. The first lookup returns an allowed IP (passes the SSRF/same-origin check); a millisecond later the cache expires and the second lookup returns an internal IP (the actual fetch lands inside the perimeter). Every IP allowlist that does not pin the resolved address is at risk.

## Discovery Signals

Technology fingerprints indicating high DNS rebinding probability:

| # | Signal | Where to Find | Why Vulnerable |
|---|--------|---------------|----------------|
| 1 | URL fetch feature (preview, webhook, OEmbed, avatar import) | App UI, API docs | Server-side fetch with separate validate+fetch steps = classic TOCTOU |
| 2 | `requests.get(url)` / `http.Get(url)` in server code | Source audit, error messages revealing library | HTTP library re-resolves DNS independently from validation |
| 3 | Node.js `--inspect` on non-loopback interface | `netstat`/`ss` output, process flags | Inspector WebSocket gives RCE; Host header validation has platform gaps |
| 4 | Local service bound to `0.0.0.0` instead of `127.0.0.1` | `netstat -an`, `lsof -i` | LAN-exposed plus browser-reachable via rebinding |
| 5 | Image resizer / PDF renderer / headless Chrome | Feature docs, response headers (`wkhtmltopdf`, `Puppeteer`) | Long-running render = seconds of rebind window |
| 6 | SSRF fix that validates input URL but follows redirects | Prior SSRF report patched, new test | Redirect target not re-validated = rebinding alternative |
| 7 | Cloud-hosted app (GCP/AWS/Azure) with URL import | `Server` header, cloud IP ranges | `169.254.169.254` metadata is the ultimate rebind target |
| 8 | Saved webhook URL re-fetched by background worker | Webhook config, cron job docs | Hours between save and fetch = trivial rebind window |
| 9 | SSO/OIDC issuer URL fetch (JWKS endpoint) | Auth flow, token validation code | Server fetches attacker-controlled issuer URL |
| 10 | Sandbox/notebook with network egress | Kaggle, Colab, CI runners | Code execution + metadata IP access = instant credential theft |
| 11 | Third-party error-tracking with source-fetch (Sentry, Bugsnag) | CSP headers reveal DSN key | Sentry fetches `filename` URLs from forged stacktraces |
| 12 | TURN/STUN server in scope (WebRTC infrastructure) | Port scan for 3478/5349, ICE candidate inspection | TURN relays to any `XOR-PEER-ADDRESS` including internal IPs |

## Attack Surface

**Server-Side (SSRF variant)**
- Any URL fetcher with an IP-based allowlist/blocklist done in a separate step from the HTTP fetch
- URL preview, webhook tester, OEmbed, avatar importer, RSS/OPML, calendar ICS fetch, OAuth userinfo endpoint
- Backend crawlers (Slack unfurls, Discord embeds, GitHub link previews)
- Image resizers, PDF renderers, headless Chrome screenshot services
- SSO/OIDC validators that fetch JWKS from user-supplied issuer URLs

**Client-Side (same-origin variant)**
- Browser-loaded page that queries `http://localhost:PORT/` or internal IP -- same-origin is bypassed by rebinding attacker's domain to the victim's LAN
- IoT local APIs (Sonos, Plex, Roku, home router admin), developer tooling (Jupyter, Elastic, Consul UI, Docker Desktop), cloud agents (Kubelet readonly, cloud-init)
- Desktop apps with embedded HTTP (Electron, Spotify, Slack, Zoom helpers listening on localhost)
- Chrome/Firefox pin to the first resolved IP per-connection but drop pinning on TTL expiry or connection reset

**Integrations**
- SSRF filters that only block RFC1918 by string match (rebinding to the IP form never appears in user input)
- Link-time validators that validate once at save, not at each fetch

## DNS Rebinding Variant Matrix

| # | Variant | Technique | TTL Requirement | Target |
|---|---------|-----------|----------------|--------|
| 1 | Classic TTL-0 flip | Authoritative DNS returns TTL=0; first response=external, second=internal | TTL=0 (some resolvers enforce min 30s) | Any TOCTOU URL fetcher |
| 2 | Multi-answer rotation | Single DNS response with both external and internal A records; resolver picks alternately | Any TTL | Resolvers that round-robin A records |
| 3 | IPv4/IPv6 preference flip | AAAA=`::ffff:127.0.0.1`, A=external; target prefers IPv6 on second attempt | Any TTL | Java/Python defaults that prefer v6 |
| 4 | CNAME chain rotation | `attacker.com CNAME rebind.attacker.com`; rotate target of CNAME between queries | TTL=0 on CNAME | Fetchers that follow CNAME chains |
| 5 | Connection-reset forced rebind | `Connection: close` or large response forces new TCP; new TCP = new DNS | N/A (bypasses pinning) | Chrome/Firefox with per-connection pinning |
| 6 | Subdomain-per-attempt | `a.attacker.com`, `b.attacker.com` each with independent rebind | TTL=0 per subdomain | Browsers that pin per-hostname |
| 7 | Platform-specific localhost | macOS routes `0.0.0.0` to loopback; `.local` mDNS resolution | N/A | Node.js `--inspect`, macOS-specific services |
| 8 | Retry-window rebind | Serve 500 externally, trigger fetcher retry; retry re-resolves to internal | TTL < retry interval | Fetchers with automatic retry on 5xx |

## High-Value Targets

### Rebindable Public Services

| Service | Usage |
|---------|-------|
| `rbndr.us` | `curl http://7f000001.1.2.3.4.rbndr.us/` -- alternates 127.0.0.1 / 1.2.3.4 |
| `lock.cmpxchg8b.com` | Tavis Ormandy's rebinder, used in Chrome bug research |
| Singularity of Origin (NCC) | Self-hosted, full web UI, handles multi-answer and payload delivery |
| custom BIND / dnschef | Full control of TTL, responses, and timing |

Singularity is the default tool when scope permits custom infra: it runs the DNS server + HTTP attacker page + payload bank in one binary.

### Short-TTL and CNAME Tricks

- Set authoritative TTL to 0 (some resolvers enforce min 30s; try 1, 5, 30)
- Return multi-answer A records and rely on resolver choosing one, then the other (RFC does not guarantee order)
- CNAME chain: `attacker.com CNAME rebind.attacker.com`; rotate the target of `rebind.attacker.com` between queries
- Mix IPv4 and IPv6 answers -- target sometimes prefers IPv6 (internal) over IPv4 (external) or vice versa
- Serve AAAA with `::ffff:127.0.0.1` and A with public IP

### Classic SSRF Integration

- App validates user-supplied URL: resolves `attacker.com` -> `1.2.3.4` (external, OK)
- Fetches `http://attacker.com/`: re-resolves -> `127.0.0.1` -> hits local AWS metadata shim, `169.254.169.254` via second-stage rebind, or internal admin API
- Key: the allowlist code does the resolve itself; the HTTP library does its own resolve on the socket call

### Localhost / LAN Services

After rebind to `127.0.0.1` or `192.168.x.x`:
- `169.254.169.254` -- cloud metadata (EC2, GCE, Azure)
- `127.0.0.1:2375` -- Docker daemon (unauthenticated -> RCE via container create)
- `127.0.0.1:8500` -- Consul API
- `127.0.0.1:9200` -- Elasticsearch (read indexes, run scripts on vulnerable versions)
- `127.0.0.1:6379` -- Redis (RCE via config rewrite in some configs)
- `127.0.0.1:10250` -- Kubelet
- `127.0.0.1:9229` -- Node.js Inspector (RCE via `Runtime.evaluate`)
- Home routers: `192.168.0.1`, `192.168.1.1`, admin UI
- `127.0.0.1:11211` -- Memcached
- `127.0.0.1:5000` -- Flask/Gunicorn dev servers
- `127.0.0.1:8080` -- Jenkins, Tomcat manager

## SSRF-to-Rebinding Escalation

| # | SSRF Type | Rebinding Technique | Why It Works | Impact |
|---|-----------|-------------------|--------------|--------|
| 1 | Blocked by IP blacklist (RFC1918 string match) | Rebind domain to internal IP after validation passes | Blacklist checks submitted URL, not resolved IP at fetch time | Full SSRF bypass |
| 2 | Fixed SSRF with input-URL validation | 302 redirect from external to internal (rebinding alternative) | Fetcher follows redirect without re-validating destination | AppSheet fix bypass ($50k) |
| 3 | Blind SSRF via third-party tool (Sentry filename) | Rebind attacker domain in filename to metadata IP | Sentry source-fetch re-resolves at fetch time | Cloud credential theft |
| 4 | TURN/STUN relay SSRF | Set XOR-PEER-ADDRESS to internal IP directly | TURN is designed to relay; no destination allowlist | Slack internal network + metadata ($3.5k) |
| 5 | Partial metadata access (v1 requires header) | Use `v1beta1` path that skips `Metadata-Flavor` header requirement | Legacy API version has weaker auth | Caja playground token theft ($233k) |
| 6 | Cloud sandbox with code exec (notebook, CI runner) | Direct `curl` to `169.254.169.254` from sandbox | No network policy blocking link-local egress | Kaggle metadata theft ($313k) |

## Key Vulnerabilities

### TOCTOU Pattern Recognition

Vulnerable pseudocode:
```python
def fetch_url(url):
    host = urlparse(url).hostname
    ip = socket.gethostbyname(host)        # Resolution #1
    if is_private(ip):
        raise Forbidden
    return requests.get(url)               # Resolution #2 (separate DNS call)
```

The two `gethostbyname` calls happen seconds apart -- a TTL=0 response lets the second one return a different IP.

Safer patterns to look for (if present, rebinding unlikely):
```python
ip = socket.gethostbyname(host)
if is_private(ip): raise Forbidden
return requests.get(url, headers={'Host': host},
                    url=url.replace(host, ip))   # use resolved IP directly
```

### Time-Based Rebinding in Long Jobs

For screenshot / PDF / crawler sinks where processing takes seconds:
- First resource (HTML) loads from external IP (validates)
- Internal resource loads (image, script, iframe src) trigger new DNS lookup -> now internal

```html
<!-- attacker's page, served from public IP first -->
<iframe src="http://rebind.attacker.com/admin"></iframe>
<script>
  setTimeout(()=>fetch('http://rebind.attacker.com/secret'), 30000);
</script>
```

### Browser-Side Rebinding

Victim visits `http://attacker.com`. Page polls `http://attacker.com/proxy/localhost/admin`. DNS rotates; browser reconnects (force via `fetch` after cache expiry); now reaches victim's localhost service.

Browser pinning defeats this in newer Chrome/Firefox when TTL respected; bypass via:
- `Connection: close` to force new TCP (new DNS)
- Large response triggering new connection
- Multiple subdomains: `a.attacker.com`, `b.attacker.com` each with their own rebind
- HTTP/2 session reuse defeats per-connection pinning if resolver has already rotated

## Defense-Bypass Pairs

| # | Defense | Bypass Technique | Real-World Basis |
|---|---------|-----------------|------------------|
| 1 | IP blacklist on submitted URL | Rebind domain: passes blacklist, re-resolves to internal at fetch | Classic TOCTOU -- every SSRF filter without IP pinning |
| 2 | Host header validation (string match) | Hostname case (`Localhost`), trailing dot (`localhost.`), numeric IP (`2130706433`), IPv6 mapped | Node.js Inspector CVE-2018-7160 followups ($500-$4.2k) |
| 3 | Per-connection DNS pinning (Chrome/Firefox) | Force connection reset via `Connection: close` or large response | Browser rebinding research (NCC Singularity) |
| 4 | IMDSv2 / `Metadata-Flavor: Google` header | Use `v1beta1` endpoint which skips header requirement | Caja playground SSRF to GCE metadata ($233k) |
| 5 | SSRF fix on input URL (post-patch) | HTTP 302 redirect from attacker server to internal IP | AppSheet fix bypass ($50k) |
| 6 | Localhost binding (`127.0.0.1`) | macOS `0.0.0.0` routes to loopback; `.local` mDNS names | Node.js Inspector macOS rebind ($4.2k) |
| 7 | DNS-over-HTTPS resolver caching | Cross-resolver fuzzing: DoH caches differ from OS resolver | Target using Cloudflare DoH vs system resolver |
| 8 | WebSocket Origin header check only | Host header not validated for WS upgrade; or Origin validated but not per-frame | Inspector insufficient fix -- validate at upgrade only, not per-frame |

## Bypass Techniques

**TTL and Pinning**
- Use TTL=0, but also serve alternating A records within a single response (RFC allows, resolvers handle inconsistently)
- Cross-resolver fuzzing: if target uses a DNS-over-HTTPS resolver, its cache behavior differs

**Host-Header Split**
- Target may validate the host header text (substring match for "internal") but resolve normally -- feed it `safe.attacker.com` that rebinds

**URL Parser Differentials**
- Validator parses `http://attacker.com@127.0.0.1/` as host=attacker.com; fetcher treats it as userinfo and fetches 127.0.0.1 -- combine when one alone fails

**Retry Windows**
- Many fetchers retry on 500/timeout; first retry uses a fresh DNS resolution -- serve 500 externally and 200 internally

**Prewarm and Flip**
- Singularity "fast" strategy: answer first N queries with external, immediately switch. Tuned per target latency.

## Chain Patterns

| # | Chain | Severity Uplift | Example |
|---|-------|----------------|---------|
| 1 | Rebind -> SSRF -> cloud metadata -> IAM creds -> cloud takeover | Medium to Critical | Every cloud-hosted URL fetcher without metadata protection |
| 2 | Rebind -> internal Jenkins/Docker -> RCE -> pivot | Medium to Critical | Unauth Jenkins on 127.0.0.1:8080 via rebound fetcher |
| 3 | Browser rebind -> victim's router admin -> DNS hijack -> long-term MitM | Low to High | Consumer router admin UI on 192.168.1.1 |
| 4 | Rebind + stored-URL (second-order SSRF) -> worker re-fetch hours later | Low to High | Saved webhook URL re-fetched by background worker |
| 5 | SSRF fix bypass via redirect -> port scan internal network -> service discovery | Medium to High | AppSheet redirect bypass + FFUF port scan ($50k) |
| 6 | Sentry source-fetch SSRF -> rebind filename URL -> metadata token | Low to Critical | Blind SSRF via forged stacktrace + DNS rebind ($3.5k) |
| 7 | Node.js Inspector rebind -> `Runtime.evaluate` RCE -> dev cred theft -> supply chain | Medium to Critical | CVE-2022-32212 macOS variant ($4.2k) |
| 8 | TURN relay SSRF -> metadata creds -> AWS account compromise | Medium to Critical | Slack TURN server to 169.254.169.254 ($3.5k) |

## Testing Methodology

1. **Find the fetcher** - URL preview, webhook, OEmbed, avatar, RSS, OAuth issuer, Sentry source-fetch, TURN relay
2. **Quick OAST baseline** - Send `https://{uid}.oast.site/` and confirm server actually fetches; observe request headers (`User-Agent` reveals library)
3. **Probe for allowlist** - Try internal IPs directly: `http://127.0.0.1/`, `http://169.254.169.254/`. If blocked, suspect IP-based allowlist
4. **Set up rebinder** - Simplest: `http://7f000001.0a000001.rbndr.us/` (alternates 127.0.0.1 / 10.0.0.1). Full control: run Singularity or custom dnschef
5. **Submit rebind URL** - Hit the fetch N times rapidly to increase chance of second-resolve rotation
6. **Differential timing** - Some targets cache only for seconds; submit multiple times with brief delays to find the hit window
7. **Time-based (long jobs)** - For screenshot/PDF workers: host an HTML page that references `http://rebind.attacker.com/internal-resource` to trigger late fetch
8. **Redirect fallback** - If rebinding fails, try 302 redirect from your server to internal IP (bypass fix without DNS tricks)
9. **Exfil channel** - Internal response reflected via OAST (attacker's rebind page reads response and forwards to OAST), or via side-channel (response time, status, Content-Length)
10. **Post-fix retest** - After any SSRF/rebinding fix, test redirect-following, platform-specific localhost variants, and alternate metadata API versions

## Validation

1. DNS logs showing two different A responses within the TTL window (dig with timestamps, or Singularity's built-in log)
2. Application-side evidence the second fetch hit internal (response body from an internal service, credential exfil, OAST callback from internal egress)
3. Request-response pair where the target clearly believed it was fetching `attacker.com` (log line, UA) but reached internal
4. Reproducibility: a scripted rebinder (Singularity scenario file or dnschef config) that triggers consistently

## False Positives

- Target pins DNS after first resolution and uses the IP directly -- rebinding window closes; fetcher will never re-resolve
- Fetcher uses a SOCKS/proxied egress that resolves at the proxy, not locally, so attacker's DNS never serves the second response
- "Worked" callback actually came from the first (external) fetch, not from an internal resource -- verify by serving distinguishable content
- Browser-side rebind against a modern browser without forcing a connection reset -- Chrome's pinning defeats naive rebinders
- Triager pushback: "Rebinding is theoretical" -- preempt with Singularity scenario file + tcpdump/dig transcripts

## Impact

- Bypass of every IP-based SSRF defense that re-resolves DNS
- Cloud metadata credential theft -> full cloud account compromise
- RCE via internal Docker/Jenkins/Redis/Elastic when exposed to localhost
- LAN pivot from browser (home router, NAS, IoT) -> persistent presence
- Bypass of same-origin policy to read local-only responses

## Pro Tips

1. Use Singularity of Origin -- it bundles the DNS server, attacker HTTP, and payloads; faster than hand-rolling dnschef
2. Always test both `rbndr.us` (no setup) and a custom rebinder -- some targets blocklist known rebind services
3. Mix rebinding with a second-order sink: saved webhook URL re-fetched hours later by a background worker is very rebindable because the background worker re-resolves
4. For long-running renderers (PDF, screenshot), rebinding works without any timing tricks -- the render phase is measured in seconds
5. Track TTL behavior: `dig +trace +short attacker.com` from the target's resolver if you can infer it
6. IPv6 preference is real -- mix AAAA and A answers; many Java and Python defaults prefer v6
7. If the fetcher uses `curl --resolve`, it pins manually -- rebinding will not work; look for `requests.get(url)` idiomatic code
8. Pair with SSRF skill: rebinding is the tool, SSRF is the impact -- submit as "SSRF via DNS rebinding reaching X", not as "DNS rebinding" alone
9. Node.js with `dns.lookup` (which calls `getaddrinfo`) is rebindable; `dns.resolve4` is often cached longer -- behavior differs per library
10. Go's `net/http` default transport caches DNS for the lifetime of the Transport -- check if target creates fresh clients per request (rebindable) or reuses (not)
11. After ANY rebinding/SSRF CVE fix, read the patch diff and ask: what platform-specific localhost representations did it miss? (`0.0.0.0` on macOS, `.local` mDNS, IPv6 `::1`, numeric IP `2130706433`, trailing dot)
12. For cloud targets, always try `v1beta1` metadata paths first -- older API versions often skip header requirements that block standard SSRF
13. When direct rebinding fails, the redirect fallback (your server 302s to internal IP) bypasses most input-URL validators since they only check the submitted URL
14. TURN/STUN servers are relay-by-design: test `XOR-PEER-ADDRESS` pointed at RFC1918 and link-local ranges before attempting DNS tricks

## Common Triager Pushback and Counters

| Pushback | Counter |
|----------|---------|
| "Rebinding is theoretical" | Ship a Singularity scenario file or dnschef config that reproduces on demand |
| "IP allowlist blocks internal" | Show the DNS logs proving the second lookup returned internal IP after validation passed |
| "Fetcher has DNS pinning" | Find the one code path that does not pin -- e.g., retry handler, separate worker |
| "Cloud metadata has IMDSv2" | Rebind to an internal admin service instead; or use `v1beta1` which skips header requirement |
| "Requires attacker infrastructure" | Use `rbndr.us` for a zero-infra PoC first, then upgrade to Singularity for the final write-up |

## Summary

DNS rebinding exists because IP allowlists and DNS resolution are almost always separate steps. Control the DNS, pick your TTL window, and the second resolve lands anywhere you want. Combine with SSRF to reach cloud metadata or internal services, or combine with browser-based attacks to reach the victim's LAN.
