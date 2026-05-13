---
name: cloudflare
description: Cloudflare attack surface: origin IP exposure, Worker injection, cache poisoning, WAF bypass
depends_on: []
---

# Cloudflare

Cloudflare fronts a large fraction of the web. Bugs typically circle: origin IP exposure (bypassing CF entirely), Worker code injection, cache poisoning via unkeyed headers, and WAF rule bypasses.

## Common Bug Classes

- Origin IP exposure via DNS history, certificate transparency, mail headers
- Worker code accepting arbitrary KV writes from request body
- Cache poisoning via unkeyed headers (`X-Forwarded-Host`, `X-HTTP-Method-Override`)
- WAF bypass via path normalization, parameter encoding, Unicode tricks
- Tunnel / Argo origin reachable directly if firewall not configured
- Web cache deception on authenticated endpoints behind CF proxy
- `/cdn-cgi/` feature endpoint abuse (image resizing SSRF, trace info disclosure)
- Cloudflare Access bypass via origin direct access or alternative auth endpoints

## Origin IP Discovery (197 reports, $69K corpus)

This is the single highest-volume Cloudflare attack pattern. Once the origin IP is found, ALL WAF/CDN protections are bypassed.

### Discovery Techniques
1. **DNS history**: SecurityTrails, ViewDNS.info, DNSdumpster for pre-Cloudflare A records
2. **Certificate transparency**: Search crt.sh for certificates issued to the domain — SANs often reveal origin IPs or internal hostnames
3. **Mail headers**: Send a password reset or signup email, inspect `Received:` headers for origin IP
4. **Censys/Shodan**: Search for TLS certificates with the target's domain in Subject CN or SAN, filter by non-Cloudflare IP ranges
5. **Direct IP scanning**: If you find a candidate IP, confirm by sending `Host: target.com` to that IP and comparing the response to the CF-proxied response
6. **Outbound connection triggers**: If the app fetches external URLs (webhooks, image previews, link unfurling), make it connect to a server you control — the source IP is the origin
7. **IPv6**: Many targets only proxy IPv4 through Cloudflare; the AAAA record may point directly to origin

### Validation After Discovery
Once you have a candidate origin IP:
1. Confirm the origin serves the same content as the CF-proxied domain
2. Verify the origin's firewall does NOT restrict to Cloudflare IP ranges only
3. Test whether the origin accepts requests without CF-specific headers (no `CF-Connecting-IP` validation)
4. Check for admin panels, debug endpoints, or internal APIs accessible on the origin but blocked by CF WAF rules

## Cache Poisoning Attacks

### Unkeyed Header Brute Force
1. Confirm caching: look for `cf-cache-status: HIT`, `Age` header, or `Vary` header
2. For each cacheable URL, inject headers one at a time and check if the response changes:
   - `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`
   - `X-Original-URL`, `X-Rewrite-URL`
   - `X-HTTP-Method-Override`
   - Custom headers specific to the backend framework
3. If a header changes the response body AND is not in the cache key, you have cache poisoning
4. Escalate: inject `<script>` via the reflected header value for stored XSS via cache

### Web Cache Deception
For any authenticated page behind Cloudflare:
1. Append cacheable extensions: `/account/settings/style.css`, `/api/me/image.jpg`
2. Check if `cf-cache-status` returns `HIT` on the response containing auth data
3. If the response is cached, any unauthenticated user requesting the same URL gets the victim's data
4. Test path variations: `/account/settings/..%2fstyle.css`, `/account/settings%00.css`

### Cache Key Normalization Differential
1. Test whether the cache key normalizes URLs differently than the origin
2. Try: encoded query separators (`%3f`), double-encoded paths (`%252e%252e`), case differences
3. If cache and origin disagree on what URL is being requested, craft a poisoned cache entry that serves to a different URL's visitors

## Cloudflare Feature Endpoint Abuse

### `/cdn-cgi/` Path Exploitation
1. **Image resizing**: `/cdn-cgi/image/width=100/https://internal-host/secret` — test for SSRF via the image source parameter
2. **Trace**: `/cdn-cgi/trace` — discloses visitor IP, Cloudflare colo, TLS version, HTTP protocol
3. **Challenge page**: Test if challenge endpoints leak information or can be bypassed

### Cloudflare Access Bypass
When a target uses Cloudflare Access (zero-trust proxy):
1. Find the origin IP (see above) — Access is enforced at the CF edge, not the origin
2. Enumerate authentication endpoints: some paths may not be covered by Access policies
3. Test `/.well-known/` paths, API endpoints, and webhook URLs — these are often excluded from Access policies
4. Check for `CF-Access-Jwt-Assertion` header tampering if the origin trusts it without verification

## WAF Bypass Techniques

1. **Double encoding**: `%2522` instead of `%22` — CF WAF decodes once, backend decodes twice
2. **Non-standard ASCII**: Insert characters like `%EF%BC%9C` (fullwidth `<`) that the WAF ignores but the browser renders
3. **Chunked transfer encoding**: Break the payload across chunk boundaries so no single chunk matches WAF signatures
4. **Content-Type confusion**: Send `application/x-www-form-urlencoded` body with `Content-Type: multipart/form-data` — WAF parses one way, backend parses another
5. **HTTP/2 pseudo-headers**: Inject via `:path` or `:authority` pseudo-headers that WAF rules do not inspect

## Subdomain Takeover via Cloudflare

1. Find CNAME records pointing to `*.cloudflare.net` or `*.cdn.cloudflare.net`
2. If the Cloudflare zone/site has been deleted, the CNAME dangles
3. Validate by attempting to claim the hostname in a Cloudflare account before reporting
4. Also check for dangling `NS` delegations to Cloudflare nameservers for decommissioned zones

## Cloudflare Workers Exploitation

When the target uses Cloudflare Workers (edge-side JavaScript):
1. Workers run in V8 isolates — test for isolate escape if the Worker processes untrusted input
2. Workers can read/write KV (key-value) stores — if the Worker accepts user input as KV keys, test for unauthorized data access
3. Workers often implement auth logic — test if the Worker's auth check can be bypassed by sending requests directly to the origin (bypassing the Worker entirely)
4. Durable Objects (stateful Workers) may have race conditions — test concurrent requests to the same Durable Object
5. Workers Secrets (env vars) may leak in error responses or be accessible via `console.log` in development Workers

## Deployment Artifact and Pipeline Leakage

For Cloudflare Pages and Workers Sites deployments:
1. Check for `.git/` directory exposure on the origin or via direct S3/R2 bucket access
2. Cloudflare Pages builds from git — check if the `_headers` and `_redirects` files are misconfigured
3. Test `/_functions/` path for exposed Cloudflare Pages Functions (serverless functions)
4. Check R2 (Cloudflare's S3-compatible storage) for public bucket access if the target uses R2 as origin

## Path Normalization Differential (Filter/Router Mismatch)

When Cloudflare sits in front of any application:
1. Test path normalization differences: Cloudflare normalizes `//`, `/../`, `/./` differently than most backends
2. Send `/%2e%2e/admin` — Cloudflare may see `/admin` (blocked), but the backend may see `/../admin` (allowed after normalization)
3. Test with semicolons: `/admin;.css` — Cloudflare may see a `.css` request (cacheable), backend sees `/admin` with a path parameter
4. Test with backslash: `/admin\..\/secret` — different parsers handle backslash differently on different OS

## Probe Targets

- DNS history (SecurityTrails, ViewDNS) for pre-CF IPs
- censys.io for cert with Subject CN matching origin
- Test cache key with fuzzed headers; check `cf-cache-status`
- Probe `?cb=<random>` to bypass cache and see origin behavior
- `/cdn-cgi/trace` for info disclosure, `/cdn-cgi/image/` for SSRF
- Send `PURGE` method to test unauthenticated cache purging
- Test authenticated pages with `.css`/`.js`/`.jpg` extensions for cache deception
- Enumerate Cloudflare Access-excluded paths (webhooks, APIs, health checks)
- Check for `.git/`, `.env`, `wp-config.php` on the origin IP directly

## Cross-References

`waf_bypass`, `cache_poisoning`, `origin_finder`, `deep_subdomain_enum`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
