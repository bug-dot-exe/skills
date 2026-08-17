---
name: fastly
description: Fastly attack surface: VCL flaws, custom headers, secondary cache key gaps
depends_on: []
---

# Fastly

Fastly uses VCL for edge logic. Bugs are usually in custom VCL: improper sanitization, secondary key construction, or trust of client headers.

## Common Bug Classes

- VCL not sanitizing X-Forwarded-* headers
- Cache key constructed from user-controlled headers without normalization
- Fastly origin IP exposure via Surrogate-Key debug
- Image API (`/IMG-*`) abuse for SSRF or DoS
- HTTP request smuggling between Fastly edge and origin
- Cache poisoning via unkeyed headers and cookies
- Subdomain takeover on dangling Fastly CNAME records
- ESI injection in Fastly-processed responses
- Web cache deception on authenticated endpoints

## Cache Poisoning (83 reports, $1.2M corpus)

### Unkeyed Header/Cookie Discovery
1. Enumerate every header and cookie that is reflected in any cached path
2. For each reflection, test whether the reflecting header/cookie is included in the cache key
3. If reflected but not keyed, inject XSS payload in the header/cookie value, request the page to cache it
4. Chain: cache poisoned page with XSS payload -> any visitor to that URL gets the XSS -> session hijack
5. Send `Fastly-Debug: 1` to see cache key details in response headers

### CDN Behavior Probing
For every Fastly-fronted target, systematically probe:
- What headers are in `Vary`? (each one is potentially keyed)
- What parameters are in the cache key? (test by varying params and checking for cache HIT/MISS)
- Does the origin set `Surrogate-Control` or `Surrogate-Key`?
- Does the `Accept` header change the response? (content negotiation poisoning)
- Is the `Host` header normalized before keying? (test with port numbers, case changes)

### Two-Parser Differential Smuggling
1. Identify the HTTP parsing chain: Fastly -> origin (Apache, Nginx, Node, Tomcat)
2. Send ambiguous HTTP with conflicting `Content-Length` and `Transfer-Encoding`
3. Test all four desync variants: CL.TE, TE.CL, TE.TE (obfuscated), H2.CL
4. Timing-based desync: pause mid-request body — if Fastly and origin have different timeout behaviors, the desync window opens
5. HTTP/2 front-end to HTTP/1.1 origin: inject via pseudo-header manipulation (`:path` with CRLF)

## VCL-Specific Vulnerabilities

### Custom VCL Edge Logic Flaws
1. If the target uses Fastly's custom VCL, the VCL code IS the security enforcement layer
2. VCL `recv` subroutine: test if `req.http.X-Forwarded-For` is trusted without validation — VCL may use it for IP-based access control
3. VCL `deliver` subroutine: test if response headers are built from request headers without sanitization
4. VCL `error` subroutine: test if error responses (custom error pages) reflect request data unsanitized
5. VCL hash subroutine: if the cache hash includes client-controlled data, test for collisions

### Surrogate-Key and Cache Tag Manipulation
1. If the target uses `Surrogate-Key` headers for cache tag-based purging
2. Test if you can inject `Surrogate-Key` values via request headers that flow into the response
3. If you control a cache tag, you may be able to purge arbitrary cached content (DoS via selective cache eviction)

## Subdomain Takeover

### Dangling Fastly CNAME
1. Scan for CNAME records pointing to Fastly endpoints (`*.fastly.net`, `*.freetls.fastly.net`)
2. If the Fastly service has been deleted or the domain is not configured, the CNAME dangles
3. Claim by creating a new Fastly service with the target domain
4. After takeover, check if the subdomain appears in CSP `script-src`, CORS allowlists, or OAuth `redirect_uri` whitelists — each extends the impact

### Cross-Tenant Inference
When a SaaS platform uses Fastly with per-tenant subdomains:
1. Fastly may serve different tenants from the same CDN edge configuration
2. Test if requests to one tenant's CDN domain can leak information about another tenant
3. Check `Surrogate-Key` headers for cross-tenant cache tag leakage

## Web Cache Deception

1. For every authenticated endpoint behind Fastly:
   - Append cacheable extensions: `/account/settings/style.css`, `/api/me/avatar.jpg`
   - Check `X-Cache`, `Age`, `X-Served-By` headers for cache HIT indicators
2. Test path confusion techniques:
   - `/account/..%2fstatic/app.css` — Fastly may normalize the path differently than the origin
   - `/account%00.css` — null byte before extension
   - `/account;param=value.css` — semicolon path parameter
3. If the authenticated response is cached, verify exfiltration by requesting the same URL from an unauthenticated session

## JSONP and Callback Cache Enumeration

1. Find any JSONP endpoint that includes the callback name in its cache key
2. Fuzz callback names to enumerate cached responses from different users/states
3. If the JSONP response includes user-specific data and the callback is part of the cache key, different callback values may serve different users' cached data

## Origin Discovery and Bypass

1. Same techniques as other CDNs: DNS history, cert transparency, mail headers, outbound triggers
2. Fastly-specific: check `X-Served-By` header for edge POP identification
3. Test if the origin accepts connections from non-Fastly IP ranges
4. If Fastly shielding is configured, the shield POP is an intermediate origin — find the real origin behind it

## Connection Pool and Object Cache Auditing

### Security-Context Cache Key Inclusion
For any Fastly-fronted target that caches based on authentication state:
1. Identify the cache key components — does the cache key include the auth cookie or token?
2. If auth state is NOT in the cache key, authenticated responses serve to unauthenticated users (cache deception) and vice versa
3. Test if the `Authorization` header is included in cache key — it usually is NOT by default
4. Test if session cookies with different user IDs produce different cache entries or share one

### Connection Reuse Attack Surface
Fastly reuses connections to the origin for multiple client requests:
1. If the origin trusts the connection state (TLS client cert, authenticated connection), test whether a second request on the same connection inherits the first request's auth
2. This is especially relevant for H2 connection multiplexing where multiple streams share one connection
3. Test if connection reuse crosses security contexts (authenticated -> unauthenticated requests on the same connection)

## Fastly Image Optimization SSRF

1. If the target uses Fastly Image Optimization (`/io/` paths or `?width=&height=`), the image source URL may be controllable
2. Test: pass internal URLs as the image source — `?src=http://169.254.169.254/latest/meta-data/`
3. Test: pass `file://` protocol URLs if the image processor runs locally
4. Test: pass very large dimensions to trigger DoS via memory exhaustion in the image processor
5. Image optimization endpoints often have different WAF rules than the main application

## Trusted Host List Inheritance

After discovering any Fastly-related subdomain:
1. Check every CSP, CORS, frame-ancestors, postMessage origin allowlist, and OAuth redirect_uri whitelist for Fastly-served domains
2. Particularly check for `*.fastly.net` or `*.freetls.fastly.net` in allowlists — these are shared across all Fastly customers
3. If a Fastly subdomain is in a trust list, taking over that subdomain (via dangling CNAME) escalates to the trust boundary

## Probe Targets

- Send `Fastly-Debug: 1` and `Fastly-FF` to capture routing info and cache key details
- Test image transformation endpoints for SSRF parameters (`/IMG-*` paths)
- Send conflicting CL/TE headers to probe for request smuggling
- Test authenticated pages with cacheable extensions for cache deception
- Fuzz unkeyed headers on cached endpoints, compare responses for reflection
- Scan CNAME records for `*.fastly.net` dangling references
- Test `Surrogate-Key` header injection via request headers
- Check `X-Served-By` for edge POP info and `X-Cache` for hit/miss status
- Probe VCL error pages for request data reflection (custom 403/404 pages)

## Cross-References

`waf_bypass`, `cache_poisoning`, `ssrf`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
