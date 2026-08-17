---
name: waf-detection
category: reconnaissance
description: WAF and firewall detection with bypass techniques using stealth HTTP, origin finding, and evasion
depends_on: []
---

# WAF Detection and Bypass

Identify what sits between you and the target, then find ways around it. A WAF that blocks your payloads is useless recon unless you know it exists and can route around it.

## When to Use

- Payloads are being blocked or sanitized unexpectedly
- Responses contain WAF-specific error pages or headers
- You need to find the origin server behind a CDN/WAF
- Testing requires stealth to avoid rate limiting or IP bans

## Methodology

### Phase 1: WAF Detection

1. Send a benign request and record baseline response (status, headers, body size)
2. Send a clearly malicious request (`<script>alert(1)</script>` in a parameter)
3. Compare responses: different status code, different body, new headers = WAF present
4. Check response headers for WAF signatures:
   - Cloudflare: `cf-ray`, `server: cloudflare`
   - AWS WAF: `x-amzn-requestid` with 403 patterns
   - Akamai: `akamai-grn`, `server: AkamaiGHost`
   - Imperva: `x-iinfo`, `incap_ses_` cookies
   - F5 BIG-IP: `server: BIG-IP`, `BIGipServer` cookies
5. Check for CAPTCHA challenges or JavaScript challenge pages

### Phase 2: Origin Discovery

1. Check DNS history for pre-WAF IP addresses (SecurityTrails, ViewDNS)
2. Query certificate transparency logs for alternative hostnames
3. Check for direct IP leaks in email headers (MX records, SPF includes)
4. Search Shodan/Censys for the target's TLS certificate fingerprint on other IPs
5. Try common origin subdomains: `origin.`, `direct.`, `backend.`, `staging.`, `dev.`
6. Check if non-HTTP services (mail, FTP, SSH) resolve to a different IP than the web

### Phase 3: Bypass Techniques

**Header-Based Evasion**
- Add `X-Originating-IP: 127.0.0.1` or `X-Forwarded-For: 127.0.0.1`
- Set `X-Real-IP`, `True-Client-IP`, `X-Custom-IP-Authorization` headers
- Vary `Host` header to see if WAF applies different rules per vhost

**Path Mutation**
- URL encoding: `/admin` vs `/%61%64%6d%69%6e`
- Double encoding: `%252f` for `/`
- Path traversal normalization: `/./admin`, `//admin`, `/admin/./`
- Case variation: `/Admin`, `/ADMIN` (IIS, case-insensitive servers)
- Null bytes: `/admin%00.html` (legacy parsers)

**Payload Obfuscation**
- Unicode/UTF-8 variants of attack characters
- Comment injection in SQL: `UN/**/ION SEL/**/ECT`
- Alternate function names: `CHAR()` instead of literal strings in SQLi
- HTML entity encoding for XSS: `&#x3c;script&#x3e;`
- Multipart/form-data boundary manipulation

**Protocol-Level**
- HTTP/2 vs HTTP/1.1 (WAFs may only inspect one)
- Chunked transfer encoding with irregular chunk sizes
- Request smuggling via CL/TE or TE/CL discrepancies
- Large parameter padding to push payload past inspection window

### Phase 4: TLS Fingerprint Evasion

1. Default curl/python TLS fingerprints are often flagged
2. Use tools that mimic browser TLS fingerprints (cipher order, extensions, ALPN)
3. Rotate between Chrome, Firefox, and Safari JA3 fingerprints
4. Test with actual browser automation if TLS fingerprint blocking is detected

## Corpus-Derived Hunting Patterns

### RFC Corner-Case Parser Differential

For every section of the HTTP grammar that says "MAY contain X" or "SHOULD reject Y," test the gap between two HTTP intermediaries on the same path:
1. Identify the front (CDN/WAF/LB) and back (app server) components
2. Send bare CR (without LF) after the HTTP method, non-ASCII bytes in header names, and mixed-case `Transfer-Encoding` values
3. If the front and back parse differently, you have a request smuggling or cache poisoning vector
4. Test both CL.TE and TE.CL variants systematically

### Multi-Auth-Mechanism CSRF Bypass

For any service that supports multiple authentication mechanisms (cookie, bearer, mTLS, basic, signed request, JWT):
1. Enumerate every auth path
2. For each state-changing endpoint, test which auth methods are accepted
3. If the endpoint accepts cookie auth, test CSRF protection: is the CSRF token bound to the session? Is it validated for all methods?
4. Custom content types (e.g., `application/x-protobuf`) often bypass CSRF protections that only check standard form types

### Filter-vs-Permission Inversion

When a UI lets users share/publish/expose a subset of an object (one tab of a sheet, one slide of a deck, one field of a form):
1. Identify the API that serves the subset
2. Test whether the API returns only the published subset or the full object
3. If the API returns the full object and the UI filters client-side, every hidden field/tab/slide is accessible via the API

### Identifier Chain Auditing

For any RPC that returns sensitive data gated on identifier X:
1. List ALL RPCs that produce X as output, given any other input
2. If you can reach X via a chain of RPCs that each have weaker auth than the final RPC, the auth is bypassed
3. Check whether bulk/batch/export endpoints return identifiers that individual endpoints would not

### ACL State-Transition Testing

For any platform where users configure ACLs/permissions via a UI:
1. Test the state-transition matrix, not just the static state
2. Snapshot enforcement at permission change time may cache the old state
3. Test: grant access, revoke access, then immediately attempt access -- does the revocation take effect instantly?
4. Look for "deprecated but pre-installed" features gated by configuration toggles that default to the less-secure legacy behavior

### Stacked-Credential Dismiss Attack

Any system with multiple authentication surfaces (device PIN, SIM PIN, work profile, parental controls, app-level lock):
1. Map every credential prompt in the system
2. Test what happens when one credential surface is dismissed while another is active
3. If dismissing a lower-priority prompt also dismisses a higher-priority one, the lock screen can be bypassed

### Blind XSS via Admin/Support Surfaces

Seed blind-XSS payloads into every user-supplied text field that flows into an admin/support/operations dashboard:
- Support ticket subjects and descriptions
- Contact/abuse report forms
- User-agent strings, referrer fields
- Profile names, organization names
- Any field visible to support/ops/admin staff

## Key Commands

```bash
# Basic WAF detection via response comparison
curl -s -o /dev/null -w "%{http_code}" "https://target.com/?id=1"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/?id=1' OR 1=1--"

# Check WAF headers
curl -sI "https://target.com/" | grep -iE "cf-ray|server|x-amzn|akamai|incap_ses|bigip"

# DNS history for origin IP (manual check)
# Use SecurityTrails, ViewDNS.info, or similar services

# Shodan search for certificate on different IPs
# shodan search ssl.cert.subject.cn:target.com

# Test header-based bypass
curl -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1" "https://target.com/admin"

# Test path mutation
curl -s "https://target.com/%61%64%6d%69%6e"
curl -s "https://target.com/./admin"
```

## What to Look For

- Different response codes or bodies when sending malicious vs benign requests
- WAF vendor signatures in headers, cookies, or error pages
- Origin IP addresses that bypass the WAF entirely (test by setting Host header)
- Inconsistent WAF behavior across HTTP methods (GET blocked but POST allowed)
- WAF rules that are path-specific (API endpoints may have weaker rules than web pages)
- Rate limiting thresholds (requests per second before blocking)
- Time-based differences suggesting payload inspection latency

## Common Pitfalls

- Do not assume a WAF blocks all attack vectors; test each vector independently
- Origin IPs found via DNS history may be outdated; verify the service is still running there
- Some WAFs learn and adapt; vary your testing patterns to avoid fingerprint-based blocking
- CDN/WAF bypass via direct origin access may violate scope; confirm with program rules
