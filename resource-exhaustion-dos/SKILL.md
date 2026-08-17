---
name: resource-exhaustion-dos
description: Resource-exhaustion DoS probing — body size, pagination abuse, nested parsers, ReDoS, decompression bombs, algorithmic complexity, amplification patterns
depends_on: []
---

# Resource Exhaustion DoS

DoS findings that are cheap to probe AND frequently in scope for bug bounty programs. Non-destructive patterns: you probe with one crafted request, observe response time / status / memory pressure, and file without actually taking the target down. NEVER launch a sustained attack; one probe per vector is enough.

## Discovery Signals

| Signal | Where to Find | Why Vulnerable |
|--------|--------------|----------------|
| Input validated by regex | Email, URL, phone, username fields | Nested quantifiers cause catastrophic backtracking |
| User-supplied search patterns | Search bars, log filters, content search | Regex compiled from user input = direct ReDoS |
| Markdown/rich text rendering | Comments, bios, wikis, issue bodies | Parsers use regex for link/emphasis detection |
| Syntax highlighting | Code paste bins, CMS code blocks | Tokenizer regex on untrusted input |
| CSV/log file parsing | Import endpoints, log viewers | Per-line regex applied to attacker-controlled rows |
| File upload with server processing | Avatars, documents, archives | Decompression bombs, pixel bombs, format parsing |
| GraphQL endpoint | `/graphql`, introspection enabled | Depth, alias, batch, fragment abuse |
| Auto-decompression in HTTP | `Content-Encoding: br/gzip` responses | No cap on decompressed size = memory bomb |
| Template filters on user content | Django `urlize`, Rails `auto_link`, CMS renderers | Quadratic loops in text-transformation utilities |
| WebSocket/streaming endpoints | Chat, live feeds, pub/sub channels | Connection exhaustion, subscription flood, slow frames |
| Embedded scripting sandbox | mruby, V8, Lua, MicroPython in app | Remove/override C-extension methods to crash sandbox ($10K) |
| Router/CPE web management UI | `/ubus`, `/luci-rpc`, `/jsonrpc/` paths | Debug JSON-RPC methods left in production firmware ($313K) |
| Client-side template engine | Angular, Vue, Mustache in stored fields | Parser-crashing payload = stored persistent DoS ($10K) |
| Account lockout mechanism | Login, MFA, password reset flows | Lockout by bruteforcing another user's credentials ($0-$500) |
| Password field with hashing | Signup, login, password change | No max-length = bcrypt/argon2 hangs on 1MB input ($100) |
| Code-generated decoders/encoders | Protobuf, Thrift, gRPC bindings | Generator template bugs produce DoS in generated parsers ($0) |

## Attack Vectors (each is a separate finding if it lands)

### 1. Body-Size DoS

POST a body of 1 MB to 10 MB to 100 MB to ANY mutating endpoint. Signals:
- `413 Payload Too Large` -> limit exists, safe
- `200 OK` or `201` -> no limit; file as DoS vector
- `500 Internal Server Error` -> parser crashed; file as DoS + potential resource exhaustion
- Response time scales linearly with body size -> parser is doing O(n) work without streaming; file

```bash
dd if=/dev/zero of=/tmp/big.bin bs=1M count=10
time curl -X POST $TARGET/api/users -H 'Content-Type: application/octet-stream' --data-binary @/tmp/big.bin
```

### 2. Pagination Abuse

Any endpoint with `limit`/`size`/`pageSize`/`count`/`perPage` parameter:
```bash
curl "$TARGET/api/items?limit=999999999"
curl "$TARGET/api/items?limit=-1"
curl "$TARGET/api/items?limit=0"
curl "$TARGET/api/items?page=-1"
curl "$TARGET/api/items?offset=999999999"
```
Signals:
- `200` + returns entire dataset -> memory exhaustion vector
- Request takes >5s -> unbounded iteration
- 500 / timeout -> hit an unhandled edge case

### 3. Deep-Nested JSON / XML

POST a JSON body nested 100+ levels deep to any JSON-accepting endpoint:
```bash
python3 -c "print('{'+'\"a\":{'*500+'\"x\":1'+'}'*500+'}')" | \
  curl -X POST $TARGET/api/something -H 'Content-Type: application/json' --data-binary @-
```
Same for XML with `<a><a>...<a>`. Parser stack overflow or 10s+ parse time = DoS finding.

Billion-laughs XML (XXE-adjacent):
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>
<lolz>&lol3;</lolz>
```

### 4. Long-Value DoS

Any string parameter -- send 1 MB of chars:
```bash
curl "$TARGET/api/search?q=$(python3 -c 'print(\"a\"*1000000)')"
```
Signals: 500, timeout >5s, regex-validation hang (ReDoS).

### 5. ReDoS (Regex Denial of Service)

#### Vulnerable Regex Patterns

| Pattern | Vulnerable Input | Where Found | Backtracking Steps |
|---------|-----------------|-------------|-------------------|
| `(a+)+$` | `'a'*25 + '!'` | Generic validators | 2^25 (~33M) |
| `(a\|a)*$` | `'a'*25 + '!'` | Alternation in parsers | 2^25 |
| `(.*a){x}` | `'a'*20 + 'b'` | Content matchers | Exponential in x |
| `([a-zA-Z]+)*` | `'a'*30 + '1'` | Name/username validators | 2^30 |
| `^([a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})*$` | `'aaa@a.'*10 + '!'` | Email validators | Exponential |
| `https?://[^\s/$.?#].[^\s]*` | `'h]'*40` | URL validators | Exponential |
| `<[^>]+>` with nesting | `'<'*65535` | HTML tag matchers (Django CVE-2024-27351) | O(n^2) |
| `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` with alternation | `'1.'*50 + 'x'` | IP address validators | Polynomial |
| `/url\s*\(\s*[^#\s][^)]+?\)/` | `'url(uu'*100000` | CSS/SVG attribute scrubbers (Rails CVE) | Exponential |
| `(\d+[-/]\d+[-/]\d+\s*)+` | `'1-1-1 '*30 + 'x'` | Date parsers, log parsers | Exponential |

#### ReDoS Payload Construction

Every ReDoS exploit follows the same formula: **pump x N + killer**.

1. **Identify the ambiguous group** -- find the quantified group where two sub-patterns can match the same character (e.g., `([a-zA-Z]+)*` -- the `+` and `*` both try to consume letters)
2. **Build the pump** -- a short string that the ambiguous group accepts, forcing the engine to try multiple partition points (e.g., `aaa` for `([a-zA-Z]+)*`)
3. **Add the killer** -- a character that fails the overall match, forcing the engine to backtrack through every partition (e.g., `1` which is not `$`)
4. **Scale N** -- repeat the pump: `pump * 20` for detection, `pump * 30` for a clear signal, `pump * 50` for an undeniable PoC

```bash
# Test any input field for ReDoS -- scale the pump and measure response time
for n in 20 25 30 35 40; do
  PAYLOAD=$(python3 -c "print('a'*$n+'!')")
  time curl -s -o /dev/null "$TARGET/api/validate?email=$PAYLOAD"
done
# Exponential: 20=instant, 25=0.5s, 30=15s, 35=8min, 40=hung
```

#### Language-Specific ReDoS Behavior

| Language/Engine | Backtracking? | Timeout? | Safe Alternative |
|----------------|--------------|----------|-----------------|
| JavaScript (V8) | Yes | No default | `re2` npm package, or `v` flag (ES2024 set notation) |
| Python `re` | Yes | No | `google-re2` package, or `regex` with timeout |
| Java `Pattern` | Yes | No | `com.google.re2j` |
| Go `regexp` | No (RE2) | N/A | Safe by default |
| Rust `regex` | No (RE2-like) | N/A | Safe by default |
| Ruby `Regexp` | Yes | `Regexp.timeout=` (Ruby 3.2+) | Set global timeout, or use `re2` gem |
| .NET `Regex` | Yes | `MatchTimeout` option | Always set `MatchTimeout` |
| PHP (PCRE) | Yes | `pcre.backtrack_limit` (1M default) | Limit helps but does not eliminate risk |

#### ReDoS Testing Methodology

1. **Find regex sources**: grep JS bundles for `/pattern/`, check error messages that echo validation patterns, read API docs for format descriptions, check client-side form validation
2. **Build minimal payload**: identify pump+killer for each pattern
3. **Baseline**: send a normal-length valid input, record response time
4. **Escalate**: send pump*20, pump*25, pump*30, pump*35, measure each
5. **Confirm exponential**: if time doubles (or more) per 5-char increase, ReDoS is confirmed
6. **File with the timing curve** -- programs accept ReDoS when you show the exponential graph

### 6. Algorithmic Complexity Attacks

- Hash collision -- many framework hashmaps use non-randomized hash, so thousand-entry form POST with specially-crafted keys degrades to O(n^2). Craft is framework-specific.
- Sort abuse -- POST 100k items, trigger server-side sort.
- Quadratic string operations -- `while changed:` loops in text transformers (Django `urlize` CVE-2024-38875: O(n^2) `trim_punctuation` via nested `str.count()` calls inside a loop). Test with `'('*50000` or `'{'*50000` in any field rendered through template filters.
- GraphQL query depth -- nested resolvers. 1000-level nested query:
  ```graphql
  query { user { friends { friends { friends { ... } } } } }
  ```
  Alias abuse:
  ```graphql
  query { a: user(id:1){name} b: user(id:1){name} c: ... }  # 1000 aliases
  ```

### 7. Decompression Bomb Patterns

| Archive/Format | Bomb Technique | Size Ratio | Detection Method |
|---------------|---------------|------------|-----------------|
| ZIP (nested) | 42.zip: 5 layers of 16 zips = 4.5 PB from 42 KB | 10^9:1 | Upload and monitor server memory/CPU |
| ZIP (quine) | Self-extracting recursive archive | Infinite loop | Upload, observe timeout or OOM |
| GZIP | 1 KB of compressed zeros -> 1 GB decompressed | 10^6:1 | `Content-Encoding: gzip` response to server-side fetch |
| Brotli | Repetitive data, better ratio than gzip (Node.js CVE) | 10^7:1 | `Content-Encoding: br` -- bypasses `maxContentLength` on compressed size |
| PNG (pixel bomb) | Small file (5 KB), huge declared dimensions (64250x64250) | 3M:1 pixels | Hex-edit image dimensions in header, upload |
| PDF | Recursive object references, huge page counts in metadata | Variable | Upload to PDF processing endpoint |
| tar | Enormous declared file sizes + path traversal | Variable | Upload to extraction endpoint |

```bash
# Create a gzip bomb: 10MB of zeros compresses to ~10KB
dd if=/dev/zero bs=1M count=10 | gzip -9 > /tmp/bomb.gz
# Serve to any endpoint that auto-decompresses or fetches URLs
curl -X POST $TARGET/api/import -H 'Content-Encoding: gzip' --data-binary @/tmp/bomb.gz
```

### 8. GraphQL DoS (Expanded)

Beyond depth and aliases:
- **Circular fragment references**: `fragment A on User { ...B } fragment B on User { ...A }` -- crashes parsers without cycle detection
- **Field duplication via aliases**: 100+ aliases of the same expensive resolver (`a1:expensiveField a2:expensiveField ...`) -- multiplies server-side work
- **Batch query abuse**: send an array of 1000 mutations in one request -- many servers process the full batch before responding
- **Introspection as DoS**: full `__schema` dump on large APIs with 500+ types produces multi-MB responses and heavy resolver load
- **Persisted query bypass**: if the server allows ad-hoc queries alongside persisted queries, send expensive ad-hoc queries that bypass complexity analysis applied only to persisted ones

### 9. WebSocket/Streaming DoS

- **Slow frames**: open a WebSocket, send partial message frames with long delays between fragments -- holds server memory for reassembly
- **Subscription flood**: subscribe to every available channel/topic -- each subscription holds server state and triggers fanout processing
- **Message amplification via pub/sub**: send one message to a channel with 10k subscribers -- 1:10000 amplification
- **Connection exhaustion**: open max connections (one probe to find the limit), never send close frame -- each holds a file descriptor

### 10. Amplification Patterns

- A 1-byte request triggers a multi-MB response -> amplification factor (DoS amplifier). Check status/admin/export endpoints.
- A single request triggers N outbound requests (fanout). If the target fetches from a user-supplied URL list with no bound, it's also SSRF + DoS.

### 11. Connection Exhaustion

- Slowloris: hold N connections open with trickled headers (don't do this in bug bounty -- it's active DoS)
- Slow POST: start POST with `Content-Length: 100000`, send 1 byte per 60 seconds
- HTTP/2 rapid-reset (CVE-2023-44487): repeatedly open + cancel streams (requires HTTP/2 server)
- HTTP/2 CONTINUATION flood: send HEADERS with END_HEADERS=false, then CONTINUATION frames, then abruptly close -- crashes servers with destructor invariant assertions (Node.js CVE-2024-22019)

**For bug bounty: probe with ONE request, measure response, STOP.** Don't keep hammering. Non-destructive signal proves vuln; running actual DoS is out of scope.

### 12. Embedded Interpreter Sandbox Crash ($10K)

For any embedded scripting sandbox (mruby, V8, Lua, MicroPython):
1. Identify built-in classes implemented in C/native code (Range, Array, String, Hash)
2. Find Ruby/JS-level methods the C code depends on (`initialize_copy`, `initialize`, `hash`, `==`)
3. Remove or override them: `Range.remove_method(:initialize_copy); (1..2).dup.to_s` -- NULL deref crash
4. Also test: deeply nested expressions, overlong identifiers, re-entrant `initialize` calls

### 13. Client-Side Template Engine Stored DoS ($10K)

For multi-user content rendered by Angular/Vue/Mustache:
1. Identify the template engine (source maps, `ng-` attributes, `{{ }}` syntax)
2. Inject parser-crashing payload into a stored field: `{{[]."-alert\`1\`-"}}` (AngularJS)
3. If editor also renders before editing, the field becomes unrecoverable via UI -- persistent DoS
4. Works even when XSS is blocked by CSP -- the crash alone is the finding

### 14. Account Lockout as DoS Vector

Test if an attacker can lock out another user's account:
- Submit N failed login attempts with the victim's username/email
- If the account locks without CAPTCHA or IP-binding -- file as DoS against any user
- Check: password reset, MFA, and security-question flows for the same pattern

### 15. Poison Pill in Messaging/Collaborative Apps ($1.5K)

1. Find a server-side data record (message, asset, account metadata) with edge-case values
2. Inject a malformed record that crashes the client parser on load (overlong field, invalid UTF-8, emoji flood)
3. If the client renders the record on startup or in a list view, the app becomes unusable for all viewers
4. The record persists server-side, so clearing local state does not fix it

## Protocol Per Vector

1. Send ONE crafted request
2. Measure:
   - Status code
   - Response time (baseline vs payload)
   - Memory-pressure signal (503, 504, slower subsequent requests from same IP)
3. If signal is strong, file immediately with the ONE request as PoC
4. Revert any created state if possible
5. Do NOT repeat

## Reporting

- **Severity**: Medium by default (availability impact with no direct data loss). Upgrade to High if it affects all users (not just requester), or if it's combined with auth bypass (unauth DoS = worse).
- **Title**: `Resource Exhaustion via <vector> on <endpoint>`
- **PoC**: single curl with before/after response times or status codes.
- **Cost-amplification framing**: calculate attacker cost vs server cost (e.g., "1 KB request -> 40s CPU = 25,000x amplification"). Programs take DoS seriously when you quantify the ratio.

### 16. ReDoS Hunting Methodology (Corpus-Extracted)

Corpus analysis of 18 ReDoS reports (up to $4K bounty) reveals a systematic approach that maximizes hit rate:

#### Step 1: Build a Regex Inventory

For the target application or framework, extract every regex literal:

```bash
# JS/TS codebases
grep -rhoE '/[^/]+/[gimsuvy]*' src/ node_modules/ | sort -u > regexes.txt
# Python
grep -rhoE "re\.(compile|match|search|sub|findall|fullmatch)\(['\"][^'\"]+['\"]" src/ | sort -u >> regexes.txt
# Ruby
grep -rhoE '/[^/]+/[imxo]*' app/ lib/ | sort -u >> regexes.txt
```

Feed each regex to `regexploit`, `recheck`, or `rxxr2` to identify vulnerable patterns automatically before crafting payloads.

#### Step 2: Prioritize by Input Surface

Not all regexes are reachable. Prioritize:

| Priority | Regex Location | Why |
|----------|---------------|-----|
| P0 | HTML sanitizers, CSS scrubbers, SVG attribute validators | Run on every user submission, fully attacker-controlled input |
| P0 | HTTP header parsers (Accept, Content-Type, Cookie, custom headers) | Fully attacker-controlled, processed before auth middleware |
| P1 | Email/URL/phone validators | User-facing form fields, common registration/invite flows |
| P1 | Markdown/rich-text renderers | Comments, bios, wikis -- attacker controls the full input |
| P2 | Log parsers, CSV importers | Partially attacker-controlled via uploaded files |
| P3 | Internal config validators | Rarely reachable from external input |

#### Step 3: Patch-Watch for Regression Windows

Subscribe to commit feeds of high-value frameworks (Django, Rails, Node.js, Spring). When a ReDoS CVE is patched:

1. Read the patch to understand the vulnerable regex pattern
2. Check if the fix introduced a NEW vulnerable regex (common: fix for `(a+)+` becomes `(a+b?)+` which is still vulnerable)
3. Check if targets running older versions are still exposed
4. Check sibling functions in the same file -- if one regex was vulnerable, adjacent regexes often share the same pattern style

#### Step 4: Runtime-Version-Dependent Testing

The same regex can be safe or vulnerable depending on the runtime:

| Factor | Impact |
|--------|--------|
| Ruby < 3.2 vs >= 3.2 | Ruby 3.2 added `Regexp.timeout` -- same regex may be capped |
| Node.js V8 version | V8 regex engine optimizations change across versions |
| Python `re` vs `regex` module | `regex` module has different backtracking behavior |
| PHP `pcre.backtrack_limit` | Default 1M may prevent exploitation; check `phpinfo()` |
| .NET `MatchTimeout` | If set, caps execution; if unset (default), unlimited |

Always test against the target's actual runtime, not your local environment. Check response headers (`X-Powered-By`, `Server`) and error messages for version hints.

#### Step 5: Rich Text Pipeline Audit

When a framework provides rich text handling (Action Text, TipTap, ProseMirror, Markdown renderers):

1. Map the full pipeline: input sanitization -> parsing -> rendering -> output sanitization
2. Each stage may use different regexes -- test each independently
3. Nested markup is the highest-yield payload: `[link](` * 10000 for Markdown, `<b><i><u>` * 10000 for HTML
4. Test both the preview endpoint (synchronous, blocks the request) and the save endpoint (may process async)

## False Positives

- Rate limiter kicks in on repeated probes (file as "no DoS" only after confirming single-shot doesn't trigger)
- Backend caches the crafted input, so second identical request returns fast
- Generic 400/500 unrelated to crafted size (check baseline small body)
- Load balancer returns 413 -- that's the limit, target itself is safe
- Engine uses RE2/safe regex -- confirm backtracking behavior before filing ReDoS
- Server-side `pcre.backtrack_limit` or `Regex.timeout` may cap damage -- measure actual impact, not theoretical

## Pro Tips

1. Body-size DoS is the cheapest -- one `dd` + `curl`, 10 seconds of work per endpoint.
2. Pagination abuse is often UNCAPPED even when body size is capped -- test every listing endpoint.
3. GraphQL depth + alias abuse are classic Medium findings that are rarely tested.
4. Time budget: 15 minutes to probe all major vectors across the surface. Don't spend an hour on one endpoint.
5. ReDoS on email validators is the highest-hit-rate regex finding -- most custom email regex patterns are vulnerable. Test every registration/invite/contact form.
6. Decompression bombs bypass `Content-Length` limits because the limit applies to the compressed size. Test any endpoint that accepts archives or auto-decompresses HTTP bodies.
7. Framework text-transform utilities (`urlize`, `auto_link`, Markdown renderers) are repeat CVE sources -- test with `'('*50000` and `'<'*50000` on any field rendered through server-side templates.
8. For ReDoS, use tools like `regexploit` or `recheck` on JS bundles to find vulnerable patterns before crafting payloads -- saves time vs blind fuzzing.
9. Password-length DoS: test every signup/login/password-change with 100, 1K, 10K, 100K, 1M char passwords. bcrypt/scrypt/argon2 without a max-length cap pin CPU for minutes per request ($100).
10. Router/CPE web UIs: look for `/ubus`, `/luci-rpc`, `/jsonrpc/` -- try anonymous session bootstrap `00...0` and enumerate `system.reboot`, `network.*`, `file.*` methods. ISP-grade impact ($313K).
11. HTML sanitizer regexes are the highest-ROI ReDoS target -- `rails-html-sanitizer`, `loofah`, Django sanitizers run on every user submission. Audit SVG attribute validation regexes first ($4K IBB pattern).
12. For embedded scripting sandboxes: `remove_method(:initialize_copy)` then `dup` on any C-extension class = NULL deref crash. Generalizes to mruby, V8, Lua ($10K).
13. "Poison pill" stored DoS: inject a malformed record (overlong field, invalid encoding) into messaging/collab apps that crashes the client renderer for ALL viewers ($1.5K).
14. Hash-flooding with guardian-bypass: if the target uses a cleanup thread, craft zero-hash collisions that evade the cleanup bookkeeping -- 10x amplification over naive hash-flooding ($30K IIS pattern).
15. Patch-watching: subscribe to commit feeds of high-value open-source projects, filter for security-related changes in parsers/validators, find the pre-patch vulnerable state in targets still on old versions.
