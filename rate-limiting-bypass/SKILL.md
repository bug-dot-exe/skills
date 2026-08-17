---
name: rate-limiting-bypass
category: vulnerabilities
description: Rate limit bypass via HTTP/2 single-packet race, IP rotation, CDN pivots, legacy endpoints, and token exhaustion
depends_on: []
---

# Rate Limiting Bypass

Rate limits protect brute-force-sensitive endpoints (login, OTP, password reset, coupon, 2FA, signup-for-promo). When they can be bypassed, the protected primitive becomes trivially exploitable and triagers treat it as an enabler bug at medium-to-high severity when you demonstrate the secondary impact.

## Attack Surface

**Endpoints That Matter**
- `POST /login`, `POST /mfa/verify`, `POST /otp/verify`, `POST /password/reset/confirm`
- `POST /email/verify`, `POST /signup`, `POST /invite/claim`, `POST /promo/redeem`
- `GET /user/{id}` (IDOR probing), `POST /search` (enumeration), `POST /graphql` (batched)
- Financial: `POST /transfer`, `POST /withdraw`, `POST /refund`
- Admin: impersonation, password reset as admin

**Where Limits Are Enforced**
- CDN/WAF layer (Cloudflare, Akamai, AWS WAF) — bypassed via origin discovery
- Reverse proxy / API gateway (Kong, Tyk, nginx `limit_req`)
- Application-layer middleware (`express-rate-limit`, Django Ratelimit)
- Identity provider (Auth0, Okta, Cognito)
- Payment/SMS provider quotas (Twilio, Stripe)

**Response Signals**
- `429 Too Many Requests`, `Retry-After` header, captcha page, custom `403`, silent delay (sleep), soft-fail to zero results, email/SMS suddenly stops sending

## High-Value Targets

### HTTP/2 Single-Packet Race (Kettle)

James Kettle's single-packet attack (DEF CON 31). TCP/TLS overhead synchronizes N requests into a single packet so they arrive within ~1ms at the server, landing inside the same rate-limit window and sometimes the same mutex.

- Tool: Burp's Turbo Intruder (`engine=Engine.BURP2`, `concurrentConnections=1`) with `send-group` gate
- Tool: `requests.toolbelt` with `curl --http2-prior-knowledge`
- Works even when the limit is 1 attempt per second if the check-then-decrement is not atomic
- Pair with TLS 1.3 0-RTT and warm TCP to maximize arrival synchrony

```python
# Turbo Intruder single-packet login bypass
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1,
                           engine=Engine.BURP2)
    for pw in ["password1","password2",...,"password30"]:
        engine.queue(target.req.replace("PASS", pw), gate='race1')
    engine.openGate('race1')
```

### IP-Based Bypass Headers

Spoofable headers (test each independently and combined):
```
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 1.2.3.4, 127.0.0.1      # last-wins parsers
X-Originating-IP: 127.0.0.1
X-Remote-IP, X-Remote-Addr
X-Client-IP, X-Real-IP, True-Client-IP
X-Host, X-Forwarded-Host
Forwarded: for=127.0.0.1
CF-Connecting-IP: 1.2.3.4                 # when the target is not behind CF
Fastly-Client-IP, Akamai-True-Client-IP
Via: 1.0 127.0.0.1
X-ProxyUser-Ip: 127.0.0.1
```

- Rotate with `ffuf -w ips.txt:FUZZ -H "X-Forwarded-For: FUZZ"`
- Generate IPs: `python -c "import ipaddress,random; [print(str(ipaddress.IPv4Address(random.randint(0,2**32-1)))) for _ in range(500)]"`

### CDN Origin Pivot

The CDN enforces the limit; the origin does not.
- Find origin via `crt.sh`, Censys, Shodan (`ssl.cert.subject.cn:"example.com"`), historical DNS (SecurityTrails), `favicon hash:xyz`
- Once origin IP found: `curl -H "Host: app.example.com" https://<origin>/login` — limit gone
- Backend-only endpoints sometimes hit via direct origin (`/_internal`, `/actuator`)

### Legacy / Mobile / Alternative Endpoints

Primary `/api/v2/auth/login` is rate-limited; these often are not:
- `/api/v1/login`, `/api/v0/login`, `/api/internal/login`
- `/m/login`, `/mobile/api/login`, `/app/login`
- `/rest/V1/login`, `/graphql` (with `mutation login`)
- `/.well-known/openid-configuration` pivots to a different auth server
- Subdomain: `api.example.com` vs `app.example.com` vs `mobile-api.example.com`
- Old Swagger docs `/swagger.json`, `/api-docs` revealing deprecated unlimited endpoints

### Account-Level vs IP-Level

- Limit keyed on victim username → switch to hundreds of throwaway usernames to guess one shared password (reverse brute force / password spraying)
- Limit keyed on attacker IP → rotate IPs
- Limit keyed on session cookie → drop the cookie or rotate it
- Limit keyed on OAuth `client_id` → register many apps, rotate client IDs
- Limit keyed on API key → rotate keys (check if free-tier generation is unlimited)

### Token / Key Exhaustion

- Many apps issue a CSRF token per page load; rate limit counts tokens, not attempts
- `_csrf` or `nonce` rotates each request — if limit is token-based, each fresh token resets
- Some apps track (IP, username, token) triples — vary the token to split the counter

### CAPTCHA Bypass Chains

- Captcha triggered only above the rate limit → below-threshold rate × bypassed rate limit = no captcha
- Captcha response reused (tokens not single-use; `g-recaptcha-response` replay works until expiry ~2 min)
- Client-side captcha check only (server never validates)
- Test site key is left in production (`6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI` — always passes)
- "I'm not a robot" sitekey resolves via `2captcha`/`anti-captcha` at $1/1000
- hCaptcha/reCaptcha v3 score threshold too low (`0.1` passes bots)

## Key Vulnerabilities

### Parameter Pollution

Split the rate-limit key:
```
username=admin%00           # null byte in key
username=Admin              # case variation
username=admin%20           # trailing space
username=admin&username=x   # HPP
username[]=admin            # array wrap
{"username":"admin"}        # JSON vs form
```

### Path Variation

```
/login  /Login  /login/  /login/./  /login%20  /login?x=1
/api/v1/login  /api/v2/login  /api//login
```

### Method Switching

```
POST /login   (limited)
PUT  /login   (sometimes not limited)
PATCH /login  (often forgotten)
```

### Logic Resets

- One successful login between failures resets the counter
- Change password → lockout resets
- Call `/logout` between attempts → session counter resets
- Wait shorter than documented cooldown (30s instead of 60s) — often resets at half
- Register a fresh account and abandon it — counter was tied to browser fingerprint, not persistent

## Bypass Techniques

**Encoding Variance**
- URL-encode parts of the path (`%6cogin`)
- Use unicode lookalikes (`/loɡin`)
- Double-encode

**Transport Variance**
- HTTP/1.1 vs HTTP/2 vs HTTP/3 — limits often tied to h2 stream count only
- Connection pipelining vs fresh TLS session

**Geography**
- Request from different regions (CDN edges) — each edge has its own counter until aggregated

**Identity Variance**
- Rotate `User-Agent`, accept-language, cookies jar per request
- Authenticated vs anonymous on same endpoint — often different limits

## Testing Methodology

1. **Baseline** - Establish N (requests before block) and the block signal (status, header, body, timing). Repeat from a cold IP to confirm determinism
2. **Key discovery** - What is the limit keyed on? Bisect: same IP + different username, different IP + same username, same session + fresh token, etc.
3. **Spoof headers** - Sweep the full IP header list; look for counter reset
4. **Origin discovery** - `crt.sh`, Censys, Shodan, historical DNS, favicon hash; try direct `Host:` header
5. **Endpoint variance** - v1/v2/v0, /mobile, /internal, /graphql, method switch, trailing slash/case/encoding
6. **Single-packet race** - Turbo Intruder, 20-50 requests in one gate, against login or OTP
7. **CAPTCHA chain** - Find the threshold that triggers captcha, bypass the limit to stay below, or replay the captcha response
8. **Token exhaustion** - If limit is per-token, fetch N tokens in parallel, use one per attempt
9. **Secondary impact** - Convert bypass to concrete damage (credential stuffed account, OTP guessed, coupon drained)

## Chaining

- **Header spoof → brute force → weak password → ATO**: `X-Forwarded-For` rotation lets `rockyou` run against `victim@example.com`
- **Origin pivot → unlimited OTP attempts → 6-digit code guessed (~10^6 / 6 tries expected)**
- **Single-packet race → coupon double-redeem**: one `CODE123` applied 15× in a single HTTP/2 frame, $15 off becomes $225 off
- **Legacy endpoint → password spray → compromised service account → pivot**

## Validation

1. Show baseline threshold (before bypass): N requests → block
2. Show bypassed threshold: N+M requests, no block, M ≥ 10× N
3. Demonstrate concrete downstream impact (credential brute forced, OTP cracked, coupon drained) — a bare "I sent more requests" is often N/A
4. Provide reproducible tool command (curl loop, Turbo Intruder script) and response samples
5. State the enforcement layer you bypassed (CDN, gateway, app) so the fix landing zone is clear

## False Positives

- "Rate limit" that is actually load-shedding under traffic spike (not security control) — check if it applies to non-sensitive endpoints equally
- Counter resets after short cooldown that is documented as expected
- Endpoint is public and unauthenticated-idempotent (e.g., search) with no secondary impact — triager will close as N/A
- Demo/staging environment with rate limits disabled in config
- `X-Forwarded-For` bypass on an endpoint where the app trusts XFF by design (behind known proxy); show real limit is not the spoof, but a per-username counter also present

## Impact

- Account takeover via credential stuffing at unlimited rate
- OTP/2FA brute force when codes are 4-6 digits
- Password reset token brute force when tokens are short-lived but enumerable
- Coupon/promo/referral abuse — direct financial loss
- User enumeration at scale (registration check, password reset "user exists" oracle)
- Business logic abuse: vote stuffing, review bombing, inventory hoarding

## Discovery Signals

| Signal | Where to Find | Why Vulnerable |
|---|---|---|
| Login form with username + password | Feature scan | Brute force / credential stuffing if rate limit is per-IP only |
| OTP/2FA input (4-6 digit numeric) | Auth flow | 10^4-10^6 keyspace brute-forceable without rate limit in hours |
| Password reset with email/SMS trigger | Auth flow | Email/SMS bombing + token brute force if tokens are short |
| CAPTCHA on a form | Feature scan | Client-side-only validation, test key in prod, response replay |
| `429` response or `Retry-After` header | Proxy log | Rate limit exists but may be single-dimension keyed |
| Mobile app with separate API endpoint | App proxy | Mobile auth often lacks web-equivalent rate limits |
| GraphQL endpoint accepting batched mutations | API scan | N operations in 1 HTTP request bypasses request-count limits |
| `/api/v1/` alongside `/api/v2/` | Path enum | Legacy versions often lack rate limits added to current version |
| SMS/phone verification step | Auth flow | Phone numbers are low entropy; missing limit = brute-forceable |
| Promotional/referral code redemption | Feature scan | Short-keyspace codes (5-8 chars) enumerable without rate limit |
| Account lockout after N failures | Auth flow | Lockout keyed on target username = DoS vector against any user |
| Step-up auth (new-IP, new-device challenge) | Auth flow | Secondary verification often rate-limit-forgotten by developers |

## Rate Limit Key-Space Bypass Matrix

| Key Dimension | Bypass Technique | Test Method | Real Example |
|---|---|---|---|
| Source IP (per /32) | Rotate via proxy pool / Tor / cloud IPs | Hit limit, change IP, retry | mopub login — $420 (H1 #819930) |
| Source IPv6 (per /128) | Rotate low 64 bits of a /64 prefix (2^64 addresses) | Bind to random IPv6 in local /64 per request | Nextcloud rate limit bypass (H1 #1154003) |
| Session cookie | Drop or rotate cookie between attempts | Clear cookies after limit, resend | Shopify fix bypass — $3,500 (H1 #1363672) |
| Client-supplied device ID | Reuse same device ID across many targets (aggregation inversion) | Issue codes for 1M accounts on 1 device ID, search code space | Instagram ATO — $10,000 (H1 #1037678295) |
| Target phone number | Exhaust victim's quota from attacker's session | Send resend-OTP from your account with victim's number | Shopify lockout DoS — $900 (H1 #1406495) |
| API key / OAuth client ID | Register multiple free-tier apps, rotate client IDs | Check if free-tier app creation is unlimited | Common in SaaS platforms with free developer tiers |
| Request path (exact match) | Path normalization: `/login` vs `/Login` vs `/login/` vs `/login?x=1` | Vary casing, trailing slash, query params, double-encode | Medium rate limit bypass — $1,800 (H1 #144817889) |
| HTTP method | `POST` rate-limited but `PUT`/`PATCH` reach same handler | Switch method on same endpoint | Common in Django/Express apps with method-agnostic views |
| Per-request count (not per-operation) | Batch N operations in 1 request (GraphQL aliases, XML-RPC multicall, JSON array) | `[{mutation1},{mutation2},...,{mutationN}]` in one POST | Uber WP xmlrpc.php — (H1 #125624) |
| CSRF/nonce token | Each fresh token resets the counter | Fetch new page load per attempt, use fresh nonce | Common in WordPress and legacy PHP apps |
| Parameter normalization | `admin%00` / `Admin` / `admin ` / `admin&username=x` treated as different keys | Null byte, case, trailing space, HPP, array wrap | Meta email confirmation brute force — $2,500 (H1 #270407957) |
| Rate limit placement (after validation) | Error response leaks info before rate limit fires | Check if "invalid user" vs "wrong password" appears before 429 | Registration enumeration (H1 #262830) |

## Endpoint-Specific Bypass Patterns

| Endpoint Type | Common Limit Key | Typical Bypass | Impact When Bypassed |
|---|---|---|---|
| Login (`/login`, `/oauth/token`) | IP or session | Mobile API / OAuth token endpoint lacks web limits | Credential stuffing ATO |
| OTP verify (`/otp/verify`, `/2fa/verify`) | Per-account with lenient threshold | 20 attempts/min x 30 days = 864K tries vs 1M space | 2FA brute force (GitLab H1 #149598) |
| Password reset send | Per-IP | Header spoof + rotate → email bomb | SMS/email flooding, token enumeration |
| Email confirmation code | None (sometimes) | Direct brute force of 6-digit code | Email hijack across products (Meta H1 #270407957) |
| Promo/referral code redeem | Per-IP | Rotate IPs, enumerate 36^5 code space | Financial loss via harvested codes (Uber H1 #125200) |
| Account registration | CAPTCHA only | Remove CAPTCHA param, replay token, use test sitekey | Mass fake accounts, referral abuse |
| SMS resend / OTP send | Per-phone-number (wrong key) | Exhaust victim's SMS quota from attacker session | 24hr lockout DoS (Shopify H1 #1406495) |
| Step-up challenge (new-IP verify) | None | Brute force phone number / security question | ATO via secondary auth bypass (Badoo H1 #174668) |
| API key regeneration | None | Rapid-fire regeneration, harvest all generated keys | Key prediction if PRNG is weak |
| GraphQL mutations (batched) | Per-request | N login mutations per request via aliases | N-fold amplification of brute force |

## CAPTCHA Bypass Techniques

| CAPTCHA Type | Bypass Technique | How to Test | Precondition |
|---|---|---|---|
| reCAPTCHA v2 | Remove `g-recaptcha-response` param entirely | Intercept, delete param, forward | Server never calls `siteverify` API (Coinbase H1 #246801) |
| reCAPTCHA v2 | Replay a previously solved token before expiry (~2 min) | Solve once, reuse token in Intruder | Server does not check single-use |
| reCAPTCHA v2 | Google test sitekey left in production (`6LeIxAcTAAAAAJcZ...`) | View page source for sitekey, compare to known test key | Deployed staging config to prod |
| reCAPTCHA v3 | Score threshold set too low (0.1-0.3) | Submit from headless browser, check if action proceeds | Default or misconfigured threshold |
| hCaptcha | Solve via `2captcha`/`anti-captcha` API ($1-3 per 1000) | Integrate solving API into brute-force loop | Always works, just adds cost |
| Any CAPTCHA | HTTP method switch (`POST` limited, try `PUT`/`GET`) | Change method in Burp | Different code path skips CAPTCHA check (H1 #206653) |
| Any CAPTCHA | Client-side validation only (JS check, no server verify) | Disable JS or replay without CAPTCHA field | Common in custom CAPTCHA implementations |
| Any CAPTCHA | Triggered only above rate limit threshold | Stay below threshold per-IP via rotation | CAPTCHA is defense-after-limit, not defense-instead-of |

## Defense-Bypass Pairs

| Defense Mechanism | Specific Bypass | How Detected in the Wild |
|---|---|---|
| Per-IP rate limit | IPv6 /64 rotation (2^64 free addresses) | Nextcloud — rate limit keyed on /128, attacker has /64 |
| Per-account lockout | Attacker triggers lockout on victim's account (DoS) | Reddit — 14 failed attempts lock victim for 5 min (H1 #1582778) |
| Login lockout on web | Mobile `/oauth/token` endpoint has no lockout | Instacart — iOS endpoint bypasses web lockout (H1 #160109) |
| Rate limit after patch | Rotate the patched key dimension (cookie/IP/UA) | Shopify — fix-bypass by rotating session cookies (H1 #1363672) |
| Per-request rate limit | Batch N operations in 1 request (multicall/GraphQL) | WP xmlrpc.php multicall with 1000 login attempts (H1 #125624) |
| CAPTCHA gate | Remove param from request (server never validates) | Coinbase — server accepted signup without CAPTCHA (H1 #246801) |
| Account-based rate limit | Register many throwaway accounts, spray 1 password each | Reverse brute force / password spraying pattern |
| Rate limit on main login | State-confusion triggers alternate login page without limits | Acronis — email-change edge case reaches unprotected login (H1 #1435392) |
| TOTP rate limit (lenient) | 20 attempts/min x 30 days = probabilistic brute force | GitLab — 9.5% success in 3.5 days on 6-digit TOTP (H1 #149598) |
| Per-device rate limit | Scale targets (1M accounts) to invert probability | Instagram — aggregation inversion across 1M accounts (H1 #1037678295) |

## Chain Patterns

| Chain | Steps | Impact | Real Payout |
|---|---|---|---|
| Header spoof -> unlimited brute force -> weak password -> ATO | Spoof XFF to reset IP counter, run credential list | Account takeover | mopub $420 |
| Mobile endpoint -> no rate limit -> credential stuff -> ATO | Proxy iOS app, find `/oauth/token`, unlimited attempts | Mass ATO with breach credentials | Instacart (H1 #160109) |
| Aggregation inversion -> OTP across 1M accounts -> mass ATO | Issue reset codes to 1M accounts on 1 device ID, search | Million-account compromise in 10 minutes | Instagram $10,000 |
| No rate limit -> promo code enumeration -> financial loss | Iterate 36^5 code space, harvest valid codes | Direct revenue loss at scale | Uber $3,000 |
| Lockout DoS on victim -> social engineering -> credential reset | Lock target account, call support claiming "locked out" | Social-engineering-assisted ATO | Shopify $900 |
| Batch attack -> parameter coercion -> token brute force | Send 100K tokens in one request via `token[]=a&token[]=b` | 5-6 order magnitude speedup | rubygems.org $480 (H1 #1559262) |
| State confusion -> alternate login -> brute force | Trigger edge-case redirect to unprotected login page | ATO via hidden page | Acronis $250 |
| IPv6 rotation -> unlimited login -> weak password ATO | Rotate low 64 bits of /64, each request is "new IP" | Unlimited brute force on residential connection | Nextcloud (H1 #1154003) |

## Pro Tips

1. Always demonstrate secondary impact — "bypassed rate limit" alone is informational; "bypassed rate limit and guessed the OTP" is high
2. The CDN often only protects edge-facing paths; internal or legacy URLs bypass it — enumerate the app's entire footprint
3. HTTP/2 single-packet attack wins on state-machine bugs even when rate limit is "1/sec" because the check-then-act isn't atomic
4. Rotate both IP and User-Agent together; some WAFs fingerprint the pair
5. Check for `Retry-After: 0` — parser sometimes treats it as "retry now"
6. Mobile app endpoints often have weaker limits because they assume a trusted client; intercept the app with `frida` or `mitmproxy`
7. If captcha is the gate, look for the site key in page source — sometimes it's the Google test key that always passes
8. GraphQL batching (`[{"query":"..."}, {"query":"..."}]`) sends N mutations in one HTTP request — limits often count requests, not operations
9. After any rate-limit fix is deployed, immediately retest by rotating each key dimension — fix-bypass reports pay well ($3,500 at Shopify for rotating the patched session key)
10. Compute the math: a "rate-limited" endpoint allowing 20 attempts/min against a 6-digit OTP gives probabilistic success within days — measure the actual threshold, do not accept "rate limit exists" as sufficient
11. For Rails/Django/Express apps, test array parameter coercion (`?token[]=a&token[]=b`) — ORM `find_by(field: array)` becomes an IN-clause, turning one request into thousands of token checks
12. Rate limit keyed on the target (victim's phone/email) instead of the requester is a DoS vector — exhaust the victim's quota from your own session
13. Error responses that leak validation state before the rate limit fires (e.g., "user not found" on attempt 1, then 429 on attempt 11) are enumeration oracles regardless of the limit
14. Diff IPv4 and IPv6 handling in rate limiters — most code was written for IPv4 first and hardcodes IPv6 to /128 (per-address) instead of /64 (per-customer)
15. When one endpoint is rate-limited, sweep every parallel endpoint for the same action (web, mobile, REST, GraphQL, v1, v2, internal, WebDAV, SAML) — inconsistency is the norm

## Summary

Rate limits are a defense-in-depth control. Bypass them by switching identity (IP, header, session, token, endpoint), compressing time (single-packet race), or bypassing the enforcement layer entirely (origin pivot, legacy API). Always pair the bypass with the secondary primitive you can now brute-force — that's what pays.
