---
name: predictable-token-enumeration
description: Hunt for hardcoded, short, or pattern-guessable authentication tokens accepted by the API even when a JWT endpoint also exists
depends_on: []
---

# Predictable Token Enumeration

Many production APIs accept BOTH a modern auth primitive (JWT, OAuth) AND a legacy or debug path using short hardcoded strings, API-key-shaped tokens, or guessable patterns. Scanning only the `/api/token` issuance endpoint misses the legacy acceptance — the finding is in what the server WILL accept, not what it issues.

## Detection Principle

The server uses one codepath to ISSUE tokens (`POST /api/login`, `GET /api/token`) and a different codepath to VERIFY tokens (every authenticated request). The issuance path can be bulletproof JWT while the verification path accepts a small static map — without testing arbitrary tokens directly, you never see the gap.

## Test Matrix (send each as `Authorization: Bearer <token>` to an authenticated endpoint)

| Class | Examples |
|---|---|
| Short strings | `a`, `1`, `x`, `0`, `admin`, `token`, `test`, `dev`, `debug`, `guest`, `user`, `root`, `super`, `master`, `default` |
| Numeric | `0`, `1`, `2`, `3`, `12345`, `00000000`, `99999999` |
| Common English words | sequential counters (`one`, `two`, `three`, `first`, `second`, …), common trivial strings (`secret`, `password`, `changeme`, `letmein`, `qwerty`, `welcome`), colors/animals/months as seen in demo environments |
| Role names | `admin`, `administrator`, `root`, `superuser`, `owner`, `moderator`, `service`, `system`, `api`, `api-key`, `internal` |
| Encoded patterns | Base64 of `admin`, `user`, role names; hex of small numbers |
| Default vendor tokens | `testtoken`, `demo-token`, `dev-token`, `staging`, `production`, vendor-sample names from docs |
| Header-format guesses | `ApiKey 12345`, `Token abc`, `Basic YWRtaW46YWRtaW4=` (admin:admin), raw username as token |

## Enumeration Protocol

1. **Find an endpoint that returns user-context-dependent data** (e.g. `/api/me`, `/api/profile`, `/api/users/me`, `/api/v1/auth/me`, `/dashboard`, `/admin`).
2. **Baseline** — send request with NO Authorization header. Note response (usually 401, sometimes 200 with limited fields).
3. **Send each candidate token** from the matrix above as `Authorization: Bearer <candidate>`:
   ```
   # Example enumeration list — adapt to any pattern you suspect.
   for t in admin root test dev debug guest 1 2 3 a x one two three foo bar demo; do
     echo "=== Bearer $t ==="
     curl -s -w '%{http_code}\n' -H "Authorization: Bearer $t" $TARGET/api/me
   done
   ```
4. **Signal interpretation**:
   - `200` + user data → **confirmed**. File immediately.
   - `200` + different data per token → **confirmed with user enumeration**.
   - `401 Invalid token` / `403` → token not accepted; keep testing.
   - `200` + same generic data as unauthed → public endpoint, move on.
5. **Escalate the finding** — if any short token works, test the same token on admin-only endpoints (`/api/admin/*`). Admin acceptance = Critical.

## Alternative Auth Header Shapes

Also try (same token matrix):
- `X-API-Key: <candidate>`
- `X-Auth-Token: <candidate>`
- `X-Access-Token: <candidate>`
- `api_key=<candidate>` in query string
- Cookie: `session=<candidate>`, `auth=<candidate>`, `token=<candidate>`
- `Authorization: Basic <base64(user:pass)>` with guessable user:pass pairs (`admin:admin`, `admin:password`, `root:root`, `test:test`, `user:user`, empty password)

## Cross-Layer Check (Inconsistent Authentication)

If the target ALSO issues JWTs (`/api/token`, `/api/login`):
- Decode a legitimate JWT. Note the algorithm, issuer, audience.
- Verify that valid JWTs and short tokens BOTH work on the SAME endpoint. If yes, this is a **class-level finding**: two authentication primitives coexist on the same verification path. File separately from any individual token bypass (see `inconsistent_authentication` skill).

## Token Generation Weakness Matrix

| Generation Method | Weakness | Attack | Corpus Example |
|---|---|---|---|
| PHP `uniqid()` | Time-based (microsecond precision, ~20 bits/sec) | Know approximate creation time, brute ~1M candidates/sec of uncertainty | Revive Adserver session tokens (#1306942) |
| PHP `md5(time())` / `sha1(microtime())` | Hash of low-entropy timestamp | Precompute hash table for time window | Common in custom PHP apps |
| Go `math/rand` / Mersenne Twister | Non-crypto PRNG, full state recoverable from outputs | Observe ~624 outputs, recover seed, predict all future values | Fuchsia/gVisor TCP ISN ($750k, #326567424) |
| JavaScript `Math.random()` | V8 xorshift128+ — recoverable from 2-3 outputs | Browser-side: observe Math.random() calls via prototype hook | — |
| UUID v1 (time-based) | Encodes timestamp + MAC address | Decode timestamp for creation time, MAC for device fingerprint | Sequential by design |
| Sequential integer ID | Trivially enumerable (increment/decrement) | Walk IDs with stride detection (try +1, +2, +5, +10) | Udemy gift ID stride-of-2 (#119166) |
| `base64(username + timestamp)` | Decode reveals username and creation time | Decode, reconstruct for target user at target time | — |
| 4-digit OTP | 10,000 possibilities, often with magic debug codes | Try `0000`, `1111`, `1234`, `123456` before brute-force | inDrive OTP `0000` bypass ($2k, #2588329) |
| Signed cookie with low-entropy variable bytes | Diff across accounts reveals 4-5 mutable bytes | Registration as signing oracle + brute-force mutable bytes | VirusTotal session mass ATO ($50k, #146455552) |
| Cloud resource name from `project_id + region + service` | All components publicly knowable | Pre-create resource (bucket squatting) before victim enables service | Google ADC bucket squatting ($1.33M, #846430720) |
| PIN / secret reused as public identifier | Secret appears in another endpoint's response | IDOR on PII endpoint leaks the PIN used for password reset | DoD PII + PIN = mass ATO (#1061736) |

## Token Source Analysis

| Token Location | Common Weakness | How to Test | Impact |
|---|---|---|---|
| `Authorization: Bearer <token>` | Short/hardcoded/debug tokens accepted | Test matrix from Enumeration Protocol above | Full auth bypass |
| Password reset link (`/reset?token=X`) | Time-based or sequential token | Request 2 resets in quick succession, diff tokens | ATO of any user |
| Email verification link | Same token format as reset | Decode, check entropy, test cross-user reuse | Email verification bypass |
| OTP (SMS/email 4-6 digits) | Magic debug codes (`0000`, `1234`), no rate limit | Try debug codes first, then check rate limiting | Auth bypass |
| Share/invite URL (`/share?id=X`) | Sequential integer or short random | Increment/decrement, test stride patterns | Data leak, gift theft |
| Session cookie | `uniqid()`, `md5(time())`, weak PRNG | Decode 2+ cookies, diff byte-by-byte, measure entropy | Session hijack |
| API key in response body | Leaked alongside PII in IDOR-vulnerable endpoint | Enumerate user IDs, check response for API key field | Full API access |
| Cloud resource name (bucket, topic) | Deterministic from public values | Pre-create with attacker IAM before victim enables service | Cross-tenant compromise |

## Defense-Bypass Pairs

| Defense | Bypass | Corpus Evidence |
|---|---|---|
| Rate limiting on OTP submission | Magic debug code `0000` accepted — no brute-force needed | inDrive phone takeover ($2k, #2588329) |
| HMAC signature on session cookie | Registration flow signs attacker-chosen payload (signing oracle) | VirusTotal mass ATO ($50k, #146455552) |
| Secondary auth headers (X-Session-Hash) | `Referer: http://127.0.0.1` skips validation (debug bypass in prod) | VirusTotal conditional header bypass |
| CAPTCHA on registration | Third-party CAPTCHA solving services (2captcha, anti-captcha) | VirusTotal mass account creation |
| UUID format appears random | UUID v1 encodes timestamp + MAC — decode to predict | — |
| Per-user hostname obscures resource | Hostname derived from `project_id` — publicly knowable | Google ADC bucket squatting ($1.33M) |
| Token appears random (hex format) | `uniqid()` output looks hex-random but is just formatted timestamp | Revive Adserver sessions (#1306942) |
| Rate limit on brute-force endpoint | IDOR on separate PII endpoint leaks the secret directly | DoD PIN leak + reset bypass (#1061736) |

## Chain Patterns

| Chain | Steps | Corpus Bounty |
|---|---|---|
| IDOR on PII endpoint → leaked PIN → password reset bypass → mass ATO | Enumerate user IDs, extract email + PIN, use in reset flow | DoD (#1061736) |
| Decode-and-diff session cookie → registration signing oracle → mass ATO | Diff cookies to find mutable bytes, register to get valid signature, brute-force | $50k VirusTotal (#146455552) |
| Sequential gift ID → coupon code leak → gift redemption theft | Enumerate `giftId` with stride-of-2, steal coupon codes | Udemy (#119166) |
| Predictable cloud resource name → bucket squatting → Terraform poisoning → RCE | Pre-create bucket, victim writes IaC to attacker bucket, attacker plants malicious code | $1.33M Google ADC (#846430720) |
| Weak PRNG seed recovery → TCP ISN prediction → connection hijacking | Observe network identifiers, recover math/rand seed, predict all future values | $750k Fuchsia/gVisor (#326567424) |
| Magic OTP bypass → phone number rebinding → ride-sharing impersonation | Enter `0000` for any phone verification, claim arbitrary phone numbers | $2k inDrive (#2588329) |
| Password reset token not bound to user → reuse own token on victim account | Request own reset, capture token, apply to victim's user_id | UPchieve ATO (#1175081) |
| IDOR + Firebase token leak → direct Firebase database access | Enumerate order IDs, extract Firebase tokens from response | Instacart (#144000) |

## False Positives

- Public endpoints returning identical data for all tokens (check baseline unauthed response first)
- Reverse-proxy stripping auth — verify via non-Authorization vector (cookie, query, header)
- Tokens that work on error/status endpoints but not real data endpoints
- Server-generated bearer echoes (some demos echo the token in response body — that's not acceptance)

## Impact

- Critical: if short token authenticates to admin or PII-returning endpoints (account takeover, mass data disclosure)
- High: if it authenticates to user-scoped data but not admin
- Medium: if it bypasses rate limits or fingerprint checks but not authorization

## Pro Tips

1. Test the MOST AUTHENTICATED endpoint first (`/api/admin/*`). If a short token grants admin, grant-for-any-other-endpoint is implied.
2. If `/api/login` returns literal-string tokens (not JWT format) for known demo accounts, the token map is hardcoded — test every short string.
3. Decode any JWT found — check `alg: none`, weak `HS256` secrets (try `secret`, `password`, `key`, `jwt`, `changeme`, `admin` via `jwt_tool -C -d wordlist.txt`).
4. Don't stop at the first working token — enumerate ALL that work. You often find a role-privilege map where several short/predictable tokens each authenticate as a different account (one per role).
5. Decode and diff: for any signed cookie or token, decode across 2+ test accounts and diff byte-by-byte. Stable bytes = constants/secrets; variable bytes = user-identifying. If variable bytes are < 8, brute-force is feasible ($50k VirusTotal pattern).
6. Look for signing oracles: when crypto signing blocks brute-force, find ANY flow that signs content with the same key — password reset emails, activation links, magic login links, invite links. If format matches the cookie, the oracle is yours.
7. On every OTP flow, try `0000`, `000000`, `1234`, `123456`, `9999`, `999999` BEFORE attempting rate-limit bypass. This 5-minute test catches debug backdoors ($2k inDrive pattern).
8. When sequential IDs return 404 at +1, try +2, +3, +5, +10 before concluding the IDOR is fixed. Stride patterns from shared ID generators are common ($0 Udemy pattern).
9. For cloud services that auto-create resources, decompose the naming format. If all components are publicly knowable (project_id, region, service code), the resource is pre-emptable ($1.33M Google pattern).
10. Any field reused as both a public identifier AND a private secret (PIN in PII response + PIN in password reset) collapses the entire auth model. Cross-reference every PII endpoint field against every auth-recovery input.
11. Check if `Referer: http://127.0.0.1` or `X-Forwarded-For: 127.0.0.1` bypasses secondary auth checks — debug/internal conditionals surviving to production are a recurring pattern.
12. Grep source code for `uniqid()`, `mt_rand()`, `Math.random()`, `math/rand`, `rand()`, `srand()` in token generation. Any non-CSPRNG used for security tokens is a finding.
