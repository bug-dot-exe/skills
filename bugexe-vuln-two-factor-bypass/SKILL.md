---
name: two_factor_bypass
category: vulnerabilities
description: Comprehensive 2FA/MFA bypass techniques — response manipulation, brute force on OTP, race conditions on verify, backup code abuse, SIM swap/port out, OTP enumeration, session fixation before 2FA, "remember device" flaws, recovery flow weaknesses, MFA deferral / step-up bypasses
depends_on: []
---

# 2FA / MFA Bypass

Multi-factor authentication adds a second gate after password entry. Every
step is implementation-dependent, and MFA bypasses are consistently paid at
high severity because they defeat the explicit layer users trust most.

## When to Use

- Target offers any form of 2FA (SMS, TOTP, push, passkey, email code, backup codes)
- Authentication flow has multiple steps (password -> code -> logged in)
- Recovery flow exists (forgot 2FA device / lost phone)
- "Remember this device" toggle
- Step-up MFA on sensitive actions
- MFA enrollment (where user first sets up 2FA)

## Discovery Signals

| # | Signal | Where to Find | Why Vulnerable |
|---|--------|---------------|----------------|
| 1 | `mfa_mode`, `auth_factor`, `method` param in login request | Intercept login POST body | Client-controlled MFA mode lets attacker downgrade -- $2.5K Grammarly mode confusion (#665722) |
| 2 | 4-digit OTP in SMS/email | Trigger OTP, observe code format | 9K-keyspace brute-forceable if rate limit is per-IP only -- $500 Grab 4-digit brute (#202425) |
| 3 | `device_trusted=true` or `device_id` cookie | Cookie jar after login | Forgeable device-trust cookie skips MFA entirely |
| 4 | Separate 2FA prompt on password-reset flow | Trigger password reset with 2FA-enabled account | Reset-flow 2FA often lacks rate limiting the login flow has -- $500 Slack reset brute (#121696) |
| 5 | `oc_sessionPassphrase` or split session cookies | Cookie inspection after each auth step | Multi-cookie session decomposition bypasses 2FA gate -- $750 Nextcloud cookie swap (#1050244) |
| 6 | SSO / "Sign in with Google" toggle in settings | Account settings > Login Services | Enabling SSO can silently disable 2FA -- $1.5K Shopify SSO clobbers 2FA (#178293) |
| 7 | UI guard "verify email to connect login service" | DOM inspection of disabled buttons | UI-only gate, server endpoint unguarded -- $1.6K Shopify pre-verification OAuth bind (#1018489) |
| 8 | OTP `send` and `verify` endpoints with decoupled IDs | Intercept claim/onboarding flow | Verification channel decoupled from target resource -- $3.25K Zomato restaurant claim (#1330529) |
| 9 | `security-challenge`, `step-up`, `verify` transitional endpoint | Network tab during suspicious-login flow | Transitional endpoints leak tokens/data without full auth -- $15.3K PayPal plaintext password leak (#739737) |
| 10 | No `crumb`/CSRF token on 2FA enrollment POST | Replay enrollment POST without CSRF token | CSRF on 2FA enrollment adds attacker's phone to victim -- $500 Slack CSRF on 2FA SMS (#155774) |
| 11 | Per-IP rate limit only (no per-account lockout) | Send 120+ wrong codes, change IP, retry | IP rotation defeats per-IP counters -- $420 mopub password brute via proxy rotation (#819930) |
| 12 | Alternate login page via state-confusion edge case | Trigger expired/conflicting confirmation link | Fallback templates miss rate limiting -- $250 Acronis alt login page brute (#1435392) |

## 2FA Bypass Technique Matrix

| 2FA Type | Bypass | Technique | Prerequisite | Impact |
|----------|--------|-----------|--------------|--------|
| Any OTP | Response manipulation | Flip `"success":false` -> `true`, status 401 -> 200 | Burp match-and-replace | Full ATO -- common across small-medium targets |
| Any OTP | Missing server-side check | Navigate directly to post-auth URL with pre-2FA cookie | Browser or curl | Full ATO -- client-side-only 2FA |
| Any OTP | Session token reuse | Use pre-2FA cookie (C1) on sensitive endpoints | Cookie capture | Full ATO -- pre-2FA cookie accepted post-2FA |
| SMS (4-digit) | Brute force | 1000-9999 range, ~9K attempts, no lockout | Per-IP rate limit only | Full ATO -- $500 Grab brute (#202425) |
| SMS (6-digit) | Race + IP rotation | Concurrent requests defeat non-atomic counter | Proxy pool | Full ATO -- $30K Instagram race (#519713875) |
| Email OTP | Mode confusion | Change `mfa_mode` from `phone` to `email` in request | Server trusts client mode | Silent ATO -- $2.5K Grammarly (#665722) |
| Any OTP | Null/skip value | Send `null`, `""`, `0`, `"none"`, omit field entirely | Server fails open on missing | Full ATO -- common implementation flaw |
| TOTP | Backup code access | Access backup code display without 2FA re-verify | Session access | Persistent access via stolen codes |
| Device trust | Cookie theft/forge | Steal `device_id` cookie or set `device_trusted=true` | XSS or API leak | Silent ATO -- $24K Facebook machine_id leak (#3320995794) |
| Any 2FA | SSO toggle clobber | Enable SSO, which silently disables 2FA for password login | Temporary session access | Permanent 2FA disable -- $1.5K Shopify (#178293) |
| Any 2FA | Enrollment CSRF | CSRF on 2FA enrollment adds attacker's phone | Missing CSRF token | Persistent backdoor -- $500 Slack (#155774) |
| Any 2FA | Pre-verification OAuth bind | Bind OAuth to unverified account via direct POST | UI guard only, no server check | Ghost account ATO -- $1.6K Shopify (#1018489) |

## Provider-Specific Bypass

| Provider/Framework | Quirk | Bypass | Condition |
|--------------------|-------|--------|-----------|
| Nextcloud | Multi-cookie session (`oc_sessionPassphrase` separate from session ID) | Swap `oc_sessionPassphrase` between two sessions of same user | 2FA enforced but not configured | $750 Nextcloud session decomposition (#1050244) |
| Shopify | Enabling Google Apps SSO clobbers 2FA boolean | Enable SSO -> 2FA silently disabled for password path | Access to account settings | $1.5K Shopify SSO-2FA clobber (#178293) |
| Shopify | OAuth connect endpoint unguarded behind UI gate | POST to `/external-login/1` with `data-method="post"` | Unverified account state | $1.6K Shopify pre-verify OAuth bind (#1018489) |
| Grammarly | Login endpoint accepts client-chosen `mfa_mode` | Set mode to `email` instead of enrolled `phone` | Device trust cookie still valid | $2.5K Grammarly mode confusion (#665722) |
| Slack | 2FA on password reset has no rate limit | Brute-force 6-digit TOTP on reset flow | Email access for reset link | $500 Slack reset-flow brute (#121696) |
| Slack | 2FA SMS enrollment lacks CSRF protection | Cross-origin POST adds attacker phone number | Victim visits attacker page | $500 Slack CSRF 2FA enrollment (#155774) |
| AWS IAM Authenticator | Cluster ID header not bound in token signature | Replay token from cluster A to cluster B | Valid IAM creds for any cluster | $2.5K K8s cross-cluster replay (#1580493) |
| Zomato | OTP verify decouples phone from restaurant ID | Send OTP to attacker phone, verify against victim restaurant | Any authenticated merchant | $3.25K Zomato restaurant claim (#1330529) |

## Backup / Recovery Code Attacks

| Attack | Technique | Where | Impact |
|--------|-----------|-------|--------|
| Backup code display without re-auth | Navigate to backup code page with active session | Settings > Security > Backup Codes | Steal all codes with session access |
| Backup code generation resets without 2FA | Call regenerate endpoint without providing current 2FA code | API for backup code regeneration | Invalidate old codes, get new ones for attacker |
| Used backup code stays valid | Submit same backup code twice | 2FA verify endpoint | Reusable codes = weaker entropy |
| Backup code brute force | Low entropy (8-char alphanumeric = feasible if no rate limit) | 2FA verify endpoint with backup code | $500 Grab -- 4-digit OTP same class (#202425) |
| Backup code use disables TOTP | Server interprets backup code use as "reset 2FA enrollment" | Recovery flow | Permanent 2FA downgrade |
| Recovery email change without 2FA | Change recovery email from settings without step-up auth | Profile settings > Recovery Email | Redirect recovery flow to attacker email |

## Defense-Bypass Pairs

| Defense | Bypass Technique | Real Example |
|---------|------------------|--------------|
| Per-IP rate limit on OTP verify | Concurrent requests + IP rotation | $30K Instagram -- race condition on non-atomic counter (#519713875) |
| Per-IP rate limit on login | Rotate through proxy pool | $420 mopub -- proxy rotation defeats per-IP throttle (#819930) |
| Rate limit on login 2FA prompt | Brute-force the password-reset 2FA prompt instead | $500 Slack -- reset endpoint missed rate limit annotation (#121696) |
| CSRF token on login | 2FA enrollment POST missing CSRF validation | $500 Slack -- `/account/settings/2fa_sms` ignores crumb (#155774) |
| Email verification before OAuth connect | UI hides button, but server endpoint allows direct POST | $1.6K Shopify -- `data-method="post"` injection bypasses UI gate (#1018489) |
| Server-side MFA enforcement via session flag | Swap `oc_sessionPassphrase` cookie from second session | $750 Nextcloud -- multi-cookie session decomposition (#1050244) |
| 2FA setting independent of SSO toggle | SSO enable silently flips 2FA boolean off | $1.5K Shopify -- Google Apps SSO clobbers 2FA (#178293) |
| Server trusts enrolled factor type from DB | Client `mfa_mode` param overrides enrolled type | $2.5K Grammarly -- email mode bypasses phone factor (#665722) |
| Cluster ID in signed token header | Authenticator verifies signature but not cluster ID field | $2.5K K8s -- cross-cluster token replay (#1580493) |
| OTP binds phone to resource at send time | Verify decouples phone from resource -- attacker phone + victim resource | $3.25K Zomato -- decoupled OTP claim (#1330529) |

## Chain Patterns

| Base Finding | Chain With | Combined Impact | Example |
|--------------|-----------|-----------------|---------|
| CSRF on 2FA enrollment | Attacker-server SMS relay script | Attacker's phone bound to victim's account | $500 Slack -- 2-step CSRF with JSONP callback (#155774) |
| MFA mode confusion | Device trust cookie still valid | Silent full ATO without any factor | $2.5K Grammarly -- mode + trust bypass (#665722) |
| Pre-verification OAuth bind | Ghost account claiming victim's email | Persistent OAuth backdoor surviving password reset | $1.6K Shopify -- unverified account OAuth (#1018489) |
| SSO toggle disables 2FA | Credential stuffing with leaked password | Full ATO (2FA was the defense, now gone) | $1.5K Shopify -- SSO clobber + password reuse (#178293) |
| Missing rate limit on reset 2FA | Email compromise (same breach database) | Full ATO bypassing 2FA via reset flow | $500 Slack -- brute force on reset (#121696) |
| Session cookie decomposition | Login as same user in parallel | 2FA enforcement bypass without TOTP secret | $750 Nextcloud -- cookie swap (#1050244) |
| IP rotation | Per-IP-only rate limit on login | Unlimited password brute force | $420 mopub -- proxy pool (#819930) |
| Cross-cluster token replay | Valid IAM creds for low-priv cluster | Admin access on high-priv cluster | $2.5K K8s -- token portability (#1580493) |

## Bypass Classes

### 1. Response Manipulation
Tamper the server response: flip `"success": false` -> `true`, status 401 -> 200, replace body with known-good 2FA success response from your own login.

### 2. Missing Server-Side Check (Direct URL Access)
After password, navigate directly to post-auth URLs. If post-auth endpoints accept pre-2FA session cookie, 2FA is client-side only.

### 3. Session Token Reuse / Decomposition
Capture pre-2FA cookie (C1) and post-2FA cookie (C2). If C1 works on sensitive endpoints, bypass. For multi-cookie sessions, swap individual cookies between sessions to confuse the 2FA gate.

### 4. Race Condition on Verify
Single-packet attack (HTTP/2): fire 100+ verify attempts in one TCP packet. Non-atomic rate-limit counters allow multiple successes.

### 5. Rate-Limit Bypass on Code Brute-Force
IP rotation via proxy pool; restart flow for new code window; pipeline requests via HTTP/2; test EVERY code path (login, reset, enrollment).

### 6. Backup Code Abuse
Enumerate format/entropy. Test: reusable? Regeneratable without re-auth? Does use silently disable TOTP?

### 7. MFA Mode Confusion
Change `mfa_mode` parameter to `email`, `none`, `skip`, `null`, or omit entirely. Server should enforce enrolled type from its own database, not trust client.

### 8. SSO / OAuth Toggle Side Effects
Enable SSO, check if 2FA survives. Login via OAuth (which may skip app-level 2FA). Bind OAuth pre-email-verification.

### 9. Enrollment Bypass / CSRF
CSRF on enrollment endpoint. IDOR on `POST /2fa/enroll?user_id=<victim>`. Bind attacker's TOTP/phone to victim's account.

### 10. "Remember This Device" Forgery
Set `device_trusted=true` manually. Forge predictable `device_id`. Flip `mfa_required=false` in JWT claim.

### 11. Step-Up Auth Downgrade
Fail primary MFA repeatedly until fallback offered. Is fallback weaker (email vs SMS vs nothing)?

### 12. Transitional Auth Endpoint Exploitation
Security-challenge / step-up endpoints return sensitive data (tokens, passwords) without full session auth. Test each XHR without cookies.

## Methodology

### Phase 1: Map the Flow
For EACH entry point (main login, SSO, password reset, invitation acceptance):
1. Record every request and response shape (JSON vs HTML redirect)
2. Note session cookie changes at each step
3. Identify where 2FA state lives (cookie, session, JWT claim, query param)
4. Map every endpoint that accepts an OTP/2FA code

### Phase 2: Test Each Bypass Class
Run all 12 classes systematically. Cross-reference: every OTP-consuming endpoint gets its own rate-limit test.

### Phase 3: Auth-Flow Interaction Matrix
For each pair (toggle X, login via Y), test silent side effects:
- Enable SSO -> does 2FA survive? Does notification fire?
- Use backup code -> does TOTP stay enabled?
- Change recovery email -> is 2FA step-up enforced?
- Add passkey -> does it bypass 2FA on subsequent logins?

### Phase 4: Focus on Recovery Flow
Recovery flows are the single most common 2FA bypass source. Every code path that accepts a 2FA code -- login, reset, enrollment, recovery, step-up -- needs independent testing.

## Key Commands

```bash
# Rate-limit bypass via IP rotation
for i in {100000..999999}; do
  curl -s -o /dev/null -w "%{http_code} " \
    -H "X-Forwarded-For: 192.168.$((RANDOM%254+1)).$((RANDOM%254+1))" \
    -X POST "https://target.com/api/2fa/verify" \
    -d "{\"code\":\"$i\"}" | head -1 | grep -q "^200" && echo "HIT: $i"
done

# Response manipulation (Burp match-and-replace)
# Proxy tab > Options > Match and Replace
#   Match:   "success":false
#   Replace: "success":true

# "Remember device" forgery
curl -X POST "https://target.com/api/login" \
  -H "Cookie: device_trusted=true; device_id=<guess>" \
  -d '{"username":"attacker","password":"..."}'

# MFA mode confusion
curl -X POST "https://target.com/api/login" \
  -d '{"username":"victim","password":"...","mfa_mode":"email"}'
# Also try: "none", "skip", "", null, omit field entirely
```

## What to Look For

**Immediate (Critical)**
- Response manipulation bypass (flip boolean -> logged in)
- Missing server-side check on post-MFA pages
- Pre-MFA cookie accepted post-MFA
- Enrollment IDOR (bind attacker's TOTP to victim account)
- Transitional endpoint leaking tokens/passwords ($15.3K PayPal #739737)

**High**
- 6-digit code brute-forceable (no rate limit)
- Race condition on verify
- MFA mode confusion (client picks factor type)
- SSO toggle silently disables 2FA
- CSRF on 2FA enrollment
- Pre-verification OAuth binding (ghost account)

**Medium**
- OAuth login bypasses app-level MFA
- Sensitive action missing MFA step-up
- Downgrade to email-code fallback
- Backup codes reusable / regeneratable without re-auth
- "Remember device" trivially forgeable

## Pro Tips

1. Response manipulation is embarrassingly common -- test every 2FA flow by flipping booleans
2. Pre-MFA session on post-MFA endpoint -- the single most common bypass class
3. Every OTP-consuming endpoint needs its own rate-limit test: login, password-reset, enrollment, step-up -- they are separate code paths with separate developers
4. MFA mode as a client-controlled parameter is a class: always test `null`, `""`, `0`, `"none"`, `"skip"`, and omit the field entirely
5. When UI greys out a button ("verify email first"), POST to the underlying endpoint directly -- UI guards are not security
6. Auth-feature interaction matrix: toggle one setting and check every other auth control for silent side-effects (SSO enable -> 2FA state?)
7. Multi-cookie sessions: enumerate what each cookie carries (identity, CSRF, MFA-status), then mix cookies from different sessions to find decomposition bypasses
8. For push-MFA, number-matching absence = reportable design flaw
9. Recovery flows are the #1 source of 2FA bypasses -- test before the login flow
10. Backup code use should NOT disable TOTP, and regeneration should require step-up auth
11. For multi-step CSRF (2FA enrollment), explore attacker-server callback to automate the OTP relay into the victim's browser session ($500 Slack #155774)
12. Ghost account pattern: register with victim's email pre-verification, bind OAuth, get persistent backdoor surviving password resets ($1.6K Shopify #1018489)

## Cross-References

- `account_takeover.md` -- chain 2FA bypass into full ATO (has its own 2FA matrix; this skill goes DEEPER on bypass mechanics)
- `authentication_jwt.md` -- if JWT carries `mfa_verified`, JWT attacks bypass MFA
- `rate_limiting_bypass.md` -- for OTP brute force techniques
- `session_security.md` -- pre/post MFA session handling
