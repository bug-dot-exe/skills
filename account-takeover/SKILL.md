---
name: account-takeover
description: Account takeover attack chains covering password reset poisoning, token prediction, session fixation, OAuth hijack, and email change without reauth
depends_on: []
---

# Account Takeover

Account takeover (ATO) attack chains combining multiple weaknesses to gain full control of another user's account. Focus on password reset poisoning, token prediction, session fixation, OAuth callback hijack, and email/phone change without re-authentication.

## Attack Surface

**Password Reset Flow**
- Reset request endpoint: email/username input
- Reset token generation: randomness, length, format
- Reset token delivery: email, SMS, in-app
- Reset token consumption: validation, single-use, expiry
- New password submission: token binding, session handling

**Session Management**
- Session creation: after login, after OAuth, after registration
- Session identifiers: cookie format, entropy, rotation
- Session binding: IP, user-agent, fingerprint
- Session invalidation: on password change, on role change, on logout

**Account Recovery**
- Security questions, backup codes, recovery email/phone
- Support/admin account recovery workflows
- Account merge/linking flows

**Identity Changes**
- Email change: verification, re-authentication requirement
- Phone change: OTP verification, re-authentication requirement
- Password change: old password requirement, session invalidation
- Username change: impact on existing sessions and tokens

**OAuth/Social Login**
- Account linking: social account to existing account
- Account creation: auto-registration from OAuth data
- Callback handling: state, token exchange, session creation

## High-Value Targets

- Password reset endpoints
- Email/phone change endpoints
- OAuth callback and account linking flows
- Session management endpoints (login, logout, session listing)
- Admin impersonation features
- API key/token regeneration endpoints
- Two-factor setup and recovery

## Key Vulnerabilities

### Password Reset Poisoning

**Host Header Injection**
```
POST /password/reset HTTP/1.1
Host: attacker.com

email=victim@target.com
```
- Reset link generated using Host header: `https://attacker.com/reset?token=TOKEN`
- Victim clicks link in email, token sent to attacker's server
- Works when: application uses Host header for URL generation without validation

**Forwarded Header Injection**
```
X-Forwarded-Host: attacker.com
X-Forwarded-Proto: https
X-Original-Host: attacker.com
X-Rewrite-URL: /reset
```
Application trusts proxy headers without validation.

**Referer Leakage**
- Reset page loads third-party resources (analytics, CDN, images)
- Token in URL leaked via Referer header to third parties
- Test: check Referrer-Policy header on reset page

**Double Submit**
- Request reset for victim, intercept response
- Use the token from response/URL before victim does
- Race condition: if token is displayed in response body or predictable URL

### Token Prediction

**Weak Token Generation**
- Sequential tokens: `token=1001`, `token=1002`
- Timestamp-based: `token=base64(timestamp + user_id)`
- MD5/SHA1 of predictable data: `MD5(email + timestamp)`
- Short tokens: 4-6 character numeric OTP brute-forceable in seconds

**Token Brute Force**
- 6-digit OTP: 1,000,000 possibilities, feasible without rate limiting
- UUID v1: contains timestamp and MAC address, partially predictable
- Base64-encoded values: decode and analyze structure for patterns

**Token Reuse**
- Token not invalidated after use: replay the same reset token
- Token not invalidated after password change: use old token after victim resets
- Multiple valid tokens: requesting reset multiple times creates multiple valid tokens without invalidating prior ones

### Session Fixation

**Pre-Authentication Fixation**
- Application assigns session ID before login and does not rotate it after authentication
- Attacker sets session cookie (via XSS, subdomain, HTTP header injection)
- Victim authenticates; attacker uses the same session ID

**Cross-Subdomain Session**
- Session cookie scoped to `.target.com`
- Attacker controls `evil.target.com` (subdomain takeover, user-generated content)
- Set session cookie from subdomain, victim authenticates on `app.target.com`

**Session Donation**
- Attacker authenticates, obtains session
- Tricks victim into using attacker's session (via CSRF-like mechanism)
- Victim performs actions (adds credit card, enters sensitive data) under attacker's session

### OAuth Hijack

**Authorization Code Theft**
- Open redirect on redirect_uri: code sent to attacker-controlled endpoint
- Missing state parameter: CSRF on OAuth callback links attacker's social account
- See oauth.md for detailed redirect_uri manipulation techniques

**Account Linking Abuse**
- Link attacker's social account to victim's account via CSRF on linking endpoint
- Missing re-authentication before linking social login
- OAuth email mismatch: social provider returns different email than expected

**Pre-Registration Race**
- Attacker creates account with victim's email before victim registers
- Victim signs up via OAuth with same email; accounts merge
- Attacker retains access via original password or linked social account

### Email Change Without Re-Authentication

**Missing Re-Auth**
```
PUT /api/account
{"email": "attacker@evil.com"}
```
- Email changed without requiring current password
- Verification email sent to new address without confirming old address
- Account recovery now goes to attacker's email

**Verification Bypass**
- Email change applied immediately, verification is advisory only
- Race condition: change email + request password reset before verification check
- Change email to one with existing account: merge or overwrite

**Email Verification Token Leak**
- Verification link in response body (not just email)
- Verification token predictable or brute-forceable
- No rate limiting on verification endpoint

### Two-Factor Bypass for ATO

**2FA Setup Without Re-Auth**
- Attacker with session access (XSS, session fixation) adds their own 2FA device
- Victim locked out; attacker has persistent access via 2FA

**Backup Code Exploitation**
- Backup codes displayed without re-authentication
- Backup codes not rotated after use
- Backup code generation endpoint accessible without 2FA verification

**2FA Removal**
- Remove 2FA without re-authentication or 2FA verification
- Support flow bypassing 2FA for "recovery" without sufficient identity proof

### Response Manipulation

**Token in Response Body**
- Password reset token returned in HTTP response (not just email)
- OTP/verification code in API response alongside "check your email" message
- Token visible in response headers (Location redirect, custom headers)

**Rate Limit Bypass**
- Rate limit on IP only: rotate IPs or use distributed requests
- Rate limit on account only: works for targeted attack on known account
- Rate limit reset on different endpoint: same operation via API vs web
- Rate limit on OTP verification but unlimited OTP requests: exhaust victim's legitimate OTPs

## Discovery Signals

| # | Signal | Where to Find | Why Vulnerable |
|---|--------|---------------|----------------|
| 1 | `/forgot-password`, `/reset`, `/recover` endpoints | Sitemap, JS bundles, mobile API | Password reset is the primary ATO surface -- test Host header, token entropy, rate limits |
| 2 | 4-6 digit OTP in SMS/email recovery | Trigger reset, observe code format | Small keyspace (10K-1M) brute-forceable if rate limit is per-IP only ($30K Instagram #519713875) |
| 3 | `machine_id`, `datr`, `device_id` in cookies or API responses | OAuth token exchange, batch API responses | Device trust identifiers leaked via API enable trusted-device recovery bypass ($24K Facebook #3320995794) |
| 4 | Email change endpoint without re-auth prompt | Profile settings, intercept PUT/PATCH | Missing re-authentication on email change is a direct ATO primitive via password reset to new email |
| 5 | `postMessage` handlers with `*` targetOrigin | JS source search for `postMessage(`, `addEventListener('message'` | Wildcard targetOrigin leaks tokens cross-origin ($30K Facebook FXAuth #3226787990) |
| 6 | SSO/OAuth account linking UI | Settings > Connected Accounts | CSRF on link/unlink endpoints enables attacker account persistence ($1.6K Shopify #1547684) |
| 7 | Sub-property with custom auth (not main SSO) | `careers.`, `support.`, `wholesale.` subdomains | Sub-properties roll custom auth with weaker controls ($50K Waymo #391838208) |
| 8 | Invitation or activation token endpoints | `/invite`, `/activate`, `/confirm` | Tokens equivalent to password-set; misissuance via state-machine bypass = ATO ($1.6K Shopify #1266828) |
| 9 | CDN headers (`X-Cache`, `Via`, `Age`) on authenticated pages | Response headers on profile/dashboard | Web cache deception caches authenticated responses under static-extension URLs ($750 Expedia #1698316) |
| 10 | MFA mode parameter in login request body | Intercept login POST, inspect JSON fields | Client-controlled MFA mode selection lets attacker downgrade to weakest factor ($2.5K Grammarly #665722) |
| 11 | Mobile API with separate recovery flow | Proxy Android/iOS traffic, compare to web | Mobile endpoints often have weaker rate limits and shorter OTPs than web equivalents |
| 12 | `security-challenge`, `step-up`, `verify` transitional endpoints | Network tab during suspicious-login flow | Transitional auth endpoints return sensitive data (tokens, even passwords) without full session auth ($15.3K PayPal #739737) |

## Password Reset Attack Matrix

| Attack | Technique | Where to Test | Real Example |
|--------|-----------|---------------|--------------|
| Host header poisoning | `Host: attacker.com` on reset request; link generated with attacker domain | Reset endpoint, also try `X-Forwarded-Host`, `X-Original-Host` | $7.5K Periscope ATO via Host header in OAuth callback (#317476) |
| Token brute-force (missing rate limit) | Enumerate token space within TTL; rate limit only per-IP, bypass with rotation | Token verification endpoint specifically (not just the request endpoint) | $500 Nextcloud -- rate limit on request but NOT on verify endpoint (#1987062) |
| OTP race condition + IP rotation | Concurrent requests exploit non-atomic rate limiter counter; multiply with IP pool | Mobile recovery API `POST /accounts/account_recovery_code_verify/` | $30K Instagram -- 6-digit OTP brute-forced via concurrency + IP rotation (#519713875) |
| Token in response body | Reset/challenge endpoint returns token in JSON response alongside "check your email" | Inspect all XHR responses during reset flow; check for token/code fields | $15.3K PayPal -- security challenge endpoint returned email AND plaintext password (#739737) |
| Referer leakage | Reset page loads third-party resources; token in URL leaked via Referer header | Check `Referrer-Policy` header; observe outbound requests from reset page | $500 Shopify -- theme editor `oseid` token leaked via Referer to third-party analytics (#1262434) |
| Signing oracle via registration | Register with crafted username; activation link signs attacker-chosen payload in same format as session cookie | Compare decoded session cookie structure across multiple accounts | $50K VirusTotal -- registration activation link signed same format as session cookie (#146455552) |
| Email-to-wrong-address | Change email before confirming original; confirmation sent to attacker-controlled old address | Sign up, do NOT confirm, immediately change email | $16K Shopify -- confirmation link for new email sent to old (unconfirmed) email (#791775) |
| Patch-diff bypass | Prior security fix missed one endpoint in the flow; token verification still unthrottled | Read CVE advisories, audit fix completeness across all flow endpoints | $500 Nextcloud -- bruteforce protection added to request but missed verify (#1987062) |
| Double-submit race | Request reset for victim, use token from response before victim does | Race condition window between token generation and victim's use | Timing attacks on predictable or response-leaked tokens |
| Conditional auth path bypass | Submit minimum fields (email only, blank name) to skip verification step | Remove optional fields, submit partial forms, test every if/else path | $50K Waymo -- blank name field bypassed verification entirely (#391838208) |
| Batch API field laundering | Chain sensitive-data API call with write API call via batch request references | GraphQL batch, REST batch APIs that support `{result=previous:$.field}` | $24K Facebook -- batch API laundered `machine_id` (device cookie) into readable post (#3320995794) |
| Cross-platform SSO redirect traversal | Double URL-encode path traversal in SSO redirect parameter to escape prefix checks | `extra_data`, `RelayState`, `next`, `redirect` params in SSO flows | $30K Facebook -- double-encoded path traversal in native_sso `extra_data` (#3226787990) |

## 2FA/MFA Bypass Matrix

| 2FA Type | Bypass | Technique | Condition |
|----------|--------|-----------|-----------|
| SMS OTP (4 digit) | Brute-force | 1000-9999 range, ~9000 attempts; no rate limit or lockout | Per-IP rate limit only, no per-account throttle ($500 Grab #202425) |
| SMS OTP (6 digit) | Race + IP rotation | Concurrent requests defeat non-atomic counter; 200K codes in 10min window | Rate limiter uses simple counter, not atomic INCR ($30K Instagram #519713875) |
| Email OTP | Mode confusion | Change `mfa_mode` from `phone` to `email` in request body; server trusts client | Server does not enforce enrolled factor type from its own database ($2.5K Grammarly #665722) |
| Any OTP | Null/skip value | Send `null`, `""`, `0`, `"none"`, `"skip"` as OTP value; omit field entirely | Server fails open on unrecognized or missing values |
| TOTP | Backup code access | Access backup code display or generation endpoint without 2FA re-verification | Backup code endpoints often skip step-up auth check |
| Device trust | Cookie theft | Steal `datr`/device-trust cookie via OAuth API leak; impersonate trusted device | Device trust cookie appears in API responses not just browser ($24K Facebook #3320995794) |
| Any 2FA | Setup hijack | With session access (XSS/fixation), add attacker's 2FA device before victim enables theirs | 2FA enrollment endpoint doesn't require re-authentication |
| Any 2FA | Removal without re-auth | Remove 2FA from account settings without current password or 2FA code | Support/admin recovery flow bypasses 2FA entirely |
| Any 2FA | Response manipulation | Intercept 2FA verification response; change `"success": false` to `"success": true` | Server-side validation but client-side trust of response body |
| Any 2FA | Endpoint version switch | Use `/v1/login` instead of `/v2/login`; older version lacks 2FA enforcement | Legacy API versions still active alongside current |

## Session Attack Matrix

| Attack | Technique | Prerequisite | Impact |
|--------|-----------|--------------|--------|
| Cookie scope abuse | XSS on any subdomain steals `.domain.com`-scoped session cookie | XSS on any subdomain + cookies scoped to parent domain | Full ATO from low-value subdomain bug ($10K Fitbit #568838656) |
| Cache deception | Lure victim to `/profile/x.css`; CDN caches authenticated response; attacker reads cache | CDN with path-based cache rules + app with catch-all routing | Session/CSRF token theft from cached page ($750 Expedia #1698316) |
| ESI injection + XSS chain | ESI tag in reflected param extracts HttpOnly cookie at edge; XSS reads response body | Edge processor (Varnish/Akamai) with ESI enabled + reflected injection point | HttpOnly bypass -- ESI reads cookies server-side, XSS reads ESI output ($750 DoD #1073780) |
| OAuth disconnect persistence | Link attacker OAuth account; victim disconnects it; attacker session survives | Prior session via any compromise + OAuth linking | Persistent ATO surviving victim's remediation ($1.6K Shopify #1547684) |
| postMessage token theft | Endpoint sends tokens via `postMessage(data, '*')`; attacker page receives as opener/parent | Endpoint with wildcard targetOrigin + attacker-controlled opener | Cross-origin token capture without XSS ($30K Facebook #3226787990) |
| Batch API session leak | Chain privileged API call returning session data with write call to attacker-readable location | Batch/GraphQL API supporting cross-request field references | Extract device trust or session identifiers ($24K Facebook #3320995794) |
| Login CSRF for session setup | Force victim to log into attacker's account; then exploit nonce-protected endpoints | Login endpoint vulnerable to CSRF (email login link, no CSRF token) | Satisfy nonce preconditions for token theft chains ($30K Facebook #3226787990) |
| jQuery sink XSS to ATO | Search term flows into `jQuery.after()` (executes scripts unlike `innerHTML`) | jQuery loaded + user input in `.after()/.append()/.html()` + missing httpOnly | Stored/reflected XSS with session cookie theft ($10K Kaggle #938474496) |

## OAuth-to-ATO Chains

| OAuth Flaw | ATO Technique | Chain | Impact |
|------------|---------------|-------|--------|
| Open redirect + implicit grant | Token in fragment leaked via redirect | Find any open redirect on OAuth client domain; trigger `response_type=token`; redirect leaks `#access_token` | Third-party account takeover ($2.4K GitLab/Bitbucket #1923672) |
| SAML RelayState redirect | Stored redirect captures OAuth token | Store malicious redirect in session via RelayState; force re-auth via logout CSRF; OAuth token lands on attacker domain | Persistent redirect survives between requests (#1923672) |
| postMessage origin trust | Self-XSS on trusted origin relays tokens | Self-XSS in payment widget origin + postMessage relay to parent + parent trusts origin | Self-XSS becomes real XSS via trust relay ($62.5K Facebook #458771975) |
| Canvas/iframe platform trust | XSS in any third-party app escalates | XSS in Canvas/embedded app iframe + parent frame trusts `apps.domain.com` origin | Platform-wide ATO from single app XSS ($126K Facebook #294166288) |
| SSO path traversal | Redirect to token-leaking endpoint | Double-encode path traversal in SSO redirect param; land on endpoint that postMessages tokens | Bypass `/accounts_center/` prefix restriction ($30K Facebook #3226787990) |
| Account linking CSRF | Link attacker's social account to victim | CSRF on OAuth connect endpoint; no re-auth required; attacker's Google/FB linked to victim's account | Persistent backdoor access via social login |

## Registration/Onboarding Attacks

| Attack | Technique | Where | Impact |
|--------|-----------|-------|--------|
| Pre-registration email claim | Register with victim's email before they do; victim signs up via OAuth; accounts merge | Any platform with both email and OAuth signup | Attacker retains access via original password after merge |
| Unconfirmed email change | Sign up but don't confirm; immediately change to victim email; confirmation sent to attacker's original | Email change flow during unconfirmed-account state | Confirm arbitrary email, chain to SSO merge ($16K Shopify #791775) |
| Invitation token reissuance | Call `send_invite` to reset state, then `invite_links` to get password-set token for active account | Admin panels with invite/activate features | ATO via invitation token on already-active accounts ($1.6K Shopify #1266828) |
| Gmail dot-equivalence | Register `v.ictim@gmail.com` (Gmail treats as same as `victim@gmail.com`); target platform treats as different | Any platform not normalizing Gmail dot-aliases | Account collision enabling email-based recovery abuse ($44.6K Facebook #1182874553) |
| Signing oracle via registration | Register users to get activation links; activation link format matches session cookie format | Registration endpoint with email confirmation tokens | Forge session cookies for arbitrary users ($50K VirusTotal #146455552) |
| Minimum-input auth bypass | Submit only email (no name, no password) to auth endpoint; server skips verification step | Career portals, candidate systems, passwordless flows | Direct login as any user by email alone ($50K Waymo #391838208) |

## Defense-Bypass Pairs

| Defense | Bypass Technique | Real Example |
|---------|------------------|--------------|
| Per-IP rate limit on login | Rotate IPs via proxy mesh; per-IP counter resets per source | $420 mopub -- proxy rotation defeated per-IP-only throttle (#819930) |
| Per-IP rate limit on OTP | Race condition on non-atomic counter + IP rotation | $30K Instagram -- concurrent requests bypass counter (#519713875) |
| Rate limit on reset request (but not verify) | Brute-force the token verification endpoint directly | $500 Nextcloud -- verify endpoint missed throttle annotation (#1987062) |
| HttpOnly cookie flag | ESI injection at edge layer reads cookies server-side; XSS reads ESI response | $750 DoD -- ESI `$(HTTP_HEADER{Cookie})` bypasses HttpOnly (#1073780) |
| JSON content-type as CSRF defense | Switch `Content-Type` to `application/x-www-form-urlencoded`; server parses both | $500 DoD -- CSRF on email change via content-type coercion (#1624421) |
| CSRF token on email change | IDOR on update endpoint; change another user's email directly | Email change IDOR on `/api/users/{id}` without ownership check |
| Origin validation on postMessage | Self-XSS in trusted origin relays arbitrary messages past check | $62.5K Facebook -- Self-XSS on payment widget, origin check satisfied (#458771975) |
| OAuth state parameter | Login CSRF forces attacker session; attacker's state is valid in victim's browser | $30K Facebook -- login CSRF satisfies nonce binding (#3226787990) |
| Device trust cookie for recovery | Steal device identifier via API response; set cookie in attacker browser | $24K Facebook -- `machine_id` leaked via OAuth exchange (#3320995794) |
| SameSite cookie attribute | Redirect chain within same site; top-level navigation preserves SameSite=Lax cookies | Android intent-picker redirect bypasses SameSite checks |

## Chain Patterns

| Base Finding | Chain With | Combined Impact | Example |
|--------------|-----------|-----------------|---------|
| Self-XSS (low/no bounty alone) | postMessage trust relay to higher-value origin | Full ATO on parent domain | $62.5K -- Self-XSS + payment widget trust + Facebook ATO (#458771975) |
| Open redirect (low) | OAuth implicit grant `response_type=token` | Third-party account takeover via token in fragment | $2.4K -- SAML RelayState redirect + Bitbucket implicit grant (#1923672) |
| Login CSRF (low) | Nonce-protected token-leaking endpoint | Satisfy nonce precondition, steal auth tokens | $30K -- login CSRF + SSO path traversal + postMessage leak (#3226787990) |
| XSS on subdomain (medium) | Cookie scoped to parent `.domain.com` | Main-app session hijack from any subdomain | $10K -- jQuery XSS on healthsolutions.fitbit.com + `.fitbit.com` cookies (#568838656) |
| CSRF on email change (low-medium) | Password reset to attacker-controlled email | Full ATO via reset flow | $500 -- content-type coercion CSRF + email change + password reset (#1624421) |
| Email confirmation bug (low) | SSO account merge by email | Cross-tenant ATO of all victim's stores | $16K -- unconfirmed email change + SSO merge (#791775) |
| XSS anywhere on origin (medium) | ESI injection on same origin | HttpOnly cookie bypass + full session theft | $750 -- reflected XSS + ESI injection chain (#1073780) |
| Web cache deception (medium) | Authenticated page caching with CSRF/session tokens | ATO via cached token theft | $750 -- profile page cached under `.css` extension (#1698316) |

## Chaining Attacks

- **XSS + Session theft**: steal session cookie or CSRF token for account modification
- **Open redirect + OAuth**: redirect authorization code to attacker via legitimate domain redirect
- **Subdomain takeover + Session fixation**: set session cookie from taken-over subdomain
- **IDOR + Email change**: change another user's email via IDOR on update endpoint
- **CSRF + Email change**: change victim's email via cross-site request (if no re-auth required)
- **Race condition + Token reuse**: use reset token simultaneously with victim to maintain access

## Testing Methodology

1. **Map account flows** - Document all authentication, recovery, and account modification endpoints
2. **Reset flow analysis** - Test Host header injection, token prediction, token reuse, Referer leakage
3. **Session audit** - Check rotation on login, fixation resistance, cross-subdomain scope
4. **OAuth testing** - Test redirect_uri validation, state parameter, account linking CSRF
5. **Identity change** - Test email/phone change re-authentication, verification bypass, race conditions
6. **2FA boundaries** - Test setup/removal without re-auth, backup code access, recovery flow
7. **Rate limiting** - Test OTP brute force, reset request flooding, per-IP vs per-account limits
8. **Chain building** - Combine individual weaknesses into full ATO attack chains

## Validation

1. Password reset poisoning: reset token intercepted via Host header manipulation
2. Token prediction: valid reset or OTP token generated/predicted without access to victim's email
3. Session fixation: authenticated session obtained via pre-set session identifier
4. OAuth hijack: victim's account accessed via stolen authorization code or CSRF account linking
5. Email change ATO: email changed without password re-entry, then password reset to attacker's email
6. 2FA bypass: persistent access obtained by adding attacker's 2FA or accessing backup codes

## False Positives

- Password reset emails use hardcoded domain, not Host header
- Sessions rotated on authentication with proper entropy
- OAuth state parameter validated and session-bound
- Email change requires current password and sends notification to old address
- Rate limiting enforced across IP, account, and API path

## Impact

- Full account takeover: attacker gains persistent access to victim's account
- Data theft: access to personal information, financial data, private communications
- Financial fraud: unauthorized transactions, payment method theft
- Reputation damage: actions performed under victim's identity
- Lateral movement: compromised account used to access connected services

## Pro Tips

1. Always test password reset with modified Host, X-Forwarded-Host, and X-Original-Host headers simultaneously
2. Request multiple password resets and check if all tokens remain valid (only the latest should work)
3. After changing password via reset, verify all existing sessions are invalidated
4. Test email change followed immediately by password reset to the new email (race window)
5. Check if the old password still works after a password reset (should not)
6. OAuth account linking is a frequent source of ATO: always test linking flows with CSRF
7. Mobile apps often have weaker reset flows than web: test both channels
8. Document the full chain end-to-end: weakness alone may be low severity, but combined chain is critical
9. Decode and diff session cookies across two test accounts -- if only 4-5 bytes differ, brute-force is feasible; then look for a signing oracle in registration/activation flows ($50K VirusTotal #146455552)
10. For any OTP endpoint, compute the attack budget: `code_space / (per_IP_limit * validity_minutes * attacker_IPs)` -- if under 10^6 practical attempts, the gate is brute-forceable ($30K Instagram #519713875)
11. When an endpoint is "greyed out" in the UI, call the API directly -- server-side state-machine bypass via adjacent endpoint side effects is a recurring ATO pattern ($1.6K Shopify #1266828)
12. Test every authenticated page with appended static extensions (`.css`, `.js`, `.png`) for web cache deception -- CDN caches the authenticated response under the crafted URL ($750 Expedia #1698316)
13. After finding any open redirect, immediately check for OAuth integrations with `response_type=token` (implicit grant) on the same origin -- the combination is always worth testing ($2.4K GitLab #1923672)
14. For JSON-only endpoints without CSRF tokens, try switching `Content-Type` to `application/x-www-form-urlencoded` -- many frameworks parse both, bypassing the implicit CSRF defense ($500 DoD #1624421)
15. Test MFA by sending `null`, `""`, `0`, `"none"` as the factor value, and by switching `mfa_mode` to a different or nonexistent method -- the server should enforce the enrolled type, not trust the client ($2.5K Grammarly #665722)
16. Sub-properties of large companies (careers portals, wholesale stores, support platforms) often have custom authentication weaker than the main SSO -- enumerate subdomains and test each auth flow independently ($50K Waymo #391838208)
17. When a victim disconnects an attacker's linked OAuth account, check if the attacker's existing session survives -- session invalidation on unlink is frequently missing ($1.6K Shopify #1547684)
18. Search every `postMessage` handler for wildcard `targetOrigin` (`'*'`) -- any endpoint sending tokens to `*` is a cross-origin token theft primitive ($30K Facebook #3226787990)
19. When the target uses a third-party IDP (Cognito, Auth0, Okta, Firebase), call the IDP API directly with your access token to bypass UI restrictions -- Flickr blocked email change in UI but Cognito `update-user-attributes` was reachable, and Flickr never checked `email_verified=false` (Flickr ATO -- H1 #1342088)
20. Test identity normalization collisions: register with a case-variant of the victim's email (`Victim@` vs `victim@`); if the IDP stores case-sensitively but the app normalizes to lowercase on lookup, two IDP records collapse into one app identity (Flickr Cognito -- H1 #1342088)
21. When you find a hardcoded hash in production code, search the public web for it -- if the preimage is public (e.g., Android `debug.keystore` SHA), any service trusting that key is exploitable ($10K Instagram -- H1 #357289285)
22. Run broken-link-hijack scans on all program-published pages (docs, blog, landing) -- dangling Twitter handles, GitHub org links, and domain references are claimable for impersonation ($0 RunPanther -- H1 #1607429)
23. For every SMS/OTP flow, map the full state machine: does each request issue a NEW code or reuse the old one? Does verification invalidate the code? Does a new request kill the previous code? Gaps in any transition enable parallel brute-force or code reuse (H1 #1245762)

## Summary

Account takeover chains exploit weaknesses across authentication, recovery, and identity management flows. A single flaw (weak token, missing re-auth, Host header trust) becomes critical when chained with standard attack techniques to achieve persistent account access.
