---
name: consumer-auth
category: archetypes
description: Consumer authentication testing covering registration abuse, password reset flaws, OAuth/social login bypass, email/phone verification bypass, session management, and account enumeration
---

# Consumer Authentication Testing

Security testing playbook for consumer-facing authentication systems. Focus on registration abuse, password reset flaws, OAuth and social login bypass, email and phone verification bypass, session management, and account enumeration.

## When to Use

- Target has consumer-facing registration and login flows
- Application supports OAuth/social login (Google, Facebook, Apple, GitHub)
- Password reset or magic link authentication is implemented
- Phone/SMS verification is part of the signup or 2FA flow
- Application manages user sessions with cookies or tokens

## Priority Checklist

### 1. Registration Abuse

- **Duplicate account creation**: register with the same email using different casing or plus-addressing (user+tag@)
- **Email normalization bypass**: unicode homoglyphs, trailing dots, or encoding tricks to create distinct accounts for the same mailbox
- **Rate limiting absence**: no throttle on registration endpoint enabling mass account creation
- **Referral/promo abuse**: create multiple accounts to exploit sign-up bonuses or referral rewards
- **Disposable email bypass**: registration accepts throwaway email providers for services requiring identity
- Test: register with `User@example.com`, `user@example.com`, and `user+a@example.com` as separate accounts

### 2. Password Reset Flaws

- **Token leakage**: reset token in URL logged by analytics, referrer headers, or proxy caches
- **Token brute-force**: short or low-entropy reset tokens susceptible to enumeration
- **Token reuse**: same reset token accepted multiple times after initial use
- **Host header poisoning**: reset email link generated using attacker-controlled Host header
- **Race condition**: request multiple resets simultaneously, use one token, others remain valid
- **Cross-user reset**: manipulate user ID or email in the reset confirmation request
- Test: request a reset, change the Host header to attacker.com, check if the email link points there

### 3. OAuth/Social Login Bypass

- **State parameter missing/static**: CSRF on OAuth callback allows attacker to link their social account to victim
- **Redirect URI manipulation**: modify redirect_uri to exfiltrate authorization codes to attacker domain
- **Token substitution**: swap the OAuth token for a different user's token in the callback
- **Implicit grant token theft**: access token in URL fragment leaked via referrer or open redirect
- **Account linking confusion**: social login creates new account instead of linking to existing, or vice versa
- **IdP email trust**: application trusts unverified email from OAuth provider without re-verification
- Test: initiate OAuth flow, modify state/redirect_uri/token parameters at each step

### 4. Email Verification Bypass

- **Direct API access**: access authenticated features before email verification by calling API directly
- **Verification token prediction**: sequential or time-based tokens that can be guessed
- **Verification race**: use the account in the window between registration and verification check
- **Email change without re-verification**: change email to unverified address and retain access
- **Token in response body**: verification token returned in the registration API response itself
- Test: register, skip the verification link, and attempt to use all application features via API

### 5. Phone/SMS Verification Bypass

- **OTP brute-force**: 4-6 digit OTP with no rate limiting or lockout allows exhaustive enumeration
- **OTP reuse**: same OTP accepted after expiry or for multiple verification attempts
- **SMS interception**: OTP sent via SMS vulnerable to SIM swap or SS7 interception (note in report)
- **VoIP/virtual number acceptance**: verification accepts virtual numbers that can be obtained in bulk
- **Response manipulation**: client-side verification check can be bypassed by modifying API response
- **Default OTP**: test common defaults like 000000, 123456, or OTP visible in response headers
- Test: submit 000000-999999 range against the OTP endpoint; check for rate limiting and lockout

### 6. Session Management

- **Session fixation**: pre-set session ID accepted after authentication without regeneration
- **Concurrent session abuse**: no limit on active sessions; stolen session persists after password change
- **Token storage**: JWT or session tokens stored in localStorage (XSS-accessible) vs httpOnly cookies
- **Insufficient expiry**: sessions or refresh tokens valid for excessively long periods
- **Logout incompleteness**: session token remains valid server-side after logout
- **Cookie scope**: session cookies scoped too broadly (parent domain, missing Secure/SameSite flags)
- Test: authenticate, note session token, logout, replay the token and check if it is still accepted

### 7. Account Enumeration

- **Differential responses**: login/register/reset endpoints return different messages for existing vs non-existing accounts
- **Timing side-channel**: password hash comparison takes measurably longer for existing accounts
- **Error code differences**: HTTP status codes or JSON error fields differ based on account existence
- **Rate limiting disparity**: existing accounts trigger different rate limiting than non-existing ones
- Test: submit valid and invalid emails to login/reset endpoints, compare response body, timing, and status codes

### 8. OAuth Scope Over-Privilege Exploitation

- **Scope enumeration**: list all available OAuth scopes from provider docs, then request each individually and map what API endpoints each scope unlocks -- scopes often grant more access than the consent screen implies
- **Scope combination escalation**: request two individually-harmless scopes that together unlock a privileged action (e.g., `profile` + `contacts.read` enables full contact export)
- **First-party client scope abuse**: enumerate every `client_id` the target platform uses (web, mobile, internal tools); first-party clients often get broader implicit scopes than third-party apps
- **Scope downgrade bypass**: request a lower scope than originally granted; if the server reissues a token with the old broader scope, the downgrade is cosmetic
- Test: capture the OAuth authorize URL, add every documented scope to the request, accept, and test what the resulting token can access

### 9. Transitional Auth Flow Exploitation

- **Step-up auth bypass**: when a sensitive action requires re-authentication (password change, payment), check if the step-up token is validated or if it is just a client-side gate
- **Recovery flow token theft**: password-reset, account-merge, and MFA-setup flows each generate one-time tokens; test if they leak via Referer, are logged, or are brute-forceable
- **Account-merge confusion**: initiate account merge between two accounts you control; observe which account's permissions, data, and sessions survive; test merging into a victim account
- **Suspicious-login challenge bypass**: trigger the "unusual login detected" flow and check if the challenge can be dismissed by replaying a previous session cookie or answering with default values
- Test: for every flow that issues a temporary credential (reset link, step-up token, merge confirmation), trace where the token appears in headers, logs, and referrer chains

### 10. postMessage Origin Exploitation

- **Wildcard targetOrigin**: find `window.postMessage(data, '*')` in JS source; any page the user visits can receive the message, including attacker-controlled iframes
- **Origin check via indexOf/startsWith**: if the receiver checks `event.origin.indexOf('example.com')`, register `example.com.attacker.com` to pass the check
- **Cross-window token relay**: OAuth callback pages that post tokens to the opener window; if the opener can be an attacker page, the token is exfiltrated
- **iframe sandboxing gap**: embedded iframes that send auth tokens via postMessage without checking if the parent frame is same-origin
- Test: inject a postMessage listener on every page (`window.addEventListener("message", e => console.log(e.data, e.origin))`), then trigger every login, OAuth, and SSO flow

### 11. JWT and Token Structure Attacks

- **Algorithm confusion (alg:none)**: set the JWT `alg` header to `none` or `HS256` (when the server expects RS256) and see if the token is accepted
- **Key confusion (RS256 to HS256)**: sign the JWT with the public key using HMAC; if the server uses the same key for verify, the signature passes
- **Claim injection**: decode the JWT, add `admin: true` or change `role` / `email` claims, re-sign if you have the secret or alg:none works
- **Cross-service token reuse**: take a JWT issued for service A and present it to service B; if both share the same signing key and do not check `aud`, it works
- **Token in URL fragment leakage**: implicit grant tokens in `#access_token=` leak via browser history, referrer headers, and analytics scripts
- Test: decode every token (JWT, opaque base64), diff tokens across accounts, test with modified claims and algorithm headers

### 12. Open Redirect Chaining with OAuth

- **OAuth code theft via open redirect**: find any open redirect on the OAuth redirect_uri domain, chain it to exfiltrate the authorization code to an attacker-controlled host
- **SAML RelayState redirect**: inject an attacker URL into the RelayState parameter; after SAML authentication the user is redirected to the attacker with a valid session
- **Post-login redirect manipulation**: many apps accept a `next=` or `return_to=` parameter after login; chain with OAuth so the code or token lands on the redirect target
- **Stored redirect in cookie**: some apps store the redirect target in a cookie before the OAuth flow; set the cookie to an attacker URL via a separate subdomain XSS
- Test: find any open redirect (even low-severity), then chain it with every OAuth/SSO callback URL to escalate to token theft

### 13. MFA Bypass Techniques

- **MFA mode parameter tampering**: send `mfa_mode=none` or `mfa_mode=email` when the account requires TOTP; the server may accept the weaker method
- **Backup code brute-force**: backup codes are often 8-digit numeric; test if the endpoint rate-limits backup code attempts separately from OTP attempts
- **Session persistence after MFA disable**: disable MFA from a session that already passed MFA; check if existing sessions that never passed MFA are now elevated
- **MFA setup race**: during initial MFA setup, call the "verify MFA" endpoint with a code from a TOTP secret you control before the user scans the QR code
- Test: enumerate all values the `mfa_mode` or `challenge_type` parameter accepts, including `null`, `""`, `"none"`, `"sms"`, `"backup"`, `"security_key"`

### 14. UI-Only Authorization Gates

- **Interstitial skip**: when the server returns an HTML page saying "access denied" or "verify your email," check if the next-step endpoint is independently accessible via direct API call
- **Client-side role filtering**: the frontend hides admin buttons based on a `role` field in the user profile response; modify the response in the proxy to unhide, then click the (now-visible) button to confirm the API enforces the restriction
- **Feature flag bypass**: feature flags delivered to the client (`features: ["beta_dashboard"]`) may gate UI elements but not API endpoints; call the beta API directly
- Test: for every "you can't do this" UI message, inspect the network tab for the actual API response and call the downstream endpoint directly

## Pro Tips

- **Chain open redirects with OAuth for maximum impact.** A low-severity open redirect on the same domain as an OAuth redirect_uri becomes a Critical token theft when chained. Always test this combination.
- **Audit every transitional flow independently.** Password reset, email change, MFA setup, account merge, and social login binding are each separate state machines with their own token issuance, validation, and expiry. A bug in one rarely exists in others.
- **Diff tokens across accounts.** Decode every opaque token (base64, JWT) from two test accounts and diff the fields. Stable bytes are constants or keys; varying bytes are identity claims. Manipulate the varying fields.
- **Login/SSO subdomains are the highest-value XSS targets.** They have privileged cookie scope, broad user reach, and are frequently the OAuth redirect_uri origin. An XSS here chains to account takeover.

## Validation

- Demonstrate authentication bypass with access to another user's account or data
- Show password reset exploitation with concrete token theft or host header poisoning
- Prove OAuth bypass with attacker-linked social account or stolen authorization code
- Confirm verification bypass with access to protected features using an unverified account
- Document exact request/response pairs, timing measurements, and observable access changes
