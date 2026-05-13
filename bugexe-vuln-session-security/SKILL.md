---
name: session-security
category: vulnerabilities
description: Session fixation, hijacking, predictable IDs, weak invalidation, JWT pitfalls, 2FA step-up bypass
depends_on: []
---

# Session Security

Session management bugs let an attacker impersonate a user by obtaining, predicting, fixing, or refusing to invalidate a session credential. Every other auth control (MFA, RBAC, password policy) is downstream of session integrity, so a single invalidation gap is often a full account takeover.

## Attack Surface

**Session Carriers**
- Cookies (`Set-Cookie`), `Authorization: Bearer` headers, query-string tokens (legacy), URL fragments (SPA)
- `localStorage`/`sessionStorage` tokens read by JS and sent as headers
- JWTs, opaque server-side sessions, stateless HMAC tokens, session-in-URL for file download signing

**Lifecycle Events That Reveal Bugs**
- Registration, login, MFA promotion, password change, email change, role change, logout, account deletion, "Remember me", "Log out all devices"
- Sudo/step-up re-auth for sensitive actions (payment, 2FA disable, API key issuance)

**Cross-Surface**
- Same account on web + mobile + CLI + desktop. Token formats often differ; revocation often does not fan out.
- Multi-tenant: switching tenants/organizations; impersonation-by-support flows.

## High-Value Targets

### Cookie Flags

- Missing `Secure` → token leaks on any accidental HTTP redirect or mixed-content request
- Missing `HttpOnly` → stealable by XSS (`document.cookie`)
- Missing/weak `SameSite` → CSRF amplifier; `None` without `Secure` is rejected by modern browsers
- Domain scoped too wide (`.example.com`) → child subdomain takeover → session theft
- Path scope `/` on APIs that should be `/api` → leaked to unrelated origins on same host
- `__Host-` and `__Secure-` prefixes not used on session/auth cookies where they should be (admin, high-trust auth, payment flows)

### JWT Pitfalls

- `alg: none` or case-variant (`NONE`, `nOnE`) accepted by lax parsers
- HS256 ↔ RS256 confusion: signing with the RSA public key as the HS256 secret
- `kid` path traversal (`../../dev/null`) or SQL injection in `kid` lookup
- `jku`/`x5u` pointing to attacker-controlled JWKS endpoint (allowlist absent)
- Weak HMAC secret (`secret`, `changeme`, `jwt_secret_key`) — brute with `hashcat -m 16500`
- Sensitive data in payload (role, tenant_id, is_admin) with client-side-only enforcement
- No `exp` or absurdly long `exp` (years); no `nbf`; no `jti` so replay is undetectable
- Server accepts `exp` as string vs int inconsistently; signed token from a sibling service reused here

### Server-Side Session IDs

- Tokens < 128 bits of entropy, sequential IDs, timestamp+userID constructions
- Token that decodes to base64(user_id + issued_at) — forgeable
- Session store keyed only by ID with no binding to UA/IP/device fingerprint at all (tradeoff, but total absence is suspicious)

### Session Fixation

- Pre-auth session ID not rotated post-auth. Attacker plants cookie via `Set-Cookie` from XSS on a subdomain, or via `?JSESSIONID=...` URL param, or via a same-site link with a cookie-setting endpoint. Victim logs in, attacker reuses the same ID.

### Concurrent Sessions & Logout Fail-States

- "Log out all devices" that only revokes the current cookie
- Password change that does not invalidate sibling sessions
- Email/phone change that does not trigger reauth (attacker keeps session after victim's 2FA was rotated)
- MFA reset does not kill pre-MFA sessions
- Refresh-token rotation missing: old refresh tokens still mint access tokens

### 2FA / Step-Up Bypass

- Pre-2FA session cookie accepted on post-2FA endpoints if you hit them directly
- `is_mfa_verified=true` claim lives client-side and is echoed to the server
- Step-up flow checks "recent_auth_at" but attacker can refresh it via a low-sensitivity endpoint
- "Trust this device" token with no expiry or bound to a weak fingerprint

## Key Vulnerabilities

### Fixation PoC
```
# 1. Attacker grabs a pre-auth session
curl -i https://app.example.com/ | grep -i set-cookie
# Set-Cookie: SESSIONID=ATTACKER_VALUE; Path=/

# 2. Attacker phishes victim to:
https://app.example.com/login?sid=ATTACKER_VALUE
# or plants cookie via subdomain XSS

# 3. After victim login, reuse ATTACKER_VALUE from attacker's browser:
curl https://app.example.com/account -b "SESSIONID=ATTACKER_VALUE"
# → returns victim's account
```

### JWT alg:none
```python
import base64, json
header = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=")
payload = base64.urlsafe_b64encode(json.dumps({"sub":"admin","role":"admin"}).encode()).rstrip(b"=")
token = header + b"." + payload + b"."
print(token.decode())
```

### JWT HS/RS confusion
```
# If server validates HS256 with whatever key you name, sign with the
# RSA public key (PEM) as the HMAC secret.
jwt_tool <token> -S hs256 -k pubkey.pem
```

### Invalidation Test
```
# 1. Login → grab cookie C1
# 2. Logout
# 3. curl with C1 → if 200, invalidation is broken
# 4. Change password with C2 → retry C1 → if 200, sibling-session bug
```

### Predictability Harvest
```bash
# Collect 500 tokens, feed to Burp Sequencer or ent(1)
for i in {1..500}; do
  curl -s -c- https://app.example.com/ | awk '/SESSIONID/{print $7}'
done | tee tokens.txt
ent tokens.txt          # entropy in bits/byte
```

## Defense-Bypass Pairs

| Defense | Bypass Technique | Real Example |
|---------|-----------------|--------------|
| `HttpOnly` cookie flag | Cookie smuggling via RFC2965 quoted-string parser desync on Jetty/Undertow — attacker opens a quote in a non-HttpOnly cookie, server concatenates HttpOnly cookie value into the quoted string, app reflects it | Cookie Bugs research (CVE against Jetty/Undertow), multiple CVEs |
| Double Submit Cookie CSRF | Cookie tossing from sibling subdomain sets attacker-controlled `_xsrf` cookie on parent domain, matching attacker's `X-XSRFToken` header | Cookie Tossing to RCE on Google Cloud JupyterLab, $3,134 |
| `__Host-`/`__Secure-` prefix | Cannot be tossed or overridden from subdomains — this is the actual defense; targets without prefixes are vulnerable | Cookie Bugs research confirmed prefixed cookies survive empty-name and tossing attacks |
| Device trust / "remember me" cookie | Swap MFA mode parameter from `phone` to `email` or `none` while device-trust cookie satisfies the second factor silently | Grammarly MFA bypass, $2,500 |
| Session-bound CSRF token | Web cache deception caches authenticated page (with CSRF token) at `/account/profile.css`; attacker reads cached token | Expedia cache deception to ATO, $750 |
| OAuth provider disconnect (revoke federation) | Existing session not invalidated on disconnect; attacker re-links from still-valid session | Shopify OAuth disconnect bypass, $1,600 |
| Registration CAPTCHA / rate limit | Use 3rd-party captcha-solving services (2captcha, anti-captcha) + catchall email for mass account creation as a signing oracle | VirusTotal session brute-force via registration oracle, $50,000 |
| Conditional header validation (Referer/Origin gate) | Set `Referer: http://127.0.0.1` to hit the permissive branch that skips secondary auth headers | VirusTotal ATO — secondary auth headers skipped when Referer looked internal, $50,000 |
| Password change invalidates current session | Sibling sessions (other browsers, mobile, CLI) not revoked; refresh tokens still mint new access tokens | Multiple programs — the invalidation matrix almost always has gaps |
| SameSite=Lax on session cookie | Top-level GET navigation still sends cookie; CSRF on any GET-with-side-effect endpoint, or method downgrade POST-to-GET on destructive endpoints | Google Creators CSRF account deletion via GET, $10,000 |

## Chain Patterns

| Base Finding | Chain With | Combined Impact | Example |
|--------------|-----------|----------------|---------|
| Subdomain XSS (low on blog/forum) | Cookie tossing to parent domain + Double Submit Cookie CSRF | Full CSRF bypass on main app, escalates to RCE on code-exec surfaces | JupyterLab cookie toss chain, $3,134 |
| Self-XSS on multi-tenant platform | Cookie injection on shared parent domain | CSRF bypass for all tenants; code execution on Jupyter/notebook platforms | Google Cloud AI Hub cookie tossing to RCE |
| Predictable session structure (4-5 bytes entropy) | Registration as signing oracle + conditional header bypass | Mass account takeover at scale | VirusTotal session brute-force, $50,000 |
| `datr` cookie (device ID) leaked via OAuth `machine_id` | Batch API field laundering + trusted device recovery flow | Full ATO bypassing password and 2FA via device impersonation | Facebook datr cookie theft, $24,000 |
| XSS on SSO-trusted subdomain | First-party OAuth token theft via redirect_uri trust | Cross-product ATO (Facebook + Instagram + Oculus from single XSS) | Oculus SSO token theft, $12,000 |
| Login CSRF (force attacker session) | postMessage token leak with `targetOrigin: *` + SSO path traversal | Two-click ATO stealing FXAuth token across Facebook/Instagram | Meta FXAuth ATO chain, $30,000 |
| Over-privileged first-party token scope | DOM XSS in any Meta subdomain reading token | Token scope includes email/phone mutation — direct ATO | Meta unrestricted permissions ATO, $18,000 |
| Password reset cookie persists hours | Shared device / kiosk access | Silent ATO — reset-window cookie outlives the email link | Weblate reset cookie ATO |

## Cookie Confusion/Tossing Attacks

| Technique | How | Impact | Condition |
|-----------|-----|--------|-----------|
| Parent domain tossing | `document.cookie = "session=X; domain=.example.com"` from XSS on any subdomain | Overrides session cookie on main app; breaks Double Submit Cookie CSRF | App uses shared parent domain for subdomains |
| Empty-name cookie spoofing | `document.cookie = "=a=b"` — browser emits bare `a=b` in Cookie header, server parses as cookie `a` with value `b` | Override any cookie name without knowing original value | Any XSS or third-party JS on same origin |
| RFC2965 quoted-string smuggling | Set cookie with unclosed double-quote — Jetty/Undertow treat everything until next quote as one value, including subsequent HttpOnly cookies | Exfiltrate HttpOnly session tokens via reflected cookie values | Backend uses JVM webserver with legacy RFC2965 parser |
| Cookie ordering manipulation | Cookies sent path-length-descending + oldest-first; attacker sets same-named cookie at longer path to win precedence | Attacker's cookie value used by server over legitimate one | Attacker can set cookies via XSS or subdomain |
| Cookie bomb / overflow | Inject many large cookies until server rejects request with 400 (header too large) | DoS for specific user — every request fails until cookies cleared | Any cookie-setting primitive (XSS, CRLF, subdomain) |
| CRLF cookie injection for parser DoS | Inject malformed cookie value via CRLF in header-reflecting endpoint — downstream parser hangs | 504 Gateway Timeout DoS amplified across backend workers | Parameter reflected into Set-Cookie without sanitization; Periscope.tv $560 |

## Session Puzzling Patterns

| Pattern | Technique | Impact |
|---------|-----------|--------|
| Pre-2FA session accepted on post-2FA endpoints | Hit sensitive endpoint directly without passing through step-up interstitial | Bypass 2FA entirely; access settings, payments, key issuance |
| MFA mode client-controlled | Change `mfa_mode` from `sms` to `email`/`none`/null in login request body | Server accepts weaker or nonexistent factor; silent MFA bypass |
| Challenge flow token as auth-equivalent | Security challenge endpoint returns user PII/password when given only the challenge token, no session | Mass credential theft via challenge token replay (PayPal $15,300) |
| Reset cookie outlives email link | Password reset drops persistent cookie; email link consumed but cookie still gates reset endpoint | Shared-device ATO — next user completes the reset hours later |
| Federation session survives disconnect | OAuth provider disconnected but existing session not invalidated; attacker re-links from live session | Persistent backdoor surviving victim's remediation action (Shopify $1,600) |
| Batch API field laundering | Chain privileged API call (returns secret) with write API call (stores to attacker-readable location) via batch request field references | Exfiltrate session-equivalent values (device trust cookies) cross-origin (Facebook $24,000) |

## Bypass Techniques

**Cookie injection surfaces**
- Subdomain XSS writing `document.cookie = "SESSIONID=...; domain=.example.com"`
- Cache poisoning of a `Set-Cookie` response header
- Response splitting via CRLF in a header-reflecting endpoint
- CORS misconfig + `credentials: true` letting attacker origin script against cookie
- Empty-name cookie spoofing: `document.cookie = "=name=value"` emits bare token parseable as any cookie name

**Desync tricks**
- Token validated by frontend proxy but not fully by backend (strip quoted parts, trailing garbage)
- JWT concatenation/padding tolerance (attacker appends bytes ignored by the verifier)
- `Authorization` header AND cookie sent — server picks the weaker one
- RFC2965 quoted-string smuggling on Jetty/Undertow: unclosed dquote collapses subsequent cookies into one value

**Step-up downgrade**
- Call sensitive endpoint directly without passing through the step-up interstitial
- Replay a step-up token across different sensitive actions
- Switch MFA mode parameter to a weaker or nonexistent factor in the login request

## Testing Methodology

1. **Enumerate carriers** - List every cookie, header, query param, and storage key that grants access
2. **Flag audit** - For each cookie: `Secure`, `HttpOnly`, `SameSite`, `Domain`, `Path`, `Max-Age`, `__Host-`/`__Secure-` prefix
3. **Fixation** - Capture pre-auth ID, authenticate, diff IDs. Same ID → fixation
4. **Invalidation matrix** - Build a matrix: {logout, password change, email change, 2FA change, admin revoke, refresh expiry} × {current session, sibling session, refresh token}. Every cell should kill the old credential
5. **JWT triage** - Decode (`jwt_tool`, `jwt.io`); try `alg:none`, HS↔RS confusion, weak-secret brute, `kid` injection, `jku` override
6. **Predictability** - Harvest ≥500 tokens, run Burp Sequencer or `ent`; look for timestamp/userID/monotonic patterns
7. **Step-up bypass** - Identify sensitive endpoints; try calling them with a pre-step-up token
8. **Cross-device** - Log in on browser A, revoke from browser B, confirm A is dead within seconds (not minutes, not on next refresh)
9. **Remember-me** - Separate token lifetime, regeneration on use, revocation path

## Chaining

- **Subdomain XSS → cookie fixation → ATO**: XSS on `blog.example.com` sets `SESSIONID` on `.example.com`, victim visits `app.example.com` and logs in, attacker reuses the ID
- **Weak JWT secret → admin forge → full control**: brute `jwt_secret` → mint `{role:admin}` token → hit admin API
- **Password change without sibling revoke → persistent ATO**: phish victim once, keep session alive indefinitely even after they rotate credentials
- **2FA step-up bypass → disable 2FA → lock-out victim**: reach `/settings/2fa/disable` with pre-step-up cookie, then change email, then reset password

## Validation

1. **Fixation**: pre-seeded ID authenticated as victim (request + response screenshots, two distinct browsers)
2. **Hijack**: token extracted via documented vector (XSS PoC, CSRF, header leak) and reused from a clean client
3. **Invalidation gap**: exact minute/second timing between "revoke action" and "old token still 200"
4. **Predictability**: entropy number + pattern description, or successful prediction of the next token from N observations
5. **JWT forgery**: show forged token, server response, and the decoded claim that granted privilege

## False Positives

- `SameSite=Lax` instead of `Strict` on a login cookie is often accepted and not payable alone
- Missing `HttpOnly` when there is no XSS vector and no `document.cookie` read
- "Remember me" cookie valid for 30 days is by design for most apps
- Session not rotating on re-login within 1 second (load balancer affinity artifacts)
- Triager pushback: "This is expected SSO behavior" — preempt by showing the revocation action the user explicitly took and its documented promise
- Triager pushback: "Requires XSS" — if so, chain the XSS; don't submit session-theft-via-hypothetical-XSS alone

## Impact

- Full account takeover without credentials (fixation, prediction, forgery)
- Persistent unauthorized access after password/email/2FA reset
- Privilege escalation via forged JWT claims
- Cross-tenant data access via leaked or reusable impersonation tokens
- Compliance violations (SOC2, PCI-DSS require reliable session termination)

## Pro Tips

1. Always test logout + password change + 2FA rotate as three separate invalidation events — they are distinct bugs
2. Compare mobile API and web API token formats; often mobile uses long-lived JWT while web uses short opaque — revocation rarely crosses them
3. Decode every JWT before assuming it is opaque; roughly 30% of "opaque" tokens are JWTs
4. Check WebSocket upgrade: does it revalidate the session on reconnect or trust the initial handshake forever?
5. Race-condition logout: fire one request during logout processing — sometimes it completes on a partially-revoked session
6. Write "fix-to-report" link: tie each finding to the exact code/config change so the triager cannot argue intent
7. For JWT: try `alg:none`, HS/RS confusion, weak secret (`hashcat -m 16500 token.jwt wordlist.txt`), and `kid`/`jku` before anything exotic
8. Always check the refresh-token endpoint separately: many apps invalidate access tokens on logout but leave refresh tokens usable
9. SSO federation tokens (SAML assertion, OIDC ID token) are frequently long-lived and not revoked even when the local session is killed — pivot through SSO if the IdP session survives
10. Watch for "impersonate user" support-admin flows: the resulting session may outlive the support agent's own session revocation
11. Decode and diff session cookies across two test accounts — stable bytes are constants, variable bytes identify the user; if variable bytes are < 8, brute-force is feasible (VirusTotal $50k pattern)
12. Any flow that signs content with the session key (registration, password reset, invite links) is a potential signing oracle — if the signed format matches the session format, you can mint arbitrary sessions
13. Test every "transitional auth" endpoint (challenge, step-up, recovery, account-merge) without session cookies — token-alone acceptance is the highest-paying ATO class (PayPal $15,300)
14. On shared-parent-domain platforms, never dismiss self-XSS — it is a cookie-tossing primitive that breaks Double Submit Cookie CSRF for all sibling tenants
15. After finding an OAuth disconnect bug, test the persistence loop: can the attacker re-link their OAuth from the still-valid session, restoring the backdoor? Victim remediation that can be undone from the live session is not remediation
16. For every auth state change, diff cookies before and after — same session ID across a privilege boundary means fixation, even on non-login events like entering a shared-link password or completing a CAPTCHA
17. When testing device trust, check whether the trust cookie (`datr`, `deviceId`, `trusted_device`) appears in any API response — `machine_id` in OAuth token exchange leaked Facebook's device trust cookie ($24,000)
18. On multi-tenant subdomain platforms, enumerate all `*.parent.com` subdomains and test cookie tossing — `__Host-` prefix is the only reliable defense; absence of prefix means any subdomain XSS escalates to session theft
19. When the obvious token is hardened, audit every OTHER token signed by the same key -- Flask/Rails/Django/Laravel use one signing key for session, CSRF, password reset, and email confirm tokens ($1.5K)
20. Build a post-logout side-channel matrix: Service Workers, Web Push subscriptions, Background Sync, open WebSockets, IndexedDB/localStorage credentials -- logout often kills only the cookie ($560)
21. After SSO/SAML/OAuth logout, test whether re-clicking the login button silently re-authenticates -- SSO logout often kills only the SP session, not the IdP session
22. Test credential persistence across app lifecycle: does uninstall clear tokens? Does OS update? Does storage migration? Desktop/mobile apps frequently persist sessions across reinstalls

## Session Lifecycle Audit Methodology

Corpus analysis of 22 "Insufficient Session Expiration" reports reveals that session invalidation gaps are the most consistently payable session finding class. The pattern: programs almost always have at least one gap in the invalidation matrix.

### The Invalidation Matrix

Build this matrix for every target. Each cell = one test. A single surviving cell is a finding.

| Trigger Event | Current Session | Sibling Sessions (other browser/device) | Refresh Tokens | Remember-Me / Device-Trust Tokens | API Keys / PATs |
|---------------|----------------|----------------------------------------|----------------|----------------------------------|-----------------|
| Logout | Kill | Kill | Kill | Kill (or scope-reduce) | No change (by design) |
| Password change | Kill | **Kill** | **Kill** | **Kill** | Depends on program |
| Password reset (email link) | Kill | **Kill** | **Kill** | **Kill** | Depends on program |
| Email change | Kill or re-auth | **Kill** | **Kill** | No change | No change |
| 2FA enrollment | Re-auth gate | **Kill pre-2FA sessions** | **Kill** | **Kill** | No change |
| 2FA removal | Re-auth gate | **Kill** | **Kill** | **Kill** | No change |
| Role/permission change | Re-auth or kill | **Kill** | **Kill** | No change | No change |
| Account deactivation | Kill | **Kill** | **Kill** | **Kill** | **Revoke** |
| Admin "revoke all sessions" | Kill | **Kill** | **Kill** | **Kill** | Depends |

**Bold cells** are where gaps most commonly appear. Test each one: capture token T1 before the trigger, execute the trigger via a second session T2, replay T1 -- if T1 still returns 200, file it.

### Post-Logout Side-Channel Persistence

Logout often kills only the session cookie. These channels survive and maintain authenticated state:

| Channel | Test Method | Impact If Survives |
|---------|-------------|-------------------|
| Service Worker registrations | DevTools > Application > Service Workers -- check if registered after logout | SW intercepts requests, can inject content, survives page refresh |
| Web Push subscriptions | Check `PushSubscription` in SW scope post-logout | Attacker receives push notifications with PII |
| Background Sync registrations | DevTools > Application > Background Sync | Queued operations execute after logout completes |
| Open WebSocket connections | Network tab -- check if WS stays connected after logout | Real-time data continues streaming to logged-out client |
| IndexedDB / localStorage credentials | Application > Storage -- check for tokens/keys post-logout | Re-authentication possible from stored credentials without login |
| Active `EventSource` (SSE) streams | Network tab -- check if SSE connection persists | Server-sent events continue delivering data post-logout |

### Multi-Interface Parity Testing

Any operation exposed through multiple interfaces (web UI, mobile API, CLI, admin panel, GraphQL, REST) must behave identically for security operations. Test:

1. Revoke session via web UI -- does mobile API session die?
2. Change password via mobile -- do web sessions invalidate?
3. "Log out all devices" via CLI -- do web + mobile sessions die?
4. Admin "force logout user" -- do ALL interfaces terminate?

The gap is almost always mobile-to-web or CLI-to-web: the revocation event fires on the interface that triggered it but does not fan out to other token types.

### Write-Access Proof for Invalidation Gaps

When demonstrating session persistence after a security event, do NOT just show a 200 response on a read endpoint. Triagers dismiss read-only persistence as "cached" or "low impact." Instead:

1. After the trigger event, use the old session to **write** (change display name, add a shipping address, post a comment)
2. Verify the write persisted (check from a different session)
3. This proves the session retains full authenticated authority, not just a cached read

## Common Triager Pushback and Counters

| Pushback | Counter |
|----------|---------|
| "Session timeout is documented" | Show invalidation of an explicit user action (logout), not idle timeout |
| "Requires prior XSS" | Chain the XSS or report it as part of an ATO chain, not standalone |
| "SameSite=Lax is fine" | Show CSRF impact on a top-level navigation-triggered POST or GET-with-effect |
| "JWT is only used internally" | Prove it crosses a trust boundary (mobile → web, service → user) |
| "Refresh token rotation is coming soon" | Demonstrate current-day abuse; future fix does not erase present risk |

## Summary

Sessions are the real authentication layer. A login is only as strong as the worst cell in the {create, validate, revoke} × {current, sibling, refresh, remember-me} × {web, mobile, CLI} matrix. Hunt the revocation gaps — they pay more than clever crypto attacks and triagers rarely dispute them.
