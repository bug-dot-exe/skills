---
name: csrf
description: CSRF testing covering token bypass, SameSite cookies, CORS misconfigurations, and state-changing request abuse
depends_on: []
---

# CSRF

Cross-site request forgery abuses ambient authority (cookies, HTTP auth) across origins. Do not rely on CORS alone; enforce non-replayable tokens and strict origin checks for every state change.

## Attack Surface

**Session Types**
- Web apps with cookie-based sessions and HTTP auth
- JSON/REST, GraphQL (GET/persisted queries), file upload endpoints

**Authentication Flows**
- Login/logout, password/email change, MFA toggles

**OAuth/OIDC**
- Authorize, token, logout, disconnect/connect endpoints

## High-Value Targets

- Credentials and profile changes (email/password/phone)
- Payment and money movement, subscription/plan changes
- API key/secret generation, PAT rotation, SSH keys
- 2FA/TOTP enable/disable; backup codes; device trust
- OAuth connect/disconnect; logout; account deletion
- Admin/staff actions and impersonation flows
- File uploads/deletes; access control changes

## Discovery Signals

| Signal | Where to Find | Why Vulnerable |
|---|---|---|
| Cookie without `SameSite` attribute | Response headers | Browser defaults to `Lax` but 2-minute exception window exists |
| `SameSite=None; Secure` cookie | Response headers | Explicitly sent cross-site — CSRF possible if no token |
| State-changing GET endpoint | Request/response analysis | GET with side effects = CSRF via img/link tag, no user interaction |
| Missing `Origin`/`Referer` validation on POST | Request analysis | Forged POST accepted without origin check |
| Anti-CSRF token in cookie only (double submit) | Cookie/form analysis | Cookie-based tokens forgeable via subdomain/CRLF injection |
| JSON API accepting `application/x-www-form-urlencoded` | Content-type test | Simple request bypasses CORS preflight |
| GraphQL mutations via GET | API test | GET-based mutations = image tag CSRF |
| `X-HTTP-Method-Override` accepted | Header test | POST with override to DELETE/PUT bypasses method checks |
| WebSocket without Origin check | WebSocket handshake | Cross-site WebSocket hijacking possible |
| File upload without token | Upload endpoint | Multipart/form-data POST doesn't need preflight |

## Reconnaissance

### Session and Cookies

- Inspect cookies: HttpOnly, Secure, SameSite (Strict/Lax/None)
- Lax allows cookies on top-level cross-site GET; None requires Secure
- Determine if Authorization headers or bearer tokens are used (generally not CSRF-prone) versus cookies (CSRF-prone)

### Token and Header Checks

- Locate anti-CSRF tokens (hidden inputs, meta tags, custom headers)
- Test removal, reuse across requests, reuse across sessions, binding to method/path
- Verify server checks Origin and/or Referer on state changes
- Test null/missing and cross-origin values

### Method and Content-Types

- Confirm whether GET, HEAD, or OPTIONS perform state changes
- Try simple content-types to avoid preflight: `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`
- Probe parsers that auto-coerce `text/plain` or form-encoded bodies into JSON

### CORS Profile

- Identify `Access-Control-Allow-Origin` and `-Credentials`
- Overly permissive CORS is not a CSRF fix and can turn CSRF into data exfiltration
- Test per-endpoint CORS differences; preflight vs simple request behavior can diverge

## Key Vulnerabilities

### Navigation CSRF

- Auto-submitting form to target origin; works when cookies are sent and no token/origin checks are enforced
- Top-level GET navigation can trigger state if server misuses GET or links actions to GET callbacks

### Simple Content-Type CSRF

- `application/x-www-form-urlencoded` and `multipart/form-data` POSTs do not require preflight
- `text/plain` form bodies can slip through validators and be parsed server-side

### JSON CSRF

- If server parses JSON from `text/plain` or form-encoded bodies, craft parameters to reconstruct JSON
- Some frameworks accept JSON keys via form fields (e.g., `data[foo]=bar`) or treat duplicate keys leniently

### Login/Logout CSRF

- Force logout to clear CSRF tokens, then chain login CSRF to bind victim to attacker's account
- Login CSRF: submit attacker credentials to victim's browser; later actions occur under attacker's account

### OAuth/OIDC Flows

- Abuse authorize/logout endpoints reachable via GET or form POST without origin checks
- Exploit relaxed SameSite on top-level navigations
- Open redirects or loose redirect_uri validation can chain with CSRF to force unintended authorizations

### File and Action Endpoints

- File upload/delete often lack token checks; forge multipart requests to modify storage
- Admin actions exposed as simple POST links are frequently CSRFable

### GraphQL CSRF

- If queries/mutations are allowed via GET or persisted queries, exploit top-level navigation with encoded payloads
- Batched operations may hide mutations within a nominally safe request

### WebSocket CSRF

- Browsers send cookies on WebSocket handshake
- Enforce Origin checks server-side; without them, cross-site pages can open authenticated sockets and issue actions

## Bypass Techniques

### SameSite Bypass Techniques

| Scenario | Bypass Technique | Condition |
|---|---|---|
| `SameSite=Lax` on POST endpoint | Convert to GET if endpoint accepts both methods | Endpoint accepts GET for state changes |
| `SameSite=Lax` with recent cookie | 2-minute Lax+POST exception: cookies sent on top-level cross-site POST within 2 min of being set | Chrome, cookie just set (OAuth flow, login) |
| `SameSite=Lax` default | Use `window.open()` or `<a>` click for top-level navigation GET | GET state change exists |
| `SameSite=Strict` | Redirect from same-site page (e.g., open redirect on target domain) | Open redirect exists on target |
| `SameSite=None` | Direct cross-site POST, no SameSite protection at all | Must also have Secure flag |
| Cookie without SameSite on old browser | Treat as `None` — old browsers don't enforce default Lax | Target users on old browsers/IE |
| `SameSite=Lax` on popup | `window.open()` to target, then postMessage to coordinate | Popup counts as top-level navigation |

### Token Bypass Techniques

| Defense | Bypass Technique | Condition |
|---|---|---|
| CSRF token in body | Remove token parameter entirely — server may not check | Weak validation |
| CSRF token in custom header | Switch to simple content-type (form/multipart) to skip header requirement | Server accepts form-encoded without header |
| CSRF token in cookie (double submit) | Inject cookie via subdomain control, CRLF, or XSS | Subdomain control or injection vector |
| CSRF token from another session | Submit token from attacker's own session — if not bound to user | Token not session-bound |
| CSRF token with wrong value | Submit empty string, `null`, or `undefined` — weak regex may accept | Weak validation regex |
| Token validation skipped on specific methods | Try PUT, PATCH, DELETE — some frameworks only check POST | Per-method validation |
| Token validation skipped on specific content-types | Send as `text/plain` or `multipart/form-data` — different code path | Content-type routing |
| Token in meta tag or JS variable | Token exposed but not validated on all endpoints | Selective enforcement |
| Predictable token (timestamp-based, sequential) | Generate valid token without accessing target page | Weak PRNG |
| Token reusable across sessions | Use captured token from previous session | No session binding |

### Origin/Referer Obfuscation

- Sandbox/iframes can produce null Origin; some frameworks incorrectly accept null
- `about:blank`/`data:` URLs alter Referer
- Ensure server requires explicit Origin/Referer match

### Method Override

- Backends honoring `_method` or `X-HTTP-Method-Override` may allow destructive actions through a simple POST

### Content-Type Switching

- Switch between form, multipart, and `text/plain` to reach different code paths
- Use duplicate keys and array shapes to confuse parsers

### Header Manipulation

- Strip Referer via meta refresh or navigate from `about:blank`
- Test null Origin acceptance
- Leverage misconfigured CORS to add custom headers that servers mistakenly treat as CSRF tokens

## JSON CSRF Payload Crafting

```html
<!-- Method 1: text/plain body looks like JSON -->
<form method="POST" action="https://target/api/change-email" enctype="text/plain">
  <input name='{"email":"evil@attacker.com","ignore":"' value='"}'>
</form>
<!-- Sends: {"email":"evil@attacker.com","ignore":"="}  -->

<!-- Method 2: Flash-based (legacy but still works on some targets) -->
<!-- Use SWF to send arbitrary Content-Type -->

<!-- Method 3: Fetch API with no-cors mode (limited but can trigger side effects) -->
<script>
  fetch('https://target/api/action', {
    method: 'POST',
    mode: 'no-cors',
    headers: {'Content-Type': 'text/plain'},
    body: JSON.stringify({action: 'delete'})
  });
</script>

<!-- Method 4: Navigator.sendBeacon (fire-and-forget POST, bypasses page unload) -->
<script>
  navigator.sendBeacon('https://target/api/action',
    new Blob([JSON.stringify({action:'delete'})], {type:'text/plain'}));
</script>
```

## PoC Templates

| Scenario | Template |
|---|---|
| Simple form POST | `<form action="URL" method="POST"><input name="k" value="v"><script>document.forms[0].submit()</script></form>` |
| Auto-submitting multipart | `<form action="URL" method="POST" enctype="multipart/form-data"><input name="file" type="hidden" value="data"><script>document.forms[0].submit()</script></form>` |
| GET state change (img) | `<img src="https://target/api/action?param=value">` |
| GET state change (iframe) | `<iframe src="https://target/api/action?param=value" style="display:none">` |
| JSON via text/plain | See JSON CSRF Payload Crafting section above |
| Multiple actions (sequential) | `<iframe name="f1" src="https://target/step1"><script>setTimeout(()=>{document.getElementById('f2').src='https://target/step2'},2000)</script><iframe id="f2">` |

## Browser-Specific Behavior

| Browser | SameSite Default | 2-Min Lax+POST | Notable Behavior |
|---|---|---|---|
| Chrome 80+ | Lax | Yes (2 min) | Strictest enforcement, 2-min exception for top-level POST |
| Firefox 86+ | Lax | No | No 2-min exception — stricter than Chrome |
| Safari 15+ | Lax-like (own impl) | Own rules | ITP can override SameSite, partitioned cookies |
| Edge (Chromium) | Same as Chrome | Same as Chrome | Follows Chromium behavior |
| Mobile WebView | Varies | Varies | In-app browsers may not enforce SameSite |

## Special Contexts

### Mobile/SPA

- Deep links and embedded WebViews may auto-send cookies; trigger actions via crafted intents/links
- SPAs that rely solely on bearer tokens are less CSRF-prone, but hybrid apps mixing cookies and APIs can still be vulnerable

### Integrations

- Webhooks and back-office tools sometimes expose state-changing GETs intended for staff
- Confirm CSRF defenses there too

## Chaining Attacks

- CSRF + IDOR: force actions on other users' resources once references are known
- CSRF + Clickjacking: guide user interactions to bypass UI confirmations
- CSRF + OAuth mix-up: bind victim sessions to unintended clients
- CSRF + OAuth: force victim to connect attacker's OAuth app — attacker gets persistent API access
- CSRF + Login: force victim into attacker's account — victim enters sensitive data in attacker's session
- CSRF + XSS amplification: CSRF changes victim's profile to include stored XSS payload
- CSRF + Privilege escalation: CSRF forces admin to add attacker as admin

## Testing Methodology

1. **Inventory endpoints** - All state-changing endpoints including admin/staff
2. **Note request details** - Method, content-type, whether reachable via simple requests
3. **Assess session model** - Cookies with SameSite attrs, custom headers, tokens
4. **Check defenses** - Anti-CSRF tokens and Origin/Referer enforcement
5. **Attempt preflightless delivery** - Form POST, text/plain, multipart/form-data
6. **Test navigation** - Top-level GET navigation
7. **Cross-browser validation** - Behavior differs by SameSite and navigation context

## Validation

1. Demonstrate a cross-origin page that triggers a state change without user interaction beyond visiting
2. Show that removing the anti-CSRF control (token/header) is accepted, or that Origin/Referer are not verified
3. Prove behavior across at least two browsers or contexts (top-level nav vs XHR/fetch)
4. Provide before/after state evidence for the same account
5. If defenses exist, show the exact condition under which they are bypassed (content-type, method override, null Origin)

## False Positives

- Token verification present and required; Origin/Referer enforced consistently
- No cookies sent on cross-site requests (SameSite=Strict, no HTTP auth) and no state change via simple requests
- Only idempotent, non-sensitive operations affected

## Impact

- Account state changes (email/password/MFA), session hijacking via login CSRF
- Financial operations, administrative actions
- Durable authorization changes (role/permission flips, key rotations) and data loss

## Pro Tips

1. Prefer preflightless vectors (form-encoded, multipart, text/plain) and top-level GET if available
2. Test login/logout, OAuth connect/disconnect, and account linking first
3. Validate Origin/Referer behavior explicitly; do not assume frameworks enforce them
4. Toggle SameSite and observe differences across navigation vs XHR
5. For GraphQL, attempt GET queries or persisted queries that carry mutations
6. Always try method overrides and parser differentials
7. Combine with clickjacking when visual confirmations block CSRF
8. Always test with tokens removed entirely before trying bypass tricks — many implementations don't validate when the parameter is absent
9. Check the 2-minute Lax+POST window after OAuth login flows — the newly-set session cookie is vulnerable for 2 minutes in Chrome
10. Test multipart/form-data — it's a "simple" content-type that doesn't trigger CORS preflight but reaches different server code paths
11. Check `navigator.sendBeacon()` — it sends a POST that survives page navigation, useful for fire-and-forget CSRF
12. Cookie-authed media endpoints (`/avatar`, `/thumbnail`, `/profile-photo`) loaded cross-origin via `<img>`/`<video>` -- re-capture content via canvas/MediaRecorder for silent PII exfiltration ($50K)
13. Mobile deeplink CSRF: enumerate custom URL schemes in AndroidManifest/Info.plist -- `myapp://action?param=value` triggers state changes without CSRF tokens ($2.9K)
14. Self-XSS + shared parent domain + cookie-based CSRF = full CSRF bypass -- cookie-toss from XSS subdomain overrides double-submit CSRF tokens ($3.1K)
15. State-change-on-GET + rich feedback to a non-victim party = deanonymization primitive -- audit all GET endpoints with side effects ($50K)

## Summary

CSRF is eliminated only when state changes require a secret the attacker cannot supply and the server verifies the caller's origin. Tokens and Origin checks must hold across methods, content-types, and transports.
