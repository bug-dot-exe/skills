---
name: oauth
description: OAuth/OIDC security testing covering authorization code theft, PKCE bypass, token leakage, and state parameter abuse
depends_on: []
---

# OAuth/OIDC

Security testing for OAuth 2.0 and OpenID Connect implementations. Focus on authorization code theft via open redirect, CSRF on callback endpoints, token leakage in Referer headers, scope escalation, PKCE bypass, client_secret exposure, and state parameter validation.

## Attack Surface

**OAuth Flows**
- Authorization Code (with and without PKCE)
- Implicit (deprecated but still deployed)
- Client Credentials
- Device Authorization
- Refresh Token rotation and binding

**Endpoints**
- Authorization endpoint: `/authorize`, `/oauth/authorize`
- Token endpoint: `/oauth/token`, `/token`
- Callback/redirect URI: application-specific
- UserInfo endpoint: `/userinfo`
- JWKS endpoint: `/.well-known/jwks.json`
- Discovery: `/.well-known/openid-configuration`

**Client Registration**
- Dynamic client registration
- Pre-registered redirect URIs
- Public vs confidential clients
- Client authentication methods: client_secret_basic, client_secret_post, private_key_jwt

**Token Types**
- Access tokens (JWT or opaque)
- Refresh tokens
- ID tokens (OIDC)
- Authorization codes

## High-Value Targets

- Authorization endpoint with redirect_uri parameter
- Callback endpoints accepting authorization codes
- Token exchange/refresh endpoints
- Social login integrations (Google, GitHub, Facebook, Apple)
- Mobile app deep link handlers for OAuth callbacks
- Admin OAuth applications management (create/edit clients)
- JWKS and discovery endpoints for key confusion attacks

## Reconnaissance

**Discovery**
```
GET /.well-known/openid-configuration
GET /.well-known/oauth-authorization-server
GET /.well-known/jwks.json
```
Extract: authorization_endpoint, token_endpoint, supported grant types, response types, scopes, PKCE support, token endpoint auth methods.

**Client Enumeration**
- Inspect login pages for OAuth provider links and client_id values
- Check mobile app source/network traffic for client_id and redirect_uri
- Search JavaScript bundles for OAuth configuration objects
- Browser developer tools during login flow: capture full authorization URL

**Redirect URI Mapping**
- Document all registered redirect URIs per client
- Test variations: subdomain, path, query parameters, fragments

## Key Vulnerabilities

### Authorization Code Theft via Open Redirect

**Redirect URI Manipulation**
```
/authorize?client_id=APP&redirect_uri=https://attacker.com&response_type=code&scope=openid
/authorize?client_id=APP&redirect_uri=https://legit.com/../../../attacker.com&response_type=code
/authorize?client_id=APP&redirect_uri=https://legit.com%40attacker.com&response_type=code
/authorize?client_id=APP&redirect_uri=https://legit.com/.attacker.com&response_type=code
```

**Subdomain Matching Bypass**
```
redirect_uri=https://evil.legit.com/callback     # If wildcard subdomain matching
redirect_uri=https://legit.com.attacker.com       # Suffix matching flaw
redirect_uri=https://attacker.com#@legit.com      # Fragment/userinfo confusion
```

**Path Traversal on Redirect**
```
redirect_uri=https://legit.com/callback/../open-redirect?url=https://attacker.com
```
Authorization code appended to an open redirect on the legitimate domain forwards to attacker.

**Implicit Flow Token Theft**
- Fragment-based token delivery: `#access_token=...` leaked via Referer, `window.opener`, or `postMessage`
- Page with third-party scripts on redirect URI can read fragment

### CSRF on Callback

**Missing State Parameter**
- If `state` not sent or not validated: attacker initiates OAuth flow, victim completes it
- Attacker's account linked to victim's session (login CSRF)
- Or attacker's code exchanged in victim's session (account linking CSRF)

**Predictable State**
- Static state values, sequential values, timestamps
- State bound to session but session is attacker-controlled (session fixation + OAuth CSRF)

**Nonce Bypass (OIDC)**
- Missing `nonce` in ID token claims
- Nonce validated in frontend JavaScript only (bypassable)
- Nonce not bound to session/state

### Token Leakage

**Referer Header**
- Access token in URL fragment or query parameter leaked to third-party resources
- Callback page loads external images, scripts, or analytics that receive Referer
- `Referrer-Policy` header not set or set to `unsafe-url`

**Browser History**
- Authorization codes in URL persist in browser history
- Tokens in query parameters cached in proxy logs, server logs

**PostMessage**
- Silent authentication via iframe + postMessage for SPAs
- Missing origin validation on message receiver: any origin can read the token
- `window.opener` access: popup-based OAuth flow leaks tokens to opener

**Server Logs**
- Tokens in query parameters logged by web servers, WAFs, CDNs, load balancers
- Refresh tokens in POST body logged by debugging middleware

### Scope Escalation

**Requesting Elevated Scopes**
```
/authorize?client_id=APP&scope=openid+profile+email+admin+write
```
- Authorization server may grant scopes not approved for the client
- User consent screen may not clearly display dangerous scopes
- Incremental authorization: request minimal scopes first, then upgrade

**Scope Downgrade Attack**
- Token issued with broader scope than user authorized
- Missing per-operation scope enforcement at resource server
- Scope inheritance: refresh token inherits original scope even after user revokes

### PKCE Bypass

**Missing PKCE Enforcement**
```
# If server doesn't require PKCE, omit code_verifier at token exchange
POST /token
  code=AUTH_CODE&grant_type=authorization_code&redirect_uri=...
  # No code_verifier - if accepted, PKCE is optional
```

**Downgrade from S256 to plain**
```
code_challenge_method=plain
code_challenge=KNOWN_VALUE
# Then use code_verifier=KNOWN_VALUE at token exchange
```

**Code Interception**
- Without PKCE: intercepted authorization code usable by any party
- Mobile apps: custom URL schemes interceptable by malicious apps
- Universal links / App Links claiming the same redirect URI

### Client Secret Exposure

**Exposure Vectors**
- Hardcoded in mobile app source (decompile APK/IPA)
- JavaScript bundles for SPAs (public client using confidential client flow)
- Git repositories, CI/CD configs, environment variable dumps
- API documentation examples with real credentials

**Impact**
- Impersonate the application to the authorization server
- Exchange intercepted authorization codes without PKCE
- Request tokens with any scope approved for the client
- Access token introspection and revocation endpoints

### State Parameter Bypass

**State Fixation**
- Attacker starts OAuth flow, captures state value and authorization URL
- Sends URL to victim; victim completes authentication
- Attacker uses the known state + victim's code (if state is not session-bound)

**State Tampering**
- State stored client-side (cookie/localStorage) without integrity protection
- State verified by string comparison without timing-safe comparison
- State accepted from query parameter when it should only come from session

### Token Confusion

**ID Token as Access Token**
- Using OIDC ID token to authenticate to resource servers
- ID token not intended for authorization; missing audience/scope checks

**Access Token Injection**
- Attacker obtains access token for one client, injects into another client's flow
- Missing audience restriction on access tokens at resource server

**Issuer Confusion**
- Multiple identity providers trusted; attacker's IdP issues tokens accepted by resource server
- Missing issuer validation in token verification

## Bypass Techniques

- Redirect URI: URL encoding, double encoding, unicode normalization, case changes
- Path manipulation: `/../`, `./`, `//`, trailing dots, backslash (`\`)
- Port addition: `https://legit.com:443/callback` may not match `https://legit.com/callback`
- Fragment injection: `redirect_uri=https://legit.com/callback#attacker-fragment`
- Registration endpoint: create new client with attacker-controlled redirect URI
- Mixed flow: request `response_type=code+token` to get token in fragment (bypass PKCE)

## Testing Methodology

1. **Discovery** - Fetch OIDC configuration, enumerate supported flows, scopes, auth methods
2. **Redirect URI validation** - Test all manipulation techniques against authorization endpoint
3. **State/nonce validation** - Omit state, reuse state, use predictable state, cross-session state
4. **PKCE enforcement** - Omit code_verifier, downgrade to plain, test with wrong verifier
5. **Token leakage** - Check Referer policy, third-party resources on callback page, postMessage handlers
6. **Scope testing** - Request elevated scopes, test enforcement at resource server per-endpoint
7. **Client secret audit** - Check mobile apps, JavaScript bundles, public repositories
8. **Token validation** - Test audience, issuer, expiration, algorithm enforcement at resource server

## Validation

1. Authorization code theft: code successfully intercepted via redirect URI manipulation or open redirect chain
2. CSRF on callback: attacker-initiated OAuth flow completed in victim's session (account linked or attacker logged in as victim)
3. Token leakage: access token or authorization code captured from Referer header, logs, or postMessage
4. Scope escalation: token with elevated scope used to access restricted resources
5. PKCE bypass: authorization code exchanged without valid code_verifier
6. State bypass: cross-session or replayed OAuth flow accepted by the application

## False Positives

- Redirect URI rejected by authorization server for all variations (strict exact match)
- State parameter validated and session-bound with timing-safe comparison
- PKCE enforced server-side with S256 only (no plain downgrade)
- Token leakage mitigated by strict Referrer-Policy and no third-party resources on callback page

## Impact

- Account takeover via authorization code theft or token interception
- Login CSRF leading to attacker account access on victim's session
- Scope escalation enabling unauthorized data access or actions
- Client impersonation via exposed client_secret
- Token replay enabling persistent unauthorized access

## Corpus-Derived Attack Patterns

### postMessage targetOrigin Bypass (auth code theft)
For every `window.postMessage(data, targetOrigin)` call in OAuth-adjacent code: verify targetOrigin is a hardcoded trusted origin, not derived from `event.origin`, `document.referrer`, `location.hash`, or any attacker-influenceable source. If targetOrigin is `"*"` or dynamically sourced, authorization codes or tokens sent via postMessage can be intercepted by an attacker-controlled frame or opener window.

### Redirect URI Whitelist + Reflected Redirect Chaining
When a whitelisted `redirect_uri` path contains an open redirect or reflected redirect parameter (e.g., `/callback?next=`), chain the two: the authorization server allows the redirect because the domain matches, then the open redirect on the whitelisted path forwards the auth code to attacker infrastructure. Enumerate every parameter on the callback page that can influence navigation.

### OAuth Scope Over-Permission via Capability Enumeration
Audit OAuth scopes by exhaustively enumerating their API capabilities, not by reading the consent screen. For providers with many scopes, request each scope individually and call every API endpoint to map the actual permission surface. Scopes that sound narrow (e.g., "print") may implicitly grant read/write access to underlying storage or infrastructure services.

### Cross-Platform SSO Token Chain Analysis
When two applications share authentication (e.g., parent-app and subsidiary-app), analyze: (1) every parameter in SSO redirect URLs that can be manipulated to redirect tokens cross-origin, (2) whether a token minted for app-A can be presented to app-B's resource server, (3) whether the SSO binding flow can be initiated by an attacker and completed by a victim (login CSRF across platforms).

### Inter-Property Auth-Token Graph Mapping
For multi-property platforms, map the inter-property token exchange graph first. Every place where one property trusts a token from another property is a potential escalation path. Enumerate every `client_id` visible across all properties, request each with different scopes, and test cross-property token acceptance.

### Transitional Auth Flow Token Leakage
Every transitional auth flow (forgot-password, step-up MFA, account merge, social-login binding, suspicious-login challenge, recovery) may issue intermediate tokens or codes. Intercept these flows in proxy and test whether the intermediate token grants access beyond its intended scope, or leaks via Referer to third-party resources loaded during the flow.

### Multi-Step Flow Race: Authority Mutation Between Issuance and Consumption
Find every multi-step flow whose authority depends on a mutable value (email, owner_id, scope) that can be changed between issuance and consumption. Race the mutation against the token exchange: start OAuth flow as user-A, change email to victim mid-flow, complete the flow. If the token binds to the original identity but the session binds to the new identity, authorization boundaries break.

### Delimiter-Separated Token Field Manipulation
When a token is Base64-encoded and decodes to a delimiter-separated string, treat each field as parser-attackable. Test boundary-shifting by inserting extra delimiters, truncating fields, or swapping field order. Tokens that embed user identity as pipe/colon/comma-separated values may allow identity spoofing if the parser splits inconsistently.

### Sharable Link Capability Token Leakage via Referer
For any product with "anyone with the link" semantics: map the URL structure to identify which segment is the capability token. If the capability URL loads any external resource (analytics, images, CDN scripts), the token leaks via the Referer header. Test with `Referrer-Policy` absent, set to `unsafe-url`, or overridable by meta tags.

## Pro Tips

1. Always capture the full OAuth flow in a proxy; small parameter differences have large security impact
2. Test redirect URI validation exhaustively: servers often validate scheme+host but not path
3. Mobile OAuth is higher risk: custom URL schemes are interceptable, universal links have race conditions
4. Check if the server downgrades gracefully: removing PKCE, state, or nonce should cause a hard failure
5. Inspect the consent screen: does it accurately represent requested scopes?
6. Test token binding: can a token issued for client A be used at client B's resource server?
7. Check refresh token rotation: is the old refresh token immediately invalidated?
8. Look for silent auth flows (iframe-based) that skip user consent
9. Decode and diff signed cookies/tokens across multiple test accounts: stable bytes reveal constants/structure, variable bytes reveal the identity field to target
10. For every OAuth integration, verify the outgoing authorization URL includes an unguessable session-bound `state` parameter; test omission, reuse, and cross-session replay

## Summary

OAuth security depends on strict redirect URI validation, state/nonce binding, PKCE enforcement, and proper token audience restriction. Each parameter omission or relaxation opens a distinct attack path from code theft to full account takeover.
