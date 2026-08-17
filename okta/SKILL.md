---
name: okta
description: Okta integration attack surface: SAML signature wrap, OIDC scope abuse, tenant subdomain confusion
depends_on: []
---

# Okta

Okta is enterprise IdP. Bugs are in the SP integration: SAML signature validation gaps, OIDC scope expansion, tenant subdomain confusion (`{tenant}.okta.com`).

## Common Bug Classes

- SAML XML signature wrapping attacks
- OIDC `scope=openid offline_access` abuse for long-lived tokens
- Tenant confusion: app accepts `tokens` from any okta.com tenant
- ACS URL allowlist gaps on SAML
- IDP-trust-asymmetry: Okta allows arbitrary email domains, target trusts email-verified claim blindly
- RelayState open redirect chaining into OAuth token theft
- Authentication-mode toggle mutations at lower permission tiers than required

## SSO / OAuth Chain Attacks (234 reports, $4.7M corpus)

### postMessage targetOrigin Bypass
For every `window.postMessage(data, targetOrigin)` call in the SSO flow:
1. Check if `targetOrigin` is hardcoded to `*` or sourced from attacker-controlled input
2. Test whether the receiving handler validates `event.origin` strictly
3. If the SSO token or authorization code is in the `data` payload, this is a Critical token theft vector
4. Enumerate every window/iframe that participates in the SSO handshake — each is a trust boundary

### Cross-Platform SSO Chain Analysis
When two applications share authentication via Okta:
1. Map every parameter in SSO redirect URLs between the apps
2. Identify which tokens are reusable cross-app (session, refresh, access)
3. Test whether revoking access on one app invalidates the shared token on the other
4. Check for token confusion: can a token issued for App A be replayed against App B's API

### IDP Email Verification Asymmetry
For every SSO option the target offers via Okta:
1. Identify Okta's email verification model for the configured IDP
2. If the IDP allows arbitrary email claims without verification, register an account with the victim's email
3. Initiate SSO — the target may trust the unverified email claim from Okta
4. Test with custom SAML assertions where `NameID` is modified post-signature

## State-Machine Adversarial Testing

For every multi-step Okta-integrated flow (signup, email change, MFA enrollment, password reset):
1. Complete all steps normally, capturing each request
2. Replay step N before step N-1 completes (out-of-order execution)
3. Skip the critical auth-gate step entirely — try jumping directly to the post-auth URL
4. Initiate the flow, then change the email/identity mid-flow before confirmation
5. Test whether the confirmation token is bound to the session that requested it

## Permission-Matrix Differential Testing

For products with Okta-based granular RBAC:
1. Build a 2D matrix: roles (rows) x endpoints/mutations (columns)
2. Document the intended permissions from the product's documentation
3. Test every cell systematically — especially authentication-mode toggles (`enforceSaml`, `convertUsersFrom`)
4. These toggle mutations should require the highest-tier permission; if accessible at any lower tier, that is a privilege escalation

## SAML-Specific Attack Patterns

### Signature Wrapping Variants
1. Move the signed `Assertion` into a sibling position, inject a new unsigned `Assertion` as the one the SP processes
2. Test with `Subject` NameID modified but `Signature` reference pointing to the original
3. Try removing the `Signature` element entirely — some SPs fall through to unsigned processing
4. Test XML comment injection inside NameID: `admin<!---->.evil@test.com`

### ACS URL Manipulation
1. Enumerate all `AssertionConsumerServiceURL` values the SP accepts
2. Test with an ACS URL pointing to an attacker-controlled domain
3. Check if the SP validates ACS URL against a registered allowlist or accepts any URL
4. Try path traversal within the ACS URL: `/saml/acs/../other-endpoint`

## OIDC-Specific Attack Patterns

### Scope and Token Abuse
1. Request `offline_access` scope — check if long-lived refresh tokens are issued
2. Test scope escalation: request scopes not in the app's configured set
3. Check if `id_token` claims include sensitive attributes not needed for the requested scopes
4. Test token exchange: use a token from one Okta application against another application's API

### Discovery Endpoint Enumeration
1. Fetch `/.well-known/openid-configuration` — map all supported endpoints
2. Test `userinfo_endpoint` with tokens from different tenants
3. Check `jwks_uri` for key rotation gaps (old keys still accepted)
4. Test `introspection_endpoint` and `revocation_endpoint` for missing auth

## Exotic Client Surfaces

For any target with Okta integration, enumerate ALL client surfaces:
1. Web admin panel, mobile apps, WeChat/LINE mini-programs, Slack integrations, CLI tools
2. Each client may have different token validation and session management
3. Test IDOR patterns on alternative clients — mobile APIs often lack the same authz checks
4. Check for client-specific OAuth flows that skip MFA or email verification

## Probe Targets

- Test SAML responses with modified Subject NameID
- Inspect OIDC discovery: `/.well-known/openid-configuration`
- Try logging in as user from different Okta tenant
- Test RelayState parameter for open redirect (chain with OAuth for token theft)
- Audit every postMessage handler in the SSO flow for origin validation
- Send SAML response with `Signature` removed — check if SP processes unsigned assertion
- Test every MFA bypass: skip the MFA step URL, replay a pre-MFA token post-enrollment
- Probe for Okta admin API exposure at `/api/v1/users`, `/api/v1/apps`
- Check if login subdomains (`login.target.com`) have weaker CSP than main app

## Integration OAuth Flow Exploitation

### OAuth Callback CSRF
For every Okta OAuth integration flow:
1. Find the entry point endpoint (`/auth/okta`, `/sso/login`, `/oauth/authorize`)
2. Test CSRF on the initiation step — if the first request lacks a `state` parameter or anti-CSRF token, an attacker can initiate an OAuth link to their own Okta account on the victim's session
3. Test the callback endpoint separately — even if the initiation is CSRF-protected, the callback may not validate `state`
4. This allows account linking attacks: attacker's Okta identity linked to victim's account

### Redirect URI Manipulation
1. Test if the redirect_uri accepts subdirectories: if `/callback` is registered, try `/callback/../other-page`
2. Test with URL-encoded characters in the redirect path
3. Test if the redirect_uri validation is substring-based (accepts `evil.com/callback.target.com`)
4. Test with different schemes: `http://` instead of `https://`

## Session Revocation and Linkage Gaps

### Post-Revocation Token Validity
For every linkage between a long-lived auth artifact (session, refresh token, API key) and Okta:
1. Disconnect the Okta SSO provider from the account
2. Test: does the existing session remain valid? (it should be invalidated)
3. Test: does the refresh token still work?
4. Test: can the disconnected Okta identity still access the API?
5. Each auth artifact that survives disconnection is a persistence vector — the attacker only needs to link once

## Post-Fix Re-Testing

Always re-test fixed Okta/SSO bugs:
1. After a fix ships, test the same flow with encoding variants (double-encode, Unicode, null bytes)
2. Check if the fix is client-side only (UI hides option) vs server-side enforced
3. Test sibling URLs — if `/saml/callback` is fixed, try `/saml/callback/`, `/SAML/callback`, `/saml/Callback`

## Cross-References

`oauth`, `oauth_oidc_attacks`, `saml`, `authentication_jwt`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
