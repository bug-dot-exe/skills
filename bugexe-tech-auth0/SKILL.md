---
name: auth0
description: Auth0 integration attack surface: callback URL trust, JWT audience validation, action injection
depends_on: []
---

# Auth0

Auth0 is identity-as-a-service. Bugs are typically in the integrating application: callback URL allowlist gaps, JWT `aud` not validated, custom Actions/Rules trusting user metadata.

## Common Bug Classes

- Callback URL allowlist using prefix match instead of exact match
- JWT `aud` claim not validated → token from different tenant accepted
- Custom Actions / Rules trusting `user.app_metadata` after user-controlled write
- Connection enum via `/u/login` parameter probing
- Open redirect via `state` or `returnTo` after callback

## JWT/IdP Trust Audit

The highest-bounty Auth0 pattern ($133K+). Audit the full JWT trust chain:

1. **Where does the JWT come from?** Can attackers mint tokens themselves (public sign-up, OAuth from any provider, direct to Firebase/Cognito/Auth0)?
2. **What claims does the relying party verify?** Test: `iss`, `aud`, `exp`, `sub`, `email_verified`
3. **What claims does it TRUST without verifying?** Custom claims (`role`, `permissions`, `org_id`) often flow from the IdP unvalidated
4. **Can you cross-tenant?** Take a valid JWT from tenant A and replay it against tenant B's API

**Critical test:** Forge a JWT with modified claims using the SAME signing algorithm but wrong `aud`. If the API accepts it, the audience validation is broken.

## IdP Trust Asymmetry

For every SSO option a target offers, identify the IdP's email verification model:

1. List all social connections (Google, GitHub, Apple) and enterprise connections (SAML, OIDC)
2. Check: does each IdP verify email before issuing tokens?
3. If an IdP allows arbitrary email without verification → sign up there, get a token with `victim@target.com`
4. Test if the relying party trusts the `email` claim without checking `email_verified`

**Cross-IdP replay:** Register the same email across multiple IdPs. If the RP links accounts by email alone (not by `sub` + `iss`), one IdP session can hijack another's account.

## Session Lifecycle After OAuth Revocation

Session persistence after IdP revocation is a common gap:

1. Log in via OAuth (Google, GitHub, etc.)
2. Revoke the app at the IdP (Google Security settings, GitHub authorized apps)
3. Test if the RP session survives — it usually does because the RP has its own session cookie
4. Check if the RP ever re-validates the OAuth token (most don't after initial exchange)
5. Report: session remains active indefinitely after OAuth revocation

## Policy Retroactivity Gaps

Auth0 policy changes frequently lack retroactive enforcement:

- **Password policy:** Change minimum length; do existing users get forced to update?
- **MFA enforcement:** Enable MFA requirement; do existing sessions survive?
- **Connection disable:** Disable a social connection; can existing tokens from that connection still authenticate?
- **Role revocation:** Remove a role from a user; do existing JWTs with the old role still work?

Test each by: set up state, change policy, verify the old state is invalidated.

## Callback URL Exploitation

Auth0 callback URL allowlists are the primary OAuth attack surface:

**Bypass techniques:**
```
# Prefix match bypass
Allowed: https://app.example.com/callback
Test:    https://app.example.com.attacker.com/callback

# Path traversal
Allowed: https://app.example.com/callback
Test:    https://app.example.com/callback/../../../attacker

# Subdomain wildcard abuse
Allowed: https://*.example.com/callback
Test:    https://attacker.example.com/callback

# Fragment/parameter injection
Allowed: https://app.example.com/callback
Test:    https://app.example.com/callback#redirect=https://attacker.com
```

**Open redirect chaining:** When the callback URL itself has an open redirect, chain:
1. OAuth flow redirects to `https://app.example.com/callback?code=...`
2. Callback page has `returnTo` parameter → `returnTo=https://attacker.com`
3. Token leaks via Referer header to attacker domain

## Connection String Injection

Auth0 connections that build connection strings (LDAP, database) are injection targets:

1. Check if login fields (username, password) flow into LDAP bind or database query
2. Test CRLF injection in non-HTTP contexts: `username\r\n` in LDAP binds
3. Test special characters in password fields that may break connection string parsing
4. For database connections: test SQL injection via authentication parameters

## API Response Over-Exposure

Auth0 social/connection flows often return excessive user data:

1. Test what user data is exposed during: friend/connection requests, profile lookups, invitation flows
2. Compare response fields for own-profile vs other-user-profile requests
3. Check if the `/userinfo` endpoint returns more claims than the frontend displays
4. Test Management API endpoints if the API key is leaked in client bundles

## Probe Targets

- Test callback URL with subdomain confusion: `https://mysite.com.attacker.com/callback`
- Forge JWT with wrong `aud` and verify rejection
- Probe `/u/login?connection=*` for backend connections
- Check `/.well-known/openid-configuration` for exposed endpoints
- Test `/authorize` with `prompt=none` for silent auth bypass
- Probe `/api/v2/` Management API with anon key
- Check `/passwordless/start` for rate limiting on magic links

## Cross-References

`oauth`, `oauth_oidc_attacks`, `open_redirect`, `authentication_jwt`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
- For JWT bypass: show the token is accepted AND grants unauthorized access, not just accepted
- For session persistence: demonstrate the session survives a policy change that should invalidate it
