# Triage & Validation (from claude-bug-bounty)

**One wrong answer = STOP. Kill it. Move on.**

> "N/A hurts your validity ratio. Only submit what passes all 7 questions."

Source: [claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) — integrated into bb-hunter.

---

## THE 7-QUESTION GATE

Ask IN ORDER. One wrong answer = STOP immediately.

### Q1: Can an attacker use this RIGHT NOW, step by step?

```
1. Setup:   I need [own account / another user's ID / no account]
2. Request: [exact HTTP method, URL, headers, body — copy-paste ready]
3. Result:  I can [read / modify / delete] [exact data shown in response]
4. Impact:  The real-world consequence is [account takeover / PII read / money stolen]
5. Cost:    Time: [X minutes], Capital: [$0 / $X subscription required]
```

**If you CANNOT write step 2 as a real HTTP request → KILL IT.**

### Q2: Is the impact on the program's accepted impact list?

Check program page: "Vulnerability Types" or "Out of Scope."
**If your bug maps to a listed exclusion → KILL IT.**

### Q3: Is the root cause in an in-scope asset?

- Vulnerable domain on in-scope list
- Production asset (not staging unless in scope)
- Not third-party (Stripe, Salesforce, Google Auth)
**If out-of-scope → KILL IT.**

### Q4: Does it require privileged access that an attacker can't realistically get?

- "Admin can do X" = **KILL IT** (99% of programs)
- "Non-admin can do X that only admin should do" = valid

### Q5: Is this already known or accepted behavior?

Search: disclosed reports, GitHub issues, changelog, API docs.
**If acknowledged/design decision → KILL IT.**

### Q6: Can you prove impact beyond "technically possible"?

- XSS → cookie theft or session hijack, not just `alert(1)`
- SSRF → internal endpoint returns data, not just DNS ping
- SQLi → actual data exfil, not just error message
- IDOR → actual other-user's data, not just 200 status
**If only "technically possible" → DOWNGRADE severity.**

### Q7: Is this a known-invalid bug class?

Check NEVER SUBMIT list. If on list without chain → **KILL IT.**

---

## 4 PRE-SUBMISSION GATES

ALL 4 must PASS.

### Gate 0: Reality Check (30 seconds)
```
[ ] Bug is REAL — confirmed with actual HTTP requests
[ ] Bug is IN SCOPE — checked program scope page
[ ] Reproducible from scratch
[ ] Evidence ready — screenshot, response body, or video
```

### Gate 1: Impact Validation (2 minutes)
```
[ ] "What can attacker DO that they couldn't before?"
[ ] Answer is more than "see non-sensitive data"
[ ] Real victim: another user's data, company's data, financial loss
```

### Gate 2: Deduplication Check (5 minutes)
```
[ ] Searched Hacktivity for this program + similar bug
[ ] Read most recent 5 disclosed reports
[ ] Not a "known issue" in changelog/docs
[ ] Google: "TARGET ENDPOINT bug bounty"
```

### Gate 3: Report Quality (10 minutes)
```
[ ] Title: [Bug Class] in [Endpoint] allows [actor] to [impact]
[ ] Steps: copy-pasteable HTTP request
[ ] Evidence: screenshot/video of actual impact (not just 200)
[ ] Severity: matches CVSS + program definitions
[ ] NEVER used "could potentially" or "may allow"
```

---

## NEVER SUBMIT LIST

```
Missing CSP / HSTS / security headers
Missing SPF / DKIM / DMARC
GraphQL introspection alone (no auth bypass, no IDOR demonstrated)
Banner / version disclosure without working CVE exploit
Clickjacking on non-sensitive pages (no sensitive action PoC)
Tabnabbing
CSV injection (no actual code execution shown)
CORS wildcard (*) without credential exfil PoC
Logout CSRF
Self-XSS (only exploits own account)
Open redirect alone (no ATO or OAuth theft chain)
OAuth client_secret in mobile app (known, expected)
SSRF DNS callback only (no internal service access or data)
Host header injection alone (no password reset poisoning PoC)
Rate limit on non-critical forms
Session not invalidated on logout
Concurrent sessions
Internal IP in error message
Mixed content
SSL weak ciphers
Missing HttpOnly / Secure cookie flags alone
Broken external links
Autocomplete on password fields
Pre-account takeover (usually — very specific conditions)
```

---

## CONDITIONALLY VALID — CHAIN REQUIRED

Build the chain first, prove it works, THEN report.

| Standalone | Chain Required | Valid Result |
|------------|----------------|--------------|
| Open redirect | + OAuth redirect_uri → auth code theft | ATO (Critical) |
| Clickjacking | + sensitive action + working PoC | Medium |
| CORS wildcard | + credentialed request exfils PII | High |
| CSRF | + sensitive action (transfer, change email, delete) | High |
| Rate limit bypass | + OTP/reset token brute force succeeds | Medium/High |
| SSRF DNS-only | + internal service access + data returned | Medium |
| Host header injection | + password reset email uses injected host | High |
| Prompt injection | + reads other user's data (IDOR) | High |
| S3 bucket listing | + JS bundles contain API keys | Medium/High |
| Self-XSS | + CSRF to trigger on victim | Medium |
| Subdomain takeover | + OAuth redirect_uri at that subdomain | Critical |
| GraphQL introspection | + auth bypass mutation or IDOR on node() | High |

---

## KILL FAST RULES

1. **5-minute rule**: Can't fill Q1 template in 5 min → move on
2. **Precondition count**: >2 preconditions simultaneously → kill it
3. **Impact test**: "What does attacker walk away with?" — nothing tangible → kill it
4. **Admin bypass**: "Admin can do X" = NEVER a bug
5. **Design doc test**: Documented behavior → kill it
6. **Rabbit hole signal**: 30+ min on Q6 with no PoC → kill it
