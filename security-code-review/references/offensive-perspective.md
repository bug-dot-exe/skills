# Offensive Security Perspective

What pentesters actually look for, what gets exploited first, and how attackers chain
findings into impact. Read this alongside the universal checklist — it's the "why"
behind every control and the lens that separates a security review from a code review.

---

## What Gets Exploited First (Pentester Priority Order)

1. **Exposed secrets** — Hardcoded API keys, leaked `.env` files, secrets in git history,
   credentials in client-side bundles. Often game over in minutes. Automated tools like
   truffleHog and gitleaks find these instantly. Check JS bundles, error messages, common
   paths (`/.env`, `/api/debug`, `/.git/config`), and cloud metadata.

2. **Broken authorization (IDOR)** — Can user A access user B's data by changing an ID in
   the URL or body? The single most common high-severity finding in app assessments. Easy
   to test, frequently missed because developers only test their own accounts.

3. **Missing auth on internal endpoints** — Endpoints that were "only for internal use"
   but are reachable from the internet. Admin panels, debug endpoints, health checks that
   leak config, API routes missing the auth middleware.

4. **Injection in search/filter/sort params** — Login forms get tested by everyone.
   Sort parameters, search queries, date range filters, and CSV export endpoints are where
   injection actually lives in modern apps.

5. **Parameter tampering for privilege escalation** — Changing `role: "user"` to
   `role: "admin"` in a signup request, or `is_admin: true` in a profile update. Mass
   assignment where the API blindly accepts whatever fields the client sends.

6. **SSRF in integrations** — Webhook URLs, image fetchers, PDF generators, URL preview
   features — anything that makes the server fetch a URL the user controls. Pivots to
   internal services, cloud metadata endpoints, and credential theft.

7. **Default or weak credentials** — Default admin passwords on dashboards, debug mode
   enabled in production, verbose error pages, open Swagger/OpenAPI docs with "Try it out"
   enabled against production.

---

## Trust Boundary Checklist

Every request crossing a trust boundary needs:
- **Authentication** — who is this?
- **Authorization** — are they allowed to do this to *this specific resource*?
- **Validation** — is the input well-formed and within expected bounds?

Trust boundaries: client → server, user input → database, external API → your code,
file upload → filesystem, webhook → handler.

---

## The Attacker's Playbook by Category

### Secrets — What Attackers Actually Do First

- Search the JavaScript bundle for API keys and endpoints (`NEXT_PUBLIC_` variables are visible to everyone)
- Search git history — even if secrets are removed from HEAD, `git log -p` reveals them and old secrets often still work
- Probe common paths: `/.env`, `/config.json`, `/api/debug`, `/.git/config`, `/server-status`
- If SSRF exists: `http://169.254.169.254/latest/meta-data/iam/security-credentials/` yields IAM credentials on AWS (similar endpoints on GCP/Azure)

### IDOR — How It's Exploited

1. Create two accounts (user A, user B)
2. Perform an action as user A, capture the request
3. Replay it authenticated as user B
4. If user B's data comes back, it's an IDOR

Common patterns pentesters check:
- `GET /api/users/123/documents` — change 123 to 124
- `GET /api/invoices?user_id=123` — swap the query param
- `PUT /api/profile` with another user's ID in the body
- `DELETE /api/comments/456` — delete someone else's comment
- Sequential integer IDs are easier to enumerate than UUIDs, but UUIDs are obscurity not a fix — authorization checks are the fix

### Injection — Where It Actually Hides

Modern ORMs prevent basic SQLi in simple queries. Pentesters target where developers drop to raw queries:
- **Sort/order parameters** — `?sort=name` → `?sort=name;DROP TABLE users--`
- **Search LIKE clauses** — raw `LIKE '%{input}%'` patterns
- **GraphQL** — nested queries, field injection, introspection enabled in production
- **Reporting/export endpoints** — often use raw queries for performance, skip the ORM
- **SSTI** — test with `{{7*7}}` in any field rendered by a template; if you see `49`, it's injectable
- **Path traversal** — `../../etc/passwd` in file paths, download endpoints, include mechanisms

### Authentication — How Sessions Get Hijacked

- **Token in localStorage** — one XSS and the attacker has it. httpOnly cookies prevent this entirely
- **No server-side invalidation** — user clicks logout, token still valid; attacker who captured it keeps using it
- **Predictable reset tokens** — sequential IDs, timestamps, short random strings; must be cryptographically random and single-use
- **Username enumeration** — "User not found" vs "Incorrect password" tells which emails are registered; feeds credential stuffing

### Rate Limiting — How It Gets Bypassed

- **Header manipulation** — adding `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP` headers. If the limiter trusts these without validation, it's defeated
- **Parameter variation** — `/api/login` vs `/api/login/` vs `/api/Login`, URL encoding, extra params
- **IP rotation** — trivial with cloud functions or proxies

Rate limiting is defense in depth, not a primary control. Combine with account lockouts and monitoring.

---

## Vulnerability Chains

Individual findings become critical when chained. Think about how findings combine:

- **Info disclosure → account takeover:** verbose error leaks internal user IDs → IDOR on password reset leaks reset tokens → attacker resets admin password
- **XSS → session hijack:** stored XSS in comment fires when admin views it → token stolen from localStorage → attacker exports all user data using admin session
- **SSRF → credential theft → lateral movement:** webhook URL field allows internal requests → points at cloud metadata endpoint → IAM credentials returned → pivots to S3, databases, other infrastructure
- **Mass assignment → privilege escalation:** profile update endpoint accepts arbitrary fields → attacker adds `"role": "admin"` → backend saves all fields blindly → full access
- **IDOR → PII breach:** document endpoint uses sequential integer IDs, no ownership check → attacker loops ID 1 to 100,000 → downloads every user's PII and financial records

---

## Common Assessment Findings by Severity

**Critical:** Hardcoded credentials, SQLi, unauthenticated admin endpoints, RCE via deserialization or template injection, IDOR on financial/PII/health data

**High:** Authorization bypass (horizontal or vertical), stored XSS in content viewed by other users or admins, SSRF with access to internal services or cloud metadata, mass assignment allowing role escalation, secrets in client-side bundles or git history

**Medium:** CSRF on state-changing operations, reflected XSS, verbose error messages with stack traces or internal paths, missing rate limiting on auth endpoints, sessions that don't expire or aren't invalidated on logout, username enumeration

**Low:** Missing security headers (CSP, HSTS, X-Frame-Options), cookies without Secure/HttpOnly flags, out-of-date dependencies with no known exploitable vulnerabilities

---

## Red Flags in Code (Scan for These)

```
# Immediate red flags — stop and investigate
eval(  exec(  system(  popen(
pickle.loads(  yaml.load(          # use yaml.safe_load
shell=True                          # subprocess shell injection
f"SELECT ... {user_input}"          # SQL injection
"SELECT * ... " + userInput         # SQL injection
fmt.Sprintf(... query               # SQL injection in Go
render_template_string(user_input)  # SSTI
Markup(user_input)                  # XSS via Jinja2
dangerouslySetInnerHTML             # XSS via React — check sanitization
template.HTML(  |safe               # XSS — check sanitization
localStorage.setItem('token', ...)  # token theft via XSS
SECRET_KEY = "  API_KEY = "  PASSWORD = "   # hardcoded secrets
verify=False                        # disabled TLS verification
allow_origins=["*"]  AllowAll()     # wide-open CORS
random.  Math.random()              # non-cryptographic randomness for security
```

```
# Needs closer inspection
.query(text(...))                   # verify bind parameters are used
requests.get(user_url)              # potential SSRF — validate URL against allowlist
open(user_path)                     # path traversal — validate and sanitize
os.path.join(  /tmp/               # path traversal — ensure no user-controlled segments
**request.json()                    # mass assignment — explicitly validate allowed fields
password in log/print/logger        # sensitive data in logs
except: pass  except Exception: pass  # swallowed errors hide security issues
DEBUG = True                        # debug mode in production
```

---

## Questions to Ask Every Endpoint

Run through these for every API endpoint in a security-sensitive review.
These are the same questions a pentester asks during an assessment.

### Authentication
- Can I call this without any authentication at all?
- What happens if I send an expired token?
- What happens if I send a malformed or truncated token?

### Authorization
- Can user A access this endpoint and see user B's data by changing a resource ID?
- Can a regular user reach this admin-only endpoint?
- Does every code path that reads or writes a resource verify ownership, not just authentication?

### Input
- What happens if I send unexpected or extra fields in the JSON body?
- What happens if I send extremely long strings, negative numbers, or zero where positive is expected?
- Can I inject SQL, template syntax, or shell commands via any parameter — including sort, filter, and search params?
- Are file uploads restricted by content (not just extension) and size?

### Response
- Does the error response reveal stack traces, internal paths, or schema details?
- Does the success response include fields the caller shouldn't see (password hashes, tokens, other users' data)?
- Are there timing differences that reveal information (valid vs. invalid usernames, existing vs. non-existing records)?

### Rate Limiting
- Can I call this 1,000 times in a minute without consequence?
- Can I bypass the rate limit with `X-Forwarded-For` or slight URL variations?

### Business Logic
- Can I skip steps in a multi-step process (checkout without payment, verify without OTP)?
- Can I replay this request to double-charge or double-credit?
- Can I tamper with pricing, quantities, or discount codes in the request body?
- Can I access functionality that should be time-locked or state-dependent?
