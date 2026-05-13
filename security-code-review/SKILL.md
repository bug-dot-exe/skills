---
name: security-review
description: >
  Use this skill when adding authentication, handling user input, working with secrets,
  creating API endpoints, implementing payment or sensitive features, or storing/transmitting
  sensitive data. Also trigger when reviewing existing code for vulnerabilities, integrating
  third-party APIs, implementing file uploads, setting up CORS, configuring security headers,
  or any time the code touches trust boundaries (user input → backend, backend → database,
  service → service). Includes offensive security perspective — what pentesters actually
  exploit, vulnerability chains, and red flags from real assessments. If the task involves
  credentials, tokens, passwords, PII, or access control in any way, use this skill. When in
  doubt about whether something is security-relevant, it probably is — use the skill.
---

# Security Review Skill

Ensure all code follows security best practices and catch vulnerabilities before they ship.
Use the checklist below, then read topic reference files as you work through each area.

## Reference Structure

References are organized by **topic**, then by **stack**. Read the `general.md` for
cross-stack non-obvious patterns, then the stack-specific file for implementation details.

Always start with `references/offensive-perspective.md` — it contains the pentester priority
order, attacker playbook by category, vulnerability chains, red flags, and the questions to
ask every endpoint. These apply regardless of stack.

### Topic → Stack Reference Map

| Topic | general.md | go.md | python.md | python-fastapi.md | nextjs.md |
|-------|-----------|-------|-----------|-------------------|-----------|
| Offensive (always read) | `references/offensive-perspective.md` | — | — | — | — |
| OWASP gaps (A04/A08/A09) | `references/owasp-gaps.md` | — | — | — | — |
| Auth & Authorization | `references/auth/general.md` | `references/auth/go.md` | `references/auth/python.md` | `references/auth/python-fastapi.md` | `references/auth/nextjs.md` |
| Input Validation | `references/input/general.md` | `references/input/go.md` | `references/input/python.md` | `references/input/python-fastapi.md` | `references/input/nextjs.md` |
| Injection Prevention | `references/injection/general.md` | `references/injection/go.md` | `references/injection/python.md` | `references/injection/python-fastapi.md` | `references/injection/nextjs.md` |
| Web (XSS/CSRF/CORS/rate limiting) | `references/web/general.md` | `references/web/go.md` | — | `references/web/python-fastapi.md` | `references/web/nextjs.md` |
| Data Exposure & Logging | `references/data/general.md` | `references/data/go.md` | `references/data/python.md` | `references/data/python-fastapi.md` | `references/data/nextjs.md` |
| Transport (TLS/HTTPS/timeouts) | `references/transport/general.md` | `references/transport/go.md` | `references/transport/python.md` | `references/transport/python.md` | `references/transport/nextjs.md` |
| Secrets Management | `references/secrets/general.md` | `references/secrets/go.md` | `references/secrets/python.md` | `references/secrets/python.md` | `references/secrets/nextjs.md` |
| Dependencies (SCA/lock files) | `references/dependencies/general.md` | `references/dependencies/go.md` | `references/dependencies/python.md` | `references/dependencies/python.md` | `references/dependencies/nextjs.md` |

**How to use:** For each checklist section you're working on, read the relevant topic row.
Read `general.md` for the gotchas, then the stack file for copy-paste patterns.
Skip topic files for areas not in scope for the current task.

If the project uses a stack not listed here, read `general.md` for each topic and adapt
from the closest stack reference.

## Think Like an Attacker

Before writing or reviewing security-sensitive code, consider what an attacker would try.
For the full exploitation playbook, red flags, and questions to ask every endpoint, read
`references/offensive-perspective.md`.

1. **What's the attack surface?** Every input the user controls is a potential entry point —
   URL params, headers, cookies, file uploads, JSON bodies, WebSocket messages.
2. **What's the blast radius?** If this component is compromised, what else falls? A leaked
   DB credential is worse than a leaked UI preference.
3. **Where are the trust boundaries?** Data crossing from untrusted → trusted context needs
   validation: client → server, user input → database, external API → your code, file upload → filesystem.
4. **What does the attacker gain?** Prioritize protecting high-value targets: auth tokens,
   payment data, PII, admin access, API keys with broad permissions.
5. **What can be chained?** A low-severity info disclosure becomes critical when it enables
   exploitation of another weakness. Think about how findings combine.

## Universal Security Checklist

Work through each category. Read the corresponding topic reference files as you go.

### 1. Secrets Management

**Reference:** `references/secrets/general.md` + stack file

- [ ] No hardcoded API keys, tokens, passwords, or connection strings
- [ ] All secrets loaded from environment variables or a secrets manager
- [ ] Secret presence validated at startup (fail fast if missing)
- [ ] `.env` / `.env.local` in `.gitignore`
- [ ] No secrets in git history (if found, rotate immediately — removing from history isn't enough)
- [ ] Production secrets managed through hosting platform or vault
- [ ] Secrets have minimal scope (least-privilege API keys, read-only DB users where possible)

### 2. Input Validation

**Reference:** `references/input/general.md` + stack file

- [ ] All user inputs validated with schemas before processing
- [ ] Validation happens server-side (client-side validation is UX, not security)
- [ ] File uploads restricted by size, MIME type (from content bytes), and extension
- [ ] Filenames sanitized — never use user-provided filenames directly in paths
- [ ] No user input passed directly into shell commands, file paths, or eval/exec
- [ ] Allowlist validation preferred over blocklist
- [ ] Error messages don't leak internal details (schema info, stack traces, file paths)

### 3. Injection Prevention

**Reference:** `references/injection/general.md` + stack file

- [ ] All database queries use parameterized queries or ORM methods
- [ ] No string concatenation or f-strings in SQL
- [ ] Dynamic identifiers (column/table names) validated against an allowlist
- [ ] No user input in shell commands (if unavoidable, use allowlists + escaping)
- [ ] Template engines used with auto-escaping enabled
- [ ] User-provided HTML sanitized with an allowlist of tags/attributes
- [ ] Deserialization only from trusted sources (never pickle/yaml.load/ObjectInputStream on user input)

### 4. Authentication & Session Management

**Reference:** `references/auth/general.md` + stack file

- [ ] Passwords hashed with bcrypt, scrypt, or argon2 (never MD5/SHA for passwords)
- [ ] Tokens stored in httpOnly, Secure, SameSite=Strict cookies (not localStorage)
- [ ] Session tokens have reasonable expiration
- [ ] Session invalidated on logout (server-side invalidation, not just cookie deletion)
- [ ] Password reset tokens are single-use, time-limited, and don't reveal account existence
- [ ] Failed login attempts rate-limited (prevent brute force)
- [ ] Authentication errors don't reveal whether the account exists

### 5. Authorization

**Reference:** `references/auth/general.md` + stack file

- [ ] Authorization checked server-side before every sensitive operation
- [ ] Object-level authorization — users can only access their own resources (IDOR prevention)
- [ ] Role-based or attribute-based access control implemented
- [ ] Admin endpoints protected and not guessable
- [ ] Row-level security enabled at the database layer where supported
- [ ] Horizontal privilege escalation tested (user A can't access user B's data)
- [ ] Vertical privilege escalation tested (regular user can't reach admin functions)

### 6. XSS & CSRF Prevention

**Reference:** `references/web/general.md` + stack file

- [ ] Framework's built-in XSS protection used (React JSX escaping, Jinja2 autoescaping, Go html/template)
- [ ] `dangerouslySetInnerHTML` / `|safe` / `Markup()` / `template.HTML()` only with sanitized content
- [ ] Content Security Policy headers configured
- [ ] User-provided URLs validated (prevent `javascript:` and `data:` schemes)
- [ ] CSRF tokens on all state-changing operations, or SameSite=Strict cookies + Origin validation

### 7. Rate Limiting

**Reference:** `references/web/general.md` + stack file

- [ ] Rate limiting on all public API endpoints
- [ ] Stricter limits on auth endpoints (login, password reset, token generation)
- [ ] Rate limiting by IP for unauthenticated requests, by user ID for authenticated
- [ ] Rate limit responses include `Retry-After` headers
- [ ] Rate limiter not bypassable via X-Forwarded-For header spoofing

### 8. Data Exposure Prevention

**Reference:** `references/data/general.md` + stack file

- [ ] API responses return only necessary fields (explicit response types, not full DB models)
- [ ] No passwords, tokens, secrets, or PII in logs (redact before logging request bodies)
- [ ] Security events logged: auth failures, authorization denials, admin actions
- [ ] User input sanitized in log messages (prevent log injection via newlines)
- [ ] Error responses generic for clients, detailed only in server-side logs
- [ ] Stack traces never exposed to end users
- [ ] Sensitive data encrypted at rest where required
- [ ] PII handling compliant with relevant regulations (GDPR, CCPA, etc.)

### 9. Transport & Infrastructure

**Reference:** `references/transport/general.md` + stack file (TLS, HTTPS, timeouts); `references/web/general.md` + stack file (headers, CORS); `references/dependencies/general.md` + stack file (SCA scanning, lock files)

- [ ] HTTPS enforced in production (HSTS header set)
- [ ] Security headers configured: CSP, X-Frame-Options, X-Content-Type-Options
- [ ] CORS configured with specific allowed origins (not wildcard in production)
- [ ] Cookies set with Secure flag
- [ ] CDN-hosted `<script>` and `<link>` tags include `integrity` (SRI) attributes
- [ ] Dependencies up to date with no known vulnerabilities
- [ ] Lock files committed for reproducible builds
- [ ] Dependency scanning enabled (Dependabot, Snyk, `pip audit`, `npm audit`, `govulncheck`)

## Offensive Review Pass

After completing the checklist, do a second pass from the attacker's perspective.
Read `references/offensive-perspective.md` and specifically:

1. **Run the red flags scan** — search the codebase for the patterns in the red flags section
2. **Check each endpoint** with the "Questions to Ask Every Endpoint" framework
3. **Consider vulnerability chains** — how could a low-severity finding combine with another?
4. **Prioritize like a pentester** — exposed secrets, IDOR, missing auth on internal endpoints,
   injection in search/filter/sort params first
5. **Review OWASP gaps** — read `references/owasp-gaps.md` for design-level issues the
   checklist doesn't catch: business logic abuse and race conditions (A04), insecure
   deserialization/SRI/CI-CD integrity (A08), and security event logging (A09)

## Security Testing Checklist

- [ ] Authentication endpoints tested (unauthenticated access returns 401)
- [ ] Authorization tested (wrong role returns 403, IDOR attempts blocked)
- [ ] Invalid input rejected with appropriate error codes
- [ ] Rate limits enforced under load
- [ ] SQL injection attempts in input fields don't alter query behavior
- [ ] XSS payloads in user content are escaped in output
- [ ] CSRF tokens validated on state-changing endpoints
- [ ] Secrets not present in client-side bundles or network responses

## Pre-Deployment Gate

Before ANY production deployment:

1. **Secrets** — All in env vars or vault, none in code or git history
2. **Input validation** — Schema validation on all endpoints, server-side
3. **Injection** — All queries parameterized, dynamic identifiers allowlisted
4. **Auth** — Tokens in httpOnly cookies, sessions expire, logout works
5. **Authz** — Server-side checks on every sensitive operation, IDOR tested
6. **XSS/CSRF** — User content sanitized, CSP headers set, SameSite cookies
7. **Rate limiting** — All endpoints protected, auth endpoints strict
8. **Data exposure** — No secrets in logs/errors, minimal API responses
9. **Transport** — HTTPS enforced, security headers configured, CORS locked down
10. **Dependencies** — Audited, no known vulnerabilities, lock files committed
