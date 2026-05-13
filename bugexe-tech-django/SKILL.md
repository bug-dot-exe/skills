---
name: django
description: Django attack surface: SSTI, ORM query injection, debug page leak, weak session signing
depends_on: []
---

# Django

Django is batteries-included. Distinct surface: template engine (autoescape on by default but bypassable), ORM (queryset filtering by user input), admin site (`/admin/`), debug pages (HTML stack traces with code), and `SECRET_KEY` reuse.

## Common Bug Classes

- SSTI in templates that use `{% autoescape off %}` blocks or `mark_safe`
- ORM raw SQL via `.raw()` or `.extra()` with string-formatted user input
- Debug page exposure (`DEBUG=True` in prod) leaking source, env, and SECRET_KEY
- Pickle-based session backend: stolen SECRET_KEY → RCE
- Admin site exposed on default `/admin/` without rate-limit
- CSRF token reuse / missing on `@csrf_exempt` views

## Debug Mode Discovery

Django debug pages are high-value information disclosure. Trigger detection:

```
# Force unhandled exceptions
GET /nonexistent-path-that-triggers-404/
POST /api/endpoint with Content-Type: application/json and body: {invalid
GET /endpoint?id=1'  # SQL-like error trigger
GET /endpoint?format=nonexistent

# Django-specific debug paths
GET /__debug__/
GET /debug/
GET /silk/  # Django Silk profiler
GET /__debug__/sql/select/
```

**What to extract from debug pages:**
- `SECRET_KEY` in settings dump → session forgery, RCE via pickle sessions
- Database credentials and connection strings
- Installed middleware revealing security controls
- Full Python path revealing directory structure
- `ALLOWED_HOSTS` revealing valid hostnames for Host header attacks

## ORM Injection Patterns

Django ORM injection differs from raw SQL injection. Target filter/ordering parameters:

```
# Ordering injection
GET /api/users?ordering=password           # Expose fields via sort order
GET /api/users?ordering=-is_superuser      # Infer field values

# Filter injection via DRF (Django REST Framework)
GET /api/users?email__startswith=admin      # Field lookup traversal
GET /api/users?password__startswith=pbkdf2  # Hash extraction char-by-char
GET /api/users?profile__user__is_staff=true # Relation traversal

# .raw() and .extra() injection
GET /api/search?q='; DROP TABLE auth_user; --
```

**Key insight:** `ORDER BY` / sort-direction / sort-column parameters are high-yield injection targets across all Django apps using DRF's `OrderingFilter`.

## SECRET_KEY Exploitation Chain

When DEBUG=True or SECRET_KEY leaks through other means:

1. **Session forgery:** Django signs session cookies with SECRET_KEY. Forge a session with `is_staff: True` or arbitrary `user_id`
2. **Pickle RCE:** If session backend is `django.contrib.sessions.backends.signed_cookies` with pickle serializer, forge a cookie containing a pickle payload
3. **Password reset forgery:** Reset tokens are HMAC'd with SECRET_KEY. Forge reset tokens for any user
4. **Message framework:** `django.contrib.messages` signs messages with SECRET_KEY

## Admin Panel Hardening Gaps

Django admin is a rich attack surface even when partially protected:

- Default path `/admin/` without rate limiting → credential brute force
- Admin login form leaks valid usernames via different error messages
- Admin actions (bulk delete, export) may lack object-level permission checks
- Inline editors may allow editing related objects the user shouldn't access
- Admin history (`/admin/auth/user/1/history/`) may be accessible to lower-privilege staff

**Social login bypass:** When a Django site uses OAuth (django-allauth), check if the standard `/admin/login/` still accepts password auth for accounts that should only use SSO.

## ReDoS in Framework Utilities

Django's own utilities have had ReDoS CVEs. Hunt methodology:

1. Track regexes modified by recent CVE patches in Django
2. After a regex patch, check: did they fix ALL callers or just the reported one?
3. Test `django.utils.text.Truncator.words()`, URL validators, email validators
4. Send progressively longer crafted strings measuring response time

## Host Header Attacks

Django's `ALLOWED_HOSTS` check has edge cases:

1. Test `Host: target.com\r\nX-Injected: value` for header injection
2. Test `X-Forwarded-Host` override when `USE_X_FORWARDED_HOST = True`
3. Empty `ALLOWED_HOSTS` with `DEBUG=True` accepts any host
4. Password reset emails use `Host` header for link generation — cache poisoning can redirect reset links

## Probe Targets

- Probe `/admin/`, `/admin/login/`, `/__debug__/`, `/debug/`
- Trigger an exception path and check for HTML traceback (DEBUG=True signal)
- Test querystring filters for ORM injection (`?ordering=password`, `?filter=__exact`)
- Check `/robots.txt`, `/sitemap.xml` for admin/staff URLs
- Test `/silk/` and `/silk/requests/` for Django Silk profiler
- Probe `/api/schema/` or `/api/docs/` for DRF schema exposure
- Check for `csrftoken` cookie attributes (Secure, SameSite, HttpOnly)

## Cross-References

`sql_injection`, `ssti`, `csrf`, `session_security`, `information_disclosure`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
- For ORM injection: demonstrate data extraction or privilege inference, not just parameter acceptance
- For debug page: confirm it exposes actionable secrets, not just a formatted error page
