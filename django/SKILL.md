---
name: django
description: Security testing playbook for Django applications covering settings exposure, ORM injection, CSRF misconfig, and admin panel hardening
depends_on: []
---

# Django

Security testing for Django applications. Focus on settings exposure (DEBUG, SECRET_KEY, ALLOWED_HOSTS), admin panel hardening, ORM injection, template injection, CSRF middleware gaps, and session cookie configuration.

## Attack Surface

**Settings & Configuration**
- `settings.py` / environment variables: DEBUG, SECRET_KEY, ALLOWED_HOSTS, DATABASES, CORS headers
- Middleware ordering: SecurityMiddleware, CsrfViewMiddleware, SessionMiddleware, AuthenticationMiddleware
- `INSTALLED_APPS`: debug toolbar, admin, REST framework, Silk profiler, django-extensions

**Authentication & Sessions**
- `django.contrib.auth`: login, logout, password reset, permission framework
- Session backends: DB, cache, file, cookie-based (signed JSON)
- Cookie settings: SESSION_COOKIE_SECURE, SESSION_COOKIE_HTTPONLY, SESSION_COOKIE_SAMESITE, CSRF_COOKIE_SECURE
- Custom backends, social auth (django-allauth), token auth (DRF)

**Admin Panel**
- `django.contrib.admin` at `/admin/` (default path)
- ModelAdmin customizations, inline editors, admin actions
- Staff vs superuser permissions, object-level permissions

**Views & Routing**
- Function-based views, class-based views (CBVs), ViewSets (DRF)
- URL patterns: path(), re_path(), include(), namespace resolution
- Decorators: `@login_required`, `@permission_required`, `@csrf_exempt`

**Data Layer**
- ORM: QuerySet filtering, `.extra()`, `.raw()`, `RawSQL()`, `connection.cursor()`
- File handling: FileField, ImageField, MEDIA_ROOT, STATIC_ROOT, storage backends
- Serializers (DRF): nested serializers, writable fields, SlugRelatedField

**Templates**
- Django template engine: autoescape, `|safe`, `{% autoescape off %}`, `mark_safe()`
- Jinja2 backend if configured: SSTI vectors through `Environment` customization

## High-Value Targets

- `/admin/` and common aliases (`/admin/login/`, `/django-admin/`, `/manage/`)
- Debug mode artifacts: `/debug/`, `/__debug__/`, `/_debug_toolbar/`, detailed error pages with tracebacks
- Password reset flow: `/accounts/password_reset/`, token predictability, Host header poisoning
- DRF endpoints: `/api/`, browsable API with auth forms, schema endpoints (`/api/schema/`)
- Static/media file serving: STATIC_URL, MEDIA_URL paths exposing uploaded content
- Management command endpoints if exposed via admin or custom views
- Silk profiler (`/silk/`), django-debug-toolbar panels

## Reconnaissance

**Debug Detection**
```
GET /nonexistent-path-triggering-404
```
DEBUG=True returns full URL configuration, installed apps, and settings context. Look for yellow Django error pages with traceback, local variables, and request metadata.

```
GET /__debug__/
GET /silk/
GET /api/schema/
GET /api/?format=api
```

**Admin Discovery**
```
GET /admin/
GET /admin/login/
GET /django-admin/
GET /manage/
GET /admin/doc/
```
Admin login page confirms Django and may reveal version in page source.

**Settings Leakage**
- Error pages exposing `SECRET_KEY`, database credentials, API keys in local variable dumps
- `ALLOWED_HOSTS` bypass: send requests with spoofed Host header; if empty list with DEBUG=True, all hosts accepted
- Check `X-Frame-Options`, `Strict-Transport-Security`, `Content-Security-Policy` headers set by SecurityMiddleware

## Key Vulnerabilities

### DEBUG=True in Production

**Information Disclosure**
- Detailed error pages reveal: full traceback, local variables, SQL queries, request/response data, settings
- Settings page accessible via error context: database passwords, API keys, SECRET_KEY
- URL configuration dump shows all registered paths including admin and internal endpoints

**DEBUG=True + ALLOWED_HOSTS=[]**
- Any Host header accepted, enabling Host header injection across all views
- Combined with password reset: attacker-controlled Host in reset email link

### SECRET_KEY Exposure

**Impact Assessment**
- SECRET_KEY signs: session cookies, CSRF tokens, password reset tokens, signed cookies, `Signer` output
- Exposed SECRET_KEY enables: session forging (admin access), CSRF token generation, password reset token forging
- Check: error pages, git history, `.env` files, client-side bundles, Docker images, CI/CD configs

**Session Forgery**
- Django's default session serializer is JSON (since 1.6) but pickle serializer (`SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'`) enables RCE via crafted session cookie
- With SECRET_KEY + cookie-based sessions: forge arbitrary session data including `_auth_user_id`

### Admin Panel Exploitation

**Brute Force**
- Default `/admin/` with no rate limiting or account lockout
- Common credentials: admin/admin, admin/password, staff accounts

**Privilege Escalation**
- Staff user with limited model access exploiting admin actions or inline editors
- ModelAdmin `save_model()`, `get_queryset()`, `has_change_permission()` overrides with gaps
- Admin log (`/admin/log/`) exposing change history of sensitive models

**Admin CSRF**
- Admin uses session auth with CSRF tokens; if CSRF middleware is bypassed for admin, cross-site admin actions possible

### CSRF Misconfiguration

**@csrf_exempt Abuse**
- Views decorated with `@csrf_exempt` skip CSRF protection entirely
- Common on API endpoints, webhook receivers, file upload handlers
- DRF `SessionAuthentication` enforces CSRF; other DRF auth classes do not

**CSRF_TRUSTED_ORIGINS**
- Overly broad trusted origins (wildcards, entire domains) enable cross-origin state changes
- Missing from configuration when using subdomains or CDN origins

**Cookie Settings**
- `CSRF_COOKIE_HTTPONLY = False` (default): JavaScript-readable CSRF token
- `CSRF_COOKIE_SECURE = False`: CSRF cookie sent over HTTP, interceptable on mixed-content sites
- `SESSION_COOKIE_SAMESITE = None` without Secure flag

### ORM Injection

**Raw SQL Paths**
```python
# Dangerous patterns
Model.objects.raw("SELECT * FROM app_model WHERE id = %s" % user_input)
Model.objects.extra(where=["name = '%s'" % user_input])
cursor.execute("SELECT * FROM app_model WHERE name = '%s'" % user_input)
RawSQL("field = %s" % user_input)
```

**QuerySet Filter Injection**
```python
# User-controlled kwargs to filter()
Model.objects.filter(**request.GET.dict())
```
Attacker sends `password__startswith=a`, `password__startswith=b` etc. to extract field values character by character via boolean inference.

**JSONField/HStoreField**
- User-controlled lookups on JSON fields: `data__key__contains`, `data__has_key`

### Template Injection

**Django Templates**
- `|safe` filter or `mark_safe()` on user input bypasses autoescape
- `{% autoescape off %}` blocks around user-controlled content
- Custom template tags with insufficient escaping

**Jinja2 Backend (if configured)**
```python
{{ config }}
{{ ''.__class__.__mro__[2].__subclasses__() }}
{{ cycler.__init__.__globals__['os'].popen('id').read() }}
```
Check `Environment` configuration for autoescape settings and custom globals/filters.

### ALLOWED_HOSTS Bypass

**Host Header Injection**
- `ALLOWED_HOSTS = ['*']` or empty with DEBUG=True: all Host values accepted
- Password reset poisoning: `Host: attacker.com` causes reset link to point to attacker domain
- Cache poisoning: different Host values generate different cache keys with attacker-controlled URLs

### Session Security

**Cookie-Based Sessions**
- `SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'`
- All session data visible to client (base64-encoded, signed but not encrypted)
- With SECRET_KEY: forge sessions, escalate to admin

**Session Fixation**
- Django rotates session key on login by default (`request.session.cycle_key()`)
- Custom auth backends may skip rotation; test by setting session cookie before auth

### File Upload

**MEDIA_ROOT Exposure**
- Uploaded files served directly without auth checks from MEDIA_URL
- Path traversal in upload filename: `../../etc/cron.d/malicious`
- Unrestricted file types: `.py`, `.html`, `.svg` (stored XSS via SVG)

**Storage Backend**
- Local storage: symlink following, race conditions on file creation
- S3/cloud storage: pre-signed URL generation with excessive expiry or permissions

## Bypass Techniques

- Method override: some middleware only checks POST for CSRF; PUT/PATCH/DELETE may bypass
- Content-type switching: `application/json` vs `multipart/form-data` hitting different validation paths
- `@csrf_exempt` on DRF views using `SessionAuthentication`: verify CSRF is actually enforced
- Admin URL path manipulation: `/admin/../admin/` or encoding tricks to bypass reverse proxy rules
- `X-Forwarded-Host` / `X-Forwarded-Proto` trusted by Django when USE_X_FORWARDED_HOST=True

## Testing Methodology

1. **Enumerate** - Trigger 404/500 errors to detect DEBUG mode; discover admin, API, profiler paths
2. **Settings audit** - Check headers for SecurityMiddleware, probe ALLOWED_HOSTS with spoofed Host
3. **Admin probing** - Brute force admin login, test staff permission boundaries, check admin log exposure
4. **CSRF validation** - Test state-changing endpoints for CSRF enforcement; find `@csrf_exempt` views
5. **ORM injection** - Identify raw SQL usage, filter() with user kwargs, extra()/RawSQL() patterns
6. **Template injection** - Search for `|safe`, `mark_safe()`, Jinja2 SSTI if backend is configured
7. **Session analysis** - Inspect cookie attributes, test session forgery if SECRET_KEY is known
8. **File upload** - Test path traversal, unrestricted types, direct MEDIA_URL access without auth

## Corpus-Derived Attack Patterns

### Import/Export as Privilege Boundary

Import endpoints (project import, data restore, CSV upload, template cloning) deserialize complex objects and often bypass field-level authorization. The import parser may process fields the importing user lacks permission to create directly.
- Map all import/export endpoints: project templates, backup restore, data migration tools
- For each importable field, compare against create/update API permissions -- any field accepted by import but rejected by direct API is an escalation vector
- Test: import a project template containing private/confidential data from another scope
- Django management commands exposed via admin or custom views (`loaddata`, `dumpdata`) may skip model-level permission checks

### SSRF via Model Dynamic Setters

Django models with URL fields (`models.URLField`) or any field accepting URLs that trigger server-side fetch (avatar URL, webhook URL, remote attachment, RSS feed) are SSRF vectors.
- List every model field that accepts URLs: `URLField`, `CharField` storing URLs, JSON fields with URL values
- Trace each URL field through the codebase to find server-side fetch: `requests.get()`, `urllib.urlopen()`, custom download logic
- Test with internal network targets: `http://169.254.169.254/latest/meta-data/`, `http://localhost:8080/admin/`
- Check if URL validation only runs on form submission but not on API/import paths

### CSRF on GraphQL and Multi-Method Endpoints

GraphQL endpoints accepting mutations via GET requests bypass CSRF protection that only validates POST. Django's CSRF middleware checks POST bodies but GET parameters pass through unchecked.
- For every GraphQL endpoint: send mutation queries via GET with `?query=mutation{...}`
- For REST endpoints supporting multiple HTTP methods: verify CSRF enforcement on each method independently
- Test `Content-Type: application/json` vs `application/x-www-form-urlencoded` -- Django CSRF only validates form-encoded POST by default
- DRF `SessionAuthentication` enforces CSRF but `TokenAuthentication` does not -- mixed auth configurations may leave gaps

### State-Changing GET Requests

Any GET endpoint that modifies state (follow/unfollow, mark-read, toggle setting, delete via link) is exploitable as CSRF without tokens. Combined with response observation, these become deanonymization primitives.
- Search for `@require_GET` or GET-only views that call `.save()`, `.delete()`, or `.update()`
- Admin action URLs triggered via GET (email links, one-click actions)
- When a state-changing GET produces feedback visible to a third party (notification, log entry, status change), the combination enables user identification attacks

### Regional and Legacy Domain CSRF

Large Django deployments maintain regional, legacy, or acquisition-era domains sharing the same backend. CSRF protections on the main domain may not cover secondary domains.
- Enumerate secondary domains: country-specific variants, legacy product domains, acquired service domains
- Test CSRF token validation across domains -- some share session backends but have independent CSRF validation
- Check `CSRF_TRUSTED_ORIGINS` for each domain independently
- Cookie tossing from a subdomain: if the attacker controls any subdomain, they can set CSRF cookies on the parent domain

### Configuration Field Stored XSS

Admin-configurable text fields rendered in user-facing contexts (validation messages, tooltip text, group names, project descriptions, onboarding templates) are often stored without sanitization because they are considered trusted input.
- Enumerate every admin-configurable text field that renders in non-admin views
- Set field values containing `<script>` or event handler payloads
- Check rendering context: Django templates with `|safe` on admin-set content, or `mark_safe()` applied to configuration values
- Group names, organization names, and project names that appear in HTML title tags, breadcrumbs, or email templates are high-priority targets

### Prototype Pollution to Template Gadget (Frontend)

When a Django application serves a frontend using Vue, Angular, or React, prototype pollution in the JavaScript layer can chain with framework template evaluation for XSS.
- Identify client-side template engine (check for `ng-app`, `v-bind`, `{{` in non-Jinja contexts)
- Find prototype pollution sources: deep merge utilities, `Object.assign()` with user input, JSON.parse of attacker-controlled data
- If PP primitive exists, test known template engine gadgets: `constructor.prototype.template`, `__proto__.sourceURL`, `__proto__.sequence`
- This bypasses Django's server-side autoescape entirely since exploitation occurs client-side

## Validation Requirements

- DEBUG=True confirmed with full traceback page showing settings/variables
- SECRET_KEY exposure demonstrated with source and forged session or CSRF token
- Admin access: successful login or privilege escalation with evidence of data access
- CSRF bypass: state-changing action executed cross-origin without valid CSRF token
- ORM injection: data extraction or boolean inference demonstrating query manipulation
- Host header injection: password reset email with attacker-controlled domain in link
- File upload: path traversal or stored XSS via uploaded content served from MEDIA_URL
- Import escalation: data from restricted scope accessible after import/template clone operation
- SSRF: server-side request triggered via model URL field reaching internal network resource
