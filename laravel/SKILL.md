---
name: laravel
description: Security testing playbook for Laravel applications covering .env exposure, mass assignment, Eloquent injection, and debug mode leakage
depends_on: []
---

# Laravel

Security testing for Laravel applications. Focus on `.env` file exposure, APP_KEY compromise, debug mode (Ignition error pages), mass assignment via Eloquent, Blade template injection, storage link traversal, and dashboard exposure (Telescope, Horizon, Nova).

## Attack Surface

**Configuration & Environment**
- `.env` file: APP_KEY, DB credentials, API keys, mail credentials, queue/cache/session drivers
- `config/` directory: app.php, auth.php, cors.php, session.php, mail.php
- `APP_DEBUG`: Ignition/Whoops error pages with stack traces and environment variables
- `APP_KEY`: base64-encoded key for encryption, signed cookies, session data

**Authentication & Authorization**
- Guards: web (session), api (token/Sanctum/Passport)
- Middleware: `auth`, `auth:sanctum`, `verified`, `can:ability`, `role`
- Policies and Gates for model-level authorization
- Password reset, email verification, two-factor (Fortify/Jetstream)

**Routing & Middleware**
- Route groups with middleware stacks
- Named routes, route model binding (implicit/explicit)
- API resource routes, `apiResource()` auto-generation
- Middleware groups: `web` (session, CSRF), `api` (throttle, no CSRF)

**Data Layer**
- Eloquent ORM: `$fillable`/`$guarded`, mass assignment, scopes, accessors/mutators
- Query Builder: `DB::raw()`, `whereRaw()`, `selectRaw()`, `orderByRaw()`
- Validation: FormRequest classes, `validate()`, custom rules

**Views & Templates**
- Blade: `{{ }}` (escaped), `{!! !!}` (unescaped), `@php` directive
- Livewire: server-side component updates via AJAX
- Inertia.js: server-side props passed to frontend framework

**File Storage**
- `storage/app/public` symlinked to `public/storage`
- Filesystem disks: local, s3, ftp; visibility settings (public/private)
- File upload via `UploadedFile`, `store()`, `storeAs()`

**Dashboards & Debug Tools**
- Laravel Telescope: `/telescope` (request/query/exception/log viewer)
- Laravel Horizon: `/horizon` (Redis queue dashboard)
- Laravel Nova: `/nova` (admin panel)
- Debugbar: `_debugbar/` endpoints

## High-Value Targets

- `/.env`, `/.env.backup`, `/.env.production`, `/.env.local`
- `/telescope`, `/horizon`, `/nova`, `/_debugbar/open`
- `/storage/` and `/storage/logs/laravel.log`
- Error pages (APP_DEBUG=true) exposing environment, queries, and stack traces
- `/api/` endpoints without `auth:sanctum` middleware
- Password reset: `/password/reset`, `/forgot-password`
- OAuth routes: `/oauth/authorize`, `/oauth/token` (Passport)
- `/sanctum/csrf-cookie` (SPA authentication flow)

## Reconnaissance

**Environment File Discovery**
```
GET /.env
GET /.env.backup
GET /.env.old
GET /.env.production
GET /.env.local
GET /.env.save
GET /.env.swp
GET /.env~
```

**Debug Mode Detection**
```
GET /nonexistent-path
POST /any-route with malformed data
```
Ignition error page reveals: full stack trace, environment variables, request data, SQL queries, application path. Whoops (older versions) similarly exposes config and trace.

**Dashboard Probing**
```
GET /telescope
GET /telescope/requests
GET /horizon
GET /horizon/api/stats
GET /nova
GET /nova/login
GET /_debugbar/open
GET /log-viewer
```

**Laravel Fingerprinting**
- `XSRF-TOKEN` and `laravel_session` cookies
- `X-Powered-By: Laravel` header (if not stripped)
- `/sanctum/csrf-cookie` returning 204
- Error page styling (Ignition UI)

## Key Vulnerabilities

### .env File Exposure

**Direct Access**
- Web server misconfiguration serving `.env` from document root
- Contents include: APP_KEY, DB_PASSWORD, MAIL_PASSWORD, AWS_SECRET_ACCESS_KEY, API keys
- Backup files: `.env.backup`, `.env.old`, `.env.save`, editor swap files (`.env.swp`, `.env~`)

**Impact of APP_KEY**
- APP_KEY encrypts: session data, cookies, cached values, queued job payloads
- With APP_KEY: decrypt sessions, forge cookies, potentially achieve RCE via deserialization
- Laravel < 9.x with cookie-based sessions: unserialize attack leading to RCE via gadget chains
- Generate valid `XSRF-TOKEN` values to bypass CSRF protection

### Debug Mode in Production

**Ignition Error Pages**
- Full environment variable dump (all `.env` values)
- SQL queries with bound parameters
- Stack trace with source code context
- Request headers, cookies, session data
- Application absolute path

**Ignition RCE (CVE-2021-3129)**
- Older Ignition versions with `_ignition/execute-solution` endpoint
- File write via solution execution leading to RCE

### Mass Assignment

**Unguarded Models**
```php
// Vulnerable: $guarded = [] and $fillable not set
User::create($request->all());
User::update($request->all());
```

**Exploitation**
```json
POST /api/users
{
  "name": "user",
  "email": "user@example.com",
  "is_admin": true,
  "role_id": 1,
  "email_verified_at": "2024-01-01"
}
```
- Inject `is_admin`, `role`, `role_id`, `verified`, `email_verified_at`, `balance`, `credits`
- Modify relationship IDs: `team_id`, `organization_id` for cross-tenant access
- Set timestamps: `created_at`, `updated_at` to manipulate time-sensitive logic

### Eloquent Injection

**Raw Expression Paths**
```php
DB::raw("SELECT * FROM users WHERE name = '{$name}'")
User::whereRaw("email = '{$email}'")
User::orderByRaw($request->input('sort'))
User::selectRaw($request->input('columns'))
```

**Column/Table Injection**
- User-controlled column names in `orderBy()`, `where()`, `select()`
- JSON column queries: `->` operator with unsanitized key paths

**Validation Bypass**
- Regex rules with missing anchors: `regex:/[a-z]/` matches any string containing a lowercase letter
- `exists:table,column` rule can be exploited for enumeration
- Custom validation rules with logic flaws

### Blade Template Injection

**Unescaped Output**
```php
{!! $userInput !!}          // Raw output, no escaping
@php echo $userInput; @endphp  // Raw PHP
```

**Indirect SSTI**
- User input stored in database, rendered via `{!! !!}` in Blade
- Markdown rendering pipelines that process Blade directives

### Storage & Log Exposure

**Storage Link Traversal**
- `public/storage` symlink pointing to `storage/app/public`
- Path traversal in file download routes: `../../../.env`, `../../logs/laravel.log`
- `laravel.log` containing stack traces, user data, and potentially secrets

**Uploaded File Access**
- Files stored in public disk accessible without auth checks
- Predictable file naming enabling enumeration
- Missing visibility enforcement on S3/cloud storage

### Dashboard Exposure

**Telescope**
- Records all requests, queries, exceptions, logs, mail, notifications
- Default gate allows access in local environment; misconfigured gates allow production access
- `/telescope/requests` exposes request/response bodies including auth tokens

**Horizon**
- Redis queue monitoring: job payloads may contain sensitive data
- `/horizon/api/stats` and `/horizon/api/jobs/recent` endpoints

**Nova**
- Admin panel with full CRUD on Eloquent models
- Default authentication may rely only on `viewNova` gate

### CSRF Issues

**API Routes Without CSRF**
- `api` middleware group excludes `VerifyCsrfToken` middleware by default
- API routes accepting session cookies (no Sanctum) allow CSRF attacks
- Mixing session auth on API routes without CSRF protection

**CSRF Token Prediction**
- With known APP_KEY: generate valid CSRF tokens
- `XSRF-TOKEN` cookie is encrypted; decryption requires APP_KEY

### Deserialization

**Cookie Deserialization (pre-9.x)**
- Older Laravel with cookie-based session driver and known APP_KEY
- PHP gadget chains (Monolog, Guzzle, Carbon) for RCE
- `laravel-exploits` and `phpggc` tools for payload generation

## Bypass Techniques

- Route model binding: manipulate route parameters to access other users' models
- Middleware ordering: custom middleware registered before auth may leak information
- Policy bypass: `before()` method returning `true` for admin skips all other checks
- Validation rule ordering: stop-on-first-failure rules hiding subsequent injection
- Sanctum token scope: tokens with broad scopes accessing restricted endpoints
- `X-CSRF-TOKEN` vs `X-XSRF-TOKEN` header confusion

## Testing Methodology

1. **Environment discovery** - Probe for `.env` files, backup variants, and editor artifacts
2. **Debug detection** - Trigger errors to identify Ignition/Whoops; check for Debugbar
3. **Dashboard access** - Test Telescope, Horizon, Nova, log-viewer without authentication
4. **Mass assignment** - Send extra fields on create/update endpoints; test `$fillable`/`$guarded` gaps
5. **ORM injection** - Identify `Raw()` usage, user-controlled column/sort parameters
6. **Template injection** - Search for `{!! !!}` with user-controlled data; test Blade directive injection
7. **Storage audit** - Check `/storage/` path for log and file access; test download route traversal
8. **Auth boundaries** - Test API routes for CSRF enforcement, Sanctum token scopes, policy gaps

## Corpus-Derived Attack Patterns

### Multi-State Object Mass Assignment
Laravel apps with multi-state objects (ads, orders, KYC applications, approval workflows) are prime mass assignment targets:
1. Identify models with state/status columns and multi-step approval workflows (apply, pending, admin approves)
2. Send extra fields targeting the state column directly: `{"status": "approved", "verified_at": "2024-01-01"}`
3. Test `PATCH`/`PUT` on status-transition endpoints with fields that should only be set by admin approval
4. Bypass payment gates: set `payment_status` or `effective_status` without completing the payment step
5. Eloquent `$guarded = []` with `$fillable` not set is the most common enabler -- probe every create/update endpoint

### Integer-Context SQLi
When testing Laravel numeric parameters, standard string-based SQLi payloads fail silently:
- Skip quote payloads entirely on integer parameters
- Use arithmetic: `id=1` vs `id=2-1` (same result = injectable)
- Use `SLEEP()`: `id=1 AND SLEEP(5)` for time-based confirmation
- `UNION SELECT` without quotes for data extraction
- `orderByRaw()` and `selectRaw()` with user-controlled columns are the most common sinks
- JSON column queries using `->` operator: unsanitized key paths enable injection

### APP_KEY Multi-Token Abuse
With a compromised APP_KEY, every signed artifact becomes forgeable:
- Session cookies: decrypt and forge admin sessions
- CSRF tokens: generate valid `XSRF-TOKEN` values to bypass CSRF protection
- Encrypted queue job payloads: inject malicious serialized objects into queued jobs
- Password reset tokens: forge valid reset links for any user
- Signed URLs (Active Storage, temporary downloads): generate access to private files
- When the primary session token is hardened, audit every other token signed by the same key

### Batch/Multicall Endpoint Abuse
Laravel endpoints where a single request triggers multiple internal operations:
- Job dispatching endpoints that accept arrays: single request queues N jobs
- Import/bulk-update endpoints: bypass per-request rate limiting and WAF rules
- XML-RPC or JSON-RPC style endpoints: N operations per HTTP request
- Laravel's `Bus::batch()` if exposed via API: test for unbounded batch sizes
- Per-request authentication rate limiting counts the outer request, not inner operations

### Subdomain Admin Panel Discovery
Laravel deployments on cloud infrastructure often have exposed admin interfaces:
- Certificate transparency logs reveal staging/admin subdomains
- Probe: `/telescope`, `/horizon`, `/nova`, `/admin`, `/log-viewer` on every discovered subdomain
- Ignition error pages on staging subdomains expose production credentials if `.env` is shared
- Internal API documentation endpoints (`/docs`, `/api-docs`, `/swagger`) on non-production subdomains

### Livewire Component Manipulation
Laravel Livewire exposes server-side component state via AJAX:
- Intercept Livewire update requests and modify component properties directly
- Test for hidden model attributes accessible via Livewire property binding
- Livewire method calls can be invoked directly without UI interaction -- test authorization on each public method
- File upload via Livewire temporary upload: test for path traversal in temporary file handling

### Validation Rule Bypass Chains
Laravel validation rules have exploitable edge cases:
- `regex:/[a-z]/` without anchors matches ANY string containing a lowercase letter -- not a full-string check
- `exists:table,column` rule can be used for data enumeration via timing differences
- `required_if` chains: satisfy one condition to skip validation on another field
- `sometimes` rule: field only validated if present -- omit the field entirely to bypass
- Stop-on-first-failure (`bail`) rules: trigger early failure to skip injection validation on later fields

## Validation Requirements

- .env exposure: file contents retrieved showing APP_KEY and credentials
- Debug mode: Ignition page with environment dump and stack trace
- Mass assignment: privilege field (is_admin, role_id) accepted and persisted
- Eloquent injection: data extraction or error-based confirmation of SQL manipulation
- Blade SSTI: server-side evaluation of injected template syntax
- Storage traversal: access to log files or files outside intended directory
- Dashboard access: Telescope/Horizon/Nova data viewed without authorization
- CSRF bypass: state-changing action executed cross-origin on session-authenticated endpoint
