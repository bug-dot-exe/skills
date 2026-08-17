---
name: flask
description: Security testing playbook for Flask applications covering debug mode, Jinja2 SSTI, session tampering, and blueprint access control
depends_on: []
---

# Flask

Security testing for Flask applications. Focus on debug mode exposure (Werkzeug debugger PIN), secret_key management, Jinja2 server-side template injection, client-side session tampering, blueprint-level access control gaps, and CORS misconfiguration.

## Attack Surface

**Core Configuration**
- `app.debug` / `FLASK_DEBUG`: Werkzeug interactive debugger with console
- `app.secret_key` / `SECRET_KEY`: signs sessions, flash messages, itsdangerous tokens
- `TESTING`, `ENV`, `SERVER_NAME` settings affecting behavior

**Routing & Blueprints**
- Blueprints with `url_prefix`: scoped route registration, per-blueprint `before_request`
- Route decorators: `@app.route`, `@blueprint.route`, method restrictions
- `@app.before_request`, `@app.after_request` hooks at app and blueprint level
- Error handlers: `@app.errorhandler` custom pages

**Session & Auth**
- Client-side signed cookies (itsdangerous/URLSafeTimedSerializer)
- Flask-Login: `login_required`, `current_user`, remember-me tokens
- Flask-Security, Flask-JWT-Extended, Flask-Dance (OAuth)

**Templates**
- Jinja2 with autoescape on `.html`/`.htm`/`.xml` by default
- Non-HTML templates (`.txt`, `.md`, `.json`) may lack autoescape
- Custom filters, globals, extensions

**Extensions**
- Flask-CORS: cross-origin configuration
- Flask-WTF: CSRF protection via WTForms
- Flask-Admin: admin interface
- Flask-RESTful / Flask-RESTX: API with Swagger UI
- Flask-SQLAlchemy: ORM layer
- Flask-Mail: email sending

**File Handling**
- `request.files`, `send_file()`, `send_from_directory()`
- Static file serving: `/static/` default mount

## High-Value Targets

- Werkzeug debugger console (`/console` when debug=True)
- Flask-Admin panel (commonly `/admin/`)
- Swagger/API docs (`/api/docs`, `/apidocs`, `/swagger`, `/swagger-ui`)
- Static directory serving potentially leaking source, configs, or `.env`
- Session cookies: decode and inspect for privilege fields
- Password reset / email verification token endpoints
- File upload and download endpoints
- Flask-RESTX/Flask-RESTful auto-generated endpoints

## Reconnaissance

**Debug Mode Detection**
```
GET /nonexistent-triggering-500
```
Werkzeug debugger page with interactive console, traceback, and local variables. The debugger PIN protects console access but the traceback itself leaks code and configuration.

**Debugger PIN Calculation**
When debug mode is active, the PIN is derived from:
- `username` running the app (from `/etc/passwd` or `/proc/self/environ`)
- `flask.app` or `werkzeug.debug` modname
- Class name: `Flask` or `DebuggedApplication`
- App module path: from `/proc/self/cmdline` or traceback
- Machine ID: `/etc/machine-id` or `/proc/sys/kernel/random/boot_id`
- MAC address: `/sys/class/net/{iface}/address` or `/proc/net/if_inet6`

If any of these leak via LFI, SSRF, or error pages, the PIN can be calculated to unlock the interactive console (RCE).

**Endpoint Discovery**
```
GET /static/
GET /admin/
GET /api/
GET /apidocs
GET /swagger-ui
GET /console
```

**Session Decoding**
Flask sessions are base64-encoded JSON signed with itsdangerous. Decode without the key to inspect structure:
```
echo "SESSION_COOKIE" | base64 -d
```
Or use `flask-unsign --decode --cookie 'VALUE'`.

## Key Vulnerabilities

### Debug Mode (Werkzeug Debugger)

**Interactive Console RCE**
- Debug=True in production exposes `/console` with interactive Python shell
- PIN-protected but calculable from leaked system information
- Even without PIN: traceback pages reveal source code, local variables, configuration

**Information Disclosure**
- Full stack traces with source code context
- Local variable dumps including database connections, API keys, secrets
- Request/response data in debug output
- Application module paths revealing deployment structure

### Secret Key Exposure

**Session Forgery**
- Flask sessions are client-side (signed cookies). With `secret_key`:
  - Decode and modify session data (user ID, role, permissions)
  - Forge admin sessions
  - Generate valid CSRF tokens (Flask-WTF)
  - Create valid itsdangerous tokens (password reset, email verification)

**Common Exposure Vectors**
- Hardcoded in source: `app.secret_key = 'supersecret'`
- Default/weak keys: `'dev'`, `'secret'`, `'changeme'`, empty string
- Git history, `.env` files, Docker images, error pages
- `flask-unsign --unsign --cookie 'VALUE' --wordlist wordlist.txt` for brute force

### Jinja2 SSTI

**Template Injection**
```python
# Vulnerable patterns
render_template_string(user_input)
Template(user_input).render()
render_template_string("Hello " + name)
```

**Exploitation**
```
{{ 7*7 }}                    # Confirm injection (49)
{{ config }}                 # Dump Flask config (SECRET_KEY, DB creds)
{{ config.items() }}         # All configuration
{{ request.environ }}        # WSGI environment

# RCE via class traversal
{{ ''.__class__.__mro__[2].__subclasses__() }}
{{ cycler.__init__.__globals__['os'].popen('id').read() }}
{{ request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__init__.__globals__['os'].popen('id').read() }}
```

**Autoescape Bypass**
- Non-HTML templates (`.txt`, `.json`, `.xml` without explicit config) have autoescape disabled
- `{% autoescape false %}` blocks
- Custom Jinja2 Environment with `autoescape=False`
- `|safe` filter applied to user input
- `Markup()` wrapping user input

### Session Cookie Tampering

**Client-Side Session Risks**
- All session data visible to the client (base64-encoded, not encrypted)
- Structure inspection reveals: user IDs, roles, permissions, CSRF tokens
- Without secret_key: read-only. With secret_key: full read-write.

**Cookie Attributes**
- Missing `Secure` flag: session sent over HTTP
- Missing `HttpOnly`: JavaScript access to session cookie
- Missing `SameSite`: cross-site request attachment
- `SESSION_COOKIE_DOMAIN` too broad: cookie shared across subdomains

### Blueprint Access Control

**Missing Authentication**
- `@login_required` on individual routes but not via `@blueprint.before_request`
- New routes added to a blueprint without inheriting auth checks
- Blueprint registered without URL prefix, overlapping with unprotected routes

**Inconsistent Authorization**
- Different blueprints enforce different permission models
- Admin blueprint accessible to regular users due to missing role checks
- API blueprint skipping CSRF (intentional for token auth) but also serving session-authenticated requests

### CORS Misconfiguration

**Flask-CORS Issues**
```python
# Dangerous configurations
CORS(app, origins="*", supports_credentials=True)  # Invalid but may be misconfigured
CORS(app, origins=r"https://.*\.example\.com")      # Regex too broad
CORS(app, origins=["null"])                          # null origin allowed
```

- `supports_credentials=True` with reflected or overly broad origins
- Regex patterns matching attacker-controlled subdomains
- Per-resource CORS overriding stricter app-level defaults

### SQL Injection (Flask-SQLAlchemy)

**Raw Query Patterns**
```python
db.engine.execute("SELECT * FROM users WHERE name = '%s'" % name)
db.session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_input})  # Safe
db.session.execute("SELECT * FROM users WHERE id = " + user_input)  # Vulnerable
```

**ORM Filter Injection**
```python
User.query.filter_by(**request.args.to_dict())  # kwargs injection
```

### File Handling

**Path Traversal**
- `send_file(user_input)` or `send_from_directory()` with unsanitized filenames
- `request.files['file'].filename` used directly for storage path
- `/static/` serving from application root instead of dedicated directory

**Unrestricted Upload**
- Missing file type validation
- Executable files uploaded and accessible via static serving

## Bypass Techniques

- Method switching: route allows GET and POST but auth only checks POST
- Blueprint prefix manipulation to hit routes outside expected namespace
- Content-type switching: JSON vs form-encoded hitting different parsing paths
- Exception handler differences between blueprints leaking information
- `X-Forwarded-For` / `X-Forwarded-Proto` trusted without proxy configuration (`ProxyFix`)

## Testing Methodology

1. **Debug detection** - Trigger errors to detect Werkzeug debugger; attempt PIN calculation from leaked data
2. **Secret key audit** - Decode session cookies to inspect structure; brute force with `flask-unsign`
3. **SSTI probing** - Inject `{{7*7}}` in all user-reflected inputs; test non-HTML template contexts
4. **Session analysis** - Decode cookies, check attributes (Secure, HttpOnly, SameSite), test forgery
5. **Blueprint mapping** - Enumerate all blueprints, verify auth enforcement per-blueprint and per-route
6. **CORS validation** - Test with null origin, reflected origin, subdomain variations
7. **SQL injection** - Identify raw query patterns, test ORM filter kwargs injection
8. **File operations** - Test path traversal in uploads/downloads, check static directory scope

## Corpus-Derived Attack Patterns

### Observability and Error Tracking Interface Exposure

Flask applications integrate error tracking tools (Sentry, Rollbar, Bugsnag) that expose their own web interfaces. These interfaces leak stack traces, environment variables, source code, and user data.
- Probe for Sentry: `/sentry/`, `/_sentry/`, check for `X-Sentry-Error` response headers, `sentry-trace` headers
- Generic telemetry endpoints: `/debug/vars`, `/metrics`, `/prometheus`, `/_stats`, `/status`
- Sentry DSN (Data Source Name) in page source or JavaScript: the DSN itself reveals the internal Sentry instance URL and project ID
- If Sentry web UI is accessible: browse error events for stack traces containing secrets, database credentials, API keys, and internal URLs

### Debug Credentials in Production Trust Stores

Applications may ship with development signing keys, debug certificates, or test API credentials that remain trusted in production. These enable authentication bypass or token forgery.
- Search for hardcoded hashes in source or decompiled packages -- hash preimages are often recoverable via public hash databases or rainbow tables
- Check if `FLASK_DEBUG`, `TESTING`, or development configuration is active by probing for Werkzeug debugger and comparing session cookie behavior
- `flask-unsign` brute-force with development-key wordlist: `dev`, `secret`, `changeme`, `development`, `testing`, `flask-secret`, app name, domain name
- Debug keystores or certificates in mobile apps that trust the same backend: decompile APK/IPA and extract signing keys

### Pickle Deserialization via Error Handling Tools

Flask applications using Sentry, Celery, or custom error handlers may deserialize pickled objects from untrusted sources. Pickle deserialization in Python enables arbitrary code execution.
- Sentry with pickle serializer: error event payloads containing pickled objects
- Celery task serialization: if `CELERY_TASK_SERIALIZER = 'pickle'` or `CELERY_ACCEPT_CONTENT` includes `pickle`, any message broker injection leads to RCE
- Redis/Memcached session backends storing pickled session data: session forgery + pickle RCE if `SECRET_KEY` is known
- Flask-Caching with pickle serializer: cache poisoning via crafted cache keys leads to deserialization

### Unsafe YAML Deserialization

Flask applications processing YAML input (configuration upload, API input, template import) using `yaml.load()` without `Loader=SafeLoader` enable arbitrary code execution.
- Grep for unsafe patterns: `yaml.load(`, `yaml.unsafe_load(`, `yaml.full_load(` -- all allow arbitrary Python object instantiation
- Test with payload: `!!python/object/apply:os.system ['id']` or `!!python/object/new:subprocess.check_output [['id']]`
- Configuration file upload endpoints, infrastructure-as-code inputs, and data import features are common injection points
- Even `yaml.safe_load()` may be bypassed in older PyYAML versions (pre-5.1) via `!!python/object/apply` tags

### Environment Variable and Debug Endpoint Disclosure

Flask applications expose environment variables and configuration through debug artifacts that persist in production.
- Probe systematically: `/env`, `/environ`, `/debug`, `/config`, `/info`, `/server-info`, `/_debug`, `/internal/config`
- `phpinfo()`-equivalent for Python: custom health check endpoints dumping `os.environ`, `app.config`, or `sys.path`
- Flask-DebugToolbar: `/__debugtoolbar/`, intercept panels exposing SQL queries, template context, request headers
- Error pages with `PROPAGATE_EXCEPTIONS=True` or custom error handlers that dump `traceback.format_exc()` including local variables

### Log File Credential Disclosure

Flask applications logging to files accessible via the web server leak credentials, tokens, and internal state through predictable log file paths.
- Check standard paths: `/log.txt`, `/error.log`, `/debug.log`, `/access.log`, `/app.log`, `/flask.log`
- Framework-specific: `/logs/`, `/var/log/`, `../logs/app.log` via path traversal
- Credentials appear in logs when: DEBUG logging is active, authentication middleware logs request headers (including `Authorization`), or exception handlers log full request context
- Structured logging (JSON logs) may be served if the log directory is within the static file serving path

### Shared Secret Key Token Chain Exploitation

Flask uses a single `SECRET_KEY` for multiple security functions. When the obvious token is hardened, audit every other token signed by the same key.
- Same key signs: session cookies, Flask-WTF CSRF tokens, itsdangerous tokens (password reset, email verification, invite links), Flask-Login remember-me tokens
- If session cookie forgery is mitigated (server-side validation), test: password reset token forgery, email verification token generation, invitation link creation
- `itsdangerous.URLSafeTimedSerializer` tokens can be forged with the key to generate valid tokens for any purpose the application uses
- Multi-application deployments sharing `SECRET_KEY`: forge tokens on one application, use on another

## Validation Requirements

- Debug mode: Werkzeug debugger page with interactive console or traceback exposing sensitive data
- Secret key: forged session cookie accepted by the server (e.g., privilege escalation)
- SSTI: server-side evaluation confirmed (`{{7*7}}` returning `49`, config dump, or RCE)
- Session tampering: modified session cookie changing server behavior (role change, user switch)
- Blueprint bypass: authenticated request to a protected blueprint route without valid credentials
- CORS: cross-origin request with credentials returning sensitive data
- SQLi: data extraction or error-based confirmation of query manipulation
- Pickle RCE: crafted pickle payload triggering code execution via deserialization endpoint or cache poisoning
- Log/env disclosure: credentials or secrets retrieved from accessible log files or environment endpoints
