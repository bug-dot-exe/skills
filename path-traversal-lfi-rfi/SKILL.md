---
name: path-traversal-lfi-rfi
description: Path traversal and file inclusion testing for local/remote file access and code execution
depends_on: []
---

# Path Traversal / LFI / RFI

Improper file path handling and dynamic inclusion enable sensitive file disclosure, config/source leakage, SSRF pivots, and code execution. Treat all user-influenced paths, names, and schemes as untrusted; normalize and bind them to an allowlist or eliminate user control entirely.

## Attack Surface

**Path Traversal**
- Read files outside intended roots via `../`, encoding, normalization gaps

**Local File Inclusion (LFI)**
- Include server-side files into interpreters/templates

**Remote File Inclusion (RFI)**
- Include remote resources (HTTP/FTP/wrappers) for code execution

**Archive Extraction**
- Zip Slip: write outside target directory upon unzip/untar

**Normalization Mismatches**
- Server/proxy differences (nginx alias/root, upstream decoders)
- OS-specific paths: Windows separators, device names, UNC, NT paths, alternate data streams

## Discovery Signals

| Signal | Where to Find | Why Vulnerable |
|---|---|---|
| File download endpoint with `file=` or `path=` param | URL analysis | Direct file reference without validation |
| Image/thumbnail resizer with URL input | Feature scan | `?image=/path/to/file` often traversal-vulnerable |
| Template/theme selector with user input | Feature scan | `?template=user_theme` → `?template=../../etc/passwd` |
| PDF/report generator with dynamic content | Feature scan | Server reads files for report inclusion |
| Log viewer or file browser UI | Admin panel | Direct filesystem access with traversal potential |
| Import/export with file path | Feature scan | File path in upload/download handler |
| Language/locale file loader | Feature scan | `?lang=en` → `?lang=../../etc/passwd%00` |
| Archive upload (ZIP/TAR) processing | Feature scan | Zip Slip: files with `../` in paths escape extraction dir |
| nginx with `alias` directive | Server config fingerprint | Missing trailing slash in alias = path escape |
| Static file server (Express static, Apache) | Framework fingerprint | Middleware path normalization differences |
| Avatar/profile picture upload | Feature scan | Filename stored without sanitization |
| Backup/restore feature | Admin panel | Restore from user-specified path |

## File Targets by Technology Stack

| Stack | High-Value Files | What They Contain |
|---|---|---|
| **Linux (any)** | `/etc/passwd`, `/etc/shadow`, `/etc/hosts`, `/proc/self/environ`, `/proc/self/cmdline` | User list, password hashes, environment variables |
| **Windows (any)** | `C:\Windows\win.ini`, `C:\Windows\System32\drivers\etc\hosts`, `C:\inetpub\wwwroot\web.config` | System config, IIS config |
| **Node.js** | `package.json`, `.env`, `node_modules/.package-lock.json` | Dependencies, secrets, exact versions |
| **Python/Django** | `settings.py`, `.env`, `requirements.txt`, `manage.py` | SECRET_KEY, DB credentials, app structure |
| **Python/Flask** | `app.py`, `config.py`, `.env`, `instance/config.py` | App config, secret key |
| **PHP** | `wp-config.php`, `.env`, `config.php`, `/etc/php.ini` | DB creds, salts, PHP config |
| **Java/Spring** | `application.properties`, `application.yml`, `WEB-INF/web.xml` | DB connection, cloud keys |
| **Ruby/Rails** | `config/database.yml`, `config/secrets.yml`, `config/master.key` | DB creds, encryption key |
| **Docker** | `/.dockerenv`, `/proc/1/cgroup`, `docker-compose.yml` | Container detection, service map |
| **Cloud** | `/proc/self/environ` (for AWS_*), `~/.aws/credentials`, `~/.config/gcloud/credentials.db` | Cloud provider credentials |
| **SSH** | `~/.ssh/id_rsa`, `~/.ssh/authorized_keys`, `~/.ssh/known_hosts` | Private keys, server list |
| **Git** | `.git/config`, `.git/HEAD`, `.git/index` | Repository info, source reconstruction |

## Reconnaissance

### Surface Map

- HTTP params: `file`, `path`, `template`, `include`, `page`, `view`, `download`, `export`, `report`, `log`, `dir`, `theme`, `lang`
- Upload and conversion pipelines: image/PDF renderers, thumbnailers, office converters
- Archive extract endpoints and background jobs; imports with ZIP/TAR/GZ/7z
- Server-side template rendering (PHP/Smarty/Twig/Blade), email templates, CMS themes/plugins
- Reverse proxies and static file servers (nginx, CDN) in front of app handlers

### Capability Probes

- Path traversal baseline: `../../etc/hosts` and `C:\Windows\win.ini`
- Encodings: `%2e%2e%2f`, `%252e%252e%252f`, `..%2f`, `..%5c`, mixed UTF-8 (`%c0%2e`), Unicode dots and slashes
- Normalization tests: `..../`, `..\\`, `././`, trailing dot/double dot segments; repeated decoding
- Absolute path acceptance: `/etc/passwd`, `C:\Windows\System32\drivers\etc\hosts`
- Server mismatch: `/static/..;/../etc/passwd` ("..;"), encoded slashes (`%2F`), double-decoding via upstream

## Detection Channels

### Direct

- Response body discloses file content (text, binary, base64)
- Error pages echo real paths

### Error-Based

- Exception messages expose canonicalized paths or `include()` warnings with real filesystem locations

### OAST

- RFI/LFI with wrappers that trigger outbound fetches (HTTP/DNS) to confirm inclusion/execution

### Side Effects

- Archive extraction writes files unexpectedly outside target
- Verify with directory listings or follow-up reads

## Key Vulnerabilities

### Path Traversal Bypasses

**Encoding Variant Matrix**

| Encoding | Pattern | Use When |
|---|---|---|
| Standard | `../` | Always try first |
| URL-encoded | `%2e%2e%2f` or `..%2f` | WAF/filter blocks literal `../` |
| Double URL-encoded | `%252e%252e%252f` | Proxy decodes once, app decodes again |
| UTF-8 overlong | `%c0%ae%c0%ae%c0%af` | Some parsers accept overlong sequences |
| Unicode | `..%ef%bc%8f` (fullwidth `/`) | Unicode normalization inconsistency |
| Backslash | `..\` or `..%5c` | Windows servers, or mixed OS handling |
| Double-dot variants | `....//`, `..../`, `....\/` | Filters strip single `../` but not doubled |
| Null byte | `../../../etc/passwd%00.png` | Old PHP/Java truncation at null byte |
| Semicolon (Tomcat) | `..;/..;/etc/passwd` | Tomcat treats `;` as parameter delimiter |
| Mixed separators | `..\/..\/etc/passwd` | Cross-platform path handling |
| Tab/newline | `..%09/`, `..%0a/` | Whitespace in path component |
| Absolute path | `/etc/passwd` (no ../) | Some apps prefix but accept absolute paths |

**Dot Tricks**
- `....//` (double dot folding), trailing dots (Windows), trailing slashes, appended valid extension

**Alias/Root Mismatch**
- nginx alias without trailing slash with nested location allows `../` to escape
- Try `/static/../etc/passwd` and ";" variants (`..;`)

**Upstream vs Backend Decoding**
- Proxies/CDNs decoding `%2f` differently; test double-decoding and encoded dots

### nginx Path Normalization Bugs

Specific nginx misconfigurations that enable path traversal:

```nginx
# VULNERABLE: alias without trailing slash
location /static {
    alias /var/www/static;
}
# Request: /static../etc/passwd -> reads /var/www/etc/passwd

# VULNERABLE: root with location merge
location /files {
    root /var/www;
}
# Request: /files/../../../etc/passwd -> traversal possible

# VULNERABLE: try_files with user input
location / {
    try_files $uri $uri/ /index.php?file=$uri;
}
# $uri contains traversal -> passed to PHP
```

Also test: `..;/` (semicolon bypass for Tomcat behind nginx), `%2f` vs `/` (nginx may not decode but backend does).

### LFI Wrappers and Techniques

**PHP Wrappers**
- `php://filter/convert.base64-encode/resource=index.php` (read source)
- `zip://archive.zip#file.txt`
- `data://text/plain;base64`
- `expect://` (if enabled)

**Log/Session Poisoning**
- Inject PHP/templating payloads into access/error logs or session files then include them

**Upload Temp Names**
- Include temporary upload files before relocation; race with scanners

**Proc and Caches**
- `/proc/self/environ` and framework-specific caches for readable secrets

**Legacy Tricks**
- Null-byte (`%00`) truncation in older stacks; path length truncation

### LFI to RCE Escalation Paths

| Technique | Prerequisite | Steps |
|---|---|---|
| **Log poisoning** | LFI + write to log file | Inject PHP payload into User-Agent, request to create log entry, LFI include the log file, code execution |
| **Session file poisoning** | LFI + PHP sessions on disk | Write PHP payload into session data, LFI include session file `/tmp/sess_xxx`, code execution |
| **PHP wrapper chains** | LFI in PHP | `php://filter/convert.iconv.UTF-8.CSISO2022KR\|...\|.../resource=/etc/passwd` to write arbitrary file content via filter chain |
| **/proc/self/environ** | LFI + environment write | If HTTP_USER_AGENT or similar in environ, inject payload, include `/proc/self/environ` |
| **Upload + traverse** | File upload + LFI | Upload file with PHP payload (.php in .jpg), LFI include the uploaded file, code execution |
| **Zip wrapper** | LFI in PHP + file upload | Upload ZIP containing PHP file, `zip://uploaded.zip#shell.php`, code execution |
| **Phar deserialization** | LFI in PHP + file upload | Upload phar archive, `phar://uploaded.jpg/shell`, deserialization RCE |
| **Expect wrapper** | LFI + expect:// enabled | `expect://id` for direct command execution (rare, but check) |
| **Mail log** | LFI + SMTP | Send email with PHP payload in subject/body, LFI include `/var/log/mail.log` |
| **SSH log** | LFI + SSH access | SSH login with PHP payload as username, LFI include `/var/log/auth.log` |

### Template Engines

- PHP include/require; Smarty/Twig/Blade with dynamic template names
- Java/JSP/FreeMarker/Velocity; Node.js ejs/handlebars/pug engines
- Seek dynamic template resolution from user input (theme/lang/template)

### RFI Conditions

**Requirements**
- Remote includes (`allow_url_include`/`allow_url_fopen` in PHP)
- Custom fetchers that eval/execute retrieved content
- SSRF-to-exec bridges

**Protocol Handlers**
- http, https, ftp; language-specific stream handlers

**Exploitation**
- Host a minimal payload that proves code execution
- Prefer OAST beacons or deterministic output over heavy shells
- Chain with upload or log poisoning when remote includes are disabled

### Archive Extraction (Zip Slip)

- Files within archives containing `../` or absolute paths escape target extract directory
- Test multiple formats: zip/tar/tgz/7z
- Verify symlink handling and path canonicalization prior to write
- Impact: overwrite config/templates or drop webshells into served directories

**Zip Slip by Archive Type**

| Archive Type | Vulnerability | Test |
|---|---|---|
| ZIP | Entry name `../../../tmp/evil.php` | Create ZIP with python: `zipfile.write('evil.php', '../../../tmp/evil.php')` |
| TAR | Symlink entry pointing outside extract dir | Create tar with symbolic link to `/etc/passwd` |
| TAR.GZ | Same as TAR, compressed | Gzip the malicious tar |
| 7z | Same traversal patterns | Less commonly tested = more likely vulnerable |
| Java JAR | JAR is ZIP format | Same exploitation as ZIP |
| XLSX/DOCX | Office formats are ZIP | Malicious file entries in office documents |

## Testing Methodology

1. **Inventory file operations** - Downloads, previews, templates, logs, exports/imports, report engines, uploads, archive extractors
2. **Identify input joins** - Path joins (base + user), include/require/template loads, resource fetchers, archive extract destinations
3. **Probe normalization** - Separators, encodings, double-decodes, case, trailing dots/slashes
4. **Compare behaviors** - Web server vs application behavior
5. **Escalate** - From disclosure (read) to influence (write/extract/include), then to execution (wrapper/engine chains)

## Validation

1. Show a minimal traversal read proving out-of-root access (e.g., `/etc/hosts`) with a same-endpoint in-root control
2. For LFI, demonstrate inclusion of a benign local file or harmless wrapper output (`php://filter` base64 of index.php)
3. For RFI, prove remote fetch by OAST or controlled output; avoid destructive payloads
4. For Zip Slip, create an archive with `../` entries and show write outside target (e.g., marker file read back)
5. Provide before/after file paths, exact requests, and content hashes/lengths for reproducibility

## False Positives

- In-app virtual paths that do not map to filesystem; content comes from safe stores (DB/object storage)
- Canonicalized paths constrained to an allowlist/root after normalization
- Wrappers disabled and includes using constant templates only
- Archive extractors that sanitize paths and enforce destination directories

## Impact

- Sensitive configuration/source disclosure → credential and key compromise
- Code execution via inclusion of attacker-controlled content or overwritten templates
- Persistence via dropped files in served directories; lateral movement via revealed secrets
- Supply-chain impact when report/template engines execute attacker-influenced files

## Pro Tips

1. Compare content-length/ETag when content is masked; read small canonical files (hosts) to avoid noise
2. Test proxy/CDN and app separately; decoding/normalization order differs, especially for `%2f` and `%2e` encodings
3. For LFI, prefer `php://filter` base64 probes over destructive payloads; enumerate readable logs and sessions
4. Validate extraction code with synthetic archives; include symlinks and deep `../` chains
5. Use minimal PoCs and hard evidence (hashes, paths). Avoid noisy DoS against filesystems
6. Try reading `/proc/self/environ` first on Linux — it contains all environment variables including database credentials and API keys, and it is world-readable
7. When path traversal is confirmed, immediately check for LFI-to-RCE escalation — log/session poisoning takes minutes and upgrades severity from Medium to Critical
8. Test the `..;/` pattern (semicolon) on any Tomcat/Java backend — this is the most common bypass for Java-based path traversal filters
9. Always try both `../` and `..\` — many filters check one separator but not the other
10. For Zip Slip, test with symbolic links too — some extractors check for `../` but not symlinks pointing outside the extraction directory
11. Check `/proc/self/cgroup` to detect Docker containers — if containerized, the traversal may be sandboxed, but container escapes via shared volumes exist
12. CSPT (Client-Side Path Traversal): any URL-bar parameter that becomes a path segment in a same-origin API call is a candidate -- `?next=../admin/settings` in client-side routing ($1.5M)
13. Trace metadata-derived filenames: EXIF data, PDF metadata, Office doc properties extracted and used for storage naming -- inject traversal into metadata fields ($12K)
14. Static-asset paths (`/assets/`, `/static/`, `/_next/static/`) are classic LFI surfaces that newer audits forget -- test traversal on every static file handler ($313K)
15. Archive-format path traversal applies to ALL package formats: `.gem`, `.whl`, `.deb`, `.nupkg`, `.crate` -- not just ZIP/TAR ($1K)

## Summary

Eliminate user-controlled paths where possible. Otherwise, resolve to canonical paths and enforce allowlists, forbid remote schemes, and lock down interpreters and extractors. Normalize consistently at the boundary closest to IO.
