---
name: upload-handler-enumeration
category: methodology
description: Source-tree enumeration of every multipart / file-upload handler with per-framework validation-chain audit
depends_on: [insecure_file_uploads]
---

# Upload Handler Enumeration

File-upload handlers concentrate a disproportionate share of high-impact bugs: stored XSS via SVG, RCE via parser CVE, path traversal via filename, server pollution via oversize, and content-type confusion via served-as-HTML. This skill enumerates every multipart handler in the source tree and audits the validation chain handler-by-handler.

## When to Use

- Any whitebox / hybrid scan with source access AND any handler that accepts file uploads
- Run after route mapping but before deep payload work — the candidate list it produces drives the dynamic probing phase

## Per-Framework Grep Recipes

Concrete commands the agent runs from the workspace root. Each finds upload handlers for one framework family.

### FastAPI (Python)
```bash
grep -rEn '(UploadFile|File\(|files: List\[UploadFile\])' --include='*.py' .
```

### Flask (Python)
```bash
grep -rEn '(request\.files|FileStorage)' --include='*.py' .
```

### Django (Python)
```bash
grep -rEn '(request\.FILES|UploadedFile|FileField|ImageField)' --include='*.py' .
```

### Express / Node
```bash
grep -rEn '(multer|formidable|busboy|multiparty)' --include='*.js' --include='*.ts' --include='*.tsx' .
```

### Rails
```bash
grep -rEn "(params\[:[a-z_]+\]\.read|ActionDispatch::Http::UploadedFile|has_attached_file|has_one_attached|has_many_attached)" --include='*.rb' .
```

### Spring (Java)
```bash
grep -rEn '(@RequestParam.*MultipartFile|MultipartHttpServletRequest|MultipartFile)' --include='*.java' --include='*.kt' .
```

### .NET / ASP.NET
```bash
grep -rEn '(IFormFile|HttpPostedFileBase|FromForm)' --include='*.cs' .
```

### Generic fallback
```bash
grep -rEn 'multipart/form-data' --include='*.py' --include='*.js' --include='*.ts' --include='*.rb' --include='*.java' --include='*.go' --include='*.php' --include='*.cs' .
```

For each match, walk back to identify the handler function and the route it serves. Build the candidate list:

```
(file:line, route, method, handler_function, framework)
```

## Per-Handler Validation-Chain Audit

For each handler in the candidate list, check the six validation steps. Each missing step is a finding-grade gap (combined into a single atomic finding per handler — see Reporting).

### 1. Extension validation

Is the filename's extension checked against an **allow-list** (not a deny-list)? Allow-list patterns:

- `if file.filename.endswith(('.png', '.jpg', '.gif')):`
- `ext in ALLOWED_EXTENSIONS`
- `mimetypes.guess_type(...)` followed by an allow-list check

Deny-list patterns are ALWAYS bypassable (`.phtml`, `.php5`, double extensions, null-byte injection, mixed case `.PhP`):

- `if not file.filename.endswith('.php'):` — bypassable
- `BLOCKED = ['.exe', '.sh']` — bypassable

### 2. Content-type validation against actual file magic bytes

Is the declared `Content-Type` validated against actual file magic bytes (not just trusted from the request header)? The header `Content-Type` is attacker-controlled. The actual content must be inspected — `python-magic`, `file -b`, `mimetypes` from filename + content cross-check.

Trust signals (`file.content_type == 'image/png'` without magic-byte check) → finding.

### 3. Size limit (per-file AND per-request)

- Per-file: `MAX_CONTENT_LENGTH`, `client_max_body_size`, framework-level cap
- Per-request: cumulative cap on a multipart request (multiple files combined)

Missing → DoS via large upload.

### 4. Filename path-traversal sanitization

Is the filename stripped of `..`, absolute paths, null bytes, and normalized? Patterns that look right:

- `werkzeug.utils.secure_filename(file.filename)`
- `os.path.basename(filename)` followed by allow-list character check
- UUID-rename instead of preserving filename

Patterns that look wrong:

- `f.save(os.path.join(UPLOAD_DIR, file.filename))` — direct concatenation, traversal vulnerable
- `open(file.filename, 'wb')` in any context that uses user-supplied filename

### 5. Storage path / served-back behavior

Where does the file end up after upload? Two questions:

- Is the storage directory web-accessible (under `static/`, `public/`, served by nginx `location /uploads/`)? If yes, the file can be requested back over HTTP.
- If served back, is the response `Content-Disposition: attachment` (forces download) or inline (renders in browser)? Inline + an unfiltered upload of `.html` / `.svg` / `.htm` → stored XSS.

### 6. Post-upload processing

Is the file passed to a parser? Each parser is a CVE-rich attack surface:

- **Image parsers**: PIL/Pillow (CVE-2022-22817 RCE via PIL.ImageMath.eval), ImageMagick (the entire `convert` family — historical RCEs), libvips
- **PDF parsers**: PyPDF2, pdfplumber, pdfminer
- **Archive parsers**: zipfile, tarfile (`extract_all()` with traversal-vulnerable members), 7z
- **Document parsers**: docx, xlsx, openpyxl
- **Office macros**: MS Office formats with macro execution

For each parser invoked: check the version against published CVEs. A pinned old version of Pillow / ImageMagick is a finding by itself.

## Probing Procedure (Dynamic)

For each handler that survives the validation-chain audit (i.e., looks safe), run the dynamic probes to confirm:

For each upload endpoint, send:

| Probe | Filename | Content-Type header | Content body | Expected | Anomaly = finding |
|---|---|---|---|---|---|
| 1 | `shell.php` | `image/png` | `<?php system($_GET['c']); ?>` | 4xx (extension reject) | 2xx + file served → RCE / stored payload |
| 2 | `xss.html` | `image/png` | `<script>alert(1)</script>` | 4xx | 2xx + served inline → stored XSS |
| 3 | `xss.svg` | `image/svg+xml` | `<svg onload="alert(1)"/>` | 4xx (SVG=script) | 2xx + served inline → stored XSS |
| 4 | `large.bin` | any | 10× declared size | 4xx (size limit) | 2xx → DoS |
| 5 | `../../../etc/passwd` | any | text | 4xx (filename reject) | 2xx → traversal |
| 6 | `image.png` (real PNG) with `<script>` comment chunk | `image/png` | crafted PNG | 2xx (it's a valid PNG) | response embeds the comment in HTML output → reflected XSS |
| 7 | `archive.zip` containing `../../../sensitive` | `application/zip` | crafted zip | 2xx (zip extracted) | path-traversal in extraction → file overwrite |

## Reporting

Group all missing-validation gaps for ONE handler into ONE atomic finding. Each missing step is a row inside the finding's "Affected validation steps" table:

```
Title: Insufficient validation in upload handler `POST /api/v1/disputes/{id}/evidence`
Location: backend/app/disputes.py:142
Affected validation steps:
| Step                            | Status          |
|---------------------------------|-----------------|
| Extension allow-list            | MISSING         |
| Content-type magic-byte check   | MISSING         |
| Size limit (per-file)           | PRESENT (10 MB) |
| Filename path-traversal sanit.  | PRESENT         |
| Storage served back inline      | YES (vulnerable)|
| Parser CVE check (Pillow 9.1.0) | OUTDATED        |
Severity: HIGH (stored XSS via SVG/HTML upload + outdated Pillow → RCE chain candidate)
PoC: probe 3 above returned 200 + inline rendering at /static/uploads/xss.svg
```

Multiple handlers → multiple findings (one per handler). Do NOT roll up across handlers — each is an atomic fix.

## Discovery Signals

| # | Signal | Where to Find | Why Vulnerable |
|---|--------|---------------|----------------|
| 1 | SCORM/LMS upload endpoint | Education platforms, `.aspx` apps | ZIP extraction without type filter -> webshell RCE (Report #1122791: DoD RCE via SCORM) |
| 2 | S3 upload destination in mobile app traffic | Burp proxy, APK strings | Misconfigured bucket perms: upload to arbitrary paths (Report #1021906) |
| 3 | WAV/DOCX/XLSX accepted as upload type | Media library, document import | Binary files contain XML metadata -> XXE (Report #1095645: WordPress WAV XXE) |
| 4 | ZIP/RAR/TAR import feature | Plugin upload, backup restore, config import | Zip Slip path traversal -> arbitrary file write ($1.2M -- Report #860186624) |
| 5 | SVG accepted as image format | Avatar, profile picture, thumbnails | SVG with `<script>` or `onload` -> stored XSS (Probe 3 in dynamic testing) |
| 6 | "Open URL" / "Open file" call in app code | grep for `openUrl`, `shell_exec`, `exec` | Scheme/extension allowlisting gaps (Report #1078002) |
| 7 | Image resize/processing after upload | PIL/Pillow, ImageMagick in stack | Parser CVEs: Pillow CVE-2022-22817, ImageMagick historical RCEs |
| 8 | `Content-Type` header not validated against body | Burp response after upload | MIME confusion: declared type trusted, actual content not checked |
| 9 | File served inline (no `Content-Disposition: attachment`) | Response headers on stored file | Uploaded HTML/SVG renders in browser -> stored XSS |
| 10 | Plugin/theme/extension upload | CMS admin, browser extension store | Malicious extension with broad permissions -> UXSS (Report #1026352640: $500K) |
| 11 | Backup restore / config import accepting ZIP | Admin panel, settings page | ZIP extraction to web root -> file overwrite -> RCE |
| 12 | File inclusion + any upload = RCE chain | LFI/include + upload endpoint | CMS with file inclusion param + upload -> require() webshell (Report #1102067) |

## Technique Matrix

| # | Technique | When | How |
|---|-----------|------|-----|
| 1 | SCORM package weaponization | Education/LMS platform | Valid `imsmanifest.xml` + `.aspx`/`.php` webshell in ZIP (Report #1122791) |
| 2 | Zip Slip path traversal | Any ZIP extraction endpoint | Archive entries with `../../../` prefix -> write outside target dir ($1.2M -- Report #860186624) |
| 3 | Binary XML metadata injection | WAV/DOCX/XLSX/TIFF upload | Embed XXE payload in iXML/XMP metadata chunk (Report #1095645) |
| 4 | Extension matrix testing | Every upload handler | `.php`, `.php5`, `.phtml`, `.phar`, `.htaccess`, `.aspx`, `.jsp`, double ext, null byte, case (Report #1081766) |
| 5 | Content-Type matrix testing | Cookie-authenticated POST | Test `application/json`, `multipart/form-data`, `text/xml`, missing header (Report #109278893) |
| 6 | Polyglot file crafting | Type validated by magic bytes | PNG header + PHP payload: passes magic check, executes as PHP |
| 7 | S3 bucket permission audit | Mobile app uploads to S3 | Capture upload URL, test listing, writing to other paths (Report #1021906) |
| 8 | File inclusion + upload chain | CMS with include param | Upload polyglot via avatar, include via LFI param -> RCE (Report #1102067) |
| 9 | `.htaccess` upload | Apache with per-directory config | Upload `.htaccess` enabling PHP execution in upload dir |
| 10 | Symlink-in-ZIP attack | ZIP extraction on Linux | Archive containing symlink -> read arbitrary server files |

## Defense-Bypass Pairs

| Defense | Bypass | Example |
|---------|--------|---------|
| Extension denylist (`.php` blocked) | `.phtml`, `.php5`, `.pHp`, double ext `.jpg.php`, null byte | Denylist never complete -- allowlist only |
| Content-Type header check | Mismatch: declare `image/png`, send PHP body | Header is attacker-controlled; magic bytes not checked |
| Magic-byte validation | Polyglot: real PNG header + PHP code after IEND | Passes magic check, PHP interprets from `<?php` |
| Web root upload blocked | Zip Slip: archive entries with `../../../web.config` | Extraction follows relative paths ($1.2M -- Report #860186624) |
| WAF blocks XML in request body | Embed XML in WAV/DOCX binary metadata | WAF inspects text body, not binary file internals (Report #1095645) |
| SVG `<script>` stripped | `<svg onload="fetch(...)">` event handler | Tag itself is allowed; event handler not stripped |
| Upload requires admin role | Any-user access to SCORM/plugin upload | Auth check missing on specialized upload endpoints (Report #1122791) |
| `nosniff` + `attachment` on stored files | Upload `.htaccess` to override serving behavior | Server config changed by uploaded file |

## Chain Patterns

| Chain | Step 1 | Step 2 | Impact |
|-------|--------|--------|--------|
| SCORM upload + webshell | Upload ZIP with valid manifest + `.aspx` shell | Browse to extracted shell path | RCE on DoD server (Report #1122791) |
| Zip Slip + config overwrite | Upload ZIP with `../../web.config` entry | Overwrite server config -> redirect traffic | Full server compromise ($1.2M) |
| WAV XXE + SSRF + Phar RCE | Upload WAV with XXE entity pointing to `phar://` | Server resolves entity -> deserialization | RCE chain (Report #1095645) |
| File inclusion + avatar upload | Upload polyglot PHP/PNG as avatar | Include avatar via LFI parameter | Webshell execution (Report #1102067) |
| S3 misconfig + data exfil | Upload endpoint reveals S3 bucket | List + download other users' files | Full data breach (Report #1021906) |
| Extension upload + UXSS | Upload browser extension with `<all_urls>` permission | Extension executes in every page context | Universal XSS ($500K -- Report #1026352640) |
| SVG upload + stored XSS + ATO | Upload SVG with `onload=fetch()` | Served inline -> cookie theft | Account takeover |
| Parser CVE + RCE | Upload crafted image triggering Pillow/ImageMagick CVE | Server processes -> code execution | RCE via dependency |

## Pro Tips from Corpus

1. **File upload deserves the most thorough single-feature audit in any web app.** Test the full matrix: extension, Content-Type, magic bytes, size, filename, serving behavior, parser CVEs (Report #1081766).
2. **ZIP upload endpoints are RCE goldmines.** Test authorization (any user?), type filter inside archive (`.aspx`/`.php`/`.jsp`?), path traversal in entries (`../../../`), extraction destination overlap with web root, and symlink following (Report #1122791, Report #860186624).
3. **Binary files hide XML.** WAV (iXML), DOCX/XLSX (embedded XML parts), TIFF (XMP), SVG (XML body) -- all can carry XXE payloads invisible to request-body WAFs (Report #1095645).
4. **Check the lockfile for parser versions.** `requirements.txt`, `package-lock.json`, `Gemfile.lock` -- a pinned old Pillow/ImageMagick is a finding by itself (Step 6 of validation chain).
5. **Content-Type matrix is mandatory for every upload.** Don't assume Content-Type is enforced; test `application/json`, `multipart/form-data`, `text/xml`, and missing header (Report #109278893).
6. **Mobile app S3 auditing is high-ROI.** Capture the upload destination URL, test bucket listing, writing to other paths, downloading other users' files (Report #1021906).
7. **File inclusion + any upload = RCE.** When you find LFI, look for any upload endpoint to chain. When you find upload, look for any include parameter to chain (Report #1102067).
8. **Specialized upload paths are under-tested.** SCORM courses, plugin/theme uploads, backup restore, config import -- these often have weaker auth than the main avatar/attachment upload (Report #1122791).
9. **Test SVG serving behavior, not just upload.** Even if SVG uploads succeed, check the response headers: `Content-Disposition: attachment` + `X-Content-Type-Options: nosniff` blocks script execution.

## Anti-Patterns

- Do NOT report "uses deny-list extension check" without demonstrating a real bypass with a working payload.
- Do NOT report "no size limit" without checking framework-level / reverse-proxy-level limits (nginx `client_max_body_size`, Cloudflare default, etc.).
- Do NOT report "stored XSS" without demonstrating script execution against a fresh browser session -- sometimes the storage path serves with `X-Content-Type-Options: nosniff` and `Content-Disposition: attachment`, making the inline-render impossible.
- Do NOT skip the parser-CVE step on grounds that the parser is patched-by-default -- check the lockfile (`requirements.txt`, `package-lock.json`, `Gemfile.lock`) for the actual pinned version.

## Composability

This skill composes with:
- `insecure_file_uploads` -- same vuln class, this skill is the source-tree enumeration counterpart
- `path_traversal_lfi_rfi` -- filename traversal is path-traversal in the upload context
- `rce` -- outdated parsers chain into RCE
- `xss` -- inline-served untrusted content is stored XSS
- `business_logic` + `invariant_extraction` -- upload endpoints often touch quota/storage accumulators that have their own invariants
