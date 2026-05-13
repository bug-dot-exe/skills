---
name: insecure-file-uploads
description: File upload security testing covering extension bypass, content-type manipulation, and path traversal
depends_on: []
---

# Insecure File Uploads

Upload surfaces are high risk: server-side execution (RCE), stored XSS, malware distribution, storage takeover, and DoS. Modern stacks mix direct-to-cloud uploads, background processors, and CDNs—authorization and validation must hold across every step.

## Attack Surface

- Web/mobile/API uploads, direct-to-cloud (S3/GCS/Azure) presigned flows, resumable/multipart protocols (tus, S3 MPU)
- Image/document/media pipelines (ImageMagick/GraphicsMagick, Ghostscript, ExifTool, PDF engines, office converters)
- Admin/bulk importers, archive uploads (zip/tar), report/template uploads, rich text with attachments
- Serving paths: app directly, object storage, CDN, email attachments, previews/thumbnails

## Discovery Signals

Fingerprints that indicate upload testing opportunities:

| Signal | Where to Find | What It Reveals |
|--------|--------------|-----------------|
| `multipart/form-data` in requests | Proxy history | Direct upload endpoint |
| `X-Amz-Algorithm` / `X-Goog-Signature` | Upload URLs | Presigned direct-to-cloud upload |
| `tus-resumable` header | Upload responses | Resumable protocol; test metadata swap between init and finalize |
| Thumbnails/previews differ from original | Compare upload vs served file | Server-side transcoding pipeline (ImageMagick/FFmpeg/libvips) |
| `X-Content-Type-Options` header absent | Download response | Browser MIME sniffing possible |
| `Content-Disposition: inline` | Download response | Browser renders file directly; XSS surface |
| Same-origin serving (no CDN subdomain) | Download URL | Uploaded file shares cookies/JS context with app |
| `policy` + `signature` in form fields | Hidden form fields | S3 POST policy; decode base64 policy to find allowed types/keys |
| `.php-fpm` or `X-Powered-By: PHP` | Server headers | PHP execution; test `.phtml`, `.phar`, `.user.ini` uploads |
| `Server: IIS` or `X-AspNet-Version` | Server headers | Test `.asp`, `.aspx`, `.config`, `.ashx` uploads |
| Rich text editor (Trix/CKEditor/TinyMCE) | Page source | Embedded attachment uploads; separate sanitization paths |
| Import/export features | Application UI | Deserialization path; test archive traversal, XML injection |
| Video re-encoding (different resolution/codec) | Compare uploaded vs served video | FFmpeg server-side; test HLS playlist injection for SSRF/LFI |
| `CarrierWave` / `Paperclip` / `Active Storage` | Ruby gem dependencies | Framework auto-defines `remote_<field>_url=` setter; SSRF via deserialization |
| Profile photo / avatar endpoint | User settings | Often separate pipeline from main uploads; weaker validation |
| Graffiti / drawing / canvas save | Rich UI features | Custom binary format upload; may eval response or proxy through app origin |

## Reconnaissance

### Surface Map

- Endpoints/fields: upload, file, avatar, image, attachment, import, media, document, template
- Direct-to-cloud params: key, bucket, acl, Content-Type, Content-Disposition, x-amz-meta-*, cache-control
- Resumable APIs: create/init -> upload/chunk -> complete/finalize; check if metadata/headers can be altered late
- Background processors: thumbnails, PDF->image, virus scan queues; identify timing and status transitions

### Capability Probes

- Small probe files of each claimed type; diff resulting Content-Type, Content-Disposition, and X-Content-Type-Options on download
- Magic bytes vs extension: JPEG/GIF/PNG headers; mismatches reveal reliance on extension or MIME sniffing
- SVG/HTML probe: do they render inline (text/html or image/svg+xml) or download (attachment)?
- Archive probe: simple zip with nested path traversal entries and symlinks to detect extraction rules

## Extension Bypass Matrix

| Server/Runtime | Executable Extensions | Double Extension | Null Byte | Case Tricks | Config Overrides |
|---|---|---|---|---|---|
| Apache + mod_php | `.php`, `.php5`, `.php7`, `.phtml`, `.pht` | `shell.php.jpg` (if `AddHandler` active) | `shell.php%00.jpg` (legacy) | `.pHp`, `.PhAR` | `.htaccess` (`AddType`/`AddHandler`), `.user.ini` (`auto_prepend_file`) |
| Nginx + PHP-FPM | `.php` (per location block) | Depends on `security.limit_extensions` | N/A on modern | Case sensitive (Linux) | `.user.ini` if PHP-FPM reads it per-dir |
| IIS + ASP.NET | `.asp`, `.aspx`, `.ashx`, `.asmx`, `.config` | `shell.asp;.jpg` (semicolon truncation) | `shell.asp%00.jpg` (IIS6) | `.aSp`, `.AsPx` (IIS case-insensitive) | `web.config` (add MIME mappings, enable handlers) |
| Tomcat/Java | `.jsp`, `.jspx`, `.jspa`, `.war` | `shell.jsp.jpg` (if default servlet serves) | N/A | `.JsP` on Windows | Deploy `.war` via management upload |
| Node.js (Express) | `.js`, `.mjs` (if `static` serves from upload dir) | N/A (no built-in execution mapping) | N/A | N/A | `package.json` in upload dir can affect module resolution |
| Python (Django/Flask) | `.py` (if WSGI misconfigured) | N/A | N/A | N/A | N/A (execution requires explicit route) |
| Ruby on Rails | `.erb`, `.rb` (if served by asset pipeline) | N/A | N/A | N/A | N/A |
| Cloudflare Workers/Lambda@Edge | N/A (no filesystem execution) | N/A | N/A | N/A | Override `Content-Type` via metadata to get inline HTML rendering |

## Content-Type Confusion

| Attack | Upload Content-Type | Served Content-Type | Impact | Condition |
|--------|-------------------|-------------------|--------|-----------|
| SVG XSS | `image/svg+xml` | `image/svg+xml` | Stored XSS via `<script>` or event handlers | Served inline without CSP sandbox |
| HTML sniffing | `image/jpeg` | `image/jpeg` (no `nosniff`) | Browser sniffs HTML from polyglot; script executes | Missing `X-Content-Type-Options: nosniff` |
| Content-Type override in presigned URL | Attacker sets `text/html` | `text/html` | Full HTML/JS execution from storage origin | Presigned upload does not force Content-Type server-side |
| Content-Disposition swap | `application/pdf` | `application/pdf; inline` | PDF JS execution, phishing overlays | `Content-Disposition: inline` instead of `attachment` |
| Flash substring match | Any containing `application/x-shockwave-flash` | Reflected into header | SWF execution bypassing origin checks | Legacy; Flash substring-matched Content-Type (report #78158) |
| MIME param injection | `image/png; charset=text/html` | Reflected as-is | Parser differential between server and browser | Server reflects upload Content-Type without sanitizing params |
| E2EE client trust | Sender-supplied MIME | Client trusts sender value | Client renders dangerous format (HTML, SVG) | E2EE shifts validation client-side; no server sanitization (report #105593574) |
| Blob URL escalation | `image/gif` | `image/gif` (correctly set) | XHR reads bytes, creates `blob:text/html` URL; script executes | Polymorphic image + JS blob trick bypasses even correct Content-Type (report #3067851781) |

## Polyglot File Techniques

| Format | Construction | Validation Bypass | Impact |
|--------|-------------|-------------------|--------|
| GIF89a + JS | `GIF89a/*<html><script>...</script>` — GIF ignores comment; HTML `/*` opens JS comment over binary garbage | Passes magic-byte checks, libmagic, image decoders | XSS when browser sniffs or via blob URL; $6.2k on Google Scholar |
| PNG + HTML | HTML payload in `tEXt`/`iTXt` chunks; IHDR/IDAT remain valid | Passes PNG decode and magic-byte validation | XSS via direct navigation or XHR + blob |
| JPEG + HTML | HTML in COM or EXIF APP1 segment before scan data | Passes JPEG magic (`FF D8`) and decoder validation | XSS; less reliable due to binary garbage before payload |
| PHAR + image | Valid image header wrapping a PHP Phar archive with serialized metadata | Passes image type checks; PHP `phar://` wrapper triggers deserialization on `file_exists()` | RCE via PHP object injection; any filesystem function is a sink (report #1063039) |
| SVG + JS | Standard SVG with `<script>`, `onload`, `<foreignObject>` embedding HTML | Passes XML/SVG validators; IS valid SVG | XSS if served as `image/svg+xml` inline |
| AVI + HLS | `.m3u8` HLS playlist embedded inside AVI container as text stream | Passes video format validation (valid AVI container) | SSRF + LFI via FFmpeg HLS demuxer; $2.7k on TikTok (report #1062888) |
| imagejs (GIF/BMP/WebP + JS) | Image format with header bytes that parse as JS no-ops; remainder is executable JS | Passes image validation AND `eval()` parses it as valid JavaScript | XSS when response is eval'd by client-side code (report #142135, $1.5k VK) |
| ZIP + HTML | HTML file as first entry in ZIP; some browsers render ZIP contents | Passes archive validation | XSS in contexts that unpack and serve ZIP entries |

## Image Processing Attacks

| Library | Attack Vector | Payload | Impact |
|---------|--------------|---------|--------|
| ImageMagick (all) | SVG/MVG/MSL delegate execution | SVG with `<image xlink:href="http://attacker/canary">` or MSL with `url:` references | SSRF, LFI; `policy.xml` may mitigate but often misconfigured |
| ImageMagick (CVE-2016-3714 "ImageTragick") | Shell command via delegate | `push graphic-context\nviewbox 0 0 640 480\nfill 'url(https://\|id)'\npop graphic-context` | RCE via shell metacharacters in filenames/delegates |
| ImageMagick (parameter injection) | Wrapper-to-CLI flag injection | `-write /tmp/shell.php` or `ephemeral:` / `pango:` prefixes in transformation params | RCE/file-write via Active Storage, Paperclip, image_processing gem (CVE-2022-21831, report #1652042) |
| GD Library (PHP) | Integer overflow in `imagecreatefromstring()` | >2GB input causes `size_t`->`int` truncation; negative length bypasses bounds check | Stack buffer overflow, heap leak; server memory disclosure (report #175587, #640048820) |
| Pillow (Python) | Decompression bomb, crafted TIFF/ICO | Nested IFDs, huge declared dimensions with minimal data | DoS, potential memory disclosure |
| FFmpeg (server-side video processing) | HLS playlist with external references | `.m3u8` playlist referencing `file:///etc/passwd` or `http://169.254.169.254/` | SSRF + arbitrary file read; `concat:` and `subfile:` protocols |
| ExifTool (< 12.38) | Perl code injection via DjVu/JPEG metadata | Crafted filename or metadata field with `${}` Perl expressions | RCE (CVE-2021-22204); common in background metadata-stripping pipelines |
| Sharp.js / libvips | SVG processing with external references | SVG with `<use href="http://attacker/...">` or `<image>` references | SSRF when Sharp processes SVG input |

## Filename Injection

| Technique | Payload | Impact | Target |
|-----------|---------|--------|--------|
| Path traversal | `../../../etc/passwd` or `%2e%2e%2f` | Arbitrary file write/read outside upload dir | Any app writing filename to disk without sanitization; $20k GitLab (report #827052), $111k Facebook Messenger (report #105593574) |
| URL-encoded traversal | `%2e%2e%5c` (`..\` for Windows) | Bypass naive `../` substring filters | Windows desktop clients processing E2EE attachments |
| Null byte truncation | `shell.php%00.jpg` | Truncates at null; server stores `.php`, passes `.jpg` validation | Legacy PHP (<5.3.4), old Java, some C-based validators |
| CRLF in filename | `file%0d%0aSet-Cookie:+evil=1.jpg` | HTTP header injection when filename reflected in Content-Disposition | Servers reflecting filename in response headers |
| XSS in filename display | `"><img src=x onerror=alert(1)>.jpg` | Stored XSS when filename rendered in UI without escaping | Admin panels, file browsers, notification emails |
| Unicode normalization | `file‥.php` (two-dot leader normalizes to `..`) or fullwidth chars | Bypass extension blocklists after Unicode NFKC normalization | Apps that normalize filenames after validation (report #191380) |
| Overlong UTF-8 | `%c0%ae%c0%ae/` (overlong encoding of `../`) | Bypass ASCII-only path traversal filters | Legacy C/Java parsers that decode overlong sequences |
| Windows reserved names | `CON`, `NUL`, `AUX`, `LPT1` as filenames | DoS or unexpected behavior on Windows servers | Windows-hosted applications |
| Trailing dots/spaces | `shell.php.` or `shell.php ` | Windows strips trailing dots/spaces; stored as `shell.php` | Windows servers; bypass extension checks that see the dot/space |
| Semicolon truncation | `shell.asp;.jpg` | IIS treats semicolon as path parameter separator; executes as `.asp` | IIS 6/7 with classic ASP |
| Regex-extracted filename traversal | `![img](/uploads/aaa.../../../etc/passwd)` in markdown | Regex `(?<file>.*?)` captures traversal; flows to filesystem op | Markdown/BBCode processors resolving embedded references ($20k GitLab, report #827052) |

## Storage-Specific Attacks

| Storage | Attack | Technique | Impact |
|---------|--------|-----------|--------|
| S3 presigned POST | Content-Type override | Set `Content-Type: text/html` in upload; policy may not constrain it | Stored XSS from S3 origin; bucket serves HTML directly |
| S3 object key injection | Path traversal in key | User-controlled blob name `../other-bucket/config.json` in SDK without URL encoding | Cross-bucket write; $313k Google Cloud Storage SDK (report #1033041408) |
| S3 bucket misconfiguration | Public-read ACL + enumerable keys | `GET /` on bucket domain; sequential or predictable object keys | Mass data exfiltration; $2.9k Shopify (report #1021906), $50k Google (report #866296320) |
| Azure Blob metadata | Metadata header injection | User-controlled metadata values reflected in response headers | Header injection, cache poisoning |
| Local filesystem | Symlink following | Upload archive containing symlinks; extraction follows symlink outside upload dir | Arbitrary file read/overwrite |
| CDN cache poisoning | Upload controls cache key | Upload with `Content-Type: text/html` + predictable CDN path; CDN caches and serves to all users | Persistent XSS via CDN; affects all users requesting the cached path |
| GCS XML API traversal | `../` in blob name not URL-encoded by SDK | SDK builds URL with unencoded `/`; GCS resolves `..` server-side | Cross-bucket write via path normalization ($313k Google SDK, report #1033041408) |
| Salesforce ContentDocument IDOR | Enumerate document IDs via SOQL + download via Shepherd servlet | `/sfc/servlet.shepherd/document/download/{id}` skips per-row ACL | Mass private file exfiltration ($50k Google/Android Enterprise, report #866296320) |

## Defense-Bypass Pairs

| Defense | Bypass Technique | Why It Works |
|---------|-----------------|-------------|
| Extension allowlist (`.jpg`, `.png`, `.gif`) | Double extension `shell.php.jpg` + server exec config; or `.phtml`, `.pht` not in list | Allowlist is incomplete; Apache AddHandler processes first extension |
| Content-Type header check | Set `image/jpeg` header but send PHP/HTML body | Content-Type is client-supplied; trivial to forge |
| Magic byte validation | Prepend `GIF89a` or `\xFF\xD8\xFF` to payload | Magic bytes are the first few bytes; payload follows after valid header |
| Image re-encoding (resize/strip) | Exploit the re-encoder itself (ImageMagick RCE, GD memory leak, FFmpeg SSRF) | The defense IS the attack surface; processing libraries have CVEs |
| File size limit | Gzip bomb: 10 bytes compress to 10GB; or many small requests | Size check on compressed data, not decompressed; or no rate limit |
| Antivirus / CDR scanning | Race condition: request file before scan completes; password-protected archives bypass AV | Async scan pipeline has a window; encrypted content is opaque to scanners |
| Filename sanitization (strip `../`) | Double encoding `%252e%252e%252f`; Unicode normalization; or null byte before extension | Single-pass stripping misses encoded variants; normalization happens after check |
| Allowlisted upload directory | Write `.htaccess`/`web.config`/`.user.ini` to the upload dir to enable execution | Config files in upload dir change server behavior for that directory |
| Extension blocklist (deny `.php`, `.asp`, etc.) | Use less-known executable extensions: `.phtml`, `.pht`, `.php7`, `.shtml`, `.jspx` | Blocklists are never complete; each server has obscure executable extensions |
| Image library decode validation (must be valid image) | Polyglot that IS a valid image AND contains executable payload | GIF89a polyglot with JS comment trick passes decode AND executes |
| Separate CDN/cookieless domain for uploads | Find XSS in CDN domain that shares `*.example.com` wildcard cookie scope | Cookie scope may still overlap; or CDN domain is in CSP trust list |

## Chain Patterns

| Chain | Steps | Impact | Example |
|-------|-------|--------|---------|
| Upload -> RCE | Upload web shell via extension bypass -> access shell URL -> command execution | Full server compromise | PHP polyglot GIF bypasses magic check, executes as PHP |
| Upload -> Stored XSS | Upload SVG/HTML polyglot -> served inline from app origin -> JS executes | Session theft, account takeover | SVG with `onload` handler on Google Scholar ($6.2k, report #3067851781) |
| Upload -> SSRF | Upload crafted video/image -> server-side processor follows external references | Internal network scanning, cloud metadata theft | FFmpeg HLS playlist reads `http://169.254.169.254/` (report #1062888) |
| Upload -> XXE | Upload DOCX/XLSX/SVG with external entity -> server-side XML parser resolves entity | File read, SSRF | Office document with DTD referencing `file:///etc/passwd` |
| Upload -> Deserialization | Upload PHAR archive disguised as image -> trigger via `phar://` in filesystem function | RCE via PHP object injection | `file_exists('phar://upload/shell.jpg')` deserializes metadata (report #1063039) |
| Upload -> Path traversal -> DLL hijack | E2EE attachment with traversal filename -> write DLL to target app dir -> victim launches app | RCE without victim interaction with upload app | Messenger `..\` filename writes `qwave.dll` to Viber dir ($111k, report #105593574) |
| Upload -> Memory disclosure | Upload malformed image (missing data blocks) -> transcoder reads uninitialized buffer -> serves leaked heap | Server memory exfiltration (tokens, keys, other users' data) | GIF with no LZW data block leaked Messenger heap ($10k, report #640048820) |
| Upload -> Cross-app file write | SQLite JDBC URL creates file on disk -> SSRF to internal Jolokia -> MLet loads written JAR | RCE on managed services | Kafka Connect chain: JDBC file write + HTTP SSRF + Jolokia RCE ($5k, report #1547877) |

## Core Payloads

### Web Shells and Configs

- PHP: GIF polyglot (starts with GIF89a) followed by `<?php echo 1; ?>`; place where PHP is executed
- .htaccess to map extensions to code (AddType/AddHandler); .user.ini (auto_prepend/append_file) for PHP-FPM
- ASP/JSP equivalents where supported; IIS web.config to enable script execution

### Stored XSS

- SVG with onload/onerror handlers served as image/svg+xml or text/html
- HTML file with script when served as text/html or sniffed due to missing nosniff

### Archive Attacks

- Zip Slip: entries with `../../` to escape extraction dir; symlink-in-zip pointing outside target; nested zips
- Zip bomb: extreme compression ratios to exhaust resources in processors

### Metadata Abuse

- Oversized EXIF/XMP/IPTC blocks to trigger parser flaws
- EXIF GPS data surviving pipeline: upload to each surface, verify stripping ($10k Google, report #935256064)
- Payloads in document properties of Office/PDF rendered by previewers

## Advanced Techniques

### Resumable Multipart

- Change metadata between init and complete (e.g., swap Content-Type/Disposition at finalize)
- Upload benign chunks, then swap last chunk or complete with different source

### Processing Races

- Request file immediately after upload but before AV/CDR completes
- Trigger heavy conversions (large images, deep PDFs) to widen race windows

### Header Manipulation

- Force inline rendering with Content-Type + inline Content-Disposition
- Cache poisoning via CDN with keys missing Vary on Content-Type/Disposition

### Gem/Framework Auto-Setters

- CarrierWave: `remote_<field>_url=` setter on any mounted uploader triggers server-side URL fetch (SSRF); `<field>_cache=` can inject paths
- Active Storage: attacker-controlled transformation params reach ImageMagick CLI
- When these setters pass through deserialization (import/export), they bypass attribute allowlists ($10k GitLab, report #826361)

## Special Contexts

### E2EE Messaging Clients

Server cannot sanitize encrypted content. ALL parsing happens client-side. Every filename, MIME type, and embedded URL extracted from encrypted messages is an attacker-controlled input. Test every field for path traversal, format confusion, and injection. Cross-app file-write pivots are especially dangerous: a write primitive from app A + DLL search path weakness in app B = RCE (report #105593574).

### Rich Text Editors

RTEs (Trix, CKEditor, TinyMCE) have multiple attachment subclasses. When one subclass is sanitized, siblings may not be. ContentAttachment vs blob attachment in ActionText had different sanitizer coverage (CVE-2024-32464, report #2542806). Test each attachment type independently.

### Mobile Clients

Mobile SDKs may send nonstandard MIME or metadata. Capture upload requests via mitmproxy. Check if the upload destination (S3/GCS) has public-read objects with enumerable keys. Mobile apps frequently use sequential IDs or timestamps in object keys instead of UUIDs.

### Serverless and CDN

Direct-to-bucket uploads with Lambda/Workers post-processing. Verify security decisions are not delegated to frontends. CDN caching of uploaded content: ensure correct cache keys and headers. Test if uploaded Content-Type propagates to CDN-served response.

### Self-Proxy Endpoints

Image proxies (`/proxy?url=`), link unfurlers, OEmbed endpoints that fetch and re-serve attacker content from the app's own origin. Combined with `eval()` of response or Content-Type confusion, these become XSS gadgets even without a traditional upload (report #142135 pattern).

## Testing Methodology

1. **Map the pipeline** - Client -> ingress -> storage -> processors -> serving. Note where validation and auth occur
2. **Identify allowed types** - Size limits, filename rules, storage keys, and who serves the content
3. **Collect baselines** - Capture resulting URLs and headers for legitimate uploads
4. **Probe transcoding** - Upload minimal-header files (GIF header + no LZW data, PNG IHDR + IEND, JPEG SOI + EOI) and compare output to detect uninitialized memory leaks
5. **Exercise bypass families** - Extension games, MIME/content-type, magic bytes, polyglots, metadata payloads, archive structure
6. **Test every serving context** - Same file via `<img>`, direct navigation, XHR+blob URL, `<embed>`/`<object>` — each has different MIME handling
7. **Check pipeline parity** - Upload the same tagged file (EXIF GPS, PDF metadata) to every upload surface on the target; verify stripping is consistent
8. **Validate execution** - Can uploaded content execute on server or client?

## Validation

1. Demonstrate execution or rendering of active content: web shell reachable, or SVG/HTML executing JS when viewed
2. Show filter bypass: upload accepted despite restrictions with evidence on retrieval
3. Prove header weaknesses: inline rendering without nosniff or missing attachment
4. Show race or pipeline gap: access before AV/CDR; extraction outside intended directory
5. Provide reproducible steps: request/response for upload and subsequent access

## False Positives

- Upload stored but never served back; or always served as attachment with strict nosniff
- Converters run in locked-down sandboxes with no external IO and no script engines
- AV/CDR blocks the payload and quarantines; access before scan is impossible by design
- Upload served from isolated cookieless domain (separate origin, no session context to steal)

## Impact

- Remote code execution on application stack or media toolchain host
- Persistent cross-site scripting and session/token exfiltration via served uploads
- Server memory disclosure via malformed images in transcoding pipelines
- Malware distribution via public storage/CDN; brand/reputation damage
- Data loss or corruption via overwrite/zip slip; service degradation via zip bombs
- Privacy violation via unstripped EXIF GPS/device metadata on public uploads

## Pro Tips

1. Keep PoCs minimal: tiny SVG/HTML for XSS, a single-line PHP/ASP where relevant
2. Always capture download response headers and final MIME; that decides browser behavior
3. When you find a file-write primitive with limited path budget, survey other installed apps for DLL/dylib hijack targets that fit the remaining character budget (report #105593574 technique)
4. Build minimal-header-only files (GIF header + no data, PNG IHDR + IEND) to probe for uninitialized memory leaks in server transcoders — each upload returns different heap contents
5. In presigned flows, decode the base64 policy JSON to find unconstrained fields; constrain all headers and object keys server-side
6. For archives, extract in a chroot/jail with explicit allowlist; drop symlinks and reject traversal
7. Test finalize/complete steps in resumable flows; many validations only run on init
8. Verify background processors with EICAR and tiny polyglots
9. When you cannot get execution, aim for stored XSS or header-driven script execution
10. Validate that CDNs honor attachment/nosniff; CDN config is often owned by a different team than app security
11. On PHP targets, test `phar://` prefix on every filesystem function that accepts user paths — `file_exists()`, `is_dir()`, `fopen()` all trigger deserialization
12. When a platform patches one upload XSS vector, audit every sibling attachment class for the same gap — sanitizer fixes are rarely comprehensive (report #2542806 pattern)
13. For video upload targets, always test FFmpeg HLS injection: embed an `.m3u8` playlist in an AVI container; point at your OOB listener AND `file:///etc/passwd`; check both the callback and the output video frames for leaked data
14. Check pipeline parity across properties: main product may strip EXIF, but support community / admin panel / partner portal often uses a different image pipeline that preserves metadata
15. Test URL fragment/parameter confusion on file-serving URLs: replace `:large` with `%23.html` or `;.html` — servers and browsers may disagree on what the "extension" is (report #191380 technique)
16. When two low-severity primitives exist (e.g., CRLF injection + image served as HTML), always ask: do they compose? Cookie injection + content-type confusion = stored XSS chain
17. After subdomain enumeration, test PUT/DELETE/PATCH on every discovered host -- object-storage-backed subdomains (S3, MinIO, GCS, Azure Blob) frequently accept PUT with no auth, giving arbitrary file upload on the target's own domain (#487656, #545136)
18. Hunt forgotten dev/test upload endpoints on large legacy estates (DoD, university, telecom): `upload.php`, `fileupload.asp`, vendor demo forms, ColdFusion `wizardform` handlers -- these survive decades unpatched and accept unauthenticated arbitrary uploads (#698789, #698793)
19. One bug -> multiple hosts: when you find a vendor upload utility on one host of a large estate, immediately grep/scan all other hosts for the same path. Legacy upload utils are deployed identically across dozens of subdomains (#698793)
20. For every upload component, enumerate which of the 4 validation layers are actually enforced: (1) extension allowlist, (2) MIME type check, (3) magic-byte validation, (4) server-side content re-encoding. Most apps enforce 1-2 of 4 -- the gap between layers is the bypass (#813395)
21. Test file upload restrictions by mismatching extension and content: rename blocked `.svg` to allowed `.png` while keeping SVG content -- servers that validate extension but not content will process the SVG and render it (#161301)
22. Identify enterprise open-source products on the target's attack surface (DotCMS, Drupal, WordPress plugins), then audit their source for upload path traversal -- a 0day in a deployed product is a direct bounty. Workflow: attribute product -> clone source -> audit upload handlers -> test on target (#689775408, CVE-2022-26352)
23. Inventory ALL upload surfaces, not just the obvious profile/avatar -- chat file attachments, support ticket uploads, import/export, bulk CSV, template uploads each have independent validation paths. The weakest path is always the one tested last (#925513)

## Summary

Secure uploads are a pipeline property. Enforce strict type, size, and header controls; transform or strip active content; never execute or inline-render untrusted uploads; and keep storage private with controlled, signed access.
