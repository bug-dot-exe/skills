---
name: angular
description: Angular attack surface: bypassSecurityTrustHtml, template injection, JSONP open vulnerabilities
depends_on: []
---

# Angular

Angular's strict HTML sanitization is bypassable when developers call `bypassSecurityTrust*`. Template injection is rare but devastating — an attacker who controls a template string achieves arbitrary code execution in the browser.

## Common Bug Classes

- XSS via `DomSanitizer.bypassSecurityTrustHtml(userInput)`
- Client-side template injection when `[innerHTML]` binds to user-controlled data
- JSONP-style open vulns via `Jsonp` module when callback param is untrusted
- DOM XSS via `Renderer2.setProperty(element, 'innerHTML', input)`
- Source-map disclosure on production deployments
- Prototype pollution to Angular template-string gadget chains
- CSP bypass via AngularJS (v1.x) sandbox escape on script-src allowlisted CDNs

## Angular-Specific XSS Hunting (178 reports, $1.5M corpus)

### Dangerous Rendering API Grep
For any Angular codebase (source or bundle), grep for these exact patterns:
1. `bypassSecurityTrustHtml` — developer-marked "safe" HTML, often user-tainted
2. `bypassSecurityTrustStyle` — CSS injection vector (expression-based in older browsers)
3. `bypassSecurityTrustScript` — direct script trust bypass
4. `bypassSecurityTrustUrl` — URL scheme injection (`javascript:`, `data:`)
5. `bypassSecurityTrustResourceUrl` — iframe/embed src injection
6. `[innerHTML]` — if the bound value is user-controlled, test with HTML+SVG payloads
7. `Renderer2.setProperty(el, 'innerHTML', ...)` — imperative DOM write, bypasses template sanitization

Each hit is a candidate. Trace the data flow backward to find user-controlled input.

### AngularJS (v1.x) CSP Bypass via CDN-Hosted Libraries
1. List every host in the target's `script-src` CSP directive
2. For each host, check if it serves AngularJS (cdnjs, googleapis, jsdelivr, unpkg)
3. If AngularJS is loadable from an allowlisted host, the Angular sandbox is irrelevant — template expressions execute directly
4. Payload pattern: `<script src="//allowlisted-cdn/angularjs/1.6.x/angular.min.js"></script><div ng-app>{{constructor.constructor('alert(1)')()}}</div>`
5. This works even if the target itself uses Angular 2+ — the CSP allows loading v1.x from the CDN

### Prototype Pollution to Template Gadget
Once a prototype pollution (PP) primitive exists on an Angular/AngularJS page:
1. Search for known gadget chains: `Object.prototype.templateUrl`, `Object.prototype.template`
2. In AngularJS: `Object.prototype.sequence` and `Object.prototype.DYNAMIC_TEMPLATE_URL`
3. In Angular 2+: PP into `Compiler` options or `ViewContainerRef` metadata
4. Mermaid, Chart.js, and other Angular-embedded libraries have their own PP-to-XSS gadgets

### Multi-Layer Template Composition
When a value flows through more than one template/parser/eval engine:
1. Map the flow: user input -> backend template (Jinja/ERB/Thymeleaf) -> Angular template -> DOM
2. Each transition point is an injection boundary — an escaped value in layer N may be unescaped in layer N+1
3. Test Angular expression injection (`{{ }}`) inside server-rendered HTML
4. Test backend template injection (`${...}`) when Angular interpolation is disabled on that element

## SSR (Angular Universal) SSRF

Angular Universal renders pages server-side. When the `useAbsoluteUrl` option or any request-time URL construction trusts client headers:
1. Inject `Host: attacker.com` — if SSR fetches API calls using the Host header, this is SSRF
2. Test `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Original-URL` for SSR URL manipulation
3. The SSR process runs as a Node.js server with internal network access — SSRF here reaches metadata endpoints, internal APIs
4. Check if SSR pre-fetches URLs from user-controlled data (route params, query strings used in `HttpClient.get()`)

## Client-Side Template Injection DoS

For multi-user content rendered via Angular's template engine:
1. Identify user-editable content that renders in Angular context (profile fields, comments, wiki pages)
2. Test AngularJS-style payloads: `{{constructor.constructor('while(1)')()}}` for infinite loop
3. In Angular 2+, template injection is rarer but `[innerHTML]` with complex SVG can trigger rendering DoS
4. If the page caches rendered output, this becomes a persistent DoS affecting all viewers

## Bundle Analysis for Internal Route / Token Leakage

1. Fetch `/main.*.js`, `/runtime.*.js`, `/polyfills.*.js` from the deployment
2. Search for: route definitions, API endpoint paths, hardcoded tokens, admin-only route guards
3. Look for `canActivate` guards that are client-side only (no server enforcement)
4. Check for `environment.prod.ts` values embedded in the bundle (API keys, internal URLs)
5. Source maps (`.map` files) often still deployed — check `/main.*.js.map` for full source

## URL Scheme Injection in Angular Router

Angular's router and sanitizer handle URL schemes differently:
1. Test `href` bindings with `javascript:alert(1)` — Angular sanitizes this by default BUT only for `[href]`, not for all URL contexts
2. Test `src` on `<iframe>`, `<embed>`, `<object>` bindings with `data:text/html,<script>alert(1)</script>`
3. If the developer uses `bypassSecurityTrustUrl()`, ALL URL scheme protection is removed
4. Angular does NOT prevent `javascript:` in anchor `href` when the value comes from a router query param that is bound via string interpolation outside Angular's sanitizer

## Error Page and Debug Mode XSS

Angular applications in development mode leak information and may have XSS:
1. If `enableProdMode()` was not called, error messages include full component templates and data bindings
2. Error pages may reflect route parameters or query strings without sanitization
3. Test 404/error routes with XSS payloads in the URL path — Angular's router may pass them to an error component that renders them unsafely
4. Zone.js stack traces in dev mode reveal: internal route names, component structure, service injection hierarchy

## Service Worker Cache Poisoning

Angular apps with `@angular/service-worker` (PWA support):
1. If the service worker caches API responses, test cache poisoning via the API (inject XSS into a cached JSON response)
2. Test if the service worker's `ngsw.json` manifest is served from a cacheable CDN path — poisoning the manifest controls what the app caches
3. Service worker updates are checked on navigation — if you can delay the update check, stale cached content persists

## Probe Targets

- Grep bundle for `bypassSecurityTrust` to find sanitization escape hatches
- Inspect zone.js stack traces for internal route names
- Test `[innerHTML]` bindings with HTML+SVG payloads
- Check `/main.*.js` and `/runtime.*.js` for embedded routes and tokens
- Test `v-html` (Vue), `dangerouslySetInnerHTML` (React) on co-located frameworks in the same app
- Fuzz `ng-app` injection on AngularJS pages behind CDN-allowlisted script-src
- Probe SSR endpoints with manipulated Host/X-Forwarded-Host headers
- Check for `.map` source map files on production deployments
- Test admin routes directly even when guarded client-side (the guard may be UI-only)

## Version-Specific Issues

| Version Range | Issue |
|---|---|
| AngularJS 1.x (all) | Sandbox escape possible, template injection = XSS |
| AngularJS < 1.6 | `$sce` bypass via `toString()` on trusted objects |
| Angular 2-5 | `Renderer` (deprecated) API allows direct DOM manipulation |
| Angular < 13 | `enableProdMode()` not called = verbose error messages in production |
| Angular Universal (all) | SSR Host-header SSRF when `useAbsoluteUrl` trusts request headers |

## Cross-References

`xss`, `spa_client_side`, `js_analysis`, `frontend_backend_parity`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
