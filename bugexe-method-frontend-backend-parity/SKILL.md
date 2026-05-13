---
name: frontend_backend_parity
category: methodology
description: Test that backend enforces every authorization gate the frontend hides — bypass via direct API call
depends_on: []
---

# Frontend-Backend Parity

The most common privilege-escalation bug class: frontend hides a feature
behind a client-side check, backend doesn't enforce the same check, attacker
calls the API directly and bypasses. Methodology: extract every client-gated
UI element, identify its API endpoint, confirm backend enforces.

## When to Use

- Any target with a SPA / JS-heavy frontend
- After surface discovery has captured the JS bundles
- Whenever the application has multiple roles or feature flags
- Whenever you find UI elements that "only admins see" — they're prime targets

## Inputs (all runtime-derived)

- **JS_BUNDLES** = JS files captured during recon (initial, lazy-loaded, dynamic chunks)
- **AUTH_TOKENS** = at least two principals with different scopes (one HIGH, one LOW privilege)
- **API_BASE** = inferred from JS bundle (axios baseURL, fetch base, env config strings)

## Process — Universal Across Frameworks

### Step 1: Bundle Acquisition

```
- Visit the application as anonymous, capture initial JS bundle URLs
- Visit as low-priv principal, capture any new bundles loaded
- Visit as high-priv principal, capture admin / privileged bundles
- For each bundle: download, beautify (if minified), index for searching
```

### Step 2: Find Client-Gated Code Patterns (framework-agnostic)

Search bundles for conditional logic gated by user state. Universal regex
patterns (work on minified code too):

```
User-state property checks:
  /\.role\s*[=!]==\s*['"]/
  /\.permissions(?:\.|\[)['"][^'"]+['"]\]?\s*[=!]==/
  /\.permissions\.(?:includes|has)\s*\(/
  /\.tenant_?[Ii]d\s*[=!]==/
  /\.scope\s*[=!]==/
  
Feature-flag patterns:
  /featureFlag/i
  /flags\.[a-zA-Z_]+/
  /isEnabled\s*\(/
  /canSee\s*\(/

Framework-specific conditional renders:
  Vue:      v-if="..." patterns referencing user/permission state
  Angular:  *ngIf="..." patterns referencing user/permission state
  React:    {condition && <Component/>} where condition references user/permission
  Svelte:   {#if condition} where condition references user/permission
  Templates: {% if %}, {{#if}} (Handlebars), <% if %> (EJS)
```

For each match, extract:
- The condition expression (what role/permission/flag gates the UI)
- The rendered component / route (what gets shown)
- The API call associated (next step)

### Step 3: Map Conditional UI to API Endpoints

For each conditional UI block, find the API endpoints it calls. Universal
patterns to search WITHIN the conditional block:

```
fetch('/api/...') / fetch(`...`)
axios.{get,post,put,patch,delete}('/...')
$http.{get,post,...}('/...')
useQuery / useMutation hook with URL string
xhr.open('METHOD', '/...')
WebSocket('/...' or 'ws://...' or 'wss://...')
```

If the API path is built from a base URL + relative path, also resolve:

```
axios.create({ baseURL: API_BASE })
const API_BASE = '...' (then concat in calls)
```

Output per conditional:
```
{
  gate_expression: "user.role === 'X'",  # whatever the JS literally says
  ui_component: "AdminPanel" / route name / etc.,
  api_endpoints: [{method, path}, ...],
}
```

### Step 4: Direct-API Bypass Test

For each (gate_expression, api_endpoint):

```
1. Determine the principal that the gate REJECTS (low-priv principal)
2. Authenticate as that principal, capture token
3. Direct-call the api_endpoint with that token
4. Observe response:
   - 401 / 403 → backend enforces → no bug
   - 200 / 2xx → backend allows → BUG (frontend-only enforcement)
   - 4xx other than auth → likely bug (validation-only protection)
```

Specifically for state-changing endpoints (POST, PUT, PATCH, DELETE):
- Confirm not just that the call succeeds, but that the STATE CHANGE persists
  (refetch with high-priv to verify the action took effect)

### Step 5: Special Cases

#### Lazy-loaded admin bundles

If a bundle is only loaded for high-priv principals (e.g., `admin.chunk.js`),
that bundle alone exposes the entire admin API. Capture it once with high-priv,
then test all its endpoints as low-priv.

#### Hidden routes

Routes registered in the JS router but conditionally rendered. Often a
hidden route has both:
- An admin-only navigation entry (gated)
- A backend endpoint serving its data (sometimes ungated)

Visit the hidden route URL directly as low-priv to see if backend serves it.

#### Feature-flag-gated endpoints

If a feature is `if (flags.beta)` gated, the backend endpoint may exist
unconditionally. Direct-call it regardless of flag value.

## Output Format

```
Gate: {client-side condition expression}
UI hidden from: {role/principal that gate excludes}
Backend endpoint: {method} {path}
Test as: {low-priv principal}
Observed: {status_and_body_excerpt}
Verdict: {ENFORCED | UNENFORCED | PARTIAL}
Evidence: {request} → {response}
```

## Discovery Signals

| # | Signal | Where to Find | Why Vulnerable |
|---|--------|---------------|----------------|
| 1 | `featureFlag`, `flags.beta`, `isEnabled()` in JS bundle | Beautified JS, webpack chunks | Feature-flag-gated endpoints exist unconditionally on backend (Step 5 above) |
| 2 | `skip_*` / `force_*` / `bypass_*` / `is_admin` in API body | Burp proxy history | Client-controlled mode flag changes server behavior (Report #1018336: Shopify Chat) |
| 3 | Lazy-loaded admin chunk (`admin.chunk.js`) | Network tab, webpack manifest | Entire admin API surface exposed in one file (Step 5 above) |
| 4 | Mobile app traffic opaque after proxy setup | Frida, APK decompile | Client-side AES/TLS layer hides API; decrypt to find unprotected endpoints (Report #100019473) |
| 5 | Parameters the client doesn't send | API docs vs actual traffic | Try every value 0-50 for enums; add undocumented fields (Report #1005020) |
| 6 | Spring Boot backend signature | `/actuator`, `/manage`, `/env` | Hit actuator endpoints for config dump, env vars, heap (Report #1019367) |
| 7 | `validate`/`verify`/`check` param in request | JSON body inspection | Set to `false` to disable server-side validation (Report #1018336) |
| 8 | URL tokens in page (API keys, session tokens) | Referer header, page source | Leaked via every outbound request the page makes -- Referer, analytics pixels (Report #1015283) |
| 9 | Allowlisted HTML tags (images, links, formatting) | Rich text editor output | Test attribute stripping on allowed tags (Report #1039750) |
| 10 | Create endpoint validates but update doesn't | Comparing create vs edit requests | Edit path has weaker validation than create path (Report #1036995) |
| 11 | Multi-step workflow with client-side state | Registration, payment, onboarding | State-machine bypass via direct endpoint invocation (Report #1036999089) |
| 12 | Path-normalization differences (proxy vs backend) | URL fuzzing | `..;`, `..%2f`, `//`, `\..` bypass proxy ACL to reach backend (Report #1004007) |

## Technique Matrix

| # | Technique | When | How |
|---|-----------|------|-----|
| 1 | JS bundle conditional extraction | SPA with auth/roles | Regex for `.role`, `.permissions`, `featureFlag` -- map every gated block to API endpoint (Step 2 above) |
| 2 | Boolean flag mass-flip | API body has suspicious flags | Flip every `skip_*`/`force_*`/`is_admin` and diff response (Report #1018336) |
| 3 | Parameter value enumeration | Client sends limited values | Try 0-50 for every numeric/enum param, add undocumented fields to body (Report #1005020) |
| 4 | Mobile app decryption | Traffic encrypted beyond TLS | Frida hook on javax.crypto / AES key extraction (Report #100019473) |
| 5 | Path normalization fuzzing | Proxy/WAF gates backend | `..;`, `..%2f`, `..%5c`, `;name=value/`, `//`, URL-triple-encode (Report #1004007) |
| 6 | Actuator endpoint spray | Spring Boot signature | Hit `/actuator`, `/manage`, `/env`, `/dump`, `/trace`, `/health` (Report #1019367) |
| 7 | Hidden route direct navigation | JS router with gated routes | Visit admin route URL directly as low-priv user (Step 5 above) |
| 8 | Referer token harvest | Tokens in page URLs | Navigate away to controlled page, check Referer for leaked tokens (Report #1015283) |
| 9 | Allowlist attribute injection | Rich text HTML allowed | Inject `style`, `class`, `data-*` on allowed tags; test event handlers (Report #1039750) |
| 10 | Create-vs-update validation split | Both endpoints exist | Submit clean via create, inject via edit/update path (Report #1036995) |

## Defense-Bypass Pairs

| Defense | Bypass | Example |
|---------|--------|---------|
| Client-side role check hides UI | Direct API call with low-priv token | Admin endpoint returns 200 -- backend never checks |
| Feature flag gates beta feature | Call beta API directly regardless of flag | Backend endpoint exists unconditionally |
| Mobile app AES encryption layer | Frida hook extracts AES key, decrypt traffic | Unprotected API endpoints revealed (Report #100019473) |
| Proxy path ACL (`/admin` blocked) | Path normalization: `/admin..;/` or `/Admin/` | Backend normalizes differently than proxy (Report #1004007) |
| Client sends only valid enum values | Add `role: "admin"` or `tier: "enterprise"` to body | Mass assignment -- backend trusts client fields (Report #1005020) |
| Actuator endpoints "internal only" | Hit `/actuator/env` from external -- often not gated | Config dump including secrets (Report #1019367) |
| Rich text allowlist (img, a, b, i) | Inject attributes on allowed tags | `<img src=x onerror=alert(1)>` passes tag allowlist (Report #1039750) |
| CSRF token on create path | Update/edit path has no CSRF check | Asymmetric protection across create vs update |

## Chain Patterns

| Chain | Step 1 | Step 2 | Impact |
|-------|--------|--------|--------|
| JS bundle -> admin API discovery -> privilege escalation | Extract admin endpoints from lazy chunk | Call as low-priv user | Full admin access |
| Boolean flip -> PII oracle | Find `skip_customer_creation` flag | Flip to `false`, get customer name from email | $1.5M data class (Report #1018336 pattern at scale) |
| Mobile decrypt -> hidden endpoints -> data leak | Frida extracts AES key from app | Enumerate API with decrypted traffic | Expose all mobile-exclusive data |
| Path normalization -> proxy bypass -> admin panel | `..;/admin/` bypasses proxy ACL | Backend serves admin panel directly | Admin takeover ($1.5M -- Report #256901120: Gmail CSPT) |
| Actuator dump -> secret extraction -> RCE | `/actuator/env` leaks DB creds | Connect to DB, write webshell | Full server compromise (Report #1019367) |
| Param enum -> mass assignment -> role escalation | Discover undocumented `role` field | Add to request body with elevated value | Privilege escalation |
| Token in URL -> Referer leak -> ATO | API key visible in page URL | Navigate to attacker page, harvest Referer | Account takeover (Report #1015283) |
| Create/update split -> stored XSS | Clean content passes create validation | Edit with XSS payload on weaker update path | Stored XSS (Report #1036995) |

## Pro Tips from Corpus

1. **The client sends a subset of what the backend accepts.** For every API endpoint, enumerate undocumented parameters: try 0-50 for numeric/enum fields, add `role`/`is_admin`/`permissions` to the body (Report #1005020).
2. **Boolean flags are API-wide.** `skip_*`, `force_*`, `bypass_*`, `validate`, `check` -- flip every boolean in every request body and diff the response (Report #1018336).
3. **Path normalization differentials are proxy-to-backend exploits.** Systematically test `..;`, `..%2f`, `..%5c`, `//`, URL-triple-encode on every path behind a proxy/WAF (Report #1004007).
4. **Lazy-loaded admin bundles are the highest-yield single artifact.** One JS chunk exposes the entire admin API surface -- capture once with high-priv, test everything as low-priv.
5. **Every token in a URL leaks via Referer.** API keys, session tokens, auth codes in URLs are exposed to every outbound request -- analytics pixels, embedded images, navigation (Report #1015283).
6. **Mobile app encryption is a speed bump, not a wall.** AES keys can be hooked with Frida in minutes; encrypted traffic hides unprotected backend APIs (Report #100019473).
7. **Always hit Spring Boot actuator paths.** `/actuator`, `/manage`, `/env`, `/health`, `/dump`, `/trace` -- these are often exposed to external traffic with no auth (Report #1019367).
8. **Create and update are different code paths.** Test both independently -- the edit flow is often built later with weaker validation (Report #1036995).

## Anti-Patterns

- **Trust the frontend hide**: never assume "admin only sees this so backend must enforce". Always verify.
- **Test ONLY logged-out**: most bugs are "low-priv user can do high-priv action", not "anonymous can do anything". Test logged-in low-priv too.
- **Skip lazy chunks**: the most-restricted features ship in lazy-loaded bundles. They're the highest-yield targets.
- **Hardcode framework**: this methodology works on Vue, React, Angular, Svelte, jQuery, vanilla JS. Don't assume a framework -- derive from bundle.
- **Skip route guards**: route-level gates (e.g., AuthGuard in Angular) are client-side too. Backend may not enforce per-route.

## Composability

- `auth_matrix_systematic` -- frontend parity is one cell of the auth matrix
- `js_analysis` -- vocabulary skill that explains JS bundle deobfuscation
- `spa_client_side` -- vocabulary skill for SPA-specific attacks
- `variant_hunting` -- once you find one parity gap, sibling endpoints likely have the same gap
