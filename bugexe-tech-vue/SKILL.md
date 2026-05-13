---
name: vue
description: Vue.js attack surface: v-html injection, template injection, vuex store tampering
depends_on: []
---

# Vue

Vue 2/3 client-rendered SPA. Distinct risk surface around `v-html` (raw HTML rendering), `<component :is>` (dynamic component injection), and SSR template-string concatenation in Nuxt.

## Common Bug Classes

- XSS via `v-html` directive rendering server-controlled markup
- Template injection in `<component :is="userControlled">` allowing arbitrary component instantiation
- Vuex store tampering via DevTools or `__VUE__` global on production builds
- SSR injection in Nuxt's `nuxtServerInit` when concatenating user input into HTML
- Open redirect via `router.push(userInput)` without same-origin validation

## Dangerous Rendering API Audit

`v-html` is the Vue equivalent of React's `dangerouslySetInnerHTML`. Systematic hunt:

```bash
# Find all v-html usage in codebase
grep -rn "v-html" src/ components/
grep -rn "innerHTML" src/

# For each instance, trace the bound expression:
# 1. Does it bind to user-controlled data (props, store, API response)?
# 2. Is there a sanitizer between the data source and v-html?
# 3. Does the sanitizer handle all contexts (HTML, attribute, URL)?
```

**Hidden `v-html` wrappers:** Like React, Vue apps use wrapper components:
- `<RichText :content="..." />` — internally uses `v-html`
- `<HtmlRenderer :html="..." />` — custom component
- Third-party Vue WYSIWYG editors rendering output without sanitization

## Client-Side Template Injection (CSTI)

Vue's template engine evaluates expressions in `{{ }}` and `v-bind`. Test every reflection point:

**Detection sequence:**
```
1. Inject {{7*7}} → output is 49 → CSTI confirmed (Vue/Angular/Handlebars)
2. Inject {{constructor.constructor('return this')()}} → global scope access
3. Inject {{_vm.$root}} → Vue instance access (Vue 2)
4. Inject {{$root}} → Vue instance access (Vue 3)
```

**Exploitation after CSTI confirmation:**
- Vue 2: `{{constructor.constructor('alert(1)')()}}` for JS execution
- Vue 3: `{{$root.$el.ownerDocument.defaultView.alert(1)}}`
- Access Vuex store: `{{$store.state}}` to dump application state
- DOM manipulation: `{{$el.innerHTML = '<img src=x onerror=alert(1)>'}}`

**Where to find template injection:**
- User-controlled content rendered by Nuxt/Vue SSR without escaping
- Admin panels, CMS content areas, email template editors
- Dynamic page titles, meta descriptions, breadcrumbs
- Multi-user-edited content (comments, profiles, wiki pages)

## Prototype Pollution to Vue Gadgets

Once you have a prototype pollution primitive:

- `Object.prototype.staticClass` → inject class names for CSS-based attacks
- `Object.prototype.attrs` → inject HTML attributes into any component
- `Object.prototype.domProps` → inject `innerHTML` into any component
- `Object.prototype.template` → inject template strings (Vue 2 with runtime compiler)

**Mermaid/diagram library chain:** Many Vue apps embed Mermaid diagrams. PP → Mermaid template string → XSS is a known chain ($3K+ payouts).

## Nuxt.js SSR Specific Attacks

Nuxt adds server-side rendering surfaces:

**`__NUXT__` state inspection:**
```javascript
// In browser console or page source
window.__NUXT__
// Contains: server-rendered state, errors, route data
// Look for: API keys, internal URLs, user data, feature flags
```

**Server middleware injection:** In Nuxt 2, `serverMiddleware` entries process requests server-side:
- Test if user input flows into `res.end()` or `res.write()` without encoding
- SSRF via `$fetch()` in Nuxt 3 server routes with user-controlled URLs
- Path traversal in static file serving configuration

**asyncData/fetch injection:** Nuxt's `asyncData` and `fetch` hooks run server-side on initial load:
- User-controlled route params (`$route.params`) flow into server-side API calls
- Test for SSRF when params are used to construct backend URLs

## Vue Router Exploitation

Vue Router handles client-side navigation but can be exploited:

```javascript
// Open redirect via router.push
router.push(userInput)           // If input is full URL: redirect
router.push({path: userInput})   // Path-based redirect

// XSS via router params in component templates
// If a route param is rendered via v-html or {{ }} without escaping
<template>
  <div v-html="$route.query.msg"></div>  // Reflected XSS
</template>
```

## SPA State Exposure Detection

Vue production builds may leak state:

1. Check for `__VUE_PROD_DEVTOOLS__` flag enabling DevTools in production
2. Inspect `window.__VUE__` or `window.__vue__` for component tree access
3. Vuex store accessible via DevTools: `$vm.$store.state` contains all application state
4. Pinia stores (Vue 3): check for `window.__pinia` global

## IDOR via Resource ID Injection

Vue apps that accept resource IDs in route params or API calls:

1. Intercept API calls triggered by UI actions
2. When an endpoint accepts a resource ID + single field, test:
   - Substitute another user's resource ID (horizontal IDOR)
   - Add additional fields beyond what the UI sends (mass assignment)
3. Check if Vue components use `v-if` to hide admin features (client-side only, server may still accept)

## Probe Targets

- Search bundle for `v-html` usage and trace data sources
- Check for production builds with DevTools enabled (`__VUE_PROD_DEVTOOLS__`)
- Probe `__NUXT__` script JSON for state and routes
- Test SPA routes for unsafe `router.push` from user input
- Inject `{{7*7}}` in every user input field rendered back on page
- Check for exposed Webpack bundle analyzer reports (`/report.html`)
- Test `javascript:` scheme in all `<a :href>` and `<router-link :to>` bindings
- Inspect network requests during every UI action for overfetch

## Cross-References

`xss`, `spa_client_side`, `js_analysis`, `open_redirect`, `prototype_pollution`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
- For CSTI: demonstrate JavaScript execution, not just expression evaluation
- For v-html XSS: show the HTML source is user-controlled, not just server-generated
