---
name: js_runtime_audit
category: reconnaissance
description: Dynamic / runtime JavaScript analysis — DevTools breakpoints, fetch & XHR monkey-patching, service worker audit, storage dump (localStorage / sessionStorage / IndexedDB / Cookies), PostMessage & WebSocket interception. Pairs with js_analysis (static grep) and js_deobfuscation (AST + source maps).
depends_on: []
---

# JavaScript Runtime Audit

Static analysis tops out when:
- Critical logic runs inside WASM or is obfuscated past recognition
- Auth happens across multiple XHRs with dynamic headers
- PostMessage is used between iframes and the origin check is hard to reason about
- Requests are assembled JIT from config pulled at load time
- A service worker intercepts everything before it hits the network

This skill runs the app and watches it — **every fetch**, **every storage
write**, **every postMessage**, **every WebSocket frame**. Pair with the
Chrome DevTools MCP tools (`mcp__chrome-devtools__*`) for scripted runtime
recon.

## When to Use

- Static grep / deobfuscation misses dynamic fetch URLs
- You need full request timing / order, not just endpoint list
- Auth tokens are derived at runtime (HMAC from a secret + timestamp)
- The app uses heavy PostMessage / Service Worker / WebSocket
- Third-party SDK injects auth headers you can't see from source
- Client-side crypto uses ephemeral keys

## Methodology

### Phase 1: DevTools Setup — Always-On Breakpoints

Launch Chrome/Edge → DevTools → **Sources tab** → enable the following
breakpoints before navigating:

| Breakpoint category | What it catches | Where in DevTools |
|---|---|---|
| `XHR/fetch` (Any XHR or fetch) | Every outbound request, BEFORE it sends | Sources → XHR/fetch breakpoints → `+` |
| DOM mutations | Dynamic script injections, third-party SDKs loading | Elements → right-click → Break on → subtree mods |
| Event listeners (all) | Handler that triggers a request | Sources → Event Listener Breakpoints |
| Exceptions | Catches obfuscated try/catch hiding errors | Sources → Pause on Caught Exceptions |

With "Any XHR" enabled, you get a stack trace at every request origin — which
reveals the exact code path that built the URL, even after deobfuscation fails.

### Phase 2: Fetch / XHR Monkey-Patching (Logs Every Call)

Paste this in the DevTools **Console** on the target page — it wraps every
future `fetch` and `XMLHttpRequest` call and logs it with full headers + body
+ response.

```javascript
// === Paste into DevTools console on the target page ===

// 1) fetch wrapper
const _origFetch = window.fetch;
window.fetch = async function(input, init = {}) {
  const url = typeof input === "string" ? input : input.url;
  const method = (init.method || (input.method ?? "GET")).toUpperCase();
  const headers = Object.fromEntries(new Headers(init.headers || input.headers || {}).entries());
  const body = init.body || null;
  console.groupCollapsed(`🟡 FETCH ${method} ${url}`);
  console.log("headers:", headers);
  if (body) console.log("body:", body);
  try {
    const resp = await _origFetch.apply(this, arguments);
    const clone = resp.clone();
    const text = await clone.text().catch(() => null);
    console.log("status:", resp.status, resp.statusText);
    console.log("resp headers:", Object.fromEntries(resp.headers.entries()));
    console.log("resp body:", text?.slice(0, 2000));
    console.groupEnd();
    return resp;
  } catch (e) { console.error(e); console.groupEnd(); throw e; }
};

// 2) XMLHttpRequest wrapper
const _origOpen = XMLHttpRequest.prototype.open;
const _origSend = XMLHttpRequest.prototype.send;
const _origSetHdr = XMLHttpRequest.prototype.setRequestHeader;
XMLHttpRequest.prototype.open = function(m, u, ...a) {
  this.__m = m; this.__u = u; this.__hdrs = {};
  return _origOpen.call(this, m, u, ...a);
};
XMLHttpRequest.prototype.setRequestHeader = function(k, v) {
  this.__hdrs[k] = v;
  return _origSetHdr.call(this, k, v);
};
XMLHttpRequest.prototype.send = function(body) {
  console.groupCollapsed(`🟠 XHR ${this.__m} ${this.__u}`);
  console.log("headers:", this.__hdrs);
  if (body) console.log("body:", body);
  this.addEventListener("loadend", () => {
    console.log("status:", this.status);
    console.log("resp:", this.responseText?.slice(0, 2000));
    console.groupEnd();
  });
  return _origSend.call(this, body);
};

console.log("✅ fetch + XHR monkey-patched");
```

Use as a **tampermonkey userscript** for persistent capture across reloads.
For headless automation see Phase 6 (Chrome DevTools MCP).

### Phase 3: Service Worker Audit

Service Workers (`sw.js`) intercept every request — they often cache auth
tokens, hold offline secrets, and implement custom routing invisible to
network DevTools.

```javascript
// List active service workers + their scopes
navigator.serviceWorker.getRegistrations().then(regs =>
  regs.forEach(r => console.log("SW:", r.active?.scriptURL, "scope:", r.scope))
);

// Force-fetch the SW source
const swUrl = (await navigator.serviceWorker.getRegistrations())[0]?.active?.scriptURL;
console.log(await fetch(swUrl).then(r => r.text()));

// Check Cache Storage (often holds auth'd responses)
const cacheNames = await caches.keys();
for (const name of cacheNames) {
  const cache = await caches.open(name);
  const reqs = await cache.keys();
  console.group(`Cache: ${name} (${reqs.length} entries)`);
  for (const req of reqs.slice(0, 20)) console.log(req.url);
  console.groupEnd();
}

// Push subscription keys (sometimes leak the VAPID server key)
navigator.serviceWorker.ready.then(r =>
  r.pushManager.getSubscription().then(s => console.log("push sub:", s))
);
```

**What to look for:**
- `sw.js` handling `/api/*` requests — it often adds `Authorization` headers invisibly
- Cached responses containing user data (e.g., `/api/me`) — survives across sessions
- Background sync registrations — reveal retry logic and data persistence
- Push VAPID keys — public but useful for impersonation mapping

### Phase 4: Storage Dump

```javascript
// localStorage
console.table(Object.fromEntries(Object.entries(localStorage)));

// sessionStorage
console.table(Object.fromEntries(Object.entries(sessionStorage)));

// Cookies (document-accessible ones only)
console.log("cookies:", document.cookie);

// IndexedDB — enumerate DBs, dump recent entries
const dbs = await indexedDB.databases();
console.log("DBs:", dbs);
for (const {name} of dbs) {
  const db = await new Promise((ok, err) => {
    const r = indexedDB.open(name); r.onsuccess = () => ok(r.result); r.onerror = () => err(r.error);
  });
  for (const store of db.objectStoreNames) {
    const tx = db.transaction(store, "readonly");
    const entries = await new Promise(ok => {
      const out = [];
      const cur = tx.objectStore(store).openCursor();
      cur.onsuccess = e => { const c = e.target.result;
        if (!c || out.length > 20) return ok(out);
        out.push({key: c.key, value: c.value}); c.continue(); };
    });
    console.group(`${name}/${store}`); console.table(entries); console.groupEnd();
  }
}

// Cache Storage — covered in Phase 3

// Decode any JWT found above
function dec(j){ try { return JSON.parse(atob(j.split('.')[1])); } catch { return null; }}
```

**High-value finds:**
- JWT in localStorage / IndexedDB → decode `dec(token)` for claims
- Refresh tokens stored alongside access tokens (common AT+RT leak)
- User profile blobs with roles, permissions, organization IDs
- Feature flag cache (enable bypass testing)
- Analytics anonymous IDs (tracking attack surface)

### Phase 5: PostMessage & Cross-Frame Audit

```javascript
// Log every incoming postMessage (origin, data, source)
window.addEventListener("message", ev => {
  console.groupCollapsed(`📨 postMessage from ${ev.origin}`);
  console.log("data:", ev.data);
  console.log("source:", ev.source);
  console.trace();
  console.groupEnd();
}, true);

// Log every outgoing (wrap .postMessage)
const _origPM = window.postMessage;
window.postMessage = function(data, targetOrigin, transfer) {
  console.log(`📤 postMessage(→ ${targetOrigin}):`, data);
  return _origPM.apply(this, arguments);
};

// Iframe-of-iframe audit — enumerate embedded frames + origins
[...document.querySelectorAll("iframe")].forEach((f, i) =>
  console.log(`iframe[${i}]: ${f.src}`));
```

**What to look for:**
- Message handlers that skip `ev.origin` validation (trust-all vulnerability)
- Auth tokens passed via postMessage between first-party + third-party frames
- Command-style data `{action: "execute", code: "..."}` — classic XSS-to-RCE
- Cross-origin iframe communication without explicit allowlist

### Phase 6: WebSocket / SSE Interception

```javascript
// WebSocket wrapper
const _OrigWS = window.WebSocket;
window.WebSocket = function(url, protocols) {
  console.log(`🔌 WS → ${url}`, protocols);
  const ws = new _OrigWS(url, protocols);
  ws.addEventListener("message", e => console.log(`⬅ WS msg:`, e.data));
  const _send = ws.send.bind(ws);
  ws.send = function(data) { console.log(`➡ WS send:`, data); return _send(data); };
  return ws;
};
window.WebSocket.prototype = _OrigWS.prototype;

// EventSource (SSE) wrapper
const _OrigES = window.EventSource;
window.EventSource = function(url, init) {
  console.log(`📡 SSE → ${url}`);
  const es = new _OrigES(url, init);
  es.addEventListener("message", e => console.log(`⬅ SSE msg:`, e.data));
  return es;
};
```

### Phase 7: Chrome DevTools MCP Automation

If you're running inside a bugdotexe agent, `mcp__chrome-devtools__*` tools
automate the above. Key workflows:

```
# Spawn a page, navigate, capture every request:
mcp__chrome-devtools__new_page url=https://target.com
mcp__chrome-devtools__navigate_page url=https://target.com/login
mcp__chrome-devtools__list_network_requests

# Inject the monkey-patch JS from Phase 2 before any app code runs:
mcp__chrome-devtools__evaluate_script script="<PASTE phase 2 code>"

# Dump all network requests seen so far:
mcp__chrome-devtools__list_network_requests

# Pull a specific request's detail (body + headers):
mcp__chrome-devtools__get_network_request id=<id>

# Listen to console output (captures your monkey-patch logs):
mcp__chrome-devtools__list_console_messages

# Take a snapshot of the rendered DOM at runtime (reveals hidden admin UI):
mcp__chrome-devtools__take_snapshot

# Memory heap snapshot (find leaked secrets in closures):
mcp__chrome-devtools__take_memory_snapshot
```

Typical agent flow:
1. `new_page` + `navigate_page` to target
2. `evaluate_script` with the Phase 2 monkey-patch (before the SPA mounts)
3. Perform auth / navigation actions via `click`, `fill`, `type_text`
4. `list_network_requests` → extract every endpoint with method, status, content-type
5. `evaluate_script` with the Phase 4 storage-dump code
6. `get_console_message` to pull the captured logs

### Phase 8: Heap Snapshot Analysis

Closures leak secrets that never show up in source. Take a heap snapshot
(`Memory` tab → "Take heap snapshot") and grep it.

```javascript
// Programmatic (DevTools Protocol required, works from mcp__chrome-devtools__take_memory_snapshot)
// Look for: strings starting with "ey" (JWT), "sk_live_" (Stripe), "AIza" (Google),
//           entropy-high strings > 30 chars.
```

Export the snapshot file → grep for secret patterns with the same regexes from
`js_analysis.md` Phase 4.

## What to Look For — Runtime-Specific Wins

1. **Auth header construction** — every request captured by the fetch wrapper shows the exact `Authorization:` value built at runtime. Often reveals HMAC signature construction.
2. **Feature flag evaluation** — runtime values beat source-code defaults. Watch `localStorage.setItem("featureFlags", ...)` calls.
3. **Crypto in action** — `crypto.subtle.encrypt` / `CryptoJS.AES` calls are visible live. Snapshot keys from arg inspection.
4. **Service worker request rewriting** — compare in-page `fetch(URL)` to the actual network panel URL.
5. **PostMessage broadcasts** — capture data sent from privileged frames (auth iframe, payments iframe).
6. **WebSocket handshake tokens** — the subprotocol / query-string auth token passed at connection time.
7. **SSO callback payloads** — the full OAuth/OIDC callback POST body, including PKCE verifier.

## Tool / Extension Cheat Sheet

| Need | Tool | Notes |
|------|------|-------|
| Persistent monkey-patch | Tampermonkey | Save Phase 2 as a `@run-at document-start` userscript |
| Headless runtime capture | Playwright | `page.on("request")`, `page.on("response")` |
| Automated runtime recon | Chrome DevTools MCP | `mcp__chrome-devtools__*` (built into bugdotexe) |
| Traffic recording + replay | Caido / Burp | Proxy mode — already running in bug.exe sandbox |
| Service worker dev | Chrome Application tab | → Service Workers → Update on reload / Offline toggle |
| Heap snapshot diffing | Chrome Memory tab | "Comparison" view across 2 snapshots finds new leaks |
| Secret scan on heap | `strings heap.heapsnapshot \| grep ...` | Post-capture |

## Tips

1. **Arm the monkey-patch BEFORE auth** — if you paste after login, you miss the auth flow. Use Tampermonkey `@run-at document-start` for persistence.
2. **Capture then replay** — save fetch/XHR logs as curl commands for subsequent offline analysis:
   ```javascript
   // Extend the fetch wrapper to also print a curl:
   console.log(`curl '${url}' -X ${method} ${Object.entries(headers).map(([k,v])=>`-H '${k}: ${v}'`).join(' ')} --data '${body||''}'`);
   ```
3. **Heap snapshot diffs** — take one before login, one after. The diff shows every new credential / token loaded into closures.
4. **Service workers need Ctrl+Shift+R** — regular reload doesn't force re-fetch. Use hard reload or "Update on reload" in DevTools.
5. **Combine with Caido proxy** — DevTools shows what the app sees, Caido shows what the network sees. Discrepancies = SW rewriting or WASM-level logic.
6. **Agent loop** — if running in bugdotexe, `mcp__chrome-devtools__evaluate_script` + `list_network_requests` are faster than manual browser clicks.
7. **Never exfiltrate captured tokens beyond the program's scope** — they're real live secrets.
