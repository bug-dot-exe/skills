---
name: clickjacking
category: vulnerabilities
description: Clickjacking testing for UI redressing via iframe overlay, frame-ancestors bypass, drag-drop theft, and multi-step click chains that lead to account takeover or fund movement
depends_on: []
---

# Clickjacking

UI redressing that rides on an authenticated session. Pure "site is framable" reports are N/A on almost every modern program. To make it payable, you need a concrete sensitive action reached in a realistic click sequence with CSRF protection absent or bypassed, and you need to show the action actually fires through the frame.

## Discovery Signals

Signals that indicate a clickjacking opportunity worth pursuing. Each signal alone is informational; two or more in combination on the same endpoint justify building a PoC.

| # | Signal | How to detect | Why it matters |
|---|--------|---------------|----------------|
| 1 | No `X-Frame-Options` header | `curl -sI <url> \| grep -i x-frame` returns empty | Page has zero server-side frame protection |
| 2 | `X-Frame-Options: ALLOW-FROM` present | Header contains `ALLOW-FROM` | Deprecated; Chrome/Safari/Edge never supported it -- equivalent to missing header |
| 3 | No CSP `frame-ancestors` directive | `curl -sI <url> \| grep -i frame-ancestors` returns empty | Modern frame protection absent; XFO alone is insufficient |
| 4 | `frame-ancestors` includes wildcards or shared-hosting | CSP contains `*.firebaseapp.com`, `*.herokuapp.com`, `*.netlify.app`, `*.vercel.app`, `*.pages.dev`, `*.github.io`, `https:`, or `*` | Attacker can deploy content on the whitelisted platform and frame from there |
| 5 | CSP via `<meta>` tag only | View source; no HTTP header CSP, only `<meta http-equiv="Content-Security-Policy">` | Meta-tag CSP cannot enforce `frame-ancestors` at all -- browsers ignore it in meta |
| 6 | Single-click confirm buttons | Sensitive action has no re-auth, no CAPTCHA, no "type DELETE to confirm" | One click through the frame executes the action |
| 7 | `SameSite=None` or `SameSite=Lax` session cookies | Inspect `Set-Cookie` header | `None`: cookies always sent cross-site. `Lax`: sent on top-level navigation clicks (form POSTs in most browsers) |
| 8 | State-changing action on GET or tokenless POST | Action endpoint accepts GET, or POST body has no unpredictable CSRF token | Clickjack can trigger the action without needing to extract a token first |
| 9 | Static element IDs / stable CSS selectors | Inspect DOM; `#confirm-delete`, `#grant-access`, `.btn-primary` | Predictable selectors make overlay alignment trivial across sessions and screen sizes |
| 10 | JS-only frame busting with no header backup | Page has `if (top !== self)` JS but no XFO/CSP headers | Sandbox attribute disables JS while keeping forms functional -- buster dies, action lives |
| 11 | OAuth consent endpoint framable | `/oauth/authorize`, `/oauth/consent`, `/grant` renders in iframe | Highest-ROI clickjack target -- durable ATO via API scopes |
| 12 | Prefill parameters on sensitive forms | `?email=`, `?userstoinvite=`, `?recipient=`, `?to=` auto-populate form fields | Attacker controls the form value; victim only needs to click submit |

## Attack Surface

**Framework endpoints to target**
- Account deletion, email/phone change, password change confirmations
- OAuth/SSO consent screens (`/authorize`, `/oauth/consent`, `/grant`)
- 2FA disable/reset, trusted-device add, recovery-code reveal
- Fund movement: send, withdraw, transfer, one-click buy, tip, invoice pay
- Team/org actions: invite, role change, transfer ownership
- Admin toggles: make public, enable API key, rotate key
- Subscription: cancel, upgrade, change plan, auto-renew toggle

**Indirect but payable**
- Tabnabbing + reverse tabnabbing where opener is framable
- Double-clickjacking (Paulos Yibelo class, 2024): window.open + follow-up click on the opener to hit consent
- `allow-forms allow-same-origin` sandbox chaining where the sandbox strips frame-busting but keeps session

## Frame-Busting Bypass Matrix

Every defense has at least one bypass. Test each row against the target.

| # | Defense | Bypass Technique | Example |
|---|---------|-----------------|---------|
| 1 | `X-Frame-Options: DENY` | None -- hard block in all browsers | Move on; this endpoint is protected |
| 2 | `X-Frame-Options: SAMEORIGIN` | Subdomain takeover gives `*.target.com` origin that counts as same-origin for framing | Claim dangling CNAME on `old.target.com`, frame from there |
| 3 | `X-Frame-Options: ALLOW-FROM <uri>` | Chrome/Safari/Edge never implemented this; treat as no protection | Frame from any origin in Chrome; document browser support gap |
| 4 | `CSP: frame-ancestors 'self'` | Subdomain takeover or XSS on any `*.target.com` subdomain | Claim expired S3/Heroku/GitHub Pages CNAME, serve framing page from that subdomain |
| 5 | `CSP: frame-ancestors 'self' *.partner.com` | HTML injection, open redirect, or postMessage receiver on any `*.partner.com` host | Weaponize partner subdomain as a nested iframe pivot |
| 6 | `CSP: frame-ancestors` via `<meta>` tag | Browsers ignore `frame-ancestors` in meta-tag CSP entirely | Frame freely; `frame-ancestors` is only enforced via HTTP header |
| 7 | JS frame-buster: `if (top !== self) top.location = self.location` | `<iframe sandbox="allow-forms allow-same-origin">` -- omit `allow-scripts` so JS never runs, forms still submit | Single attribute defeats most JS busters |
| 8 | JS frame-buster checking `top` vs `self` | Double framing: `attacker.html` -> `middle.html` -> `target`; buster checks `top` which is middle, not attacker | Many busters only check one level of nesting |
| 9 | JS frame-buster with navigation | `onbeforeunload` on the outer page calls `event.preventDefault()` to cancel the bust navigation | Chrome shows a dialog but the bust is blocked |
| 10 | `CSP: frame-ancestors https:` or `frame-ancestors *` | No restriction -- anyone frames over HTTPS (or any origin) | Frame from attacker origin directly |
| 11 | CSP with shared-hosting wildcard (`*.firebaseapp.com`) | Deploy attacker page on Firebase; subdomain matches the CSP wildcard | Deploy to `evil-poc.firebaseapp.com`, frame target from there |
| 12 | Typoed directive (`frame-ancestor` singular, `frame-ancestor` vs `frame-ancestors`) | Browser silently ignores unrecognized directives | Check exact spelling in CSP; common copy-paste error |

## Click Target Matrix

What the victim clicks determines severity. Pair with the bypass matrix to build a complete attack.

| # | Target Action | Typical Severity | Technique Notes |
|---|--------------|-----------------|-----------------|
| 1 | OAuth consent grant (API scopes) | High / Critical | Frame `/oauth/authorize?client_id=<you>&scope=read:user+write:user&redirect_uri=<you>`. One click = durable ATO via API. Prefill `client_id` with an app you registered on the platform. |
| 2 | Change email (no reauth) | High | Prefill `?email=attacker@evil.com` if supported. Single click -> password reset -> ATO chain. |
| 3 | Disable 2FA / remove recovery | High | Target the "turn off" or "remove authenticator" button. One click removes the strongest auth factor. |
| 4 | Transfer funds / withdraw / pay invoice | High | Frame `/transfer/confirm` or `/withdraw/approve`. Show money moved between your own test accounts. |
| 5 | Add trusted device / passkey | High | Attacker's device becomes trusted. Persistent session access without credentials. |
| 6 | Grant admin role / transfer ownership | Medium / High | Frame team management page. One click elevates attacker's account or transfers org ownership. |
| 7 | Delete account / data | Medium / High | Irreversible action. Frame the confirm button. High impact but some programs consider it self-harm. |
| 8 | Make repo/profile/doc public | Medium | Frame the visibility toggle. Privacy breach; supply-chain risk for private repos. |
| 9 | Install integration / authorize webhook | Medium / High | Frame the "Connect" or "Install" button. Attacker's app gains API access to the workspace. |
| 10 | Follow / like / subscribe | Low | Social manipulation only. Include if program accepts social-action clickjacking. |

## Advanced Techniques

### Double-click attack (2024 -- Paulos Yibelo)
`window.open(target)` opens the consent page in a new window. The attacker page draws a decoy button; during the first click, attacker uses `window.opener.location` to swap the opener page while the popup receives the second click that hits the consent button. Defeats frame-based protections because the target is a top-level window, not an iframe.

### Cursor jacking
Apply `cursor: none` on the attacker page and render a CSS pseudo-cursor offset by 200px. The user aims at the fake cursor; the real click lands on the invisible iframe target. Effective on desktop; degrades on touchscreens where no cursor is shown. Combine with `pointer-events: none` on decoy layers to ensure clicks pass through.

### Drag-and-drop data exfiltration
The victim drags a visual element (puzzle piece, prize, game token) from the attacker page. The drag payload is not subject to same-origin policy, so it can be dropped into an invisible cross-origin iframe form field. The dropped content becomes the "new email" value, chat message body, or comment text. Works without JavaScript in the iframe if `sandbox="allow-forms"` is set.

### Touch event hijacking (mobile)
Mobile WebViews and in-app browsers often strip `X-Frame-Options` for embed compatibility. Touch events (`touchstart`, `touchend`) can be captured and replayed across iframe boundaries. The smaller mobile viewport makes overlay alignment easier -- one full-screen "tap to continue" button covers the entire frameable action area.

### Keyboard focus hijacking
Focus an invisible iframe input field via `autofocus` or programmatic `.focus()`. The victim types on what they believe is the attacker page (search box, chat), but keystrokes flow into the framed input. Useful when the target action requires typed confirmation (e.g., typing "DELETE" to confirm account removal, entering a transfer amount).

### Redirect-chain same-origin framing
Chain a path traversal or open redirect through a trusted subdomain to land an iframe on the target's own origin. The Google Docs chain ($413K bounty) used YouTube embed ID path traversal -> `/signin?next=` open redirect -> `accounts.youtube.com/SetSID` -> `docs.google.com` to achieve same-origin framing of Drive share dialogs, enabling one-click file hijack with layered iframe overlay.

### postMessage bridge exploitation
When the target uses iframe sandboxes communicating via `postMessage`, navigate a child iframe to `about:blank` from the parent context. The `about:blank` frame inherits message-listener access while still receiving `postMessage` events from the sandbox. Used in the Google Office Editing extension chain ($313K bounty) to leak Drive document content.

## Defense-Bypass Pairs

Specific defense configurations and the exact technique that defeats them.

| # | Defense Configuration | Bypass | Precondition |
|---|----------------------|--------|-------------|
| 1 | `X-Frame-Options: ALLOW-FROM https://trusted.com` only | Frame from any origin in Chrome/Safari/Edge | Victim uses any non-Firefox browser |
| 2 | `frame-ancestors 'self'` + dangling CNAME on `old.target.com` | Claim the subdomain; frame from `old.target.com` | Subdomain points to deprovisioned S3/Heroku/Azure/GitHub Pages |
| 3 | `frame-ancestors 'self' *.cdn.target.com` | Find JSONP, HTML injection, or open redirect on any CDN subdomain | Any content-injection primitive on the CDN wildcard |
| 4 | JS buster `if (top !== self) top.location = self.location` | `sandbox="allow-forms allow-same-origin"` (omit `allow-scripts`) | Target action submits via form, not JS |
| 5 | JS buster + `onbeforeunload` detection | Double framing through a middle page; buster checks `top` which is middle | Buster does not walk the full frame ancestry |
| 6 | CSP header + `frame-ancestors 'none'` | None -- fully protected | Move on to other endpoints |
| 7 | Re-authentication required before action | Combine with a self-XSS or XSS that leaks the reauth token, then clickjack | Requires a separate XSS primitive |
| 8 | `SameSite=Strict` session cookies | `window.open` same-site navigation (cookies sent for top-level nav); or use a `*.target.com` subdomain takeover for same-site context | Strict blocks cross-site iframes but not all same-site paths |

## Chain Patterns

Clickjacking alone is often Low/Informational. These chains escalate to High/Critical.

| # | Chain | Severity | How it works |
|---|-------|----------|-------------|
| 1 | Clickjack -> OAuth consent -> ATO | Critical | Frame `/oauth/authorize?client_id=<attacker>&scope=full`. One decoy click grants the attacker's app durable API access. Read email, change password via API, exfiltrate data. ($500 -- HackerOne #172289 proved this against Slack integration; $413K Google Docs chain used same-origin framing for Drive share dialog hijack.) |
| 2 | Clickjack -> email change -> password reset -> ATO | High / Critical | Frame the change-email page with `?email=attacker@evil.com` prefill. One click changes the account email. Attacker runs password reset on the new email. Full ATO in two steps. |
| 3 | Clickjack -> integration install -> data exfil | High | Frame the "Connect with Slack/GitHub/etc." button. Attacker forces victim's account to link to attacker-controlled service. Sensitive notifications, webhooks, or API data route to attacker. |
| 4 | Clickjack -> CSRF token leak -> further CSRF | Medium / High | Combine with a same-origin iframe that reads the CSRF token via `window.postMessage` listener. Then auto-submit a second form carrying the leaked token to perform actions the clickjack alone could not. |
| 5 | Subdomain takeover -> frame-ancestors bypass -> clickjack | High | Prove the dangling CNAME, claim the origin, frame the target from the taken-over subdomain to satisfy `frame-ancestors 'self'`. Chain converts an otherwise-useless subdomain takeover into ATO. |
| 6 | Clickjack -> drag-and-drop -> stored XSS | High | Drag an HTML payload from the attacker page into a rich-text comment field. The sanitizer trusts paste/drop-origin content. Stored XSS fires for every viewer. |
| 7 | Clickjack + reflected XSS (interaction-gated) | Medium / High | RXSS requiring a click (e.g., `url=javascript:...` in href context) is self-only without clickjacking. Frame the page with the XSS payload; one decoy click triggers execution. Converts Low self-XSS to one-click full XSS. (Multiple DoD reports -- #1149144, #1171403.) |
| 8 | Clickjack -> scanner/crawler RCE | Critical | Serve a clickjacking page to an automated scanner (Burp, Nessus). The scanner's auto-click logic deterministically triggers the overlay sequence, navigating the headless browser to `file://` or custom protocol handlers. Inverted clickjacking -- the "victim" is automated, making exploitation deterministic. ($3K -- PortSwigger #1274695.) |

## High-Value Targets

### OAuth / SSO consent hijack

- `/oauth/authorize?client_id=<attacker_app>&redirect_uri=<attacker>&response_type=token&scope=read:user`
- If the consent page is framable, a clickjack grants the attacker's OAuth app access to the victim's account. Triagers always accept this chain because it is durable ATO.
- Verify `redirect_uri` allowlist is loose enough to accept attacker-owned origin, OR use a vendored `client_id` you registered on the platform.

### Same-site, same-account ATO

- Change email page framable + no reauth + email change takes effect without click-to-confirm link = clickjack-to-ATO.
- Same pattern for adding a recovery phone / passkey / backup code.

### Financial / irreversible actions

- `/transfer/confirm`, `/withdraw/approve`, `/invoice/pay/<id>` -- show the POST fires with a framed click and money moves (use your own second account).
- One-click purchase / tipping / pay-to-unlock = payable even at low severity because impact is direct.

### Admin surface on tenant apps

- Make repo public, rotate org API key, enable webhook to attacker URL, add billing contact
- Supply-chain adjacent actions (install integration, approve app) are typically paid as High.

## Key Vulnerabilities

### Missing headers

Neither `X-Frame-Options: DENY|SAMEORIGIN` nor `Content-Security-Policy: frame-ancestors 'self'|'none'|<list>` present on the sensitive response. `X-Frame-Options: ALLOW-FROM` is deprecated and unsupported in Chromium -- treat as missing.

### CSP frame-ancestors misconfig

- `frame-ancestors *` or `frame-ancestors https:` -- anyone frames.
- `frame-ancestors 'self' *.partner.com` -- if any `*.partner.com` has HTML injection or open redirect to an attacker-controlled page inside an iframe, you pivot via the partner subdomain.
- Typoed directives in CSP (e.g., `frame-ancestor` singular) are ignored silently -- still vulnerable.
- Report-only CSP (`Content-Security-Policy-Report-Only`) does not enforce.

### JS-only frame busting

Server ships no headers but the page has `if (top !== self) top.location = self.location`. Bypassable:

- `<iframe sandbox="allow-forms allow-same-origin">` -- `allow-scripts` omitted, frame-bust JS never runs, forms still submit.
- `onbeforeunload` hijack: the outer attacker page registers `onbeforeunload` that calls `event.preventDefault()` to cancel the bust navigation.
- Double framing: `attacker.html` -> `middle.html` -> `target`. Many busters only check `top` vs `self`, not `parent`.

### Click timing / state swap

- `iframe.src` swapped via JS between user clicks so the same DOM coordinate hits different targets in sequence (e.g., click 1 = open settings, click 2 = delete).

### Drag-and-drop data theft

- Victim drags text (prize, puzzle piece) from attacker page into an invisible iframe form field. Lands as the "new email" or "reply" body. Works without same-origin because drag payload is not subject to SOP.

## PoC Template (copy-paste)

```html
<!doctype html>
<html><head><style>
  body { margin:0; font-family:sans-serif; }
  .bait { position:absolute; top:300px; left:300px; padding:18px 32px;
          background:#16a34a; color:#fff; font-size:20px; cursor:pointer; z-index:1; }
  iframe { position:absolute; top:260px; left:260px; width:300px; height:120px;
           opacity:0.0001; z-index:2; border:0; }
</style></head>
<body>
  <h2>Claim your prize</h2>
  <div class="bait">Click to claim $50</div>
  <iframe src="https://TARGET/settings/delete-account?confirm=1"
          sandbox="allow-forms allow-same-origin allow-top-navigation-by-user-activation">
  </iframe>
</body></html>
```

For multi-step: keep two iframes, toggle `display:none` on each in a `setTimeout` chain synced to visible bait-button repositions.

## Testing Methodology

1. **Pull headers** -- `curl -sI https://target/<path>` for every sensitive endpoint. Grep `X-Frame-Options` and `frame-ancestors`. Missing on any state-changing endpoint is the entry point.
2. **Frame it** -- load the target in a throwaway HTML file served over `python3 -m http.server`. Confirm the page actually renders (some apps ship JS-only busters).
3. **Map the click** -- open devtools on the framed page, find the selector of the confirm button, measure offsetX/offsetY from an anchor.
4. **Authentication model** -- confirm the action works for an already-logged-in victim (SameSite cookie behavior). If `SameSite=Strict`, top-level click from attacker origin will NOT send cookies -- kill the finding unless you can navigate inside an allowed context.
5. **CSRF check** -- inspect the POST: does it carry `X-CSRF-Token`, anti-forgery field, or double-submit cookie? If yes and token is not fetchable from a framed same-origin endpoint, clickjack alone is insufficient.
6. **Reauth check** -- does the action require password re-entry, OTP, or webauthn gesture? If yes, it is N/A.
7. **Build the chain** -- if single-click works, PoC it. If multi-step, use a decoy game (whack-a-mole, captcha) where each click lines up with a real target click.
8. **Record** -- video or GIF of victim-tab state before/after. Browser console open to show POST firing.

## Validation

1. Show the sensitive page rendering inside an attacker-controlled iframe (screenshot with attacker URL bar).
2. Show the state change actually happening on the target (victim account shows "email changed" / "session terminated" / "app authorized").
3. Prove the victim did not intentionally click the real control -- narrate the decoy UX.
4. Reproduce in current stable Chrome or Firefox. Do not rely on dead browsers.
5. Confirm `SameSite` and CSRF behavior -- a clickjack that cannot carry session cookies to the POST is theoretical.

## False Positives

- Page is framable but no state-changing action on it (static marketing, docs, login-only with no autologin). Triage closes these as informational.
- Action requires password reauth, OTP, or webauthn -- clickjack cannot produce that gesture.
- `SameSite=Strict` session cookies + cross-site click -- the POST lands without auth and fails.
- `X-Frame-Options: SAMEORIGIN` plus no open redirect / subdomain takeover anywhere useful.
- Target only framable from `localhost` or your own origin because of CSP allowlist you happen to control.
- Triager pushback: "user would notice" -- preempt with a believable decoy (prize claim, captcha, video play button) and a video PoC.
- Triager pushback: "requires social engineering" -- every clickjack does; point to the program policy (most H1/Bugcrowd programs accept clickjacking-to-sensitive-action).

## Impact

- Account takeover via email/password/2FA change in one or two clicks
- OAuth consent theft granting durable API access to attacker apps
- Unauthorized fund movement, purchases, subscription changes
- Org-level takeover: ownership transfer, API key rotation, webhook to attacker
- Privacy exposure via "make public" toggles on repos, docs, profiles

## Pro Tips

1. Sensitive-action + missing header is the baseline; always prove the action fires end-to-end, not just that the frame loads.
2. `SameSite=Lax` cookies ride top-level navigation clicks (form POSTs in many browsers) -- clickjack still works; `Strict` usually kills it.
3. When only frame-busting JS protects, try `sandbox` first; it is one attribute and defeats most busters.
4. OAuth consent endpoints are the highest-ROI clickjack targets -- bounty committees understand the impact immediately.
5. For multi-step, record a 15-second video. Text-only PoCs for chained clickjacks get closed as "unclear".
6. If the program explicitly excludes clickjacking, check whether a concrete ATO chain still qualifies under "authentication" -- write the report under the chain, not under "clickjacking".
7. Check the mobile web view -- mobile clients often strip `X-Frame-Options` for embed support and are still framable.
8. Double-clickjacking via `window.opener` is current (2024) and often overlooked; try it when single-frame fails.
9. Always check for prefill parameters (`?email=`, `?userstoinvite=`, `?to=`, `?recipient=`) on framed forms -- they convert a "victim clicks submit" into "victim clicks submit on attacker-controlled data" without needing drag-and-drop.
10. When a reflected XSS requires user interaction to trigger (click on a link, press a button), test framing immediately. Clickjacking converts self-only RXSS to one-click full XSS -- programs that reject standalone clickjacking still pay for this chain.
11. Legacy/undocumented URL formats (`/a/{workspace}/...`, `/u/{N}/...`, `/folders/{ID}/edit`) often bypass frame restrictions that only apply to canonical paths. Mine old documentation and Wayback Machine for deprecated routes.
12. Automated tools (scanners, crawlers, link-preview generators) that auto-click are deterministic clickjacking victims. If your target processes attacker-controlled HTML, the tool's automation replaces the human click -- no social engineering required.
13. Enumerate every frameable action including those behind "disabled" UI buttons -- the disabled state is client-side; a framed form submit bypasses the button entirely ($313K SVG-filter iframe enumeration pattern).
14. Check `frame-ancestors` via `<meta>` tag vs HTTP header -- browsers ignore `frame-ancestors` in meta-tag CSP entirely; treat meta-only CSP as no protection.
15. Cross-tab dialog origin attribution: verify that browser dialogs/prompts triggered by web content visually attribute to the correct origin -- misattribution enables permission/consent phishing without framing.

## Reporting Template (minimum fields)

- Target URL and exact state-changing endpoint
- Observed headers: `X-Frame-Options`, `Content-Security-Policy` (paste raw)
- `SameSite` attribute of the session cookie and whether the POST is GET or POST
- CSRF protection status on the action
- Frame-bust JS present? If yes, which bypass you used (sandbox, double-frame, opener trick)
- Step-by-step victim UX with decoy description
- Final state on the victim account (screenshot or video, time-stamped)
- Browser + OS versions where the PoC was reproduced

## Severity Calibration

| Scenario | Typical severity on H1/Bugcrowd |
|----------|---------------------------------|
| OAuth consent clickjack granting API scopes | High / Critical |
| Email change + password reset chain (single-click ATO) | High |
| 2FA disable without reauth | High |
| Fund transfer / withdraw / irreversible purchase | High |
| Make repo/profile public, settings toggles | Medium |
| Add admin member, role upgrade | Medium / High |
| Subscribe/unsubscribe, low-value prefs | Low |
| Framable but no sensitive action | Informational (usually N/A) |

## Summary

A clickjacking report pays when you prove a specific, irreversible, session-backed action fires through a frame the victim realistically clicks. Everything else -- "site is framable" -- is an informational. Hunt OAuth consents, email/phone change, withdraw/confirm, and org-level toggles, and always show the state change after the click.
