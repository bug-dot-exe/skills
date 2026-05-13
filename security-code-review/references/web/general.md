# Web Hardening — Non-Obvious Patterns

XSS, CSRF, CORS, CSP, headers, and rate limiting patterns that are commonly
misconfigured.

## CSP: Nonce-Based Script Allowlisting

`script-src 'self'` blocks inline scripts but allows any script served from
your origin. For tighter control, use nonces: `script-src 'nonce-{random}'`
on each response, with matching `<script nonce="{random}">` tags. The nonce
must be cryptographically random and unique per response.

## CORS: Wildcard + Credentials = Always Dangerous

`Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`
is explicitly forbidden by the spec, but some browsers/frameworks handle it
inconsistently. More dangerous: reflecting the request's `Origin` header as the
allowed origin — this effectively allows any site to make credentialed requests.
Always use an explicit allowlist of origins.

## Rate Limiting: By IP AND By User

IP-only rate limiting is bypassed via IP rotation (trivial with cloud functions).
User-only rate limiting allows unauthenticated abuse. Combine both: rate limit by
IP for unauthenticated requests, and by authenticated user ID for authenticated
ones. For auth endpoints, use strict limits (5/minute) with progressive backoff.

## Rate Limit Bypass Techniques

Pentesters routinely bypass rate limits via:
- `X-Forwarded-For` / `X-Real-IP` header manipulation (if the limiter trusts them)
- URL variations: `/api/login` vs `/api/login/` vs `/api/Login`
- Parameter variations: adding extra params
- Distributed requests across IPs

Ensure your rate limiter normalizes paths, ignores spoofable headers behind
trusted proxies, and has reasonable limits even per-IP.

## X-XSS-Protection: Set to 0

The `X-XSS-Protection` header's filter mode is deprecated and can actually
introduce vulnerabilities. Set it to `0` (disabled) and rely on CSP instead.
This is counterintuitive but correct.

## SameSite Cookies and Third-Party Auth

`SameSite=Strict` blocks the cookie on all cross-site requests, including
legitimate OAuth redirects back to your site. For auth flows involving
third-party redirects, use `SameSite=Lax` (allows top-level navigations)
and add Origin header validation as defense in depth.
