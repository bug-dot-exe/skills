---
name: shopify
description: Shopify attack surface: webhook HMAC validation, app proxy auth, metafield enumeration
depends_on: []
---

# Shopify

Shopify is closed-source SaaS — bugs are usually in the merchant's app integrations. Webhook signature validation gaps and OAuth scope creep are recurring.

## Common Bug Classes

- Webhook HMAC validation skipped or wrong secret used
- App Proxy `signature` parameter not verified
- Metafields with `public` namespace exposing internal data via Storefront API
- Shop OAuth `scope` parameter granted but not enforced server-side
- Password-protected content bypassed via alternate access paths (embed, preview, share)
- Cross-app data-flow XSS (data enters via one app, renders unsanitized in another)
- GraphQL field authorization gaps (staff with no permissions can query sensitive fields)
- Email confirmation bypass in multi-step merchant flows

## State-Machine Adversarial Testing (162 reports, $113K corpus)

For every multi-step Shopify-integrated flow (signup, email change, payment update, account migration):
1. Complete the flow normally, capturing each request
2. Replay step N before step N-1 completes (out-of-order execution)
3. Skip the critical verification step — jump directly to the post-verification URL
4. Initiate the flow, then change identity mid-flow before confirmation completes
5. Test whether confirmation tokens are bound to the session/email that requested them
6. After a fix ships, re-enumerate every mutation primitive — accepted bugs indicate the entire flow is under-tested

## Password-Protected Content Bypass

When a Shopify store has password-protected pages:
1. Access the content through the primary auth path to understand what is protected
2. Check for alternate access paths: share URLs, embed widgets, preview links, API endpoints
3. Test if the password token is bound to a specific resource or replayable across all protected pages
4. Check Storefront API — password protection may not extend to API-fetched content
5. Test if the token binding covers the full content (page, images, API data) or only the HTML

## Staff Permission Escalation

### GraphQL Field Authorization Sweep
1. Capture authenticated GraphQL queries from the highest-privilege role (owner)
2. Re-issue every captured query from a staff account with `Settings` only permission
3. Pay special attention to: `orders`, `customers`, `products`, `financials`, `apps`
4. Test mutations: `appInstall`, `webhookSubscriptionCreate`, `scriptTagCreate`
5. `internal` / `private` / `admin-api` endpoints often skip staff permission checks

### Multi-Client Authorization Differential
When the Shopify admin API has multiple clients (admin UI, mobile app, developer tools, partner API):
1. Capture the same operation from each client
2. Compare authorization enforcement — mobile and partner APIs may grant broader access
3. Test operations that exist in one client but not another (hidden API endpoints)

## Cross-App Data-Flow XSS

When user-supplied content flows from one app to another within the Shopify ecosystem:
1. Enter a payload in App A (e.g., product description via the Product API)
2. Check where the same data renders in App B (e.g., Handshake, Email, POS, Shopify Inbox)
3. Each rendering context has different sanitization — an escaped value in App A may be raw in App B
4. First-party apps under the admin domain (`/admin/apps/shopify-email/editor`) are high-value XSS targets because they share the admin session

## SVG/XML Upload Bypass

For every Shopify SVG upload sanitizer:
1. Test with no DOCTYPE (baseline behavior)
2. Test with DOCTYPE only (no entities) — some parsers change behavior
3. Test with external entity reference: `<!DOCTYPE svg SYSTEM "http://attacker/evil.dtd">`
4. Test with internal entities expanding to XSS: `<!ENTITY xxs "javascript:alert(1)">`
5. Test with `<foreignObject>` containing raw HTML inside SVG
6. Try polyglot SVG/HTML files that are parsed as HTML in some contexts

## Template Injection Patterns

### Liquid / Twine Template Injection
When Shopify uses Liquid or Twine templates that process user data:
1. Test for expression evaluation: `{{ 7*7 }}`, `{% if true %}yes{% endif %}`
2. If expressions evaluate, test object access: `{{ shop.name }}`, `{{ customer.email }}`
3. Multi-layer template composition: if a value passes through Liquid then into a JS template engine (`Shopify.API.foo('{user_input}')`), injection at the JS layer may bypass Liquid escaping

### Sanitizer State Pollution
When client-side or server-side sanitizers operate on user-controlled JSON/object trees:
1. Look for sanitizer state shared across multiple sanitization passes
2. Test if attributes stripped in pass 1 affect how pass 2 handles remaining attributes
3. Test `"` stripping combined with attribute re-parsing to inject event handlers

## Shopify Cloud Infrastructure

### Subdomain Enumeration
1. Enumerate `*.shopifycloud.com` subdomains for internal tools
2. Check for known-platform default pages: Cortex (`/services`), Grafana (`/api/dashboards`), Kibana, Prometheus
3. Internal metrics endpoints (`/metrics`, `/debug/pprof`) on cloud subdomains often lack authentication
4. Git-related subdomains (`online-store-git.shopifycloud.com`) may have different auth requirements

### Mobile App and Mini-Program Surfaces
1. Map all clients: web admin, mobile apps, WeChat mini-programs, POS, Shopify Inbox
2. Each client may have different API endpoints, token validation, and authz enforcement
3. Mobile APIs often include IDOR-vulnerable lookup endpoints not exposed in the web admin
4. Mini-program APIs may use different auth schemes (WeChat OAuth) with weaker binding

## Cache Poisoning on Shopify Themes

### Host Header Cache Poisoning
For any Shopify-hosted storefront (themes.shopify.com, `*.myshopify.com`):
1. Test reflected-header cache poisoning: send requests with `X-Forwarded-Host: attacker.com` on cacheable URLs
2. If the response reflects the injected host in `<base>`, `<link>`, or `<script>` tags, and the response is cached, this is stored XSS via cache
3. Test with `X-Forwarded-Scheme: http` to force mixed-content or protocol-relative URL exploitation
4. Check `X-Cache` and `Age` response headers to confirm caching behavior

### S3 Bucket Exposure
1. Shopify mobile apps (Ping, Inbox, POS) may upload user content to S3
2. Capture the upload URL — test if the S3 bucket has public read access
3. Test if the bucket allows listing: `?list-type=2&prefix=`
4. If the bucket serves user-uploaded images, check if other users' images are accessible via predictable paths

## Integration Webhook and Host Header Attacks

### Reverse Proxy Misroute for Token Theft
On Shopify's authenticated GraphQL and REST endpoints:
1. Test Host header manipulation: send `Host: attacker.com` on authenticated requests
2. If the backend uses the Host header to route internal service calls, a misroute may expose the `X-Shopify-Access-Token` header to an attacker-controlled server
3. Test `X-Forwarded-Host`, `X-Original-Host` as alternative injection vectors
4. This pattern has yielded SSRF leading to internal token theft on Shopify infrastructure

## Probe Targets

- Send unsigned webhook payload, verify rejection
- Probe `/apps/*` (App Proxy) without signature
- Query Storefront API for metafield namespaces
- Test password-protected page access via embed/share/API paths
- GraphQL introspection query from a low-privilege staff account
- Enumerate `*.shopifycloud.com` subdomains for exposed internal services
- Test admin XSS via SVG upload with `foreignObject` payload
- Check `return_url` and `redirect` parameters for `javascript:` scheme acceptance
- Test error-rendering paths separately from success-rendering paths on forms
- Probe Host header manipulation on authenticated GraphQL endpoints

## Cross-References

`api_security`, `signature_replay`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
