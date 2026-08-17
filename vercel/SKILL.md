---
name: vercel
description: Vercel attack surface: serverless function cold-start trust, deployment URL abuse, env exposure
depends_on: []
---

# Vercel

Vercel hosts Next.js and other frameworks. Bug surface: deployment URL hierarchy (`<branch>-<project>.vercel.app`) leaking pre-prod, env var exposure via `process.env` in client bundles, edge function trust.

## Common Bug Classes

- Pre-prod deployment URLs (`*-git-<branch>.vercel.app`) accessible without auth
- `NEXT_PUBLIC_*` env vars containing secrets
- Edge middleware bypass via `x-middleware-skip` (older versions)
- Vercel Auth bypass via cookie tampering
- Subdomain takeover on dangling Vercel CNAME records
- Shared infrastructure library vulnerabilities affecting all Vercel-hosted sites
- Container escape in serverless function environments
- Build artifact and deployment config exposure

## Pre-Production Deployment Exposure (33 reports, $3.2M corpus)

### Deployment URL Enumeration
Vercel generates predictable deployment URLs for every git push:
1. Pattern: `<project>-<git-branch>-<team>.vercel.app` and `<project>-<hash>.vercel.app`
2. Enumerate branches: `main`, `staging`, `develop`, `feature-*`, `fix-*`, `release-*`
3. Pre-prod deployments often have: weaker auth, debug endpoints enabled, test API keys, verbose error messages
4. Check if preview deployments have different CSP, CORS, or auth requirements than production
5. Use cert transparency logs to discover `*.vercel.app` subdomains matching the target project name

### Environment Variable Leakage
1. Grep the client-side bundle for `NEXT_PUBLIC_` keys — these are intentionally exposed but may contain secrets
2. Check for non-public env vars accidentally bundled: `process.env.DATABASE_URL`, `process.env.SECRET_KEY`
3. Source maps (`.map` files) on preview deployments may reveal the full server-side code including env var references
4. Check `/_next/static/chunks/` for embedded configuration objects with API keys

## Shared Infrastructure / Library Universal Impact

### Next.js Library Vulnerabilities
When a vulnerability exists in Next.js itself (the framework Vercel develops and most Vercel sites use):
1. Identify the vulnerability class (SSRF in middleware, XSS in error pages, auth bypass in API routes)
2. Every Vercel-hosted Next.js site running the affected version is a potential target
3. Test specifically: middleware auth bypass, `_next/data` route parameter injection, server action deserialization
4. Check the target's Next.js version via `/_next/static/` asset paths or `x-powered-by` header

### Per-Tenant Hostname Exploitation
When Vercel serves per-user/per-tenant hostnames (preview deploys, custom domains):
1. Each tenant hostname shares the same `*.vercel.app` origin for cookie scoping purposes
2. Test if cookies set on `<attacker>.vercel.app` are readable from `<victim>.vercel.app`
3. Test cross-tenant request forgery via shared cookie domain

## Subdomain Takeover

### Dangling Vercel CNAME
1. Scan for CNAME records pointing to `cname.vercel-dns.com` or `*.vercel.app`
2. If the Vercel project has been deleted or the domain is unclaimed, the CNAME dangles
3. Claim by adding the domain in a Vercel project you control
4. After takeover: check if the subdomain appears in CSP, CORS, OAuth redirect_uri, or `frame-ancestors` policies of the parent domain

### Impact Amplification
A taken-over subdomain on a major organization can:
1. Host phishing pages with legitimate-looking URLs
2. Serve malicious scripts if the subdomain is in CSP `script-src`
3. Steal OAuth tokens if the subdomain is in `redirect_uri` allowlists
4. Intercept postMessage communications if the subdomain is in origin validation checks

## Serverless Function and Edge Middleware Attacks

### Container Escape / Function Isolation
When Vercel runs untrusted code (serverless functions, edge middleware):
1. The first hypothesis is: can you escape the sandbox?
2. Test: file system access outside the function's directory (`/tmp`, `/proc`, `/etc`)
3. Test: network access to cloud metadata (`169.254.169.254`, `fd00::`) from within the function
4. Test: environment variable enumeration from within the function (`Object.keys(process.env)`)

### Edge Middleware Bypass
1. Test with `x-middleware-skip: 1` header (patched in newer versions, still present in legacy deployments)
2. Test with `x-middleware-rewrite` and `x-middleware-next` headers for middleware flow manipulation
3. If middleware performs authentication checks, bypassing it grants unauthenticated access to all routes

### Server Actions and API Routes
1. Next.js server actions can be invoked directly via POST to `/_next/` paths
2. Test if server actions validate the calling context (are they callable from outside the expected page?)
3. Test API routes (`/api/*`) for missing authentication that the middleware was supposed to enforce

## Build Artifact and Config Exposure

### Static File Mining
1. Check `/_next/static/` for: chunk files with embedded configs, source maps, build manifests
2. Test `/.vercel/output/` and `/.vercel/project.json` for deployment configuration exposure
3. Check for Helm charts, Docker Compose files, Terraform configs in public repos associated with the project
4. Look for `vercel.json` in public repos — it reveals routes, rewrites, headers, and function configurations

### Infrastructure-as-Code Credential Mining
1. Check public repos for `values.yaml`, `docker-compose.yml`, `.env.example`, `terraform.tfvars`
2. These files often contain: database credentials, API keys, internal service URLs, cloud provider secrets
3. Even `.env.example` may contain real credentials that were copy-pasted instead of placeholder values

## Protocol Assumption vs Deployment Reality

### ACME TLS-SNI Challenge Abuse
On shared hosting platforms like Vercel:
1. ACME TLS-SNI-01/02 certificate validation assumes each IP serves one hostname
2. On shared infrastructure (many tenants per IP), an attacker on the same platform can intercept the validation challenge
3. This allows issuing TLS certificates for domains you do not own
4. Newer ACME challenges (HTTP-01, DNS-01) are not vulnerable to this, but legacy configurations may still use TLS-SNI

## Demo and Staging Deployment Targeting

1. Test demo/staging/sandbox deployments first — they run older code with weaker security headers
2. Look for `demo.target.com`, `staging.target.com`, `sandbox.target.com` subdomains
3. Preview deployments (`<branch>-<project>.vercel.app`) are effectively staging environments accessible to anyone who can guess the URL
4. Same DOM, same cookies, weaker CSP — bugs found on staging often reproduce on production

## Next.js Specific Attack Patterns

### Server-Side Request Forgery via API Routes
1. Next.js API routes (`/api/*`) run server-side with full network access
2. If any API route accepts a URL parameter and fetches it (image proxy, link preview, webhook test), test for SSRF
3. Internal targets: `http://169.254.169.254/latest/meta-data/`, `http://localhost:3000/api/admin/`, internal service hostnames
4. Next.js `getServerSideProps` and `getStaticProps` also run server-side — if they fetch user-influenced URLs, same SSRF risk

### Data Fetching Route Injection
1. Next.js data routes (`/_next/data/<buildId>/<page>.json`) serve the server-side props as JSON
2. If a route parameter is user-controlled and used in a database query or file path, injection applies
3. Test: `/_next/data/<buildId>/admin.json` — may return admin-only data if the auth check is only on the page component, not the data route
4. Build IDs are predictable from `/_next/static/` asset paths

### ISR (Incremental Static Regeneration) Cache Poisoning
1. ISR pages are statically generated and cached, then revalidated on a timer
2. If the page content depends on request headers (User-Agent, Accept-Language), test if different header values produce different cached versions
3. If ISR revalidation fetches from an API that is SSRF-able, you can poison the static cache for all users
4. Test `x-vercel-cache` header for cache status and `x-vercel-id` for regional edge information

## Probe Targets

- Subdomain enumeration on `*.vercel.app` for pre-prod deployments
- Grep bundle for `NEXT_PUBLIC_` keys and `process.env` references
- Test middleware with various `x-middleware-*` headers
- Check for source maps at `/_next/static/chunks/*.map`
- CNAME records pointing to `cname.vercel-dns.com` for dangling entries
- Test server actions via direct POST to `/_next/` paths
- Check `/.vercel/output/` and `/.vercel/project.json` for config exposure
- Enumerate preview deployment URLs via cert transparency and branch name guessing
- Test serverless function metadata access (`169.254.169.254`, `process.env`)
- Check Next.js version and cross-reference against known CVEs

## Cross-References

`deep_subdomain_enum`, `information_disclosure`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
