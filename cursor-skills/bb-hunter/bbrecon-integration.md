# bbrecon Integration

When the project includes **bbrecon** (bug bounty recon framework), use it as the primary recon pipeline. bb-hunter workflows consume bbrecon output.

## Workflow

```
1. Run bbrecon       → ./bbrecon run -d target.com
2. Consume output    → Use ASSETS/, LIVE/, ACTIVE/, CRAWLING/, JS/, ACTIVE/API/, ACTIVE/PARAMS/
3. Map + Test        → Caido + Playwright, strix-* skills
```

## bbrecon Output Paths

| Path | Content | Use for |
|------|---------|---------|
| `ASSETS/all.passive.sub` | Passive subdomains | Subdomain list |
| `ASSETS/all.active.sub` | Resolved subdomains (dnsx, alterx, gotator) | Live probing |
| `LIVE/all.live.sub` | Live hosts | Crawl targets |
| `LIVE/httpx.urls` | Full URLs (https://...) | Param discovery, API discovery |
| `ACTIVE/JUICY/juicy.focus.live.txt` | Prioritized live URLs | Start here for testing |
| `CRAWLING/all.crawled.urls` | Crawled URLs | Param extraction, URL surface |
| `JS/all.endpoints.urls` | Endpoints from JS | Hidden API routes |
| `ACTIVE/API/api_candidates.txt` | API endpoints found | GraphQL, OpenAPI, OAuth testing |
| `ACTIVE/API/graphql_found.txt` | GraphQL endpoints | strix-graphql |
| `ACTIVE/API/oauth_found.txt` | OAuth/OIDC endpoints | strix-authentication-jwt |
| `ACTIVE/PARAMS/all.params.txt` | URLs with params | IDOR, param-based attacks |
| `ACTIVE/PARAMS/all.param.keys.txt` | Param names only | Param fuzzing |

## When to Run bbrecon

- **Before hunting** — Run full pipeline: `./bbrecon run -d target.com`
- **Resume** — `./bbrecon run -d target.com --resume` to skip completed phases
- **Phases only** — `./bbrecon run -d target.com --only assets,post_assets` for quick subdomain + API discovery
- **Batch** — `./bbrecon run -l domains.txt -o output` for multiple targets

## Feeding bbrecon into bb-hunter

1. **Crawl targets** — Use `LIVE/httpx.urls` or `ACTIVE/JUICY/juicy.focus.live.txt` as input for Playwright.
2. **API testing** — Start with `ACTIVE/API/graphql_found.txt`, `openapi_found.txt`, `oauth_found.txt`.
3. **Param testing** — Use `ACTIVE/PARAMS/all.params.txt` for IDOR/SSRF/XSS param fuzzing.
4. **Caido scope** — Import `LIVE/httpx.urls` into Caido scope for in-proxy testing.

## bbrecon Skills (Extension)

When extending recon beyond bbrecon's default:

| Skill | When to use |
|-------|-------------|
| `bbrecon-subdomain-deep` | Passive enum returns few results; need permutation discovery |
| `bbrecon-api-discovery` | API-heavy scope; bbrecon's API discovery found nothing |
| `bbrecon-scope-expansion` | Narrow scope; wildcard interpretation; post-acquisition |
| `bbrecon-parameter-discovery` | Param discovery returns few; heavy JS target |

## Config Sync

bbrecon scope: `config/scope.yml`. Use `./bbrecon scope-sync` to import from HackerOne/Bugcrowd exports. Keep scope aligned with program policy.

## Cloudflare / WAF Blocked

When bbrecon's httpx/curl returns 403 (Cloudflare challenge):
- Use Playwright through Caido proxy to solve JS challenge
- Capture session cookies after browser load
- Re-run API discovery or param discovery with session
