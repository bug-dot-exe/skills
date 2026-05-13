---
name: bbrecon-api-discovery
description: API and auth endpoint discovery for bug bounty recon. Use when mapping attack surface, after bbrecon crawl phase, or when targeting API-heavy programs. Covers GraphQL introspection, OpenAPI/Swagger, OAuth/OIDC discovery, webhook patterns, and SDK/Postman collection mining.
---

# bbrecon API Discovery

Finds API surfaces that crawlers and directory brute-forcing miss.

## When to Use

- Target has mobile app in scope (backend APIs)
- Crawl found `/api/` or `/graphql` paths
- Program scope includes `*.target.com` (API subdomains)
- Auth flow uses OAuth/OIDC (login.target.com, auth.target.com)

## 1. GraphQL Discovery

```bash
# Introspection (if introspection enabled)
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}' | jq .

# Full schema dump
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}' > graphql_schema.json

# Common paths
for path in /graphql /api/graphql /v1/graphql /query /gql; do
  curl -s -o /dev/null -w "%{http_code} $path\n" "https://target.com$path" -X POST -H "Content-Type: application/json" -d '{}'
done
```

## 2. OpenAPI / Swagger Discovery

```bash
# Standard paths
for path in /.well-known/openapi /openapi.json /swagger.json /api-docs /api/swagger.json /v1/swagger.json /api-docs/swagger.json; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
  [ "$code" = "200" ] && echo "FOUND: https://target.com$path"
done

# From crawl output
grep -E "(swagger|openapi|api-docs)" CRAWLING/all.crawled.urls
```

## 3. OAuth / OIDC Discovery

```bash
# Well-known endpoints (no auth needed)
curl -s "https://login.target.com/.well-known/openid-configuration" | jq .
curl -s "https://auth.target.com/.well-known/oauth-authorization-server" | jq .

# Key fields: authorization_endpoint, token_endpoint, jwks_uri, registration_endpoint
# Test: redirect_uri validation, PKCE, dynamic client registration
```

## 4. Auth Endpoint Patterns

| Pattern | Example |
|---------|---------|
| OAuth | `/oauth/authorize`, `/oauth/token`, `/oauth/callback` |
| OIDC | `/.well-known/openid-configuration`, `/userinfo` |
| SAML | `/saml/login`, `/saml/metadata` |
| Custom | `/auth/login`, `/api/auth/*`, `/v1/session` |

```bash
# Probe from live hosts
cat LIVE/all.live.sub | while read h; do
  for path in /.well-known/openid-configuration /oauth/authorize /api/auth/login; do
    curl -s -o /dev/null -w "%{http_code} https://$h$path\n" "https://$h$path"
  done
done | grep -v "404\|000"
```

## 5. Webhook / Callback Patterns

APIs that accept URLs (SSRF, open redirect surface).

```bash
# From JS analysis
grep -rE "(webhook|callback|redirect_uri|return_url|url\s*:)" JS/ | grep -v node_modules

# Common param names
# webhook_url, callback, redirect_uri, return_to, success_url, failure_url, notify_url
```

## 6. SDK / Postman / API Docs

```bash
# GitHub
# "target.com" filename:postman extension:json
# "target.com" path:openapi path:swagger

# Public Postman workspaces
# postman.com/search?q=target.com

# Extract from mobile app (apktool/jadx)
# Look for base URLs in strings.xml, NetworkSecurityConfig
```

## 7. API Versioning

Old versions often lack security controls.

```bash
# Enumerate versions
for v in v1 v2 v3 api/v1 api/v2 1.0 2.0; do
  curl -s -o /dev/null -w "%{http_code} /$v\n" "https://api.target.com/$v"
done
```

## 8. bbrecon Integration

- **CRAWL output:** `CRAWLING/all.crawled.urls` — grep for api, graphql, swagger
- **JS output:** `JS/all.endpoints.urls` — linkfinder extracts API paths from bundles
- **Params:** `ACTIVE/PARAMS/all.params.txt` — API params from paramspider/arjun

```bash
# After crawl
grep -E "(/api/|/graphql|/v[0-9]/|swagger|openapi)" CRAWLING/all.crawled.urls | sort -u > ACTIVE/api_candidates.txt
```

## Output Convention

- `ACTIVE/api_candidates.txt` — URLs to probe
- `ACTIVE/graphql_schema.json` — introspected schema
- `ACTIVE/oauth_config.json` — OIDC discovery

## References

- strix-graphql — GraphQL testing
- strix-authentication-jwt — OAuth/OIDC testing
- bb-hunter recon.md — base pipeline
