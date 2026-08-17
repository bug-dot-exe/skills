---
name: api-endpoint-discovery
category: reconnaissance
description: Systematic API endpoint enumeration using tech-aware wordlists, ffuf fuzzing, Swagger/OpenAPI parsing, and multi-source merging
depends_on: []
---

# API Endpoint Discovery

## When to Use
- Target has an API (detected via tech fingerprinting or `/api` path)
- After subdomain enumeration to discover API services
- Before vulnerability testing to build the endpoint map

## Methodology

### Phase 1: Documentation Discovery (free endpoints)

Check for exposed API documentation first — instant full endpoint map:

```bash
for doc_path in /swagger.json /openapi.json /api-docs /swagger-ui.html \
  /swagger/v1/swagger.json /v1/api-docs /v2/api-docs /v3/api-docs \
  /openapi.yaml /.well-known/openapi /redoc /docs /api/docs \
  /api/swagger /api/schema /graphql /graphiql /altair; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$doc_path" --max-time 5)
  [ "$CODE" = "200" ] && echo "[+] API docs found: $TARGET$doc_path (HTTP $CODE)"
done

# Parse Swagger/OpenAPI if found
curl -s "$TARGET/swagger.json" 2>/dev/null | python3 -c "
import sys,json
try:
  spec=json.load(sys.stdin)
  for path in spec.get('paths',{}):
    methods=','.join(spec['paths'][path].keys()).upper()
    print(f'{methods} {path}')
except: pass
" 2>/dev/null
```

### Phase 2: Tech-Aware Wordlist Selection

Select wordlists based on detected technology stack:

**Wordlist Priority:**
1. **fuzz4bounty** (curated for bounties): `/usr/share/wordlists/fuzz4bounty/`
   - `discovery/api.txt` — API-specific paths
   - `discovery/admin.txt` — Admin panel paths
   - `directory/dicc.txt` — General directory discovery
2. **Assetnote** (tech-specific, auto-generated from real targets):
   - `httparchive_php_2024.txt` — PHP endpoints from HTTP Archive
   - `httparchive_aspx_asp_cfm_svc_ashx_asmx.txt` — .NET paths
   - `httparchive_jsp_jspa_do_action.txt` — Java paths
3. **SecLists**: `/usr/share/seclists/Discovery/Web-Content/`
   - `api/api-endpoints.txt` — General API paths
   - `raft-medium-directories.txt` — Common directories
   - `spring-boot.txt` — Spring Boot actuators
4. **Fallback**: `/usr/share/wordlists/dirb/common.txt`

**Tech → Wordlist mapping:**
```
PHP detected     → fuzz4bounty/technologies/php.txt + assetnote/php
Node.js/Express  → api-endpoints.txt + assetnote/nodejs
Java/Spring      → spring-boot.txt + assetnote/java
Python/Django    → django-specific paths + api-endpoints.txt
Ruby/Rails       → rails.txt + api-endpoints.txt
.NET/ASP         → assetnote/aspx + IIS shortname
GraphQL          → graphql introspection (skip fuzzing)
```

### Phase 3: Fuzzing with ffuf

```bash
# Primary pass — tech-aware wordlist
ffuf -u "$TARGET/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,301,302,401,403,405,500 \
  -fc 404 -t 50 -o ffuf_primary.json -of json

# Second pass — custom wordlist from historical URLs + JS endpoints
# (built by url_crawl and js_analysis skills)
[ -f custom_wordlist.txt ] && ffuf -u "$TARGET/FUZZ" \
  -w custom_wordlist.txt \
  -mc 200,201,301,302,401,403,405,500 \
  -fc 404 -t 30 -o ffuf_custom.json -of json

# Extension fuzzing on discovered directories
ffuf -u "$TARGET/api/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -e .json,.yaml,.yml,.xml,.txt,.bak,.old,.conf,.env \
  -mc 200,301,302,401,403,500 -t 30

# Version enumeration
for ver in v1 v2 v3 v4 v0 beta staging internal; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/api/$ver/" --max-time 3)
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "[+] /api/$ver/ → HTTP $CODE"
done
```

### Phase 4: Quick Checks for Common High-Value Paths

Always test these regardless of tech stack:

```bash
# Admin/debug endpoints
for path in /admin /dashboard /manage /console /debug /trace \
  /actuator /actuator/env /actuator/health /actuator/heapdump \
  /.env /config /settings /phpinfo.php /server-status /server-info \
  /elmah.axd /web.config /wp-admin /wp-login.php; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$path" --max-time 3)
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "[+] $path → HTTP $CODE"
done

# GraphQL introspection
curl -s -X POST "$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}' | \
  python3 -c "import sys,json;d=json.load(sys.stdin);print('GraphQL introspection enabled!' if '__schema' in str(d) else 'Introspection disabled')" 2>/dev/null
```

## Response Interpretation

- **200** → Accessible, test for auth bypass (try without token)
- **401** → Auth required — high-value target, test with different tokens
- **403** → Forbidden — try path mutation, method change, header injection
- **405** → Method not allowed — try POST/PUT/DELETE/PATCH/OPTIONS
- **500** → Server error — info disclosure, send malformed input to trigger stack traces
- **301/302** → Redirect — follow it, might reveal internal paths

## Corpus-Derived Hunting Patterns

Techniques extracted from high-bounty disclosed reports where API endpoint discovery was the critical recon step.

### GraphQL Field-Level Authorization Audit

GraphQL APIs are consistently under-audited at the field level. For every GraphQL endpoint:

1. **Acquire the schema** via introspection (`{ __schema { types { name fields { name } } } }`) or by extracting persisted queries from JS bundles
2. **For each type**, build a query requesting EVERY field — especially fields with sensitive-sounding names (`private_`, `internal_`, `admin_`, `secret_`, `token_`, `email_`, `phone_`)
3. **Test nested resolvers**: a `Team` object's `members.email` field may be protected, but `Team.private_comment` may not be
4. **Exhaust sibling operations**: when you find one IDOR in a GraphQL query, immediately test ALL queries/mutations that accept the same object type as an argument
5. **Test every mutation as an underprivileged user**: use schema introspection to enumerate ALL mutations, then call each with placeholder IDs from a low-privilege session

### Disabled UI Elements Are Not Access Controls

When a UI disables a button, removes a menu item, or hides a form field:

1. Remove the `disabled` attribute in DevTools and click — observe the network request
2. Replay the request directly via curl/Burp — the backend often has no corresponding authorization check
3. For multi-step workflows (apply -> pending -> admin approves), enumerate all REST verbs on each step's endpoint — `PATCH` on a "pending" resource may skip the approval gate

### HTTP Method Swap Matrix

For every discovered endpoint, test authorization on BOTH axes — method AND identity:

1. **Method swap**: try GET, POST, PUT, PATCH, DELETE, OPTIONS on every endpoint regardless of what the UI uses
2. **ID swap**: for every parameterized endpoint (`/api/users/{id}`), test with IDs belonging to other accounts
3. **Cross-reference**: an endpoint might enforce auth on GET but not on DELETE, or enforce on your own ID but not on others

### Privacy Setting Enforcement Audit

For every user-facing privacy/visibility toggle:

1. Identify ALL API endpoints that touch the protected attribute (not just the one the UI calls)
2. Test each endpoint independently — privacy settings are often enforced in the primary endpoint but forgotten in search, export, bulk-fetch, and webhook delivery paths
3. Send three test cases per endpoint: (a) real-resource-with-access, (b) real-resource-without-access, (c) nonexistent-resource — if (b) and (c) return different errors, the resource exists and the check is bypassable

### OAuth Client/Token Scope Auditing

For platforms with multiple first-party OAuth clients:

1. Enumerate every `client_id` visible in JS bundles, mobile app decompilation, and OAuth redirect flows
2. Map each client's granted scopes by inspecting the token response or JWT claims
3. Test whether one client's token can access another client's endpoints — scope boundaries between first-party apps are frequently misconfigured
4. Check if token permissions exceed what the UI exposes — a "read-only" token may still work on write endpoints

### CORS Misconfiguration on API Endpoints

For every API endpoint discovered:

1. Send an `OPTIONS` preflight with `Origin: https://attacker.com`
2. Check `Access-Control-Allow-Origin` — if it reflects the attacker origin or uses `*`, test whether credentialed requests (cookies) are also permitted
3. A permissive CORS policy on a sensitive endpoint (user data, session tokens, admin actions) is a direct account takeover vector

### Feature Freshness as Discovery Signal

New features have the freshest (least-tested) code:

1. Monitor changelogs, app store release notes, GraphQL schema diffs, and JS bundle diffs between deploys
2. New endpoints within the first 2 weeks of launch are statistically more likely to have authorization gaps
3. When a new feature launches, immediately enumerate all its endpoints and test every CRUD operation with low-privilege tokens

## Key Principle

Generic wordlists find 20% of endpoints. Tech-aware wordlists + historical paths + JS extraction find 80%. Always combine at least 3 sources.
