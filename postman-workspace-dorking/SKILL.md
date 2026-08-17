---
name: postman-workspace-dorking
category: reconnaissance
description: Search Postman public workspaces, collections, and environments for leaked API endpoints, auth tokens, internal URLs, and undocumented methods
depends_on: []
---

# Postman Workspace Dorking

Developers share API collections with colleagues via Postman's "public" visibility setting without realizing the workspace is indexed by Postman's global search. Result: full production API collections, complete with Bearer tokens, cookie values, internal staging URLs, and undocumented admin endpoints are one query away.

As of 2024-2025, this is one of the highest-signal dorking surfaces in bug bounty — most teams don't even check it.

## When to Use

- Any target with a public API
- Always run on medium-to-large targets during initial recon
- When github_dorking / google_dorking reveal API endpoints but no parameters
- Hunting for admin / internal / partner API endpoints not in public docs
- Looking for hardcoded auth tokens that are still live

## Methodology

### Phase 1: Public Workspace Search

1. Search Postman's public workspace index for the target name, domain, and product keywords
2. Open every hit — workspaces are organized by team, each containing multiple collections
3. Dump each collection as JSON via the "Run in Postman" → "Export" UI, or via the API

### Phase 2: Collection Exploitation

For each collection found:

1. **Endpoint discovery**: enumerate every request method, path, and parameter
2. **Auth inspection**: check the "Authorization" tab for Bearer tokens, API keys, Basic auth
3. **Environment inspection**: check the `environments` array for variable values — often contains prod credentials
4. **Pre-request scripts**: read any JavaScript in pre-request scripts — sometimes computes secrets
5. **Test scripts**: read test assertions — reveal expected response shapes (data leak hints)

### Phase 3: Environment Variable Extraction

Environments (`{{variable}}`) are the biggest leak:

1. Most developers use `{{baseUrl}}`, `{{apiKey}}`, `{{token}}` — these are *resolved* in the shared workspace
2. Export the workspace JSON and grep `"value":` — every variable value is in there
3. Check for live tokens (many are production credentials)
4. Check for internal `baseUrl` values (`https://api-internal.target.com`, `https://staging-api.target.com`)

### Phase 4: Endpoint Validation

Every endpoint found is a new attack surface:

1. Test each endpoint against the live server with the workspace's provided auth
2. Compare response to documented behavior (differences often mean bugs)
3. Look for admin/internal endpoints not documented externally
4. Check for deprecated endpoints (still accepted by server, but no longer publicly listed)

## Key Queries

### Postman Public Workspace Search

Use `postman.com/search` or the search dropdown in Postman Desktop.

```
# Direct workspace search (via UI and /search URL)
target                                 # free text match
target.com
target API
"target corp"
internal target                        # sometimes finds internal-leaked

# API-specific search (searches within collections)
site:postman.com "target.com"
site:www.postman.com "target"
site:www.postman.com inurl:collection "target"
```

### Postman API (programmatic search)

Postman exposes a public API for workspace and collection search. Rate-limited but generous.

```bash
# Search public collections by keyword
curl -s "https://www.postman.com/_api/ws/proxy" \
  -X POST -H "Content-Type: application/json" \
  -d '{"service":"search","method":"POST","path":"/search-all","body":{"queryText":"target","domain":"all","limit":100}}'

# Pull a specific collection by UID (shown in URL after you open one)
curl -s "https://www.postman.com/_api/collection/<uid>" | jq .

# Pull a full public workspace
curl -s "https://www.postman.com/_api/workspace/<workspace_uuid>" | jq .
```

### PostmanX / search wrappers

Community tools wrap the above for convenience:

```bash
# Tool: postleaks
# https://github.com/cosad3s/postleaks
postleaks -k target
postleaks -k target.com --extend-workspaces

# Tool: PostDump
# https://github.com/wireless90/Trufflepig-Postman
```

### Google fallback (if Postman UI is slow)

```
site:postman.com "target.com"
site:documenter.getpostman.com "target.com"
site:go.postman.co "target"
```

## Collection JSON Structure (what you're looking at)

A Postman collection export has this shape:

```json
{
  "info": {"name": "Target API", "schema": "..."},
  "item": [
    {
      "name": "Get user",
      "request": {
        "method": "GET",
        "url": {"raw": "{{baseUrl}}/api/v1/users/{{userId}}"},
        "header": [
          {"key": "Authorization", "value": "Bearer {{authToken}}"}
        ]
      }
    }
  ],
  "variable": [
    {"key": "baseUrl", "value": "https://api-internal.target.com"},
    {"key": "authToken", "value": "eyJhbGciOiJIUzI1NiIs..."},      // <-- LEAK
    {"key": "userId", "value": "admin"}
  ]
}
```

## What to Look For

**Immediate Wins**
- Bearer tokens in `header[].value` fields (often live)
- API keys in `variable[].value` fields
- Basic auth `user:pass` in `request.auth.basic` blocks
- Cookie values in `header[].value` where key is "Cookie"
- OAuth refresh tokens in environment JSON
- AWS SigV4 credentials in `request.auth.awsv4` blocks

**Endpoint Intelligence**
- Internal / admin / debug endpoints not in public API docs
- Deprecated API versions still documented internally
- Non-public query parameters that alter response behavior
- GraphQL queries revealing full schema + admin mutations
- WebSocket / SSE endpoints rarely documented externally

**Infrastructure Intel**
- Internal `baseUrl` values (`https://prod-api-internal.target.com`)
- Staging / QA environment URLs with reduced security
- Partner API endpoints (may reveal business relationships)
- Service mesh topology from multi-collection layouts (API Gateway → Service A → Service B)

**Code Intelligence**
- Pre-request JavaScript that computes HMAC signatures (reveals secret format)
- Test scripts that reveal expected response shapes (field names you didn't know existed)
- Example response bodies with real user data (GDPR leaks)

## Validation

1. Never use found tokens against production beyond a single auth-check — many are live
2. Verify the workspace actually belongs to the target (not a customer's workspace using the target's API)
3. Cross-reference endpoints against current API — server may have changed
4. Check the `updatedAt` timestamp — very old collections may have been rotated
5. Report with the full workspace URL, collection UID, and the specific leak

## Operational Notes

- Postman workspaces can be deleted by owners — archive findings immediately (`wget` the collection JSON)
- Public workspaces used to be default; Postman now defaults to private, but millions of legacy public workspaces remain
- `documenter.getpostman.com` renders public collections as docs pages — often indexed by Google
- Check sub-workspaces within large orgs — enterprises often have 50+ workspaces, some public by mistake
- Developer personal workspaces are separate from org workspaces — check employee names too

## Tips

1. Run Postman dorking **before** github_dorking — it's faster and often richer
2. Target's product keywords (not just domain) — `"target-analytics"` + `"target-auth-service"`
3. Search for the target's SDK names — SDK docs often link to a Postman workspace
4. Partner/customer integrations — sometimes a customer publicly shares a workspace that leaks the target's API
5. For enterprise Postman users, check their main org workspace URL format: `https://www.postman.com/<org-slug>/workspaces`
6. Always check `updatedAt` — freshness matters, old tokens may be rotated
7. The Postman desktop app has better search ranking than the web UI — worth installing for a deep hunt
8. Complement with `graphql_voyager` for any GraphQL endpoints found
