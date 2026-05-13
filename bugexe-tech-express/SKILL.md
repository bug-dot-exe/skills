---
name: express
description: Express.js attack surface: middleware ordering, body-parser pollution, prototype pollution, path traversal
depends_on: []
---

# Express

Express is the dominant Node.js web framework. Bug-rich because middleware order matters: auth-after-parse means parsed bodies still hit handlers. Prototype pollution via merge utilities (lodash.merge, deepmerge) is recurring.

## Common Bug Classes

- Middleware ordering: auth registered after `express.json()` → body parses but auth never runs
- Prototype pollution via `Object.assign({}, req.body)` or `lodash.merge` on user input
- Path traversal in `res.sendFile` / `static` when user input concatenates to a base path
- SSRF in URL-fetching endpoints not validating destination
- Insecure session middleware: `express-session` with weak secret or `cookie.httpOnly: false`
- JSON parameter pollution: `{a: 1, a: 2}` last-wins behavior bypasses validation
- Verbose error responses (`res.send(err.stack)`) exposing file paths

## Middleware Security Patterns

### Auth-Filter Chain Auditing

Audit the middleware stack as a state machine, not individual functions. When multiple `authenticate` hooks run in sequence:

1. Map every middleware in order from `app.use()` calls and route-level middleware arrays
2. For each middleware, determine: does it SET state (e.g., `req.user`), READ state, or GATE on state?
3. Find gaps: a middleware that GATES but runs after a handler that already acted on the un-gated request
4. Test by removing or reordering cookies/headers that individual middleware expect

### Type Confusion in Endpoints

Express parses JSON bodies with type preservation. Authentication endpoints are prime targets:

```
POST /auth/login
Content-Type: application/json
{"email": ["admin@example.com"], "password": {"$gt": ""}}
```

Test every login/auth endpoint with:
- Array where string expected: `{"email": ["a@b.com"]}`
- Object where string expected: `{"password": {"$gt": ""}}`
- Null where value expected: `{"token": null}`
- Numeric where string expected: `{"code": 0}` (falsy bypass)

### CSRF on Session-Based Routes

For Express apps with `session=eyJ...=` style cookies:

1. The session cookie IS the authentication primitive
2. Test every POST/PUT/PATCH/DELETE endpoint for CSRF protection
3. Check if `csurf` or equivalent middleware is registered globally or per-route
4. Try state-changing requests without CSRF token from a cross-origin page

## ReDoS Discovery

Express and its middleware ecosystem use regexes extensively for routing and validation.

**Audit methodology:**
1. Catalog every URL parameter that flows into a regex (search, filter, pattern-match routes)
2. Extract the regex pattern from source or middleware config
3. Test for catastrophic backtracking with nested quantifiers: `(a+)+$`, `(a|b|ab)*$`
4. Send progressively longer inputs and measure response time delta

**High-value targets:**
- Custom route parameter validators using regex
- Input sanitizers/validators (email, URL, phone patterns)
- `path-to-regexp` patterns with optional segments and wildcards

## Header Trust Boundary Attacks

When Express middleware processes HTTP headers expected to come from infrastructure (reverse proxies, load balancers):

1. Map all headers the app reads: `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Real-IP`
2. Check `app.set('trust proxy')` configuration — overly broad trust allows header spoofing
3. Test `Rack::Sendfile`-style headers that control file serving behavior
4. Inject into headers that feed regex-based security controls (host validation, IP allowlists)

## Object Injection via Deserialization

Express apps commonly deserialize user input beyond JSON:

- `node-serialize` / `serialize-javascript` with function expressions
- `cookie-parser` signed cookies with predictable secrets
- Custom session stores deserializing untrusted data
- `req.body` flowing into `eval()`, `new Function()`, or `vm.runInNewContext()`

## JavaScript Bundle Analysis

Production bundles leak internal details. Audit methodology:

1. Fetch all `/static/js/*.chunk.js` or equivalent bundled files
2. Search for: API endpoint strings, internal hostnames, admin route paths
3. Extract dependency names and versions from bundle comments/sourcemaps
4. Cross-reference extracted packages against known CVE databases
5. Look for hardcoded secrets: API keys, OAuth client secrets, debug tokens

## Debug Mode Detection

Express debug leaks surface across the middleware stack:

```
# Trigger error responses
GET /api/nonexistent
POST /api/endpoint with malformed JSON
GET /api/endpoint?callback=<script>  # JSONP reflection

# Framework-specific debug paths
GET /__express/
GET /debug/
GET /status/
```

Look for: stack traces with file paths, dependency version strings, environment variable dumps, database connection strings in error responses.

## Probe Targets

- Send `__proto__` and `constructor.prototype` in JSON bodies
- Test `/api/*` for path-traversal in file-serving routes
- Trigger errors via malformed JSON, look for stack-trace leakage
- Check session cookie attributes and secret entropy
- Test `Content-Type` switching: `application/json` vs `application/x-www-form-urlencoded`
- Probe for exposed `node_modules` or `.env` files via path traversal
- Check `X-Powered-By: Express` header (often not disabled)

## Cross-References

`prototype_pollution`, `ssrf`, `path_traversal_lfi_rfi`, `session_security`, `http_parameter_pollution`, `nodejs`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
- For ReDoS: demonstrate measurable time delta (>2x) between normal and crafted input
- For type confusion: show the authentication bypass leads to a different identity, not just a different error
