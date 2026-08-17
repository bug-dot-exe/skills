---
name: express
category: frameworks
description: Express.js security testing for prototype pollution, path traversal, SSTI, CORS misconfig, JWT bypass, and debug mode exposure
depends_on: []
---

# Express.js Security

Security testing for Express.js applications. Focus on prototype pollution via body-parser, path traversal in static middleware, SSTI in template engines, CORS misconfiguration, JWT middleware bypass, and debug mode exposure.

## Attack Surface

**Request Parsing**
- body-parser: JSON, URL-encoded, raw, text parsing
- multer: multipart/form-data file upload handling
- cookie-parser: signed and unsigned cookie parsing
- express.json() and express.urlencoded() (built-in since Express 4.16)

**Middleware Pipeline**
- Route ordering: first match wins, middleware execution order matters
- Error handling middleware: 4-argument signature, information leakage
- Third-party middleware: passport, cors, helmet, express-rate-limit, csurf

**Template Engines**
- EJS, Pug (Jade), Handlebars, Nunjucks, Mustache
- Template compilation and rendering with user input

**Static File Serving**
- express.static: directory traversal, dotfile handling, symlink following
- serve-index: directory listing exposure

**Session and Auth**
- express-session: store configuration, session fixation, cookie flags
- passport.js: strategy configuration, serialization/deserialization
- JWT libraries: jsonwebtoken, express-jwt

## High-Value Targets

- Authentication routes: login, register, password reset, OAuth callbacks
- File upload endpoints using multer
- Routes rendering user input through template engines
- API endpoints with JSON body parsing
- Admin routes protected by middleware ordering
- Debug and development routes (often left in production)
- WebSocket upgrade endpoints (socket.io, ws)

## Key Vulnerabilities

### Prototype Pollution via body-parser

JSON parsing can inject `__proto__`, `constructor`, or `prototype` properties:

```json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
```

Test if polluted properties propagate to other objects. Impact: auth bypass, RCE (if pollution reaches child_process options or template engine options).

Check Express version: versions before 4.17.3 with qs library before 6.10.3 are vulnerable to nested prototype pollution via URL-encoded bodies.

### Path Traversal in Static Middleware

`express.static` misconfigurations:

- Dotfiles: default `dotfiles: 'ignore'` but misconfigured to `'allow'` exposes `.env`, `.git/config`
- Symlinks: `followSymlinks` option can escape the static root
- URL encoding: `%2e%2e%2f` and double-encoding `%252e%252e%252f` to traverse
- Null bytes (old Node versions): `file.txt%00.jpg` to bypass extension checks

Test: `GET /static/..%2f..%2f..%2fetc/passwd`

### SSTI in Template Engines

**EJS**: 
```
<%= user.name %>  // If user.name is attacker-controlled
// Payload: {{= global.process.mainModule.require('child_process').execSync('id') }}
```

**Pug/Jade**:
```
#{user.input}  // Code execution context
// Payload via prototype pollution: pollute __proto__.block to inject template code
```

**Handlebars**:
```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}{{this.push (lookup string.sub "constructor")}}
      {{this.pop}}{{#with string.split as |codelist|}}
        {{this.pop}}{{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}
          {{this}}
        {{/with}}{{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

### CORS Misconfiguration

Common Express CORS mistakes:

- Reflecting Origin header directly: `Access-Control-Allow-Origin: [attacker.com]`
- Allowing null origin: `Access-Control-Allow-Origin: null` (exploitable via sandboxed iframe)
- Regex bypass: `*.target.com` matching `attacker-target.com`
- Credentials with wildcard: `Access-Control-Allow-Credentials: true` with reflected origin

Test: send request with `Origin: https://evil.com` header, check if reflected with credentials allowed.

### JWT Middleware Bypass

**Algorithm confusion**: if server accepts both HS256 and RS256, sign token with HS256 using the public key as the HMAC secret.

**Missing verification**: express-jwt with `credentialsRequired: false` on sensitive routes.

**Token in multiple locations**: JWT checked in header but not in cookie, or vice versa. Send token in the unchecked location to bypass middleware that only strips one.

**kid injection**: `kid` header parameter used in file path or SQL query for key lookup.

### Debug Mode and Error Handling

- `NODE_ENV=development` in production: verbose stack traces, source maps
- Express error handler with `err.stack` in response body
- morgan/winston logging sensitive data to client-accessible logs
- Express `app.get('env')` returning 'development'

Test: trigger a 500 error and examine the response body for stack traces.

## Bypass Techniques

- HTTP Parameter Pollution: `?role=user&role=admin` — Express takes the last value by default
- Method override: `X-HTTP-Method-Override: DELETE` on a POST request
- Content-type switching: send `application/x-www-form-urlencoded` when JSON is expected (or vice versa)
- Route confusion: `/admin/..;/user` path traversal past middleware
- Middleware ordering: find routes registered before authentication middleware

## Testing Methodology

1. **Fingerprint**: identify Express version, template engine, middleware stack from headers and errors
2. **Prototype pollution**: test JSON endpoints with `__proto__` and `constructor.prototype` payloads
3. **SSTI**: inject template syntax in every user input rendered in responses
4. **CORS**: test Origin reflection, null origin, subdomain regex bypass
5. **JWT**: test algorithm confusion, missing verification, token location switching
6. **Static files**: test path traversal with encoding variants on static routes
7. **Debug mode**: trigger errors, check for stack traces and environment info
8. **Middleware ordering**: map which routes have which middleware, find gaps

## Corpus-Derived Attack Patterns

### Prototype Pollution to RCE Gadget Chains
Prototype pollution alone is medium severity. The real payoff is chaining PP to a gadget that achieves RCE:
1. Find PP primitive: `lodash.merge`, `lodash.defaultsDeep`, `hoek.applyToDefaults`, `jQuery.extend(true,...)`, `qs` nested parsing
2. Map gadgets in the dependency tree: template engine options (`outputFunctionName` in EJS, `compileDebug`/`self` in Pug), `child_process.spawn` options (`shell`, `env`), and `require()` resolution paths
3. PP to EJS RCE: pollute `__proto__.outputFunctionName` with payload like `x;process.mainModule.require('child_process').execSync('id');x`
4. PP to Pug RCE: pollute `__proto__.block` to inject template code during compilation
5. PP via Vue/React framework template-string gadgets: `__proto__.client`, `__proto__.compileDebug`, `__proto__.debug`

### Credential Serialization Leaks
Node.js SDK objects holding credentials may serialize unsafely:
- Test `JSON.stringify()` on any SDK client object (Firebase, AWS, Stripe, database drivers)
- Check `console.log()`, `util.inspect()`, `Object.keys()` on credential-bearing objects
- Leaked keys appear in error logging, debug output, API responses that serialize request context
- Express error handlers that stringify the error object may include attached request/session data with credentials

### Archive Extraction Path Traversal (Zip Slip)
Any Express endpoint accepting archive uploads (ZIP, TAR, NPM package, Helm chart):
1. Craft archive with entries containing `../../` in filenames
2. Upload via multipart form endpoint
3. If the server extracts to a temporary directory without sanitizing entry paths, files land outside the intended directory
4. Combine with a predictable extraction path to overwrite application code or configuration
5. Different archive formats need separate testing -- TAR, ZIP, and language-specific package formats each have distinct extraction libraries

### RBAC Verb-Asymmetric Authorization
Express apps with role-based access often enforce permissions inconsistently across HTTP verbs:
1. Enumerate every action/mutation/endpoint and its required permission
2. Classify by sensitivity: security-critical (role change, MFA toggle, domain enforcement) vs operational
3. Test if security-critical actions are gated at the same tier as read operations for the same resource
4. Authentication-mode toggle mutations (enable/disable SSO, change auth provider) should require highest-tier permission -- if at any lower tier, that is a bug

### Parser Differential in Service Handoffs
When Express sits behind a reverse proxy, load balancer, or communicates with microservices:
- Two services exchanging data where one signs a parse-result that the other re-parses create differential opportunities
- Request smuggling via Transfer-Encoding/Content-Length disagreement between proxy and Express
- Express `body-parser` may parse differently than upstream API gateway validation
- Multipart boundary manipulation: proxy validates one interpretation, Express parses another

### Node.js Permission Model Bypass
For Express apps running on newer Node.js with the experimental permission model:
- Enumerate every native-code-load primitive: `--require`, `NODE_OPTIONS`, OpenSSL engines, `.node` addons, worker threads
- Each native-code-load path is a separate bypass candidate for the permission sandbox
- `process.binding('natives')` and `require('module')._cache` expose internal module surface
- Inspector protocol (`--inspect`) if reachable bypasses process-based permissions entirely

### UI-vs-API Guard Mismatch
Express apps where the frontend conditionally hides features (verify email first, upgrade to Pro, MFA required):
- Test the API endpoint directly -- UI guards are client-side only
- Submit the action without completing the prerequisite (email verification, payment, MFA setup)
- Race condition: submit the action simultaneously with the prerequisite check
- Pre-email-verification state: OAuth login may bypass email verification requirements

### Batch Endpoint Defense Bypass
Any Express endpoint that lets a single HTTP request trigger N internal operations:
- GraphQL batch queries, JSON-RPC multicall, REST bulk endpoints
- Per-request rate limiting counts the outer request, not inner operations
- WAF rules on individual request patterns do not inspect batched payloads
- Authentication brute force via batch: N credential attempts in one request

## Validation Requirements

- Prototype pollution: demonstrate property injection affecting application behavior (auth bypass, config change)
- SSTI: achieve code execution or file read, not just template syntax reflection
- CORS: demonstrate cross-origin data theft with credentials
- JWT bypass: access protected endpoint with crafted or unsigned token
- Path traversal: read a file outside the intended static directory
