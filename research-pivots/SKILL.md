---
name: research-pivots
category: methodology
description: Systematic pivot strategies when stuck — technology, vulnerability class, target surface, and escalation direction changes
depends_on: []
---

# Research Pivots

Getting stuck is normal. The difference between wasted hours and a payout is knowing when and how to pivot. Systematic pivots prevent tunnel vision and open new attack surface.

## When to Use

- Spent 2+ hours on a single target or vuln class with no progress
- All obvious attack vectors tested and blocked
- WAF or strong defenses are defeating your payloads
- Recon revealed a large attack surface and you need to prioritize
- Current approach feels repetitive with diminishing returns

## Methodology

### Pivot Type 1: Technology-Based Pivots

When one technology path is blocked, switch to another part of the stack:

| Blocked On | Pivot To |
|------------|----------|
| Web app (frontend) | API endpoints, GraphQL, WebSocket |
| Main domain | Subdomains, staging, dev environments |
| HTTP endpoints | gRPC, MQTT, message queues |
| Modern app | Legacy systems, old API versions still accessible |
| Cloud console | Cloud metadata, S3 buckets, serverless functions |
| Application layer | Infrastructure: DNS, TLS, CORS, CSP misconfig |

### Pivot Type 2: Vulnerability Class Pivots

When one vuln class is well-defended, switch to another:

| Defended Against | Try Instead |
|------------------|-------------|
| XSS (strong CSP) | CSRF, clickjacking, open redirect |
| SQLi (parameterized) | NoSQL injection, ORM-specific bypass, LDAP injection |
| SSRF (blocklist) | DNS rebinding, TOCTOU bypass, redirect chains |
| Auth bypass (MFA enforced) | Session fixation, token leakage, OAuth misconfiguration |
| IDOR (UUID-based) | Mass assignment, GraphQL field access, broken function auth |
| Injection (WAF blocked) | Business logic, race conditions, workflow abuse |

### Pivot Type 3: Target Surface Pivots

Same program, different attack surface:

| Current Surface | Pivot Surface |
|----------------|---------------|
| Web application | Mobile app (different API, weaker validation) |
| User-facing features | Admin/internal features |
| API v2 (current) | API v1 (deprecated but still live) |
| Production domain | Staging/sandbox (weaker controls, same data) |
| Primary product | Acquisitions, subsidiary products, integrations |
| Browser-based | CLI tools, SDKs, desktop apps |

### Pivot Type 4: Horizontal vs Vertical Escalation

**Horizontal**: same privilege level, different scope
- Found IDOR on one endpoint? Test every endpoint with ID parameters
- Found XSS in one parameter? Test every input field across the app
- Found misconfigured S3 bucket? Check all buckets in the same org

**Vertical**: same finding, higher privilege
- User-level access? Test admin endpoints with user token
- Read access? Test write/delete operations
- Single account impact? Scale to multi-account or org-wide

## Decision Framework: Abandon vs Persist

### Persist When

- You have partial evidence (403 instead of 404, intermittent behavior)
- You discovered a unique attack surface others likely have not tested
- The technology stack has known vulnerability patterns you have not exhausted
- You are making measurable progress (new info each attempt)

### Abandon When

- Three distinct approaches all hit the same defense
- The vuln class is explicitly out of scope
- The target shows signs of mature security (quick patches, bug bounty veterans)
- Your estimated remaining time exceeds the expected reward
- You are repeating the same tests with minor variations

## Pivot Execution

1. **Log current state**: what you tried, what you learned, what is blocked
2. **Pick pivot type**: technology, vuln class, surface, or escalation direction
3. **Set a time box**: 1-2 hours on the new direction before evaluating again
4. **Carry forward intel**: recon data, session tokens, discovered endpoints still apply
5. **Evaluate after time box**: new leads found? Persist or pivot again

## Pivot Chains

Effective hunters chain multiple pivots in a session:

```
Web app XSS blocked (strong CSP)
  --> Pivot to API (no CSP on API responses)
    --> Found verbose error messages (info disclosure)
      --> Pivot to vertical: errors reveal internal paths
        --> Directory traversal on internal path
          --> Pivot to escalation: read config files
            --> Database credentials in config
```

Each pivot builds on the previous finding. The final impact was unreachable from the starting point without the chain of pivots.

## Corpus-Derived Pivot Patterns

### Half-Blind to Full Exploitation Pivot

When you find an SSRF, LFI, or injection that gives partial output (blind or semi-blind):

1. **Do not stop at the blind primitive** -- pair it with a response channel
2. SSRF + cloud metadata endpoint = credentials (the "half-blind to full" pivot is the hallmark of cloud-native SSRF research)
3. Blind XXE + out-of-band HTTP/DNS exfiltration = file read
4. Blind SQLi + conditional response differences = data extraction
5. The primitive alone may be Low/Informational; the pivot to full exploitation is High/Critical

### Outdated-Library Fingerprint Pivot

1. Fingerprint client-side library versions on every endpoint (JavaScript includes, CSS frameworks, embedded widgets)
2. Map each outdated version to its known CVEs
3. If a CVE exists: build a delivery vector using the target's own features (file upload, markdown renderer, embed/iframe)
4. The library CVE provides the payload; your job is to find the delivery path specific to the target

### Path Traversal to Config Overwrite Pivot

When you have an arbitrary-file-write primitive but the obvious targets (cron, SSH keys, web shell) are blocked:

1. **Enumerate writable config files** that the application reads on startup or per-request (`.env`, `.htaccess`, `web.config`, `settings.py`, `application.yml`)
2. **Overwrite the config** to change behavior: redirect logs to a world-readable path, enable debug mode, change the database connection string, disable authentication
3. The write itself may be Low; the config overwrite that changes application behavior is the real finding

### Admin Panel Access as a Pivot (Not a Finding)

When you gain access to an admin interface:

1. **Do not submit "admin panel accessible"** -- that is a primitive, not an impact
2. Immediately probe every admin function: can you execute code? Can you read all user data? Can you modify permissions? Can you access the database console?
3. The finding is what you can DO from the admin panel, not that you reached it
4. Common admin panel escalations: SSRF via webhook config, RCE via template editor, data exfil via export/backup, user impersonation via session management

### Trust Chain Pivot

When a `postMessage` listener or OAuth flow validates a specific origin:

1. That validated origin becomes your next XSS target
2. If you find XSS on the trusted origin, you can send arbitrary postMessages that pass validation
3. Methodology: map all `postMessage` listeners and their origin checks, then hunt XSS specifically on those trusted origins
4. Works for OAuth redirect_uri validation too: if `redirect_uri` must match `*.example.com`, hunt for open redirect or XSS on any `*.example.com` subdomain

### N-Day Enterprise Pivot

Large enterprises run dozens of instances of the same software (Atlassian, GitLab, Jenkins, SonarQube):

1. When a CVE drops for an enterprise tool, enumerate every instance in the target's scope
2. Test each instance: large organizations patch unevenly -- some instances are months behind
3. The same CVE on different instances may be accepted as separate findings on some programs (especially government VDP)

### Personal Archive Pivot

Revisit your own "won't fix" and "low severity" findings whenever you discover a new gadget:

1. Maintain a list of low-impact primitives you have found: open redirects, info disclosures, CSRF on non-sensitive endpoints, self-XSS
2. When you discover a new chain opportunity (new XSS sink, new auth bypass, new SSRF), check whether any archived primitive provides the missing precondition
3. The combination may upgrade both findings: a self-XSS + a `postMessage` bridge = stored XSS on the parent origin

### Asset Discovery Multi-Pivot

Do not limit recon to domain enumeration:

1. Start from organization name, get ASN list, IP ranges, cloud account identifiers
2. Certificate transparency logs reveal internal service names and staging domains
3. GitHub/GitLab search for the organization reveals internal tooling, API keys in commits, infrastructure patterns
4. Each discovered asset is a new pivot surface: IP scan reveals open admin port, admin port reveals debug endpoint, debug endpoint reveals internal API

### Default-Vhost Pivot

When a target returns "host not valid" or 421 Misdirected Request:

1. Resolve the IP and visit it directly (no Host header or with the IP as Host)
2. The default vhost may serve a different application or an older version without the WAF/CDN protection
3. Test with the original Host header but sent directly to the origin IP (bypass CDN/WAF)

### Bug-Class Exhaustion Pivot

When you find one instance of a bug class on a target:

1. Do not stop -- enumerate every entry point for the same bug class
2. One IDOR on `/api/v2/users/{id}` means test `/api/v2/orders/{id}`, `/api/v2/documents/{id}`, every resource with an ID parameter
3. One open redirect on `/login?next=` means test `/logout?redirect=`, `/oauth/callback?return_to=`, every redirect parameter
4. File the most impactful instance as the primary report; list all affected endpoints in the impact section
