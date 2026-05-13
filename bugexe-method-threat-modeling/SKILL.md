---
name: threat_modeling
category: methodology
description: Quick threat modeling to map attack surface, trust boundaries, and high-value targets before testing
depends_on: []
---

# Threat Modeling

Lightweight pre-testing threat model. Identifies what matters so you test high-value targets first.

## When to Use

- At the start of any new target or engagement
- When scoping a large application with limited time
- Before building a coverage matrix

## Step 1: Identify Assets by Tier

| Tier | Assets | Testing Priority |
|------|--------|-----------------|
| **1 (Critical)** | Credentials, sessions, payment data, PII/PHI, admin access, API keys, secrets | Most time |
| **2 (High)** | User content, business data, config data, audit logs, service tokens | Some time |
| **3 (Standard)** | Public content, preferences, anonymous analytics | Minimal time |

## Step 2: Identify Actors

| Actor | Trust Level | Worst Case If Authz Broken |
|-------|------------|---------------------------|
| Anonymous user | None | Unauthenticated data access |
| Authenticated user | Low | Cross-account data theft |
| Premium user | Low | Payment bypass, feature abuse |
| Admin/staff | High | Target for escalation TO this level |
| API consumer | Medium | Exceed scoped API access |
| Internal service | High | Spoofing, confused deputy |

## Step 3: Map Trust Boundaries

Every boundary crossing is a testing target:

```
[Browser] --(1)-- [API Gateway] --(2)-- [App] --(3)-- [Database]
                       |                  |
                      (4)                (5)
                  [Auth Service]    [Cloud Storage]

(1) Client-server: input validation, auth, rate limiting
(2) Gateway-app: header trust, token forwarding
(3) App-database: query construction, access scoping
(4) App-auth: token validation, session management
(5) App-storage: access control on stored objects
```

Key boundaries: client-to-server, user-to-user, role-to-role, service-to-service, internal-to-external, tenant-to-tenant.

## Step 4: Trace Data Flows

For each critical feature, trace input to storage to output and mark attack points:

```
File Upload:
  Input (upload) --> Processing (validate, scan) --> Storage (S3) --> Output (download)
  Attack points: malicious file type, path traversal in name, SSRF via content,
                 predictable storage keys, IDOR on download endpoint
```

## Step 5: Prioritize Testing

1. Authentication and session management (protects everything)
2. Authorization on Tier 1 asset endpoints (highest impact)
3. Trust boundary crossings with weakest controls (most exploitable)
4. Data flows involving external services (SSRF, confused deputy)
5. Business logic on financial features (direct impact)
6. Input handling on public endpoints (widest surface)

## Output

A completed model produces: asset inventory by tier, actor list with worst-case scenarios, trust boundary diagram, data flow traces with attack points, and a prioritized testing plan. Investment: 30-60 minutes, saves multiples in focused testing.

---

## Corpus-Derived Threat Modeling Techniques

Patterns from high-bounty reports that reveal systematic gaps in how threat models are built.

### Internal Service RPC Bridge Audit

At any organization with internal RPC or microservice architecture:
1. Identify any externally reachable endpoint that proxies to internal services (support APIs, admin consoles, debug endpoints, status pages).
2. Map which internal service names are referenced in error messages, headers, or JS bundles.
3. Test whether internal RPCs trust the caller's identity because the request "came from inside" -- the proxy becomes a confused deputy.
4. Check if the external-facing layer forwards auth headers to internal services without re-validation.

### CI/CD Workflow Threat Model

For any target with public repositories and build automation:
1. Search workflow files for `pull_request_target` triggers -- these run with write permissions on fork PRs.
2. Check for `issue_comment` triggers that pass comment body to shell commands.
3. Look for self-hosted runner usage on public repos (attacker-submitted code runs on target infrastructure).
4. Identify any workflow that checks out PR code and then runs it with elevated permissions.

### Extension and Plugin Architecture Threats

For any system with extensions, plugins, or sandboxed code execution:
1. Map the boundary between sandboxed plugin code and trusted host code.
2. Identify every shared object or state that crosses the sandbox boundary (shared memory, global variables, shared caches, message channels).
3. Test whether one sandbox can influence another sandbox's execution through shared state.
4. Check if "disabled features" in the sandbox have parallel code paths that still touch the same internal state.

### E2EE Threat Model Shift

When a feature uses end-to-end encryption, the threat model shifts validation responsibility to the client:
1. The server no longer validates content -- the client must handle filenames, paths, media formats, and metadata safely.
2. Audit the client's filename/path/format handlers for injection, traversal, and type confusion.
3. Check whether the client trusts metadata from the encrypted payload without sanitization.

### Parser Differential Threat Modeling

When two parsers process the same input (URL parser + URL validator, HTML sanitizer + HTML renderer, JSON parser + JSON validator):
1. Identify every place in the architecture where the same input is parsed twice.
2. Build test cases where the two parsers disagree on interpretation (trailing dots, encoding differences, comment syntax variations).
3. The security check uses parser A's interpretation, but the execution uses parser B's -- the delta is the attack surface.

### Marketing Claim vs Architecture Audit

When a vendor markets a feature as a security control ("Secure View," "DRM," "Hide Download," "Private Browsing"):
1. Identify the architectural layer implementing the control.
2. Test whether the control is enforced server-side or only client-side.
3. Client-side-only security controls are bypassable by definition -- test with a direct API call bypassing the UI.
4. Check if the feature was designed for convenience (UI hint) but marketed as security (access control).

### Password Reset Attack Tree

For any target with password reset or account recovery:
1. Token predictability: request 5 resets quickly, compare tokens for sequential or timestamp-based patterns.
2. Token scope: can a reset token for user A be applied to user B?
3. Rate limiting: does the verification endpoint have brute-force protection? Compute the attack budget (code space / rate limit).
4. Channel switching: if SMS rate-limited, can you switch to email (or vice versa) to reset the attempt counter?
5. Timing: does the reset endpoint respond differently for valid vs invalid tokens (timing oracle)?

### Buffered Amplifier DoS

For any system with a "process then forward" architecture:
1. Identify buffering surfaces: request bodies, file uploads, streaming payloads, message queues.
2. Calculate the amplification factor: what is the ratio of attacker-sent bytes to server-processed bytes?
3. Test concurrent large payloads to trigger memory exhaustion before the forwarding stage can drain the buffer.
4. Check if the buffer has size limits and whether those limits are enforced before or after allocation.
