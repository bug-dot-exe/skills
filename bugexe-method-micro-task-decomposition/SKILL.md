---
name: micro_task_decomposition
description: Break broad vulnerability testing into atomic micro-tasks with fresh agent context — coordinator pattern for systematic coverage without context dilution
depends_on: []
---

# Micro-Task Decomposition

One coordinator that PLANS, many short-lived solvers that EXECUTE. Instead of a
single long-running agent that accumulates context noise over 50+ tool calls,
decompose broad vulnerability testing into dozens of atomic probes — each with
fresh context, a single objective, and a binary outcome.

## The Problem: Context Dilution

A single agent tasked with "test SSRF on this target" will typically try 5-10
payloads against the first parameter it finds, get sidetracked by interesting
responses, accumulate dozens of tool call results in context, lose track of
what was tested vs. skipped, and move on after partial coverage.

After ~50 tool calls, context is polluted with response bodies, error messages,
and intermediate reasoning. The agent becomes reactive (following whatever the
last response suggested) instead of systematic (following a plan).

**The fix is architectural, not prompting.** No amount of "be thorough"
survives 50 rounds of context accumulation. The solution is structural:
keep each solver's context small and focused.

## When to Use

- Any testing scope with >10 endpoints or testable surfaces
- Any vulnerability class with >5 bypass variants or payload families
- When the agent has been running >30 tool calls without findings (tunnel vision)
- When coverage tracking shows large gaps despite long runtime
- The coordinator should ask: "Am I testing broadly enough, or am I fixated
  on one endpoint while 20 others sit untouched?"

## Decomposition Patterns

Each vulnerability class decomposes differently. The goal is to break one
broad task into N atomic probes where each probe has exactly ONE expected
outcome.

### SSRF Decomposition (1 task -> ~20 micro-tasks)

| Group | Micro-Tasks | Count |
|-------|------------|-------|
| Cloud metadata | IMDSv1, IMDSv2 (token-based), GCP metadata, Azure metadata | 4 |
| Internal services | localhost on ports 80, 443, 8080, 8443, 3000, 5000 | 6 |
| DNS rebinding | Each bypass variant (short TTL, dual-A, CNAME) | 3 |
| Redirect chains | 301 to internal, 302 to internal | 2 |
| Protocol handlers | gopher://, dict://, file:// | 3 |
| Encoding bypasses | Decimal IP, hex IP, IPv6 localhost | 3 |

Each micro-task tests ONE specific probe against ONE specific input vector.
"Send gopher://localhost:6379 to the webhook URL parameter" — not "test SSRF."

### Auth Bypass Decomposition (1 task -> ~15 micro-tasks)

| Group | Micro-Tasks | Count |
|-------|------------|-------|
| Token removal | Remove cookie, remove bearer token, remove API key header | 3 |
| Method override | POST to GET, X-HTTP-Method-Override, X-Method-Override | 3 |
| Path traversal | /admin/../public/resource, /admin;/public, /admin%2f..%2f | 3 |
| Parameter pollution | Duplicate params, array notation, JSON key collision | 3 |
| Header manipulation | X-Forwarded-For, X-Original-URL, X-Rewrite-URL | 3 |

### IDOR Decomposition (1 task -> N x M micro-tasks)

For each endpoint with an identifier parameter (N endpoints), test with each
authorization context (M users/roles):

- N endpoints with sequential/UUID IDs
- M authorization contexts (unauthenticated, low-priv, peer user, admin)
- Each micro-task: "As context A, access endpoint /api/X with entity B's
  identifier Y, expect 403 or filtered response"

This scales multiplicatively — 10 endpoints x 3 auth contexts = 30 focused
probes, each trivially fast with fresh context.

### Injection Decomposition (1 task -> N x P micro-tasks)

For each user-controlled input (N parameters), test each payload family
(P families):

| Family | Example Probes |
|--------|---------------|
| SQL syntax | Single quote, comment termination, UNION SELECT, boolean blind |
| NoSQL operators | $gt, $ne, $regex, $where |
| Template syntax | {{7*7}}, ${7*7}, #{7*7}, <% 7*7 %> |
| Command separators | ;, |, &&, $(), backticks |
| Path traversal | ../, ....//,  ..%2f, ..%252f |

Each micro-task sends ONE payload to ONE parameter and checks for ONE
indicator. No ambiguity, no distraction.

## Coordinator Protocol

The coordinator agent (the root/parent) runs the decomposition pipeline:

### Phase 1: ENUMERATE

Map all testable surfaces (endpoints, parameters, methods, content types).
Identify which parameters accept which input types (URLs, IDs, text, files).
Note authentication requirements per endpoint. Output: structured surface inventory.

### Phase 2: DECOMPOSE

Apply decomposition patterns above to generate atomic micro-tasks. Match each
endpoint/parameter to relevant vulnerability classes, expand each class into
micro-task variants, tag with priority. Output: an ordered task queue.

### Phase 3: PRIORITIZE

Order the task queue by expected impact:

1. Endpoints handling sensitive operations (auth, payments, admin)
2. Parameters accepting URLs or identifiers (SSRF, IDOR surface)
3. Endpoints with complex business logic (race conditions, state bugs)
4. Input reflection points (injection, XSS)
5. Everything else

### Phase 4: DISPATCH

Spawn micro-task solvers in parallel batches (3-5 concurrent). Each solver
gets ONE micro-task with fresh context, runs in isolation, and is time-boxed
(30-60 seconds typical). Coordinator waits for batch completion before
dispatching the next batch.

### Phase 5: COLLECT

Aggregate results and generate follow-up tasks. Track: total dispatched,
completed, clean, suspicious, vulnerable, errors. SUSPICIOUS results get
refined follow-up probes. VULNERABLE results route to a validation agent.
ERROR results get one retry with modified approach.

### Phase 6: ESCALATE

When a micro-task finds something, spawn a dedicated investigation agent with
ONLY the relevant context (endpoint, parameter, payload that triggered, raw
response). Fresh context means it approaches validation without the discovery
agent's assumptions or biases.

## Micro-Task Specification Format

Each micro-task dispatched to a solver follows this template:

```
TARGET: [METHOD] [ENDPOINT]
ACTION: [Exact request modification or payload to send]
AUTH: [Authentication context to use]
EXPECTED: [What a non-vulnerable response looks like]
FINDING_IF: [Specific indicator of vulnerability in the response]
TIMEOUT: [Maximum seconds before abandoning]
```

Example:

```
TARGET: POST /api/v2/webhooks
ACTION: Set url parameter to http://169.254.169.254/latest/meta-data/
AUTH: Session token for role=user
EXPECTED: 4xx response or URL validation error
FINDING_IF: Response contains instance metadata keywords (ami-id, instance-id, iam)
TIMEOUT: 30 seconds
```

The solver does NOT interpret, theorize, or explore beyond this spec. It
executes the probe, checks the FINDING_IF condition, and returns a result.

## Result Aggregation

Each micro-task returns exactly one of four statuses:

| Status | Meaning | Coordinator Action |
|--------|---------|-------------------|
| CLEAN | No vulnerability indicator detected | Mark complete, move on |
| SUSPICIOUS | Anomalous response, not conclusive | Spawn follow-up micro-task with refined payload |
| VULNERABLE | Clear vulnerability indicator matched | Route to validation agent |
| ERROR | Request failed, timeout, or unexpected state | Retry once with modified approach, then mark failed |

The coordinator maintains a running scoreboard tracking total, completed,
clean, suspicious, vulnerable, errors, and remaining counts. This gives
clear progress and coverage visibility at any point.

## Discovery / Validation Separation

This is the most critical architectural constraint: the agent that DISCOVERS
a potential vulnerability must NOT be the same agent that VALIDATES it.

### Why Separation Matters

- **Discovery agents** are creative and exploratory. They cast a wide net,
  tolerate false positives, and follow hunches.
- **Validation agents** are deterministic and rigorous. They prove or disprove
  a specific hypothesis. Zero tolerance for ambiguity.

When one agent does both, it anchors on its discovery hypothesis and
interprets ambiguous evidence as confirmation. Splitting forces re-examination.

### Validation Agent Protocol

When a discovery agent returns VULNERABLE, the coordinator spawns a
validation agent with:

1. **Hypothesis**: One-sentence claim of what the vulnerability is
2. **Preconditions**: Exact state needed to test
3. **Exploit**: Specific exploit sequence to execute
4. **Impact verification**: Confirm the impact is real and meaningful
5. **Evidence capture**: Collect request/response pairs, timestamps, proof

The validation agent has NO knowledge of how the discovery was made or what
other probes were tried. It starts from the hypothesis with fresh eyes.

### Validation Outcomes

| Outcome | Meaning | Next Step |
|---------|---------|-----------|
| CONFIRMED | Exploit reproduces, impact verified | Proceed to reporting |
| PARTIAL | Exploit works but impact is limited | Reassess severity, still report |
| FAILED | Cannot reproduce | Mark as false positive, log for review |
| ESCALATED | Found WORSE impact than claimed | Upgrade severity, deeper investigation |

## Scaling Principles

### Breadth Before Depth

Dispatch one micro-task per surface before sending two to any single surface.
The first probe on an untested endpoint is far more valuable than the 50th
variant on an already-tested one.

### Diminishing Returns Detection

If the last 20 micro-tasks in a vulnerability class all returned CLEAN,
deprioritize that class and reallocate to underexplored classes.

### Error Budget

If >20% of micro-tasks return ERROR, pause and investigate infrastructure
(WAF blocking, rate limiting, session expiry) before burning more capacity.

### Context Reset Is the Feature

Every solver starts with zero history. It cannot be anchored by a previous
solver's failure or distracted by tangents from three probes ago. This is
not a limitation — it is the primary advantage of the architecture.

## Anti-Patterns

| Anti-Pattern | Why It Fails | Fix |
|-------------|-------------|-----|
| One agent tests everything | Context dilution after 50 calls | Decompose into micro-tasks |
| Solver explores beyond its spec | Loses focus, duplicates other solvers' work | Strict single-probe scope per solver |
| Coordinator micro-manages payloads | Becomes a bottleneck, limits parallelism | Define probe families, let solvers handle encoding details |
| Skipping validation | Discovery bias produces false positives | Always spawn a separate validation agent |
| Sequential dispatch only | Wastes time on CLEAN probes | Parallel batches of 3-5 solvers |
| Retrying errors indefinitely | Often a WAF or infra issue, not a bug | One retry, then mark failed and investigate |
| Reusing solver context across tasks | Defeats the purpose of fresh context | One solver per task, always |

---

## Corpus-Derived Micro-Task Patterns

High-bounty patterns that decompose into atomic probes for systematic coverage.

### CI/CD Workflow Injection Decomposition (1 task -> ~12 micro-tasks)

For each public repository owned by the target:

| Group | Micro-Tasks | Count |
|-------|------------|-------|
| Trigger audit | Check each workflow for `pull_request_target`, `issue_comment`, `workflow_run` triggers | 3 |
| Expression injection | For each `${{ }}` expression in run steps, test if attacker-controlled input flows in | 3 |
| Self-hosted runners | Check runner labels for `self-hosted`, test if fork PRs execute on target infra | 2 |
| Artifact poisoning | Check if workflows download and execute artifacts from other workflows or forks | 2 |
| Secret exfiltration | Test if PR-triggered workflows have access to repository secrets | 2 |

Each micro-task checks ONE workflow file for ONE specific dangerous pattern.

### JWT/Token Validation Decomposition (1 task -> ~10 micro-tasks)

| Group | Micro-Tasks | Count |
|-------|------------|-------|
| Algorithm confusion | Test `alg: none`, `alg: HS256` with public key as secret, `alg: RS256` with self-signed | 3 |
| Claim manipulation | Modify `sub`, `aud`, `iss` claims independently; test cross-tenant token reuse | 3 |
| Key source audit | Test if tokens from public sign-up sources are accepted by admin endpoints | 2 |
| Expiry bypass | Test expired tokens, tokens with no `exp`, tokens with future `nbf` | 2 |

### Cross-Service Idempotency Decomposition (1 task -> ~8 micro-tasks)

For every multi-service workflow involving money/balance/state:

| Group | Micro-Tasks | Count |
|-------|------------|-------|
| Replay attack | Replay the same idempotency key across services; check if credit applies twice | 2 |
| Partial failure exploit | Trigger failure between service A commit and service B commit; check state consistency | 2 |
| Race condition | Submit identical requests concurrently; check if both succeed | 2 |
| Key reuse | Use a successful idempotency key from operation A on operation B | 2 |

### HTML Sanitizer Differential Decomposition (1 task -> ~15 micro-tasks)

| Group | Micro-Tasks | Count |
|-------|------------|-------|
| Parser mutation | Test `<` encoding variants that survive sanitizer but render as tags | 3 |
| Nesting depth | Test deeply nested tags that overflow sanitizer stack but render in browser | 2 |
| Attribute injection | Test event handlers via case variations, unicode, encoding bypasses | 3 |
| Style tag abuse | Test `<style>` content that the sanitizer parses differently than the browser | 2 |
| Comment tricks | Test empty comments, nested comments, conditional comments | 2 |
| SVG/MathML context | Test foreign content elements that switch the parsing context | 3 |

### Clickjacking / UI Action Enumeration (1 task -> N micro-tasks)

For any web app with clickjacking defenses:
1. Enumerate every sensitive action (button, menu item, toggle, form submit) in the application.
2. For each action, test whether it can be triggered from an iframe without user re-authentication.
3. Each micro-task tests ONE action from ONE iframe configuration (with/without sandbox, with/without allow attributes).
4. Focus on actions that modify state: delete, transfer, approve, revoke, change settings.

### XS-Leak / XS-Search Decomposition (1 task -> ~10 micro-tasks)

For any privileged search endpoint that searches user-private content:

| Group | Micro-Tasks | Count |
|-------|------------|-------|
| Frame count oracle | Embed search URL in iframe, check `window.length` for result count variation | 2 |
| Timing oracle | Measure response time difference for matching vs non-matching search queries | 2 |
| Error oracle | Check if search with results vs no results returns different HTTP status or redirect | 2 |
| Cache oracle | Check if search results are cached and detectable via timing on subsequent requests | 2 |
| Content-Type oracle | Check if response content-type varies based on result count | 2 |
