---
name: shared-context
category: methodology
description: Shared context management between agents using ScanContext for dedup, credential sharing, hypothesis tracking, and coverage coordination
depends_on: []
---

# Shared Context Between Agents

Multi-agent scanning creates redundancy and missed coverage without shared state. ScanContext is the coordination layer that prevents duplicate work, shares intelligence, and tracks what has been tested.

## When to Use

- Multiple agents working on the same target simultaneously
- Coordinating recon, scanning, and exploitation phases
- Avoiding redundant requests that trigger WAF or rate limiting
- Tracking which endpoints, parameters, and vuln classes have been tested
- Sharing discovered credentials, tokens, or session state across agents

## Methodology

### Step 1: Initialize Shared Context

At scan start, establish the shared ScanContext with:

- **Target definition**: base URLs, scope boundaries, excluded paths
- **Credential store**: discovered tokens, API keys, session cookies
- **Endpoint registry**: discovered URLs with test status per vuln class
- **Hypothesis board**: suspected vulnerabilities pending validation
- **WAF status**: detected WAF type, known bypass status, rate limit thresholds
- **Coverage matrix**: what has been tested, by whom, with what result

### Step 2: Endpoint Deduplication

Before any agent tests an endpoint:

1. Check if the endpoint is already registered in the shared context
2. Check what vuln classes have already been tested against it
3. Only test untested combinations (endpoint x vuln class)

| Endpoint | XSS | SQLi | IDOR | Auth | Race | SSRF |
|----------|-----|------|------|------|------|------|
| /api/users | done | done | | done | | |
| /api/upload | | | | | | done |

### Step 3: Credential and Token Sharing

When an agent discovers authentication material:

1. Store in shared context with scope (which endpoints it works for)
2. Tag with privilege level (anonymous, user, admin, API, internal)
3. Track expiration and refresh requirements
4. Other agents consume without re-discovering

Types to share: session cookies, JWT tokens, API keys, OAuth tokens, CSRF tokens, basic auth credentials, service account tokens.

### Step 4: Hypothesis Tracking

A hypothesis is a suspected vulnerability not yet confirmed:

| ID | Source | Hypothesis | Status | Assigned To |
|----|--------|-----------|--------|-------------|
| H-1 | Recon agent | Admin panel at /internal/admin lacks auth | pending | Vuln agent |
| H-2 | JS analysis | Hidden API at /api/v1/debug returns verbose errors | testing | Exploit agent |
| H-3 | Scanner | Rate limiting on /login appears bypassable | confirmed | Report agent |

Agents create hypotheses. Other agents pick them up for validation. No hypothesis should go untested.

### Step 5: WAF Status Propagation

When any agent detects WAF behavior:

1. Record WAF type, detection method, and observed behavior
2. Share known bypass techniques that worked
3. Track rate limit thresholds (requests per second before blocking)
4. Propagate block status so other agents back off

This prevents multiple agents independently triggering blocks.

### Step 6: Coverage Matrix Coordination

The coverage matrix tracks completeness:

- **Horizontal coverage**: which endpoints have been reached
- **Vertical coverage**: which vuln classes tested per endpoint
- **Depth coverage**: surface scan vs deep testing per combination
- **Gap identification**: untested combinations that need attention

Agents check the matrix before starting work and update it after finishing.

## Coordination Rules

1. **Read before write**: always check shared context before starting a test
2. **Write after test**: update context with results immediately, not at session end
3. **No silent failures**: if a test was blocked or inconclusive, mark it as such
4. **Hypothesis ownership**: claim a hypothesis before testing to prevent duplicate effort
5. **Credential hygiene**: mark tokens as expired when they stop working
6. **Coverage gaps get priority**: untested combinations rank higher than re-testing

## Anti-Patterns

- Two agents testing the same endpoint for the same vuln class simultaneously
- Discovering an API key and not sharing it with other agents
- Testing against a WAF-blocked path without checking WAF status first
- Leaving the coverage matrix empty while hunting ad hoc
- Creating hypotheses without ever assigning them for validation

---

## Corpus-Derived Shared Context Patterns

Intelligence-sharing patterns from high-bounty reports that reveal how cross-agent coordination catches bugs that single-agent scanning misses.

### Internal Service Name Propagation

When any agent discovers internal service names, API paths, or infrastructure details, propagate immediately:

1. Error messages, verbose responses, and debug endpoints leak internal service names, hostnames, and RPC paths.
2. Share every discovered internal name in the shared context — another agent's SSRF or redirect finding may need exactly that name to escalate.
3. Internal-service-name + RPC-bridge-auth-gap is a recurring high-value chain: one agent finds the name, another agent finds the access path.

### Cross-Sandbox Shared State Intelligence

When the target runs multi-sandbox architectures (API gateway policies, serverless functions, plugin systems):

1. If any agent identifies shared state between sandboxes (class prototypes, globals, caches, connection pools), broadcast to all agents.
2. An agent working on sandbox A can mutate shared state; an agent working on sandbox B can observe the effect.
3. This requires coordinated testing: one agent sets the condition, another agent checks for it.

### Extension and Shared-Component Vulnerability Map

When an agent identifies a shared component (library version, browser extension, framework module):

1. Record the component and its version in shared context.
2. If the component has known vulnerabilities, propagate to all agents testing surfaces that use the same component.
3. A single vulnerability in a shared component may be exploitable through multiple surfaces — each agent tests its own surface with the same root cause.

### GraphQL Schema Intelligence Sharing

When any agent performs GraphQL introspection or schema discovery:

1. Share the full schema (types, fields, mutations, subscriptions) in shared context.
2. Other agents can then test field-level authorization without re-discovering the schema.
3. Focus on: fields that exist in the schema but are hidden from the UI, union types that leak data through inline fragments, mutations that accept extra fields not shown in documentation.

### Privilege-Tier Request Capture and Replay

When an agent with higher-privilege access captures API interactions:

1. Share the full request/response pairs in the shared context with privilege-level tags.
2. Lower-privilege agents can replay these requests with their own credentials to test authorization boundaries.
3. The highest-value pattern: capture a legitimate privileged request, then test whether the server enforces the privilege or just the session validity.

### Cross-Platform Path and Token Divergence

When agents test the same application across different platforms (web, mobile, desktop, API):

1. Share discovered tokens and paths per platform in the shared context.
2. Different platforms may use different API versions, different token formats, or different authorization checks for the same resource.
3. A token from the mobile API may grant access to resources the web API denies — cross-platform token replay is a systematic authorization test.

### Parser-Differential Shared Discovery

When any agent identifies the parser or renderer used for a content type:

1. Record the parser identity and version in shared context (e.g., "HTML sanitizer: DOMPurify 3.0.6", "Markdown renderer: marked 9.1.2").
2. All agents handling content that flows through that parser can then target parser-specific edge cases.
3. When two agents discover that two different parsers process the same content in sequence, the differential between them is a shared hypothesis that any agent can validate.

### Insecure Default Configuration Sharing

When any agent discovers a default configuration that is insecure:

1. Record the default and its security implication in shared context.
2. Test whether the default persists across: new installations, version upgrades, configuration resets, different deployment modes.
3. Other agents testing different parts of the same stack can check whether their surfaces inherit the insecure default.

### Cross-Trust-Boundary Serializer Intelligence

When any agent identifies a serialization boundary (JSON.parse, pickle, protobuf, MessagePack, custom wire format):

1. Share the serializer identity and the data that crosses the boundary.
2. Test what happens when serialization fails: does the error path expose the raw data? Does it skip validation? Does it use a fallback parser?
3. The success path is usually safe; the failure paths are where authorization checks are skipped.
