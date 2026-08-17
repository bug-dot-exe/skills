---
name: coverage-matrix
category: methodology
description: Systematic endpoint x vuln class x auth state test coverage tracking
depends_on: []
---

# Coverage Matrix

Track coverage across three dimensions: endpoints, vulnerability classes, and auth states. Systematic coverage finds bugs in the corners ad-hoc testing skips.

## When to Use

- At the start of testing to plan coverage
- During testing to track progress and identify gaps
- At the end to verify completeness

## Step 1: Endpoint Inventory

Enumerate every testable surface from docs, JS bundles, proxy history, source code:

| # | Method | Endpoint | Auth | Parameters |
|---|--------|----------|------|------------|
| 1 | GET | /api/users/{id} | Yes | id (path) |
| 2 | PUT | /api/users/{id} | Yes | email, name (body) |
| 3 | POST | /api/files/upload | Yes | file (multipart) |

## Step 2: Vulnerability Classes

Select classes relevant to the target:

| Code | Class | Applicable To |
|------|-------|---------------|
| IDOR | Broken object-level auth | Endpoints with object IDs |
| BFLA | Broken function-level auth | Role-restricted endpoints |
| INJ | Injection (SQLi, NoSQLi, CMDi) | User input in queries/commands |
| XSS | Cross-site scripting | Endpoints reflecting/storing input |
| SSRF | Server-side request forgery | Endpoints fetching URLs |
| CSRF | Cross-site request forgery | State-changing endpoints |
| RACE | Race conditions | Financial/quota endpoints |
| LOGIC | Business logic | Workflow endpoints |
| MASS | Mass assignment | JSON/form body endpoints |

## Step 3: Auth States

| State | Description |
|-------|-------------|
| UNAUTH | No token |
| USER_A | Owner account |
| USER_B | Other user (cross-account tests) |
| ADMIN | Admin account |
| EXPIRED | Revoked/expired token |

## Step 4: Track the Matrix

For each endpoint, mark every cell:

```
PUT /api/users/{id}
| Class | UNAUTH | USER_A | USER_B | ADMIN |
|-------|--------|--------|--------|-------|
| IDOR  |   -    |   ok   | FOUND  |  ok   |
| BFLA  |  ok    |   ok   |   ok   |  ok   |
| MASS  |   -    |   ok   |   ok   |  ok   |
| CSRF  |   -    |   ok   |   -    |  ok   |

ok=clean  FOUND=vulnerable  -=N/A  blank=untested
```

## Step 5: Prioritize

**High priority** (test first): State-changing endpoints x IDOR/BFLA at cross-user auth. Financial endpoints x RACE/LOGIC. Upload endpoints x all auth states.

**Medium**: Read endpoints x IDOR cross-user. All endpoints x AUTH at UNAUTH/EXPIRED.

**Low**: Static endpoints x INFO. Idempotent GETs x CSRF.

## Step 6: Gap Analysis

Before wrapping up, scan for blank cells in high-priority areas. If IDOR was found on 2 of 5 similar endpoints, the remaining 3 are untested gaps. Summary: `Endpoints:[N] Classes:[N] States:[N] Tested:[N]/[total]([%]) Gaps:[N]`

## Resource × Transition Matrix

Every resource the agent identifies supports some subset of state transitions. Missing a transition = missing half the attack surface for that resource. Enumerate which transitions the TARGET exposes for each resource, then test each with each principal.

**Transition classes** (every protocol maps to these; the agent must discover the target's own grammar):

- **Create** — a transition that brings a new instance of the resource into existence
- **Read** — a transition that returns the resource state without changing it
- **Update** — a transition that mutates an existing instance in place
- **Delete** — a transition that ends the resource instance's existence
- **List / Enumerate** — a transition that reveals which instances exist (separate from Read because the leak is the set, not the content)
- **Invoke / Trigger** — a transition that runs the resource's embedded behavior (relevant when resources have executable semantics)

**Rule:** for every resource, enumerate which transition classes the target supports (do not assume a template). Then test each supported transition with each principal/role. A resource where only a subset of its supported transitions was tested is not complete.

**Output:** record the Resource × Transition × Principal matrix. Before any `agent_finish`, the matrix must have NO gaps in the high-priority row (state-changing transitions at cross-principal auth).

**Common failure mode:** finding cross-tenant exposure on a Read transition, declaring the resource "done," and missing an Update transition that allows overwriting another principal's state — a strictly worse bug than the read-only exposure.

## Systematic Audit Methodologies

Patterns extracted from 1,117 paid reports. These are exhaustive enumeration approaches that produce the highest-bounty findings by ensuring ZERO gaps in coverage.

### CI/CD Workflow Trigger + Permissions Matrix Audit ($3.1M pattern)

For every public repository owned by a target:

| Step | Action | What You Are Looking For |
|------|--------|------------------------|
| 1 | Clone repo, locate all workflow files (`.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`) | Every automated pipeline definition |
| 2 | For each workflow, extract the trigger event (`pull_request_target`, `issue_comment`, `workflow_run`, `schedule`) | Triggers that fire on external input |
| 3 | For each trigger, trace every variable derived from the triggering event (PR title, branch name, issue body, commit message) | User-controlled strings entering the pipeline |
| 4 | For each variable, check: does it flow into `run:`, `uses:`, environment variables, or artifact paths WITHOUT sanitization? | Injection points for command execution |
| 5 | Check the workflow `permissions:` block -- if missing, default is `write-all` on `pull_request_target` | Overpermissioned tokens available post-injection |

**Critical trigger**: `pull_request_target` runs with the BASE repo's secrets and write token, but processes the FORK's code. Any code execution in this context = full repo compromise. This single pattern produced $3.1M+ in bounties across GitHub Actions audits.

**Exhaustive variant hunt**: once you find one unsafe workflow, enumerate ALL workflows in ALL repos owned by the same org. Developers repeat patterns. A finding in repo A almost certainly exists in repos B through Z.

### Alternate-Surface Authorization Audit ($1.5M pattern)

For multi-surface platforms (web, mobile, API, desktop, TV, embedded):

| Step | What to Test |
|------|-------------|
| 1 | Enumerate every surface that can perform the SAME action (e.g., "change email" via web, mobile app, API, admin panel) |
| 2 | For each surface, document the exact authorization check (cookie, bearer token, API key, session, cert) |
| 3 | Compare auth enforcement across surfaces -- the weakest surface is the attack target |
| 4 | Test cross-surface token reuse: does a token minted for Surface A work on Surface B? |
| 5 | Test deprecated surface access: do old API versions (v1, v2) still accept requests with weaker auth? |

**Key insight**: authorization is often implemented per-surface, not per-action. The web app checks CSRF + session + 2FA. The mobile API for the same action checks only a bearer token. The internal API checks nothing. Finding the weakest surface for a high-value action is a systematic $50K+ pattern.

### Differential Behavior Auditing ($2M pattern)

When a target reimplements an existing specification (EVM opcodes, HTTP parsing, JSON parsing, Unicode handling):

| Step | Action |
|------|--------|
| 1 | Enumerate every operation/opcode/function in the specification |
| 2 | For each, identify which operations MUTATE state vs. which are pure reads |
| 3 | Write a differential test: execute the same operation on the reference implementation and the target |
| 4 | Compare outputs -- any divergence is a candidate finding |
| 5 | Focus on operations that interact (e.g., CREATE2 address depends on SELFDESTRUCT behavior) |

This pattern found a $2M bug where an L2 client's SELFDESTRUCT implementation diverged from the EVM spec, allowing ETH minting. The methodology is: specification + reimplementation = differential testing opportunity.

### Archive Upload Extraction Auditing ($1.2M pattern)

For every file upload endpoint that accepts archives (ZIP, TAR, JAR, APK, DOCX, XLSX):

| Test | What It Catches |
|------|----------------|
| Symlink inside archive pointing to `/etc/passwd` or `../../../../etc/shadow` | Path traversal via symlink resolution |
| Filename with `../` components | Zip slip -- file extraction outside intended directory |
| Archive with 10,000 empty directories | Resource exhaustion during extraction |
| Archive containing a file with the same name as the extraction script/config | Overwrite of extraction infrastructure |
| Nested archives (zip inside zip inside zip) | Recursive extraction DoS or bypass of single-level checks |
| Archive with filename encoding mismatch (UTF-8 vs CP437) | Parser differential leading to path traversal |

### Method x Endpoint Exhaustive Matrix ($50K pattern)

For EVERY endpoint discovered:

```
Endpoint: /api/resource/{id}
| Method  | Unauth | User_A | User_B | Admin | Expired |
|---------|--------|--------|--------|-------|---------|
| GET     |        |        |        |       |         |
| POST    |        |        |        |       |         |
| PUT     |        |        |        |       |         |
| PATCH   |        |        |        |       |         |
| DELETE  |        |        |        |       |         |
| OPTIONS |        |        |        |       |         |
| HEAD    |        |        |        |       |         |
```

**Rule**: test EVERY cell. Authorization is frequently enforced per-method. A 403 on PUT does not mean PATCH is blocked. A 403 on DELETE does not mean you cannot POST with `_method=DELETE`. Discovering that PATCH allows unauthenticated modification while PUT requires auth is a $50K finding.

### OAuth Scope Exhaustive Enumeration ($313K pattern)

For any OAuth provider with multiple scopes:

| Step | Action |
|------|--------|
| 1 | Enumerate ALL available scopes (documentation, consent screen, API errors, JS bundles) |
| 2 | For each scope, request a token with ONLY that scope |
| 3 | Systematically call EVERY API endpoint with that single-scope token |
| 4 | Document which endpoints accept the token vs. reject it |
| 5 | Compare actual access granted vs. scope description -- look for scope overpermission |

**What you are looking for**: a scope described as "read user profile" that also grants access to "modify billing" or "read private messages." Consent screen descriptions are aspirational; actual enforcement is the ground truth.

### Platform Fingerprint to Known-Misconfig Checklist

| Platform Detected | Immediate Checklist |
|-------------------|-------------------|
| Salesforce Experience Cloud | Guest user API access, Aura component exposure, object-level permissions on guest profile |
| ServiceNow | ACL bypass via direct API, table-level read access, widget server-script injection |
| Firebase | `.json` suffix on database URL for public read, auth rule misconfiguration, public storage buckets |
| WordPress + plugins | Enumerate all plugins, check abandoned/removed ones, test each for auth bypass |
| GraphQL | Introspection enabled? Field suggestion via error messages? Nested query DoS? Mutation auth? |
| Electron app | Check bundled Chromium version, `nodeIntegration` setting, `contextIsolation`, preload script sinks |

### "Every Function, Every Endpoint" Enumeration

The single most productive methodology at scale: treat the target as a finite set and test EVERY element.

| Scope | Enumeration Source | What to Test Per Element |
|-------|--------------------|------------------------|
| REST endpoints | Proxy history, OpenAPI spec, JS bundles, mobile app decompilation | Auth bypass (5 auth states), IDOR (cross-user IDs), injection (every parameter) |
| GraphQL resolvers | Introspection, error-based field enumeration, schema from app bundle | Each resolver: auth check, nested resolver auth, N+1 query depth |
| CLI subcommands | `--help`, man pages, source code | Each subcommand: argument injection, file path traversal, privilege escalation |
| Workflow triggers | CI/CD config files | Each trigger: user-controlled input flow, secret exposure, token permissions |
| File parsers | Import/upload features, build tools, IDE project-open | Each parser: XXE, path traversal, deserialization, resource exhaustion |
| Browser extensions | Chrome Web Store, manifest.json | Each extension: externally_connectable, message handlers, content script injection |
| OAuth scopes | Provider documentation, consent screens | Each scope: actual API access granted vs. described access |
| Iframe-able actions | Every button, menu item, form in the app | Each action: X-Frame-Options bypass, clickjacking via SVG filters, drag-and-drop |

**Rule**: "I tested the main endpoints" is never complete. The bug is in endpoint 47 of 50, in the one HTTP method you did not try, with the one auth state you skipped.

### State-Transition Matrix (Beyond CRUD)

For permission and workflow systems, test transitions, not just static states:

```
State Machine: [Draft] -> [Pending] -> [Approved] -> [Published]

| From \ To   | Draft | Pending | Approved | Published | Deleted |
|-------------|-------|---------|----------|-----------|---------|
| Draft       |  -    | USER    | ???      | ???       | USER    |
| Pending     | ???   |  -      | ADMIN    | ???       | ???     |
| Approved    | ???   | ???     |  -       | ADMIN     | ???     |
| Published   | ???   | ???     | ???      |  -        | ADMIN   |
```

Every `???` cell is an untested transition. Test: can a USER trigger Draft->Approved directly (skipping Pending)? Can a USER trigger Published->Draft (reverting admin approval)? Can UNAUTH trigger any transition?

**The "PATCH-then-promote" pattern**: multi-step approval workflows often allow you to PATCH an object's status field directly, bypassing the intended approval chain. If the status field is mass-assignable, you can self-approve.

### Variant Hunting After First Finding

Once you find one instance of a bug class, exhaustively hunt for variants:

| Strategy | Application |
|----------|------------|
| Same class, different endpoint | Found SQLi on `/search`? Test every other endpoint that accepts user input in queries |
| Same endpoint, different parameter | Found XSS in `?name=`? Test every other parameter on the same endpoint |
| Same pattern, different repo | Found unsafe workflow in repo A? Check every other repo in the org |
| Same fix bypass | Fix blocklisted `<script>`? Try `<img onerror>`, `<svg onload>`, `<details ontoggle>` |
| Same class, different depth | Found argument injection via one flag? Enumerate EVERY CLI flag the binary accepts |

**Exhaustive variant hunting is the highest-ROI activity after a first find.** One $12K finding becomes five $12K findings because developers repeat the same mistake across entry points. The variant hunt is where $12K becomes $60K.

### Error Message Schema Discovery

When APIs return verbose error messages:

| Error Content | What It Reveals | Next Step |
|--------------|----------------|-----------|
| Parameter names in validation errors | Hidden API parameters not in documentation | Add discovered params to your endpoint inventory |
| SQL table/column names in database errors | Database schema | Targeted SQL injection with known column names |
| Internal service names in timeout errors | Microservice architecture map | SSRF targeting discovered internal services |
| Stack traces with file paths | Application structure, framework version | Targeted CVE exploitation, path traversal with known paths |
| Different error messages for "user not found" vs "wrong password" | User enumeration | Build valid user list, then credential stuff |

**Rule**: error messages are unintentional API documentation. Every unique error response is an enumeration signal.
