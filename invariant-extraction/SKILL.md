---
name: invariant-extraction
category: methodology
description: Extract data-model conservation and monotonicity invariants from source, then probe whether every state-mutating endpoint preserves them
depends_on: [state_machine_traversal, business_logic]
---

# Invariant Extraction

Most high-impact business-logic bugs reduce to "an endpoint mutates state in a way that breaks an invariant the system was designed around". This skill extracts those invariants from source so they can be tested mechanically rather than guessed at narratively.

## When to Use

- Any target with source-code access
- After surface mapping, before deep payload work
- Especially valuable when the target tracks numeric state across multiple entities (accumulators, counters, quotas, value tracking)

## Core Concept

An **invariant** is a property that should hold across every state mutation. Five shapes dominate:

1. **Conservation** — `sum(field across entity_set_A) == sum(paired_field across entity_set_B)` for all time (e.g., debit/credit pairing in any double-entry system, reserved/total quota pairing, locked/unlocked counters)
2. **Monotonicity** — a field that is supposed to only increase (or only decrease) over time (e.g., usage counter, sequence number, audit log offset)
3. **Authorization** — permission A implies permission B, and permission revocation cascades correctly (e.g., revoking team membership revokes access to team resources, OAuth scope removal disables associated API capabilities)
4. **Temporal** — order of operations matters and the system enforces sequencing (e.g., step N-1 must complete before step N, approval must precede execution, verification must precede action)
5. **Cross-system** — two systems agree on the truth about shared state (e.g., local ledger matches payment provider's ledger, cached ACL matches authoritative ACL store, CDN content matches origin)

If the agent can extract these invariants from source, every endpoint that writes to the involved fields becomes a test target.

## Five-Step Procedure

### Step 1 — Parse data models

Locate ORM declarations and migration files. Per framework:

- **SQLAlchemy / FastAPI**: `Column(...)` decorations inside class bodies that inherit `Base` / `DeclarativeBase`
- **Prisma**: `model {}` blocks in `schema.prisma`
- **Django**: `models.Field(...)` in `models.py`
- **ActiveRecord (Rails)**: `db/migrate/*.rb` and `db/schema.rb`
- **TypeORM / Sequelize**: `@Column`, `@Entity` decorators
- **Mongoose**: `new Schema({...})` declarations
- **Generic SQL**: `migrations/*.sql` or `schema.sql`

For each entity, extract: entity name, every field with type, every foreign key, every unique constraint.

### Step 2 — Identify accumulator fields

Accumulators are numeric fields that are mutated by multiple operations. Filter by name shape:

- Direct sums: `total_*`, `*_total`, `sum_*`, `*_sum`
- Counters: `*_count`, `count_*`, `*_remaining`, `*_used`, `*_claimed`
- Value tracking: `balance`, `amount`, `quantity`, `weight`, `volume`
- State-flagged: `*_credits`, `*_debits`, `locked_*`, `available_*`, `reserved_*`

Field type must be numeric (int, float, Decimal, BigInt). Mutated by multiple code paths (grep for `field_name +=`, `field_name -=`, `field_name = field_name + ...`).

### Step 3 — Derive invariants ("What MUST always be true?")

Before looking at specific accumulator pairs, enumerate invariants systematically by asking seven questions about the system. Each question targets a different invariant class:

| # | Question | Invariant Class | Signal |
|---|----------|----------------|--------|
| 1 | "If I sum all X across all entities, does it equal Y?" | Conservation | Paired numeric fields (debit/credit, in/out, reserved/available) |
| 2 | "Can this value ever go backward?" | Monotonicity | Sequence numbers, counters, version fields, audit log offsets |
| 3 | "If I revoke permission P, does entity E immediately lose capability C?" | Authorization | Role assignments, OAuth scopes, team membership, feature flags |
| 4 | "If step A and step B happen out of order, does the system break?" | Temporal | Multi-step workflows, approval-then-execute, verify-then-act |
| 5 | "Do system X and system Y agree on value V right now?" | Cross-system | Payment provider balance vs local ledger, cached ACL vs authoritative store |
| 6 | "Does this utility get called at EVERY site that needs it?" | Consistency | Centralized escape/quote/verify functions vs direct construction ($undisclosed, #1033041408) |
| 7 | "Is this limit enforced on the aggregate, not just per-operation?" | Aggregation | Rate limits, transfer caps, quota systems where per-request checks miss cumulative totals |

Answer each question for the target. Each "yes, and here's the invariant" becomes a test target. Each "I don't know" becomes a research task.

#### Conservation constraints (from accumulator pairs)

For each accumulator field A on entity E, look for paired entities/fields where the FK structure implies a conservation invariant.

Example shapes (parenthetical names are illustrative — the invariant itself is structural, not industry-bound):

- **Pair on opposite sign**: `entity.transferred_out` vs `entity.transferred_in`. Conservation: `sum(transferred_out across all senders) == sum(transferred_in across all receivers)`. Whenever a state mutation increases `transferred_in` for one entity, it MUST decrease `transferred_out` (or its analogue) for the paired entity by the same amount.
- **Reserved + available + total**: `reserved + available == total` for all time. A mutation that increments `available` without decrementing `reserved` (or vice versa) breaks the invariant.
- **State enum + counter**: `count(items where status='X') == counter_field_for_state_X`. Cached aggregate counts that must stay consistent with the underlying rows.
- **Monotonic-only fields**: nonce / sequence / version fields that should only increase. Any mutation that resets or decreases them is a finding.

Write the extracted invariants as plain assertions — one per line — for use in step 5:

```
INV-1: sum(account.transferred_out for all accounts) == sum(account.transferred_in for all accounts)
INV-2: account.reserved + account.available == account.total
INV-3: account.version is monotonically increasing
```

### Step 3b — Extract authorization invariants

Authorization invariants govern who can do what and how permission changes propagate. They break when revocation is incomplete or trust is transitive.

For each role/permission system, extract:

```
AUTH-INV-1: revoking role R from user U removes access to ALL resources gated by R
AUTH-INV-2: token issued with scope S cannot access endpoints outside S
AUTH-INV-3: permission granted to entity A does not transitively grant to entity B (unless explicit delegation)
AUTH-INV-4: downgrading tier (premium -> standard) removes access to tier-gated features within T seconds
```

**Where to find them**: Role definitions, middleware/decorator chains, OAuth scope definitions, RBAC policy files, feature flag configurations.

**How they break**: Cached sessions retain revoked permissions. Tokens carry stale scopes. Transitive trust in token graphs creates unintended cross-property access ($62K, #247030819). Step-gated workflows check "step N-1 happened" but not "by whom" — cross-user step completion ($0, #1145428).

### Step 3c — Extract temporal invariants

Temporal invariants enforce that operations happen in the correct order and that time-dependent state is fresh.

For each multi-step workflow and time-gated operation, extract:

```
TEMP-INV-1: step N can only execute after step N-1 completed (AND by same authenticated user)
TEMP-INV-2: approval timestamp < execution timestamp (approved operations do not execute retroactively)
TEMP-INV-3: cached permission state refreshes within T seconds of authoritative change
TEMP-INV-4: time-limited tokens/codes expire and cannot be reused after expiry
```

**Where to find them**: Workflow state machines, approval pipelines, scheduled job triggers, cache TTL configurations, token expiry logic.

**How they break**: PATCH-then-promote — modifying an object between approval and execution ($50K, #116404224). Permission state cached at deployment time not refreshing on ACL update ($133K, #489003520). Expired coupons checked at display time but not at apply time.

### Step 3d — Extract cross-system invariants

Cross-system invariants assert that two systems agree on shared state. They break at integration boundaries where each system has its own source of truth.

For each external service integration, extract:

```
CROSS-INV-1: local ledger balance == payment provider balance (reconciliation)
CROSS-INV-2: cached user profile == authoritative identity provider profile
CROSS-INV-3: local permission state == external ACL state (within sync window)
CROSS-INV-4: idempotency key carried through every retry path to downstream service
```

**Where to find them**: Payment integration code, webhook handlers, SSO flows, inter-service API calls, cache invalidation logic, retry/timeout handlers.

**How they break**: Partial failure — local debit succeeds, external credit fails, no reconciler runs ($undisclosed, #307239). Retry path uses different idempotency key than original request, causing double-payout. Local cache of external ACL state goes stale when external system updates permissions.

### Step 4 — Enumerate every endpoint that writes to those fields

For each accumulator field A:

```bash
grep -rEn "(\\.${A}\\s*[-+*/]?=|set_${A}|update.*${A}|${A}=)" --include='*.py' --include='*.js' --include='*.ts' --include='*.rb' --include='*.go' --include='*.java' .
```

For each match, walk back to find the route handler — the function reachable from a registered route that calls into this write. Build a list:

```
(endpoint, method, accumulator_field, write_pattern, transaction_boundary)
```

`transaction_boundary` notes whether the write is wrapped in a DB transaction with the paired field's write — non-atomic pairs are likely invariant-breakers.

### Step 5 — Hand the captured workflow to `generate_workflow_probes`

For each multi-step business workflow that touches accumulator fields, capture the canonical step sequence and call the registered tool:

```python
generate_workflow_probes(
    steps=[
        {"name": "create_record", "method": "POST", "endpoint": "/api/v1/records",
         "body": {"amount": 100}, "sensitive_fields": ["amount", "recipient_id"],
         "required_for_next": True, "idempotent": False},
        {"name": "review_record", "method": "POST", "endpoint": "/api/v1/records/{id}/review",
         "body": {"resolution": "approve"}, "sensitive_fields": ["resolution"],
         "required_for_next": True, "idempotent": False},
        {"name": "finalize_record", "method": "POST", "endpoint": "/api/v1/records/{id}/finalize",
         "body": {}, "required_for_next": True, "idempotent": False},
    ],
    tests=["skip", "replay", "reorder", "mutate"],
)
```

The tool returns a battery of probe sequences (skip-step, replay, reorder, value-mutation). Execute each via `terminal_execute` (or `browser` for UI flows), preserving auth/cookies between calls.

For each probe execution, **measure the invariant before and after**:
- Snapshot the accumulator values via a read endpoint (or direct DB query if available)
- Run the probe sequence
- Re-snapshot
- Compute the invariant — if it now violates the expression from step 3, that's a finding

## Anti-Patterns

- Do NOT report a missing invariant **claim** — that's a documentation gap, not a vulnerability. The finding requires demonstrating that mutating endpoint X breaks invariant Y with concrete before/after values.
- Do NOT report an invariant violation that is by design (e.g., a reservation expiry that releases value back to `available`). Confirm the design by reading the code path before reporting.
- Do NOT report monotonicity violations on fields that are documented as resettable (admin reset, period rollover).
- Do NOT skip step 5 — the probe-tool handoff is what mechanizes the test. Without it, the methodology is just narrative.

## The Violated Assumption Pattern

The highest-value invariant testing approach: identify what the system ASSUMES to be true, then systematically break each assumption.

### Step 1: Assumption Extraction

Every system makes implicit assumptions. Extract them from these sources:

| Source | Assumption Shape | Example |
|--------|-----------------|---------|
| **Error messages** | "This should never happen" guards reveal what the system considers impossible | `assert user.balance >= 0` assumes balance cannot go negative |
| **Missing validation** | What the endpoint does NOT check reveals what it assumes is guaranteed upstream | No ownership check on draft endpoint assumes drafts are private by obscurity |
| **Documentation / comments** | "Users can only...", "This endpoint is only called by..." | Comment says "internal only" but endpoint has no auth middleware |
| **Configuration defaults** | Default values reveal assumed operating conditions | Default rate limit assumes 1 device per user — multi-device breaks this |
| **Integration contracts** | What one service expects from another | Payment service assumes webhook arrives within 30s — what if it doesn't? |

### Step 2: Assumption Violation Matrix

For each extracted assumption, enumerate how it can be broken:

| Assumption | Violation Vector | Test |
|------------|-----------------|------|
| "User has at most 1 active session" | Open multiple sessions simultaneously | Do session-scoped limits apply per-session instead of per-user? |
| "Request body matches content-type" | Send JSON body with form content-type (or vice versa) | Does the parser fall back to a less-strict mode? |
| "Admin endpoints are behind VPN" | Access from public internet | Is the auth check on the endpoint or only at the network layer? |
| "IDs are opaque to users" | Enumerate sequential IDs, decode base64 IDs, predict UUIDs | Does the system rely on unguessability instead of authorization? |
| "Webhook comes from trusted service" | Send forged webhook from attacker IP | Is the webhook authenticated (signature, IP allowlist) or just accepted? |
| "Object is immutable after state X" | Attempt mutation via alternative endpoint or HTTP method | Does EVERY write endpoint enforce the immutability constraint? |

### Step 3: Assumption Dependency Chains

Assumptions form chains. Breaking one assumption may cascade:

```
Assumption A: "Referral code is single-use" (enforced by DB unique constraint on code+account)
Assumption B: "Each account has one email" (enforced by UI, not API)
Chain: Create multiple accounts with same email → each uses the referral code → single-use invariant holds per-account but breaks per-person
```

For each assumption, ask: what OTHER assumption does this depend on? Test the chain from the weakest link.

## Reporting

For each confirmed invariant violation:
- **Title**: name the invariant + the breaking operation ("Conservation invariant `transferred_out == transferred_in` broken by `POST /api/v1/transfers/{id}/reverse`")
- **Invariant**: the exact expression from step 3
- **Endpoint**: the route handler that breaks it
- **Steps to reproduce**: the probe sequence (from `generate_workflow_probes` output)
- **Before / after measurement**: concrete accumulator values
- **Impact**: the operational consequence (value materialization, quota inflation, monotonicity break enables replay)

## Tool Reference

- `generate_workflow_probes` — registered agent tool. Source: `bugdotexe/tools/workflow_probe/probe.py`. Schema: `bugdotexe/tools/workflow_probe/workflow_probe_actions_schema.xml`.

## Discovery Signals

Scan for these signals that indicate high-value invariant testing targets:

| # | Signal | Where to Find | What It Means |
|---|--------|--------------|---------------|
| 1 | Paired numeric fields (`reserved` + `available` + `total`) | Data models, ORM declarations | Conservation invariant: `reserved + available == total` must hold across all mutations |
| 2 | Cross-entity balance fields (`transferred_in`, `transferred_out`) | Account/ledger models, FK relationships | Double-entry invariant: sum of debits must equal sum of credits |
| 3 | Counter fields (`*_count`, `*_remaining`, `*_used`) | Cached aggregates, denormalized counters | Aggregate-vs-source invariant: cached count must match underlying row count |
| 4 | Monotonic fields (`version`, `sequence`, `nonce`, `last_processed_id`) | Audit logs, replay protection fields | Monotonicity: field should only increase — any decrement is replay/corruption |
| 5 | Multi-service payment/transfer flows | Payment integration code, webhook handlers | Cross-service idempotency: same key must be carried through every retry path (report #307239) |
| 6 | Rate-limit keyed on attacker-controllable dimension | Rate-limit middleware, per-device/per-IP buckets | Aggregation inversion: scaling the controllable dimension multiplies effective budget (report #1037678295) |
| 7 | Centralized security utility (`_quote`, `escape_html`, `verify_signature`) | Utility modules, shared helpers | Consistency invariant: every call site must use the utility — unmatched sites are bugs (report #1033041408) |
| 8 | OTP/code bound to `(session, account)` tuple | 2FA implementation, verification flows | Binding invariant: verification must reject codes valid for different account (report #1037678295) |
| 9 | Multi-endpoint settlement with external service | Payment/Stripe/PayPal integration, webhook callbacks | Reconciliation invariant: local ledger must match external ledger at all times (report #307239) |
| 10 | "Private"/"personal" label with numeric ID in URL | Privacy-labeled features, per-user content | Privacy enforcement invariant: every endpoint touching resource must check ownership (report #568849408, $50k) |
| 11 | Meta-resources (program config, org settings, scope definitions) | Admin panel, platform management APIs | Meta-resource IDOR: config mutations need same BOLA protection as data (report #1501611) |
| 12 | Multi-property platform with inter-service auth tokens | SSO flows, cross-product API calls | Token scope invariant: token from Property A must not grant access to Property B data (report #247030819, $62k Meta) |

## Invariant Violation Pattern Matrix

Patterns extracted from real disclosed reports:

| Invariant Type | Violation | Technique | Impact |
|----------------|-----------|-----------|--------|
| Conservation (debit == credit) | State mutation increments one side without decrementing the other | Trigger partial failure: local debit succeeds, external credit fails, no reconciler | Value materialization / double-spend (report #307239) |
| Idempotency (single-process guarantee) | Retry path uses different idempotency key than original | Fire parallel requests within timeout window, or use retry button that doesn't carry original key | Double-payout on same entitlement (report #307239) |
| Privacy (owner-only access) | Non-published state endpoint lacks ownership check | Substitute numeric ID for different user's resource on draft/private endpoint | Mass PII exposure — Fitbit $50k (#568849408) |
| Rate-limit (budget ≤ N per window) | Budget keyed on attacker-controllable dimension | Vary the controllable dimension (create devices, rotate IPs, enumerate accounts) | Effective budget = limit x variation count (report #1037678295) |
| Binding (token tied to specific entity) | Verification accepts token valid for different entity | Submit OTP code generated for account A to verification endpoint for account B | 2FA bypass / account takeover (report #1037678295) |
| Consistency (utility used everywhere) | Some code paths construct dangerous primitives without using centralized utility | Grep for all sites that build URLs/HTML/paths, find ones that skip `_quote`/`escape` | Injection at unprotected site (report #1033041408) |
| Meta-resource ACL (config is protected) | Platform management mutations lack per-tenant authorization | Call archive/rename/configure mutation with different tenant's resource ID | Cross-tenant scope manipulation (report #1501611) |
| Monotonicity (version only increases) | Reset or decrement of sequence/nonce field | Trigger admin reset, period rollover, or race condition on increment | Replay attacks, ordering violations |

## Consistency Invariant Deep-Dive

The consistency invariant ("every call site uses the centralized utility") deserves special treatment because it is testable mechanically and has produced high-value findings.

### Methodology: Grep for the Negative

1. **Identify the centralized utility**: `_quote()`, `escape_html()`, `verify_signature()`, `sanitize_input()`, or any shared security function
2. **Identify the dangerous primitive it protects**: URL construction, HTML interpolation, SQL query building, path construction, signature verification
3. **Grep for ALL sites that construct the dangerous primitive** — not just the ones that call the utility
4. **Diff the two sets**: sites that construct the primitive MINUS sites that use the utility = candidate injection points

```bash
# Example: find all URL construction sites
grep -rn 'http://' --include='*.py' --include='*.js' . | wc -l   # total sites
grep -rn '_quote\|url_escape\|encodeURIComponent' --include='*.py' --include='*.js' . | wc -l  # protected sites
# Difference = unprotected URL construction sites
```

This is not "find where the utility is used" (that's easy). This is "find where the utility SHOULD be used but ISN'T" (that's where the bugs are).

### Incomplete Patch Variant

When a security fix patches one code path, enumerate all OTHER code paths that handle the same data. The fix typically blocks one input vector (e.g., one HTML tag) but leaves others unblocked ($13.9K, #1481207). The methodology: once a vulnerability class is known for a component, exhaustively variant-hunt every entry point of that class ($12K, #658013).

## Business Logic Invariants

Domain-specific invariants that commonly break in production:

| Domain | Expected Invariant | How It Breaks | Consequence |
|--------|-------------------|---------------|-------------|
| Payment/billing | Every charge has exactly one settlement | Retry without idempotency key, or parallel requests within processing window | Double-charge or double-refund (report #307239) |
| Multi-tenant SaaS | Tenant A's mutations never affect Tenant B's state | Config/scope/program management endpoint accepts cross-tenant ID | Scope manipulation, data leak (report #1501611) |
| Privacy settings | "Private" content accessible only to owner | Draft/pending/archived states have separate fetch endpoints without owner check | Mass PII exposure (report #568849408, $50k) |
| Rate limiting / anti-abuse | User limited to N actions per window | Rate-limit key includes attacker-controllable component (device ID, IP) | Budget multiplication — N x device_count (report #1037678295) |
| Cross-product SSO | Token from Product A cannot access Product B data | Inter-property auth-token graph has transitive trust | Cross-property data access (report #247030819, $62k) |
| Content security | Every interpolation site uses centralized escape utility | New code path constructs URL/HTML without calling `_quote` | Injection via consistency gap (report #1033041408) |
| OTP verification | Code is bound to (session, account) — not just valid-format | Verification checks format but not account binding | Code generated for account A accepted for account B (report #1037678295) |
| Step-gated workflows | Step N verifies Step N-1 completed by same user | Step N checks "step N-1 happened" but not "by whom" | Cross-user step completion bypass (report #1145428) |

## Pro Tips (Corpus-Evidenced)

1. **Every cross-service settlement needs idempotency-key continuity.** Map the state machine. For each retry/timeout/cancel branch, verify the same idempotency key is reused on the downstream service. Retry buttons in UI that don't carry the original key are double-spend candidates. (report #307239)

2. **Rate-limit keys reveal the bypass.** Identify the rate-limit key. If it's `(IP, account)` and the attacker can vary IP, effective budget = limit x IP_count. If it's `(device, account)` and the attacker can create devices, same multiplication. (report #1037678295)

3. **Centralized security utility? Grep for the negative.** Don't just verify the utility works — find every code site that builds the same dangerous primitive (URL, HTML, SQL, path) WITHOUT calling the utility. Each unmatched site is a candidate injection point. (report #1033041408)

4. **OTP binding must be verified, not assumed.** Send an OTP generated for account A to the verification endpoint for account B. If it works, the code is checked for format/validity but not account binding. (report #1037678295)

5. **"Private" label + numeric ID = test cross-account immediately.** Increment the ID. If the server returns data, the privacy invariant is broken at the API layer regardless of what the UI shows. (report #568849408, $50k Fitbit)

6. **Meta-resources deserve the same BOLA treatment as data resources.** Program config, org settings, scope definitions — every mutation on platform management objects needs cross-tenant authorization testing. (report #1501611)

7. **Map the inter-property auth-token graph before testing.** On multi-property platforms (Meta, Google, Microsoft), enumerate where tokens flow between products. Transitive trust in the token graph = cross-property data access. (report #247030819, $62k)

8. **Step-gated workflow invariant: "same user" not just "step happened."** Payment flows, approval workflows, multi-step verifications — step N must verify step N-1 was performed by the same authenticated user, not just that it happened at all. (report #1145428)

9. **Conservation invariants are testable via partial failure injection.** Trigger a multi-service transaction, cause the second service to fail (timeout, reject), check if the first service rolled back. If not, the conservation invariant is broken. (report #307239)

## Composability

This skill composes with:
- `business_logic` — invariant extraction is the systematic version of business_logic's "Document invariants" step
- `state_machine_traversal` — invariants live on the same workflows the state-machine traversal walks
- `race_conditions_methodology` — invariant violations under concurrency are race-condition findings
- `chain_building` — leaked credentials (from `source_secret_detection`) often unlock the read endpoints needed for accumulator snapshots
