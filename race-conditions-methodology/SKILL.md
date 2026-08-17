---
name: race-conditions-methodology
category: methodology
description: Systematic race condition and concurrency hunting — every state-mutation endpoint is a candidate
depends_on: []
---

# Race Conditions Methodology

A race condition exists wherever two operations on shared state can interleave
without synchronization. Methodology: enumerate state-mutation endpoints from
runtime state, classify by mutation type, then apply the type-specific
concurrency test.

## When to Use

- Any target with state-mutation endpoints (POST / PUT / PATCH / DELETE)
- Any target performing accumulator updates (counters, balances, quotas, slots)
- Any target with multi-step workflows (apply → review → approve → finalize)
- Any target with finite resources (slot limits, daily limits, single-use codes)
- After surface discovery has produced the endpoint inventory

## Inputs (all runtime-derived — never hardcoded)

- **STATE_MUTATION_ENDPOINTS** = endpoints from `discoveries.jsonl` whose method ∈ {POST, PUT, PATCH, DELETE}
- **OBSERVED_RESPONSE_FIELDS** = fields seen in API responses that look stateful (`balance`, `count`, `quota`, `remaining`, `slots`, `tries`, `attempts`, `version`)
- **WORKFLOW_TRANSITIONS** = endpoints whose path or body suggests state change (`/approve`, `/reject`, `/finalize`, `/submit`, `?status=`)
- **PRINCIPALS** = `scan_config.credential_inventory.keys()` ∪ `{"anonymous"}`

## Five Race Classes Per Endpoint

### 1. ACCUMULATOR — concurrent writes to the same numeric field

For each endpoint that modifies an `OBSERVED_RESPONSE_FIELD` of numeric type:
- Read baseline value V
- Fire N parallel requests (N = 5, 10, 20)
- Read final value V'
- Expected: V' = V + (N × delta)
- If V' < V + (N × delta) → **lost update** finding
- If V' > V + (N × delta) → **double-count** finding (response counted twice)

Both directions matter: lost-update favors the system (anti-user), double-count
favors the user (anti-system).

### 2. LIMIT-BYPASS — concurrent calls past a documented threshold

For each endpoint with a documented limit L (rate, daily, count, size):
- Submit (L - 1) requests sequentially → baseline allowed
- Submit N requests in parallel where N > 1 → see if limit-check is non-atomic
- If more than L pass through → **TOCTOU on limit check** finding

Common manifestations:
- Documented per-period limit bypassed via parallel calls
- Rate limit bypassed via concurrency
- Single-use token / code / coupon redeemed multiple times
- Quota or threshold bypassed via parallel reaches

### 3. STATE-DUPLICATION — concurrent operations on the same record

For each endpoint that creates a per-record artifact (any one-shot per record — comment, vote, review, claim, ticket, action):
- Identify the record key (record_id)
- Submit N parallel creates against the same record_id
- Expected: first succeeds, rest reject as "already exists"
- If multiple succeed → **duplicate-state** finding

Common manifestations:
- Multiple per-record artifacts created against a record meant to allow one
- Multiple votes on the same poll
- Duplicate primary-key bypass
- Multi-claim of a one-shot allocation

### 4. WORKFLOW-RACE — concurrent operations across workflow steps

For each multi-step workflow A → B → C:
- Submit A, then submit B and C in parallel
- Expected: B succeeds, C blocked until B completes
- If C succeeds before B → **state-machine race** finding

Common manifestations:
- Approve and finalize concurrently
- Submit and cancel concurrently — partial outcome
- Login and password-change concurrently — token confusion

### 5. CACHE-RACE — concurrent reads/writes against a cache layer

If the target has a cache layer (CDN, Redis, application-level memo):
- Trigger cache-warm with state V
- Update state to V' via one principal, while reading via another
- Expected: invalidation propagates atomically
- If a stale read of V is observable post-V' → **cache invalidation race** finding

## Concurrency Mechanisms (universal — pick what the surface supports)

### HTTP/1.1 with parallel sockets

```
seq 20 | xargs -P 20 -I{} curl -s -X POST -d "..." -H "..." {URL}
```

Or in Python:
```python
import concurrent.futures
def fire(): return requests.post(URL, ...)
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
    futures = [ex.submit(fire) for _ in range(20)]
```

### HTTP/2 last-byte sync

If target speaks HTTP/2: send N requests withholding final byte, then release
the final bytes simultaneously. Tools: `h2cSmuggler`, custom h2 clients.

### WebSocket frame burst

If state-mutation happens over WebSocket: send N frames in a tight loop without
waiting for ACKs.

### Single-packet attack (Burp Turbo Intruder)

If the framework supports it, send all N requests in a single TCP packet —
maximum simultaneity.

## Output Format

For each race class that produces an unexpected result:

```
Endpoint: {METHOD} {path}
Race class: {ACCUMULATOR|LIMIT-BYPASS|STATE-DUPLICATION|WORKFLOW-RACE|CACHE-RACE}
Concurrency: {N parallel requests} via {mechanism}
Baseline (sequential): {expected outcome}
Observed (parallel): {actual outcome}
Delta: {numeric or qualitative gap}
Evidence: {timestamps, before/after state snapshots, packet capture}
```

## Anti-Patterns

- **Sequential-only testing**: if you only fire one request at a time, you cannot
  observe concurrency bugs. Parallel mode is mandatory.
- **Low concurrency**: 2-3 parallel requests rarely interleave on modern systems.
  Use 10-20 minimum.
- **No baseline**: without measuring sequential behavior first, you cannot
  distinguish "race condition" from "endpoint misconfigured."
- **Single principal only**: some races only manifest cross-principal (e.g.,
  approve as P1 + disburse as P2 racing). Always test cross-principal where roles allow.
- **Hardcode resource names**: never assume specific resource types (orders,
  posts, etc.). Discover the state-mutation endpoints from runtime traffic.
- **Skip TOCTOU on limits**: documented limits are the most-tested-and-still-broken
  surface. Always race them.

## Coverage Self-Check

Before declaring concurrency tested:
- [ ] Every state-mutation endpoint exercised with N≥10 parallel requests
- [ ] Every documented limit raced (TOCTOU)
- [ ] Every multi-step workflow tested for cross-step race
- [ ] Every per-record-create endpoint tested for duplicate-state
- [ ] Every cache layer tested for invalidation race

## Corpus-Derived Race Patterns

### Financial/Balance Operations (Universal Priority Target)

Every financial operation is a race condition candidate. Systematic test:

1. Identify all operations that transfer, debit, or credit a balance (withdraw, transfer, redeem, purchase, tip, donate)
2. For each: fire 10-20 parallel requests for the same operation with the same session
3. Check: did the balance decrease by 1x or Nx? Did the recipient receive 1x or Nx?
4. Test both directions: over-debit (system loses money) and over-credit (attacker gains money)

### One-Time Benefit Redemption Races

Any endpoint that grants a one-time benefit is a high-priority race target:

- Free trial activation
- Coupon/promo code redemption
- Referral bonus credit
- Sign-up bonus
- First-purchase discount
- Loyalty reward claim
- Invitation acceptance

Test: fire N parallel redemption requests. If more than one succeeds, the uniqueness constraint is not atomic.

### Counter-Gated Resources with Refund Mechanisms

When a system has both a counter (invites remaining, credits, votes) and a refund/undo mechanism:

1. Consume the resource (spend credit, use invite)
2. Simultaneously request a refund and consume again
3. If the refund and the new consumption both succeed, the counter is corrupted
4. Repeat: the attacker can generate unlimited resources from a single initial allocation

### Email/Notification Side-Effect Races

Every email-sending or notification-triggering endpoint should be tested:

1. Fire N parallel requests that trigger the side effect
2. Check the inbox: did the target receive 1 email or N emails?
3. Notification spam via race condition can be a valid DoS finding (especially for SMS/voice calls with cost implications)

### TOCTOU on SSRF Defenses

When an SSRF defense uses "resolve hostname, check IP, then fetch URL":

1. Set up a DNS server that alternates responses (first query returns allowed IP, second returns 127.0.0.1)
2. The validation resolves to the allowed IP; the fetch re-resolves to the blocked IP
3. Test with DNS rebinding tools (`rbndr.us`, `1u.ms`, custom DNS server)
4. Short TTL (0 or 1 second) increases the window

### TOCTOU on File Operations

When privileged code operates on file hierarchies (delete, chmod, chown, move):

1. Race the operation with a symlink swap: create `target_dir/file` as a regular file, then swap it for a symlink to a sensitive file between the permission check and the operation
2. For SUID binaries: race the path verification with a path relocation (rename the directory between `stat()` and `open()`)
3. Tools: `inotifywait` to trigger the swap at the exact moment

### Static/Global State in Multi-Tenant Libraries

For any library used in concurrent or multi-tenant contexts:

1. Search for `static`, `global`, class-level variables, and singletons
2. If per-request state is stored in a static variable, concurrent requests from different tenants can leak data across tenants
3. Test: send requests from two different sessions simultaneously, check if response A contains data from session B

### Sequential Repetition Before Concurrency

Before investing in complex race condition tooling:

1. Test simple sequential repetition first -- fire the same request 10 times in sequence
2. A non-idempotent endpoint may show the bug without any concurrency at all
3. If sequential repetition does not trigger but the endpoint modifies state, then escalate to concurrent testing

## Composability

This skill composes with:
- `auth_matrix_systematic` — race a permission boundary (e.g., role downgrade
  during privileged action)
- `boundary_spec_violation` — race a limit boundary (TOCTOU on limit check)
- `chain_building` — combine a race-enabled state corruption with a downstream
  exploit primitive
- `variant_hunting` — once a race lands on one endpoint, test sibling endpoints
