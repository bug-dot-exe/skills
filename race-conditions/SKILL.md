---
name: race-conditions
description: Race condition testing for TOCTOU bugs, double-spend, and concurrent state manipulation
depends_on: []
---

# Race Conditions

Concurrency bugs enable duplicate state changes, quota bypass, financial abuse, and privilege errors. Treat every read-modify-write and multi-step workflow as adversarially concurrent.

## Discovery Signals

| Signal | Where to Find | Why Vulnerable |
|--------|--------------|----------------|
| Balance/credit transfer endpoint | Wallet, points, loyalty, data credits | Read-balance then deduct is non-atomic; parallel transfers duplicate value |
| Coupon/promo code redemption | Checkout, rewards, referral | Single-use check precedes consumption; N parallel requests = N redemptions |
| Like/vote/follow/helpful endpoint | Social features, polls, articles | "Already acted" check is app-level, not DB constraint; inflate counts |
| File upload finalization | Multi-part upload, S3 presigned | Parallel complete/finalize creates duplicate objects or corrupt state |
| Invitation acceptance | Team/org/group join flows | Member-count quota checked then written; exceed plan-tier seat limits |
| Password reset token consumption | Auth flows, magic links, OTP | Token marked used after grant; parallel consumption mints multiple sessions |
| Inventory/seat purchase | E-commerce, ticketing, SaaS plans | Stock-check then decrement; oversell beyond available inventory |
| Free trial/premium activation | SaaS onboarding, feature gates | "Already activated" flag set after grant; multiply free trial days |
| Withdrawal/payout request | Crypto, banking, rewards | Balance validated then debited; drain more than balance allows |
| API key/token generation | Developer portals, integrations | Quota check then create; exceed per-account key limits |
| Background job creation | Export, import, report generation | Job-limit check is app-level; spawn unlimited concurrent jobs |
| Referral bonus claim | Growth/affiliate systems | "Already claimed" check is non-atomic; multiply bonus credits |

## Attack Surface

**Read-Modify-Write**
- Sequences without atomicity or proper locking

**Multi-Step Operations**
- Check -> reserve -> commit with gaps between phases

**Cross-Service Workflows**
- Sagas, async jobs with eventual consistency

**Rate Limits and Quotas**
- Controls implemented at the edge only

## High-Value Targets

- Payments: auth/capture/refund/void; credits/loyalty points; gift cards
- Coupons/discounts: single-use codes, stacking checks, per-user limits
- Quotas/limits: API usage, inventory reservations, seat counts, vote limits
- Auth flows: password reset/OTP consumption, session minting, device trust
- File/object storage: multi-part finalize, version writes, share-link generation
- Background jobs: export/import create/finalize endpoints; job cancellation/approve
- GraphQL mutations and batch operations; WebSocket actions

## Reconnaissance

### Identify Race Windows

- Look for explicit sequences: "check balance then deduct", "verify coupon then apply", "check inventory then purchase"
- Watch for optimistic concurrency markers: ETag/If-Match, version fields, updatedAt checks
- Examine idempotency-key support: scope (path vs principal), TTL, and persistence (cache vs DB)
- Map cross-service steps: when is state written vs published, what retries/compensations exist

### Signals

- Sequential request fails but parallel succeeds
- Duplicate rows, negative counters, over-issuance, or inconsistent aggregates
- Distinct response shapes/timings for simultaneous vs sequential requests
- Audit logs out of order; multiple 2xx for the same intent; missing or duplicate correlation IDs

## HTTP/2 Single-Packet Attack

The most important race condition technique in modern bug bounty (James Kettle, PortSwigger Research). Eliminates network jitter entirely -- all requests arrive within microseconds of each other.

**How it works**: Queue 20-30 HTTP/2 requests on a single TCP connection, withholding each request's final byte. Release all final bytes in one TCP packet. The server receives and processes all requests near-simultaneously, defeating millisecond-level application locks.

**Why it beats traditional threading**: Threaded/async scripts suffer from network jitter (1-50ms variance per request). Single-packet delivery reduces variance to sub-microsecond on the server side. This is the difference between "sometimes hits the window" and "reliably hits the window."

**Turbo Intruder setup**:
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)  # HTTP/2
    for i in range(30):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')  # sends all queued as single packet

def handleResponse(req, interesting):
    table.add(req)
```

**Connection warming**: Before firing the race, send 1-2 throwaway requests to establish TCP + TLS + HTTP/2 session. This removes connection-setup variance from the attack window.

**HTTP/1.1 last-byte sync** (fallback when target lacks HTTP/2): Open N connections, send all but the final byte of each request, then send all final bytes simultaneously. Less precise than single-packet but still effective.

## Limit Overrun Patterns

| Target | Normal Behavior | Race Outcome | Business Impact |
|--------|----------------|--------------|-----------------|
| Coupon redemption | 1 use per code | Code applied N times | Revenue loss per redeemed value |
| Like/upvote | 1 per user per item | Count inflated to N | Metric manipulation, SEO gaming |
| Team member invite | Capped at plan tier | Exceed seat limit | Billing/subscription bypass |
| Free trial activation | 1 per account | N days/activations granted | Feature access without payment |
| Withdrawal request | Capped at balance | Drain beyond balance to negative | Direct financial loss |
| Referral bonus | 1 per referrer-referee pair | N bonus credits minted | Free credit generation |
| Gift card redemption | 1 use per card | Card value extracted N times | Direct financial loss |
| Vote/poll submission | 1 vote per user | N votes registered | Election/ranking manipulation |
| API key generation | Capped per account | Exceed key quota | Abuse amplification |
| Data credit transfer | Balance-checked debit | Credits duplicated across orgs | Value created from nothing |

## Financial Race Patterns

**Double-withdrawal**: Send 2+ withdrawal requests simultaneously when balance covers only 1. Both read the same pre-deduction balance, both pass validation, both execute. Net effect: withdraw 2x your balance. Proven pattern on Helium ($250 bounty), crypto exchanges, point systems.

**Reward/bonus multiplication**: Claim the same one-time reward in parallel. The "already claimed" flag is set after the reward grant, not atomically with it. Each parallel request reads "not claimed" and grants the reward.

**Payment race**: Initiate 2 purchases where combined cost exceeds balance but each individually passes. Both read the same balance, both succeed. Equivalent to interest-free credit.

**Refund + re-purchase**: Request a refund and simultaneously re-purchase with the same balance. The refund credits back while the purchase debits from the pre-refund state. Result: both money returned and item retained.

**Plan upgrade race**: Submit plan-upgrade request in parallel with a payment-bypass vector. The plan-grant logic processes both before the payment-validation write lands.

## Code Pattern Indicators

| Code Pattern | Language/Framework | Race Risk |
|-------------|-------------------|-----------|
| `SELECT balance; UPDATE balance` (not `SELECT FOR UPDATE`) | SQL (any ORM) | Classic TOCTOU: read and write are separate transactions |
| `if count < limit: insert()` | Python/Ruby/Node | App-level check without DB constraint; parallel inserts all pass |
| `redis.GET key; redis.SET key` (not `SETNX`/`GETSET`) | Redis | Non-atomic read-then-write; use `SETNX`, `INCR`, or Lua scripts |
| Optimistic lock without retry on conflict | JPA/Hibernate/Django | Version check detects conflict but silently drops the update |
| `async job.create()` without idempotency key | Background workers | Duplicate jobs from parallel triggers; no dedup at queue level |
| `if !exists: create()` (not `INSERT ON CONFLICT`) | Any ORM | Existence check and insert are separate operations |
| `cache.get(); ...; cache.set()` without lock | Memcached/Redis | Cache-aside pattern; parallel requests all miss and all write |
| `fs.exists() then fs.write()` | Node.js/Python | TOCTOU on filesystem; parallel writes corrupt or duplicate |
| `user.save()` after field update (no atomic update) | Django/Rails/Express | Full-object save overwrites concurrent changes from other requests |
| `claims.includes(userId)` then `claims.push(userId)` | In-memory array | Array check and mutation are non-atomic in concurrent handlers |

## Time Window Estimation

**Measure the gap**: Time the interval between the check operation and the write operation. Longer gaps = easier races. Look for: DB round-trips, external API calls, email sends, file I/O, or computation between check and write.

**Widen the window**:
- Add processing load: large JSON payloads, complex query parameters, or fields that trigger slow operations (bcrypt hashing, image processing)
- Trigger garbage collection pauses in managed runtimes (Java, Go, Node)
- Target endpoints behind slow middleware (logging, analytics, webhook dispatch)
- Use requests that hit a cold cache path (first request after cache expiry)

**Synchronize with server timing**:
- Read the `Date` header to estimate server clock and processing latency
- Use sequential request IDs or timestamps in responses to gauge processing order
- Compare response times for identical requests to measure server-side variance

## Key Vulnerabilities

### Request Synchronization

- HTTP/2 multiplexing for tight concurrency; send many requests on warmed connections
- Last-byte synchronization: hold requests open and release final byte simultaneously
- Connection warming: pre-establish sessions, cookies, and TLS to remove jitter

### Idempotency and Dedup Bypass

- Reuse the same idempotency key across different principals/paths if scope is inadequate
- Hit the endpoint before the idempotency store is written (cache-before-commit windows)
- App-level dedup drops only the response while side effects (emails/credits) still occur

### Atomicity Gaps

- Lost update: read-modify-write increments without atomic DB statements
- Partial two-phase workflows: success committed before validation completes
- Unique checks done outside a unique index/upsert: create duplicates under load

### Cross-Service Races

- Saga/compensation timing gaps: execute compensation without preventing the original success path
- Eventual consistency windows: act in Service B before Service A's write is visible
- Retry storms: duplicate side effects due to at-least-once delivery without idempotent consumers

### Rate Limits and Quotas

- Per-IP or per-connection enforcement: bypass with multiple IPs/sessions
- Counter updates not atomic or sharded inconsistently; send bursts before counters propagate

### Optimistic Concurrency Evasion

- Omit If-Match/ETag where optional; supply stale versions if server ignores them
- Version fields accepted but not validated across all code paths (e.g., GraphQL vs REST)

### Database Isolation

- Exploit READ COMMITTED/REPEATABLE READ anomalies: phantoms, non-serializable sequences
- Upsert races: use unique indexes with proper ON CONFLICT/UPSERT or exploit naive existence checks
- Lock granularity issues: row vs table; application locks held only in-process

### Distributed Locks

- Redis locks without NX/EX or fencing tokens allow multiple winners
- Locks stored in memory on a single node; bypass by hitting other nodes/regions

## Bypass Techniques

- Distribute across IPs, sessions, and user accounts to evade per-entity throttles
- Switch methods/content-types/endpoints that trigger the same state change via different code paths
- Intentionally trigger timeouts to provoke retries that cause duplicate side effects
- Degrade the target (large payloads, slow endpoints) to widen race windows

## Platform-Specific Tooling

| Platform | Technique | Setup |
|----------|-----------|-------|
| Burp Turbo Intruder | Single-packet via `Engine.BURP2` + gate sync | `engine.queue(req, gate='g'); engine.openGate('g')` |
| Burp Repeater | "Send group in parallel" (Burp 2023.9+) | Select tabs, right-click, send group in parallel |
| Python asyncio | `asyncio.gather(*[send(req) for _ in range(N)])` | Pre-open connections, fire coroutines simultaneously |
| Python requests | `ThreadPoolExecutor` with pre-warmed sessions | Session pool with keep-alive, `executor.map(send, reqs)` |
| Go goroutines | `sync.WaitGroup` + channel signal for simultaneous fire | Goroutines block on channel, main sends start signal |
| curl | `curl --parallel --parallel-max 30` | Requires curl 7.66+ with HTTP/2; less precise than Turbo Intruder |
| JavaScript fetch | `Promise.all(urls.map(u => fetch(u)))` | Same-origin with keepalive; useful for client-side race PoCs |
| WebSocket | Send N messages without awaiting responses | Parallel frames on single connection; bypasses HTTP-level guards |

## Special Contexts

### GraphQL

- Parallel mutations and batched operations may bypass per-mutation guards
- Ensure resolver-level idempotency and atomicity
- Persisted queries and aliases can hide multiple state changes in one request

### WebSocket

- Per-message authorization and idempotency must hold
- Concurrent emits can create duplicates if only the handshake is checked

### Files and Storage

- Parallel finalize/complete on multi-part uploads can create duplicate or corrupted objects
- Re-use pre-signed URLs concurrently

### Auth Flows

- Concurrent consumption of one-time tokens (reset codes, magic links) to mint multiple sessions
- Verify consume is atomic

## Chaining Attacks

| Chain | Steps | Combined Impact |
|-------|-------|-----------------|
| Race + IDOR | Race to create/modify resource, IDOR to target other users' objects | Modify/read others' resources before ownership check commits |
| Race + Business Logic | Parallel requests violate domain invariants | Double-refund, negative balance, limit bypass with durable state |
| Race + CSRF | Victim's browser fires parallel cross-origin requests | Amplify single victim action into N state changes |
| Race + Cache Poisoning | Race to poison cache during write window | Stale cached response serves privileged state to all users |
| Race + Session Fixation | Race session creation during auth flow | Attacker session promoted to authenticated before invalidation |
| Race + 2FA Bypass | Race token consumption to create session before 2FA check | Parallel login bypasses sequential 2FA gate |
| Race + Payment Bypass | Race plan-grant with payment-cancel | Obtain premium features without completed payment |

## Testing Methodology

1. **Model invariants** - Conservation of value, uniqueness, maximums for each workflow
2. **Identify reads/writes** - Where they occur (service, DB, cache)
3. **Baseline** - Single requests to establish expected behavior
4. **Concurrent requests** - Issue parallel requests with identical inputs; observe deltas
5. **Scale and synchronize** - Ramp up parallelism, use HTTP/2, align timing (last-byte sync)
6. **Cross-channel** - Test across web, API, GraphQL, WebSocket
7. **Confirm durability** - Verify state changes persist and are reproducible

## Validation

1. Single request denied; N concurrent requests succeed where only 1 should
2. Durable state change proven (ledger entries, inventory counts, role/flag changes)
3. Reproducible under controlled synchronization (HTTP/2, last-byte sync) across multiple runs
4. Evidence across channels (e.g., REST and GraphQL) if applicable
5. Include before/after state and exact request set used

## False Positives

- Truly idempotent operations with enforced ETag/version checks or unique constraints
- Serializable transactions or correct advisory locks/queues
- Visual-only glitches without durable state change
- Rate limits that reject excess with atomic counters

## Impact

- Financial loss (double spend, over-issuance of credits/refunds)
- Policy/limit bypass (quotas, single-use tokens, seat counts)
- Data integrity corruption and audit trail inconsistencies
- Privilege or role errors due to concurrent updates

## Pro Tips

1. Favor HTTP/2 with warmed connections; add last-byte sync for precision
2. Start with N=2 (simplest possible race), confirm the window exists, then scale to N=20-30 for impact demonstration
3. Target read-modify-write code paths and endpoints with idempotency keys
4. Compare REST vs GraphQL vs WebSocket; protections often differ
5. Look for cross-service gaps (queues, jobs, webhooks) and retry semantics
6. Check unique constraints and upsert usage; avoid relying on pre-insert checks
7. Use correlation IDs and timestamps in responses to prove concurrent interleaving happened
8. Widen windows by adding server load (large payloads, bcrypt-triggering fields, slow backend dependencies)
9. Validate on production-like latency; some races only appear under real load
10. Document minimal, repeatable request sets that demonstrate durable impact
11. Target state transitions (pending->approved, trial->paid) not just balance checks -- transition guards are often weaker
12. Test both success+success AND success+failure races: two withdrawals that both succeed, or one withdrawal + one refund that create an impossible state
13. Check if rate limiting itself is raceable: can you exhaust the rate-limit counter and your attack requests in the same burst?
14. Look for race conditions in background job creation: can you trigger the same export/import/report job N times before the "job already running" guard fires?
15. After finding a race on one endpoint, test every sibling endpoint with the same pattern (all setters, all claim endpoints, all transfer endpoints)
16. Test across deployment boundaries: if the app runs behind multiple load-balanced instances, requests hitting different backends may bypass in-process locks entirely
17. Multi-step flow authority mutation: find flows where a value (email, owner_id, scope) can be mutated BETWEEN issuance and consumption -- e.g., change email after password reset token is issued but before it is consumed ($15.2K)
18. Counter-guarded resources with refund mechanisms: race the refund (which restores the counter) against new consumption -- create infinite resources from a single allocation
19. Async-pipeline filesystem race: when a web request stages content to disk and an async worker processes it, the gap between write and pickup is a TOCTOU window for file replacement
20. macOS `.pkg` postinstall scripts running as root are privilege-escalation candidates via symlink TOCTOU on the extracted paths ($10K)

## Summary

Concurrency safety is a property of every path that mutates state. If any path lacks atomicity, proper isolation, or idempotency, parallel requests will eventually break invariants.
