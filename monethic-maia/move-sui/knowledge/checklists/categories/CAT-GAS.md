# CAT-GAS — Gas & Performance

## CL-GAS-01: Storage Growth / State Bloat

**Rule:** `MOVE-GAS-BLOAT-01`
**Severity:** Low-Medium

### Description
The protocol must ensure that on-chain data structures do not grow without bounds or cleanup mechanisms. Unbounded growth eventually exceeds object size limits (Sui: 256KB), causes excessive gas costs for reads/writes, or leaves stale entries that waste storage and confuse logic.

### Patterns

#### Pattern 1: Object Size Limits
On Sui, objects have a ~256KB size limit. Verify no vector/table within a shared object can grow past this. On Aptos, verify global storage doesn't grow unbounded.

**Vulnerable:**
```move
// Orders never cleaned up -- will hit 256KB limit on Sui
struct OrderBook has key {
    id: UID,
    orders: vector<Order>  // Grows forever
}

public entry fun place_order(book: &mut OrderBook, order: Order) {
    vector::push_back(&mut book.orders, order);
    // No mechanism to remove filled/cancelled orders
}
```

**Fixed:**
```move
// Cleanup mechanism for filled orders
public entry fun cleanup_filled_orders(book: &mut OrderBook) {
    let i = vector::length(&book.orders);
    while (i > 0) {
        i = i - 1;
        if (vector::borrow(&book.orders, i).filled) {
            vector::swap_remove(&mut book.orders, i);
        };
    };
}
```

#### Pattern 2: Missing Cleanup
Are entries ever removed from collections? If add-only with no remove/prune, the structure grows forever.

**Vulnerable:**
```move
// Positions are created but never removed after closing
struct Vault has key {
    id: UID,
    positions: Table<address, vector<Position>>
}

public entry fun close_position(vault: &mut Vault, ctx: &TxContext) {
    let positions = table::borrow_mut(&mut vault.positions, tx_context::sender(ctx));
    let pos = vector::pop_back(positions);
    settle(pos);
    // Empty vectors remain in the table -- stale entries accumulate
}
```

**Fixed:**
```move
public entry fun close_position(vault: &mut Vault, ctx: &TxContext) {
    let sender = tx_context::sender(ctx);
    let positions = table::borrow_mut(&mut vault.positions, sender);
    let pos = vector::pop_back(positions);
    settle(pos);
    // Remove table entry when no positions remain
    if (vector::is_empty(positions)) {
        table::remove(&mut vault.positions, sender);
    };
}
```

#### Pattern 3: Stale State
After entities are logically deleted or expired, are their entries removed from all data structures? Stale entries waste storage and may cause logic errors.

**Vulnerable:**
```move
// Proposal marked inactive but not removed from active list
public entry fun cancel_proposal(gov: &mut Governance, id: u64) {
    let proposal = table::borrow_mut(&mut gov.proposals, id);
    proposal.active = false;
    // Still in active_ids vector -- iterated every vote cycle
}
```

**Fixed:**
```move
public entry fun cancel_proposal(gov: &mut Governance, id: u64) {
    let proposal = table::borrow_mut(&mut gov.proposals, id);
    proposal.active = false;
    // Remove from active list
    let (found, idx) = vector::index_of(&gov.active_ids, &id);
    if (found) {
        vector::swap_remove(&mut gov.active_ids, idx);
    };
}
```

#### Pattern 4: Event Emission Limits
On Sui, excessive event emission per transaction can hit limits. Verify batch operations don't emit unbounded events.

**Vulnerable:**
```move
// Emits one event per item -- unbounded if vector is large
public entry fun process_all(items: &mut vector<Item>) {
    let i = 0;
    while (i < vector::length(items)) {
        process(vector::borrow_mut(items, i));
        event::emit(ItemProcessed { index: i });
        i = i + 1;
    };
}
```

**Fixed:**
```move
// Single summary event for the batch
public entry fun process_all(items: &mut vector<Item>) {
    let count = vector::length(items);
    let i = 0;
    while (i < count) {
        process(vector::borrow_mut(items, i));
        i = i + 1;
    };
    event::emit(BatchProcessed { count });
}
```

#### Pattern 5: Ghost Entries
Entries that are logically invalid but never physically removed from maps/tables, accumulating over time and inflating storage costs.

**Vulnerable:**
```move
// Expired listings remain in the table
public fun is_valid_listing(market: &Market, id: u64, clock: &Clock): bool {
    let listing = table::borrow(&market.listings, id);
    listing.expiry > clock::timestamp_ms(clock)
    // Expired listings are never removed -- ghost entries
}
```

**Fixed:**
```move
// Remove expired listing on access
public fun get_listing(market: &mut Market, id: u64, clock: &Clock): &Listing {
    let listing = table::borrow(&market.listings, id);
    if (listing.expiry <= clock::timestamp_ms(clock)) {
        table::remove(&mut market.listings, id);
        abort EListingExpired
    };
    table::borrow(&market.listings, id)
}
```

### Remediation
Implement cleanup/pruning functions, use expiration-based eviction, cap collection sizes, archive old entries off-chain, and monitor object sizes.

### Signature
**Slug:** `storage-growth-invariant->state-bloat-dos`
**Detect:** For every dynamically growing data structure: (1) verify a cleanup/removal mechanism exists, (2) verify object size won't exceed platform limits, (3) check for stale/ghost entries after logical deletion, (4) verify event emission is bounded per transaction.
**What's Wrong:** On-chain data structures grow without bounds or cleanup, eventually causing DoS via size limits, escalating gas costs, or stale state corruption.
**Remediation:** Implement pruning, expiration-based eviction, size caps, and cleanup functions for all growing collections.

---

## CL-GAS-02: Hash Collision DoS

**Rule:** `MOVE-GAS-HASH-01`
**Severity:** Low

### Description
Protocols using hash-based data structures (like `sui::table` or custom hash maps) must ensure that the hash function is collision-resistant and that bucket overflows are handled gracefully. Predictable hashing allows attackers to cluster entries into a single bucket, causing transaction aborts.

### Patterns

#### Pattern 1: Hash-Based Collection with User-Provided Keys
Usage of hash-based collections where keys are directly derived from user input. An attacker who can predict the hash function can craft keys that all map to the same bucket.

**Vulnerable:**
```move
use sui::table::{Self, Table};

struct Registry has key {
    id: UID,
    data: Table<address, u64>
}

public entry fun add_entry(reg: &mut Registry, val: u64, ctx: &mut TxContext) {
    // If custom hash logic is used underneath, clustering can cause DoS
    table::add(&mut reg.data, tx_context::sender(ctx), val);
}
```

**Fixed:**
```move
use sui::table::{Self, Table};

// Use Table with collision-resistant key derivation
struct Registry has key {
    id: UID,
    data: Table<address, u64>
}

public entry fun add_entry(reg: &mut Registry, val: u64, ctx: &mut TxContext) {
    table::add(&mut reg.data, tx_context::sender(ctx), val);
}
```

#### Pattern 2: Custom Hash Maps with Weak Hashing
Custom hash-map implementations using simple modular arithmetic or predictable hash functions that are vulnerable to pre-image attacks.

**Vulnerable:**
```move
// Weak bucket assignment -- trivially predictable
fun get_bucket(key: u64, num_buckets: u64): u64 {
    key % num_buckets
}
```

**Fixed:**
```move
// Use cryptographic hash for bucket assignment
fun get_bucket(key: u64, num_buckets: u64): u64 {
    let hash = hash::sha3_256(bcs::to_bytes(&key));
    let bucket_seed = ((*vector::borrow(&hash, 0) as u64) << 8) | (*vector::borrow(&hash, 1) as u64);
    bucket_seed % num_buckets
}
```

### Remediation
Use collision-resistant hash functions, implement bucket size limits with graceful degradation, or transition to data structures that handle collisions more robustly (like `sui::table::Table` or object-per-entry patterns).

### Signature
**Slug:** `hash-collision->dos`
**Detect:** Identify usage of custom hash-maps or hash-based collections where keys are user-provided. Check if the hash function is susceptible to pre-image/collision attacks that could saturate specific storage buckets.
**What's Wrong:** Predictable hashing allows attackers to cluster entries into a single storage bucket, causing the Move VM to abort due to gas limits or internal bucket constraints.
**Remediation:** Ensure the underlying storage structure is resilient to clustering or use a more distributed storage pattern like object-per-entry or `sui::table::Table`.

---

## CL-GAS-03: Unbounded Iteration

**Rule:** `MOVE-GAS-LOOP-01`
**Severity:** Medium-Critical

### Description
The protocol must ensure that every loop in the codebase has bounded iteration counts, pagination, or early termination. Loops over dynamically growing collections or unbounded ranges without safeguards cause gas exhaustion and denial of service on critical functions.

### Patterns

#### Pattern 1: Vector/Collection Iteration
Functions that loop over vectors, tables, or linked lists whose length grows with user actions (deposits, registrations, rewards). Verify the collection has a size cap or the function uses pagination.

**Vulnerable:**
```move
// Unbounded reward distribution over growing staker list
public entry fun distribute_rewards(pool: &mut Pool) {
    let i = 0;
    let len = vector::length(&pool.stakers);
    while (i < len) {
        let staker = vector::borrow(&pool.stakers, i);
        send_reward(staker);
        i = i + 1;
    };
    // If stakers grows to thousands, this will exceed gas limit
}
```

**Fixed:**
```move
// Paginated distribution with batch size
public entry fun distribute_rewards(pool: &mut Pool, start: u64, batch_size: u64) {
    let len = vector::length(&pool.stakers);
    let end = math::min(start + batch_size, len);
    let i = start;
    while (i < end) {
        let staker = vector::borrow(&pool.stakers, i);
        send_reward(staker);
        i = i + 1;
    };
}
```

#### Pattern 2: Permissionless Accumulation
Can any user add entries to a collection that is later iterated by a critical function? If so, an attacker can grief the protocol by bloating the collection.

**Vulnerable:**
```move
// Anyone can register, bloating the list iterated by settle()
public entry fun register(pool: &mut Pool, ctx: &mut TxContext) {
    vector::push_back(&mut pool.participants, tx_context::sender(ctx));
    // No cap on participants
}

public entry fun settle(pool: &mut Pool) {
    let i = 0;
    while (i < vector::length(&pool.participants)) {
        pay_out(vector::borrow(&pool.participants, i));
        i = i + 1;
    };
}
```

**Fixed:**
```move
// Capped registration with max participants
const MAX_PARTICIPANTS: u64 = 500;

public entry fun register(pool: &mut Pool, ctx: &mut TxContext) {
    assert!(vector::length(&pool.participants) < MAX_PARTICIPANTS, ETooManyParticipants);
    vector::push_back(&mut pool.participants, tx_context::sender(ctx));
}
```

#### Pattern 3: Epoch/Time Range Iteration
Loops that iterate from a stored timestamp/epoch to the current one. If the function hasn't been called in a long time, the range can be enormous.

**Vulnerable:**
```move
// Iterates every epoch since last update -- unbounded if stale
public fun accrue_interest(pool: &mut Pool, clock: &Clock) {
    let current_epoch = clock::epoch(clock);
    while (pool.last_epoch < current_epoch) {
        pool.accumulated = pool.accumulated + compute_rate(pool.last_epoch);
        pool.last_epoch = pool.last_epoch + 1;
    };
}
```

**Fixed:**
```move
// Capped catch-up with max epochs per call
const MAX_EPOCHS_PER_CALL: u64 = 100;

public fun accrue_interest(pool: &mut Pool, clock: &Clock) {
    let current_epoch = clock::epoch(clock);
    let target = math::min(pool.last_epoch + MAX_EPOCHS_PER_CALL, current_epoch);
    while (pool.last_epoch < target) {
        pool.accumulated = pool.accumulated + compute_rate(pool.last_epoch);
        pool.last_epoch = pool.last_epoch + 1;
    };
}
```

#### Pattern 4: Linear Search in Loops
Using vector::contains or manual iteration to find an element. Should use Table/Bag for O(1) lookup instead.

**Vulnerable:**
```move
// O(n) lookup in a growing vector
public fun is_whitelisted(list: &vector<address>, addr: address): bool {
    let i = 0;
    while (i < vector::length(list)) {
        if (*vector::borrow(list, i) == addr) {
            return true
        };
        i = i + 1;
    };
    false
}
```

**Fixed:**
```move
// O(1) lookup using Table
struct Whitelist has key {
    id: UID,
    members: Table<address, bool>
}

public fun is_whitelisted(list: &Whitelist, addr: address): bool {
    table::contains(&list.members, addr)
}
```

#### Pattern 5: Loop Control Flow Defects
Loop constructs where the index variable is not incremented in all paths (causing infinite loops) or where iteration continues after the result is determined (wasting gas by not breaking/returning early).

**Vulnerable:**
```move
// Missing increment on else branch -- infinite loop
public fun find_active(items: &vector<Item>): u64 {
    let i = 0;
    while (i < vector::length(items)) {
        if (vector::borrow(items, i).active) {
            return i
        };
        // BUG: i not incremented when item is not active
    };
    abort ENotFound
}

// No early termination -- keeps iterating after answer found
public fun has_expired(entries: &vector<Entry>, clock: &Clock): bool {
    let i = 0;
    let found = false;
    while (i < vector::length(entries)) {
        if (vector::borrow(entries, i).expiry < clock::timestamp_ms(clock)) {
            found = true;
            // Does not break, iterates remaining entries wastefully
        };
        i = i + 1;
    };
    found
}
```

**Fixed:**
```move
// Correct increment on all paths
public fun find_active(items: &vector<Item>): u64 {
    let i = 0;
    while (i < vector::length(items)) {
        if (vector::borrow(items, i).active) {
            return i
        };
        i = i + 1;
    };
    abort ENotFound
}

// Early return once result is determined
public fun has_expired(entries: &vector<Entry>, clock: &Clock): bool {
    let i = 0;
    while (i < vector::length(entries)) {
        if (vector::borrow(entries, i).expiry < clock::timestamp_ms(clock)) {
            return true
        };
        i = i + 1;
    };
    false
}
```

### Remediation
Implement pagination (process N items per call), cap collection sizes, use lazy evaluation patterns, use O(1) data structures for lookups, ensure all loop paths increment the iterator, and break/return early once a result is determined.

### Signature
**Slug:** `unbounded-iteration-invariant->gas-exhaustion-dos`
**Detect:** For every loop in the codebase: (1) identify what determines the iteration count, (2) verify it has a cap, pagination, or is bounded by a constant, (3) check if external users can grow the iterated collection, (4) check for missing increments or missing early termination.
**What's Wrong:** Loops iterate over unbounded or user-growable collections without pagination or caps, causing gas exhaustion on critical functions.
**Remediation:** Implement pagination, cap collection sizes, use O(1) data structures for lookups, and ensure all loop paths increment the iterator.

---

## CL-GAS-04: Redundant Code / Gas Waste

**Rule:** `MOVE-GAS-REDUN-01`
**Severity:** Informational-Low

### Description
The codebase must not contain redundant operations, dead code, unused declarations, tautological checks, or inefficient patterns that increase gas consumption without contributing to protocol functionality.

### Patterns

#### Pattern 1: Redundant State Operations
Writing the same value back without change, borrowing global state multiple times when once suffices, or extracting and re-merging resources without modification.

**Vulnerable:**
```move
// Writes even if value unchanged -- wastes gas on storage write
public entry fun update_fee(_: &AdminCap, config: &mut Config, new_fee: u64) {
    config.fee = new_fee;
}
```

**Fixed:**
```move
// Skip write if unchanged
public entry fun update_fee(_: &AdminCap, config: &mut Config, new_fee: u64) {
    if (config.fee != new_fee) {
        config.fee = new_fee;
    };
}
```

#### Pattern 2: Dead Code
Unused functions, constants, struct fields, module imports, or function parameters that should be prefixed with `_`.

**Vulnerable:**
```move
// Unused parameter and unused constant
const LEGACY_FEE: u64 = 100; // Never referenced

public fun calculate(amount: u64, unused_flag: bool): u64 {
    amount * 2
    // unused_flag is never read
}
```

**Fixed:**
```move
public fun calculate(amount: u64, _unused_flag: bool): u64 {
    amount * 2
}
// Remove LEGACY_FEE constant entirely
```

#### Pattern 3: Tautological / Redundant Checks
Assertions that are always true (e.g., checking x >= 0 for unsigned), boolean comparisons, or assertions duplicating checks already done by called functions.

**Vulnerable:**
```move
// Tautological: u64 is always >= 0
public fun deposit(amount: u64) {
    assert!(amount >= 0, EInvalidAmount);
    // Redundant: coin::value already asserts non-zero internally
    assert!(amount > 0, EZeroAmount);
    do_deposit(amount);
}
```

**Fixed:**
```move
public fun deposit(amount: u64) {
    assert!(amount > 0, EZeroAmount);
    do_deposit(amount);
}
```

### Remediation
Remove dead code, eliminate redundant operations, add equality checks before state writes, and eliminate tautological assertions.

### Signature
**Slug:** `redundant-code-invariant->gas-waste`
**Detect:** Scan for: (1) state writes without equality pre-check, (2) unused functions/constants/parameters/imports, (3) tautological assertions or redundant checks.
**What's Wrong:** Codebase contains redundant operations, dead code, or tautological checks that waste gas.
**Remediation:** Remove dead code, add equality checks before state writes, eliminate tautological assertions.
