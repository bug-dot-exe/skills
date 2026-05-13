# CAT-GEN: General Safety

**Context:** `ctx:generic`
**Detectors:** 9

## CL-GEN-01: Error Handling Invariant

**Rule:** `MOVE-GEN-ABORT-01`
**Severity:** informational-low

## Precondition
The module uses `assert!` or `abort` with numeric error codes across multiple functions.

## Root Cause
Error codes are duplicated across assertions within or across functions, making it impossible to determine which condition caused a transaction abort.

## Impact
Duplicate error codes make debugging impossible — when a transaction aborts, the error code cannot pinpoint which specific assertion failed.

## Remediation
Use unique named error code constants for every assertion across the module.

---

## Pattern 1: Duplicate Error Codes

Multiple `assert!` statements use the same numeric error code, making it impossible to determine which condition failed when a transaction aborts.

### Vulnerable
```move
module example::marketplace {
    use std::signer;

    struct Listing has key {
        seller: address,
        price: u64,
        active: bool,
    }

    public entry fun purchase(buyer: &signer, listing_addr: address) acquires Listing {
        let buyer_addr = signer::address_of(buyer);
        let listing = borrow_global_mut<Listing>(listing_addr);
        // BUG: All three assertions use error code 1
        // When tx aborts with code 1, impossible to know which check failed
        assert!(listing.active, 1);
        assert!(buyer_addr != listing.seller, 1);
        assert!(listing.price > 0, 1);
        listing.active = false;
    }

    public entry fun cancel(seller: &signer, listing_addr: address) acquires Listing {
        let listing = borrow_global_mut<Listing>(listing_addr);
        // BUG: Same error code 1 as purchase — even across functions
        assert!(signer::address_of(seller) == listing.seller, 1);
        assert!(listing.active, 1);
        listing.active = false;
    }
}
```

### Fixed
```move
module example::marketplace {
    use std::signer;

    struct Listing has key {
        seller: address,
        price: u64,
        active: bool,
    }

    const E_LISTING_NOT_ACTIVE: u64 = 1;
    const E_BUYER_IS_SELLER: u64 = 2;
    const E_ZERO_PRICE: u64 = 3;
    const E_NOT_SELLER: u64 = 4;

    public entry fun purchase(buyer: &signer, listing_addr: address) acquires Listing {
        let buyer_addr = signer::address_of(buyer);
        let listing = borrow_global_mut<Listing>(listing_addr);
        // Each assertion has a unique, descriptive error code
        assert!(listing.active, E_LISTING_NOT_ACTIVE);
        assert!(buyer_addr != listing.seller, E_BUYER_IS_SELLER);
        assert!(listing.price > 0, E_ZERO_PRICE);
        listing.active = false;
    }

    public entry fun cancel(seller: &signer, listing_addr: address) acquires Listing {
        let listing = borrow_global_mut<Listing>(listing_addr);
        assert!(signer::address_of(seller) == listing.seller, E_NOT_SELLER);
        assert!(listing.active, E_LISTING_NOT_ACTIVE);
        listing.active = false;
    }
}
```

---

## Signature
**Slug:** `improper-abort-->unexpected-halt`
**Detect:** For every module: verify all error codes are unique across all `assert!` and `abort` statements.
**What's Wrong:** Multiple assertions share the same error code, making it impossible to identify which check failed.
**Remediation:** Use unique named error code constants for every assertion across the module.

---

## CL-GEN-02: Data Structure Invariant

**Rule:** `MOVE-GEN-DATA-01`
**Severity:** low-high

## Precondition
The module uses vectors, tables, or other collection types to store dynamic data that grows based on user interaction.

## Root Cause
Collections grow without bounds, indices are accessed without validation, keys collide on insertion, order-dependent logic uses unordered removal, or correlated collections are not kept in sync on deletion.

## Impact
Unbounded growth causes gas exhaustion and denial of service on iteration. Out-of-bounds access aborts transactions. Key collisions silently overwrite data. Unordered removal breaks index-based references. Stale entries in correlated collections cause phantom data and incorrect lookups.

## Remediation
Cap vector lengths. Validate indices before access. Check key existence before table insertion. Use indexed removal only when order is irrelevant. Clean up all correlated collections on deletion.

---

## Pattern 1: Unbounded Vector Growth

A vector grows with each user action without any length cap, eventually causing gas exhaustion when the vector is iterated.

### Vulnerable
```move
module example::whitelist {
    use std::signer;
    use std::vector;

    struct Whitelist has key {
        addresses: vector<address>,
    }

    public entry fun add_to_whitelist(admin: &signer, addr: address) acquires Whitelist {
        let wl = borrow_global_mut<Whitelist>(@example);
        // BUG: No length cap — vector grows indefinitely
        // Any function that iterates over this vector will eventually exceed gas limits
        vector::push_back(&mut wl.addresses, addr);
    }

    public fun is_whitelisted(addr: address): bool acquires Whitelist {
        let wl = borrow_global<Whitelist>(@example);
        // This iteration becomes prohibitively expensive as the vector grows
        vector::contains(&wl.addresses, &addr)
    }
}
```

### Fixed
```move
module example::whitelist {
    use std::signer;
    use std::vector;
    use aptos_std::table::{Self, Table};

    const MAX_WHITELIST_SIZE: u64 = 1000;
    const E_WHITELIST_FULL: u64 = 1;

    struct Whitelist has key {
        addresses: Table<address, bool>,
        count: u64,
    }

    public entry fun add_to_whitelist(admin: &signer, addr: address) acquires Whitelist {
        let wl = borrow_global_mut<Whitelist>(@example);
        assert!(wl.count < MAX_WHITELIST_SIZE, E_WHITELIST_FULL);
        if (!table::contains(&wl.addresses, addr)) {
            table::add(&mut wl.addresses, addr, true);
            wl.count = wl.count + 1;
        };
    }

    public fun is_whitelisted(addr: address): bool acquires Whitelist {
        let wl = borrow_global<Whitelist>(@example);
        table::contains(&wl.addresses, addr)
    }
}
```

---

## Pattern 2: Vector Index Out of Bounds

Accessing a vector element by index without checking that the index is within the valid range causes the transaction to abort.

### Vulnerable
```move
module example::queue {
    use std::vector;

    struct TaskQueue has key {
        tasks: vector<Task>,
    }

    struct Task has store, drop {
        id: u64,
        priority: u8,
    }

    public fun get_task(queue: &TaskQueue, index: u64): (u64, u8) {
        // BUG: No bounds check — aborts if index >= vector length
        let task = vector::borrow(&queue.tasks, index);
        (task.id, task.priority)
    }

    public fun remove_task(queue: &mut TaskQueue, index: u64): Task {
        // BUG: No bounds check before swap_remove
        vector::swap_remove(&mut queue.tasks, index)
    }
}
```

### Fixed
```move
module example::queue {
    use std::vector;

    struct TaskQueue has key {
        tasks: vector<Task>,
    }

    struct Task has store, drop {
        id: u64,
        priority: u8,
    }

    const E_INDEX_OUT_OF_BOUNDS: u64 = 1;

    public fun get_task(queue: &TaskQueue, index: u64): (u64, u8) {
        assert!(index < vector::length(&queue.tasks), E_INDEX_OUT_OF_BOUNDS);
        let task = vector::borrow(&queue.tasks, index);
        (task.id, task.priority)
    }

    public fun remove_task(queue: &mut TaskQueue, index: u64): Task {
        assert!(index < vector::length(&queue.tasks), E_INDEX_OUT_OF_BOUNDS);
        vector::swap_remove(&mut queue.tasks, index)
    }
}
```

---

## Pattern 3: Table Key Collision

Calling `table::add` without first checking if the key already exists causes an abort when a duplicate key is inserted.

### Vulnerable
```move
module example::accounts {
    use std::signer;
    use aptos_std::table::{Self, Table};

    struct AccountBook has key {
        records: Table<address, AccountRecord>,
    }

    struct AccountRecord has store, drop {
        balance: u64,
        created_at: u64,
    }

    public entry fun create_account(
        user: &signer,
        initial_balance: u64,
        timestamp: u64
    ) acquires AccountBook {
        let addr = signer::address_of(user);
        let book = borrow_global_mut<AccountBook>(@example);
        // BUG: Aborts if user already has a record — table::add fails on existing key
        table::add(&mut book.records, addr, AccountRecord {
            balance: initial_balance,
            created_at: timestamp,
        });
    }
}
```

### Fixed
```move
module example::accounts {
    use std::signer;
    use aptos_std::table::{Self, Table};

    struct AccountBook has key {
        records: Table<address, AccountRecord>,
    }

    struct AccountRecord has store, drop {
        balance: u64,
        created_at: u64,
    }

    const E_ACCOUNT_EXISTS: u64 = 1;

    public entry fun create_account(
        user: &signer,
        initial_balance: u64,
        timestamp: u64
    ) acquires AccountBook {
        let addr = signer::address_of(user);
        let book = borrow_global_mut<AccountBook>(@example);
        // Check before add to prevent collision abort
        assert!(!table::contains(&book.records, addr), E_ACCOUNT_EXISTS);
        table::add(&mut book.records, addr, AccountRecord {
            balance: initial_balance,
            created_at: timestamp,
        });
    }
}
```

---

## Pattern 4: Swap-Remove Order Dependency

Using `vector::swap_remove` on a vector where element order matters breaks external index-based references, since swap_remove moves the last element into the removed position.

### Vulnerable
```move
module example::auction {
    use std::vector;

    struct AuctionHouse has key {
        bids: vector<Bid>,
    }

    struct Bid has store, drop {
        bidder: address,
        amount: u64,
    }

    struct BidReceipt has key {
        bid_index: u64, // References position in bids vector
    }

    public fun cancel_bid(house: &mut AuctionHouse, index: u64) {
        // BUG: swap_remove changes the position of the last element
        // Any BidReceipt pointing to the last index now references wrong bid
        // Any BidReceipt pointing to `index` is now stale
        vector::swap_remove(&mut house.bids, index);
    }

    public fun get_bid_amount(house: &AuctionHouse, index: u64): u64 {
        // After swap_remove, this returns the wrong bid for affected indices
        vector::borrow(&house.bids, index).amount
    }
}
```

### Fixed
```move
module example::auction {
    use std::vector;
    use aptos_std::table::{Self, Table};

    struct AuctionHouse has key {
        bids: Table<u64, Bid>,
        next_bid_id: u64,
    }

    struct Bid has store, drop {
        bidder: address,
        amount: u64,
    }

    struct BidReceipt has key {
        bid_id: u64, // References stable ID, not position
    }

    public fun cancel_bid(house: &mut AuctionHouse, bid_id: u64) {
        // Table removal does not affect other entries
        table::remove(&mut house.bids, bid_id);
    }

    public fun get_bid_amount(house: &AuctionHouse, bid_id: u64): u64 {
        table::borrow(&house.bids, bid_id).amount
    }
}
```

---

## Pattern 5: Missing Table Entry Cleanup

Removing an entry from one collection but leaving stale entries in a correlated collection, causing phantom lookups and inconsistent state.

### Vulnerable
```move
module example::dao {
    use std::signer;
    use std::vector;
    use aptos_std::table::{Self, Table};

    struct DAO has key {
        proposals: Table<u64, Proposal>,
        proposal_ids: vector<u64>,
        vote_counts: Table<u64, u64>,
    }

    struct Proposal has store, drop {
        title: vector<u8>,
        creator: address,
    }

    public fun delete_proposal(dao: &mut DAO, proposal_id: u64) {
        // Removes from proposals table
        table::remove(&mut dao.proposals, proposal_id);
        // BUG: proposal_ids vector still contains the ID
        // BUG: vote_counts table still has the entry
        // Iteration over proposal_ids will try to look up deleted proposals
    }
}
```

### Fixed
```move
module example::dao {
    use std::signer;
    use std::vector;
    use aptos_std::table::{Self, Table};

    struct DAO has key {
        proposals: Table<u64, Proposal>,
        proposal_ids: vector<u64>,
        vote_counts: Table<u64, u64>,
    }

    struct Proposal has store, drop {
        title: vector<u8>,
        creator: address,
    }

    public fun delete_proposal(dao: &mut DAO, proposal_id: u64) {
        // Remove from all correlated collections
        table::remove(&mut dao.proposals, proposal_id);

        let (found, idx) = vector::index_of(&dao.proposal_ids, &proposal_id);
        if (found) {
            vector::swap_remove(&mut dao.proposal_ids, idx);
        };

        if (table::contains(&dao.vote_counts, proposal_id)) {
            table::remove(&mut dao.vote_counts, proposal_id);
        };
    }
}
```

---

## Signature
**Slug:** `data-structure-misuse-->corruption`
**Detect:** For every collection operation: (1) verify vectors have growth caps or use bounded alternatives, (2) verify index access is bounds-checked, (3) verify table insertions check for existing keys, (4) verify swap_remove is not used when order matters, (5) verify correlated collections are cleaned up together.
**What's Wrong:** One or more collection operations allow unbounded growth, access unchecked indices, collide on key insertion, break order invariants via swap_remove, or leave stale entries in correlated collections.
**Remediation:** Cap vector lengths. Validate indices before access. Check key existence before table insertion. Use indexed removal only when order is irrelevant. Clean up all correlated collections on deletion.

## Classification Reasoning
This invariant detector consolidates all data-structure-related patterns into a single comprehensive check. Collection misuse issues are universal across Move modules and represent a spectrum of the same fundamental concern: ensuring data structures maintain their integrity invariants throughout their lifecycle. The five patterns cover the primary ways vectors and tables can be misused in Move programs.

---

## CL-GEN-03: Event Emission Invariant

**Rule:** `MOVE-GEN-EVT-01`
**Severity:** informational-low

## Precondition
The module modifies state (resource writes, coin transfers, role changes) in functions that should be observable by off-chain systems.

## Root Cause
Events are missing, use wrong parameters, lack proper handle registration, capture pre-update state, or are absent from some execution paths.

## Impact
Off-chain indexers, explorers, monitoring bots, and front-ends receive incomplete or incorrect data, leading to state desynchronization, broken UIs, missed alerts, and inability to reconstruct on-chain history.

## Remediation
Emit events for all state changes. Use post-mutation values. Register event handles in `init_module`. Ensure event struct fields match recorded data. Cover all conditional branches with event emission.

---

## Pattern 1: Missing Event Emission on State Change

A state-modifying function has no `event::emit_event` call. Critical for off-chain indexing, monitoring, and governance transparency.

### Vulnerable
```move
module example::config {
    use std::signer;

    struct Config has key {
        admin: address,
        fee_bps: u64,
        paused: bool,
    }

    public entry fun update_fee(admin: &signer, new_fee: u64) acquires Config {
        let config = borrow_global_mut<Config>(@example);
        // BUG: No event emitted — off-chain systems cannot detect fee changes
        config.fee_bps = new_fee;
    }

    public entry fun set_paused(admin: &signer, paused: bool) acquires Config {
        let config = borrow_global_mut<Config>(@example);
        // BUG: No event emitted — pause state change is invisible
        config.paused = paused;
    }
}
```

### Fixed
```move
module example::config {
    use std::signer;
    use aptos_framework::event;

    struct Config has key {
        admin: address,
        fee_bps: u64,
        paused: bool,
    }

    #[event]
    struct FeeUpdatedEvent has drop, store {
        old_fee: u64,
        new_fee: u64,
    }

    #[event]
    struct PauseStateChanged has drop, store {
        paused: bool,
    }

    public entry fun update_fee(admin: &signer, new_fee: u64) acquires Config {
        let config = borrow_global_mut<Config>(@example);
        let old_fee = config.fee_bps;
        config.fee_bps = new_fee;
        event::emit(FeeUpdatedEvent { old_fee, new_fee });
    }

    public entry fun set_paused(admin: &signer, paused: bool) acquires Config {
        let config = borrow_global_mut<Config>(@example);
        config.paused = paused;
        event::emit(PauseStateChanged { paused });
    }
}
```

---

## Pattern 2: Event Emitted with Pre-Mutation Values

Event is fired before the state mutation or uses values captured before the update, so it logs stale data rather than the actual post-change state.

### Vulnerable
```move
module example::staking {
    use std::signer;
    use aptos_framework::event;

    struct StakePool has key {
        total_staked: u64,
    }

    struct UserStake has key {
        amount: u64,
    }

    #[event]
    struct StakeEvent has drop, store {
        user: address,
        total_staked: u64,
        user_balance: u64,
    }

    public entry fun stake(user: &signer, amount: u64) acquires StakePool, UserStake {
        let addr = signer::address_of(user);
        let pool = borrow_global_mut<StakePool>(@example);
        let user_stake = borrow_global_mut<UserStake>(addr);

        // BUG: Event emitted with pre-mutation values
        event::emit(StakeEvent {
            user: addr,
            total_staked: pool.total_staked,
            user_balance: user_stake.amount,
        });

        pool.total_staked = pool.total_staked + amount;
        user_stake.amount = user_stake.amount + amount;
    }
}
```

### Fixed
```move
module example::staking {
    use std::signer;
    use aptos_framework::event;

    struct StakePool has key {
        total_staked: u64,
    }

    struct UserStake has key {
        amount: u64,
    }

    #[event]
    struct StakeEvent has drop, store {
        user: address,
        total_staked: u64,
        user_balance: u64,
    }

    public entry fun stake(user: &signer, amount: u64) acquires StakePool, UserStake {
        let addr = signer::address_of(user);
        let pool = borrow_global_mut<StakePool>(@example);
        let user_stake = borrow_global_mut<UserStake>(addr);

        // Mutate state first
        pool.total_staked = pool.total_staked + amount;
        user_stake.amount = user_stake.amount + amount;

        // Event emitted with post-mutation values
        event::emit(StakeEvent {
            user: addr,
            total_staked: pool.total_staked,
            user_balance: user_stake.amount,
        });
    }
}
```

---

## Pattern 3: Missing Event Handle Registration

Using the legacy `EventHandle`-based API without registering the handle in `init_module`, causing event emission to abort at runtime.

### Vulnerable
```move
module example::marketplace {
    use std::signer;
    use aptos_framework::event::{Self, EventHandle};
    use aptos_framework::account;

    struct MarketEvents has key {
        listing_events: EventHandle<ListingEvent>,
    }

    struct ListingEvent has drop, store {
        seller: address,
        price: u64,
    }

    // BUG: No init_module to register EventHandle
    // MarketEvents resource is never created

    public entry fun create_listing(seller: &signer, price: u64) acquires MarketEvents {
        // Aborts because MarketEvents doesn't exist at @example
        let events = borrow_global_mut<MarketEvents>(@example);
        event::emit_event(&mut events.listing_events, ListingEvent {
            seller: signer::address_of(seller),
            price,
        });
    }
}
```

### Fixed
```move
module example::marketplace {
    use std::signer;
    use aptos_framework::event::{Self, EventHandle};
    use aptos_framework::account;

    struct MarketEvents has key {
        listing_events: EventHandle<ListingEvent>,
    }

    struct ListingEvent has drop, store {
        seller: address,
        price: u64,
    }

    // Event handle registered during module initialization
    fun init_module(deployer: &signer) {
        move_to(deployer, MarketEvents {
            listing_events: account::new_event_handle<ListingEvent>(deployer),
        });
    }

    public entry fun create_listing(seller: &signer, price: u64) acquires MarketEvents {
        let events = borrow_global_mut<MarketEvents>(@example);
        event::emit_event(&mut events.listing_events, ListingEvent {
            seller: signer::address_of(seller),
            price,
        });
    }
}
```

---

## Pattern 4: Inconsistent Event Fields

Event struct fields do not match the actual data being recorded, either due to missing fields, wrong field types, or fields that do not capture the full context of the operation.

### Vulnerable
```move
module example::swap {
    use std::signer;
    use aptos_framework::event;

    #[event]
    struct SwapEvent has drop, store {
        user: address,
        amount_in: u64,
        // BUG: Missing amount_out — cannot determine swap result
        // BUG: Missing token types — cannot identify which pair was swapped
    }

    public entry fun swap(
        user: &signer,
        amount_in: u64,
        min_out: u64
    ) {
        let addr = signer::address_of(user);
        let amount_out = calculate_output(amount_in);

        // Event does not capture the output amount or token types
        event::emit(SwapEvent {
            user: addr,
            amount_in,
        });
    }

    fun calculate_output(amount_in: u64): u64 { amount_in * 997 / 1000 }
}
```

### Fixed
```move
module example::swap {
    use std::signer;
    use std::string::String;
    use aptos_framework::event;

    #[event]
    struct SwapEvent has drop, store {
        user: address,
        token_in: String,
        token_out: String,
        amount_in: u64,
        amount_out: u64,
        fee: u64,
    }

    public entry fun swap(
        user: &signer,
        amount_in: u64,
        min_out: u64
    ) {
        let addr = signer::address_of(user);
        let fee = amount_in * 3 / 1000;
        let amount_out = calculate_output(amount_in);

        // Event captures all relevant swap details
        event::emit(SwapEvent {
            user: addr,
            token_in: std::string::utf8(b"APT"),
            token_out: std::string::utf8(b"USDC"),
            amount_in,
            amount_out,
            fee,
        });
    }

    fun calculate_output(amount_in: u64): u64 { amount_in * 997 / 1000 }
}
```

---

## Pattern 5: Missing Events in Conditional Branches

Event emitted on one code path but not another that also modifies state, leaving some operations invisible to off-chain observers.

### Vulnerable
```move
module example::rewards {
    use std::signer;
    use aptos_framework::event;

    struct RewardPool has key {
        balance: u64,
        distributed: u64,
    }

    #[event]
    struct RewardClaimed has drop, store {
        user: address,
        amount: u64,
    }

    public entry fun claim_reward(user: &signer, amount: u64) acquires RewardPool {
        let addr = signer::address_of(user);
        let pool = borrow_global_mut<RewardPool>(@example);

        if (amount > pool.balance) {
            // Partial claim — gives whatever is left
            let remaining = pool.balance;
            pool.balance = 0;
            pool.distributed = pool.distributed + remaining;
            // BUG: No event emitted on partial claim path
        } else {
            pool.balance = pool.balance - amount;
            pool.distributed = pool.distributed + amount;
            event::emit(RewardClaimed { user: addr, amount });
        };
    }
}
```

### Fixed
```move
module example::rewards {
    use std::signer;
    use aptos_framework::event;

    struct RewardPool has key {
        balance: u64,
        distributed: u64,
    }

    #[event]
    struct RewardClaimed has drop, store {
        user: address,
        amount: u64,
        partial: bool,
    }

    public entry fun claim_reward(user: &signer, amount: u64) acquires RewardPool {
        let addr = signer::address_of(user);
        let pool = borrow_global_mut<RewardPool>(@example);

        if (amount > pool.balance) {
            let remaining = pool.balance;
            pool.balance = 0;
            pool.distributed = pool.distributed + remaining;
            // Event emitted on partial claim path too
            event::emit(RewardClaimed { user: addr, amount: remaining, partial: true });
        } else {
            pool.balance = pool.balance - amount;
            pool.distributed = pool.distributed + amount;
            event::emit(RewardClaimed { user: addr, amount, partial: false });
        };
    }
}
```

---

## Signature
**Slug:** `missing-events-->silent-state-change`
**Detect:** For every state-modifying function: (1) verify an event is emitted, (2) verify event parameters match post-mutation state, (3) verify event handles are registered in `init_module`, (4) verify event struct fields capture full operation context, (5) verify all conditional branches emit events.
**What's Wrong:** One or more state-modifying functions lack event emission, emit pre-mutation values, miss event handle registration, have incomplete event fields, or skip events in some code paths.
**Remediation:** Emit events for all state changes. Use post-mutation values. Register event handles in `init_module`. Ensure event struct fields match recorded data. Cover all conditional branches with event emission.

## Classification Reasoning
This invariant detector consolidates all event-emission-related patterns into a single comprehensive check. Event issues are universally applicable across all Move modules and represent a spectrum of the same fundamental concern: ensuring off-chain observability of on-chain state changes. The five patterns cover the complete lifecycle of event correctness in Aptos Move.

---

## CL-GEN-04: Initialization Safety Invariant

**Rule:** `MOVE-GEN-INIT-01`
**Severity:** medium-high

## Precondition
The module requires one-time setup of resources, capabilities, or configuration during deployment via `init_module` or a public initialization function.

## Root Cause
The `init_module` function is missing, public initialization functions are callable by anyone, initialization is incomplete, setup functions are re-callable, or initialization depends on external state that may not exist.

## Impact
Modules fail to function because required resources are absent. Attackers front-run initialization to gain admin privileges. Partial setup leaves the module in a broken state. Re-initialization resets critical state. External dependencies cause initialization failures.

## Remediation
Use `init_module` for all required setup. Protect public initializers with deployer checks. Initialize all required resources completely. Guard against re-initialization. Minimize external dependencies during init.

---

## Pattern 1: Missing `init_module`

A module requires setup resources to function but has no `init_module` function, leaving the module in an unusable state until someone manually calls setup.

### Vulnerable
```move
module example::lending {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;

    struct LendingPool has key {
        total_deposited: u64,
        total_borrowed: u64,
        interest_rate_bps: u64,
    }

    struct AdminCap has key {}

    // BUG: No init_module — LendingPool and AdminCap never created
    // All functions that acquires LendingPool will abort

    public entry fun deposit(user: &signer, amount: u64) acquires LendingPool {
        // Aborts: LendingPool doesn't exist at @example
        let pool = borrow_global_mut<LendingPool>(@example);
        pool.total_deposited = pool.total_deposited + amount;
    }

    public entry fun set_interest_rate(admin: &signer, rate: u64) acquires LendingPool, AdminCap {
        // Aborts: AdminCap doesn't exist
        assert!(exists<AdminCap>(signer::address_of(admin)), 1);
        let pool = borrow_global_mut<LendingPool>(@example);
        pool.interest_rate_bps = rate;
    }
}
```

### Fixed
```move
module example::lending {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;

    struct LendingPool has key {
        total_deposited: u64,
        total_borrowed: u64,
        interest_rate_bps: u64,
    }

    struct AdminCap has key {}

    // Proper initialization during module deployment
    fun init_module(deployer: &signer) {
        move_to(deployer, LendingPool {
            total_deposited: 0,
            total_borrowed: 0,
            interest_rate_bps: 500, // 5% default
        });
        move_to(deployer, AdminCap {});
    }

    public entry fun deposit(user: &signer, amount: u64) acquires LendingPool {
        let pool = borrow_global_mut<LendingPool>(@example);
        pool.total_deposited = pool.total_deposited + amount;
    }

    public entry fun set_interest_rate(admin: &signer, rate: u64) acquires LendingPool, AdminCap {
        assert!(exists<AdminCap>(signer::address_of(admin)), 1);
        let pool = borrow_global_mut<LendingPool>(@example);
        pool.interest_rate_bps = rate;
    }
}
```

---

## Pattern 2: Race Condition on Manual Initialize

A public `initialize()` function is callable by anyone, allowing an attacker to front-run the legitimate deployer and set themselves as admin.

### Vulnerable
```move
module example::governance {
    use std::signer;

    struct GovernanceConfig has key {
        admin: address,
        quorum: u64,
        voting_period: u64,
    }

    // BUG: Public function — anyone can call this and become admin
    public entry fun initialize(caller: &signer, quorum: u64, period: u64) {
        let addr = signer::address_of(caller);
        // First caller becomes admin — attacker can front-run deployment
        assert!(!exists<GovernanceConfig>(@example), 1);
        move_to(caller, GovernanceConfig {
            admin: addr,  // Caller sets themselves as admin
            quorum,
            voting_period: period,
        });
    }
}
```

### Fixed
```move
module example::governance {
    use std::signer;

    struct GovernanceConfig has key {
        admin: address,
        quorum: u64,
        voting_period: u64,
    }

    // Only the module deployer can call init_module — no front-running possible
    fun init_module(deployer: &signer) {
        move_to(deployer, GovernanceConfig {
            admin: signer::address_of(deployer),
            quorum: 100,
            voting_period: 86400, // 1 day in seconds
        });
    }
}
```

---

## Pattern 3: Incomplete `init_module`

The `init_module` creates some required resources but not all, leaving the module partially initialized and causing aborts in functions that depend on the missing resources.

### Vulnerable
```move
module example::exchange {
    use std::signer;
    use aptos_framework::event::{Self, EventHandle};
    use aptos_framework::account;

    struct ExchangeState has key {
        fee_bps: u64,
        paused: bool,
    }

    struct FeeCollector has key {
        collected: u64,
        treasury: address,
    }

    struct ExchangeEvents has key {
        trade_events: EventHandle<TradeEvent>,
    }

    struct TradeEvent has drop, store {
        trader: address,
        amount: u64,
    }

    fun init_module(deployer: &signer) {
        // BUG: Only ExchangeState is initialized
        move_to(deployer, ExchangeState {
            fee_bps: 30,
            paused: false,
        });
        // FeeCollector NOT initialized — fee collection will abort
        // ExchangeEvents NOT initialized — event emission will abort
    }

    public entry fun trade(user: &signer, amount: u64) acquires ExchangeState, FeeCollector, ExchangeEvents {
        let state = borrow_global<ExchangeState>(@example);
        // Aborts: FeeCollector doesn't exist
        let collector = borrow_global_mut<FeeCollector>(@example);
        collector.collected = collector.collected + (amount * state.fee_bps / 10000);
    }
}
```

### Fixed
```move
module example::exchange {
    use std::signer;
    use aptos_framework::event::{Self, EventHandle};
    use aptos_framework::account;

    struct ExchangeState has key {
        fee_bps: u64,
        paused: bool,
    }

    struct FeeCollector has key {
        collected: u64,
        treasury: address,
    }

    struct ExchangeEvents has key {
        trade_events: EventHandle<TradeEvent>,
    }

    struct TradeEvent has drop, store {
        trader: address,
        amount: u64,
    }

    fun init_module(deployer: &signer) {
        let deployer_addr = signer::address_of(deployer);
        // All required resources initialized completely
        move_to(deployer, ExchangeState {
            fee_bps: 30,
            paused: false,
        });
        move_to(deployer, FeeCollector {
            collected: 0,
            treasury: deployer_addr,
        });
        move_to(deployer, ExchangeEvents {
            trade_events: account::new_event_handle<TradeEvent>(deployer),
        });
    }

    public entry fun trade(user: &signer, amount: u64) acquires ExchangeState, FeeCollector, ExchangeEvents {
        let state = borrow_global<ExchangeState>(@example);
        let collector = borrow_global_mut<FeeCollector>(@example);
        collector.collected = collector.collected + (amount * state.fee_bps / 10000);
    }
}
```

---

## Pattern 4: Re-Initialization via Public Setup Function

A public setup function can be called again after initial setup, resetting critical state like admin address, accumulated balances, or configuration.

### Vulnerable
```move
module example::vault {
    use std::signer;

    struct VaultConfig has key {
        admin: address,
        max_capacity: u64,
        total_deposited: u64,
    }

    // BUG: Can be called again after init, resetting total_deposited to 0
    // and allowing caller to change admin
    public entry fun setup(caller: &signer, max_capacity: u64) {
        let addr = signer::address_of(caller);
        if (exists<VaultConfig>(@example)) {
            // Re-initialization: overwrites existing config
            let config = borrow_global_mut<VaultConfig>(addr);
            config.admin = addr;          // Hijack admin
            config.max_capacity = max_capacity;
            config.total_deposited = 0;   // Reset deposited — accounting destroyed
        } else {
            move_to(caller, VaultConfig {
                admin: addr,
                max_capacity,
                total_deposited: 0,
            });
        };
    }
}
```

### Fixed
```move
module example::vault {
    use std::signer;

    struct VaultConfig has key {
        admin: address,
        max_capacity: u64,
        total_deposited: u64,
    }

    const E_ALREADY_INITIALIZED: u64 = 1;
    const E_NOT_ADMIN: u64 = 2;

    // One-time initialization only
    fun init_module(deployer: &signer) {
        move_to(deployer, VaultConfig {
            admin: signer::address_of(deployer),
            max_capacity: 1000000,
            total_deposited: 0,
        });
    }

    // Separate function for updating config — only admin, no state reset
    public entry fun update_capacity(admin: &signer, new_capacity: u64) acquires VaultConfig {
        let config = borrow_global_mut<VaultConfig>(@example);
        assert!(signer::address_of(admin) == config.admin, E_NOT_ADMIN);
        // Only update the config field, never reset total_deposited
        config.max_capacity = new_capacity;
    }
}
```

---

## Pattern 5: `init_module` Depends on External State

The initialization function reads from another module's resource that may not exist yet, causing the entire deployment to abort.

### Vulnerable
```move
module example::price_feed {
    use std::signer;

    struct PriceFeedConfig has key {
        oracle_address: address,
        initial_price: u64,
    }

    struct OracleData has key {
        price: u64,
        last_updated: u64,
    }

    fun init_module(deployer: &signer) {
        // BUG: Reads from an external oracle that may not be deployed yet
        // If @oracle_provider module is not deployed, this aborts
        // and the entire module deployment fails
        let oracle_data = borrow_global<OracleData>(@oracle_provider);
        move_to(deployer, PriceFeedConfig {
            oracle_address: @oracle_provider,
            initial_price: oracle_data.price,
        });
    }
}
```

### Fixed
```move
module example::price_feed {
    use std::signer;

    struct PriceFeedConfig has key {
        oracle_address: address,
        initial_price: u64,
        oracle_connected: bool,
    }

    struct OracleData has key {
        price: u64,
        last_updated: u64,
    }

    const E_NOT_ADMIN: u64 = 1;

    fun init_module(deployer: &signer) {
        // Initialize with safe defaults — no external dependencies
        move_to(deployer, PriceFeedConfig {
            oracle_address: @oracle_provider,
            initial_price: 0,
            oracle_connected: false,
        });
    }

    // Separate function to connect oracle after both modules are deployed
    public entry fun connect_oracle(admin: &signer) acquires PriceFeedConfig {
        assert!(signer::address_of(admin) == @example, E_NOT_ADMIN);
        assert!(exists<OracleData>(@oracle_provider), 2);
        let oracle_data = borrow_global<OracleData>(@oracle_provider);
        let config = borrow_global_mut<PriceFeedConfig>(@example);
        config.initial_price = oracle_data.price;
        config.oracle_connected = true;
    }
}
```

---

## Signature
**Slug:** `unsafe-init-->state-hijack`
**Detect:** For every module initialization: (1) verify `init_module` exists for modules requiring setup resources, (2) verify public initializers are not front-runnable, (3) verify all required resources are created in `init_module`, (4) verify setup functions cannot be called again to reset state, (5) verify `init_module` does not depend on external resources that may not exist.
**What's Wrong:** One or more modules lack `init_module`, expose front-runnable public initializers, perform incomplete initialization, allow re-initialization, or depend on external state during init.
**Remediation:** Use `init_module` for all required setup. Protect public initializers with deployer checks. Initialize all required resources completely. Guard against re-initialization. Minimize external dependencies during init.

## Classification Reasoning
This invariant detector consolidates all initialization-safety-related patterns into a single comprehensive check. Initialization issues are critical for Move module security and represent a spectrum of the same fundamental concern: ensuring modules start in a correct, complete, and tamper-proof state. The five patterns cover the complete initialization lifecycle from deployment to post-deployment setup.

---

## CL-GEN-05: Resource Management Invariant

**Rule:** `MOVE-GEN-RES-01`
**Severity:** medium-critical

## Precondition
The module creates, reads, moves, or destroys resources using `move_to`, `move_from`, `borrow_global`, or `borrow_global_mut`.

## Root Cause
Resources are not cleaned up on removal, missing required abilities, published without uniqueness checks, or become orphaned after module upgrades.

## Impact
Resources become permanently locked or inaccessible, funds are lost due to orphaned resources, or transfers fail due to missing ability constraints.

## Remediation
Clean up all associated data on removal. Ensure transferable resources have `store`. Guard `move_to` with existence checks. Plan resource migration for upgrades.

---

## Pattern 1: Resource Not Cleaned Up on Account Removal

When removing a resource with `move_from`, associated entries in tables, vectors, or other resources are not cleaned up, leading to stale references and potential state corruption.

### Vulnerable
```move
module example::registry {
    use std::signer;
    use std::vector;
    use aptos_std::table::{Self, Table};

    struct UserProfile has key {
        name: vector<u8>,
        score: u64,
    }

    struct Registry has key {
        users: vector<address>,
        scores: Table<address, u64>,
    }

    public entry fun remove_user(admin: &signer, user_addr: address) acquires UserProfile, Registry {
        // BUG: Removes the resource but leaves stale entries in Registry
        let UserProfile { name: _, score: _ } = move_from<UserProfile>(user_addr);
        // Registry.users still contains user_addr
        // Registry.scores still has the entry
    }
}
```

### Fixed
```move
module example::registry {
    use std::signer;
    use std::vector;
    use aptos_std::table::{Self, Table};

    struct UserProfile has key {
        name: vector<u8>,
        score: u64,
    }

    struct Registry has key {
        users: vector<address>,
        scores: Table<address, u64>,
    }

    public entry fun remove_user(admin: &signer, user_addr: address) acquires UserProfile, Registry {
        let UserProfile { name: _, score: _ } = move_from<UserProfile>(user_addr);

        // Clean up all associated entries
        let registry = borrow_global_mut<Registry>(@example);
        let (found, idx) = vector::index_of(&registry.users, &user_addr);
        if (found) {
            vector::swap_remove(&mut registry.users, idx);
        };
        if (table::contains(&registry.scores, user_addr)) {
            table::remove(&mut registry.scores, user_addr);
        };
    }
}
```

---

## Pattern 2: Missing `store` Ability on Transferable Resource

A resource intended to be stored inside another struct or transferred between accounts lacks the `store` ability, preventing composition and storage in collections.

### Vulnerable
```move
module example::nft {
    use std::signer;
    use std::vector;

    // BUG: Missing `store` ability — cannot be placed in a collection or another resource
    struct NFT has key {
        id: u64,
        uri: vector<u8>,
    }

    struct Collection has key, store {
        items: vector<NFT>, // Compile error: NFT does not have `store`
    }

    public entry fun mint(creator: &signer, id: u64, uri: vector<u8>) {
        let nft = NFT { id, uri };
        move_to(creator, nft);
    }
}
```

### Fixed
```move
module example::nft {
    use std::signer;
    use std::vector;

    // Added `store` so NFT can be embedded in other resources and collections
    struct NFT has key, store {
        id: u64,
        uri: vector<u8>,
    }

    struct Collection has key, store {
        items: vector<NFT>, // Now valid: NFT has `store`
    }

    public entry fun mint(creator: &signer, id: u64, uri: vector<u8>) {
        let nft = NFT { id, uri };
        move_to(creator, nft);
    }
}
```

---

## Pattern 3: Double `move_to` Without Existence Check

Publishing a resource to an account that already has one causes an abort. Functions that may be called multiple times must guard against duplicate publication.

### Vulnerable
```move
module example::profile {
    use std::signer;

    struct UserProfile has key {
        level: u64,
        reputation: u64,
    }

    public entry fun create_profile(user: &signer) {
        // BUG: If user already has a UserProfile, this aborts
        move_to(user, UserProfile {
            level: 1,
            reputation: 0,
        });
    }

    public entry fun register_and_setup(user: &signer) {
        // BUG: Calls create_profile which does move_to, then does another move_to
        create_profile(user);
        // Later code might also try to publish another resource without checking
        move_to(user, UserProfile { level: 1, reputation: 100 });
    }
}
```

### Fixed
```move
module example::profile {
    use std::signer;

    struct UserProfile has key {
        level: u64,
        reputation: u64,
    }

    const E_PROFILE_EXISTS: u64 = 1;

    public entry fun create_profile(user: &signer) {
        let addr = signer::address_of(user);
        // Guard against double publication
        assert!(!exists<UserProfile>(addr), E_PROFILE_EXISTS);
        move_to(user, UserProfile {
            level: 1,
            reputation: 0,
        });
    }

    public entry fun register_and_setup(user: &signer) {
        let addr = signer::address_of(user);
        if (!exists<UserProfile>(addr)) {
            move_to(user, UserProfile { level: 1, reputation: 100 });
        };
    }
}
```

---

## Pattern 4: Orphaned Resource After Module Upgrade

When a module is upgraded, if a struct's definition is changed or removed, resources created by the old version become inaccessible, permanently locking any funds or data they contain.

### Vulnerable
```move
// Version 1 of the module — deployed and users have stored resources
module example::staking_v1 {
    use std::signer;

    struct StakePosition has key {
        amount: u64,
        start_time: u64,
    }

    public entry fun stake(user: &signer, amount: u64, time: u64) {
        move_to(user, StakePosition { amount, start_time: time });
    }
}

// Version 2 — BUG: StakePosition struct changed, old resources are orphaned
module example::staking_v2 {
    use std::signer;

    // Changed struct layout — old StakePosition resources are now inaccessible
    struct StakePosition has key {
        amount: u128,          // was u64
        start_time: u64,
        lock_period: u64,      // new field added
        reward_debt: u128,     // new field added
    }
    // Users who staked in v1 can never unstake — funds permanently locked
}
```

### Fixed
```move
// Version 1 — design resources with migration in mind
module example::staking {
    use std::signer;

    struct StakePosition has key {
        amount: u64,
        start_time: u64,
    }

    // Version 2 adds new resource alongside old one
    struct StakePositionV2 has key {
        amount: u128,
        start_time: u64,
        lock_period: u64,
        reward_debt: u128,
    }

    const E_NO_V1_POSITION: u64 = 1;

    // Migration function: converts v1 resource to v2
    public entry fun migrate_position(user: &signer) acquires StakePosition {
        let addr = signer::address_of(user);
        assert!(exists<StakePosition>(addr), E_NO_V1_POSITION);
        let StakePosition { amount, start_time } = move_from<StakePosition>(addr);
        move_to(user, StakePositionV2 {
            amount: (amount as u128),
            start_time,
            lock_period: 0,
            reward_debt: 0,
        });
    }
}
```

---

## Signature
**Slug:** `resource-mismanagement-->loss`
**Detect:** For every resource operation: (1) verify all associated data is cleaned up on `move_from`, (2) verify transferable resources have `store` ability, (3) verify `move_to` is guarded against double publication, (4) verify resources remain accessible after module upgrades.
**What's Wrong:** One or more resource operations fail to clean up associated data, miss required abilities, allow double publication, or create orphaned resources on upgrade.
**Remediation:** Clean up all associated data on removal. Ensure transferable resources have `store`. Guard `move_to` with existence checks. Plan resource migration for upgrades.

---

## CL-GEN-06: State Freshness Invariant

**Rule:** `MOVE-GEN-STALE-01`
**Severity:** medium-high

## Precondition
The module has state-dependent operations where parameters can be updated or local variables cache mutable state across function calls.

## Root Cause
Global parameters are updated without first settling state under the old parameters, or local state caches are written back after intermediate mutations overwrite them.

## Impact
Retroactive application of new rates/parameters to un-settled periods, or intermediate state changes silently lost when stale local copies are written back.

## Remediation
Always settle/accrue state under old parameters before applying new ones. Re-read state after any mutation instead of using cached local copies.

---

## Pattern 1: Stale State Before Parameter Update

Global parameters (interest rate, fee tier, reward rate) are updated without first accruing state under the old parameters, causing retroactive application of new values to the un-accrued period.

### Vulnerable
```move
// VULNERABLE: changes rate without accruing under old rate
public fun set_interest_rate(pool: &mut Pool, new_rate: u64) {
    pool.interest_rate = new_rate; // old period now charged at new rate
}
```

### Fixed
```move
// FIXED: accrue before update
public fun set_interest_rate(pool: &mut Pool, new_rate: u64) {
    accrue_interest(pool, timestamp::now_seconds()); // settle old rate period
    pool.interest_rate = new_rate;
}
```

---

## Pattern 2: Stale Cache Overwrite

A function loads state into a local variable, performs operations that modify the global state, then writes the stale local copy back, overwriting intermediate updates.

### Vulnerable
```move
// VULNERABLE: local copy overwrites intermediate state changes
public fun process(pool: &mut Pool, withdrawal: u64) {
    let cached_total = pool.total_assets; // cache
    transfer_fees(pool); // modifies pool.total_assets internally
    pool.total_assets = cached_total - withdrawal; // overwrites fee update
}
```

### Fixed
```move
// FIXED: re-read after mutations
public fun process(pool: &mut Pool, withdrawal: u64) {
    transfer_fees(pool);
    pool.total_assets = pool.total_assets - withdrawal; // reads current state
}
```

---

## Signature
**Slug:** `state-freshness-invariant`
**Detect:** For every parameter update or cached state write-back: (1) verify state is accrued/settled under old parameters before applying new ones, (2) verify local state caches are not written back after intermediate mutations.
**What's Wrong:** Parameters are applied retroactively to un-settled periods, or stale local copies overwrite intermediate state changes.
**Remediation:** Accrue before parameter updates. Re-read state after any mutation instead of using cached copies.

---

## CL-GEN-07: State Consistency Invariant

**Rule:** `MOVE-GEN-STATE-01`
**Severity:** medium-high

## Precondition
The module maintains coupled state across multiple fields, resources, or tables that must remain synchronized after every mutation.

## Root Cause
State mutations update one part of coupled data without updating the counterpart, hold stale references across mutations, or fail to maintain aggregate invariants.

## Impact
Inconsistent state leads to incorrect balances, broken accounting, exploitable discrepancies between local and global state, and potential fund extraction through state desynchronization.

## Remediation
Update all coupled fields atomically. Avoid holding references across mutations. Maintain counter/total invariants on every add/remove. Synchronize global aggregates with individual state changes. Ensure multi-resource updates complete fully or revert entirely.

---

## Pattern 1: Partial Struct Field Update

Updating one field of a mutably borrowed resource but failing to update its coupled counterpart, creating an inconsistent state.

### Vulnerable
```move
module example::pool {
    use std::signer;

    struct Pool has key {
        total_shares: u64,
        total_assets: u64,
        last_update_time: u64,
        accumulated_rewards: u64,
    }

    public entry fun deposit_assets(admin: &signer, amount: u64) acquires Pool {
        let pool = borrow_global_mut<Pool>(@example);
        // BUG: total_assets updated but total_shares not recalculated
        // and last_update_time not refreshed
        pool.total_assets = pool.total_assets + amount;
        // pool.total_shares should be updated proportionally
        // pool.last_update_time should be set to current time
    }
}
```

### Fixed
```move
module example::pool {
    use std::signer;
    use aptos_framework::timestamp;

    struct Pool has key {
        total_shares: u64,
        total_assets: u64,
        last_update_time: u64,
        accumulated_rewards: u64,
    }

    public entry fun deposit_assets(admin: &signer, amount: u64) acquires Pool {
        let pool = borrow_global_mut<Pool>(@example);
        let new_shares = if (pool.total_assets == 0) {
            amount
        } else {
            (amount * pool.total_shares) / pool.total_assets
        };
        // All coupled fields updated together
        pool.total_assets = pool.total_assets + amount;
        pool.total_shares = pool.total_shares + new_shares;
        pool.last_update_time = timestamp::now_seconds();
    }
}
```

---

## Pattern 2: Stale Reference After Table Mutation

Holding a reference to a table value while the underlying table is mutated through another path, causing the reference to reflect stale data.

### Vulnerable
```move
module example::ledger {
    use aptos_std::table::{Self, Table};
    use std::signer;

    struct Ledger has key {
        balances: Table<address, u64>,
        total: u64,
    }

    public fun transfer(
        ledger: &mut Ledger,
        from: address,
        to: address,
        amount: u64
    ) {
        // BUG: Borrow `from` balance, then mutate table for `to` — if from == to,
        // the first borrow is stale after the second mutation
        let from_bal = table::borrow_mut(&mut ledger.balances, from);
        *from_bal = *from_bal - amount;

        let to_bal = table::borrow_mut(&mut ledger.balances, to);
        *to_bal = *to_bal + amount;
        // If from == to, the final balance is wrong (only the add is reflected)
    }
}
```

### Fixed
```move
module example::ledger {
    use aptos_std::table::{Self, Table};
    use std::signer;

    struct Ledger has key {
        balances: Table<address, u64>,
        total: u64,
    }

    const E_SELF_TRANSFER: u64 = 1;

    public fun transfer(
        ledger: &mut Ledger,
        from: address,
        to: address,
        amount: u64
    ) {
        // Guard against self-transfer which would corrupt state
        assert!(from != to, E_SELF_TRANSFER);

        let from_bal = table::borrow_mut(&mut ledger.balances, from);
        *from_bal = *from_bal - amount;

        let to_bal = table::borrow_mut(&mut ledger.balances, to);
        *to_bal = *to_bal + amount;
    }
}
```

---

## Pattern 3: Counter/Total Mismatch

A counter is incremented when items are added but not decremented on removal (or vice versa), causing the counter to diverge from the actual count.

### Vulnerable
```move
module example::marketplace {
    use std::signer;
    use std::vector;

    struct Marketplace has key {
        listings: vector<Listing>,
        active_count: u64,
        total_volume: u64,
    }

    struct Listing has store, drop {
        seller: address,
        price: u64,
        active: bool,
    }

    public fun add_listing(market: &mut Marketplace, seller: address, price: u64) {
        vector::push_back(&mut market.listings, Listing { seller, price, active: true });
        market.active_count = market.active_count + 1;
    }

    public fun cancel_listing(market: &mut Marketplace, index: u64) {
        let listing = vector::borrow_mut(&mut market.listings, index);
        listing.active = false;
        // BUG: active_count not decremented — will overcount active listings
    }
}
```

### Fixed
```move
module example::marketplace {
    use std::signer;
    use std::vector;

    struct Marketplace has key {
        listings: vector<Listing>,
        active_count: u64,
        total_volume: u64,
    }

    struct Listing has store, drop {
        seller: address,
        price: u64,
        active: bool,
    }

    const E_ALREADY_CANCELLED: u64 = 1;

    public fun add_listing(market: &mut Marketplace, seller: address, price: u64) {
        vector::push_back(&mut market.listings, Listing { seller, price, active: true });
        market.active_count = market.active_count + 1;
    }

    public fun cancel_listing(market: &mut Marketplace, index: u64) {
        let listing = vector::borrow_mut(&mut market.listings, index);
        assert!(listing.active, E_ALREADY_CANCELLED);
        listing.active = false;
        // Counter decremented to stay in sync
        market.active_count = market.active_count - 1;
    }
}
```

---

## Pattern 4: Global State Not Synced With User State

Global aggregate totals are not adjusted when individual user balances change, creating accounting discrepancies exploitable for over-withdrawal.

### Vulnerable
```move
module example::staking {
    use std::signer;

    struct GlobalState has key {
        total_staked: u64,
        reward_per_token: u64,
    }

    struct UserStake has key {
        amount: u64,
        reward_debt: u64,
    }

    public entry fun emergency_withdraw(user: &signer) acquires UserStake, GlobalState {
        let addr = signer::address_of(user);
        let user_stake = borrow_global_mut<UserStake>(addr);
        let withdraw_amount = user_stake.amount;
        user_stake.amount = 0;
        user_stake.reward_debt = 0;
        // BUG: GlobalState.total_staked not decremented
        // reward_per_token calculations will be wrong for all other users
        // let global = borrow_global_mut<GlobalState>(@example);
        // global.total_staked not updated
    }
}
```

### Fixed
```move
module example::staking {
    use std::signer;

    struct GlobalState has key {
        total_staked: u64,
        reward_per_token: u64,
    }

    struct UserStake has key {
        amount: u64,
        reward_debt: u64,
    }

    public entry fun emergency_withdraw(user: &signer) acquires UserStake, GlobalState {
        let addr = signer::address_of(user);
        let user_stake = borrow_global_mut<UserStake>(addr);
        let withdraw_amount = user_stake.amount;
        user_stake.amount = 0;
        user_stake.reward_debt = 0;

        // Global state synchronized with user state change
        let global = borrow_global_mut<GlobalState>(@example);
        global.total_staked = global.total_staked - withdraw_amount;
    }
}
```

---

## Pattern 5: Non-Atomic Multi-Resource Update

Updating one resource successfully but aborting before the second coupled resource is updated, leaving the system in a half-mutated state.

### Vulnerable
```move
module example::escrow {
    use std::signer;

    struct EscrowState has key {
        locked_amount: u64,
        release_count: u64,
    }

    struct UserBalance has key {
        available: u64,
        locked: u64,
    }

    const E_INSUFFICIENT: u64 = 1;

    public entry fun release_escrow(
        admin: &signer,
        user_addr: address,
        amount: u64
    ) acquires EscrowState, UserBalance {
        // First resource updated
        let escrow = borrow_global_mut<EscrowState>(@example);
        escrow.locked_amount = escrow.locked_amount - amount;
        escrow.release_count = escrow.release_count + 1;

        // BUG: If this assert fails, EscrowState is already mutated but
        // UserBalance is not updated — state is inconsistent
        let user_bal = borrow_global_mut<UserBalance>(user_addr);
        assert!(user_bal.locked >= amount, E_INSUFFICIENT);
        user_bal.locked = user_bal.locked - amount;
        user_bal.available = user_bal.available + amount;
    }
}
```

### Fixed
```move
module example::escrow {
    use std::signer;

    struct EscrowState has key {
        locked_amount: u64,
        release_count: u64,
    }

    struct UserBalance has key {
        available: u64,
        locked: u64,
    }

    const E_INSUFFICIENT: u64 = 1;
    const E_ESCROW_MISMATCH: u64 = 2;

    public entry fun release_escrow(
        admin: &signer,
        user_addr: address,
        amount: u64
    ) acquires EscrowState, UserBalance {
        // Validate all preconditions BEFORE any mutation
        let escrow = borrow_global<EscrowState>(@example);
        assert!(escrow.locked_amount >= amount, E_ESCROW_MISMATCH);

        let user_bal = borrow_global<UserBalance>(user_addr);
        assert!(user_bal.locked >= amount, E_INSUFFICIENT);

        // All validations passed — now perform mutations
        let escrow_mut = borrow_global_mut<EscrowState>(@example);
        escrow_mut.locked_amount = escrow_mut.locked_amount - amount;
        escrow_mut.release_count = escrow_mut.release_count + 1;

        let user_bal_mut = borrow_global_mut<UserBalance>(user_addr);
        user_bal_mut.locked = user_bal_mut.locked - amount;
        user_bal_mut.available = user_bal_mut.available + amount;
    }
}
```

---

## Signature
**Slug:** `state-inconsistency-->corruption`
**Detect:** For every state mutation: (1) verify all coupled struct fields are updated together, (2) verify no stale references are held across table mutations, (3) verify counters/totals are maintained on every add/remove, (4) verify global aggregates stay synchronized with individual state changes, (5) verify multi-resource updates validate preconditions before any mutation.
**What's Wrong:** One or more state mutations leave coupled fields out of sync, hold stale references, allow counter drift, desynchronize global and local state, or perform partial updates that can abort mid-way.
**Remediation:** Update all coupled fields atomically. Avoid holding references across mutations. Maintain counter/total invariants on every add/remove. Synchronize global aggregates with individual state changes. Validate all preconditions before beginning mutations.

## Classification Reasoning
This invariant detector consolidates all state-consistency-related patterns into a single comprehensive check. State consistency issues are fundamental to any stateful Move module and represent a spectrum of the same core concern: ensuring all coupled state remains synchronized after every mutation. The five patterns cover the main ways state can become inconsistent in Move programs.

---

## CL-GEN-08: Timestamp/Deadline Invariant

**Rule:** `MOVE-GEN-TIME-01`
**Severity:** low-high

## Precondition
The module uses timestamps for deadlines, time-locked operations, vesting schedules, auction timing, or any time-dependent business logic.

## Root Cause
Timestamp units are mixed (seconds vs microseconds), deadlines are stored but never enforced, block timestamps are used for sensitive timing, cached timestamps become stale, or boundary conditions use incorrect comparison operators.

## Impact
Deadlines are bypassed or enforced at wrong times, auctions can be manipulated through block timing, operations proceed with stale time values, and off-by-one errors at boundaries cause incorrect allow/deny decisions.

## Remediation
Use consistent timestamp units throughout. Enforce deadlines before allowing gated actions. Avoid using block timestamps for security-critical timing. Refresh timestamps for long operations. Use correct comparison operators at boundaries.

---

## Pattern 1: Seconds vs Microseconds Mismatch

Mixing `timestamp::now_seconds()` with microsecond values (or vice versa) causes deadline checks to be off by a factor of 1,000,000.

### Vulnerable
```move
module example::vesting {
    use std::signer;
    use aptos_framework::timestamp;

    struct VestingSchedule has key {
        start_time: u64,     // Stored in microseconds from another source
        cliff_duration: u64, // Intended as seconds
        total_amount: u64,
        claimed: u64,
    }

    public entry fun claim(user: &signer) acquires VestingSchedule {
        let addr = signer::address_of(user);
        let schedule = borrow_global_mut<VestingSchedule>(addr);
        // BUG: now_seconds() returns seconds, but start_time is in microseconds
        // The cliff check will pass almost immediately
        let now = timestamp::now_seconds();
        assert!(now >= schedule.start_time + schedule.cliff_duration, 1);
        // cliff_duration in seconds added to start_time in microseconds = wrong
    }
}
```

### Fixed
```move
module example::vesting {
    use std::signer;
    use aptos_framework::timestamp;

    struct VestingSchedule has key {
        start_time_secs: u64,   // Explicitly named with unit
        cliff_duration_secs: u64,
        total_amount: u64,
        claimed: u64,
    }

    const E_CLIFF_NOT_REACHED: u64 = 1;

    public entry fun claim(user: &signer) acquires VestingSchedule {
        let addr = signer::address_of(user);
        let schedule = borrow_global_mut<VestingSchedule>(addr);
        // Consistent units: all in seconds
        let now_secs = timestamp::now_seconds();
        assert!(
            now_secs >= schedule.start_time_secs + schedule.cliff_duration_secs,
            E_CLIFF_NOT_REACHED
        );
    }
}
```

---

## Pattern 2: Missing Deadline Enforcement

An expiry or deadline timestamp is stored in the resource but never actually checked before allowing the time-gated action.

### Vulnerable
```move
module example::proposal {
    use std::signer;
    use aptos_framework::timestamp;

    struct Proposal has key {
        description: vector<u8>,
        votes_for: u64,
        votes_against: u64,
        deadline: u64,  // Voting deadline stored but never checked
    }

    public entry fun vote(voter: &signer, proposal_addr: address, support: bool) acquires Proposal {
        let proposal = borrow_global_mut<Proposal>(proposal_addr);
        // BUG: deadline is never enforced — votes accepted forever
        if (support) {
            proposal.votes_for = proposal.votes_for + 1;
        } else {
            proposal.votes_against = proposal.votes_against + 1;
        };
    }

    public entry fun execute(admin: &signer, proposal_addr: address) acquires Proposal {
        let proposal = borrow_global<Proposal>(proposal_addr);
        // BUG: Can execute before deadline — no check that voting period ended
        assert!(proposal.votes_for > proposal.votes_against, 1);
    }
}
```

### Fixed
```move
module example::proposal {
    use std::signer;
    use aptos_framework::timestamp;

    struct Proposal has key {
        description: vector<u8>,
        votes_for: u64,
        votes_against: u64,
        deadline: u64,
    }

    const E_VOTING_ENDED: u64 = 1;
    const E_VOTING_NOT_ENDED: u64 = 2;

    public entry fun vote(voter: &signer, proposal_addr: address, support: bool) acquires Proposal {
        let proposal = borrow_global_mut<Proposal>(proposal_addr);
        // Enforce deadline — reject votes after expiry
        assert!(timestamp::now_seconds() < proposal.deadline, E_VOTING_ENDED);
        if (support) {
            proposal.votes_for = proposal.votes_for + 1;
        } else {
            proposal.votes_against = proposal.votes_against + 1;
        };
    }

    public entry fun execute(admin: &signer, proposal_addr: address) acquires Proposal {
        let proposal = borrow_global<Proposal>(proposal_addr);
        // Ensure voting period has ended before execution
        assert!(timestamp::now_seconds() >= proposal.deadline, E_VOTING_NOT_ENDED);
        assert!(proposal.votes_for > proposal.votes_against, 1);
    }
}
```

---

## Pattern 3: Stale Timestamp After Long Transaction

Caching the timestamp at the start of a complex operation and using it for later decisions, where the cached value no longer reflects the current block time after intermediate operations.

### Vulnerable
```move
module example::batch_processor {
    use std::signer;
    use std::vector;
    use aptos_framework::timestamp;

    struct Order has store, drop {
        amount: u64,
        deadline: u64,
        owner: address,
    }

    struct OrderBook has key {
        orders: vector<Order>,
    }

    public entry fun process_batch(admin: &signer) acquires OrderBook {
        // BUG: Timestamp captured once at the start
        let now = timestamp::now_seconds();
        let book = borrow_global_mut<OrderBook>(@example);
        let i = 0;
        let len = vector::length(&book.orders);
        while (i < len) {
            let order = vector::borrow(&book.orders, i);
            // Uses stale `now` for all orders — within the same tx this is
            // technically the same, but the logic error is that `now` should
            // be compared per-order if orders have different time contexts
            if (now < order.deadline) {
                // Process order using stale timestamp for price calculation
                // Price may have changed between order creation and now
            };
            i = i + 1;
        };
    }
}
```

### Fixed
```move
module example::batch_processor {
    use std::signer;
    use std::vector;
    use aptos_framework::timestamp;

    struct Order has store, drop {
        amount: u64,
        deadline: u64,
        owner: address,
        max_price: u64, // User-specified price bound instead of time dependency
    }

    struct OrderBook has key {
        orders: vector<Order>,
    }

    struct PriceOracle has key {
        current_price: u64,
        last_updated: u64,
    }

    const E_STALE_PRICE: u64 = 1;

    public entry fun process_batch(admin: &signer) acquires OrderBook, PriceOracle {
        let now = timestamp::now_seconds();
        let oracle = borrow_global<PriceOracle>(@example);
        // Verify oracle price is fresh before processing batch
        assert!(now - oracle.last_updated < 60, E_STALE_PRICE);

        let book = borrow_global_mut<OrderBook>(@example);
        let i = 0;
        let len = vector::length(&book.orders);
        while (i < len) {
            let order = vector::borrow(&book.orders, i);
            if (now < order.deadline && oracle.current_price <= order.max_price) {
                // Process with verified fresh price and deadline check
            };
            i = i + 1;
        };
    }
}
```

---

## Pattern 4: Off-By-One in Time Window Check

Using `>=` instead of `>` (or vice versa) at time boundaries causes actions to be allowed or denied at the exact boundary moment, leading to edge-case exploits.

### Vulnerable
```move
module example::auction {
    use std::signer;
    use aptos_framework::timestamp;

    struct Auction has key {
        highest_bid: u64,
        highest_bidder: address,
        end_time: u64,
        settled: bool,
    }

    const E_AUCTION_ENDED: u64 = 1;
    const E_AUCTION_NOT_ENDED: u64 = 2;
    const E_LOW_BID: u64 = 3;

    public entry fun place_bid(bidder: &signer, amount: u64) acquires Auction {
        let auction = borrow_global_mut<Auction>(@example);
        // BUG: Uses strict `<` — at exactly end_time, bidding is blocked
        assert!(timestamp::now_seconds() < auction.end_time, E_AUCTION_ENDED);
        assert!(amount > auction.highest_bid, E_LOW_BID);
        auction.highest_bid = amount;
        auction.highest_bidder = signer::address_of(bidder);
    }

    public entry fun settle(admin: &signer) acquires Auction {
        let auction = borrow_global_mut<Auction>(@example);
        // BUG: Uses strict `>` — at exactly end_time, settlement is also blocked
        // Combined: at end_time, place_bid requires < (fails) and settle requires > (fails)
        // Creates a dead zone where neither operation is possible
        assert!(timestamp::now_seconds() > auction.end_time, E_AUCTION_NOT_ENDED);
        auction.settled = true;
    }
}
```

### Fixed
```move
module example::auction {
    use std::signer;
    use aptos_framework::timestamp;

    struct Auction has key {
        highest_bid: u64,
        highest_bidder: address,
        end_time: u64,
        settled: bool,
    }

    const E_AUCTION_ENDED: u64 = 1;
    const E_AUCTION_NOT_ENDED: u64 = 2;

    public entry fun place_bid(bidder: &signer, amount: u64) acquires Auction {
        let auction = borrow_global_mut<Auction>(@example);
        // Strict less-than: bidding allowed only before end_time
        assert!(timestamp::now_seconds() < auction.end_time, E_AUCTION_ENDED);
        assert!(amount > auction.highest_bid, 3);
        auction.highest_bid = amount;
        auction.highest_bidder = signer::address_of(bidder);
    }

    public entry fun settle(admin: &signer) acquires Auction {
        let auction = borrow_global_mut<Auction>(@example);
        // Greater-or-equal: settlement allowed at and after end_time
        // No gap between bid window and settle window
        assert!(timestamp::now_seconds() >= auction.end_time, E_AUCTION_NOT_ENDED);
        assert!(!auction.settled, 4);
        auction.settled = true;
    }
}
```

---

## Signature
**Slug:** `time-misuse-->deadline-bypass`
**Detect:** For every time-dependent operation: (1) verify timestamp units are consistent (seconds vs microseconds), (2) verify stored deadlines are enforced before gated actions, (3) verify timestamps are fresh for time-sensitive decisions, (4) verify comparison operators at time boundaries are correct.
**What's Wrong:** One or more time-dependent operations mix timestamp units, store but never enforce deadlines, rely on stale timestamps, or have off-by-one errors at time boundaries.
**Remediation:** Use consistent timestamp units throughout. Enforce deadlines before allowing gated actions. Refresh timestamps for long operations. Use correct comparison operators at boundaries.

---

## CL-GEN-09: Type Safety Invariant

**Rule:** `MOVE-GEN-TYPE-01`
**Severity:** medium-high

## Precondition
The module uses generic type parameters, phantom types, or type-based dispatch to differentiate behavior or access control for different token types or resource categories.

## Root Cause
Generic type parameters are unconstrained, phantom types lack runtime validation, type identity is not verified against a registry, generic instantiation enables cross-type storage access, or coin type registration is not checked before operations.

## Impact
Type confusion allows unauthorized access to unrelated storage, bypass of access controls through arbitrary type instantiation, operations on unregistered or invalid tokens, and logic errors from unconstrained generic parameters.

## Remediation
Constrain generic types with required abilities. Validate phantom types with runtime checks or witness patterns. Verify type registration with `type_info` or coin registry. Prevent cross-type access via per-type storage isolation. Check coin initialization before operations.

---

## Pattern 1: Unconstrained Generic Type Parameter

A generic function accepts any type `T` without requiring it to satisfy specific abilities, allowing callers to pass types that may cause runtime errors or unintended behavior.

### Vulnerable
```move
module example::storage {
    use std::signer;

    struct Vault<T> has key {
        contents: T,
    }

    // BUG: T has no ability constraints — caller can pass a type without
    // `store` or `drop`, causing issues when the Vault is moved or destroyed
    public fun store_item<T>(owner: &signer, item: T) {
        move_to(owner, Vault<T> { contents: item });
    }

    // BUG: T has no `drop` — if extraction fails, resource leaks
    public fun extract_item<T>(owner: &signer): T acquires Vault {
        let addr = signer::address_of(owner);
        let Vault { contents } = move_from<Vault<T>>(addr);
        contents
    }
}
```

### Fixed
```move
module example::storage {
    use std::signer;

    struct Vault<T: store> has key {
        contents: T,
    }

    // T must have `store` to be placed in a resource and `drop` for safe cleanup
    public fun store_item<T: store + drop>(owner: &signer, item: T) {
        let addr = signer::address_of(owner);
        if (exists<Vault<T>>(addr)) {
            let vault = borrow_global_mut<Vault<T>>(addr);
            vault.contents = item;
        } else {
            move_to(owner, Vault<T> { contents: item });
        };
    }

    public fun extract_item<T: store>(owner: &signer): T acquires Vault {
        let addr = signer::address_of(owner);
        let Vault { contents } = move_from<Vault<T>>(addr);
        contents
    }
}
```

---

## Pattern 2: Phantom Type Parameter Misuse

A phantom type parameter is used for logical grouping or namespacing, but no runtime check prevents cross-type operations, allowing one pool's logic to affect another.

### Vulnerable
```move
module example::multi_pool {
    use std::signer;

    // phantom T is supposed to separate pools for different tokens
    struct Pool<phantom T> has key {
        balance: u64,
        reward_rate: u64,
    }

    // BUG: Nothing prevents calling deposit<CoinA> and then
    // withdraw<CoinB> — phantom types provide no runtime separation
    public entry fun deposit<T>(user: &signer, amount: u64) acquires Pool {
        let pool = borrow_global_mut<Pool<T>>(@example);
        pool.balance = pool.balance + amount;
    }

    public entry fun withdraw<T>(user: &signer, amount: u64) acquires Pool {
        let pool = borrow_global_mut<Pool<T>>(@example);
        pool.balance = pool.balance - amount;
        // Actual token transfer uses the same generic T but
        // user's deposit was tracked under a different T
    }
}
```

### Fixed
```move
module example::multi_pool {
    use std::signer;
    use aptos_std::table::{Self, Table};

    struct Pool<phantom T> has key {
        balance: u64,
        reward_rate: u64,
        user_deposits: Table<address, u64>,
    }

    public entry fun deposit<T>(user: &signer, amount: u64) acquires Pool {
        let addr = signer::address_of(user);
        let pool = borrow_global_mut<Pool<T>>(@example);
        pool.balance = pool.balance + amount;
        // Track per-user deposits under the specific type T
        if (table::contains(&pool.user_deposits, addr)) {
            let current = table::borrow_mut(&mut pool.user_deposits, addr);
            *current = *current + amount;
        } else {
            table::add(&mut pool.user_deposits, addr, amount);
        };
    }

    public entry fun withdraw<T>(user: &signer, amount: u64) acquires Pool {
        let addr = signer::address_of(user);
        let pool = borrow_global_mut<Pool<T>>(@example);
        // Validate withdrawal against user's deposit under this specific type
        let user_bal = table::borrow_mut(&mut pool.user_deposits, addr);
        assert!(*user_bal >= amount, 1);
        *user_bal = *user_bal - amount;
        pool.balance = pool.balance - amount;
    }
}
```

---

## Pattern 3: Missing `type_info` Validation

Accepting an arbitrary generic `CoinType` without verifying it corresponds to a registered coin, allowing operations on non-existent or malicious token types.

### Vulnerable
```move
module example::dex {
    use std::signer;
    use aptos_framework::coin;

    struct LiquidityPool<phantom X, phantom Y> has key {
        reserve_x: u64,
        reserve_y: u64,
    }

    // BUG: No validation that X and Y are actual registered coin types
    // Attacker can create a pool with arbitrary types
    public entry fun create_pool<X, Y>(creator: &signer) {
        move_to(creator, LiquidityPool<X, Y> {
            reserve_x: 0,
            reserve_y: 0,
        });
    }

    public entry fun add_liquidity<X, Y>(
        provider: &signer,
        amount_x: u64,
        amount_y: u64
    ) acquires LiquidityPool {
        // Operates on potentially fake coin types
        let pool = borrow_global_mut<LiquidityPool<X, Y>>(@example);
        pool.reserve_x = pool.reserve_x + amount_x;
        pool.reserve_y = pool.reserve_y + amount_y;
    }
}
```

### Fixed
```move
module example::dex {
    use std::signer;
    use aptos_framework::coin;
    use aptos_std::type_info;

    struct LiquidityPool<phantom X, phantom Y> has key {
        reserve_x: u64,
        reserve_y: u64,
    }

    const E_COIN_NOT_REGISTERED: u64 = 1;
    const E_SAME_COIN: u64 = 2;

    public entry fun create_pool<X, Y>(creator: &signer) {
        // Validate both types are initialized coins
        assert!(coin::is_coin_initialized<X>(), E_COIN_NOT_REGISTERED);
        assert!(coin::is_coin_initialized<Y>(), E_COIN_NOT_REGISTERED);
        // Ensure X and Y are different types
        assert!(
            type_info::type_of<X>() != type_info::type_of<Y>(),
            E_SAME_COIN
        );
        move_to(creator, LiquidityPool<X, Y> {
            reserve_x: 0,
            reserve_y: 0,
        });
    }

    public entry fun add_liquidity<X, Y>(
        provider: &signer,
        amount_x: u64,
        amount_y: u64
    ) acquires LiquidityPool {
        assert!(coin::is_coin_initialized<X>(), E_COIN_NOT_REGISTERED);
        assert!(coin::is_coin_initialized<Y>(), E_COIN_NOT_REGISTERED);
        let pool = borrow_global_mut<LiquidityPool<X, Y>>(@example);
        pool.reserve_x = pool.reserve_x + amount_x;
        pool.reserve_y = pool.reserve_y + amount_y;
    }
}
```

---

## Pattern 4: Type-Punning via Generic Instantiation

The same generic function called with different type parameters accesses logically unrelated storage, enabling a user to manipulate one type's data through another type's interface.

### Vulnerable
```move
module example::reward_vault {
    use std::signer;

    struct RewardBalance<phantom T> has key {
        amount: u64,
    }

    // BUG: User deposits as type A, then claims as type B
    // Both create separate RewardBalance resources, but the
    // claim logic doesn't verify the type matches the deposit
    public entry fun deposit_reward<T>(user: &signer, amount: u64) {
        let addr = signer::address_of(user);
        if (exists<RewardBalance<T>>(addr)) {
            let bal = borrow_global_mut<RewardBalance<T>>(addr);
            bal.amount = bal.amount + amount;
        } else {
            move_to(user, RewardBalance<T> { amount });
        };
    }

    public entry fun claim_reward<T>(user: &signer) acquires RewardBalance {
        let addr = signer::address_of(user);
        let RewardBalance { amount } = move_from<RewardBalance<T>>(addr);
        // Pays out `amount` of whatever actual token, regardless of T
        // If payout is in APT regardless of T, user can deposit worthless type
        // and claim valuable APT
    }
}
```

### Fixed
```move
module example::reward_vault {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};

    struct RewardBalance<phantom T> has key {
        coins: Coin<T>,
    }

    public entry fun deposit_reward<T>(user: &signer, amount: u64) acquires RewardBalance {
        let addr = signer::address_of(user);
        let deposited = coin::withdraw<T>(user, amount);
        if (exists<RewardBalance<T>>(addr)) {
            let bal = borrow_global_mut<RewardBalance<T>>(addr);
            coin::merge(&mut bal.coins, deposited);
        } else {
            move_to(user, RewardBalance<T> { coins: deposited });
        };
    }

    public entry fun claim_reward<T>(user: &signer) acquires RewardBalance {
        let addr = signer::address_of(user);
        let RewardBalance { coins } = move_from<RewardBalance<T>>(addr);
        // Pays out the same type T that was deposited — no type punning possible
        coin::deposit(addr, coins);
    }
}
```

---

## Pattern 5: Missing Coin Type Registration Check

Operating on `Coin<T>` without verifying that `T` is a properly initialized coin type, leading to aborts or operations on phantom coins.

### Vulnerable
```move
module example::payment {
    use std::signer;
    use aptos_framework::coin;

    struct PaymentConfig<phantom T> has key {
        price: u64,
        treasury: address,
    }

    // BUG: No check that T is an initialized coin
    public entry fun pay<T>(buyer: &signer, amount: u64) acquires PaymentConfig {
        let config = borrow_global<PaymentConfig<T>>(@example);
        // Will abort at runtime if CoinStore<T> doesn't exist for buyer
        // or if T was never registered as a coin
        coin::transfer<T>(buyer, config.treasury, amount);
    }

    // BUG: Creates payment config for potentially non-existent coin
    public entry fun setup_payment<T>(admin: &signer, price: u64, treasury: address) {
        move_to(admin, PaymentConfig<T> { price, treasury });
    }
}
```

### Fixed
```move
module example::payment {
    use std::signer;
    use aptos_framework::coin;

    struct PaymentConfig<phantom T> has key {
        price: u64,
        treasury: address,
    }

    const E_COIN_NOT_INITIALIZED: u64 = 1;
    const E_COIN_STORE_NOT_REGISTERED: u64 = 2;

    public entry fun pay<T>(buyer: &signer, amount: u64) acquires PaymentConfig {
        assert!(coin::is_coin_initialized<T>(), E_COIN_NOT_INITIALIZED);
        let buyer_addr = signer::address_of(buyer);
        assert!(coin::is_account_registered<T>(buyer_addr), E_COIN_STORE_NOT_REGISTERED);
        let config = borrow_global<PaymentConfig<T>>(@example);
        coin::transfer<T>(buyer, config.treasury, amount);
    }

    public entry fun setup_payment<T>(admin: &signer, price: u64, treasury: address) {
        // Verify coin exists before creating config
        assert!(coin::is_coin_initialized<T>(), E_COIN_NOT_INITIALIZED);
        move_to(admin, PaymentConfig<T> { price, treasury });
    }
}
```

---

## Signature
**Slug:** `type-confusion-->logic-bypass`
**Detect:** For every generic type parameter: (1) verify it has appropriate ability constraints, (2) verify phantom types have runtime validation preventing cross-type operations, (3) verify coin types are checked with `is_coin_initialized`, (4) verify generic instantiation cannot access unrelated storage, (5) verify coin registration before operations on `Coin<T>`.
**What's Wrong:** One or more generic type parameters are unconstrained, phantom types lack runtime separation, unregistered coin types are accepted, generic instantiation enables type punning, or coin operations proceed without registration checks.
**Remediation:** Constrain generic types with required abilities. Validate phantom types with runtime checks or witness patterns. Verify type registration with `type_info` or coin registry. Prevent cross-type access via per-type storage isolation. Check coin initialization before operations.

## Classification Reasoning
This invariant detector consolidates all type-safety-related patterns into a single comprehensive check. Type safety issues are fundamental to Move's generic programming model and represent a spectrum of the same core concern: ensuring type parameters are properly validated and constrained to prevent confusion and unauthorized access. The five patterns cover the main ways type safety can be violated in Aptos Move.

---
