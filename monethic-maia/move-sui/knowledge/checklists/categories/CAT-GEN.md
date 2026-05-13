# CAT-GEN — General Logic

## CL-GEN-01: Error Handling

**Rule:** `MOVE-GEN-ABORT-01`
**Severity:** Informational-Low

### Description
Error codes are duplicated across assertions within or across functions, making it impossible to determine which condition caused a transaction abort. Duplicate error codes make debugging impossible — when a transaction aborts, the error code cannot pinpoint which specific assertion failed.

### Patterns

#### Pattern 1: Duplicate Error Codes
Multiple `assert!` statements use the same numeric error code, making it impossible to determine which condition failed when a transaction aborts.

**Vulnerable:**
```move
module example::marketplace {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};

    struct Listing has key {
        id: UID,
        seller: address,
        price: u64,
        active: bool,
    }

    public fun purchase(listing: &mut Listing, ctx: &mut TxContext) {
        let buyer_addr = tx_context::sender(ctx);
        // BUG: All three assertions use error code 1
        // When tx aborts with code 1, impossible to know which check failed
        assert!(listing.active, 1);
        assert!(buyer_addr != listing.seller, 1);
        assert!(listing.price > 0, 1);
        listing.active = false;
    }

    public fun cancel(listing: &mut Listing, ctx: &mut TxContext) {
        // BUG: Same error code 1 as purchase — even across functions
        assert!(tx_context::sender(ctx) == listing.seller, 1);
        assert!(listing.active, 1);
        listing.active = false;
    }
}
```

**Fixed:**
```move
module example::marketplace {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};

    struct Listing has key {
        id: UID,
        seller: address,
        price: u64,
        active: bool,
    }

    const E_LISTING_NOT_ACTIVE: u64 = 1;
    const E_BUYER_IS_SELLER: u64 = 2;
    const E_ZERO_PRICE: u64 = 3;
    const E_NOT_SELLER: u64 = 4;

    public fun purchase(listing: &mut Listing, ctx: &mut TxContext) {
        let buyer_addr = tx_context::sender(ctx);
        // Each assertion has a unique, descriptive error code
        assert!(listing.active, E_LISTING_NOT_ACTIVE);
        assert!(buyer_addr != listing.seller, E_BUYER_IS_SELLER);
        assert!(listing.price > 0, E_ZERO_PRICE);
        listing.active = false;
    }

    public fun cancel(listing: &mut Listing, ctx: &mut TxContext) {
        assert!(tx_context::sender(ctx) == listing.seller, E_NOT_SELLER);
        assert!(listing.active, E_LISTING_NOT_ACTIVE);
        listing.active = false;
    }
}
```

### Remediation
Use unique named error code constants for every assertion across the module.

### Signature
**Slug:** `improper-abort-->unexpected-halt`
**Detect:** For every module: verify all error codes are unique across all `assert!` and `abort` statements.
**What's Wrong:** Multiple assertions share the same error code, making it impossible to identify which check failed.
**Remediation:** Use unique named error code constants for every assertion across the module.

---

## CL-GEN-02: Data Structure Integrity

**Rule:** `MOVE-GEN-DATA-01`
**Severity:** Low-High

### Description
Collections grow without bounds, indices are accessed without validation, keys collide on insertion, order-dependent logic uses unordered removal, or correlated collections are not kept in sync on deletion. Unbounded growth causes gas exhaustion and denial of service on iteration. Out-of-bounds access aborts transactions. Key collisions silently overwrite data. Unordered removal breaks index-based references. Stale entries in correlated collections cause phantom data and incorrect lookups.

### Patterns

#### Pattern 1: Unbounded Vector Growth
A vector grows with each user action without any length cap, eventually causing gas exhaustion when the vector is iterated.

**Vulnerable:**
```move
module example::whitelist {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;
    use std::vector;

    struct Whitelist has key {
        id: UID,
        addresses: vector<address>,
    }

    public fun add_to_whitelist(wl: &mut Whitelist, addr: address) {
        // BUG: No length cap — vector grows indefinitely
        // Any function that iterates over this vector will eventually exceed gas limits
        vector::push_back(&mut wl.addresses, addr);
    }

    public fun is_whitelisted(wl: &Whitelist, addr: address): bool {
        // This iteration becomes prohibitively expensive as the vector grows
        vector::contains(&wl.addresses, &addr)
    }
}
```

**Fixed:**
```move
module example::whitelist {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;
    use sui::table::{Self, Table};

    const MAX_WHITELIST_SIZE: u64 = 1000;
    const E_WHITELIST_FULL: u64 = 1;

    struct Whitelist has key {
        id: UID,
        addresses: Table<address, bool>,
        count: u64,
    }

    public fun add_to_whitelist(wl: &mut Whitelist, addr: address) {
        assert!(wl.count < MAX_WHITELIST_SIZE, E_WHITELIST_FULL);
        if (!table::contains(&wl.addresses, addr)) {
            table::add(&mut wl.addresses, addr, true);
            wl.count = wl.count + 1;
        };
    }

    public fun is_whitelisted(wl: &Whitelist, addr: address): bool {
        table::contains(&wl.addresses, addr)
    }
}
```

#### Pattern 2: Vector Index Out of Bounds
Accessing a vector element by index without checking that the index is within the valid range causes the transaction to abort.

**Vulnerable:**
```move
module example::queue {
    use sui::object::{Self, UID};
    use std::vector;

    struct TaskQueue has key {
        id: UID,
        tasks: vector<Task>,
    }

    struct Task has store, drop {
        task_id: u64,
        priority: u8,
    }

    public fun get_task(queue: &TaskQueue, index: u64): (u64, u8) {
        // BUG: No bounds check — aborts if index >= vector length
        let task = vector::borrow(&queue.tasks, index);
        (task.task_id, task.priority)
    }

    public fun remove_task(queue: &mut TaskQueue, index: u64): Task {
        // BUG: No bounds check before swap_remove
        vector::swap_remove(&mut queue.tasks, index)
    }
}
```

**Fixed:**
```move
module example::queue {
    use sui::object::{Self, UID};
    use std::vector;

    struct TaskQueue has key {
        id: UID,
        tasks: vector<Task>,
    }

    struct Task has store, drop {
        task_id: u64,
        priority: u8,
    }

    const E_INDEX_OUT_OF_BOUNDS: u64 = 1;

    public fun get_task(queue: &TaskQueue, index: u64): (u64, u8) {
        assert!(index < vector::length(&queue.tasks), E_INDEX_OUT_OF_BOUNDS);
        let task = vector::borrow(&queue.tasks, index);
        (task.task_id, task.priority)
    }

    public fun remove_task(queue: &mut TaskQueue, index: u64): Task {
        assert!(index < vector::length(&queue.tasks), E_INDEX_OUT_OF_BOUNDS);
        vector::swap_remove(&mut queue.tasks, index)
    }
}
```

#### Pattern 3: Table Key Collision
Calling `table::add` without first checking if the key already exists causes an abort when a duplicate key is inserted.

**Vulnerable:**
```move
module example::accounts {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::table::{Self, Table};

    struct AccountBook has key {
        id: UID,
        records: Table<address, AccountRecord>,
    }

    struct AccountRecord has store, drop {
        balance: u64,
        created_at: u64,
    }

    public fun create_account(
        book: &mut AccountBook,
        initial_balance: u64,
        timestamp: u64,
        ctx: &mut TxContext
    ) {
        let addr = tx_context::sender(ctx);
        // BUG: Aborts if user already has a record — table::add fails on existing key
        table::add(&mut book.records, addr, AccountRecord {
            balance: initial_balance,
            created_at: timestamp,
        });
    }
}
```

**Fixed:**
```move
module example::accounts {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::table::{Self, Table};

    struct AccountBook has key {
        id: UID,
        records: Table<address, AccountRecord>,
    }

    struct AccountRecord has store, drop {
        balance: u64,
        created_at: u64,
    }

    const E_ACCOUNT_EXISTS: u64 = 1;

    public fun create_account(
        book: &mut AccountBook,
        initial_balance: u64,
        timestamp: u64,
        ctx: &mut TxContext
    ) {
        let addr = tx_context::sender(ctx);
        // Check before add to prevent collision abort
        assert!(!table::contains(&book.records, addr), E_ACCOUNT_EXISTS);
        table::add(&mut book.records, addr, AccountRecord {
            balance: initial_balance,
            created_at: timestamp,
        });
    }
}
```

#### Pattern 4: Swap-Remove Order Dependency
Using `vector::swap_remove` on a vector where element order matters breaks external index-based references, since swap_remove moves the last element into the removed position.

**Vulnerable:**
```move
module example::auction {
    use sui::object::{Self, UID};
    use std::vector;

    struct AuctionHouse has key {
        id: UID,
        bids: vector<Bid>,
    }

    struct Bid has store, drop {
        bidder: address,
        amount: u64,
    }

    struct BidReceipt has key {
        id: UID,
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

**Fixed:**
```move
module example::auction {
    use sui::object::{Self, UID};
    use sui::table::{Self, Table};
    use sui::tx_context::TxContext;

    struct AuctionHouse has key {
        id: UID,
        bids: Table<u64, Bid>,
        next_bid_id: u64,
    }

    struct Bid has store, drop {
        bidder: address,
        amount: u64,
    }

    struct BidReceipt has key {
        id: UID,
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

#### Pattern 5: Missing Table Entry Cleanup
Removing an entry from one collection but leaving stale entries in a correlated collection, causing phantom lookups and inconsistent state.

**Vulnerable:**
```move
module example::dao {
    use sui::object::{Self, UID};
    use sui::table::{Self, Table};
    use std::vector;

    struct DAO has key {
        id: UID,
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

**Fixed:**
```move
module example::dao {
    use sui::object::{Self, UID};
    use sui::table::{Self, Table};
    use std::vector;

    struct DAO has key {
        id: UID,
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

### Remediation
Cap vector lengths. Validate indices before access. Check key existence before table insertion. Use indexed removal only when order is irrelevant. Clean up all correlated collections on deletion.

### Signature
**Slug:** `data-structure-misuse-->corruption`
**Detect:** For every collection operation: (1) verify vectors have growth caps or use bounded alternatives, (2) verify index access is bounds-checked, (3) verify table insertions check for existing keys, (4) verify swap_remove is not used when order matters, (5) verify correlated collections are cleaned up together.
**What's Wrong:** One or more collection operations allow unbounded growth, access unchecked indices, collide on key insertion, break order invariants via swap_remove, or leave stale entries in correlated collections.
**Remediation:** Cap vector lengths. Validate indices before access. Check key existence before table insertion. Use indexed removal only when order is irrelevant. Clean up all correlated collections on deletion.

---

## CL-GEN-03: Event Emission

**Rule:** `MOVE-GEN-EVT-01`
**Severity:** Informational-Low

### Description
Events are missing, use wrong parameters, capture pre-update state, or are absent from some execution paths. Off-chain indexers, explorers, monitoring bots, and front-ends receive incomplete or incorrect data, leading to state desynchronization, broken UIs, missed alerts, and inability to reconstruct on-chain history.

### Patterns

#### Pattern 1: Missing Event Emission on State Change
A state-modifying function has no `sui::event::emit` call. Critical for off-chain indexing, monitoring, and governance transparency.

**Vulnerable:**
```move
module example::config {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};

    struct Config has key {
        id: UID,
        admin: address,
        fee_bps: u64,
        paused: bool,
    }

    public fun update_fee(config: &mut Config, new_fee: u64, ctx: &mut TxContext) {
        // BUG: No event emitted — off-chain systems cannot detect fee changes
        config.fee_bps = new_fee;
    }

    public fun set_paused(config: &mut Config, paused: bool, ctx: &mut TxContext) {
        // BUG: No event emitted — pause state change is invisible
        config.paused = paused;
    }
}
```

**Fixed:**
```move
module example::config {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::event;

    struct Config has key {
        id: UID,
        admin: address,
        fee_bps: u64,
        paused: bool,
    }

    struct FeeUpdatedEvent has copy, drop {
        old_fee: u64,
        new_fee: u64,
    }

    struct PauseStateChanged has copy, drop {
        paused: bool,
    }

    public fun update_fee(config: &mut Config, new_fee: u64, ctx: &mut TxContext) {
        let old_fee = config.fee_bps;
        config.fee_bps = new_fee;
        event::emit(FeeUpdatedEvent { old_fee, new_fee });
    }

    public fun set_paused(config: &mut Config, paused: bool, ctx: &mut TxContext) {
        config.paused = paused;
        event::emit(PauseStateChanged { paused });
    }
}
```

#### Pattern 2: Event Emitted with Pre-Mutation Values
Event is fired before the state mutation or uses values captured before the update, so it logs stale data rather than the actual post-change state.

**Vulnerable:**
```move
module example::staking {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::event;

    struct StakePool has key {
        id: UID,
        total_staked: u64,
    }

    struct UserStake has key {
        id: UID,
        amount: u64,
    }

    struct StakeEvent has copy, drop {
        user: address,
        total_staked: u64,
        user_balance: u64,
    }

    public fun stake(
        pool: &mut StakePool,
        user_stake: &mut UserStake,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let addr = tx_context::sender(ctx);

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

**Fixed:**
```move
module example::staking {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::event;

    struct StakePool has key {
        id: UID,
        total_staked: u64,
    }

    struct UserStake has key {
        id: UID,
        amount: u64,
    }

    struct StakeEvent has copy, drop {
        user: address,
        total_staked: u64,
        user_balance: u64,
    }

    public fun stake(
        pool: &mut StakePool,
        user_stake: &mut UserStake,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let addr = tx_context::sender(ctx);

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

#### Pattern 3: Missing Event Emission in Module Init
The `init` function creates shared objects but emits no event, making it impossible for off-chain systems to discover the newly created shared objects.

**Vulnerable:**
```move
module example::marketplace {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    struct MARKETPLACE has drop {}

    struct MarketState has key {
        id: UID,
        fee_bps: u64,
    }

    // BUG: No event emitted — off-chain indexers cannot discover the shared object
    fun init(_witness: MARKETPLACE, ctx: &mut TxContext) {
        transfer::share_object(MarketState {
            id: object::new(ctx),
            fee_bps: 30,
        });
    }
}
```

**Fixed:**
```move
module example::marketplace {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::event;

    struct MARKETPLACE has drop {}

    struct MarketState has key {
        id: UID,
        fee_bps: u64,
    }

    struct MarketCreatedEvent has copy, drop {
        market_id: address,
        fee_bps: u64,
    }

    fun init(_witness: MARKETPLACE, ctx: &mut TxContext) {
        let uid = object::new(ctx);
        let market_id = object::uid_to_address(&uid);
        transfer::share_object(MarketState {
            id: uid,
            fee_bps: 30,
        });
        event::emit(MarketCreatedEvent { market_id, fee_bps: 30 });
    }
}
```

#### Pattern 4: Inconsistent Event Fields
Event struct fields do not match the actual data being recorded, either due to missing fields, wrong field types, or fields that do not capture the full context of the operation.

**Vulnerable:**
```move
module example::swap {
    use sui::tx_context::{Self, TxContext};
    use sui::event;

    struct SwapEvent has copy, drop {
        user: address,
        amount_in: u64,
        // BUG: Missing amount_out — cannot determine swap result
        // BUG: Missing token types — cannot identify which pair was swapped
    }

    public fun swap(
        amount_in: u64,
        min_out: u64,
        ctx: &mut TxContext
    ) {
        let addr = tx_context::sender(ctx);
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

**Fixed:**
```move
module example::swap {
    use sui::tx_context::{Self, TxContext};
    use sui::event;
    use std::string::String;

    struct SwapEvent has copy, drop {
        user: address,
        token_in: String,
        token_out: String,
        amount_in: u64,
        amount_out: u64,
        fee: u64,
    }

    public fun swap(
        amount_in: u64,
        min_out: u64,
        ctx: &mut TxContext
    ) {
        let addr = tx_context::sender(ctx);
        let fee = amount_in * 3 / 1000;
        let amount_out = calculate_output(amount_in);

        // Event captures all relevant swap details
        event::emit(SwapEvent {
            user: addr,
            token_in: std::string::utf8(b"SUI"),
            token_out: std::string::utf8(b"USDC"),
            amount_in,
            amount_out,
            fee,
        });
    }

    fun calculate_output(amount_in: u64): u64 { amount_in * 997 / 1000 }
}
```

#### Pattern 5: Missing Events in Conditional Branches
Event emitted on one code path but not another that also modifies state, leaving some operations invisible to off-chain observers.

**Vulnerable:**
```move
module example::rewards {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::event;

    struct RewardPool has key {
        id: UID,
        balance: u64,
        distributed: u64,
    }

    struct RewardClaimed has copy, drop {
        user: address,
        amount: u64,
    }

    public fun claim_reward(pool: &mut RewardPool, amount: u64, ctx: &mut TxContext) {
        let addr = tx_context::sender(ctx);

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

**Fixed:**
```move
module example::rewards {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::event;

    struct RewardPool has key {
        id: UID,
        balance: u64,
        distributed: u64,
    }

    struct RewardClaimed has copy, drop {
        user: address,
        amount: u64,
        partial: bool,
    }

    public fun claim_reward(pool: &mut RewardPool, amount: u64, ctx: &mut TxContext) {
        let addr = tx_context::sender(ctx);

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

### Remediation
Emit events for all state changes. Use post-mutation values. Ensure event struct fields match recorded data. Cover all conditional branches with event emission.

### Signature
**Slug:** `missing-events-->silent-state-change`
**Detect:** For every state-modifying function: (1) verify an event is emitted via `sui::event::emit`, (2) verify event parameters match post-mutation state, (3) verify `init` emits events for created shared objects, (4) verify event struct fields capture full operation context, (5) verify all conditional branches emit events.
**What's Wrong:** One or more state-modifying functions lack event emission, emit pre-mutation values, miss events in init, have incomplete event fields, or skip events in some code paths.
**Remediation:** Emit events for all state changes. Use post-mutation values. Emit events in `init` for shared object creation. Ensure event struct fields match recorded data. Cover all conditional branches with event emission.

---

## CL-GEN-04: Initialization Safety

**Rule:** `MOVE-GEN-INIT-01`
**Severity:** Medium-High

### Description
The `init` function is missing, public initialization functions are callable by anyone, initialization is incomplete, setup functions are re-callable, or initialization depends on external state that may not exist. Modules fail to function because required shared objects are absent. Attackers front-run initialization to gain admin privileges. Partial setup leaves the module in a broken state. Re-initialization resets critical state. External dependencies cause initialization failures.

### Patterns

#### Pattern 1: Missing `init` Function
A module requires shared objects to function but has no `init` function, leaving the module in an unusable state until someone manually calls setup.

**Vulnerable:**
```move
module example::lending {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;

    struct LendingPool has key {
        id: UID,
        total_deposited: u64,
        total_borrowed: u64,
        interest_rate_bps: u64,
    }

    struct AdminCap has key {
        id: UID,
    }

    // BUG: No init function — LendingPool and AdminCap never created
    // All functions expecting these shared objects will fail

    public fun deposit(pool: &mut LendingPool, amount: u64) {
        // Fails: LendingPool shared object doesn't exist
        pool.total_deposited = pool.total_deposited + amount;
    }

    public fun set_interest_rate(
        _admin: &AdminCap,
        pool: &mut LendingPool,
        rate: u64
    ) {
        // Fails: AdminCap was never created
        pool.interest_rate_bps = rate;
    }
}
```

**Fixed:**
```move
module example::lending {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;

    struct LENDING has drop {}

    struct LendingPool has key {
        id: UID,
        total_deposited: u64,
        total_borrowed: u64,
        interest_rate_bps: u64,
    }

    struct AdminCap has key {
        id: UID,
    }

    // Proper initialization during module deployment using one-time witness
    fun init(_witness: LENDING, ctx: &mut TxContext) {
        transfer::share_object(LendingPool {
            id: object::new(ctx),
            total_deposited: 0,
            total_borrowed: 0,
            interest_rate_bps: 500, // 5% default
        });
        transfer::transfer(AdminCap {
            id: object::new(ctx),
        }, tx_context::sender(ctx));
    }

    public fun deposit(pool: &mut LendingPool, amount: u64) {
        pool.total_deposited = pool.total_deposited + amount;
    }

    public fun set_interest_rate(
        _admin: &AdminCap,
        pool: &mut LendingPool,
        rate: u64
    ) {
        pool.interest_rate_bps = rate;
    }
}
```

#### Pattern 2: Race Condition on Manual Initialize
A public `initialize()` function is callable by anyone, allowing an attacker to front-run the legitimate deployer and gain control of the admin capability.

**Vulnerable:**
```move
module example::governance {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    struct GovernanceConfig has key {
        id: UID,
        admin: address,
        quorum: u64,
        voting_period: u64,
    }

    // BUG: Public function — anyone can call this and become admin
    public fun initialize(quorum: u64, period: u64, ctx: &mut TxContext) {
        // First caller becomes admin — attacker can front-run deployment
        transfer::share_object(GovernanceConfig {
            id: object::new(ctx),
            admin: tx_context::sender(ctx),  // Caller sets themselves as admin
            quorum,
            voting_period: period,
        });
    }
}
```

**Fixed:**
```move
module example::governance {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    struct GOVERNANCE has drop {}

    struct GovernanceConfig has key {
        id: UID,
        admin: address,
        quorum: u64,
        voting_period: u64,
    }

    // Only callable once during module publish via one-time witness — no front-running possible
    fun init(_witness: GOVERNANCE, ctx: &mut TxContext) {
        transfer::share_object(GovernanceConfig {
            id: object::new(ctx),
            admin: tx_context::sender(ctx),
            quorum: 100,
            voting_period: 86400000, // 1 day in milliseconds
        });
    }
}
```

#### Pattern 3: Incomplete `init` Function
The `init` creates some required shared objects but not all, leaving the module partially initialized and causing failures in functions that depend on the missing objects.

**Vulnerable:**
```move
module example::exchange {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    struct EXCHANGE has drop {}

    struct ExchangeState has key {
        id: UID,
        fee_bps: u64,
        paused: bool,
    }

    struct FeeCollector has key {
        id: UID,
        collected: u64,
        treasury: address,
    }

    fun init(_witness: EXCHANGE, ctx: &mut TxContext) {
        // BUG: Only ExchangeState is initialized
        transfer::share_object(ExchangeState {
            id: object::new(ctx),
            fee_bps: 30,
            paused: false,
        });
        // FeeCollector NOT initialized — fee collection will fail
    }

    public fun trade(
        state: &ExchangeState,
        collector: &mut FeeCollector,
        amount: u64
    ) {
        // Fails: FeeCollector shared object doesn't exist
        collector.collected = collector.collected + (amount * state.fee_bps / 10000);
    }
}
```

**Fixed:**
```move
module example::exchange {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    struct EXCHANGE has drop {}

    struct ExchangeState has key {
        id: UID,
        fee_bps: u64,
        paused: bool,
    }

    struct FeeCollector has key {
        id: UID,
        collected: u64,
        treasury: address,
    }

    fun init(_witness: EXCHANGE, ctx: &mut TxContext) {
        let deployer_addr = tx_context::sender(ctx);
        // All required shared objects initialized completely
        transfer::share_object(ExchangeState {
            id: object::new(ctx),
            fee_bps: 30,
            paused: false,
        });
        transfer::share_object(FeeCollector {
            id: object::new(ctx),
            collected: 0,
            treasury: deployer_addr,
        });
    }

    public fun trade(
        state: &ExchangeState,
        collector: &mut FeeCollector,
        amount: u64
    ) {
        collector.collected = collector.collected + (amount * state.fee_bps / 10000);
    }
}
```

#### Pattern 4: Re-Initialization via Public Setup Function
A public setup function can be called again after initial setup, resetting critical state like admin address, accumulated balances, or configuration.

**Vulnerable:**
```move
module example::vault {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    struct VaultConfig has key {
        id: UID,
        admin: address,
        max_capacity: u64,
        total_deposited: u64,
    }

    // BUG: Can be called again after init, creating a second config object
    // or resetting state via a mutable reference
    public fun setup(max_capacity: u64, ctx: &mut TxContext) {
        // Creates a new shared object every time — multiple configs
        transfer::share_object(VaultConfig {
            id: object::new(ctx),
            admin: tx_context::sender(ctx),
            max_capacity,
            total_deposited: 0,
        });
    }
}
```

**Fixed:**
```move
module example::vault {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    struct VAULT has drop {}

    struct VaultConfig has key {
        id: UID,
        admin: address,
        max_capacity: u64,
        total_deposited: u64,
    }

    struct AdminCap has key {
        id: UID,
    }

    // One-time initialization only via witness pattern
    fun init(_witness: VAULT, ctx: &mut TxContext) {
        transfer::share_object(VaultConfig {
            id: object::new(ctx),
            admin: tx_context::sender(ctx),
            max_capacity: 1000000,
            total_deposited: 0,
        });
        transfer::transfer(AdminCap {
            id: object::new(ctx),
        }, tx_context::sender(ctx));
    }

    // Separate function for updating config — requires admin cap, no state reset
    public fun update_capacity(
        _admin: &AdminCap,
        config: &mut VaultConfig,
        new_capacity: u64
    ) {
        // Only update the config field, never reset total_deposited
        config.max_capacity = new_capacity;
    }
}
```

#### Pattern 5: `init` Depends on External State
The initialization function reads from another module's shared object that may not exist yet, causing the entire deployment to abort.

**Vulnerable:**
```move
module example::price_feed {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    struct PRICE_FEED has drop {}

    struct PriceFeedConfig has key {
        id: UID,
        oracle_address: address,
        initial_price: u64,
    }

    struct OracleData has key {
        id: UID,
        price: u64,
        last_updated: u64,
    }

    fun init(_witness: PRICE_FEED, ctx: &mut TxContext) {
        // BUG: Cannot read from an external shared object in init
        // If the oracle object doesn't exist or isn't passed, deployment fails
        // Sui's init function only receives the witness and TxContext
        abort 0 // Would need oracle but can't receive it in init
    }
}
```

**Fixed:**
```move
module example::price_feed {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    struct PRICE_FEED has drop {}

    struct PriceFeedConfig has key {
        id: UID,
        oracle_address: address,
        initial_price: u64,
        oracle_connected: bool,
    }

    struct AdminCap has key {
        id: UID,
    }

    struct OracleData has key {
        id: UID,
        price: u64,
        last_updated: u64,
    }

    fun init(_witness: PRICE_FEED, ctx: &mut TxContext) {
        // Initialize with safe defaults — no external dependencies
        transfer::share_object(PriceFeedConfig {
            id: object::new(ctx),
            oracle_address: @0x0,
            initial_price: 0,
            oracle_connected: false,
        });
        transfer::transfer(AdminCap {
            id: object::new(ctx),
        }, tx_context::sender(ctx));
    }

    // Separate function to connect oracle after both modules are deployed
    public fun connect_oracle(
        _admin: &AdminCap,
        config: &mut PriceFeedConfig,
        oracle: &OracleData,
    ) {
        config.initial_price = oracle.price;
        config.oracle_connected = true;
    }
}
```

### Remediation
Use `init` with the one-time witness pattern for all required setup. Protect public initializers with capability checks. Initialize all required shared objects completely. Guard against re-initialization. Minimize external dependencies during init.

### Signature
**Slug:** `unsafe-init-->state-hijack`
**Detect:** For every module initialization: (1) verify `init` with one-time witness exists for modules requiring shared objects, (2) verify public initializers are not front-runnable, (3) verify all required shared objects are created in `init`, (4) verify setup functions cannot be called again to reset state, (5) verify `init` does not depend on external shared objects that may not exist.
**What's Wrong:** One or more modules lack `init`, expose front-runnable public initializers, perform incomplete initialization, allow re-initialization, or depend on external state during init.
**Remediation:** Use `init` with one-time witness for all required setup. Protect public initializers with capability checks. Initialize all required shared objects completely. Guard against re-initialization. Minimize external dependencies during init.

---

## CL-GEN-05: Resource Management

**Rule:** `MOVE-GEN-RES-01`
**Severity:** Medium-Critical

### Description
Objects are not cleaned up on removal, missing required abilities, shared without uniqueness checks, or become orphaned after module upgrades. Objects become permanently locked or inaccessible, funds are lost due to orphaned objects, or transfers fail due to missing ability constraints.

### Patterns

#### Pattern 1: Object Not Cleaned Up on Destruction
When destroying an object, associated entries in tables, vectors, or other objects are not cleaned up, leading to stale references and potential state corruption.

**Vulnerable:**
```move
module example::registry {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;
    use sui::table::{Self, Table};
    use std::vector;

    struct UserProfile has key {
        id: UID,
        name: vector<u8>,
        score: u64,
    }

    struct Registry has key {
        id: UID,
        users: vector<address>,
        scores: Table<address, u64>,
    }

    public fun remove_user(profile: UserProfile, _registry: &mut Registry) {
        let UserProfile { id, name: _, score: _ } = profile;
        object::delete(id);
        // BUG: Registry.users still contains user address
        // BUG: Registry.scores still has the entry
    }
}
```

**Fixed:**
```move
module example::registry {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::table::{Self, Table};
    use std::vector;

    struct UserProfile has key {
        id: UID,
        name: vector<u8>,
        score: u64,
    }

    struct Registry has key {
        id: UID,
        users: vector<address>,
        scores: Table<address, u64>,
    }

    public fun remove_user(profile: UserProfile, registry: &mut Registry, ctx: &mut TxContext) {
        let user_addr = tx_context::sender(ctx);
        let UserProfile { id, name: _, score: _ } = profile;
        object::delete(id);

        // Clean up all associated entries
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

#### Pattern 2: Missing `store` Ability on Transferable Object
An object intended to be stored inside another struct or transferred between accounts via `public_transfer` lacks the `store` ability, preventing transfers and composition.

**Vulnerable:**
```move
module example::nft {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    // BUG: Missing `store` ability — cannot be transferred via public_transfer
    // or placed in a collection
    struct NFT has key {
        id: UID,
        token_id: u64,
        uri: vector<u8>,
    }

    struct Collection has key, store {
        id: UID,
        items: vector<NFT>, // Compile error: NFT does not have `store`
    }

    public fun mint(token_id: u64, uri: vector<u8>, ctx: &mut TxContext) {
        let nft = NFT { id: object::new(ctx), token_id, uri };
        // Can only use transfer::transfer (module-only), not public_transfer
        transfer::transfer(nft, tx_context::sender(ctx));
    }
}
```

**Fixed:**
```move
module example::nft {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    // Added `store` so NFT can be transferred via public_transfer and embedded in collections
    struct NFT has key, store {
        id: UID,
        token_id: u64,
        uri: vector<u8>,
    }

    struct Collection has key, store {
        id: UID,
        items: vector<NFT>, // Now valid: NFT has `store`
    }

    public fun mint(token_id: u64, uri: vector<u8>, ctx: &mut TxContext) {
        let nft = NFT { id: object::new(ctx), token_id, uri };
        // public_transfer works because NFT has `store`
        transfer::public_transfer(nft, tx_context::sender(ctx));
    }
}
```

#### Pattern 3: Duplicate Shared Object Creation Without Guard
Creating a shared object in a function that may be called multiple times without guarding against duplicate creation causes multiple instances where only one is expected.

**Vulnerable:**
```move
module example::profile {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    struct UserProfile has key {
        id: UID,
        owner: address,
        level: u64,
        reputation: u64,
    }

    public fun create_profile(ctx: &mut TxContext) {
        // BUG: No guard against creating multiple profiles
        // Each call creates a new shared object — no uniqueness check
        transfer::share_object(UserProfile {
            id: object::new(ctx),
            owner: tx_context::sender(ctx),
            level: 1,
            reputation: 0,
        });
    }
}
```

**Fixed:**
```move
module example::profile {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::table::{Self, Table};

    struct ProfileRegistry has key {
        id: UID,
        profiles: Table<address, address>, // owner -> profile object ID
    }

    struct UserProfile has key {
        id: UID,
        owner: address,
        level: u64,
        reputation: u64,
    }

    const E_PROFILE_EXISTS: u64 = 1;

    public fun create_profile(registry: &mut ProfileRegistry, ctx: &mut TxContext) {
        let owner = tx_context::sender(ctx);
        // Guard against duplicate profile creation
        assert!(!table::contains(&registry.profiles, owner), E_PROFILE_EXISTS);
        let uid = object::new(ctx);
        let profile_addr = object::uid_to_address(&uid);
        table::add(&mut registry.profiles, owner, profile_addr);
        transfer::share_object(UserProfile {
            id: uid,
            owner,
            level: 1,
            reputation: 0,
        });
    }
}
```

#### Pattern 4: Orphaned Object After Module Upgrade
When a module is upgraded, if a struct's definition is changed or removed, objects created by the old version become inaccessible, permanently locking any funds or data they contain.

**Vulnerable:**
```move
// Version 1 of the module — deployed and users have created objects
module example::staking_v1 {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    struct StakePosition has key {
        id: UID,
        amount: u64,
        start_time: u64,
    }

    public fun stake(amount: u64, time: u64, ctx: &mut TxContext) {
        transfer::transfer(StakePosition {
            id: object::new(ctx),
            amount,
            start_time: time,
        }, tx_context::sender(ctx));
    }
}

// Version 2 — BUG: StakePosition struct changed, old objects are orphaned
module example::staking_v2 {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};

    // Changed struct layout — old StakePosition objects are now inaccessible
    struct StakePosition has key {
        id: UID,
        amount: u128,          // was u64
        start_time: u64,
        lock_period: u64,      // new field added
        reward_debt: u128,     // new field added
    }
    // Users who staked in v1 can never unstake — funds permanently locked
}
```

**Fixed:**
```move
// Version 1 — design objects with migration in mind
module example::staking {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    struct StakePosition has key {
        id: UID,
        amount: u64,
        start_time: u64,
    }

    // Version 2 adds new object type alongside old one
    struct StakePositionV2 has key {
        id: UID,
        amount: u128,
        start_time: u64,
        lock_period: u64,
        reward_debt: u128,
    }

    // Migration function: converts v1 object to v2
    public fun migrate_position(old: StakePosition, ctx: &mut TxContext) {
        let StakePosition { id, amount, start_time } = old;
        object::delete(id);
        transfer::transfer(StakePositionV2 {
            id: object::new(ctx),
            amount: (amount as u128),
            start_time,
            lock_period: 0,
            reward_debt: 0,
        }, tx_context::sender(ctx));
    }
}
```

### Remediation
Clean up all associated data on object destruction. Ensure transferable objects have `store`. Guard shared object creation with uniqueness checks. Plan object migration for upgrades.

### Signature
**Slug:** `resource-mismanagement-->loss`
**Detect:** For every object operation: (1) verify all associated data is cleaned up on `object::delete`, (2) verify transferable objects have `store` ability, (3) verify shared object creation is guarded against duplicates, (4) verify objects remain accessible after module upgrades.
**What's Wrong:** One or more object operations fail to clean up associated data, miss required abilities, allow duplicate shared object creation, or create orphaned objects on upgrade.
**Remediation:** Clean up all associated data on destruction. Ensure transferable objects have `store`. Guard shared object creation with uniqueness checks. Plan object migration for upgrades.

---

## CL-GEN-06: State Freshness

**Rule:** `MOVE-GEN-STALE-01`
**Severity:** Medium-High

### Description
Global parameters are updated without first settling state under the old parameters, or local state caches are written back after intermediate mutations overwrite them. Retroactive application of new rates/parameters to un-settled periods, or intermediate state changes silently lost when stale local copies are written back.

### Patterns

#### Pattern 1: Stale State Before Parameter Update
Global parameters (interest rate, fee tier, reward rate) are updated without first accruing state under the old parameters, causing retroactive application of new values to the un-accrued period.

**Vulnerable:**
```move
// VULNERABLE: changes rate without accruing under old rate
public fun set_interest_rate(pool: &mut Pool, new_rate: u64) {
    pool.interest_rate = new_rate; // old period now charged at new rate
}
```

**Fixed:**
```move
// FIXED: accrue before update
public fun set_interest_rate(pool: &mut Pool, new_rate: u64, clock: &Clock) {
    accrue_interest(pool, clock); // settle old rate period
    pool.interest_rate = new_rate;
}
```

#### Pattern 2: Stale Cache Overwrite
A function loads state into a local variable, performs operations that modify the global state, then writes the stale local copy back, overwriting intermediate updates.

**Vulnerable:**
```move
// VULNERABLE: local copy overwrites intermediate state changes
public fun process(pool: &mut Pool) {
    let cached_total = pool.total_assets; // cache
    transfer_fees(pool); // modifies pool.total_assets internally
    pool.total_assets = cached_total - withdrawal; // overwrites fee update
}
```

**Fixed:**
```move
// FIXED: re-read after mutations
public fun process(pool: &mut Pool) {
    transfer_fees(pool);
    pool.total_assets = pool.total_assets - withdrawal; // reads current state
}
```

### Remediation
Always settle/accrue state under old parameters before applying new ones. Re-read state after any mutation instead of using cached local copies.

### Signature
**Slug:** `state-freshness-invariant`
**Detect:** For every parameter update or cached state write-back: (1) verify state is accrued/settled under old parameters before applying new ones, (2) verify local state caches are not written back after intermediate mutations.
**What's Wrong:** Parameters are applied retroactively to un-settled periods, or stale local copies overwrite intermediate state changes.
**Remediation:** Accrue before parameter updates. Re-read state after any mutation instead of using cached copies.

---

## CL-GEN-07: State Consistency

**Rule:** `MOVE-GEN-STATE-01`
**Severity:** Medium-High

### Description
State mutations update one part of coupled data without updating the counterpart, hold stale references across mutations, or fail to maintain aggregate invariants. Inconsistent state leads to incorrect balances, broken accounting, exploitable discrepancies between local and global state, and potential fund extraction through state desynchronization.

### Patterns

#### Pattern 1: Partial Struct Field Update
Updating one field of a mutably borrowed object but failing to update its coupled counterpart, creating an inconsistent state.

**Vulnerable:**
```move
module example::pool {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    struct Pool has key {
        id: UID,
        total_shares: u64,
        total_assets: u64,
        last_update_time_ms: u64,
        accumulated_rewards: u64,
    }

    public fun deposit_assets(pool: &mut Pool, amount: u64) {
        // BUG: total_assets updated but total_shares not recalculated
        // and last_update_time_ms not refreshed
        pool.total_assets = pool.total_assets + amount;
        // pool.total_shares should be updated proportionally
        // pool.last_update_time_ms should be set to current time
    }
}
```

**Fixed:**
```move
module example::pool {
    use sui::object::{Self, UID};
    use sui::clock::{Self, Clock};
    use sui::tx_context::TxContext;

    struct Pool has key {
        id: UID,
        total_shares: u64,
        total_assets: u64,
        last_update_time_ms: u64,
        accumulated_rewards: u64,
    }

    public fun deposit_assets(pool: &mut Pool, amount: u64, clock: &Clock) {
        let new_shares = if (pool.total_assets == 0) {
            amount
        } else {
            (amount * pool.total_shares) / pool.total_assets
        };
        // All coupled fields updated together
        pool.total_assets = pool.total_assets + amount;
        pool.total_shares = pool.total_shares + new_shares;
        pool.last_update_time_ms = clock::timestamp_ms(clock);
    }
}
```

#### Pattern 2: Stale Reference After Table Mutation
Holding a reference to a table value while the underlying table is mutated through another path, causing the reference to reflect stale data.

**Vulnerable:**
```move
module example::ledger {
    use sui::object::{Self, UID};
    use sui::table::{Self, Table};

    struct Ledger has key {
        id: UID,
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

**Fixed:**
```move
module example::ledger {
    use sui::object::{Self, UID};
    use sui::table::{Self, Table};

    struct Ledger has key {
        id: UID,
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

#### Pattern 3: Counter/Total Mismatch
A counter is incremented when items are added but not decremented on removal (or vice versa), causing the counter to diverge from the actual count.

**Vulnerable:**
```move
module example::marketplace {
    use sui::object::{Self, UID};
    use std::vector;

    struct Marketplace has key {
        id: UID,
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

**Fixed:**
```move
module example::marketplace {
    use sui::object::{Self, UID};
    use std::vector;

    struct Marketplace has key {
        id: UID,
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

#### Pattern 4: Global State Not Synced With User State
Global aggregate totals in a shared object are not adjusted when individual user object balances change, creating accounting discrepancies exploitable for over-withdrawal.

**Vulnerable:**
```move
module example::staking {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};

    struct GlobalState has key {
        id: UID,
        total_staked: u64,
        reward_per_token: u64,
    }

    struct UserStake has key {
        id: UID,
        amount: u64,
        reward_debt: u64,
    }

    public fun emergency_withdraw(
        user_stake: &mut UserStake,
        _global: &mut GlobalState,
        ctx: &mut TxContext
    ) {
        let withdraw_amount = user_stake.amount;
        user_stake.amount = 0;
        user_stake.reward_debt = 0;
        // BUG: GlobalState.total_staked not decremented
        // reward_per_token calculations will be wrong for all other users
    }
}
```

**Fixed:**
```move
module example::staking {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};

    struct GlobalState has key {
        id: UID,
        total_staked: u64,
        reward_per_token: u64,
    }

    struct UserStake has key {
        id: UID,
        amount: u64,
        reward_debt: u64,
    }

    public fun emergency_withdraw(
        user_stake: &mut UserStake,
        global: &mut GlobalState,
        ctx: &mut TxContext
    ) {
        let withdraw_amount = user_stake.amount;
        user_stake.amount = 0;
        user_stake.reward_debt = 0;

        // Global state synchronized with user state change
        global.total_staked = global.total_staked - withdraw_amount;
    }
}
```

#### Pattern 5: Non-Atomic Multi-Object Update
Updating one shared object successfully but aborting before the second coupled object is updated, leaving the system in a half-mutated state.

**Vulnerable:**
```move
module example::escrow {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    struct EscrowState has key {
        id: UID,
        locked_amount: u64,
        release_count: u64,
    }

    struct UserBalance has key {
        id: UID,
        available: u64,
        locked: u64,
    }

    const E_INSUFFICIENT: u64 = 1;

    public fun release_escrow(
        escrow: &mut EscrowState,
        user_bal: &mut UserBalance,
        amount: u64
    ) {
        // First object updated
        escrow.locked_amount = escrow.locked_amount - amount;
        escrow.release_count = escrow.release_count + 1;

        // BUG: If amount > escrow.locked_amount, the subtraction underflows with
        // an opaque abort code instead of the meaningful E_INSUFFICIENT error.
        // Validation should precede all mutations.
        assert!(user_bal.locked >= amount, E_INSUFFICIENT);
        user_bal.locked = user_bal.locked - amount;
        user_bal.available = user_bal.available + amount;
    }
}
```

**Fixed:**
```move
module example::escrow {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    struct EscrowState has key {
        id: UID,
        locked_amount: u64,
        release_count: u64,
    }

    struct UserBalance has key {
        id: UID,
        available: u64,
        locked: u64,
    }

    const E_INSUFFICIENT: u64 = 1;
    const E_ESCROW_MISMATCH: u64 = 2;

    public fun release_escrow(
        escrow: &mut EscrowState,
        user_bal: &mut UserBalance,
        amount: u64
    ) {
        // Validate all preconditions BEFORE any mutation
        assert!(escrow.locked_amount >= amount, E_ESCROW_MISMATCH);
        assert!(user_bal.locked >= amount, E_INSUFFICIENT);

        // All validations passed — now perform mutations
        escrow.locked_amount = escrow.locked_amount - amount;
        escrow.release_count = escrow.release_count + 1;

        user_bal.locked = user_bal.locked - amount;
        user_bal.available = user_bal.available + amount;
    }
}
```

### Remediation
Update all coupled fields atomically. Avoid holding references across mutations. Maintain counter/total invariants on every add/remove. Synchronize global aggregates with individual state changes. Validate all preconditions before beginning mutations.

### Signature
**Slug:** `state-inconsistency-->corruption`
**Detect:** For every state mutation: (1) verify all coupled struct fields are updated together, (2) verify no stale references are held across table mutations, (3) verify counters/totals are maintained on every add/remove, (4) verify global aggregates stay synchronized with individual state changes, (5) verify multi-object updates validate preconditions before any mutation.
**What's Wrong:** One or more state mutations leave coupled fields out of sync, hold stale references, allow counter drift, desynchronize global and local state, or perform partial updates that can abort mid-way.
**Remediation:** Update all coupled fields atomically. Avoid holding references across mutations. Maintain counter/total invariants on every add/remove. Synchronize global aggregates with individual state changes. Validate all preconditions before beginning mutations.

---

## CL-GEN-08: Timestamp/Deadline Safety

**Rule:** `MOVE-GEN-TIME-01`
**Severity:** Low-High

### Description
Timestamp units are mixed (seconds vs milliseconds), deadlines are stored but never enforced, block timestamps are used for sensitive timing, cached timestamps become stale, or boundary conditions use incorrect comparison operators. Deadlines are bypassed or enforced at wrong times, auctions can be manipulated through block timing, operations proceed with stale time values, and off-by-one errors at boundaries cause incorrect allow/deny decisions.

### Patterns

#### Pattern 1: Seconds vs Milliseconds Mismatch
Mixing `clock::timestamp_ms(clock)` (milliseconds) with second-based values (or vice versa) causes deadline checks to be off by a factor of 1,000.

**Vulnerable:**
```move
module example::vesting {
    use sui::object::{Self, UID};
    use sui::clock::{Self, Clock};
    use sui::tx_context::{Self, TxContext};

    struct VestingSchedule has key {
        id: UID,
        start_time: u64,     // Stored in seconds from another source
        cliff_duration: u64, // Intended as seconds
        total_amount: u64,
        claimed: u64,
    }

    public fun claim(schedule: &mut VestingSchedule, clock: &Clock, ctx: &mut TxContext) {
        // BUG: clock::timestamp_ms returns milliseconds, but start_time is in seconds
        // The cliff check will be wrong by a factor of 1000
        let now = clock::timestamp_ms(clock);
        assert!(now >= schedule.start_time + schedule.cliff_duration, 1);
        // cliff_duration in seconds added to start_time in seconds, but now is in ms
    }
}
```

**Fixed:**
```move
module example::vesting {
    use sui::object::{Self, UID};
    use sui::clock::{Self, Clock};
    use sui::tx_context::{Self, TxContext};

    struct VestingSchedule has key {
        id: UID,
        start_time_ms: u64,     // Explicitly named with unit
        cliff_duration_ms: u64,
        total_amount: u64,
        claimed: u64,
    }

    const E_CLIFF_NOT_REACHED: u64 = 1;

    public fun claim(schedule: &mut VestingSchedule, clock: &Clock, ctx: &mut TxContext) {
        // Consistent units: all in milliseconds
        let now_ms = clock::timestamp_ms(clock);
        assert!(
            now_ms >= schedule.start_time_ms + schedule.cliff_duration_ms,
            E_CLIFF_NOT_REACHED
        );
    }
}
```

#### Pattern 2: Missing Deadline Enforcement
An expiry or deadline timestamp is stored in the resource but never actually checked before allowing the time-gated action.

**Vulnerable:**
```move
module example::proposal {
    use sui::object::{Self, UID};
    use sui::clock::{Self, Clock};
    use sui::tx_context::{Self, TxContext};

    struct Proposal has key {
        id: UID,
        description: vector<u8>,
        votes_for: u64,
        votes_against: u64,
        deadline_ms: u64,  // Voting deadline stored but never checked
    }

    public fun vote(proposal: &mut Proposal, support: bool, _clock: &Clock, ctx: &mut TxContext) {
        // BUG: deadline is never enforced — votes accepted forever
        if (support) {
            proposal.votes_for = proposal.votes_for + 1;
        } else {
            proposal.votes_against = proposal.votes_against + 1;
        };
    }

    public fun execute(proposal: &Proposal, _clock: &Clock) {
        // BUG: Can execute before deadline — no check that voting period ended
        assert!(proposal.votes_for > proposal.votes_against, 1);
    }
}
```

**Fixed:**
```move
module example::proposal {
    use sui::object::{Self, UID};
    use sui::clock::{Self, Clock};
    use sui::tx_context::{Self, TxContext};

    struct Proposal has key {
        id: UID,
        description: vector<u8>,
        votes_for: u64,
        votes_against: u64,
        deadline_ms: u64,
    }

    const E_VOTING_ENDED: u64 = 1;
    const E_VOTING_NOT_ENDED: u64 = 2;

    public fun vote(proposal: &mut Proposal, support: bool, clock: &Clock, ctx: &mut TxContext) {
        // Enforce deadline — reject votes after expiry
        assert!(clock::timestamp_ms(clock) < proposal.deadline_ms, E_VOTING_ENDED);
        if (support) {
            proposal.votes_for = proposal.votes_for + 1;
        } else {
            proposal.votes_against = proposal.votes_against + 1;
        };
    }

    public fun execute(proposal: &Proposal, clock: &Clock) {
        // Ensure voting period has ended before execution
        assert!(clock::timestamp_ms(clock) >= proposal.deadline_ms, E_VOTING_NOT_ENDED);
        assert!(proposal.votes_for > proposal.votes_against, 1);
    }
}
```

#### Pattern 3: Stale Timestamp After Long Transaction
Caching the timestamp at the start of a complex operation and using it for later decisions, where the cached value no longer reflects the current block time after intermediate operations.

**Vulnerable:**
```move
module example::batch_processor {
    use sui::object::{Self, UID};
    use sui::clock::{Self, Clock};
    use sui::tx_context::TxContext;
    use std::vector;

    struct Order has store, drop {
        amount: u64,
        deadline_ms: u64,
        owner: address,
    }

    struct OrderBook has key {
        id: UID,
        orders: vector<Order>,
    }

    public fun process_batch(book: &mut OrderBook, clock: &Clock) {
        // BUG: Timestamp captured once at the start
        let now = clock::timestamp_ms(clock);
        let i = 0;
        let len = vector::length(&book.orders);
        while (i < len) {
            let order = vector::borrow(&book.orders, i);
            // Uses stale `now` for all orders — within the same tx this is
            // technically the same, but the logic error is that `now` should
            // be compared per-order if orders have different time contexts
            if (now < order.deadline_ms) {
                // Process order using stale timestamp for price calculation
                // Price may have changed between order creation and now
            };
            i = i + 1;
        };
    }
}
```

**Fixed:**
```move
module example::batch_processor {
    use sui::object::{Self, UID};
    use sui::clock::{Self, Clock};
    use sui::tx_context::TxContext;
    use std::vector;

    struct Order has store, drop {
        amount: u64,
        deadline_ms: u64,
        owner: address,
        max_price: u64, // User-specified price bound instead of time dependency
    }

    struct OrderBook has key {
        id: UID,
        orders: vector<Order>,
    }

    struct PriceOracle has key {
        id: UID,
        current_price: u64,
        last_updated_ms: u64,
    }

    const E_STALE_PRICE: u64 = 1;

    public fun process_batch(book: &mut OrderBook, oracle: &PriceOracle, clock: &Clock) {
        let now = clock::timestamp_ms(clock);
        // Verify oracle price is fresh before processing batch
        assert!(now - oracle.last_updated_ms < 60000, E_STALE_PRICE);

        let i = 0;
        let len = vector::length(&book.orders);
        while (i < len) {
            let order = vector::borrow(&book.orders, i);
            if (now < order.deadline_ms && oracle.current_price <= order.max_price) {
                // Process with verified fresh price and deadline check
            };
            i = i + 1;
        };
    }
}
```

#### Pattern 4: Off-By-One in Time Window Check
Using `>=` instead of `>` (or vice versa) at time boundaries causes actions to be allowed or denied at the exact boundary moment, leading to edge-case exploits.

**Vulnerable:**
```move
module example::auction {
    use sui::object::{Self, UID};
    use sui::clock::{Self, Clock};
    use sui::tx_context::{Self, TxContext};

    struct Auction has key {
        id: UID,
        highest_bid: u64,
        highest_bidder: address,
        end_time_ms: u64,
        settled: bool,
    }

    const E_AUCTION_ENDED: u64 = 1;
    const E_AUCTION_NOT_ENDED: u64 = 2;

    const E_LOW_BID: u64 = 3;

    public fun place_bid(auction: &mut Auction, amount: u64, clock: &Clock, ctx: &mut TxContext) {
        // BUG: Uses strict `<` — at exactly end_time_ms, bidding is blocked
        assert!(clock::timestamp_ms(clock) < auction.end_time_ms, E_AUCTION_ENDED);
        assert!(amount > auction.highest_bid, E_LOW_BID);
        auction.highest_bid = amount;
        auction.highest_bidder = tx_context::sender(ctx);
    }

    public fun settle(auction: &mut Auction, clock: &Clock) {
        // BUG: Uses strict `>` — at exactly end_time_ms, settlement is also blocked
        // Combined with strict `<` above, there's a dead zone at exactly end_time_ms
        assert!(clock::timestamp_ms(clock) > auction.end_time_ms, E_AUCTION_NOT_ENDED);
        auction.settled = true;
    }
}
```

**Fixed:**
```move
module example::auction {
    use sui::object::{Self, UID};
    use sui::clock::{Self, Clock};
    use sui::tx_context::{Self, TxContext};

    struct Auction has key {
        id: UID,
        highest_bid: u64,
        highest_bidder: address,
        end_time_ms: u64,
        settled: bool,
    }

    const E_AUCTION_ENDED: u64 = 1;
    const E_AUCTION_NOT_ENDED: u64 = 2;

    public fun place_bid(auction: &mut Auction, amount: u64, clock: &Clock, ctx: &mut TxContext) {
        // Strict less-than: bidding allowed only before end_time
        assert!(clock::timestamp_ms(clock) < auction.end_time_ms, E_AUCTION_ENDED);
        assert!(amount > auction.highest_bid, 3);
        auction.highest_bid = amount;
        auction.highest_bidder = tx_context::sender(ctx);
    }

    public fun settle(auction: &mut Auction, clock: &Clock) {
        // Greater-or-equal: settlement allowed at and after end_time
        // No gap between bid window and settle window
        assert!(clock::timestamp_ms(clock) >= auction.end_time_ms, E_AUCTION_NOT_ENDED);
        assert!(!auction.settled, 4);
        auction.settled = true;
    }
}
```

### Remediation
Use consistent timestamp units throughout. Enforce deadlines before allowing gated actions. Refresh timestamps for long operations. Use correct comparison operators at boundaries.

### Signature
**Slug:** `time-misuse-->deadline-bypass`
**Detect:** For every time-dependent operation: (1) verify timestamp units are consistent (milliseconds from `clock::timestamp_ms` throughout), (2) verify stored deadlines are enforced before gated actions, (3) verify timestamps are fresh for time-sensitive decisions, (4) verify comparison operators at time boundaries are correct.
**What's Wrong:** One or more time-dependent operations mix timestamp units, store but never enforce deadlines, rely on stale timestamps, or have off-by-one errors at time boundaries.
**Remediation:** Use consistent timestamp units throughout. Enforce deadlines before allowing gated actions. Refresh timestamps for long operations. Use correct comparison operators at boundaries.

---

## CL-GEN-09: Type Safety

**Rule:** `MOVE-GEN-TYPE-01`
**Severity:** Medium-High

### Description
Generic type parameters are unconstrained, phantom types lack runtime validation, type identity is not verified against a registry, generic instantiation enables cross-type storage access, or coin type registration is not checked before operations. Type confusion allows unauthorized access to unrelated storage, bypass of access controls through arbitrary type instantiation, operations on unregistered or invalid tokens, and logic errors from unconstrained generic parameters.

### Patterns

#### Pattern 1: Unconstrained Generic Type Parameter
A generic function accepts any type `T` without requiring it to satisfy specific abilities, allowing callers to pass types that may cause runtime errors or unintended behavior.

**Vulnerable:**
```move
module example::storage {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    struct Vault<T> has key {
        id: UID,
        contents: T,
    }

    // BUG: T has no ability constraints — caller can pass a type without
    // `store` or `drop`, causing issues when the Vault is transferred or destroyed
    public fun store_item<T>(item: T, ctx: &mut TxContext) {
        transfer::transfer(Vault<T> {
            id: object::new(ctx),
            contents: item,
        }, tx_context::sender(ctx));
    }
}
```

**Fixed:**
```move
module example::storage {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    struct Vault<T: store> has key, store {
        id: UID,
        contents: T,
    }

    // T must have `store` to be placed in an object
    public fun store_item<T: store>(item: T, ctx: &mut TxContext) {
        transfer::public_transfer(Vault<T> {
            id: object::new(ctx),
            contents: item,
        }, tx_context::sender(ctx));
    }

    public fun extract_item<T: store>(vault: Vault<T>): T {
        let Vault { id, contents } = vault;
        object::delete(id);
        contents
    }
}
```

#### Pattern 2: Phantom Type Parameter Misuse
A phantom type parameter is used for logical grouping or namespacing, but no runtime check prevents cross-type operations, allowing one pool's logic to affect another.

**Vulnerable:**
```move
module example::multi_pool {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};

    // phantom T is supposed to separate pools for different tokens
    struct Pool<phantom T> has key {
        id: UID,
        balance: u64,
        reward_rate: u64,
    }

    // BUG: Nothing prevents calling deposit<CoinA> and then
    // withdraw<CoinB> — phantom types provide no runtime separation
    public fun deposit<T>(pool: &mut Pool<T>, amount: u64) {
        pool.balance = pool.balance + amount;
    }

    public fun withdraw<T>(pool: &mut Pool<T>, amount: u64) {
        pool.balance = pool.balance - amount;
        // Actual token transfer uses the same generic T but
        // user's deposit was tracked under a different T
    }
}
```

**Fixed:**
```move
module example::multi_pool {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::table::{Self, Table};

    struct Pool<phantom T> has key {
        id: UID,
        balance: u64,
        reward_rate: u64,
        user_deposits: Table<address, u64>,
    }

    public fun deposit<T>(pool: &mut Pool<T>, amount: u64, ctx: &mut TxContext) {
        let addr = tx_context::sender(ctx);
        pool.balance = pool.balance + amount;
        // Track per-user deposits under the specific type T
        if (table::contains(&pool.user_deposits, addr)) {
            let current = table::borrow_mut(&mut pool.user_deposits, addr);
            *current = *current + amount;
        } else {
            table::add(&mut pool.user_deposits, addr, amount);
        };
    }

    public fun withdraw<T>(pool: &mut Pool<T>, amount: u64, ctx: &mut TxContext) {
        let addr = tx_context::sender(ctx);
        // Validate withdrawal against user's deposit under this specific type
        let user_bal = table::borrow_mut(&mut pool.user_deposits, addr);
        assert!(*user_bal >= amount, 1);
        *user_bal = *user_bal - amount;
        pool.balance = pool.balance - amount;
    }
}
```

#### Pattern 3: Missing Type Validation
Accepting an arbitrary generic `CoinType` without verifying it corresponds to a registered coin, allowing operations on non-existent or malicious token types.

**Vulnerable:**
```move
module example::dex {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::coin::{Self, Coin};

    struct LiquidityPool<phantom X, phantom Y> has key {
        id: UID,
        reserve_x: u64,
        reserve_y: u64,
    }

    // BUG: No validation that X and Y are actual registered coin types
    // Attacker can create a pool with arbitrary types
    public fun create_pool<X, Y>(ctx: &mut TxContext) {
        transfer::share_object(LiquidityPool<X, Y> {
            id: object::new(ctx),
            reserve_x: 0,
            reserve_y: 0,
        });
    }

    public fun add_liquidity<X, Y>(
        pool: &mut LiquidityPool<X, Y>,
        amount_x: u64,
        amount_y: u64
    ) {
        // Operates on potentially fake coin types
        pool.reserve_x = pool.reserve_x + amount_x;
        pool.reserve_y = pool.reserve_y + amount_y;
    }
}
```

**Fixed:**
```move
module example::dex {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::coin::{Self, Coin};
    use std::type_name;

    struct LiquidityPool<phantom X, phantom Y> has key {
        id: UID,
        reserve_x: u64,
        reserve_y: u64,
    }

    const E_SAME_COIN: u64 = 1;

    public fun create_pool<X, Y>(ctx: &mut TxContext) {
        // Ensure X and Y are different types
        assert!(
            type_name::get<X>() != type_name::get<Y>(),
            E_SAME_COIN
        );
        transfer::share_object(LiquidityPool<X, Y> {
            id: object::new(ctx),
            reserve_x: 0,
            reserve_y: 0,
        });
    }

    public fun add_liquidity<X, Y>(
        pool: &mut LiquidityPool<X, Y>,
        coin_x: Coin<X>,
        coin_y: Coin<Y>,
    ) {
        // Accept actual Coin objects to ensure types are real coins
        let amount_x = coin::value(&coin_x);
        let amount_y = coin::value(&coin_y);
        pool.reserve_x = pool.reserve_x + amount_x;
        pool.reserve_y = pool.reserve_y + amount_y;
        // ... handle coins
    }
}
```

#### Pattern 4: Type-Punning via Generic Instantiation
The same generic function called with different type parameters accesses logically unrelated storage, enabling a user to manipulate one type's data through another type's interface.

**Vulnerable:**
```move
module example::reward_vault {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    struct RewardBalance<phantom T> has key {
        id: UID,
        amount: u64,
    }

    // BUG: User deposits as type A, then claims as type B
    // Both create separate RewardBalance objects, but the
    // claim logic doesn't verify the type matches the deposit
    public fun deposit_reward<T>(amount: u64, ctx: &mut TxContext) {
        transfer::transfer(RewardBalance<T> {
            id: object::new(ctx),
            amount,
        }, tx_context::sender(ctx));
    }

    public fun claim_reward<T>(reward: RewardBalance<T>): u64 {
        let RewardBalance { id, amount } = reward;
        object::delete(id);
        // Pays out `amount` of whatever actual token, regardless of T
        // If payout is in SUI regardless of T, user can deposit worthless type
        // and claim valuable SUI
        amount
    }
}
```

**Fixed:**
```move
module example::reward_vault {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};

    struct RewardBalance<phantom T> has key {
        id: UID,
        coins: Balance<T>,
    }

    public fun deposit_reward<T>(coin: Coin<T>, ctx: &mut TxContext) {
        transfer::transfer(RewardBalance<T> {
            id: object::new(ctx),
            coins: coin::into_balance(coin),
        }, tx_context::sender(ctx));
    }

    public fun claim_reward<T>(reward: RewardBalance<T>, ctx: &mut TxContext): Coin<T> {
        let RewardBalance { id, coins } = reward;
        object::delete(id);
        // Pays out the same type T that was deposited — no type punning possible
        coin::from_balance(coins, ctx)
    }
}
```

#### Pattern 5: Missing Coin Type Existence Check
Operating on `Coin<T>` without verifying that `T` is a proper coin type with a treasury cap, leading to operations on phantom coins.

**Vulnerable:**
```move
module example::payment {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::coin::{Self, Coin};

    struct PaymentConfig<phantom T> has key {
        id: UID,
        price: u64,
        treasury: address,
    }

    // BUG: No check that T is a legitimate coin type
    public fun pay<T>(
        config: &PaymentConfig<T>,
        payment: Coin<T>,
        ctx: &mut TxContext
    ) {
        // Accepts any Coin<T> without validating T
        assert!(coin::value(&payment) >= config.price, 1);
        transfer::public_transfer(payment, config.treasury);
    }

    // BUG: Creates payment config for potentially non-existent coin
    public fun setup_payment<T>(price: u64, treasury: address, ctx: &mut TxContext) {
        transfer::share_object(PaymentConfig<T> {
            id: object::new(ctx),
            price,
            treasury,
        });
    }
}
```

**Fixed:**
```move
module example::payment {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::coin::{Self, Coin, TreasuryCap};

    struct PaymentConfig<phantom T> has key {
        id: UID,
        price: u64,
        treasury: address,
    }

    const E_INSUFFICIENT_PAYMENT: u64 = 1;

    public fun pay<T>(
        config: &PaymentConfig<T>,
        payment: Coin<T>,
        ctx: &mut TxContext
    ) {
        assert!(coin::value(&payment) >= config.price, E_INSUFFICIENT_PAYMENT);
        transfer::public_transfer(payment, config.treasury);
    }

    // Require treasury cap reference to prove coin type is legitimate
    public fun setup_payment<T>(
        _treasury_proof: &TreasuryCap<T>,
        price: u64,
        treasury: address,
        ctx: &mut TxContext
    ) {
        transfer::share_object(PaymentConfig<T> {
            id: object::new(ctx),
            price,
            treasury,
        });
    }
}
```

### Remediation
Constrain generic types with required abilities. Validate phantom types with runtime checks or witness patterns. Verify type registration with `type_name` or coin treasury checks. Prevent cross-type access via per-type storage isolation. Check coin existence before operations.

### Signature
**Slug:** `type-confusion-->logic-bypass`
**Detect:** For every generic type parameter: (1) verify it has appropriate ability constraints, (2) verify phantom types have runtime validation preventing cross-type operations, (3) verify coin types are validated via `Coin<T>` parameters or treasury cap checks, (4) verify generic instantiation cannot access unrelated storage, (5) verify coin type legitimacy before operations.
**What's Wrong:** One or more generic type parameters are unconstrained, phantom types lack runtime separation, unregistered coin types are accepted, generic instantiation enables type punning, or coin operations proceed without validation.
**Remediation:** Constrain generic types with required abilities. Validate phantom types with runtime checks or witness patterns. Verify type registration with `type_name` or treasury cap proof. Prevent cross-type access via per-type storage isolation. Check coin legitimacy before operations.
