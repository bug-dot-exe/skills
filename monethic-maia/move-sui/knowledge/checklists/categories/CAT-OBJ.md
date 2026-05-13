# CAT-OBJ — Object Model

## CL-OBJ-01: Ability & Type Safety

**Rule:** `MOVE-OBJ-ABIL-01`
**Severity:** High-Critical

### Description
Value-bearing objects have copy ability enabling token duplication, obligation objects have drop ability enabling debt destruction, sensitive objects have store enabling unauthorized wrapping/transfer via `public_transfer`, generic type parameters are not validated allowing type confusion attacks, or phantom types are not enforced on coin operations allowing cross-token manipulation. Unlimited token minting via copy ability, debt/obligation destruction via drop, capability exfiltration via store + `public_transfer`, complete pool drainage via type confusion, and accounting corruption via phantom type bypass.

### Patterns

#### Pattern 1: Value Struct Has Copy Ability — Token Duplication
A value-bearing struct (voucher, ticket, reward proof) has the `copy` ability, allowing anyone to duplicate it. An attacker duplicates tokens to drain pools or inflate supply without limit.

> **Note:** On Sui, structs with a `UID` field cannot have `copy` (UID lacks copy). This pattern applies to non-object value structs used as receipts, tickets, or proofs within function calls — any struct without UID that carries economic value.

**Vulnerable:**
```move
module example::rewards {
    use sui::object::{Self, UID};

    // BUG: copy ability on a value-bearing voucher
    // Anyone holding one voucher can duplicate it infinitely
    // (No UID, so copy is allowed by compiler)
    struct RewardVoucher has copy, drop, store {
        pool_id: address,
        amount: u64,
    }

    public fun issue_reward(pool_id: address, amount: u64): RewardVoucher {
        RewardVoucher { pool_id, amount }
    }

    // Attacker: get one voucher, copy it 1000 times, redeem all copies
    public fun redeem(pool: &mut Pool, voucher: RewardVoucher) {
        let RewardVoucher { pool_id, amount } = voucher;
        assert!(pool_id == object::id_address(pool), E_WRONG_POOL);
        // Transfer amount from pool to caller
        // Each copy drains `amount` from the pool
    }
}
```

**Fixed:**
```move
module example::rewards {
    use sui::object::{Self, UID};

    // No copy — voucher cannot be duplicated
    // No drop — voucher must be consumed via redeem
    struct RewardVoucher has store {
        pool_id: address,
        amount: u64,
    }

    public fun issue_reward(pool_id: address, amount: u64): RewardVoucher {
        RewardVoucher { pool_id, amount }
    }

    public fun redeem(pool: &mut Pool, voucher: RewardVoucher) {
        let RewardVoucher { pool_id, amount } = voucher;
        assert!(pool_id == object::id_address(pool), E_WRONG_POOL);
        // Voucher consumed — cannot be redeemed again
    }
}
```

#### Pattern 2: Obligation Struct Has Drop Ability — Debt Destruction
An obligation struct (flash loan receipt, debt record, collateral lock) has the `drop` ability. A borrower silently destroys their debt without repaying, or destroys a collateral lock to unlock assets early. This is the inverse of the hot potato pattern.

> **Note:** On Sui, structs with a `UID` field cannot have `drop` (UID lacks drop). This pattern applies to non-object obligation structs used as receipts within PTBs (the classic hot potato). Any struct without UID that represents an obligation must lack drop.

**Vulnerable:**
```move
module example::flash_loan {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;

    // BUG: FlashReceipt has `drop` — borrower can destroy their obligation
    struct FlashReceipt has drop {
        pool_id: address,
        borrow_amount: u64,
        fee: u64,
    }

    public fun flash_borrow(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ): (Coin<SUI>, FlashReceipt) {
        let coin = coin::take(&mut pool.reserves, amount, ctx);
        let receipt = FlashReceipt {
            pool_id: object::id_address(pool),
            borrow_amount: amount,
            fee: amount / 1000,
        };
        (coin, receipt)
        // Borrower receives coin + receipt
        // Since receipt has `drop`, borrower just drops it — debt vanishes
        // Pool loses the borrowed amount permanently
    }
}
```

**Fixed:**
```move
module example::flash_loan {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;

    // No abilities at all — hot potato pattern
    // Receipt MUST be consumed via flash_repay within the same PTB
    struct FlashReceipt {
        pool_id: address,
        borrow_amount: u64,
        fee: u64,
    }

    public fun flash_borrow(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ): (Coin<SUI>, FlashReceipt) {
        let coin = coin::take(&mut pool.reserves, amount, ctx);
        let receipt = FlashReceipt {
            pool_id: object::id_address(pool),
            borrow_amount: amount,
            fee: amount / 1000,
        };
        (coin, receipt)
    }

    // Only way to consume the FlashReceipt — must repay
    public fun flash_repay(
        pool: &mut Pool,
        receipt: FlashReceipt,
        payment: Coin<SUI>,
    ) {
        let FlashReceipt { pool_id, borrow_amount, fee } = receipt;
        assert!(pool_id == object::id_address(pool), E_WRONG_POOL);
        assert!(coin::value(&payment) >= borrow_amount + fee, E_UNDERPAY);
        balance::join(&mut pool.reserves, coin::into_balance(payment));
    }
}
```

#### Pattern 3: Sui Object Has Store Ability — Unauthorized Wrapping and Transfer
On Sui, `store` ability controls whether an object can be transferred via `transfer::public_transfer` and wrapped inside other objects by any module. A sensitive capability object with `store` can be wrapped in an attacker's struct and moved beyond protocol control. Without `store`, only the defining module can call `transfer::transfer`.

**Vulnerable:**
```move
module example::governance {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    // BUG: AdminCap has `store` — can be wrapped in arbitrary containers
    // and transferred via public_transfer by any module
    struct AdminCap has key, store {
        id: UID,
    }

    // With `store`, attacker wraps AdminCap inside their own struct
    // and transfers it out of the protocol's control:
    // module attacker::theft {
    //     struct Wrapper has key, store { id: UID, stolen_cap: AdminCap }
    //     fun steal(cap: AdminCap, ctx: &mut TxContext) {
    //         let w = Wrapper { id: object::new(ctx), stolen_cap: cap };
    //         transfer::public_transfer(w, @attacker);
    //     }
    // }
}
```

**Fixed:**
```move
module example::governance {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    // key only — AdminCap cannot be wrapped or transferred via public_transfer
    // Only transferable via transfer::transfer (requires defining module)
    struct AdminCap has key {
        id: UID,
    }

    // Controlled transfer within the module only
    public fun transfer_admin(cap: AdminCap, new_admin: address) {
        transfer::transfer(cap, new_admin);
    }
}
```

#### Pattern 4: Generic Type Parameter Not Validated
Functions accepting generic `<T>` (especially `Coin<T>`) don't verify T matches the expected/whitelisted type. This is the #1 critical vulnerability across real Move audits. An attacker deposits worthless FakeUSDC and borrows real assets.

**Vulnerable:**
```move
module example::lending {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::object::{Self, UID};
    use sui::sui::SUI;

    struct Pool has key {
        id: UID,
        reserves: Balance<SUI>,
    }

    // BUG: Accepts ANY CoinType as collateral — no whitelist
    // Attacker creates Coin<FakeToken> with arbitrary value
    public fun deposit_collateral<T>(
        pool: &mut Pool,
        collateral: Coin<T>,
        ctx: &mut TxContext
    ) {
        let value = coin::value(&collateral);
        // Credits collateral value without verifying T is an approved asset
        // Attacker: deposit 1M Coin<FakeToken> -> borrow 1M SUI -> pool drained
    }
}
```

**Fixed:**
```move
module example::lending {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::object::{Self, UID};
    use sui::sui::SUI;

    // Pool is parameterized by the collateral type
    struct Pool<phantom T> has key {
        id: UID,
        reserves: Balance<SUI>,
        collateral: Balance<T>,
    }

    // Type safety: T is bound to the pool's phantom type
    // Only the specific collateral type the pool was created for is accepted
    public fun deposit_collateral<T>(
        pool: &mut Pool<T>,
        collateral: Coin<T>,
        ctx: &mut TxContext
    ) {
        balance::join(&mut pool.collateral, coin::into_balance(collateral));
    }
}
```

#### Pattern 5: Phantom Type Not Enforced on Coin Operations
Coin or balance operations don't leverage the phantom type parameter for safety. Different coin types can be mixed in the same pool or vault, breaking accounting invariants.

**Vulnerable:**
```move
module example::vault {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::object::{Self, UID};
    use sui::sui::SUI;

    struct MultiVault has key {
        id: UID,
        total_value: u64,  // tracks "total" across all coin types — meaningless
    }

    // BUG: Deposits any coin type, credits the same total_value counter
    // No per-type balance tracking
    public fun deposit<T: store>(vault: &mut MultiVault, coin: Coin<T>, ctx: &mut TxContext) {
        vault.total_value = vault.total_value + coin::value(&coin);
        transfer::public_transfer(coin, tx_context::sender(ctx)); // coin accepted but not tracked per-type
    }

    // Withdraw gives SUI regardless of what was deposited
    public fun withdraw(vault: &mut MultiVault, amount: u64, ctx: &mut TxContext): Coin<SUI> {
        vault.total_value = vault.total_value - amount;
        coin::take(&mut vault.sui_reserves, amount, ctx)
        // Deposit FakeToken, withdraw SUI — pool drained
    }
}
```

**Fixed:**
```move
module example::vault {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::object::{Self, UID};

    // Phantom type T enforced on the vault — each coin type has its own vault
    struct TypedVault<phantom T> has key {
        id: UID,
        balance: Balance<T>,
    }

    // Deposit and withdraw are type-safe — can only withdraw what was deposited
    public fun deposit<T>(vault: &mut TypedVault<T>, coin: Coin<T>) {
        balance::join(&mut vault.balance, coin::into_balance(coin));
    }

    public fun withdraw<T>(
        vault: &mut TypedVault<T>,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<T> {
        coin::take(&mut vault.balance, amount, ctx)
    }
}
```

### Remediation
Never give copy to value-bearing objects. Never give drop to obligation objects. Restrict store on sensitive capabilities (use `key` only so only `transfer::transfer` works). Validate all generic type parameters against stored/expected types. Enforce phantom type separation on all coin operations.

### Signature
**Slug:** `ability-type-safety-invariant`
**Detect:** For every struct definition: (1) verify value-bearing objects (coins, NFTs, badges) never have copy ability, (2) verify obligation objects (debts, receipts, locks) never have drop ability, (3) verify sensitive capabilities have `key` only (no `store`) unless wrapping/public_transfer is intentional, (4) verify all generic type parameters are validated against stored or whitelisted types, (5) verify phantom types enforce per-type separation on all coin and balance operations.
**What's Wrong:** One or more value-bearing structs have copy enabling duplication, obligation structs have drop enabling destruction, capabilities have store enabling wrapping/public_transfer, generic types are unvalidated enabling type confusion, or phantom types are not enforced enabling cross-type manipulation.
**Remediation:** Remove copy from value types. Remove drop from obligation types. Remove store from sensitive capabilities. Validate generics against whitelists or phantom-parameterized containers. Enforce per-type balance isolation.

---

## CL-OBJ-02: Hot Potato Pattern Integrity

**Rule:** `MOVE-OBJ-HOT-01`
**Severity:** High-Critical

### Description
Hot potato structs have drop or store abilities allowing obligation destruction or deferral, start functions can be called multiple times resetting snapshots, or cross-module consumption allows forged receipts. Flash loans taken without repayment, obligation destruction bypassing protocol invariants, nested flash loan attacks resetting snapshots to steal funds, and permanent fund loss from receipt forgery.

### Patterns

#### Pattern 1: Hot Potato with Drop or Store Ability
A flash loan receipt struct is given `drop` or `store` ability, breaking the hot potato enforcement. With `drop`, the borrower silently discards the receipt without repaying. With `store`, the receipt can be stored and never consumed.

**Vulnerable:**
```move
module example::flash_loan {
    use sui::object::{Self, UID};

    // BUG: FlashReceipt has `drop` — borrower discards it, never repays
    struct FlashReceipt has drop {
        amount: u64,
        fee: u64,
    }

    struct Pool has key {
        id: UID,
        reserves: Balance<SUI>,
    }

    public fun borrow(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ): (Coin<SUI>, FlashReceipt) {
        let coin = coin::take(&mut pool.reserves, amount, ctx);
        let receipt = FlashReceipt { amount, fee: amount / 100 };
        (coin, receipt)
        // Borrower receives coin + receipt
        // Since receipt has `drop`, borrower can just... drop it
        // and keep the coin. Pool drained.
    }

    public fun repay(
        pool: &mut Pool,
        payment: Coin<SUI>,
        receipt: FlashReceipt,
    ) {
        let FlashReceipt { amount, fee } = receipt;
        assert!(coin::value(&payment) >= amount + fee, E_UNDERPAY);
        balance::join(&mut pool.reserves, coin::into_balance(payment));
    }
}
```

**Fixed:**
```move
module example::flash_loan {
    use sui::object::{Self, UID, ID};

    // No abilities — compiler forces consumption in same PTB
    struct FlashReceipt {
        pool_id: ID,
        amount: u64,
        fee: u64,
    }

    public fun borrow(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ): (Coin<SUI>, FlashReceipt) {
        let coin = coin::take(&mut pool.reserves, amount, ctx);
        let receipt = FlashReceipt {
            pool_id: object::id(pool),
            amount,
            fee: amount / 100,
        };
        (coin, receipt)
        // receipt MUST be consumed by repay() — no other option
    }

    public fun repay(
        pool: &mut Pool,
        payment: Coin<SUI>,
        receipt: FlashReceipt,
    ) {
        let FlashReceipt { pool_id, amount, fee } = receipt;
        assert!(pool_id == object::id(pool), E_WRONG_POOL);
        assert!(coin::value(&payment) >= amount + fee, E_UNDERPAY);
        balance::join(&mut pool.reserves, coin::into_balance(payment));
    }
}
```

#### Pattern 2: Hot Potato State Reset via Nested Operations
The flash loan `start` function can be called multiple times within the same PTB, resetting the vault's saved snapshot each time. The attacker borrows, calls start again to reset the baseline to the depleted balance, then finishes validation against the lower baseline.

**Vulnerable:**
```move
module example::harvest {
    use sui::object::{Self, UID};

    struct Vault has key {
        id: UID,
        reserves: u64,
        saved_reserves: u64,       // snapshot stored in vault, not receipt!
        operation_in_progress: bool,
    }

    struct HarvestOp {}  // hot potato

    public fun start_harvest(vault: &mut Vault, ctx: &TxContext): HarvestOp {
        // BUG: Overwrites saved_reserves every call — no reentrancy guard
        vault.saved_reserves = vault.reserves;
        vault.operation_in_progress = true;
        HarvestOp {}
    }

    // BUG: returned_amount is a user-supplied number, not actual funds
    public fun finish_harvest(
        vault: &mut Vault,
        op: HarvestOp,
        returned_amount: u64,
    ) {
        let min_return = vault.saved_reserves * 98 / 100;
        assert!(returned_amount >= min_return, E_INSUFFICIENT);
        vault.operation_in_progress = false;
        let HarvestOp {} = op;
        // Attacker: start(reserves=1000) -> withdraw 900 -> start again(reserves=100)
        // -> finish(returned_amount=98) -> passes 98% of 100 -> keeps 900
    }
}
```

**Fixed:**
```move
module example::harvest {
    use sui::object::{Self, UID, ID};

    struct Vault has key {
        id: UID,
        reserves: Balance<SUI>,
        operation_in_progress: bool,
    }

    // Hot potato stores the snapshot — not the vault
    struct HarvestOp {
        vault_id: ID,
        snapshot_amount: u64,
    }

    public fun start_harvest(vault: &mut Vault, ctx: &TxContext): HarvestOp {
        // Guard: cannot start if already in progress
        assert!(!vault.operation_in_progress, E_ALREADY_IN_PROGRESS);
        vault.operation_in_progress = true;
        HarvestOp {
            vault_id: object::id(vault),
            snapshot_amount: balance::value(&vault.reserves),
        }
    }

    public fun finish_harvest(
        vault: &mut Vault,
        op: HarvestOp,
        payment: Coin<SUI>,
    ) {
        let HarvestOp { vault_id, snapshot_amount } = op;
        assert!(vault_id == object::id(vault), E_WRONG_VAULT);
        // Verify actual funds returned, not a user-supplied number
        let min_return = snapshot_amount * 98 / 100;
        let current = balance::value(&vault.reserves);
        balance::join(&mut vault.reserves, coin::into_balance(payment));
        assert!(balance::value(&vault.reserves) >= snapshot_amount + min_return - snapshot_amount, E_UNDERPAY);
        vault.operation_in_progress = false;
    }
}
```

#### Pattern 3: Cross-Module Hot Potato Validation Bypass
A hot potato receipt is created in Module A but consumed in Module B. Module B does not properly validate the receipt's contents, allowing an attacker to create a fake receipt from a malicious module that Module B accepts.

**Vulnerable:**
```move
// Module A: legitimate flash loan
module protocol::flash {
    struct FlashReceipt { amount: u64 }

    public fun borrow(pool: &mut Pool, amount: u64, ctx: &mut TxContext): (Coin<SUI>, FlashReceipt) {
        (coin::take(&mut pool.reserves, amount, ctx), FlashReceipt { amount })
    }
}

// Module B: repayment handler — accepts receipts from ANY module
module protocol::repay {
    use protocol::flash::FlashReceipt;

    // BUG: If FlashReceipt struct is public, attacker creates compatible struct
    // in their own module and passes it here
    public fun repay(
        pool: &mut Pool,
        payment: Coin<SUI>,
        receipt: FlashReceipt,
    ) {
        let FlashReceipt { amount } = receipt;
        assert!(coin::value(&payment) >= amount, E_UNDERPAY);
        balance::join(&mut pool.reserves, coin::into_balance(payment));
    }
}
```

**Fixed:**
```move
// Single module handles both borrow and repay — receipt never crosses module boundary
module protocol::flash {
    struct FlashReceipt { pool_id: ID, amount: u64, fee: u64 }

    public fun borrow(pool: &mut Pool, amount: u64, ctx: &mut TxContext): (Coin<SUI>, FlashReceipt) {
        (coin::take(&mut pool.reserves, amount, ctx),
         FlashReceipt { pool_id: object::id(pool), amount, fee: amount * FEE_BPS / 10000 })
    }

    // Same module — receipt type cannot be forged from outside
    public fun repay(
        pool: &mut Pool,
        payment: Coin<SUI>,
        receipt: FlashReceipt,
    ) {
        let FlashReceipt { pool_id, amount, fee } = receipt;
        assert!(pool_id == object::id(pool), E_WRONG_POOL);
        assert!(coin::value(&payment) >= amount + fee, E_UNDERPAY);
        balance::join(&mut pool.reserves, coin::into_balance(payment));
    }
}
```

### Remediation
Ensure hot potato structs have zero abilities (no copy, drop, store, or key). Guard start functions with active-operation flags. Store snapshot amounts inside the hot potato, not in the vault. Keep receipt lifecycle in a single module.

### Signature
**Slug:** `hot-potato-integrity-invariant`
**Detect:** For every hot potato struct: (1) verify it has zero abilities (no copy, drop, store, key), (2) verify start/borrow functions check for existing active operations, (3) verify receipt creation and consumption happen in the same module.
**What's Wrong:** One or more hot potato structs have abilities enabling obligation bypass, start functions allow re-entry resetting snapshots, or receipts cross module boundaries without validation.
**Remediation:** Strip all abilities from receipt structs. Add active-operation guards. Keep receipt lifecycle in single module.

---

## CL-OBJ-03: Witness & Publisher Pattern

**Rule:** `MOVE-OBJ-WIT-01`
**Severity:** High-Critical

### Description
OTW structs have copy ability enabling repeated initialization, allowing anyone to create duplicate witnesses and call initialization functions multiple times. Multiple token supply initializations inflating supply, duplicate TreasuryCap creation enabling infinite minting.

### Patterns

#### Pattern 1: One-Time Witness (OTW) Validation Bypass
The witness struct used for privileged initialization has `copy` ability, allowing anyone to create additional witnesses and call initialization functions multiple times. This enables supply inflation, duplicate treasury creation, and other one-time-only violations.

**Vulnerable:**
```move
module example::my_coin {
    use sui::coin;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    // BUG: OTW has `copy` — can be duplicated
    // Anyone can create MY_COIN {} and call create_currency again
    struct MY_COIN has copy, drop {}

    fun init(witness: MY_COIN, ctx: &mut TxContext) {
        let (treasury_cap, metadata) = coin::create_currency(
            witness,
            9,
            b"MYCOIN",
            b"My Coin",
            b"",
            option::none(),
            ctx,
        );
        // With copy: attacker creates another MY_COIN {} and calls
        // create_currency again — duplicate TreasuryCap, infinite minting
        transfer::public_transfer(treasury_cap, tx_context::sender(ctx));
        transfer::public_freeze_object(metadata);
    }
}
```

**Fixed:**
```move
module example::my_coin {
    use sui::coin;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    // Correct OTW: only `drop`, struct name matches module name in ALL_CAPS
    struct MY_COIN has drop {}

    fun init(witness: MY_COIN, ctx: &mut TxContext) {
        // Sui runtime validates OTW: created exactly once, in init, consumed here
        let (treasury_cap, metadata) = coin::create_currency(
            witness,  // consumed — cannot be recreated
            9,
            b"MYCOIN",
            b"My Coin",
            b"",
            option::none(),
            ctx,
        );
        // Secure: transfer to governance, not deployer EOA
        transfer::public_transfer(treasury_cap, @governance_multisig);
        transfer::public_freeze_object(metadata);
    }
}
```

### Remediation
OTW structs must only have drop ability and use the module name in ALL_CAPS.

### Signature
**Slug:** `witness-publisher-invariant`
**Detect:** For every Sui module using OTW: verify OTW structs have only drop ability and match module name in ALL_CAPS.
**What's Wrong:** OTW structs have copy enabling re-initialization and duplicate treasury creation.
**Remediation:** OTW: only drop ability. No copy, store, or key.
