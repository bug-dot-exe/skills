# CAT-OBJ: Object Model

**Context:** `ctx:generic`
**Detectors:** 4

## CL-OBJ-01: Ability & Type Safety Invariant

**Rule:** `MOVE-OBJ-ABIL-01`
**Severity:** high-critical

## Precondition
The module defines structs representing value-bearing resources (coins, NFTs, capabilities, receipts, obligations) with Move abilities (copy, drop, store, key), uses generic type parameters for pool/token operations, or employs phantom types for coin/token differentiation.

## Root Cause
Value-bearing resources have copy ability enabling token duplication, obligation resources have drop ability enabling debt destruction, sensitive resources have store enabling unauthorized nesting in other resources, generic type parameters are not validated allowing type confusion attacks, or phantom types are not enforced on coin operations allowing cross-token manipulation.

## Impact
Unlimited token minting via copy ability, debt/obligation destruction via drop, capability exfiltration via store (nesting inside other resources), complete pool drainage via type confusion, and accounting corruption via phantom type bypass.

## Remediation
Never give copy to value-bearing resources. Never give drop to obligation resources. Restrict store on sensitive capabilities (only give key for global storage). Validate all generic type parameters against stored/expected types. Enforce phantom type separation on all coin operations.

---

## Pattern 1: Value Struct Has Copy Ability — Token Duplication

A value-bearing struct (voucher, ticket, reward proof) has the `copy` ability, allowing anyone to duplicate it. An attacker duplicates tokens to drain pools or inflate supply without limit.

> **Note:** On Aptos, any resource struct (with `key`) stored in global storage can be affected. Structs without `key` used as intermediate values in function calls are also vulnerable if they carry economic value and have `copy`.

### Vulnerable
```move
module example::rewards {
    use std::signer;

    // BUG: copy ability on a value-bearing voucher
    // Anyone holding one voucher can duplicate it infinitely
    struct RewardVoucher has copy, drop, store {
        pool_addr: address,
        amount: u64,
    }

    public fun issue_reward(pool_addr: address, amount: u64): RewardVoucher {
        RewardVoucher { pool_addr, amount }
    }

    // Attacker: get one voucher, copy it 1000 times, redeem all copies
    public fun redeem(account: &signer, voucher: RewardVoucher) acquires Pool {
        let RewardVoucher { pool_addr, amount } = voucher;
        let pool = borrow_global_mut<Pool>(pool_addr);
        // Transfer amount from pool to caller
        // Each copy drains `amount` from the pool
        coin::transfer<AptosCoin>(&pool.resource_signer, signer::address_of(account), amount);
    }
}
```

### Fixed
```move
module example::rewards {
    use std::signer;

    // No copy — voucher cannot be duplicated
    // No drop — voucher must be consumed via redeem
    struct RewardVoucher has store {
        pool_addr: address,
        amount: u64,
    }

    public fun issue_reward(pool_addr: address, amount: u64): RewardVoucher {
        RewardVoucher { pool_addr, amount }
    }

    public fun redeem(account: &signer, voucher: RewardVoucher) acquires Pool {
        let RewardVoucher { pool_addr, amount } = voucher;
        let pool = borrow_global_mut<Pool>(pool_addr);
        // Voucher consumed — cannot be redeemed again
        coin::transfer<AptosCoin>(&pool.resource_signer, signer::address_of(account), amount);
    }
}
```

---

## Pattern 2: Obligation Struct Has Drop Ability — Debt Destruction

An obligation struct (flash loan receipt, debt record, collateral lock) has the `drop` ability. A borrower silently destroys their debt without repaying, or destroys a collateral lock to unlock assets early. This is the inverse of the hot potato pattern.

> **Note:** On Aptos, this applies to any struct used as a transactional obligation. The hot potato pattern (no abilities) forces consumption within the same transaction, which works identically on Aptos as on other Move platforms.

### Vulnerable
```move
module example::flash_loan {
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;

    // BUG: FlashReceipt has `drop` — borrower can destroy their obligation
    struct FlashReceipt has drop {
        pool_addr: address,
        borrow_amount: u64,
        fee: u64,
    }

    public fun flash_borrow(
        pool_addr: address,
        amount: u64
    ): (Coin<AptosCoin>, FlashReceipt) acquires Pool {
        let pool = borrow_global_mut<Pool>(pool_addr);
        let coin = coin::extract(&mut pool.reserve, amount);
        let receipt = FlashReceipt {
            pool_addr,
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

### Fixed
```move
module example::flash_loan {
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;

    // No abilities at all — hot potato pattern
    // Receipt MUST be consumed via flash_repay within the same transaction
    struct FlashReceipt {
        pool_addr: address,
        borrow_amount: u64,
        fee: u64,
    }

    public fun flash_borrow(
        pool_addr: address,
        amount: u64
    ): (Coin<AptosCoin>, FlashReceipt) acquires Pool {
        let pool = borrow_global_mut<Pool>(pool_addr);
        let coin = coin::extract(&mut pool.reserve, amount);
        let receipt = FlashReceipt {
            pool_addr,
            borrow_amount: amount,
            fee: amount / 1000,
        };
        (coin, receipt)
    }

    // Only way to consume the FlashReceipt — must repay
    public fun flash_repay(
        pool_addr: address,
        receipt: FlashReceipt,
        payment: Coin<AptosCoin>,
    ) acquires Pool {
        let FlashReceipt { pool_addr: receipt_addr, borrow_amount, fee } = receipt;
        assert!(receipt_addr == pool_addr, E_WRONG_POOL);
        assert!(coin::value(&payment) >= borrow_amount + fee, E_UNDERPAY);
        let pool = borrow_global_mut<Pool>(pool_addr);
        coin::merge(&mut pool.reserve, payment);
    }
}
```

---

## Pattern 3: Resource Has Store Without Key — Unauthorized Nesting

On Aptos, `store` ability allows a struct to be nested inside other resources. A sensitive capability with `store` can be embedded in an attacker-controlled resource and moved to a different account, bypassing intended access control. On Aptos, `key` enables global storage; `store` enables nesting inside other `key` resources.

### Vulnerable
```move
module example::governance {
    use std::signer;

    // BUG: AdminCap has `store` — can be nested in arbitrary resources
    // and moved to attacker-controlled accounts
    struct AdminCap has key, store {
        admin: address,
    }

    // With `store`, attacker nests AdminCap inside their own resource:
    // module attacker::theft {
    //     struct Wrapper has key, store { stolen_cap: AdminCap }
    //     fun steal(account: &signer, cap: AdminCap) {
    //         move_to(account, Wrapper { stolen_cap: cap });
    //     }
    // }
}
```

### Fixed
```move
module example::governance {
    use std::signer;

    // key only — AdminCap can exist in global storage but cannot be nested
    // inside other resources by external modules
    struct AdminCap has key {
        admin: address,
    }

    // Controlled transfer within the module only
    public fun transfer_admin(
        current_admin: &signer,
        new_admin: address
    ) acquires AdminCap {
        let cap = move_from<AdminCap>(signer::address_of(current_admin));
        assert!(cap.admin == signer::address_of(current_admin), E_NOT_ADMIN);
        cap.admin = new_admin;
        move_to(&create_signer(new_admin), cap);
    }
}
```

---

## Pattern 4: Generic Type Parameter Not Validated

Functions accepting generic `<T>` (especially `Coin<T>`) don't verify T matches the expected/whitelisted type. This is the #1 critical vulnerability across real Move audits. An attacker deposits worthless FakeUSDC and borrows real assets.

### Vulnerable
```move
module example::lending {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;

    struct Pool has key {
        reserve: Coin<AptosCoin>,
    }

    // BUG: Accepts ANY CoinType as collateral — no whitelist
    // Attacker creates Coin<FakeToken> with arbitrary value
    public fun deposit_collateral<T>(
        account: &signer,
        amount: u64
    ) acquires Pool {
        let value = amount;
        // Credits collateral value without verifying T is an approved asset
        // Attacker: deposit 1M Coin<FakeToken> -> borrow 1M APT -> pool drained
    }
}
```

### Fixed
```move
module example::lending {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};

    // Pool is parameterized by the collateral type
    struct Pool<phantom T> has key {
        reserve: Coin<T>,
        collateral: Coin<T>,
    }

    // Type safety: T is bound to the pool's phantom type
    // Only the specific collateral type the pool was created for is accepted
    public fun deposit_collateral<T>(
        account: &signer,
        pool_addr: address,
        amount: u64
    ) acquires Pool {
        let pool = borrow_global_mut<Pool<T>>(pool_addr);
        let coins = coin::withdraw<T>(account, amount);
        coin::merge(&mut pool.collateral, coins);
    }
}
```

---

## Pattern 5: Phantom Type Not Enforced on Coin Operations

Coin or balance operations don't leverage the phantom type parameter for safety. Different coin types can be mixed in the same pool or vault, breaking accounting invariants.

### Vulnerable
```move
module example::vault {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;

    struct MultiVault has key {
        total_value: u64,  // tracks "total" across all coin types — meaningless
    }

    // BUG: Deposits any coin type, credits the same total_value counter
    // No per-type balance tracking
    public fun deposit<T>(account: &signer, amount: u64) acquires MultiVault {
        let vault = borrow_global_mut<MultiVault>(@vault_addr);
        vault.total_value = vault.total_value + amount;
        // Different T types are all counted in the same total_value
        coin::transfer<T>(account, @vault_addr, amount);
    }

    // Withdraw gives AptosCoin regardless of what was deposited
    public fun withdraw(account: &signer, amount: u64) acquires MultiVault {
        let vault = borrow_global_mut<MultiVault>(@vault_addr);
        vault.total_value = vault.total_value - amount;
        // Deposit FakeToken, withdraw APT — pool drained
        coin::transfer<AptosCoin>(&vault.resource_signer, signer::address_of(account), amount);
    }
}
```

### Fixed
```move
module example::vault {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};

    // Phantom type T enforced on the vault — each coin type has its own vault
    struct TypedVault<phantom T> has key {
        reserve: Coin<T>,
    }

    // Deposit and withdraw are type-safe — can only withdraw what was deposited
    public fun deposit<T>(account: &signer, amount: u64) acquires TypedVault {
        let vault = borrow_global_mut<TypedVault<T>>(@vault_addr);
        let coins = coin::withdraw<T>(account, amount);
        coin::merge(&mut vault.reserve, coins);
    }

    public fun withdraw<T>(account: &signer, amount: u64) acquires TypedVault {
        let vault = borrow_global_mut<TypedVault<T>>(@vault_addr);
        let coins = coin::extract(&mut vault.reserve, amount);
        coin::deposit(signer::address_of(account), coins);
    }
}
```

---

## Signature
**Slug:** `ability-type-safety-invariant`
**Detect:** For every struct definition: (1) verify value-bearing resources (coins, NFTs, badges) never have copy ability, (2) verify obligation resources (debts, receipts, locks) never have drop ability, (3) verify sensitive capabilities have `key` only (no `store`) unless nesting is intentional, (4) verify all generic type parameters are validated against stored or whitelisted types, (5) verify phantom types enforce per-type separation on all coin operations.
**What's Wrong:** One or more value-bearing structs have copy enabling duplication, obligation structs have drop enabling destruction, capabilities have store enabling nesting/exfiltration, generic types are unvalidated enabling type confusion, or phantom types are not enforced enabling cross-type manipulation.
**Remediation:** Remove copy from value types. Remove drop from obligation types. Remove store from sensitive capabilities. Validate generics against whitelists or phantom-parameterized containers. Enforce per-type balance isolation.

---

## CL-OBJ-02: Aptos Resource & Object Invariant

**Rule:** `MOVE-OBJ-APTOS-01`
**Severity:** medium-critical

## Precondition
The module targets the Aptos blockchain and uses resource accounts with SignerCapability, creates objects via ConstructorRef, stores multiple resources at object accounts, passes mutable references to callbacks or untrusted code, or uses function values (closures) in Move 2.2+.

## Root Cause
SignerCapability is stored insecurely enabling unauthorized signer creation, ConstructorRef is leaked enabling object reclaim after sale, multiple resources at the same object account cause unintended co-transfer, mutable references are swapped by untrusted callees, or function value callbacks re-enter with altered parameters.

## Impact
Full resource account takeover via SignerCapability abuse, NFT theft via ConstructorRef-derived TransferRef, unintended asset transfer when co-located resources are moved, asset substitution via mem::swap on mutable references, and reentrancy-based fund theft via function value callbacks.

## Remediation
Store SignerCapability in access-controlled resources with admin gating. Never expose ConstructorRef outside the creating function. Use separate object accounts for independently-transferable resources. Re-validate invariants after passing &mut to untrusted code. Bind critical values into non-droppable structs before callback invocation.

---

## Pattern 1: Resource Account Privilege Escalation

A SignerCapability for a resource account is stored in a globally readable resource or accessible without proper authorization. Any code path reaching `create_signer_with_capability` grants full control of the resource account.

### Vulnerable
```move
module example::protocol {
    use std::signer;
    use aptos_framework::account;

    struct ProtocolConfig has key {
        signer_cap: account::SignerCapability,
        treasury_balance: u64,
    }

    // BUG: Any caller can use the signer capability
    // No check that caller is authorized
    public fun withdraw_treasury(
        caller: &signer,
        amount: u64
    ) acquires ProtocolConfig {
        let config = borrow_global<ProtocolConfig>(@protocol);
        let resource_signer = account::create_signer_with_capability(&config.signer_cap);
        // resource_signer has FULL control of the resource account
        // Attacker can transfer all funds, modify all resources
        coin::transfer<AptosCoin>(&resource_signer, signer::address_of(caller), amount);
    }
}
```

### Fixed
```move
module example::protocol {
    use std::signer;
    use aptos_framework::account;

    struct ProtocolConfig has key {
        signer_cap: account::SignerCapability,
        treasury_balance: u64,
        admin: address,
    }

    // Admin-gated: only authorized caller can use signer capability
    public fun withdraw_treasury(
        caller: &signer,
        amount: u64
    ) acquires ProtocolConfig {
        let config = borrow_global<ProtocolConfig>(@protocol);
        assert!(signer::address_of(caller) == config.admin, E_NOT_ADMIN);
        let resource_signer = account::create_signer_with_capability(&config.signer_cap);
        assert!(amount <= config.treasury_balance, E_INSUFFICIENT);
        coin::transfer<AptosCoin>(&resource_signer, signer::address_of(caller), amount);
    }
}
```

---

## Pattern 2: ConstructorRef Leak Enabling Object Reclaim

A function returns a ConstructorRef after creating an Aptos object. The caller stores it and later generates a TransferRef, reclaiming the object (e.g., an NFT) even after it has been sold to another user.

### Vulnerable
```move
module example::nft {
    use aptos_framework::object;
    use aptos_token_objects::token;

    // BUG: Returns ConstructorRef — caller can generate TransferRef at any time
    public fun mint_nft(
        creator: &signer,
        name: String,
        description: String,
        uri: String,
    ): object::ConstructorRef {
        let constructor_ref = token::create_named_token(
            creator, string::utf8(b"Collection"), description, name, option::none(), uri
        );
        // Attacker stores constructor_ref
        // Later: let transfer_ref = object::generate_transfer_ref(&constructor_ref);
        // Uses transfer_ref to reclaim NFT after selling it
        constructor_ref
    }
}
```

### Fixed
```move
module example::nft {
    use aptos_framework::object;
    use aptos_token_objects::token;

    // Never expose ConstructorRef — use it internally only
    public fun mint_nft(
        creator: &signer,
        name: String,
        description: String,
        uri: String,
    ) {
        let constructor_ref = token::create_named_token(
            creator, string::utf8(b"Collection"), description, name, option::none(), uri
        );
        // Use constructor_ref for immediate setup only
        let object_signer = object::generate_signer(&constructor_ref);
        move_to(&object_signer, NFTMetadata { rarity: 1 });
        // constructor_ref goes out of scope — no one can generate TransferRef
        // NFT ownership is now governed by normal Aptos object transfer rules
    }
}
```

---

## Pattern 3: Object Account Resource Grouping Transfer

Multiple resources stored at the same Aptos object account are all transferred together when any one is transferred. `object::transfer` operates on ObjectCore, affecting all resources at that address.

### Vulnerable
```move
module example::gaming {
    use std::signer;
    use aptos_framework::object;

    struct Sword has key { attack: u64 }
    struct Shield has key { defense: u64 }

    // BUG: Both resources at the same object account
    public fun mint_equipment(creator: &signer, recipient: address) {
        let constructor_ref = object::create_object(signer::address_of(creator));
        let obj_signer = object::generate_signer(&constructor_ref);
        // Sword and Shield share the same object account
        move_to(&obj_signer, Sword { attack: 100 });
        move_to(&obj_signer, Shield { defense: 50 });

        let sword_obj = object::address_to_object<Sword>(
            signer::address_of(&obj_signer)
        );
        // Transferring Sword also transfers Shield!
        object::transfer(creator, sword_obj, recipient);
        // Recipient gets both — seller loses Shield unintentionally
    }
}
```

### Fixed
```move
module example::gaming {
    use std::signer;
    use aptos_framework::object;

    struct Sword has key { attack: u64 }
    struct Shield has key { defense: u64 }

    // Separate object accounts — independent transfers
    public fun mint_equipment(creator: &signer, recipient: address) {
        // Each resource gets its own object account
        let sword_ref = object::create_object(signer::address_of(creator));
        let sword_signer = object::generate_signer(&sword_ref);
        move_to(&sword_signer, Sword { attack: 100 });

        let shield_ref = object::create_object(signer::address_of(creator));
        let shield_signer = object::generate_signer(&shield_ref);
        move_to(&shield_signer, Shield { defense: 50 });

        // Now Sword and Shield can be transferred independently
        let sword_obj = object::address_to_object<Sword>(
            signer::address_of(&sword_signer)
        );
        object::transfer(creator, sword_obj, recipient);
        // Only Sword transferred — Shield stays with creator
    }
}
```

---

## Pattern 4: Mutable Reference Swap Attack

Passing `&mut T` to untrusted code (callbacks, function values) allows the callee to use `mem::swap` to replace the entire value behind the reference. This bypasses private field protections without reading or writing them directly.

### Vulnerable
```move
module example::vault {
    use aptos_framework::fungible_asset::{Self, FungibleAsset};
    use aptos_framework::primary_fungible_store;

    // BUG: Passes &mut FungibleAsset to untrusted hook
    // Hook can mem::swap a worthless asset in
    public fun process_deposit(
        user: address,
        asset: FungibleAsset,
        hook: |&mut FungibleAsset|,
    ) {
        // Validate asset metadata — it's the expected token
        assert!(
            fungible_asset::metadata(&asset) == @expected_token,
            E_WRONG_TOKEN
        );

        // Pass mutable reference to untrusted code
        hook(&mut asset);
        // BUG: asset may now be a COMPLETELY DIFFERENT token!
        // hook called mem::swap(&mut asset, &mut worthless_asset)

        // Deposits potentially worthless asset
        primary_fungible_store::deposit(@treasury, asset);
    }
}
```

### Fixed
```move
module example::vault {
    use aptos_framework::fungible_asset::{Self, FungibleAsset};
    use aptos_framework::primary_fungible_store;

    // Re-validate after untrusted mutation
    public fun process_deposit(
        user: address,
        asset: FungibleAsset,
        hook: |&mut FungibleAsset|,
    ) {
        let expected_metadata = @expected_token;
        assert!(fungible_asset::metadata(&asset) == expected_metadata, E_WRONG_TOKEN);
        let expected_amount = fungible_asset::amount(&asset);

        hook(&mut asset);

        // Re-validate AFTER untrusted code touched it
        assert!(fungible_asset::metadata(&asset) == expected_metadata, E_SWAPPED_TOKEN);
        assert!(fungible_asset::amount(&asset) >= expected_amount, E_AMOUNT_REDUCED);

        primary_fungible_store::deposit(@treasury, asset);
    }
}
```

---

## Pattern 5: Function Value Reentrancy

Since Move 2.2, function values (closures) enable reentrancy. While re-entered modules cannot access their own resources during dynamic dispatch, attackers can still exploit by altering callback parameters or swapping values via captured references.

### Vulnerable
```move
module example::lending {
    use std::signer;

    struct Grant { amount: u64 }  // has drop — attacker ignores it

    // BUG: Function value can re-enter and alter the effective amount
    public fun withdraw_with_callback(
        user: &signer,
        amount: u64,
        callback: |address, &Grant, u64|,   // attacker-supplied
    ) {
        let addr = signer::address_of(user);
        assert!(balance(addr) >= amount, E_INSUFFICIENT);
        let grant = Grant { amount };

        // Attacker's callback ignores `amount` parameter entirely
        // and calls withdraw_with_callback again, or uses a different amount
        callback(addr, &grant, amount);
        // Grant is passed by reference — attacker reads amount but acts on different value
    }
}
```

### Fixed
```move
module example::lending {
    use std::signer;

    // Non-droppable Grant — amount is fixed at creation
    struct Grant { user: address, amount: u64 }

    public fun withdraw_with_callback(
        user: &signer,
        amount: u64,
        callback: |address, Grant|,
    ) {
        let addr = signer::address_of(user);
        assert!(balance(addr) >= amount, E_INSUFFICIENT);

        // State updated BEFORE callback (checks-effects-interactions)
        debit_balance(addr, amount);

        // Grant binds the amount — callback cannot alter it
        let grant = Grant { user: addr, amount };
        callback(addr, grant);
        // Grant must be consumed by callback (no drop)
        // Amount is fixed inside Grant — cannot be inflated
    }

    // Only way to use Grant — amount is enforced
    public fun execute_grant(grant: Grant) {
        let Grant { user, amount } = grant;
        credit_withdrawal(user, amount);
    }
}
```

---

## Signature
**Slug:** `aptos-resource-object-invariant`
**Detect:** For every Aptos module: (1) verify SignerCapability is stored with access control and all paths to create_signer_with_capability are admin-gated, (2) verify ConstructorRef is never returned or stored beyond the creating function, (3) verify independently-transferable resources have separate object accounts, (4) verify &mut references are re-validated after passing to untrusted code, (5) verify function value callbacks follow checks-effects-interactions and bind critical values in non-droppable structs.
**What's Wrong:** One or more modules expose SignerCapability without access control, return ConstructorRef enabling object reclaim, co-locate independent resources at the same object account, pass &mut to untrusted code without re-validation, or use function values without reentrancy protection.
**Remediation:** Admin-gate SignerCapability usage. Scope ConstructorRef to creating function. Separate object accounts per resource. Re-validate after untrusted mutation. Use checks-effects-interactions with non-droppable Grants.

---

## CL-OBJ-03: Aptos Framework Safety Invariant

**Rule:** `MOVE-OBJ-APTOS-02`
**Severity:** medium-high

## Precondition
The module targets Aptos and uses the FungibleAsset framework, legacy Coin framework, upgradeable modules with on-chain structs, OrderedMap/BigOrderedMap for sorted data, or map types (SimpleMap, Table, SmartTable) for permissionless data storage.

## Root Cause
Mixed FungibleAsset and legacy Coin frameworks create accounting inconsistencies, zero-value FungibleAsset operations corrupt counters and bypass limits, struct field reordering on upgrade breaks deserialization of existing resources, OrderedMap key structs have wrong field ordering, or wrong map type selection enables DoS on permissionless operations.

## Impact
Accounting errors from framework mixing causing fund loss, counter corruption and limit bypass from zero-value operations, permanent inaccessibility of user funds from upgrade-induced deserialization failure, incorrect orderbook matching from wrong key ordering, and DoS bricking core protocol functions from quadratic map operations.

## Remediation
Use a single asset framework consistently with proper conversion. Reject zero-value operations on all FungibleAsset paths. Preserve struct field order across upgrades or use migration functions. Verify OrderedMap key struct field ordering matches intended sort. Use Table or BigOrderedMap for permissionless unbounded data.

---

## Pattern 1: FungibleAsset vs Legacy Coin Framework Mixing

A protocol mixes the legacy `coin` framework with the new `fungible_asset` framework without proper conversion. Balance accounting becomes inconsistent because the two frameworks maintain separate state.

### Vulnerable
```move
module example::vault {
    use aptos_framework::coin;
    use aptos_framework::fungible_asset;
    use aptos_framework::primary_fungible_store;
    use std::signer;

    struct VaultState has key {
        total_deposits: u64,
    }

    // Deposits via legacy Coin framework
    public entry fun deposit_coin<T>(
        user: &signer,
        amount: u64
    ) acquires VaultState {
        let coins = coin::withdraw<T>(user, amount);
        // BUG: Deposits into Coin balance
        coin::deposit(@vault, coins);
        let state = borrow_global_mut<VaultState>(@vault);
        state.total_deposits = state.total_deposits + amount;
    }

    // Withdraws via FungibleAsset framework
    public entry fun withdraw_fa(
        user: &signer,
        amount: u64
    ) acquires VaultState {
        // BUG: Withdraws from FungibleAsset store — different balance pool!
        // Coin deposits and FA withdrawals are NOT linked
        // User deposits via Coin, withdraws from FA — double-spending possible
        let fa = primary_fungible_store::withdraw(user, @token_metadata, amount);
        primary_fungible_store::deposit(signer::address_of(user), fa);
        let state = borrow_global_mut<VaultState>(@vault);
        state.total_deposits = state.total_deposits - amount;
    }
}
```

### Fixed
```move
module example::vault {
    use aptos_framework::coin;
    use aptos_framework::fungible_asset;
    use aptos_framework::primary_fungible_store;
    use std::signer;

    struct VaultState has key {
        total_deposits: u64,
    }

    // Single framework: use FungibleAsset consistently
    // Convert any legacy Coin to FA on deposit
    public entry fun deposit<T>(
        user: &signer,
        amount: u64
    ) acquires VaultState {
        assert!(amount > 0, E_ZERO_AMOUNT);
        let coins = coin::withdraw<T>(user, amount);
        // Convert Coin to FungibleAsset using official bridge
        let fa = coin::coin_to_fungible_asset(coins);
        primary_fungible_store::deposit(@vault, fa);
        let state = borrow_global_mut<VaultState>(@vault);
        state.total_deposits = state.total_deposits + amount;
    }

    // Withdraw from the same FA store
    public entry fun withdraw(
        user: &signer,
        amount: u64
    ) acquires VaultState {
        assert!(amount > 0, E_ZERO_AMOUNT);
        let state = borrow_global_mut<VaultState>(@vault);
        assert!(state.total_deposits >= amount, E_INSUFFICIENT);
        let fa = primary_fungible_store::withdraw(user, @token_metadata, amount);
        primary_fungible_store::deposit(signer::address_of(user), fa);
        state.total_deposits = state.total_deposits - amount;
    }
}
```

---

## Signature
**Slug:** `aptos-framework-safety-invariant`
**Detect:** For every Aptos module: (1) verify a single asset framework is used consistently (Coin or FungibleAsset) with proper conversion.
**What's Wrong:** Modules mix Coin and FungibleAsset frameworks without conversion, causing accounting inconsistencies and potential double-spending.
**Remediation:** Use single framework with conversion bridge.

---

## CL-OBJ-04: Hot Potato Pattern Integrity

**Rule:** `MOVE-OBJ-HOT-01`
**Severity:** high-critical

## Precondition
The module uses hot potato structs (structs with no abilities) to enforce transactional obligations such as flash loan repayment, borrow-return invariants, or multi-step operation completion within a single transaction.

## Root Cause
Hot potato structs have drop or store abilities allowing obligation destruction or deferral, start functions can be called multiple times resetting snapshots, or cross-module consumption allows forged receipts.

## Impact
Flash loans taken without repayment, obligation destruction bypassing protocol invariants, nested flash loan attacks resetting snapshots to steal funds, and permanent fund loss from receipt forgery.

## Remediation
Ensure hot potato structs have zero abilities (no copy, drop, store, or key). Guard start functions with active-operation flags. Store snapshot amounts inside the hot potato, not in the vault. Keep receipt lifecycle in a single module.

---

## Pattern 1: Hot Potato with Drop or Store Ability

A flash loan receipt struct is given `drop` or `store` ability, breaking the hot potato enforcement. With `drop`, the borrower silently discards the receipt without repaying. With `store`, the receipt can be stored in a resource and never consumed.

### Vulnerable
```move
module example::flash_loan {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;

    // BUG: FlashReceipt has `drop` — borrower discards it, never repays
    struct FlashReceipt has drop {
        amount: u64,
        fee: u64,
    }

    struct Pool has key {
        reserve: Coin<AptosCoin>,
    }

    public fun borrow(
        pool_addr: address,
        amount: u64
    ): (Coin<AptosCoin>, FlashReceipt) acquires Pool {
        let pool = borrow_global_mut<Pool>(pool_addr);
        let coin = coin::extract(&mut pool.reserve, amount);
        let receipt = FlashReceipt { amount, fee: amount / 100 };
        (coin, receipt)
        // Borrower receives coin + receipt
        // Since receipt has `drop`, borrower can just... drop it
        // and keep the coin. Pool drained.
    }

    public fun repay(
        pool_addr: address,
        payment: Coin<AptosCoin>,
        receipt: FlashReceipt,
    ) acquires Pool {
        let FlashReceipt { amount, fee } = receipt;
        assert!(coin::value(&payment) >= amount + fee, E_UNDERPAY);
        let pool = borrow_global_mut<Pool>(pool_addr);
        coin::merge(&mut pool.reserve, payment);
    }
}
```

### Fixed
```move
module example::flash_loan {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;

    // No abilities — compiler forces consumption in same transaction
    struct FlashReceipt {
        pool_addr: address,
        amount: u64,
        fee: u64,
    }

    struct Pool has key {
        reserve: Coin<AptosCoin>,
    }

    public fun borrow(
        pool_addr: address,
        amount: u64
    ): (Coin<AptosCoin>, FlashReceipt) acquires Pool {
        let pool = borrow_global_mut<Pool>(pool_addr);
        let coin = coin::extract(&mut pool.reserve, amount);
        let receipt = FlashReceipt {
            pool_addr,
            amount,
            fee: amount / 100,
        };
        (coin, receipt)
        // receipt MUST be consumed by repay() — no other option
    }

    public fun repay(
        pool_addr: address,
        payment: Coin<AptosCoin>,
        receipt: FlashReceipt,
    ) acquires Pool {
        let FlashReceipt { pool_addr: receipt_addr, amount, fee } = receipt;
        assert!(receipt_addr == pool_addr, E_WRONG_POOL);
        assert!(coin::value(&payment) >= amount + fee, E_UNDERPAY);
        let pool = borrow_global_mut<Pool>(pool_addr);
        coin::merge(&mut pool.reserve, payment);
    }
}
```

---

## Pattern 2: Hot Potato State Reset via Nested Operations

The flash loan `start` function can be called multiple times within the same transaction, resetting the vault's saved snapshot each time. The attacker borrows, calls start again to reset the baseline to the depleted balance, then finishes validation against the lower baseline.

### Vulnerable
```move
module example::harvest {
    use std::signer;

    struct Vault has key {
        reserves: u64,
        saved_reserves: u64,       // snapshot stored in vault, not receipt!
        operation_in_progress: bool,
    }

    struct HarvestOp {}  // hot potato

    public fun start_harvest(vault_addr: address): HarvestOp acquires Vault {
        let vault = borrow_global_mut<Vault>(vault_addr);
        // BUG: Overwrites saved_reserves every call — no reentrancy guard
        vault.saved_reserves = vault.reserves;
        vault.operation_in_progress = true;
        HarvestOp {}
    }

    // BUG: returned_amount is a user-supplied number, not actual funds
    public fun finish_harvest(
        vault_addr: address,
        op: HarvestOp,
        returned_amount: u64,
    ) acquires Vault {
        let vault = borrow_global_mut<Vault>(vault_addr);
        let min_return = vault.saved_reserves * 98 / 100;
        assert!(returned_amount >= min_return, E_INSUFFICIENT);
        vault.operation_in_progress = false;
        let HarvestOp {} = op;
        // Attacker: start(reserves=1000) -> withdraw 900 -> start again(reserves=100)
        // -> finish(returned_amount=98) -> passes 98% of 100 -> keeps 900
    }
}
```

### Fixed
```move
module example::harvest {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;

    struct Vault has key {
        reserve: Coin<AptosCoin>,
        operation_in_progress: bool,
    }

    // Hot potato stores the snapshot — not the vault
    struct HarvestOp {
        vault_addr: address,
        snapshot_amount: u64,
    }

    public fun start_harvest(vault_addr: address): HarvestOp acquires Vault {
        let vault = borrow_global_mut<Vault>(vault_addr);
        // Guard: cannot start if already in progress
        assert!(!vault.operation_in_progress, E_ALREADY_IN_PROGRESS);
        vault.operation_in_progress = true;
        HarvestOp {
            vault_addr,
            snapshot_amount: coin::value(&vault.reserve),
        }
    }

    public fun finish_harvest(
        vault_addr: address,
        op: HarvestOp,
        payment: Coin<AptosCoin>,
    ) acquires Vault {
        let HarvestOp { vault_addr: op_addr, snapshot_amount } = op;
        assert!(op_addr == vault_addr, E_WRONG_VAULT);
        let vault = borrow_global_mut<Vault>(vault_addr);
        // Verify actual funds returned, not a user-supplied number
        let min_return = snapshot_amount * 98 / 100;
        coin::merge(&mut vault.reserve, payment);
        assert!(coin::value(&vault.reserve) >= min_return, E_UNDERPAY);
        vault.operation_in_progress = false;
    }
}
```

---

## Pattern 3: Cross-Module Hot Potato Validation Bypass

A hot potato receipt is created in Module A but consumed in Module B. Module B does not properly validate the receipt's contents, allowing an attacker to create a fake receipt from a malicious module that Module B accepts.

### Vulnerable
```move
// Module A: legitimate flash loan
module protocol::flash {
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;

    struct FlashReceipt { amount: u64 }

    public fun borrow(
        pool_addr: address,
        amount: u64
    ): (Coin<AptosCoin>, FlashReceipt) acquires Pool {
        let pool = borrow_global_mut<Pool>(pool_addr);
        (coin::extract(&mut pool.reserve, amount), FlashReceipt { amount })
    }
}

// Module B: repayment handler — accepts receipts from ANY module
module protocol::repay {
    use protocol::flash::FlashReceipt;

    // BUG: If FlashReceipt struct is public, attacker creates compatible struct
    // in their own module and passes it here
    public fun repay(
        pool_addr: address,
        payment: Coin<AptosCoin>,
        receipt: FlashReceipt,
    ) acquires Pool {
        let FlashReceipt { amount } = receipt;
        assert!(coin::value(&payment) >= amount, E_UNDERPAY);
        let pool = borrow_global_mut<Pool>(pool_addr);
        coin::merge(&mut pool.reserve, payment);
    }
}
```

### Fixed
```move
// Single module handles both borrow and repay — receipt never crosses module boundary
module protocol::flash {
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;

    struct FlashReceipt { pool_addr: address, amount: u64, fee: u64 }

    public fun borrow(
        pool_addr: address,
        amount: u64
    ): (Coin<AptosCoin>, FlashReceipt) acquires Pool {
        let pool = borrow_global_mut<Pool>(pool_addr);
        (coin::extract(&mut pool.reserve, amount),
         FlashReceipt { pool_addr, amount, fee: amount * FEE_BPS / 10000 })
    }

    // Same module — receipt type cannot be forged from outside
    public fun repay(
        pool_addr: address,
        payment: Coin<AptosCoin>,
        receipt: FlashReceipt,
    ) acquires Pool {
        let FlashReceipt { pool_addr: receipt_addr, amount, fee } = receipt;
        assert!(receipt_addr == pool_addr, E_WRONG_POOL);
        assert!(coin::value(&payment) >= amount + fee, E_UNDERPAY);
        let pool = borrow_global_mut<Pool>(pool_addr);
        coin::merge(&mut pool.reserve, payment);
    }
}
```

---

## Signature
**Slug:** `hot-potato-integrity-invariant`
**Detect:** For every hot potato struct: (1) verify it has zero abilities (no copy, drop, store, key), (2) verify start/borrow functions check for existing active operations, (3) verify receipt creation and consumption happen in the same module.
**What's Wrong:** One or more hot potato structs have abilities enabling obligation bypass, start functions allow re-entry resetting snapshots, or receipts cross module boundaries without validation.
**Remediation:** Strip all abilities from receipt structs. Add active-operation guards. Keep receipt lifecycle in single module.

---
