# CAT-COIN: Coin/Token Handling

**Context:** `ctx:defi`
**Detectors:** 2

## CL-COIN-01: Coin/Token Handling Invariant

**Rule:** `MOVE-COIN-HAND-01`
**Severity:** medium-high

## Precondition
The module handles coin transfers, token minting, fungible asset operations, or manages coin balances on behalf of users.

## Root Cause
Zero-amount operations bypass validation, coin merge/extract amounts are miscalculated, fungible asset metadata is uninitialized, or partial operations leave unrecoverable dust.

## Impact
Zero-value operations waste gas or bypass fee checks, incorrect extraction causes balance corruption or fund loss, uninitialized metadata causes runtime aborts, and coin dust becomes permanently locked.

## Remediation
Reject zero-amount operations. Validate extraction amounts against available balance. Initialize fungible asset metadata before use. Handle full extraction to avoid dust.

---

## Pattern 1: Zero-Amount Coin Operations

Creating or transferring zero-value coins wastes gas, may bypass minimum amount checks, or creates misleading events.

### Vulnerable
```move
module example::fee_collector {
    use std::signer;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;

    struct FeeConfig has key {
        fee_bps: u64,
        treasury: address,
    }

    public entry fun process_payment(
        payer: &signer,
        amount: u64
    ) acquires FeeConfig {
        let config = borrow_global<FeeConfig>(@example);
        let fee = amount * config.fee_bps / 10000;
        // BUG: If amount < 10000/fee_bps, fee is 0 due to integer division
        // Zero-amount transfer proceeds, bypassing the fee entirely
        coin::transfer<AptosCoin>(payer, config.treasury, fee);
        // User pays 0 fee on small transactions
    }
}
```

### Fixed
```move
module example::fee_collector {
    use std::signer;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;

    struct FeeConfig has key {
        fee_bps: u64,
        treasury: address,
        min_fee: u64,
    }

    const E_ZERO_AMOUNT: u64 = 1;

    public entry fun process_payment(
        payer: &signer,
        amount: u64
    ) acquires FeeConfig {
        assert!(amount > 0, E_ZERO_AMOUNT);
        let config = borrow_global<FeeConfig>(@example);
        let fee = amount * config.fee_bps / 10000;
        // Enforce minimum fee to prevent zero-fee bypass
        if (fee < config.min_fee) {
            fee = config.min_fee;
        };
        coin::transfer<AptosCoin>(payer, config.treasury, fee);
    }
}
```

---

## Pattern 2: Coin Merge/Extract Amount Mismatch

Extracting more coins than available in a `Coin<T>` value or merging coins incorrectly, leading to abort or balance corruption.

### Vulnerable
```move
module example::splitter {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;

    struct SplitVault has key {
        pool: Coin<AptosCoin>,
    }

    public fun split_and_distribute(
        vault: &mut SplitVault,
        share_a: u64,
        share_b: u64,
        addr_a: address,
        addr_b: address
    ) {
        let pool_value = coin::value(&vault.pool);
        // BUG: No check that share_a + share_b <= pool_value
        // If shares exceed pool, second extract will abort
        let coins_a = coin::extract(&mut vault.pool, share_a);
        let coins_b = coin::extract(&mut vault.pool, share_b);
        coin::deposit(addr_a, coins_a);
        coin::deposit(addr_b, coins_b);
    }
}
```

### Fixed
```move
module example::splitter {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;

    struct SplitVault has key {
        pool: Coin<AptosCoin>,
    }

    const E_INSUFFICIENT_BALANCE: u64 = 1;

    public fun split_and_distribute(
        vault: &mut SplitVault,
        share_a: u64,
        share_b: u64,
        addr_a: address,
        addr_b: address
    ) {
        let pool_value = coin::value(&vault.pool);
        // Validate total extraction does not exceed pool balance
        assert!(share_a + share_b <= pool_value, E_INSUFFICIENT_BALANCE);
        let coins_a = coin::extract(&mut vault.pool, share_a);
        let coins_b = coin::extract(&mut vault.pool, share_b);
        coin::deposit(addr_a, coins_a);
        coin::deposit(addr_b, coins_b);
    }
}
```

---

## Pattern 3: Unregistered FungibleAsset Metadata

Operating on a fungible asset without initializing its metadata first causes runtime aborts when trying to mint, transfer, or query the asset.

### Vulnerable
```move
module example::custom_token {
    use std::signer;
    use std::string;
    use aptos_framework::fungible_asset::{Self, MintRef, TransferRef, Metadata};
    use aptos_framework::object;
    use aptos_framework::primary_fungible_store;

    struct TokenRefs has key {
        mint_ref: MintRef,
        transfer_ref: TransferRef,
    }

    // BUG: No init_module — metadata and refs never created
    // All subsequent operations will abort

    public entry fun mint_tokens(admin: &signer, to: address, amount: u64) acquires TokenRefs {
        let refs = borrow_global<TokenRefs>(@example);
        // Aborts: metadata object doesn't exist
        let fa = fungible_asset::mint(&refs.mint_ref, amount);
        primary_fungible_store::deposit(to, fa);
    }
}
```

### Fixed
```move
module example::custom_token {
    use std::signer;
    use std::string;
    use aptos_framework::fungible_asset::{Self, MintRef, TransferRef, Metadata};
    use aptos_framework::object;
    use aptos_framework::primary_fungible_store;

    struct TokenRefs has key {
        mint_ref: MintRef,
        transfer_ref: TransferRef,
    }

    // Initialize metadata during module deployment
    fun init_module(deployer: &signer) {
        let constructor_ref = object::create_named_object(deployer, b"MY_TOKEN");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &constructor_ref,
            std::option::none(),
            string::utf8(b"My Token"),
            string::utf8(b"MTK"),
            8,
            string::utf8(b"https://example.com/icon.png"),
            string::utf8(b"https://example.com"),
        );
        let mint_ref = fungible_asset::generate_mint_ref(&constructor_ref);
        let transfer_ref = fungible_asset::generate_transfer_ref(&constructor_ref);
        move_to(deployer, TokenRefs { mint_ref, transfer_ref });
    }

    public entry fun mint_tokens(admin: &signer, to: address, amount: u64) acquires TokenRefs {
        let refs = borrow_global<TokenRefs>(@example);
        let fa = fungible_asset::mint(&refs.mint_ref, amount);
        primary_fungible_store::deposit(to, fa);
    }
}
```

---

## Pattern 4: Coin Dust Left After Operation

Partial coin extraction leaves a tiny remainder that becomes effectively unrecoverable, as it is too small to withdraw or transfer economically.

### Vulnerable
```move
module example::fee_splitter {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;

    struct FeePool has key {
        coins: Coin<AptosCoin>,
    }

    public fun distribute_fees(pool: &mut FeePool, recipients: u64) {
        let total = coin::value(&pool.coins);
        let share = total / recipients;
        // BUG: If total is not evenly divisible, remainder stays in pool
        // E.g., 100 coins / 3 = 33 each, 1 coin left as dust
        // Over time, dust accumulates and is never distributed
        let i = 0;
        while (i < recipients) {
            let portion = coin::extract(&mut pool.coins, share);
            // ... distribute portion
            coin::deposit(@example, portion);
            i = i + 1;
        };
        // pool.coins now holds undistributed dust
    }
}
```

### Fixed
```move
module example::fee_splitter {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;

    struct FeePool has key {
        coins: Coin<AptosCoin>,
    }

    public fun distribute_fees(
        pool: &mut FeePool,
        recipients: u64,
        last_recipient: address
    ) {
        let total = coin::value(&pool.coins);
        let share = total / recipients;
        let i = 0;
        while (i < recipients - 1) {
            let portion = coin::extract(&mut pool.coins, share);
            coin::deposit(@example, portion);
            i = i + 1;
        };
        // Last recipient gets remaining balance including any dust
        let remaining = coin::extract_all(&mut pool.coins);
        coin::deposit(last_recipient, remaining);
    }
}
```

---

## Signature
**Slug:** `coin-mishandling-->fund-loss`
**Detect:** For every coin/fungible asset operation: (1) verify non-zero amounts on coin operations, (2) verify extraction amounts do not exceed available balance, (3) verify fungible asset metadata is initialized, (4) verify full extraction to avoid dust accumulation.
**What's Wrong:** One or more coin operations allow zero-amount bypass, extract more than available, operate on uninitialized metadata, or leave unrecoverable dust.
**Remediation:** Reject zero-amount operations. Validate extraction amounts against available balance. Initialize fungible asset metadata before use. Handle full extraction to avoid dust.

---

## CL-COIN-02: Decimal Precision Invariant

**Rule:** `MOVE-COIN-SCALE-01`
**Severity:** high-critical

## Description
For every arithmetic operation involving coins or tokens with different decimal precisions, all operands must be normalized to a common unit system before comparison or calculation. Mixing different decimal precisions or using wrong time unit constants silently produces results off by orders of magnitude.

## Patterns

1. **Decimal Precision Mismatch in Cross-Asset Math** — Collateral and debt values with different token decimals (e.g., 6 vs 8) are used in arithmetic without normalization, producing results off by orders of magnitude.

```move
// VULNERABLE: 8-decimal collateral vs 6-decimal debt, no normalization
public fun collateral_to_return(debt_amount: u64, price: u64): u64 {
    debt_amount * PRECISION / price // debt is 6 decimals, result treated as 8
}

// FIXED: normalize to common precision
public fun collateral_to_return(debt_amount: u64, debt_decimals: u8, coll_decimals: u8, price: u64): u64 {
    let normalized = if (coll_decimals > debt_decimals) {
        debt_amount * math::pow(10, (coll_decimals - debt_decimals) as u64)
    } else {
        debt_amount / math::pow(10, (debt_decimals - coll_decimals) as u64)
    };
    normalized * PRECISION / price
}
```

2. **Time Unit Constant Error** — A time duration constant uses the wrong unit (milliseconds vs seconds, hours vs days), causing interest accrual, cooldown periods, or rate calculations to be off by 1000x or 24x.

```move
// VULNERABLE: SECONDS_PER_YEAR defined in milliseconds
const SECONDS_PER_YEAR: u64 = 31_536_000_000; // milliseconds, not seconds

public fun accrue_interest(pool: &mut Pool, elapsed: u64) {
    let rate = pool.annual_rate * elapsed / SECONDS_PER_YEAR; // 1000x too small
}

// FIXED: correct unit
const SECONDS_PER_YEAR: u64 = 31_536_000; // actual seconds

public fun accrue_interest(pool: &mut Pool, elapsed: u64) {
    let rate = pool.annual_rate * elapsed / SECONDS_PER_YEAR;
}
```

## Remediation
Establish a canonical internal precision for the protocol and convert all external values at the boundary. Verify all time constants against their usage context (seconds vs milliseconds).

## Signature
**Slug:** `decimal-precision-invariant`
**Detect:** For every cross-asset arithmetic operation: (1) verify decimal precisions are normalized before comparison or calculation, (2) verify time constants use correct units matching the runtime API.
**What's Wrong:** Arithmetic operations silently produce incorrect results by mixing values with different decimal precisions or using wrong time unit constants.
**Remediation:** Normalize all values to a common precision at computation boundaries and verify time constants match runtime units.

---
