# CAT-COIN — Coin/Token

## CL-COIN-01: Coin/Token Handling

**Rule:** `MOVE-COIN-HAND-01`
**Severity:** Medium-High

### Description
Zero-amount operations bypass validation, balance split/join amounts are miscalculated, coin metadata is uninitialized, or partial operations leave unrecoverable dust. Zero-value operations waste gas or bypass fee checks, incorrect splitting causes balance corruption or fund loss, uninitialized coin metadata causes runtime aborts, and coin dust becomes permanently locked.

### Patterns

#### Pattern 1: Zero-Amount Coin Operations
Creating or transferring zero-value coins wastes gas, may bypass minimum amount checks, or creates misleading events.

**Vulnerable:**
```move
module example::fee_collector {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    public struct FeeConfig has key {
        id: UID,
        fee_bps: u64,
        treasury: address,
    }

    public entry fun process_payment(
        config: &FeeConfig,
        payment: &mut Coin<SUI>,
        ctx: &mut TxContext
    ) {
        let amount = coin::value(payment);
        let fee = amount * config.fee_bps / 10000;
        // BUG: If amount < 10000/fee_bps, fee is 0 due to integer division
        // Zero-amount transfer proceeds, bypassing the fee entirely
        let fee_coin = coin::split(payment, fee, ctx);
        transfer::public_transfer(fee_coin, config.treasury);
        // User pays 0 fee on small transactions
    }
}
```

**Fixed:**
```move
module example::fee_collector {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    public struct FeeConfig has key {
        id: UID,
        fee_bps: u64,
        treasury: address,
        min_fee: u64,
    }

    const E_ZERO_AMOUNT: u64 = 1;

    public entry fun process_payment(
        config: &FeeConfig,
        payment: &mut Coin<SUI>,
        ctx: &mut TxContext
    ) {
        let amount = coin::value(payment);
        assert!(amount > 0, E_ZERO_AMOUNT);
        let fee = amount * config.fee_bps / 10000;
        // Enforce minimum fee to prevent zero-fee bypass
        let actual_fee = if (fee < config.min_fee) {
            config.min_fee
        } else {
            fee
        };
        let fee_coin = coin::split(payment, actual_fee, ctx);
        transfer::public_transfer(fee_coin, config.treasury);
    }
}
```

#### Pattern 2: Balance Split/Join Amount Mismatch
Splitting more from a `Balance<T>` than available or joining balances incorrectly, leading to abort or balance corruption.

**Vulnerable:**
```move
module example::splitter {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    public struct SplitVault has key {
        id: UID,
        pool: Balance<SUI>,
    }

    public fun split_and_distribute(
        vault: &mut SplitVault,
        share_a: u64,
        share_b: u64,
        addr_a: address,
        addr_b: address,
        ctx: &mut TxContext
    ) {
        let pool_value = balance::value(&vault.pool);
        // BUG: No check that share_a + share_b <= pool_value
        // If shares exceed pool, second split will abort
        let coins_a = coin::from_balance(balance::split(&mut vault.pool, share_a), ctx);
        let coins_b = coin::from_balance(balance::split(&mut vault.pool, share_b), ctx);
        transfer::public_transfer(coins_a, addr_a);
        transfer::public_transfer(coins_b, addr_b);
    }
}
```

**Fixed:**
```move
module example::splitter {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    public struct SplitVault has key {
        id: UID,
        pool: Balance<SUI>,
    }

    const E_INSUFFICIENT_BALANCE: u64 = 1;

    public fun split_and_distribute(
        vault: &mut SplitVault,
        share_a: u64,
        share_b: u64,
        addr_a: address,
        addr_b: address,
        ctx: &mut TxContext
    ) {
        let pool_value = balance::value(&vault.pool);
        // Validate total extraction does not exceed pool balance
        assert!(share_a + share_b <= pool_value, E_INSUFFICIENT_BALANCE);
        let coins_a = coin::from_balance(balance::split(&mut vault.pool, share_a), ctx);
        let coins_b = coin::from_balance(balance::split(&mut vault.pool, share_b), ctx);
        transfer::public_transfer(coins_a, addr_a);
        transfer::public_transfer(coins_b, addr_b);
    }
}
```

#### Pattern 3: Uninitialized Coin TreasuryCap
Minting coins without properly creating the currency via `coin::create_currency` causes runtime aborts because `TreasuryCap` and `CoinMetadata` do not exist.

**Vulnerable:**
```move
module example::custom_token {
    use sui::coin::{Self, TreasuryCap, CoinMetadata};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    public struct MTK has drop {}

    // BUG: No init function — TreasuryCap and CoinMetadata never created
    // All subsequent mint operations will fail because TreasuryCap doesn't exist

    public entry fun mint_tokens(
        cap: &mut TreasuryCap<MTK>,
        amount: u64,
        to: address,
        ctx: &mut TxContext
    ) {
        // Aborts: TreasuryCap was never created via create_currency
        let minted = coin::mint(cap, amount, ctx);
        transfer::public_transfer(minted, to);
    }
}
```

**Fixed:**
```move
module example::custom_token {
    use sui::coin::{Self, TreasuryCap, CoinMetadata};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    public struct MTK has drop {}

    // Initialize coin metadata during module deployment
    fun init(witness: MTK, ctx: &mut TxContext) {
        let (treasury_cap, metadata) = coin::create_currency(
            witness,
            8,                              // decimals
            b"MTK",                         // symbol
            b"My Token",                    // name
            b"Example token",              // description
            option::none(),                 // icon_url
            ctx
        );
        transfer::public_freeze_object(metadata);
        transfer::public_transfer(treasury_cap, tx_context::sender(ctx));
    }

    public entry fun mint_tokens(
        cap: &mut TreasuryCap<MTK>,
        amount: u64,
        to: address,
        ctx: &mut TxContext
    ) {
        let minted = coin::mint(cap, amount, ctx);
        transfer::public_transfer(minted, to);
    }
}
```

#### Pattern 4: Coin Dust Left After Operation
Partial balance splitting leaves a tiny remainder that becomes effectively unrecoverable, as it is too small to withdraw or transfer economically.

**Vulnerable:**
```move
module example::fee_splitter {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    public struct FeePool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    public fun distribute_fees(
        pool: &mut FeePool,
        recipients: u64,
        ctx: &mut TxContext
    ) {
        let total = balance::value(&pool.balance);
        let share = total / recipients;
        // BUG: If total is not evenly divisible, remainder stays in pool
        // E.g., 100 coins / 3 = 33 each, 1 coin left as dust
        // Over time, dust accumulates and is never distributed
        let i = 0;
        while (i < recipients) {
            let portion = coin::from_balance(balance::split(&mut pool.balance, share), ctx);
            // ... distribute portion
            transfer::public_transfer(portion, @example);
            i = i + 1;
        };
        // pool.balance now holds undistributed dust
    }
}
```

**Fixed:**
```move
module example::fee_splitter {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    public struct FeePool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    public fun distribute_fees(
        pool: &mut FeePool,
        recipients: u64,
        last_recipient: address,
        ctx: &mut TxContext
    ) {
        let total = balance::value(&pool.balance);
        let share = total / recipients;
        let i = 0;
        while (i < recipients - 1) {
            let portion = coin::from_balance(balance::split(&mut pool.balance, share), ctx);
            transfer::public_transfer(portion, @example);
            i = i + 1;
        };
        // Last recipient gets remaining balance including any dust
        let remaining_val = balance::value(&pool.balance);
        let remaining_balance = balance::split(&mut pool.balance, remaining_val);
        let remaining = coin::from_balance(remaining_balance, ctx);
        transfer::public_transfer(remaining, last_recipient);
    }
}
```

### Remediation
Reject zero-amount operations. Validate split amounts against available balance. Initialize coin metadata before use. Handle full extraction to avoid dust.

### Signature
**Slug:** `coin-mishandling-->fund-loss`
**Detect:** For every coin/balance operation: (1) verify non-zero amounts on coin operations, (2) verify split amounts do not exceed available balance, (3) verify coin metadata is initialized via `create_currency`, (4) verify full extraction to avoid dust accumulation.
**What's Wrong:** One or more coin operations allow zero-amount bypass, split more than available, operate on uninitialized coin metadata, or leave unrecoverable dust.
**Remediation:** Reject zero-amount operations. Validate split amounts against available balance. Initialize coin metadata before use. Handle full extraction to avoid dust.

---

## CL-COIN-02: Decimal Precision

**Rule:** `MOVE-COIN-SCALE-01`
**Severity:** High-Critical

### Description
For every arithmetic operation involving coins or tokens with different decimal precisions, all operands must be normalized to a common unit system before comparison or calculation. Mixing different decimal precisions or using wrong time unit constants silently produces results off by orders of magnitude.

### Patterns

#### Pattern 1: Decimal Precision Mismatch in Cross-Asset Math
Collateral and debt values with different token decimals (e.g., 6 vs 8) are used in arithmetic without normalization, producing results off by orders of magnitude.

**Vulnerable:**
```move
// VULNERABLE: 8-decimal collateral vs 6-decimal debt, no normalization
public fun collateral_to_return(debt_amount: u64, price: u64): u64 {
    debt_amount * PRECISION / price // debt is 6 decimals, result treated as 8
}
```

**Fixed:**
```move
// FIXED: normalize to common precision
public fun collateral_to_return(debt_amount: u64, debt_decimals: u8, coll_decimals: u8, price: u64): u64 {
    let normalized = if (coll_decimals > debt_decimals) {
        debt_amount * math::pow(10, (coll_decimals - debt_decimals))
    } else {
        debt_amount / math::pow(10, (debt_decimals - coll_decimals))
    };
    normalized * PRECISION / price
}
```

#### Pattern 2: Time Unit Constant Error
A time duration constant uses the wrong unit (milliseconds vs seconds, hours vs days), causing interest accrual, cooldown periods, or rate calculations to be off by 1000x or 24x.

**Vulnerable:**
```move
// VULNERABLE: SECONDS_PER_YEAR defined in milliseconds
const SECONDS_PER_YEAR: u64 = 31_536_000_000; // milliseconds, not seconds

public fun accrue_interest(pool: &mut Pool, elapsed: u64) {
    let rate = pool.annual_rate * elapsed / SECONDS_PER_YEAR; // 1000x too small
}
```

**Fixed:**
```move
// FIXED: correct unit
const SECONDS_PER_YEAR: u64 = 31_536_000; // actual seconds

public fun accrue_interest(pool: &mut Pool, elapsed: u64) {
    let rate = pool.annual_rate * elapsed / SECONDS_PER_YEAR;
}
```

### Remediation
Establish a canonical internal precision for the protocol and convert all external values at the boundary. Verify all time constants against their usage context (seconds vs milliseconds).

### Signature
**Slug:** `decimal-precision-invariant`
**Detect:** For every cross-asset arithmetic operation: (1) verify decimal precisions are normalized before comparison or calculation, (2) verify time constants use correct units matching the runtime API.
**What's Wrong:** Arithmetic operations silently produce incorrect results by mixing values with different decimal precisions or using wrong time unit constants.
**Remediation:** Normalize all values to a common precision at computation boundaries and verify time constants match runtime units.
