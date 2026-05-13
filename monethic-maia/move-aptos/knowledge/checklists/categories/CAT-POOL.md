# CAT-POOL: Pool/DEX/Staking

**Context:** `ctx:pool`
**Detectors:** 8

## CL-POOL-01: Pool Accounting & Share Arithmetic Invariant

**Rule:** `MOVE-POOL-ACCT-01`
**Severity:** medium-critical

## Description
For every pool operation that modifies balances, shares, or debt records, the protocol must maintain exact bidirectional consistency between asset amounts, share conversions, and internal accounting state. Rounding must always favor the protocol, and every fund outflow must be reflected in the corresponding internal ledger.

## Patterns

1. **Share-Asset Conversion Bypass** — Pool logic directly assigns raw asset amounts to share variables (or vice versa) without applying the exchange rate conversion, inflating or deflating positions.

```move
// VULNERABLE: direct assignment without conversion
public fun liquidate(obligation: &mut Obligation, amount: u64) {
    let seized = calculate_seize_amount(amount);
    obligation.collateral_shares = seized; // raw amount assigned to shares field
}

// FIXED: proper share conversion
public fun liquidate(obligation: &mut Obligation, amount: u64) {
    let seized = calculate_seize_amount(amount);
    obligation.collateral_shares = amount_to_shares(seized, pool.exchange_rate);
}
```

2. **Protocol-Adverse Rounding** — Debt share calculations round down when issuing debt (favoring borrower) or round down when calculating repayment (shortchanging the protocol), violating the invariant that rounding always favors the pool.

```move
// VULNERABLE: rounds down debt shares on borrow (borrower gets cheaper debt)
public fun borrow(pool: &mut Pool, amount: u64): u64 {
    let shares = amount * pool.total_shares / pool.total_debt; // floor division
    pool.total_shares = pool.total_shares + shares;
    shares
}

// FIXED: round up debt shares on borrow
public fun borrow(pool: &mut Pool, amount: u64): u64 {
    let shares = (amount * pool.total_shares + pool.total_debt - 1) / pool.total_debt;
    pool.total_shares = pool.total_shares + shares;
    shares
}
```

3. **Untracked Fund Outflow** — Assets leave the module via transfer, but the internal accounting (total_assets, reserves, pool balance) is not decremented, creating phantom liquidity.

```move
// VULNERABLE: transfers fee but doesn't reduce pool accounting
public fun collect_fee<T>(account: &signer, pool_addr: address) acquires Pool {
    let pool = borrow_global_mut<Pool<T>>(pool_addr);
    let fee_amount = pool.accrued_fee;
    let fee_coin = coin::extract(&mut pool.balance, fee_amount);
    coin::deposit(pool.treasury, fee_coin);
    pool.accrued_fee = 0;
    // pool.total_assets not decremented!
}

// FIXED: decrement total assets
public fun collect_fee<T>(account: &signer, pool_addr: address) acquires Pool {
    let pool = borrow_global_mut<Pool<T>>(pool_addr);
    let fee_amount = pool.accrued_fee;
    let fee_coin = coin::extract(&mut pool.balance, fee_amount);
    coin::deposit(pool.treasury, fee_coin);
    pool.total_assets = pool.total_assets - fee_amount;
    pool.accrued_fee = 0;
}
```

4. **Incomplete Debt in Health Calculation** — Collateral ratio or health factor computed using only principal debt, omitting accrued interest, pending fees, or flash loan obligations.

```move
// VULNERABLE: health factor ignores accrued interest
public fun health_factor(obligation: &Obligation, price: u64): u64 {
    let collateral_value = obligation.collateral * price;
    collateral_value / obligation.principal_debt // misses interest
}

// FIXED: include all debt components
public fun health_factor(obligation: &Obligation, price: u64): u64 {
    let collateral_value = obligation.collateral * price;
    let total_debt = obligation.principal_debt + obligation.accrued_interest;
    collateral_value / total_debt
}
```

5. **Flash Loan Repayment Inflation** — Flash loan settlement treats the entire repayment (principal + interest) as new profit, inflating the pool's exchange rate and diluting other depositors.

```move
// VULNERABLE: full repayment counted as earnings
public fun settle_flash_loan<T>(pool_addr: address, repaid: Coin<T>) acquires Pool {
    let pool = borrow_global_mut<Pool<T>>(pool_addr);
    let amount = coin::value(&repaid);
    pool.total_earned = pool.total_earned + amount; // includes principal!
    coin::merge(&mut pool.balance, repaid);
}

// FIXED: only fee portion is profit
public fun settle_flash_loan<T>(pool_addr: address, repaid: Coin<T>, principal: u64) acquires Pool {
    let pool = borrow_global_mut<Pool<T>>(pool_addr);
    let amount = coin::value(&repaid);
    let fee = amount - principal;
    pool.total_earned = pool.total_earned + fee;
    coin::merge(&mut pool.balance, repaid);
}
```

## Remediation
Enforce strict share-asset conversion on every assignment. Use ceil rounding for debt issuance and floor rounding for debt repayment. Every fund outflow must have a matching internal accounting decrement. Health factor calculations must include all debt components (principal + interest + fees). Flash loan settlements must separate principal return from fee income.

## Signature
**Slug:** `pool-accounting-share-arithmetic-invariant`
**Detect:** For every pool operation that modifies balances or shares: (1) verify share-asset conversions use exchange rate, (2) verify rounding direction favors protocol, (3) verify all fund outflows decrement internal accounting, (4) verify health calculations include total debt, (5) verify flash loan settlements separate principal from fee.
**What's Wrong:** Pool accounting fails to maintain consistency between raw asset amounts and internal share/debt representations, enabling value extraction through conversion bypasses, adverse rounding, untracked outflows, incomplete debt calculations, or flash loan inflation.
**Remediation:** Enforce bidirectional conversion on every share-asset boundary, protocol-favorable rounding on all debt arithmetic, matched accounting on every fund movement, and complete debt aggregation in every health computation.

---

## CL-POOL-02: AMM Invariant & Slippage Enforcement

**Rule:** `MOVE-POOL-AMM-01`
**Severity:** low-critical

## Precondition
The protocol implements an AMM with constant product, stable swap, or other bonding curve math, and exposes swap/liquidity operations to users.

## Root Cause
The swap or liquidity math fails to correctly enforce the pool invariant, price formulas are inverted, liquidity provision ratio is incorrect, or slippage/deadline protection is missing on user-facing operations.

## Impact
Attackers drain pool reserves via broken invariant checks, mispriced swaps, or sandwich attacks on unprotected operations. Missing deadlines allow stale execution.

## Remediation
Enforce k_new >= k_old after every swap. Never recalculate invariant from post-swap state. Verify price formula direction. Accept user-supplied min_amount_out and deadline on every swap, add_liquidity, and remove_liquidity.

---

## Pattern 1 -- Missing or incorrect constant product invariant check

The swap function does not verify that k_new >= k_old after execution.

### Vulnerable

```move
public fun swap<X, Y>(pool: &mut Pool<X, Y>, coin_in: Coin<X>): Coin<Y> {
    let amount_in = coin::value(&coin_in);
    let amount_out = (pool.reserve_y * amount_in) / (pool.reserve_x + amount_in);
    pool.reserve_x = pool.reserve_x + amount_in;
    pool.reserve_y = pool.reserve_y - amount_out;
    // BUG: No invariant check -- k could decrease
    coin::extract(&mut pool.balance_y, amount_out)
}
```

### Fixed

```move
public fun swap<X, Y>(pool: &mut Pool<X, Y>, coin_in: Coin<X>): Coin<Y> {
    let k_before = (pool.reserve_x as u128) * (pool.reserve_y as u128);
    let amount_in = coin::value(&coin_in);
    let amount_out = (pool.reserve_y * amount_in) / (pool.reserve_x + amount_in);
    pool.reserve_x = pool.reserve_x + amount_in;
    pool.reserve_y = pool.reserve_y - amount_out;
    let k_after = (pool.reserve_x as u128) * (pool.reserve_y as u128);
    assert!(k_after >= k_before, ERR_INVARIANT_VIOLATED);
    coin::extract(&mut pool.balance_y, amount_out)
}
```

---

## Pattern 2 -- Stable curve invariant recalculated from post-swap state

The invariant D is recomputed using post-swap reserves instead of being preserved from the pre-swap snapshot, masking value leakage.

### Vulnerable

```move
public fun stable_swap<X, Y>(pool: &mut StablePool<X, Y>, coin_in: Coin<X>): Coin<Y> {
    let amount_in = coin::value(&coin_in);
    pool.reserve_x = pool.reserve_x + amount_in;
    // BUG: D is recalculated from new reserves -- any output satisfies it
    let d_new = compute_d(pool.reserve_x, pool.reserve_y, pool.amp);
    let new_y = compute_y(pool.reserve_x, d_new, pool.amp);
    let amount_out = pool.reserve_y - new_y;
    pool.reserve_y = new_y;
    coin::extract(&mut pool.balance_y, amount_out)
}
```

### Fixed

```move
public fun stable_swap<X, Y>(pool: &mut StablePool<X, Y>, coin_in: Coin<X>): Coin<Y> {
    let amount_in = coin::value(&coin_in);
    let d_before = compute_d(pool.reserve_x, pool.reserve_y, pool.amp);
    pool.reserve_x = pool.reserve_x + amount_in;
    let new_y = compute_y(pool.reserve_x, d_before, pool.amp);
    let amount_out = pool.reserve_y - new_y;
    pool.reserve_y = new_y;
    let d_after = compute_d(pool.reserve_x, pool.reserve_y, pool.amp);
    assert!(d_after >= d_before, ERR_INVARIANT_VIOLATED);
    coin::extract(&mut pool.balance_y, amount_out)
}
```

---

## Pattern 3 -- Inverted price calculation formula

The price function swaps numerator and denominator, computing Quote/Base instead of Base/Quote (or vice versa), returning reciprocal prices.

### Vulnerable

```move
public fun get_price<X, Y>(pool: &Pool<X, Y>): u128 {
    // BUG: Inverted -- returns reserve_y/reserve_x instead of reserve_x/reserve_y
    ((pool.reserve_y as u128) * PRECISION) / (pool.reserve_x as u128)
}
```

### Fixed

```move
public fun get_price<X, Y>(pool: &Pool<X, Y>): u128 {
    // Price of X in terms of Y -- ensure convention matches callers
    ((pool.reserve_x as u128) * PRECISION) / (pool.reserve_y as u128)
}
```

---

## Pattern 4 -- No slippage on swap, add_liquidity, or remove_liquidity

User-facing operations lack a `min_amount_out` parameter, allowing sandwich attacks. Applies to swaps (no min output), add_liquidity (no min LP), and remove_liquidity (no min tokens back).

### Vulnerable

```move
public entry fun swap<X, Y>(pool: &mut Pool<X, Y>, coin_in: Coin<X>, account: &signer) {
    let coin_out = pool::exchange(pool, coin_in);
    // BUG: No min_amount_out -- any execution price accepted
    coin::deposit(signer::address_of(account), coin_out);
}

public entry fun remove_liquidity<X, Y>(pool: &mut Pool<X, Y>, lp: Coin<LP<X,Y>>, account: &signer) {
    let (coin_x, coin_y) = pool::burn(pool, lp);
    // BUG: No minimum output checks
    coin::deposit(signer::address_of(account), coin_x);
    coin::deposit(signer::address_of(account), coin_y);
}
```

### Fixed

```move
public entry fun swap<X, Y>(
    pool: &mut Pool<X, Y>, coin_in: Coin<X>,
    min_amount_out: u64, account: &signer
) {
    let coin_out = pool::exchange(pool, coin_in);
    assert!(coin::value(&coin_out) >= min_amount_out, ERR_SLIPPAGE);
    coin::deposit(signer::address_of(account), coin_out);
}

public entry fun remove_liquidity<X, Y>(
    pool: &mut Pool<X, Y>, lp: Coin<LP<X,Y>>,
    min_x: u64, min_y: u64, account: &signer
) {
    let (coin_x, coin_y) = pool::burn(pool, lp);
    assert!(coin::value(&coin_x) >= min_x, ERR_SLIPPAGE);
    assert!(coin::value(&coin_y) >= min_y, ERR_SLIPPAGE);
    coin::deposit(signer::address_of(account), coin_x);
    coin::deposit(signer::address_of(account), coin_y);
}
```

---

## Pattern 5 -- Missing deadline parameter

No transaction deadline check. Validators or sequencers can hold the transaction and execute it later when the price has moved unfavorably.

### Vulnerable

```move
public entry fun swap<X, Y>(
    pool: &mut Pool<X, Y>, coin_in: Coin<X>,
    min_amount_out: u64, account: &signer
) {
    // BUG: No deadline -- tx can be held and executed hours/days later
    let coin_out = pool::exchange(pool, coin_in);
    assert!(coin::value(&coin_out) >= min_amount_out, ERR_SLIPPAGE);
    coin::deposit(signer::address_of(account), coin_out);
}
```

### Fixed

```move
public entry fun swap<X, Y>(
    pool: &mut Pool<X, Y>, coin_in: Coin<X>,
    min_amount_out: u64, deadline: u64,
    account: &signer
) {
    assert!(timestamp::now_seconds() <= deadline, ERR_EXPIRED);
    let coin_out = pool::exchange(pool, coin_in);
    assert!(coin::value(&coin_out) >= min_amount_out, ERR_SLIPPAGE);
    coin::deposit(signer::address_of(account), coin_out);
}
```

---

## Signature
- **detect**: For every swap or liquidity function: (1) verify constant product invariant k_new >= k_old is enforced, (2) verify stable curve invariant D is not recalculated from post-swap state, (3) verify price formula direction is correct, (4) verify user-supplied min_amount_out exists on swap/add/remove, (5) verify deadline parameter exists.
- **whats_wrong**: AMM invariant is missing or recalculated from post-swap state, price formulas are inverted, slippage protection is missing on swap/add/remove operations, or deadline parameter is absent.
- **remediation**: Enforce k_new >= k_old after every swap. Never recalculate invariant from post-swap state. Accept user-supplied min_amount_out and deadline on every user-facing operation.

---

## CL-POOL-03: Flash Loan Safety

**Rule:** `MOVE-POOL-FLASH-01`
**Severity:** low-critical

## Precondition
The protocol offers flash loans or has unordered operations that can function as implicit flash loans.

## Root Cause
Flash loan receipt validation is incomplete — missing asset type, pool ID, or amount verification in the repayment function, or operation ordering allows implicit flash loans.

## Impact
Attackers borrow from one pool and repay to another, steal assets by repaying with wrong token type, or use add/remove liquidity sequences as fee-free flash loans.

## Remediation
Store pool ID, asset type, and borrowed amount in the receipt. Validate all three fields on repayment. Enforce operation ordering or per-block cooldowns to prevent implicit flash loans.

---

## Pattern 1 -- Flash loan receipt missing pool or asset identifier

The receipt struct only stores the borrowed amount, not which pool or asset type was borrowed. Repayment can target any pool.

### Vulnerable

```move
struct FlashReceipt {
    amount: u64,
    // BUG: No pool_addr or asset type stored
}

public fun flash_borrow<X>(account: &signer, pool_addr: address, amount: u64): (Coin<X>, FlashReceipt) acquires Pool {
    let pool = borrow_global_mut<Pool<X>>(pool_addr);
    let coin = coin::extract(&mut pool.balance, amount);
    (coin, FlashReceipt { amount })
}

public fun flash_repay<X>(pool_addr: address, coin: Coin<X>, receipt: FlashReceipt) acquires Pool {
    let FlashReceipt { amount } = receipt;
    let pool = borrow_global_mut<Pool<X>>(pool_addr);
    // BUG: Any pool accepts this receipt
    assert!(coin::value(&coin) >= amount + calc_fee(amount), ERR_INSUFFICIENT);
    coin::merge(&mut pool.balance, coin);
}
```

### Fixed

```move
struct FlashReceipt {
    pool_addr: address,
    asset_type: TypeInfo,
    amount: u64,
}

public fun flash_borrow<X>(account: &signer, pool_addr: address, amount: u64): (Coin<X>, FlashReceipt) acquires Pool {
    let pool = borrow_global_mut<Pool<X>>(pool_addr);
    let coin = coin::extract(&mut pool.balance, amount);
    (coin, FlashReceipt {
        pool_addr,
        asset_type: type_info::type_of<X>(),
        amount,
    })
}

public fun flash_repay<X>(pool_addr: address, coin: Coin<X>, receipt: FlashReceipt) acquires Pool {
    let FlashReceipt { pool_addr: receipt_addr, asset_type, amount } = receipt;
    assert!(receipt_addr == pool_addr, ERR_WRONG_POOL);
    assert!(asset_type == type_info::type_of<X>(), ERR_WRONG_ASSET);
    let pool = borrow_global_mut<Pool<X>>(pool_addr);
    assert!(coin::value(&coin) >= amount + calc_fee(amount), ERR_INSUFFICIENT);
    coin::merge(&mut pool.balance, coin);
}
```

---

## Pattern 2 -- Repayment with wrong asset type accepted

The repay function accepts a generic Coin<T> without checking that T matches the originally borrowed asset type.

### Vulnerable

```move
public fun repay_flash<T>(pool_addr: address, coin: Coin<T>, receipt: FlashReceipt) acquires Pool {
    let FlashReceipt { amount } = receipt;
    let pool = borrow_global_mut<Pool<T>>(pool_addr);
    // BUG: No type check -- can borrow USDC, repay with worthless token
    assert!(coin::value(&coin) >= amount, ERR_AMOUNT);
    coin::merge(&mut pool.balance, coin);
}
```

### Fixed

```move
public fun repay_flash<T>(pool_addr: address, coin: Coin<T>, receipt: FlashReceipt) acquires Pool {
    let FlashReceipt { amount, asset_type, pool_addr: receipt_addr } = receipt;
    assert!(type_info::type_of<T>() == asset_type, ERR_WRONG_ASSET);
    let pool = borrow_global_mut<Pool<T>>(pool_addr);
    assert!(coin::value(&coin) >= amount + calc_fee(amount), ERR_AMOUNT);
    coin::merge(&mut pool.balance, coin);
}
```

---

## Pattern 3 -- Flash loan receipt uses user input instead of actual borrowed amount

The receipt records the user-requested amount rather than the actual coins extracted, allowing underpayment.

### Vulnerable

```move
public fun flash_borrow<X>(
    pool_addr: address,
    requested_amount: u64,
): (Coin<X>, FlashReceipt) acquires Pool {
    let pool = borrow_global_mut<Pool<X>>(pool_addr);
    let actual = min(requested_amount, pool.available);
    let coin = coin::extract(&mut pool.balance, actual);
    // BUG: Receipt stores requested_amount, not actual
    (coin, FlashReceipt { amount: requested_amount })
}
```

### Fixed

```move
public fun flash_borrow<X>(
    pool_addr: address,
    requested_amount: u64,
): (Coin<X>, FlashReceipt) acquires Pool {
    let pool = borrow_global_mut<Pool<X>>(pool_addr);
    let actual = min(requested_amount, pool.available);
    let coin = coin::extract(&mut pool.balance, actual);
    // Store actual borrowed amount
    (coin, FlashReceipt { amount: actual, /* ... */ })
}
```

---

## Pattern 4 -- Flash loan receipt ID not validated on repayment

Receipts carry a unique ID but the repayment function does not check it, allowing receipt reuse or cross-pool repayment.

### Vulnerable

```move
public fun repay<X>(pool_addr: address, coin: Coin<X>, receipt: FlashReceipt) acquires Pool {
    let FlashReceipt { id: _id, amount } = receipt;
    let pool = borrow_global_mut<Pool<X>>(pool_addr);
    // BUG: _id is ignored -- any receipt works for any pool
    assert!(coin::value(&coin) >= amount, ERR_AMOUNT);
    coin::merge(&mut pool.balance, coin);
}
```

### Fixed

```move
public fun repay<X>(pool_addr: address, coin: Coin<X>, receipt: FlashReceipt) acquires Pool {
    let FlashReceipt { id, amount } = receipt;
    let pool = borrow_global_mut<Pool<X>>(pool_addr);
    assert!(id == pool.flash_loan_id, ERR_WRONG_RECEIPT);
    assert!(coin::value(&coin) >= amount + calc_fee(amount), ERR_AMOUNT);
    coin::merge(&mut pool.balance, coin);
}
```

---

## Pattern 5 -- Implicit flash loan via atomic add/remove liquidity

No ordering constraint or cooldown prevents adding liquidity (receiving pool tokens) and immediately removing it in the same transaction, creating a fee-free flash loan. On Aptos, multi-step scripts can combine add + arbitrage + remove in a single transaction.

### Vulnerable

```move
// Attacker in a single transaction script:
// 1. add_liquidity(pool, coin_a, coin_b) -> receive LP tokens
// 2. Use pool reserves (now inflated) for arbitrage
// 3. remove_liquidity(pool, lp_tokens) -> get coins back
// BUG: No per-block or per-tx cooldown between add and remove
public fun add_liquidity<X, Y>(account: &signer, pool_addr: address, /*...*/) acquires Pool { /* no timestamp lock */ }
public fun remove_liquidity<X, Y>(account: &signer, pool_addr: address, /*...*/) acquires Pool { /* no timestamp check */ }
```

### Fixed

```move
public fun add_liquidity<X, Y>(account: &signer, pool_addr: address, /*...*/) acquires Pool, Position {
    let addr = signer::address_of(account);
    let position = borrow_global_mut<Position<X, Y>>(addr);
    // Record deposit timestamp on position
    position.last_deposit_time = timestamp::now_seconds();
    // ...
}

public fun remove_liquidity<X, Y>(account: &signer, pool_addr: address, /*...*/) acquires Pool, Position {
    let addr = signer::address_of(account);
    let position = borrow_global<Position<X, Y>>(addr);
    // Enforce minimum holding period
    assert!(
        timestamp::now_seconds() > position.last_deposit_time + MIN_HOLD_SECONDS,
        ERR_TOO_SOON_WITHDRAWAL
    );
    // ...
}
```

---

## Signature
- **detect**: For every flash loan issuance and repayment path: (1) verify the receipt stores the source pool identifier, (2) verify the receipt stores the borrowed asset type, (3) verify repayment validates the receipt amount against actual repayment, (4) verify the repayment asset type matches the borrowed asset type, (5) verify add/remove liquidity cannot be combined atomically to create implicit flash loans.
- **whats_wrong**: Flash loan receipts lack pool ID, asset type, or amount fields; repayment functions skip validation of these fields; or atomic add-then-remove liquidity creates fee-free flash loans.
- **remediation**: Store pool ID, asset type, and borrowed amount in the receipt. Validate all three fields on repayment. Enforce operation ordering or per-block cooldowns to prevent implicit flash loans.

---

## CL-POOL-04: Pool Initialization Safety

**Rule:** `MOVE-POOL-INIT-01`
**Severity:** medium-critical

## Precondition
The protocol allows creation of new liquidity pools with user-specified asset types and initial liquidity.

## Root Cause
Pool initialization lacks guards on asset identity, uniqueness, token ordering, initial price ratio, or minimum liquidity lock, allowing broken or duplicate pools.

## Impact
Identical-asset pools enable risk-free reward farming. Duplicate pools fragment liquidity. Missing minimum liquidity lock enables share inflation attacks. Unordered token pairs cause state corruption.

## Remediation
Assert asset types are distinct and canonically ordered. Enforce pool uniqueness via a registry. Lock minimum initial liquidity (e.g., burn MINIMUM_LIQUIDITY LP tokens). Validate initial deposit ratio.

---

## Pattern 1 -- Identical asset pair pool creation

No guard prevents creating a pool where both assets are the same type, breaking AMM invariants and enabling risk-free LP farming.

### Vulnerable

```move
public fun create_pool<X, Y>(admin: &signer): Pool<X, Y> {
    // BUG: No check that X != Y -- allows Pool<USDC, USDC>
    Pool<X, Y> { reserve_x: 0, reserve_y: 0, total_lp: 0 }
}
```

### Fixed

```move
public fun create_pool<X, Y>(admin: &signer): Pool<X, Y> {
    assert!(type_info::type_of<X>() != type_info::type_of<Y>(), ERR_IDENTICAL_ASSETS);
    Pool<X, Y> { reserve_x: 0, reserve_y: 0, total_lp: 0 }
}
```

---

## Pattern 2 -- Unordered token pair creation

No canonical ordering enforced, allowing both Pool<A,B> and Pool<B,A> to exist, fragmenting liquidity and causing routing confusion.

### Vulnerable

```move
public fun create_pool<X, Y>(admin: &signer) {
    // BUG: No ordering check -- Pool<USDC, ETH> and Pool<ETH, USDC> can coexist
    let pool = Pool<X, Y> { reserve_x: 0, reserve_y: 0 };
    move_to(admin, pool);
}
```

### Fixed

```move
public fun create_pool<X, Y>(admin: &signer) {
    // Enforce canonical ordering: type_of<X>() < type_of<Y>()
    assert!(
        comparator::is_smaller_than(
            &comparator::compare(&type_info::type_of<X>(), &type_info::type_of<Y>())
        ),
        ERR_UNORDERED_PAIR
    );
    let pool = Pool<X, Y> { reserve_x: 0, reserve_y: 0 };
    move_to(admin, pool);
}
```

---

## Pattern 3 -- Duplicate pool creation for identical pairs

No registry or existence check prevents creating multiple pools for the same asset pair, fragmenting liquidity.

### Vulnerable

```move
public fun create_pool<X, Y>(admin: &signer) {
    // BUG: No uniqueness check -- can create multiple Pool<X, Y>
    let pool = Pool<X, Y> { reserve_x: 0, reserve_y: 0 };
    move_to(admin, pool);
}
```

### Fixed

```move
public fun create_pool<X, Y>(admin: &signer) {
    // Move semantics prevent double move_to for same type at same address,
    // but use a registry for multi-address deployments
    assert!(!exists<Pool<X, Y>>(signer::address_of(admin)), ERR_POOL_EXISTS);
    let pool = Pool<X, Y> { reserve_x: 0, reserve_y: 0 };
    move_to(admin, pool);
}
```

---

## Pattern 4 -- Missing minimum liquidity lock on first deposit

No LP tokens are burned or locked on initial deposit, enabling share price inflation attacks where the first depositor donates to inflate share value.

### Vulnerable

```move
public fun add_initial_liquidity<X, Y>(
    user: &signer, pool: &mut Pool<X, Y>,
    coin_x: Coin<X>, coin_y: Coin<Y>,
): Coin<LP<X, Y>> {
    let lp_amount = math::sqrt(coin::value(&coin_x) * coin::value(&coin_y));
    // BUG: All LP tokens go to first depositor -- no minimum lock
    pool.total_lp = lp_amount;
    coin::mint<LP<X, Y>>(lp_amount)
}
```

### Fixed

```move
const MINIMUM_LIQUIDITY: u64 = 1000;

public fun add_initial_liquidity<X, Y>(
    user: &signer, pool: &mut Pool<X, Y>,
    coin_x: Coin<X>, coin_y: Coin<Y>,
): Coin<LP<X, Y>> {
    let lp_amount = math::sqrt(coin::value(&coin_x) * coin::value(&coin_y));
    assert!(lp_amount > MINIMUM_LIQUIDITY, ERR_INSUFFICIENT_INITIAL_LIQ);
    // Lock minimum liquidity by burning it
    pool.total_lp = lp_amount;
    let user_lp = lp_amount - MINIMUM_LIQUIDITY;
    coin::mint<LP<X, Y>>(user_lp) // MINIMUM_LIQUIDITY is permanently locked
}
```

---

## Pattern 5 -- Unconstrained initial deposit ratio

First liquidity provision sets the pool price with no constraint, allowing manipulation of the initial price to extract value from subsequent depositors.

### Vulnerable

```move
public fun add_initial_liquidity<X, Y>(
    user: &signer, pool: &mut Pool<X, Y>,
    amount_x: u64, amount_y: u64,
) {
    // BUG: Any ratio accepted -- attacker sets 1 wei : 1M tokens
    pool.reserve_x = amount_x;
    pool.reserve_y = amount_y;
    let lp = math::sqrt(amount_x * amount_y);
    pool.total_lp = lp;
}
```

### Fixed

```move
public fun add_initial_liquidity<X, Y>(
    user: &signer, pool: &mut Pool<X, Y>,
    amount_x: u64, amount_y: u64,
    oracle: &PriceOracle,
) {
    // Validate initial ratio against oracle or enforce minimum amounts
    let expected_ratio = oracle::get_price<X, Y>(oracle);
    let actual_ratio = ((amount_x as u128) * PRECISION) / (amount_y as u128);
    let deviation = if (actual_ratio > expected_ratio) {
        actual_ratio - expected_ratio
    } else { expected_ratio - actual_ratio };
    assert!(deviation * 100 / expected_ratio <= MAX_INIT_DEVIATION, ERR_BAD_RATIO);
    pool.reserve_x = amount_x;
    pool.reserve_y = amount_y;
}
```

---

## Signature
- **detect**: For every pool creation or initialization function: (1) verify asset types A and B are distinct, (2) verify token types are canonically ordered (A < B), (3) verify a uniqueness registry prevents duplicate pools for the same pair, (4) verify a minimum liquidity amount is locked or burned on first deposit, (5) verify the initial deposit ratio is validated or constrained.
- **whats_wrong**: Pool creation allows identical asset pairs, unordered token types, duplicate pools for the same pair, zero minimum liquidity lock, or unconstrained initial price ratios.
- **remediation**: Assert asset types are distinct and canonically ordered. Enforce pool uniqueness via a registry. Lock minimum initial liquidity (e.g., burn MINIMUM_LIQUIDITY LP tokens). Validate initial deposit ratio.

---

## CL-POOL-05: LP Token Integrity

**Rule:** `MOVE-POOL-LP-01`
**Severity:** low-high

## Description
LP tokens and coin operations must enforce zero-value guards, correct supply tracking, and proper minting/burning semantics. Missing checks allow empty positions, supply drift, or value extraction.

## Patterns

### Pattern 1: Zero Liquidity Token Minting Accepted
No check that the calculated LP amount is greater than zero before minting. Very small deposits round to zero LP tokens, wasting gas and creating phantom positions.

**Vulnerable:**
```move
public fun add_liquidity<X, Y>(
    pool: &mut Pool<X, Y>,
    coin_x: Coin<X>, coin_y: Coin<Y>,
): Coin<LP<X, Y>> {
    let lp_amount = calc_lp_amount(pool, coin::value(&coin_x), coin::value(&coin_y));
    // BUG: lp_amount could be 0 for very small deposits
    pool.total_lp = pool.total_lp + lp_amount;
    coin::mint<LP<X, Y>>(lp_amount)
}
```

**Fixed:**
```move
public fun add_liquidity<X, Y>(
    pool: &mut Pool<X, Y>,
    coin_x: Coin<X>, coin_y: Coin<Y>,
): Coin<LP<X, Y>> {
    let lp_amount = calc_lp_amount(pool, coin::value(&coin_x), coin::value(&coin_y));
    assert!(lp_amount > 0, ERR_ZERO_LP);
    pool.total_lp = pool.total_lp + lp_amount;
    coin::mint<LP<X, Y>>(lp_amount)
}
```

### Pattern 2: Coin Split/Join Accounting Error
Splitting or joining coins does not preserve total value. A split that creates a new coin without decrementing the source, or a join that fails to add both values.

**Vulnerable:**
```move
public fun split_reward(coin: &mut Coin<REWARD>, amount: u64): Coin<REWARD> {
    // BUG: creates new coin but doesn't decrement source
    coin::mint<REWARD>(amount)
}
```

**Fixed:**
```move
public fun split_reward(coin: &mut Coin<REWARD>, amount: u64): Coin<REWARD> {
    coin::extract(coin, amount) // Atomically decrements source
}
```

### Pattern 3: First Depositor Share Price Manipulation
First depositor can inflate share price by depositing minimal amount then donating tokens directly, causing subsequent depositors to receive zero shares due to rounding. For pool-based systems, lock minimum initial liquidity on first deposit to prevent this attack.

**Vulnerable:**
```move
public fun deposit<T>(account: &signer, vault_addr: address, coin: Coin<T>): Coin<SHARE> acquires Vault {
    let vault = borrow_global_mut<Vault<T>>(vault_addr);
    let shares = if (vault.total_shares == 0) {
        coin::value(&coin) // First deposit: 1:1
    } else {
        (coin::value(&coin) * vault.total_shares) / coin::value(&vault.assets)
    };
    // BUG: No minimum initial deposit or dead shares
    coin::merge(&mut vault.assets, coin);
    vault.total_shares = vault.total_shares + shares;
    coin::mint<SHARE>(shares)
}
```

**Fixed:**
```move
const MINIMUM_LIQUIDITY: u64 = 1000;

public fun deposit<T>(account: &signer, vault_addr: address, coin: Coin<T>): Coin<SHARE> acquires Vault {
    let vault = borrow_global_mut<Vault<T>>(vault_addr);
    let deposit_amount = coin::value(&coin);
    let shares = if (vault.total_shares == 0) {
        // Burn minimum liquidity to prevent inflation attack
        let dead_shares = coin::mint<SHARE>(MINIMUM_LIQUIDITY);
        coin::burn(dead_shares, &vault.burn_cap);
        vault.total_shares = MINIMUM_LIQUIDITY;
        deposit_amount - MINIMUM_LIQUIDITY
    } else {
        (deposit_amount * vault.total_shares) / coin::value(&vault.assets)
    };
    assert!(shares > 0, ERR_ZERO_SHARES);
    coin::merge(&mut vault.assets, coin);
    vault.total_shares = vault.total_shares + shares;
    coin::mint<SHARE>(shares)
}
```

## Remediation
Assert LP/share minting produces non-zero output. Use atomic split/join for coin operations. Lock minimum initial liquidity on first deposit to prevent share inflation attacks.

## Signature
**Slug:** `lp-token-integrity`
**Detect:** For every LP/share minting operation: (1) verify minted amount is checked > 0, (2) verify coin split/join preserves total value, (3) verify first depositor cannot manipulate share price via donation.
**What's Wrong:** LP operations allow zero-value minting, coin split/join breaks accounting, or first depositor can inflate share price.
**Remediation:** Assert non-zero minting. Use framework coin::split/join. Lock minimum initial liquidity.

---

## CL-POOL-06: Reward Accumulator Integrity

**Rule:** `MOVE-POOL-REWD-01`
**Severity:** medium-critical

## Description
Every function that changes staking balances, reward rates, or distribution parameters must first synchronize the global reward accumulator to the current timestamp/epoch, and every new participant must snapshot the current accumulator index. Failure to maintain this ordering allows reward theft, dilution, or permanent loss.

## Patterns

1. **Uninitialized User Reward Index** — A new user joins with reward_index = 0 instead of the current global accumulator value, instantly becoming eligible for all historically accumulated rewards.

```move
// VULNERABLE: new user starts at index 0
public fun stake(pool: &mut Pool, user: &mut User, amount: u64) {
    user.staked = user.staked + amount;
    pool.total_staked = pool.total_staked + amount;
    // user.reward_index left at default 0
}

// FIXED: snapshot current global index
public fun stake(pool: &mut Pool, user: &mut User, amount: u64) {
    update_rewards(pool);
    if (user.staked == 0) {
        user.reward_index = pool.global_reward_index;
    } else {
        settle_user(pool, user);
    };
    user.staked = user.staked + amount;
    pool.total_staked = pool.total_staked + amount;
}
```

2. **Missing Accumulator Sync Before Config Change** — Updating reward rate, duration, or emission parameters without first finalizing accrued rewards under the old config causes retroactive miscalculation.

```move
// VULNERABLE: config change without settling
public fun set_reward_rate(pool: &mut Pool, new_rate: u64) {
    pool.reward_rate = new_rate;
    // rewards between last_update and now calculated at new_rate
}

// FIXED: settle first, then change
public fun set_reward_rate(pool: &mut Pool, new_rate: u64) {
    update_rewards(pool); // finalize at old rate
    pool.reward_rate = new_rate;
}
```

3. **Zero-Supply Reward Loss** — When total staked supply drops to zero, incoming rewards have no recipients. If the accumulator skips the update, those rewards are permanently lost or dilute future stakers unfairly.

```move
// VULNERABLE: rewards lost during zero-supply period
public fun update_rewards(pool: &mut Pool) {
    let elapsed = timestamp::now_seconds() - pool.last_update;
    if (pool.total_staked == 0) {
        pool.last_update = timestamp::now_seconds();
        return // rewards for this period vanish
    };
    pool.acc_per_share = pool.acc_per_share + (elapsed * pool.rate) / pool.total_staked;
    pool.last_update = timestamp::now_seconds();
}

// FIXED: buffer rewards during zero-supply
public fun update_rewards(pool: &mut Pool) {
    let elapsed = timestamp::now_seconds() - pool.last_update;
    let pending = elapsed * pool.rate;
    if (pool.total_staked == 0) {
        pool.buffered_rewards = pool.buffered_rewards + pending;
    } else {
        let total = pending + pool.buffered_rewards;
        pool.acc_per_share = pool.acc_per_share + total / pool.total_staked;
        pool.buffered_rewards = 0;
    };
    pool.last_update = timestamp::now_seconds();
}
```

4. **Unvalidated Asset Type in Reward Claim** — The claim function accepts a user-supplied type parameter to select which reward token to withdraw without verifying it against the protocol's registered reward types, enabling arbitrary token drainage.

```move
// VULNERABLE: user controls which type to withdraw
public fun claim_reward<CoinType>(pool: &mut Pool, user: &mut User) {
    let amount = user.pending_rewards;
    let reward = coin::extract(&mut pool.vault, amount);
    coin::deposit(user.addr, reward);
}

// FIXED: validate CoinType against registered rewards
public fun claim_reward<CoinType>(pool: &mut Pool, user: &mut User) {
    assert!(table::contains(&pool.reward_types, type_info::type_of<CoinType>()), E_INVALID_TYPE);
    let amount = user.pending_rewards;
    let reward = coin::extract(&mut pool.vault, amount);
    coin::deposit(user.addr, reward);
}
```

## Remediation
Always update the global reward accumulator before any operation that changes total staked supply, individual balances, or distribution parameters. Initialize every new user's reward index to the current global value. Buffer rewards during zero-supply periods. Enforce minimum stake durations to prevent flash-deposit extraction.

## Signature
**Slug:** `reward-accumulator-integrity`
**Detect:** For every staking state mutation: (1) verify new users snapshot current accumulator index, (2) verify config changes trigger final accrual at old rate, (3) verify zero-supply periods buffer rewards, (4) verify reward claim asset types are validated against registry.
**What's Wrong:** The reward accumulator allows stale index exploitation, retroactive config changes, zero-supply reward loss, or unvalidated asset type claims.
**Remediation:** Snapshot index on join; settle before config changes; buffer zero-supply rewards; validate claim asset types against registry.

---

## CL-POOL-07: Swap Routing Integrity

**Rule:** `MOVE-POOL-ROUTE-01`
**Severity:** low-medium

## Precondition
The protocol supports multi-hop swaps, routing through multiple pools, or integrates external DEX contracts.

## Root Cause
Multi-hop routing logic has incorrect token chaining, partial validation of intermediate outputs, inconsistent path validation vs execution, or hardcoded dependencies on external resources.

## Impact
Incorrect routing silently drops intermediate swap outputs. Partial validation misses failed intermediate hops. Hardcoded dependencies cause permanent DoS when external pools are removed. Uncontrolled external calls have no fallback.

## Remediation
Chain intermediate outputs correctly (output of hop N = input of hop N+1). Validate all intermediate amounts, not just the final output. Match path validation logic to execution logic. Add circuit breakers for external DEX dependencies.

---

## Pattern 1 -- Incorrect output chaining in multi-hop swap

Each hop uses the original input amount or a fixed reference instead of the previous hop's actual output.

### Vulnerable

```move
public fun multi_hop_swap(
    pools: &mut vector<Pool>,
    amount_in: u64,
    path: vector<TypeInfo>,
): u64 {
    let i = 0;
    let current_amount = amount_in;
    while (i < vector::length(&path) - 1) {
        let pool = vector::borrow_mut(pools, i);
        // BUG: Uses amount_in for all hops instead of current_amount
        let out = do_swap(pool, amount_in);
        current_amount = out;
        i = i + 1;
    };
    current_amount
}
```

### Fixed

```move
public fun multi_hop_swap(
    pools: &mut vector<Pool>,
    amount_in: u64,
    path: vector<TypeInfo>,
): u64 {
    let i = 0;
    let current_amount = amount_in;
    while (i < vector::length(&path) - 1) {
        let pool = vector::borrow_mut(pools, i);
        current_amount = do_swap(pool, current_amount); // chain outputs
        i = i + 1;
    };
    current_amount
}
```

---

## Pattern 2 -- Only final output validated in multi-hop

Intermediate hop results are not checked, so a failed or zero-output intermediate swap is silently passed to the next hop.

### Vulnerable

```move
public fun multi_hop_swap(pools: &mut vector<Pool>, amount_in: u64, min_out: u64): u64 {
    let out_1 = do_swap(vector::borrow_mut(pools, 0), amount_in);
    let out_2 = do_swap(vector::borrow_mut(pools, 1), out_1);
    let out_3 = do_swap(vector::borrow_mut(pools, 2), out_2);
    // BUG: Only checks final output -- out_1 or out_2 could be 0
    assert!(out_3 >= min_out, ERR_SLIPPAGE);
    out_3
}
```

### Fixed

```move
public fun multi_hop_swap(pools: &mut vector<Pool>, amount_in: u64, min_out: u64): u64 {
    let out_1 = do_swap(vector::borrow_mut(pools, 0), amount_in);
    assert!(out_1 > 0, ERR_ZERO_INTERMEDIATE);
    let out_2 = do_swap(vector::borrow_mut(pools, 1), out_1);
    assert!(out_2 > 0, ERR_ZERO_INTERMEDIATE);
    let out_3 = do_swap(vector::borrow_mut(pools, 2), out_2);
    assert!(out_3 >= min_out, ERR_SLIPPAGE);
    out_3
}
```

---

## Pattern 3 -- Divergent path validation and execution logic

The validation checks one token pair ordering but execution uses a different ordering, causing the validated path to differ from the executed path.

### Vulnerable

```move
public fun validate_path(path: &vector<TypeInfo>) {
    // Validates: path[0]->path[1], path[1]->path[2]
    let i = 0;
    while (i < vector::length(path) - 1) {
        assert!(pool_exists(*vector::borrow(path, i), *vector::borrow(path, i + 1)), ERR_NO_POOL);
        i = i + 1;
    };
}

public fun execute_path(path: &vector<TypeInfo>, amount: u64): u64 {
    // BUG: Executes path[0]->path[1], path[0]->path[2] (reuses index 0)
    let out = do_swap_by_type(*vector::borrow(path, 0), *vector::borrow(path, 1), amount);
    let out = do_swap_by_type(*vector::borrow(path, 0), *vector::borrow(path, 2), out); // wrong!
    out
}
```

### Fixed

```move
public fun execute_path(path: &vector<TypeInfo>, amount: u64): u64 {
    let current = amount;
    let i = 0;
    while (i < vector::length(path) - 1) {
        current = do_swap_by_type(*vector::borrow(path, i), *vector::borrow(path, i + 1), current);
        i = i + 1;
    };
    current
}
```

---

## Pattern 4 -- Hardcoded resource dependency on non-existent pool

The swap logic hardcodes a lookup for a specific pool type that may not exist, causing permanent abort.

### Vulnerable

```move
public fun swap_via_base<X>(pool_x: &mut Pool<X, BASE>, amount: u64): u64 {
    // BUG: Assumes Pool<X, BASE> always exists -- aborts if it doesn't
    let metadata = borrow_global<PoolMetadata<X, BASE>>(@dex);
    do_swap(pool_x, amount, metadata.fee)
}
```

### Fixed

```move
public fun swap_via_base<X>(amount: u64): u64 {
    assert!(exists<PoolMetadata<X, BASE>>(@dex), ERR_POOL_NOT_FOUND);
    let metadata = borrow_global<PoolMetadata<X, BASE>>(@dex);
    let pool = borrow_global_mut<Pool<X, BASE>>(@dex);
    do_swap(pool, amount, metadata.fee)
}
```

---

## Pattern 5 -- No circuit breaker for external DEX dependency

External DEX calls have no pause mechanism or fallback, so a compromised or frozen external contract permanently blocks the protocol.

### Vulnerable

```move
public fun swap_external<X, Y>(amount: u64): u64 {
    // BUG: No way to pause if external_dex is compromised
    external_dex::swap<X, Y>(amount)
}
```

### Fixed

```move
public fun swap_external<X, Y>(config: &Config, amount: u64): u64 {
    assert!(!config.paused_dexes.contains(&type_info::type_of<ExternalDex>()), ERR_DEX_PAUSED);
    external_dex::swap<X, Y>(amount)
}

public fun pause_dex(admin: &signer, config: &mut Config, dex_type: TypeInfo) {
    assert!(signer::address_of(admin) == config.admin, ERR_NOT_ADMIN);
    vector::push_back(&mut config.paused_dexes, dex_type);
}
```

---

## Signature
- **detect**: For every multi-hop swap or routing function: (1) verify each hop's output is correctly used as the next hop's input, (2) verify all intermediate swap outputs are validated not just the final result, (3) verify path validation logic matches execution logic for token pairs, (4) verify external DEX dependencies have fallback or pause mechanisms, (5) verify resource lookups do not hardcode assumptions about which pools exist.
- **whats_wrong**: Multi-hop routing reuses the original input instead of chaining outputs, only validates the final amount, has divergent validation and execution paths, hardcodes external pool dependencies, or lacks circuit breakers for external calls.
- **remediation**: Chain intermediate outputs correctly (output of hop N = input of hop N+1). Validate all intermediate amounts, not just the final output. Match path validation logic to execution logic. Add circuit breakers for external DEX dependencies.

---

## CL-POOL-08: Flash Stake Attack Invariant

**Rule:** `MOVE-POOL-STAKE-01`
**Severity:** medium-critical

## Description
Staking protocols must resist single-transaction manipulation of reward distribution. Flash deposit/withdraw attacks, direct transfer reward dilution, balance caching mismatches, accumulator update ordering errors, and stale reward indices after parameter changes all enable attackers to capture rewards without genuine economic commitment.

## Patterns

### Pattern 1: Flash Deposit/Withdraw Reward Capture
Attacker performs a large flash deposit to dilute pending rewards, claims a disproportionate share, then immediately withdraws. On Aptos, multi-step transaction scripts can combine stake + claim + unstake atomically.

**Vulnerable:**
```move
struct UserStake has key {
    amount: u64,
    reward_debt: u128,
    // No timestamp -- no duration enforcement
}

public fun unstake<T>(account: &signer, pool_addr: address): Coin<T> acquires Pool, UserStake {
    let addr = signer::address_of(account);
    let UserStake { amount, reward_debt: _ } = move_from<UserStake>(addr);
    let pool = borrow_global_mut<Pool<T>>(pool_addr);
    pool.total_staked = pool.total_staked - amount;
    coin::extract(&mut pool.staked, amount)
}
```

**Fixed:**
```move
struct UserStake has key {
    amount: u64,
    reward_debt: u128,
    stake_time_secs: u64,
}

public fun unstake<T>(account: &signer, pool_addr: address): Coin<T> acquires Pool, UserStake {
    let addr = signer::address_of(account);
    let UserStake { amount, reward_debt: _, stake_time_secs } = move_from<UserStake>(addr);
    let elapsed = timestamp::now_seconds() - stake_time_secs;
    assert!(elapsed >= MIN_STAKE_DURATION_SECS, E_STAKE_TOO_SHORT);
    let pool = borrow_global_mut<Pool<T>>(pool_addr);
    pool.total_staked = pool.total_staked - amount;
    coin::extract(&mut pool.staked, amount)
}
```

### Pattern 2: Reward Dilution via Direct Transfer
Sending reward tokens directly to a staking pool's balance bypasses the reward accumulator update. The balance increases but `reward_per_share` is never updated, causing rewards to be distributed incorrectly or silently lost.

**Vulnerable:**
```move
public fun update_rewards<T>(pool_addr: address) acquires StakePool {
    let pool = borrow_global_mut<StakePool<T>>(pool_addr);
    let current_balance = coin::value(&pool.balance);
    // BUG: current_balance includes directly deposited tokens
    let new_rewards = (current_balance as u128) - (pool.total_staked as u128);
    if (pool.total_staked > 0) {
        pool.reward_per_share = pool.reward_per_share
            + new_rewards / (pool.total_staked as u128);
    };
}
```

**Fixed:**
```move
public fun add_rewards<T>(pool_addr: address, reward_coin: Coin<T>) acquires StakePool {
    let pool = borrow_global_mut<StakePool<T>>(pool_addr);
    let reward_amount = coin::value(&reward_coin);
    if (pool.total_staked > 0) {
        pool.reward_per_share = pool.reward_per_share
            + ((reward_amount as u128) * PRECISION) / (pool.total_staked as u128);
    };
    pool.distributed_rewards = pool.distributed_rewards + reward_amount;
    coin::merge(&mut pool.reward_balance, reward_coin);
}
```

### Pattern 3: Zero-Value Operation Acceptance
Functions accept zero-amount stakes, withdrawals, or reward claims that consume gas, create empty state entries, or trigger reward distributions without economic commitment.

**Vulnerable:**
```move
public fun request_withdrawal(pool: &mut Pool, user: &mut User, amount: u64) {
    let ticket = WithdrawalTicket { amount, user: user.addr };
    vector::push_back(&mut pool.pending_withdrawals, ticket);
    // zero-amount tickets still processed later
}
```

**Fixed:**
```move
public fun request_withdrawal(pool: &mut Pool, user: &mut User, amount: u64) {
    assert!(amount > 0, E_ZERO_AMOUNT);
    assert!(user.staked >= amount, E_INSUFFICIENT);
    let ticket = WithdrawalTicket { amount, user: user.addr };
    vector::push_back(&mut pool.pending_withdrawals, ticket);
}
```

### Pattern 4: Accumulator Update Ordering
Reward accumulator updated AFTER balance change instead of before. If the accumulator is updated after a deposit, the new deposit immediately earns historical rewards. If updated after withdrawal, the withdrawer's final rewards use the wrong accumulator value.

**Vulnerable:**
```move
public fun stake(pool: &mut Pool, amount: u64) {
    pool.total_staked = pool.total_staked + amount; // Balance change first
    update_reward_accumulator(pool); // BUG: accumulator updated with new total
}
```

**Fixed:**
```move
public fun stake(pool: &mut Pool, amount: u64) {
    update_reward_accumulator(pool); // Always update accumulator FIRST
    pool.total_staked = pool.total_staked + amount;
}
```

### Pattern 5: Stale Reward Index After Parameter Change
Adding new rewards or changing the reward rate without updating `reward_per_share` first causes stale calculations. Admin functions commonly omit the index update that every other state-modifying function includes.

**Vulnerable:**
```move
public fun add_rewards<T>(pool_addr: address, reward_coin: Coin<T>, new_rate: u64) acquires Pool {
    let pool = borrow_global_mut<Pool<T>>(pool_addr);
    // Missing: update_reward_index(pool);
    // Rewards accrued at old rate since last_update_time are lost
    coin::merge(&mut pool.reward_balance, reward_coin);
    pool.reward_rate = new_rate; // Rate change applied retroactively
}
```

**Fixed:**
```move
public fun add_rewards<T>(pool_addr: address, reward_coin: Coin<T>, new_rate: u64) acquires Pool {
    let pool = borrow_global_mut<Pool<T>>(pool_addr);
    update_reward_index(pool); // Settle accrued rewards at old rate using timestamp::now_seconds()
    coin::merge(&mut pool.reward_balance, reward_coin);
    pool.reward_rate = new_rate; // Now safe to change rate
}
```

## Remediation
Enforce minimum stake duration via on-chain timestamp to prevent flash attacks. Separate staked and reward balances to prevent direct transfer manipulation. Reject zero-value operations. Always update the reward accumulator before any balance change (update-before-mutate pattern). Ensure every admin function that modifies reward parameters calls the accumulator update first.

## Signature
**Slug:** `flash-stake-attack-invariant`
**Detect:** For every staking state mutation: (1) verify minimum stake duration prevents flash deposit/withdraw, (2) verify reward accounting uses internal tracking not raw balance, (3) verify zero-value operations are rejected, (4) verify accumulator is updated before balance changes, (5) verify admin reward parameter changes trigger accumulator update first.
**What's Wrong:** Staking protocol allows single-transaction reward capture via flash stakes, reward dilution through direct transfers, zero-value operations, incorrect accumulator ordering, or retroactive parameter changes without settlement.
**Remediation:** Enforce minimum stake duration, separate staked/reward balances, reject zero-value operations, update accumulator before balance changes, and settle rewards before parameter modifications.

---
