# CAT-LEND: Lending

**Context:** `ctx:lending`
**Detectors:** 3

## CL-LEND-01: Liquidation Logic Integrity Invariant

**Rule:** `MOVE-LEND-LIQ-01`
**Severity:** low-critical

## Description
For every liquidation execution path, the protocol must validate position eligibility, compute seizure amounts correctly, handle edge cases (dust, partial, sequential), and prevent atomic manipulation. Liquidation is the protocol's solvency backstop -- flaws here directly cause bad debt or unfair seizure.

## Patterns

1. **Missing Liquidation Eligibility Check** — The liquidation function does not verify that the target position is actually undercollateralized (health factor < 1) before executing seizure, allowing liquidation of healthy positions.

```move
// VULNERABLE: no health check before liquidation
public fun liquidate(obligation: &mut Obligation, pool: &mut Pool, repay_amount: u64) {
    let seize = repay_amount * pool.liquidation_bonus / PRECISION;
    obligation.collateral = obligation.collateral - seize;
    obligation.debt = obligation.debt - repay_amount;
}

// FIXED: verify position is underwater
public fun liquidate(obligation: &mut Obligation, pool: &mut Pool, repay_amount: u64) {
    let hf = health_factor(obligation, pool);
    assert!(hf < HEALTH_FACTOR_THRESHOLD, E_POSITION_HEALTHY);
    let seize = repay_amount * pool.liquidation_bonus / PRECISION;
    obligation.collateral = obligation.collateral - seize;
    obligation.debt = obligation.debt - repay_amount;
}
```

2. **Incorrect Liquidation Cap / Bonus Math** — The maximum seizable collateral or the liquidation bonus is miscalculated due to wrong divisors, missing close factor enforcement, or incorrect scaling, enabling over-seizure or under-incentivized liquidations.

```move
// VULNERABLE: bonus divisor too small, 10x intended bonus
public fun calculate_seize(repay: u64, bonus_bps: u64): u64 {
    repay * (100 + bonus_bps) / 100 // bonus_bps=500 means 6x instead of 1.05x
}

// FIXED: correct basis point scaling
public fun calculate_seize(repay: u64, bonus_bps: u64): u64 {
    repay * (10000 + bonus_bps) / 10000 // bonus_bps=500 means 1.05x
}
```

3. **Dust Position Deadlock** — After partial liquidation, the remaining position falls below the minimum debt threshold, making it impossible to liquidate further (would violate minimum) but also impossible to leave (position is unhealthy), creating permanent bad debt.

```move
// VULNERABLE: no dust handling after partial liquidation
public fun liquidate_partial(obligation: &mut Obligation, repay: u64) {
    assert!(repay <= obligation.debt * CLOSE_FACTOR / PRECISION, E_EXCEEDS_CLOSE_FACTOR);
    obligation.debt = obligation.debt - repay;
    // remaining debt may be below MIN_DEBT, unliquidatable
}

// FIXED: force full liquidation if remainder would be dust
public fun liquidate_partial(obligation: &mut Obligation, repay: u64) {
    let remaining = obligation.debt - repay;
    if (remaining > 0 && remaining < MIN_DEBT) {
        repay = obligation.debt; // force full close
    };
    obligation.debt = obligation.debt - repay;
}
```

4. **Missing Solvency Check on State Transition** — Withdrawal, borrowing, or collateral toggle operations do not verify the position remains solvent (health factor >= 1) after the state change, allowing users to extract value while undercollateralized.

```move
// VULNERABLE: no post-withdrawal solvency check
public fun withdraw_collateral(account: &signer, amount: u64) acquires Obligation, Pool {
    let addr = signer::address_of(account);
    let obligation = borrow_global_mut<Obligation>(addr);
    let pool = borrow_global<Pool>(@protocol);
    obligation.collateral = obligation.collateral - amount;
    // no solvency check — user may now be undercollateralized
    let pool_signer = account::create_signer_with_capability(&pool.signer_cap);
    coin::transfer<CollateralCoin>(&pool_signer, addr, amount);
}

// FIXED: check health after withdrawal
public fun withdraw_collateral(account: &signer, amount: u64) acquires Obligation, Pool {
    let addr = signer::address_of(account);
    let obligation = borrow_global_mut<Obligation>(addr);
    let pool = borrow_global<Pool>(@protocol);
    obligation.collateral = obligation.collateral - amount;
    let hf = health_factor(obligation, pool);
    assert!(hf >= MIN_HEALTH_FACTOR, E_WOULD_BE_UNDERCOLLATERALIZED);
    let pool_signer = account::create_signer_with_capability(&pool.signer_cap);
    coin::transfer<CollateralCoin>(&pool_signer, addr, amount);
}
```

## Remediation
Always verify health factor before executing liquidation. Use correct basis-point scaling for bonus calculations. Handle dust positions by forcing full liquidation when remainder would be below minimum. Verify post-operation solvency on all collateral reductions.

## Signature
**Slug:** `liquidation-logic-integrity-invariant`
**Detect:** For every liquidation path: (1) verify health factor / eligibility is checked before seizure, (2) verify liquidation cap and bonus math uses correct scaling, (3) verify dust positions are handled to avoid deadlocks, (4) verify post-operation solvency on all collateral reductions.
**What's Wrong:** Liquidation logic fails to validate eligibility, miscalculates seizure amounts, creates unliquidatable dust positions, or allows collateral withdrawal without solvency check.
**Remediation:** Enforce pre-liquidation health checks, correct bonus arithmetic, dust-aware partial liquidation, and post-operation solvency verification.

---

## CL-LEND-02: Advanced Liquidation Mechanics Invariant

**Rule:** `MOVE-LEND-LIQ-02`
**Severity:** medium-critical

## Description
Beyond basic liquidation eligibility and seizure math (covered by LIQ-01), lending protocols must handle economic incentive alignment, self-liquidation abuse, dust accumulation blocking liquidation paths, bad debt socialization, and interest behavior during protocol pauses. Failures in these areas lead to protocol insolvency, unfair forced liquidations, or permanently stuck positions.

## Patterns

### Pattern 1: Missing Liquidation Incentive
Liquidation provides no bonus to the liquidator. Without economic incentive, trustless liquidators will not spend gas, leading to bad debt accumulation as underwater positions go unseized.

**Vulnerable:**
```move
public fun liquidate(
    liquidator: &signer, borrower: address, repay_amount: u64
) acquires Position {
    let position = borrow_global_mut<Position>(borrower);
    // Liquidator receives exactly the debt value -- no profit motive
    coin::transfer<DebtCoin>(liquidator, @protocol, repay_amount);
    let collateral = withdraw_collateral(position, repay_amount);
    coin::deposit(signer::address_of(liquidator), collateral);
}
```

**Fixed:**
```move
public fun liquidate(
    liquidator: &signer, borrower: address, repay_amount: u64
) acquires Position {
    let position = borrow_global_mut<Position>(borrower);
    let bonus = (repay_amount as u128) * (LIQUIDATION_BONUS_BPS as u128) / 10000u128;
    let seize_amount = repay_amount + (bonus as u64);
    coin::transfer<DebtCoin>(liquidator, @protocol, repay_amount);
    let collateral = withdraw_collateral(position, seize_amount);
    coin::deposit(signer::address_of(liquidator), collateral);
}
```

### Pattern 2: Self-Liquidation Profitability
A user liquidates their own position and profits from the liquidation bonus exceeding the net cost. When the bonus percentage on seized collateral exceeds the user's effective loss from debt repayment, self-liquidation becomes a profitable arbitrage.

**Vulnerable:**
```move
public fun liquidate(
    liquidator: &signer, borrower: address, repay_amount: u64
) acquires LendingPool, Position {
    let pool = borrow_global_mut<LendingPool>(@protocol);
    let borrower_pos = borrow_global_mut<Position>(borrower);
    // No check if liquidator == position owner
    let hf = health_factor(borrower_pos);
    assert!(hf < LIQUIDATION_THRESHOLD, E_HEALTHY);
    execute_seizure(pool, borrower_pos, liquidator, repay_amount)
}
```

**Fixed:**
```move
public fun liquidate(
    liquidator: &signer, borrower: address, repay_amount: u64
) acquires LendingPool, Position {
    let liquidator_addr = signer::address_of(liquidator);
    assert!(liquidator_addr != borrower, E_SELF_LIQUIDATION);
    let pool = borrow_global_mut<LendingPool>(@protocol);
    let borrower_pos = borrow_global_mut<Position>(borrower);
    let hf = health_factor(borrower_pos);
    assert!(hf < LIQUIDATION_THRESHOLD, E_HEALTHY);
    execute_seizure(pool, borrower_pos, liquidator, repay_amount)
}
```

### Pattern 3: Dust Position Accumulation Blocking Liquidation
Tiny positions cost more gas to liquidate than the bonus provides. Without minimum position sizes, dust positions accumulate as permanent bad debt that cannot be economically cleared.

**Vulnerable:**
```move
public fun borrow<T>(account: &mut Account, amount: u64) {
    // No minimum -- amount = 1 is allowed, creating unliquidatable dust
    add_debt(account, amount);
}
```

**Fixed:**
```move
const MIN_BORROW_AMOUNT: u64 = 1000;

public fun borrow<T>(account: &mut Account, amount: u64) {
    assert!(amount >= MIN_BORROW_AMOUNT, E_BELOW_MINIMUM);
    add_debt(account, amount);
}

public fun repay<T>(pool: &mut Pool, borrower: address, amount: u64) {
    let debt = get_debt(pool, borrower);
    if (debt <= MIN_BORROW_AMOUNT || amount >= debt) {
        reduce_debt(pool, borrower, debt); // force full closure
    } else {
        assert!(debt - amount >= MIN_BORROW_AMOUNT, E_DUST_POSITION);
        reduce_debt(pool, borrower, amount);
    };
}
```

### Pattern 4: Bad Debt Not Socialized
When collateral is fully seized but residual debt remains, no mechanism absorbs the loss. The bad debt sits in the protocol indefinitely, creating an accounting hole that silently makes the protocol insolvent.

**Vulnerable:**
```move
public fun liquidate(
    liquidator: &signer, borrower: address, repay_amount: u64
) acquires Position {
    let position = borrow_global_mut<Position>(borrower);
    coin::transfer<USDC>(liquidator, @protocol, repay_amount);
    let remaining = position.debt - repay_amount;
    if (remaining > 0 && position.collateral == 0) {
        // Bad debt ignored -- protocol becomes insolvent
    };
}
```

**Fixed:**
```move
public fun liquidate(
    liquidator: &signer, borrower: address, repay_amount: u64
) acquires Position, InsuranceFund {
    let position = borrow_global_mut<Position>(borrower);
    coin::transfer<USDC>(liquidator, @protocol, repay_amount);
    let remaining = position.debt - repay_amount;
    if (remaining > 0 && position.collateral == 0) {
        // Socialize bad debt through insurance fund
        let insurance = borrow_global_mut<InsuranceFund>(@protocol);
        insurance.balance = insurance.balance - remaining;
        position.debt = 0;
        event::emit_event(&mut insurance.bad_debt_events, BadDebtSocialized { amount: remaining });
    };
}
```

### Pattern 5: Interest Accrual During Pause
Protocol pauses operations but interest keeps accruing. Users cannot repay during the pause. On unpause, previously healthy positions are instantly liquidatable due to accumulated interest they had no opportunity to address.

**Vulnerable:**
```move
public fun repay(account: &signer, amount: u64) acquires Position, State {
    let state = borrow_global<State>(@protocol);
    assert!(!state.paused, E_PAUSED); // Repayment blocked
    // But interest calculation ignores pause -- keeps accruing
}

public fun calculate_debt(borrower: address): u64 acquires Position {
    let pos = borrow_global<Position>(borrower);
    let elapsed = timestamp::now_seconds() - pos.last_update;
    pos.principal + calculate_interest(pos.principal, elapsed)
}
```

**Fixed:**
```move
public fun calculate_debt(borrower: address): u64 acquires Position, State {
    let pos = borrow_global<Position>(borrower);
    let state = borrow_global<State>(@protocol);
    let elapsed = if (state.paused) {
        state.pause_timestamp - pos.last_update
    } else {
        timestamp::now_seconds() - pos.last_update
    };
    pos.principal + calculate_interest(pos.principal, elapsed)
}
```

## Remediation
Ensure liquidation bonus exists and exceeds gas costs (5-15% typical). Block self-liquidation or ensure the bonus is structured so self-liquidation is unprofitable. Enforce minimum position sizes at borrow time and force full closure when partial repay would leave dust. Implement an insurance fund or socialized loss mechanism for bad debt. Freeze interest accrual during protocol pause or provide a grace period after unpause before liquidation is enabled.

---

## CL-LEND-03: Lending Pause & Recovery Invariant

**Rule:** `MOVE-LEND-PAUSE-01`
**Severity:** medium-critical

## Description
Lending protocol pause mechanisms must maintain fairness between borrowers and liquidators. Asymmetric pauses, token denylists blocking repayment, missing grace periods, forced debt creation on unwilling users, and state manipulation via refinancing all create exploitable windows where users suffer losses through no fault of their own.

## Patterns

### Pattern 1: Asymmetric Pause (Repay Paused but Liquidation Active)
Protocol pauses repayments but leaves liquidation active, creating an unfair forced-liquidation window where borrowers cannot defend their positions.

**Vulnerable:**
```move
public fun repay<T>(account: &signer, amount: u64) acquires LendingPool {
    let pool = borrow_global_mut<LendingPool>(@protocol);
    assert!(!pool.paused, E_PAUSED); // Repay blocked during pause
    let addr = signer::address_of(account);
    coin::transfer<T>(account, @protocol, amount);
    reduce_debt(pool, addr, amount);
}

public fun liquidate<T>(account: &signer, borrower: address, amount: u64) acquires LendingPool {
    let pool = borrow_global_mut<LendingPool>(@protocol);
    // BUG: no pause check -- liquidation proceeds while repay is blocked
    assert!(calculate_health_factor(pool, borrower) < LIQUIDATION_THRESHOLD, E_HEALTHY);
    coin::transfer<T>(account, @protocol, amount);
    execute_liquidation(pool, borrower, account, amount);
}
```

**Fixed:**
```move
public fun liquidate<T>(account: &signer, borrower: address, amount: u64) acquires LendingPool {
    let pool = borrow_global_mut<LendingPool>(@protocol);
    assert!(!pool.paused, E_PAUSED); // Symmetric with repay
    assert!(calculate_health_factor(pool, borrower) < LIQUIDATION_THRESHOLD, E_HEALTHY);
    coin::transfer<T>(account, @protocol, amount);
    execute_liquidation(pool, borrower, account, amount);
}
```

### Pattern 2: Token Denylist Blocking Repayment
Aptos FungibleAsset freeze capability blocks transfers from denylisted addresses, preventing repayment and forcing liquidation through no fault of the borrower.

**Vulnerable:**
```move
public fun repay<T>(account: &signer, amount: u64) acquires LendingPool {
    let pool = borrow_global_mut<LendingPool>(@protocol);
    // Only direct repayment -- denylisted borrower tx reverts
    let addr = signer::address_of(account);
    coin::transfer<T>(account, @protocol, amount);
    reduce_debt(pool, addr, amount);
}
```

**Fixed:**
```move
public fun repay<T>(account: &signer, amount: u64) acquires LendingPool {
    let pool = borrow_global_mut<LendingPool>(@protocol);
    let addr = signer::address_of(account);
    coin::transfer<T>(account, @protocol, amount);
    process_repayment(pool, addr, amount);
}

public fun repay_on_behalf<T>(account: &signer, borrower: address, amount: u64) acquires LendingPool {
    let pool = borrow_global_mut<LendingPool>(@protocol);
    coin::transfer<T>(account, @protocol, amount);
    process_repayment(pool, borrower, amount); // Payer != borrower
}

fun process_repayment(pool: &mut LendingPool, borrower: address, amount: u64) {
    reduce_debt(pool, borrower, amount);
}
```

### Pattern 3: No Grace Period Before Liquidation
Positions become liquidatable and are immediately seized with no time buffer for users to add collateral or repay. Combined with interest accrual, this creates flash-liquidation traps.

**Vulnerable:**
```move
public fun liquidate<T>(account: &signer, borrower: address, amount: u64) acquires LendingPool {
    let pool = borrow_global_mut<LendingPool>(@protocol);
    accrue_interest(pool);
    assert!(calculate_health_factor(pool, borrower) < LIQUIDATION_THRESHOLD, E_HEALTHY);
    coin::transfer<T>(account, @protocol, amount);
    execute_liquidation(pool, borrower, account, amount); // Instant liquidation
}
```

**Fixed:**
```move
public fun liquidate<T>(account: &signer, borrower: address, amount: u64) acquires LendingPool {
    let pool = borrow_global_mut<LendingPool>(@protocol);
    accrue_interest(pool);
    assert!(calculate_health_factor(pool, borrower) < LIQUIDATION_THRESHOLD, E_HEALTHY);
    let now = timestamp::now_seconds();
    let pos = borrow_position_mut(pool, borrower);
    if (pos.unhealthy_since == 0) {
        pos.unhealthy_since = now;
        abort E_GRACE_PERIOD_ACTIVE
    };
    assert!(now - pos.unhealthy_since >= GRACE_PERIOD_SECS, E_GRACE_PERIOD_ACTIVE);
    coin::transfer<T>(account, @protocol, amount);
    execute_liquidation(pool, borrower, account, amount);
}
```

### Pattern 4: Forced Debt Creation
Attacker forces debt onto unwilling users. On Aptos, a forwarded signer reference allows `move_to` at an arbitrary address, creating debt resources under the victim's account.

**Vulnerable:**
```move
// Attacker forwards victim's signer to create debt under their address
struct DebtObligation has key { amount: u64 }

public fun create_debt_for(victim: &signer, amount: u64) {
    // If attacker obtains victim's signer ref, debt is forced
    move_to(victim, DebtObligation { amount: 1_000_000 });
}
```

**Fixed:**
```move
struct DebtObligation has key { borrower: address, amount: u64 }

public fun borrow(account: &signer, amount: u64) acquires LendingPool {
    let borrower = signer::address_of(account);
    let pool = borrow_global_mut<LendingPool>(@protocol);
    // Debt always bound to caller's own address -- no signer forwarding
    assert!(!exists<DebtObligation>(borrower), E_ALREADY_HAS_DEBT);
    move_to(account, DebtObligation { borrower, amount });
    coin::transfer<AptosCoin>(pool, borrower, amount);
}
```

### Pattern 5: State Manipulation via Refinancing
Borrow + refinance in the same transaction lets the attacker reset their interest index, skipping accumulated interest owed. Without a cooldown or proper interest settlement, the refinance function becomes an interest-evasion tool.

**Vulnerable:**
```move
public fun refinance(account: &signer) acquires LendingPool, Position {
    let pool = borrow_global_mut<LendingPool>(@protocol);
    accrue_interest(pool);
    let addr = signer::address_of(account);
    let pos = borrow_global_mut<Position>(addr);
    // Resets index without settling accrued interest -- skips owed amount
    pos.interest_index = pool.global_interest_index;
}
```

**Fixed:**
```move
public fun refinance(account: &signer) acquires LendingPool, Position {
    let pool = borrow_global_mut<LendingPool>(@protocol);
    accrue_interest(pool);
    let addr = signer::address_of(account);
    let pos = borrow_global_mut<Position>(addr);
    let now = timestamp::now_seconds();
    assert!(now - pos.last_action_ts >= MIN_REFINANCE_COOLDOWN, E_COOLDOWN);
    // Settle accrued interest before resetting index
    pos.borrowed = pos.borrowed +
        calc_accrued(pos.borrowed, pos.interest_index, pool.global_interest_index);
    pos.interest_index = pool.global_interest_index;
    pos.last_action_ts = now;
}
```

## Remediation
Enforce symmetric pause across repay and liquidation. Provide third-party repayment paths for denylisted borrowers. Implement grace periods between position becoming unhealthy and liquidation eligibility. Use `entry` functions requiring the borrower's own `&signer` for debt creation; never forward signer references to untrusted code. Enforce cooldowns between borrow and refinance with proper interest settlement before index reset.

---
