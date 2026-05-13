# CAT-LEND — Lending

## CL-LEND-01: Liquidation Logic Integrity

**Rule:** `MOVE-LEND-LIQ-01`
**Severity:** Low-Critical

### Description
For every liquidation execution path, the protocol must validate position eligibility, compute seizure amounts correctly, handle edge cases (dust, partial, sequential), and prevent atomic manipulation. Liquidation is the protocol's solvency backstop -- flaws here directly cause bad debt or unfair seizure.

### Patterns

#### Pattern 1: Missing Liquidation Eligibility Check
The liquidation function does not verify that the target position is actually undercollateralized (health factor < 1) before executing seizure, allowing liquidation of healthy positions.

**Vulnerable:**
```move
// VULNERABLE: no health check before liquidation
public fun liquidate(obligation: &mut Obligation, pool: &mut Pool, repay_amount: u64) {
    let seize = repay_amount * pool.liquidation_bonus / PRECISION;
    obligation.collateral = obligation.collateral - seize;
    obligation.debt = obligation.debt - repay_amount;
}
```

**Fixed:**
```move
// FIXED: verify position is underwater
public fun liquidate(obligation: &mut Obligation, pool: &mut Pool, repay_amount: u64) {
    let hf = health_factor(obligation, pool);
    assert!(hf < HEALTH_FACTOR_THRESHOLD, E_POSITION_HEALTHY);
    let seize = repay_amount * pool.liquidation_bonus / PRECISION;
    obligation.collateral = obligation.collateral - seize;
    obligation.debt = obligation.debt - repay_amount;
}
```

#### Pattern 2: Incorrect Liquidation Cap / Bonus Math
The maximum seizable collateral or the liquidation bonus is miscalculated due to wrong divisors, missing close factor enforcement, or incorrect scaling, enabling over-seizure or under-incentivized liquidations.

**Vulnerable:**
```move
// VULNERABLE: bonus divisor too small, 10x intended bonus
public fun calculate_seize(repay: u64, bonus_bps: u64): u64 {
    repay * (100 + bonus_bps) / 100 // bonus_bps=500 means 6x instead of 1.05x
}
```

**Fixed:**
```move
// FIXED: correct basis point scaling
public fun calculate_seize(repay: u64, bonus_bps: u64): u64 {
    repay * (10000 + bonus_bps) / 10000 // bonus_bps=500 means 1.05x
}
```

#### Pattern 3: Dust Position Deadlock
After partial liquidation, the remaining position falls below the minimum debt threshold, making it impossible to liquidate further (would violate minimum) but also impossible to leave (position is unhealthy), creating permanent bad debt.

**Vulnerable:**
```move
// VULNERABLE: no dust handling after partial liquidation
public fun liquidate_partial(obligation: &mut Obligation, repay: u64) {
    assert!(repay <= obligation.debt * CLOSE_FACTOR / PRECISION, E_EXCEEDS_CLOSE_FACTOR);
    obligation.debt = obligation.debt - repay;
    // remaining debt may be below MIN_DEBT, unliquidatable
}
```

**Fixed:**
```move
// FIXED: force full liquidation if remainder would be dust
public fun liquidate_partial(obligation: &mut Obligation, repay: u64) {
    let remaining = obligation.debt - repay;
    if (remaining > 0 && remaining < MIN_DEBT) {
        repay = obligation.debt; // force full close
    };
    obligation.debt = obligation.debt - repay;
}
```

#### Pattern 4: Missing Solvency Check on State Transition
Withdrawal, borrowing, or collateral toggle operations do not verify the position remains solvent (health factor >= 1) after the state change, allowing users to extract value while undercollateralized.

**Vulnerable:**
```move
// VULNERABLE: no post-withdrawal solvency check
public fun withdraw_collateral(obligation: &mut Obligation, amount: u64, ctx: &mut TxContext) {
    obligation.collateral = obligation.collateral - amount;
    // user may now be undercollateralized
    transfer_to_user(amount, ctx);
}
```

**Fixed:**
```move
// FIXED: check health after withdrawal
public fun withdraw_collateral(obligation: &mut Obligation, pool: &Pool, amount: u64, ctx: &mut TxContext) {
    obligation.collateral = obligation.collateral - amount;
    let hf = health_factor(obligation, pool);
    assert!(hf >= MIN_HEALTH_FACTOR, E_WOULD_BE_UNDERCOLLATERALIZED);
    transfer_to_user(amount, ctx);
}
```

### Remediation
Always verify health factor before executing liquidation. Use correct basis-point scaling for bonus calculations. Handle dust positions by forcing full liquidation when remainder would be below minimum. Verify post-operation solvency on all collateral reductions.

### Signature
**Slug:** `liquidation-logic-integrity-invariant`
**Detect:** For every liquidation path: (1) verify health factor / eligibility is checked before seizure, (2) verify liquidation cap and bonus math uses correct scaling, (3) verify dust positions are handled to avoid deadlocks, (4) verify post-operation solvency on all collateral reductions.
**What's Wrong:** Liquidation logic fails to validate eligibility, miscalculates seizure amounts, creates unliquidatable dust positions, or allows collateral withdrawal without solvency check.
**Remediation:** Enforce pre-liquidation health checks, correct bonus arithmetic, dust-aware partial liquidation, and post-operation solvency verification.

---

## CL-LEND-02: Advanced Liquidation Mechanics

**Rule:** `MOVE-LEND-LIQ-02`
**Severity:** Medium-Critical

### Description
Beyond basic liquidation eligibility and seizure math (covered by LIQ-01), lending protocols must handle economic incentive alignment, self-liquidation abuse, dust accumulation blocking liquidation paths, bad debt socialization, and interest behavior during protocol pauses. Failures in these areas lead to protocol insolvency, unfair forced liquidations, or permanently stuck positions.

### Patterns

#### Pattern 1: Missing Liquidation Incentive
Liquidation provides no bonus to the liquidator. Without economic incentive, trustless liquidators will not spend gas, leading to bad debt accumulation as underwater positions go unseized.

**Vulnerable:**
```move
public fun liquidate(position: &mut Position, repayment: Coin<Debt>): Coin<Collateral> {
    let repay_value = coin::value(&repayment);
    // Liquidator receives exactly the debt value -- no profit motive
    withdraw_collateral(position, repay_value)
}
```

**Fixed:**
```move
public fun liquidate(position: &mut Position, repayment: Coin<Debt>): Coin<Collateral> {
    let repay_value = coin::value(&repayment);
    let bonus = (repay_value as u128) * (LIQUIDATION_BONUS_BPS as u128) / 10000u128;
    let seize_amount = repay_value + (bonus as u64);
    withdraw_collateral(position, seize_amount)
}
```

#### Pattern 2: Self-Liquidation Profitability
A user liquidates their own position and profits from the liquidation bonus exceeding the net cost. When the bonus percentage on seized collateral exceeds the user's effective loss from debt repayment, self-liquidation becomes a profitable arbitrage.

**Vulnerable:**
```move
public fun liquidate(
    pool: &mut LendingPool,
    borrower_pos: &mut Position,
    repayment: Coin<USDC>,
    ctx: &mut TxContext
): Coin<Collateral> {
    // No check if liquidator == position owner
    let hf = health_factor(borrower_pos);
    assert!(hf < LIQUIDATION_THRESHOLD, E_HEALTHY);
    execute_seizure(pool, borrower_pos, repayment, ctx)
}
```

**Fixed:**
```move
public fun liquidate(
    pool: &mut LendingPool,
    borrower_pos: &mut Position,
    repayment: Coin<USDC>,
    ctx: &mut TxContext
): Coin<Collateral> {
    let liquidator = tx_context::sender(ctx);
    assert!(liquidator != borrower_pos.owner, E_SELF_LIQUIDATION);
    let hf = health_factor(borrower_pos);
    assert!(hf < LIQUIDATION_THRESHOLD, E_HEALTHY);
    execute_seizure(pool, borrower_pos, repayment, ctx)
}
```

#### Pattern 3: Dust Position Accumulation Blocking Liquidation
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

#### Pattern 4: Bad Debt Not Socialized
When collateral is fully seized but residual debt remains, no mechanism absorbs the loss. The bad debt sits in the protocol indefinitely, creating an accounting hole that silently makes the protocol insolvent.

**Vulnerable:**
```move
public fun liquidate(position: &mut Position, repayment: Coin<USDC>) {
    let remaining = position.debt - coin::value(&repayment);
    if (remaining > 0 && position.collateral == 0) {
        // Bad debt ignored -- protocol becomes insolvent
    };
}
```

**Fixed:**
```move
public fun liquidate(
    position: &mut Position,
    insurance: &mut InsuranceFund,
    repayment: Coin<USDC>
) {
    let remaining = position.debt - coin::value(&repayment);
    if (remaining > 0 && position.collateral == 0) {
        // Socialize bad debt through insurance fund
        balance::split(&mut insurance.balance, remaining);
        position.debt = 0;
        event::emit(BadDebtSocialized { amount: remaining });
    };
}
```

#### Pattern 5: Interest Accrual During Pause
Protocol pauses operations but interest keeps accruing. Users cannot repay during the pause. On unpause, previously healthy positions are instantly liquidatable due to accumulated interest they had no opportunity to address.

**Vulnerable:**
```move
public fun repay(pos: &mut Position, payment: Coin<USDC>, state: &State) {
    assert!(!state.paused, E_PAUSED); // Repayment blocked
    // But interest calculation ignores pause -- keeps accruing
}

public fun calculate_debt(pos: &Position, clock: &Clock): u64 {
    let elapsed = clock::timestamp_ms(clock) - pos.last_update;
    pos.principal + calculate_interest(pos.principal, elapsed)
}
```

**Fixed:**
```move
public fun calculate_debt(pos: &Position, state: &State, clock: &Clock): u64 {
    let elapsed = if (state.paused) {
        state.pause_timestamp - pos.last_update
    } else {
        clock::timestamp_ms(clock) - pos.last_update
    };
    pos.principal + calculate_interest(pos.principal, elapsed)
}
```

### Remediation
Ensure liquidation bonus exists and exceeds gas costs (5-15% typical). Block self-liquidation or ensure the bonus is structured so self-liquidation is unprofitable. Enforce minimum position sizes at borrow time and force full closure when partial repay would leave dust. Implement an insurance fund or socialized loss mechanism for bad debt. Freeze interest accrual during protocol pause or provide a grace period after unpause before liquidation is enabled.

### Signature
**Slug:** `advanced-liquidation-mechanics-invariant`
**Detect:** For every liquidation path: (1) verify liquidation bonus exists and exceeds gas costs, (2) verify self-liquidation is blocked or unprofitable, (3) verify minimum position sizes prevent dust accumulation, (4) verify bad debt is socialized through insurance or shared loss, (5) verify interest freezes during protocol pause or grace period exists post-unpause.
**What's Wrong:** Liquidation economics fail to incentivize third-party liquidators, allow profitable self-liquidation, permit dust positions that block liquidation, leave bad debt unsocialized creating insolvency, or accrue interest during pause causing unfair forced liquidations.
**Remediation:** Implement meaningful liquidation bonus, block self-liquidation, enforce minimum position sizes, socialize bad debt via insurance fund, and freeze interest during pause with grace period on unpause.

---

## CL-LEND-03: Pause & Recovery

**Rule:** `MOVE-LEND-PAUSE-01`
**Severity:** Medium-Critical

### Description
Lending protocol pause mechanisms must maintain fairness between borrowers and liquidators. Asymmetric pauses, token denylists blocking repayment, missing grace periods, forced debt creation on unwilling users, and state manipulation via refinancing all create exploitable windows where users suffer losses through no fault of their own.

### Patterns

#### Pattern 1: Asymmetric Pause (Repay Paused but Liquidation Active)
Protocol pauses repayments but leaves liquidation active, creating an unfair forced-liquidation window where borrowers cannot defend their positions.

**Vulnerable:**
```move
public fun repay<T>(pool: &mut LendingPool, payment: Coin<T>, ctx: &mut TxContext) {
    assert!(!pool.paused, E_PAUSED); // Repay blocked during pause
    reduce_debt(pool, tx_context::sender(ctx), coin::value(&payment));
    coin::put(&mut pool.reserves, payment);
}

public fun liquidate<T>(pool: &mut LendingPool, borrower: address,
    repay_coin: Coin<T>, ctx: &mut TxContext) {
    // BUG: no pause check -- liquidation proceeds while repay is blocked
    assert!(calculate_health_factor(pool, borrower) < LIQUIDATION_THRESHOLD, E_HEALTHY);
    execute_liquidation(pool, borrower, repay_coin, ctx);
}
```

**Fixed:**
```move
public fun liquidate<T>(pool: &mut LendingPool, borrower: address,
    repay_coin: Coin<T>, ctx: &mut TxContext) {
    assert!(!pool.paused, E_PAUSED); // Symmetric with repay
    assert!(calculate_health_factor(pool, borrower) < LIQUIDATION_THRESHOLD, E_HEALTHY);
    execute_liquidation(pool, borrower, repay_coin, ctx);
}
```

#### Pattern 2: Token Denylist Blocking Repayment
Sui DenyCapV2 blocks transfers from denylisted addresses, preventing repayment and forcing liquidation through no fault of the borrower.

**Vulnerable:**
```move
public fun repay<T>(pool: &mut LendingPool, payment: Coin<T>, ctx: &mut TxContext) {
    // Only direct repayment -- denylisted borrower tx reverts
    reduce_debt(pool, tx_context::sender(ctx), coin::value(&payment));
    coin::put(&mut pool.reserves, payment);
}
```

**Fixed:**
```move
public fun repay<T>(pool: &mut LendingPool, payment: Coin<T>, ctx: &mut TxContext) {
    process_repayment(pool, tx_context::sender(ctx), payment);
}

public fun repay_on_behalf<T>(pool: &mut LendingPool, borrower: address,
    payment: Coin<T>, _ctx: &mut TxContext) {
    process_repayment(pool, borrower, payment); // Payer != borrower
}

fun process_repayment<T>(pool: &mut LendingPool, borrower: address, payment: Coin<T>) {
    reduce_debt(pool, borrower, coin::value(&payment));
    coin::put(&mut pool.reserves, payment);
}
```

#### Pattern 3: No Grace Period Before Liquidation
Positions become liquidatable and are immediately seized with no time buffer for users to add collateral or repay. Combined with interest accrual, this creates flash-liquidation traps.

**Vulnerable:**
```move
public fun liquidate<T>(pool: &mut LendingPool, clock: &Clock,
    borrower: address, repay_coin: Coin<T>, ctx: &mut TxContext) {
    accrue_interest(pool, clock);
    assert!(calculate_health_factor(pool, borrower) < LIQUIDATION_THRESHOLD, E_HEALTHY);
    execute_liquidation(pool, borrower, repay_coin, ctx); // Instant liquidation
}
```

**Fixed:**
```move
public fun liquidate<T>(pool: &mut LendingPool, clock: &Clock,
    borrower: address, repay_coin: Coin<T>, ctx: &mut TxContext) {
    accrue_interest(pool, clock);
    assert!(calculate_health_factor(pool, borrower) < LIQUIDATION_THRESHOLD, E_HEALTHY);
    let now = clock::timestamp_ms(clock);
    let pos = borrow_position_mut(pool, borrower);
    if (pos.unhealthy_since == 0) {
        pos.unhealthy_since = now;
        abort E_GRACE_PERIOD_ACTIVE
    };
    assert!(now - pos.unhealthy_since >= GRACE_PERIOD_MS, E_GRACE_PERIOD_ACTIVE);
    execute_liquidation(pool, borrower, repay_coin, ctx);
}
```

#### Pattern 4: Forced Debt Creation
Attacker forces debt onto unwilling users. On Sui, the `store` ability lets debt objects be transferred to arbitrary addresses via `transfer::public_transfer`, creating obligations for victims who never consented.

**Vulnerable:**
```move
// Sui: store ability lets anyone transfer debt to victim
public struct DebtObligation has key, store { id: UID, amount: u64 }

public fun force_debt(victim: address, ctx: &mut TxContext) {
    transfer::public_transfer(
        DebtObligation { id: object::new(ctx), amount: 1_000_000 }, victim
    );
}
```

**Fixed:**
```move
// No store -- debt bound to sender only via transfer::transfer
public struct DebtObligation has key { id: UID, borrower: address, amount: u64 }

public fun borrow(pool: &mut LendingPool, amount: u64, ctx: &mut TxContext): Coin<SUI> {
    let borrower = tx_context::sender(ctx);
    transfer::transfer(
        DebtObligation { id: object::new(ctx), borrower, amount }, borrower
    );
    withdraw_from_pool(pool, amount, ctx)
}
```

#### Pattern 5: State Manipulation via Refinancing
Borrow + refinance in the same transaction lets the attacker reset their interest index, skipping accumulated interest owed. Without a cooldown or proper interest settlement, the refinance function becomes an interest-evasion tool.

**Vulnerable:**
```move
public fun refinance(pool: &mut LendingPool, clock: &Clock, ctx: &mut TxContext) {
    accrue_interest(pool, clock);
    let pos = get_or_create_position(pool, tx_context::sender(ctx));
    // Resets index without settling accrued interest -- skips owed amount
    pos.interest_index = pool.global_interest_index;
}
```

**Fixed:**
```move
public fun refinance(pool: &mut LendingPool, clock: &Clock, ctx: &mut TxContext) {
    accrue_interest(pool, clock);
    let pos = get_or_create_position(pool, tx_context::sender(ctx));
    let now = clock::timestamp_ms(clock);
    assert!(now - pos.last_action_ts >= MIN_REFINANCE_COOLDOWN, E_COOLDOWN);
    // Settle accrued interest before resetting index
    pos.borrowed = pos.borrowed +
        calc_accrued(pos.borrowed, pos.interest_index, pool.global_interest_index);
    pos.interest_index = pool.global_interest_index;
    pos.last_action_ts = now;
}
```

### Remediation
Enforce symmetric pause across repay and liquidation. Provide third-party repayment paths for denylisted borrowers. Implement grace periods between position becoming unhealthy and liquidation eligibility. Remove `store` ability from debt structs so they cannot be transferred to unwilling recipients via `transfer::public_transfer`. Enforce cooldowns between borrow and refinance with proper interest settlement before index reset.

### Signature
**Slug:** `lending-pause-recovery-invariant`
**Detect:** For every lending pause and recovery path: (1) verify pause is symmetric across repay and liquidation, (2) verify repayment is possible for denylisted addresses via proxy, (3) verify grace period exists before liquidation, (4) verify debt objects cannot be transferred to unwilling recipients, (5) verify refinancing settles accrued interest and enforces cooldown.
**What's Wrong:** Lending protocol pause and recovery mechanisms create unfair windows where borrowers cannot defend positions, denylisted users are force-liquidated, no grace period exists, debt is forcibly created, or interest index is manipulable via refinancing.
**Remediation:** Implement symmetric pause, proxy repayment, grace periods, unforgeable debt binding, and cooldown-gated refinancing with interest settlement.
