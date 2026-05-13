# CAT-VAULT: Vault

**Context:** `ctx:vault`
**Detectors:** 2

## CL-VAULT-01: Share Accounting Invariant

**Rule:** `MOVE-VAULT-SHARE-01`
**Severity:** low-critical

## Description

Every vault that converts between shares and underlying assets must maintain mathematically consistent exchange-rate accounting across all entry points. Violations include first-depositor manipulation, inconsistent rounding direction, unsegregated fees inflating share price, stale balance tracking, unvalidated initial ratios, and zero-value minting.

## Patterns

1. **First-Depositor Share Price Manipulation** — The vault's share price can be inflated by the first depositor through donation-based attacks when total supply is zero or near-zero, causing subsequent depositors' shares to round to zero.

```move
// VULNERABLE: No protection against first-depositor attack
public fun deposit(account: &signer, amount: u64): u64 acquires Vault {
    let vault = borrow_global_mut<Vault>(@vault_addr);
    let shares = if (vault.total_shares == 0) {
        amount // 1:1 on first deposit, no dead shares
    } else {
        amount * vault.total_shares / vault.total_assets
    };
    // Attacker: deposit 1 wei, then donate 1M tokens directly
    // Next depositor gets 0 shares due to rounding
    vault.total_assets = vault.total_assets + amount;
    vault.total_shares = vault.total_shares + shares;
    coin::transfer<AptosCoin>(account, @vault_addr, amount);
    shares
}

// FIXED: Virtual offset + dead shares on first deposit
public fun deposit(account: &signer, amount: u64): u64 acquires Vault {
    let vault = borrow_global_mut<Vault>(@vault_addr);
    let virtual_assets = vault.total_assets + VIRTUAL_OFFSET;
    let virtual_shares = vault.total_shares + VIRTUAL_OFFSET;
    let shares = if (vault.total_shares == 0) {
        let dead = amount / 1000;
        vault.total_shares = vault.total_shares + dead; // burn dead shares
        amount - dead
    } else {
        amount * virtual_shares / virtual_assets
    };
    assert!(shares > 0, E_ZERO_SHARES);
    vault.total_assets = vault.total_assets + amount;
    vault.total_shares = vault.total_shares + shares;
    coin::transfer<AptosCoin>(account, @vault_addr, amount);
    shares
}
```

2. **Inconsistent Rounding Direction in Share Conversions** — The protocol applies caller-favorable rounding in share/asset conversions, allowing value extraction through repeated micro-transactions.

```move
// VULNERABLE: Rounding up shares on deposit (favors depositor)
public fun assets_to_shares(assets: u64, total_assets: u64, total_shares: u64): u64 {
    (assets * total_shares + total_assets - 1) / total_assets // ceiling = BAD for deposit
}

// VULNERABLE: Rounding down shares burned on withdrawal (favors withdrawer)
public fun shares_to_assets(shares: u64, total_assets: u64, total_shares: u64): u64 {
    shares * total_assets / total_shares // floor on assets = BAD for withdrawal
}

// FIXED: Protocol-favorable rounding in all directions
public fun assets_to_shares(assets: u64, total_assets: u64, total_shares: u64, round_up: bool): u64 {
    if (round_up) {
        (assets * total_shares + total_assets - 1) / total_assets
    } else {
        assets * total_shares / total_assets // floor for deposit
    }
}
// Deposit: round DOWN shares minted. Withdraw: round DOWN assets, round UP shares burned.
```

3. **Unsegregated Fees Inflating Share Price** — Fees deducted during withdrawal remain in the main vault balance, artificially inflating total_assets relative to total_shares.

```move
// VULNERABLE: Fee stays in vault balance, inflates share price
public fun withdraw(account: &signer, shares: u64) acquires Vault {
    let vault = borrow_global_mut<Vault>(@vault_addr);
    let assets = shares * vault.total_assets / vault.total_shares;
    let fee = assets * FEE_BPS / 10000;
    let payout = assets - fee;
    // fee remains in vault, total_assets not reduced by fee
    vault.total_shares = vault.total_shares - shares;
    vault.total_assets = vault.total_assets - payout; // only payout deducted
    let resource_signer = account::create_signer_with_capability(&vault.signer_cap);
    coin::transfer<AptosCoin>(&resource_signer, signer::address_of(account), payout);
}

// FIXED: Move fee to separate collector
public fun withdraw(account: &signer, shares: u64) acquires Vault, FeeCollector {
    let vault = borrow_global_mut<Vault>(@vault_addr);
    let assets = shares * vault.total_assets / vault.total_shares;
    let fee = assets * FEE_BPS / 10000;
    let payout = assets - fee;
    vault.total_shares = vault.total_shares - shares;
    vault.total_assets = vault.total_assets - assets; // full amount deducted
    let resource_signer = account::create_signer_with_capability(&vault.signer_cap);
    // Fee sent to separate collector address
    coin::transfer<AptosCoin>(&resource_signer, @fee_collector, fee);
    coin::transfer<AptosCoin>(&resource_signer, signer::address_of(account), payout);
}
```

4. **Asymmetric Share-to-Balance Accounting** — Withdrawal logic decrements total shares but fails to update the corresponding total balance tracker, causing share price to spike.

```move
// VULNERABLE: Shares burned but total_balance not updated
public fun redeem(account: &signer, shares: u64) acquires Vault {
    let vault = borrow_global_mut<Vault>(@vault_addr);
    let assets = shares * vault.total_assets / vault.total_shares;
    vault.total_shares = vault.total_shares - shares;
    // BUG: vault.total_assets NOT decremented
    // Next share is now worth more: total_assets / (total_shares - burned)
    let resource_signer = account::create_signer_with_capability(&vault.signer_cap);
    coin::transfer<AptosCoin>(&resource_signer, signer::address_of(account), assets);
}

// FIXED: Both numerator and denominator updated atomically
public fun redeem(account: &signer, shares: u64) acquires Vault {
    let vault = borrow_global_mut<Vault>(@vault_addr);
    let assets = shares * vault.total_assets / vault.total_shares;
    vault.total_shares = vault.total_shares - shares;
    vault.total_assets = vault.total_assets - assets;
    let resource_signer = account::create_signer_with_capability(&vault.signer_cap);
    coin::transfer<AptosCoin>(&resource_signer, signer::address_of(account), assets);
}
```

5. **Zero-Value Share Minting and Unvalidated Initial Ratio** — Deposits too small relative to the exchange rate produce zero shares (donation to pool), or initialization sets an arbitrary share-to-asset ratio breaking the accounting invariant.

```move
// VULNERABLE: No check that minted shares > 0
public fun deposit(account: &signer, amount: u64) acquires Vault {
    let vault = borrow_global_mut<Vault>(@vault_addr);
    let shares = amount * vault.total_shares / vault.total_assets;
    // shares could be 0 if amount is tiny relative to ratio
    vault.total_shares = vault.total_shares + shares;
    vault.total_assets = vault.total_assets + amount;
    coin::transfer<AptosCoin>(account, @vault_addr, amount);
}

// VULNERABLE: Arbitrary initial ratio in LST creation
public fun create_lst(account: &signer, amount: u64, supply: u64) acquires LSTConfig {
    let config = borrow_global_mut<LSTConfig>(@lst_addr);
    // No check that amount == supply
    config.total_staked = amount;
    config.total_supply = supply;
    coin::transfer<AptosCoin>(account, @lst_addr, amount);
}

// FIXED: Assert shares > 0 and enforce 1:1 initial ratio
public fun deposit(account: &signer, amount: u64) acquires Vault {
    let vault = borrow_global_mut<Vault>(@vault_addr);
    let shares = amount * vault.total_shares / vault.total_assets;
    assert!(shares > 0, E_ZERO_SHARES);
    vault.total_shares = vault.total_shares + shares;
    vault.total_assets = vault.total_assets + amount;
    coin::transfer<AptosCoin>(account, @vault_addr, amount);
}

public fun create_lst(account: &signer, amount: u64) acquires LSTConfig {
    let config = borrow_global_mut<LSTConfig>(@lst_addr);
    config.total_staked = amount;
    config.total_supply = amount; // enforced 1:1
    coin::transfer<AptosCoin>(account, @lst_addr, amount);
}
```

6. **Inconsistent Invariant Enforcement Across Entry Points** — Balance or health invariants are checked in some state-changing functions but omitted in others.

```move
// VULNERABLE: Invariant checked in withdraw but not repay
public fun withdraw(account: &signer, amount: u64) acquires Vault {
    let vault = borrow_global_mut<Vault>(@vault_addr);
    vault.balance = vault.balance - amount;
    assert!(vault.balance >= vault.total_debt, E_INVARIANT); // checked here
    let resource_signer = account::create_signer_with_capability(&vault.signer_cap);
    coin::transfer<AptosCoin>(&resource_signer, signer::address_of(account), amount);
}

public fun repay(account: &signer, amount: u64) acquires Vault {
    let vault = borrow_global_mut<Vault>(@vault_addr);
    vault.total_debt = vault.total_debt - amount;
    coin::transfer<AptosCoin>(account, @vault_addr, amount);
    // BUG: no invariant check here
}

// FIXED: Centralized invariant check
fun enforce_invariant(vault: &Vault) {
    assert!(vault.balance >= vault.total_debt, E_INVARIANT);
}

public fun withdraw(account: &signer, amount: u64) acquires Vault {
    let vault = borrow_global_mut<Vault>(@vault_addr);
    vault.balance = vault.balance - amount;
    enforce_invariant(vault);
    let resource_signer = account::create_signer_with_capability(&vault.signer_cap);
    coin::transfer<AptosCoin>(&resource_signer, signer::address_of(account), amount);
}

public fun repay(account: &signer, amount: u64) acquires Vault {
    let vault = borrow_global_mut<Vault>(@vault_addr);
    vault.total_debt = vault.total_debt - amount;
    coin::transfer<AptosCoin>(account, @vault_addr, amount);
    enforce_invariant(vault);
}
```

## Remediation

- Use virtual share/asset offsets and burn dead shares on first deposit to prevent donation attacks.
- Implement a unified conversion function with an explicit rounding direction parameter; deposits round DOWN shares minted, withdrawals round DOWN assets returned and round UP shares burned.
- Segregate collected fees into a dedicated balance, removing them from total_assets used in share price calculations.
- Update both total_shares and total_assets atomically in every state-changing operation.
- Assert that minted shares are always greater than zero and enforce strict initial ratios.
- Extract invariant checks into a centralized function called from every state-changing entry point.

## Signature
**Slug:** `share-accounting-invariant→fund-loss`
**Detect:** For every vault share/asset conversion path: (1) check first-depositor protection (virtual offsets, dead shares, minimum deposit), (2) verify rounding favors the protocol in all directions, (3) confirm fees are segregated from total_assets, (4) ensure total_shares and total_assets are updated symmetrically, (5) assert minted shares > 0 and initial ratios are validated, (6) confirm invariant checks are applied consistently across all entry points.
**What's Wrong:** The vault's share-to-asset accounting is inconsistent — share price can be manipulated via donation attacks, rounding exploits, unsegregated fees, asymmetric state updates, zero-value minting, or inconsistent invariant enforcement.
**Remediation:** Implement virtual offsets with dead shares, protocol-favorable rounding, fee segregation, atomic state updates, non-zero share assertions, and centralized invariant enforcement across all conversion paths.

---

## CL-VAULT-02: State Synchronization Invariant

**Rule:** `MOVE-VAULT-SYNC-01`
**Severity:** medium-high

## Description
Every operation that modifies one side of a dual-accounting pair (shares vs assets, internal balance vs external balance, per-pool vs global totals) must atomically update the corresponding counterpart. Desynchronized state variables create phantom balances, double-counting, or unclaimable funds.

## Patterns

1. **Double-Subtraction on State Variable** — A value is subtracted from a state variable in two separate code paths within the same operation (e.g., once in the accounting update and again in the transfer logic), effectively debiting twice.

```move
// VULNERABLE: allocated_rewards subtracted twice
public fun distribute(pool: &mut Pool, amount: u64) {
    pool.total_rewards = pool.total_rewards - amount; // first subtraction
    let net = pool.total_rewards - pool.allocated; // uses already-reduced total
    pool.allocated = pool.allocated - amount; // second subtraction
}

// FIXED: single atomic update
public fun distribute(pool: &mut Pool, amount: u64) {
    pool.allocated = pool.allocated - amount;
    pool.total_rewards = pool.total_rewards - amount;
}
```

2. **Asymmetric Share-Asset Update** — Shares are burned or minted without correspondingly adjusting the total_assets denominator, inflating or deflating the exchange rate for remaining holders.

```move
// VULNERABLE: shares burned but assets still counted
public fun withdraw(vault: &mut Vault, user: &mut User, shares: u64) {
    let assets = shares_to_assets(vault, shares);
    burn_shares(vault, user, shares);
    // vault.total_assets NOT reduced — remaining shares overvalued
    transfer(user, assets);
}

// FIXED: atomically update both
public fun withdraw(vault: &mut Vault, user: &mut User, shares: u64) {
    let assets = shares_to_assets(vault, shares);
    burn_shares(vault, user, shares);
    vault.total_assets = vault.total_assets - assets;
    transfer(user, assets);
}
```

3. **Internal vs External Balance Desync** — The protocol's internal accounting does not reflect external state changes from slashing, validator penalties, or direct transfers, causing the recorded balance to diverge from actual holdings.

```move
// VULNERABLE: internal state ignores slashing
public fun get_user_balance(pool: &Pool, user: &User): u64 {
    user.staked * pool.exchange_rate // exchange_rate never updated after slash
}

// FIXED: sync with actual balance
public fun sync_external_state(pool: &mut Pool) {
    let actual = coin::value(&pool.vault);
    let recorded = pool.total_staked * pool.exchange_rate;
    if (actual < recorded) {
        pool.exchange_rate = actual / pool.total_staked;
    };
}
```

4. **Shared Vault Without Per-Pool Isolation** — Multiple pools share a single vault or balance variable without internal sub-accounting, allowing one pool's operations to consume another pool's funds.

```move
// VULNERABLE: global vault, no per-pool tracking
public fun claim_pool_reward(vault: &mut Vault, pool_id: u64, amount: u64) {
    assert!(coin::value(&vault.balance) >= amount, E_INSUFFICIENT);
    // any pool can drain the entire vault
    transfer(pool_id, coin::extract(&mut vault.balance, amount));
}

// FIXED: per-pool accounting
public fun claim_pool_reward(vault: &mut Vault, pool_id: u64, amount: u64) {
    let pool_bal = table::borrow_mut(&mut vault.pool_balances, pool_id);
    assert!(*pool_bal >= amount, E_INSUFFICIENT);
    *pool_bal = *pool_bal - amount;
    transfer(pool_id, coin::extract(&mut vault.balance, amount));
}
```

## Remediation
Ensure every state mutation updates both sides of any accounting pair atomically within the same function call. After loops, verify accumulators reflect the total processed. Sync internal balances with external state (slashing, fees) before computing distributions. Isolate per-pool accounting within shared vaults.

## Signature
**Slug:** `state-synchronization-invariant`
**Detect:** For every dual-accounting state update: (1) verify no double-subtraction on same variable, (2) verify share burns update total_assets, (3) verify internal state syncs with external changes, (4) verify shared vaults track per-pool balances.
**What's Wrong:** State variables representing paired economic values are updated independently or incompletely, causing accounting divergence.
**Remediation:** Atomic dual-side updates; external state synchronization; per-pool vault isolation.

---
