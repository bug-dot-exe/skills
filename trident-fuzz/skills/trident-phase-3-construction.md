---
name: trident-phase-3-construction
description: "Phase 3 of Trident fuzzing: design modular flows, write instruction builders, and compose #[end] assertions from invariant modules."
type: reference
---

# Phase 3: Test Construction

**GOAL:** Write modular flows and compose `#[end]` assertions from the invariant functions built in Phase 2.

---

## Step 3.1 — Design flows

Each `#[flow]` method = one transaction path the fuzzer randomly selects.

### Flow design principles

1. **Flows must be independent** — any ordering should be valid.
2. **Never panic on transaction failure in flows** — both success and revert are valid.
3. **Track success/revert counts per flow type** — needed for non-triviality guards and debugging.
4. **Use `common/instructions.rs` builders** — flows should be 3-5 lines, not 50.
5. **Cover both directions** — deposit AND withdraw, borrow AND repay.

### Flow categories to consider

| Category | Purpose | Example | Frequency |
| -------- | ------- | ------- | --------- |
| **Happy path** | Normal operations, random amounts | deposit, withdraw | Every iteration, multiple times |
| **Cross-protocol** | Operations on another protocol sharing state | lending deposit/withdraw | Every iteration, multiple times |
| **Adversarial** | Irreversible state transitions | oracle crash + liquidate | Once per iteration (guard with bool) |
| **Post-event** | Operations after irreversible changes | operate on liquidated position | Once, after adversarial flow |
| **Time-based** | Advance clock between operations | `forward_in_time` + accrue | Every iteration |

### Handling architectural constraints

**Dynamic-PDA problem (e.g., borrow -> tick):**

Each borrow amount computes a different tick, which is a different PDA that must be pre-initialized. Three options:

- **Scope down:** Only fuzz deposit/withdraw. Use fixed setup borrows for position initialization. Note the gap.
- **Pre-initialize a range:** Create N ticks in setup, constrain random amounts to values that land on those ticks.
- **Compute dynamically:** Use the same tick math library as on-chain code to derive the correct PDA in the flow. Hardest but most complete.

**One-shot flows (irreversible state changes):**

```rust
#[flow]
fn flow_liquidation_cycle(&mut self) {
    if self.liquidation_done { return; }
    // ... crash oracle, liquidate, restore oracle ...
    self.liquidation_done = true;
}
```

### Oracle price manipulation for liquidation testing

Use `set_account_custom` to inject custom oracle prices:

```rust
// Crash oracle: $1.00 -> $0.88
let mut price_data = self.trident.get_raw_account(&oracle_price_pk);
// Modify the price bytes in the Pyth price struct
// price_data[offset..offset+8] = new_price.to_le_bytes();
self.trident.set_account_custom(&oracle_price_pk, &price_data);
```

## Step 3.2 — Write instruction builders in `common/instructions.rs`

Each builder takes `Trident` + accounts, returns `TransactionResult`. The caller decides success/failure handling:

```rust
pub fn do_operate(
    trident: &mut Trident,
    accounts: &AccountAddresses,
    col_delta: i128,
    debt_delta: i128,
) -> TransactionResult {
    let signer = accounts.signer.get(trident).expect("signer not set");
    // ... gather all accounts ...

    let ix = OperateInstruction::data(OperateInstructionData::new(
        col_delta, debt_delta, Some(TransferType::DIRECT), vec![1u8, 1u8, 1u8],
    ))
    .accounts(OperateInstructionAccounts::new(/* ... */))
    .remaining_accounts(vec![
        AccountMeta::new_readonly(oracle_source, false),
        AccountMeta::new(branch, false),
        AccountMeta::new(tick_has_debt, false),
    ])
    .instruction();

    trident.process_transaction(&[ix], Some("operate"))
}
```

## Step 3.3 — Write flows in `test_fuzz.rs`

Flows become thin wrappers around instruction builders:

```rust
#[flow]
fn flow_deposit(&mut self) {
    let amount = self.trident.random_from_range(1..1_000_000_u64) as i128;
    let res = instructions::do_operate(&mut self.trident, &self.fuzz_accounts, amount, 0);
    if res.is_success() { self.deposit_ok += 1; }
    else {
        self.deposit_err += 1;
        eprintln!("[deposit revert] amount={}\n{}", amount, res.logs());
    }
}

#[flow]
fn flow_withdraw(&mut self) {
    let amount = self.trident.random_from_range(1..1_000_000_u64) as i128;
    let res = instructions::do_operate(&mut self.trident, &self.fuzz_accounts, -amount, 0);
    if res.is_success() { self.withdraw_ok += 1; }
    else { self.withdraw_err += 1; }
}
```

## Step 3.4 — Compose `#[end]` from invariant modules

Call invariant functions from `common/invariants.rs`:

```rust
#[end]
fn end(&mut self) {
    // -- Summary --
    eprintln!("[fuzz] deposit ok={} err={}, withdraw ok={} err={}",
        self.deposit_ok, self.deposit_err, self.withdraw_ok, self.withdraw_err);

    // -- Non-triviality --
    assert!(self.deposit_ok + self.withdraw_ok > 0, "nothing succeeded -- setup broken");

    // -- Invariants (pick from common/invariants.rs) --
    let vs_pk = self.fuzz_accounts.vault_state.get(&mut self.trident).unwrap();
    let tick_pk = self.fuzz_accounts.tick_zero.get(&mut self.trident).unwrap();

    invariants::check_debt_ledger(&self.trident, &vs_pk, &tick_pk);
    invariants::check_bitmap_sync(&self.trident, &thd_pk, &tick_pk);
    invariants::check_dust_bound(&self.trident, &pos_pk, &tick_pk);

    // -- Campaign-specific (not reusable) --
    if self.deposit_ok > self.withdraw_ok {
        let pos = self.trident.get_account_with_type::<Position>(&pos_pk, 8).unwrap();
        assert!(pos.col_raw > 0, "NT-1: deposits > withdrawals but no collateral");
    }
}
```

## Step 3.5 — Set `main()` parameters

```rust
fn main() {
    // Start small for Phase 4 validation, scale up after
    FuzzTest::fuzz(100, 50);  // (iterations, max_flows_per_iteration)
}
```

**Present the complete file set to the user: `test_fuzz.rs`, `common/setup.rs`, `common/instructions.rs`, `common/invariants.rs`.**

**STOP. Wait for user approval before Phase 4.**
