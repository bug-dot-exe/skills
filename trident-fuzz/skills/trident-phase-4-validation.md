---
name: trident-phase-4-validation
description: "Phase 4 of Trident fuzzing: compile, run a short campaign, verify flows execute correctly, debug setup issues, confirm invariants fire."
type: reference
---

# Phase 4: Dry Run & Validation

**GOAL:** Verify the test actually works before running a full campaign. A passing fuzz test is worthless if the setup is broken and all flows silently revert.

---

## Step 4.1 — Build programs and compile

```bash
# Build program binaries (from project root)
anchor build

# Verify binaries exist at Trident.toml paths
ls -la target/deploy/*.so

# Compile fuzz test (from trident-tests/)
cd trident-tests
cargo build --bin fuzz_0
```

**Common compile errors:**

| Error | Cause | Fix |
| ----- | ----- | --- |
| `unresolved import crate::types::my_program` | Module name in `types.rs` differs from your import | Read `types.rs`, search for `pub mod` |
| `no method named new` | Wrong parameter count/order | Read the struct's `pub fn new()` in `types.rs` |
| `trait bound: BorshDeserialize` | State struct is zero_copy, not borsh | Use raw byte reading instead of `get_account_with_type` |
| `cannot find type` | Type not in `types.rs` | Import from program crate: `use my_program::state::MyStruct` |
| `#[path] module` | `common/` module not found | Check `#[path = "../common/mod.rs"]` and `mod.rs` exports |

## Step 4.2 — Run a short validation campaign

Set `FuzzTest::fuzz(10, 10)` — just 10 iterations, 10 flows each. Run:

```bash
cargo run --bin fuzz_0
```

### Critical debugging gotcha: parallel mode hides panics

Trident's parallel mode routes panics through a progress bar, NOT stderr. Redirecting stderr (`2>file.txt`) produces an empty file even when panics occur.

**Debug mode** — force single-threaded execution:

```bash
cargo build --bin fuzz_0
TRIDENT_FUZZ_DEBUG=0000000000000000 ./target/debug/fuzz_0 2>&1 | head -200
```

Use this whenever you need to see panic messages or program logs.

## Step 4.3 — Validation checklist

### A. Setup success

Every init transaction in `start()` must succeed. If any fails, the assert panics with logs.

- [ ] All PDA seeds match on-chain expectations
- [ ] Init instructions ran in correct dependency order
- [ ] Token mints created before token accounts
- [ ] Rate models initialized before token configs
- [ ] Sufficient SOL airdropped (100 SOL per account)

### B. Flow execution rates

From the `eprintln!` output in `end()`:

- [ ] **Total success > 0** — the non-triviality guard passes
- [ ] **Each flow type has some successes** — if a flow type is 100% revert, investigate

| Flow always reverts | Likely cause |
| ------------------- | ------------ |
| Borrow | Final tick PDA doesn't match computed tick for borrow amount |
| Withdraw | Random amount > deposited amount (expected, fine) |
| Repay | Random amount > debt (expected, fine) |
| ALL flows | PDA seed mismatch in instruction builder |

### C. Invariant sensitivity test

Temporarily break an invariant to confirm it fires:

```rust
// Add temporarily to end():
assert_eq!(vault_state.total_borrow, 999999, "E2 sensitivity test");
```

If the assertion never fires, the state read is returning wrong data. Check:

- Account pubkey correct?
- Discriminator offset = 8?
- State type matches on-chain struct?
- Both sides of the assertion are always 0? (trivially true = broken setup)

### D. Log inspection

Check the revert logs from flows. Are they expected reverts (insufficient balance, CF exceeded) or unexpected errors (wrong account, missing signer)?

Expected reverts = healthy. The fuzzer is exploring boundary conditions.
Unexpected errors = setup bug. Fix before proceeding.

## Step 4.4 — Interpret validation output

### Green — ready to scale

```text
[fuzz] deposit ok=47 err=53, withdraw ok=22 err=78
All 10 iterations passed.
```

Good mix of success and revert. Scale up: `FuzzTest::fuzz(1000, 100)`.

### Yellow — partial success

```text
[fuzz] deposit ok=3 err=97, withdraw ok=0 err=100
```

Deposits barely work, withdraws never work. Check:

- Are random amounts too large relative to initial funding?
- Does a time-dependent check need `forward_in_time`?
- Is the initial deposit too small for withdraw ranges?

Constrain ranges, re-run.

### Red — setup broken

```text
assertion failed: init supply mint failed
  logs: Program log: Error: AccountNotInitialized
```

or:

```text
assertion failed: nothing succeeded -- setup broken
```

Use debug mode (Step 4.2) to identify the failing transaction. Fix setup, re-compile, re-run.

## Step 4.5 — Scale up

Once validation passes:

```rust
fn main() {
    FuzzTest::fuzz(1000, 100);
}
```

```bash
cargo run --bin fuzz_0 --release  # --release for faster execution
```

**Present validation results to user: success/revert rates per flow, any issues found, ready for Phase 5 or need to loop back.**

**STOP. Wait for user approval before Phase 5.**
