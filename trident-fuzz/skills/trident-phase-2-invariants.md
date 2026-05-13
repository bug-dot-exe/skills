---
name: trident-phase-2-invariants
description: "Phase 2 of Trident fuzzing: derive testable invariants from protocol state relationships, audit findings, and cross-program interactions."
type: reference
---

# Phase 2: Invariant Mapping

**GOAL:** Derive testable invariants from the protocol's state relationships. These become the assertions in `#[end]`.

---

## Step 2.1 — Source invariants

Pull invariants from these sources (in priority order):

### Source A: Existing invariant table from a prior audit (check first)

If a prior audit produced an invariant table, look for it in audit reports, findings files, or CLAUDE.md. The expected format:

```markdown
| # | Invariant | Derived From | Fuzzable? | State Reads Needed | Detection Scope |
```

**If this table exists, use it directly.** The `State Reads Needed` column tells you which accounts to read with `get_account_with_type`. The `Detection Scope` column maps to the detection hierarchy in Step 2.3. Filter for `Fuzzable? = Yes` and skip to Step 2.2.

If no invariant table exists (e.g., fuzzing before audit, or fuzzing a program you didn't audit), continue with Sources B-D below.

### Source B: Audit findings (regression invariants)

Confirmed bugs become **regression invariants**. For each finding:
- What state was incorrect? That's the invariant (negated).
- Can you detect it from on-chain account state after the instruction completes?
- Is the bug **within-program** or **cross-program**? This determines where to assert.

**Lesson learned:** Cross-protocol invariants (e.g., "liquidity layer totals >= protocol position amounts") will NOT catch within-protocol bugs where both sides of a CPI record the same wrong number consistently. For within-protocol bugs (e.g., stale dust after liquidation), you need **within-protocol assertions** that compare internal fields against each other.

### Source C: State relationship analysis

Read the target instruction's logic and identify:

| Category | Pattern | Example | Detection difficulty |
| -------- | ------- | ------- | -------------------- |
| **Accounting identity** | Global aggregate == sum of parts | `total_borrow == sum(tick.raw_debt)` | Easy — read 2 accounts |
| **Bitmap/flag sync** | Bit set iff condition | `has_debt_bit == (raw_debt > 0)` | Easy — read 2 accounts |
| **Dust/rounding bound** | Dust < parent value | `dust_debt < raw_debt` | Easy — read 2 accounts |
| **Cross-protocol conservation** | Layer total >= protocol position | `TR.total_supply >= position.amount` | Medium — read cross-program accounts |
| **Ordering constraint** | Timestamps monotonic | `last_update <= current_time` | Easy — read 1 account |
| **Token conservation** | Vault balance >= tracked value | `token_account.amount >= total_redeemable` | Hard — need token account + protocol state |

### Source D: Implicit invariants (verified by transaction success)

Some properties don't need explicit assertions — they're verified by the on-chain program reverting if violated. Document these but don't assert them in `end()`:

| Property | How verified |
| -------- | ----------- |
| Tick computation matches on-chain expectation | `operate()` succeeds |
| PDA seeds are correct | Any instruction using the PDA succeeds |
| Signer authority is valid | Instruction doesn't revert with unauthorized |

## Step 2.2 — Classify and filter

For each candidate invariant, determine:

**Can it be checked with `get_account_with_type`?**
- Borsh-serialized Anchor accounts: yes, offset = 8 (discriminator)
- Zero-copy accounts: may need custom byte casting (more complex)
- Token accounts: use `get_token_account()` or `get_mint()` helpers

**Is it single-account or cross-account?**
- Cross-account invariants are more valuable (catch more bugs)
- Cross-program invariants catch the most (shared state corruption)

**Is it a general invariant or a bug-specific assertion?**
- **General invariants** should always hold, regardless of bug fixes. Preferred.
- **Bug-specific assertions** assert the *presence* of a known bug (useful for regression testing, but will break when the bug is fixed). Mark these clearly.

## Step 2.3 — Categorize by detection scope

This is the critical insight from our experience:

```text
Detection scope hierarchy:

  Cross-protocol invariants (T1, T2, B1)
    |
    |  catches: shared state corruption between programs
    |  misses:  within-protocol bugs where CPI records same wrong number on both sides
    |
  Within-protocol invariants (E2, C1, D1)
    |
    |  catches: internal state inconsistency (debt ledger, bitmap, dust)
    |  misses:  bugs where all internal fields stay consistent but values are wrong
    |
  Token balance invariants
    |
    |  catches: actual fund loss (vault balance vs tracked value)
    |  misses:  accounting bugs that don't manifest as balance differences yet
    |
  Non-triviality guards (NT-1)
    |
    |  catches: "everything passes because nothing happened"
    |  essential: prevents false confidence from broken setup
```

**You need invariants at multiple levels.** A single level will always have blind spots.

## Step 2.4 — Add non-triviality guards

Always include at least one **non-triviality invariant** — a meta-check that verifies the fuzzer is actually exercising meaningful state:

```rust
// If more deposits succeeded than withdrawals, position must have balance
if deposit_ok > withdraw_ok {
    assert!(position.amount > 0, "NT-1: deposits succeeded but balance is zero");
}
```

Without this, a broken setup causes all flows to silently revert, all invariants pass trivially (zero state = no violations), and you get false confidence.

## Step 2.5 — Present invariant table

| ID | Invariant | Scope | Accounts | Check Method | Source |
| -- | --------- | ----- | -------- | ------------ | ------ |
| T1 | `supply_TR.with_interest >= lending_position.amount` | Cross-protocol | token_reserve, lending_pos | `get_account_with_type` | conservation |
| T2 | `supply_TR.interest_free >= vault_position.amount` | Cross-protocol | token_reserve, vault_pos | `get_account_with_type` | conservation |
| E2 | `vault_state.total_borrow == tick.raw_debt` | Within-protocol | vault_state, tick | `get_account_with_type` | accounting |
| C1 | `has_debt_bit SET iff raw_debt > 0` | Within-protocol | tick_has_debt, tick | `get_account_with_type` | bitmap sync |
| D1 | `position.dust_debt < tick.raw_debt` | Within-protocol | position, tick | `get_account_with_type` | dust bound |
| NT-1 | `deposit_ok > withdraw_ok => position.amount > 0` | Meta | position | `get_account_with_type` | non-triviality |

For each invariant, also note:
- **What it catches** (the bug class)
- **What it misses** (known blind spots)
- **Whether it's general or bug-specific**

## Step 2.6 — Assess invariant quality

An invariant that never fails is either proof of correctness or proof that you're not testing anything. This step helps you tell the difference.

### The independence test

The quality of an invariant is determined by **how independently the two sides are computed.** The more independent the code paths that produce each value, the more bugs the invariant can detect.

| Independence level | Description | Example | Quality |
| ------------------ | ----------- | ------- | ------- |
| **High** | Two values updated by completely separate code paths, stored in separate accounts | `vault_state.total_borrow` vs `tick.raw_debt` — updated by different functions in the operate pipeline | Strong — a bug in either path causes divergence |
| **Medium** | Two values updated by the same transaction but in different programs via CPI | `supply_TR.interest_free` vs `vault_supply_position.amount` — vault CPIs to liquidity, both update | Moderate — catches cross-program bugs, but CPI-consistent bugs are invisible |
| **Low** | Two values derived from the same source in the same function | `position.col_raw` vs a re-read of the same field | Weak — tautological, catches nothing |
| **Zero** | One side is a constant | `total_supply >= 0` | Useless unless the type is signed |

**Rule of thumb:** If you can trace both sides of the assertion back to the same write in the same function, the invariant is tautological. You need at least one side to be written by a different code path.

### The bypass test

For each invariant, ask: **"Can I construct a scenario where the protocol has a real bug but this invariant still holds?"**

Examples from our experience:

| Invariant | Bypass scenario | Why it's bypassed |
| --------- | --------------- | ----------------- |
| T1: `TR.with_interest >= lending_pos.amount` | Vault computes wrong repayment via stale dust, CPIs wrong amount to liquidity layer | Both sides of the CPI record the same wrong number — cross-protocol conservation holds |
| E2: `total_borrow == raw_debt` | Interest accrual changes effective debt but neither field is updated until next operation | Both fields are stale by the same amount — equality holds |
| D1: `dust < raw_debt` | Dust is recalculated correctly but the tick it's computed from is wrong | Dust < raw_debt holds numerically even though the dust value is semantically wrong |

If you find a bypass, you need a **complementary invariant** at a different scope that catches what this one misses.

### The sensitivity test

**The problem:** An invariant that never fails could mean (1) the code is correct, or (2) the invariant isn't actually checking anything — like a smoke detector with dead batteries. The sensitivity test checks the batteries.

**Three failure modes that make an invariant insensitive:**

1. **Dead read** — reading the wrong account or wrong offset, getting zeroed/garbage data:

```rust
// Bug: wrong pubkey — reads a different account that happens to be zeroed
let state = self.trident.get_account_with_type::<VaultState>(&wrong_pk, 8);
// state.total_borrow = 0, tick.raw_debt = 0, assert_eq!(0, 0) — always passes
```

2. **Tautological comparison** — both sides come from the same source:

```rust
// Bug: comparing a field to itself
let a = state.total_borrow;
let b = state.total_borrow;  // same field, same read
assert_eq!(a, b);  // always true, catches nothing
```

3. **Unreachable state** — flows never put the protocol into a state where the invariant is exercised:

```rust
// D1 only fires when raw_debt > 0, but no flow ever borrows
if tick.raw_debt > 0 {
    assert!(position.dust < tick.raw_debt);  // never reached
}
```

**How to test sensitivity — two approaches:**

**Approach A: Inject a known-false assertion (temporary, manual)**

```rust
// Temporarily add to end() — if this DOESN'T panic, the state read is broken
assert_eq!(vault_state.total_borrow, 999999, "E2 sensitivity check");
```

Remove after verifying. Quick but not durable.

**Approach B: Built-in sensitivity validation (permanent, automated)**

Add a sensitivity check that runs on the first iteration and verifies state reads return non-trivial values:

```rust
#[end]
fn end(&mut self) {
    // -- Sensitivity validation (first iteration only) --
    if self.iteration == 1 && self.success_count > 0 {
        let vs = self.trident.get_account_with_type::<VaultState>(&vs_pk, 8);
        assert!(vs.is_some(), "SENSITIVITY: vault_state read returned None");
        // After at least one successful deposit, total_supply should be > 0
        let vs = vs.unwrap();
        assert!(vs.total_supply > 0,
            "SENSITIVITY: total_supply is 0 after successful deposits — state read is broken");
    }

    // -- Actual invariants (every iteration) --
    // ...
}
```

This approach is permanent — it validates on every run that the invariant machinery is actually reading real state.

### The durability test

Classify each invariant by how long it remains useful:

| Durability | Description | Example | Action |
| ---------- | ----------- | ------- | ------ |
| **Permanent** | Always true regardless of protocol changes | `total_supply >= sum(user_positions)` | Keep forever |
| **Conditional** | True given current protocol design, may change | `dust_debt < raw_debt` (depends on rounding strategy) | Keep, but review on protocol upgrades |
| **Bug-specific** | Asserts presence of a known bug | `assert_eq!(post_liq_dust, pre_liq_dust)` for M-2 | Replace with general invariant when bug is fixed |
| **Temporal** | Only true at certain points in time | `exchange_price >= 1.0` (true at initialization, not after losses) | Gate on conditions or remove |

**Bug-specific invariants are useful for regression testing** but mark them clearly. When the bug is fixed, they'll fail — and that's correct behavior. Replace them with a general invariant that catches the same bug class.

### Quality scorecard

For each invariant in the table, score it:

| ID | Independence | Bypass exists? | Sensitivity verified? | Durability | Score |
| -- | ------------ | -------------- | --------------------- | ---------- | ----- |
| E2 | High (separate code paths) | Yes (stale accrual) | Yes | Permanent | Strong |
| T1 | Medium (CPI boundary) | Yes (CPI-consistent bugs) | Yes | Permanent | Moderate |
| C1 | High (bitmap vs debt field) | No known bypass | Yes | Permanent | Strong |
| D1 | High (position vs tick) | Yes (wrong tick source) | Yes | Conditional | Moderate |
| NT-1 | N/A (meta) | N/A | Yes | Permanent | Essential |

**Minimum quality bar:** Your campaign needs at least:

- 1 **Strong** invariant (high independence, no known bypass)
- Invariants at 2+ detection scopes (cross-protocol AND within-protocol)
- All invariants sensitivity-tested
- All known bypasses documented with complementary invariants or accepted risk

If all your invariants are Moderate or lower, you're likely missing bugs. Find a higher-independence comparison.

**STOP. Wait for user approval before Phase 3.**
