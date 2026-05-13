---
name: trident-phase-5-analysis
description: "Phase 5 of Trident fuzzing: interpret results, assess coverage, classify findings, decide whether to iterate or finalize."
type: reference
---

# Phase 5: Result Analysis & Iteration

**GOAL:** Interpret the fuzzing output, assess what was actually tested vs what was missed, and decide whether to refine, expand, or finalize.

---

## Step 5.1 — Interpret the results

### Case A: No violations found

"No violations" is only meaningful if the test exercised interesting state. Evaluate:

**1. Flow success rates** — from `eprintln!` output:

| Rate | Assessment |
| ---- | ---------- |
| 40-60% success | Ideal — both success and revert paths exercised |
| 80-100% success | Fine — mostly happy path, edge cases may be under-explored |
| 1-10% success | Weak — almost nothing was tested. Constrain input ranges. |
| 0% success | Invalid — setup broken. Return to Phase 1. |

**2. Cross-protocol interleaving** — if you have vault + lending flows, BOTH should show nonzero success counts. If only one protocol's flows succeed, shared state isn't being tested.

**3. Adversarial flows fired** — liquidation, oracle crashes. Check one-shot flow counters.

**4. State non-triviality** — if all state values are 0 at the end of every iteration, invariants passed because nothing happened.

### Case B: Invariant violation found

**Triage process:**

```text
Violation found
  |
  |-- Is the invariant correct?
  |     |-- Review Phase 2 logic. Does it account for rounding/edge cases?
  |     |-- No -> Fix invariant, re-run
  |     |-- Yes ->
  |
  |-- Reproduce with fixed seed:
  |     TRIDENT_FUZZ_DEBUG=<seed> ./target/debug/fuzz_0 2>&1
  |
  |-- First iteration?
  |     |-- Yes -> Likely setup artifact. Check init() ordering.
  |     |-- No -> State-dependent. Walk through transitions.
  |
  |-- Walk through state:
  |     1. What state before the violating flow?
  |     2. Which flow triggered it?
  |     3. What state change broke the invariant?
  |     4. Is this a legitimate protocol state?
  |
  |-- Classification:
  |     |-- Cross-protocol -> High severity. Shared state corruption.
  |     |-- Within-protocol -> Assess fund loss potential.
  |     |-- Rounding/dust -> Often acceptable. Check magnitude.
```

**Important lesson from experience:** Cross-protocol invariants (T1/T2/B1) will NOT catch within-protocol bugs where both sides of a CPI record the same wrong number. Example: stale dust causes wrong repayment amount, but both vault and liquidity layer record the same wrong CPI amount consistently — cross-protocol invariants hold, the bug is invisible. You need **within-protocol invariants** to catch these.

### Case C: Panic (not assertion failure)

| Panic | Likely cause | Is it a finding? |
| ----- | ------------ | ---------------- |
| `range end index N out of range` | Wrong remaining_accounts count | Setup bug |
| `AccountLoaderMissingAccountLoader` | Uninitialized AccountLoader account | Setup bug |
| `overflow` / `underflow` | Math error in on-chain code | **Likely real bug** |
| `InvalidAccountData` | Wrong account type or corrupted state | Investigate |

**Math panics are often real bugs.** Reproduce and investigate before dismissing.

## Step 5.2 — Assess coverage

Build a coverage matrix:

| Area | Tested? | How | Gap risk |
| ---- | ------- | --- | -------- |
| Vault deposit/withdraw | Yes | Random flows | Low |
| Vault borrow (dynamic) | No | Dynamic PDA problem | **High** — manual audit |
| Lending deposit/withdraw | Yes | Random flows | Low |
| Cross-protocol shared state | Yes | Interleaved flows | Low |
| Liquidation (absorb) | Yes | One-shot flow | Medium |
| Interest accrual | No | No `forward_in_time` | **High** |
| Rebalance | No | Not in flow set | Medium |
| Multi-user same tick | No | All positions at different ticks | Medium |

### Coverage quality levels

| Level | Criteria |
| ----- | -------- |
| **Strong** | Random inputs + random ordering + >10K flows + cross-protocol invariants |
| **Moderate** | Fixed setup inputs + random ordering + >1K flows + within-protocol invariants |
| **Weak** | Only happy path, low iterations, or high revert rate |
| **False confidence** | 0% success, invariants pass trivially |

## Step 5.3 — Assess invariant strength

For each invariant that held, ask: **is it strong enough?**

| Sign of weak invariant | What to do |
| ---------------------- | ---------- |
| Both sides are always 0 | The state is never reached. Add flows that reach it. |
| Both sides are always equal because they're set from the same source | The invariant is tautological. Find an independent check. |
| Invariant only checks `>=` but should check `==` | Tighten to exact equality where possible. |
| Invariant passes even when you manually corrupt state | The state read is wrong (wrong pubkey, wrong offset). |

**Bug-specific vs general invariants:** If you added an assertion that detects a known bug's presence (e.g., `assert_eq!(dust, stale_value)` to confirm M-2), mark it clearly. These will break when the bug is fixed and should be replaced with a general invariant (e.g., "dust matches current tick's computed dust").

## Step 5.4 — Decide next steps

### Option A: Finalize — coverage is sufficient

Produce a final report:

```markdown
# Fuzz Testing Report

## Campaigns
| Campaign | Scope | Iterations x Flows | Result |
| -------- | ----- | ------------------ | ------ |
| fuzz_0 | Vault deposit/withdraw | 1000 x 100 | No violations |
| fuzz_1 | Cross-protocol + liquidation | 200 x 50 | No violations |

## Invariants
| ID | Invariant | Scope | Result |
| -- | --------- | ----- | ------ |
| E2 | total_borrow == raw_debt | Within-protocol | Held |
| T1 | TR.with_interest >= lending_pos | Cross-protocol | Held |

## Implicit Invariants (verified by tx success)
| Property | How verified |
| -------- | ----------- |
| Tick computation correct | operate() succeeds |
| PDA seeds match | All instructions succeed |

## Coverage Matrix
(from Step 5.2)

## Limitations
(High-risk gaps from coverage matrix)

## Reproducing
cd trident-tests && cargo run --bin fuzz_0
```

### Option B: Expand — significant gaps remain

Design a new campaign targeting gaps. Create `fuzz_N+1/` and restart Phase 1, reusing `common/` modules.

**Progressive expansion:**

| Gap | New campaign focus |
| --- | ------------------ |
| Interest accrual | Add `forward_in_time` flow, check exchange price drift |
| Multi-user same tick | Add second position at same tick, check contention |
| Dynamic borrow | Pre-initialize tick range, constrain random amounts |
| Multi-round liquidation | Add second oracle crash flow after first liquidation |

### Option C: Finding confirmed — document

1. Reproduce with fixed seed
2. Trace state transitions
3. Document: root cause, reproduction steps, impact, suggested fix
4. Add regression invariant (general, not bug-specific)

## Step 5.5 — Document lessons learned

After each campaign, note for future reference:

- What broke during setup and the fix (feeds Phase 1 gotcha table)
- Which invariants were trivially true and need strengthening
- Which flows had 100% revert rate and why
- Architectural constraints that prevented testing (e.g., dynamic PDA problem)
- What the optimal input ranges were (too large = all reverts, too small = no edge cases)

These lessons improve future campaigns on this AND other projects.

**Present the final report and coverage assessment to the user.**
