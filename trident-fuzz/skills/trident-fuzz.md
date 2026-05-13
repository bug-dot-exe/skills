---
name: trident-fuzz
description: Set up and write Trident fuzz tests for Solana/Anchor programs in 5 phases — setup, invariant mapping, test construction, validation, and result analysis.
trigger: When the user asks to fuzz, set up fuzz tests, write property-based tests for Solana programs, or references Trident/trident. Also triggered by /trident-fuzz or /fuzz.
---

# Trident Fuzz Testing Skill

**Current API version: Trident v0.12.0** — see `trident-api-v0.12.md` for method signatures. If Trident updates and APIs change, only that file needs replacing.

## What Trident Does

Trident is a **stateful fuzzer** for Solana programs. It runs programs inside a local BanksClient (no validator needed), randomly picks transaction "flows", and checks invariants after each iteration:

```text
iteration = init() -> [random flow1, flow2, ..., flowN] -> end()
                        ^ fuzzer picks randomly each time
```

## When Fuzzing Is Worth It (and When It's Not)

**High ROI:**
- Instructions where inputs are numeric ranges (amounts, percentages)
- Cross-program shared state (two protocols touching the same account)
- Operations that should be commutative/associative (order shouldn't matter)
- Post-event operations (after liquidation, after migration)

**Low ROI / architectural blockers:**
- Instructions where each input requires a unique pre-initialized PDA (e.g., borrow amount determines tick, tick is a PDA that must exist). Random inputs need random PDAs — impractical.
- Pure admin/config instructions with no user inputs
- Programs with no state persistence between transactions

**When you hit a low-ROI path:** Don't force it. Scope the campaign to what CAN be fuzzed effectively (e.g., deposit/withdraw only), and note the gap for manual audit.

## Guidance for First-Time Users

If this is your first time building a Trident fuzzing harness, read this before starting Phase 1.

### How to think about it

Fuzzing is NOT "throw random inputs and see what breaks." For Solana programs, fuzzing is:

1. **Build a valid protocol state** (the hard part — Phase 1 is 60% of the work)
2. **Define what "correct" means** (invariants — Phase 2)
3. **Let the fuzzer find paths to "incorrect"** (flows — Phase 3)

Most of your time will be spent on #1. On-chain programs have deep initialization chains — account A requires account B which requires account C. Getting this right takes iteration.

### What to expect

- **Phase 1 will take the longest.** You'll hit hidden prerequisites (rate model version gates, supply checks, duration bounds). Each one is a dead end that requires reading the on-chain validation code, understanding what it wants, and adding a setup step. This is normal.
- **Your first campaign will be narrow.** Don't try to fuzz everything. Start with deposit/withdraw on a single instruction. Get the setup working. Then expand.
- **Most flows will revert.** This is expected. The fuzzer throws random amounts — many will exceed balances, violate collateral factors, etc. A 40-60% success rate is ideal.
- **"No violations found" is the likely outcome.** Well-audited code rarely has bugs that random fuzzing catches. The value is in the confidence gained and the regression safety net, not in finding new bugs.
- **Some paths are architecturally unfuzzable.** When an instruction requires a PDA derived from the input value (e.g., borrow amount -> tick -> tick PDA), you can't practically fuzz with random inputs. Acknowledge the gap, cover it manually.

### The most common mistakes

1. **Putting everything in one file.** Leads to 1000+ line `test_fuzz.rs` that can't be reused. Use `common/` modules from the start.
2. **Not asserting setup success.** If init transactions fail silently, all flows revert, all invariants pass trivially, and you think the code is correct when nothing was tested.
3. **Only checking one invariant level.** Cross-protocol invariants miss within-protocol bugs. Within-protocol invariants miss cross-protocol corruption. You need both.
4. **Skipping the sensitivity test.** If you don't verify that your invariant CAN fail, you don't know if it's actually checking anything.
5. **Ignoring revert logs.** Revert logs tell you what the program rejected and why. Expected reverts (insufficient balance) are fine. Unexpected reverts (wrong account type) mean your setup is wrong.

## Phases

Execute in **5 sequential phases**. Complete each phase, present output to user, **wait for approval** before the next.

| Phase | Name | Goal | Reference |
| ----- | ---- | ---- | --------- |
| 1 | Setup & Account Graph | Map dependencies, generate scaffolding, write setup modules | `trident-phase-1-setup.md` |
| 2 | Invariant Mapping | Derive testable properties at multiple detection scopes | `trident-phase-2-invariants.md` |
| 3 | Test Construction | Write modular flows + invariant assertions | `trident-phase-3-construction.md` |
| 4 | Dry Run & Validation | Compile, run short campaign, verify flows execute | `trident-phase-4-validation.md` |
| 5 | Result Analysis & Iteration | Interpret output, assess coverage, decide next steps | `trident-phase-5-analysis.md` |

## When to stop or loop back

- **Phase 1 fails to compile** -> Fix setup. Do not move to Phase 2.
- **Phase 4 shows 0% flow success** -> Setup broken. Return to Phase 1.
- **Phase 4 shows 100% revert on specific flows** -> PDA seed mismatch or missing prerequisite. Debug in Phase 4, fix in Phase 1.
- **Phase 5 coverage gaps are significant** -> Design a new campaign (new `fuzz_N/`) targeting the gap. Restart from Phase 1, reuse setup modules.

## Modular file structure

**Do not put everything in `test_fuzz.rs`.** Split into reusable modules:

```text
trident-tests/
  Cargo.toml
  Trident.toml
  common/              <-- shared across campaigns
    mod.rs
    setup.rs           <-- reusable init functions (create_mints, init_oracle, etc.)
    instructions.rs    <-- instruction builders (do_operate, do_deposit, etc.)
    invariants.rs      <-- assertion functions (check_accounting, check_bitmap, etc.)
    constants.rs       <-- program IDs, VAULT_ID, MIN_TICK, etc.
  fuzz_0/
    test_fuzz.rs       <-- FuzzTest struct + #[flow] + #[end] only
    fuzz_accounts.rs
    types.rs           <-- auto-generated
  fuzz_1/
    test_fuzz.rs       <-- different flows, different invariants, reuses common/
    fuzz_accounts.rs
    types.rs           <-- auto-generated
```

This way:
- **Campaign 2 reuses 80% of Campaign 1's setup** — just `use common::setup::*`
- **Instruction builders are tested once, used everywhere**
- **Invariants can be mixed and matched** per campaign
- **`test_fuzz.rs` stays small** (~200 lines of flows + glue)

## Progressive Invariant Fuzzing

This methodology is **invariant-driven stateful fuzzing** — not traditional crash fuzzing. The goal is not "find crashes" but "prove that defined properties hold across all reachable states." Each campaign stage's blind spots inform the next stage's design.

### Refinement loop

```text
Campaign N passes
    |
    v
Ask: "What can this campaign NOT catch?"
    |
    v
Identify the blind spot category
    |
    v
Design Campaign N+1 to target that blind spot
    |
    v
Reuse common/ modules, add new flows + invariants
```

### Four stages of progressive invariant fuzzing

| Stage | Name | Scope | Invariants | Catches | Misses |
| ----- | ---- | ----- | ---------- | ------- | ------ |
| 1 | **Foundation** (unit-level) | Single program, random deposit/withdraw, 1000+ iterations | Within-protocol accounting (debt ledger, bitmap sync, dust bounds) | Basic state inconsistencies from random operation ordering | Cross-program corruption, adversarial transitions |
| 2 | **Integration** (cross-boundary) | Cross-program CPI, interleaved multi-protocol flows | Cross-protocol conservation (layer totals >= protocol positions) + within-protocol | Shared state corruption between programs | Within-protocol bugs where both CPI sides record same wrong number |
| 3 | **Scenario** (adversarial) | Targeted code paths — oracle crash, liquidation, post-event operations | Bug-specific assertions + general invariants at all scopes | Specific edge cases, regressions for known findings | Paths not in the adversarial scenario, time-dependent bugs |
| 4 | **Temporal** (time-dependent) | Same as Integration + `forward_in_time` between operations | Exchange price drift, interest accrual, rate model correctness | Time-dependent accounting bugs | Still misses dynamic-PDA paths |

### How each stage informs the next

**Foundation -> Integration:** Foundation shows within-protocol invariants hold. But you realize: "If vault and lending both touch the same TokenReserve, a bug in one could corrupt the other's view." This motivates cross-protocol invariants.

**Integration -> Scenario:** Integration shows cross-protocol invariants hold under normal operations. But you realize two things: (1) "Liquidation is the most complex state transition — what if it corrupts shared state?" and (2) "Cross-protocol invariants can't catch within-protocol bugs where both CPI sides agree on the wrong number." This motivates adversarial flows and deeper within-protocol assertions.

**Scenario -> Temporal:** Scenario validates liquidation paths. But you realize: "All operations happen at t=0. Interest accrual changes exchange prices over time, which affects collateral ratios, withdrawal limits, and debt amounts." This motivates time-advancement flows.

### The key question at each stage

After each campaign passes, ask: **"If there were a bug in each of these categories, would this campaign have caught it?"**

- **Accounting bug:** `total_borrow` incremented but `tick.raw_debt` not. Caught by Foundation (E2).
- **Cross-protocol bug:** Vault deposit subtracts from lending's bucket. Caught by Integration (T1/T2).
- **CPI-consistent bug:** Vault computes wrong repayment, CPIs the same wrong amount. NOT caught by Integration — both sides agree. Needs Scenario with within-protocol assertions.
- **Time-dependent bug:** Cached exchange price goes stale, position becomes liquidatable undetected. NOT caught without Temporal flows.

If you can think of a realistic bug your campaign would miss, that's your next campaign.

## When Is a Fuzz Campaign Sufficient?

Sufficiency is not about iteration count. It's about being able to articulate what was tested and what wasn't.

### Sufficiency checklist

Run through this after Phase 5. All items checked = sufficient for its scope.

**Coverage:**

- [ ] Every instruction in scope has at least one flow exercising it
- [ ] Both success and revert paths are exercised (20-80% success rate)
- [ ] Cross-protocol flows interleave (if applicable)
- [ ] Adversarial state transitions are exercised (if applicable)

**Invariant quality:**

- [ ] Invariants exist at multiple detection scopes (cross-protocol AND within-protocol)
- [ ] Each invariant has been sensitivity-tested (verified it CAN fail)
- [ ] Non-triviality guards confirm meaningful state was reached
- [ ] No invariant is trivially true (both sides always 0, or both sides from same source)

**Iteration depth:**

- [ ] Enough iterations that rare flow combinations are explored (1000+ for Foundation, 200+ for Scenario)
- [ ] Multiple flows succeed per iteration (not just 1 deposit then 99 reverts)

**Gap documentation:**

- [ ] Coverage matrix explicitly lists what was NOT tested
- [ ] Each gap has a risk assessment (high / medium / low)
- [ ] High-risk gaps have a documented alternative (manual audit, next campaign, or accepted risk)

**Reproducibility:**

- [ ] Seed and commands documented for re-running
- [ ] Setup is deterministic (same seed = same result)

### What "sufficient" does NOT mean

- **Not "100% code coverage."** Trident is not coverage-guided. It explores state space through random flow combinations, not code paths.
- **Not "found a bug."** Most well-audited code won't yield bugs from random fuzzing. The value is confidence + regression safety.
- **Not "ran for N hours."** 100 iterations with good coverage beats 100,000 iterations of meaningless execution where all flows revert.
- **Not "tested every instruction."** Some instructions are architecturally unfuzzable (dynamic PDA problem). Acknowledge and cover manually.

### The honest assessment

At the end of your fuzzing work, you should be able to write:

> "We executed N iterations with M total flows across K campaigns (Foundation / Integration / Scenario / Temporal). Our invariants verified [accounting consistency / cross-protocol conservation / bitmap sync] at [within-protocol / cross-protocol / token-balance] levels. Flow success rates ranged from X-Y%. The following areas were NOT covered: [list]. These gaps are covered by [manual audit / accepted risk]."

If you can't write this statement, your fuzzing work is not yet sufficient.
