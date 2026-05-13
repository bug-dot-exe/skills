# Trident Fuzz Skill for Claude Code

A [Claude Code](https://docs.anthropic.com/en/docs/claude-code) skill that guides you through setting up **invariant-driven stateful fuzz tests** for Solana/Anchor programs using [Trident v0.12.0](https://github.com/Ackee-Blockchain/trident).

## What This Is

This skill teaches Claude Code how to build Trident fuzz harnesses in 5 sequential phases:

| Phase | File | What It Does |
|-------|------|-------------|
| 1 | `trident-phase-1-setup.md` | Map account dependencies, generate scaffolding, write setup modules |
| 2 | `trident-phase-2-invariants.md` | Derive testable invariants at multiple detection scopes |
| 3 | `trident-phase-3-construction.md` | Write modular flows + invariant assertions |
| 4 | `trident-phase-4-validation.md` | Compile, run short campaign, verify flows execute |
| 5 | `trident-phase-5-analysis.md` | Interpret output, assess coverage, decide next steps |

Plus:
- `trident-fuzz.md` — Entry point with overview, progressive methodology, and sufficiency checklist
- `trident-api-v0.12.md` — Version-dependent API reference (swap this file when Trident updates)

## What This Is NOT

- Not a crash fuzzer — it's **invariant-driven stateful fuzzing** that proves properties hold across all reachable states
- Not a one-click tool — building valid protocol state is the hard part (Phase 1 is 60% of the work)
- Not a replacement for manual audit — it catches regressions and edge cases that audit might miss

## Installation

Copy the skill files into your project's `.claude/skills/` directory:

```bash
# From your project root
mkdir -p .claude/skills
cp path/to/trident-fuzz-skill/skills/*.md .claude/skills/
```

Or symlink them:

```bash
ln -s path/to/trident-fuzz-skill/skills/*.md .claude/skills/
```

## Usage

In Claude Code, trigger the skill with:

```
/fuzz
```

Or ask naturally:

```
"Set up fuzz tests for the vault program"
"Write a Trident fuzzing harness targeting the deposit/withdraw instructions"
```

Claude will walk through each phase, presenting output and waiting for approval before proceeding.

## Prerequisites

- [Trident v0.12.0](https://github.com/Ackee-Blockchain/trident) installed (`cargo install trident-cli`)
- An Anchor project with `anchor build` completing successfully
- (Optional) An invariant table from a prior audit — Phase 2 can consume it directly or derive invariants from code

### Invariant Table Format

If you have a prior audit, the skill works best when given an invariant table in this format:

```markdown
| # | Invariant | Derived From | Fuzzable? | State Reads Needed | Detection Scope |
|---|-----------|-------------|-----------|-------------------|-----------------|
| 1 | total_borrow == sum(tick.raw_debt) | Accounting identity | Yes | VaultState, Tick | within-protocol |
```

## Methodology: Progressive Invariant Fuzzing

The skill teaches a 4-stage progressive refinement methodology:

| Stage | Name | What It Tests | What It Misses |
|-------|------|--------------|----------------|
| 1 | **Foundation** | Single-program accounting with random operations | Cross-program corruption |
| 2 | **Integration** | Cross-program CPI with interleaved flows | CPI-consistent bugs (both sides record same wrong number) |
| 3 | **Scenario** | Adversarial state transitions (liquidation, oracle crash) | Time-dependent bugs |
| 4 | **Temporal** | Time advancement + interest accrual | Dynamic-PDA paths |

Each stage's blind spots inform the next stage's design.

## File Structure for Fuzz Tests

The skill teaches a modular test structure:

```
trident-tests/
  common/              # shared across campaigns
    mod.rs
    setup.rs           # reusable init functions
    instructions.rs    # instruction builders
    invariants.rs      # assertion functions
    constants.rs       # program IDs, config values
  fuzz_0/
    test_fuzz.rs       # FuzzTest struct + #[flow] + #[end] only
    fuzz_accounts.rs
    types.rs           # auto-generated
  fuzz_1/              # different campaign, reuses common/
    test_fuzz.rs
    ...
```

## Updating for New Trident Versions

When Trident releases a new version, only `trident-api-v0.12.md` needs updating. The phase files describe the workflow and are version-independent.

## License

MIT
