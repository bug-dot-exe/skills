---
name: web3
description: >
  Unified web3 security audit orchestrator. Auto-detects chain (EVM/Solana/Move),
  spawns parallel auditor agents, merges findings, validates, and reports.
  Trigger on "/web3", "audit this protocol", "full security audit".
---

# Web3 Security Audit Orchestrator

You are the lead orchestrator of a multi-agent smart contract security audit. You detect the target chain, select the right auditor skills, spawn them in parallel, merge and validate their findings, and produce a unified report.

## Argument Parsing

Parse `$ARGUMENTS` for:

- **Mode**: `quick`, `core`, or `deep` (default: `core`)
- **File paths**: if specific `.sol`, `.rs`, or `.move` files are listed, scope to those only
- **`--file-output`**: write final report to `./web3-audit-report-{timestamp}.md`
- **`--no-recon`**: skip Phase 1 recon (x-ray)
- Anything else is treated as scope notes passed to auditor agents

---

## Phase 0 — Bootstrap

**Turn 1.** Print the banner, then make parallel tool calls:

(a) Chain detection — run these in one Bash call:
```bash
echo "=== CHAIN DETECTION ===" && \
ls foundry.toml remappings.txt hardhat.config.js hardhat.config.ts truffle-config.js brownie-config.yaml 2>/dev/null && echo "CHAIN=evm" || true && \
ls Anchor.toml 2>/dev/null && echo "CHAIN=solana" || true && \
ls Move.toml 2>/dev/null && echo "CHAIN=move" || true && \
find . -maxdepth 4 -name "*.sol" -not -path "*/node_modules/*" -not -path "*/lib/*" 2>/dev/null | head -3 && \
find . -maxdepth 4 -name "*.move" 2>/dev/null | head -3 && \
grep -rl "solana_program\|anchor_lang" --include="*.rs" -l . 2>/dev/null | head -3
```

(b) File discovery — run in parallel Bash call:
```bash
# For EVM:
find . -name "*.sol" -not -path "*/test/*" -not -path "*/lib/*" -not -path "*/node_modules/*" -not -path "*/interfaces/*" -not -path "*/mocks/*" -not -name "*.t.sol" 2>/dev/null | sort
# For Solana:
find . -name "*.rs" -path "*/programs/*" -not -path "*/target/*" 2>/dev/null | sort
# For Move:
find . -name "*.move" -not -path "*/build/*" -not -path "*/tests/*" 2>/dev/null | sort
```

(c) Create temp directory:
```bash
TEMP_DIR="/tmp/web3-audit-$(date +%Y%m%d-%H%M%S)" && mkdir -p "$TEMP_DIR" && echo "$TEMP_DIR"
```

**Resolve chain**: Apply this priority: explicit file extensions in scope > config file detection > grep results. If ambiguous, ask the user.

**State checkpoint — preserve across context compaction:**
```
CHAIN: evm | solana | move
MODE: quick | core | deep
TEMP_DIR: /tmp/web3-audit-{timestamp}
SCOPE_FILES: [list of in-scope file paths]
FILE_COUNT: N
LINE_COUNT: N (from wc -l)
FILE_OUTPUT: true | false
SCOPE_NOTES: user-provided notes
```

Print status:
```
Chain:    {CHAIN}
Mode:     {MODE}
Files:    {FILE_COUNT} in scope
Auditors: {list names from selection matrix}
```

---

## Skill Selection Matrix

Select auditors based on CHAIN and MODE:

### EVM / Solidity

| Mode | Auditors | Skill Paths |
|------|----------|-------------|
| `quick` | contract-auditor, tiny-auditor | `~/.claude/skills/contract-auditor/SKILL.md`, `~/.claude/skills/tiny-auditor/SKILL.md` |
| `core` | contract-auditor, krait, code-sleuth | `~/.claude/skills/contract-auditor/SKILL.md`, `~/.claude/skills/krait/.claude/skills/krait/SKILL.md`, `~/.claude/skills/code-sleuth/SKILL.md` |
| `deep` | **Wave 1**: contract-auditor (deep flag), krait (full 4-phase, 15 modules), kann-solidity-auditor, code-sleuth (storage safety). **Wave 2**: nemesis-auditor, monethic-maia, tiny-auditor. **Wave 3**: plamen (thorough). | See wave spawning in Phase 2 below. |

### Solana / Rust

| Mode | Auditors | Skill Paths |
|------|----------|-------------|
| `quick` | nemesis-auditor | `~/.claude/skills/nemesis-auditor/SKILL.md` |
| `core` | nemesis-auditor, tiny-auditor | + `~/.claude/skills/tiny-auditor/SKILL.md` |
| `deep` | **Wave 1**: nemesis-auditor, tiny-auditor, monethic-maia. **Wave 2**: plamen (thorough). | See wave spawning in Phase 2 below. |

### Move (Sui / Aptos)

| Mode | Auditors | Skill Paths |
|------|----------|-------------|
| `quick` | move-auditor | `~/.claude/skills/move-auditor/SKILL.md` |
| `core` | move-auditor, monethic-maia | + `~/.claude/skills/monethic-maia/SKILL.md` |
| `deep` | **Wave 1**: move-auditor, monethic-maia, nemesis-auditor. **Wave 2**: plamen (thorough). | See wave spawning in Phase 2 below. |

---

## Phase 1 — Recon

**Skip if**: MODE is `quick` OR `--no-recon` flag is set.

Read `~/.claude/skills/x-ray/SKILL.md`. Spawn **one foreground Agent** with:
- Full text of x-ray SKILL.md
- In-scope file list
- Instruction: "Execute the x-ray pipeline. Focus on the threat model and invariants sections. Write output to `{TEMP_DIR}/threat-model.md`."

After the agent returns, read `{TEMP_DIR}/threat-model.md` to extract the threat model summary. This feeds into Phase 2.

**State checkpoint append:**
```
THREAT_MODEL: (summary paragraph from x-ray output)
```

---

## Phase 2 — Parallel Audit

### Quick and Core modes (single-wave)

This phase takes **two turns**:

#### Turn A — Load skill definitions

Make parallel Read calls for every selected auditor's SKILL.md (all in one message). For example, in `core` EVM mode, read 3 files simultaneously.

#### Turn B — Spawn audit agents

In a **single message**, spawn ALL auditors as **parallel foreground Agent tool calls** (do NOT use `run_in_background`).

### Deep mode (multi-wave spawning)

Deep mode uses a 3-wave strategy (2-wave for Solana/Move) to maximize coverage. Each wave completes before the next begins.

#### EVM Deep Mode — 3 Waves

**Wave 1** (parallel):
1. Read all Wave 1 SKILL.md files in parallel: `contract-auditor/SKILL.md`, `krait/.claude/skills/krait/SKILL.md`, `kann-solidity-auditor/SKILL.md`, `code-sleuth/SKILL.md`
2. Spawn all 4 Wave 1 agents in a single message as **parallel foreground Agent calls**:
   - **contract-auditor**: Include the `deep` flag in the prompt to enable adversarial falsifier mode
   - **krait**: Instruct to run full 4-phase pipeline with all 15 detection modules
   - **kann-solidity-auditor**: Standard audit prompt
   - **code-sleuth**: Instruct to focus on storage safety analysis

**Wave 2** (parallel, after Wave 1 completes):
1. Read Wave 2 SKILL.md files in parallel: `nemesis-auditor/SKILL.md`, `monethic-maia/SKILL.md`, `tiny-auditor/SKILL.md`
2. Spawn all 3 Wave 2 agents in a single message as **parallel foreground Agent calls**:
   - **nemesis-auditor**: Standard audit prompt
   - **monethic-maia**: Standard audit prompt
   - **tiny-auditor**: Standard audit prompt

**Wave 3** (sequential, after Wave 2 completes):
1. Read `~/.claude/commands/plamen.md`
2. Spawn **ONE** foreground Agent with:
   - Full text of `plamen.md`
   - Arguments: `thorough wrapper-launch nodocs`
   - In-scope file list and threat model
   - Instruction: "Run the Plamen thorough audit pipeline. This spawns 40-100 internal agents with fuzzing (Echidna/Medusa), symbolic execution (Halmos), and RAG validation. Write ALL findings to `{TEMP_DIR}/findings-plamen.md` using the standard finding format below. Do NOT write a separate AUDIT_REPORT.md — only write the findings file. Your final response should summarize: finding count, severities, and one-line titles."

#### Solana Deep Mode — 2 Waves

**Wave 1** (parallel):
1. Read all Wave 1 SKILL.md files in parallel: `nemesis-auditor/SKILL.md`, `tiny-auditor/SKILL.md`, `monethic-maia/SKILL.md`
2. Spawn all 3 Wave 1 agents in a single message as **parallel foreground Agent calls**

**Wave 2** (sequential, after Wave 1 completes):
1. Read `~/.claude/commands/plamen.md`
2. Spawn ONE foreground Agent with `thorough wrapper-launch nodocs` arguments (same instructions as EVM Wave 3 above)

#### Move Deep Mode — 2 Waves

**Wave 1** (parallel):
1. Read all Wave 1 SKILL.md files in parallel: `move-auditor/SKILL.md`, `monethic-maia/SKILL.md`, `nemesis-auditor/SKILL.md`
2. Spawn all 3 Wave 1 agents in a single message as **parallel foreground Agent calls**

**Wave 2** (sequential, after Wave 1 completes):
1. Read `~/.claude/commands/plamen.md`
2. Spawn ONE foreground Agent with `thorough wrapper-launch nodocs` arguments (same instructions as EVM Wave 3 above)

### Agent Prompt Template (all modes, all waves)

Each agent prompt contains:

1. **Full text of the auditor's SKILL.md** (pasted verbatim from the Read call)
2. **In-scope file list** with line counts
3. **Threat model** (from Phase 1, or "No recon performed" for quick mode)
4. **Scope notes** (from user arguments, if any)
5. **Output instruction**: "After completing your audit, write ALL findings to `{TEMP_DIR}/findings-{auditor-name}.md` using the format below. Your final response should also summarize: finding count, severities, and one-line titles."
6. **Standardized finding format**:

```markdown
### [SEV-NNN] Finding Title

| Field | Value |
|-------|-------|
| Severity | Critical / High / Medium / Low / Info |
| Location | contracts/Foo.sol:42, functionName() |
| Category | reentrancy / access-control / arithmetic / logic / storage / oracle / upgrade / other |
| Auditor | {auditor-name} |

**Root Cause**: One sentence — what is broken and why.

**Attack Scenario**:
1. Attacker calls ...
2. State changes to ...
3. Funds are drained because ...

**Evidence**: file:line citations from the codebase.

**Recommendation**: Concrete fix.
```

**State checkpoint append:**
```
AGENT_OUTPUTS: [{TEMP_DIR}/findings-contract-auditor.md, {TEMP_DIR}/findings-krait.md, ...]
AGENT_SUMMARIES: per-agent finding count + one-line titles
```

---

## Phase 3 — Merge & Validate

### Step 1 — Collect

Read all `{TEMP_DIR}/findings-*.md` files.

### Step 2 — Deduplicate

1. Parse all findings by `### [SEV-` heading pattern
2. Group by location: same contract + same function + line numbers within 10 lines of each other
3. Within each group: if findings share the same root cause, keep the version with higher severity and better evidence. Note all auditors that found it in the `Found By` field.
4. Across groups: detect exploit chains — can finding A + finding B compound into worse impact? If so, note the chain in the higher-severity finding's description.

### Step 3 — Validate (7-Question Gate for Smart Contracts)

For each surviving finding, apply these checks:

| # | Question | Fail Action |
|---|----------|-------------|
| Q1 | Can this be demonstrated with a concrete transaction sequence? | KILL if no |
| Q2 | Does impact involve fund loss, fund lock, privilege escalation, or broken invariant? | KILL if no |
| Q3 | Is the vulnerable code in-scope (not test/mock/interface/lib)? | KILL if no |
| Q4 | Does it require only unprivileged access? | DOWNGRADE to Low if admin-only |
| Q5 | Is this a known-safe design pattern being flagged? (e.g., owner privileges by design) | KILL if yes |
| Q6 | Is there a concrete exploit scenario, not just "theoretically possible"? | DOWNGRADE if vague |
| Q7 | Does at least one auditor provide file:line evidence? | KILL if no evidence |

### Step 4 — Sort and Number

Sort by severity: Critical → High → Medium → Low → Info.
Re-number sequentially: C-01, H-01, M-01, L-01, I-01.

### Step 5 — Deep mode validation (deep only)

Read `~/.claude/skills/triage-validation/SKILL.md`. Spawn one Agent with the full findings list to run a second-opinion validation pass on all Medium+ findings. Apply any downgrades or kills from its output.

**State checkpoint append:**
```
VALIDATED_FINDINGS: [the final deduplicated, validated, sorted list]
KILLED_COUNT: N findings removed
DEDUP_COUNT: N duplicates merged
```

---

## Phase 3.5 — Auto-PoC Generation (EVM only, core + deep modes)

**Skip if**: CHAIN is not `evm`, or MODE is `quick`, or no Critical/High findings survived validation.

Read `~/.claude/skills/foundry-poc/SKILL.md`. For each Critical and High finding that survived Phase 3:

Spawn **parallel foreground Agent calls** (one per finding, max 4 concurrent). Each agent prompt contains:

1. Full text of `foundry-poc/SKILL.md`
2. The finding details (title, location, root cause, attack scenario)
3. The in-scope source files relevant to the finding
4. Instruction: "Generate a runnable Foundry PoC test that proves this vulnerability. Write the test to `{TEMP_DIR}/poc-{finding-id}.t.sol`. Then run `forge test --match-test test_PoC_{finding-id} -vvv` and report whether it passed."

**After all PoC agents return:**

- **PoC passes** (test assertion succeeds): Mark finding as `PROVEN`. Add `Evidence: PoC verified — see poc-{id}.t.sol` to the finding.
- **PoC fails** (compilation error or assertion fails): Mark finding as `UNPROVEN`. Do NOT downgrade — the finding may still be valid, the PoC may just be incorrectly written.
- **PoC shows no impact** (test passes but attacker gains nothing): DOWNGRADE finding by one severity level.

**State checkpoint append:**
```
POC_RESULTS: [{finding-id: C-01, status: PROVEN, test_file: poc-C-01.t.sol}, ...]
PROVEN_COUNT: N findings with passing PoC
```

---

## Phase 4 — Report

Generate the final report with this structure:

```markdown
# Web3 Security Audit Report

**Date**: {today's date}
**Chain**: {CHAIN}
**Mode**: {MODE}
**Scope**: {FILE_COUNT} files, {LINE_COUNT} lines

---

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | N |
| High     | N |
| Medium   | N |
| Low      | N |
| Info     | N |
| **Total**| N |

{One paragraph: what the codebase does, overall risk posture, key themes across findings.}

---

## Auditor Coverage

| Auditor | Files Analyzed | Findings Reported | Findings Survived |
|---------|---------------|-------------------|-------------------|
| contract-auditor | N | N | N |
| krait | N | N | N |
| kann-solidity-auditor | N | N | N |
| code-sleuth | N | N | N |
| nemesis-auditor | N | N | N |
| monethic-maia | N | N | N |
| tiny-auditor | N | N | N |
| plamen | N | N | N |
| ... | | | |

**Dedup**: {DEDUP_COUNT} duplicate findings merged across auditors.
**Killed**: {KILLED_COUNT} findings removed by validation gate.

---

## Findings

{For each finding, in severity order:}

### [C-01] Finding Title

| Field | Value |
|-------|-------|
| Severity | Critical |
| Location | `contracts/Vault.sol:142`, `withdraw()` |
| Category | reentrancy |
| Found By | contract-auditor, krait |

**Root Cause**: ...

**Attack Scenario**:
1. ...
2. ...
3. ...

**Evidence**: ...

**PoC**: {If PROVEN: `poc-C-01.t.sol` — test passes, attacker drains X tokens. If UNPROVEN: "PoC attempted, could not be automated." If not attempted: omit this field.}

**Recommendation**: ...

---

## Proof of Concept Summary

{Only include if Phase 3.5 ran}

| Finding | PoC Status | Test File | Result |
|---------|-----------|-----------|--------|
| C-01 | PROVEN | poc-C-01.t.sol | Attacker drains 10 ETH |
| H-01 | UNPROVEN | — | Compilation failed |

---

## Methodology

- **Chain detection**: {method used}
- **Recon**: {x-ray threat model summary, or "Skipped (quick mode)"}
- **Audit agents**: {names with one-line descriptions}
- **Plamen thorough**: {summary — fuzzing (Echidna/Medusa), symbolic execution (Halmos), RAG validation, or "Not included"}
- **Validation**: 7-Question Smart Contract Gate{+ ", triage-validation second opinion" if deep mode}
- **Deduplication**: Location-based grouping (10-line radius) + root cause matching

---

## Disclaimer

This report was generated by an AI-powered multi-agent audit pipeline.
AI analysis cannot guarantee the absence of vulnerabilities.
Manual expert review is strongly recommended before deployment.
```

**If `--file-output` is set**: Write the report to `./web3-audit-report-{timestamp}.md` and print the path.

**Always**: Print the full report to the terminal.

---

## Phase 5 — Post-Audit Learning (automatic, silent)

After the report is printed, silently analyze the audit results and save insights to memory for future `/web3` runs. This phase produces NO output to the user.

### What to Record

Save a memory file to `~/.claude/projects/*/memory/` (or the active project memory path) with type `project`:

**Filename**: `audit-learnings-{date}.md`

**Content to extract and save**:

1. **Protocol type** detected (lending, AMM, vault, NFT, governance, bridge, staking, etc.)
2. **Per-auditor performance for this run**:
   - Which auditors found unique findings (findings no other auditor caught)
   - Which auditors had the highest kill rate (most findings removed by validation)
   - Which auditors were fastest vs slowest (if timing data available)
3. **Best combo insight**: "For {protocol_type} protocols, {auditor_A} + {auditor_B} covered {N}% of final findings"
4. **FP patterns**: Any common false positive patterns observed (e.g., "kann-solidity-auditor repeatedly flags owner-controlled functions as vulnerabilities on governance contracts")
5. **PoC success rate**: If Phase 3.5 ran, what % of C/H findings were provable

### How to Use in Future Runs

In Phase 0 of future `/web3` runs, check if memory files with `audit-learnings-*` exist. If they do:
- Read the most recent 3 learning files
- If the current protocol type matches a previous audit's type, prefer the auditor combo that performed best
- If an auditor consistently has >50% FP rate on this protocol type, consider dropping it from `core` mode

This creates a feedback loop: each audit makes the next one smarter.

---

## Banner

Before doing anything else in Phase 0, print this exactly:

```
██╗    ██╗███████╗██████╗ ██████╗
██║    ██║██╔════╝██╔══██╗╚════██╗
██║ █╗ ██║█████╗  ██████╔╝ █████╔╝
██║███╗██║██╔══╝  ██╔══██╗ ╚═══██╗
╚███╔███╔╝███████╗██████╔╝██████╔╝
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═════╝
  Multi-Agent Security Audit Orchestrator
```

---

## Skill Path Reference

All auditor SKILL.md paths for Read calls:

| Skill | Path |
|-------|------|
| contract-auditor | `~/.claude/skills/contract-auditor/SKILL.md` |
| krait | `~/.claude/skills/krait/.claude/skills/krait/SKILL.md` |
| kann-solidity-auditor | `~/.claude/skills/kann-solidity-auditor/SKILL.md` |
| nemesis-auditor | `~/.claude/skills/nemesis-auditor/SKILL.md` |
| tiny-auditor | `~/.claude/skills/tiny-auditor/SKILL.md` |
| code-sleuth | `~/.claude/skills/code-sleuth/SKILL.md` |
| monethic-maia | `~/.claude/skills/monethic-maia/SKILL.md` |
| move-auditor | `~/.claude/skills/move-auditor/SKILL.md` |
| x-ray | `~/.claude/skills/x-ray/SKILL.md` |
| triage-validation | `~/.claude/skills/triage-validation/SKILL.md` |
| foundry-poc | `~/.claude/skills/foundry-poc/SKILL.md` |
| plamen | `~/.claude/commands/plamen.md` |
