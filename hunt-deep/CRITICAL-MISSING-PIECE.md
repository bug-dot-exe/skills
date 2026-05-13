---
name: critical-missing-piece
description: >
  Anomaly-first deep audit methodology for finding critical bugs through exhaustive
  line-by-line analysis, persistent anomaly tracking, and aggressive chain escalation.
  The premise: most criticals hide as two harmless-looking pieces that nobody connected.
  Supplements hunt-deep with a depth-oriented methodology. Trigger on "hunt deep --source".
---

# The Missing Piece Hunt

> **Philosophy**: A critical is rarely one obvious bug. It's two or three things that look harmless alone — a missing check here, a stale value there, an assumption nobody questioned — that chain into fund loss, account takeover, or full compromise. Your job is to find every anomaly, track it, and keep asking: *"What one thing, combined with this, makes it critical?"*

---

## Phase 0 — Anomaly Register (Persistent, Append-Only)

Before any analysis begins, create the anomaly register. Every agent writes to it. Nothing is too small.

```bash
mkdir -p "$TARGET_DIR/anomalies"
touch "$TARGET_DIR/anomalies/register.md"
```

### What goes in the register

| Category | Examples | Why it matters |
|----------|---------|---------------|
| **Inconsistency** | Function A validates X, function B doesn't. Naming mismatch between paired operations. Comment says one thing, code does another. | Inconsistency = different assumptions = exploitable gap |
| **Missing symmetric** | Deposit validates, withdraw doesn't. Lock has timelock, unlock doesn't. Encode uses param A, decode doesn't. | Asymmetry is the #1 source of exploitable logic bugs |
| **Dead/unreachable code** | Branch that can never execute. Parameter always zero. Modifier that's never actually restrictive. | Dead code hides dead assumptions — when the assumption revives, the bug does too |
| **Implicit assumption** | "This can't be zero." "Caller is always the owner." "This runs after X." No require/assert enforces it. | Unvalidated assumptions are preconditions waiting for an enabler |
| **Unusual pattern** | Custom math instead of SafeMath. Inline assembly. Unconventional reentrancy pattern. Hand-rolled access control. | Custom = untested. If they wrote it themselves, it hasn't been hammered by millions of users. |
| **Boundary behavior** | What happens at 0? At MAX_UINT? At 1 wei? At exactly the threshold? When the array is empty? When it has 1 element? | Edge values break invariants that hold at normal operating ranges |
| **Temporal dependency** | Stale oracle. Price between transactions. Timestamp in a block-dependent check. Order-dependent state. | Time creates windows. Windows create races. Races create exploits. |
| **Trust boundary crossing** | User input flows to privileged operation. External call result used without validation. Return value ignored. | Every trust boundary crossing is a potential injection/manipulation point |

### Register format

```markdown
## [A-{NNN}] {one-line description}
- **File**: {path}:{line}
- **Category**: {from table above}
- **Observation**: {what's weird — 1-2 sentences, concrete}
- **Hypothesis**: {what could go wrong if combined with X — speculative is fine}
- **Chains to**: {other anomaly IDs this could combine with, or "NONE YET"}
- **Status**: OPEN | CHAINED (→ F-{id}) | DISMISSED ({reason})
```

Every agent MUST append anomalies as they find them. The register is append-only during analysis; chaining and dismissal happen in Phase 4.

---

## Phase 1 — Attack Surface Cartography (Exhaustive, Not Prioritized)

> **Key difference from standard recon**: Standard recon ranks and filters. This phase maps EVERYTHING — the critical is hiding where nobody looked.

### 1a. Entry Point Enumeration (COMPLETE)

For EVERY public/external function, for EVERY endpoint, for EVERY user-reachable path:

| Field | Capture |
|-------|---------|
| Function/endpoint | Exact signature, visibility, modifiers |
| Caller constraints | Who CAN call this? Who is EXPECTED to call this? Are those the same? |
| Input parameters | Every param: type, range, validation applied, validation MISSING |
| State reads | Which state does this function READ? Is any of it writable by another caller? |
| State writes | Which state does this function WRITE? Who else reads this state? |
| External calls | What external contracts/services does this call? What does it trust from the response? |
| Return value | What's returned? Does every caller check it? |
| Preconditions | What MUST be true for this to work correctly? Is each precondition ENFORCED or ASSUMED? |
| Postconditions | What state changes after this executes? Could any of those changes violate another function's precondition? |

Write to `$TARGET_DIR/surface/entry_points.md`.

### 1b. State Variable Atlas

For EVERY state variable (storage slot, account field, database column):

| Field | Capture |
|-------|---------|
| Variable | Name, type, visibility |
| Writers | ALL functions that modify this variable (direct + indirect via internal calls) |
| Readers | ALL functions that read this variable |
| Invariants | What constraints should always hold? (e.g., totalSupply == sum of balances) |
| Initialization | How is it set initially? Can it be zero/uninitialized? |
| Lifecycle | Can it be reset? Paused? Migrated? Upgraded? |

Write to `$TARGET_DIR/surface/state_atlas.md`.

### 1c. Trust Boundary Map

```
EXTERNAL (untrusted)
  │
  ├─ User transactions/HTTP requests
  │    └─ Input validation layer [MAP EVERY CHECK]
  │         └─ Core logic
  │              ├─ Internal state [MAP EVERY WRITE]
  │              └─ External calls [MAP EVERY OUTBOUND]
  │                   └─ Return handling [MAP EVERY ASSUMPTION]
  │
  ├─ Admin/privileged calls
  │    └─ Access control layer [MAP EVERY MODIFIER]
  │         └─ Parameter validation [MAP WHAT'S MISSING]
  │
  └─ External feeds (oracles, cross-chain, callbacks)
       └─ Validation layer [MAP WHAT'S TRUSTED]
```

Write to `$TARGET_DIR/surface/trust_boundaries.md`.

### 1d. Unexplored Surface Tracker (MANDATORY)

After mapping, create an explicit list of what HASN'T been fully explored:

```markdown
## Unexplored Surfaces
| Area | Why Not Yet | Priority | Assigned Agent |
|------|-----------|----------|---------------|
| [list every gap] | [why] | [P1/P2/P3] | [agent or NONE] |
```

Write to `$TARGET_DIR/surface/unexplored.md`. This file is checked at every phase gate. Anything still NONE after Phase 3 gets a dedicated agent.

---

## Phase 2 — Line-by-Line Audit (EVERY LINE, NO SKIPPING)

> **The rule**: If you didn't read it, you can't find bugs in it. Every line gets eyes.

### Agent Fan-Out Strategy

Split the codebase into segments. Each agent gets one segment. Segments overlap by 20 lines at boundaries (to catch cross-boundary bugs).

**Segment assignment**: By file for small codebases (<2000 LOC), by logical module for larger ones. Each agent gets MAX 500 lines — beyond that, attention degrades.

### Per-Line Audit Protocol

For each line, the agent asks these 7 questions (in order — each builds on the previous):

| # | Question | If YES → |
|---|----------|----------|
| 1 | **What does this line DO?** (not what the comment says — what the code ACTUALLY does) | Proceed |
| 2 | **Can the inputs be attacker-controlled?** Trace back: where does each value come from? | If yes → check validation at every hop |
| 3 | **What happens at boundary values?** (0, 1, MAX, empty, max_length, exactly-equal-to-threshold) | If weird → ANOMALY REGISTER |
| 4 | **What does this line ASSUME?** (previous state, caller identity, timing, external state) | For each assumption: is it ENFORCED or just expected? If expected → ANOMALY REGISTER |
| 5 | **What's the INVERSE operation?** (if this encodes, where's the decode? if this locks, where's the unlock?) | If inverse is missing or asymmetric → ANOMALY REGISTER |
| 6 | **Who else reads/writes the same state?** | If multiple writers with different validation → ANOMALY REGISTER |
| 7 | **What would make this line DANGEROUS?** Not "is it dangerous now" — what precondition, if true, would make this exploitable? | Document the hypothetical enabler → ANOMALY REGISTER with hypothesis |

### Agent Prompt Template (Line-by-Line Auditor)

```
You are Line-by-Line Auditor #{N} — your segment is {FILE}:{START_LINE}-{END_LINE}.

## Your Mission
Read every line in your segment. For each line, apply the 7-question protocol.
You are not looking for known vulnerability patterns. You are looking for ANOMALIES —
anything that's inconsistent, asymmetric, unvalidated, assumption-dependent, or unusual.

## Critical Mindset
A line that's "probably fine" is a line you haven't thought about hard enough.
The critical is hiding in the line everyone glosses over.

Ask yourself for EVERY function: "What's the one thing that, if true, would make
this a critical?" Then ask: "Is there ANY path in this codebase that makes it true?"

## Your Outputs
1. ANOMALY REGISTER entries → append to {TARGET_DIR}/anomalies/register.md
2. Per-function analysis → write to {TARGET_DIR}/analysis/segment_{N}.md

## Per-Function Analysis Format
### {function_name} ({file}:{line})
**Purpose**: {what it actually does, not what the name implies}
**Callers**: {who calls this, from entry_points.md}
**State touched**: {reads + writes, from state_atlas.md}
**Assumptions**: {list every assumption, mark ENFORCED or UNVALIDATED}
**Boundary behavior**: {what happens at 0, MAX, empty, threshold}
**Dangerous if**: {the hypothetical that makes this exploitable}
**Anomalies found**: [A-{ids}]

## HARD RULES
- Do NOT skip "simple" functions. Simple getters can return stale data. Simple setters can lack validation.
- Do NOT say "this looks fine." State what you VERIFIED and what you DID NOT CHECK.
- If you find something weird, ALWAYS add it to the anomaly register even if it seems low-severity.
  Low-severity anomalies are the missing pieces that chain into criticals.
```

### Coverage Assertion (Orchestrator, After Phase 2)

```
total_lines = wc -l {all source files}
analyzed_lines = sum(segment ranges across all agents)
ASSERT: analyzed_lines >= total_lines
If gap: spawn additional agent for uncovered lines
```

---

## Phase 3 — Deep Surface Dives (Parallel Specialists)

> **Fan out aggressively.** Each specialist goes DEEP on one attack surface. They read the anomaly register and hunt for chains.

### Specialist Roster (Spawn ALL relevant agents in ONE message)

| Agent | Focus | Key Question |
|-------|-------|-------------|
| **State Mutation Tracer** | Cross-function state consistency | "When function A writes X, does every function that reads X still work correctly?" |
| **Access Control Auditor** | Permission boundaries | "Can ANY less-privileged actor reach a more-privileged outcome through ANY sequence of calls?" |
| **Value Flow Tracker** | Token/fund movement | "Can value enter and exit in a way that creates or destroys value for anyone?" |
| **Temporal Analyst** | Time-dependent behavior | "Can the ordering or timing of operations change the outcome in an exploitable way?" |
| **External Dependency Prober** | Oracle, cross-chain, callback surfaces | "What happens when the external dependency returns unexpected/malicious data?" |
| **Edge Case Specialist** | Boundary values, empty states, first/last operations | "What's the most extreme input that doesn't revert? What state does it create?" |
| **Assumption Challenger** | Unvalidated assumptions from anomaly register | "For each UNVALIDATED assumption: what's the cheapest path to violating it?" |
| **Inverse Operation Auditor** | Paired operations (deposit/withdraw, mint/burn, lock/unlock) | "Are the operations truly symmetric? What state leaks through the gap?" |

### Specialist Agent Prompt Template

```
You are the {SPECIALIST_NAME}.

## Context
- Read: {TARGET_DIR}/anomalies/register.md (the full anomaly register — YOUR anomalies + everyone else's)
- Read: {TARGET_DIR}/surface/ (attack surface cartography)
- Read: {TARGET_DIR}/analysis/ (line-by-line audit outputs)
- Read: Source code in scope

## Your Mission
Deep dive on {FOCUS_AREA}. Your key question: "{KEY_QUESTION}"

For every relevant function in scope:
1. Apply your specialist lens to answer your key question
2. Cross-reference the anomaly register — does any existing anomaly become DANGEROUS through your lens?
3. Check the unexplored.md — does your analysis reveal new unexplored surfaces?

## Chain Building (CRITICAL)
For each issue you find, IMMEDIATELY check:
- Does this issue's POSTCONDITION match any anomaly's HYPOTHESIS as an enabler?
- Does any anomaly's OBSERVATION provide the PRECONDITION your issue needs?
- If yes → document the chain with specific code paths

## Missing Piece Protocol
For every PARTIAL finding (issue that needs one more thing to be exploitable):
Write out explicitly:
1. What you found (the 90%)
2. What's missing (the 10% — the missing piece)
3. Where to look for the missing piece (specific files, functions, external conditions)
4. What the impact would be IF the missing piece exists (quantify — $$, users affected, protocol state)

## Output
- Append new anomalies to {TARGET_DIR}/anomalies/register.md
- Write specialist findings to {TARGET_DIR}/findings/specialist_{NAME}.md
- Update {TARGET_DIR}/surface/unexplored.md with new surfaces found
- Write chains to {TARGET_DIR}/chains/specialist_{NAME}_chains.md

SCOPE: Do NOT proceed to reporting. Return your findings and stop.
```

---

## Phase 4 — Chain Synthesis & Missing Piece Resolution

> **This is where criticals are born.** Take every anomaly, every specialist finding, every PARTIAL — and systematically try to chain them.

### 4a. Anomaly Cross-Reference Matrix

Spawn a **chain synthesis agent** that reads the ENTIRE anomaly register and builds:

```markdown
## Cross-Reference Matrix

For every pair (A-{i}, A-{j}) where i != j:
| Anomaly A | Anomaly B | Chain? | Combined Impact | Missing Piece |
|-----------|-----------|--------|----------------|---------------|

Focus on pairs where:
- A's postcondition matches B's hypothesis
- A and B touch the same state variable
- A and B are in the same trust boundary crossing
- A is an unvalidated assumption and B provides a path to violate it
```

### 4b. Missing Piece Hunt (DEDICATED AGENTS)

For each PARTIAL finding with an identified missing piece:

```
You are the Missing Piece Hunter for finding {F-ID}.

## The Finding
{description — the 90% that's confirmed}

## The Missing Piece
{what's needed to make this critical — the 10%}

## Where to Look
{specific files, functions, external conditions suggested by the specialist}

## Your Job
1. Exhaustively search for the missing piece. Not a quick grep — trace every path.
2. If found → document the COMPLETE chain with code references
3. If the exact piece isn't there → look for ADJACENT pieces:
   - A different function that achieves the same precondition
   - An admin operation that could be coerced or mistimed
   - An external condition (oracle, governance, market state) that creates it
   - A sequence of normal operations that accidentally creates it
4. If truly nothing → document WHY it's not exploitable (what defense holds)

## Output
Write to {TARGET_DIR}/findings/missing_piece_{F_ID}.md:
- FOUND: [the complete chain] OR
- ADJACENT: [a variant chain that partially works] OR  
- BLOCKED: [what defense prevents exploitation + confidence level]
```

### 4c. Unexplored Surface Sweep

Read `$TARGET_DIR/surface/unexplored.md`. For every entry still marked NONE:

Spawn a dedicated agent to explore it. No surface goes unexamined.

### 4d. Severity Escalation Pass

For each confirmed chain:

```
Impact Assessment:
- Direct fund loss? → CRITICAL floor
- Account takeover? → CRITICAL floor
- Protocol state corruption? → HIGH floor (CRITICAL if irreversible)
- Denial of service? → MEDIUM floor (HIGH if permanent)
- Information disclosure? → depends on what's disclosed

Likelihood Assessment:
- Permissionless (anyone can do it)? → HIGH likelihood
- Requires specific timing? → MEDIUM likelihood  
- Requires privileged access? → LOW likelihood (trace the permission chain — one privileged hop = floor at Low)
- Requires multiple transactions? → still HIGH if automated

Chain Bonus:
- If chain combines 2+ independently-confirmed anomalies → upgrade one tier
- If chain requires no external preconditions → upgrade one tier
- Cap at CRITICAL
```

---

## Phase 5 — Validation & PoC

For every finding at Medium+:

1. **Write a PoC** that proves the HARM, not just the mechanism
2. **Execute it** — a PoC that was never run provides zero evidence
3. **Before FALSE_POSITIVE**: test at least one relaxed variant (different timing, amount, ordering, initial state)

For every finding with a chain:
- The PoC MUST execute the COMPLETE chain (enabler → exploitation → impact assertion)
- Assert the COMBINED impact, not just individual steps

---

## Orchestrator Execution Checklist

```
[ ] Phase 0: Anomaly register created
[ ] Phase 1a: Entry points enumerated (COUNT: ___)
[ ] Phase 1b: State atlas written (VARIABLES: ___)
[ ] Phase 1c: Trust boundaries mapped
[ ] Phase 1d: Unexplored surfaces tracked (GAPS: ___)
[ ] Phase 2: Line-by-line agents spawned (AGENTS: ___, LINES: ___/TOTAL)
[ ] Phase 2 gate: Coverage assertion PASSED (analyzed >= total)
[ ] Phase 2: Anomaly register populated (ANOMALIES: ___)
[ ] Phase 3: Specialist agents spawned (AGENTS: ___)
[ ] Phase 3: Specialist findings written
[ ] Phase 3: Unexplored surfaces updated
[ ] Phase 4a: Cross-reference matrix built (PAIRS EXAMINED: ___)
[ ] Phase 4b: Missing piece hunters spawned (PARTIALS: ___)
[ ] Phase 4c: Unexplored surface sweep (REMAINING GAPS: ___)
[ ] Phase 4d: Severity escalation applied
[ ] Phase 5: PoC execution for all Medium+ (VERIFIED: ___/TOTAL)
[ ] FINAL: No surface in unexplored.md is marked NONE
[ ] FINAL: Every anomaly is CHAINED, DISMISSED (with reason), or documented as OPEN
```

---

## Anti-Patterns (What NOT To Do)

| Anti-Pattern | Why It Kills Criticals | Instead |
|-------------|----------------------|---------|
| Skipping "simple" code | Simple code has simple bugs that chain with complex code | Read every line |
| Filtering anomalies by severity | A Low anomaly + another Low anomaly = Critical chain | Track everything |
| Analyzing functions in isolation | Bugs live between functions, not inside them | Trace state across functions |
| Stopping at "this requires admin" | Admin keys get compromised. Timelocks expire. Governance attacks exist. | Ask "what if admin is malicious/compromised?" (then apply permission chain rule for severity) |
| Trusting comments | Comments lie. Comments rot. Comments describe intent, not behavior. | Read the code, not the comments |
| Dismissing race conditions | "Block time is 12 seconds" — and mempool is public, and flashloans exist | Model worst-case timing |
| "This is by design" closure | "By design" describes mechanism, not impact. Users can still lose funds by design. | Always quantify impact before dismissing |
| Prioritizing known vuln classes | The critical is in the class nobody has a scanner for | Anomaly-first, not pattern-first |
