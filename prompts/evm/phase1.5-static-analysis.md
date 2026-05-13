# Phase 1.5: Static Analysis Scan (EVM only)

> **Usage**: Orchestrator reads this file and spawns 1 agent after Phase 1 recon completes.
> Replace placeholders: `{SCRATCHPAD}`, `{TARGET_DIR}`.
> **Trigger**: LANGUAGE=evm AND SLITHER_AVAILABLE=true AND build succeeded.
> **Skip**: If any trigger condition is false, write empty `slither_report.md` and proceed to Phase 2.

---

## Trigger Check (Orchestrator Inline)

```
IF LANGUAGE != "evm" OR SLITHER_AVAILABLE != true:
  Write "{SCRATCHPAD}/slither_report.md" with "# Static Analysis Report (Slither)\n\nSkipped: SLITHER_AVAILABLE=false or non-EVM target."
  Write "{SCRATCHPAD}/slither_call_graph.md" with "# Function Reachability Map\n\nSkipped."
  GOTO Phase 2
```

---

## Agent Specification

**Model**: sonnet (mechanical task — run tool, parse JSON, categorize)
**Budget**: 1 agent, not counted against depth budget
**Timeout**: 10 minutes

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are the Static Analysis Agent. You run Slither on the target codebase
and produce structured output for downstream agents.

## Your Task

### STEP 1: Run Slither

Execute via Bash:

slither {TARGET_DIR} --json /tmp/slither_output.json \
  --exclude naming-convention,pragma,solc-version,external-function,constable-states,immutable-states \
  --filter-paths 'test/,tests/,script/,lib/,node_modules/' \
  2>&1 | tee /tmp/slither_stderr.txt

If Slither fails:
- Read stderr for the error
- If compilation error: write SLITHER_FAILED + error to slither_report.md, STOP
- If timeout: write SLITHER_TIMEOUT to slither_report.md, STOP
- Do NOT retry more than once

### STEP 2: Parse Detector Output

Read /tmp/slither_output.json. For each detector hit, extract:
- Detector name (e.g., reentrancy-eth, arbitrary-send-eth)
- Confidence (High/Medium/Low/Informational — from Slither's own classification)
- Impact (High/Medium/Low/Informational — from Slither's own classification)
- Affected elements (contract, function, line numbers)
- Description (Slither's generated description)

Categorize into tiers:

HIGH_CONFIDENCE_DETECTORS (Slither confidence High, historically low FP rate):
  reentrancy-eth, reentrancy-no-eth, reentrancy-benign, reentrancy-events,
  arbitrary-send-eth, suicidal, controlled-delegatecall, delegatecall-loop,
  msg-value-loop, unprotected-upgrade, backdoor, protected-vars,
  tautological-compare, write-after-write

MEDIUM_CONFIDENCE_DETECTORS (Slither confidence Medium, moderate FP rate):
  unchecked-transfer, locked-ether, tx-origin, uninitialized-state,
  uninitialized-storage, uninitialized-local, divide-before-multiply,
  incorrect-equality, shadowing-state, unused-return, reentrancy-unlimited-gas

LOW_CONFIDENCE_DETECTORS (context-only, not used for validation):
  Everything else — timestamp, assembly, low-level-calls, too-many-digits,
  missing-zero-check, etc.

### STEP 3: Extract Call Graphs

For each external/public function in scope, use MCP tools:
  mcp__slither-analyzer__get_function_callees(contract_name='{contract}', function_name='{function}')

Build a reachability map:
- Which external entry points can reach each internal function?
- Which functions have NO external entry point (dead code or internal-only)?

If MCP tools fail or timeout, skip call graph extraction. Detector output alone is still valuable.

When an MCP tool call returns a timeout error or fails, do NOT retry the same call. Record [MCP: TIMEOUT] and skip ALL remaining calls to that provider — switch immediately to fallback (grep-based call tracing). You cannot cancel a pending call — but you control what happens after the error returns.

### STEP 4: Write Output

Write to {SCRATCHPAD}/slither_report.md:

```markdown
# Static Analysis Report (Slither)

## Summary
- Detectors run: {N}
- Total hits: {N} (High-confidence: {N}, Medium-confidence: {N}, Low-confidence: {N})
- Excluded detectors: naming-convention, pragma, solc-version, external-function, constable-states, immutable-states
- Excluded paths: test/, tests/, script/, lib/, node_modules/

## High-Confidence Detector Hits
| # | Detector | Impact | Contract | Function | Lines | Description |
|---|----------|--------|----------|----------|-------|-------------|

## Medium-Confidence Detector Hits
| # | Detector | Impact | Contract | Function | Lines | Description |
|---|----------|--------|----------|----------|-------|-------------|

## Low-Confidence Detector Hits (Context Only)
| # | Detector | Impact | Contract | Function | Lines | Description |
|---|----------|--------|----------|----------|-------|-------------|

These low-confidence hits are NOT used for finding validation. They provide
background context only — agents should not cite them as evidence.
```

Write to {SCRATCHPAD}/slither_call_graph.md:

```markdown
# Function Reachability Map

## External Entry Points
| Contract | Function | Visibility | Modifiers | Direct Callees | Reachable Internal Functions |
|----------|----------|-----------|-----------|----------------|------------------------------|

## Unreachable Functions (no external entry point)
| Contract | Function | Notes |
|----------|----------|-------|
```

Return: 'DONE: {H} high-confidence, {M} medium-confidence, {L} low-confidence detector hits. {F} external entry points mapped. {U} unreachable functions identified.'
")
```

---

## Downstream Consumption

### Breadth Agents (Phase 3)

The orchestrator injects this block into every breadth agent prompt when `slither_report.md` contains hits:

```
## Static Analysis Context (from Slither)

The following detector hits were identified by static analysis. These are
MECHANICAL findings — they may be true positives or false positives. Your job
is to ANALYZE them in the context of the protocol's design, not to blindly
confirm or dismiss them.

### High-Confidence Hits in Your Scope
{filtered subset of slither_report.md HIGH_CONFIDENCE for this agent's scope}

### Function Reachability
{filtered subset of slither_call_graph.md for this agent's scope}

RULES:
1. Every HIGH_CONFIDENCE hit in your scope MUST appear in your output —
   either as a finding (with your own analysis) or as an explicit dismissal
   with reasoning.
2. Use reachability data to assess exploitability — a reentrancy in an
   unreachable function is Informational, not High.
3. Tag findings that match a Slither detector: [SLITHER-CONFIRM: {detector_name}]
4. Tag findings where Slither found nothing at the same location: [SLITHER-ABSENT]
   (this is not a penalty — Slither misses 63-74% of real bugs)
```

### Depth Agents (Phase 4b)

Depth agents receive `slither_report.md` as an additional artifact. When analyzing a function, they check whether Slither flagged it and use that as supporting evidence (or as a starting point for deeper investigation).

### Validation Sweep (Phase 4b)

The validation sweep agent receives `slither_report.md` as additional input. For each finding it validates, it checks whether a matching Slither detector hit exists at the same location. If yes, the agent adds `[SLITHER-CONFIRM: {detector}]` to the finding's evidence tags.

### Verification (Phase 5)

Verifier agents receive `slither_call_graph.md`. When writing PoCs, the call graph confirms which functions are externally callable and which require specific setup to reach.

---

## Confidence Scoring Integration

New evidence tag for the Evidence axis (Phase 4 confidence scoring):

| Tag | Evidence Score | Rationale |
|-----|---------------|-----------|
| `[SLITHER-CONFIRM]` | 0.9 | Mechanical confirmation from static analysis — same weight as [PROD-SOURCE] |
| `[SLITHER-ABSENT]` | No change | Slither misses most bugs; absence is not evidence of absence |

The composite formula is unchanged. `[SLITHER-CONFIRM]` provides a high Evidence score, boosting composite confidence for findings where LLM analysis and static analysis agree.

---

## Fallback Behavior

| Condition | Action |
|-----------|--------|
| LANGUAGE != evm | Skip Phase 1.5, write empty slither_report.md |
| SLITHER_AVAILABLE = false | Skip Phase 1.5, write empty slither_report.md |
| Build failed | Skip Phase 1.5, write empty slither_report.md |
| Slither fails (compilation) | Write SLITHER_FAILED + error, skip |
| Slither times out (>10 min) | Write SLITHER_TIMEOUT, skip |
| Slither returns 0 hits | Write empty tables, proceed normally |
| MCP slither-analyzer unavailable | Skip call graph extraction, detector output still usable |
