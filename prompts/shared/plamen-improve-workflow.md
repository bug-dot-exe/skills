# Evolution Engine: Cross-Audit Pattern Learning

> **Usage**: Orchestrator reads this file when the user runs `/plamen compare` (Step 0e).
> Replace placeholders: `{REPORT_PATH}`, `{GROUND_TRUTH_PATH}`, `{PROJECT_ROOT}`.
> **Reference**: `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\rules\post-audit-improvement-protocol.md` for anti-anchoring rules and RC classification codes.

---

## Anti-Anchoring Constraint (HARD RULE)

NOTHING from the comparison persists except approved methodology changes.
The agent must approach each new audit with zero knowledge of previous audit findings.

**Persists**: Approved edits to rules/skills/prompts (methodology only) + one-line MEMORY.md entry.
**Does NOT persist**: Alignment matrix, finding details, ground truth content, classification evidence chains, proposal drafts, any description of specific bugs/protocols/codebases.

---

## Step 1: Alignment Agent

**Model**: sonnet (structured comparison — no deep reasoning needed)

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are the Alignment Agent. You compare Plamen's audit report with a
ground truth report to measure detection performance.

## Your Inputs
Read these files:
- {REPORT_PATH} (Plamen's output)
- {GROUND_TRUTH_PATH} (ground truth report)

## Your Task

### STEP 1: Parse Both Reports
Extract from each: finding ID, severity, title, location (file:line or function),
1-line root cause description.

### STEP 2: Match Findings
For each ground truth finding, search Plamen's report for a match:
1. LOCATION MATCH: same file AND overlapping line range (±10 lines)
2. ROOT CAUSE MATCH: same vulnerability class + same affected component
3. IMPACT MATCH: same consequence described

Classification:
- MATCHED: location + root cause match
- PARTIAL: root cause match but different severity OR different location
- MISSED: no match in Plamen's report (FALSE NEGATIVE)
- EXTRA: Plamen finding with no ground truth match (potential FALSE POSITIVE,
  but may also be a finding the ground truth missed)

### STEP 3: Compute Metrics
- Recall: (MATCHED + PARTIAL) / total_ground_truth
- Precision: (MATCHED + PARTIAL) / total_plamen
- Severity accuracy: exact_severity_match / MATCHED
- By severity tier: recall per Critical/High/Medium/Low/Info

### STEP 4: Summarize Misses
For each MISSED finding, extract:
- Ground truth ID, severity, title
- Location (file:line)
- Vulnerability class (1 word: reentrancy, access-control, oracle, economic, etc.)
- 1-line root cause (generic, no protocol-specific terms)

## Output
Return the alignment matrix and metrics as structured text.
Do NOT write to any file. This data is ephemeral — it lives only in this session.

Format your return as:

METRICS:
  Recall: {R}% ({matched}+{partial} / {total_gt})
  Precision: {P}% ({matched}+{partial} / {total_plamen})
  Severity accuracy: {S}%
  Per-tier recall: C={X}%, H={X}%, M={X}%, L={X}%, I={X}%

ALIGNMENT MATRIX:
| GT ID | GT Sev | GT Title | Match | Plamen ID | Plamen Sev | Delta |
|-------|--------|----------|-------|-----------|-----------|-------|
...

MISSED FINDINGS (for Classification Agent):
| GT ID | Severity | Vuln Class | Location | Root Cause (1-line) |
|-------|----------|-----------|----------|---------------------|
...

EXTRA FINDINGS (Plamen found, GT did not):
| Plamen ID | Severity | Title |
|-----------|----------|-------|
...

Return: 'DONE: Recall={R}%, Precision={P}%, Severity accuracy={S}%.
{M} matched, {PA} partial, {MI} missed, {E} extra.'
")
```

### After Step 1

The orchestrator captures the Alignment Agent's return text. This contains the alignment matrix and missed findings list. It is passed to Step 2 as context — never written to disk.

If Recall >= 95% and 0 missed findings at Medium+: output metrics to user, skip Steps 2-5. Nothing to improve.

---

## Step 2: Classification Agent

**Model**: opus (RC-AGENT Exclusion Test requires deep reasoning about methodology coverage)

```
Task(subagent_type="general-purpose", model="opus", prompt="
You are the Classification Agent. For each missed finding, you determine
whether the miss is fixable via pipeline changes or is an inherent LLM
reasoning error.

## Your Inputs

### Alignment Data (from Step 1 — ephemeral, not on disk)
{PASTE_ALIGNMENT_MATRIX_AND_MISSED_FINDINGS}

### Pipeline Files (read as needed)
You have grep/read access to:
- C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\rules\ (all shared rules: R1-R16 in generic-security-rules, confidence scoring, etc.)
- C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\prompts\evm/ (recon, inventory, depth, scanner, verification prompts)
- C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\ (all skill trees: evm/, solana/, aptos/, sui/, injectable/, niche/)
- {PROJECT_ROOT}/.plamen/ scratchpad files (agent output from the audit run)

### Audit Agent Outputs
Read the actual agent output files from the audit scratchpad to check what agents analyzed:
- {SCRATCHPAD}/analysis_*.md (breadth agent outputs)
- {SCRATCHPAD}/depth_*_findings.md (depth agent outputs)
- {SCRATCHPAD}/niche_*_findings.md (niche agent outputs, if any)

## RC-AGENT Exclusion Test (MANDATORY for every miss)

Before classifying ANY miss as RC-METHOD, RC-DEPTH, or RC-CONTEXT, you MUST
pass ALL THREE questions. If ANY answer is NO → classify as RC-AGENT.

Q1 — METHODOLOGY SEARCH:
  Grep existing rules, scanner checks, depth templates, skills, and security
  rules for keywords related to this vulnerability class.
  Command: grep -r '{vuln_class_keywords}' C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\rules\ C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\prompts\evm/ C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\evm/
  Did the search find ZERO relevant coverage? [YES/NO]
  If NO (coverage exists): DEFAULT TO RC-AGENT.

Q2 — REASONING TRACE:
  Read the relevant agent output file for the area where the miss occurred.
  Did the agent SKIP the area entirely (no mention of the file/function)? [YES/NO]
  If NO (agent analyzed it but reached wrong conclusion): DEFAULT TO RC-AGENT.

Q3 — METHODOLOGY GAP PROOF:
  State in ONE sentence what specific methodology instruction is missing —
  not 'the agent should have checked X' (that's a pattern) but 'no existing
  rule tells the agent HOW to systematically discover this class of bug.'
  Can you state this WITHOUT referencing the specific missed finding? [YES/NO]
  If NO: DEFAULT TO RC-AGENT. You are describing a pattern, not methodology.

## Classification Codes

| Code | Meaning | Pipeline Change? |
|------|---------|-----------------|
| RC-AGENT | Agent reasoning error | NO |
| RC-ANCHOR | Anchoring bias | NO |
| RC-NOVEL | Unprecedented class | RAG entry only |
| RC-SCOPE | File/function not analyzed | Fix recon |
| RC-METHOD | No rule/skill covers this class | New skill/check |
| RC-DEPTH | Correct area, too shallow | Depth directive |
| RC-CONTEXT | Lacked domain knowledge | Recon doc ingestion |

BIAS WARNING: You are biased toward fixable classifications (RC-METHOD,
RC-DEPTH) because they have actionable fixes. RC-AGENT feels like 'giving up.'
In practice, most misses are RC-AGENT. When in doubt, default to RC-AGENT.

## Output

Return per-miss classification with full exclusion test transcript.

Format:

CLASSIFICATION RESULTS:

## Miss: {GT_ID} — {title}
Exclusion Test:
  Q1 (methodology search): {YES|NO} — {what was found or not found}
  Q2 (reasoning trace): {YES|NO} — {agent skipped or analyzed}
  Q3 (methodology gap): {YES|NO} — '{gap statement}' or FAIL
Classification: RC-{CODE}
Rationale: {1 sentence}
[If fix-eligible: Fix target: {which file/section to modify}]

...

SUMMARY:
  Total misses: {N}
  RC-AGENT: {A} (no pipeline change)
  RC-ANCHOR: {AN} (no pipeline change)
  RC-NOVEL: {V} (RAG entry only)
  RC-SCOPE: {S}
  RC-METHOD: {M}
  RC-DEPTH: {D}
  RC-CONTEXT: {C}
  Reclassified to RC-AGENT after exclusion test: {R}
  Fix-eligible: {S+M+D+C}

Return: 'DONE: {N} misses classified. {A} RC-AGENT, {M} RC-METHOD,
{D} RC-DEPTH, {S} RC-SCOPE, {C} RC-CONTEXT, {V} RC-NOVEL.
{R} reclassified to RC-AGENT after exclusion test. {FE} fix-eligible.'
")
```

### After Step 2

The orchestrator captures the Classification Agent's return. If 0 fix-eligible misses (all RC-AGENT/RC-ANCHOR/RC-NOVEL): output classification summary to user, skip Steps 3-5.

Otherwise, extract the fix-eligible classifications and pass to Step 3.

---

## Step 3: Proposal Agent

**Model**: opus (requires judgment about anti-bloat gates and methodology vs pattern)

```
Task(subagent_type="general-purpose", model="opus", prompt="
You are the Proposal Agent. For each fix-eligible miss, you design a minimal
methodology improvement and verify it passes anti-bloat gates.

## Your Inputs

### Fix-Eligible Classifications (from Step 2 — ephemeral)
{PASTE_FIX_ELIGIBLE_CLASSIFICATIONS}

### Pipeline Files (read as needed)
You have read access to all files in:
- C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\rules\
- C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\prompts\evm/
- C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\

## Decision Tree (per miss)

Is the gap covered by an EXISTING rule/skill/check?
├── YES → Re-run RC-AGENT Exclusion Test Q1. If coverage exists, likely RC-AGENT.
│   ├── Coverage exists but fails to trigger → trigger-fix (~2 lines, low risk)
│   └── Coverage exists and triggered → RC-AGENT, no fix
└── NO → Is the vulnerability class generalizable (2+ protocol types)?
    ├── YES → Extends existing component? → extend (~5-10 lines, medium risk)
    │         No existing component? → new-injectable (~50-100 lines)
    └── NO → rag-entry only (0 pipeline lines)

## Anti-Bloat Gates (MANDATORY for extend or higher)

1. LINE BUDGET: Will this push any file past its cap?
   Scanner: 600, Depth templates: 250, Security rules: 1000, Skills: 300,
   Recon: 1100, CLAUDE.md: 500, Confidence scoring: 200, Chain: 250, Report: 500
   → Read the target file, count lines, check against cap.

2. DUPLICATION: Does this require touching 4+ files with near-identical text?
   If yes → find a shared location (rules/, depth agent definitions) instead.

3. MARGINAL VALUE: Would this catch the miss AND is it unlikely to produce
   false positives in general?

4. OVERLAP: Does a similar check already exist?
   Grep all scanner checks, depth checks, skill steps for keyword overlap.
   If >60% overlap → merge into existing check, don't create new one.

## Methodology Test (HARD GATE)

Does this teach the agent HOW to look? → proceed
Does this tell the agent WHAT to find? → REJECT, rag-entry only

'Enumerate all write sites for accumulator variables' = methodology (HOW)
'Check if updateReward() is called in emergencyWithdraw()' = pattern (WHAT)

## Output

For each fix-eligible miss, produce a proposal:

## Proposal {N}: {title}
- RC: {code}
- Type: {trigger-fix | extend | new-injectable | rag-entry}
- Target file(s): {path(s) with current line count and +/- delta}
- Anti-bloat gates: budget={OK|OVER}, duplication={OK|N files}, value={OK|NOISY}, overlap={OK|MERGE with {existing}}
- Methodology test: {PASS|FAIL — 1 sentence}
- Change description: {what to add/modify, in methodology terms — not specific to this audit}
- Proposed diff (for trigger-fix and extend only):
  [include actual diff lines]

SUMMARY:
  Proposals: {N}
  trigger-fix: {T}
  extend: {E}
  new-injectable: {I}
  rag-entry: {R}
  rejected (methodology test FAIL): {X}

Return: 'DONE: {N} proposals generated. {T} trigger-fix, {E} extend,
{I} new-injectable, {R} rag-entry, {X} rejected.'
")
```

---

## Step 4: Human Review Gate (MANDATORY)

The orchestrator presents each proposal to the user using `AskUserQuestion`.

For each proposal, present 4 options:
- **APPROVED**: implement the change as proposed
- **APPROVED AS INJECTABLE**: convert to injectable skill instead of always-on
- **DEFERRED**: add to RAG only, revisit later
- **REJECTED**: no change

No automatic approvals. The human is the final gate.

If ALL proposals are DEFERRED or REJECTED: output summary, stop.

---

## Step 5: Apply (Orchestrator Inline)

For each APPROVED proposal:

1. **Apply the change**: Edit the identified file(s) with the proposed diff
2. **Version bump**: If the file has a version comment/header, increment it
3. **Grep verify**: Confirm the key phrase landed correctly in the target file
4. **Cross-tree sync**: If the change applies to language-specific files, apply to all relevant trees (evm, solana, aptos, sui) where the same pattern exists. Skip trees where the pattern is absent.

After all approved changes applied:

5. **Update MEMORY.md**: Add one-line entry under `## Pipeline Improvements`:
   ```
   ## Pipeline v{X} (YYYY-MM-DD)
   {1-2 sentence description of methodology changes}. {N}xRC-{code} fixes,
   {R}xRC-AGENT reclassified. Recall: {X}% on {project type}.
   ```

6. **Commit**: Stage all modified files and commit with message:
   `feat(plamen): evolution engine — {N} methodology improvements (recall {X}%→target)`

---

## Budget

| Step | Agent | Model | Purpose |
|------|-------|-------|---------|
| 1 | Alignment | sonnet | Structured report comparison |
| 2 | Classification | opus | RC-AGENT exclusion test (deep reasoning) |
| 3 | Proposal | opus | Methodology design + anti-bloat gates |
| **Total** | **3 agents** | | Sequential, not parallel |

---

## Early Exit Conditions

| After Step | Condition | Action |
|------------|-----------|--------|
| 1 | Recall >= 95% AND 0 missed Medium+ | Output metrics, stop |
| 2 | 0 fix-eligible misses | Output classification summary, stop |
| 4 | All proposals DEFERRED/REJECTED | Output summary, stop |
