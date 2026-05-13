# Stage 06: Candidate Generation

Stage ID: `S06_CANDIDATES`

## Objective

Run detector batches and generalist against the full source code to produce vulnerability candidates.

## Input sources

Read detected platform from `./.maia_auditor/platform.txt`, then load:

- `./.maia_auditor/recon.md` (context — roles, entry points, state, recommendations)
- `./.maia_auditor/packed_source.txt` (full concatenated source code with file path headers)
- `./.maia_auditor/checklist.plan.min.json` (which detectors to run, from checklist plan)
- `./.maia_auditor/evidence.map.min.json` (call graph, signals — from evidence stage)
- `./.maia_auditor/deep_sweep.findings.min.json` (sink-first findings — from deep sweep)
- `{platform_dir}/knowledge/rulepack.md` (rule ID mapping)
- `{platform_dir}/knowledge/checklists/categories/CAT-*.md` (loaded per batch)

Where `{platform_dir}` is `evm`, `move-aptos`, or `move-sui`.

## Exclusions

If `./.maia_auditor/exclusions.txt` exists, skip all listed paths. Do not generate candidates for excluded files.

## Core approach: context + code + detectors per batch

For each batch, the LLM receives FIVE inputs:

1. **Recon context** — `./.maia_auditor/recon.md` (what is this project, who are the actors, what does it do)
2. **Full source code** — `./.maia_auditor/packed_source.txt` (all in-scope files, the LLM sees ALL the code at once)
3. **Evidence map** — `./.maia_auditor/evidence.map.min.json` (call graph, function signals — use this to trace cross-function flows)
4. **Deep sweep findings** — `./.maia_auditor/deep_sweep.findings.min.json` (sink-first findings to cross-reference and reinforce)
5. **Detector batch** — the CAT file(s) for this batch's categories (patterns, detect steps, remediation)

The LLM applies each detector's patterns and detect steps against the full source code, using recon context + evidence map to understand the architecture, and cross-referencing deep sweep findings for reinforcement.

## Batch execution

### Batch threshold

- **Default batch size**: 3 categories or ~10 detectors per pass (whichever is reached first)
- **When to chunk**: if total selected detectors > 15
- **Small projects** (≤ 15 detectors selected): single pass with all detectors

### Process

1. Sort selected categories by relevance (from recon recommendations, most relevant first)
2. Group categories into batches respecting the threshold
3. For each batch:

```
[detector batch 1/N] running: ACC, GEN, MATH (24 detectors)
```

   a. Load the CAT files for this batch's categories
   b. Feed the LLM: recon context + full source code + batch detector patterns
   c. For each detector, apply its Detect steps mechanically against the source code
   d. Generate findings with file:line references, evidence, and exploit paths
   e. Write partial findings to `./.maia_auditor/findings.batch_{N}.min.json`
   f. Print batch result:

```
[detector batch 1/N] complete: 7 candidates found
```

4. **Generalist pass** — always runs as the final batch:

```
[generalist] running full-spectrum audit
[generalist] complete: 4 candidates found
```

   The generalist receives: recon context + full source code + `prompts/generalist/generalist_{platform}.md`. It is a full-spectrum security audit that catches anything the detector batches missed — including sink-first analysis (reentrancy, delegatecall, flash loans, etc.), cross-function flows, and novel patterns not covered by any detector.

5. After all batches + generalist complete, merge all `findings.batch_*.min.json` + `generalist.findings.json` into `findings.candidates.min.json`
6. Run deduplication across the merged set

### Progress output

```
[detector batch 1/4] running: ACC, GEN, MATH (24 detectors)
[detector batch 1/4] complete: 7 candidates
[detector batch 2/4] running: LEND, ORACLE, VAULT (19 detectors)
[detector batch 2/4] complete: 5 candidates
[detector batch 3/4] running: PROXY, ERC20, DEX (15 detectors)
[detector batch 3/4] complete: 3 candidates
[detector batch 4/4] running: GAS, STAKE, XCHAIN (18 detectors)
[detector batch 4/4] complete: 1 candidate
[generalist] complete: 4 candidates
[S06] merged: 20 candidates, 3 dedup removed → 17 total
```

## Generation principles

Each candidate represents one concrete rule/file/location claim. Include specific line references and code snippets from the actual source code.

For each detector in the batch:
1. Read the detector's Patterns section — understand what vulnerable code looks like
2. Read the detector's Detect steps — follow them mechanically against the source
3. If a pattern matches, create a finding with exact file:line, code snippet, and exploit path

Cross-reference with deep-sweep findings: if a deep sweep finding matches a detector pattern, reinforce it (higher confidence). If a deep sweep finding has no detector match, include it with `rule_id = "AI-ONLY"`.

For findings from the generalist that don't match any detector rule, also assign `rule_id = "AI-ONLY"`.

## Deduplication

Deduplicate by: `(rule_id, file, line, title)`. Keep highest severity/confidence on collision.

Applied both within batches and across the final merged set.

## Mandatory checklist linking

Every finding must include `checklist_item_ids` array:
1. Match finding's rule_id to checklist items via rulepack
2. Infer from checklist semantics if no direct match
3. Empty array as fallback if no reliable match

## Output

Required: `./.maia_auditor/findings.candidates.min.json`

```json
{
  "summary": {
    "batches_used": 4,
    "generalist_used": true,
    "detector_candidates": 0,
    "generalist_candidates": 0,
    "dedup_removed": 0,
    "total_candidates": 0
  },
  "findings": [
    {
      "id": "CF-001",
      "rule_id": "EVM-ACC-AUTH-01",
      "checklist_item_ids": ["CL-ACC-01"],
      "title": "Missing access control on set_fee",
      "severity": "high",
      "confidence": 0.85,
      "file": "contracts/Config.sol",
      "line": 42,
      "description": "...",
      "exploit_path": "...",
      "recommendation": "...",
      "evidence_signals": ["onlyOwner missing"],
      "status": "candidate"
    }
  ]
}
```

## Runtime progress

Follow `references/progress_protocol.md` and `references/output_budget.md`.
