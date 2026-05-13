---
name: monethic_maia
description: Monethic AI Auditor (MAIA) - Smart contract security audit engine for EVM, Move-Aptos, and Move-Sui projects. Use for automated multi-phase security audits with over 192 detectors across all platforms.
---

# monethic_maia

Monethic AI Auditor (MAIA) — Smart contract security audit engine.

## Invocation

```
/monethic_maia
```

## Startup

1. Print the banner from `references/banner.md`
2. Ask user for the target to audit:

```
Point me to the code to audit, or press ENTER to use the current directory:
```

The user can provide:
- A directory path (e.g., `/path/to/project`)
- A specific subdirectory (e.g., `/path/to/project/src`)
- Current directory (press ENTER)
- Path with exclusions (e.g., `. --exclude contracts/mocks tests/`)

### Out-of-scope handling

If the user specifies `--exclude` paths, store them in `./.maia_auditor/exclusions.txt` (one path per line). All pipeline stages must skip excluded paths.

## Audit Pipeline

### Phase 1: Bootstrap (`prompts/01_bootstrap.md`)
- Auto-detect platform (EVM / Move-Aptos / Move-Sui)
- Build scope manifest (`scope.md` — file list with line counts)
- Concatenate all in-scope source into `./.maia_auditor/packed_source.txt` (one file, with `// === FILE: path ===` headers between files)
- Create output dirs (`.maia_auditor/`, `report_maia_{timestamp}/`)
- Print: `Please wait a moment — you will be able to choose detectors soon.`

### Phase 2: Recon (`prompts/02_recon.md`)
- Read `packed_source.txt`, identify project context
- Produce `recon.md` — roles, entry points, state, dependencies, recommended categories
- Present options to user:

```
Detected: {Platform} project
Context: {context summary}
Recommended detectors: {categories} = {total} detectors

Options:
- ENTER / 'go'    → run recommended detectors
- 'ALL'           → all detectors for this platform
- 'NUCLEAR'       → all detectors across all platforms
- 'ACC LEND'      → pick specific categories
- 'force:evm'     → override detected platform
```

After user picks mode, print: `Starting! Grab yourself a coffee ☕ — results should be ready in 5-15 minutes.`

### Phase 3: Analysis passes

Three sequential analysis passes build context before detector batches run:

**3a. Checklist Plan** (`prompts/03_checklist_plan.md`)
- Load `index.md` + `checklist_router.md` for the detected platform
- Map selected categories to rule IDs
- Output: `checklist.plan.min.json`

**3b. Evidence Map** (`prompts/04_scope_and_evidence.md`)
- Read `packed_source.txt`, extract function call graph, access control signals, state patterns
- Build structural model of the codebase (who calls what, what state each function touches)
- Output: `evidence.map.min.json`

**3c. Deep Sweep** (`prompts/05_deep_file_sweep.md`)
- Sink-first analysis: start from dangerous patterns, trace backwards
- Independent from detectors — finds things no detector explicitly covers
- Uses evidence map for cross-function flow tracing
- Output: `deep_sweep.findings.min.json`

### Phase 4: Audit — detector rounds (`prompts/06_candidate_generation.md`)

Group selected categories into batches of ~3 categories / ~10 detectors.

For EACH batch, feed the LLM:
1. **Context** — `./.maia_auditor/recon.md`
2. **Code** — `./.maia_auditor/packed_source.txt`
3. **Evidence map** — `./.maia_auditor/evidence.map.min.json`
4. **Deep sweep** — `./.maia_auditor/deep_sweep.findings.min.json`
5. **Detectors** — the CAT-*.md file(s) for this batch's categories

The LLM applies each detector's Detect steps against the full source code, uses the evidence map for cross-function tracing, and cross-references deep sweep findings.

```
[detector batch 1/N] running: ACC, GEN, MATH (24 detectors)
[detector batch 1/N] complete: 7 candidates
[detector batch 2/N] running: LEND, ORACLE, VAULT (19 detectors)
[detector batch 2/N] complete: 5 candidates
...
```

**Generalist** is just another round that always runs:
- Feed: recon context + packed source + `prompts/generalist/generalist_{platform}.md`
- Same process, different "detector set"

```
[generalist] running full-spectrum audit
[generalist] complete: 4 candidates
```

Merge all batch results + generalist results. Deduplicate by `(rule_id, file, line, title)`.

### Phase 5: Verify (`prompts/07_adversarial_verifier.md`)
- FP-first review of all merged candidates
- Each finding: `false_positive`, `valid`, or `valid_downgraded`

### Phase 6: Report (`prompts/08_report_writer.md`)
- Generate 4 files in `report_maia_{timestamp}/`
- Output clickable `file:///` link to HTML report

## NUCLEAR Mode

When user selects NUCLEAR:
1. Load ALL detector categories from ALL platforms (EVM 20 cats + Move-Aptos 11 cats + Move-Sui 11 cats)
2. Run all 3 generalists as separate rounds
3. Verifier applies cross-platform caution

## Platform directories

- **EVM**: `evm/knowledge/` — 95 detectors across 20 categories
- **Move-Aptos**: `move-aptos/knowledge/` — 49 detectors across 11 categories
- **Move-Sui**: `move-sui/knowledge/` — 48 detectors across 11 categories

## Platform Integrations

- **Claude Code**: See `claude/SKILL.md`
