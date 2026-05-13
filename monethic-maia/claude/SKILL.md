# monethic_maia

Monethic AI Auditor (MAIA) — Claude Code skill for automated smart contract security auditing.

## Invocation

```
/monethic_maia
```

## Startup

Always begin by printing the banner from `references/banner.md`.

Then ask the user for the target:

```
Point me to the code to audit, or press ENTER to use the current directory:
```

The user can provide:
- A directory path, subdirectory, current directory (ENTER), or path with `--exclude`

Store exclusions in `./.maia_auditor/exclusions.txt`. All stages skip excluded paths.

## Pipeline (6 phases)

### Phase 1: Bootstrap (`prompts/01_bootstrap.md`)
- Auto-detect platform (EVM / Move-Aptos / Move-Sui)
- Build scope manifest (`scope.md`) and concatenate source into `packed_source.txt` via bash
- Create working dirs
- Print: `Please wait a moment — you will be able to choose detectors soon.`

### Phase 2: Recon (`prompts/02_recon.md`)
- Read packed source, analyze context
- Produce `recon.md` (roles, entry points, state, dependencies, category recommendations)
- Present mode options: go / ALL / NUCLEAR / custom / force:{platform}
- After user picks, print: `Starting! Grab yourself a coffee ☕ — results should be ready in 5-15 minutes.`

### Phase 3: Analysis passes
- **3a. Checklist Plan** (`prompts/03_checklist_plan.md`) — map categories to rule IDs
- **3b. Evidence Map** (`prompts/04_scope_and_evidence.md`) — call graph, signals, state patterns from packed source
- **3c. Deep Sweep** (`prompts/05_deep_file_sweep.md`) — sink-first analysis using evidence map

### Phase 4: Audit — detector rounds (`prompts/06_candidate_generation.md`)

For each batch of ~3 categories / ~10 detectors, feed the LLM:
- `recon.md` + `packed_source.txt` + `evidence.map.min.json` + `deep_sweep.findings.min.json` + CAT-*.md files

Generalist (`prompts/generalist/generalist_{platform}.md`) is another round that always runs.

Debug output:
```
[detector batch 1/4] running: ACC, GEN, MATH (24 detectors)
[detector batch 1/4] complete: 7 candidates
...
[generalist] complete: 4 candidates
[merged] 20 candidates, 3 dedup removed → 17 total
```

All results merged and deduplicated.

### Phase 5: Verify (`prompts/07_adversarial_verifier.md`)
FP-first review: `false_positive`, `valid`, or `valid_downgraded`

### Phase 6: Report (`prompts/08_report_writer.md`)
Generate 4 files in `report_maia_{timestamp}/`:
- `{platform}_audit.html` ← primary output, clickable `file:///` link
- `{platform}_audit.md`
- `{platform}_audit_full.html`
- `{platform}_audit_full.md`

## NUCLEAR Mode

1. Load ALL categories from ALL platforms
2. Run all 3 generalists
3. Verifier applies cross-platform caution

## Knowledge

- **EVM**: 95 detectors / 20 categories in `evm/knowledge/`
- **Move-Aptos**: 49 detectors / 11 categories in `move-aptos/knowledge/`
- **Move-Sui**: 48 detectors / 11 categories in `move-sui/knowledge/`

## Skill Root

All paths are relative to the skill installation directory.
