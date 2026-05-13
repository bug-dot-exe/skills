# Workflow Overview

Six-phase audit pipeline for smart contracts (EVM, Move-Aptos, Move-Sui).

1. **Bootstrap** — Auto-detect platform, build scope manifest, concatenate source into `packed_source.txt` via bash
2. **Recon** — Pre-audit context analysis, recommend categories, present mode options to user
3. **Analysis passes** (sequential, each builds on the previous):
   - **3a. Checklist Plan** — Map selected categories to rule IDs, build coverage plan
   - **3b. Evidence Map** — Extract call graph, signals, state patterns from packed source
   - **3c. Deep Sweep** — Sink-first vulnerability discovery using evidence map for cross-function tracing
4. **Audit** — Run detector batches + generalist. Each batch: recon + packed source + evidence map + deep sweep + detectors. Merge and deduplicate all candidates.
5. **Adversarial Verifier** — FP-first review per finding: `false_positive`, `valid`, or `valid_downgraded`
6. **Report Writer** — Generate 4 report files in `report_maia_{timestamp}/`

## Supported Platforms

| Platform | Dir | Detectors | Categories |
|----------|-----|-----------|------------|
| EVM (Solidity) | `evm/` | 95 | 20 |
| Move-Aptos | `move-aptos/` | 49 | 11 |
| Move-Sui | `move-sui/` | 48 | 11 |

## Audit Modes

- **Recommended** (default): Only categories relevant to the detected project context
- **ALL**: All detectors for the detected platform
- **NUCLEAR**: All detectors across all platforms (cross-platform pattern matching, high FP rate)
- **Custom**: User-specified categories

## Knowledge Sources

- `{platform_dir}/knowledge/checklists/index.md` with `categories/CAT-*.md` files
- `{platform_dir}/knowledge/rulepack.md` for rule summaries
- `{platform_dir}/knowledge/checklist_router.md` for keyword-to-rule mapping

## Prompts

- `prompts/01_bootstrap.md` — phase 1
- `prompts/02_recon.md` — phase 2
- `prompts/03_checklist_plan.md` — phase 3a
- `prompts/04_scope_and_evidence.md` — phase 3b
- `prompts/05_deep_file_sweep.md` — phase 3c
- `prompts/06_candidate_generation.md` — phase 4 (detector batches)
- `prompts/generalist/generalist_{platform}.md` — phase 4 (generalist round)
- `prompts/07_adversarial_verifier.md` — phase 5
- `prompts/08_report_writer.md` — phase 6

## Deliverables

- `report_maia_{timestamp}/{platform}_audit.html` — Selected findings (HTML, primary output)
- `report_maia_{timestamp}/{platform}_audit.md` — Selected findings (Markdown)
- `report_maia_{timestamp}/{platform}_audit_full.html` — Full findings (HTML)
- `report_maia_{timestamp}/{platform}_audit_full.md` — Full findings (Markdown)
- `./.maia_auditor/` — Intermediate artifacts

Where `{platform}` is `evm`, `move_aptos`, or `move_sui`.
