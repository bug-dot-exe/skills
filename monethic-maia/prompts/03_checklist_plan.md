# Stage 03: Checklist Plan (Pre-Analysis)

Stage ID: `S03_CHECKLIST_PLAN`

## Objective

Load checklist index and build a low-token coverage plan.
This stage defines coverage intent only (no PASS/FAIL yet).

## Inputs

Read detected platform from `./.maia_auditor/platform.txt`, then load:

- `{platform_dir}/knowledge/checklists/index.md` (primary)
- `{platform_dir}/knowledge/checklists/categories/CAT-*.md` (lazy detail only)
- `{platform_dir}/knowledge/rulepack.md`
- `{platform_dir}/knowledge/checklist_router.md`

Where `{platform_dir}` is:
- EVM → `evm`
- Move-Aptos → `move-aptos`
- Move-Sui → `move-sui`

## Parsing contract (index-first)

1. Read `index.md`.
2. Parse category table under `## Categories`.
3. Parse item lists under `## Checklist Items`.

Do not rewrite checklist text. Build normalized metadata in memory only.

## Stable internal IDs

Use item IDs from `index.md` directly (e.g., `CL-ACC-01` for all platforms).

## Mapping policy

For each checklist item title:

1. **Explicit mapping**: if title contains a rule ID, use it directly. `mapping_mode = "explicit"`.
2. **Inferred mapping**: infer from title keywords using `knowledge/checklist_router.md`. `mapping_mode = "inferred"`.
3. **AI-only coverage**: when rulepack has no suitable rule, set `rule_ids = ["AI-ONLY"]`. `mapping_mode = "ai_only"`.

Populate only minimal evidence hints:
- `expected_evidence`: short code signals for later stages.

## Context-aware filtering

Use recon output from `./.maia_auditor/recon.md` to skip irrelevant categories.

## Lazy detail loading

- Do not load category detail markdown by default.
- Load `categories/CAT-*.md` only when a later stage needs exact description/remediation wording.

## Important constraints

- Do NOT assign `PASS` / `FAIL` / `UNKNOWN` in this stage.
- If checklist is missing, emit an empty plan with `available: false`.
- Write plan artifacts in a single write operation per file.
- Do not print checklist item details to terminal.
- If direct write fails, retry once via shell heredoc.
- Follow `references/output_budget.md`.

## Output files

Required: `./.maia_auditor/checklist.plan.min.json`

### `checklist.plan.min.json` schema

```json
{
  "platform": "evm|move-aptos|move-sui",
  "summary": {
    "available": true,
    "total_categories": 0,
    "total_items": 0,
    "explicit_mappings": 0,
    "inferred_mappings": 0,
    "ai_only_items": 0,
    "skipped_categories": []
  },
  "categories": [
    {"id": "CAT-ACC", "title": "Access Control", "item_count": 0}
  ],
  "items": [
    {
      "id": "CL-ACC-01",
      "title": "Access Control Enforcement",
      "rule_ids": ["EVM-ACC-AUTH-01"],
      "mapping_mode": "explicit",
      "expected_evidence": ["onlyOwner", "modifier", "require(msg.sender"]
    }
  ]
}
```

## Runtime progress output

Follow `references/progress_protocol.md`. In terse mode emit only:
- `stage_start` at checklist parse start
- `metric` summary (`total_categories`, `total_items`, mappings)
- `stage_end` with planning summary
