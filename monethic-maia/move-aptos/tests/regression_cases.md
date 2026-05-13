# Regression Cases

Run whenever prompt workflow, rule knowledge, or report format changes.

## Full run

```
/move_aptos_auditor
```

## Validate outputs

- `<repo>/move_aptos_audit.md` exists
- `<repo>/move_aptos_audit.html` exists
- `<repo>/move_aptos_audit_full.md` exists
- `<repo>/move_aptos_audit_full.html` exists
- `<repo>/.move_aptos_auditor/recon.md` exists
- `<repo>/.move_aptos_auditor/findings.validated.min.json` exists

## Quality checks

- Bootstrap prints the banner from `references/banner.md`, then `move_aptos_auditor`.
- Recon runs first and produces a capped (~500 words) structured summary.
- Recon presents recommended categories to user.
- All selected category detectors run alongside generalist audit.
- Generalist audit always runs regardless of category selection.
- All findings (checklist + generalist) are merged before verification.
- Adversarial verifier reviews all merged findings with FP-first presumption.
- Report uses standard format: `[SEVERITY-##]` with sentence case title, description, impact, recommendation.
- Each finding includes impact, attack path, evidence, fix, and confidence.
- Findings are separated by `---`.
- Report includes Executive Snapshot, Severity Summary, Checklist Summary, Triage, Prioritized Remediation.
- `false_positive` findings are removed from selected report but present in full report.
- `valid_downgraded` findings include severity transition and explanation.
- Move-specific: Aptos resource model patterns correctly identified.
- Context-aware: irrelevant categories (e.g., CAT-LEND for NFT project) can be skipped.
- 4 output files generated: `.md` + `.html` for both selected and full reports.
- HTML reports include severity-colored badges and professional styling.
