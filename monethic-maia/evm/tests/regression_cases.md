# Regression Cases

Run whenever prompt workflow, rule knowledge, or report format changes.

## Full run

```
/monethic_maia
```

Point at a Solidity project. Auto-detection should identify EVM platform.

## Validate outputs

- `<repo>/evm_audit.md` exists
- `<repo>/evm_audit.html` exists
- `<repo>/evm_audit_full.md` exists
- `<repo>/evm_audit_full.html` exists
- `<repo>/.maia_auditor/recon.md` exists
- `<repo>/.maia_auditor/platform.txt` contains `evm`
- `<repo>/.maia_auditor/findings.validated.min.json` exists

## Quality checks

- Bootstrap auto-detects `.sol` files + build config as EVM platform.
- Recon runs first and produces a capped (~500 words) structured summary.
- Recon presents recommended categories (from 20 EVM categories) to user.
- User can select go/ALL/NUCLEAR/custom categories.
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
- Context-aware: irrelevant categories (e.g., CAT-LEND for NFT project) can be skipped.
- 4 output files generated: `.md` + `.html` for both selected and full reports.
- HTML reports include severity-colored badges and professional styling.

## EVM-specific regression checks

### Access control
- Unprotected `initialize()` without `initializer` modifier should trigger CL-PROXY-04
- Missing `onlyOwner` on admin function should trigger CL-ACC-01
- `tx.origin` used for auth should trigger CL-ACC-01

### Reentrancy
- Classic CEI violation (state update after external call) should trigger CL-GEN-08
- Read-only reentrancy (view returns stale state during callback) should trigger CL-GEN-08
- Function with `nonReentrant` modifier: verifier should NOT flag reentrancy

### Token handling
- `transfer()` without return value check should trigger CL-ERC20-02
- Fee-on-transfer token not handled should trigger CL-ERC20-01
- Missing `SafeERC20` usage should trigger CL-ERC20-02

### Proxy and upgrades
- Storage collision in upgradeable contract should trigger CL-PROXY-07
- Missing `_disableInitializers()` in constructor should trigger CL-PROXY-04
- UUPS without `_authorizeUpgrade` restriction should trigger CL-PROXY-08

### Oracle
- Stale price (no freshness check on `latestRoundData`) should trigger CL-ORACLE-05
- Spot price used without TWAP protection should trigger CL-ORACLE-04

### Vault
- First depositor attack (no minimum deposit) should trigger CL-VAULT-04
- Share inflation via donation should trigger CL-VAULT-04
- Vault formula `shares = amount * totalShares / totalPool` without ERC-4626 import: recon should recommend VAULT category

### Math
- Overflow in `unchecked` block should trigger CL-MATH-03
- Division before multiplication (precision loss) should trigger CL-MATH-02
- Solidity >= 0.8 arithmetic outside `unchecked`: verifier should NOT flag overflow

### Flash loan
- Callback without caller validation should trigger CL-GEN-01 or CL-ACC-01

## NUCLEAR mode check

- Select NUCLEAR: loads all detectors from EVM + Move-Aptos + Move-Sui
- Cross-platform pattern matching runs (vault math, oracle freshness, access control)
- Higher FP rate expected: verifier adds cross-platform caution context

## Platform override check

- Feed a Solidity project: auto-detects EVM
- Type `force:move-aptos`: overrides to Move-Aptos pipeline
- Should gracefully report no Move files found
