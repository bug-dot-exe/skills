# Generalist — Full-Spectrum Security Audit

## Objective

Perform a full-spectrum security audit of the provided Aptos Move program. This is an independent audit flow that does not rely on checklist templates — instead it applies comprehensive security analysis from first principles.

## Methodology

### 1. Global Coverage

- Apply every check in your knowledge base, plus all items in the checklist below.
- Review all modules, functions (entry, public, private), structs, resources, and test files.
- Examine all potential severities: Critical, High, Medium, Low, and Informational.
- Trace execution flow, including inter-contract calls, and analyze potential gas usage issues (computation and storage).
- Inspect edge cases, boundary conditions, and logic for collections like `vector` and `table`.

### 2. Aptos Move-Specific Checklist (must be covered at minimum)

**Authentication & Access Control:**
- Correct use of `&signer` for all privileged actions.
- Validation that `signer::address_of` matches expected admin/owner addresses.
- No unintended entry functions exposing internal logic.
- Proper use of `public(friend)` for module-to-module interactions.

**Resource and State Management:**
- `exists<T>` checks before all `borrow_global` and `move_from` calls.
- No stale state after operations (e.g., counters not updated, records not cleared).
- Correct resource creation (`move_to`) and destruction patterns.
- Prevention of storage bloating via zero-amount operations or unbounded vector pushes.

**Storage and Objects:**
- For every storage item / variable / object used, verify it is used properly — loaded from proper parent structure, from proper global or object storage, with no mismatches (e.g., function A saves variable X to global storage, but function B means to access the same object from object storage, leading to impact).

**Arithmetic Safety:**
- `assert!` checks or conditional logic to prevent underflow/overflow aborts.
- No division before multiplication to avoid precision loss.
- Careful handling of `u64`, `u128`, and `u256` types.
- Validation that user-provided amount matches `coin::value`.

**Coin & Token Handling:**
- `coin::is_account_registered<T>` checks before `coin::deposit`.
- Correct handling of `MintCapability` and `BurnCapability` (stored securely, not exposed).
- No risk of creating unbacked or unaccounted-for coins.

**Data Structures & Logic:**
- Validation of `vector` and `table` access to prevent out-of-bounds errors.
- Validation of input parameters to prevent invalid state (e.g., empty IDs, incorrect enums).
- Handling of matching inputs (`token_a == token_b`) where distinct inputs are expected.
- Correct use and validation of phantom type parameters for access control.

**Events and View Functions:**
- Emission of events for all critical state changes.
- No state mutations within functions intended to be read-only (view).

### 3. Best-Practice & Code-Quality Checks (Informational)

- Unclear or misleading function and parameter names.
- TODO / FIXME comments left in production paths.
- Redundant code, repetitive `assert!` checks, or overly complex logic.
- Missing events for important user or admin actions.
- Inefficient use of storage or computation.

### 4. Realistic Findings Only

Report exploitable paths or concrete best-practice deviations. Ignore purely theoretical issues that have no practical impact. Do not flag intended administrative powers as vulnerabilities unless they can be misused by unauthorized actors.

## Output Format

For each finding:

```
[SEVERITY-##] Title in sentence case

Description + Vulnerability Details
[Root cause → attack flow → security impact as confluent text]

[FOR HIGH/MEDIUM: unmodified code snippet]

Impact
[Concrete impact in 1-2 sentences]

Recommendation
[Specific technical fix in 1-2 sentences]
```

Write findings to `./.maia_auditor/generalist.findings.json`

## Summary

At the end, provide:
```
Total Critical: X
Total High: X
Total Medium: X
Total Low: X
Total Informational: X
```
