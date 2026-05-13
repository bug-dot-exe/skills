# Generalist — Full-Spectrum EVM/Solidity Security Audit

## Objective

Perform a full-spectrum security audit of the provided Solidity/EVM smart contracts. This is an independent audit flow that does not rely on checklist templates — instead it applies comprehensive security analysis from first principles.

## Methodology

### 1. Sink-First Pass (do this FIRST)

Before applying the checklist, scan for high-risk sinks — these are the most dangerous patterns and should be checked first:
- `call` / `delegatecall` / `staticcall` without reentrancy guards
- `selfdestruct` / `SELFDESTRUCT` opcode usage
- `tx.origin` used for authorization
- `ecrecover` returning `address(0)` without check
- Unprotected `initialize()` functions (missing `initializer` modifier)
- Storage slot collisions in proxy/upgradeable contracts
- Inline assembly `sstore` / `sload` — manual storage manipulation
- Flash loan callbacks (`onFlashLoan`, `executeOperation`) without caller validation
- `transferFrom` without return value check (non-standard ERC-20)
- Unchecked low-level call return values

For each sink found, trace backwards: who can reach it, what preconditions are needed, what state is affected.

### 2. Global Coverage

- Apply every check in your knowledge base, plus all items in the checklist below.
- Review all contracts, functions (external, public, internal, private), structs, events, and modifiers.
- Examine all potential severities: Critical, High, Medium, Low, and Informational.
- Trace execution flow, including inter-contract calls, delegate calls, and proxy patterns.
- Inspect edge cases, boundary conditions, and logic for mappings, arrays, and structs.

### 3. EVM/Solidity-Specific Checklist (must be covered at minimum)

**Authentication & Access Control:**
- Correct use of `onlyOwner`, `onlyRole`, access control modifiers for all privileged actions
- No use of `tx.origin` for authentication
- Unprotected `initialize()` functions in upgradeable contracts
- Proper use of `internal` / `private` for helper functions not meant to be called externally
- No unintended `external` / `public` visibility exposing sensitive logic
- Missing zero-address checks on critical address parameters

**Reentrancy:**
- Checks-Effects-Interactions (CEI) pattern followed for all external calls
- `nonReentrant` modifier on functions that transfer value or call external contracts
- Cross-function reentrancy: shared state between functions where one has external calls
- Cross-contract reentrancy: callback to another contract that reads stale state
- Read-only reentrancy: view functions returning stale state during callbacks

**Token Handling (ERC-20/721/1155):**
- Return value checking for `transfer` / `transferFrom` (non-standard tokens)
- Use of `SafeERC20` for token interactions
- `approve` race condition — reset to zero before setting new allowance
- Fee-on-transfer token handling (actual received amount vs parameter)
- Rebasing token handling (balance changes without transfers)
- ERC-777 callback hooks enabling reentrancy
- Token decimal precision mismatches between different tokens

**Proxy & Upgrades:**
- Storage layout consistency between proxy versions (no storage collisions)
- `initializer` modifier on initialization functions
- `_disableInitializers()` in implementation constructor
- UUPS: `_authorizeUpgrade` properly restricted
- No `selfdestruct` on implementation contracts
- Storage gaps (`__gap`) in base contracts for future variables
- ERC-7201 namespaced storage for collision resistance

**Low-Level Calls:**
- Return value checking for `call`, `delegatecall`, `staticcall`
- `delegatecall` context preservation (storage, msg.sender, msg.value)
- No `delegatecall` to untrusted/user-controlled addresses
- Proper handling of `staticcall` (no state modifications)

**Flash Loans:**
- Callback authentication (verify `msg.sender` is the expected pool/lender)
- State manipulation within single transaction
- Price oracle manipulation via flash-loaned liquidity
- Profit extraction through flash loan + vulnerable function combo

**Front-Running & MEV:**
- Slippage protection on all swap/trade operations
- Deadline parameters on time-sensitive operations
- Commit-reveal patterns for sensitive operations
- Sandwich attack resistance on large trades

**Assembly & Low-Level:**
- Memory corruption in `assembly` blocks
- `returndata` handling correctness
- Overflow/underflow in assembly (no Solidity 0.8 protection)
- `extcodesize` check reliability (can be bypassed during construction)
- Proper free memory pointer management

**Gas & DoS:**
- Unbounded loops over dynamic arrays or mappings
- External call failures in loops causing full revert (pull over push)
- Block gas limit issues with large state iterations
- Griefing via dust amounts or spam

**Oracle & Price Feeds:**
- Stale price data (missing `updatedAt` freshness check)
- Round completeness verification (`answeredInRound >= roundId`)
- Fallback oracle for Chainlink downtime
- Spot price manipulation resistance (TWAP vs spot)
- L2 sequencer uptime check for L2 deployments

**Cross-Chain:**
- Message replay across chains (missing chain ID in signatures/hashes)
- Cross-chain message authentication (verify source chain and sender)
- Bridge invariant preservation (total supply across chains)

**Governance:**
- Flash loan governance attacks (borrow voting power)
- Proposal execution delay / timelock
- Quorum manipulation
- Vote delegation correctness

### 4. Best-Practice & Code-Quality Checks (Informational)

- Unclear or misleading function and parameter names
- TODO / FIXME comments left in production paths
- Redundant code, repetitive require statements, or overly complex logic
- Missing events for important state changes
- Inefficient storage usage (packing, unnecessary SLOADs)
- Missing NatSpec documentation on external/public functions
- Use of deprecated Solidity features

### 5. Realistic Findings Only

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
