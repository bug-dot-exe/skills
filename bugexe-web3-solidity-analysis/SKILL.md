---
name: solidity-analysis
category: web3
description: Solidity code analysis covering common vulnerability patterns, gas optimization as security risks, storage layout issues, and proxy/upgrade patterns
depends_on: []
---

# Solidity Code Analysis

Security-focused static analysis of Solidity smart contracts. Focus on common vulnerability patterns (reentrancy, overflow, access control), gas optimization issues that create security risks, storage layout concerns, and proxy/upgrade patterns.

## When to Use

- Reviewing Solidity source code for security vulnerabilities
- Auditing proxy/upgradeable contract implementations
- Analyzing gas optimizations for unintended security side effects
- Reviewing storage layout for collision or corruption risks
- Pre-audit code review to identify high-priority areas for deep analysis

## Methodology

### 1. Reentrancy Patterns

- **CEI violation**: external call before state update in the same function
- **Cross-function**: function A calls external, function B reads state A has not yet updated
- **Cross-contract**: contract A calls external, attacker reenters contract B that reads A's stale state
- **Read-only**: view function returns incorrect value during callback execution
- **ERC-721/1155 callbacks**: `safeTransferFrom` triggers `onERC721Received`/`onERC1155Received` callbacks
- Search: all `.call{`, `.transfer(`, `.send(`, `safeTransferFrom`, `safeTransfer` — check state writes after each

### 2. Access Control Flaws

- **Missing modifiers**: state-modifying functions without `onlyOwner`, `onlyRole`, or `require(msg.sender ==)`
- **tx.origin misuse**: `require(tx.origin == owner)` bypassed via intermediary contract
- **Initializer exposure**: `initialize()` callable by anyone if not protected or already called
- **Role hierarchy gaps**: role A can grant role B with higher privileges than A holds
- **Self-destruct/delegatecall unprotected**: critical functions without access restriction
- Search: all `public`/`external` functions that modify storage — verify access control on each

### 3. Integer and Arithmetic Issues

- **Unchecked blocks**: `unchecked { }` arithmetic without validating inputs are within safe ranges
- **Unsafe downcasting**: `uint256` to `uint128`/`uint96` without overflow check (use SafeCast)
- **Division before multiplication**: `(a / b) * c` loses precision; correct is `(a * c) / b`
- **Rounding direction**: share calculations should round against the user (down on deposit, up on withdrawal)
- **Signed/unsigned conversion**: `int256(uint256)` with values exceeding `type(int256).max`
- Search: all `unchecked` blocks, all casts between integer types, all division operations

### 4. Gas Optimization as Security Risk

- **Short-circuit removal**: gas-optimizing conditional order may skip critical checks
- **Storage packing unsafety**: packing multiple values into one slot without proper masking
- **Assembly for gas savings**: inline assembly bypasses Solidity safety checks (overflow, bounds)
- **Memory vs calldata confusion**: function expects `calldata` but is called internally with `memory` data
- **Tight variable packing**: struct packing may cause silent truncation on write
- Review: every `assembly` block for missing overflow checks; every packed struct for masking correctness

### 5. Storage Layout Issues

- **Proxy storage collision**: implementation storage variables overlap with proxy storage slots
- **EIP-1967 compliance**: verify implementation/admin/beacon slots use correct EIP-1967 addresses
- **Inheritance ordering**: changing base contract order shifts storage slot assignments
- **Gap variables**: upgradeable contracts missing `__gap` arrays for future storage expansion
- **Diamond storage conflicts**: multiple facets writing to overlapping storage namespaces
- Verify: `forge inspect {Contract} storage-layout` — compare proxy and implementation layouts

### 6. Proxy and Upgrade Patterns

- **Uninitialized implementation**: implementation contract's constructor is a no-op in proxy context; check for `_disableInitializers()`
- **Function selector clash**: proxy admin functions collide with implementation function selectors
- **UUPS missing upgrade guard**: `_authorizeUpgrade` not overridden or has insufficient access control
- **Transparent proxy admin access**: admin can accidentally call implementation functions via proxy
- **Beacon manipulation**: beacon address changed to point to malicious implementation
- Check: is the implementation initialized? Is upgrade restricted? Are selectors collision-free?

### 7. Common Code Smells

- **Unchecked return values**: low-level `.call()` return value not checked (`(bool success,) = addr.call(...)`)
- **Hardcoded addresses**: addresses that should be configurable are hardcoded (wrong on other chains)
- **Missing event emissions**: state changes without events break off-chain monitoring and indexing
- **Floating pragma**: `pragma solidity ^0.8.0` allows compilation with any 0.8.x version
- **Unused variables and imports**: dead code that increases attack surface and deployment cost
- **Block.timestamp dependency**: time-sensitive logic using `block.timestamp` manipulable by miners within ~15s
- Search: all low-level calls for unchecked returns; all events for missing emissions on state changes

## Key Commands

```bash
# Static analysis with Slither
slither . --detect reentrancy-eth,reentrancy-no-eth,uninitialized-state,controlled-delegatecall
slither . --print human-summary
slither . --print function-summary

# Storage layout inspection
forge inspect {Contract} storage-layout
forge inspect {Contract} abi

# Compile and check
forge build --force
forge test -vvv

# Find patterns
grep -rn "unchecked" contracts/
grep -rn "assembly" contracts/
grep -rn "delegatecall\|selfdestruct\|suicide" contracts/
```

## Validation

- Demonstrate reentrancy with a PoC contract that exploits the callback to extract additional funds
- Show access control flaw with an unauthorized caller successfully executing a restricted function
- Prove arithmetic issue with concrete input values that produce incorrect or overflowed results
- Confirm storage collision with forge inspect output showing overlapping slot assignments
- Document vulnerable code, specific line numbers, and a minimal test case reproducing the issue
