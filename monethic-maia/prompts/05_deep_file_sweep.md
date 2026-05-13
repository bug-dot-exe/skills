# Stage 05: Deep File Sweep (Sink-First)

Stage ID: `S05_DEEP_SWEEP`

## Objective

Independently identify genuine, exploitable vulnerabilities using sink-first analysis.

Read detected platform from `./.maia_auditor/platform.txt`.

## Source code

Read the full source from `./.maia_auditor/packed_source.txt`. Use the evidence map from `./.maia_auditor/evidence.map.min.json` for call graph context. Do NOT re-read individual files.

## Analysis strategy

1. **Identify high-risk sinks first**: Scan `packed_source.txt` for dangerous patterns (see platform-specific sinks below).
2. **Trace backwards from each sink**: Who can reach it, what preconditions are needed, what state is affected.
3. **Use evidence map**: Cross-reference sinks with call graph from `evidence.map.min.json` to find cross-function and cross-contract attack paths.
4. **Exploitability focus**: Every finding must demonstrate a concrete attack path with preconditions. Unclear exploitability receives lower confidence.

---

## Platform: EVM

### High-risk sinks
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

### Focus areas
- **Reentrancy**: Classic (state after call), cross-function, cross-contract, read-only reentrancy
- **Front-running / MEV**: Missing slippage protection, no deadline, commit-reveal absence
- **Storage collisions**: Upgradeable contracts without `__gap` or ERC-7201 namespaced storage
- **ERC-20 approval races**: `approve` without reset-to-zero
- **Signature malleability**: Missing `s` value check, no EIP-712 domain separator
- **Oracle manipulation**: Spot price used without TWAP, stale price without freshness check
- **Flash loan attacks**: State manipulation within single transaction
- **Integer overflow in assembly**: Solidity >=0.8 doesn't protect `unchecked` blocks or assembly
- **Proxy initialization**: Uninitialized implementation contracts, missing `_disableInitializers()`

## Platform: Move-Aptos

### High-risk sinks
- `borrow_global_mut` on shared resources without access control
- `move_from` / `move_to` without ownership checks
- `coin::transfer` / `coin::mint` without authorization
- `object::transfer` without ownership verification
- `account::create_signer_with_capability` — SignerCapability usage
- Arithmetic operations without overflow protection
- Missing `acquires` annotations
- `public entry` functions without signer validation

### Focus areas
- Resource account SignerCapability misuse
- ConstructorRef leaks enabling object reclaim
- Object co-location causing unintended transfers
- Mutable reference swap attacks (`mem::swap`)
- Function value reentrancy (Move 2.2+)
- Missing `acquires` causing runtime aborts
- Phantom type auth bypass
- `public(friend) entry` visibility anti-pattern
- Flash loan attack vectors on pools
- Oracle price manipulation
- Decimal precision mismatches across assets

## Platform: Move-Sui

### High-risk sinks
- `transfer::public_transfer` / `transfer::transfer` without ownership checks
- `coin::mint` / `coin::burn` without authorization
- Shared object mutations without proper access control
- OTW structs with `copy` ability
- `dynamic_field::remove` without validation
- Arithmetic operations without overflow protection
- Missing `public(friend)` on internal functions
- `public entry` functions without sender validation

### Focus areas
- One-Time Witness (OTW) bypass — `copy` ability on witness struct
- Shared object race conditions
- Dynamic field manipulation attacks
- Missing object ownership verification
- Witness pattern violations
- Hot potato drop/store ability issues
- Flash loan attack vectors on pools
- Oracle price manipulation
- Decimal precision mismatches

---

## Output files

Required: `./.maia_auditor/deep_sweep.findings.min.json`

### Finding schema

```json
{
  "findings": [
    {
      "id": "DS-001",
      "severity": "high",
      "file": "contracts/Vault.sol",
      "line": 142,
      "title": "Missing access control on withdraw",
      "exploit_path": "Any user can call withdraw() and drain the vault",
      "preconditions": ["Function is external", "No access control modifier"],
      "confidence": 0.85
    }
  ]
}
```

## Constraints

- No in-scope file can be skipped.
- Do not duplicate findings across windows.
- Quality over quantity — only report findings you can substantiate.
- Follow `references/progress_protocol.md` and `references/output_budget.md`.
