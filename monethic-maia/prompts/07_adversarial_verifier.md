# Stage 07: Adversarial Verifier

Stage ID: `S07_ADVERSARIAL_VERIFY`

## Objective

Remove false positives and downgrade overstated findings through isolated, fresh reviews.

## Core stance

**Each finding begins with the presumption: "This is likely a false positive unless local evidence proves exploitability."**

## Verification process

For EACH candidate finding, independently:

1. **Verify references**: Do the cited file:line locations exist and contain the described code?
2. **Validate attack path**: Is the exploit scenario realistic given the actual architecture?
3. **Check scope**: Does the finding fall within the audit scope?
4. **Check mitigations**: Are there existing guards/checks that prevent exploitation?
5. **Deduplicate**: Same code lines + same root cause = same finding (keep highest severity)

## Reviewer constraints

- No cross-finding memory
- No prior decision context
- Input limited to finding payload and relevant code excerpts only

## Decision framework

Three outcomes:
1. **`false_positive`** — remove from final report
2. **`valid`** — retain unchanged
3. **`valid_downgraded`** — retain with reduced severity per `{platform_dir}/knowledge/severity_policy.md`

## Universal rejection criteria

- File/line references don't match actual code
- Attack path requires conditions the architecture prevents
- Finding is outside audit scope
- Finding describes intended behavior, not a bug
- Pattern matching on names without verifying actual logic
- Detector template is for wrong protocol type (e.g., lending template against NFT project)

---

## Platform: EVM

### EVM-specific rejection criteria
- Reentrancy claim but checks-effects-interactions pattern followed AND/OR `nonReentrant` modifier present
- Overflow/underflow claim but Solidity >= 0.8.0 and code is NOT in `unchecked` block
- Front-running claim but deployed on L2 with sequencer (no public mempool) — downgrade, don't reject
- Delegatecall risk but target address is hardcoded or immutable
- Storage collision claim but ERC-7201 namespaced storage (`@custom:storage-location`) is used
- Uninitialized proxy claim but `_disableInitializers()` is called in constructor
- Oracle staleness claim but freshness check (`updatedAt + heartbeat > block.timestamp`) is present
- Signature replay claim but nonce or EIP-712 domain separator with chain ID is used
- Gas optimization finding in code path that executes rarely (e.g., admin-only setup functions)

## Platform: Move-Aptos

### Move-Aptos-specific rejection criteria
- Missing signer check claim but signer is validated via capability pattern
- Overflow claim but Move's built-in overflow protection applies (non-`unchecked` arithmetic)
- Resource access claim but `acquires` annotation is correctly present
- Object transfer claim but ownership is verified via `object::is_owner`

## Platform: Move-Sui

### Move-Sui-specific rejection criteria
- Missing auth claim but capability object is required in function signature
- OTW bypass claim but struct correctly has `drop` only (no `copy`)
- Shared object race claim but object is actually owned, not shared
- Dynamic field claim but field access is properly guarded

---

## Output

Required: `./.maia_auditor/findings.validated.min.json`

```json
{
  "summary": {
    "total_reviewed": 0,
    "valid": 0,
    "valid_downgraded": 0,
    "false_positive_dropped": 0
  },
  "findings": [
    {
      "id": "CF-001",
      "verdict": "valid",
      "severity": "high",
      "confidence": 0.85,
      "reason": "Confirmed: setFee() at Config.sol:42 has no access control modifier",
      "original_severity": "high"
    }
  ]
}
```

## Runtime progress

Follow `references/progress_protocol.md` and `references/output_budget.md`.
Always emit verifier `decision` events.
