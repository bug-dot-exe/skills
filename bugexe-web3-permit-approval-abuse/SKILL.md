---
name: permit-approval-abuse
category: web3
description: ERC-20 permit and approval abuse covering unlimited approval exploitation, permit signature replay, approval front-running, and Permit2 universal router attacks
depends_on: []
---

# ERC-20 Permit and Approval Abuse

Security testing for token approval and permit mechanisms. Focus on unlimited approval exploitation, permit signature replay, approval front-running, Permit2 universal router attacks, and allowance management flaws.

## When to Use

- Target protocol requests ERC-20 token approvals from users
- ERC-2612 permit functionality is used for gasless approvals
- Uniswap Permit2 or similar universal approval routers are integrated
- dApp manages or caches approval state for user convenience
- Protocol uses approval-based token transfer patterns (transferFrom)

## Methodology

### 1. Unlimited Approval Exploitation

- **Max approval pattern**: protocol requests `type(uint256).max` approval for user convenience
- **Upgradeable spender risk**: approved contract is upgradeable; new implementation can drain tokens
- **Proxy approval persistence**: approval granted to proxy survives implementation upgrade
- **Multi-function exposure**: approval intended for one function is usable by any function calling transferFrom
- **Dormant approval drain**: user forgets about old approval; contract is later compromised
- Check: what amount does the dApp request? Is the spender contract upgradeable? Can approval be scoped?

### 2. Permit Signature Replay

- **Same-chain replay**: permit signature used once but nonce not incremented due to contract bug
- **Cross-chain replay**: permit signed for mainnet replayed on L2 where the same token is deployed
- **Cross-contract replay**: permit domain separator missing `verifyingContract`, accepted by different token
- **Expired permit acceptance**: `deadline` parameter checked with `<=` instead of `<`, or not checked at all
- **Nonce skip vulnerability**: attacker invalidates legitimate permits by consuming nonces out of order
- Check: trace permit signature from creation through on-chain verification; verify nonce, chainId, contract address

### 3. Approval Front-Running

- **Classic race condition**: user changes approval from N to M; attacker spends N before the update, then spends M
- **Mitigation check**: does the token use `increaseAllowance`/`decreaseAllowance` or require reset to 0?
- **Permit front-running**: attacker observes permit in mempool, front-runs with their own transferFrom
- **Batch approval race**: in a multicall, approval set in call 1 is exploited before call 2 executes
- **Griefing via approval reset**: attacker front-runs to reset approval to 0, breaking dependent transactions
- Test: approve a contract for N tokens, then submit a new approval for M; check if N can be spent first

### 4. Permit2 Universal Router Attacks

- **Broad Permit2 approval**: user approves Permit2 for max amount; any Permit2-integrated contract can request transfers
- **Signature transfer abuse**: `SignatureTransfer` permits with overly broad `spender` or `token` fields
- **Allowance transfer misconfiguration**: `AllowanceTransfer` with expiration set too far in the future
- **Batch permit manipulation**: batch SignatureTransfer with one legitimate and one malicious transfer
- **Unordered nonce exploitation**: `UnorderedNonceTransfer` allows out-of-sequence consumption
- Check: what Permit2 mode does the protocol use? What are the expiration and amount parameters?

### 5. Allowance State Management

- **Stale allowance display**: frontend shows outdated approval state, misleading users
- **Allowance caching**: protocol caches allowance value and does not detect on-chain changes
- **Multiple spender confusion**: same tokens approved to multiple contracts; total exposure exceeds balance
- **Token-specific quirks**: USDT requires approval reset to 0 before setting new value; some tokens revert on non-zero to non-zero
- **Disapproval mechanism absence**: no way for users to revoke approvals through the dApp interface
- Check: does the protocol handle USDT-style approval? Is there a revocation UI? Are approvals tracked?

### 6. Approval Interaction with Protocol Logic

- **Pull payment timing**: protocol calls transferFrom at unexpected times (liquidation, rebalance)
- **Approval check before action**: protocol checks allowance but does not verify it still exists at execution time
- **Conditional approval consumption**: approval consumed in a revert path, leaving insufficient allowance for the happy path
- **Delegated spending conflicts**: multiple protocol features compete for the same approval allowance
- **Gas griefing via approval**: trigger transferFrom with insufficient approval to waste gas without state change
- Trace: map every transferFrom call site in the protocol and identify the approval dependency for each

## Key Commands

```bash
# Check current allowance
cast call {token} "allowance(address,address)(uint256)" {owner} {spender}

# Check Permit2 allowance
cast call {permit2} "allowance(address,address,address)(uint160,uint48,uint48)" {owner} {token} {spender}

# Check nonces
cast call {token} "nonces(address)(uint256)" {owner}

# Decode permit signature
cast abi-decode "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)" {calldata}
```

### 7. Approval Phishing and Social Engineering Vectors

**Malicious dApp approval requests**
- Attacker deploys a dApp that requests max approval to a malicious contract
- Contract appears to be a DEX router or vault but contains a `drain()` function callable by the attacker
- Detection: is the approved spender address a verified, audited contract? Is the spender upgradeable?

**Approval to upgradeable contract**
- User approves a legitimate upgradeable contract; after the approval, the contract is upgraded to include a drain function
- The approval persists across upgrades -- the proxy address does not change
- Detection: does the protocol's upgrade mechanism require re-approval? Is there a timelock on upgrades that gives users time to revoke?

**Batch approval via multicall**
- Some protocols bundle multiple approvals in a single multicall transaction
- User approves multiple tokens in one click without reviewing each individually
- Malicious dApp can include extra approvals in the batch that the user does not notice
- Detection: does the dApp show each approval individually? Can the multicall include unexpected approvals?

### 8. Cross-Protocol Approval Risks

**Shared router approval**
- User approves a shared router (e.g., DEX aggregator) for Token A
- The same router is used by multiple protocols; any protocol integrated with the router can request transfers of Token A
- Detection: does the router enforce per-protocol transfer limits? Can any integrated protocol call `transferFrom` on the router's behalf?

**Deprecated protocol approval persistence**
- User approved a protocol that is now deprecated or compromised
- The approval remains active indefinitely unless the user explicitly revokes
- Old protocol's admin keys may be less secure than during active development
- Detection: does the protocol have a deprecation plan that revokes or limits approvals? Is there a UI for users to discover and revoke stale approvals?

**Approval delegation chains**
- Protocol A is approved by user; Protocol A approves Protocol B; Protocol B can now transfer user's tokens through the chain
- Detection: does the approved contract re-approve tokens to other contracts? Is the delegation chain bounded?

### 9. Permit2 Advanced Exploitation

**Witness type confusion**
- Permit2 allows `witness` data to be included in the signature for application-specific validation
- If two applications use the same Permit2 deployment but define different witness types with overlapping structures, a signature for Application A may be valid for Application B
- Detection: are witness type hashes unique across all applications using the same Permit2 instance?

**Allowance transfer expiration exploitation**
- `AllowanceTransfer` in Permit2 includes an `expiration` field
- If set too far in the future, the allowance remains active long after the user's intent has changed
- If set too short, legitimate operations may fail
- Detection: what expiration does the protocol set? Is it user-configurable or hardcoded?

**Nonce bitmap manipulation**
- Permit2 uses unordered nonce bitmaps for `SignatureTransfer`
- Each nonce is a single bit in a uint256 word; consuming a nonce flips the bit
- Attacker can strategically consume nonces to invalidate the user's pending signatures
- Detection: is the nonce chosen by the user or the protocol? Can an attacker predict and pre-consume nonces?

### 10. Token-Specific Approval Quirks

**USDT approval reset requirement**
- USDT requires `approve(spender, 0)` before `approve(spender, newAmount)` if current allowance is non-zero
- If the protocol does not handle this, the second approval reverts, breaking deposit/transfer flows
- Detection: does the protocol use `safeApprove` (which handles this) or raw `approve`?

**Non-standard return value on approve**
- Some tokens return `false` instead of reverting on failed approval
- If the protocol does not check the return value, it proceeds with zero allowance
- Detection: does the protocol use SafeERC20's `safeApprove` which checks the return value?

**Approval event mismatch**
- Some tokens emit `Approval` events with incorrect amounts (e.g., emitting the new total instead of the change)
- Off-chain systems relying on `Approval` events for allowance tracking may desync
- Detection: does the protocol's off-chain monitoring rely on `Approval` events for state tracking?

## Validation

- Demonstrate approval exploitation with token drain from a user who granted excessive allowance
- Show permit replay with the same signature accepted twice, extracting tokens on each use
- Prove front-running with approval race: spend old allowance and new allowance in sequence
- Confirm Permit2 abuse with unauthorized transfer via a Permit2-integrated contract
- Show upgradeable contract drain: approve a proxy, upgrade implementation, drain tokens
- Demonstrate USDT approval failure: attempt non-zero to non-zero approval without reset
- Prove nonce bitmap manipulation: pre-consume a nonce to invalidate a pending signature
- Verify cross-protocol approval chain: show how approval to Protocol A enables Protocol B to transfer
- Document token addresses, approval amounts, nonce states, and transferred balances
