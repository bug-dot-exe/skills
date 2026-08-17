---
name: web3-smart-contract-audit
category: web3
description: Smart contract security testing covering reentrancy, integer overflow, access control, delegatecall, storage collision, front-running, and flash loan attacks
depends_on: []
---

# Smart Contract Security Audit

Security testing for EVM-compatible smart contracts. Focus on reentrancy, integer overflow/underflow, access control flaws, delegatecall risks, storage collision, front-running, and flash loan attack vectors.

## When to Use

- Solidity/Vyper smart contracts are in scope
- DeFi protocol audit or bug bounty with on-chain components
- Wallet or dApp interacts with custom smart contracts
- Proxy/upgradeable contract patterns are in use
- Token contracts (ERC20, ERC721, ERC1155) need review

## Methodology

### 1. Reentrancy

**Classic Reentrancy**
- External call before state update (violates Checks-Effects-Interactions pattern)
- Look for: `.call{value:}("")`, `.transfer()`, `.send()`, ERC721 `safeTransferFrom`, ERC1155 callbacks

**Cross-Function Reentrancy**
- Function A makes external call, function B reads stale state modified by A
- Map all functions sharing state variables and check call ordering

**Cross-Contract Reentrancy**
- Contract A calls external, attacker reenters Contract B which reads A's stale state
- Trace state dependencies between cooperating contracts

**Read-Only Reentrancy**
- View function returns stale state during callback execution
- Common in lending protocols reading pool balances mid-swap

**Detection Pattern**
1. Find all external calls (call, delegatecall, staticcall, token transfers with callbacks)
2. For each call, check if state updates happen AFTER the call
3. Check if any other function reads the not-yet-updated state
4. Verify reentrancy guards (ReentrancyGuard, mutex) cover all affected functions

### 2. Integer Overflow/Underflow

**Solidity < 0.8.0**
- No built-in overflow protection; check for SafeMath usage
- Unchecked arithmetic in assembly blocks

**Solidity >= 0.8.0**
- Overflow reverts by default, but `unchecked {}` blocks bypass this
- Review every `unchecked` block for safe arithmetic assumptions

**Precision Loss**
- Division before multiplication: `(a / b) * c` loses precision vs `(a * c) / b`
- Rounding direction exploitation in share/token calculations
- First depositor attacks in vaults: deposit 1 wei, donate large amount, inflate share price

**Type Casting**
- Unsafe downcasting: `uint256` to `uint128/uint96/uint64` without bounds check
- Signed/unsigned conversion: `int256` to `uint256` with negative values

### 3. Access Control

**Missing Access Control**
- Public/external functions that modify critical state without `onlyOwner`, `onlyRole`, or similar
- Initializer functions callable by anyone (missing `initializer` modifier or already-initialized check)
- Self-destruct or proxy upgrade functions without access restriction

**Broken Access Control**
- `tx.origin` used for authorization instead of `msg.sender`
- Role assignment functions accessible to non-admins
- Default admin role not set in constructor/initializer
- Privilege escalation: role A can grant role B which has higher privileges

**Review Pattern**
1. List all state-modifying functions
2. For each, verify access control modifier or require statement
3. Check role hierarchy: who can grant/revoke each role?
4. Verify initializers are protected and can only execute once

### 4. Delegatecall Risks

**Storage Collision**
- Delegatecall preserves caller's storage layout; implementation must match proxy layout
- Adding/reordering variables in upgraded implementation corrupts storage

**Uninitialized Implementation**
- Implementation contract constructor does not run in proxy context
- If implementation is not initialized, attacker can call initializer and take ownership
- Check: does the implementation call `_disableInitializers()` in its constructor?

**Function Selector Clashing**
- Proxy admin functions may clash with implementation function selectors
- Transparent proxy pattern mitigates but does not eliminate

**Delegatecall to Untrusted Target**
- `address.delegatecall(data)` where `address` is user-controlled
- Allows arbitrary code execution in the caller's context

### 5. Storage Collision

**Proxy Patterns**
- EIP-1967 storage slots for implementation, admin, beacon addresses
- Verify slots are computed as `bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`
- Check for non-standard slot usage that may conflict with implementation variables

**Unstructured Storage**
- Diamond pattern (EIP-2535): verify facet storage does not overlap
- Custom storage patterns: check namespace hashing is collision-resistant

### 6. Front-Running / MEV

**Transaction Ordering Dependency**
- Approval front-running: `approve()` race condition (use increaseAllowance/permit instead)
- Sandwich attacks: large swaps without slippage protection
- Liquidation front-running: profitable liquidations extracted by MEV bots

**Commit-Reveal Weakness**
- On-chain randomness from block.timestamp, block.difficulty, blockhash is predictable
- Auction/bid reveals where commitment scheme is weak or timing is exploitable

**Mitigation Checks**
- Slippage parameters: `amountOutMin`, deadline in swap functions
- Private mempools / commit-reveal schemes for sensitive operations
- Batch auction or uniform price mechanisms

### 7. Flash Loan Attacks

**Price Oracle Manipulation**
- Spot price from AMM pool as oracle: manipulable within a single transaction
- Check: does the protocol use TWAP, Chainlink, or spot price?
- Verify oracle cannot be moved significantly by a flash-borrowed amount

**Governance Manipulation**
- Flash-borrow governance tokens, vote, return in same transaction
- Check: snapshot-based voting vs current-balance voting

**Collateral Inflation**
- Flash-borrow to inflate collateral value, borrow against it, default
- Check: does the lending protocol use time-weighted or manipulation-resistant price feeds?

**Detection Pattern**
1. Identify all external price/balance reads
2. For each, determine if the value can be manipulated atomically
3. Check if manipulation leads to profit (borrow more, extract more, vote more)
4. Verify flash loan callbacks are properly restricted

### 8. EVM Equivalence and L2 Divergence

**Opcode behavior differences across L2 chains**
- L2 chains (Optimism, Arbitrum, zkSync, Scroll) implement EVM-equivalent or EVM-compatible VMs with subtle divergences
- `SELFDESTRUCT` semantics differ: some L2s no-op it, some defer balance clearing, some preserve contract code
- `PUSH0`, `PREVRANDAO`, `BLOBBASEFEE` may not exist or return different values
- `block.number` and `block.timestamp` may reflect L1 values instead of L2 sequencer values

**Differential opcode auditing**
1. Enumerate every EVM opcode the contract depends on that mutates state or reads chain context
2. For each opcode, check the target L2's documentation for behavioral differences
3. Compare: deploy the same test on L1 and each target L2, assert identical results
4. Focus on: `CREATE2` address derivation, `SELFDESTRUCT` balance handling, `COINBASE` return value, gas metering

**Cross-L2 deployment risks**
- Same contract deployed to multiple L2s may behave differently due to VM divergence
- Precompile availability differs: some L2s lack certain precompiles (e.g., `ecrecover` edge cases in zkEVM)
- Gas costs differ substantially, breaking hardcoded gas limits in `call{gas: N}()`

### 9. Proxy and Upgrade Vulnerabilities

**Uninitialized implementation takeover**
- Implementation contract behind a proxy can be directly initialized by an attacker if `_disableInitializers()` is not called in the implementation constructor
- After takeover: attacker calls `selfdestruct` on implementation, bricking all proxies pointing to it

**UUPS upgrade function exposure**
- UUPS proxies place `upgradeTo` in the implementation, not the proxy
- If the upgrade function lacks access control or if it is inherited but not overridden with protection, anyone can upgrade
- Check: is `_authorizeUpgrade` properly overridden with `onlyOwner` or equivalent?

**Storage layout corruption on upgrade**
- New implementation adds variables before existing ones, shifting storage slots
- Inherited contracts reordered between versions corrupt slot alignment
- Detection: `forge inspect OldImpl storage-layout` vs `forge inspect NewImpl storage-layout`, diff the output

**Beacon proxy hijacking**
- All proxies using a shared beacon inherit the implementation address from the beacon
- Compromise the beacon owner -> redirect all proxies to a malicious implementation in one transaction
- Detection: trace beacon ownership chain, verify timelock/multisig protection

### 10. Gas Griefing and DoS

**Unbounded loop DoS**
- Functions iterating over user-controlled arrays (token lists, recipient lists, staker lists) can exceed block gas limit
- Detection: find every for/while loop where the bound depends on storage length or function parameter

**Returndata bomb**
- External call to untrusted contract that returns massive data (e.g., 2MB) causes OOG in the caller
- Impact: any `abi.decode` or return data copy after the call consumes unbounded gas
- Detection: low-level calls (`address.call`) without return data size cap

**Block stuffing**
- Attacker fills blocks to delay time-sensitive operations (auctions, liquidations, governance votes)
- Impact: missed deadlines, expired commitments, stale oracle prices during the stuffing window

**Griefing via revert**
- In batch operations (airdrops, multi-claims), one recipient reverting blocks all others
- Detection: does the protocol use try/catch or continue-on-failure for batch transfers?

### 11. CREATE2 and Address Prediction

**Metamorphic contracts**
- `CREATE2` with `SELFDESTRUCT` + redeploy at same address allows code replacement
- Impact: contract at a known address changes behavior after users have approved/deposited to it
- Detection: does the contract at a CREATE2 address contain `SELFDESTRUCT`? Can the deployer redeploy?

**Pre-computed address exploitation**
- `CREATE2` addresses are deterministic; attacker can pre-compute an address, get approvals/deposits sent to it, then deploy a malicious contract at that address
- Detection: any protocol that sends funds to an address before verifying code exists there

## Key Commands

```bash
# Foundry
forge build                              # Compile
forge test -vvv                          # Run tests with traces
forge test --match-test testExploit -vvv # Run specific test

# Slither (static analysis)
slither . --detect reentrancy-eth,reentrancy-no-eth,uninitialized-state
slither . --print human-summary

# Storage layout
forge inspect {Contract} storage-layout
cast storage {address} {slot} --rpc-url {rpc}

# L2-specific
cast chain-id --rpc-url {l2_rpc}                     # Verify chain ID
cast call {contract} "implementation()(address)" --rpc-url {rpc}  # Proxy implementation
forge inspect {Contract} storage-layout               # Compare pre/post upgrade
```

## Validation

- Demonstrate exploit with a Foundry/Hardhat PoC test showing concrete fund loss or state corruption
- Quantify impact: exact token amounts extractable, affected user count, or protocol TVL at risk
- For flash loan attacks: show the full atomic sequence (borrow, manipulate, exploit, repay, profit)
- For reentrancy: show the reentrant call trace and the stale state read
- For L2 divergence: deploy identical test on L1 and L2, show behavioral difference with concrete state change
- For proxy bugs: show uninitialized implementation takeover or storage corruption with specific slot values
- Document: vulnerable function, exact call sequence, and concrete numeric impact
