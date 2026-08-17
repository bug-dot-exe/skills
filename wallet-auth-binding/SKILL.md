---
name: wallet-auth-binding
category: web3
description: Wallet authentication security covering signature replay, nonce reuse, message spoofing, chain ID bypass, and permit/approval abuse
depends_on: []
---

# Wallet Authentication & Binding

Security testing for wallet-based authentication and transaction signing. Focus on signature replay attacks, nonce reuse, message spoofing, chain ID bypass, and permit/approval abuse in dApps and smart contracts.

## When to Use

- dApp uses wallet signatures for authentication (Sign-In with Ethereum, personal_sign, EIP-712)
- Smart contracts verify off-chain signatures (permit, meta-transactions, gasless relays)
- Application binds wallet addresses to user accounts or sessions
- ERC-2612 permit or ERC-20 approval patterns are in scope
- Multi-chain deployment where cross-chain replay is possible

## Methodology

### 1. Signature Replay Attacks

**Same-Chain Replay**
- Signature used for one action replayed to perform it again
- Check: is there a nonce that increments and is verified on-chain?
- Check: is the signature bound to a specific contract address?

**Cross-Chain Replay**
- Signature valid on chain A replayed on chain B (same contract deployed at same address)
- Check: does the signed message include `block.chainid` or EIP-712 domain separator with chainId?
- Verify: domain separator is computed at runtime, not cached from deployment chain

**Cross-Contract Replay**
- Signature for Contract A replayed on Contract B
- Check: does the signed message include the verifying contract address?
- EIP-712 domain separator must include `verifyingContract`

**Detection Pattern**
1. Find all `ecrecover`, `ECDSA.recover`, `SignatureChecker.isValidSignatureNow` calls
2. For each, trace what data is included in the signed hash
3. Verify presence of: nonce, chainId, contract address, deadline/expiry
4. Check nonce is stored, incremented, and validated before signature use

### 2. Nonce Management

**Missing Nonce**
- No nonce in signed message allows unlimited replay
- Every signature-verified action must consume a unique nonce

**Nonce Skip / Gap**
- Sequential nonce (n, n+1, n+2) allows front-running: submit nonce n+1 before n, blocking n
- Bitmap nonce (bit per nonce ID) avoids ordering dependency
- Check: can an attacker grief by consuming another user's nonce?

**Nonce Scope**
- Per-user nonce: standard, prevents cross-user replay
- Global nonce: risky if shared across operations
- Per-function nonce: prevents replay within function but not across functions sharing the same signer

**Review Pattern**
```solidity
// Vulnerable: no nonce
bytes32 hash = keccak256(abi.encodePacked(to, amount));
address signer = ECDSA.recover(hash, sig);

// Secure: includes nonce, chainId, contract address
bytes32 hash = keccak256(abi.encodePacked(to, amount, nonces[signer]++, block.chainid, address(this)));
address signer = ECDSA.recover(hash, sig);
```

### 3. Message Spoofing

**Personal Sign Spoofing**
- `personal_sign` prepends `\x19Ethereum Signed Message:\n{length}` to arbitrary bytes
- If the dApp signs a raw hash, the user sees hex gibberish in their wallet
- Check: does the dApp use human-readable EIP-712 typed data instead of raw hashes?

**EIP-712 Domain Mismatch**
- Domain separator fields: `name`, `version`, `chainId`, `verifyingContract`, `salt`
- Missing or incorrect fields allow cross-domain signature reuse
- Verify all domain fields match the deployed contract and intended chain

**Phishing via Structured Data**
- Malicious dApp presents EIP-712 data that looks like a harmless message but encodes a transfer/approval
- Review: what data structures does the contract expect? Could a user be tricked into signing one?

**Signature Malleability**
- ECDSA signatures have a malleability issue: (v, r, s) and (v', r, -s mod n) are both valid
- Check: does the contract use OpenZeppelin's ECDSA library (which rejects malleable signatures)?
- Verify: `s` is in the lower half of the curve order

### 4. Chain ID Bypass

**Deployment-Time Domain Separator**
```solidity
// Vulnerable: cached at deployment, stale after hard fork
bytes32 DOMAIN_SEPARATOR = keccak256(abi.encode(
    DOMAIN_TYPEHASH, name, version, block.chainid, address(this)
));

// Secure: recomputed when chainId changes
function DOMAIN_SEPARATOR() public view returns (bytes32) {
    if (block.chainid == _CACHED_CHAIN_ID) return _CACHED_DOMAIN_SEPARATOR;
    return _computeDomainSeparator();
}
```

**Missing Chain ID**
- Signed message does not include chain ID at all
- Valid on any EVM chain where the contract exists at the same address

**Hard Fork Replay**
- After a chain fork, signatures from the original chain are valid on the fork
- Check: does the contract handle chain ID changes dynamically?

### 5. Permit and Approval Abuse

**ERC-2612 Permit**
- Off-chain signature authorizes token spending without on-chain `approve` transaction
- Check: can a permit signature be front-run? (attacker submits permit before intended relayer)
- Check: does the permit nonce increment correctly?
- Check: is the deadline enforced? (`block.timestamp <= deadline`)
- Verify: permit cannot be replayed after nonce consumption

**Permit2 (Uniswap)**
- Universal approval system: user approves Permit2 once, then signs per-transfer permits
- Check: signature includes correct `spender`, `token`, `amount`, `nonce`, `deadline`
- Check: batch permits cannot be partially replayed
- Verify: `SignatureTransfer` vs `AllowanceTransfer` modes are correctly handled

**Approval Front-Running**
- Classic: user calls `approve(spender, newAmount)`, spender front-runs to spend old allowance + new
- Check: does the contract use `increaseAllowance` / `decreaseAllowance` or require approval reset to 0?
- Permit variant: attacker front-runs permit submission to extract current allowance before new permit takes effect

**Infinite Approval Risk**
- dApp requests `type(uint256).max` approval for convenience
- Check: is the approval scoped to the minimum necessary amount?
- If infinite approval is used, verify the spender contract is non-upgradeable or trust assumptions are documented

### 6. Authentication Binding

**Sign-In with Ethereum (SIWE / EIP-4361)**
- Verify: message includes domain, address, statement, URI, nonce, issued-at, expiration
- Check: server validates all fields, not just the recovered address
- Check: nonce is server-generated and single-use (prevents replay)
- Check: domain binding prevents phishing (message domain matches request origin)

**Session Binding**
- After wallet signature, is the session token bound to the wallet address?
- Can an attacker bind their wallet to another user's account?
- Is re-authentication required for sensitive operations (withdrawal, transfer)?

**Address Ownership**
- Verify the signing address matches the authenticated session
- Check for address case sensitivity issues (mixed-case checksum vs lowercase)
- Smart contract wallets (EIP-1271): verify `isValidSignature` is called for contract accounts

### 7. Smart Contract Wallet Interactions (EIP-1271)

**Missing EIP-1271 support**
- Protocol only checks `ecrecover` for EOA signatures, rejecting smart contract wallets (multisigs, AA wallets)
- Detection: does the protocol call `isValidSignature(bytes32, bytes)` for contract accounts?
- Impact: smart contract wallet users cannot use signature-based features (permits, meta-transactions, SIWE)

**EIP-1271 oracle manipulation**
- Smart contract wallet's `isValidSignature` can return different results based on on-chain state
- Attacker manipulates the state that the wallet's validation logic reads, making a previously-invalid signature valid
- Detection: does the `isValidSignature` implementation read external mutable state (oracle prices, governance votes)?

**EIP-1271 replay**
- Unlike EOA signatures where nonce consumption invalidates the signature, a smart contract wallet may return `isValid` for the same hash indefinitely
- The consuming protocol MUST track its own nonces rather than relying on the wallet to invalidate
- Detection: is nonce tracking in the consuming contract or delegated to the wallet?

### 8. Meta-Transaction and Gasless Relay Vulnerabilities

**Relayer censorship and front-running**
- Relayer sees the signed meta-transaction and front-runs it (extracts MEV, replays on a different chain)
- Relay network may selectively censor certain meta-transactions while processing others
- Detection: is the meta-transaction bound to a specific relayer address? Is there a trusted forwarder pattern?

**Trusted forwarder bypass**
- ERC-2771 context: `_msgSender()` reads the appended sender from calldata when called via the trusted forwarder
- If the contract accepts calls from both the forwarder and directly, an attacker can append a spoofed sender to a direct call
- Detection: is `isTrustedForwarder(msg.sender)` checked before reading the appended sender? Can the forwarder address be changed?

**Gas estimation attacks**
- Meta-transaction includes a gas limit; if the inner call uses more gas than provided, it reverts but the outer relay succeeds
- Attacker submits meta-transaction with insufficient gas, consuming the nonce without executing the action
- Detection: does the relay contract verify sufficient gas is forwarded to the inner call?

### 9. Account Abstraction (ERC-4337) Risks

**Bundler manipulation**
- Bundlers can reorder UserOperations within a bundle to extract MEV
- Bundler can drop a UserOperation after seeing it, front-running the action with their own transaction
- Detection: does the UserOperation include MEV protection (slippage, deadline)?

**Paymaster drain**
- Paymaster sponsors gas for UserOperations; if validation is insufficient, attacker can drain paymaster's deposit
- Attacker crafts UserOperations that pass `validatePaymasterUserOp` but perform expensive/malicious actions
- Detection: does the paymaster validate the operation's calldata or just the sender? Is there a per-operation spend limit?

**Signature validation timing**
- `validateUserOp` must not depend on mutable storage that can change between validation and execution
- If a storage value changes between validation (where signature is checked) and execution, the operation may execute with an invalid authorization state
- Detection: does `validateUserOp` read any state that `execute` can modify? Are there reentrancy paths between validation and execution?

## Key Commands

```bash
# Signature analysis with cast (Foundry)
cast sig "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)"
cast abi-decode "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)" {calldata}

# Recover signer
cast wallet verify --address {addr} --message {msg} {sig}

# Check domain separator
cast call {contract} "DOMAIN_SEPARATOR()(bytes32)" --rpc-url {rpc}

# EIP-712 hash computation
cast keccak "$(cast abi-encode 'f(bytes32,bytes32,bytes32,uint256,address)' {args})"

# Check EIP-1271 support
cast call {wallet} "isValidSignature(bytes32,bytes)(bytes4)" {hash} {sig}

# Check trusted forwarder
cast call {contract} "isTrustedForwarder(address)(bool)" {forwarder}

# Check ERC-4337 entrypoint
cast call {entrypoint} "getNonce(address,uint192)(uint256)" {sender} 0
```

## Validation

- Demonstrate signature replay: same signature accepted twice with concrete on-chain impact
- Show cross-chain replay: signature from chain A used on chain B to perform unauthorized action
- Prove permit abuse: extract tokens via front-run or replayed permit signature
- Confirm message spoofing: construct a misleading EIP-712 message that encodes a harmful operation
- Show EIP-1271 replay: smart contract wallet returns valid for same hash after nonce should be consumed
- Demonstrate trusted forwarder bypass: direct call with appended sender spoofing `_msgSender()`
- Prove paymaster drain: craft UserOperations that pass validation but drain the paymaster deposit
- Document: exact signed data, recovered address, chain/contract context, and observed impact
