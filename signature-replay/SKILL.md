---
name: signature-replay
category: web3
description: Signature replay attacks covering same-chain replay, cross-chain replay, cross-contract replay, nonce skip, expired signature exploitation, and EIP-712 domain separator analysis
depends_on: []
---

# Signature Replay Attacks

Security testing for signature-based authentication and authorization in smart contracts. Focus on same-chain replay, cross-chain replay, cross-contract replay, nonce skip attacks, expired signature exploitation, and EIP-712 domain separator analysis.

## When to Use

- Smart contracts verify off-chain signatures for authorization (permits, meta-transactions, gasless actions)
- Protocol uses ecrecover, ECDSA.recover, or SignatureChecker for signature verification
- EIP-712 typed data signing is implemented
- Multi-chain deployment where contracts exist at the same address across chains
- Nonce-based replay protection is implemented and needs validation

## Methodology

### 1. Same-Chain Replay

- **Missing nonce**: signed message contains no nonce; same signature accepted unlimited times
- **Nonce not consumed**: nonce is checked but not incremented after successful verification
- **Nonce in wrong storage**: nonce tracked in memory or local variable instead of persistent storage
- **Batch replay**: signature valid for a batch operation; entire batch replayed after partial execution
- **Function-scoped nonce gap**: nonce tracked per-function but signatures usable across functions
- Trace: follow the signature from verification through nonce consumption; verify storage write occurs before external calls

### 2. Cross-Chain Replay

- **Missing chainId**: signed data does not include block.chainid or EIP-712 domain chainId
- **Cached domain separator**: domain separator computed at deployment and cached; stale after chain fork
- **Hardcoded chainId**: chainId hardcoded rather than read from block.chainid at verification time
- **L1/L2 replay**: signature created on L1 replayed on L2 (or vice versa) where same contract is deployed
- **Testnet-mainnet replay**: signature from testnet replayed on mainnet if chainId is not enforced
- Check: is chainId included in the signed hash? Is the domain separator recomputed on chainId change?

### 3. Cross-Contract Replay

- **Missing verifyingContract**: EIP-712 domain separator does not include the contract address
- **Shared verification logic**: library or base contract verifies signatures without binding to deployment address
- **Factory-deployed replay**: contracts deployed by the same factory at predictable addresses across chains
- **Proxy address confusion**: signature bound to proxy address but verification happens in implementation
- **Diamond/facet replay**: signature verified in one facet but valid for operations in another facet
- Check: does the signed data include `address(this)`? Are signatures scoped to specific contract instances?

### 4. Nonce Skip Attacks

- **Sequential nonce front-running**: attacker submits nonce N+1 before user's nonce N, permanently blocking N
- **Nonce gap creation**: skip nonces to create gaps that prevent legitimate transactions from executing
- **Bitmap nonce manipulation**: in bitmap-based systems, consume bits that the user planned to use
- **Nonce race condition**: two transactions with the same nonce submitted simultaneously; one succeeds, one fails
- **Nonce overflow**: nonce counter overflows back to 0, re-enabling previously used signatures
- Check: is the nonce sequential or bitmap-based? Can an attacker consume another user's nonce?

### 5. Expired Signature Exploitation

- **Missing deadline**: no expiration timestamp in the signed data; signature valid indefinitely
- **Off-by-one in deadline check**: `block.timestamp <= deadline` vs `block.timestamp < deadline` boundary
- **Clock skew exploitation**: different chains have different block timestamps; deadline meaningful on one chain may be past on another
- **Long deadline griefing**: user signs with a far-future deadline; signature usable long after intent has changed
- **Deadline not in signed data**: deadline checked but not included in the hash that was signed, allowing modification
- Check: is deadline part of the signed hash? Is the comparison strict? What is the typical deadline window?

### 6. EIP-712 Domain Separator Analysis

- **Incomplete domain**: missing fields (name, version, chainId, verifyingContract, salt) reduce replay protection
- **Version mismatch**: domain version does not match contract version; signatures from old version still valid
- **Name collision**: generic domain name (e.g., "ERC20") shared across different token contracts
- **Salt absence**: no salt in domain separator; relying solely on other fields for uniqueness
- **Dynamic vs cached**: domain separator computed once in constructor vs recomputed per-call
- Verify each field of the domain separator against EIP-712 requirements:
  ```solidity
  // Complete domain separator
  keccak256(abi.encode(
      DOMAIN_TYPEHASH,
      keccak256(bytes(name)),      // unique protocol name
      keccak256(bytes(version)),   // contract version
      block.chainid,               // dynamic, not cached
      address(this)                // verifying contract
  ));
  ```

### 7. Advanced Replay Vectors

- **Permit after transfer**: user signs permit, transfers tokens away, receives them back; permit still valid
- **Delegate replay**: delegated signer's signature replayed after delegation is revoked
- **Multisig partial replay**: partial signatures from a multisig reused in a different signing round
- **EIP-1271 replay**: smart contract wallet's `isValidSignature` returns valid for old signatures
- **Signature stripping**: remove wrapping (meta-tx envelope) and use the inner signature directly
- Check: are there any secondary conditions that should invalidate a signature beyond nonce and deadline?

## Key Commands

```bash
# Find all signature verification points
grep -rn "ecrecover\|ECDSA.recover\|isValidSignature\|SignatureChecker" contracts/

# Check domain separator on-chain
cast call {contract} "DOMAIN_SEPARATOR()(bytes32)"
cast call {contract} "eip712Domain()(bytes1,string,string,uint256,address,bytes32,uint256[])"

# Check nonce
cast call {contract} "nonces(address)(uint256)" {signer}

# Verify a signature off-chain
cast wallet verify --address {signer} --message {messageHash} {signature}
```

### 8. Signature Canonicalization Attacks

**EIP-712 struct hash collision**
- Two different struct types with identical field layouts produce the same hash if the type hash is not included
- Detection: does the protocol include `TYPEHASH` in every struct hash? Are different action types distinguished?

**abi.encodePacked in signature hash**
- Using `abi.encodePacked` for signature hash construction allows collision between different parameter combinations
- `abi.encodePacked(address, uint256)` and `abi.encodePacked(bytes20, bytes32)` can produce identical bytes for crafted inputs
- Detection: is the signed hash constructed with `abi.encode` (safe, padded) or `abi.encodePacked` (collision-prone)?

**Signature malleability in custom verification**
- Custom `ecrecover` usage without checking `s <= secp256k1n/2` allows (v, r, s) and (v^1, r, -s mod n) to both recover the same address
- Impact: attacker creates a second valid signature for the same message, bypassing deduplication that tracks (v, r, s) tuples
- Detection: does the contract use OZ ECDSA (which rejects malleable signatures) or raw `ecrecover`?

### 9. Multi-Signature and Threshold Vulnerabilities

**Signature ordering exploitation**
- Multisig contracts require signatures in address-sorted order; submitting out-of-order causes revert
- Attacker can grief by submitting a valid transaction with wrong signature order, consuming gas
- Detection: does the multisig enforce ordering? Can an attacker exploit the ordering check?

**Threshold bypass via duplicate signers**
- If the multisig does not deduplicate signer addresses, the same signer can sign twice to meet threshold
- Detection: does the contract check `signer > lastSigner` (sorted, deduplicated) or just count signatures?

**Guardian/recovery key replay**
- Social recovery wallets allow guardians to authorize recovery; guardian signatures may not include recovery-specific nonces
- After a successful recovery, old guardian signatures may authorize a second unwanted recovery
- Detection: are guardian signatures bound to a specific recovery round/epoch?

### 10. Meta-Transaction Signature Binding

**Trusted forwarder signature stripping**
- ERC-2771 meta-transactions append the original sender to calldata
- If the forwarder verifies the signature but the target contract does not re-verify, an attacker can call the target directly with a spoofed appended sender
- Detection: does the target contract verify that `msg.sender == trustedForwarder` before reading the appended sender?

**Gas token griefing in relayed signatures**
- Relayer submits meta-transaction with insufficient gas; the inner call reverts but the nonce is consumed
- User's signed action fails but the nonce is spent, requiring a new signature
- Detection: does the relay contract ensure sufficient gas is forwarded? Is the nonce only consumed on successful execution?

**Cross-contract forwarding**
- Meta-transaction forwarded to Contract A, which internally calls Contract B
- If Contract B also reads `_msgSender()`, it may get the forwarder's address instead of the original signer
- Detection: in multi-contract call chains starting from a meta-transaction, does each contract correctly resolve the original sender?

### 11. Permit-Specific Replay Vectors

**Permit front-running griefing**
- Attacker sees a permit transaction in the mempool and front-runs it by calling `permit()` with the same signature
- The attacker's `permit` call succeeds and consumes the nonce; the original transaction reverts
- The attacker gains nothing but the victim's action fails
- Detection: does the protocol wrap `permit` in try/catch so the overall transaction succeeds even if permit was already consumed?

**Permit2 witness data manipulation**
- Permit2 `SignatureTransfer` allows arbitrary `witness` data hashed into the signature
- If the consuming contract does not validate the witness data, an attacker can substitute different witness data
- Detection: is the witness type hash included in the signature? Does the contract verify witness data matches expected values?

## Validation

- Demonstrate same-chain replay with the same signature accepted twice producing duplicate state changes
- Show cross-chain replay with a signature from chain A executing an unauthorized action on chain B
- Prove nonce skip with a legitimate transaction permanently blocked by attacker's nonce consumption
- Confirm expired signature exploitation with a past-deadline signature still accepted
- Show signature malleability: produce two valid signatures for the same message using (v,r,s) and (v',r,-s mod n)
- Demonstrate multisig threshold bypass via duplicate signer addresses
- Prove permit front-running griefing: front-run a permit call to consume the nonce
- Document signed data, domain separator fields, nonce states before/after, and chain IDs involved
