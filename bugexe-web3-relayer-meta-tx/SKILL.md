---
name: relayer-meta-tx
category: web3
description: Meta-transaction security covering relayer manipulation, gas price griefing, nonce management, signature malleability, and trusted forwarder bypass
depends_on: []
---

# Meta-Transaction Security

Security testing for meta-transaction and relayer systems. Focus on relayer manipulation, gas price griefing, nonce management, signature malleability, trusted forwarder bypass, and gasless transaction abuse.

## When to Use

- Protocol supports gasless transactions via meta-transactions (EIP-2771)
- Relayer network processes signed user requests off-chain and submits on-chain
- Trusted forwarder pattern (OpenZeppelin MinimalForwarder or similar) is used
- Application uses ERC-2612 permits or EIP-712 typed data for off-chain signing
- Gas sponsorship or account abstraction (ERC-4337) is implemented

## Methodology

### 1. Relayer Manipulation

- **Selective execution**: relayer cherry-picks profitable transactions and drops unprofitable ones
- **Transaction reordering**: relayer reorders user transactions for MEV extraction
- **Delayed execution**: relayer holds transactions to exploit time-sensitive operations
- **Censorship**: relayer refuses to process specific users or transaction types
- **Relayer impersonation**: unauthorized entity submits transactions pretending to be a registered relayer
- Check: is there a single relayer or a decentralized network? What guarantees execution ordering?

### 2. Gas Price Griefing

- **Insufficient gas forwarding**: relayer provides just enough gas for the outer call but not the inner execution (63/64 rule)
- **Gas price manipulation**: relayer submits with minimal gas price, causing transaction to sit pending indefinitely
- **Gas estimation mismatch**: signed meta-transaction specifies gas limit; relayer provides less
- **Refund gaming**: relayer inflates gas usage to claim larger gas refunds from the protocol
- **Out-of-gas revert abuse**: inner call reverts due to insufficient gas but outer call succeeds, consuming nonce
- Check: does the contract verify `gasleft()` after forwarding? Is there a minimum gas requirement?

### 3. Nonce Management

- **Nonce reuse**: signed meta-transaction replayed because nonce is not tracked or incremented
- **Nonce front-running**: attacker submits a transaction with the user's next nonce, invalidating the user's pending tx
- **Nonce gap griefing**: consume nonce N+1 before N, blocking N from ever executing (sequential nonce)
- **Bitmap nonce bypass**: bitmap-based nonce tracking (ERC-4337 style) with insufficient bit validation
- **Cross-channel nonce conflict**: nonce shared between direct transactions and meta-transactions
- Check: is the nonce sequential or bitmap-based? Is it per-sender? Can it be front-run?

### 4. Signature Malleability

- **ECDSA malleability**: signature (v, r, s) can be transformed to (v', r, -s mod n) and remain valid
- **Missing malleability check**: ecrecover accepts both s values without enforcing lower-half curve order
- **Compact signature confusion**: EIP-2098 compact signatures (64 bytes) vs standard (65 bytes) handling
- **Signature type mixing**: contract accepts multiple signature formats without proper disambiguation
- **Zero-address recovery**: invalid signatures recovering to address(0) pass if zero-address is not rejected
- Check: does the contract use OpenZeppelin ECDSA? Is recovered address checked against address(0)?

### 5. Trusted Forwarder Bypass

- **Forwarder spoofing**: call the target contract directly (not through forwarder) to bypass sender extraction
- **Multiple forwarders**: contract trusts more than one forwarder; compromised forwarder enables impersonation
- **Forwarder upgrade**: trusted forwarder is upgradeable; new implementation can forge sender addresses
- **Suffix extraction error**: _msgSender() extracts the appended address incorrectly due to calldata length mismatch
- **Direct call detection**: contract does not distinguish between forwarder calls and direct calls correctly
- Check: how is the trusted forwarder set? Is it immutable? Does _msgSender() handle both direct and forwarded calls?

### 6. ERC-4337 Account Abstraction

- **Bundler manipulation**: bundler reorders or drops UserOperations for profit
- **Paymaster abuse**: drain paymaster balance by submitting expensive operations it is forced to pay for
- **Validation-execution mismatch**: validateUserOp succeeds but execution logic differs from validation assumptions
- **Storage access violations**: UserOperation accesses forbidden storage slots during validation phase
- **Aggregator spoofing**: signature aggregator returns valid for forged aggregate signatures
- Check: what paymaster is used? Are gas limits enforced? Does validation match execution assumptions?

## Key Commands

```bash
# Check trusted forwarder
cast call {contract} "isTrustedForwarder(address)(bool)" {forwarder}

# Check meta-tx nonce
cast call {forwarder} "getNonce(address)(uint256)" {sender}

# Decode EIP-712 meta-transaction
cast abi-decode "execute((address,address,uint256,uint256,uint256,bytes,uint256))" {calldata}

# Verify signature recovery
cast wallet verify --address {expected} --message {hash} {signature}
```

## Validation

- Demonstrate relayer manipulation with reordered or dropped transactions causing user harm
- Show gas griefing with inner call reverting while outer succeeds, consuming the nonce
- Prove nonce replay with the same signed meta-transaction executed twice
- Confirm forwarder bypass with direct contract call impersonating another user's address
- Document signed payloads, relayer behavior, gas traces, and on-chain state changes
