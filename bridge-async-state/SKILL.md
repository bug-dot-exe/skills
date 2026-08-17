---
name: bridge-async-state
category: web3
description: Cross-chain bridge security covering async state handling, message replay, validator set manipulation, proof verification bypass, timeout exploitation, and double-spend via bridge
depends_on: []
---

# Cross-Chain Bridge Security

Security testing for cross-chain bridge protocols. Focus on asynchronous state handling, message replay, validator set manipulation, proof verification bypass, timeout exploitation, and double-spend attack vectors.

## When to Use

- Target is a cross-chain bridge or messaging protocol
- Protocol relays messages, tokens, or state between different blockchains
- Validator/relayer network processes cross-chain proofs
- Lock-and-mint or burn-and-mint token bridging is implemented
- Application has timeout/refund mechanisms for failed bridge transfers

## Methodology

### 1. Async State Handling

- **State divergence**: source chain state changes (reorg, slash) after message was relayed to destination
- **Out-of-order message delivery**: messages processed in different order than sent, breaking dependent state
- **Partial state sync**: only subset of state updates bridged, creating inconsistency
- **Finality assumptions**: bridge treats source chain transactions as final before sufficient confirmations
- **Nonce gaps**: skipped message nonces allow replay of future messages or block delivery of pending ones
- Trace: map the full lifecycle of a bridge message from source to destination including all state checkpoints

### 2. Message Replay

- **Same-destination replay**: identical message processed twice on the destination chain
- **Cross-destination replay**: message for chain A replayed on chain B if both accept the same proof format
- **Nonce reuse**: message nonce not tracked or tracked in a bypassable manner
- **Batch replay**: one message in a batch replayed by resubmitting the entire batch with the same proof
- **Upgrade window replay**: messages from before a contract upgrade replayed after upgrade changes validation
- Check: does the bridge store processed message hashes? Is the nonce per-sender, per-chain, or global?

### 3. Validator Set Manipulation

- **Threshold bypass**: fewer validators than required to reach consensus sign a fraudulent message
- **Validator key compromise**: single validator key signs conflicting messages for different destinations
- **Validator rotation race**: submit messages signed by outgoing validator set during rotation transition
- **Economic attack**: cost to corrupt sufficient validators vs value secured by the bridge
- **Censorship by validators**: validators selectively refuse to sign certain messages
- Check: what is the validator threshold? How are keys rotated? What is the slashing mechanism?

### 4. Proof Verification Bypass

- **Merkle proof forgery**: submit fabricated Merkle proofs against manipulated state roots
- **Light client spoofing**: feed false block headers to the bridge's on-chain light client
- **Optimistic proof window**: submit fraudulent proofs during the challenge window when no challenger is active
- **Proof reuse**: valid proof from one message used to authorize a different message
- **ZK proof circuit bugs**: zero-knowledge proof circuits that accept invalid witness data
- Check: does the bridge verify proofs on-chain or rely on off-chain attestation? What is the challenge period?

### 5. Timeout Exploitation

- **Double-claim via timeout**: initiate bridge transfer, claim refund after timeout on source, but funds already minted on destination
- **Timeout racing**: submit claim on destination and timeout refund on source simultaneously
- **Griefing via timeout**: intentionally trigger timeouts to lock user funds in pending state
- **Timeout parameter manipulation**: user-supplied timeout values that are too short or too long
- **Clock skew exploitation**: different chain block times cause timeout to trigger prematurely on one side
- Check: is the timeout enforced on both sides atomically? Can a user claim on both sides?

### 6. Double-Spend via Bridge

- **Source chain reorg**: transaction confirmed on source, relayed to destination, then source chain reorgs
- **Deposit replay**: same deposit event used to mint tokens on destination multiple times
- **Withdrawal race**: submit multiple withdrawal proofs for the same locked balance
- **Cross-bridge double-spend**: same tokens locked on bridge A and bridge B simultaneously
- **Liquidity pool drain**: flash-borrow on destination side to drain bridge liquidity before proof settles
- Check: how many confirmations does the bridge wait? Is the deposit event indexed and deduplicated?

## Key Commands

```bash
# Trace bridge events
cast logs --from-block {start} --to-block {end} --address {bridge} "MessageSent(bytes32,address,uint256)"
cast logs --from-block {start} --to-block {end} --address {bridge} "MessageReceived(bytes32,address,uint256)"

# Check processed message hashes
cast call {bridge} "processedMessages(bytes32)(bool)" {messageHash}

# Query validator set
cast call {bridge} "getValidators()(address[])"
cast call {bridge} "threshold()(uint256)"
```

### 7. Bridge Token Accounting Exploits

**Lock-mint imbalance**
- Source chain locks X tokens but destination chain mints X+Y due to rounding, fee miscalculation, or decimal mismatch
- Over many transactions, the destination chain has more minted tokens than locked on source, creating unbacked supply
- Detection: trace the exact amount locked vs minted for representative transfers; verify 1:1 correspondence

**Burn-unlock mismatch**
- User burns tokens on destination to unlock on source; bridge credits a different amount than burned
- Decimal conversion between chains with different token decimals (e.g., 18 decimals on Ethereum, 6 on another chain) can create conversion rounding exploits
- Detection: does the bridge normalize decimals consistently in both directions?

**Wrapped token de-peg**
- Bridge's wrapped token trades on destination chain DEXs; if the bridge is compromised, the wrapped token de-pegs
- Users holding wrapped tokens suffer losses even if they never used the bridge directly
- Detection: is there a mechanism to pause minting if the backing ratio drops? Is the backing ratio verifiable on-chain?

### 8. Relayer and Sequencer Manipulation

**Relayer MEV extraction**
- Relayer observes bridge messages in the mempool and reorders them to extract MEV on the destination chain
- Example: front-run a large token bridge with a DEX trade on the destination chain to profit from the price impact
- Detection: are messages processed in strict order? Is there a commit-reveal or delay mechanism?

**Relayer censorship**
- Relayer selectively refuses to relay certain messages, effectively freezing specific users' funds
- If the bridge has a single relayer or a small relayer set, censorship risk is high
- Detection: can users self-relay if the designated relayer refuses? Is there a permissionless relay fallback?

**Sequencer downtime bridge exploitation**
- On L2s with sequencers, sequencer downtime means no new blocks are produced on the L2
- Bridge messages from L1 to L2 queue up during downtime; when the sequencer restarts, all messages process at once
- Attacker can exploit the batch processing with stale oracle prices or accumulated state changes
- Detection: does the bridge enforce a grace period after sequencer restart before processing messages?

### 9. Cross-Chain Governance and Access Control

**Cross-chain admin key relay**
- Bridge relays admin/governance actions from one chain to another
- If the bridge message is delayed or replayed, the admin action executes at the wrong time
- Example: parameter change intended for current state executes after a market event, causing harm
- Detection: do cross-chain governance actions have expiry timestamps? Is there a destination-chain confirmation step?

**Multi-chain permission desync**
- Protocol deployed on multiple chains with governance on one chain
- If the governance bridge message fails silently, one chain has updated permissions while others do not
- Detection: is there a mechanism to verify governance actions were applied on all chains? What happens if relay fails?

### 10. Bridge Contract Upgrade Risks

**Upgrade during pending messages**
- Bridge contract is upgraded while messages are in flight; new implementation may interpret old message format differently
- Detection: does the bridge drain all pending messages before upgrade? Is there a message format version field?

**Proxy storage collision in bridge contracts**
- Bridge upgrades that change storage layout corrupt critical state (processed message hashes, validator set, nonce counters)
- Corrupted processed-message mapping allows replaying previously processed messages
- Detection: compare storage layout before and after upgrade; verify no slot collisions in critical mappings

### 11. Liquidity Network Bridge Exploits

**Pool imbalance extraction**
- Liquidity-based bridges (not lock-mint) maintain token pools on each chain
- Attacker drains one side by repeatedly bridging in one direction until the pool is depleted
- Detection: is there a per-transaction or per-block bridge limit? Does the fee increase with pool imbalance?

**Rebalancing arbitrage**
- During pool rebalancing, bridging fees may temporarily become negative (incentivized) or the exchange rate may be favorable
- Attacker monitors rebalancing and exploits the temporary favorable rate
- Detection: can the rebalancing fee go negative? Is the exchange rate bounded?

## Validation

- Demonstrate message replay with duplicate minting or state change on destination chain
- Show timeout exploitation with funds claimed on both source and destination
- Prove proof verification bypass with a crafted proof accepted for an unauthorized message
- Confirm validator threshold attack with economic analysis and concrete signing scenario
- Show lock-mint imbalance with concrete decimal conversion producing unbacked tokens
- Demonstrate relayer censorship by showing no permissionless relay fallback exists
- Prove cross-chain governance desync with a failed relay leaving chains in inconsistent state
- Verify pending message handling across bridge contract upgrades
- Document message hashes, chain IDs, block numbers, and state changes on both chains
