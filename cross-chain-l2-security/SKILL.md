---
name: cross-chain-l2-security
category: web3
description: Cross-chain bridge and L2 security covering PUSH0 opcode compatibility, zkSync ERA specifics, L2 sequencer downtime exploitation, L1-L2 message spoofing, bridge message replay, LayerZero/CCIP/Wormhole patterns, chain-specific opcode differences, and multi-chain deployment risks
depends_on: []
---

# Cross-Chain and L2 Security

Security testing for cross-chain protocols, bridge implementations, and Layer 2 deployments. Focus on L2 opcode incompatibilities, zkSync ERA-specific pitfalls, sequencer downtime exploitation, bridge message replay and spoofing, LayerZero/CCIP/Wormhole integration patterns, and multi-chain deployment risks.

## When to Use

- Protocol deploys on multiple L2s (Arbitrum, Optimism, Base, zkSync, Scroll, Linea, Polygon zkEVM)
- Smart contracts compiled with Solidity 0.8.20+ targeting non-Ethereum chains
- Cross-chain messaging via LayerZero, Chainlink CCIP, Wormhole, Hyperlane, or Axelar
- Bridge contract handles lock/mint, burn/mint, or liquidity pool transfers across chains
- Protocol depends on price feeds or oracles on L2s where sequencer downtime is possible
- Multi-chain governance or token deployment with synchronized state requirements
- zkSync ERA deployment with paymaster or system contract interactions

## Methodology

### 1. L2 Opcode Compatibility

**PUSH0 (Solidity 0.8.20+)**
- Solidity 0.8.20 introduced `PUSH0` as default for pushing zero onto the stack (EIP-3855)
- `PUSH0` is NOT supported on all L2s: zkSync ERA, Arbitrum (before ArbOS 11), older Polygon zkEVM versions reject it at deployment
- Contracts compiled with Solidity >= 0.8.20 without `evm_version = "paris"` will fail to deploy on unsupported chains
- Detection: check `foundry.toml` or `hardhat.config` for EVM version; if absent and solc >= 0.8.20, the contract is at risk
- Fix: set `evm_version = "paris"` in compiler config or pin Solidity to < 0.8.20 for affected chains

**SELFDESTRUCT Deprecation**
- Post-Dencun (EIP-6780): `SELFDESTRUCT` only deletes the contract if called in the same transaction as creation
- On L2s, behavior varies: some L2s implemented Dencun changes on different timelines
- Contracts relying on `SELFDESTRUCT` for fund recovery or metamorphic deployment will behave differently across chains
- Check: any use of `selfdestruct` or `SELFDESTRUCT` in assembly; trace whether it is called in the creation transaction or later

**PREVRANDAO**
- On L1: `block.prevrandao` (formerly `block.difficulty`) returns the beacon chain RANDAO mix
- On L2 rollups: `PREVRANDAO` returns a sequencer-determined or fixed value, NOT a true random source
- Arbitrum: returns a value derived from the L1 block hash, partially predictable
- Optimism/Base: returns a pseudorandom value from the sequencer, fully predictable by the sequencer operator
- zkSync: returns a constant or unsupported, depending on version
- Any contract using `block.prevrandao` for randomness is exploitable on L2s

**Block Properties**
- `block.number`: on Optimism/Base, this returns the L2 block number (updates every 2 seconds), NOT the L1 block number. Use `L1Block.number()` for L1 block number. On Arbitrum, `block.number` returns the L1 block number by default (via ArbSys).
- `block.timestamp`: generally reliable on L2s but the sequencer controls the exact timestamp within bounds (Arbitrum: up to 24 hours ahead of L1; Optimism: within the sequencer's drift limit). Contracts with tight time-based logic (auctions, deadlines) can be manipulated.
- `block.basefee`: on L2 rollups, the base fee is calculated differently. Arbitrum uses an internal gas pricing model. Optimism/Base uses EIP-1559 but with different parameters. Contracts relying on `block.basefee` for fee calculations will get unexpected values.

**Gas Pricing on Rollups**
- All optimistic and zk-rollups have a two-component gas cost: L2 execution gas + L1 data posting cost
- Arbitrum: L1 data cost exposed via `ArbGasInfo.getL1BaseFeeEstimate()`. Spiking L1 gas prices can make L2 transactions unprofitable for bots (liquidators, keepers), creating windows of vulnerability.
- Optimism/Base: L1 data cost accessible via the `L1Block` precompile. After EIP-4844 (blobs), costs dropped significantly but can still spike.
- Contracts that hardcode gas assumptions (e.g., forwarding fixed gas to callbacks) may fail on L2s when L1 data costs spike
- Check: any `gasleft()` comparisons, hardcoded gas values in `.call{gas: X}()`, or gas estimation logic

### 2. zkSync ERA Specifics

**CREATE/CREATE2 Differences**
- zkSync ERA does NOT deploy contracts using raw bytecode in `CREATE`/`CREATE2`. Instead, it uses the bytecode hash via the `ContractDeployer` system contract.
- `type(Contract).creationCode` returns empty bytes on zkSync: you cannot use it for CREATE2 address prediction
- Factory contracts that use `new Contract{salt: ...}()` will compile but the resulting address differs from the EVM formula
- Any off-chain address prediction using `keccak256(0xff, deployer, salt, keccak256(bytecodeHash))` will be wrong on zkSync
- Fix: use `IContractDeployer.getNewAddressCreate2()` for address prediction on zkSync

**Transfer/Send Gas Stipend Failure**
- `.transfer()` and `.send()` forward exactly 2300 gas, which is insufficient for smart contract wallets on zkSync
- zkSync ERA treats ALL accounts as smart contracts (account abstraction by default). Even EOAs route through a default account contract.
- Real-world impact: Gemholic protocol had 921 ETH permanently locked because `.transfer()` failed when sending to a multisig on zkSync. The funds remain unrecoverable.
- This also affects `address.transfer()` in receive/fallback patterns and any refund logic using `.send()`
- Fix: always use `.call{value: amount}("")` with return value check instead of `.transfer()` or `.send()`

**System Contracts**
- `ContractDeployer` (0x0...8006): handles all contract deployment; custom deployment logic must go through it
- `MsgValueSimulator` (0x0...8009): simulates `msg.value` behavior since zkSync uses a different native transfer model
- `NonceHolder` (0x0...8003): manages nonces for both deployment and transaction nonces separately
- `L1Messenger` (0x0...8008): handles L2-to-L1 message passing
- `KnownCodesStorage` (0x0...8004): stores known bytecode hashes; contracts must be registered before deployment
- Contracts interacting directly with these system addresses will not work on other EVM chains

**Paymaster Integration**
- zkSync paymasters can pay gas fees on behalf of users in any ERC-20 token
- Paymaster validation runs in a separate context with a gas limit: if paymaster validation reverts, the entire transaction fails
- Malicious paymasters can censor or front-run transactions by selectively accepting/rejecting
- Paymaster contracts on zkSync differ entirely from ERC-4337 paymasters on other chains

**Missing/Different Opcodes**
- `EXTCODECOPY`: not fully supported on zkSync; returns zeros for some system contracts
- `CODECOPY`: bytecode is stored differently (bytecode hashes, not raw bytecode); `address(this).code` may not return expected results
- `CALLCODE`: deprecated and not supported; use `DELEGATECALL` instead
- `CODESIZE`: for deployed contracts, returns the hash size, not the actual bytecode size
- `tx.origin`: behaves differently with account abstraction since even EOA transactions route through account contracts
- `ecrecover`: works but with different gas costs; precompile addresses may differ

### 3. Sequencer Risks

**Sequencer Downtime and Stale Prices**
- L2 sequencers (Arbitrum, Optimism, Base) are centralized operators that order and batch transactions
- When the sequencer goes offline, NO new transactions are processed on L2 (Arbitrum has a delayed inbox with ~24h delay for L1 forced inclusion)
- During downtime, Chainlink price feeds on L2 stop updating but their `updatedAt` timestamps remain at the last update
- A staleness check like `require(block.timestamp - updatedAt < 3600)` will eventually PASS again when the sequencer restarts, even if the price is hours old and dangerously stale
- Real-world: during Arbitrum sequencer outages (June 2023, multiple events), prices diverged significantly from L1

**Sequencer Uptime Feed (Chainlink)**
- Chainlink provides a sequencer uptime feed on Arbitrum (`0xFdB631F5EE196F0ed6FAa767959853A9F217697D`) and Optimism
- Correct integration requires checking BOTH the sequencer status AND a grace period after restart:
```solidity
(, int256 answer, uint256 startedAt, , ) = sequencerUptimeFeed.latestRoundData();
bool isSequencerUp = answer == 0;
if (!isSequencerUp) revert SequencerDown();
uint256 timeSinceUp = block.timestamp - startedAt;
if (timeSinceUp < GRACE_PERIOD) revert GracePeriodNotOver();
```
- Missing this check allows exploitation immediately after sequencer restart when prices are still stale
- Many protocols skip this entirely, or check uptime but not the grace period

**Sequencer Manipulation Vectors**
- Transaction ordering: the sequencer sees all pending transactions and can reorder for MEV extraction
- Censorship: sequencer can selectively exclude transactions (e.g., block liquidations to protect specific positions)
- Timestamp manipulation: sequencer controls L2 block timestamps within L1-enforced bounds
- Forced inclusion delay: on Arbitrum, users can force-include transactions via L1 after ~24 hours, but this delay creates a censorship window
- On Optimism/Base, there is no delayed inbox mechanism; if the sequencer is down, users must wait

**Grace Period After Restart**
- After sequencer restarts, positions that became liquidatable during downtime should NOT be immediately liquidated
- Users had no ability to add collateral or close positions during downtime
- Best practice: implement a grace period (typically 1 hour) after sequencer restart before allowing liquidations or time-sensitive actions
- Check: does the protocol have any liquidation, auction, or deadline logic? If yes, is there a grace period tied to sequencer uptime?

**Delayed Transaction Inclusion**
- Transactions submitted during sequencer downtime queue in the delayed inbox (Arbitrum) or are simply dropped (Optimism/Base)
- Arbitrum delayed inbox transactions have a different `msg.sender` than direct sequencer submissions (they come from the L1 bridge)
- Contracts that check `msg.sender` against a whitelist may reject delayed inbox transactions
- Time-sensitive operations (votes, auctions, loan repayments) submitted during downtime may execute far later than intended

### 4. Bridge Security Patterns

**Message Replay**
- A bridge message without a unique nonce or message hash tracking can be replayed: the same payload is accepted and processed multiple times on the destination chain
- Check: does the bridge contract maintain a `mapping(bytes32 => bool) processedMessages`? Is the nonce per-sender, per-chain, or global?
- Cross-chain replay: a message valid for Chain A is replayed on Chain B if the destination chain ID is not included in the message hash
- Batch replay: a valid message within a batch allows the entire batch to be resubmitted if the batch is not individually tracked

**Message Spoofing**
- Source chain address and chain ID must be validated in the receive handler on the destination chain
- Common flaw: `onReceive()` handler does not verify that `msg.sender` is the trusted bridge contract, or does not validate the source chain/address
- LayerZero: `_lzReceive` must validate that the sender is a registered `peer` for the source endpoint ID
- CCIP: `ccipReceive` must verify `msg.sender == i_ccipRouter` and the source chain selector + sender
- Wormhole: the VAA must be parsed and the emitter address + chain ID verified against a trusted set

**Relayer Manipulation**
- Relayers (off-chain actors that submit proofs/messages to the destination chain) can: delay delivery, reorder messages, or front-run the payload with a competing transaction
- If the bridge relies on a single relayer, it is a censorship and liveness risk
- Token bridges: relayer can observe a large bridge transfer, front-run it with a DEX trade on the destination chain, and profit from the price impact
- Check: are there multiple relayers? Is there a permissionless relay mechanism? What happens if the relayer never delivers?

**Token Bridge Accounting**
- Lock-and-mint: tokens locked on source, minted on destination. Risk: mint without lock (spoofed message), lock without mint (message lost), or lock on source but destination mint reverts and no refund path exists
- Burn-and-mint: tokens burned on source, minted on destination. Risk: burn succeeds but mint message never arrives, destroying user funds permanently
- Liquidity pool bridges: LP provides liquidity on destination. Risk: pool drained if message is spoofed, or pool imbalanced if one side is exploited
- Check: is the total supply across all chains consistent? Can minting exceed the locked/burned amount?

**Finality Risks**
- Optimistic rollups: 7-day challenge period before finality. A message relayed before finality could be invalidated by a fraud proof.
- ZK rollups: finality when the ZK proof is verified on L1 (minutes to hours). Faster but still not instant.
- L1 Ethereum: 2 epochs (~12.8 minutes) for finality post-Merge.
- Bridges that relay messages before source chain finality risk double-spend: relay message, then source chain reorgs and the source transaction disappears.
- Check: how many confirmations does the bridge wait? Is there a challenge/dispute mechanism?

### 5. LayerZero-Specific

**OApp/OFT Peer Validation**
- Every LayerZero OApp must set trusted peers per chain: `setPeer(uint32 eid, bytes32 peer)`
- If `peers[eid]` is not set for a source chain, messages from that chain should be rejected
- If `setPeer` is callable by a non-admin, an attacker can register a malicious contract as a trusted peer
- OFT (Omnichain Fungible Token): peer must be the canonical OFT contract on each chain; misconfigured peers allow minting from unauthorized sources

**lzCompose Sender Impersonation**
- `lzCompose` allows composing multiple cross-chain actions in a single message
- The `_from` parameter in `lzCompose` can be spoofed if not validated against the actual sender
- Check: does the composed receiver validate `_from` against `peers[_origin.srcEid]`?
- A malicious composed message can impersonate a trusted sender to execute privileged actions

**enforcedOptions for Gas Limits**
- LayerZero v2 allows setting `enforcedOptions` to guarantee minimum gas for execution on the destination chain
- If `enforcedOptions` are not set, a sender can provide insufficient gas, causing the destination execution to revert after the source transaction succeeds
- This creates a stuck message: source tokens burned/locked, but destination execution failed
- The message can be retried, but griefing is possible if the attacker controls the gas parameter
- Check: are `enforcedOptions` set for all message types (`SEND`, `SEND_AND_CALL`)?

**Ordered vs Unordered Nonce Channels**
- LayerZero v2 supports ordered nonces (messages must be processed in sequence) and unordered nonces (any message can be processed at any time)
- Ordered channels: if message N fails, messages N+1, N+2, ... are blocked until N is resolved. This can be used for griefing.
- Unordered channels: no ordering guarantee, but individual messages can be skipped or processed out of order, which may break dependent state
- Check: does the application logic depend on message ordering? Is the nonce channel type configured correctly?

**DVN (Decentralized Verifier Network) Collusion**
- LayerZero v2 replaces the Ultra Light Node with configurable DVNs (Decentralized Verifier Networks)
- The security model depends on the DVN configuration: `requiredDVNs` and `optionalDVNs` with a `optionalDVNThreshold`
- If only 1 DVN is required and it is compromised, all messages can be forged
- Check: how many DVNs are configured? What is the threshold? Are they independent entities?
- Low DVN diversity (e.g., single operator running multiple DVN instances) reduces security

**Shared Decimals Truncation in OFT**
- LayerZero OFT uses `sharedDecimals` (default: 6) to normalize token amounts across chains
- Tokens with more than 6 decimals lose precision when bridged: `amount` is truncated to `sharedDecimals` and the remainder (`dust`) is kept on the source chain
- If `sharedDecimals` is misconfigured (e.g., set to 8 for a 6-decimal token), amounts are incorrectly scaled
- Dust amounts can accumulate in the OFT contract over time, creating accounting discrepancies
- Check: does the token have > 6 decimals? Is `sharedDecimals` set correctly? Is dust handled?

### 6. CCIP (Chainlink Cross-Chain Interoperability Protocol)

**ccipReceive Handler Access Control**
- The `ccipReceive` function is called by the CCIP router contract on the destination chain
- MUST verify: `msg.sender == i_ccipRouter` (the trusted CCIP router address)
- MUST verify: the source chain selector and sender address against an allowlist
- Common flaw: checking the router but not the source chain/sender, allowing any message from any chain
- The `_ccipReceive` internal function (in Chainlink's `CCIPReceiver` base) already checks the router, but source validation is the developer's responsibility

**Message Lane Configuration**
- CCIP message lanes are unidirectional: a lane from Chain A to Chain B does not automatically create a return lane
- Fee tokens must be approved on the source chain: LINK or native token
- If the fee token is insufficient, the transaction reverts on the source chain (no stuck messages)
- Rate limits are per-lane, per-token: a high-volume lane can be rate-limited independently

**Rate Limiting on Token Pools**
- CCIP token pools enforce rate limits: `maxCapacity` (bucket size) and `rate` (refill rate per second)
- If a protocol depends on large bridge transfers, rate limits can cause transactions to revert during high-volume periods
- An attacker can intentionally fill the rate limit bucket to grief legitimate users
- Check: what are the rate limits for the token pools in use? Can they be manipulated?

**Gas Limit for Cross-Chain Execution**
- The sender specifies `gasLimit` in the CCIP message for destination execution
- Insufficient gas: destination `ccipReceive` runs out of gas and reverts. The message enters a failed state and can be retried manually.
- Excessive gas: sender overpays in fees. No security risk but economic waste.
- Check: is the gas limit hardcoded, user-supplied, or estimated? Is there a minimum enforced?

**Revert Handling on Destination**
- If `ccipReceive` reverts on the destination, the message is NOT automatically retried
- The message enters a `FAILED` state and must be manually retried via the `manuallyExecute` function on the CCIP OffRamp contract
- Tokens sent with the message are held in the token pool until the message succeeds or is resolved
- A contract that always reverts on receive can permanently lock tokens in the pool
- Check: can the `ccipReceive` handler revert under any condition? Is there a fallback?

### 7. Wormhole

**Guardian Set Validation**
- Wormhole relies on a set of 19 Guardians (as of 2024) with a 13/19 threshold for message signing
- VAAs (Verified Action Approvals) contain signatures from Guardians; the on-chain verifier checks signature count against the threshold
- If the guardian set index in the VAA does not match the current on-chain set, the VAA should be rejected
- Stale guardian set: after a guardian rotation, old VAAs signed by the previous set may still be valid until the old set expires
- Check: does the protocol verify the guardian set index? Is there an expiry on old guardian sets?

**VAA (Verified Action Approval) Replay**
- A VAA is a signed attestation of an event on the source chain. Once verified, it should be marked as consumed.
- Replay attack: submit the same VAA to the destination contract multiple times to mint/transfer repeatedly
- The Wormhole core bridge tracks consumed VAAs, but custom integrations that verify VAAs independently may not
- Check: does the receiving contract call `wormhole.parseAndVerifyVM()` AND track consumed VAA hashes?
- Cross-chain replay: a VAA intended for Chain A submitted on Chain B (if the destination chain ID is not validated in the payload)

**Governance Message Injection**
- Wormhole governance messages (guardian set upgrades, contract upgrades) use the same VAA format
- If a contract accepts governance-type messages without verifying the emitter is the Wormhole governance contract, an attacker with sufficient guardian signatures could inject malicious governance actions
- Check: for any `completeGovernance()` or similar function, verify the emitter chain and address match the expected governance source

**Token Attestation vs Native Asset**
- Wormhole distinguishes between attested tokens (wrapped representations) and native assets
- Attested tokens: Wormhole creates a wrapped token contract on the destination chain
- Native assets: the protocol may expect to receive the native token but get the wrapped version instead (or vice versa)
- Check: does the protocol handle both wrapped and native versions correctly? Are there denomination mismatches?

### 8. Multi-Chain Deployment Risks

**Hardcoded Addresses**
- Contracts that hardcode addresses for routers, oracles, admin multisigs, or token contracts will break when deployed on a different chain
- Common pattern: constructor parameters for chain-specific addresses, but the deployment script reuses the same values across chains
- Uniswap router, WETH, Chainlink feed addresses, and governance multisig addresses ALL differ between chains
- Check: grep for address literals in the contract code; verify each is correct for the target chain

**Chain ID in Signatures**
- EIP-712 domain separators include `chainId`; if the domain separator is computed at deployment time and cached, it is correct
- If `chainId` is hardcoded or computed at runtime on a chain that does not match (e.g., after a hard fork), signatures can be replayed across chains
- `block.chainid` can change after a hard fork: the original chain keeps the old ID, the fork gets a new one. Cached domain separators become valid on both chains.
- Check: is the domain separator recomputed dynamically or cached? Does the contract handle chain ID changes?

**Different Token Addresses/Decimals**
- USDC on Ethereum: `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` (6 decimals)
- USDC on Arbitrum: `0xaf88d065e77c8cC2239327C5EDb3A432268e5831` (6 decimals, but different address)
- USDC.e (bridged USDC) on Arbitrum: `0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8` (6 decimals, yet another address)
- WBTC: 8 decimals on all chains, but addresses differ
- Contracts that store token addresses in configuration must be updated per-chain; a deployment script error can point to the wrong token or a nonexistent address

**CREATE2 Address Predictability**
- `CREATE2` address depends on `deployer`, `salt`, and `keccak256(bytecodeHash)`
- On EVM-equivalent L2s (Arbitrum, Optimism, Base): same formula, same address if deployer and bytecode match
- On zkSync ERA: completely different formula (uses `ContractDeployer` system contract)
- On other chains: variations in address derivation may exist
- Protocols that rely on `CREATE2` for counterfactual addresses (e.g., pre-computed wallet addresses) will get different addresses on non-EVM-equivalent chains

**Cross-Chain Governance Synchronization**
- Governance decisions made on Chain A (e.g., parameter updates, pausing, upgrades) must be propagated to Chains B, C, D
- If propagation uses a bridge message: the decision can be delayed, censored, or arrive out of order
- If each chain has independent governance: parameters can diverge, creating arbitrage or inconsistency
- Timelock delays may differ across chains, creating windows where Chain A is updated but Chain B is not
- Check: how are governance decisions propagated? Is there a single source of truth? What happens during propagation delay?

**Nonce Management Across Chains**
- EOA nonces are per-chain: the same deployer address has independent nonces on each chain
- If a deployment script assumes nonce N on all chains, a single failed transaction on one chain shifts all subsequent addresses
- `CREATE` addresses depend on deployer + nonce: address mismatch if nonces diverge
- Best practice: use `CREATE2` with explicit salts instead of nonce-dependent `CREATE` for cross-chain consistency

## Key Commands

```bash
# --- Detection Patterns (grep for cross-chain issues) ---

# PUSH0 / EVM version issues
grep -rn "pragma solidity" --include="*.sol" | grep -E "0\.8\.(2[0-9]|[3-9][0-9])"
grep -rn "evm_version" foundry.toml hardhat.config.ts hardhat.config.js 2>/dev/null

# zkSync-specific risks
grep -rn "\.transfer(" --include="*.sol"
grep -rn "\.send(" --include="*.sol"
grep -rn "type(.*).creationCode" --include="*.sol"
grep -rn "EXTCODECOPY\|CODECOPY\|CALLCODE" --include="*.sol"

# Sequencer uptime / staleness
grep -rn "sequencer" --include="*.sol" -i
grep -rn "latestRoundData\|updatedAt\|answeredInRound" --include="*.sol"
grep -rn "GRACE_PERIOD\|gracePeriod\|grace_period" --include="*.sol"

# Bridge patterns
grep -rn "lzReceive\|_lzReceive\|lzCompose" --include="*.sol"
grep -rn "ccipReceive\|_ccipReceive\|CCIPReceiver" --include="*.sol"
grep -rn "parseAndVerifyVM\|verifyVM\|wormhole" --include="*.sol" -i
grep -rn "setPeer\|setTrustedRemote\|trustedRemoteLookup" --include="*.sol"

# Cross-chain message validation
grep -rn "srcEid\|srcChainId\|sourceChainSelector\|emitterChainId" --include="*.sol"
grep -rn "onlyRouter\|onlyBridge\|onlyRelayer" --include="*.sol"
grep -rn "processedMessages\|consumedVAAs\|usedNonces" --include="*.sol"

# LayerZero-specific
grep -rn "enforcedOptions\|setEnforcedOptions" --include="*.sol"
grep -rn "sharedDecimals\|decimalConversionRate" --include="*.sol"
grep -rn "OApp\|OFT\|ONFT\|EndpointV2" --include="*.sol"

# CCIP-specific
grep -rn "i_ccipRouter\|ccipRouter\|Client.EVM2AnyMessage" --include="*.sol"
grep -rn "getRouter\|supportsInterface.*0x85572ffb" --include="*.sol"

# Multi-chain deployment risks
grep -rn "block\.chainid\|block\.prevrandao\|block\.difficulty" --include="*.sol"
grep -rn "DOMAIN_SEPARATOR\|domainSeparator\|EIP712" --include="*.sol"
grep -rn "selfdestruct\|SELFDESTRUCT" --include="*.sol"
grep -rn "0x[a-fA-F0-9]\{40\}" --include="*.sol" | grep -v "address(0)"

# Hardcoded gas amounts (risky on L2s)
grep -rn "\.call{gas:" --include="*.sol"
grep -rn "gasleft()" --include="*.sol"
grep -rn "2300\|21000\|30000" --include="*.sol"
```

```bash
# --- Fork Testing ---

# Test contract on different chain forks to detect behavioral differences
# Arbitrum
forge test --fork-url https://arb-mainnet.g.alchemy.com/v2/{KEY} -vvv

# Optimism
forge test --fork-url https://opt-mainnet.g.alchemy.com/v2/{KEY} -vvv

# Base
forge test --fork-url https://base-mainnet.g.alchemy.com/v2/{KEY} -vvv

# zkSync ERA (requires foundry-zksync or hardhat-zksync)
# Standard forge does not support zkSync; use era-test-node or hardhat-zksync-deploy
npx hardhat test --network zkSyncTestnet

# Compare Chainlink feed staleness across chains
cast call {CHAINLINK_FEED} "latestRoundData()" --rpc-url {L2_RPC}
cast call {SEQUENCER_UPTIME_FEED} "latestRoundData()" --rpc-url {ARB_RPC}

# Check bridge message processing state
cast call {BRIDGE} "processedMessages(bytes32)(bool)" {MSG_HASH} --rpc-url {DEST_RPC}
cast call {OFT} "peers(uint32)(bytes32)" {EID} --rpc-url {RPC}

# Verify CREATE2 address matches across chains
cast create2 --starts-with 0x --deployer {DEPLOYER} --init-code-hash {HASH} --salt {SALT}
```

## Validation

- **PUSH0 compatibility**: compile the contract with `--evm-version paris`, deploy to L2 fork, verify deployment succeeds; then compile without the flag and confirm deployment fails on affected chains
- **zkSync .transfer() failure**: write a test where a smart contract wallet receives ETH via `.transfer()` on a zkSync fork; confirm it reverts with out-of-gas, then verify `.call{value:}("")` succeeds
- **Sequencer downtime**: fork an L2, mock the sequencer uptime feed returning `answer = 1` (down), verify the protocol correctly blocks price-dependent operations; then mock `answer = 0` with `startedAt` within the grace period and verify operations are still blocked
- **Bridge message replay**: submit a valid bridge message, record the message hash, submit the same message again; verify the second submission is rejected by the `processedMessages` check
- **Bridge message spoofing**: call the receive handler from a non-bridge address; confirm it reverts with an access control error. Call from the bridge address but with a non-whitelisted source chain/sender; confirm rejection.
- **LayerZero peer misconfiguration**: call `lzReceive` with a source EID that has no peer configured; confirm the message is rejected. Then set a malicious peer and verify the message is accepted (demonstrating the risk).
- **CCIP gas limit exhaustion**: send a CCIP message with a gas limit too low for the `ccipReceive` handler; verify the message enters the failed state and can be manually retried with sufficient gas
- **Cross-chain signature replay**: sign an EIP-712 message on Chain A, submit it on Chain B's fork; verify it is accepted if `chainId` is not in the domain separator (proving the vulnerability) and rejected if it is (proving the mitigation)
- **Multi-chain address divergence**: deploy the same contract with `CREATE2` on two different chain forks; compare the deployed addresses; verify they match on EVM-equivalent chains and differ on zkSync
- **Wormhole VAA replay**: parse and verify a VAA on the destination contract, then submit the same VAA again; confirm the second call reverts due to the consumed hash check
