## CL-XCHAIN-01: Cross-Chain Accounting Integrity Invariant

**Rule:** `ACCT-01`
**Severity:** high-critical

### Description
The protocol transfers value across chains via lock/mint, burn/mint, or liquidity pool mechanisms where token amounts, decimals, or supply must remain consistent across deployments. Cross-chain bridges fail to maintain accounting parity -- decimal mismatches cause silent truncation, supply invariants are violated by uncapped minting, share-vs-value confusion causes exchange rate drift, token mappings are inconsistent, or liquidity pools are drained without on-chain solvency checks. Permanent fund loss from decimal truncation, infinite minting from supply invariant violation, exchange rate manipulation on rebasing tokens, double-registration draining bridge reserves, or liquidity pool insolvency.

### Patterns


### Detect
For every cross-chain value transfer: (1) verify decimal normalization handles both upward and downward conversion with dust accounting, (2) verify total minted on destination never exceeds total locked/burned on source, (3) verify rebasing tokens bridge share counts not underlying values, (4) verify token registrations enforce 1:1 uniqueness with no self-mapping, (5) verify liquidity pools enforce on-chain solvency checks and rate limits before releasing funds.

### Remediation


## CL-XCHAIN-02: Cross-Chain Finality & State Ordering Invariant

**Rule:** `FINAL-01`
**Severity:** high-critical

### Description
The protocol relies on cross-chain state reads, block confirmations, message ordering, or time-dependent parameters that differ across source and destination chains. Cross-chain protocols assume instant finality, consistent block times, in-order message delivery, or synchronized timestamps across chains. These assumptions break under reorgs, sequencer downtime, variable block production, or asynchronous message delivery. Premature state reads enable front-running or double-spending during reorgs. Stale cross-chain state allows exploitation of price/rate differences. Out-of-order execution corrupts sequential state machines. Time-dependent operations break across chains with different block cadences.

### Patterns


### Detect
For every cross-chain state dependency: (1) verify block confirmation requirements match each source chain's finality model, (2) verify cross-chain state reads include freshness timestamps with staleness bounds, (3) verify the protocol handles out-of-order message delivery via buffering or monotonic checks, (4) verify time-dependent logic uses chain-agnostic timestamps not block numbers and enforces asymmetric timelocks, (5) verify queued transfers snapshot configuration at queue time and handle peer migration gracefully.

### Remediation


## CL-XCHAIN-03: Cross-Chain Liveness & Error Recovery Invariant

**Rule:** `LIVE-01`
**Severity:** medium-high

### Description
The contract sends or receives cross-chain messages that may fail on the destination, require gas fee payment, or depend on bridge infrastructure availability. Cross-chain protocols lack error recovery mechanisms -- failed messages permanently block ordered channels, insufficient gas causes destination reverts with no retry, missing fee handling prevents message delivery, no fallback exists when bridge infrastructure is down, and pause mechanisms applied to async receivers cause permanent fund lock. Permanently blocked message channels halt all subsequent cross-chain operations. Underfunded gas causes irreversible message loss. Missing fee refunds or overpayment locks user funds. Bridge downtime with no escape hatch traps assets. Paused receivers reject inbound bridge messages, locking bridged funds.

### Patterns


### Detect
For every cross-chain message handler: (1) verify execution failures are caught and stored for retry instead of reverting on ordered channels, (2) verify destination gas limits are configurable with enforced minimums per chain, (3) verify fee estimation uses actual payloads with overpayment refunds to the user, (4) verify timeout-based recovery and L1 forced-exit mechanisms exist for locked funds, (5) verify pause guards do not block bridge receivers and instead store messages for deferred execution.

### Remediation


## CL-XCHAIN-04: Cross-Chain Message Authentication Invariant

**Rule:** `MSG-01`
**Severity:** medium-critical

### Description
The contract receives cross-chain messages via a bridge, relayer, or messaging protocol (LayerZero, CCIP, Wormhole, Axelar, Hyperlane) and acts on the payload. Cross-chain message receivers fail to authenticate the origin of inbound messages -- missing sender validation, missing source chain verification, unsigned parameters, unvalidated payload schemas, or insufficient verifier diversity. Unauthorized actors forge cross-chain messages to mint tokens, drain bridges, bypass access control, or corrupt destination state. A single missing check can allow full protocol takeover from any chain.

### Patterns


### Detect
For every cross-chain message receiver: (1) verify msg.sender is the authorized bridge endpoint, (2) verify source chain ID and source sender against a trusted peer registry, (3) verify all payload parameters are covered by cryptographic signatures, (4) verify encoding schema matches between source encoder and destination decoder, (5) verify multiple independent verifiers are required for message attestation.

### Remediation


## CL-XCHAIN-05: Cross-Chain Replay Protection Invariant

**Rule:** `REPLAY-01`
**Severity:** medium-critical

### Description
The contract processes cross-chain messages, signatures, or state proofs that could be re-submitted on the same or different chain. Cross-chain operations lack replay protection -- missing nonces, absent chain ID binding, no domain separation, reusable proofs, or non-unique message identifiers. An attacker replays a valid message to duplicate its effect. Double-spending bridged assets, re-executing withdrawals, replaying governance votes across chains, duplicating mints, or re-deploying contracts with identical CREATE2 salts on new chains.

### Patterns


### Detect
For every cross-chain message handler: (1) verify a unique nonce is included in all signed payloads and marked consumed after use, (2) verify the message hash includes destination chain ID and contract address for domain separation, (3) verify sequence numbers are monotonically increasing and scoped per source chain, (4) verify deployment salts and transaction signatures include chain ID, (5) verify cross-chain events include unique identifiers that prevent proof reuse.

### Remediation

