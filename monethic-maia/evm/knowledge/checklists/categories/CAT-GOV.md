## CL-GOV-01: Timelock & Delay Enforcement Invariant

**Rule:** `EVM-GOV-LOCK-01`
**Severity:** medium-high

### Description
The contract implements timelocks, lock-up periods, cooldowns, or delay mechanisms for governance actions, parameter changes, or user fund access. Timelock and delay enforcement can be bypassed through role-based shortcuts, missing delay on parameter changes, permissionless out-of-order execution, reentrancy across timelock operations, incorrect lock state validation for vote-escrowed tokens, or asymmetric validation between initializers and setters. Privileged actors make instant changes without community review, users are locked beyond intended periods by retroactive parameter changes, governance is captured through immediate parameter manipulation, locked assets become permanently inaccessible, or invalid state is introduced through unvalidated update paths.

### Patterns


### Detect
For every governance system with timelocks or delays: (1) verify all privileged actions route through timelock not just role checks, (2) verify parameter updates have sanity bounds and don't retroactively affect existing users, (3) verify timelock execution has access control and ordering enforcement, (4) verify ve-token lock operations validate all inputs and use absolute time comparisons, (5) verify lock/cooldown parameters are snapshotted at entry and emergency exits exist, (6) verify init and update paths enforce identical validation constraints.

### Remediation


## CL-GOV-02: Proposal Lifecycle Integrity Invariant

**Rule:** `EVM-GOV-PROP-01`
**Severity:** medium-high

### Description
The contract implements a proposal-based governance system with creation, voting, cancellation, and execution phases. Proposal state transitions lack proper validation, allowing creation with insufficient checks, execution with unvalidated payloads, cancellation logic inversions, duplicate/spam proposals, and missing expiration enforcement. Malicious proposals pass or execute undetected, legitimate proposals get improperly cancelled, governance is spammed into unusability, expired proposals execute with outdated parameters, and proposal payloads bypass safety checks.

### Patterns


### Detect
For every proposal-based governance system: (1) verify proposal creation enforces uniqueness and non-zero thresholds, (2) verify cancellation logic uses correct comparison operators and creation-time thresholds, (3) verify execution validates all payload elements and msg.value, (4) verify proposals have enforced deadlines and bounded extensions, (5) verify state machine transitions handle boundaries correctly and validate parameters at creation.

### Remediation


## CL-GOV-03: Quorum & Threshold Integrity Invariant

**Rule:** `EVM-GOV-QUORUM-01`
**Severity:** medium-high

### Description
The contract implements quorum requirements, voting thresholds, multisig approval counts, or minimum participation checks for governance decisions. Quorum and threshold calculations contain integer truncation errors, use static denominators against dynamic numerators, fail to validate reachability, or become desynchronized with the actual voter set. Minority passes proposals that should require majority, quorum becomes permanently unreachable locking governance, thresholds desync from signer sets allowing unauthorized execution, or zero-value edge cases bypass all checks.

### Patterns


### Detect
For every governance quorum/threshold system: (1) verify threshold calculations round up to prevent minority bypass, (2) verify quorum denominators track dynamic voting power via snapshots, (3) verify thresholds are initialized non-zero and validated as reachable, (4) verify multisig thresholds synchronize with signer set changes, (5) verify quorum recalculates on strategy/membership changes.

### Remediation


## CL-GOV-04: Voting Power Integrity Invariant

**Rule:** `EVM-GOV-VOTE-01`
**Severity:** medium-critical

### Description
The contract implements a governance voting system where users hold, delegate, or calculate voting power for decision-making. Voting power can be artificially inflated, double-counted, desynchronized from actual holdings, or manipulated through flash loans, delegation cycles, stale snapshots, and incorrect accounting. Attackers gain disproportionate governance influence, pass malicious proposals, extract treasury funds, override quorum, or dilute legitimate voters' power.

### Patterns


### Detect
For every governance voting system: (1) verify voting weight uses historical snapshots not current-block state, (2) verify delegation accounting prevents double-counting and cycles, (3) verify snapshot freshness and checkpoint synchronization, (4) verify power calculations handle precision/exclusion/bounds correctly, (5) verify all transfer/redeem/merge paths update voting power atomically.

### Remediation

