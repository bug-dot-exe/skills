## CL-STAKE-01: Epoch and Period Management Invariant

**Rule:** `EVM-STAKE-EPOCH-01`
**Severity:** low-high

### Description
The contract uses time-based periods, epochs, or duration parameters to govern reward distribution, lock schedules, or state transitions. Time boundary logic uses incorrect comparisons (inclusive vs exclusive), fails to validate duration parameters, allows retroactive or unbounded timestamps, or does not cap reward accrual at epoch boundaries. Premature or delayed state transitions, permanent fund lock from unbounded timestamps, reward over-distribution beyond epoch end, or DoS from division-by-zero on invalid durations.

### Patterns


### Detect
For every time-dependent staking function: (1) verify consistent inclusive/exclusive boundary comparisons with no overlap, (2) verify all duration and timestamp parameters have min/max bounds validation, (3) verify reward accrual is capped at period end, (4) verify epoch transitions finalize previous state and handle skipped epochs, (5) verify global parameter changes do not retroactively affect existing positions.

### Remediation


## CL-STAKE-02: Reward Accumulation Invariant

**Rule:** `EVM-STAKE-REWD-01`
**Severity:** medium-critical

### Description
The contract distributes rewards proportional to staked balances over time, using a global reward-per-token accumulator or similar mechanism. The reward accumulation state (rate, index, timestamp, user debt) is not kept in sync with every balance-changing operation, causing rewards to be lost, over-distributed, or stolen. Permanent loss of reward tokens, reward theft via stale state exploitation, protocol insolvency from over-distribution, or DoS from accumulator overflow.

### Patterns


### Detect
For every reward-distributing staking function: (1) verify the global accumulator skips zero-supply periods, (2) verify per-user reward index is checkpointed before every balance change (stake/unstake/transfer/mint/burn), (3) verify global reward state is updated before any balance or rate modification, (4) verify accumulator precision is sufficient without overflow risk, (5) verify pending rewards are accumulated not overwritten and state is reset only after successful distribution.

### Remediation


## CL-STAKE-03: Staking Configuration and Initialization Invariant

**Rule:** `EVM-STAKE-SCONF-01`
**Severity:** low-high

### Description
The contract has configurable parameters (reward tokens, fee rates, operator addresses, pool settings) that are set during initialization or modified by admin functions. Configuration parameters lack validation, initialization is incomplete or non-idempotent, mutable references break assumptions of dependent logic, or admin operations violate accounting invariants. Fund lock from invalid parameters, DoS from uninitialized state, reward loss from token misconfiguration, or protocol insolvency from unconstrained admin operations.

### Patterns


### Detect
For every configurable staking parameter: (1) verify admin-settable values have upper/lower bounds and cross-parameter consistency checks, (2) verify critical state (timestamps, addresses, counters) is properly initialized and handles the zero/default case, (3) verify token and asset references are immutable or changed only with proper migration, (4) verify external call failures in hooks or token operations cannot block core staking functions, (5) verify all entry points enforce the same constraints for shared invariants.

### Remediation


## CL-STAKE-04: Slashing and Penalty Invariant

**Rule:** `EVM-STAKE-SLASH-01`
**Severity:** medium-critical

### Description
The contract implements slashing, penalty, or fee-on-exit mechanisms that reduce user positions or redistribute value upon violation conditions. Slashing logic miscalculates penalty amounts, fails to propagate reductions through all affected state, allows evasion through timing or partial withdrawals, or uses incorrect interpolation for time-based penalty decay. Under-slashing leaves protocol under-collateralized, over-slashing causes unfair loss, cascading arithmetic errors cause DoS, or front-running allows penalty evasion.

### Patterns


### Detect
For every slashing/penalty function: (1) verify unstaking has mandatory cooldown preventing front-run evasion of slashing, (2) verify cascading slashes use saturating arithmetic and only count actually-slashed amounts, (3) verify time-based penalty decay uses correct interpolation direction, (4) verify iterative slash distribution accounts for rounding remainder, (5) verify vesting/lock cancellation slashes proportional rewards and clears all associated state.

### Remediation


## CL-STAKE-05: Reward Gaming and Flash-Staking Invariant

**Rule:** `EVM-STAKE-SNIPE-01`
**Severity:** low-high

### Description
The contract distributes rewards based on balance snapshots, instantaneous state, or without minimum holding requirements, allowing strategic entry/exit timing. Reward distribution uses instantaneous balance without time-weighting, lacks minimum stake duration, or allows atomic stake-claim-unstake sequences that extract yield without meaningful commitment. Dilution of rewards for long-term stakers, MEV extraction through sandwich attacks on reward distributions, or economic drain via flash-loan-funded stake cycling.

### Patterns


### Detect
For every reward distribution mechanism: (1) verify rewards use time-weighted calculations not instantaneous balance snapshots, (2) verify lock/boost multiplier changes checkpoint existing rewards before applying, (3) verify minimum stake duration prevents same-block stake-unstake, (4) verify reward rate changes are not front-runnable or use delayed activation, (5) verify public state-update functions cannot be front-run for favorable entry.

### Remediation


## CL-STAKE-06: Staking Accounting Invariant

**Rule:** `EVM-STAKE-STAKE-ACC-01`
**Severity:** medium-critical

### Description
The contract maintains global and per-user accounting state (balances, shares, totals, counters) that must remain internally consistent across all operations. Staking accounting state drifts out of sync due to asymmetric updates, missing state changes on certain code paths, rounding mismatches between related variables, or external dependencies that mutate without notification. Protocol insolvency from inflated balances, permanent fund lock from underflowed totals, denial of service from invariant check failures, or reward misallocation from desynchronized accounting.

### Patterns


### Detect
For every staking state mutation: (1) verify global aggregates and per-user balances are updated symmetrically on all paths including slash/admin/migration, (2) verify self-transfers and deposit-source confusion cannot create phantom balances, (3) verify reward funds and staked principal are tracked separately when using the same token, (4) verify array/mapping state remains consistent after deletions with no stale references, (5) verify multi-token accounting uses per-token state and normalizes decimals.

### Remediation


## CL-STAKE-07: Unstaking and Withdrawal Invariant

**Rule:** `EVM-STAKE-UNSTK-01`
**Severity:** medium-critical

### Description
The contract allows users to unstake, withdraw, or redeem staked positions, potentially with cooldown periods, queues, or lock schedules. Withdrawal logic fails to correctly handle state transitions — incomplete state resets leave funds locked, cooldown bypasses allow premature exits, queue accounting mismatches block legitimate withdrawals, or partial withdrawal paths have asymmetric state updates. Permanent fund lock from incomplete withdrawal logic, denial of service on withdrawal functions, cooldown/lock bypass enabling penalty evasion, or accounting desync causing insolvency.

### Patterns


### Detect
For every unstaking/withdrawal function: (1) verify all associated state (locks, debts, metadata) is fully reset on complete withdrawal, (2) verify cooldown/lock enforcement on all exit paths including emergency and migration, (3) verify queue processing handles gaps, out-of-order, and unfillable requests, (4) verify partial actions do not reset maturity/timestamp for the entire position, (5) verify global aggregate decrements match individual position changes accounting for fees and slashing.

### Remediation

