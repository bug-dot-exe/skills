## CL-PRED-01: Prediction Market Creation & Participation Invariant

**Rule:** `EVM-PRED-MKT-01`
**Severity:** medium-high

### Description
The contract creates prediction markets, accepts bets/positions, or manages participation phases with timed transitions. Prediction market logic fails when phase transitions allow late participation after outcome information is available, timing boundaries overlap enabling same-block front-running, market parameters are unvalidated, or sentinel/default values collide with legitimate state.

### Patterns


### Detect
For every prediction market: (1) verify participation closes strictly before resolution with enforced minimum duration, (2) verify timestamp boundaries use exclusive comparisons to prevent same-block front-running, (3) verify market parameters are validated (>=2 outcomes, oracle-sourced prices, bounded inputs), (4) verify sentinel/default values don't collide with legitimate oracle or scoring values, (5) verify YES+NO prices sum to exactly 1.00 in order matching.

### Remediation


## CL-PRED-02: Prediction Market Settlement & Payout Invariant

**Rule:** `EVM-PRED-SETTLE-01`
**Severity:** high-critical

### Description
The contract resolves prediction market outcomes and distributes payouts, handles Conditional Token Framework (CTF) positions, or manages collateral pools for binary/multi-outcome markets. Settlement logic fails when binary outcomes have implicit equality bias, CTF token transfers enable reentrancy through ERC-1155 callbacks, fees are collected in outcome-specific tokens creating directional exposure, negative yield events distribute losses incorrectly, or collateral accounting doesn't enforce position invariants.

### Patterns


### Detect
For every prediction market settlement: (1) verify binary outcomes handle equality explicitly (three-way branch or draw), (2) verify CTF/ERC-1155 token transfers use reentrancy guards and CEI pattern, (3) verify fees are collected in collateral tokens not outcome tokens, (4) verify negative yield events reduce collateral backing uniformly not by probability split, (5) verify payout calculations have explicit bounds checks with descriptive errors.

### Remediation

