## CL-VESTING-01: Vesting Schedule Integrity Invariant

**Rule:** `EVM-VESTING-SCHED-01`
**Severity:** medium-critical

### Description
The contract implements token vesting, time-locked allocations, or scheduled release mechanisms for team, investor, or user tokens. Vesting contracts manage the tension between locked and unlocked tokens across time. Flaws in time-branch logic, revocation accounting, liquidity reservation, allocation updates, or initial lock enforcement allow premature access, fund loss, or insolvency.

### Patterns


### Detect
For every vesting contract: (1) verify privileged allocations (team, dev, advisor) are locked in vesting contracts, not sent directly to EOAs, (2) verify all withdrawal paths check remaining balance covers outstanding vesting debt (totalAllocated - totalReleased), (3) verify time-branch logic explicitly handles before-cliff, active-vesting, and post-end states with no default-to-100% fallthrough, (4) verify revocation only reclaims unvested tokens and preserves the beneficiary's earned portion, (5) verify allocation updates require newTotal >= claimed to prevent underflow DoS.

### Remediation

