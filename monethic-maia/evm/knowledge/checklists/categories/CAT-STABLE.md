## CL-STABLE-01: Stablecoin Mechanism Invariant

**Rule:** `EVM-STABLE-MECH-01`
**Severity:** high-critical

### Description
The protocol implements a stablecoin: algorithmic, collateralized (CDP), fractional-reserve, or rebasing. The system mints a pegged token backed by collateral, algorithmic expansion/contraction, or a combination of both. Stablecoin protocols contain intertwined mechanisms (minting, redemption, liquidation, collateral management, peg maintenance) where a flaw in any single component can cascade into systemic insolvency, bank-run dynamics, or permanent depeg.

### Patterns


### Detect
For every stablecoin protocol: (1) verify minting uses manipulation-resistant price feeds with liquidity-depth awareness, (2) verify liquidation has partial execution, cooldowns, and cascade circuit breakers, (3) verify redemption has dynamic fees, rate limits, and market-price awareness, (4) verify algorithmic expansion/contraction maintains a hard collateral backing floor, (5) verify interest/fee accrual is included in all debt calculations and health checks.

### Remediation


## CL-STABLE-02: Peg Assumption Invariant

**Rule:** `EVM-STABLE-PEG-01`
**Severity:** medium-high

### Description
The contract values a pegged, wrapped, or derivative asset (stablecoins, LSTs like stETH/rETH, wrapped tokens like WBTC) by assuming a fixed exchange rate rather than querying a live price feed. The protocol hardcodes a 1:1 (or other fixed) exchange rate between assets that can and do deviate from their peg. This includes stablecoin/USD assumptions, LST/ETH canonical rate vs market rate, wrapped asset parity, and derivative token pricing via underlying feed instead of derivative-specific feed. During depeg events, the protocol overvalues the depegged asset. Borrowers mint debt against inflated collateral. Redemption arbitrageurs drain reserves by redeeming at par when market price is below par. Liquidations fail to trigger because the hardcoded rate masks the true undercollateralization.

### Patterns


### Detect
For every pegged/wrapped/derivative asset valuation: (1) verify stablecoins are priced via oracle, not hardcoded to $1.00, (2) verify LSTs use minimum of canonical and market rate, (3) verify wrapped tokens use a wrapper-specific price feed, not just the underlying, (4) verify derivative tokens have their own price feed reflecting their specific risk, (5) verify redemption mechanisms use market-aware rates with depeg circuit breakers.

### Remediation

