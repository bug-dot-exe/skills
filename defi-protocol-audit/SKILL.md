---
name: defi-protocol-audit
category: web3
description: DeFi protocol audit covering flash loan attacks, oracle manipulation, liquidity pool drainage, governance attacks, token approval abuse, sandwich attacks, and MEV
depends_on: []
---

# DeFi Protocol Audit

Security testing for DeFi protocols. Focus on flash loan attack vectors, oracle manipulation, liquidity pool drainage, governance attacks, token approval abuse, sandwich attacks, and MEV extraction.

## When to Use

- Target is a DeFi protocol (DEX, lending, yield aggregator, staking, vault)
- Protocol uses price oracles for critical calculations
- Flash loan providers or receivers are in scope
- Governance token or on-chain voting mechanism exists
- Protocol handles user deposits with share-based accounting

## Methodology

### 1. Flash Loan Attack Vectors

- **Spot price manipulation**: flash-borrow to move AMM price, exploit dependent protocol, repay
- **Collateral inflation**: borrow assets to inflate collateral value, take out loan, default on repayment
- **Governance manipulation**: flash-borrow governance tokens to pass a malicious proposal in one tx
- **Liquidity manipulation**: add/remove liquidity to manipulate pool ratios used in calculations
- **Callback reentrancy**: flash loan callback exploits reentrancy in the lending or target protocol
- Trace: identify all price/balance reads; determine which can be moved atomically by flash-borrowed capital

### 2. Oracle Manipulation

- **Spot price oracles**: AMM spot prices used as oracles are trivially manipulable within one transaction
- **TWAP insufficiency**: short TWAP windows (under 30 minutes) can be manipulated over multiple blocks
- **Chainlink staleness**: no check on `updatedAt` timestamp allows use of stale prices
- **Oracle decimals mismatch**: different feeds return prices with different decimal precision
- **Multi-oracle inconsistency**: protocol uses multiple oracles without a consistent aggregation strategy
- **Fallback oracle bypass**: trigger primary oracle failure to force fallback to a weaker oracle
- Check: what oracle type is used? Is there a staleness check? Are decimals normalized?

### 3. Liquidity Pool Drainage

- **Imbalanced withdrawal**: withdraw in a way that leaves the pool in an exploitable ratio
- **First depositor attack**: deposit 1 wei, donate large amount, inflate share price to steal from next depositors
- **Rounding exploitation**: small deposits/withdrawals accumulate rounding errors in the attacker's favor
- **Fee-on-transfer tokens**: pool accounting assumes 1:1 transfer but fee tokens deliver less
- **Rebasing token desync**: pool balance changes without corresponding share updates
- Check: is there a minimum deposit? Does the vault handle non-standard tokens? Review share calculations

### 4. Governance Attacks

- **Proposal spam**: create proposals to drain treasury or change critical parameters
- **Vote buying**: off-chain vote buying or bribery via platforms like Votium/Hidden Hand
- **Timelock bypass**: execute proposals before timelock expires or cancel-and-resubmit to reset
- **Delegation confusion**: delegated votes not properly accounted when delegate re-delegates
- **Quorum manipulation**: reduce quorum threshold to make malicious proposals passable
- **Snapshot timing**: proposal snapshot at a block where attacker temporarily holds large voting power
- Check: what is the proposal threshold, quorum, voting period, and timelock delay?

### 5. Token Approval Abuse

- **Infinite approval drain**: contract with max approval can drain user tokens at any time
- **Approval race condition**: changing approval from A to B allows frontrunner to spend A + B
- **Approval on deprecated contracts**: old protocol versions retain active approvals
- **Permit signature theft**: off-chain permit signatures intercepted and used by attacker
- **Multicall approval bundling**: batch calls that approve and transfer in one transaction
- Check: does the protocol request minimum necessary approval? Are old contracts decommissioned?

### 6. Sandwich Attacks and MEV

- **Missing slippage protection**: swap functions without `amountOutMin` or with 0 minimum
- **Missing deadline**: transactions without expiry sit in mempool exploitable by MEV bots
- **Hardcoded slippage**: protocol sets fixed slippage instead of user-configurable protection
- **Just-in-time liquidity**: LPs add and remove liquidity around large swaps for risk-free profit
- **Priority gas auction**: MEV bots bid up gas prices to front-run profitable transactions
- Check: does every swap-like function accept and enforce slippage and deadline parameters?

### 7. Share and Accounting Bugs

- **Deposit/withdrawal asymmetry**: calculation path differs for deposit vs withdrawal, creating arbitrage
- **Fee miscalculation**: fees applied inconsistently between entry and exit
- **Reward distribution errors**: late depositors receive rewards they did not earn; early withdrawers keep unclaimed rewards
- **Total supply desync**: share total supply diverges from actual underlying asset balance
- **Rounding direction**: rounding favors user over protocol (should round against the user on deposit and withdrawal)
- Check: trace a deposit through to withdrawal with concrete numbers; verify accounting identity holds

### 8. Liquidation Mechanism Exploits

**Self-liquidation for profit**
- Borrower manipulates oracle price to trigger their own liquidation, receiving collateral back at a discount plus liquidation bonus
- Detection: does the liquidation function allow `msg.sender == borrower`? Does the bonus exceed the manipulation cost?

**Cascading liquidation spiral**
- Large liquidation swaps collateral through the same AMM pool used for price discovery
- The swap moves the pool price, triggering more liquidations, each worsening the price
- Detection: does the protocol use the same pool for liquidation swaps and price feed? Is there a circuit breaker on consecutive liquidations?

**Bad debt socialization**
- When a position is underwater (debt > collateral), the liquidation penalty cannot cover the shortfall
- Protocol socializes the loss across depositors by reducing the exchange rate or burning shares
- Detection: what happens when `collateral * liquidationBonus < debt`? Is there a reserve fund or insurance module?

**Partial liquidation rounding**
- Liquidator specifies `repayAmount`; share calculation rounds in liquidator's favor
- Repeated partial liquidations of 1 wei extract rounding profits
- Detection: does the close factor allow arbitrary partial amounts? Is rounding direction correct?

### 9. Yield Aggregator and Auto-Compounder Risks

**Harvest sandwich**
- Attacker front-runs the harvest/compound transaction, deposits before compounding, and withdraws after to capture a share of the yield
- Detection: is the harvest function callable by anyone? Is there a deposit lock period or harvest-only-for-existing-depositors guard?

**Strategy migration drain**
- When a vault migrates from one strategy to another, the withdrawal from the old strategy and deposit to the new strategy can be exploited
- Sandwich the migration: deposit before, let migration increase share value from strategy switch profit, withdraw after
- Detection: is migration permissioned? Is there a cooldown between migration and user withdrawal?

**Reward token price manipulation**
- Auto-compounder sells reward tokens via AMM swap; attacker manipulates the reward token price before harvest
- Attacker buys reward token cheap, triggers harvest (which sells at inflated price), or vice versa
- Detection: is the swap path hardcoded? Is there slippage protection on the harvest swap?

### 10. Cross-Protocol Composability Risks

**Reentrancy through composability**
- Protocol A deposits into Protocol B; Protocol B's callback reenters Protocol A
- Read-only reentrancy: Protocol A reads Protocol B's state mid-callback, getting stale data
- Detection: map all external calls to other DeFi protocols, trace callback paths back to the caller

**Dependency liveness**
- Protocol depends on an external protocol that can be paused, upgraded, or sunset
- If the external dependency pauses, the dependent protocol's withdrawal/liquidation may be blocked
- Detection: does the protocol have fallback paths for every external dependency? Can users withdraw if a dependency is paused?

**Flash loan callback exploitation**
- Protocol implements `onFlashLoan` or `executeOperation` callback for flash loan integration
- Attacker initiates a flash loan naming the protocol as receiver; the callback executes with the flash-borrowed funds in the protocol's context
- Detection: is the callback restricted to known flash loan providers? Does it verify `msg.sender` is the expected lender?

### 11. Interest Rate and Utilization Exploits

**Utilization rate manipulation**
- Flash-borrow to artificially push utilization to 100%, spiking interest rates for existing borrowers
- Repay the flash loan immediately, leaving the interest rate spike in effect until the next update
- Detection: does the protocol update interest rates using current utilization? Can utilization be manipulated atomically?

**Interest accrual timing**
- Interest accrued per-second vs per-block produces different results; switching between them or migrating creates accrual gaps
- Stale interest index: if `accrueInterest()` is not called before every state-changing operation, some users pay less interest
- Detection: is `accrueInterest` called in every borrow/repay/deposit/withdraw function? Can an attacker benefit by calling it at specific times?

### 12. Emergency and Pause Mechanism Abuse

**Pause-then-exploit**
- Protocol pauses deposits but not withdrawals (or vice versa); attacker exploits the asymmetric state
- Paused liquidations allow positions to become deeply underwater
- Detection: for each pausable function, what other functions remain active? Can the asymmetry be exploited?

**Emergency withdrawal privilege escalation**
- Emergency withdraw functions bypass normal accounting (fees, vesting, time locks)
- If emergency mode is triggerable by a semi-trusted role, they can enable fee-free withdrawal for allies
- Detection: what is the access control on emergency functions? Do they bypass fee collection?

## Key Commands

```bash
# Check oracle price
cast call {oracle} "latestRoundData()(uint80,int256,uint256,uint256,uint80)"

# Check pool reserves
cast call {pool} "getReserves()(uint112,uint112,uint32)"

# Check governance params
cast call {governor} "proposalThreshold()(uint256)"
cast call {governor} "quorum(uint256)(uint256)" {blockNumber}

# Check interest rate state
cast call {lending} "getReserveData(address)((uint256))" {asset}
cast call {lending} "utilizationRate()(uint256)"

# Check liquidation parameters
cast call {lending} "liquidationBonus(address)(uint256)" {collateral}
cast call {lending} "getHealthFactor(address)(uint256)" {user}
```

## Validation

- Demonstrate flash loan attack with a complete atomic sequence: borrow, manipulate, exploit, repay, profit
- Show oracle manipulation with concrete price deviation and resulting protocol impact
- Prove accounting bug with deposit/withdrawal trace showing value leakage
- Confirm governance attack with proposal lifecycle and economic feasibility analysis
- Show liquidation exploit with self-liquidation or cascading liquidation PoC
- Demonstrate harvest sandwich with deposit-before-harvest-withdraw-after sequence
- Prove interest rate manipulation with flash-borrow utilization spike
- Document transaction sequence, token amounts, pool states, and net attacker profit
