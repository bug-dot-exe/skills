---
name: oracle-price-manipulation
category: web3
description: Deep oracle attack patterns covering Chainlink staleness/decimals/sequencer checks, TWAP window manipulation, spot price attacks via flash loans, derivative asset mispricing, multi-oracle disagreement, L2 sequencer downtime exploitation, and oracle-dependent liquidation manipulation
depends_on: []
---

# Oracle Price Manipulation

Deep attack surface analysis for protocols that consume external price data. Covers Chainlink, Uniswap TWAP, Pyth, Redstone, Band, API3, and custom on-chain oracles. Focuses on manipulation vectors, failure modes, and downstream impact on lending, liquidation, collateral valuation, and reward distribution.

## When to Use

- Protocol reads external price data (Chainlink, Uniswap TWAP, Band, Pyth, API3, Redstone)
- Lending/borrowing protocols using collateral valuation
- DEX protocols with price-dependent logic (limit orders, stop-loss)
- Any calculation multiplied by an oracle price
- Vault or yield aggregator that prices non-standard assets (LP tokens, staked tokens, wrapped assets)
- Liquidation logic that depends on price feeds
- Cross-chain protocol consuming L2 price data

## Methodology

### 1. Oracle Type Classification

Classify every oracle integration by trust model before testing:

| Type | Manipulation Difficulty | Common Issues |
|------|------------------------|---------------|
| Chainlink | Hard (decentralized) | Staleness, decimals, sequencer, circuit breakers |
| Uniswap V3 TWAP | Medium (multi-block) | Short window, low liquidity pools |
| Uniswap V2 spot | Trivial (single tx) | Flash loan manipulable via `getReserves()` |
| Pyth Network | Hard (pull oracle) | Stale price if not updated by caller |
| Redstone | Medium | Payload injection, timestamp manipulation |
| Band Protocol | Hard (IBC relayed) | Staleness, request-response latency |
| API3 / Airnode | Hard (first-party) | Stale beacon data, dAPI reconfiguration |
| Custom on-chain | Varies | Often single-source, no aggregation, no staleness check |

For each oracle found: identify the exact data source, check who can update it, and determine the cost to move the price by 10%.

### 2. Chainlink-Specific Attacks

**Staleness** -- oracle returns price from hours/days ago without detection.
- Detection: search for `latestRoundData()` without checking `updatedAt` or `answeredInRound`
- Required checks:
  ```solidity
  (uint80 roundId, int256 price, , uint256 updatedAt, uint80 answeredInRound) = feed.latestRoundData();
  require(price > 0, "Negative/zero price");
  require(updatedAt > 0, "Round not complete");
  require(block.timestamp - updatedAt < STALENESS_THRESHOLD, "Stale price");
  require(answeredInRound >= roundId, "Stale round");
  ```
- Impact: stale price allows borrowing against inflated collateral or avoids liquidation

**Decimal mismatch** -- USD pairs return 8 decimals, ETH pairs return 18.
- Detection: hardcoded decimal assumption (e.g., dividing by `1e8`) vs calling `feed.decimals()`
- Attack: if code assumes 8 decimals for an 18-decimal feed, price is inflated by 1e10
- Required: dynamic `10 ** feed.decimals()` normalization per feed

**Negative/zero price** -- Chainlink can return `price <= 0` in edge cases.
- Required: `require(price > 0)` immediately after `latestRoundData()`
- Impact: zero price makes collateral worthless or allows free minting

**L2 Sequencer downtime** -- on Optimism/Arbitrum, if the sequencer is down prices appear fresh but are stale.
- Detection: search for `sequencerUptimeFeed` -- if absent on an L2 deployment, it is a finding
- Required: check sequencer uptime feed, enforce grace period after sequencer restarts
  ```solidity
  (, int256 answer, uint256 startedAt, , ) = sequencerFeed.latestRoundData();
  require(answer == 0, "Sequencer down");
  require(block.timestamp - startedAt > GRACE_PERIOD, "Grace period not over");
  ```
- Impact: during downtime, positions can be liquidated at stale prices or bad debt accumulates

**Circuit breakers (minAnswer/maxAnswer)** -- Chainlink aggregators have price bounds.
- If the real price exceeds bounds, the feed returns the boundary value, not the real price
- LUNA crash example: feed returned `minAnswer` while real price was orders of magnitude lower
- Detection: check if protocol handles the case where `price == minAnswer` or `price == maxAnswer`
- Impact: lending protocol accepts collateral at floor price far above real value

**Multi-feed composition** -- combining feeds (e.g., `TOKEN/ETH * ETH/USD = TOKEN/USD`).
- Detection: look for two `latestRoundData()` calls with results multiplied or divided
- Each feed has independent staleness, decimals, and heartbeat -- all must be checked individually
- Decimal math: `(priceA * priceB) / (10 ** decimalsA)` -- verify scaling is correct

### 3. TWAP Manipulation

**Short window** -- TWAP under 30 minutes can be manipulated with sustained multi-block pressure.
- Manipulation cost: `cost ~ liquidity_depth * price_impact * window_blocks`
- A 5-minute TWAP on a $500K liquidity pool costs roughly $50K-$100K to move 20%

**Low liquidity** -- TWAP on a thin pool is disproportionately cheaper to manipulate.
- Detection: check the pool address used for TWAP, query its TVL, calculate manipulation cost
- If TVL < 10x the maximum position size in the dependent protocol, TWAP is economically manipulable

**Uniswap V3 specifics** -- uses `observe()` with `secondsAgo` array.
- Detection: find the `secondsAgo` parameter, check minimum enforced window
- If window is configurable: check minimum bound and who can change it
- Tick accumulator math: verify the protocol handles the case where observation is unavailable (pool too young)

**Manipulation profitability**: if `profit_from_exploit - cost_to_move_TWAP > 0`, the attack is viable.
- Historical: Euler Finance ($197M), Inverse Finance ($15.6M) both exploited via oracle manipulation

### 4. Spot Price Attacks (Flash Loan)

**AMM spot price as oracle** -- `reserve0 / reserve1` is trivially manipulable in a single transaction.
- Attack sequence: flash borrow -> swap to move price -> exploit dependent protocol -> swap back -> repay
- Detection: search for `getReserves()`, `slot0()`, `balanceOf(pool)` used as price input
- Any `balanceOf(address)` used for valuation where the address is a pool or vault is manipulable

**Common vulnerable patterns**:
- `price = reserveA / reserveB` (Uniswap V2 spot)
- `price = sqrtPriceX96` from `slot0()` (Uniswap V3 current tick -- NOT TWAP)
- `price = token.balanceOf(pool) / pool.totalSupply()` (LP token pricing)
- `price = vault.totalAssets() / vault.totalSupply()` (vault share pricing)

**Impact targets**: lending liquidation thresholds, collateral valuation, reward calculations, limit order triggers.

### 5. Derivative Asset Mispricing

**LP token valuation** -- pricing LP tokens by `totalAssets / totalSupply` is flash-loan manipulable.
- Safe pattern: Alpha Finance fair LP pricing formula (`2 * sqrt(r0 * r1) * sqrt(p0 * p1) / totalSupply`)
- Unsafe: any formula that reads pool reserves directly without manipulation resistance

**Wrapped/staked asset exchange rate** -- `stETH/ETH`, `rETH/ETH` rates can deviate from 1:1.
- If protocol assumes 1:1 peg: attacker exploits depeg events for profit
- If protocol uses on-chain exchange rate: check if the rate is flash-loan manipulable
- Safe: use Chainlink feed for the derivative (e.g., stETH/USD feed) or enforce a depeg circuit breaker

**Synthetic/rebasing assets** -- pricing via backing ratio without considering market price.
- Detection: trace how the protocol values non-standard assets end-to-end
- Check: can the backing ratio be moved atomically? Is there a cap on deviation from market price?

### 6. Oracle Failure Modes

**Revert on stale** -- if oracle reverts instead of returning stale data, all dependent protocol functions DoS.
- Detection: does the protocol use `try/catch` around oracle calls? What is the fallback?
- Impact: critical functions (liquidation, withdrawal) become permanently blocked

**Oracle sunset** -- deprecated Chainlink feeds stop updating without reverting.
- Detection: is the feed address hardcoded or updatable? Who can update it?
- Impact: protocol operates on frozen price indefinitely

**Fallback oracle weakness** -- primary fails, fallback uses a weaker oracle.
- Detection: can an attacker trigger the fallback? Is the fallback manipulable (e.g., spot price)?
- Attack: DoS the primary oracle, force protocol to the weaker fallback, manipulate the fallback

**Multi-oracle disagreement** -- protocol uses multiple feeds without a clear aggregation/tiebreak strategy.
- Detection: what happens when feed A says $100 and feed B says $80? Which wins?
- If the protocol takes the higher/lower: attacker manipulates the chosen feed

### 7. Oracle-Dependent Liquidation Manipulation

**Delayed liquidation** -- stale oracle delays liquidation, bad debt accumulates.
- Trace: price drops -> oracle still shows old price -> position goes underwater -> bad debt for protocol
- Impact: protocol socializes losses across all depositors

**Forced liquidation** -- manipulate oracle to trigger premature liquidation of healthy positions.
- Attack: move oracle price down (flash loan or TWAP manipulation) -> liquidate healthy position -> collect liquidation bonus
- Profitability: `liquidation_bonus - manipulation_cost > 0`

**Self-liquidation for profit** -- manipulate price to liquidate own undercollateralized position.
- Attack: borrow at fair price -> manipulate oracle down -> self-liquidate -> receive collateral at discount + bonus
- Detection: does the liquidation function allow the borrower to liquidate themselves?

**Cascading liquidations** -- one large liquidation moves the market, triggering more liquidations.
- Detection: check if liquidation swaps route through the same pool used for price discovery

## Key Detection Commands

```bash
# Find all oracle usage patterns
grep -rn "latestRoundData\|getPrice\|getReserves\|slot0\|observe\|consult\|getLatestPrice" contracts/

# Find staleness checks (or lack thereof)
grep -rn "updatedAt\|answeredInRound\|staleness\|heartbeat\|STALENESS" contracts/

# Find sequencer checks (L2 -- absence is a finding)
grep -rn "sequencer\|uptimeFeed\|isSequencerUp\|GRACE_PERIOD" contracts/

# Find decimal handling
grep -rn "decimals()\|1e8\|1e18\|10\*\*\|PRICE_PRECISION" contracts/

# Find price composition (multi-feed)
grep -B2 -A5 "latestRoundData" contracts/ | grep -c "latestRoundData"

# Find spot price reads (flash loan targets)
grep -rn "getReserves\|slot0\|balanceOf.*pool\|balanceOf.*vault\|totalAssets.*totalSupply" contracts/

# Find LP/derivative token pricing
grep -rn "totalAssets\|exchangeRate\|getRateToEth\|getPooledEthByShares" contracts/
```

### 8. Pull Oracle Exploitation (Pyth, Redstone)

**Stale pull oracle data**
- Pull oracles (Pyth, Redstone) require the caller to push price data on-chain before use
- If the protocol does not enforce freshness on the pushed data, an attacker can submit stale prices
- Detection: does the protocol check `price.publishTime` against a maximum age? Who triggers the price update?

**Pyth-specific vectors**
- Price confidence interval: Pyth returns price + confidence; protocol may use price without considering confidence
- If confidence is wide (high uncertainty), the price may be far from the true market price
- Detection: does the protocol check `price.conf` against a threshold? Is `price.expo` handled correctly?

**Redstone payload manipulation**
- Redstone embeds price data in calldata; the contract extracts it during execution
- If the extraction logic does not validate the data source or timestamp, crafted payloads can inject arbitrary prices
- Detection: does the contract verify Redstone signatures? Is the timestamp checked against a staleness window?

**Update fee manipulation**
- Pyth charges a fee per price update; if the protocol does not forward sufficient fee, the update reverts
- Attacker can grief price-dependent operations by ensuring the price update step always reverts
- Detection: does the protocol handle `InsufficientFee` errors gracefully? Can users bypass the update step?

### 9. Oracle Sandwich and Timing Attacks

**Oracle update front-running**
- Attacker sees an oracle price update in the mempool and front-runs it
- Before update: borrow against overvalued collateral or exit an underwater position
- After update: the protocol would have prevented the action at the new price
- Detection: is there a delay between oracle update and its use? Can users act between update submission and inclusion?

**Block-by-block oracle exploitation**
- On L2s, block timestamps can differ from L1 by the sequencer's discretion
- Attacker coordinates with the sequencer (or IS the sequencer in centralized L2) to time oracle reads
- Detection: does the protocol rely on `block.timestamp` for staleness checks? Is the L2 sequencer trusted?

**Multi-oracle arbitrage**
- Protocol uses Oracle A for deposits but Oracle B for withdrawals (or different functions use different oracles)
- If Oracle A and Oracle B disagree, attacker deposits at favorable price from A and withdraws at favorable price from B
- Detection: does every state-changing function use the same oracle? Are there code paths that read different feeds?

### 10. Oracle-Dependent Access Control

**Price-gated function bypass**
- Functions restricted by price conditions (e.g., "only callable when price < threshold") can be bypassed by manipulating the oracle
- Detection: find every `require` or `if` that checks an oracle price; determine if that price can be manipulated to bypass the check

**Liquidation threshold manipulation**
- Health factor calculations using manipulable oracle prices allow triggering or preventing liquidations at will
- Self-liquidation: manipulate price to make own position unhealthy, self-liquidate to receive bonus
- Detection: is the oracle used for health factor calculation manipulation-resistant? Can borrowers liquidate themselves?

**Reward rate oracle dependency**
- Reward distribution that scales with oracle price: high price = high rewards
- Attacker inflates oracle price, claims rewards, deflates price
- Detection: do reward calculations use oracle prices? Can the oracle be moved profitably within a single transaction?

## Validation

- **Chainlink staleness**: fork test at a block where the feed was stale; show the protocol accepts the stale price and the resulting incorrect action (bad liquidation, inflated borrow)
- **TWAP manipulation**: calculate manipulation cost vs extractable value; show profitability with concrete numbers
- **Spot price / flash loan**: full atomic PoC sequence -- borrow, swap, exploit, swap back, repay -- showing net profit
- **Derivative mispricing**: demonstrate exchange rate manipulation and downstream value extraction
- **Circuit breaker**: fork test at the LUNA crash block; show `minAnswer` returned and protocol impact
- **Quantify**: TVL at risk, maximum extractable value, manipulation cost, and profit ratio
- **L2 sequencer**: simulate sequencer downtime; show stale prices are accepted and positions are incorrectly liquidated
- **Pull oracle staleness**: submit a Pyth/Redstone price update with old timestamp and show it is accepted
- **Oracle sandwich**: demonstrate front-running an oracle update to extract value before the new price takes effect
- **Multi-oracle arbitrage**: deposit at Oracle A's price and withdraw at Oracle B's favorable price
