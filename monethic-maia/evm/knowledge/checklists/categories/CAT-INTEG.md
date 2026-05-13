## CL-INTEG-01: Aave Lending Integration Invariant

**Rule:** `EVM-INTEG-AAVE-01`
**Severity:** medium-high

### Description
The protocol integrates with Aave V2 or V3 for lending, borrowing, flash loans, or yield generation by calling Pool/LendingPool functions and holding aTokens, debt tokens, or interacting with the incentives controller. Aave integration requires correct handling of aToken mechanics (rebasing balance, interest accrual), incentives controller API (derivative token references, reward enumeration), reserve data validation, and version-specific API differences. Errors in any of these produce stuck rewards, incorrect accounting, or silent failures.

### Patterns


### Detect
For every Aave integration: (1) verify claimRewards passes aToken/debtToken addresses not underlying, (2) verify adapter exposes reward claim functions for all incentive types, (3) verify getReserveData return fields are validated against address(0) before use, (4) verify pool references are updatable and not hardcoded to V2, (5) verify aToken balances are read fresh at point-of-use not cached.

### Remediation


## CL-INTEG-02: Uniswap V3 Concentrated Liquidity Integration Invariant

**Rule:** `EVM-INTEG-UNIV3-01`
**Severity:** medium-critical

### Description
The integration mishandles Uniswap V3 specific mechanics: tick boundary overflow, sqrtPriceX96 arithmetic overflow, cached vs live liquidity mismatch, Solidity 0.8 breaking unchecked fee math, or using slot0() spot price as a price oracle (flash-loan manipulable).

### Patterns
1. **Tick Boundary Overflow** — verify tick arithmetic respects MIN_TICK/MAX_TICK and spacing alignment

```solidity
// VULNERABLE: tick range can exceed bounds
int24 lower = currentTick - deviation;
int24 upper = currentTick + deviation;
// lower could be < MIN_TICK (-887272) or upper > MAX_TICK

// FIXED: clamp to valid range
int24 lower = currentTick - deviation;
int24 upper = currentTick + deviation;
if (lower < TickMath.MIN_TICK) lower = TickMath.MIN_TICK;
if (upper > TickMath.MAX_TICK) upper = TickMath.MAX_TICK;
lower = (lower / tickSpacing) * tickSpacing;
upper = (upper / tickSpacing) * tickSpacing;
```

2. **SqrtPriceX96 Arithmetic Overflow** — verify sqrtPriceX96 calculations use appropriate bit-width arithmetic

```solidity
// VULNERABLE: squaring sqrtPriceX96 overflows uint256
uint256 price = uint256(sqrtPriceX96) * uint256(sqrtPriceX96); // overflows for large prices

// FIXED: use FullMath for safe multiplication
uint256 price = FullMath.mulDiv(uint256(sqrtPriceX96), uint256(sqrtPriceX96), 1 << 96);
```

3. **Stale Position Data and Cached Liquidity** — verify position data is fetched from pool at operation time

```solidity
// VULNERABLE: uses cached liquidity for burn
uint128 storedLiquidity = positions[tokenId].liquidity;
npm.decreaseLiquidity(DecreaseLiquidityParams(tokenId, storedLiquidity, 0, 0, block.timestamp));
// Reverts if external fees were collected, changing actual liquidity

// FIXED: query current liquidity from pool
(,, address token0, address token1, uint24 fee, int24 tickLower, int24 tickUpper, uint128 liquidity,,,,)
    = npm.positions(tokenId);
npm.decreaseLiquidity(DecreaseLiquidityParams(tokenId, liquidity, 0, 0, block.timestamp));
```

4. **Fee Growth Unchecked Arithmetic** — verify fee calculations use unchecked blocks for intentional overflow

```solidity
// VULNERABLE: Solidity 0.8+ reverts on overflow
uint256 feeGrowthInside = feeGrowthGlobal - feeGrowthOutsideLower - feeGrowthOutsideUpper;
// Reverts when feeGrowthGlobal < feeGrowthOutside (intentional underflow)

// FIXED: use unchecked to match Uniswap V3 semantics
uint256 feeGrowthInside;
unchecked {
    feeGrowthInside = feeGrowthGlobal - feeGrowthOutsideLower - feeGrowthOutsideUpper;
}
```

5. **slot0 Spot Price as Oracle** — verify protocol does not use `pool.slot0()` sqrtPriceX96 as a price oracle; use TWAP via `observe()` instead

```solidity
// VULNERABLE: slot0 returns instantaneous price, manipulable via flash loan
function getPrice(IUniswapV3Pool pool) public view returns (uint256) {
    (uint160 sqrtPriceX96,,,,,,) = pool.slot0();
    // Attacker flash-swaps to skew price → reads manipulated sqrtPriceX96
    // → inflates collateral value / deflates liquidation threshold
    return FullMath.mulDiv(uint256(sqrtPriceX96), uint256(sqrtPriceX96), 1 << 192);
}

// FIXED: use TWAP via observe() — resistant to single-block manipulation
function getPrice(IUniswapV3Pool pool) public view returns (uint256) {
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = 1800; // 30-minute TWAP
    secondsAgos[1] = 0;
    (int56[] memory tickCumulatives,) = pool.observe(secondsAgos);
    int24 avgTick = int24((tickCumulatives[1] - tickCumulatives[0]) / 1800);
    uint160 sqrtPriceX96 = TickMath.getSqrtRatioAtTick(avgTick);
    return FullMath.mulDiv(uint256(sqrtPriceX96), uint256(sqrtPriceX96), 1 << 192);
}
```

### Detect
For every Uniswap V3 integration: (1) verify tick arithmetic respects MIN_TICK/MAX_TICK bounds and tick spacing alignment; (2) verify sqrtPriceX96 calculations use FullMath or appropriate bit-width arithmetic without overflow; (3) verify position liquidity is fetched from the pool at burn time, not cached; (4) verify fee growth calculations use unchecked arithmetic to match Uniswap V3 intentional overflow semantics; (5) verify the protocol does not use pool.slot0() sqrtPriceX96 as a price oracle — must use TWAP via observe() instead.

### Remediation
Clamp ticks to MIN_TICK/MAX_TICK. Use FullMath for sqrtPriceX96 arithmetic. Query position liquidity from the pool at burn time. Use unchecked blocks for fee growth subtraction. Never use slot0() as a price oracle — use TWAP via observe() with a sufficient window (e.g., 30 minutes).

## CL-INTEG-03: Uniswap V4 Hook Integration Invariant

**Rule:** `EVM-INTEG-UNIV4-01`
**Severity:** medium-high

### Description
The hook contract has mismatched permission flags vs implementation, hardcoded tick ranges outside valid bounds, missing delta return values that break settlement accounting, zero-liquidity edge cases that revert, or sign-inverted deltas that corrupt swap execution.

### Patterns
1. **Permission Flag Mismatch** — verify hook address permission bits match implemented callbacks

```solidity
// VULNERABLE: hook implements afterSwap with return delta but address lacks the flag
// Hook address: 0x...0040 (only AFTER_SWAP_FLAG, missing AFTER_SWAP_RETURNS_DELTA_FLAG)
function afterSwap(...) external returns (bytes4, int128) {
    int128 hookDelta = int128(amount * feeRate / 1e18);
    return (BaseHook.afterSwap.selector, hookDelta); // delta silently ignored
}

// FIXED: deploy hook at address with both flags set
// Hook address: 0x...00C0 (AFTER_SWAP_FLAG | AFTER_SWAP_RETURNS_DELTA_FLAG)
```

2. **Tick Range vs Pool Spacing** — verify tick boundaries align with pool tick spacing

```solidity
// VULNERABLE: hardcoded ticks that violate spacing
int24 tickLower = -887272; // not divisible by tickSpacing
int24 tickUpper = 887272;

// FIXED: align to tick spacing
int24 tickLower = (TickMath.MIN_TICK / tickSpacing) * tickSpacing;
int24 tickUpper = (TickMath.MAX_TICK / tickSpacing) * tickSpacing;
```

3. **Missing Delta Return in afterSwap** — verify hooks that take fees return hookDeltaUnspecified

```solidity
// VULNERABLE: takes fee but returns zero delta
function afterSwap(..., int128 /*hookDelta*/) external returns (bytes4, int128) {
    uint256 fee = calculateFee(amount);
    poolManager.take(currency, address(this), fee);
    return (this.afterSwap.selector, 0); // pool accounting broken
}

// FIXED: return the delta
function afterSwap(...) external returns (bytes4, int128) {
    uint256 fee = calculateFee(amount);
    poolManager.take(currency, address(this), fee);
    return (this.afterSwap.selector, int128(uint128(fee)));
}
```

4. **Zero Liquidity modifyLiquidity Revert** — verify modifyLiquidity handles zero-liquidity positions

```solidity
// VULNERABLE: rebalance calls modifyLiquidity with delta=0 on empty tick
poolManager.modifyLiquidity(poolKey, IPoolManager.ModifyLiquidityParams({
    tickLower: lower, tickUpper: upper, liquidityDelta: 0
})); // reverts on uninitialized tick

// FIXED: skip modification if no liquidity change needed
if (liquidityDelta != 0) {
    poolManager.modifyLiquidity(poolKey, params);
}
```

5. **Delta Sign Inversion** — verify hook deltas do not flip swap direction

```solidity
// VULNERABLE: delta larger than swap amount flips sign
function afterSwap(..., BalanceDelta delta) external returns (bytes4, int128) {
    int128 hookDelta = -delta.amount0(); // if this exceeds original amount, sign flips
    return (this.afterSwap.selector, hookDelta);
}

// FIXED: cap delta to prevent sign inversion
function afterSwap(..., BalanceDelta delta) external returns (bytes4, int128) {
    int128 maxDelta = delta.amount0() > 0 ? delta.amount0() : -delta.amount0();
    int128 hookDelta = int128(uint128(uint256(int256(maxDelta)) * feeRate / 1e18));
    return (this.afterSwap.selector, hookDelta);
}
```

### Detect
For every Uniswap V4 hook implementation: (1) verify hook permission flags in the contract address match the actually implemented callback functions, including return-delta flags for hooks that modify swap amounts; (2) verify tick boundaries in hook logic respect the pool tick spacing and do not hardcode values outside mathematical limits; (3) verify hooks that apply fees or taxes in afterSwap return the correct hookDeltaUnspecified to maintain delta neutrality; (4) verify modifyLiquidity calls handle zero-liquidity positions without reverting on uninitialized ticks; (5) verify hook return deltas do not cause sign inversion that would flip the swap direction.

### Remediation
Align hook address permission bits with all implemented callbacks. Use pool-specific tick spacing for range calculations. Return hookDeltaUnspecified from afterSwap when taking fees. Guard modifyLiquidity against zero-delta on empty positions. Validate delta magnitudes against swap amounts to prevent sign flips.
