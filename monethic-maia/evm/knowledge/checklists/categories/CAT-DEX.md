## CL-DEX-01: AMM Formula & Invariant Correctness

**Rule:** `EVM-DEX-AMM-01`
**Severity:** high

### Description
The AMM formula implementation contains rounding errors, edge case failures, view/execution inconsistencies, or missing first-depositor protections that allow value extraction from the pool or denial of service. Incorrect rounding, formula edge cases, or missing initialization validation in AMM math allows value extraction or DoS.

### Patterns
### Pattern 1: AMM invariant violation after swap

The contract executes a swap and updates reserves, but the post-swap state violates the AMM's core invariant (xy=k or weighted equivalent). This happens when rounding directions are inconsistent between minting/burning LP tokens and swapping, when fees are deducted after the invariant check instead of before, or when the invariant comparison uses strict equality instead of a one-sided bound. The drift accumulates over many swaps and can eventually make the pool insolvent or cause permanent DoS on liquidity removal.

**Vulnerable:**
```solidity
// Inconsistent rounding causes invariant drift
function swap(uint256 amountIn) external {
    uint256 amountOut = formula.calcOut(reserves, amountIn); // rounds to nearest
    reserves[0] += amountIn;
    reserves[1] -= amountOut;
    // strict equality fails after accumulated rounding
    require(reserves[0] * reserves[1] == k, "Invariant broken");
}
```

**Fixed:**
```solidity
// Explicit rounding direction and one-sided invariant check
function swap(uint256 amountIn) external {
    uint256 amountOut = formula.calcOut(reserves, amountIn, Rounding.Down); // round output down
    reserves[0] += amountIn;
    reserves[1] -= amountOut;
    // one-sided check: new k must be >= old k
    require(reserves[0] * reserves[1] >= k, "Invariant broken");
    k = reserves[0] * reserves[1];
}
```

### Pattern 2: Asymmetric rounding in swap directions

The AMM's pricing functions use the same rounding direction (typically floor) for both buy and sell operations. Integer division rounds down by default; if buy prices are rounded down, the protocol receives less than ideal, and if sell payouts are rounded up, the protocol overpays. Over many trades the rounding leak compounds, draining value from liquidity providers. This also applies to fee calculations that round in the trader's favor.

**Vulnerable:**
```solidity
// Both directions use floor rounding
function getBuyPrice(uint256 amount) public view returns (uint256) {
    return amount * price / SCALE; // rounds down -- protocol receives less
}
function getSellPrice(uint256 amount) public view returns (uint256) {
    return amount * price / SCALE; // rounds down -- fine for payouts
}
```

**Fixed:**
```solidity
// Asymmetric rounding favors the protocol
function getBuyPrice(uint256 amount) public view returns (uint256) {
    return (amount * price + SCALE - 1) / SCALE; // round UP -- user pays more
}
function getSellPrice(uint256 amount) public view returns (uint256) {
    return amount * price / SCALE; // round DOWN -- user receives less
}
```

### Pattern 3: Formula degeneration at edge cases

AMM formulas that use quadratic equations fail when the leading coefficient becomes zero, causing division by zero. Weighted pool math using power functions overflows at extreme weight ratios. Concentrated liquidity implementations with tick iterators can skip boundary ticks due to off-by-one errors in less-than vs less-than-or-equal comparisons, causing swaps to miss liquidity or revert at tick boundaries.

**Vulnerable:**
```solidity
// Division by zero when quadratic coefficient is zero
function solveForPrice(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
    uint256 discriminant = b * b - 4 * a * c;
    return (sqrt(discriminant) - b) / (2 * a); // reverts if a == 0
}
```

**Fixed:**
```solidity
// Handle linear degeneration
function solveForPrice(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
    if (a == 0) {
        // Degenerate case: linear equation bx + c = 0
        require(b > 0, "Unsolvable");
        return c / b;
    }
    uint256 discriminant = b * b - 4 * a * c;
    return (sqrt(discriminant) - b) / (2 * a);
}
```

### Pattern 4: Inconsistent view vs execution results

Functions like `getAmountOut`, `quoteExactInput`, or `previewSwap` compute expected output using a different code path, rounding mode, or state snapshot than the actual swap execution. Users and integrators rely on these quotes for slippage calculations, but the discrepancy means the actual output can be higher or lower than quoted, breaking composability with routers and aggregators.

**Vulnerable:**
```solidity
// Quote uses stale reserves, swap uses current
function getAmountOut(uint256 amountIn) external view returns (uint256) {
    // Uses stored reserves without pending fee accrual
    return (amountIn * reserve1) / (reserve0 + amountIn);
}

function swap(uint256 amountIn) external {
    _accrueProtocolFees(); // modifies reserves before calculation
    uint256 amountOut = (amountIn * reserve1) / (reserve0 + amountIn);
    // amountOut differs from getAmountOut due to fee accrual
    _transfer(token1, msg.sender, amountOut);
}
```

**Fixed:**
```solidity
// Shared internal calculation
function _calcAmountOut(uint256 amountIn, uint256 r0, uint256 r1) internal pure returns (uint256) {
    return (amountIn * r1) / (r0 + amountIn);
}

function getAmountOut(uint256 amountIn) external view returns (uint256) {
    (uint256 r0, uint256 r1) = _getReservesAfterFeeAccrual();
    return _calcAmountOut(amountIn, r0, r1);
}
```

### Pattern 5: Initial price/ratio not validated

When a pool has zero total supply, the first liquidity provider can deposit tokens at any ratio, setting an arbitrary initial price. Without burning a minimum amount of initial LP tokens (dead shares), an attacker can initialize a pool with an extreme ratio, then arbitrage subsequent depositors. This also covers pools that derive initial price from manipulable on-chain state like order book bids/asks.

**Vulnerable:**
```solidity
// First LP sets arbitrary price, no minimum liquidity burned
function addLiquidity(uint256 amountA, uint256 amountB) external returns (uint256 shares) {
    if (totalSupply == 0) {
        shares = sqrt(amountA * amountB); // attacker controls ratio
        _mint(msg.sender, shares);
    } else {
        shares = min(amountA * totalSupply / reserveA, amountB * totalSupply / reserveB);
        _mint(msg.sender, shares);
    }
}
```

**Fixed:**
```solidity
// Burn minimum liquidity on first deposit
function addLiquidity(uint256 amountA, uint256 amountB) external returns (uint256 shares) {
    if (totalSupply == 0) {
        shares = sqrt(amountA * amountB);
        uint256 MINIMUM_LIQUIDITY = 1000;
        _mint(address(0), MINIMUM_LIQUIDITY); // burn dead shares
        _mint(msg.sender, shares - MINIMUM_LIQUIDITY);
        require(shares > MINIMUM_LIQUIDITY, "Insufficient initial liquidity");
    } else {
        shares = min(amountA * totalSupply / reserveA, amountB * totalSupply / reserveB);
        _mint(msg.sender, shares);
    }
}
```

### Detect
For every AMM or bonding curve implementation: (1) verify the core invariant (xy=k, weighted product, stableswap) is preserved after each swap with correct rounding, (2) verify buy vs sell pricing uses asymmetric rounding favoring the protocol, (3) check formula edge cases (zero coefficients, extreme ratios, tick boundaries), (4) compare view/quote function math against actual execution path, (5) verify first-depositor protection (minimum burned liquidity, validated initial ratio).

### Remediation
Enforce consistent rounding: round up for amounts the protocol receives (cost to user, LP burned) and round down for amounts the protocol sends (payout to user, LP minted). Check invariant with one-sided inequality (new_k >= old_k) rather than strict equality. Handle formula edge cases (zero coefficients, extreme weight ratios, tick boundaries). Ensure view functions use identical math to execution functions. Burn minimum initial liquidity on first deposit and validate initial token ratios.

## CL-DEX-02: DEX Fee Accounting Invariant

**Rule:** `EVM-DEX-FEE-01`
**Severity:** medium-high

### Description
The fee accounting logic contains ordering errors relative to the invariant, distributes to empty pools, allows overflow from additive components, uses mismatched decimal precision, or conditionally skips collection on certain paths. Incorrect fee ordering, empty pool allocation, additive overflow, decimal mismatch, or conditional bypass in fee accounting causes revenue loss or invariant violation.

### Patterns
### Pattern 1: Fees not deducted before invariant check

The swap function computes the AMM output using the full input amount, then subtracts a fee from the output after the invariant has already been evaluated. This means the actual reserves post-swap do not satisfy the invariant because the fee was removed after the curve calculation. Alternatively, fees are added to reserves before the swap calculation, inflating the effective liquidity and producing incorrect output amounts.

**Vulnerable:**
```solidity
// Fee deducted after invariant evaluated on gross amounts
function swap(uint256 amountIn) external {
    uint256 amountOut = (amountIn * reserveOut) / (reserveIn + amountIn);
    uint256 fee = amountOut * feeRate / 10000;
    uint256 netOut = amountOut - fee;
    reserveIn += amountIn;
    reserveOut -= netOut; // reserves no longer satisfy xy=k with the gross amountOut
    _transfer(tokenOut, msg.sender, netOut);
}
```

**Fixed:**
```solidity
// Fee deducted from input before curve calculation
function swap(uint256 amountIn) external {
    uint256 fee = amountIn * feeRate / 10000;
    uint256 netIn = amountIn - fee;
    uint256 amountOut = (netIn * reserveOut) / (reserveIn + netIn);
    reserveIn += netIn;
    feeAccumulator += fee;
    reserveOut -= amountOut;
    _transfer(tokenOut, msg.sender, amountOut);
}
```

### Pattern 2: Fee allocation to empty/zero liquidity

The protocol distributes trading fees or protocol revenue to a pool's fee accumulator without checking whether the pool has any active liquidity providers (totalSupply > 0). When no LPs exist, the fees are written to storage but have no claimant. They are either permanently locked, or the next LP who deposits captures all accumulated fees for free, creating a front-running incentive around pool creation.

**Vulnerable:**
```solidity
// Fees allocated regardless of LP existence
function distributeFees(uint256 tradingFees) external {
    uint256 poolShare = (tradingFees * poolRatio) / 1e18;
    poolFeeBalance += poolShare; // locked forever if totalSupply == 0
}
```

**Fixed:**
```solidity
// Check for active LPs before distribution
function distributeFees(uint256 tradingFees) external {
    uint256 poolShare = (tradingFees * poolRatio) / 1e18;
    if (totalSupply > 0) {
        poolFeeBalance += poolShare;
    } else {
        treasuryBalance += poolShare; // redirect to treasury
    }
}
```

### Pattern 3: Fee arithmetic overflow/underflow

Multiple independent fee components (base fee, surge fee, protocol fee, hook fee) are calculated as separate percentages of the trade amount and then summed. When each component can independently reach high values, their sum can exceed 100% of the principal, causing an arithmetic underflow when subtracted from the output amount. With unchecked math, this wraps to a huge number; with checked math, it causes a revert.

**Vulnerable:**
```solidity
// Independent fee components can sum beyond 100%
function calculateNetOutput(uint256 amount) internal view returns (uint256) {
    uint256 baseFee = amount * baseFeeRate / 10000;     // e.g., 8000 = 80%
    uint256 surgeFee = amount * surgeFeeRate / 10000;    // e.g., 5000 = 50%
    uint256 hookFee = amount * hookFeeRate / 10000;      // e.g., 200 = 2%
    return amount - baseFee - surgeFee - hookFee;        // underflows: 132% total fees
}
```

**Fixed:**
```solidity
// Cap total fees
function calculateNetOutput(uint256 amount) internal view returns (uint256) {
    uint256 totalFeeRate = baseFeeRate + surgeFeeRate + hookFeeRate;
    uint256 maxFeeRate = 5000; // cap at 50%
    if (totalFeeRate > maxFeeRate) totalFeeRate = maxFeeRate;
    uint256 totalFee = amount * totalFeeRate / 10000;
    return amount - totalFee;
}
```

### Pattern 4: Decimal scaling mismatch in fee calculation

The fee percentage is applied using a fixed-point denominator (e.g., 1e18 or 10000) that does not match the decimal precision of the tokens involved. When pool tokens have different decimals (e.g., USDC with 6 and WETH with 18), applying a fee calculated in one token's precision to the other produces fees that are orders of magnitude too large or too small. This also covers fee accumulators that use a global precision constant incompatible with the specific token pair.

**Vulnerable:**
```solidity
// Fee accumulator uses 18-decimal math on 6-decimal token
function accrueSwapFee(uint256 amountOut, address token) internal {
    // feePerLiquidityUnit is in 1e18 precision
    uint256 feeAmount = amountOut * swapFeeRate / 10000;
    // USDC (6 decimals) fee stored in 18-decimal accumulator without scaling
    feePerLiquidityUnit += feeAmount * 1e18 / totalLiquidity; // wrong if token is 6 decimals
}
```

**Fixed:**
```solidity
// Normalize to token's own decimals before accumulation
function accrueSwapFee(uint256 amountOut, address token) internal {
    uint256 feeAmount = amountOut * swapFeeRate / 10000;
    uint256 decimals = IERC20Metadata(token).decimals();
    uint256 scaledFee = feeAmount * 1e18 / (10 ** decimals); // normalize
    feePerLiquidityUnit += scaledFee * 1e18 / totalLiquidity;
}
```

### Pattern 5: Conditional fee bypass

Fee calculation logic is nested inside a conditional block that only executes for specific token directions or output amounts. When a swap moves tokens in the other direction, or when a multi-hop path routes through an intermediate token, the fee logic is not triggered. This includes flash loan paths that bypass swap fees, and operations where amount0Out is zero causing the fee block for token0 to be skipped entirely even though token1 is being swapped.

**Vulnerable:**
```solidity
// Fee only applied when token0 is output
function swap(uint256 amount0Out, uint256 amount1Out, address to) external {
    if (amount0Out > 0) {
        uint256 fee0 = calculateFee(amount0Out);
        _safeTransfer(token0, to, amount0Out - fee0);
        accumulatedFees0 += fee0;
    }
    if (amount1Out > 0) {
        _safeTransfer(token1, to, amount1Out); // no fee applied to token1
    }
    // ...
}
```

**Fixed:**
```solidity
// Apply fees to both token directions independently
function swap(uint256 amount0Out, uint256 amount1Out, address to) external {
    if (amount0Out > 0) {
        uint256 fee0 = calculateFee(amount0Out);
        _safeTransfer(token0, to, amount0Out - fee0);
        accumulatedFees0 += fee0;
    }
    if (amount1Out > 0) {
        uint256 fee1 = calculateFee(amount1Out);
        _safeTransfer(token1, to, amount1Out - fee1);
        accumulatedFees1 += fee1;
    }
    // ...
}
```

### Detect
For every DEX fee mechanism: (1) verify fees are deducted at the correct point relative to the invariant calculation, (2) check fee distribution targets have active liquidity (totalSupply > 0), (3) verify the sum of all fee components cannot exceed a safe maximum, (4) check fee precision matches the token's decimal scale, (5) verify all swap paths and token directions trigger fee collection.

### Remediation
Deduct fees from input before computing the AMM output (fee-on-input) or from output after computing but before updating reserves (fee-on-output with adjusted invariant). Check totalSupply > 0 before allocating fees to a pool; redirect to treasury if empty. Cap the sum of all fee components to a maximum (e.g., 50%) and validate after summation. Ensure fee arithmetic uses the correct decimal precision for the specific token being charged. Apply fees unconditionally to all swap paths regardless of token direction or operation type.

## CL-DEX-03: Pool Management & Integrity Invariant

**Rule:** `EVM-DEX-POOL-01`
**Severity:** medium-high

### Description
The pool management logic allows duplicate or same-token pools, passes unvalidated parameters, exposes manipulable state during flash operations, or uses shared global state that creates cross-pool interference. Missing uniqueness checks, unvalidated parameters, exposed flash-state, or shared global accounting in pool management enables manipulation.

### Patterns
### Pattern 1: Duplicate pool creation for identical pairs

The factory or registry contract allows deploying multiple pools for the same token pair without validating uniqueness. This fragments liquidity across duplicate pools, confuses routers and aggregators that expect a canonical pool per pair, and enables attackers to create malicious clone pools with manipulated initial state. The uniqueness check must also handle token ordering (A/B vs B/A) and multi-asset pool permutations.

**Vulnerable:**
```solidity
// No uniqueness check for token pairs
function createPool(address tokenA, address tokenB) external returns (address pool) {
    pool = deploy(tokenA, tokenB);
    allPools.push(pool);
    return pool;
}
```

**Fixed:**
```solidity
// Canonical ordering and uniqueness mapping
function createPool(address tokenA, address tokenB) external returns (address pool) {
    (address token0, address token1) = tokenA < tokenB
        ? (tokenA, tokenB)
        : (tokenB, tokenA);
    require(getPool[token0][token1] == address(0), "Pool exists");
    pool = deploy(token0, token1);
    getPool[token0][token1] = pool;
    getPool[token1][token0] = pool; // reverse lookup
    allPools.push(pool);
}
```

### Pattern 2: Same-token pool creation

The factory does not validate that all token addresses in a pool are distinct. A pool created with identical tokens (e.g., USDC/USDC) breaks the swap invariant since both reserves reference the same balance. This can lead to infinite minting, accounting corruption, or exploitable arbitrage depending on the AMM formula. Multi-asset pools need pairwise uniqueness checks across all token positions.

**Vulnerable:**
```solidity
// No check for identical tokens
function initialize(address[] calldata tokens) external {
    for (uint256 i = 0; i < tokens.length; i++) {
        poolTokens.push(tokens[i]);
    }
}
```

**Fixed:**
```solidity
// Enforce pairwise uniqueness
function initialize(address[] calldata tokens) external {
    for (uint256 i = 0; i < tokens.length; i++) {
        for (uint256 j = i + 1; j < tokens.length; j++) {
            require(tokens[i] != tokens[j], "Duplicate token");
        }
        require(tokens[i] != address(0), "Zero address");
        poolTokens.push(tokens[i]);
    }
}
```

### Pattern 3: Unrestricted pool creation

The factory allows permissionless pool deployment without validating token legitimacy, minimum initial liquidity, or any form of governance approval. Attackers can create pools with fee-on-transfer tokens, rebasing tokens, or tokens with callbacks that break the AMM assumptions. This also covers missing validation in factory parameters passed through to the pool implementation (e.g., unchecked fee tiers, invalid curve parameters).

**Vulnerable:**
```solidity
// No parameter validation passed to pool
function createPool(address token, uint256 fee, address curve) external returns (address) {
    // fee and curve are passed through without validation
    address pool = new Pool(token, fee, curve);
    return pool;
}
```

**Fixed:**
```solidity
// Validate parameters and token properties
function createPool(address token, uint256 fee, address curve) external returns (address) {
    require(fee <= MAX_FEE, "Fee too high");
    require(approvedCurves[curve], "Curve not approved");
    require(token != address(0), "Zero address");
    require(IERC20(token).totalSupply() > 0, "Invalid token");
    address pool = new Pool(token, fee, curve);
    return pool;
}
```

### Pattern 4: Pool state manipulation during flash operations

During a flash loan or flash swap, the pool's reserves are temporarily imbalanced. If other contracts read the pool's reserve state (via getReserves, slot0, or balanceOf) during this window, they observe a manipulated price. Contracts that use the pool as a price oracle or that allow sync/skim during flash operations are vulnerable to single-transaction price manipulation. This includes donation attacks where tokens are sent directly to the pool to skew the balance-based accounting.

**Vulnerable:**
```solidity
// Reserves readable during flash loan
function flashLoan(uint256 amount, bytes calldata data) external {
    _transfer(token, msg.sender, amount);
    // During callback, getReserves() returns imbalanced state
    IFlashBorrower(msg.sender).onFlashLoan(amount, data);
    require(token.balanceOf(address(this)) >= reserve + fee, "Not repaid");
}

// Also vulnerable: sync() callable during imbalanced state
function sync() external {
    reserve0 = IERC20(token0).balanceOf(address(this)); // attacker donated tokens
    reserve1 = IERC20(token1).balanceOf(address(this));
}
```

**Fixed:**
```solidity
// Use reentrancy lock and internal accounting
function flashLoan(uint256 amount, bytes calldata data) external nonReentrant {
    uint256 balanceBefore = token.balanceOf(address(this));
    _transfer(token, msg.sender, amount);
    IFlashBorrower(msg.sender).onFlashLoan(amount, data);
    require(token.balanceOf(address(this)) >= balanceBefore + fee, "Not repaid");
    // reserves updated only after flash loan completes
    _updateReserves();
}
```

### Pattern 5: Shared liquidity accounting across pools

A protocol uses a global state variable (timelock, nonce, or shared LP token) that affects multiple independent pools. When one pool's operation modifies the shared state, it interferes with other pools' operations. This includes global withdrawal timelocks that block all pool exits when any single pool is locked, and shared LP token contracts where burning from one pool affects the balance used by another pool's accounting.

**Vulnerable:**
```solidity
// Global timelock affects all pools
mapping(address => uint256) public lastDepositTime;

function withdraw(address pool, uint256 shares) external {
    // Global timelock: depositing into ANY pool blocks withdrawal from ALL pools
    require(block.timestamp >= lastDepositTime[msg.sender] + TIMELOCK, "Locked");
    Pool(pool).burn(msg.sender, shares);
}
```

**Fixed:**
```solidity
// Per-pool timelock
mapping(address => mapping(address => uint256)) public lastDepositTime; // user => pool => time

function withdraw(address pool, uint256 shares) external {
    require(
        block.timestamp >= lastDepositTime[msg.sender][pool] + TIMELOCK,
        "Locked"
    );
    Pool(pool).burn(msg.sender, shares);
}
```

### Detect
For every pool factory and pool lifecycle: (1) verify token pair uniqueness with canonical ordering, (2) verify all token addresses in a pool are distinct and non-zero, (3) verify factory parameters are validated before forwarding to pool implementation, (4) check whether pool reserves or balances are readable/writable during flash operations, (5) verify per-pool isolation of timelocks, LP tokens, and accounting state.

### Remediation
Enforce token uniqueness (pairwise for multi-asset) and pair uniqueness (canonical ordering) at the factory level. Validate all factory parameters before forwarding to pool implementation. Prevent reserve reads during flash operations or use internal accounting that is not affected by temporary imbalance. Use per-pool state isolation for timelocks, LP tokens, and any accounting variables. Consider requiring minimum initial liquidity or governance approval for pool creation.

## CL-DEX-04: Slippage & Deadline Protection Invariant

**Rule:** `EVM-DEX-SLIP-01`
**Severity:** medium-high

### Description
One or more swap or liquidity operations lack slippage protection, use hardcoded tolerance, pass block.timestamp as deadline, or have calculation errors in slippage enforcement. Missing or ineffective slippage and deadline parameters allow sandwich attacks and stale-price execution.

### Patterns
### Pattern 1: Missing slippage protection on swaps

The function performs a token swap via a DEX router (Uniswap V2/V3, Curve, Balancer) or internal bonding curve without accepting a user-supplied minimum output. This includes direct swap calls as well as swaps buried inside harvest, compound, or rebalance flows. With amountOutMinimum set to 0, the transaction executes at any price, enabling sandwich attacks.

**Vulnerable:**
```solidity
// amountOutMinimum hardcoded to 0
function swapRewards(uint256 amountIn) external {
    ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
        tokenIn: rewardToken,
        tokenOut: baseToken,
        fee: 3000,
        recipient: address(this),
        deadline: block.timestamp + 300,
        amountIn: amountIn,
        amountOutMinimum: 0, // <-- accepts any output, sandwich-able
        sqrtPriceLimitX96: 0
    });
    router.exactInputSingle(params);
}
```

**Fixed:**
```solidity
// User-supplied minimum output
function swapRewards(uint256 amountIn, uint256 minAmountOut) external {
    ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
        tokenIn: rewardToken,
        tokenOut: baseToken,
        fee: 3000,
        recipient: address(this),
        deadline: block.timestamp + 300,
        amountIn: amountIn,
        amountOutMinimum: minAmountOut, // <-- caller specifies floor
        sqrtPriceLimitX96: 0
    });
    router.exactInputSingle(params);
}
```

### Pattern 2: Missing slippage protection on liquidity operations

The function adds or removes liquidity from an AMM pool without enforcing minimum asset amounts. This covers Uniswap V2 addLiquidity/removeLiquidity, concentrated liquidity position creation via Uniswap V3 NonFungiblePositionManager, pool migrations, and zap-in flows. Attackers can manipulate pool ratios before the operation to extract value.

**Vulnerable:**
```solidity
// Zero minimums on addLiquidity
function addLiq(uint256 amountA, uint256 amountB) external {
    router.addLiquidity(
        tokenA, tokenB,
        amountA, amountB,
        0, 0,              // <-- amountAMin and amountBMin are 0
        address(this),
        block.timestamp
    );
}
```

**Fixed:**
```solidity
// User-supplied or oracle-derived minimums
function addLiq(
    uint256 amountA, uint256 amountB,
    uint256 amountAMin, uint256 amountBMin,
    uint256 deadline
) external {
    router.addLiquidity(
        tokenA, tokenB,
        amountA, amountB,
        amountAMin, amountBMin, // <-- caller specifies floors
        address(this),
        deadline
    );
}
```

### Pattern 3: Hardcoded or static slippage tolerance

The contract applies a constant slippage bound (e.g., 5% or 10%) rather than accepting it as a function parameter. This gives MEV bots a guaranteed extraction window up to the tolerance. It also applies to protocols that calculate slippage on-chain using spot pool state (get_dy, getAmountsOut, slot0), since an attacker can manipulate the pool before the query, making the "expected" value already skewed.

**Vulnerable:**
```solidity
// Hardcoded 5% slippage tolerance
function harvest() external {
    uint256 rewardBal = rewardToken.balanceOf(address(this));
    uint256 expectedOut = router.getAmountsOut(rewardBal, path)[path.length - 1];
    uint256 minOut = expectedOut * 95 / 100; // <-- fixed 5%, MEV bots extract up to 5%
    router.swapExactTokensForTokens(rewardBal, minOut, path, address(this), block.timestamp);
}
```

**Fixed:**
```solidity
// User-supplied slippage parameter
function harvest(uint256 minAmountOut, uint256 deadline) external {
    uint256 rewardBal = rewardToken.balanceOf(address(this));
    router.swapExactTokensForTokens(rewardBal, minAmountOut, path, address(this), deadline);
}
```

### Pattern 4: Missing or ineffective deadline

The function lacks a deadline parameter entirely, or passes block.timestamp as the deadline to a DEX router. Since block.timestamp is set by the validator at execution time, it always equals "now" and provides no protection. Transactions can sit in the mempool indefinitely and execute at stale prices.

**Vulnerable:**
```solidity
// block.timestamp as deadline (always passes)
function swap(uint256 amountIn, uint256 minOut) external {
    router.swapExactTokensForTokens(
        amountIn, minOut, path, address(this),
        block.timestamp // <-- always equals "now", no protection
    );
}
```

**Fixed:**
```solidity
// User-supplied deadline
function swap(uint256 amountIn, uint256 minOut, uint256 deadline) external {
    router.swapExactTokensForTokens(
        amountIn, minOut, path, address(this),
        deadline // <-- caller specifies expiration
    );
}
```

### Pattern 5: Slippage calculation errors

The slippage enforcement logic contains a computational error: the minimum output is denominated in the wrong token's units (e.g., input token decimals applied to output token), the comparison is inverted, cumulative slippage across multi-step swaps is not bounded, or the minimum is derived from a manipulable on-chain source like Uniswap V3 slot0 sqrtPriceX96.

**Vulnerable:**
```solidity
// Using slot0 sqrtPriceX96 to derive minOut (manipulable via flash loan)
function swapWithOnChainCalc(uint256 amountIn) external {
    (uint160 sqrtPriceX96,,,,,,) = pool.slot0(); // <-- manipulable in same block
    uint256 expectedOut = calculateFromSqrtPrice(sqrtPriceX96, amountIn);
    uint256 minOut = expectedOut * 99 / 100;
    router.exactInputSingle(/* ... amountOutMinimum: minOut ... */);
}

// Slippage in wrong token units (input token used for output floor)
function compoundRewards() external {
    uint256 rewardBal = rewardToken.balanceOf(address(this));
    // rewardToken has 18 decimals, baseToken has 6 decimals
    uint256 amountOutMin = (rewardBal * 95) / 100; // <-- wrong: uses reward token units for output
    router.swapExactTokensForTokens(rewardBal, amountOutMin, path, address(this), block.timestamp);
}
```

**Fixed:**
```solidity
// Oracle-based minimum, correct token units
function swapWithOracleCalc(uint256 amountIn, uint256 deadline) external {
    uint256 oraclePrice = oracle.latestAnswer(); // TWAP or Chainlink, not spot
    uint256 expectedOut = (amountIn * oraclePrice) / 1e18;
    uint256 minOut = expectedOut * 99 / 100; // small tolerance on top of oracle price
    router.exactInputSingle(/* ... amountOutMinimum: minOut, deadline: deadline ... */);
}
```

### Detect
For every function that executes a swap or modifies a liquidity position: (1) verify user-supplied slippage parameter exists, (2) verify deadline parameter is not block.timestamp, (3) verify slippage is not hardcoded, (4) verify slippage units match the token being checked, (5) verify multi-step operations have cumulative slippage bounds.

### Remediation
Accept user-supplied `minAmountOut` and `deadline` on every swap and liquidity operation. Never hardcode slippage or use `block.timestamp` as deadline. Use oracle prices (not spot pool state) for any on-chain slippage calculation. Validate cumulative slippage across multi-step operations. Ensure slippage units match the output token.
