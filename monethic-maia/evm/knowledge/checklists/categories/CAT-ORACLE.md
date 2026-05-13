## CL-ORACLE-01: Oracle Administration Invariant

**Rule:** `ADMIN-01`
**Severity:** low-medium

### Description
When a contract has administrative functions that configure oracle parameters -- feed addresses, staleness thresholds, price bounds, data sources, or manual price overrides -- those functions must enforce input validation and operational flexibility. Oracle administration functions that lack input validation allow privileged actors to set malicious feed addresses, unbounded staleness thresholds, zero/extreme price bounds, or directly inject arbitrary prices. Additionally, immutable oracle addresses without update mechanisms create operational rigidity that prevents responding to feed deprecation. A compromised or malicious admin can silently redirect price feeds to attacker-controlled contracts, set staleness thresholds so high that ancient prices are accepted, remove price bounds entirely, or inject arbitrary prices. Immutable addresses prevent recovery when feeds are deprecated or compromised.

### Patterns
### Pattern 1: Unvalidated Oracle Address Swap

An admin function accepts any address as a new oracle without verifying it implements the expected interface. A compromised admin sets a malicious contract that returns attacker-chosen prices.

**Vulnerable:**
```solidity
contract Vault {
    AggregatorV3Interface public priceFeed;

    function setOracle(address _newFeed) external onlyOwner {
        // BUG: No interface check — any contract accepted
        // Admin (or compromised key) sets malicious feed
        priceFeed = AggregatorV3Interface(_newFeed);
    }
}
```

**Fixed:**
```solidity
contract Vault {
    AggregatorV3Interface public priceFeed;
    AggregatorV3Interface public pendingFeed;
    uint256 public pendingFeedTimestamp;
    uint256 public constant TIMELOCK = 48 hours;

    function proposeOracle(address _newFeed) external onlyOwner {
        // Verify interface compatibility
        AggregatorV3Interface feed = AggregatorV3Interface(_newFeed);
        (, int256 price,, uint256 updatedAt,) = feed.latestRoundData();
        require(price > 0 && updatedAt > 0, "Feed not responding");
        require(feed.decimals() > 0, "Invalid decimals");

        pendingFeed = feed;
        pendingFeedTimestamp = block.timestamp;
        emit OracleProposed(_newFeed);
    }

    function executeOracleChange() external onlyOwner {
        require(address(pendingFeed) != address(0), "No pending feed");
        require(block.timestamp >= pendingFeedTimestamp + TIMELOCK, "Timelock active");

        priceFeed = pendingFeed;
        delete pendingFeed;
        emit OracleUpdated(address(priceFeed));
    }
}
```

### Pattern 2: Unbounded Staleness Threshold Configuration

An admin can set the price validity duration to an extreme value (e.g., `type(uint256).max`), effectively disabling staleness checks and allowing arbitrarily old prices to be consumed.

**Vulnerable:**
```solidity
contract Oracle {
    uint256 public maxStaleness;

    function setMaxStaleness(uint256 _maxStaleness) external onlyOwner {
        // BUG: No upper bound — can be set to type(uint256).max
        // Effectively disables all staleness checks
        maxStaleness = _maxStaleness;
    }

    function getPrice() public view returns (uint256) {
        (, int256 price,, uint256 updatedAt,) = feed.latestRoundData();
        require(block.timestamp - updatedAt <= maxStaleness, "Stale");
        return uint256(price);
    }
}
```

**Fixed:**
```solidity
contract Oracle {
    uint256 public maxStaleness;
    uint256 public constant MIN_STALENESS = 60;      // 1 minute
    uint256 public constant MAX_STALENESS_CAP = 86400; // 24 hours

    function setMaxStaleness(uint256 _maxStaleness) external onlyOwner {
        require(_maxStaleness >= MIN_STALENESS, "Too short");
        require(_maxStaleness <= MAX_STALENESS_CAP, "Too long");
        emit MaxStalenessUpdated(maxStaleness, _maxStaleness);
        maxStaleness = _maxStaleness;
    }
}
```

### Pattern 3: Unbounded Manual Price Override

An admin function allows setting prices directly without bounds validation. A malicious or compromised admin injects extreme prices to manipulate liquidations, borrowing, or redemptions.

**Vulnerable:**
```solidity
contract ManualOracle {
    uint256 public price;

    function setPrice(uint256 _price) external onlyOwner {
        // BUG: No bounds — admin can set price to 0, 1, or type(uint256).max
        price = _price;
    }

    function getPrice() public view returns (uint256) {
        return price;
    }
}
```

**Fixed:**
```solidity
contract ManualOracle {
    uint256 public price;
    uint256 public lastUpdate;
    uint256 public constant MAX_DEVIATION = 50; // 50% max change per update
    uint256 public constant MIN_PRICE = 1e4;    // Minimum sane price
    uint256 public constant MAX_PRICE = 1e30;   // Maximum sane price

    function setPrice(uint256 _price) external onlyOwner {
        require(_price >= MIN_PRICE && _price <= MAX_PRICE, "Out of bounds");

        // Limit price deviation from previous value
        if (price > 0) {
            uint256 deviation = _price > price
                ? (_price - price) * 100 / price
                : (price - _price) * 100 / price;
            require(deviation <= MAX_DEVIATION, "Deviation too large");
        }

        emit PriceUpdated(price, _price, msg.sender);
        price = _price;
        lastUpdate = block.timestamp;
    }
}
```

### Pattern 4: Immutable Oracle Address Without Update Mechanism

The oracle address is set once (in constructor or as `immutable`) with no admin function to update it. When Chainlink deprecates a feed or the oracle contract is compromised, the protocol has no recovery path and must be fully redeployed.

**Vulnerable:**
```solidity
contract ImmutableOracleVault {
    AggregatorV3Interface public immutable priceFeed;

    constructor(address _feed) {
        priceFeed = AggregatorV3Interface(_feed);
    }

    // No way to update feed if Chainlink deprecates it
    // Protocol must be redeployed and all users must migrate
    function getPrice() public view returns (uint256) {
        (, int256 price,,,) = priceFeed.latestRoundData();
        return uint256(price);
    }
}
```

**Fixed:**
```solidity
contract UpgradeableOracleVault {
    AggregatorV3Interface public priceFeed;
    address public owner;

    constructor(address _feed) {
        priceFeed = AggregatorV3Interface(_feed);
        owner = msg.sender;
    }

    function updateFeed(address _newFeed) external {
        require(msg.sender == owner, "Not owner");
        // Validate the new feed responds correctly
        AggregatorV3Interface newFeed = AggregatorV3Interface(_newFeed);
        (, int256 price,, uint256 updatedAt,) = newFeed.latestRoundData();
        require(price > 0 && updatedAt > 0, "Invalid feed");

        emit FeedUpdated(address(priceFeed), _newFeed);
        priceFeed = newFeed;
    }
}
```

### Pattern 5: Centralized Off-Chain Signer Without Verification

The protocol trusts a single off-chain signer for price data with no on-chain cross-validation, quorum requirement, or deviation check. A compromised signer key allows arbitrary price injection.

**Vulnerable:**
```solidity
contract SignerOracle {
    address public signer;

    function submitPrice(uint256 price, bytes calldata sig) external {
        // BUG: Single signer — compromised key = full control
        // No cross-validation against any on-chain source
        // No deviation check from previous price
        bytes32 hash = keccak256(abi.encodePacked(price, block.timestamp));
        require(ECDSA.recover(hash, sig) == signer, "Bad sig");
        currentPrice = price;
    }
}
```

**Fixed:**
```solidity
contract MultiSignerOracle {
    address[] public signers;
    uint256 public quorum;
    AggregatorV3Interface public referenceFeed;
    uint256 public constant MAX_DEVIATION_FROM_REF = 5; // 5%

    function submitPrice(uint256 price, bytes[] calldata sigs) external {
        // Require quorum of signers
        bytes32 hash = keccak256(abi.encodePacked(price, block.timestamp));
        uint256 validSigs;
        for (uint i = 0; i < sigs.length; i++) {
            address recovered = ECDSA.recover(hash, sigs[i]);
            if (_isValidSigner(recovered)) validSigs++;
        }
        require(validSigs >= quorum, "Insufficient quorum");

        // Cross-validate against on-chain reference
        (, int256 refPrice,,,) = referenceFeed.latestRoundData();
        if (refPrice > 0) {
            uint256 deviation = price > uint256(refPrice)
                ? (price - uint256(refPrice)) * 100 / uint256(refPrice)
                : (uint256(refPrice) - price) * 100 / uint256(refPrice);
            require(deviation <= MAX_DEVIATION_FROM_REF, "Exceeds reference deviation");
        }

        currentPrice = price;
        emit PriceSubmitted(price, validSigs);
    }
}
```

### Detect
For every oracle administration function: (1) verify new oracle addresses are validated for interface compatibility and liveness, (2) verify staleness thresholds have enforced upper and lower bounds, (3) verify manual price updates have deviation and bounds checks, (4) verify oracle addresses can be updated for feed deprecation recovery, (5) verify off-chain signer oracles use quorum and cross-validation.

### Remediation
Validate all admin inputs: verify interface support for new feed addresses, enforce sane bounds on thresholds and prices, use timelocks for sensitive changes, emit events for all configuration updates. Provide update mechanisms with appropriate access control for oracle addresses.

## CL-ORACLE-02: Decimal & Precision Handling Invariant

**Rule:** `DECIMAL-01`
**Severity:** medium-high

### Description
When a contract normalizes oracle prices across feeds with different decimal precisions, or performs arithmetic that combines oracle values with token amounts of varying decimals (6, 8, 18, etc.), the scaling logic must be correct and dynamic. Oracle price scaling that uses hardcoded decimal assumptions, divides before multiplying (losing precision to integer truncation), casts between fixed-point formats incorrectly, or fails to query and adapt to the actual decimal precision of each feed and token results in prices inflated or deflated by orders of magnitude (e.g., 1e10x or 1e-10x), truncated to zero, or subtly inaccurate. This enables overborrowing, undercollateralized positions, incorrect liquidations, arbitrage extraction, and protocol insolvency.

### Patterns
### Pattern 1: Hardcoded Decimal Multiplier Mismatch

The contract applies a fixed multiplier (e.g., `1e10`, `1e12`) assuming all oracle feeds return 8 decimals and all tokens have 18 decimals. When a feed returns 18 decimals (ETH-denominated feeds) or a token has 6 decimals (USDC), the price is wrong by orders of magnitude.

**Vulnerable:**
```solidity
contract LendingPool {
    function getValueInUSD(address token, uint256 amount) public view returns (uint256) {
        (, int256 price,,,) = feeds[token].latestRoundData();
        // BUG: Assumes ALL feeds return 8 decimals
        // ETH/BTC feed returns 18 decimals → price inflated by 1e10
        uint256 normalizedPrice = uint256(price) * 1e10; // force to 18 dec

        // BUG: Assumes ALL tokens have 18 decimals
        // USDC has 6 decimals → result deflated by 1e12
        return amount * normalizedPrice / 1e18;
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    function getValueInUSD(address token, uint256 amount) public view returns (uint256) {
        AggregatorV3Interface feed = feeds[token];
        (, int256 price,,,) = feed.latestRoundData();
        require(price > 0, "Invalid price");

        uint8 feedDecimals = feed.decimals();
        uint8 tokenDecimals = IERC20Metadata(token).decimals();

        // Dynamic normalization: amount * price scaled to 18 decimals
        // amount has tokenDecimals, price has feedDecimals
        // result = amount * price * 10^(18 - tokenDecimals - feedDecimals)
        uint256 value = uint256(price) * amount;
        uint8 totalDecimals = feedDecimals + tokenDecimals;

        if (totalDecimals < 18) {
            return value * 10 ** (18 - totalDecimals);
        } else if (totalDecimals > 18) {
            return value / 10 ** (totalDecimals - 18);
        }
        return value;
    }
}
```

### Pattern 2: Division Before Multiplication (Precision Truncation)

Integer division in Solidity truncates. Dividing a fixed-point value by its scale before multiplying by the target scale destroys all fractional precision. This is catastrophic for X96/X128 Uniswap prices where the integer part may be zero.

**Vulnerable:**
```solidity
contract UniV3Oracle {
    function getSqrtPriceX96AsPrice() public view returns (uint256) {
        (uint160 sqrtPriceX96,,,,,,) = pool.slot0();
        uint256 sqrtPrice = uint256(sqrtPriceX96);

        // BUG: Divide by 2^96 first → truncates to 0 or 1 for most pairs
        uint256 price = (sqrtPrice * sqrtPrice) / (2**96) / (2**96);
        // Then multiply by 1e18 → 0 * 1e18 = 0
        return price * 1e18;
    }
}
```

**Fixed:**
```solidity
contract UniV3Oracle {
    function getSqrtPriceX96AsPrice() public view returns (uint256) {
        (uint160 sqrtPriceX96,,,,,,) = pool.slot0();
        uint256 sqrtPrice = uint256(sqrtPriceX96);

        // Multiply by target precision BEFORE dividing by scale
        // Use FullMath to prevent overflow
        uint256 price = FullMath.mulDiv(
            sqrtPrice * sqrtPrice,
            1e18,
            2**192 // (2^96)^2
        );
        return price;
    }
}
```

### Pattern 3: Oracle Price Direction Inversion

Using a "forward" oracle price (A/B) when the calculation requires "inverse" (B/A), or failing to check Uniswap V3 token0/token1 ordering. The price is inverted, causing valuations to be the reciprocal of the correct value.

**Vulnerable:**
```solidity
contract CrossRateOracle {
    // ETH/USD oracle: returns ETH price in USD (e.g., 2000e8)
    AggregatorV3Interface public ethUsdFeed;

    function convertUsdToEth(uint256 usdAmount) public view returns (uint256) {
        (, int256 ethPrice,,,) = ethUsdFeed.latestRoundData();
        // BUG: ethPrice = 2000e8 (ETH in USD), but we need USD→ETH
        // Should divide by ethPrice, not multiply
        return usdAmount * uint256(ethPrice) / 1e8;
        // Returns 1 USD * 2000 = 2000 ETH instead of 0.0005 ETH
    }
}
```

**Fixed:**
```solidity
contract CrossRateOracle {
    AggregatorV3Interface public ethUsdFeed;

    function convertUsdToEth(uint256 usdAmount) public view returns (uint256) {
        (, int256 ethPrice,,,) = ethUsdFeed.latestRoundData();
        require(ethPrice > 0, "Invalid price");

        // Invert: USD→ETH = usdAmount / (ETH/USD price)
        // Multiply first for precision: usdAmount * 1e8 / ethPrice
        return usdAmount * 1e8 / uint256(ethPrice);
    }
}
```

### Pattern 4: Unsafe Exponent and Scaling Overflow

Oracle feeds (Pyth, custom) return prices with signed exponents. Assuming the exponent is always negative and blindly negating it causes overflow when positive. Scaling within `unchecked` blocks masks overflow to produce corrupt prices.

**Vulnerable:**
```solidity
contract PythScaler {
    function normalizePrice(int64 price, int32 expo) public pure returns (uint256) {
        // BUG: Assumes expo is always negative
        // If expo = 5, then -expo overflows int32 (or gives -5)
        uint32 decimals = uint32(-expo);

        // BUG: Inside unchecked — overflow wraps silently
        unchecked {
            // If price is large and decimals is wrong, this overflows to garbage
            return uint256(uint64(price)) * (10 ** (18 - decimals));
        }
    }
}
```

**Fixed:**
```solidity
contract PythScaler {
    function normalizePrice(int64 price, int32 expo) public pure returns (uint256) {
        require(price > 0, "Non-positive price");
        require(expo <= 0 && expo >= -18, "Unexpected exponent");

        uint256 decimals = uint256(uint32(-expo));
        uint256 normalized = uint256(uint64(price));

        if (decimals < 18) {
            normalized = normalized * (10 ** (18 - decimals));
        } else if (decimals > 18) {
            normalized = normalized / (10 ** (decimals - 18));
        }

        require(normalized > 0, "Normalized to zero");
        return normalized;
    }
}
```

### Pattern 5: Token Decimal Mismatch in Cross-Price Calculation

Computing a cross-rate or collateral value by multiplying token amounts by oracle prices without normalizing for the difference in token decimals. USDC (6 dec) multiplied by an 8-decimal oracle gives 14 decimals, not 18 -- off by 10,000x.

**Vulnerable:**
```solidity
contract CrossCollateral {
    function getCollateralValueUSD(
        address token,
        uint256 amount
    ) public view returns (uint256) {
        (, int256 price,,,) = feeds[token].latestRoundData();
        // BUG: amount has token-specific decimals (6 for USDC, 18 for WETH)
        // price has 8 decimals from Chainlink
        // Result decimal = tokenDecimals + 8, NOT normalized to 18
        // 1000 USDC = 1000e6 * 1e8 = 1e17 (should be 1e21 in 18-dec terms)
        return amount * uint256(price);
    }
}
```

**Fixed:**
```solidity
contract CrossCollateral {
    function getCollateralValueUSD(
        address token,
        uint256 amount
    ) public view returns (uint256) {
        AggregatorV3Interface feed = feeds[token];
        (, int256 price,,,) = feed.latestRoundData();
        require(price > 0, "Invalid");

        uint8 feedDec = feed.decimals();
        uint8 tokenDec = IERC20Metadata(token).decimals();

        // Normalize to 18 decimals: amount * price * 10^(18 - tokenDec - feedDec)
        return FullMath.mulDiv(
            amount * uint256(price),
            10 ** 18,
            10 ** (uint256(tokenDec) + uint256(feedDec))
        );
    }
}
```

### Detect
For every oracle price normalization: (1) verify decimal counts are queried dynamically, not hardcoded, (2) verify multiplication is performed before division to preserve precision, (3) verify the oracle price direction matches the calculation intent, (4) verify exponent signs are validated before negation, (5) verify cross-token calculations account for differing decimal precisions.

### Remediation
Always query `oracle.decimals()` and `token.decimals()` dynamically. Multiply before dividing (use `FullMath.mulDiv` for safe full-precision math). Never hardcode decimal assumptions. Validate that scaled prices fall within sane bounds.

## CL-ORACLE-03: Oracle Resilience & Fallback Invariant

**Rule:** `FALLBACK-01`
**Severity:** medium-high

### Description
When a contract depends on an external oracle (Chainlink, Pyth, custom) for price data that gates critical protocol operations (liquidations, withdrawals, deposits, redemptions), the integration must be resilient against oracle failure modes. The oracle integration that has no resilience against reverting feeds, L2 sequencer downtime, circuit breaker activation (min/max price clamping), missing fallback sources, or unprotected external calls that propagate reverts into the protocol causes oracle failures to cascade into full protocol DoS -- users cannot withdraw, liquidations freeze (bad debt accumulates), or circuit breaker clamping causes the protocol to operate on artificially bounded prices while the real market moves beyond bounds.

### Patterns
### Pattern 1: Unprotected Oracle Call Propagates Revert

A direct oracle call without try/catch causes the calling function to revert when the oracle reverts (multisig pause, feed deprecation, access control change). This freezes all protocol operations that depend on that price.

**Vulnerable:**
```solidity
contract Vault {
    AggregatorV3Interface public priceFeed;

    function withdraw(uint256 shares) external {
        // BUG: If Chainlink multisig pauses feed, this reverts
        // ALL withdrawals freeze — user funds locked
        (, int256 price,,,) = priceFeed.latestRoundData();
        uint256 value = shares * uint256(price) / 1e8;
        _burn(msg.sender, shares);
        token.transfer(msg.sender, value);
    }

    function liquidate(address user) external {
        // Same problem — liquidations freeze, bad debt accumulates
        (, int256 price,,,) = priceFeed.latestRoundData();
        require(getHealth(user, uint256(price)) < MIN_HEALTH, "Healthy");
        _liquidate(user);
    }
}
```

**Fixed:**
```solidity
contract Vault {
    AggregatorV3Interface public primaryFeed;
    AggregatorV3Interface public fallbackFeed;
    uint256 public lastKnownPrice;
    uint256 public lastPriceTimestamp;

    function getPrice() public returns (uint256) {
        // Try primary feed
        try primaryFeed.latestRoundData() returns (
            uint80 roundId, int256 price, uint256, uint256 updatedAt, uint80 answeredInRound
        ) {
            if (price > 0 && block.timestamp - updatedAt <= 3600 && answeredInRound >= roundId) {
                lastKnownPrice = uint256(price);
                lastPriceTimestamp = updatedAt;
                return uint256(price);
            }
        } catch {}

        // Try fallback feed
        try fallbackFeed.latestRoundData() returns (
            uint80, int256 price, uint256, uint256 updatedAt, uint80
        ) {
            if (price > 0 && block.timestamp - updatedAt <= 7200) {
                lastKnownPrice = uint256(price);
                lastPriceTimestamp = updatedAt;
                return uint256(price);
            }
        } catch {}

        // Last resort: use cached price if recent enough
        require(block.timestamp - lastPriceTimestamp <= 14400, "No valid price");
        return lastKnownPrice;
    }
}
```

### Pattern 2: Missing L2 Sequencer Uptime Check

On L2s (Arbitrum, Optimism), when the sequencer goes down, oracle prices freeze at their last value. After recovery, the stale prices are briefly "valid" (within heartbeat) but do not reflect market movements during downtime. Liquidations and trades execute at outdated prices.

**Vulnerable:**
```solidity
contract L2LendingPool {
    AggregatorV3Interface public priceFeed;

    function liquidate(address user) external {
        (, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
        // BUG: No sequencer check — after 2-hour downtime, price is stale
        // but updatedAt may pass freshness check due to heartbeat overlap
        require(block.timestamp - updatedAt <= 3600, "Stale");
        require(price > 0, "Invalid");

        uint256 health = _calculateHealth(user, uint256(price));
        require(health < MIN_HEALTH, "Healthy");
        _seize(user, msg.sender);
    }
}
```

**Fixed:**
```solidity
contract L2LendingPool {
    AggregatorV3Interface public priceFeed;
    AggregatorV3Interface public sequencerFeed;
    uint256 public constant GRACE_PERIOD = 3600; // 1 hour after recovery

    function liquidate(address user) external {
        // Check sequencer status first
        (, int256 answer,, uint256 startedAt,) = sequencerFeed.latestRoundData();
        bool isSequencerUp = answer == 0;
        require(isSequencerUp, "Sequencer down");

        // Enforce grace period after recovery
        uint256 timeSinceUp = block.timestamp - startedAt;
        require(timeSinceUp > GRACE_PERIOD, "Grace period active");

        // Now safe to use price feed
        (, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
        require(block.timestamp - updatedAt <= 3600, "Stale");
        require(price > 0, "Invalid");

        uint256 health = _calculateHealth(user, uint256(price));
        require(health < MIN_HEALTH, "Healthy");
        _seize(user, msg.sender);
    }
}
```

### Pattern 3: Chainlink Circuit Breaker (Min/Max Answer) Bypass

Chainlink aggregators clamp reported prices between hardcoded `minAnswer` and `maxAnswer`. During extreme market events (e.g., LUNA crash), the real price drops below `minAnswer` but the feed reports `minAnswer` -- a floor price that is far above market reality. Protocols operating on this clamped price allow borrowers to maintain positions that should be liquidated.

**Vulnerable:**
```solidity
contract CollateralManager {
    AggregatorV3Interface public feed;

    function getPrice() public view returns (uint256) {
        (, int256 price,,,) = feed.latestRoundData();
        require(price > 0, "Invalid");
        // BUG: No circuit breaker detection
        // If real price = $0.01 but minAnswer = $0.10, feed returns $0.10
        // Protocol treats collateral as 10x more valuable than reality
        return uint256(price);
    }
}
```

**Fixed:**
```solidity
contract CollateralManager {
    AggregatorV3Interface public feed;
    int192 public minAnswer;
    int192 public maxAnswer;

    constructor(address _feed) {
        feed = AggregatorV3Interface(_feed);
        // Cache circuit breaker bounds from aggregator
        // These can be read from the aggregator contract
        minAnswer = IOffchainAggregator(feed.aggregator()).minAnswer();
        maxAnswer = IOffchainAggregator(feed.aggregator()).maxAnswer();
    }

    function getPrice() public view returns (uint256) {
        (, int256 price,,,) = feed.latestRoundData();
        require(price > 0, "Invalid");

        // Detect circuit breaker activation
        require(price > int256(minAnswer), "Price at circuit breaker floor");
        require(price < int256(maxAnswer), "Price at circuit breaker ceiling");

        return uint256(price);
    }
}
```

### Pattern 4: Silent Oracle Failure Returns Zero

The oracle wrapper catches errors or detects stale data but returns zero instead of reverting. Downstream consumers interpret zero as a valid price, enabling free borrowing (collateral value = 0 means infinite LTV) or division-by-zero panics.

**Vulnerable:**
```solidity
contract OracleWrapper {
    function getPrice(address feed) public view returns (uint256) {
        try AggregatorV3Interface(feed).latestRoundData() returns (
            uint80, int256 price, uint256, uint256 updatedAt, uint80
        ) {
            if (block.timestamp - updatedAt > 3600) {
                return 0; // BUG: Returns 0 on stale — caller treats as valid
            }
            return uint256(price);
        } catch {
            return 0; // BUG: Returns 0 on revert — caller treats as valid
        }
    }
}

contract Lending {
    OracleWrapper public oracle;

    function borrow(uint256 amount) external {
        uint256 price = oracle.getPrice(collateralFeed);
        // If price = 0: collateralValue = 0 → no collateral needed
        uint256 collateralValue = deposits[msg.sender] * price / 1e8;
        // Or: division by zero if used as denominator
    }
}
```

**Fixed:**
```solidity
contract OracleWrapper {
    function getPrice(address feed) public view returns (uint256 price, bool valid) {
        try AggregatorV3Interface(feed).latestRoundData() returns (
            uint80 roundId, int256 answer, uint256, uint256 updatedAt, uint80 answeredInRound
        ) {
            if (answer > 0 && block.timestamp - updatedAt <= 3600 && answeredInRound >= roundId) {
                return (uint256(answer), true);
            }
            return (0, false); // Explicitly signal invalidity
        } catch {
            return (0, false);
        }
    }
}

contract Lending {
    OracleWrapper public oracle;

    function borrow(uint256 amount) external {
        (uint256 price, bool valid) = oracle.getPrice(collateralFeed);
        require(valid && price > 0, "Oracle unavailable");
        uint256 collateralValue = deposits[msg.sender] * price / 1e8;
    }
}
```

### Pattern 5: Missing Fallback Oracle with Empty Backup Array

The primary oracle check detects staleness, but the fallback logic iterates an empty or unconfigured backup array, falling through to use the stale primary price or returning without reverting.

**Vulnerable:**
```solidity
contract MultiOracle {
    AggregatorV3Interface public primary;
    AggregatorV3Interface[] public backups; // Initialized empty

    function getPrice() public view returns (uint256) {
        (, int256 price,, uint256 updatedAt,) = primary.latestRoundData();

        if (block.timestamp - updatedAt > 3600) {
            // Try backups
            for (uint i = 0; i < backups.length; i++) {
                (, int256 bp,, uint256 bu,) = backups[i].latestRoundData();
                if (block.timestamp - bu <= 3600 && bp > 0) {
                    return uint256(bp);
                }
            }
            // BUG: backups.length == 0 → falls through
            // Returns stale primary price without reverting
        }
        return uint256(price);
    }
}
```

**Fixed:**
```solidity
contract MultiOracle {
    AggregatorV3Interface public primary;
    AggregatorV3Interface[] public backups;

    function getPrice() public view returns (uint256) {
        (, int256 price,, uint256 updatedAt,) = primary.latestRoundData();

        if (price > 0 && block.timestamp - updatedAt <= 3600) {
            return uint256(price);
        }

        // Try backups
        for (uint i = 0; i < backups.length; i++) {
            (, int256 bp,, uint256 bu,) = backups[i].latestRoundData();
            if (block.timestamp - bu <= 3600 && bp > 0) {
                return uint256(bp);
            }
        }

        // No valid source — revert, do not return stale data
        revert("All oracles stale or failed");
    }
}
```

### Detect
For every oracle integration: (1) verify external oracle calls are wrapped in try/catch with fallback logic, (2) verify L2 deployments check sequencer uptime feed with grace period, (3) verify Chainlink min/max answer circuit breaker bounds are detected, (4) verify oracle failure paths revert or return explicit failure signals rather than zero, (5) verify fallback oracle sources exist and are validated with the same rigor as the primary.

### Remediation
Wrap oracle calls in try/catch. Implement fallback oracle sources. Check L2 sequencer uptime before consuming prices. Detect Chainlink min/max answer clamping. Add grace periods after sequencer recovery. Ensure the protocol can operate (at least in safe mode) when oracles fail.

## CL-ORACLE-04: Spot Price Manipulation Invariant

**Rule:** `SPOT-01`
**Severity:** high-critical

### Description
When a contract derives a price, exchange rate, or valuation from the instantaneous state of an on-chain liquidity pool (AMM reserves, balances, `calc_withdraw_one_coin`, `getAmountOut`, pool ratio), the spot price reflects the current pool state, which can be atomically manipulated within a single transaction via flash loans. Any protocol decision based on spot price -- collateral valuation, share pricing, liquidation triggers, slippage calculation -- is exploitable. Attackers use flash loans to skew pool reserves, execute the vulnerable function at the manipulated price, then restore reserves -- all in one transaction. This drains lending pools, mints shares at deflated prices, triggers unfair liquidations, and extracts arbitrage from every user.

### Patterns
### Pattern 1: AMM Reserve Ratio as Price Oracle

Using `getReserves()` or direct balance queries to calculate a token price. Flash loans can inflate/deflate reserves within a single block to manipulate the derived price.

**Vulnerable:**
```solidity
contract SpotPriceVault {
    IUniswapV2Pair public pair;

    function getTokenPrice() public view returns (uint256) {
        // BUG: Spot reserves are flash-loan manipulable
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        // Price = reserve1 / reserve0 — attacker swaps to skew ratio
        return uint256(reserve1) * 1e18 / uint256(reserve0);
    }

    function deposit(uint256 amount) external {
        uint256 price = getTokenPrice();
        // Attacker flash-loans to deflate price → gets more shares per token
        uint256 shares = amount * 1e18 / price;
        _mint(msg.sender, shares);
        token.transferFrom(msg.sender, address(this), amount);
    }
}
```

**Fixed:**
```solidity
contract TWAPVault {
    AggregatorV3Interface public chainlinkFeed;
    uint256 public constant MAX_STALENESS = 3600;

    function getTokenPrice() public view returns (uint256) {
        (, int256 price,, uint256 updatedAt,) = chainlinkFeed.latestRoundData();
        require(price > 0 && block.timestamp - updatedAt <= MAX_STALENESS, "Bad price");
        return uint256(price) * 1e10; // Normalize 8 → 18 decimals
    }

    function deposit(uint256 amount) external {
        uint256 price = getTokenPrice();
        uint256 shares = amount * 1e18 / price;
        _mint(msg.sender, shares);
        token.transferFrom(msg.sender, address(this), amount);
    }
}
```

### Pattern 2: Curve `calc_withdraw_one_coin` / `get_virtual_price` as Oracle

Curve pool view functions reflect current pool composition. `calc_withdraw_one_coin` is especially dangerous as it amplifies imbalance effects. Attackers imbalance the pool via large swaps, then call the victim contract that reads the distorted price.

**Vulnerable:**
```solidity
contract CurveLPValuation {
    ICurvePool public pool;
    IERC20 public lpToken;

    function getLPValue(uint256 lpAmount) public view returns (uint256) {
        // BUG: calc_withdraw_one_coin uses current pool state
        // Attacker imbalances pool → inflates/deflates single-coin value
        uint256 underlyingAmount = pool.calc_withdraw_one_coin(lpAmount, 0);
        return underlyingAmount;
    }

    function borrow(uint256 lpCollateral) external {
        uint256 value = getLPValue(lpCollateral);
        // Attacker inflates LP value → borrows more than collateral is worth
        uint256 maxBorrow = value * 80 / 100; // 80% LTV
        _issueLoan(msg.sender, maxBorrow);
    }
}
```

**Fixed:**
```solidity
contract CurveLPValuation {
    ICurvePool public pool;
    AggregatorV3Interface public underlyingFeed;

    function getLPValue(uint256 lpAmount) public view returns (uint256) {
        // Use virtual price (more resistant) * external oracle price
        uint256 virtualPrice = pool.get_virtual_price(); // monotonically increasing
        (, int256 underlyingPrice,, uint256 updatedAt,) = underlyingFeed.latestRoundData();
        require(underlyingPrice > 0 && block.timestamp - updatedAt <= 3600, "Bad price");

        // LP value = lpAmount * virtualPrice * underlyingPrice
        return lpAmount * virtualPrice / 1e18 * uint256(underlyingPrice) / 1e8;
    }
}
```

### Pattern 3: Pool Balance Query for Collateral Valuation

Direct `balanceOf` or `get_balances()` calls on pool contracts to derive prices. These are trivially manipulable by anyone who can deposit/withdraw from the pool in the same transaction.

**Vulnerable:**
```solidity
contract BalanceOracle {
    IERC20 public tokenA;
    IERC20 public tokenB;
    address public pool;

    function getPrice() public view returns (uint256) {
        // BUG: Raw balance query — manipulable via deposit/withdrawal
        uint256 balA = tokenA.balanceOf(pool);
        uint256 balB = tokenB.balanceOf(pool);
        return balB * 1e18 / balA;
    }

    function liquidate(address user) external {
        uint256 price = getPrice();
        // Attacker donates tokens to pool → inflates price → prevents liquidation
        // Or drains tokens from pool → deflates price → triggers unfair liquidation
        uint256 collateralValue = collateral[user] * price / 1e18;
        require(collateralValue < debt[user], "Healthy");
        _seize(user);
    }
}
```

**Fixed:**
```solidity
contract SafeOracle {
    AggregatorV3Interface public priceFeed;

    function getPrice() public view returns (uint256) {
        (, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
        require(price > 0, "Invalid");
        require(block.timestamp - updatedAt <= 3600, "Stale");
        return uint256(price) * 1e10;
    }
}
```

### Pattern 4: Spot Price for Slippage Calculation

Using instantaneous AMM price to compute expected output or slippage bounds. Attacker sandwiches: manipulates spot price before the victim's transaction, then the "slippage check" passes against the already-manipulated reference.

**Vulnerable:**
```solidity
contract DEXRouter {
    IUniswapV2Pair public pair;

    function swapWithProtection(uint256 amountIn) external {
        // BUG: Spot price used as slippage reference — already manipulated
        (uint112 r0, uint112 r1,) = pair.getReserves();
        uint256 spotPrice = uint256(r1) * 1e18 / uint256(r0);
        uint256 expectedOut = amountIn * spotPrice / 1e18;
        uint256 minOut = expectedOut * 99 / 100; // 1% slippage from spot

        // Attacker front-runs: manipulates reserves so spot = manipulated price
        // Victim's swap executes at bad price but passes "slippage check"
        uint256 actualOut = _executeSwap(amountIn);
        require(actualOut >= minOut, "Slippage exceeded");
    }
}
```

**Fixed:**
```solidity
contract DEXRouter {
    function swapWithProtection(
        uint256 amountIn,
        uint256 userMinOut // User provides their own minimum from off-chain quote
    ) external {
        uint256 actualOut = _executeSwap(amountIn);
        // Slippage bound comes from user's off-chain calculation, not on-chain spot
        require(actualOut >= userMinOut, "Slippage exceeded");
    }
}
```

### Pattern 5: Spot Price for Initial Share/LP Pricing

First depositor or initial LP pricing uses spot price, allowing attackers to manipulate the pool before the first deposit to set an unfavorable exchange rate that persists for subsequent depositors.

**Vulnerable:**
```solidity
contract YieldVault {
    IUniswapV2Pair public pool;
    uint256 public totalShares;

    function deposit(uint256 amount) external {
        uint256 shares;
        if (totalShares == 0) {
            // BUG: Initial pricing from spot — attacker manipulates pool first
            (uint112 r0, uint112 r1,) = pool.getReserves();
            uint256 price = uint256(r1) * 1e18 / uint256(r0);
            shares = amount * price / 1e18;
        } else {
            shares = amount * totalShares / totalAssets();
        }
        totalShares += shares;
        _mint(msg.sender, shares);
    }
}
```

**Fixed:**
```solidity
contract YieldVault {
    AggregatorV3Interface public oracle;
    uint256 public totalShares;

    function deposit(uint256 amount) external {
        uint256 shares;
        if (totalShares == 0) {
            // Use external oracle for initial pricing, not spot
            (, int256 price,, uint256 updatedAt,) = oracle.latestRoundData();
            require(price > 0 && block.timestamp - updatedAt <= 3600, "Bad oracle");
            shares = amount * uint256(price) / 1e8;
        } else {
            shares = amount * totalShares / totalAssets();
        }
        totalShares += shares;
        _mint(msg.sender, shares);
    }
}
```

### Detect
For every price derivation from on-chain pool state: (1) verify the contract does not use `getReserves()` or `balanceOf(pool)` as a price source, (2) verify Curve view functions are not used as sole price oracle, (3) verify `balanceOf` on pool addresses is not used for pricing, (4) verify slippage bounds are not derived from the same spot price being protected against, (5) verify initial share/LP pricing does not rely on manipulable spot state.

### Remediation
Never use instantaneous pool state as a price oracle. Use Chainlink feeds, Uniswap V3 TWAP via `observe()`, or time-weighted mechanisms. If spot price must be used, add manipulation-resistant checks (e.g., compare against TWAP, enforce minimum time between operations).

## CL-ORACLE-05: Price Staleness & Freshness Invariant

**Rule:** `STALE-01`
**Severity:** medium-critical

### Description
When a contract consumes price data from an external oracle (Chainlink, Pyth, custom push/pull feed) to make financial decisions (liquidations, swaps, valuations, redemptions), the oracle consumer must validate that the returned price is fresh, complete, and positive before using it in downstream logic. Failure to validate freshness includes missing timestamp checks, missing round-completion checks, using deprecated APIs that lack metadata, ignoring per-feed heartbeat differences, and accepting zero/negative prices. Stale, zero, or negative prices flow into liquidation engines, collateral valuations, swap calculations, and redemption logic, allowing attackers to exploit the gap between the stale oracle price and the real market price to extract value through arbitrage, unfair liquidations, or overborrowing.

### Patterns
### Pattern 1: Missing Staleness Check on Chainlink `latestRoundData`

The contract calls `latestRoundData()` but ignores the `updatedAt` timestamp, allowing arbitrarily stale prices to be consumed. This is the single most common oracle vulnerability in DeFi.

**Vulnerable:**
```solidity
contract LendingPool {
    AggregatorV3Interface public priceFeed;

    function getCollateralValue(address user) public view returns (uint256) {
        // BUG: No staleness check — price could be hours/days old
        (, int256 price,,,) = priceFeed.latestRoundData();
        return userCollateral[user] * uint256(price) / 1e8;
    }

    function liquidate(address user) external {
        uint256 value = getCollateralValue(user);
        // Liquidation proceeds with stale price — user liquidated unfairly
        // or attacker borrows against inflated stale collateral
        require(value < minCollateral[user], "Healthy");
        _seize(user, msg.sender);
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    AggregatorV3Interface public priceFeed;
    uint256 public constant MAX_STALENESS = 3600; // 1 hour for ETH/USD

    function getCollateralValue(address user) public view returns (uint256) {
        (
            uint80 roundId,
            int256 price,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();

        // Validate freshness
        require(updatedAt > 0, "Round not complete");
        require(block.timestamp - updatedAt <= MAX_STALENESS, "Stale price");
        // Validate round completion
        require(answeredInRound >= roundId, "Stale round");
        // Validate positive price
        require(price > 0, "Invalid price");

        return userCollateral[user] * uint256(price) / 1e8;
    }
}
```

### Pattern 2: Deprecated `latestAnswer()` Usage

The deprecated `latestAnswer()` function returns a raw `int256` with no metadata -- no timestamp, no round ID, no completion flag. It silently returns 0 on failure instead of reverting. Protocols using it cannot detect stale or failed feeds.

**Vulnerable:**
```solidity
contract Vault {
    AggregatorV3Interface public oracle;

    function getPrice() public view returns (uint256) {
        // BUG: latestAnswer() is deprecated — returns 0 on failure,
        // provides no staleness metadata, no round completion check
        int256 price = oracle.latestAnswer();
        return uint256(price);
    }

    function deposit(uint256 amount) external {
        uint256 price = getPrice();
        // If oracle fails, price = 0 → shares minted at zero cost
        uint256 shares = amount * 1e18 / price; // Division by zero or free shares
        _mint(msg.sender, shares);
    }
}
```

**Fixed:**
```solidity
contract Vault {
    AggregatorV3Interface public oracle;
    uint256 public constant MAX_STALENESS = 3600;

    function getPrice() public view returns (uint256) {
        (
            uint80 roundId,
            int256 price,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = oracle.latestRoundData();

        require(price > 0, "Invalid price");
        require(updatedAt > 0 && block.timestamp - updatedAt <= MAX_STALENESS, "Stale");
        require(answeredInRound >= roundId, "Incomplete round");

        return uint256(price);
    }
}
```

### Pattern 3: Uniform Heartbeat for Heterogeneous Feeds

Different Chainlink feeds have different heartbeat intervals (ETH/USD = 1h, USDC/USD = 24h, exotic pairs = variable). Applying a single staleness threshold to all feeds either accepts stale data from fast feeds or rejects valid data from slow feeds.

**Vulnerable:**
```solidity
contract MultiAssetVault {
    uint256 public constant FRESHNESS = 86400; // 24 hours for ALL feeds

    function getPrice(address feed) public view returns (uint256) {
        (, int256 price,, uint256 updatedAt,) =
            AggregatorV3Interface(feed).latestRoundData();
        // BUG: ETH/USD has 1h heartbeat — 24h threshold accepts
        // prices that are 23 hours stale
        require(block.timestamp - updatedAt <= FRESHNESS, "Stale");
        require(price > 0, "Zero price");
        return uint256(price);
    }
}
```

**Fixed:**
```solidity
contract MultiAssetVault {
    mapping(address => uint256) public feedHeartbeat;

    function setFeedHeartbeat(address feed, uint256 heartbeat) external onlyOwner {
        require(heartbeat >= 60 && heartbeat <= 86400, "Invalid heartbeat");
        feedHeartbeat[feed] = heartbeat;
    }

    function getPrice(address feed) public view returns (uint256) {
        uint256 maxAge = feedHeartbeat[feed];
        require(maxAge > 0, "Feed not configured");

        (, int256 price,, uint256 updatedAt,) =
            AggregatorV3Interface(feed).latestRoundData();

        // Per-feed staleness threshold
        require(block.timestamp - updatedAt <= maxAge, "Stale");
        require(price > 0, "Zero price");
        return uint256(price);
    }
}
```

### Pattern 4: Unchecked Zero or Negative Oracle Price

The oracle returns `int256` which can be zero (on failure) or negative (in extreme market conditions or feed errors). Casting directly to `uint256` without validation causes underflow to `type(uint256).max`, inflating prices astronomically and enabling unlimited borrowing or draining.

**Vulnerable:**
```solidity
contract Lending {
    function getOraclePrice(address feed) internal view returns (uint256) {
        (, int256 answer,,,) = AggregatorV3Interface(feed).latestRoundData();
        // BUG: No check for answer <= 0
        // If answer = -1, uint256(-1) = type(uint256).max → infinite collateral value
        // If answer = 0, division by zero or zero-cost borrowing downstream
        return uint256(answer);
    }

    function borrow(address collateralFeed, uint256 borrowAmount) external {
        uint256 price = getOraclePrice(collateralFeed);
        uint256 collateralValue = deposits[msg.sender] * price / 1e8;
        require(collateralValue >= borrowAmount * 15 / 10, "Undercollateralized");
        _transferBorrow(msg.sender, borrowAmount);
    }
}
```

**Fixed:**
```solidity
contract Lending {
    function getOraclePrice(address feed) internal view returns (uint256) {
        (
            uint80 roundId,
            int256 answer,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = AggregatorV3Interface(feed).latestRoundData();

        // Validate positive and non-zero
        require(answer > 0, "Oracle: non-positive price");
        require(updatedAt > 0, "Oracle: round not complete");
        require(answeredInRound >= roundId, "Oracle: stale round");

        return uint256(answer);
    }
}
```

### Pattern 5: Pyth/Custom Feed Missing Confidence & Freshness

Pyth prices include a confidence interval and publish timestamp. Using `getPriceUnsafe()` or ignoring the confidence interval accepts prices with extreme uncertainty or arbitrary staleness, enabling exploitation during volatile markets.

**Vulnerable:**
```solidity
contract PythConsumer {
    IPyth public pyth;
    bytes32 public priceId;

    function getPrice() public view returns (uint256) {
        // BUG: getPriceUnsafe skips ALL staleness checks
        PythStructs.Price memory price = pyth.getPriceUnsafe(priceId);
        // BUG: Confidence interval ignored — price could be ±50%
        // BUG: No check on price.expo sign — could overflow
        return uint256(uint64(price.price)) * (10 ** 18) / (10 ** uint32(-price.expo));
    }

    function executeSwap(uint256 amount) external {
        uint256 price = getPrice();
        // Swap executes at wildly uncertain or stale price
        uint256 output = amount * price / 1e18;
        _swap(msg.sender, output);
    }
}
```

**Fixed:**
```solidity
contract PythConsumer {
    IPyth public pyth;
    bytes32 public priceId;
    uint256 public constant MAX_STALENESS = 60; // 60 seconds
    uint64 public constant MAX_CONFIDENCE_RATIO = 10; // price/conf must be > 10

    function getPrice() public view returns (uint256) {
        // Use safe getter with staleness check
        PythStructs.Price memory price = pyth.getPriceNoOlderThan(priceId, MAX_STALENESS);

        require(price.price > 0, "Non-positive price");
        require(price.expo <= 0, "Unexpected positive exponent");

        // Validate confidence is tight enough
        uint64 absPrice = uint64(price.price);
        require(absPrice / price.conf >= MAX_CONFIDENCE_RATIO, "Price too uncertain");

        uint256 decimals = uint256(uint32(-price.expo));
        return uint256(absPrice) * 1e18 / (10 ** decimals);
    }
}
```

### Detect
For every oracle price read: (1) verify the `updatedAt` timestamp is checked against a feed-appropriate maximum age, (2) verify `answeredInRound >= roundId` for Chainlink feeds, (3) verify the price is checked for `> 0`, (4) verify per-feed heartbeat thresholds rather than a single global constant, (5) verify Pyth/custom feeds check both staleness and confidence intervals.

### Remediation
Validate all oracle metadata on every read: revert if `updatedAt` is older than the feed's heartbeat, revert if `answeredInRound < roundId`, revert if `answer <= 0`, use feed-specific heartbeat thresholds, and never use deprecated APIs that lack metadata.

## CL-ORACLE-06: TWAP Configuration Invariant

**Rule:** `TWAP-01`
**Severity:** medium-high

### Description
When a contract uses a Time-Weighted Average Price (TWAP) oracle, typically from Uniswap V3 `observe()`, Uniswap V2 cumulative prices, or a custom accumulator-based mechanism, the TWAP implementation must be properly configured and validated. An implementation that uses observation windows too short to resist manipulation, fails to handle token ordering, allows configurable periods to be set to zero or near-zero, does not account for L2 sequencer downtime extending stale observations, or has accumulator initialization issues that corrupt the first TWAP reading leads to exploitable price feeds. Short TWAP windows allow multi-block manipulation attacks where an attacker sustains a price distortion across the observation period. Misconfigured token ordering inverts the price. Zero-period TWAPs degenerate to spot prices. Post-sequencer-recovery TWAPs extrapolate stale prices across the downtime gap.

### Patterns
### Pattern 1: Observation Window Too Short

A TWAP with a short observation window (seconds to minutes) can be manipulated by sustaining a price distortion across a few blocks. The cost of manipulation scales linearly with the window length -- short windows are cheap to attack.

**Vulnerable:**
```solidity
contract ShortTWAP {
    IUniswapV3Pool public pool;
    uint32 public twapInterval = 60; // BUG: 60 seconds — 5 blocks on mainnet

    function getTWAPPrice() public view returns (uint256) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = twapInterval;
        secondsAgos[1] = 0;

        (int56[] memory tickCumulatives,) = pool.observe(secondsAgos);
        int56 tickDiff = tickCumulatives[1] - tickCumulatives[0];
        int24 avgTick = int24(tickDiff / int56(int32(twapInterval)));

        // 60-second TWAP — attacker holds position for ~5 blocks to manipulate
        return OracleLibrary.getQuoteAtTick(avgTick, 1e18, token0, token1);
    }
}
```

**Fixed:**
```solidity
contract SafeTWAP {
    IUniswapV3Pool public pool;
    uint32 public constant MIN_TWAP_INTERVAL = 1800; // 30 minutes minimum
    uint32 public twapInterval = 1800;

    function setTWAPInterval(uint32 _interval) external onlyOwner {
        require(_interval >= MIN_TWAP_INTERVAL, "Interval too short");
        twapInterval = _interval;
    }

    function getTWAPPrice() public view returns (uint256) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = twapInterval;
        secondsAgos[1] = 0;

        (int56[] memory tickCumulatives,) = pool.observe(secondsAgos);
        int56 tickDiff = tickCumulatives[1] - tickCumulatives[0];
        int24 avgTick = int24(tickDiff / int56(int32(twapInterval)));

        return OracleLibrary.getQuoteAtTick(avgTick, 1e18, token0, token1);
    }
}
```

### Pattern 2: Token0/Token1 Ordering Assumption

Uniswap V3 pools sort tokens by address. The tick-derived price is always `token1/token0`. If the code assumes a fixed base/quote relationship without checking token ordering, the price is inverted when the target token happens to be `token1`.

**Vulnerable:**
```solidity
contract TWAPOracle {
    IUniswapV3Pool public pool;
    address public targetToken;

    function getTargetPrice() public view returns (uint256) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = 1800;
        secondsAgos[1] = 0;

        (int56[] memory tickCumulatives,) = pool.observe(secondsAgos);
        int24 avgTick = int24((tickCumulatives[1] - tickCumulatives[0]) / 1800);

        // BUG: Always treats result as targetToken price
        // If targetToken == pool.token1(), the price is inverted
        uint256 price = OracleLibrary.getQuoteAtTick(avgTick, 1e18, pool.token0(), pool.token1());
        return price;
    }
}
```

**Fixed:**
```solidity
contract TWAPOracle {
    IUniswapV3Pool public pool;
    address public targetToken;
    address public quoteToken;
    bool public isTargetToken0;

    constructor(address _pool, address _target) {
        pool = IUniswapV3Pool(_pool);
        targetToken = _target;
        isTargetToken0 = (pool.token0() == _target);
        quoteToken = isTargetToken0 ? pool.token1() : pool.token0();
    }

    function getTargetPrice() public view returns (uint256) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = 1800;
        secondsAgos[1] = 0;

        (int56[] memory tickCumulatives,) = pool.observe(secondsAgos);
        int24 avgTick = int24((tickCumulatives[1] - tickCumulatives[0]) / 1800);

        // Correct ordering: quote how much quoteToken per 1 targetToken
        return OracleLibrary.getQuoteAtTick(
            avgTick,
            uint128(10 ** IERC20Metadata(targetToken).decimals()),
            targetToken,
            quoteToken
        );
    }
}
```

### Pattern 3: Zero or Uncapped TWAP Period Configuration

An admin-configurable TWAP period with no minimum bound allows setting the window to zero, which degenerates the TWAP to a spot price query. Alternatively, no maximum bound means the oracle may query observations that no longer exist in the cardinality buffer.

**Vulnerable:**
```solidity
contract ConfigurableTWAP {
    uint32 public period; // BUG: No minimum — can be set to 0

    function setPeriod(uint32 _period) external onlyOwner {
        // BUG: No validation — period = 0 makes TWAP = spot price
        period = _period;
    }

    function getPrice() public view returns (uint256) {
        if (period == 0) {
            // Degenerates to spot price — fully manipulable
            (uint160 sqrtPrice,,,,,,) = pool.slot0();
            return _sqrtPriceToPrice(sqrtPrice);
        }
        return _getTWAP(period);
    }
}
```

**Fixed:**
```solidity
contract ConfigurableTWAP {
    uint32 public constant MIN_PERIOD = 1800;  // 30 minutes
    uint32 public constant MAX_PERIOD = 86400; // 24 hours
    uint32 public period = 1800;

    function setPeriod(uint32 _period) external onlyOwner {
        require(_period >= MIN_PERIOD, "Period too short");
        require(_period <= MAX_PERIOD, "Period too long");
        period = _period;
    }

    function getPrice() public view returns (uint256) {
        return _getTWAP(period); // Always uses validated period
    }
}
```

### Pattern 4: Accumulator Initialization Edge Case

The first TWAP reading after initialization uses only a single observation point, making the "average" equivalent to the spot price at initialization time. If the pool was just created or observations just started, the TWAP provides no manipulation resistance.

**Vulnerable:**
```solidity
contract TWAPConsumer {
    uint256 public lastCumPrice;
    uint256 public lastTimestamp;
    bool public initialized;

    function update() external {
        uint256 cumPrice = pool.price0CumulativeLast();
        if (!initialized) {
            lastCumPrice = cumPrice;
            lastTimestamp = block.timestamp;
            initialized = true;
            return;
        }
        // Process TWAP...
    }

    function getPrice() public view returns (uint256) {
        // BUG: If only one update occurred, TWAP = single point = spot
        uint256 cumPrice = pool.price0CumulativeLast();
        uint256 elapsed = block.timestamp - lastTimestamp;
        // elapsed could be 0 if called in same block → division by zero
        return (cumPrice - lastCumPrice) / elapsed;
    }
}
```

**Fixed:**
```solidity
contract TWAPConsumer {
    uint256 public lastCumPrice;
    uint256 public lastTimestamp;
    uint256 public minElapsed = 1800; // Require 30 min of data

    function update() external {
        uint256 cumPrice = pool.price0CumulativeLast();
        lastCumPrice = cumPrice;
        lastTimestamp = block.timestamp;
    }

    function getPrice() public view returns (uint256) {
        require(lastTimestamp > 0, "Not initialized");
        uint256 cumPrice = pool.price0CumulativeLast();
        uint256 elapsed = block.timestamp - lastTimestamp;
        require(elapsed >= minElapsed, "Insufficient TWAP data");
        return (cumPrice - lastCumPrice) / elapsed;
    }
}
```

### Pattern 5: L2 Sequencer Downtime Corrupts TWAP

When an L2 sequencer goes offline, no new observations are recorded but time continues. After recovery, the TWAP calculation includes the downtime gap, during which the price was extrapolated at the last known value. This dilutes the "average" with stale data proportional to downtime duration.

**Vulnerable:**
```solidity
contract L2TWAP {
    IUniswapV3Pool public pool;

    function getPrice() public view returns (uint256) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = 1800; // 30 minutes
        secondsAgos[1] = 0;

        // BUG: If sequencer was down for 2 hours, the "30 min TWAP"
        // includes 1.5 hours of extrapolated stale price + 30 min of real price
        // TWAP is dominated by the stale pre-downtime price
        (int56[] memory tickCumulatives,) = pool.observe(secondsAgos);
        int24 avgTick = int24((tickCumulatives[1] - tickCumulatives[0]) / 1800);
        return OracleLibrary.getQuoteAtTick(avgTick, 1e18, token0, token1);
    }
}
```

**Fixed:**
```solidity
contract L2TWAP {
    IUniswapV3Pool public pool;
    AggregatorV3Interface public sequencerFeed;
    uint256 public constant RECOVERY_PERIOD = 3600;

    function getPrice() public view returns (uint256) {
        // Check sequencer and enforce recovery period
        (, int256 status,, uint256 startedAt,) = sequencerFeed.latestRoundData();
        require(status == 0, "Sequencer down");
        require(block.timestamp - startedAt > RECOVERY_PERIOD, "Recovery period");

        // Only use TWAP observations from after recovery
        uint32 safeWindow = uint32(block.timestamp - startedAt - RECOVERY_PERIOD);
        uint32 twapPeriod = safeWindow > 1800 ? 1800 : safeWindow;
        require(twapPeriod >= 900, "Insufficient post-recovery data"); // Min 15 min

        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = twapPeriod;
        secondsAgos[1] = 0;

        (int56[] memory tickCumulatives,) = pool.observe(secondsAgos);
        int24 avgTick = int24((tickCumulatives[1] - tickCumulatives[0]) / int32(twapPeriod));
        return OracleLibrary.getQuoteAtTick(avgTick, 1e18, token0, token1);
    }
}
```

### Detect
For every TWAP oracle usage: (1) verify the observation window is at least 30 minutes on mainnet, (2) verify token0/token1 ordering is checked dynamically against the target token, (3) verify the TWAP period has enforced minimum and maximum bounds, (4) verify accumulator initialization requires sufficient elapsed time before first read, (5) verify L2 deployments account for sequencer downtime in TWAP observation validity.

### Remediation
Enforce minimum TWAP observation windows (30+ minutes for mainnet, longer for L2). Verify token0/token1 ordering dynamically. Validate accumulator initialization before first read. Account for sequencer downtime in TWAP calculations. Bound configuration parameters.
