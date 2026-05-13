## CL-MATH-01: Type Casting Invariant

**Rule:** `EVM-MATH-CAST-01`
**Severity:** low-high

### Description
A contract converts between integer types of different widths (uint256 to uint128/uint96/uint64/uint32/uint8) or between signed and unsigned types (int256 to uint256 or vice versa). Solidity type casts silently truncate values that exceed the target type's range — downcasting a uint256 to uint128 discards the upper 128 bits, converting a negative int256 to uint256 produces a huge positive number, and narrow-type arithmetic overflows before promotion to a wider type. This leads to silent state corruption when balances, timestamps, or prices are truncated, validation bypass when a large value truncates to a small one that passes checks, accounting manipulation when negative values become huge positive values, and DoS when narrow-type arithmetic reverts on overflow.

### Patterns
### Pattern 1: Unsafe Downcasting (uint256 to Smaller Type)
A uint256 value is cast to a narrower type without checking that it fits, silently truncating the upper bits and corrupting the stored value.

**Vulnerable:**
```solidity
contract Staking {
    struct UserInfo {
        uint128 amount;
        uint64 lastClaim;
        uint64 lockEnd;
    }
    mapping(address => UserInfo) public users;

    function stake(uint256 amount) external {
        // BUG: if amount > type(uint128).max, upper bits are silently discarded
        // User stakes 2^128 + 1000 tokens, contract records only 1000
        users[msg.sender].amount += uint128(amount);
        token.transferFrom(msg.sender, address(this), amount); // takes full amount
    }

    function setLockDuration(uint256 duration) external {
        // BUG: block.timestamp + duration can exceed uint64 max
        users[msg.sender].lockEnd = uint64(block.timestamp + duration);
    }
}
```

**Fixed:**
```solidity
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

contract Staking {
    using SafeCast for uint256;

    struct UserInfo {
        uint128 amount;
        uint64 lastClaim;
        uint64 lockEnd;
    }
    mapping(address => UserInfo) public users;

    function stake(uint256 amount) external {
        // Reverts if amount > type(uint128).max
        users[msg.sender].amount += amount.toUint128();
        token.transferFrom(msg.sender, address(this), amount);
    }

    function setLockDuration(uint256 duration) external {
        users[msg.sender].lockEnd = (block.timestamp + duration).toUint64();
    }
}
```

### Pattern 2: Signed-to-Unsigned Conversion of Negative Values
A negative int256 is cast to uint256, producing a huge positive number (two's complement), corrupting balances or bypassing validation.

**Vulnerable:**
```solidity
contract BalanceTracker {
    function applyDelta(uint256 balance, int256 delta) external pure returns (uint256) {
        // BUG: if delta is negative, uint256(delta) wraps to ~2^256 - |delta|
        // balance + uint256(-5) = balance + 2^256 - 5 => overflow or huge value
        return balance + uint256(delta);
    }

    function getAbsoluteValue(int256 value) external pure returns (uint256) {
        // BUG: if value is type(int256).min, -value overflows (no positive equivalent)
        if (value < 0) return uint256(-value); // reverts for int256.min
        return uint256(value);
    }
}
```

**Fixed:**
```solidity
contract BalanceTracker {
    function applyDelta(uint256 balance, int256 delta) external pure returns (uint256) {
        if (delta >= 0) {
            return balance + uint256(delta);
        } else {
            uint256 absDelta = uint256(-delta);
            require(balance >= absDelta, "underflow");
            return balance - absDelta;
        }
    }

    function getAbsoluteValue(int256 value) external pure returns (uint256) {
        if (value == type(int256).min) return uint256(type(int256).max) + 1;
        if (value < 0) return uint256(-value);
        return uint256(value);
    }
}
```

### Pattern 3: Narrow-Type Arithmetic Overflow Before Widening
Arithmetic on small types (uint8, uint16, uint32) overflows within the narrow type before the result is assigned to or used in a wider type.

**Vulnerable:**
```solidity
contract Counter {
    uint8 public count; // max 255

    function increment() external {
        // BUG: reverts when count reaches 255 — permanent DoS
        count += 1;
    }

    function calculateFee(uint32 amount, uint32 multiplier) external pure returns (uint256) {
        // BUG: amount * multiplier overflows uint32 before promotion to uint256
        // e.g., amount=100000, multiplier=100000 => 1e10 > 2^32
        uint256 fee = amount * multiplier;
        return fee;
    }

    function shortTimestamp() external view returns (uint256) {
        uint32 start = uint32(startTime);
        uint32 now32 = uint32(block.timestamp);
        // BUG: now32 - start can underflow if timestamps wrap past uint32 max
        uint32 elapsed = now32 - start;
        return uint256(elapsed) * rewardRate;
    }
}
```

**Fixed:**
```solidity
contract Counter {
    uint256 public count; // use full-width type

    function increment() external {
        count += 1;
    }

    function calculateFee(uint32 amount, uint32 multiplier) external pure returns (uint256) {
        // Widen BEFORE arithmetic
        return uint256(amount) * uint256(multiplier);
    }

    function shortTimestamp() external view returns (uint256) {
        // Use uint256 for all timestamp arithmetic
        uint256 elapsed = block.timestamp - startTime;
        return elapsed * rewardRate;
    }
}
```

### Pattern 4: Truncation in External Call Results
Return values from external calls or ABI decoding are implicitly or explicitly truncated when assigned to narrow storage types, losing significant bits.

**Vulnerable:**
```solidity
contract PriceOracle {
    uint96 public lastPrice;

    function updatePrice() external {
        (, int256 price,,,) = chainlinkFeed.latestRoundData();
        // BUG: Chainlink price can exceed uint96 max for some feeds
        // e.g., ETH/BTC in wei-scale or high-precision feeds
        lastPrice = uint96(uint256(price));
    }

    function getTokenId(address nft, uint256 fullId) external view returns (uint32) {
        // BUG: NFT IDs can exceed uint32 — silently truncated
        return uint32(fullId);
    }
}
```

**Fixed:**
```solidity
contract PriceOracle {
    uint256 public lastPrice; // use full-width for external data

    function updatePrice() external {
        (, int256 price,,,) = chainlinkFeed.latestRoundData();
        require(price > 0, "invalid price");
        lastPrice = uint256(price);
    }
}
```

### Pattern 5: Redundant or Dead Comparisons from Type Limits
Comparing an unsigned integer to a value outside its range creates tautological or dead-code conditions, hiding bugs.

**Vulnerable:**
```solidity
contract Validator {
    function validate(uint256 amount) external pure returns (bool) {
        // BUG: uint256 can never be < 0 — this check always passes
        require(amount >= 0, "negative"); // tautology — dead validation

        // BUG: uint8 can never exceed 255, so this always passes for uint8
        uint8 score = uint8(amount);
        require(score <= 255, "too high"); // always true for uint8

        return true;
    }

    function checkIndex(uint256 index) external pure {
        // BUG: after casting to uint8, large indices wrap and pass the check
        uint8 idx = uint8(index);
        require(idx < 10, "out of bounds"); // index=266 => idx=10... fails
        // But index=256 => idx=0, passes! Silent truncation bypasses validation
    }
}
```

**Fixed:**
```solidity
contract Validator {
    function validate(uint256 amount) external pure returns (bool) {
        require(amount > 0, "zero amount"); // meaningful check
        return true;
    }

    function checkIndex(uint256 index) external pure {
        // Validate BEFORE casting
        require(index < 10, "out of bounds");
        uint8 idx = uint8(index); // safe — value is guaranteed < 10
    }
}
```

### Detect
For every type cast: (1) check if uint256 is downcast to a narrower type without SafeCast or bounds check, (2) check if negative int256 values are cast to uint256, (3) check if arithmetic on narrow types can overflow before widening, (4) check if external return values are truncated on assignment, (5) check for tautological comparisons caused by type-range limits.

### Remediation
Use OpenZeppelin SafeCast for all downcasts. Validate that values fit in the target type before casting. Perform arithmetic in the widest type, then downcast the result. Never cast negative signed integers to unsigned without checking sign. Avoid uint8/uint16/uint32 for values that can grow.

## CL-MATH-02: Division Invariant

**Rule:** `EVM-MATH-DIV-01`
**Severity:** low-critical

### Description
A contract performs division where the denominator is derived from state, user input, or can be zero under certain conditions (empty pools, initial state, edge cases). Division by zero causes a panic revert in Solidity (no graceful error), division-before-multiplication loses precision that cannot be recovered, and unvalidated denominators from dynamic state (totalSupply, array length, elapsed time) reach zero in edge cases. This leads to permanent DoS when a view function or critical state transition diverts through a zero denominator, precision loss from div-before-mul causing material value leak in financial calculations, and incorrect ordering of mul/div operations amplifying truncation errors.

### Patterns
### Pattern 1: Unguarded Division by Zero
A denominator derived from state (totalSupply, array length, time delta, pool balance) can reach zero, causing a panic revert that bricks the function.

**Vulnerable:**
```solidity
contract RewardPool {
    function rewardPerToken() public view returns (uint256) {
        // BUG: reverts with panic if totalStaked == 0
        // Bricks all reward calculations when pool is empty
        return accumulatedReward * PRECISION / totalStaked;
    }

    function averagePrice(uint256[] memory prices) public pure returns (uint256) {
        uint256 sum;
        for (uint256 i = 0; i < prices.length; i++) sum += prices[i];
        // BUG: panic if prices array is empty
        return sum / prices.length;
    }

    function getRate() public view returns (uint256) {
        uint256 elapsed = block.timestamp - lastUpdate;
        // BUG: panic if called in same block as lastUpdate
        return totalAccrued / elapsed;
    }
}
```

**Fixed:**
```solidity
contract RewardPool {
    function rewardPerToken() public view returns (uint256) {
        if (totalStaked == 0) return 0;
        return accumulatedReward * PRECISION / totalStaked;
    }

    function averagePrice(uint256[] memory prices) public pure returns (uint256) {
        require(prices.length > 0, "empty array");
        uint256 sum;
        for (uint256 i = 0; i < prices.length; i++) sum += prices[i];
        return sum / prices.length;
    }

    function getRate() public view returns (uint256) {
        uint256 elapsed = block.timestamp - lastUpdate;
        if (elapsed == 0) return 0;
        return totalAccrued / elapsed;
    }
}
```

### Pattern 2: Division Before Multiplication
Dividing first and multiplying second loses precision from the truncation in the division step. Reordering to multiply first preserves precision.

**Vulnerable:**
```solidity
contract Pricing {
    function calculateOutput(uint256 input, uint256 rate, uint256 fee) public pure returns (uint256) {
        // BUG: division first truncates, then multiplication amplifies the error
        // e.g., input=7, rate=3, fee=2: (7/3)*2 = 2*2 = 4 vs (7*2)/3 = 14/3 = 4
        // But: input=100, rate=3, fee=1000: (100/3)*1000 = 33*1000 = 33000 vs (100*1000)/3 = 33333
        return (input / rate) * fee;
    }

    function vestingAmount(uint256 total, uint256 elapsed, uint256 duration) public pure returns (uint256) {
        // BUG: total/duration truncates first, loses up to (duration-1) wei per second
        return (total / duration) * elapsed;
    }
}
```

**Fixed:**
```solidity
contract Pricing {
    function calculateOutput(uint256 input, uint256 rate, uint256 fee) public pure returns (uint256) {
        // Multiply first, divide second — maximum precision
        return input * fee / rate;
    }

    function vestingAmount(uint256 total, uint256 elapsed, uint256 duration) public pure returns (uint256) {
        return total * elapsed / duration;
    }
}
```

### Pattern 3: Dynamic Denominator Manipulation
A denominator changes between the time a numerator is set and the time division occurs, allowing manipulation of the result through deposits, withdrawals, or other state changes.

**Vulnerable:**
```solidity
contract VaultShares {
    function convertToShares(uint256 assets) public view returns (uint256) {
        // BUG: attacker can inflate totalAssets via donation (direct transfer)
        // before victim's deposit, causing shares to round to zero
        return assets * totalSupply() / totalAssets();
    }

    function claimReward() external {
        // BUG: if totalWeight changes between reward accrual and claim,
        // user gets wrong proportion
        uint256 share = userWeight[msg.sender] * totalReward / totalWeight;
        token.transfer(msg.sender, share);
    }
}
```

**Fixed:**
```solidity
contract VaultShares {
    function convertToShares(uint256 assets) public view returns (uint256) {
        // Virtual shares/assets prevent donation attack (ERC-4626 defense)
        return assets * (totalSupply() + 1) / (totalAssets() + 1);
    }

    function claimReward() external {
        // Snapshot totalWeight at accrual time
        uint256 share = userWeight[msg.sender] * totalReward / snapshotTotalWeight;
        token.transfer(msg.sender, share);
    }
}
```

### Pattern 4: Mismatched Fee/Percentage Divisor
A percentage calculation uses the wrong base (e.g., dividing by 100 instead of 10000 for basis points, or using inconsistent divisors across related calculations).

**Vulnerable:**
```solidity
contract FeeManager {
    uint256 public feeBps = 250; // intended: 2.5%

    function applyFee(uint256 amount) public view returns (uint256) {
        // BUG: divides by 100 instead of 10000
        // 250/100 = 2.5 => but integer = 2, so fee = amount * 2 (200% fee!)
        uint256 fee = amount * feeBps / 100;
        return amount - fee;
    }

    function inverseFee(uint256 netAmount) public view returns (uint256) {
        // BUG: uses 1000 instead of 10000 — inconsistent with applyFee
        return netAmount * 1000 / (1000 - feeBps);
    }
}
```

**Fixed:**
```solidity
contract FeeManager {
    uint256 public feeBps = 250; // 2.5% = 250 basis points
    uint256 constant BPS = 10000;

    function applyFee(uint256 amount) public view returns (uint256) {
        uint256 fee = amount * feeBps / BPS;
        return amount - fee;
    }

    function inverseFee(uint256 netAmount) public view returns (uint256) {
        return netAmount * BPS / (BPS - feeBps);
    }
}
```

### Pattern 5: Unrefunded Division Remainder
An operation divides a total by a unit size (auction lots, token bundles, vesting periods), but the remainder is neither refunded to the user nor accounted for, causing silent fund loss.

**Vulnerable:**
```solidity
contract Auction {
    uint256 public lotSize = 1000;

    function bid(uint256 amount) external {
        uint256 lots = amount / lotSize;
        // BUG: remainder = amount % lotSize is taken from user but not used
        // User sends 2999 tokens, gets credit for 2 lots (2000), loses 999
        token.transferFrom(msg.sender, address(this), amount);
        userLots[msg.sender] += lots;
    }

    function distribute(uint256 total, uint256 interval) external {
        uint256 perPeriod = total / interval;
        // BUG: total % interval is lost
        // total=1000, interval=3: perPeriod=333, distributed=999, lost=1
        for (uint256 i = 0; i < interval; i++) {
            _distribute(perPeriod);
        }
    }
}
```

**Fixed:**
```solidity
contract Auction {
    uint256 public lotSize = 1000;

    function bid(uint256 amount) external {
        uint256 lots = amount / lotSize;
        uint256 cost = lots * lotSize;
        // Only take what's used, refund the rest
        token.transferFrom(msg.sender, address(this), cost);
        userLots[msg.sender] += lots;
    }

    function distribute(uint256 total, uint256 interval) external {
        uint256 perPeriod = total / interval;
        uint256 distributed;
        for (uint256 i = 0; i < interval - 1; i++) {
            _distribute(perPeriod);
            distributed += perPeriod;
        }
        // Last period gets remainder
        _distribute(total - distributed);
    }
}
```

### Detect
For every division operation: (1) verify the denominator cannot be zero under any reachable state, (2) check if division precedes multiplication and could be reordered, (3) verify denominators are not manipulable between related operations, (4) check percentage divisors are consistent (100 vs 1000 vs 10000), (5) verify division remainders are refunded or accounted for.

### Remediation
Always validate denominators are non-zero before division. Reorder arithmetic to multiply before dividing. Use `mulDiv` helpers for combined operations. Handle the zero-denominator edge case explicitly (return 0, revert with message, or use a default). Use consistent BPS constants. Refund or account for division remainders.

## CL-MATH-03: Overflow/Underflow Invariant

**Rule:** `EVM-MATH-OVERFLOW-01`
**Severity:** low-critical

### Description
A contract performs arithmetic operations (addition, subtraction, multiplication) where operands can grow large, wrap around, or where `unchecked` blocks are used for gas optimization. Arithmetic operations exceed the range of their integer type, causing silent wraparound (in `unchecked` blocks or pre-0.8 Solidity) or unexpected reverts (in Solidity 0.8+ checked mode when overflow is intentional, e.g., cumulative counters). This leads to silent overflow corrupting state, enabling validation bypass or fund theft, silent underflow wrapping to `type(uint256).max` to drain funds or break invariants, and unexpected reverts from checked arithmetic on intentional wraps causing permanent DoS.

### Patterns
### Pattern 1: Unchecked Subtraction Underflow
A subtraction in an `unchecked` block where the subtrahend can exceed the minuend, causing wraparound to `type(uint256).max`.

**Vulnerable:**
```solidity
contract Staking {
    mapping(address => uint256) public staked;
    mapping(address => uint256) public rewards;

    function withdraw(uint256 amount) external {
        unchecked {
            // BUG: if amount > staked[msg.sender], wraps to ~2^256
            staked[msg.sender] -= amount;
            // BUG: if rewards < penalty, wraps to ~2^256
            uint256 net = rewards[msg.sender] - penalty;
            token.transfer(msg.sender, net);
        }
    }
}
```

**Fixed:**
```solidity
contract Staking {
    mapping(address => uint256) public staked;
    mapping(address => uint256) public rewards;

    function withdraw(uint256 amount) external {
        require(amount <= staked[msg.sender], "insufficient stake");
        require(rewards[msg.sender] >= penalty, "insufficient rewards");
        staked[msg.sender] -= amount;
        uint256 net = rewards[msg.sender] - penalty;
        token.transfer(msg.sender, net);
    }
}
```

### Pattern 2: Unchecked Accumulation Overflow
A running total (accumulated rewards, cumulative index, total supply tracker) grows without bound in an `unchecked` block, eventually wrapping past `type(uint256).max` and corrupting all dependent calculations.

**Vulnerable:**
```solidity
contract RewardTracker {
    uint256 public cumulativeRewardPerToken;

    function updateReward(uint256 reward) external {
        unchecked {
            // BUG: over time, cumulativeRewardPerToken can overflow
            // All user reward calculations become corrupted
            cumulativeRewardPerToken += reward * PRECISION / totalSupply;
        }
    }

    function claimable(address user) public view returns (uint256) {
        unchecked {
            // If cumulativeRewardPerToken overflowed, this wraps too
            return (cumulativeRewardPerToken - userCheckpoint[user]) * balanceOf[user] / PRECISION;
        }
    }
}
```

**Fixed:**
```solidity
contract RewardTracker {
    uint256 public cumulativeRewardPerToken;

    function updateReward(uint256 reward) external {
        // Let Solidity 0.8+ revert if overflow would occur
        cumulativeRewardPerToken += reward * PRECISION / totalSupply;
    }

    function claimable(address user) public view returns (uint256) {
        // Safe: checkpoint <= cumulative by invariant
        return (cumulativeRewardPerToken - userCheckpoint[user]) * balanceOf[user] / PRECISION;
    }
}
```

### Pattern 3: Checked Arithmetic Blocking Intentional Overflow
Solidity 0.8+ checked arithmetic reverts on overflow, but some patterns (e.g., cumulative counters, timestamp deltas) are designed to wrap. Missing `unchecked` causes permanent DoS.

**Vulnerable:**
```solidity
contract Oracle {
    // Uniswap V2-style cumulative price (designed to overflow)
    uint256 public price0CumulativeLast;

    function update() external {
        uint256 timeElapsed = block.timestamp - blockTimestampLast;
        // BUG: Solidity 0.8+ reverts on overflow
        // Cumulative prices are DESIGNED to overflow and use delta math
        price0CumulativeLast += uint256(UQ112x112.encode(reserve1).uqdiv(reserve0)) * timeElapsed;
        blockTimestampLast = block.timestamp;
    }
}
```

**Fixed:**
```solidity
contract Oracle {
    uint256 public price0CumulativeLast;

    function update() external {
        uint256 timeElapsed = block.timestamp - blockTimestampLast;
        unchecked {
            // Intentional overflow: consumers use (current - previous) delta
            price0CumulativeLast += uint256(UQ112x112.encode(reserve1).uqdiv(reserve0)) * timeElapsed;
        }
        blockTimestampLast = block.timestamp;
    }
}
```

### Pattern 4: Intermediate Multiplication Overflow
Two values are multiplied before dividing, but the intermediate product exceeds `type(uint256).max` even though the final result would fit.

**Vulnerable:**
```solidity
contract PriceCalculator {
    function getPrice(uint256 amount, uint256 price, uint256 decimals) public pure returns (uint256) {
        // BUG: amount * price can overflow uint256 before the division
        // e.g., amount = 1e30, price = 1e30 => product = 1e60 > 2^256
        return amount * price / (10 ** decimals);
    }

    function getReward(uint256 staked, uint256 rewardPerToken) public pure returns (uint256) {
        // BUG: staked * rewardPerToken overflows for large staking pools
        return staked * rewardPerToken / PRECISION;
    }
}
```

**Fixed:**
```solidity
contract PriceCalculator {
    function getPrice(uint256 amount, uint256 price, uint256 decimals) public pure returns (uint256) {
        // Use mulDiv to handle intermediate overflow via 512-bit math
        return FullMath.mulDiv(amount, price, 10 ** decimals);
    }

    function getReward(uint256 staked, uint256 rewardPerToken) public pure returns (uint256) {
        return FullMath.mulDiv(staked, rewardPerToken, PRECISION);
    }
}
```

### Pattern 5: Timestamp/Block Arithmetic Overflow
Arithmetic on `block.timestamp` or `block.number` overflows or underflows due to unchecked subtraction, addition of large durations, or narrow type casting.

**Vulnerable:**
```solidity
contract Vesting {
    function claimable(address user) public view returns (uint256) {
        // BUG: if start is somehow > block.timestamp, underflows
        uint256 elapsed = block.timestamp - vestingStart[user];

        // BUG: endTime can overflow if duration is very large
        uint256 endTime = vestingStart[user] + vestingDuration;

        // BUG: casting to uint32 truncates after year 2106
        uint32 ts = uint32(block.timestamp);
        uint32 delta = ts - uint32(lastClaim[user]); // wraps if lastClaim > ts after truncation
        return staked[user] * delta / vestingDuration;
    }
}
```

**Fixed:**
```solidity
contract Vesting {
    function claimable(address user) public view returns (uint256) {
        if (block.timestamp <= vestingStart[user]) return 0;
        uint256 elapsed = block.timestamp - vestingStart[user];
        if (elapsed > vestingDuration) elapsed = vestingDuration;

        uint256 endTime = vestingStart[user] + vestingDuration;
        require(endTime >= vestingStart[user], "overflow"); // or use SafeMath

        // Use uint256 for timestamps to avoid truncation
        uint256 delta = block.timestamp - lastClaim[user];
        return staked[user] * delta / vestingDuration;
    }
}
```

### Detect
For every arithmetic operation: (1) check if `unchecked` blocks contain subtraction or addition with external/dynamic operands, (2) verify accumulating state variables cannot overflow, (3) check if intentional-wrap patterns are blocked by checked arithmetic, (4) verify intermediate multiplications cannot exceed uint256, (5) check timestamp arithmetic for underflow and narrow-type truncation.

### Remediation
Remove `unchecked` from arithmetic with external inputs. Add explicit bounds checks before unchecked operations. Use `unchecked` only for provably-safe gas optimizations. For intentional wraps (cumulative counters), use unchecked with documented safety. Validate inputs fit within the expected range before arithmetic. Use `mulDiv` for large intermediate products. Validate timestamp ordering before subtraction.

## CL-MATH-04: Rounding Invariant

**Rule:** `EVM-MATH-ROUND-01`
**Severity:** low-critical

### Description
A contract performs integer division, percentage-based fee splits, or pro-rata distribution where the result is used in accounting, transfers, or share calculations. Solidity has no native floating-point, and integer division always truncates toward zero. When rounding direction is not explicitly controlled, value leaks to the wrong party, dust accumulates, or zero-value outputs enable free operations. This leads to fund loss through systematic rounding in favor of the wrong party, protocol insolvency from accumulated dust, fee evasion via small-amount transactions that round to zero, or DoS from underflow when rounding creates accounting mismatches.

### Patterns
### Pattern 1: Round-to-Zero Exploitation
A fee, price, or share calculation produces zero when the input is small relative to the divisor, allowing free minting, zero-fee flash loans, or costless operations.

**Vulnerable:**
```solidity
contract Vault {
    uint256 public totalShares;
    uint256 public totalAssets;

    function deposit(uint256 assets) external returns (uint256 shares) {
        // BUG: For small deposits, assets * totalShares / totalAssets == 0
        // User gets 0 shares but their assets are accepted
        shares = assets * totalShares / totalAssets;
        totalShares += shares;
        totalAssets += assets;
        token.transferFrom(msg.sender, address(this), assets);
    }

    function calculateFee(uint256 amount) public view returns (uint256) {
        // BUG: fee = 0 when amount < 10000 / feeBps
        // e.g., feeBps=30, amount < 334 => fee is zero
        return amount * feeBps / 10000;
    }
}
```

**Fixed:**
```solidity
contract Vault {
    uint256 public totalShares;
    uint256 public totalAssets;
    uint256 constant MIN_DEPOSIT = 1e6;

    function deposit(uint256 assets) external returns (uint256 shares) {
        require(assets >= MIN_DEPOSIT, "below minimum");
        // Round down shares on deposit (protocol-favorable)
        shares = assets * totalShares / totalAssets;
        require(shares > 0, "zero shares");
        totalShares += shares;
        totalAssets += assets;
        token.transferFrom(msg.sender, address(this), assets);
    }

    function calculateFee(uint256 amount) public view returns (uint256) {
        // Round up fees to prevent evasion
        return (amount * feeBps + 9999) / 10000;
    }
}
```

### Pattern 2: Inconsistent Rounding Direction
Deposit and withdrawal (or mint and burn) use the same rounding direction, allowing arbitrage. Or a protocol calculates fees/rewards with rounding that favors users in both directions.

**Vulnerable:**
```solidity
contract LendingPool {
    function deposit(uint256 assets) external returns (uint256 shares) {
        // Rounds DOWN: user gets fewer shares (good for protocol)
        shares = assets * totalShares / totalAssets;
        _mint(msg.sender, shares);
        totalAssets += assets;
    }

    function withdraw(uint256 shares) external returns (uint256 assets) {
        // BUG: Also rounds DOWN: user gets fewer assets (also good for protocol?)
        // Actually: attacker deposits max, then withdraws in small chunks,
        // dust accumulates — but the REAL issue is the asymmetry allows
        // rounding profit by choosing deposit/withdraw sizes strategically
        assets = shares * totalAssets / totalShares;
        _burn(msg.sender, shares);
        totalAssets -= assets;
        token.transfer(msg.sender, assets);
    }

    function borrow(uint256 amount) external {
        // BUG: interest rounds DOWN, borrower pays less than owed
        uint256 interest = amount * rate / 1e18;
        debt[msg.sender] += amount + interest;
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    function deposit(uint256 assets) external returns (uint256 shares) {
        // Round DOWN shares on deposit (fewer shares = protocol-favorable)
        shares = mulDivDown(assets, totalShares, totalAssets);
        _mint(msg.sender, shares);
        totalAssets += assets;
    }

    function withdraw(uint256 shares) external returns (uint256 assets) {
        // Round DOWN assets on withdrawal (less out = protocol-favorable)
        assets = mulDivDown(shares, totalAssets, totalShares);
        _burn(msg.sender, shares);
        totalAssets -= assets;
        token.transfer(msg.sender, assets);
    }

    function borrow(uint256 amount) external {
        // Round UP interest (borrower pays at least the fair amount)
        uint256 interest = mulDivUp(amount, rate, 1e18);
        debt[msg.sender] += amount + interest;
    }
}
```

### Pattern 3: Dust Accumulation in Pro-Rata Distribution
When distributing a total among N recipients using integer division, each share truncates and the sum of distributions is less than the total. Residual dust is permanently trapped.

**Vulnerable:**
```solidity
contract RevenueShare {
    address[] public recipients;
    uint256[] public shares; // basis points, sum = 10000

    function distribute(uint256 total) external {
        // BUG: Each division truncates independently
        // sum of all payments < total, remainder trapped forever
        for (uint256 i = 0; i < recipients.length; i++) {
            uint256 payment = total * shares[i] / 10000;
            token.transfer(recipients[i], payment);
        }
    }
}
```

**Fixed:**
```solidity
contract RevenueShare {
    address[] public recipients;
    uint256[] public shares;

    function distribute(uint256 total) external {
        uint256 distributed;
        for (uint256 i = 0; i < recipients.length - 1; i++) {
            uint256 payment = total * shares[i] / 10000;
            token.transfer(recipients[i], payment);
            distributed += payment;
        }
        // Last recipient gets the remainder — no dust trapped
        token.transfer(recipients[recipients.length - 1], total - distributed);
    }
}
```

### Pattern 4: Precision Loss in Frequent Accrual
Interest, rewards, or fees are accrued in small increments. Each accrual truncates, and over many iterations the cumulative loss is significant compared to a single large calculation.

**Vulnerable:**
```solidity
contract InterestAccrual {
    uint256 public index = 1e18;
    uint256 public ratePerSecond; // e.g., 1e10 (~3.15% APY)

    function accrue() external {
        uint256 elapsed = block.timestamp - lastUpdate;
        // BUG: for small elapsed (1 second), rate * elapsed / PRECISION
        // truncates significantly. Called every block vs. once per day
        // produces materially different results
        uint256 increment = index * ratePerSecond * elapsed / 1e18;
        index += increment;
        lastUpdate = block.timestamp;
    }
}
```

**Fixed:**
```solidity
contract InterestAccrual {
    uint256 public index = 1e27; // Use RAY (27 decimals) for higher precision
    uint256 public ratePerSecond;

    function accrue() external {
        uint256 elapsed = block.timestamp - lastUpdate;
        // Use higher internal precision and compound properly
        // rate = (1 + ratePerSecond)^elapsed via exponentiation
        uint256 compounded = rpow(1e27 + ratePerSecond, elapsed, 1e27);
        index = index * compounded / 1e27;
        lastUpdate = block.timestamp;
    }
}
```

### Pattern 5: Split-Rounding Mismatch (Fee on Parts vs. Whole)
A fee is calculated on individual sub-amounts rather than the aggregate. Each sub-calculation truncates, so total fees collected are less than if calculated on the whole, creating an accounting gap.

**Vulnerable:**
```solidity
contract Splitter {
    uint256 constant FEE_BPS = 30; // 0.3%

    function splitDeposit(uint256 total, uint256 parts) external {
        uint256 perPart = total / parts;
        uint256 totalFee;
        for (uint256 i = 0; i < parts; i++) {
            // BUG: fee on each part truncates independently
            // sum of fees < fee on total
            uint256 fee = perPart * FEE_BPS / 10000;
            totalFee += fee;
            _credit(msg.sender, perPart - fee);
        }
        // totalFee is less than (total * FEE_BPS / 10000)
        // protocol is underpaid
        treasury += totalFee;
    }
}
```

**Fixed:**
```solidity
contract Splitter {
    uint256 constant FEE_BPS = 30;

    function splitDeposit(uint256 total, uint256 parts) external {
        // Calculate fee on the whole amount first
        uint256 totalFee = total * FEE_BPS / 10000;
        uint256 distributable = total - totalFee;
        uint256 perPart = distributable / parts;
        uint256 distributed;
        for (uint256 i = 0; i < parts - 1; i++) {
            _credit(msg.sender, perPart);
            distributed += perPart;
        }
        // Last part gets remainder
        _credit(msg.sender, distributable - distributed);
        treasury += totalFee;
    }
}
```

### Detect
For every integer division, percentage calculation, or pro-rata distribution: (1) check if the result can be zero for valid inputs, (2) verify rounding direction favors the protocol on both sides of a symmetric operation, (3) check for dust accumulation in multi-recipient splits, (4) verify accrual frequency does not cause material precision loss, (5) check if fees calculated on sub-amounts differ from fees on the whole.

### Remediation
Always round against the party who could exploit direction. Use `mulDivUp` / `mulDivDown` explicitly. Enforce minimum amounts to prevent round-to-zero. Use the "remainder to last recipient" pattern for distributions. Ensure deposit/mint rounds up, withdraw/burn rounds down (from protocol's perspective).

## CL-MATH-05: Decimal Scaling Invariant

**Rule:** `EVM-MATH-SCALE-01`
**Severity:** medium-critical

### Description
A contract handles tokens with different decimal precisions, uses hardcoded decimal assumptions, or performs scaling/normalization between different numeric representations (WAD, RAY, basis points, price feeds). EVM tokens have no standard decimal count, and contracts that assume 18 decimals, hardcode scaling factors, or fail to normalize between different precisions produce results that are off by orders of magnitude. Redundant or missing scaling steps compound the error. This leads to critical value corruption: transfers of wrong magnitude (e.g., 1e12x too much or too little), complete protocol insolvency from inflated minting, permanent DoS from overflow when scaling high-decimal tokens, or silent accounting drift from mismatched precision contexts.

### Patterns
### Pattern 1: Hardcoded Decimal Assumption
A contract assumes all tokens have 18 (or 6) decimals and uses hardcoded scaling factors, breaking when tokens with different decimals are used.

**Vulnerable:**
```solidity
contract TokenSale {
    uint256 constant PRICE = 1e18; // "1 token = 1 USD"

    function buy(address token, uint256 usdAmount) external {
        // BUG: assumes token has 18 decimals
        // USDC (6 dec): user sends 1e6 (1 USDC), gets 1e6 * 1e18 / 1e18 = 1e6 tokens
        // But token also has 6 dec, so user should get 1e6 tokens — works by accident
        // WBTC (8 dec): completely broken
        uint256 tokens = usdAmount * 1e18 / PRICE;
        IERC20(token).transfer(msg.sender, tokens);
    }

    function getBalance(address token, address user) public view returns (uint256) {
        // BUG: assumes 18 decimals for "human readable" conversion
        return IERC20(token).balanceOf(user) / 1e18;
    }
}
```

**Fixed:**
```solidity
contract TokenSale {
    uint256 constant INTERNAL_PRECISION = 1e18;

    function buy(address token, uint256 usdAmount) external {
        uint8 dec = IERC20Metadata(token).decimals();
        // Normalize to internal precision, then scale to token decimals
        uint256 tokens = usdAmount * (10 ** dec) / INTERNAL_PRECISION;
        IERC20(token).transfer(msg.sender, tokens);
    }
}
```

### Pattern 2: Missing or Redundant Scaling
A scaling factor is applied when operands are already normalized (redundant), or omitted when operands have different precisions (missing), causing magnitude errors.

**Vulnerable:**
```solidity
contract PriceFeed {
    function getValueInUSD(uint256 tokenAmount, uint256 oraclePrice) external view returns (uint256) {
        uint8 tokenDecimals = 18;
        uint8 oracleDecimals = 8; // Chainlink = 8 decimals

        // BUG: redundant scaling — applies 1e18 when result is already in correct precision
        // tokenAmount (18 dec) * oraclePrice (8 dec) = 26 decimals
        // dividing by 1e8 gives 18 decimals (correct) — but then multiplies by 1e18 (WRONG)
        return tokenAmount * oraclePrice * 1e18 / (10 ** oracleDecimals);
    }

    function convert(uint256 amountA, address tokenA, address tokenB) external view returns (uint256) {
        // BUG: no decimal adjustment between tokens
        // If tokenA=18dec, tokenB=6dec, result is 1e12x too large
        uint256 priceA = oracle.getPrice(tokenA);
        uint256 priceB = oracle.getPrice(tokenB);
        return amountA * priceA / priceB;
    }
}
```

**Fixed:**
```solidity
contract PriceFeed {
    function getValueInUSD(uint256 tokenAmount, uint256 oraclePrice) external view returns (uint256) {
        uint8 oracleDecimals = 8;
        // tokenAmount (18 dec) * oraclePrice (8 dec) / 1e8 = 18 dec result
        return tokenAmount * oraclePrice / (10 ** oracleDecimals);
    }

    function convert(uint256 amountA, address tokenA, address tokenB) external view returns (uint256) {
        uint8 decA = IERC20Metadata(tokenA).decimals();
        uint8 decB = IERC20Metadata(tokenB).decimals();
        uint256 priceA = oracle.getPrice(tokenA);
        uint256 priceB = oracle.getPrice(tokenB);
        // Adjust for decimal difference between tokens
        if (decA >= decB) {
            return amountA * priceA / priceB / (10 ** (decA - decB));
        } else {
            return amountA * priceA * (10 ** (decB - decA)) / priceB;
        }
    }
}
```

### Pattern 3: Decimal Mismatch in Cross-Token Arithmetic
Two token amounts with different decimals are compared, added, or used in the same formula without normalization, producing meaningless results.

**Vulnerable:**
```solidity
contract LiquidityPool {
    function addLiquidity(address tokenA, address tokenB, uint256 amountA, uint256 amountB) external {
        // BUG: comparing raw amounts of tokens with different decimals
        // 1 WBTC (1e8) vs 30000 USDC (3e10) — direct comparison is meaningless
        require(amountA * price(tokenA) == amountB * price(tokenB), "unbalanced");

        // BUG: adding amounts of different-decimal tokens
        totalLiquidity += amountA + amountB; // 1e8 + 3e10 = nonsense
    }

    function checkCollateral(address token, uint256 debt) external view {
        uint256 collateral = IERC20(token).balanceOf(msg.sender);
        // BUG: debt is in 18-decimal internal units, collateral is in token decimals
        require(collateral >= debt * LTV / 100, "undercollateralized");
    }
}
```

**Fixed:**
```solidity
contract LiquidityPool {
    uint256 constant PRECISION = 1e18;

    function addLiquidity(address tokenA, address tokenB, uint256 amountA, uint256 amountB) external {
        uint256 valueA = normalize(tokenA, amountA) * price(tokenA) / PRECISION;
        uint256 valueB = normalize(tokenB, amountB) * price(tokenB) / PRECISION;
        require(valueA == valueB, "unbalanced");
        totalLiquidity += valueA + valueB;
    }

    function normalize(address token, uint256 amount) internal view returns (uint256) {
        uint8 dec = IERC20Metadata(token).decimals();
        if (dec < 18) return amount * (10 ** (18 - dec));
        if (dec > 18) return amount / (10 ** (dec - 18));
        return amount;
    }
}
```

### Pattern 4: Fixed-Point Scaling Mismatch (WAD/RAY Confusion)
Mixing WAD (1e18) and RAY (1e27) arithmetic, or applying the wrong scaling constant in fixed-point multiplication/division, producing results off by 1e9.

**Vulnerable:**
```solidity
contract Interest {
    uint256 constant WAD = 1e18;
    uint256 constant RAY = 1e27;

    function accrueInterest(uint256 principal, uint256 rateRay) external pure returns (uint256) {
        // BUG: principal is in WAD, rate is in RAY, dividing by WAD instead of RAY
        // Result is 1e9x too large
        return principal * rateRay / WAD;
    }

    function compound(uint256 index, uint256 rate) external pure returns (uint256) {
        // BUG: both are RAY but divides by WAD
        return index * rate / WAD; // off by 1e9
    }
}
```

**Fixed:**
```solidity
contract Interest {
    uint256 constant WAD = 1e18;
    uint256 constant RAY = 1e27;

    function accrueInterest(uint256 principal, uint256 rateRay) external pure returns (uint256) {
        // principal (WAD) * rate (RAY) / RAY = result in WAD
        return principal * rateRay / RAY;
    }

    function compound(uint256 index, uint256 rate) external pure returns (uint256) {
        // RAY * RAY / RAY = RAY
        return index * rate / RAY;
    }
}
```

### Pattern 5: Scaling Overflow on High-Decimal Tokens
Normalizing a high-decimal token (e.g., 24 or 27 decimals) by multiplying by a large scaling factor causes uint256 overflow, permanently bricking the contract for that token.

**Vulnerable:**
```solidity
contract Vault {
    function deposit(address token, uint256 amount) external {
        uint8 dec = IERC20Metadata(token).decimals();
        // BUG: if token has 24+ decimals and amount is large,
        // amount * (10 ** (36 - dec)) can overflow uint256
        // e.g., 1e24 amount * 1e12 scaling = 1e36 — close to uint256 max
        uint256 normalized = amount * (10 ** (36 - dec));
        shares[msg.sender] += normalized;
    }

    function convertToShares(uint256 assets, address token) public view returns (uint256) {
        uint8 dec = IERC20Metadata(token).decimals();
        // BUG: hardcoded upscale direction — reverts for tokens with >18 decimals
        return assets * (10 ** (18 - dec)); // underflow in exponent if dec > 18
    }
}
```

**Fixed:**
```solidity
contract Vault {
    uint256 constant INTERNAL_DECIMALS = 18;

    function deposit(address token, uint256 amount) external {
        uint256 normalized = toInternal(token, amount);
        shares[msg.sender] += normalized;
    }

    function toInternal(address token, uint256 amount) internal view returns (uint256) {
        uint8 dec = IERC20Metadata(token).decimals();
        if (dec <= INTERNAL_DECIMALS) {
            return amount * (10 ** (INTERNAL_DECIMALS - dec));
        } else {
            // Scale down for high-decimal tokens (precision loss is acceptable)
            return amount / (10 ** (dec - INTERNAL_DECIMALS));
        }
    }
}
```

### Detect
For every token amount operation: (1) check for hardcoded decimal constants (1e18, 1e6, 1e12), (2) verify scaling factors match the actual token decimals, (3) check for missing normalization in cross-token arithmetic, (4) verify WAD/RAY consistency in fixed-point math, (5) check if scaling can overflow for high-decimal tokens.

### Remediation
Always read `decimals()` dynamically. Normalize all amounts to a common internal precision before arithmetic. Never hardcode `1e18`, `1e6`, or `1e12` as universal scaling factors. Validate that scaling operations cannot overflow. Test with tokens of 2, 6, 8, 18, and 24+ decimals.
