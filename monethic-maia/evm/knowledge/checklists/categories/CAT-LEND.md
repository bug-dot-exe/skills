## CL-LEND-01: Borrow/Repay Accounting Invariant

**Rule:** `EVM-LEND-BORROW-01`
**Severity:** medium-critical

### Description
A lending protocol tracks user debt through shares, indices, or direct balances, and allows borrowing, repayment, and position management operations that must maintain accounting consistency between individual and global state. Debt accounting logic has mismatches between individual and global state updates, missing transfers, incorrect share calculations, dust debt accumulation, unchecked auth on borrow-on-behalf, or cap bypass through alternative entry points. Users can borrow without collateral, repay without transferring tokens, accumulate irrecoverable dust debt, bypass deposit/borrow caps, or have debt assigned without consent.

### Patterns
### Pattern 1: Missing Asset Transfer in Borrow or Repay
The function updates debt accounting but fails to actually transfer tokens—either the borrowed tokens to the user on borrow, or the repayment tokens from the user on repay.

**Vulnerable:**
```solidity
contract LendingPool {
    function repay(uint256 amount) external {
        uint256 debt = getUserDebt(msg.sender);
        uint256 repayAmount = amount > debt ? debt : amount;
        userDebt[msg.sender] -= repayAmount;
        totalBorrows -= repayAmount;
        // BUG: No transferFrom - debt reduced without payment
    }

    function borrow(uint256 amount) external {
        require(isHealthy(msg.sender), "unhealthy");
        userDebt[msg.sender] += amount;
        totalBorrows += amount;
        // BUG: Token transfer missing - user gets debt but no tokens
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    function repay(uint256 amount) external {
        uint256 debt = getUserDebt(msg.sender);
        uint256 repayAmount = amount > debt ? debt : amount;
        IERC20(token).transferFrom(msg.sender, address(this), repayAmount);
        userDebt[msg.sender] -= repayAmount;
        totalBorrows -= repayAmount;
    }

    function borrow(uint256 amount) external {
        require(isHealthy(msg.sender), "unhealthy");
        userDebt[msg.sender] += amount;
        totalBorrows += amount;
        IERC20(token).transfer(msg.sender, amount);
    }
}
```

### Pattern 2: Debt Share Inflation via First-Depositor / Rounding Attack
When the debt share pool is empty or near-empty, an attacker can manipulate the share-to-asset ratio by donating or borrowing a tiny amount, then exploiting rounding to steal from subsequent borrowers.

**Vulnerable:**
```solidity
contract LendingPool {
    uint256 public totalDebtShares;
    uint256 public totalDebt;

    function borrow(uint256 amount) external {
        uint256 shares;
        if (totalDebtShares == 0) {
            shares = amount;
        } else {
            // BUG: Attacker borrows 1 wei, then donates to inflate totalDebt
            // Next borrower's shares = amount * 1 / (1 + donated) = 0
            shares = amount * totalDebtShares / totalDebt;
        }
        require(shares > 0, "zero shares");
        debtShares[msg.sender] += shares;
        totalDebtShares += shares;
        totalDebt += amount;
        IERC20(token).transfer(msg.sender, amount);
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    uint256 public totalDebtShares;
    uint256 public totalDebt;
    uint256 constant INITIAL_SHARES_OFFSET = 1e3; // Virtual offset

    function borrow(uint256 amount) external {
        uint256 shares;
        // Use virtual offset to prevent inflation attack
        shares = amount * (totalDebtShares + INITIAL_SHARES_OFFSET) / (totalDebt + 1);
        require(shares > 0, "zero shares");
        debtShares[msg.sender] += shares;
        totalDebtShares += shares;
        totalDebt += amount;
        IERC20(token).transfer(msg.sender, amount);
    }
}
```

### Pattern 3: Global vs Individual Accounting Drift
Rounding differences between individual debt updates and global totalBorrows cause the sum of individual debts to diverge from the global total over time, leading to either trapped funds or protocol insolvency.

**Vulnerable:**
```solidity
contract LendingPool {
    function repay(uint256 amount) external {
        accrueInterest();
        uint256 debt = userPrincipal[msg.sender] * borrowIndex / userIndex[msg.sender];
        uint256 repayAmount = amount > debt ? debt : amount;
        // BUG: Individual update uses one rounding, global uses another
        uint256 principalReduction = repayAmount * userIndex[msg.sender] / borrowIndex;
        userPrincipal[msg.sender] -= principalReduction;
        // Global uses the raw repayAmount - rounding mismatch
        totalBorrows -= repayAmount;
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    function repay(uint256 amount) external {
        accrueInterest();
        uint256 debt = userPrincipal[msg.sender] * borrowIndex / userIndex[msg.sender];
        uint256 repayAmount = amount > debt ? debt : amount;
        // Consistent: derive global change from individual change
        uint256 principalReduction = repayAmount * userIndex[msg.sender] / borrowIndex;
        userPrincipal[msg.sender] -= principalReduction;
        // Global reduction matches individual
        uint256 globalReduction = principalReduction * borrowIndex / userIndex[msg.sender];
        totalBorrows -= globalReduction;
        userIndex[msg.sender] = borrowIndex;
    }
}
```

### Pattern 4: Unauthenticated Borrow-on-Behalf
The protocol allows borrowing on behalf of another user without their explicit approval, enabling attackers to create unwanted debt positions for victims or front-run repayments with new borrows.

**Vulnerable:**
```solidity
contract LendingPool {
    function borrow(address onBehalfOf, uint256 amount) external {
        // BUG: No authorization check - anyone can create debt for any user
        require(isHealthy(onBehalfOf), "unhealthy");
        userDebt[onBehalfOf] += amount;
        totalBorrows += amount;
        IERC20(token).transfer(msg.sender, amount);
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    mapping(address => mapping(address => bool)) public borrowAllowance;

    function borrow(address onBehalfOf, uint256 amount) external {
        if (msg.sender != onBehalfOf) {
            require(borrowAllowance[onBehalfOf][msg.sender], "not authorized");
        }
        require(isHealthy(onBehalfOf), "unhealthy");
        userDebt[onBehalfOf] += amount;
        totalBorrows += amount;
        IERC20(token).transfer(msg.sender, amount);
    }
}
```

### Pattern 5: Deposit/Borrow Cap Bypass via Alternative Entry Points
The protocol enforces caps on the main `deposit` or `borrow` function but not on alternative paths like `repay` (which adds liquidity), `transfer`, or router/zapper contracts that aggregate operations.

**Vulnerable:**
```solidity
contract LendingPool {
    uint256 public depositCap = 1_000_000e18;

    function deposit(uint256 amount) external {
        require(totalDeposits + amount <= depositCap, "cap exceeded");
        totalDeposits += amount;
        IERC20(token).transferFrom(msg.sender, address(this), amount);
    }

    function repay(uint256 amount) external {
        // BUG: Repayment adds tokens to pool without cap check
        // Overpayment beyond debt becomes a deposit
        uint256 debt = getUserDebt(msg.sender);
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        if (amount > debt) {
            uint256 excess = amount - debt;
            userDebt[msg.sender] = 0;
            totalDeposits += excess; // Bypasses depositCap
        } else {
            userDebt[msg.sender] -= amount;
        }
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    uint256 public depositCap = 1_000_000e18;

    function deposit(uint256 amount) external {
        require(totalDeposits + amount <= depositCap, "cap exceeded");
        totalDeposits += amount;
        IERC20(token).transferFrom(msg.sender, address(this), amount);
    }

    function repay(uint256 amount) external {
        uint256 debt = getUserDebt(msg.sender);
        uint256 repayAmount = amount > debt ? debt : amount;
        IERC20(token).transferFrom(msg.sender, address(this), repayAmount);
        userDebt[msg.sender] -= repayAmount;
        // Excess is returned, not deposited
        if (amount > repayAmount) {
            IERC20(token).transfer(msg.sender, amount - repayAmount);
        }
    }
}
```

### Detect
For every borrow/repay function: (1) verify token transfer matches accounting change, (2) check for share inflation attacks on empty pools, (3) verify global-individual accounting consistency, (4) confirm borrow-on-behalf requires authorization, (5) check all entry points enforce caps.

### Remediation
Ensure: (1) every borrow creates matching debt + transfer, (2) every repay reduces debt + transfers tokens, (3) global and per-user state stay in sync, (4) dust debt is handled, (5) borrow-on-behalf requires authorization.

## CL-LEND-02: Collateral Management Invariant

**Rule:** `EVM-LEND-COLL-01`
**Severity:** medium-critical

### Description
A lending protocol tracks collateral deposits, enforces collateral factors/LTV ratios, and restricts withdrawals based on outstanding debt positions. Collateral logic fails to enforce health checks on all paths that reduce collateral value, allows bypass via unregistered assets or self-backing loops, or permits withdrawal without adequate remaining collateral. Users withdraw collateral while having outstanding debt, create undercollateralized positions, bypass health factor checks through internal transfers, or exploit self-backing loops to borrow without real collateral.

### Patterns
### Pattern 1: Collateral Withdrawal Bypassing Health Check
Internal accounting functions (transfer, burn, redeem) reduce a user's collateral balance without triggering the health factor check, allowing users to become undercollateralized through paths other than the main `withdraw` function.

**Vulnerable:**
```solidity
contract LendingPool {
    function withdraw(uint256 amount) external {
        _updateCollateral(msg.sender, -int256(amount));
        require(isHealthy(msg.sender), "unhealthy"); // Checked here
        IERC20(token).transfer(msg.sender, amount);
    }

    // BUG: Internal transfer reduces sender's collateral without health check
    function transfer(address to, uint256 amount) external returns (bool) {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        // No health check on sender - can transfer collateral out while in debt
        return true;
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    function withdraw(uint256 amount) external {
        _updateCollateral(msg.sender, -int256(amount));
        require(isHealthy(msg.sender), "unhealthy");
        IERC20(token).transfer(msg.sender, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        // Health check on any balance reduction
        if (userDebt[msg.sender] > 0) {
            require(isHealthy(msg.sender), "unhealthy after transfer");
        }
        return true;
    }
}
```

### Pattern 2: Self-Backing Collateralization Loop
A user can use borrowed tokens as collateral for the same or a correlated asset, creating a circular dependency where debt backs itself. This inflates apparent collateral without adding real value.

**Vulnerable:**
```solidity
contract LendingPool {
    function borrow(address asset, uint256 amount) external {
        require(isHealthy(msg.sender), "unhealthy");
        // BUG: No check that borrowed asset != collateral asset
        // User deposits TokenA, borrows TokenA, deposits borrowed TokenA as more collateral
        userDebt[msg.sender][asset] += amount;
        IERC20(asset).transfer(msg.sender, amount);
    }

    function deposit(address asset, uint256 amount) external {
        IERC20(asset).transferFrom(msg.sender, address(this), amount);
        userCollateral[msg.sender][asset] += amount;
        // Borrowed tokens can be re-deposited as collateral
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    function borrow(address asset, uint256 amount) external {
        require(isHealthy(msg.sender), "unhealthy");
        // Prevent borrowing an asset that's used as collateral
        require(!isCollateralEnabled[msg.sender][asset], "cannot borrow collateral asset");
        userDebt[msg.sender][asset] += amount;
        IERC20(asset).transfer(msg.sender, amount);
    }

    function deposit(address asset, uint256 amount) external {
        // Prevent depositing an asset that's currently borrowed
        require(userDebt[msg.sender][asset] == 0, "cannot collateralize borrowed asset");
        IERC20(asset).transferFrom(msg.sender, address(this), amount);
        userCollateral[msg.sender][asset] += amount;
    }
}
```

### Pattern 3: Collateral Bypass via Unregistered or Misconfigured Asset
A user deposits an asset not in the protocol's registered asset list, or one with a missing/zero collateral factor. The system doesn't count it toward collateral but also doesn't prevent withdrawal, allowing debt-free exit.

**Vulnerable:**
```solidity
contract LendingPool {
    mapping(address => AssetConfig) public assetConfigs;

    function enableAsCollateral(address asset) external {
        // BUG: No check that asset is configured or user has balance
        userCollateralEnabled[msg.sender][asset] = true;
    }

    function withdraw(address asset, uint256 amount) external {
        userBalance[msg.sender][asset] -= amount;
        // BUG: If asset has no config, collateral factor is 0
        // Health check passes because this collateral wasn't counted
        require(isHealthy(msg.sender), "unhealthy");
        IERC20(asset).transfer(msg.sender, amount);
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    mapping(address => AssetConfig) public assetConfigs;

    function enableAsCollateral(address asset) external {
        require(assetConfigs[asset].isListed, "asset not listed");
        require(assetConfigs[asset].collateralFactor > 0, "zero CF");
        require(userBalance[msg.sender][asset] > 0, "no balance");
        userCollateralEnabled[msg.sender][asset] = true;
    }

    function withdraw(address asset, uint256 amount) external {
        require(assetConfigs[asset].isListed, "asset not listed");
        userBalance[msg.sender][asset] -= amount;
        require(isHealthy(msg.sender), "unhealthy");
        IERC20(asset).transfer(msg.sender, amount);
    }
}
```

### Pattern 4: Asymmetric Collateral Enforcement Across Operations
The protocol enforces different LTV thresholds or health checks for different operations (borrow vs withdraw vs transfer vs liquidation), creating arbitrage between the inconsistent boundaries.

**Vulnerable:**
```solidity
contract LendingPool {
    uint256 public borrowLTV = 0.75e18;     // 75% for borrowing
    uint256 public liquidationLTV = 0.85e18; // 85% for liquidation

    function borrow(uint256 amount) external {
        userDebt[msg.sender] += amount;
        // Uses borrowLTV
        require(getDebtValue(msg.sender) <= getCollValue(msg.sender) * borrowLTV / 1e18);
        IERC20(token).transfer(msg.sender, amount);
    }

    function withdraw(uint256 amount) external {
        userCollateral[msg.sender] -= amount;
        // BUG: Uses liquidationLTV instead of borrowLTV for withdrawal
        // User can withdraw collateral down to liquidation threshold
        require(getDebtValue(msg.sender) <= getCollValue(msg.sender) * liquidationLTV / 1e18);
        IERC20(collToken).transfer(msg.sender, amount);
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    uint256 public borrowLTV = 0.75e18;
    uint256 public liquidationLTV = 0.85e18;

    function _checkBorrowHealth(address user) internal view {
        require(getDebtValue(user) <= getCollValue(user) * borrowLTV / 1e18, "unhealthy");
    }

    function borrow(uint256 amount) external {
        userDebt[msg.sender] += amount;
        _checkBorrowHealth(msg.sender); // Consistent threshold
        IERC20(token).transfer(msg.sender, amount);
    }

    function withdraw(uint256 amount) external {
        userCollateral[msg.sender] -= amount;
        _checkBorrowHealth(msg.sender); // Same threshold as borrow
        IERC20(collToken).transfer(msg.sender, amount);
    }
}
```

### Detect
For every function that modifies collateral balances: (1) verify health check is enforced, (2) check for self-backing loops, (3) validate asset registration before collateral operations, (4) confirm consistent threshold enforcement across all operations.

### Remediation
Enforce health factor checks on every code path that reduces effective collateral (withdraw, transfer, disable-as-collateral). Validate asset eligibility. Block self-backing. Use consistent LTV across all integrations.

## CL-LEND-03: Solvency / Health Factor Invariant

**Rule:** `EVM-LEND-HEALTH-01`
**Severity:** medium-critical

### Description
A lending protocol maintains solvency through health factor checks, recovery modes, minimum debt thresholds, and bad debt socialization mechanisms that prevent the protocol from becoming insolvent. Solvency logic contains errors in health factor calculation, recovery mode transitions, bad debt handling, fee accounting in solvency checks, or pause-state interactions that allow the protocol to accumulate uncovered debt or prevent necessary protective actions. Protocol becomes insolvent through accumulated bad debt, recovery mode can be manipulated to DoS the system, positions avoid necessary liquidation through health factor miscalculation, or pause states create deadlocks that prevent debt resolution.

### Patterns
### Pattern 1: Double-Counting or Missing Components in Solvency Check
The health factor calculation either double-counts protocol fees as both debt and deductions from available liquidity, or fails to include accrued interest, pending fees, or flash-loan-temporary balances.

**Vulnerable:**
```solidity
contract LendingPool {
    function isHealthy(address user) public view returns (bool) {
        uint256 collValue = getUserCollateralValue(user);
        uint256 debt = userPrincipal[user]; // BUG: Missing accrued interest
        // Also: protocol fees deducted from collateral AND added to debt
        uint256 fees = pendingFees[user];
        uint256 adjustedColl = collValue - fees; // Fees reduce collateral
        uint256 adjustedDebt = debt + fees;       // AND increase debt - double counted
        return adjustedColl * LTV / 1e18 >= adjustedDebt;
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    function isHealthy(address user) public view returns (bool) {
        uint256 collValue = getUserCollateralValue(user);
        // Include ALL debt components: principal + accrued interest + fees
        uint256 totalDebt = getUserDebt(user); // Includes interest
        // Fees are part of debt, not deducted from collateral
        return collValue * LTV / 1e18 >= totalDebt;
    }
}
```

### Pattern 2: Recovery Mode Manipulation
In CDP-like systems, recovery mode activates when the Total Collateral Ratio drops below a threshold. Attackers can manipulate the boundary to force the system into recovery mode (blocking operations) or prevent it from entering recovery mode (allowing risky positions).

**Vulnerable:**
```solidity
contract CDPSystem {
    uint256 public constant RECOVERY_MCR = 1.5e18; // 150%
    uint256 public constant NORMAL_MCR = 1.1e18;   // 110%

    function openPosition(uint256 coll, uint256 debt) external {
        if (isRecoveryMode()) {
            // BUG: In recovery mode, uses RECOVERY_MCR for new positions
            // but any position at 150.01% can open, dragging TCR lower
            require(coll * 1e18 / debt >= RECOVERY_MCR, "below MCR");
        } else {
            require(coll * 1e18 / debt >= NORMAL_MCR, "below MCR");
        }
        // BUG: No check if this operation would push system INTO recovery
        positions[msg.sender] = Position(coll, debt);
        totalColl += coll;
        totalDebt += debt;
    }
}
```

**Fixed:**
```solidity
contract CDPSystem {
    function openPosition(uint256 coll, uint256 debt) external {
        uint256 newTCR = (totalColl + coll) * 1e18 / (totalDebt + debt);
        if (isRecoveryMode()) {
            require(coll * 1e18 / debt >= RECOVERY_MCR, "below MCR");
            // New position must improve or maintain TCR
            require(newTCR >= getTCR(), "would worsen TCR");
        } else {
            require(coll * 1e18 / debt >= NORMAL_MCR, "below MCR");
            // Must not push system into recovery
            require(newTCR >= RECOVERY_MCR, "would trigger recovery");
        }
        positions[msg.sender] = Position(coll, debt);
        totalColl += coll;
        totalDebt += debt;
    }
}
```

### Pattern 3: Bad Debt Socialization Failure
When a position is liquidated but its debt exceeds its collateral (underwater), the resulting bad debt is not properly redistributed to remaining participants, causing a silent insolvency hole in the protocol.

**Vulnerable:**
```solidity
contract LendingPool {
    function liquidate(address borrower) external {
        uint256 debt = getUserDebt(borrower);
        uint256 collValue = getCollateralValue(borrower);

        if (collValue >= debt) {
            // Normal liquidation
            _normalLiquidation(borrower);
        } else {
            // BUG: Bad debt case - debt > collateral
            // Seizes all collateral but doesn't handle remaining debt
            uint256 collateral = userCollateral[borrower];
            userCollateral[borrower] = 0;
            userDebt[borrower] = 0; // Debt wiped without coverage
            totalBorrows -= debt;   // Total reduced but no matching assets
            IERC20(collToken).transfer(msg.sender, collateral);
            // Protocol now has debt - collValue of uncovered liabilities
        }
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    function liquidate(address borrower) external {
        uint256 debt = getUserDebt(borrower);
        uint256 collValue = getCollateralValue(borrower);
        uint256 collateral = userCollateral[borrower];

        userCollateral[borrower] = 0;
        userDebt[borrower] = 0;

        if (collValue >= debt) {
            _normalLiquidation(borrower);
        } else {
            // Bad debt: socialize across all depositors
            uint256 badDebt = debt - collValue;
            // Reduce exchange rate for all depositors proportionally
            totalDeposits -= badDebt;
            totalBorrows -= debt;
            IERC20(collToken).transfer(msg.sender, collateral);
            emit BadDebtSocialized(borrower, badDebt);
        }
    }
}
```

### Pattern 4: Minimum Debt Threshold Absence
Without a minimum debt size, users can create positions with dust-level debt that are economically irrational to liquidate (gas cost > profit), leading to accumulation of small bad-debt positions.

**Vulnerable:**
```solidity
contract LendingPool {
    function borrow(uint256 amount) external {
        // BUG: No minimum borrow amount
        // User borrows 1 wei - costs more gas to liquidate than it's worth
        userDebt[msg.sender] += amount;
        totalBorrows += amount;
        require(isHealthy(msg.sender), "unhealthy");
        IERC20(token).transfer(msg.sender, amount);
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    uint256 public constant MIN_DEBT = 100e18; // Minimum $100 equivalent

    function borrow(uint256 amount) external {
        userDebt[msg.sender] += amount;
        totalBorrows += amount;
        require(userDebt[msg.sender] >= MIN_DEBT, "below min debt");
        require(isHealthy(msg.sender), "unhealthy");
        IERC20(token).transfer(msg.sender, amount);
    }

    function repay(uint256 amount) external {
        uint256 debt = getUserDebt(msg.sender);
        uint256 repayAmount = amount > debt ? debt : amount;
        uint256 remaining = debt - repayAmount;
        // Must either fully repay or leave at least MIN_DEBT
        require(remaining == 0 || remaining >= MIN_DEBT, "dust debt");
        userDebt[msg.sender] -= repayAmount;
        IERC20(token).transferFrom(msg.sender, address(this), repayAmount);
    }
}
```

### Detect
For every solvency-related function: (1) verify health factor includes all debt components without double-counting, (2) check recovery mode transition guards, (3) verify bad debt socialization exists, (4) confirm minimum debt thresholds prevent dust.

### Remediation
Ensure health factor calculation includes all debt components (fees, interest). Implement robust recovery mode with manipulation resistance. Handle bad debt through socialization. Enforce minimum debt thresholds.

## CL-LEND-04: Interest Rate Accrual Invariant

**Rule:** `EVM-LEND-IR-01`
**Severity:** medium-critical

### Description
A lending protocol calculates interest on borrows over time, using either per-block or per-second accrual with a utilization-based rate model. Interest accrual logic contains errors in compounding, truncation, utilization calculation, rate model boundaries, index updates, or timing assumptions that cause incorrect debt growth, zero-interest exploitation, or protocol insolvency. Borrowers pay incorrect interest (too much or too little), lenders receive wrong yield, protocol reserves are drained, or the interest rate model produces absurd rates that break the market.

### Patterns
### Pattern 1: Interest Accrual Truncation to Zero
For small borrows or short time deltas, `interest = principal * rate * dt / PRECISION` truncates to zero due to integer division. Attackers exploit this by making frequent tiny interactions to reset the accrual timestamp without accumulating any interest.

**Vulnerable:**
```solidity
contract LendingPool {
    uint256 public lastAccrualTime;
    uint256 public borrowIndex = 1e18;

    function accrueInterest() public {
        uint256 dt = block.timestamp - lastAccrualTime;
        uint256 rate = getInterestRate();
        // BUG: For small dt or small rate, this truncates to 0
        uint256 interestFactor = rate * dt / SECONDS_PER_YEAR;
        borrowIndex += borrowIndex * interestFactor / 1e18;
        lastAccrualTime = block.timestamp;
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    uint256 public lastAccrualTime;
    uint256 public borrowIndex = 1e18;

    function accrueInterest() public {
        uint256 dt = block.timestamp - lastAccrualTime;
        if (dt == 0) return;
        uint256 rate = getInterestRate();
        // Use higher precision intermediate to prevent truncation
        uint256 interestFactor = rate * dt;
        // Only update if meaningful interest accrued
        uint256 indexDelta = borrowIndex * interestFactor / (SECONDS_PER_YEAR * 1e18);
        if (indexDelta == 0 && interestFactor > 0) {
            // Accumulate sub-precision remainder
            accruedRemainder += borrowIndex * interestFactor;
            indexDelta = accruedRemainder / (SECONDS_PER_YEAR * 1e18);
            accruedRemainder %= (SECONDS_PER_YEAR * 1e18);
        }
        borrowIndex += indexDelta;
        lastAccrualTime = block.timestamp;
    }
}
```

### Pattern 2: Non-Compounding (Simple) Interest Instead of Compound
The protocol calculates `interest = principal * rate * time` (simple interest) instead of compounding, causing systematic underpayment to lenders. Alternatively, it compounds per-call instead of per-second, making interest path-dependent.

**Vulnerable:**
```solidity
contract LendingPool {
    function accrueInterest() public {
        uint256 dt = block.timestamp - lastAccrualTime;
        uint256 rate = getInterestRate();
        // BUG: Simple interest - does not compound
        uint256 interest = totalBorrows * rate * dt / (SECONDS_PER_YEAR * 1e18);
        totalBorrows += interest;
        totalReserves += interest * reserveFactor / 1e18;
        lastAccrualTime = block.timestamp;
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    function accrueInterest() public {
        uint256 dt = block.timestamp - lastAccrualTime;
        if (dt == 0) return;
        uint256 rate = getInterestRate();
        // Compound interest using exponentiation
        uint256 compoundFactor = _rpow(1e18 + rate / SECONDS_PER_YEAR, dt, 1e18);
        uint256 newTotalBorrows = totalBorrows * compoundFactor / 1e18;
        uint256 interestAccrued = newTotalBorrows - totalBorrows;
        totalBorrows = newTotalBorrows;
        totalReserves += interestAccrued * reserveFactor / 1e18;
        borrowIndex = borrowIndex * compoundFactor / 1e18;
        lastAccrualTime = block.timestamp;
    }
}
```

### Pattern 3: Utilization Rate Miscalculation
The utilization formula incorrectly subtracts reserves from cash, includes unredeemable debt, uses wrong decimals, or produces values > 100%, causing the interest rate model to output incorrect rates.

**Vulnerable:**
```solidity
contract InterestRateModel {
    function getUtilization(uint256 cash, uint256 borrows, uint256 reserves) public pure returns (uint256) {
        if (borrows == 0) return 0;
        // BUG: Subtracting reserves from denominator inflates utilization
        // Can produce utilization > 100% if reserves > cash
        return borrows * 1e18 / (cash + borrows - reserves);
    }
}
```

**Fixed:**
```solidity
contract InterestRateModel {
    function getUtilization(uint256 cash, uint256 borrows, uint256 reserves) public pure returns (uint256) {
        if (borrows == 0) return 0;
        uint256 totalAssets = cash + borrows;
        if (totalAssets == 0) return 0;
        uint256 util = borrows * 1e18 / totalAssets;
        // Cap at 100% to prevent rate model explosion
        return util > 1e18 ? 1e18 : util;
    }
}
```

### Pattern 4: Stale Interest Index Before State-Changing Operation
A borrow, repay, withdraw, liquidation, or any other state-changing function reads the borrow index without first calling `accrueInterest()`, using a stale value to calculate debt. This under/over-counts interest since the last accrual. Particularly dangerous in liquidation paths where stale indices can make positions appear healthy when they are actually underwater, or vice versa.

**Vulnerable:**
```solidity
contract LendingPool {
    function repay(uint256 amount) external {
        // BUG: No accrueInterest() call - uses stale borrowIndex
        uint256 currentDebt = userPrincipal[msg.sender] * borrowIndex / userBorrowIndex[msg.sender];
        require(amount <= currentDebt, "overpay");
        userPrincipal[msg.sender] -= amount * userBorrowIndex[msg.sender] / borrowIndex;
        totalBorrows -= amount;
        IERC20(token).transferFrom(msg.sender, address(this), amount);
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    function repay(uint256 amount) external {
        accrueInterest(); // Fresh index
        uint256 currentDebt = userPrincipal[msg.sender] * borrowIndex / userBorrowIndex[msg.sender];
        require(amount <= currentDebt, "overpay");
        userPrincipal[msg.sender] -= amount * userBorrowIndex[msg.sender] / borrowIndex;
        totalBorrows -= amount;
        IERC20(token).transferFrom(msg.sender, address(this), amount);
    }
}
```

### Pattern 5: Interest Accrual During Pause State
When the protocol is paused, interest continues accruing but users cannot repay or add collateral. This creates unfair debt growth during the pause window and can push positions underwater without recourse.

**Vulnerable:**
```solidity
contract LendingPool {
    bool public paused;

    function repay(uint256 amount) external whenNotPaused { /* ... */ }

    // BUG: Interest accrual continues during pause
    function accrueInterest() public {
        // No pause check - debt grows while repayment is frozen
        uint256 dt = block.timestamp - lastAccrualTime;
        borrowIndex += borrowIndex * rate * dt / (SECONDS_PER_YEAR * 1e18);
        lastAccrualTime = block.timestamp;
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    bool public paused;

    function repay(uint256 amount) external {
        // Repayment always allowed - users should always be able to reduce risk
        accrueInterest();
        _repay(msg.sender, amount);
    }

    function accrueInterest() public {
        // Skip accrual during pause to prevent unfair debt growth
        if (paused) return;
        uint256 dt = block.timestamp - lastAccrualTime;
        borrowIndex += borrowIndex * rate * dt / (SECONDS_PER_YEAR * 1e18);
        lastAccrualTime = block.timestamp;
    }
}
```

### Pattern 6: Hardcoded Block Time or Incorrect Time Constants
Interest rate models assume a fixed block time (e.g., 12s or 15s) that differs from actual block production, or use incorrect constants for seconds-per-year, causing systematic rate errors across all positions.

**Vulnerable:**
```solidity
contract InterestRateModel {
    // BUG: Assumes 15-second blocks (Ethereum pre-merge)
    // Post-merge blocks are 12 seconds
    uint256 public constant BLOCKS_PER_YEAR = 2_102_400; // 365.25 * 24 * 3600 / 15

    function getSupplyRate(uint256 util) external view returns (uint256) {
        uint256 annualRate = baseRate + util * multiplier / 1e18;
        return annualRate / BLOCKS_PER_YEAR;
    }
}
```

**Fixed:**
```solidity
contract InterestRateModel {
    // Use per-second rates instead of per-block
    uint256 public constant SECONDS_PER_YEAR = 365.25 days;

    function getSupplyRate(uint256 util) external view returns (uint256) {
        uint256 annualRate = baseRate + util * multiplier / 1e18;
        return annualRate / SECONDS_PER_YEAR;
    }
}
```

### Detect
For every interest-related function: (1) verify accrual doesn't truncate to zero, (2) check compounding vs simple interest, (3) validate utilization formula (no >100%, correct reserves handling), (4) confirm accrueInterest() called before all state changes including liquidation, (5) verify interest accrual halts during pause states, (6) verify time constants match chain reality.

### Remediation
Ensure interest: (1) compounds correctly (not simple), (2) never truncates to zero for small amounts, (3) uses correct utilization formula, (4) caps rates at sane bounds, (5) accrues before every state-changing operation including liquidation, (6) halts accrual during pause states.

## CL-LEND-05: Liquidation Mechanism Invariant

**Rule:** `EVM-LEND-LIQ-01`
**Severity:** medium-critical

### Description
A lending protocol implements liquidation logic where underwater positions (debt > collateral * threshold) can be seized by liquidators in exchange for repaying part or all of the borrower's debt. Liquidation functions contain logic errors in threshold checks, state updates, incentive calculations, access control, or ordering that allow positions to avoid liquidation, enable self-liquidation profit extraction, cause DoS, or leave the protocol with bad debt. Bad debt accumulates in the protocol, liquidators are not incentivized, positions become permanently stuck, or attackers extract value through self-liquidation or liquidation manipulation.

### Patterns
### Pattern 1: Missing or Incomplete State Update on Liquidation
The liquidation function decrements the borrower's debt and collateral but fails to update global state variables (total borrows, total collateral, total supply), causing protocol-level accounting drift.

**Vulnerable:**
```solidity
contract LendingPool {
    uint256 public totalBorrows;
    uint256 public totalCollateral;
    mapping(address => uint256) public userDebt;
    mapping(address => uint256) public userCollateral;

    function liquidate(address borrower, uint256 repayAmount) external {
        require(isUnderwater(borrower), "healthy");
        uint256 seizeAmount = repayAmount * liquidationBonus / 1e18;

        userDebt[borrower] -= repayAmount;
        userCollateral[borrower] -= seizeAmount;
        // BUG: totalBorrows and totalCollateral not updated
        // Protocol accounting drifts from reality

        IERC20(debtToken).transferFrom(msg.sender, address(this), repayAmount);
        IERC20(collToken).transfer(msg.sender, seizeAmount);
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    uint256 public totalBorrows;
    uint256 public totalCollateral;
    mapping(address => uint256) public userDebt;
    mapping(address => uint256) public userCollateral;

    function liquidate(address borrower, uint256 repayAmount) external {
        require(isUnderwater(borrower), "healthy");
        uint256 seizeAmount = repayAmount * liquidationBonus / 1e18;

        userDebt[borrower] -= repayAmount;
        userCollateral[borrower] -= seizeAmount;
        totalBorrows -= repayAmount;
        totalCollateral -= seizeAmount;

        IERC20(debtToken).transferFrom(msg.sender, address(this), repayAmount);
        IERC20(collToken).transfer(msg.sender, seizeAmount);
    }
}
```

### Pattern 2: Self-Liquidation Profit Extraction
The protocol allows a borrower to liquidate their own position, capturing the liquidation bonus that should incentivize external actors. Trivially bypassed when the only check is `msg.sender != borrower` by using a proxy contract.

**Vulnerable:**
```solidity
contract LendingPool {
    function liquidate(address borrower, uint256 repayAmount) external {
        // BUG: No self-liquidation check, or only checks msg.sender
        // Attacker uses a proxy contract to bypass msg.sender check
        require(isUnderwater(borrower), "healthy");
        uint256 bonus = repayAmount * LIQUIDATION_BONUS / 1e18;
        uint256 seizeAmount = repayAmount + bonus;

        userDebt[borrower] -= repayAmount;
        userCollateral[borrower] -= seizeAmount;

        IERC20(debtToken).transferFrom(msg.sender, address(this), repayAmount);
        IERC20(collToken).transfer(msg.sender, seizeAmount);
        // Attacker profits: seizeAmount - repayAmount = bonus
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    function liquidate(address borrower, uint256 repayAmount) external {
        require(isUnderwater(borrower), "healthy");
        // Check both msg.sender and tx.origin to prevent proxy bypass
        require(msg.sender != borrower && tx.origin != borrower, "no self-liquidation");

        uint256 bonus = repayAmount * LIQUIDATION_BONUS / 1e18;
        uint256 seizeAmount = repayAmount + bonus;

        userDebt[borrower] -= repayAmount;
        userCollateral[borrower] -= seizeAmount;

        IERC20(debtToken).transferFrom(msg.sender, address(this), repayAmount);
        IERC20(collToken).transfer(msg.sender, seizeAmount);
    }
}
```

### Pattern 3: Liquidation Incentive Inadequacy or Absence
The protocol either provides no liquidation bonus, sets it too low to cover gas costs, or has an uncapped bonus that can exceed the collateral ratio—making liquidation unprofitable for small positions or allowing protocol insolvency for large ones.

**Vulnerable:**
```solidity
contract LendingPool {
    uint256 public liquidationBonus = 1e18; // 100% = no bonus at all

    function liquidate(address borrower, uint256 repayAmount) external {
        require(isUnderwater(borrower), "healthy");
        // BUG: seizeAmount == repayAmount, no incentive for liquidator
        uint256 seizeAmount = repayAmount * liquidationBonus / 1e18;

        userDebt[borrower] -= repayAmount;
        userCollateral[borrower] -= seizeAmount;

        IERC20(debtToken).transferFrom(msg.sender, address(this), repayAmount);
        IERC20(collToken).transfer(msg.sender, seizeAmount);
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    uint256 public constant MIN_BONUS = 1.02e18;  // 2% minimum
    uint256 public constant MAX_BONUS = 1.15e18;  // 15% maximum
    uint256 public liquidationBonus = 1.05e18;     // 5% default

    function setLiquidationBonus(uint256 _bonus) external onlyOwner {
        require(_bonus >= MIN_BONUS && _bonus <= MAX_BONUS, "out of range");
        liquidationBonus = _bonus;
    }

    function liquidate(address borrower, uint256 repayAmount) external {
        require(isUnderwater(borrower), "healthy");
        uint256 seizeAmount = repayAmount * liquidationBonus / 1e18;
        require(seizeAmount <= userCollateral[borrower], "insufficient collateral");

        userDebt[borrower] -= repayAmount;
        userCollateral[borrower] -= seizeAmount;

        IERC20(debtToken).transferFrom(msg.sender, address(this), repayAmount);
        IERC20(collToken).transfer(msg.sender, seizeAmount);
    }
}
```

### Pattern 4: Liquidation DoS via Pause, Config, or Loop Revert
Liquidation is blocked by: (1) pausing that freezes both deposits and liquidations together, (2) missing asset configuration preventing collateral seizure, (3) loop over assets where one reverting token blocks the entire liquidation, or (4) front-running that resets liquidation eligibility.

**Vulnerable:**
```solidity
contract LendingPool {
    bool public paused;

    modifier whenNotPaused() { require(!paused, "paused"); _; }

    // BUG: Liquidation shares the same pause as deposits/borrows
    function liquidate(address borrower, uint256 repayAmount) external whenNotPaused {
        require(isUnderwater(borrower), "healthy");
        _executeLiquidation(borrower, repayAmount);
    }

    function _liquidateMultiCollateral(address borrower) internal {
        address[] memory assets = getUserAssets(borrower);
        for (uint i = 0; i < assets.length; i++) {
            // BUG: If any asset transfer reverts, entire liquidation fails
            IERC20(assets[i]).transfer(msg.sender, seizeAmounts[i]);
        }
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    bool public depositsPaused;
    bool public liquidationsPaused; // Separate pause for liquidations

    function liquidate(address borrower, uint256 repayAmount) external {
        require(!liquidationsPaused, "liquidations paused");
        require(isUnderwater(borrower), "healthy");
        _executeLiquidation(borrower, repayAmount);
    }

    function _liquidateMultiCollateral(address borrower) internal {
        address[] memory assets = getUserAssets(borrower);
        for (uint i = 0; i < assets.length; i++) {
            // Try-catch prevents one bad asset from blocking liquidation
            try IERC20(assets[i]).transfer(msg.sender, seizeAmounts[i]) {
            } catch {
                emit LiquidationAssetSkipped(borrower, assets[i]);
            }
        }
    }
}
```

### Detect
For every liquidation function: (1) verify all global and per-user state is updated, (2) check self-liquidation is blocked including proxy bypass, (3) verify liquidation bonus is bounded and profitable, (4) confirm liquidation cannot be DoS'd by pause/config/loop.

### Remediation
Ensure liquidation: (1) correctly checks health factor before and after, (2) updates all global and per-user state atomically, (3) provides adequate incentive, (4) blocks self-liquidation, (5) handles partial liquidation correctly without leaving dust.

## CL-LEND-06: Parameter Validation Invariant

**Rule:** `EVM-LEND-PARAM-01`
**Severity:** low-high

### Description
A lending protocol exposes administrative functions to set economic parameters such as interest rate multipliers, collateral factors, liquidation bonuses, fee rates, and caps that govern market behavior. Administrative setter functions lack upper/lower bound validation, relational constraints between parameters, range consistency checks, or initialization guards, allowing parameters to be set to values that break protocol invariants. Misconfigured parameters cause interest rates to exceed 100%, collateral factors to exceed 1.0, liquidation bonuses to exceed collateral ratios, fee rates to drain all user funds, or caps to be trivially bypassed.

### Patterns
### Pattern 1: Missing Upper/Lower Bounds on Economic Parameters
Admin functions accept any value for critical parameters like interest rate multipliers, fee rates, or BPS values without checking they fall within sane ranges.

**Vulnerable:**
```solidity
contract LendingPool {
    uint256 public interestRateMultiplier;
    uint256 public protocolFeeBps;
    uint256 public collateralFactor;

    function setInterestMultiplier(uint256 _multiplier) external onlyOwner {
        // BUG: No upper bound - can set to absurd values
        interestRateMultiplier = _multiplier;
    }

    function setProtocolFee(uint256 _feeBps) external onlyOwner {
        // BUG: No max check - could set to 10000 (100%) or higher
        protocolFeeBps = _feeBps;
    }

    function setCollateralFactor(uint256 _factor) external onlyOwner {
        // BUG: Could set > 1e18 meaning users borrow more than collateral
        collateralFactor = _factor;
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    uint256 public constant MAX_INTEREST_MULTIPLIER = 2e18;
    uint256 public constant MAX_FEE_BPS = 2000; // 20%
    uint256 public constant MAX_COLLATERAL_FACTOR = 0.9e18; // 90%

    function setInterestMultiplier(uint256 _multiplier) external onlyOwner {
        require(_multiplier > 0 && _multiplier <= MAX_INTEREST_MULTIPLIER, "out of range");
        interestRateMultiplier = _multiplier;
    }

    function setProtocolFee(uint256 _feeBps) external onlyOwner {
        require(_feeBps <= MAX_FEE_BPS, "fee too high");
        protocolFeeBps = _feeBps;
    }

    function setCollateralFactor(uint256 _factor) external onlyOwner {
        require(_factor > 0 && _factor <= MAX_COLLATERAL_FACTOR, "invalid CF");
        collateralFactor = _factor;
    }
}
```

### Pattern 2: Missing Relational Constraints Between Parameters
Parameters that must maintain relationships (liquidation threshold > borrow LTV, max rate > base rate, close factor < 100%) are validated independently, allowing inversions.

**Vulnerable:**
```solidity
contract LendingPool {
    uint256 public borrowLTV;
    uint256 public liquidationThreshold;
    uint256 public liquidationBonus;

    function setBorrowLTV(uint256 _ltv) external onlyOwner {
        require(_ltv <= 1e18, "too high");
        borrowLTV = _ltv;
        // BUG: No check that borrowLTV < liquidationThreshold
    }

    function setLiquidationThreshold(uint256 _threshold) external onlyOwner {
        require(_threshold <= 1e18, "too high");
        liquidationThreshold = _threshold;
        // BUG: No check that liquidationThreshold + bonus <= 100%
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    function setBorrowLTV(uint256 _ltv) external onlyOwner {
        require(_ltv <= 1e18, "too high");
        require(_ltv < liquidationThreshold, "LTV must be < liq threshold");
        borrowLTV = _ltv;
    }

    function setLiquidationThreshold(uint256 _threshold) external onlyOwner {
        require(_threshold <= 1e18, "too high");
        require(_threshold > borrowLTV, "must be > borrow LTV");
        require(_threshold + liquidationBonus <= 1e18, "threshold + bonus > 100%");
        liquidationThreshold = _threshold;
    }

    function setLiquidationBonus(uint256 _bonus) external onlyOwner {
        require(liquidationThreshold + _bonus <= 1e18, "would exceed 100%");
        liquidationBonus = _bonus;
    }
}
```

### Pattern 3: Uninitialized or Zero-Default Parameter Exploitation
Critical parameters default to zero in Solidity storage. If not explicitly initialized, they cause division by zero, skip critical checks, or disable security mechanisms entirely.

**Vulnerable:**
```solidity
contract LendingPool {
    uint256 public maxLTV; // Defaults to 0 if not initialized
    uint256 public minDebt; // Defaults to 0

    function borrow(uint256 amount) external {
        userDebt[msg.sender] += amount;
        // BUG: If maxLTV == 0, this always passes (0 >= anything is false)
        // Actually: debt <= collateral * 0 / 1e18 = 0, so blocks all borrows
        // OR if check is inverted: always allows borrows
        require(getUserDebt(msg.sender) <= getCollValue(msg.sender) * maxLTV / 1e18);

        // BUG: minDebt == 0 means dust positions are allowed
        require(userDebt[msg.sender] >= minDebt);
        IERC20(token).transfer(msg.sender, amount);
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    uint256 public maxLTV;
    uint256 public minDebt;
    bool public initialized;

    function initialize(uint256 _maxLTV, uint256 _minDebt) external onlyOwner {
        require(!initialized, "already init");
        require(_maxLTV > 0 && _maxLTV <= 0.9e18, "invalid LTV");
        require(_minDebt > 0, "invalid min debt");
        maxLTV = _maxLTV;
        minDebt = _minDebt;
        initialized = true;
    }

    function borrow(uint256 amount) external {
        require(initialized, "not initialized");
        userDebt[msg.sender] += amount;
        require(getUserDebt(msg.sender) <= getCollValue(msg.sender) * maxLTV / 1e18);
        require(userDebt[msg.sender] >= minDebt);
        IERC20(token).transfer(msg.sender, amount);
    }
}
```

### Pattern 4: Retroactive Parameter Change Affecting Existing Positions
Changing a global parameter (interest rate, collateral factor, liquidation threshold) immediately affects all existing positions, potentially making healthy positions instantly liquidatable or unlocking excess borrowing capacity.

**Vulnerable:**
```solidity
contract LendingPool {
    function setCollateralFactor(address asset, uint256 newCF) external onlyOwner {
        // BUG: Instantly reduces collateral value for all existing positions
        // Users who were healthy at CF=80% become underwater at CF=50%
        assetConfig[asset].collateralFactor = newCF;
        // No grace period, no gradual transition
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    struct PendingChange {
        uint256 newValue;
        uint256 effectiveTime;
    }
    mapping(address => PendingChange) public pendingCFChanges;
    uint256 public constant TIMELOCK = 48 hours;

    function proposeCollateralFactor(address asset, uint256 newCF) external onlyOwner {
        require(newCF > 0 && newCF <= MAX_CF, "invalid CF");
        // Only allow gradual decreases
        if (newCF < assetConfig[asset].collateralFactor) {
            pendingCFChanges[asset] = PendingChange(newCF, block.timestamp + TIMELOCK);
            emit CFChangeProposed(asset, newCF, block.timestamp + TIMELOCK);
        } else {
            // Increases are safe - can apply immediately
            assetConfig[asset].collateralFactor = newCF;
        }
    }

    function executeCollateralFactor(address asset) external {
        PendingChange memory change = pendingCFChanges[asset];
        require(change.effectiveTime > 0 && block.timestamp >= change.effectiveTime);
        assetConfig[asset].collateralFactor = change.newValue;
        delete pendingCFChanges[asset];
    }
}
```

### Detect
For every admin setter function: (1) verify absolute bounds on each parameter, (2) check relational constraints between dependent parameters, (3) verify initialization guards, (4) check for retroactive impact on existing positions and timelock protection.

### Remediation
Validate all parameters against absolute bounds and relative constraints. Enforce relational invariants (e.g., liquidation threshold > collateral factor). Guard against uninitialized state. Use timelocks for sensitive changes.

## CL-LEND-07: Rounding / Precision Invariant

**Rule:** `EVM-LEND-ROUND-01`
**Severity:** low-high

### Description
A lending protocol performs division operations for share conversions, collateral calculations, interest accrual, debt distribution, or redemption amounts where integer math produces truncation. Rounding direction favors the wrong party (user vs protocol), rounding differences between related calculations cause accounting drift, or precision loss enables extraction through repeated micro-operations. Users extract value through rounding in their favor on each operation, protocol slowly leaks value through systematic rounding errors, dust positions accumulate that cannot be closed, or share inflation attacks drain depositor funds.

### Patterns
### Pattern 1: Rounding Direction Favoring User Over Protocol
Division rounds down by default in Solidity. When calculating collateral requirements, debt values, or liquidation amounts, rounding down favors the borrower/withdrawer rather than the protocol.

**Vulnerable:**
```solidity
contract LendingPool {
    function getCollateralRequired(uint256 borrowAmount) public view returns (uint256) {
        // BUG: Rounds DOWN - user provides less collateral than needed
        return borrowAmount * 1e18 / collateralFactor;
    }

    function getLiquidationSeize(uint256 repayAmount) public view returns (uint256) {
        // BUG: Rounds DOWN - liquidator gets less, borrower keeps dust
        return repayAmount * liquidationBonus / 1e18;
    }

    function getRedeemAmount(uint256 shares) public view returns (uint256) {
        // BUG: Rounds DOWN on redeem - fine for withdrawals
        // But for share price calc, can be exploited
        return shares * totalAssets() / totalShares;
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    function getCollateralRequired(uint256 borrowAmount) public view returns (uint256) {
        // Round UP - require slightly more collateral
        return (borrowAmount * 1e18 + collateralFactor - 1) / collateralFactor;
    }

    function getLiquidationSeize(uint256 repayAmount) public view returns (uint256) {
        // Round UP - liquidator gets full incentive
        return (repayAmount * liquidationBonus + 1e18 - 1) / 1e18;
    }

    function getRedeemAmount(uint256 shares) public view returns (uint256) {
        // Round DOWN on redeem (favor protocol)
        return shares * totalAssets() / totalShares;
    }

    function getDepositShares(uint256 assets) public view returns (uint256) {
        // Round DOWN on deposit (favor protocol)
        return assets * totalShares / totalAssets();
    }
}
```

### Pattern 2: Accounting Drift from Asymmetric Rounding
Two related calculations (e.g., individual debt update and global debt update, or debt shares and collateral shares) use different rounding, causing their totals to diverge over time.

**Vulnerable:**
```solidity
contract LendingPool {
    function redistribute(uint256 debt, uint256 collateral) internal {
        uint256 numPositions = activePositions.length;
        for (uint i = 0; i < numPositions; i++) {
            // BUG: Each individual addition rounds down
            // Sum of individual shares < total being distributed
            uint256 debtShare = debt / numPositions;
            uint256 collShare = collateral / numPositions;
            positions[activePositions[i]].debt += debtShare;
            positions[activePositions[i]].coll += collShare;
        }
        // Dust remains: debt % numPositions lost
        totalDebt += debt;  // But global tracks full amount
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    function redistribute(uint256 debt, uint256 collateral) internal {
        uint256 numPositions = activePositions.length;
        uint256 debtDistributed;
        uint256 collDistributed;
        for (uint i = 0; i < numPositions; i++) {
            uint256 debtShare;
            if (i == numPositions - 1) {
                // Last position gets remainder
                debtShare = debt - debtDistributed;
            } else {
                debtShare = debt / numPositions;
            }
            positions[activePositions[i]].debt += debtShare;
            debtDistributed += debtShare;
            // Same for collateral...
        }
        totalDebt += debt;
    }
}
```

### Pattern 3: Micro-Operation Value Extraction
An attacker performs many tiny operations where each one rounds in their favor by 1 wei, extracting cumulative value. Common in deposit/withdraw cycles, interest compounding by dust redemption, or repeated partial liquidations.

**Vulnerable:**
```solidity
contract LendingPool {
    function withdraw(uint256 shares) external returns (uint256 assets) {
        // Each withdrawal: assets = shares * totalAssets / totalShares
        // For 1 share: may round up to get 1 more wei than fair share
        assets = (shares * totalAssets() + totalShares - 1) / totalShares;
        // BUG: Rounding UP on withdrawal favors withdrawer
        totalShareSupply -= shares;
        userShares[msg.sender] -= shares;
        IERC20(token).transfer(msg.sender, assets);
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    uint256 public constant MIN_WITHDRAWAL = 100; // Minimum withdrawal amount

    function withdraw(uint256 shares) external returns (uint256 assets) {
        require(shares >= MIN_WITHDRAWAL, "below minimum");
        // Round DOWN on withdrawal (favor protocol)
        assets = shares * totalAssets() / totalShares;
        totalShareSupply -= shares;
        userShares[msg.sender] -= shares;
        IERC20(token).transfer(msg.sender, assets);
    }
}
```

### Pattern 4: Interest-Bearing Token Exchange Rate Precision Loss
When converting between interest-bearing tokens (cTokens, aTokens) and underlying assets, the growing exchange rate causes precision issues where the conversion back doesn't match the original amount.

**Vulnerable:**
```solidity
contract LendingPool {
    function redeemAndSwap(uint256 cTokenAmount, uint256 minOut) external {
        uint256 underlyingAmount = cToken.redeem(cTokenAmount);
        // BUG: underlyingAmount != cTokenAmount * exchangeRate / 1e18
        // due to rounding in the cToken contract
        // Swap expects exact amount but gets slightly different
        router.swap(underlying, underlyingAmount, minOut);
    }

    function migrateLoan(uint256 amount) external {
        // BUG: Flash loan fee + swap slippage erodes collateral
        // but LTV check uses pre-migration collateral value
        uint256 flashAmount = flashLoan(amount);
        uint256 afterFees = flashAmount - flashFee;
        uint256 afterSlippage = swap(afterFees); // Less than original
        newPool.deposit(afterSlippage); // Collateral reduced but debt same
    }
}
```

**Fixed:**
```solidity
contract LendingPool {
    function redeemAndSwap(uint256 cTokenAmount, uint256 minOut) external {
        // Get actual balance change instead of calculated amount
        uint256 balBefore = IERC20(underlying).balanceOf(address(this));
        cToken.redeem(cTokenAmount);
        uint256 actualAmount = IERC20(underlying).balanceOf(address(this)) - balBefore;
        router.swap(underlying, actualAmount, minOut);
    }

    function migrateLoan(uint256 amount) external {
        uint256 flashAmount = flashLoan(amount);
        uint256 afterFees = flashAmount - flashFee;
        uint256 afterSlippage = swap(afterFees);
        newPool.deposit(afterSlippage);
        // Re-check health with new collateral value
        require(newPool.isHealthy(msg.sender), "unhealthy after migration");
    }
}
```

### Detect
For every division operation in lending logic: (1) verify rounding direction favors the protocol, (2) check related calculations use consistent rounding, (3) confirm minimum amounts prevent micro-operation exploitation, (4) verify exchange rate conversions use actual balances not calculations.

### Remediation
Round against the party initiating the action (round up for borrows/withdrawals, round down for deposits/repayments). Use consistent rounding across related operations. Implement minimum amounts to prevent micro-operation exploitation.
