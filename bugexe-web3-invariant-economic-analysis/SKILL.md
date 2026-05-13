---
name: invariant-economic-analysis
category: web3
description: Invariant and economic security analysis covering conservation law verification, state coupling detection, assumption violation methodology, round-trip testing, flash loan feasibility assessment, token misbehavior exploitation, and systematic first-principles approach to finding deep logic bugs
depends_on: []
---

# Invariant and Economic Security Analysis

First-principles security analysis for smart contracts. Focuses on conservation law verification, state coupling detection, systematic assumption violation, round-trip identity testing, flash loan feasibility assessment, token misbehavior exploitation, path divergence analysis, edge value probing, and invariant fuzzing strategy. These techniques find deep logic bugs that pattern-matching approaches miss.

## When to Use

- Auditing DeFi protocols with share-based accounting (vaults, staking, lending)
- Reviewing contracts that hold user deposits and issue receipt tokens
- Protocols with fee collection, reward distribution, or yield calculation
- Any contract where multiple state variables must maintain a mathematical relationship
- Contracts accepting arbitrary ERC20 tokens or interacting with external protocols
- Systems with paired inverse operations (deposit/withdraw, mint/redeem, lock/unlock)
- Targets where flash loan capital could manipulate price or balance reads
- First-depositor or empty-state scenarios need analysis

## Methodology

### 1. Conservation Law Analysis

Conservation laws are mathematical identities the protocol must preserve across all state transitions. Violations indicate token creation from nothing, token destruction (permanent loss), or accounting desynchronization.

**Sum Invariants**
- `totalSupply == sum(balances[i])` for all `i` in token holders
- `totalDeposited == sum(userDeposits[i])` for all `i` in depositors
- `totalBorrowed == sum(userBorrows[i])` for all `i` in borrowers
- `totalStaked == sum(userStakes[i])` for all `i` in stakers
- Detection: identify every variable that represents an aggregate total, then find all individual-level variables that should sum to it. Grep for `total`, `supply`, `reserve`, `aggregate`, `cumulative` in state variables.

**In-Out Balance**
- Every token entering the system must exit through an accounted path (no creation or destruction except intended mint/burn)
- Trace all `transferFrom` (inflow) and `transfer` (outflow) calls. Map each to the accounting variable it should update.
- If any transfer path does not update accounting, tokens leak out of the system or accumulate silently.

**Fee Conservation**
- Fees collected must equal fees distributed plus fees retained in treasury
- `feeCollected == feeDistributed + feeTreasury` at all times
- Check every fee deduction: is the deducted amount added to a fee accumulator? Is the accumulator ever drained to recipients?
- Common violation: emergency functions, admin withdrawals, or migration paths that bypass fee accounting

**Share-Asset Ratio (Accounting Identity)**
- `totalShares * pricePerShare == totalAssets` must hold before and after every operation
- For ERC4626 vaults: `convertToAssets(totalSupply()) == totalAssets()` must be consistent
- Check: after deposit, do shares * price still equal total assets? After withdrawal? After yield accrual?

**Detection Method**
1. List all state variables that represent totals or aggregates
2. For each aggregate, find every function that modifies it
3. Verify that every modification to a constituent variable has a corresponding modification to the aggregate
4. Test: call function, check if `aggregate == sum(constituents)` still holds
5. Pay special attention to: emergency/pause functions, admin override functions, migration functions, fee-exempt paths

### 2. State Coupling Verification

State coupling means two or more variables that must be updated together. A broken coupling leaves stale state that can be exploited.

**Coupled Variable Pairs**
- When `balances[user]` changes, `totalSupply` must also change
- When `userRewardDebt[user]` changes, `accRewardPerShare` should already be current
- When `collateral[user]` changes, health factor / liquidation threshold must be recalculated
- When `lastUpdateTime` changes, accumulated rewards must be settled first

**Detection Method**
1. For each state variable A, find all write sites (`SSTORE` or assignment)
2. At each write site, verify that every coupled variable B is also written or explicitly up-to-date
3. If variable B is not updated in the same code path, the coupling is broken

**Temporal Coupling**
- Variable A must be updated BEFORE variable B in the same transaction
- Example: `updateReward()` must execute before `stake()` or `unstake()` to prevent stale reward calculation
- Detection: find all functions that call `updateReward` (or equivalent accumulator refresh). If any state-modifying function skips this call, rewards go stale.

**Cross-Contract Coupling**
- State in Contract A depends on state in Contract B being consistent
- Example: a vault reads a price feed from an oracle contract. If the oracle is stale, vault calculations are wrong.
- Detection: trace all external `staticcall` and `call` reads. For each, determine what guarantees freshness of the returned data.

**Common Broken Coupling Examples**
- `updateReward()` not called before `stake()` / `unstake()` / `withdraw()` -- stale rewards
- `accrueInterest()` not called before `borrow()` / `repay()` / `liquidate()` -- stale interest
- Balance updated but `totalSupply` not updated in the same path -- supply desynchronization
- User position closed but global aggregate not decremented -- phantom positions inflate totals

### 3. Assumption Violation Methodology (First Principles)

For every code line, extract the implicit assumption. Then systematically violate each assumption and trace what happens. This is the most general technique and catches bugs no pattern can anticipate.

**Assumption Categories**

| Category | Assumption | Violation | Consequence to Trace |
|----------|-----------|-----------|---------------------|
| Value range | "This value is always positive" | Set to 0 or `type(uint256).max` | Division by zero, overflow, underflow |
| Ordering | "A always happens before B" | Call B first, then A, or call B without A | Stale state, uninitialized values |
| Uniqueness | "Each user calls this once" | Call twice in the same transaction | Double-counting, double-mint |
| Trust | "This address is the oracle" | Oracle returns 0, negative, or extreme value | Price manipulation, liquidation cascade |
| Timing | "This happens within one block" | Span operation across multiple blocks or epochs | MEV, frontrunning, stale data |
| Existence | "This account/position exists" | Delete the position, then call the function | Zero-division, underflow, null reference |

**Systematic Process**
1. Select a function
2. For each `require` / `if` statement, write down what it assumes
3. For each arithmetic operation, write down what input range makes it safe
4. For each external call, write down what return value the code expects
5. For each storage read, write down when that value was last written
6. For each of the above, construct a scenario that violates the assumption
7. Trace the violating scenario through the function to its terminal state (revert, return, or state change)

### 4. Round-Trip Testing

Any pair of inverse operations should compose to the identity function (minus explicit fees). A round-trip that loses value or creates value is a bug.

**Standard Round-Trip Pairs**

| Forward | Reverse | Identity Check |
|---------|---------|---------------|
| `deposit(X)` | `withdraw(all)` | User gets back X minus fees |
| `mint(shares)` | `redeem(all)` | Assets returned equal assets deposited minus fees |
| `lock(tokens, duration)` | `unlock()` after duration | User gets original token amount |
| `encode(data)` | `decode(encoded)` | Returns original data exactly |
| `stake(X)` | `unstake(all)` | User gets back X plus earned rewards |
| `borrow(X)` | `repay(all)` | Debt is exactly zero after repay |
| `open(position)` | `close(position)` | Net PnL matches expected formula |

**Detection Method**
1. For every "forward" operation, find the corresponding "reverse" operation
2. Compute the round-trip with concrete values: deposit 1000 tokens, immediately withdraw all
3. The difference should be exactly the documented fee (or zero if no fee)
4. Test with edge amounts: deposit 1 wei, deposit `type(uint256).max`, deposit the exact minimum
5. Test ordering: deposit A then B, withdraw B then A -- should produce the same result as depositing and withdrawing individually

**Common Round-Trip Failures**
- Rounding losses accumulate: deposit 100, get 99 shares, redeem 99 shares, get 98 tokens
- Fee applied on both deposit and withdrawal when documentation says fee is one-way
- First depositor gets fewer shares due to initial share price calculation
- Last withdrawer cannot exit because rounding leaves dust that fails minimum checks

### 5. Flash Loan Feasibility Assessment

Flash loans make capital free for the duration of a single transaction. When assessing any finding, assume the attacker has unlimited capital and evaluate profitability.

**Capital Availability**
- Aave V3: up to billions in USDC/ETH/WBTC, currently 0% fee (previously 0.05%)
- dYdX: 0% fee flash loans on supported assets
- Uniswap V3: flash swaps with 0.3% fee (or 0.05%/1% depending on pool tier)
- Balancer: 0% fee flash loans on all pool assets
- Euler: 0% fee flash loans
- MakerDAO: DAI flash mint with 0% fee
- Attacker effective capital: sum of all available flash loan sources for the target asset

**Profitability Formula**
```
profit = value_extracted - flash_loan_fee - gas_cost
```
- `value_extracted`: the delta in attacker balance after the exploit
- `flash_loan_fee`: percentage of borrowed amount (often 0%)
- `gas_cost`: typically negligible (<$50) relative to DeFi exploit value

**Assessment Method**
1. For every price read, balance check, or threshold comparison in the contract:
   - Can the read value be moved by depositing or withdrawing a large amount in the same transaction?
   - If yes: what is the cost to move it (slippage, fees) versus the value extracted?
2. If `profit > 0` for any manipulable read, it is a vulnerability
3. Map the complete atomic sequence: borrow, manipulate, exploit, repay, profit
4. Verify the entire sequence can execute in one transaction (no block boundaries required)

**Common Flash Loan Targets**
- AMM spot prices used as oracles (trivially manipulable)
- Collateral ratio checks that read current balance
- Reward calculations based on current pool size
- Governance vote weight checks based on current token balance
- Liquidation thresholds that check current collateral value

### 6. Token Misbehavior Exploitation

When a protocol accepts arbitrary tokens, assume the worst-case token behavior for each interaction. Protocols that only work with "standard" ERC20 tokens are vulnerable to every non-standard behavior.

**Token Misbehavior Classes**

| Behavior | Effect | Detection |
|----------|--------|-----------|
| Fee-on-transfer | `balanceOf(recipient)` after transfer is less than `amount` sent | Check if protocol uses `transferFrom` amount or actual balance delta |
| Rebasing (up) | Token balance increases without transfer (e.g., stETH) | Check if accounting tracks shares or absolute balances |
| Rebasing (down) | Token balance decreases without transfer (negative rebase) | Check if withdrawal can fail when balance drops below recorded amount |
| Blacklisting | `transfer` reverts for specific addresses (e.g., USDC, USDT) | Check if a blocked recipient can brick protocol withdrawals |
| Pausable | All transfers revert when paused | Check if protocol handles transfer revert gracefully |
| ERC-777 hooks | `tokensReceived` callback enables reentrancy via transfer | Check if reentrancy guard covers all token transfer paths |
| Multiple entry points | Some tokens have two addresses (upgradeable proxies) | Check if protocol deduplicates token addresses |
| Missing return value | `transfer` / `approve` do not return bool (USDT) | Check if protocol uses `SafeERC20` or checks return value |
| Decimals != 18 | USDC (6), WBTC (8), some tokens (0 or 24) | Check if protocol normalizes decimals in calculations |

**Assessment Method**
- For each `transfer`, `transferFrom`, and `approve` call: "What if the token does X during this call?"
- Replace X with each misbehavior from the table above
- If any misbehavior causes incorrect accounting, stuck funds, or a revert that blocks other users, report it

### 7. Path Divergence Analysis

When an operation can execute through multiple code paths, verify all paths produce equivalent outcomes. Divergent paths create arbitrage opportunities.

**Divergence Sources**
- Multiple deposit routes (direct vs router vs zap)
- Different withdrawal paths (normal vs emergency vs admin)
- Fee application differences between paths
- Batch execution vs individual execution
- Different token pair orderings producing different results

**Detection Method**
1. Identify all entry points that achieve the same end state (e.g., all ways to deposit)
2. Trace each path with identical inputs
3. Compare: final balances, shares received, fees charged, state variables updated
4. If any path produces a different result for the same input, the divergence is exploitable
5. Check partial execution: if a multi-step operation fails midway, what state is left?

**Common Path Divergence Bugs**
- Fees charged on path A but not path B for the same operation
- Rounding direction differs between deposit and withdrawal calculation paths
- Batch processing uses a different price snapshot than individual processing
- Emergency withdrawal skips reward settlement, leaving stale reward debt

### 8. Sentinel and Edge Value Analysis

Boundary values expose off-by-one errors, division by zero, overflow conditions, and degenerate state handling.

**Critical Values to Test**

| Category | Values | What Breaks |
|----------|--------|-------------|
| Zero | `amount = 0` | Division by zero, meaningless state transitions, zero-share minting |
| One | `amount = 1 wei` | Rounding to zero shares, dust positions that cannot be closed |
| Maximum | `type(uint256).max` | Overflow in `unchecked` blocks, approval manipulation |
| Boundary | Value exactly at threshold | Off-by-one in `<` vs `<=` comparisons |
| First user | No existing deposits, empty pool | Share price undefined, division by zero in `totalSupply` |
| Last user | All other users have withdrawn | Dust remaining, inability to fully exit |
| Empty state | Protocol has zero TVL | Pool ratio undefined, reward rate division by zero |

**Systematic Process**
1. For each public/external function parameter, substitute each sentinel value
2. Trace execution with the sentinel value through every arithmetic operation
3. Check: does the function revert safely, or does it produce an incorrect but accepted result?
4. An incorrect accepted result is worse than a revert -- it corrupts state silently

**First-Depositor Attack Pattern**
1. Attacker deposits 1 wei, receives 1 share
2. Attacker donates (transfers directly) a large amount to the vault
3. Share price is now inflated: 1 share = 1 wei + donated amount
4. Next depositor's deposit rounds down to 0 shares if deposit < share price
5. Detection: check if `convertToShares(amount)` can return 0 for a non-zero `amount`

### 9. Invariant Fuzzing Strategy

Define system invariants as executable properties and let a fuzzer search for violations. This mechanically verifies conservation laws and state coupling across random operation sequences.

**Core Invariant Categories**

| Invariant | Property | Foundry Assertion |
|-----------|----------|-------------------|
| Supply conservation | `totalSupply == sum(balances)` | `assertEq(token.totalSupply(), sumAllBalances())` |
| Solvency | `address(vault).balance >= totalDeposited` | `assertGe(vault.totalAssets(), vault.totalSupply())` |
| Share price monotonicity | Share price never decreases (non-rebasing vaults) | `assertGe(currentPrice, lastRecordedPrice)` |
| No token creation | No function creates tokens without corresponding deposit | `assertEq(token.totalSupply(), expectedSupply)` |
| Withdrawal cap | User cannot withdraw more than deposited plus earned | `assertLe(withdrawn, deposited + earned)` |
| Round-trip identity | deposit then withdraw returns original minus fees | `assertGe(balanceAfter, balanceBefore - maxFee)` |

**Handler Approach**
- Restrict the fuzzer to valid operation sequences using a handler contract
- The handler calls target functions with fuzzed parameters but in realistic patterns
- Track expected values in ghost variables to compare against actual contract state

## Key Commands

```bash
# Read a specific storage slot (check state variable values)
cast storage {contract} {slot}

# Check totalSupply
cast call {token} "totalSupply()(uint256)"

# Check user balance
cast call {token} "balanceOf(address)(uint256)" {user}

# Check vault share price
cast call {vault} "convertToAssets(uint256)(uint256)" 1000000000000000000

# Check vault total assets
cast call {vault} "totalAssets()(uint256)"

# Check if round-trip is lossy (deposit then preview withdrawal)
cast call {vault} "previewDeposit(uint256)(uint256)" {amount}
cast call {vault} "previewRedeem(uint256)(uint256)" {shares_from_above}

# Check fee-on-transfer token behavior
cast call {token} "balanceOf(address)(uint256)" {recipient}  # before transfer
cast send {token} "transfer(address,uint256)" {recipient} {amount}
cast call {token} "balanceOf(address)(uint256)" {recipient}  # after: compare delta vs amount

# Check oracle freshness
cast call {oracle} "latestRoundData()(uint80,int256,uint256,uint256,uint80)"
# Fields: roundId, answer, startedAt, updatedAt, answeredInRound

# Find state variable writes
grep -rn "totalSupply\|totalAssets\|totalStaked\|totalDebt\|totalDeposited" contracts/

# Find accumulator updates
grep -rn "rewardPerToken\|accReward\|cumulativeReward\|lastUpdate" contracts/

# Find all token transfer calls
grep -rn "\.transfer\|\.transferFrom\|safeTransfer\|safeTransferFrom" contracts/

# Find flash loan interfaces
grep -rn "flashLoan\|flash\|FlashBorrower\|IERC3156" contracts/

# Find emergency/admin functions
grep -rn "emergency\|pause\|admin\|onlyOwner\|onlyRole" contracts/

# Run Foundry invariant tests
forge test --match-contract InvariantTest -vvv

# Run specific invariant test with deep fuzzing
forge test --match-test invariant_ -vvv --fuzz-runs 10000
```

**Foundry Invariant Test Template**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract Handler is Test {
    TargetVault public vault;
    IERC20 public token;

    // Ghost variables: track expected state off-chain
    uint256 public ghost_totalDeposited;
    uint256 public ghost_totalWithdrawn;
    uint256 public ghost_totalFees;

    constructor(TargetVault _vault, IERC20 _token) {
        vault = _vault;
        token = _token;
    }

    function deposit(uint256 amount) external {
        amount = bound(amount, 1, token.balanceOf(address(this)));
        if (amount == 0) return;

        token.approve(address(vault), amount);
        vault.deposit(amount, address(this));

        ghost_totalDeposited += amount;
    }

    function withdraw(uint256 amount) external {
        uint256 maxWithdraw = vault.maxWithdraw(address(this));
        amount = bound(amount, 0, maxWithdraw);
        if (amount == 0) return;

        vault.withdraw(amount, address(this), address(this));
        ghost_totalWithdrawn += amount;
    }

    function redeem(uint256 shares) external {
        uint256 maxRedeem = vault.maxRedeem(address(this));
        shares = bound(shares, 0, maxRedeem);
        if (shares == 0) return;

        uint256 assets = vault.redeem(shares, address(this), address(this));
        ghost_totalWithdrawn += assets;
    }
}

contract InvariantTest is Test {
    TargetVault public vault;
    IERC20 public token;
    Handler public handler;

    function setUp() public {
        // Deploy or fork target contracts
        // vault = new TargetVault(...);
        // token = IERC20(vault.asset());
        handler = new Handler(vault, token);
        deal(address(token), address(handler), 1_000_000e18);

        // Tell Foundry to only call handler functions
        targetContract(address(handler));
    }

    /// @notice totalSupply of shares must equal sum of all individual share balances
    function invariant_supplyConservation() public view {
        uint256 totalShares = vault.totalSupply();
        uint256 sumBalances = vault.balanceOf(address(handler));
        // Add other known holders as needed
        assertEq(totalShares, sumBalances, "Supply conservation violated");
    }

    /// @notice Vault must always be solvent: real token balance >= tracked totalAssets
    function invariant_solvency() public view {
        if (vault.totalSupply() == 0) return;
        assertGe(
            token.balanceOf(address(vault)),
            vault.totalAssets(),
            "Vault is insolvent: real balance < totalAssets"
        );
    }

    /// @notice No user can withdraw more total value than was deposited
    function invariant_noExcessWithdrawal() public view {
        assertGe(
            handler.ghost_totalDeposited(),
            handler.ghost_totalWithdrawn(),
            "Withdrawn exceeds total deposited"
        );
    }

    /// @notice Share price should not decrease without an explicit loss event
    function invariant_sharePriceMonotonic() public view {
        if (vault.totalSupply() == 0) return;
        uint256 currentPrice = vault.convertToAssets(1e18);
        assertGt(currentPrice, 0, "Share price collapsed to zero");
    }

    /// @notice Accounting identity: convertToAssets(totalSupply) == totalAssets
    function invariant_accountingIdentity() public view {
        if (vault.totalSupply() == 0) return;
        uint256 sharesValue = vault.convertToAssets(vault.totalSupply());
        uint256 totalAssets = vault.totalAssets();
        // Allow 1 wei tolerance for rounding
        assertApproxEqAbs(
            sharesValue,
            totalAssets,
            1,
            "Accounting identity broken: shares value != totalAssets"
        );
    }

    /// @notice No function should create tokens out of thin air
    function invariant_noPhantomTokens() public view {
        uint256 vaultBalance = token.balanceOf(address(vault));
        uint256 handlerBalance = token.balanceOf(address(handler));
        uint256 total = vaultBalance + handlerBalance;
        assertEq(
            total,
            1_000_000e18,
            "Token conservation violated: tokens created or destroyed"
        );
    }
}
```

**Foundry Fuzz Test Template (Round-Trip)**

```solidity
contract RoundTripFuzzTest is Test {
    TargetVault public vault;
    IERC20 public token;

    function setUp() public {
        // Deploy target
    }

    /// @notice Deposit then full withdrawal should return original minus max fee
    function testFuzz_roundTripDeposit(uint256 amount) public {
        amount = bound(amount, vault.minDeposit(), 1_000_000e18);
        deal(address(token), address(this), amount);
        token.approve(address(vault), amount);

        uint256 balanceBefore = token.balanceOf(address(this));
        uint256 shares = vault.deposit(amount, address(this));
        uint256 assetsOut = vault.redeem(shares, address(this), address(this));
        uint256 balanceAfter = token.balanceOf(address(this));

        // Round-trip loss should not exceed documented fee + 1 wei rounding
        uint256 maxLoss = (amount * vault.feeBps()) / 10000 + 1;
        assertGe(
            balanceAfter,
            balanceBefore - maxLoss,
            "Round-trip lost more than fee + rounding"
        );
    }

    /// @notice First depositor should not be able to steal from second depositor
    function testFuzz_firstDepositorAttack(uint256 donation, uint256 victimDeposit) public {
        donation = bound(donation, 1e18, 100e18);
        victimDeposit = bound(victimDeposit, 1, donation);

        // Attacker: deposit 1 wei
        deal(address(token), address(this), 1);
        token.approve(address(vault), 1);
        vault.deposit(1, address(this));

        // Attacker: donate directly to inflate share price
        deal(address(token), address(this), donation);
        token.transfer(address(vault), donation);

        // Victim: deposit
        address victim = makeAddr("victim");
        deal(address(token), victim, victimDeposit);
        vm.startPrank(victim);
        token.approve(address(vault), victimDeposit);
        uint256 victimShares = vault.deposit(victimDeposit, victim);
        vm.stopPrank();

        // Victim must receive non-zero shares for non-zero deposit
        assertGt(victimShares, 0, "Victim received 0 shares: first depositor attack viable");
    }
}
```

## Validation

- **Conservation law**: for each identified invariant, show a concrete function call sequence that violates `aggregate == sum(constituents)` with actual numbers
- **State coupling**: demonstrate a call path where variable A is updated but coupled variable B is stale, then show exploitation of the stale value
- **Assumption violation**: for each implicit assumption, show a concrete input that violates it and trace to the terminal state (revert, incorrect return, or corrupted storage)
- **Round-trip**: deposit X tokens, withdraw all, show the delta is not equal to the documented fee (or show value creation/destruction)
- **Flash loan**: construct a complete atomic sequence (borrow, manipulate, exploit, repay) with concrete amounts showing `profit > 0`
- **Token misbehavior**: substitute a fee-on-transfer or rebasing token and show accounting diverges from actual balances
- **Path divergence**: execute the same logical operation via two different code paths and show different outcomes
- **Edge values**: call functions with zero, one, and maximum values, showing either silent corruption or unexpected acceptance
- **Invariant fuzz**: run `forge test --match-test invariant_ -vvv --fuzz-runs 10000` and report any counterexamples found, including the exact call sequence that violated the property
