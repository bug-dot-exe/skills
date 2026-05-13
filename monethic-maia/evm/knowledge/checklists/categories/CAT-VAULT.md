## CL-VAULT-01: Vault Accounting Integrity Invariant

**Rule:** `EVM-VAULT-ACCT-01`
**Severity:** high-critical

### Description
When a tokenized vault tracks assets across deposits, withdrawals, fees, and strategies using internal accounting state, vault accounting corrupts when state updates occur in wrong order relative to transfers, fee calculations mishandle underlying vault charges, strategy interfaces confuse shares with assets, or totalAssets() diverges from actual holdings. These produce silent undercollateralization or permanent fund loss.

### Patterns
### Pattern 1: Deposit/Withdrawal State Ordering Errors
State is updated before funds actually arrive (or after they leave), creating windows where accounting is inconsistent. Also: yield amounts included in base tracking, silent downcast truncation of large values, and wrong owner parameter in delegated withdrawals.

**Vulnerable:**
```solidity
// BUG: State update before transfer — accounting reflects funds not yet received
function deposit(uint256 amount) external {
    _refreshBalance(amount); // Updates internal state
    SafeTransferLib.safeTransferFrom(token, msg.sender, address(this), amount); // Transfer after
}

// BUG: Yield included in base decrement — corrupts depositedBase tracking
function withdraw(uint256 assets, uint256 shares) internal {
    uint256 totalWithYield = assets + previewYield(msg.sender, shares);
    depositedBase -= totalWithYield; // Should only subtract base assets, not yield
}

// BUG: Silent downcast overflow
_twabController.burn(msg.sender, _owner, uint96(_shares)); // Truncates shares > 2^96!
```

**Fixed:**
```solidity
// Transfer first, then update state
function deposit(uint256 amount) external {
    SafeTransferLib.safeTransferFrom(token, msg.sender, address(this), amount);
    _refreshBalance(amount);
}

// Only subtract base assets from base tracking
function withdraw(uint256 assets, uint256 shares) internal {
    uint256 baseOnly = convertToAssets(shares); // Exclude yield
    depositedBase -= baseOnly;
}

// Safe cast
_twabController.burn(msg.sender, _owner, SafeCast.toUint96(_shares));
```

### Pattern 2: Fee Calculation Errors
Vault fees are miscalculated when underlying vaults charge their own fees (double-fee gap), adjustor functions are reversed, batch netting logic has ordering bugs, or fee shares are minted at the wrong time relative to reward distribution.

**Vulnerable:**
```solidity
// BUG: Doesn't cover underlying vault's deposit fee — protocol becomes undercollateralized
function deposit(uint256 assets) external {
    asset.transferFrom(msg.sender, address(this), assets);
    underlyingVault.deposit(assets); // Underlying charges 1% fee — only 99% actually deposited
    _trackedAssets += assets; // Tracks 100% — 1% gap grows forever
}

// BUG: Netting logic subtracts from already-zeroed variable
if (assetsToWithdraw > assetsToDeposit) {
    assetsToDeposit = 0;
    assetsToWithdraw -= assetsToDeposit; // Subtracting 0! Should subtract before zeroing
}

// BUG: Fee shares minted before rewards — fee recipient gets shares at old (cheaper) rate
function harvest() external {
    _mintFeeShares(); // Minted at pre-harvest rate
    _distributeRewards(); // Rate increases — fee recipient got cheap shares
}
```

**Fixed:**
```solidity
// Account for underlying vault fees
function deposit(uint256 assets) external {
    asset.transferFrom(msg.sender, address(this), assets);
    uint256 sharesBefore = underlyingVault.balanceOf(address(this));
    underlyingVault.deposit(assets);
    uint256 sharesAfter = underlyingVault.balanceOf(address(this));
    _trackedAssets += underlyingVault.convertToAssets(sharesAfter - sharesBefore); // Actual amount
}

// Fix netting order
if (assetsToWithdraw > assetsToDeposit) {
    assetsToWithdraw -= assetsToDeposit; // Subtract first
    assetsToDeposit = 0; // Then zero
}

// Mint fee shares AFTER reward distribution
function harvest() external {
    _distributeRewards();
    _mintFeeShares(); // At post-harvest rate — correct fee amount
}
```

### Pattern 3: Strategy Return Value Confusion
Strategy adapters return shares when the vault expects assets (or vice versa). `_deploy()` returns vault shares instead of assets deployed. `_getBalance()` returns share count instead of asset value. `_undeploy()` returns requested amount instead of actual withdrawn.

**Vulnerable:**
```solidity
// BUG: _deploy returns shares, not assets
function _deploy(uint256 amount) internal override returns (uint256) {
    return _yieldVault.deposit(amount, address(this)); // Returns shares!
}

// BUG: _getBalance returns shares
function _getBalance() internal view override returns (uint256) {
    return _yieldVault.balanceOf(address(this)); // Returns shares, not asset value!
}

// BUG: Returns requested amount, not actual withdrawn
function undeploy(uint256 amount) external returns (uint256) {
    uint256 actual = _yieldVault.withdraw(amount, address(this), address(this));
    asset.safeTransfer(msg.sender, actual);
    return amount; // Should return actual!
}
```

**Fixed:**
```solidity
function _deploy(uint256 amount) internal override returns (uint256) {
    _yieldVault.deposit(amount, address(this));
    return amount; // Return assets deployed, not shares received
}

function _getBalance() internal view override returns (uint256) {
    return _yieldVault.convertToAssets(_yieldVault.balanceOf(address(this))); // Convert to assets
}

function undeploy(uint256 amount) external returns (uint256) {
    uint256 actual = _yieldVault.withdraw(amount, address(this), address(this));
    asset.safeTransfer(msg.sender, actual);
    return actual; // Return what was actually withdrawn
}
```

### Pattern 4: totalAssets() Drift and Mismatch
totalAssets() excludes yield from nested vaults (users lose yield), includes assets from external depositors in shared strategies (inflatable), diverges from internal exchange rate tracking, or underflows post-maturity.

**Vulnerable:**
```solidity
// BUG: Excludes yield — depositors lose entitled yield
function totalAssets() public view override returns (uint256) {
    return depositedBase; // Ignores yield accrued in nested vaults
}

// BUG: Includes ALL strategy assets regardless of ownership
function totalAssets() public view override returns (uint256 total) {
    for (uint i = 0; i < strategies.length; i++) {
        total += strategies[i].totalAssets(); // Includes other depositors!
    }
}

// BUG: Post-maturity underflow
uint256 yield = ((maturityRate * 1e26) / vlt.exchangeRate) - 1e26;
// When exchangeRate > maturityRate, this underflows and reverts
```

**Fixed:**
```solidity
// Include yield from nested vaults
function totalAssets() public view override returns (uint256) {
    uint256 total;
    for (uint i = 0; i < strategies.length; i++) {
        total += strategies[i].convertToAssets(strategies[i].balanceOf(address(this)));
    }
    return total + asset.balanceOf(address(this)); // Our shares only + idle
}

// Cap exchange rate at maturity
function _getExchangeRate() internal view returns (uint256) {
    uint256 rate = _calculateRate();
    return rate > maturityRate ? maturityRate : rate;
}
```

### Pattern 5: Multi-Strategy Decimal and Accounting Mismatch
Multi-strategy vaults assume uniform decimals across strategies, fail to cascade withdrawals across multiple vaults, allow duplicate strategy entries, or accept strategies with mismatched underlying assets.

**Vulnerable:**
```solidity
// BUG: Only withdraws if single vault covers full amount
function redeemRequired(uint256 baseTokens) internal {
    for (uint i = 0; i < vaults.length; i++) {
        uint256 available = vaults[i].previewRedeem(vaults[i].balanceOf(address(this)));
        if (available >= baseTokens) {
            vaults[i].withdraw(baseTokens, address(this), address(this));
            break; // Skips if no single vault has enough!
        }
    }
}

// BUG: No duplicate check — same strategy added twice doubles reported assets
function addStrategy(address strategy) external onlyOwner {
    strategies.push(strategy); // No duplicate check
}
```

**Fixed:**
```solidity
// Cascade withdrawal across multiple vaults
function redeemRequired(uint256 baseTokens) internal {
    uint256 remaining = baseTokens;
    for (uint i = 0; i < vaults.length && remaining > 0; i++) {
        uint256 available = vaults[i].maxWithdraw(address(this));
        uint256 toWithdraw = Math.min(available, remaining);
        if (toWithdraw > 0) {
            vaults[i].withdraw(toWithdraw, address(this), address(this));
            remaining -= toWithdraw;
        }
    }
    require(remaining == 0, "Insufficient assets");
}

// Prevent duplicate strategies
function addStrategy(address strategy) external onlyOwner {
    require(!_isStrategy[strategy], "duplicate");
    require(IStrategy(strategy).asset() == asset(), "wrong asset");
    _isStrategy[strategy] = true;
    strategies.push(strategy);
}
```

### Detect
For every vault: (1) verify state updates occur after transfers and base tracking excludes yield, (2) verify fee calculations account for underlying vault fees, netting order is correct, and fee shares mint after rewards, (3) verify strategy deploy/getBalance/undeploy return assets not shares, (4) verify totalAssets() includes owned yield, excludes external deposits, and handles post-maturity caps, (5) verify multi-strategy vaults cascade withdrawals, prevent duplicates, and validate asset/decimal consistency.

### Remediation
- Transfer before state update. Measure actual amounts after underlying vault operations.
- Return assets from strategy interfaces, not shares.
- Use only owned positions in totalAssets.
- Cascade multi-vault withdrawals with duplicate and asset validation.

## CL-VAULT-02: ERC-7540 Async Vault Compliance Invariant

**Rule:** `EVM-VAULT-ERC7540-01`
**Severity:** medium-critical

### Description
When a contract implements the ERC-7540 Asynchronous Tokenized Vault Standard extending ERC-4626 with request-based deposit and redemption flows, ERC-7540 introduces a 3-state lifecycle (Pending -> Claimable -> Claimed) with strict MUST requirements for asset/share custody, claim function overrides, operator authorization, state accounting, and security around the async gap. Deviations cause double transfers, stuck funds, unauthorized claims, or state corruption.

### Patterns
### Pattern 1: Request Lifecycle Violations
`requestDeposit` must transfer assets from owner via transferFrom. `requestRedeem` must remove shares from owner custody (lock or burn). Requests must not skip the Claimable state. Partial acceptance must revert. Required events must be emitted.

**Vulnerable:**
```solidity
// BUG 1: No asset transfer at request time
function requestDeposit(uint256 assets, address controller, address owner) external returns (uint256) {
    pendingDeposits[controller] += assets;
    return 0; // Assets never pulled — deposit() will double-charge
}

// BUG 2: Shares not removed from owner
function requestRedeem(uint256 shares, address controller, address owner) external returns (uint256) {
    pendingRedeems[controller] += shares;
    return 0; // Owner still holds shares — can transfer or double-redeem
}

// BUG 3: Auto-claims, skipping Claimable state
function fulfillDeposit(address controller, uint256 shares) internal {
    pendingDeposits[controller] = 0;
    _mint(controller, shares); // Directly mints — no claim step needed
}
```

**Fixed:**
```solidity
function requestDeposit(uint256 assets, address controller, address owner) external returns (uint256) {
    require(msg.sender == owner || isOperator(owner, msg.sender), "unauthorized");
    asset.transferFrom(owner, address(this), assets); // Pull assets at request time
    pendingDeposits[controller] += assets;
    emit DepositRequest(controller, owner, 0, msg.sender, assets);
    return 0;
}

function requestRedeem(uint256 shares, address controller, address owner) external returns (uint256) {
    require(msg.sender == owner || isOperator(owner, msg.sender), "unauthorized");
    _transfer(owner, address(this), shares); // Lock shares in vault
    pendingRedeems[controller] += shares;
    emit RedeemRequest(controller, owner, 0, msg.sender, shares);
    return 0;
}

function fulfillDeposit(address controller, uint256 shares) internal {
    uint256 assets = pendingDeposits[controller];
    pendingDeposits[controller] = 0;
    claimableDeposits[controller] += assets; // Move to Claimable, don't auto-claim
    claimableShares[controller] += shares;
}
```

### Pattern 2: Claim Function Override Violations
In async mode, ERC-4626 deposit/mint/redeem/withdraw become claim-only operations. They MUST NOT re-transfer assets or re-burn shares. Preview functions MUST revert unconditionally. Max functions must sync with claimable state.

**Vulnerable:**
```solidity
// BUG: deposit() still transfers assets — user pays double
function deposit(uint256 assets, address receiver) public override returns (uint256 shares) {
    asset.transferFrom(msg.sender, address(this), assets); // WRONG: already transferred at request
    shares = claimableShares[msg.sender];
    _mint(receiver, shares);
}

// BUG: previewDeposit returns value — implies synchronous behavior
function previewDeposit(uint256 assets) public view override returns (uint256) {
    return convertToShares(assets); // WRONG: must revert for async
}

// BUG: maxDeposit ignores claimable state
function maxDeposit(address) public view override returns (uint256) {
    return type(uint256).max; // WRONG: not synced with claimable
}
```

**Fixed:**
```solidity
function deposit(uint256 assets, address receiver, address controller) public returns (uint256 shares) {
    require(msg.sender == controller || isOperator(controller, msg.sender));
    require(assets <= claimableDepositRequest(0, controller));
    shares = _convertToShares(assets);
    claimableDeposits[controller] -= assets;
    _mint(receiver, shares); // Claim-only: no asset transfer
}

function previewDeposit(uint256) public pure override returns (uint256) {
    revert("async"); // MUST revert unconditionally
}

function maxDeposit(address controller) public view override returns (uint256) {
    return claimableDepositRequest(0, controller); // Synced with claimable
}
```

### Pattern 3: Operator Authorization Gaps
ERC-7540 uses an operator model where operators act on behalf of controllers. Missing auth checks on requests allow anyone to force deposits/redeems. Missing auth on claims allows theft of fulfilled requests. ERC-165 interface IDs must be declared.

**Vulnerable:**
```solidity
// BUG: No operator check — anyone can claim another user's fulfilled request
function deposit(uint256 assets, address receiver, address controller) external returns (uint256) {
    uint256 shares = claimableShares[controller];
    claimableDeposits[controller] = 0;
    _mint(receiver, shares); // Attacker claims and routes to their address
    return shares;
}

// BUG: Operator deducts ERC-20 allowance unnecessarily
function requestRedeem(uint256 shares, address controller, address owner) external returns (uint256) {
    if (msg.sender != owner) {
        _spendAllowance(owner, msg.sender, shares); // Deducts even for operators
    }
    _transfer(owner, address(this), shares);
    return 0;
}
```

**Fixed:**
```solidity
function deposit(uint256 assets, address receiver, address controller) external returns (uint256) {
    require(msg.sender == controller || isOperator(controller, msg.sender), "unauthorized");
    require(assets <= claimableDepositRequest(0, controller));
    uint256 shares = _convertToShares(assets);
    claimableDeposits[controller] -= assets;
    _mint(receiver, shares);
    return shares;
}

function requestRedeem(uint256 shares, address controller, address owner) external returns (uint256) {
    if (msg.sender != owner) {
        if (!isOperator(owner, msg.sender)) {
            _spendAllowance(owner, msg.sender, shares); // Only non-operators use allowance
        }
    }
    _transfer(owner, address(this), shares);
    emit RedeemRequest(controller, owner, 0, msg.sender, shares);
    return 0;
}

function supportsInterface(bytes4 interfaceId) public pure returns (bool) {
    return interfaceId == 0xe3bc4e65  // operator methods
        || interfaceId == 0x2f0a18c5  // ERC-7575
        || interfaceId == 0xce3bbe50  // async deposit
        || interfaceId == 0x620ee8e4; // async redemption
}
```

### Pattern 4: Request State Accounting Errors
Pending and claimable amounts must be strictly separated. Same-requestId requests must be fungible (transition together, pro-rata). View functions must not vary by msg.sender and must not revert. requestId policy must be consistent (all zero or all non-zero).

**Vulnerable:**
```solidity
// BUG: pending includes claimable — integrators double-count
function pendingDepositRequest(uint256, address controller) external view returns (uint256) {
    return totalRequested[controller]; // Includes both pending AND claimable
}

// BUG: View function varies by caller
function claimableRedeemRequest(uint256, address controller) external view returns (uint256) {
    if (msg.sender != controller && !isOperator(controller, msg.sender)) {
        return 0; // Hides state from non-controllers
    }
    return _claimableRedeems[controller];
}

// BUG: View function reverts on unknown controller
function pendingRedeemRequest(uint256, address controller) external view returns (uint256) {
    require(knownControllers[controller], "unknown");
    return _pendingRedeems[controller];
}
```

**Fixed:**
```solidity
function pendingDepositRequest(uint256, address controller) external view returns (uint256) {
    return _pendingDeposits[controller]; // Only pending, excludes claimable
}

function claimableDepositRequest(uint256, address controller) external view returns (uint256) {
    return _claimableDeposits[controller]; // Only claimable, excludes pending
}

// View functions: same output regardless of caller, never revert
function claimableRedeemRequest(uint256, address controller) external view returns (uint256) {
    return _claimableRedeems[controller]; // Anyone can read
}

function pendingRedeemRequest(uint256, address controller) external view returns (uint256) {
    return _pendingRedeems[controller]; // Returns 0 for unknown, no revert
}
```

### Pattern 5: Async Gap Security Vulnerabilities
The time gap between request and claim creates unique attack vectors: stuck requests with no cancellation, exchange rate manipulation between request/fulfillment, queue DoS via dust entries, liquidity reservation failures, and epoch transitions destroying pending state.

**Vulnerable:**
```solidity
// BUG: No cancellation — stuck pending assets permanently locked
function requestDeposit(uint256 assets, address controller, address owner) external returns (uint256) {
    asset.transferFrom(owner, address(this), assets);
    pendingDeposits[controller] += assets;
    return 0;
    // No cancel function, no timeout, no admin rescue
}

// BUG: Reserved liquidity deployed to strategy
function deployToStrategy(uint256 amount) external onlyManager {
    asset.transfer(strategy, amount); // Includes reserved-for-redemption liquidity!
}

// BUG: Epoch transition drops unfulfilled requests
function rollEpoch() external onlyKeeper {
    currentEpoch++;
    totalPendingDeposits = 0; // Pending requests from previous epoch silently lost
    totalPendingRedeems = 0;
}
```

**Fixed:**
```solidity
// Timeout-based recovery for stuck requests
function cancelDepositRequest(address controller) external {
    require(msg.sender == controller || isOperator(controller, msg.sender));
    require(block.timestamp > requestTimestamp[controller] + TIMEOUT, "too early");
    uint256 assets = pendingDeposits[controller];
    pendingDeposits[controller] = 0;
    asset.transfer(controller, assets);
}

// Exclude reserved liquidity from deployment
function deployToStrategy(uint256 amount) external onlyManager {
    uint256 available = asset.balanceOf(address(this)) - totalReserved;
    require(amount <= available, "reserved");
    asset.transfer(strategy, amount);
}

// Carry forward unfulfilled requests across epochs
function rollEpoch() external onlyKeeper {
    uint256 unfulfilledDeposits = totalPendingDeposits - fulfilledDepositsThisEpoch;
    uint256 unfulfilledRedeems = totalPendingRedeems - fulfilledRedeemsThisEpoch;
    currentEpoch++;
    totalPendingDeposits = unfulfilledDeposits;
    totalPendingRedeems = unfulfilledRedeems;
}
```

### Detect
For every ERC-7540 implementation: (1) verify requestDeposit transfers assets and requestRedeem removes shares at request time, with no lifecycle short-circuiting or partial acceptance, (2) verify deposit/mint/redeem/withdraw are claim-only (no re-transfer) and preview functions revert unconditionally, (3) verify operator authorization on all request and claim paths with correct allowance handling, (4) verify pending/claimable state is strictly separated, view functions are caller-independent and non-reverting, and requestId policy is consistent, (5) verify stuck request recovery exists, reserved liquidity is excluded from deployment, and epoch transitions carry forward unfulfilled requests.

### Remediation
- Transfer assets/shares at request time.
- Make claim functions transfer-free.
- Enforce operator auth on all paths.
- Separate pending/claimable state strictly.
- Add cancellation timeouts, liquidity reservation, and epoch migration.

## CL-VAULT-03: Vault Operations Safety Invariant

**Rule:** `EVM-VAULT-OPS-01`
**Severity:** medium-critical

### Description
When a vault interacts with external protocols (DEXes, strategies, routers), supports upgrades/migrations, or uses timelocks and access controls around operational functions, vault operations fail or become exploitable when slippage protection is missing, external dependencies can DoS withdrawals, upgrade paths corrupt state, routers expose unauthorized operations, or cooldown/timelock mechanisms are bypassable.

### Patterns
### Pattern 1: Missing Slippage Protection
ERC-4626 deposit/withdraw have no built-in slippage parameter. Without user-specified minimums, deposits are sandwichable. Internal DEX calls with `amountOutMinimum: 0` or hardcoded tolerances leak value or cause DoS during volatility.

**Vulnerable:**
```solidity
// BUG: No minimum shares — sandwich attack profitable
function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
    shares = previewDeposit(assets);
    _deposit(msg.sender, receiver, assets, shares);
    // Attacker inflates share price before, deflates after
}

// BUG: Zero slippage in swap call
router.exactInputSingle(ExactInputSingleParams({
    amountIn: amount,
    amountOutMinimum: 0, // Entire swap value extractable by MEV
    deadline: block.timestamp // No deadline protection either
}));

// BUG: Hardcoded tolerance — DoS in volatile markets
uint256 minOut = (amount * 999) / 1000; // 0.1% always — too tight for volatile periods
```

**Fixed:**
```solidity
// User-specified minimum shares
function deposit(uint256 assets, uint256 minShares, address receiver) public returns (uint256 shares) {
    shares = previewDeposit(assets);
    require(shares >= minShares, "slippage");
    _deposit(msg.sender, receiver, assets, shares);
}

// Oracle-derived or user-supplied minimum for swaps
router.exactInputSingle(ExactInputSingleParams({
    amountIn: amount,
    amountOutMinimum: _getOracleMinOut(amount), // Oracle-derived floor
    deadline: userDeadline // User-supplied deadline
}));
```

### Pattern 2: Withdrawal DoS via External Dependencies
Multi-strategy vaults iterate all strategies for withdrawals without try/catch. A single paused/broken strategy blocks everything. Zero-amount undeploy reverts. Last strategy removal causes division by zero. External cooldowns (GMX) are griefable.

**Vulnerable:**
```solidity
// BUG: Single paused strategy blocks all withdrawals
function deallocate(uint256 amount) internal returns (uint256 total) {
    for (uint i = 0; i < strategies.length; i++) {
        uint256 frac = (amount * balances[i]) / totalAssets;
        total += IStrategy(strategies[i]).undeploy(frac); // Reverts if strategy paused!
    }
}

// BUG: Last strategy removal — division by zero
function removeStrategy(address strategy) external onlyOwner {
    uint256 assets = IStrategy(strategy).getBalance();
    _allocateAssets(assets); // Divides by _totalWeight which is now 0!
}

// BUG: Any deposit resets cooldown — attacker griefs with 1-wei deposits
function deposit(uint256 assets, address receiver) public returns (uint256) {
    glpManager.addLiquidity(token, assets, 0, 0); // Resets cooldown for ALL users
    // Attacker deposits 1 wei every 15 minutes — nobody can ever redeem
}
```

**Fixed:**
```solidity
// Try/catch and skip zero amounts
function deallocate(uint256 amount) internal returns (uint256 total) {
    for (uint i = 0; i < strategies.length; i++) {
        uint256 frac = (amount * balances[i]) / totalAssets;
        if (frac == 0) continue;
        try IStrategy(strategies[i]).undeploy(frac) returns (uint256 amt) {
            total += amt;
        } catch {} // Skip failed strategies, try next
    }
}

// Handle last strategy as special case
function removeStrategy(address strategy) external onlyOwner {
    if (strategies.length == 1) {
        IStrategy(strategy).undeploy(IStrategy(strategy).getBalance());
    } else {
        _allocateAssets(IStrategy(strategy).getBalance());
    }
}

// Separate deposit and redemption windows for cooldown protocols
function redeem(uint256 shares, address receiver, address owner) public returns (uint256) {
    require(block.timestamp >= redemptionWindowStart && block.timestamp < redemptionWindowEnd);
    // Deposits blocked during redemption window
}
```

### Pattern 3: Upgrade and Migration State Corruption
Upgradeable vaults without storage gaps get slot collisions on upgrade. Missing `_disableInitializers()` allows implementation hijacking. Platform/strategy address updates forget to migrate token approvals. Reward migration sequences have loss windows.

**Vulnerable:**
```solidity
// BUG: No storage gap — new parent variables shift child storage
abstract contract MetaVault is IMetaVault, Initializable {
    uint256 public depositedBase;
    TAsset[] public assetsArr;
    // Adding a variable here shifts ALL child contract storage slots
}

// BUG: Implementation can be initialized by attacker
contract VaultImpl is Initializable {
    function initialize(address admin) external initializer {
        _transferOwnership(admin); // Attacker calls on implementation!
    }
}

// BUG: Platform update loses approvals — all deposits fail
function setPlatform(address _platform) external onlyOwner {
    platform = _platform; // New platform has no token approvals!
}
```

**Fixed:**
```solidity
abstract contract MetaVault is IMetaVault, Initializable {
    uint256 public depositedBase;
    TAsset[] public assetsArr;
    uint256[48] private __gap; // Storage gap for upgrades
}

contract VaultImpl is Initializable {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() { _disableInitializers(); }
}

function setPlatform(address _platform) external onlyOwner {
    token.safeApprove(platform, 0); // Revoke old
    token.safeApprove(_platform, type(uint256).max); // Grant new
    platform = _platform;
}
```

### Pattern 4: Router Exploitation
Vault routers accept user-controlled `owner` parameters for withdrawals, enabling share theft from anyone who approved the router. `pullToken` functions don't restrict `from` to msg.sender. Permit signatures are front-runnable. Deposit limits apply to the router address, not the actual user.

**Vulnerable:**
```solidity
// BUG: Attacker specifies victim as owner — steals their shares
function routerRedeem(uint256 shares, address receiver, address owner) external {
    vault.redeem(shares, receiver, owner); // owner = victim, receiver = attacker
}

// BUG: Anyone can pull approved tokens from any user
function pullTokenFrom(IERC20 token, address from, uint256 amount) internal {
    token.safeTransferFrom(from, address(this), amount); // from != msg.sender!
}

// BUG: Deposit limit checked on router address, not actual depositor
function deposit(uint256 assets, address receiver) public returns (uint256) {
    require(balanceOf(msg.sender) <= maxPerUser); // msg.sender is router!
}
```

**Fixed:**
```solidity
// Force owner = msg.sender
function routerRedeem(uint256 shares, address receiver) external {
    vault.redeem(shares, receiver, msg.sender); // Can only redeem own shares
}

// Restrict from to caller
function pullTokenFrom(IERC20 token, address from, uint256 amount) internal {
    require(from == msg.sender, "only own tokens");
    token.safeTransferFrom(from, address(this), amount);
}

// Apply limits to actual depositor
function deposit(uint256 assets, address receiver) public returns (uint256) {
    require(balanceOf(receiver) + previewDeposit(assets) <= maxPerUser);
}
```

### Pattern 5: Timelock and Access Control Bypass
Withdrawal timelocks use msg.sender's proposal but withdraw from a different owner parameter. Whitelist checks only validate msg.sender (the router), not the actual recipient. Pause modifiers missing from critical operational paths.

**Vulnerable:**
```solidity
// BUG: Timelock bypass — use accomplice's ready proposal to withdraw instantly
function withdraw(uint256 assets, address receiver, address owner) public returns (uint256) {
    WithdrawProposal storage p = proposals[msg.sender]; // Caller's proposal
    require(block.timestamp >= p.readyAt, "locked");
    _withdraw(receiver, owner, assets); // But withdraws from owner!
}

// BUG: Whitelist only checks router, not actual recipient
function deposit(uint256 assets, address receiver) public onlyWhitelisted returns (uint256) {
    // msg.sender (router) is whitelisted, but receiver may not be
    return _deposit(assets, receiver);
}
```

**Fixed:**
```solidity
// Bind timelock to owner, not msg.sender
function withdraw(uint256 assets, address receiver, address owner) public returns (uint256) {
    WithdrawProposal storage p = proposals[owner]; // Owner's proposal
    require(block.timestamp >= p.readyAt, "locked");
    require(msg.sender == owner || allowance(owner, msg.sender) >= assets);
    _withdraw(receiver, owner, assets);
}

// Check both caller and receiver
function deposit(uint256 assets, address receiver) public returns (uint256) {
    require(isWhitelisted(msg.sender) && isWhitelisted(receiver), "!whitelist");
    return _deposit(assets, receiver);
}
```

### Detect
For every vault with external interactions: (1) verify deposit/withdraw have user-specified slippage parameters and DEX calls use non-zero minimums, (2) verify multi-strategy withdrawals use try/catch, handle zero amounts, and manage cooldown/last-strategy edge cases, (3) verify upgradeable vaults have storage gaps, disabled initializers, and atomic approval migration, (4) verify router operations force owner=msg.sender and restrict token pulls to caller, (5) verify timelocks bind to the correct owner and access controls check both caller and receiver.

### Remediation
- Add user-specified minimums everywhere.
- Use try/catch for external calls.
- Add storage gaps and disable initializers.
- Force owner=msg.sender in routers.
- Bind timelocks to owners and check receivers.

## CL-VAULT-04: Share Price Integrity Invariant

**Rule:** `EVM-VAULT-SHARE-01`
**Severity:** high-critical

### Description
When a tokenized vault converts between shares and underlying assets using an exchange rate derived from totalAssets/totalSupply, vault share price can be manipulated through first-depositor inflation attacks, direct token donations, rounding direction errors, share/asset type confusion, or sandwich attacks on vault operations. All exploit the relationship between totalAssets and totalSupply.

### Patterns
### Pattern 1: First Depositor Inflation Attack
The first depositor mints minimal shares, then donates a large amount of underlying tokens directly to the vault. This inflates the share price so that subsequent depositors receive zero shares due to rounding, with their assets absorbed by the attacker's single share.

**Vulnerable:**
```solidity
function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
    shares = totalSupply == 0 ? assets : assets * totalSupply / totalAssets();
    // Attacker: deposit(1) -> donate(1e18) -> share price = 1e18+1 per share
    // Victim: deposit(5e17) -> 5e17 * 1 / (1e18+1) = 0 shares!
    _mint(receiver, shares);
    asset.transferFrom(msg.sender, address(this), assets);
}
```

**Fixed:**
```solidity
function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
    shares = totalSupply == 0 ? assets : assets * totalSupply / totalAssets();
    _mint(receiver, shares);
    asset.transferFrom(msg.sender, address(this), assets);
}

// Mitigation 1: Virtual offset (OpenZeppelin pattern)
function _decimalsOffset() internal pure override returns (uint8) { return 3; }
// Adds 1e3 virtual shares/assets, making inflation attack cost 1000x more

// Mitigation 2: Mint dead shares on first deposit
constructor() {
    _mint(address(1), 1e3); // Dead shares prevent inflation
}
```

### Pattern 2: Direct Transfer / Donation Attacks
An attacker sends tokens directly to the vault (bypassing deposit), inflating totalAssets without increasing totalSupply. This corrupts the exchange rate, inflates yield calculations, or bricks the vault when totalAssets > 0 but totalSupply == 0.

**Vulnerable:**
```solidity
// BUG: Yield uses balanceOf — sees donations as real yield
function previewYield(address caller, uint256 shares) public view returns (uint256) {
    uint256 totalUnderlying = asset.balanceOf(address(this)); // Includes donations!
    uint256 totalYield = totalUnderlying - depositedBase; // Inflated by donation
    return totalYield * shares / totalSupply;
}

// BUG: Direct transfer bricks vault permanently
function deposit(uint256 assets, address receiver) internal returns (uint256 shares) {
    uint256 totalAssets_ = totalAssets();
    // Reverts if totalAssets > 0 but totalSupply == 0 (someone sent tokens directly)
    if (!((totalAssets_ == 0 && totalSupply() == 0) || (totalSupply() > 0 && totalAssets_ > 0)))
        revert InvalidAssetsState();
}
```

**Fixed:**
```solidity
// Track deposits internally, not via balanceOf
function previewYield(address caller, uint256 shares) public view returns (uint256) {
    uint256 totalYield = _accruedYield; // Internal tracking, immune to donations
    return totalYield * shares / totalSupply;
}

// Use internal accounting for totalAssets
function totalAssets() public view returns (uint256) {
    return _trackedAssets; // Not balanceOf — immune to direct transfers
}

// Or: sweep excess on deposit
function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
    uint256 excess = asset.balanceOf(address(this)) - _trackedAssets;
    if (excess > 0) _trackedAssets += excess; // Absorb donations into accounting
    shares = assets * totalSupply() / totalAssets();
    _mint(receiver, shares);
}
```

### Pattern 3: Rounding Direction Errors
ERC-4626 requires deposits to round in favor of the vault (down for shares-out) and withdrawals to round in favor of the vault (up for assets-in). Incorrect rounding enables systematic value extraction through zero-share withdrawals or favorable preview exploits.

**Vulnerable:**
```solidity
// BUG: previewMint rounds down — user pays less than they should
function previewMint(uint256 shares) public view returns (uint256) {
    return shares.mulDivDown(totalAssets(), totalSupply()); // Should round UP (vault's favor)
}

// BUG: Division before multiplication zeroes small amounts
uint256 entitledAmount = amount.divWadDown(finalTVL).mulDivDown(claimTVL, 1 ether);
// If amount < finalTVL, first division = 0, entire result = 0

// BUG: Zero-share withdrawal — free asset extraction
function withdraw(uint256 assets, address receiver, address owner) public returns (uint256 shares) {
    shares = assets * totalSupply / totalAssets; // Rounds down to 0 for small assets
    _burn(owner, shares); // Burns 0 shares
    asset.transfer(receiver, assets); // Sends real assets for free
}
```

**Fixed:**
```solidity
// previewMint rounds UP (vault charges more)
function previewMint(uint256 shares) public view returns (uint256) {
    return shares.mulDivUp(totalAssets(), totalSupply());
}

// Multiply before divide to preserve precision
uint256 entitledAmount = (amount * claimTVL) / finalTVL;

// Require non-zero shares on withdrawal
function withdraw(uint256 assets, address receiver, address owner) public returns (uint256 shares) {
    shares = assets.mulDivUp(totalSupply, totalAssets); // Round UP
    require(shares > 0, "zero shares");
    _burn(owner, shares);
    asset.transfer(receiver, assets);
}
```

### Pattern 4: Share / Asset Type Confusion
Functions pass shares where assets are expected (or vice versa). This causes incorrect minting, wrong redemption amounts, or broken fee calculations. Common in vault hierarchies where inner/outer vaults use different units.

**Vulnerable:**
```solidity
// BUG: _amountOut treated as both shares (for minting) and assets (for fees)
function liquidate(address account, uint256 _amountOut) public {
    _mint(account, _amountOut); // Treated as shares
    uint256 fee = (_amountOut * FEE) / PRECISION; // Also treated as assets!
}

// BUG: Shares passed to rewardPool expecting assets
function redeem(uint256 shares, address receiver, address owner) public returns (uint256) {
    uint256 assets = IPool(rewardPool).redeem(shares, ...); // rewardPool expects assets!
}

// BUG: WAD-scale returned but caller expects token-scale
function _executeAction(uint256 amount) internal returns (uint256) {
    return amount * 1e18 / tokenScale; // Returns WAD, caller uses as raw token amount
}
```

**Fixed:**
```solidity
function liquidate(address account, uint256 _amountOut) public {
    uint256 assets = convertToAssets(_amountOut); // Convert shares to assets for fee calc
    _mint(account, _amountOut);
    uint256 fee = (assets * FEE) / PRECISION;
}

function redeem(uint256 shares, address receiver, address owner) public returns (uint256) {
    uint256 assets = convertToAssets(shares); // Convert first
    uint256 received = IPool(rewardPool).redeem(assets, ...);
}
```

### Pattern 5: Sandwich Attacks on Vault Operations
Attacker front-runs a large deposit by depositing first (getting more shares at the old rate), then back-runs after the victim's deposit increases totalAssets. Also applies to reward distribution events and fee changes that shift the exchange rate.

**Vulnerable:**
```solidity
// BUG: Reward distribution changes exchange rate — sandwichable
function distributeReward(uint256 amount) external onlyRewarder {
    asset.transferFrom(msg.sender, address(this), amount);
    // totalAssets jumps instantly — front-runner already deposited, withdraws after
}

// BUG: Fee shares minted before reward distribution
function harvest() external {
    _mintFeeShares(); // Mints shares at OLD rate (cheaper)
    _distributeRewards(); // Rate jumps — fee recipient profits
}
```

**Fixed:**
```solidity
// Drip rewards over time to prevent sandwich
function distributeReward(uint256 amount) external onlyRewarder {
    asset.transferFrom(msg.sender, address(this), amount);
    rewardEndTime = block.timestamp + DRIP_DURATION;
    rewardRate = amount / DRIP_DURATION;
}

function totalAssets() public view returns (uint256) {
    uint256 elapsed = Math.min(block.timestamp - lastUpdate, DRIP_DURATION);
    return _baseAssets + elapsed * rewardRate; // Gradual increase
}

// Mint fee shares AFTER reward distribution at new rate
function harvest() external {
    _distributeRewards();
    _mintFeeShares(); // Minted at new (higher) rate — no free profit
}
```

### Detect
For every tokenized vault: (1) verify first-deposit protection exists (virtual offset, dead shares, or minimum deposit), (2) verify totalAssets uses internal accounting immune to direct transfers/donations, (3) verify rounding direction favors the vault in all preview/convert functions and no zero-share withdrawal is possible, (4) verify shares and assets are never used interchangeably across function boundaries, (5) verify exchange rate changes (rewards, fees, harvests) are drip-distributed or sandwich-resistant.

### Remediation
- Add virtual offset or dead shares for first deposit.
- Use internal asset tracking immune to direct transfers/donations.
- Round in vault's favor everywhere.
- Maintain strict share/asset type separation.
- Drip-distribute rewards over time.

## CL-VAULT-05: ERC-4626 Vault Compliance Invariant

**Rule:** `EVM-VAULT-V4626-01`
**Severity:** informational-medium

### Description
When a contract implements or claims to implement the ERC-4626 Tokenized Vault Standard, the vault implementation may deviate from the ERC-4626 specification by disabling mandatory functions, returning inconsistent max* view functions, having decimal mismatches, emitting non-standard events, or breaking allowance flows. This causes yield aggregators and routers to fail composing with the vault, max limit functions to report wrong values causing transaction reverts, non-compliant events to break indexers, and missing allowance checks to enable unauthorized redemptions.

> **Cross-reference:** Share/asset unit confusion (e.g. redeem passing shares where assets are expected) is covered comprehensively by **EVM-VAULT-SHARE-01 Pattern 4**.

### Patterns
### Pattern 1: Disabled Mandatory Functions
The vault disables mint, previewMint, withdraw, or previewWithdraw by reverting, breaking the "exact output" accounting flow required by ERC-4626.

**Vulnerable:**
```solidity
contract PartialVault is ERC4626 {
    // BUG: mint disabled — aggregators expecting exact-shares-in flow break
    function mint(uint256 shares, address receiver) public override returns (uint256) {
        revert("mint disabled");
    }

    function previewMint(uint256 shares) public view override returns (uint256) {
        revert("not supported");
    }

    // BUG: Custom withdrawal ignores receiver parameter
    function withdraw(uint256 assets, address, address owner) public override returns (uint256) {
        // Always sends to msg.sender, ignoring receiver — breaks composability
        uint256 shares = previewWithdraw(assets);
        _burn(owner, shares);
        IERC20(asset()).transfer(msg.sender, assets);
        return shares;
    }
}
```

**Fixed:**
```solidity
contract CompliantVault is ERC4626 {
    function mint(uint256 shares, address receiver) public override returns (uint256) {
        uint256 assets = previewMint(shares);
        // Include fee in preview so exact-shares flow works
        IERC20(asset()).transferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares);
        return assets;
    }

    function withdraw(uint256 assets, address receiver, address owner) public override returns (uint256) {
        uint256 shares = previewWithdraw(assets);
        if (msg.sender != owner) _spendAllowance(owner, msg.sender, shares);
        _burn(owner, shares);
        IERC20(asset()).transfer(receiver, assets);
        emit Withdraw(msg.sender, receiver, owner, assets, shares);
        return shares;
    }
}
```

### Pattern 2: Inconsistent Max Limit Functions
maxDeposit/maxMint return non-zero when the vault is paused. maxWithdraw reverts instead of returning 0. Max functions not updated to reflect custom deposit/withdrawal overrides or caps.

**Vulnerable:**
```solidity
contract PausableVault is ERC4626, Pausable {
    function deposit(uint256 assets, address receiver) public override whenNotPaused returns (uint256) {
        return super.deposit(assets, receiver);
    }

    // BUG: Returns max even when paused — ERC-4626 requires 0 when disabled
    function maxDeposit(address) public view override returns (uint256) {
        return type(uint256).max;
    }

    // BUG: Reverts instead of returning 0 — violates ERC-4626 MUST NOT revert
    function maxWithdraw(address owner) public view override returns (uint256) {
        require(!paused(), "paused");
        return convertToAssets(balanceOf(owner));
    }
}
```

**Fixed:**
```solidity
contract PausableVault is ERC4626, Pausable {
    function maxDeposit(address) public view override returns (uint256) {
        return paused() ? 0 : type(uint256).max;
    }

    function maxMint(address) public view override returns (uint256) {
        return paused() ? 0 : type(uint256).max;
    }

    function maxWithdraw(address owner) public view override returns (uint256) {
        return paused() ? 0 : convertToAssets(balanceOf(owner));
    }
}
```

### Pattern 3: Decimal Mismatch and Overflow in Uncapped Limits
Vault decimals differ from underlying asset decimals, breaking off-chain accounting. maxMint converts type(uint256).max through convertToAssets causing overflow instead of returning max directly.

**Vulnerable:**
```solidity
contract DecimalVault is ERC4626 {
    // BUG: Vault has 18 decimals but underlying USDC has 6
    // 1 share != 1 asset in display — every integration must special-case

    function maxMint(address) public view override returns (uint256) {
        // BUG: convertToAssets(type(uint256).max) overflows
        return convertToShares(maxDeposit(address(0)));
    }
}
```

**Fixed:**
```solidity
contract DecimalVault is ERC4626 {
    constructor(IERC20 asset_) ERC4626(asset_) ERC20("Vault", "vUSDC") {
        // ERC-4626 recommendation: match underlying decimals
        require(decimals() >= IERC20Metadata(address(asset_)).decimals());
    }

    function maxMint(address) public view override returns (uint256) {
        // Return max directly for uncapped vaults
        return type(uint256).max;
    }
}
```

### Pattern 4: Non-Standard Events and Missing Allowance Flows
Custom events instead of standard Deposit/Withdraw events break indexers. Missing allowance check when caller != owner in withdraw/redeem. Binary approval (approve/reject) instead of granular share amounts.

**Vulnerable:**
```solidity
contract NonStandardVault is ERC4626 {
    // BUG: Custom event instead of standard ERC-4626 Deposit event
    event VaultDeposit(address user, uint256 amount);

    function deposit(uint256 assets, address receiver) public override returns (uint256) {
        uint256 shares = previewDeposit(assets);
        IERC20(asset()).transferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares);
        emit VaultDeposit(receiver, assets);  // Non-standard
        return shares;
    }

    // BUG: No allowance check — anyone can redeem owner's shares
    function redeem(uint256 shares, address receiver, address owner) public override returns (uint256) {
        uint256 assets = convertToAssets(shares);
        _burn(owner, shares);
        IERC20(asset()).transfer(receiver, assets);
        return assets;
    }
}
```

**Fixed:**
```solidity
contract StandardVault is ERC4626 {
    function deposit(uint256 assets, address receiver) public override returns (uint256) {
        uint256 shares = previewDeposit(assets);
        IERC20(asset()).transferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares);
        emit Deposit(msg.sender, receiver, assets, shares);
        return shares;
    }

    function redeem(uint256 shares, address receiver, address owner) public override returns (uint256) {
        if (msg.sender != owner) {
            _spendAllowance(owner, msg.sender, shares);
        }
        uint256 assets = convertToAssets(shares);
        _burn(owner, shares);
        IERC20(asset()).transfer(receiver, assets);
        emit Withdraw(msg.sender, receiver, owner, assets, shares);
        return assets;
    }
}
```

### Detect
For every ERC-4626 implementation: (1) verify all mandatory functions are implemented and not disabled, (2) verify max* functions return 0 when operations are disabled and never revert, (3) verify vault decimals match underlying and max functions handle overflow, (4) verify standard events are emitted and allowance is enforced when caller != owner. See also EVM-VAULT-SHARE-01 for share/asset unit confusion.

### Remediation
- Implement all mandatory ERC-4626 functions.
- Ensure max* functions reflect actual limits including pause state and never revert.
- Mirror underlying decimals.
- Use standard events.
- Support receiver/owner separation and enforce allowance for third-party operations.
- For share/asset unit confusion, see EVM-VAULT-SHARE-01.

## CL-VAULT-06: Reward & Yield Distribution Invariant

**Rule:** `EVM-VAULT-YIELD-01`
**Severity:** high-critical

### Description
When a vault distributes rewards, yield, or emissions to stakers/depositors through a reward-per-token, vesting, or epoch-based distribution mechanism, reward distribution fails when state is not updated before claims, precision is lost through division-before-multiplication, reward periods are reset by dust amounts, vesting entries overwrite accumulated rewards, or reward tokens can be drained by admins.

### Patterns
### Pattern 1: Missing State Update Before Reward Claim
The reward integral or reward-per-token is not updated before a claim or balance change. Accrued rewards since the last checkpoint are permanently lost because the claim resets the user's tracking without capturing pending amounts.

**Vulnerable:**
```solidity
// BUG: Fetches new rewards without updating integral — pending rewards lost
function fetchRewards() external {
    _fetchRewards(); // Resets reward source without capturing accrued
}

// BUG: Balance change without reward checkpoint
function transfer(address to, uint256 amount) public override returns (bool) {
    // Missing: _updateReward(msg.sender); _updateReward(to);
    _transfer(msg.sender, to, amount);
    return true;
}
```

**Fixed:**
```solidity
function fetchRewards() external {
    _updateIntegrals(address(0), 0, totalSupply); // Capture all pending
    _fetchRewards();
}

function transfer(address to, uint256 amount) public override returns (bool) {
    _updateReward(msg.sender);
    _updateReward(to);
    _transfer(msg.sender, to, amount);
    return true;
}
```

### Pattern 2: Reward Precision Loss
Division-before-multiplication zeroes small allocations. When per-user reward amounts are computed by first dividing (weight/totalWeight) then multiplying by emissions, users with small weights receive zero. Also affects fee distributions where percentage is computed before applying to amount.

**Vulnerable:**
```solidity
// BUG: Division first — small weights get zero
uint256 votePct = receiverWeight / totalWeight; // Rounds to 0 for small weights
uint256 amount = votePct * weeklyEmissions; // 0 * anything = 0

// BUG: rewardPerToken underflows for low reward rates
uint256 rewardPerToken = (rewardRate * elapsed * 1e18) / totalSupply;
// If rewardRate * elapsed * 1e18 < totalSupply, result is 0 — rewards accumulate nowhere
```

**Fixed:**
```solidity
// Multiply first, divide last
uint256 amount = (weeklyEmissions * receiverWeight) / totalWeight;

// Use higher precision scaling
uint256 rewardPerToken = (rewardRate * elapsed * PRECISION) / totalSupply;
// where PRECISION = 1e36 or higher to avoid zero truncation
```

### Pattern 3: Reward Overwrite and Dust Griefing
New reward notifications overwrite accumulated but unclaimed rewards. An attacker sends 1 wei of reward token to trigger `_notifyReward`, resetting the distribution period and diluting existing rewards over the new (extended) period.

**Vulnerable:**
```solidity
// BUG: New vesting entry overwrites accumulated rewards
function vestTokens(address user, uint256 amount) external {
    if (user == address(this)) {
        _notifyReward(address(rdntToken), amount); // Overwrites existing!
        return;
    }
}

// BUG: 1-wei transfer triggers reward notification
function _notifyUnseenReward(address token) internal {
    uint256 unseen = IERC20(token).balanceOf(address(this)) - tracked[token];
    if (unseen > 0) {
        _notifyReward(token, unseen); // Even 1 wei resets distribution period!
    }
}

// BUG: Zero-amount notifyRewardAmount extends period with no new rewards
function notifyRewardAmount(uint256 reward) external {
    rewardRate = (remaining + reward) / DURATION; // If reward=0, dilutes remaining
    periodFinish = block.timestamp + DURATION;
}
```

**Fixed:**
```solidity
// Update existing rewards before new notification
function vestTokens(address user, uint256 amount) external {
    if (user == address(this)) {
        _updateReward(address(this)); // Capture existing first
        _notifyReward(address(rdntToken), amount);
        return;
    }
}

// Minimum threshold for reward notifications
function _notifyUnseenReward(address token) internal {
    uint256 unseen = IERC20(token).balanceOf(address(this)) - tracked[token];
    if (unseen > MIN_REWARD_THRESHOLD) {
        _notifyReward(token, unseen);
    }
}

// Require non-zero reward amount
function notifyRewardAmount(uint256 reward) external {
    require(reward > 0, "zero reward");
    rewardRate = (remaining + reward) / DURATION;
    periodFinish = block.timestamp + DURATION;
}
```

### Pattern 4: Fee Capture and Range Re-entry Timing Attacks
Attacker times deposits to capture accumulated but undistributed fees or rewards. In concentrated liquidity vaults, fees accumulate while positions are out of range -- attacker deposits just before rebalance to capture disproportionate fees. In staking, attacker deposits before reward distribution and withdraws immediately after.

**Vulnerable:**
```solidity
// BUG: New LP added to denominator before pending fees distributed
function addLiquidity(uint256 amount) external {
    totalLiquidity += amount; // Dilutes existing fee pool
    _mint(msg.sender, amount);
    // Accumulated fees now shared with new depositor who contributed nothing
}

// BUG: Expired vault tokens continue earning rewards
function claimReward(uint256 epochId, uint256 tokenId) external {
    // No check that token hasn't expired — worthless tokens claim from future epochs
    uint256 reward = _calculateReward(epochId, tokenId);
    rewardToken.transfer(msg.sender, reward);
}
```

**Fixed:**
```solidity
// Distribute pending fees before adding new liquidity
function addLiquidity(uint256 amount) external {
    _distributePendingFees(); // Existing holders get their share first
    totalLiquidity += amount;
    _mint(msg.sender, amount);
}

// Validate token hasn't expired
function claimReward(uint256 epochId, uint256 tokenId) external {
    require(!isExpired(tokenId), "expired token");
    uint256 reward = _calculateReward(epochId, tokenId);
    rewardToken.transfer(msg.sender, reward);
}
```

### Pattern 5: Reward Token Recovery Backdoor
Admin `recoverERC20` function does not exclude reward tokens, allowing the owner to withdraw tokens meant for user distribution. Also: emergency withdrawal functions that drain active reward pools.

**Vulnerable:**
```solidity
// BUG: No reward token exclusion — admin can steal user rewards
function recoverERC20(address token, uint256 amount) external onlyOwner {
    require(token != address(stakingToken), "!staking");
    // Missing: require(token != rewardToken)
    ERC20(token).safeTransfer(owner, amount);
}

// BUG: Emergency withdraw drains active reward pool
function emergencyWithdraw() external onlyOwner {
    uint256 bal = rewardToken.balanceOf(address(this));
    rewardToken.transfer(owner, bal); // Users lose all pending rewards
}
```

**Fixed:**
```solidity
function recoverERC20(address token, uint256 amount) external onlyOwner {
    require(token != address(stakingToken), "!staking");
    require(token != address(rewardToken), "!reward");
    for (uint i = 0; i < extraRewards.length; i++) {
        require(token != extraRewards[i], "!extra reward");
    }
    ERC20(token).safeTransfer(owner, amount);
}

// Emergency: only withdraw excess beyond owed rewards
function emergencyRecoverExcess() external onlyOwner {
    uint256 owed = _totalOwedRewards();
    uint256 bal = rewardToken.balanceOf(address(this));
    require(bal > owed, "no excess");
    rewardToken.transfer(owner, bal - owed);
}
```

### Detect
For every vault with reward distribution: (1) verify reward integrals are updated before any claim or balance change, (2) verify reward calculations multiply before dividing to prevent precision loss, (3) verify reward notifications cannot be griefed via dust amounts or zero-value calls, (4) verify fee/reward distributions occur before new deposits dilute the pool, (5) verify recoverERC20 excludes all reward tokens and emergency functions don't drain active pools.

### Remediation
- Update integrals before claims/transfers.
- Multiply before dividing to prevent precision loss.
- Add minimum thresholds for reward notifications.
- Distribute fees before accepting new liquidity.
- Exclude reward tokens from recovery functions.
