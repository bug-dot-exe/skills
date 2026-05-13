## CL-ERC20-01: ERC-20 Token Compatibility Invariant

**Rule:** `EVM-ERC20-COMPAT-01`
**Severity:** medium-high

### Description
The contract integrates with arbitrary ERC-20 tokens and must handle the diversity of real-world token behaviors beyond the minimal standard. Token compatibility breaks when approval patterns trigger front-running or revert on non-zero allowance, decimal handling is hardcoded, blocklist/pausable tokens freeze the protocol, permit signatures are front-runnable, or exotic tokens (double-entry, upgradeable, flash-mintable) violate standard assumptions.

### Patterns
### Pattern 1: Approval Race and Stale Allowances
Standard `approve` is front-runnable (old + new allowance double-spend). `safeApprove` reverts if current allowance != 0. Some tokens reject `type(uint256).max`. Stale approvals to old router/contract addresses persist after migration.

**Vulnerable:**
```solidity
// BUG: safeApprove reverts if allowance not zero
token.safeApprove(spender, newAmount); // Reverts if current > 0!

// BUG: Stale approval after router update
function setRouter(address newRouter) external onlyOwner {
    router = newRouter;
    // Old router still has infinite approval!
}

// BUG: Max approval to upgradeable contract
token.approve(upgradeableVault, type(uint256).max); // Vault upgrade can drain
```

**Fixed:**
```solidity
// Use forceApprove (OZ 5.x) or reset-then-set
token.forceApprove(spender, newAmount); // Handles non-zero allowance
// Or:
token.safeApprove(spender, 0);
token.safeApprove(spender, newAmount);

// Revoke old router on migration
function setRouter(address newRouter) external onlyOwner {
    token.safeApprove(router, 0); // Revoke old
    token.safeApprove(newRouter, type(uint256).max);
    router = newRouter;
}

// Use exact amounts instead of infinite approval
token.safeApprove(vault, exactAmount);
```

### Pattern 2: Decimal Mismatch
Hardcoded 18 decimals breaks for USDC (6), WBTC (8), or tokens with >18 decimals. Arithmetic like `18 - decimals()` underflows for >18.

**Vulnerable:**
```solidity
// BUG: Hardcoded 18 decimals — USDC has 6
uint256 normalizedAmount = amount * 1e18 / 10**18; // No-op! Should use token decimals

// BUG: Underflows for tokens with >18 decimals
uint256 scale = 10 ** (18 - token.decimals()); // Reverts if decimals > 18!

// BUG: Decimal cached at deploy but token is upgradeable
uint8 immutable tokenDecimals = token.decimals(); // Could change after upgrade
```

**Fixed:**
```solidity
// Query decimals dynamically
uint8 dec = IERC20Metadata(token).decimals();
uint256 normalizedAmount;
if (dec <= 18) {
    normalizedAmount = amount * 10 ** (18 - dec);
} else {
    normalizedAmount = amount / 10 ** (dec - 18);
}
```

### Pattern 3: Blocklist and Pausable Token DoS
USDC, USDT, and others have admin-controlled blocklists and pause mechanisms. A blocklisted fee recipient blocks all transfers that route through them.

**Vulnerable:**
```solidity
// BUG: Blocklisted fee recipient blocks all trades
function swap(uint256 amount) external {
    token.safeTransfer(feeRecipient, fee); // Reverts if feeRecipient blocklisted!
    token.safeTransfer(msg.sender, amount - fee);
}

// BUG: Paused token locks protocol
function withdraw(uint256 amount) external {
    usdc.safeTransfer(msg.sender, amount);
}
```

**Fixed:**
```solidity
// Use pull pattern for fees
function swap(uint256 amount) external {
    accruedFees[feeRecipient] += fee; // Track, don't push
    token.safeTransfer(msg.sender, amount - fee);
}

function claimFees() external {
    uint256 amount = accruedFees[msg.sender];
    accruedFees[msg.sender] = 0;
    try token.transfer(msg.sender, amount) {} catch {
        accruedFees[msg.sender] = amount; // Restore on failure
    }
}

// Emergency rescue for paused tokens
function rescueToken(address token, address to, uint256 amount) external onlyOwner {
    IERC20(token).safeTransfer(to, amount);
}
```

### Pattern 4: Permit Front-Running
Attacker extracts permit signature from mempool, front-runs to consume the nonce, and the original transaction reverts on invalid nonce.

**Vulnerable:**
```solidity
// BUG: Permit + action as separate calls — front-runnable
function depositWithPermit(uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
    token.permit(msg.sender, address(this), amount, deadline, v, r, s); // Front-runnable!
    token.safeTransferFrom(msg.sender, address(this), amount);
}
```

**Fixed:**
```solidity
function depositWithPermit(uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
    // Wrap permit in try/catch — if front-run, permit already granted
    try token.permit(msg.sender, address(this), amount, deadline, v, r, s) {} catch {}
    // transferFrom works regardless — either permit succeeded or was front-run
    token.safeTransferFrom(msg.sender, address(this), amount);
}
```

### Pattern 5: Double-Entry Points and Exotic Behaviors
SNX accessible via legacy + current contract addresses — same balance counted twice or swept via secondary. Upgradeable token proxies can change behavior post-integration.

**Vulnerable:**
```solidity
// BUG: Same balance counted via two addresses (SNX)
function totalValue() public view returns (uint256) {
    return token1.balanceOf(address(this)) + token2.balanceOf(address(this));
    // If token1 and token2 are same underlying (SNX), double-counted!
}

// BUG: Sweep function drains via secondary entry point
function sweepToken(address token) external onlyOwner {
    require(token != address(mainToken), "!main");
    IERC20(token).safeTransfer(owner, IERC20(token).balanceOf(address(this)));
    // Attacker passes legacy SNX address — drains mainToken balance!
}
```

**Fixed:**
```solidity
// Maintain canonical token mapping
mapping(address => address) public canonicalToken;

function sweepToken(address token) external onlyOwner {
    address canonical = canonicalToken[token];
    require(canonical == address(0) || canonical != address(mainToken), "protected");
    IERC20(token).safeTransfer(owner, IERC20(token).balanceOf(address(this)));
}

// Check extcodesize before interacting
function safeBalanceOf(address token, address account) internal view returns (uint256) {
    if (token.code.length == 0) return 0;
    return IERC20(token).balanceOf(account);
}
```

### Detect
For every ERC-20 integration: (1) verify approval patterns handle non-zero allowance reset and stale approvals are revoked on migration, (2) verify decimal handling queries dynamically and handles >18 decimals, (3) verify blocklist/pausable tokens use pull patterns and have rescue functions, (4) verify permit calls are wrapped in try/catch to handle front-running, (5) verify double-entry tokens are mapped canonically and sweep functions check secondary addresses.

### Remediation
Use forceApprove and revoke on migration. Query decimals dynamically. Use pull patterns for blocklist-sensitive flows. Wrap permit in try/catch. Map canonical token addresses.

## CL-ERC20-02: ERC-20 Token Transfer Integrity Invariant

**Rule:** `EVM-ERC20-TRANSFER-01`
**Severity:** medium-high

### Description
The contract transfers ERC-20 tokens using transfer, transferFrom, or low-level call, and must handle the diversity of real-world token implementations. Token transfers fail silently or corrupt state when return values are unchecked (USDT returns void), fee-on-transfer tokens deliver less than requested, ERC-777/ERC-1363 hooks enable reentrancy, self-transfers corrupt cached balances, or edge-case tokens revert on zero amounts.

### Patterns
### Pattern 1: Unchecked Transfer Return Values
USDT and some tokens don't return a boolean from transfer/transferFrom. Standard IERC20 interface expects bool, causing abi.decode to revert. Low-level calls to EOAs succeed silently.

**Vulnerable:**
```solidity
// BUG: USDT returns void — abi.decode reverts
IERC20(usdt).transfer(to, amount); // Reverts on USDT!

// BUG: Low-level call to EOA succeeds with no transfer
(bool success, ) = token.call(abi.encodeWithSelector(IERC20.transfer.selector, to, amount));
require(success); // true even if token is EOA (no code)!

// BUG: Return value ignored — silent failure
token.transfer(to, amount); // Might return false, never checked
```

**Fixed:**
```solidity
// Use SafeERC20 — handles void returns and checks success
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
using SafeERC20 for IERC20;

IERC20(usdt).safeTransfer(to, amount); // Works with USDT
IERC20(token).safeTransferFrom(from, to, amount); // Checks return or void
```

### Pattern 2: Fee-on-Transfer and Rebasing Token Accounting
Fee-on-transfer tokens deliver less than requested. Rebasing tokens change balanceOf between transactions. Recording requested amount instead of measuring actual receipt creates accounting gaps.

**Vulnerable:**
```solidity
// BUG: Records requested amount — actual received is less (FOT tax)
function deposit(address token, uint256 amount) external {
    IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    balances[msg.sender] += amount; // Could be amount - 2% fee!
}

// BUG: Cached balance stale for rebasing tokens
function deposit(uint256 amount) external {
    stETH.safeTransferFrom(msg.sender, address(this), amount);
    deposits[msg.sender] = amount; // stETH rebases — this goes stale instantly
}
```

**Fixed:**
```solidity
// Measure actual received via balance delta
function deposit(address token, uint256 amount) external {
    uint256 before = IERC20(token).balanceOf(address(this));
    IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    uint256 received = IERC20(token).balanceOf(address(this)) - before;
    balances[msg.sender] += received; // Actual amount after fees
}

// For rebasing: use shares-based accounting (wstETH) or read fresh
function getBalance(address user) public view returns (uint256) {
    return wstETH.getStETHByWstETH(wstETHShares[user]); // Always fresh
}
```

### Pattern 3: Transfer Hook Reentrancy (ERC-777 / ERC-1363)
ERC-777 fires `tokensToSend` and `tokensReceived`. ERC-1363 fires `onTransferReceived`. If state is modified after the token transfer, attackers re-enter during the hook.

**Vulnerable:**
```solidity
// BUG: State updated after transfer — ERC-777 hook re-enters
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    token.safeTransfer(msg.sender, amount); // ERC-777: tokensReceived fires HERE
    balances[msg.sender] -= amount;
}
```

**Fixed:**
```solidity
function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount; // CEI: update state BEFORE transfer
    token.safeTransfer(msg.sender, amount);
}
```

### Pattern 4: Self-Transfer State Corruption
When from == to in a transfer, cached balance variables become stale. The second write overwrites the first, causing double-credit.

**Vulnerable:**
```solidity
// BUG: Self-transfer with cached balances
function _transfer(address from, address to, uint256 amount) internal {
    uint256 fromBal = balances[from];
    uint256 toBal = balances[to];     // If from==to, this is same slot!
    balances[from] = fromBal - amount;
    balances[to] = toBal + amount;    // Overwrites the subtraction!
}
```

**Fixed:**
```solidity
function _transfer(address from, address to, uint256 amount) internal {
    if (from == to) return; // No-op for self-transfer
    // Or: use storage directly without caching
    balances[from] -= amount;
    balances[to] += amount;
}
```

### Pattern 5: Zero-Value and Zero-Address Edge Cases
Some tokens (BNB, LEND) revert on zero-amount transfers. Others burn to address(0) instead of reverting.

**Vulnerable:**
```solidity
// BUG: Zero amount reverts on BNB
function distribute(address[] calldata recipients, uint256[] calldata amounts) external {
    for (uint i = 0; i < recipients.length; i++) {
        token.safeTransfer(recipients[i], amounts[i]); // Reverts if amounts[i] == 0
    }
}

// BUG: Transfer to address(0) burns tokens on some implementations
function sweep(address token, address to) external onlyOwner {
    IERC20(token).safeTransfer(to, IERC20(token).balanceOf(address(this)));
}
```

**Fixed:**
```solidity
function distribute(address[] calldata recipients, uint256[] calldata amounts) external {
    for (uint i = 0; i < recipients.length; i++) {
        if (amounts[i] > 0) {
            token.safeTransfer(recipients[i], amounts[i]);
        }
    }
}

function sweep(address token, address to) external onlyOwner {
    require(to != address(0), "zero address");
    uint256 bal = IERC20(token).balanceOf(address(this));
    if (bal > 0) IERC20(token).safeTransfer(to, bal);
}
```

### Detect
For every ERC-20 transfer: (1) verify SafeERC20 or equivalent is used for all transfer/transferFrom/approve calls, (2) verify amount accounting uses balance-delta measurement for FOT/rebasing tokens, (3) verify reentrancy guards protect against ERC-777/1363 hooks with CEI pattern, (4) verify self-transfers (from==to) are handled without cached-balance corruption, (5) verify zero-amount and zero-address edge cases are guarded.

### Remediation
Use SafeERC20. Measure via balance delta. Apply nonReentrant + CEI. Handle self-transfers. Guard zero amounts and addresses.
