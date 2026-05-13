## CL-ACC-01: Privileged Function Access Control Invariant

**Rule:** `EVM-ACC-AUTH-01`
**Severity:** medium-critical

### Description
Functions intended for restricted use are accessible to unauthorized callers due to missing or incorrect access control enforcement. The protocol defines contracts with functions that modify state, transfer assets, emit administrative events, manage roles, or interact with external contracts via delegatecall/call, but these functions lack proper `onlyOwner`/`onlyRole` modifiers, `require(msg.sender == ...)` checks, use the wrong role, have conditionally bypassed checks, or have inverted assertion logic. Unauthorized actors can corrupt protocol state, drain funds, manipulate balances, spoof events, escalate privileges, destroy contracts, or hijack proxy implementations.

### Patterns
### Pattern 1: State Mutators Without Auth
Any `public`/`external` function that writes to storage, transfers assets, emits administrative events, or calls external contracts without a modifier or `msg.sender` check. Includes setters for protocol parameters, fee recipients, oracle addresses, and strategy configurations.

**Vulnerable:**
```solidity
// Anyone can redirect fees — no access control
function updateFeeRecipient(address newRecipient) external {
    feeRecipient = newRecipient;
}
```

**Fixed:**
```solidity
// Proper modifier-based access control
function updateFeeRecipient(address newRecipient) external onlyOwner {
    feeRecipient = newRecipient;
}
```

### Pattern 2: Unprotected initialize() in Proxies
Proxy implementation contracts where `initialize()` lacks `initializer` modifier or can be called by anyone, enabling frontrunning of proxy initialization to set attacker as admin.

**Vulnerable:**
```solidity
// Frontrunnable — no initializer guard
function initialize(address _admin) external {
    admin = _admin;
}
```

**Fixed:**
```solidity
// Initializer guard prevents re-initialization
function initialize(address _admin) external initializer {
    admin = _admin;
}
```

### Pattern 3: Public Mint / Burn Without Auth
`mint()` or `burn()` functions callable by any address without role verification, enabling arbitrary token inflation or destruction.

**Vulnerable:**
```solidity
function mint(address to, uint256 amount) external {
    _mint(to, amount); // Anyone can mint
}
```

**Fixed:**
```solidity
function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
    _mint(to, amount);
}
```

### Pattern 4: Arbitrary From in transferFrom
Functions that accept a `from` parameter and call `transferFrom(from, ...)` without verifying `msg.sender == from` or that sufficient allowance exists, enabling unauthorized spending of other users' tokens.

**Vulnerable:**
```solidity
// Spends anyone's allowance without authorization
function depositFor(address from, uint256 amount) external {
    token.transferFrom(from, address(this), amount);
}
```

**Fixed:**
```solidity
function depositFor(address from, uint256 amount) external {
    require(msg.sender == from, "Unauthorized");
    token.transferFrom(from, address(this), amount);
}
```

### Pattern 5: Incorrect Caller Validation
Access control checks that validate the wrong entity: checking `msg.sender` when the actual authorized party is different (e.g., in hook callbacks, meta-transactions, or delegated calls), or checking against the wrong role.

**Vulnerable:**
```solidity
// Wrong role checked — operator should not have admin power
function setAdmin(address newAdmin) external onlyRole(OPERATOR_ROLE) {
    admin = newAdmin;
}
```

**Fixed:**
```solidity
function setAdmin(address newAdmin) external onlyRole(ADMIN_ROLE) {
    admin = newAdmin;
}
```

### Pattern 6: Conditional Access Control Bypass
Access control checks nested inside `if` blocks, time windows, or state conditionals that leave a permissionless execution path. If a time check wraps the auth check, the function is public outside that window.

**Vulnerable:**
```solidity
function withdraw(uint256 amount) external {
    if (block.timestamp < lockEnd) {
        require(msg.sender == owner, "Locked");
    }
    // After lockEnd, anyone can withdraw
    _transfer(msg.sender, amount);
}
```

**Fixed:**
```solidity
function withdraw(uint256 amount) external onlyOwner {
    if (block.timestamp < lockEnd) {
        revert("Still locked");
    }
    _transfer(msg.sender, amount);
}
```

### Pattern 7: Assertion Polarity / Logic Errors
Inverted boolean logic in access control: `require(!isAdmin[msg.sender])` instead of `require(isAdmin[msg.sender])`, or `||` instead of `&&` in multi-condition checks, or using `!=` instead of `==`.

**Vulnerable:**
```solidity
// BUG: inverted — blocks admins, allows everyone else
function withdraw(uint256 amount) external {
    require(!isAdmin[msg.sender], "Not authorized");
    _transfer(msg.sender, amount);
}
```

**Fixed:**
```solidity
function withdraw(uint256 amount) external {
    require(isAdmin[msg.sender], "Not authorized");
    _transfer(msg.sender, amount);
}
```

### Pattern 8: Inconsistent Enforcement Across Entry Points
Multiple entry points for the same privileged operation use different role checks, or some paths skip the check entirely. Includes direct factory calls bypassing validation wrappers.

**Vulnerable:**
```solidity
function setFeeA(uint256 fee) external onlyOwner { protocolFee = fee; }
function setFeeB(uint256 fee) external { protocolFee = fee; } // Same operation, no auth
```

**Fixed:**
```solidity
function setFeeA(uint256 fee) external onlyOwner { protocolFee = fee; }
function setFeeB(uint256 fee) external onlyOwner { protocolFee = fee; }
```

### Pattern 9: Delegatecall / Arbitrary Call Targets
Functions that execute `delegatecall`, low-level `.call`, or `selfdestruct` to user-supplied addresses without validation, enabling arbitrary code execution in the contract's storage context, destruction of implementation contracts, or fund theft via crafted calldata.

**Vulnerable:**
```solidity
function execute(address target, bytes calldata data) external {
    (bool ok, ) = target.delegatecall(data); // Anyone can hijack storage
    require(ok);
}
```

**Fixed:**
```solidity
function execute(address target, bytes calldata data) external onlyOwner {
    require(allowedTargets[target], "Invalid target");
    (bool ok, ) = target.delegatecall(data);
    require(ok);
}
```

### Pattern 10: Missing Callback Authentication
Flash loan callbacks, token receiver hooks (`onERC721Received`, `tokensReceived`), or Uniswap/Chainlink callbacks that don't verify `msg.sender` is the expected caller, enabling unauthorized execution.

**Vulnerable:**
```solidity
function uniswapV3SwapCallback(int256 amount0, int256 amount1, bytes calldata) external {
    // BUG: no msg.sender check — anyone can call
    token.transfer(msg.sender, uint256(amount0));
}
```

**Fixed:**
```solidity
function uniswapV3SwapCallback(int256 amount0, int256 amount1, bytes calldata) external {
    require(msg.sender == address(pool), "Unauthorized callback");
    token.transfer(msg.sender, uint256(amount0));
}
```

### Pattern 11: On-Behalf-Of Without Auth
Functions that act on behalf of another user (passing an `account` parameter) without verifying the caller is authorized by that account, enabling unauthorized state changes for arbitrary users.

**Vulnerable:**
```solidity
function claimFor(address account) external {
    uint256 rewards = pendingRewards[account];
    pendingRewards[account] = 0;
    token.transfer(account, rewards); // Anyone can trigger for any account
}
```

**Fixed:**
```solidity
function claimFor(address account) external {
    require(msg.sender == account || approved[account][msg.sender], "Unauthorized");
    uint256 rewards = pendingRewards[account];
    pendingRewards[account] = 0;
    token.transfer(account, rewards);
}
```

### Pattern 12: Redundant / Dead Access Control
Access control machinery that is defined but never enforced, commented-out checks, or `restricted` functions that are unreachable due to incorrect internal call patterns.

**Vulnerable:**
```solidity
modifier onlyAdmin() {
    require(msg.sender == admin, "Not admin");
    _;
}
// Modifier defined but never used on privileged functions
function setConfig(uint256 val) external {
    config = val; // Missing onlyAdmin
}
```

**Fixed:**
```solidity
function setConfig(uint256 val) external onlyAdmin {
    config = val;
}
```

### Detect
For every contract: (1) identify all functions mutating state, transferring assets, emitting administrative events, or calling external contracts, (2) verify each has unconditional access control via modifier or require, (3) verify the role checked matches the function's purpose, (4) verify assertion logic is correct, (5) verify consistency across all entry points including proxy initialization and callbacks, (6) verify delegatecall/call/selfdestruct targets are validated.

### Remediation
For every privileged function, enforce access control via OpenZeppelin modifiers (`onlyOwner`, `onlyRole`), explicit `require(msg.sender == ...)` checks, or `AccessManaged` patterns. Verify checks are unconditional, use the correct role, and have correct assertion logic. Guard `initialize()` with `initializer` modifier. Validate delegatecall/call targets. Authenticate callbacks.

## CL-ACC-02: Centralization Risk — Admin Can Damage Protocol

**Rule:** `EVM-ACC-CENT-01`
**Severity:** low

### Description
The protocol grants an admin account (EOA, multisig, or role) the ability to intentionally or accidentally cause material harm — such as draining user funds, bricking the protocol, inflating supply, or manipulating parameters — with no technical safeguard beyond key security. This is a trust assumption, not an exploitable bug. Severity is low because it requires a compromised or malicious admin, which is unlikely but has catastrophic impact.

### Patterns
### Pattern 1: Direct Fund Extraction
Admin can withdraw, sweep, or redirect user-deposited assets from pools, vaults, or escrows.

**Vulnerable:**
```solidity
function rescueTokens(address token, uint256 amount) external onlyOwner {
    IERC20(token).transfer(owner(), amount); // Can drain user funds
}
```

**Fixed:**
```solidity
function rescueTokens(address token, uint256 amount) external onlyOwner {
    require(token != address(stakingToken), "Cannot rescue staked tokens");
    IERC20(token).transfer(owner(), amount);
}
```

### Pattern 2: Uncapped Supply Control
Admin can mint or burn arbitrary token amounts without caps, rate limits, or governance.

**Vulnerable:**
```solidity
function mint(address to, uint256 amount) external onlyOwner {
    _mint(to, amount); // No supply cap
}
```

**Fixed:**
```solidity
uint256 public constant MAX_SUPPLY = 1_000_000e18;
function mint(address to, uint256 amount) external onlyOwner {
    require(totalSupply() + amount <= MAX_SUPPLY, "Cap exceeded");
    _mint(to, amount);
}
```

### Pattern 3: Unbounded Parameter Manipulation
Admin can change critical economic parameters (fees, rates, oracle addresses) immediately with no bounds, timelock, or delay — enabling frontrunning users.

**Vulnerable:**
```solidity
function setFee(uint256 newFee) external onlyOwner {
    fee = newFee; // Can set to 100%, no delay
}
```

**Fixed:**
```solidity
uint256 public constant MAX_FEE = 1000; // 10%
uint256 public constant TIMELOCK_DELAY = 2 days;
function proposeFee(uint256 newFee) external onlyOwner {
    require(newFee <= MAX_FEE, "Exceeds max");
    pendingFee = newFee;
    feeEffectiveTime = block.timestamp + TIMELOCK_DELAY;
}
```

### Pattern 4: Unguarded Upgrade Authority
Admin can upgrade proxy implementations instantly without timelock, governance vote, or user notification.

**Vulnerable:**
```solidity
function upgradeTo(address newImpl) external onlyOwner {
    _upgradeTo(newImpl); // Immediate, silent logic replacement
}
```

**Fixed:**
```solidity
function proposeUpgrade(address newImpl) external onlyOwner {
    pendingImplementation = newImpl;
    upgradeTimestamp = block.timestamp + UPGRADE_DELAY;
}
function executeUpgrade() external onlyOwner {
    require(block.timestamp >= upgradeTimestamp, "Timelock active");
    _upgradeTo(pendingImplementation);
}
```

### Pattern 5: No Permissionless Emergency Exit
After admin triggers emergency pause/shutdown, users have no way to withdraw their own funds — recovery is admin-only.

**Vulnerable:**
```solidity
function emergencyRecover() external onlyOwner {
    token.transfer(owner(), token.balanceOf(address(this)));
}
```

**Fixed:**
```solidity
function emergencyWithdraw() external {
    uint256 balance = userBalances[msg.sender];
    userBalances[msg.sender] = 0;
    token.transfer(msg.sender, balance);
}
```

### Detect
For every admin-gated function: can the admin cause disproportionate harm (drain funds, brick protocol, inflate supply, manipulate prices) with no safeguard beyond key security? If yes, flag as low-severity centralization risk.

### Remediation
Add multi-sig, timelocks, supply caps, rate limits, role separation, and permissionless emergency exits. The goal is to reduce the blast radius of a single compromised key.

## CL-ACC-03: Input Validation Invariant for Setters and Configuration

**Rule:** `EVM-ACC-INPUT-01`
**Severity:** informational-medium

### Description
The protocol contains setter, update, constructor, or configuration functions that accept numerical values, addresses, bytes, or identifiers as parameters. Input values are not validated for zero/empty, out-of-range, semantically invalid, duplicate, or inconsistent states before being stored, even when the caller is authorized. Protocol bricking (zero divisor, impossible threshold), DoS (fee set to 100% causes reverts), state corruption (duplicate entries, zero-address recipients), fund loss (transfers to address(0)), or logic bypass (zero threshold approves without signatures) can result. Impact is context-dependent and defaults to informational unless a concrete exploit path is demonstrated.

### Patterns
### Pattern 1: Zero-Address Checks
`address` parameters in constructors, setters, and role assignments must be checked against `address(0)`. Applies to fee recipients, oracle addresses, router addresses, token addresses, and immutable variables set in the constructor.

**Vulnerable:**
```solidity
// No zero-address check in constructor — fees lost forever if zero
constructor(address _feeRecipient) {
    feeRecipient = _feeRecipient;
}
```

**Fixed:**
```solidity
constructor(address _feeRecipient) {
    require(_feeRecipient != address(0), "Zero address");
    feeRecipient = _feeRecipient;
}
```

### Pattern 2: Zero-Value Checks
Fee rates, thresholds, durations, and limits should not be 0 when zero is nonsensical. Division denominators that would cause revert and amounts in state-changing operations must be validated.

**Vulnerable:**
```solidity
function setDuration(uint256 _duration) external onlyOwner {
    duration = _duration; // Can be 0 — division by zero in reward calc
}
```

**Fixed:**
```solidity
function setDuration(uint256 _duration) external onlyOwner {
    require(_duration > 0, "Zero duration");
    duration = _duration;
}
```

### Pattern 3: Upper Bound Checks
Fee rates, slippage parameters, thresholds, multipliers, rates, and durations must have reasonable upper bounds to prevent misconfiguration.

**Vulnerable:**
```solidity
// No bounds on fee — can be set to 100% or higher
function setFee(uint256 feeBps) external onlyOwner {
    protocolFee = feeBps;
}
```

**Fixed:**
```solidity
uint256 public constant MAX_FEE_BPS = 1000; // 10%
function setFee(uint256 feeBps) external onlyOwner {
    require(feeBps <= MAX_FEE_BPS, "Fee too high");
    protocolFee = feeBps;
}
```

### Pattern 4: Semantic Validity
Addresses and IDs must not be reserved or forbidden identifiers. Registry keys must check uniqueness before insert. Parallel arrays must have equal length before zipped iteration. Configuration value setter validation must match consumer expectations.

**Vulnerable:**
```solidity
function registerToken(address token, string calldata symbol) external onlyOwner {
    tokenSymbols[token] = symbol; // Can overwrite existing registration
}
```

**Fixed:**
```solidity
function registerToken(address token, string calldata symbol) external onlyOwner {
    require(bytes(tokenSymbols[token]).length == 0, "Already registered");
    require(token != address(0), "Zero address");
    tokenSymbols[token] = symbol;
}
```

### Pattern 5: Silent Zero-Address Failures
Functions that silently skip operations when address is zero instead of reverting, leading to trapped funds or missed state updates.

**Vulnerable:**
```solidity
function distribute(address recipient, uint256 amount) internal {
    if (recipient == address(0)) return; // Silently skips — funds trapped
    token.transfer(recipient, amount);
}
```

**Fixed:**
```solidity
function distribute(address recipient, uint256 amount) internal {
    require(recipient != address(0), "Zero recipient");
    token.transfer(recipient, amount);
}
```

### Detect
For every setter/update/constructor/config function: (1) check if zero/empty values are rejected when nonsensical, (2) check if upper bounds exist for rates/thresholds/multipliers, (3) check semantic validity (format, uniqueness, reserved values), (4) check for silent zero-address failures.

### Remediation
Validate all inputs at the setter boundary: non-zero checks, upper/lower bounds, format validation, uniqueness checks, and consistency between setter and consumer logic. Apply the same validation in constructors as in runtime setters.

## CL-ACC-04: Whitelist / Blacklist Consistency Invariant

**Rule:** `EVM-ACC-LIST-01`
**Severity:** Medium-Critical

### Description
The protocol implements a whitelist (allowlist) or blacklist (denylist/blocklist) mechanism to control which addresses can interact with specific functions, typically for compliance (OFAC), anti-bot, or access gating. The list mechanism is flawed when: checks are not applied at ALL entry points, checks are one-sided (e.g., only `from` but not `to` and `msg.sender`), boolean logic is inverted, list entries are irreversible, self-exclusion is possible, enforcement is inconsistent across transfer paths, or the hook placement misses certain code paths. Restricted entities bypass controls, compliance requirements are violated, or users are permanently locked out.

**Severity guidance:** Missing `msg.sender` check or missing entry point coverage on a compliance/sanctions token = High-Critical. Missing `to` check on a blocklist = Medium-High. Self-exclusion or irreversible entries = Medium. Stale entries = Low-Medium.

### Patterns

#### Pattern 1: Incomplete entry point coverage
All token movement paths must enforce blocklist checks. This includes `transfer()`, `transferFrom()`, `_transfer()` internal, `_update()` (OZ v5), batch transfers, bridge mint/burn, `permit()`, and any custom transfer variant. A missing check on ANY path is a full bypass.

**Vulnerable:**
```solidity
// Only transfer() is checked — transferFrom() is wide open
function transfer(address to, uint256 amount) public override returns (bool) {
    require(!blacklisted[msg.sender] && !blacklisted[to], "Blacklisted");
    return super.transfer(to, amount);
}
// BUG: No blacklist check — blacklisted users can use transferFrom freely
function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
    return super.transferFrom(from, to, amount);
}
```

**Fixed:**
```solidity
// Centralized check in _update (OZ v5) or _beforeTokenTransfer (OZ v4)
// catches ALL paths: transfer, transferFrom, mint, burn
function _update(address from, address to, uint256 amount) internal override {
    require(!blacklisted[from], "Sender blacklisted");
    require(!blacklisted[to], "Recipient blacklisted");
    require(!blacklisted[msg.sender], "Caller blacklisted");
    super._update(from, to, amount);
}
```

#### Pattern 2: One-sided check (missing `to` or `msg.sender`)
A blocklist check that only validates ONE address per transfer is incomplete. There are THREE addresses to check on every transfer: `from` (token source), `to` (recipient), and `msg.sender` (the caller who initiated the transaction). Missing any one creates a bypass.

**Vulnerable:**
```solidity
function _beforeTokenTransfer(address from, address to, uint256) internal override {
    require(!blacklisted[from], "Sender blacklisted");
    // BUG: 'to' not checked — blacklisted address can receive tokens
    // BUG: msg.sender not checked — blacklisted spender can call transferFrom
}
```

**Fixed:**
```solidity
function _beforeTokenTransfer(address from, address to, uint256) internal override {
    require(!blacklisted[from], "Sender blacklisted");
    require(!blacklisted[to], "Recipient blacklisted");
    require(!blacklisted[msg.sender], "Caller blacklisted");
}
```

#### Pattern 3: msg.sender bypass in transferFrom
`transferFrom()` checks `from` and `to` against the blacklist but does NOT check `msg.sender` (the caller/spender). A blacklisted attacker who holds an existing approval can call `transferFrom` to move funds between two clean addresses, effectively operating on the protocol despite being sanctioned. This is a compliance-critical gap.

**Vulnerable:**
```solidity
function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
    require(!blacklisted[from], "Sender blacklisted");
    require(!blacklisted[to], "Recipient blacklisted");
    // BUG: msg.sender not checked — a blacklisted spender with existing
    // approval can still move tokens between clean addresses
    return super.transferFrom(from, to, amount);
}
```

**Fixed:**
```solidity
function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
    require(!blacklisted[from] && !blacklisted[to] && !blacklisted[msg.sender],
        "Blacklisted");
    return super.transferFrom(from, to, amount);
}
```

#### Pattern 4: Boolean correctness (inverted logic)
Whitelist: `require(isWhitelisted[addr])`. Blacklist: `require(!isBlacklisted[addr])`. Inverted check = complete bypass.

**Vulnerable:**
```solidity
// BUG: inverted — allows blacklisted, blocks everyone else
function transfer(address to, uint256 amount) public {
    require(blacklisted[msg.sender], "Not allowed");
    super.transfer(to, amount);
}
```

**Fixed:**
```solidity
function transfer(address to, uint256 amount) public {
    require(!blacklisted[msg.sender], "Blacklisted");
    super.transfer(to, amount);
}
```

#### Pattern 5: Self-exclusion prevention
The owner/admin must not be able to add themselves to the blacklist, which would brick admin operations permanently.

**Vulnerable:**
```solidity
function addToBlacklist(address account) external onlyOwner {
    blacklisted[account] = true; // Owner can blacklist themselves — no recovery
}
```

**Fixed:**
```solidity
function addToBlacklist(address account) external onlyOwner {
    require(account != owner(), "Cannot blacklist owner");
    blacklisted[account] = true;
}
```

#### Pattern 6: Irreversible list entries
Entries must be removable. If only `addToBlacklist()` exists with no `removeFromBlacklist()`, users are permanently restricted.

**Vulnerable:**
```solidity
function addToBlacklist(address account) external onlyOwner {
    blacklisted[account] = true;
}
// Missing: removeFromBlacklist — permanent restriction
```

**Fixed:**
```solidity
function addToBlacklist(address account) external onlyOwner {
    blacklisted[account] = true;
}
function removeFromBlacklist(address account) external onlyOwner {
    blacklisted[account] = false;
}
```

#### Pattern 7: Non-transfer entry points missing checks
Beyond transfer functions, blocklist checks should also apply to `approve()`, `increaseAllowance()`, `permit()`, `burn()`, `burnFrom()`, and protocol-specific interactions (staking, voting, claiming). A blacklisted address that can still set approvals creates a launder path.

**Vulnerable:**
```solidity
// Blocklist only on transfers — approve() is unchecked
function approve(address spender, uint256 amount) public override returns (bool) {
    // BUG: blacklisted address can set approvals, enabling future
    // transferFrom by clean addresses on their behalf
    return super.approve(spender, amount);
}
```

**Fixed:**
```solidity
function approve(address spender, uint256 amount) public override returns (bool) {
    require(!blacklisted[msg.sender], "Caller blacklisted");
    require(!blacklisted[spender], "Spender blacklisted");
    return super.approve(spender, amount);
}
```

#### Pattern 8: Stale entries after state changes
After role transfers, token migrations, or contract upgrades, list entries must carry over. Stale whitelist entries for old contracts create bypass opportunities.

**Vulnerable:**
```solidity
function setRouter(address newRouter) external onlyOwner {
    router = newRouter;
    // BUG: old router still whitelisted — can bypass restrictions
}
```

**Fixed:**
```solidity
function setRouter(address newRouter) external onlyOwner {
    whitelisted[router] = false;
    router = newRouter;
    whitelisted[newRouter] = true;
}
```

### Detect
1. Enumerate ALL entry points: `transfer`, `transferFrom`, `_transfer`, `_update`, `_beforeTokenTransfer`, `approve`, `increaseAllowance`, `permit`, `burn`, `burnFrom`, `mint`, and any protocol-specific (stake, claim, vote, bridge).
2. For EACH entry point, verify the blocklist/allowlist check is present. Missing check on any path = finding.
3. For each check, verify ALL THREE addresses are validated: `from` (token source), `to` (recipient), AND `msg.sender` (caller). A check on only `from`+`to` but not `msg.sender` is a finding. A check on only `msg.sender` but not `to` is a finding.
4. In `transferFrom` specifically, verify `msg.sender` is checked — not just `from` and `to`. This is the most commonly missed check.
5. Verify `approve()` and `permit()` also check both `msg.sender` and the target spender against the list.
6. Verify boolean polarity: blacklist uses `!blacklisted[x]`, whitelist uses `whitelisted[x]`.
7. Verify admin cannot self-exclude (add self to blacklist / remove self from whitelist).
8. Verify entries are reversible (remove function exists).
9. Verify stale entries are cleaned on role/address changes.

### Remediation
Centralize ALL list checks into `_update()` (OZ v5) or `_beforeTokenTransfer()` (OZ v4) hook — this catches transfer, transferFrom, mint, and burn in one place. In the hook, check all THREE addresses: `from`, `to`, AND `msg.sender`. Additionally check `msg.sender` and target in `approve()`, `permit()`, and any protocol-specific entry points. Verify boolean polarity. Prevent self-exclusion of admin/owner. Ensure list entries are reversible.

## CL-ACC-05: Ownership & Role Transfer Invariant

**Rule:** `EVM-ACC-OWN-01`
**Severity:** medium-high

### Description
The protocol defines one or more administrative or privileged roles (owner, admin, operator, guardian, multisig signer) stored in contract state variables or role mappings. The role transfer mechanism is absent, single-step (no confirmation), uses hardcoded addresses, has stale pending state issues, allows self-removal of the last admin, or creates governance deadlock through inconsistent threshold management. This can lead to permanent loss of administrative control, inability to rotate compromised keys, wrong entity claiming the wrong role, governance deadlock, or protocol bricking from renounced ownership.

### Patterns
### Pattern 1: Transfer Mechanism Exists
Every admin address or role must have a transfer/update function. If the admin is set only in the constructor with no setter, it is permanently locked to that address.

**Vulnerable:**
```solidity
constructor(address _admin) {
    admin = _admin; // No setter — admin permanently locked
}
```

**Fixed:**
```solidity
constructor(address _admin) {
    admin = _admin;
}
function transferAdmin(address newAdmin) external onlyAdmin {
    pendingAdmin = newAdmin;
}
function acceptAdmin() external {
    require(msg.sender == pendingAdmin, "Not pending");
    admin = msg.sender;
    pendingAdmin = address(0);
}
```

### Pattern 2: Two-Step Transfer (Ownable2Step)
Transfer must be 2-step (propose + accept). Single-step `transferOwnership()` from OpenZeppelin `Ownable` means a typo causes permanent loss.

**Vulnerable:**
```solidity
// Single-step — typo = permanent loss
function transferOwnership(address newOwner) public onlyOwner {
    owner = newOwner;
}
```

**Fixed:**
```solidity
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

contract MyContract is Ownable2Step {
    // 2-step: transferOwnership() sets pendingOwner, acceptOwnership() confirms
}
```

### Pattern 3: Zero-Address Transfer Check
`transferOwnership` must reject `address(0)`. Without this check, ownership can be accidentally burned, bricking all admin functions.

**Vulnerable:**
```solidity
function transferOwnership(address newOwner) public onlyOwner {
    owner = newOwner; // Can be address(0) — ownership burned
}
```

**Fixed:**
```solidity
function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0), "Zero address");
    pendingOwner = newOwner;
}
```

### Pattern 4: Stale Proposed Owner
When a new owner is proposed, the previous pending proposal must be invalidated. A stale `pendingOwner` from months ago could call `acceptOwnership()` and seize control.

**Vulnerable:**
```solidity
function acceptOwnership() external {
    require(msg.sender == pendingOwner); // Stale pendingOwner from months ago
    owner = msg.sender;
    // BUG: pendingOwner not cleared, no expiry
}
```

**Fixed:**
```solidity
function transferOwnership(address newOwner) public onlyOwner {
    pendingOwner = newOwner; // Overwrites any previous proposal
    proposalTimestamp = block.timestamp;
}
function acceptOwnership() external {
    require(msg.sender == pendingOwner, "Not pending");
    require(block.timestamp <= proposalTimestamp + PROPOSAL_EXPIRY, "Expired");
    owner = msg.sender;
    pendingOwner = address(0);
}
```

### Pattern 5: Renounce Ownership Risks
If the contract inherits `renounceOwnership()` and admin-gated functions exist (pause, upgrade, parameter changes), renouncing ownership bricks them permanently.

**Vulnerable:**
```solidity
contract MyToken is Ownable, Pausable {
    function pause() external onlyOwner { _pause(); }
    // renounceOwnership() inherited — if called, pause/unpause bricked
}
```

**Fixed:**
```solidity
contract MyToken is Ownable2Step, Pausable {
    function pause() external onlyOwner { _pause(); }
    function renounceOwnership() public override onlyOwner {
        revert("Renounce disabled");
    }
}
```

### Pattern 6: Renounce While Paused
Ownership can be renounced while the contract is paused, creating a permanently paused, unrecoverable state.

**Vulnerable:**
```solidity
// Can call renounceOwnership() while paused — permanently frozen
contract MyContract is Ownable, Pausable {
    function unpause() external onlyOwner { _unpause(); }
}
```

**Fixed:**
```solidity
contract MyContract is Ownable2Step, Pausable {
    function renounceOwnership() public override onlyOwner {
        revert("Renounce disabled");
    }
}
```

### Pattern 7: Role Self-Removal (Last Admin)
The last holder of an admin role must not be able to remove themselves, which would create a state where no one can perform admin operations.

**Vulnerable:**
```solidity
function revokeRole(bytes32 role, address account) public override {
    super.revokeRole(role, account);
    // BUG: last admin can revoke themselves
}
```

**Fixed:**
```solidity
function revokeRole(bytes32 role, address account) public override {
    if (role == DEFAULT_ADMIN_ROLE) {
        require(getRoleMemberCount(role) > 1, "Cannot remove last admin");
    }
    super.revokeRole(role, account);
}
```

### Pattern 8: Multisig Threshold Consistency
After removing a signer from a multisig, the threshold must be adjusted. If threshold remains at N but only N-1 signers remain, governance is deadlocked.

**Vulnerable:**
```solidity
function removeSigner(address signer) external onlyOwner {
    signers.remove(signer);
    // BUG: threshold stays at 3 but only 2 signers remain
}
```

**Fixed:**
```solidity
function removeSigner(address signer) external onlyOwner {
    signers.remove(signer);
    if (threshold > signers.length()) {
        threshold = signers.length();
    }
}
```

### Pattern 9: Hardcoded Admin Addresses
The admin address is a literal `0x...` in require statements instead of read from storage. Rotation is impossible even if a setter exists elsewhere.

**Vulnerable:**
```solidity
function adminAction() external {
    require(msg.sender == 0x1234...abcd, "Not admin"); // Hardcoded
}
```

**Fixed:**
```solidity
function adminAction() external {
    require(msg.sender == admin, "Not admin"); // Dynamic lookup
}
```

### Pattern 10: Deployer Privilege Retention
The deployer retains admin privileges after deployment without explicit transfer to the intended admin, creating a hidden backdoor if the deployer key is compromised.

**Vulnerable:**
```solidity
constructor() {
    admin = msg.sender; // Deployer is admin — may not be intended long-term admin
}
```

**Fixed:**
```solidity
constructor(address _admin) {
    require(_admin != address(0), "Zero address");
    admin = _admin; // Explicit admin, not deployer
}
```

### Pattern 11: Cross-Chain Privilege Persistence
On multi-chain deployments, revoking a signer on one chain must propagate to others. Stale signers on secondary chains can retain full authority.

**Vulnerable:**
```solidity
// Signer revoked on mainnet but still active on L2
// No cross-chain synchronization mechanism
```

**Fixed:**
```solidity
// Use cross-chain messaging to propagate role changes
// Or implement independent admin management per chain with clear documentation
```

### Detect
For every privileged role: (1) verify a transfer/update function exists, (2) verify it is 2-step, (3) verify zero-address rejection, (4) verify stale pending state is handled, (5) verify renounceOwnership is safe or disabled, (6) verify last-admin self-removal is prevented, (7) verify multisig threshold consistency after member changes, (8) verify no hardcoded address literals in auth checks.

### Remediation
Implement OpenZeppelin `Ownable2Step` for every privileged role. Validate recipient addresses. Clear stale pending state on new proposals. Prevent last-admin self-removal. Override `renounceOwnership()` to revert when admin-gated functions exist. Synchronize multisig thresholds with member count. Use dynamic state lookup instead of hardcoded addresses.

## CL-ACC-06: Pause Mechanism Invariant

**Rule:** `EVM-ACC-PAUSE-01`
**Severity:** medium-high

### Description
The protocol implements a pause, emergency stop, or circuit breaker mechanism using OpenZeppelin `Pausable`, custom boolean flags, or per-function pause granularity. The pause mechanism has incomplete coverage (some functions skip the `whenNotPaused` modifier), inconsistent logic across pause states, allows permanent fund locking (no emergency exit when paused), or has conflicting multi-role pause control. Critical functions may remain callable during emergency pause, or users may be locked out of funds with no exit when the protocol is paused.

### Patterns
### Pattern 1: Global Pause Coverage
All `external`/`public` functions that modify state must have the `whenNotPaused` modifier. Any that skip it remain callable during emergencies.

**Vulnerable:**
```solidity
// Deposit paused but swap is not
function deposit() external whenNotPaused {
    // Protected
}
function swap(uint256 amount) external {
    // BUG: Not paused — attackers can still swap during emergency
}
```

**Fixed:**
```solidity
function deposit() external whenNotPaused { ... }
function swap(uint256 amount) external whenNotPaused { ... }
```

### Pattern 2: Selective Pause Gaps
If the protocol uses granular pause flags (per-function or per-feature), all related functions must check the relevant flag. A swap pause that doesn't cover the settlement function is ineffective.

**Vulnerable:**
```solidity
function swap() external {
    require(!swapPaused, "Paused");
    // ...
}
function settleSwap() external {
    // BUG: settlement not checked — swaps can still complete
}
```

**Fixed:**
```solidity
function swap() external {
    require(!swapPaused, "Paused");
    // ...
}
function settleSwap() external {
    require(!swapPaused, "Paused");
    // ...
}
```

### Pattern 3: Emergency User Exit / Pause Locks User Funds
When paused, users must still be able to withdraw their own assets via a permissionless emergency function. If no emergency exit exists, or if exit functions (withdraw, redeem, claim) carry `whenNotPaused` with no alternative path, pausing equals locking user funds.

**Vulnerable:**
```solidity
function withdraw(uint256 amount) external whenNotPaused {
    // BUG: Users cannot withdraw during pause
    _transfer(msg.sender, amount);
}
function claim() external whenNotPaused {
    // BUG: Users cannot claim rewards during pause
}
// No emergency exit — funds locked when paused
```

**Fixed:**
```solidity
function withdraw(uint256 amount) external whenNotPaused {
    _transfer(msg.sender, amount);
}
function claim() external whenNotPaused {
    _claimRewards(msg.sender);
}
function emergencyWithdraw() external {
    // Works even when paused — users can always exit
    uint256 balance = balances[msg.sender];
    balances[msg.sender] = 0;
    token.transfer(msg.sender, balance);
}
```

### Pattern 4: No Unpause Mechanism
No unpause or unfreeze mechanism exists, or a restrictive toggle (pause, freeze, shutdown) lacks a corresponding reverse operation. If only `pause()` exists, the contract can be permanently frozen with no recovery.

**Vulnerable:**
```solidity
function pause() external onlyOwner {
    _pause();
}
// Missing: unpause() — permanent freeze
```

**Fixed:**
```solidity
function pause() external onlyOwner {
    _pause();
}
function unpause() external onlyOwner {
    _unpause();
}
```

### Pattern 5: Conflicting Multi-Role Pause Control
If multiple roles can pause/unpause independently, conflicting actions can create an inconsistent state (one role pauses while another unpauses simultaneously).

**Vulnerable:**
```solidity
function pause() external onlyGuardian { _pause(); }
function unpause() external onlyAdmin { _unpause(); }
// Guardian pauses, admin unpauses, guardian re-pauses — conflict
```

**Fixed:**
```solidity
function pause() external onlyGuardian { _pause(); }
function unpause() external onlyAdmin {
    require(!guardianPaused, "Guardian override active");
    _unpause();
}
```

### Pattern 6: Logic Bypass via OR Conditions
Pause check combined with other conditions using `||` instead of `&&`, allowing bypass when the other condition is met.

**Vulnerable:**
```solidity
function action() external {
    require(!paused || msg.sender == admin, "Paused");
    // BUG: admin can still act when paused — may not be intended
}
```

**Fixed:**
```solidity
function action() external whenNotPaused {
    // Pause applies to everyone equally
}
function adminAction() external onlyAdmin {
    // Separate admin-only function if needed
}
```

### Detect
(1) Identify the pause flag/mechanism, (2) list ALL public/external state-changing functions, (3) verify each has the whenNotPaused modifier, (4) verify unpause/unfreeze exists for every pause/freeze toggle, (5) verify emergency exit exists for users when paused — check that exit functions (withdraw, redeem, claim) are not blocked by whenNotPaused without an alternative path, (6) verify no conflicting multi-role pause control.

### Remediation
Centralize pause checks into the `whenNotPaused` modifier. Apply it to every state-changing function. Implement a permissionless emergency withdrawal that works even when paused — ensure exit functions (withdraw, redeem, claim) are not blocked by `whenNotPaused` without an alternative path. Ensure an `unpause()` or `unfreeze()` function exists for every restrictive toggle. Ensure a single authority controls pause/unpause with clear escalation. Avoid combining pause checks with other conditions using `||`.

## CL-ACC-07: Signature & Authentication Invariant

**Rule:** `EVM-ACC-SIG-01`
**Severity:** medium-critical

### Description
The protocol uses cryptographic signatures for authentication, authorization, or off-chain message verification — including ECDSA signatures, EIP-712 typed data, EIP-2612 permits, meta-transactions, account abstraction (ERC-4337), or ERC-1271 smart contract signatures. The signature verification mechanism is flawed: `ecrecover` returns `address(0)` without check, signatures lack replay protection (missing nonce or chain ID), `tx.origin` is used instead of `msg.sender`, signature malleability is not prevented, deadlines are missing, or delegated signature validation trusts untrusted contracts. This can lead to signature replay across transactions or chains, phishing via `tx.origin`, unauthorized execution via `address(0)` bypass, front-running of signed messages, or privilege escalation through malicious ERC-1271 delegation. For callback authentication (flash loans, VRF, hooks), see EVM-ACC-AUTH-01.

### Patterns
### Pattern 1: ecrecover Returns address(0)
`ecrecover` returns `address(0)` on invalid signature instead of reverting. If the recovered address is compared against a zero-initialized variable, the check passes.

**Vulnerable:**
```solidity
function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
    address signer = ecrecover(hash, v, r, s);
    return signer == authorizedSigner; // BUG: if authorizedSigner is unset (0), invalid sig passes
}
```

**Fixed:**
```solidity
function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
    address signer = ecrecover(hash, v, r, s);
    require(signer != address(0), "Invalid signature");
    return signer == authorizedSigner;
}
```

### Pattern 2: Missing Nonce for Replay Protection
Signed messages without an incrementing nonce can be replayed multiple times. Each signature should be usable exactly once.

**Vulnerable:**
```solidity
function executeWithSig(address to, uint256 amount, bytes memory sig) external {
    bytes32 hash = keccak256(abi.encodePacked(to, amount));
    address signer = ECDSA.recover(hash, sig);
    require(signer == owner(), "Invalid");
    // BUG: Same signature can be replayed forever
    token.transfer(to, amount);
}
```

**Fixed:**
```solidity
function executeWithSig(address to, uint256 amount, uint256 nonce, bytes memory sig) external {
    require(nonce == nonces[owner()]++, "Invalid nonce");
    bytes32 hash = keccak256(abi.encodePacked(to, amount, nonce));
    address signer = ECDSA.recover(hash, sig);
    require(signer == owner(), "Invalid");
    token.transfer(to, amount);
}
```

### Pattern 3: Missing Chain ID / Domain Separator
Without EIP-712 domain separator including `chainId`, signatures from one chain are valid on another after a fork or cross-chain deployment.

**Vulnerable:**
```solidity
function verify(bytes32 hash, bytes memory sig) public view returns (address) {
    // BUG: no chain binding — signature valid on any chain
    return ECDSA.recover(hash, sig);
}
```

**Fixed:**
```solidity
function verify(bytes32 structHash, bytes memory sig) public view returns (address) {
    bytes32 digest = _hashTypedDataV4(structHash); // Includes chainId in domain separator
    return ECDSA.recover(digest, sig);
}
```

### Pattern 4: tx.origin Authentication
Using `tx.origin` instead of `msg.sender` for authentication. In a multi-call or phishing context, `tx.origin` is the EOA that initiated the top-level transaction, not the direct caller.

**Vulnerable:**
```solidity
function transferOwnership(address newOwner) external {
    require(tx.origin == owner, "Not owner"); // BUG: phishing via malicious contract
    owner = newOwner;
}
```

**Fixed:**
```solidity
function transferOwnership(address newOwner) external {
    require(msg.sender == owner, "Not owner");
    owner = newOwner;
}
```

### Pattern 5: Signature Malleability
ECDSA signatures have two valid (r, s) pairs for the same message. Without enforcing `s <= secp256k1n/2`, an attacker can modify the s-value to create a second valid signature, bypassing uniqueness checks.

**Vulnerable:**
```solidity
function execute(bytes32 hash, bytes memory sig) external {
    require(!usedSignatures[sig], "Already used");
    usedSignatures[sig] = true;
    address signer = ecrecover(hash, v, r, s);
    // BUG: attacker can flip s-value to create a different but valid sig
}
```

**Fixed:**
```solidity
function execute(bytes32 hash, bytes memory sig) external {
    // Use OpenZeppelin ECDSA which enforces s-value range
    address signer = ECDSA.recover(hash, sig);
    require(!usedHashes[hash], "Already executed");
    usedHashes[hash] = true;
}
```

### Pattern 6: Missing Deadline / Expiry
Signed permits or orders without an expiration timestamp remain valid indefinitely. Stale signatures can be executed long after the signer's intent has changed.

**Vulnerable:**
```solidity
function permit(address owner, address spender, uint256 value, bytes memory sig) external {
    // BUG: No deadline — stale permit valid forever
    bytes32 hash = keccak256(abi.encodePacked(owner, spender, value, nonces[owner]++));
    require(ECDSA.recover(hash, sig) == owner);
    _approve(owner, spender, value);
}
```

**Fixed:**
```solidity
function permit(
    address owner, address spender, uint256 value, uint256 deadline, bytes memory sig
) external {
    require(block.timestamp <= deadline, "Expired");
    bytes32 hash = _hashTypedDataV4(keccak256(abi.encode(
        PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline
    )));
    require(ECDSA.recover(hash, sig) == owner);
    _approve(owner, spender, value);
}
```

### Pattern 7: Signature Frontrunning / Griefing
Signed messages that don't bind to `msg.sender` can be extracted from the mempool and submitted by a different relayer, potentially with different execution context or to grief the signer.

**Vulnerable:**
```solidity
function executeOrder(bytes memory orderData, bytes memory sig) external {
    // BUG: anyone can submit this order — no msg.sender binding
    address signer = ECDSA.recover(keccak256(orderData), sig);
    _execute(signer, orderData);
}
```

**Fixed:**
```solidity
function executeOrder(bytes memory orderData, bytes memory sig) external {
    // Bind to specific relayer if needed, or use commit-reveal
    bytes32 hash = keccak256(abi.encodePacked(orderData, msg.sender));
    address signer = ECDSA.recover(hash, sig);
    _execute(signer, orderData);
}
```

### Pattern 8: ERC-1271 Delegation Issues
Smart contract signature validation via `isValidSignature()` that delegates to an untrusted or upgradeable contract, enabling the delegate to approve arbitrary signatures.

**Vulnerable:**
```solidity
function isValidSignature(bytes32 hash, bytes memory sig) external view returns (bytes4) {
    // Delegates to any contract — attacker can approve arbitrary signatures
    address delegate = delegateSigners[msg.sender];
    return IERC1271(delegate).isValidSignature(hash, sig);
}
```

**Fixed:**
```solidity
function isValidSignature(bytes32 hash, bytes memory sig) external view returns (bytes4) {
    address delegate = delegateSigners[msg.sender];
    require(trustedDelegates[delegate], "Untrusted delegate");
    return IERC1271(delegate).isValidSignature(hash, sig);
}
```

### Pattern 9: Account Abstraction (ERC-4337) Entry Point
`validateUserOp` or execution functions in account abstraction wallets that don't verify `msg.sender == entryPoint`, allowing direct calls that bypass signature validation.

**Vulnerable:**
```solidity
function validateUserOp(UserOperation calldata userOp, bytes32 hash, uint256 missingFunds)
    external returns (uint256) {
    // BUG: no msg.sender check — anyone can call, bypassing entry point validation
    _validateSignature(userOp, hash);
}
```

**Fixed:**
```solidity
function validateUserOp(UserOperation calldata userOp, bytes32 hash, uint256 missingFunds)
    external returns (uint256) {
    require(msg.sender == entryPoint, "Not entry point");
    _validateSignature(userOp, hash);
}
```

### Pattern 10: Meta-Transaction Context
Meta-transaction relayers that use `msg.sender` instead of extracting the actual signer from the appended calldata, or entry points that don't restrict which relayers can submit.

**Vulnerable:**
```solidity
function executeMetaTx(bytes calldata data) external {
    // BUG: uses msg.sender instead of extracting signer from calldata
    _execute(msg.sender, data);
}
```

**Fixed:**
```solidity
function executeMetaTx(bytes calldata data, bytes calldata sig) external {
    address signer = _extractSigner(data, sig);
    require(signer != address(0), "Invalid signer");
    _execute(signer, data);
}
```

### Detect
For every signature verification: (1) verify ecrecover result is checked against address(0), (2) verify nonce is included and incremented, (3) verify EIP-712 domain separator with chainId is used, (4) verify no tx.origin authentication, (5) verify s-value malleability prevention, (6) verify deadline exists, (7) verify ERC-1271 delegation targets are trusted, (8) verify ERC-4337 entry point checks, (9) verify meta-transaction signer extraction.

### Remediation
Always check `ecrecover` result against `address(0)`. Include nonce, chain ID (EIP-712 domain separator), and deadline in signed data. Never use `tx.origin` for authentication. Enforce s-value range for malleability prevention. Validate ERC-1271 delegation targets. Use OpenZeppelin ECDSA library with EIP-712.
