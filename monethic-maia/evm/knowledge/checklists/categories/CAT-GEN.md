## CL-GEN-01: Authorization Invariant

**Rule:** `EVM-GEN-AUTH-01`
**Severity:** medium-critical

### Description
The contract has privileged operations that should be restricted to authorized callers. State-changing functions lack access control modifiers, authorization is applied inconsistently across similar functions, delegated actions don't verify caller authority, emergency functions are unprotected, or internal helpers are externally accessible. Unauthorized users can steal funds, seize ownership, modify protocol parameters, pause/unpause operations, or bypass intended restrictions, potentially leading to complete protocol compromise.

### Patterns
### Pattern 1: Missing Access Control on State-Changing Function
A public or external function that modifies critical state has no ownership or role check, allowing any caller to execute it.

**Vulnerable:**
```solidity
contract TokenManager {
    address public minter;
    uint256 public mintCap;
    mapping(address => uint256) public balances;

    // BUG: No access control — anyone can set themselves as minter
    function setMinter(address _minter) external {
        minter = _minter;
    }

    // BUG: No access control — anyone can raise the mint cap
    function setMintCap(uint256 _cap) external {
        mintCap = _cap;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == minter, "not minter");
        require(amount <= mintCap, "exceeds cap");
        balances[to] += amount;
    }
}
```

**Fixed:**
```solidity
import "@openzeppelin/contracts/access/Ownable.sol";

contract TokenManager is Ownable {
    address public minter;
    uint256 public mintCap;
    mapping(address => uint256) public balances;

    constructor() Ownable(msg.sender) {}

    function setMinter(address _minter) external onlyOwner {
        require(_minter != address(0), "zero address");
        minter = _minter;
    }

    function setMintCap(uint256 _cap) external onlyOwner {
        mintCap = _cap;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == minter, "not minter");
        require(amount <= mintCap, "exceeds cap");
        balances[to] += amount;
    }
}
```

### Pattern 2: Inconsistent Authorization Across Similar Functions
Some functions in a related set have access control checks while others performing equivalent operations do not.

**Vulnerable:**
```solidity
contract FeeManager {
    uint256 public swapFee;
    uint256 public withdrawFee;
    uint256 public depositFee;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setSwapFee(uint256 _fee) external onlyOwner {
        require(_fee <= 1000, "fee too high");
        swapFee = _fee;
    }

    // BUG: Missing onlyOwner — anyone can set withdraw fee
    function setWithdrawFee(uint256 _fee) external {
        require(_fee <= 1000, "fee too high");
        withdrawFee = _fee;
    }

    // BUG: Missing onlyOwner — anyone can set deposit fee
    function setDepositFee(uint256 _fee) external {
        require(_fee <= 1000, "fee too high");
        depositFee = _fee;
    }
}
```

**Fixed:**
```solidity
contract FeeManager {
    uint256 public swapFee;
    uint256 public withdrawFee;
    uint256 public depositFee;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setSwapFee(uint256 _fee) external onlyOwner {
        require(_fee <= 1000, "fee too high");
        swapFee = _fee;
    }

    function setWithdrawFee(uint256 _fee) external onlyOwner {
        require(_fee <= 1000, "fee too high");
        withdrawFee = _fee;
    }

    function setDepositFee(uint256 _fee) external onlyOwner {
        require(_fee <= 1000, "fee too high");
        depositFee = _fee;
    }
}
```

### Pattern 3: Missing msg.sender Validation in Delegated Action
A function acts on behalf of a user parameter but does not verify that msg.sender is authorized to act for that user.

**Vulnerable:**
```solidity
contract Staking {
    mapping(address => uint256) public staked;
    mapping(address => uint256) public rewards;

    function claimFor(address user) external {
        // BUG: Anyone can call claimFor and redirect rewards
        uint256 reward = rewards[user];
        rewards[user] = 0;
        // Reward sent to msg.sender instead of user
        payable(msg.sender).transfer(reward);
    }

    function unstakeFor(address user, uint256 amount) external {
        // BUG: No check that msg.sender is authorized to unstake for user
        require(staked[user] >= amount, "insufficient");
        staked[user] -= amount;
        payable(user).transfer(amount);
    }
}
```

**Fixed:**
```solidity
contract Staking {
    mapping(address => uint256) public staked;
    mapping(address => uint256) public rewards;
    mapping(address => mapping(address => bool)) public delegates;

    function setDelegate(address delegate, bool approved) external {
        delegates[msg.sender][delegate] = approved;
    }

    function claimFor(address user) external {
        require(
            msg.sender == user || delegates[user][msg.sender],
            "not authorized"
        );
        uint256 reward = rewards[user];
        rewards[user] = 0;
        payable(user).transfer(reward);
    }

    function unstakeFor(address user, uint256 amount) external {
        require(
            msg.sender == user || delegates[user][msg.sender],
            "not authorized"
        );
        require(staked[user] >= amount, "insufficient");
        staked[user] -= amount;
        payable(user).transfer(amount);
    }
}
```

### Pattern 4: Unprotected Emergency/Admin Function
Emergency functions such as pause, unpause, emergency withdraw, upgrade, or contract destruction lack authorization checks.

**Vulnerable:**
```solidity
contract Vault {
    bool public paused;
    mapping(address => uint256) public balances;

    // BUG: Anyone can pause the contract — griefing attack
    function pause() external {
        paused = true;
    }

    // BUG: Anyone can unpause — defeats the purpose of pausing
    function unpause() external {
        paused = false;
    }

    // BUG: Anyone can sweep all funds
    function emergencyWithdraw(address token, address to) external {
        uint256 balance = IERC20(token).balanceOf(address(this));
        IERC20(token).transfer(to, balance);
    }

    function deposit(uint256 amount) external {
        require(!paused, "paused");
        balances[msg.sender] += amount;
    }
}
```

**Fixed:**
```solidity
import "@openzeppelin/contracts/access/AccessControl.sol";

contract Vault is AccessControl {
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    bool public paused;
    mapping(address => uint256) public balances;

    constructor(address admin, address guardian) {
        _grantRole(ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, guardian);
    }

    function pause() external onlyRole(GUARDIAN_ROLE) {
        paused = true;
    }

    function unpause() external onlyRole(ADMIN_ROLE) {
        paused = false;
    }

    function emergencyWithdraw(address token, address to) external onlyRole(ADMIN_ROLE) {
        require(to != address(0), "zero address");
        uint256 balance = IERC20(token).balanceOf(address(this));
        IERC20(token).transfer(to, balance);
    }

    function deposit(uint256 amount) external {
        require(!paused, "paused");
        balances[msg.sender] += amount;
    }
}
```

### Pattern 5: Bypassable Access Control via Internal Call Path
An external function is protected by access control, but an internal helper that performs the privileged action is marked public or external and directly callable.

**Vulnerable:**
```solidity
contract Registry {
    mapping(address => bool) public registered;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function registerBatch(address[] calldata users) external onlyOwner {
        for (uint256 i = 0; i < users.length; i++) {
            _register(users[i]);
        }
    }

    // BUG: Helper is public — anyone can call it directly, bypassing onlyOwner
    function _register(address user) public {
        registered[user] = true;
    }

    function deregister(address user) external onlyOwner {
        _deregister(user);
    }

    // BUG: Helper is external — anyone can call it directly
    function _deregister(address user) external {
        registered[user] = false;
    }
}
```

**Fixed:**
```solidity
contract Registry {
    mapping(address => bool) public registered;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function registerBatch(address[] calldata users) external onlyOwner {
        for (uint256 i = 0; i < users.length; i++) {
            _register(users[i]);
        }
    }

    // Internal visibility — only callable from within the contract
    function _register(address user) internal {
        registered[user] = true;
    }

    function deregister(address user) external onlyOwner {
        _deregister(user);
    }

    // Internal visibility — only callable from within the contract
    function _deregister(address user) internal {
        registered[user] = false;
    }
}
```

### Detect
For every privileged operation: (1) verify access control modifier or require check is present, (2) verify all similar functions have consistent authorization, (3) verify delegated actions validate msg.sender authority, (4) verify emergency/admin functions are protected, (5) verify internal helpers are not externally accessible.

### Remediation
Apply access control to all state-changing functions. Use consistent authorization patterns (OpenZeppelin AccessControl or Ownable). Verify msg.sender in delegated actions. Protect all admin/emergency functions. Ensure internal helpers are not externally callable.

## CL-GEN-02: Data Structure Integrity Invariant

**Rule:** `EVM-GEN-DATA-01`
**Severity:** low-high

### Description
The contract uses complex data structures -- mappings with associated arrays, linked lists, enumerable sets, or dynamically growing arrays -- to track entities such as users, tokens, orders, or proposals. Data structure operations fail to maintain structural invariants: deletions leave dangling references, array operations create gaps, key changes orphan mapping entries, unbounded growth enables DoS, or library return values are ignored. Corrupted data structures lead to phantom entries, duplicated records, inaccessible state, gas-limit DoS on iteration, and exploitable inconsistencies between mapping and array views of the same data.

### Patterns
### Pattern 1: Mapping Deletion Without Cleanup
Deleting a mapping entry does not clean up associated array or linked-list references, leaving dangling pointers to non-existent data.

**Vulnerable:**
```solidity
contract UserRegistry {
    mapping(address => uint256) public userIndex;
    mapping(address => uint256) public userBalance;
    address[] public userList;

    function addUser(address user) external {
        userIndex[user] = userList.length;
        userList.push(user);
        userBalance[user] = 0;
    }

    function removeUser(address user) external onlyOwner {
        // BUG: Only deletes mapping entries — userList still contains the address
        // Iteration over userList will reference deleted users
        delete userBalance[user];
        delete userIndex[user];
        // userList entry not removed — ghost entry remains
    }

    function totalUsers() external view returns (uint256) {
        // Returns inflated count including removed users
        return userList.length;
    }
}
```

**Fixed:**
```solidity
contract UserRegistry {
    mapping(address => uint256) public userIndex;
    mapping(address => uint256) public userBalance;
    address[] public userList;

    function addUser(address user) external {
        require(userBalance[user] == 0 && userList.length == 0 || userList[userIndex[user]] != user, "exists");
        userIndex[user] = userList.length;
        userList.push(user);
        userBalance[user] = 0;
    }

    function removeUser(address user) external onlyOwner {
        uint256 idx = userIndex[user];
        address lastUser = userList[userList.length - 1];

        // Swap-and-pop to remove from array
        userList[idx] = lastUser;
        userIndex[lastUser] = idx;
        userList.pop();

        // Clean all mapping entries
        delete userBalance[user];
        delete userIndex[user];
    }

    function totalUsers() external view returns (uint256) {
        return userList.length;
    }
}
```

### Pattern 2: Array Gap on Unordered Delete
Deleting a middle element from an array by setting it to zero or shifting incorrectly creates gaps or corrupts ordering, breaking iteration logic.

**Vulnerable:**
```solidity
contract OrderBook {
    uint256[] public orderIds;
    mapping(uint256 => uint256) public orderAmounts;

    function addOrder(uint256 orderId, uint256 amount) external {
        orderIds.push(orderId);
        orderAmounts[orderId] = amount;
    }

    function cancelOrder(uint256 orderId) external {
        for (uint256 i = 0; i < orderIds.length; i++) {
            if (orderIds[i] == orderId) {
                // BUG: Sets to 0 instead of removing — creates gap
                // Subsequent iteration hits 0 entries, breaks accounting
                delete orderIds[i];
                delete orderAmounts[orderId];
                break;
            }
        }
    }

    function activeOrderCount() external view returns (uint256 count) {
        // Must skip gaps — incorrect if caller expects length == active count
        for (uint256 i = 0; i < orderIds.length; i++) {
            if (orderIds[i] != 0) count++;
        }
    }
}
```

**Fixed:**
```solidity
contract OrderBook {
    uint256[] public orderIds;
    mapping(uint256 => uint256) public orderAmounts;
    mapping(uint256 => uint256) public orderIndex;

    function addOrder(uint256 orderId, uint256 amount) external {
        orderIndex[orderId] = orderIds.length;
        orderIds.push(orderId);
        orderAmounts[orderId] = amount;
    }

    function cancelOrder(uint256 orderId) external {
        uint256 idx = orderIndex[orderId];
        uint256 lastId = orderIds[orderIds.length - 1];

        // Swap with last element and pop — no gaps
        orderIds[idx] = lastId;
        orderIndex[lastId] = idx;
        orderIds.pop();

        delete orderAmounts[orderId];
        delete orderIndex[orderId];
    }

    function activeOrderCount() external view returns (uint256) {
        return orderIds.length;
    }
}
```

### Pattern 3: Stale Mapping Entry After Key Change
A key used for a mapping lookup is changed, but the old entry under the previous key is not cleared, leaving orphaned data.

**Vulnerable:**
```solidity
contract NameRegistry {
    mapping(bytes32 => address) public nameOwner;
    mapping(address => bytes32) public ownerName;

    function register(bytes32 name) external {
        require(nameOwner[name] == address(0), "taken");
        nameOwner[name] = msg.sender;
        ownerName[msg.sender] = name;
    }

    function rename(bytes32 newName) external {
        require(nameOwner[newName] == address(0), "taken");
        bytes32 oldName = ownerName[msg.sender];
        // BUG: Old name->owner mapping not cleared
        // nameOwner[oldName] still points to msg.sender
        nameOwner[newName] = msg.sender;
        ownerName[msg.sender] = newName;
    }
}
```

**Fixed:**
```solidity
contract NameRegistry {
    mapping(bytes32 => address) public nameOwner;
    mapping(address => bytes32) public ownerName;

    function register(bytes32 name) external {
        require(nameOwner[name] == address(0), "taken");
        nameOwner[name] = msg.sender;
        ownerName[msg.sender] = name;
    }

    function rename(bytes32 newName) external {
        require(nameOwner[newName] == address(0), "taken");
        bytes32 oldName = ownerName[msg.sender];

        // Clear old mapping entry before setting new one
        delete nameOwner[oldName];

        nameOwner[newName] = msg.sender;
        ownerName[msg.sender] = newName;
    }
}
```

### Pattern 4: Unbounded Array Growth
An array grows with each user action via `push()` without any length cap or cleanup mechanism, eventually causing iteration to exceed the block gas limit.

**Vulnerable:**
```solidity
contract Whitelist {
    address[] public members;
    mapping(address => bool) public isMember;

    function join() external {
        require(!isMember[msg.sender], "already member");
        isMember[msg.sender] = true;
        // BUG: Array grows unbounded — no cap, no pruning
        members.push(msg.sender);
    }

    function distributeRewards(uint256 totalReward) external onlyOwner {
        uint256 share = totalReward / members.length;
        // BUG: If members array grows too large, this loop exceeds gas limit
        for (uint256 i = 0; i < members.length; i++) {
            payable(members[i]).transfer(share);
        }
    }
}
```

**Fixed:**
```solidity
contract Whitelist {
    address[] public members;
    mapping(address => bool) public isMember;
    uint256 public constant MAX_MEMBERS = 1000;

    function join() external {
        require(!isMember[msg.sender], "already member");
        require(members.length < MAX_MEMBERS, "capacity reached");
        isMember[msg.sender] = true;
        members.push(msg.sender);
    }

    function distributeRewards(
        uint256 totalReward,
        uint256 startIdx,
        uint256 batchSize
    ) external onlyOwner {
        uint256 end = startIdx + batchSize;
        if (end > members.length) end = members.length;
        uint256 share = totalReward / members.length;
        for (uint256 i = startIdx; i < end; i++) {
            payable(members[i]).transfer(share);
        }
    }
}
```

### Pattern 5: Incorrect EnumerableSet/Map Usage
Return values from `add()`, `remove()`, or `contains()` are not checked, or the set is mutated during iteration, leading to silent failures or skipped/duplicated entries.

**Vulnerable:**
```solidity
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

contract TokenWhitelist {
    using EnumerableSet for EnumerableSet.AddressSet;
    EnumerableSet.AddressSet private _allowedTokens;

    function addToken(address token) external onlyOwner {
        // BUG: Return value not checked — silent no-op if already present
        _allowedTokens.add(token);
    }

    function removeAllBlacklisted(address[] calldata blacklist) external onlyOwner {
        // BUG: Removing during iteration by index causes skips
        for (uint256 i = 0; i < _allowedTokens.length(); i++) {
            for (uint256 j = 0; j < blacklist.length; j++) {
                if (_allowedTokens.at(i) == blacklist[j]) {
                    _allowedTokens.remove(blacklist[j]);
                    // After remove, element at index i changed — next iteration skips an element
                }
            }
        }
    }
}
```

**Fixed:**
```solidity
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

contract TokenWhitelist {
    using EnumerableSet for EnumerableSet.AddressSet;
    EnumerableSet.AddressSet private _allowedTokens;

    function addToken(address token) external onlyOwner {
        bool added = _allowedTokens.add(token);
        require(added, "token already whitelisted");
    }

    function removeTokens(address[] calldata tokens) external onlyOwner {
        // Remove by value — no iteration over the set during mutation
        for (uint256 i = 0; i < tokens.length; i++) {
            bool removed = _allowedTokens.remove(tokens[i]);
            require(removed, "token not in set");
        }
    }

    function isAllowed(address token) external view returns (bool) {
        return _allowedTokens.contains(token);
    }
}
```

### Detect
For every data structure operation: (1) verify deletions clean all cross-references, (2) verify array removals don't create gaps, (3) verify key changes clear old mapping entries, (4) verify array growth is bounded or paginated, (5) verify EnumerableSet/Map return values are checked and mutation doesn't occur during iteration.

### Remediation
Clean all cross-references on deletion. Use swap-and-pop for unordered array removal. Clear old mapping entries when keys change. Cap array growth or use pagination. Check return values from EnumerableSet/Map operations.

## CL-GEN-03: DoS Resistance Invariant

**Rule:** `EVM-GEN-DOS-01`
**Severity:** medium-high

### Description
The contract has user-facing functions that iterate over dynamic data structures, process batches, accept deposits from arbitrary addresses, rely on balance checks, or have permissionless initialization. Functions iterate over user-controlled arrays without bounds, batch operations attempt to process all items in a single transaction, attackers can cheaply inflate data structures, forced ETH breaks balance invariants, or permissionless initializers are front-runnable. Critical functions become permanently uncallable due to gas limits, protocol operations halt, dust deposits inflate storage costs, force-sent ETH breaks accounting logic, and front-run initialization steals contract ownership.

### Patterns
### Pattern 1: Unbounded Loop Over User-Controlled Array
A function iterates over an array whose length grows with user actions, eventually exceeding the block gas limit and making the function permanently uncallable.

**Vulnerable:**
```solidity
contract Rewards {
    address[] public stakers;
    mapping(address => uint256) public staked;

    function stake(uint256 amount) external {
        if (staked[msg.sender] == 0) {
            stakers.push(msg.sender); // Array grows with each new staker
        }
        staked[msg.sender] += amount;
    }

    function distributeRewards() external onlyOwner {
        uint256 reward = address(this).balance / stakers.length;
        // BUG: If stakers array grows to thousands of entries,
        // this loop exceeds block gas limit — rewards are permanently stuck
        for (uint256 i = 0; i < stakers.length; i++) {
            payable(stakers[i]).transfer(reward);
        }
    }
}
```

**Fixed:**
```solidity
contract Rewards {
    address[] public stakers;
    mapping(address => uint256) public staked;
    mapping(address => uint256) public pendingRewards;

    function stake(uint256 amount) external {
        if (staked[msg.sender] == 0) {
            stakers.push(msg.sender);
        }
        staked[msg.sender] += amount;
    }

    function distributeRewards(uint256 startIdx, uint256 batchSize) external onlyOwner {
        uint256 end = startIdx + batchSize;
        if (end > stakers.length) end = stakers.length;
        uint256 reward = address(this).balance / stakers.length;

        for (uint256 i = startIdx; i < end; i++) {
            // Credit rewards — users claim via pull pattern
            pendingRewards[stakers[i]] += reward;
        }
    }

    function claimRewards() external {
        uint256 amount = pendingRewards[msg.sender];
        require(amount > 0, "no rewards");
        pendingRewards[msg.sender] = 0;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "claim failed");
    }
}
```

### Pattern 2: Block Gas Limit DoS via Batch Operation
A batch processing function attempts to handle all pending items in a single transaction, exceeding the block gas limit when the queue is large.

**Vulnerable:**
```solidity
contract WithdrawalQueue {
    struct Request {
        address user;
        uint256 amount;
    }

    Request[] public queue;

    function requestWithdrawal(uint256 amount) external {
        queue.push(Request(msg.sender, amount));
    }

    function processAllWithdrawals() external onlyOwner {
        // BUG: Processes entire queue in one tx — will exceed gas limit
        for (uint256 i = 0; i < queue.length; i++) {
            payable(queue[i].user).transfer(queue[i].amount);
        }
        delete queue;
    }
}
```

**Fixed:**
```solidity
contract WithdrawalQueue {
    struct Request {
        address user;
        uint256 amount;
    }

    Request[] public queue;
    uint256 public processedIndex;

    function requestWithdrawal(uint256 amount) external {
        queue.push(Request(msg.sender, amount));
    }

    function processWithdrawals(uint256 batchSize) external onlyOwner {
        uint256 end = processedIndex + batchSize;
        if (end > queue.length) end = queue.length;

        for (uint256 i = processedIndex; i < end; i++) {
            (bool ok,) = payable(queue[i].user).call{value: queue[i].amount}("");
            if (ok) {
                delete queue[i];
            }
        }

        processedIndex = end;

        // Reset when fully processed
        if (processedIndex >= queue.length) {
            delete queue;
            processedIndex = 0;
        }
    }
}
```

### Pattern 3: Griefing via Dust Deposits
An attacker sends minimal amounts to create entries or extend arrays cheaply, inflating storage and making iteration-dependent functions unusable.

**Vulnerable:**
```solidity
contract Crowdfund {
    address[] public contributors;
    mapping(address => uint256) public contributions;

    // BUG: No minimum deposit — attacker can call with 1 wei thousands of times
    // with different addresses to inflate the contributors array
    function contribute() external payable {
        if (contributions[msg.sender] == 0) {
            contributors.push(msg.sender);
        }
        contributions[msg.sender] += msg.value;
    }

    function refundAll() external onlyOwner {
        // Iterates over potentially griefed array — gas limit DoS
        for (uint256 i = 0; i < contributors.length; i++) {
            uint256 amount = contributions[contributors[i]];
            if (amount > 0) {
                contributions[contributors[i]] = 0;
                payable(contributors[i]).transfer(amount);
            }
        }
    }
}
```

**Fixed:**
```solidity
contract Crowdfund {
    address[] public contributors;
    mapping(address => uint256) public contributions;
    uint256 public constant MIN_CONTRIBUTION = 0.01 ether;

    function contribute() external payable {
        // Minimum threshold prevents dust griefing
        require(msg.value >= MIN_CONTRIBUTION, "below minimum");
        if (contributions[msg.sender] == 0) {
            contributors.push(msg.sender);
        }
        contributions[msg.sender] += msg.value;
    }

    function refund() external {
        // Pull-pattern: each contributor claims their own refund
        uint256 amount = contributions[msg.sender];
        require(amount > 0, "nothing to refund");
        contributions[msg.sender] = 0;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "refund failed");
    }
}
```

### Pattern 4: SELFDESTRUCT Griefing
An attacker force-sends ETH into a contract via `selfdestruct`, breaking `address(this).balance` invariants that the contract relies on for accounting.

**Vulnerable:**
```solidity
contract EtherVault {
    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient");
        deposits[msg.sender] -= amount;
        totalDeposits -= amount;
        payable(msg.sender).transfer(amount);
    }

    function isFullyBacked() external view returns (bool) {
        // BUG: Attacker can selfdestruct ETH into this contract,
        // making balance > totalDeposits — or use strict equality check
        // that breaks when extra ETH is received
        return address(this).balance == totalDeposits;
    }

    function withdrawSurplus() external onlyOwner {
        // BUG: Relies on balance matching totalDeposits exactly
        uint256 surplus = address(this).balance - totalDeposits;
        require(surplus > 0, "no surplus");
        payable(owner).transfer(surplus);
    }
}
```

**Fixed:**
```solidity
contract EtherVault {
    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient");
        deposits[msg.sender] -= amount;
        totalDeposits -= amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "transfer failed");
    }

    function isFullyBacked() external view returns (bool) {
        // Use >= instead of == to tolerate force-sent ETH
        return address(this).balance >= totalDeposits;
    }

    function withdrawSurplus() external onlyOwner {
        // Safe: works correctly even with force-sent ETH
        uint256 surplus = address(this).balance - totalDeposits;
        require(surplus > 0, "no surplus");
        (bool ok,) = payable(owner).call{value: surplus}("");
        require(ok, "transfer failed");
    }
}
```

### Pattern 5: Front-Running Initialization Race
A permissionless `initialize()` function can be called by an attacker before the legitimate deployer, allowing the attacker to set themselves as owner or inject malicious parameters.

**Vulnerable:**
```solidity
contract LendingPoolV1 {
    address public owner;
    address public oracle;
    uint256 public liquidationThreshold;
    bool public initialized;

    // BUG: Anyone can call initialize — attacker front-runs deployer
    function initialize(address _oracle, uint256 _threshold) external {
        require(!initialized, "already initialized");
        initialized = true;
        owner = msg.sender; // Attacker becomes owner
        oracle = _oracle;   // Attacker sets malicious oracle
        liquidationThreshold = _threshold;
    }

    function liquidate(address user) external {
        uint256 price = IOracle(oracle).getPrice(); // Attacker-controlled oracle
        // ...
    }
}
```

**Fixed:**
```solidity
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract LendingPoolV1 is Initializable {
    address public owner;
    address public oracle;
    uint256 public liquidationThreshold;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // Initialize via proxy deployment in same tx — cannot be front-run
    function initialize(
        address _owner,
        address _oracle,
        uint256 _threshold
    ) external initializer {
        require(_owner != address(0), "zero owner");
        require(_oracle != address(0), "zero oracle");
        require(_threshold > 0 && _threshold <= 10000, "invalid threshold");
        owner = _owner;
        oracle = _oracle;
        liquidationThreshold = _threshold;
    }

    function liquidate(address user) external {
        uint256 price = IOracle(oracle).getPrice();
        // ...
    }
}
```

### Detect
For every user-facing function: (1) verify loops over dynamic arrays are bounded or paginated, (2) verify batch operations have configurable size limits, (3) verify minimum thresholds prevent dust griefing, (4) verify balance checks tolerate force-sent ETH, (5) verify initialization cannot be front-run.

### Remediation
Bound loops with pagination. Process batches with configurable size limits. Require minimum deposit thresholds. Use internal accounting instead of `address(this).balance`. Protect initialization with deployer checks or CREATE2 determinism.

## CL-GEN-04: Native Token (ETH) Handling Invariant

**Rule:** `EVM-GEN-ETH-01`
**Severity:** low-medium

### Description
The contract interacts with native tokens (ETH/BNB/MATIC) via payable functions, receive()/fallback(), or WETH wrapping/unwrapping. Native token handling errors span five interrelated patterns: msg.value double-counting in loops, missing overpayment refunds, broken balance invariants from forced ETH, inconsistent ETH/WETH paths, and unswept dust accumulation. These can lead to fund loss, locked ETH, broken accounting, and protocol insolvency.

### Patterns
### Pattern 1: msg.value Not Validated or Double-Counted in Loops
msg.value is a transaction-level constant that does not decrease when "spent" in sub-operations. Using it inside a loop or across multiple delegatecall frames allows the same ETH to be credited multiple times.

**Vulnerable:**
```solidity
// VULNERABLE: msg.value checked per iteration but never consumed
function batchDeposit(address[] calldata vaults) external payable {
    for (uint256 i = 0; i < vaults.length; i++) {
        require(msg.value >= DEPOSIT_AMOUNT, "Insufficient");
        IVault(vaults[i]).deposit{value: DEPOSIT_AMOUNT}(msg.sender);
        // BUG: msg.value still equals original amount on next iteration
    }
}

// ALSO VULNERABLE: payable function with ERC20 path doesn't reject msg.value
function pay(address token, uint256 amount) external payable {
    if (token == address(0)) {
        require(msg.value >= amount);
    } else {
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        // BUG: msg.value is silently accepted and locked
    }
}
```

**Fixed:**
```solidity
// FIXED: Track remaining balance
function batchDepositFixed(address[] calldata vaults) external payable {
    uint256 remaining = msg.value;
    for (uint256 i = 0; i < vaults.length; i++) {
        require(remaining >= DEPOSIT_AMOUNT, "Insufficient");
        remaining -= DEPOSIT_AMOUNT;
        IVault(vaults[i]).deposit{value: DEPOSIT_AMOUNT}(msg.sender);
    }
    if (remaining > 0) payable(msg.sender).transfer(remaining);
}
```

### Pattern 2: Missing ETH Refund for Overpayment
The contract validates msg.value >= requiredAmount but does not compute or return the surplus, permanently locking excess ETH.

**Vulnerable:**
```solidity
// VULNERABLE: Excess ETH trapped
function mint(uint256 qty) external payable {
    require(msg.value >= price * qty, "Underpaid");
    _mint(msg.sender, qty);
    // No refund of msg.value - price * qty
}

// VULNERABLE: Push refund enables DoS
function bid() external payable {
    require(msg.value > highestBid);
    payable(previousBidder).transfer(previousBid); // Reverts if previousBidder can't receive
    highestBid = msg.value;
    previousBidder = msg.sender;
}
```

**Fixed:**
```solidity
// FIXED: Strict equality + pull pattern
function mintFixed(uint256 qty) external payable {
    require(msg.value == price * qty, "Exact payment required");
    _mint(msg.sender, qty);
}
```

### Pattern 3: Forced ETH via selfdestruct/coinbase Breaks Invariants
ETH can be forcibly sent to any contract via selfdestruct or coinbase rewards, bypassing receive() and fallback(). Contracts that assume their balance only changes through defined entry points have a broken invariant.

**Vulnerable:**
```solidity
// VULNERABLE: Strict balance check brickable via selfdestruct dust
function finalize() external {
    require(address(this).balance == totalDeposits, "Balance mismatch");
    // Attacker sends 1 wei via selfdestruct -> permanently bricked
    _distribute();
}

// VULNERABLE: Zero-balance gate breakable
function reset() external onlyOwner {
    require(address(this).balance == 0, "Funds remaining");
    // Attacker sends dust -> reset permanently blocked
    state = State.Idle;
}

// VULNERABLE: Funding flag without value check
function fill() external payable {
    isFilled = true;           // Set even if msg.value == 0
    totalRewards += msg.value; // Remains 0 after selfdestruct top-up
}
```

**Fixed:**
```solidity
// FIXED: Internal accounting
uint256 private trackedBalance;
function deposit() external payable {
    trackedBalance += msg.value;
}
function finalize() external {
    require(trackedBalance >= threshold, "Insufficient deposits");
    _distribute();
}
```

### Pattern 4: Inconsistent ETH/WETH Handling
The ETH and WETH code paths have asymmetric validation, missing payable modifiers, or conflated address semantics, causing swap failures, untracked deposits, or fund lock.

**Vulnerable:**
```solidity
// VULNERABLE: WETH address conflated with native ETH
function swap(address tokenIn, uint256 amount) external payable {
    if (tokenIn == address(WETH)) {
        // Assumes native ETH, but user may hold WETH ERC20
        require(msg.value >= amount);
    } else {
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amount);
    }
}

// VULNERABLE: Unrestricted receive allows untracked deposits
receive() external payable {} // Anyone can send ETH, breaks accounting

// VULNERABLE: Missing payable on forwarder
function execute(address target, bytes calldata data) external {
    // Cannot receive msg.value - will revert if caller sends ETH
    (bool ok,) = target.call{value: msg.value}(data);
}
```

**Fixed:**
```solidity
// FIXED: Restricted receive + distinct handling
receive() external payable {
    require(msg.sender == address(WETH), "Only WETH unwrap");
}

function swap(address tokenIn, uint256 amount, bool isNative) external payable {
    if (isNative) {
        require(msg.value == amount);
        WETH.deposit{value: amount}();
    } else {
        require(msg.value == 0, "No ETH for token path");
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amount);
    }
}
```

### Pattern 5: Contract Dust / Unswept ETH Accumulation
ETH accumulates in the contract from fees, rounding, failed transfers, or unneeded receive() functions, with no mechanism to recover the residual balance.

**Vulnerable:**
```solidity
// VULNERABLE: Fees collected but no withdrawal
function collectFee() internal {
    uint256 fee = msg.value * FEE_BPS / 10000;
    protocolFees += fee;
    // No function exists to withdraw protocolFees
}

// VULNERABLE: Empty receive with no sweep
receive() external payable {} // Boilerplate, but ETH gets stuck

// VULNERABLE: Sweep doesn't exclude core token
function sweep(address token) external onlyOwner {
    IERC20(token).transfer(owner, IERC20(token).balanceOf(address(this)));
    // Can sweep the staking token, causing insolvency
}
```

**Fixed:**
```solidity
// FIXED: Proper sweep with exclusions
function sweepETH() external onlyOwner {
    uint256 sweepable = address(this).balance - trackedDeposits;
    require(sweepable > 0, "Nothing to sweep");
    payable(owner).transfer(sweepable);
}

function sweepToken(address token) external onlyOwner {
    require(token != stakingToken, "Cannot sweep core token");
    IERC20(token).transfer(owner, IERC20(token).balanceOf(address(this)));
}
```

### Detect
Check for: (1) msg.value usage inside loops or delegatecall multicall; (2) payable functions using >= on msg.value without refund; (3) address(this).balance used in equality checks or accounting; (4) asymmetric ETH/WETH code paths or missing payable modifiers; (5) receive()/fallback() without corresponding sweep/withdrawal mechanisms.

### Remediation
Use internal accounting variables instead of address(this).balance. Track msg.value consumption in a local variable. Enforce strict equality or implement refund logic. Restrict receive() to trusted senders. Implement sweep functions with core-token exclusions.

## CL-GEN-05: Event Emission Invariant

**Rule:** `EVM-GEN-EVT-01`
**Severity:** informational-low

### Description
The contract modifies state (storage writes, transfers, role changes) in functions that should be observable by off-chain systems. Events are missing, use wrong parameters, lack indexed fields, capture pre-update state, or are absent from some execution paths. Off-chain indexers, subgraphs, monitoring bots, and front-ends receive incomplete or incorrect data, leading to state desynchronization, broken UIs, missed alerts, and inability to reconstruct on-chain history.

### Patterns
### Pattern 1: Missing Event Emission on State Change
A state-modifying function has no `emit` statement. Critical for off-chain indexing, monitoring, and governance transparency.

**Vulnerable:**
```solidity
contract Registry {
    address public admin;
    uint256 public threshold;

    function setThreshold(uint256 _newThreshold) external onlyOwner {
        // No event emitted - off-chain systems cannot detect this change
        threshold = _newThreshold;
    }

    function setAdmin(address _newAdmin) external onlyOwner {
        // No event emitted - admin change is invisible to monitors
        admin = _newAdmin;
    }
}
```

**Fixed:**
```solidity
contract Registry {
    address public admin;
    uint256 public threshold;

    event ThresholdUpdated(uint256 indexed oldThreshold, uint256 indexed newThreshold);
    event AdminChanged(address indexed previousAdmin, address indexed newAdmin);

    function setThreshold(uint256 _newThreshold) external onlyOwner {
        uint256 oldThreshold = threshold;
        threshold = _newThreshold;
        emit ThresholdUpdated(oldThreshold, _newThreshold);
    }

    function setAdmin(address _newAdmin) external onlyOwner {
        address oldAdmin = admin;
        admin = _newAdmin;
        emit AdminChanged(oldAdmin, _newAdmin);
    }
}
```

### Pattern 2: Incorrect or Misleading Event Parameters
Event emits wrong variable (e.g., old value instead of new, wrong address, input instead of actual). Causes incorrect off-chain state reconstruction.

**Vulnerable:**
```solidity
contract Exchange {
    event TradeFulfilled(address indexed trader, uint256 amount);
    event Transfer(address indexed from, address indexed to, uint256 value);

    function fulfillTrade(uint256 amount) external {
        uint256 fee = amount * feeBps / 10000;
        uint256 finalAmount = amount - fee;
        _transfer(msg.sender, finalAmount);
        // BUG: Emits original amount instead of finalAmount
        emit TradeFulfilled(msg.sender, amount);
    }

    function execute(address _from, address _to, uint256 _amt) external {
        _doTransfer(_from, _to, _amt);
        // BUG: _to and _from are swapped compared to declaration
        emit Transfer(_to, _from, _amt);
    }
}
```

**Fixed:**
```solidity
contract Exchange {
    event TradeFulfilled(address indexed trader, uint256 amount, uint256 fee);
    event Transfer(address indexed from, address indexed to, uint256 value);

    function fulfillTrade(uint256 amount) external {
        uint256 fee = amount * feeBps / 10000;
        uint256 finalAmount = amount - fee;
        _transfer(msg.sender, finalAmount);
        // Emits actual post-fee amount
        emit TradeFulfilled(msg.sender, finalAmount, fee);
    }

    function execute(address _from, address _to, uint256 _amt) external {
        _doTransfer(_from, _to, _amt);
        // Arguments match declaration order
        emit Transfer(_from, _to, _amt);
    }
}
```

### Pattern 3: Missing Indexed Fields
Key parameters (addresses, IDs) not indexed, making log filtering impossible for integrators and block explorers.

**Vulnerable:**
```solidity
contract Vault {
    // BUG: address parameters not indexed - cannot filter by user
    event Deposit(address user, uint256 amount, address token);
    event Withdrawal(address user, uint256 amount);

    function deposit(address token, uint256 amount) external {
        balances[msg.sender][token] += amount;
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        emit Deposit(msg.sender, amount, token);
    }

    function withdraw(uint256 amount) external {
        balances[msg.sender][address(0)] -= amount;
        payable(msg.sender).transfer(amount);
        emit Withdrawal(msg.sender, amount);
    }
}
```

**Fixed:**
```solidity
contract Vault {
    // Indexed fields enable efficient log filtering
    event Deposit(address indexed user, uint256 amount, address indexed token);
    event Withdrawal(address indexed user, uint256 amount);

    function deposit(address token, uint256 amount) external {
        balances[msg.sender][token] += amount;
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        emit Deposit(msg.sender, amount, token);
    }

    function withdraw(uint256 amount) external {
        balances[msg.sender][address(0)] -= amount;
        payable(msg.sender).transfer(amount);
        emit Withdrawal(msg.sender, amount);
    }
}
```

### Pattern 4: Event Emitted with Stale or Pre-Update Values
Event fired before state mutation, so it logs the pre-change value rather than the post-change value. Or event uses a cached local variable that does not reflect the final state.

**Vulnerable:**
```solidity
contract Staking {
    event Staked(address indexed user, uint256 totalStaked);
    event RewardClaimed(address indexed user, uint256 rewardAmount);

    function stake(uint256 amount) external {
        // BUG: Event emits stale totalStaked before update
        emit Staked(msg.sender, stakedBalance[msg.sender]);
        stakedBalance[msg.sender] += amount;
    }

    function claimReward() external {
        uint256 reward = pendingRewards[msg.sender];
        // BUG: Event emitted before cap adjustment
        emit RewardClaimed(msg.sender, reward);
        if (reward > rewardCap) {
            reward = rewardCap;
        }
        pendingRewards[msg.sender] = 0;
        token.transfer(msg.sender, reward);
    }
}
```

**Fixed:**
```solidity
contract Staking {
    event Staked(address indexed user, uint256 totalStaked);
    event RewardClaimed(address indexed user, uint256 rewardAmount);

    function stake(uint256 amount) external {
        stakedBalance[msg.sender] += amount;
        // Event emitted after state update with correct value
        emit Staked(msg.sender, stakedBalance[msg.sender]);
    }

    function claimReward() external {
        uint256 reward = pendingRewards[msg.sender];
        if (reward > rewardCap) {
            reward = rewardCap;
        }
        pendingRewards[msg.sender] = 0;
        token.transfer(msg.sender, reward);
        // Event emitted after all adjustments with final value
        emit RewardClaimed(msg.sender, reward);
    }
}
```

### Pattern 5: Missing Events in Conditional Branches
Event emitted on one code path but not another that also modifies state (e.g., emitted on deposit but not on fee collection within the same function).

**Vulnerable:**
```solidity
contract TokenSale {
    event Purchase(address indexed buyer, uint256 amount);

    function buy(uint256 amount) external payable {
        if (amount >= bulkThreshold) {
            uint256 discount = amount * discountBps / 10000;
            uint256 finalAmount = amount - discount;
            balances[msg.sender] += finalAmount;
            // Event emitted on bulk path
            emit Purchase(msg.sender, finalAmount);
        } else {
            uint256 fee = amount * feeBps / 10000;
            uint256 finalAmount = amount - fee;
            balances[msg.sender] += finalAmount;
            collectedFees += fee;
            // BUG: No event emitted on standard purchase path
        }
    }

    function withdraw(uint256 amount) external {
        if (amount == balances[msg.sender]) {
            // Full withdrawal - closes position
            delete balances[msg.sender];
            payable(msg.sender).transfer(amount);
            emit Purchase(msg.sender, 0); // Reuses wrong event
            return;
            // BUG: Early return bypasses proper event
        }
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
        emit Purchase(msg.sender, balances[msg.sender]);
    }
}
```

**Fixed:**
```solidity
contract TokenSale {
    event Purchase(address indexed buyer, uint256 amount, uint256 fee);
    event Withdrawal(address indexed user, uint256 amount, uint256 remaining);

    function buy(uint256 amount) external payable {
        if (amount >= bulkThreshold) {
            uint256 discount = amount * discountBps / 10000;
            uint256 finalAmount = amount - discount;
            balances[msg.sender] += finalAmount;
            emit Purchase(msg.sender, finalAmount, 0);
        } else {
            uint256 fee = amount * feeBps / 10000;
            uint256 finalAmount = amount - fee;
            balances[msg.sender] += finalAmount;
            collectedFees += fee;
            // Event emitted on all paths
            emit Purchase(msg.sender, finalAmount, fee);
        }
    }

    function withdraw(uint256 amount) external {
        if (amount == balances[msg.sender]) {
            delete balances[msg.sender];
            payable(msg.sender).transfer(amount);
            emit Withdrawal(msg.sender, amount, 0);
            return;
        }
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
        emit Withdrawal(msg.sender, amount, balances[msg.sender]);
    }
}
```

### Detect
For every state-modifying function: (1) verify an event is emitted, (2) verify event parameters match post-mutation state, (3) verify key fields are indexed, (4) verify event is emitted after state update, (5) verify all conditional branches emit events.

### Remediation
Emit events for all state changes. Use post-mutation values. Index addresses and IDs. Emit after state update. Cover all conditional branches.

## CL-GEN-06: Frontrunning Invariant

**Rule:** `EVM-GEN-FRONT-01`
**Severity:** medium-high

### Description
The contract uses predictable identifiers, commit-reveal schemes, public state transitions, order systems, or balance-dependent logic accessible to external actors. On-chain transaction ordering is adversarial, and any function whose outcome depends on mempool-visible parameters, non-atomic multi-step flows, or externally manipulable state is vulnerable to frontrunning, sandwich attacks, or griefing. This can lead to denial of service via preemptive registration, identity hijacking, sandwich attacks on state transitions, forced trade execution, and fund theft through balance manipulation.

### Patterns
### Pattern 1: Predictable Identifier Frontrunning
The identifier is derived from user-controlled or predictable inputs without binding to msg.sender or using an internal nonce. Any observer can precompute the same identifier and claim it first.

**Vulnerable:**
```solidity
// VULNERABLE: Anyone can squat the salt/name/ID
function deploy(bytes32 salt) external {
    address addr = address(new Impl{salt: salt}());
}

function register(string memory name) external {
    require(registry[name] == address(0), "Taken");
    registry[name] = msg.sender;
}

function createPosition(uint256 amount) external {
    uint256 id = positions.length; // predictable
    positions.push(Position(msg.sender, amount));
}
```

**Fixed:**
```solidity
// FIXED: Salt bound to caller
function deploy(bytes32 salt) external {
    bytes32 secureSalt = keccak256(abi.encode(msg.sender, salt));
    address addr = address(new Impl{salt: secureSalt}());
}

// FIXED: Commit-reveal for name registration
function commitName(bytes32 hash) external {
    commitments[msg.sender] = Commitment(hash, block.number);
}
function revealName(string memory name, bytes32 nonce) external {
    require(keccak256(abi.encode(msg.sender, name, nonce)) == commitments[msg.sender].hash);
    require(block.number >= commitments[msg.sender].blockNum + MIN_DELAY);
    registry[name] = msg.sender;
}

// FIXED: Expected ID parameter
function createPosition(uint256 amount, uint256 expectedId) external {
    require(positions.length == expectedId, "ID mismatch");
    positions.push(Position(msg.sender, amount));
}
```

### Pattern 2: Commit-Reveal Scheme Bypass
The commitment hash does not include msg.sender, or the reveal phase does not validate the original committer's identity. Alternatively, the revealed data is not validated for semantic correctness, or there is no minimum commit duration allowing same-block commit-reveal.

**Vulnerable:**
```solidity
// VULNERABLE: Commitment not bound to sender
function commit(bytes32 _hash) external {
    commitments[msg.sender] = _hash;
}
// Attacker copies _hash from mempool and calls commit() themselves

// VULNERABLE: No validation of revealed data
function reveal(bytes memory data, bytes32 salt) external {
    require(keccak256(abi.encodePacked(data, salt)) == commitments[msg.sender]);
    DecodedData memory d = abi.decode(data, (DecodedData));
    // BUG: d.deadline could be in the past, d.amount could be zero
    state = d;
}
```

**Fixed:**
```solidity
// FIXED: Sender-bound commitment with validation
function commit(bytes32 _hash) external {
    commitments[msg.sender] = Commitment(_hash, block.number);
}
function reveal(bytes memory data, bytes32 salt) external {
    Commitment memory c = commitments[msg.sender];
    require(block.number >= c.blockNum + MIN_DELAY, "Too early");
    require(keccak256(abi.encode(msg.sender, data, salt)) == c.hash, "Invalid");
    DecodedData memory d = abi.decode(data, (DecodedData));
    require(d.deadline > block.timestamp, "Stale deadline");
    require(d.amount > 0, "Zero amount");
    state = d;
    delete commitments[msg.sender];
}
```

### Pattern 3: Permissionless State Transition Frontrunning
A public function triggers a meaningful state change that creates a window of vulnerability exploitable via transaction ordering. The state transition is not atomic with its safety prerequisites.

**Vulnerable:**
```solidity
// VULNERABLE: Non-atomic unlock + collateralize
function unlock(uint256 id) external isOwner(id) {
    isLocked[id] = false;
    // Attacker liquidates here before owner deposits collateral
}
function deposit(uint256 id) external payable {
    balances[id] += msg.value;
}

// VULNERABLE: Persistent guard
modifier persistentGuard() {
    require(_status != LOCKED);
    _status = LOCKED;
    _;
    // BUG: _status never reset
}

// VULNERABLE: Multiple valid permits
mapping(bytes32 => bool) public isValidAction;
function authorize(bytes32 hash) external onlyOwner {
    isValidAction[hash] = true; // old hashes remain valid
}
```

**Fixed:**
```solidity
// FIXED: Atomic unlock with minimum collateral
function unlock(uint256 id) external payable isOwner(id) {
    require(balances[id] + msg.value >= MIN_COLLATERAL, "Undercollateralized");
    balances[id] += msg.value;
    isLocked[id] = false;
}

// FIXED: Guard resets in same flow
modifier transientGuard() {
    require(_status != LOCKED);
    _status = LOCKED;
    _;
    _status = UNLOCKED;
}

// FIXED: Single active permit
bytes32 public activeAction;
function authorize(bytes32 hash) external onlyOwner {
    activeAction = hash; // overwrites previous
}
```

### Pattern 4: Order Cancellation / Modification Race
Cancellation and execution are independent transactions visible in the mempool. A searcher or counterparty can observe a pending cancel and race to execute the order before the cancellation is mined.

**Vulnerable:**
```solidity
// VULNERABLE: Cancel and fill race on same state
function cancelOrder(bytes32 orderId) external {
    require(orders[orderId].maker == msg.sender);
    delete orders[orderId];
}
function fulfillOrder(bytes32 orderId) external {
    // Searcher calls this after seeing cancelOrder in mempool
    Order memory order = orders[orderId];
    require(order.maker != address(0), "No order");
    _executeTrade(order);
    delete orders[orderId];
}
```

**Fixed:**
```solidity
// FIXED: Two-phase cancel with delay
function requestCancel(bytes32 orderId) external {
    require(orders[orderId].maker == msg.sender);
    cancelRequests[orderId] = block.number;
}
function finalizeCancel(bytes32 orderId) external {
    require(cancelRequests[orderId] != 0);
    require(block.number >= cancelRequests[orderId] + CANCEL_DELAY);
    delete orders[orderId];
}
function fulfillOrder(bytes32 orderId) external {
    require(cancelRequests[orderId] == 0, "Cancel pending");
    _executeTrade(orders[orderId]);
    delete orders[orderId];
}
```

### Pattern 5: Contract Balance / Global State Dependency
A function's behavior depends on the contract's own token balance or a global state variable that any external actor can manipulate via transfers or public interactions.

**Vulnerable:**
```solidity
// VULNERABLE: Relies on pre-existing balance
function initialize(address beneficiary, uint256 amount) external onlyAdmin {
    require(token.balanceOf(address(this)) >= amount, "Insufficient");
    _startVesting(beneficiary, amount);
}
// Attacker front-runs to claim funds deposited by another admin

// VULNERABLE: Strict equality griefing
function closePosition(address user) external {
    if (balances[user] == 0) {  // attacker dusts to prevent cleanup
        _removeFromActiveList(user);
    }
}
```

**Fixed:**
```solidity
// FIXED: Atomic fund pull
function initialize(address beneficiary, uint256 amount) external onlyAdmin {
    token.safeTransferFrom(msg.sender, address(this), amount);
    _startVesting(beneficiary, amount);
}

// FIXED: Threshold-based check
function closePosition(address user) external {
    if (balances[user] <= DUST_THRESHOLD) {
        _removeFromActiveList(user);
    }
}
```

### Detect
Check for (1) unique identifiers derived from predictable/unbound inputs, (2) commit-reveal schemes missing sender binding or data validation, (3) non-atomic state transitions creating exploitable windows, (4) order cancel/fill races without delay mechanisms, (5) function logic depending on manipulable contract balance or global state with strict equality.

### Remediation
Bind identifiers to msg.sender. Use commit-reveal with sender inclusion and minimum delay. Make state transitions atomic with their safety prerequisites. Add cancel delays or nonce-based invalidation. Pull funds atomically via transferFrom and use threshold checks instead of strict equality.

## CL-GEN-07: Conditional Logic Invariant

**Rule:** `EVM-GEN-LOGIC-01`
**Severity:** low-high

### Description
The contract uses conditional branches (if/else, ternary, require) to partition execution paths based on input values, state, or external data. Boundary checks use the wrong comparison operator, boolean logic is inverted or mis-combined, short-circuit evaluation hides side effects, conditional chains lack exhaustive coverage, or strict equality is used on non-deterministic values. Edge cases route to the wrong branch, causing incorrect fee calculations, bypassed validation, unreachable code paths, locked funds, or exploitable timing/balance-dependent conditions.

### Patterns
### Pattern 1: Off-By-One in Boundary Check
Using `<` instead of `<=` (or vice versa) causes an edge-case value to be routed to the wrong branch, typically affecting the boundary between fee tiers, access thresholds, or time windows.

**Vulnerable:**
```solidity
contract Vesting {
    uint256 public vestingEnd;
    mapping(address => uint256) public allocation;
    mapping(address => bool) public claimed;

    function claim() external {
        require(!claimed[msg.sender], "already claimed");
        // BUG: Uses `<` — if block.timestamp == vestingEnd, claim is blocked
        // User must wait one more second after vesting period ends
        require(block.timestamp < vestingEnd, "vesting not ended");
        claimed[msg.sender] = true;
        payable(msg.sender).transfer(allocation[msg.sender]);
    }

    function isVestingComplete() external view returns (bool) {
        // BUG: Uses `>` — returns false when timestamp equals vestingEnd
        return block.timestamp > vestingEnd;
    }
}
```

**Fixed:**
```solidity
contract Vesting {
    uint256 public vestingEnd;
    mapping(address => uint256) public allocation;
    mapping(address => bool) public claimed;

    function claim() external {
        require(!claimed[msg.sender], "already claimed");
        // Correct: `>=` allows claim at exactly vestingEnd
        require(block.timestamp >= vestingEnd, "vesting not ended");
        claimed[msg.sender] = true;
        payable(msg.sender).transfer(allocation[msg.sender]);
    }

    function isVestingComplete() external view returns (bool) {
        return block.timestamp >= vestingEnd;
    }
}
```

### Pattern 2: Negated or Inverted Condition
Boolean logic is reversed -- `!` applied incorrectly, `&&` used where `||` is needed, or condition semantics are swapped, causing the opposite of intended behavior.

**Vulnerable:**
```solidity
contract Lending {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public minCollateralRatio; // e.g., 150 = 150%

    function liquidate(address borrower) external {
        uint256 ratio = (collateral[borrower] * 100) / debt[borrower];
        // BUG: Condition inverted — liquidates healthy positions, protects unhealthy ones
        require(ratio >= minCollateralRatio, "not liquidatable");
        // Should be ratio < minCollateralRatio
        _executeLiquidation(borrower);
    }

    function isHealthy(address user) external view returns (bool) {
        // BUG: `&&` should be `||` — both conditions must fail for unhealthy
        return collateral[user] > 0 && debt[user] == 0;
        // A user with collateral AND debt is considered healthy
    }
}
```

**Fixed:**
```solidity
contract Lending {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public minCollateralRatio;

    function liquidate(address borrower) external {
        uint256 ratio = (collateral[borrower] * 100) / debt[borrower];
        // Correct: liquidate only undercollateralized positions
        require(ratio < minCollateralRatio, "not liquidatable");
        _executeLiquidation(borrower);
    }

    function isHealthy(address user) external view returns (bool) {
        // Correct: healthy if no debt OR sufficient collateral ratio
        if (debt[user] == 0) return true;
        uint256 ratio = (collateral[user] * 100) / debt[user];
        return ratio >= minCollateralRatio;
    }
}
```

### Pattern 3: Short-Circuit Evaluation Side Effect
Code relies on the second operand of `&&` or `||` to execute a side effect, but short-circuit evaluation skips it when the first operand determines the result.

**Vulnerable:**
```solidity
contract Raffle {
    mapping(address => bool) public entered;
    mapping(address => uint256) public tickets;
    uint256 public ticketPrice;

    function enter() external payable {
        // BUG: If entered[msg.sender] is true, the second operand (which has the
        // side effect of adding a ticket) is never evaluated due to short-circuit
        // The function silently does nothing for repeat entries
        if (!entered[msg.sender] && _addTicket(msg.sender)) {
            entered[msg.sender] = true;
        }
    }

    function _addTicket(address user) internal returns (bool) {
        require(msg.value >= ticketPrice, "insufficient payment");
        tickets[user] += 1;
        return true;
    }
}
```

**Fixed:**
```solidity
contract Raffle {
    mapping(address => bool) public entered;
    mapping(address => uint256) public tickets;
    uint256 public ticketPrice;

    function enter() external payable {
        require(!entered[msg.sender], "already entered");
        require(msg.value >= ticketPrice, "insufficient payment");

        // Separate side-effect logic from conditional evaluation
        tickets[msg.sender] += 1;
        entered[msg.sender] = true;
    }
}
```

### Pattern 4: Missing Default/Else Case
An if-else chain or conditional dispatch does not cover all possible input values, allowing state to fall through silently without any action or revert.

**Vulnerable:**
```solidity
contract PaymentRouter {
    enum Tier { Bronze, Silver, Gold, Platinum }
    mapping(address => Tier) public userTier;

    function calculateDiscount(address user, uint256 amount) external view returns (uint256) {
        Tier tier = userTier[user];

        if (tier == Tier.Silver) {
            return amount * 5 / 100;
        } else if (tier == Tier.Gold) {
            return amount * 10 / 100;
        } else if (tier == Tier.Platinum) {
            return amount * 20 / 100;
        }
        // BUG: Bronze tier (default enum value 0) falls through — returns 0
        // No explicit handling and no revert, silently gives no discount
        // If new tier is added to enum, it also falls through silently
    }

    function processPayment(uint256 amount, uint8 method) external {
        if (method == 1) {
            _payWithToken(amount);
        } else if (method == 2) {
            _payWithETH(amount);
        }
        // BUG: method == 0 or method >= 3 silently does nothing
        // Payment marked as processed but no funds moved
    }
}
```

**Fixed:**
```solidity
contract PaymentRouter {
    enum Tier { Bronze, Silver, Gold, Platinum }
    mapping(address => Tier) public userTier;

    function calculateDiscount(address user, uint256 amount) external view returns (uint256) {
        Tier tier = userTier[user];

        if (tier == Tier.Bronze) {
            return 0;
        } else if (tier == Tier.Silver) {
            return amount * 5 / 100;
        } else if (tier == Tier.Gold) {
            return amount * 10 / 100;
        } else if (tier == Tier.Platinum) {
            return amount * 20 / 100;
        } else {
            revert("unknown tier");
        }
    }

    function processPayment(uint256 amount, uint8 method) external {
        if (method == 1) {
            _payWithToken(amount);
        } else if (method == 2) {
            _payWithETH(amount);
        } else {
            revert("unsupported payment method");
        }
    }
}
```

### Pattern 5: Strict Equality on Non-Deterministic Value
Using `==` to compare against `block.timestamp`, `address(this).balance`, or other values that may not match an exact target, causing conditions to be practically unreachable.

**Vulnerable:**
```solidity
contract TimeLock {
    mapping(uint256 => uint256) public unlockTime;
    mapping(uint256 => uint256) public lockedAmount;

    function unlock(uint256 lockId) external {
        // BUG: Strict equality — block.timestamp must exactly equal unlockTime
        // Virtually impossible to hit the exact second
        require(block.timestamp == unlockTime[lockId], "not unlock time");
        payable(msg.sender).transfer(lockedAmount[lockId]);
        delete lockedAmount[lockId];
    }

    function checkBalance() external view returns (bool) {
        // BUG: Strict equality on balance — attacker can send 1 wei to break this
        require(address(this).balance == totalDeposits, "balance mismatch");
        return true;
    }
}
```

**Fixed:**
```solidity
contract TimeLock {
    mapping(uint256 => uint256) public unlockTime;
    mapping(uint256 => uint256) public lockedAmount;
    uint256 public totalDeposits;

    function unlock(uint256 lockId) external {
        // Range check: allow unlock at or after the unlock time
        require(block.timestamp >= unlockTime[lockId], "too early");
        payable(msg.sender).transfer(lockedAmount[lockId]);
        delete lockedAmount[lockId];
    }

    function checkBalance() external view returns (bool) {
        // Range check: balance must be at least totalDeposits (extra ETH is acceptable)
        require(address(this).balance >= totalDeposits, "insufficient balance");
        return true;
    }
}
```

### Detect
For every conditional branch: (1) verify boundary operators handle edge values correctly, (2) verify boolean logic matches intended semantics, (3) verify side effects are not hidden by short-circuit evaluation, (4) verify all branches are exhaustively covered, (5) verify non-deterministic values use range checks instead of strict equality.

### Remediation
Audit boundary operators for off-by-one. Verify boolean logic with truth tables. Avoid side effects in short-circuit operands. Add explicit default/else branches. Use range checks instead of strict equality on volatile values.

## CL-GEN-08: Reentrancy Invariant

**Rule:** `EVM-GEN-REENT-01`
**Severity:** medium-high

### Description
The contract performs external calls (transfers, low-level calls, safe-transfers, hooks, or callbacks) and has state variables that track balances, ownership, entitlements, or protocol accounting. State is read or modified in an unsafe temporal relationship with an external call, allowing an attacker or intermediate protocol to observe or exploit inconsistent state during re-entrant execution. This can lead to fund drainage, share inflation, oracle manipulation, double-claiming, or protocol state corruption.

### Patterns
### Pattern 1: Classic Reentrancy (State After External Call)
State is updated after an external call (transfer, low-level call, send). An attacker re-enters the function before state is finalized, passing stale checks repeatedly.

**Vulnerable:**
```solidity
// VULNERABLE: State update after external call
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient");
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok);
    balances[msg.sender] -= amount; // BUG: too late
}
```

**Fixed:**
```solidity
// FIXED: CEI pattern
function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount, "Insufficient");
    balances[msg.sender] -= amount; // Effect before interaction
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok);
}
```

### Pattern 2: Read-Only Reentrancy
View functions return stale state during a callback window. Another protocol reads these stale values (e.g., `get_virtual_price`, `totalAssets`, `getRate`) to compute prices, collateral values, or share ratios, leading to manipulation.

**Vulnerable:**
```solidity
// VULNERABLE: View returns stale price mid-callback
contract Pool {
    function remove_liquidity() external {
        // Burns LP tokens, sends ETH via callback
        _burn(msg.sender, shares);
        msg.sender.call{value: ethAmount}(""); // callback here
        _updateReserves(); // reserves not yet updated during callback
    }
    function get_virtual_price() external view returns (uint256) {
        return totalAssets / totalSupply; // stale during callback
    }
}

contract Lending {
    // VULNERABLE: reads stale price during reentrancy window
    function borrow(uint256 amount) external {
        uint256 collateralValue = pool.get_virtual_price() * userLP;
        require(collateralValue >= amount * ratio);
        _transfer(msg.sender, amount);
    }
}
```

**Fixed:**
```solidity
// FIXED: Check lock status before reading
function borrow(uint256 amount) external {
    require(!pool.isLocked(), "Pool in transition");
    uint256 collateralValue = pool.get_virtual_price() * userLP;
    require(collateralValue >= amount * ratio);
    _transfer(msg.sender, amount);
}
```

### Pattern 3: Cross-Function Reentrancy
Attacker re-enters a DIFFERENT function that reads state not yet updated by the first function. Both functions share state variables but only one (or neither) has a reentrancy guard.

**Vulnerable:**
```solidity
// VULNERABLE: Two functions share `balances` but only withdraw sends ETH
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool ok, ) = msg.sender.call{value: amount}(""); // attacker re-enters transfer()
    require(ok);
    balances[msg.sender] -= amount;
}

function transfer(address to, uint256 amount) external {
    // No reentrancy guard — reads stale balance
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    balances[to] += amount;
}
```

**Fixed:**
```solidity
// FIXED: Shared nonReentrant guard on both functions
function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok);
}

function transfer(address to, uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    balances[to] += amount;
}
```

### Pattern 4: Callback-Triggered Reentrancy (ERC721/ERC1155/Hooks)
Functions using `safeMint`, `safeTransfer`, `safeTransferFrom` (ERC721/ERC1155), Uniswap v4 hooks, or ERC777 `tokensReceived` hooks trigger callbacks that allow re-entry before state is finalized.

**Vulnerable:**
```solidity
// VULNERABLE: safeMint triggers onERC721Received before state update
function mint(address to) external {
    uint256 tokenId = nextId++;
    _safeMint(to, tokenId); // triggers onERC721Received callback
    totalMinted += 1; // state update after callback
    userMintCount[to] += 1; // limit check bypassed
}

// VULNERABLE: ERC1155 safeTransferFrom before accounting
function buy(uint256 amount) external {
    token.safeTransferFrom(address(this), msg.sender, id, amount, "");
    _finalizeAccounting(); // too late
}
```

**Fixed:**
```solidity
// FIXED: Update state before safe-transfer
function mint(address to) external nonReentrant {
    uint256 tokenId = nextId++;
    totalMinted += 1;
    userMintCount[to] += 1;
    _safeMint(to, tokenId);
}
```

### Pattern 5: Try-Catch State Inconsistency
State is updated before a try block containing an external call. If the external call reverts and is caught, state remains in an advanced/inconsistent position. Alternatively, state is updated only inside the try success branch, creating a CEI violation window.

**Vulnerable:**
```solidity
// VULNERABLE (variant A): State updated only on success — CEI violation
function claim(uint256 amount) external {
    require(entitled[msg.sender] >= claimed[msg.sender] + amount);
    try token.transfer(msg.sender, amount) {
        claimed[msg.sender] += amount; // only on success, but reentrant before update
    } catch {
        // nothing
    }
}

// VULNERABLE (variant B): State advanced before try, not rolled back on catch
function process(uint256 index) external {
    processedIndex = index + 1; // optimistic update
    try target.execute(index) {
        // success
    } catch {
        // processedIndex is now wrong — item skipped
    }
}
```

**Fixed:**
```solidity
// FIXED: Optimistic update with rollback
function claim(uint256 amount) external nonReentrant {
    require(entitled[msg.sender] >= claimed[msg.sender] + amount);
    claimed[msg.sender] += amount;
    try token.transfer(msg.sender, amount) {
        // success
    } catch {
        claimed[msg.sender] -= amount; // rollback on failure
    }
}
```

### Detect
Identify any function where state variables are read or written in an unsafe temporal relationship with external calls -- including classic CEI violations, cross-function shared state without unified guards, callback-triggered re-entry via safe-transfer/hooks, view function reads during transitional states, and try-catch state management errors.

### Remediation
Apply the Checks-Effects-Interactions (CEI) pattern universally. Use reentrancy guards (nonReentrant) on all state-modifying external-facing functions. For read-only reentrancy, verify the target contract's lock status before reading view functions used for valuation. For try-catch patterns, update state optimistically before the try block and revert in catch.

## CL-GEN-09: State Consistency Invariant

**Rule:** `EVM-GEN-STATE-01`
**Severity:** medium-critical

### Description
The contract manages two or more coupled state variables that must remain consistent after every mutation (e.g., individual balances and aggregate totals, linked mapping-array pairs, or symmetric deposit/withdraw accounting). State mutations update some but not all coupled variables, use stale reads across external calls, commit partial state on revert, overwrite instead of accumulate, or apply asymmetric logic to inverse operations. Corrupted accounting state leads to locked funds, inflated/deflated balances, broken invariants exploitable for profit extraction, and protocol insolvency.

### Patterns
### Pattern 1: Partial State Update
A function updates one of multiple coupled variables but not the others (e.g., updates a user balance but not the global totalSupply counter).

**Vulnerable:**
```solidity
contract TokenLedger {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    uint256 public holderCount;

    function mint(address to, uint256 amount) external onlyOwner {
        // BUG: Updates balances but forgets to update totalSupply and holderCount
        balances[to] += amount;
    }

    function burn(address from, uint256 amount) external {
        require(balances[from] >= amount, "insufficient");
        balances[from] -= amount;
        // BUG: totalSupply not decremented — accounting permanently inflated
    }
}
```

**Fixed:**
```solidity
contract TokenLedger {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    uint256 public holderCount;

    function mint(address to, uint256 amount) external onlyOwner {
        bool isNewHolder = balances[to] == 0;
        balances[to] += amount;
        totalSupply += amount;
        if (isNewHolder) {
            holderCount += 1;
        }
    }

    function burn(address from, uint256 amount) external {
        require(balances[from] >= amount, "insufficient");
        balances[from] -= amount;
        totalSupply -= amount;
        if (balances[from] == 0) {
            holderCount -= 1;
        }
    }
}
```

### Pattern 2: Stale State After External Call
State is read before an external call and used after the call returns, but the external call may have modified that state via a callback or re-entrant path.

**Vulnerable:**
```solidity
contract Vault {
    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;

    function withdrawAndDonate(address charity, uint256 amount) external {
        uint256 userBalance = deposits[msg.sender]; // Read before external call
        require(userBalance >= amount, "insufficient");

        // External call — charity contract could call back into deposit()
        (bool ok,) = charity.call{value: amount}("");
        require(ok, "transfer failed");

        // BUG: Uses stale userBalance — if callback modified deposits[msg.sender],
        // this write overwrites the updated value
        deposits[msg.sender] = userBalance - amount;
        totalDeposits -= amount;
    }
}
```

**Fixed:**
```solidity
contract Vault {
    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;

    function withdrawAndDonate(address charity, uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient");

        // Effects before interaction (CEI pattern)
        deposits[msg.sender] -= amount;
        totalDeposits -= amount;

        // External call after state is finalized
        (bool ok,) = charity.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
```

### Pattern 3: Non-Atomic Multi-Step State Transition
A multi-step state transition where an intermediate step can revert after earlier steps have already committed state, leaving the contract in an inconsistent partial state.

**Vulnerable:**
```solidity
contract Escrow {
    mapping(uint256 => address) public dealBuyer;
    mapping(uint256 => address) public dealSeller;
    mapping(uint256 => uint256) public dealAmount;
    mapping(uint256 => bool) public dealFinalized;

    function finalizeDeal(uint256 dealId) external {
        require(!dealFinalized[dealId], "already finalized");

        // Step 1: Mark finalized (committed to storage)
        dealFinalized[dealId] = true;

        // Step 2: Pay seller — if this reverts, dealFinalized is still true
        // BUG: Deal marked finalized but funds never moved
        IERC20(token).transfer(dealSeller[dealId], dealAmount[dealId]);

        // Step 3: Clear deal data
        delete dealAmount[dealId];
    }
}
```

**Fixed:**
```solidity
contract Escrow {
    mapping(uint256 => address) public dealBuyer;
    mapping(uint256 => address) public dealSeller;
    mapping(uint256 => uint256) public dealAmount;
    mapping(uint256 => bool) public dealFinalized;

    function finalizeDeal(uint256 dealId) external {
        require(!dealFinalized[dealId], "already finalized");

        uint256 amount = dealAmount[dealId];
        address seller = dealSeller[dealId];

        // Perform external call first — if it reverts, no state changes persist
        bool success = IERC20(token).transfer(seller, amount);
        require(success, "transfer failed");

        // All state updates after successful external interaction
        dealFinalized[dealId] = true;
        delete dealAmount[dealId];
    }
}
```

### Pattern 4: Overwrite Instead of Accumulate
A state variable is assigned with `=` where it should be accumulated with `+=`, erasing previously stored value.

**Vulnerable:**
```solidity
contract RewardPool {
    mapping(address => uint256) public pendingRewards;
    mapping(address => uint256) public totalEarned;

    function distributeReward(address user, uint256 reward) external onlyRewarder {
        // BUG: Overwrites any existing pending rewards instead of accumulating
        pendingRewards[user] = reward;
        totalEarned[user] = reward;
    }

    function addBonus(address user, uint256 bonus) external onlyOwner {
        // BUG: Overwrites totalEarned instead of adding to it
        totalEarned[user] = bonus;
    }
}
```

**Fixed:**
```solidity
contract RewardPool {
    mapping(address => uint256) public pendingRewards;
    mapping(address => uint256) public totalEarned;

    function distributeReward(address user, uint256 reward) external onlyRewarder {
        // Accumulate rewards — prior unclaimed rewards preserved
        pendingRewards[user] += reward;
        totalEarned[user] += reward;
    }

    function addBonus(address user, uint256 bonus) external onlyOwner {
        // Accumulate into both pending and total
        pendingRewards[user] += bonus;
        totalEarned[user] += bonus;
    }
}
```

### Pattern 5: Asymmetric State Update in Bidirectional Operation
Add/remove or deposit/withdraw paths do not mirror state changes symmetrically, causing drift between coupled state variables.

**Vulnerable:**
```solidity
contract LiquidityPool {
    mapping(address => uint256) public liquidity;
    uint256 public totalLiquidity;
    uint256 public providerCount;

    function addLiquidity(uint256 amount) external {
        if (liquidity[msg.sender] == 0) {
            providerCount += 1;
        }
        liquidity[msg.sender] += amount;
        totalLiquidity += amount;
        IERC20(token).transferFrom(msg.sender, address(this), amount);
    }

    function removeLiquidity(uint256 amount) external {
        require(liquidity[msg.sender] >= amount, "insufficient");
        liquidity[msg.sender] -= amount;
        // BUG: totalLiquidity not decremented
        // BUG: providerCount not decremented when balance reaches zero
        IERC20(token).transfer(msg.sender, amount);
    }
}
```

**Fixed:**
```solidity
contract LiquidityPool {
    mapping(address => uint256) public liquidity;
    uint256 public totalLiquidity;
    uint256 public providerCount;

    function addLiquidity(uint256 amount) external {
        if (liquidity[msg.sender] == 0) {
            providerCount += 1;
        }
        liquidity[msg.sender] += amount;
        totalLiquidity += amount;
        IERC20(token).transferFrom(msg.sender, address(this), amount);
    }

    function removeLiquidity(uint256 amount) external {
        require(liquidity[msg.sender] >= amount, "insufficient");
        liquidity[msg.sender] -= amount;
        totalLiquidity -= amount;
        if (liquidity[msg.sender] == 0) {
            providerCount -= 1;
        }
        IERC20(token).transfer(msg.sender, amount);
    }
}
```

### Detect
For every state mutation: (1) verify all coupled state variables are updated together, (2) verify state is not read before and used after external calls, (3) verify multi-step transitions are atomic, (4) verify accumulation operators are used where required, (5) verify add/remove paths mirror state changes symmetrically.

### Remediation
Update all coupled state variables atomically within the same execution frame. Re-read state after external calls. Use checks-effects-interactions. Prefer accumulation operators over assignment. Mirror add/remove paths symmetrically.

## CL-GEN-10: Timestamp & Deadline Invariant

**Rule:** `EVM-GEN-TIME-01`
**Severity:** low-high

### Description
The contract has time-dependent logic (deadlines, vesting, cooldowns, schedules, time-weighted calculations). Missing deadline parameters, block.timestamp as deadline, incorrect boundary operators, uninitialized timestamps, or unbounded duration configuration can lead to stale transaction execution, premature or delayed state transitions, financial loss through time manipulation, and denial of service.

### Patterns
### Pattern 1: Missing Transaction Deadline
Time-sensitive operations (swaps, deposits, governance votes) have no deadline parameter, allowing transactions to be delayed indefinitely in the mempool and executed at unfavorable conditions.

**Vulnerable:**
```solidity
// VULNERABLE: No deadline — transaction can sit in mempool and execute days later
struct Transaction {
    address to;
    uint256 value;
    bool executed;
}

function executeProposal(uint256 txId) external {
    Transaction storage t = transactions[txId];
    require(!t.executed, "Already executed");
    t.executed = true;
    // No timestamp check — proposal from months ago can still execute
    (bool ok, ) = t.to.call{value: t.value}("");
    require(ok);
}
```

**Fixed:**
```solidity
// FIXED: User-supplied deadline enforced at execution
struct Transaction {
    address to;
    uint256 value;
    bool executed;
    uint256 deadline;
}

function executeProposal(uint256 txId) external {
    Transaction storage t = transactions[txId];
    require(!t.executed, "Already executed");
    require(block.timestamp <= t.deadline, "Transaction expired");
    t.executed = true;
    (bool ok, ) = t.to.call{value: t.value}("");
    require(ok);
}
```

### Pattern 2: block.timestamp Used as Deadline (Always Passes)
Deadline parameter is set to block.timestamp, which is always the current time at execution, making the check useless. Also covers hardcoded block time assumptions.

**Vulnerable:**
```solidity
// VULNERABLE: Deadline equals block.timestamp — always passes
function deposit(uint256 amount) external {
    // Caller passes block.timestamp as deadline, or contract sets it internally
    uint256 deadline = block.timestamp;
    require(block.timestamp <= deadline, "Expired"); // Always true!
    _processDeposit(msg.sender, amount);
}

// VULNERABLE: Hardcoded block time assumption
uint256 constant BLOCKS_PER_DAY = 7200; // Assumes 12s blocks
function isExpired(uint256 startBlock) public view returns (bool) {
    // Breaks if block time changes (e.g., post-merge, L2s with 2s blocks)
    return block.number > startBlock + BLOCKS_PER_DAY;
}
```

**Fixed:**
```solidity
// FIXED: Require deadline to be in the future, use timestamps not block counts
function deposit(uint256 amount, uint256 deadline) external {
    require(deadline > block.timestamp, "Deadline must be in the future");
    require(block.timestamp <= deadline, "Expired");
    _processDeposit(msg.sender, amount);
}
```

### Pattern 3: Incorrect Time Comparison Operators
Off-by-one in expiration checks (< vs <=, > vs >=), allowing actions at exactly the boundary when they should be blocked, or blocking when they should be allowed.

**Vulnerable:**
```solidity
// VULNERABLE: Strict inequality allows action at exact expiry second
function validatePermit(uint256 deadline) external view {
    if (block.timestamp > deadline) revert Expired();
    // When block.timestamp == deadline, permit is still valid (off-by-one)
}

// VULNERABLE: Dead-zone where neither condition matches
function getPhase() public view returns (uint8) {
    if (block.timestamp < phaseOneEnd) return 1;
    if (block.timestamp > phaseTwoStart) return 2;
    // When phaseOneEnd == phaseTwoStart, timestamp == boundary hits neither
    revert("Invalid phase"); // Unexpected revert
}
```

**Fixed:**
```solidity
// FIXED: Consistent boundary handling
function validatePermit(uint256 deadline) external view {
    if (block.timestamp >= deadline) revert Expired();
}

function getPhase() public view returns (uint8) {
    if (block.timestamp < phaseOneEnd) return 1;
    if (block.timestamp >= phaseTwoStart) return 2;
    revert("Gap between phases");
}
```

### Pattern 4: Stale Time-Dependent State
Time-weighted calculations use uninitialized timestamps (defaulting to 0, causing massive accrual), or pause mechanisms don't freeze time-based accumulators, or vesting schedules don't validate start times are in the past.

**Vulnerable:**
```solidity
// VULNERABLE: Uninitialized timestamp defaults to 0 (epoch 1970)
uint40[5] public discountTimestamps; // All zero by default

function calculateDecay(uint256 value) public view returns (uint256) {
    uint256 elapsed = block.timestamp - discountTimestamps[0]; // ~54 years!
    uint256 scale = 1e18 >> (elapsed / 30 days);
    return (value * scale) / 1e18; // Always returns 0
}

// VULNERABLE: Pause doesn't freeze expiry window
function isExpired(uint256 requestId) public view returns (bool) {
    // Expires during pause — user can't act while contract is paused
    return block.timestamp > requests[requestId].timestamp + MAX_PERIOD;
}

// VULNERABLE: Vesting starts in the past, tokens immediately claimable
function initVesting(uint256 startTime, uint256 duration) external onlyOwner {
    // No check that startTime >= block.timestamp
    vestingStart = startTime; // Could be set to a past date
    vestingDuration = duration;
}

// VULNERABLE: Absolute timestamp set before deployment, immediately unlocked
function setUnlockTime(uint256 timestamp) external onlyOwner {
    unlockTime = timestamp; // If timestamp is relative offset, treated as ~1970 absolute
}
```

**Fixed:**
```solidity
// FIXED: Initialize timestamps, pause-aware expiry, validate start times
constructor() {
    for (uint i = 0; i < 5; i++) {
        discountTimestamps[i] = uint40(block.timestamp);
    }
}

function isExpired(uint256 requestId) public view returns (bool) {
    return block.timestamp > requests[requestId].timestamp + MAX_PERIOD + totalPausedDuration;
}

function initVesting(uint256 startTime, uint256 duration) external onlyOwner {
    require(startTime >= block.timestamp, "Start must be current or future");
    vestingStart = startTime;
    vestingDuration = duration;
}
```

### Pattern 5: Unbounded or Misconfigured Time Windows
Missing validation on duration parameters (allowing 0 or extremely large values), static time windows that don't account for pause periods, or absolute vs relative timestamp confusion in configuration.

**Vulnerable:**
```solidity
// VULNERABLE: Zero duration allows instant unlock
function lock(uint256 amount, uint256 duration) external {
    // No minimum duration check — duration=0 means instant unlock
    locks[msg.sender] = Lock(amount, block.timestamp + duration);
}

// VULNERABLE: No upper bound on emission period
function setDistribution(uint256 amount, uint256 period) external onlyOwner {
    // period could be 0 (division by zero) or type(uint256).max
    rewardRate = amount / period;
}

// VULNERABLE: Dust deposit resets timelock
function deposit(uint256 amount) external {
    balances[msg.sender] += amount;
    unlockTime[msg.sender] = block.timestamp + LOCK_PERIOD; // Reset on ANY deposit
    // Attacker deposits 1 wei to reset victim's timelock via a wrapper
}
```

**Fixed:**
```solidity
// FIXED: Validate duration bounds, protect timelocks
function lock(uint256 amount, uint256 duration) external {
    require(duration >= MIN_LOCK, "Duration too short");
    require(duration <= MAX_LOCK, "Duration too long");
    locks[msg.sender] = Lock(amount, block.timestamp + duration);
}

function setDistribution(uint256 amount, uint256 period) external onlyOwner {
    require(period >= MIN_PERIOD && period <= MAX_PERIOD, "Invalid period");
    rewardRate = amount / period;
}

function deposit(uint256 amount) external {
    require(amount >= MIN_DEPOSIT, "Below minimum");
    balances[msg.sender] += amount;
    if (unlockTime[msg.sender] == 0) {
        unlockTime[msg.sender] = block.timestamp + LOCK_PERIOD;
    }
    // Don't reset existing timelock on additional deposits
}
```

### Detect
For every time-sensitive operation: (1) verify deadline parameter exists and is user-supplied, (2) verify deadline is not block.timestamp, (3) verify comparison operators handle boundaries correctly, (4) verify time accumulators are initialized and pause-aware, (5) verify duration parameters are bounded and validated.

### Remediation
Accept user-supplied deadlines. Never use block.timestamp as deadline. Use consistent comparison operators at boundaries. Initialize timestamps before use. Validate duration bounds. Freeze accumulators during pause.

## CL-GEN-11: Input & Initialization Validation Invariant

**Rule:** `EVM-GEN-VAL-01`
**Severity:** informational-medium

### Description
The contract accepts external parameters and initializes state via constructors, initializers, or setters. Missing validation is informational unless a specific impact is demonstrated (e.g., division by zero, bricked admin, locked funds). This detector covers zero-address/zero-value checks, upper bound enforcement, validation consistency across entry points, re-initialization guards, and uninitialized state usage.

### Patterns
### Pattern 1: Missing Zero-Address and Zero-Value Validation
Address parameters used for critical roles (admin, treasury, token) are not checked against address(0). Numeric parameters where zero is semantically invalid (durations, denominators, amounts) are not guarded, causing division by zero, instant unlocks, or bricked functionality.

**Vulnerable:**
```solidity
contract Vault {
    address public admin;
    uint256 public lockDuration;

    constructor(address _admin, uint256 _lockDuration) {
        admin = _admin;           // BUG: could be address(0) — admin functions bricked
        lockDuration = _lockDuration; // BUG: could be 0 — instant unlock
    }

    function setAdmin(address _admin) external onlyAdmin {
        admin = _admin; // BUG: no zero-address check
    }

    function calculateRate(uint256 total, uint256 period) internal pure returns (uint256) {
        return total / period; // BUG: division by zero if period == 0
    }
}
```

**Fixed:**
```solidity
contract Vault {
    address public admin;
    uint256 public lockDuration;

    constructor(address _admin, uint256 _lockDuration) {
        require(_admin != address(0), "zero admin");
        require(_lockDuration > 0, "zero duration");
        admin = _admin;
        lockDuration = _lockDuration;
    }

    function setAdmin(address _admin) external onlyAdmin {
        require(_admin != address(0), "zero admin");
        admin = _admin;
    }

    function calculateRate(uint256 total, uint256 period) internal pure returns (uint256) {
        require(period > 0, "zero period");
        return total / period;
    }
}
```

### Pattern 2: Missing Upper Bound Validation
Parameters for fees, rates, multipliers, or durations have no maximum, allowing values that break protocol invariants (100%+ fees, infinite locks, gas-limit arrays).

**Vulnerable:**
```solidity
contract Protocol {
    function setFee(uint256 _feeBps) external onlyOwner {
        // BUG: owner can set fee to 10000 (100%) or higher
        feeBps = _feeBps;
    }

    function setLockDuration(uint256 _duration) external onlyOwner {
        // BUG: can set to type(uint256).max — locked forever
        lockDuration = _duration;
    }
}
```

**Fixed:**
```solidity
contract Protocol {
    uint256 public constant MAX_FEE_BPS = 3000;
    uint256 public constant MAX_LOCK = 365 days;

    function setFee(uint256 _feeBps) external onlyOwner {
        require(_feeBps <= MAX_FEE_BPS, "fee too high");
        feeBps = _feeBps;
    }

    function setLockDuration(uint256 _duration) external onlyOwner {
        require(_duration > 0 && _duration <= MAX_LOCK, "invalid duration");
        lockDuration = _duration;
    }
}
```

### Pattern 3: Inconsistent Validation Across Entry Points
Constructor, initializer, and setter functions modify the same state variable but apply different validation rules. A setter rejects zero but the constructor accepts it, or vice versa. Hardcoded defaults in constructors prevent adaptation to different deployments.

**Vulnerable:**
```solidity
contract Config {
    uint256 public maxSupply;

    constructor(uint256 _maxSupply) {
        maxSupply = _maxSupply; // BUG: no validation — can deploy with 0
    }

    function setMaxSupply(uint256 _maxSupply) external onlyOwner {
        require(_maxSupply > 0 && _maxSupply <= 1_000_000, "invalid");
        maxSupply = _maxSupply;
    }
}

contract Bridge {
    constructor(address _relayer) {
        relayer = _relayer;
        requiredConfirmations = 12; // BUG: hardcoded — cannot adapt per chain
    }
}
```

**Fixed:**
```solidity
contract Config {
    uint256 public maxSupply;

    function _validateMaxSupply(uint256 _maxSupply) internal pure {
        require(_maxSupply > 0 && _maxSupply <= 1_000_000, "invalid");
    }

    constructor(uint256 _maxSupply) {
        _validateMaxSupply(_maxSupply);
        maxSupply = _maxSupply;
    }

    function setMaxSupply(uint256 _maxSupply) external onlyOwner {
        _validateMaxSupply(_maxSupply);
        maxSupply = _maxSupply;
    }
}

contract Bridge {
    constructor(address _relayer, uint256 _confirmations) {
        require(_relayer != address(0), "zero relayer");
        require(_confirmations > 0, "zero confirmations");
        relayer = _relayer;
        requiredConfirmations = _confirmations;
    }
}
```

### Pattern 4: Re-Initialization and Upgradeable Init Guards
An initializer function can be called more than once, allowing an attacker to reset ownership or configuration. Upgradeable contracts missing `_disableInitializers()` in the implementation constructor leave the implementation directly initializable.

**Vulnerable:**
```solidity
contract Governance {
    // BUG: No guard — attacker can re-initialize and seize ownership
    function initialize(address _owner) external {
        owner = _owner;
    }
}

contract VaultV1 is UUPSUpgradeable {
    // BUG: No _disableInitializers() — implementation can be initialized directly
    function initialize(address _owner) external {
        owner = _owner;
    }
}
```

**Fixed:**
```solidity
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract Governance is Initializable {
    function initialize(address _owner) external initializer {
        require(_owner != address(0), "zero owner");
        owner = _owner;
    }
}

contract VaultV1 is Initializable, UUPSUpgradeable {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() { _disableInitializers(); }

    function initialize(address _owner) external initializer {
        require(_owner != address(0), "zero owner");
        __UUPSUpgradeable_init();
        owner = _owner;
    }
}
```

### Pattern 5: Uninitialized State Variable Used in Logic
A storage variable is used in control flow or arithmetic before it is ever assigned, silently defaulting to zero or false. Timers default to epoch 0 causing massive accrual. Thresholds default to 0 allowing bypass.

**Vulnerable:**
```solidity
contract Auction {
    uint256 public minBid;
    uint256 public duration;

    function startAuction() external onlyOwner {
        started = true;
        // BUG: minBid and duration were never set — default to 0
        // Any bid of 0 wei accepted, auction ends immediately
    }

    function bid() external payable {
        require(msg.value >= minBid); // minBid is 0 — always passes
    }
}
```

**Fixed:**
```solidity
contract Auction {
    uint256 public minBid;
    uint256 public duration;

    constructor(uint256 _minBid, uint256 _duration) {
        require(_minBid > 0, "zero minBid");
        require(_duration > 0, "zero duration");
        minBid = _minBid;
        duration = _duration;
    }

    function startAuction() external onlyOwner {
        require(!started, "already started");
        started = true;
        startTime = block.timestamp;
    }
}
```

### Detect
For every function accepting parameters or initializing state: (1) verify addresses checked against zero and values checked against zero where semantically invalid, (2) verify rates, fees, and durations have upper bounds, (3) verify constructor, initializer, and setter apply identical validation for the same parameter, (4) verify initializer is callable only once and upgradeable contracts use _disableInitializers(), (5) verify state variables are assigned before use in logic.

### Remediation
Validate all inputs at entry points. Check address(0) for critical roles. Check zero for denominators and durations. Cap fees, rates, and durations. Share validation logic between constructors and setters. Use `initializer` modifier and `_disableInitializers()` for upgradeable contracts. Initialize all state before use. Note: missing validation without demonstrated impact is informational.

## CL-GEN-12: External Call & Return Value Invariant

**Rule:** `EVM-GEN-XCALL-01`
**Severity:** medium-high

### Description
The contract makes external calls and consumes return values from low-level calls, interface calls, library functions, or its own functions. Unchecked or misinterpreted return values, push-payment patterns, missing error isolation, misleading return types, and unbounded returndata copies lead to silent failures, DoS, logic bypass, state desynchronization, and gas bombs.

### Patterns
### Pattern 1: Unchecked Call and Function Return Values
Low-level `.call()` return values are not checked. ERC-20 `transfer()`/`approve()` return booleans that are ignored. Library functions like `EnumerableSet.remove()` return false on no-op but the result is discarded. Execution continues on a false assumption of success.

**Vulnerable:**
```solidity
contract Vault {
    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        // BUG: Return value not checked — silent failure
        payable(msg.sender).call{value: amount}("");
    }

    function distribute(address to, uint256 amount) external {
        // BUG: ERC-20 transfer returns bool — some tokens return false on failure
        token.transfer(to, amount);
    }

    function removeFromSet(EnumerableSet.AddressSet storage set, address user) internal {
        // BUG: remove() returns false if element not present — silent no-op
        set.remove(user);
        emit Removed(user); // Event emitted even if nothing was removed
    }
}
```

**Fixed:**
```solidity
contract Vault {
    using SafeERC20 for IERC20;

    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        (bool success,) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");
    }

    function distribute(address to, uint256 amount) external {
        token.safeTransfer(to, amount);
    }

    function removeFromSet(EnumerableSet.AddressSet storage set, address user) internal {
        bool removed = set.remove(user);
        require(removed, "Not in set");
        emit Removed(user);
    }
}
```

### Pattern 2: Push-Payment DoS
Sending ETH directly to an arbitrary address that can revert (contract with no receive, or malicious contract) blocks the entire function. Critical in auctions, refund loops, and batch payments. **Precondition:** this is only a vulnerability if (a) downstream logic depends on the transfer succeeding (e.g., the revert blocks other users' operations), AND (b) the griefing party is not the victim themselves — self-griefing (a user blocking only their own withdrawal) is a non-issue.

**Vulnerable:**
```solidity
contract Auction {
    function bid() external payable {
        require(msg.value > highestBid, "bid too low");
        // BUG: If previousBidder is a contract that reverts on receive,
        // no one else can ever bid — auction permanently stuck
        payable(previousBidder).transfer(previousBid);
        highestBidder = msg.sender;
        highestBid = msg.value;
    }
}
```

**Fixed:**
```solidity
contract Auction {
    mapping(address => uint256) public pendingWithdrawals;

    function bid() external payable {
        require(msg.value > highestBid, "bid too low");
        if (highestBidder != address(0)) {
            pendingWithdrawals[highestBidder] += highestBid;
        }
        highestBidder = msg.sender;
        highestBid = msg.value;
    }

    function withdraw() external {
        uint256 amount = pendingWithdrawals[msg.sender];
        require(amount > 0, "nothing to withdraw");
        pendingWithdrawals[msg.sender] = 0;
        (bool success,) = payable(msg.sender).call{value: amount}("");
        require(success, "withdraw failed");
    }
}
```

### Pattern 3: Inverted or Misleading Return Values
Return value check uses wrong polarity (treating false as success). Functions always return true regardless of outcome. Functions fall through without returning, silently yielding zero. Callers are given a false sense of validation.

**Vulnerable:**
```solidity
contract Bridge {
    function processTransfer(address token, address to, uint256 amount) external {
        (bool success,) = token.call(abi.encodeWithSelector(IERC20.transfer.selector, to, amount));
        // BUG: Inverted — proceeds when call FAILS
        if (!success) {
            _updateState(to, amount);
        }
    }
}

contract Oracle {
    function getPrice(address token) public view returns (uint256 price) {
        if (token == WETH) return ethPrice;
        if (token == USDC) return 1e18;
        // BUG: Unknown tokens fall through — returns 0 silently
    }
}

contract Governance {
    function validateProposal(uint256 id) internal returns (bool) {
        if (proposals[id].votes >= quorum) {
            proposals[id].validated = true;
        }
        return true; // BUG: Always returns true regardless of quorum
    }
}
```

**Fixed:**
```solidity
contract Bridge {
    function processTransfer(address token, address to, uint256 amount) external {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(IERC20.transfer.selector, to, amount)
        );
        require(success && (data.length == 0 || abi.decode(data, (bool))), "Transfer failed");
        _updateState(to, amount);
    }
}

contract Oracle {
    function getPrice(address token) public view returns (uint256 price) {
        if (token == WETH) return ethPrice;
        if (token == USDC) return 1e18;
        revert("Unsupported token");
    }
}

contract Governance {
    function validateProposal(uint256 id) internal returns (bool) {
        if (proposals[id].votes >= quorum) {
            proposals[id].validated = true;
            return true;
        }
        return false;
    }
}
```

### Pattern 4: Missing Try-Catch on Recoverable External Calls
An external call to another contract without error handling causes the entire transaction to revert when the failure is recoverable. One broken oracle takes down the whole aggregator. One failed payment blocks all payments.

**Vulnerable:**
```solidity
contract PriceAggregator {
    function getAveragePrice() external view returns (uint256) {
        uint256 total = 0;
        for (uint256 i = 0; i < oracles.length; i++) {
            // BUG: If any single oracle reverts, entire aggregation fails
            total += IOracle(oracles[i]).getPrice();
        }
        return total / oracles.length;
    }
}
```

**Fixed:**
```solidity
contract PriceAggregator {
    function getAveragePrice() external view returns (uint256) {
        uint256 total = 0;
        uint256 validCount = 0;
        for (uint256 i = 0; i < oracles.length; i++) {
            try IOracle(oracles[i]).getPrice() returns (uint256 price) {
                if (price > 0) {
                    total += price;
                    validCount += 1;
                }
            } catch {}
        }
        require(validCount > 0, "no valid prices");
        return total / validCount;
    }
}
```

### Pattern 5: Gas Bomb via Unbounded Return Data
An external call to an untrusted contract copies all returndata into memory. The callee returns a huge payload, consuming all remaining gas on memory expansion.

**Vulnerable:**
```solidity
contract Relayer {
    function relay(address target, bytes calldata data) external {
        // BUG: copies all returndata — target can return megabytes
        (bool success, bytes memory result) = target.call(data);
        require(success, "relay failed");
        emit RelayResult(target, result);
    }
}
```

**Fixed:**
```solidity
contract Relayer {
    uint256 public constant MAX_RETURN_SIZE = 256;

    function relay(address target, bytes calldata data) external {
        (bool success,) = target.call(data);
        require(success, "relay failed");
        bytes memory result;
        assembly {
            let size := returndatasize()
            if gt(size, MAX_RETURN_SIZE) { size := MAX_RETURN_SIZE }
            result := mload(0x40)
            mstore(result, size)
            returndatacopy(add(result, 0x20), 0, size)
            mstore(0x40, add(add(result, 0x20), size))
        }
        emit RelayResult(target, result);
    }
}
```

### Detect
For every external call and return value: (1) verify low-level call, ERC-20, and library return values are captured and checked, (2) verify ETH transfers to untrusted recipients use pull-payment pattern, (3) verify return value polarity is correct, all paths return explicitly, and return values accurately reflect outcomes, (4) verify recoverable external calls are wrapped in try-catch, (5) verify returndata copy size is bounded for untrusted callees.

### Remediation
Check all return values from low-level calls, ERC-20 transfers, and library operations. Use SafeERC20. Use pull-payment pattern for untrusted recipients. Verify return value polarity and ensure all code paths return explicitly. Wrap recoverable external calls in try-catch. Limit returndata copy size for untrusted callees.
