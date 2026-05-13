## CL-GAS-01: Constants, Immutables & Compiler Hints Invariant

**Rule:** `EVM-GAS-CONST-01`
**Severity:** gas

### Description
The contract has values set once (constructor/deploy time) or known at compile time, uses function parameters, or has compiler/pragma configuration choices that affect gas. Values that never change after deployment stored as regular state variables cost SLOAD (2100/100 gas) on every access. Using `memory` for read-only function parameters instead of `calldata` copies data unnecessarily. Missing custom errors, outdated pragmas, and redundant SafeMath all add avoidable gas overhead.

### Patterns
### Pattern 1: Missing constant/immutable Modifiers
Variables set at compile time or in the constructor are declared as regular storage variables, costing SLOAD on every read instead of being embedded in bytecode (constant) or stored in contract code (immutable).

**Vulnerable:**
```solidity
contract Token {
    string public name = "MyToken";       // BUG: known at compile time
    uint256 public decimals = 18;          // BUG: known at compile time
    address public factory;                // BUG: set once in constructor
    uint256 public maxSupply;              // BUG: set once in constructor

    constructor(address _factory, uint256 _maxSupply) {
        factory = _factory;
        maxSupply = _maxSupply;
    }
}
```

**Fixed:**
```solidity
contract Token {
    string public constant name = "MyToken";       // Embedded in bytecode
    uint256 public constant decimals = 18;          // Embedded in bytecode
    address public immutable factory;               // Stored in code section
    uint256 public immutable maxSupply;             // Stored in code section

    constructor(address _factory, uint256 _maxSupply) {
        factory = _factory;
        maxSupply = _maxSupply;
    }
}
```

### Pattern 2: Memory Instead of Calldata for Read-Only Parameters
Function parameters of reference types (arrays, bytes, strings, structs) declared as `memory` are copied from calldata to memory, wasting gas when the function only reads them.

**Vulnerable:**
```solidity
contract Verifier {
    // BUG: memory copies the entire array - wastes gas
    function verify(bytes memory signature, address[] memory signers)
        external view returns (bool)
    {
        bytes32 hash = keccak256(signature);
        for (uint256 i = 0; i < signers.length; i++) {
            if (recoverSigner(hash) == signers[i]) return true;
        }
        return false;
    }
}
```

**Fixed:**
```solidity
contract Verifier {
    // calldata avoids the copy - reads directly from transaction data
    function verify(bytes calldata signature, address[] calldata signers)
        external view returns (bool)
    {
        bytes32 hash = keccak256(signature);
        uint256 len = signers.length;
        for (uint256 i = 0; i < len; ) {
            if (recoverSigner(hash) == signers[i]) return true;
            unchecked { ++i; }
        }
        return false;
    }
}
```

### Pattern 3: Revert Strings Instead of Custom Errors
Using `require(cond, "long error string")` stores the string in bytecode and expands memory on revert. Custom errors (Solidity >=0.8.4) use 4-byte selectors, saving both deployment and runtime gas.

**Vulnerable:**
```solidity
contract Vault {
    function withdraw(uint256 amount) external {
        require(amount > 0, "Vault: withdrawal amount must be greater than zero");
        require(balances[msg.sender] >= amount, "Vault: insufficient balance for withdrawal");
        require(!paused, "Vault: contract is currently paused for maintenance");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
```

**Fixed:**
```solidity
contract Vault {
    error ZeroAmount();
    error InsufficientBalance(uint256 available, uint256 requested);
    error ContractPaused();

    function withdraw(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        uint256 bal = balances[msg.sender];
        if (bal < amount) revert InsufficientBalance(bal, amount);
        if (paused) revert ContractPaused();
        balances[msg.sender] = bal - amount;
        payable(msg.sender).transfer(amount);
    }
}
```

### Pattern 4: Redundant SafeMath in Solidity >=0.8
Solidity >=0.8 has built-in overflow/underflow checks. Using OpenZeppelin's SafeMath library adds redundant checked arithmetic, doubling the gas cost of every operation.

**Vulnerable:**
```solidity
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract Staking {
    using SafeMath for uint256; // BUG: redundant in Solidity >=0.8

    function stake(uint256 amount) external {
        totalStaked = totalStaked.add(amount);       // Double-checked
        userStake[msg.sender] = userStake[msg.sender].add(amount);
        uint256 reward = amount.mul(rate).div(1e18); // Double-checked
    }
}
```

**Fixed:**
```solidity
contract Staking {
    function stake(uint256 amount) external {
        totalStaked += amount;                    // Built-in overflow check
        userStake[msg.sender] += amount;
        uint256 reward = amount * rate / 1e18;    // Built-in overflow check
    }
}
```

### Pattern 5: Magic Numbers and Hardcoded Values
Numeric literals scattered throughout code without named constants reduce readability and miss compiler optimizations available to `constant` declarations.

**Vulnerable:**
```solidity
contract Exchange {
    function swap(uint256 amountIn) external returns (uint256) {
        uint256 fee = amountIn * 30 / 10000;      // BUG: what is 30? what is 10000?
        uint256 amountOut = getQuote(amountIn - fee);
        require(amountOut >= amountIn * 95 / 100, "slippage"); // BUG: 95? 100?
        if (block.timestamp > 1735689600) revert(); // BUG: magic timestamp
        return amountOut;
    }
}
```

**Fixed:**
```solidity
contract Exchange {
    uint256 private constant FEE_BPS = 30;
    uint256 private constant BPS_DENOMINATOR = 10000;
    uint256 private constant MIN_OUTPUT_PCT = 95;
    uint256 private constant PCT_DENOMINATOR = 100;
    uint256 private constant MIGRATION_DEADLINE = 1735689600;

    function swap(uint256 amountIn) external returns (uint256) {
        uint256 fee = amountIn * FEE_BPS / BPS_DENOMINATOR;
        uint256 amountOut = getQuote(amountIn - fee);
        require(amountOut >= amountIn * MIN_OUTPUT_PCT / PCT_DENOMINATOR, "slippage");
        if (block.timestamp > MIGRATION_DEADLINE) revert();
        return amountOut;
    }
}
```

### Detect
For every contract: (1) check for state variables that should be constant or immutable, (2) check for memory parameters that could use calldata, (3) check for require strings that should be custom errors, (4) check for SafeMath usage in Solidity >=0.8, (5) check for magic numbers without named constants.

### Remediation
Mark deploy-time constants as `immutable`, compile-time constants as `constant`. Use `calldata` for read-only reference-type parameters. Use custom errors instead of revert strings. Use Solidity >=0.8 and remove SafeMath. Define named constants for all magic numbers.

## CL-GAS-02: Loop & Iteration Invariant

**Rule:** `EVM-GAS-LOOP-01`
**Severity:** gas

### Description
The contract contains loops (for, while) that iterate over arrays, mappings, or time-based sequences. Loops amplify gas costs linearly or quadratically. Unbounded loops over user-controlled arrays can hit the block gas limit. Repeated storage reads of loop bounds, missing unchecked increments, O(n^2) patterns, and storage writes inside loops all waste gas that scales with iteration count.

### Patterns
### Pattern 1: Unbounded Loop Over User-Controlled Array
A loop iterates over an array whose length is controlled by external users (e.g., stakers, depositors, registrants). As the array grows, the function eventually exceeds the block gas limit.

**Vulnerable:**
```solidity
contract Staking {
    address[] public stakers;

    function stake() external {
        stakers.push(msg.sender); // Array grows without bound
    }

    function distributeRewards(uint256 total) external onlyOwner {
        // BUG: iterates all stakers - will DoS as array grows
        for (uint256 i = 0; i < stakers.length; i++) {
            uint256 share = total / stakers.length;
            payable(stakers[i]).transfer(share);
        }
    }
}
```

**Fixed:**
```solidity
contract Staking {
    mapping(address => uint256) public stakes;
    uint256 public totalStaked;

    function stake(uint256 amount) external {
        stakes[msg.sender] += amount;
        totalStaked += amount;
    }

    // Pull pattern: each user claims their own rewards
    function claimReward() external {
        uint256 share = pendingRewards * stakes[msg.sender] / totalStaked;
        stakes[msg.sender] = 0; // or track claimed separately
        payable(msg.sender).transfer(share);
    }
}
```

### Pattern 2: Array Length Read from Storage on Every Iteration
The loop condition reads `.length` from a storage array on every iteration instead of caching it in a local variable.

**Vulnerable:**
```solidity
contract Whitelist {
    address[] public allowed;

    function isAllowed(address user) public view returns (bool) {
        // BUG: allowed.length is SLOAD on every iteration
        for (uint256 i = 0; i < allowed.length; i++) {
            if (allowed[i] == user) return true;
        }
        return false;
    }
}
```

**Fixed:**
```solidity
contract Whitelist {
    address[] public allowed;

    function isAllowed(address user) public view returns (bool) {
        uint256 len = allowed.length; // Cache once
        for (uint256 i = 0; i < len; i++) {
            if (allowed[i] == user) return true;
        }
        return false;
    }
}
```

### Pattern 3: Missing Unchecked Increment for Loop Counter
Loop counters that cannot realistically overflow still use checked arithmetic (default in Solidity >=0.8), adding ~80 gas per iteration for the overflow check.

**Vulnerable:**
```solidity
contract Batch {
    function process(uint256[] calldata ids) external {
        for (uint256 i = 0; i < ids.length; i++) {
            // BUG: checked increment wastes ~80 gas/iteration
            // i cannot overflow - bounded by ids.length which fits in uint256
            _process(ids[i]);
        }
    }
}
```

**Fixed:**
```solidity
contract Batch {
    function process(uint256[] calldata ids) external {
        uint256 len = ids.length;
        for (uint256 i = 0; i < len; ) {
            _process(ids[i]);
            unchecked { ++i; } // Safe: i < len which is bounded
        }
    }
}
```

### Pattern 4: Storage Writes Inside Loop
State variables are written on every loop iteration instead of accumulating in memory and writing once after the loop.

**Vulnerable:**
```solidity
contract Aggregator {
    uint256 public totalCollected;

    function collect(uint256[] calldata amounts) external {
        for (uint256 i = 0; i < amounts.length; i++) {
            // BUG: SSTORE on every iteration (5000+ gas each)
            totalCollected += amounts[i];
        }
    }
}
```

**Fixed:**
```solidity
contract Aggregator {
    uint256 public totalCollected;

    function collect(uint256[] calldata amounts) external {
        uint256 sum = totalCollected; // Load once
        uint256 len = amounts.length;
        for (uint256 i = 0; i < len; ) {
            sum += amounts[i];
            unchecked { ++i; }
        }
        totalCollected = sum; // Single SSTORE after loop
    }
}
```

### Pattern 5: O(n^2) Linear Search or Duplicate Check
A loop uses nested iteration or repeated linear scans for membership checks, duplicate detection, or element removal, when a mapping would provide O(1).

**Vulnerable:**
```solidity
contract Registry {
    address[] public members;

    function addUnique(address member) external {
        // BUG: O(n) scan for each add = O(n^2) for batch
        for (uint256 i = 0; i < members.length; i++) {
            require(members[i] != member, "duplicate");
        }
        members.push(member);
    }

    function remove(address member) external {
        // BUG: O(n) scan + O(n) shift
        for (uint256 i = 0; i < members.length; i++) {
            if (members[i] == member) {
                for (uint256 j = i; j < members.length - 1; j++) {
                    members[j] = members[j + 1];
                }
                members.pop();
                return;
            }
        }
    }
}
```

**Fixed:**
```solidity
contract Registry {
    address[] public members;
    mapping(address => uint256) private memberIndex; // 1-indexed
    mapping(address => bool) public isMember;

    function addUnique(address member) external {
        require(!isMember[member], "duplicate"); // O(1)
        members.push(member);
        memberIndex[member] = members.length; // 1-indexed
        isMember[member] = true;
    }

    function remove(address member) external {
        require(isMember[member], "not member");
        uint256 idx = memberIndex[member] - 1;
        address last = members[members.length - 1];
        members[idx] = last; // Swap with last
        memberIndex[last] = idx + 1;
        members.pop();
        delete memberIndex[member];
        isMember[member] = false;
    }
}
```

### Detect
For every loop: (1) verify the iteration count is bounded and cannot be grown by external users, (2) verify array length is cached before the loop, (3) verify the loop counter uses unchecked increment (Solidity >=0.8), (4) verify no state variables are written inside the loop body, (5) verify no O(n^2) patterns exist (nested loops, linear search for membership/removal).

### Remediation
Cap loop iterations. Cache array length before loop. Use unchecked increment for loop counters. Move invariant computations outside loops. Use mappings instead of linear search. Implement pagination for large datasets.

## CL-GAS-03: Redundant Code & Dead Code Invariant

**Rule:** `EVM-GAS-REDUN-01`
**Severity:** gas

### Description
The contract contains code artifacts -- functions, variables, imports, computations, or logic branches -- that do not contribute to the contract's functionality. Dead code (unused functions, variables, imports), redundant computations (re-deriving known values, identity arithmetic), duplicate logic across branches, and unnecessary intermediate operations all inflate deployment cost and runtime gas without functional benefit.

### Patterns
### Pattern 1: Unused State Variables, Functions, and Imports
State variables, internal/private functions, or imported contracts/libraries that are never referenced consume deployment gas and storage slots without purpose.

**Vulnerable:**
```solidity
import "@openzeppelin/contracts/utils/Context.sol"; // BUG: never used
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Vault is ReentrancyGuard, Context { // BUG: Context unused
    uint256 public totalDeposits;
    uint256 private _legacyCounter; // BUG: never read or written
    address private _pendingAdmin;  // BUG: never used

    function _validateInput(uint256 x) internal pure returns (bool) {
        return x > 0; // BUG: function never called
    }

    function deposit() external payable nonReentrant {
        totalDeposits += msg.value;
    }
}
```

**Fixed:**
```solidity
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Vault is ReentrancyGuard {
    uint256 public totalDeposits;

    function deposit() external payable nonReentrant {
        totalDeposits += msg.value;
    }
}
```

### Pattern 2: Redundant Arithmetic and Identity Operations
Operations that have no effect on the result: adding zero, multiplying by one, dividing by one, double negation, or re-computing a value already available on the stack.

**Vulnerable:**
```solidity
contract Calculator {
    function compute(uint256 x, uint256 y) external pure returns (uint256) {
        uint256 result = x * 1;           // BUG: identity multiply
        result = result + 0;               // BUG: identity add
        result = result / 1;               // BUG: identity divide
        uint256 scaled = result * 10**18 / 10**18; // BUG: multiply then divide by same
        return scaled;
    }

    function fee(uint256 amount) external pure returns (uint256) {
        uint256 rate = 500;
        uint256 basis = 10000;
        // BUG: redundant - could just return amount * 500 / 10000
        uint256 numerator = amount * rate;
        uint256 intermediate = numerator;  // BUG: unnecessary copy
        return intermediate / basis;
    }
}
```

**Fixed:**
```solidity
contract Calculator {
    function compute(uint256 x, uint256 y) external pure returns (uint256) {
        return x; // All operations were identity
    }

    function fee(uint256 amount) external pure returns (uint256) {
        return amount * 500 / 10000;
    }
}
```

### Pattern 3: Duplicate Logic Across Conditional Branches
Identical code appears in both branches of an if/else, or the same computation is performed before and after a conditional. Should be hoisted out.

**Vulnerable:**
```solidity
contract Token {
    function transfer(address to, uint256 amount) external {
        if (isExempt[msg.sender]) {
            require(balances[msg.sender] >= amount, "insufficient");
            balances[msg.sender] -= amount;
            balances[to] += amount;
            emit Transfer(msg.sender, to, amount);
        } else {
            uint256 fee = amount * feeBps / 10000;
            // BUG: balance check, subtraction, addition, event all duplicated
            require(balances[msg.sender] >= amount, "insufficient");
            balances[msg.sender] -= amount;
            balances[to] += (amount - fee);
            balances[feeCollector] += fee;
            emit Transfer(msg.sender, to, amount - fee);
        }
    }
}
```

**Fixed:**
```solidity
contract Token {
    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;

        uint256 netAmount = amount;
        if (!isExempt[msg.sender]) {
            uint256 fee = amount * feeBps / 10000;
            netAmount = amount - fee;
            balances[feeCollector] += fee;
        }
        balances[to] += netAmount;
        emit Transfer(msg.sender, to, netAmount);
    }
}
```

### Pattern 4: Redundant External Calls and Intermediate Operations
External calls made for values already available, unnecessary token transfer hops (mint-then-transfer vs mint-to), or re-encoding data that is already in the correct format.

**Vulnerable:**
```solidity
contract Bridge {
    function bridge(address token, uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        // BUG: mint to self then transfer - two operations instead of one
        wrappedToken.mint(address(this), amount);
        wrappedToken.transfer(msg.sender, amount);
    }

    function getInfo(address token) external view returns (uint8, string memory) {
        // BUG: calls decimals() twice via different paths
        uint8 d = IERC20Metadata(token).decimals();
        string memory n = IERC20Metadata(token).name();
        require(d == IERC20Metadata(token).decimals(), "mismatch"); // redundant
        return (d, n);
    }
}
```

**Fixed:**
```solidity
contract Bridge {
    function bridge(address token, uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        wrappedToken.mint(msg.sender, amount); // Mint directly to recipient
    }

    function getInfo(address token) external view returns (uint8, string memory) {
        return (IERC20Metadata(token).decimals(), IERC20Metadata(token).name());
    }
}
```

### Pattern 5: Commented-Out Code, Residual Debug Artifacts, and TODOs
Production code containing commented-out logic, console.log statements, TODO markers, or test-only functions that inflate bytecode and indicate incomplete implementation.

**Vulnerable:**
```solidity
contract Governance {
    // TODO: implement proper access control
    // import "hardhat/console.sol";

    function execute(uint256 proposalId) external {
        // console.log("executing", proposalId);
        // uint256 oldQuorum = quorum;
        // require(votes[proposalId] >= oldQuorum, "no quorum");
        require(votes[proposalId] >= quorum, "no quorum");
        executed[proposalId] = true;
        // TODO: add timelock check
    }

    // function _debugState() internal view { ... } // leftover debug fn
}
```

**Fixed:**
```solidity
contract Governance {
    function execute(uint256 proposalId) external {
        require(votes[proposalId] >= quorum, "no quorum");
        executed[proposalId] = true;
    }
}
```

### Detect
For every contract: (1) check for unused state variables, functions, imports, and inherited contracts, (2) check for identity arithmetic and redundant computations, (3) check for duplicate code across conditional branches, (4) check for unnecessary intermediate external calls or token transfer hops, (5) check for commented-out code, TODOs, and debug artifacts.

### Remediation
Remove unused functions, variables, imports, and inheritance. Simplify redundant arithmetic and conditional logic. Consolidate duplicate code paths. Eliminate no-op operations. Clean debug artifacts.

## CL-GAS-04: Storage Read Caching Invariant

**Rule:** `EVM-GAS-SLOAD-01`
**Severity:** gas

### Description
The contract reads state variables (SLOAD) in functions where the same slot may be accessed more than once, or where a cheaper alternative exists. Storage reads cost 2100 gas (cold) or 100 gas (warm) per SLOAD. Repeated reads of the same slot, reads inside loops, reads in both modifier and function body, or reads that could be replaced by stack/memory variables waste gas.

### Patterns
### Pattern 1: Repeated SLOAD of Same Variable
A state variable is read multiple times within the same function without caching. Each read after the first wastes ~100 gas (warm SLOAD).

**Vulnerable:**
```solidity
contract Staking {
    uint256 public totalStaked;
    mapping(address => uint256) public stakes;

    function unstake(uint256 amount) external {
        require(stakes[msg.sender] >= amount, "insufficient");
        // BUG: totalStaked read twice from storage
        require(totalStaked >= amount, "impossible");
        stakes[msg.sender] -= amount;
        totalStaked -= amount;
        // BUG: third SLOAD of totalStaked
        emit Unstaked(msg.sender, amount, totalStaked);
    }
}
```

**Fixed:**
```solidity
contract Staking {
    uint256 public totalStaked;
    mapping(address => uint256) public stakes;

    function unstake(uint256 amount) external {
        uint256 userStake = stakes[msg.sender];
        require(userStake >= amount, "insufficient");
        uint256 _totalStaked = totalStaked;
        require(_totalStaked >= amount, "impossible");
        stakes[msg.sender] = userStake - amount;
        _totalStaked -= amount;
        totalStaked = _totalStaked;
        emit Unstaked(msg.sender, amount, _totalStaked);
    }
}
```

### Pattern 2: Storage Read in Modifier Duplicated in Function Body
A modifier reads a state variable for validation, then the function body reads the same variable again. The compiler does not optimize this away.

**Vulnerable:**
```solidity
contract Vault {
    address public owner;
    uint256 public balance;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner"); // SLOAD 1
        _;
    }

    function withdraw() external onlyOwner {
        // BUG: owner read again from storage (SLOAD 2)
        payable(owner).transfer(balance);
    }
}
```

**Fixed:**
```solidity
contract Vault {
    address public owner;
    uint256 public balance;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function withdraw() external onlyOwner {
        // Use msg.sender directly - already validated as owner
        payable(msg.sender).transfer(balance);
    }
}
```

### Pattern 3: Storage Variable Read Inside Loop
A state variable is read on every iteration of a loop instead of being cached before the loop. Costs 100 gas per iteration (warm).

**Vulnerable:**
```solidity
contract Distributor {
    uint256 public feeRate;
    address[] public recipients;

    function distribute(uint256 total) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            // BUG: feeRate read from storage every iteration
            uint256 fee = total * feeRate / 10000;
            _send(recipients[i], fee);
        }
    }
}
```

**Fixed:**
```solidity
contract Distributor {
    uint256 public feeRate;
    address[] public recipients;

    function distribute(uint256 total) external {
        uint256 _feeRate = feeRate; // Cache before loop
        uint256 len = recipients.length; // Cache array length too
        for (uint256 i = 0; i < len; i++) {
            uint256 fee = total * _feeRate / 10000;
            _send(recipients[i], fee);
        }
    }
}
```

### Pattern 4: Struct Fields Loaded Individually from Storage
Multiple fields of the same storage struct are read separately, each incurring a separate SLOAD, when loading the whole struct into memory would be cheaper.

**Vulnerable:**
```solidity
contract Auction {
    struct Bid {
        address bidder;
        uint256 amount;
        uint256 timestamp;
    }
    mapping(uint256 => Bid) public bids;

    function settle(uint256 id) external {
        // BUG: 3 separate SLOADs for each field
        require(bids[id].bidder != address(0), "no bid");
        require(block.timestamp > bids[id].timestamp + 1 days, "too early");
        payable(bids[id].bidder).transfer(bids[id].amount);
        delete bids[id];
    }
}
```

**Fixed:**
```solidity
contract Auction {
    struct Bid {
        address bidder;
        uint256 amount;
        uint256 timestamp;
    }
    mapping(uint256 => Bid) public bids;

    function settle(uint256 id) external {
        Bid memory bid = bids[id]; // Single struct load
        require(bid.bidder != address(0), "no bid");
        require(block.timestamp > bid.timestamp + 1 days, "too early");
        payable(bid.bidder).transfer(bid.amount);
        delete bids[id];
    }
}
```

### Pattern 5: Redundant External Call for On-Chain Constant
A value that does not change (e.g., token decimals, name, or an immutable address in another contract) is fetched via an external call on every invocation instead of being cached once.

**Vulnerable:**
```solidity
contract PriceOracle {
    IERC20 public token;

    function getPrice(uint256 amount) external view returns (uint256) {
        // BUG: decimals() called every time - it never changes
        uint256 decimals = token.decimals();
        return amount * price / (10 ** decimals);
    }

    function getValue(uint256 amount) external view returns (uint256) {
        // BUG: another call to decimals() in different function
        return amount * 1e18 / (10 ** token.decimals());
    }
}
```

**Fixed:**
```solidity
contract PriceOracle {
    IERC20 public token;
    uint8 private immutable tokenDecimals;

    constructor(IERC20 _token) {
        token = _token;
        tokenDecimals = _token.decimals(); // Cache once at deploy
    }

    function getPrice(uint256 amount) external view returns (uint256) {
        return amount * price / (10 ** tokenDecimals);
    }

    function getValue(uint256 amount) external view returns (uint256) {
        return amount * 1e18 / (10 ** tokenDecimals);
    }
}
```

### Detect
For every function: (1) check if any state variable is read more than once without caching, (2) check if modifier and function body read the same variable, (3) check for state variable reads inside loops, (4) check for individual struct field reads instead of memory load, (5) check for repeated external calls to immutable values.

### Remediation
Cache storage variables in local memory/stack variables at the start of the function. Re-use the cached value throughout. For struct fields, load the entire struct into memory once. Cache immutable external values at deployment.

## CL-GAS-05: Storage Write & Layout Invariant

**Rule:** `EVM-GAS-SSTORE-01`
**Severity:** gas

### Description
The contract writes to storage (SSTORE) or declares state variables whose layout affects gas costs. Storage writes cost 5000-20000 gas per SSTORE. Redundant writes, poor variable packing (wasting 32-byte slots), failure to zero-out storage for gas refunds, sub-uint256 types causing masking overhead, and redundant state variables all inflate gas costs.

### Patterns
### Pattern 1: Unoptimized Storage Variable Packing
State variables smaller than 32 bytes are declared in an order that prevents the compiler from packing them into shared storage slots, wasting entire slots.

**Vulnerable:**
```solidity
contract Token {
    // BUG: each variable takes a full 32-byte slot due to ordering
    uint128 public totalSupply;    // slot 0 (16 bytes, wastes 16)
    address public owner;          // slot 1 (20 bytes, wastes 12)
    uint128 public maxSupply;      // slot 2 (16 bytes, wastes 16)
    bool public paused;            // slot 3 (1 byte, wastes 31)
    address public minter;         // slot 4 (20 bytes, wastes 12)
}
```

**Fixed:**
```solidity
contract Token {
    // Packed: variables ordered by size to share slots
    address public owner;          // slot 0: 20 bytes
    bool public paused;            // slot 0: +1 byte = 21 bytes (packed)
    address public minter;         // slot 1: 20 bytes
    uint128 public totalSupply;    // slot 2: 16 bytes
    uint128 public maxSupply;      // slot 2: +16 bytes = 32 bytes (packed)
}
```

### Pattern 2: Redundant Storage Writes
A state variable is written multiple times in the same execution path, or written with a value identical to its current value, wasting SSTORE gas.

**Vulnerable:**
```solidity
contract Rewards {
    uint256 public lastUpdate;
    uint256 public rewardRate;

    function update(uint256 newRate) external {
        lastUpdate = block.timestamp;  // SSTORE 1
        rewardRate = newRate;
        // BUG: lastUpdate written again with same value
        lastUpdate = block.timestamp;  // SSTORE 2 (redundant)
    }

    function setRate(uint256 newRate) external {
        // BUG: writes even when value hasn't changed
        rewardRate = newRate;
    }
}
```

**Fixed:**
```solidity
contract Rewards {
    uint256 public lastUpdate;
    uint256 public rewardRate;

    function update(uint256 newRate) external {
        rewardRate = newRate;
        lastUpdate = block.timestamp; // Single write
    }

    function setRate(uint256 newRate) external {
        if (rewardRate != newRate) { // Skip write if unchanged
            rewardRate = newRate;
        }
    }
}
```

### Pattern 3: Missing Storage Zeroing for Gas Refund
When deleting entries (mappings, arrays), the contract does not zero-out storage slots, missing the EIP-2200 gas refund of up to 4800 gas per cleared slot.

**Vulnerable:**
```solidity
contract Registry {
    struct Entry {
        address owner;
        uint256 amount;
        uint256 expiry;
    }
    mapping(uint256 => Entry) public entries;

    function remove(uint256 id) external {
        // BUG: only resets owner, leaves amount and expiry occupying storage
        entries[id].owner = address(0);
    }
}
```

**Fixed:**
```solidity
contract Registry {
    struct Entry {
        address owner;
        uint256 amount;
        uint256 expiry;
    }
    mapping(uint256 => Entry) public entries;

    function remove(uint256 id) external {
        // delete zeroes all fields, earning gas refunds
        delete entries[id];
    }
}
```

### Pattern 4: Redundant State Variables Tracking Derivable Values
A state variable stores a value that can be cheaply derived from other existing state, doubling SSTORE costs on every update.

**Vulnerable:**
```solidity
contract Pool {
    uint256 public tokenABalance;
    uint256 public tokenBBalance;
    // BUG: totalValue is always tokenABalance + tokenBBalance
    uint256 public totalValue;

    function deposit(uint256 amountA, uint256 amountB) external {
        tokenABalance += amountA;
        tokenBBalance += amountB;
        totalValue = tokenABalance + tokenBBalance; // Extra SSTORE
    }
}
```

**Fixed:**
```solidity
contract Pool {
    uint256 public tokenABalance;
    uint256 public tokenBBalance;

    function totalValue() public view returns (uint256) {
        return tokenABalance + tokenBBalance; // Derived on read
    }

    function deposit(uint256 amountA, uint256 amountB) external {
        tokenABalance += amountA;
        tokenBBalance += amountB;
        // No extra SSTORE needed
    }
}
```

### Pattern 5: Sub-uint256 Type Masking Overhead Outside Packed Structs
Using uint8, uint32, etc. for standalone state variables (not packed with others in the same slot) adds masking/shifting overhead without saving any storage.

**Vulnerable:**
```solidity
contract Config {
    // BUG: each takes a full slot anyway, but adds masking overhead
    uint8 public decimals;      // slot 0: 1 byte used, 31 wasted + mask cost
    uint32 public cooldown;     // slot 1: 4 bytes used, 28 wasted + mask cost
    uint16 public feeBps;       // slot 2: 2 bytes used, 30 wasted + mask cost
}
```

**Fixed:**
```solidity
contract Config {
    // If not packing, use full uint256 to avoid masking
    uint256 public decimals;    // slot 0: no masking overhead
    uint256 public cooldown;    // slot 1: no masking overhead
    uint256 public feeBps;      // slot 2: no masking overhead
    // OR pack them together:
    // uint8 public decimals;   // slot 0
    // uint32 public cooldown;  // slot 0 (packed)
    // uint16 public feeBps;    // slot 0 (packed)
}
```

### Detect
For every contract: (1) check if state variable declarations can be reordered for tighter slot packing, (2) check for redundant writes to the same slot in a single execution, (3) check for missing delete/zeroing on removed entries, (4) check for state variables that duplicate derivable values, (5) check for sub-uint256 types used outside of packed slot groups.

### Remediation
Pack variables into single slots. Eliminate redundant state variables. Zero-out storage when deleting. Avoid redundant writes to the same slot. Use uint256 unless packing.

## CL-GAS-06: Validation Ordering & Short-Circuit Invariant

**Rule:** `EVM-GAS-VALID-01`
**Severity:** gas

### Description
The contract performs input validation, access control checks, or state precondition checks before executing logic. Expensive operations (storage reads, external calls, computation) are performed before cheap checks that would revert, wasting gas on failing transactions. Redundant checks duplicated across caller/callee boundaries, missing early exits, and suboptimal check ordering all waste gas.

### Patterns
### Pattern 1: Expensive Check Before Cheap Revert (Fail-Fast Violation)
A function performs storage reads or external calls for validation before checking cheap conditions (msg.sender, msg.value, calldata params) that would revert.

**Vulnerable:**
```solidity
contract Sale {
    function buy(uint256 tokenId) external payable {
        // BUG: SLOAD before msg.value check
        uint256 price = prices[tokenId];
        address seller = owners[tokenId];
        require(seller != address(0), "not listed");
        // Cheap check should be first
        require(msg.value >= price, "insufficient payment");
        require(msg.sender != seller, "self-buy");
    }
}
```

**Fixed:**
```solidity
contract Sale {
    function buy(uint256 tokenId) external payable {
        // Cheapest checks first (no SLOAD)
        require(msg.value > 0, "no payment");
        // Then storage reads
        uint256 price = prices[tokenId];
        address seller = owners[tokenId];
        require(seller != address(0), "not listed");
        require(msg.value >= price, "insufficient payment");
        require(msg.sender != seller, "self-buy");
    }
}
```

### Pattern 2: Duplicate Validation Across Call Boundaries
The same check is performed in both the external function and an internal function it calls, or in both a modifier and the function body.

**Vulnerable:**
```solidity
contract Vault {
    function deposit(uint256 amount) external {
        require(amount > 0, "zero amount");     // Check 1
        require(!paused, "paused");              // Check 2
        _processDeposit(amount);
    }

    function _processDeposit(uint256 amount) internal {
        require(amount > 0, "zero amount");     // BUG: duplicate of Check 1
        require(!paused, "paused");              // BUG: duplicate of Check 2
        balances[msg.sender] += amount;
        token.transferFrom(msg.sender, address(this), amount);
    }
}
```

**Fixed:**
```solidity
contract Vault {
    function deposit(uint256 amount) external {
        require(amount > 0, "zero amount");
        require(!paused, "paused");
        _processDeposit(amount);
    }

    function _processDeposit(uint256 amount) internal {
        // No duplicate checks - caller already validated
        balances[msg.sender] += amount;
        token.transferFrom(msg.sender, address(this), amount);
    }
}
```

### Pattern 3: Missing Early Exit for Zero-Value or No-Op Operations
A function executes full logic (storage reads, writes, external calls, events) even when the input is zero or the operation would be a no-op, wasting gas.

**Vulnerable:**
```solidity
contract Rewards {
    function claim() external {
        uint256 pending = _calculateRewards(msg.sender);
        // BUG: full execution even when nothing to claim
        userRewards[msg.sender] = 0;
        lastClaim[msg.sender] = block.timestamp;
        token.transfer(msg.sender, pending); // Transfers 0 tokens
        emit RewardClaimed(msg.sender, pending); // Emits 0-value event
    }
}
```

**Fixed:**
```solidity
contract Rewards {
    function claim() external {
        uint256 pending = _calculateRewards(msg.sender);
        if (pending == 0) return; // Early exit
        userRewards[msg.sender] = 0;
        lastClaim[msg.sender] = block.timestamp;
        token.transfer(msg.sender, pending);
        emit RewardClaimed(msg.sender, pending);
    }
}
```

### Pattern 4: Redundant Zero-Address and Bounds Checks
Checks that can never fail given the context: checking msg.sender != address(0) (impossible), checking array bounds after .length check, or re-validating immutable/constant values.

**Vulnerable:**
```solidity
contract Registry {
    function register() external {
        // BUG: msg.sender can never be address(0)
        require(msg.sender != address(0), "zero address");
        // BUG: checking immutable that was validated in constructor
        require(address(token) != address(0), "no token");
        entries[msg.sender] = true;
    }

    function process(uint256[] calldata data) external {
        require(data.length > 0, "empty");
        for (uint256 i = 0; i < data.length; i++) {
            // BUG: i is always < data.length, bounds check redundant
            require(i < data.length, "out of bounds");
            _handle(data[i]);
        }
    }
}
```

**Fixed:**
```solidity
contract Registry {
    function register() external {
        // msg.sender is never zero - remove check
        // token is immutable and validated in constructor - remove check
        entries[msg.sender] = true;
    }

    function process(uint256[] calldata data) external {
        require(data.length > 0, "empty");
        uint256 len = data.length;
        for (uint256 i = 0; i < len; ) {
            _handle(data[i]); // Loop bounds guarantee safety
            unchecked { ++i; }
        }
    }
}
```

### Pattern 5: Suboptimal Short-Circuit Evaluation Order
In compound conditions (&&, ||), the more expensive or less likely-to-fail check is placed first, causing unnecessary evaluation of the costly side.

**Vulnerable:**
```solidity
contract Access {
    function execute(bytes32 role, uint256 amount) external {
        // BUG: storage read (hasRole) before cheap comparison
        require(hasRole[msg.sender][role] && amount > 0, "denied");
        // BUG: external call before local check
        require(oracle.getPrice() > minPrice && !paused, "invalid");
    }
}
```

**Fixed:**
```solidity
contract Access {
    function execute(bytes32 role, uint256 amount) external {
        // Cheap check first - if amount is 0, skip storage read
        require(amount > 0 && hasRole[msg.sender][role], "denied");
        // Local check first - if paused, skip external call
        require(!paused && oracle.getPrice() > minPrice, "invalid");
    }
}
```

### Detect
For every function with validation logic: (1) verify cheap checks (msg.sender, msg.value, calldata) precede expensive checks (SLOAD, external calls), (2) verify no duplicate checks exist across caller/callee or modifier/body, (3) verify early exits for zero-value or no-op inputs, (4) verify no impossible-to-fail checks exist (msg.sender != 0, bounds inside loops), (5) verify short-circuit conditions order cheap/likely before expensive/unlikely.

### Remediation
Order checks cheapest-first. Remove duplicate checks across call boundaries. Add early returns for zero-value or no-op cases. Use short-circuit evaluation effectively. Remove impossible checks.
