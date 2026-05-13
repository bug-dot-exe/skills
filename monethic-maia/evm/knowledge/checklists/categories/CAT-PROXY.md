## CL-PROXY-01: Diamond and Multi-Facet Proxy Invariant

**Rule:** `DIAM-01`
**Severity:** informational-high

### Description
When a contract uses the EIP-2535 Diamond pattern, a multi-facet proxy, or a router-based architecture where function selectors map to different implementation addresses, diamond proxies can fail to register all function selectors, perform incomplete facet cuts during upgrades, implement non-standard dispatch logic that deviates from EIP-2535, use mutable routing tables that can be manipulated, or break proxy-implementation interface contracts through incorrect selector mappings. This results in functions becoming silently unreachable through the proxy, stale facets executing outdated vulnerable logic after upgrade, non-standard implementations breaking tooling and introspection, manipulable routing redirecting calls to malicious facets, and interface mismatches causing permanent DoS.

### Patterns
### Pattern 1: Incomplete Facet Cut Missing Modified Selectors
An upgrade script adds or replaces some facets but misses others that were also modified. The diamond continues routing missed selectors to the old facet, executing outdated or vulnerable logic.

**Vulnerable:**
```solidity
contract DiamondUpgradeScript {
    function run(IDiamond diamond) external {
        IDiamond.FacetCut[] memory cuts = new IDiamond.FacetCut[](1);

        // Only updating VaultFacet — but LiquidationFacet was also
        // modified to use new VaultFacet storage layout
        cuts[0] = IDiamond.FacetCut({
            facetAddress: address(new VaultFacetV2()),
            action: IDiamond.FacetCutAction.Replace,
            functionSelectors: getVaultSelectors()
        });
        // BUG: LiquidationFacet not included — still runs V1
        // V1 LiquidationFacet reads V2 storage layout = corruption
        diamond.diamondCut(cuts, address(0), "");
    }
}
```

**Fixed:**
```solidity
contract DiamondUpgradeScript {
    function run(IDiamond diamond) external {
        IDiamond.FacetCut[] memory cuts = new IDiamond.FacetCut[](2);

        cuts[0] = IDiamond.FacetCut({
            facetAddress: address(new VaultFacetV2()),
            action: IDiamond.FacetCutAction.Replace,
            functionSelectors: getVaultSelectors()
        });

        // Include ALL modified facets
        cuts[1] = IDiamond.FacetCut({
            facetAddress: address(new LiquidationFacetV2()),
            action: IDiamond.FacetCutAction.Replace,
            functionSelectors: getLiquidationSelectors()
        });

        diamond.diamondCut(cuts, address(0), "");
    }
}
```

### Pattern 2: Missing Selector Registration in Diamond Constructor
The diamond's initial setup fails to register all function selectors from its facets. Unregistered functions are unreachable — calls to them revert or fall through to the fallback.

**Vulnerable:**
```solidity
contract Diamond {
    constructor(address _owner, IDiamondCut.FacetCut[] memory _cuts) {
        // Register ownership facet
        _cuts[0] = IDiamondCut.FacetCut({
            facetAddress: address(new OwnershipFacet()),
            action: IDiamondCut.FacetCutAction.Add,
            functionSelectors: getOwnershipSelectors()
        });

        // BUG: DiamondLoupeFacet selectors not registered
        // EIP-2535 introspection (facets(), facetAddresses()) broken
        // BUG: DiamondCutFacet selectors not registered
        // Cannot upgrade the diamond after deployment!

        LibDiamond.diamondCut(_cuts, address(0), "");
        LibDiamond.setContractOwner(_owner);
    }
}
```

**Fixed:**
```solidity
contract Diamond {
    constructor(address _owner, IDiamondCut.FacetCut[] memory _cuts) {
        // Register ALL required facets
        IDiamondCut.FacetCut[] memory allCuts =
            new IDiamondCut.FacetCut[](_cuts.length + 2);

        // Copy user cuts
        for (uint i = 0; i < _cuts.length; i++) {
            allCuts[i] = _cuts[i];
        }

        // Always register DiamondCut and DiamondLoupe
        allCuts[_cuts.length] = IDiamondCut.FacetCut({
            facetAddress: address(new DiamondCutFacet()),
            action: IDiamondCut.FacetCutAction.Add,
            functionSelectors: getDiamondCutSelectors()
        });

        allCuts[_cuts.length + 1] = IDiamondCut.FacetCut({
            facetAddress: address(new DiamondLoupeFacet()),
            action: IDiamondCut.FacetCutAction.Add,
            functionSelectors: getLoupeSelectors()
        });

        LibDiamond.diamondCut(allCuts, address(0), "");
        LibDiamond.setContractOwner(_owner);
    }
}
```

### Pattern 3: Non-Standard Diamond Implementation Breaking Introspection
The diamond implements core dispatch logic in raw assembly (Yul) without following EIP-2535 standards. Introspection tools, block explorers, and governance dashboards cannot parse the proxy's capabilities.

**Vulnerable:**
```solidity
contract YulDiamond {
    // Entire routing table in assembly — no standard interface
    fallback() external payable {
        assembly {
            let selector := shr(224, calldataload(0))
            // Hardcoded selector routing — no diamond loupe
            switch selector
            case 0xa9059cbb { // transfer
                let impl := sload(0x01)
                // ... delegatecall
            }
            case 0x095ea7b3 { // approve
                let impl := sload(0x02)
                // ... delegatecall
            }
            default {
                revert(0, 0) // Unknown selector — silent failure
            }
        }
    }

    // BUG: No EIP-2535 introspection functions
    // BUG: No diamondCut — routing is immutable
    // BUG: No facets() or facetAddresses() for tooling
}
```

**Fixed:**
```solidity
contract StandardDiamond {
    fallback() external payable {
        LibDiamond.DiamondStorage storage ds =
            LibDiamond.diamondStorage();
        address facet = ds.selectorToFacetAddress[msg.sig];
        require(facet != address(0), "selector not found");
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    // Implements EIP-2535 standard interfaces
    // DiamondCutFacet: diamondCut()
    // DiamondLoupeFacet: facets(), facetFunctionSelectors(),
    //   facetAddresses(), facetAddress()
    // ERC165: supportsInterface()
}
```

### Pattern 4: Broken Proxy-Implementation Interface Mismatch
The proxy calls implementation functions using incorrect selectors, wrong argument encoding, or mismatched return types. Calls silently fail, return garbage data, or revert with unhelpful errors.

**Vulnerable:**
```solidity
interface IVaultV1 {
    function deposit(uint256 amount, address token) external;
    function getBalance(address user) external view returns (uint256);
}

contract VaultProxy {
    IVaultV1 public implementation;

    function userDeposit(address token, uint256 amount) external {
        // BUG: Parameter order swapped vs IVaultV1.deposit
        // Solidity ABI-encodes (token, amount) but impl expects (amount, token)
        implementation.deposit(amount, token); // wrong encoding
    }
}

// Actual implementation changed signature in V2
contract VaultV2 {
    // deposit now takes 3 args — proxy still sends 2
    function deposit(uint256 amount, address token, bytes calldata data)
        external
    {
        // Proxy call decodes incorrectly — data is garbage
    }
}
```

**Fixed:**
```solidity
contract VaultProxy {
    address public implementation;

    // Use delegatecall with matching interface, or
    // encode calls explicitly with correct signature
    function userDeposit(address token, uint256 amount) external {
        (bool ok,) = implementation.delegatecall(
            abi.encodeWithSelector(
                IVaultV2.deposit.selector,
                amount, token, ""
            )
        );
        require(ok, "deposit failed");
    }
}
```

### Pattern 5: Missing Administrative Forwarding in Proxy Hierarchy
A parent contract holds a proxy to a child contract but lacks functions to forward administrative calls (pause, upgrade dependencies, rescue tokens). Critical child operations are permanently unreachable.

**Vulnerable:**
```solidity
contract MasterVault {
    // Holds proxy to child vault
    ChildVaultProxy public childProxy;

    function deposit(uint256 amount) external {
        childProxy.deposit(amount); // works
    }

    function withdraw(uint256 amount) external {
        childProxy.withdraw(amount); // works
    }

    // BUG: No way to call childProxy.pause()
    // BUG: No way to call childProxy.setOracle()
    // BUG: No way to call childProxy.rescueToken()
    // These child admin functions are permanently inaccessible
    // because MasterVault is the owner of childProxy
}
```

**Fixed:**
```solidity
contract MasterVault is OwnableUpgradeable {
    ChildVaultProxy public childProxy;

    function deposit(uint256 amount) external {
        childProxy.deposit(amount);
    }

    function withdraw(uint256 amount) external {
        childProxy.withdraw(amount);
    }

    // Forward admin operations to child
    function pauseChild() external onlyOwner {
        childProxy.pause();
    }

    function setChildOracle(address oracle) external onlyOwner {
        childProxy.setOracle(oracle);
    }

    // Generic forwarding for future admin functions
    function forwardToChild(bytes calldata data) external onlyOwner {
        (bool ok,) = address(childProxy).call(data);
        require(ok, "forward failed");
    }
}
```

### Detect
For every diamond/multi-facet proxy: (1) verify all modified facets are included in upgrade cuts, (2) verify all function selectors are registered in the constructor, (3) verify EIP-2535 standard interfaces are implemented, (4) verify proxy-to-implementation selector and ABI encoding matches, (5) verify parent contracts can forward admin calls to child proxies.

### Remediation
Register all selectors during diamond cut. Include all modified facets in upgrades. Follow EIP-2535 standard for introspection. Make routing tables immutable or admin-protected. Verify selector-to-facet mappings match expected interfaces.

## CL-PROXY-02: Delegatecall Safety Invariant

**Rule:** `DLGT-01`
**Severity:** informational-high

### Description
When a contract uses delegatecall (directly or via proxy patterns) to execute logic in the context of the caller's storage and msg.value, delegatecall preserves the original msg.value, msg.sender, and storage context, creating subtle bugs when logic assumes it runs in its own context. This leads to double-spending of msg.value in batch operations, ETH permanently locked in proxies with no withdrawal mechanism, incorrect activity attribution breaking reward/airdrop systems, failed ETH transfers through proxy fallbacks, and silent execution failures from context mismatches.

### Patterns
### Pattern 1: msg.value Persistence in Delegatecall Loops
In a batch/multicall pattern using delegatecall, msg.value remains constant across all iterations. Each delegated call sees the full original msg.value, enabling double-spending of the same ETH across multiple operations.

**Vulnerable:**
```solidity
contract MultiCallProxy {
    function batchExecute(
        address[] calldata targets,
        bytes[] calldata data
    ) external payable {
        for (uint i = 0; i < targets.length; i++) {
            // BUG: msg.value is the SAME for every delegatecall
            // If each target uses msg.value to credit ETH, total credits
            // = msg.value * targets.length, but only msg.value was sent
            (bool ok,) = targets[i].delegatecall(data[i]);
            require(ok, "call failed");
        }
    }
}

contract DepositHandler {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        // Each delegatecall sees full msg.value
        balances[msg.sender] += msg.value; // credited N times
    }
}
```

**Fixed:**
```solidity
contract MultiCallProxy {
    function batchExecute(
        address[] calldata targets,
        bytes[] calldata data,
        uint256[] calldata values
    ) external payable {
        uint256 totalUsed;
        for (uint i = 0; i < targets.length; i++) {
            totalUsed += values[i];
            // Use call instead of delegatecall for ETH operations
            (bool ok,) = targets[i].call{value: values[i]}(data[i]);
            require(ok, "call failed");
        }
        require(totalUsed == msg.value, "ETH mismatch");
    }
}
```

### Pattern 2: Locked ETH in Proxy via Payable Fallback
The proxy's fallback is payable (to support delegatecall to payable functions), but the implementation has no mechanism to withdraw ETH from the proxy. Direct ETH transfers to the proxy are permanently locked.

**Vulnerable:**
```solidity
contract PayableProxy {
    address public implementation;

    // Proxy accepts ETH to support payable implementation functions
    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    // BUG: ETH sent directly (no calldata) has no withdrawal path
    receive() external payable {}
}

contract ImplementationV1 {
    // No withdrawETH function — ETH sent to proxy is trapped
    function doWork() external payable {
        // Uses msg.value in proxy context
    }
}
```

**Fixed:**
```solidity
contract ImplementationV1 {
    function doWork() external payable {
        // Uses msg.value in proxy context
    }

    // Admin can rescue ETH accidentally sent to proxy
    function rescueETH(address payable to, uint256 amount) external onlyOwner {
        require(to != address(0), "zero address");
        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
```

### Pattern 3: Inconsistent Proxy ETH Delegation
The proxy defines an empty `receive()` that absorbs ETH without delegating, while `fallback()` delegates everything else. ETH sent without calldata behaves differently than ETH sent with calldata, confusing integrators and trapping funds.

**Vulnerable:**
```solidity
contract InconsistentProxy {
    address public implementation;

    // BUG: receive() does NOT delegate — ETH absorbed silently
    receive() external payable {
        // ETH trapped here, implementation never sees it
    }

    // fallback() delegates all calls with data
    fallback() external payable {
        _delegate(implementation);
    }

    function _delegate(address impl) internal {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
```

**Fixed:**
```solidity
contract ConsistentProxy {
    address public implementation;

    // Both receive and fallback delegate to implementation
    receive() external payable {
        _delegate(implementation);
    }

    fallback() external payable {
        _delegate(implementation);
    }

    function _delegate(address impl) internal {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
```

### Pattern 4: Incorrect Activity Attribution in Delegatecall Context
When a proxy delegatecalls an implementation, `address(this)` returns the proxy address but the executing code belongs to the implementation. Systems that attribute activity based on code address (callcode) or log the implementation address miss the actual proxy performing the action.

**Vulnerable:**
```solidity
contract RewardTracker {
    mapping(address => uint256) public activityPoints;

    function recordActivity(address actor) external {
        activityPoints[actor] += 1;
    }
}

contract Implementation {
    RewardTracker public tracker;

    function doAction() external {
        // BUG: In delegatecall context, this records the proxy address
        // but some systems may track the implementation address instead
        tracker.recordActivity(address(this));
    }

    function getCodeAddress() internal view returns (address addr) {
        // BUG: Returns implementation address, not proxy
        // Used for identity but wrong in delegatecall context
        assembly {
            addr := address()
        }
    }
}
```

**Fixed:**
```solidity
contract Implementation {
    RewardTracker public tracker;
    address public immutable SELF;

    constructor() {
        SELF = address(this);
    }

    function doAction() external {
        // Explicitly use address(this) which returns proxy in delegatecall
        require(address(this) != SELF, "must be called via proxy");
        tracker.recordActivity(address(this));
    }
}
```

### Pattern 5: Payable Proxy Fallback Rejection
The proxy's fallback explicitly reverts when `msg.value > 0`, preventing legitimate payable function calls through the proxy. This breaks any implementation function that needs to accept ETH.

**Vulnerable:**
```solidity
contract StrictProxy {
    address public implementation;

    fallback() external payable {
        // BUG: Rejects all ETH — no payable implementation function works
        require(msg.value == 0, "no ETH accepted");
        _delegate(implementation);
    }

    function _delegate(address impl) internal {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

// Implementation has payable functions that can never be called
contract VaultImpl {
    function deposit() external payable {
        // This can never receive ETH through the proxy
    }
}
```

**Fixed:**
```solidity
contract FlexibleProxy {
    address public implementation;

    // Allow ETH through — let implementation decide what's acceptable
    fallback() external payable {
        _delegate(implementation);
    }

    receive() external payable {
        _delegate(implementation);
    }

    function _delegate(address impl) internal {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
```

### Detect
For every contract using delegatecall: (1) verify msg.value is not reused across loop iterations, (2) verify ETH sent to proxy has a withdrawal path, (3) verify receive() and fallback() delegation behavior is consistent, (4) verify activity attribution uses correct address context, (5) verify proxy fallback does not reject legitimate payable calls.

### Remediation
Track consumed msg.value in multi-call patterns. Implement ETH withdrawal from proxies. Ensure consistent receive/fallback delegation. Validate context assumptions in delegatecall targets. Use address(this) awareness for attribution.

## CL-PROXY-03: Factory and Clone Deployment Invariant

**Rule:** `FACT-01`
**Severity:** low-critical

### Description
When a protocol uses a factory contract to deploy proxies, minimal clones, or deterministic (CREATE2) instances, factory contracts can miscalculate deterministic addresses, use insufficient salt entropy enabling front-running, fail to atomically initialize deployed instances, propagate stale configuration to children, or use mismatched init code hashes for address prediction. This leads to deployment front-running via predictable CREATE2 addresses, permanently bricked contracts from init code hash mismatches, uninitialized instances exploitable by attackers, stale factory configuration propagating to all children, and duplicate deployments from inconsistent salt computation.

### Patterns
### Pattern 1: CREATE2 Front-Running via Predictable Salt
The CREATE2 salt is derived from publicly known parameters without including msg.sender or a nonce. An attacker predicts the deployment address, deploys a contract there first, and griefs the legitimate deployment.

**Vulnerable:**
```solidity
contract PoolFactory {
    function createPool(address tokenA, address tokenB)
        external returns (address)
    {
        // BUG: Salt is fully predictable — no sender, no nonce
        bytes32 salt = keccak256(abi.encodePacked(tokenA, tokenB));
        // Attacker can front-run with same salt, deploy garbage
        address pool = address(new Pool{salt: salt}(tokenA, tokenB));
        return pool;
    }

    function getPoolAddress(address tokenA, address tokenB)
        external view returns (address)
    {
        bytes32 salt = keccak256(abi.encodePacked(tokenA, tokenB));
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff), address(this), salt,
            keccak256(type(Pool).creationCode)
        )))));
    }
}
```

**Fixed:**
```solidity
contract PoolFactory {
    mapping(address => uint256) public nonces;

    function createPool(address tokenA, address tokenB)
        external returns (address)
    {
        // Include msg.sender and nonce to prevent front-running
        bytes32 salt = keccak256(abi.encodePacked(
            msg.sender, tokenA, tokenB, nonces[msg.sender]++
        ));
        address pool = address(new Pool{salt: salt}(tokenA, tokenB));
        return pool;
    }
}
```

### Pattern 2: Mismatched Init Code Hash for Address Prediction
The factory hardcodes a `POOL_INIT_CODE_HASH` for deterministic address calculation, but the actual contract bytecode differs (due to compiler version, optimization settings, or constructor args). All predicted addresses are wrong.

**Vulnerable:**
```solidity
contract DEXFactory {
    // BUG: Hash was computed with Solidity 0.8.19 but contract
    // is now compiled with 0.8.24 — different bytecode
    bytes32 public constant POOL_INIT_CODE_HASH =
        0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890;

    function createPair(address tokenA, address tokenB) external {
        bytes32 salt = keccak256(abi.encodePacked(tokenA, tokenB));
        address pair = address(new Pair{salt: salt}(tokenA, tokenB));
        // pair address doesn't match what getAddress() returns
    }

    function getAddress(address tokenA, address tokenB)
        external view returns (address)
    {
        bytes32 salt = keccak256(abi.encodePacked(tokenA, tokenB));
        // Returns wrong address due to stale POOL_INIT_CODE_HASH
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff), address(this), salt, POOL_INIT_CODE_HASH
        )))));
    }
}
```

**Fixed:**
```solidity
contract DEXFactory {
    bytes32 public immutable POOL_INIT_CODE_HASH;

    constructor() {
        // Compute hash at deployment time from actual creation code
        POOL_INIT_CODE_HASH = keccak256(type(Pair).creationCode);
    }

    function getAddress(address tokenA, address tokenB)
        external view returns (address)
    {
        bytes32 salt = keccak256(abi.encodePacked(tokenA, tokenB));
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff), address(this), salt, POOL_INIT_CODE_HASH
        )))));
    }
}
```

### Pattern 3: Non-Atomic Clone Deployment and Initialization
The factory deploys a clone or proxy in one step but does not call `initialize` in the same transaction. An attacker front-runs the initialization and takes ownership of the deployed instance.

**Vulnerable:**
```solidity
contract VaultFactory {
    address public implementation;

    function deployVault() external returns (address) {
        // Step 1: Deploy clone
        address clone = Clones.clone(implementation);
        // BUG: initialize() not called — attacker can front-run
        emit VaultDeployed(clone, msg.sender);
        return clone;
    }

    // Step 2: Team calls this later — but attacker may call first
    function initializeVault(address vault, address admin) external {
        IVault(vault).initialize(admin);
    }
}
```

**Fixed:**
```solidity
contract VaultFactory {
    address public implementation;

    function deployVault(address admin) external returns (address) {
        address clone = Clones.clone(implementation);
        // Atomic: deploy and initialize in same transaction
        IVault(clone).initialize(admin);
        emit VaultDeployed(clone, admin);
        return clone;
    }
}
```

### Pattern 4: Stale Factory Configuration Propagating to Children
The factory copies global configuration into child contracts at deployment time. When the factory's config is updated, existing children retain stale values with no mechanism to sync.

**Vulnerable:**
```solidity
contract LendingFactory is OwnableUpgradeable {
    address public oracle;
    uint256 public liquidationThreshold;

    function deployPool(address token) external returns (address) {
        LendingPool pool = new LendingPool();
        // Config copied at deploy time — becomes stale
        pool.initialize(token, oracle, liquidationThreshold);
        return address(pool);
    }

    function setOracle(address _oracle) external onlyOwner {
        oracle = _oracle;
        // BUG: Existing pools still use old oracle
        // No mechanism to update them
    }

    function setThreshold(uint256 _threshold) external onlyOwner {
        liquidationThreshold = _threshold;
        // BUG: Existing pools still use old threshold
    }
}
```

**Fixed:**
```solidity
contract LendingFactory is OwnableUpgradeable {
    address public oracle;
    uint256 public liquidationThreshold;
    address[] public deployedPools;

    function deployPool(address token) external returns (address) {
        LendingPool pool = new LendingPool();
        pool.initialize(token, address(this)); // pools read from factory
        deployedPools.push(address(pool));
        return address(pool);
    }
}

contract LendingPool {
    IFactory public factory;

    function getOracle() public view returns (address) {
        // Always reads current value from factory
        return factory.oracle();
    }
}
```

### Pattern 5: Inconsistent Salt Derivation Across Factory Functions
Different factory functions (deploy, predict address, check existence) compute the CREATE2 salt differently, causing address predictions to fail, existence checks to miss deployed contracts, and duplicate deployments.

**Vulnerable:**
```solidity
contract TokenFactory {
    function deploy(string memory name, string memory symbol)
        external returns (address)
    {
        // Uses name + symbol + sender for salt
        bytes32 salt = keccak256(abi.encodePacked(name, symbol, msg.sender));
        return address(new Token{salt: salt}(name, symbol));
    }

    function predictAddress(string memory name, string memory symbol)
        external view returns (address)
    {
        // BUG: Missing msg.sender — different salt than deploy()
        bytes32 salt = keccak256(abi.encodePacked(name, symbol));
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff), address(this), salt,
            keccak256(type(Token).creationCode)
        )))));
    }

    function exists(string memory name, string memory symbol)
        external view returns (bool)
    {
        // BUG: Uses yet another salt derivation — symbol + name (reversed)
        bytes32 salt = keccak256(abi.encodePacked(symbol, name));
        address predicted = address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff), address(this), salt,
            keccak256(type(Token).creationCode)
        )))));
        return predicted.code.length > 0;
    }
}
```

**Fixed:**
```solidity
contract TokenFactory {
    function _computeSalt(
        string memory name,
        string memory symbol,
        address deployer
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(name, symbol, deployer));
    }

    function deploy(string memory name, string memory symbol)
        external returns (address)
    {
        bytes32 salt = _computeSalt(name, symbol, msg.sender);
        return address(new Token{salt: salt}(name, symbol));
    }

    function predictAddress(
        string memory name,
        string memory symbol,
        address deployer
    ) external view returns (address) {
        bytes32 salt = _computeSalt(name, symbol, deployer);
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff), address(this), salt,
            keccak256(type(Token).creationCode)
        )))));
    }
}
```

### Detect
For every factory/clone deployment: (1) verify CREATE2 salt includes msg.sender or unpredictable component, (2) verify init code hash matches actual contract bytecode, (3) verify deployment and initialization are atomic, (4) verify child contracts read current factory config, (5) verify salt derivation is consistent across all factory functions.

### Remediation
Include msg.sender in CREATE2 salt. Verify init code hash matches at deployment. Atomically deploy and initialize in same transaction. Propagate config updates to children. Use consistent salt derivation across factory functions.

## CL-PROXY-04: Initialization Access Control Invariant

**Rule:** `INIT-01`
**Severity:** medium-critical

### Description
When a contract uses a proxy pattern (transparent, UUPS, minimal clone, beacon, diamond) and has one or more initialization functions that set critical state (owner, admin, roles, dependencies), initialization functions can lack access control, re-entrancy guards, or one-time execution guarantees, allowing attackers to front-run deployment, re-initialize post-upgrade, or call setup functions repeatedly to hijack ownership and corrupt protocol state. This results in complete contract takeover via ownership hijacking, privilege escalation through repeated initialization, state corruption from unauthorized re-initialization, and fund theft through attacker-controlled admin roles.

### Patterns
### Pattern 1: Unprotected Public Initializer Front-Running
The `initialize` function is public with no access control. An attacker monitors the mempool for proxy deployment, front-runs with their own `initialize` call, and becomes the owner.

**Vulnerable:**
```solidity
contract VaultV1 is UUPSUpgradeable {
    address public owner;
    address public treasury;

    // BUG: No access control — anyone can call after deployment
    function initialize(address _treasury) public {
        owner = msg.sender;
        treasury = _treasury;
    }

    function _authorizeUpgrade(address) internal override {
        require(msg.sender == owner);
    }

    function withdrawAll() external {
        require(msg.sender == owner);
        payable(treasury).transfer(address(this).balance);
    }
}
```

**Fixed:**
```solidity
contract VaultV1 is UUPSUpgradeable, Initializable {
    address public owner;
    address public treasury;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _treasury) public initializer {
        owner = msg.sender;
        treasury = _treasury;
    }

    function _authorizeUpgrade(address) internal override {
        require(msg.sender == owner);
    }
}
```

### Pattern 2: Missing Initializer Guard Allows Re-Initialization
A custom initialization function uses a manual boolean flag but fails to set it, or uses a check that can be bypassed, allowing repeated calls that overwrite critical state.

**Vulnerable:**
```solidity
contract LendingPool is Proxy {
    bool private _initialized;
    address public admin;
    uint256 public interestRate;

    function initialize(address _admin, uint256 _rate) external {
        require(!_initialized, "already initialized");
        admin = _admin;
        interestRate = _rate;
        // BUG: _initialized never set to true — can be called again
    }

    function setRate(uint256 _rate) external {
        require(msg.sender == admin);
        interestRate = _rate;
    }
}
```

**Fixed:**
```solidity
contract LendingPool is Proxy {
    bool private _initialized;
    address public admin;
    uint256 public interestRate;

    function initialize(address _admin, uint256 _rate) external {
        require(!_initialized, "already initialized");
        _initialized = true;
        admin = _admin;
        interestRate = _rate;
    }

    function setRate(uint256 _rate) external {
        require(msg.sender == admin);
        interestRate = _rate;
    }
}
```

### Pattern 3: Unprotected Versioned Reinitializer on Upgrade
An upgrade introduces a `reinitializer(N)` function to migrate state but omits `onlyOwner`. An attacker calls it before the team, setting malicious parameters for the new version.

**Vulnerable:**
```solidity
contract TokenV2 is TokenV1 {
    address public feeRecipient;
    uint256 public feeRate;

    // BUG: No access control — anyone can set fees on upgrade
    function initializeV2(address _feeRecipient, uint256 _feeRate)
        public reinitializer(2)
    {
        feeRecipient = _feeRecipient;
        feeRate = _feeRate;
    }

    function transfer(address to, uint256 amount) public override {
        uint256 fee = amount * feeRate / 10000;
        super.transfer(feeRecipient, fee);
        super.transfer(to, amount - fee);
    }
}
```

**Fixed:**
```solidity
contract TokenV2 is TokenV1 {
    address public feeRecipient;
    uint256 public feeRate;

    function initializeV2(address _feeRecipient, uint256 _feeRate)
        public reinitializer(2) onlyOwner
    {
        feeRecipient = _feeRecipient;
        feeRate = _feeRate;
    }

    function transfer(address to, uint256 amount) public override {
        uint256 fee = amount * feeRate / 10000;
        super.transfer(feeRecipient, fee);
        super.transfer(to, amount - fee);
    }
}
```

### Pattern 4: Uninitialized Implementation Contract Takeover
The implementation contract behind a proxy is deployed without calling `_disableInitializers()` in its constructor. An attacker initializes the implementation directly, then uses `selfdestruct` or UUPS upgrade to brick or hijack all proxies pointing to it.

**Vulnerable:**
```solidity
contract VaultImpl is UUPSUpgradeable, OwnableUpgradeable {
    uint256 public depositCap;

    // BUG: No constructor calling _disableInitializers()
    // Attacker can call initialize() on the implementation itself

    function initialize(uint256 _cap) public initializer {
        __Ownable_init();
        depositCap = _cap;
    }

    function _authorizeUpgrade(address newImpl) internal override onlyOwner {}

    function deposit() external payable {
        require(address(this).balance <= depositCap);
    }
}
```

**Fixed:**
```solidity
contract VaultImpl is UUPSUpgradeable, OwnableUpgradeable {
    uint256 public depositCap;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(uint256 _cap) public initializer {
        __Ownable_init();
        depositCap = _cap;
    }

    function _authorizeUpgrade(address newImpl) internal override onlyOwner {}

    function deposit() external payable {
        require(address(this).balance <= depositCap);
    }
}
```

### Pattern 5: Repeatable Critical Address Setter Without One-Time Guard
A setter function for a critical protocol address (oracle, treasury, registry) lacks a one-time initialization check. It can be called repeatedly or has no access control, allowing an attacker to redirect funds or manipulate protocol behavior.

**Vulnerable:**
```solidity
contract Bridge is Initializable {
    address public validator;
    address public feeCollector;

    function initialize() public initializer {
        validator = msg.sender;
    }

    // BUG: No one-time guard, no access control
    function setFeeCollector(address _collector) external {
        feeCollector = _collector;
    }

    // BUG: Can be called by anyone to replace validator
    function registerValidator(address _validator) external {
        require(validator == address(0), "already set");
        // Race condition: attacker calls before team if validator
        // is reset during upgrade
        validator = _validator;
    }
}
```

**Fixed:**
```solidity
contract Bridge is Initializable, OwnableUpgradeable {
    address public validator;
    address public feeCollector;

    function initialize(address _validator, address _collector)
        public initializer
    {
        __Ownable_init();
        require(_validator != address(0), "zero validator");
        require(_collector != address(0), "zero collector");
        validator = _validator;
        feeCollector = _collector;
    }

    function setFeeCollector(address _collector) external onlyOwner {
        require(_collector != address(0), "zero address");
        feeCollector = _collector;
    }

    function setValidator(address _validator) external onlyOwner {
        require(_validator != address(0), "zero address");
        validator = _validator;
    }
}
```

### Detect
For every initialization function in a proxy-based contract: (1) verify it uses `initializer` or `reinitializer` modifier, (2) verify manual init flags are properly set, (3) verify upgrade reinitializers have access control, (4) verify implementation constructors call `_disableInitializers()`, (5) verify critical address setters have one-time or access-controlled guards.

### Remediation
Use OpenZeppelin's `initializer`/`reinitializer` modifiers. Add `onlyOwner` or equivalent to upgrade initializers. Ensure `_disableInitializers()` is called in implementation constructors. Never leave custom init functions unguarded.

## CL-PROXY-05: Initialization Completeness Invariant

**Rule:** `INIT-02`
**Severity:** low-high

### Description
When a contract inherits from upgradeable base contracts (OwnableUpgradeable, ERC20Upgradeable, ReentrancyGuardUpgradeable, etc.) or has dependencies that must be set during initialization, the initialization function can fail to call all required parent initializers, leave critical state variables unset, use `__init` instead of `__init_unchained` in diamond inheritance, or split setup across multiple transactions creating an exploitable window. This results in uninitialized reentrancy guards leaving contracts vulnerable, missing ownership setup granting no one admin rights, unset dependency addresses causing reverts on first use, and two-step initialization gaps allowing attackers to intercept partially configured contracts.

### Patterns
### Pattern 1: Missing Parent Initializer Call
The `initialize` function fails to call `__ParentContract_init()` for one or more inherited upgradeable contracts, leaving their state at default values (zero addresses, disabled guards).

**Vulnerable:**
```solidity
contract StakingV1 is
    Initializable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable
{
    IERC20 public stakingToken;
    uint256 public rewardRate;

    function initialize(address _token, uint256 _rate) public initializer {
        __Ownable_init();
        // BUG: Missing __ReentrancyGuard_init() — guard is disabled
        // BUG: Missing __Pausable_init() — pause state undefined
        stakingToken = IERC20(_token);
        rewardRate = _rate;
    }

    function stake(uint256 amount) external nonReentrant whenNotPaused {
        // nonReentrant may not work without initialization
        stakingToken.transferFrom(msg.sender, address(this), amount);
    }
}
```

**Fixed:**
```solidity
contract StakingV1 is
    Initializable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable
{
    IERC20 public stakingToken;
    uint256 public rewardRate;

    function initialize(address _token, uint256 _rate) public initializer {
        __Ownable_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        stakingToken = IERC20(_token);
        rewardRate = _rate;
    }

    function stake(uint256 amount) external nonReentrant whenNotPaused {
        stakingToken.transferFrom(msg.sender, address(this), amount);
    }
}
```

### Pattern 2: Non-Unchained Initializer in Diamond Inheritance
In a diamond inheritance hierarchy, calling `__Parent_init()` instead of `__Parent_init_unchained()` causes shared ancestor initializers to run multiple times, wasting gas or corrupting state.

**Vulnerable:**
```solidity
contract GovernanceToken is
    Initializable,
    ERC20Upgradeable,
    ERC20BurnableUpgradeable,
    ERC20VotesUpgradeable
{
    function initialize(string memory name, string memory symbol)
        public initializer
    {
        // BUG: ERC20 __init called 3 times through diamond
        __ERC20_init(name, symbol);         // calls __ERC20_init
        __ERC20Burnable_init();              // also calls __ERC20_init
        __ERC20Votes_init();                 // also calls __ERC20_init
    }
}
```

**Fixed:**
```solidity
contract GovernanceToken is
    Initializable,
    ERC20Upgradeable,
    ERC20BurnableUpgradeable,
    ERC20VotesUpgradeable
{
    function initialize(string memory name, string memory symbol)
        public initializer
    {
        __ERC20_init(name, symbol);
        __ERC20Burnable_init_unchained();
        __ERC20Votes_init_unchained();
    }
}
```

### Pattern 3: Uninitialized Critical Dependency Causing DoS
A state variable (oracle, router, registry address) is never assigned during initialization. The first user interaction attempts to call the zero address and reverts permanently.

**Vulnerable:**
```solidity
contract YieldAggregator is Initializable, OwnableUpgradeable {
    IOracle public oracle;
    IRouter public router;
    address public treasury;

    function initialize(address _treasury) public initializer {
        __Ownable_init();
        treasury = _treasury;
        // BUG: oracle and router never set — first deposit reverts
    }

    function deposit(uint256 amount) external {
        uint256 price = oracle.getPrice();  // reverts: call to 0x0
        uint256 minOut = amount * price / 1e18;
        router.swap(amount, minOut);         // also reverts
    }
}
```

**Fixed:**
```solidity
contract YieldAggregator is Initializable, OwnableUpgradeable {
    IOracle public oracle;
    IRouter public router;
    address public treasury;

    function initialize(
        address _treasury,
        address _oracle,
        address _router
    ) public initializer {
        __Ownable_init();
        require(_oracle != address(0), "zero oracle");
        require(_router != address(0), "zero router");
        require(_treasury != address(0), "zero treasury");
        treasury = _treasury;
        oracle = IOracle(_oracle);
        router = IRouter(_router);
    }

    function deposit(uint256 amount) external {
        uint256 price = oracle.getPrice();
        uint256 minOut = amount * price / 1e18;
        router.swap(amount, minOut);
    }
}
```

### Pattern 4: Two-Step Initialization Gap
Critical state setup is split across deployment and a second transaction (e.g., deploy then `setOracle`), creating a window where the contract is live but misconfigured. Attackers exploit the incomplete state.

**Vulnerable:**
```solidity
contract Marketplace is Initializable, OwnableUpgradeable {
    address public paymentToken;
    address public feeRecipient;
    bool public whitelistEnabled;

    function initialize(address _token) public initializer {
        __Ownable_init();
        paymentToken = _token;
        // BUG: feeRecipient set in separate tx — fees go to 0x0
        // BUG: whitelistEnabled not set — anyone can list
    }

    // Called hours later by team
    function configure(address _feeRecipient, bool _whitelist) external onlyOwner {
        feeRecipient = _feeRecipient;
        whitelistEnabled = _whitelist;
    }

    function purchase(uint256 listingId) external payable {
        // Fees sent to address(0) if configure() not called yet
        payable(feeRecipient).transfer(msg.value / 10);
    }
}
```

**Fixed:**
```solidity
contract Marketplace is Initializable, OwnableUpgradeable {
    address public paymentToken;
    address public feeRecipient;
    bool public whitelistEnabled;

    function initialize(
        address _token,
        address _feeRecipient,
        bool _whitelist
    ) public initializer {
        __Ownable_init();
        require(_token != address(0), "zero token");
        require(_feeRecipient != address(0), "zero fee recipient");
        paymentToken = _token;
        feeRecipient = _feeRecipient;
        whitelistEnabled = _whitelist;
    }

    function purchase(uint256 listingId) external payable {
        payable(feeRecipient).transfer(msg.value / 10);
    }
}
```

### Pattern 5: Nested Initializer Modifiers Blocking Execution
Both child and parent `initialize` functions use the `initializer` modifier. Since `initializer` can only succeed once, the parent's modifier blocks after the child's consumes it, leaving the parent uninitialized.

**Vulnerable:**
```solidity
contract BaseVault is Initializable {
    address public asset;

    // BUG: Uses `initializer` — conflicts with child's modifier
    function initialize(address _asset) public initializer {
        asset = _asset;
    }
}

contract LeveragedVault is BaseVault {
    uint256 public leverage;

    function initialize(address _asset, uint256 _leverage) public initializer {
        // BUG: This call fails because `initializer` already consumed
        BaseVault.initialize(_asset);
        leverage = _leverage;
    }
}
```

**Fixed:**
```solidity
contract BaseVault is Initializable {
    address public asset;

    function __BaseVault_init(address _asset) internal onlyInitializing {
        asset = _asset;
    }
}

contract LeveragedVault is BaseVault {
    uint256 public leverage;

    function initialize(address _asset, uint256 _leverage) public initializer {
        __BaseVault_init(_asset);
        leverage = _leverage;
    }
}
```

### Detect
For every upgradeable contract: (1) verify all inherited `__init` or `__init_unchained` functions are called, (2) verify diamond inheritance uses `_unchained` variants, (3) verify all critical dependencies are set during init, (4) verify no two-step initialization gaps exist, (5) verify parent initializers use `onlyInitializing` not `initializer`.

### Remediation
Call every inherited contract's initializer. Use `__init_unchained` in diamond inheritance. Set all critical state in a single atomic initialization. Verify all dependencies are non-zero after init.

## CL-PROXY-06: Initialization Parameter Validation Invariant

**Rule:** `INIT-03`
**Severity:** informational-high

### Description
When a contract's initialization function accepts parameters that configure addresses, rates, thresholds, roles, or other critical state that cannot easily be corrected post-deployment, initialization functions can accept parameters without validating zero addresses, value ranges, parameter ordering, cross-parameter consistency, or uniqueness constraints. This leads to permanent misconfiguration causing fund loss (fees sent to zero address), DoS (invalid thresholds blocking operations), incorrect accounting (swapped parameters), duplicate registrations inflating state, and stale hardcoded values preventing cross-chain deployment.

### Patterns
### Pattern 1: Missing Zero-Address Validation on Critical Addresses
Initialization accepts address parameters for owner, treasury, oracle, or token without checking for `address(0)`. Funds or calls are permanently directed to the zero address.

**Vulnerable:**
```solidity
contract RewardDistributor is Initializable, OwnableUpgradeable {
    IERC20 public rewardToken;
    address public treasury;
    address public oracle;

    function initialize(
        address _token,
        address _treasury,
        address _oracle
    ) public initializer {
        __Ownable_init();
        // BUG: No zero-address checks — all three could be 0x0
        rewardToken = IERC20(_token);
        treasury = _treasury;
        oracle = _oracle;
    }

    function distributeRewards(uint256 amount) external onlyOwner {
        // Transfers to address(0) — tokens burned permanently
        rewardToken.transfer(treasury, amount);
    }
}
```

**Fixed:**
```solidity
contract RewardDistributor is Initializable, OwnableUpgradeable {
    IERC20 public rewardToken;
    address public treasury;
    address public oracle;

    function initialize(
        address _token,
        address _treasury,
        address _oracle
    ) public initializer {
        __Ownable_init();
        require(_token != address(0), "zero token");
        require(_treasury != address(0), "zero treasury");
        require(_oracle != address(0), "zero oracle");
        rewardToken = IERC20(_token);
        treasury = _treasury;
        oracle = _oracle;
    }
}
```

### Pattern 2: Incorrect Parameter Ordering in Initialization
Positional arguments are passed in the wrong order during initialization, silently swapping role assignments, addresses, or numeric values without any type-system protection.

**Vulnerable:**
```solidity
contract MultiSigWallet is Initializable {
    address public admin;
    address public guardian;
    uint256 public threshold;
    uint256 public timelock;

    function initialize(
        address _admin,
        address _guardian,
        uint256 _threshold,
        uint256 _timelock
    ) public initializer {
        admin = _admin;
        guardian = _guardian;
        threshold = _threshold;
        timelock = _timelock;
    }
}

contract Factory {
    function deploy(address admin, address guardian) external {
        MultiSigWallet wallet = new MultiSigWallet();
        // BUG: guardian and admin swapped — guardian gets admin powers
        wallet.initialize(guardian, admin, 3, 86400);
    }
}
```

**Fixed:**
```solidity
contract Factory {
    function deploy(address admin, address guardian) external {
        MultiSigWallet wallet = new MultiSigWallet();
        // Correct ordering matches initialize() declaration
        wallet.initialize(admin, guardian, 3, 86400);
    }
}

// Even better: use a struct to prevent ordering issues
contract MultiSigWalletV2 is Initializable {
    struct InitParams {
        address admin;
        address guardian;
        uint256 threshold;
        uint256 timelock;
    }

    function initialize(InitParams calldata params) public initializer {
        require(params.admin != params.guardian, "same address");
        // Named fields prevent ordering bugs
    }
}
```

### Pattern 3: Missing Cross-Parameter Consistency Checks
Initialization accepts multiple parameters that have semantic relationships (e.g., start < end, fee < max, collateral > debt) but does not validate their consistency.

**Vulnerable:**
```solidity
contract Auction is Initializable {
    uint256 public startTime;
    uint256 public endTime;
    uint256 public minBid;
    uint256 public reservePrice;

    function initialize(
        uint256 _start,
        uint256 _end,
        uint256 _minBid,
        uint256 _reserve
    ) public initializer {
        // BUG: No check that _end > _start
        // BUG: No check that _reserve >= _minBid
        // BUG: No check that _start > block.timestamp
        startTime = _start;
        endTime = _end;
        minBid = _minBid;
        reservePrice = _reserve;
    }

    function bid() external payable {
        require(block.timestamp >= startTime && block.timestamp < endTime);
        require(msg.value >= minBid);
    }
}
```

**Fixed:**
```solidity
contract Auction is Initializable {
    uint256 public startTime;
    uint256 public endTime;
    uint256 public minBid;
    uint256 public reservePrice;

    function initialize(
        uint256 _start,
        uint256 _end,
        uint256 _minBid,
        uint256 _reserve
    ) public initializer {
        require(_start > block.timestamp, "start in past");
        require(_end > _start, "end before start");
        require(_reserve >= _minBid, "reserve below min");
        require(_minBid > 0, "zero min bid");
        startTime = _start;
        endTime = _end;
        minBid = _minBid;
        reservePrice = _reserve;
    }
}
```

### Pattern 4: Duplicate Registration in Initialization Without Uniqueness Check
Initialization or asset-addition functions accept arrays without checking for duplicates, allowing the same asset/address to be registered multiple times, inflating accounting or granting double voting power.

**Vulnerable:**
```solidity
contract AssetRegistry is Initializable, OwnableUpgradeable {
    address[] public supportedAssets;
    mapping(address => bool) public isSupported;

    function initialize(address[] calldata _assets) public initializer {
        __Ownable_init();
        for (uint256 i = 0; i < _assets.length; i++) {
            // BUG: No duplicate check — same asset counted twice
            supportedAssets.push(_assets[i]);
            isSupported[_assets[i]] = true;
        }
    }

    function totalAssets() external view returns (uint256) {
        // Returns inflated count if duplicates exist
        return supportedAssets.length;
    }
}
```

**Fixed:**
```solidity
contract AssetRegistry is Initializable, OwnableUpgradeable {
    address[] public supportedAssets;
    mapping(address => bool) public isSupported;

    function initialize(address[] calldata _assets) public initializer {
        __Ownable_init();
        for (uint256 i = 0; i < _assets.length; i++) {
            require(_assets[i] != address(0), "zero address");
            require(!isSupported[_assets[i]], "duplicate asset");
            supportedAssets.push(_assets[i]);
            isSupported[_assets[i]] = true;
        }
    }
}
```

### Pattern 5: Hardcoded Environment-Specific Parameters
Critical addresses, chain IDs, or protocol parameters are hardcoded in source rather than passed as initialization parameters, preventing reuse across chains or environments and creating permanent misconfiguration risk.

**Vulnerable:**
```solidity
contract CrossChainBridge is Initializable {
    // BUG: Hardcoded mainnet WETH — breaks on L2s and testnets
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    // BUG: Hardcoded Uniswap V3 router — breaks if deprecated
    address constant ROUTER = 0xE592427A0AEce92De3Edee1F18E0157C05861564;
    // BUG: Hardcoded slippage — may be too high or low
    uint256 constant MAX_SLIPPAGE = 100; // 1%

    function initialize() public initializer {
        // Nothing configurable
    }

    function bridgeAndSwap(uint256 amount) external {
        IERC20(WETH).approve(ROUTER, amount);
        IRouter(ROUTER).swap(amount, amount * (10000 - MAX_SLIPPAGE) / 10000);
    }
}
```

**Fixed:**
```solidity
contract CrossChainBridge is Initializable, OwnableUpgradeable {
    address public weth;
    address public router;
    uint256 public maxSlippage;

    function initialize(
        address _weth,
        address _router,
        uint256 _maxSlippage
    ) public initializer {
        __Ownable_init();
        require(_weth != address(0), "zero weth");
        require(_router != address(0), "zero router");
        require(_maxSlippage <= 1000, "slippage too high"); // max 10%
        weth = _weth;
        router = _router;
        maxSlippage = _maxSlippage;
    }
}
```

### Detect
For every initialization function: (1) verify all address parameters are checked against zero, (2) verify parameter ordering matches semantic intent, (3) verify cross-parameter consistency constraints, (4) verify array inputs have uniqueness checks, (5) verify no critical values are hardcoded.

### Remediation
Validate all address parameters against zero. Check numeric ranges and cross-parameter consistency. Verify parameter ordering matches expected semantics. Add uniqueness checks for registrations. Avoid hardcoding environment-specific values.

## CL-PROXY-07: Storage Layout Safety Invariant

**Rule:** `STOR-01`
**Severity:** informational-high

### Description
When a contract is upgradeable and uses delegatecall-based proxy patterns where the proxy holds storage and the implementation defines the layout, storage slot assignments can change between implementation versions due to variable reordering, missing storage gaps, constructor-based initialization, mixing upgradeable and non-upgradeable library imports, or field-level default value assignments that only execute in the implementation context. This results in complete state corruption: balances map to wrong users, ownership assigned to random addresses, reentrancy guards broken, token supplies corrupted. Any storage collision is typically catastrophic and irreversible.

### Patterns
### Pattern 1: Missing Storage Gap in Upgradeable Base Contract
A base contract that is inherited by multiple children does not reserve a `__gap` array. Adding new variables to the base in a future version shifts all child storage slots.

**Vulnerable:**
```solidity
contract BaseAccessControl is Initializable {
    address public owner;
    mapping(address => bool) public operators;
    // BUG: No __gap — adding variables here corrupts children

    function __BaseAccessControl_init() internal onlyInitializing {
        owner = msg.sender;
    }
}

contract VaultV1 is BaseAccessControl {
    uint256 public totalDeposits;  // slot 2
    mapping(address => uint256) public balances;  // slot 3
}

// Future upgrade adds `paused` to BaseAccessControl
// totalDeposits now reads from `paused` slot — catastrophic
```

**Fixed:**
```solidity
contract BaseAccessControl is Initializable {
    address public owner;
    mapping(address => bool) public operators;
    uint256[48] private __gap;  // Reserve 48 slots

    function __BaseAccessControl_init() internal onlyInitializing {
        owner = msg.sender;
    }
}

contract VaultV1 is BaseAccessControl {
    uint256 public totalDeposits;  // Stable slot assignment
    mapping(address => uint256) public balances;
}
```

### Pattern 2: Storage Variable Reordering Between Versions
New variables are inserted between existing ones or existing variables are reordered, shifting all subsequent slot assignments and corrupting storage reads.

**Vulnerable:**
```solidity
// V1 Layout
contract TokenV1 is Initializable {
    string public name;       // slot 0
    string public symbol;     // slot 1
    uint256 public totalSupply; // slot 2
    mapping(address => uint256) public balances; // slot 3
}

// V2 Layout — WRONG: inserted decimals before totalSupply
contract TokenV2 is Initializable {
    string public name;       // slot 0
    string public symbol;     // slot 1
    uint8 public decimals;    // slot 2 — NEW, shifts everything
    uint256 public totalSupply; // slot 3 — WAS slot 2, now reads balances!
    mapping(address => uint256) public balances; // slot 4
    uint256 public maxSupply; // slot 5
}
```

**Fixed:**
```solidity
// V2 Layout — CORRECT: append new variables at the end
contract TokenV2 is Initializable {
    string public name;       // slot 0
    string public symbol;     // slot 1
    uint256 public totalSupply; // slot 2 — unchanged
    mapping(address => uint256) public balances; // slot 3 — unchanged
    uint8 public decimals;    // slot 4 — appended
    uint256 public maxSupply; // slot 5 — appended
}
```

### Pattern 3: Constructor Storage Initialization in Upgradeable Contract
State variables are initialized in the constructor or via field-level declarations. These run during implementation deployment (setting implementation storage) but never during proxy deployment, leaving proxy storage at zero.

**Vulnerable:**
```solidity
contract LendingPoolV1 is UUPSUpgradeable {
    // BUG: Field declaration runs in constructor context only
    uint256 public maxLTV = 8000;           // 80% — set in implementation, not proxy
    uint256 public liquidationBonus = 500;  // 5% — same issue
    bool public active = true;              // never true in proxy

    function initialize() public initializer {
        // maxLTV, liquidationBonus, active are 0/false in proxy context
        __UUPSUpgradeable_init();
    }

    function borrow(uint256 amount, uint256 collateral) external {
        // maxLTV is 0 in proxy — all borrows fail or allow infinite leverage
        require(amount * 10000 / collateral <= maxLTV, "exceeds LTV");
    }
}
```

**Fixed:**
```solidity
contract LendingPoolV1 is UUPSUpgradeable {
    uint256 public maxLTV;
    uint256 public liquidationBonus;
    bool public active;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize() public initializer {
        __UUPSUpgradeable_init();
        maxLTV = 8000;
        liquidationBonus = 500;
        active = true;
    }
}
```

### Pattern 4: Mixed Upgradeable and Non-Upgradeable Library Imports
The contract mixes standard OpenZeppelin imports (which use constructors) with upgradeable variants (which use initializers). The non-upgradeable constructors set state in the implementation's storage, not the proxy's.

**Vulnerable:**
```solidity
import "@openzeppelin/contracts/access/Ownable.sol";  // non-upgradeable
import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";  // non-upgradeable

// BUG: Ownable constructor sets owner in impl storage, not proxy
// BUG: ReentrancyGuard constructor sets _status in impl storage
contract TokenV1 is Ownable, ERC20Upgradeable, ReentrancyGuard {
    function initialize(string memory name, string memory symbol)
        public initializer
    {
        __ERC20_init(name, symbol);
        // Ownable owner is 0x0 in proxy — no one can admin
        // ReentrancyGuard _status is 0 in proxy — guard broken
    }
}
```

**Fixed:**
```solidity
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

contract TokenV1 is OwnableUpgradeable, ERC20Upgradeable, ReentrancyGuardUpgradeable {
    function initialize(string memory name, string memory symbol)
        public initializer
    {
        __Ownable_init();
        __ERC20_init(name, symbol);
        __ReentrancyGuard_init();
    }
}
```

### Pattern 5: Immutable Arguments Overflow in Minimal Clones
Clones with immutable arguments (ClonesWithImmutableArgs / CWIA) encode arguments into bytecode. If the total argument length exceeds the 2-byte length field (65535 bytes) or argument boundaries are miscalculated, reads return corrupted data.

**Vulnerable:**
```solidity
contract CloneFactory {
    using ClonesWithImmutableArgs for address;

    function createVault(
        address owner,
        address token,
        bytes memory metadata  // could be arbitrarily long
    ) external returns (address) {
        bytes memory data = abi.encodePacked(owner, token, metadata);
        // BUG: If metadata > 65,503 bytes, length field overflows
        // BUG: No validation of metadata length
        return implementation.clone(data);
    }
}

contract VaultClone {
    function _getArgAddress(uint256 offset) internal pure returns (address) {
        // If offsets are wrong due to overflow, reads wrong data
        return address(bytes20(_getArgBytes(offset, 20)));
    }
}
```

**Fixed:**
```solidity
contract CloneFactory {
    using ClonesWithImmutableArgs for address;

    uint256 constant MAX_IMMUTABLE_ARGS = 65000;

    function createVault(
        address owner,
        address token,
        bytes memory metadata
    ) external returns (address) {
        bytes memory data = abi.encodePacked(owner, token, metadata);
        require(data.length <= MAX_IMMUTABLE_ARGS, "args too long");
        require(owner != address(0) && token != address(0), "zero addr");
        return implementation.clone(data);
    }
}
```

### Detect
For every upgradeable contract: (1) verify base contracts declare `__gap` storage arrays, (2) verify no variable reordering or insertion between versions, (3) verify no constructor/field-level storage initialization, (4) verify all imports use upgradeable variants, (5) verify immutable clone argument lengths are bounded.

### Remediation
Reserve storage gaps in base contracts. Never reorder or remove variables. Use upgradeable library variants exclusively. Never initialize storage in constructors or field declarations. Use OpenZeppelin's storage checker plugin.

## CL-PROXY-08: Upgrade Authorization Invariant

**Rule:** `UPG-01`
**Severity:** low-critical

### Description
When a contract uses a proxy pattern (UUPS, transparent, beacon, or custom) with a mechanism to change the implementation address, upgrade functions can lack access control, skip implementation validation, concentrate authority in a single EOA without timelock, allow invariant bypasses during upgrade, or fail to verify the new implementation is a valid contract with the expected interface. This results in complete protocol takeover via malicious implementation swap, rug-pull by single admin key, bricked proxies from upgrading to invalid code, broken state from bypassed upgrade invariants, and silent degradation from unvalidated implementation targets.

### Patterns
### Pattern 1: Unprotected UUPS _authorizeUpgrade
The UUPS pattern requires the implementation to contain the upgrade logic. If `_authorizeUpgrade` is left empty or has no access control, anyone can upgrade the proxy to a malicious implementation.

**Vulnerable:**
```solidity
contract VaultV1 is UUPSUpgradeable, Initializable {
    mapping(address => uint256) public balances;

    function initialize() public initializer {
        // No ownership setup
    }

    // BUG: No access control — anyone can upgrade
    function _authorizeUpgrade(address newImplementation)
        internal
        override
    {
        // Empty — completely unprotected
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
```

**Fixed:**
```solidity
contract VaultV1 is UUPSUpgradeable, OwnableUpgradeable {
    mapping(address => uint256) public balances;

    function initialize() public initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyOwner
    {
        // Only owner can upgrade
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
```

### Pattern 2: Centralized Upgrade Authority Without Timelock
A single EOA (externally owned account) can instantly upgrade the proxy implementation, enabling rug-pulls or compromised-key attacks with no time for users to exit.

**Vulnerable:**
```solidity
contract ManagedProxy is TransparentUpgradeableProxy {
    // ProxyAdmin is controlled by a single EOA
    // No timelock, no governance, no multi-sig
    // Admin can swap implementation to a contract that drains all funds
}

contract ProxyAdmin is Ownable {
    // BUG: Single owner can instantly upgrade any proxy
    function upgrade(
        TransparentUpgradeableProxy proxy,
        address implementation
    ) public onlyOwner {
        proxy.upgradeTo(implementation);
    }

    function upgradeAndCall(
        TransparentUpgradeableProxy proxy,
        address implementation,
        bytes memory data
    ) public payable onlyOwner {
        proxy.upgradeToAndCall{value: msg.value}(implementation, data);
    }
}
```

**Fixed:**
```solidity
contract TimelockProxyAdmin is Ownable {
    uint256 public constant UPGRADE_DELAY = 48 hours;

    struct PendingUpgrade {
        address implementation;
        uint256 executeAfter;
    }

    mapping(address => PendingUpgrade) public pendingUpgrades;

    function proposeUpgrade(address proxy, address impl) external onlyOwner {
        pendingUpgrades[proxy] = PendingUpgrade({
            implementation: impl,
            executeAfter: block.timestamp + UPGRADE_DELAY
        });
    }

    function executeUpgrade(address proxy) external onlyOwner {
        PendingUpgrade memory pending = pendingUpgrades[proxy];
        require(pending.executeAfter != 0, "no pending upgrade");
        require(block.timestamp >= pending.executeAfter, "timelock active");
        delete pendingUpgrades[proxy];
        TransparentUpgradeableProxy(payable(proxy)).upgradeTo(
            pending.implementation
        );
    }
}
```

### Pattern 3: Unvalidated Upgrade Target
The upgrade function accepts any address as the new implementation without verifying it is a deployed contract, implements the expected interface, or meets version requirements.

**Vulnerable:**
```solidity
contract BeaconController is Ownable {
    address public implementation;

    // BUG: No validation that newImpl is a contract
    // BUG: No interface check
    // BUG: No version check
    function upgradeBeacon(address newImpl) external onlyOwner {
        implementation = newImpl;
        emit Upgraded(newImpl);
    }
}

contract MultiProxyAdmin is Ownable {
    function batchUpgrade(address[] calldata proxies, address[] calldata impls)
        external onlyOwner
    {
        for (uint i = 0; i < proxies.length; i++) {
            // BUG: No validation on any implementation address
            IProxy(proxies[i]).upgradeTo(impls[i]);
        }
    }
}
```

**Fixed:**
```solidity
contract BeaconController is Ownable {
    address public implementation;

    function upgradeBeacon(address newImpl) external onlyOwner {
        require(newImpl.code.length > 0, "not a contract");
        require(
            IERC165(newImpl).supportsInterface(type(IVault).interfaceId),
            "bad interface"
        );
        implementation = newImpl;
        emit Upgraded(newImpl);
    }
}
```

### Pattern 4: Bypassable Upgrade Invariant Checks
The upgrade path allows skipping internal validation logic (e.g., paused state, migration checks, version constraints) that should always hold. The new implementation can override or bypass these protections.

**Vulnerable:**
```solidity
contract ProtocolV1 is UUPSUpgradeable, OwnableUpgradeable {
    uint256 public version;
    bool public migrationComplete;

    function _authorizeUpgrade(address newImpl) internal override onlyOwner {
        // BUG: No version monotonicity check
        // BUG: No migration completion check
        // Allows downgrade or upgrade before migration finishes
    }

    function migrate() external onlyOwner {
        // Long-running migration process
        migrationComplete = true;
    }
}
```

**Fixed:**
```solidity
contract ProtocolV1 is UUPSUpgradeable, OwnableUpgradeable {
    uint256 public version;
    bool public migrationComplete;

    function _authorizeUpgrade(address newImpl) internal override onlyOwner {
        require(migrationComplete, "migration not done");
        uint256 newVersion = IVersioned(newImpl).version();
        require(newVersion > version, "must be newer version");
        version = newVersion;
    }
}
```

### Pattern 5: Proxy Implementation Upgrade Without Proxy Validation
Custom proxy implementations store the implementation address in a non-standard slot or fail to validate the caller through the admin mechanism, allowing unauthorized address changes.

**Vulnerable:**
```solidity
contract CustomProxy {
    address public implementation;
    address public admin;

    // BUG: Anyone can call — no admin check
    function setImplementation(address _impl) external {
        implementation = _impl;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
```

**Fixed:**
```solidity
contract CustomProxy {
    bytes32 private constant IMPL_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
    bytes32 private constant ADMIN_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);

    function setImplementation(address _impl) external {
        require(msg.sender == _getAdmin(), "not admin");
        require(_impl.code.length > 0, "not a contract");
        StorageSlot.getAddressSlot(IMPL_SLOT).value = _impl;
    }

    function _getAdmin() internal view returns (address) {
        return StorageSlot.getAddressSlot(ADMIN_SLOT).value;
    }
}
```

### Detect
For every upgradeable proxy: (1) verify `_authorizeUpgrade` has access control, (2) verify upgrade authority uses timelock/governance, (3) verify new implementations are validated as contracts with correct interfaces, (4) verify upgrade invariants cannot be bypassed, (5) verify implementation address changes require admin authentication.

### Remediation
Always protect `_authorizeUpgrade` with `onlyOwner` or governance. Validate new implementations are contracts with expected interfaces. Use timelocks for upgrade authority. Enforce upgrade invariants. Verify implementation targets before setting.

## CL-PROXY-09: Upgrade State Consistency Invariant

**Rule:** `UPG-02`
**Severity:** low-high

### Description
When a contract undergoes an upgrade that introduces new state variables, changes accounting logic, modifies dependency addresses, or requires state migration from V1 layout to V2 layout, upgrade transitions can fail to migrate existing state, use incorrect reinitializer versions, update dependencies in one contract but not linked contracts, reuse stale implementation references, or introduce new accounting without backfilling historical data. This results in state desynchronization between linked contracts, stale implementations processing with outdated logic, accounting inconsistencies from unmigrated state, broken cross-contract references, and permanent DoS from version mismatches.

### Patterns
### Pattern 1: Incorrect Reinitializer Version Sequencing
The reinitializer uses wrong version number (skipping, reusing, or decrementing), causing the upgrade initializer to either revert (version already used) or leave a gap exploitable by future upgrades.

**Vulnerable:**
```solidity
contract TokenV1 is Initializable {
    string public name;
    function initialize(string memory _name) public initializer {
        name = _name;
    }
}

contract TokenV2 is TokenV1 {
    uint256 public fee;
    // BUG: Should be reinitializer(2), not reinitializer(3)
    // Leaves version 2 unused — someone could claim it
    function initializeV2(uint256 _fee) public reinitializer(3) {
        fee = _fee;
    }
}

contract TokenV3 is TokenV2 {
    address public feeRecipient;
    // BUG: Version 2 is still open — attacker can call any
    // function with reinitializer(2) to inject state
    function initializeV3(address _recipient) public reinitializer(4) {
        feeRecipient = _recipient;
    }
}
```

**Fixed:**
```solidity
contract TokenV2 is TokenV1 {
    uint256 public fee;
    function initializeV2(uint256 _fee) public reinitializer(2) {
        fee = _fee;
    }
}

contract TokenV3 is TokenV2 {
    address public feeRecipient;
    function initializeV3(address _recipient) public reinitializer(3) {
        feeRecipient = _recipient;
    }
}
```

### Pattern 2: Unmigrated State After Accounting Logic Change
An upgrade introduces new accounting variables (e.g., per-user tracking, fee accumulators) without backfilling them from existing state, causing inconsistencies between old users and new users.

**Vulnerable:**
```solidity
contract VaultV1 is Initializable {
    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;
}

contract VaultV2 is VaultV1 {
    // New tracking: individual deposit timestamps
    mapping(address => uint256) public depositTimestamp;
    // New tracking: total weighted deposits
    uint256 public totalWeightedDeposits;

    function initializeV2() public reinitializer(2) {
        // BUG: Existing depositors have depositTimestamp = 0
        // BUG: totalWeightedDeposits = 0 but totalDeposits > 0
        // Reward calculations will be wrong for old users
    }

    function claimReward(address user) external {
        uint256 duration = block.timestamp - depositTimestamp[user];
        // Old users: duration = block.timestamp (massive rewards)
        uint256 reward = deposits[user] * duration / 365 days;
    }
}
```

**Fixed:**
```solidity
contract VaultV2 is VaultV1 {
    mapping(address => uint256) public depositTimestamp;
    uint256 public totalWeightedDeposits;
    uint256 public migrationTimestamp;

    function initializeV2() public reinitializer(2) {
        migrationTimestamp = block.timestamp;
        totalWeightedDeposits = totalDeposits;
    }

    function claimReward(address user) external {
        uint256 startTime = depositTimestamp[user];
        if (startTime == 0) startTime = migrationTimestamp;
        uint256 duration = block.timestamp - startTime;
        uint256 reward = deposits[user] * duration / 365 days;
    }
}
```

### Pattern 3: Inconsistent Dependency Update Across Modular Contracts
A setter updates a dependency address in one contract but not in linked contracts that reference the same dependency, creating state desynchronization.

**Vulnerable:**
```solidity
contract Controller is OwnableUpgradeable {
    address public oracle;
    address public vault;
    address public liquidator;

    function setOracle(address _oracle) external onlyOwner {
        oracle = _oracle;
        // BUG: vault and liquidator still reference old oracle
        // They fetch prices from stale/wrong source
    }
}

contract Vault {
    Controller public controller;
    function getPrice() internal view returns (uint256) {
        // Uses controller.oracle() — gets updated
        return IOracle(controller.oracle()).getPrice();
    }
}

contract Liquidator {
    address public oracle; // BUG: Cached — never updated
    function checkLiquidation(address user) external view {
        uint256 price = IOracle(oracle).getPrice(); // stale oracle
    }
}
```

**Fixed:**
```solidity
contract Controller is OwnableUpgradeable {
    address public oracle;
    address public vault;
    address public liquidator;

    function setOracle(address _oracle) external onlyOwner {
        require(_oracle != address(0), "zero oracle");
        oracle = _oracle;
        IVault(vault).updateOracle(_oracle);
        ILiquidator(liquidator).updateOracle(_oracle);
        emit OracleUpdated(_oracle);
    }
}
```

### Pattern 4: Stale Proxy Implementation Reuse
A pool or factory retrieves a previously deployed proxy from storage and reuses it without verifying that its implementation is current. The proxy may point to an outdated or deprecated implementation version.

**Vulnerable:**
```solidity
contract ProxyPool is OwnableUpgradeable {
    address[] public availableProxies;
    address public currentImplementation;

    function getProxy() external returns (address) {
        if (availableProxies.length > 0) {
            // BUG: Reused proxy may point to old implementation
            address proxy = availableProxies[availableProxies.length - 1];
            availableProxies.pop();
            return proxy; // Still running V1 while currentImplementation is V3
        }
        return address(new TransparentUpgradeableProxy(
            currentImplementation, address(this), ""
        ));
    }

    function returnProxy(address proxy) external {
        availableProxies.push(proxy);
    }
}
```

**Fixed:**
```solidity
contract ProxyPool is OwnableUpgradeable {
    address[] public availableProxies;
    address public currentImplementation;

    function getProxy() external returns (address) {
        if (availableProxies.length > 0) {
            address proxy = availableProxies[availableProxies.length - 1];
            availableProxies.pop();
            // Upgrade reused proxy to current implementation
            TransparentUpgradeableProxy(payable(proxy)).upgradeTo(
                currentImplementation
            );
            return proxy;
        }
        return address(new TransparentUpgradeableProxy(
            currentImplementation, address(this), ""
        ));
    }
}
```

### Pattern 5: Unprotected Asset Address Migration
An upgrade or setter changes a token/asset address without migrating balances, approvals, or accounting from the old address. Funds remain trapped in the old token and new accounting is inconsistent.

**Vulnerable:**
```solidity
contract VaultV2 is VaultV1 {
    function initializeV2(address newToken) public reinitializer(2) {
        // BUG: Old deposits are in oldToken — not migrated
        // BUG: Approvals still point to oldToken
        // BUG: totalDeposits reflects old token balance
        asset = newToken;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount);
        deposits[msg.sender] -= amount;
        // Tries to transfer newToken but vault only holds oldToken
        IERC20(asset).transfer(msg.sender, amount);  // reverts or wrong
    }
}
```

**Fixed:**
```solidity
contract VaultV2 is VaultV1 {
    address public legacyAsset;

    function initializeV2(address newToken) public reinitializer(2) onlyOwner {
        legacyAsset = asset;
        asset = newToken;
        // Migrate liquidity atomically or provide claim mechanism
    }

    function claimLegacy(uint256 amount) external {
        require(legacyDeposits[msg.sender] >= amount);
        legacyDeposits[msg.sender] -= amount;
        IERC20(legacyAsset).transfer(msg.sender, amount);
    }
}
```

### Detect
For every proxy upgrade: (1) verify reinitializer version numbers are sequential without gaps, (2) verify new accounting variables are backfilled from existing state, (3) verify dependency updates propagate to all linked contracts, (4) verify reused proxies have current implementations, (5) verify asset/token address changes include balance migration.

### Remediation
Always migrate state atomically during upgrade. Use correct reinitializer version numbers. Propagate dependency updates across all linked contracts. Verify implementation freshness. Backfill new accounting variables from existing state.
