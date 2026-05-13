---
name: proxy-upgrade-attacks
category: web3
description: Deep proxy and upgrade pattern security covering EIP-1967 Transparent, UUPS (EIP-1822), Beacon, Diamond (EIP-2535), Minimal Proxy (EIP-1167), storage collision detection, initializer patterns, selector clashing, implementation takeover, ERC-7201 namespaced storage, and upgrade path validation
depends_on: []
---

# Proxy and Upgrade Pattern Security

Deep security testing for upgradeable smart contract architectures. Focus on proxy pattern classification and misuse, storage collision detection across inheritance chains and facets, initializer security, function selector clashing, implementation contract takeover, ERC-7201 namespaced storage validation, and upgrade path compatibility.

## When to Use

- Target uses any upgradeable proxy pattern (Transparent, UUPS, Beacon, Diamond)
- Protocol deploys clone factories using Minimal Proxy (EIP-1167)
- Contract inheritance hierarchy involves gap arrays or namespaced storage
- Implementation contract upgrade is planned or has occurred historically
- Delegatecall is used anywhere in the codebase (even outside formal proxy patterns)
- Metamorphic contract patterns (CREATE2 + selfdestruct) are detected

## Methodology

### 1. Proxy Pattern Classification

Identify which proxy architecture is in use before analyzing vulnerabilities. Each pattern has distinct attack surfaces.

**Transparent Proxy (EIP-1967)**
- Two-tier call routing: admin calls hit the proxy contract logic, non-admin calls are delegated to the implementation
- ProxyAdmin contract holds admin privileges and is the only address that can call `upgradeTo`, `changeAdmin`
- User calls are always forwarded to implementation via `fallback()` even if they match a proxy function selector
- Admin calls NEVER reach the implementation, preventing the admin from accidentally calling implementation functions
- Attack surface: if ProxyAdmin ownership is compromised, attacker controls the upgrade path for all proxies managed by that admin
- Check: `cast call {proxy} "admin()(address)"` from the ProxyAdmin address to verify the admin is a contract, not an EOA

**UUPS (EIP-1822)**
- Upgrade logic lives in the implementation contract, not the proxy
- The proxy is minimal: only `fallback()` with delegatecall, no admin functions
- Implementation must include `upgradeTo` or `upgradeToAndCall` protected by `_authorizeUpgrade`
- If a new implementation omits `_authorizeUpgrade`, the proxy becomes permanently non-upgradeable (bricked)
- If `_authorizeUpgrade` has no access control, anyone can upgrade to a malicious implementation
- Advantage over Transparent: no selector clashing possible since proxy has no admin functions
- Check: read implementation slot `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc` and verify the implementation has `upgradeTo`

**Beacon Proxy**
- Multiple proxies share a single beacon contract that stores the implementation address
- Upgrading the beacon upgrades ALL proxies simultaneously in a single transaction
- Beacon address stored at EIP-1967 slot `0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50`
- Attack surface: if beacon ownership is compromised, attacker redirects all proxies to malicious code at once
- Check: `cast call {beacon} "implementation()(address)"` to verify the implementation contract is legitimate

**Diamond (EIP-2535)**
- Multi-facet architecture: a single proxy maps function selectors to different implementation contracts (facets)
- `diamondCut` function adds, replaces, or removes selector-to-facet mappings
- Storage is shared across all facets via delegatecall, requiring strict namespace separation
- Each facet can only expose functions for its registered selectors
- Attack surface: `diamondCut` access control is the single point of failure; also storage namespace collisions between facets
- Selector registry prevents clashing but does NOT prevent storage overlaps
- Check: `cast call {diamond} "facets()(tuple(address,bytes4[])[])"` via the DiamondLoupe facet to enumerate all facets and their selectors

**Minimal Proxy (EIP-1167)**
- Non-upgradeable clone: bytecode is a fixed delegatecall to an immutable implementation address
- Created by clone factories using `Clones.clone()` or `Clones.cloneDeterministic()`
- The implementation address is hardcoded in the proxy bytecode and cannot be changed
- Attack surface: if the implementation contract is compromised (e.g., uninitialized + taken over), all clones are affected
- No upgrade mechanism exists; to "upgrade" you must deploy new clones and migrate state
- Check: read the first 20 bytes of the proxy bytecode after the EIP-1167 prefix to extract the implementation address

**Metamorphic Contracts (pre-Dencun)**
- Uses CREATE2 to deploy at a predictable address, then selfdestruct to clear code, then redeploy different code at the same address
- Effectively upgradeable without a proxy pattern: the contract address stays the same but the code changes
- Post-Dencun (EIP-6780): selfdestruct only sends ETH, does not clear code or storage, breaking this pattern
- Detection: look for CREATE2 deployment + selfdestruct in the same protocol, or a factory that deploys via CREATE2 with varying initcode
- Attack surface: if the deployer key is compromised, attacker can destroy and redeploy with malicious code (pre-Dencun only)

### 2. Storage Collision Detection

Storage collisions corrupt state silently. The proxy and implementation share the same storage address space via delegatecall.

**EIP-1967 Standard Slots**
- Implementation slot: `bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)` = `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc`
- Admin slot: `bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1)` = `0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103`
- Beacon slot: `bytes32(uint256(keccak256("eip1967.proxy.beacon")) - 1)` = `0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50`
- These slots are chosen to be astronomically unlikely to collide with normal sequential Solidity storage slots
- Verify: the proxy contract must NOT declare any storage variables that could occupy these slots (sequential variables start at slot 0)

**Storage Layout Comparison with forge inspect**
```bash
# Dump storage layout of old and new implementation
forge inspect OldImplementation storage-layout --pretty > old_layout.txt
forge inspect NewImplementation storage-layout --pretty > new_layout.txt

# Compare side by side
diff old_layout.txt new_layout.txt

# Check specific slot on-chain
cast storage {proxy_address} 0 --rpc-url {rpc}
cast storage {proxy_address} 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url {rpc}
```

**Gap Arrays in Base Contracts**
- Base contracts in an inheritance chain reserve storage slots with `uint256[50] private __gap`
- When a new variable is added to a base contract, `__gap` is reduced: `uint256[49] private __gap`
- If the gap is not reduced, the new variable pushes all subsequent variables in derived contracts forward by one slot, corrupting their values
- Check: for every base contract in the chain, sum `(declared variables) + __gap` and verify it equals the original constant (typically 50)
- Common mistake: adding a mapping or dynamic array to a base contract without reducing the gap; mappings use keccak-hashed slots so they do not shift layout, but the slot for the mapping pointer itself still occupies one sequential slot

**ERC-7201 Namespaced Storage**
- Modern replacement for gap arrays; each storage struct is placed at a deterministic isolated slot
- Formula: `keccak256(abi.encode(uint256(keccak256("namespace.id")) - 1)) & ~bytes32(uint256(0xff))`
- The `& ~bytes32(uint256(0xff))` mask zeroes the last byte, giving 256 consecutive aligned slots per namespace
- Each namespace is collision-resistant: different namespace IDs produce slots separated by ~2^256 / 2^8 on average
- Verify: ensure the namespace string is unique per contract/module (e.g., `"openzeppelin.storage.Ownable"`)
- Common mistake: two facets or modules using the same namespace string, causing their structs to overlap
- Check with `forge inspect`:
```bash
# ERC-7201 namespaced layouts show up with the @custom:storage-location annotation
forge inspect Contract storage-layout --pretty
# Look for storage locations starting with high slot numbers (namespaced) vs sequential (legacy)
```

**Collision Between Proxy and Implementation**
- The proxy itself should declare zero storage variables (only use EIP-1967 slots)
- Any storage in the proxy contract body will collide with the implementation's slot 0, 1, 2...
- Verify: read the proxy source; it should inherit only from EIP-1967 compliant base contracts

**Collision Between Base Contracts in Inheritance Chain**
- Solidity uses C3 linearization: the order of inheritance determines slot assignment
- If contract C inherits A and B: `contract C is A, B`, then A's variables come first, then B's, then C's
- Changing inheritance order in an upgrade (e.g., `contract C is B, A`) shifts all slot assignments
- Check: compare C3 linearization between old and new implementations; it must be identical or strictly appending

**Diamond Facet Storage Namespace Overlap**
- Diamond facets share the entire storage space; without explicit namespacing, facet A's slot 0 IS facet B's slot 0
- Each facet MUST use a unique storage namespace (typically via AppStorage pattern or ERC-7201 namespaces)
- Verify: each facet accesses storage ONLY through its namespaced struct; no raw `sstore`/`sload` to sequential slots

### 3. Initializer Security

Constructors do not execute in the proxy context because the proxy uses delegatecall to the implementation. All setup must happen via initializer functions.

**`initialize()` vs Constructor**
- Constructor code runs once at deployment and modifies the implementation contract's storage, not the proxy's
- The proxy's storage is populated only via delegatecall, so setup logic must be in an `initialize()` function
- OpenZeppelin's `Initializable` contract provides the `initializer` modifier to enforce single-execution
- Check: verify that the implementation constructor is empty or only calls `_disableInitializers()`

**`_disableInitializers()` in Implementation Constructor**
- Calling `_disableInitializers()` in the implementation's constructor sets the initialized flag to `type(uint8).max` on the implementation contract itself
- This prevents attackers from calling `initialize()` directly on the implementation (not through the proxy)
- Without this, an attacker can call `initialize()` on the implementation, set themselves as owner, and in some cases use this to affect the proxy
- Check: verify the implementation constructor calls `_disableInitializers()`:
```solidity
/// @custom:oz-upgrades-unsafe-allow constructor
constructor() {
    _disableInitializers();
}
```

**Reentrancy in Initializer**
- If `initialize()` makes an external call (e.g., token approval, callback registration) before setting the initialized flag, an attacker can reenter and call `initialize()` again
- The `initializer` modifier from OpenZeppelin sets the flag before the function body executes, mitigating this
- Custom initializer implementations that set a flag at the end of the function are vulnerable
- Check: trace the execution order; the initialized flag must be set BEFORE any external calls

**`reinitializer(N)` for Upgrade-Time Re-Initialization**
- When upgrading, new state variables may need initialization via a migration function
- `reinitializer(2)` allows a one-time call during the upgrade that was not possible after the original `initializer` ran
- Each reinitializer version can only execute once; version N requires all versions < N to have already executed
- Check: if an upgrade adds new state variables, verify a `reinitializer` migration function exists and is called during `upgradeToAndCall`

**Missing Initializer on Implementation -- Attacker Takes Ownership**
- Scenario: implementation is deployed but `initialize()` is not called in the same transaction
- Window of opportunity: between deployment and initialization, anyone can call `initialize()` and become the owner
- For minimal proxies (EIP-1167): each clone must be initialized immediately after cloning; factory contracts should use `cloneAndInitialize` patterns
- For UUPS: attacker initializes the implementation directly, becomes owner, calls `upgradeTo` to point at malicious code
- Check: verify deployment scripts call `initialize()` atomically (in the same transaction as deployment or via constructor callback)

**Double Initialization**
- The `initializer` modifier from OpenZeppelin prevents double-init by checking a boolean flag
- Custom implementations using `require(!initialized)` followed by `initialized = true` can be vulnerable if the flag set is after external calls
- Transparent proxies: if the admin calls `upgradeToAndCall` with a reinitializer, verify the call cannot be replayed
- Check: attempt to call `initialize()` on the proxy after initial setup; it should revert with "Initializable: contract is already initialized"

### 4. Function Selector Clashing

Function selectors are the first 4 bytes of the keccak256 hash of the function signature. Different functions can have the same 4-byte selector.

**Proxy Admin vs Implementation Selector Clash**
- If a proxy has an admin function `upgrade(address)` and the implementation has a function with the same 4-byte selector, calls are misrouted
- Example: `proxyAdmin()` (selector `0x3e47158c`) could theoretically clash with an implementation function
- The probability of accidental clash is ~1 in 2^32 per function pair, but with many functions the birthday paradox applies
- Check: dump both proxy and implementation selectors and verify no overlap:
```bash
forge inspect Proxy methodIdentifiers
forge inspect Implementation methodIdentifiers
# Compare the two lists for any matching 4-byte selectors
```

**Transparent Proxy Mitigation**
- The Transparent Proxy pattern routes calls based on `msg.sender`: admin calls stay in proxy logic, all other calls are delegated
- This eliminates selector clashing entirely for non-admin callers
- Trade-off: the admin address can NEVER interact with the implementation, even for non-admin functions
- This is why a separate ProxyAdmin contract is used: EOAs can still call the implementation directly

**UUPS Has No Selector Clashing Issue**
- UUPS proxies have no admin functions in the proxy contract itself
- The proxy's only function is `fallback()`, which delegates all calls unconditionally
- Upgrade functions live in the implementation and are accessed via delegatecall like any other function
- No selector overlap is possible between proxy and implementation because the proxy has no selectors

**Diamond Selector Registry**
- EIP-2535 maintains an explicit mapping of selector to facet address
- `diamondCut` reverts if you try to register a selector that already belongs to another facet
- This prevents selector clashing between facets at the registry level
- However: if a facet exposes a function not registered in the diamond, it is unreachable (not a clash, but a misconfiguration)
- Check: verify all public/external functions in every facet are registered in the diamond's selector mapping

**Manual Selector Collision Search**
```bash
# Dump all selectors for a contract
forge inspect MyContract methodIdentifiers

# Compute a specific selector
cast sig "transfer(address,uint256)"
# Output: 0xa9059cbb

# Search for known collision pairs (these are rare but exist)
# Example: `collate_propagate_storage(bytes16)` and `burn(uint256)` both hash to 0x42966c68
# Use https://www.4byte.directory/ to check for known collisions
```

### 5. Implementation Takeover

Attacking the implementation contract directly (not through the proxy) can compromise the entire system.

**Uninitialized Implementation**
- If `_disableInitializers()` was not called in the implementation constructor, anyone can call `initialize()` on the implementation contract directly
- The attacker becomes the owner of the implementation contract (not the proxy, but the implementation itself)
- For UUPS: the attacker can now call `upgradeTo()` on the implementation, changing the implementation's internal pointer; this does NOT affect the proxy unless the proxy delegates reads to the implementation for upgrade logic
- For Transparent: the attacker owns the implementation but cannot upgrade the proxy (ProxyAdmin controls that); however, the attacker can selfdestruct the implementation (pre-Dencun)

**Pre-Dencun: Initialize Then Selfdestruct**
- Attack sequence: (1) call `initialize()` on uninitialized implementation to become owner, (2) call `selfdestruct` on the implementation, (3) the proxy now delegatecalls to an empty address, all calls revert, the proxy is bricked
- This permanently destroys the proxy's functionality with no recovery path
- Severity: Critical (permanent DoS on the proxy and all its state)
- Post-Dencun mitigation: selfdestruct no longer clears code, so this attack vector is eliminated on new chains

**Post-Dencun: Attacker Still Owns Implementation**
- Selfdestruct only sends ETH (EIP-6780), does not destroy the contract code or storage
- Attacker still controls the implementation contract after initializing it
- For UUPS: attacker can call `upgradeTo` on the implementation contract directly, changing its internal upgrade pointer; impact depends on whether the proxy reads this pointer
- For Transparent: limited impact since the ProxyAdmin controls upgrades independently
- Severity: Medium to High depending on the proxy pattern

**Beacon Manipulation**
- If the beacon contract's `upgradeTo` is insufficiently protected, attacker changes the implementation for ALL proxies simultaneously
- Beacon ownership is often a single admin address or multisig
- Attack: compromise the beacon owner, call `upgradeTo(maliciousImpl)`, all beacon proxies now execute attacker code
- Check: verify beacon ownership is behind a timelock or multisig, not a single EOA

**UUPS Without _authorizeUpgrade**
- If the implementation has `upgradeTo` but `_authorizeUpgrade` is a no-op or missing, anyone can call `upgradeTo` through the proxy
- The attacker upgrades to a malicious implementation that drains all funds from the proxy's storage
- This is a Critical severity vulnerability: permissionless upgrade = complete protocol takeover
- Check: read the `_authorizeUpgrade` function; it must have an explicit access control check (e.g., `onlyOwner`, `onlyRole(UPGRADER_ROLE)`)

### 6. Upgrade Path Validation

Upgrades must preserve storage layout compatibility. A single misaligned slot corrupts all state in that slot and every slot after it.

**Storage Layout Compatibility: Append-Only Rule**
- New variables MUST be appended after all existing variables from the previous implementation
- No variable can be removed, reordered, or have its type changed
- Slot assignments are deterministic from the declaration order and types
- Verify with OpenZeppelin's upgrade safety checks:
```bash
# Hardhat
npx hardhat run scripts/validate-upgrade.js
# The @openzeppelin/upgrades-core package validates layout compatibility

# Foundry (manual comparison)
forge inspect V1 storage-layout --pretty > v1.txt
forge inspect V2 storage-layout --pretty > v2.txt
diff v1.txt v2.txt
# All v1 entries must appear identically in v2; v2 may have additional entries at the end
```

**Variable Type Changes**
- Changing `uint128` to `uint256` doubles the slot width, pushing all subsequent variables to new slots
- Changing `address` to `uint256` changes from 20-byte to 32-byte packing, shifting layout
- Changing `bool` to `uint8` is safe (same size), but `bool` to `uint256` is not
- Safe changes: renaming a variable (same type, same slot); adding new variables at the end
- Unsafe changes: any type size change, any reordering, any removal

**Mapping and Array Reordering**
- Solidity mappings: the mapping slot stores nothing directly; values are at `keccak256(key . slot)`, so mapping entries do not shift other slots
- However, the mapping's declaration slot itself is sequential; adding a variable before the mapping shifts the mapping's base slot, which changes where ALL its entries live
- Dynamic arrays: length is stored at the declaration slot, elements at `keccak256(slot) + index`; same issue as mappings if the base slot shifts
- Fixed-size arrays: occupy sequential slots; reordering them shifts everything after them

**Inheritance Order Changes**
- Solidity uses C3 linearization to determine the order base contract variables are laid out in storage
- `contract V2 is A, B` and `contract V2 is B, A` produce different slot assignments for A's and B's variables
- Any change in the inheritance list order between versions corrupts storage
- Check: the `is` clause must be identical (or strictly extended at the end) between old and new implementations

**Cross-Version Upgrades: Skipping Versions**
- If V1 -> V2 requires a migration function (reinitializer), and V2 -> V3 requires another migration, upgrading directly from V1 -> V3 may skip V2's migration
- State initialized by V2's migration will be zero/unset in the V3 context
- Check: verify the upgrade path is sequential and each reinitializer version has been executed; use `upgradeToAndCall` to run migrations atomically with upgrades

### 7. Upgrade Access Control

Who controls upgrades determines the trust model of the entire protocol.

**Upgrade Authority Analysis**
| Authority | Risk Level | Notes |
|-----------|-----------|-------|
| Single EOA | Critical | Private key compromise = instant protocol takeover |
| 2-of-3 multisig | High | Social engineering 2 signers = takeover |
| 5-of-9 multisig + timelock | Medium | Timelock gives users time to exit before malicious upgrade |
| Governance vote + timelock | Lower | Transparent process, but governance attacks still possible |
| No upgrade path (immutable) | Lowest | No upgrade risk, but no bug fix capability either |

**Emergency Upgrade Without Timelock**
- Some protocols have a "guardian" role that can upgrade without waiting for the timelock
- This is a backdoor: the guardian can upgrade to a malicious implementation at any time
- Severity depends on who holds the guardian key and whether it is behind a multisig
- Check: verify whether any role can bypass the timelock for upgrades; document the key holders

**Upgrade to Non-Contract Address**
- If `upgradeTo` does not verify that the new implementation has code (`extcodesize > 0`), the proxy can be pointed at an EOA or empty address
- All subsequent delegatecalls return success with empty data (EVM behavior: calls to non-contract addresses succeed)
- This effectively bricks the proxy: all functions return zero/empty/false
- OpenZeppelin's `ERC1967Utils._setImplementation` includes an `extcodesize` check; custom implementations may not
- Check: attempt (in a test) to upgrade to `address(0)` or a fresh EOA; it should revert

**Downgrade Prevention**
- Can the implementation be rolled back to a previous version?
- If yes: can the rollback bypass a migration that the current version depends on?
- Some protocols track an implementation version number and enforce `newVersion > currentVersion`
- UUPS: if the new implementation lacks `upgradeTo`, the proxy is permanently stuck (no further upgrades possible); this can be intentional (finalization) or accidental (bricking)

**Upgrade + State Migration Atomicity**
- `upgradeToAndCall` combines upgrade and initialization in a single transaction, preventing a window where the new implementation is active but not yet initialized
- If upgrade and migration are separate transactions, an attacker can interact with the un-migrated new implementation between the two calls
- Check: all upgrades that require migration must use `upgradeToAndCall`, never a separate `upgradeTo` followed by a manual migration call

## Key Commands

```bash
# Storage layout inspection
forge inspect Contract storage-layout --pretty
forge inspect Contract storage-layout --pretty | grep -E "slot|offset|type"

# Compare layouts between implementations
forge inspect V1Implementation storage-layout --pretty > v1_layout.txt
forge inspect V2Implementation storage-layout --pretty > v2_layout.txt
diff --side-by-side v1_layout.txt v2_layout.txt

# Read EIP-1967 implementation slot on-chain
cast storage {proxy_address} 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url {rpc}

# Read EIP-1967 admin slot on-chain
cast storage {proxy_address} 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103 --rpc-url {rpc}

# Read EIP-1967 beacon slot on-chain
cast storage {proxy_address} 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50 --rpc-url {rpc}

# Get implementation address from proxy
cast call {proxy_address} "implementation()(address)" --rpc-url {rpc}

# Dump function selectors to check for clashes
forge inspect Proxy methodIdentifiers
forge inspect Implementation methodIdentifiers

# Compute a specific function selector
cast sig "upgradeTo(address)"
cast sig "initialize(address)"

# Check if implementation is initialized
cast call {impl_address} "proxiableUUID()(bytes32)" --rpc-url {rpc}

# Verify implementation has code (not EOA)
cast code {impl_address} --rpc-url {rpc}

# Read Diamond facet registry
cast call {diamond_address} "facets()(tuple(address,bytes4[])[])" --rpc-url {rpc}

# Slither upgrade checks
slither . --detect uninitialized-state
slither-check-upgradeability proxy.sol Proxy impl.sol Implementation
```

**Foundry PoC Template: Storage Collision**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract V1 {
    uint256 public value;   // slot 0
    address public owner;   // slot 1

    function initialize(address _owner) external {
        owner = _owner;
    }
}

contract V2Bad {
    address public owner;   // slot 0 -- COLLISION: was uint256 value in V1
    uint256 public value;   // slot 1 -- COLLISION: was address owner in V1
    uint256 public newVar;  // slot 2

    function initialize(address _owner) external {
        owner = _owner;
    }
}

contract StorageCollisionTest is Test {
    function test_storageCollisionCorruptsState() public {
        // Deploy V1 and proxy
        V1 v1Impl = new V1();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(v1Impl),
            abi.encodeCall(V1.initialize, (address(this)))
        );

        // Set value in V1
        V1 v1 = V1(address(proxy));
        // ... interact with v1, set value = 42

        // Upgrade to V2Bad (reordered variables)
        V2Bad v2Impl = new V2Bad();
        // Upgrade the proxy to v2Impl...

        // Now V2Bad.owner reads from slot 0, which contains V1's uint256 value
        // V2Bad.value reads from slot 1, which contains V1's address owner
        // State is silently corrupted
        V2Bad v2 = V2Bad(address(proxy));
        assertNotEq(v2.owner(), address(this)); // owner is now garbage
    }
}
```

**Foundry PoC Template: Implementation Takeover**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract VulnerableImpl is UUPSUpgradeable, OwnableUpgradeable {
    // BUG: no _disableInitializers() in constructor
    function initialize(address _owner) public initializer {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}

contract MaliciousImpl {
    fallback() external payable {
        // Drain all ETH from proxy
        payable(msg.sender).transfer(address(this).balance);
    }
}

contract ImplementationTakeoverTest is Test {
    function test_takeoverUnprotectedImplementation() public {
        // Deploy implementation WITHOUT calling _disableInitializers
        VulnerableImpl impl = new VulnerableImpl();

        // Attacker calls initialize directly on the implementation
        address attacker = makeAddr("attacker");
        vm.prank(attacker);
        impl.initialize(attacker);

        // Attacker is now the owner of the implementation contract
        assertEq(impl.owner(), attacker);

        // For UUPS: attacker can now call upgradeTo on the implementation
        // (This affects the implementation's storage, not the proxy's,
        //  but demonstrates the ownership takeover)
        MaliciousImpl malicious = new MaliciousImpl();
        vm.prank(attacker);
        impl.upgradeToAndCall(address(malicious), "");
    }
}
```

## Validation

- Demonstrate storage collision by upgrading to a reordered-variable implementation and showing corrupted state reads via `cast storage` or Foundry test assertions
- Prove implementation takeover by calling `initialize()` on an unprotected implementation and confirming attacker ownership
- Show selector clash impact by finding two functions with matching 4-byte selectors and demonstrating misrouted calls
- Verify initializer protection by attempting double-initialization and confirming the revert
- Confirm upgrade path safety by comparing storage layouts with `forge inspect` before and after the upgrade
- For Diamond patterns, verify facet storage isolation by writing to a slot in facet A and reading from facet B to prove no overlap
- Document: proxy pattern type, implementation address, admin/owner address, upgrade authority chain, storage layout diff, and concrete impact of any discovered vulnerability
