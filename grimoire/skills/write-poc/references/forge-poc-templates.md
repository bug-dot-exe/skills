# forge-poc-templates (Immunefi)

Reference for the [forge-poc-templates](https://github.com/immunefi-team/forge-poc-templates/)
library by Immunefi. Provides structured base contracts for building smart contract PoCs with
built-in support for flash loans, reentrancy, price manipulation, balance tracking, and
multi-chain token constants.

## When to Recommend

Recommend forge-poc-templates when the PoC involves any of the following:

- **Flash loans** — the library handles provider callbacks, repayment, and supports Aave (V2/V3),
  Uniswap (V2/V3), Balancer, and MakerDAO out of the box
- **Reentrancy** — provides a state machine and pre-built callbacks for ERC677, ERC777, ERC1363,
  ERC1155, ERC721, and native ETH receive/fallback
- **Price manipulation** — includes Curve pool interaction wrappers and composable flash loan
  chaining
- **Balance/profit tracking** — automatic pre/post balance snapshots with formatted output,
  useful for demonstrating monetary impact
- **Multi-chain fork tests** — ships token address constants for Ethereum, Polygon, Arbitrum,
  Optimism, Avalanche, Fantom, and BSC

Do **not** recommend it when:
- The PoC is a simple unit test against a locally deployed contract with no DeFi interactions
- The vulnerability is pure logic (access control, arithmetic, state machine) with no
  callbacks or flash loans involved
- The project already has its own test framework and adding a dependency would complicate
  reproduction

## Before Writing Code

Before implementing a PoC that uses forge-poc-templates, **study the repository** to understand
the base contracts and their APIs. Key files to read:

- `src/PoC.sol` — base contract with balance snapshotting (`snapshotAndPrint`, `setAlias`)
- `src/flashloan/FlashLoan.sol` — `takeFlashLoan()` and provider enum
- `src/reentrancy/Reentrancy.sol` — state machine and callback dispatch
- `src/pricemanipulation/PriceManipulation.sol` — price oracle manipulation wrapper
- `src/tokens/Tokens.sol` — `deal()` / `dealFrom()` wrappers and per-chain token constants
- `src/log/Log.sol` — structured logging with phase and step tracking

Also review the examples in `test/` and `pocs/` for real usage patterns.

## Installation

Install as a Foundry dependency:

```bash
forge install immunefi-team/forge-poc-templates --no-commit
```

Then add the remapping to `foundry.toml` or `remappings.txt`:

```
forge-poc-templates/=lib/forge-poc-templates/src/
```

## Architecture

The library uses a hook-based architecture. You extend a base contract and implement
hook methods that fire at specific points during the exploit:

| Method | When it fires | Required |
|---|---|---|
| `initiateAttack()` | You define this as the entry point | Yes |
| `_executeAttack()` | Called inside the flash loan / reentrancy callback | Yes |
| `_completeAttack()` | Called after the callback returns | Yes |
| `_reentrancyCallback()` | Called on each reentrant invocation | Only for Reentrancy |

## Base Contracts

### PoC

The root base contract. Extends `Test`, `Tokens`, and `Log`. Use this when you only need
balance tracking without flash loan or reentrancy scaffolding.

```solidity
import "forge-poc-templates/PoC.sol";

contract MyPoC is PoC {
    function initiateAttack() external {
        // ...
    }
}
```

Key methods:
- `snapshotAndPrint(address user, IERC20[] tokens)` — capture and log balances
- `setAlias(address addr, string name)` — label addresses for readable output
- `deal(IERC20 token, address to, uint256 amount)` — set token balances

### FlashLoan

Manages multi-provider flash loan execution with automatic repayment.

```solidity
import "forge-poc-templates/flashloan/FlashLoan.sol";
import "forge-poc-templates/tokens/Tokens.sol";

contract MyFlashLoanPoC is FlashLoan, Tokens {
    function initiateAttack() external {
        takeFlashLoan(FlashLoanProviders.AAVE_V3, IERC20(token), amount);
    }

    function _executeAttack() internal override {
        // runs inside the flash loan callback — funds are available here
    }

    function _completeAttack() internal override {
        // runs after repayment
    }
}
```

**Supported providers:** `AAVE_V2`, `AAVE_V3`, `UNISWAPV2`, `UNISWAPV3`, `BALANCER`,
`MAKERDAO`.

Chaining: call `takeFlashLoan()` again inside `_executeAttack()` to chain providers.
Use `currentFlashLoanProvider()` to branch on which provider is active.

### Reentrancy

State machine with callback dispatch. Implements receiver interfaces for all common
token standards so the contract automatically accepts callbacks.

```solidity
import "forge-poc-templates/reentrancy/Reentrancy.sol";

contract MyReentrancyPoC is Reentrancy {
    function initiateAttack() external {
        // trigger the vulnerable function
    }

    function _executeAttack() internal override {
        // first invocation logic
    }

    function _completeAttack() internal override {
        // post-attack verification
    }

    function _reentrancyCallback() internal override {
        // fires on each reentrant callback — implement the re-entry loop here
    }
}
```

Callbacks handled automatically: `onTokenTransfer` (ERC677), `onTransferReceived` (ERC1363),
`tokensReceived` (ERC777), `onERC721Received`, `onERC1155Received`, `receive()`/`fallback()`.

### PriceManipulation

Extends Reentrancy. Use when the exploit involves manipulating an on-chain price oracle
(e.g. Curve read-only reentrancy).

```solidity
import "forge-poc-templates/pricemanipulation/PriceManipulation.sol";

contract MyPricePoC is PriceManipulation {
    function initiateAttack() external {
        manipulatePrice(
            PriceManipulationProviders.CURVE,
            token0, token1, amount0, amount1
        );
    }

    function _executeAttack() internal override { }
    function _completeAttack() internal override { }
}
```

## Utilities

### Token Constants

Import per-chain token addresses to avoid hardcoding:

```solidity
import "forge-poc-templates/tokens/Tokens.sol";

// Use as: EthereumTokens.WETH, EthereumTokens.USDC, etc.
// Also: PolygonTokens, ArbitrumTokens, OptimismTokens, AvalancheTokens, ...
```

### Oracle Mocks

Mock contracts for oracle-dependent tests:

- `MockChainLink` — mock Chainlink Feed Registry with `mockOracleData()`
- `MockPyth` — mock Pyth oracle with price feed constants
- `MockBand` — mock Band oracle with symbol-based pairs

### Logging

Structured logging with phase tracking:

```solidity
_setPhase(LogPhase.EXECUTE_ATTACK);
_log("Draining pool");
_logInt("Profit", profit);
```

### Malicious Contract Mocks

Pre-built adversarial contracts in `src/mocks/`:
- `gasExhaust.sol` — consumes all gas
- `returnBomb.sol` — returns massive data to cause OOG on the caller
- `self-destruct.sol` — self-destructing contract

## Typical Test Harness

The PoC contract is usually deployed from a standard Foundry test:

```solidity
contract ExploitTest is Test {
    function setUp() public {
        vm.createSelectFork(vm.envString("ETH_RPC_URL"), BLOCK_NUMBER);
    }

    function test_exploit() public {
        MyFlashLoanPoC exploit = new MyFlashLoanPoC();

        // snapshot balances
        IERC20[] memory tokens = new IERC20[](1);
        tokens[0] = IERC20(EthereumTokens.WETH);
        exploit.snapshotAndPrint(address(exploit), tokens);

        // execute
        exploit.initiateAttack();

        // print profit
        exploit.snapshotAndPrint(address(exploit), tokens);
    }
}
```
