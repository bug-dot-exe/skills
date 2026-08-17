---
name: web3-bounty
category: web3
description: Web3 bug bounty specifics covering Immunefi/Code4rena submission format, severity criteria for DeFi bugs, PoC requirements, and on-chain evidence collection
depends_on: []
---

# Web3 Bug Bounty Specifics

Guidance for web3 bug bounty submissions on major platforms. Focus on Immunefi and Code4rena submission format, severity criteria for DeFi vulnerabilities, PoC requirements, and on-chain evidence collection.

## When to Use

- Submitting a smart contract vulnerability to Immunefi, Code4rena, Sherlock, or Hats Finance
- Determining severity classification for a DeFi vulnerability
- Building a proof-of-concept for an on-chain exploit
- Collecting on-chain evidence to support a vulnerability report
- Deciding whether a finding meets the threshold for submission

## Methodology

### 1. Platform Submission Formats

**Immunefi**
- Title: concise impact statement, not the mechanism
- Severity: must match Immunefi's severity classification (see section 2)
- Description: vulnerability details, affected code, root cause
- Impact: direct financial impact with quantified USD value where possible
- PoC: required for Critical/High; strongly recommended for Medium
- Fix recommendation: optional but increases credibility
- Scope: must be within the program's listed assets and impact categories

**Code4rena / Sherlock**
- Title: `[SEVERITY]-[N] Description of the impact` (e.g., `[H-01] Attacker can drain pool via flash loan`)
- Summary: 1-2 sentence impact statement
- Vulnerability detail: root cause, code references, attack path
- Impact: quantified where possible; state which impact category from judging criteria
- Code snippet: inline vulnerable code with line references
- PoC: Foundry test preferred; must compile and run against the contest repo
- Recommendation: specific fix with code diff

**Hats Finance**
- Similar to Immunefi but submission via on-chain transaction
- PoC can be in any framework the project uses
- Severity must align with the project's stated impact criteria

### 2. Severity Criteria for DeFi Bugs

**Critical**
- Direct theft of user funds (any amount) without user interaction
- Permanent freezing of user funds above $10K
- Protocol insolvency (liabilities exceed assets)
- Governance takeover enabling treasury drain
- Oracle manipulation leading to >10% price deviation exploitable for profit

**High**
- Theft of unclaimed yield or rewards
- Temporary freezing of funds (>24 hours)
- Manipulation of voting results without governance takeover
- Theft of protocol fees or treasury funds requiring elevated but non-admin role
- Forced liquidation of user positions through price manipulation

**Medium**
- Griefing attacks that cost the attacker more than the victim loses (but victim still loses)
- Temporary DoS of protocol functions (1-24 hours)
- Incorrect fee calculation resulting in minor over/under-charge
- Information disclosure of sensitive protocol parameters
- Broken accounting that does not directly lead to fund loss

**Low/Informational**
- Gas optimization suggestions
- Best practice violations without concrete exploit path
- Theoretical attacks requiring unrealistic conditions
- Missing events or incorrect event parameters
- Code quality issues

### 3. PoC Requirements

**Foundry PoC Structure**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {TargetContract} from "src/TargetContract.sol";

contract ExploitTest is Test {
    TargetContract target;
    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");

    function setUp() public {
        // Deploy or fork
        // Fund accounts
        // Set initial state
    }

    function test_exploit() public {
        // Record state before
        uint256 victimBalanceBefore = token.balanceOf(victim);

        // Execute attack
        vm.startPrank(attacker);
        // ... attack steps ...
        vm.stopPrank();

        // Assert impact
        uint256 victimBalanceAfter = token.balanceOf(victim);
        assertLt(victimBalanceAfter, victimBalanceBefore, "Victim lost funds");
    }
}
```

**PoC Rules**
- Must compile against the contest/bounty repository without external modifications
- Must demonstrate concrete impact (fund loss, state corruption), not just mechanism
- Fork tests for mainnet state: `forge test --fork-url {RPC} --fork-block-number {block}`
- Include setup comments explaining any non-obvious initialization
- Assertions must prove the claimed impact, not just that a function was called

### 4. On-Chain Evidence Collection

**Transaction Analysis**
- Use block explorers (Etherscan, Basescan) to trace relevant transactions
- Identify historical instances of the vulnerable pattern being triggered
- Calculate TVL at risk based on current contract balances
- Check if similar contracts have been exploited before

**State Verification**
```bash
# Read contract state
cast call {contract} "functionName(args)(returnType)" --rpc-url {rpc}

# Check token balances at risk
cast call {token} "balanceOf(address)(uint256)" {contract} --rpc-url {rpc}

# Read storage slots directly
cast storage {contract} {slot} --rpc-url {rpc}

# Trace a transaction
cast run {txHash} --rpc-url {rpc}
```

**Impact Quantification**
- Total value locked in affected contracts
- Number of users with active positions
- Maximum single-transaction extractable value
- Cost of attack (flash loan fees, gas) vs profit

### 5. Submission Pre-Checks

**Before submitting, verify:**
- [ ] Finding is within the program's declared scope (contract addresses, chains)
- [ ] Impact category is listed in the program's accepted impacts
- [ ] PoC compiles and runs against the exact codebase version in scope
- [ ] Attack does not require admin/owner privileges (unless admin abuse is in scope)
- [ ] Finding is not a known issue or previously reported (check project's GitHub issues)
- [ ] Severity matches the platform's classification criteria, not your own assessment
- [ ] Report includes: title, description, impact, PoC, and fix recommendation
- [ ] Financial impact is quantified with current on-chain data

### 6. Common Rejection Reasons

- **Out of scope**: contract or impact type not listed in the program
- **Known issue**: vulnerability documented in project's known issues or audit reports
- **Admin/governance trust assumption**: attack requires trusted actor to be malicious
- **Theoretical only**: no concrete PoC; attack described in prose without demonstration
- **Centralization risk reported as vulnerability**: project accepts the trust assumption
- **No real impact**: mechanism proven but no fund loss, no state corruption, no DoS
- **Duplicate**: same root cause as another submission (first valid report wins)
- **Insufficient severity**: impact does not meet minimum severity threshold for rewards

### 7. Fork Testing for Maximum Impact

**Mainnet fork PoC**
- Fork at specific block to capture current TVL, oracle prices, and pool states
- Demonstrate the exploit against real-world state rather than synthetic test environments
- `forge test --fork-url {RPC_URL} --fork-block-number {block} -vvv`
- Pin the block number for reproducibility -- state changes block-to-block

**Historical exploit reproduction**
- Fork at the block before a known exploit to demonstrate the vulnerability existed before the fix
- Useful for: proving severity when a project disputes impact, showing vulnerability was present in the audit scope

**Multi-chain fork testing**
- For cross-chain protocols: fork both source and destination chains
- Demonstrate the exploit requires coordination across chains with concrete block numbers on each

### 8. Impact Quantification Techniques

**TVL-at-risk calculation**
- Query current contract balances: `cast call {token} "balanceOf(address)(uint256)" {protocol} --rpc-url {rpc}`
- For lending protocols: sum all supplied collateral minus borrowed amounts
- For vaults: `totalAssets()` gives the TVL directly
- Convert to USD using on-chain oracle price at the fork block

**Maximum extractable value (MEV)**
- For flash loan attacks: `profit = extracted_value - flash_loan_fee - gas_cost`
- For oracle manipulation: `profit = position_size * price_deviation - manipulation_cost`
- For reentrancy: `profit = sum_of_stale_state_extractions - gas_cost`

**Profitability threshold**
- If `profit > 0` after gas and fees, the attack is economically viable
- On L2s, gas costs are 10-100x cheaper: attacks unprofitable on L1 may be profitable on L2
- Include flash loan provider fees (typically 0.05-0.09%)

### 9. Web3-Specific Recon for Bounties

**On-chain reconnaissance**
- Read proxy implementation: `cast call {proxy} "implementation()(address)" --rpc-url {rpc}`
- Check owner/admin: `cast call {contract} "owner()(address)" --rpc-url {rpc}`
- Read all public state variables to understand current configuration
- Trace recent transactions to understand actual usage patterns vs theoretical documentation

**Deployment analysis**
- Compare deployed bytecode against source code in the bounty scope to detect discrepancies
- Check if the deployed version matches the audited version: `cast etherscan-source {address}`
- Identify unverified contracts in the protocol's dependency chain

**Previous audit findings**
- Check if the project's prior audits are public (usually linked in docs or GitHub)
- Focus on findings marked "acknowledged" or "won't fix" -- the project accepted the risk but it may still be in scope
- Audit-to-audit deltas: new code added after the last audit is highest-priority attack surface

### 10. Immunefi-Specific Strategies

**Bounty table analysis**
- Many programs tier payouts by impact type and chain
- Direct theft of user funds on mainnet typically pays maximum bounty
- Same vulnerability on testnet or on a paused contract pays nothing
- Check: is the finding on a chain and contract listed in the "assets in scope" table?

**Proof-of-impact over proof-of-concept**
- Immunefi prioritizes demonstrated impact over theoretical analysis
- A PoC that shows "$1M drainable in a single transaction" is stronger than "this function has a reentrancy"
- Include attacker profit calculation in the report: `Attacker invests $X (flash loan), extracts $Y, profit = $Y - $X`

**Program-specific quirks**
- Some programs explicitly exclude "admin key compromise" scenarios
- Some require the attacker to be permissionless (no admin role, no governance)
- Some accept only direct fund loss and exclude DoS/griefing
- Read the full program description and scope before spending time on a PoC

## Validation

- PoC compiles with `forge build` against the exact in-scope codebase
- PoC passes with `forge test --match-test test_exploit -vvv` showing concrete impact
- Fork test against mainnet state demonstrates real-world exploitability
- Impact is quantified with current on-chain balances and token prices
- Profitability calculation includes flash loan fees, gas costs, and MEV
- Severity classification matches the platform's stated criteria
- Report follows the platform's required format exactly
- Finding is confirmed within the program's stated assets and impact types
