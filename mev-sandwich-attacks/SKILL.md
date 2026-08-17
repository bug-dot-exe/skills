---
name: mev-sandwich-attacks
category: web3
description: MEV and sandwich attack analysis covering sandwich mechanics on swaps and liquidity operations, JIT liquidity extraction, block stuffing for deadline manipulation, transaction ordering dependence, oracle update frontrunning, commit-reveal bypass, and protocol-level MEV mitigation assessment
depends_on: []
---

# MEV and Sandwich Attack Analysis

Security testing for Maximal Extractable Value (MEV) vulnerabilities in DeFi protocols. Focus on sandwich attack mechanics, slippage and deadline protection gaps, JIT liquidity extraction, block stuffing, oracle update frontrunning, transaction ordering dependence, commit-reveal bypass, and protocol-level MEV mitigation assessment.

## When to Use

- Protocol executes swaps through AMMs (Uniswap, Curve, Balancer, or custom pools)
- Any function performs a token exchange where output amount depends on pool state
- Protocol adds or removes liquidity from AMM pools
- Time-sensitive operations exist (auctions, governance votes, option expiry, liquidations)
- Protocol reads on-chain oracle prices that update via public transactions
- Commit-reveal schemes are used for randomness, bidding, or ordering
- First-come-first-served mechanisms exist (mints, sales, liquidation bonuses)
- Protocol is deployed on L2 with sequencer-dependent transaction ordering

## Methodology

### 1. Sandwich Attack Mechanics

A sandwich attack wraps a victim transaction between two attacker transactions within the same block:

- **Front-run**: attacker buys the target token before the victim's large buy, pushing the price up against the victim
- **Victim execution**: victim's swap executes at a worse price than expected due to the attacker's front-run moving the pool state
- **Back-run**: attacker sells the target token immediately after the victim's swap, capturing the price difference as profit
- **Profitability factors**: swap size relative to pool liquidity depth, victim's slippage tolerance setting, gas priority fee required to position before and after the victim
- **Attack cost**: gas priority fee (tip) paid to the block builder to guarantee transaction ordering; must be less than extracted profit
- **Multi-hop amplification**: swaps routed through multiple pools are sandwichable at each hop, compounding price impact
- **Liquidity operation sandwiching**: adding or removing liquidity changes pool ratios; large liquidity events are sandwichable just like swaps
- Detection: any swap function where `amountOutMin` is zero, absent, hardcoded, or not enforced on-chain is fully sandwichable
- Trace: identify every function that calls an external swap router or pool; verify each has caller-supplied and on-chain-enforced minimum output

### 2. Slippage and Deadline Protection

Slippage and deadline parameters are the primary on-chain defense against sandwich attacks. Audit every swap-like operation for both:

**Slippage protection failures**:
- **Missing slippage**: `amountOutMin` parameter is absent or unused; attacker extracts arbitrary value
- **Zero slippage**: `amountOutMin = 0` passed to the swap router; equivalent to no protection
- **Hardcoded slippage**: protocol sets a fixed percentage (e.g., 1%) instead of allowing user configuration; may be too loose in volatile markets or too tight in stable markets
- **Slippage on wrong value**: slippage checked against intermediate amount rather than final received amount
- **Partial-fill gap**: multi-hop swap where the outer call has slippage but intermediate hops do not; attacker sandwiches at an unprotected intermediate step
- **Off-chain slippage only**: slippage computed on the frontend but not enforced by the smart contract; attacker bypasses by calling the contract directly

**Deadline protection failures**:
- **Missing deadline**: no `block.timestamp` check; transaction can sit in the mempool indefinitely and execute at any future time when pool state favors the attacker
- **Ignored deadline**: deadline parameter accepted but never checked against `block.timestamp`
- **Hardcoded deadline**: deadline set to `type(uint256).max` or `block.timestamp + 0` (current block), defeating the purpose
- **Deadline in wrong scope**: outer function checks deadline but the inner swap call does not pass it through

**Detection pattern**:
```bash
# Find swap-like function calls
grep -rn "swap\|swapExact\|exchange\|amountOutMin\|minAmountOut\|minOut\|getAmountOut" contracts/

# Find missing slippage parameters
grep -rn "amountOutMin.*=.*0\|minAmountOut.*=.*0\|, 0," contracts/ | grep -i swap

# Find missing deadline checks
grep -rn "block.timestamp\|deadline" contracts/ | grep -i swap

# Find hardcoded deadline
grep -rn "type(uint256).max\|uint256(-1)\|0xffffffff" contracts/ | grep -i deadline
```

### 3. JIT (Just-In-Time) Liquidity

JIT liquidity is an MEV strategy targeting passive liquidity providers:

- **Mechanism**: MEV bot monitors the mempool, sees a large pending swap, adds a tight range of concentrated liquidity just before the swap, captures trading fees from the swap, then removes the liquidity immediately after
- **Victim**: passive LPs who earn fewer fees because the JIT bot captured the fee from the large swap without bearing any long-term impermanent loss
- **Risk-free extraction**: the JIT position is open for a single block; there is no price risk because the bot knows the exact trade that will hit the pool
- **Concentrated liquidity amplification**: protocols using concentrated liquidity (Uniswap V3-style) are more vulnerable because JIT bots can place extremely narrow ranges around the expected price
- **Protocol-level mitigation assessment**:
  - Does the protocol impose a minimum liquidity lock period (prevents single-block add/remove)?
  - Does fee accrual require time-weighted participation (fees vest over time, not instantly)?
  - Are there withdrawal fees or cooldown periods for liquidity positions?
  - Does the protocol use a fee distribution mechanism that resists single-block sniping?
- Detection: check if `mint` and `burn` (or equivalent add/remove liquidity) can execute in the same block with no penalty

### 4. Block Stuffing

Block stuffing is an MEV attack where the attacker fills blocks with high-gas transactions to delay or prevent time-sensitive operations:

- **Mechanism**: attacker submits many transactions consuming all available block gas, preventing the victim's transaction from being included
- **Targets**: auction endings (Fomo3D attack), governance vote deadlines, option expiry, liquidation windows, oracle update submissions
- **Fomo3D precedent**: attacker stuffed blocks with high-gas transactions to become the last player in the round, winning the pot
- **Cost**: gas for filling blocks; expensive on L1 Ethereum (multi-ETH per block), cheaper on some L2s or sidechains
- **Duration**: attacker must stuff blocks for the entire sensitive window; longer windows are more expensive to attack
- **Protocol-level mitigation assessment**:
  - Does any operation have a single-block execution window? (highly vulnerable)
  - Are time-sensitive operations gated on `block.timestamp` ranges rather than exact blocks?
  - Can execution windows span multiple blocks to increase attack cost?
  - Is `block.number` used instead of `block.timestamp` for time boundaries (more predictable)?
  - Are there keeper/bot incentives to submit time-sensitive transactions with high priority fees?
- Detection: identify all operations with deadlines; check if the deadline window is long enough to survive block stuffing

### 5. Oracle Update Frontrunning

Oracle price updates are visible in the mempool before inclusion, creating frontrunning opportunities:

- **Price update frontrunning**: Chainlink or other oracle keeper submits a price update; MEV bot sees the new price in the mempool, front-runs trades based on the price difference between old and new values
- **Example**: ETH price drops 5% in the pending oracle update; bot shorts or liquidates positions at the old (higher) price before the update is mined
- **Liquidation frontrunning**: large price move makes positions liquidatable; MEV bots race to call `liquidate()` first to capture the liquidation bonus
- **Oracle sandwich**: front-run the oracle update with a position change, let the update execute, back-run to close the position at a profit
- **Multi-oracle arbitrage**: protocol uses oracle A; attacker sees oracle B's update first and trades on the price discrepancy before oracle A updates
- **Protocol-level mitigation assessment**:
  - Does the protocol use the previous block's oracle price instead of the current one?
  - Is there a commit-reveal or time-lock on oracle-dependent actions?
  - Are liquidation bonuses set low enough that frontrunning is marginally profitable (reducing MEV incentive)?
  - Does the protocol batch oracle-dependent operations to reduce per-transaction extractable value?
  - Are oracle updates submitted through private mempools (Flashbots Protect) to prevent observation?
- Detection: find all code paths that read an oracle value and execute a value-changing operation in the same transaction

```bash
# Find oracle read points
grep -rn "latestRoundData\|latestAnswer\|getPrice\|consult\|observe\|slot0" contracts/

# Find liquidation functions
grep -rn "liquidat\|liqudate\|seize\|closePosition" contracts/

# Check if oracle read and action are in the same function
grep -rn "latestRoundData" contracts/ -l | xargs grep -l "transfer\|swap\|mint\|burn"
```

### 6. Transaction Ordering Dependence

Any operation where the outcome depends on transaction position within a block is vulnerable to MEV extraction:

**First-come-first-served mechanisms**:
- NFT mints with no commit-reveal: bots monitor the mempool and front-run public mint calls
- Token sales (ICO, IDO): large buy orders front-run by bots extracting favorable allocation
- Liquidation bonus races: multiple liquidators compete; the first to execute captures the bonus
- Arbitrage: price differences between pools are captured by the first transaction

**Approval front-running**:
- `approve(spender, N)` followed by `approve(spender, M)`: attacker front-runs the second approval to spend N, then spends M after the new approval is set
- Total extraction: N + M instead of the intended M
- Mitigation check: does the token use `increaseAllowance`/`decreaseAllowance` or require reset to 0 before setting a new value?

**Commit-reveal weakness**:
- Weak commitment: hash of the committed value is predictable (e.g., `keccak256(abi.encode(value))` with small value space)
- Reveal predictability: if the committed value can be brute-forced from the commitment hash, the attacker reveals before the user
- Missing binding: commitment does not bind to `msg.sender`, allowing an attacker to copy and submit another user's commitment
- Timing gap: insufficient delay between commit and reveal phases allows same-block commit-reveal

**Permit front-running**:
- User signs an ERC-2612 permit off-chain; attacker observes the signature in a pending transaction
- Attacker calls `permit()` with the user's signature first, then calls `transferFrom()` before the user's intended transaction executes
- This does not steal tokens directly (the permit was intended) but can grief the user's transaction by making it revert (nonce already used)

**Detection pattern**:
```bash
# Find ordering-dependent patterns
grep -rn "approve\|increaseAllowance\|decreaseAllowance" contracts/

# Find commit-reveal schemes
grep -rn "commit\|reveal\|keccak256.*abi.encode" contracts/

# Find first-come mechanisms
grep -rn "firstCome\|claimed\[.*\]\|minted\[.*\]" contracts/

# Find permit usage
grep -rn "permit\|DOMAIN_SEPARATOR\|PERMIT_TYPEHASH\|nonces" contracts/
```

### 7. Protocol-Level MEV Assessment

For any DeFi protocol, systematically answer these questions to map the full MEV attack surface:

**Sandwich vectors**:
- Does ANY function benefit from specific transaction ordering? (sandwich attack)
- Are there swap-like operations? Do ALL of them accept and enforce `amountOutMin` and `deadline`?
- Can liquidity be added and removed in the same block without penalty? (JIT vector)

**Flash loan and oracle vectors**:
- Does ANY function read a value that can be manipulated within the same block? (spot price, pool balance, token balance)
- Does the protocol use atomic composability with external pools that are manipulable via flash loans?
- Are oracle prices consumed in the same transaction they can be influenced?

**Block stuffing vectors**:
- Does ANY time-sensitive operation have a single-block or narrow execution window?
- Can an attacker benefit from delaying a specific transaction by one or more blocks?
- Are keeper operations critical to protocol health (liquidations, rebalancing, oracle updates)?

**Information leakage vectors**:
- Does ANY state change reveal information that benefits from front-running? (oracle update, large order, governance proposal)
- Are there pending state transitions visible on-chain before they execute? (timelocks, queued actions)

**Mitigation checklist**:
- Slippage parameters on ALL swap-like operations
- Deadline parameters on ALL time-sensitive operations
- Commit-reveal with strong bindings (sender, nonce, chainId) for ordering-sensitive operations
- Private mempool compatibility (Flashbots Protect, MEV Blocker, MEV Share) for sensitive user operations
- Multi-block execution windows for time-critical operations
- Fee vesting or liquidity lock periods to counter JIT extraction

### 8. MEV on L2s

MEV properties differ significantly across L2 architectures:

**Sequencer centralization**:
- L2 sequencers have unilateral transaction ordering control; MEV extraction is more centralized
- A malicious or compromised sequencer can sandwich every transaction without competition
- Sequencer censorship: the sequencer can delay or exclude specific transactions

**Chain-specific MEV properties**:
- **Arbitrum**: uses First-Come-First-Served (FCFS) ordering; less MEV from reordering, but sequencer can still front-run and the time-boost mechanism introduces priority ordering
- **Optimism/Base**: use Priority Gas Auction (PGA)-style ordering with sequencer priority; MEV extraction is similar to L1 but with the sequencer as gatekeeper
- **zkSync**: sequencer ordering with limited public mempool visibility; MEV is sequencer-extracted rather than searcher-extracted
- **Shared sequencing**: emerging protocols (Espresso, Astria) aim to decentralize sequencing; MEV properties will shift toward L1-like competitive extraction

**MEV redistribution mechanisms**:
- **MEV Share**: users receive a portion of MEV extracted from their transactions
- **Order Flow Auctions (OFA)**: user order flow is auctioned to searchers who compete on price improvement rather than extraction
- **MEV Blocker**: transaction protection service routing through private channels
- **Threshold encryption**: encrypt transactions until block ordering is committed; prevents observation-based MEV

**L2-specific assessment**:
- What sequencer does the target L2 use? Is ordering FCFS, PGA, or custom?
- Is the sequencer decentralized or a single operator?
- Does the protocol recommend or integrate with MEV protection services?
- Are there forced-inclusion mechanisms (L1 escape hatch) that bypass the sequencer?

## Key Commands

```bash
# Foundry: check if a swap function enforces slippage
cast call {router} "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)" \
  {amountIn} 0 "[{tokenA},{tokenB}]" {to} {deadline}

# Check pool reserves for sandwich profitability estimation
cast call {pool} "getReserves()(uint112,uint112,uint32)"

# Check oracle price and round data for frontrunning analysis
cast call {oracle} "latestRoundData()(uint80,int256,uint256,uint256,uint80)"

# Check Uniswap V3 pool state
cast call {pool} "slot0()(uint160,int24,uint16,uint16,uint16,uint8,bool)"

# Check if liquidity can be added/removed in same block
cast call {pool} "positions(bytes32)(uint128,uint256,uint256,uint128,uint128)" {positionKey}

# Simulate sandwich profitability with Foundry
forge test --match-test testSandwich -vvvv --fork-url {RPC_URL}
```

```solidity
// Foundry PoC template: demonstrate sandwich attack on unprotected swap
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IRouter {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

contract SandwichTest is Test {
    IRouter router = IRouter(ROUTER_ADDRESS);
    IERC20 tokenIn = IERC20(TOKEN_IN_ADDRESS);
    IERC20 tokenOut = IERC20(TOKEN_OUT_ADDRESS);

    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");

    function testSandwichOnZeroSlippage() public {
        // Setup: fund attacker and victim
        deal(address(tokenIn), attacker, 100 ether);
        deal(address(tokenIn), victim, 10 ether);

        address[] memory path = new address[](2);
        path[0] = address(tokenIn);
        path[1] = address(tokenOut);

        // Step 1: Front-run — attacker buys tokenOut before victim
        vm.startPrank(attacker);
        tokenIn.approve(address(router), type(uint256).max);
        uint256 attackerTokenOutBefore = tokenOut.balanceOf(attacker);
        router.swapExactTokensForTokens(50 ether, 0, path, attacker, block.timestamp);
        vm.stopPrank();

        // Step 2: Victim swap executes at worse price (amountOutMin = 0)
        vm.startPrank(victim);
        tokenIn.approve(address(router), type(uint256).max);
        uint256 victimTokenOutBefore = tokenOut.balanceOf(victim);
        router.swapExactTokensForTokens(10 ether, 0, path, victim, block.timestamp);
        uint256 victimReceived = tokenOut.balanceOf(victim) - victimTokenOutBefore;
        vm.stopPrank();

        // Step 3: Back-run — attacker sells tokenOut
        address[] memory reversePath = new address[](2);
        reversePath[0] = address(tokenOut);
        reversePath[1] = address(tokenIn);

        vm.startPrank(attacker);
        tokenOut.approve(address(router), type(uint256).max);
        uint256 attackerTokenInBefore = tokenIn.balanceOf(attacker);
        uint256 attackerTokenOutGained = tokenOut.balanceOf(attacker) - attackerTokenOutBefore;
        router.swapExactTokensForTokens(attackerTokenOutGained, 0, reversePath, attacker, block.timestamp);
        uint256 attackerProfit = tokenIn.balanceOf(attacker) - attackerTokenInBefore;
        vm.stopPrank();

        // Verify: attacker profited, victim received less than fair price
        assertGt(attackerProfit, 50 ether, "Attacker should profit from sandwich");
        // Compare victim's received amount to what they would get without the sandwich
        // (would need a separate call to estimate fair output)
        emit log_named_uint("Attacker profit (tokenIn)", attackerProfit - 50 ether);
        emit log_named_uint("Victim received (tokenOut)", victimReceived);
    }
}
```

```solidity
// Foundry PoC template: demonstrate missing deadline allows delayed execution
contract DeadlineTest is Test {
    function testMissingDeadlineExploitation() public {
        // Victim submits swap with no deadline
        // Simulate passage of time where pool price moves against victim
        vm.warp(block.timestamp + 1 days);

        // Victim's transaction executes at a much worse price
        // because the pool state changed significantly since submission
        // and there was no deadline to reject the stale transaction

        // Assert: victim receives significantly less than expected at submission time
    }
}
```

## Validation

- Demonstrate sandwich attack with a Foundry fork test: show attacker profit and victim loss from a zero-slippage swap by executing the front-run, victim swap, and back-run in sequence within the same block
- Prove missing slippage by calling the swap function with `amountOutMin = 0` and showing the contract accepts it without revert
- Prove missing deadline by showing a swap transaction succeeds when executed at `block.timestamp + 1 days` or later
- Demonstrate JIT liquidity extraction by adding concentrated liquidity, executing a swap, and removing liquidity in a three-transaction sequence within one block, showing fee capture
- Show oracle frontrunning by executing a trade before an oracle update and profiting from the price change
- Confirm transaction ordering dependence by showing different outcomes (e.g., different NFT allocation, different liquidation bonus capture) based solely on transaction position within a block
- Quantify MEV: report extracted value in token amounts, percentage of victim's swap value lost, and gas cost vs profit ratio for the attacker
- Document the complete transaction sequence, pool states before and after each step, and net profit or loss for all parties
