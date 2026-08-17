---
name: erc4626-vault-security
category: web3
description: ERC4626 tokenized vault security covering first depositor inflation attack, share calculation rounding direction, virtual shares/assets offset, deposit/withdrawal asymmetry, maxDeposit/maxMint compliance, compound vault composition risks, and donation attack vectors
depends_on: []
---

# ERC4626 Tokenized Vault Security

Security testing for ERC4626 vaults and share-based deposit/withdrawal systems. Focus on inflation attacks, rounding direction compliance, virtual offset effectiveness, deposit/withdrawal asymmetry, limit function compliance, donation vectors, and compound vault composition risks.

## When to Use

- Protocol implements ERC4626 tokenized vault standard
- Any vault with share-based deposit/withdrawal (even non-ERC4626)
- Yield aggregators, auto-compounders, liquid staking wrappers
- Lending protocols with supply/borrow share tokens

## Methodology

### 1. First Depositor / Inflation Attack

The classic vault attack: attacker deposits 1 wei, donates a large amount directly to the vault, and the next depositor gets 0 shares due to rounding.

**Attack sequence step by step:**
1. Attacker deposits 1 wei, gets 1 share (totalSupply=1, totalAssets=1)
2. Attacker sends 10,000 tokens directly to vault contract (donation, not deposit)
3. Now totalSupply=1, totalAssets=10,001
4. Victim deposits 9,999 tokens, shares = 9999 * 1 / 10001 = 0 (rounds to zero)
5. Attacker redeems 1 share, gets all 20,000 tokens

**Detection:**
- Check for virtual shares/assets offset in `_decimalsOffset()` returning non-zero
- Look for minimum deposit requirements or initial dead shares minted in constructor
- ERC4626 mitigation: override `_decimalsOffset()` to return non-zero (e.g., 3 for 1e3 virtual shares)
- Alternative mitigations: mint initial shares to dead address, enforce minimum first deposit
- If none of the above are present, the vault is vulnerable to this attack

**Cost analysis:** the attacker loses the donated amount minus what they recover via share redemption. For low-decimal tokens (USDC with 6 decimals), the attack is cheaper to execute than for 18-decimal tokens.

### 2. Rounding Direction Compliance

ERC4626 spec REQUIRES specific rounding directions per function:

| Function | Required Rounding | Rationale |
|----------|-------------------|-----------|
| `convertToShares` | DOWN | Caller gets fewer shares |
| `convertToAssets` | DOWN | Caller told fewer assets redeemable |
| `previewDeposit` | DOWN shares | Conservative for depositor |
| `previewMint` | UP assets required | Conservative for minter |
| `previewWithdraw` | UP shares burned | Conservative for withdrawer |
| `previewRedeem` | DOWN assets returned | Conservative for redeemer |

**The rule:** round AGAINST the caller in all cases (vault always benefits from rounding).

**Detection:**
- Check `mulDiv` vs `mulDivUp` usage in each preview/convert function
- Common bug: using same rounding direction for both deposit and withdrawal paths
- Impact: incorrect rounding allows extraction of vault value through repeated small operations
- Watch for custom math libraries that use floor division by default without explicit rounding control
- Verify `deposit` and `mint` use different rounding than `withdraw` and `redeem` in the internal implementation

### 3. Virtual Shares and Assets

`_decimalsOffset()` adds virtual shares/assets to denominators, preventing inflation.

**How it works:**
- With offset=3, virtual shares=1000, virtual assets=1
- Donation of D tokens only inflates exchange rate by D/(1+D) instead of D/1
- Rule of thumb: offset should be >= (token decimals - vault decimals) or at minimum 3

**Detection:**
- Is `_decimalsOffset()` overridden? What value does it return?
- Is the offset sufficient for the underlying token's decimals?
- Gotcha: virtual offset changes the initial exchange rate -- verify this is acceptable for integrators
- If offset is 0 (default), the vault has NO virtual share protection
- Verify the offset value works correctly with the actual token: USDC (6 decimals) needs different offset considerations than WETH (18 decimals)

**Formulas with virtual offset applied:**
- shares = assets * (totalSupply + 10^offset) / (totalAssets + 1)
- assets = shares * (totalAssets + 1) / (totalSupply + 10^offset)

### 4. Deposit/Withdrawal Asymmetry

Different code paths for deposit vs withdrawal can create arbitrage opportunities.

**Checks:**
- Does `deposit(assets)` followed by `redeem(shares)` return exactly `assets`? (should return <= assets)
- Does `mint(shares)` followed by `withdraw(assets)` burn the same shares?
- Fee handling: are fees applied symmetrically? Entry fee + exit fee or just one?
- Timing: if vault accrues value between deposit and withdraw, is the accrual correctly attributed?
- Detection: trace a round-trip (deposit then immediate redeem) with concrete numbers

**Common asymmetry bugs:**
- `deposit` uses `mulDiv` floor but `withdraw` also uses floor (should use ceil for withdraw)
- Fee-on-transfer tokens: deposit path receives fewer tokens than expected but mints shares based on input amount
- Rebasing tokens: `totalAssets()` changes between deposit and redeem without share adjustment

### 5. maxDeposit / maxMint / maxWithdraw / maxRedeem Compliance

ERC4626 requires these functions to return accurate limits, not revert.

**Detection:**
- Does `maxDeposit` return `type(uint256).max` when there IS a cap? Bug.
- If the vault has a cap, these functions must reflect it accurately
- Do these functions revert instead of returning 0 when deposits are paused? (should return 0, not revert)
- Impact: integrating protocols may allow deposits that exceed the vault's capacity or break when functions revert unexpectedly

### 6. Donation Attacks (Beyond First Depositor)

Direct token transfer to vault inflates `totalAssets()` without minting shares.

**Impact depends on how `totalAssets()` is calculated:**
- If `balanceOf(address(this))`: donation directly inflates it (DANGEROUS)
- If tracked via internal accounting: donation has no effect (SAFE)

**Detection:** does `totalAssets()` use `balanceOf` or internal bookkeeping?

**Attack variants:**
- **Sandwich donation**: donate before victim's deposit to inflate share price, redeem after
- **Reward manipulation**: donate to inflate rewards calculation, claim excess
- **Oracle manipulation**: if vault share price is used as oracle, donation manipulates it
- **Grief donation**: donate small amounts repeatedly to prevent share minting for dust depositors

**Mitigation patterns:**
- Internal accounting variable tracking all deposited assets separately from `balanceOf`
- Sweep function that moves excess balance (donations) to a separate location
- Time-weighted share price that resists single-block manipulation

### 7. Compound Vault Composition

Vault of vaults: outer vault holds shares of inner vault.

**Risks:**
- Inner vault's share price manipulation affects outer vault
- Reentrancy: inner vault's deposit/withdraw may callback to outer vault
- Share price cascading: rounding errors compound across vault layers
- Liquidation risk: if inner vault depegs, outer vault becomes undercollateralized

**Detection:** trace the full asset chain from outer vault to underlying assets. Verify each layer handles rounding correctly and cannot be manipulated independently.

**Specific checks:**
- Does the outer vault call `previewDeposit` on the inner vault, or does it use actual deposit return values?
- Can an attacker manipulate the inner vault's share price to affect the outer vault's accounting?
- Are there reentrancy guards across the vault boundary? Inner vault hooks may re-enter outer vault.
- Does the outer vault properly handle the case where the inner vault is paused or migrated?

### 8. ERC4626 Compliance Gaps

Many implementations claim ERC4626 but don't fully comply.

**Common gaps:**
- `deposit` and `mint` should return the exact shares/assets, not estimates
- `withdraw` and `redeem` should allow `msg.sender != owner` if approved via allowance
- Functions should not revert for view queries with amounts of 0
- `totalAssets` should include unrealized gains/losses, not just deposited principal
- `decimals()` should return the underlying asset's decimals (or offset-adjusted), not hardcoded 18
- Share transfers (ERC20 `transfer`/`transferFrom`) should work correctly since vault shares are ERC20 tokens

**Detection:** test each function against the ERC4626 spec's MUST/SHOULD requirements.
**Impact:** non-compliant vaults break composability with integrating protocols that rely on standard behavior.

**Integration risk:** protocols building on top of ERC4626 vaults (lending markets accepting vault shares as collateral, aggregators routing deposits) may calculate incorrect amounts if the vault deviates from the spec. This can lead to bad debt in lending markets or lost funds in aggregators.

## Key Detection Commands

```bash
# Find ERC4626 implementations
grep -rn "ERC4626\|IERC4626\|convertToShares\|convertToAssets" contracts/ --include="*.sol"

# Find totalAssets calculation
grep -rn "totalAssets\|balanceOf(address(this))" contracts/ --include="*.sol"

# Find rounding in share calculations
grep -rn "mulDiv\|mulDivUp\|Math.Rounding" contracts/ --include="*.sol"

# Find virtual offset
grep -rn "_decimalsOffset\|virtualAssets\|virtualShares" contracts/ --include="*.sol"

# Find deposit/withdrawal limits
grep -rn "maxDeposit\|maxMint\|maxWithdraw\|maxRedeem" contracts/ --include="*.sol"
```

## Foundry PoC Template

```solidity
function test_inflationAttack() public {
    // Step 1: Attacker deposits 1 wei
    vm.startPrank(attacker);
    asset.approve(address(vault), type(uint256).max);
    uint256 shares = vault.deposit(1, attacker);

    // Step 2: Donate large amount directly
    asset.transfer(address(vault), 10_000e18);

    // Step 3: Victim deposits
    vm.startPrank(victim);
    asset.approve(address(vault), type(uint256).max);
    uint256 victimShares = vault.deposit(9_999e18, victim);

    // Assert: victim got 0 shares (or very few)
    assertEq(victimShares, 0, "Inflation attack: victim gets no shares");
    vm.stopPrank();
}
```

### 9. Vault Reentrancy via Token Callbacks

**ERC-777 reentrancy during deposit/withdraw**
- Vault deposits/withdraws tokens using `transferFrom`; if the token is ERC-777, the sender/receiver hook fires mid-operation
- Attacker's hook reenters the vault before state (share balance, totalAssets) is updated
- Detection: does the vault use `ReentrancyGuard` on `deposit`, `withdraw`, `mint`, `redeem`?

**ERC-721/1155 vault callback**
- NFT-based vaults using `safeTransferFrom` trigger `onERC721Received` / `onERC1155Received`
- The callback executes before the vault's state update completes
- Detection: is there a reentrancy guard on NFT deposit/withdrawal paths?

**Cross-function reentrancy in vaults**
- Token callback reenters a DIFFERENT vault function that reads stale `totalAssets` or `totalSupply`
- Example: deposit callback reenters `convertToShares` which returns a stale exchange rate
- Detection: do ALL vault functions sharing state (not just deposit/withdraw) use the same reentrancy guard?

### 10. Vault Accounting Under Extreme Conditions

**Zero totalSupply edge case**
- First deposit after all shares are redeemed: if `totalSupply == 0` but `totalAssets > 0` (dust remains), the first new depositor gets shares at an inflated rate
- Detection: what happens when the last user redeems all shares? Is remaining dust recoverable?

**totalAssets underflow**
- If a strategy reports a loss, `totalAssets` can decrease below the virtual offset baseline
- This can cause `convertToShares` to revert (division by zero or underflow) or return extremely inflated shares
- Detection: does `totalAssets()` have a floor? Can a strategy loss create a revert in core vault functions?

**Maximum value overflow**
- Deposits of `type(uint256).max - 1` combined with virtual offset can overflow the numerator in share calculations
- Detection: does the vault use safe math for `assets * (totalSupply + offset)`? What is the maximum safe deposit?

**Multi-token vault desync**
- Vaults accepting multiple tokens (multi-asset vaults, LP token vaults) must maintain consistent accounting across all assets
- If one asset appreciates/depreciates independently, the share price may not reflect the true weighted value
- Detection: how does the vault handle multi-token pricing? Are all assets valued at the same oracle update frequency?

### 11. Vault Integration Risks

**Vault shares as collateral in lending**
- Lending protocol accepts vault shares as collateral; vault's exchange rate becomes the collateral's price
- Donation attack on the vault inflates share price, allowing over-borrowing against inflated collateral
- Detection: does the lending protocol use the vault's `convertToAssets` or an independent oracle for collateral pricing?

**Flash deposit-borrow-withdraw cycle**
- Attacker flash-deposits into vault, uses minted shares as collateral to borrow, withdraws from vault
- If the vault does not enforce a deposit-to-withdrawal delay, the cycle completes atomically
- Detection: is there a deposit lock period? Can shares be used as collateral in the same block they are minted?

**Vault migration during active positions**
- When a vault migrates to a new strategy or implementation, users with active positions (locked shares, collateral) may be affected
- Share token address changes if a new vault is deployed, stranding shares locked in other protocols
- Detection: does the migration path handle all integrations that hold vault shares?

## Validation

- Demonstrate inflation attack with concrete token amounts showing victim fund loss
- Test round-trip precision: deposit X, immediately redeem all shares, verify returned <= X
- Verify rounding direction for each preview function with small and large amounts
- Test donation resistance: send tokens directly to vault, verify share price impact
- Check maxDeposit accuracy against actual deposit limits
- Test callback reentrancy: deploy a malicious ERC-777 token and reenter during deposit
- Test zero totalSupply recovery: redeem all shares, leave dust, deposit again
- Demonstrate vault share collateral manipulation: donate to inflate share price, over-borrow
- Verify totalAssets underflow handling: simulate strategy loss below virtual offset
