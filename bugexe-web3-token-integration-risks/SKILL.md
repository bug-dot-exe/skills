---
name: token-integration-risks
category: web3
description: Weird ERC20 token integration risks covering fee-on-transfer, rebasing, USDT no-return, blacklistable/pausable tokens, double-entry-point tokens, ERC-777 hooks, ERC-721/1155 callbacks, approval race conditions, and tokens with non-standard decimals
depends_on: []
---

# Token Integration Risks

Security analysis for protocols integrating external tokens. Covers the full spectrum of non-standard token behaviors that break assumptions in vaults, lending protocols, DEXs, and any contract that handles arbitrary ERC20/721/1155 tokens.

## When to Use

- Protocol integrates arbitrary ERC20 tokens (vaults, lending, DEXs)
- Protocol interacts with specific known-quirky tokens (USDT, USDC, stETH, AMPL, cUSDC)
- Any token transfer where the amount received may differ from amount sent
- Protocol uses safeTransferFrom for NFTs (ERC-721/1155 callbacks)

## Methodology

### 1. Fee-on-Transfer Tokens

- Tokens that take a fee on every transfer (e.g., STA, PAXG, some deflationary tokens)
- Impact: protocol records `amount` but only receives `amount - fee`
- Accounting desync: protocol thinks it has more tokens than it actually does
- Detection: search for `transferFrom` followed by balance-based accounting without measuring actual received amount
- Safe pattern: measure `balanceBefore` and `balanceAfter`, use the delta
- Also check: does the protocol use `safeTransferFrom` from OZ? It doesn't help -- fee still applies

### 2. Rebasing Tokens

- Tokens whose balance changes automatically (stETH positive rebase, AMPL elastic supply)
- Impact: cached balance becomes stale after rebase
- Types:
  - Positive rebase (stETH): balance increases -- protocol may not distribute the surplus
  - Negative rebase (AMPL): balance decreases -- protocol may become insolvent
  - Interest-bearing (aTokens, cTokens): balance changes represent accrued interest
- Detection: does protocol cache token balances in storage? Does it use `balanceOf()` for current state?
- Safe pattern: use wrapper tokens (wstETH instead of stETH) or continuously sync balances

### 3. USDT / Non-Standard Return Values

- USDT's `transfer()` and `approve()` return `void` instead of `bool`
- Impact: `IERC20(usdt).approve(spender, amount)` reverts because return data decoding fails
- Also affected: BNB, OMG, and other older tokens
- Detection: search for `IERC20.approve()` or `IERC20.transfer()` -- if using standard interface, it will fail on USDT
- Safe pattern: use OpenZeppelin's `SafeERC20` (`safeTransfer`, `safeApprove`, `safeIncreaseAllowance`)
- Double approve issue: USDT requires setting allowance to 0 before setting to a new non-zero value

### 4. Blacklistable / Pausable Tokens

- USDC, USDT: admin can blacklist addresses, freezing all transfers
- Impact: if protocol address is blacklisted, all funds are permanently frozen
- DoS vector: attacker sends blacklisted tokens to protocol, blocking operations that iterate over token list
- Detection: does the protocol have a fallback if a token transfer reverts? Can operations be skipped?
- Also: USDC can be paused globally, blocking all transfers

### 5. Tokens with Hooks (ERC-777, ERC-1155)

- ERC-777: `tokensReceived` hook called on receiver, `tokensToSend` hook called on sender
- Impact: reentrancy via the hook -- sender/receiver executes code during transfer
- ERC-1155: `onERC1155Received` and `onERC1155BatchReceived` callbacks on receiver
- ERC-721: `onERC721Received` callback on `safeTransferFrom`
- Detection: does the protocol use `ReentrancyGuard` on functions that transfer these token types?
- Critical: ERC-777 tokens registered in ERC-1820 registry can masquerade as ERC-20

### 6. Double-Entry-Point Tokens

- Some tokens have two contract addresses pointing to the same balance (old Synthetix SNX/sUSD pattern)
- Impact: draining through the secondary address while protocol tracks the primary
- Detection: search for token whitelists that don't check for double-entry-point aliases
- Legacy example: Compound was vulnerable to this with legacy SNX

### 7. Approval Race Condition

- Changing approval from A to B: frontrunner can spend A, then spend B (total: A + B)
- Solidity: `approve(spender, newAmount)` is atomic but can be front-run
- Detection: does the protocol use `approve` or `increaseAllowance/decreaseAllowance`?
- Safe pattern: `safeIncreaseAllowance` / `safeDecreaseAllowance`, or set to 0 first

### 8. Tokens with Non-Standard Decimals

- Most tokens: 18 decimals. USDC/USDT: 6. WBTC: 8. Some: 0, 2, or 24
- Impact: if protocol assumes 18 decimals, calculations are off by orders of magnitude
- Detection: hardcoded `1e18` or `10**18` in token amount calculations
- Critical: mixing tokens with different decimals in the same calculation without normalization

### 9. Upgradeable Token Contracts

- USDC, USDT are upgradeable proxies -- behavior can change
- Impact: future upgrade could add fees, change decimals, or modify transfer semantics
- Detection: are critical tokens stored as immutable addresses? Is there a mechanism to handle behavior changes?

### 10. Tokens with Transfer Restrictions

- Some tokens restrict transfers to whitelisted addresses (security tokens, KYC tokens)
- Some have maximum transaction amounts or cooldown periods
- Impact: protocol may fail to transfer tokens if restrictions aren't met
- Detection: does the protocol handle transfer failures gracefully?

### 11. Return Data Bombs

- Malicious token returns extremely large data from `transfer()`
- Impact: `abi.decode` of the return data consumes excessive gas, causing OOG
- Detection: does the protocol use `SafeERC20` (which handles return data safely)?
- Affected: any low-level call that copies full return data without size limits

## Weird ERC20 Quick Reference Table

| Token | Quirk | Impact |
|-------|-------|--------|
| USDT | No return value, requires 0 approval first | Revert on standard interface |
| USDC | 6 decimals, blacklistable, pausable, upgradeable | Frozen funds, DoS |
| stETH | Positive rebase, 1-2 wei transfer rounding | Balance desync, dust loss |
| AMPL | Elastic supply (rebase up and down) | Insolvency on negative rebase |
| PAXG | Fee-on-transfer (0.02%) | Accounting desync |
| cUSDC | Interest-bearing, exchange rate changes | Stale cached value |
| WBTC | 8 decimals | Decimal mismatch |
| SNX (legacy) | Double entry point | Drain via secondary address |
| ERC-777 tokens | Transfer hooks | Reentrancy |

### 12. Low-Decimal Token Amplification

- Tokens with 0-2 decimals (some governance tokens, NFT-adjacent tokens) amplify rounding errors
- 1 unit = 1 token (no fractional amounts), making precision loss severe in division operations
- Impact: share calculations that work for 18-decimal tokens produce zero-share deposits for low-decimal tokens
- Detection: does the protocol enforce a minimum decimal count? Does it test with 0-decimal and 2-decimal tokens?
- Combined with vault inflation attacks: low-decimal tokens make first-depositor attacks dramatically cheaper

### 13. Token Callback Reentrancy Patterns

- ERC-777 `tokensToSend` and `tokensReceived` hooks fire on EVERY transfer, including internal protocol transfers
- ERC-1155 `onERC1155Received` fires on `safeTransferFrom` -- if the protocol mints/transfers ERC-1155 to an attacker contract, the callback can reenter
- ERC-721 `onERC721Received` fires on `safeTransferFrom` and `safeMint` -- minting to a contract triggers the callback before state is finalized
- Detection: search for `_safeMint`, `safeTransferFrom` on NFT/ERC-1155 tokens followed by state-modifying code
- Cross-contract variant: Token A's callback reenters a different protocol contract that reads Token A's stale balance

### 14. Permit-Bearing Token Risks

- ERC-2612 permit on tokens allows gasless approval via off-chain signature
- If the protocol calls `transferFrom` and the token supports permit, an attacker can front-run with a `permit` call to set allowance and then the protocol's `transferFrom` uses the attacker's allowance instead of reverting
- `permit` front-running griefing: attacker calls `permit` with the user's signature before the protocol does, causing the protocol's `permit` call to revert (nonce already consumed)
- Detection: does the protocol wrap `permit` calls in try/catch? Does it handle the case where permit was already consumed?

### 15. Token Supply Manipulation

- Tokens with public mint functions (misconfigured access control) allow supply inflation
- Deflationary tokens with burn-on-transfer reduce circulating supply; protocol accounting must track the deflation
- Tokens with `MAX_SUPPLY` cap: protocol may assume unlimited minting availability
- Flash-mintable tokens (ERC-3156 flash mint): token supply temporarily inflated during the transaction, affecting any calculation using `totalSupply()`
- Detection: does the protocol read `totalSupply()` for pricing or share calculation? Can `totalSupply` be manipulated atomically?

## Key Detection Commands

```bash
# Find token transfers without balance checking
grep -rn "transferFrom\|transfer(" contracts/ --include="*.sol"

# Find approval patterns
grep -rn "\.approve(" contracts/ --include="*.sol"

# Find SafeERC20 usage (good)
grep -rn "safeTransfer\|safeApprove\|safeIncreaseAllowance" contracts/ --include="*.sol"

# Find hardcoded decimals
grep -rn "1e18\|1e6\|1e8\|10\*\*18\|10\*\*6" contracts/ --include="*.sol"

# Find balanceOf caching
grep -rn "balanceOf" contracts/ --include="*.sol"

# Find callback-triggering transfers
grep -rn "_safeMint\|safeTransferFrom\|_mint.*ERC1155\|_mint.*ERC721" contracts/ --include="*.sol"

# Find permit usage
grep -rn "\.permit(\|IERC20Permit\|ERC20Permit" contracts/ --include="*.sol"

# Find totalSupply reads in calculations
grep -rn "totalSupply()" contracts/ --include="*.sol"
```

## Validation

- Test with fee-on-transfer mock: deploy a token that takes 1% fee, demonstrate accounting desync
- Test with rebasing mock: change balance between deposit and withdrawal, show insolvency
- Test with USDT interface: demonstrate revert when using standard IERC20
- Fork test with real USDC: demonstrate blacklist scenario
- Test with 0-decimal and 2-decimal token mocks: show rounding amplification in share calculations
- Test callback reentrancy: deploy a malicious ERC-721/1155 receiver that reenters during safeTransferFrom
- Quantify: total value at risk from each token quirk in the protocol
