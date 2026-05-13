---
name: evm-attack-vectors
category: web3
description: Comprehensive EVM attack vector database with 100+ patterns covering ERC4626, cross-chain, proxy/upgrade, oracle, governance, DeFi lending, AMM/DEX, token quirks, assembly, signatures, account abstraction, staking, and MEV — each with detection heuristic and false-positive indicator
depends_on: []
---

# EVM Attack Vector Database

Structured attack vector reference distilled from 266 real-world patterns. Each vector: detection heuristic (D) and false-positive indicator (FP).

## When to Use
- Auditing any EVM/Solidity smart contract or protocol
- Reviewing DeFi protocols (vaults, lending, DEX, staking, governance)
- Analyzing cross-chain messaging, bridge, proxy/upgradeable, oracle, signature, or assembly contracts
- Evaluating ERC-4337 account abstraction or EIP-7702 delegation implementations

## How to Use
1. **Identify protocol type** (vault, lending, DEX, bridge, governance, staking, etc.)
2. **Select relevant categories** -- always check Token Quirks, Reentrancy, and Signatures regardless of type
3. **For each vector**: check Detection (D) against codebase via grep/manual review
4. **On match**: check False Positive (FP) -- if the FP condition holds, the pattern is safe
5. **Cross-reference across categories** -- compound bugs chain vectors from different categories

## 1. ERC4626 Vaults

**V1: Inflation Attack (First Depositor)**
- D: `deposit()`/`mint()` callable when `totalSupply == 0` without minimum deposit or virtual offset; `convertToShares` uses `assets * supply / totalAssets`
- FP: Uses virtual shares/assets offset (`_decimalsOffset()`, constructor seeds), or enforces minimum first deposit

**V2: Rounding Direction Against User**
- D: `convertToShares` on deposit rounds DOWN; `convertToAssets` on withdraw rounds DOWN. Check inverse: `convertToShares` on withdraw rounds UP, `convertToAssets` on mint rounds UP
- FP: All rounding consistently favors the vault as specified by EIP-4626

**V3: Caller-Dependent Conversion**
- D: `maxDeposit`/`maxMint`/`maxWithdraw`/`maxRedeem` return per-address values but `previewDeposit`/`previewMint` ignore caller for fee calculation
- FP: Fees uniform for all users, or preview functions incorporate per-user fee schedules

**V4: maxDeposit/maxMint Overpromise**
- D: `maxDeposit` returns `type(uint256).max` but actual deposit reverts at lower value due to supply cap, allowance, or balance
- FP: No supply cap and underlying asset has no transfer restrictions

**V5: Round-Trip Profit**
- D: `deposit(X)` then immediate `redeem(shares)` returns > X assets due to inconsistent rounding between deposit and withdrawal
- FP: Round-trip always loses at least 1 wei due to consistent rounding against caller

**V6: Donation Attack (Direct Transfer)**
- D: `totalAssets()` reads `balanceOf(address(this))`, allowing direct ERC20 transfer to inflate share price without minting
- FP: `totalAssets()` tracks internal accounting variable, not raw balance

**V7: Decimal Mismatch**
- D: Vault `decimals()` differs from `asset.decimals()` and conversion math does not adjust
- FP: Vault returns `asset.decimals() + _decimalsOffset()` per EIP-4626

## 2. Cross-Chain / LayerZero

**V8: Missing Peer Validation**
- D: `lzReceive()`/`_lzReceive()` does not verify `_origin.srcEid` and `_origin.sender` against trusted peer mapping
- FP: Inherits OApp/OFT with peer check, or has explicit `require(peers[srcEid] == sender)`

**V9: Compose Sender Impersonation**
- D: `lzCompose()` reads `_from` without verifying it equals expected OApp address; attacker calls Endpoint.lzCompose with arbitrary `_from`
- FP: `_from` validated against hardcoded/stored OApp address before use

**V10: Cross-Chain Message Replay**
- D: No nonce tracking or message hash dedup in receive handler; same payload accepted multiple times
- FP: Endpoint provides built-in nonce ordering, or contract tracks processed hashes

**V11: Shared Decimals Truncation (OFT)**
- D: OFT `sharedDecimals()` < `decimals()`, dust silently lost on send; `_removeDust()` strips low bits without refund
- FP: Dust refunded to sender or emitted for off-chain tracking

**V12: Missing enforcedOptions**
- D: `_lzSend()` with user-supplied `_options` without merging `enforcedOptions`; user sets gas to 1 wei causing destination revert with stuck funds
- FP: enforcedOptions set for all message types and chains, merged via `combineOptions()`

**V13: Ordered Nonce Blocking**
- D: Ordered channel where one failed message at nonce N blocks all N+1, N+2, etc.
- FP: Uses unordered channel, or implements skip/retry via `nextNonce` management

**V14: Rate Limit Desync**
- D: Per-chain send rate limits ignoring in-flight messages; total bridged exceeds global limit via simultaneous multi-chain sends
- FP: Global limit enforced at destination, or cross-chain oracle synchronizes limits

## 3. Oracle & Price Feed

**V15: Chainlink Staleness**
- D: `latestRoundData()` `updatedAt` not checked against max staleness; `answeredInRound < roundId` not checked
- FP: Staleness check present with threshold matching feed heartbeat

**V16: TWAP Manipulation**
- D: TWAP window < 1800s used for pricing in lending/liquidation
- FP: Window >= 30 min AND not used for critical instant-settlement decisions

**V17: Spot Price as Oracle**
- D: `getReserves()`, `slot0()`, `balanceOf(pool)` used for collateral valuation, minting, or liquidation
- FP: Spot price used only for UI display or non-critical reporting

**V18: Derivative/LP Token Mispricing**
- D: LP/derivative (stETH, rETH) priced 1:1 with underlying instead of exchange rate; or rate from manipulable source
- FP: Price from manipulation-resistant oracle or time-weighted rate

**V19: Multi-Oracle Disagreement**
- D: Multiple oracles queried, takes max/min/first without deviation threshold; weaker oracle manipulable
- FP: Deviation check with fallback to trusted source when threshold exceeded

**V20: L2 Sequencer Downtime**
- D: On L2, Chainlink feed used without sequencer uptime check; stale pre-downtime prices used after restart
- FP: Sequencer uptime feed checked with grace period after restart

**V21: Decimal Mismatch Between Feeds**
- D: Two feeds with different `decimals()` combined in arithmetic without normalization
- FP: All answers normalized to common decimal base before arithmetic

**V22: Oracle Zero Price**
- D: No check for `price <= 0` from `latestRoundData()`
- FP: Explicit `require(price > 0)` after every oracle call

## 4. Proxy & Upgradeability

**V23: Storage Collision**
- D: Implementation storage variables in different order/slots than proxy; new variables inserted mid-layout
- FP: Append-only layout with `__gap` arrays or ERC-7201 namespaced storage

**V24: Selector Clash**
- D: Admin selector in proxy collides with implementation selector; user calls route to admin logic
- FP: TransparentUpgradeableProxy routes admin calls only through ProxyAdmin

**V25: Uninitialized Implementation**
- D: `initialize()` never called on implementation itself; attacker initializes then destructs via delegatecall
- FP: Constructor calls `_disableInitializers()`

**V26: UUPS Missing Auth**
- D: `_authorizeUpgrade()` empty or no access control; anyone can upgrade
- FP: Contains `onlyOwner` / `onlyRole(UPGRADER_ROLE)` or equivalent

**V27: Diamond Facet Overlap**
- D: Two facets register same selector; second silently overwrites first
- FP: `diamondCut()` reverts on duplicate selector

**V28: Missing Gap Arrays**
- D: Base contract has no `__gap`; adding variables in upgrade collides with derived storage
- FP: All bases use `uint256[50] private __gap` or ERC-7201

**V29: Initializer Reentrancy**
- D: `initialize()` makes external call before `_initialized` is set; attacker reenters to re-initialize
- FP: OZ `initializer` modifier sets flag before body, or no external calls in initializer

## 5. DeFi Lending

**V30: Stale Interest on Liquidation**
- D: `liquidate()` skips `accrueInterest()`; debt excludes recent interest, liquidator underpays
- FP: `liquidate()` accrues at top or via auto-accrue modifier

**V31: Health Factor on Stale Price**
- D: Health factor uses cached price; liquidation on outdated collateral value
- FP: Always fetches current oracle price in same transaction

**V32: Self-Liquidation Profit**
- D: Borrower liquidates own position, receives liquidation bonus on own collateral
- FP: `require(msg.sender != borrower)`, or bonus < gas + fees

**V33: Bad Debt Socialization**
- D: Collateral < debt after liquidation; bad debt silently absorbed without accounting update
- FP: Bad debt explicitly tracked and socialized proportionally with event

**V34: Interest Rate Jump Exploitation**
- D: Sharp kink in rate model; attacker pushes utilization past kink to grief borrowers with high rates
- FP: Jump smoothed over range or governance-controlled with timelock

**V35: Collateral Factor Retroactive**
- D: Changing collateral factor immediately affects all positions; healthy positions become liquidatable
- FP: Applied only to new deposits, or grace period for adjustment

**V36: Flash Loan Collateral**
- D: Deposit + borrow + repay in same tx; flash-loaned collateral extracts borrows
- FP: Same-block borrow restriction or collateral time-lock

## 6. AMM/DEX

**V37: Tick Crossing Error**
- D: Fee accumulation not snapshotted on tick boundary crossing; fees leaked or double-counted
- FP: `cross()` correctly updates `feeGrowthOutside` per Uniswap V3 reference

**V38: JIT Liquidity Sandwich**
- D: No minimum liquidity duration; bot adds concentrated liquidity before swap, captures fees, removes after
- FP: Minimum lock period or time-weighted fee accrual

**V39: Flash Accounting Imbalance**
- D: Balancer-style transient debt checked only at batch end; intermediate inconsistency exploitable via callbacks
- FP: Reentrancy guard on entire sequence, or per-step debt check

**V40: Swap Path Manipulation**
- D: Multi-hop with user-controlled path; routes through malicious/low-liquidity pool
- FP: Path whitelist or per-hop slippage enforcement

**V41: Price Impact Underestimation**
- D: `amountOutMin` from stale frontend quote; worse execution accepted on-chain
- FP: On-chain enforcement with user-set slippage tolerance

**V42: First LP Deposit Ratio**
- D: First depositor sets arbitrary token ratio; outsized pool share from manipulated ratio
- FP: Fixed initial ratio or minimum liquidity locked to dead address

**V43: Concentrated Liquidity Abuse**
- D: 1-tick range captures all fees in-range but provides near-zero depth
- FP: Minimum tick range or fee structure discouraging extreme concentration

## 7. Governance

**V44: Flash Loan Governance**
- D: Voting power snapshot at proposal/vote block; flash-borrow tokens, vote, return in same tx
- FP: Snapshot at block N-1, or delegation required before snapshot

**V45: Quorum Manipulation**
- D: Quorum = % of total supply; locking tokens in non-voting contract lowers active supply needed
- FP: Quorum based on delegated/active supply, not total

**V46: Self-Delegation Double Count**
- D: `delegate(self)` counted AND underlying balance counted; doubled votes
- FP: Delegation replaces direct balance voting

**V47: Vote-Transfer-Vote**
- D: Vote, transfer tokens, second address votes on same proposal; checkpoints not per-proposal
- FP: Snapshot block prevents post-snapshot transfers from granting power

**V48: Timelock Bypass**
- D: Emergency admin function bypasses timelock delay for critical operations
- FP: Emergency functions require higher quorum and are rate-limited

**V49: Proposal Collision**
- D: Proposal ID from calldata hash; identical submission overwrites pending proposal
- FP: ID includes nonce or proposer, or reverts on duplicate

## 8. Token Quirks

**V50: Fee-on-Transfer**
- D: Assumes `balanceAfter - balanceBefore == amount` after `transferFrom()`
- FP: Measures actual received via `balanceOf` before/after

**V51: Rebasing Tokens**
- D: Cached balance ignores automatic rebase changes (stETH, AMPL); accounting drifts
- FP: Shares-based accounting (wstETH) or re-reads balance each operation

**V52: Approval Race**
- D: `approve(spender, newAmount)` when existing allowance > 0; front-runner double-spends
- FP: Uses `increaseAllowance`/`decreaseAllowance` or approve-to-zero

**V53: USDT No-Return**
- D: `IERC20(token).approve()`/`.transfer()` with strict bool return; USDT has no return value
- FP: Uses `SafeERC20.safeApprove()`/`safeTransfer()`

**V54: Blacklistable Token DoS**
- D: Funds in single pool address; USDC/USDT blacklist freezes all users
- FP: Per-user vaults/escrows limit blacklist blast radius

**V55: Double-Entry-Point Token**
- D: Token has two addresses (legacy + proxy) sharing balance mapping; deposit via A, withdraw via B
- FP: Token whitelist with canonical addresses only

**V56: ERC-777 Hooks**
- D: `tokensReceived()` hook enables reentrancy on standard-looking transfer calls
- FP: Reentrancy guard on all token-receiving functions, or ERC-777 disallowed

**V57: Non-Standard decimals()**
- D: Assumes `decimals() == 18`; USDC (6), WBTC (8), GUSD (2) break arithmetic
- FP: `decimals()` fetched and used in all calculations

## 9. Assembly & Low-Level

**V58: Dirty Memory**
- D: Assembly reads memory offset without masking; Solidity does not zero-pad beyond written data
- FP: Explicit mask (`and(value, 0xff)`) after memory read

**V59: returndata Corruption**
- D: `returndatacopy()`/`returndatasize()` used after subsequent call that overwrites buffer
- FP: Return data copied immediately after relevant call, before any subsequent calls

**V60: calldataload Overflow**
- D: `calldataload(offset)` where offset may exceed `calldatasize()`; returns zero-padded bytes
- FP: `require(calldatasize() >= offset + 32)` or Solidity decoder handles bounds

**V61: CREATE2 Collision**
- D: `create2` with user-controlled salt; attacker deploys different code at same address after selfdestruct (pre-Dencun)
- FP: Salt includes `msg.sender` or hashed with sender

**V62: extcodesize Bypass**
- D: `extcodesize(addr) == 0` for EOA check; constructors have codesize 0
- FP: `tx.origin == msg.sender` (breaks AA) or `msg.sender.code.length` post-construction

**V63: Transient Storage Cross-Context**
- D: `tstore/tload` for lock; persists across delegate calls in same tx
- FP: Keys namespaced per contract address or unique slot per context

**V64: Unchecked Call Return**
- D: `.call()`/`.delegatecall()`/`.staticcall()` success not checked; silent failure
- FP: `require(success)` or `if (!success) revert`

## 10. Signatures & Cryptography

**V65: Cross-Chain Replay**
- D: EIP-712 `DOMAIN_SEPARATOR` missing `block.chainid` or cached at deploy; forks allow replay
- FP: Recomputed per call using `block.chainid`, or uses OZ EIP712

**V66: Signature Malleability**
- D: `ecrecover` accepts both low-s and high-s; alternate signature replays/bypasses nonce
- FP: s-value constrained to lower half order, or uses OZ ECDSA

**V67: ecrecover Returns address(0)**
- D: Invalid signature returns `address(0)`; compared against zero-initialized mapping bypasses auth
- FP: `require(recovered != address(0))` or OZ ECDSA.recover reverts

**V68: encodePacked Collision**
- D: `abi.encodePacked(a, b)` with both dynamic types; `("ab","c")` == `("a","bc")`
- FP: At most one dynamic type, or uses `abi.encode`

**V69: Permit Frontrunning**
- D: `permit()` + action in separate txs; front-runner calls permit, user's tx reverts
- FP: Combined in single tx, or catches permit revert and falls back to existing allowance

**V70: Missing Nonce**
- D: Signed message has no nonce; same signature reusable indefinitely
- FP: Nonce in signed payload, incremented on-chain after use

**V71: Domain Separator Missing Fields**
- D: `DOMAIN_SEPARATOR` omits `verifyingContract` or `chainId`; valid across contracts/chains
- FP: Includes `name`, `version`, `chainId`, `verifyingContract`

## 11. Account Abstraction (ERC-4337)

**V72: Validation/Execution Divergence**
- D: `validateUserOp()` checks condition that changes between phases (timestamp, balance); sim passes but execution fails
- FP: Validation uses only immutable or time-locked state

**V73: Storage Access Violation**
- D: `validateUserOp()` accesses storage not associated with sender; violates 4337 rules, bundler rejects
- FP: Validation accesses only sender's own and immutable associated storage

**V74: Paymaster Gas Drain**
- D: Paymaster approves sponsorship without cap; max-gas operations drain paymaster ETH
- FP: Per-operation and per-user gas limits, or off-chain signature with gas cap

**V75: Bundler Manipulation**
- D: UserOp depends on `block.timestamp`/`block.number`/`tx.gasprice`; bundler controls these
- FP: Outcome deterministic based only on on-chain state at validation time

**V76: Gas Estimation Abuse**
- D: `validateUserOp` passes estimation but reverts execution via `gasleft()` branching; griefs bundlers
- FP: No gas-dependent branching in validation

**V77: EntryPoint Reentrancy**
- D: Account/paymaster `postOp` callback reenters EntryPoint to execute additional ops mid-batch
- FP: EntryPoint reentrancy guard on `handleOps`/`handleAggregatedOps`

## 12. Staking & Rewards

**V78: Reward Precision Loss**
- D: `rewardPerToken += (reward * 1e18) / totalStaked` truncates to 0 when totalStaked very large
- FP: Precision multiplier ensures numerator exceeds denominator for minimum reward periods

**V79: Late Depositor**
- D: Stake after reward period starts, before `rewardPerToken` updated; gets full-period rewards
- FP: `rewardPerTokenStored` updated every stake/unstake; `userRewardPerTokenPaid` set on deposit

**V80: Checkpoint Manipulation**
- D: `checkpoint()` callable by anyone; called at strategically favorable moment to lock rewards
- FP: Checkpoint automatic on every state change, not independently callable

**V81: Slashing Desync**
- D: Slashing reduces individual balance but not `totalStaked`; unslashed stakers get diluted rewards
- FP: Slashing updates both individual and total atomically

**V82: Reward Duration Extension**
- D: `notifyRewardAmount()` before period ends; remaining + new rewards spread over only new duration
- FP: Remaining correctly added and divided by total new duration

**V83: Claim-and-Unstake**
- D: Claim full rewards then unstake in same tx; extracts rewards without full-period stake
- FP: Proportional time-based rewards, or cooldown between claim and unstake

## 13. MEV & Frontrunning

**V84: Sandwich Attack**
- D: Swap with no/loose `amountOutMin`; bot front-runs buy, user executes at worse price, bot back-runs sell
- FP: Tight on-chain slippage tolerance or private mempool

**V85: Oracle Update Frontrunning**
- D: Oracle update in public mempool; bot trades on old price before update lands
- FP: MEV-protected updates (commit-reveal, Chainlink DON) or previous-block price

**V86: Liquidation Sniping**
- D: Bot manipulates price to trigger liquidation, captures bonus
- FP: Fresh oracle price (not AMM spot) with grace period/buffer

**V87: Block Stuffing**
- D: Time-sensitive op (auction, expiry, vote) via `block.timestamp`; stuffed blocks delay past deadline
- FP: Sufficient buffer (hours) or block-number-based deadline

**V88: Backrun Priority**
- D: First-come-first-served mechanism; bot backruns trigger with higher priority fee
- FP: Batch/auction mechanism or commit-reveal scheme

## 14. Reentrancy Variants

**V89: Classic (ETH Transfer)**
- D: `.call{value:}("")` before state update; `receive()`/`fallback()` reenters
- FP: CEI pattern followed or `nonReentrant` applied

**V90: Cross-Function**
- D: Function A calls external; attacker reenters B which reads A's stale shared state
- FP: `nonReentrant` on all functions sharing mutable state, or all updates before external call

**V91: Cross-Contract**
- D: Contract X calls external; callback reenters Y which reads X's stale state via view/getter
- FP: Global reentrancy lock across cooperating contracts, or Y independent of X's mid-execution state

**V92: Read-Only**
- D: View returns stale intermediate state during callback; external protocol makes wrong pricing decision
- FP: View reverts during reentrancy, or dependent protocol guards reads

**V93: ERC-721/1155 Callback**
- D: `safeTransferFrom` triggers `onERC721Received`/`onERC1155Received` before state finalized
- FP: State updated before safeTransfer, or `nonReentrant` guard

**V94: ERC-777 Hooks**
- D: `tokensToSend`/`tokensReceived` fires during `transfer()`; reentrancy on standard-looking transfer
- FP: ERC-777 disallowed, or reentrancy guards on all transfer-adjacent functions

**V95: Transient Storage Lock Failure**
- D: `tstore(LOCK, 1)` not cleared in all exit paths (early return, revert catch); stale lock in same tx
- FP: Lock cleared in finally-equivalent pattern across all exits

## 15. EIP-7702 (Pectra)

**V96: Code Inspection Invalidation**
- D: `extcodesize == 0` / `code.length == 0` for EOA check; 7702-delegated EOAs have code (`0xef0100 || addr`)
- FP: Uses `msg.sender == tx.origin` or no code-presence-based classification

**V97: Whitelist Privilege Borrowing**
- D: EOA delegates to whitelisted contract to inherit permissions; access control uses `extcodehash` not registration
- FP: Whitelist based on explicit address registration

**V98: Delegation Init Frontrun**
- D: 7702 delegation tx in mempool; attacker front-runs to set malicious implementation
- FP: Delegation requires EOA private key signature; initialization atomic with delegation

**V99: Storage Collision on Redelegation**
- D: Delegate to A (layout X), redelegate to B (layout Y); B misreads A's leftover storage
- FP: Targets use ERC-7201 namespaced storage, or redelegation clears previous

**V100: Cross-Chain Authorization Replay**
- D: 7702 authorization payload missing chain ID; valid delegation replayed on other chain
- FP: `chainId` included per spec, or `chainId = 0` intentionally cross-chain

**V101: Delegated EOA Callback Gas**
- D: `.transfer()` (2300 gas) to EOA with delegation; delegation code runs with insufficient gas, reverts
- FP: Uses `.call{value:}("")` with sufficient gas

**V102: Delegation Revocation Race**
- D: Protocol caches delegation status; EOA revokes between check and use
- FP: Status checked at execution time, not cached; handles both states gracefully
