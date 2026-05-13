# Checklist Router

Maps project keywords/context to relevant checklist categories and rule IDs.

## Keyword → Rule-ID Table

| Keyword / Context | Rule IDs |
|---|---|
| `onlyOwner`, `onlyRole`, `access control`, `modifier`, `require(msg.sender` | EVM-ACC-AUTH-01 |
| `centralization`, `admin power`, `rug pull`, `single key` | EVM-ACC-CENT-01 |
| `input validation`, `setter`, `config`, `parameter`, `bounds` | EVM-ACC-INPUT-01 |
| `whitelist`, `blacklist`, `blocklist`, `allowlist`, `denylist`, `isBlocked`, `restricted`, `sanctioned`, `banned` | EVM-ACC-LIST-01 |
| `transferOwnership`, `renounceOwnership`, `2-step`, `pending owner` | EVM-ACC-OWN-01 |
| `pause`, `unpause`, `whenNotPaused`, `emergency` | EVM-ACC-PAUSE-01 |
| `signature`, `ecrecover`, `ECDSA`, `permit`, `EIP-712`, `meta-tx` | EVM-ACC-SIG-01 |
| `assembly`, `inline asm`, `delegatecall`, `staticcall` | EVM-ASM-CALL-01 |
| `assembly memory`, `mstore`, `mload`, `calldatacopy` | EVM-ASM-MEM-01 |
| `VRF`, `randomness`, `block.prevrandao`, `keccak256(abi.encodePacked` | EVM-CRYPTO-RNG-01 |
| `ecrecover`, `signature verification`, `merkle proof` | EVM-CRYPTO-SIG-01 |
| `AMM`, `swap`, `constant product`, `curve`, `invariant` | EVM-DEX-AMM-01 |
| `swap fee`, `trading fee`, `protocol fee`, `fee accounting` | EVM-DEX-FEE-01 |
| `pool`, `liquidity pool`, `addLiquidity`, `removeLiquidity` | EVM-DEX-POOL-01 |
| `slippage`, `deadline`, `minAmountOut`, `amountOutMinimum` | EVM-DEX-SLIP-01 |
| `ERC20`, `IERC20`, `approve`, `allowance`, `fee-on-transfer` | EVM-ERC20-COMPAT-01 |
| `transfer`, `transferFrom`, `safeTransfer`, `SafeERC20` | EVM-ERC20-TRANSFER-01 |
| `constant`, `immutable`, `calldata`, `memory`, `custom error` | EVM-GAS-CONST-01 |
| `loop`, `iteration`, `unbounded`, `for`, `while` | EVM-GAS-LOOP-01 |
| `dead code`, `redundant`, `unused`, `tautological` | EVM-GAS-REDUN-01 |
| `SLOAD`, `storage read`, `cache`, `local variable` | EVM-GAS-SLOAD-01 |
| `SSTORE`, `storage write`, `packing`, `layout` | EVM-GAS-SSTORE-01 |
| `short-circuit`, `validation order`, `require order` | EVM-GAS-VALID-01 |
| `authorization`, `auth`, `access`, `permission` | EVM-GEN-AUTH-01 |
| `data structure`, `mapping`, `array`, `struct`, `encoding` | EVM-GEN-DATA-01 |
| `DoS`, `denial of service`, `revert`, `block gas limit` | EVM-GEN-DOS-01 |
| `ETH`, `msg.value`, `receive`, `fallback`, `selfdestruct` | EVM-GEN-ETH-01 |
| `event`, `emit`, `indexed`, `logging` | EVM-GEN-EVT-01 |
| `front-running`, `MEV`, `sandwich`, `commit-reveal` | EVM-GEN-FRONT-01 |
| `business logic`, `conditional`, `branch`, `edge case` | EVM-GEN-LOGIC-01 |
| `reentrancy`, `nonReentrant`, `CEI`, `callback` | EVM-GEN-REENT-01 |
| `state consistency`, `invariant`, `accounting`, `atomic` | EVM-GEN-STATE-01 |
| `timestamp`, `block.timestamp`, `deadline`, `expiry` | EVM-GEN-TIME-01 |
| `input validation`, `zero address`, `zero amount`, `initialize` | EVM-GEN-VAL-01 |
| `external call`, `return value`, `low-level call`, `try/catch` | EVM-GEN-XCALL-01 |
| `timelock`, `delay`, `governance delay`, `admin delay` | EVM-GOV-LOCK-01 |
| `proposal`, `lifecycle`, `voting period`, `execution` | EVM-GOV-PROP-01 |
| `quorum`, `threshold`, `minimum votes`, `supermajority` | EVM-GOV-QUORUM-01 |
| `voting`, `vote`, `delegation`, `snapshot`, `flash loan governance` | EVM-GOV-VOTE-01 |
| `Aave`, `aToken`, `lending pool`, `flash loan` | EVM-INTEG-AAVE-01 |
| `Uniswap V3`, `concentrated liquidity`, `tick`, `position` | EVM-INTEG-UNIV3-01 |
| `Uniswap V4`, `hook`, `beforeSwap`, `afterSwap` | EVM-INTEG-UNIV4-01 |
| `borrow`, `repay`, `debt`, `utilization` | EVM-LEND-BORROW-01 |
| `collateral`, `deposit collateral`, `withdraw collateral`, `LTV` | EVM-LEND-COLL-01 |
| `health factor`, `solvency`, `liquidation threshold` | EVM-LEND-HEALTH-01 |
| `interest rate`, `accrual`, `compound`, `utilization rate` | EVM-LEND-IR-01 |
| `liquidation`, `liquidate`, `seizure`, `penalty` | EVM-LEND-LIQ-01 |
| `lending parameter`, `risk parameter`, `max LTV` | EVM-LEND-PARAM-01 |
| `rounding`, `precision`, `roundUp`, `roundDown`, `mulDiv` | EVM-LEND-ROUND-01 |
| `cast`, `uint256`, `uint128`, `int256`, `type conversion` | EVM-MATH-CAST-01 |
| `division`, `divide`, `modulo`, `division by zero` | EVM-MATH-DIV-01 |
| `overflow`, `underflow`, `unchecked`, `wrapping` | EVM-MATH-OVERFLOW-01 |
| `rounding`, `ceil`, `floor`, `precision loss` | EVM-MATH-ROUND-01 |
| `decimal`, `scaling`, `normalization`, `10**`, `1e18` | EVM-MATH-SCALE-01 |
| `ERC-721`, `NFT`, `tokenURI`, `metadata`, `base URI` | EVM-NFT-META-01 |
| `marketplace`, `listing`, `auction`, `royalty` | EVM-NFT-MKT-01 |
| `onERC721Received`, `safeTransferFrom`, `ERC-721 standard` | EVM-NFT-STD-01 |
| `oracle admin`, `price feed admin`, `aggregator` | ADMIN-01 |
| `decimal conversion`, `oracle precision`, `price scaling` | DECIMAL-01 |
| `oracle fallback`, `circuit breaker`, `backup oracle` | FALLBACK-01 |
| `spot price`, `manipulation`, `flash loan oracle` | SPOT-01 |
| `stale price`, `freshness`, `heartbeat`, `updatedAt` | STALE-01 |
| `TWAP`, `time-weighted`, `observation`, `cardinality` | TWAP-01 |
| `prediction market`, `bet`, `outcome`, `resolution` | EVM-PRED-MKT-01 |
| `settlement`, `payout`, `oracle resolution` | EVM-PRED-SETTLE-01 |
| `diamond`, `facet`, `DiamondCut`, `multi-proxy` | DIAM-01 |
| `delegatecall`, `delegate`, `context` | DLGT-01 |
| `factory`, `clone`, `minimal proxy`, `CREATE2` | FACT-01 |
| `initialize`, `initializer`, `reinitialize` | INIT-01 |
| `initialization completeness`, `missing init` | INIT-02 |
| `initialization parameter`, `init validation` | INIT-03 |
| `storage layout`, `storage slot`, `collision`, `gap` | STOR-01 |
| `upgrade`, `upgradeTo`, `UUPS`, `transparent proxy` | UPG-01 |
| `upgrade state`, `migration`, `post-upgrade` | UPG-02 |
| `stablecoin`, `peg`, `mechanism`, `mint/redeem` | EVM-STABLE-MECH-01 |
| `peg assumption`, `depeg`, `oracle peg` | EVM-STABLE-PEG-01 |
| `epoch`, `period`, `cycle`, `rotation` | EVM-STAKE-EPOCH-01 |
| `staking reward`, `reward rate`, `reward per token` | EVM-STAKE-REWD-01 |
| `staking config`, `minimum stake`, `lock period` | EVM-STAKE-SCONF-01 |
| `slashing`, `penalty`, `slash condition` | EVM-STAKE-SLASH-01 |
| `reward sniping`, `flash stake`, `just-in-time` | EVM-STAKE-SNIPE-01 |
| `staking accounting`, `stake balance`, `total staked` | EVM-STAKE-STAKE-ACC-01 |
| `unstake`, `withdraw`, `cooldown`, `unbonding` | EVM-STAKE-UNSTK-01 |
| `vault`, `ERC-4626`, `deposit`, `withdraw`, `totalAssets` | EVM-VAULT-ACCT-01 |
| `ERC-7540`, `async vault`, `requestDeposit`, `requestRedeem` | EVM-VAULT-ERC7540-01 |
| `vault operations`, `harvest`, `strategy`, `rebalance` | EVM-VAULT-OPS-01 |
| `share price`, `exchange rate`, `inflation attack`, `first depositor` | EVM-VAULT-SHARE-01 |
| `ERC-4626 compliance`, `maxDeposit`, `maxWithdraw`, `preview` | EVM-VAULT-V4626-01 |
| `yield`, `reward distribution`, `fee`, `performance fee` | EVM-VAULT-YIELD-01 |
| `vesting`, `cliff`, `schedule`, `release`, `revocable` | EVM-VESTING-SCHED-01 |
| `cross-chain`, `bridge`, `message`, `relay` | ACCT-01 |
| `finality`, `confirmation`, `reorg`, `ordering` | FINAL-01 |
| `liveness`, `retry`, `stuck message`, `timeout` | LIVE-01 |
| `message auth`, `source verification`, `trusted remote` | MSG-01 |
| `replay`, `nonce`, `message ID`, `idempotency` | REPLAY-01 |

## Context → Category Table

| Context Tag | Categories |
|---|---|
| `ctx:generic` | ACC, ASM, GAS, GEN, MATH, CRYPTO |
| `ctx:defi` | All categories |
| `ctx:nft` | ACC, GAS, GEN, MATH, NFT |
| `ctx:lending` | ACC, ERC20, GAS, GEN, LEND, MATH, ORACLE |
| `ctx:dex` | ACC, DEX, ERC20, GAS, GEN, MATH, ORACLE |
| `ctx:vault` | ACC, ERC20, GAS, GEN, MATH, ORACLE, VAULT |
| `ctx:governance` | ACC, GAS, GEN, GOV, MATH |
| `ctx:staking` | ACC, ERC20, GAS, GEN, MATH, STAKE |
| `ctx:oracle` | ACC, GEN, ORACLE |
| `ctx:proxy` | ACC, GEN, PROXY |
| `ctx:crosschain` | ACC, GEN, XCHAIN |
| `ctx:stablecoin` | ACC, ERC20, GAS, GEN, MATH, ORACLE, STABLE |
| `ctx:prediction` | ACC, GAS, GEN, MATH, ORACLE, PRED |
