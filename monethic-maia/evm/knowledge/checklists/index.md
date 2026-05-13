# EVM / Solidity Checklist Index

20 categories, 95 skill detectors.

## Categories

| ID | Name | Context | Detectors |
|---|---|---|---|
| CAT-ACC | Access Control | ctx:generic | 7 |
| CAT-ASM | Assembly | ctx:generic | 2 |
| CAT-CRYPTO | Cryptography | ctx:generic | 2 |
| CAT-DEX | DEX/AMM | ctx:defi | 4 |
| CAT-ERC20 | ERC-20 Token | ctx:defi | 2 |
| CAT-GAS | Gas Optimization | ctx:generic | 6 |
| CAT-GEN | General Safety | ctx:generic | 12 |
| CAT-GOV | Governance | ctx:governance | 4 |
| CAT-INTEG | Protocol Integration | ctx:defi | 3 |
| CAT-LEND | Lending | ctx:lending | 7 |
| CAT-MATH | Mathematics | ctx:generic | 5 |
| CAT-NFT | NFT | ctx:nft | 3 |
| CAT-ORACLE | Oracle | ctx:oracle | 6 |
| CAT-PRED | Prediction Market | ctx:defi | 2 |
| CAT-PROXY | Proxy & Upgrades | ctx:proxy | 9 |
| CAT-STABLE | Stablecoin | ctx:defi | 2 |
| CAT-STAKE | Staking | ctx:staking | 7 |
| CAT-VAULT | Vault | ctx:vault | 6 |
| CAT-VESTING | Vesting | ctx:defi | 1 |
| CAT-XCHAIN | Cross-Chain | ctx:crosschain | 5 |

## Checklist Items

### CAT-ACC — Access Control
- CL-ACC-01: Privileged function access control → `EVM-ACC-AUTH-01`
- CL-ACC-02: Centralization risk → `EVM-ACC-CENT-01`
- CL-ACC-03: Input validation for setters → `EVM-ACC-INPUT-01`
- CL-ACC-04: Whitelist/blacklist consistency → `EVM-ACC-LIST-01`
- CL-ACC-05: Ownership & role transfer → `EVM-ACC-OWN-01`
- CL-ACC-06: Pause mechanism → `EVM-ACC-PAUSE-01`
- CL-ACC-07: Signature & authentication → `EVM-ACC-SIG-01`

### CAT-ASM — Assembly
- CL-ASM-01: Assembly call & control flow integrity → `EVM-ASM-CALL-01`
- CL-ASM-02: Assembly memory & data integrity → `EVM-ASM-MEM-01`

### CAT-CRYPTO — Cryptography
- CL-CRYPTO-01: Randomness → `EVM-CRYPTO-RNG-01`
- CL-CRYPTO-02: Signature & proof verification → `EVM-CRYPTO-SIG-01`

### CAT-DEX — DEX/AMM
- CL-DEX-01: AMM formula & invariant correctness → `EVM-DEX-AMM-01`
- CL-DEX-02: DEX fee accounting → `EVM-DEX-FEE-01`
- CL-DEX-03: Pool management & integrity → `EVM-DEX-POOL-01`
- CL-DEX-04: Slippage & deadline protection → `EVM-DEX-SLIP-01`

### CAT-ERC20 — ERC-20 Token
- CL-ERC20-01: ERC-20 token compatibility → `EVM-ERC20-COMPAT-01`
- CL-ERC20-02: ERC-20 token transfer integrity → `EVM-ERC20-TRANSFER-01`

### CAT-GAS — Gas Optimization
- CL-GAS-01: Constants, immutables & compiler hints → `EVM-GAS-CONST-01`
- CL-GAS-02: Loop & iteration → `EVM-GAS-LOOP-01`
- CL-GAS-03: Redundant code & dead code → `EVM-GAS-REDUN-01`
- CL-GAS-04: Storage read caching → `EVM-GAS-SLOAD-01`
- CL-GAS-05: Storage write & layout → `EVM-GAS-SSTORE-01`
- CL-GAS-06: Validation ordering & short-circuit → `EVM-GAS-VALID-01`

### CAT-GEN — General Safety
- CL-GEN-01: Authorization → `EVM-GEN-AUTH-01`
- CL-GEN-02: Data structure integrity → `EVM-GEN-DATA-01`
- CL-GEN-03: DoS resistance → `EVM-GEN-DOS-01`
- CL-GEN-04: Native token (ETH) handling → `EVM-GEN-ETH-01`
- CL-GEN-05: Event emission → `EVM-GEN-EVT-01`
- CL-GEN-06: Frontrunning → `EVM-GEN-FRONT-01`
- CL-GEN-07: Conditional logic → `EVM-GEN-LOGIC-01`
- CL-GEN-08: Reentrancy → `EVM-GEN-REENT-01`
- CL-GEN-09: State consistency → `EVM-GEN-STATE-01`
- CL-GEN-10: Timestamp & deadline → `EVM-GEN-TIME-01`
- CL-GEN-11: Input & initialization validation → `EVM-GEN-VAL-01`
- CL-GEN-12: External call & return value → `EVM-GEN-XCALL-01`

### CAT-GOV — Governance
- CL-GOV-01: Timelock & delay enforcement → `EVM-GOV-LOCK-01`
- CL-GOV-02: Proposal lifecycle integrity → `EVM-GOV-PROP-01`
- CL-GOV-03: Quorum & threshold integrity → `EVM-GOV-QUORUM-01`
- CL-GOV-04: Voting power integrity → `EVM-GOV-VOTE-01`

### CAT-INTEG — Protocol Integration
- CL-INTEG-01: Aave lending integration → `EVM-INTEG-AAVE-01`
- CL-INTEG-02: Uniswap V3 concentrated liquidity → `EVM-INTEG-UNIV3-01`
- CL-INTEG-03: Uniswap V4 hook integration → `EVM-INTEG-UNIV4-01`

### CAT-LEND — Lending
- CL-LEND-01: Borrow/repay accounting → `EVM-LEND-BORROW-01`
- CL-LEND-02: Collateral management → `EVM-LEND-COLL-01`
- CL-LEND-03: Solvency/health factor → `EVM-LEND-HEALTH-01`
- CL-LEND-04: Interest rate accrual → `EVM-LEND-IR-01`
- CL-LEND-05: Liquidation mechanism → `EVM-LEND-LIQ-01`
- CL-LEND-06: Parameter validation → `EVM-LEND-PARAM-01`
- CL-LEND-07: Rounding/precision → `EVM-LEND-ROUND-01`

### CAT-MATH — Mathematics
- CL-MATH-01: Type casting → `EVM-MATH-CAST-01`
- CL-MATH-02: Division → `EVM-MATH-DIV-01`
- CL-MATH-03: Overflow/underflow → `EVM-MATH-OVERFLOW-01`
- CL-MATH-04: Rounding → `EVM-MATH-ROUND-01`
- CL-MATH-05: Decimal scaling → `EVM-MATH-SCALE-01`

### CAT-NFT — NFT
- CL-NFT-01: NFT metadata integrity → `EVM-NFT-META-01`
- CL-NFT-02: NFT marketplace integrity → `EVM-NFT-MKT-01`
- CL-NFT-03: ERC-721 implementation → `EVM-NFT-STD-01`

### CAT-ORACLE — Oracle
- CL-ORACLE-01: Oracle administration → `ADMIN-01`
- CL-ORACLE-02: Decimal & precision handling → `DECIMAL-01`
- CL-ORACLE-03: Oracle resilience & fallback → `FALLBACK-01`
- CL-ORACLE-04: Spot price manipulation → `SPOT-01`
- CL-ORACLE-05: Price staleness & freshness → `STALE-01`
- CL-ORACLE-06: TWAP configuration → `TWAP-01`

### CAT-PRED — Prediction Market
- CL-PRED-01: Market creation & participation → `EVM-PRED-MKT-01`
- CL-PRED-02: Settlement & payout → `EVM-PRED-SETTLE-01`

### CAT-PROXY — Proxy & Upgrades
- CL-PROXY-01: Diamond and multi-facet proxy → `DIAM-01`
- CL-PROXY-02: Delegatecall safety → `DLGT-01`
- CL-PROXY-03: Factory and clone deployment → `FACT-01`
- CL-PROXY-04: Initialization access control → `INIT-01`
- CL-PROXY-05: Initialization completeness → `INIT-02`
- CL-PROXY-06: Initialization parameter validation → `INIT-03`
- CL-PROXY-07: Storage layout safety → `STOR-01`
- CL-PROXY-08: Upgrade authorization → `UPG-01`
- CL-PROXY-09: Upgrade state consistency → `UPG-02`

### CAT-STABLE — Stablecoin
- CL-STABLE-01: Stablecoin mechanism → `EVM-STABLE-MECH-01`
- CL-STABLE-02: Peg assumption → `EVM-STABLE-PEG-01`

### CAT-STAKE — Staking
- CL-STAKE-01: Epoch and period management → `EVM-STAKE-EPOCH-01`
- CL-STAKE-02: Reward accumulation → `EVM-STAKE-REWD-01`
- CL-STAKE-03: Staking configuration → `EVM-STAKE-SCONF-01`
- CL-STAKE-04: Slashing and penalty → `EVM-STAKE-SLASH-01`
- CL-STAKE-05: Reward gaming and flash-staking → `EVM-STAKE-SNIPE-01`
- CL-STAKE-06: Staking accounting → `EVM-STAKE-STAKE-ACC-01`
- CL-STAKE-07: Unstaking and withdrawal → `EVM-STAKE-UNSTK-01`

### CAT-VAULT — Vault
- CL-VAULT-01: Vault accounting integrity → `EVM-VAULT-ACCT-01`
- CL-VAULT-02: ERC-7540 async vault compliance → `EVM-VAULT-ERC7540-01`
- CL-VAULT-03: Vault operations safety → `EVM-VAULT-OPS-01`
- CL-VAULT-04: Share price integrity → `EVM-VAULT-SHARE-01`
- CL-VAULT-05: ERC-4626 vault compliance → `EVM-VAULT-V4626-01`
- CL-VAULT-06: Reward & yield distribution → `EVM-VAULT-YIELD-01`

### CAT-VESTING — Vesting
- CL-VESTING-01: Vesting schedule integrity → `EVM-VESTING-SCHED-01`

### CAT-XCHAIN — Cross-Chain
- CL-XCHAIN-01: Cross-chain accounting integrity → `ACCT-01`
- CL-XCHAIN-02: Cross-chain finality & state ordering → `FINAL-01`
- CL-XCHAIN-03: Cross-chain liveness & error recovery → `LIVE-01`
- CL-XCHAIN-04: Cross-chain message authentication → `MSG-01`
- CL-XCHAIN-05: Cross-chain replay protection → `REPLAY-01`
