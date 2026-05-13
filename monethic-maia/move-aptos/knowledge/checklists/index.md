# Move / Aptos Checklist Index

11 categories, 49 skill detectors.

## Categories

| ID | Name | Context | Detectors |
|---|---|---|---|
| CAT-ACC | Access Control | ctx:generic | 6 |
| CAT-COIN | Coin/Token Handling | ctx:defi | 2 |
| CAT-CRYPTO | Cryptography | ctx:generic | 1 |
| CAT-GAS | Gas & Storage | ctx:generic | 4 |
| CAT-GEN | General Safety | ctx:generic | 9 |
| CAT-LEND | Lending | ctx:lending | 3 |
| CAT-MATH | Mathematics | ctx:generic | 5 |
| CAT-OBJ | Object Model | ctx:generic | 4 |
| CAT-ORACLE | Oracle | ctx:oracle | 5 |
| CAT-POOL | Pool/DEX/Staking | ctx:pool | 8 |
| CAT-VAULT | Vault | ctx:vault | 2 |

## Checklist Items

### CAT-ACC — Access Control
- CL-ACC-01: Access Control Enforcement → `MOVE-ACC-AUTH-01`
- CL-ACC-02: Centralization Risk (Design) → `MOVE-ACC-CENT-01`
- CL-ACC-03: Centralization Risk (Missing Safeguard) → `MOVE-ACC-CENT-02`
- CL-ACC-04: Whitelist/Blacklist Consistency → `MOVE-ACC-LIST-01`
- CL-ACC-05: Ownership & Role Transfer → `MOVE-ACC-OWNER-01`
- CL-ACC-06: Input Validation → `MOVE-ACC-VALID-01`

### CAT-COIN — Coin/Token Handling
- CL-COIN-01: Coin/Token Handling → `MOVE-COIN-HAND-01`
- CL-COIN-02: Decimal Precision → `MOVE-COIN-SCALE-01`

### CAT-CRYPTO — Cryptography
- CL-CRYPTO-01: Signature & Proof Verification → `MOVE-CRYPTO-SIG-01`

### CAT-GAS — Gas & Storage
- CL-GAS-01: Storage Growth / Bloat → `MOVE-GAS-BLOAT-01`
- CL-GAS-02: Hash Collision DoS → `MOVE-GAS-HASH-01`
- CL-GAS-03: Unbounded Iteration → `MOVE-GAS-LOOP-01`
- CL-GAS-04: Redundant Code / Gas Waste → `MOVE-GAS-REDUN-01`

### CAT-GEN — General Safety
- CL-GEN-01: Error Handling → `MOVE-GEN-ABORT-01`
- CL-GEN-02: Data Structure Safety → `MOVE-GEN-DATA-01`
- CL-GEN-03: Event Emission → `MOVE-GEN-EVT-01`
- CL-GEN-04: Initialization Safety → `MOVE-GEN-INIT-01`
- CL-GEN-05: Resource Management → `MOVE-GEN-RES-01`
- CL-GEN-06: State Freshness → `MOVE-GEN-STALE-01`
- CL-GEN-07: State Consistency → `MOVE-GEN-STATE-01`
- CL-GEN-08: Timestamp/Deadline → `MOVE-GEN-TIME-01`
- CL-GEN-09: Type Safety → `MOVE-GEN-TYPE-01`

### CAT-LEND — Lending
- CL-LEND-01: Liquidation Logic → `MOVE-LEND-LIQ-01`
- CL-LEND-02: Advanced Liquidation → `MOVE-LEND-LIQ-02`
- CL-LEND-03: Pause & Recovery → `MOVE-LEND-PAUSE-01`

### CAT-MATH — Mathematics
- CL-MATH-01: Unsafe Type Casting → `MOVE-MATH-CAST-01`
- CL-MATH-02: Incorrect Formula → `MOVE-MATH-FORM-01`
- CL-MATH-03: Overflow/Underflow → `MOVE-MATH-OVF-01`
- CL-MATH-04: Precision Loss → `MOVE-MATH-PREC-01`
- CL-MATH-05: Decimal Scaling → `MOVE-MATH-SCALE-01`

### CAT-OBJ — Object Model
- CL-OBJ-01: Ability & Type Safety → `MOVE-OBJ-ABIL-01`
- CL-OBJ-02: Aptos Resource & Object → `MOVE-OBJ-APTOS-01`
- CL-OBJ-03: Aptos Framework Safety → `MOVE-OBJ-APTOS-02`
- CL-OBJ-04: Hot Potato Pattern → `MOVE-OBJ-HOT-01`

### CAT-ORACLE — Oracle
- CL-ORACLE-01: Oracle Administration → `MOVE-ORACLE-ADMIN-01`
- CL-ORACLE-02: Oracle Aggregation → `MOVE-ORACLE-AGG-01`
- CL-ORACLE-03: Oracle DeFi Integration → `MOVE-ORACLE-DEFI-01`
- CL-ORACLE-04: Oracle Freshness → `MOVE-ORACLE-FRESH-01`
- CL-ORACLE-05: Price Source Validation → `MOVE-ORACLE-PRICE-01`

### CAT-POOL — Pool/DEX/Staking
- CL-POOL-01: Pool Accounting → `MOVE-POOL-ACCT-01`
- CL-POOL-02: AMM Invariant → `MOVE-POOL-AMM-01`
- CL-POOL-03: Flash Loan Safety → `MOVE-POOL-FLASH-01`
- CL-POOL-04: Pool Initialization → `MOVE-POOL-INIT-01`
- CL-POOL-05: LP Token Integrity → `MOVE-POOL-LP-01`
- CL-POOL-06: Reward Accumulator → `MOVE-POOL-REWD-01`
- CL-POOL-07: Swap Routing → `MOVE-POOL-ROUTE-01`
- CL-POOL-08: Flash Stake Attack → `MOVE-POOL-STAKE-01`

### CAT-VAULT — Vault
- CL-VAULT-01: Share Accounting → `MOVE-VAULT-SHARE-01`
- CL-VAULT-02: State Synchronization → `MOVE-VAULT-SYNC-01`
