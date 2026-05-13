# Move/Sui Security Checklist

Token-efficient security checklist for Sui Move program auditing.
Load category detail files (`categories/CAT-*.md`) only when stage needs exact descriptions.

## Categories

| ID | Name | Items | Detail |
|----|------|-------|--------|
| CAT-ACC | Access Control | 6 | `categories/CAT-ACC.md` |
| CAT-COIN | Coin/Token | 2 | `categories/CAT-COIN.md` |
| CAT-CRYPTO | Cryptography | 1 | `categories/CAT-CRYPTO.md` |
| CAT-GAS | Gas & Performance | 4 | `categories/CAT-GAS.md` |
| CAT-GEN | General Logic | 9 | `categories/CAT-GEN.md` |
| CAT-LEND | Lending | 3 | `categories/CAT-LEND.md` |
| CAT-MATH | Arithmetic | 5 | `categories/CAT-MATH.md` |
| CAT-OBJ | Object Model | 3 | `categories/CAT-OBJ.md` |
| CAT-ORACLE | Oracle | 5 | `categories/CAT-ORACLE.md` |
| CAT-POOL | Pool/DEX/Staking | 8 | `categories/CAT-POOL.md` |
| CAT-VAULT | Vault | 2 | `categories/CAT-VAULT.md` |

**Total: 11 categories, 48 items**

## Items

### CAT-ACC — Access Control
- CL-ACC-01: Access Control Enforcement (signer checks, visibility, auth gaps, admin validation) `[MOVE-ACC-AUTH-01]`
- CL-ACC-02: Centralization Risk — Design-Inherent Admin Authority `[MOVE-ACC-CENT-01]`
- CL-ACC-03: Centralization Risk — Missing Operational Safeguard `[MOVE-ACC-CENT-02]`
- CL-ACC-04: Whitelist/Blacklist Consistency `[MOVE-ACC-LIST-01]`
- CL-ACC-05: Ownership & Role Transfer Safety `[MOVE-ACC-OWNER-01]`
- CL-ACC-06: Input Validation for Setters `[MOVE-ACC-VALID-01]`

### CAT-COIN — Coin/Token
- CL-COIN-01: Coin/Token Handling (zero-amount, split/join, dust) `[MOVE-COIN-HAND-01]`
- CL-COIN-02: Decimal Precision Consistency `[MOVE-COIN-SCALE-01]`

### CAT-CRYPTO — Cryptography
- CL-CRYPTO-01: Signature & Proof Verification `[MOVE-CRYPTO-SIG-01]`

### CAT-GAS — Gas & Performance
- CL-GAS-01: Unbounded Iteration `[MOVE-GAS-LOOP-01]`
- CL-GAS-02: Storage Growth / State Bloat `[MOVE-GAS-BLOAT-01]`
- CL-GAS-03: Hash Collision DoS `[MOVE-GAS-HASH-01]`
- CL-GAS-04: Redundant Code / Gas Waste `[MOVE-GAS-REDUN-01]`

### CAT-GEN — General Logic
- CL-GEN-01: Error Handling (duplicate abort codes) `[MOVE-GEN-ABORT-01]`
- CL-GEN-02: Data Structure Safety `[MOVE-GEN-DATA-01]`
- CL-GEN-03: Event Emission Completeness `[MOVE-GEN-EVT-01]`
- CL-GEN-04: Initialization Safety `[MOVE-GEN-INIT-01]`
- CL-GEN-05: Resource Management `[MOVE-GEN-RES-01]`
- CL-GEN-06: State Freshness `[MOVE-GEN-STALE-01]`
- CL-GEN-07: State Consistency `[MOVE-GEN-STATE-01]`
- CL-GEN-08: Timestamp/Deadline Safety `[MOVE-GEN-TIME-01]`
- CL-GEN-09: Type Safety `[MOVE-GEN-TYPE-01]`

### CAT-LEND — Lending
- CL-LEND-01: Liquidation Logic Integrity `[MOVE-LEND-LIQ-01]`
- CL-LEND-02: Advanced Liquidation Mechanics `[MOVE-LEND-LIQ-02]`
- CL-LEND-03: Lending Pause & Recovery `[MOVE-LEND-PAUSE-01]`

### CAT-MATH — Arithmetic
- CL-MATH-01: Arithmetic Overflow/Underflow `[MOVE-MATH-OVF-01]`
- CL-MATH-02: Unsafe Type Casting `[MOVE-MATH-CAST-01]`
- CL-MATH-03: Incorrect Mathematical Formula `[MOVE-MATH-FORM-01]`
- CL-MATH-04: Precision Loss / Rounding `[MOVE-MATH-PREC-01]`
- CL-MATH-05: Decimal Scaling Errors `[MOVE-MATH-SCALE-01]`

### CAT-OBJ — Object Model
- CL-OBJ-01: Ability & Type Safety `[MOVE-OBJ-ABIL-01]`
- CL-OBJ-02: Hot Potato Pattern Integrity `[MOVE-OBJ-HOT-01]`
- CL-OBJ-03: Witness & Publisher Pattern `[MOVE-OBJ-WIT-01]`

### CAT-ORACLE — Oracle
- CL-ORACLE-01: Oracle Administration `[MOVE-ORACLE-ADMIN-01]`
- CL-ORACLE-02: Oracle Aggregation Integrity `[MOVE-ORACLE-AGG-01]`
- CL-ORACLE-03: Oracle DeFi Integration `[MOVE-ORACLE-DEFI-01]`
- CL-ORACLE-04: Oracle Freshness `[MOVE-ORACLE-FRESH-01]`
- CL-ORACLE-05: Price Source Validation `[MOVE-ORACLE-PRICE-01]`

### CAT-POOL — Pool/DEX/Staking
- CL-POOL-01: Pool Initialization Safety `[MOVE-POOL-INIT-01]`
- CL-POOL-02: AMM Invariant & Slippage `[MOVE-POOL-AMM-01]`
- CL-POOL-03: Flash Loan Safety `[MOVE-POOL-FLASH-01]`
- CL-POOL-04: Pool Accounting & Shares `[MOVE-POOL-ACCT-01]`
- CL-POOL-05: LP Token Integrity `[MOVE-POOL-LP-01]`
- CL-POOL-06: Swap Routing Integrity `[MOVE-POOL-ROUTE-01]`
- CL-POOL-07: Reward Accumulator Integrity `[MOVE-POOL-REWD-01]`
- CL-POOL-08: Flash Stake Attack `[MOVE-POOL-STAKE-01]`

### CAT-VAULT — Vault
- CL-VAULT-01: Share Accounting `[MOVE-VAULT-SHARE-01]`
- CL-VAULT-02: State Synchronization `[MOVE-VAULT-SYNC-01]`
