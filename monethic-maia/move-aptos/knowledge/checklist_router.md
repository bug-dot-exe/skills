# Checklist Router

Maps project keywords/context to relevant checklist categories and rule IDs.

## Keyword → Rule-ID Table

| Keyword / Context | Rule IDs |
|---|---|
| `signer`, `admin`, `owner`, `access control`, `auth`, `capability` | MOVE-ACC-AUTH-01 |
| `centralization`, `admin power`, `governance`, `multisig`, `timelock` | MOVE-ACC-CENT-01, MOVE-ACC-CENT-02 |
| `whitelist`, `blacklist`, `allowlist`, `denylist`, `bitmask` | MOVE-ACC-LIST-01 |
| `ownership transfer`, `role`, `2-step`, `pending admin` | MOVE-ACC-OWNER-01 |
| `setter`, `config`, `parameter`, `validation`, `bounds` | MOVE-ACC-VALID-01 |
| `coin`, `token`, `fungible asset`, `balance`, `dust` | MOVE-COIN-HAND-01 |
| `decimal`, `precision`, `scaling`, `cross-asset` | MOVE-COIN-SCALE-01 |
| `signature`, `merkle`, `proof`, `nonce`, `replay` | MOVE-CRYPTO-SIG-01 |
| `storage`, `bloat`, `cleanup`, `pruning`, `eviction` | MOVE-GAS-BLOAT-01 |
| `smart_table`, `hash collision`, `bucket` | MOVE-GAS-HASH-01 |
| `loop`, `iteration`, `pagination`, `unbounded`, `while` | MOVE-GAS-LOOP-01 |
| `dead code`, `unused`, `redundant`, `tautological` | MOVE-GAS-REDUN-01 |
| `error code`, `abort`, `assert`, `error handling` | MOVE-GEN-ABORT-01 |
| `vector`, `table`, `data structure`, `swap_remove`, `index` | MOVE-GEN-DATA-01 |
| `event`, `emit`, `EventHandle`, `event::emit` | MOVE-GEN-EVT-01 |
| `init_module`, `initialize`, `setup`, `front-run` | MOVE-GEN-INIT-01 |
| `resource`, `move_from`, `move_to`, `store`, `cleanup` | MOVE-GEN-RES-01 |
| `stale`, `cache`, `accrue`, `settle`, `parameter update` | MOVE-GEN-STALE-01 |
| `state`, `consistency`, `counter`, `aggregate`, `atomic` | MOVE-GEN-STATE-01 |
| `timestamp`, `deadline`, `expiry`, `time`, `microseconds` | MOVE-GEN-TIME-01 |
| `generic`, `phantom`, `type parameter`, `Coin<T>`, `type_info` | MOVE-GEN-TYPE-01 |
| `liquidation`, `health factor`, `collateral`, `seizure` | MOVE-LEND-LIQ-01, MOVE-LEND-LIQ-02 |
| `pause`, `unpause`, `grace period`, `denylist repay` | MOVE-LEND-PAUSE-01 |
| `cast`, `downcast`, `u128`, `u64`, `narrowing` | MOVE-MATH-CAST-01 |
| `formula`, `ratio`, `denominator`, `constant`, `convergence` | MOVE-MATH-FORM-01 |
| `overflow`, `underflow`, `arithmetic`, `multiply`, `subtract` | MOVE-MATH-OVF-01 |
| `precision`, `rounding`, `division`, `truncation`, `dust` | MOVE-MATH-PREC-01 |
| `scaling`, `normalization`, `decimal`, `10^`, `power` | MOVE-MATH-SCALE-01 |
| `ability`, `copy`, `drop`, `store`, `key`, `struct` | MOVE-OBJ-ABIL-01 |
| `SignerCapability`, `ConstructorRef`, `object`, `resource account` | MOVE-OBJ-APTOS-01 |
| `FungibleAsset`, `Coin`, `framework`, `conversion` | MOVE-OBJ-APTOS-02 |
| `hot potato`, `receipt`, `flash`, `zero abilities` | MOVE-OBJ-HOT-01 |
| `oracle admin`, `price feed admin`, `single updater` | MOVE-ORACLE-ADMIN-01 |
| `oracle aggregation`, `feed`, `duplicate`, `uniqueness` | MOVE-ORACLE-AGG-01 |
| `oracle defi`, `price manipulation`, `TWAP`, `circuit breaker` | MOVE-ORACLE-DEFI-01 |
| `oracle freshness`, `staleness`, `timestamp check` | MOVE-ORACLE-FRESH-01 |
| `spot price`, `reserve ratio`, `instantaneous price` | MOVE-ORACLE-PRICE-01 |
| `pool accounting`, `share`, `exchange rate`, `health` | MOVE-POOL-ACCT-01 |
| `AMM`, `swap`, `constant product`, `slippage`, `invariant` | MOVE-POOL-AMM-01 |
| `flash loan`, `repayment`, `hot potato`, `borrow` | MOVE-POOL-FLASH-01 |
| `pool init`, `first depositor`, `initial liquidity` | MOVE-POOL-INIT-01 |
| `LP token`, `mint`, `share price`, `donation attack` | MOVE-POOL-LP-01 |
| `reward`, `accumulator`, `staking reward`, `accrual` | MOVE-POOL-REWD-01 |
| `routing`, `multi-hop`, `intermediate token` | MOVE-POOL-ROUTE-01 |
| `flash stake`, `stake duration`, `minimum lock` | MOVE-POOL-STAKE-01 |
| `vault`, `share accounting`, `first depositor`, `ERC4626` | MOVE-VAULT-SHARE-01 |
| `vault sync`, `dual accounting`, `double subtraction` | MOVE-VAULT-SYNC-01 |

## Context → Category Table

| Context Tag | Categories |
|---|---|
| `ctx:generic` | ACC, GAS, GEN, MATH, OBJ, CRYPTO |
| `ctx:defi` | All categories |
| `ctx:nft` | ACC, GAS, GEN, MATH, OBJ |
| `ctx:lending` | ACC, COIN, GAS, GEN, LEND, MATH, OBJ, ORACLE |
| `ctx:pool` | ACC, COIN, GAS, GEN, MATH, OBJ, ORACLE, POOL |
| `ctx:vault` | ACC, COIN, GAS, GEN, MATH, OBJ, ORACLE, VAULT |
| `ctx:oracle` | ACC, GEN, ORACLE |
