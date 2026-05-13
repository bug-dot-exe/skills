# Checklist Router (Keyword to Rule Mapping)

Use this file in `S02_CHECKLIST_PLAN` to map natural-language checklist items to rulepack rule IDs.
This router is for inference only; it does not modify checklist text.

## Mapping priority

1. Explicit `MOVE-*` rule ID in checklist text
2. Router keyword mapping in this file
3. Fallback to `MOVE-AI` when no rulepack-equivalent exists

## Router table

| Keyword patterns (title/description) | Rule ID | Notes |
|---|---|---|
| signer, capability, access control, admin check, privilege | MOVE-ACC-AUTH-01 | Access control enforcement |
| centralization, single admin, admin authority, trust assumption | MOVE-ACC-CENT-01 | Centralization risk (design) |
| missing safeguard, no reverse, no unfreeze, emergency bypass | MOVE-ACC-CENT-02 | Centralization risk (operational) |
| whitelist, blacklist, allowlist, denylist | MOVE-ACC-LIST-01 | List consistency |
| ownership transfer, role transfer, admin rotation | MOVE-ACC-OWNER-01 | Ownership transfer |
| input validation, setter, configuration bounds | MOVE-ACC-VALID-01 | Input validation |
| coin handling, token handling, zero amount, dust | MOVE-COIN-HAND-01 | Coin handling |
| decimal, precision mismatch, cross-asset math | MOVE-COIN-SCALE-01 | Decimal precision |
| signature, proof, replay, merkle, domain separation | MOVE-CRYPTO-SIG-01 | Signature verification |
| storage bloat, state growth, cleanup, ghost entries | MOVE-GAS-BLOAT-01 | Storage bloat |
| hash collision, table, DoS | MOVE-GAS-HASH-01 | Hash collision DoS |
| unbounded loop, iteration, vector iteration, permissionless accumulation | MOVE-GAS-LOOP-01 | Unbounded iteration |
| redundant, dead code, gas waste, tautological | MOVE-GAS-REDUN-01 | Redundant code |
| error code, abort code, duplicate error | MOVE-GEN-ABORT-01 | Error handling |
| data structure, vector growth, index bounds, table collision, swap remove | MOVE-GEN-DATA-01 | Data structure |
| event emission, missing event, event handle | MOVE-GEN-EVT-01 | Event emission |
| initialization, init, re-initialization, race condition | MOVE-GEN-INIT-01 | Initialization |
| resource management, cleanup, orphaned | MOVE-GEN-RES-01 | Resource management |
| stale state, freshness, cache overwrite | MOVE-GEN-STALE-01 | State freshness |
| state consistency, partial update, counter mismatch, non-atomic | MOVE-GEN-STATE-01 | State consistency |
| timestamp, deadline, seconds vs milliseconds | MOVE-GEN-TIME-01 | Timestamp/deadline |
| type safety, generic type, phantom type | MOVE-GEN-TYPE-01 | Type safety |
| liquidation, eligibility, bonus math, dust position | MOVE-LEND-LIQ-01 | Liquidation logic |
| liquidation incentive, self-liquidation, bad debt | MOVE-LEND-LIQ-02 | Advanced liquidation |
| pause, recovery, denylist, grace period | MOVE-LEND-PAUSE-01 | Lending pause |
| overflow, underflow, accumulator | MOVE-MATH-OVF-01 | Arithmetic overflow |
| type casting, downcast, truncation | MOVE-MATH-CAST-01 | Unsafe casting |
| formula, inverted ratio, wrong operation, division by zero | MOVE-MATH-FORM-01 | Formula errors |
| precision, rounding, division before multiplication | MOVE-MATH-PREC-01 | Precision loss |
| decimal scaling, double scaling, normalization | MOVE-MATH-SCALE-01 | Scaling errors |
| ability, copy, drop, store, key, type safety | MOVE-OBJ-ABIL-01 | Ability safety |
| hot potato, drop ability, nested operation, cross-module | MOVE-OBJ-HOT-01 | Hot potato pattern |
| witness, OTW, publisher, one-time witness, TreasuryCap | MOVE-OBJ-WIT-01 | Witness pattern |
| oracle admin, centralization, unvalidated price update | MOVE-ORACLE-ADMIN-01 | Oracle admin |
| oracle aggregation, duplicate feed, non-deterministic | MOVE-ORACLE-AGG-01 | Oracle aggregation |
| flash loan manipulation, circuit breaker, depeg | MOVE-ORACLE-DEFI-01 | Oracle DeFi integration |
| oracle freshness, timestamp validation, staleness | MOVE-ORACLE-FRESH-01 | Oracle freshness |
| spot price, hardcoded peg, stableswap | MOVE-ORACLE-PRICE-01 | Price source validation |
| pool initialization, identical pair, minimum liquidity | MOVE-POOL-INIT-01 | Pool init safety |
| AMM, constant product, slippage, deadline | MOVE-POOL-AMM-01 | AMM invariant |
| flash loan, receipt, asset identifier | MOVE-POOL-FLASH-01 | Flash loan safety |
| pool accounting, share arithmetic, rounding | MOVE-POOL-ACCT-01 | Pool accounting |
| LP token, zero liquidity, first depositor | MOVE-POOL-LP-01 | LP token integrity |
| swap routing, output chaining, circuit breaker | MOVE-POOL-ROUTE-01 | Routing integrity |
| reward accumulator, reward index, zero supply | MOVE-POOL-REWD-01 | Reward integrity |
| flash stake, reward dilution, zero-value, stale index | MOVE-POOL-STAKE-01 | Flash stake attack |
| share accounting, first depositor, rounding direction, fee segregation | MOVE-VAULT-SHARE-01 | Vault share accounting |
| state sync, vault sync, balance update | MOVE-VAULT-SYNC-01 | Vault state sync |

## AI-only buckets (`MOVE-AI`)

When checklist item falls outside current rulepack coverage, map to `MOVE-AI`.

## Expected evidence hints

Use these hints to fill `expected_evidence` in `checklist.plan.min.json`:

- signer/auth: `tx_context::sender`, capability patterns, `assert!` checks
- objects: `transfer::transfer`, `transfer::public_transfer`, `transfer::share_object`, `transfer::freeze_object`
- shared objects: `&mut T` with shared object pattern
- witness: OTW struct (ALL_CAPS module name), `has drop` only
- coin/token: `coin::mint`, `coin::burn`, `coin::split`, `coin::join`, `balance::*`
- math: `*`, `/`, `as u64`, `as u128`, overflow patterns
- oracle: `get_price`, `pyth::`, `switchboard::`, timestamp checks
- pool: `swap`, `add_liquidity`, `remove_liquidity`, `flash_loan`
- events: `event::emit`, Sui event types
- dynamic fields: `dynamic_field::add`, `dynamic_object_field::add`
