# Rulepack — Move / Aptos

49 skill detectors across 11 categories.

Each rule below maps to a full detector in `checklists/categories/CAT-*.md`.

## MOVE-ACC-AUTH-01
- **Title:** Access Control Enforcement Invariant
- **Severity default:** medium-critical
- **Trigger idea:** For every module: (1) verify privileged functions have signer or capability checks, (2) verify no `public` where `public(friend)` is intended and no `public(friend) entry` without explicit auth, (3) verify no gaps in access control across same-privilege entry points and pause enforcement is consistent, (4) verify object ownership before mutation, (5) verify generic type parameters are not used as sole authorization mechanism, (6) verify no test/debug functions are published without `#[test_only]`.
- **Counter-evidence:** Add signer or capability checks to every privileged function. Fix visibility modifiers. Centralize pause checks. Validate object ownership. Use explicit capability patterns. Gate test/debug functions with `#[test_only]`.

## MOVE-ACC-CENT-01
- **Title:** Centralization Risk — Design-Inherent Admin Authority
- **Severity default:** informational
- **Trigger idea:** For every admin-gated function: assess whether the admin's power is proportionate. Flag as informational if admin could cause disproportionate harm (drain funds, brick protocol) with no safeguard beyond key security.
- **Counter-evidence:** Implement multi-sig, timelocks, supply caps, rate limits, and permissionless emergency exits to reduce trust assumptions.

## MOVE-ACC-CENT-02
- **Title:** Centralization Risk — Missing Operational Safeguard
- **Severity default:** low-medium (context-dependent)
- **Trigger idea:** For every admin power that restricts user state: (1) verify a corresponding release/reverse function exists, (2) verify granted capabilities can be revoked, (3) verify emergency powers have equivalent safeguards, (4) verify state deletion validates preconditions.
- **Counter-evidence:** Implement symmetric operations (freeze/unfreeze, grant/revoke), add precondition checks on deletions, and ensure emergency powers have multi-sig or governance equivalents.

## MOVE-ACC-LIST-01
- **Title:** Whitelist / Blacklist Consistency Invariant
- **Severity default:** medium-high (context-dependent)
- **Trigger idea:** (1) Map all entry points and verify list check is called at each, (2) verify boolean polarity of contains() checks, (3) verify list state persists across epoch/committee rotations, (4) verify bitmask set/unset operations are symmetric.
- **Counter-evidence:** Centralize list checks. Verify polarity. Decouple list storage from rotating state. Ensure symmetric bitmask operations.

## MOVE-ACC-OWNER-01
- **Title:** Ownership & Role Transfer Invariant
- **Severity default:** medium-high
- **Trigger idea:** For every privileged role: (1) verify a transfer function exists, (2) verify it is 2-step with recipient validation, (3) verify pending state is cancellable and role-specific, (4) verify liveness (cancel/restart possible), (5) verify no hardcoded address literals in auth checks.
- **Counter-evidence:** Implement 2-step propose/accept for all roles. Use dynamic state lookup. Validate recipients. Make pending state cancellable and role-specific.

## MOVE-ACC-VALID-01
- **Title:** Input Validation Invariant for Setters and Configuration
- **Severity default:** informational-medium
- **Trigger idea:** For every setter/update/config function: (1) check if zero/empty values are rejected when nonsensical, (2) check if upper bounds exist for rates/thresholds/multipliers, (3) check semantic validity (format, uniqueness, length), (4) check setter validation matches what consumer logic expects.
- **Counter-evidence:** Add assert! checks for non-zero, bounds, format, uniqueness, and consistency at every setter entry point.

## MOVE-COIN-HAND-01
- **Title:** Coin/Token Handling Invariant
- **Severity default:** medium-high
- **Trigger idea:** For every coin/fungible asset operation: (1) verify non-zero amounts on coin operations, (2) verify extraction amounts do not exceed available balance, (3) verify fungible asset metadata is initialized, (4) verify full extraction to avoid dust accumulation.
- **Counter-evidence:** Reject zero-amount operations. Validate extraction amounts against available balance. Initialize fungible asset metadata before use. Handle full extraction to avoid dust.

## MOVE-COIN-SCALE-01
- **Title:** Decimal Precision Invariant
- **Severity default:** high-critical
- **Trigger idea:** For every cross-asset arithmetic operation: (1) verify decimal precisions are normalized before comparison or calculation, (2) verify time constants use correct units matching the runtime API.
- **Counter-evidence:** Normalize all values to a common precision at computation boundaries and verify time constants match runtime units.

## MOVE-CRYPTO-SIG-01
- **Title:** Signature & Proof Verification Invariant
- **Severity default:** medium-critical
- **Trigger idea:** For every on-chain signature/proof/merkle verification path: (1) verify replay protection via consumed nonce/nullifier/claimed-set, (2) verify domain separation binding to contract+chain+action, (3) verify all outcome-affecting parameters are in the signed payload, (4) verify merkle proofs use double-hashed leaves, canonical ordering, and claim tracking, (5) verify digest field order and encoding matches off-chain schema.
- **Counter-evidence:** Implement nonce-based replay protection, add domain separators, include all parameters in signed messages, double-hash merkle leaves with canonical ordering, and verify digest reconstruction matches the signing schema.

## MOVE-GAS-BLOAT-01
- **Title:** Storage Growth / State Bloat Invariant
- **Severity default:** low-medium (context-dependent)
- **Trigger idea:** For every dynamically growing data structure: (1) verify a cleanup/removal mechanism exists, (2) verify global storage resources won't grow unbounded, (3) check for stale/ghost entries after logical deletion, (4) verify event emission is bounded per transaction.
- **Counter-evidence:** Implement pruning, expiration-based eviction, size caps, and cleanup functions for all growing collections.

## MOVE-GAS-HASH-01
- **Title:** Hash Collision Denial of Service in SmartTable
- **Severity default:** low
- **Trigger idea:** Identify usage of `aptos_std::smart_table` or custom hash-maps where keys are user-provided. Check if the hash function is susceptible to pre-image/collision attacks that could saturate specific storage buckets.
- **Counter-evidence:** Ensure the underlying storage structure is resilient to clustering or use a more distributed storage pattern like per-account resources or `aptos_std::table::Table`.

## MOVE-GAS-LOOP-01
- **Title:** Unbounded Iteration Invariant
- **Severity default:** medium-critical (context-dependent)
- **Trigger idea:** For every loop in the codebase: (1) identify what determines the iteration count, (2) verify it has a cap, pagination, or is bounded by a constant, (3) check if external users can grow the iterated collection, (4) check for missing increments or missing early termination.
- **Counter-evidence:** Implement pagination, cap collection sizes, use O(1) data structures for lookups, and ensure all loop paths increment the iterator.

## MOVE-GAS-REDUN-01
- **Title:** Redundant Code / Gas Waste Invariant
- **Severity default:** informational-low
- **Trigger idea:** Scan for: (1) state writes without equality pre-check, (2) unused functions/constants/parameters/imports, (3) tautological assertions or redundant checks.
- **Counter-evidence:** Remove dead code, add equality checks before state writes, eliminate tautological assertions.

## MOVE-GEN-ABORT-01
- **Title:** Error Handling Invariant
- **Severity default:** informational-low
- **Trigger idea:** For every module: verify all error codes are unique across all `assert!` and `abort` statements.
- **Counter-evidence:** Use unique named error code constants for every assertion across the module.

## MOVE-GEN-DATA-01
- **Title:** Data Structure Invariant
- **Severity default:** low-high
- **Trigger idea:** For every collection operation: (1) verify vectors have growth caps or use bounded alternatives, (2) verify index access is bounds-checked, (3) verify table insertions check for existing keys, (4) verify swap_remove is not used when order matters, (5) verify correlated collections are cleaned up together.
- **Counter-evidence:** Cap vector lengths. Validate indices before access. Check key existence before table insertion. Use indexed removal only when order is irrelevant. Clean up all correlated collections on deletion.

## MOVE-GEN-EVT-01
- **Title:** Event Emission Invariant
- **Severity default:** informational-low
- **Trigger idea:** For every state-modifying function: (1) verify an event is emitted, (2) verify event parameters match post-mutation state, (3) verify event handles are registered in `init_module`, (4) verify event struct fields capture full operation context, (5) verify all conditional branches emit events.
- **Counter-evidence:** Emit events for all state changes. Use post-mutation values. Register event handles in `init_module`. Ensure event struct fields match recorded data. Cover all conditional branches with event emission.

## MOVE-GEN-INIT-01
- **Title:** Initialization Safety Invariant
- **Severity default:** medium-high
- **Trigger idea:** For every module initialization: (1) verify `init_module` exists for modules requiring setup resources, (2) verify public initializers are not front-runnable, (3) verify all required resources are created in `init_module`, (4) verify setup functions cannot be called again to reset state, (5) verify `init_module` does not depend on external resources that may not exist.
- **Counter-evidence:** Use `init_module` for all required setup. Protect public initializers with deployer checks. Initialize all required resources completely. Guard against re-initialization. Minimize external dependencies during init.

## MOVE-GEN-RES-01
- **Title:** Resource Management Invariant
- **Severity default:** medium-critical
- **Trigger idea:** For every resource operation: (1) verify all associated data is cleaned up on `move_from`, (2) verify transferable resources have `store` ability, (3) verify `move_to` is guarded against double publication, (4) verify resources remain accessible after module upgrades.
- **Counter-evidence:** Clean up all associated data on removal. Ensure transferable resources have `store`. Guard `move_to` with existence checks. Plan resource migration for upgrades.

## MOVE-GEN-STALE-01
- **Title:** State Freshness Invariant
- **Severity default:** medium-high
- **Trigger idea:** For every parameter update or cached state write-back: (1) verify state is accrued/settled under old parameters before applying new ones, (2) verify local state caches are not written back after intermediate mutations.
- **Counter-evidence:** Accrue before parameter updates. Re-read state after any mutation instead of using cached copies.

## MOVE-GEN-STATE-01
- **Title:** State Consistency Invariant
- **Severity default:** medium-high
- **Trigger idea:** For every state mutation: (1) verify all coupled struct fields are updated together, (2) verify no stale references are held across table mutations, (3) verify counters/totals are maintained on every add/remove, (4) verify global aggregates stay synchronized with individual state changes, (5) verify multi-resource updates validate preconditions before any mutation.
- **Counter-evidence:** Update all coupled fields atomically. Avoid holding references across mutations. Maintain counter/total invariants on every add/remove. Synchronize global aggregates with individual state changes. Validate all preconditions before beginning mutations.

## MOVE-GEN-TIME-01
- **Title:** Timestamp/Deadline Invariant
- **Severity default:** low-high
- **Trigger idea:** For every time-dependent operation: (1) verify timestamp units are consistent (seconds vs microseconds), (2) verify stored deadlines are enforced before gated actions, (3) verify timestamps are fresh for time-sensitive decisions, (4) verify comparison operators at time boundaries are correct.
- **Counter-evidence:** Use consistent timestamp units throughout. Enforce deadlines before allowing gated actions. Refresh timestamps for long operations. Use correct comparison operators at boundaries.

## MOVE-GEN-TYPE-01
- **Title:** Type Safety Invariant
- **Severity default:** medium-high
- **Trigger idea:** For every generic type parameter: (1) verify it has appropriate ability constraints, (2) verify phantom types have runtime validation preventing cross-type operations, (3) verify coin types are checked with `is_coin_initialized`, (4) verify generic instantiation cannot access unrelated storage, (5) verify coin registration before operations on `Coin<T>`.
- **Counter-evidence:** Constrain generic types with required abilities. Validate phantom types with runtime checks or witness patterns. Verify type registration with `type_info` or coin registry. Prevent cross-type access via per-type storage isolation. Check coin initialization before operations.

## MOVE-LEND-LIQ-01
- **Title:** Liquidation Logic Integrity Invariant
- **Severity default:** low-critical
- **Trigger idea:** For every liquidation path: (1) verify health factor / eligibility is checked before seizure, (2) verify liquidation cap and bonus math uses correct scaling, (3) verify dust positions are handled to avoid deadlocks, (4) verify post-operation solvency on all collateral reductions.
- **Counter-evidence:** Enforce pre-liquidation health checks, correct bonus arithmetic, dust-aware partial liquidation, and post-operation solvency verification.

## MOVE-LEND-LIQ-02
- **Title:** Advanced Liquidation Mechanics Invariant
- **Severity default:** medium-critical
- **Trigger idea:** For every liquidation path: (1) verify liquidation bonus exists and exceeds gas costs, (2) verify self-liquidation is blocked or unprofitable, (3) verify minimum position sizes prevent dust accumulation, (4) verify bad debt is socialized through insurance or shared loss, (5) verify interest freezes during protocol pause or grace period exists post-unpause.
- **Counter-evidence:** Implement meaningful liquidation bonus, block self-liquidation, enforce minimum position sizes, socialize bad debt via insurance fund, and freeze interest during pause with grace period on unpause.

## MOVE-LEND-PAUSE-01
- **Title:** Lending Pause & Recovery Invariant
- **Severity default:** medium-critical
- **Trigger idea:** For every lending pause and recovery path: (1) verify pause is symmetric across repay and liquidation, (2) verify repayment is possible for denylisted addresses via proxy, (3) verify grace period exists before liquidation, (4) verify debt objects cannot be transferred to unwilling recipients, (5) verify refinancing settles accrued interest and enforces cooldown.
- **Counter-evidence:** Implement symmetric pause, proxy repayment, grace periods, unforgeable debt binding, and cooldown-gated refinancing with interest settlement.

## MOVE-MATH-CAST-01
- **Title:** Unsafe Type Casting
- **Severity default:** low-high
- **Trigger idea:** For every type cast operation: (1) check u128-to-u64 downcasts for overflow assertion, (2) check signed-to-unsigned conversions for negative value handling, (3) check bit-width boundary validations for off-by-one, (4) check math utility return paths for unchecked narrowing casts, (5) check custom signed types for zero-sign normalization.
- **Counter-evidence:** Add explicit range assertions before every narrowing cast, handle negative values before signed-to-unsigned conversion, and normalize signed zero.

## MOVE-MATH-FORM-01
- **Title:** Incorrect Mathematical Formula and Logic
- **Severity default:** low-critical
- **Trigger idea:** For every mathematical formula: (1) check that numerator/denominator ordering matches the intended ratio, (2) check that hardcoded constants match their canonical values, (3) check that compound operations follow correct mathematical order, (4) check that all divisors are validated non-zero, (5) check that iterative algorithms verify convergence correctly.
- **Counter-evidence:** Verify formulas against specifications, use named constants from verified libraries, validate divisors, and test convergence on return values.

## MOVE-MATH-OVF-01
- **Title:** Arithmetic Overflow and Underflow
- **Severity default:** medium-critical
- **Trigger idea:** For every arithmetic operation: (1) check multiplications for intermediate overflow without upcasting, (2) check subtractions for underflow without guards, (3) check accumulators for unbounded growth, (4) check custom signed math for sign-boundary overflow, (5) check bitwise shifts for out-of-range shift amounts.
- **Counter-evidence:** Use wider intermediate types, saturating arithmetic, conditional guards, and range validation for all arithmetic operations.

## MOVE-MATH-PREC-01
- **Title:** Precision Loss and Rounding Errors
- **Severity default:** low-high
- **Trigger idea:** For every division operation: (1) check that all multiplications precede the division, (2) check that the precision factor is large enough for the value range, (3) check that rounding direction is asymmetric (favors protocol on both deposit and withdraw), (4) check that zero-truncation on small values is handled, (5) check that sqrt/pow is applied after maximizing the intermediate product.
- **Counter-evidence:** Reorder to multiply-first-divide-last, increase precision factors, enforce asymmetric rounding, reject dust, and defer lossy operations.

## MOVE-MATH-SCALE-01
- **Title:** Decimal Scaling and Normalization Errors
- **Severity default:** medium-critical
- **Trigger idea:** For every scaling or normalization operation: (1) check that precision factors are applied exactly once across the call chain, (2) check that multiplied precision factors are divided back before returning, (3) check that numerator and denominator operands share the same decimal scale, (4) check for hardcoded decimal constants that may not match token metadata, (5) check that decimal values from external sources are validated.
- **Counter-evidence:** Centralize normalization logic, validate decimal metadata on-chain, and ensure consistent scaling across all operands.

## MOVE-OBJ-ABIL-01
- **Title:** Ability & Type Safety Invariant
- **Severity default:** high-critical
- **Trigger idea:** For every struct definition: (1) verify value-bearing resources (coins, NFTs, badges) never have copy ability, (2) verify obligation resources (debts, receipts, locks) never have drop ability, (3) verify sensitive capabilities have `key` only (no `store`) unless nesting is intentional, (4) verify all generic type parameters are validated against stored or whitelisted types, (5) verify phantom types enforce per-type separation on all coin operations.
- **Counter-evidence:** Remove copy from value types. Remove drop from obligation types. Remove store from sensitive capabilities. Validate generics against whitelists or phantom-parameterized containers. Enforce per-type balance isolation.

## MOVE-OBJ-APTOS-01
- **Title:** Aptos Resource & Object Invariant
- **Severity default:** medium-critical
- **Trigger idea:** For every Aptos module: (1) verify SignerCapability is stored with access control and all paths to create_signer_with_capability are admin-gated, (2) verify ConstructorRef is never returned or stored beyond the creating function, (3) verify independently-transferable resources have separate object accounts, (4) verify &mut references are re-validated after passing to untrusted code, (5) verify function value callbacks follow checks-effects-interactions and bind critical values in non-droppable structs.
- **Counter-evidence:** Admin-gate SignerCapability usage. Scope ConstructorRef to creating function. Separate object accounts per resource. Re-validate after untrusted mutation. Use checks-effects-interactions with non-droppable Grants.

## MOVE-OBJ-APTOS-02
- **Title:** Aptos Framework Safety Invariant
- **Severity default:** medium-high
- **Trigger idea:** For every Aptos module: (1) verify a single asset framework is used consistently (Coin or FungibleAsset) with proper conversion.
- **Counter-evidence:** Use single framework with conversion bridge.

## MOVE-OBJ-HOT-01
- **Title:** Hot Potato Pattern Integrity
- **Severity default:** high-critical
- **Trigger idea:** For every hot potato struct: (1) verify it has zero abilities (no copy, drop, store, key), (2) verify start/borrow functions check for existing active operations, (3) verify receipt creation and consumption happen in the same module.
- **Counter-evidence:** Strip all abilities from receipt structs. Add active-operation guards. Keep receipt lifecycle in single module.

## MOVE-ORACLE-ADMIN-01
- **Title:** Oracle Administration Invariant
- **Severity default:** low-medium
- **Trigger idea:** Check if oracle price updates are restricted to a single administrative capability or account without multi-sig or decentralized validation.
- **Counter-evidence:** Implement multi-sig or decentralized oracle validation with quorum requirements.

## MOVE-ORACLE-AGG-01
- **Title:** Oracle Aggregation Integrity Invariant
- **Severity default:** medium-high
- **Trigger idea:** Search for loops processing signed data packages or oracle feeds where the feed identifier is used to update state or contribute to an aggregate without a uniqueness check.
- **Counter-evidence:** Enforce feed identifier uniqueness per aggregation round and validate each feed contribution is counted exactly once.

## MOVE-ORACLE-DEFI-01
- **Title:** Oracle DeFi Integration Invariant
- **Severity default:** medium-critical
- **Trigger idea:** For every oracle-dependent DeFi operation: (1) verify valuations use manipulation-resistant oracles not spot pool prices, (2) verify circuit breakers exist for abnormal price deviations, (3) verify wrapped/pegged assets have depeg detection, (4) verify price direction (A/B vs B/A) is correct at every usage, (5) verify slippage references come from off-chain or external TWAP not same-pool queries.
- **Counter-evidence:** Use external oracles for valuations, implement deviation circuit breakers, add depeg detection for wrapped assets, verify price direction at every integration, and require off-chain slippage parameters.

## MOVE-ORACLE-FRESH-01
- **Title:** Oracle Freshness Invariant
- **Severity default:** low-high
- **Trigger idea:** Search for all functions calling oracle read methods. Verify if the returned timestamp is checked against the current system clock using a maximum age threshold.
- **Counter-evidence:** Enforce maximum staleness threshold on every oracle read and reject stale data.

## MOVE-ORACLE-PRICE-01
- **Title:** Price Source Validation Invariant
- **Severity default:** medium-critical
- **Trigger idea:** Check if pricing, valuation, or fee logic relies on current reserve balances, instantaneous pool prices, or get_reserves calls without time-weighting or external oracle verification.
- **Counter-evidence:** Use time-weighted averages or external oracle feeds instead of instantaneous pool state for pricing decisions.

## MOVE-POOL-ACCT-01
- **Title:** Pool Accounting & Share Arithmetic Invariant
- **Severity default:** medium-critical
- **Trigger idea:** For every pool operation that modifies balances or shares: (1) verify share-asset conversions use exchange rate, (2) verify rounding direction favors protocol, (3) verify all fund outflows decrement internal accounting, (4) verify health calculations include total debt, (5) verify flash loan settlements separate principal from fee.
- **Counter-evidence:** Enforce bidirectional conversion on every share-asset boundary, protocol-favorable rounding on all debt arithmetic, matched accounting on every fund movement, and complete debt aggregation in every health computation.

## MOVE-POOL-AMM-01
- **Title:** AMM Invariant & Slippage Enforcement
- **Severity default:** low-critical
- **Trigger idea:** For every swap operation: (1) verify constant-product or curve invariant holds post-swap, (2) verify minimum output amount is enforced, (3) verify fee is deducted before invariant calculation, (4) verify no path allows invariant bypass.
- **Counter-evidence:** Enforce invariant check post-swap, require minimum output parameters, apply fees before invariant calculation, and audit all swap paths.

## MOVE-POOL-FLASH-01
- **Title:** Flash Loan Safety
- **Severity default:** low-critical
- **Trigger idea:** For every flash loan mechanism: (1) verify repayment check uses hot potato pattern, (2) verify fee is enforced on repayment, (3) verify borrowed amount cannot exceed pool balance, (4) verify flash loan cannot be used to manipulate pool state.
- **Counter-evidence:** Use hot potato receipts for repayment enforcement, validate fees, cap borrows to available balance, and snapshot state before flash operations.

## MOVE-POOL-INIT-01
- **Title:** Pool Initialization Safety
- **Severity default:** medium-critical
- **Trigger idea:** For every pool creation: (1) verify initial liquidity ratio is validated, (2) verify pool cannot be re-initialized, (3) verify first depositor cannot manipulate share price, (4) verify pool parameters are validated at creation.
- **Counter-evidence:** Validate initial ratios, guard against re-initialization, lock minimum initial liquidity, and validate all pool parameters.

## MOVE-POOL-LP-01
- **Title:** LP Token Integrity
- **Severity default:** low-high
- **Trigger idea:** For every LP/share minting operation: (1) verify minted amount is checked > 0, (2) verify coin split/join preserves total value, (3) verify first depositor cannot manipulate share price via donation.
- **Counter-evidence:** Assert non-zero minting. Use framework coin::split/join. Lock minimum initial liquidity.

## MOVE-POOL-REWD-01
- **Title:** Reward Accumulator Integrity
- **Severity default:** medium-critical
- **Trigger idea:** For every staking state mutation: (1) verify new users snapshot current accumulator index, (2) verify config changes trigger final accrual at old rate, (3) verify zero-supply periods buffer rewards, (4) verify reward claim asset types are validated against registry.
- **Counter-evidence:** Snapshot index on join; settle before config changes; buffer zero-supply rewards; validate claim asset types against registry.

## MOVE-POOL-ROUTE-01
- **Title:** Swap Routing Integrity
- **Severity default:** low-medium
- **Trigger idea:** For every multi-hop swap: (1) verify intermediate token types are validated, (2) verify routing cannot be exploited for arbitrage at protocol expense, (3) verify slippage is enforced on final output.
- **Counter-evidence:** Validate intermediate tokens, enforce end-to-end slippage, and prevent routing manipulation.

## MOVE-POOL-STAKE-01
- **Title:** Flash Stake Attack Invariant
- **Severity default:** medium-critical
- **Trigger idea:** For every staking state mutation: (1) verify minimum stake duration prevents flash deposit/withdraw, (2) verify reward accounting uses internal tracking not raw balance, (3) verify zero-value operations are rejected, (4) verify accumulator is updated before balance changes, (5) verify admin reward parameter changes trigger accumulator update first.
- **Counter-evidence:** Enforce minimum stake duration, separate staked/reward balances, reject zero-value operations, update accumulator before balance changes, and settle rewards before parameter modifications.

## MOVE-VAULT-SHARE-01
- **Title:** Share Accounting Invariant
- **Severity default:** low-critical
- **Trigger idea:** For every vault share/asset conversion path: (1) check first-depositor protection (virtual offsets, dead shares, minimum deposit), (2) verify rounding favors the protocol in all directions, (3) confirm fees are segregated from total_assets, (4) ensure total_shares and total_assets are updated symmetrically, (5) assert minted shares > 0 and initial ratios are validated, (6) confirm invariant checks are applied consistently across all entry points.
- **Counter-evidence:** Implement virtual offsets with dead shares, protocol-favorable rounding, fee segregation, atomic state updates, non-zero share assertions, and centralized invariant enforcement across all conversion paths.

## MOVE-VAULT-SYNC-01
- **Title:** State Synchronization Invariant
- **Severity default:** medium-high
- **Trigger idea:** For every dual-accounting state update: (1) verify no double-subtraction on same variable, (2) verify share burns update total_assets, (3) verify internal state syncs with external changes, (4) verify shared vaults track per-pool balances.
- **Counter-evidence:** Atomic dual-side updates; external state synchronization; per-pool vault isolation.
