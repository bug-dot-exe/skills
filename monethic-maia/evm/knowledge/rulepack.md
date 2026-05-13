# EVM / Solidity Rulepack

95 rules across 20 categories.

---

## EVM-ACC-AUTH-01

- Title: Privileged Function Access Control Invariant
- Severity default: medium-critical
- Trigger idea: For every contract: (1) identify all functions mutating state, transferring assets, emitting administrative events, or calling external contracts, (2) verify each has unconditional access control via modifier or require, (3) verify the role checked matches the function's purpose, (4) verify assertion logic is correct, (5) verify consistency across all entry points including proxy initialization and callbacks, (6) verify delegatecall/call/selfdestruct targets are validated.
- Counter-evidence: Enforce modifier-based or require-based access control on every privileged function. Centralize role checks. Verify assertion logic. Ensure checks are unconditional. Guard initialize() with initializer modifier. Validate delegatecall/call targets.

## EVM-ACC-CENT-01

- Title: Centralization Risk -- Admin Can Damage Protocol
- Severity default: low
- Trigger idea: For every admin-gated function: can the admin cause disproportionate harm (drain funds, brick protocol, inflate supply, manipulate prices) with no safeguard beyond key security? If yes, flag as low-severity centralization risk.
- Counter-evidence: Add multi-sig, timelocks, supply caps, rate limits, role separation, and permissionless emergency exits. The goal is to reduce the blast radius of a single compromised key.

## EVM-ACC-INPUT-01

- Title: Input Validation Invariant for Setters and Configuration
- Severity default: informational-medium
- Trigger idea: For every setter/update/constructor/config function: (1) check if zero/empty values are rejected when nonsensical, (2) check if upper bounds exist for rates/thresholds/multipliers, (3) check semantic validity (format, uniqueness, reserved values), (4) check for silent zero-address failures.
- Counter-evidence: Validate all inputs at the setter boundary: non-zero checks, upper/lower bounds, format validation, uniqueness checks, and consistency between setter and consumer logic. Apply the same validation in constructors as in runtime setters.

## EVM-ACC-LIST-01

- Title: Whitelist / Blacklist Consistency Invariant
- Severity default: medium-critical
- Trigger idea: (1) Enumerate ALL entry points: transfer, transferFrom, approve, permit, burn, burnFrom, mint, stake, claim, bridge. (2) For EACH, verify blocklist check is present. (3) Verify ALL THREE addresses checked: from, to, AND msg.sender — missing any one is a finding. (4) In transferFrom, specifically verify msg.sender is checked (most commonly missed). (5) Verify approve/permit check msg.sender and spender. (6) Verify boolean polarity. (7) Verify admin cannot self-exclude. (8) Verify entries are reversible. (9) Verify stale entries cleaned on state changes.
- Counter-evidence: Centralized check in _update (OZ v5) or _beforeTokenTransfer (OZ v4) hook validating from+to+msg.sender. approve/permit also check both parties. Boolean polarity correct. Admin self-exclusion prevented. Entries reversible.

## EVM-ACC-OWN-01

- Title: Ownership & Role Transfer Invariant
- Severity default: medium-high
- Trigger idea: For every privileged role: (1) verify a transfer/update function exists, (2) verify it is 2-step, (3) verify zero-address rejection, (4) verify stale pending state is handled, (5) verify renounceOwnership is safe or disabled, (6) verify last-admin self-removal is prevented, (7) verify multisig threshold consistency after member changes, (8) verify no hardcoded address literals in auth checks.
- Counter-evidence: Implement Ownable2Step for all roles. Validate recipients. Clear stale proposals. Override renounceOwnership to revert when admin functions exist. Sync thresholds. Use dynamic state lookup.

## EVM-ACC-PAUSE-01

- Title: Pause Mechanism Invariant
- Severity default: medium-high
- Trigger idea: (1) Identify the pause flag/mechanism, (2) list ALL public/external state-changing functions, (3) verify each has the whenNotPaused modifier, (4) verify unpause/unfreeze exists for every pause/freeze toggle, (5) verify emergency exit exists for users when paused -- check that exit functions (withdraw, redeem, claim) are not blocked by whenNotPaused without an alternative path, (6) verify no conflicting multi-role pause control.
- Counter-evidence: Centralize pause checks into the whenNotPaused modifier. Apply it to every state-changing function. Implement a permissionless emergency withdrawal that works even when paused. Ensure an unpause() or unfreeze() function exists for every restrictive toggle.

## EVM-ACC-SIG-01

- Title: Signature & Authentication Invariant
- Severity default: medium-critical
- Trigger idea: For every signature verification: (1) verify ecrecover result is checked against address(0), (2) verify nonce is included and incremented, (3) verify EIP-712 domain separator with chainId is used, (4) verify no tx.origin authentication, (5) verify s-value malleability prevention, (6) verify deadline exists, (7) verify ERC-1271 delegation targets are trusted, (8) verify ERC-4337 entry point checks, (9) verify meta-transaction signer extraction.
- Counter-evidence: Always check ecrecover result against address(0). Include nonce, chain ID (EIP-712 domain separator), and deadline in signed data. Never use tx.origin for authentication. Enforce s-value range for malleability prevention. Validate ERC-1271 delegation targets. Use OpenZeppelin ECDSA library with EIP-712.

## EVM-ASM-CALL-01

- Title: Assembly Call & Control Flow Integrity
- Severity default: low-critical
- Trigger idea: For every inline assembly block that uses `call`, `delegatecall`, or `staticcall`: (1) verify the return value is not wrapped in `iszero()` before assignment and revert conditions are not inverted, (2) verify the return value is not discarded via `pop()` or left unchecked, (3) verify the target address is validated against `address(0)` and checked for code via `extcodesize`.
- Counter-evidence: Always validate the return value of call, delegatecall, and staticcall opcodes in assembly. Use `if iszero(result) { revert(0, 0) }` to revert on failure. Never wrap call results in iszero() before assigning to a success variable. Validate target addresses against address(0) and check extcodesize before calling.

## EVM-ASM-MEM-01

- Title: Assembly Memory & Data Integrity
- Severity default: low-medium
- Trigger idea: For every inline assembly block that performs memory or storage operations: (1) verify sub-256-bit types are masked before `mstore` and `keccak256` length covers all stored slots, (2) verify packed storage writes use `sload` + bitmask for partial updates and unpacking applies bitwise shifts, (3) verify memory copy loops validate source buffer length before iteration, (4) verify no `mstore(0x40, ...)` writes non-pointer data to the free memory pointer, (5) verify key derivation uses correct offsets without bit-field overlaps or address truncation.
- Counter-evidence: Mask sub-word types before memory operations. Match keccak256 length to actual data. Use sload+mask for partial storage writes. Validate copy bounds. Use scratch space (0x00-0x3f) instead of 0x40. Use abi.encodePacked for key derivation or verify manual offsets are correct.

## EVM-CRYPTO-RNG-01

- Title: Randomness Invariant
- Severity default: critical
- Trigger idea: Check that randomness generation enforces all five layers: (1) no block.timestamp, block.number, block.prevrandao, or blockhash used as entropy sources, (2) VRF request and fulfillment in separate transactions with state snapshot at request time, (3) re-request prevention for same outcome context, (4) modulo applied as final operation without subsequent scaling, (5) callback value validated as non-zero with matching requestId.
- Counter-evidence: Enforce all five sub-checks as a single randomness invariant. Never use block variables for entropy. Separate VRF request and fulfillment into distinct transactions with state snapshots at request time. Prevent re-requests for the same outcome. Apply modulo as the final operation. Validate callback values.

## EVM-CRYPTO-SIG-01

- Title: Signature & Proof Verification Invariant
- Severity default: critical
- Trigger idea: Check that signature and proof verification enforces all layers: (1) low-s malleability rejection, (2) nonce consumption + deadline + domain separator with chainId and contract address, (3) complete EIP-712 struct hash binding all state-changing parameters and signer identity, (4) recovered address != address(0) check before comparison, (5) current OpenZeppelin ECDSA version without manual v/r/s parsing, (6) Merkle proofs use double-hashed leaves bound to msg.sender with domain separation, claim tracking, and proof depth validation.
- Counter-evidence: Use OpenZeppelin ECDSA.recover with EIP-712 structured data. Include nonce, deadline, chainId, and contract address in the domain. Bind all parameters in the type hash. Always check recovered != address(0). For Merkle proofs, double-hash leaves, bind to msg.sender, include domain separators, track claims, and validate proof depth.

## EVM-DEX-AMM-01

- Title: AMM Formula & Invariant Correctness
- Severity default: high
- Trigger idea: For every AMM or bonding curve implementation: (1) verify the core invariant (xy=k, weighted product, stableswap) is preserved after each swap with correct rounding, (2) verify buy vs sell pricing uses asymmetric rounding favoring the protocol, (3) check formula edge cases (zero coefficients, extreme ratios, tick boundaries), (4) compare view/quote function math against actual execution path, (5) verify first-depositor protection (minimum burned liquidity, validated initial ratio).
- Counter-evidence: Use asymmetric rounding (ceil for inputs, floor for outputs), one-sided invariant checks, edge case handling for degenerate formulas, shared calculation logic for views and execution, and minimum burned liquidity for initial deposits.

## EVM-DEX-FEE-01

- Title: DEX Fee Accounting Invariant
- Severity default: medium-high
- Trigger idea: For every DEX fee mechanism: (1) verify fees are deducted at the correct point relative to the invariant calculation, (2) check fee distribution targets have active liquidity (totalSupply > 0), (3) verify the sum of all fee components cannot exceed a safe maximum, (4) check fee precision matches the token's decimal scale, (5) verify all swap paths and token directions trigger fee collection.
- Counter-evidence: Deduct fees before or consistently after invariant evaluation. Guard fee distribution with totalSupply checks. Cap aggregate fee rates. Match fee precision to token decimals. Apply fees unconditionally across all swap directions and paths.

## EVM-DEX-POOL-01

- Title: Pool Management & Integrity Invariant
- Severity default: medium-high
- Trigger idea: For every pool factory and pool lifecycle: (1) verify token pair uniqueness with canonical ordering, (2) verify all token addresses in a pool are distinct and non-zero, (3) verify factory parameters are validated before forwarding to pool implementation, (4) check whether pool reserves or balances are readable/writable during flash operations, (5) verify per-pool isolation of timelocks, LP tokens, and accounting state.
- Counter-evidence: Enforce pair uniqueness with canonical token ordering and pairwise distinctness. Validate all factory parameters. Protect pool state during flash operations with reentrancy guards and internal accounting. Isolate all per-pool state variables.

## EVM-DEX-SLIP-01

- Title: Slippage & Deadline Protection Invariant
- Severity default: medium-high
- Trigger idea: For every function that executes a swap or modifies a liquidity position: (1) verify user-supplied slippage parameter exists, (2) verify deadline parameter is not block.timestamp, (3) verify slippage is not hardcoded, (4) verify slippage units match the token being checked, (5) verify multi-step operations have cumulative slippage bounds.
- Counter-evidence: Accept user-supplied minAmountOut and deadline on every swap and liquidity operation. Never hardcode slippage or use block.timestamp as deadline. Use oracle prices (not spot) for on-chain slippage calculation. Validate cumulative slippage across multi-step operations.

## EVM-ERC20-COMPAT-01

- Title: ERC-20 Token Compatibility Invariant
- Severity default: medium-high
- Trigger idea: For every ERC-20 integration: (1) verify approval patterns handle non-zero allowance reset and stale approvals are revoked on migration, (2) verify decimal handling queries dynamically and handles >18 decimals, (3) verify blocklist/pausable tokens use pull patterns and have rescue functions, (4) verify permit calls are wrapped in try/catch to handle front-running, (5) verify double-entry tokens are mapped canonically and sweep functions check secondary addresses.
- Counter-evidence: Use forceApprove and revoke on migration. Query decimals dynamically. Use pull patterns for blocklist-sensitive flows. Wrap permit in try/catch. Map canonical token addresses.

## EVM-ERC20-TRANSFER-01

- Title: ERC-20 Token Transfer Integrity Invariant
- Severity default: medium-high
- Trigger idea: For every ERC-20 transfer: (1) verify SafeERC20 or equivalent is used for all transfer/transferFrom/approve calls, (2) verify amount accounting uses balance-delta measurement for FOT/rebasing tokens, (3) verify reentrancy guards protect against ERC-777/1363 hooks with CEI pattern, (4) verify self-transfers (from==to) are handled without cached-balance corruption, (5) verify zero-amount and zero-address edge cases are guarded.
- Counter-evidence: Use SafeERC20. Measure via balance delta. Apply nonReentrant + CEI. Handle self-transfers. Guard zero amounts and addresses.

## EVM-GAS-CONST-01

- Title: Constants, Immutables & Compiler Hints Invariant
- Severity default: gas
- Trigger idea: For every contract: (1) check for state variables that should be constant or immutable, (2) check for memory parameters that could use calldata, (3) check for require strings that should be custom errors, (4) check for SafeMath usage in Solidity >=0.8, (5) check for magic numbers without named constants.
- Counter-evidence: Use constant/immutable for fixed values. Use calldata for read-only parameters. Use custom errors. Remove SafeMath in >=0.8. Define named constants for all literals.

## EVM-GAS-LOOP-01

- Title: Loop & Iteration Invariant
- Severity default: gas
- Trigger idea: For every loop: (1) verify the iteration count is bounded and cannot be grown by external users, (2) verify array length is cached before the loop, (3) verify the loop counter uses unchecked increment (Solidity >=0.8), (4) verify no state variables are written inside the loop body, (5) verify no O(n^2) patterns exist (nested loops, linear search for membership/removal).
- Counter-evidence: Cap loop iterations or use pull patterns. Cache array length. Use unchecked increment. Accumulate in memory and write once after loop. Replace linear search with mappings.

## EVM-GAS-REDUN-01

- Title: Redundant Code & Dead Code Invariant
- Severity default: gas
- Trigger idea: For every contract: (1) check for unused state variables, functions, imports, and inherited contracts, (2) check for identity arithmetic and redundant computations, (3) check for duplicate code across conditional branches, (4) check for unnecessary intermediate external calls or token transfer hops, (5) check for commented-out code, TODOs, and debug artifacts.
- Counter-evidence: Remove unused variables, functions, imports, and inheritance. Simplify identity arithmetic. Consolidate duplicate branches. Eliminate intermediate operations. Clean debug artifacts.

## EVM-GAS-SLOAD-01

- Title: Storage Read Caching Invariant
- Severity default: gas
- Trigger idea: For every function: (1) check if any state variable is read more than once without caching, (2) check if modifier and function body read the same variable, (3) check for state variable reads inside loops, (4) check for individual struct field reads instead of memory load, (5) check for repeated external calls to immutable values.
- Counter-evidence: Cache storage variables in local memory/stack variables at function entry. Load full structs into memory. Cache immutable external values at deployment. Re-use cached values throughout the function.

## EVM-GAS-SSTORE-01

- Title: Storage Write & Layout Invariant
- Severity default: gas
- Trigger idea: For every contract: (1) check if state variable declarations can be reordered for tighter slot packing, (2) check for redundant writes to the same slot in a single execution, (3) check for missing delete/zeroing on removed entries, (4) check for state variables that duplicate derivable values, (5) check for sub-uint256 types used outside of packed slot groups.
- Counter-evidence: Pack variables into shared slots. Eliminate redundant writes and derivable state variables. Use delete for removal. Use uint256 unless variables share a slot.

## EVM-GAS-VALID-01

- Title: Validation Ordering & Short-Circuit Invariant
- Severity default: gas
- Trigger idea: For every function with validation logic: (1) verify cheap checks (msg.sender, msg.value, calldata) precede expensive checks (SLOAD, external calls), (2) verify no duplicate checks exist across caller/callee or modifier/body, (3) verify early exits for zero-value or no-op inputs, (4) verify no impossible-to-fail checks exist (msg.sender != 0, bounds inside loops), (5) verify short-circuit conditions order cheap/likely before expensive/unlikely.
- Counter-evidence: Order checks cheapest-first. Remove duplicate checks in internal calls. Add early returns for no-ops. Remove impossible checks. Place cheap/likely conditions first in compound expressions.

## EVM-GEN-AUTH-01

- Title: Authorization Invariant
- Severity default: medium-critical
- Trigger idea: For every privileged operation: (1) verify access control modifier or require check is present, (2) verify all similar functions have consistent authorization, (3) verify delegated actions validate msg.sender authority, (4) verify emergency/admin functions are protected, (5) verify internal helpers are not externally accessible.
- Counter-evidence: Apply access control to all state-changing functions. Use consistent authorization patterns (OpenZeppelin AccessControl or Ownable). Verify msg.sender in delegated actions. Protect all admin/emergency functions. Ensure internal helpers are not externally callable.

## EVM-GEN-DATA-01

- Title: Data Structure Integrity Invariant
- Severity default: low-high
- Trigger idea: For every data structure operation: (1) verify deletions clean all cross-references, (2) verify array removals don't create gaps, (3) verify key changes clear old mapping entries, (4) verify array growth is bounded or paginated, (5) verify EnumerableSet/Map return values are checked and mutation doesn't occur during iteration.
- Counter-evidence: Clean all cross-references on deletion. Use swap-and-pop for unordered array removal. Clear old mapping entries when keys change. Cap array growth or use pagination. Check return values from EnumerableSet/Map operations.

## EVM-GEN-DOS-01

- Title: DoS Resistance Invariant
- Severity default: medium-high
- Trigger idea: For every user-facing function: (1) verify loops over dynamic arrays are bounded or paginated, (2) verify batch operations have configurable size limits, (3) verify minimum thresholds prevent dust griefing, (4) verify balance checks tolerate force-sent ETH, (5) verify initialization cannot be front-run.
- Counter-evidence: Bound loops with pagination. Process batches with configurable size limits. Require minimum deposit thresholds. Use internal accounting instead of address(this).balance. Protect initialization with deployer checks or CREATE2 determinism.

## EVM-GEN-ETH-01

- Title: Native Token (ETH) Handling Invariant
- Severity default: low-medium
- Trigger idea: Check for: (1) msg.value usage inside loops or delegatecall multicall; (2) payable functions using >= on msg.value without refund; (3) address(this).balance used in equality checks or accounting; (4) asymmetric ETH/WETH code paths or missing payable modifiers; (5) receive()/fallback() without corresponding sweep/withdrawal mechanisms.
- Counter-evidence: Use internal accounting variables instead of address(this).balance. Track msg.value consumption in a local variable. Enforce strict equality or implement refund logic. Restrict receive() to trusted senders. Implement sweep functions with core-token exclusions.

## EVM-GEN-EVT-01

- Title: Event Emission Invariant
- Severity default: informational-low
- Trigger idea: For every state-modifying function: (1) verify an event is emitted, (2) verify event parameters match post-mutation state, (3) verify key fields are indexed, (4) verify event is emitted after state update, (5) verify all conditional branches emit events.
- Counter-evidence: Emit events for all state changes. Use post-mutation values. Index addresses and IDs. Emit after state update. Cover all conditional branches.

## EVM-GEN-FRONT-01

- Title: Frontrunning Invariant
- Severity default: medium-high
- Trigger idea: Check for (1) unique identifiers derived from predictable/unbound inputs, (2) commit-reveal schemes missing sender binding or data validation, (3) non-atomic state transitions creating exploitable windows, (4) order cancel/fill races without delay mechanisms, (5) function logic depending on manipulable contract balance or global state with strict equality.
- Counter-evidence: Bind identifiers to msg.sender. Use commit-reveal with sender inclusion and minimum delay. Make state transitions atomic. Add cancel delays. Pull funds via transferFrom and use threshold checks instead of strict equality.

## EVM-GEN-LOGIC-01

- Title: Conditional Logic Invariant
- Severity default: low-high
- Trigger idea: For every conditional branch: (1) verify boundary operators handle edge values correctly, (2) verify boolean logic matches intended semantics, (3) verify side effects are not hidden by short-circuit evaluation, (4) verify all branches are exhaustively covered, (5) verify non-deterministic values use range checks instead of strict equality.
- Counter-evidence: Audit boundary operators for off-by-one. Verify boolean logic with truth tables. Avoid side effects in short-circuit operands. Add explicit default/else branches. Use range checks instead of strict equality on volatile values.

## EVM-GEN-REENT-01

- Title: Reentrancy Invariant
- Severity default: medium-high
- Trigger idea: Identify any function where state variables are read or written in an unsafe temporal relationship with external calls -- including classic CEI violations, cross-function shared state without unified guards, callback-triggered re-entry via safe-transfer/hooks, view function reads during transitional states, and try-catch state management errors.
- Counter-evidence: Apply CEI universally. Use shared nonReentrant guards across all functions touching the same state. For read-only reentrancy, verify target lock status or use manipulation-resistant oracles. For try-catch, use optimistic state updates with catch rollback.

## EVM-GEN-STATE-01

- Title: State Consistency Invariant
- Severity default: medium-critical
- Trigger idea: For every state mutation: (1) verify all coupled state variables are updated together, (2) verify state is not read before and used after external calls, (3) verify multi-step transitions are atomic, (4) verify accumulation operators are used where required, (5) verify add/remove paths mirror state changes symmetrically.
- Counter-evidence: Update all coupled state variables atomically within the same execution frame. Re-read state after external calls. Use checks-effects-interactions. Prefer accumulation operators over assignment. Mirror add/remove paths symmetrically.

## EVM-GEN-TIME-01

- Title: Timestamp & Deadline Invariant
- Severity default: low-high
- Trigger idea: For every time-sensitive operation: (1) verify deadline parameter exists and is user-supplied, (2) verify deadline is not block.timestamp, (3) verify comparison operators handle boundaries correctly, (4) verify time accumulators are initialized and pause-aware, (5) verify duration parameters are bounded and validated.
- Counter-evidence: Accept user-supplied deadlines. Never use block.timestamp as deadline. Use consistent comparison operators at boundaries. Initialize timestamps before use. Validate duration bounds. Freeze accumulators during pause.

## EVM-GEN-VAL-01

- Title: Input & Initialization Validation Invariant
- Severity default: informational-medium
- Trigger idea: For every function accepting parameters or initializing state: (1) verify addresses checked against zero and values checked against zero where semantically invalid, (2) verify rates, fees, and durations have upper bounds, (3) verify constructor, initializer, and setter apply identical validation for the same parameter, (4) verify initializer is callable only once and upgradeable contracts use _disableInitializers(), (5) verify state variables are assigned before use in logic.
- Counter-evidence: Validate all inputs. Check zero addresses and values. Cap parameters. Share validation logic across entry points. Guard initializers. Initialize all state before use.

## EVM-GEN-XCALL-01

- Title: External Call & Return Value Invariant
- Severity default: medium-high
- Trigger idea: For every external call and return value: (1) verify low-level call, ERC-20, and library return values are captured and checked, (2) verify ETH transfers to untrusted recipients use pull-payment pattern, (3) verify return value polarity is correct, all paths return explicitly, and return values accurately reflect outcomes, (4) verify recoverable external calls are wrapped in try-catch, (5) verify returndata copy size is bounded for untrusted callees.
- Counter-evidence: Check all return values. Use SafeERC20 and pull-payment patterns. Verify return polarity and explicit returns on all paths. Wrap recoverable calls in try-catch. Bound returndata copy size.

## EVM-GOV-LOCK-01

- Title: Timelock & Delay Enforcement Invariant
- Severity default: medium-high
- Trigger idea: For every governance system with timelocks or delays: (1) verify all privileged actions route through timelock not just role checks, (2) verify parameter updates have sanity bounds and don't retroactively affect existing users, (3) verify timelock execution has access control and ordering enforcement, (4) verify ve-token lock operations validate all inputs and use absolute time comparisons, (5) verify lock/cooldown parameters are snapshotted at entry and emergency exits exist, (6) verify init and update paths enforce identical validation constraints.
- Counter-evidence: Route all changes through timelock. Bound all parameters. Enforce execution ordering and access control. Validate all ve-token inputs. Snapshot lock parameters at entry time. Provide bounded emergency exits. Mirror init validation in all setter functions.

## EVM-GOV-PROP-01

- Title: Proposal Lifecycle Integrity Invariant
- Severity default: medium-high
- Trigger idea: For every proposal-based governance system: (1) verify proposal creation enforces uniqueness and non-zero thresholds, (2) verify cancellation logic uses correct comparison operators and creation-time thresholds, (3) verify execution validates all payload elements and msg.value, (4) verify proposals have enforced deadlines and bounded extensions, (5) verify state machine transitions handle boundaries correctly and validate parameters at creation.
- Counter-evidence: Hash proposals for uniqueness. Validate parameters at creation. Use creation-time thresholds for cancellation. Inspect all payload elements. Enforce deadlines with bounded extensions. Use consistent boundary operators.

## EVM-GOV-QUORUM-01

- Title: Quorum & Threshold Integrity Invariant
- Severity default: medium-high
- Trigger idea: For every governance quorum/threshold system: (1) verify threshold calculations round up to prevent minority bypass, (2) verify quorum denominators track dynamic voting power via snapshots, (3) verify thresholds are initialized non-zero and validated as reachable, (4) verify multisig thresholds synchronize with signer set changes, (5) verify quorum recalculates on strategy/membership changes.
- Counter-evidence: Round up all threshold divisions. Use snapshotted dynamic denominators. Initialize and bound all thresholds. Synchronize thresholds with membership changes. Recalculate quorum on strategy updates.

## EVM-GOV-VOTE-01

- Title: Voting Power Integrity Invariant
- Severity default: medium-critical
- Trigger idea: For every governance voting system: (1) verify voting weight uses historical snapshots not current-block state, (2) verify delegation accounting prevents double-counting and cycles, (3) verify snapshot freshness and checkpoint synchronization, (4) verify power calculations handle precision/exclusion/bounds correctly, (5) verify all transfer/redeem/merge paths update voting power atomically.
- Counter-evidence: Use historical snapshots for voting weight. Prevent delegation cycles. Synchronize checkpoints on all state-changing paths. Bound weight multipliers and handle precision correctly. Update voting records atomically on transfers and membership changes.

## EVM-INTEG-AAVE-01

- Title: Aave Lending Integration Invariant
- Severity default: medium-high
- Trigger idea: For every Aave integration: (1) verify claimRewards passes aToken/debtToken addresses not underlying, (2) verify adapter exposes reward claim functions for all incentive types, (3) verify getReserveData return fields are validated against address(0) before use, (4) verify pool references are updatable and not hardcoded to V2, (5) verify aToken balances are read fresh at point-of-use not cached.
- Counter-evidence: Pass derivative tokens to incentivesController. Expose reward claim functions. Validate reserve data fields. Use updatable pool references. Read aToken balances at point-of-use for share calculations.

## EVM-INTEG-UNIV3-01

- Title: Uniswap V3 Concentrated Liquidity Integration Invariant
- Severity default: medium-critical
- Trigger idea: For every Uniswap V3 integration: (1) verify tick arithmetic respects MIN_TICK/MAX_TICK bounds and tick spacing alignment; (2) verify sqrtPriceX96 calculations use FullMath or appropriate bit-width arithmetic without overflow; (3) verify position liquidity is fetched from the pool at burn time, not cached; (4) verify fee growth calculations use unchecked arithmetic to match Uniswap V3 intentional overflow semantics; (5) verify the protocol does not use pool.slot0() sqrtPriceX96 as a price oracle -- must use TWAP via observe() instead.
- Counter-evidence: Clamp ticks to MIN_TICK/MAX_TICK. Use FullMath for sqrtPriceX96 arithmetic. Query position liquidity from the pool at burn time. Use unchecked blocks for fee growth subtraction. Never use slot0() as a price oracle -- use TWAP via observe() with a sufficient window (e.g., 30 minutes).

## EVM-INTEG-UNIV4-01

- Title: Uniswap V4 Hook Integration Invariant
- Severity default: medium-high
- Trigger idea: For every Uniswap V4 hook implementation: (1) verify hook permission flags in the contract address match the actually implemented callback functions, including return-delta flags for hooks that modify swap amounts; (2) verify tick boundaries in hook logic respect the pool tick spacing and do not hardcode values outside mathematical limits; (3) verify hooks that apply fees or taxes in afterSwap return the correct hookDeltaUnspecified to maintain delta neutrality; (4) verify modifyLiquidity calls handle zero-liquidity positions without reverting on uninitialized ticks; (5) verify hook return deltas do not cause sign inversion that would flip the swap direction.
- Counter-evidence: Align hook address permission bits with all implemented callbacks. Use pool-specific tick spacing for range calculations. Return hookDeltaUnspecified from afterSwap when taking fees. Guard modifyLiquidity against zero-delta on empty positions. Validate delta magnitudes against swap amounts to prevent sign flips.

## EVM-LEND-BORROW-01

- Title: Borrow/Repay Accounting Invariant
- Severity default: medium-critical
- Trigger idea: For every borrow/repay function: (1) verify token transfer matches accounting change, (2) check for share inflation attacks on empty pools, (3) verify global-individual accounting consistency, (4) confirm borrow-on-behalf requires authorization, (5) check all entry points enforce caps.
- Counter-evidence: Ensure every borrow creates matching debt + transfer, every repay reduces debt + transfers tokens, global and per-user state stay in sync, dust debt is handled, and borrow-on-behalf requires authorization.

## EVM-LEND-COLL-01

- Title: Collateral Management Invariant
- Severity default: medium-critical
- Trigger idea: For every function that modifies collateral balances: (1) verify health check is enforced, (2) check for self-backing loops, (3) validate asset registration before collateral operations, (4) confirm consistent threshold enforcement across all operations.
- Counter-evidence: Enforce health factor checks on every code path that reduces effective collateral (withdraw, transfer, disable-as-collateral). Validate asset eligibility. Block self-backing. Use consistent LTV across all integrations.

## EVM-LEND-HEALTH-01

- Title: Solvency / Health Factor Invariant
- Severity default: medium-critical
- Trigger idea: For every solvency-related function: (1) verify health factor includes all debt components without double-counting, (2) check recovery mode transition guards, (3) verify bad debt socialization exists, (4) confirm minimum debt thresholds prevent dust.
- Counter-evidence: Ensure health factor calculation includes all debt components (fees, interest). Implement robust recovery mode with manipulation resistance. Handle bad debt through socialization. Enforce minimum debt thresholds.

## EVM-LEND-IR-01

- Title: Interest Rate Accrual Invariant
- Severity default: medium-critical
- Trigger idea: For every interest-related function: (1) verify accrual doesn't truncate to zero, (2) check compounding vs simple interest, (3) validate utilization formula (no >100%, correct reserves handling), (4) confirm accrueInterest() called before all state changes including liquidation, (5) verify interest accrual halts during pause states, (6) verify time constants match chain reality.
- Counter-evidence: Ensure interest compounds correctly (not simple), never truncates to zero for small amounts, uses correct utilization formula, caps rates at sane bounds, accrues before every state-changing operation including liquidation, and halts accrual during pause states.

## EVM-LEND-LIQ-01

- Title: Liquidation Mechanism Invariant
- Severity default: medium-critical
- Trigger idea: For every liquidation function: (1) verify all global and per-user state is updated, (2) check self-liquidation is blocked including proxy bypass, (3) verify liquidation bonus is bounded and profitable, (4) confirm liquidation cannot be DoS'd by pause/config/loop.
- Counter-evidence: Ensure liquidation correctly checks health factor before and after, updates all global and per-user state atomically, provides adequate incentive, blocks self-liquidation, and handles partial liquidation correctly without leaving dust.

## EVM-LEND-PARAM-01

- Title: Parameter Validation Invariant
- Severity default: low-high
- Trigger idea: For every admin setter function: (1) verify absolute bounds on each parameter, (2) check relational constraints between dependent parameters, (3) verify initialization guards, (4) check for retroactive impact on existing positions and timelock protection.
- Counter-evidence: Validate all parameters against absolute bounds and relative constraints. Enforce relational invariants (e.g., liquidation threshold > collateral factor). Guard against uninitialized state. Use timelocks for sensitive changes.

## EVM-LEND-ROUND-01

- Title: Rounding / Precision Invariant
- Severity default: low-high
- Trigger idea: For every division operation in lending logic: (1) verify rounding direction favors the protocol, (2) check related calculations use consistent rounding, (3) confirm minimum amounts prevent micro-operation exploitation, (4) verify exchange rate conversions use actual balances not calculations.
- Counter-evidence: Round against the party initiating the action (round up for borrows/withdrawals, round down for deposits/repayments). Use consistent rounding across related operations. Implement minimum amounts to prevent micro-operation exploitation.

## EVM-MATH-CAST-01

- Title: Type Casting Invariant
- Severity default: low-high
- Trigger idea: For every type cast: (1) check if uint256 is downcast to a narrower type without SafeCast or bounds check, (2) check if negative int256 values are cast to uint256, (3) check if arithmetic on narrow types can overflow before widening, (4) check if external return values are truncated on assignment, (5) check for tautological comparisons caused by type-range limits.
- Counter-evidence: Use OpenZeppelin SafeCast for all downcasts. Validate that values fit in the target type before casting. Perform arithmetic in the widest type, then downcast the result. Never cast negative signed integers to unsigned without checking sign. Avoid uint8/uint16/uint32 for values that can grow.

## EVM-MATH-DIV-01

- Title: Division Invariant
- Severity default: low-critical
- Trigger idea: For every division operation: (1) verify the denominator cannot be zero under any reachable state, (2) check if division precedes multiplication and could be reordered, (3) verify denominators are not manipulable between related operations, (4) check percentage divisors are consistent (100 vs 1000 vs 10000), (5) verify division remainders are refunded or accounted for.
- Counter-evidence: Always validate denominators are non-zero before division. Reorder arithmetic to multiply before dividing. Use mulDiv helpers for combined operations. Handle the zero-denominator edge case explicitly. Use consistent BPS constants. Refund or account for division remainders.

## EVM-MATH-OVERFLOW-01

- Title: Overflow/Underflow Invariant
- Severity default: low-critical
- Trigger idea: For every arithmetic operation: (1) check if `unchecked` blocks contain subtraction or addition with external/dynamic operands, (2) verify accumulating state variables cannot overflow, (3) check if intentional-wrap patterns are blocked by checked arithmetic, (4) verify intermediate multiplications cannot exceed uint256, (5) check timestamp arithmetic for underflow and narrow-type truncation.
- Counter-evidence: Remove unchecked from arithmetic with external inputs. Add explicit bounds checks before unchecked operations. Use unchecked only for provably-safe gas optimizations. For intentional wraps (cumulative counters), use unchecked with documented safety. Validate inputs fit within the expected range before arithmetic. Use mulDiv for large intermediate products. Validate timestamp ordering before subtraction.

## EVM-MATH-ROUND-01

- Title: Rounding Invariant
- Severity default: low-critical
- Trigger idea: For every integer division, percentage calculation, or pro-rata distribution: (1) check if the result can be zero for valid inputs, (2) verify rounding direction favors the protocol on both sides of a symmetric operation, (3) check for dust accumulation in multi-recipient splits, (4) verify accrual frequency does not cause material precision loss, (5) check if fees calculated on sub-amounts differ from fees on the whole.
- Counter-evidence: Always round against the party who could exploit direction. Use mulDivUp / mulDivDown explicitly. Enforce minimum amounts to prevent round-to-zero. Use the "remainder to last recipient" pattern for distributions. Ensure deposit/mint rounds up, withdraw/burn rounds down (from protocol's perspective).

## EVM-MATH-SCALE-01

- Title: Decimal Scaling Invariant
- Severity default: medium-critical
- Trigger idea: For every token amount operation: (1) check for hardcoded decimal constants (1e18, 1e6, 1e12), (2) verify scaling factors match the actual token decimals, (3) check for missing normalization in cross-token arithmetic, (4) verify WAD/RAY consistency in fixed-point math, (5) check if scaling can overflow for high-decimal tokens.
- Counter-evidence: Always read decimals() dynamically. Normalize all amounts to a common internal precision before arithmetic. Never hardcode 1e18, 1e6, or 1e12 as universal scaling factors. Validate that scaling operations cannot overflow. Test with tokens of 2, 6, 8, 18, and 24+ decimals.

## EVM-NFT-META-01

- Title: NFT Metadata Integrity Invariant
- Severity default: informational-medium
- Trigger idea: For every NFT metadata system: (1) verify burn functions clean up all associated metadata and custom mappings, (2) verify bidirectional mappings clear reverse entries on update, (3) verify metadata writes check for existing values when uniqueness is required, (4) verify tokenURI validates string length and handles missing baseURI, (5) verify on-chain metadata generation uses actual token ID variables not string placeholders.
- Counter-evidence: Delete all metadata on burn. Clear reverse mappings on update. Check existence before overwrite. Validate URI length and format. Use actual variables in on-chain metadata.

## EVM-NFT-MKT-01

- Title: NFT Marketplace Integrity Invariant
- Severity default: medium-critical
- Trigger idea: For every NFT marketplace: (1) verify non-standard NFT deposit flows validate the original owner to prevent front-running, (2) verify auction bids have minimum commitment periods and withdrawal doesn't check current ownership, (3) verify listings escrow the NFT or prevent duplicates, and buy orders require non-zero value, (4) verify fee modules are whitelisted and minimum fees are enforced at protocol level, (5) verify fractional exchanges only transfer exact costs or refund remainders.
- Counter-evidence: Validate depositor identity for non-standard NFTs. Add bid commitment periods. Escrow NFTs on listing. Whitelist fee modules with minimums. Transfer only exact costs in fractional swaps.

## EVM-NFT-STD-01

- Title: ERC-721 Implementation Invariant
- Severity default: medium-high
- Trigger idea: For every ERC-721 integration: (1) verify safeMint callbacks cannot re-enter to bypass mint limits or corrupt state (CEI pattern or reentrancy guard), (2) verify ownership-dependent state is updated on every transfer path and per-token tracking is used instead of balance-based, (3) verify batch operations check for duplicate IDs, use monotonic counters not totalSupply, and refund excess ETH, (4) verify contracts holding NFTs implement IERC721Receiver and support all transfer variants, (5) verify the integration handles non-standard ERC-721 variants: dual-standard tokens, multi-collection contracts, self-burning/pausable/upgradeable tokens, non-sequential IDs, and pre-standard tokens.
- Counter-evidence: Use CEI pattern or reentrancy guards for safeMint. Track ownership per-token. Dedup batch operations and use monotonic counters. Implement IERC721Receiver. Handle non-standard variants with try/catch, uint256 IDs, and per-token approvals.

## ADMIN-01

- Title: Oracle Administration Invariant
- Severity default: low-medium
- Trigger idea: For every oracle administration function: (1) verify new oracle addresses are validated for interface compatibility and liveness, (2) verify staleness thresholds have enforced upper and lower bounds, (3) verify manual price updates have deviation and bounds checks, (4) verify oracle addresses can be updated for feed deprecation recovery, (5) verify off-chain signer oracles use quorum and cross-validation.
- Counter-evidence: Validate all admin inputs: verify interface support for new feed addresses, enforce sane bounds on thresholds and prices, use timelocks for sensitive changes, emit events for all configuration updates. Provide update mechanisms with appropriate access control for oracle addresses.

## DECIMAL-01

- Title: Decimal & Precision Handling Invariant
- Severity default: medium-high
- Trigger idea: For every oracle price normalization: (1) verify decimal counts are queried dynamically, not hardcoded, (2) verify multiplication is performed before division to preserve precision, (3) verify the oracle price direction matches the calculation intent, (4) verify exponent signs are validated before negation, (5) verify cross-token calculations account for differing decimal precisions.
- Counter-evidence: Always query oracle.decimals() and token.decimals() dynamically. Multiply before dividing (use FullMath.mulDiv for safe full-precision math). Never hardcode decimal assumptions. Validate that scaled prices fall within sane bounds.

## FALLBACK-01

- Title: Oracle Resilience & Fallback Invariant
- Severity default: medium-high
- Trigger idea: For every oracle integration: (1) verify external oracle calls are wrapped in try/catch with fallback logic, (2) verify L2 deployments check sequencer uptime feed with grace period, (3) verify Chainlink min/max answer circuit breaker bounds are detected, (4) verify oracle failure paths revert or return explicit failure signals rather than zero, (5) verify fallback oracle sources exist and are validated with the same rigor as the primary.
- Counter-evidence: Wrap oracle calls in try/catch. Implement fallback oracle sources. Check L2 sequencer uptime before consuming prices. Detect Chainlink min/max answer clamping. Add grace periods after sequencer recovery. Ensure the protocol can operate (at least in safe mode) when oracles fail.

## SPOT-01

- Title: Spot Price Manipulation Invariant
- Severity default: high-critical
- Trigger idea: For every price derivation from on-chain pool state: (1) verify the contract does not use `getReserves()` or `balanceOf(pool)` as a price source, (2) verify Curve view functions are not used as sole price oracle, (3) verify `balanceOf` on pool addresses is not used for pricing, (4) verify slippage bounds are not derived from the same spot price being protected against, (5) verify initial share/LP pricing does not rely on manipulable spot state.
- Counter-evidence: Never use instantaneous pool state as a price oracle. Use Chainlink feeds, Uniswap V3 TWAP via observe(), or time-weighted mechanisms. If spot price must be used, add manipulation-resistant checks (e.g., compare against TWAP, enforce minimum time between operations).

## STALE-01

- Title: Price Staleness & Freshness Invariant
- Severity default: medium-critical
- Trigger idea: For every oracle price read: (1) verify the `updatedAt` timestamp is checked against a feed-appropriate maximum age, (2) verify `answeredInRound >= roundId` for Chainlink feeds, (3) verify the price is checked for `> 0`, (4) verify per-feed heartbeat thresholds rather than a single global constant, (5) verify Pyth/custom feeds check both staleness and confidence intervals.
- Counter-evidence: Validate all oracle metadata on every read: revert if updatedAt is older than the feed's heartbeat, revert if answeredInRound < roundId, revert if answer <= 0, use feed-specific heartbeat thresholds, and never use deprecated APIs that lack metadata.

## TWAP-01

- Title: TWAP Configuration Invariant
- Severity default: medium-high
- Trigger idea: For every TWAP oracle usage: (1) verify the observation window is at least 30 minutes on mainnet, (2) verify token0/token1 ordering is checked dynamically against the target token, (3) verify the TWAP period has enforced minimum and maximum bounds, (4) verify accumulator initialization requires sufficient elapsed time before first read, (5) verify L2 deployments account for sequencer downtime in TWAP observation validity.
- Counter-evidence: Enforce minimum TWAP observation windows (30+ minutes for mainnet, longer for L2). Verify token0/token1 ordering dynamically. Validate accumulator initialization before first read. Account for sequencer downtime in TWAP calculations. Bound configuration parameters.

## EVM-PRED-MKT-01

- Title: Prediction Market Creation & Participation Invariant
- Severity default: medium-high
- Trigger idea: For every prediction market: (1) verify participation closes strictly before resolution with enforced minimum duration, (2) verify timestamp boundaries use exclusive comparisons to prevent same-block front-running, (3) verify market parameters are validated (>=2 outcomes, oracle-sourced prices, bounded inputs), (4) verify sentinel/default values don't collide with legitimate oracle or scoring values, (5) verify YES+NO prices sum to exactly 1.00 in order matching.
- Counter-evidence: Enforce close < resolution. Use strict timestamp comparisons. Validate all market parameters. Use boolean flags instead of sentinel values. Enforce complementary pricing in order matching.

## EVM-PRED-SETTLE-01

- Title: Prediction Market Settlement & Payout Invariant
- Severity default: high-critical
- Trigger idea: For every prediction market settlement: (1) verify binary outcomes handle equality explicitly (three-way branch or draw), (2) verify CTF/ERC-1155 token transfers use reentrancy guards and CEI pattern, (3) verify fees are collected in collateral tokens not outcome tokens, (4) verify negative yield events reduce collateral backing uniformly not by probability split, (5) verify payout calculations have explicit bounds checks with descriptive errors.
- Counter-evidence: Add explicit draw handling. Use nonReentrant on all CTF transfers. Collect fees in collateral. Distribute losses by collateral ratio. Add explicit bounds checks on all subtractions.

## DIAM-01

- Title: Diamond and Multi-Facet Proxy Invariant
- Severity default: informational-high
- Trigger idea: For every diamond/multi-facet proxy: (1) verify all modified facets are included in upgrade cuts, (2) verify all function selectors are registered in the constructor, (3) verify EIP-2535 standard interfaces are implemented, (4) verify proxy-to-implementation selector and ABI encoding matches, (5) verify parent contracts can forward admin calls to child proxies.
- Counter-evidence: Register all selectors during diamond cut. Include all modified facets in upgrades. Follow EIP-2535 standard for introspection. Make routing tables immutable or admin-protected. Verify selector-to-facet mappings match expected interfaces.

## DLGT-01

- Title: Delegatecall Safety Invariant
- Severity default: informational-high
- Trigger idea: For every contract using delegatecall: (1) verify msg.value is not reused across loop iterations, (2) verify ETH sent to proxy has a withdrawal path, (3) verify receive() and fallback() delegation behavior is consistent, (4) verify activity attribution uses correct address context, (5) verify proxy fallback does not reject legitimate payable calls.
- Counter-evidence: Track consumed msg.value in multi-call patterns. Implement ETH withdrawal from proxies. Ensure consistent receive/fallback delegation. Validate context assumptions in delegatecall targets. Use address(this) awareness for attribution.

## FACT-01

- Title: Factory and Clone Deployment Invariant
- Severity default: low-critical
- Trigger idea: For every factory/clone deployment: (1) verify CREATE2 salt includes msg.sender or unpredictable component, (2) verify init code hash matches actual contract bytecode, (3) verify deployment and initialization are atomic, (4) verify child contracts read current factory config, (5) verify salt derivation is consistent across all factory functions.
- Counter-evidence: Include msg.sender in CREATE2 salt. Verify init code hash matches at deployment. Atomically deploy and initialize in same transaction. Propagate config updates to children. Use consistent salt derivation across factory functions.

## INIT-01

- Title: Initialization Access Control Invariant
- Severity default: medium-critical
- Trigger idea: For every initialization function in a proxy-based contract: (1) verify it uses `initializer` or `reinitializer` modifier, (2) verify manual init flags are properly set, (3) verify upgrade reinitializers have access control, (4) verify implementation constructors call `_disableInitializers()`, (5) verify critical address setters have one-time or access-controlled guards.
- Counter-evidence: Use OpenZeppelin's initializer/reinitializer modifiers. Add onlyOwner or equivalent to upgrade initializers. Ensure _disableInitializers() is called in implementation constructors. Never leave custom init functions unguarded.

## INIT-02

- Title: Initialization Completeness Invariant
- Severity default: low-high
- Trigger idea: For every upgradeable contract: (1) verify all inherited `__init` or `__init_unchained` functions are called, (2) verify diamond inheritance uses `_unchained` variants, (3) verify all critical dependencies are set during init, (4) verify no two-step initialization gaps exist, (5) verify parent initializers use `onlyInitializing` not `initializer`.
- Counter-evidence: Call every inherited contract's initializer. Use __init_unchained in diamond inheritance. Set all critical state in a single atomic initialization. Verify all dependencies are non-zero after init.

## INIT-03

- Title: Initialization Parameter Validation Invariant
- Severity default: informational-high
- Trigger idea: For every initialization function: (1) verify all address parameters are checked against zero, (2) verify parameter ordering matches semantic intent, (3) verify cross-parameter consistency constraints, (4) verify array inputs have uniqueness checks, (5) verify no critical values are hardcoded.
- Counter-evidence: Validate all address parameters against zero. Check numeric ranges and cross-parameter consistency. Verify parameter ordering matches expected semantics. Add uniqueness checks for registrations. Avoid hardcoding environment-specific values.

## STOR-01

- Title: Storage Layout Safety Invariant
- Severity default: informational-high
- Trigger idea: For every upgradeable contract: (1) verify base contracts declare `__gap` storage arrays, (2) verify no variable reordering or insertion between versions, (3) verify no constructor/field-level storage initialization, (4) verify all imports use upgradeable variants, (5) verify immutable clone argument lengths are bounded.
- Counter-evidence: Reserve storage gaps in base contracts. Never reorder or remove variables. Use upgradeable library variants exclusively. Never initialize storage in constructors or field declarations. Use OpenZeppelin's storage checker plugin.

## UPG-01

- Title: Upgrade Authorization Invariant
- Severity default: low-critical
- Trigger idea: For every upgradeable proxy: (1) verify `_authorizeUpgrade` has access control, (2) verify upgrade authority uses timelock/governance, (3) verify new implementations are validated as contracts with correct interfaces, (4) verify upgrade invariants cannot be bypassed, (5) verify implementation address changes require admin authentication.
- Counter-evidence: Always protect _authorizeUpgrade with onlyOwner or governance. Validate new implementations are contracts with expected interfaces. Use timelocks for upgrade authority. Enforce upgrade invariants. Verify implementation targets before setting.

## UPG-02

- Title: Upgrade State Consistency Invariant
- Severity default: low-high
- Trigger idea: For every proxy upgrade: (1) verify reinitializer version numbers are sequential without gaps, (2) verify new accounting variables are backfilled from existing state, (3) verify dependency updates propagate to all linked contracts, (4) verify reused proxies have current implementations, (5) verify asset/token address changes include balance migration.
- Counter-evidence: Always migrate state atomically during upgrade. Use correct reinitializer version numbers. Propagate dependency updates across all linked contracts. Verify implementation freshness. Backfill new accounting variables from existing state.

## EVM-STABLE-MECH-01

- Title: Stablecoin Mechanism Invariant
- Severity default: high-critical
- Trigger idea: For every stablecoin protocol: (1) verify minting uses manipulation-resistant price feeds with liquidity-depth awareness, (2) verify liquidation has partial execution, cooldowns, and cascade circuit breakers, (3) verify redemption has dynamic fees, rate limits, and market-price awareness, (4) verify algorithmic expansion/contraction maintains a hard collateral backing floor, (5) verify interest/fee accrual is included in all debt calculations and health checks.
- Counter-evidence: Use oracle prices with liquidity haircuts for minting. Implement partial liquidation with cooldowns and circuit breakers. Add dynamic redemption fees with daily caps. Maintain hard collateral floors for algorithmic components. Always include accrued interest in debt and health calculations.

## EVM-STABLE-PEG-01

- Title: Peg Assumption Invariant
- Severity default: medium-high
- Trigger idea: For every pegged/wrapped/derivative asset valuation: (1) verify stablecoins are priced via oracle, not hardcoded to $1.00, (2) verify LSTs use minimum of canonical and market rate, (3) verify wrapped tokens use a wrapper-specific price feed, not just the underlying, (4) verify derivative tokens have their own price feed reflecting their specific risk, (5) verify redemption mechanisms use market-aware rates with depeg circuit breakers.
- Counter-evidence: Never hardcode exchange rates. Query dedicated price feeds for each asset. Use minimum of canonical and market rate for collateral. Implement depeg circuit breakers for redemption mechanisms.

## EVM-STAKE-EPOCH-01

- Title: Epoch and Period Management Invariant
- Severity default: low-high
- Trigger idea: For every time-dependent staking function: (1) verify consistent inclusive/exclusive boundary comparisons with no overlap, (2) verify all duration and timestamp parameters have min/max bounds validation, (3) verify reward accrual is capped at period end, (4) verify epoch transitions finalize previous state and handle skipped epochs, (5) verify global parameter changes do not retroactively affect existing positions.
- Counter-evidence: Use exclusive end boundaries consistently. Validate all time parameters with min/max bounds. Cap reward calculations at periodFinish. Finalize epoch state before advancing. Snapshot time-dependent parameters per position.

## EVM-STAKE-REWD-01

- Title: Reward Accumulation Invariant
- Severity default: medium-critical
- Trigger idea: For every reward-distributing staking function: (1) verify the global accumulator skips zero-supply periods, (2) verify per-user reward index is checkpointed before every balance change (stake/unstake/transfer/mint/burn), (3) verify global reward state is updated before any balance or rate modification, (4) verify accumulator precision is sufficient without overflow risk, (5) verify pending rewards are accumulated not overwritten and state is reset only after successful distribution.
- Counter-evidence: Checkpoint global and per-user reward state before every balance change. Guard zero-supply periods. Use sufficient precision scaling (1e18). Cap accumulators. Reset pending state only after successful transfer.

## EVM-STAKE-SCONF-01

- Title: Staking Configuration and Initialization Invariant
- Severity default: low-high
- Trigger idea: For every configurable staking parameter: (1) verify admin-settable values have upper/lower bounds and cross-parameter consistency checks, (2) verify critical state (timestamps, addresses, counters) is properly initialized and handles the zero/default case, (3) verify token and asset references are immutable or changed only with proper migration, (4) verify external call failures in hooks or token operations cannot block core staking functions, (5) verify all entry points enforce the same constraints for shared invariants.
- Counter-evidence: Validate all parameters with min/max bounds. Initialize timestamps to deployment time and addresses to non-zero. Make critical references immutable. Use try-catch for external hooks. Centralize constraint checks in internal functions shared by all entry points.

## EVM-STAKE-SLASH-01

- Title: Slashing and Penalty Invariant
- Severity default: medium-critical
- Trigger idea: For every slashing/penalty function: (1) verify unstaking has mandatory cooldown preventing front-run evasion of slashing, (2) verify cascading slashes use saturating arithmetic and only count actually-slashed amounts, (3) verify time-based penalty decay uses correct interpolation direction, (4) verify iterative slash distribution accounts for rounding remainder, (5) verify vesting/lock cancellation slashes proportional rewards and clears all associated state.
- Counter-evidence: Enforce cooldowns before unstaking. Use saturating arithmetic for cascading slashes. Verify penalty interpolation direction with boundary tests. Assign rounding remainder to last participant. Slash all position components proportionally on cancellation.

## EVM-STAKE-SNIPE-01

- Title: Reward Gaming and Flash-Staking Invariant
- Severity default: low-high
- Trigger idea: For every reward distribution mechanism: (1) verify rewards use time-weighted calculations not instantaneous balance snapshots, (2) verify lock/boost multiplier changes checkpoint existing rewards before applying, (3) verify minimum stake duration prevents same-block stake-unstake, (4) verify reward rate changes are not front-runnable or use delayed activation, (5) verify public state-update functions cannot be front-run for favorable entry.
- Counter-evidence: Use time-weighted (Synthetix-style) reward distribution. Checkpoint before multiplier changes. Enforce minimum stake blocks. Delay reward rate activation. Drip rewards over time windows.

## EVM-STAKE-STAKE-ACC-01

- Title: Staking Accounting Invariant
- Severity default: medium-critical
- Trigger idea: For every staking state mutation: (1) verify global aggregates and per-user balances are updated symmetrically on all paths including slash/admin/migration, (2) verify self-transfers and deposit-source confusion cannot create phantom balances, (3) verify reward funds and staked principal are tracked separately when using the same token, (4) verify array/mapping state remains consistent after deletions with no stale references, (5) verify multi-token accounting uses per-token state and normalizes decimals.
- Counter-evidence: Update global and per-user state symmetrically on every path. Block self-transfers. Track reward and principal funds separately. Use swap-and-pop with index mapping for array deletions. Maintain per-token accounting with decimal normalization.

## EVM-STAKE-UNSTK-01

- Title: Unstaking and Withdrawal Invariant
- Severity default: medium-critical
- Trigger idea: For every unstaking/withdrawal function: (1) verify all associated state (locks, debts, metadata) is fully reset on complete withdrawal, (2) verify cooldown/lock enforcement on all exit paths including emergency and migration, (3) verify queue processing handles gaps, out-of-order, and unfillable requests, (4) verify partial actions do not reset maturity/timestamp for the entire position, (5) verify global aggregate decrements match individual position changes accounting for fees and slashing.
- Counter-evidence: Fully reset all position state on withdrawal. Enforce cooldowns on every exit path. Use skip-capable queue processing. Only reset timestamps for new positions. Use matching increment/decrement accounting with saturating arithmetic.

## EVM-VAULT-ACCT-01

- Title: Vault Accounting Integrity Invariant
- Severity default: high-critical
- Trigger idea: For every vault: (1) verify state updates occur after transfers and base tracking excludes yield, (2) verify fee calculations account for underlying vault fees, netting order is correct, and fee shares mint after rewards, (3) verify strategy deploy/getBalance/undeploy return assets not shares, (4) verify totalAssets() includes owned yield, excludes external deposits, and handles post-maturity caps, (5) verify multi-strategy vaults cascade withdrawals, prevent duplicates, and validate asset/decimal consistency.
- Counter-evidence: Transfer before state update. Measure actual amounts after underlying vault operations. Return assets from strategy interfaces, not shares. Use only owned positions in totalAssets. Cascade multi-vault withdrawals with duplicate and asset validation.

## EVM-VAULT-ERC7540-01

- Title: ERC-7540 Async Vault Compliance Invariant
- Severity default: medium-critical
- Trigger idea: For every ERC-7540 implementation: (1) verify requestDeposit transfers assets and requestRedeem removes shares at request time, with no lifecycle short-circuiting or partial acceptance, (2) verify deposit/mint/redeem/withdraw are claim-only (no re-transfer) and preview functions revert unconditionally, (3) verify operator authorization on all request and claim paths with correct allowance handling, (4) verify pending/claimable state is strictly separated, view functions are caller-independent and non-reverting, and requestId policy is consistent, (5) verify stuck request recovery exists, reserved liquidity is excluded from deployment, and epoch transitions carry forward unfulfilled requests.
- Counter-evidence: Transfer assets/shares at request time. Make claim functions transfer-free. Enforce operator auth on all paths. Separate pending/claimable state strictly. Add cancellation timeouts, liquidity reservation, and epoch migration.

## EVM-VAULT-OPS-01

- Title: Vault Operations Safety Invariant
- Severity default: medium-critical
- Trigger idea: For every vault with external interactions: (1) verify deposit/withdraw have user-specified slippage parameters and DEX calls use non-zero minimums, (2) verify multi-strategy withdrawals use try/catch, handle zero amounts, and manage cooldown/last-strategy edge cases, (3) verify upgradeable vaults have storage gaps, disabled initializers, and atomic approval migration, (4) verify router operations force owner=msg.sender and restrict token pulls to caller, (5) verify timelocks bind to the correct owner and access controls check both caller and receiver.
- Counter-evidence: Add user-specified minimums everywhere. Use try/catch for external calls. Add storage gaps and disable initializers. Force owner=msg.sender in routers. Bind timelocks to owners and check receivers.

## EVM-VAULT-SHARE-01

- Title: Share Price Integrity Invariant
- Severity default: high-critical
- Trigger idea: For every tokenized vault: (1) verify first-deposit protection exists (virtual offset, dead shares, or minimum deposit), (2) verify totalAssets uses internal accounting immune to direct transfers/donations, (3) verify rounding direction favors the vault in all preview/convert functions and no zero-share withdrawal is possible, (4) verify shares and assets are never used interchangeably across function boundaries, (5) verify exchange rate changes (rewards, fees, harvests) are drip-distributed or sandwich-resistant.
- Counter-evidence: Add virtual offset or dead shares for first deposit. Use internal asset tracking immune to direct transfers/donations. Round in vault's favor everywhere. Maintain strict share/asset type separation. Drip-distribute rewards over time.

## EVM-VAULT-V4626-01

- Title: ERC-4626 Vault Compliance Invariant
- Severity default: informational-medium
- Trigger idea: For every ERC-4626 implementation: (1) verify all mandatory functions are implemented and not disabled, (2) verify max* functions return 0 when operations are disabled and never revert, (3) verify vault decimals match underlying and max functions handle overflow, (4) verify standard events are emitted and allowance is enforced when caller != owner. See also EVM-VAULT-SHARE-01 for share/asset unit confusion.
- Counter-evidence: Implement all mandatory ERC-4626 functions. Ensure max* functions reflect actual limits including pause state and never revert. Mirror underlying decimals. Use standard events. Support receiver/owner separation and enforce allowance for third-party operations.

## EVM-VAULT-YIELD-01

- Title: Reward & Yield Distribution Invariant
- Severity default: high-critical
- Trigger idea: For every vault with reward distribution: (1) verify reward integrals are updated before any claim or balance change, (2) verify reward calculations multiply before dividing to prevent precision loss, (3) verify reward notifications cannot be griefed via dust amounts or zero-value calls, (4) verify fee/reward distributions occur before new deposits dilute the pool, (5) verify recoverERC20 excludes all reward tokens and emergency functions don't drain active pools.
- Counter-evidence: Update integrals before claims/transfers. Multiply before dividing to prevent precision loss. Add minimum thresholds for reward notifications. Distribute fees before accepting new liquidity. Exclude reward tokens from recovery functions.

## EVM-VESTING-SCHED-01

- Title: Vesting Schedule Integrity Invariant
- Severity default: medium-critical
- Trigger idea: For every vesting contract: (1) verify privileged allocations (team, dev, advisor) are locked in vesting contracts, not sent directly to EOAs, (2) verify all withdrawal paths check remaining balance covers outstanding vesting debt (totalAllocated - totalReleased), (3) verify time-branch logic explicitly handles before-cliff, active-vesting, and post-end states with no default-to-100% fallthrough, (4) verify revocation only reclaims unvested tokens and preserves the beneficiary's earned portion, (5) verify allocation updates require newTotal >= claimed to prevent underflow DoS.
- Counter-evidence: Lock privileged allocations in vesting contracts. Reserve vested liquidity in all withdrawal paths. Handle all three time states explicitly. Only revoke unvested tokens. Require allocation updates >= claimed amount.

## ACCT-01

- Title: Cross-Chain Accounting Integrity Invariant
- Severity default: high-critical
- Trigger idea: For every cross-chain value transfer: (1) verify decimal normalization handles both upward and downward conversion with dust accounting, (2) verify total minted on destination never exceeds total locked/burned on source, (3) verify rebasing tokens bridge share counts not underlying values, (4) verify token registrations enforce 1:1 uniqueness with no self-mapping, (5) verify liquidity pools enforce on-chain solvency checks and rate limits before releasing funds.
- Counter-evidence: Normalize decimals bidirectionally with dust refunds. Enforce lock==mint supply invariant. Bridge share counts for rebasing tokens. Validate 1:1 token mappings with collision detection. Verify on-chain solvency and enforce rate limits before fund release.

## FINAL-01

- Title: Cross-Chain Finality & State Ordering Invariant
- Severity default: high-critical
- Trigger idea: For every cross-chain state dependency: (1) verify block confirmation requirements match each source chain's finality model, (2) verify cross-chain state reads include freshness timestamps with staleness bounds, (3) verify the protocol handles out-of-order message delivery via buffering or monotonic checks, (4) verify time-dependent logic uses chain-agnostic timestamps not block numbers and enforces asymmetric timelocks, (5) verify queued transfers snapshot configuration at queue time and handle peer migration gracefully.
- Counter-evidence: Configure per-chain finality thresholds. Include timestamps with staleness bounds in all cross-chain reads. Buffer out-of-order messages or enforce monotonic updates. Use timestamps not block numbers for cross-chain coordination. Snapshot configuration at queue time with migration grace periods.

## LIVE-01

- Title: Cross-Chain Liveness & Error Recovery Invariant
- Severity default: medium-high
- Trigger idea: For every cross-chain message handler: (1) verify execution failures are caught and stored for retry instead of reverting on ordered channels, (2) verify destination gas limits are configurable with enforced minimums per chain, (3) verify fee estimation uses actual payloads with overpayment refunds to the user, (4) verify timeout-based recovery and L1 forced-exit mechanisms exist for locked funds, (5) verify pause guards do not block bridge receivers and instead store messages for deferred execution.
- Counter-evidence: Wrap execution in try/catch with stored-retry on ordered channels. Enforce per-chain minimum gas limits. Estimate fees with real payloads and refund excess. Implement timeout recovery and L1 forced exits. Store bridge messages during pause for deferred execution.

## MSG-01

- Title: Cross-Chain Message Authentication Invariant
- Severity default: medium-critical
- Trigger idea: For every cross-chain message receiver: (1) verify msg.sender is the authorized bridge endpoint, (2) verify source chain ID and source sender against a trusted peer registry, (3) verify all payload parameters are covered by cryptographic signatures, (4) verify encoding schema matches between source encoder and destination decoder, (5) verify multiple independent verifiers are required for message attestation.
- Counter-evidence: Validate bridge endpoint as msg.sender. Check source chain and sender against trusted peer mapping. Include all parameters in signature hash. Use shared encoding libraries. Require multiple independent verifiers with adequate thresholds.

## REPLAY-01

- Title: Cross-Chain Replay Protection Invariant
- Severity default: medium-critical
- Trigger idea: For every cross-chain message handler: (1) verify a unique nonce is included in all signed payloads and marked consumed after use, (2) verify the message hash includes destination chain ID and contract address for domain separation, (3) verify sequence numbers are monotonically increasing and scoped per source chain, (4) verify deployment salts and transaction signatures include chain ID, (5) verify cross-chain events include unique identifiers that prevent proof reuse.
- Counter-evidence: Include unique nonces in all signed payloads. Use EIP-712 domain separation with chain ID and contract address. Enforce monotonic per-chain sequence numbers. Bind CREATE2 salts to chain ID. Emit unique identifiers in all bridge events.
