---
name: cairo-starknet-security
category: web3
description: Cairo and Starknet contract security covering felt252 field arithmetic, non-deterministic hints, native account abstraction, L1-L2 message vulnerabilities, replace_class_syscall upgrades, storage patterns, and component-based architecture risks
depends_on: []
---

# Cairo and Starknet Smart Contract Security

Security analysis of Cairo smart contracts deployed on Starknet. Covers felt252 prime field arithmetic traps, non-deterministic hint exploitation, native account abstraction quirks, L1-L2 message spoofing and replay, replace_class_syscall hijacking, storage patterns and collision risks, component-based architecture vulnerabilities, and Starknet-specific access control. This is the only Cairo security skill in bug.exe and must serve as the comprehensive reference for all Starknet-related auditing.

## When to Use

- Target is a Cairo smart contract on Starknet (Cairo 0 or Cairo 1/2)
- Bug bounty with Starknet contracts in scope (Immunefi, Code4rena, Sherlock)
- Reviewing contracts using OpenZeppelin Contracts for Cairo
- Auditing L1-L2 messaging bridges or cross-layer components
- Reviewing upgradeable contracts using `replace_class_syscall`
- Analyzing component-based contract architectures for storage or function collisions
- Porting EVM contracts to Cairo where assumption gaps may introduce vulnerabilities
- Starknet account contract (wallet) security review

## Methodology

### 1. felt252 Field Arithmetic

The fundamental numeric type in Cairo is `felt252`, a field element in the Stark-friendly prime field. Arithmetic in this field does NOT behave like integer arithmetic and is the most common source of Cairo-specific vulnerabilities.

**Prime field definition**: P = 2^251 + 17 * 2^192 + 1 (approximately 3.6 * 10^75)

**Subtraction wrapping (not underflow)**
- `a - b` where `a < b` does NOT revert and does NOT produce a negative number
- It wraps to `a - b + P`, producing a massive positive field element
- Example: `5 - 7 = P - 2` (approximately 3.6 * 10^75) — silently treated as a valid positive value
- Impact: balance checks like `if balance - amount > 0` always pass because felt252 values are always >= 0
- Common locations: token balance deductions, allowance decrements, reward calculations, fee subtractions
- Detection: search for all subtraction operations on felt252 types without a prior `>=` comparison
- Safe pattern: use `u256` or `u128` types which DO panic on underflow, or guard with `assert(a >= b)`

**Division is modular inverse, NOT integer division**
- `7 / 2` in felt252 produces the field element `x` where `2 * x mod P = 7`, NOT the integer 3
- This value is approximately P/2 + 4 — a huge number with no intuitive relationship to 3 or 3.5
- Impact: any division used for share calculations, fee splitting, pro-rata distributions, or price computation produces completely wrong results when performed on felt252
- Detection: any felt252 division operation is suspicious — especially in financial math
- Safe pattern: always use integer types (u256, u128, u64) for arithmetic and reserve felt252 for hashing, addresses, and storage keys

**Multiplication overflow (silent wrapping)**
- Multiplying two large felt252 values wraps modulo P without error
- Example: two values each around P/2 multiplied together produce a small result, not the expected large product
- Impact: fee calculations, share pricing, collateral ratio math, or any proportional computation can silently produce wrong results
- Detection: search for `*` on felt252 operands where either operand could be large

**Comparison operators on felt252**
- `<`, `>`, `<=`, `>=` operate on the raw field element representation
- Values near P (e.g., a wrapped subtraction result) compare as very large, which may bypass or satisfy checks unexpectedly
- Example: after `let x: felt252 = 5 - 7;` (which equals P-2), the check `x > 1000000` is true
- Impact: boundary checks, sorting logic, range validation can be bypassed with carefully chosen values or through subtraction wrapping
- Detection: search for comparison operators applied to felt252 values — especially those that could be wrapping results

**felt252 vs integer types — when to use which**

| Type | Range | Overflow | Division | Use For |
|------|-------|----------|----------|---------|
| `felt252` | 0 to P-1 | Wraps silently | Modular inverse | Hashing, addresses, storage keys, Pedersen inputs |
| `u8`-`u128` | 0 to 2^N - 1 | Panics | Integer (truncates) | Amounts, balances, counters, timestamps, indices |
| `u256` | 0 to 2^256 - 1 | Panics | Integer (truncates) | Large amounts, EVM-compatible values, token balances |
| `i8`-`i128` | -2^(N-1) to 2^(N-1)-1 | Panics | Integer (truncates) | Signed math (rare in contracts) |

- Rule: if a value represents money, a count, a timestamp, or an index, it MUST be an integer type, not felt252
- Detection: search for financial operations using felt252 operands — each is a potential vulnerability

**Type conversion pitfalls**
- `felt252.try_into::<u128>()` can return `None` if the value exceeds u128::MAX — if the `Option` is unwrapped without checking, the contract panics
- `felt252.into::<u256>()` is always safe (u256 range covers the felt252 range)
- Converting from u256 to felt252 can silently wrap if the u256 value exceeds P
- Detection: search for `.try_into()` and `.into()` on felt252 values — verify error handling exists

**Address arithmetic**
- Contract addresses are `ContractAddress` (a felt252 wrapper) — performing arithmetic on addresses is syntactically valid but almost always a bug
- Detection: any math operation (`+`, `-`, `*`, `/`) on a `ContractAddress` or on a felt252 known to be an address

### 2. Non-Deterministic Hints (Cairo 0)

Cairo 0 uses a prover-verifier model where "hints" are Python code executed off-chain by the prover to assist computation. Hints are the most powerful attack surface in Cairo 0 because they allow the prover to supply arbitrary values.

**How hints work**
- Hints are Python code blocks (`%{ ... %}`) embedded in Cairo 0 programs
- The prover executes hints off-chain and injects results into the execution trace
- The STARK proof only validates the constraints (assertions) — NOT the hint code
- A malicious prover can supply ANY value through a hint as long as the subsequent assertions pass

**Attack pattern: unconstrained hint output**
- If a hint assigns a value to a variable and no assertion constrains that variable, the prover controls it completely
- Example: hint provides a square root `%{ ids.x = isqrt(ids.n) %}` — if the program does not assert `x * x == n`, any `x` is accepted by the verifier
- Example: hint supplies a Merkle proof — if leaf inclusion is not verified by Cairo assertions, any data is accepted as "proven"
- Impact: Critical — the prover can fabricate any state, balance, ownership proof, or authorization
- Detection: for each `%{ ... %}` block, identify every variable the hint writes to, then trace forward to find the assertion that constrains it. Missing assertion = critical vulnerability.

**Common unconstrained hint patterns**
- Sorting hints: hint sorts an array but program does not verify the output is a permutation of the input
- Division hints: hint computes `a / b` but program does not verify `result * b == a`
- Lookup hints: hint provides a value from a table but program does not verify membership
- Conditional hints: hint chooses a branch but program does not verify the branch condition

**Cairo 1 (current) and hint-like risks**
- Cairo 1 does not have raw Python hints, but non-determinism still exists:
  - `extern fn` declarations — functions implemented by the VM, not by Cairo code. These may rely on prover-supplied values.
  - `core::hint` — low-level hint mechanism in Cairo 1, rarely used in application contracts
  - Oracle inputs — external data supplied to contracts behaves similarly to hints (unconstrained without verification)
- Detection: search for `extern fn` declarations in dependencies — verify the outputs are constrained

**Migration from Cairo 0 to Cairo 1**
- Contracts ported from Cairo 0 to Cairo 1 may have logic that was safe only because of hint constraints
- The port may remove the hint but also remove the constraint that validated the hint output
- Detection: if the project has a Cairo 0 predecessor, compare the constraint structure — missing assertions that were previously hint-guards are vulnerabilities
- Impact: moderate to critical depending on what the removed constraint was validating

**Sequencer-level risk**
- The Starknet sequencer executes transactions and produces blocks — a malicious or compromised sequencer can:
  - Reorder transactions (front-running, sandwich attacks)
  - Censor transactions temporarily
  - Choose favorable block timestamps
- Impact: time-sensitive operations, auctions, and first-come-first-served mechanisms are at risk
- Note: this is an infrastructure risk, not a contract-level bug, but auditors should flag contracts that assume fair ordering

### 3. Native Account Abstraction

On Starknet, there are NO externally-owned accounts (EOAs). Every account is a smart contract, which means every user wallet is a Cairo contract with custom validation logic. This creates a unique attack surface.

**`__validate__` and `__execute__` separation**
- Transaction processing has two distinct phases: validation (can this transaction proceed?) and execution (do the work)
- `__validate__` runs first — if it reverts, the transaction is rejected and the sequencer is not compensated
- `__execute__` runs second — if it reverts, the transaction is still included and gas is consumed
- Critical bug: state changes made in `__validate__` persist even if `__execute__` reverts
  - Impact: an attacker can cause state changes via the validation phase alone
  - Detection: search for any storage writes within `__validate__` — it should be strictly view-only
  - Any write in `__validate__` is a finding (minimum Medium severity)

**Authorization divergence between validate and execute**
- `__validate__` checks the signature and authorizes the transaction
- `__execute__` performs the actual call(s)
- Bug: if `__validate__` authorizes transaction X but `__execute__` allows the caller to perform actions beyond what was validated
- Example: `__validate__` checks the signature for a specific function call, but `__execute__` blindly forwards any call data
- Detection: verify that the scope of what `__execute__` does is strictly bounded by what `__validate__` approved

**`__validate_declare__` and `__validate_deploy__`**
- Separate validation entry points for class declaration and contract deployment
- These are often overlooked in audits — same rules apply: no state writes, proper authorization
- Detection: search for `__validate_declare__` and `__validate_deploy__` and apply the same analysis as `__validate__`

**Custom signature schemes and replay risks**
- Account contracts implement their own signature verification — there is no protocol-enforced standard
- Replay risks in custom signature schemes:
  - Missing nonce: signed message has no nonce — same signature accepted repeatedly
  - Missing chain_id: signature valid on testnet replayed on mainnet (or cross-chain)
  - Missing contract address: signature from account A replayed against account B
  - Signature malleability: ECDSA s-value not canonicalized — attacker creates a second valid signature from the first
  - Missing hash domain separation: different message types with the same structure can be confused
- Detection: extract the signed hash construction — verify it includes nonce, chain_id, contract address, and a type prefix
- Safe pattern: follow Starknet's recommended transaction hash structure or SNIP-12 (analogous to EIP-712)

**Multicall and atomic composability**
- Starknet accounts natively support batched calls in a single transaction via `__execute__`
- Impact: atomicity of multicall enables flash-loan-like composability — an attacker can manipulate state, exploit, and restore in a single transaction
- Detection: can a sequence of batched calls create a temporary state that violates invariants?

**Gas estimation attacks against account contracts**
- `__validate__` consumes gas — if an account contract always passes validation but always fails execution, it wastes sequencer resources without paying fees
- A contract with an expensive `__validate__` that conditionally reverts can be used as a DoS vector against the sequencer
- Fee estimation calls (`estimate_fee`) execute `__validate__` — a contract can return different gas estimates than actual execution costs
- Impact: DoS against the sequencer, fee market manipulation, gas estimation oracle poisoning
- Detection: does `__validate__` have consistent gas behavior? Can it be forced into expensive paths by external state?

### 4. L1-L2 Message Vulnerabilities

Starknet's L1-L2 messaging bridge enables communication between Ethereum (L1) and Starknet (L2). This cross-layer channel is a high-value attack surface.

**L1->L2 message spoofing (`from_address` validation)**
- Anyone can send an L1->L2 message by calling the Starknet core contract on Ethereum
- The L2 handler receives `from_address` as the first parameter — this is the L1 sender address
- Critical: if the L2 handler does not validate `from_address`, an attacker sends a message from their own L1 contract and spoofs any intended sender
- Detection: every `#[l1_handler]` function must verify `from_address` against a stored whitelist or expected L1 contract address
- Pattern: `assert(from_address == self.trusted_l1_bridge.read(), 'unauthorized L1 sender');`
- Severity: Critical — allows unauthorized minting, balance manipulation, or privilege escalation on L2

**L2->L1 message replay**
- L2->L1 messages are sent via `send_message_to_l1_syscall` and consumed on L1 via `consumeMessageFromL2`
- If the L1 contract does not properly track consumed messages, the same message can be consumed multiple times
- Detection: does the L1 consumer call `consumeMessageFromL2` (which handles deduplication internally via the Starknet core contract)? Or does it use a custom consumption mechanism that may be replayable?
- Impact: double-spend — withdraw assets on L1 multiple times for a single L2 burn

**Message ordering and race conditions**
- L1->L2 messages are NOT guaranteed to arrive or be processed in the order they were sent
- Impact: if a protocol assumes ordered delivery (e.g., "deposit before withdraw"), a sequencer can reorder messages or process them in any sequence
- Detection: does the handler use sequence numbers? Does it depend on a specific message ordering?
- Example: user sends "set allowance to X" then "transfer Y" — if transfer arrives first, it may fail or use stale allowance

**Message cancellation and double-spend**
- L1 sender can cancel an unconsumed L1->L2 message after a timeout period (typically 5 days)
- Attack: sender deposits on L1, L2 credits the deposit, sender cancels the L1 message and reclaims the deposit
- Impact: double-spend — attacker has funds on both L1 and L2
- Detection: does the L2 handler account for the possibility that a credited deposit's L1 message gets cancelled?
- Mitigation: finality delay — do not credit L2 funds until the cancellation window has passed, OR use a challenge mechanism

**Cross-layer reentrancy via L1-L2 message ping-pong**
- A contract on L1 sends a message to L2, which triggers an L2 contract that sends a message back to L1, which triggers the L1 contract again
- If any contract in this cycle has reentrancy-vulnerable state (e.g., it updates state AFTER sending a cross-layer message), the ping-pong can exploit it
- Detection: trace the full message flow: L1 function -> L2 handler -> L2 function -> L1 handler -> L1 function. Are there state updates that happen after message sends?
- Note: cross-layer reentrancy is not atomic (unlike EVM reentrancy) — it plays out over multiple blocks, but the state corruption is real

**Payload encoding mismatch**
- L1 (Solidity) and L2 (Cairo) use different type systems and encoding
- `uint256` on L1 requires TWO `felt252` values on L2 (low 128 bits and high 128 bits)
- `address` on L1 (20 bytes) must be correctly cast to `ContractAddress` (felt252) on L2
- Detection: verify that the serialization in the L1 contract matches the deserialization in the L2 handler
- Common bug: L1 sends a uint256 as a single value, L2 reads only the low 128 bits — high bits silently lost

### 5. Upgrade Mechanism (replace_class_syscall)

Starknet contracts are natively upgradeable through `replace_class_syscall`, which replaces the contract's class (code) in place. Unlike EVM, no proxy pattern is needed — this simplifies upgrades but creates unique risks.

**Missing access control (class hijacking)**
- `replace_class_syscall(new_class_hash)` replaces the contract's entire code in a single call
- If the function containing this syscall lacks access control, anyone can replace the contract code
- Impact: Critical — attacker replaces the contract with a malicious class that drains all funds, since the new code inherits the contract's storage and address
- Detection: search for `replace_class_syscall` — verify the containing function has `assert_only_owner`, `assert_only_role`, or equivalent guard
- The new class inherits ALL existing storage — the attacker's replacement code can read and manipulate all balances, approvals, and configuration

**Storage layout compatibility**
- The new class must use the same storage layout as the old class — there is no automatic verification
- If the new class reorders, removes, or changes the type of storage variables, existing data is read as the wrong type
- Example: old class has `balance: u256` at slot X, new class has `owner: ContractAddress` at slot X — the balance value is interpreted as an address
- Detection: compare the `#[storage]` structs of old and new classes — verify slot compatibility
- Impact: silent data corruption, potential loss of all funds or access control bypass

**Upgrade to invalid or zero class hash**
- Calling `replace_class_syscall` with a non-existent class hash bricks the contract permanently
- There is no recovery path — the contract becomes non-functional with no way to upgrade again
- Detection: is the new class hash validated before the syscall? Does the contract verify the class exists?
- Safe pattern: declare the new class first, verify declaration succeeded, then call replace_class

**Timelock bypass through self-replacing upgrade**
- If an upgrade function has a timelock but can replace the contract's class with a version that has NO timelock, the timelock is meaningless
- Attack: call upgrade with a class that has the same logic but removes the timelock, then immediately upgrade again to the malicious class
- Detection: analyze whether the upgrade path allows bypassing its own safeguards through an intermediate upgrade step
- Mitigation: the timelock logic should be immutable or enforced at a higher level (e.g., multisig wallet)

**Upgrade + migration atomicity concerns**
- After a class replacement, the new code may need to migrate storage (e.g., restructure data, initialize new variables)
- If the upgrade and migration are separate transactions, the contract is in an inconsistent state between the upgrade and migration
- Impact: during the inconsistency window, transactions may fail, produce wrong results, or be exploitable
- Detection: does the upgrade function also call a migration function atomically? Or is migration a separate step?
- Safe pattern: combine upgrade and migration in a single function that calls `replace_class_syscall` and then runs migration logic in the new class's `__constructor__` or a dedicated migration entry point
- Note: the constructor of the new class is NOT called on upgrade — migration must be triggered explicitly

### 6. Storage Patterns

Cairo storage on Starknet uses a key-value model based on Pedersen hashing. Understanding storage slot derivation is essential for detecting collisions and data corruption.

**Simple variable storage**
- Storage address for a simple variable: `sn_keccak(variable_name)`
- `sn_keccak` is a Starknet-specific Keccak variant that produces a felt252 output
- The variable name is the ASCII string of the variable as declared in the `#[storage]` struct

**Map storage (LegacyMap and Map)**
- `LegacyMap<K, V>` storage address: `h(sn_keccak(variable_name), key)` where `h` is the Pedersen hash
- For nested maps (`LegacyMap<K1, LegacyMap<K2, V>>`): `h(h(sn_keccak(variable_name), key1), key2)`
- The newer `Map<K, V>` (Cairo 2.7+) uses Poseidon hash for better performance: `poseidon(sn_keccak(variable_name), key)`
- Detection: if a contract mixes `LegacyMap` and `Map` with the same variable name, the different hash functions produce different slots — data written via one is invisible to the other

**Storage collision between components**
- Two components embedded in the same contract can collide if they use the same variable name
- Component storage prefix: `sn_keccak(component_path)` — but the path depends on how the component is imported
- If two custom components both declare a variable named `balance`, their storage slots collide
- OpenZeppelin components use well-qualified paths (e.g., `openzeppelin::access::ownable::OwnableComponent::owner`) to avoid this
- Detection: extract all `#[storage]` structs from all embedded components, compute their storage addresses, check for duplicates
- Impact: one component's storage write silently corrupts another component's data — can break balances, access control, or any stored state

**Large value storage (u256 and structs)**
- `u256` is stored as TWO consecutive felt252 slots: low 128 bits at the base slot, high 128 bits at base + 1
- If another variable is stored at base + 1, its data is corrupted by the u256 high bits
- Detection: verify that u256 variables have two consecutive slots reserved and no other variable maps to the adjacent slot
- Structs are stored sequentially: each field occupies one or more slots starting from the struct's base address
- Nested structs flatten into sequential slots — verify the total slot count matches expectations

**Struct storage packing considerations**
- Unlike Solidity, Cairo does NOT pack multiple small values into a single 252-bit slot automatically
- Each field in a `#[storage]` struct gets its own storage address derived from the struct path and field name
- Impact: storage is not as dense as EVM — but there are no packing-related corruption risks from tight packing
- However, custom packing (manually encoding multiple values into a single felt252) introduces risks: incorrect bit shifting, overflow during encoding, or truncation during decoding
- Detection: search for manual bit operations (`BitAnd`, `BitOr`, `BitShift`) on storage values — verify encoding/decoding is symmetric and handles all value ranges

**Storage address predictability**
- Storage addresses are deterministic from variable names — an attacker who knows the variable name can compute the exact slot
- This is not a vulnerability per se (same as Solidity) but is relevant for:
  - Direct storage reads via `starkli storage` or RPC calls — all storage is publicly readable
  - Contracts that assume storage values are "private" — they are not

### 7. Component-Based Architecture Risks

Cairo 2 introduced a component system that allows reusable modules to be embedded in contracts. Components bring their own storage, events, and external functions. This architecture creates several collision and composability risks.

**Storage collision between components**
- Each component declares its own `#[storage]` struct with named fields
- If two components use identical variable names in their storage, the derived storage addresses collide
- The collision is deterministic and silent — both components read and write the same slot
- Detection: list all components (search for `component!(path: ...)` in the contract), extract their storage field names, check for duplicates
- Impact: corrupted balances, broken access control, invalid state transitions
- OpenZeppelin components are safe (unique qualified paths), but custom and third-party components must be manually verified

**Event name collision between components**
- Components can emit events with the same name but different field structures
- If two components emit an event named `Transfer` with different payloads, off-chain indexers cannot distinguish them
- Impact: corrupted event logs, broken analytics, failed event-driven automation
- Detection: extract all `#[event]` enums from all embedded components, compare event variant names
- Severity: typically Low/Informational unless the protocol depends on event indexing for critical operations

**External function name collision between components**
- Components expose external functions via `#[embeddable_as(name)]` implementations
- If two components expose functions with the same selector (derived from function name and parameter types), only one is dispatched
- The last embedded component's function wins — the other is silently shadowed
- Impact: calling what a user expects to be component A's function actually executes component B's version — can lead to authorization bypass if one version has access control and the other does not
- Detection: list all `#[external(v0)]` functions from all embedded components, compute selectors, check for duplicates
- Critical check: if a shadowed function has access control but the shadowing function does not, the access control is effectively removed

**Component dependency ordering issues**
- Components can depend on other components (e.g., an ERC20 component depends on a Pausable component)
- If a required component is not embedded or is embedded after the dependent component, initialization may fail or dependencies may not resolve
- Detection: for each component, trace its `use` statements and `impl` requirements — verify all dependencies are satisfied in the contract's component list
- Impact: missing functionality, uninitialized state, or silent failure of component features

**Access control across component boundaries**
- A component may have internal functions (not external) that modify state — these are callable by any other component in the same contract
- If component A exposes an internal function that modifies sensitive state, component B can call it without A's access control checks
- Detection: search for `fn` (non-external) functions in components that modify storage — are they called from other components without authorization?
- Impact: privilege escalation through component boundary bypass
- Safe pattern: components should enforce access control within their internal functions, not just on external entry points

**Component upgrade incompatibility**
- When a contract is upgraded via `replace_class_syscall`, the new class may use different component versions
- If the new component version changes its storage layout or variable names, existing component data is corrupted
- Detection: compare component storage layouts between the old and new class — same analysis as section 5 (storage compatibility)

### 8. Access Control Patterns

Access control in Cairo contracts follows similar principles to EVM but uses Starknet-specific components and has unique pitfalls related to the account abstraction model.

**OpenZeppelin Ownable component**
- Provides `assert_only_owner()` for owner-restricted functions
- Initial owner MUST be set in the constructor — an unset owner means no one controls the contract (or a default zero address controls it)
- Detection: verify `initializer(owner)` is called in the constructor with a non-zero address
- `renounce_ownership()` permanently removes the owner — verify this is intentional and cannot be triggered accidentally
- Transfer ownership: prefer `OwnableTwoStep` (transfer + accept) over direct `transfer_ownership` to prevent ownership loss from typos

**OpenZeppelin AccessControl component**
- Role-based access with `grant_role`, `revoke_role`, `has_role`
- DEFAULT_ADMIN_ROLE must be assigned in the constructor — without it, no roles can ever be granted
- Detection: is `_grant_role(DEFAULT_ADMIN_ROLE, admin_address)` called during initialization?
- Role hierarchy: a role admin can grant and revoke its subordinate roles — verify the hierarchy does not allow privilege escalation (role A admin grants itself role B which has higher privileges)
- Self-revocation: an account can renounce its own role — verify critical single-holder roles cannot be accidentally renounced

**Missing access control on critical functions**
- Most critical: `replace_class_syscall` (upgrade) — MUST have access control (see section 5)
- Other critical functions: parameter setters, pause/unpause, emergency withdrawal, fee configuration, whitelist management
- Detection: list all `#[external(v0)]` functions that modify storage — verify each has an appropriate access control guard
- Pattern: search for functions containing `self.write()` or state modifications without `assert_only_owner`, `assert_only_role`, or equivalent

**Two-step ownership transfer**
- Single-step `transfer_ownership(new_owner)` is dangerous — if the new owner address is wrong, ownership is permanently lost
- Safe pattern: use OpenZeppelin's `OwnableTwoStep` component:
  1. Current owner calls `transfer_ownership(pending_owner)`
  2. Pending owner calls `accept_ownership()` to complete the transfer
- Detection: does the contract use `OwnableComponent` or `OwnableTwoStepComponent`? If single-step, flag as informational

**Constructor vs upgrade initialization**
- Cairo contracts run their `#[constructor]` on deployment — this sets initial state correctly
- BUT `replace_class_syscall` does NOT run the new class's constructor
- If the new class adds new state variables that need initialization, they remain at their default values (zero)
- Detection: does the new class have state variables not present in the old class? Are they initialized post-upgrade?
- Impact: uninitialized access control variables default to zero — which may mean "no owner" or "no admin", leaving the contract unprotected

**Pausable component**
- OpenZeppelin provides `PausableComponent` with `assert_not_paused()` and `assert_paused()`
- Detection: are there state-modifying functions that bypass the pause check? All critical operations should respect the pause state
- Common miss: upgrade function is pausable but the pause function itself is not — an attacker pauses, then the owner cannot upgrade to fix the issue
- Safe pattern: upgrade and unpause functions should NOT be pausable

## Key Commands

```bash
# Build and compile Cairo contracts
scarb build

# Run Cairo tests (built-in test runner)
scarb test

# Run tests with Starknet Foundry (snforge)
snforge test
snforge test --filter test_name        # Run specific test
snforge test -e test_pattern           # Run tests matching pattern

# Declare and deploy contracts via Starkli
starkli declare target/dev/contract.contract_class.json --account account.json
starkli deploy <class_hash> <constructor_args> --account account.json

# Inspect deployed contract storage
starkli storage <contract_address> <storage_key>

# Call contract functions (read-only)
starkli call <contract_address> <function_name> <args>

# Invoke contract functions (state-modifying)
starkli invoke <contract_address> <function_name> <args> --account account.json

# Find felt252 arithmetic (potential traps)
grep -rn "felt252" src/ --include="*.cairo"

# Find replace_class_syscall usage
grep -rn "replace_class_syscall\|replace_class" src/ --include="*.cairo"

# Find L1 message handlers
grep -rn "l1_handler\|from_address" src/ --include="*.cairo"

# Find access control checks
grep -rn "assert_only_role\|OwnableComponent\|assert_owner\|assert_only_owner" src/ --include="*.cairo"

# Find storage variables
grep -rn "#\[storage\]" src/ --include="*.cairo"

# Find hint blocks (Cairo 0 legacy)
grep -rn "%{" src/ --include="*.cairo"

# Find component declarations
grep -rn "component!" src/ --include="*.cairo"

# Find account entrypoints
grep -rn "__validate__\|__execute__\|__validate_declare__\|__validate_deploy__" src/ --include="*.cairo"

# Find external functions without access control (manual review needed)
grep -rn "#\[external(v0)\]" src/ --include="*.cairo"

# Find event declarations
grep -rn "#\[event\]" src/ --include="*.cairo"
```

## Validation

**felt252 arithmetic exploit PoC with snforge**
```cairo
#[test]
fn test_felt252_subtraction_wrapping() {
    let a: felt252 = 5;
    let b: felt252 = 7;
    let result = a - b;
    // result is NOT -2 — it is P - 2, a massive positive field element
    // This assertion proves the wrapping: result > 1000000
    assert(result != 0, 'result should not be zero');
    // Demonstrate: if used as a balance, this passes a "has sufficient balance" check
    assert(result > 1000000, 'wrapping produces huge value');
}

#[test]
fn test_felt252_division_is_modular_inverse() {
    let a: felt252 = 7;
    let b: felt252 = 2;
    let result = a / b;
    // result is NOT 3 — it is the modular inverse x where 2*x mod P = 7
    // Verify: result * 2 == 7 (this is the definition of field division)
    assert(result * b == a, 'modular inverse property holds');
    // But result itself is approximately P/2, NOT 3
    assert(result != 3, 'field division != integer division');
}
```

**L1->L2 message spoofing test**
```cairo
#[test]
fn test_l1_handler_without_sender_validation() {
    // Setup: deploy contract with expected L1 bridge address
    let contract = deploy_contract(trusted_l1_bridge: L1_BRIDGE_ADDRESS);
    // Attack: call the L1 handler with an unauthorized from_address
    let attacker_l1_address: felt252 = 0xDEAD;
    // If the handler does not check from_address, this succeeds
    // A passing test here means the contract is vulnerable
    contract.__l1_handler_deposit(from_address: attacker_l1_address, amount: 1000000);
    // Verify: attacker's deposit was credited without authorization
    let balance = contract.get_balance(attacker_l1_address);
    assert(balance == 1000000, 'unauthorized deposit succeeded — vulnerability confirmed');
}
```

**replace_class_syscall access control test**
```cairo
#[test]
#[should_panic(expected: ('Caller is not the owner',))]
fn test_unauthorized_upgrade_reverts() {
    let contract = deploy_contract(owner: OWNER_ADDRESS);
    // Attempt upgrade from a non-owner account
    start_prank(CheatTarget::One(contract.contract_address), ATTACKER_ADDRESS);
    let malicious_class_hash: ClassHash = 0x1234.try_into().unwrap();
    contract.upgrade(malicious_class_hash);
    // If this does NOT panic, the upgrade function lacks access control — Critical finding
}
```

**Component storage collision test**
```cairo
#[test]
fn test_component_storage_collision() {
    // Deploy a contract with two components that have colliding variable names
    let contract = deploy_dual_component_contract();
    // Write via component A
    contract.component_a_set_value(42);
    // Read via component B — if they share a storage slot, B sees A's value
    let b_value = contract.component_b_get_value();
    // If this assertion passes, storage is colliding
    assert(b_value == 42, 'storage collision detected — components share a slot');
}
```

**Account abstraction — validate state modification test**
```cairo
#[test]
fn test_validate_does_not_modify_state() {
    let account = deploy_account_contract();
    let state_before = account.get_counter();
    // Construct a transaction that triggers __validate__
    // __validate__ should be pure/view — no state changes
    let tx = build_test_transaction(account);
    account.__validate__(tx);
    let state_after = account.get_counter();
    // If state changed during validation, the account contract is vulnerable
    assert(state_before == state_after, 'validate modified state — vulnerability');
}
```

**General validation requirements**
- Demonstrate felt252 underflow: show subtraction producing a huge positive number instead of reverting
- Show L1->L2 message spoofing: send message from unauthorized L1 address and confirm handler accepts it
- Prove upgrade hijacking: call `replace_class_syscall` without authorization and confirm class hash changes
- Verify component storage collision: show two components writing to the same storage key and corrupting each other's data
- Test account abstraction: demonstrate state changes persisting from `__validate__` even when `__execute__` reverts
- Test cross-layer encoding: send a u256 from L1 and verify L2 reconstructs it correctly from two felt252 values
- Document: vulnerable function, exact call sequence, concrete state corruption, and affected user impact
