# CAT-ACC: Access Control

**Context:** `ctx:generic`
**Detectors:** 6

## CL-ACC-01: Access Control Enforcement Invariant

**Rule:** `MOVE-ACC-AUTH-01`
**Severity:** medium-critical

## Description
Every function that performs privileged operations must enforce access control. Verify the presence of signer checks, capability checks, correct visibility restrictions, consistent coverage across all entry points, and consistent pause enforcement.

## Patterns

### Pattern 1: Missing Signer or Capability Check
A public/entry function modifies privileged state but never verifies `signer::address_of(caller)` against a stored admin/owner address, and does not require a capability resource. Also covers unchecked capability extraction — `move_from<Capability>(addr)` without verifying the signer owns that address.

**Vulnerable:**
```move
// Anyone can set the fee — no signer check
public entry fun set_fee(new_fee: u64) acquires Config {
    let config = borrow_global_mut<Config>(@module_addr);
    config.fee_bps = new_fee;
}

// Anyone can extract the mint capability
public fun acquire_mint_cap(addr: address): MintCapability acquires MintCapability {
    move_from<MintCapability>(addr) // No signer check
}
```

**Fixed:**
```move
// Signer check
public entry fun set_fee(account: &signer, new_fee: u64) acquires Config {
    let config = borrow_global_mut<Config>(@module_addr);
    assert!(signer::address_of(account) == config.admin, EUnauthorized);
    config.fee_bps = new_fee;
}

// Signer owns the capability
public fun acquire_mint_cap(caller: &signer): MintCapability acquires MintCapability {
    move_from<MintCapability>(signer::address_of(caller))
}
```

### Pattern 2: Visibility Bypass — friend as public / entry overriding friend
Using `public` instead of `public(friend)` for inter-module functions exposes internal operations to any caller. Similarly, combining `public(friend)` with `entry` defeats the friend restriction — `entry` allows direct transaction invocation by anyone regardless of the `friend` modifier.

**Vulnerable:**
```move
// Internal credit function exposed as public — anyone can call
public fun credit_user_internal(addr: address, amount: u64) acquires VaultState {
    let state = borrow_global_mut<VaultState>(@example);
    state.total_locked = state.total_locked + amount;
}

// entry overrides friend restriction — anyone can call via transaction
public(friend) entry fun emergency_drain(caller: &signer) acquires Vault {
    let vault = borrow_global_mut<Vault>(@module_addr);
    let amount = vault.balance;
    vault.balance = 0;
    coin::transfer<AptosCoin>(caller, signer::address_of(caller), amount);
}
```

**Fixed:**
```move
// Restrict to friend modules
friend example::vault_router;
public(friend) fun credit_user_internal(addr: address, amount: u64) acquires VaultState {
    let state = borrow_global_mut<VaultState>(@example);
    state.total_locked = state.total_locked + amount;
}

// Remove entry to keep friend-only, OR add explicit auth check
public(friend) fun emergency_drain(caller: &signer) acquires Vault {
    let vault = borrow_global_mut<Vault>(@module_addr);
    assert!(signer::address_of(caller) == vault.admin, EUnauthorized);
    let amount = vault.balance;
    vault.balance = 0;
    coin::transfer<AptosCoin>(caller, signer::address_of(caller), amount);
}
```

### Pattern 3: Gaps in Access Control and Pause Enforcement
Some entry points at the same privilege level are protected while others are not. Also, when a pause mechanism exists, not all state-changing entry points check it.

**Vulnerable:**
```move
public entry fun update_fee(admin: &signer, fee: u64) acquires Config {
    let config = borrow_global_mut<Config>(@module_addr);
    assert!(signer::address_of(admin) == config.admin, EUnauth);
    config.fee = fee; // Protected
}
public entry fun update_reward_rate(rate: u64) acquires Config {
    let config = borrow_global_mut<Config>(@module_addr);
    config.reward_rate = rate; // Same privilege level, no signer check — gap
}

// Pause check missing on swap
public entry fun deposit(account: &signer, amount: u64) acquires State, Pool {
    let state = borrow_global<State>(@module_addr);
    assert!(!state.paused, EPaused); // Checked
}
public entry fun swap(account: &signer, amount_in: u64) acquires State, Pool {
    // No pause check — swaps continue during emergency
    let pool = borrow_global_mut<Pool>(@module_addr);
    execute_swap(pool, signer::address_of(account), amount_in);
}
```

**Fixed:**
```move
public entry fun update_fee(admin: &signer, fee: u64) acquires Config {
    let config = borrow_global_mut<Config>(@module_addr);
    assert!(signer::address_of(admin) == config.admin, EUnauth);
    config.fee = fee;
}
public entry fun update_reward_rate(admin: &signer, rate: u64) acquires Config {
    let config = borrow_global_mut<Config>(@module_addr);
    assert!(signer::address_of(admin) == config.admin, EUnauth);
    config.reward_rate = rate;
}

fun assert_not_paused() acquires State { assert!(!borrow_global<State>(@module_addr).paused, EPaused); }
public entry fun deposit(account: &signer, amount: u64) acquires State, Pool { assert_not_paused(); }
public entry fun swap(account: &signer, amount_in: u64) acquires State, Pool {
    assert_not_paused();
    let pool = borrow_global_mut<Pool>(@module_addr);
    execute_swap(pool, signer::address_of(account), amount_in);
}
```

### Pattern 4: Missing Object Ownership Verification
Operating on an Aptos Object without verifying that the caller is the owner, allowing anyone who knows the object address to manipulate it.

**Vulnerable:**
```move
// Anyone can update the URI of any NFT — no ownership check
public entry fun update_uri(
    caller: &signer,
    nft_obj: Object<NFTData>,
    new_uri: vector<u8>
) acquires NFTData {
    let nft_addr = object::object_address(&nft_obj);
    let nft = borrow_global_mut<NFTData>(nft_addr);
    nft.uri = new_uri;
}
```

**Fixed:**
```move
public entry fun update_uri(
    caller: &signer,
    nft_obj: Object<NFTData>,
    new_uri: vector<u8>
) acquires NFTData {
    assert!(object::is_owner(nft_obj, signer::address_of(caller)), E_NOT_OWNER);
    let nft_addr = object::object_address(&nft_obj);
    let nft = borrow_global_mut<NFTData>(nft_addr);
    nft.uri = new_uri;
}
```

### Pattern 5: Type-Based Access Control Bypass
Using a generic type parameter as implicit authorization, where any caller can instantiate the function with an arbitrary type to bypass the intended access restriction.

**Vulnerable:**
```move
struct AdminVault<phantom T> has key { balance: u64 }
struct AdminToken {}

// T is used as implicit auth — anyone can define their own type
public entry fun withdraw<T>(caller: &signer, amount: u64) acquires AdminVault {
    let vault = borrow_global_mut<AdminVault<T>>(signer::address_of(caller));
    vault.balance = vault.balance - amount;
}
```

**Fixed:**
```move
struct AdminVault has key { balance: u64 }
struct AdminCap has key, store {}

// Explicit capability check instead of phantom type auth
public entry fun withdraw(caller: &signer, amount: u64) acquires AdminVault, AdminCap {
    assert!(exists<AdminCap>(signer::address_of(caller)), E_NOT_ADMIN);
    let vault = borrow_global_mut<AdminVault>(@example);
    vault.balance = vault.balance - amount;
}
```

### Pattern 6: Test/Debug Function Exposed in Production
A function intended for testing or debugging (state resets, balance overrides, free mints) is published without `#[test_only]`, making it callable on mainnet. The `#[test_only]` attribute excludes the function from compiled bytecode entirely.

**Vulnerable:**
```move
// Debug helper ships to production — anyone can reset pool state
public entry fun reset_pool(admin: &signer) acquires Pool {
    let pool = borrow_global_mut<Pool>(@module_addr);
    pool.total_staked = 0;
    pool.accumulated_rewards = 0;
}

// Free mint for "testing" — callable on mainnet
public entry fun mint_test_tokens(recipient: &signer, amount: u64) {
    let coins = coin::mint<ProtocolToken>(amount, &get_mint_cap());
    coin::deposit(signer::address_of(recipient), coins);
}
```

**Fixed:**
```move
// #[test_only] excludes from published bytecode
#[test_only]
public fun reset_pool() acquires Pool {
    let pool = borrow_global_mut<Pool>(@module_addr);
    pool.total_staked = 0;
    pool.accumulated_rewards = 0;
}

#[test_only]
public fun mint_test_tokens(recipient: &signer, amount: u64) {
    let coins = coin::mint<ProtocolToken>(amount, &get_mint_cap());
    coin::deposit(signer::address_of(recipient), coins);
}
```

## Remediation
For every public/entry function that modifies state: verify it has either a signer check or capability resource. Use `public(friend)` for inter-module functions instead of `public`. Never combine `entry` with `public(friend)` without an explicit auth check. Ensure all entry points at the same privilege level use the same auth pattern. If a pause mechanism exists, verify every state-changing function checks it. Validate object ownership before mutation. Use explicit capability patterns instead of phantom type authorization. Gate all test/debug functions with `#[test_only]`.

## Signature
**Slug:** `access-control-enforcement-invariant`
**Detect:** For every module: (1) verify privileged functions have signer or capability checks, (2) verify no `public` where `public(friend)` is intended and no `public(friend) entry` without explicit auth, (3) verify no gaps in access control across same-privilege entry points and pause enforcement is consistent, (4) verify object ownership before mutation, (5) verify generic type parameters are not used as sole authorization mechanism, (6) verify no test/debug functions are published without `#[test_only]`.
**What's Wrong:** One or more privileged functions lack signer/capability checks, use visibility anti-patterns (`entry` overriding `friend`), have inconsistent auth/pause coverage, skip object ownership checks, rely on bypassable type-based access control, or ship test/debug functions to production.
**Remediation:** Add signer or capability checks to every privileged function. Fix visibility modifiers. Centralize pause checks. Validate object ownership. Use explicit capability patterns. Gate test/debug functions with `#[test_only]`.

---

## CL-ACC-02: Centralization Risk — Design-Inherent Admin Authority

**Rule:** `MOVE-ACC-CENT-01`
**Severity:** informational

## Precondition
The protocol uses a single administrative account, capability, or role to manage critical system parameters, asset flows, and operations — and the access control for this role IS correctly implemented.

## Root Cause
Concentration of high-impact permissions in a single account or capability without multi-sig, timelock, or decentralized governance. This is a design choice, not a bug — impact only materializes if the admin acts in bad faith or their key is compromised.

## Impact
A compromised or malicious admin can inflate token supply, drain user funds, manipulate economic parameters, pause the protocol indefinitely, or rug-pull users. This is a trust assumption, not an exploitable vulnerability.

## Remediation
- Multi-sig for admin operations
- Timelock on parameter changes (users can exit before effect)
- DAO/governance for critical decisions
- Rate limits / caps on admin-controlled parameters
- Permissionless emergency withdrawal for users

## Sub-Checks

### a) Token Supply Control
Can admin mint/burn arbitrary amounts without supply caps or rate limits?

### b) Privilege Concentration
Are multiple high-impact powers (fee setting, asset withdrawal, parameter updates, upgrades) concentrated in a single key?

### c) Direct Asset Control
Can admin withdraw or redirect user funds directly from custodial pools?

### d) Unrestricted Parameter Modification
Can admin modify economic parameters (fees, rates, ratios, exchange rates) at any time without bounds or timelock?

### e) Over-scoped Sub-Admin
Can a lower-privileged role modify parameters that should be reserved for a higher role?

### f) Centralized Emergency Recovery
After emergency pause/shutdown, is asset recovery restricted to admin with no permissionless user exit?

## Code Example
```move
// INFORMATIONAL: Admin can mint unlimited tokens — correctly gated but uncapped
public entry fun mint(admin: &signer, amount: u64, recipient: address) acquires Treasury {
    let treasury = borrow_global_mut<Treasury>(@protocol);
    let coin = coin::mint(&treasury.mint_cap, amount);
    coin::deposit(recipient, coin);
}
// RECOMMENDATION: Add supply cap, timelock, or multi-sig requirement
```

## Signature
**Slug:** `centralization-design-inherent→trust-assumption`
**Detect:** For every admin-gated function: assess whether the admin's power is proportionate. Flag as informational if admin could cause disproportionate harm (drain funds, brick protocol) with no safeguard beyond key security.
**What's Wrong:** Protocol relies on a single trusted admin for critical operations without multi-sig, timelock, or governance safeguards.
**Remediation:** Implement multi-sig, timelocks, supply caps, rate limits, and permissionless emergency exits to reduce trust assumptions.

## Classification Reasoning
These are not bugs — access control works correctly. The risk is centralization of power. Flagged as informational to inform users of trust assumptions. Separate from findings where a safeguard is missing (see CENT-02).

---

## CL-ACC-03: Centralization Risk — Missing Operational Safeguard

**Rule:** `MOVE-ACC-CENT-02`
**Severity:** low-medium (context-dependent)

## Precondition
The protocol implements admin powers that modify user-facing state (freezing, locking, granting permissions, emergency actions, state deletion) but is missing a corresponding reverse/safety mechanism.

## Root Cause
A concrete safeguard is absent: restrictive actions lack release counterparts, granted permissions cannot be revoked, timelocks can be bypassed, or state deletion skips validation. Unlike pure centralization (CENT-01), these have a specific missing mechanism.

## Impact
Users can be permanently locked out of funds, permissions cannot be revoked after compromise, or state can be corrupted by admin error.

## Remediation
Every restrictive action needs a release counterpart. Every grant needs a revoke. Emergency powers need equivalent safeguards. State deletion needs precondition validation.

## Patterns

### Pattern 1: Lack of Reverse Function Leads to Stale/Permanent State
Admin can freeze accounts, lock positions, or grant capabilities but no corresponding unfreeze/unlock/revoke function exists. This creates permanently stale or irreversible state — frozen users are locked forever, compromised capability holders retain power indefinitely.

**Vulnerable:**
```move
public entry fun freeze_account(admin: &signer, user_addr: address) acquires UserAccount {
    let account = borrow_global_mut<UserAccount>(user_addr);
    account.frozen = true;
}
// No unfreeze_account function — user is permanently frozen

public entry fun grant_cap(admin: &signer, recipient: address) acquires CapStore {
    let store = borrow_global_mut<CapStore>(@module_addr);
    let cap = WithdrawCap {};
    move_to(&account::create_signer_for_test(recipient), cap); // Simplified
}
// No revoke_cap or destroy mechanism — compromised holder keeps power forever
```

**Fixed:**
```move
public entry fun freeze_account(admin: &signer, user_addr: address) acquires AdminConfig, UserAccount {
    assert_admin(admin);
    let account = borrow_global_mut<UserAccount>(user_addr);
    account.frozen = true;
}
public entry fun unfreeze_account(admin: &signer, user_addr: address) acquires AdminConfig, UserAccount {
    assert_admin(admin);
    let account = borrow_global_mut<UserAccount>(user_addr);
    account.frozen = false;
}

public entry fun grant_cap(admin: &signer, recipient: address) acquires AdminConfig, CapRegistry {
    assert_admin(admin);
    let registry = borrow_global_mut<CapRegistry>(@module_addr);
    table::add(&mut registry.caps, recipient, true);
}
public entry fun revoke_cap(admin: &signer, holder: address) acquires AdminConfig, CapRegistry {
    assert_admin(admin);
    let registry = borrow_global_mut<CapRegistry>(@module_addr);
    table::remove(&mut registry.caps, holder);
}
```

### Pattern 2: Emergency Timelock Bypass
Emergency powers allow bypassing intended delays without equivalent multi-sig or governance safeguard.

**Vulnerable:**
```move
public entry fun emergency_update(admin: &signer, new_value: u64) acquires AdminConfig, Config {
    assert_admin(admin);
    // Bypasses the normal 24h timelock with no additional safeguard
    let config = borrow_global_mut<Config>(@module_addr);
    config.critical_param = new_value;
}
```

**Fixed:**
```move
public entry fun emergency_update(
    admin: &signer,
    new_value: u64,
) acquires AdminConfig, MultisigState, Config {
    assert_admin(admin);
    assert_multisig_approved(admin); // Requires multi-sig for emergency bypass
    let config = borrow_global_mut<Config>(@module_addr);
    config.critical_param = new_value;
}
```

### Pattern 3: Unvalidated State Deletion
Admin can delete time-sensitive state (nonces, records, positions) without verifying expiration criteria are met.

**Vulnerable:**
```move
public entry fun cleanup_position(admin: &signer, position_id: u64) acquires AdminConfig, Registry {
    assert_admin(admin);
    // Deletes position without checking if it has active debt or unexpired locks
    let registry = borrow_global_mut<Registry>(@module_addr);
    table::remove(&mut registry.positions, position_id);
}
```

**Fixed:**
```move
public entry fun cleanup_position(admin: &signer, position_id: u64) acquires AdminConfig, Registry {
    assert_admin(admin);
    let registry = borrow_global_mut<Registry>(@module_addr);
    let position = table::borrow(&registry.positions, position_id);
    assert!(position.debt == 0, EActiveDebt);
    assert!(timestamp::now_seconds() > position.expiry, ENotExpired);
    table::remove(&mut registry.positions, position_id);
}
```

## Signature
**Slug:** `centralization-missing-safeguard→irreversible-admin-action`
**Detect:** For every admin power that restricts user state: (1) verify a corresponding release/reverse function exists, (2) verify granted capabilities can be revoked, (3) verify emergency powers have equivalent safeguards, (4) verify state deletion validates preconditions.
**What's Wrong:** Admin actions that restrict users or grant permissions lack corresponding reverse mechanisms, creating irreversible states.
**Remediation:** Implement symmetric operations (freeze/unfreeze, grant/revoke), add precondition checks on deletions, and ensure emergency powers have multi-sig or governance equivalents.

---

## CL-ACC-04: Whitelist / Blacklist Consistency Invariant

**Rule:** `MOVE-ACC-LIST-01`
**Severity:** medium-high (context-dependent)

## Precondition
The protocol implements a whitelist (allowlist) or blacklist (denylist/restriction list) mechanism to control which addresses or entities can interact with specific functions.

## Root Cause
The list mechanism itself is flawed: checks are not applied at all entry points, boolean logic is inverted, list state is lost during rotations/upgrades, or bitmask operations are asymmetric.

## Impact
Restricted entities bypass controls via unchecked paths, whitelisted entities are incorrectly blocked, blacklisted entities regain access after rotations, or composite permission flags are incompletely cleared.

## Remediation
Centralize list checks into a single helper called at every relevant entry point. Verify boolean polarity. Store list state independently from rotating structures. Ensure bitmask set/unset are symmetric.

## Sub-Checks

### a) Enforcement Coverage
Map ALL entry points (transfer, mint, swap, claim, etc.). Verify each checks the list for BOTH sender AND recipient where applicable. Flag paths that skip the check.

### b) Boolean Correctness
Verify contains() result is used with correct polarity:
- Whitelist: assert!(contains(list, addr)) — must be IN list
- Blacklist: assert!(!contains(list, addr)) — must NOT be in list
Inverted check = complete bypass.

### c) Persistence Across Rotations
Verify list storage is decoupled from rotating state (epochs, committees, validator sets). Blacklisted validators must remain blacklisted after committee rotation.

### d) Bitmask Symmetry
If permissions/restrictions use bitmasks: clearing a composite flag (ALL/FULL_RESTRICT) must clear all constituent bits. Adding and removing must be inverse operations.

## Code Example
```move
// VULNERABLE: blacklist check missing on transfer path
public fun transfer(token: &mut Token, from: address, to: address) {
    // BUG: No blacklist check on 'to' address
    assert!(!is_blacklisted(from), EBlacklisted);
    do_transfer(token, from, to);
}

// VULNERABLE: inverted whitelist check
public fun is_allowed(list: &Table<address, bool>, addr: address): bool {
    !table::contains(list, addr) // BUG: should be table::contains (no negation)
}

// FIXED
public fun transfer(token: &mut Token, from: address, to: address) {
    assert!(!is_blacklisted(from), EBlacklisted);
    assert!(!is_blacklisted(to), EBlacklisted); // Check both sides
    do_transfer(token, from, to);
}
```

## Signature
**Slug:** `whitelist-blacklist-consistency-invariant→list-bypass`
**Detect:** (1) Map all entry points and verify list check is called at each, (2) verify boolean polarity of contains() checks, (3) verify list state persists across epoch/committee rotations, (4) verify bitmask set/unset operations are symmetric.
**What's Wrong:** Whitelist or blacklist mechanism has gaps in coverage, inverted logic, non-persistent state, or asymmetric bitmask operations.
**Remediation:** Centralize list checks. Verify polarity. Decouple list storage from rotating state. Ensure symmetric bitmask operations.

## Classification Reasoning
This invariant covers the correctness of list-based access mechanisms (separate from WHO controls the list, which is covered by access control and centralization invariants). The focus is on the mechanism itself being consistent, complete, and persistent.

---

## CL-ACC-05: Ownership & Role Transfer Invariant

**Rule:** `MOVE-ACC-OWNER-01`
**Severity:** medium-high

## Description
Every privileged role must have a safe transfer mechanism: 2-step (propose/accept), recipient-validated, cancellable, role-specific, and using dynamic state lookup. Missing or flawed transfer mechanisms lead to permanent admin loss, governance deadlock, or role confusion.

## Patterns

### Pattern 1: Transfer Possible
Every admin/owner address stored in global state must have a corresponding update/transfer function. If the admin is set only at `init` with no setter, it is permanently locked to the deployer address with no key rotation possible.

**Vulnerable:**
```move
fun init_module(deployer: &signer) {
    move_to(deployer, Config {
        admin: signer::address_of(deployer), // No setter exists — locked forever
    });
}
// No transfer_admin function anywhere in module
```

**Fixed:**
```move
fun init_module(deployer: &signer) {
    move_to(deployer, Config {
        admin: signer::address_of(deployer),
        pending_admin: option::none(),
    });
}

public entry fun propose_admin(admin: &signer, new_admin: address) acquires Config {
    let config = borrow_global_mut<Config>(@module_addr);
    assert!(signer::address_of(admin) == config.admin, EUnauth);
    config.pending_admin = option::some(new_admin);
}
```

### Pattern 2: Two-Step Transfer with Recipient Validation
Transfer must be 2-step (propose + accept). Single-step transfer means a typo permanently loses admin. The recipient address must be validated (non-zero, non-self).

**Vulnerable:**
```move
public entry fun transfer_admin(admin: &signer, new_admin: address) acquires State {
    let state = borrow_global_mut<State>(@addr);
    assert!(signer::address_of(admin) == state.admin, EUnauth);
    state.admin = new_admin; // Single-step: typo = permanent loss, no validation
}
```

**Fixed:**
```move
public entry fun propose_admin(admin: &signer, candidate: address) acquires State {
    let state = borrow_global_mut<State>(@addr);
    assert!(signer::address_of(admin) == state.admin, EUnauth);
    assert!(candidate != @0x0, EZeroAddress);
    assert!(candidate != state.admin, ESelfTransfer);
    state.pending_admin = option::some(candidate);
}

public entry fun accept_admin(candidate: &signer) acquires State {
    let state = borrow_global_mut<State>(@addr);
    assert!(option::contains(&state.pending_admin, &signer::address_of(candidate)), ENotPending);
    state.admin = signer::address_of(candidate);
    state.pending_admin = option::none();
}
```

### Pattern 3: Cancellable Pending State with Role-Specific Claiming
Pending proposals must be cancellable by the current admin. When multiple roles exist (admin, treasury, operator), claim functions must verify the caller matches the correct pending role, not a different one.

**Vulnerable:**
```move
// Shared claim function for all roles — role confusion
public entry fun claim_role(claimer: &signer) acquires State {
    let state = borrow_global_mut<State>(@addr);
    let addr = signer::address_of(claimer);
    // Pending treasury can accidentally claim admin role
    if (option::contains(&state.pending_admin, &addr)) {
        state.admin = addr;
    };
    if (option::contains(&state.pending_treasury, &addr)) {
        state.treasury = addr;
    };
    // No cancel mechanism exists
}
```

**Fixed:**
```move
public entry fun accept_admin(candidate: &signer) acquires State {
    let state = borrow_global_mut<State>(@addr);
    assert!(option::contains(&state.pending_admin, &signer::address_of(candidate)), ENotPendingAdmin);
    state.admin = signer::address_of(candidate);
    state.pending_admin = option::none();
}

public entry fun accept_treasury(candidate: &signer) acquires State {
    let state = borrow_global_mut<State>(@addr);
    assert!(option::contains(&state.pending_treasury, &signer::address_of(candidate)), ENotPendingTreasury);
    state.treasury = signer::address_of(candidate);
    state.pending_treasury = option::none();
}

public entry fun cancel_pending_admin(admin: &signer) acquires State {
    let state = borrow_global_mut<State>(@addr);
    assert!(signer::address_of(admin) == state.admin, EUnauth);
    state.pending_admin = option::none();
}
```

### Pattern 4: Liveness
If the pending admin never accepts, the current admin must be able to cancel and restart the process. Without cancellation or timeout, governance can deadlock.

**Vulnerable:**
```move
public entry fun propose_admin(admin: &signer, candidate: address) acquires State {
    let state = borrow_global_mut<State>(@addr);
    assert!(signer::address_of(admin) == state.admin, EUnauth);
    assert!(option::is_none(&state.pending_admin), EAlreadyPending); // Blocked if pending never accepts
    state.pending_admin = option::some(candidate);
}
// No cancel function — if candidate never calls accept, admin transfer is permanently stuck
```

**Fixed:**
```move
public entry fun propose_admin(admin: &signer, candidate: address) acquires State {
    let state = borrow_global_mut<State>(@addr);
    assert!(signer::address_of(admin) == state.admin, EUnauth);
    state.pending_admin = option::some(candidate); // Overwrites old pending
}

public entry fun cancel_pending_admin(admin: &signer) acquires State {
    let state = borrow_global_mut<State>(@addr);
    assert!(signer::address_of(admin) == state.admin, EUnauth);
    state.pending_admin = option::none();
}
```

### Pattern 5: No Hardcoded Addresses
Admin addresses must be read from state, not hardcoded as `@0x...` literals in `assert!` checks. Hardcoded addresses make key rotation impossible even when a setter function exists.

**Vulnerable:**
```move
public entry fun admin_action(caller: &signer) {
    assert!(signer::address_of(caller) == @0xCAFE, EUnauth); // Hardcoded — cannot rotate
}
```

**Fixed:**
```move
public entry fun admin_action(caller: &signer) acquires Config {
    let config = borrow_global<Config>(@module_addr);
    assert!(signer::address_of(caller) == config.admin, EUnauth); // Dynamic lookup
}
```

## Remediation
Implement 2-step propose/accept for all privileged roles. Validate recipient addresses. Use dynamic state lookup instead of hardcoded addresses. Make pending proposals cancellable. Use separate claim functions per role.

## Signature
**Slug:** `ownership-role-transfer-invariant`
**Detect:** For every privileged role: (1) verify a transfer function exists, (2) verify it is 2-step with recipient validation, (3) verify pending state is cancellable and role-specific, (4) verify liveness (cancel/restart possible), (5) verify no hardcoded address literals in auth checks.
**What's Wrong:** Role transfer mechanism is missing, single-step, lacks recipient validation, has uncancellable pending state, confuses role types, or uses hardcoded addresses.
**Remediation:** Implement 2-step propose/accept for all roles. Use dynamic state lookup. Validate recipients. Make pending state cancellable and role-specific.

---

## CL-ACC-06: Input Validation Invariant for Setters and Configuration

**Rule:** `MOVE-ACC-VALID-01`
**Severity:** informational-medium

## Description
All setter, update, and configuration functions must validate input values even when the caller is authorized. Human error and compromised keys can submit garbage values that brick the protocol, cause DoS, or bypass logic gates.

## Patterns

### Pattern 1: Zero/Empty Value Checks
Address parameters must not be `@0x0`, numeric amounts/rates/limits must not be zero when zero is nonsensical, string identifiers must be non-empty, and vectors must contain valid entries.

**Vulnerable:**
```move
public fun set_treasury(_: &AdminCap, config: &mut Config, addr: address) {
    config.treasury = addr; // Can be set to @0x0 — funds sent to burn address
}

public fun set_min_stake(_: &AdminCap, pool: &mut Pool, amount: u64) {
    pool.min_stake = amount; // Can be 0 — bypasses minimum stake requirement
}
```

**Fixed:**
```move
public fun set_treasury(_: &AdminCap, config: &mut Config, addr: address) {
    assert!(addr != @0x0, EZeroAddress);
    config.treasury = addr;
}

public fun set_min_stake(_: &AdminCap, pool: &mut Pool, amount: u64) {
    assert!(amount > 0, EZeroAmount);
    pool.min_stake = amount;
}
```

### Pattern 2: Upper Bound Checks
Fee rates, thresholds, multipliers, and durations must have maximum bounds. Without bounds, an admin can set fees to 100% (or higher), thresholds to zero, or durations to effectively infinite values.

**Vulnerable:**
```move
public fun set_fee(_: &AdminCap, config: &mut Config, fee_bps: u64) {
    config.fee_bps = fee_bps; // Can be set to 10000 (100%) or higher
}

public fun set_threshold(_: &AdminCap, ms: &mut MultiSig, t: u64) {
    ms.threshold = t; // Can be 0 — bypasses all signature requirements
}
```

**Fixed:**
```move
const MAX_FEE_BPS: u64 = 3000; // 30% max

public fun set_fee(_: &AdminCap, config: &mut Config, fee_bps: u64) {
    assert!(fee_bps > 0 && fee_bps <= MAX_FEE_BPS, EInvalidFee);
    config.fee_bps = fee_bps;
}

public fun set_threshold(_: &AdminCap, ms: &mut MultiSig, t: u64) {
    assert!(t > 0 && t <= vector::length(&ms.signers), EInvalidThreshold);
    ms.threshold = t;
}
```

### Pattern 3: Semantic Validity
Public keys must have correct length, registry keys must be unique before insert, vector entries must not contain duplicates when uniqueness is assumed, and parallel vectors must have equal length.

**Vulnerable:**
```move
public fun set_validators(
    _: &AdminCap,
    config: &mut Config,
    keys: vector<vector<u8>>,
    weights: vector<u64>,
) {
    // No length check — keys and weights can be mismatched
    // No key length check — invalid pubkeys accepted
    // No duplicate check
    config.validator_keys = keys;
    config.validator_weights = weights;
}
```

**Fixed:**
```move
public fun set_validators(
    _: &AdminCap,
    config: &mut Config,
    keys: vector<vector<u8>>,
    weights: vector<u64>,
) {
    let len = vector::length(&keys);
    assert!(len == vector::length(&weights), ELengthMismatch);
    assert!(len > 0, EEmptyValidatorSet);
    let i = 0;
    while (i < len) {
        assert!(vector::length(vector::borrow(&keys, i)) == 33, EInvalidKeyLength);
        let j = i + 1;
        while (j < len) {
            assert!(vector::borrow(&keys, i) != vector::borrow(&keys, j), EDuplicateKey);
            j = j + 1;
        };
        i = i + 1;
    };
    config.validator_keys = keys;
    config.validator_weights = weights;
}
```

### Pattern 4: Setter-Consumer Consistency
Validation applied at the setter must match what the consumer logic expects. If the consumer divides by a value, the setter must ensure it is non-zero. If the consumer indexes into a vector, the setter must bounds-check.

**Vulnerable:**
```move
public fun set_reward_divisor(_: &AdminCap, config: &mut Config, divisor: u64) {
    config.reward_divisor = divisor; // No zero check
}

// Elsewhere in the codebase:
public fun calculate_reward(config: &Config, amount: u64): u64 {
    amount / config.reward_divisor // Division by zero if divisor == 0
}
```

**Fixed:**
```move
public fun set_reward_divisor(_: &AdminCap, config: &mut Config, divisor: u64) {
    assert!(divisor > 0, EZeroDivisor);
    assert!(divisor <= MAX_DIVISOR, EDivisorTooLarge);
    config.reward_divisor = divisor;
}
```

## Remediation
Add `assert!` checks for non-zero, bounds, format, uniqueness, and consistency at every setter entry point. Default to informational severity unless a concrete exploit path (division by zero, permanent DoS) is demonstrated.

## Signature
**Slug:** `input-validation-invariant`
**Detect:** For every setter/update/config function: (1) check if zero/empty values are rejected when nonsensical, (2) check if upper bounds exist for rates/thresholds/multipliers, (3) check semantic validity (format, uniqueness, length), (4) check setter validation matches what consumer logic expects.
**What's Wrong:** Configuration functions accept values that are zero, out-of-range, duplicate, or semantically invalid, risking protocol bricking, DoS, or logic bypass.
**Remediation:** Add assert! checks for non-zero, bounds, format, uniqueness, and consistency at every setter entry point.

---
