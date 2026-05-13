# CAT-ACC — Access Control

## CL-ACC-01: Access Control Enforcement Invariant

**Rule:** `MOVE-ACC-AUTH-01`
**Severity:** Medium-Critical

### Description
Every function that performs privileged operations must enforce access control. Verify the presence of sender checks, capability checks, correct visibility restrictions, consistent coverage across all entry points, and consistent pause enforcement.

### Patterns

#### Pattern 1: Missing Sender or Capability Check
A public/entry function modifies privileged state but never verifies `tx_context::sender(ctx)` against a stored admin/owner address, and does not require a capability object (`&AdminCap`, `&OperatorCap`, etc.) in its signature.

**Vulnerable:**
```move
// Anyone can set the fee — no sender check or capability required
public entry fun set_fee(config: &mut Config, new_fee: u64) {
    config.fee_bps = new_fee;
}

// Anyone can extract the mint capability — no sender check
public entry fun acquire_mint_cap(cap_holder: &mut MintCapHolder, ctx: &mut TxContext) {
    let cap = option::extract(&mut cap_holder.cap);
    transfer::public_transfer(cap, tx_context::sender(ctx)); // No auth check
}
```

**Fixed:**
```move
// Sender check
public entry fun set_fee(config: &mut Config, new_fee: u64, ctx: &mut TxContext) {
    assert!(config.admin == tx_context::sender(ctx), EUnauthorized);
    config.fee_bps = new_fee;
}

// Capability-gated extraction
public entry fun acquire_mint_cap(_: &AdminCap, cap_holder: &mut MintCapHolder, ctx: &mut TxContext) {
    let cap = option::extract(&mut cap_holder.cap);
    transfer::public_transfer(cap, tx_context::sender(ctx));
}
```

#### Pattern 2: Visibility Bypass — entry+public(package)
Marking a function as both `entry` and `public(package)` makes it callable by anyone via direct transaction despite the visibility suggesting restricted access.

**Vulnerable:**
```move
// entry overrides package visibility — anyone can call
public(package) entry fun emergency_withdraw(vault: &mut Vault, ctx: &mut TxContext) {
    let coin = coin::take(&mut vault.balance, balance::value(&vault.balance), ctx);
    transfer::public_transfer(coin, tx_context::sender(ctx));
}
```

**Fixed:**
```move
// Remove entry to restrict to package-internal calls, OR add capability check
public(package) fun emergency_withdraw(vault: &mut Vault, ctx: &mut TxContext) {
    let coin = coin::take(&mut vault.balance, balance::value(&vault.balance), ctx);
    transfer::public_transfer(coin, tx_context::sender(ctx));
}
```

#### Pattern 3: Gaps in Access Control and Pause Enforcement
Some entry points at the same privilege level are protected while others are not. Also, when a pause mechanism exists, not all state-changing entry points check it.

**Vulnerable:**
```move
public entry fun update_fee(_: &AdminCap, config: &mut Config, fee: u64) {
    config.fee = fee; // Protected
}
public entry fun update_reward_rate(config: &mut Config, rate: u64) {
    config.reward_rate = rate; // Same privilege level, no cap — gap
}

// Pause check missing on swap
public entry fun deposit(state: &State, pool: &mut Pool, coin: Coin<SUI>) {
    assert!(!state.paused, EPaused); // Checked
}
public entry fun swap(state: &State, pool: &mut Pool, coin_in: Coin<SUI>, ctx: &mut TxContext) {
    // No pause check — swaps continue during emergency
    execute_swap(pool, coin_in, ctx);
}
```

**Fixed:**
```move
public entry fun update_fee(_: &AdminCap, config: &mut Config, fee: u64) { config.fee = fee; }
public entry fun update_reward_rate(_: &AdminCap, config: &mut Config, rate: u64) { config.reward_rate = rate; }

fun assert_not_paused(state: &State) { assert!(!state.paused, EPaused); }
public entry fun deposit(state: &State, pool: &mut Pool, coin: Coin<SUI>) { assert_not_paused(state); }
public entry fun swap(state: &State, pool: &mut Pool, coin_in: Coin<SUI>, ctx: &mut TxContext) {
    assert_not_paused(state);
    execute_swap(pool, coin_in, ctx);
}
```

#### Pattern 4: Missing Ownership Verification on Shared Objects
Operating on a shared object without verifying that the caller is the authorized owner/admin, allowing anyone to manipulate it.

**Vulnerable:**
```move
// Anyone can update the URI of any NFT — no ownership check
public entry fun update_uri(
    nft: &mut NFTData,
    new_uri: vector<u8>,
) {
    nft.uri = new_uri;
}
```

**Fixed:**
```move
public entry fun update_uri(
    nft: &mut NFTData,
    new_uri: vector<u8>,
    ctx: &TxContext,
) {
    assert!(nft.creator == tx_context::sender(ctx), E_NOT_OWNER);
    nft.uri = new_uri;
}
```

#### Pattern 5: Type-Based Access Control Bypass
Using a generic type parameter as implicit authorization, where any caller can instantiate the function with an arbitrary type to bypass the intended access restriction.

**Vulnerable:**
```move
struct AdminVault<phantom T> has key { id: UID, balance: u64 }
struct AdminToken {}

// T is used as implicit auth — anyone can define their own type
public entry fun withdraw<T>(vault: &mut AdminVault<T>, amount: u64, ctx: &mut TxContext) {
    vault.balance = vault.balance - amount;
    // ... transfer to sender
}
```

**Fixed:**
```move
struct AdminVault has key { id: UID, balance: u64 }
struct AdminCap has key, store { id: UID }

// Explicit capability check instead of phantom type auth
public entry fun withdraw(_: &AdminCap, vault: &mut AdminVault, amount: u64, ctx: &mut TxContext) {
    vault.balance = vault.balance - amount;
    // ... transfer to sender
}
```

#### Pattern 6: Test/Debug Function Exposed in Production
A function intended for testing or debugging (state resets, balance overrides, free mints) is published without `#[test_only]`, making it callable on mainnet.

**Vulnerable:**
```move
// Debug helper ships to production — anyone can reset pool state
public entry fun reset_pool(pool: &mut Pool) {
    pool.total_deposited = 0;
    pool.reward_index = 0;
}
```

**Fixed:**
```move
#[test_only]
public fun reset_pool(pool: &mut Pool) {
    pool.total_deposited = 0;
    pool.reward_index = 0;
}
```

### Remediation
For every public/entry function that modifies state: verify it has either a sender check or capability parameter. Never combine `entry` with `public(package)` without an explicit auth check. Ensure all entry points at the same privilege level use the same auth pattern. If a pause mechanism exists, verify every state-changing function checks it. Validate ownership before mutation. Use explicit capability patterns instead of phantom type authorization. Gate all test/debug functions with `#[test_only]`.

### Signature
**Slug:** `access-control-enforcement-invariant`
**Detect:** For every module: (1) verify privileged functions have sender or capability checks, (2) verify no `entry` + `public(package)` combination without explicit auth, (3) verify no gaps in access control across same-privilege entry points and pause enforcement is consistent, (4) verify ownership before mutation of shared objects, (5) verify generic type parameters are not used as sole authorization mechanism, (6) verify no test/debug functions are published without `#[test_only]`.
**What's Wrong:** One or more privileged functions lack sender/capability checks, use visibility anti-patterns, have inconsistent auth/pause coverage, skip ownership checks, rely on bypassable type-based access control, or ship test/debug functions to production.
**Remediation:** Add sender or capability checks to every privileged function. Fix visibility modifiers. Centralize pause checks. Validate ownership. Use explicit capability patterns. Gate test/debug functions with `#[test_only]`.

---

## CL-ACC-02: Centralization Risk — Design-Inherent Admin Authority

**Rule:** `MOVE-ACC-CENT-01`
**Severity:** Informational

### Description
Concentration of high-impact permissions in a single account or capability without multi-sig, timelock, or decentralized governance. This is a design choice, not a bug — impact only materializes if the admin acts in bad faith or their key is compromised.

### Sub-Checks

- **a) Token Supply Control** — Can admin mint/burn arbitrary amounts without supply caps or rate limits?
- **b) Privilege Concentration** — Are multiple high-impact powers concentrated in a single key?
- **c) Direct Asset Control** — Can admin withdraw or redirect user funds directly from custodial pools?
- **d) Unrestricted Parameter Modification** — Can admin modify economic parameters at any time without bounds or timelock?
- **e) Over-scoped Sub-Admin** — Can a lower-privileged role modify parameters reserved for a higher role?
- **f) Centralized Emergency Recovery** — After emergency pause/shutdown, is asset recovery restricted to admin with no permissionless user exit?

### Code Example
```move
// INFORMATIONAL: Admin can mint unlimited tokens — correctly gated but uncapped
public entry fun mint(_: &AdminCap, amount: u64, recipient: address, ctx: &mut TxContext) {
    let coin = coin::mint(&mut treasury, amount, ctx);
    transfer::public_transfer(coin, recipient);
}
// RECOMMENDATION: Add supply cap, timelock, or multi-sig requirement
```

### Remediation
Implement multi-sig, timelocks, supply caps, rate limits, and permissionless emergency exits to reduce trust assumptions.

### Signature
**Slug:** `centralization-design-inherent->trust-assumption`
**Detect:** For every admin-gated function: assess whether the admin's power is proportionate. Flag as informational if admin could cause disproportionate harm with no safeguard beyond key security.
**What's Wrong:** Protocol relies on a single trusted admin for critical operations without multi-sig, timelock, or governance safeguards.
**Remediation:** Implement multi-sig, timelocks, supply caps, rate limits, and permissionless emergency exits to reduce trust assumptions.

---

## CL-ACC-03: Centralization Risk — Missing Operational Safeguard

**Rule:** `MOVE-ACC-CENT-02`
**Severity:** Low-Medium

### Description
The protocol implements admin powers that modify user-facing state (freezing, locking, granting permissions, emergency actions, state deletion) but is missing a corresponding reverse/safety mechanism. Unlike pure centralization (CENT-01), these have a specific missing mechanism.

### Patterns

#### Pattern 1: Lack of Reverse Function Leads to Stale/Permanent State
Admin can freeze accounts, lock positions, or grant capabilities but no corresponding unfreeze/unlock/revoke function exists.

**Vulnerable:**
```move
public entry fun freeze_account(_: &AdminCap, account: &mut UserAccount) {
    account.frozen = true;
}
// No unfreeze_account function — user is permanently frozen
```

**Fixed:**
```move
public entry fun freeze_account(_: &AdminCap, account: &mut UserAccount) {
    account.frozen = true;
}
public entry fun unfreeze_account(_: &AdminCap, account: &mut UserAccount) {
    account.frozen = false;
}
```

#### Pattern 2: Emergency Timelock Bypass
Emergency powers allow bypassing intended delays without equivalent multi-sig or governance safeguard.

**Vulnerable:**
```move
public entry fun emergency_update(_: &AdminCap, config: &mut Config, new_value: u64) {
    config.critical_param = new_value;
}
```

**Fixed:**
```move
public entry fun emergency_update(
    _admin: &AdminCap,
    _multisig: &MultisigApproval,
    config: &mut Config,
    new_value: u64,
) {
    config.critical_param = new_value;
}
```

#### Pattern 3: Unvalidated State Deletion
Admin can delete time-sensitive state without verifying expiration criteria are met.

**Vulnerable:**
```move
public entry fun cleanup_position(_: &AdminCap, registry: &mut Registry, position_id: u64) {
    table::remove(&mut registry.positions, position_id);
}
```

**Fixed:**
```move
public entry fun cleanup_position(_: &AdminCap, registry: &mut Registry, position_id: u64, clock: &Clock) {
    let position = table::borrow(&registry.positions, position_id);
    assert!(position.debt == 0, EActiveDebt);
    assert!(clock::timestamp_ms(clock) > position.expiry, ENotExpired);
    table::remove(&mut registry.positions, position_id);
}
```

### Remediation
Every restrictive action needs a release counterpart. Every grant needs a revoke. Emergency powers need equivalent safeguards. State deletion needs precondition validation.

### Signature
**Slug:** `centralization-missing-safeguard->irreversible-admin-action`
**Detect:** For every admin power that restricts user state: (1) verify a corresponding release/reverse function exists, (2) verify granted capabilities can be revoked, (3) verify emergency powers have equivalent safeguards, (4) verify state deletion validates preconditions.
**What's Wrong:** Admin actions that restrict users or grant permissions lack corresponding reverse mechanisms, creating irreversible states.
**Remediation:** Implement symmetric operations (freeze/unfreeze, grant/revoke), add precondition checks on deletions, and ensure emergency powers have multi-sig or governance equivalents.

---

## CL-ACC-04: Whitelist/Blacklist Consistency Invariant

**Rule:** `MOVE-ACC-LIST-01`
**Severity:** Medium-High

### Description
The list mechanism itself is flawed: checks are not applied at all entry points, boolean logic is inverted, list state is lost during rotations/upgrades, or bitmask operations are asymmetric.

### Sub-Checks

- **a) Enforcement Coverage** — Map ALL entry points. Verify each checks the list for BOTH sender AND recipient where applicable.
- **b) Boolean Correctness** — Verify contains() result is used with correct polarity.
- **c) Persistence Across Rotations** — Verify list storage is decoupled from rotating state.
- **d) Bitmask Symmetry** — Clearing a composite flag must clear all constituent bits.

### Code Example
```move
// VULNERABLE: blacklist check missing on transfer path
public entry fun transfer(token: &mut Token, from: address, to: address) {
    assert!(!is_blacklisted(from), EBlacklisted);
    do_transfer(token, from, to);
}

// FIXED
public entry fun transfer(token: &mut Token, from: address, to: address) {
    assert!(!is_blacklisted(from), EBlacklisted);
    assert!(!is_blacklisted(to), EBlacklisted);
    do_transfer(token, from, to);
}
```

### Remediation
Centralize list checks into a single helper called at every relevant entry point. Verify boolean polarity. Store list state independently from rotating structures. Ensure bitmask set/unset are symmetric.

### Signature
**Slug:** `whitelist-blacklist-consistency-invariant->list-bypass`
**Detect:** (1) Map all entry points and verify list check is called at each, (2) verify boolean polarity of contains() checks, (3) verify list state persists across epoch/committee rotations, (4) verify bitmask set/unset operations are symmetric.
**What's Wrong:** Whitelist or blacklist mechanism has gaps in coverage, inverted logic, non-persistent state, or asymmetric bitmask operations.
**Remediation:** Centralize list checks. Verify polarity. Decouple list storage from rotating state. Ensure symmetric bitmask operations.

---

## CL-ACC-05: Ownership & Role Transfer Safety

**Rule:** `MOVE-ACC-OWNER-01`
**Severity:** Medium-High

### Description
Every privileged role must have a safe transfer mechanism: 2-step (propose/accept), recipient-validated, cancellable, role-specific, and using dynamic state lookup.

### Patterns

#### Pattern 1: Transfer Possible
Every admin/owner address stored in shared state must have a corresponding update/transfer function.

**Vulnerable:**
```move
fun init(ctx: &mut TxContext) {
    transfer::share_object(Config {
        id: object::new(ctx),
        admin: tx_context::sender(ctx), // No setter exists — locked forever
    });
}
```

**Fixed:**
```move
fun init(ctx: &mut TxContext) {
    transfer::share_object(Config {
        id: object::new(ctx),
        admin: tx_context::sender(ctx),
        pending_admin: option::none(),
    });
}

public entry fun propose_admin(config: &mut Config, new_admin: address, ctx: &TxContext) {
    assert!(tx_context::sender(ctx) == config.admin, EUnauth);
    config.pending_admin = option::some(new_admin);
}
```

#### Pattern 2: Two-Step Transfer with Recipient Validation
Transfer must be 2-step (propose + accept). Single-step transfer means a typo permanently loses admin.

**Vulnerable:**
```move
public entry fun transfer_admin(config: &mut Config, new_admin: address, ctx: &TxContext) {
    assert!(tx_context::sender(ctx) == config.admin, EUnauth);
    config.admin = new_admin; // Single-step: typo = permanent loss
}
```

**Fixed:**
```move
public entry fun propose_admin(config: &mut Config, candidate: address, ctx: &TxContext) {
    assert!(tx_context::sender(ctx) == config.admin, EUnauth);
    assert!(candidate != @0x0, EZeroAddress);
    assert!(candidate != config.admin, ESelfTransfer);
    config.pending_admin = option::some(candidate);
}

public entry fun accept_admin(config: &mut Config, ctx: &TxContext) {
    assert!(option::contains(&config.pending_admin, &tx_context::sender(ctx)), ENotPending);
    config.admin = tx_context::sender(ctx);
    config.pending_admin = option::none();
}
```

#### Pattern 3: Cancellable Pending State with Role-Specific Claiming
Pending proposals must be cancellable by the current admin. When multiple roles exist, claim functions must verify the caller matches the correct pending role.

#### Pattern 4: Liveness
If the pending admin never accepts, the current admin must be able to cancel and restart the process.

#### Pattern 5: No Hardcoded Addresses
Admin addresses must be read from state, not hardcoded as `@0x...` literals in `assert!` checks.

### Remediation
Implement 2-step propose/accept for all privileged roles. Validate recipient addresses. Use dynamic state lookup instead of hardcoded addresses. Make pending proposals cancellable. Use separate claim functions per role.

### Signature
**Slug:** `ownership-role-transfer-invariant`
**Detect:** For every privileged role: (1) verify a transfer function exists, (2) verify it is 2-step with recipient validation, (3) verify pending state is cancellable and role-specific, (4) verify liveness (cancel/restart possible), (5) verify no hardcoded address literals in auth checks.
**What's Wrong:** Role transfer mechanism is missing, single-step, lacks recipient validation, has uncancellable pending state, confuses role types, or uses hardcoded addresses.
**Remediation:** Implement 2-step propose/accept for all roles. Use dynamic state lookup. Validate recipients. Make pending state cancellable and role-specific.

---

## CL-ACC-06: Input Validation for Setters

**Rule:** `MOVE-ACC-VALID-01`
**Severity:** Informational-Medium

### Description
All setter, update, and configuration functions must validate input values even when the caller is authorized. Human error and compromised keys can submit garbage values that brick the protocol, cause DoS, or bypass logic gates.

### Patterns

#### Pattern 1: Zero/Empty Value Checks
Address parameters must not be `@0x0`, numeric amounts must not be zero when zero is nonsensical.

#### Pattern 2: Upper Bound Checks
Fee rates, thresholds, multipliers, and durations must have maximum bounds.

#### Pattern 3: Semantic Validity
Public keys must have correct length, registry keys must be unique before insert, parallel vectors must have equal length.

#### Pattern 4: Setter-Consumer Consistency
Validation applied at the setter must match what the consumer logic expects. If the consumer divides by a value, the setter must ensure it is non-zero.

### Remediation
Add `assert!` checks for non-zero, bounds, format, uniqueness, and consistency at every setter entry point.

### Signature
**Slug:** `input-validation-invariant`
**Detect:** For every setter/update/config function: (1) check if zero/empty values are rejected when nonsensical, (2) check if upper bounds exist for rates/thresholds/multipliers, (3) check semantic validity (format, uniqueness, length), (4) check setter validation matches what consumer logic expects.
**What's Wrong:** Configuration functions accept values that are zero, out-of-range, duplicate, or semantically invalid, risking protocol bricking, DoS, or logic bypass.
**Remediation:** Add assert! checks for non-zero, bounds, format, uniqueness, and consistency at every setter entry point.
