---
name: solana-anchor-security
category: web3
description: Solana and Anchor program security covering account validation, PDA security, CPI privilege escalation, type confusion, remaining_accounts bypass, account closing/revival, arithmetic overflow, sysvar spoofing, and Anchor-specific constraint patterns
depends_on: [solana_security]
---

# Solana & Anchor Smart Contract Security

Comprehensive security knowledge for auditing Solana programs built with the Anchor framework and native Rust. Covers the full Solana threat model: account validation failures, PDA derivation flaws, CPI privilege escalation, Anchor constraint gaps, arithmetic overflow in release mode, sysvar spoofing, account lifecycle attacks, and token program integration pitfalls. This is the primary skill for Immunefi Solana bug bounties and Solana program audits.

## When to Use

- Target is a Solana program (native Rust or Anchor framework)
- Bug bounty on Immunefi, Code4rena, or Sherlock with Solana programs in scope
- Auditing Anchor programs for missing or insufficient constraints
- Reviewing Cross-Program Invocation (CPI) security and privilege flow
- Analyzing PDA derivation patterns for collision or canonicalization issues
- Token-2022 programs with transfer hooks, permanent delegates, or transfer fees in scope
- Any Solana program that handles user deposits, token transfers, or authority management

## Methodology

### 1. Account Validation

Account validation is the single most exploited vulnerability class on Solana. Unlike EVM where `msg.sender` is implicit and the runtime enforces caller identity, Solana requires every account passed to every instruction to be explicitly validated by the program. A missing check on any account is a direct attack vector.

#### 1.1 Missing Signer Check

The program does not verify that a given account actually signed the transaction. An attacker can pass any pubkey as the "authority" account without signing, impersonating administrators, vault owners, or multisig participants.

**Native Rust pattern (vulnerable)**:
```rust
// VULNERABLE: no signer check -- attacker passes any pubkey as authority
let authority = next_account_info(account_info_iter)?;
// proceeds to use authority.key for authorization decisions
```

**Native Rust pattern (safe)**:
```rust
let authority = next_account_info(account_info_iter)?;
if !authority.is_signer {
    return Err(ProgramError::MissingRequiredSignature);
}
```

**Anchor pattern (vulnerable)**:
```rust
// VULNERABLE: AccountInfo has no automatic signer enforcement
pub authority: AccountInfo<'info>,
```

**Anchor pattern (safe)**:
```rust
// Option A: Signer type enforces the signer check automatically
pub authority: Signer<'info>,
// Option B: Explicit constraint
#[account(signer)]
pub authority: AccountInfo<'info>,
```

**Where to look**: admin functions, withdrawal instructions, configuration updates, multisig approval handlers, vault authority transfers, any instruction that gates behavior on "who called this."

**Impact**: full privilege escalation -- attacker executes admin-only instructions, drains vaults, changes protocol parameters.

#### 1.2 Missing Owner Check

The program does not verify that an account is owned by the expected program. An attacker creates a fake account with a crafted data layout matching the expected struct, but containing malicious values (inflated balances, wrong authority keys, tampered configuration).

**Native Rust pattern (vulnerable)**:
```rust
// VULNERABLE: deserializes data without verifying account owner
let vault_data = VaultState::try_from_slice(&vault_account.data.borrow())?;
```

**Native Rust pattern (safe)**:
```rust
if vault_account.owner != program_id {
    return Err(ProgramError::IncorrectProgramId);
}
let vault_data = VaultState::try_from_slice(&vault_account.data.borrow())?;
```

**Anchor pattern (vulnerable)**:
```rust
// VULNERABLE: raw AccountInfo -- no owner or type validation
pub vault: AccountInfo<'info>,
```

**Anchor pattern (safe)**:
```rust
// Account<'info, VaultState> enforces both owner == program_id AND discriminator check
pub vault: Account<'info, VaultState>,
```

**Impact**: attacker creates an account with crafted data that deserializes cleanly but contains malicious values. For example, a fake vault account reporting 1,000,000 SOL balance when the real vault holds 10 SOL, enabling over-withdrawal.

#### 1.3 Missing Key Check

The program does not verify that the account pubkey matches the expected address. An attacker substitutes a structurally valid but different account at the same position in the instruction's account list.

**Anchor pattern (vulnerable)**:
```rust
// VULNERABLE: vault is typed but nothing checks it's THE RIGHT vault
pub vault: Account<'info, VaultState>,
pub config: Account<'info, Config>,
// attacker passes their own vault with a favorable authority field
```

**Anchor pattern (safe)**:
```rust
// has_one verifies vault.authority == authority.key()
#[account(has_one = authority)]
pub vault: Account<'info, VaultState>,
// address constraint verifies exact pubkey
#[account(address = GLOBAL_CONFIG_PUBKEY)]
pub config: Account<'info, Config>,
```

**Where to look**: any instruction that reads a stored pubkey from one account and uses it to authorize actions on another. Fee recipient accounts, pool config accounts, oracle price accounts.

**Impact**: attacker substitutes their own account (e.g., a vault where they are the authority) to pass authorization checks meant for a different vault.

#### 1.4 Missing Writable Check

The program attempts to mutate an account that was not marked as writable in the transaction. The Solana runtime will reject the transaction, but if the instruction conditionally writes (e.g., only writes on certain paths), an attacker may force the non-writing path by passing a read-only account.

**Anchor pattern**: missing `#[account(mut)]` on accounts the instruction modifies.

**Detection**: for every account in every instruction, determine if the instruction writes to it. If yes, verify `mut` is declared.

#### 1.5 Account Data Deserialization Without Discriminator Check

In native programs, there is no automatic type tag on account data. If the program deserializes raw bytes without verifying a discriminator prefix, an attacker can pass an account of a completely different type whose byte layout happens to produce valid but malicious field values.

**Example**: a `StakeAccount` has fields `[amount: u64, authority: Pubkey]` starting at byte 0. A `TokenAccount` has `[mint: Pubkey, owner: Pubkey, amount: u64]`. Without discriminator checks, passing a TokenAccount where a StakeAccount is expected maps `mint` bytes to the `amount` field -- potentially a very large number.

**Detection in native programs**: search for `borsh::BorshDeserialize`, `try_from_slice`, `unpack`, `Pack::unpack_from_slice` without a preceding discriminator comparison.

**Anchor**: the 8-byte discriminator (`sha256("account:TypeName")[..8]`) is automatically checked when using `Account<'info, T>`. Vulnerability exists when code uses raw `AccountInfo` or `UncheckedAccount` and manually deserializes.

#### 1.6 Validation Matrix Approach

For every instruction in the program, build a validation matrix covering every account:

| Account | Needs Signer? | Checked? | Expected Owner | Owner Checked? | Specific Key? | Key Checked? | Writable? | Mut Declared? |
|---------|---------------|----------|----------------|----------------|---------------|--------------|-----------|---------------|
| authority | YES | ? | N/A (wallet) | N/A | NO | N/A | NO | N/A |
| vault | NO | N/A | this program | ? | Via has_one | ? | YES | ? |
| token_program | NO | N/A | BPFLoader | ? | spl_token::ID | ? | NO | N/A |

Any `?` that resolves to NO is a finding.

### 2. PDA Security

Program Derived Addresses (PDAs) are addresses deterministically derived from seeds and a program ID. They have no private key -- only the program can sign for them via `invoke_signed`. PDA security issues arise from incorrect derivation, missing validation, and seed collision.

#### 2.1 Missing Bump Validation (Non-Canonical Bump)

`Pubkey::find_program_address(seeds, program_id)` returns the canonical bump (the highest valid bump, 255 down to 0). `Pubkey::create_program_address(seeds_with_bump, program_id)` accepts any bump. If the program uses `create_program_address` with a user-supplied bump, multiple valid PDAs exist for the same logical entity.

**Attack**: attacker finds a non-canonical bump (e.g., bump=253 instead of canonical bump=254) and derives a different PDA address. If the program stores state at this PDA, the attacker can create a parallel account that bypasses uniqueness assumptions.

**Vulnerable pattern**:
```rust
// VULNERABLE: accepts arbitrary bump from user input
let pda = Pubkey::create_program_address(
    &[b"vault", user.key.as_ref(), &[user_provided_bump]],
    program_id,
)?;
```

**Safe pattern**:
```rust
// SAFE: always use find_program_address for canonical bump
let (pda, bump) = Pubkey::find_program_address(
    &[b"vault", user.key.as_ref()],
    program_id,
);
```

**Anchor pattern**: `#[account(seeds = [b"vault", user.key().as_ref()], bump)]` stores and verifies the canonical bump. Suspicious: `bump = some_field` where the bump comes from a stored value that was never validated as canonical.

#### 2.2 PDA Seed Collision

Different logical entities share the same seeds, mapping to the same PDA. This happens when seeds are insufficiently specific.

**Example**: a lending protocol derives vault PDAs as `[b"vault", pool_id]`. If `pool_id` is a sequential u8, there are only 256 possible vaults. Two pools with the same ID would collide.

**More subtle example**: variable-length seeds without delimiters:
```rust
// VULNERABLE: seeds [b"AB", b"C"] and [b"A", b"BC"] produce the same concatenation "ABC"
let seeds = &[prefix.as_bytes(), suffix.as_bytes()];
```

**Safe pattern**: include length prefixes or fixed-width fields:
```rust
// SAFE: fixed-width or length-prefixed seeds prevent collision
let seeds = &[b"vault", &pool_id.to_le_bytes(), user.key().as_ref()];
```

**Detection**: examine all PDA derivation sites. Can two different logical entities produce the same seed sequence? Are all variable-length fields delimited or length-prefixed?

#### 2.3 Missing Seeds Constraint in Anchor

Anchor accounts with `init` but without `seeds` and `bump` constraints are not PDA-derived -- they are allocated at a random address. If the intended behavior is a deterministic PDA, the missing `seeds` constraint means the account address is unpredictable and cannot be re-derived.

**Vulnerable**:
```rust
#[account(init, payer = user, space = 8 + 64)]
pub user_state: Account<'info, UserState>,
// No seeds -- account is at a random address, not derivable from user pubkey
```

**Safe**:
```rust
#[account(init, payer = user, space = 8 + 64, seeds = [b"state", user.key().as_ref()], bump)]
pub user_state: Account<'info, UserState>,
```

#### 2.4 find_program_address vs create_program_address Misuse

- `find_program_address`: iterates bumps from 255 to 0, returns the first valid (canonical) PDA + bump. Deterministic and safe for derivation.
- `create_program_address`: takes explicit seeds including bump. Used for verification (checking a PDA matches expected seeds) and in `invoke_signed`.

**Vulnerability**: using `create_program_address` for initial derivation with a hardcoded or user-supplied bump instead of finding the canonical bump. This either creates the wrong PDA or allows bump manipulation.

**Detection**: every call to `create_program_address` should either (a) use a bump obtained from `find_program_address` or (b) use a bump stored on-chain that was originally derived canonically.

#### 2.5 PDA Signing Authority Confusion

When a program uses `invoke_signed` to sign a CPI on behalf of a PDA, the seeds and bump must exactly match the PDA's derivation. If the wrong seeds or bump are used, the CPI fails. But if the program derives the signer PDA from user-controllable data, the user might craft inputs that produce a PDA they control.

**Detection**: trace every `invoke_signed` call. Are the signer seeds derived from trusted program state, or do any seeds come from user input?

### 3. CPI Privilege Escalation

Cross-Program Invocation (CPI) is how Solana programs call each other. CPI carries implicit privilege: all accounts marked as signers in the parent instruction propagate their signer status to the callee. This privilege propagation creates escalation risks.

#### 3.1 Signer Propagation via CPI

When program A calls program B via `invoke`, every `AccountInfo` passed with `is_signer = true` retains signer authority in program B's context. If program A passes an account as a signer to a CPI that the account should NOT have signer authority for, the callee program trusts the signer flag.

**Attack scenario**: program A has a CPI to the Token Program's `transfer` instruction. If program A passes a user's token account with signer authority (because the user signed the original transaction), the Token Program sees a valid signer and executes the transfer -- even if program A's logic should not have authorized this transfer path.

**Detection**: for every CPI call, list which accounts are passed with `is_signer = true`. Verify each one SHOULD have signer authority in the callee's context. A common error: passing the user's wallet as a signer to a CPI where the PDA should be the signer instead.

#### 3.2 CPI to Arbitrary Program ID

If the target program for a CPI is loaded from an account or instruction data without validation, an attacker can redirect the CPI to a malicious program they control.

**Vulnerable pattern (native)**:
```rust
// VULNERABLE: target_program comes from an unvalidated account
invoke(
    &instruction,
    &[account_a.clone(), account_b.clone(), target_program.clone()],
)?;
```

**Safe pattern (Anchor)**:
```rust
// Anchor's Program<'info, Token> validates the program key automatically
pub token_program: Program<'info, Token>,
```

**Safe pattern (native)**:
```rust
if *target_program.key != spl_token::id() {
    return Err(ProgramError::IncorrectProgramId);
}
```

**Detection**: find every `invoke` and `invoke_signed` call. Trace the program ID: is it hardcoded, validated against a known constant, or loaded from user-controlled input?

#### 3.3 Missing Program ID Check on CPI Target

Even when the program ID appears to be validated, subtle bugs exist:

- Checking only the first few bytes of the program key
- Comparing against the wrong constant (e.g., Token Program ID when Token-2022 ID is needed)
- Off-by-one in the program ID account position (checking account N when the program is account N+1)

**Anchor mitigation**: `Program<'info, Token>` enforces the exact program ID match. `Program<'info, Token2022>` for Token-2022.

#### 3.4 Privilege Escalation Through Nested CPI Chains

Solana allows up to 4 levels of CPI depth. In complex protocols, program A calls program B which calls program C. Signer privileges from A propagate through B to C. If B does not carefully scope which signers it passes to C, privileges intended only for the A-to-B interaction leak into the B-to-C interaction.

**Detection**: trace the full CPI call graph. At each level, verify only the intended accounts carry signer authority forward.

### 4. Anchor-Specific Vulnerabilities

#### 4.1 Missing `has_one` Constraint

The `has_one` constraint verifies that a stored pubkey field on the account matches a provided account's key. Without it, related accounts are not validated against each other.

**Vulnerable**:
```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
    // MISSING: has_one = authority -- attacker can pass any vault with any authority
}
```

**Safe**:
```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
```

**Detection**: for every instruction that reads a stored pubkey from an account (e.g., `vault.authority`, `pool.oracle`, `config.admin`), verify a `has_one` or equivalent `constraint` validates the relationship.

#### 4.2 Missing `seeds` and `bump` Constraint on PDA Accounts

PDA accounts accessed without `seeds` and `bump` constraints are not verified to be the correct PDA. The account could be any account of the correct type owned by the program -- not necessarily the PDA at the expected deterministic address.

**Detection**: for every account that should be a PDA (identifiable by `init` with seeds elsewhere, or by naming convention), verify the access-side instruction also specifies `seeds` and `bump`.

#### 4.3 `remaining_accounts` Bypass

`ctx.remaining_accounts` provides access to any additional accounts passed to the instruction beyond those in the `Accounts` struct. Anchor performs ZERO validation on these accounts -- no owner check, no type check, no signer check, no discriminator check.

**Attack**: if the program iterates over `remaining_accounts` and trusts any of them (reads data, transfers tokens, uses as authority), an attacker passes crafted accounts.

**Common vulnerable pattern**:
```rust
for account in ctx.remaining_accounts.iter() {
    // VULNERABLE: no validation -- attacker controls these accounts entirely
    let data = TokenAccount::try_deserialize(&mut &account.data.borrow()[..])?;
    total += data.amount;
}
```

**Safe pattern**: validate each remaining account before use:
```rust
for account in ctx.remaining_accounts.iter() {
    // Verify owner, mint, and other properties
    if account.owner != &spl_token::id() {
        return Err(ErrorCode::InvalidTokenAccount.into());
    }
    let data = TokenAccount::try_deserialize(&mut &account.data.borrow()[..])?;
    if data.mint != expected_mint {
        return Err(ErrorCode::InvalidMint.into());
    }
    total += data.amount;
}
```

**Detection**: grep for `remaining_accounts`. Trace every field read and operation performed on each remaining account. Verify each has explicit owner, key, type, and authority validation.

#### 4.4 `init` Without Proper `payer` and `space`

Anchor `init` accounts require a `payer` (who pays rent) and `space` (account size in bytes). Wrong `space` causes issues:
- Too small: data truncation on serialization, potential corruption
- Too large: wasted lamports (minor), or if the space comes from user input, rent drain attack (user forces creation of a very large account at someone else's expense)
- Missing `payer`: compile-time error in modern Anchor, but older versions may not enforce

**Rent calculation**: space = 8 (discriminator) + serialized struct size. Failing to account for the discriminator is a common off-by-8 error that causes deserialization failures.

#### 4.5 `close` Account Vulnerability (Reopening After Close)

Anchor's `#[account(close = destination)]` constraint zeroes the account data and transfers all lamports to the destination. However, within the same transaction, a subsequent instruction can re-fund the account (send lamports back), reviving it with zeroed data.

**Attack sequence**:
1. Instruction 1: calls `close` on an account (lamports drained, data zeroed)
2. Instruction 2: transfers lamports back to the closed account's address
3. Instruction 3: the account now exists with zero data but non-zero lamports -- subsequent reads may interpret zeroed data as valid defaults (e.g., balance = 0, authority = 11111111... i.e., system program)

**Detection**: search for `close` constraints and trace whether the closed account's address could be re-funded within the same transaction by another instruction.

**Mitigation**: programs should check for initialization state (a non-zero discriminator or an explicit `is_initialized` flag) before operating on any account. The zeroed discriminator after close should cause `Account<'info, T>` deserialization to fail on revival -- but raw `AccountInfo` access bypasses this.

#### 4.6 Anchor Discriminator Collision Between Instructions

Anchor derives instruction discriminators as `sha256("global:instruction_name")[..8]`. If two instructions have the same discriminator (extremely unlikely but possible with crafted names, or in cross-program scenarios), a CPI intended for instruction A could execute instruction B.

**Detection**: extract all instruction discriminators and check for collisions. Anchor's IDL generator will show these. Cross-program: if program A builds a CPI instruction for program B using a manual discriminator, verify it matches B's actual discriminator.

#### 4.7 `init_if_needed` Hazard

`#[account(init_if_needed, ...)]` creates the account if it does not exist, or uses the existing account if it does. This is a front-running vector: an attacker can create the account before the legitimate user, seeding it with attacker-controlled initial state.

**Detection**: search for `init_if_needed`. This feature must be explicitly enabled in Anchor (`features = ["init-if-needed"]`). Every use should be audited for front-running risk. Ask: what happens if an attacker initializes this account with their own pubkey as the authority before the intended user?

### 5. Arithmetic and Overflow

#### 5.1 Release Mode Wrapping

This is Solana's most counter-intuitive arithmetic behavior. Rust compiled with `cargo build-sbf` uses the release profile, which wraps on integer overflow instead of panicking. Unlike debug mode (which panics on overflow), deployed Solana programs silently wrap.

**Example**:
```rust
let balance: u64 = 10;
let withdrawal: u64 = 20;
let remaining = balance - withdrawal; // In release mode: 18446744073709551606 (u64::MAX - 9)
// No panic, no error -- program continues with a massive incorrect value
```

**Impact**: balance underflows produce astronomical values, enabling over-withdrawal. Accumulated rewards overflow to zero. Timestamps wrap producing far-future or far-past values.

**Detection**: search for ALL arithmetic operations (`+`, `-`, `*`, `%`, `<<`, `>>`) on integer types. Each must use checked methods or be provably safe via domain constraints.

**Safe patterns**:
```rust
let remaining = balance.checked_sub(withdrawal).ok_or(ErrorCode::InsufficientFunds)?;
let total = amount_a.checked_add(amount_b).ok_or(ErrorCode::Overflow)?;
let product = price.checked_mul(quantity).ok_or(ErrorCode::Overflow)?;
```

**Anchor mitigation**: the `overflow-checks = true` setting in `Cargo.toml` under `[profile.release]` causes overflow to panic even in release mode. Verify this is set. If the program uses `#[cfg(not(feature = "no-overflow-checks"))]`, ensure the `no-overflow-checks` feature is NOT enabled in the production build.

#### 5.2 checked_add / checked_mul / checked_sub Not Used

Beyond the wrapping behavior, missing checked arithmetic is a direct vulnerability. Every arithmetic operation on user-controlled or state-derived values must use checked methods.

**Priority targets for detection**:
- Token amount calculations (deposits, withdrawals, fees, rewards)
- Time-based calculations (duration, deadline, epoch math)
- Share/rate calculations in vaults and staking
- Loop counters and array indices

#### 5.3 Integer Truncation via `as` Casts

Rust's `as` keyword performs silent truncation when casting to a smaller type. In release mode, no panic occurs.

**Vulnerable**:
```rust
let large_amount: u128 = 340282366920938463463374607431768211455; // u128::MAX
let truncated: u64 = large_amount as u64; // Silently truncates to 18446744073709551615
```

**Safe**:
```rust
let safe_amount: u64 = u64::try_from(large_amount)
    .map_err(|_| ErrorCode::AmountTooLarge)?;
```

**Detection**: search for `as u64`, `as u32`, `as u16`, `as u8`, `as i64`, `as i32`, `as i16`, `as i8`. Each is a potential silent truncation.

#### 5.4 SPL Token Amount Calculations with Precision Loss

SPL Token amounts are u64 with implicit decimal scaling (e.g., 6 decimals for USDC, 9 for SOL). Precision loss in division operations creates extractable rounding errors.

**Vulnerable ordering**:
```rust
// VULNERABLE: division before multiplication loses precision
let fee = amount / FEE_DENOMINATOR * fee_rate;
```

**Safe ordering**:
```rust
// SAFE: multiplication before division preserves precision
let fee = amount.checked_mul(fee_rate)
    .ok_or(ErrorCode::Overflow)?
    .checked_div(FEE_DENOMINATOR)
    .ok_or(ErrorCode::DivisionByZero)?;
```

**Rounding direction**: in share/vault calculations, always round against the user. Deposits: round shares down (user gets fewer shares). Withdrawals: round tokens down (user gets fewer tokens). This prevents rounding-based extraction attacks.

### 6. Sysvar Spoofing

#### 6.1 Passing Fake Sysvar Accounts

Before Solana 1.8, programs accessed sysvars by deserializing from an `AccountInfo` passed in the instruction accounts. An attacker could craft a fake account with the same data layout as a sysvar but with manipulated values (e.g., a `Clock` with a future timestamp, or `Rent` with zero minimum balance).

**Vulnerable pattern**:
```rust
// VULNERABLE: reads Clock from a passed account without verifying the account address
let clock_account = next_account_info(account_info_iter)?;
let clock: Clock = bincode::deserialize(&clock_account.data.borrow())?;
```

**Safe patterns**:
```rust
// SAFE: syscall-based access, cannot be spoofed (Solana 1.8+)
let clock = Clock::get()?;
let rent = Rent::get()?;

// SAFE: validates account address before deserialization
let clock = Clock::from_account_info(clock_account)?;
// from_account_info verifies clock_account.key == sysvar::clock::id()
```

**Anchor pattern (safe)**:
```rust
// Anchor's Sysvar<'info, Clock> validates the address automatically
pub clock: Sysvar<'info, Clock>,
```

**Detection**: search for sysvar deserialization from `AccountInfo` without address validation. Search for `bincode::deserialize` on accounts named `clock`, `rent`, `epoch_schedule`, `slot_hashes`.

#### 6.2 Clock Sysvar Manipulation Considerations

Even with legitimate Clock access, `Clock::get()?.unix_timestamp` comes from the validator's system clock and is not perfectly accurate. Validators have some leeway in the timestamp they report. For time-critical logic:

- Do not rely on sub-second timestamp precision
- Consider that timestamps can drift within the slot time (~400ms)
- For auction deadlines, use slot numbers instead of timestamps where possible
- `Clock::get()?.slot` is monotonically increasing and more reliable than `unix_timestamp`

#### 6.3 Rent Sysvar and Rent Exemption Checks

After any lamport transfer from an account, verify the source account remains rent-exempt:
```rust
let rent = Rent::get()?;
let min_balance = rent.minimum_balance(account.data_len());
if account.lamports() < min_balance {
    return Err(ProgramError::InsufficientFunds);
}
```

If an account drops below rent exemption, it becomes eligible for garbage collection at the end of the epoch. This can be weaponized: an attacker drains just enough lamports from a program-owned account to make it non-rent-exempt, causing permanent data loss.

### 7. Account Closing and Revival

#### 7.1 Incomplete Closing (Rent-Exempt Lamports Not Fully Drained)

A properly closed account must have ALL lamports transferred out AND data zeroed AND ownership reassigned to the system program. If any step is skipped:

- Lamports not fully drained: account persists, may be re-used
- Data not zeroed: stale data readable by other programs or subsequent transactions
- Owner not reassigned: the program still owns the account, can write to it

**Required close sequence (native)**:
```rust
// 1. Zero all data
let mut data = account.data.borrow_mut();
data.fill(0);
// 2. Transfer ALL lamports to recipient
let dest_lamports = dest.lamports();
**dest.lamports.borrow_mut() = dest_lamports.checked_add(account.lamports())
    .ok_or(ProgramError::ArithmeticOverflow)?;
**account.lamports.borrow_mut() = 0;
// 3. Assign owner to system program
account.assign(&system_program::id());
```

**Anchor**: `#[account(close = destination)]` handles all three steps correctly. Verify Anchor version is recent enough to include the system program owner reassignment (added in Anchor 0.25+).

#### 7.2 Account Reopened in Same Transaction After Close

The Solana runtime does not garbage-collect accounts mid-transaction. A closed account (zero lamports, zero data) can be re-funded by a subsequent instruction within the same transaction, resurrecting it.

**Attack**:
1. Transaction with 3 instructions:
   - Instruction 1: close a staking account (receive rewards + principal)
   - Instruction 2: transfer 1 lamport back to the closed account address
   - Instruction 3: call the staking program again -- the account exists with zeroed data, which may be interpreted as a fresh state (zero balance = no prior withdrawals)

**Mitigation**: check for a non-zero discriminator before operating on any account. The zeroed discriminator after close should be treated as "this account is dead." Anchor's `Account<'info, T>` enforces this -- but raw `AccountInfo` access does not.

#### 7.3 Data Not Zeroed After Closing

If the program transfers lamports out but does not zero the data, the account remains readable. Other programs or off-chain indexers may interpret stale data as current state.

**Impact**: stale authority fields, stale balance fields, stale configuration -- any of these can be exploited if another instruction or program reads them.

#### 7.4 Account Closing Without Returning Lamports to Correct Recipient

If the close destination is user-controlled without validation, an attacker can redirect the lamports to their own account instead of the intended recipient. Verify the close recipient is either hardcoded or validated against stored state.

### 8. Token Program Integration

#### 8.1 Missing Token Account Mint Check

If a program accepts a token account but does not verify the `mint` field matches the expected token, an attacker can pass a token account for a worthless mint and have the program treat it as a valuable token.

**Vulnerable**:
```rust
// VULNERABLE: no mint verification
pub user_token_account: Account<'info, TokenAccount>,
```

**Safe**:
```rust
// Verifies the token account's mint matches the expected mint
#[account(token::mint = expected_mint)]
pub user_token_account: Account<'info, TokenAccount>,
```

**Detection**: for every token account in every instruction, verify a `token::mint` constraint or manual mint comparison exists.

#### 8.2 Missing Token Account Authority Check

The `authority` field on a token account determines who can transfer tokens from it. If the program does not verify the authority matches the expected signer, an attacker can pass a token account they control but with the correct mint.

**Safe pattern**:
```rust
#[account(
    token::mint = expected_mint,
    token::authority = user,
)]
pub user_token_account: Account<'info, TokenAccount>,
```

#### 8.3 Token-2022 Transfer Hooks (Reentrancy via Hook)

Token-2022 (SPL Token Extensions) introduces transfer hooks: custom programs that execute automatically during every token transfer. A malicious or buggy transfer hook can:

- Reenter the calling program during the transfer
- Revert the transfer conditionally (DoS)
- Execute arbitrary logic with the signer context of the transfer instruction

**Impact**: any program that transfers Token-2022 tokens with transfer hooks enabled is potentially vulnerable to reentrancy. The hook executes within the CPI context, inheriting signer privileges.

**Detection**: does the program interact with Token-2022 tokens? Check if the token mint has a transfer hook extension configured. If the program does not expect reentrancy during transfers, it must either reject tokens with transfer hooks or implement reentrancy guards.

**Safe pattern**: verify the token program ID is the expected one, and if Token-2022 is supported, audit all transfer paths for reentrancy safety.

#### 8.4 Associated Token Account Creation Race

The Associated Token Account (ATA) program creates a deterministic token account for a wallet+mint pair. If two transactions both try to create the same ATA, one fails. Programs that assume ATA creation always succeeds may revert unexpectedly.

**Detection**: if a program creates ATAs as part of its logic, verify it handles the case where the ATA already exists (use `create_idempotent` instead of `create`).

#### 8.5 Token-2022 Permanent Delegate

Token-2022 mints can designate a permanent delegate who can transfer or burn tokens from ANY token account of that mint without the account owner's approval.

**Impact**: if a program holds Token-2022 tokens with a permanent delegate, the delegate can drain the program's token account at any time. Programs must check for the permanent delegate extension and assess trust.

#### 8.6 Token-2022 Transfer Fees

Token-2022 mints can configure automatic transfer fees. The amount received by the destination is less than the amount sent by the source. Programs that assume `amount_sent == amount_received` will have accounting bugs.

**Detection**: if the program interacts with Token-2022, check for the transfer fee extension. Calculate expected received amounts using `spl_token_2022::extension::transfer_fee::TransferFee::calculate_post_fee_amount()`.

### 9. Additional Attack Vectors

#### 9.1 Duplicate Account Passing

An attacker passes the same account at multiple positions in the instruction's account list. If the program assumes accounts are distinct, this can cause double-counting, self-referential transfers, or constraint bypass.

**Example**: an instruction takes `from_account` and `to_account`. If the attacker passes the same token account for both, a "transfer" becomes a no-op but the program's accounting may still credit the destination.

**Detection**: for every pair of accounts in an instruction, determine if same-account would cause incorrect behavior. Add explicit `key != key` checks where needed.

#### 9.2 Missing Return Data Validation

Solana programs can return data via `sol_set_return_data`. If a program makes a CPI and reads return data without verifying the callee's program ID on the return data, an attacker could manipulate the return data (if they control the called program).

**Detection**: search for `sol_get_return_data` and verify the returned program ID is validated.

#### 9.3 Realloc Attacks

Anchor's `realloc` constraint resizes an account's data allocation. If the realloc size comes from user input or is not properly bounded, attackers can:
- Shrink the account to corrupt stored data
- Expand the account to drain the payer's lamports (rent increase)
- Expand beyond the 10 KB realloc limit per instruction (causes runtime error)

**Detection**: search for `realloc` constraints. Is the new size bounded? Is the payer authorized? Can an attacker trigger unbounded reallocation?

## Key Commands

```bash
# Build Anchor project
anchor build

# Run Anchor tests (TypeScript)
anchor test

# Run Anchor tests with specific test
anchor test -- --grep "exploit test name"

# Build native Solana program
cargo build-sbf

# Run native Solana program tests
cargo test-sbf

# Run specific test (native)
cargo test test_exploit_name -- --nocapture

# Generate keypair for test accounts
solana-keygen grind --starts-with ATTK:1

# Start local validator with cloned mainnet accounts
solana-test-validator --clone <PROGRAM_PUBKEY> --url mainnet-beta

# Inspect IDL for Anchor programs
anchor idl fetch <PROGRAM_ID> --provider.cluster mainnet

# Find missing signer checks (native programs)
grep -rn "is_signer" programs/ --include="*.rs" | wc -l

# Find Anchor account constraints
grep -rn "#\[account(" programs/ --include="*.rs"

# Find remaining_accounts usage (bypass vector)
grep -rn "remaining_accounts" programs/ --include="*.rs"

# Find unchecked arithmetic (missing checked_* methods)
grep -rn "\.checked_add\|\.checked_sub\|\.checked_mul\|\.checked_div" programs/ --include="*.rs" | wc -l

# Find CPI calls
grep -rn "invoke\b\|invoke_signed\|CpiContext" programs/ --include="*.rs"

# Find PDA derivation patterns
grep -rn "find_program_address\|create_program_address" programs/ --include="*.rs"

# Find unsafe integer casts
grep -rn "as u64\|as u32\|as u16\|as u8\|as i64\|as i32" programs/ --include="*.rs"

# Find sysvar account usage (potential spoofing)
grep -rn "Clock\|Rent\|EpochSchedule\|SlotHashes" programs/ --include="*.rs"

# Find UncheckedAccount usage (missing validation)
grep -rn "UncheckedAccount\|AccountInfo" programs/ --include="*.rs"

# Check overflow-checks in Cargo.toml
grep -rn "overflow-checks" Cargo.toml programs/**/Cargo.toml

# Find init_if_needed usage (front-running risk)
grep -rn "init_if_needed" programs/ --include="*.rs"

# Find close constraints
grep -rn "close\s*=" programs/ --include="*.rs"

# Find Token-2022 interactions
grep -rn "token_2022\|Token2022\|TokenzQdBNbLqP5VEh" programs/ --include="*.rs"
```

## Validation

Prove every finding with a concrete PoC demonstrating the exploit end-to-end. Solana findings without a working PoC are routinely rejected on Immunefi.

**Anchor test PoC template (TypeScript)**:
```typescript
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { TargetProgram } from "../target/types/target_program";
import { assert } from "chai";

describe("exploit: [finding title]", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.TargetProgram as Program<TargetProgram>;

  it("demonstrates [vulnerability class]", async () => {
    // 1. SETUP: create legitimate state
    // ... initialize accounts, fund vaults, set authorities ...

    // 2. RECORD: snapshot state before attack
    const balanceBefore = await provider.connection.getBalance(victimPubkey);

    // 3. ATTACK: execute the exploit
    // ... craft malicious accounts, build attack transaction ...
    // For account substitution: create fake account with crafted data
    // For PDA manipulation: derive non-canonical PDA
    // For CPI escalation: build CPI with escalated privileges
    // For arithmetic overflow: provide values that trigger wrapping

    // 4. VERIFY: assert the harm occurred
    const balanceAfter = await provider.connection.getBalance(victimPubkey);
    assert.isTrue(
      balanceAfter < balanceBefore,
      `Victim lost ${balanceBefore - balanceAfter} lamports`
    );
    // Assert HARM, not just mechanism:
    // BAD:  assert.ok(tx, "transaction succeeded") -- proves call, not harm
    // GOOD: assert.equal(stolenAmount, expectedLoss, "attacker extracted funds")
  });
});
```

**Native Rust PoC template**:
```rust
#[cfg(test)]
mod exploit_tests {
    use super::*;
    use solana_program_test::*;
    use solana_sdk::{
        signature::{Keypair, Signer},
        transaction::Transaction,
    };

    #[tokio::test]
    async fn test_exploit_account_substitution() {
        let program_id = Pubkey::new_unique();
        let mut context = ProgramTest::new("target_program", program_id, None)
            .start_with_context()
            .await;

        // 1. SETUP: create legitimate accounts and state
        // ...

        // 2. ATTACK: craft malicious account and build exploit transaction
        let fake_account = Keypair::new();
        // ... populate fake_account with crafted data layout ...

        let tx = Transaction::new_signed_with_payer(
            &[/* exploit instruction with substituted accounts */],
            Some(&context.payer.pubkey()),
            &[&context.payer],
            context.last_blockhash,
        );
        context.banks_client.process_transaction(tx).await.unwrap();

        // 3. VERIFY: assert concrete harm
        // ... check balances, state, authority changes ...
    }
}
```

**What to assert in the PoC**:
- Account substitution: attacker passes a fake account and extracts funds or gains unauthorized access
- PDA collision: two different logical entities resolve to the same PDA, causing state corruption
- CPI escalation: an unprivileged caller executes a privileged instruction via CPI chain
- Arithmetic overflow: concrete u64 values that wrap silently, producing incorrect balances or share calculations
- Account revival: close an account, re-fund it in the same transaction, and demonstrate stale state is exploitable
- Sysvar spoofing: pass a crafted account in place of Clock sysvar and demonstrate manipulated time logic
- `remaining_accounts` bypass: pass an unvalidated account through `remaining_accounts` and exploit it
- Token-2022 reentrancy: demonstrate a transfer hook reentering the calling program and corrupting state

**Quantify impact**: exact lamport/token amounts extractable, number of affected users, or protocol TVL at risk. Immunefi requires concrete financial impact for Critical and High severity bounties.
