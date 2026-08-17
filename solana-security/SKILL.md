---
name: solana-security
category: web3
description: Solana program security covering account validation (signer/owner/key/writable), PDA bump canonicalization, type confusion via missing discriminators, CPI privilege escalation, account closing and revival attacks, Anchor framework constraints, remaining_accounts bypass, arithmetic overflow in release mode, and sysvar spoofing
depends_on: []
---

# Solana Program Security

Security testing for Solana programs (native Rust and Anchor framework). Focus on account validation, PDA security, type confusion, CPI privilege escalation, account closing/revival, arithmetic overflow in release mode, Anchor constraint gaps, and sysvar spoofing.

## When to Use

- Target is a Solana program (native Rust or Anchor framework)
- Bug bounty on Immunefi with Solana programs in scope
- Auditing Anchor programs for missing constraints
- Reviewing CPI (Cross-Program Invocation) security

## Methodology

### 1. Account Validation (CRITICAL -- Most Common Solana Bug Class)

Every account passed to every instruction must be validated. Missing checks are the #1 Solana bug class. Unlike EVM where `msg.sender` is implicit, Solana passes all accounts explicitly -- each one is an attack surface.

- **Missing signer check**: program doesn't verify `account.is_signer` -- anyone can impersonate authority
  - Anchor: missing `Signer<'info>` type or `#[account(signer)]` constraint
  - Native: missing `if !account.is_signer { return Err(...) }`
  - Impact: attacker calls privileged instructions (withdraw, config change) as if they were the authority
  - Common in: admin functions, multisig approvals, vault withdrawals
- **Missing owner check**: program doesn't verify account is owned by expected program
  - Anchor: missing `#[account(owner = expected_program)]` or wrong Account type (e.g., `AccountInfo` instead of `Account<'info, MyType>`)
  - Native: missing `if account.owner != &expected_program_id { return Err(...) }`
  - Impact: attacker creates fake account with crafted data layout, passes all deserialization but contains malicious values (e.g., inflated balance field)
- **Missing key check**: program doesn't verify account pubkey matches expected address
  - Anchor: missing `#[account(address = expected_key)]` or `has_one`
  - Impact: attacker substitutes a different but structurally valid account (e.g., a different user's vault, a different pool's config)
  - Especially dangerous when account stores authority pubkeys or fee recipients
- **Missing writable check**: program writes to account not marked writable in transaction
  - Anchor: missing `#[account(mut)]`
  - Native: missing `if !account.is_writable { return Err(...) }`
- **Missing rent-exempt check**: account balance below rent exemption threshold -- runtime can garbage-collect it
  - Check after any lamport transfer that the source account remains rent-exempt
  - Minimum rent: `Rent::get()?.minimum_balance(account_data_len)`
- **Detection**: for every account in every instruction, build a validation matrix:
  - Does this account need signer authority? Is it checked?
  - Who should own this account? Is ownership verified?
  - Should this be a specific known address? Is the key compared?
  - Does the instruction write to it? Is it marked mutable?
  - Will lamports change? Is rent exemption maintained?

### 2. PDA Security

- **Non-canonical bump**: using a bump != the canonical bump allows multiple valid PDAs for the same seeds
  - `find_program_address` returns the canonical (highest) bump; `create_program_address` accepts any bump
  - Attack: attacker finds an alternative bump producing a different PDA address, bypassing uniqueness assumptions
  - Detection: search for `create_program_address` usage -- canonical derivation uses `find_program_address`
  - Anchor: `#[account(seeds = [...], bump)]` stores canonical bump automatically; `bump = custom_bump` is suspicious
- **Missing seeds**: PDA derived with insufficient seeds allows collision across users or entities
  - Example: PDA seeded only with `[b"vault"]` -- all users share one vault PDA
  - Correct: `[b"vault", user_pubkey.as_ref()]` -- unique per user
- **Seed injection**: user-controlled seed data allows crafting a PDA that collides with a legitimate account
  - Detection: are any PDA seeds derived from user input without length prefixing or type-safe serialization?
  - Attack: variable-length seed without delimiter lets attacker concatenate seeds to match another PDA
- **PDA as signer**: PDAs can sign CPIs via `invoke_signed` -- verify the seeds and bump match the intended PDA exactly
  - If seeds include user-controllable data, attacker may derive a valid PDA signer for a different account
- **PDA account reuse across programs**: two programs using the same seed pattern can produce the same PDA address
  - If both programs expect to own the account, the first creator wins -- second program's init fails or reads wrong data
  - Detection: check if seed patterns include the program ID or a unique namespace prefix

### 3. Type Confusion / Missing Discriminator

- **Account type confusion**: program deserializes account data without verifying the account type tag
  - Native: must manually embed and check a discriminator byte/field before deserialization
  - Attack: pass a TokenAccount where a UserAccount is expected -- fields map to different semantics
  - Detection (native): search for `try_from_slice`, `deserialize`, `unpack` without preceding discriminator check
  - Detection (Anchor): look for `UncheckedAccount` or raw `AccountInfo` used where a typed `Account<'info, T>` should be
- **Anchor discriminator**: Anchor auto-adds an 8-byte discriminator (SHA256 of `account:{TypeName}`). Native programs lack this.
  - Anchor-to-native interop: if a native program reads Anchor accounts, it must validate the 8-byte prefix
- **Zero-copy deserialization**: `#[account(zero_copy)]` accounts may not enforce discriminator by default in older Anchor versions
  - Must manually verify discriminator field exists and is checked on access
- **Cross-program type confusion**: passing accounts created by program A into program B where data layout assumptions differ
  - Detection: does the receiving program verify `account.owner` before deserializing?
- **Data length validation**: native programs should check `account.data_len()` matches expected struct size before deserializing
  - Undersized data causes slice panic; oversized data may hide appended malicious payloads
  - Anchor handles this automatically for typed accounts but NOT for `UncheckedAccount`

### 4. CPI Privilege Escalation

- **Signer privilege propagation**: when program A CPIs into program B, all of A's signers propagate to B
  - If A does not restrict which accounts carry signer privilege, attacker can escalate through the CPI chain
  - Detection: review every `invoke`/`invoke_signed` -- which AccountInfo entries have `is_signer = true`?
- **Arbitrary CPI target**: if the target program ID for a CPI comes from an unvalidated account, attacker can redirect the CPI
  - Detection: is the CPI target program ID hardcoded or loaded from a validated, owner-checked account?
  - Safe pattern: `token_program.key() == spl_token::id()` or Anchor's `Program<'info, Token>`
- **PDA signer escalation**: program signs CPI with PDA seeds -- if seeds are predictable and attacker-influenceable, they can craft a matching PDA
  - Verify seeds contain program-controlled data (not purely user-supplied)
- **Token program verification**: verify CPI targets the real Token Program or Token-2022 Program, not a fake
  - Anchor: `#[account(address = token::ID)]` or `Program<'info, Token>`
  - Native: explicit `if *token_program.key != spl_token::id() { return Err(...) }`
- **CPI depth limit**: Solana enforces a max CPI depth of 4. Deeply nested CPI chains may hit this limit unexpectedly.
  - Detection: trace CPI call chains -- does any path exceed 4 levels?
  - Impact: unexpected instruction failure under specific call paths (DoS vector)

### 5. Account Closing and Revival

- **Incomplete closing**: account lamports zeroed but data not zeroed out
  - Attack: within the same transaction, another instruction re-funds the account to revive it with stale data
  - Required close sequence: zero all data bytes, transfer ALL lamports to destination, assign owner to system program
  - Anchor: `#[account(close = destination)]` handles data zeroing + lamport transfer + owner reassignment correctly
- **Revival attack**: account closed in instruction N, re-funded in instruction N+1 of the same transaction
  - The runtime does not garbage-collect mid-transaction -- a zeroed account can be resurrected
  - Detection: does the program check an `is_initialized` flag or discriminator before operating on an account?
- **Rent exemption exploit**: transfer lamports out of an account to drop below rent exemption threshold
  - Account becomes eligible for garbage collection at end of epoch -- permanent data loss
  - Detection: after any lamport-modifying operation, verify the account remains rent-exempt
- **Cross-instruction state assumption**: instruction A closes account, instruction B (same tx) assumes it still exists
  - Detection: search for multi-instruction flows where account lifecycle is not atomic
  - Impact: instruction B reads zeroed data or fails silently depending on program logic

### 6. Arithmetic Overflow (Solana-Specific)

- **Release mode wrapping**: Rust compiled with `cargo build-sbf` (release profile) does NOT panic on integer overflow -- it wraps silently
  - This is the opposite of debug mode behavior, where overflow panics
  - Impact: all unchecked arithmetic in deployed Solana programs silently wraps around (e.g., `u64::MAX + 1 == 0`)
  - Detection: search for arithmetic operations (`+`, `-`, `*`, `/`, `%`) without `checked_add`/`checked_sub`/`checked_mul`/`checked_div`
  - Safe patterns: `a.checked_add(b).ok_or(ErrorCode::Overflow)?` or Anchor's `require!` with overflow validation
- **Anchor overflow protection**: Anchor's `overflow-checks` feature flag enables overflow panics in release mode
  - Verify `Cargo.toml` contains `overflow-checks = true` under `[profile.release]` or the Anchor feature flag is active
  - `#[cfg(not(feature = "no-overflow-checks"))]` -- ensure this feature is NOT enabled in production builds
- **Casting truncation**: `u128` to `u64` via `as u64` silently truncates high bits in release mode
  - Detection: search for `as u64`, `as u32`, `as u16`, `as u8` -- each is a potential silent truncation
  - Safe pattern: `u64::try_from(value).map_err(|_| ErrorCode::Overflow)?`
- **Division by zero**: Rust panics on integer division by zero even in release mode, causing transaction revert
  - Attacker can trigger DoS by setting up state where a divisor becomes zero
  - Detection: for every division operation, trace the divisor -- can an attacker influence it to be zero?
- **Precision loss in token math**: fixed-point arithmetic using u64 with implicit decimals loses precision on division
  - Example: `amount * rate / RATE_DENOMINATOR` vs `amount / RATE_DENOMINATOR * rate` -- ordering matters
  - Impact: rounding errors accumulate over many operations, creating extractable value

### 7. Anchor-Specific Issues

- **Missing constraints**: every Anchor account should carry appropriate constraints
  - `has_one = authority` -- verifies a stored pubkey matches the provided account
  - `constraint = expr` -- arbitrary boolean expression that must hold
  - `seeds = [...]` + `bump` -- PDA derivation and canonical bump verification
  - `address = expected_key` -- exact pubkey match
  - `owner = program_id` -- account owner check
- **`remaining_accounts` bypass**: `ctx.remaining_accounts` is NOT validated by Anchor's derive macros
  - Any accounts passed via remaining_accounts are raw `AccountInfo` with zero automatic checks
  - Attacker can pass arbitrary accounts through this vector
  - Detection: grep for `remaining_accounts` -- is each account validated (owner, key, signer, data) before use?
- **`init` without `payer`/`space`**: `#[account(init, payer = user, space = 8 + N)]` -- missing payer or space causes compile error, but wrong space causes truncation or wasted lamports
- **`mut` on read-only accounts**: marking accounts mutable when the instruction only reads them increases attack surface
  - Mutable accounts can be written to by the runtime after the instruction completes
- **Account reallocation**: `#[account(realloc = new_size, realloc::payer = user, realloc::zero = false)]`
  - If authorization is missing, attacker can resize accounts, corrupting data or inflating lamport requirements
- **`init_if_needed` hazard**: `#[account(init_if_needed, ...)]` creates the account if it does not exist
  - Race condition: attacker front-runs to initialize with malicious parameters before the legitimate user
  - Detection: search for `init_if_needed` -- verify the initialized state is validated, not just existence
  - Anchor requires `#[cfg(feature = "init-if-needed")]` to be explicitly enabled -- if present, audit every use
- **Event emission without CPI guard**: Anchor events (`emit!`) are logged to the transaction log -- they cannot be spoofed
  - But if events are emitted inside CPI contexts, the emitting program's pubkey in the log may confuse indexers
  - Detection: verify off-chain indexers validate the program ID on each event log entry

### 8. Sysvar Spoofing

- **Passing sysvar as AccountInfo**: if the program reads sysvars by deserializing from a passed AccountInfo
  - Attack: pass a crafted account with fake sysvar data instead of the real sysvar account
  - Impact: manipulate clock timestamps, rent parameters, epoch schedule for exploit advantage
  - Detection: search for sysvar accounts (`Clock`, `Rent`, `EpochSchedule`, `SlotHashes`) passed as `AccountInfo` or `UncheckedAccount`
  - Safe pattern: `Clock::get()?` or `Rent::get()?` (syscall-based, cannot be spoofed)
  - If account-based access is required: use `Sysvar::from_account_info()` which validates the account address matches the known sysvar address
- **Deprecated sysvar accounts**: some sysvars (RecentBlockhashes, Fees) are deprecated but still deserializable
  - Programs relying on deprecated sysvars may break when the runtime removes them
  - Detection: search for deprecated sysvar IDs in account validation logic

### 9. Token Program Security

- **Token-2022 extensions**: transfer hooks, confidential transfers, permanent delegate, non-transferable, transfer fees
  - Transfer hooks execute arbitrary code during token transfers -- reentrancy and DoS vector
  - Permanent delegate can transfer/burn tokens without owner approval -- check if program accounts for this
  - Transfer fee extension silently deducts fees -- amount received != amount sent
  - Detection: does the program handle both Token Program (`TokenkegQEcnVrCgLJ...`) and Token-2022 (`TokenzQdBNbLqP5VEh...`)?
- **Mint authority validation**: verify the mint authority is correctly set and authority transitions are authorized
  - Attack: if program doesn't verify mint authority, attacker can pass a mint they control
- **Freeze authority**: tokens can be frozen by freeze authority, blocking all transfers
  - Impact: DoS on any logic that requires token transfers to succeed
- **Close authority**: token accounts can be closed by the close authority
  - Impact: attacker closes a program-owned token account, destroying held tokens
- **Associated Token Account assumption**: program assumes an ATA exists without verifying
  - If the ATA does not exist, the transfer CPI fails -- DoS if creation is not handled
  - Detection: does the program create the ATA if missing, or does it fail open?
- **Decimal mismatch**: program assumes token has 9 decimals (SOL default) but token uses 6 (USDC) or other
  - Impact: amounts calculated with wrong decimal places -- 1000x over/underpayment
  - Detection: does the program read `mint.decimals` or hardcode a decimal assumption?

### 10. Compute Budget and DoS

- **Compute unit exhaustion**: Solana instructions have a compute unit limit (default 200k, max 1.4M per transaction)
  - Unbounded loops over user-controlled data can exceed compute limits, causing permanent DoS
  - Detection: search for loops where iteration count depends on account data length or user input
  - Impact: if a critical function (e.g., liquidation, withdrawal) can be made to exceed compute limits, funds are locked
- **Stack depth**: Solana BPF has a 64-frame stack limit -- deeply recursive functions hit this
  - Detection: search for recursive function calls or deep call chains
- **Log truncation**: `msg!` and `sol_log` have a per-instruction log limit -- excessive logging can hide important events
  - Impact: off-chain monitoring misses events if logs are truncated

## Key Detection Commands

```bash
# Find missing signer checks (native programs)
grep -rn "is_signer" programs/ --include="*.rs" | wc -l

# Find Anchor account constraints
grep -rn "#\[account(" programs/ --include="*.rs"

# Find remaining_accounts usage (potential bypass vector)
grep -rn "remaining_accounts" programs/ --include="*.rs"

# Find unchecked arithmetic (missing checked_* methods)
grep -rn "checked_add\|checked_sub\|checked_mul\|checked_div" programs/ --include="*.rs" | wc -l

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
grep -rn "overflow-checks" programs/ --include="Cargo.toml"
```

## Validation

- Demonstrate account substitution: craft a fake account with valid structure but malicious data that passes deserialization
- Show PDA collision: derive two different PDAs with different bumps or seeds where only one should exist
- Prove CPI escalation: CPI call with unexpected signer privilege reaching a privileged instruction
- Show arithmetic overflow: concrete u64 values that wrap silently in release mode producing incorrect results
- Demonstrate account revival: close an account then re-fund it in the same transaction to resurrect stale state
- Prove sysvar spoofing: pass a crafted account in place of Clock sysvar with a manipulated timestamp
- Fork test on devnet/mainnet with real program state using `solana-test-validator --clone`
- For Anchor: write exploit test in TypeScript (`anchor test`) or Rust showing the full attack sequence
