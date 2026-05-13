---
name: trident-phase-1-setup
description: "Phase 1 of Trident fuzzing: analyze target program, map account dependency graph, generate modular scaffolding files."
type: reference
---

# Phase 1: Setup & Account Graph

**GOAL:** Generate the scaffolding and a modular, reusable `setup.rs` so that every iteration starts from a valid protocol state — and future campaigns can reuse it.

---

## Step 1.1 — Identify the target

Ask or determine:

- Which program(s) are being fuzzed?
- Which instruction(s) are the fuzzing targets?
- Which CPI targets does the program call?
- What token standard is used? (Token-2022 vs legacy SPL — affects ATA derivation)
- **Is there a dynamic-PDA problem?** Does the target instruction compute a PDA from user input (e.g., borrow amount -> tick -> tick PDA)? If yes, random inputs require random pre-initialized PDAs. Scope down or pre-initialize a range.

## Step 1.2 — Map the account graph

For each target instruction, read its `#[derive(Accounts)]` struct. List every account:

| Account | Type | Seeds / Derivation | Program | Needs init? |
| ------- | ---- | ------------------ | ------- | ----------- |
| signer | Keypair | -- | -- | airdrop only |
| vault_config | PDA | `[b"vault_config", id.to_le_bytes()]` | vaults | yes |
| user_ata | ATA | derived from mint x owner | Token-2022 | yes |

**Walk the dependency chain backwards.** For each account that needs init, find that init instruction's accounts, and recurse. Build a topological ordering.

### Hidden prerequisites checklist

Grep the init instructions for these patterns. Each one burned us at least once:

| Pattern | What to look for | Example fix |
| ------- | ---------------- | ----------- |
| **Supply gate** | `max_ceiling <= N * total_supply` | Mint tokens before setting ceiling |
| **Version gate** | `model.version != 0` | Call `update_rate_data` before `update_config` |
| **Utilization gate** | `reserve.max_utilization != 0` | Call `update_token_config` before `update_user_config` |
| **Program ID vs PDA** | Init takes a program ID, not a state PDA | Pass `program::program_id()` not the PDA |
| **Counter start** | ID counters start at 1, not 0 | Use `1u32` in PDA seeds for first position |
| **Duration bounds** | `expand_duration > 0 && <= 0xffffff` | Use 172800 (2 days), not 0 |
| **Casting limits** | Field stored as u64 but API accepts u128 | Use `u64::MAX as u128`, not `u128::MAX` |
| **Source type arity** | Oracle source types require N accounts | `Pyth` needs 1 source, `JupLend` needs 4 |
| **AccountLoader vs UncheckedAccount** | Account type requires initialization even if unused | Initialize tick accounts even for deposit-only |
| **Optional but required** | `Option<UncheckedAccount>` must still be passed | Derive the PDA address, pass uninitialized |

## Step 1.3 — Read `types.rs`

After `trident init`, `types.rs` is auto-generated (can be 500KB+). **Read it before writing any code.** You need:

1. **Module names** — one per program. Import path: `crate::types::module_name::*`
2. **`::new()` constructor parameter order** — the #1 source of compile errors. The parameter order in `::new()` matches the account order in the `#[derive(Accounts)]` struct, which may NOT match the order you'd expect.
3. **Data struct fields** — what arguments the instruction takes and their types.
4. **State struct layouts** — for `get_account_with_type` in invariant checks.

**Tip:** Search `types.rs` for `pub fn new` to find all constructors quickly.

## Step 1.4 — Generate modular files

### `common/constants.rs`

```rust
use trident_fuzz::fuzzing::*;

pub const VAULT_ID: u16 = 1;
pub const MIN_TICK: i32 = -16383;
pub const POSITION_ID: u32 = 1; // starts at 1, not 0

pub const TOKEN_2022: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
pub const SPL_TOKEN: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
```

### `common/setup.rs`

Break setup into **composable functions** that each handle one logical step:

```rust
use trident_fuzz::fuzzing::*;
use super::constants::*;

/// Create Token-2022 mints for supply and borrow tokens.
/// Returns (supply_mint, borrow_mint).
pub fn create_mints(
    trident: &mut Trident,
    authority: &Pubkey,
    supply_storage: &mut AddressStorage,
    borrow_storage: &mut AddressStorage,
) -> (Pubkey, Pubkey) {
    let supply = supply_storage.insert(trident, None);
    let borrow = borrow_storage.insert(trident, None);

    let ixs = trident.initialize_mint_2022(authority, &supply, 6, authority, None, &[]);
    let res = trident.process_transaction(&ixs, Some("init supply mint"));
    assert!(res.is_success(), "init supply mint failed\n{}", res.logs());

    let ixs = trident.initialize_mint_2022(authority, &borrow, 6, authority, None, &[]);
    let res = trident.process_transaction(&ixs, Some("init borrow mint"));
    assert!(res.is_success(), "init borrow mint failed\n{}", res.logs());

    (supply, borrow)
}

/// Initialize oracle admin + oracle config with a dummy Pyth source.
pub fn init_oracle(
    trident: &mut Trident,
    authority: &Pubkey,
    oracle_admin_storage: &mut AddressStorage,
    oracle_storage: &mut AddressStorage,
    oracle_source_storage: &mut AddressStorage,
) -> (Pubkey, Pubkey) {
    // ... each step asserts success with logs ...
}

/// Initialize liquidity layer + token reserves + rate models.
pub fn init_liquidity_layer(/* ... */) { /* ... */ }

/// Initialize vault admin + config + state + branch + tick.
pub fn init_vault(/* ... */) { /* ... */ }

/// Create user position with NFT mint.
pub fn init_position(/* ... */) { /* ... */ }

/// Fund user with supply tokens (create ATA + mint).
pub fn fund_user(/* ... */) { /* ... */ }
```

### `common/instructions.rs`

Instruction builders return the result, let the caller decide how to handle it:

```rust
use trident_fuzz::fuzzing::*;

/// Build and execute a vault operate() instruction.
/// Returns the transaction result (caller decides success/failure handling).
pub fn do_operate(
    trident: &mut Trident,
    accounts: &AccountAddresses,
    col_delta: i128,
    debt_delta: i128,
) -> TransactionResult {
    let signer = accounts.signer.get(trident).expect("signer not set");
    // ... get all accounts, build instruction ...
    trident.process_transaction(&[ix], Some("operate"))
}
```

### `common/invariants.rs`

Each invariant is a standalone function that reads state and asserts:

```rust
use trident_fuzz::fuzzing::*;

/// E2: vault_state.total_borrow == tick.raw_debt
pub fn check_debt_ledger(trident: &Trident, vault_state_pk: &Pubkey, tick_pk: &Pubkey) {
    let vs = trident.get_account_with_type::<VaultState>(vault_state_pk, 8).expect("missing");
    let tick = trident.get_account_with_type::<Tick>(tick_pk, 8).expect("missing");
    assert_eq!(vs.total_borrow, tick.raw_debt,
        "E2: total_borrow ({}) != raw_debt ({})", vs.total_borrow, tick.raw_debt);
}

/// C1: tick_has_debt bitmap bit SET iff raw_debt > 0
pub fn check_bitmap_sync(trident: &Trident, thd_pk: &Pubkey, tick_pk: &Pubkey) { /* ... */ }

/// T1: supply_TR.with_interest >= lending_position.amount
pub fn check_cross_protocol_supply(/* ... */) { /* ... */ }
```

### `fuzz_0/test_fuzz.rs` — now small and clean

```rust
use trident_fuzz::fuzzing::*;
mod fuzz_accounts;
mod types;
use fuzz_accounts::*;

// Reuse common modules
#[path = "../common/mod.rs"]
mod common;
use common::{constants::*, setup, instructions, invariants};

#[derive(FuzzTestMethods)]
struct FuzzTest {
    trident: Trident,
    fuzz_accounts: AccountAddresses,
    deposit_ok: u32,
    withdraw_ok: u32,
}

#[flow_executor]
impl FuzzTest {
    fn new() -> Self { /* ... */ }

    #[init]
    fn start(&mut self) {
        self.deposit_ok = 0;
        self.withdraw_ok = 0;

        let authority = self.fuzz_accounts.authority.insert(&mut self.trident, None);
        self.trident.airdrop(&authority, 100 * LAMPORTS_PER_SOL);

        // Each setup function is one logical step
        let (supply, borrow) = setup::create_mints(&mut self.trident, &authority, /* ... */);
        setup::init_oracle(&mut self.trident, &authority, /* ... */);
        setup::init_liquidity_layer(&mut self.trident, &authority, /* ... */);
        setup::init_vault(&mut self.trident, &authority, /* ... */);
        setup::init_position(&mut self.trident, &authority, /* ... */);
        setup::fund_user(&mut self.trident, &authority, /* ... */);
    }

    #[flow]
    fn flow_deposit(&mut self) {
        let amount = self.trident.random_from_range(1..1_000_000_u64) as i128;
        let res = instructions::do_operate(&mut self.trident, &self.fuzz_accounts, amount, 0);
        if res.is_success() { self.deposit_ok += 1; }
    }

    #[flow]
    fn flow_withdraw(&mut self) {
        let amount = self.trident.random_from_range(1..1_000_000_u64) as i128;
        let res = instructions::do_operate(&mut self.trident, &self.fuzz_accounts, -amount, 0);
        if res.is_success() { self.withdraw_ok += 1; }
    }

    #[end]
    fn end(&mut self) {
        assert!(self.deposit_ok + self.withdraw_ok > 0, "nothing succeeded");
        invariants::check_debt_ledger(&self.trident, /* ... */);
        invariants::check_bitmap_sync(&self.trident, /* ... */);
    }
}

fn main() { FuzzTest::fuzz(1000, 100); }
```

## Step 1.5 — Present the PDA seed table

Document every PDA in the campaign. Seed mismatches are silent killers — the init succeeds but the instruction that reads the PDA gets a different address and reverts.

```text
Account                  Seeds                                              Program
oracle_admin             [b"oracle_admin"]                                  oracle
oracle                   [b"oracle", vault_id: u16 LE]                     oracle
vault_admin              [b"vault_admin"]                                  vaults
vault_config             [b"vault_config", vault_id: u16 LE]               vaults
position                 [b"position", vault_id: u16 LE, pos_id: u32 LE]   vaults  <-- pos_id=1 not 0
position_mint            [b"position_mint", vault_id: u16 LE, pos_id: u32] vaults
position_token_account   ATA(position_mint, signer)                        SPL_TOKEN (legacy!)
metadata_account         [b"metadata", METAPLEX_ID, position_mint]         metaplex
```

## Step 1.6 — Present setup dependency table

| Step | Function | Purpose | Depends on | Gotcha |
| ---- | -------- | ------- | ---------- | ------ |
| 1 | `airdrop` | Fund accounts | -- | 100 SOL minimum |
| 2 | `create_mints` | Supply + borrow mints | 1 | Token-2022 |
| 2b | `mint_to_2022` | Pre-mint borrow tokens | 2 | `max_ceiling <= 10 * total_supply` |
| 3 | `init_oracle` | Oracle admin + config | 1 | Use Pyth (1 acct) not JupLend (4) |
| 4 | `init_liquidity_layer` | Reserves + rate models | 2, 3 | rate_data before token_config |
| 5 | `init_vault` | Admin + config + state | 3, 4 | program ID not PDA for admin |
| 6 | `init_position` | Position + NFT | 5 | pos_id=1, legacy SPL for NFT |
| 7 | `fund_user` | Supply ATA + tokens | 2, 6 | Token-2022 for ATA |

**STOP. Wait for user approval before Phase 2.**
