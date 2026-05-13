---
name: trident-api-v0.12
description: "Trident v0.12.0 API quick reference. Version-dependent — replace this file when Trident updates. Phase files (1-5) are version-independent."
type: reference
---

# Trident API — v0.12.0

Replace this file when Trident releases a new version. The 5 phase files describe the workflow and are version-independent.

## Test Structure

```rust
use trident_fuzz::fuzzing::*;

#[derive(FuzzTestMethods)]
struct FuzzTest {
    trident: Trident,
    fuzz_accounts: AccountAddresses,
}

#[flow_executor]
impl FuzzTest {
    fn new() -> Self { /* ... */ }
    #[init]  fn start(&mut self) { /* once per iteration start */ }
    #[flow]  fn my_flow(&mut self) { /* randomly selected */ }
    #[end]   fn end(&mut self) { /* once per iteration end */ }
}

fn main() { FuzzTest::fuzz(iterations, max_flows); }
```

## Accounts

```rust
// Keypair
let key = storage.insert(&mut self.trident, None);

// PDA
let pda = storage.insert(&mut self.trident,
    Some(PdaSeeds::new(&[b"seed", &id.to_le_bytes()], program::program_id())));

// Retrieve existing
let key = storage.get(&mut self.trident).expect("not set");

// Store derived address (ATA, find_program_address result)
storage.insert_with_address(pubkey);
```

## Transactions

```rust
// Build: Type::data(Data::new(...)).accounts(Accounts::new(...)).instruction()
let ix = MyIx::data(MyIxData::new(arg1, arg2))
    .accounts(MyIxAccounts::new(acct1, acct2))
    .remaining_accounts(vec![AccountMeta::new(writable, false)])  // optional
    .instruction();

let res = self.trident.process_transaction(&[ix], Some("label"));
res.is_success();   // bool
res.logs();         // String
```

## State Reading

```rust
// Anchor accounts (8-byte discriminator offset)
let state = self.trident.get_account_with_type::<MyStruct>(&pk, 8);

// Token queries
self.trident.get_mint(pk);           // Option<MintData { mint, extensions }>
self.trident.get_token_account(pk);  // Option<TokenAccountData { account, extensions }>
self.trident.get_associated_token_address(&mint, &owner, &token_program);  // Pubkey
```

## Utilities

```rust
self.trident.airdrop(&acct, 100 * LAMPORTS_PER_SOL);
self.trident.random_from_range(1..1_000_000_u64);
self.trident.random_from_range(0..=u8::MAX);  // inclusive
self.trident.random_string(10);
self.trident.forward_in_time(seconds);
```

## Token Helpers (requires `features = ["token"]`)

```rust
// Token-2022 — return Vec<Instruction>
initialize_mint_2022(payer, mint, decimals, authority, freeze_auth, &[MintExtension])
initialize_token_account_2022(payer, account, mint, owner, &[AccountExtension])
initialize_associated_token_account_2022(payer, mint, owner, &[AccountExtension])

// Token-2022 — return single Instruction
mint_to_2022(token_account, mint, authority, amount)
transfer_checked(source, dest, mint, authority, &[signers], amount, decimals)

// Legacy SPL — return Vec<Instruction>
initialize_mint(payer, mint, decimals, authority, freeze_auth)
initialize_token_account(payer, account, mint, owner)

// Legacy SPL — return single Instruction
initialize_associated_token_account(payer, mint, owner)
```

## Well-Known Pubkeys

```rust
pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")  // Token-2022
pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")  // SPL Token
pubkey!("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s")  // Metaplex
pubkey!("11111111111111111111111111111111")                // System
```

## CLI Commands

```bash
cargo install trident-cli          # install
trident init                       # scaffold (from project root)
anchor build                       # build .so binaries first
cd trident-tests && cargo run --bin fuzz_0          # run
cd trident-tests && cargo run --bin fuzz_0 --release  # faster

# Debug mode (single-threaded, panics visible)
cargo build --bin fuzz_0
TRIDENT_FUZZ_DEBUG=0000000000000000 ./target/debug/fuzz_0 2>&1 | head -200
```
