# Stage 04: Scope And Evidence

Stage ID: `S04_SCOPE_EVIDENCE`

## Objective

Build an auditable evidence map from source code.

Use `./.maia_auditor/checklist.plan.min.json` to prioritize evidence tied to mapped rules.

Read detected platform from `./.maia_auditor/platform.txt`.

## Source code

Read the full source from `./.maia_auditor/packed_source.txt` (already concatenated with file path headers by bootstrap). Do NOT re-read individual files — the packed source is the single source of truth.

## In-scope rules

### Platform: EVM
- Include `*.sol` files under `contracts/`, `src/`, or project root
- Exclude `node_modules/`, `out/`, `cache/`, `artifacts/`, `build/`, `test/`, `tests/`, `script/`, `lib/` (unless lib contains in-scope custom code)
- Track framework: detect OpenZeppelin, Chainlink, Uniswap usage patterns

### Platform: Move-Aptos
- Include `*.move` files under `sources/` paths
- Exclude `build/`, `deps/`, `tests/`, `.aptos/`
- Track framework: detect Aptos framework usage patterns

### Platform: Move-Sui
- Include `*.move` files under `sources/` paths
- Exclude `build/`, `deps/`, `tests/`
- Track framework: detect Sui framework usage patterns

## Evidence extraction checklist

### Platform: EVM
- **Access control**: `onlyOwner`, `onlyRole`, `require(msg.sender`, `AccessControl`, modifiers
- **Visibility**: `external`, `public`, `internal`, `private`
- **State**: storage variables, mappings, arrays, structs, inheritance
- **Proxy patterns**: `delegatecall`, `_implementation`, `upgradeTo`, `initialize`, `__gap`
- **Token handling**: `transfer`, `transferFrom`, `approve`, `safeTransfer`, `balanceOf`
- **Math patterns**: multiplication/division sequences, unchecked blocks, casting
- **Oracle usage**: `latestRoundData`, `AggregatorV3Interface`, TWAP calculations
- **Reentrancy signals**: `nonReentrant`, external calls before state updates, `call{value:}`
- **DeFi patterns**: `swap`, `addLiquidity`, `removeLiquidity`, `flashLoan`, `borrow`, `repay`, `liquidate`
- **Events**: `emit` statements
- **Assembly**: `assembly` blocks, `sstore`, `sload`, `delegatecall`, `staticcall`

### Platform: Move-Aptos
- **Access control**: `signer::address_of`, capability patterns, `assert!` admin checks
- **Visibility**: `public(friend)`, `entry`, `friend` declarations, `#[test_only]`
- **Resources**: `borrow_global`, `borrow_global_mut`, `move_to`, `move_from`, `exists<>`, `acquires`
- **Objects**: `Object<T>`, `object::is_owner`, `ConstructorRef`, `TransferRef`
- **Coins/tokens**: `coin::transfer`, `coin::mint`, `coin::burn`, `FungibleAsset`
- **Events**: `event::emit`, `EventHandle`, `emit_event`
- **Math patterns**: multiplication/division sequences, `as u64`/`as u128` casts
- **Oracle usage**: `pyth::*`, `switchboard::*`, price feed patterns
- **Pool/DeFi**: `swap`, `add_liquidity`, `remove_liquidity`, `flash_loan`
- **Initialization**: `init_module`, `initialize` functions

### Platform: Move-Sui
- **Access control**: `tx_context::sender`, capability objects, witness patterns
- **Visibility**: `public(package)`, `entry` functions
- **Objects**: shared objects, owned objects, dynamic fields, `transfer::public_transfer`
- **Coins/tokens**: `coin::mint`, `TreasuryCap<T>`, `coin::from_balance`
- **Events**: `event::emit`
- **Math patterns**: multiplication/division sequences, `as` casts
- **Initialization**: `init` function, OTW pattern

Also build file-level call relations:
- function callers/callees
- entry function -> internal helper mappings
- state access patterns per function

## Output files

Required: `./.maia_auditor/evidence.map.min.json`

### `evidence.map.min.json` schema

```json
{
  "platform": "evm|move-aptos|move-sui",
  "files": [
    {
      "path": "contracts/Vault.sol",
      "line_count": 0,
      "functions": [
        {
          "name": "deposit",
          "line": 42,
          "callers": [],
          "callees": ["_mint"],
          "touches": ["totalAssets", "balances"]
        }
      ],
      "signals": [
        {"name": "reentrancy_guard", "line": 10, "snippet": "ReentrancyGuard"}
      ]
    }
  ]
}
```

## Runtime progress output

Follow `references/progress_protocol.md` and `references/output_budget.md`.

Emit:
- `stage_start` before file discovery
- `metric` for `files_total`, `files_done`, `functions_indexed`, `call_edges`
- `stage_end` with evidence extraction summary
