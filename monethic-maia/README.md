# Monethic AI Auditor (MAIA)

Smart contract security audit engine. 192 detectors across EVM, Move-Aptos, and Move-Sui.

Created by [Monethic](https://monethic.io) | Coded by [0xluk3](https://x.com/0xluk3)

## Usage

### 1. Install

**Claude Code:**
```bash
git clone https://github.com/Monethic/monethic-maia.git C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\monethic-maia
```


### 2. Run

Run the skill:
```
/monethic_maia
```

**Codex:** invoke the skill:
```
$monethic-maia
```

### 3. Point at code

```
Point me to the code to audit, or press ENTER to use the current directory:
> /path/to/project
> ./src --exclude tests/ mocks/
```

### 4. Pick mode

MAIA auto-detects the platform and recommends detectors. Press ENTER to go, or:

```
go           run recommended detectors (default)
ALL          run all detectors for detected platform
NUCLEAR      run all detectors across all platforms
ACC LEND     pick specific categories
force:evm    override detected platform
```

### 5. Get report

Reports are saved to `report_maia_{timestamp}/`:

```
report_maia_20260317_143022/
  evm_audit.html          ← open in browser
  evm_audit.md            markdown version
  evm_audit_full.html     full report (includes false positives + downgrades)
  evm_audit_full.md       full markdown
```

MAIA outputs a clickable `file:///` link — paste it in your browser.

The `prompts/` directory also works standalone with any LLM that supports long context and file access.

---

## Supported Platforms

| Platform | Detectors | Categories | Language |
|----------|-----------|------------|----------|
| EVM | 95 | 20 | Solidity |
| Move-Aptos | 49 | 11 | Move |
| Move-Sui | 48 | 11 | Move |


## EVM Detector Coverage (20 categories, 95 detectors)

| ID | Category | # | Scope |
|----|----------|---|-------|
| ACC | Access Control | 7 | Auth, roles, modifiers, centralization, signatures |
| ASM | Assembly | 2 | Inline assembly, memory management |
| CRYPTO | Cryptography | 2 | Randomness, signatures, proofs |
| DEX | DEX/AMM | 4 | AMM formulas, fees, pool management, slippage |
| ERC20 | ERC-20 Token | 2 | Token compatibility, transfer integrity |
| GAS | Gas Optimization | 6 | Constants, loops, storage, redundancy |
| GEN | General Safety | 12 | Auth, DoS, ETH, events, reentrancy, state |
| GOV | Governance | 4 | Timelocks, proposals, quorum, voting |
| INTEG | Integration | 3 | Aave, Uniswap V3/V4 |
| LEND | Lending | 7 | Borrow/repay, collateral, health, interest, liquidation |
| MATH | Mathematics | 5 | Casting, division, overflow, rounding, scaling |
| NFT | NFT | 3 | Metadata, marketplace, ERC-721 |
| ORACLE | Oracle | 6 | Staleness, manipulation, fallback, TWAP |
| PRED | Prediction Market | 2 | Market creation, settlement |
| PROXY | Proxy & Upgrades | 9 | Diamond, delegatecall, init, storage, upgrades |
| STABLE | Stablecoin | 2 | Mechanism, peg assumptions |
| STAKE | Staking | 7 | Epochs, rewards, slashing, gaming, unstaking |
| VAULT | Vault | 6 | Accounting, share price, ERC-4626, ERC-7540, yield |
| VESTING | Vesting | 1 | Schedule integrity |
| XCHAIN | Cross-Chain | 5 | Accounting, finality, message auth, replay |

## Move Detector Coverage (11 categories)

| ID | Category | Aptos | Sui | Scope |
|----|----------|-------|-----|-------|
| ACC | Access Control | 6 | 6 | Auth, roles, visibility, centralization |
| COIN | Coin/Token | 2 | 2 | Token handling, decimal precision |
| CRYPTO | Cryptography | 1 | 1 | Signatures, proofs, replay |
| GAS | Gas & Performance | 4 | 4 | Loops, storage bloat, hash collision |
| GEN | General Logic | 9 | 9 | Init, state, events, timestamps, types |
| LEND | Lending | 3 | 3 | Liquidation, pause/recovery |
| MATH | Arithmetic | 5 | 5 | Overflow, casting, precision, scaling |
| OBJ | Object Model | 4 | 3 | Abilities, hot potato, witness |
| ORACLE | Oracle | 5 | 5 | Freshness, aggregation, price validation |
| POOL | Pool/DEX/Staking | 8 | 8 | AMM, flash loans, LP, rewards |
| VAULT | Vault | 2 | 2 | Share accounting, state sync |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Disclaimer

This tool helps catch common vulnerability patterns but may miss subtle or novel issues. **Not a substitute for a professional security audit.**

For professional smart contract audits, contact [Monethic](https://monethic.io/contact).

## License

[AGPL-3.0](LICENSE)
