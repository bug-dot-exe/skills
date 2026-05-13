# MAIA Detector Format Specification

This document defines the standard format for MAIA detectors (also called "skills" or "checklist items"). Follow this specification when creating new detectors to ensure consistency across the knowledge base.

---

## File Placement

Detectors are organized by category in platform-specific directories:

```
{platform_dir}/knowledge/checklists/categories/CAT-{CATEGORY}.md
```

Where `{platform_dir}` is:
- `evm` for EVM/Solidity detectors
- `move-aptos` for Aptos Move detectors
- `move-sui` for Sui Move detectors

Each category file (`CAT-*.md`) contains one or more detectors. A detector is a single checklist item within a category.

When adding a new detector, also register it in:
- `{platform_dir}/knowledge/checklists/index.md` — category index with item counts and one-liner per detector
- `{platform_dir}/knowledge/rulepack.md` — compact rule entry with trigger idea and counter-evidence

---

## Detector Structure

Each detector within a `CAT-*.md` file follows this exact structure:

```markdown
## CL-{CAT}-{NN}: {Title}

**Rule:** `{PLATFORM}-{CAT}-{ABBR}-{NN}`
**Severity:** {Severity}

### Description
{One paragraph explaining the invariant or property this detector checks. Should state what MUST hold true, not what the bug is.}

### Patterns

#### Pattern N: {Pattern Title}
{One sentence explaining the specific anti-pattern or vulnerable code shape.}

**Vulnerable:**
```{language}
// Comment explaining why this is vulnerable
{vulnerable code example}
```

**Fixed:**
```{language}
// Comment explaining the fix
{corrected code example}
```

{Repeat Pattern blocks as needed — each detector should have 1-12 patterns.}

### Detect
{A numbered detection procedure. Each step is a concrete check the auditor applies to source code. Written as imperatives: "verify X", "check Y", "confirm Z".}

### Remediation
{Concise remediation guidance — what to implement or change to eliminate the vulnerability class.}
```

---

## Field Reference

### Identifiers

| Field | Format | Example | Description |
|-------|--------|---------|-------------|
| Checklist ID | `CL-{CAT}-{NN}` | `CL-ACC-01` | Unique within category. `NN` is zero-padded sequential. |
| Rule ID (EVM) | `EVM-{CAT}-{ABBR}-{NN}` | `EVM-ACC-AUTH-01` | Global unique. `ABBR` is a short mnemonic for the sub-topic. |
| Rule ID (Move) | `MOVE-{CAT}-{ABBR}-{NN}` | `MOVE-ACC-AUTH-01` | Global unique. Same format, different platform prefix. |

### Platform Variants

| Platform | Rule prefix | Code language | File extension | Example detector |
|----------|-------------|---------------|----------------|------------------|
| EVM | `EVM-` | `solidity` | `.sol` | `EVM-ACC-AUTH-01` |
| Move-Aptos | `MOVE-` | `move` | `.move` | `MOVE-ACC-AUTH-01` |
| Move-Sui | `MOVE-` | `move` | `.move` | `MOVE-ACC-AUTH-01` |

### Severity Scale

Use one of these severity values (ranges allowed for context-dependent findings):

| Severity | Meaning |
|----------|---------|
| Critical | Direct fund loss or protocol bricking with no preconditions |
| High | Fund loss or severe DoS with realistic preconditions |
| Medium | Conditional exploit, economic inefficiency, or degraded security |
| Low | Minor issue, edge case, or defense-in-depth gap |
| Informational | Design observation, best practice, or trust assumption |
| Gas | Gas optimization opportunity with no security impact (EVM only) |

Range format: `{Lower}-{Higher}` (e.g., `Medium-Critical`) — used when severity depends on deployment context.

### Categories

#### EVM Categories (20)

| ID | Name | Scope |
|----|------|-------|
| ACC | Access Control | Auth, roles, modifiers, centralization, input validation, signatures |
| ASM | Assembly | Inline assembly safety, memory management |
| CRYPTO | Cryptography | Randomness, signatures, proofs |
| DEX | DEX/AMM | AMM formulas, fees, pool management, slippage |
| ERC20 | ERC-20 Token | Token compatibility, transfer integrity |
| GAS | Gas Optimization | Constants, loops, storage, redundancy |
| GEN | General Safety | Auth, data, DoS, ETH handling, events, reentrancy, state |
| GOV | Governance | Timelocks, proposals, quorum, voting |
| INTEG | Protocol Integration | Aave, Uniswap V3/V4 integration |
| LEND | Lending | Borrow/repay, collateral, health, interest, liquidation |
| MATH | Mathematics | Casting, division, overflow, rounding, scaling |
| NFT | NFT | Metadata, marketplace, ERC-721 |
| ORACLE | Oracle | Admin, decimals, fallback, spot manipulation, staleness, TWAP |
| PRED | Prediction Market | Market creation, settlement |
| PROXY | Proxy & Upgrades | Diamond, delegatecall, factory, initialization, storage, upgrades |
| STABLE | Stablecoin | Mechanism, peg assumptions |
| STAKE | Staking | Epochs, rewards, config, slashing, gaming, accounting, unstaking |
| VAULT | Vault | Accounting, ERC-7540, operations, share price, ERC-4626, yield |
| VESTING | Vesting | Schedule integrity |
| XCHAIN | Cross-Chain | Accounting, finality, liveness, message auth, replay |

#### Move Categories (11, shared by Aptos and Sui)

| ID | Name | Scope |
|----|------|-------|
| ACC | Access Control | Auth, roles, visibility, centralization, input validation |
| COIN | Coin/Token | Token handling, decimal precision, supply |
| CRYPTO | Cryptography | Signatures, proofs, merkle, replay protection |
| GAS | Gas & Performance | Loops, storage bloat, hash collision, redundancy |
| GEN | General Logic | Init, state, events, errors, timestamps, types |
| LEND | Lending | Liquidation, pause/recovery, collateral |
| MATH | Arithmetic | Overflow, casting, formulas, precision, scaling |
| OBJ | Object Model | Abilities, hot potato, witness, resource accounts |
| ORACLE | Oracle | Freshness, aggregation, price validation, DeFi integration |
| POOL | Pool/DEX/Staking | AMM, flash loans, LP, routing, rewards |
| VAULT | Vault | Share accounting, state sync |

---

## Rulepack Entry Format

Each detector also needs a compact entry in `rulepack.md`:

```markdown
## {PLATFORM}-{CAT}-{ABBR}-{NN}

- Title: {Same title as checklist item}
- Severity default: {Severity}
- Trigger idea: {Numbered detection steps as a single line — what to look for in code}
- Counter-evidence: {What a secure implementation looks like — what negates the finding}
```

---

## Index Entry Format

Each detector needs a one-liner in `index.md` under its category:

```markdown
- CL-{CAT}-{NN}: {Short description} → `{PLATFORM}-{CAT}-{ABBR}-{NN}`
```

Update the category's item count in the index table when adding detectors.

---

## Guidelines for Writing Detectors

1. **One invariant per detector.** Each detector checks a single security property. If two properties are unrelated, split them.
2. **Patterns must be concrete.** Every pattern includes compilable (or near-compilable) code showing both the vulnerable and fixed versions.
3. **Detection steps are mechanical.** Write them so an auditor (human or AI) can follow them step-by-step without domain intuition.
4. **Counter-evidence is specific.** State exactly what implementation elements negate the finding — not vague advice like "add proper checks".
5. **Severity reflects worst-case realistic impact.** Use ranges when the severity depends on deployment context (e.g., whether admin keys are multisig).
6. **Platform parity.** When a vulnerability concept applies across platforms, create parallel entries. Adjust code examples for platform-specific APIs.
7. **Keep patterns minimal.** Show only the code relevant to the vulnerability — strip unrelated logic from examples.
