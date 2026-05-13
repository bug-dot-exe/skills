# Recon — Pre-Audit Context Analysis

## Objective

Perform a static pre-audit analysis of the codebase. Do NOT find vulnerabilities at this stage. Generate a Context Report that provides the necessary context for the security audit phases.

Read the detected platform from `./.maia_auditor/platform.txt` and apply the corresponding platform section below.

## Exclusions

If `./.maia_auditor/exclusions.txt` exists, skip all listed paths during analysis. Do not include excluded files in entry point tables, state analysis, or category recommendations.

## Instructions

Analyze the code and generate a Context Report containing the following sections:

### 1. High-Level Summary

- **Language & Platform:** Identify the language and confirm the target platform.
- **Project Purpose:** Based on the code, describe the intended on-chain business logic and purpose in 1-2 sentences.

### 2. Roles & Trust Assumptions

- **Identified Roles:** List all distinct roles managed by the contracts/modules.
- **Trust Model:** For each role, describe its assumed purpose and trust level.

### 3. Entry Points & Access Control

Generate a markdown table of all externally callable functions with their visibility, access control mechanisms, and intended callers.

### 4. State & Dependencies

- **Critical State:** List key state variables/resources and their purpose.
- **Dependencies:** List framework/library dependencies.

### 5. Context Gaps

List any symbols, contracts, or external dependencies referenced but not present in the provided code. Do NOT guess their behavior.

### 6. Recommended Categories

List which categories are relevant based on detected patterns, with a one-line rationale per category.

---

## Platform: EVM

### Roles identification
- Look for: `onlyOwner`, `onlyRole`, `AccessControl`, `Ownable`, custom modifiers, `msg.sender` checks, `tx.origin`, `initializer` modifier
- Identify: admin, owner, operator, guardian, keeper, minter, pauser, upgrader roles

### Entry points table

| Function Signature | Visibility | Modifiers | Access Control | Intended Role(s) |
|--------------------|-----------|-----------|----------------|-------------------|

List every `external` and `public` function. For each, list visibility, modifiers (nonReentrant, whenNotPaused, etc.), access control checks, and intended caller role.

### State identification
- Storage variables (especially mappings, arrays, structs)
- Inheritance chain and storage layout
- Proxy patterns (transparent, UUPS, beacon, diamond)
- Immutable and constant values

### Dependencies
- OpenZeppelin contracts (AccessControl, Ownable, ReentrancyGuard, Pausable, etc.)
- Chainlink (AggregatorV3Interface, VRF, Automation)
- Uniswap (ISwapRouter, IQuoter, pools)
- Other protocol integrations (Aave, Compound, Curve, etc.)

### Vault pattern detection
CRITICAL: Must detect vault-like accounting BEYOND explicit ERC-4626:
- Formula `shares = assets * totalShares / totalAssets` under ANY variable names
- Variables like `lpTokens`, `poolShares`, `staked`, `totalDeposited`, `totalSupply` used in ratio math
- Any deposit function computing proportional shares via ratio math
- Any withdraw function converting shares back to assets via ratio
- This triggers VAULT category even without ERC-4626 inheritance

### Available categories (20)
ACC, ASM, CRYPTO, DEX, ERC20, GAS, GEN, GOV, INTEG, LEND, MATH, NFT, ORACLE, PRED, PROXY, STABLE, STAKE, VAULT, VESTING, XCHAIN

### Context-aware filtering
- Always include: ACC, GAS, GEN, MATH (universal for all EVM contracts)
- Include DEX only if AMM/swap/liquidity logic detected
- Include ERC20 if custom token or token interaction beyond simple transfers
- Include GOV if governance/voting/proposal logic detected
- Include INTEG if specific protocol integrations (Aave, Uniswap, etc.) detected
- Include LEND if lending/borrowing/collateral logic detected
- Include NFT if ERC-721/ERC-1155 logic detected
- Include ORACLE if price feed/oracle integration detected
- Include PRED if prediction market logic detected
- Include PROXY if upgradeable/proxy patterns detected
- Include STABLE if stablecoin mechanics detected
- Include STAKE if staking/rewards logic detected
- Include VAULT if vault/share accounting detected (see vault pattern detection above)
- Include VESTING if token vesting/lockup logic detected
- Include XCHAIN if cross-chain/bridge logic detected

## Platform: Move-Aptos

### Roles identification
- Look for: `signer::address_of`, capability patterns, `friend` declarations, hardcoded addresses, `assert!` admin checks

### Entry points table

| Function Signature | Visibility | Access Control | Acquires | Intended Role(s) |
|--------------------|-----------|---------------|----------|-------------------|

List every `public`, `public(friend)`, and `entry` function.

### State identification
- Resources/structs stored via `move_to`
- Module dependencies (`aptos_framework::*`, `aptos_std::*`)
- Object model usage (resource accounts, capabilities, ConstructorRef)

### Available categories (11)
ACC, COIN, CRYPTO, GAS, GEN, LEND, MATH, OBJ, ORACLE, POOL, VAULT

### Context-aware filtering
- Always include: ACC, GEN, MATH, OBJ
- Skip LEND, POOL, ORACLE, VAULT for non-DeFi projects

## Platform: Move-Sui

### Roles identification
- Look for: `tx_context::sender` checks, capability object patterns (`&AdminCap`), witness patterns, OTW structs, hardcoded addresses

### Entry points table

| Function Signature | Visibility | Access Control | Object Parameters | Intended Role(s) |
|--------------------|-----------|---------------|-------------------|-------------------|

List every `public`, `public(package)`, and `entry` function.

### State identification
- Structs/objects with ownership model (shared, owned, frozen)
- Dynamic fields (`dynamic_field::*`, `dynamic_object_field::*`)
- Witness/OTW patterns
- Framework dependencies (`sui::*`)

### Available categories (11)
ACC, COIN, CRYPTO, GAS, GEN, LEND, MATH, OBJ, ORACLE, POOL, VAULT

### Context-aware filtering
- Always include: ACC, GEN, MATH, OBJ
- Skip LEND, POOL, ORACLE, VAULT for non-DeFi projects

---

## Output Constraints

Keep the context report concise and structured:
- **High-Level Summary**: 2-3 sentences max
- **Roles table**: Max 10 rows
- **Entry Points table**: Max 30 rows
- **State & Dependencies**: Bullet points only, no prose
- **Context Gaps**: Simple list
- **Recommended Categories**: Category ID + one-line rationale

Target total output: ~500 words structured summary.

## Output

Write the context report to `./.maia_auditor/recon.md`

## After user selects mode

Once the user has chosen their detector mode (go / ALL / NUCLEAR / custom), print:

```
Starting! Grab yourself a coffee ☕ — results should be ready in 5-15 minutes.
```

Then proceed to the analysis passes.
