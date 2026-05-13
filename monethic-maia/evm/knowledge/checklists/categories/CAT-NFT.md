## CL-NFT-01: NFT Metadata Integrity Invariant

**Rule:** `EVM-NFT-META-01`
**Severity:** informational-medium

### Description
The contract manages NFT metadata — storing, generating, or serving tokenURI, attributes, or on-chain metadata for ERC-721 or ERC-1155 tokens. NFT metadata becomes corrupted or stale when: burned tokens leave dangling state, 1-to-1 mappings are updated without clearing reverse entries, metadata is overwritten without existence checks, URIs are not validated, or dynamic metadata uses static placeholders.

### Patterns


### Detect
For every NFT metadata system: (1) verify burn functions clean up all associated metadata and custom mappings, (2) verify bidirectional mappings clear reverse entries on update, (3) verify metadata writes check for existing values when uniqueness is required, (4) verify tokenURI validates string length and handles missing baseURI, (5) verify on-chain metadata generation uses actual token ID variables not string placeholders.

### Remediation


## CL-NFT-02: NFT Marketplace Integrity Invariant

**Rule:** `EVM-NFT-MKT-01`
**Severity:** medium-critical

### Description
The contract implements an NFT marketplace, auction house, or exchange mechanism — handling listings, bids, escrow, fees, or fractional NFT swaps. NFT marketplace logic fails when: deposit flows for non-standard NFTs are frontrunnable, auction bids can be placed and withdrawn instantly for griefing, listings exist without escrow allowing duplicates, platform fees are bypassable via modular architecture, or fractional exchanges lose remainder funds through rounding.

### Patterns


### Detect
For every NFT marketplace: (1) verify non-standard NFT deposit flows validate the original owner to prevent front-running, (2) verify auction bids have minimum commitment periods and withdrawal doesn't check current ownership, (3) verify listings escrow the NFT or prevent duplicates, and buy orders require non-zero value, (4) verify fee modules are whitelisted and minimum fees are enforced at protocol level, (5) verify fractional exchanges only transfer exact costs or refund remainders.

### Remediation


## CL-NFT-03: ERC-721 Implementation Invariant

**Rule:** `EVM-NFT-STD-01`
**Severity:** medium-high

### Description
The contract implements, integrates with, or processes ERC-721 tokens — including minting, transferring, staking, or wrapping NFTs. ERC-721 implementations exhibit non-standard behaviors that break integrating protocols: mint reentrancy via safeMint callbacks, ownership state desync on transfer, batch operation edge cases, non-compliant interface implementations, and "weird" ERC-721 variants (dual-standard, upgradeable, pausable, self-burning, non-sequential IDs) that violate assumptions integrators rely on.

### Patterns


### Detect
For every ERC-721 integration: (1) verify safeMint callbacks cannot re-enter to bypass mint limits or corrupt state (CEI pattern or reentrancy guard), (2) verify ownership-dependent state is updated on every transfer path and per-token tracking is used instead of balance-based, (3) verify batch operations check for duplicate IDs, use monotonic counters not totalSupply, and refund excess ETH, (4) verify contracts holding NFTs implement IERC721Receiver and support all transfer variants, (5) verify the integration handles non-standard ERC-721 variants: dual-standard tokens, multi-collection contracts, self-burning/pausable/upgradeable tokens, non-sequential IDs, and pre-standard tokens.

### Remediation

