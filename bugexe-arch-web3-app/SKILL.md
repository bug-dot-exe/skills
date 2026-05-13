---
name: web3-app
category: archetypes
description: Web3 app testing covering wallet auth bypass, signature replay, frontend manipulation of contract calls, MEV extraction, allowance abuse, flash loan interactions, and bridge exploits
---

# Web3 Application Testing

Security testing playbook for web3 applications and dApps. Focus on wallet authentication bypass, signature replay, frontend manipulation of smart contract calls, MEV extraction, token allowance abuse, flash loan interaction vectors, and bridge exploits.

## When to Use

- Target is a dApp with wallet-based authentication (MetaMask, WalletConnect)
- Application submits transactions or signs messages on behalf of users
- Frontend constructs and submits smart contract calls
- DeFi protocol with swaps, lending, staking, or bridging functionality
- Application interacts with multiple chains or bridges

## Priority Checklist

### 1. Wallet Authentication Bypass

- **Signature validation skip**: server accepts requests without verifying wallet signature
- **SIWE (EIP-4361) flaws**: missing domain binding, nonce reuse, or expiration enforcement
- **Address spoofing**: submit a different wallet address in the request body than the one that signed
- **Session persistence after disconnect**: wallet disconnected but session token remains valid
- **Smart contract wallet (EIP-1271)**: isValidSignature not called for contract wallets
- Test: authenticate with wallet A, then change the address field in API requests to wallet B

### 2. Signature Replay

- **Missing nonce**: signed messages without nonce allow unlimited replay
- **Cross-chain replay**: signature valid on mainnet replayed on L2 or testnet (missing chainId in domain)
- **Cross-contract replay**: signature scoped to contract A accepted by contract B at same address on another chain
- **Expired signature acceptance**: signatures with past deadlines still accepted
- **Permit replay**: ERC-2612 permit signatures replayed after nonce consumption failure
- Test: capture a signed transaction, replay it verbatim; test on alternate chains if multi-chain

### 3. Frontend Manipulation of Contract Calls

- **Parameter tampering**: modify calldata in the frontend before wallet signing (amounts, addresses, slippage)
- **Contract address substitution**: frontend points to a different contract than expected
- **ABI mismatch**: frontend encodes different function selector than the user intends
- **Approval bait-and-switch**: UI shows small approval but calldata requests unlimited allowance
- **Hidden multicall**: frontend bundles additional calls the user did not explicitly approve
- Test: intercept the transaction before wallet confirmation, decode calldata, compare to UI display

### 4. MEV Extraction

- **Sandwich attack surface**: swaps or trades without minimum output protection (slippage set to 0 or 100%)
- **Front-running sensitive operations**: liquidations, arbitrage, or NFT mints visible in mempool
- **Back-running opportunities**: large state changes that create arbitrage for the next transaction
- **Default slippage analysis**: check what slippage the frontend sets by default (>1% is risky)
- **Private mempool bypass**: verify if the application uses Flashbots or similar MEV protection
- Test: trace frontend swap calls for amountOutMin values; check if slippage protection is user-configurable

### 5. Allowance Abuse

- **Infinite approval requests**: dApp requests type(uint256).max approval for convenience
- **Stale approvals**: approvals to old/deprecated contracts that remain active
- **Approval front-running**: race between approval update and spend of old allowance
- **Permit2 misconfiguration**: universal approval to Permit2 with overly broad sub-permissions
- **Revocation UX gap**: no clear way for users to view or revoke active approvals
- Test: approve the dApp, then check if the approved contract can drain the full token balance

### 6. Flash Loan Interactions

- **Oracle manipulation**: protocol uses spot prices manipulable within a flash loan transaction
- **Collateral inflation**: flash-borrow assets to inflate collateral value, borrow against it, default
- **Governance flash voting**: flash-borrow governance tokens, vote, return in one transaction
- **Liquidity manipulation**: flash-borrow to drain or inflate pool liquidity and exploit dependent calculations
- **Callback reentrancy**: flash loan callback triggers reentrant calls to the protocol
- Test: construct a sequence: flash borrow, manipulate state, exploit, repay; check oracle type (TWAP vs spot)

### 7. Bridge Exploits

- **Message replay across chains**: bridge message processed on destination chain replayed
- **Proof verification bypass**: insufficient validation of Merkle proofs or validator signatures
- **Finality assumption violations**: source chain reorganization after bridge message was relayed
- **Relayer manipulation**: relayer submits modified or selectively censored messages
- **Timeout exploitation**: claim funds on both sides by exploiting timeout/refund race conditions
- Test: trace bridge message flow end-to-end; check nonce handling, proof verification, and finality assumptions

### 8. PRNG and Identifier Predictability

- **Session/token PRNG audit**: for any security-relevant identifier generated by the dApp backend (session IDs, nonces, invite tokens, API keys), collect 100+ samples and test for sequential patterns, time-based seeds, or low-entropy sources
- **Nonce prediction for meta-transactions**: if the dApp uses meta-transactions (gasless tx), predict the next nonce to front-run or replay the meta-transaction
- **Randomness in NFT minting**: if NFT traits or mint order depend on off-chain randomness, test if the seed is predictable (block hash, timestamp, sequential counter) to enable targeted minting
- Test: collect 50+ tokens/nonces/IDs, sort by generation time, and check for patterns (sequential, timestamp-based, modular arithmetic)

### 9. Shareable Link and Capability Token Abuse

- **Capability token in URL path**: if the dApp uses "anyone with the link" sharing (shared portfolios, public dashboards), the URL path segment IS the authorization token; test if it is guessable or enumerable
- **Referrer leakage of capability tokens**: shared links clicked from external sites leak the token via the Referer header to third-party scripts on the landing page
- **Token scope escalation**: a read-only share link may work for write operations if the backend does not distinguish read vs write capability tokens
- **Cached share page indexing**: shared pages cached by search engines or web archives expose the capability token in the indexed URL
- Test: generate a share link, inspect the URL for the capability token, test if shortening or modifying the token still grants access, check Referrer leakage

### 10. Cross-Property and Inter-Protocol Auth Token Abuse

- **Cross-dApp token reuse**: for platforms with multiple dApps (DEX + lending + staking), take a JWT or session token from one dApp and present it to another; if they share an auth service, the token may be accepted
- **OAuth token scope creep across properties**: first-party OAuth clients for different properties (main site, developer portal, analytics) may have different implicit scopes; use the broader token on the restricted property
- **Bridge auth token forwarding**: bridge UIs that authenticate on chain A and issue a session for chain B may not bind the session to the specific chain, allowing cross-chain session reuse
- Test: authenticate on each property/dApp in the ecosystem, capture every token, and replay each token on every other property

### 11. Webhook and Callback Body Manipulation

- **Webhook body template injection**: when a webhook lets you define a custom body template, the rendering engine may support template directives that read server-side variables or execute code (SSTI)
- **Callback URL SSRF**: webhook/callback URLs pointing to internal endpoints; beyond the standard `169.254.169.254`, test cloud metadata endpoints for the specific cloud provider (GCP, Azure, AWS)
- **Event payload data leakage**: webhook payloads for on-chain events may include full transaction details, private user data, or internal state that the subscriber should not see
- Test: register a webhook to your own endpoint, trigger every possible event type, inspect the payload for sensitive data; set the URL to internal endpoints and check for SSRF

### 12. Signed Cookie and Opaque Token Cracking

- **Decode and diff**: collect the same opaque cookie/token from two test accounts, base64-decode both, and diff byte-by-byte; stable bytes are constants or keys, varying bytes are identity/role claims
- **Delimiter-separated token field manipulation**: if the decoded token is delimiter-separated (`user_id|role|timestamp|hmac`), modify individual fields and test if the HMAC is recalculated or just truncated
- **Cryptographic parameter audit**: for any parameter that looks encrypted/signed (`*Encrypted`, `*Token`, `*Sig`, `*Hash`), test if it is actually validated: modify one byte and check if the server still accepts it
- Test: for every opaque token in cookies or headers, decode it (base64, hex, URL-encoded), identify the structure, modify fields, re-encode, and replay

### 13. Cloud IDE and Dev Environment Exploitation

- **Hosted dev environment isolation bypass**: for platforms with cloud IDEs or dev environments (browser-based code editors, sandbox environments), test if the dev container can reach internal services or other users' containers
- **Dev environment persistence after logout**: dev environments that persist after session end may contain credentials, private keys, or deployment artifacts accessible to the next user
- **Sandbox escape via package install**: in cloud IDEs, install a package that reads environment variables or network-scans the internal network from within the sandbox
- Test: access any cloud IDE or dev environment feature, attempt to reach internal services (`curl 169.254.169.254`, `curl localhost:*`), and check for credentials in environment variables

### 14. LLM and AI Integration Vectors (Web3-Specific)

- **AI agent wallet authorization bypass**: for dApps with AI agents that can execute transactions, inject prompts that make the agent sign transactions the user did not authorize
- **AI-assisted phishing via dApp chat**: if the dApp has an AI assistant, inject instructions (via stored data like token names or ENS records) that make the AI recommend sending funds to the attacker's address
- **RAG poisoning with on-chain data**: if the AI indexes on-chain data (contract names, token descriptions), poison that data source to alter the AI's responses for other users
- Test: interact with any AI feature in the dApp, attempt to make it reveal private keys, sign transactions, or surface other users' wallet data

## Pro Tips

- **Decode and diff every opaque token.** Most web3 apps use a mix of on-chain signatures and off-chain session tokens. The off-chain tokens are where traditional web bugs live. Diff them across accounts to find manipulable fields.
- **The frontend is the attack surface.** In web3, the smart contract is audited, but the frontend that constructs and submits transactions is not. Focus on what happens between the UI and the wallet confirmation dialog.
- **Shared link = bearer token.** Any "share this portfolio/dashboard" feature creates a capability token in the URL. Treat it with the same scrutiny as a session token.
- **Cross-property token reuse is highest-yield for multi-dApp ecosystems.** Platforms running multiple dApps on a shared auth service rarely validate the `aud` or `scope` claim per property.

## Validation

- Demonstrate wallet auth bypass with access to another user's on-chain or off-chain resources
- Show signature replay with duplicate transaction execution or unauthorized action
- Prove frontend manipulation with decoded calldata differing from displayed UI parameters
- Confirm MEV exposure with a concrete sandwich attack scenario and estimated extractable value
- Document wallet addresses, transaction hashes, decoded calldata, and chain state before/after
