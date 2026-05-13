# CAT-CRYPTO — Cryptography

## CL-CRYPTO-01: Signature & Proof Verification

**Rule:** `MOVE-CRYPTO-SIG-01`
**Severity:** Medium-Critical

### Description
On-chain signature and proof verification must enforce replay protection, domain separation, payload completeness, malleability resistance, and digest correctness. Failure in any enables replay attacks, cross-chain reuse, parameter manipulation, forgery, or DoS.

### Patterns

#### Pattern 1: Replay Protection
Every signature must be consumed exactly once via a nonce, salt, or nullifier. Without tracking, the same valid signature can be submitted repeatedly.

**Vulnerable:**
```move
// No nonce tracking -- same signature can be replayed
public fun claim(sig: vector<u8>, amount: u64) {
    assert!(ed25519::ed25519_verify(&sig, &PUBKEY, &bcs::to_bytes(&amount)), EInvalidSig);
    mint_tokens(amount);
}
```

**Fixed:**
```move
// Nonce consumed on first use
public fun claim(sig: vector<u8>, amount: u64, nonce: u64, state: &mut State) {
    assert!(!table::contains(&state.used_nonces, nonce), ENonceUsed);
    let mut msg = bcs::to_bytes(&nonce);
    vector::append(&mut msg, bcs::to_bytes(&amount));
    assert!(ed25519::ed25519_verify(&sig, &PUBKEY, &msg), EInvalidSig);
    table::add(&mut state.used_nonces, nonce, true);
    mint_tokens(amount);
}
```

#### Pattern 2: Domain Separation
Signatures must be bound to a specific chain, contract, and action type. Without domain separation, a signature valid on Sui can be replayed on Aptos or across contracts on the same chain.

**Vulnerable:**
```move
// No domain separator -- signature valid across chains and contracts
public fun authorize(sig: vector<u8>, action_data: vector<u8>) {
    assert!(ed25519::ed25519_verify(&sig, &PUBKEY, &action_data), EInvalidSig);
}
```

**Fixed:**
```move
// Domain-separated with contract + chain binding
public fun authorize(sig: vector<u8>, action_data: vector<u8>) {
    let mut msg = b"MyProtocol::v1::Authorize::";
    vector::append(&mut msg, bcs::to_bytes(&@my_contract));
    vector::append(&mut msg, b"sui:mainnet");
    vector::append(&mut msg, action_data);
    assert!(ed25519::ed25519_verify(&sig, &PUBKEY, &msg), EInvalidSig);
}
```

#### Pattern 3: Missing Parameters in Signed Payload
Critical parameters not included in the signed message can be manipulated by the transaction submitter. If the message includes `amount` but not `recipient`, the relayer can redirect funds.

**Vulnerable:**
```move
public fun execute_transfer(
    amount: u64,
    recipient: address,  // NOT in signed message -- attacker-controlled
    nonce: u64,
    signature: vector<u8>,
    public_key: vector<u8>,
) {
    let message = bcs::to_bytes(&TransferMsg { amount, nonce }); // recipient missing!
    assert!(ed25519::ed25519_verify(&signature, &public_key, &message), E_INVALID);
    transfer_tokens(amount, recipient); // Attacker redirects funds
}
```

**Fixed:**
```move
public fun execute_transfer(
    amount: u64,
    recipient: address,
    nonce: u64,
    deadline: u64,
    signature: vector<u8>,
    public_key: vector<u8>,
    clock: &Clock,
) {
    assert!(clock::timestamp_ms(clock) <= deadline, E_EXPIRED);
    // ALL outcome-affecting parameters in the signed message
    let message = bcs::to_bytes(&TransferMsg { amount, recipient, nonce, deadline });
    assert!(ed25519::ed25519_verify(&signature, &public_key, &message), E_INVALID);
    transfer_tokens(amount, recipient);
}
```

#### Pattern 4: Merkle Proof Verification
Merkle proofs used for whitelists, airdrops, or state verification must hash leaves with a domain separator (double-hash or prefix) to prevent second-preimage attacks, must validate proof length, and must track claimed leaves to prevent replay.

**Vulnerable:**
```move
// BUG 1: leaf = hash(addr, amount) — internal nodes are also hash(a, b)
//   attacker can submit an internal node as a "leaf" (second preimage)
// BUG 2: no claim tracking — same proof can be replayed
public fun claim_airdrop(
    root: vector<u8>,
    proof: vector<vector<u8>>,
    amount: u64,
    ctx: &mut TxContext,
) {
    let leaf = hash::sha3_256(bcs::to_bytes(&AirdropLeaf {
        addr: tx_context::sender(ctx), amount
    }));
    assert!(verify_merkle_proof(root, proof, leaf), E_INVALID_PROOF);
    mint_tokens(amount, tx_context::sender(ctx));
}

fun verify_merkle_proof(root: vector<u8>, proof: vector<vector<u8>>, leaf: vector<u8>): bool {
    let current = leaf;
    let i = 0;
    while (i < vector::length(&proof)) {
        let sibling = vector::borrow(&proof, i);
        // No ordering — attacker can swap leaf/sibling positions
        let mut combined = current;
        vector::append(&mut combined, *sibling);
        current = hash::sha3_256(combined);
        i = i + 1;
    };
    current == root
}
```

**Fixed:**
```move
public fun claim_airdrop(
    state: &mut AirdropState,
    proof: vector<vector<u8>>,
    amount: u64,
    ctx: &mut TxContext,
) {
    let sender = tx_context::sender(ctx);
    // Double-hash leaf to prevent second-preimage (leaf ≠ internal node)
    let leaf = hash::sha3_256(hash::sha3_256(bcs::to_bytes(&AirdropLeaf {
        addr: sender, amount
    })));
    assert!(verify_merkle_proof(state.root, proof, leaf), E_INVALID_PROOF);
    // Prevent replay — mark leaf as claimed
    assert!(!table::contains(&state.claimed, sender), E_ALREADY_CLAIMED);
    table::add(&mut state.claimed, sender, true);
    mint_tokens(amount, sender);
}

fun verify_merkle_proof(root: vector<u8>, proof: vector<vector<u8>>, leaf: vector<u8>): bool {
    let current = leaf;
    let i = 0;
    while (i < vector::length(&proof)) {
        let sibling = vector::borrow(&proof, i);
        // Canonical ordering: smaller hash first to prevent ordering attacks
        current = if (compare_bytes(&current, sibling)) {
            let mut combined = current;
            vector::append(&mut combined, *sibling);
            hash::sha3_256(combined)
        } else {
            let mut combined = *sibling;
            vector::append(&mut combined, current);
            hash::sha3_256(combined)
        };
        i = i + 1;
    };
    current == root
}
```

#### Pattern 5: Digest Correctness
The fields used to reconstruct the digest on-chain must exactly match the fields signed off-chain. Types, field ordering, and encoding must be consistent.

**Vulnerable:**
```move
// Off-chain signs (nonce, amount, recipient) but on-chain reconstructs (amount, nonce, recipient)
public fun execute(sig: vector<u8>, amount: u64, nonce: u64, recipient: address) {
    let mut msg = bcs::to_bytes(&amount);   // Wrong order vs off-chain
    vector::append(&mut msg, bcs::to_bytes(&nonce));
    vector::append(&mut msg, bcs::to_bytes(&recipient));
    assert!(ed25519::ed25519_verify(&sig, &PUBKEY, &msg), EInvalidSig);
}
```

**Fixed:**
```move
// Field order matches off-chain signing schema exactly
public fun execute(sig: vector<u8>, amount: u64, nonce: u64, recipient: address) {
    let mut msg = bcs::to_bytes(&nonce);     // Matches off-chain order
    vector::append(&mut msg, bcs::to_bytes(&amount));
    vector::append(&mut msg, bcs::to_bytes(&recipient));
    assert!(ed25519::ed25519_verify(&sig, &PUBKEY, &msg), EInvalidSig);
}
```

### Remediation
Implement comprehensive signature verification: consume a nonce/nullifier per use, enforce byte-length checks, include all outcome-affecting parameters and domain separators (contract address, chain ID, action type) in signed messages, and verify digest reconstruction matches the off-chain signing schema exactly.

### Signature
**Slug:** `signature-verification-invariant`
**Detect:** For every on-chain signature/proof/merkle verification path: (1) verify replay protection via consumed nonce/nullifier/claimed-set, (2) verify domain separation binding to contract+chain+action, (3) verify all outcome-affecting parameters are in the signed payload, (4) verify merkle proofs use double-hashed leaves, canonical ordering, and claim tracking, (5) verify digest field order and encoding matches off-chain schema.
**What's Wrong:** Signature/proof verification is missing replay protection, domain separation, payload completeness, merkle proof safety, or digest correctness.
**Remediation:** Implement nonce-based replay protection, add domain separators, include all parameters in signed messages, double-hash merkle leaves with canonical ordering, and verify digest reconstruction matches the signing schema.
