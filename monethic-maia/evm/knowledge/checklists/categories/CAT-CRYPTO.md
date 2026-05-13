## CL-CRYPTO-01: Randomness Invariant

**Rule:** `EVM-CRYPTO-RNG-01`
**Severity:** critical

### Description
On-chain randomness generation must avoid predictable block variables, separate VRF request and fulfillment into distinct transactions, prevent re-requests for the same outcome, preserve entropy through correct modulo application, and validate callback seeds. Failure in any single layer breaks the entire fairness model. These layers are interdependent: using VRF is insufficient if the result is consumed in the same transaction as the request, and proper request-response separation is meaningless if an attacker can re-request to fish for favorable outcomes.

### Patterns
### Pattern 1: No Block Variables
block.timestamp, block.number, block.prevrandao, and blockhash are deterministic values known to validators before block finalization. Any randomness derived from these values can be predicted or influenced by miners/validators.

**Vulnerable:**
```solidity
// Predictable randomness from block variables -- validator can manipulate
function getRandomNumber() public view returns (uint256) {
    return uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender)));
}
```

**Fixed:**
```solidity
// External VRF oracle provides verifiable randomness
function requestRandomNumber() external returns (uint256 requestId) {
    requestId = VRF_COORDINATOR.requestRandomWords(
        keyHash, subscriptionId, requestConfirmations, callbackGasLimit, numWords
    );
}
```

### Pattern 2: VRF Request-Response
If the VRF result is used in the same transaction as the request (synchronous pattern), the randomness is known before state changes are finalized. Always separate request and fulfillment into distinct transactions. Snapshot all relevant state at request time, not at fulfillment time, to prevent state manipulation between request and callback.

**Vulnerable:**
```solidity
// Synchronous VRF -- randomness known in same tx as state changes
function mintRandom() external {
    uint256 random = IRandomSource(oracle).getRandomNumber();
    uint256 tokenId = random % totalSupply;
    _mint(msg.sender, tokenId); // attacker can revert if unfavorable
}
```

**Fixed:**
```solidity
// Async VRF -- state snapshotted at request, applied at callback
function requestMint() external {
    uint256 requestId = VRF_COORDINATOR.requestRandomWords(...);
    snapshots[requestId] = MintSnapshot({minter: msg.sender, timestamp: block.timestamp});
}

function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) internal override {
    MintSnapshot memory snap = snapshots[requestId];
    uint256 tokenId = randomWords[0] % totalSupply;
    _mint(snap.minter, tokenId);
}
```

### Pattern 3: Re-Request Protection
If an attacker can cancel or re-request VRF randomness for the same outcome, they can fish for favorable results. Prevent multiple active requests for the same game round, mint batch, or outcome identifier. Invalidate or reject previous pending requests when a new one is submitted for the same context.

**Vulnerable:**
```solidity
// No re-request protection -- attacker can keep requesting until favorable
function requestRandom(uint256 roundId) external {
    uint256 requestId = VRF_COORDINATOR.requestRandomWords(...);
    roundRequests[roundId] = requestId;
}
```

**Fixed:**
```solidity
// Re-request protection -- one request per round
function requestRandom(uint256 roundId) external {
    require(roundRequests[roundId] == 0, "Already requested");
    uint256 requestId = VRF_COORDINATOR.requestRandomWords(...);
    roundRequests[roundId] = requestId;
    requestToRound[requestId] = roundId;
}
```

### Pattern 4: Entropy Preservation
Applying modulo to reduce the range and then multiplying or scaling the result destroys entropy and creates distribution bias. Always apply modulo as the final arithmetic operation on the random value. Never transform a reduced-range value back into a larger range.

**Vulnerable:**
```solidity
// Modulo then multiply destroys entropy
uint256 reduced = randomWord % 100;  // 0-99
uint256 scaled = reduced * 1e18;     // only 100 possible values at 1e18 scale
```

**Fixed:**
```solidity
// Modulo as final operation preserves entropy
uint256 result = randomWord % 100;  // 0-99, used directly
```

### Pattern 5: Seed Validation
VRF callbacks may return zero values on failure, and requestId mismatches can lead to applying randomness to the wrong context. Validate that the random value is non-zero before use. Verify the requestId matches a pending request for the expected context.

**Vulnerable:**
```solidity
// No validation -- zero value or wrong requestId silently accepted
function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) internal override {
    uint256 result = randomWords[0] % totalSupply;
    _mint(pendingMinter, result);
}
```

**Fixed:**
```solidity
// Validate non-zero value and matching requestId
function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) internal override {
    require(randomWords[0] != 0, "Invalid random value");
    MintSnapshot memory snap = snapshots[requestId];
    require(snap.minter != address(0), "Unknown requestId");
    uint256 result = randomWords[0] % totalSupply;
    _mint(snap.minter, result);
    delete snapshots[requestId];
}
```

### Detect
Check that randomness generation enforces all five layers: (1) no block.timestamp, block.number, block.prevrandao, or blockhash used as entropy sources, (2) VRF request and fulfillment in separate transactions with state snapshot at request time, (3) re-request prevention for same outcome context, (4) modulo applied as final operation without subsequent scaling, (5) callback value validated as non-zero with matching requestId.

### Remediation
Enforce all five sub-checks as a single randomness invariant. Never use block variables for entropy. Separate VRF request and fulfillment into distinct transactions with state snapshots at request time. Prevent re-requests for the same outcome. Apply modulo as the final operation. Validate callback values.

## CL-CRYPTO-02: Signature & Proof Verification Invariant

**Rule:** `EVM-CRYPTO-SIG-01`
**Severity:** critical

### Description
On-chain signature and proof verification must enforce malleability rejection, replay protection, payload completeness, zero-address recovery checks, dependency hygiene, and Merkle proof safety. Failure in any single layer breaks the entire authorization or inclusion proof model. These layers are interdependent: fixing malleability alone is insufficient if replay protection is missing, and replay protection is meaningless if the signed payload does not bind all state-changing parameters. Similarly, Merkle proofs share the same underlying requirements — domain separation, replay prevention, and binding — but applied to inclusion proofs rather than signatures.

### Patterns
### Pattern 1: Malleability
ecrecover accepts both high-s and low-s signature values for the same message. An attacker can compute the complementary s-value (s' = n - s) to produce a second valid signature. Enforce s < secp256k1n/2 by using OpenZeppelin ECDSA which rejects high-s values.

**Vulnerable:**
```solidity
// Raw ecrecover -- accepts high-s malleable signatures
function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
    address signer = ecrecover(hash, v, r, s);
    return signer == expectedSigner;
}
```

**Fixed:**
```solidity
// OpenZeppelin ECDSA rejects high-s values
function verify(bytes32 hash, bytes memory signature) public view returns (bool) {
    address signer = ECDSA.recover(hash, signature);
    return signer == expectedSigner;
}
```

### Pattern 2: Replay Protection
Without a consumed nonce, deadline, and domain separator (chainId + contract address), a valid signature can be resubmitted across time, chains, or contract instances. Consume nonces atomically with verification. Enforce block.timestamp <= deadline. Include chainId and address(this) in the EIP-712 domain separator.

**Vulnerable:**
```solidity
// No nonce, no deadline, no domain -- signature replayable everywhere
function execute(bytes32 hash, bytes memory sig) external {
    address signer = ECDSA.recover(hash, sig);
    require(signer == admin, "Invalid");
    _execute(hash);
}
```

**Fixed:**
```solidity
// Nonce + deadline + EIP-712 domain separator
function execute(bytes memory data, uint256 nonce, uint256 deadline, bytes memory sig) external {
    require(block.timestamp <= deadline, "Expired");
    require(!usedNonces[nonce], "Replayed");
    usedNonces[nonce] = true;
    bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(TYPEHASH, keccak256(data), nonce, deadline)));
    address signer = ECDSA.recover(digest, sig);
    require(signer == admin, "Invalid");
    _execute(data);
}
```

### Pattern 3: Payload Completeness
If the signed hash does not bind all state-changing parameters, an attacker can reuse a signature in a different context. Use EIP-712 structured typing with a complete type hash covering every parameter that affects execution. Include the signer's address in the payload. Bind gas limits for meta-transactions.

**Vulnerable:**
```solidity
// Only amount signed -- recipient is attacker-controlled
function transfer(address to, uint256 amount, bytes memory sig) external {
    bytes32 hash = keccak256(abi.encode(amount));
    address signer = ECDSA.recover(hash, sig);
    require(signer == admin, "Invalid");
    token.transfer(to, amount); // attacker redirects funds
}
```

**Fixed:**
```solidity
// All state-changing parameters in the signed payload
function transfer(address to, uint256 amount, uint256 nonce, uint256 deadline, bytes memory sig) external {
    require(block.timestamp <= deadline, "Expired");
    require(!usedNonces[nonce], "Replayed");
    usedNonces[nonce] = true;
    bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
        TRANSFER_TYPEHASH, to, amount, nonce, deadline
    )));
    address signer = ECDSA.recover(digest, sig);
    require(signer == admin, "Invalid");
    token.transfer(to, amount);
}
```

### Pattern 4: Zero-Address Return
ecrecover returns address(0) on invalid input rather than reverting. If the expected signer is uninitialized (also address(0)), any invalid signature passes the check. Always require(recovered != address(0)) before comparing to the expected signer.

**Vulnerable:**
```solidity
// No zero-address check -- uninitialized signer matches ecrecover failure
function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
    address signer = ecrecover(hash, v, r, s);
    require(signer == expectedSigner); // passes if both are address(0)
}
```

**Fixed:**
```solidity
// Zero-address check before comparison
function verify(bytes32 hash, bytes memory sig) public view returns (bool) {
    address signer = ECDSA.recover(hash, sig);
    require(signer != address(0), "Invalid signature");
    require(signer == expectedSigner, "Wrong signer");
}
```

### Pattern 5: Dependency Hygiene
Older versions of OpenZeppelin ECDSA (pre-4.7.3) contain known vulnerabilities including signature malleability bypasses. Use the latest stable release. Avoid manual v/r/s parsing which commonly introduces off-by-one or type confusion errors.

**Vulnerable:**
```solidity
// Manual v/r/s parsing -- error-prone and misses malleability checks
function verify(bytes32 hash, bytes memory sig) public view returns (bool) {
    bytes32 r; bytes32 s; uint8 v;
    assembly {
        r := mload(add(sig, 32))
        s := mload(add(sig, 64))
        v := byte(0, mload(add(sig, 96)))
    }
    address signer = ecrecover(hash, v, r, s);
    return signer == expectedSigner;
}
```

**Fixed:**
```solidity
// Current OpenZeppelin ECDSA handles parsing and malleability
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

function verify(bytes32 hash, bytes memory sig) public view returns (bool) {
    address signer = ECDSA.recover(hash, sig);
    require(signer != address(0), "Invalid signature");
    return signer == expectedSigner;
}
```

### Pattern 6: Merkle Proof Verification
Merkle proofs used for whitelists, airdrops, or state verification must enforce second preimage resistance via double-hashing, bind leaves to msg.sender, include domain separators (contract address, chainId, epoch), track claims per leaf to prevent replay, and validate proof length against expected tree depth.

**Vulnerable:**
```solidity
// Single hash, user-supplied address, no domain, no claim tracking, no depth check
function claim(address to, uint256 amount, bytes32[] calldata proof) external {
    bytes32 leaf = keccak256(abi.encodePacked(to, amount));
    require(MerkleProof.verify(proof, root, leaf), "Invalid proof");
    _mint(to, amount);
}
```

**Fixed:**
```solidity
// Double-hash, msg.sender binding, domain separation, claim tracking, depth validation
function claim(uint256 amount, bytes32[] calldata proof) external {
    bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(
        address(this), block.chainid, msg.sender, amount
    ))));
    require(!claimed[leaf], "Already claimed");
    require(proof.length == expectedDepth, "Invalid proof length");
    require(MerkleProof.verify(proof, root, leaf), "Invalid proof");
    claimed[leaf] = true;
    _mint(msg.sender, amount);
}
```

### Detect
Check that signature and proof verification enforces all layers: (1) low-s malleability rejection, (2) nonce consumption + deadline + domain separator with chainId and contract address, (3) complete EIP-712 struct hash binding all state-changing parameters and signer identity, (4) recovered address != address(0) check before comparison, (5) current OpenZeppelin ECDSA version without manual v/r/s parsing, (6) Merkle proofs use double-hashed leaves bound to msg.sender with domain separation, claim tracking, and proof depth validation.

### Remediation
Enforce all sub-checks as a single verification invariant. Use OpenZeppelin ECDSA.recover with EIP-712 structured data, include nonce + deadline + chainId + contract address in the domain, bind all state-changing parameters in the struct hash, always validate the recovered address is non-zero, and use current dependency versions. For Merkle proofs, double-hash leaves, bind to msg.sender, include domain separators, track claims per leaf, and validate proof depth.
