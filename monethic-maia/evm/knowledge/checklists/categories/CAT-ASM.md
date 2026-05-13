## CL-ASM-01: Assembly Call & Control Flow Integrity

**Rule:** `EVM-ASM-CALL-01`
**Severity:** low-critical

### Description
Contract uses inline assembly (Yul) to perform external calls via call, delegatecall, or staticcall opcodes. Assembly call return values are inverted, discarded, or unchecked, while target addresses may be unvalidated — leading to silent failures, state desynchronization, gas manipulation attacks, or denial of service.

### Patterns
### Pattern 1: Inverted Call Success Logic
The `call`/`delegatecall`/`staticcall` opcodes return 1 for success and 0 for failure. The success semantics are inverted by wrapping in `iszero()` before assigning to a success variable, or by branching on `if success { revert }` instead of `if iszero(success) { revert }`.

**Vulnerable:**
```solidity
// VULNERABLE: iszero(call(...)) returns true if the call FAILED
function _tryExecute(address target, uint256 value, bytes calldata data) internal returns (bool success) {
    assembly {
        success := iszero(call(gas(), target, value, add(data, 0x20), mload(data), 0, 0))
    }
}

// VULNERABLE: reverts on success, continues on failure
assembly {
    let success := delegatecall(gas(), target, 0, calldatasize(), 0, 0)
    if success { revert(0, 0) }
}
```

**Fixed:**
```solidity
// FIXED: call(...) returns 1 on success, 0 on failure — assign directly
function _tryExecuteFixed(address target, uint256 value, bytes calldata data) internal returns (bool success) {
    assembly {
        success := call(gas(), target, value, add(data, 0x20), mload(data), 0, 0)
    }
}

// FIXED: revert on failure
assembly {
    let success := delegatecall(gas(), target, 0, calldatasize(), 0, 0)
    if iszero(success) { revert(0, 0) }
}
```

### Pattern 2: Unchecked Call Return Value
The return value of call/delegatecall/staticcall is discarded via `pop()` or stored but never branched on. An attacker can force the sub-call to revert (e.g., via the 63/64 gas rule) while the parent execution continues, creating state desynchronization.

**Vulnerable:**
```solidity
// VULNERABLE: result is popped and ignored
function _notifyPod(address pod, address user, uint256 amount) internal {
    bytes4 selector = IPod.update.selector;
    uint256 gasLimit = 100000;
    assembly {
        let ptr := mload(0x40)
        mstore(ptr, selector)
        mstore(add(ptr, 0x04), user)
        mstore(add(ptr, 0x24), amount)
        pop(call(gasLimit, pod, 0, ptr, 0x44, 0, 0))
    }
}

// VULNERABLE: delegatecall result stored but never checked
assembly {
    let result := delegatecall(gas(), target, data, len, 0, 0)
    // execution continues regardless of result
}
```

**Fixed:**
```solidity
// FIXED: check return value and revert on failure
function _notifyPod(address pod, address user, uint256 amount) internal {
    bytes4 selector = IPod.update.selector;
    assembly {
        let ptr := mload(0x40)
        mstore(ptr, selector)
        mstore(add(ptr, 0x04), user)
        mstore(add(ptr, 0x24), amount)
        let success := call(gas(), pod, 0, ptr, 0x44, 0, 0)
        if iszero(success) { revert(0, 0) }
    }
}
```

### Pattern 3: Silent Call to Zero/Codeless Address
The EVM returns success for calls to addresses with no code, including address(0). Assembly code that checks `iszero(success)` will not catch this case — the call silently succeeds with no effect.

**Vulnerable:**
```solidity
// VULNERABLE: returns 1 if target is address(0) or has no code
assembly {
    let success := call(gas(), target, value, 0, 0, 0, 0)
    if iszero(success) { revert(0, 0) }
}
```

**Fixed:**
```solidity
// FIXED: validate target before calling
require(target != address(0), "Invalid target");
require(target.code.length > 0, "No code at target");
assembly {
    let success := call(gas(), target, value, 0, 0, 0, 0)
    if iszero(success) { revert(0, 0) }
}
```

### Detect
For every inline assembly block that uses `call`, `delegatecall`, or `staticcall`: (1) verify the return value is not wrapped in `iszero()` before assignment and revert conditions are not inverted, (2) verify the return value is not discarded via `pop()` or left unchecked, (3) verify the target address is validated against `address(0)` and checked for code via `extcodesize`.

### Remediation
Always validate the return value of `call`, `delegatecall`, and `staticcall` opcodes in assembly. Use `if iszero(result) { revert(0, 0) }` to revert on failure. Never wrap call results in `iszero()` before assigning to a success variable. For best-effort calls, ensure failure cannot create exploitable state mismatches. Validate target addresses against `address(0)` and check `extcodesize` before calling when the target is user-supplied or may be uninitialized.

## CL-ASM-02: Assembly Memory & Data Integrity

**Rule:** `EVM-ASM-MEM-01`
**Severity:** low-medium

### Description
Contract uses inline assembly (Yul) for memory operations, storage packing, hashing, or key derivation. Assembly memory/storage operations miss bit-masking for sub-word types, use incorrect packing logic, trust user-supplied copy lengths, overwrite the free memory pointer, or derive keys with wrong offsets — all producing silently incorrect results leading to state corruption, data leaks, DoS, or hash collisions.

### Patterns
### Pattern 1: Dirty Upper Bits & Keccak256 Length Mismatch
Solidity does not guarantee upper bits of sub-256-bit types are zeroed. When passed to mstore followed by keccak256, dirty bits produce incorrect hashes.

**Vulnerable:**
```solidity
// VULNERABLE: address may have dirty upper bits
assembly {
    mstore(0x00, spender) // dirty bits included
    let slot := keccak256(0x00, 0x20)
    sstore(slot, amount)
}

// VULNERABLE: keccak256 length too small, ignoring second value
assembly {
    mstore(0x00, val1)
    mstore(0x20, val2)
    let result := keccak256(0x00, 0x20) // only hashes val1
}
```

**Fixed:**
```solidity
// FIXED: clean upper bits before mstore
assembly {
    let cleanSpender := and(spender, 0xffffffffffffffffffffffffffffffffffffffff)
    mstore(0x00, cleanSpender)
    let slot := keccak256(0x00, 0x20)
    sstore(slot, amount)
}

// FIXED: hash both slots
assembly {
    mstore(0x00, val1)
    mstore(0x20, val2)
    let result := keccak256(0x00, 0x40) // hashes val1 + val2
}
```

### Pattern 2: Storage Slot Packing Errors
Assembly code that packs multiple values into a single 256-bit storage slot fails to handle edge cases: full-slot sstore without masking overwrites adjacent data; unpacking via sload without shifts reads the wrong value.

**Vulnerable:**
```solidity
// VULNERABLE: full sstore overwrites adjacent data for odd element counts
function store(bytes32 slot, uint128[] memory data) internal {
    assembly {
        let len := mload(data)
        for { let i := 0 } lt(i, len) { i := add(i, 2) } {
            let val := mload(add(add(data, 32), mul(i, 16)))
            sstore(add(slot, div(i, 2)), val) // clears upper 128 bits if odd
        }
    }
}

// VULNERABLE: unpacking without bitwise shift reads wrong element
assembly {
    let slotData := sload(slot)
    mstore(add(memPtr, 32), slotData)
    mstore(add(memPtr, 64), slotData) // second element needs shl(128, ...)
}
```

**Fixed:**
```solidity
// FIXED: use sload + mask for partial writes, shift for unpacking
assembly {
    let slotData := sload(slot)
    mstore(add(memPtr, 32), slotData)
    mstore(add(memPtr, 64), shl(128, slotData)) // shift to extract second element
}
```

### Pattern 3: Unchecked Memory Copy Out-of-Bounds
Library functions using inline assembly to copy bytes accept user-provided length without validating against actual source buffer length, reading past the allocated buffer.

**Vulnerable:**
```solidity
// VULNERABLE: no bounds check on length vs source buffer
function sliceUnchecked(bytes memory source, uint256 offset, uint256 length) internal pure returns (bytes memory ret) {
    assembly {
        let srcPtr := add(add(source, 32), offset)
        ret := mload(0x40)
        mstore(ret, length)
        let destPtr := add(ret, 32)
        for { let i := 0 } lt(i, length) { i := add(i, 32) } {
            mstore(add(destPtr, i), mload(add(srcPtr, i)))
        }
    }
}
```

**Fixed:**
```solidity
// FIXED: validate bounds before assembly
function sliceChecked(bytes memory source, uint256 offset, uint256 length) internal pure returns (bytes memory ret) {
    require(offset + length <= source.length, "OOB");
    assembly {
        let srcPtr := add(add(source, 32), offset)
        ret := mload(0x40)
        mstore(ret, length)
        let destPtr := add(ret, 32)
        for { let i := 0 } lt(i, length) { i := add(i, 32) } {
            mstore(add(destPtr, i), mload(add(srcPtr, i)))
        }
        mstore(0x40, add(destPtr, length))
    }
}
```

### Pattern 4: Free Memory Pointer Overwrite
The Solidity compiler reserves memory slot 0x40 as the free memory pointer. Writing arbitrary values to this slot corrupts the allocator, triggering panic 0x41.

**Vulnerable:**
```solidity
// VULNERABLE: overwrites the free memory pointer at 0x40
assembly {
    mstore(0x40, someValue)
    result := keccak256(0x00, 0x60)
}
// subsequent abi.encode will panic (error 0x41)
bytes memory data = abi.encode(result);
```

**Fixed:**
```solidity
// FIXED: use scratch space (0x00-0x3f) instead
assembly {
    mstore(0x00, someValue)
    result := keccak256(0x00, 0x20)
}
```

### Pattern 5: Non-Standard Assembly Key Derivation
Manual mstore packing with wrong offsets or bit-shifts causes hash collisions where different users' inputs produce the same storage key.

**Vulnerable:**
```solidity
// VULNERABLE: wrong offsets and bit-shifts truncate address bytes
function getBadKey(address user, int24 tick, uint256 salt) public pure returns (bytes32 key) {
    assembly {
        mstore(0x00, or(shl(96, user), tick))
        mstore(0x20, salt)
        key := keccak256(0x0c, 0x34) // starts at wrong offset, misses data
    }
}
```

**Fixed:**
```solidity
// FIXED: use standard encoding
function getKey(address user, int24 tick, uint256 salt) public pure returns (bytes32) {
    return keccak256(abi.encodePacked(user, tick, salt));
}
```

### Detect
For every inline assembly block that performs memory or storage operations: (1) verify sub-256-bit types are masked before `mstore` and `keccak256` length covers all stored slots, (2) verify packed storage writes use `sload` + bitmask for partial updates and unpacking applies bitwise shifts, (3) verify memory copy loops validate source buffer length before iteration, (4) verify no `mstore(0x40, ...)` writes non-pointer data to the free memory pointer, (5) verify key derivation uses correct offsets without bit-field overlaps or address truncation.

### Remediation
Mask sub-256-bit types before `mstore` (e.g., `and(addr, 0xffffffffffffffffffffffffffffffffffffffff)`). Ensure `keccak256` length covers all stored data. Use `sload` + bitwise AND/OR masks for packed storage instead of full-slot `sstore`. Validate `offset + length <= source.length` before assembly memory copy loops. Never write non-pointer data to memory slot `0x40` — use scratch space (`0x00`-`0x3f`) for temporary values. Use `keccak256(abi.encodePacked(...))` for key derivation instead of manual `mstore` packing.
