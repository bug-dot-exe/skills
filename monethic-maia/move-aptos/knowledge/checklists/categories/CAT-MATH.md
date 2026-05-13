# CAT-MATH: Mathematics

**Context:** `ctx:generic`
**Detectors:** 5

## CL-MATH-01: Unsafe Type Casting

**Rule:** `MOVE-MATH-CAST-01`
**Severity:** low-high

## Description
Every numeric type conversion must validate that the source value fits within the target type's representable range, including sign, width, and boundary conditions.

## Patterns

1. **Unchecked Downcast (u128 to u64)** — Casting a u128 value to u64 with the `as` operator silently truncates high-order bits when the value exceeds U64_MAX.

```move
// VULNERABLE: silent truncation if result > U64_MAX
public fun to_u64(value: u128): u64 {
    (value as u64)
}

// FIXED: assert value fits
public fun to_u64(value: u128): u64 {
    assert!(value <= (U64_MAX as u128), E_OVERFLOW);
    (value as u64)
}
```

2. **Signed-to-Unsigned Conversion** — A custom signed integer with a negative value is converted to unsigned without checking the sign, wrapping to a large positive value.

```move
// VULNERABLE: negative value becomes huge unsigned
public fun abs_value(x: I64): u64 {
    x.magnitude
}
// Caller uses abs_value in arithmetic without checking sign

// FIXED: explicitly handle negative case
public fun to_u64_checked(x: I64): u64 {
    assert!(!x.negative, E_NEGATIVE_VALUE);
    x.magnitude
}
```

3. **Off-by-One in Bit-Width Validation** — Using inclusive comparison against 2^N instead of exclusive (2^N - 1) allows values that overflow the target type.

```move
// VULNERABLE: allows value == 2^64 which doesn't fit in u64
public fun validate_u64(value: u128): bool {
    value <= 18446744073709551616  // 2^64, should be 2^64 - 1
}

// FIXED: use correct max
public fun validate_u64(value: u128): bool {
    value <= 18446744073709551615  // U64_MAX = 2^64 - 1
}
```

4. **Silent Truncation in Math Utilities** — Library functions performing intermediate calculations in a wider type cast back to a narrower type without overflow checks.

```move
// VULNERABLE: intermediate u128 result cast back to u64 without check
public fun mul_div(a: u64, b: u64, c: u64): u64 {
    let result = ((a as u128) * (b as u128)) / (c as u128);
    (result as u64)
}

// FIXED: validate before downcast
public fun mul_div(a: u64, b: u64, c: u64): u64 {
    let result = ((a as u128) * (b as u128)) / (c as u128);
    assert!(result <= (U64_MAX as u128), E_OVERFLOW);
    (result as u64)
}
```

5. **Signed Zero Ambiguity** — Custom signed integer representations allow both +0 and -0, causing equality checks and branching logic to behave inconsistently.

```move
// VULNERABLE: negative zero passes sign checks differently than positive zero
public fun is_negative(x: I64): bool {
    x.negative  // true for -0, false for +0
}

// FIXED: normalize zero to positive
public fun new(magnitude: u64, negative: bool): I64 {
    I64 {
        magnitude,
        negative: if (magnitude == 0) { false } else { negative }
    }
}
```

## Remediation
Always assert that values fit the target type before downcasting. Normalize signed zero representations. Use exclusive upper bounds (2^N - 1) for bit-width validation. Validate sign before signed-to-unsigned conversion.

## Signature
**Slug:** `unsafe-type-casting`
**Detect:** For every type cast operation: (1) check u128-to-u64 downcasts for overflow assertion, (2) check signed-to-unsigned conversions for negative value handling, (3) check bit-width boundary validations for off-by-one, (4) check math utility return paths for unchecked narrowing casts, (5) check custom signed types for zero-sign normalization.
**What's Wrong:** Type conversions silently truncate, wrap, or misrepresent values when the source value does not fit the target type's range or sign semantics.
**Remediation:** Add explicit range assertions before every narrowing cast, handle negative values before signed-to-unsigned conversion, and normalize signed zero.

---

## CL-MATH-02: Incorrect Mathematical Formula and Logic

**Rule:** `MOVE-MATH-FORM-01`
**Severity:** low-critical

## Description
Every mathematical formula, constant definition, and algorithmic implementation must correctly encode the intended mathematical relationship, including operand ordering, constant values, convergence checks, and boundary validations.

## Patterns

1. **Inverted Ratio / Swapped Operands** — The numerator and denominator in a division are swapped, or operands are passed in the wrong order, producing the reciprocal of the intended result.

```move
// VULNERABLE: calculates reserve_a/reserve_b instead of reserve_b/reserve_a
public fun get_price(reserve_a: u64, reserve_b: u64): u64 {
    (reserve_a * PRECISION) / reserve_b
}

// FIXED: correct operand order
public fun get_price(reserve_a: u64, reserve_b: u64): u64 {
    (reserve_b * PRECISION) / reserve_a
}
```

2. **Incorrect Constant Literal** — A hardcoded constant (hex boundary, max value, mathematical constant) contains a typo or uses the wrong value, breaking boundary checks or calculations.

```move
// VULNERABLE: typo in U64_MAX constant (missing F)
const U64_MAX: u64 = 0xFFFFFFFFFFFFFFF;  // 15 F's, should be 16

// FIXED: correct hex literal
const U64_MAX: u64 = 0xFFFFFFFFFFFFFFFF;  // 16 F's = 2^64 - 1
```

3. **Incorrect Order of Operations** — Squaring, square root, or exponentiation is applied at the wrong step in a multi-step formula, violating the mathematical identity.

```move
// VULNERABLE: sqrt applied to components separately loses cross-term
public fun geometric_mean(a: u64, b: u64): u64 {
    (math::sqrt(a) * math::sqrt(b))  // != sqrt(a*b) due to truncation
}

// FIXED: multiply first, then sqrt
public fun geometric_mean(a: u64, b: u64): u64 {
    (math::sqrt((a as u128) * (b as u128)) as u64)
}
```

4. **Division by Zero** — A division operation does not validate that the divisor is non-zero, causing a runtime abort when pools are empty or weights are unset.

```move
// VULNERABLE: reserve can be zero for new pools
public fun get_amount_out(amount_in: u64, reserve_in: u64, reserve_out: u64): u64 {
    (amount_in * reserve_out) / reserve_in
}

// FIXED: validate divisor
public fun get_amount_out(amount_in: u64, reserve_in: u64, reserve_out: u64): u64 {
    assert!(reserve_in > 0, E_ZERO_RESERVE);
    (amount_in * reserve_out) / reserve_in
}
```

5. **Flawed Convergence / Boundary Check** — Iterative algorithms (Newton's method, binary search) use incorrect loop termination, post-loop assertions, or arbitrary growth limits that cause incorrect results or DoS.

```move
// VULNERABLE: convergence check outside loop uses stale variable
public fun newton_sqrt(x: u128): u128 {
    let y = x;
    let z = (y + 1) / 2;
    while (z < y) {
        y = z;
        z = (x / z + z) / 2;
    };
    assert!(z * z <= x, E_NOT_CONVERGED);  // z may differ from y
    y
}

// FIXED: check convergence using the returned value
public fun newton_sqrt(x: u128): u128 {
    let y = x;
    let z = (y + 1) / 2;
    while (z < y) {
        y = z;
        z = (x / z + z) / 2;
    };
    assert!(y * y <= x && (y + 1) * (y + 1) > x, E_NOT_CONVERGED);
    y
}
```

## Remediation
Review all formulas against their mathematical specifications. Verify constant literals against canonical definitions. Validate all divisors are non-zero. Ensure iterative algorithms check convergence on the returned value, not intermediate state.

## Signature
**Slug:** `incorrect-formula-logic`
**Detect:** For every mathematical formula: (1) check that numerator/denominator ordering matches the intended ratio, (2) check that hardcoded constants match their canonical values, (3) check that compound operations follow correct mathematical order, (4) check that all divisors are validated non-zero, (5) check that iterative algorithms verify convergence correctly.
**What's Wrong:** Mathematical formulas produce incorrect results due to swapped operands, typos in constants, wrong operation ordering, unguarded division by zero, or flawed convergence logic.
**Remediation:** Verify formulas against specifications, use named constants from verified libraries, validate divisors, and test convergence on return values.

---

## CL-MATH-03: Arithmetic Overflow and Underflow

**Rule:** `MOVE-MATH-OVF-01`
**Severity:** medium-critical

## Description
Every arithmetic operation on unsigned or custom signed integers must be validated against overflow and underflow boundaries before execution, or use safe-math wrappers that handle wrapping semantics correctly.

## Patterns

1. **Multiplication Overflow** — Two large values are multiplied without upcasting to a wider type, causing a runtime abort or silent wrap in custom math libraries.

```move
// VULNERABLE: u64 * u64 can exceed u64 max
public fun quote(amount: u64, reserve_in: u64, reserve_out: u64): u64 {
    (amount * reserve_out) / reserve_in
}

// FIXED: upcast to u128 before multiplication
public fun quote(amount: u64, reserve_in: u64, reserve_out: u64): u64 {
    ((((amount as u128) * (reserve_out as u128)) / (reserve_in as u128)) as u64)
}
```

2. **Subtraction Underflow** — An unsigned subtraction is performed without verifying the minuend is greater than or equal to the subtrahend, causing a runtime abort.

```move
// VULNERABLE: if fee > collateral, this aborts
public fun deduct_fee(collateral: u64, fee: u64): u64 {
    collateral - fee
}

// FIXED: clamp or check before subtraction
public fun deduct_fee(collateral: u64, fee: u64): u64 {
    if (fee >= collateral) { 0 } else { collateral - fee }
}
```

3. **Accumulator Overflow** — A global counter or accumulator that grows with each transaction eventually exceeds the type maximum under high-volume usage.

```move
// VULNERABLE: volume can overflow u128 under sustained high-volume trading
public fun update_volume(pool: &mut Pool, amount: u64) {
    pool.total_volume = pool.total_volume + (amount as u128);
}

// FIXED: use saturating addition or wider type with reset mechanism
public fun update_volume(pool: &mut Pool, amount: u64) {
    let new_vol = pool.total_volume + (amount as u128);
    pool.total_volume = if (new_vol < pool.total_volume) { U128_MAX } else { new_vol };
}
```

4. **Custom Signed Integer Overflow** — Protocols implementing signed math (i64/i128) via structs fail to check overflow at sign boundaries (e.g., MAX_I64 + 1 wraps to negative).

```move
// VULNERABLE: no overflow check on signed add
public fun add(a: I128, b: I128): I128 {
    I128 { value: a.value + b.value, negative: false }
}

// FIXED: check that result does not cross sign boundary
public fun add(a: I128, b: I128): I128 {
    let result = a.value + b.value;
    assert!(result >= a.value || b.negative, E_OVERFLOW);
    I128 { value: result, negative: compute_sign(a, b) }
}
```

5. **Bitwise Shift Overflow** — A left-shift operation does not validate the shift amount, producing zero or exceeding the type width.

```move
// VULNERABLE: shift >= 64 causes zero or abort
public fun pow2(exp: u8): u64 {
    1u64 << exp
}

// FIXED: validate shift range
public fun pow2(exp: u8): u64 {
    assert!(exp < 64, E_SHIFT_OVERFLOW);
    1u64 << exp
}
```

## Remediation
Upcast operands to wider types (u128/u256) before multiplication. Guard all subtractions with `>=` checks or saturating math. Validate shift amounts against type width. For custom signed types, check overflow at sign boundaries. For accumulators, use saturating addition or periodic resets.

## Signature
**Slug:** `arithmetic-overflow-underflow`
**Detect:** For every arithmetic operation: (1) check multiplications for intermediate overflow without upcasting, (2) check subtractions for underflow without guards, (3) check accumulators for unbounded growth, (4) check custom signed math for sign-boundary overflow, (5) check bitwise shifts for out-of-range shift amounts.
**What's Wrong:** Arithmetic operations exceed or underflow the value range of the integer type, causing runtime aborts (DoS) or incorrect results in custom wrapping implementations.
**Remediation:** Use wider intermediate types, saturating arithmetic, conditional guards, and range validation for all arithmetic operations.

---

## CL-MATH-04: Precision Loss and Rounding Errors

**Rule:** `MOVE-MATH-PREC-01`
**Severity:** low-high

## Description
Every integer arithmetic operation that involves division must preserve maximum precision by ordering operations correctly, using sufficient precision factors, and applying directionally-correct rounding to prevent value leakage.

## Patterns

1. **Division Before Multiplication** — Performing division before multiplication truncates the intermediate result, magnifying precision loss when the quotient is subsequently scaled.

```move
// VULNERABLE: division truncates before multiplication
public fun calculate_reward(amount: u64, rate: u64, precision: u64): u64 {
    (amount / precision) * rate
}

// FIXED: multiply first, divide last
public fun calculate_reward(amount: u64, rate: u64, precision: u64): u64 {
    (((amount as u128) * (rate as u128) / (precision as u128)) as u64)
}
```

2. **Insufficient Precision Factor** — The scaling multiplier is too small relative to the value range, causing accumulator updates or rate calculations to truncate to zero.

```move
// VULNERABLE: 1e6 precision too small for large total_supply
public fun update_index(rewards: u64, total_supply: u64): u64 {
    (rewards * 1_000_000) / total_supply
}

// FIXED: use higher precision factor
public fun update_index(rewards: u64, total_supply: u64): u128 {
    ((rewards as u128) * 1_000_000_000_000_000_000u128) / (total_supply as u128)
}
```

3. **Asymmetric Rounding Required** — Using the same rounding direction for both deposit (mint) and withdrawal (burn) allows users to extract value through repeated small operations.

```move
// VULNERABLE: both mint and burn round down, favoring the user on burns
public fun to_shares(amount: u64, total: u64, supply: u64): u64 {
    (amount * supply) / total
}
public fun to_assets(shares: u64, total: u64, supply: u64): u64 {
    (shares * total) / supply
}

// FIXED: round against the user (down on mint, up on burn)
public fun to_shares(amount: u64, total: u64, supply: u64): u64 {
    (amount * supply) / total  // round down: user gets fewer shares
}
public fun to_assets(shares: u64, total: u64, supply: u64): u64 {
    let result = (shares * total) / supply;
    if (shares * total % supply != 0) { result + 1 } else { result }  // round up: user pays more
}
```

4. **Zero-Truncation on Small Values** — Integer division produces zero when the numerator is smaller than the denominator, allowing zero-fee or zero-reward operations.

```move
// VULNERABLE: small amounts produce zero fee
public fun calculate_fee(amount: u64, fee_bps: u64): u64 {
    (amount * fee_bps) / 10000
}

// FIXED: enforce minimum fee or revert on dust
public fun calculate_fee(amount: u64, fee_bps: u64): u64 {
    let fee = (amount * fee_bps) / 10000;
    assert!(fee > 0 || amount == 0, E_DUST_AMOUNT);
    fee
}
```

5. **Premature Sqrt / Exponentiation Precision Loss** — Applying square root or power operations before multiplication loses precision that cannot be recovered by subsequent scaling.

```move
// VULNERABLE: sqrt before multiply loses precision
public fun geometric_mean(a: u64, b: u64): u64 {
    let sa = math::sqrt(a);
    let sb = math::sqrt(b);
    sa * sb
}

// FIXED: multiply first, then sqrt
public fun geometric_mean(a: u64, b: u64): u64 {
    math::sqrt_u128((a as u128) * (b as u128))
}
```

## Remediation
Always multiply before dividing. Use precision factors of at least 1e18 for accumulator math. Apply round-down on deposits, round-up on withdrawals. Reject dust amounts that truncate to zero fees. Perform sqrt/pow on the largest possible intermediate value.

## Signature
**Slug:** `precision-loss-rounding`
**Detect:** For every division operation: (1) check that all multiplications precede the division, (2) check that the precision factor is large enough for the value range, (3) check that rounding direction is asymmetric (favors protocol on both deposit and withdraw), (4) check that zero-truncation on small values is handled, (5) check that sqrt/pow is applied after maximizing the intermediate product.
**What's Wrong:** Integer division truncation causes precision loss, zero-value results, or directional value leakage through repeated small operations.
**Remediation:** Reorder to multiply-first-divide-last, increase precision factors, enforce asymmetric rounding, reject dust, and defer lossy operations.

---

## CL-MATH-05: Decimal Scaling and Normalization Errors

**Rule:** `MOVE-MATH-SCALE-01`
**Severity:** medium-critical

## Description
Every arithmetic operation involving token amounts with different decimal precisions must apply scaling factors exactly once, consistently across numerator and denominator, and validate decimal metadata before use.

## Patterns

1. **Double Scaling** — A value is normalized or scaled by a decimal/precision factor twice in nested function calls, inflating or deflating the result.

```move
// VULNERABLE: scale_to_internal already normalizes, then caller normalizes again
public fun get_balance(raw: u64, decimals: u8): u64 {
    let internal = scale_to_internal(raw, decimals);
    internal * math::pow(10, (18 - decimals as u64))  // double-scaled!
}

// FIXED: scale exactly once
public fun get_balance(raw: u64, decimals: u8): u64 {
    scale_to_internal(raw, decimals)  // single normalization
}
```

2. **Missing Denormalization** — A calculation multiplies by a precision factor but never divides by it (or vice versa), leaving the result in the wrong unit scale.

```move
// VULNERABLE: multiplies by PRECISION but never divides back
public fun calculate_refund(amount: u64): u64 {
    amount * PRECISION  // returns value in scaled units, not token units
}

// FIXED: apply and remove scaling factor
public fun calculate_refund(amount: u64, rate: u64): u64 {
    (amount * PRECISION * rate) / PRECISION  // or simplify: amount * rate
}
```

3. **Inconsistent Scaling Across Operands** — Numerator and denominator use different decimal scales, producing a ratio in the wrong order of magnitude.

```move
// VULNERABLE: numerator in 18 decimals, denominator in 6 decimals
public fun price(amount_18: u64, amount_6: u64): u64 {
    amount_18 / amount_6  // result is off by 1e12
}

// FIXED: normalize both to same scale
public fun price(amount_18: u64, amount_6: u64): u64 {
    amount_18 / (amount_6 * 1_000_000_000_000)
}
```

4. **Hardcoded Decimal Assumption** — The code assumes a fixed decimal precision (e.g., 8 or 9) that does not match the actual token decimals, producing incorrect amounts.

```move
// VULNERABLE: assumes 9 decimals for all tokens
public fun to_base_units(amount: u64): u64 {
    amount * 1_000_000_000
}

// FIXED: use actual token decimals
public fun to_base_units(amount: u64, decimals: u8): u64 {
    amount * math::pow(10, (decimals as u64))
}
```

5. **Unvalidated Decimal Input** — User-supplied or externally-provided decimal values are used in scaling calculations without verification against the actual token metadata, enabling manipulation.

```move
// VULNERABLE: trusts user-provided decimals
public fun convert(amount: u64, decimals: u8): u64 {
    amount * math::pow(10, (18 - decimals as u64))
}

// FIXED: validate decimals against token metadata
public fun convert<CoinType>(amount: u64): u64 {
    let decimals = coin::decimals<CoinType>();
    assert!(decimals <= 18, E_INVALID_DECIMALS);
    amount * math::pow(10, ((18 - (decimals as u64))))
}
```

## Remediation
Apply scaling factors exactly once using a single normalization entry point. Ensure numerator and denominator use the same decimal base. Read token decimals from on-chain metadata rather than hardcoding. Validate external decimal inputs against token registry.

## Signature
**Slug:** `decimal-scaling-errors`
**Detect:** For every scaling or normalization operation: (1) check that precision factors are applied exactly once across the call chain, (2) check that multiplied precision factors are divided back before returning, (3) check that numerator and denominator operands share the same decimal scale, (4) check for hardcoded decimal constants that may not match token metadata, (5) check that decimal values from external sources are validated.
**What's Wrong:** Incorrect decimal scaling causes values to be inflated, deflated, or misrepresented by orders of magnitude, enabling fund extraction or breaking protocol invariants.
**Remediation:** Centralize normalization logic, validate decimal metadata on-chain, and ensure consistent scaling across all operands.

---
