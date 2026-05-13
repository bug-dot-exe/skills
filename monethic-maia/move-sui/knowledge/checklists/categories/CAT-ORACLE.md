# CAT-ORACLE — Oracle

## CL-ORACLE-01: Oracle Administration

**Rule:** `MOVE-ORACLE-ADMIN-01`
**Severity:** Low-Medium

### Description
Oracle configuration, initialization, and administrative controls are insufficient to maintain protocol integrity. Single-signer oracle control, unvalidated price updates, and immutable configuration parameters all create exploitable weaknesses.

### Patterns

#### Pattern 1: Oracle Centralization and Single Point of Failure
Price data is sourced from a single-signer account or a centralized module without multi-signature requirements or decentralized fallback mechanisms. A compromise of this entity's credentials allows total control over price-dependent logic.

**Vulnerable:**
```move
// VULNERABLE: single admin controls all prices
public fun set_price(_admin: &AdminCap, store: &mut PriceStore, asset: u8, price: u64) {
    // Only one AdminCap holder controls all prices
    *vector::borrow_mut(&mut store.prices, (asset as u64)) = price;
}
```

**Fixed:**
```move
// FIXED: multi-source with threshold
public fun set_price(
    signers: &vector<address>,
    signatures: &vector<vector<u8>>,
    store: &mut PriceStore,
    asset: u8,
    price: u64
) {
    let valid = verify_multisig(signers, signatures, MIN_SIGNERS);
    assert!(valid, E_INSUFFICIENT_SIGNATURES);
    *vector::borrow_mut(&mut store.prices, (asset as u64)) = price;
}
```

#### Pattern 2: Unvalidated Oracle Price Update Bypasses Limits
The administrative function used to update asset prices lacks sanity checks or bounds validation. If an artificially low price is set, value-based security constraints are effectively neutralized.

**Vulnerable:**
```move
// VULNERABLE: no bounds on price update
public fun update_asset_price(admin: &AdminCap, registry: &mut PriceRegistry, asset: u8, price: u64) {
    table::upsert(&mut registry.prices, asset, price);
    // No check: price could be 1 wei, making rate limits useless
}
```

**Fixed:**
```move
// FIXED: deviation check
public fun update_asset_price(admin: &AdminCap, registry: &mut PriceRegistry, asset: u8, price: u64) {
    let old_price = *table::borrow(&registry.prices, asset);
    let max_change = old_price * MAX_DEVIATION_PCT / 100;
    let diff = if (price > old_price) { price - old_price } else { old_price - price };
    assert!(diff <= max_change, E_EXCESSIVE_DEVIATION);
    assert!(price > 0, E_ZERO_PRICE);
    table::upsert(&mut registry.prices, asset, price);
}
```

#### Pattern 3: Immutable Oracle Configuration Parameters
Setter functions for oracle configurations lack the logic to update existing parameters, requiring a full removal and re-addition of the oracle to change settings.

**Vulnerable:**
```move
// VULNERABLE: can only set, not update
public fun set_oracle(admin: &AdminCap, config: &mut OracleConfig, oracle_addr: address, max_dev: u64) {
    assert!(!option::is_some(&config.oracle), E_ALREADY_SET);
    config.oracle = option::some(OracleInfo { addr: oracle_addr, max_deviation: max_dev });
}
```

**Fixed:**
```move
// FIXED: allow updates
public fun set_oracle(admin: &AdminCap, config: &mut OracleConfig, oracle_addr: address, max_dev: u64) {
    config.oracle = option::some(OracleInfo { addr: oracle_addr, max_deviation: max_dev });
    event::emit(OracleUpdated { addr: oracle_addr, max_deviation: max_dev });
}
```

### Remediation
Implement multi-signature requirements for oracle updates, integrate decentralized oracles (Pyth, Switchboard), add deviation bounds on price updates, and allow oracle configuration to be updated without destructive removal.

### Signature
**Slug:** `oracle-administration-invariant`
**Detect:** For every oracle admin function: (1) verify oracle updates require multi-sig or decentralized validation, (2) verify price updates are bounded against deviation limits, (3) verify oracle configuration can be updated without destruction.
**What's Wrong:** Oracle admin controls allow single-point-of-failure price manipulation, unbounded price updates, or immutable configuration.
**Remediation:** Multi-sig oracle updates, deviation bounds, and updatable configuration.

---

## CL-ORACLE-02: Aggregation Integrity

**Rule:** `MOVE-ORACLE-AGG-01`
**Severity:** Medium-High

### Description
Oracle data aggregation or consensus mechanisms can be subverted through input manipulation or non-determinism. Duplicate feed injection and user-selected oracle subsets break aggregation security assumptions.

### Patterns

#### Pattern 1: Duplicate Data Feed ID Injection
Lack of uniqueness validation for feed IDs allows a single data source to provide multiple values for the same identifier, bypassing the security assumptions of median-based aggregation.

**Vulnerable:**
```move
// VULNERABLE: no duplicate check
public fun aggregate_feeds(feeds: &vector<DataFeed>): u64 {
    let prices = vector::empty<u64>();
    let i = 0;
    while (i < vector::length(feeds)) {
        let feed = vector::borrow(feeds, i);
        vector::push_back(&mut prices, feed.price);
        // No check if feed.id already seen
        i = i + 1;
    };
    median(&prices)
}
```

**Fixed:**
```move
// FIXED: enforce uniqueness
public fun aggregate_feeds(feeds: &vector<DataFeed>): u64 {
    let seen = vec_set::empty<vector<u8>>();
    let prices = vector::empty<u64>();
    let i = 0;
    while (i < vector::length(feeds)) {
        let feed = vector::borrow(feeds, i);
        assert!(!vec_set::contains(&seen, &feed.id), E_DUPLICATE_FEED);
        vec_set::insert(&mut seen, feed.id);
        vector::push_back(&mut prices, feed.price);
        i = i + 1;
    };
    median(&prices)
}
```

#### Pattern 2: Non-Deterministic Oracle Selection
The system allows callers to provide or select a subset of available oracle feeds to satisfy a weight/threshold requirement, enabling cherry-picking of favorable prices.

**Vulnerable:**
```move
// VULNERABLE: user chooses which feeds to include
public fun get_price(
    feeds: &vector<PriceFeed>,
    selected_indices: &vector<u64>
): u64 {
    let total_weight = 0;
    let weighted_sum = 0;
    let i = 0;
    while (i < vector::length(selected_indices)) {
        let idx = *vector::borrow(selected_indices, i);
        let feed = vector::borrow(feeds, idx);
        weighted_sum = weighted_sum + feed.price * feed.weight;
        total_weight = total_weight + feed.weight;
        i = i + 1;
    };
    assert!(total_weight >= MIN_WEIGHT, E_INSUFFICIENT);
    weighted_sum / total_weight // User picked favorable subset
}
```

**Fixed:**
```move
// FIXED: use all valid feeds deterministically
public fun get_price(feeds: &vector<PriceFeed>, clock: &Clock): u64 {
    let prices = vector::empty<u64>();
    let i = 0;
    while (i < vector::length(feeds)) {
        let feed = vector::borrow(feeds, i);
        if (is_fresh(feed, clock)) {
            vector::push_back(&mut prices, feed.price);
        };
        i = i + 1;
    };
    assert!(vector::length(&prices) >= MIN_FEEDS, E_INSUFFICIENT);
    median(&prices)
}
```

### Remediation
Implement uniqueness checks for feed IDs during payload processing. Enforce deterministic selection of all valid feeds rather than allowing user-defined subsets.

### Signature
**Slug:** `oracle-aggregation-integrity-invariant`
**Detect:** For every oracle aggregation function: (1) verify feed IDs are checked for uniqueness, (2) verify oracle selection is deterministic not user-controlled.
**What's Wrong:** Oracle aggregation allows duplicate feed injection or user-selected subsets that bias the aggregate price.
**Remediation:** Enforce feed ID uniqueness and deterministic selection of all valid feeds.

---

## CL-ORACLE-03: DeFi Integration

**Rule:** `MOVE-ORACLE-DEFI-01`
**Severity:** Medium-Critical

### Description
Beyond basic oracle validation (freshness, sanitization, aggregation), DeFi protocols face integration-specific oracle risks: flash loan price manipulation, missing circuit breakers on deviation, depeg events for wrapped/pegged assets, price direction confusion (A/B vs B/A), and using on-chain spot prices as slippage references.

### Patterns

#### Pattern 1: Flash Loan Price Manipulation
Protocol uses spot pool price or reserve ratio for valuation. Attacker uses a PTB to borrow via flash loan, manipulate pool price, execute at the manipulated price, and repay -- all atomically in a single transaction.

**Vulnerable:**
```move
public fun get_token_value(pool: &Pool, amount: u64): u64 {
    // Uses instantaneous pool reserves as price -- manipulable via flash loan
    let (reserve_a, reserve_b) = get_reserves(pool);
    amount * reserve_b / reserve_a
}

public fun borrow_against_collateral(
    pool: &Pool, lending: &mut LendingPool, collateral: Coin<TokenA>
) {
    let value = get_token_value(pool, coin::value(&collateral));
    // Attacker inflates pool price, borrows against inflated value
    issue_loan(lending, value);
}
```

**Fixed:**
```move
public fun get_token_value_safe(
    oracle: &PriceInfoObject, clock: &Clock, amount: u64
): u64 {
    let price = pyth::price_info::get_price(oracle);
    assert!(
        clock::timestamp_ms(clock) / 1000 - pyth::price::get_publish_time(&price) < 60,
        E_STALE_PRICE
    );
    let raw = pyth::price::get_price(&price);
    assert!(raw > 0, E_INVALID_PRICE);
    (((amount as u128) * (raw as u128) / (PRECISION as u128)) as u64)
}
```

#### Pattern 2: Circuit Breaker Missing
No deviation check between consecutive oracle updates. A sudden 50x spike triggers mass liquidations or unbounded borrowing immediately without any safety pause.

**Vulnerable:**
```move
struct PriceState has key, store { id: UID, current_price: u64 }

public fun update_price(state: &mut PriceState, price_info: &PriceInfoObject) {
    // Blindly accepts any price, even 100x jumps
    state.current_price = (pyth::price::get_price(
        &pyth::price_info::get_price(price_info)) as u64);
}
```

**Fixed:**
```move
const MAX_DEV_BPS: u64 = 1500; // 15% max deviation
const BPS: u64 = 10000;

struct PriceState has key, store { id: UID, current_price: u64, is_paused: bool }

public fun update_price_safe(
    state: &mut PriceState, price_info: &PriceInfoObject, clock: &Clock
) {
    assert!(!state.is_paused, E_CIRCUIT_BREAKER);
    let new_price = (pyth::price::get_price(
        &pyth::price_info::get_price(price_info)) as u64);
    assert!(new_price > 0, E_NEGATIVE_PRICE);
    if (state.current_price > 0) {
        let dev = if (new_price > state.current_price) {
            (new_price - state.current_price) * BPS / state.current_price
        } else {
            (state.current_price - new_price) * BPS / state.current_price
        };
        if (dev > MAX_DEV_BPS) {
            state.is_paused = true;
            abort E_CIRCUIT_BREAKER
        };
    };
    state.current_price = new_price;
}
```

#### Pattern 3: Depeg Events Not Handled
Protocol assumes wrapped/pegged asset equals underlying (wBTC=BTC, USDC=$1). Depeg breaks this assumption, causing incorrect valuations and exploitable arbitrage opportunities.

**Vulnerable:**
```move
public fun wbtc_collateral_value(
    wbtc_amount: u64, btc_usd_info: &PriceInfoObject
): u64 {
    let price = pyth::price_info::get_price(btc_usd_info);
    // Assumes wBTC == BTC -- ignores depeg
    wbtc_amount * (pyth::price::get_price(&price) as u64)
}
```

**Fixed:**
```move
const MAX_DEPEG_BPS: u64 = 200;

public fun wbtc_collateral_value_safe(
    wbtc_amount: u64,
    wbtc_usd_info: &PriceInfoObject,
    btc_usd_info: &PriceInfoObject,
): u64 {
    let wbtc_usd = (pyth::price::get_price(
        &pyth::price_info::get_price(wbtc_usd_info)) as u64);
    let btc_usd = (pyth::price::get_price(
        &pyth::price_info::get_price(btc_usd_info)) as u64);
    let ratio_bps = wbtc_usd * 10000 / btc_usd;
    let dev = if (ratio_bps > 10000) { ratio_bps - 10000 } else { 10000 - ratio_bps };
    assert!(dev <= MAX_DEPEG_BPS, E_DEPEG_DETECTED);
    wbtc_amount * wbtc_usd
}
```

#### Pattern 4: Price Direction Confusion (A/B vs B/A)
Using TOKEN_A/TOKEN_B price where TOKEN_B/TOKEN_A was needed. If BTC/USD = 50000, accidentally using USD/BTC produces values off by a factor of price-squared.

**Vulnerable:**
```move
public fun eth_needed_for_usd(
    usd_amount: u64, eth_usd_info: &PriceInfoObject
): u64 {
    let eth_per_usd = (pyth::price::get_price(
        &pyth::price_info::get_price(eth_usd_info)) as u64);
    // BUG: oracle returns usd_per_eth (3000), not eth_per_usd
    // Returns usd * 3000 instead of usd / 3000
    usd_amount * eth_per_usd
}
```

**Fixed:**
```move
const PRECISION: u64 = 100_000_000;

public fun eth_needed_for_usd_safe(
    usd_amount: u64, eth_usd_price_info: &PriceInfoObject, clock: &Clock
): u64 {
    let price = pyth::price_info::get_price(eth_usd_price_info);
    let usd_per_eth = (pyth::price::get_price(&price) as u64);
    assert!(usd_per_eth > 0, E_NEGATIVE_PRICE);
    // Divide to go USD -> ETH (price is USD-per-ETH)
    usd_amount * PRECISION / usd_per_eth
}
```

#### Pattern 5: On-Chain Price as Slippage Reference
Calculating `min_amount_out` from the same pool state that will execute the swap. An attacker manipulates pool state first, then the slippage calculation reflects the manipulated state, providing zero protection.

**Vulnerable:**
```move
public fun swap_with_auto_slippage<A, B>(
    pool: &mut Pool<A, B>, coin_in: Coin<A>
) {
    let amount_in = coin::value(&coin_in);
    // Attacker front-runs: manipulates pool reserves
    let expected_out = quote(pool, amount_in);
    let min_out = expected_out * 95 / 100; // 5% of manipulated price = no protection
    let out = do_swap(pool, coin_in);
    assert!(coin::value(&out) >= min_out, E_SLIPPAGE);
}
```

**Fixed:**
```move
public fun swap<A, B>(
    pool: &mut Pool<A, B>,
    coin_in: Coin<A>,
    min_amount_out: u64, // Calculated off-chain from TWAP or external oracle
    ctx: &mut TxContext
) {
    let out = do_swap(pool, coin_in);
    assert!(coin::value(&out) >= min_amount_out, E_SLIPPAGE);
    transfer::public_transfer(out, tx_context::sender(ctx));
}
```

### Remediation
Use external validated oracles (Pyth, Switchboard) instead of spot pool prices for valuations. Implement circuit breakers that pause on abnormal price deviations. Use dedicated price feeds for wrapped/pegged assets with depeg detection. Document and verify price direction at every oracle integration point. Require user-supplied slippage parameters calculated off-chain rather than derived from on-chain pool state.

### Signature
**Slug:** `oracle-defi-integration-invariant`
**Detect:** For every oracle-dependent DeFi operation: (1) verify valuations use manipulation-resistant oracles not spot pool prices, (2) verify circuit breakers exist for abnormal price deviations, (3) verify wrapped/pegged assets have depeg detection, (4) verify price direction (A/B vs B/A) is correct at every usage, (5) verify slippage references come from off-chain or external TWAP not same-pool queries.
**What's Wrong:** DeFi oracle integration allows flash-loan price manipulation, lacks circuit breakers for extreme deviations, ignores depeg risks for wrapped assets, confuses price quote direction, or derives slippage protection from manipulable on-chain state.
**Remediation:** Use external oracles for valuations, implement deviation circuit breakers, add depeg detection for wrapped assets, verify price direction at every integration, and require off-chain slippage parameters.

---

## CL-ORACLE-04: Freshness Validation

**Rule:** `MOVE-ORACLE-FRESH-01`
**Severity:** Low-High

### Description
Protocols consume oracle data without ensuring it reflects current market conditions. Missing timestamp checks, pull oracle staleness, and timestamp arithmetic underflows all compromise price validity.

### Patterns

#### Pattern 1: Missing Timestamp Freshness Check
The contract retrieves price data from an oracle but fails to compare the data's timestamp against the current block/system time to ensure it falls within an acceptable maximum interval.

**Vulnerable:**
```move
// VULNERABLE: no timestamp check
public fun get_price(oracle: &PriceOracle): u64 {
    let price_info = pyth::get_price(oracle);
    price_info.price // Could be hours old
}
```

**Fixed:**
```move
// FIXED: freshness validation
public fun get_price(oracle: &PriceOracle, clock: &Clock): u64 {
    let price_info = pyth::get_price(oracle);
    let age = clock::timestamp_ms(clock) - price_info.publish_time;
    assert!(age <= MAX_PRICE_AGE_MS, E_STALE_PRICE);
    price_info.price
}
```

#### Pattern 2: Pull Oracle Staleness
Pull oracles do not push updates automatically; if no one pays to update the price, the on-chain state becomes stale. The protocol reads from on-chain oracle storage without ensuring a recent update has been pushed.

**Vulnerable:**
```move
// VULNERABLE: reads potentially stale pull oracle
public fun borrow(oracle: &PriceOracle, amount: u64) {
    let price = pyth::get_price(oracle); // Could be days old
    let collateral_value = user_collateral * price.price;
    assert!(collateral_value >= amount * MIN_RATIO, E_UNDERCOLLATERALIZED);
}
```

**Fixed:**
```move
// FIXED: require fresh update in same tx
public fun borrow(
    oracle: &mut PriceOracle,
    update_data: vector<u8>,
    clock: &Clock,
    amount: u64
) {
    pyth::update_price_feed(oracle, update_data);
    let price = pyth::get_price(oracle);
    assert!(clock::timestamp_ms(clock) - price.publish_time < MAX_AGE, E_STALE);
    let collateral_value = user_collateral * price.price;
    assert!(collateral_value >= amount * MIN_RATIO, E_UNDERCOLLATERALIZED);
}
```

#### Pattern 3: Oracle Timestamp Underflow from Clock Drift
The code assumes the current system time is always greater than or equal to the oracle's reported timestamp. In distributed systems, an oracle might report a timestamp slightly in the future, causing arithmetic underflow.

**Vulnerable:**
```move
// VULNERABLE: underflow if oracle timestamp is in the future
public fun check_freshness(oracle_ts: u64, clock: &Clock): bool {
    let age = clock::timestamp_ms(clock) - oracle_ts; // UNDERFLOW if oracle_ts > now
    age < MAX_AGE
}
```

**Fixed:**
```move
// FIXED: saturating subtraction
public fun check_freshness(oracle_ts: u64, clock: &Clock): bool {
    let now = clock::timestamp_ms(clock);
    if (oracle_ts > now) { return true }; // Future timestamp = fresh
    let age = now - oracle_ts;
    age < MAX_AGE
}
```

### Remediation
Enforce strict heartbeat checks by comparing oracle timestamps with current transaction timestamps. Require fresh updates in the same transaction for pull-based oracles. Use saturating subtraction for timestamp arithmetic.

### Signature
**Slug:** `oracle-freshness-invariant`
**Detect:** For every oracle consumption: (1) verify timestamp freshness is checked against a maximum age, (2) verify pull oracles require fresh updates before consumption, (3) verify timestamp subtraction handles future-dated oracle timestamps.
**What's Wrong:** Oracle data is consumed without temporal validation, allowing stale prices, pull oracle staleness, or timestamp underflow.
**Remediation:** Enforce freshness checks, require in-transaction updates for pull oracles, and use saturating subtraction.

---

## CL-ORACLE-05: Price Source Validation

**Rule:** `MOVE-ORACLE-PRICE-01`
**Severity:** Medium-Critical

### Description
Protocols derive asset prices from unreliable, manipulable, or static sources instead of validated oracle feeds. Spot prices, hardcoded pegs, and stableswap curves without depeg protection all create exploitable pricing.

### Patterns

#### Pattern 1: Spot Price / Reserve Ratio as Oracle
Instantaneous reserve ratios and spot prices are easily manipulated within a single transaction via flash loans or large swaps, affecting all downstream calculations.

**Vulnerable:**
```move
// VULNERABLE: instantaneous spot price from reserves
public fun get_price(pool: &Pool): u64 {
    let (res_a, res_b) = get_reserves(pool);
    res_a / res_b // Manipulable via flash loan
}
```

**Fixed:**
```move
// FIXED: use external oracle
public fun get_price(oracle: &PriceOracle, clock: &Clock): u64 {
    let price_info = pyth::get_price(oracle);
    assert!(clock::timestamp_ms(clock) - price_info.timestamp < MAX_AGE, E_STALE);
    price_info.price
}
```

#### Pattern 2: Hardcoded Stablecoin Price Peg
Using a fixed constant value (e.g., 1.0) for an asset's price instead of querying a dynamic oracle feed. Stablecoins can and do depeg.

**Vulnerable:**
```move
// VULNERABLE: hardcoded price
public fun get_stablecoin_price(): u64 {
    1_000_000 // Assumes USDC is always $1.00
}
```

**Fixed:**
```move
// FIXED: dynamic oracle lookup
public fun get_stablecoin_price(oracle: &PriceOracle): u64 {
    let price = oracle::get_price<USDC>(oracle);
    assert!(price > 0, E_INVALID_PRICE);
    price
}
```

#### Pattern 3: Stableswap Invariant Without Depeg Protection
The stableswap formula flattens the curve near 1:1. If an asset depegs, the pool becomes a cheap exit for the failing asset, draining the healthy asset. No oracle circuit breaker detects this.

**Vulnerable:**
```move
// VULNERABLE: no depeg check
public fun swap(pool: &mut StablePool, amount_in: u64): u64 {
    let out = calculate_stableswap_output(pool, amount_in);
    // No oracle check -- if asset depegs, pool is drained
    transfer_out(pool, out)
}
```

**Fixed:**
```move
// FIXED: oracle circuit breaker
public fun swap(pool: &mut StablePool, oracle: &PriceOracle, amount_in: u64): u64 {
    let price_ratio = oracle::get_ratio(oracle, pool.coin_a, pool.coin_b);
    assert!(price_ratio > MIN_PEG_RATIO && price_ratio < MAX_PEG_RATIO, E_DEPEG);
    calculate_stableswap_output(pool, amount_in)
}
```

### Remediation
Use TWAP or integrate decentralized oracles (Pyth, Switchboard) with proper validation. Never rely on instantaneous pool state for security-critical pricing. Use dynamic oracle feeds for stablecoins. Add depeg circuit breakers for stableswap pools.

### Signature
**Slug:** `price-source-validation-invariant`
**Detect:** For every price source: (1) verify valuations do not use instantaneous reserve ratios or spot prices, (2) verify stablecoin prices are not hardcoded, (3) verify stableswap pools have oracle-based depeg detection.
**What's Wrong:** Price sources are manipulable (spot prices), static (hardcoded pegs), or unprotected (stableswap without depeg detection).
**Remediation:** Use external manipulation-resistant oracles, dynamic stablecoin pricing, and depeg circuit breakers.
