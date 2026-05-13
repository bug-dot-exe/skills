# CAT-ORACLE: Oracle

**Context:** `ctx:oracle`
**Detectors:** 5

## CL-ORACLE-01: Oracle Administration Invariant

**Rule:** `MOVE-ORACLE-ADMIN-01`
**Severity:** low-medium

This invariant detector covers five patterns where oracle configuration, initialization, and administrative controls are insufficient to maintain protocol integrity.

---

## Pattern 1: Oracle Centralization and Single Point of Failure

### Precondition
The protocol relies on a single, internally managed oracle module or account for price feeds.

### Root Cause
Price data is sourced from a single-signer account or a centralized module without multi-signature requirements or decentralized fallback mechanisms. A compromise of this entity's credentials allows total control over price-dependent logic.

### Impact
Single key compromise enables arbitrary price manipulation across the entire protocol.

### Remediation
Implement a multi-signature requirement for oracle updates, integrate decentralized oracles (Pyth, Switchboard), or use a medianizer from multiple sources.

### Code Example
```move
// VULNERABLE: single admin controls all prices
public fun set_price(admin: &signer, asset: u8, price: u64) {
    assert!(signer::address_of(admin) == @oracle_admin, E_UNAUTHORIZED);
    let store = borrow_global_mut<PriceStore>(@oracle);
    *table::borrow_mut(&mut store.prices, asset) = price;
}

// FIXED: multi-source with threshold
public fun set_price(
    signers: &vector<address>,
    signatures: &vector<vector<u8>>,
    asset: u8,
    price: u64
) {
    let valid = verify_multisig(signers, signatures, MIN_SIGNERS);
    assert!(valid, E_INSUFFICIENT_SIGNATURES);
    let store = borrow_global_mut<PriceStore>(@oracle);
    *table::borrow_mut(&mut store.prices, asset) = price;
}
```

### Signature
**Slug:** `oracle-centralization->price-manipulation`
**Detect:** Check if oracle price updates are restricted to a single administrative capability or account without multi-sig or decentralized validation.
**What's Wrong:** The protocol's price feed depends on a single trusted entity. A compromise of this entity's credentials allows total control over price-dependent logic.

---

## Pattern 2: Unvalidated Oracle Price Update Bypasses Limits

### Precondition
The protocol implements a rate-limiter or safety cap based on the notional value of assets calculated via an internal price registry.

### Root Cause
The administrative function used to update asset prices lacks sanity checks or bounds validation. If an artificially low price is set, value-based security constraints are effectively neutralized.

### Impact
Rate limits, safety caps, and value-based security measures become mathematically irrelevant when prices are set to near-zero.

### Remediation
Implement sanity checks on price updates, such as maximum percentage deviations from previous prices, or cross-reference with an external secondary oracle before updating the internal registry.

### Code Example
```move
// VULNERABLE: no bounds on price update
public fun update_asset_price(admin: &AdminCap, registry: &mut PriceRegistry, asset: u8, price: u64) {
    table::upsert(&mut registry.prices, asset, price);
    // No check: price could be 1 wei, making rate limits useless
}

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

### Signature
**Slug:** `unvalidated-price-update->limit-bypass`
**Detect:** Search for functions that update internal price registries or notional values. Check if the input parameters are validated against zero, extreme values, or significant deviations from the current state.
**What's Wrong:** Asset prices used for security calculations can be set to arbitrarily low values, making rate limits and safety caps mathematically irrelevant.

---

## Pattern 3: Immutable Oracle Configuration Parameters

### Precondition
Protocol uses configurable oracle parameters (e.g., max deviation) stored in a resource.

### Root Cause
The setter functions for oracle configurations lack the logic to update existing parameters, requiring a full removal and re-addition of the oracle to change settings. This creates operational risk and potential downtime.

### Impact
Oracle parameters cannot be adjusted without destructive actions, preventing timely response to changing market conditions.

### Remediation
Implement update logic in setter functions to allow modification of existing oracle configuration fields without unsetting the oracle.

### Code Example
```move
// VULNERABLE: can only set, not update
public fun set_oracle(admin: &AdminCap, config: &mut OracleConfig, oracle_addr: address, max_dev: u64) {
    assert!(!option::is_some(&config.oracle), E_ALREADY_SET);
    config.oracle = option::some(OracleInfo { addr: oracle_addr, max_deviation: max_dev });
}

// FIXED: allow updates
public fun set_oracle(admin: &AdminCap, config: &mut OracleConfig, oracle_addr: address, max_dev: u64) {
    config.oracle = option::some(OracleInfo { addr: oracle_addr, max_deviation: max_dev });
    event::emit(OracleUpdated { addr: oracle_addr, max_deviation: max_dev });
}
```

### Signature
**Slug:** `immutable-config->operational-rigidity`
**Detect:** Check if oracle setter functions handle the case where the oracle is already initialized and allow updating fields like max_deviation.
**What's Wrong:** Oracle parameters are hardcoded or only settable once, preventing adjustments to risk parameters without destructive actions.

---

## Classification Reasoning
These three patterns share the root cause of insufficient administrative controls around oracle configuration and updates. Whether it is centralized control, missing bounds on updates, or immutable configs, the invariant is: every oracle administrative operation must enforce proper access control, input validation, and updateability. Absorbs move-oracle-0011, 0013, 0020.

---

## CL-ORACLE-02: Oracle Aggregation Integrity Invariant

**Rule:** `MOVE-ORACLE-AGG-01`
**Severity:** medium-high

This invariant detector covers five patterns where oracle data aggregation or consensus mechanisms can be subverted through input manipulation, non-determinism, or flawed comparison logic.

---

## Pattern 1: Duplicate Data Feed ID Injection

### Precondition
The protocol processes signed data packages containing multiple data feeds and aggregates them (e.g., via median) without checking for duplicate identifiers within the same package.

### Root Cause
Lack of uniqueness validation for feed IDs allows a single data source to provide multiple values for the same identifier, bypassing the security assumptions of median-based aggregation.

### Impact
A single signer can skew the resulting aggregate (median/average) beyond the intended weight of a single signature.

### Remediation
Implement a uniqueness check for feed IDs during payload processing. Use a temporary set or sort the IDs to ensure each feed ID is processed exactly once per data package.

### Code Example
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

// FIXED: enforce uniqueness
public fun aggregate_feeds(feeds: &vector<DataFeed>): u64 {
    let seen = vector::empty<vector<u8>>();
    let prices = vector::empty<u64>();
    let i = 0;
    while (i < vector::length(feeds)) {
        let feed = vector::borrow(feeds, i);
        assert!(!vector::contains(&seen, &feed.id), E_DUPLICATE_FEED);
        vector::push_back(&mut seen, feed.id);
        vector::push_back(&mut prices, feed.price);
        i = i + 1;
    };
    median(&prices)
}
```

### Signature
**Slug:** `duplicate-feed-id->oracle-manipulation`
**Detect:** Search for loops processing signed data packages or oracle feeds where the feed identifier is used to update state or contribute to an aggregate without a uniqueness check.
**What's Wrong:** Lack of uniqueness validation for feed IDs allows a single data source to provide multiple values for the same identifier, bypassing median-based aggregation security.

---

## Pattern 2: Non-Deterministic Oracle Selection

### Precondition
The protocol allows callers to provide or select a subset of available oracle feeds to satisfy a weight/threshold requirement.

### Root Cause
The system does not enforce a canonical or deterministic selection of price feeds when multiple valid subsets exist, allowing users to choose the most favorable price within a valid range.

### Impact
Users cherry-pick the highest or lowest valid price subset to maximize their profit from each oracle query.

### Remediation
Enforce a deterministic selection algorithm (e.g., always use all available valid feeds or a sorted subset) or use a median/aggregate of all valid feeds rather than allowing user-defined subsets.

### Code Example
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

// FIXED: use all valid feeds deterministically
public fun get_price(feeds: &vector<PriceFeed>): u64 {
    let prices = vector::empty<u64>();
    let i = 0;
    while (i < vector::length(feeds)) {
        let feed = vector::borrow(feeds, i);
        if (is_fresh(feed, timestamp::now_seconds())) {
            vector::push_back(&mut prices, feed.price);
        };
        i = i + 1;
    };
    assert!(vector::length(&prices) >= MIN_FEEDS, E_INSUFFICIENT);
    median(&prices)
}
```

### Signature
**Slug:** `user-selected-oracle-subset->price-manipulation`
**Detect:** Check if oracle aggregation functions accept a user-defined list of feeds and if different valid subsets of those feeds can result in different price outputs.
**What's Wrong:** Allowing users to choose which oracles are used enables them to cherry-pick the highest or lowest valid prices.

---

## Classification Reasoning
These two patterns share the root cause of flawed oracle aggregation or consensus logic. Whether it is duplicate feed injection or user-selected subsets, the invariant is: oracle aggregation must enforce input uniqueness and deterministic selection. Absorbs move-oracle-0002, 0015.

---

## CL-ORACLE-03: Oracle DeFi Integration Invariant

**Rule:** `MOVE-ORACLE-DEFI-01`
**Severity:** medium-critical

## Description
Beyond basic oracle validation (freshness, sanitization, aggregation covered by existing detectors), DeFi protocols face integration-specific oracle risks: flash loan price manipulation, missing circuit breakers on deviation, depeg events for wrapped/pegged assets, price direction confusion (A/B vs B/A), and using on-chain spot prices as slippage references. These integration failures enable atomic value extraction, incorrect valuations, and bypassed slippage protection.

## Patterns

### Pattern 1: Flash Loan Price Manipulation
Protocol uses spot pool price or reserve ratio for valuation. Attacker calls flash loan entry function, manipulates pool price, executes at the manipulated price, and repays -- all atomically within a single entry function scope.

**Vulnerable:**
```move
public fun get_token_value(pool_addr: address, amount: u64): u64 acquires Pool {
    // Uses instantaneous pool reserves as price -- manipulable via flash loan
    let pool_ref = borrow_global<Pool>(pool_addr);
    let (reserve_a, reserve_b) = get_reserves(pool_ref);
    amount * reserve_b / reserve_a
}

public fun borrow_against_collateral(
    account: &signer, pool_addr: address, collateral: Coin<TokenA>
) acquires Pool, LendingPool {
    let value = get_token_value(pool_addr, coin::value(&collateral));
    // Attacker inflates pool price, borrows against inflated value
    let lending = borrow_global_mut<LendingPool>(@lending_addr);
    issue_loan(lending, value);
}
```

**Fixed:**
```move
public fun get_token_value_safe(
    oracle_addr: address, amount: u64
): u64 acquires PriceInfoObject {
    let oracle = borrow_global<PriceInfoObject>(oracle_addr);
    let price = pyth::price_info::get_price(oracle);
    assert!(
        timestamp::now_seconds() - pyth::price::get_publish_time(&price) < 60,
        E_STALE_PRICE
    );
    let raw = pyth::price::get_price(&price);
    assert!(raw > 0, E_INVALID_PRICE);
    ((amount as u128) * (raw as u128) / (PRECISION as u128) as u64)
}
```

### Pattern 2: Circuit Breaker Missing
No deviation check between consecutive oracle updates. A sudden 50x spike triggers mass liquidations or unbounded borrowing immediately without any safety pause.

**Vulnerable:**
```move
struct PriceState has key { current_price: u64 }

public fun update_price(admin: &signer, price_info_addr: address) acquires PriceState, PriceInfoObject {
    let price_info = borrow_global<PriceInfoObject>(price_info_addr);
    // Blindly accepts any price, even 100x jumps
    let state = borrow_global_mut<PriceState>(signer::address_of(admin));
    state.current_price = (pyth::price::get_price(
        &pyth::price_info::get_price(price_info)) as u64);
}
```

**Fixed:**
```move
const MAX_DEV_BPS: u64 = 1500; // 15% max deviation
const BPS: u64 = 10000;

struct PriceState has key { current_price: u64, is_paused: bool }

public fun update_price_safe(
    admin: &signer, price_info_addr: address
) acquires PriceState, PriceInfoObject {
    let state = borrow_global_mut<PriceState>(signer::address_of(admin));
    assert!(!state.is_paused, E_CIRCUIT_BREAKER);
    let price_info = borrow_global<PriceInfoObject>(price_info_addr);
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

### Pattern 3: Depeg Events Not Handled
Protocol assumes wrapped/pegged asset equals underlying (wBTC=BTC, USDC=$1). Depeg breaks this assumption, causing incorrect valuations and exploitable arbitrage opportunities.

**Vulnerable:**
```move
public fun wbtc_collateral_value(
    wbtc_amount: u64, btc_usd_info_addr: address
): u64 acquires PriceInfoObject {
    let btc_usd_info = borrow_global<PriceInfoObject>(btc_usd_info_addr);
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
    wbtc_usd_info_addr: address,
    btc_usd_info_addr: address,
): u64 acquires PriceInfoObject {
    let wbtc_usd_info = borrow_global<PriceInfoObject>(wbtc_usd_info_addr);
    let wbtc_usd = (pyth::price::get_price(
        &pyth::price_info::get_price(wbtc_usd_info)) as u64);
    let btc_usd_info = borrow_global<PriceInfoObject>(btc_usd_info_addr);
    let btc_usd = (pyth::price::get_price(
        &pyth::price_info::get_price(btc_usd_info)) as u64);
    let ratio_bps = wbtc_usd * 10000 / btc_usd;
    let dev = if (ratio_bps > 10000) { ratio_bps - 10000 } else { 10000 - ratio_bps };
    assert!(dev <= MAX_DEPEG_BPS, E_DEPEG_DETECTED);
    wbtc_amount * wbtc_usd
}
```

### Pattern 4: Price Direction Confusion (A/B vs B/A)
Using TOKEN_A/TOKEN_B price where TOKEN_B/TOKEN_A was needed. If BTC/USD = 50000, accidentally using USD/BTC produces values off by a factor of price-squared, enabling massive over/under-valuation.

**Vulnerable:**
```move
public fun eth_needed_for_usd(
    usd_amount: u64, eth_usd_info_addr: address
): u64 acquires PriceInfoObject {
    let eth_usd_info = borrow_global<PriceInfoObject>(eth_usd_info_addr);
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
    usd_amount: u64, eth_usd_price_info_addr: address
): u64 acquires PriceInfoObject {
    let eth_usd_price_info = borrow_global<PriceInfoObject>(eth_usd_price_info_addr);
    let price = pyth::price_info::get_price(eth_usd_price_info);
    let usd_per_eth = (pyth::price::get_price(&price) as u64);
    assert!(usd_per_eth > 0, E_NEGATIVE_PRICE);
    // Divide to go USD -> ETH (price is USD-per-ETH)
    usd_amount * PRECISION / usd_per_eth
}
```

### Pattern 5: On-Chain Price as Slippage Reference
Calculating `min_amount_out` from the same pool state that will execute the swap. An attacker manipulates pool state first, then the slippage calculation reflects the manipulated state, providing zero protection.

**Vulnerable:**
```move
public fun swap_with_auto_slippage<A, B>(
    account: &signer, coin_in: Coin<A>
) acquires Pool {
    let pool = borrow_global_mut<Pool<A, B>>(@pool_addr);
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
    account: &signer,
    pool_addr: address,
    coin_in: Coin<A>,
    min_amount_out: u64, // Calculated off-chain from TWAP or external oracle
) acquires Pool {
    let pool = borrow_global_mut<Pool<A, B>>(pool_addr);
    let out = do_swap(pool, coin_in);
    assert!(coin::value(&out) >= min_amount_out, E_SLIPPAGE);
    coin::deposit(signer::address_of(account), out);
}
```

## Remediation
Use external validated oracles (Pyth, Switchboard) instead of spot pool prices for valuations. Implement circuit breakers that pause on abnormal price deviations. Use dedicated price feeds for wrapped/pegged assets with depeg detection. Document and verify price direction at every oracle integration point. Require user-supplied slippage parameters calculated off-chain rather than derived from on-chain pool state.

---

## CL-ORACLE-04: Oracle Freshness Invariant

**Rule:** `MOVE-ORACLE-FRESH-01`
**Severity:** low-high

This invariant detector covers five patterns where protocols consume oracle data without ensuring it reflects current market conditions.

---

## Pattern 1: Missing Timestamp Freshness Check

### Precondition
The protocol relies on an external oracle (Pyth, Switchboard, Chainlink) for asset valuation without enforcing a freshness threshold on the returned data.

### Root Cause
The contract retrieves price data from an oracle but fails to compare the data's timestamp against the current block/system time to ensure it falls within an acceptable maximum interval.

### Impact
Stale prices enable market manipulation, unfair liquidations, or incorrect collateral valuations during network congestion or oracle downtime.

### Remediation
Enforce a strict heartbeat check by comparing the oracle's last update timestamp with the current transaction timestamp in every oracle-consuming function.

### Code Example
```move
// VULNERABLE: no timestamp check
public fun get_price(oracle_addr: address): u64 acquires PriceOracle {
    let oracle = borrow_global<PriceOracle>(oracle_addr);
    let price_info = pyth::get_price(oracle);
    price_info.price // Could be hours old
}

// FIXED: freshness validation
public fun get_price(oracle_addr: address): u64 acquires PriceOracle {
    let oracle = borrow_global<PriceOracle>(oracle_addr);
    let price_info = pyth::get_price(oracle);
    let age = timestamp::now_seconds() - price_info.publish_time;
    assert!(age <= MAX_PRICE_AGE_SECS, E_STALE_PRICE);
    price_info.price
}
```

### Signature
**Slug:** `missing-timestamp-validation->stale-price-usage`
**Detect:** Search for all functions calling oracle read methods. Verify if the returned timestamp is checked against the current system clock using a maximum age threshold.
**What's Wrong:** The protocol accepts price data regardless of when it was last updated, making it vulnerable to stale state during network congestion or oracle downtime.

---

## Pattern 2: Pull Oracle Staleness

### Precondition
Protocol relies on an external pull-based oracle (like Pyth) where price updates must be triggered by users or relayers.

### Root Cause
Pull oracles do not push updates automatically; if no one pays to update the price, the on-chain state becomes stale. The protocol reads from on-chain oracle storage without ensuring a recent update has been pushed.

### Impact
Operations proceed with outdated prices, causing incorrect liquidations, collateral miscalculations, or DoS if the protocol reverts on stale data without fallback.

### Remediation
Implement a check for price freshness (timestamp validation) and provide a mechanism to update the price feed within the same transaction or via a dedicated relayer before consumption.

### Code Example
```move
// VULNERABLE: reads potentially stale pull oracle
public fun borrow(account: &signer, oracle_addr: address, amount: u64) acquires PriceOracle {
    let oracle = borrow_global<PriceOracle>(oracle_addr);
    let price = pyth::get_price(oracle); // Could be days old
    let collateral_value = user_collateral * price.price;
    assert!(collateral_value >= amount * MIN_RATIO, E_UNDERCOLLATERALIZED);
}

// FIXED: require fresh update in same tx
public fun borrow(
    account: &signer,
    oracle_addr: address,
    update_data: vector<u8>,
    amount: u64
) acquires PriceOracle {
    let oracle = borrow_global_mut<PriceOracle>(oracle_addr);
    pyth::update_price_feed(oracle, update_data);
    let price = pyth::get_price(oracle);
    assert!(timestamp::now_seconds() - price.publish_time < MAX_AGE, E_STALE);
    let collateral_value = user_collateral * price.price;
    assert!(collateral_value >= amount * MIN_RATIO, E_UNDERCOLLATERALIZED);
}
```

### Signature
**Slug:** `pull-oracle-staleness->oracle-dos`
**Detect:** Check if the protocol consumes pull-based oracle data without validating the timestamp of the last update or requiring a fresh update in the call flow.
**What's Wrong:** Pull oracles do not push updates automatically. Without freshness enforcement, on-chain state can be arbitrarily stale.

---

## Pattern 3: Oracle Timestamp Underflow from Clock Drift

### Precondition
The protocol calculates the age of an oracle price by subtracting the oracle's reported timestamp from the current block/system timestamp.

### Root Cause
The code assumes the current system time is always greater than or equal to the oracle's reported timestamp. In distributed systems, an oracle might report a timestamp slightly in the future relative to the local node, causing arithmetic underflow.

### Impact
Transaction failure (abort) from arithmetic underflow, causing DoS for price-dependent operations.

### Remediation
Use a saturating subtraction or a conditional check to treat future-dated timestamps as having an age of zero, or allow for a small tolerance window.

### Code Example
```move
// VULNERABLE: underflow if oracle timestamp is in the future
public fun check_freshness(oracle_ts: u64): bool {
    let age = timestamp::now_seconds() - oracle_ts; // UNDERFLOW if oracle_ts > now
    age < MAX_AGE
}

// FIXED: saturating subtraction
public fun check_freshness(oracle_ts: u64): bool {
    let now = timestamp::now_seconds();
    if (oracle_ts > now) { return true }; // Future timestamp = fresh
    let age = now - oracle_ts;
    age < MAX_AGE
}
```

### Signature
**Slug:** `future-oracle-timestamp->underflow-dos`
**Detect:** Search for subtractions where the current block/ledger timestamp is the minuend and an external oracle-provided timestamp is the subtrahend without a safety check.
**What's Wrong:** Arithmetic underflow occurs if the oracle timestamp is ahead of the system clock, leading to transaction failure.

---

## Classification Reasoning
These three patterns are unified by the root cause of consuming oracle data without ensuring temporal validity. Whether the protocol skips timestamp checks, ignores pull-oracle staleness, or underflows on future timestamps, the invariant is the same: every oracle price consumed must be validated for freshness before use. Absorbs move-oracle-0004, 0018, 0026.

---

## CL-ORACLE-05: Price Source Validation Invariant

**Rule:** `MOVE-ORACLE-PRICE-01`
**Severity:** medium-critical

This invariant detector covers five patterns where protocols derive asset prices from unreliable, manipulable, or static sources instead of validated oracle feeds.

---

## Pattern 1: Spot Price / Reserve Ratio as Oracle

### Precondition
Protocol derives asset prices, position values, or fee calculations from instantaneous pool state (reserve ratios, spot price, or current swap output) without time-weighted averaging or external oracle verification.

### Root Cause
Instantaneous reserve ratios and spot prices are easily manipulated within a single transaction via flash loans or large swaps, affecting all downstream calculations that depend on them.

### Impact
Attacker manipulates prices to drain funds, inflate/deflate position values, bypass collateral checks, or extract excess value from the protocol.

### Remediation
Use TWAP or integrate a decentralized oracle (Pyth, Switchboard) with proper validation. Never rely on instantaneous pool state for security-critical pricing.

### Code Example
```move
// VULNERABLE: instantaneous spot price from reserves
public fun get_price(pool: &Pool): u64 {
    let (res_a, res_b) = get_reserves(pool);
    res_a / res_b // Manipulable via flash loan
}

// FIXED: use external oracle
public fun get_price(oracle_addr: address): u64 acquires PriceOracle {
    let oracle = borrow_global<PriceOracle>(oracle_addr);
    let price_info = pyth::get_price(oracle);
    assert!(timestamp::now_seconds() - price_info.timestamp < MAX_AGE, E_STALE);
    price_info.price
}
```

### Signature
**Slug:** `spot-price-ratio->fund-drain`
**Detect:** Check if pricing, valuation, or fee logic relies on current reserve balances, instantaneous pool prices, or get_reserves calls without time-weighting or external oracle verification.
**What's Wrong:** Instantaneous reserve ratios and spot prices are easily manipulated within a single transaction via flash loans or large swaps.

---

## Pattern 2: Hardcoded Stablecoin Price Peg

### Precondition
Protocol assumes a 1:1 peg for a stablecoin without real-time market data.

### Root Cause
Using a fixed constant value (e.g., 1.0) for an asset's price instead of querying a dynamic oracle feed. Stablecoins can and do depeg.

### Impact
Users exploit the difference between protocol price and market price to extract value during depeg events.

### Remediation
Integrate a decentralized oracle (Pyth, Switchboard) to fetch the actual market price of the stablecoin.

### Code Example
```move
// VULNERABLE: hardcoded price
public fun get_stablecoin_price(): u64 {
    1_000_000 // Assumes USDC is always $1.00
}

// FIXED: dynamic oracle lookup
public fun get_stablecoin_price(oracle: &PriceOracle): u64 {
    let price = oracle::get_price<USDC>(oracle);
    assert!(price > 0, E_INVALID_PRICE);
    price
}
```

### Signature
**Slug:** `hardcoded-peg->price-misalignment`
**Detect:** Search for hardcoded price constants or logic that returns a fixed value for specific coin types in oracle or valuation modules.
**What's Wrong:** Stablecoins can depeg; assuming a fixed price allows users to exploit the difference between the protocol price and market price.

---

## Pattern 3: Stableswap Invariant Without Depeg Protection

### Precondition
Protocol uses an amplified invariant (Stableswap/Curve-like) for assets assumed to be 1:1 without external price validation.

### Root Cause
The stableswap formula flattens the curve near 1:1. If an asset depegs, the pool becomes a cheap exit for the failing asset, draining the healthy asset. No oracle circuit breaker detects this.

### Impact
Healthy asset drained from the pool as arbitrageurs exploit the flat pricing curve during a depeg event.

### Remediation
Integrate price oracles to detect depegs. If the oracle price deviates beyond a threshold, pause swaps or adjust the invariant to reflect market prices.

### Code Example
```move
// VULNERABLE: no depeg check
public fun swap(pool: &mut StablePool, amount_in: u64): u64 {
    let out = calculate_stableswap_output(pool, amount_in);
    // No oracle check — if asset depegs, pool is drained
    transfer_out(pool, out)
}

// FIXED: oracle circuit breaker
public fun swap(pool: &mut StablePool, oracle: &PriceOracle, amount_in: u64): u64 {
    let price_ratio = oracle::get_ratio(oracle, pool.coin_a, pool.coin_b);
    assert!(price_ratio > MIN_PEG_RATIO && price_ratio < MAX_PEG_RATIO, E_DEPEG);
    calculate_stableswap_output(pool, amount_in)
}
```

### Signature
**Slug:** `stableswap-missing-oracle->arbitrage-drain`
**Detect:** Check if DEX pools using amplified invariants (Curve-like) lack external oracle checks or circuit breakers for asset depegging.
**What's Wrong:** The stableswap formula flattens the curve near 1:1 parity. Without oracle validation, a depeg event causes one-sided drainage.

---

## Classification Reasoning
These three patterns are unified by the root cause of using an unreliable, manipulable, or static price source for protocol-critical decisions. Whether the price comes from instantaneous reserves, a hardcoded constant, or a stableswap curve without depeg detection, the invariant is the same: every price source consumed by the protocol must be validated for accuracy and manipulation resistance. Absorbs move-oracle-0001, 0003, 0009.

---
