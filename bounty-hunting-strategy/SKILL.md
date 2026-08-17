---
name: bounty-hunting-strategy
category: methodology
description: Bug bounty hunting strategy covering target-type threat profiling, program intelligence gathering, impact-based severity classification, asset prioritization by value-at-risk and reward, attack surface mapping by application category, and submission optimization for maximum acceptance rate
depends_on: []
---

# Bug Bounty Hunting Strategy

Systematic methodology for bug bounty hunting across any platform. Covers target-type threat profiling, program intelligence, severity classification by impact, asset prioritization, systematic attack surface mapping per application category, and submission optimization.

## When to Use

- Hunting on any bug bounty program
- Deciding which program to target next
- Mapping attack surface for a new target by application type
- Writing a submission to maximize acceptance rate
- Assessing whether a finding meets the program's impact-based severity threshold
- Prioritizing between multiple programs based on value-at-risk and reward

## Methodology

### 1. Target-Type Threat Profiles

For each application category, the top attack vectors ranked by historical exploit frequency. Load the relevant profile immediately after identifying the target type.

The profiles below use web3/protocol examples because they represent the highest-density public exploit data. Apply the same structural analysis patterns (state mutation tracing, access control mapping, external dependency auditing, race condition probing, value flow verification) to ANY target type.

#### State-Tracking Applications (balance/ledger systems)

| Rank | Attack Vector | Mechanism | Historical Examples |
|------|--------------|-----------|-------------------|
| 1 | External data source manipulation leading to incorrect state transitions | Manipulate a data feed to make valid state appear invalid, triggering incorrect state changes or preventing valid ones | Euler ($197M), Mango Markets ($117M) |
| 2 | Temporary resource inflation for unauthorized borrowing power | Temporarily inflate collateral/balance via borrowed resources, extract maximum value, default on the temporary resource leaving the system with bad debt | Cream Finance ($130M), bZx ($8M) |
| 3 | Rate/interest model manipulation | Exploit utilization or rate calculations to force extreme rates; manipulate rate curves to extract value from existing participants | Rate model edge cases across protocols |
| 4 | State transition logic errors | Self-triggered adverse transitions for profit, loss socialization failures, bonus exceeding collateral value, race conditions between competing state changes | Various liquidation/settlement events |
| 5 | First-user / empty-state share inflation | Interact with empty state to manipulate share pricing, causing subsequent users to receive zero shares due to rounding | Share-based vault implementations |

Key patterns to analyze: state transition functions, external data lookups, rate calculations, health/validity checks, interest accrual, collateral factor computations.

#### Exchange/Swap Applications (value conversion systems)

| Rank | Attack Vector | Mechanism | Historical Examples |
|------|--------------|-----------|-------------------|
| 1 | Price manipulation via low-liquidity state | Move price in a thin pool used as a reference by another system; profit from the downstream effect | Numerous dependent protocols |
| 2 | Front-running on unprotected conversions | Front-run user conversion to move price, user gets worse rate, back-run to capture profit; targets missing slippage protection or deadline checks | Pervasive across conversion systems |
| 3 | Share/receipt token mispricing | Manipulate reserves to inflate/deflate receipt token value used for pricing elsewhere; donate-to-pool attacks | Warp Finance ($7.7M) |
| 4 | Range/boundary manipulation | Exploit boundary math, position accounting across ranges, fee calculation errors at range edges | Tick math edge cases in concentrated liquidity |
| 5 | Fee accounting errors across boundaries | Fees not properly accumulated when positions span multiple boundaries; global vs per-boundary desync | Concentrated position protocols |

Key patterns to analyze: swap/conversion functions, reserve queries, price calculation slots, boundary/tick math, fee growth tracking, slippage parameters, deadline checks.

#### Vault/Aggregator Applications (pooled value systems)

| Rank | Attack Vector | Mechanism | Historical Examples |
|------|--------------|-----------|-------------------|
| 1 | First depositor inflation attack | First deposit of minimal amount, donate large amount directly to vault, inflated share price causes next depositor to receive zero shares via rounding | Widespread across share-based implementations |
| 2 | Share calculation rounding errors | Rounding in shares-to-assets conversion consistently favors attacker direction; accumulates over many deposit/withdraw cycles | Multiple vault protocols |
| 3 | Strategy loss not properly socialized | Strategy reports loss but accounting does not proportionally reduce all share values; last withdrawer bears disproportionate loss | Strategy loss events |
| 4 | Donation attacks on balance-based accounting | Direct value transfer to contract inflates total assets without minting shares; distorts share price for subsequent operations | Any vault using balance-of-self for accounting |
| 5 | Harvest/compound sandwich attacks | Front-run yield distribution transaction; deposit before yield is added, withdraw after yield is distributed | Yield aggregator harvest timing attacks |

Key patterns to analyze: deposit/withdraw/redeem functions, share conversion functions, total assets/total supply queries, harvest/earn functions, balance-of-self accounting.

#### Cross-System Bridge Applications (message/value relay systems)

| Rank | Attack Vector | Mechanism | Historical Examples |
|------|--------------|-----------|-------------------|
| 1 | Message replay across systems | Replay a valid message on a different target system or replay the same message multiple times to double-credit | Wormhole ($326M), Ronin ($624M) |
| 2 | Source system spoofing | Forge or manipulate the source identifier to make the destination believe a message came from a trusted source | Nomad ($190M) |
| 3 | Relayer/validator manipulation | Compromise or manipulate the relay/validator set to forge attestations or withhold messages; bribe validators below economic security threshold | Various bridge exploits |
| 4 | Accounting desync (credit without debit) | Credit on destination without corresponding debit/lock on source; exploit race condition or verification gap between systems | Multichain, Poly Network |
| 5 | Finality assumption violations | Submit proof from source before finality; source reorganizes after destination has already processed the message | Bridges with optimistic verification |

Key patterns to analyze: message receive functions, trusted source configuration, message ID/nonce tracking, source identifiers, payload handling.

#### Governance Applications (voting/proposal systems)

| Rank | Attack Vector | Mechanism | Historical Examples |
|------|--------------|-----------|-------------------|
| 1 | Temporary voting power inflation | Temporarily acquire voting power, vote on or create a malicious proposal within the same snapshot window | Beanstalk ($182M) |
| 2 | Quorum manipulation | Manipulate total supply or voting power calculations to artificially meet quorum thresholds with fewer votes than intended | Governance edge cases |
| 3 | Proposal collision/overwrite | Create proposal with same ID or that overwrites pending proposal; exploit proposal ID generation or queue slot collisions | Governance bugs |
| 4 | Timelock/delay bypass | Circumvent the delay mechanism through emergency functions, direct execution paths, or by manipulating the delay parameter itself | Various DAO exploits |
| 5 | Vote-transfer-vote | Vote, transfer voting power to another address, vote again within the same voting period when snapshots are not enforced | Snapshot-less governance |

Key patterns to analyze: propose/vote/execute functions, queue/timelock functions, quorum calculations, voting power delegation, proposal threshold, voting delay/period.

#### Staking/Reward Applications (time-locked value with yield)

| Rank | Attack Vector | Mechanism | Historical Examples |
|------|--------------|-----------|-------------------|
| 1 | Reward distribution timing attack | Deposit just before reward distribution, claim disproportionate share, withdraw immediately; exploit the gap between deposit time and reward snapshot | Multiple staking protocols |
| 2 | Slashing/penalty accounting errors | Penalty event reduces one participant's stake but accounting does not properly reduce all participants proportionally; some participants withdraw pre-penalty value | Penalty edge cases |
| 3 | Lock period bypass | Find a path to withdraw locked value without waiting for the required period; receipt token redemption shortcuts | Protocol-specific bypasses |
| 4 | Compounding errors | Compound function miscalculates accumulated rewards when restaking; rounding in reward-to-stake conversion accumulates | Restaking edge cases |
| 5 | Withdrawal queue exploitation | Manipulate queue ordering, claim priority, or exploit the queue state to skip ahead or block other withdrawals | Withdrawal queue implementations |

Key patterns to analyze: stake/unstake/withdraw functions, reward claiming, reward-per-token calculations, earned calculations, reward rate/period, lock period, restake functions.

#### Derivatives/Margin Applications (leveraged position systems)

| Rank | Attack Vector | Mechanism | Historical Examples |
|------|--------------|-----------|-------------------|
| 1 | Data feed manipulation for forced liquidation | Manipulate price data to trigger liquidations at incorrect prices; profit from the liquidation bonus or from acquiring positions cheaply | Oracle manipulation attempts across protocols |
| 2 | Funding/fee rate manipulation | Open large positions to skew rates, collect from counterparties, then close position | Perpetual protocol exploits |
| 3 | Position size exploitation | Exploit maximum position limits, leverage limits, or open interest caps to create outsized impact or drain insurance/reserve funds | Various derivatives protocols |
| 4 | Margin calculation errors | Incorrect margin requirement calculations allow under-collateralized positions; cross-margin vs isolated-margin accounting bugs | Derivatives platform bugs |
| 5 | Insurance/reserve fund drainage | Systematically create bad debt that the reserve fund must cover; deplete the fund then exploit unprotected positions | Various protocols |

Key patterns to analyze: position open/close functions, liquidation functions, margin/leverage calculations, funding rate, mark/index price, insurance fund, open interest, PnL calculations.

#### Liquid Receipt Applications (wrapped/receipt token systems)

| Rank | Attack Vector | Mechanism | Historical Examples |
|------|--------------|-----------|-------------------|
| 1 | Exchange rate manipulation | Manipulate the receipt-to-underlying exchange rate via donation, data feed delay, or reward timing to extract value on mint or redeem | Depeg events |
| 2 | Withdrawal queue exploitation | Exploit ordering, priority, or state transitions in the withdrawal queue to skip ahead, block others, or claim more than entitled | Withdrawal queue edge cases |
| 3 | Rebasing accounting in integrations | Integrating system uses cached balance instead of live balance for a rebasing asset; desync between actual and recorded amounts | Integration bugs across protocols |
| 4 | Operator set manipulation | Influence which operators are chosen, how stake is distributed, or how exits are processed to extract value or cause penalties for others | Operator selection logic |
| 5 | Reward skimming via sandwich | Front-run the data update or reward distribution that changes the exchange rate; mint before rate increase, redeem after | Rate update timing attacks |

Key patterns to analyze: submit/mint functions, withdrawal request/claim functions, share-to-underlying conversion functions, total underlying/total shares queries, data feed functions, rebase functions.

### 2. Program Intelligence

Before writing a single line of analysis, gather intelligence on the specific program.

**Scope analysis**:
- Read the program page carefully. Focus on "Impacts in Scope" not just "Assets in Scope" -- many programs classify by impact, and some impacts are explicitly out of scope even if the asset is in scope
- Identify the exact assets, versions, and deployment details that are in scope
- Note any known issues or previously accepted findings listed on the program page
- Check the program's verification/payout requirements and timeline

**Historical intelligence**:
- Check the program's previous payouts -- what severity level do they actually pay for? Some programs list high bounties but have never paid above a moderate level
- Read all prior audit/assessment reports for the target. Look for edge cases that were noted but not classified as findings, "acknowledged" issues that were not fixed, and areas explicitly flagged as out of scope
- Check the project's source repository for recent commits, open issues, security-related changes, and any discussions about known bugs or design trade-offs
- Search for disclosed reports on the same target or similar targets in the same category

**Known issue list**:
- Every finding must be checked against the program's known issue list before submission
- If the target has public audit reports, every finding in those reports is implicitly a known issue
- If the program page says "issues from Assessment X are known," treat the entire report as excluded

**Value-at-risk and economic context**:
- Assess the total value controlled by the target across all deployments
- Higher value-at-risk means higher potential impact, which directly affects severity and reward
- Check if value has been declining (team may be less responsive) or growing (team more incentivized to pay bounties)

### 3. Impact-Based Severity Classification

Many bug bounty programs use impact-based severity, not likelihood-based. This is one of the most important distinctions from traditional CVSS-based rating.

| Severity | Criteria | Typical Reward Range |
|----------|----------|---------------------|
| Critical | Direct theft of user assets, permanent freezing of assets, system insolvency, administrative takeover leading to asset theft | Top-tier rewards |
| High | Direct theft of user assets below a threshold, temporary freezing >24 hours, theft of unclaimed yield/rewards, unauthorized creation of value | Mid-tier rewards |
| Medium | Griefing where attacker loses more than victim, temporary DoS <24 hours, broken accounting without direct asset loss, theft of gas/fees | Lower-tier rewards |
| Low | Informational, best practices, code quality, no demonstrable impact on assets | Minimal or no reward |

**Key rules for severity classification**:
- Rewards are proportional to value at risk. A Critical finding on a high-value target pays significantly more than the same finding on a low-value target
- "Temporary freezing" vs "permanent freezing" is a common severity boundary. If an admin can resolve it, it is likely High not Critical
- Griefing (attacker loses money to cause loss) is capped at Medium unless the loss ratio heavily favors the attacker
- Theft of yield is High, not Critical, unless it drains the entire system
- Impact must be demonstrated on the in-scope assets specifically

**Common severity mistakes**:
- Reporting a "Critical" that requires admin key compromise -- this is usually out of scope under standard trust assumptions
- Reporting a "High" for a DoS that only lasts one block/cycle -- this is Low at best
- Claiming value-at-risk based on theoretical maximum rather than realistic attack scenario -- reviewers will challenge inflated impact claims
- Missing the distinction between "assets at risk" (direct loss) and "system disruption" (operational impact)

### 4. Asset Prioritization Strategy

**Scoring formula for program selection**:

```
Program Score = max_bounty * sqrt(value_at_risk) * freshness_multiplier * complexity_bonus
```

Where:
- `max_bounty`: published maximum reward for Critical findings
- `value_at_risk`: current total value controlled by the target
- `freshness_multiplier`: 3x for launched within 30 days, 2x for updated within 30 days, 1x otherwise
- `complexity_bonus`: 1.5x for novel/complex application mechanics, 1x for standard patterns

**High-priority targets** (hunt these first):
- Recently launched applications with high value-at-risk and high max bounty -- least audited, most bugs
- Applications that recently upgraded or deployed new components -- new code, migration bugs, state transition errors
- Applications with high value-at-risk but few or no prior assessment reports
- Multi-deployment targets -- cross-deployment accounting bugs, deployment-specific edge cases
- Applications using novel mechanics that do not have established security patterns

**Low-priority targets** (avoid unless you have a specific lead):
- Heavily audited mature applications with many prior submissions (extremely high duplicate risk)
- Applications with very low value-at-risk -- even a Critical finding may pay a minimal reward
- Programs that have been active for 2+ years without scope updates -- likely picked clean
- Programs with a history of disputing valid findings or slow payouts

**When to pivot**:
- After 4 hours of hunting with no leads, switch to a different target
- If you find a Low/Medium, submit it and pivot to higher-value hunting
- If you discover the target is a fork/clone, check if the same bug was already found on the original

### 5. Attack Surface Mapping Workflow

Step-by-step process for systematically analyzing a new target.

**Step 1: Classify the application type**
- Identify the primary category (state-tracking, exchange, vault, bridge, governance, staking, derivatives, receipt token, or web2 equivalent)
- Load the corresponding threat profile from Section 1
- If the target spans multiple categories, load all relevant profiles

**Step 2: Read documentation and extract invariants**
- Read all available documentation to understand the intended application behavior
- Extract explicit invariants: "total deposits always equals total shares times exchange rate"
- Extract implicit invariants: economic assumptions, trust assumptions, ordering assumptions
- Note any stated trust model: who is trusted (admin, operator, relayer), who is untrusted

**Step 3: Map entry points**
- List all public-facing functions/endpoints
- Classify each as: user-facing, admin-only, keeper/bot, callback/hook, view-only
- Identify functions that can be called by anyone without authorization -- these are the primary attack surface
- Identify functions gated by roles -- these define the trust boundary for "admin compromise" scoping

**Step 4: Map value flows**
- Trace every path value takes: entry point, internal accounting updates, yield/reward accrual, exit point
- Verify that balances and internal accounting stay synchronized at every step
- Check for edge cases with special value types (fee-on-transfer, rebasing, callback-triggering)
- Look for donation vectors: can someone inject value directly to desync tracked balance from internal accounting?

**Step 5: Map admin functions and trust assumptions**
- List every admin/owner/governance function
- For each: what is the worst case if this function is called maliciously?
- Check: can admin extract user assets? Is there a timelock? Are there parameter bounds?
- Note: most programs consider admin actions as trusted unless the program explicitly puts admin trust in scope

**Step 6: Map external data dependencies**
- Identify every external data source (oracles, APIs, price feeds, custom data providers)
- For each: what happens if it returns 0? What if it returns stale data? What if it returns max value?
- Check staleness validation, decimal/unit normalization, and fallback logic
- Determine if any data source can be manipulated within a single transaction

**Step 7: Map cross-component interactions**
- List every external call to another component or service
- For each: what happens if the external call fails? What if it returns unexpected data?
- Check for re-entrancy vectors at every external call site (can a callback re-enter the calling function before state is finalized?)
- Identify callback patterns: flash resource callbacks, value transfer hooks, execution callbacks

**Step 8: Run the threat profile checklist**
- Go through every attack vector in the relevant threat profile(s) from Section 1
- For each vector: is this target susceptible? Check specific code/behavior patterns
- Document which vectors are mitigated and which are potentially exploitable

**Step 9: Test edge cases**
- Zero values: deposit 0, withdraw 0, transfer 0, set parameter to 0
- Maximum values: deposit max, request maximum allowed, set parameter to max
- First/last user: first user into empty state, last user draining state completely
- Empty state: what happens when the system has zero value or zero participants?
- Transition states: what happens during pause/unpause, migration, upgrade, emergency shutdown?

### 6. Submission Optimization

How to write submissions that get accepted and paid at maximum severity.

**Title format**: Impact-first, not mechanism-first
- Good: "Attacker can drain $2.3M from the target via data feed manipulation"
- Bad: "Missing staleness check in price data source"
- Good: "First user can steal 99.9% of subsequent deposits in isolated state"
- Bad: "Rounding error in share calculation"

**Required submission components**:
1. **Vulnerability details**: Clear explanation of the root cause. Reference exact lines of code in the in-scope assets at the in-scope version
2. **Impact statement**: Quantify value at risk in concrete terms using current data. State the exact impact: "Attacker profits X, system/users lose Y"
3. **Proof of Concept**: Always include a PoC, even for moderate findings. Programs strongly favor submissions with working PoCs. Use fork tests against production state when possible
4. **Attack scenario**: Step-by-step description of how an attacker would execute this in production, including required capital, number of transactions, and timing constraints
5. **Fix recommendation**: Concise suggestion for remediation. Not required but improves acceptance rate and response time

**PoC best practices**:
- Fork production state to demonstrate on real deployed assets when applicable
- Assert the harm, not just the mechanism: show the actual profit extracted or value lost in the test assertions
- Include logging output showing states before and after the attack
- Keep the PoC minimal and focused -- one clear attack sequence, not a sprawling test suite
- If the attack requires multiple steps across time, structure the PoC to clearly show each step

**Severity justification**:
- Always reference the program's severity classification explicitly
- Calculate value at risk using real data, not theoretical maximums
- If the attack is profitable, show the profit calculation: `attacker_cost` vs `attacker_gain`
- If the attack requires temporary resources (borrowed capital, flash-borrowed assets), specify the source and available amount
- If the attack is time-sensitive, specify the window and realistic execution constraints

**Common rejection reasons and how to avoid them**:
- "Out of scope impact" -- verify the specific impact is listed under the program's in-scope impacts
- "Known issue" -- check all prior assessments and the known issues list before submitting
- "Insufficient impact" -- quantify the impact in concrete terms; if it is below the program's minimum threshold, do not submit
- "Requires trusted actor" -- unless the program specifically includes admin trust in scope, do not report admin-dependent findings
- "No PoC" -- always include a PoC; submissions without PoCs have significantly lower acceptance rates
- "Duplicate" -- search for disclosed reports on similar targets; check if the same bug class was already submitted

## Validation

Before submitting, verify every item:

1. The vulnerability affects an in-scope asset at the in-scope version
2. The impact is listed under the program's in-scope impacts (not just the asset)
3. The finding is not in any prior assessment report or known issue list for the target
4. The PoC demonstrates actual harm (value loss, permanent freeze, unauthorized value creation), not just a function call
5. The severity classification matches the program's impact-based criteria, not generic likelihood-based criteria
6. Value at risk is quantified using current real data
7. The attack is executable by an untrusted actor without admin keys (unless admin trust is explicitly in scope)

## Quick Start Checklist for a New Target

Use this checklist when starting work on any new bug bounty program.

- [ ] Read the full program page: scope, impacts in scope, known issues, verification requirements
- [ ] Assess current value-at-risk across all deployments
- [ ] Check program payout history
- [ ] Download and read all prior assessment reports for the target
- [ ] Identify the application type and load the matching threat profile from Section 1
- [ ] Clone the repo at the exact in-scope version
- [ ] Compile and run existing tests to verify the build environment works
- [ ] Map all entry points (public functions/endpoints) and classify by access level
- [ ] Map all value flows: entry to internal accounting to exit
- [ ] Map all external data dependencies and check staleness/normalization handling
- [ ] Map all admin functions and note trust assumptions
- [ ] Run through the threat profile checklist systematically
- [ ] Test edge cases: zero, max, first user, last user, empty state
- [ ] For any finding: write PoC, quantify impact, verify it is not a known issue
- [ ] Format submission: impact-first title, vulnerability details, PoC, attack scenario, fix recommendation

---

## Corpus-Derived Bounty Hunting Techniques

Patterns from high-bounty disclosed reports specific to bug bounty program hunting.

### Deserialization Sink Audit on Webhook/Callback Features

For any feature that lets a user define a webhook, callback URL, or custom request body:
1. The body almost never travels untouched -- there is a template engine, serializer, or formatter in the path.
2. Identify what serialization format the server uses internally (Java serialization, pickle, YAML, MessagePack, protobuf).
3. Test whether the user-controlled body is deserialized by the server before being forwarded.
4. If deserialization occurs, test for RCE via known gadget chains for the detected serialization library.

### Template-Then-Shell RCE Pattern

Every workflow/orchestration/build system that lets users define templated commands:
1. Identify the template engine (Jinja2, Mustache, ERB, Go templates, Airflow macros).
2. Test whether template expressions can inject shell metacharacters into the final command string.
3. Common targets: CI/CD pipeline definitions, workflow orchestrators, scheduled task configs, notification templates.
4. The template is evaluated first, then the result is passed to a shell -- if the template output contains `;`, `|`, `$()`, or backticks, it is RCE.

### P2P Protocol Amplification Audit

For any blockchain node, P2P network, or discovery protocol:
1. Identify the handshake that gates large responses from small requests.
2. Measure the amplification factor: bytes sent by attacker vs bytes generated by the node.
3. Test whether the handshake can be spoofed (UDP source address spoofing) to redirect amplified traffic to a victim.
4. Also test connection exhaustion: can an attacker open enough connections to prevent legitimate peers from connecting?

### Falsy Coercion in Security Config Parsers

For any library or framework that disables a security check via a boolean config value:
1. Test what happens when the config value is `undefined`, `null`, `0`, `""`, or missing entirely.
2. Many languages coerce these to `false` -- if `false` means "disable security check," then an unset config silently disables security.
3. Focus on TLS verification (`rejectUnauthorized`), CSRF protection, authentication requirements, and rate limiting.
4. Check if environment variable parsing treats an empty string the same as `false`.

### SCA Dependency Chain Exploitation

For any in-scope project with open-source dependencies:
1. Clone the repository and enumerate all dependencies with exact versions.
2. Run SCA tools (npm audit, cargo audit, pip-audit, govulncheck) to find known vulnerabilities in dependencies.
3. For each CVE found, trace whether the vulnerable code path is reachable from the project's code.
4. Focus on transitive dependencies -- they are less likely to be updated promptly and more likely to contain unpatched vulnerabilities.

### Authorization Revocation Completeness

For any platform with access grants (invitations, API keys, shared links, team memberships):
1. Inventory every code path that GRANTS access.
2. For each grant path, find the corresponding REVOKE path.
3. Test whether revocation removes access from ALL grant paths or only the primary one.

### Null and Type Boundary Injection

For every API parameter, test invalid TYPES beyond strings: `null`, `[]`, `{}`, `0`. Focus on access-gating parameters -- a `null` project ID may match all projects. In GraphQL, test every nullable field with `null`.
