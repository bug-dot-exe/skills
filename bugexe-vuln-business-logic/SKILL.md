---
name: business-logic
description: Business logic testing for workflow bypass, state manipulation, and domain invariant violations
depends_on: [race_conditions]
---

# Business Logic Flaws

Business logic flaws exploit intended functionality to violate domain invariants: move money without paying, exceed limits, retain privileges, or bypass reviews. They require a model of the business, not just payloads.

## Discovery Signals

| Signal | Where to Find | Why Vulnerable |
|---|---|---|
| Cart/checkout flow with multiple steps | Feature scan | Step-skip and parameter mutation between steps |
| Coupon/promo code input field | Feature scan | Stacking, reuse, cross-user, negative-value coupons |
| Subscription/plan upgrade UI | Feature scan | Plan confusion, trial extension, feature retention after downgrade |
| Currency selector | Feature scan | Cross-currency rounding arbitrage, rate manipulation |
| Referral/invite system | Feature scan | Self-referral, infinite loop, referral bonus stacking |
| "Request a quote" or manual pricing | Feature scan | Price lock race, quote-to-order parameter swap |
| Gift card/voucher system | Feature scan | Negative transfer, self-redemption loop, expired card reuse |
| Free trial signup | Feature scan | Trial reset via email change, multiple trial accounts |
| Waitlist/queue system | Feature scan | Queue position manipulation, priority bypass |
| Seat-based licensing | Feature scan | Race on seat assignment, phantom seat creation |
| Usage-based billing (metered) | Feature scan | Late reporting, under-reporting, meter reset |
| Import/export feature | Feature scan | Import malformed data to bypass validation, export cross-tenant data |

## Attack Surface

- Financial logic: pricing, discounts, payments, refunds, credits, chargebacks
- Account lifecycle: signup, upgrade/downgrade, trial, suspension, deletion
- Authorization-by-logic: feature gates, role transitions, approval workflows
- Quotas/limits: rate/usage limits, inventory, entitlements, seat licensing
- Multi-tenant isolation: cross-organization data or action bleed
- Event-driven flows: jobs, webhooks, sagas, compensations, idempotency

## High-Value Targets

- Pricing/cart: price locks, quote to order, tax/shipping computation
- Discount engines: stacking, mutual exclusivity, scope (cart vs item), once-per-user enforcement
- Payments: auth/capture/void/refund sequences, partials, split tenders, chargebacks, idempotency keys
- Credits/gift cards/vouchers: issuance, redemption, reversal, expiry, transferability
- Subscriptions: proration, upgrade/downgrade, trial extension, seat counts, meter reporting
- Refunds/returns/RMAs: multi-item partials, restocking fees, return window edges
- Admin/staff operations: impersonation, manual adjustments, credit/refund issuance, account flags
- Quotas/limits: daily/monthly usage, inventory reservations, feature usage counters

## Reconnaissance

### Workflow Mapping

- Derive endpoints from the UI and proxy/network logs; map hidden/undocumented API calls, especially finalize/confirm endpoints
- Identify tokens/flags: stepToken, paymentIntentId, orderStatus, reviewState, approvalId; test reuse across users/sessions
- Document invariants: conservation of value (ledger balance), uniqueness (idempotency), monotonicity (non-decreasing counters), exclusivity (one active subscription)

### Input Surface

- Hidden fields and client-computed totals; server must recompute on trusted sources
- Alternate encodings and shapes: arrays instead of scalars, objects with unexpected keys, null/empty/0/negative, scientific notation
- Business selectors: currency, locale, timezone, tax region; vary to trigger rounding and ruleset changes

### State and Time Axes

- Replays: resubmit stale finalize/confirm requests
- Out-of-order: call finalize before verify; refund before capture; cancel after ship
- Time windows: end-of-day/month cutovers, daylight saving, grace periods, trial expiry edges

## Payment Flow Bypass Patterns

| Technique | How | Impact |
|---|---|---|
| Price parameter tampering | Intercept checkout request, modify `amount`, `price`, or `total` field | Purchase at arbitrary price |
| Currency swap | Change `currency: "USD"` to `currency: "IDR"` between quote and payment | Pay 1/15000th of the price |
| Quantity-price desync | Set quantity=0 but item still in cart, or negative quantity for credit | Free/negative-cost purchase |
| Coupon race | Apply same coupon code in parallel requests before "used" flag updates | Multiple discount applications |
| Gift card to cash conversion | Buy gift card at discount, redeem at full value, refund original purchase | Net positive cash extraction |
| Partial refund abuse | Request partial refunds on each item exceeding original total | Refund more than paid |
| Payment intent reuse | Capture a confirmed payment intent against a different, more expensive order | Pay for cheap item, get expensive one |
| Shipping method swap | Select free shipping at checkout, modify to express in the request | Free premium shipping |
| Tax exemption toggle | Add `tax_exempt: true` or modify tax calculation fields | Purchase without tax |
| Discount code enumeration | Brute-force short discount codes (4-6 alphanumeric) | Find active internal/partner discount codes |

## Key Vulnerabilities

### State Machine Violations

| State Machine | Violation | How to Test |
|---|---|---|
| Order: draft, confirmed, paid, shipped | Skip confirmed: draft to paid directly | Call payment endpoint before confirm, or modify order_status in request |
| KYC: submitted, under_review, approved | Bypass review: submit then call approved-user endpoints | Access verified-user features before KYC approval |
| Document: draft, review, approved, published | Publish without approval: modify document status directly | `PATCH /documents/123 {"status": "published"}` |
| Withdrawal: requested, approved, processed | Process without approval: call process endpoint directly | Access the admin approval/process endpoint as regular user |
| Contest: open, closed, judged | Submit after close: send submission with past-deadline timestamp | Submit entry after contest close, check if accepted |

Additional state machine techniques:
- Skip or reorder steps via direct API calls; verify server enforces preconditions on each transition
- Replay prior steps with altered parameters (e.g., swap price after approval but before capture)
- Split a single constrained action into many sub-actions under the threshold (limit slicing)

### Privilege Escalation via State Transitions

| Transition | Vulnerability | Test |
|---|---|---|
| Free to Premium upgrade | Feature access retained after downgrade back to free | Upgrade, use premium features, downgrade, check if features persist |
| User to Admin role change | Admin endpoints accessible after admin role removed | Get admin access, lose admin role, test admin endpoints |
| Active to Suspended account | Actions still possible during suspension grace period | Suspend account, attempt state-changing actions |
| Trial to Expired | Trial features accessible after expiration without payment | Let trial expire, attempt to use premium features |
| Single-user to Team plan | Phantom team members or seat count manipulation | Create team, add members, reduce seat count -- do members persist? |
| OAuth app authorized to revoked | Access tokens remain valid after app authorization revoked | Revoke app, use existing token |

### Concurrency and Idempotency

- Parallelize identical operations to bypass atomic checks (create, apply, redeem, transfer)
- Abuse idempotency: key scoped to path but not principal; reuse other users' keys; or idempotency stored only in cache
- Message reprocessing: queue workers re-run tasks on retry without idempotent guards; cause duplicate fulfillment/refund

### Numeric and Currency

- Floating point vs decimal rounding; rounding/truncation favoring attacker at boundaries
- Cross-currency arbitrage: buy in currency A, refund in B at stale rates; tax rounding per-item vs per-order
- Negative amounts, zero-price, free shipping thresholds, minimum/maximum guardrails

### Quotas, Limits, and Inventory

- Off-by-one and time-bound resets (UTC vs local); pre-warm at T-1s and post-fire at T+1s
- Reservation/hold leaks: reserve multiple, complete one, release not enforced; backorder logic inconsistencies
- Distributed counters without strong consistency enabling double-consumption

### Refund and Return Abuse

| Pattern | Technique | Detection |
|---|---|---|
| Double refund | Refund via API + refund via support simultaneously | Two refund events for one purchase |
| Partial refund exceeding total | Multiple partial refunds each under threshold, total > original | Sum of refund amounts > purchase amount |
| Refund after consumption | Download digital good, request refund, keep downloaded content | Refund processed without revoking access |
| Return window abuse | Modify purchase_date or extend return window via API | Return accepted outside stated window |
| Shipping label arbitrage | Generate return label, use for personal shipping | Label used but return not received |
| Chargeback + refund | Request refund AND file chargeback, get money back twice | Both refund and chargeback credited |

### Feature Gates and Roles

- Feature flags enforced client-side or at edge but not in core services; toggle names guessed or fallback to default-enabled
- Role transitions leaving stale capabilities (retain premium after downgrade; retain admin endpoints after demotion)

## Rate Limit Key-Space Exploration

Most rate limits use a single dimension as the key. Rotating that dimension resets the counter:

| Rate Limit Key | Bypass Technique |
|---|---|
| Per IP | Rotate IP via proxy, X-Forwarded-For header injection, IPv4 vs IPv6 |
| Per session/cookie | Clear cookies, use incognito, rotate session tokens |
| Per account | Create multiple accounts (if registration is open) |
| Per endpoint | Same action via different endpoint (`/api/v1/login` vs `/api/v2/login` vs `/graphql`) |
| Per API key | Use multiple API keys (free tier accounts) |
| Per user-agent | Rotate User-Agent strings |
| Composite (IP + account) | Rotate IP while keeping account, or rotate account while keeping IP |
| Per request path | Add trailing slash, path parameter, query param: `/login` vs `/login/` vs `/login?x=1` |
| Time-window based | Wait for window reset (often 60s or 15min), then burst again |

Test methodology: Send 100 requests, hit rate limit, change ONE dimension, send 100 more. If limit resets, that dimension is the key.

## Cross-Channel Inconsistency

| Channel A | Channel B | What Differs | Vulnerability |
|---|---|---|---|
| Web app | Mobile API | Price validation | Mobile API accepts client-calculated prices web rejects |
| REST API | GraphQL API | Authorization checks | GraphQL mutations skip middleware present on REST |
| Public API | Internal/partner API | Rate limits, quotas | Internal endpoints have higher or no limits |
| Main app | Admin panel | Input validation | Admin panel trusts inputs the main app sanitizes |
| Checkout v1 | Checkout v2 | Discount stacking rules | Old checkout allows stacking new one prevents |
| Browser | API client (curl) | CSRF protection | API endpoints without CSRF when called directly |

## Advanced Techniques

### Event-Driven Sagas

- Saga/compensation gaps: trigger compensation without original success; or execute success twice without compensation
- Outbox/Inbox patterns missing idempotency; duplicate downstream side effects
- Cron/backfill jobs operating outside request-time authorization; mutate state broadly

### Microservices Boundaries

- Cross-service assumption mismatch: one service validates total, another trusts line items; alter between calls
- Header trust: internal services trusting X-Role or X-User-Id from untrusted edges
- Partial failure windows: two-phase actions where phase 1 commits without phase 2, leaving exploitable intermediate state

### Multi-Tenant Isolation

- Tenant-scoped counters and credits updated without tenant key in the where-clause; leak across orgs
- Admin aggregate views allowing actions that impact other tenants due to missing per-tenant enforcement

## Bypass Techniques

- Content-type switching (JSON/form/multipart) to hit different code paths
- Method alternation (GET performing state change; overrides via X-HTTP-Method-Override)
- Client recomputation: totals, taxes, discounts computed on client and accepted by server
- Cache/gateway differentials: stale decisions from CDN/APIM that are not identity-aware

## Special Contexts

### E-commerce

- Stack incompatible discounts via parallel apply; remove qualifying item after discount applied; retain free shipping after cart changes
- Modify shipping tier post-quote; abuse returns to keep product and refund

### Banking/Fintech

- Split transfers to bypass per-transaction threshold; schedule vs instant path inconsistencies
- Exploit grace periods on holds/authorizations to withdraw again before settlement

### SaaS/B2B

- Seat licensing: race seat assignment to exceed purchased seats; stale license checks in background tasks
- Usage metering: report late or duplicate usage to avoid billing or to over-consume

## Chaining Attacks

- Business logic + race: duplicate benefits before state updates
- Business logic + IDOR: operate on others' resources once a workflow leak reveals IDs
- Business logic + CSRF: force a victim to complete a sensitive step sequence

## Testing Methodology

1. **Enumerate state machine** - Per critical workflow (states, transitions, pre/post-conditions); note invariants
2. **Build Actor x Action x Resource matrix** - Unauth, basic user, premium, staff/admin; identify actions per role
3. **Test transitions** - Step skipping, repetition, reordering, late mutation
4. **Introduce variance** - Time, concurrency, channel (mobile/web/API/GraphQL), content-types
5. **Validate persistence boundaries** - All services, queues, and jobs re-enforce invariants

## Validation

1. Show an invariant violation (e.g., two refunds for one charge, negative inventory, exceeding quotas)
2. Provide side-by-side evidence for intended vs abused flows with the same principal
3. Demonstrate durability: the undesired state persists and is observable in authoritative sources (ledger, emails, admin views)
4. Quantify impact per action and at scale (unit loss x feasible repetitions)

## False Positives

- Promotional behavior explicitly allowed by policy (documented free trials, goodwill credits)
- Visual-only inconsistencies with no durable or exploitable state change
- Admin-only operations with proper audit and approvals

## Impact

- Direct financial loss (fraud, arbitrage, over-refunds, unpaid consumption)
- Regulatory/contractual violations (billing accuracy, consumer protection)
- Denial of inventory/services to legitimate users through resource exhaustion
- Privilege retention or unauthorized access to premium features

## Signature and Canonicalization Attacks

| # | Technique | Signal | Real-World Example |
|---|-----------|--------|-------------------|
| 1 | Delimiter-less HMAC smuggling | Signature computed by concatenating field name+value without separators | Steam/Smart2Pay: email field smuggles `amount=100` into signed string ($7.5k) |
| 2 | Attacker-controlled field as smuggling lever | Large free-form field (email, name, description) in signed request | Set email to `brixamount100abc@x` to embed boundary-shifting content |
| 3 | Dual-channel data pre-staging | Signed field is also a profile attribute set before the request | Change profile email, then initiate payment flow -- email content is pre-staged |
| 4 | Sorted query-string collision | Duplicate keys, key-order tricks, encoding differences (`+` vs `%20`) | Any API using sorted key=value signature canonicalization |
| 5 | JSON canonicalization collision | Duplicate keys, Unicode normalization, number parsing (`1.0` vs `1`) | Signature schemes over non-canonical JSON |

## Mass Assignment on State Machines

| # | Target | Technique | Real-World Example |
|---|--------|-----------|-------------------|
| 1 | Ad/campaign approval workflows | Set `admin_approval: APPROVED` and `effective_status: ACTIVE` via API | Reddit ads: bypass review + payment, serve free ads ($5k) |
| 2 | KYC/verification state | Write server-only enum field (`verified`, `approved`) in update request | Any platform with multi-state objects accepting whole-object PUT |
| 3 | Billing bypass via state field | Set `payment_status: PAID` or `billing_verified: true` client-side | Decoupled state machines where fields are stored independently |
| 4 | Role/tier assignment | Mass-assign `is_premium`, `account_tier`, `plan_type` in profile update | Inspect server-set fields after state change, then write them yourself |

## Patch-Adjacent and Variant Hunting

| # | Technique | When to Apply | Real-World Example |
|---|-----------|---------------|-------------------|
| 1 | Re-enumerate mutation primitives after fix | Every accepted finding hints the flow is under-tested | Shopify Part II: email change after verification dispatched ($15k) |
| 2 | Different mutable-attribute path, same broken invariant | Fix patches one mutation; find another that reaches same state | Edit-profile vs social-login-link vs admin-edit vs API patch |
| 3 | Token binding audit after state mutation | Change email/identifier between token issuance and consumption | Confirmation token applies to new email, not original ($16k) |
| 4 | Pre-confirmation state exploitation | Skip initial confirmation, then change bound attribute | Shopify: don't confirm email, then change to victim's email ($16k) |

## Pro Tips

1. Start from invariants and ledgers, not UI -- prove conservation of value breaks
2. Test with time and concurrency; many bugs only appear under pressure
3. Recompute totals server-side; never accept client math -- flag when you observe otherwise
4. Treat idempotency and retries as first-class: verify key scope and persistence
5. Probe background workers and webhooks separately; they often skip auth and rule checks
6. Validate role/feature gates at the service that mutates state, not only at the edge
7. Explore end-of-period edges (month-end, trial end, DST) for rounding and window issues
8. Use minimal, auditable PoCs that demonstrate durable state change and exact loss
9. Chain with authorization tests (IDOR/Function-level access) to magnify impact
10. When in doubt, map the state machine; gaps appear where transitions lack server-side guards
11. Map every financial flow as a ledger -- if any sequence produces a net positive for the attacker without providing real value to the platform, it is a bug
12. Test every workflow in reverse order -- the forward path is what developers test; the reverse/cancel/undo path is where logic bugs hide
13. Look for off-by-one in time windows -- trial periods, rate limits, and quotas often have boundary errors at exactly the cutoff time
14. Test currency edge cases -- KRW (no decimals), BHD (3 decimals), BTC (8 decimals) vs USD (2 decimals) produce rounding bugs
15. Probe background job endpoints directly -- they frequently skip auth because they were designed for internal cron triggers
16. Test idempotency keys across users -- some implementations scope keys to endpoint but not to user, allowing cross-user key collision
17. For every signed payment/API request, reverse-engineer the canonicalization function and test for collisions -- concatenation without delimiters is never injective ($7.5k Steam)
18. After any fix lands, re-enumerate every mutation primitive (edit-profile, social-login-link, admin-edit, API patch) and re-run the original attack with each -- variant hunting on patched bugs is consistently high-yield ($15k Shopify)
19. In platforms with multi-state objects (ads, orders, KYC), walk the legitimate flow, observe server-set fields, then try to set them yourself via the update API -- mass assignment on approval fields bypasses entire review workflows ($5k Reddit)
20. For every "confirm arbitrary email" primitive you find, immediately check whether the system has SSO/account-merge by email -- that is the chain to ATO ($16k Shopify)
21. Audit security checks by their FAILURE mode, not their SUCCESS mode -- if signature check fails, does the request still process? If allowlist check fails, does the default case pass? ($700)
22. For composite identifiers built from sub-IDs (`A_B`, `A:B`, `hash(A,B)`), test the inverse ordering and field-swap -- many parsers do not canonicalize the composition order ($560)

## Summary

Business logic security is the enforcement of domain invariants under adversarial sequencing, timing, and inputs. If any step trusts the client or prior steps, expect abuse.

## Tool Wiring

After you have built the state machine (this skill describes how), call the registered agent tool `generate_workflow_probes` with the captured workflow steps. The tool emits a battery of skip / replay / reorder / value-mutation probes for every step you provide.

Procedure:

1. Capture each step as a dict with these keys: `name`, `method`, `endpoint`, `headers`, `body`, `required_for_next` (bool), `sensitive_fields` (list of strings), `idempotent` (bool).
2. Call `generate_workflow_probes(steps=[step1, step2, ...], tests=["skip", "replay", "reorder", "mutate"])`.
3. The tool returns a list of probe-request sequences. Execute each sequence in order via `terminal_execute` (or `browser` for UI flows), preserving auth/cookies between calls.
4. Anomaly criterion: a probe whose terminal step returns 2xx where the canonical flow would 4xx is a finding. Report the probe label and the response chain as evidence.

This wiring catches state-machine bypass, idempotency violations, step-reorder priv-esc, and value-mutation bugs (negative amounts, currency swaps, decimal rounding) -- exactly the class that pure narrative testing tends to miss.

Tool source: `bugdotexe/tools/workflow_probe/probe.py`. Tool schema: `bugdotexe/tools/workflow_probe/workflow_probe_actions_schema.xml`.
