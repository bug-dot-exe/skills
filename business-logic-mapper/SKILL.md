---
name: business-logic-mapper
description: Systematic business logic flaw discovery through state machine mapping, economic invariant testing, and workflow violation
depends_on: []
---

# Business Logic Mapper

Automated scanners find injection. Fuzzers find crashes. Neither finds the flaw where a legitimate API sequence, used in an unintended order, drains value or bypasses controls. This skill teaches systematic discovery and testing of business logic flaws by treating the target as a state machine with economic invariants.

## When to Use

- After initial recon reveals stateful workflows (multi-step processes, object lifecycles)
- When the target handles monetary operations (transfers, credits, refunds, subscriptions, rewards)
- When role-based access controls gate privileged actions
- When you need to go beyond input validation testing into workflow-level exploitation

---

## Phase 1: State Machine Extraction

Every stateful object in the target has a lifecycle. Map it before testing it.

### Step 1: Identify Stateful Objects

From proxy history, API docs, or source code, enumerate every object that has a lifecycle:

| Object | Create Endpoint | Identifying Field | Observed States |
|--------|----------------|-------------------|-----------------|
| /api/orders | POST /api/orders | order_id | created, pending, paid, shipped, delivered, cancelled |
| /api/subscriptions | POST /api/subscriptions | sub_id | trial, active, paused, expired, cancelled |
| /api/transfers | POST /api/transfers | transfer_id | initiated, pending_approval, approved, completed, reversed |

### Step 2: Map State Transitions

For each object, build the transition graph. Each edge is an API call:

```
[created] --POST /orders/{id}/pay--> [pending] --webhook/confirm--> [paid]
   |                                                                   |
   +---POST /orders/{id}/cancel---> [cancelled] <--POST /orders/{id}/cancel--+
                                                                       |
                                    [shipped] <--POST /orders/{id}/ship--+
                                       |
                                    [delivered] <--POST /orders/{id}/deliver--+
```

### Step 3: State Completeness Audit

Before probing for flaws, verify the state machine is fully mapped. Missing states hide bugs.

**Exhaustive state enumeration**: For each object, answer: what are ALL the states this entity can exist in? Not just the happy-path states visible in the UI, but also:
- **Error/failure states**: payment_failed, verification_expired, approval_rejected
- **Intermediate states**: processing, pending_webhook, awaiting_callback
- **Administrative states**: suspended, under_review, flagged, locked
- **Temporal states**: expired_trial, grace_period, cooling_off

**Transition matrix completeness**: Build the full NxN matrix where N = number of states. For every (source_state, target_state) pair, determine: is this transition possible? If yes, via which endpoint? If no, is the guard enforced server-side?

```
          | created | pending | paid | shipped | cancelled | failed |
created   |   -     |  pay    | -    |   -     |  cancel   |   -    |
pending   |   -     |   -     | hook |   -     |  cancel   | hook   |
paid      |   -     |   -     |  -   |  ship   |  cancel   |   -    |
shipped   |   -     |   -     |  -   |   -     |    ???    |   -    |
cancelled |   -     |   -     |  -   |   -     |    -      |   -    |
failed    | retry?  |   -     |  -   |   -     |    -      |   -    |
```

Every `???` and `retry?` cell is a test target. Every `-` cell needs verification that the guard actually exists.

### Step 4: Probe for Logic Flaws in the State Machine

For each transition, test these violation classes:

| Violation | Test | Example |
|-----------|------|---------|
| **Missing transition guard** | Call a transition endpoint when the object is in a state that should reject it | POST /orders/{id}/ship when status=cancelled |
| **Irreversible action reversal** | Attempt to undo a terminal transition | POST /orders/{id}/cancel after status=delivered |
| **Parallel path bypass** | Use an alternative endpoint to skip a required step | POST /orders/{id}/deliver without going through /ship |
| **State regression** | Force an object backward in its lifecycle | POST /orders/{id}/pay on an already-delivered order (double charge) |
| **Orphan state** | Create a state with no outbound transition | Pause a subscription, then let the pause endpoint reject resume |
| **Concurrent transition** | Race two transitions on the same object simultaneously | POST /pay and POST /cancel at the same instant |
| **PATCH-then-promote** | In multi-step approval flows (apply -> pending -> approved), PATCH the object between steps | PATCH /transfers/{id} to change amount after approval is queued but before it executes ($50K, #116404224) |

### Step 5: Enumerate Implicit State Dependencies

Some transitions depend on state in a different object. Map cross-object dependencies:

```
Order.pay requires: Cart.items.length > 0 AND Account.balance >= total
Transfer.approve requires: Approver.role == "manager" AND Transfer.amount <= Approver.limit
```

Test: can you satisfy the transition while violating the implicit dependency? (Empty the cart after payment starts. Lower the approver's limit after approval is queued.)

---

## Phase 2: Economic Invariant Discovery

Every system that handles value has invariants it must maintain. Find them, then break them.

### Step 1: Identify Monetary Operations

Scan for endpoints that create, move, or destroy value:

| Operation | Endpoint | Direction | Parameters |
|-----------|----------|-----------|------------|
| Charge | POST /api/payments | User -> System | amount, method |
| Refund | POST /api/refunds | System -> User | order_id, amount |
| Transfer | POST /api/transfers | User -> User | to_id, amount |
| Credit | POST /api/credits/apply | System -> User | code, amount |
| Discount | POST /api/cart/discount | Reduces total | code |
| Reward | POST /api/rewards/claim | System -> User | reward_id |

### Step 2: Extract Expected Invariants

From the observed operations, derive what MUST remain true:

```
INV-1: order.total == sum(items.price * items.quantity) - discounts + tax + shipping
INV-2: refund.amount <= order.paid_amount
INV-3: account.balance >= 0 (no negative balances)
INV-4: transfer.debit + transfer.credit == 0 (zero-sum)
INV-5: reward.claimed <= reward.earned (cannot claim more than earned)
INV-6: discount.applied <= 1 per order (single-use)
```

### Step 3: Test Each Invariant Systematically

For every invariant, attempt each manipulation class:

| Manipulation | Target | Test |
|--------------|--------|------|
| **Negative quantity** | INV-1 | Set item quantity to -1; does the total decrease below zero? |
| **Zero-price override** | INV-1 | Modify item price to 0 in the request body |
| **Discount exceeds total** | INV-1 | Apply a discount code worth more than the cart total |
| **Partial refund loop** | INV-2 | Request partial refunds that sum to more than the original payment |
| **Fractional rounding** | INV-4 | Transfer 0.001 units repeatedly; do rounding errors accumulate? |
| **Currency confusion** | INV-1 | Submit payment in a lower-value denomination than displayed |
| **Type coercion** | INV-3 | Send amount as string "0" vs integer 0 vs float 0.0 |
| **Overflow** | INV-5 | Claim reward with quantity near MAX_INT |

### Step 4: Test Cross-Invariant Interactions

Some invariants interact. Breaking one may cascade:

- Apply discount (INV-6) THEN request refund of original amount (INV-2) — refund based on pre-discount total?
- Earn reward from purchase (INV-5) THEN refund the purchase — is the reward revoked?
- Transfer to self (INV-4) — does the system double-count?

---

## Phase 3: Workflow Violation Testing

Map the expected sequence, then violate it at every boundary.

### Step 1: Map the Happy Path

Document the intended flow as a numbered sequence:

```
1. POST /api/cart/items         (add items)
2. POST /api/cart/discount      (apply coupon)
3. POST /api/checkout/address   (set shipping)
4. POST /api/checkout/payment   (submit payment)
5. POST /api/checkout/confirm   (finalize order)
```

### Step 2: Violation Matrix

For each step, test these violations:

| Violation | Method | What to Watch |
|-----------|--------|---------------|
| **Skip step** | Jump from step 1 to step 5 directly | Does the system enforce the prerequisite? |
| **Repeat step** | Execute step 4 twice | Double charge? Double credit? |
| **Reverse order** | Execute step 4 before step 1 | Payment without items? |
| **Modify after commit** | Change cart items (step 1) after payment (step 4) | Does the final total reflect the change? |
| **Parallel workflows** | Start two checkout flows for the same cart | Can both complete? |
| **Abandon and resume** | Complete steps 1-3, wait, then hit step 5 | Does stale state persist? |
| **Interleave flows** | Alternate steps between two different objects | Does session state bleed between objects? |

### Step 3: Step Boundary Probing

At each step boundary, the system transitions internal state. Probe the boundary:

- **Pre-transition state leak**: Before step 4 completes, can you read the payment token via another endpoint?
- **Post-transition rollback**: After step 5 confirms, does hitting step 4 again change anything?
- **Boundary timing**: Send step 4 and step 5 simultaneously — which wins?

---

## Phase 4: Render Surface Enumeration

Every feature's data is rendered in multiple places. A fix that sanitizes one surface often misses others. ($13.9K stored XSS, #1578400)

### Step 1: Map Every Render Surface Per Feature

For each feature that accepts user input, enumerate ALL locations where that data appears:

| Feature | Input Point | Render Surfaces |
|---------|------------|-----------------|
| User profile | POST /api/profile | Profile page, comment headers, @mention autocomplete, admin user list, exported CSV, email notifications, API responses, search results |
| Project name | POST /api/projects | Dashboard, sidebar, breadcrumbs, sharing dialog, webhook payloads, audit log, exported reports |
| File upload | POST /api/files | File browser, thumbnail preview, download link, embed renderer, preview tooltip, API metadata |

### Step 2: Test Each Surface Independently

For every (input, surface) pair:
- Does the surface apply its own sanitization, or rely on the input endpoint's validation?
- Is the rendering context different (HTML body vs attribute vs JS string vs CSV field vs email template)?
- Are there surfaces that render raw data for "internal" use (admin panels, logs, exports)?

A common pattern: the primary render surface is secured, but a secondary surface (autocomplete dropdown, notification email, export file) renders the same data without escaping.

### Step 3: Cross-Surface State Consistency

When data is updated at the input point, do ALL render surfaces reflect the update atomically? Test:
- Update the value, then immediately check each surface — stale caches may serve the old (unpatched) value
- Surfaces backed by different data stores (primary DB vs search index vs CDN cache) may disagree

---

## Phase 5: Cross-Feature Interaction Testing

Features tested in isolation may be secure. Their interaction may not be. Systematically test how Feature A's state affects Feature B's security.

### Step 1: Build the Feature Interaction Matrix

List all features that share state, users, or resources:

| Feature A | Feature B | Shared State | Interaction Risk |
|-----------|-----------|-------------|-----------------|
| Referral program | Account deletion | Account existence | Delete referred account — does referrer keep credit? |
| Subscription upgrade | Coupon system | Pricing tier | Apply coupon to upgrade checkout, downgrade, coupon still applied? |
| Team permissions | API key scoping | Role grants | Revoke team member's role — does their API key retain permissions? |
| File sharing | Version history | File content | Share file, update to benign version — does recipient see original? |

### Step 2: Test Design Intent vs Implementation

For each critical workflow, articulate what the system INTENDS to enforce, then test whether the implementation actually enforces it:

| Design Intent | Implementation Check | Violation Test |
|---------------|---------------------|---------------|
| "Only the creator can delete" | Does the DELETE endpoint check `creator_id == current_user`? | Substitute another user's token on the DELETE call |
| "Expired trials lose access" | Does the access check query `expiry > now()` on every request? | Access a premium endpoint 1 second after trial expiry |
| "Refunds cannot exceed payment" | Does the refund endpoint check `sum(refunds) + new_refund <= payment`? | Issue partial refunds that sum to > original payment |
| "Approved operations are immutable" | Does the PATCH endpoint reject changes when `status == approved`? | PATCH the resource after approval but before execution |

The gap between intent and implementation is where business logic bugs live. Document the intent (from docs, UI copy, error messages) and verify it mechanically at the API layer.

### Step 3: Permission Staleness After State Change

Access-control state caching is a $133K pattern (#489003520). When a permission-relevant state changes, test whether enforcement updates:

| State Change | Expected Effect | Staleness Test |
|--------------|----------------|---------------|
| Revoke team member | Loses access to team resources | Hit team endpoints with revoked user's token — cached session may still grant access |
| Downgrade subscription | Loses premium features | Access premium endpoints — check if cached tier persists beyond downgrade |
| Disable 2FA | Should re-prompt for verification | Perform sensitive actions — does the session retain its 2FA-verified flag? |
| Remove OAuth scope | Loses API capabilities | Use existing token — are revoked scopes enforced at the API or only at token refresh? |

Snapshot enforcement BEFORE the change. Make the change. Re-test with the same credentials. Any access that persists is a staleness bug.

---

## Phase 6: Role-Based Logic Abuse

### Step 1: Map the Role-Action Matrix

| Action | Anonymous | User | Premium | Staff | Admin |
|--------|-----------|------|---------|-------|-------|
| View own profile | - | Y | Y | Y | Y |
| Edit own profile | - | Y | Y | Y | Y |
| View other profiles | - | N | N | Y | Y |
| Delete any profile | - | N | N | N | Y |
| Access premium features | - | N | Y | Y | Y |
| Approve operations | - | N | N | Y | Y |

### Step 2: Test the Matrix

For every cell marked N, attempt the action with that role's credentials:

- **Vertical escalation**: User token on admin-only endpoints
- **Horizontal access**: User A's token on User B's resources (same role, different identity)
- **Feature boundary**: Standard user token on premium-only endpoints
- **Self-approval**: Can the same account that initiates an operation also approve it?
- **Role transition abuse**: Downgrade from premium to standard — do premium features persist?
- **Method swap matrix** ($50K, #170878464): For every endpoint, test BOTH axes — method and ID. Try every HTTP verb (GET/POST/PUT/PATCH/DELETE) on every discovered endpoint. An endpoint that blocks unauthorized GET may permit unauthorized DELETE

### Step 3: Role Escalation Sequences

Test multi-step escalation paths:

```
1. Anonymous -> create account (User)
2. User -> invite self via referral (get credit)
3. User -> use credit to access premium trial
4. Premium trial -> access staff-visible endpoints
```

Each step is individually legitimate. The sequence achieves unauthorized access.

---

## Phase 7: Quantity and Limit Manipulation

### Step 1: Identify All Numeric Limits

| Limit | Endpoint | Declared Value | Enforcement Point |
|-------|----------|---------------|-------------------|
| Max items per cart | POST /api/cart/items | 100 | Client? Server? |
| Max transfer amount | POST /api/transfers | 10,000 | Per-request? Per-day? |
| Rate limit | * | 100/min | By IP? By token? By endpoint? |
| Max file size | POST /api/files | 10MB | Content-Length? Actual size? |

### Step 2: Boundary and Bypass Tests

| Test | Method | Goal |
|------|--------|------|
| **Zero value** | quantity=0, amount=0 | Does it create a zero-value record that passes later checks? |
| **Negative value** | quantity=-1, amount=-100 | Does it invert the operation (charge becomes credit)? |
| **Fractional value** | quantity=0.5, amount=0.001 | Does rounding create exploitable remainder? |
| **Max integer** | quantity=2147483647 | Overflow to negative? Allocation failure? |
| **Just above limit** | amount=10001 when limit=10000 | Is the check off-by-one? |
| **Accumulated bypass** | 100 requests of amount=100 each (limit=10000 total) | Is the limit per-operation only, missing aggregate enforcement? |
| **Concurrent bypass** | Send 5 requests simultaneously, each at 50% of limit | Do all 5 succeed before the limit is checked? |

---

## Phase 8: Coupon, Discount, and Reward Abuse

### Step 1: Enumerate Reward Mechanisms

| Mechanism | Apply Endpoint | Constraints | Observed Enforcement |
|-----------|---------------|-------------|---------------------|
| Coupon code | POST /api/cart/coupon | Single-use, one per order | Client-side? Server-side? |
| Referral credit | POST /api/referrals | One per referred account | By email? By account? |
| Loyalty points | POST /api/rewards/redeem | Points <= earned | Real-time? Batch? |
| Trial period | POST /api/subscriptions | One per account | By account? By payment method? |

### Step 2: Abuse Tests

| Test | Method | Expected Flaw |
|------|--------|---------------|
| **Double application** | Send coupon apply request twice in rapid succession | Race condition allows double discount |
| **Stacking** | Apply coupon A, then apply coupon B in the same session | System allows incompatible discounts to combine |
| **Post-price-change application** | Apply discount after modifying cart to lower-price items | Discount calculated on original total, applied to reduced total |
| **Cross-account transfer** | Earn rewards on Account A, attempt to redeem on Account B | Reward ID is a direct reference, not account-bound |
| **Referral loop** | Account A refers B, B refers C, C refers A | Circular referral generates unbounded credits |
| **Expired reuse** | Use a coupon code after its stated expiration | Expiration checked at display time but not at apply time |
| **Negative-value item + coupon** | Add negative-quantity item to reduce total, then apply percentage discount | Discount percentage applied to artificially reduced total |

---

## Phase 9: Integration with Other Skills

Business logic mapping reveals structural information that amplifies other testing:

| Discovery from Logic Mapping | Follow-Up Test | Skill |
|------------------------------|---------------|-------|
| Object IDs in state transitions (order_id, transfer_id) | IDOR on every identified ID parameter | coverage_matrix |
| State transition boundaries (pay -> confirm) | Race condition at each transition point | race_condition_hunter |
| Webhook/callback endpoints in workflows | SSRF via callback URL manipulation | ssrf_deep_hunter |
| Role-action matrix reveals privileged endpoints | Auth bypass and escalation on each | auth_bypass_hunter |
| Economic flows reveal external service calls | Parameter injection at integration points | api_security_hunter |
| Multi-step workflows reveal session state | Session fixation and state confusion | chain_building |

### Handoff Protocol

After completing business logic mapping, export these artifacts for downstream testing:

1. **Stateful object inventory** — every object with its state graph and transition endpoints
2. **Economic invariant list** — every invariant with its constituent variables and test results
3. **Workflow sequence map** — every multi-step flow with step dependencies
4. **Role-action matrix** — every role-endpoint combination with observed enforcement
5. **Numeric limit inventory** — every limit with its enforcement mechanism and boundary test results

Each artifact becomes input to the relevant specialized skill. Logic mapping is the foundation; other skills attack the specific surfaces it reveals.

---

## Common Failure Modes

| Failure | Why It Happens | Mitigation |
|---------|---------------|------------|
| Testing only the happy path | Agent follows the documented flow without deviating | Always test: skip, repeat, reorder, interleave |
| Missing cross-object dependencies | Agent tests each object in isolation | Map dependencies in Phase 1 Step 4; test cross-object invariants |
| Ignoring timing | Agent sends sequential requests only | Test concurrent transitions at every state boundary |
| Stopping at authorization | Agent finds an authz block and moves on | Check if the block is enforced at every state, not just the current one |
| Treating limits as absolute | Agent tests exact boundary only | Test accumulated operations, concurrent operations, and cross-session operations |
| Assuming server-side enforcement | Client shows a constraint (max 100 items) | Always verify by sending the raw request bypassing the client |
