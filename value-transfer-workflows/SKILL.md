---
name: value-transfer-workflows
category: vulnerabilities
description: Value transfer workflow attacks including unit/decimal abuse, callback signature bypass, race conditions, idempotency reuse, and discount stacking
depends_on: []
---

# Value Transfer Workflow Attacks

Value transfer bugs exploit gaps between what the client displays, what the server trusts, and what the downstream processor confirms. The highest-paid findings combine small primitives (negative quantities, unit switches, race conditions, idempotency-key reuse) into full value loss. Most programs pay well for demonstrable value-equivalent loss; hypothetical impact rarely pays out.

## Attack Surface

**Client-Side Trust**
- `price`, `amount`, `total`, `discount`, `tax`, `fee`, `unit`, `rate` in request bodies
- Hidden form fields / JSON fields the server accepts without recalculation
- Discount codes, credit balances, loyalty points, referral credits
- Rate lookups, tax-jurisdiction lookups, fee schedule lookups
- Multi-step workflows where early-step values carry forward

**Server-Side Race Windows**
- Selection -> checkout -> authorize -> capture -> confirm (each state transition is a race target)
- Balance check and deduction as non-atomic operations
- Discount "use count" incremented after order creation, not during
- Inventory/quota decrement between "add to selection" and "confirm"

**Downstream Service Integrations**
- Third-party processors, gateways, and fulfillment services
- Callbacks for `operation.succeeded`, `operation.refunded`, `operation.completed`
- Idempotency keys, client-side tokens, redirect-based flows (verification callbacks, return URLs)

**Fulfillment Logic**
- Digital goods unlocked on client-side redirect vs server callback
- Reversal processing that does not revoke digital access
- Fulfill-then-charge vs charge-then-fulfill ordering

## Discovery Signals

| Signal | Where to Find | Why Vulnerable |
|--------|---------------|----------------|
| `Hash` or `signature` field in payment POST | Proxy intercept of checkout | HMAC canonicalization smuggling if concat without delimiters (H1 #1295844: Steam $7.5K) |
| `Idempotency-Key` / `ClientRequestId` in headers | Request headers to processor | Reuse across operations or missing scoping (H1 #1849626: Stripe $5K — no idempotency at all) |
| `amount` or `price` field in client request body | Proxy intercept | Server may trust client-supplied amounts (H1 #1213765: Reddit coin IDOR $500) |
| `currency` / `unit` parameter at any checkout step | Request body / query params | Unit swap between steps if server does not revalidate (JPY/IDR/VND vs USD) |
| Redirect-based payment flow (PayPal, 3DS) | Payment redirect chain | Order-ID substitution between payment confirm and fulfillment |
| `wallet_id` / `payment_method_id` in purchase request | Proxy intercept | Cross-user IDOR: pay with someone else's wallet (H1 #938021: Zomato $2K) |
| Callback URL pattern (`/webhook`, `/callback`, `/notify`) | JS bundle grep, endpoint enum | Unsigned or weakly-signed callbacks allow forged completion events |
| Fee discount / promo acceptance endpoint | Admin or dashboard traffic | Non-idempotent redemption: call N times, get N discounts (H1 #1849626) |
| Async processing spinner during purchase | UI observation | TOCTOU race window: publish/fulfill before payment lock (H1 #953083: Shopify $2K) |
| Client-controlled `order_id` at confirmation step | Proxy intercept | Bind cheap payment to expensive order (H1 #1213765) |
| Mass-assignment fields in campaign/order create | API response diff vs request | Server-only fields (approval, status) writable by client (H1 #1543159: Reddit $5K) |
| `sender_batch_id` or missing idempotency on payout | Payout flow proxy | Double payout if key is regenerated on retry (H1 #307239: Coinbase $10K) |

## Value and Amount Manipulation

### Direct Field Tampering

Intercept every step, modify `price`/`amount`/`total`:
```
POST /api/selection/add     {"itemId": 42, "qty": 1, "price": 0.01}
POST /api/selection/update  {"selectionId":"x", "total": 0.01}
POST /api/checkout/start    {"amount": 1, "unit": "USD"}
POST /api/confirm           {"orderId":"x", "amount": 0.01}
```

Common server behaviors to distinguish:
- Server ignores price, always recomputes -> dead path
- Server trusts price only on first insert (add step) -> modify at add-time
- Server recomputes before auth but not before capture -> race against capture
- Server trusts price after discount applied -> apply discount then tamper

### Numeric Edge Cases

Test negative (`qty: -1`), zero, overflow (`qty: 2147483648` wraps on int32), `NaN`, `Infinity`, `"1e10"`, and decimal truncation (`"0.001"` stored as 0 smallest-units). Negative quantities net to positive for the processor but issue internal credit. Decimal truncation compounds at scale: 0.004 per transaction x millions = real value loss.

## Unit Confusion

Different units, same numeric amount:
```
{"amount": 10000, "unit": "USD"}   // $100.00
{"amount": 10000, "unit": "JPY"}   // ~$0.67
{"amount": 10000, "unit": "IDR"}   // ~$0.60
{"amount": 10000, "unit": "VND"}   // ~$0.40
```

Many processors take amount in the unit's smallest subdivision. Swapping units in a request body while the server displays the same numeric amount can produce orders-of-magnitude value reductions.

Vectors: `currency` param in checkout, locale switch via session cookie, `Accept-Language` header, multi-unit apps. Test: add item in unit A, swap to unit B at authorize, check processor dashboard for actual unit processed.

## Discount and Voucher Abuse

### Stacking

Apply multiple exclusive discounts by varying request:
```
POST /selection/discount {"code": "SAVE10"}
POST /selection/discount {"code": "SAVE20"}
POST /selection/discount {"code": "FREE_EXTRA"}
GET  /selection                                 // total shows all three applied?
```

Multi-parameter or array forms:
```
POST /selection/discount {"codes": ["SAVE10","SAVE20"]}
POST /selection/discount?code[]=SAVE10&code[]=SAVE20
```

### Percentage Overflow

Some discount systems accept percentages server-side from fields that were meant to be client-display only:
```
{"code": "CUSTOM", "percentage": 150}
{"code": "CUSTOM", "discountAmount": 9999999}
```

### Reuse After Expiry

Operation creation stores the applied discount ID. If reversal returns the discount to "unused" state, you can:
1. Complete operation with discount
2. Reverse the operation (digital good retained? see reversal abuse)
3. Discount is now valid again -> reuse

Also test applying an expired discount via API where the UI hides expired ones.

### Self-Referral

Referral programs crediting both referrer and referee: sign up with your own referral code (different email, same account details) -> credit arbitrage.

### Short-Code Bruteforce

Short redemption codes (8 digits, numeric only) are brute-forceable. Rate-limiting on the redeem endpoint is sometimes absent or per-session. Also test:
- Alphanumeric codes with weak entropy
- Sequential codes from observed batches
- Check-balance endpoints without rate limiting (silent enumeration)

## Race Conditions

Single-packet or burst attacks at state-transition points:

**Burst a single-use discount**:
```bash
# Turbo Intruder / single-packet HTTP/2 attack
# Send N identical "apply discount" requests in one TCP connection
```

**Double-spend credit balance**: 10 parallel checkouts each consuming full credit balance -- if any two commit before the other reads balance, both succeed.

**Inventory race**: last-in-stock item acquired by N users simultaneously -- some processors authorize all, then fulfillment fails after charge. See the `race-condition-hunter` skill for HTTP/2 single-packet mechanics. Checkout, discount, and balance endpoints are the three highest-signal race targets in multi-step workflows.

## Idempotency Key Reuse

Many services use idempotency keys (`Idempotency-Key`) so that retrying a request does not double-process. If the application:
- Generates the key client-side and trusts it
- Reuses the key across different operations
- Accepts a header-level key that the attacker supplies

Attacks:
- **Replay success**: capture a successful response, replay with same key for a different operation -> second operation inherits "completed" status without actual processing
- **Force failure**: an idempotency key tied to a failed attempt marks future attempts with the same key as failed too; grief legitimate users by claiming their key
- **Cross-user reuse**: attacker sets idempotency key to a known successful key from another account

Look for `Idempotency-Key`, `X-Idempotency-Key`, `ClientRequestId`, `requestId` in request headers/bodies. If server echoes them back in responses, they are likely trusted.

## Callback Signature Bypass

Downstream services deliver event notifications to the application via callbacks. If the application trusts the callback without signature verification, an attacker delivers a fake "completed" event and triggers fulfillment.

Callback verification typically uses a signature header with timestamp + HMAC-SHA256 over the body.

Pitfalls in application code:
```js
// Vulnerable -- no verification
app.post('/callback', (req, res) => {
  const event = JSON.parse(req.body);
  if (event.type === 'operation.succeeded') fulfillOrder(event.data.object.metadata.orderId);
});
```

**Attack** -- if the callback URL is known or guessable (`/api/callback`, `/webhooks/notify`), POST a fake event:
```bash
curl -X POST https://target.tld/api/callback \
  -H 'Content-Type: application/json' \
  -d '{"type":"operation.succeeded","data":{"object":{"metadata":{"orderId":"YOUR_ORDER"}}}}'
```

**Bypass even when signatures are checked**:
- Test env signing key leaked in client bundle or public repo
- Timing-window acceptance (default `tolerance=300s`; if disabled, replay old valid events)
- Content-type tricks where verifier hashes raw body but handler re-parses
- HTTP/2 request smuggling to inject a second event past the verifier

Common patterns: callback verification via a round-trip to the originating service; skipping verification allows forging completion status. HMAC on specific fields with pitfalls including missing fields in the signed set, sandbox/live key mix-up, and endpoint accepting both.

## Reversal and Fulfillment Abuse

**Reverse-then-fulfill**: many platforms process reversals and fulfillment asynchronously. Complete operation, trigger reversal, item still delivered.

**Digital-good retention**: reversal does not revoke access to downloaded file, streamed content, or activated license.

**Delivery address manipulation post-auth**: once an operation is authorized, some flows allow address edit "before delivery". Use to redirect physical goods while keeping the charge attached to the original account.

**Partial reversal exceeding original amount**: `POST /reverse {"amount": 99999}` when original was 100. Some processors enforce, others do not; application layer sometimes does not.

**Tax/jurisdiction-exempt abuse**: mark address as exempt jurisdiction then deliver to a non-exempt location. Check whether tax is computed on delivery-to vs billing-to address.

**Return + internal credit**: return item, receive internal credit + kept item via photo-only verification flows.

## Source Method Manipulation

Swap `sourceMethodId` to another account's, use a saved method from a different user (if method ID is enumerable), inject `saveMethod: true` to capture another user's credential token, or swap methods mid-flow (verified method fails, swap to unverified after auth marker is set).

## Chaining

**Unit swap + discount + reversal**
1. Add item valued at 100, swap unit to a lower-value equivalent, checkout at a fraction of the value
2. Apply 20% discount reducing further
3. Request reversal, system reverses in the original higher-value unit equivalent
4. Net positive: paid a fraction, reversed at full value -> infinite value extraction at small amounts

**Idempotency reuse + race**
1. Make one successful small operation, capture its idempotency key
2. Race 10 large operations with the same idempotency key
3. Some processors short-circuit on key match, returning "completed" without processing

**Callback forge + discount reuse**
1. Forge `operation.succeeded` callback to unlock a digital good without charge
2. Trigger reversal flow which "re-issues" the discount used (since the operation is marked completed)
3. Iterate: free goods + recycled discount

## Payment Flow Bypass Matrix

| Flow Step | Bypass | Technique | Impact |
|-----------|--------|-----------|--------|
| Price calculation | Client-supplied price trusted | Modify `price`/`amount` in checkout POST | Purchase at arbitrary price |
| Currency selection | Unit swap between steps | Change `currency: "USD"` to `"IDR"` between quote and capture | Pay 1/15000th of price |
| Discount application | Non-idempotent accept endpoint | Call `/accept_discount` N times sequentially | N x discount applied (H1 #1849626: $600K from 30 calls) |
| Payment confirmation | Order-ID substitution | Create cheap + expensive order; pay cheap; confirm against expensive `order_id` | Pay $2 get $40 product (H1 #1213765) |
| Signature validation | HMAC concat smuggling via email | Embed `amount100` in email field; re-split form params | Signature valid, amount changed (H1 #1295844: $7.5K) |
| Callback verification | Forge `operation.succeeded` POST | POST fake completion event to `/webhook` endpoint | Fulfillment without payment |
| Wallet/method binding | Cross-user wallet IDOR | Replace `wallet_id` with another user's ID | Pay with victim's wallet (H1 #938021) |
| Payout settlement | Double payout via retry race | Timeout on PayPal call; retry regenerates idempotency key | User receives 2x payout (H1 #307239: $10K) |
| State machine approval | Mass assignment on status fields | Set `admin_approval: APPROVED` in campaign update API | Bypass review + payment (H1 #1543159) |
| Async provisioning | TOCTOU race on publish | Call publish during processing window before payment lock | Free paid asset (H1 #953083) |
| Refund processing | Partial refunds exceeding total | Multiple partial refunds each under threshold | Total refund > original charge |
| Digital fulfillment | Refund after download | Complete digital purchase, trigger refund, retain access | Free digital goods |

## Payment Provider Quirks

| Provider | Quirk | Exploitation | Impact |
|----------|-------|-------------|--------|
| Stripe | `Idempotency-Key` header scoped to endpoint but not always to user | Cross-user key collision: reuse another user's successful key | Short-circuit payment as "already completed" |
| Stripe | Fee discount offers lack idempotency check | Sequential repetition of accept endpoint | Unlimited fee-free processing (H1 #1849626) |
| PayPal | `sender_batch_id` for Payouts API idempotency is caller-generated | Fresh batch ID on retry = PayPal processes both | Double payout (H1 #307239) |
| PayPal | Redirect-based flow exposes `order_id` in client URL | Swap order_id between payment approval and capture | Pay for cheap order, fulfill expensive one |
| Smart2Pay (Nuvei) | HMAC computed by concatenating field names+values without delimiters | Email field smuggles amount into canonical form | Arbitrary amount manipulation (H1 #1295844, #57866115) |
| Braintree | Client-side nonce generation for payment methods | Replay nonce from test/sandbox against production | Bypass payment method verification |
| Adyen | `shopperReference` links stored cards to users | Enumerate references to access other users' stored methods | Cross-user payment method access |
| Square | Idempotency key has 24h window | Replay within window to force duplicate processing | Double-charge or double-fulfillment |

## Defense-Bypass Pairs

| Defense | Bypass | Corpus Evidence |
|---------|--------|----------------|
| HMAC signature on payment request | Concatenation-without-delimiter smuggling via controllable field (email, description) | H1 #1295844, #57866115: Steam/Smart2Pay $7.5K each |
| Server recomputes price before capture | Modify amount at authorize step, not create step — race capture before recompute | Common pattern: recompute happens before auth but not before capture |
| Single-use discount flag | Sequential repetition: flag check absent entirely | H1 #1849626: Stripe fee discount, no flag check at all |
| Callback signature verification | Test-env key in client JS bundle; timing tolerance disabled; content-type parsing diff | Common: `STRIPE_WEBHOOK_SECRET` in `.env` committed to repo |
| Rate limiting on discount endpoint | Turbo Intruder single-packet: all requests arrive before counter increments | Race beats per-request rate limiting |
| Amount validation on confirmation | Create 2 orders; pay small; bind small payment to large order via client `order_id` | H1 #1213765: Reddit coin IDOR |
| Session-bound wallet selection | IDOR: server validates session for consumer but not for funding source | H1 #938021: Zomato wallet_id swap |
| Admin-only approval status | Mass assignment: PUT entire object with `admin_approval: APPROVED` | H1 #1543159: Reddit ad platform bypass |
| Payment lock on async provisioning | Race: publish call wins narrow window before lock stamps | H1 #953083: Shopify theme publish race |
| Idempotency key on payouts | Retry path generates new key instead of reusing original | H1 #307239: Coinbase double PayPal payout |

## Chain Patterns

| Chain | Steps | Impact |
|-------|-------|--------|
| HMAC smuggling -> amount manipulation -> wallet drain | Stage magic string in email; split form params; signature validates; pay $1 get $20 | H1 #1295844: Steam unlimited wallet funds ($7.5K) |
| Unit swap + discount + refund -> profit | Checkout in JPY (low value); apply percentage discount; refund in USD (high value) | Net positive: paid fraction, refunded at full rate |
| Double payout + retry race | Timeout first payout call; retry with new idempotency key; both settle | H1 #307239: Coinbase $10K — 2x PayPal payout |
| Callback forge + discount recycle | Forge completion callback; trigger refund; discount re-issued as "unused" | Free goods + recycled discount loop |
| IDOR order swap + payment intent reuse | Pay for cheap order via PayPal; swap order_id at confirm -> expensive order fulfilled | H1 #1213765: Reddit coins — pay $2 get $40 |
| Mass assignment + approval bypass + free ads | Set `admin_approval: APPROVED` + `effective_status: ACTIVE` without payment | H1 #1543159: Reddit unlimited free advertising ($5K) |
| Race condition + balance double-spend | Parallel checkouts each read pre-debit balance; both commit | Classic double-spend on non-atomic balance check |
| TOCTOU provisioning + permanent ownership | Race publish during processing window; paid-flag never stamps | H1 #953083: Shopify paid theme free + permanently owned |

## Bug-Bounty Framing

**What makes this payable**
- Demonstrable value loss: real charge at manipulated amount in a test environment, or documented path in production
- Quantifiable multiplier: "orders-of-magnitude value reduction" / "free item" / "reversal exceeds charge"
- Full request chain from start to completed operation with altered state
- Transaction IDs from processor dashboard (test mode) proving the processor actually accepted the manipulated amount

**Common triager pushback**
- "This would get caught by fraud detection." -> Fraud detection is a compensating control, not a fix. Show the bug at the logic level; fraud detection is not triggered by one test
- "Our callback is signed." -> Show either the missing verification, exposed secret, or timing-window abuse
- "Negative qty is caught." -> Test variants: decimals, type confusion (`qty:"1"` vs `qty:1`), array-as-qty
- "You need a valid source method." -> Use test-mode credentials to show the processor's response; demonstrate server-side mishandling separate from source validity
- "Requires admin." -> Discount/voucher bugs may; negative qty and unit switches typically do not. Frame accordingly

**Preempt**
- Always use test/sandbox mode processors where available
- Never use credentials you do not own
- Document exact value amounts for impact -- triagers compute payout from `value_lost x exploitability`
- Include the request chain (1-6 requests) with headers, response status, and any dashboard screenshots from processor sandboxes

## Testing Methodology

1. Map all value-carrying fields across selection -> checkout -> authorize -> fulfill
2. Tamper at each step, not just the last -- early-step values often carry forward without recheck
3. Test negative, zero, huge, decimal, string, overflow, NaN, Infinity
4. Swap units at each step; observe server recompute or passthrough
5. Stack/reuse discounts via arrays, parallel requests, and reset flows
6. Hit discount, checkout, inventory with HTTP/2 single-packet races
7. Probe callback endpoints: POST fake events, replay old events, swap signatures
8. Trace idempotency keys -- client-controlled, cross-user, cross-order
9. Test reversal boundaries: amount > charge, digital retention, discount rollback
10. Check cross-unit rounding and jurisdiction-exempt handling

## Validation

1. Operation/transaction ID proving the processor accepted the manipulated value
2. Net value impact expressed numerically (paid X, received Y valued Z)
3. Request chain reproducible from cold initial state
4. Screenshot of admin/user dashboard showing the inconsistent state
5. For callback bypass: log of your forged request being accepted and the resulting operation state change

## False Positives

- Client-side UI showing modified value but server recomputes silently before capture
- Sandbox-only bug with a fix deployed to production
- "Bug" in a flow gated by trusted-partner auth (not reachable from a normal user)
- Race condition that triggers transaction-rollback rather than double-charge
- Callback endpoint that accepts unsigned events only in dev environment with hostname gate

## Impact

- Direct value loss: operations at arbitrary values, free goods, double reversals
- Revenue leak: discount stacking at scale, redemption code enumeration
- Inventory loss: race-condition over-fulfillment
- Downstream fraud exposure: dispute/reversal liability from manipulated operations
- Regulatory exposure: incorrect reporting from jurisdiction abuse

## Pro Tips

1. Processor sandboxes are free -- use them. Test mode shows the exact value the server requested, which is the ground truth
2. Unit confusion is the highest-value/lowest-effort bug in the class. Check every endpoint that takes a unit parameter
3. Decimal-truncation bugs compound: 0.004 per transaction x millions of transactions = real value. Frame the impact accordingly
4. Callback bugs are often findable via JS bundle grep for `/callback`, `/webhook`, `/notify`
5. When a race succeeds, quantify the window -- burst of 20 with 3 winning is very different from 10k with 2 winning
6. Triagers pay more for "one-click repro with test credentials" than for theoretical paths; invest time in a clean PoC
7. Keep physical fulfillment out of PoC; use digital-goods flows whenever possible to avoid real-world fraud exposure
8. Test simple repetition BEFORE race conditions. Stripe's $5K bug needed zero concurrency -- just calling the endpoint 30 times sequentially worked. Many researchers over-complicate and miss the obvious
9. For any HMAC-signed payment request, find the canonicalization method. If it concatenates values without delimiters, every controllable field (email, description, name) is a smuggling vector. Test: does changing one field's boundary while keeping the same byte sequence preserve the hash?
10. Create two orders at different prices, pay for the cheap one, confirm against the expensive one's ID. This "two-order substitution" pattern is the single highest-yield payment IDOR test
11. When auditing cross-service settlements (app -> PayPal/Stripe), verify the SAME idempotency key persists through every retry path. Fresh key on retry = double settlement
12. Every field the UI hides but the API accepts is a mass-assignment candidate. After any server-side state change, diff the response and try writing each new field yourself on a different object

## Summary

Value transfer bugs live in the trust gaps between client display, server recomputation, and downstream processor confirmation. The durable payable classes are unit swap, negative/decimal amounts, race-condition double-spend, idempotency reuse, and unsigned or weakly-signed callbacks. Prove the bug with a processor-sandbox transaction that actually settles at the manipulated amount, and express impact in concrete value terms.
