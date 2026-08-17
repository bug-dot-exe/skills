---
name: state-mutation-workflows
category: archetypes
description: Testing state-mutation-heavy applications covering value manipulation, balance race conditions, unit conversion abuse, transaction replay, verification bypass, rate limit circumvention, and negative amount edge cases
---

# State-Mutation Workflow Testing

Security testing playbook for applications with stateful value tracking. Focus on value manipulation, balance race conditions, unit conversion abuse, transaction replay, verification gate bypass, rate limit circumvention, and negative amount edge cases.

## When to Use

- Target tracks internal values: balances, credits, points, quotas, or allocations
- Application has mutable state that represents transferable or consumable value
- Unit conversion or multi-unit support is present (currencies, token types, measurement systems)
- Verification or approval gates control access to privileged features
- Withdrawal, redemption, export, or payout functionality exists

## Priority Checklist

### 1. Value Manipulation

- **Amount tampering**: modify value amount in client-side requests before server processing
- **Unit code swap**: change unit parameter to a lower-value unit while keeping the numeric amount
- **Fee bypass**: remove or zero-out fee parameters in requests
- **Source substitution**: swap value source to use another user's stored method or account
- **Partial fulfillment acceptance**: send less than required and check if the system marks the operation complete
- **Idempotency key abuse**: reuse idempotency keys to replay successful operations or corrupt state
- Test: intercept value-transfer request, modify amount/unit/fee fields, observe server behavior

### 2. Balance Race Conditions

- **Double-spend**: send concurrent transfer/withdrawal requests that both read the same balance
- **Deposit-withdrawal race**: deposit and withdraw simultaneously to exploit timing gaps
- **Multi-account transfer race**: transfer between accounts concurrently to create value from nothing
- **Ledger inconsistency**: parallel operations result in balance != sum of transactions
- **Reversal race**: request reversal while the original transaction is still processing
- Test: send 10 concurrent withdrawal requests for the full balance using HTTP/2 single-packet attack

### 3. Unit Conversion Abuse

- **Rounding exploitation**: convert between units repeatedly to accumulate rounding gains
- **Rate manipulation**: conversion uses client-supplied rate instead of server-side rate
- **Stale rate exploitation**: trigger conversion during rate update window using a cached favorable rate
- **Triangle arbitrage**: convert A to B to C to A exploiting inconsistent internal rates
- **Precision truncation**: amounts truncated differently at each step, enabling fractional-value accumulation
- Test: convert a fractional value between units and back repeatedly; check if balance increases over iterations

### 4. Transaction Replay

- **Duplicate submission**: replay a successful transaction request to double-credit or double-debit
- **Reference ID reuse**: use the same transaction reference to trigger duplicate processing
- **Callback replay**: replay provider callbacks to credit accounts multiple times
- **Reversal replay**: replay a reversal/refund to extract value repeatedly
- **Pending-to-complete replay**: replay the completion callback for a pending transaction
- Test: capture a successful transfer request, replay it verbatim, check if both are processed

### 5. Verification Gate Bypass

- **Feature access without verification**: access privileged features by calling APIs directly before verification completes
- **Document substitution**: upload forged or synthetic verification artifacts
- **Status manipulation**: modify verification status fields in client requests or local storage
- **Partial verification exploitation**: complete some steps, skip others, and retain partial access
- **Re-verification bypass**: change account details after approval without re-triggering verification
- Test: create account, skip verification steps, and attempt to initiate privileged operations via API

### 6. Rate Limit Circumvention

- **Limit reset timing**: perform operations across limit boundary windows (e.g., 23:59 then 00:01) to bypass periodic limits
- **Multi-channel bypass**: perform the same operation via API, mobile, and web simultaneously against a single shared limit
- **Denomination splitting**: make many small operations that individually fall under per-operation limits
- **Unit arbitrage on limits**: operate in a unit where the limit is higher in equivalent value
- **Pending operation abuse**: create pending operations totaling more than the limit before any are processed
- Test: submit multiple small requests in rapid succession totaling more than the stated limit

### 7. Negative Amount Transfers

- **Negative transfer**: send a negative amount to reverse the flow of value (debit becomes credit)
- **Zero-amount processing**: submit zero-amount operations to trigger side effects without value transfer
- **Integer overflow via negative**: negative amounts cast to unsigned integers become extremely large
- **Signed/unsigned confusion**: API accepts negative values but downstream systems interpret as unsigned
- **Minimum amount bypass**: amounts below the stated minimum (0.001, -1) accepted by the API
- Test: submit transfer/operation requests with amounts of -1, 0, -0.01, and MIN_INT; observe behavior

### 8. Cross-Service Settlement and Idempotency Abuse

- **Idempotency key replay across services**: when a payment flow spans multiple services (gateway, ledger, provider), replay the idempotency key at a different service to trigger a second settlement
- **Partial settlement divergence**: if step 2 of a 3-step settlement fails, check if step 1 is rolled back; test the window where the user has been debited but the merchant has not been credited (or vice versa)
- **Callback idempotency**: payment provider callbacks (Stripe webhook, PayPal IPN) replayed with the same event ID may re-credit the account if the receiver does not deduplicate
- **Reference collision**: generate two distinct transactions with the same reference ID; observe if the second one inherits the first's settlement state
- Test: capture a successful payment callback, replay it 5 times in rapid succession; check if the balance increases with each replay

### 9. Payment Signature and Canonicalization Attacks

- **Canonicalization collision**: when the system signs a request by concatenating fields (`amount|currency|merchant`), test if adding delimiters to field values produces a collision (e.g., `100|USD|shop` vs `10|0USD|shop`)
- **Parameter ordering bypass**: if the signature covers fields in alphabetical order, add an extra field that sorts earlier to shift the hash
- **Amount-equality validation gap**: the application creates a payment intent for $50 but accepts a provider callback confirming $0.50; the amounts are not compared
- **Stale signature acceptance**: sign a request, wait past the stated TTL, and replay; if the server does not check the timestamp, the signature is valid indefinitely
- Test: reverse-engineer the signature function (or probe by flipping bits), then construct two different requests that produce the same signature

### 10. Actor/Payer/Beneficiary Substitution

- **Cross-account beneficiary swap**: in a transfer request with fields for actor, payer, and beneficiary, substitute the beneficiary with your own account while keeping the payer as the victim
- **Self-referential transfer**: set payer and beneficiary to the same account to see if the system creates value (balance goes up) or destroys value (balance goes down)
- **Payer downgrade**: on a split-payment or group-payment endpoint, change the payer to a different group member who did not authorize the charge
- **Merchant ID spoofing**: substitute the merchant ID in a payment request to redirect funds to a different merchant account
- Test: for every endpoint with more than one identifier (sender, receiver, payer, merchant), substitute each one independently and observe the ledger effect

### 11. Multi-Axis Rate Limit Testing

- **Window boundary bypass**: execute operations at 23:59:59 and 00:00:01 to get double the daily limit across the boundary
- **Limit per identifier confusion**: test if limits are per-IP, per-session, per-account, or per-device; switch the unchecked identifier to reset the counter
- **Denomination splitting under per-operation limits**: if the limit is "$10,000 per transaction," make 100 transactions of $99.99 each
- **Pending operation accumulation**: create many pending (not yet finalized) operations that individually are under the limit but collectively exceed it; finalize all at once
- **Currency-switching limit bypass**: if limits are in USD, operate in a minor currency where the per-unit limit converts to a higher USD equivalent
- Test: send requests across every axis (different IPs, sessions, accounts, endpoints, currencies) and track which combination resets the counter

### 12. Email and Notification Link Security

- **Insecure links in transactional emails**: password reset and payment confirmation emails may use HTTP instead of HTTPS, leaking tokens to network observers
- **Token in non-primary emails**: the main password-reset email is secure but invoice emails, payment receipts, or statement links contain tokens in plain URLs
- **Email-to-PDF link injection**: for platforms that generate PDF statements, inject a URL into a transaction description field that becomes a clickable link in the PDF
- Test: trigger every email type the platform sends (signup, reset, invoice, receipt, statement, alert) and inspect every link for token leakage and protocol downgrade

### 13. Parser-Differential Exploitation

- **CDN/proxy desync**: when a CDN sits in front of the API, send requests that the CDN and origin parse differently (e.g., `Content-Length` vs `Transfer-Encoding` mismatch) to smuggle requests
- **HTTP/2 to HTTP/1.1 downgrade**: proxy upgrades H2 to H1; test if header injection is possible via H2 pseudo-headers that become inline in H1
- **Path normalization divergence**: the CDN normalizes `/api/../admin` to `/admin` but the origin receives `/api/../admin` literally and matches a different route
- **Routing-layer character fuzzing**: inject `@`, `\`, `;`, `..`, `%00`, `%2f` into URL paths and observe if error responses reveal the backend stack or internal routing
- Test: send the four canonical HTTP request smuggling probes (CL.TE, TE.CL, TE.TE, H2.CL) to every endpoint behind a load balancer or CDN

## Pro Tips

- **Test simple repetition before racing.** A non-idempotent endpoint shows up as a sequential replay bug just as easily as a race condition, and the proof is simpler. Only escalate to parallel HTTP/2 single-packet attacks if sequential replay is blocked.
- **Always audit the full actor/payer/beneficiary tuple.** Any endpoint that moves value has at least three identifiers; most authorization checks only cover one. Substitute each independently.
- **Cross-service idempotency is the highest-yield fintech pattern.** When money moves through multiple services, each service may enforce idempotency independently, but the composition of services does not. Test the seams.
- **Per-resource CSRF tokens are leak-once-compromised-forever.** In financial apps, a leaked CSRF token tied to a resource (not a session) can be reused indefinitely. Check if CSRF tokens rotate.

## Validation

- Demonstrate value manipulation with concrete impact: wrong amount charged or credited
- Show race condition with ledger proof: balance after parallel operations exceeds expected value
- Prove unit conversion abuse with measurable gain over multiple iterations
- Confirm transaction replay with duplicate ledger entries or double credit
- Document exact amounts, account states before/after, and the request sequence used
