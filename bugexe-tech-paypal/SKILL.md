---
name: paypal
description: PayPal integration attack surface: IPN signature, REST API token scope, Smart Buttons amount tampering
depends_on: []
---

# Paypal

PayPal has multiple integration paths (REST API, IPN, Smart Buttons, Express Checkout). Server-side IPN/webhook validation and amount verification are the recurring gaps.

## Common Bug Classes

- IPN (Instant Payment Notification) signature verification skipped
- REST API access tokens stored client-side or leaked
- Smart Buttons amount client-controlled, not re-verified server-side
- Refund/void operations without ownership checks

## Payment Amount Verification

The highest-bounty PayPal integration pattern ($10K+). Audit every cross-service settlement:

**Idempotency-key continuity:** When money changes via a multi-service workflow (client → app server → PayPal → webhook → fulfillment), check:
1. What happens if the same payment ID is submitted twice with different amounts?
2. Can a user initiate payment for $1, then the app fulfills an order worth $100?
3. Is the amount verified ONLY at creation, or also at capture/execution?

**Amount-equality validation checklist:**
```
# Capture the order-submit request
# Identify all price-related parameters
amount, currency, price_id, plan_id, quantity, discount_code, tax

# Test each independently:
1. Lower the body-sent amount → does the server reject?
2. Change the currency (USD → lowest-value currency) → does conversion matter?
3. Send a negative discount or negative tax
4. Change quantity to 0 or negative
5. Replace price_id/plan_id with a cheaper plan's ID
```

## postMessage Handler Exploitation

PayPal integrations heavily use postMessage for cross-origin widget communication:

1. Search JavaScript bundles for `addEventListener("message"` and `onmessage =`
2. For each handler, check: does it validate `event.origin`? Against what allowlist?
3. Test if handlers accept commands that modify: cookie values, DOM state, redirect destinations
4. PayPal checkout widgets often have handlers that set cookies or trigger redirects based on message content

**Specific targets:**
- Checkout sandbox iframes on `/sandbox/google_pay`, `/sandbox/paypal`
- Payment confirmation callback handlers
- Cross-domain analytics/tracking message listeners

## CSRF on Payment Provider Connections

State-changing payment endpoints are often missing CSRF protection:

1. **Identify CSRF token scope:** Is it per-session, per-request, or per-resource?
2. **Test token lifetime:** Do tokens expire? Can old tokens be replayed?
3. **Connection endpoints:** `POST /connect/paypal`, `POST /settings/payment` — test without CSRF token
4. **OAuth callback CSRF:** Can an attacker initiate the PayPal OAuth flow and have the victim complete it, linking attacker's PayPal to victim's account?

## Payment Flow Trust Boundary

**Client-side trust audit for every checkout:**

1. Intercept the handoff to PayPal (Smart Buttons `createOrder`, Express Checkout redirect)
2. Identify what the CLIENT controls vs what the SERVER controls in the PayPal API call
3. If the client sends `amount` to the server which passes it to PayPal: tamper the client-sent amount
4. If the server creates the PayPal order: check if the server re-verifies the amount on capture callback

**Payment gateway assumption divergence:**
- Application creates order with amount X
- PayPal processes payment for amount X
- But does the application verify the CAPTURED amount matches the ORDER amount before fulfilling?

## Token/Link Consumability Audit

Post-consumption state-residue in payment flows:

1. **Payment confirmation tokens:** After completing a purchase, can the confirmation URL/token be reused?
2. **Single-use checkout links:** Generate a checkout link, complete the purchase, try the link again
3. **Discount/coupon codes:** Apply once, complete purchase, re-apply on a new order
4. **Gift cards/vouchers:** Apply partial balance, check if the full amount is still available on retry

## Redirect Parameter Exploitation

PayPal success/cancel/return URLs are common open redirect vectors:

```
# Test these parameters on every checkout endpoint
?success_url=https://attacker.com
?cancel_url=https://attacker.com
?return=https://attacker.com
?redirect=//attacker.com
?next=javascript:alert(1)
?prejoin_data=...
```

**Chained with whitelisted domains:** When redirect validation whitelists PayPal domains, check if those domains themselves have open redirects (PayPal's own OAuth flow, merchant landing pages).

## Embedded Widget Parameter Injection

When testing PayPal embeddable widgets (checkout forms, donate buttons):

1. Enumerate all URL parameters that configure the widget
2. Test parameter injection: can you add `amount=0.01` to a pre-configured widget?
3. Check if widget configuration is signed or if parameters can be freely modified
4. Test XSS via widget parameters that render in the payment page

## Probe Targets

- Send unsigned IPN POSTs to merchant IPN URL
- Search bundle for PayPal client_id and secret
- Test order amount tampering between client and server
- Intercept PayPal capture/execute callbacks and verify amount matching
- Test refund endpoints with other users' transaction IDs
- Check for exposed PayPal webhook signing secret
- Test PayPal OAuth callback for CSRF (missing state parameter)

## Cross-References

`api_security`, `signature_replay`, `payment_ecommerce`, `csrf`, `open_redirect`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
- For amount tampering: demonstrate the order is fulfilled at the tampered (lower) amount
- For CSRF: show the state change completes cross-origin without user interaction beyond visiting a page
