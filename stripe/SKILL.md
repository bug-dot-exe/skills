---
name: stripe
description: Stripe integration attack surface: webhook signature, client-side secret leak, payment-intent confirmation
depends_on: []
---

# Stripe

Stripe is closed PCI-compliant payment infra. Bugs are in the integrator: webhook signature not validated, secret keys leaked client-side, PaymentIntent confirmed without server-side amount check.

## Common Bug Classes

- Webhook signature (`Stripe-Signature` header) not validated
- `sk_live_*` secret key leaked in JS bundle or repo
- PaymentIntent amount controlled client-side, server doesn't re-verify
- Customer ID enumeration via `cus_*` IDs
- Connect platform: account ID treated as auth proof
- Payment confirmation endpoint accepts mismatched amounts
- CSRF on payment provider connection flows
- Integration OAuth scope creep in Stripe Connect

## Payment Flow Manipulation (85 reports, $98K corpus)

### Amount-Equality Validation Bypass
Whenever an application has a payment provider (Stripe, PayPal, etc.):
1. Create a legitimate payment on the target application for amount X
2. Intercept the Stripe PaymentIntent creation or Checkout Session creation
3. Test: can you change the amount client-side before confirmation? (modify `amount` in the JS call to `stripe.confirmCardPayment`)
4. Test: after Stripe processes amount Y, does the server verify `amount == original_order_amount` in the webhook handler?
5. If the server trusts the Stripe webhook `amount_received` without comparing to its own order amount, you pay less

### Signature Canonicalization Collision
For every signed payment/API request:
1. Find the signature field and reverse-engineer the canonicalization function
2. Test for collision: can two different request bodies produce the same canonical form?
3. Common collisions: parameter reordering, whitespace normalization, encoding differences
4. If the canonicalization function is lossy (strips characters, truncates), forge a different request that produces the same signature

### Mass Assignment on Payment Objects
For any platform with multi-state objects (orders, subscriptions, invoices):
1. Capture the normal creation/update request
2. Add fields not present in the UI: `status`, `paid`, `amount`, `currency`, `metadata`
3. Test if the backend accepts and processes the extra fields
4. Stripe-specific: test if `payment_intent` metadata can be injected to alter server-side processing logic

## Webhook Security (Critical Integration Pattern)

### Signature Validation Bypass
1. Send a webhook payload to the target's webhook URL without the `Stripe-Signature` header — does the server process it?
2. Send with an invalid signature — does the server reject it?
3. Send with a valid signature but replayed timestamp (outside the tolerance window) — does the server reject it?
4. Test if the webhook endpoint is discoverable (common paths: `/webhooks/stripe`, `/api/webhooks`, `/stripe/webhook`)

### Webhook Event Confusion
1. If webhook signature is validated, test event type confusion: does the handler verify the `type` field?
2. Send a `payment_intent.succeeded` event with a forged `data.object.amount` — does the server trust it over its own records?
3. Test if the handler processes events for objects belonging to other customers (cross-tenant webhook confusion)

## Stripe Connect Exploitation

### OAuth Flow Attacks
1. Enumerate every endpoint in the Stripe Connect OAuth flow
2. Test CSRF on the connection initiation (`/oauth/authorize`) — can you connect a victim's account to your platform?
3. Test `redirect_uri` manipulation — is the allowlist strict or does it accept subpaths/subdomains?
4. After connection, test scope escalation — can the connected account's permissions be expanded without re-authorization?

### Account ID Authorization Bypass
1. In Connect platforms, the connected account ID (`acct_*`) is often passed in requests
2. Test if changing the account ID grants access to another connected account's data
3. Check if the platform verifies that the authenticated user owns the referenced account ID

## Secret Key Exposure

### JS Bundle and Repository Mining
1. Grep JS bundles for `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_` (restricted key prefix)
2. Search public GitHub repos, npm packages, Docker images for the same patterns
3. Only `pk_live_*` (publishable key) and `pk_test_*` should be client-visible
4. If `sk_live_*` is found, the impact is full Stripe account access: refunds, transfers, customer data
5. Check for Stripe API keys in error messages, debug responses, and source maps

### Connect Platform Key Leakage
1. In Stripe Connect, the platform's secret key can create charges on behalf of connected accounts
2. If leaked, an attacker can: create refunds, modify connected account settings, access all customer data across the platform
3. Test if the application accidentally returns the Stripe API key in API responses or logs

## CSRF on Payment Configuration

### Sensitive Endpoint Audit
For developer dashboards and admin panels:
1. Test CSRF on: API key generate/revoke, webhook URL set/update, payout schedule change
2. Test CSRF on payment provider connection: `/settings/payments/connect-stripe`
3. If the CSRF token is per-resource (not per-session), check if it leaks in any cacheable response
4. Test cross-origin POST to payment configuration endpoints with `Content-Type: text/plain` (bypasses preflight)

## postMessage Handler Attacks

For Stripe.js embedded payment forms and 3D Secure iframes:
1. Search JS for `addEventListener("message"` and `onmessage =`
2. Check if the handler validates `event.origin` strictly (must match Stripe's domain exactly)
3. Test if the handler accepts messages from any origin — if so, inject payment confirmation events
4. Stripe's own postMessage handlers are typically secure, but the integrator's surrounding handlers may not be

## Notification and Side-Channel Leakage

### Transaction Notification IDOR
1. Find endpoints that generate transaction receipts, invoices, or payment confirmations
2. Test if authenticated receipt/invoice endpoints accept other users' transaction IDs
3. If receipts are delivered via email or push notification, test if you can redirect them to your address
4. Audit webhook delivery logs for cross-tenant data leakage — some platforms expose webhook payloads in admin UIs

### GraphQL Field Authorization in Payment Platforms
For platforms with Stripe integration and a GraphQL API:
1. Query payment-related fields from a low-privilege account: `charges`, `balanceTransactions`, `payouts`, `customers`
2. Test if the API returns Stripe object IDs (`pi_*`, `ch_*`, `cus_*`) that can be used to query the Stripe API directly
3. If the platform leaks Stripe object IDs AND the platform's Stripe API key is exposed, chain for full payment data access

## Integration-Takeover Chain Construction

For Stripe integrations that involve a multi-step link flow:
1. Map the full OAuth-and-link sequence: authorize -> callback -> token exchange -> account link
2. Test each step for: CSRF, state parameter validation, redirect_uri manipulation
3. If any step is vulnerable, an attacker can link their own Stripe account to the victim's platform account
4. Impact: receive victim's payouts, view victim's transaction history, modify victim's payment settings

## Probe Targets

- Grep bundle for `sk_live_`, `pk_live_` (only `pk_*` should be public)
- Send unsigned webhook payload to webhook URLs
- Test PaymentIntent confirm with mismatched amount
- Test CSRF on Stripe Connect OAuth initiation endpoint
- Send webhook with valid structure but forged amount/status
- Test `acct_*` account ID substitution in Connect API calls
- Check for Stripe keys in error responses, debug endpoints, source maps
- Audit postMessage handlers around Stripe.js payment form iframes
- Test payment creation with extra fields (mass assignment on order objects)
- Verify webhook endpoint rejects replayed timestamps outside tolerance

## Cross-References

`api_security`, `signature_replay`, `payment_ecommerce`, `public_credential_disclosure`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
