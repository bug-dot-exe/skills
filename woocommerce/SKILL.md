---
name: woocommerce
description: WooCommerce attack surface: REST API auth, coupon abuse, webhook signature
depends_on: []
---

# Woocommerce

WooCommerce is a WordPress plugin — inherits its bug surface plus commerce-specific issues. Customer data exposure via WC REST API is the most-impactful class.

## Common Bug Classes

- WC REST API consumer keys leaked via `/wp-json/wc/v3/`
- Coupon stacking / negative-amount coupons
- Webhook signature not validated
- Order status manipulation via REST without ownership check

## Probe Targets

- Probe `/wp-json/wc/v3/orders`, `/wp-json/wc/v3/customers`
- Test coupon application logic for race conditions
- Send unsigned webhook payloads to known WC webhook URLs

## Cross-References

`api_security`, `race_conditions`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
