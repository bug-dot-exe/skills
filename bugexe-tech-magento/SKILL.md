---
name: magento
description: Magento attack surface: API auth bypass, deserialization, admin path enumeration
depends_on: []
---

# Magento

Magento (Adobe Commerce) has a history of severe bugs (Magento Shoplift, RCE chains). REST/SOAP APIs commonly misconfigured.

## Common Bug Classes

- REST/GraphQL endpoints exposing customer/admin data without auth
- Deserialization via SOAP `module/index` legacy paths
- Admin path predictable / brute-forceable: `/admin`, `/index.php/admin`
- Reflected XSS in storefront search and category filters

## Probe Targets

- Probe `/rest/V1/`, `/graphql`, `/soap/?wsdl`
- Test `/admin` and common variants
- Pull `/magento_version` (info disclosure)

## Cross-References

`api_security`, `graphql_attacks`, `insecure_deserialization`, `xss`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
