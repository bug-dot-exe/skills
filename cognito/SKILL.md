---
name: cognito
description: AWS Cognito attack surface: User Pool client misconfig, identity pool unauth role, JWT confusion
depends_on: []
---

# Cognito

AWS Cognito has User Pools (for direct user storage) and Identity Pools (for federation to AWS roles). The Identity Pool unauthenticated role is frequently overpermissive.

## Common Bug Classes

- Identity Pool `unauth` role granting AWS resource access
- User Pool client with no secret on confidential flows
- Custom attributes exposed via tokens (writable by user)
- JWT `kid` confusion across user pools

## Probe Targets

- Find Cognito client ID in JS bundle
- Use AWS CLI with anonymous credentials to test STS exchange
- Decode ID token, look for custom `custom:role` writable attributes

## Cross-References

`aws`, `authentication_jwt`, `oauth_oidc_attacks`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
