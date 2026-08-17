---
name: aws-lambda
description: AWS Lambda attack surface: IAM role over-permission, environment secrets, layer trust, RIE leakage
depends_on: []
---

# Aws Lambda

Lambda functions front many APIs. Bug surface: execution role with too-broad `iam:PassRole` / `s3:*`, env-var secrets visible in Lambda console, layer hijack via shared/public layers, Runtime Interface Emulator (RIE) leakage in containerized Lambdas.

## Common Bug Classes

- Execution role with `s3:*`, `dynamodb:*`, `iam:PassRole` instead of scoped resources
- Env vars containing static secrets viewable to anyone with `lambda:GetFunction`
- Public Lambda layers consumed without integrity check
- Function URLs (`*.lambda-url.<region>.on.aws`) exposed without IAM auth
- API Gateway integration accepting `Host`/`X-Forwarded-*` for downstream auth

## Probe Targets

- Subdomain enum on `*.lambda-url.<region>.on.aws`
- Test API Gateway routes for AWS_IAM auth bypass
- Inspect Lambda response headers for runtime version

## Cross-References

`aws`, `api_security`, `ssrf`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
