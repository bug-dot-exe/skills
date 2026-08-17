---
name: aws
category: cloud
description: AWS security testing covering S3 buckets, IAM policies, metadata endpoints, Lambda exposure, and CloudFront misconfig
depends_on: []
---

# AWS Security Testing

Security testing for AWS-hosted applications and infrastructure. Focus on S3 bucket enumeration, IAM policy analysis, EC2 metadata exploitation, Lambda function exposure, CloudFront misconfigurations, and STS token abuse.

## When to Use

- Target application is hosted on AWS (EC2, ECS, EKS, Lambda, Elastic Beanstalk)
- S3 bucket names discovered during recon (via DNS, JS bundles, error messages)
- SSRF or cloud metadata access is suspected
- AWS API keys or STS tokens are found in source, logs, or responses
- CloudFront distributions serve the target application

## Methodology

### 1. S3 Bucket Enumeration

**Discovery**
- Extract bucket names from JS bundles, HTML source, API responses, and error messages
- Common patterns: `{company}-assets`, `{company}-uploads`, `{company}-backups`, `{company}-{env}`
- Check CNAME records pointing to `s3.amazonaws.com` or `s3-{region}.amazonaws.com`

**Access Testing**
- List objects: `aws s3 ls s3://{bucket} --no-sign-request`
- Read objects: `aws s3 cp s3://{bucket}/{key} - --no-sign-request`
- Write test: `aws s3 cp test.txt s3://{bucket}/test.txt --no-sign-request`
- ACL check: `aws s3api get-bucket-acl --bucket {bucket} --no-sign-request`
- Policy check: `aws s3api get-bucket-policy --bucket {bucket} --no-sign-request`

**High-Value Objects**
- `.env`, `config.yml`, `credentials`, `.git/`, database dumps, backups, logs

### 2. IAM Policy Analysis

**If credentials are obtained (keys, tokens, or role assumption):**
- Enumerate identity: `aws sts get-caller-identity`
- List attached policies: `aws iam list-attached-user-policies --user-name {user}`
- Get policy details: `aws iam get-policy-version --policy-arn {arn} --version-id {v}`
- Check inline policies: `aws iam list-user-policies --user-name {user}`
- Test privilege escalation paths: iam:PassRole, iam:CreatePolicyVersion, iam:AttachUserPolicy, lambda:CreateFunction + iam:PassRole, sts:AssumeRole with overly permissive trust policies

### 3. EC2 Metadata Endpoint (169.254.169.254)

**IMDSv1 (no token required)**
```
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/{role-name}
curl http://169.254.169.254/latest/user-data
```

**IMDSv2 (token required)**
```
TOKEN=$(curl -X PUT http://169.254.169.254/latest/api/token \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}
```

**ECS Task Credentials**
```
curl http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

**EKS Pod Identity**
```
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Also check: AWS_WEB_IDENTITY_TOKEN_FILE, AWS_ROLE_ARN env vars
```

### 4. Lambda Function Exposure

- Discover function URLs and API Gateway endpoints from recon
- Test unauthenticated invocation on function URLs (AuthType: NONE)
- Check for overly permissive API Gateway resource policies
- Probe for environment variable leakage via error responses
- Test event injection: manipulate event fields (pathParameters, queryStringParameters, body)
- Check if Lambda role has excessive permissions (S3, DynamoDB, STS, Secrets Manager)

### 5. CloudFront Misconfiguration

- Origin access: test direct access to origin (S3, ALB, custom) bypassing CloudFront
- Cache poisoning: inject headers (X-Forwarded-Host, X-Original-URL) and check cached responses
- Signed URL/cookie bypass: test expired or reused signed URLs, missing key pair rotation
- Origin failover: test if secondary origin has weaker security
- Custom error pages: check if error responses leak internal paths or stack traces
- WAF bypass: if CloudFront WAF is present, test origin directly

### 6. STS Token Analysis

**When tokens are found:**
- Decode and identify token type (temporary credentials vs long-term keys)
- Check token scope: `aws sts get-caller-identity` with the token
- Enumerate accessible services: attempt S3, DynamoDB, Lambda, SecretsManager, SSM
- Check for cross-account access: `aws sts get-caller-identity` may reveal unexpected account IDs
- Test token refresh: if a refresh mechanism exists, check for token scope escalation

## Key Commands

```bash
# Identity and access
aws sts get-caller-identity
aws iam get-user
aws iam list-attached-user-policies --user-name {user}
aws iam simulate-principal-policy --policy-source-arn {arn} --action-names s3:GetObject

# S3
aws s3 ls s3://{bucket} --no-sign-request
aws s3api get-bucket-acl --bucket {bucket} --no-sign-request
aws s3api get-bucket-policy --bucket {bucket} --no-sign-request

# Secrets and parameters
aws secretsmanager list-secrets
aws ssm describe-parameters
aws ssm get-parameter --name {name} --with-decryption

# Lambda
aws lambda list-functions
aws lambda get-function --function-name {name}
aws lambda get-policy --function-name {name}
```

## Validation

- Demonstrate unauthorized access to S3 objects containing sensitive data
- Show IAM credential retrieval via metadata endpoint (SSRF chain)
- Prove Lambda invocation without intended authentication
- Confirm CloudFront origin bypass exposes resources not meant to be public
- Document exact AWS CLI commands, credentials used, and responses received

## Corpus-Derived Advanced Techniques

### Alternate-Surface Authorization Audit

Large platforms expose the same resource through multiple API surfaces (web, mobile, API, GraphQL, legacy). Each surface may enforce authorization independently:
```bash
# If web blocks access to resource X, test the same resource via:
# 1. Mobile API endpoints (proxy mobile app traffic)
# 2. GraphQL (different field-level auth)
# 3. Legacy API versions (/v1/ vs /v2/)
# 4. Batch/bulk API endpoints
# 5. Export/download endpoints
# 6. Internal-facing endpoints on alternate ports
```
Authorization on surface A does not guarantee authorization on surface B for the same backing resource.

### Dependency Confusion via Internal Package Names

Search public repos, Docker images, and error pages for internal package manifests:
```bash
# Scan for internal package names in public repos
grep -r 'Gemfile\|package.json\|requirements.txt\|setup.py\|go.mod\|Cargo.toml' \
  /workspace --include='*.lock' --include='*.json' --include='*.txt' --include='*.toml'
# Check if internal package names are claimable on public registries
# (npm, PyPI, RubyGems, crates.io)
```

### CI/CD Script Cloud Asset Audit

Audit every CI script in public repos for cloud resource references:
```bash
# Regex for cloud assets in CI configs
grep -rE 'https?://[^\s]*(\.s3[.-][a-z0-9-]+\.amazonaws\.com|\.blob\.core\.windows\.net|\.storage\.googleapis\.com)' \
  /workspace/.github/ /workspace/.gitlab-ci.yml /workspace/Jenkinsfile 2>/dev/null
# S3 bucket names in CI scripts may be claimable if deleted
```

### Batch API Field Laundering

When an API supports batch/chained requests where later requests reference fields from earlier responses:
```bash
# Step 1: Batch request that queries your own profile (authorized)
# Step 2: In the same batch, reference a field from step 1 but targeting another user's profile
# The batch processor may not re-check authorization on cross-referenced fields
curl -X POST "$TARGET/api/batch" -H 'Content-Type: application/json' \
  -d '[{"method":"GET","path":"/me","ref":"self"},{"method":"GET","path":"/users/{TARGET_ID}","using":"self.session"}]'
```

### Cloud Storage URL Extraction From Responses

Inspect every web response for direct cloud-storage URLs:
```bash
# Extract S3/GCS/Azure URLs from all response bodies
grep -oE 'https?://[a-zA-Z0-9.-]+\.(s3[.-][a-z0-9-]+\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net)[^ "'"'"'<]*' \
  response_store/*.body | sort -u > cloud_urls.txt
# Test each for anonymous access
while read url; do curl -s -o /dev/null -w "%{http_code} $url\n" "$url"; done < cloud_urls.txt
```

### RichText and Markdown Sanitization Bypass

For applications with rich-text input, test sanitization across all CRUD paths:
```bash
# Create content with XSS payload via API (may bypass client-side sanitizer)
curl -X POST "$TARGET/api/posts" -H 'Content-Type: application/json' \
  -d '{"body":"<img src=x onerror=alert(1)>","format":"richtext"}'
# Also test: edit path, scheduled-post path, draft path, import path
# Sanitization may be present on create but missing on update
```

### File Processing Pipeline Parser Enumeration

For every file upload feature, enumerate all parsers the file passes through:
```bash
# Test metadata-based attacks
# EXIF → filename extraction (path traversal)
# ZIP → symlink following (Zip Slip)
# XML → entity expansion (XXE via DOCX, XLSX, SVG)
# PDF → JavaScript execution
# Image → ImageMagick/ExifTool RCE payloads
```
Each parser in the pipeline is a separate attack surface. ExifTool CVEs are particularly high-value.

### Privacy Boundary Leakage via Secondary Metadata

When a platform supports "act as another identity" (page-as-actor, org-as-actor):
```bash
# Query that reveals the underlying user behind a page/org identity
# Test: activity logs, notification endpoints, collaboration features
# The "act as" identity may leak the personal identity through metadata
# fields that were not updated to use the new identity
```
