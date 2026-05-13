---
name: cloud_bucket_dorking
category: reconnaissance
description: Discover exposed cloud storage buckets (AWS S3, GCP Storage, Azure Blob, DO Spaces) via naming permutations, Google dorks, certificate transparency, and bucket-specific search engines
depends_on: []
---

# Cloud Bucket Dorking

Exposed cloud buckets are one of the most reliable high-impact findings in bug bounty. A target names their bucket something predictable (`target-backups`, `target-prod-assets`), sets permissions wrong (public-read, or worse public-write), and the buckets sit there indexable by search engines and bucket-focused scanners for years.

## When to Use

- Any target using AWS, GCP, Azure, or DigitalOcean (virtually all of them)
- Looking for raw data leaks (customer data, logs, backups)
- Hunting for source code / build artifacts in CI/CD storage
- Looking for misconfigured public-write buckets (lethal — arbitrary file upload)
- Finding legacy buckets the org forgot about

## Methodology

### Phase 1: Target Keyword Expansion

1. Build a keyword list: `target`, `targetcorp`, `target-prod`, company product names, subsidiary names
2. Add common bucket suffixes: `-backups`, `-logs`, `-data`, `-assets`, `-uploads`, `-media`, `-dev`, `-staging`, `-prod`, `-dist`, `-static`, `-artifacts`, `-builds`, `-dumps`
3. Add environment prefixes: `prod-target`, `dev-target`, `staging-target`, `qa-target`
4. Add year/version suffixes: `target-backup-2024`, `target-v2`

### Phase 2: Per-Provider Enumeration

Run the permuted list against each provider's bucket-existence test. Most providers respond differently for existing vs nonexistent buckets.

### Phase 3: Public-Access Testing

For each existing bucket:

1. Test read-all: `GET /<bucket>/?list-type=2` (lists contents if public-read)
2. Test object-get: `GET /<bucket>/<some-key>` (may be public even if listing isn't)
3. Test write: `PUT /<bucket>/poc-<rand>.txt` (disclose responsibly if public-write)
4. Test ACL disclosure: `GET /<bucket>/?acl` (sometimes reveals structure)

### Phase 4: Content Mining

If a bucket is listable, mine it:

1. Grep filenames for `backup`, `dump`, `config`, `.env`, `.pem`, `.sql`
2. Sort by size desc — large files often hold data dumps
3. Sort by date desc — recent uploads reveal active pipelines
4. Look for file types that shouldn't be public: `.db`, `.sqlite`, `.bak`, `.tar.gz`, `.zip`

## Key Queries

### AWS S3

S3 bucket naming is globally unique. Test via HEAD or region-aware URLs.

```bash
# Bucket existence test (region-agnostic)
curl -sI "https://<bucket>.s3.amazonaws.com/"
# 200 = public+listable, 403 = exists but not listable, 404 = no bucket, 301 = wrong region

# Region-specific (useful for non-default regions)
curl -sI "https://<bucket>.s3.<region>.amazonaws.com/"

# List contents (if public)
curl -s "https://<bucket>.s3.amazonaws.com/?list-type=2" | xmllint --format -

# via AWS CLI (anonymous)
aws s3 ls s3://<bucket>/ --no-sign-request
aws s3 cp s3://<bucket>/suspicious_file.sql - --no-sign-request

# Bucket-focused search engines
# https://buckets.grayhatwarfare.com/buckets?keywords=target
# https://osint.sh/buckets/ (aggregator)

# Google dorks for S3
site:s3.amazonaws.com "target"
site:s3.amazonaws.com intitle:"index of" "target"
site:s3.amazonaws.com intext:"target.com"

# CDX / Wayback finds old exposed bucket URLs
# (see wayback_cdx_dorking.md)
```

### GCP Cloud Storage

GCS is also globally unique. Test via standard HTTPS endpoints.

```bash
# Bucket existence / public listing
curl -s "https://storage.googleapis.com/<bucket>/"
curl -s "https://<bucket>.storage.googleapis.com/"

# API listing endpoint
curl -s "https://www.googleapis.com/storage/v1/b/<bucket>/o"

# via gcloud (anonymous)
gsutil ls -b gs://<bucket>/
gsutil ls gs://<bucket>/**

# Google dorks for GCS
site:storage.googleapis.com "target"
site:googleapis.com inurl:"storage" "target"
```

### Azure Blob Storage

Azure bucket URLs have a two-part structure: `<account>.blob.core.windows.net/<container>`.

```bash
# Account existence — resolves via DNS
nslookup <account>.blob.core.windows.net

# Container listing (if public) — requires both account + container name
curl -s "https://<account>.blob.core.windows.net/<container>?restype=container&comp=list"

# via Azure CLI (anonymous)
az storage blob list --account-name <account> --container-name <container> --auth-mode login

# Google dorks for Azure
site:blob.core.windows.net "target"
site:windows.net intitle:"<Blobs>" target

# Specialized tool: cloud_enum (supports Azure container enumeration)
cloud_enum -k target -k target-prod -k targetcorp
```

### DigitalOcean Spaces

Format: `<space>.<region>.digitaloceanspaces.com`. Regions: nyc3, sfo2, sfo3, ams3, sgp1, fra1.

```bash
# Test each region
for REGION in nyc3 sfo3 ams3 sgp1 fra1; do
  curl -sI "https://<space>.${REGION}.digitaloceanspaces.com/"
done

# List if public
curl -s "https://<space>.nyc3.digitaloceanspaces.com/?list-type=2"
```

### Backblaze B2 / Wasabi / Other S3-Compatible

Same S3 API, different endpoints:

```
# Backblaze B2
https://f<NNN>.backblazeb2.com/file/<bucket>/<key>
https://s3.<region>.backblazeb2.com/<bucket>

# Wasabi
https://s3.<region>.wasabisys.com/<bucket>
# regions: us-east-1, us-west-1, eu-central-1, ap-northeast-1

# Linode Object Storage
https://<bucket>.<region>.linodeobjects.com/
```

### Bucket-focused Search Engines

Several public services scan the entire S3 / GCS / Azure namespace and make results searchable:

| Service | Scope | URL |
|---------|-------|-----|
| **GrayHatWarfare** | S3, GCS, DO, Azure | `buckets.grayhatwarfare.com` |
| **OSINT.sh Buckets** | S3 aggregator | `osint.sh/buckets/` |
| **BuckHacker** | S3 (partly defunct) | `buckhacker.com` |
| **S3Scanner** | S3 CLI tool | `github.com/sa7mon/S3Scanner` |
| **cloud_enum** | All 3 major clouds | `github.com/initstring/cloud_enum` |

### Automation (permutation + scan)

```bash
# cloud_enum (Python tool, all 3 clouds)
cloud_enum -k target -k target-prod -k target-corp --disable-azure-msft

# S3Scanner (Python, S3-focused, very fast)
python3 s3scanner.py --bucket-file bucket_candidates.txt

# bbot (modular recon — has a cloud-buckets module)
bbot -t target.com -f cloud-enum

# Minimal shell oneliner
for BUCKET in $(cat candidates.txt); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://${BUCKET}.s3.amazonaws.com/")
  case "$STATUS" in
    200) echo "[!] Public+Listable: $BUCKET" ;;
    403) echo "[~] Exists but not listable: $BUCKET" ;;
    301) echo "[~] Wrong region: $BUCKET" ;;
  esac
done
```

### Certificate Transparency

Sometimes buckets show up in CT logs (S3 static hosting attaches a cert):

```bash
# crt.sh search for target's bucket naming patterns
curl -s "https://crt.sh/?q=%25.s3.amazonaws.com&output=json" | \
  jq -r '.[].name_value' | grep -i "target"

curl -s "https://crt.sh/?q=%25.s3-website%25&output=json" | \
  jq -r '.[].name_value' | grep -i "target"
```

## What to Look For

**Immediate Wins**
- Public-write buckets (`403 Forbidden` on `GET` but `200 OK` on `PUT` — catastrophic)
- Public listable buckets containing `.env`, `.pem`, `.sql`, `.db` files
- Backup buckets (`target-backups`, `target-db-snapshots`) — usually contain full dumps
- Build-artifact buckets (`target-ci-artifacts`) — often have signed release binaries + source
- Log buckets (`target-logs`) — may contain auth tokens in request logs

**Infrastructure Intel**
- Bucket-naming convention reveals internal team / service structure
- Multiple regional buckets reveal where the target operates
- Content-type metadata reveals which files were meant to be served as web pages

**Configuration Leaks**
- Terraform state files (`.tfstate`) — full infra blueprint + sometimes credentials
- CloudFormation templates — same
- Kubernetes manifest dumps

## Validation

1. Always disclose responsibly — public-write buckets should not be modified beyond a PoC marker file
2. Public-read buckets still require authorization to enumerate aggressively — check program scope
3. Check the bucket owner — may be a customer using target branding, not the target itself
4. Compare against the target's public CDN URLs — many public buckets are intentional assets

## Corpus-Derived Hunting Patterns

Techniques from high-bounty cloud storage reports ($1M+ combined payouts).

### Deterministic Name Pre-emption (Bucket Squatting)

Cloud services that auto-create infrastructure with deterministic names are vulnerable to pre-emption:

1. Audit every cloud service's documentation for "a bucket named X will be created" statements
2. Create the bucket BEFORE the target provisions the service — the service then writes to your bucket
3. Common patterns: `{project-id}-deploy`, `{org-name}-terraform-state`, `{service}-{region}-assets`
4. This applies to GCS, S3, Azure Blob — any globally-namespaced storage

### Authorization Boundary Confusion in Layered Services

When a cloud service is layered atop another (container registry over object storage, serverless over containers):

1. Check if the inner service's IAM scope is enforced independently from the outer service
2. Test: can a GKE node without Cloud Storage scope still read the underlying GCR bucket directly?
3. API-level access to the underlying storage may bypass the higher-level service's permission model

### CI Script and Public Repo URL Audit

Every CI script in every public repo of the target is a source of bucket references:

1. Build a regex: `https?://[^\s]*\.(s3[.-][a-z0-9-]+\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net)`
2. Grep all CI configs (`.github/workflows/`, `.gitlab-ci.yml`, `bitbucket-pipelines.yml`, `Jenkinsfile`, `Makefile`)
3. For each discovered URL, test if the bucket exists AND if the reference is still active — decommissioned references point to unregistered buckets ripe for takeover

### Mobile App Upload Destination Audit

For every mobile app that uploads user content:

1. Capture the upload destination URL from network traffic (often an S3 presigned URL)
2. Test the bucket directly: can you list contents? Can you read OTHER users' uploads by guessing keys?
3. Check if presigned URLs are generated with overly broad permissions (read+write when only write is needed)
4. Test if the presigned URL's path/key prefix is scoped to the current user or allows traversal

### Cloud-Bootstrap State Bucket Escalation

Cluster-management tools (kOps, Rancher, Cluster API) store state in cloud buckets:

1. Identify the state bucket from deployment docs, error messages, or config files in public repos
2. If the bucket is writable, you can modify the cluster spec — this is full cluster compromise
3. Terraform state files (`.tfstate`) in public buckets contain the entire infrastructure blueprint plus sometimes credentials in plaintext

### Presigned URL and SDK Endpoint Audit

1. Identify every endpoint that generates presigned URLs or signed tokens for cloud storage
2. Trace the path/key parameter — can the user control which object the presigned URL points to?
3. Test if the presigned URL generation endpoint validates the requester's ownership of the target object

## Tips

1. Start with `buckets.grayhatwarfare.com` for free — it's already scanned most of the S3 namespace
2. Permutation wordlists from `bucket-stream` and `interlace` are better than hand-crafted
3. Large targets often have 50-200+ buckets — don't stop at the first finding
4. Azure buckets are HARDER to find than S3 — use `cloud_enum` with `--azure-only` for focused scan
5. Old-school naming: `.old`, `.bak`, `-2023`, `-legacy` frequently exist when current buckets don't
6. Region mismatch (301 redirect) tells you a bucket exists — follow the redirect header
7. Combine with `wayback_cdx_dorking.md` — old asset references often point to buckets the target forgot they had
8. Subsidiary names are gold — `target-acquired-co-backups` is the kind of thing no one remembers to audit
