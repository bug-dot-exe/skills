---
name: recon-subdomain-permutations
category: reconnaissance
description: Generate subdomain candidate variations from known assets — environment, region, service, numeric, concatenation, mutator, and cloud-naming patterns — to surface dev/staging/internal hosts that passive sources never indexed
depends_on: []
---

# Subdomain Permutation Generation

## Purpose

Multiply known subdomains into candidate lists by applying systematic naming patterns. Passive sources only return subdomains that were publicly indexed at some point. Anything that was never crawled — fresh dev environments, internal-only staging, region-specific deployments, time-shifted cohort buckets — is invisible to passive recon. Permutation closes that gap by generating the names the target probably created and never advertised, then resolving the candidates to confirm which actually exist.

The yield is asymmetric. Permutation is cheap (CPU + DNS queries) and frequently surfaces the highest-impact subdomains — internal admin panels, deprecated APIs, pre-prod environments with weaker auth. A dev environment that was never linked from any public page is still resolvable if its name follows the org's convention.

## When to Use

- A passive subdomain pass (chain to `recon_passive_subdomain`) returned a baseline seed list and you need broader coverage
- The target's subdomain naming follows a visible convention (most enterprises do)
- You have at least 5 known subdomains as seeds — fewer than 5 yields too little signal for pattern detection
- The scope allows active DNS resolution against the target's nameservers
- The engagement timeline allows a multi-pass recursive expansion (each pass uses prior pass results as new seeds)
- You suspect environment- or region-specific subdomains exist that were never indexed publicly
- The target uses a cloud provider with predictable bucket/storage naming (S3, GCS, Azure)

## Inputs

- Seed list of known subdomains (from passive recon, prior engagements, or scope provided by the program)
- Parent domain(s) (`target.example`, `target-internal.example`)
- The target organisation's name and common abbreviations (used for cloud naming permutations)
- Optional: documented naming convention from the program scope page or prior reports

## Permutation Patterns

Pattern catalogue. Apply every pattern systematically — the union of all patterns × all seeds is the candidate space.

### Environment prefixes (with hyphen and dot delimiters)

```
dev-    dev.        develop-    develop.
staging- staging.   stg-        stg.
qa-     qa.         test-       test.
beta-   beta.       alpha-      alpha.
demo-   demo.       sandbox-    sandbox.
preview- preview.   uat-        uat.
prod-   prod.       production- production.
```

Applied to seed `api.target.example`:
```
dev-api.target.example
dev.api.target.example
staging-api.target.example
staging.api.target.example
qa-api.target.example
test-api.target.example
beta-api.target.example
preview-api.target.example
sandbox-api.target.example
prod-api.target.example
```

### Environment suffixes

```
-dev        .dev
-staging    .staging
-stg        .stg
-qa         .qa
-test       .test
-beta       .beta
-demo       .demo
-prod       .prod
-internal   .internal
```

Applied to seed `api.target.example`:
```
api-dev.target.example
api.dev.target.example
api-staging.target.example
api-qa.target.example
api-prod.target.example
api-internal.target.example
```

### Region / datacenter codes

```
us-     us1-    us2-    us-east-    us-west-    us-central-
eu-     eu1-    eu-west-    eu-central-    eu-north-
ap-     apac-   ap-south-   ap-southeast-   ap-northeast-
asia-   na-     sa-     latam-  emea-
ca-     uk-     de-     fr-     jp-     in-     au-     br-
```

Applied to seed `api.target.example`:
```
us-api.target.example
us-east-api.target.example
eu-api.target.example
eu-west-api.target.example
ap-southeast-api.target.example
emea-api.target.example
```

Combinations: region + environment.
```
dev-us-api.target.example
us-dev-api.target.example
staging-eu-api.target.example
eu-staging-api.target.example
```

### Service prefixes

```
api-    www-    admin-  internal-   secure-     login-
auth-   sso-    oauth-  saml-       idp-
cdn-    static- assets- media-      content-
blog-   docs-   help-   support-
mail-   smtp-   imap-   pop3-       webmail-
ftp-    sftp-   vpn-    bastion-    jump-       remote-
proxy-  gateway- gw-    edge-       lb-         router-
db-     mysql-  pg-     redis-      mongo-      kafka-
git-    repo-   ci-     cd-         build-      jenkins-
mon-    monitoring- log- logs-      metrics-    grafana-
files-  storage- backup- archive-
```

Applied to seed `target.example`:
```
api.target.example
admin.target.example
internal.target.example
sso.target.example
mail.target.example
vpn.target.example
gateway.target.example
mon.target.example
backup.target.example
```

### Service suffixes

```
-api    .api
-admin  .admin
-internal .internal
-portal .portal
-app    .app
-www    .www
-cdn    .cdn
-files  .files
```

### Numeric variations

```
-1  -01  -001  1   01  001
-2  -02  -002  2   02  002
-v1 -v2  -v3   v1  v2  v3
-old -new -legacy -current -prev -next
```

Applied to seed `api.target.example`:
```
api-1.target.example
api-01.target.example
api1.target.example
api-v1.target.example
api-v2.target.example
api-old.target.example
api-new.target.example
api-legacy.target.example
```

Multi-digit numerics (`api-1.target.example` through `api-50.target.example`) are useful when the seed list reveals existing numbered hosts.

### Concatenation patterns (level-2 / level-3 stacking)

Permutations stack within hostnames:
```
dev.api.target.example
staging.admin.target.example
qa-internal.api.target.example
us-east.dev.api.target.example
```

Apply each prefix/suffix at each level: `<env>.<service>.<parent>` and `<region>-<env>.<service>.<parent>` and `<env>-<service>.<parent>`.

### Word-list mutators

Transformation rules applied to existing hostnames:

| Transformation | Example seed | Permutation |
|----------------|--------------|-------------|
| Insert hyphen | `apidev.target.example` | `api-dev.target.example` |
| Remove hyphen | `api-dev.target.example` | `apidev.target.example` |
| Swap delimiter | `api-dev.target.example` | `api.dev.target.example` |
| Reverse word order | `api-staging.target.example` | `staging-api.target.example` |
| Double prefix | `dev-api.target.example` | `dev-dev-api.target.example` |
| Pluralise | `service.target.example` | `services.target.example` |
| Singularise | `apis.target.example` | `api.target.example` |
| Lowercase variants | `API-DEV.target.example` | `api-dev.target.example` |
| Common typos | `admin.target.example` | `admn.target.example`, `addmin.target.example` |

### Cloud-naming permutations

Cloud asset names typically follow `<org>-<purpose>` patterns. Generate candidates aligned with bucket/storage hosting providers — most chain into the cloud-bucket dorking skill but the names themselves are also subdomain candidates (often via CNAME).

```
target-bucket           target-storage          target-cdn
target-static           target-assets           target-uploads
target-media            target-images           target-videos
target-backup           target-backups          target-archive
target-prod-data        target-dev-data         target-staging-data
target-logs             target-metrics          target-events
target-public           target-private          target-internal-files
```

Replace `target` with each org-name variant: `target`, `targetcorp`, `target-corp`, `target-inc`, `targetinc`, common abbreviations.

For S3-hosted subdomain CNAMEs:
```
assets.target.example -> target-assets.s3.amazonaws.com
static.target.example -> target-static.s3.us-west-2.amazonaws.com
```

The bucket name itself is a recon target (bucket misconfiguration), and the CNAME target is a candidate subdomain.

## Methodology

### Stage 1 — Convention Detection

Read the seed list and identify the org's naming convention. Examples of convention signals:

| Signal pattern in seeds | Inferred convention |
|-------------------------|---------------------|
| `api-dev.target.example`, `web-dev.target.example`, `auth-dev.target.example` | `<service>-<env>` is canonical |
| `dev.api.target.example`, `dev.web.target.example` | `<env>.<service>` is canonical |
| `api-us.target.example`, `web-eu.target.example` | Region suffix without env |
| `api1.target.example`, `api2.target.example` | Numeric scaling without delimiter |
| `gateway-prod-eu-1.target.example` | Multi-segment hyphenated |

Convention detection feeds permutation weighting in Stage 3 — seeds matching the canonical pattern run first.

### Stage 2 — Candidate Generation

```bash
SEEDS=seed_subdomains.txt
PARENT=target.example
OUT=candidates.txt

# alterx — pattern-based engine (ProjectDiscovery)
cat "$SEEDS" | alterx -enrich -o alterx.out

# gotator — word-list driven prepend/append
gotator -sub "$SEEDS" -perm wordlist.txt -depth 2 -mindup -adv > gotator.out

# dnsgen — Markov-chain-style mutations
dnsgen "$SEEDS" > dnsgen.out

cat alterx.out gotator.out dnsgen.out | sort -u > "$OUT"
wc -l "$OUT"
```

Each engine has different transformation rules — alterx is permutation-rich, gotator is wordlist-rich, dnsgen learns substring patterns. Run all three.

#### Manual permutation (LLM-driven)

When the org name has cultural / abbreviational variants, generate them explicitly:

```
Org name: "Target Corporation"
Variants: target, target-corp, targetcorp, tcorp, tc, target-co
```

Combine with the cloud-naming patterns and concatenation rules to seed additional candidates.

### Stage 3 — Resolution

Resolve every candidate through fast public resolvers in parallel.

```bash
puredns resolve "$OUT" \
  --resolvers /usr/share/resolvers/resolvers.txt \
  --rate-limit 10000 \
  --rate-limit-trusted 500 \
  -q -w resolved.txt
```

Or:

```bash
dnsx -l "$OUT" -resp -silent -t 200 -o resolved_dnsx.txt
```

`-t 200` runs 200 concurrent DNS queries. Tune to your resolver pool's capacity.

### Stage 4 — Wildcard Filter

Many domains use wildcard DNS — `*.target.example` resolves to a single IP regardless of name. Without filtering, every permutation appears "live" (false positive).

Detect wildcard:

```bash
# Generate a random hostname unlikely to exist
RAND=$(openssl rand -hex 16).target.example
WILDCARD_IP=$(dig +short A "$RAND")

if [ -n "$WILDCARD_IP" ]; then
  echo "[wildcard] $WILDCARD_IP — filtering candidates resolving to this IP"
fi
```

Filter resolved.txt by removing entries whose IP equals `$WILDCARD_IP`. Multiple wildcard IPs can exist (round-robin); test 5 random names and collect the full set.

### Stage 5 — Distinct-from-wildcard verification

Some legitimate subdomains share the wildcard IP (intentional). Verify via TLS handshake:

```bash
# Compare cert SAN list — wildcard cert vs name-specific cert
echo | openssl s_client -connect candidate.target.example:443 -servername candidate.target.example 2>/dev/null \
  | openssl x509 -noout -text \
  | grep -A1 'Subject Alternative Name'
```

If the cert SANs include `candidate.target.example` explicitly (not just `*.target.example`), the host is real. If only the wildcard SAN is present, the host may or may not be real — flag for HTTP probe (chain to active probe / port-service).

### Stage 6 — Recursive Expansion (multi-pass)

Newly resolved subdomains become seeds for the next pass. Repeat Stages 2–5 until a pass returns no new resolved names.

```bash
PASS=1
LAST_COUNT=0
while true; do
  echo "[pass $PASS]"
  # generate candidates from current seeds
  # resolve, filter wildcard, verify
  COUNT=$(wc -l < resolved_pass${PASS}.txt)
  if [ "$COUNT" -eq "$LAST_COUNT" ]; then
    break
  fi
  cat resolved_pass${PASS}.txt >> seeds_master.txt
  sort -u -o seeds_master.txt seeds_master.txt
  LAST_COUNT=$COUNT
  PASS=$((PASS+1))
done
```

Three passes are common; the second pass routinely yields 10-30% of the first pass; the third pass yields a long tail.

## Search Operators / Patterns

### alterx invocation patterns

```bash
# Default — auto-discover patterns from seeds
cat seeds.txt | alterx

# Enrich with built-in word lists
cat seeds.txt | alterx -enrich

# Custom pattern: {{word}}-{{sub}}.{{root}}
cat seeds.txt | alterx -p '{{word}}-{{sub}}.{{root}}' -pp 'word=dev,staging,qa,test,prod'

# Custom pattern: regional prefix + env + service
cat seeds.txt | alterx -p '{{region}}-{{env}}-{{sub}}.{{root}}' \
  -pp 'region=us,eu,ap' -pp 'env=dev,prod,staging'

# Limit recursion depth
cat seeds.txt | alterx -enrich -limit 100000
```

### gotator invocation patterns

```bash
gotator -sub seeds.txt -perm wordlist.txt > out.txt                          # single pass
gotator -sub seeds.txt -perm wordlist.txt -depth 3 -mindup -adv > out.txt    # combinatorial
gotator -sub seeds.txt -perm numbers.txt -numbers 2 > out.txt                # numeric only
```

### dnsgen invocation patterns

```bash
dnsgen seeds.txt > out.txt                          # Markov-style default
dnsgen -w mywordlist.txt seeds.txt > out.txt        # custom wordlist
```

### puredns / dnsx mass-resolution patterns

```bash
puredns resolve candidates.txt -r resolvers.txt -q --rate-limit 10000   # public resolvers
dnsx -l candidates.txt -resp -a -aaaa -cname -t 100 -silent             # multi-record type
```

### Wildcard detection one-liner

```bash
for i in 1 2 3 4 5; do
  R=$(openssl rand -hex 16).target.example
  echo "$R -> $(dig +short A $R)"
done | sort -u
```

## Decision Tree

```
seed list available?
├── NO → run recon_passive_subdomain first; stop
├── YES, < 5 names → recon_passive_subdomain probably incomplete; expand seeds first
└── YES, >= 5 names → continue

   ├── Stage 1 convention detection identifies a canonical pattern?
   │   ├── YES → weight permutations toward that pattern; still run all patterns
   │   └── NO → run all patterns equally
   │
   ├── Stage 2 candidate generation produces candidates?
   │   ├── YES → continue
   │   └── NO → seed list is too small or homogeneous; widen seed sources
   │
   ├── Stage 3 resolution returns ANY hits?
   │   ├── YES → continue to wildcard filter
   │   └── NO → resolver throttling? wrong nameservers? wildcard absorbing? investigate
   │
   ├── Stage 4 wildcard filter applied?
   │   ├── wildcard detected → filter applied
   │   ├── no wildcard → all resolved names are candidates
   │
   ├── Stage 5 verification distinguishes real hosts?
   │   ├── cert/HTTP confirms host → CONFIRMED
   │   └── shared wildcard, no cert evidence → CANDIDATE-UNVERIFIED (still test)
   │
   └── Stage 6 recursive expansion
       ├── new resolved names this pass > 0 → run another pass
       └── new resolved names this pass = 0 → stop
```

## Pitfalls

- **Wildcard DNS catches everything** — without Stage 4/5 filtering, every permutation looks alive. The downstream tools then waste time fuzzing nonexistent hosts. Always run wildcard detection before treating resolved candidates as real.
- **CDN absorbs all `*.target.example` queries** — Cloudflare, Akamai, Fastly often answer for any subdomain pointed at them. Cert SAN inspection is the definitive disambiguator: a cert with SAN `candidate.target.example` proves the host exists; a wildcard-only cert leaves the host status unknown.
- **DNS rate limits** — public resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9) throttle around 100-1000 qps per source IP. Use a rotating resolver pool (`resolvers.txt`) and a tool that supports it (puredns, dnsx with `-resolvers`). Resolver pool size of 50-200 is typical.
- **Combinatorial explosion** — full pattern × full seed × multi-depth mutations can produce tens of millions of candidates. Cap depth at 2 or 3, dedup before resolving, and shard candidate files for parallel resolvers.
- **Convention drift** — the org may have multiple naming conventions (mergers, acquisitions, legacy systems). Permutation weighted to one convention misses the others. Run all patterns even when one convention dominates.
- **Punycode / IDN names** — international subdomains use `xn--` form. Permutation engines that operate on ASCII won't generate IDN candidates. If the org uses IDN, generate variants manually.
- **Numeric range walking** — `api-1` through `api-99` may all resolve, but most are duplicates of one canonical IP. After resolving, dedup by IP and keep one representative per cluster.
- **Stale wildcard IP** — wildcard IP can change between runs. Re-detect at the start of each engagement.
- **DNS poisoning / lying resolvers** — some upstream resolvers fabricate NXDOMAIN responses (parental filter ISPs) or return constant catchall IPs (hotel DNS). Verify resolver health before mass-resolving.
- **Org-name false positives** — `target-corp.s3.amazonaws.com` may belong to a different "Target Corp" entirely. Verify via cert subject, ownership records, or domain-of-record before claiming the asset.
- **Cloud-storage permutations leak** — generating every `target-<word>` against S3 bucket-name resolution is its own recon path. Output the bucket-name candidates separately for `recon_cloud_bucket_dorking`.
- **CNAME-only resolution** — some hosts return CNAME without resolvable A/AAAA. They are still real (DNS layer says so) but unreachable for HTTP. Record them; downstream skills decide whether to probe.
- **Resolver caching** — repeated queries to the same resolver return cached negatives. Vary resolvers and clear caches between passes.
- **Permutation engine overlap** — alterx, gotator, dnsgen produce overlapping outputs. Dedup after concatenation; the union covers more than any single tool.
- **Recursive expansion non-termination** — without a fixed-point check (no new names this pass), recursion can loop forever on permutations of permutations. Always cap at a small number of passes (3-5) plus a fixed-point check.

## Output Format

Each candidate is recorded as:

```json
{
  "candidate": "us-east-staging-api.target.example",
  "resolved": true,
  "ip": ["203.0.113.12"],
  "wildcard_ip": "203.0.113.99",
  "distinct_from_wildcard": true,
  "cert_san_match": true,
  "generated_from_pattern": "{{region}}-{{env}}-{{sub}}.{{root}}",
  "seed": "api.target.example",
  "pass": 1
}
```

Resolved candidates that are distinct from wildcard and have cert SAN match flow into the confirmed subdomain pool. Resolved candidates that share the wildcard IP and have no cert SAN match are flagged as CANDIDATE-UNVERIFIED — still worth HTTP probing because the wildcard backend may serve different content based on Host header (chain to vhost fuzzing).

Persist as JSONL.

## Composes With

- `recon_passive_subdomain` — passive results provide the initial seed list. Permutation amplifies the passive output by 5–50x in candidate volume.
- `recon_subdomain_active_brute` — pure brute force using a wordlist of common subdomains is complementary. Permutation expands an existing seed; brute force tries every word in a generic wordlist. Run both.
- `recon_vhost_fuzzing` — subdomains that resolve to the wildcard IP without a name-specific cert are vhost candidates. The wildcard backend may serve different content per Host header even though DNS gives the same answer.
- `recon_cloud_bucket_dorking` — cloud-naming permutations (`target-bucket`, `target-storage`) double as bucket-name candidates for S3/GCS/Azure.
- `recon_asn_network_mapping` — confirmed permutation hits resolve to IPs that may belong to ASNs the target owns. Once one IP is confirmed, every IP in that ASN is a candidate.
- `recon_port_service_analysis` — every confirmed permutation feeds port/service enumeration.

## Termination Policy

- Apply EVERY catalogued permutation pattern × every seed. No early-stopping after "patterns A and B produced enough." Each pattern catches different hosts.
- Run alterx, gotator, dnsgen all three. Engine output overlaps but is not identical; dedup after concat.
- DO NOT stop after the first pass. The second pass uses pass-1 results as seeds and routinely yields 10–30% of pass-1 volume in new names. The third pass yields the long tail.
- DO NOT stop because "the candidate count is huge." Big candidate files are the expected output. Resolution is fast (millions per minute with a tuned resolver pool); the cost is finite.
- DO NOT stop after wildcard detection finds a wildcard IP. Real hosts can share the wildcard IP — verify each one via cert SAN inspection or HTTP response delta against the wildcard backend.
- DO NOT skip the cloud-naming permutations even if the target uses on-prem infrastructure. Cloud assets are common shadow IT for any organisation.
- Continue until a recursive pass returns zero new resolved names AND every catalogued pattern has been applied AND every engine has run.
