---
name: dorking-orchestration
category: reconnaissance
description: Master playbook that chains all dorking skills (Google, GitHub, Shodan, FOFA, Pastebin, code search, Wayback, Postman, cloud buckets) into a single coordinated recon flow
depends_on: []
---

# Dorking Orchestration

No single dork surface is complete. Each finds a slice of what's leaked. The power comes from chaining them:

- `google_dorking` finds the admin panel URL
- `wayback_cdx_dorking` finds its prior versions
- `github_dorking` finds its original auth logic
- `code_search_dorking` finds customer integrations using it
- `postman_workspace_dorking` finds the internal API calls it depends on
- `pastebin_dorking` finds a recent credential dump
- `cloud_bucket_dorking` finds the deployment artifacts
- `fofa_zoomeye_dorking` finds the staging copy still running

This skill is the playbook — the order to run dorks and how to feed outputs into downstream skills.

## When to Use

- Every new target, before touching any live endpoint
- When re-engaging an old target (indexes change — revisit all surfaces)
- When a finding lead is thin (chain dorks to build context)
- Before submitting a report (check you haven't missed a higher-impact angle)

## The 90-Minute Dorking Sprint

A structured run through every surface. Total: ~90 minutes for a medium-sized target.

### Tier 0 — Setup (5 min)

1. Build the target's keyword list:
   - Primary domain + all variants (`target.com`, `targetcorp.com`, `target.io`)
   - Subsidiaries / acquisitions (check Crunchbase, Wikipedia)
   - Product codenames from the marketing site
   - Developer org names from GitHub (may differ from marketing name)
   - Common email format (`{firstname.lastname}@target.com`)
2. Create working directory with subdirs per skill:
   ```
   recon/target/
     google/ github/ shodan/ fofa/ wayback/
     pastebin/ postman/ buckets/ code_search/
     notes.md
   ```

### Tier 1 — Historical + Paste (15 min, fastest wins)

Run first because they are fast, don't hit the target, and shape later phases:

1. `wayback_cdx_dorking` — pull all historical URLs (`waybackurls`, CDX API)
   - Output: `wayback_urls.txt`, `wayback_params.txt`, `wayback_js.txt`
2. `pastebin_dorking` — search paste aggregators for target keywords
   - Output: paste URLs, leaked-credential candidates, internal URL hints

**Gate**: Before moving on, check `wayback_urls.txt` for endpoints not on live target.

### Tier 2 — Code + GitHub (20 min)

Run before Shodan/FOFA because code-level findings inform what to look for in infrastructure:

1. `github_dorking` — primary pass (org + employee accounts)
2. `code_search_dorking` — grep.app + Sourcegraph + PublicWWW (covers non-GitHub code + deployed JS)
3. `postman_workspace_dorking` — public Postman workspaces + documenter.getpostman.com

**Gate**: Extract all unique:
- Subdomains seen in code → feed to DNS resolution
- Parameter names seen in code → feed to endpoint_enum + content discovery
- API paths seen in code → feed to active testing

### Tier 3 — Google + Web Surface (15 min)

Run after code recon so you know what specific queries to ask Google:

1. `google_dorking` — general dorks + specific queries built from code-recon findings
2. Cross-reference with Bing / DuckDuckGo / Yandex (different index coverage)

### Tier 4 — Infrastructure (20 min)

Run after you have a comprehensive hostname / org-name list:

1. `shodan_dorking` — primary infrastructure fingerprinting
2. `fofa_zoomeye_dorking` — complementary coverage (20-40% unique hits)
3. `cloud_bucket_dorking` — AWS/GCP/Azure/DO permutations

### Tier 5 — Synthesis (15 min)

1. Cross-reference findings across tiers:
   - Does a Wayback URL appear in GitHub source? Probably current admin panel.
   - Does a FOFA-found IP match a Postman collection's `baseUrl`? Bingo — internal service exposed.
   - Does a Pastebin credential match a GitHub org name? Credential-stuffing candidate.
2. Write a `chains.md` in the working directory noting every cross-tier pivot
3. Feed all unique subdomains / URLs into live recon (DNS resolve + httpx fingerprint)

## Cross-Skill Data Flows

```
wayback_cdx  ───┐
                 ├──► unique_subdomains.txt ──► infrastructure scans
github_dorking ─┤                               (shodan/fofa/cloud_enum)
code_search ───┘

wayback_cdx  ───┐
                 ├──► param_names.txt ────────► content discovery
postman ────────┤                               (ffuf with -w)
github_dorking ─┘

github_dorking  ┐
                 ├──► credential_candidates ──► validation via login endpoints
pastebin ───────┤                               (ONE request per candidate — no brute force)
postman ────────┘

fofa + shodan  ┐
                ├──► exposed_services.txt ───► vuln assessment
                │                              (nuclei with CVE templates)
cloud_buckets ─┘
```

## Sample Target Keyword Expansion (example: "Target Corp")

Use this template — most orgs follow predictable variations:

```
# Domain variants
target.com, targetcorp.com, target.io, target-corp.com

# Subsidiary / acquisition
targetanalytics.com, target-labs.com, acqco.io

# Internal codenames (from marketing / careers page)
project-phoenix, target-ai, target-next

# Org slugs
github.com/target-corp, github.com/target-inc, github.com/targetcorp-oss

# Email formats
@target.com, @targetcorp.com, @target-labs.com, @targetanalytics.com

# Bucket naming guesses
target-prod, target-backups, target-logs, target-assets
targetcorp-prod, targetcorp-dev, targetcorp-qa
target-staging, target-qa, target-internal

# Favicon/cert anchors
# (compute hash, reuse across fofa/shodan/zoomeye)
```

## Sanity-Check Checklist

Before concluding recon is done, verify you have:

- [ ] Historical URLs from Wayback + CommonCrawl + URLScan (`wayback_cdx_dorking`)
- [ ] Credentials search on Pastebin + Psbdmp + IntelligenceX (`pastebin_dorking`)
- [ ] GitHub org + employee accounts searched (`github_dorking`)
- [ ] Code-search beyond GitHub (Sourcegraph + grep.app + PublicWWW) (`code_search_dorking`)
- [ ] Postman public workspaces searched (`postman_workspace_dorking`)
- [ ] Google/Bing/DuckDuckGo dorks run (`google_dorking`)
- [ ] Shodan infrastructure search (`shodan_dorking`)
- [ ] FOFA + ZoomEye + Quake (covers what Shodan misses) (`fofa_zoomeye_dorking`)
- [ ] S3 + GCS + Azure + DO Spaces permuted (`cloud_bucket_dorking`)
- [ ] Favicon hash computed and searched across FOFA + Shodan + ZoomEye
- [ ] Wayback URLs fed into ffuf for live reachability
- [ ] Parameter names fed into Arjun / ParamSpider
- [ ] All findings cross-referenced in `chains.md`

## What NOT to Do

1. **Don't run active scans (nmap/nuclei/ffuf) until passive recon is exhausted** — passive is free, passive is stealthy
2. **Don't skip the paste sites** — they're fast and often the highest-impact single source
3. **Don't trust a single engine** — Shodan + FOFA + ZoomEye disagree 40% of the time
4. **Don't ignore subsidiary names** — acquired companies often have weaker security than the parent
5. **Don't stop at the first finding** — early findings shape the keyword list for later phases
6. **Don't use credentials you find against production without authorization** — validate via login-check endpoints only

## Outputs You Should Have

After a full sprint:

| Output | Source | Use |
|--------|--------|-----|
| `subdomains.txt` | Wayback + Shodan + FOFA + cert-T | DNS-resolve → live host probing |
| `urls_historical.txt` | Wayback + CommonCrawl + gau | ffuf against live server |
| `params.txt` | CDX query strings + Postman + GitHub | Arjun / ParamSpider |
| `endpoints_internal.txt` | GitHub + Postman + Pastebin | Testing for auth / IDOR |
| `credentials_candidates.txt` | Pastebin + GitHub + Postman | Single-auth-check validation |
| `buckets_found.txt` | cloud_bucket_dorking output | Public-read / public-write test |
| `exposed_services.txt` | Shodan + FOFA + ZoomEye | Nuclei CVE templates |
| `chains.md` | Manual cross-referencing | Report writeup seed |

## Corpus-Derived Hunting Patterns

Cross-cutting techniques from high-bounty reports that span multiple dorking surfaces.

### Cache Poisoning Hunting Workflow

Cache poisoning ($500K+ individual payouts) requires a multi-dork approach:

1. **Identify the CDN** (Shodan/FOFA fingerprint, response headers) — different CDNs have different cache key behavior
2. **Brute-force unkeyed headers** — send requests with each header from a header wordlist and compare the response hash; any header that changes the response but is NOT in the cache key is a poisoning vector
3. **Cross-reference unkeyed headers against response reflection points** — if `X-Forwarded-Host` value appears in the HTML and is unkeyed, you have cache poisoning
4. Compose with `google_dorking` (find cacheable assets) and `code_search_dorking` (find CDN config in OSS)

### CI/CD Shared-Storage Tenancy Audit

When multiple tenants share a CI/CD backend (cache, artifact store, secrets):

1. Dork for CI config files that reference shared storage paths: `site:github.com "target-org" "cache-from" OR "cache-key" filetype:yml`
2. Test if tenant isolation is enforced by storage path naming — if the cache key is `$PROJECT_NAME-$BRANCH`, test path traversal via branch names like `../other-project-main`
3. Artifact stores with predictable URLs (`/artifacts/{project_id}/{job_id}/`) are IDOR candidates

### Kubernetes/Infrastructure Controller Audit

For any infrastructure operator/controller exposed on a target:

1. Dork for exposed operator endpoints: `site:target.com inurl:"/api/v1/" OR inurl:"/apis/"` plus Shodan `ssl.cert.subject.CN:target.com port:6443`
2. Map the controller's RBAC permissions — what ServiceAccount token does it use? Does it have cluster-admin?
3. If the controller accepts user input that flows into Kubernetes API calls (annotations, labels, ingress configs), test for injection into the API object

### Parser Differential Hunting (Multi-Surface)

When two systems in the request path parse the same data differently, security boundaries break:

1. Use `shodan_dorking` to identify the reverse proxy/LB/WAF in front of each target
2. Use `code_search_dorking` to find the origin's URL parsing code
3. Test characters that the frontend proxy normalizes differently from the backend: `%2f` (path separator), `\` (backslash), `;` (path parameter), `..` (traversal)
4. Any difference in URL interpretation between the cache layer and origin is a cache poisoning/deception vector

### Object-Cache Key Auditing

For any library or service that maintains a connection/session cache:

1. Identify the cache key (often: host + port + protocol)
2. List every security-relevant option that SHOULD be in the cache key but may not be (auth credentials, TLS client cert, proxy settings, tenant ID)
3. If an option is NOT in the cache key, two requests with different security contexts get the same cached connection — privilege escalation

## Tips

1. Keep a `notes.md` with one-line observations per surface — you'll miss patterns if you only save raw output
2. Re-run the sprint monthly on active bounty targets — indexes change, new leaks appear
3. If the program scope forbids some engines (e.g., "no active recon"), the passive dorks here are your entire toolkit — don't cut corners
4. Use `notify` + `slackbot` / email alerts for Wayback + Pastebin + Postman on high-value targets — leaks appear in real time
5. Invest in API keys for at least Shodan + FOFA + GitHub CLI + IntelligenceX — the time savings dwarf the cost on any paid program
6. When an engine is down, swap to its nearest alternative (Shodan → Censys → Odin; FOFA → Quake → ZoomEye)
7. Archive your findings to a private S3 bucket or `git`-based tracker — organizations delete leaks the moment they see your report, but not before
