---
name: deep-recon-loops
category: methodology
description: Recursive reconnaissance iteration with multi-layer discovery, historical data correlation, and technology fingerprinting chains
depends_on: []
---

# Deep Reconnaissance Loops

Recon is not a single pass. Each discovery round feeds the next. Recursive iteration uncovers assets invisible to a single sweep.

## When to Use

- Initial recon pass returned fewer than expected results
- Target has a large, complex infrastructure with many subdomains
- You suspect hidden assets behind CDNs, load balancers, or WAFs
- Historical data suggests the target has changed infrastructure recently
- Standard subdomain enumeration feels incomplete

## Methodology

### Loop 1: Broad Subdomain Discovery

Run multiple tools in parallel for maximum coverage:

1. **Passive sources**: subfinder, amass passive, crt.sh, SecurityTrails, VirusTotal
2. **DNS brute force**: puredns with SecLists DNS wordlist against resolved nameservers
3. **Permutation**: gotator or altdns generating permutations from discovered subdomains
4. **Certificate transparency**: crt.sh `%.target.com`, Censys certificates search

Merge and deduplicate results. This is your seed list for Loop 2.

### Loop 2: Depth Expansion (Level 2-3 Directories)

For each live host from Loop 1:

1. **Content discovery**: ffuf or feroxbuster with level 2-3 recursion (`/api/v1/`, `/admin/config/`)
2. **Wordlist enrichment**: extract path fragments from JS files, HTML comments, robots.txt, sitemap.xml
3. **Technology-specific paths**: append known paths for detected frameworks (Spring Actuator, Laravel debug, Django admin)
4. **Response analysis**: diff 200/301/302/403 responses; 403s are access-controlled, not absent

### Loop 3: Historical Data Correlation

Cross-reference current findings with historical snapshots:

1. **Wayback Machine**: waybackurls to find removed endpoints, old API versions, deprecated features
2. **GitHub history**: search target org repos for deleted files, old configs, removed secrets in commit diffs
3. **DNS history**: SecurityTrails historical DNS for old A/CNAME records pointing to decommissioned infra
4. **Google cache**: cached versions of pages since removed from production

Flag any historical asset that still resolves or returns non-404 responses.

### Loop 4: Technology Fingerprinting Chains

Use discovered technology to drive deeper recon:

1. **Identify stack**: Wappalyzer headers, error pages, default files, response headers
2. **Version-specific recon**: known vulnerable paths for detected versions (e.g., Spring Boot Actuator endpoints for Spring 2.x)
3. **Dependency mapping**: JS bundle analysis reveals frontend libraries, API client versions, internal service names
4. **Cloud fingerprinting**: S3 bucket naming patterns, Azure blob URLs, GCP storage paths derived from org name

### Loop 5: Feed Back and Iterate

New discoveries from Loops 2-4 become inputs for another pass:

- New subdomains found in JS bundles or historical data go back to Loop 1
- New technology detected triggers targeted content discovery in Loop 2
- Old endpoints from Wayback get probed for current accessibility

### Exit Criteria

Stop iterating when:

- Two consecutive loops produce zero new unique assets
- Coverage reaches diminishing returns (each loop adds <5% new findings)
- Time budget exhausted (set a hard cap before starting)

## Correlation Techniques

| Source A | Source B | Correlation |
|----------|----------|-------------|
| Wayback URLs | Current 200s | Forgotten endpoints still live |
| GitHub commits | Live endpoints | Removed features still accessible |
| DNS history | Port scans | Old IPs still hosting services |
| JS bundles | API discovery | Internal API routes exposed in client code |
| CT logs | Subdomain enum | Subdomains with certs but no DNS (stale, takeover candidate) |

## Depth vs Breadth Balance

- Loop 1-2: breadth-first (maximize asset discovery)
- Loop 3-4: depth-first (maximize intelligence per asset)
- Loop 5: targeted (only re-scan where new signal was found)

---

## Advanced Discovery Loops

The following loops extend the core methodology with patterns extracted from high-value disclosed reports. Each targets a class of hidden surface that standard subdomain/directory enumeration misses entirely.

### Loop 6: Archive Upload and Extraction Surface Discovery

Any product that accepts archive uploads (ZIP, TAR, RAR, NPM packages, Helm charts, Docker images, OCI bundles) has extraction code that is a path-traversal and RCE surface. This loop discovers those surfaces.

1. **Enumerate upload features**: crawl every file-upload endpoint, form, and API. Note which accept archives vs single files
2. **Identify extraction behaviors**: upload a benign archive and observe — does the server extract it? List contents? Preview files? Parse manifests?
3. **Test with canonical Zip Slip PoCs**: use the Snyk Zip Slip test archives (https://github.com/snyk/zip-slip-vulnerability) against every extraction endpoint. Vary archive formats (ZIP, TAR, TAR.GZ, JAR, WAR, APK)
4. **Map post-extraction surfaces**: when extraction succeeds, probe the extracted file namespace — can you access extracted files via URL? Are they served with executable content types?
5. **Check nested archives**: some parsers extract recursively. A ZIP containing a TAR containing a symlink traversal bypasses single-layer defenses

**Key signal**: any endpoint that accepts an archive and performs server-side operations on its contents is a high-value target regardless of the endpoint's stated purpose (CI artifact upload, plugin install, theme import, data import).

### Loop 7: Differential Behavior Auditing Across Variants

When a target runs on or integrates with forks, L2s, clones, or multi-chain deployments, behavioral differences between variants are a discovery surface.

1. **Enumerate variants**: identify all forks, L2 deployments, EVM-equivalent chains, multi-region instances, or white-label deployments of the target
2. **Map opcode/feature divergence**: for EVM targets, diff supported opcodes (e.g., `SELFDESTRUCT`, `PUSH0`, `BLOBHASH`). For web targets, diff feature flags, API capabilities, and middleware stacks across regions/instances
3. **Test equivalent operations on each variant**: the same transaction/request may produce different outcomes on different variants. The delta IS the vulnerability
4. **Check assumption propagation**: code written for Variant A may assume behaviors that Variant B does not guarantee (e.g., assuming `SELFDESTRUCT` is a no-op on an L2 where it actually mutates state)
5. **Prioritize state-mutating divergences**: read-only differences are low impact. Focus on operations where variants disagree on state changes, balance modifications, or access control outcomes

**Key signal**: any documentation that says "equivalent to X" or "compatible with Y" is asserting behavioral identity — test that assertion exhaustively.

### Loop 8: CI/CD Workflow Enumeration on Public Repos

Public repositories expose CI/CD configurations that reveal internal infrastructure, secret naming conventions, deployment targets, and injectable workflow inputs.

1. **Enumerate workflow files**: scan `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, `.circleci/config.yml`, `bitbucket-pipelines.yml`, `.travis.yml` in every in-scope repository
2. **Extract environment references**: grep for `${{ secrets.* }}`, `${{ env.* }}`, `${{ github.event.* }}` — these reveal secret names, internal service hostnames, deployment URLs
3. **Map injectable inputs**: identify workflows triggered by `pull_request_target`, `issue_comment`, `workflow_dispatch` with user-controlled inputs. Trace each input through the workflow to find injection points (especially into `run:` steps)
4. **Check for artifact leakage**: workflows that upload artifacts, publish packages, or push to registries may expose internal build outputs
5. **Cross-reference deployment targets**: internal URLs, staging hostnames, and API endpoints referenced in CI configs are recon gold — add them to Loop 1 seed list

**Key signal**: any workflow that runs on external triggers (`pull_request_target`, `issue_comment`, fork PRs) with user-controlled data flowing into shell commands.

### Loop 9: Alternate-Surface Discovery on Multi-Product Platforms

Large platforms have multiple products sharing infrastructure. A vulnerability surface blocked on the primary product may be open on an alternate product.

1. **Enumerate all products/surfaces**: for the target org, list every product, service, mobile app, browser extension, desktop client, CLI tool, and internal tool that shares the same auth domain or API backend
2. **Map shared infrastructure**: identify which products share session cookies, OAuth tokens, API gateways, CDN configs, or storage backends
3. **Test cross-product token acceptance**: authenticate on Product A, use that token/cookie against Product B's API. Shared auth infrastructure means shared attack surface
4. **Check for "platform within a platform"**: subdomains hosting third-party content (marketplace iframes, add-on sandboxes, embedded editors, Canvas/Slides-style features) are XSS-to-ATO escalation paths because they share the parent domain's cookie scope
5. **Audit less-tested surfaces**: admin panels, partner portals, developer consoles, and internal tools receive less security attention than the primary product. They often share the same backend but with weaker access controls

**Key signal**: any subdomain or product that shares cookies/tokens with the primary target but has its own distinct codebase or feature set.

### Loop 10: Mobile App Binary Analysis for API Discovery

Mobile apps contain hardcoded API endpoints, internal hostnames, debug flags, and authentication flows that are invisible from web-only recon.

1. **Obtain APKs/IPAs**: download from app stores, or use `apktool`/`jadx` on cached versions. Check for multiple app variants (beta, enterprise, regional)
2. **Extract strings**: `strings` on the binary, then filter for URLs, hostnames, API paths, secret prefixes (`sk_`, `api_`, `token_`)
3. **Decompile and grep**: use `jadx` (Android) or `class-dump`/Hopper (iOS) to recover source. Search for `BaseURL`, `API_ENDPOINT`, `STAGING_URL`, internal service names
4. **Map API surface**: extracted endpoints often include internal/admin APIs, staging endpoints, and deprecated versions not exposed via the web app. Add every unique hostname/path to the recon seed list
5. **Check certificate pinning bypass paths**: if the app pins certificates, the pinning config itself reveals which domains the app communicates with (more recon signal)
6. **Diff app versions**: download multiple versions from APKMirror/Wayback. Diff strings and decompiled code — removed endpoints and deprecated features may still be live server-side

### Loop 11: Third-Party Domain Scope Expansion

Acquired companies, partner integrations, and third-party services often remain in scope but are invisible to standard recon.

1. **Enumerate acquisitions**: search Crunchbase, Wikipedia, press releases for every company the target has acquired. Each acquisition's original domains are recon targets
2. **Check acquired infrastructure**: acquired domains rarely get fully migrated. Old admin panels, staging servers, and forgotten APIs persist on the original domain with the acquirer's production credentials or SSO
3. **Map third-party integrations**: OAuth callbacks, webhook endpoints, payment processor redirects, and CDN origins are trust boundaries. Each third-party domain that handles target data is a surface
4. **Test scope boundaries**: for bug bounty programs with wildcard scope (`*.target.com`), check whether acquired-company subdomains have been migrated under the wildcard. If not, they may still be in scope under the original domain
5. **Port-scan owned IP ranges**: large organizations own IP blocks (check ARIN/RIPE/APNIC WHOIS). Systematic port scanning of owned ranges reveals forgotten services, internal tools exposed to the internet, and shadow IT

**Key signal**: any domain that shares SSO, cookies, or API tokens with the primary target is functionally in-scope regardless of what the bounty brief says about "out of scope" domains.

### Loop 12: Patch-Bypass and Variant Discovery Loop

Published security advisories and accepted bug reports are a map to under-tested code paths.

1. **Monitor advisories**: for in-scope targets, track CVEs, changelogs, and security advisories. Each patch addresses a specific attack — read the patch diff to understand what was fixed and what was NOT fixed
2. **Test bypass variants**: patches typically block the reported vector. Test adjacent vectors: different encoding, different entry point, different parameter, different HTTP method, race condition around the patch
3. **Re-enumerate the patched flow**: an accepted finding means the entire flow was under-tested. Re-enumerate every mutation primitive (edit, delete, transfer, export) in the same feature for the same vulnerability class
4. **Check for incomplete sanitization**: when a fix blocklists a specific tag/payload, enumerate all other tags/payloads that survive the sanitizer. Sanitization fixes are rarely exhaustive on first pass
5. **Hunt variant classes**: if one endpoint had SQLi, test every other endpoint that uses the same query pattern. If one parser had path traversal, test every other parser in the same codebase

**Key signal**: the existence of a past vulnerability in a code path is strong evidence that adjacent code paths have similar issues.
