---
name: subdomain-takeover
description: Subdomain takeover testing for dangling DNS records and unclaimed cloud resources
depends_on: []
---

# Subdomain Takeover

Subdomain takeover lets an attacker serve content from a trusted subdomain by claiming resources referenced by dangling DNS (CNAME/A/ALIAS/NS) or mis-bound provider configurations. Consequences include phishing on a trusted origin, cookie and CORS pivot, OAuth redirect abuse, and CDN cache poisoning.

## Discovery Signals

| # | Signal | Where to Find | Why Vulnerable |
|---|--------|---------------|----------------|
| 1 | CNAME to decommissioned SaaS | `dig CNAME sub.target.com` | Service tenant deleted, DNS record persists |
| 2 | NXDOMAIN on CNAME target domain | Resolve the CNAME chain terminal | Target domain expired or never registered |
| 3 | 404 with provider branding | `curl -sI https://sub.target.com` | Resource unclaimed on active provider |
| 4 | Expired domain in NS delegation | WHOIS on NS target domains | Register domain to control entire subzone |
| 5 | Wildcard CNAME to cloud provider | `dig *.target.com` or test random prefix | Every nonexistent sub-sub is claimable |
| 6 | A record pointing to released elastic IP | `dig A sub.target.com` then verify IP owner | Reallocate the IP in same cloud region |
| 7 | MX to abandoned mail provider | `dig MX sub.target.com` | Claim account to intercept email |
| 8 | TLS cert CN/SAN shows provider default | `openssl s_client -connect sub.target.com:443` | Custom domain not bound, provider default served |
| 9 | Orphan TXT verification records | `dig TXT _dnsauth.sub.target.com` | Proves prior binding existed, check if still claimed |
| 10 | CNAME to purchasable domain | WHOIS on CNAME target | Buy domain to inherit all DNS traffic |
| 11 | S3 bucket ref in HTML/JS returns NoSuchBucket | Crawl page source for `s3.amazonaws.com` | Create bucket with exact name, serve content |
| 12 | GitHub org/repo in source code is 404 | `org:<target>` code search for cloud hostnames | Register matching resource to serve attacker code |
| 13 | Hardcoded S3/cloud URL in CI scripts | Grep CI/Dockerfiles for `s3.amazonaws.com` URLs | Deprovisioned bucket = supply-chain takeover ($5K) |
| 14 | Marketing platform CNAME (Brandpad, Unbounce, HubSpot) | `dig CNAME` on brand/landing subdomains | Marketing team subdomains outlive campaigns ($750) |
| 15 | Acquired company domain still in DNS | M&A news + historical WHOIS/DNS | Acquisition domains inherit dangling pointers ($100-$500) |
| 16 | SRV record to decommissioned host | `dig SRV _sip._tcp.target.com` | Claim target to intercept VoIP/XMPP service discovery |
| 17 | EC2 elastic IP in A record after termination | `dig A` + verify IP ownership via `whois` | Allocate IPs in same region until target IP acquired |

## Provider Takeover Matrix

| Provider | Fingerprint (HTTP response) | CNAME Pattern | Takeover Method | Verification Req? | Difficulty |
|----------|----------------------------|---------------|-----------------|-------------------|------------|
| GitHub Pages | "There isn't a GitHub Pages site here." | `*.github.io` | Create repo, add CNAME file with target domain | No | Low |
| Heroku | "No such app" / "There's nothing here, yet." | `*.herokudns.com`, `*.herokuapp.com` | `heroku create`, add custom domain | No | Low |
| AWS S3 (website) | "NoSuchBucket" / "The specified bucket does not exist" | `*.s3.amazonaws.com`, `*.s3-website-*.amazonaws.com` | Create bucket matching subdomain name | No | Low |
| AWS CloudFront | "Bad Request" / "The request could not be satisfied" (403) | `*.cloudfront.net` | Create distribution, add alternate domain name | No (but uniqueness) | Medium |
| Azure App Service | "404 Web Site not found" (default IIS page) | `*.azurewebsites.net` | Create web app with matching name | No | Low |
| Azure Traffic Mgr | "This page has been parked free" | `*.trafficmanager.net` | Create Traffic Manager profile with matching name | No | Low |
| Fastly | "Fastly error: unknown domain:" | CNAME to Fastly IP ranges | Create service, add domain as backend | No | Medium |
| Shopify | "Sorry, this shop is currently unavailable." | `shops.myshopify.com` | Create store, add custom domain | Yes (DNS) | Medium |
| Tumblr | "There's nothing here." / "Whatever you were looking for doesn't currently exist" | `*.tumblr.com`, `domains.tumblr.com` | Create blog, add custom domain | No | Low |
| WordPress.com | "Do you want to register *.wordpress.com?" | `*.wordpress.com` | Create site with matching subdomain | No | Low |
| Pantheon | "404 error unknown site!" | `*.pantheonsite.io` | Create site with matching name | No | Low |
| Cargo Collective | "404 Not Found" (Cargo-branded) | `*.cargocollective.com` | Create account, claim domain | No | Low |
| Zendesk | "Help Center Closed" / Zendesk-branded 404 | `*.zendesk.com` | Create account, add custom domain | Yes (TXT) | Medium |
| Unbounce | "The requested URL was not found on this server." | `unbouncepages.com` | Create account, add landing page domain | No | Low |
| Surge.sh | "project not found" | `*.surge.sh` | `surge --domain sub.target.com` | No | Low |
| Bitbucket | "Repository not found" | `*.bitbucket.io` | Create repo with matching name | No | Low |
| Ghost | "404" (Ghost default) | `*.ghost.io` | Create publication, add custom domain | No | Low |
| Netlify | "Not Found - Request ID:" | `*.netlify.app`, `*.netlify.com` | Create site, add custom domain | Yes (TXT) | Medium |
| Fly.io | "404 Not Found" (Fly default) | `*.fly.dev` | `fly apps create`, add certificate | No | Low |
| Vercel | "404: NOT_FOUND" | `*.vercel.app`, `cname.vercel-dns.com` | Add domain in project settings | Yes (TXT) | Medium |
| Google Cloud Storage | "NoSuchBucket" (XML) | `*.storage.googleapis.com` | Create bucket with matching name | No | Low |
| Firebase Hosting | "Site Not Found" | `*.web.app`, `*.firebaseapp.com` | Create project, add custom domain | Yes (TXT) | Medium |
| Webflow | "404" (Webflow default) | `proxy-ssl.webflow.com` | Create site, add custom domain in hosting settings | No (CNAME = proof) | Low |
| Wix | Default Wix 404 / unclaimed page | Wix CDN endpoints | Create site, claim domain | No | Low |
| HubSpot | "is not available" / "trying to find your account" | `*.hubspot.net`, `*.hs-sites.com` | Create tenant, add custom domain | No | Low |

## Attack Surface

- Dangling CNAME/A/ALIAS to third-party services (hosting, storage, serverless, CDN)
- Orphaned NS delegations (child zones with abandoned/expired nameservers)
- Decommissioned SaaS integrations (support, docs, marketing, forms) referenced via CNAME
- CDN "alternate domain" mappings (CloudFront/Fastly/Azure CDN) lacking ownership verification
- Storage and static hosting endpoints (S3/Blob/GCS buckets, GitHub/GitLab Pages)

## Reconnaissance

### Enumeration Pipeline

- Subdomain inventory: combine CT (crt.sh APIs), passive DNS sources, in-house asset lists, IaC/terraform outputs
- Resolver sweep: use IPv4/IPv6-aware resolvers; track NXDOMAIN vs SERVFAIL vs provider-branded 4xx/5xx
- Record graph: build a CNAME graph and collapse chains to identify external endpoints

### DNS Indicators

- CNAME targets ending in provider domains: `github.io`, `amazonaws.com`, `cloudfront.net`, `azurewebsites.net`, `blob.core.windows.net`, `fastly.net`, `vercel.app`, `netlify.app`, `herokudns.com`, `trafficmanager.net`, `azureedge.net`, `akamaized.net`
- Orphaned NS: subzone delegated to nameservers on a domain that has expired or no longer hosts authoritative servers
- MX to third-party mail providers with decommissioned domains
- TXT/verification artifacts (`asuid`, `_dnsauth`, `_github-pages-challenge`) suggesting previous external bindings

### HTTP Fingerprints

Service-specific unclaimed messages (examples):
- **GitHub Pages**: "There isn't a GitHub Pages site here."
- **Fastly**: "Fastly error: unknown domain"
- **Heroku**: "No such app" or "There's nothing here, yet."
- **S3 static site**: "NoSuchBucket" / "The specified bucket does not exist"
- **CloudFront**: 403/400 with "The request could not be satisfied"
- **Azure App Service**: default 404 for azurewebsites.net unless custom-domain verified
- **Shopify**: "Sorry, this shop is currently unavailable"

TLS clues: certificate CN/SAN referencing provider default host instead of the custom subdomain

## Key Vulnerabilities

### Claim Third-Party Resource

- Create the resource with the exact required name:
  - Storage/hosting: S3 bucket "sub.example.com" (website endpoint)
  - Pages hosting: create repo/site and add the custom domain
  - Serverless/app hosting: create app/site matching the target hostname

### CDN Alternate Domains

- Add the victim subdomain as an alternate domain on your CDN distribution if the provider does not enforce domain ownership checks
- Upload a TLS cert or use managed cert issuance

### NS Delegation Takeover

- If a child zone is delegated to nameservers under an expired domain, register that domain and host authoritative NS
- Publish records to control all hosts under the delegated subzone

### Mail Surface

- If MX points to a decommissioned provider, takeover could enable email receipt for that subdomain

## Edge-Case Takeover Patterns

**Wildcard CNAME takeover**: `*.example.com` CNAMEs to a provider. Every nonexistent sub-subdomain resolves to the provider. Claim one resource and serve content on infinite subdomains. Test with `dig random123.target.com`.

**A-record takeover via elastic IP release**: When a cloud VM is terminated, its elastic/static IP returns to the provider pool. If a DNS A record still points to it, allocate IPs in the same region until you get the target IP. Works on AWS, GCP, Azure.

**MX record takeover for email interception**: Dangling MX to a decommissioned mail SaaS (Mailgun, SendGrid, Google Workspace) lets an attacker receive email for that subdomain. Enables password reset interception, domain verification bypass, and SPF-passing phish.

**TXT record abuse for domain verification bypass**: Leftover `_dnsauth`, `google-site-verification`, or `_github-pages-challenge` TXT records may satisfy ownership checks on other services. An attacker who controls a different verification endpoint can piggyback on stale TXT records.

**Partial CNAME chain takeover**: `a.target.com` CNAMEs to `b.vendor.com` which CNAMEs to `c.cdn.com`. If `b.vendor.com` is dangling (even though `c.cdn.com` is active), claim the intermediate hop to intercept the chain.

**NS delegation takeover (step-by-step)**: (1) `dig NS sub.target.com` shows `ns1.expired-domain.com`, (2) WHOIS confirms `expired-domain.com` is available, (3) register `expired-domain.com`, (4) configure authoritative DNS on `ns1.expired-domain.com`, (5) publish any record under `sub.target.com` -- full control of entire subzone including A, MX, TXT.

**SRV record takeover**: `_sip._tcp.target.com` SRV points to a decommissioned host. Claim the target to intercept service discovery for VoIP, XMPP, or other SRV-dependent protocols.

**CI/CD supply-chain takeover ($5K)**: Grep target's public repos for hardcoded cloud URLs in CI scripts, Dockerfiles, and Makefiles. Regex: `https?://[^\s]*\.(s3[.-].*\.amazonaws\.com|cloudfront\.net|azureedge\.net|github\.io)`. For each matched S3 URL, `aws s3api head-bucket --bucket NAME` -- if `NoSuchBucket`, claim the bucket name and serve backdoored dependencies. Forked repos carry the parent's dangling references.

**Feature-flag bypass for custom domain claims ($1.1K)**: When a SaaS gates a feature behind client-side flags, intercept and flip them (mitmproxy). If the server-side check was removed, attacker can register custom domains on platform-owned wildcards (`*.r2.dev`, `*.netlify.app`). Test: can a tenant claim a hostname they do not own? Can they claim a platform-owned hostname?

## Impact Escalation Techniques

| # | Escalation | Technique | Severity Upgrade |
|---|-----------|-----------|-----------------|
| 1 | Cookie theft | Parent sets `Domain=.target.com` cookies; takeover subdomain JS reads non-HttpOnly tokens | Medium to High |
| 2 | CSP bypass | Subdomain listed in `script-src` or `default-src`; serve malicious JS from taken-over origin | Medium to High/Critical |
| 3 | OAuth redirect_uri abuse | Subdomain whitelisted as OAuth callback; intercept authorization codes/tokens | Medium to Critical |
| 4 | Email interception (MX) | Receive password-reset emails; chain to account takeover on any service using that email | Medium to Critical |
| 5 | CORS trust exploitation | Parent API allows `Origin: https://sub.target.com`; exfiltrate API responses cross-origin | Medium to High |
| 6 | SSL cert issuance | Issue a DV certificate for the subdomain; proves control and enables HTTPS phishing | PoC evidence (any) |
| 7 | postMessage trust | Parent window accepts messages from `*.target.com`; send crafted postMessage from taken-over sub | Medium to High |
| 8 | Service Worker persistence | Register a SW on the taken-over subdomain; persists attacker code even after DNS fix if same scope | High escalation |

## Advanced Techniques

### Blind and Cache Channels

- CDN edge behavior: 404/421 vs 403 differentials reveal whether an alt name is partially configured
- Cache poisoning: once taken over, exploit cache keys to persist malicious responses

### CT and TLS

- Use CT logs to detect unexpected certificate issuance for your subdomain
- For PoC, issue a DV cert post-takeover (within scope) to produce verifiable evidence

### OAuth and Trust Chains

- If the subdomain is whitelisted as an OAuth redirect/callback or in CSP/script-src, takeover elevates to account takeover or script injection

### Verification Gaps

- Look for providers that accept domain binding prior to TXT verification
- Race windows: re-claim resource names immediately after victim deletion

### Wildcards and Fallbacks

- Wildcard CNAMEs to providers may expose unbounded subdomains
- Fallback origins: CDNs configured with multiple origins may expose unknown-domain responses

## Special Contexts

### Storage and Static

- S3/GCS/Azure Blob static sites: bucket naming constraints dictate whether a bucket can match hostname
- Website vs API endpoints differ in claimability and fingerprints

### Serverless and Hosting

- GitHub/GitLab Pages, Netlify, Vercel, Azure Static Web Apps: domain binding flows vary
- Most require TXT now, but historical projects may not

### CDN and Edge

- CloudFront/Fastly/Azure CDN/Akamai: alternate domain verification differs
- Some products historically allowed alt-domain claims without proof

### DNS Delegations

- Child-zone NS delegations outrank parent records
- Control of delegated NS yields full control of all hosts below that label

## Automation Pipeline

```bash
# 1. Enumerate subdomains from multiple sources
subfinder -d target.com -all -o subs.txt
amass enum -passive -d target.com >> subs.txt
sort -u subs.txt -o subs.txt

# 2. Resolve DNS and extract CNAMEs
cat subs.txt | dnsx -resp -cname -o dns_cnames.txt

# 3. Probe HTTP for fingerprints (status, title, body hash)
cat subs.txt | httpx -sc -title -server -td -o http_probes.txt

# 4. Run nuclei takeover templates
cat subs.txt | nuclei -t http/takeovers/ -o takeover_hits.txt

# 5. Targeted checks with subjack / subzy
subjack -w subs.txt -t 50 -timeout 30 -ssl -o subjack_results.txt

# 6. Check can-i-take-over-xyz fingerprints against CNAME targets
# Reference: github.com/EdOverflow/can-i-take-over-xyz

# 7. Hardcoded cloud asset grep (S3/GCS/Azure refs in source)
# GitHub: org:<target> "s3.amazonaws.com" OR "blob.core.windows.net"
```

## Testing Methodology

1. **Enumerate subdomains** - Aggregate CT logs, passive DNS, and org inventory
2. **Resolve DNS** - All RR types: A/AAAA, CNAME, NS, MX, TXT; keep CNAME chains
3. **HTTP/TLS probe** - Capture status, body, error text, Server headers, certificate SANs
4. **Fingerprint providers** - Map known "unclaimed/missing resource" signatures
5. **Attempt claim** (with authorization) - Create missing resource with exact required name
6. **Validate control** - Serve minimal unique payload; confirm over HTTPS

## Validation

1. Before: record DNS chain, HTTP response (status/body length/fingerprint), and TLS details
2. After claim: serve unique content and verify over HTTPS at the target subdomain
3. Optional: issue a DV certificate (legal scope) and reference CT entry as evidence
4. Demonstrate impact chains (CSP/script-src trust, OAuth redirect acceptance, cookie Domain scoping)

## False Positives

- "Unknown domain" pages that are not claimable due to enforced TXT/ownership checks
- Provider-branded default pages for valid, owned resources (not a takeover)
- Soft 404s from your own infrastructure or catch-all vhosts

## Impact

- Content injection under trusted subdomain: phishing, malware delivery, brand damage
- Cookie and CORS pivot: if parent site sets Domain-scoped cookies or allows subdomain origins
- OAuth/SSO abuse via whitelisted redirect URIs
- Email delivery manipulation for subdomain

## Pro Tips

1. Build a pipeline: enumerate (subfinder/amass) -> resolve (dnsx) -> probe (httpx) -> fingerprint (nuclei/custom) -> verify claims
2. Maintain a current fingerprint corpus; provider messages change frequently
3. Prefer minimal PoCs: static "ownership proof" page and, where allowed, DV cert issuance
4. Monitor CT for unexpected certs on your subdomains
5. Eliminate dangling DNS in decommission workflows first
6. For NS delegations, treat any expired nameserver domain as critical
7. Use CAA to limit certificate issuance while you triage
8. **Race condition on deletion**: monitor target's DNS changes; when a cloud resource is deleted, the DNS record often lags by hours -- claim the resource name within that window before cleanup
9. **Cloud IP recycling**: AWS/GCP/Azure return released elastic IPs to the pool. Script `allocate-address` in a loop in the same region to recapture a target's released IP for A-record takeover
10. **Passive DNS history**: SecurityTrails, VirusTotal passive DNS, and Farsight DNSDB reveal historical CNAMEs that were removed but may return. Hunt targets that had previous SaaS bindings
11. **Second-order takeover**: Service A CNAMEs to Service B which CNAMEs to Service C. If B is decommissioned, claim B to control A. Trace the full CNAME chain, not just the first hop
12. **CT monitoring for detection**: Subscribe to `certspotter.com` or `crt.sh` feeds for `*.target.com`. Unexpected cert issuance on a subdomain you don't use signals someone else claimed it
13. **IaC dangling references**: Grep Terraform state files and CloudFormation templates for `resource "aws_route53_record"` pointing to deleted resources. Terraform drift between state and live infra creates takeover windows
14. **Grep CI scripts for cloud URLs**: `org:<target> "s3.amazonaws.com"` on GitHub -- CI scripts with deprovisioned bucket refs are supply-chain takeovers, not just subdomain takeovers ($5K Reddit pattern)
15. **Acquisition recon**: subscribe to M&A news for your bounty targets; immediately enumerate the acquired entity's DNS for dangling records -- new acquisitions have the highest density of orphaned infra
16. **Marketing team subdomains**: marketing creates subdomains for campaigns (Brandpad, Unbounce, HubSpot, Instapage) and rarely cleans up after -- these are the most reliable repeat-find surface ($750)
17. **Government and public-sector scopes**: DoD/DHS/GSA programs have sprawling DNS footprints with the same dangling-CNAME patterns as commercial targets -- apply commercial-cloud takeover techniques unchanged
18. **Check ALL DNS record types, not just CNAME**: NS, MX, SRV, and A records all create takeover surfaces. NS takeover is the highest-severity (full subzone control); MX enables email interception for password resets
19. **Inventory drift is the root cause**: every decommissioned system that does not trigger DNS cleanup creates a takeover window. Frame reports around the lifecycle gap, not just the technical claim

## Summary

Subdomain safety is lifecycle safety: if DNS points at anything, you must own and verify the thing on every provider and product path. Remove or verify--there is no safe middle.
