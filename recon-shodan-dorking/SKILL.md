---
name: recon-shodan-dorking
category: reconnaissance
description: Methodology for hunting target infrastructure via Shodan banner/cert/favicon indexes — operators, SSL/favicon pivots, ASN expansion, multi-pass coverage
depends_on: []
---

# Recon Shodan Dorking

## Purpose

Shodan is fundamentally different from a web crawler. It does not follow links, scrape HTML, or render pages. It performs internet-wide port scans on a rolling schedule, captures the raw banner of every open service it finds, parses TLS handshakes for certificate details, fingerprints software versions, and stores the result in a queryable index. This means Shodan can reveal infrastructure that is invisible to crawlers: forgotten dev hosts that are not linked from anywhere, internal services that listened on a public IP for 5 minutes during a misconfiguration, RDP/SMB/Redis/Mongo/Elastic instances exposed by accident, IoT/industrial gear, printers, cameras, and entire shadow-IT zones the target's own asset team has lost track of.

This skill teaches the agent to:
1. Read Shodan's operator language fluently and combine operators for surgical queries.
2. Pivot from a single org-name to an exhaustive infrastructure map using TLS certificate subject-CN matching and favicon-hash matching.
3. Convert Shodan results back into ASN/CIDR ranges for downstream active-probe sweeps.
4. Survive query-credit exhaustion by ordering queries from highest-yield to lowest-yield.
5. Recognize and discount stale-banner false positives (Shodan re-scans hosts on a weekly-to-monthly cadence; a banner from 6 weeks ago may not reflect the live host).

## When to Use

- New target onboarding: build the first-pass external surface inventory.
- After passive subdomain enumeration: cross-reference subdomain → IP → service banner → unexpected port.
- When the target's web surface looks small/hardened: Shodan often reveals the unhardened back office (admin panels on weird ports, jump boxes, dev clones).
- When you suspect cloud sprawl: org-name search reveals AWS/GCP/Azure/Oracle assets the target owns directly under cloud provider org names.
- When the target has acquired companies: SSL cert subject-CN of the parent often appears on subsidiaries you did not know about.
- After finding a single IP from any other source (subdomain DNS, traceroute, header leak): pivot via ASN/net to discover the whole subnet.

## Inputs

- `target_apex` — the target's primary domain (e.g., `target.example`).
- `target_org_names[]` — every legal-entity name the target uses or has used (parent + subsidiaries + brand names + historical names). The recon agent should try multiple variants because Shodan's `org:` field is populated from WHOIS/RIR data and is inconsistent.
- `known_ips[]` — any IPs the agent has already discovered through other means (subfinder/dnsx output, prior runs).
- `known_certs[]` — any cert subject-CN values seen in passive DNS or CT logs.
- `shodan_api_key` — required for all API calls; agent must have a key configured. Free-tier keys are limited to 100 query credits/month.

## Methodology

### Stage 1: Operator Reference (load this into working memory before querying)

Shodan supports the following operators. Each operator is colon-separated. Operators can be combined with implicit AND (whitespace) and explicit `-` (NOT) prefix.

| Operator | What it filters | When to use | Placeholder example |
|---|---|---|---|
| `port:` | Open TCP/UDP port number | Narrow service-type sweeps; combine with `product:` | `port:9200 product:elasticsearch` |
| `hostname:` | Reverse-DNS hostname or PTR record | Find hosts whose PTR resolves under target.example | `hostname:target.example` |
| `org:` | WHOIS organization name from RIR | Top-level org-wide search | `org:"Target Example Inc"` |
| `country:` | 2-letter ISO country code | Geographic narrowing | `org:"Target Example Inc" country:US` |
| `city:` | City name (uppercase, country-context) | Combined with country | `org:"Target Example Inc" city:"Austin"` |
| `geo:` | Lat,lon[,radius_km] bounding | Lat/lon with optional radius | `geo:30.27,-97.74,50` |
| `os:` | Operating system fingerprint | Find legacy Windows boxes etc | `os:"Windows Server 2008"` |
| `product:` | Software product name | Service identification | `product:"docker registry"` |
| `version:` | Software version string | Combined with product, narrows to vulnerable versions | `product:apache version:"2.4.49"` |
| `asn:` | Autonomous System Number | Sweep entire AS allocation | `asn:AS00000` |
| `net:` | CIDR block | Surgical subnet sweep | `net:198.51.100.0/24` |
| `ssl:` | Free-text SSL cert search | Loose cert content match | `ssl:"target.example"` |
| `ssl.cert.subject.cn:` | Cert Subject Common Name (exact) | Cert pivot — most powerful | `ssl.cert.subject.cn:"target.example"` |
| `ssl.cert.subject.o:` | Cert Subject Organization | Cert pivot via legal name | `ssl.cert.subject.o:"Target Example Inc"` |
| `ssl.cert.issuer.cn:` | Cert Issuer Common Name | Find self-signed certs (issuer == subject) | `ssl.cert.issuer.cn:"target-internal-ca"` |
| `ssl.cert.expired:` | true/false expired flag | Find legacy hosts still alive | `ssl.cert.expired:true ssl.cert.subject.cn:"target.example"` |
| `ssl.cert.serial:` | Specific cert serial number | Pivot from a known cert | `ssl.cert.serial:0x0123456789abcdef` |
| `ssl.cipher.version:` | TLS protocol version (e.g. SSLv3) | Find weak/legacy TLS endpoints | `ssl.cipher.version:SSLv3` |
| `http.title:` | HTML <title> string | Find admin panels by title | `http.title:"Admin Login"` |
| `http.html:` | Free-text body match | Match in-page strings | `http.html:"Powered by Internal Wiki"` |
| `http.html_hash:` | Hash of HTTP body | Find clones of a page | `http.html_hash:-1565800538` |
| `http.component:` | Detected web framework | Find Drupal/WordPress/etc instances | `http.component:"drupal"` |
| `http.status:` | HTTP response code | Filter by status | `http.status:200` |
| `http.server:` | Server header value | Server fingerprint | `http.server:"nginx"` |
| `http.favicon.hash:` | mmh3 hash of /favicon.ico | Strongest pivot — see Stage 4 | `http.favicon.hash:-1234567890` |
| `tag:` | Pre-computed tag (cdn, cloud, vpn, ics, scada, malware, honeypot) | Filter or prioritize | `tag:cdn -tag:honeypot` |
| `vuln:` | CVE filter (Premium API only) | Direct CVE filtering | `vuln:CVE-2024-XXXXX` |
| `category:` | Built-in category (ics, malware, compromised) | Specialized hunting | `category:ics` |
| `before:` / `after:` | Date filter on banner timestamp (YYYY-MM-DD) | Constrain to recently-seen | `org:"Target Example Inc" after:2025-01-01` |

### Stage 2: Org-Name Discovery (don't skip — operator yields depend on getting the right name)

Before running `org:` queries, normalize the org names. Shodan stores `org` exactly as the RIR returns it. The agent should:

1. Pull WHOIS for `target_apex`'s primary IP (any A record). Note the OrgName/OrgID/NetName.
2. Pull WHOIS for any `known_ips[]` already discovered. Different IPs may show different org names because of historic re-allocations.
3. Search certificate transparency logs for the apex; note the Subject Organization field (O=).
4. Construct an `org_candidates[]` list: every distinct value from steps 1-3, plus common variants:
   - `"Target Example Inc"`, `"Target Example Inc."`, `"Target Example, Inc"`, `"Target Example, Inc."`
   - With and without trailing punctuation, with and without LLC/Ltd/GmbH/Pty/SA suffix
   - Brand vs legal name (target.example may legally be `"TGX Holdings LLC"`)
   - Acquired-subsidiary names (read About/Press pages on target.example for acquisition history)

Run a probe query for each candidate: `org:"<candidate>"` with `limit=1`. Discard candidates that return zero hits. Keep candidates that return any hits as confirmed `org_names[]`.

### Stage 3: Org-Wide Sweep (the broad foundation)

For each confirmed `org_name`, run the following sweep. Each query is a separate API call. DO NOT skip queries because earlier queries returned a lot of results — Shodan's UI defaults to 100-result pages and the agent must paginate.

```
# Stage 3.1: All assets
GET /shodan/host/search?key=<KEY>&query=org:"<org_name>"&page=1
# paginate until the matches list is shorter than the page size or page count = ceil(total/100)
```

Then narrow by service category to ensure rare services aren't drowned by web noise:

```
# Stage 3.2: All non-HTTP services (often the most interesting)
query: org:"<org_name>" -port:80 -port:443 -port:8080 -port:8443
# Stage 3.3: Database exposures
query: org:"<org_name>" (port:9200 OR port:27017 OR port:6379 OR port:5432 OR port:3306 OR port:11211 OR port:9300 OR port:5984 OR port:7474)
# Stage 3.4: Remote-access exposures
query: org:"<org_name>" (port:22 OR port:23 OR port:3389 OR port:5900 OR port:5901 OR port:5985 OR port:5986)
# Stage 3.5: Mail/file
query: org:"<org_name>" (port:21 OR port:25 OR port:110 OR port:143 OR port:445 OR port:139 OR port:993 OR port:995)
# Stage 3.6: Container/orchestration
query: org:"<org_name>" (product:"docker registry" OR port:2375 OR port:2376 OR port:2379 OR port:6443 OR port:10250)
# Stage 3.7: Industrial/SCADA (often left over from facilities)
query: org:"<org_name>" category:ics
# Stage 3.8: Tagged compromised/malware (rare but high-signal if hit)
query: org:"<org_name>" (tag:malware OR tag:compromised OR tag:cobaltstrike)
```

### Stage 4: SSL Certificate Pivot (highest-yield operator — never skip)

The `ssl.cert.subject.cn:` operator finds every host on the internet that is currently presenting a TLS certificate where the subject Common Name matches. This is more powerful than `org:` because:

- A host on a third-party CDN/cloud will show the CDN org but the cert subject is the target's domain.
- A new dev host that was never registered with the corporate RIR account will still present a cert generated from the target's automated cert pipeline.
- Wildcard certs reveal entire subdomain spaces that DNS enumeration missed.

Run these queries:

```
# Stage 4.1: Apex cert
query: ssl.cert.subject.cn:"target.example"
# Stage 4.2: Wildcard cert
query: ssl.cert.subject.cn:"*.target.example"
# Stage 4.3: Subject organization (catches certs not bound to the apex domain)
query: ssl.cert.subject.o:"Target Example Inc"
# Stage 4.4: Expired-but-present (legacy hosts still serving traffic)
query: ssl.cert.expired:true ssl.cert.subject.cn:"target.example"
# Stage 4.5: Self-signed internal CA leaks (if you discover an internal CA name from any source)
query: ssl.cert.issuer.cn:"target-internal-ca"
# Stage 4.6: For each known internal subdomain pattern, query the cert directly
query: ssl.cert.subject.cn:"target-internal.example"
query: ssl.cert.subject.cn:"target-staging.example"
query: ssl.cert.subject.cn:"target-dev.example"
```

For each SSL hit, record the IP and the full Subject Alternative Name (SAN) list — every SAN is potentially a new in-scope hostname.

### Stage 5: Favicon Hash Pivot (the second silver-bullet operator)

Shodan computes the mmh3 (MurmurHash3) hash of every host's `/favicon.ico` and stores it. Targets often deploy the same favicon across all their assets — main site, admin panels, status dashboards, internal tools, dev clones. Computing the favicon hash from the apex once and querying for it across the internet returns assets that share branding even when the hostname/cert/IP gives no clue.

Compute the favicon hash:

```python
import mmh3, base64, requests
r = requests.get("https://target.example/favicon.ico", timeout=10, verify=False)
favicon_b64 = base64.encodebytes(r.content)
favicon_hash = mmh3.hash(favicon_b64)
print(favicon_hash)  # signed 32-bit int — Shodan accepts negative values
```

Then query Shodan:

```
query: http.favicon.hash:<favicon_hash>
```

Iterate: for every site found that the agent confirms is target-related, fetch its favicon too — sometimes the dev clone uses an older favicon. Record every distinct hash and query each one.

Also try favicon hashes for known internal tools (e.g., if the agent discovers a Jenkins, Jira, GitLab, Grafana, Kibana, RabbitMQ Management instance during recon, the default favicon hashes for those tools are well-known and a hit on the target's IP space confirms an exposed instance).

### Stage 6: HTTP-Title and HTTP-HTML Sweeps

After org/cert/favicon establish a candidate IP space, run targeted HTTP-content sweeps:

```
# Admin/login panels
query: org:"<org_name>" (http.title:"admin" OR http.title:"login" OR http.title:"dashboard" OR http.title:"console")
# Common debug/dev endpoints
query: org:"<org_name>" (http.title:"phpinfo" OR http.title:"swagger" OR http.title:"actuator" OR http.title:"jenkins")
# Index-of directory listings
query: org:"<org_name>" http.title:"Index of /"
# Default install pages (frequently abandoned)
query: org:"<org_name>" (http.title:"Welcome to nginx" OR http.title:"Apache2 Default Page" OR http.title:"IIS")
# Specific framework signatures
query: org:"<org_name>" http.component:"drupal"
query: org:"<org_name>" http.component:"wordpress"
query: org:"<org_name>" http.html:"Powered by"
```

### Stage 7: ASN/Net Expansion (close the loop)

Take every distinct IP from Stages 3-6 and resolve it to an ASN. For target-owned ASNs (org name matches), sweep the entire AS:

```
query: asn:AS00000
```

For every CIDR allocated under the AS, sweep the CIDR. This catches services on IPs that did not have a TLS cert or HTTP component and were therefore invisible to certificate/favicon/title pivots.

```
query: net:198.51.100.0/24
```

Also reverse the direction: for every IP that hit during Stage 3-6, take the IP's `/24` and sweep it — neighboring IPs in the same subnet are extremely likely to belong to the same target.

### Stage 8: CVE / Vuln Sweep (Premium-only; degrade gracefully if free tier)

If the API key is Premium, the `vuln:` operator filters hosts where Shodan has tagged a known CVE. Run:

```
query: org:"<org_name>" has_vuln:true
```

Then for high-criticality CVEs that match products discovered in Stage 3 (e.g., if you found a `product:apache version:"2.4.49"`):

```
query: org:"<org_name>" vuln:CVE-2021-41773
```

If the API key is free tier, the `vuln:` operator returns 401 Unauthorized. Record this and use the `product:` + `version:` data from Stage 3 instead — match versions against the NIST NVD locally to identify probable CVE exposure.

## Search Operator Cookbook (combined-operator examples)

```
# All open Redis instances belonging to the target, with no auth (default install indicator)
org:"Target Example Inc" port:6379 -product:"Redis (auth required)"

# Exposed Elastic clusters with the cluster status visible
org:"Target Example Inc" port:9200 product:elasticsearch http.html:"\"cluster_name\""

# Internet-exposed Mongo instances responding to listDatabases
org:"Target Example Inc" port:27017 "MongoDB Server Information"

# Open Docker daemons (port 2375 unauthenticated)
org:"Target Example Inc" port:2375 product:Docker

# Kubernetes API servers exposed (anonymous read often possible)
org:"Target Example Inc" (port:6443 OR port:8443) http.title:"Kubernetes"

# Prometheus metrics endpoints exposed (often leak internal hostnames + service names)
org:"Target Example Inc" port:9090 "# HELP"

# Jenkins exposed with /script console accessible
org:"Target Example Inc" http.title:"Dashboard [Jenkins]"

# Spring Boot Actuator exposed (env/heapdump/jolokia)
org:"Target Example Inc" http.html:"\"_links\":" http.html:"actuator"

# Old self-hosted GitLab pre-CVE (version-specific)
org:"Target Example Inc" http.title:"GitLab" http.component:"gitlab"

# Memcached exposed UDP (amplification + data leak)
org:"Target Example Inc" port:11211

# RDP (3389) — combined with SSL cert pivot to find ALL target RDP regardless of org tag
ssl.cert.subject.cn:"target.example" port:3389

# Misconfigured S3-compatible storage front
org:"Target Example Inc" http.title:"403 Forbidden" http.html:"<ListBucketResult"

# Unauthenticated Solr admin panel
org:"Target Example Inc" http.title:"Solr Admin"
```

## Decision Tree

```
START
  │
  ├── shodan_api_key configured?
  │     ├── NO → record blocker; agent cannot proceed; do NOT silently skip — surface to user
  │     └── YES → continue
  │
  ├── target_apex provided?
  │     └── YES → run Stage 2 to derive org_names[]
  │
  ├── For each org_name → run Stage 3 (8 sub-queries) → record all IPs
  ├── Run Stage 4 SSL cert pivot (6 sub-queries) → record all IPs and SANs
  ├── Compute favicon hash → run Stage 5 → record all IPs
  ├── Run Stage 6 HTTP-content sweeps → record all IPs
  ├── Resolve all IPs to ASNs → run Stage 7 ASN/Net expansion
  ├── If Premium key → run Stage 8 CVE sweep
  ├── If free key → match product+version locally against NIST NVD
  │
  └── Aggregate → dedup by IP+port → output structured records
```

DO NOT short-circuit any stage based on volume of intermediate hits. Each stage covers a different visibility surface.

## Pitfalls

- **Stale banners.** Shodan re-scans most hosts on a 2-to-6-week cadence. A banner showing `port:9200 product:elasticsearch` is what Shodan saw last scan — the host may have been firewalled since. Treat Shodan as a candidate generator; confirm with active probe (see `recon_port_service_analysis`).
- **Query-credit exhaustion.** Free tier = 100 queries/month. The methodology above uses ~30-50 queries per target. If multiple targets are queued in one billing month, the agent will exhaust credits mid-pipeline. Order queries from highest-yield (Stages 4 + 5) to lowest-yield (Stage 6 specific titles) so partial completion still produces useful results.
- **Shared hosting false positives.** SSL cert subject `target.example` on an IP that hosts hundreds of unrelated certs probably means the cert is on a CDN/SaaS that the target merely uses, not infrastructure the target controls. Cross-check the IP's other certs — if it serves 50+ different orgs, it is shared hosting and out of scope for direct attack.
- **Cert subject mismatches.** Some orgs use a generic Subject CN like `*.cdn-provider.example` and put the real hostname only in the SAN. Always inspect SANs, not just CN.
- **Org-name drift.** RIR records lag behind acquisitions. A subsidiary that was acquired 6 months ago may still be under its old org name in Shodan. Always include known historical names.
- **Honeypots.** `tag:honeypot` exists. Combine with `-tag:honeypot` on every query so the agent doesn't waste time pivoting from a deception host.
- **Pagination silently truncates.** The default response includes only the first 100 matches and a `total` field. The agent MUST check `total` and paginate if `total > page_size * pages_fetched`. Without pagination, results past the first page are lost and the agent will believe the surface is smaller than it is.
- **Scan-on-demand confusion.** Shodan offers `/shodan/scan` to request a fresh scan of a target IP. This consumes scan credits (different from query credits) and is rate-limited. Do not call it for org-wide sweeps — only for confirming a specific candidate post-discovery.
- **Banner truncation.** Some banners exceed Shodan's storage cap and are truncated. The `data` field may not contain the full handshake response. For confirmation, active-probe the host directly.
- **IPv6 coverage gap.** Shodan's IPv6 scanning is dramatically less comprehensive than IPv4. If the target has IPv6 deployments, Shodan likely misses most of them. Combine with IPv6 scanning via DNS AAAA records and active probes.

## Output Format

Per-host record (one JSON object per row in the agent's notes file):

```json
{
  "ip": "198.51.100.42",
  "port": 9200,
  "transport": "tcp",
  "service": "elasticsearch",
  "product": "Elastic",
  "version": "7.10.2",
  "asn": "AS00000",
  "asn_name": "TARGET-EXAMPLE-AS",
  "org": "Target Example Inc",
  "country": "US",
  "city": "Austin",
  "ssl_cert_subject_cn": "target.example",
  "ssl_cert_subject_o": "Target Example Inc",
  "ssl_cert_subject_san": ["target.example", "*.target.example", "target-internal.example"],
  "ssl_cert_expired": false,
  "ssl_cert_serial": "0x0123456789abcdef",
  "http_title": null,
  "http_status": null,
  "http_server": null,
  "http_component": null,
  "http_favicon_hash": null,
  "tags": [],
  "last_seen": "2026-04-12T03:14:00Z",
  "banner_snippet": "{\"version\":{\"number\":\"7.10.2\"},\"cluster_name\":\"target-prod\"}",
  "discovery_query": "org:\"Target Example Inc\" port:9200 product:elasticsearch",
  "discovery_stage": "Stage 3.3"
}
```

Aggregate summary file:

```
hosts_total: <int>
hosts_by_stage: {Stage 3: <int>, Stage 4: <int>, Stage 5: <int>, Stage 6: <int>, Stage 7: <int>}
unique_ips: <int>
unique_subnets: <int>
asns_discovered: [<list>]
ssl_subjects_discovered: [<list>]
favicon_hashes_discovered: [<list>]
queries_consumed: <int>
queries_remaining: <int>
```

## Composes With

- `recon_asn_network_mapping` — Shodan returns IPs; ASN lookup expands IP → CIDR → adjacent neighbors that Shodan missed because they had no open ports during the last scan window.
- `recon_passive_subdomain` — SSL cert SANs returned by Shodan Stage 4 frequently contain hostnames that passive DNS sources never logged.
- `recon_port_service_analysis` — Shodan banner is stale; this skill's output feeds active probes that re-confirm the live state.
- `recon_archive_intel` — once an IP is confirmed live and serves HTTP, query Wayback/URLScan for archived URLs against the IP directly (bypassing hostname-only archive coverage).
- `recon_information_disclosure` — Shodan-discovered admin/debug panels become priority targets for the disclosure-path enumeration in that skill.
- `recon_content_discovery` — Shodan-discovered services with custom http.title or product give a hint about the right tech-specific wordlist for content fuzzing.

## Termination Policy

This skill terminates ONLY when ALL of the following are complete:

1. Stage 2 has been executed for every org_name candidate (no candidate skipped).
2. Stage 3 has executed all 8 sub-queries for every confirmed org_name, with full pagination on each.
3. Stage 4 has executed all 6 sub-queries (apex cert, wildcard, org cert, expired cert, internal CA, every known subdomain CN).
4. Stage 5 has computed the favicon hash for the apex AND for every distinct host found in Stages 3-4 that serves a different favicon, and queried each hash.
5. Stage 6 has executed at least the 8 sub-queries listed (admin/login titles, debug/dev titles, index-of, default install, framework components).
6. Stage 7 has executed `asn:` for every distinct ASN discovered AND `net:/24` for every distinct subnet (capped at 256 sweeps per target to control credit consumption — if the cap is reached, document the remaining subnets and continue).
7. Stage 8 has either run (Premium) or has been explicitly recorded as `degraded: free-tier; product+version exported for offline NVD match`.
8. The aggregate summary file is written and reflects the actual queries consumed.

DO NOT terminate early because:
- The first stage returned a lot of results — there are 8 stages and each surfaces different hosts.
- The free-tier credit count is low — the agent should still execute the highest-yield queries (Stages 4 + 5) and document credit exhaustion if it hits.
- The target "looks small" — Shodan often reveals an order of magnitude more infrastructure than the public web surface suggests.
- A previous run cached results — the cache is stale within weeks; re-run on every engagement.
