---
name: recon-asn-network-mapping
category: reconnaissance
description: Map an organisation's full network footprint via ASN ownership — known IP to ASN to all org-owned ASNs to all CIDRs to every IP, then reverse-DNS, cert-CN, and HTTP-banner pivots reveal subdomains and assets the user did not declare
depends_on: []
---

# ASN-Based Network Mapping

## Purpose

An organisation that owns its IP space announces it via Border Gateway Protocol. Each announcement carries an ASN (Autonomous System Number) and a CIDR prefix. Walking from a single known IP up to the ASN, sideways to every other ASN that org owns, then down to every CIDR and every IP within those CIDRs, exposes the full self-hosted network footprint — including assets the program scope page never listed. PTR records, presented certificates, and HTTP banners on each IP reveal subdomains, services, and applications that no passive subdomain source ever indexed.

The yield is asymmetric. A multi-billion-dollar org may own 30 ASNs, 500 CIDRs, and 1 million IPs. Most are routers, mail servers, NAT egress, internal-only. A small percentage are public-facing apps. Some of those public-facing apps are unannounced — never in DNS, never in CT logs, never on the program scope page. Those are the highest-impact targets in any engagement.

## When to Use

- The target operates self-hosted infrastructure (not 100% cloud-tenant)
- A passive recon pass returned IPs that resolve to ranges other than the major cloud providers (AWS/GCP/Azure)
- The scope is broad ("any asset owned by the company") or includes IP ranges
- You are searching for shadow IT, M&A leftovers, deprecated infrastructure
- You suspect the org has internal ASNs (often filed under acquired-company names)
- You need to identify origin servers behind a CDN — origin IPs frequently sit in the org's own ASN
- The user-declared scope feels incomplete and you want to surface assets they may not have known were exposed

## Inputs

- At least one known IP that belongs to the target (from passive resolution of any subdomain)
- The organisation's legal name(s) — primary, parent corp, subsidiaries, prior names from M&A
- Optional: list of known ASNs from prior engagements
- Optional: API keys for BGPView (free), Hurricane Electric (free, scrape), RIPE Stat (free), PeeringDB (free, registration), Censys

## Sources Catalog

### whois on an IP

The starting point — every `whois` response on an IP returns the registered ASN, organisation, and the CIDR the IP belongs to.

```bash
whois 198.51.100.42
# Yields: NetRange, CIDR, NetName, OrgId, OrgName, OriginAS, RegDate, etc.
```

Fields to extract:
- `OriginAS` or `origin:` — the announcing ASN
- `OrgName` / `org:` — the registered organisation
- `CIDR` / `inetnum:` — the registered prefix (often broader than the actually-announced prefix)

Different RIRs (ARIN, RIPE, APNIC, LACNIC, AFRINIC) format whois differently. Parse generically by line key.

### BGPView (free, no auth)

Comprehensive ASN/prefix/peer database. Public REST API.

```bash
# IP -> ASN
curl -s "https://api.bgpview.io/ip/198.51.100.42" | jq '.data'

# ASN -> announced prefixes
curl -s "https://api.bgpview.io/asn/64500/prefixes" \
  | jq -r '.data.ipv4_prefixes[].prefix'
curl -s "https://api.bgpview.io/asn/64500/prefixes" \
  | jq -r '.data.ipv6_prefixes[].prefix'

# Org search -> all ASNs by org name
curl -s 'https://api.bgpview.io/search?query_term=Target+Corp' \
  | jq '.data.asns[] | {asn, name, description, country_code}'

# ASN details (peers, upstreams, downstreams)
curl -s "https://api.bgpview.io/asn/64500" | jq '.data'
curl -s "https://api.bgpview.io/asn/64500/peers" | jq '.data'
curl -s "https://api.bgpview.io/asn/64500/upstreams" | jq '.data'
```

Rate limit: ~1 req/sec sustained. Batch with sleep when iterating ASNs.

### Hurricane Electric BGP (free, scrape)

`https://bgp.he.net/AS<num>` is a public dashboard with prefixes, peers, IRR objects. No public API but the HTML is parseable.

```bash
# Fetch ASN page
curl -s "https://bgp.he.net/AS64500" \
  -H "User-Agent: Mozilla/5.0" > as64500.html

# Extract IPv4 prefixes
grep -oE '/net/[0-9.]+/[0-9]+' as64500.html \
  | sed 's|/net/||' | sort -u > as64500_v4.txt

# Org search
curl -s 'https://bgp.he.net/search?search%5Bsearch%5D=Target+Corp&commit=Search' \
  -H "User-Agent: Mozilla/5.0"
```

Hurricane Electric data tracks current routing. CIDRs that whois claims for an org but HE no longer shows announced may be unused / leased back.

### PeeringDB (free, registration)

Peering and IX data for ASNs. Often surfaces the physical locations and upstream relationships of an org.

```bash
curl -s "https://www.peeringdb.com/api/asn/64500" | jq '.data'

# Org search
curl -s 'https://www.peeringdb.com/api/org?name__contains=Target+Corp' \
  | jq '.data[] | {id, name, website, asn_set}'
```

The `asn_set` returns every ASN PeeringDB associates with that org — useful for org normalization.

### RIPE Stat (free, no auth)

RIPE NCC's data API. Real-time announcement data plus historical records.

```bash
# Real-time announcements for an ASN
curl -s 'https://stat.ripe.net/data/announcements/data.json?resource=AS64500' \
  | jq '.data.prefixes[] | .prefix'

# Org-id -> resources
curl -s 'https://stat.ripe.net/data/related-prefixes/data.json?resource=AS64500'

# Whois lookup with structured output
curl -s 'https://stat.ripe.net/data/whois/data.json?resource=198.51.100.42' \
  | jq '.data.records'

# Reverse DNS bulk
curl -s 'https://stat.ripe.net/data/reverse-dns-ip/data.json?resource=198.51.100.42'
```

RIPE Stat is the most authoritative source for European ASNs. ARIN-region ASNs are also covered but with less depth.

### ipinfo / ipgeolocation (free tier)

Free tier API for IP -> ASN lookup. Useful as a verification source against whois.

```bash
curl -s "https://ipinfo.io/198.51.100.42/json" | jq
# Returns: { "ip": "...", "org": "AS64500 Target Corp", "country": "US", ... }
```

### Censys (cert-based pivot)

Cert subject pivots reveal IPs presenting certs issued to the org — often catching hosts in cloud ASNs (where IP-level org search fails).

```bash
curl -s -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
  -H 'Content-Type: application/json' \
  -d '{"q": "services.tls.certificates.leaf_data.subject.organization: \"Target Corp\""}' \
  'https://search.censys.io/api/v2/hosts/search'

# Pivot by exact subject DN
curl -s -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
  -H 'Content-Type: application/json' \
  -d '{"q": "parsed.subject_dn: \"O=Target Corp\""}' \
  'https://search.censys.io/api/v2/certificates/search'
```

### Shodan (banner-based pivot)

Once an org name and ASN list are known, Shodan filters narrow IP-level scans:

```bash
shodan search 'org:"Target Corp"' --fields ip_str,port,hostnames,ssl.cert.subject.cn
shodan search 'asn:AS64500'
shodan search 'ssl.cert.subject.organization:"Target Corp"'
```

(Shodan dorking has a dedicated skill — `recon_shodan_dorking`. The org/ASN filter chain belongs there.)

## Methodology

### Stage 1 — Seed ASN Discovery

Start from any known IP belonging to the target. Look up ASN three ways and reconcile.

```bash
SEED_IP=198.51.100.42

# Source 1: whois
ASN_WHOIS=$(whois "$SEED_IP" | grep -iE 'OriginAS|origin:' | head -1 | grep -oE 'AS[0-9]+' | tr -d 'AS')

# Source 2: BGPView
ASN_BGPVIEW=$(curl -s "https://api.bgpview.io/ip/$SEED_IP" | jq -r '.data.prefixes[0].asn.asn')

# Source 3: ipinfo
ASN_IPINFO=$(curl -s "https://ipinfo.io/$SEED_IP/json" | jq -r '.org' | grep -oE 'AS[0-9]+' | tr -d 'AS')

echo "whois=$ASN_WHOIS bgpview=$ASN_BGPVIEW ipinfo=$ASN_IPINFO"
```

Three sources agree → high confidence. Two of three agree → use majority. Disagreement → investigate (lease boundary? recently changed announcement? data lag?).

### Stage 2 — Org-Name Normalisation

ASN -> Org Name via BGPView. Then enumerate the org-name variants used across registries and search ALL of them.

```bash
SEED_ASN=64500
ORG=$(curl -s "https://api.bgpview.io/asn/$SEED_ASN" \
  | jq -r '.data.organisation_name')

echo "Primary org: $ORG"
```

Variant generation rules:
- Strip suffixes: `Inc`, `Inc.`, `LLC`, `Ltd`, `Limited`, `Corp`, `Corporation`, `Pty Ltd`, `GmbH`, `S.A.`, `S.A.S`, `BV`
- Add suffixes: an org filed as `Target` may also be filed as `Target Corp`, `Target Inc`, `Target Holdings`, `Target Cloud Services`
- Punctuation: `Target, Inc.` vs `Target Inc` vs `Target-Inc`
- Casing: `TARGET CORP` vs `Target Corp`
- M&A history: prior names of acquired companies (`Old-Co Inc`, `Old-Co Holdings`)
- Parent / subsidiary: `Target Holdings Inc` (parent), `Target Operating Co` (subsidiary)

```bash
ORG_VARIANTS=(
  "Target"
  "Target Corp"
  "Target Inc"
  "Target Holdings"
  "Target Cloud Services"
  "Target Pty Ltd"
  "TargetCorp"
  "OldCo Inc"
)
```

### Stage 3 — All ASNs by Org

For each org variant, query BGPView's search endpoint:

```bash
for V in "${ORG_VARIANTS[@]}"; do
  curl -s "https://api.bgpview.io/search?query_term=$(printf '%s' "$V" | jq -sRr @uri)" \
    | jq -r '.data.asns[] | "\(.asn)\t\(.name)\t\(.description)\t\(.country_code)"'
  sleep 1
done | sort -u > all_asns.tsv

cat all_asns.tsv
```

Cross-reference against PeeringDB and Hurricane Electric. ASNs that BGPView lists for the org but PeeringDB/HE do not are still valid — they may be small, regional, or recently allocated.

Manual filter:
- Drop ASNs whose `country_code` is implausible for the org (e.g., ASN registered in Russia for a US-only company — likely lease)
- Flag ASNs with very different names (potential M&A artefacts) for separate confirmation
- Keep ASNs registered under subsidiary names — those are real recon ground

### Stage 4 — All CIDRs per ASN

For each confirmed ASN, pull every announced prefix.

```bash
> all_prefixes.txt
while IFS=$'\t' read -r ASN NAME DESC COUNTRY; do
  curl -s "https://api.bgpview.io/asn/$ASN/prefixes" \
    | jq -r '.data.ipv4_prefixes[].prefix' >> all_prefixes.txt
  curl -s "https://api.bgpview.io/asn/$ASN/prefixes" \
    | jq -r '.data.ipv6_prefixes[].prefix' >> all_prefixes.txt
  sleep 1
done < all_asns.tsv
sort -u -o all_prefixes.txt all_prefixes.txt
```

Cross-reference against Hurricane Electric (`https://bgp.he.net/AS<asn>`) to catch prefixes BGPView missed and vice versa.

### Stage 5 — Enumerate IPs and Reverse-DNS Sweep

Expand each CIDR into its IP list and reverse-DNS each IP.

```bash
# Expand prefixes
> all_ips.txt
while read -r PREFIX; do
  prips "$PREFIX" >> all_ips.txt 2>/dev/null
done < all_prefixes.txt

# Reverse-DNS sweep with dnsx
dnsx -l all_ips.txt -ptr -resp -silent -t 200 -o ptr_results.txt
```

For very large ASNs (millions of IPs), shard `all_ips.txt` and parallel-process. PTR sweep at 200 concurrent queries achieves ~10k IPs/minute against public resolvers — a /16 (~65k IPs) takes ~7 minutes.

### Stage 6 — Cert-CN / SAN Pivots

For every IP that responds on TCP/443, fetch the presented cert.

```bash
# tlsx by ProjectDiscovery
tlsx -l all_ips.txt -san -cn -resp -silent -o tls_results.txt

# Manual openssl
echo | openssl s_client -connect 198.51.100.42:443 -servername 198.51.100.42 2>/dev/null \
  | openssl x509 -noout -subject -ext subjectAltName
```

Cert SANs reveal hostnames the IP serves. Cross-reference SANs against the parent-domain list — SANs ending in `target.example` are subdomains worth adding to the master list.

### Stage 7 — HTTP Host-Header Probes

Many IPs serve a default response on TCP/80 and TCP/443 but route by Host header. A blank Host probe returns the default; targeted Host probes (using known parent domains) reveal vhost-specific apps.

```bash
# httpx
echo "198.51.100.42" | httpx -title -tech-detect -status-code -silent

# With Host header
curl -ks -H "Host: api.target.example" "https://198.51.100.42/" -o /dev/null \
  -w "%{http_code}\t%{ssl_verify_result}\n"
```

Hosts whose default response differs from the Host-header response indicate vhost routing — chain to `recon_vhost_fuzzing`.

### Stage 8 — Categorize by Service Banner

For each IP, record:
- PTR record (if any)
- Cert CN / SANs (if HTTPS)
- HTTP title (if HTTP/HTTPS)
- Open ports beyond 80/443 (chain to `recon_port_service_analysis`)

Bucket the resulting host list by service type:

| Banner / port pattern | Category |
|-----------------------|----------|
| Cert CN matches `*.target.example`, app frameworks (Rails, Django, Laravel) | Web app |
| Banner mentions `OpenVPN`, port 1194/UDP, port 443 with VPN cert | VPN |
| Cert CN includes `mail`, `mx`, `smtp`, port 25/465/587 open | Mail |
| Banner includes Cisco, Juniper, Mikrotik, `SSH-2.0-Cisco_*` | Network device |
| Cert CN matches `bastion`, `jump`, ports 22/SSH | Bastion / jump |
| Banner mentions `Jenkins`, `GitLab`, `Jira`, `Confluence` | Internal SaaS |

Internal SaaS instances exposed to the public internet are frequent finding sources (auth bypass, default creds, unpatched RCEs).

## Search Operators / Patterns

### whois pivots

```bash
whois 198.51.100.42                                    # IP -> registration record
whois -h whois.radb.net AS64500                        # ASN registry record
whois -h whois.arin.net 'a TARGET-CORP'                # ARIN org search
whois -h whois.ripe.net 'inverse Target Corp'          # RIPE org search
```

### BGPView API patterns

```bash
curl -s "https://api.bgpview.io/ip/$IP"                          # IP info
curl -s "https://api.bgpview.io/asn/$ASN"                        # ASN info
curl -s "https://api.bgpview.io/asn/$ASN/prefixes"               # all prefixes
curl -s "https://api.bgpview.io/asn/$ASN/peers"                  # BGP peers
curl -s "https://api.bgpview.io/asn/$ASN/upstreams"              # transit
curl -s "https://api.bgpview.io/asn/$ASN/downstreams"            # downstream
curl -s 'https://api.bgpview.io/search?query_term=Target+Corp'   # org search
curl -s "https://api.bgpview.io/prefix/198.51.100.0/24"          # prefix info
```

### RIPE Stat patterns

```bash
curl -s 'https://stat.ripe.net/data/announcements/data.json?resource=AS64500'
curl -s 'https://stat.ripe.net/data/whois/data.json?resource=198.51.100.42'
curl -s 'https://stat.ripe.net/data/reverse-dns-ip/data.json?resource=198.51.100.42'
curl -s 'https://stat.ripe.net/data/searchcomplete/data.json?resource=Target+Corp'
curl -s 'https://stat.ripe.net/data/network-info/data.json?resource=198.51.100.0/24'
```

### Hurricane Electric scrape patterns

- `https://bgp.he.net/AS64500` — ASN dashboard
- `https://bgp.he.net/AS64500#_prefixes` — IPv4 prefixes
- `https://bgp.he.net/AS64500#_prefixes6` — IPv6 prefixes
- `https://bgp.he.net/AS64500#_peers` — peering relationships
- `https://bgp.he.net/search?search[search]=Target+Corp` — org search
- `https://bgp.he.net/net/198.51.100.0/24` — prefix details

### Reverse DNS sweep tools

```bash
dnsx -l ips.txt -ptr -resp -silent -t 200 -o ptrs.txt
prips 198.51.100.0/24 | xargs -P 50 -n 1 -I {} dig +short -x {}
```

### TLS cert pivots

```bash
tlsx -l ips.txt -san -cn -resp -silent
nmap -p 443 --script ssl-cert -iL ips.txt -oG -                 # Nmap-based
```

## Decision Tree

```
known IP for target?
├── NO → run recon_passive_subdomain to obtain at least one resolved IP first
└── YES → continue

   ├── Stage 1 ASN discovery — three sources agree?
   │   ├── YES → use the agreed ASN
   │   └── NO → investigate; use majority; flag for re-check
   │
   ├── Stage 2 org-name normalised → variants generated?
   │   ├── YES → continue
   │   └── NO (single name only) → org may be filed under multiple names; double-check via PeeringDB
   │
   ├── Stage 3 search returned ASNs?
   │   ├── 0 ASNs → org-name variants insufficient or org has only one ASN
   │   ├── 1-5 ASNs → small footprint; verify via cross-source
   │   └── >5 ASNs → large footprint; filter by country_code and name plausibility
   │
   ├── Stage 4 prefixes per ASN — any prefix overlap with known cloud providers?
   │   ├── YES → flag for cloud-pivot path (cert-based, not IP-based)
   │   └── NO → continue with PTR sweep
   │
   ├── Stage 5 PTR sweep returns hostnames?
   │   ├── YES → harvest names; pass through parent-domain filter to identify in-scope subdomains
   │   └── NO (or very few) → IP range may be backbone/router-only; skip to cert pivot
   │
   ├── Stage 6 cert pivot reveals SANs?
   │   ├── YES → SANs feed back into subdomain master list
   │   └── NO → IP range is non-HTTPS; rely on PTR + Host probes
   │
   └── Stage 7-8 host categorisation
       ├── internal SaaS / bastion / VPN exposed → high-priority finding candidates
       ├── web apps with cert-matching parent domain → confirmed in-scope subdomains
       └── unknown banner → record and feed to port/service analysis
```

## Pitfalls

- **Cloud ASN dominance** — most modern orgs host primarily in AWS/GCP/Azure. Their ASN is the cloud provider's, not theirs. IP-based ASN search returns the cloud provider's millions of IPs — useless. Switch to cert-based pivot (Censys cert subject) or banner-based pivot (Shodan org filter) instead.
- **Org name false positives** — `Target Corp` ASN might belong to a different "Target Corp" entirely. Cross-reference: BGPView name + PeeringDB website + cert SAN domain + announced prefix country code. If three sources disagree, drop the ASN.
- **Subsidiary / parent confusion** — `Target Holdings Inc` may own ASNs unrelated to the in-scope `Target Operating Co`. Confirm via the public corporate structure and the program scope page.
- **Decommissioned ranges** — ASN data lags reality. A CIDR listed under the org may have been transferred or returned. Active probe each prefix (ICMP / TCP/443) before trusting; chain to `recon_port_service_analysis`.
- **Leased IP ranges** — orgs lease IP ranges from upstreams; the registered org may not match the using org. Cross-reference whois `OrgName` vs BGPView `name` vs cert subject. If lease boundary detected, treat range as out-of-scope unless confirmed.
- **PTR records lie** — PTR is operator-controlled and frequently stale. A PTR pointing to `decommissioned.target.example` is a hint, not proof. Verify with forward DNS, cert SAN, and HTTP banner.
- **Wildcard PTR records** — some operators set `*.198-51-100.in-addr.arpa` to a single hostname. Detect by checking 5 random IPs in the range and looking for identical responses.
- **IPv6 tunnels and 6to4 relays** — IPv6 prefixes from BGPView may include tunnel-broker-allocated ranges that the org does not actually use. Verify by reverse-DNS and cert presence.
- **Anycast IPs** — some IPs (CDNs, public DNS, NTP) are anycast and respond from many locations. PTR may differ per location; the IP "belongs to" the announcing CDN, not the customer.
- **Geo-blocked ranges** — some ASNs only respond to traffic from specific regions. A scan from a US IP may report a range as down when it is up from EU; rotate vantage points if results are sparse.
- **Internal-only ranges in BGP** — orgs sometimes announce private ranges through BGP for internal use. RFC1918 ranges (`10.x`, `172.16.x`, `192.168.x`) appearing in `prefixes` output are usually data noise.
- **PTR rate limits** — `dig -x` against public resolvers is throttled at the same rates as forward DNS. Use a rotating resolver pool and a tool like dnsx with `-resolvers`.
- **CDN-fronted origin discovery** — origin IPs frequently sit in the org's own ASN. Once the ASN is known, scanning every IP for a Host-header match against the CDN-fronted hostname can reveal the origin (chain to `recon_vhost_fuzzing` and Host probes).
- **Multi-homed assets** — large orgs may have multiple ASNs covering the same logical service (geo-redundancy, failover). Treat IP-clustering by service banner, not by ASN, when categorising.
- **Bypassing IP-based scope** — never assume "org owns IP X" implies "asset Y in scope." Always confirm against the program's scope page and policy. ASN walking surfaces candidate assets; scope verification confirms which are testable.

## Output Format

Each discovered host is recorded as:

```json
{
  "asn": 64500,
  "asn_name": "TARGET-CORP-ASN",
  "asn_country": "US",
  "org_name_variant_matched": "Target Corp",
  "prefix": "198.51.100.0/24",
  "ip": "198.51.100.42",
  "ptr_record": "host42.target.example",
  "cert_cn": "api-internal.target.example",
  "cert_san": ["api-internal.target.example", "api.target.example"],
  "http_title": "Target Internal API",
  "http_status": 200,
  "open_ports": [22, 80, 443, 8443],
  "service_category": "web app|vpn|mail|bastion|internal SaaS|network device|unknown",
  "discovered_via_subdomain": false
}
```

`discovered_via_subdomain=false` indicates the host was found via ASN walking and was NOT in any subdomain enumeration list — these are the highest-value entries (assets the user did not declare). Persist as JSONL.

## Composes With

- `recon_passive_subdomain` — provides the seed IP. PTR records and cert SANs harvested in this skill feed back into the subdomain master list, often revealing names no passive source indexed.
- `recon_subdomain_permutations` — confirmed parent-domain SANs become new seeds for permutation. The recursion (this skill -> subdomain pool -> permutation -> resolution -> new IPs -> back to this skill) closes the loop.
- `recon_port_service_analysis` — every IP enumerated in this skill is a port-scan candidate. Service banners categorise the host beyond cert/PTR data.
- `recon_shodan_dorking` — once ASN(s) and org name(s) are known, Shodan's `org:` and `asn:` filters narrow Shodan to just the target's footprint.
- `recon_vhost_fuzzing` — IPs that respond on 80/443 with a generic default response and route by Host header are vhost candidates. The known parent domain feeds Host-header probes.
- `recon_cloud_bucket_dorking` — org names normalised in Stage 2 are the same name variants used as cloud bucket prefixes.
- `recon_attack_surface_mapping` — the categorised host list (web app, VPN, mail, internal SaaS) becomes input to attack-surface prioritisation.

## Termination Policy

- Walk EVERY ASN owned by EVERY org-name variant. No early stopping after "we found one ASN with lots of prefixes."
- Walk EVERY CIDR in EVERY ASN. The CIDR with the smallest /N may host the highest-value asset.
- Reverse-DNS EVERY IP in scope. PTR sweeps are O(N) and parallelisable; do not skip ranges to save time.
- Cert-pivot EVERY IP responding on TCP/443. Cert SANs are the single highest-yield pivot in this skill.
- Re-run org-name search after Stage 7 — host categorisation may reveal new org names (cert subjects, banner strings) that re-feed Stage 2 / Stage 3.
- Multi-pass: when host categorisation reveals a new subsidiary or parent name (Stage 8 cert subjects), re-run Stages 2-7 with the new name. Continue until a pass returns zero new ASNs and zero new hosts.
- DO NOT skip cloud-hosted assets. If the org rents IPs in AWS/GCP/Azure, switch to cert-based pivot rather than IP-based; the cert pivot still works in cloud ASNs.
- DO NOT stop because "we already have a lot of subdomains." The unique value of ASN walking is finding hosts that have no subdomain — they are reachable by IP only and are systematically missed by subdomain-only recon.
- Continue until every catalogued ASN, every CIDR, every IP, every cert, every PTR has been enumerated and the multi-pass cert-subject feedback loop has stabilised.
