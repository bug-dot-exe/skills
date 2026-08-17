---
name: recon-passive-subdomain
category: reconnaissance
description: Passive subdomain enumeration via certificate transparency, third-party intel APIs, search engines, reverse DNS pivots, and DNS-record-type mining — zero traffic to the target
depends_on: []
---

# Passive Subdomain Enumeration

## Purpose

Discover subdomains of an in-scope domain without sending a single packet to the target. Every query targets third-party indexes, certificate logs, archived DNS data, or search engines. The target sees nothing; the dataset comes from systems that already crawled, logged, or recorded the asset.

Coverage of subdomains is the foundation of every downstream finding. A subdomain that is never enumerated is a subdomain that is never tested. An unindexed dev environment, a stale staging host, a deprecated API gateway — each one expands the attack surface and the finding count. Passive recon is the cheapest way to expand it.

## When to Use

- The scope is a wildcard (`*.target.example`) or a parent domain implied to include subdomains
- You are starting recon and have no list of subdomains yet
- You need to enumerate without alerting the target's WAF, SIEM, or anomaly detection
- You want to seed downstream tools (permutation engines, active resolvers, vhost fuzzers)
- The target operates blue-team monitoring that flags unusual DNS query volumes from your IP
- You are time-boxed and want maximum subdomain yield per minute of recon
- You are operating in a stealth-required engagement and any active probe creates legal risk

## Inputs

- One or more parent domains in scope (`target.example`, `target-internal.example`)
- Optional API keys: Censys, VirusTotal, SecurityTrails, Chaos, RiskIQ/PassiveTotal
- Optional list of known subdomains from a prior engagement (used to verify source coverage)

## Sources Catalog

Each source has its own coverage profile, freshness, and access path. Treat the catalog as exhaustive — query every source listed before moving to active enumeration.

### Certificate Transparency

CT logs are append-only ledgers of every TLS certificate ever issued by a participating CA. Most modern CAs participate. Every cert lists the SAN entries (subject alternative names) — frequently every subdomain the cert covers, including ones that never get indexed elsewhere.

#### crt.sh

Free, open, no auth required. Aggregates Let's Encrypt, Sectigo, DigiCert, Google CT, Cloudflare CT, and others.

```bash
# JSON output, percent-encoded wildcard prefix matches all subdomains
curl -s 'https://crt.sh/?q=%25.target.example&output=json' \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | tr '[:upper:]' '[:lower:]' \
  | sort -u > crt_target.example.txt
```

Each cert can list multiple SANs. `name_value` may contain newlines inside one record — split on `\n` after extraction. Wildcard certs (`*.target.example`) HIDE individual subdomain names — you will not see `dev.target.example` if the cert was issued as a single wildcard. Pivot via issuer: certs from internal CAs or pinned cert issuers may reveal infrastructure clusters.

```bash
# Pivot by issuer — find every cert issued by the target's internal CA (if they run one)
curl -s 'https://crt.sh/?q=target.example&output=json' \
  | jq -r '.[] | "\(.issuer_name)\t\(.name_value)"' \
  | sort -u
```

Filter expired-only certs by checking `not_after`. Expired certs still reveal historical hostnames worth probing.

#### Censys (certificate search + host search)

Paid API, generous free tier. Cert search returns certs matching a name pattern; host search returns IPs whose presented certs match.

```bash
# Cert search — find certs whose SANs include any name ending in target.example
curl -s -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
  -H 'Content-Type: application/json' \
  -d '{"q": "names: *.target.example", "per_page": 100}' \
  'https://search.censys.io/api/v2/certificates/search'

# Host search — find live hosts presenting a cert covering target.example
curl -s -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
  -H 'Content-Type: application/json' \
  -d '{"q": "services.tls.certificates.leaf_data.names: *.target.example"}' \
  'https://search.censys.io/api/v2/hosts/search'
```

Cert search syntax to memorize:
- `parsed.names: target.example` — exact name match in SAN list
- `parsed.subject_dn: "O=Target Corp"` — pivot by org name in cert subject
- `parsed.issuer_dn: "O=Target Corp Internal CA"` — pivot by issuer
- `parsed.serial_number: ...` — pivot a known cert's serial across hosts

Host search query budget: each query consumes credits. Page only as far as new names appear; stop paging when results plateau.

#### Google CT and Facebook CT

Free CT search dashboards. Useful as a sanity check when crt.sh is rate-limited or down.

- `https://transparencyreport.google.com/https/certificates?domain=target.example`
- `https://developers.facebook.com/tools/ct/?domain=target.example` (login required)

Manual UI scraping — schedule these as verification passes when automation hits limits.

### Third-Party Intel APIs

#### VirusTotal

Aggregates passive DNS, sample submissions, URL scans. The `/subdomains` endpoint returns observed subdomains.

```bash
# v3 API — paginated, max 40 per page
curl -s -H "x-apikey: $VT_API_KEY" \
  'https://www.virustotal.com/api/v3/domains/target.example/subdomains?limit=40' \
  | jq -r '.data[].id'

# Follow next cursor until empty
NEXT='https://www.virustotal.com/api/v3/domains/target.example/subdomains?limit=40'
while [ -n "$NEXT" ] && [ "$NEXT" != "null" ]; do
  RES=$(curl -s -H "x-apikey: $VT_API_KEY" "$NEXT")
  echo "$RES" | jq -r '.data[].id'
  NEXT=$(echo "$RES" | jq -r '.links.next // empty')
done
```

Public VT keys: 4 requests per minute, 500 per day. Rotate keys across an engagement or queue requests.

#### AlienVault OTX

Free passive DNS dataset.

```bash
curl -s 'https://otx.alienvault.com/api/v1/indicators/domain/target.example/passive_dns' \
  | jq -r '.passive_dns[].hostname' \
  | sort -u
```

`passive_dns` records show observed `(hostname, IP, first_seen, last_seen)` — also useful for IP-side pivots.

#### SecurityTrails

Subdomain enumeration plus historical DNS records. Free tier ~50 queries/month.

```bash
curl -s -H "APIKEY: $ST_API_KEY" \
  'https://api.securitytrails.com/v1/domain/target.example/subdomains?children_only=false&include_inactive=true' \
  | jq -r '.subdomains[]' \
  | sed "s/$/.target.example/"
```

`include_inactive=true` retrieves historically-seen subdomains that are no longer resolving — these are still recon gold (the host may still exist on internal DNS or behind a CDN).

#### Chaos (ProjectDiscovery)

Free for verified bug bounty hunters. Pre-indexed dataset of public bug bounty programs.

```bash
chaos -d target.example -silent -o chaos_target.example.txt 2>/dev/null
# or via curl:
curl -s -H "Authorization: $CHAOS_API_KEY" \
  'https://dns.projectdiscovery.io/dns/target.example/subdomains' \
  | jq -r '.subdomains[]' \
  | sed "s/$/.target.example/"
```

Refresh cadence: weekly. Treat Chaos as a baseline, not a complete view.

#### DNSDumpster

No public API — web form returns subdomain lists derived from passive sources. Scrape pattern: GET `https://dnsdumpster.com/` to fetch the CSRF token from `csrfmiddlewaretoken`, then POST `csrfmiddlewaretoken=<token>&targetip=target.example&user=free` with `Referer: https://dnsdumpster.com/` and the cookie jar from the GET. Regex-extract `[a-z0-9._-]+\.target\.example` from the response. Brittle — UI changes break parsers; use as a backup, not primary.

#### HackerTarget

Free tier with 10 queries/day per IP. Returns hostsearch results derived from third-party DNS data.

```bash
curl -s 'https://api.hackertarget.com/hostsearch/?q=target.example' \
  | awk -F',' '{print $1}' \
  | sort -u
```

#### ThreatCrowd / RiskIQ PassiveTotal

ThreatCrowd: legacy, free, sometimes 503s.

```bash
curl -s 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=target.example' \
  | jq -r '.subdomains[]?'
```

RiskIQ PassiveTotal (now Microsoft Defender Threat Intelligence): paid API, exhaustive passive DNS history.

```bash
curl -s -u "$RISKIQ_USER:$RISKIQ_KEY" \
  'https://api.riskiq.net/pt/v2/dns/passive?query=target.example' \
  | jq -r '.results[].resolve'
```

#### subfinder / amass passive aggregators

`subfinder` and `amass` orchestrate ~30 of the sources above plus several more (BinaryEdge, BufferOver, ThreatBook, DNSrepo, FullHunt). Run them with passive-only flags to enforce zero target traffic.

```bash
subfinder -d target.example -all -silent -o subs_subfinder.txt
amass enum -passive -d target.example -o subs_amass.txt
```

Use `subfinder -all` to enable every configured source. Configure `~/.config/subfinder/provider-config.yaml` with API keys for sources that require auth.

### Search Engines (Reverse Lookup)

Different from sensitive-data dorking — the goal here is purely subdomain extraction.

#### Google

```
site:*.target.example -www
site:*.target.example -www -api
site:*.target.example inurl:dev
site:*.target.example -site:www.target.example
```

The exclusion chain (`-www -api -...`) walks Google through "show me everything except what I have already seen." Repeat until results stop revealing new hostnames.

#### Bing / Yandex / DuckDuckGo

All three accept `site:*.target.example`. Each aggregates a different crawl pool. Bing covers mid-size and regional subdomains Google misses. Yandex retains older indexes longer (deprecated subdomains that fell out of Google's index). DuckDuckGo aggregates Bing plus smaller engines as a sanity check. Yandex also accepts `host:target.example` syntax.

Extract subdomains from result HTML by regex — the SERP exposes hostnames in title, snippet, and URL fields.

```bash
# Pseudo-extraction — replace SERP with a real fetch
grep -oE '[a-z0-9.-]+\.target\.example' serp.html | sort -u
```

### Reverse DNS Pivots

#### ASN-based pivot

Identifies subdomains by walking every IP an organisation announces. Detailed methodology lives in `recon_asn_network_mapping`. The high-level chain: known IP → ASN lookup → enumerate every CIDR for that ASN → reverse-DNS each IP → harvest PTR records.

#### IP-based pivot (PTR harvesting on a single IP)

```bash
dig +short -x 198.51.100.42
```

Many corporate IPs are shared by multiple hostnames; the PTR returns one canonical name but TLS SNI probing can reveal the others (chain to active probe — covered in port/service skill).

#### Shared-host detection

Multiple unrelated organisations frequently share a hosting IP (Heroku, Cloudflare, Cloudfront, GitHub Pages). Treat shared-host PTR records as low-confidence — verify with cert SANs or independent DNS resolution before claiming the subdomain belongs to the target.

### DNS-Record-Type Mining

Subdomains often leak through DNS records that are not A/AAAA records.

#### TXT records (SPF, DKIM, DMARC)

SPF records list every host or IP allowed to send mail for a domain. They commonly reference internal mail relays, third-party SaaS senders, and otherwise-undocumented infrastructure.

```bash
dig +short TXT target.example
# Example output:
# "v=spf1 include:mail.target.example include:smtp-relay.target-internal.example -all"

# Recursively follow include: chains
dig +short TXT target.example | grep -oE 'include:[^ ]+' | sed 's/include://'
# Then resolve each included domain and recursively expand
```

DKIM selectors: `dig +short TXT default._domainkey.target.example` and try common selectors (`default`, `selector1`, `google`, `mail`, `s1`, `s2`, `mx`, `dkim`).

#### MX records

```bash
dig +short MX target.example
# Returns hostname:priority — each hostname is a candidate subdomain
```

Mail infrastructure subdomains (`mail.target.example`, `mx1.target-internal.example`) often expose webmail, autodiscover endpoints, and admin consoles.

#### CNAME chains

```bash
dig +trace target.example
dig CNAME api.target.example
```

CNAME chains reveal cloud providers (e.g., `api.target.example -> api-prod.us-east-1.elb.amazonaws.com`) and naming conventions internal teams use.

#### NS records

```bash
dig +short NS target.example
```

If the target operates its own nameservers (`ns1.target.example`), querying those nameservers directly may yield zone-level data the public resolver chain hides.

#### SRV records

Service-record convention: `_service._proto.name`. Common probes:

```bash
for SVC in _ldap._tcp _kerberos._tcp _sip._tls _sip._tcp _xmpp-server._tcp _autodiscover._tcp; do
  dig +short SRV "${SVC}.target.example"
done
```

Each hit may reveal `ldap.target-internal.example`, `sip-edge.target.example`, etc.

## Methodology

### Stage 1 — Source Sweep (Parallel)

Spawn one query per source in parallel. Each source returns a deduplicated subdomain list to its own file.

```bash
PARENT=target.example

# Bucket per source so failures are isolated
( curl -s "https://crt.sh/?q=%25.${PARENT}&output=json" \
    | jq -r '.[].name_value' | sed 's/\*\.//g' \
    | tr '[:upper:]' '[:lower:]' | sort -u > src_crt.txt ) &

( curl -s -H "x-apikey: $VT_API_KEY" \
    "https://www.virustotal.com/api/v3/domains/${PARENT}/subdomains?limit=40" \
    | jq -r '.data[].id' | sort -u > src_vt.txt ) &

( curl -s "https://otx.alienvault.com/api/v1/indicators/domain/${PARENT}/passive_dns" \
    | jq -r '.passive_dns[].hostname' | sort -u > src_otx.txt ) &

( curl -s -H "APIKEY: $ST_API_KEY" \
    "https://api.securitytrails.com/v1/domain/${PARENT}/subdomains?include_inactive=true" \
    | jq -r '.subdomains[]' | sed "s/$/.${PARENT}/" | sort -u > src_st.txt ) &

( chaos -d "$PARENT" -silent > src_chaos.txt 2>/dev/null ) &

( curl -s "https://api.hackertarget.com/hostsearch/?q=${PARENT}" \
    | awk -F',' '{print $1}' | sort -u > src_ht.txt ) &

( subfinder -d "$PARENT" -all -silent > src_subfinder.txt 2>/dev/null ) &
( amass enum -passive -d "$PARENT" -silent > src_amass.txt 2>/dev/null ) &

wait
```

Failure of one source does not block others. Inspect the per-source files individually to confirm coverage and detect zero-hit failures (likely auth/quota issue).

### Stage 2 — Search-Engine Sweep

Run search-engine reverse lookups for each engine. Cap pagination at the point where new hostnames stop appearing (typically 5–20 pages).

### Stage 3 — DNS-Record-Type Mining

Pull TXT/SPF, MX, CNAME, NS, SRV records on the parent domain and the highest-traffic discovered subdomains. Recursively expand SPF includes.

### Stage 4 — Dedup, Normalize, Cluster

```bash
cat src_*.txt \
  | tr '[:upper:]' '[:lower:]' \
  | sed 's/^\*\.//; s/\.$//' \
  | grep -E "\.${PARENT}$" \
  | sort -u > all_passive_subs.txt
```

Cluster by IP (chain to active resolution downstream). Same-IP clusters reveal CDN groupings and origin servers.

### Stage 5 — CDN vs Origin Classification

Resolve each name and bucket by IP range and response headers. CDN ranges (Cloudflare, Akamai, Fastly, Cloudfront) → CDN-fronted; target-org cloud ranges with matching PTR → origin; other IPs → verify via cert SAN. Headers: `cf-ray:` → Cloudflare; `Server: AkamaiGHost` → Akamai; `via: 1.1 varnish` + `x-served-by:` → Fastly; `x-amz-cf-id:` → Cloudfront.

### Stage 6 — Environment Categorization

Bucket by naming convention:

| Pattern keywords | Bucket |
|------------------|--------|
| `dev`, `develop`, `internal-dev` | development |
| `stg`, `stage`, `staging` | staging |
| `qa`, `test`, `uat`, `preprod` | quality / preprod |
| `demo`, `sandbox`, `preview` | demo |
| `prod`, `production`, `live` | production |
| `internal`, `corp`, `vpn`, `bastion` | internal-leaked |
| `api`, `gateway`, `proxy` | service tier |
| `cdn`, `static`, `assets`, `media` | content delivery |
| `mail`, `smtp`, `mx`, `imap` | mail |
| `sso`, `auth`, `login`, `idp` | identity |

The categorization is heuristic but feeds prioritization downstream — internal-leaked and quality/preprod hosts are high-value attack surfaces.

## Search Operators / Patterns

### CT log advanced queries
- `https://crt.sh/?q=%25.target.example&output=json` — JSON, all certs covering subdomains
- `https://crt.sh/?O=Target+Corp&output=json` — pivot by organisation name
- `https://crt.sh/?CN=target.example&output=json` — exact CN match
- `https://crt.sh/?serial=ABCDEF1234&output=json` — pivot by cert serial

### Censys queries
- `parsed.names: *.target.example` — SAN-based subdomain discovery
- `parsed.subject_dn: "O=Target Corp"` — org pivot
- `parsed.issuer_dn: "O=Internal CA"` — internal CA pivot
- `services.tls.certificates.leaf_data.names: target.example` — host with cert
- `parsed.fingerprint_sha256: <hash>` — pivot by exact cert

### Search-engine subdomain extraction
- Google: `site:*.target.example -www -api -static -img`
- Bing: `site:target.example -site:www.target.example`
- Yandex: `host:target.example`
- DuckDuckGo: `site:*.target.example`

### DNS record probes
- `dig +short TXT target.example` — SPF + verification records
- `dig +short MX target.example` — mail hostnames
- `dig +short NS target.example` — nameservers (then `dig @ns1.target.example AXFR target.example` if zone transfer is permitted — rare but worth one attempt)
- `dig +short SRV _service._proto.target.example` — service hostnames
- `dig +short CAA target.example` — CA authorisation (often names the target's CA)
- `dig +short DMARC target.example`

## Decision Tree

```
parent domain known?
├── NO → request parent domain in scope; stop
├── YES → continue
   │
   ├── API keys for VT/Censys/SecurityTrails/Chaos available?
   │   ├── YES → include those sources in Stage 1 sweep
   │   └── NO → still run free sources (crt.sh, OTX, HackerTarget, subfinder, amass)
   │
   ├── Stage 1 sweep complete → counts seem plausible (>0 per source)?
   │   ├── ANY zero-hit source → log auth/quota issue, retry once
   │   └── all ok → proceed
   │
   ├── Stage 2 search-engine sweep produces NEW names not in Stage 1?
   │   ├── YES → re-run Stage 1 with new seeds (some sources accept hostname seeds)
   │   └── NO → continue
   │
   ├── Stage 3 DNS-record mining reveals SPF includes pointing OUT of scope?
   │   ├── YES → record those domains as related infrastructure (potentially in scope)
   │   └── NO → continue
   │
   └── Stages 4–6 produce final passive list
       ├── pass list to recon_subdomain_active_brute for resolution
       ├── pass list to recon_subdomain_permutations as seeds
       └── pass IPs to recon_asn_network_mapping for ASN expansion
```

## Pitfalls

- **Stale data** — passive DBs commonly retain decommissioned subdomains. A name resolving five years ago may not resolve today; downstream resolution stages will discard them but treat any passive hit as candidate, not confirmed.
- **Wildcard cert hides individual names** — a single `*.target.example` cert in CT logs lists no subdomains. Combine CT with passive DNS sources to compensate.
- **False positives from shared infrastructure** — `<random>.herokuapp.com` listed by VT may be unrelated tenants. Filter passive results by parent-domain suffix before treating them as in-scope.
- **API quota exhaustion** — VT free keys cap at 500/day; SecurityTrails free at ~50/month. Rotate keys, queue requests, persist state across runs.
- **Wildcard resolution downstream** — passive sources do not validate that a name still resolves. The downstream active resolver (chain) does that work.
- **CDN-fronted names look identical from passive sources** — every CDN customer's subdomain CNAMEs to the same set of edge IPs. CDN classification is required before scanning IPs.
- **Geographic bias** — Yandex retains EU/Russian indices longest; Bing covers global mid-tier; Google is most aggressive but also expires content fastest. Querying a single engine yields a single-bias view.
- **Inactive but interesting** — SecurityTrails `include_inactive=true` returns names that no longer resolve. Do not delete them; they often resurface or remain active on internal DNS.
- **CSP/X-Forwarded-For leaks bonus subdomains** — when a discovered subdomain is HTTP-active, its response headers may list additional hostnames. This is borderline-passive (you sent the HTTP request) — record but mark as semi-active.
- **DNS-record TTL caching** — repeated `dig` queries against the same resolver return cached data. Use `+trace` or vary resolvers (`@8.8.8.8`, `@1.1.1.1`, `@9.9.9.9`) for fresh views.
- **Public CT logs lag minutes-to-hours** — newly issued certs may not appear in crt.sh immediately. Repeat the CT query at the end of the engagement.
- **Zone-transfer attempts** — most nameservers refuse `AXFR`, but a misconfigured one will dump the zone. The query is a single AXFR — try once per nameserver, do not loop.
- **Encoded unicode names** — internationalised domain names round-trip through punycode (`xn--`). Both forms can appear in CT data; normalize via `idn` or `idn2` before dedup.

## Output Format

Every subdomain entry is a structured record:

```json
{
  "name": "api-internal.target.example",
  "source": "crt.sh|virustotal|otx|securitytrails|chaos|subfinder|amass|google_serp|bing_serp|spf_record|mx_record|cname|ptr|censys",
  "first_seen": "2025-01-14",
  "last_seen": "2026-04-02",
  "ip_resolved": "203.0.113.45",
  "environment_guess": "internal-leaked|prod|staging|qa|demo|dev|service|cdn|mail|identity|unknown",
  "category": "active|inactive|wildcard|cdn-fronted|origin|shared-host"
}
```

Each subdomain may have multiple source entries. Aggregator output collapses `source` into a `sources` array. Persist as JSONL (one record per line) so downstream skills can stream-process.

## Composes With

- `recon_subdomain_permutations` — passive results become seeds for permutation generation. The permutation engine multiplies `api.target.example` into `dev-api`, `staging-api`, `api-internal`, etc.
- `recon_subdomain_active_brute` — every passive name needs active DNS resolution to confirm it still exists. Inactive-but-listed names get re-checked against multiple resolvers.
- `recon_asn_network_mapping` — IPs returned by passive resolution feed ASN expansion. Once one IP belongs to the target, every IP in the same ASN/CIDR becomes a recon candidate.
- `recon_vhost_fuzzing` — passive sources never expose pure vhosts (subdomains served only when sent in the `Host:` header without DNS). Names returned by passive sources still need vhost probing for completeness.
- `recon_port_service_analysis` — every confirmed subdomain feeds port/service enumeration.
- `recon_shodan_dorking` — Shodan queries by `ssl.cert.subject.cn:target.example` complement CT log searches and add port/banner data.

## Termination Policy

- Query EVERY listed source. A source that returns zero results due to auth/quota issues is logged and retried once; a source that returns zero results twice in a row is flagged as unavailable for this engagement.
- Cross-reference every source. A subdomain found by only one source is still recorded — diversity of source coverage is the value proposition.
- DO NOT stop after the first source returns "many results." Different sources have different coverage profiles. Stopping at one source guarantees missing the names that source did not crawl.
- DO NOT stop after the second pass returns "few new results." Schedule one CT log refetch and one passive DNS refetch at the end of the engagement to catch newly logged data.
- DO NOT stop because the seed list is "long enough." Length is not coverage. The next subdomain after position 1000 may be the only one in scope that exposes the vulnerability you eventually report.
- Continue until every catalogued source has been queried, every search engine has been paginated to plateau, every DNS record type has been pulled, and the dedup pass has stabilised across two consecutive runs.
