---
name: shodan-dorking
category: reconnaissance
description: Shodan and Censys dorking for service fingerprinting, SSL certificate search, organization lookup, and CVE-specific queries
depends_on: []
---

# Shodan/Censys Dorking

Search engine dorking for internet-connected infrastructure. Shodan and Censys index banners, certificates, and service metadata that reveal exposed services, misconfigurations, and vulnerable software without sending a single packet to the target.

## When to Use

- Mapping a target's internet-facing infrastructure beyond web applications
- Looking for non-HTTP services (databases, admin panels, IoT, industrial control)
- Identifying specific software versions for known CVE exploitation
- Finding assets behind CDNs by searching SSL certificates
- Discovering related infrastructure through organization and ASN lookups

## Methodology

### Phase 1: Organization and ASN Discovery

1. Search Shodan for the organization name: `org:"Target Corp"`
2. Identify ASN ranges: `asn:AS12345`
3. Cross-reference with ARIN/RIPE WHOIS for full IP allocations
4. Map the network footprint before searching for specific services

### Phase 2: Service Fingerprinting

Query for specific services across the target's infrastructure:

```
# Web servers and frameworks
org:"Target Corp" http.title:"Dashboard"
org:"Target Corp" http.component:"nginx" http.component:"php"
hostname:"target.com" port:8080,8443,9090

# Databases
org:"Target Corp" port:3306,5432,27017,6379,9200
org:"Target Corp" product:"MongoDB" -authentication
org:"Target Corp" product:"Elasticsearch"

# Remote access
org:"Target Corp" port:22,3389,5900
org:"Target Corp" product:"OpenSSH" version:"7."

# Mail and DNS
org:"Target Corp" port:25,587,993
org:"Target Corp" port:53 product:"BIND"

# Message queues and caches
org:"Target Corp" port:5672,15672,6379,11211
org:"Target Corp" product:"RabbitMQ"
```

### Phase 3: SSL Certificate Search

Certificates reveal subdomains, internal names, and related assets:

```
# Shodan
ssl.cert.subject.CN:"target.com"
ssl.cert.subject.O:"Target Corp"
ssl:"*.internal.target.com"

# Censys
parsed.names: target.com
parsed.subject.organization: "Target Corp"
```

Extract SANs (Subject Alternative Names) for subdomain discovery.

### Phase 4: CVE-Specific Queries

Search for known vulnerable software versions:

```
# Specific CVEs
vuln:CVE-2021-44228    # Log4Shell
vuln:CVE-2023-44487    # HTTP/2 Rapid Reset
vuln:CVE-2024-3400     # Palo Alto PAN-OS

# Vulnerable version ranges
org:"Target Corp" product:"Apache" version:"2.4.49"
org:"Target Corp" http.component:"spring" version:"5.3"
org:"Target Corp" product:"OpenSSL" version:"1.0"
```

### Phase 5: Historical Host Data

Track infrastructure changes over time:

- Shodan: use the host history API to see past banners and services
- Censys: historical certificate data reveals decommissioned but indexed assets
- Compare current vs historical to find recently removed services (may still be accessible)

### Phase 6: Censys-Specific Queries

Censys has different syntax and strengths:

```
# Service search
services.service_name: HTTP AND autonomous_system.name: "Target Corp"
services.port: 443 AND services.tls.certificates.leaf_data.subject.common_name: "target.com"
services.software.product: "nginx" AND services.software.version: "1.14"

# Certificate search
parsed.names: "*.target.com" AND parsed.validity.end: [2024-01-01 TO *]
```

## Corpus-Derived Hunting Patterns

### Deterministic Cloud Resource Pre-emption

For every cloud service that auto-creates infrastructure with a deterministic name (buckets, registries, DNS zones, queue names), test pre-emption:
1. Identify the naming convention from documentation or by creating a test resource
2. Check whether an attacker can pre-create the resource before the legitimate tenant
3. If successful, the attacker controls infrastructure that the service later trusts
This pattern has yielded cross-tenant compromise bounties exceeding $1.3M.

### Internal RPC Bridge Discovery

At organizations with heavy internal-RPC architectures, search Shodan/Censys for internal service names exposed on public-facing ports. Query patterns:
```
org:"Target Corp" http.title:"gRPC" OR http.title:"Thrift" OR http.title:"protobuf"
org:"Target Corp" port:9090,50051,8081 http.html:"service"
```
Internal service names appearing in public HTTP responses are a red flag for RPC bridge endpoints that may lack auth.

### SaaS Platform Fingerprinting

When Shodan reveals a target running a recognizable SaaS or open-source platform, immediately test known platform-specific misconfigurations:
- **Salesforce Experience Cloud**: test `/s/contentdocument/ContentDocument/All`
- **Chronograf/InfluxDB**: test admin ports 8083/8086 for unauthenticated access
- **Flagsmith/Sentry/GitLab self-hosted**: check default admin paths and API keys
- **Firebase**: test `.json` append on Realtime Database URLs for open read

### IoT Device Account-Linking Audit

For any IoT device discovered on Shodan that supports account linking:
1. Map the linking protocol with MITM
2. Look for trust based on LAN-presence alone or missing physical confirmation
3. Test whether link-then-unlink cycles leave orphaned auth tokens
4. Check for firmware update endpoints accepting unsigned payloads

### Cross-Product Bulk Export Path Testing

When Shodan reveals an organization running multiple interconnected products, map cross-product export paths:
- Product A holds resources with strict ACLs
- Product B provides a bulk export/download/API that queries Product A's data
- If Product B's export path checks its own permissions (not Product A's), you can export data you should not access

### PRNG Audit for Externally-Observable Identifiers

For any system that generates externally-observable identifiers (session IDs, tokens, sequence numbers), collect 1000+ samples and test:
1. Sequential or time-correlated patterns
2. Entropy analysis (NIST SP 800-22 or similar)
3. Hash-key recovery from observable sequences
4. Whether the PRNG state can be reconstructed from a small window of outputs

## Key Queries Reference

| Purpose | Shodan Query |
|---------|-------------|
| All org assets | `org:"Target Corp"` |
| Specific ASN | `asn:AS12345` |
| HTTP title match | `http.title:"admin"` |
| Open ports | `hostname:target.com port:8080` |
| Product + version | `product:"Apache" version:"2.4.49"` |
| SSL cert org | `ssl.cert.subject.O:"Target Corp"` |
| Country filter | `org:"Target Corp" country:US` |
| Favicon hash | `http.favicon.hash:116323821` |
| Has screenshot | `has_screenshot:true org:"Target Corp"` |
| HTTP headers | `http.headers.server:"cloudflare"` |

## What to Look For

- Database ports open to the internet without authentication
- Admin panels and management interfaces on non-standard ports
- Software versions with known CVEs
- Internal hostnames leaked in SSL certificates or HTTP headers
- Development/staging services exposed alongside production
- Default credentials on discovered services (check after discovery)
- Services that should be internal-only (Elasticsearch, Redis, Memcached)
- Disabled UI buttons hiding functional API endpoints (always remove `disabled` attribute and observe the request)

## Operational Notes

- Shodan/Censys data can be hours to weeks old; verify findings against live hosts
- API access provides richer data than web interface (historical, bulk, filters)
- Rate limiting applies: batch queries efficiently
- Results are passive reconnaissance; no packets sent to target until you verify
- Combine with target_mapping skill for complete infrastructure picture
