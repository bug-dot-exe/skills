---
name: target_mapping
category: reconnaissance
description: Target infrastructure mapping with subdomain enumeration, IP range discovery, CDN detection, shared hosting, and autonomous system lookup
depends_on: []
---

# Target Mapping

Build a complete picture of the target's internet-facing infrastructure. Subdomain enumeration is just the start. Map IP ranges, identify CDN-protected vs direct assets, find shared hosting neighbors, and trace autonomous system boundaries.

## When to Use

- Starting reconnaissance on a new target
- Scope includes wildcard domains (*.target.com)
- Need to identify the full attack surface before hunting
- Looking for assets that bypass CDN or WAF protections
- Mapping relationships between the target and its subsidiaries

## Methodology

### Phase 1: Subdomain Enumeration

Run multiple tools for maximum coverage:

1. **subfinder**: passive sources (VirusTotal, SecurityTrails, Shodan, Censys, crt.sh)
   ```
   subfinder -d target.com -all -o subs_subfinder.txt
   ```
2. **amass enum**: active + passive with DNS resolution
   ```
   amass enum -d target.com -o subs_amass.txt
   ```
3. **crt.sh**: certificate transparency logs
   ```
   curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
   ```
4. **Chaos**: ProjectDiscovery dataset for known subdomains
5. **Merge and deduplicate**: combine all results, resolve DNS, remove dead hosts

### Phase 2: IP Range Mapping

From discovered subdomains, map the underlying IP infrastructure:

1. **Resolve all subdomains**: bulk DNS resolution with dnsx or massdns
2. **Group by IP/CIDR**: identify IP ranges owned by the target
3. **WHOIS lookup**: confirm ownership of IP blocks via ARIN/RIPE/APNIC
4. **Reverse DNS**: find additional hostnames on discovered IPs
5. **Port scan representative IPs**: naabu or masscan on key ranges

### Phase 3: CDN Detection

Identify which assets are behind CDNs vs direct:

| Indicator | CDN Present | Direct |
|-----------|-------------|--------|
| IP ownership | Cloudflare, Akamai, Fastly ranges | Target's own ASN |
| DNS CNAME | Points to CDN domain | Points to target IP |
| Response headers | `cf-ray`, `x-akamai-*`, `x-fastly-*` | No CDN headers |
| Multiple IPs | Anycast addresses | Single or few IPs |

Direct assets are higher-priority targets: no WAF, no caching layer, direct server access.

### Phase 4: Shared Hosting Identification

Check if target IPs host other organizations:

1. **Reverse IP lookup**: Bing `ip:1.2.3.4`, Shodan, SecurityTrails
2. **Virtual host discovery**: send requests with different Host headers to find co-hosted sites
3. **SSL certificate SANs**: other domains on the same certificate
4. **Implication**: shared hosting means shared infrastructure vulnerabilities

### Phase 5: Related Domain Discovery

Find domains related to the target but outside the primary domain:

1. **WHOIS cross-reference**: same registrant name, email, or organization
2. **Google Analytics ID**: find sites sharing the same UA-XXXXX tracking ID
3. **Favicon hash**: Shodan `http.favicon.hash:HASH` for sites using the same favicon
4. **SSL certificate organization**: Censys/crt.sh search by organization field
5. **Acquisitions and subsidiaries**: business research for related entities

### Phase 6: Autonomous System (ASN) Lookup

Map the target's network presence at the routing level:

1. Look up target's ASN: `whois -h whois.radb.net target.com`
2. Enumerate all prefixes announced by the ASN
3. Scan for services across the full prefix range
4. Check for ASN peers and upstream providers

## Corpus-Derived Hunting Patterns

### Acquisition Infrastructure Mapping

For every acquired company in scope, enumerate the original company's infrastructure. Acquired domains rarely get reabsorbed into the acquirer's security stack quickly. Run subdomain enumeration, port scanning, and fingerprinting on the acquired brand's domain separately -- these assets often run legacy stacks with weaker controls and less monitoring.

### CI/CD and Public Repository Attack Surface

For every public repo owned by the target org, pull `.github/workflows/` and scan for:
1. `pull_request_target` triggers (pwn-request vector)
2. Self-hosted runner labels in workflow `runs-on` fields
3. Workflow permissions granting `write` access to `contents`, `id-token`, or `packages`
4. Composite actions that interpolate PR title/body into shell commands

Public CI/CD workflows are a distinct attack surface class -- map them as infrastructure, not just code.

### Cloud Service Layer Confusion

When a target uses a cloud service layered atop another cloud service (e.g., container registry over object storage, function service over container runtime), map BOTH layers independently. The inner layer's auth boundary may not enforce the outer layer's access restrictions. Test whether credentials scoped to the outer service grant unscoped access to the inner service.

### Electron/Desktop App Mapping

For any desktop application distributed by the target:
1. Inspect launch arguments for `--remote-debugging-port`, `--inspect`, `--remote-allow-origins=*`
2. Check if CEF/Electron debug ports are accessible on localhost or LAN
3. Map IPC channels and protocol handlers (`target://` custom schemes)
4. Decompile `asar` bundles for embedded secrets and internal URLs

### Metadata Egress on Cloud-Hosted Services

For any service the target hosts on cloud VMs that executes user-supplied code or fetches user-supplied URLs, test metadata endpoint egress: `169.254.169.254` (AWS/GCP), `100.100.100.200` (Alibaba), `169.254.169.253` (Azure IMDS). Map which services have network-level metadata protection vs which rely on application-layer blocking.

### Android/Mobile App Component Mapping

For targets with mobile applications:
1. Decompile the APK and parse `AndroidManifest.xml`
2. List every `exported="true"` activity, service, receiver, and content-provider
3. For each exported component, trace what data/intents it accepts and what privileged actions it performs
4. Map all custom URI schemes and deep links as entry points into the app's web origin

## Output Format

Compile the target map:

```
Target: target.com
ASN: AS12345 (Target Corp)
IP Ranges: 203.0.113.0/24, 198.51.100.0/24

Subdomains: 347 discovered, 283 live
CDN-protected: 45 (Cloudflare)
Direct access: 238

Key Assets:
  - api.target.com (direct, 203.0.113.10, nginx/1.21)
  - admin.target.com (direct, 203.0.113.15, custom app)
  - staging.target.com (direct, 198.51.100.5, no WAF)
  - app.target.com (Cloudflare, origin unknown)

Related Domains:
  - targetcorp.io (same registrant)
  - target-internal.com (same SSL cert org)

Shared Hosting:
  - 203.0.113.10 also hosts: otherclient.com
```

## Prioritization

After mapping, prioritize assets for testing:

| Priority | Asset Type | Reason |
|----------|-----------|--------|
| Highest | Direct (no CDN), staging/dev | Weakest defenses |
| High | Admin panels, API endpoints | High-value targets |
| Medium | CDN-protected primary apps | Standard attack surface |
| Lower | Static content, marketing sites | Low vuln potential |

## Pro Tips

- Multi-tenant content tools that let users select a target tenant from a dropdown almost always have BOLA on the underlying API. The dropdown is a UI convenience, not an authorization boundary. Test every tenant-selecting parameter with IDs from other tenants.
- For every state-changing operation in a multi-tenant collaborative product, identify the `(object, target_principal, actor)` tuple in the request, then swap each element independently while holding the others constant.
- When mapping OAuth providers, audit scopes by exhaustively enumerating their API capabilities, not by reading the consent screen. The consent screen describes intent; the API enforces (or fails to enforce) boundaries.
- Internal-tooling surfaces (corp domains, employee dashboards, admin portals) are often paid at premium tiers even for standard vulnerability classes. Prioritize `*.corp.*`, `*.internal.*`, `*admin*` subdomains.
