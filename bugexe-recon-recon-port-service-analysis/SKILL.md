---
name: recon_port_service_analysis
category: reconnaissance
description: Port scanning + service fingerprinting + per-service deep enumeration. Covers TCP/UDP scan strategy (top-100, top-1000, all-65535), SYN/CONNECT/FIN scan modes, IPv4 + IPv6 coverage, NSE script categories, and per-service deep enum recipes for SSH/FTP/SMTP/DNS/SMB/LDAP/RPC/SNMP/NTP/SQL/Redis/Memcached/Elasticsearch/MongoDB/Docker-registry/Kubernetes/VNC/RDP/IMAP/POP3. Composes with ASN mapping, vhost fuzzing, and information disclosure skills.
depends_on: []
---

# Port & Service Analysis

## Why Deep Port Analysis Matters

A port scan that returns "port 22 = ssh, port 80 = http, port 443 = https" is the bare minimum, not the deliverable. Every open port is an application-layer attack surface, and every application has its own enumeration depth. The difference between a surface scan and a deep scan is the difference between "I found 6 open ports" and "I found a Redis instance with no auth, an Elasticsearch cluster exposing `_cat/indices`, an LDAP that allows anonymous bind, a Docker registry listing all images, and a Kubernetes API listening on 10250."

Most organizations have layered hardening on the standard web tier (nginx, application firewall, rate limiting, authentication) but neglect the supporting services. The attack surface is not at port 443 — it is at the database, message broker, secret manager, internal API, debug endpoint, and admin console that the developer believed was unreachable from the internet. Port and service analysis exists to find those.

The technique is mechanical but the depth matters. A `nmap --top-ports 100` is necessary, not sufficient. The full pipeline:

1. Scan all 65535 TCP ports (with rate limits if the target is sensitive)
2. Scan top-100 UDP ports (full UDP is too slow for most engagements)
3. Service-detect every open port
4. Per-service deep enumeration on every open port (not just version banner — actual usage probes)
5. IPv6: same pipeline if the target has AAAA records
6. Re-feed discovered services into other recon skills

## Port Scan Strategy

The strategy is staged: fast pass first, comprehensive pass after, all-65535 if the comprehensive pass shows interesting non-standard ports.

### Fast pass — top-100 TCP

The top-100 TCP ports cover ~85% of common services (HTTP, HTTPS, SSH, FTP, SMTP, DNS, SMB, RDP, MySQL, PostgreSQL, Redis, MongoDB, etc.). Fast and low-noise, suitable for an initial sanity check.

```
nmap -sS --top-ports 100 -T4 {ip}
```

Or with `naabu` (simpler, faster for IP-list inputs):

```
naabu -tp 100 -host {ip} -silent
```

If the fast pass returns more than ~5 open ports or any non-standard port, escalate to the comprehensive pass.

### Comprehensive pass — top-1000 TCP

Standard `nmap` default. Covers most services that any operator would expose.

```
nmap -sS --top-ports 1000 -T4 -sV --version-intensity 5 {ip}
```

`-sV --version-intensity 5` enables service detection at moderate intensity (probes enough to identify the service version without being overly noisy).

### Exhaustive pass — all 65535 TCP

When the target is high-value or the comprehensive pass shows anomalies (e.g., open ports in the 30000-50000 range, suggesting non-standard service exposure), run the full pass.

```
nmap -sS -p- -T4 --min-rate 1000 --max-retries 2 {ip}
```

`-T4 --min-rate 1000` is moderate-aggressive. Lower (`-T3`, `--min-rate 100`) for friendly hosts; higher (`-T5`) for hostile-and-disposable. The full pass takes 5-30 minutes per IP depending on packet-loss and rate limits.

For very large IP ranges, `masscan` is faster than `nmap` for the discovery phase, then re-scan discovered ports with `nmap -sV` for fingerprinting:

```
masscan -p1-65535 --rate 10000 {cidr-range} -oG masscan-out.txt
# Extract IP+port pairs and re-scan with nmap
nmap -sV -p {port-list} {ip-list}
```

### UDP scan — top-100

UDP is often overlooked because UDP scans are slow (no connection state means timeouts dominate). It is also where the highest-value misconfigurations live: DNS amplification, SNMP community-string leaks, NTP monlist, IPMI exposure.

```
nmap -sU --top-ports 100 -T4 {ip}
```

For IPMI specifically (common on hardware management interfaces): UDP/623 with Cipher 0 / 1 enumeration.

```
nmap -sU -p 623 --script ipmi-version,ipmi-cipher-zero {ip}
```

### TCP scan modes — pick the right one

- `-sS` (SYN scan) — default, requires raw socket access, fast, less likely to be logged by the application
- `-sT` (CONNECT scan) — full TCP handshake, no privileges required, slower, logged by application
- `-sF` / `-sN` / `-sX` (FIN / NULL / Xmas) — sends unusual flag combinations; useful when the firewall blocks SYN but lets through TCP segments with other flag combinations
- `-sA` (ACK scan) — does not detect open vs closed but does map firewall rules (filtered vs unfiltered)
- `-sI` (idle/zombie scan) — uses an unrelated host's IP-ID counter; advanced, used when source-spoofing is required

For routine bug-bounty recon, `-sS` is the default. For environments where stealth matters or where the firewall blocks SYN, fall back to `-sT` or experiment with `-sF`.

### IPv6 — also scan

If the target's DNS includes AAAA records, scan over IPv6:

```
nmap -6 -sS --top-ports 1000 -T4 {ipv6-addr}
```

IPv6 is frequently neglected by operators. Services that are firewalled on IPv4 are sometimes left wide open on IPv6 because the operator forgot the dual-stack listener.

## Service Detection

Open port detection is necessary; service identification is required. Three depth levels.

### Banner grab (-sV)

`nmap -sV` sends well-known protocol probes and matches responses against a large signature database (`nmap-service-probes`). It identifies the service (e.g., "OpenSSH") and often the version ("8.9p1 Ubuntu-3ubuntu0.1"). Version → CVE candidates.

```
nmap -sV --version-intensity 7 -p {port-list} {ip}
```

`--version-intensity` ranges 0-9. Higher = more probes = more accurate identification but more noise. 7 is a good default for thorough enum.

### OS fingerprint (-O)

`nmap -O` analyzes TCP/IP-stack heuristics (TCP options ordering, window size, ICMP responses, etc.) to guess the OS family and version. Useful for prioritizing which CVEs to chase but not as reliable as service banners.

```
nmap -O -T4 {ip}
```

### Aggressive (-A)

`-A` enables `-sV`, `-O`, NSE default scripts, and traceroute in one flag. Slow but informative.

```
nmap -A -T4 -p {port-list} {ip}
```

Run `-A` once per IP after the discovery phase. Save the output — it becomes the input for per-service deep enum.

### NSE scripts

Nmap Scripting Engine has hundreds of scripts. Use categories matched to the engagement:

- `default` — safe scripts, baseline information
- `version` — same as `-sV`
- `discovery` — gather more info about the target
- `safe` — unlikely to cause harm
- `auth` — authentication-related (banner, supported methods)
- `vuln` — known-vuln checks (some are false-positive prone)
- `exploit` — actually exploits (use with explicit authorization only)
- `intrusive` — likely to be flagged by IDS
- `dos` — denial of service (do NOT run on production targets)

Practical default for in-scope bug-bounty recon:

```
nmap -sV --script "default,discovery,safe,auth,vuln" -p {port-list} {ip}
```

Add `-T2` for friendly scanning if the org is sensitive to noise.

## Per-Service Deep Enumeration

This is the core methodology. Do not stop at "port 22 = ssh." For every open port, run the per-service deep enum.

### SSH (22, 2222, 22222)

```
ssh -vvv -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p {port} root@{ip} 2>&1 | head -60
```

Captures the SSH banner (version), supported algorithms, host key fingerprint, and authentication methods.

NSE alternatives:

```
nmap -p {port} --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods {ip}
```

What to look for:

- OpenSSH version with known CVEs (e.g., < 7.4 → CVE-2017-15906 + others)
- Weak algorithms (CBC ciphers, weak MACs, weak KEX)
- Authentication: `password` enabled (brute-force surface), `publickey` only (harder), `keyboard-interactive` (PAM, may have weakness)
- Host key reuse across different IPs of the same org → infrastructure correlation

### FTP (21, 990 FTPS) and SMTP (25, 465, 587, 2525)

```
nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor {ip}
nmap -p 25,465,587 --script smtp-commands,smtp-enum-users,smtp-open-relay,smtp-vuln-cve2010-4344 {ip}
```

FTP: anonymous login enabled = direct read of server contents; FTP bounce attack; vsftpd backdoor (CVE-2011-2523). Manual: `ftp -inv {ip}` then `user anonymous anonymous@example.com`.

SMTP: EHLO response (supported extensions PIPELINING/SIZE/STARTTLS/AUTH); AUTH method exposure (PLAIN/LOGIN/CRAM-MD5/NTLM — plaintext over non-TLS = credential exposure); open-relay test (`MAIL FROM:<external>` + `RCPT TO:<external>` accepted → relay abuse); VRFY / EXPN user enumeration; STARTTLS cert. Manual: `swaks --to test@target.example --server {ip}:{port} --auth PLAIN --auth-user test --auth-password test`.

### DNS (53/UDP, 53/TCP)

```
nmap -p 53 -sU -sT --script dns-recursion,dns-cache-snoop,dns-zone-transfer,dns-nsid,dns-srv-enum {ip}
```

The high-value tests:

- `dns-zone-transfer` (AXFR): `dig axfr @{ip} target.example` — if it succeeds, you've dumped the full DNS zone
- Recursion enabled for external clients: amplification + cache-poisoning surface
- `version.bind` chaos query: leaks the DNS server version

```
dig @{ip} version.bind chaos txt
dig @{ip} hostname.bind chaos txt
dig axfr @{ip} target.example
```

### SMB (139/TCP, 445/TCP)

```
nmap -p 139,445 --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb-protocols,smb-security-mode,smb-vuln-* {ip}
```

What to look for:

- Shares with anonymous read access (`\\{ip}\public`, `\\{ip}\IPC$`, etc.)
- SMB protocol versions enabled: SMBv1 = critical (CVE-2017-0144 EternalBlue)
- Signing requirement: `signing not required` enables NTLM relay attacks
- Null session: `smbclient -L //{ip}/ -N`

```
smbclient -L //{ip}/ -N
smbclient //{ip}/{share} -N
```

### LDAP (389, 636 LDAPS, 3268 GC, 3269 GC SSL)

```
nmap -p 389,636,3268,3269 --script ldap-rootdse,ldap-search,ldap-novell-getpass {ip}
```

What to look for:

- Anonymous bind allowed: `ldapsearch -x -h {ip} -s base namingContexts`
- Schema disclosure (rootDSE)
- Anonymous tree search reveals AD/IPA/389DS structure → user enumeration

```
ldapsearch -x -h {ip} -p {port} -b "" -s base "(objectClass=*)"
ldapsearch -x -h {ip} -p {port} -b "DC=target,DC=example" "(objectClass=user)" sAMAccountName
```

### RPC / portmap (111/TCP, 111/UDP)

```
rpcinfo -p {ip}
nmap -p 111 --script rpcinfo {ip}
```

`rpcinfo` enumerates registered RPC services and the ports they listen on. NFS (port 2049) is the high-value follow-up: `showmount -e {ip}` lists exported shares.

### SNMP (161/UDP, 162/UDP traps)

```
nmap -p 161 -sU --script snmp-info,snmp-sysdescr,snmp-interfaces,snmp-processes,snmp-win32-software,snmp-netstat {ip}
```

Try common community strings:

```
for c in public private community manager admin root snmp; do
  snmpwalk -v 1 -c $c {ip} 1.3.6.1.2.1.1.5.0 2>/dev/null && echo "[+] community: $c"
done
```

A weak community string + read access leaks: hostname, OS, network interfaces, running processes, installed software, routing table, ARP table.

### NTP (123/UDP)

```
nmap -p 123 -sU --script ntp-info,ntp-monlist {ip}
```

`ntp-monlist` (CVE-2013-5211) returns the last-600 IPs that talked to the NTP server — both an IP-disclosure leak and a DDoS amplification primitive. Direct probe: `ntpdc -c monlist {ip}` and `ntpq -c rv {ip}`.

### Relational SQL — MSSQL (1433), MySQL/MariaDB (3306), PostgreSQL (5432), Oracle (1521)

For every relational DB port, run service-specific NSE scripts and try anonymous / default-credential auth. Common patterns:

```
nmap -p 1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-ntlm-info {ip}
nmap -p 3306 --script mysql-info,mysql-empty-password,mysql-users,mysql-databases {ip}
nmap -p 5432 --script pgsql-brute {ip}
nmap -p 1521 --script oracle-sid-brute,oracle-tns-version {ip}
```

What to look for: version banner with known CVEs, empty-password admin (`sa`, `root`, `postgres`, `system`), anonymous user enumeration, and NTLM info leak (MSSQL specifically — exposes NetBIOS name and AD domain). Manual confirm with `sqsh`, `mysql`, `psql`, `sqlplus` / `tnscmd10g`.

### Redis (6379, 6380)

Redis with no auth is a critical-severity finding when exposed. The protocol is RESP2/RESP3 over TCP — no handshake, just text commands.

```
redis-cli -h {ip} -p {port} INFO
redis-cli -h {ip} -p {port} CLIENT LIST
redis-cli -h {ip} -p {port} CONFIG GET *
redis-cli -h {ip} -p {port} KEYS *
```

If `INFO` returns server stats without `AUTH` first → no auth required → full read access. Common follow-up: write-to-disk via `CONFIG SET dir` + `CONFIG SET dbfilename` to plant a webshell or SSH key.

### Memcached (11211/TCP, 11211/UDP), Elasticsearch (9200), MongoDB (27017), Docker registry (5000)

Each of these is high-yield when exposed without authentication:

```
echo "stats" | nc {ip} 11211                                      # memcached
curl http://{ip}:9200/_cluster/health                              # elasticsearch
curl http://{ip}:9200/_cat/indices?v                               # elasticsearch indices
mongosh "mongodb://{ip}:27017/" --eval "show dbs"                  # mongodb
curl http://{ip}:5000/v2/_catalog                                  # docker registry
```

For Memcached: `stats` returns server info; UDP variant supports amplification DDoS (CVE-2018-1000115). For Elasticsearch: `_cat/indices` reveals every index name (often customer data, logs, tokens). For MongoDB: `show dbs` lists all databases when no auth. For Docker registry: `_catalog` lists every repo and image — pulling images leaks code, secrets, and build artifacts.

### Kubernetes API (6443, 8443, 10250 kubelet, 10255 read-only kubelet, 10256 kube-proxy)

```
curl -k https://{ip}:6443/api
curl -k https://{ip}:6443/api/v1/namespaces
curl -k https://{ip}:10250/pods
curl -k https://{ip}:10250/runningpods/
curl http://{ip}:10255/pods
curl http://{ip}:10255/metrics
```

The kubelet read-only port (10255) is unauth by default in old configs and reveals running pods. The kubelet API (10250) without auth allows pod exec.

### Remote-desktop / mail surfaces — VNC (5900-5910), RDP (3389), IMAP/POP3 (143, 993, 110, 995)

```
nmap -p 5900-5910 --script vnc-info,vnc-title,realvnc-auth-bypass {ip}
nmap -p 3389 --script rdp-enum-encryption,rdp-vuln-ms12-020,rdp-ntlm-info {ip}
nmap -p 143,993,110,995 --script imap-capabilities,pop3-capabilities,imap-ntlm-info,pop3-ntlm-info {ip}
```

What to look for: VNC with no password set (direct visual access) or old VNC versions with auth-bypass CVEs; RDP with NLA disabled (BlueKeep CVE-2019-0708, MS12-020) or NTLM info leak (NetBIOS name + AD domain); IMAP/POP3 capability banner showing weak AUTH methods or NTLM info leak via SASL NTLM.

### Other protocols worth probing

- **CouchDB (5984)**: `curl http://{ip}:5984/_all_dbs`
- **CassandraDB (9042, 9160)**: cqlsh, native protocol
- **Zookeeper (2181)**: `echo stat | nc {ip} 2181`
- **Kafka (9092)**: kafka-topics.sh, kafka-console-consumer.sh
- **RabbitMQ management (15672)**: `curl http://{ip}:15672/api/overview` with `guest:guest`
- **Consul (8500)**: `curl http://{ip}:8500/v1/agent/self`
- **Etcd (2379, 2380)**: `etcdctl --endpoints=http://{ip}:2379 get / --prefix`
- **Hadoop (50070, 8088, 8042)**: NameNode UI, ResourceManager UI
- **Spark UI (4040, 7077, 8080)**: master UI, application UI
- **Solr (8983)**: `curl http://{ip}:8983/solr/admin/cores`
- **InfluxDB (8086)**: `curl http://{ip}:8086/query?q=SHOW+DATABASES`
- **NATS (4222)**: text protocol over TCP, `INFO` on connect
- **Kibana (5601)**: web UI, often exposes Elasticsearch by extension
- **Grafana (3000)**: web UI, `/login` shows version, `/api/datasources` if unauth
- **Jenkins (8080, 50000)**: `/script` console if unauth = RCE
- **GitLab (80, 443, 22)**: `/api/v4/version` for version disclosure
- **Tomcat manager (8080, 8009 AJP)**: `/manager/html` with `tomcat:tomcat`
- **JMX (1099, 11099)**: management interface, often unauth = RCE
- **Java RMI registry (1099)**: `nmap --script rmi-dumpregistry`

## Methodology

The full pipeline:

1. **IP set**: derive target IPs from ASN walks (`recon_asn_network_mapping`), DNS resolutions (`recon_subdomain_active_brute`), and direct scope assets
2. **Discovery scan**: top-100 TCP per IP for fast triage; escalate to top-1000 or all-65535 if any signal
3. **UDP discovery**: top-100 UDP per IP
4. **Service detection**: `-sV` per open port
5. **Per-service deep enum**: run the matching recipe above for every open port
6. **NSE vulnerability scripts**: targeted vuln scripts based on identified service+version
7. **CVE candidate generation**: for every banner version, query NVD/CVE for matching CVEs
8. **Cross-feed**: HTTP ports → `recon_vhost_fuzzing`; admin/dev ports → `recon_information_disclosure`; new IPs discovered via banner leak → re-feed into IP set
9. **IPv6**: full pipeline against the IPv6 address if AAAA records exist

## Tool Primitives

Sandbox-installable tools (verify per-environment):

- `nmap` — flagship port scanner + NSE
- `naabu` — fast, simple TCP scanner from ProjectDiscovery
- `masscan` — internet-scale TCP scanner
- `rustscan` — fast wrapper that pipes to nmap
- `unimap` — modern unified scanner
- `httpx` — HTTP probing (chain to vhost fuzzing)
- `nuclei` — template-driven vulnerability scanner
- `sslscan` / `sslyze` / `testssl.sh` — TLS configuration analysis
- service-specific clients (`smbclient`, `redis-cli`, `mongosh`, `mysql`, `psql`, `ldapsearch`, `swaks`, `dig`, `mongosh`)
- `enum4linux-ng` — SMB / LDAP / RID enumeration
- `crackmapexec` / `nxc` — multi-protocol enumeration

## Pitfalls

### Rate limit triggers

Aggressive scanning trips IDS. Symptoms: nmap reporting all-ports-filtered after the first few hundred queries, `tcp_retransmits` growing, response latency increasing. Solution: drop to `-T2`, use `--max-rate 100`, randomize port order with `--randomize-hosts`, and rotate source IPs if you have multiple egress addresses.

### CDN / firewall hides origin

If the target's DNS points to a CDN (Cloudflare, Akamai, Fastly, CloudFront), your port scan is hitting the CDN edge, not the origin. The CDN exposes only ports 80 and 443. The origin may have many more open ports, but is not directly reachable. Pivot to origin-IP discovery (chain to `recon_origin_disclosure` if it exists, or use historical DNS / Censys / Shodan / SSL-cert-fingerprint matching to find the origin).

### Port forwards / NAT

A scan target may be a NAT gateway, port-forwarding rules from a public IP to a different internal IP per port. Different ports may belong to different backend services. Treat each open port's banner as potentially-different host; do not assume single-host coherence.

### IPv6 neglected

Operators that forget IPv6 leave the dual-stack listener wide open. Always check AAAA records, always run the full pipeline against the IPv6 address.

### Banner spoofing / honeypots

Some operators run honeypots (Cowrie SSH, Conpot ICS, Dionaea SMB) that mimic real services. Symptoms: banners that look "too good" (default versions, default config strings, suspiciously open auth). Cross-validate against TTL, ASN, and behavior — a real Redis allows arbitrary commands; a honeypot may parrot specific commands and 500-error on others.

### Service version detection false positives

`nmap -sV` matches against signature databases. Custom services or modified banners may mismatch. Always cross-verify a critical version match before reporting (e.g., a CVE based on `nmap`'s version detection alone is not strong evidence — confirm with a service-specific probe).

### Port-knocking / single-packet auth

Some hosts use port-knocking: a port appears closed until a specific sequence of packets is sent. A naive scan reports closed; the port is in fact open after the right sequence. Out of scope for routine recon but worth flagging if banners hint at the practice.

### UDP false negatives

UDP scans frequently report "open|filtered" rather than definitive open/closed. The default 1-second timeout is often too short. Add `--max-retries 3` and increase per-port timeout for UDP. Re-scan high-value UDP ports (53, 161, 123, 500, 1900, 5353) individually with longer timeouts.

### Scanning your own VPN

If you are connected to the target's VPN (e.g., partner connection, employee access), your IP is inside their perimeter and the scan results reflect internal exposure, not external. Confirm scope before reporting findings — internal exposure is a different report than external exposure.

## Output Format

For every (IP, port) pair, record:

```
{
  "ip": "{ip}",
  "ipv6": "{ipv6-or-null}",
  "port": {port},
  "protocol": "tcp|udp",
  "state": "open|closed|filtered|open|filtered",
  "service": "{name}",
  "version": "{version-string}",
  "banner": "{raw-banner}",
  "tls_present": true|false,
  "tls_cert_cn": "{cn-or-null}",
  "tls_cert_san": ["{san1}"],
  "tls_protocol_versions": ["TLSv1.2", "TLSv1.3"],
  "ntlm_info_leak": "{netbios-name|null}",
  "auth_methods": ["password", "publickey"],
  "anonymous_access": true|false,
  "special_flags": ["NULL_SESSION", "NO_AUTH", "WEAK_CIPHER", "DEFAULT_CRED"],
  "cve_candidates": [
    {"id": "CVE-yyyy-nnnn", "score": 9.8, "match_confidence": "high|medium|low"}
  ],
  "nse_scripts_run": ["{script1}", "{script2}"],
  "discovered_via": "topscan|fullscan|banner-leak|recursive",
  "scan_timestamp": "{iso8601}",
  "additional_endpoints": [
    {"path": "{url-path}", "status": {code}, "size": {bytes}}
  ]
}
```

Persist as JSON Lines per IP per scan run. Re-feed into vhost fuzzing, information disclosure, and ASN mapping.

## Composes With

- `recon_asn_network_mapping` — provides target IP set for the scan
- `recon_subdomain_active_brute` — DNS-resolved IPs are scan candidates
- `recon_vhost_fuzzing` — every HTTP-listening port is a vhost-fuzz target
- `recon_information_disclosure` — every open admin / dev / debug port is a path-fuzz target
- `recon_origin_disclosure` (if exists) — when the target is CDN-fronted, pivot to origin first
- `js_analysis` — when an HTTP listener serves JS, mine the JS for additional internal endpoints

Port-and-service is a recon hub. Every other technique either feeds it (IP discovery) or consumes its output (HTTP-layer probing).

## Termination

Port-and-service analysis terminates when **the full IP × port × protocol matrix has been probed and per-service deep enumeration has been run on every open port**, not when "we have N open ports."

Concretely:

- Per IP: scan all 65535 TCP ports (minimum top-1000; full sweep when budget permits)
- Per IP: scan top-100 UDP ports (minimum); high-value UDP ports always
- Per IP: scan over IPv4 AND IPv6 if AAAA exists
- Per open port: run service detection at version-intensity 7 minimum
- Per open port: run the per-service deep enum recipe above
- Per banner version: query CVE database for matching CVEs and tag candidates
- Per discovered new IP (from banner leak, NTLM info, certificate SAN, etc.): add to IP set and re-feed pipeline

There is no "we have enough." The cost of an extra port probe is one packet. The cost of a missed open admin port is the entire finding. Iterate to exhaustion across all ports, all protocols, both IP families. When a full pass produces no new ports and no new banners, the loop is done. Until then, continue.
