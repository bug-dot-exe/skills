---
name: nmap
description: Canonical Nmap CLI syntax, two-pass scanning workflow, and sandbox-safe bounded scan patterns.
depends_on: []
---

# Nmap CLI Playbook

Official docs:
- https://nmap.org/book/man-briefoptions.html
- https://nmap.org/book/man.html
- https://nmap.org/book/man-performance.html

Canonical syntax:
`nmap [Scan Type(s)] [Options] {target specification}`

High-signal flags:
- `-n` skip DNS resolution
- `-Pn` skip host discovery when ICMP/ping is filtered
- `-sS` SYN scan (root/privileged)
- `-sT` TCP connect scan (no raw-socket privilege)
- `-sV` detect service versions
- `-sC` run default NSE scripts
- `-p <ports>` explicit ports (`-p-` for all TCP ports)
- `--top-ports <n>` quick common-port sweep
- `--open` show only hosts with open ports
- `-T<0-5>` timing template (`-T4` common)
- `--max-retries <n>` cap retransmissions
- `--host-timeout <time>` give up on very slow hosts
- `--script-timeout <time>` bound NSE script runtime
- `-oA <prefix>` output in normal/XML/grepable formats

Agent-safe baseline for automation:
`nmap -n -Pn --open --top-ports 100 -T4 --max-retries 1 --host-timeout 90s -oA nmap_quick <host>`

Common patterns:
- Fast first pass:
  `nmap -n -Pn --top-ports 100 --open -T4 --max-retries 1 --host-timeout 90s <host>`
- Very small important-port pass:
  `nmap -n -Pn -p 22,80,443,8080,8443 --open -T4 --max-retries 1 --host-timeout 90s <host>`
- Service/script enrichment on discovered ports:
  `nmap -n -Pn -sV -sC -p <comma_ports> --script-timeout 30s --host-timeout 3m -oA nmap_services <host>`
- No-root fallback:
  `nmap -n -Pn -sT --top-ports 100 --open --host-timeout 90s <host>`

Critical correctness rules:
- Always set target scope explicitly.
- Prefer two-pass scanning: discovery pass, then enrichment pass.
- Always set a timeout boundary with `--host-timeout`; add `--script-timeout` whenever NSE scripts are involved.
- Keep discovery scans tight: use explicit important ports or a small `--top-ports` profile unless broader coverage is explicitly required.
- In sandboxed runs, avoid exhaustive sweeps (`-p-`, very high `--top-ports`, or wide host ranges) unless explicitly required.
- Do not spam traffic; start with the smallest port set that can answer the question.
- Prefer `naabu` for broad port discovery; use `nmap` for scoped verification/enrichment.

Usage rules:
- Add `-n` by default in automation to avoid DNS delays.
- Use `-oA` for reusable artifacts.
- Prefer `-p 22,80,443,8080,8443` or `--top-ports 100` before considering larger sweeps.
- Do not use `-h`/`--help` for routine usage unless absolutely necessary.

Failure recovery:
- If host appears down unexpectedly, rerun with `-Pn`.
- If scan stalls, tighten scope (`-p` or smaller `--top-ports`) and lower retries.
- If scripts run too long, add `--script-timeout`.

If uncertain, query web_search with:
`site:nmap.org/book nmap <flag>`

## Corpus-Derived Advanced Workflows

Patterns extracted from 566 disclosed reports ($3.6M total bounty). These show HOW top researchers use port scanning and service enumeration to find real bugs.

### Two-Pass Scanning with Service Fingerprinting

The standard recon pattern: fast discovery pass, then targeted enrichment on open ports:

```bash
# Pass 1: Fast discovery
nmap -n -Pn --top-ports 200 --open -T4 --max-retries 1 --host-timeout 90s -oA nmap_disco <host>

# Extract open ports
PORTS=$(grep -oP '\d+/open' nmap_disco.gnmap | cut -d/ -f1 | sort -un | paste -sd,)

# Pass 2: Service version + default scripts on discovered ports only
nmap -n -Pn -sV -sC -p "$PORTS" --script-timeout 30s --host-timeout 3m -oA nmap_services <host>
```

### Platform Fingerprinting for Known-Misconfig Checklists

After port scanning, identify the technology stack and test known default configurations ($50K+ pattern):

```bash
# Service version detection reveals platform identity
nmap -n -Pn -sV -p 80,443,8080,8443,9090 --host-timeout 90s <host>

# NSE scripts for specific platform fingerprinting
nmap -n -Pn --script http-title,http-server-header,http-favicon-hash -p 80,443 <host>
```

Map detected services to known-misconfiguration checklists:
- Firebase backend -> test Firestore rules, API key restrictions
- Grafana/Prometheus -> test anonymous access to `/api/datasources`, `/metrics`
- Jenkins -> test `/script` console, `/api/json` without auth
- Kubernetes -> test `/healthz`, API server on 6443/8443

### Cloud-IDE and DevTools Port Discovery

Cloud IDEs expose debug ports that leak tokens ($313K pattern):

```bash
# Scan for common debug/DevTools ports
nmap -n -Pn -p 9222,9229,9230,5858,8000-8010,3000-3010 --open -sV --host-timeout 90s <host>
```

Port 9222 (Chrome DevTools), 9229 (Node.js inspector), and similar debug ports on cloud workstations are high-value findings.

### Routing-Layer Fuzzing via NSE

Detect path confusion and request smuggling by probing unusual characters through load balancers ($313K pattern):

```bash
# HTTP methods and path probing via NSE
nmap -n -Pn -p 80,443 --script http-methods,http-trace --script-timeout 30s <host>

# Detect reverse proxy stack from response headers
nmap -n -Pn -p 80,443 --script http-headers --script-timeout 15s <host>
```

### OAuth Scope Discovery via Port-to-Service Mapping

Scan for API endpoints that expose OAuth configuration ($313K pattern):

```bash
# Find API and auth-related services
nmap -n -Pn -sV -p 80,443,8080,8443 --script http-title --host-timeout 90s <host>

# Follow up with well-known OAuth endpoints on discovered services
# /.well-known/openid-configuration, /oauth/authorize, /.well-known/oauth-authorization-server
```

### GraphQL Endpoint Discovery

Researchers chain nmap service detection with GraphQL introspection ($50K+ pattern across corpus):

```bash
# Discover web services
nmap -n -Pn -sV -p 80,443,8080,4000,5000 --open --host-timeout 90s <host>

# NSE script for GraphQL detection
nmap -n -Pn -p 80,443 --script http-title --script-timeout 15s <host>
# Then probe discovered hosts for /graphql, /api/graphql, /v1/graphql endpoints
```

### Dependency Confusion Recon

Scan internal package registry ports that should not be exposed ($5K pattern):

```bash
# Internal registry ports: npm (4873 verdaccio), PyPI (8036), Maven (8081 nexus), gems (9292)
nmap -n -Pn -p 4873,8036,8081,9292,5000 --open -sV --host-timeout 90s <host>
```

### Chaining nmap with Other Tools

1. **nmap -> nuclei**: discovered open ports and services feed nuclei scans with appropriate templates (`-tags cve,misconfig`)
2. **nmap -> subfinder**: nmap confirms which enumerated subdomains have active services
3. **nmap -> mitmproxy**: discovered API ports become reverse-proxy targets for interception
4. **nmap -> semgrep**: service version detection reveals the software stack, guiding which semgrep rulesets to run against source code
