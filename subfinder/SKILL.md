---
name: subfinder
description: Subfinder passive subdomain enumeration syntax, source controls, and pipeline-ready output patterns.
depends_on: []
---

# Subfinder CLI Playbook

Official docs:
- https://docs.projectdiscovery.io/opensource/subfinder/usage
- https://docs.projectdiscovery.io/opensource/subfinder/running
- https://github.com/projectdiscovery/subfinder

Canonical syntax:
`subfinder [flags]`

High-signal flags:
- `-d <domain>` single domain
- `-dL <file>` domain list
- `-all` include all sources
- `-recursive` use recursive-capable sources
- `-s <sources>` include specific sources
- `-es <sources>` exclude specific sources
- `-rl <n>` global rate limit
- `-rls <source=n/s,...>` per-source rate limits
- `-proxy <http://host:port>` proxy outbound source requests
- `-silent` compact output
- `-o <file>` output file
- `-oJ, -json` JSONL output
- `-cs, -collect-sources` include source metadata (`-oJ` output)
- `-nW, -active` show only active subdomains
- `-timeout <seconds>` request timeout
- `-max-time <minutes>` overall enumeration cap

Agent-safe baseline for automation:
`subfinder -d example.com -all -recursive -rl 20 -timeout 30 -silent -oJ -o subfinder.jsonl`

Common patterns:
- Standard passive enum:
  `subfinder -d example.com -silent -o subs.txt`
- Broad-source passive enum:
  `subfinder -d example.com -all -recursive -silent -o subs_all.txt`
- Multi-domain run:
  `subfinder -dL domains.txt -all -recursive -rl 20 -silent -o subfinder_out.txt`
- Source-attributed JSONL output:
  `subfinder -d example.com -all -oJ -cs -o subfinder_sources.jsonl`
- Passive enum via explicit proxy:
  `subfinder -d example.com -all -recursive -proxy http://127.0.0.1:48080 -silent -oJ -o subfinder_proxy.jsonl`

Critical correctness rules:
- `-cs` is useful only with JSON output (`-oJ`).
- Many sources require API keys in provider config; low results can be config-related, not target-related.
- `-nW` performs active resolution/filtering and can drop passive-only hits.
- Keep passive enum first, then validate with `httpx`.

Usage rules:
- Keep output files explicit when chaining to `httpx`/`nuclei`.
- Use `-rl/-rls` when providers throttle aggressively.
- Do not use `-h`/`--help` for routine tasks unless absolutely necessary.

Failure recovery:
- If results are unexpectedly low, rerun with `-all` and verify provider config/API keys.
- If provider errors appear, lower `-rl` and apply `-rls` per source.
- If runs take too long, lower scope or split domain batches.

If uncertain, query web_search with:
`site:docs.projectdiscovery.io subfinder <flag> usage`

## Corpus-Derived Advanced Workflows

Patterns extracted from 1,005 disclosed reports ($5.2M total bounty). These show HOW top researchers use subdomain enumeration to find real bugs.

### Full Pipeline: Subfinder -> httpx -> Nuclei

The canonical recon chain. Subfinder discovers subdomains, httpx probes for live hosts, nuclei scans for vulnerabilities:

```bash
# Phase 1: Passive enumeration
subfinder -d target.tld -all -recursive -rl 20 -silent -o subs.txt

# Phase 2: Probe for live HTTP services
cat subs.txt | httpx -silent -status-code -tech-detect -o live_hosts.txt

# Phase 3: Vulnerability scan on live hosts
nuclei -l live_hosts.txt -as -s critical,high -rl 50 -j -o nuclei_results.jsonl
```

### Platform Fingerprinting via Subdomain Patterns

Researchers identify self-hosted open-source software on subdomains, then test known default misconfigurations ($10K+ pattern):

```bash
# Enumerate all subdomains
subfinder -d target.tld -all -recursive -silent -o all_subs.txt

# Fingerprint known platforms from subdomain names and HTTP responses
cat all_subs.txt | httpx -silent -title -server -tech-detect -json -o fingerprints.jsonl

# Filter for high-value platform indicators
# Look for: flagsmith, sentry, grafana, jenkins, gitlab, jira, kibana, prometheus
grep -iE '(flagsmith|sentry|grafana|jenkins|gitlab|jira|kibana|prometheus|cortex|vault)' fingerprints.jsonl
```

Then test each identified platform against its known default-credential and misconfiguration checklist.

### Brand-Tier and Vanity Subdomain Discovery

Major targets run campaigns on vanity subdomains that often have weaker security posture ($10K pattern):

```bash
# Broad recursive enumeration
subfinder -d target.tld -all -recursive -silent -o subs.txt

# Also enumerate acquisition and brand domains
subfinder -d acquired-brand.tld -all -recursive -silent >> subs.txt
subfinder -d campaign-domain.tld -all -recursive -silent >> subs.txt

# Deduplicate
sort -u subs.txt -o subs.txt

# Probe and filter for interesting tech stacks
cat subs.txt | httpx -silent -title -status-code -content-length -tech-detect -json -o probed.jsonl

# Find forgotten or campaign-specific hosts with interesting responses
cat probed.jsonl | jq -r 'select(.status_code != 403 and .status_code != 404) | .url'
```

### Cloud Storage URL Extraction from Discovered Hosts

After subdomain enumeration, extract cloud storage references from live hosts ($500K pattern):

```bash
# Enumerate and probe
subfinder -d target.tld -all -recursive -silent | httpx -silent -o live.txt

# Crawl live hosts for cloud storage URLs
cat live.txt | while read url; do
  curl -s "$url" | grep -oiE '(https?://[a-z0-9.-]+\.(s3|storage\.googleapis|blob\.core\.windows)\.[\w./-]+)'
done | sort -u > cloud_urls.txt
```

### Cross-Product Integration Endpoint Discovery

Large platforms have integration endpoints between products that often have authorization gaps ($313K pattern):

```bash
# Discover all subdomains across the product family
for domain in target.tld api.target.tld docs.target.tld drive.target.tld; do
  subfinder -d "$domain" -all -recursive -silent
done | sort -u > all_subs.txt

# Probe and identify cross-product API endpoints
cat all_subs.txt | httpx -silent -path '/api/' -status-code -json -o api_endpoints.jsonl
```

### CI/CD and Internal Tool Discovery

Production CI/CD systems on public DNS are high-value targets ($15K+ pattern):

```bash
# Enumerate subdomains looking for CI/CD fingerprints
subfinder -d target.tld -all -recursive -silent -o subs.txt

# Filter for CI/CD indicators in subdomain names
grep -iE '(jenkins|ci|cd|build|deploy|gitlab|drone|argo|concourse|teamcity)' subs.txt > cicd_candidates.txt

# Probe for known CI/CD default pages
cat cicd_candidates.txt | httpx -silent -title -status-code -tech-detect -json -o cicd_probed.jsonl
```

### Source-Attributed Output for Prioritization

Track which passive sources found each subdomain to prioritize novel discoveries:

```bash
# Source-attributed enumeration
subfinder -d target.tld -all -oJ -cs -o subfinder_sources.jsonl

# Find subdomains reported by only 1 source (less well-known, higher chance of being forgotten)
cat subfinder_sources.jsonl | jq -r 'select(.sources | length == 1) | .host' > rare_subs.txt
```

### Chaining Subfinder with Other Tools

1. **Subfinder -> nmap**: discovered subdomains feed port-scanning for service enumeration
2. **Subfinder -> nuclei**: live hosts from subfinder+httpx feed directly into nuclei template scanning
3. **Subfinder -> mitmproxy**: discovered API subdomains become reverse-proxy targets for traffic interception
4. **Subfinder -> spectral**: discovered API hosts are crawled for OpenAPI specs, then linted for security issues
