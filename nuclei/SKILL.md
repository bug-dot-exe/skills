---
name: nuclei
description: Exact Nuclei command structure, template selection, and bounded high-throughput execution controls.
depends_on: []
---

# Nuclei CLI Playbook

Official docs:
- https://docs.projectdiscovery.io/opensource/nuclei/running
- https://docs.projectdiscovery.io/opensource/nuclei/mass-scanning-cli
- https://github.com/projectdiscovery/nuclei

Canonical syntax:
`nuclei [flags]`

High-signal flags:
- `-u, -target <url>` single target
- `-l, -list <file>` targets file
- `-im, -input-mode <mode>` list/burp/jsonl/yaml/openapi/swagger
- `-t, -templates <path|tag>` explicit template path(s)
- `-tags <tag1,tag2>` run by tag
- `-s, -severity <critical,high,...>` severity filter
- `-as, -automatic-scan` tech-mapped automatic scan
- `-ni, -no-interactsh` disable OAST/interactsh requests
- `-rl, -rate-limit <n>` global request rate cap
- `-c, -concurrency <n>` template concurrency
- `-bs, -bulk-size <n>` hosts in parallel per template
- `-timeout <seconds>` request timeout
- `-retries <n>` retries
- `-stats` periodic scan stats output
- `-silent` findings-only output
- `-j, -jsonl` JSONL output
- `-o <file>` output file

Agent-safe baseline for automation:
`nuclei -l targets.txt -as -s critical,high -rl 50 -c 20 -bs 20 -timeout 10 -retries 1 -silent -j -o nuclei.jsonl`

Common patterns:
- Focused severity scan:
  `nuclei -u https://target.tld -s critical,high -silent -o nuclei_high.txt`
- List-driven controlled scan:
  `nuclei -l targets.txt -as -rl 50 -c 20 -bs 20 -timeout 10 -retries 1 -j -o nuclei.jsonl`
- Tag-driven run:
  `nuclei -l targets.txt -tags cve,misconfig -s critical,high,medium -silent`
- Explicit templates:
  `nuclei -l targets.txt -t http/cves/ -t dns/ -rl 30 -c 10 -bs 10 -j -o nuclei_templates.jsonl`
- Deterministic non-OAST run:
  `nuclei -l targets.txt -as -s critical,high -ni -stats -rl 30 -c 10 -bs 10 -timeout 10 -retries 1 -j -o nuclei_no_oast.jsonl`

Critical correctness rules:
- Provide a template selection method (`-as`, `-t`, or `-tags`); avoid unscoped broad runs.
- Keep `-rl`, `-c`, and `-bs` explicit for predictable resource use.
- Use `-ni` when outbound interactsh/OAST traffic is not expected or not allowed.
- Use structured output (`-j -o <file>`) for automation.

Usage rules:
- Start with severity/tags/templates filters to keep runs explainable.
- Keep retries conservative (`-retries 1`) unless transport instability is proven.
- Do not use `-h`/`--help` for routine operation unless absolutely necessary.

Failure recovery:
- If performance degrades, lower `-c/-bs` before lowering `-rl`.
- If findings are unexpectedly empty, verify template selection (`-as` vs explicit `-t/-tags`).
- If scan duration grows, reduce target set and enforce stricter template/severity filters.

If uncertain, query web_search with:
`site:docs.projectdiscovery.io nuclei <flag> running`

## SecOpsAgentKit contributions

Additional patterns sourced from SecOpsAgentKit's `appsec/dast-nuclei/SKILL.md`. Use these when bug.exe's tighter CLI playbook above doesn't already cover the surface you need.

### SARIF Export for Code-Scanning UIs

Emit SARIF directly so findings can land in GitHub Security tab, GitLab DAST UI, or Defender for Cloud:

```bash
nuclei -l targets.txt -as -severity critical,high -sarif-export nuclei.sarif
```

Then upload via GitHub Actions:
```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: nuclei.sarif
```

### Docker Invocation (Sandbox-Friendly)

For environments that prefer image-pinned tool versions:

```bash
docker run --rm -v "$(pwd):/reports" projectdiscovery/nuclei:latest \
  -l /reports/targets.txt \
  -as -severity critical,high \
  -j -jsonl-export /reports/nuclei.jsonl
```

### Diff-Against-Baseline Pattern

Quick remediation verification — same scan twice, diff the outputs:

```bash
nuclei -u https://target.tld -severity critical,high -o scan_pre.txt
# (apply fixes)
nuclei -u https://target.tld -severity critical,high -o scan_post.txt
diff scan_pre.txt scan_post.txt
```

If `scan_post.txt` removes a finding from `scan_pre.txt`, the fix worked.

### Authenticated Scanning

For Bearer/JWT-protected endpoints, pass auth headers:

```bash
nuclei -u https://api.target.tld \
  -H "Authorization: Bearer $TOKEN" \
  -tags cve,exposure \
  -severity critical,high
```

For session-cookie auth:
```bash
nuclei -u https://target.tld \
  -H "Cookie: session=abcd1234" \
  -tags owasp,misconfig
```

### Verification Mode (`-verify`)

After a finding fires, replay the request with extra confirmation steps:

```bash
nuclei -u https://target.tld -severity critical -verify -verbose
```

`-verify` makes Nuclei re-fire each matched template and confirm the response shape matches the expected detection — eliminates a class of timing/transient false positives.

### Custom Template Skeleton

```yaml
id: custom-internal-secret-exposure
info:
  name: Internal Secret Exposure Check
  author: security-team
  severity: high
  tags: custom,exposure

http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/config.json"
      - "{{BaseURL}}/secrets.yaml"
    matchers:
      - type: regex
        regex:
          - 'AWS_(SECRET|ACCESS)_KEY[_=][A-Z0-9/+=]{20,}'
          - 'BEGIN.*PRIVATE KEY'
        part: body
```

Save under `custom-templates/`, then run:
```bash
nuclei -t custom-templates/ -l targets.txt -j -o custom_findings.jsonl
```

## Corpus-Derived Advanced Workflows (726 reports, $14.2M bounty)

### CVE-Sweep Recon Pipeline ($5K+ pattern)

Fingerprint internet-facing assets and match against known CVEs:

```bash
# Step 1: Enumerate subdomains and probe for live services
subfinder -d target.tld -all -recursive -silent | httpx -silent -tech-detect -json -o probed.jsonl

# Step 2: Extract technology fingerprints
cat probed.jsonl | jq -r '.technologies[]' | sort -u > tech_stack.txt

# Step 3: Run CVE templates matching the detected stack
nuclei -l live_hosts.txt -tags cve -s critical,high -rl 50 -c 20 -j -o cve_sweep.jsonl

# Step 4: For specific products, run targeted templates
nuclei -l live_hosts.txt -t http/cves/2024/ -t http/cves/2023/ -s critical,high -j -o recent_cves.jsonl
```

### Self-Hosted Library CVE Hunt ($10K pattern)

Write a template that probes for vendored library paths (`/pdfjs/web/viewer.js`, `/ckeditor/ckeditor.js`, `/tinymce/tinymce.min.js`) and extracts version strings via regex. Cross-reference against NVD:

```bash
nuclei -t templates/vendored-lib-detect.yaml -l live_hosts.txt -j -o lib_versions.jsonl
```

### Tech-Detect to Template Mapping

Use automatic scan mode for technology detection, then run targeted template directories:

```bash
nuclei -u https://target.tld -as -s critical,high,medium -stats -j -o auto_scan.jsonl
# Stack-specific: -t http/technologies/wordpress/ or -t http/misconfiguration/nginx/
```

### GitHub Actions Workflow Scanning

Scan target organization repos for CI/CD injection vectors ($750K+ pattern):

```bash
# Clone all public repos from a target org
gh repo list TARGET_ORG --public --limit 500 --json nameWithOwner -q '.[].nameWithOwner' > repos.txt

# For each repo, extract workflow files and scan
cat > templates/gha-pwn-request.yaml << 'EOF'
id: gha-pull-request-target
info:
  name: GitHub Actions pull_request_target with checkout
  severity: critical
  tags: cicd,supply-chain

file:
  - extensions:
      - yml
      - yaml
    matchers:
      - type: word
        words:
          - "pull_request_target"
      - type: word
        words:
          - "actions/checkout"
          - "ref: ${{ github.event.pull_request"
        condition: or
    matchers-condition: and
EOF
```

### Headless Verification of Findings

After initial scan, use verification mode to eliminate transient false positives:

```bash
# Initial scan
nuclei -l targets.txt -as -s critical,high -j -o initial_scan.jsonl

# Verification pass on findings
nuclei -l targets.txt -s critical -verify -verbose -j -o verified.jsonl

# Authenticated verification for protected endpoints
nuclei -l targets.txt -H "Authorization: Bearer $TOKEN" -s critical,high -verify -j -o auth_verified.jsonl
```

### Chaining Nuclei with Other Tools

1. **subfinder -> httpx -> nuclei**: the canonical recon pipeline — enumerate, probe, scan
2. **nuclei -> mitmproxy**: nuclei detects a vulnerable endpoint, mitmproxy captures the full request/response for manual exploitation
3. **nuclei -> semgrep**: nuclei finds a running vulnerable service, semgrep audits the source code for the root cause
4. **nmap -> nuclei**: nmap discovers services on unusual ports, nuclei scans those specific ports with targeted templates
