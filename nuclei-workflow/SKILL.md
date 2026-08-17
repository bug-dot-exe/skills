---
name: nuclei-workflow
category: reconnaissance
description: Nuclei scanning workflow with template selection, severity-based ordering, custom templates, and result interpretation
depends_on: []
---

# Nuclei Scanning Workflow

Structured approach to running Nuclei scans: select the right templates for the target's tech stack, run scans in severity order, write custom templates for target-specific checks, and interpret results without drowning in noise.

## When to Use

- After initial recon has identified live hosts and tech stacks
- Scanning for known CVEs, misconfigurations, and exposures
- Need automated coverage of common vulnerability patterns
- Writing custom templates for target-specific checks
- Continuous monitoring of a target for new exposures

## Methodology

### Phase 1: Pre-Scan Setup

1. Ensure targets list is clean (live hosts only, from httpx output)
2. Identify tech stack per host (from httpx, Wappalyzer, or manual fingerprinting)
3. Select templates based on detected technology
4. Set rate limits appropriate for the target (respect program rules)

### Phase 2: Severity-Based Scan Order

Run scans in severity tiers. Start with Critical/High to find the most impactful issues first.

**Tier 1: Critical and High -- run first**
```bash
nuclei -l targets.txt -s critical,high -rl 30 -c 15 -bs 15 -timeout 10 -retries 1 -stats -j -o nuclei_crit_high.jsonl
```

**Tier 2: Tech-stack targeted -- run second**
```bash
# Based on detected tech stack, use targeted tags
nuclei -l targets.txt -tags <tech-tags> -s critical,high,medium -rl 30 -c 15 -bs 15 -timeout 10 -retries 1 -stats -j -o nuclei_tech.jsonl
```

**Tier 3: Medium with focused templates -- run third**
```bash
nuclei -l targets.txt -s medium -tags cve,misconfig,exposure -rl 50 -c 20 -bs 20 -timeout 10 -retries 1 -stats -j -o nuclei_medium.jsonl
```

**Tier 4: Broad coverage -- run last (optional, noisy)**
```bash
nuclei -l targets.txt -as -s critical,high,medium -rl 50 -c 20 -bs 20 -timeout 10 -retries 1 -stats -j -o nuclei_broad.jsonl
```

### Phase 3: Technology-Specific Template Selection

Match tags to detected technology:

| Technology | Tags |
|-----------|------|
| WordPress | `wordpress,wp-plugin,wp-theme` |
| Joomla | `joomla` |
| Drupal | `drupal` |
| Apache | `apache` |
| Nginx | `nginx` |
| IIS | `iis` |
| Java/Spring | `java,spring,springboot` |
| Node.js/Express | `nodejs,express` |
| PHP | `php` |
| .NET | `asp,dotnet` |
| AWS | `aws,amazon,s3` |
| Azure | `azure` |
| GCP | `gcp,google` |
| Kubernetes | `kubernetes,k8s` |
| Jenkins | `jenkins` |
| GitLab | `gitlab` |
| Grafana | `grafana` |
| Elastic | `elastic,elasticsearch,kibana` |

### Phase 4: Result Interpretation

1. Parse JSONL output for structured analysis
2. Deduplicate findings across scan tiers
3. Validate Critical/High findings manually before reporting
4. Cross-reference CVE findings with target's actual version
5. Filter out false positives from generic pattern matches

## Key Commands

```bash
# Update nuclei and templates
nuclei -update
nuclei -ut

# List available templates and tags
nuclei -tl | wc -l
nuclei -tl -tags cve | wc -l

# Controlled scan with automatic tech detection
nuclei -l targets.txt -as -s critical,high -rl 30 -c 15 -bs 15 -timeout 10 -retries 1 -stats -j -o nuclei_auto.jsonl

# Specific template directories
nuclei -l targets.txt -t http/cves/ -s critical,high -rl 30 -c 15 -j -o nuclei_cves.jsonl
nuclei -l targets.txt -t http/misconfigurations/ -rl 30 -c 15 -j -o nuclei_misconfig.jsonl
nuclei -l targets.txt -t http/exposures/ -rl 30 -c 15 -j -o nuclei_exposures.jsonl
nuclei -l targets.txt -t http/vulnerabilities/ -rl 30 -c 15 -j -o nuclei_vulns.jsonl

# Exposure-focused scans (quick wins)
nuclei -l targets.txt -tags exposure,config,backup -rl 50 -c 20 -j -o nuclei_exposure.jsonl

# No outbound interaction (stealth mode)
nuclei -l targets.txt -as -s critical,high -ni -rl 30 -c 15 -j -o nuclei_stealth.jsonl

# Parse results
cat nuclei_crit_high.jsonl | jq -r '[.info.severity, .host, .info.name, .matched_at] | @tsv' | sort
```

## Custom Template Writing

For target-specific checks not covered by default templates:

```yaml
id: custom-target-check

info:
  name: Target Specific Exposure Check
  author: your-handle
  severity: medium
  description: Checks for target-specific exposure pattern
  tags: custom,exposure

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/internal/config"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "database_url"
          - "api_key"
        condition: or
```

**Common custom template patterns:**
- Exposed admin panels found during recon: match on specific page title or body content
- API endpoints returning sensitive data without auth: match on status 200 + sensitive keywords
- Version-specific vulnerabilities: match on version string in response
- Custom error pages leaking information: match on stack trace patterns

## What to Look For

**Critical Findings (validate immediately)**
- Remote code execution (RCE) via known CVEs
- Authentication bypass or default credentials
- Server-side request forgery (SSRF) to cloud metadata
- SQL injection via automated detection

**High Findings (validate before reporting)**
- Sensitive data exposure (config files, environment variables)
- Known CVEs with public exploits matching the target version
- Open admin panels with weak or default authentication

**Medium Findings (useful for chaining)**
- Information disclosure (version numbers, internal paths)
- Misconfigured security headers
- Directory listings enabled
- Open redirects

**Common False Positives**
- Generic version detection matching on banner text, not actual vulnerability
- CORS "misconfiguration" that only reflects the request origin in headers, not in actual access
- WAF or CDN returning custom responses that match template patterns
- Cached or static pages matching dynamic vulnerability patterns

## Corpus-Derived Hunting Patterns

Techniques from high-bounty reports where template-based scanning or the methodology behind it was the discovery vector.

### Self-Hosted Library CVE Sweep

Many web apps vendor JavaScript libraries at non-standard paths. For every target:

1. Enumerate paths suggesting vendored libraries: `/pdfjs/`, `/ckeditor/`, `/tinymce/`, `/moment/`, `/marked/`, `/highlight.js/`
2. Fingerprint the version (check `version` property in the JS file, `package.json`, or HTTP headers)
3. Cross-reference against CVE databases — self-hosted libraries are often years behind upstream patches
4. Write a custom Nuclei template per discovered library that checks the version endpoint

```yaml
id: vendored-pdfjs-check
info:
  name: Self-hosted PDF.js Version Check
  severity: info
  tags: custom,library
http:
  - method: GET
    path:
      - "{{BaseURL}}/pdfjs/build/pdf.js"
      - "{{BaseURL}}/pdf.js/build/pdf.js"
      - "{{BaseURL}}/static/pdfjs/pdf.js"
    matchers:
      - type: regex
        regex:
          - 'pdfjsVersion\s*=\s*"([0-9.]+)"'
        group: 1
    extractors:
      - type: regex
        regex:
          - 'pdfjsVersion\s*=\s*"([0-9.]+)"'
        group: 1
```

### Rich Content Renderer Injection

Any platform rendering Markdown, LaTeX, BBCode, MathJax, Mermaid, or custom DSL is an injection target:

1. Identify the rendering pipeline ORDER — which engine runs first, which sanitizer runs last
2. Test template-injection payloads for each engine: `{{7*7}}` for Jinja/Nunjucks, `${7*7}` for JS template literals, `#{7*7}` for Ruby/Pug
3. If CSP blocks inline scripts, test `data-*` attribute injection for any JS sinks that consume attributes (Mermaid, MathJax config objects)
4. Write a Nuclei template that tests the injection in the most common user-input field (comments, descriptions, wiki pages)

### Parser Differential Scanning

When the target has a CDN or reverse proxy in front of the origin:

1. Test how the CDN and origin disagree on URL parsing — send unusual characters in paths (`@`, `\`, `;`, `..`, `%00`, `%2f`, leading `-`)
2. Monitor which characters cause routing differences (different status codes, different response bodies)
3. If the CDN caches based on one interpretation and the origin routes based on another, you have request smuggling or cache poisoning

### Import/Export Endpoint Privilege Boundary Audit

For any platform with import/export features (project import, data export, CSV upload):

1. Create a custom template that tests whether the import endpoint accepts references to cross-tenant resources
2. Test if exported data includes fields not visible in the UI (internal IDs, other users' data, admin flags)
3. Import endpoints that deserialize complex formats (JSON, YAML, XML, ZIP) are privilege boundaries — test for path traversal, SSRF, and deserialization attacks

### Incomplete Patch Detection

When a CVE fix is published for a target's known software:

1. Read the patch diff to understand what was blocked
2. Enumerate all variations that survive the fix — if a fix blocks `<img onerror=`, test `<video onerror=`, `<body onload=`, `<svg onload=`
3. Write a Nuclei template for each bypass variant

## Tips

1. Always run `-as` (automatic scan) as a baseline; it maps templates to detected tech
2. Keep rate limits conservative (`-rl 30`) until you know the target tolerates more
3. Use `-ni` to disable interactsh when you cannot receive callbacks or want stealth
4. Validate every Critical/High finding manually; Nuclei has false positives
5. Save all JSONL output; you can reprocess results without rescanning
6. Run custom templates separately from default ones for cleaner output
7. Schedule periodic rescans; new templates are released with each update
