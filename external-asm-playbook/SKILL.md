---
name: external-asm-playbook
description: Scheduled external ASM playbook. Discovers and fingerprints the perimeter (subdomains, ports, services, tech), takes screenshots, and diffs 
license: Apache-2.0 (lifted from Armur-Ai/Pentest-Swarm-AI ebca218f :: playbooks/external-asm.yaml)
depends_on: []
---

# External Attack Surface Monitoring

> Phase-orchestrated playbook converted from upstream YAML at
> `Armur-Ai/Pentest-Swarm-AI/playbooks/external-asm.yaml` (Apache-2.0).

## Description

Scheduled external ASM playbook. Discovers and fingerprints the perimeter (subdomains, ports, services, tech), takes screenshots, and diffs against the previous run so the swarm only surfaces NEW exposures. Meant for cron.

## Variables (declare at scan start)

```yaml
  target_domain:
    type: string
    required: true
  diff_against_run:
    type: string
    required: false
    description: Campaign ID of a prior run to diff against (default = most recent)

```

## Phases

```yaml
  - name: passive_osint
    tools:
      - name: subfinder
        options: { recursive: true }
      - name: gau
    post_analysis: |
      Passive collection first — no packets to target infrastructure.
      Pull historical URLs and passive DNS to enrich the picture.

  - name: resolution
    tools:
      - name: dnsx
    post_analysis: |
      Resolve every candidate to A/AAAA/CNAME. Flag cloud-ranges
      (AWS, GCP, Azure) separately — owner attribution changes by range.

  - name: port_and_service
    tools:
      - name: naabu
        options: { ports: top-1000, rate: 1000 }
      - name: nmap
        options: { scan_type: "-sV", top_ports: 1000, timing: "-T4" }
    post_analysis: |
      Concentrate on unexpected-open ports on production assets.
      Cross-reference product + version against CVE database for
      known-bad versions.

  - name: web_fingerprint
    tools:
      - name: httpx
        options: { follow_redirects: true, threads: 100 }
    post_analysis: |
      Note tech stack, TLS certs (flag expiring < 30d), HTTP headers
      (missing HSTS, CSP, X-Frame-Options).

  - name: quick_vuln_sweep
    tools:
      - name: nuclei
        options:
          severity: [critical, high]
          templates: ["cves/", "exposures/", "misconfiguration/"]
    post_analysis: |
      Critical + high severity only — ASM noise at lower severities
      swamps the signal. Everything else becomes follow-up campaigns.
```

## How to use this playbook in bug.exe

1. The phases above are a recommended **execution sequence**. The root agent
   should treat each phase as a worker brief: dispatch a specialist that owns
   that phase's tools, then collect results before progressing.
2. Where the source YAML declares `post_analysis:`, that is the LLM analysis
   prompt for the agent that finishes the phase — pass it through to the
   worker as the `<test_plan>` or `<post_analysis>` portion of the brief.
3. Where the YAML declares `pheromone >= N` gating, treat N as the minimum
   confidence score before escalating to active testing. bug.exe's
   verification ladder is a natural place to enforce this gate.
4. The full original YAML structure is preserved above for reference. If
   bug.exe later adds a native YAML playbook executor, point it at this
   file; otherwise, the agent reads the markdown and dispatches manually.

## Corpus-Derived ASM Hunting Patterns

Distilled from 677 disclosed reports ($2.5M in bounties). Apply these during
the `quick_vuln_sweep` and `web_fingerprint` phases and as follow-up actions
on discovered assets.

### TLS-CN on Raw IPs as Asset Class

Big organizations end up with forgotten services on raw IPs:

1. Reverse-DNS and TLS-CN lookup on every IP in the target's ranges
2. Expired or internal-only certs on public IPs indicate forgotten services
3. Test these IPs for admin interfaces, default credentials, and
   unauthenticated access

### Blind XSS on Submission/Feedback Surfaces

For any platform with submission, contact, or feedback flows:

1. Identify the admin-review surface (sometimes findable via subdomain
   enum: `/admin`, `/dashboard`, `/internal`)
2. Seed blind-XSS payloads in every text field that flows to staff
3. Include payloads in filenames, email display names, and user-agent strings
4. Test support-chat widgets -- agent-facing UIs often render user HTML

### Open-Source Software IDOR Audit

When a target self-hosts open-source software:

1. Enumerate subdomains and look for fingerprints of self-hosted tools
   (error pages, default favicons, version headers)
2. Read the OSS project's source for known authorization gaps
3. Test default API keys, default admin credentials, and unauthenticated
   API endpoints that the OSS project ships with

### Known-Platform Default Page Fingerprinting

When you find a subdomain:

1. Visit `/` and capture the response -- compare against known default
   pages (Grafana, Kibana, Prometheus, Airflow, Jupyter, etc.)
2. Test default credentials for the identified platform
3. Check `/metrics`, `/debug`, `/healthz`, `/api/v1/` for unauthenticated
   info disclosure

### Post-Authentication URL Tree Walking

After successful authentication on any service:

1. Try the hostname root, parent paths, sibling paths, and common admin
   paths (`/admin`, `/dashboard`, `/config`, `/debug`)
2. Enumerate API versioning paths (`/api/v1/`, `/api/v2/`, `/api/internal/`)
3. Check for directory listing on parent directories of known resources

### Brand-Tier Subdomain XSS

Major companies have many brand-tier subdomains (`*.withgoogle.com`,
`*.shopify.io`, etc.):

1. Enumerate brand-tier subdomains and properties
2. Test each for reflected XSS in common parameters (`?q=`, `?s=`,
   `?search=`, `?name=`)
3. Brand-tier subdomains often use different (less hardened) tech stacks
4. Cookie scope may overlap with the main domain

### Polymorphic Image Upload XSS

For any upload endpoint:

1. Test: does it serve uploaded files from a JS-sensitive origin?
2. Upload a file that is both a valid image AND valid HTML/SVG/JavaScript
3. Test content-type sniffing: does the server set `Content-Type` based on
   extension, magic bytes, or the upload's claimed type?
4. Test SVG uploads for embedded JavaScript (`<script>`, `onload`, etc.)

### CI Script External Resource Audit

Every CI script in every public repo of the target:

1. Build a regex pattern for external resource URLs (S3 buckets, CDN URLs,
   package registry URLs)
2. Check if any referenced external resource is unclaimed or claimable
3. Test for subdomain takeover via dangling CNAMEs in CI scripts
4. Check for hardcoded credentials in CI configuration files

### Android Intent/IPC Abuse

For every exported component of a mobile app:

1. Map all intent filters to callable WebView bridges
2. Test deep links that load URLs in a WebView with JavaScript bridge access
3. Test `market://` and custom scheme handlers for intent redirection
4. Check whether WebView `file://` access is restricted

### CSRF on Subdomain APIs

Subdomain isolation should be assumed broken:

1. For every API on every subdomain, test CSRF regardless of SameSite
   cookie settings
2. Test cookie tossing from sibling subdomains to override CSRF tokens
3. Test whether CORS allows the origin of other subdomains
4. Self-XSS on a subdomain + shared parent domain + cookie-based CSRF
   can escalate to full CSRF bypass

---

**Source attribution**: This playbook is a faithful conversion of the
Apache-2.0-licensed YAML at upstream Armur-Ai/Pentest-Swarm-AI. The phase
structure and post_analysis text are reproduced verbatim. See
`bugdotexe/skills/playbooks/SOURCE.md` for full provenance.
