---
name: bug-bounty-playbook
description: End-to-end swarm for bug-bounty programs. Starts from a root domain, enumerates subdomains and endpoints, hunts for low-hanging vulns, then 
license: Apache-2.0 (lifted from Armur-Ai/Pentest-Swarm-AI ebca218f :: playbooks/bug-bounty.yaml)
depends_on: []
---

# Bug Bounty Swarm

> Phase-orchestrated playbook converted from upstream YAML at
> `Armur-Ai/Pentest-Swarm-AI/playbooks/bug-bounty.yaml` (Apache-2.0).

## Description

End-to-end swarm for bug-bounty programs. Starts from a root domain, enumerates subdomains and endpoints, hunts for low-hanging vulns, then escalates on candidate SQLi/SSRF/IDOR with targeted active tests. Scope-enforced at every step; dedup-ready output for HackerOne / Bugcrowd.

## Variables (declare at scan start)

```yaml
  target_domain:
    type: string
    required: true
  program_slug:
    type: string
    required: false
    description: HackerOne/Bugcrowd program slug, used for dedup and scope hints

```

## Phases

```yaml
  - name: subdomain_enumeration
    tools:
      - name: subfinder
        options: { recursive: true, timeout: 300 }
      - name: dnsx
    post_analysis: |
      Catalogue every subdomain, flag wildcards and takeover candidates
      (dangling CNAMEs pointing to third-party services).

  - name: web_surface
    tools:
      - name: httpx
        options: { follow_redirects: true, threads: 50 }
      - name: katana
        options: { depth: 3, js_crawl: true }
      - name: gau
    post_analysis: |
      Map alive hosts, status codes, tech stacks, and deep-link endpoints.
      Prioritise endpoints with query parameters, admin-ish paths, and
      old/deprecated versions.

  - name: vulnerability_scan
    tools:
      - name: nuclei
        options:
          severity: [critical, high, medium]
          templates: ["http/", "cves/", "exposures/"]
    post_analysis: |
      Report-ready findings only — filter duplicates against known
      program issues when program_slug is provided.

  - name: active_escalation
    # Opt-in by the swarm: only triggers if nuclei / classifier produce a
    # POTENTIAL_SQLI, SSRF, or IDOR finding with pheromone >= 0.5.
    tools:
      - name: sqlmap
        options: { risk: 1, level: 2, batch: true }
    post_analysis: |
      Confirm exploitability for high-pheromone findings. Cleanup
      commands must be registered for anything that mutates state.
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

## Corpus-Derived Bug Bounty Hunting Patterns

Distilled from 543 disclosed reports ($4M in bounties). Apply these across
all phases of the playbook.

### Patch-Bypass Hunting

One of the highest-ROI methodologies on mature platforms:

1. When a security issue is fixed, read the patch carefully
2. Identify the exact check the patch added
3. Test whether the check can be bypassed via encoding, parameter position,
   type confusion, or alternative code path
4. Re-test every fixed bug -- bypass rate on first-attempt patches is high

### Inter-Property Auth-Token Graph

For any large multi-property platform:

1. Map the auth-token graph: which property issues tokens, which properties
   accept them, what scopes transfer
2. Test cross-property token reuse -- a token from Property A used on
   Property B may have unintended permissions
3. Test token downgrade: use a high-privilege token from one property on
   a lower-privilege endpoint of another

### Asset-Discovery-Driven Hunting

Large organizations own millions of IPs. Systematic port-scanning finds
forgotten services:

1. Enumerate IP ranges (ASN lookup, cloud provider ranges, acquisition history)
2. Port-scan non-standard ports (8080, 8443, 9090, 3000, 8888, etc.)
3. Fingerprint services: match banners to known software with default creds
4. Focus on admin interfaces exposed without authentication

### Error Message Schema Disclosure

When APIs return verbose error messages:

1. Test whether errors reveal parameter names, internal paths, or stack traces
2. Send malformed types (string where int expected, array where string expected)
3. Test boundary values (negative, zero, MAX_INT) to trigger different errors
4. Chain: use disclosed parameter names to discover undocumented API fields

### Escalate Dismissed Findings

When an initial finding is dismissed or classified as low severity:

1. Use the initial finding as a foothold for deeper enumeration
2. Chain with other low-severity findings to demonstrate higher impact
3. Find every location where the same pattern repeats -- a single LFI that
   leads to config disclosure may exist on every static-asset path

### Meta-Resource IDOR

Enumerate every "manage program / org / project" UI action:

1. List all administrative operations (archive, delete, transfer, rename,
   export, clone, fork, share)
2. Test each with a cross-tenant identifier
3. These meta-resources are consistently underexplored -- programs focus on
   data IDOR but miss management-action IDOR

### Regional and Legacy Domain Hunting

For mature programs with hardened main stacks:

1. Enumerate regional/legacy/secondary domains (country variants, legacy
   acquisitions, dev/staging environments)
2. Test CSRF, XSS, and auth bypass on these domains -- they often lack
   the hardening of the main stack
3. Check for cross-origin trust relationships between legacy and main domains

### Login / SSO Subdomain XSS

Login and SSO subdomains are the highest-value XSS targets:

1. They have privileged cookie scope and broad user reach
2. Test redirect parameters (`?next=`, `?return=`, `?redirect_uri=`)
   for open redirect and XSS
3. Test error pages on login flows for reflected XSS
4. Chain: login-subdomain XSS + cookie scope = session hijack on main domain

### Upstream OSS CVE Recycling

For any cloud product built on open-source software:

1. Identify the upstream OSS project (and specific fork/version)
2. Search for CVEs in that upstream project
3. Test whether the cloud product has patched the upstream CVEs
4. Cloud products often lag upstream patches by weeks to months

---

**Source attribution**: This playbook is a faithful conversion of the
Apache-2.0-licensed YAML at upstream Armur-Ai/Pentest-Swarm-AI. The phase
structure and post_analysis text are reproduced verbatim. See
`bugdotexe/skills/playbooks/SOURCE.md` for full provenance.
