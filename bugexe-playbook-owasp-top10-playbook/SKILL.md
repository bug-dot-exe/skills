---
name: owasp_top10_playbook
description: Comprehensive assessment targeting the OWASP Top 10 vulnerability categories
license: Apache-2.0 (lifted from Armur-Ai/Pentest-Swarm-AI ebca218f :: playbooks/owasp-top10.yaml)
depends_on: []
---

# OWASP Top 10 Assessment

> Phase-orchestrated playbook converted from upstream YAML at
> `Armur-Ai/Pentest-Swarm-AI/playbooks/owasp-top10.yaml` (Apache-2.0).

## Description

Comprehensive assessment targeting the OWASP Top 10 vulnerability categories

## Variables (declare at scan start)

```yaml
  target_domain:
    type: string
    required: true

```

## Phases

```yaml
  - name: reconnaissance
    tools:
      - name: subfinder
        options: { recursive: true }
      - name: httpx
        options: { follow_redirects: true }
      - name: katana
        options: { depth: 3 }
      - name: gau
    post_analysis: |
      Map the full attack surface. Identify all web endpoints, parameters,
      forms, API routes, and authentication mechanisms. Note technology
      stack for targeted vulnerability checks.

  - name: injection_testing
    tools:
      - name: nuclei
        options:
          templates: ["cves/", "vulnerabilities/sqli/", "vulnerabilities/xss/"]
          severity: [critical, high]
    post_analysis: |
      Focus on A03:2021 Injection. Test all input points for SQL injection,
      XSS, command injection, LDAP injection, and template injection.
      Verify findings and assess exploitability.

  - name: auth_and_access
    tools:
      - name: nuclei
        options:
          templates: ["vulnerabilities/auth-bypass/", "misconfiguration/"]
    post_analysis: |
      Cover A01:2021 Broken Access Control, A02:2021 Cryptographic Failures,
      and A07:2021 Identification and Authentication Failures.
      Check for IDOR, privilege escalation, weak passwords, exposed tokens.

  - name: misconfig_and_components
    tools:
      - name: nuclei
        options:
          templates: ["exposures/", "technologies/", "misconfiguration/"]
    post_analysis: |
      Cover A05:2021 Security Misconfiguration and A06:2021 Vulnerable
      and Outdated Components. Check for default credentials, unnecessary
      features, outdated libraries, exposed admin panels.
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

## Corpus-Derived OWASP Hunting Patterns

Distilled from 1,634 disclosed reports ($15M in bounties). Apply these
alongside the phase-based nuclei scanning above.

### A03 Injection -- Parser Differential XSS

HTML sanitizers fail when the parser mutates input differently than expected.
High-bounty bug class across all major platforms:

1. Identify the sanitizer library and version (DOMPurify, bleach, sanitize-html,
   golang net/html, etc.)
2. Feed the sanitizer's output to a DIFFERENT parser (browser, markdown renderer,
   email client) and check for mutation
3. Test edge cases: empty comments (`<!---->`), entity encoding inside style/script
   contexts (`&lt;` becoming `<`), null bytes between tag characters
4. Test context-crossing: inject content that is safe in one context (attribute)
   but dangerous after the sanitizer moves it to another (element body)

### A03 Injection -- Blind XSS on Internal Surfaces

Customer-support, contact, and abuse-report forms flow into admin dashboards
that rarely sanitize display:

1. Find every form whose content is viewed by internal staff (support tickets,
   feedback, abuse reports, account deletion requests)
2. Seed blind-XSS payloads (use an out-of-band callback server)
3. Include payloads in every text field, filename, email display name, and
   custom header value
4. Check support-chat widgets -- agent-facing UIs often render user HTML

### A01 Broken Access Control -- Identifier-Chain Auditing

For any RPC that returns sensitive data gated on identifier X:

1. List ALL RPCs that produce X as output, given different inputs
2. Test whether X can be obtained from a lower-privileged path
3. Chain: obtain X from the weaker endpoint, use X on the stronger endpoint

### A01 Broken Access Control -- Platform-Within-Platform XSS

Subdomains where third-party content runs (embedded apps, add-ons, marketplace
iframes) share cookie scope with the parent:

1. Identify all iframe/embed domains that share cookies with the main domain
2. XSS on the embedded domain = session token for the main platform
3. Test sandbox attribute bypasses on the embedding iframe

### A05 Misconfiguration -- Framework Convenience SSRF

When a framework offers automatic URL handling, check whether it respects
SSRF protections:

1. Identify SSR (server-side rendering) features that fetch resources
2. Test `Host` header injection in SSR frameworks -- the framework may use
   the Host header to construct internal API URLs
3. Test `useAbsoluteUrl`, `baseURL`, proxy config, and redirect-following
   behavior for SSRF
4. Always test metadata endpoints: `169.254.169.254`, `metadata.google.internal`,
   `169.254.170.2` (ECS)

### A07 Auth Failures -- Transitional Auth Flow Abuse

Every transitional auth flow (forgot-password, step-up, MFA setup,
social-login binding, account-merge, recovery, suspicious-login challenge):

1. Map the full state machine -- every step, every token, every redirect
2. Test skipping steps (jump from step 1 to step 3)
3. Test replaying tokens from one flow in another flow
4. Test race conditions between parallel flow instances

### A03 Injection -- Markdown Rendering Chains

For any product that renders user content via Markdown:

1. Identify the Markdown library and version
2. Test every HTML element the library passes through (most allow some subset)
3. Test interaction with extensions (MathJax, Mermaid, code fence syntax
   highlighting) -- extensions often introduce new injection sinks
4. Test nested rendering: Markdown inside tooltip, validation message,
   notification, or email template

### A01 Broken Access Control -- WebView Bridge Exploitation

For every mobile app that exposes a WebView with a JavaScript bridge:

1. Find `@JavascriptInterface` / `addJavascriptInterface` / `postMessage`
   bridge methods
2. Identify all origins the bridge trusts
3. XSS on ANY trusted origin = bridge access = native API calls
4. Test `file://` and `data:` URL loading in the WebView

### A08 Software Integrity -- Acquired Domain Hunting

For every acquired company in a target's portfolio:

1. Enumerate the original company's infrastructure (subdomains, IPs)
2. Test for legacy authentication, unpatched services, forgotten admin panels
3. Acquired domains rarely get security-hardened to the acquirer's standard

---

**Source attribution**: This playbook is a faithful conversion of the
Apache-2.0-licensed YAML at upstream Armur-Ai/Pentest-Swarm-AI. The phase
structure and post_analysis text are reproduced verbatim. See
`bugdotexe/skills/playbooks/SOURCE.md` for full provenance.
