---
name: ctf_solver_playbook
description: Autonomous CTF machine solver for retired HackTheBox / TryHackMe boxes (or your own lab targets). The swarm iterates: enumerate -> exploit -
license: Apache-2.0 (lifted from Armur-Ai/Pentest-Swarm-AI ebca218f :: playbooks/ctf-solver.yaml)
depends_on: []
---

# CTF Solver Swarm

> Phase-orchestrated playbook converted from upstream YAML at
> `Armur-Ai/Pentest-Swarm-AI/playbooks/ctf-solver.yaml` (Apache-2.0).

## Description

Autonomous CTF machine solver for retired HackTheBox / TryHackMe boxes (or your own lab targets). The swarm iterates: enumerate -> exploit -> stabilize foothold -> escalate -> collect flag. Retired boxes only by default — live competition boxes require explicit opt-in.

## Variables (declare at scan start)

```yaml
  target_ip:
    type: string
    required: true
  difficulty:
    type: string
    default: easy
    description: "easy | medium | hard — affects agent-hour budget"
  flag_path_hints:
    type: string
    default: "/root/root.txt,/home/*/user.txt"
    description: Comma-separated list of likely flag paths

```

## Phases

```yaml
  - name: enumeration
    tools:
      - name: nmap
        options: { scan_type: "-sV", top_ports: 1000, timing: "-T4" }
      - name: httpx
      - name: katana
        options: { depth: 3 }
      - name: nuclei
        options: { severity: [critical, high, medium] }
    post_analysis: |
      Pull the enum into one coherent picture. CTF boxes have a
      single intended path 95% of the time — find the weirdest thing
      and follow it.

  - name: initial_foothold
    tools:
      - name: sqlmap
        options: { risk: 2, level: 3 }
    post_analysis: |
      Try the obvious first (default creds, exposed config files,
      git leaks, known CVEs for the exact banner version).
      Stabilize any shell into a proper TTY before privesc.

  - name: privilege_escalation
    tools:
      - name: nuclei
        options: { templates: ["network/enumeration/"] }
    post_analysis: |
      SUID binaries, sudo -l, cron jobs, writable PATH entries,
      capabilities, kernel exploits (last resort — crashes boxes).

  - name: flag_collection
    tools: []
    post_analysis: |
      Read flags from flag_path_hints. Submit via box's grader
      if credentials available; otherwise surface to report.
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

## Corpus-Derived CTF Methodology Patterns

Distilled from 457 disclosed reports ($18M in bounties). Apply these during
enumeration and initial-foothold phases.

### Inter-Subsystem Object Lifetime Auditing

When a new subsystem interacts with existing object-management code:

1. Identify every place where subsystem A holds a reference to an object
   managed by subsystem B
2. Test: what happens when B frees the object while A still holds a ref?
3. Focus on new kernel subsystems, plugin frameworks, and extension APIs
   that interact with existing resource managers

### N-Day Exploit Development

When a CVE patches a memory-corruption bug:

1. Read the patch commit and regression test -- this is your trigger
2. Build the pre-patch version and reproduce the crash
3. Determine exploitability from the crash primitive (UAF, OOB read/write,
   type confusion)
4. Develop the exploit within the bounty program's window

### Alternate-Surface Authorization Audit

For any multi-surface platform:

1. List every API surface (REST, mobile, internal, partner, legacy)
2. For each protected action, test through every surface
3. The weakest surface's authorization is the effective authorization

### Iframe Action Enumeration

For any web app with clickjacking defenses:

1. Enumerate every action (button, menu item, form submit) that can be
   triggered via iframe embedding
2. Test whether `X-Frame-Options` / CSP `frame-ancestors` is enforced
   on every response, not just the landing page
3. Test SVG filter overlay techniques to make the framed page visually
   indistinguishable from a benign page

### Multi-Layer Dispatch + Third-Party Renderer RCE

When a rendering pipeline has multiple dispatch layers:

1. Identify the dispatch chain (e.g., wiki markup -> markdown -> HTML ->
   browser, or template language -> output format -> viewer)
2. Test whether options or extensions can be injected through the input
   (e.g., Kramdown options via `{: .class}` syntax, Mermaid directives)
3. Focus on renderers that support `eval` or dynamic code execution

### Systematic Chrome Extension Audit

For any organization that publishes browser extensions:

1. Collect all extensions via Chrome Web Store search
2. Pull manifest.json: list `content_scripts` matches, `permissions`,
   `externally_connectable`, `web_accessible_resources`
3. For each extension with `<all_urls>` or broad host permissions, read
   the content script code for DOM manipulation, `eval`, or
   `chrome.tabs.executeScript` with dynamic code
4. Test `externally_connectable` -- any listed origin can send messages
   to the extension's background page

### Configuration Cross-Product Audit

For tools with many flags and options:

1. Enumerate all flags from `--help` or man pages
2. Cluster flags into functional groups (output, input, network, auth)
3. Test pairwise combinations ACROSS groups -- bugs live in the
   interaction between flags from different groups, not within a group
4. Focus on flags that modify the same underlying state from different
   angles

### Symlink-Following in Desktop Applications

For any desktop application that processes files from a user-writable
directory:

1. Identify every file-read and file-write operation the app performs
2. Test: replace a regular file with a symlink to a sensitive target
   BETWEEN the app's check and use (TOCTOU)
3. Focus on temp files, auto-save, cache directories, and export paths

### PII Export Endpoint Audit

For any SaaS platform:

1. List every endpoint that exports CSVs, generates PDFs, or returns
   "all-records" JSON
2. Test each with cross-tenant identifiers
3. Test whether the export respects field-level ACLs or dumps everything

### SSRF Bypass Layering

For any feature that fetches a user-supplied URL, test 6 layers before
declaring it safe:

1. Direct internal target (`http://localhost`, `http://127.0.0.1`)
2. DNS rebinding (domain that resolves to internal IP after first check)
3. Redirect chain (external URL that 302s to internal target)
4. Protocol smuggling (`gopher://`, `dict://`, `file://`)
5. IPv6 mapping (`[::1]`, `[0:0:0:0:0:ffff:127.0.0.1]`)
6. URL parser differential (backslash, at-sign, fragment confusion)

---

**Source attribution**: This playbook is a faithful conversion of the
Apache-2.0-licensed YAML at upstream Armur-Ai/Pentest-Swarm-AI. The phase
structure and post_analysis text are reproduced verbatim. See
`bugdotexe/skills/playbooks/SOURCE.md` for full provenance.
