---
name: internal-network-playbook
description: Authorized internal network pentest playbook. Requires a signed scope file (see scope_file variable) — the runner refuses to execute without
license: Apache-2.0 (lifted from Armur-Ai/Pentest-Swarm-AI ebca218f :: playbooks/internal-network.yaml)
depends_on: []
---

# Internal Network Swarm

> Phase-orchestrated playbook converted from upstream YAML at
> `Armur-Ai/Pentest-Swarm-AI/playbooks/internal-network.yaml` (Apache-2.0).

## Description

Authorized internal network pentest playbook. Requires a signed scope file (see scope_file variable) — the runner refuses to execute without one. Walks CIDR -> service enumeration -> optional Metasploit post-ex with cleanup always registered.

## Variables (declare at scan start)

```yaml
  scope_file:
    type: string
    required: true
    description: Path to the signed scope YAML authorising this engagement
  cidr:
    type: string
    required: true
  post_exploitation:
    type: string
    default: read-only
    description: "read-only | active (active requires separate written approval)"

```

## Phases

```yaml
  - name: network_sweep
    tools:
      - name: nmap
        options:
          scan_type: "-sS"
          top_ports: 1000
          timing: "-T3"   # quieter on internal networks
    post_analysis: |
      Identify live hosts and top-1000 open ports. Skip printer/IoT
      ranges unless explicitly in scope — they crash easily.

  - name: service_enum
    tools:
      - name: nmap
        options:
          scan_type: "-sV"
          top_ports: 100
          timing: "-T3"
    post_analysis: |
      Version-fingerprint the services that matter: SSH, SMB, RDP,
      WinRM, LDAP, SNMP, databases. Credential hygiene findings
      are critical-severity by default on internal nets.

  - name: post_exploitation
    tools:
      # Metasploit is opt-in and only fires when post_exploitation == "active".
      # The swarm's exploit agent refuses without cleanup commands registered.
      - name: metasploit
        options:
          post_exploitation: "{{ post_exploitation }}"
    post_analysis: |
      Read-only: enumerate users, shares, group memberships.
      Active: require per-action written approval (the playbook runner
      will halt and prompt). All sessions must be killed and artefacts
      removed on exit — cleanup registry enforces this.
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

## Corpus-Derived Internal Network Hunting Patterns

Distilled from 307 disclosed reports ($6.4M in bounties). Apply these during
the service enumeration and post-exploitation phases.

### CI/CD on Public OSS Repos as Pivot

Public repos with CI/CD workflows that have access to internal infrastructure:

1. For every public repo in the org, pull all workflow files
2. Check for `pull_request_target` triggers with write permissions
3. Check for self-hosted runners that may sit on the internal network
4. A successful workflow injection = code execution on internal infra

### Internal RPC Bridge Auth Audit

At any company with a heavy internal-RPC architecture:

1. Identify internal-service-name patterns in API responses, error messages,
   or JavaScript bundles
2. Test whether external-facing endpoints proxy to internal RPCs without
   per-resource authorization
3. Look for internal API documentation exposed via Swagger/OpenAPI on
   non-production domains

### SSRF to Cloud Metadata Pivot

For every cloud-hosted service that fetches user URLs:

1. Test `http://169.254.169.254/latest/meta-data/` (AWS)
2. Test `http://metadata.google.internal/computeMetadata/v1/` (GCP)
3. Test `http://169.254.170.2/v2/credentials/{guid}` (ECS)
4. Use DNS rebinding when direct IPs are blocked
5. Chain: metadata credentials -> internal service access -> lateral movement

### Third-Party Deployments Inside Org Domains

Large orgs run thousands of internal-facing services:

1. Enumerate internal domains and subdomains
2. Fingerprint third-party software (Confluence, JIRA, Jenkins, Grafana,
   Kibana, Airflow, Jupyter, GitLab)
3. Test default credentials and known CVEs for each identified service
4. These deployments often run unpatched and with default configurations

### GraphQL Field-Level Audit

For any GraphQL endpoint on internal services:

1. Pull the schema and list every field with sensitive-naming patterns
   (`private_`, `internal_`, `admin_`, `secret_`, `debug_`)
2. Test whether these fields are returned in queries even without
   authorization
3. Test mutation access: can you modify fields that should be read-only?
4. Test nested queries for data exfiltration across type boundaries

### Dependency Confusion / Internal Package Hijack

Target's internal package names leaked in manifests:

1. Search GitHub repos, Docker images, mobile apps, and error pages for
   internal package manifests (Gemfile, package.json, requirements.txt, go.mod)
2. Check if internal package names are claimable on public registries
   (npm, PyPI, RubyGems, crates.io)
3. Publish a higher-versioned package on the public registry -- many
   build systems prefer the higher version

### Internal Admin Panel Blind XSS

Every B2B SaaS has an internal support console:

1. Identify merchant/customer-controlled fields that flow into
   admin-facing views (names, descriptions, custom fields)
2. Seed blind-XSS payloads into these fields
3. Staff name fields, support ticket bodies, and feedback forms are
   the most common vectors

### SSRF via Managed Service Plugins

In multi-tenant managed services with plugin ecosystems:

1. Identify every plugin/connector and its interaction with filesystem,
   network, and process
2. Test JDBC URL injection for SSRF (e.g., SQLite JDBC with remote
   resource loading)
3. Chain: SSRF to internal API (Jolokia, Prometheus, etc.) for
   code execution

### Infrastructure Relay Abuse

On any infrastructure relay (TURN, SIP proxy, SMTP smarthost, mesh peer):

1. Check whether the destination of the relay is restricted to external
   targets or can reach internal IPs
2. Test TURN relay to `127.0.0.1`, `169.254.169.254`, and internal CIDR ranges
3. Test whether the relay supports TCP tunneling (not just UDP)

### Protocol-Multiplexing DoS

In multiplexed protocols (HTTP/2, WebSocket, gRPC):

1. Test whether byte-count limits are enforced on internal allocation
   amplification (not just wire bytes)
2. Send HTTP/2 CONTINUATION floods -- small on the wire, large in
   server memory
3. Test whether connection-level limits prevent a single client from
   exhausting server resources

---

**Source attribution**: This playbook is a faithful conversion of the
Apache-2.0-licensed YAML at upstream Armur-Ai/Pentest-Swarm-AI. The phase
structure and post_analysis text are reproduced verbatim. See
`bugdotexe/skills/playbooks/SOURCE.md` for full provenance.
