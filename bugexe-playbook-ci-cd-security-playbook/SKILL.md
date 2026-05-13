---
name: ci_cd_security_playbook
description: Source-side security swarm for GitHub Actions (or any CI). Runs inside the repo: secret scanning (gitleaks + trufflehog), SAST (semgrep), an
license: Apache-2.0 (lifted from Armur-Ai/Pentest-Swarm-AI ebca218f :: playbooks/ci-cd-security.yaml)
depends_on: []
---

# CI/CD Security Swarm

> Phase-orchestrated playbook converted from upstream YAML at
> `Armur-Ai/Pentest-Swarm-AI/playbooks/ci-cd-security.yaml` (Apache-2.0).

## Description

Source-side security swarm for GitHub Actions (or any CI). Runs inside the repo: secret scanning (gitleaks + trufflehog), SAST (semgrep), and dependency audit. Emits SARIF so findings flow into GitHub Code Scanning. Zero network traffic to production.

## Variables (declare at scan start)

```yaml
  repo_path:
    type: string
    default: .
  fail_on_severity:
    type: string
    default: high
    description: Minimum severity that fails the job (critical | high | medium | low)

```

## Phases

```yaml
  - name: secret_scan
    tools:
      - name: gitleaks
        options: { config: ".gitleaks.toml", report_format: sarif }
      - name: trufflehog
        options: { only_verified: true }
    post_analysis: |
      Any VERIFIED secret = pipeline fail regardless of fail_on_severity.
      Historical commits are in scope — a rotated secret is still a
      disclosure event until someone confirms rotation on the vendor side.

  - name: static_analysis
    tools:
      - name: semgrep
        options:
          config: ["p/owasp-top-ten", "p/cwe-top-25", "p/security-audit"]
          sarif: true
    post_analysis: |
      Focus on auth/authz paths, crypto misuse, deserialisation, SSRF
      sinks, and template injection. Autofix suggestions go to the PR
      review comments.

  - name: dependency_audit
    tools:
      - name: semgrep
        options: { config: ["p/supply-chain"] }
    post_analysis: |
      Transitive dependency CVEs — pin major known-bad versions, flag
      unpinned floating tags in Dockerfiles and base images.

  - name: emit_sarif
    tools: []
    post_analysis: |
      Merge all tool SARIFs into a single artefact. Job exit code
      follows fail_on_severity.
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

## Corpus-Derived CI/CD Hunting Patterns

Distilled from 463 disclosed reports ($11.5M in bounties). Apply these during
and after the static analysis and dependency audit phases.

### GitHub Actions Pwn Request Audit

For any GitHub Actions repository owned by a target:

1. Clone the repo and locate every `.github/workflows/*.yml` file
2. Search for `pull_request_target` triggers -- these run with write
   permissions on the base repo, not the fork
3. For each, trace every `${{ github.event.pull_request.* }}` expression
   into `run:` blocks -- any interpolation is code injection
4. Check for `actions/checkout` of the PR head ref in a `pull_request_target`
   workflow -- this checks out attacker-controlled code with elevated perms

### Self-Hosted Runner Attack

Self-hosted runner exploitation is a canonical bug class:

1. Find target's public repos that run GitHub Actions
2. Pull run logs and check for `runs-on: self-hosted` or custom labels
3. If self-hosted: a PR from a fork may execute on the org's infrastructure
4. Test whether the runner persists state between jobs (credentials, tokens,
   SSH keys left on disk)

### CI/CD Recon Dorks

Systematically discover exposed CI/CD infrastructure:

1. `inurl:workflows +"self-hosted"` -- repos using self-hosted runners
2. `inurl:.github/workflows "pull_request_target"` -- pwn request candidates
3. `shodan: "X-Jenkins"`, `shodan: "X-Hudson"` -- exposed Jenkins instances
4. Look for CI status badges pointing to internal CI URLs

### Deployment Artifact Auditing

Security posture is determined by deployment config as much as code:

1. Check `nginx.conf`, `Caddyfile`, `traefik.yml` in repos for
   `alias` path traversal (`location /static { alias /data/; }` allows
   `/static../etc/passwd`)
2. Audit Helm charts, Kubernetes manifests, Docker Compose files for
   exposed ports, default credentials, privileged containers
3. Check Terraform/Pulumi/CloudFormation for overly permissive IAM policies

### File Processing Pipeline RCE

For every file-processing pipeline in the target:

1. Enumerate all parsers (image: ImageMagick/libvips, video: ffmpeg,
   document: LibreOffice, metadata: ExifTool, archive: zip/tar)
2. Look for `eval`, `system`, `exec`, dynamic loading, or shell expansion
   in parser code paths
3. Test archive uploads for Zip Slip (path traversal in extracted filenames)
4. Test image/video uploads for SSRF via SVG `<image>` tags or video
   subtitle URLs

### Cross-Service Idempotency Failures

For any multi-service settlement workflow:

1. Identify every place where money/balance/state changes across services
2. Test whether idempotency keys are enforced end-to-end or only at one
   service boundary
3. Replay requests with modified amounts but same idempotency keys
4. Test race conditions between the authorization and capture steps

### Argument Injection via Filenames

For any feature that builds a shell command from user-controlled paths:

1. Test filenames starting with `--` (e.g., `--output=/etc/passwd`)
2. Test filenames with shell metacharacters (`;`, `|`, `` ` ``, `$()`)
3. Test filenames with newlines (`%0a`) to inject additional commands
4. Check git operations: branch names, tag names, and commit messages
   are common injection vectors

### Pipeline Parity Audit

When a company publishes a global privacy/security policy (e.g., "we strip
EXIF", "we resize uploads", "we transcode video"):

1. Test every upload endpoint to see if the pipeline actually runs
2. Upload a file with EXIF GPS data -- download it and check if stripped
3. Upload an oversized image -- check if resized
4. Different endpoints (support, community, marketplace) often skip
   the processing pipeline

### Developer Tooling XXE

IDE plugins, build tools, and language servers parse untrusted XML:

1. Inventory every file the IDE/build tool parses on project-open or build
2. For each XML parser, test external entity resolution
3. Check `.project`, `.classpath`, `pom.xml`, `.csproj`, and IDE-specific
   config files for XXE injection points
4. Test whether the XXE is blind (OOB exfil) or reflected in error messages

---

**Source attribution**: This playbook is a faithful conversion of the
Apache-2.0-licensed YAML at upstream Armur-Ai/Pentest-Swarm-AI. The phase
structure and post_analysis text are reproduced verbatim. See
`bugdotexe/skills/playbooks/SOURCE.md` for full provenance.
