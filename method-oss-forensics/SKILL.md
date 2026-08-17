---
name: method-oss-forensics
description: Forensic investigation methodology for public GitHub repositories — multi-source evidence collection, hypothesis formation, verification, and timeline reporting
depends_on: []
---

# OSS Forensics

Methodology for investigating suspicious activity on public GitHub repositories — typosquats, malicious commits, supply-chain attacks, deleted-but-archived material. Decomposes into evidence collection, hypothesis formation, verification, and report assembly.

## Prerequisites

Tooling and access expected:
- `gh` CLI (install: `apt install gh`, then `gh auth login`)
- `git` (install: `apt install git`)
- `curl`/`wget` for raw HTTP fetches
- BigQuery client `bq` for `githubarchive` queries (install: `gcloud components install bq`, requires `GOOGLE_APPLICATION_CREDENTIALS` and a billing-enabled GCP project)
- Wayback Machine — fetch via the public REST endpoints; no auth needed
- `gitleaks` or `trufflehog` for credential-scan recovery (install: `apt install gitleaks` or via release archive)

If BigQuery access is not available, downgrade to GitHub-API-only investigation and note the limitation in the report.

## Workflow

### Phase 0: Initialize Investigation

Create a working directory at `.out/oss-forensics-<timestamp>/`. Initialize an empty `evidence.json` keyed by source. All evidence collection writes into this directory.

---

### Phase 1: Parse Prompt & Form Research Question

Extract from user's prompt:
- Repository references (e.g., `aws/aws-toolkit-vscode`)
- Actor usernames (e.g., `lkmanka58`)
- Date ranges (e.g., `July 13, 2025`)
- Vendor report URLs (e.g., `https://...`)

Form a research question specific enough to produce a report with:
- **Timeline**: When did events occur?
- **Attribution**: Who performed what actions?
- **Intent**: What was the goal?
- **Impact**: What was affected?

**If prompt is ambiguous**, use AskUserQuestion to clarify:
- Missing repo: "Which repository should I investigate?"
- Missing timeframe: "What date range should I focus on?"
- Vague scope: "Should I focus on PRs, commits, or all activity?"

---

### Phase 2: Parallel Evidence Collection

Run the four evidence-collection probes in parallel (single message with multiple tool invocations) so the slowest probe sets the total wall-clock cost. Each probe writes a separate evidence chunk into the shared workdir.

**Probe 1 — GH Archive (BigQuery):**
Query `githubarchive.day.YYYYMMDD` for the actor/repo/date triple. Capture `PullRequestEvent`, `PushEvent`, `IssuesEvent`, `DeleteEvent`. Save to `evidence-gharchive.json`.

```sql
SELECT created_at, type, actor.login, repo.name, payload
FROM `githubarchive.day.20250713`
WHERE actor.login = 'lkmanka58' OR repo.name = 'aws/aws-toolkit-vscode';
```

**Probe 2 — GitHub API:**
Use `gh api` to fetch current state of repos, commits, PRs, issues. Capture metadata even if content has been edited or deleted. Save to `evidence-github.json`.

```bash
gh api "repos/{owner}/{repo}/commits/{sha}" > commit.json
gh api "repos/{owner}/{repo}/pulls/{n}/commits" > pr_commits.json
gh api "users/{actor}/events" > actor_events.json
```

**Probe 3 — Wayback Machine:**
Recover deleted content via the Internet Archive's CDX API. Useful for commit pages, PR descriptions, and force-pushed branches.

```bash
curl "https://web.archive.org/cdx/search/cdx?url=github.com/{owner}/{repo}&output=json"
curl "https://web.archive.org/web/{timestamp}/{url}"
```

Save snapshots and CDX listings to `evidence-wayback.json`.

**Probe 4 — Local Git Forensics:**
Clone the repo with full history (including dangling refs). Use `git fsck --unreachable` and `git reflog` to recover deleted commits.

```bash
git clone --mirror "https://github.com/{owner}/{repo}.git"
cd {repo}.git
git fsck --unreachable --no-reflogs --no-progress 2>&1 | grep "unreachable commit"
```

Save the unreachable SHA list and per-commit diffs to `evidence-local-git.json`.

**Optional Probe 5 — IOC Extraction (only if vendor report URL is provided):**
Parse the vendor advisory for actor handles, commit SHAs, file paths, network indicators. Save to `evidence-iocs.json`.

After all probes complete, proceed to hypothesis formation.

---

### Phase 3: Hypothesis Formation Loop (max 3 iterations)

Synthesize the collected evidence into one or more candidate hypotheses describing what happened. Each hypothesis must explain the timeline, attribution, intent, and impact.

If a hypothesis cannot yet be formed because of an evidence gap, write an `evidence-request-<n>.md` listing what's missing and which probe to re-run with what query. Re-run that probe, append to evidence, and try hypothesis formation again. Cap at 3 follow-up loops to avoid infinite expansion. If still unsupported after 3 follow-ups, proceed with the strongest partial hypothesis and flag uncertainty in the report.

Save the final hypothesis to `hypothesis-001.md`.

### Phase 4: Evidence Verification

Walk every evidence claim and cross-check it against the original source:
- GitHub API claims → re-fetch the live endpoint, compare bodies
- Wayback claims → confirm the archive snapshot URL still resolves
- Local-git claims → re-run `git show <sha>` and compare diff hash
- BigQuery claims → re-run the query bounded to the same time window

Produce `evidence-verification-report.md` with a per-claim verdict: VERIFIED / MUTATED / GONE.

### Phase 5: Hypothesis Validation Loop (max 3 iterations)

Take the verified evidence and the candidate hypothesis. For each hypothesis claim, find the supporting evidence item. If any claim is uncovered or contradicted, write a `hypothesis-001-rebuttal.md` describing what evidence is missing or what evidence contradicts the hypothesis.

If rebuttal is non-empty, revise the hypothesis using the rebuttal as guidance and re-validate. Cap at 3 retries. If still unsupported after 3 retries, finalize with the strongest hypothesis and document the uncertainty in the report.

When the hypothesis is fully supported, save as `hypothesis-001-confirmed.md`.

### Phase 6: Generate Report

Assemble `forensic-report.md` with:
- Executive summary (timeline, attribution, intent, impact in 3 paragraphs)
- Evidence catalog (table per source, with claim → evidence ID → verification status)
- Hypothesis with mapped supporting evidence
- IOCs (commit SHAs, file paths, actor handles, network indicators)
- Limitations (what evidence was missing, what was unreachable)

---

### Phase 7: Complete

Inform user:
```
Investigation complete!

Report location: .out/oss-forensics-<timestamp>/forensic-report.md

Key outputs:
- evidence.json - All collected evidence
- evidence-verification-report.md - Verification results
- hypothesis-*.md - Analysis iterations
- forensic-report.md - Final report with timeline, attribution, IOCs
```

---

## Error Handling

- **BigQuery auth fails**: Stop, show credential setup instructions
- **GitHub API rate limited**: Continue with other sources, note limitation in report
- **Repo clone fails**: Note in evidence, continue investigation
- **Max retries exceeded**: Produce report with current hypothesis, note uncertainty
- **Agent spawn fails**: Stop and report error to user with agent name and error message

---

## Critical Rules

1. **You are the ONLY orchestrator** - You spawn all agents, agents never spawn other agents
2. **Spawn in parallel when possible** - Use single message with multiple Task calls for Phase 2
3. **Wait for completion** - Don't proceed to next phase until current agents finish
4. **Pass working directory** - Every agent needs the workdir path
5. **Check for evidence requests** - Hypothesis former may request more evidence instead of forming hypothesis
6. **Respect limits** - Honor max_followups and max_retries flags

---

## Corpus-Derived Hunting Techniques

Patterns extracted from high-bounty OSS security research. These augment the forensic workflow above with proactive discovery methodology.

### CI/CD Pipeline Auditing

Public OSS repos with GitHub Actions are high-value targets. The vulnerability sits in the workflow trigger + permissions matrix.

1. For every public repo under a target org, pull every `.github/workflows/*.yml` file.
2. Search for `pull_request_target` triggers — these run with WRITE permissions on the base repo, not the fork. Trace every variable from the PR context (`github.event.pull_request.title`, `github.event.pull_request.body`, `.head.ref`) into any `run:` step. If user-controlled text reaches a shell command, it is code injection.
3. Check for `workflow_run` triggers that inherit secrets from the triggering workflow.
4. Look for self-hosted runner labels (`runs-on: self-hosted`). Dork patterns: search workflow files for `self-hosted`, pull run logs for runner names, check if the runner is shared across public and private repos.
5. Audit Actions marketplace actions used by the target — a compromised or typosquatted action in a trusted workflow inherits all workflow permissions.

### Diff-Audit and Patch-Bypass Hunting

Monitor new PRs/commits to popular OSS libraries used by the target. When a security-relevant commit lands:

1. Read the patch carefully. Identify the exact condition the fix prevents.
2. Check: does the fix cover ALL code paths, or only the one reported? Many patches fix the specific PoC but leave the class open.
3. Test variant inputs that satisfy the spirit of the attack but not the literal regex/check the patch added.
4. For any accepted bug bounty fix, re-test the entire flow 2-4 weeks after the fix ships — regressions are common during refactors.

### Parser-Differential Discovery

When the target uses a parser (HTML sanitizer, URL parser, Markdown renderer, JSON/YAML decoder):

1. Identify the specific library and version used for parsing.
2. Identify where the parsed output is consumed — if a different library or context re-parses the output, the gap between parsers is the attack surface.
3. Feed edge-case inputs from the relevant RFC (bare CR in HTTP, BOM in JSON, null bytes in URLs, empty comments in HTML) and compare what the parser produces vs. what the consumer sees.
4. When two implementations of equivalent semantics exist (e.g., two EVM clients, MRI Ruby vs mruby, CPython vs PyPy), write a differential harness: same input, both implementations, assert outputs match. Any divergence is a candidate bug.

### Cross-Product Identifier Leakage

When a product family integrates many tools, identifiers (object IDs, user handles, internal names) leak across trust boundaries:

1. Map all integration points — export features, embed URLs, sharing links, API connectors.
2. For each, capture the identifiers transmitted and test: does the receiving product enforce the same ACLs the originating product does?
3. Bulk-export paths (e.g., "Export as .zip", "Download all") are a goldmine for authorization bugs — they often bypass the row-level checks that the UI enforces per-item.

### Cloud Resource Pre-Emption

For every cloud service that auto-creates infrastructure with a deterministic name (S3 buckets, GCS buckets, DNS records, container registries):

1. Read the service documentation to find the naming pattern (usually `{project-id}-{service-name}-{region}`).
2. Create the resource before the victim service does. When the service later tries to create it, it either fails or writes to the attacker-controlled resource.
3. Audit deployment templates (Terraform, CloudFormation, Pulumi) in OSS repos for hardcoded or predictable resource names.

### Deployment Artifact Security

Web application security depends on reverse-proxy/WAF/ingress configuration as much as code:

1. Search the target's OSS repos for `nginx.conf`, `Caddyfile`, `traefik.yml`, `ingress.yaml`, `haproxy.cfg`, `.htaccess`.
2. Look for `alias` directives in nginx without trailing slashes — classic path traversal. Look for `proxy_pass` with user-controlled path segments.
3. Check Kubernetes ingress annotations for injection vectors (annotation values reach nginx config generation).

### n-day Exploit Development on Patched Bugs

When a CVE patches a memory-corruption or logic bug in an OSS dependency:

1. Read the patch commit and the regression test. The test input is a trigger — the patch is a roadmap to the vulnerability.
2. Check the target's dependency pinning — if they pin to a version before the patch, the n-day window is open.
3. Build the pre-patch version and confirm the trigger reproduces. Then develop the exploit against the target's specific deployment.

### Cross-Sandbox Shared State Audit

When auditing multi-policy or multi-language platforms (API gateways, serverless runtimes, plugin systems):

1. Identify all sandboxes — each policy, each function, each plugin runs in its own execution context.
2. Map shared state between sandboxes: class prototypes, global registries, thread-locals, connection pools, caches.
3. Craft a payload in sandbox A that mutates shared state, then observe whether sandbox B reads the mutated state. Prototype pollution across sandbox boundaries is a canonical example.

---

## Example Execution

```
User: /oss-forensics "Investigate lkmanka58's activity on aws/aws-toolkit-vscode on July 13, 2025"

Phase 0: Run init script -> workdir: .out/oss-forensics-20251130-143022/
Phase 1: Parse prompt -> repo=aws/aws-toolkit-vscode, actor=lkmanka58, date=2025-07-13
Phase 2: Spawn 4 investigators in parallel -> collected 42 evidence items
Phase 3: Hypothesis former -> wrote hypothesis-001.md
Phase 4: Verifier -> 40/42 verified
Phase 5: Checker -> REJECTED -> Former revises -> Checker -> ACCEPTED
Phase 6: Report generator -> forensic-report.md
Phase 7: Inform user

Result: Complete forensic report ready
```
