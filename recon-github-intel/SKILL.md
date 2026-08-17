---
name: recon-github-intel
category: reconnaissance
description: Deep GitHub passive intelligence — code, issues, PRs, commits, forks, gists, wiki, and member-extension search. Methodology-first replacement for one-shot subprocess scrapers — exhaustive search-tree walk for leaked secrets, internal hostnames, deployment configs, and architecture intel.
trigger: starting passive recon on a target with a discoverable organization or developer account; looking for leaked secrets, internal endpoints, deployment configs, API specs; cross-checking subdomain/host candidates against committed source; need to discover acquisitions/subsidiaries through developer footprint
composes_with: recon_google_dorking, recon_yandex_dorking, recon_archive_intel, recon_information_disclosure, recon_passive_subdomain
depends_on: []
---

# Recon — GitHub Intelligence (Deep)

## Purpose

GitHub is the single highest-yield passive-intel surface for a modern target. Developers regularly commit `.env` files, internal hostnames, deployment manifests, API specs, JWT secrets, cloud credentials, database connection strings, and entire CI/CD pipelines into public repos — often by accident, often into forks rather than the upstream they later cleaned up. A complete GitHub sweep replaces hours of active scanning: every internal hostname leaked in a Helm values file, every dev-cluster URL pasted into a PR comment, every rotated-but-still-cached secret in a deleted-then-restored repo is a free attack surface. Subprocess tools (`gau`, `waymore`, generic `gh search code`) hit one slice and stop. This skill is the methodology a reasoning agent uses to walk the entire search tree — code, issues, PRs, commits, wikis, gists, members' personal repos, forks of cleaned upstreams, archived repos, security advisories — without skipping branches based on early negatives.

## When to Use

- Starting passive reconnaissance on any target with a likely developer presence
- The target's primary domain or org name has been resolved in earlier scope intake
- Looking for leaked secrets, deployment topology, internal hostnames, or API specs
- Need to enumerate acquisitions/subsidiaries via shared developers
- Cross-checking previously-found credentials against committed source
- Validating that a hostname found in DNS records actually maps to a real internal service
- Hunting subdomain candidates from values files, kubeconfigs, terraform state
- Looking for SSRF/SSO/auth-flow source you can read before fuzzing live

## Inputs (runtime-derived)

- `target_root_domain` — primary apex domain extracted from `--target` arg
- `target_alt_domains` — subsidiary / acquisition domains discovered earlier
- `target_org_candidates` — likely GitHub org slugs (target-name, target-name-inc, target-internal, target-team, etc.)
- `known_subdomains` — from prior recon (used as keyword anchors)
- `known_employees` — names/handles surfaced earlier (LinkedIn, conference talks, blog bylines), optional but multiplies coverage
- `known_email_pattern` — `firstname.lastname@target.example`, `f.lastname@target.example`, etc. for cross-referencing personal repos
- `auth_token` — `GITHUB_TOKEN` env var if set (lifts unauth 60/hr → 5000/hr authenticated)

## Methodology

### Stage 1 — Org Discovery & Anchor Building

Before the first search, build the anchor set. The whole sweep depends on the anchor list being complete.

1. **Domain → org slug enumeration**: try natural variations
   - bare slug: `target`
   - corporate suffixes: `target-inc`, `target-corp`, `target-co`, `target-ltd`, `target-llc`, `target-team`
   - functional suffixes: `target-engineering`, `target-platform`, `target-eng`, `target-internal`, `target-labs`, `target-oss`, `target-research`
   - product/codename variants discovered from marketing pages or job postings
   - acquisition variants: every alt domain produces its own slug guesses
2. **Cross-reference with GitHub**: for every candidate, check `https://github.com/{slug}` — confirm it exists, count public repos, count members, check pinned repos for stack hints
3. **Member enumeration**: if the org page allows it, walk public members. Record handles, real names, email patterns. Each member is a downstream target for personal-repo + gist mining.
4. **Reverse domain→user**: search for users where the bio / website / location references `target.example`. Use `gh api search/users --field q="{target.example} in:bio in:email"` and `gh api search/users --field q="@{target.example}"`.
5. **Acquisition discovery via developer footprint**: if multiple GitHub orgs share members or share an email domain, document them. They are in scope unless the program explicitly excludes them.
6. **Subsidiary org guess via repo cross-listing**: a repo owned by `target` may have a downstream fork pinned under `target-acquired-co` — document.

Output of Stage 1: `anchors.json`
```json
{
  "primary_orgs": ["target", "target-engineering"],
  "subsidiary_orgs": ["target-acquired-co"],
  "known_handles": ["alice", "bob", "..."],
  "domain_anchors": ["target.example", "target-internal.example", "target-cdn.example"],
  "email_anchors": ["@target.example", "@corp.target.example"]
}
```

### Stage 2 — Code Search (Org-Scoped → Domain-Scoped → Pattern-Scoped)

Three search axes, each independent. Run all three; do not stop at the first that returns hits.

#### Axis A: Org-scoped code search

For each org slug in `primary_orgs`:

```
org:target filename:.env
org:target filename:.env.production
org:target filename:.env.local
org:target filename:.env.staging
org:target filename:application.properties
org:target filename:application.yml
org:target filename:settings.py "SECRET_KEY"
org:target filename:web.config "connectionString"
org:target filename:appsettings.json
org:target filename:database.yml
org:target filename:secrets.yml
org:target filename:config.json "password"
org:target filename:config.yaml "password"
org:target filename:docker-compose.yml "password"
org:target filename:docker-compose.override.yml
org:target filename:Dockerfile "ENV" "KEY"
org:target filename:.npmrc "_authToken"
org:target filename:.pypirc "username" "password"
org:target filename:.docker/config.json "auth"
org:target filename:.aws/credentials
org:target filename:.aws/config
org:target filename:.s3cfg
org:target filename:.boto
org:target filename:.netrc
org:target filename:credentials.json "private_key"
org:target filename:service-account.json
org:target filename:kubeconfig
org:target filename:cluster.yaml "server"
org:target filename:terraform.tfvars
org:target filename:terraform.tfstate
org:target filename:.terraform "backend"
org:target filename:Pulumi.yaml
org:target filename:Pulumi.dev.yaml
org:target filename:helm/values.yaml
org:target filename:values.yaml "image" "host"
org:target filename:Chart.yaml
org:target filename:kustomization.yaml
org:target filename:.helmignore
org:target filename:Jenkinsfile "credentials"
org:target filename:.gitlab-ci.yml "variables"
org:target path:.github/workflows
org:target filename:.travis.yml "secure"
org:target filename:.circleci/config.yml
org:target filename:.drone.yml
org:target filename:azure-pipelines.yml
org:target filename:bitbucket-pipelines.yml
org:target filename:cloudbuild.yaml
org:target filename:openapi.yaml
org:target filename:openapi.json
org:target filename:swagger.yaml
org:target filename:swagger.json
org:target filename:schema.graphql
org:target filename:asyncapi.yaml
```

For each query: record total hit count, top 10 file paths, file URLs. Don't read every file; look for divergent ones.

#### Axis B: Domain-scoped code search (across ALL of GitHub, not just the org)

Developers leak target hostnames in OTHER orgs' repos — third-party integrations, contractor work, conference demos.

```
"target.example" filename:.env
"target.example" filename:config.json "password"
"target.example" filename:terraform.tfstate
"target.example" filename:values.yaml
"target.example" "Authorization: Bearer"
"target.example" "X-Api-Key"
"target.example" "BEGIN RSA PRIVATE KEY"
"target.example" "BEGIN OPENSSH PRIVATE KEY"
"target-internal.example"
"target-cdn.example"
"@target.example" filename:.gitconfig
"@target.example" filename:.netrc
"@target.example" filename:.npmrc
"target.example" "postgres://"
"target.example" "mysql://"
"target.example" "mongodb+srv://"
"target.example" "redis://"
"target.example" "amqp://"
"target.example" "nats://"
"target.example" "elasticsearch" "host"
"target.example" "vault" "token"
"target.example" "BEGIN CERTIFICATE"
```

#### Axis C: Pattern-scoped credential search (within target's anchor set)

Credentials have predictable prefixes. Combine prefix with target anchor.

| Prefix | Vendor / Class | Query example |
|--------|---------------|---------------|
| `AKIA` | AWS access key (long-lived) | `org:target "AKIA"` |
| `ASIA` | AWS access key (temp/STS) | `org:target "ASIA"` |
| `AIza` | Google API key | `org:target "AIza"` |
| `ya29.` | Google OAuth token | `org:target "ya29."` |
| `sk_live_` | Stripe live secret | `org:target "sk_live_"` |
| `sk_test_` | Stripe test secret | `org:target "sk_test_"` |
| `rk_live_` | Stripe restricted | `org:target "rk_live_"` |
| `xoxb-` | Slack bot token | `org:target "xoxb-"` |
| `xoxp-` | Slack user token | `org:target "xoxp-"` |
| `xoxa-` | Slack app token | `org:target "xoxa-"` |
| `xapp-` | Slack app-level | `org:target "xapp-"` |
| `ghp_` | GitHub PAT (classic) | `org:target "ghp_"` |
| `gho_` | GitHub OAuth | `org:target "gho_"` |
| `ghs_` | GitHub server | `org:target "ghs_"` |
| `ghu_` | GitHub user-to-server | `org:target "ghu_"` |
| `glpat-` | GitLab PAT | `org:target "glpat-"` |
| `dckr_pat_` | DockerHub PAT | `org:target "dckr_pat_"` |
| `npm_` | npm token | `org:target "npm_"` |
| `pypi-` | PyPI token | `org:target "pypi-"` |
| `SG.` | SendGrid API | `org:target "SG."` |
| `key-` | Mailgun | `org:target "key-"` |
| `AC` | Twilio Account SID | `org:target "AC" "auth_token"` |
| `EAACEdEose0cBA` | Facebook access token | `"target.example" "EAA"` |
| `ya29` | Google OAuth refresh | `org:target "ya29"` |
| `1//0` | Google refresh token | `org:target "1//0"` |
| `eyJ` | JWT (any) | `org:target "eyJ" filename:.env` |
| `BEGIN RSA PRIVATE KEY` | RSA key block | `org:target "BEGIN RSA PRIVATE KEY"` |
| `BEGIN OPENSSH PRIVATE KEY` | OpenSSH key | `org:target "BEGIN OPENSSH PRIVATE KEY"` |
| `BEGIN PGP PRIVATE KEY` | PGP private | `org:target "BEGIN PGP PRIVATE KEY"` |

Connection-string patterns (host fragments embed real internal infra):
```
org:target "postgres://"
org:target "postgresql://"
org:target "mysql://"
org:target "mongodb://"
org:target "mongodb+srv://"
org:target "redis://"
org:target "amqp://"
org:target "kafka://"
org:target "ldap://"
org:target "ldaps://"
org:target "smb://"
org:target "ftp://"
org:target "elasticsearch://"
```

### Stage 3 — Issue and PR Mining

Source code is sanitized; *issue and PR comments are not*. Developers paste full URLs, full stack traces, full env dumps into bug reports.

#### Issue search

```
org:target is:issue "redacted"
org:target is:issue "internal only"
org:target is:issue "production credentials"
org:target is:issue "stack trace"
org:target is:issue "Traceback"
org:target is:issue "stagehost"
org:target is:issue "localhost"
org:target is:issue in:body "https://target-internal.example"
org:target is:issue in:body "X-Forwarded-For"
org:target is:issue in:body "Authorization:"
org:target is:issue in:body "Bearer "
org:target is:issue in:body "kubectl"
org:target is:issue in:body "vault read"
org:target is:issue in:body "[error]" "host"
org:target is:issue in:body "screenshot"
"target.example" is:issue in:body "credentials"
"target-internal.example" is:issue
```

#### PR search

```
org:target is:pr "remove credential"
org:target is:pr "rotate"
org:target is:pr "leak"
org:target is:pr "redact"
org:target is:pr "fix secret"
org:target is:pr "oops"
org:target is:pr "accidentally committed"
org:target is:pr in:title "rotate"
org:target is:pr in:title "key"
org:target is:pr in:body "this PR removes" "secret"
org:target is:pr is:closed "credential"
```

#### Comment search (in:comments)

Comments live separately from body and often leak more freely.

```
org:target in:comments "host=" "password="
org:target in:comments "DATABASE_URL"
org:target in:comments "internal.target.example"
org:target in:comments "kubectl exec"
org:target in:comments "ssh "
"target.example" in:comments "BEGIN"
```

### Stage 4 — Commit Message and History Mining

Secrets in HEAD are removed; secrets in history persist until force-push + GC.

#### Commit message search

```
org:target "remove key"
org:target "remove secret"
org:target "remove password"
org:target "remove token"
org:target "fix leak"
org:target "rotate token"
org:target "rotate key"
org:target "rotate secret"
org:target "rotate credential"
org:target "credential"
org:target "rotated"
org:target "redacted"
org:target "oops"
org:target "accidentally"
org:target "wip"
org:target "do not merge"
org:target "DEBUG=true"
org:target "password reset"
```

For each high-signal commit message hit:
1. Open the commit URL: `https://github.com/{org}/{repo}/commit/{sha}`
2. The diff still shows the removed content. Read it.
3. If a credential was removed in commit `X`, read `X^` (parent) — that's where the secret lives at HEAD before deletion.
4. Walk the file history backward (`?path={path}`) — earlier commits may show earlier credential rotations.

#### Local repo cloning and history grep

For high-yield repos, clone shallow + walk history with primitive tools (rate-limit-free, exhaustive):

```
gh repo clone {org}/{repo} /tmp/{repo}
cd /tmp/{repo}
git log --all --full-history --source -p -- "*.env" "*.config" "*.yml" "*.yaml" "*.json"
git log --all -p -S "AKIA" --source --all
git log --all -p -S "BEGIN RSA PRIVATE KEY" --source --all
git log --all -p -S "password" --source --all -- "*.env" "*.config"
git log --all -p -G '(api|secret|token|password)[_-]?key' --source --all
git log --all --source --remotes --pretty=oneline -S "ghp_"
git log --all --source --remotes --pretty=oneline -S "AKIA"
```

Walk every long-lived branch. Walk every tag. Walk every detached commit reachable via `git fsck --lost-found`.

### Stage 5 — Fork Mining

Forks are the highest-value, most-overlooked branch of the search tree. When upstream rotates a leaked secret with a force-push, the fork still has the old commit. When upstream deletes a repo, every fork persists. A fork on an obscure personal account can hold what the org cleaned up two years ago.

```
# All forks of a given repo
gh api repos/{org}/{repo}/forks --paginate --jq '.[].full_name'

# Search across forks
"target.example" fork:only filename:.env
"target.example" fork:true filename:terraform.tfstate
org:target fork:only "BEGIN"

# Find personal accounts that forked the org's repos
gh api repos/{org}/{repo}/forks --paginate --jq '.[] | "\(.owner.login) \(.full_name)"'
```

For each fork found:
1. Note the owner; if not in `anchors.json`, add them — they are likely a former / current developer
2. Diff the fork's HEAD against upstream HEAD — what extra files did the fork add?
3. Check fork's branches; sometimes work-in-progress branches contain credentials the dev never pushed upstream
4. Check fork's `default_branch`; sometimes it's renamed/changed and points to a different state

### Stage 6 — Member-Extension Mining

For each handle in `known_handles` from Stage 1:

```
# Personal repos containing target anchors
user:{handle} "target.example"
user:{handle} filename:.env
user:{handle} filename:.gitconfig
user:{handle} filename:.npmrc

# Their gists (often where dev pastes "just for me" code)
gh api users/{handle}/gists --paginate --jq '.[] | {url: .html_url, files: (.files | keys)}'

# Their starred repos can reveal interest in target tech stack
gh api users/{handle}/starred --paginate --jq '.[] | .full_name'

# Their followed users (other devs in same org)
gh api users/{handle}/following --paginate --jq '.[] | .login'
```

Pivot: each new handle discovered via "following" goes back to Stage 6, recursively until no new handles surface.

### Stage 7 — Wiki / Pages / Discussions

```
# Wiki pages — separate index from code
"target.example" in:wiki
org:target in:wiki "BEGIN"
org:target in:wiki "deploy"

# GitHub Pages sites under the org
# https://{org}.github.io/{repo}/  — often contain leaked dev URLs

# Discussions
org:target in:discussions "credential"
org:target in:discussions "internal"
org:target in:discussions "production"
```

### Stage 8 — Gist Mining

Gists are public by default and outside the org context.

```
# Direct API search
gh api search/code --field q='"target.example" filename:.env' --paginate
gh api search/code --field q='"@target.example" extension:env' --paginate

# Per-handle gists (covered partially in Stage 6)
gh api users/{handle}/gists --paginate

# Anonymous gists matching target keywords (gist site search)
"target.example" site:gist.github.com    # via Google
"target.example" site:gist.github.com    # via Yandex
"target-internal.example" site:gist.github.com
```

Gists have NO commit-history retention guarantees — clone them immediately on discovery.

### Stage 9 — Archived & Deleted Repo Recovery

```
# Archived repos still in the org
org:target archived:true

# Repos created/pushed in a window
org:target created:<2020-01-01
org:target pushed:<2020-01-01
org:target created:2020-01-01..2021-01-01
```

For repos that have been deleted, fork copies (Stage 5) and the GitHub Archive ([gharchive.org](https://www.gharchive.org/)) BigQuery dataset are the recovery routes. The agent can query gharchive via the public BigQuery interface to retrieve historical events for `target` orgs.

### Stage 10 — Security Advisories & Dependency Graphs

```
# Org-published security advisories
org:target type:advisories

# Dependency graph (manifest files reveal infrastructure)
# /{org}/{repo}/network/dependents
# /{org}/{repo}/network/dependencies
```

A `package-lock.json` resolved version pins reveal exact versions in production — feed those into CVE lookups.

## Search Operators / Patterns Reference

| Operator | What it matches | Example |
|----------|-----------------|---------|
| `org:` | Repos owned by org | `org:target` |
| `user:` | Repos owned by user | `user:alice` |
| `repo:` | Specific repo | `repo:target/api` |
| `filename:` | Filename match | `filename:.env` |
| `extension:` / `ext:` | File extension | `extension:env` |
| `path:` | Path substring | `path:.github/workflows` |
| `language:` | Source language | `language:go "AKIA"` |
| `in:file` | Match in file content (default) | `"AKIA" in:file` |
| `in:path` | Match in path | `".env" in:path` |
| `in:comments` | Match in PR/issue comments | `"BEGIN" in:comments` |
| `in:body` | Match in issue/PR body | `"redacted" in:body` |
| `in:title` | Match in issue/PR title | `"rotate" in:title` |
| `in:wiki` | Match in wiki | `"deploy" in:wiki` |
| `in:discussions` | Match in discussions | `"credential" in:discussions` |
| `is:public` | Public-only filter | `org:target is:public` |
| `is:private` | Visible only with token+permission | `is:private` |
| `is:issue` / `is:pr` | Type filter | `is:issue org:target` |
| `is:open` / `is:closed` | State filter | `is:closed is:pr "rotate"` |
| `fork:only` | Forks only (excludes original repos) | `org:target fork:only` |
| `fork:true` | Include forks | `"target.example" fork:true` |
| `archived:true` / `archived:false` | Archive state | `org:target archived:true` |
| `mirror:true` | Mirror repos only | `org:target mirror:true` |
| `created:` | Creation date | `org:target created:>2020-01-01` |
| `pushed:` | Last push date | `org:target pushed:>2024-01-01` |
| `size:` | Repo size in KB | `org:target size:>10000` |
| `stars:` | Star count range | `org:target stars:>10` |
| `forks:` | Fork count | `org:target forks:>5` |
| `topic:` | Topic tag | `org:target topic:kubernetes` |
| `license:` | License filter | `org:target license:mit` |

## Tool Primitives (sandbox-installed)

The sandbox container has `curl`, `gh` CLI, `git`, `ripgrep`, `jq`, `yq`. Use them directly; do not depend on a pre-built scraper.

```
# Authenticated rate limit (5000/hr)
export GITHUB_TOKEN=...   # if available

# Programmatic search via gh
gh api search/code -f q='org:target filename:.env' --paginate --jq '.items[] | {repo: .repository.full_name, path: .path, url: .html_url}'
gh api search/issues -f q='org:target is:issue "redacted"' --paginate --jq '.items[] | {url: .html_url, title: .title}'
gh api search/commits -f q='org:target "remove key"' --paginate --jq '.items[] | {sha: .sha, msg: .commit.message, url: .html_url}' -H "Accept: application/vnd.github.cloak-preview"

# Direct REST when gh hits coverage gaps
GH_API="https://api.github.com"
curl -s -H "Authorization: bearer $GITHUB_TOKEN" "${GH_API}/search/code?q=org%3Atarget+filename%3A.env&per_page=100"
curl -s -H "Authorization: bearer $GITHUB_TOKEN" "${GH_API}/search/issues?q=org%3Atarget+is%3Aissue+%22redacted%22&per_page=100"

# Clone shallow for history walk
gh repo clone {org}/{repo} -- --depth=200

# Offline rgrep across all cloned repos
rg -uu --no-ignore -l 'AKIA[0-9A-Z]{16}' /tmp/clones/
rg -uu -tjson 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.' /tmp/clones/
rg -uu 'BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY' /tmp/clones/
```

For unauthenticated calls (60/hr), space them. For authenticated, batch aggressively up to 5000/hr; pagination is `per_page=100` max.

## Decision Tree

```
Stage 1 done? (org slugs + handles + anchors complete)
  ├─ no  → return to Stage 1; without anchors, every later stage is shallow
  └─ yes → proceed

Stage 2 (code) returned hits?
  ├─ no hits in Axis A (org-scoped)
  │    → it does NOT mean "no GitHub presence". Run Axis B (domain-scoped) — third parties leak target hosts more than the target itself.
  │    → run Axis C (pattern-scoped) — even targets that scrub their own repos miss prefix patterns.
  └─ hits → record but do NOT stop. Each hit's repo becomes a Stage 4 (commit history) target.

Stage 3 (issues/PRs) returned hits?
  ├─ no → continue. Issues are noisy and many orgs have private issue trackers.
  └─ yes → for each high-signal issue, also walk the LINKED PR(s) and their commit history.

Stage 4 (commits) returned hits?
  ├─ each "remove credential" commit → read parent commit's diff for the secret pre-removal
  └─ for any repo with >100 stars or many contributors → clone shallow and history-grep with rg

Stage 5 (forks) — was upstream cleaned?
  ├─ no → still walk forks; forks accumulate work-in-progress branches
  └─ yes → forks are MORE valuable; upstream rotation does not propagate

Stage 6 (members) — got new handles?
  ├─ yes → recurse to Stage 6 with new handles; loop until no new handles surface
  └─ no → continue

Stages 7/8/9/10 — always run them. Wiki, Pages, Gists, Archived repos are independent indexes.

A negative result in any stage NEVER terminates the sweep. The sweep terminates only when ALL stages have been exercised against ALL anchors and no further anchors emerge.
```

## Patterns to Search (target-agnostic checklist)

Per anchor in `anchors.json`, verify each of the following has been searched:

- [ ] All `.env*` filenames (`.env`, `.env.local`, `.env.production`, `.env.staging`, `.env.dev`, `.env.test`, `.env.prod`)
- [ ] All major framework config files (`application.properties`, `application.yml`, `appsettings.json`, `web.config`, `settings.py`, `config.json`, `config.yaml`, `database.yml`, `secrets.yml`)
- [ ] Cloud credential files (`.aws/credentials`, `.aws/config`, `.s3cfg`, `.boto`, `service-account.json`, `gcp-key.json`, `azure.json`, credentials manifests)
- [ ] Container & orchestration manifests (`Dockerfile`, `docker-compose*.yml`, `kubeconfig`, `cluster.yaml`, `helm/values.yaml`, `Chart.yaml`, `kustomization.yaml`)
- [ ] IaC state (`terraform.tfvars`, `terraform.tfstate`, `Pulumi.yaml`, `Pulumi.*.yaml`, `cdk.json`)
- [ ] CI/CD configs (`Jenkinsfile`, `.gitlab-ci.yml`, `.travis.yml`, `.circleci/config.yml`, `.drone.yml`, `azure-pipelines.yml`, `bitbucket-pipelines.yml`, `cloudbuild.yaml`)
- [ ] Workflow files (`.github/workflows/*.yml`)
- [ ] API specs (`openapi.yaml`, `openapi.json`, `swagger.yaml`, `swagger.json`, `schema.graphql`, `asyncapi.yaml`)
- [ ] Per-language credential files (`.npmrc`, `.pypirc`, `.docker/config.json`, `.gitconfig`, `.netrc`)
- [ ] SSH/PGP/PEM (`id_rsa`, `*.pem`, `*.pfx`, `*.key`, `*.crt`)
- [ ] All cloud-credential prefixes from the table above
- [ ] All connection-string scheme prefixes from the list above
- [ ] All target-domain anchors as in-content searches
- [ ] All target email-pattern anchors
- [ ] All commit-message keywords (`remove key`, `rotate`, `oops`, `redacted`, etc.)
- [ ] All issue/PR keywords (`internal`, `production`, `redacted`, `traceback`, etc.)

Each box gets ticked only when the search has been run AGAINST EACH anchor in `anchors.json`.

## Pitfalls

- **Unauthenticated rate limit (60/hr)**: surface the `GITHUB_TOKEN` env var first; if missing, the sweep still proceeds but rate-pace each Axis. Pace and continue — the sweep resumes from the last unexecuted query.
- **Authenticated rate limit (5000/hr)**: batch via `gh api --paginate` and `per_page=100`; track remaining via the `X-RateLimit-Remaining` response header. When it drops below 100, cool down 60 seconds and resume.
- **Search index lag**: GitHub's code search has a multi-minute to multi-hour lag for newly-pushed code. Repeat the sweep across a sweep-window if the target is actively pushing.
- **False positives in test data**: fixture / test files often contain dummy credentials. Filter by examining file path: `tests/`, `__tests__/`, `fixtures/`, `examples/`, `sample/` are usually noise. Cross-reference with whether the value matches a real prefix vs a placeholder like `your-key-here`.
- **Abandoned forks under different ownership**: a fork's owner may not be a real developer of the target — note in metadata; do not tag the upstream owner.
- **Cached pages**: `cached.googleusercontent.com` and `webcache.googleusercontent.com` can hold deleted GitHub content; follow up with `recon_archive_intel` for the same repo.
- **Partial-match noise**: `org:target` matches the literal slug; if the target has multiple plausible slugs, run the sweep against EACH. Do not pick "the most likely".
- **Search cap of 1000 results**: GitHub search returns at most 1000 results per query. If a query saturates 1000, refine with additional operators (`size:`, date ranges, language) to slice the result set.
- **Code search requires repository visibility**: private repos a token can read are searchable; public-only sweeps miss them. Document whether the token has access and what slice was searched.
- **Org-renames**: orgs sometimes rename. Check `https://api.github.com/orgs/{old-slug}` for `301` and follow `Location` to the new slug.
- **Search-string escaping**: `gh search` and `gh api search/code -f q=` differ in URL escaping. Test each query with a known-positive (e.g., `org:torvalds`) before trusting empty results.

## Output Format

`recon/{target}/github_intel.json` — append-mode, one record per finding:

```json
{
  "type": "leaked_secret | hostname_leak | api_spec | iac_state | issue_disclosure | pr_disclosure | commit_disclosure | wiki_page | gist | fork_divergence",
  "source": "github",
  "stage": 2,
  "axis": "A",
  "source_url": "https://github.com/<org>/<repo>/blob/HEAD/.env.staging",
  "repo": "<org>/<repo>",
  "path": ".env.staging",
  "ref": "abc123def",
  "snippet": "DATABASE_URL=postgres://app:REDACTED@db-internal.target.example:5432/prod",
  "secret_pattern": "postgres connection string",
  "discovered_anchor": "target-internal.example",
  "confidence": "high | medium | low",
  "first_committed": "2024-04-12T08:31:00Z",
  "removed": false,
  "notes": "Hostname db-internal.target.example feeds recon_passive_subdomain"
}
```

Aggregate output `recon/{target}/anchors.json` (Stage 1) feeds the rest of the recon stack.

## Composes With

- **`recon_google_dorking`** — domain-anchor hits in GitHub feed Google `site:` queries; conversely, Google-found GitHub repos that don't appear in the org slug seed Stage 1 expansion.
- **`recon_yandex_dorking`** — same flow, on a different index. Yandex sometimes indexes GitHub Pages and gist content Google has dropped.
- **`recon_archive_intel`** — for repos that 404 today, fetch the archived snapshot through the archive skill; cross-reference removed-secret commits against archive page captures.
- **`recon_information_disclosure`** — every hostname found in a manifest gets resolved live and probed.
- **`recon_passive_subdomain`** — values files, kubeconfigs, terraform state contain raw internal hostnames; they go straight into the subdomain candidate pool.

## Termination Policy

The sweep terminates when ALL of the following are true, NOT when any of them returns "looks empty":

- Every org slug in `anchors.json/primary_orgs` has been searched against every entry in the Stage 2 axis-A query list
- Every entry in `anchors.json/domain_anchors` has been searched against the Stage 2 axis-B query list
- Every credential prefix in the Stage 2 axis-C table has been searched against every org slug
- Every entry in `anchors.json/known_handles` has had its personal repos and gists searched (Stage 6 / Stage 8)
- Stage 5 (forks) has been run against every repo that returned a Stage 2 hit
- Stage 4 (commit history) has been walked locally (`git log -S`) for every repo that returned a Stage 2 hit
- Stage 6 (member recursion) has stabilized — one full pass added zero new handles
- Stages 7, 8, 9, 10 have each had a full execution

A negative result in any single stage / axis / query is data, not a stop condition. Document every empty result (`{"query": "...", "result_count": 0}`) so the next pass knows what was already exhausted.
