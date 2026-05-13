---
name: gitlab_bitbucket_dorking
category: reconnaissance
description: Search GitLab (gitlab.com + self-hosted) and Bitbucket for leaked credentials, internal repos, and code that github_dorking misses
depends_on: []
---

# GitLab / Bitbucket Dorking

`github_dorking` covers GitHub. Plenty of organizations use GitLab or Bitbucket instead — or in addition. Self-hosted GitLab instances (`gitlab.target.com`) are particularly high-signal because developers assume internal hosting means private, and then forget to double-check repo visibility.

This skill is a direct analog to `github_dorking.md` for non-GitHub code hosts.

## When to Use

- Target uses GitLab (`gitlab.com/<org>`) or self-hosted GitLab
- Target uses Bitbucket (common for enterprise and Atlassian-centric orgs)
- `github_dorking` came up empty — the org may just use a different forge
- Looking for self-hosted forge instances (huge attack surface if exposed)

## Methodology

### Phase 1: Forge Discovery

Find every code-hosting surface the target has:

1. Check gitlab.com for the org: `gitlab.com/target-org`
2. Check bitbucket.org for the org: `bitbucket.org/target-org`
3. Check sourcehut: `sr.ht/~target-user` (less common but happens)
4. Check Gitea / Gitlab self-hosted on predictable subdomains:
   - `gitlab.target.com`, `git.target.com`, `code.target.com`, `src.target.com`
   - `bitbucket.target.com`, `stash.target.com` (Atlassian legacy)
   - `gitea.target.com`, `gogs.target.com`
5. Check reverse-WHOIS on SSL cert: a cert for `gitlab.target.com` issued means it exists

### Phase 2: Public Repo / Snippet Enumeration

For each forge found:

1. List all public projects / repositories in the org
2. List all public snippets (GitLab's equivalent of gists)
3. Check member profiles for personal repos mentioning the target
4. Check forks — often contain changes with secrets not in upstream

### Phase 3: Secret Scanning

Same playbook as `github_dorking` but with forge-specific search syntax.

### Phase 4: Self-Hosted Forge Probing

Self-hosted instances often leak differently than cloud versions:

1. Check for default-enabled public registration (account spam risk)
2. Check for exposed `.git/config` on web servers
3. Check for GitLab "Snippets" feature — often public by default
4. Check for exposed CI/CD runner registration tokens in job logs
5. Check version disclosure (`/help`, `/api/v4/version`) for known CVEs

## Key Queries

### GitLab (`gitlab.com`)

GitLab has a proper full-text search API. Unlike GitHub, it respects scope and returns better results for negative searches.

```
# via web UI (gitlab.com/search)
groups: target-org
projects: target
snippets: target.com

# GitLab API — blob search (code content)
curl -s "https://gitlab.com/api/v4/search?scope=blobs&search=target.com+AKIA" \
  -H "PRIVATE-TOKEN: <your_token>"

# Search specific project
curl -s "https://gitlab.com/api/v4/projects/<project_id>/search?scope=blobs&search=API_KEY"

# Search for snippets (GitLab's gists)
curl -s "https://gitlab.com/api/v4/snippets?search=target.com"

# CI job logs (often leak secrets)
curl -s "https://gitlab.com/api/v4/projects/<pid>/jobs" \
  | jq '.[] | select(.status=="success")'

# Group-wide search
curl -s "https://gitlab.com/api/v4/groups/<group_id>/search?scope=blobs&search=password"
```

### GitLab self-hosted (`gitlab.target.com`)

Many self-hosted instances allow unauthenticated search on public projects. If registration is open, create an account to unlock authenticated search.

```bash
# Check if public search is available
curl -s "https://gitlab.target.com/search?search=password"

# Version disclosure (vulnerability targeting)
curl -s "https://gitlab.target.com/help" | grep -i "version"
curl -s "https://gitlab.target.com/api/v4/version" -H "PRIVATE-TOKEN: <token>"

# Check if default-open registration (bug in itself)
curl -s "https://gitlab.target.com/users/sign_up"

# Exposed .git directory (standard web misconfig)
curl -s "https://gitlab.target.com/.git/config"
```

### Bitbucket (`bitbucket.org`)

Bitbucket's search is weaker than GitLab's, and code search is rate-limited.

```
# Web UI
https://bitbucket.org/repo/target-org/
https://bitbucket.org/snippets/target-org/

# API (OAuth required for authenticated; public searches work without)
curl -s "https://api.bitbucket.org/2.0/repositories/target-org"

# Snippet search
curl -s "https://api.bitbucket.org/2.0/snippets?role=owner&q=target"

# Code search (requires auth + Bitbucket Cloud, not all tiers)
curl -s "https://api.bitbucket.org/2.0/workspaces/target-org/search/code?search_query=API_KEY"
```

### Bitbucket self-hosted (Bitbucket Server / Atlassian Stash)

```bash
# Common subdomain patterns
stash.target.com
bitbucket.target.com

# Version / config leak
curl -s "https://stash.target.com/atlassian-admin/config"
curl -s "https://stash.target.com/rest/api/1.0/projects"  # open if anonymous-read is on
```

### Gitea / Gogs (lightweight self-hosted)

Often used by small teams or devops groups:

```bash
# Common subdomains
gitea.target.com, gogs.target.com, git.target.com

# API (many instances have unauthenticated API access)
curl -s "https://gitea.target.com/api/v1/repos/search?q=target"
curl -s "https://gitea.target.com/api/v1/users/search?q=target"

# Expose-all misconfig
curl -s "https://gitea.target.com/explore/repos"
```

### Cross-forge Google dorking

```
site:gitlab.com "target.com"
site:gitlab.com "target.com" "password"
site:gitlab.com inurl:"target-org"

site:bitbucket.org "target.com"
site:bitbucket.org "target.com" filename:.env

site:gitlab.target.com                  # self-hosted (if indexed)
site:stash.target.com                   # self-hosted
```

## What to Look For

**Same as github_dorking.md** (credentials, API keys, internal URLs, infrastructure intel), plus these forge-specific items:

**GitLab-specific**
- Public snippets containing quick-paste credentials (very common)
- CI/CD job logs with leaked env vars (`CI_JOB_TOKEN` being echoed, etc.)
- Runner registration tokens in admin pages or job logs
- Wiki pages with architecture details (GitLab has Wikis per-project)

**Bitbucket-specific**
- Self-hosted Atlassian Stash instances (often older, unpatched)
- Bitbucket Pipelines config files (`bitbucket-pipelines.yml`) with secrets
- Linked Jira tickets referencing the same code (pivot to Jira intel)

**Self-hosted forge-specific**
- Public registration enabled (often by mistake — spam / phishing vector)
- Web-facing admin panel (`/admin`) with default credentials
- Default SSH keys for initial-setup accounts
- Exposed `.git/config` at web root (classic web misconfig)
- API-token-only endpoints that respond to anonymous requests
- Known CVEs for the forge version (GitLab has a long history of RCE CVEs)

## Validation

1. Verify the forge is actually owned by the target (cert chain, `whois`, Company legal pages)
2. Self-hosted forges may belong to employees' personal projects — check before reporting
3. For credential findings, test only against non-destructive endpoints
4. Fresh findings trump stale — check `last_activity_at` fields

## Corpus-Derived Hunting Patterns

Techniques from disclosed reports ($3M+ combined bounties) where CI/CD and forge-level findings were the primary vector.

### GitHub Actions Pwn-Request Audit

This is now a canonical bug class with $1M+ individual payouts. For every public repo with GitHub Actions:

1. `git clone --depth 1` the repo and search `.github/workflows/` for these dangerous patterns:
   - `pull_request_target` trigger + `actions/checkout` of the PR head (allows attacker-controlled code to run with write permissions)
   - `issue_comment` trigger that passes comment body to a shell command
   - Self-hosted runners on public repos (attacker PR gets shell access to the runner environment)
2. For each workflow file, trace every use of `${{ github.event.* }}` — if any flows into `run:` blocks without sanitization, it is command injection
3. Check run logs (`gato` tool, or manual API calls) for leaked `GITHUB_TOKEN` values and their actual permission set (`issue: write`, `id-token: write` are escalation paths)

```
# Search patterns across target's GitHub org
inurl:.github/workflows "self-hosted" org:target-org
inurl:.github/workflows "pull_request_target" org:target-org
inurl:.github/workflows "issue_comment" org:target-org
```

### Deployment Artifact Audit in OSS Repos

Web apps' security posture depends on reverse-proxy/WAF/ingress configs as much as code:

1. Search for Nginx, Apache, HAProxy, Traefik, or Caddy configs committed to repos: `filename:nginx.conf`, `filename:.htaccess`, `filename:Caddyfile`
2. Check for `alias` directives in Nginx (off-by-slash path traversal: `location /assets { alias /app/public/; }` — request `/assets../etc/passwd`)
3. Look for Terraform/CloudFormation/Helm templates that expose the infrastructure graph

### Argument Injection via Filenames

For any feature that builds shell commands from user-controlled paths/filenames/refs:

1. Search for git-related CLI invocations: `git archive`, `git diff`, `git log`, `git checkout` where a branch/tag/path argument comes from user input
2. Test if filenames starting with `--` are interpreted as flags (e.g., `--output=/tmp/evil`)
3. Once you find one argument injection, enumerate EVERY API endpoint that touches the same subsystem — the same class typically affects multiple paths

### Cross-Tenant Reference Leaks

Modern platforms have @mention, /command, and quick-action surfaces:

1. For every "mention" or "reference" feature, test whether typing a cross-project or cross-org reference leaks metadata (title, description, status) from private resources
2. Check if slash commands in issues/MRs can reference objects outside the current project's permission boundary
3. Test JSON serialization of project/group objects — custom serializers sometimes include fields (runner tokens, deploy keys) that the API shouldn't expose

### Image/Media Transcoder Memory Disclosure

For any target that processes uploaded images (resize, transcode, thumbnail):

1. Submit a malformed GIF/PNG with truncated dimensions or corrupted headers
2. Compare the output image's byte size with expected size — extra bytes may be uninitialized server memory
3. The asymmetry between decoder (lenient) and encoder (strict) often causes the encoder to read past buffer boundaries

## Tips

1. Self-hosted GitLab / Bitbucket / Gitea are JACKPOTS — most targets forget they're public
2. GitLab snippets are like GitHub gists but less-searched — high FP-to-signal ratio
3. Bitbucket requires patience — API is rate-limited hard; use web UI for small queries
4. Check `.gitlab-ci.yml` files for secret references — even if the secret value isn't in git, the secret NAME is, which reveals what creds exist
5. For CI job logs: GitLab often keeps them for 30 days; fresh commits → fresh logs → fresh leaks
6. For self-hosted instances, always check the version against `gitlab.com/advisory` (or equivalent) — RCE CVEs are common
7. Complement with `github_dorking.md` — some orgs mirror repos across forges
8. Look for `.gitattributes` files — sometimes reveal private submodule URLs
