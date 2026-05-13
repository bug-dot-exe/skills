---
name: github_dorking
category: reconnaissance
description: GitHub search for leaked credentials, API keys, internal URLs, config files, and secrets in public repos
depends_on: []
---

# GitHub Dorking

Search GitHub for secrets, credentials, internal URLs, and configuration files that developers accidentally committed to public repositories. A single leaked API key or `.env` file can unlock entire cloud environments.

## When to Use

- Target organization has public GitHub repositories
- Looking for leaked credentials, API keys, or tokens
- Searching for internal URLs, staging endpoints, or infrastructure details
- Discovering code that reveals business logic or security mechanisms
- Finding third-party service configurations with embedded secrets

## Methodology

### Phase 1: Organization Mapping

1. Find all GitHub accounts associated with the target (org accounts, employee accounts)
2. List all public repositories and recently active forks
3. Check organization members for personal repos mentioning the target
4. Look for archived repos that may contain old but valid secrets

### Phase 2: Secret Scanning

1. Search for common credential patterns across all repos
2. Check commit history (secrets removed from HEAD may still exist in old commits)
3. Look for `.env` files, config files, and deployment scripts
4. Search for hardcoded API keys, tokens, and passwords
5. Check CI/CD configuration files for leaked environment variables

### Phase 3: Infrastructure Discovery

1. Find internal URLs, IP addresses, and domain names
2. Look for cloud resource identifiers (ARNs, bucket names, project IDs)
3. Discover database connection strings and service endpoints
4. Find VPN configurations, SSH keys, or certificate files

### Phase 4: Code Intelligence

1. Analyze authentication and authorization implementation details
2. Find security-sensitive code patterns (crypto, auth, access control)
3. Look for TODO/FIXME/HACK comments near security-relevant code
4. Check for disabled security features or hardcoded bypasses

## Key Queries

Use GitHub's code search (github.com/search or `gh search code`):

```
# Organization-scoped searches
org:targetorg filename:.env
org:targetorg "API_KEY" OR "api_key" OR "apikey"
org:targetorg "password" OR "passwd" OR "pwd" NOT "placeholder"
org:targetorg "secret" OR "token" NOT "test" NOT "example"

# Credential patterns
org:targetorg "AKIA" (AWS access key prefix)
org:targetorg "sk-" OR "sk_live" OR "sk_test" (Stripe keys)
org:targetorg "xoxb-" OR "xoxp-" (Slack tokens)
org:targetorg "ghp_" OR "gho_" OR "ghs_" (GitHub tokens)
org:targetorg "SG." (SendGrid API key prefix)
org:targetorg "AIza" (Google API key prefix)

# Configuration files
org:targetorg filename:.env.production
org:targetorg filename:config.json "password"
org:targetorg filename:docker-compose.yml "password"
org:targetorg filename:application.properties "spring.datasource"
org:targetorg filename:.npmrc "_authToken"

# Infrastructure details
org:targetorg "s3.amazonaws.com" OR "s3://"
org:targetorg "rds.amazonaws.com"
org:targetorg "mongodb+srv://" OR "mongodb://"
org:targetorg "postgres://" OR "mysql://" OR "redis://"
org:targetorg filename:Dockerfile "ENV" "KEY"

# CI/CD secrets
org:targetorg filename:.github/workflows "secrets."
org:targetorg filename:.gitlab-ci.yml "variables"
org:targetorg filename:Jenkinsfile "credentials"
org:targetorg filename:.travis.yml "secure"

# Security-relevant code
org:targetorg "BEGIN RSA PRIVATE KEY"
org:targetorg "BEGIN OPENSSH PRIVATE KEY"
org:targetorg filename:id_rsa
org:targetorg "jwt.sign" OR "jwt.verify" "secret"
org:targetorg "disable_ssl" OR "verify=False" OR "NODE_TLS_REJECT_UNAUTHORIZED"

# Internal URLs and endpoints
org:targetorg "internal." OR "staging." OR "dev." "target.com"
org:targetorg "localhost" "target.com" NOT "example" NOT "test"
org:targetorg "vpn" OR "bastion" "target.com"

# Broad searches (use target domain name across all GitHub)
"target.com" filename:.env
"target.com" "password" OR "secret" OR "token" filename:.config
"@target.com" filename:.env (email domain in configs)
```

## Corpus-Derived Hunting Patterns

### GitHub Actions Workflow Auditing

For every public repo owned by the target that uses GitHub Actions:
1. `git clone --depth 1` and locate every `.yml`/`.yaml` under `.github/workflows/`
2. Search for `pull_request_target` triggers -- these run with write permissions on PR author's input
3. Trace every `${{ github.event.pull_request.* }}` interpolation into `run:` blocks (injection vector)
4. Check for self-hosted runner labels -- if a workflow with `pull_request_target` runs on self-hosted runners, it is an RCE vector
5. Search workflow run logs (publicly visible) for leaked secrets, runner metadata, and internal URLs

### Patch-Bypass and Security Advisory Mining

When a vendor publishes a security advisory:
1. Read the patch commit diff -- understand exactly what was fixed and what the fix boundaries are
2. Search for adjacent code paths that handle the same input differently
3. Test whether the fix can be bypassed via encoding, method swap, or parameter aliasing
4. Check if the fix was applied consistently across all entry points (often only the reported path is patched)
This approach has produced $225K+ payouts on mature platforms.

### Diff-Audit for New Commits

Monitor new PRs/commits to popular OSS libraries the target depends on:
1. Subscribe to release notifications for critical dependencies
2. When a security-adjacent commit lands, audit the diff for incomplete fixes
3. Apply consistency-principle testing: if the fix added validation in path A, check paths B/C/D for the same missing validation

### JWT and IdP Implementation Auditing

Search for JWT handling code in the target's repos:
```
org:targetorg "jwt.verify" OR "jwt.decode" OR "idToken" OR "firebase.auth"
```
Then audit:
1. Is the JWT verified server-side or only decoded client-side?
2. Can attackers mint tokens themselves (public sign-up, direct-to-IdP)?
3. Does the server check `iss`, `aud`, `exp` claims, or only decode the payload?
4. Are debug/development signing keys still in the production trust store?

### Shared-Component Vulnerability Mapping

When you find a vulnerability in a component (Code OSS, Lodash, Express, etc.) used by the target:
1. Grep all the target's repos for that component's import/usage
2. Map every embedder/consumer -- the vuln affects all of them
3. Test each consumer independently; they may have different configurations or mitigations

### Cross-Tenant Reference Testing in Quick-Actions

Modern apps have many `@mention`, `/command`, and autocomplete surfaces. Search the target's code for these patterns:
```
org:targetorg "mention" OR "autocomplete" OR "slash_command" OR "quick_action"
```
Test whether mention/autocomplete suggestions leak entities (users, repos, projects) from other tenants when the input is a partial match.

### Capability-Token URL Leakage

For any product with "sharable link" or "anyone with the link" semantics:
1. Map the URL structure: which segment is the capability token?
2. Search the target's code and public repos for URLs containing these tokens
3. Test whether the token leaks via `Referer` header when the page loads external resources
4. Check if the token appears in server logs, analytics, or error reporting

## What to Look For

**Immediate Wins**
- AWS access keys (`AKIA...`) with corresponding secret keys
- Private keys (RSA, SSH, PEM) for servers or services
- Database connection strings with embedded credentials
- OAuth client secrets paired with client IDs
- API keys for payment processors (Stripe, PayPal)

**Infrastructure Intel**
- Internal hostnames and IP ranges
- Cloud resource names (S3 buckets, GCP projects, Azure subscriptions)
- VPN/bastion server addresses
- Service mesh or microservice topology from docker-compose or k8s configs

**Code Intelligence**
- Authentication bypass patterns or hardcoded admin credentials
- Security features disabled via environment flags
- Known vulnerability patterns in dependencies
- Comments revealing security concerns (`// TODO: fix auth`, `// HACK: skip validation`)

## Searching Commit History

Secrets removed from current code may persist in git history:

```bash
# Clone the repo and search all commits
git log --all --full-history -p -- "*.env" "*.config"
git log --all -p -S "API_KEY" --source --all
git log --all -p -S "password" --source --all

# Using truffleHog or gitleaks for automated scanning
gitleaks detect --source=./repo --report-path=leaks.json
trufflehog git https://github.com/targetorg/repo --only-verified
```

## Validation

1. Never use discovered credentials against production systems without authorization
2. Check if found API keys are still active by testing against non-destructive endpoints
3. Verify the repository is actually associated with the target (not a fork or unrelated project)
4. Check commit timestamps; old secrets may have been rotated
5. Report found secrets to the program even if you cannot verify they are active

## Tips

1. Search employee personal accounts, not just the organization account
2. Check GitHub Gists for the organization's developers
3. Forked repositories may contain changes with secrets not in the upstream
4. Use time-range filters to find recently committed secrets
5. Archived and deleted repos may still be cached in search indexes
6. Pair GitHub dorking with Google dorking: `site:github.com "target.com" password`
7. Any Base64 token that decodes to a delimiter-separated string is parser-attackable -- test boundary shifting between fields
8. When you find a hardcoded hash in production code, search the public web for its preimage -- debug signing keys with known hashes are often exploitable
