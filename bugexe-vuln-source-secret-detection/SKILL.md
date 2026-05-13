---
name: source_secret_detection
description: Source-tree secret-detection sweep — gitleaks + trufflehog + entropy heuristics + known-placeholder phrases over source AND config files
depends_on: [public_credential_disclosure]
---

# Source-Tree Secret Detection

When source code or local config files are accessible, hardcoded secrets are the highest-value, lowest-effort source-only finding class. This skill operationalizes a layered sweep across every credential shape that survives in source trees.

## When to Use

- Any target with repository or local-code access (whitebox / hybrid scans)
- After the workspace is cloned or mounted
- Before deep manual review — the sweep produces the candidate list that drives the rest of the source audit

## Detection Layers (Run All)

A single tool will not catch every secret. Run every layer; the union is the candidate list.

### 1. gitleaks (HEAD + commit history)

```bash
gitleaks detect --source . --report-format json --report-path /tmp/gitleaks.json
```

Covers HEAD plus the entire commit history. Catches secrets that were committed and later removed (still extractable from `git log`).

### 2. trufflehog (entropy + verifiers)

```bash
trufflehog filesystem --no-update --json --no-verification . > /tmp/trufflehog.json
```

Entropy-based detection plus vendor-specific verifiers. Pair with gitleaks — they find different things.

### 3. Manual entropy regex over source + config files

```bash
grep -rEn "(secret|password|token|api[_-]?key|jwt[_-]?secret|client[_-]?secret|private[_-]?key)\s*[:=]\s*[\"'][^\"']+[\"']" \
  --include='*.py' --include='*.js' --include='*.ts' --include='*.tsx' --include='*.jsx' \
  --include='*.go' --include='*.rs' --include='*.java' --include='*.rb' --include='*.php' \
  --include='*.env' --include='*.env.*' --include='*.yaml' --include='*.yml' --include='*.toml' \
  --include='*.json' --include='*.tf' --include='*.cfg' --include='*.ini' --include='*.properties' .
```

### 4. Known-placeholder phrase scan

Many production deployments forget to replace placeholder values. Treat each match as a candidate even when the value LOOKS placeholder — a `change-me` literal IN production code paths is a finding because it shows the deploy step was skipped.

```bash
grep -rEn "change-?me|change-?this|your-?secret|your-?key|replace-?me|TODO replace|secretkey123|password123|admin123|test1234" .
```

### 5. Vendor key regexes (universal)

For vendor-format keys, reuse the universal patterns from `public_credential_disclosure.md`:

| Vendor | Pattern |
|---|---|
| AWS | `AKIA[0-9A-Z]{16}` |
| AWS temp | `ASIA[0-9A-Z]{16}` |
| GitHub PAT | `ghp_[A-Za-z0-9]{36}` |
| GitHub app | `ghs_[A-Za-z0-9]{36}` |
| GitHub OAuth | `gho_[A-Za-z0-9]{36}` |
| OpenAI | `sk-[A-Za-z0-9]{32,}` or `sk-proj-[A-Za-z0-9_-]{80,}` |
| Anthropic | `sk-ant-[A-Za-z0-9-]{80,}` |
| Slack | `xox[baprs]-[A-Za-z0-9-]{10,}` |
| Stripe live | `sk_live_[A-Za-z0-9]{24,}` |
| Stripe test | `sk_test_[A-Za-z0-9]{24,}` |
| GitLab PAT | `glpat-[A-Za-z0-9_-]{20}` |
| Google API | `AIza[A-Za-z0-9_-]{35}` |
| Mailgun | `key-[a-f0-9]{32}` |
| SendGrid | `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}` |
| Twilio | `AC[a-f0-9]{32}` |
| JWT | `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}` |
| Private key | `-----BEGIN (RSA\|DSA\|EC\|OPENSSH\|PGP) PRIVATE KEY-----` |
| Connection string | `[a-z]+://[^:]+:[^@]+@[^/]+` |

## File-Types in Scope

- **Source**: `.py .js .jsx .ts .tsx .svelte .vue .go .rs .java .rb .php .c .cpp .cs .swift .kt .sol .move`
- **Config**: `.env .env.* .yaml .yml .toml .json .tf .cfg .ini .properties`
- **Filename-based**: `Dockerfile`, `docker-compose.yml`, `docker-compose.yaml`

## Validation Procedure

For each candidate string the sweep produces:

1. **Confirm runtime read** — is the variable actually used at runtime, or only mentioned in a comment / docstring? Grep the codebase for assignments to confirm a runtime read path.
2. **Trace the use** — where does the value flow? Token signing, encryption key, auth header, third-party API call. Record the sink.
3. **Confirm production persistence** — would this literal value persist in a production build? If the code reads `os.environ.get("KEY", "literal_default")`, the literal is the production fallback — confirm the production env actually overrides.
4. **Demonstrate impact** — forge a JWT with the leaked secret, decrypt a stored session, query the third-party API. The finding is severity-graded by impact: token forge for any user → CRITICAL; vendor-API quota theft → MEDIUM-HIGH; demo-only key → LOW or INFO.

## False-Positive Rules

- **Test / mock / fixture files** (`tests/`, `__tests__/`, `spec/`, `mocks/`, `fixtures/`) are LOWER priority unless the test file is a fixture loaded in production paths (some frameworks load `seed.py` at boot).
- **`.env.example`-style files** with `change-me` / `your-key` placeholders ARE findings if the project's deploy process is unclear — the placeholder shows intent, and many production envs have been observed to ship with the placeholder still in place. Severity here is INFO/LOW unless you can confirm production carries the same literal.
- **Vendor demo / library-shipped keys** (the SDK's own demo key shipped with the library) are NOT findings — they're public examples, intentional.
- **Commit-history-only secrets** that have been rotated and are confirmed inert are NOT findings (no live impact). Confirm rotation by trying the leaked value against the live system.

## Anti-Patterns

- Do NOT report a secret without validation — high-entropy strings are sometimes hashes, fingerprints, or random opaque IDs that have no auth value.
- Do NOT report a `.env.example` finding without checking the live `.env` (or live behavior) — the example file is the design intent, not necessarily the deployed reality.
- Do NOT batch-report 100 entropy hits without ranking — the agent's reporting cap is small. Rank by sink-impact (token forge > vendor key > internal hash) and report the top distinct ones.
- Do NOT treat a missing `.env` as "no secret risk" — the secret might be hardcoded directly into a `config.py` / `settings.json` / `application.yml`. The `.env` absence redirects you to the alternative location, not to a clean bill.

## Reporting

For each confirmed secret:
- **Title**: short, action-oriented ("Hardcoded JWT signing key in {file}")
- **Location**: `file:line` of the literal AND the sink it reaches
- **Impact**: concrete demonstrated effect (token forge, account takeover, vendor billing theft)
- **PoC**: one-line proof — forged token decoded, vendor API call result, etc.
- **Fix**: rotate the key + move to env-variable-injected configuration

## Defense-Bypass Pairs

| Defense | Bypass Technique | Real Example |
|---|---|---|
| `.gitignore` excludes `.env` | `.env.production`, `.env.local`, `.env.backup` not in gitignore; or `.env` committed before gitignore rule added | Common: git history retains pre-gitignore commits |
| ProGuard / code obfuscation | `strings` on native binary; `apktool` + `jadx` on APK; `unzip` on IPA; obfuscation protects code logic, not string literals | Shopify Sello deploy key in Podfile, $1.5K |
| Secrets in CI environment variables (not code) | CI logs print env on failure; `actions/checkout` persists GITHUB_TOKEN in `.git/config`; build scripts echo vars for debugging | Google AlloyDB pwn-request, $10K |
| SDK marks credentials as "internal" | `JSON.stringify()` walks all enumerable properties regardless of naming convention; `console.log(error)` includes full object tree | Firebase/Firestore private key leak, $50K |
| Webpack DefinePlugin replaces env vars at build | `NEXT_PUBLIC_`, `REACT_APP_`, `VITE_` prefixed vars are INTENTIONALLY included in client bundles; devs put secrets in these | Recurring: API keys in JS bundles |
| Secret rotation after exposure | Same credential reused across multiple services; rotation on primary service leaves secondary exposed | Common: AWS key in prod rotated but staging unchanged |
| Git-secrets / pre-commit hooks | Hooks only run on new commits; existing history retains secrets; `git log -p --all -S 'AKIA'` bypasses hooks entirely | Common: pre-hook installed after initial commit |
| Server-side rendering hides API calls | SSR props leak in `__NEXT_DATA__` JSON embedded in HTML; hydration data includes server-only values | Recurring: Next.js/Nuxt server props with API keys |
| Docker multi-stage build removes secrets | `docker history --no-trunc` reveals build args from intermediate layers; secrets in early stages persist in image metadata | Recurring: `ARG DB_PASSWORD` visible in layer history |
| Vault/KMS integration for production | Development fallback defaults hardcoded in source: `os.environ.get("KEY", "actual_dev_key")`; dev key works against staging/dev | Recurring: fallback defaults in config.py |

## Chain Patterns

| Base Finding | Chain With | Combined Impact | Real Example |
|---|---|---|---|
| Hardcoded JWT signing secret in source | Token forgery (any user, any role) | Full ATO for all users; admin impersonation; data exfiltration | Recurring: Django `SECRET_KEY`, Express `JWT_SECRET` |
| GitHub deploy token in Podfile/Cartfile | Private repository access | Clone all private repos; extract further secrets from source; pivot to infrastructure | Shopify Sello, $1.5K |
| Django `SECRET_KEY` in source | `signed_cookies` session backend + `PickleSerializer` | Forge session cookie with pickle RCE payload; full server compromise | Facebook Sentry, $5K |
| AWS `AKIA` key in committed source | IAM privilege enumeration | S3 bucket access, EC2 control, potential lateral to production; supply-chain via CodeBuild | Recurring: six-figure class on major programs |
| Firebase config in JS bundle | Misconfigured Firestore/Storage rules | Full database read/write; user data exfiltration; file storage manipulation | Recurring: `/.json` endpoint returns full DB |
| Hardcoded SMTP credentials | Email spoofing from legitimate domain | Phishing from real company domain; password-reset email interception | Recurring: SES/SendGrid/Mailgun credentials |
| CI service-account key in build log | Cross-project IAM (shared identity) | Single token accesses multiple cloud projects; GKE clusters, GCS secrets buckets, Cloud Build | Google magic-modules, $3.1M |
| Database connection string in `.env.backup` | Direct external DB access | Full read/write on production database; PII exfiltration; privilege escalation via DB FILE perms | DoD database.php.orig, $500 |

## Pro Tips

1. Run `JSON.stringify(client)` on any initialized SDK client object. If the credential appears in output, every error log and crash report leaks it. 30-second test for a $50K-class bug.
2. `git log -p --all -S 'password'` finds secrets added then removed — gitleaks catches most, but manual `git log -S` with targeted keywords catches custom patterns tools miss.
3. For mobile bundles: `strings -a BinaryName | grep -iE 'AKIA|secret|token|password|api[_-]?key|Bearer|https?://[^:]+:[^@]+@'` is the single most productive one-liner.
4. Treat `os.environ.get("KEY", "literal_default")` as a finding — the literal is the production fallback. Confirm whether production env actually overrides it.
5. `node_modules/` sometimes ships to production (Docker images, serverless deploys). Scan it: third-party packages occasionally contain test credentials that work against shared staging services.
6. Check `.npmrc`, `.pypirc`, `.gem/credentials`, `~/.docker/config.json` patterns in source — package registry auth tokens grant publish access.
7. Webpack/Vite bundles: search for `process.env` references in the bundle output. Build tools replace these at compile time, so the literal value is in the JS even if the env var is "server-side only."
8. For any Airflow/Prefect/Dagster deployment: explore task lifecycle states (failed + depends_on_past) to find windows where secret masking hasn't run yet.
9. Always check CI workflow files (`.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`) for `echo $SECRET`, `env` dumps, and `cat .git/config` patterns that leak credentials to build logs.
10. SDK version matters: check if the target's SDK version predates the fix for credential serialization. Firebase Firestore fixed in PR #1742; older pinned versions still leak.

## Composability

This skill composes with:
- `public_credential_disclosure` — same regex catalogue, different surface (HTML response bodies vs source trees)
- `authentication_jwt` — JWT-secret hits chain into token-forge findings
- `business_logic` + `invariant_extraction` — leaked database/API keys often unlock data layers that violate accounting invariants
- `source_aware_sast` — gitleaks/trufflehog runs alongside semgrep/ast-grep for full-source coverage
