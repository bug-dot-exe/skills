---
name: public-credential-disclosure
description: Scan public HTML bodies, landing pages, inline JS, meta files, and error responses for plaintext credentials, API keys, and hardcoded tokens
depends_on: []
---

# Public Credential Disclosure

Targets often leak credentials in plain sight: the landing page's HTML, inline `<script>` blocks, documentation, `.env.sample` pages, demo-user lists, git metadata, backup archives. These are trivially discoverable (GET + grep) and map to Critical findings because the credential authenticates to the same target.

## Scope

Any public-accessible response body that a user WITHOUT credentials can fetch:
- `/` (landing/home page)
- `/login`, `/register`, `/help`, `/docs`, `/about`, `/contact`
- `/admin` (often shown to unauthed users with login form)
- `/vulns`, `/demo`, `/test`, `/staging` (staging markers)
- `/api/docs`, `/swagger`, `/openapi.json`, `/redoc`, `/api-docs`
- `/.well-known/*`, `/security.txt`
- `/robots.txt`, `/sitemap.xml`, `/humans.txt`
- `/.git/config`, `/.env`, `/.env.*`, `/.npmrc`, `/.dockerignore`
- `/package.json`, `/composer.json`, `/Gemfile.lock`
- `/backup.zip`, `/dump.sql`, `/db.sqlite`, `/app.tar.gz`
- JS bundles (may contain hardcoded fetch URLs with auth tokens)
- CSS source maps (may leak absolute paths)
- Error responses (may embed stack traces with connection strings)

## Detection Patterns

For each fetched body, scan for credential-shape patterns:

### Named-credential shapes

| Pattern | Example match |
|---|---|
| `\b(password)\s*[:=]\s*['"]?([^'"\s,}]+)` | `password: "P@ssw0rd!"`, `PASSWORD=changeme123` |
| `\b(token)\s*[:=]\s*['"]?([^'"\s,}]+)` | `token: "abc123"` |
| `\b(secret)\s*[:=]\s*['"]?([^'"\s,}]+)` | `secret: "changeme"` |
| `\b(api[_-]?key)\s*[:=]\s*['"]?([^'"\s,}]+)` | `api_key: "..."`, `ApiKey="..."` |
| `\b(access[_-]?token)\s*[:=]\s*['"]?([^'"\s,}]+)` | `access_token: "..."` |
| `\b(authorization)\s*[:=]\s*['"]?bearer\s+([^'"\s,}]+)` | `Authorization: Bearer abc` |

### Vendor API-key formats (universal, non-target-specific)

| Vendor | Pattern | Example prefix |
|---|---|---|
| AWS | `AKIA[0-9A-Z]{16}` | `AKIA...` |
| AWS temp | `ASIA[0-9A-Z]{16}` | `ASIA...` |
| AWS secret | `[A-Za-z0-9/+=]{40}` (contextual) | (after `aws_secret`) |
| GitHub PAT | `ghp_[A-Za-z0-9]{36}` | `ghp_...` |
| GitHub app | `ghs_[A-Za-z0-9]{36}` | `ghs_...` |
| GitHub OAuth | `gho_[A-Za-z0-9]{36}` | `gho_...` |
| OpenAI | `sk-[A-Za-z0-9]{32,}` or `sk-proj-[A-Za-z0-9_-]{80,}` | `sk-...`, `sk-proj-...` |
| Anthropic | `sk-ant-[A-Za-z0-9-]{80,}` | `sk-ant-...` |
| Slack | `xox[baprs]-[A-Za-z0-9-]{10,}` | `xoxb-...`, `xoxp-...` |
| Stripe live | `sk_live_[A-Za-z0-9]{24,}` | `sk_live_...` |
| Stripe test | `sk_test_[A-Za-z0-9]{24,}` | `sk_test_...` |
| GitLab PAT | `glpat-[A-Za-z0-9_-]{20}` | `glpat-...` |
| Google API | `AIza[A-Za-z0-9_-]{35}` | `AIza...` |
| Mailgun | `key-[a-f0-9]{32}` | `key-...` |
| SendGrid | `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}` | `SG.xxx.yyy` |
| Twilio | `AC[a-f0-9]{32}` | `AC...` |
| PagerDuty | `[a-zA-Z0-9+/]{20,24}` (contextual with `pd_api_key`) | (contextual) |
| JWT | `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}` | `eyJ...` |
| Private key | `-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----` | (header) |
| Connection string | `[a-z]+://[^:]+:[^@]+@[^/]+` | `postgres://user:pass@host` |

### Demo-credentials-in-plain-text

Many apps proudly display:
```
Demo accounts:
  regular_user / <some-password>
  privileged_user / <another-password>
```
on their landing page. Look for the pattern — two or more username/password pairs with the text "demo", "test", "try", "sample", "default", "example" nearby. If the credentials actually authenticate, they're PRODUCTION credentials, not demo. File as Critical.

Look for these strings in body: `demo`, `test account`, `default credentials`, `try it out`, `sample login`.

### Environment sample blocks

```
DATABASE_URL=postgres://produser:realpass@db.example.com:5432/prod
JWT_SECRET=actualsecretinuse
AWS_ACCESS_KEY_ID=AKIA...
```

`.env.example` is supposed to show SHAPE, not VALUES. If the values are realistic (not `YOUR_KEY_HERE`, not `CHANGEME`), they're live.

## Test Protocol

1. Fetch root path + every page discoverable in 3 levels of crawl.
2. Fetch every metadata file listed in "Scope" above.
3. For each body, grep for the named-credential shapes + vendor API-key regexes.
4. For each match:
   - Validate: does the credential actually authenticate?
     - JWT → decode header/payload, try it as `Authorization: Bearer`
     - AWS key → `aws sts get-caller-identity` (if authorized)
     - API key → one test call with the vendor's official docs endpoint
     - Username/password → `POST /api/login` with the pair
   - If it works → Critical finding (auth succeeds with publicly-available credential)
   - If it doesn't → still file as Information Disclosure (the KEY existing tells an attacker "this endpoint uses this shape")
5. Check JS bundles specifically — these are the most common leak path. Use `grep -oE '(ghp_|sk-|AKIA|eyJ)[a-zA-Z0-9_-]+' main.js`.

## Reporting

- **Title pattern**: `Public <credential-type> Disclosure on <path>`
- **Severity**:
  - Critical: credential authenticates to THIS target with admin or data access
  - High: credential is for a real vendor service (AWS, Stripe, OpenAI) but access level is limited
  - Medium: credential-shaped but doesn't work (information disclosure)
- **PoC**: one curl to fetch the page + one validation showing the credential works.

## Discovery Signals

| Signal | Where to Find | Why Valuable |
|---|---|---|
| `DEBUG=True` stacktrace with env vars | Error pages, `/password-reset` crash, 500 responses | Django/Sentry snip-list misses third-party keys (`SENTRY_OPTIONS["system.secret-key"]`); mine every line for crypto material ($5K-$50K class) |
| CI/CD build log with access token | GitHub Actions logs, GitLab CI artifacts, Jenkins console | PR-triggered builds leak service-account creds scoped to multiple internal projects ($3.1M Google payout) |
| `JSON.stringify()` of SDK client object | Error logs, Sentry crash reports, structured logging sinks | Firebase/GCP SDK stored private key on enumerable property; any log of a Firestore object leaks the SA key ($50K) |
| `Podfile`/`Cartfile` with `https://user:token@github.com` | iOS IPA extraction, Android APK `assets/` | Dependency manifests ship deploy tokens that access all private repos ($1.5K-$25K) |
| `access_token=` in binary strings | `strings Messenger.app/Contents/MacOS/*`, APK decompilation | Employee test tokens left in shipped binaries; validate via provider debug tool ($500+) |
| `database.php.orig` / `.bak` / `.swp` served as plaintext | Backup-extension fuzzing on every `.php`/`.jsp`/`.asp` URL | Apache serves `.orig` as static text bypassing PHP interpreter; contains DB creds |
| GitHub Actions `pull_request_target` + checkout of PR head | `.github/workflows/*.yml` in public OSS repos | "pwn-request" pattern: attacker PR code runs with base repo secrets; auto-label bots bypass label gates ($10K) |
| `__NEXT_DATA__` / inline `<script>` with config objects | Page source, SSR props, hydration data | Server-side props leak API keys, internal URLs, feature flags in every page load |
| Cortex / Prometheus / Grafana default page on subdomain | Subdomain enumeration + fingerprinting default landing pages | `/config` dumps full config; `/debug/pprof/cmdline` reveals command-line secrets ($6.3K) |
| `Authorization: Bearer` in Swagger/OpenAPI `Try It Out` | `/swagger`, `/api-docs`, `/redoc` with pre-filled auth | Docs ship with a real token in the example; devs forget to rotate |
| Airflow rendered template showing unmasked secrets | `/admin/taskinstance/rendered` in transitional task states | Masking layer skipped when task is `depends_on_past` + prior run failed ($480) |
| `gs://` / `s3://` bucket URL with inline credentials | Config files, CI scripts, IaC templates | Connection strings with embedded access keys to cloud storage |

## Credential Source Matrix

| Source | What's Exposed | How to Find | Impact |
|---|---|---|---|
| CI/CD build environment | Service-account tokens, GITHUB_TOKEN, deploy keys | Fork + PR to public OSS repo; read build logs or exfil via webhook | Multi-project IAM, supply-chain backdoor |
| SDK object serialization | Private keys on enumerable properties | `JSON.stringify(client)` on any initialized SDK client; grep logs | Full service-account impersonation |
| Mobile app bundle | Deploy tokens, API keys, third-party secrets | `unzip .ipa`; `apktool d .apk`; `strings` on binaries | Private repo access, analytics hijack |
| Debug/error page | Django `SECRET_KEY`, Sentry `system.secret-key`, DB creds | Trigger errors on `/password-reset`, malformed input, 500 handlers | Cookie forgery, RCE via pickle, DB access |
| Infrastructure default pages | Cortex config, pprof cmdline, Prometheus targets | Subdomain enum + hit `/config`, `/debug/pprof/cmdline?debug=1` | Internal service topology, metric injection |
| Backup file extensions | DB passwords, JWT secrets, connection strings | Fuzz `.bak`, `.orig`, `.swp`, `.old`, `~` on config filenames | Direct DB access |
| JS bundles / source maps | API keys, internal endpoints, feature flags | Grep for `sk-`, `ghp_`, `AKIA`, `eyJ` prefixes in `main.*.js` | Vendor account access, internal API abuse |
| `.env` / `.env.production` | Full credential set in key=value format | Direct path fetch; Nginx/Apache misconfig serves it raw | Everything: DB, cloud, third-party, JWT secret |
| Git history (removed secrets) | Rotated credentials that may not actually be rotated | `gitleaks detect --source .`; `git log -p --all -S 'AKIA'` | Credential reuse across services |
| Workflow/orchestration UIs | Connection passwords, API tokens in rendered templates | Explore Airflow/Prefect/Dagster task lifecycle states | Lateral movement via shared connections |
| GraphQL introspection / Swagger | Pre-filled auth tokens, internal mutation names | `{__schema{types{name}}}` probe; `/openapi.json` with auth values | API abuse with leaked tokens |
| Docker / Kubernetes manifests | Image pull secrets, service account tokens, env vars | `/.dockerenv`, `/proc/1/cgroup`, exposed registries | Container escape, cluster-wide access |

## Cloud Provider Credential Patterns

| Provider | Key Pattern | Where Found | Exploitation |
|---|---|---|---|
| AWS IAM | `AKIA[0-9A-Z]{16}` + 40-char secret | `.env`, JS bundles, CI logs, mobile bundles | `aws sts get-caller-identity` then enumerate S3/EC2/IAM |
| AWS STS temp | `ASIA[0-9A-Z]{16}` + secret + session token | CI build output, Lambda env, metadata response | Short-lived but same IAM; check `gcloud projects list` equivalent |
| GCP service account | JSON file with `"private_key": "-----BEGIN..."` | Build logs, SDK serialization, config dumps, `.json` files | `gcloud auth activate-service-account --key-file`; enumerate projects |
| GCP OAuth | `ya29.` prefix access token | CI logs, debugger output, leaked env vars | Direct API calls; `gcloud auth print-access-token` equivalent |
| Azure | `DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...` | Connection strings in `.env`, app settings, web.config | Full storage account access |
| Azure AD | Client secret (40-char random) + tenant/client IDs | App registrations, CI variables | Token generation for any scope the app has |
| Firebase | `AIzaSy...` API key + project config object | JS bundles (`firebaseConfig`), mobile `Info.plist` | Check Firestore rules (often world-readable); Storage access |
| DigitalOcean | `dop_v1_` or `do_` prefix tokens | `.env`, CI config | Full Spaces/Droplet/DNS control |
| Cloudflare | `Bearer` tokens, Global API key (37-char hex) | `.env`, worker scripts | DNS manipulation, WAF bypass, cache purge |

## Defense-Bypass Pairs

| Defense | Bypass Technique | Real Example |
|---|---|---|
| Django `SECRET_KEY` snip-list on debug page | Third-party config dicts escape the snip-list; `SENTRY_OPTIONS["system.secret-key"]` not filtered | Facebook Sentry RCE, $5K |
| GitHub Actions label gate on `pull_request_target` | Auto-label bot assigns labels from PR title regex; craft title to trigger labeling | Google AlloyDB GITHUB_TOKEN leak, $10K |
| Credential rotation after commit-history exposure | Credentials reused across services; rotated key still valid on secondary service | Common: same AWS key in prod + staging |
| Mobile app obfuscation / ProGuard | `strings` on native binary; `apktool` on APK; `unzip` on IPA bypasses all code obfuscation | Shopify Sello deploy key, $1.5K; FB Messenger token, $500 |
| Log masking (Airflow, Sentry, Datadog) | Trigger task lifecycle state where mask hasn't run yet; race condition between render and mask | Airflow secret leak via `depends_on_past`, $480 |
| `.env.example` with placeholder values | Production `.env` deployed with placeholder unchanged; or `.env.production` exists alongside | Common: `password123` in production `DATABASE_URL` |
| Firebase security rules | `AIzaSy` key is public by design, but Firestore/Storage rules often misconfigured to allow read | Firebase DB dump via `/.json` endpoint |
| WAF blocking `/.env` path | Try `/.env.production`, `/.env.local`, `/.env.backup`, `/.env.old`, URL-encode the dot | Nginx path normalization differences |

## Chain Patterns

| Base Finding | Chain With | Combined Impact | Real Example |
|---|---|---|---|
| CI/CD token leak via PR build | Cross-project IAM (shared service account) | Single token compromises entire CI estate: GKE, GCS, Cloud Build, G-Suite SA keys | Google magic-modules, $3.1M |
| Debug page leaks `SECRET_KEY` | Pickle deserialization in Django `signed_cookies` | Forge session cookie with RCE payload; full server compromise | Facebook Sentry RCE, $5K |
| Mobile bundle leaks GitHub deploy token | Private repo access | Read all source code; extract further secrets from source; pivot to infra | Shopify Sello, $1.5K |
| Exposed Cortex `/config` | Metric injection via push API | Poison monitoring alerts; hide real attacks; disrupt SLA metrics | Shopify Cortex, $6.3K |
| JS bundle leaks Firebase API key | Misconfigured Firestore rules | Full database read/write without authentication | Recurring across programs |
| `.env` with JWT secret | JWT forgery | Mint tokens for any user; admin access; full ATO | Recurring: Django, Express, Rails |
| Backup file leaks DB credentials | External DB access | Direct read/write on production database; PII exfiltration | DoD `database.php.orig`, $500 |
| Stack trace reveals internal hostnames | SSRF targeting leaked internal service | Pivot from info-disc to internal network access | Recurring: `ECONNREFUSED 127.0.0.1:PORT` |

## False Positives

- Placeholder values: `YOUR_API_KEY_HERE`, `xxx`, `***`, `CHANGEME`, empty string
- Sample keys from vendor documentation (e.g. Stripe's `sk_test_tr_1234...` is a literal example they publish)
- Checksum-valid but revoked keys (check with vendor if authorized to do so)
- Keys in markdown code blocks clearly labeled "Example" in vendor onboarding docs
- Firebase `AIzaSy` API key alone (public by design; only a finding if paired with misconfigured Firestore/Storage rules)
- GITHUB_TOKEN in `pull_request` (not `pull_request_target`) trigger — scoped to read-only fork permissions

## Pro Tips

1. Demo-credentials-on-homepage is THE classic missed finding. Always fetch `/` before anything else.
2. Sourcemaps (`.map` files) sometimes leak absolute filesystem paths that then leak credentials in inline-data.
3. `.env` exposed on Nginx/Apache misconfig is a 1-minute Critical.
4. Check `robots.txt` for `Disallow:` entries — these are often the juiciest paths ("hidden" pages).
5. `/phpinfo.php`, `/info.php`, `/.well-known/security.txt`, `/app-ads.txt` are all free info leaks worth a 5s probe.
6. JS bundles: `curl <main-bundle>.js | grep -oE '(sk-|ghp_|eyJ|AKIA)[A-Za-z0-9_-]+'` finds vendor tokens in seconds.
7. For any debug page, read EVERY line of the stacktrace. Django's snip-list only covers known setting names; third-party plugin config dicts are exposed verbatim. This is a $5K-$50K pattern.
8. `JSON.stringify()` any SDK client object you find in a codebase. If the credential appears in the output, every error log and crash report leaks it.
9. For public OSS repos of any target company, audit `.github/workflows/` for `pull_request_target` + `actions/checkout` of PR head SHA. The "pwn-request" pattern is a recurring six-figure class.
10. Mobile app bundles: `Podfile`, `Podfile.lock`, `build.gradle`, `Info.plist`, `AndroidManifest.xml`, `google-services.json` all ship inside the binary. Extract and grep — 30 seconds per app.
11. Backup-extension fuzzing on credential-suggestive filenames (`database`, `config`, `settings`, `wp-config`, `secrets`) catches findings that automated scanners miss because they only fuzz directory paths.
12. When a credential is found in one location, always check if the same value appears elsewhere — credential reuse across services turns a single leak into a multi-system compromise.
13. IP-range scanning (`/24` blocks owned by the target) finds forgotten services with no DNS records. Cortex, Prometheus, Grafana, Jenkins on owned IPs are common high-value finds.
14. Test desktop app uninstall/reinstall cycles for session persistence -- Slack Windows kept you logged in after uninstall because `%APPDATA%` tokens survived; check `%APPDATA%`, `~/Library/Application Support/`, `~/.config/` post-uninstall ($500 Slack -- H1 #238260)
15. For HTTP clients and SDKs, audit redirect handlers for credential leakage across scheme (HTTPS-to-HTTP) and port changes on the same host -- curl leaked `Authorization` on same-host scheme-downgrade redirects ($480 CVE-2022-27776 -- H1 #1551591)
16. After any security patch lands in a library, audit the fix for adjacent-header/adjacent-flag completeness -- curl's `Authorization` cross-host strip was patched but `Cookie`, `Proxy-Authorization`, and custom auth headers were missed in successive CVEs ($0-$480 each -- H1 #1568175, #2408074)
17. Treat published media (conference photos, livestream VODs, tutorial videos, demo screenshots) as recon sources -- a leaderboard photo disclosed a local wifi password in the background ($500 H1 #329798)
18. Audit CLI tools accepting dual-form input (public ID vs secret token) for log-before-classify leaks -- kubeadm logged the full bootstrap token before parsing whether input was an ID or secret (Kubernetes -- H1 #972561)
19. For every CI/CD system, check whether secrets are exposed to fork PRs: CircleCI's "Pass secrets to forked PRs" toggle, GitHub Actions `pull_request_target`, Travis `TRAVIS_SECURE_ENV_VARS` -- a single toggle exposes all repo secrets to any contributor (Nextcloud -- H1 #794407)
20. For wildcard-scope programs, build Google dorks for PowerPoint/Word/PDF training materials (`site:*.target.mil filetype:pptx "password"`) -- training docs frequently embed live credentials in screenshots ($0-$500 DoD -- H1 #672629, #805027)
21. Audit encryption-at-rest schemes against the documented threat model -- if the system stores both keys and ciphertext on the same medium, the key file must be authenticated by something the storage cannot forge (H1 #732431, #743505)
22. For any framework with method-dispatch patterns (ColdFusion CFC, Java RMI, .NET ASMX, gRPC reflection), check if internal methods are exposed by default -- ColdFusion CFCs expose all remote methods unless explicitly restricted ($0 DoD -- H1 #241116)
