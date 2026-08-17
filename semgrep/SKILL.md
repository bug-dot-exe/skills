---
name: semgrep
description: Exact Semgrep CLI structure, metrics-off scanning, scoped ruleset selection, and automation-safe output patterns.
depends_on: []
---

# Semgrep CLI Playbook

Official docs:
- https://semgrep.dev/docs/cli-reference
- https://semgrep.dev/docs/getting-started/cli
- https://semgrep.dev/docs/semgrep-code/semgrep-pro-engine-intro

Canonical syntax:
`semgrep scan [flags]`

High-signal flags:
- `--config <rule_or_ruleset>` ruleset, registry pack, local rule file, or directory
- `--metrics=off` disable telemetry and metrics reporting
- `--json` JSON output
- `--sarif` SARIF output
- `--output <file>` write findings to file
- `--severity <level>` filter by severity
- `--error` return non-zero exit when findings exist
- `--quiet` suppress progress noise
- `--jobs <n>` parallel workers
- `--timeout <seconds>` per-file timeout
- `--exclude <pattern>` exclude path pattern
- `--include <pattern>` include path pattern
- `--exclude-rule <rule_id>` suppress specific rule
- `--baseline-commit <sha>` only report findings introduced after baseline
- `--pro` enable Pro engine if available
- `--oss-only` force OSS engine only

Agent-safe baseline for automation:
`semgrep scan --config p/default --metrics=off --json --output semgrep.json --quiet --jobs 4 --timeout 20 /workspace`

Common patterns:
- Default security scan:
  `semgrep scan --config p/default --metrics=off --json --output semgrep.json --quiet /workspace`
- High-severity focused pass:
  `semgrep scan --config p/default --severity ERROR --metrics=off --json --output semgrep_high.json --quiet /workspace`
- OWASP-oriented scan:
  `semgrep scan --config p/owasp-top-ten --metrics=off --sarif --output semgrep.sarif --quiet /workspace`
- Language- or framework-specific rules:
  `semgrep scan --config p/python --config p/secrets --metrics=off --json --output semgrep_python.json --quiet /workspace`
- Scoped directory scan:
  `semgrep scan --config p/default --metrics=off --json --output semgrep_api.json --quiet /workspace/services/api`
- Pro engine check or run:
  `semgrep scan --config p/default --pro --metrics=off --json --output semgrep_pro.json --quiet /workspace`

Critical correctness rules:
- Always include `--metrics=off`; Semgrep sends telemetry by default.
- Always provide an explicit `--config`; do not rely on vague or implied defaults.
- Prefer `--json --output <file>` or `--sarif --output <file>` for machine-readable downstream processing.
- Keep the target path explicit; use an absolute or clearly scoped workspace path instead of `.` when possible.
- If Pro availability matters, check it explicitly with a bounded command before assuming cross-file analysis exists.

Usage rules:
- Start with `p/default` unless the task clearly calls for a narrower pack.
- Add focused packs such as `p/secrets`, `p/python`, or `p/javascript` only when they match the target stack.
- Use `--quiet` in automation to reduce noisy logs.
- Use `--jobs` and `--timeout` explicitly for reproducible runtime behavior.
- Do not use `-h`/`--help` for routine operation unless absolutely necessary.

Failure recovery:
- If scans are too slow, narrow the target path and reduce the active rulesets before changing engine settings.
- If scans time out, increase `--timeout` modestly or lower `--jobs`.
- If output is too broad, scope `--config`, add `--severity`, or exclude known irrelevant paths.
- If Pro mode fails, rerun with `--oss-only` or without `--pro` and note the loss of cross-file coverage.

If uncertain, query web_search with:
`site:semgrep.dev semgrep <flag> cli`

## SecOpsAgentKit contributions

Additional patterns sourced from SecOpsAgentKit's `appsec/sast-semgrep/SKILL.md`. Use these when bug.exe's tighter CLI playbook above doesn't already cover the surface you need.

### Diff-Against-Baseline (Branch-Scoped Scan)

Scan only files changed since a baseline commit — enables PR-friendly scanning where only new vulnerabilities block:

```bash
semgrep scan --config p/default \
  --baseline-commit origin/main \
  --metrics=off \
  --json --output semgrep_diff.json /workspace
```

Findings present in `origin/main` are filtered out automatically.

### SARIF Export for Code-Scanning UIs

Emit SARIF for upload to GitHub Security, GitLab SAST UI, or DefectDojo:

```bash
semgrep scan --config p/default --metrics=off \
  --sarif --output semgrep.sarif /workspace
```

GitHub Actions upload pattern:
```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: semgrep.sarif
```

### Pattern-Specific Researcher Mode

When hunting one specific vulnerability class across the codebase, target the registry pack directly:

```bash
# XSS-only sweep across JS code
semgrep --config "r/javascript.lang.security.audit.xss" \
  --json /workspace | jq '.results[] | {check_id, path, start: .start.line, end: .end.line}'

# SSRF-only sweep across Python
semgrep --config "r/python.lang.security.audit.ssrf" \
  --json /workspace | jq '.results'

# Hardcoded-secret sweep
semgrep --config p/secrets --json --output semgrep_secrets.json /workspace
```

### Custom Rule Skeleton

Save as `custom_rules.yaml`:

```yaml
rules:
  - id: hardcoded-jwt-secret
    pattern-either:
      - pattern: $X = "..."
      - pattern: $X = '...'
    metavariable-pattern:
      metavariable: $X
      patterns:
        - pattern-regex: "(?i)(jwt[_-]?secret|hmac[_-]?key|signing[_-]?secret)"
    message: "Hardcoded JWT/HMAC signing secret detected. Use a secret manager (Vault, AWS Secrets Manager) instead."
    severity: ERROR
    languages: [python, javascript, typescript, ruby, go, java]
    metadata:
      category: security
      cwe: "CWE-798"
      owasp: "A02:2021 Cryptographic Failures"
```

Validate against test fixtures:
```bash
# Test rule against known-vulnerable samples
semgrep --config custom_rules.yaml --test tests/vulnerable_samples/
```

Run against the codebase:
```bash
semgrep scan --config custom_rules.yaml --metrics=off --json --output custom.json /workspace
```

### Multi-Language Coverage

Semgrep supports 30+ languages out of the box. Most-relevant security packs by stack:

| Stack | Recommended Pack |
|---|---|
| Python web (Django, Flask, FastAPI) | `p/python` + `p/django` (or `p/flask`) |
| Node/Express/Next.js | `p/javascript` + `p/typescript` |
| Java/Spring | `p/java` + `p/spring` |
| Go | `p/golang` |
| Ruby/Rails | `p/ruby` + `p/rails` |
| PHP | `p/php` + `p/laravel` |
| Terraform / IaC | `p/terraform` + `p/dockerfile` + `p/kubernetes` |
| Mobile (iOS Swift, Android Kotlin) | `p/swift` + `p/kotlin` |
| Solidity | `p/solidity` |

Combine multiple `--config` flags to layer packs.

### OWASP Top 10 → CWE Quick Map

Common Semgrep rule categories aligned to OWASP A01-A10:

- A01 Broken Access Control → CWE-285, CWE-862
- A02 Cryptographic Failures → CWE-327, CWE-330, CWE-798
- A03 Injection → CWE-89 (SQL), CWE-79 (XSS), CWE-78 (OS command)
- A04 Insecure Design → mostly architectural; Semgrep flags discrete instances (e.g., missing rate limiting)
- A05 Security Misconfiguration → CWE-16, CWE-1004
- A06 Vulnerable Components → handled by SCA tools, not Semgrep
- A07 Authentication Failures → CWE-287, CWE-384
- A08 Data Integrity Failures → CWE-502 (insecure deserialization)
- A10 SSRF → CWE-918

## Corpus-Derived Advanced Workflows (1,236 reports, $11M bounty)

### GitHub Actions Workflow Injection Audit ($1.3M+ pattern)

Scan public repos for unsafe GitHub Actions patterns -- expression injection in `run:` blocks via user-controlled event data:

```bash
# Registry rule for pull_request_target checkout
semgrep scan --config 'r/yaml.github-actions.security.pull-request-target-code-checkout' \
  --metrics=off --json --output gha_unsafe.json /workspace/.github/workflows/

# Custom rule: expression injection in run blocks
cat > gha_injection.yaml << 'EOF'
rules:
  - id: gha-expression-injection
    patterns:
      - pattern: "run: ... ${{ github.event.$X }} ..."
    message: "GitHub Actions expression injection via user-controlled event data"
    severity: ERROR
    languages: [yaml]
EOF
semgrep scan --config gha_injection.yaml --metrics=off --json /workspace/.github/
```

### API-vs-UI Permission Inconsistency ($750K pattern)

Write a rule using `pattern` + `pattern-not-inside` to find route handlers (`@app.route(...)`) that lack authorization decorators (`@requires_auth`) or permission checks. This catches server-side enforcement gaps where the UI hides features client-side only.

### Mass Assignment / PATCH-then-Promote ($50K pattern)

Write a `pattern-either` rule matching `$OBJ.update($REQUEST.json)`, `Object.assign($TARGET, req.body)`, and similar unfiltered-input-to-update patterns across Python/JS/TS:

```bash
cat > mass_assignment.yaml << 'EOF'
rules:
  - id: mass-assignment-risk
    pattern-either:
      - pattern: "$OBJ.update($REQUEST.json)"
      - pattern: "$OBJ.update(**$REQUEST.json)"
      - pattern: "Object.assign($TARGET, req.body)"
    message: "Unfiltered user input passed to update — mass assignment risk"
    severity: ERROR
    languages: [python, javascript, typescript]
EOF
semgrep scan --config mass_assignment.yaml --metrics=off --json /workspace/
```

### Extension Auditing ($500K+ pattern)

Scan for `executeScript` with string concatenation and `externally_connectable` misconfigurations:

```bash
cat > extension_audit.yaml << 'EOF'
rules:
  - id: chrome-extension-code-injection
    pattern-either:
      - pattern: "chrome.tabs.executeScript({code: $CODE})"
      - pattern: "chrome.tabs.executeScript($TAB, {code: $CODE})"
    message: "Dynamic code execution via executeScript — UXSS candidate if input is user-controlled"
    severity: ERROR
    languages: [javascript, typescript]
  - id: broad-host-permissions
    pattern: '"<all_urls>"'
    message: "Extension has <all_urls> permission — every page is in scope for confused-deputy attacks"
    severity: WARNING
    languages: [json]
EOF
semgrep scan --config extension_audit.yaml --metrics=off --json /workspace/
```

### Serialization Leak Detection ($50K pattern)

Detect credential objects that expose secrets via `JSON.stringify` or `console.log`:

```bash
cat > serialization_leak.yaml << 'EOF'
rules:
  - id: credential-serialization-leak
    pattern-either:
      - pattern: "JSON.stringify($CRED_OBJ)"
      - pattern: "console.log($CRED_OBJ)"
      - pattern: "str($CRED_OBJ)"
      - pattern: "repr($CRED_OBJ)"
    where:
      - metavariable: $CRED_OBJ
        regex: "(?i)(client|credential|firebase|auth|service_account)"
    message: "Credential-bearing object passed to serializer — may expose private keys"
    severity: ERROR
    languages: [javascript, typescript, python]
EOF
semgrep scan --config serialization_leak.yaml --metrics=off --json /workspace/
```

### Chaining Semgrep with Other Tools

1. **Semgrep -> Nuclei**: code-level SSRF sinks found by semgrep, reachability confirmed by nuclei
2. **Semgrep -> mitmproxy**: URL-fetch functions identified, mitmproxy addon intercepts to inject payloads
3. **Semgrep -> patch_diff**: after vendor patch, semgrep rules target the fixed pattern to find incomplete patches
4. **Semgrep -> git blame**: trace when vulnerable code was introduced to find similar patterns by same author
