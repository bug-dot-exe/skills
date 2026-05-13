---
name: bandit
description: Bandit Python SAST — AST-driven scanner for hardcoded secrets, SQL/command injection, insecure deserialization, weak crypto, and shell-true subprocess
depends_on: []
---

# Bandit Python SAST

Bandit parses Python source into AST and runs security plugins to flag common Python anti-patterns: hardcoded credentials, `subprocess(shell=True)`, `pickle.loads`, MD5/SHA1, `assert` for security checks, `eval`/`exec` on untrusted input, weak SSL/TLS configs.

## Prerequisites

- Bandit (install: `pip install bandit`)
- Python 3.8+

## Canonical Syntax

`bandit [flags] <path>` — defaults to scanning the given file or directory recursively.

## High-Signal Flags

- `-r <path>` recursive scan of a directory
- `-f json|xml|csv|txt|html|sarif` output format
- `-o <file>` write report to file
- `-l, -ll, -lll` severity threshold (LOW, MEDIUM, HIGH)
- `-i` confidence threshold (only HIGH confidence)
- `-c <config>` use a `.bandit.yaml` configuration
- `-s <test_ids>` skip specific tests (comma-separated, e.g. `B101,B601`)
- `-t <test_ids>` run only specific tests
- `--exclude <patterns>` skip directories (comma-separated)
- `-n <num>` context lines around each finding
- `--no-code` exclude code snippets from report (safer for shared output)

## Agent-Safe Baseline

```bash
bandit -r /workspace \
  -f json \
  -o bandit.json \
  --exclude /workspace/tests,/workspace/.venv,/workspace/venv \
  -ll
```

This produces a JSON report capturing MEDIUM-and-above severities, excluding tests and virtualenvs that produce noise.

## Common Patterns

- **Quick triage** (HIGH severity + HIGH confidence only):
  `bandit -r /workspace -lll -i -f json -o bandit_high.json`
- **Single-file deep dive**:
  `bandit -f txt -n 5 /workspace/path/to/file.py`
- **CI gate** (exit 1 on findings, blocking):
  `bandit -r /workspace -ll || exit 1`
- **Diff-against-baseline**:
  ```bash
  bandit -r /workspace -f json -o current.json
  diff <(jq -S . baseline.json) <(jq -S . current.json)
  ```
- **SARIF for code-scanning UIs**:
  `bandit -r /workspace -f sarif -o bandit.sarif`

## Test ID Cheat Sheet

Bandit identifies findings by test ID. The most security-relevant:

| ID | Issue |
|---|---|
| B101 | `assert` used (often optimized out under `-O`) |
| B105/B106/B107 | Hardcoded password string / argument / function default |
| B201 | Flask `debug=True` |
| B301 | `pickle.loads` on untrusted data |
| B303/B304 | MD5 / weak DES, RC4 ciphers |
| B306 | `mktemp` use (TOCTOU race) |
| B501/B502 | SSL `verify=False`, weak SSL/TLS protocols |
| B601 | `paramiko.exec_command` shell injection |
| B602 | `subprocess(shell=True)` |
| B608 | SQL injection via string concatenation/formatting |
| B610/B611 | Django `extra` / `RawSQL` injection |
| B701 | Jinja2 `autoescape=False` |

## Severity × Confidence Matrix

Bandit attaches BOTH severity (impact if true) and confidence (likelihood it's real). Triage priority:

| Severity ↓ / Confidence → | LOW | MEDIUM | HIGH |
|---|---|---|---|
| **HIGH** | Investigate | Likely fix | **Critical — fix now** |
| **MEDIUM** | Triage when time permits | Likely fix | Fix now |
| **LOW** | Often false positives — review | Triage | Likely fix |

## Suppression

Inline `# nosec` comment suppresses a finding on that line. Always document the rationale:

```python
import pickle  # nosec B301 - serializing internal-only cache, not user input
```

For broader suppressions, list test IDs in `.bandit.yaml`:

```yaml
exclude_dirs: [/tests/, /.venv/, /node_modules/]
skips: [B101]   # assert is fine in test files
```

## Critical Correctness Rules

- Always pass `--exclude` to skip `.venv`, `venv`, `tests`, and virtualenv directories — otherwise reports drown in third-party-package findings.
- Always use `-f json -o <file>` (or SARIF) for automation; the default text output is not stable.
- A `B608` (SQL injection) finding is HIGH-confidence ONLY when the source is a function parameter (likely user-controlled). Confirm by reading the call site.
- Confidence LOW findings are often false positives — review before acting.

## Failure Recovery

- If scan stalls on a huge dependency tree, narrow `-r` to source dirs only.
- If output is empty for a known-buggy file, check `-l` threshold and confirm `--exclude` isn't filtering the file.
- If JSON is malformed (rare), re-run with `-f txt` to see whether Bandit raised an error mid-scan.

## OWASP / CWE Mapping

Bandit emits CWE IDs in JSON output. Common mappings:

- B105/B106 → CWE-259 (hardcoded password)
- B301 → CWE-502 (insecure deserialization)
- B303/B304 → CWE-327 (broken/risky crypto)
- B501 → CWE-295 (improper certificate validation)
- B602/B605 → CWE-78 (OS command injection)
- B608 → CWE-89 (SQL injection)

## SecOpsAgentKit contributions

Sourced from SecOpsAgentKit's `appsec/sast-bandit/SKILL.md` (rule cheat sheet, severity × confidence matrix, suppression patterns, baseline-diff workflow). Adapted to bug.exe's CLI-playbook format used by other tooling skills.

## Corpus-Derived Advanced Techniques

### ReDoS Pattern Detection

Bandit does not catch ReDoS natively. Supplement with manual grep:
```bash
# Enumerate all regex compilation sites
grep -rn 're.match\|re.search\|re.findall\|re.compile\|re.sub' /workspace --include='*.py' > regex_sites.txt
# Flag patterns with nested quantifiers (backtracking amplification)
grep -E '\(\.\*\).*\1|\(\[.*\]\+\).*\+|\(\.\+\)\{' regex_sites.txt
```
Look for user-controlled input flowing into any regex operation. Nested quantifiers like `(a+)+`, `(a|a)*`, or `([a-z]+)*` are classic ReDoS triggers.

### Insecure TLS Defaults Survey

Extend B501/B502 coverage to audit every TLS wrapper in the codebase:
```bash
# Scan for all SSL/TLS context creation
bandit -r /workspace -t B501,B502,B503,B504 -f json -o tls_audit.json
# Also grep for insecure defaults Bandit misses
grep -rn 'verify=False\|CERT_NONE\|check_hostname.*False\|ssl_context.*None' /workspace --include='*.py'
```
Check every library that wraps TLS: `requests`, `urllib3`, `httpx`, `aiohttp`, `xmlrpc.client`, `smtplib`, `imaplib`.

### C Extension Type Confusion Audit

For Python projects with C extensions (via ctypes, cffi, Cython, or raw C modules):
```bash
# Find C extension entry points
grep -rn 'ctypes\.\|cffi\.\|CDLL\|from.*import.*_C' /workspace --include='*.py' > c_ext_sites.txt
# Bandit extended check on those files
bandit -f json -o c_ext_audit.json $(cat c_ext_sites.txt | cut -d: -f1 | sort -u | tr '\n' ' ')
```
Every parameter that flows from Python into C code is a potential type confusion, buffer overflow, or use-after-free vector. Check that type tags are verified before pointer casts.

### Deserialization Chain Audit

Extend B301 (pickle) to cover all serialization formats:
```bash
# Bandit catches pickle, but also hunt for:
grep -rn 'yaml.load\|yaml.unsafe_load\|marshal.loads\|shelve.open\|jsonpickle' /workspace --include='*.py'
grep -rn '__reduce__\|__setstate__\|__getstate__' /workspace --include='*.py'
```
Any `__setstate__` or `__reduce__` method on a class that handles deserialized data is a code-execution vector if the input is attacker-controlled.

### Format String and Buffer Size Audit

For projects using `ctypes` or C FFI bindings:
```bash
# Check for sprintf/snprintf-equivalent patterns
grep -rn 'sprintf\|snprintf\|vsprintf\|format_string' /workspace --include='*.c' --include='*.h'
# Check Python format strings that build SQL/commands
bandit -r /workspace -t B608,B602 -f json -o format_audit.json
```

### Negative Offset and Boundary Value Patterns

For Python C extensions that accept index parameters:
```bash
# Find array/buffer indexing in C code called from Python
grep -rn 'PyArg_Parse\|PyLong_AsLong\|PyFloat_AsDouble' /workspace --include='*.c'
```
Test: does the function handle negative indices, zero, and values exceeding buffer length? Any unchecked index that becomes a C array offset is an OOB read/write candidate.

### Cross-Language Vulnerability Porting

When a CVE is found in one language's stdlib, check the same module in the target:
```bash
# Example: STARTTLS stripping (CVE-2016-0772 in Python)
grep -rn 'smtplib\.\|imaplib\.\|poplib\.\|STARTTLS\|starttls' /workspace --include='*.py'
# Check if the code handles upgrade failure correctly
bandit -r /workspace -t B504 -f json -o starttls_audit.json
```
Same vulnerability class often exists across Python, Ruby, Node, PHP, and Go implementations of the same protocol.
