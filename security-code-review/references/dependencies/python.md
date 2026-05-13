# Dependency Security — Python Patterns

## Vulnerability Scanning

```bash
pip-audit                          # Check installed packages against OSV/PyPI Advisory DB
safety check -r requirements.txt  # Alternative; requires free API key
bandit -r src/                     # Static security analysis (code patterns, not CVEs)
```

`pip-audit` and `safety` check for known CVEs. `bandit` checks for insecure
code patterns (hardcoded passwords, use of `subprocess` with shell=True, etc.).
Both types of check belong in CI.

## Lock Files

```bash
# pip: pin all versions including transitive deps
pip-compile requirements.in --generate-hashes  # hashes prevent tampered packages

# poetry: always commit the lock file
git add poetry.lock

# pip freeze snapshot
pip freeze > requirements.txt && git add requirements.txt
```

`--generate-hashes` with pip-compile means `pip install` will verify the hash
of every downloaded package — equivalent to `go.sum` verification.

## Dependabot Configuration

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
```
