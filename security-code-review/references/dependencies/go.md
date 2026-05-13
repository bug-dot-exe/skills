# Dependency Security — Go Patterns

## Vulnerability Scanning

```bash
govulncheck ./...    # Check entire module for known CVEs (uses Go vuln DB)
go mod verify        # Verify module checksums haven't been tampered with
go mod tidy          # Remove unused dependencies (reduce attack surface)
git add go.sum       # Always commit — go.sum is the lock file
```

Run `govulncheck` in CI. It only reports vulnerabilities in code paths that
are actually reachable, reducing noise compared to tools that flag all
transitive dependencies regardless of usage.

## go.sum Tampering

`go.sum` contains cryptographic hashes of every module. `go mod verify` checks
that the modules in the local cache match these hashes. Run it in CI before
building to detect supply chain tampering.

## Dependabot Configuration

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```
