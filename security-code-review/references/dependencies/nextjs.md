# Dependency Security — Next.js / TypeScript Patterns

## Vulnerability Scanning

```bash
npm audit              # Check for known vulnerabilities in package-lock.json
npm audit --json       # Machine-readable output for CI integration
npm audit fix          # Auto-fix non-breaking vulnerability upgrades
npm audit fix --force  # Fix breaking upgrades too — review changes carefully
```

Run `npm audit` in CI. A non-zero exit code (vulnerabilities found) should
block the build for high/critical severity findings.

## npm ci vs npm install

```bash
npm ci       # CI installs: uses package-lock.json exactly, fails if lock is out of sync
npm install  # Dev installs: may update package-lock.json, resolves ranges
```

Always use `npm ci` in CI and Docker builds. `npm install` in CI means the
build may silently install different (potentially vulnerable) versions than
what was tested locally.

## package-lock.json

`package-lock.json` is the lock file. Always commit it. Never add it to
`.gitignore`. Without it, `npm ci` fails and `npm install` installs whatever
the latest version is at build time.

## Dependabot Configuration

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```
