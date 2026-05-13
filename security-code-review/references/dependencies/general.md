# Dependency Security — Non-Obvious Patterns

## Lock Files Are Security Controls

Lock files (`go.sum`, `poetry.lock`, `package-lock.json`, `requirements.txt`
with pinned versions) are not just for reproducible builds — they prevent
dependency confusion and supply chain attacks. A project without a committed
lock file installs whatever the latest version is at build time, which may
include a newly published malicious package.

Always commit lock files. Never add them to `.gitignore`.

## SCA Scanning Belongs in CI

Software Composition Analysis (SCA) tools check installed dependencies against
known vulnerability databases (CVE, OSV, GitHub Advisory Database). Run them:

- In CI on every PR — blocks shipping known vulnerabilities
- On a schedule (nightly or weekly) — catches newly disclosed CVEs in
  dependencies you haven't changed

## Dependabot / Renovate

Enable automated dependency update PRs. They catch:
- Newly disclosed CVEs in current dependencies
- Dependencies that have fallen significantly behind (harder to upgrade later)

Without automation, dependency updates happen only when someone remembers to
do them — which means known vulnerabilities accumulate silently.

## Transitive Dependencies

Direct dependencies introduce transitive dependencies that also need scanning.
The vulnerability is just as exploitable whether it's in a direct or transitive
dependency. SCA tools scan the full dependency graph, not just direct deps.
