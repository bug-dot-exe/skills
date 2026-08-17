# Conjure 3301 Skills

A consolidated collection of AI-agent skills for authorized security research,
bug bounty hunting, and smart-contract auditing. Not a single product: the
skills were assembled from multiple upstream open-source projects and are
maintained here as one loadable tree.

## What's in here

- 417 top-level skill directories, 622 SKILL.md files
- Bug bounty hunting: vulnerability classes, methodologies, reconnaissance,
  tools, frameworks, technologies, cloud, playbooks, archetypes
- The `hunt-deep` orchestrator: multi-agent bounty pipeline (scope -> intel ->
  recon -> parallel vuln-class hunters -> validate -> rescan loop -> chain ->
  report), merged with the TTM depth discipline
- A web3 audit pipeline (`prompts/`, `rules/`, `agents/`, `commands/`,
  `aptos/`, `evm/`, `sui/`, `solana/`, `injectable/`, `niche/`) - the Plamen
  pipeline skills
- Standalone smart-contract auditors and frameworks (`solidity-guard`,
  `building-secure-contracts`, `krait`, `monethic-maia`, `nemesis-auditor`,
  `move-auditor-skills`, and others)
- Utility skills: `hash-verifier` (integrity manifests), `security-monitor`,
  `output-sanitizer`, plus misc helpers

## Category breakdown

| Category | Count | Examples |
|----------|-------|----------|
| Vulnerability classes | 64 | `idor`, `xss`, `ssrf`, `sql-injection`, `rce` |
| Technologies | 55 | `aws`, `stripe`, `react`, `tech-django` |
| Methodologies | 44 | `chain-building`, `kill-signals`, `threat-modeling` |
| Reconnaissance | 42 | `deep-recon-for-bug-bounties`, `js-analysis`, `wayback-cdx-dorking` |
| Web3 | 22 | `oracle-price-manipulation`, `mev-sandwich-attacks` |
| Tools | 15 | `ffuf`, `nuclei`, `sqlmap`, `semgrep` |
| Frameworks | 11 | `django`, `flask`, `express`, `rails` |
| Playbooks | 8 | `bug-bounty-playbook`, `owasp-top10-playbook` |
| Archetypes | 6 | `b2b-saas`, `fintech`, `mobile-api` |
| Protocols | 5 | `oauth`, `saml`, `graphql` |
| Cloud | 4 | `aws`, `azure`, `gcp`, `kubernetes` |
| Mobile | 2 | `android-dast-sast`, `ios-testing` |
| Custom | 1 | `source-aware-sast` |

## Lineage

Content originates from multiple upstream projects, including the Conjure bug
bounty cockpit, the Plamen web3 audit pipeline, codex-bug-bounty, grimoire,
cursor-skills, the Trail of Bits testing handbook, solidity-guard, and others.
Skills retain their upstream content; some carry attribution files (e.g.
`krait/ATTRIBUTION.md`). This repository has no LICENSE file of its own -
individual upstream licenses apply. Verify licensing before redistributing
anything.

## Loading

This tree is consumed by opencode:

```json
{ "skills": { "paths": ["C:/Users/pc/.config/opencode/vendor/conjure-3301-skills"] } }
```

Skill names are kebab-case and match their folder names. Restart the client
after changes - the skill registry loads at startup.

## Repository

Public at `github.com/conjure-3301/skills`, branch `main`. Commit rules:

- Only skill content goes here. Never commit target data, credentials,
  operator hunt briefs, run artifacts, or captured traffic.
- Keep skills target-agnostic - no hardcoded industry or program vocabulary.

## Safety

These skills describe offensive security techniques. Use them only against
systems you own or have explicit written authorization to test. Respect each
program's scope, rules of engagement, and rate limits.

## Known quirks

- Vendored collections keep their internal structure; some nested trees contain
  their own SKILL.md hierarchies and occasional stale references.
- `docs/`, `agents/`, `prompts/`, `rules/`, `commands/` are pipeline internals
  and developer documentation, not user-facing skills.
- Root stray files (`coverage.md`, `goal`) are artifacts, not skills.
