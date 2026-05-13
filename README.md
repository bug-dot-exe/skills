# Plamen Skills

Security auditing skills for the Plamen Web3 security auditing pipeline and bug bounty hunting.

## Structure

### Bug Bounty & Recon Skills (404 skills)

| Category | Count | Description |
|----------|-------|-------------|
| `bugexe-vuln-*` | 65 | Vulnerability classes (XSS, SSRF, IDOR, SQLi, RCE, etc.) |
| `bugexe-tech-*` | 56 | Technology stacks (React, Django, Rails, WordPress, etc.) |
| `bugexe-method-*` | 46 | Methodologies (exploit dev, threat modeling, chain building, etc.) |
| `bugexe-recon-*` | 44 | Reconnaissance (deep recon, JS analysis, subdomain enum, etc.) |
| `bugexe-web3-*` | 25 | Web3 security (smart contracts, MEV, bridges, oracles, etc.) |
| `bugexe-tool-*` | 15 | Tools (nuclei, sqlmap, nmap, semgrep, ffuf, etc.) |
| `bugexe-fw-*` | 11 | Frameworks (Django, Flask, Express, Laravel, Rails, etc.) |
| `bugexe-arch-*` | 10 | Architectures (fintech, B2B SaaS, mobile API, AI SaaS, etc.) |
| `bugexe-playbook-*` | 8 | Playbooks (bug bounty, API security, OWASP top 10, etc.) |
| `bugexe-cloud-*` | 8 | Cloud providers (AWS, Azure, GCP, Kubernetes) |
| `bugexe-proto-*` | 7 | Protocols (OAuth, SAML, GraphQL, gRPC, LDAP) |
| `bugexe-mobile-*` | 3 | Mobile (Android DAST/SAST, iOS testing) |
| Other | 122 | Utilities, standalone tools, frameworks, audits |

### Web3 Audit Pipeline Skills (98 skills)

| Platform | Count | Description |
|----------|-------|-------------|
| `aptos/` | 22 | Aptos Move security skills |
| `evm/` | 18 | EVM/Solidity security skills |
| `solana/` | 20 | Solana/Anchor security skills |
| `sui/` | 22 | Sui Move security skills |
| `injectable/` | 8 | Protocol-type-specific injectable skills |
| `niche/` | 8 | Flag-triggered standalone niche agent skills |

### Prompts (`prompts/`)

40 audit pipeline prompt templates across 5 platforms (aptos, evm, shared, solana, sui) — recon, inventory, depth, scanner, verification, and security rules.

### Cross-Tool Skills

| Directory | Count | Source |
|-----------|-------|--------|
| `cursor-skills/` | 14 | Cursor bug bounty recon skills |
| `cursor-skills-cursor/` | 13 | Cursor utility/workflow skills |
| `codex-skills/` | 6 | Codex platform skills |
| `codex-bug-bounty/` | ~10 | Codex bug bounty plugin (full plugin) |
| `deepseek-skills/` | 1 | DeepSeek platform skill |
| `goal/` | 1 | Goal tracking skill |
| `audit-prep/` | 1 | Audit preparation skill |

### Commands (`commands/`)

24 slash commands: hunt, recon, scope, validate, triage, chain, report, ctf-solver, web3-audit, and more.

### Agents (`agents/`)

6 agent definitions: security-analyzer, security-verifier, depth-state-trace, depth-token-flow, depth-external, depth-edge-case.

### Rules (`rules/`)

10 methodology rules: finding output format, confidence scoring, chain analysis, report templates, PoC execution, post-audit improvement, and more.

## Usage

Each skill is defined in its `SKILL.md` file. Web3 audit skills are loaded by Plamen pipeline agents based on trigger patterns. Bug bounty skills are invoked via the `Skill` tool or slash commands.
