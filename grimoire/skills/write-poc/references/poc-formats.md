# PoC Format Guide by Vulnerability Class

Detailed format templates for proof-of-concept output, organized by vulnerability class.
Select the format that best communicates the issue to the maintainer.

Each vulnerability class has a dedicated reference file with templates, examples, and
conventions. Consult the relevant file below when writing a PoC.

## Vulnerability Classes

- **[Web Application Vulnerabilities](web-application-vulns.md)** — SQL injection, XSS,
  SSRF, authentication/authorization bypass, and IDOR. Covers standalone scripts, curl
  commands, and multi-step request sequences.

- **[Memory Corruption](memory-corruption.md)** — Buffer overflows (stack and heap),
  use-after-free, and format string vulnerabilities. Covers C programs, trigger input
  generation, and crash evidence.

- **[Cryptographic Vulnerabilities](crypto-vulns.md)** — Weak randomness, ECB mode,
  padding oracles, hash collisions, and hardcoded secrets. Focus on demonstrating the
  mathematical/logical weakness.

- **[Race Conditions](race-conditions.md)** — TOCTOU and concurrent request exploitation.
  Covers threading scripts and timing evidence.

- **[Logic / Business Logic Flaws](logic-flaws.md)** — Step-by-step reproduction format
  with narrative context explaining why the logic fails.

- **[Configuration / Deployment Issues](config-issues.md)** — Exposed debug ports,
  misconfigured services, and insecure defaults. Minimal config + demonstration command.

- **[Smart Contract Vulnerabilities](smart-contracts.md)** — Fork test and unit test
  templates, Foundry conventions, cheatcode usage, interface resolution, and attacker
  contract patterns.

## Libraries

- **[forge-poc-templates](forge-poc-templates.md)** — Immunefi's PoC library for smart
  contracts. Base contracts for flash loans, reentrancy, price manipulation, and balance
  tracking. API reference, installation, and usage patterns.

## General

- **[General Format Principles](general-principles.md)** — Five core principles that apply
  regardless of vulnerability class: show don't tell, diff expected vs actual, one vuln per
  PoC, version-pin the target, include cleanup.
