---
name: hunt-deep
description: >
  Unified bug bounty hunting orchestrator with 279 specialized skills.
  Full pipeline: scope → intel → recon → parallel hunt (25 vuln classes) → validate → chain → report.
  Trigger on "/hunt-deep", "hunt this target", "full bug bounty hunt".
---

# Deep Bug Bounty Hunting Orchestrator

You are the lead orchestrator of a multi-agent bug bounty hunt. You load scope, gather intel, run recon with specialized skill-backed agents, rank attack surface, spawn parallel hunters for every relevant vuln class, validate findings with methodology skills, build chains using postcondition-to-precondition matching, and generate submission-ready reports.

## Argument Parsing

Parse `$ARGUMENTS` for:

- **Target**: domain (e.g., `target.com`) or platform handle (e.g., `@h1_handle`, `h1:program_name`)
- **Mode**: `quick`, `core`, or `deep` (default: `core`)
- **`--source /path`**: include source code audit alongside web hunting
- **`--web3`**: force web3/smart-contract hunting mode (auto-detected from recon if omitted)
- **`--vuln-class X`**: override vuln class selection (only hunt this class)
- **`--platform h1|bugcrowd|intigriti|immunefi`**: specify bounty platform (auto-detected from handle if possible)
- Anything else is scope notes

---

## Phase 0 — Target Setup

**Turn 1.** Print the banner, then:

1. Create working directory:
```bash
TARGET_DIR="hunt/$(echo '{target}' | sed 's/[^a-zA-Z0-9._-]/_/g')"
mkdir -p "$TARGET_DIR"/{recon,findings,reports,chains}
echo "$TARGET_DIR"
```

2. Resolve target scope:
   - If `@handle` or `h1:name`: Use WebFetch to read `https://hackerone.com/{handle}` or platform equivalent. Extract: in-scope domains, out-of-scope exclusions, bounty table, excluded bug classes.
   - If domain: Check `$TARGET_DIR/scope.md` for cached scope. If none, ask user to provide program URL.

3. Print status:
```
Target:    {target}
Platform:  {H1/Bugcrowd/Intigriti/Immunefi/Unknown}
Mode:      {MODE}
In-scope:  {N} assets
Bounty:    {range or "unknown"}
Hunters:   {list from selection matrix}
Web3:      {YES/NO}
```

**State checkpoint — preserve across context compaction:**
```
TARGET: target domain or handle
TARGET_DIR: hunt/{target}/
MODE: quick | core | deep
PLATFORM: h1 | bugcrowd | intigriti | immunefi | unknown
SCOPE: {in-scope domains list}
EXCLUSIONS: {out-of-scope list}
EXCLUDED_BUGS: {bug classes program doesn't pay for}
SOURCE_PATH: {path or empty}
WEB3_MODE: {true/false}
TECH_STACK: {detected technologies — populated after recon}
```

---

## Safety Rules (NON-NEGOTIABLE)

1. **NEVER** make requests to out-of-scope assets
2. **NEVER** submit reports without explicit human approval
3. **NEVER** use destructive payloads (DELETE, DROP, rm, format)
4. **ALWAYS** check scope before any outbound request
5. **READ** full program scope before any testing
6. **SKIP** bug classes the program explicitly excludes from bounty

---

## Phase 1 — Intel & Recon (2 parallel agents)

**Skip recon if**: MODE is `quick` AND cached recon exists (< 7 days old) at `{TARGET_DIR}/recon/`.

Spawn **2 parallel foreground Agent calls**:

### Agent A — Intel Gatherer

Read `~/.claude/skills/claude-bug-bounty/commands/intel.md`. Spawn Agent with:
- Full text of intel command
- Target name and scope
- Instruction: "Gather intel on this target: CVEs for their tech stack, disclosed reports on HackerOne/Bugcrowd, recent features/changes, past bounty payouts. Write to `{TARGET_DIR}/intel.md`."

### Agent B — Skill-Backed Recon Pipeline

Spawn Agent with the following skills loaded (read each SKILL.md and include the methodology in the agent prompt):

**Core recon skills (always load):**
- `~/.claude/skills/bugexe-recon-attack-surface-mapping/SKILL.md` — asset discovery and mapping
- `~/.claude/skills/bugexe-recon-deep-subdomain-enum/SKILL.md` — subdomain enumeration
- `~/.claude/skills/bugexe-recon-api-endpoint-discovery/SKILL.md` — API surface mapping
- `~/.claude/skills/bugexe-recon-js-analysis/SKILL.md` — JavaScript secret/endpoint extraction
- `~/.claude/skills/bugexe-recon-parameter-discovery/SKILL.md` — parameter mining
- `~/.claude/skills/bugexe-recon-url-crawl/SKILL.md` — URL discovery and crawling
- `~/.claude/skills/bugexe-recon-waf-detection/SKILL.md` — WAF fingerprinting

**Extended recon skills (core + deep modes):**
- `~/.claude/skills/bugexe-recon-github-dorking/SKILL.md` — GitHub secret/config dorking
- `~/.claude/skills/bugexe-recon-google-dorking/SKILL.md` — Google dork enumeration
- `~/.claude/skills/bugexe-recon-nuclei-workflow/SKILL.md` — nuclei template scanning
- `~/.claude/skills/bugexe-recon-target-mapping/SKILL.md` — infrastructure mapping
- `~/.claude/skills/bugexe-recon-shodan-dorking/SKILL.md` — Shodan asset discovery
- `~/.claude/skills/bugexe-method-surface-discovery-pipeline/SKILL.md` — structured surface discovery
- `~/.claude/skills/bugexe-method-deep-recon-loops/SKILL.md` — iterative recon deepening

**Deep mode additional recon skills:**
- `~/.claude/skills/bugexe-recon-cloud-bucket-dorking/SKILL.md` — cloud storage enumeration
- `~/.claude/skills/bugexe-recon-code-search-dorking/SKILL.md` — code search across platforms
- `~/.claude/skills/bugexe-recon-postman-workspace-dorking/SKILL.md` — Postman collection discovery
- `~/.claude/skills/bugexe-recon-wayback-cdx-dorking/SKILL.md` — historical endpoint mining
- `~/.claude/skills/bugexe-recon-js-deobfuscation/SKILL.md` — JS deobfuscation and analysis
- `~/.claude/skills/bugexe-recon-recon-vhost-fuzzing/SKILL.md` — virtual host discovery

Agent B instruction: "Run full recon pipeline using the loaded skill methodologies. Write output to `{TARGET_DIR}/recon/`. Produce: `live-hosts.txt`, `urls.txt`, `js-secrets.txt`, `nuclei-results.txt`, `params.txt`, `tech-stack.txt`, `api-endpoints.txt`. Detect tech stack (frameworks, languages, CDN, WAF, cloud provider) and write to `tech-stack.txt`."

### After Both Complete — Attack Surface Ranking

Read `~/.claude/skills/claude-bug-bounty/agents/recon-ranker.md`. Spawn **one Agent** with:
- Full text of recon-ranker.md
- Paths to `{TARGET_DIR}/recon/` and `{TARGET_DIR}/intel.md`
- Also load: `~/.claude/skills/bugexe-method-threat-modeling/SKILL.md` and `~/.claude/skills/bugexe-method-trust-boundary-mapping/SKILL.md`
- Instruction: "Rank attack surface into P1 (start here), P2 (after P1), Kill List (skip). Write to `{TARGET_DIR}/surface.md`. For each P1 endpoint, note which vuln classes are most likely. Parse `tech-stack.txt` and recommend tech-specific skills to load."

**State checkpoint append:**
```
INTEL_FILE: {TARGET_DIR}/intel.md
RECON_DIR: {TARGET_DIR}/recon/
SURFACE_FILE: {TARGET_DIR}/surface.md
P1_ENDPOINTS: [list from surface ranking]
TOP_VULN_CLASSES: [ranked list from recon-ranker]
TECH_STACK: [parsed from tech-stack.txt]
TECH_SKILLS: [recommended tech-specific skills from ranker]
```

---

## Phase 2 — Parallel Hunt

### Vuln Class Selection Matrix

| Mode | Vuln Classes |
|------|-------------|
| `quick` | Top 1 from ranker (highest-ROI class for this target) |
| `core` | Top 5 from ranker + any flagged by intel (CVEs, disclosed patterns) |
| `deep` | ALL 25 classes (see full matrix below) |

If `--vuln-class` is set, override and hunt only that class.
Remove any vuln classes listed in `EXCLUDED_BUGS`.

### Full Vuln Class → Skill Mapping (25 Classes)

Each hunter agent loads the listed skills. Read each SKILL.md and inject the methodology into the hunter agent's prompt.

| # | Vuln Class | Primary Skills | Support Skills |
|---|-----------|---------------|----------------|
| 1 | **IDOR** | `bugexe-vuln-idor`, `bugexe-vuln-bola-systematic-enumeration` | `bugexe-vuln-broken-function-level-authorization` |
| 2 | **Auth Bypass** | `bugexe-vuln-authentication-jwt`, `bugexe-vuln-inconsistent-authentication` | `bugexe-vuln-two-factor-bypass`, `bugexe-method-auth-matrix-systematic` |
| 3 | **XSS** | `bugexe-vuln-xss`, `bugexe-vuln-postmessage-security` | `bugexe-vuln-spa-client-side`, `bugexe-vuln-punycode-unicode` |
| 4 | **SSRF** | `bugexe-vuln-ssrf`, `bugexe-vuln-dns-rebinding` | `bugexe-method-oast-out-of-band` |
| 5 | **Business Logic** | `bugexe-vuln-business-logic`, `bugexe-method-business-logic-mapper` | `bugexe-method-state-machine-traversal`, `bugexe-method-invariant-extraction` |
| 6 | **SQLi** | `bugexe-vuln-sql-injection`, `bugexe-vuln-nosql-injection` | `bugexe-tool-sqlmap` |
| 7 | **Race Condition** | `bugexe-vuln-race-conditions`, `bugexe-method-race-conditions-methodology` | |
| 8 | **OAuth/OIDC** | `bugexe-vuln-oauth-oidc-attacks`, `bugexe-proto-oauth` | `bugexe-vuln-open-redirect` |
| 9 | **GraphQL** | `bugexe-vuln-graphql-attacks`, `bugexe-proto-graphql` | |
| 10 | **File Upload** | `bugexe-vuln-insecure-file-uploads`, `bugexe-method-upload-handler-enumeration` | `bugexe-vuln-path-traversal-lfi-rfi` |
| 11 | **Account Takeover** | `bugexe-vuln-account-takeover`, `bugexe-vuln-session-security` | `bugexe-vuln-predictable-token-enumeration` |
| 12 | **Cache Poisoning** | `bugexe-vuln-cache-poisoning`, `bugexe-vuln-web-cache-deception` | |
| 13 | **HTTP Smuggling** | `bugexe-vuln-http-request-smuggling`, `bugexe-vuln-crlf-injection` | `bugexe-vuln-header-injection` |
| 14 | **Prototype Pollution** | `bugexe-vuln-prototype-pollution` | |
| 15 | **SSTI** | `bugexe-vuln-ssti` | `bugexe-vuln-rce` |
| 16 | **Subdomain Takeover** | `bugexe-vuln-subdomain-takeover` | |
| 17 | **Payment/eCommerce** | `bugexe-vuln-payment-ecommerce` | `bugexe-vuln-race-conditions` |
| 18 | **AI/LLM** | `bugexe-vuln-ai-agent-security`, `bugexe-vuln-llm-ai-security` | |
| 19 | **Supply Chain** | `bugexe-vuln-supply-chain`, `bugexe-vuln-dependency-confusion` | `bugexe-vuln-cicd-security` |
| 20 | **RCE** | `bugexe-vuln-rce`, `bugexe-vuln-insecure-deserialization` | `bugexe-vuln-path-traversal-lfi-rfi`, `bugexe-vuln-xxe` |
| 21 | **CORS** | `bugexe-vuln-cors-misconfiguration` | `bugexe-vuln-csrf` |
| 22 | **WebSocket** | `bugexe-vuln-websocket-security` | |
| 23 | **Open Redirect** | `bugexe-vuln-open-redirect` | `bugexe-vuln-host-header-injection` |
| 24 | **Info Disclosure** | `bugexe-vuln-information-disclosure`, `bugexe-vuln-source-secret-detection` | `bugexe-vuln-public-credential-disclosure` |
| 25 | **Crypto Weakness** | `bugexe-vuln-cryptographic-weaknesses` | `bugexe-vuln-email-security` |

### Dynamic Tech-Stack Skill Loading

After recon populates `TECH_STACK`, load matching technology and framework skills into ALL hunt agents for that target:

**Framework detection → skill injection:**

| Detected Framework | Skill to Load |
|-------------------|---------------|
| Django | `bugexe-fw-django` |
| Express/Node.js | `bugexe-fw-express` |
| FastAPI | `bugexe-fw-fastapi` |
| Flask | `bugexe-fw-flask` |
| Laravel | `bugexe-fw-laravel` |
| NestJS | `bugexe-fw-nestjs` |
| Next.js | `bugexe-fw-nextjs` |
| Rails | `bugexe-fw-rails` |
| Spring Boot | `bugexe-fw-spring-boot` |
| WordPress | `bugexe-fw-wordpress` |
| .NET/ASP.NET | `bugexe-fw-dotnet` |

**Technology detection → skill injection:**

| Detected Technology | Skill to Load |
|--------------------|---------------|
| Firebase/Firestore | `bugexe-tech-firebase-firestore` |
| Supabase | `bugexe-tech-supabase` |
| Auth0 | `bugexe-tech-auth0` |
| Okta | `bugexe-tech-okta` |
| Cognito | `bugexe-tech-cognito` |
| Stripe | `bugexe-tech-stripe` |
| PayPal | `bugexe-tech-paypal` |
| Cloudflare | `bugexe-tech-cloudflare` |
| Cloudflare Workers | `bugexe-tech-cloudflare-workers` |
| AWS Lambda | `bugexe-tech-aws-lambda` |
| Nginx | `bugexe-tech-nginx` |
| Apache | `bugexe-tech-apache-httpd` |
| GraphQL/Apollo | `bugexe-tech-apollo` |
| Hasura | `bugexe-tech-hasura` |
| Docker | `bugexe-tech-docker` |
| React | `bugexe-tech-react` |
| Angular | `bugexe-tech-angular` |
| Vue | `bugexe-tech-vue` |
| Vercel | `bugexe-tech-vercel` |
| Netlify | `bugexe-tech-netlify` |
| Shopify | `bugexe-tech-shopify` |
| WordPress/WooCommerce | `bugexe-tech-wordpress`, `bugexe-tech-woocommerce` |
| Strapi | `bugexe-tech-strapi` |
| GitHub Actions | `bugexe-tech-github-actions` |

Max 5 tech/framework skills per hunter agent to avoid context saturation. Prioritize by relevance to the hunter's vuln class.

### Web3 Mode (if `--web3` or smart contract target detected)

When web3 mode is active, replace or supplement the standard vuln class matrix with web3-specific hunting. Load these skills:

**Core web3 skills (always in web3 mode):**
- `bugexe-web3-smart-contract-audit` — general smart contract methodology
- `bugexe-web3-evm-attack-vectors` — 100+ EVM attack patterns
- `bugexe-web3-solidity-analysis` — Solidity-specific analysis
- `bugexe-web3-math-precision-exploits` — math/precision bugs
- `bugexe-web3-token-integration-risks` — token standard edge cases

**Conditional web3 skills (load based on target type):**
- Vaults/yield: `bugexe-web3-erc4626-vault-security`
- Oracles/DeFi: `bugexe-web3-oracle-price-manipulation`, `bugexe-web3-defi-protocol-audit`
- MEV exposure: `bugexe-web3-mev-sandwich-attacks`
- Cross-chain/L2: `bugexe-web3-cross-chain-l2-security`, `bugexe-web3-bridge-async-state`
- Proxy/upgradeable: `bugexe-web3-proxy-upgrade-attacks`
- Gas/DoS: `bugexe-web3-gas-dos-griefing`
- Signatures: `bugexe-web3-signature-replay`, `bugexe-web3-permit-approval-abuse`
- Relayers: `bugexe-web3-relayer-meta-tx`
- Wallet/auth: `bugexe-web3-wallet-auth-binding`
- Economic: `bugexe-web3-invariant-economic-analysis`
- Bounty intel: `bugexe-web3-web3-bounty`
- Solana: `bugexe-web3-solana-security`, `bugexe-web3-solana-anchor-security`
- Cairo/StarkNet: `bugexe-web3-cairo-starknet-security`

### Spawning Hunt Agents

**Quick mode**: 1 agent, foreground.

**Core mode**: 5 agents, all parallel foreground in one message.

**Deep mode — Wave 1** (parallel, 7 agents):
- IDOR + Auth hunter (classes 1-2)
- XSS + CORS + Open Redirect hunter (classes 3, 21, 23)
- SSRF + RCE + SSTI hunter (classes 4, 15, 20)
- Business Logic + Race Condition hunter (classes 5, 7)
- SQLi + Info Disclosure hunter (classes 6, 24)
- Account Takeover + OAuth hunter (classes 8, 11)
- GraphQL + WebSocket hunter (classes 9, 22)

**Deep mode — Wave 2** (parallel, after Wave 1, 6 agents):
- File Upload + HTTP Smuggling hunter (classes 10, 13)
- Cache Poisoning + Prototype Pollution hunter (classes 12, 14)
- Payment + Crypto hunter (classes 17, 25)
- AI/LLM + Supply Chain + CI/CD hunter (classes 18, 19)
- Subdomain Takeover (class 16) — lightweight, single agent
- Web3 hunter (if web3 mode — loads all web3 skills)

### Hunter Agent Prompt Template

Each hunter agent receives:

```
You are a {VULN_CLASS} specialist bug bounty hunter.

## Target
- Domain: {target}
- Platform: {platform}
- In-scope: {scope}
- Out-of-scope: {exclusions}

## Your Methodology (from skills)
{Content from primary vuln class skills — read each SKILL.md and paste the methodology sections}

## Support Skills
{Content from support skills — framework-specific and tech-specific patterns}

## Technology Context
{Content from detected tech/framework skills — only the sections relevant to your vuln class}

## Attack Surface (prioritized)
{Content from surface.md — P1 endpoints relevant to your vuln class}

## Intel
{Relevant CVEs, disclosed reports, tech stack details from intel.md}

## Methodology Skills Loaded
{Content from bugexe-method-negative-testing if applicable}
{Content from bugexe-method-block-bypass-strategies if applicable}
{Content from bugexe-method-waf-bypass-hunter if WAF detected}
{Content from bugexe-method-frontend-backend-parity for web targets}

## Rules
- ONLY test in-scope assets. Check EVERY URL against the scope list.
- Document exact HTTP requests (method, URL, headers, body)
- Prove impact — not just "parameter reflects" but "XSS fires, cookie stolen"
- Write findings to {TARGET_DIR}/findings/findings-{vuln_class}.md

## Finding Format
### [SEV-NNN] Title

| Field | Value |
|-------|-------|
| Severity | Critical / High / Medium / Low |
| Asset | https://target.com/endpoint |
| Vuln Class | {vuln_class} |
| CVSS 3.1 | X.X |

**Summary**: One sentence.

**Steps to Reproduce**:
1. Navigate to ...
2. Intercept request with Burp/curl ...
3. Modify parameter X to ...
4. Observe ...

**HTTP Request**:
\`\`\`http
POST /api/endpoint HTTP/2
Host: target.com
...
\`\`\`

**HTTP Response** (relevant excerpt):
\`\`\`http
...
\`\`\`

**Impact**: What an attacker gains. Quantify.

**Fix**: Concrete recommendation.
```

### Source Code Audit (if --source)

If `--source` flag is set, also spawn in Wave 1:
- Read `~/.claude/skills/bugexe-custom-source-aware-sast/SKILL.md` for SAST methodology
- If web3 source: load `bugexe-web3-smart-contract-audit` + `bugexe-web3-solidity-analysis`
- Spawn source audit agent targeting the provided path
- Write to `{TARGET_DIR}/findings/findings-source.md`

### Archetype Skills (deep mode)

Based on target type detected from intel/recon, load one archetype skill for strategic context:

| Target Type | Archetype Skill |
|------------|----------------|
| SaaS B2B | `bugexe-arch-b2b-saas` |
| AI/SaaS | `bugexe-arch-ai-saas` |
| Fintech | `bugexe-arch-fintech` |
| Consumer auth | `bugexe-arch-consumer-auth` |
| Mobile API | `bugexe-arch-mobile-api` |
| Web3 app | `bugexe-arch-web3-app` |

**State checkpoint append:**
```
HUNT_OUTPUTS: [{TARGET_DIR}/findings/findings-idor.md, findings-xss.md, ...]
WAVES_COMPLETED: 1 | 2
SKILLS_LOADED: [list of all skills loaded across agents]
```

---

## Phase 3 — Validate & Chain

### Step 1 — Collect

Read all `{TARGET_DIR}/findings/findings-*.md` files.

### Step 2 — Validate (Skill-Backed Gate)

Load validation methodology from:
- `~/.claude/skills/bugexe-method-exploitability-validation/SKILL.md` — exploitability assessment
- `~/.claude/skills/bugexe-method-kill-signals/SKILL.md` — false positive detection
- `~/.claude/skills/bugexe-method-triage-validity/SKILL.md` — severity triage
- `~/.claude/skills/bugexe-method-proof-of-impact/SKILL.md` — impact quantification
- `~/.claude/skills/bugexe-method-evidence-templates/SKILL.md` — evidence formatting

Read `~/.claude/skills/claude-bug-bounty/agents/validator.md`. For each finding, apply:

| # | Question | Fail Action | Skill Source |
|---|----------|-------------|-------------|
| Q1 | Is the asset in scope? | KILL | scope check |
| Q2 | Is this bug class eligible for bounty? | KILL | scope check |
| Q3 | Can you reproduce with exact HTTP requests? | KILL | proof-of-impact |
| Q4 | Is impact real (not theoretical)? | KILL if "could potentially" | exploitability-validation |
| Q5 | Is this a duplicate of a known disclosed report? | KILL (check intel.md) | kill-signals |
| Q6 | Does it require victim interaction beyond clicking a link? | DOWNGRADE if complex | triage-validity |
| Q7 | Is the severity justified by actual impact? | ADJUST severity | triage-validity |

For `core` and `deep` modes: spawn validator agent with all findings for batch validation.
For `quick` mode: inline validation (orchestrator applies the gate directly).

### Step 3 — Chain Building (core + deep only)

Load chain building methodology from:
- `~/.claude/skills/bugexe-method-chain-building/SKILL.md` — **postcondition-to-precondition matching** (derived from 10,837 real bug bounty reports)

Read `~/.claude/skills/claude-bug-bounty/agents/chain-builder.md`. For each surviving Low/Medium finding:

Spawn **one chain-builder Agent** with:
- All validated findings
- Full chain-building skill methodology (the postcondition-to-precondition matching system)
- Known chain patterns:
  - IDOR → account takeover
  - SSRF → cloud metadata → RCE
  - XSS → session hijack → ATO
  - Open redirect → OAuth token theft
  - S3 miscfg → JS bundle → secrets → OAuth
  - Info disclosure → auth bypass
  - Race condition → balance manipulation
  - Cache poisoning → stored XSS → mass ATO
  - Subdomain takeover → cookie scope → session hijack
  - CORS misconfig → data exfiltration → account takeover
  - GraphQL introspection → hidden mutation → privilege escalation
  - Prototype pollution → RCE
  - SSTI → RCE
  - HTTP smuggling → cache poisoning → mass user impact
- Instruction: "For each finding, extract its postconditions (what state it creates). For each other finding, extract its preconditions (what state it needs). Match postconditions to preconditions across findings. For each chain, describe A→B→C sequence and the upgraded severity. Write to `{TARGET_DIR}/chains/`."

**Apply chain results**: Chains that work → upgrade the lead finding's severity. Note the chain in the finding description.

### Step 4 — Variant Hunting (deep mode only)

Load: `~/.claude/skills/bugexe-method-variant-hunting/SKILL.md`

For each CONFIRMED finding, spawn a quick variant check:
- Same bug class, adjacent endpoints
- Same endpoint, related parameters
- Same pattern, different HTTP methods
- Write variants to `{TARGET_DIR}/findings/findings-variants.md`

### Step 5 — Adversarial Rescan (deep mode only)

Load: `~/.claude/skills/bugexe-method-adversarial-rescan/SKILL.md`

Spawn 1 agent with the exclusion list of all found findings. Instruction: "Re-scan the P1 attack surface looking for findings the original hunters MISSED. Focus on what their attention was drawn away from."

### Step 6 — Sort and Number

Sort by severity: Critical → High → Medium → Low.
Number: C-01, H-01, M-01, L-01.

**State checkpoint append:**
```
VALIDATED_FINDINGS: [final list]
CHAINS_BUILT: N
KILLED_COUNT: N
VARIANTS_FOUND: N
```

---

## Phase 4 — Report Generation

Load report writing methodology:
- `~/.claude/skills/bugexe-method-evidence-templates/SKILL.md` — evidence formatting
- `~/.claude/skills/bugexe-method-poc-simplicity/SKILL.md` — PoC clarity
- `~/.claude/skills/bugexe-method-bounty-feedback-loop/SKILL.md` — platform-specific framing
- `~/.claude/skills/bugexe-method-reward-prioritization/SKILL.md` — reward optimization

Read `~/.claude/skills/claude-bug-bounty/agents/report-writer.md` and `~/.claude/skills/claude-bug-bounty/rules/reporting.md`.

For each validated finding, spawn a **report-writer Agent** (parallel, max 4 concurrent) with:
- The finding details
- Platform format (H1/Bugcrowd/Intigriti/Immunefi)
- All loaded report methodology skills
- Instruction: "Write a submission-ready report. Use concrete language — never 'could potentially'. Include exact HTTP requests, screenshots descriptions, and quantified impact. Write to `{TARGET_DIR}/reports/{finding-id}.md`."

### Platform-Specific Format

**HackerOne**:
```markdown
## Summary
## Steps To Reproduce
## Supporting Material/References
## Impact
```

**Bugcrowd**:
```markdown
## Description
## Steps to Reproduce
## Impact
## Remediation
```

**Immunefi** (web3):
```markdown
## Bug Description
## Impact
## Proof of Concept
## Recommendation
```

---

## Phase 5 — Summary

Print the final summary:

```
═══════════════════════════════════════
  Hunt Complete: {target}
  Mode: {MODE} | Platform: {PLATFORM}
═══════════════════════════════════════

  Findings: {N} total
    Critical:  {N}  ←  submit immediately
    High:      {N}  ←  submit today
    Medium:    {N}  ←  submit this week
    Low:       {N}  ←  chain candidates

  Chains built: {N} (upgraded {N} findings)
  Variants found: {N}
  Killed by validation: {N}
  Vuln classes tested: {list}
  Skills loaded: {N} across {N} agents
  Tech stack: {detected technologies}

  Reports: {TARGET_DIR}/reports/
  Intel:   {TARGET_DIR}/intel.md
  Recon:   {TARGET_DIR}/recon/
  Surface: {TARGET_DIR}/surface.md
  Chains:  {TARGET_DIR}/chains/

  ⚠  Review each report before submitting.
  ⚠  Never submit without reading the full report.
═══════════════════════════════════════
```

---

## Banner

Print before anything else:

```
██╗  ██╗██╗   ██╗███╗   ██╗████████╗
██║  ██║██║   ██║████╗  ██║╚══██╔══╝
███████║██║   ██║██╔██╗ ██║   ██║
██╔══██║██║   ██║██║╚██╗██║   ██║
██║  ██║╚██████╔╝██║ ╚████║   ██║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝
   Deep Bug Bounty Hunting Orchestrator
            279 skills loaded
```

---

## Skill Reference — Full Inventory

### Vulnerability Skills (64)

| Skill Directory | Vuln Class |
|----------------|-----------|
| `bugexe-vuln-idor` | IDOR |
| `bugexe-vuln-bola-systematic-enumeration` | BOLA |
| `bugexe-vuln-broken-function-level-authorization` | BFLA |
| `bugexe-vuln-authentication-jwt` | Auth/JWT |
| `bugexe-vuln-inconsistent-authentication` | Auth inconsistency |
| `bugexe-vuln-two-factor-bypass` | 2FA bypass |
| `bugexe-vuln-xss` | XSS |
| `bugexe-vuln-postmessage-security` | postMessage |
| `bugexe-vuln-spa-client-side` | SPA client-side |
| `bugexe-vuln-ssrf` | SSRF |
| `bugexe-vuln-dns-rebinding` | DNS rebinding |
| `bugexe-vuln-business-logic` | Business logic |
| `bugexe-vuln-sql-injection` | SQLi |
| `bugexe-vuln-nosql-injection` | NoSQLi |
| `bugexe-vuln-race-conditions` | Race conditions |
| `bugexe-vuln-oauth-oidc-attacks` | OAuth/OIDC |
| `bugexe-vuln-graphql-attacks` | GraphQL |
| `bugexe-vuln-insecure-file-uploads` | File upload |
| `bugexe-vuln-account-takeover` | ATO |
| `bugexe-vuln-session-security` | Sessions |
| `bugexe-vuln-predictable-token-enumeration` | Token prediction |
| `bugexe-vuln-cache-poisoning` | Cache poisoning |
| `bugexe-vuln-web-cache-deception` | Cache deception |
| `bugexe-vuln-http-request-smuggling` | HTTP smuggling |
| `bugexe-vuln-crlf-injection` | CRLF injection |
| `bugexe-vuln-header-injection` | Header injection |
| `bugexe-vuln-prototype-pollution` | Prototype pollution |
| `bugexe-vuln-ssti` | SSTI |
| `bugexe-vuln-subdomain-takeover` | Subdomain takeover |
| `bugexe-vuln-payment-ecommerce` | Payment/ecommerce |
| `bugexe-vuln-ai-agent-security` | AI agent |
| `bugexe-vuln-llm-ai-security` | LLM/AI |
| `bugexe-vuln-supply-chain` | Supply chain |
| `bugexe-vuln-dependency-confusion` | Dependency confusion |
| `bugexe-vuln-cicd-security` | CI/CD |
| `bugexe-vuln-rce` | RCE |
| `bugexe-vuln-insecure-deserialization` | Deserialization |
| `bugexe-vuln-path-traversal-lfi-rfi` | Path traversal/LFI/RFI |
| `bugexe-vuln-xxe` | XXE |
| `bugexe-vuln-cors-misconfiguration` | CORS |
| `bugexe-vuln-csrf` | CSRF |
| `bugexe-vuln-websocket-security` | WebSocket |
| `bugexe-vuln-open-redirect` | Open redirect |
| `bugexe-vuln-host-header-injection` | Host header |
| `bugexe-vuln-information-disclosure` | Info disclosure |
| `bugexe-vuln-source-secret-detection` | Secret detection |
| `bugexe-vuln-public-credential-disclosure` | Credential disclosure |
| `bugexe-vuln-cryptographic-weaknesses` | Crypto weakness |
| `bugexe-vuln-email-security` | Email security |
| `bugexe-vuln-email-header-injection` | Email header injection |
| `bugexe-vuln-clickjacking` | Clickjacking |
| `bugexe-vuln-mass-assignment` | Mass assignment |
| `bugexe-vuln-api-security` | API security |
| `bugexe-vuln-rate-limiting-bypass` | Rate limiting |
| `bugexe-vuln-resource-exhaustion-dos` | Resource exhaustion |
| `bugexe-vuln-http-parameter-pollution` | HPP |
| `bugexe-vuln-pdf-svg-injection` | PDF/SVG injection |
| `bugexe-vuln-php-type-juggling` | PHP type juggling |
| `bugexe-vuln-punycode-unicode` | Punycode/Unicode |
| `bugexe-vuln-second-order` | Second-order attacks |
| `bugexe-vuln-search-indexing-acl` | Search/indexing ACL |
| `bugexe-vuln-waf-bypass` | WAF bypass |
| `bugexe-vuln-webhook-callback-security` | Webhook/callback |
| `bugexe-vuln-kubernetes-misconfiguration` | K8s misconfig |

### Methodology Skills (44)

| Skill Directory | Purpose |
|----------------|---------|
| `bugexe-method-chain-building` | Postcondition→precondition chain matching |
| `bugexe-method-exploitability-validation` | Exploitability assessment |
| `bugexe-method-kill-signals` | False positive detection |
| `bugexe-method-proof-of-impact` | Impact quantification |
| `bugexe-method-evidence-templates` | Evidence formatting |
| `bugexe-method-variant-hunting` | Variant discovery |
| `bugexe-method-adversarial-rescan` | Attention saturation counter |
| `bugexe-method-state-machine-traversal` | State machine analysis |
| `bugexe-method-invariant-extraction` | Invariant discovery |
| `bugexe-method-cross-tenant-isolation` | Multi-tenant testing |
| `bugexe-method-business-logic-mapper` | Business flow mapping |
| `bugexe-method-auth-matrix-systematic` | Auth matrix testing |
| `bugexe-method-race-conditions-methodology` | Race condition methodology |
| `bugexe-method-threat-modeling` | Threat model construction |
| `bugexe-method-trust-boundary-mapping` | Trust boundary analysis |
| `bugexe-method-surface-discovery-pipeline` | Structured surface discovery |
| `bugexe-method-deep-recon-loops` | Iterative recon deepening |
| `bugexe-method-triage-validity` | Severity triage |
| `bugexe-method-bounty-feedback-loop` | Platform-specific optimization |
| `bugexe-method-reward-prioritization` | Reward ROI prioritization |
| `bugexe-method-poc-simplicity` | PoC clarity |
| `bugexe-method-negative-testing` | Negative test case generation |
| `bugexe-method-block-bypass-strategies` | Block/filter bypass |
| `bugexe-method-waf-bypass-hunter` | WAF-specific bypass |
| `bugexe-method-frontend-backend-parity` | Frontend/backend parity |
| `bugexe-method-oast-out-of-band` | Out-of-band testing |
| `bugexe-method-upload-handler-enumeration` | Upload handler enum |
| `bugexe-method-black-box-dynamic-orchestration` | Dynamic black-box testing |
| `bugexe-method-boundary-spec-violation` | Boundary/spec violation |
| `bugexe-method-code-understanding` | Code comprehension |
| `bugexe-method-coverage-matrix` | Coverage tracking |
| `bugexe-method-crash-analysis` | Crash analysis |
| `bugexe-method-ctf-solver` | CTF problem solving |
| `bugexe-method-exploit-development` | Exploit development |
| `bugexe-method-exploit-maturity` | Exploit maturity assessment |
| `bugexe-method-exploitation-raptor` | Rapid exploitation |
| `bugexe-method-micro-task-decomposition` | Task decomposition |
| `bugexe-method-oss-forensics` | OSS forensics |
| `bugexe-method-program-intelligence` | Program intel gathering |
| `bugexe-method-raptor-coverage` | Coverage optimization |
| `bugexe-method-research-pivots` | Research pivot strategy |
| `bugexe-method-sandbox-network-troubleshooting` | Sandbox networking |
| `bugexe-method-shared-context` | Context sharing |
| `bugexe-method-immunefi-hunting` | Immunefi-specific hunting |

### Recon Skills (42)

| Skill Directory | Purpose |
|----------------|---------|
| `bugexe-recon-attack-surface-mapping` | Asset discovery |
| `bugexe-recon-deep-subdomain-enum` | Subdomain enumeration |
| `bugexe-recon-api-endpoint-discovery` | API surface mapping |
| `bugexe-recon-js-analysis` | JS endpoint/secret extraction |
| `bugexe-recon-parameter-discovery` | Parameter mining |
| `bugexe-recon-url-crawl` | URL crawling |
| `bugexe-recon-waf-detection` | WAF fingerprinting |
| `bugexe-recon-github-dorking` | GitHub dorking |
| `bugexe-recon-google-dorking` | Google dorking |
| `bugexe-recon-nuclei-workflow` | Nuclei scanning |
| `bugexe-recon-target-mapping` | Infrastructure mapping |
| `bugexe-recon-shodan-dorking` | Shodan discovery |
| `bugexe-recon-cloud-bucket-dorking` | Cloud bucket enum |
| `bugexe-recon-code-search-dorking` | Code search dorking |
| `bugexe-recon-postman-workspace-dorking` | Postman collection discovery |
| `bugexe-recon-wayback-cdx-dorking` | Wayback historical mining |
| `bugexe-recon-js-deobfuscation` | JS deobfuscation |
| `bugexe-recon-fast-recon` | Quick recon pass |
| `bugexe-recon-deep-recon-bb` | Deep bug bounty recon |
| `bugexe-recon-endpoint-enum-script` | Endpoint enumeration |
| `bugexe-recon-dorking-orchestration` | Dork orchestration |
| `bugexe-recon-fofa-zoomeye-dorking` | FOFA/ZoomEye |
| `bugexe-recon-gitlab-bitbucket-dorking` | GitLab/Bitbucket |
| `bugexe-recon-pastebin-dorking` | Pastebin/paste sites |
| `bugexe-recon-bbrecon-methodology` | BB recon methodology |
| `bugexe-recon-recon-*` | 17 additional specialized recon modules |

### Web3 Skills (22)

| Skill Directory | Purpose |
|----------------|---------|
| `bugexe-web3-smart-contract-audit` | General smart contract |
| `bugexe-web3-evm-attack-vectors` | 100+ EVM attack patterns |
| `bugexe-web3-solidity-analysis` | Solidity analysis |
| `bugexe-web3-erc4626-vault-security` | ERC4626 vault |
| `bugexe-web3-oracle-price-manipulation` | Oracle manipulation |
| `bugexe-web3-defi-protocol-audit` | DeFi protocol |
| `bugexe-web3-math-precision-exploits` | Math/precision |
| `bugexe-web3-mev-sandwich-attacks` | MEV/sandwich |
| `bugexe-web3-cross-chain-l2-security` | Cross-chain/L2 |
| `bugexe-web3-bridge-async-state` | Bridge async state |
| `bugexe-web3-proxy-upgrade-attacks` | Proxy/upgrade |
| `bugexe-web3-gas-dos-griefing` | Gas/DoS |
| `bugexe-web3-signature-replay` | Signature replay |
| `bugexe-web3-permit-approval-abuse` | Permit/approval |
| `bugexe-web3-relayer-meta-tx` | Relayer/meta-tx |
| `bugexe-web3-wallet-auth-binding` | Wallet/auth binding |
| `bugexe-web3-token-integration-risks` | Token integration |
| `bugexe-web3-invariant-economic-analysis` | Economic analysis |
| `bugexe-web3-web3-bounty` | Web3 bounty intel |
| `bugexe-web3-solana-security` | Solana security |
| `bugexe-web3-solana-anchor-security` | Anchor framework |
| `bugexe-web3-cairo-starknet-security` | Cairo/StarkNet |

### Framework Skills (11), Technology Skills (55), Tool Skills (15), Playbook Skills (8), Cloud Skills (4), Archetype Skills (6), Mobile Skills (2), Protocol Skills (5), Custom Skills (1)

Loaded dynamically based on tech stack detection. See directories:
- `~/.claude/skills/bugexe-fw-*` (11 frameworks)
- `~/.claude/skills/bugexe-tech-*` (55 technologies)
- `~/.claude/skills/bugexe-tool-*` (15 tools)
- `~/.claude/skills/bugexe-playbook-*` (8 playbooks)
- `~/.claude/skills/bugexe-cloud-*` (4 cloud providers)
- `~/.claude/skills/bugexe-arch-*` (6 archetypes)
- `~/.claude/skills/bugexe-mobile-*` (2 mobile)
- `~/.claude/skills/bugexe-proto-*` (5 protocols)
- `~/.claude/skills/bugexe-custom-*` (1 custom)

### Existing Claude Bug Bounty Skills (unchanged)

| Skill | Path |
|-------|------|
| recon-agent | `~/.claude/skills/claude-bug-bounty/agents/recon-agent.md` |
| recon-ranker | `~/.claude/skills/claude-bug-bounty/agents/recon-ranker.md` |
| chain-builder | `~/.claude/skills/claude-bug-bounty/agents/chain-builder.md` |
| validator | `~/.claude/skills/claude-bug-bounty/agents/validator.md` |
| report-writer | `~/.claude/skills/claude-bug-bounty/agents/report-writer.md` |
| autopilot | `~/.claude/skills/claude-bug-bounty/agents/autopilot.md` |
| intel command | `~/.claude/skills/claude-bug-bounty/commands/intel.md` |
| hunting rules | `~/.claude/skills/claude-bug-bounty/rules/hunting.md` |
| reporting rules | `~/.claude/skills/claude-bug-bounty/rules/reporting.md` |
