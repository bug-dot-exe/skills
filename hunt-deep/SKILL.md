---
name: hunt-deep
description: >
  Unified bug bounty hunting orchestrator with 279 specialized skills, merged with the TTM depth discipline (invariant-binding, evidence calibration, proof ladder, negative knowledge, capability-delta reporting).
  Full pipeline: scope → intel → recon → parallel hunt (25 vuln classes) → validate → chain → report.
  Trigger on "/hunt-deep", "/hunt", "hunt this target", "full bug bounty hunt".
---

# Deep Bug Bounty Hunting Orchestrator

You are the lead orchestrator of a multi-agent bug bounty hunt. You load scope, gather intel, run recon with specialized skill-backed agents, rank attack surface, spawn parallel hunters for every relevant vuln class, validate findings with methodology skills, build chains using postcondition-to-precondition matching, and generate submission-ready reports.

## Hunting Principles

Sometimes you only need a tiny missing piece to get pure solid critical.
- Fan out subagents.
- Keep digging unexplored attack surfaces.
- Note down every single piece that is weird.
- Map attack surfaces to the deepest.
- Audit the deepest, each single line of code.
- Ultrathink to get pure solid findings.
- Only critical findings matter.
- Map reachable attacker input.
- Trace to sensitive sinks or invariants.
- Report only concrete, production-reachable vulnerabilities.

## TTM Depth Discipline (merged — applies to EVERY phase)

Full merged reference: `C:\Users\pc\OneDrive - BIM ADVANCED TECHNOLOGY SERVICES PTE. LTD\Apple_Research\workflows\ttm-hunt-orchestrator.v20260817.md`

- **Confidence rubric** (closed scale, never free text): CONFIRMED = source_code +
  dynamic_test; STRONG = source + config; PLAUSIBLE = one evidence type;
  SPECULATIVE = inference only; CONTESTED = evidence disagrees (preserve the
  contradiction, route to the gauntlet).
- **Evidence anchors**: every non-unknown claim carries `file:line` (else
  `unknown`). Inventing an anchor is the only unrecoverable error.
- **Proof ladder**: T0 pattern → T1 file:line → T2 survived gauntlet → T3
  chained across a boundary → T4 runtime-proven. Nothing below T4 is CONFIRMED.
  Never claim a PoC that was not executed.
- **Subject differential**: access-control claims need two subjects against the
  SAME object, route, and parameters. A privileged-actor demo proves mechanism,
  not privilege crossing.
- **Role-sweep mandate**: authenticate every provided credential serially
  before testing; a 403 to one role proves nothing — re-test with each role.
- **Negative knowledge is a deliverable**: record refuted hypotheses and the
  guard that holds — falsified paths carry a reason for the next run.
- **Coverage attestation**: record every (surface × class) CONSIDERED —
  input-handling, authz, state/workflow, auth/session — with outcome. Blank
  cells are work items, not passes.
- **Knowledge persistence**: read prior knowledge (product + topology) in
  Phase 0; commit facts/falsified paths/risk patterns at the end — even on a
  zero-finding run. Never store verdicts cross-run (anti-anchoring).
- **Gate chain**: reachability → accessibility → exploitability, in order.
  Code existing is not reachability.

## opencode Execution Notes (replaces Claude Code mechanics)

- Subagents are spawned via the **Task tool** (`explore` for code discovery,
  `general` for intel/recon/hunting/validation/reporting). Parallel = multiple
  Task calls in one message. Every "spawn Agent" below means one Task call
  whose result you wait for before continuing that branch.
- Skill paths below are absolute vendor paths; the subagent can either read
  the SKILL.md at that path or load the skill by its directory name (e.g.
  `idor`) with the skill tool.
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\claude-bug-bounty/*` does not exist in this environment.
  Equivalents (load by name): intel → `program_intelligence`; recon-ranker →
  `threat_modeling` + `trust_boundary_mapping`; validator → `triage-validation`
  + `kill_signals` + `exploitability_validation`; chain-builder →
  `chain_building`; report-writer/reporting rules → `report-writing`.
- Runtime validation (T4) uses the Caido MCP tools: caido_send_request,
  caido_edit_request, caido_batch_send, caido_race_window_send — manual,
  low-rate, in-scope only.
- Apple or `--platform internal` targets: force passive mode — no
  ffuf/nuclei/katana sweeps against production; active testing is manual Caido
  replay on accounts you own.

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

Spawn **2 parallel subagents via the Task tool** (foreground = wait for both results):

### Agent A — Intel Gatherer

Read skill `program_intelligence`. Spawn Agent with:
- The program_intelligence methodology
- Target name and scope
- Instruction: "Gather intel on this target: CVEs for their tech stack, disclosed reports on HackerOne/Bugcrowd, recent features/changes, past bounty payouts. Write to `{TARGET_DIR}/intel.md`."

### Agent B — Skill-Backed Recon Pipeline

Spawn Agent with the following skills loaded (read each SKILL.md and include the methodology in the agent prompt):

**Core recon skills (always load):**
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\attack-surface-mapping/SKILL.md` — asset discovery and mapping
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\deep-subdomain-enumeration/SKILL.md` — subdomain enumeration
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\api-endpoint-discovery/SKILL.md` — API surface mapping
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\js-analysis/SKILL.md` — JavaScript secret/endpoint extraction
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\parameter-discovery/SKILL.md` — parameter mining
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\url-crawling-historical-mining/SKILL.md` — URL discovery and crawling
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\waf-detection/SKILL.md` — WAF fingerprinting

**Extended recon skills (core + deep modes):**
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\github-dorking/SKILL.md` — GitHub secret/config dorking
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\google-dorking/SKILL.md` — Google dork enumeration
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\nuclei-workflow/SKILL.md` — nuclei template scanning
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\target-mapping/SKILL.md` — infrastructure mapping
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\shodan-dorking/SKILL.md` — Shodan asset discovery
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\surface-discovery-pipeline/SKILL.md` — structured surface discovery
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\deep-recon-loops/SKILL.md` — iterative recon deepening

**Deep mode additional recon skills:**
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\cloud-bucket-dorking/SKILL.md` — cloud storage enumeration
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\code-search-dorking/SKILL.md` — code search across platforms
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\postman-workspace-dorking/SKILL.md` — Postman collection discovery
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\wayback-cdx-dorking/SKILL.md` — historical endpoint mining
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\js-deobfuscation/SKILL.md` — JS deobfuscation and analysis
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\recon-vhost-fuzzing/SKILL.md` — virtual host discovery

Agent B instruction: "Run full recon pipeline using the loaded skill methodologies. Write output to `{TARGET_DIR}/recon/`. Produce: `live-hosts.txt`, `urls.txt`, `js-secrets.txt`, `nuclei-results.txt`, `params.txt`, `tech-stack.txt`, `api-endpoints.txt`. Detect tech stack (frameworks, languages, CDN, WAF, cloud provider) and write to `tech-stack.txt`."

### After Both Complete — Attack Surface Ranking

Read skills `threat_modeling` + `trust_boundary_mapping` (replaces recon-ranker agent spec). Spawn **one Agent** with:
- The threat_modeling + trust_boundary_mapping methodologies
- Paths to `{TARGET_DIR}/recon/` and `{TARGET_DIR}/intel.md`
- Also load: `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\threat-modeling/SKILL.md` and `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\trust-boundary-mapping/SKILL.md`
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

Fan-out is keyed on ATTACK SURFACES first, classes second: assign each
subagent a concrete surface from `surface.md` (P1 first) and give it the
vuln classes most likely for that surface. A surface without a worker is a
blind spot — the Phase 3 loop exists to catch exactly that.

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
| 1 | **IDOR** | `idor`, `bola-systematic-enumeration` | `broken-function-level-authorization` |
| 2 | **Auth Bypass** | `authentication-jwt`, `inconsistent-authentication` | `two-factor-bypass`, `auth-matrix-systematic` |
| 3 | **XSS** | `xss`, `postmessage-security` | `spa-client-side`, `punycode-unicode` |
| 4 | **SSRF** | `ssrf`, `dns-rebinding` | `oast-out-of-band` |
| 5 | **Business Logic** | `business-logic`, `business-logic-mapper` | `state-machine-traversal`, `invariant-extraction` |
| 6 | **SQLi** | `sql-injection`, `nosql-injection` | `sqlmap` |
| 7 | **Race Condition** | `race-conditions`, `race-conditions-methodology` | |
| 8 | **OAuth/OIDC** | `oauth-oidc-attacks`, `oauth` | `open-redirect` |
| 9 | **GraphQL** | `graphql-attacks`, `graphql` | |
| 10 | **File Upload** | `insecure-file-uploads`, `upload-handler-enumeration` | `path-traversal-lfi-rfi` |
| 11 | **Account Takeover** | `account-takeover`, `session-security` | `predictable-token-enumeration` |
| 12 | **Cache Poisoning** | `cache-poisoning`, `web-cache-deception` | |
| 13 | **HTTP Smuggling** | `http-request-smuggling`, `crlf-injection` | `header-injection` |
| 14 | **Prototype Pollution** | `prototype-pollution` | |
| 15 | **SSTI** | `ssti` | `rce` |
| 16 | **Subdomain Takeover** | `subdomain-takeover` | |
| 17 | **Payment/eCommerce** | `value-transfer-workflows` | `race-conditions` |
| 18 | **AI/LLM** | `ai-agent-security`, `llm-ai-security` | |
| 19 | **Supply Chain** | `supply-chain`, `dependency-confusion` | `cicd-security` |
| 20 | **RCE** | `rce`, `insecure-deserialization` | `path-traversal-lfi-rfi`, `xxe` |
| 21 | **CORS** | `cors-misconfiguration` | `csrf` |
| 22 | **WebSocket** | `websocket-security` | |
| 23 | **Open Redirect** | `open-redirect` | `host-header-injection` |
| 24 | **Info Disclosure** | `information-disclosure`, `source-secret-detection` | `public-credential-disclosure` |
| 25 | **Crypto Weakness** | `cryptographic-weaknesses` | `email-security` |

### Dynamic Tech-Stack Skill Loading

After recon populates `TECH_STACK`, load matching technology and framework skills into ALL hunt agents for that target:

**Framework detection → skill injection:**

| Detected Framework | Skill to Load |
|-------------------|---------------|
| Django | `django` |
| Express/Node.js | `express` |
| FastAPI | `fastapi` |
| Flask | `flask` |
| Laravel | `laravel` |
| NestJS | `nestjs` |
| Next.js | `nextjs` |
| Rails | `rails` |
| Spring Boot | `spring-boot` |
| WordPress | `wordpress` |
| .NET/ASP.NET | `dotnet` |

**Technology detection → skill injection:**

| Detected Technology | Skill to Load |
|--------------------|---------------|
| Firebase/Firestore | `firebase-firestore` |
| Supabase | `supabase` |
| Auth0 | `auth0` |
| Okta | `okta` |
| Cognito | `cognito` |
| Stripe | `stripe` |
| PayPal | `paypal` |
| Cloudflare | `cloudflare` |
| Cloudflare Workers | `cloudflare-workers` |
| AWS Lambda | `aws-lambda` |
| Nginx | `nginx` |
| Apache | `apache-httpd` |
| GraphQL/Apollo | `apollo` |
| Hasura | `hasura` |
| Docker | `docker` |
| React | `react` |
| Angular | `angular` |
| Vue | `vue` |
| Vercel | `vercel` |
| Netlify | `netlify` |
| Shopify | `shopify` |
| WordPress/WooCommerce | `tech-wordpress`, `woocommerce` |
| Strapi | `strapi` |
| GitHub Actions | `github-actions` |

Max 5 tech/framework skills per hunter agent to avoid context saturation. Prioritize by relevance to the hunter's vuln class.

### Web3 Mode (if `--web3` or smart contract target detected)

When web3 mode is active, replace or supplement the standard vuln class matrix with web3-specific hunting. Load these skills:

**Core web3 skills (always in web3 mode):**
- `web3-smart-contract-audit` — general smart contract methodology
- `evm-attack-vectors` — 100+ EVM attack patterns
- `solidity-analysis` — Solidity-specific analysis
- `math-precision-exploits` — math/precision bugs
- `token-integration-risks` — token standard edge cases

**Conditional web3 skills (load based on target type):**
- Vaults/yield: `erc4626-vault-security`
- Oracles/DeFi: `oracle-price-manipulation`, `defi-protocol-audit`
- MEV exposure: `mev-sandwich-attacks`
- Cross-chain/L2: `cross-chain-l2-security`, `bridge-async-state`
- Proxy/upgradeable: `proxy-upgrade-attacks`
- Gas/DoS: `gas-dos-griefing`
- Signatures: `signature-replay`, `permit-approval-abuse`
- Relayers: `relayer-meta-tx`
- Wallet/auth: `wallet-auth-binding`
- Economic: `invariant-economic-analysis`
- Bounty intel: `web3-bounty`
- Solana: `solana-security`, `solana-anchor-security`
- Cairo/StarkNet: `cairo-starknet-security`

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
{Content from negative-testing if applicable}
{Content from block-bypass-strategies if applicable}
{Content from waf-bypass-hunter if WAF detected}
{Content from frontend-backend-parity for web targets}

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
- Read `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\source-aware-sast/SKILL.md` for SAST methodology
- If web3 source: load `web3-smart-contract-audit` + `solidity-analysis`
- Spawn source audit agent targeting the provided path
- Write to `{TARGET_DIR}/findings/findings-source.md`

### Archetype Skills (deep mode)

Based on target type detected from intel/recon, load one archetype skill for strategic context:

| Target Type | Archetype Skill |
|------------|----------------|
| SaaS B2B | `b2b-saas` |
| AI/SaaS | `ai-saas` |
| Fintech | `state-mutation-workflows` |
| Consumer auth | `consumer-auth` |
| Mobile API | `mobile-api` |
| Web3 app | `web3-app` |

**State checkpoint append:**
```
HUNT_OUTPUTS: [{TARGET_DIR}/findings/findings-idor.md, findings-xss.md, ...]
WAVES_COMPLETED: 1 | 2
SKILLS_LOADED: [list of all skills loaded across agents]
```

---

## Phase 3 — Validate, Rescan Loop & Chain

The Conjure loop: validate → blind-spot rescan from the start → variant sweep
per vuln → blind-spot recheck → chain building last.

### Step 1 — Collect

Read all `{TARGET_DIR}/findings/findings-*.md` files.

### Step 2 — Validate (Skill-Backed Gate)

Load validation methodology from:
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\method-exploitability-validation/SKILL.md` — exploitability assessment
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\kill-signals/SKILL.md` — false positive detection
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\triage-validity/SKILL.md` — severity triage
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\proof-of-impact/SKILL.md` — impact quantification
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\evidence-templates/SKILL.md` — evidence formatting

Read skills `triage-validation`, `kill_signals`, `exploitability_validation`. For each finding, apply:

| # | Question | Fail Action | Skill Source |
|---|----------|-------------|-------------|
| Q1 | Is the asset in scope? | KILL | scope check |
| Q2 | Is this bug class eligible for bounty? | KILL | scope check |
| Q3 | Can you reproduce with exact HTTP requests? | KILL | proof-of-impact |
| Q4 | Is impact real (not theoretical)? | KILL if "could potentially" | exploitability-validation |
| Q5 | Is this a duplicate of a known disclosed report? | KILL (check intel.md) | kill-signals |
| Q6 | Does it require victim interaction beyond clicking a link? | DOWNGRADE if complex | triage-validity |
| Q7 | Is the severity justified by actual impact? | ADJUST severity | triage-validity |

**TTM deep questions — resolve BEFORE any auth/token/scope finding survives:**
- What token types exist and how are they differentiated? (Read the token
  creation/validation code.)
- Does the affected endpoint validate the token type?
- Do ID namespaces prevent cross-type confusion?
- What scope enforcement exists?
- **Temporal validity**: TTL of the credential vs alternatives (a 24-hour
  session vs a 5-minute access token changes exploitability).
- **Routing/dispatch reachability**: does the bypass path actually route to
  actionable code through the framework's dispatch layer?
- **Concrete victim impact**: trace to what the victim actually experiences —
  a scary mechanism is not impact.
- **Capability delta**: state what the attacker gains BEYOND the preconditions.
  If preconditions already grant equivalent capability, frame as
  defense-in-depth, not escalation.

For `core` and `deep` modes: spawn validator agent with all findings for batch validation.
For `quick` mode: inline validation (orchestrator applies the gate directly).

### Step 3 — Blind-Spot Rescan (fresh from the start; core + deep)

Load: `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\adversarial-rescan/SKILL.md`

The first wave found what its attention was drawn to. Now re-scan the WHOLE
attack surface fresh from the start, NOT the first wave's leftovers:

- Spawn fresh agents with an exclusion list of every finding filed so far:
  "ALREADY KNOWN — do not re-report: <finding-id> + one-sentence root cause".
- Same surface, fresh angle. Find what the first wave MISSED.
- Blind spots are the deliverable: surfaces never mapped, leads never
  explored, endpoints observed in recon but never hypothesis-tested,
  classes nobody claimed.
- Cap: 5 rescan agents per scan. Cheap-target exception: skip when
  scanned_endpoints <= 5 AND first_wave_findings <= 3.
- Write rescan findings to `{TARGET_DIR}/findings/findings-rescan.md`.

### Step 4 — Variant Sweep (per vuln, per surface; core + deep)

Load: `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\variant-hunting/SKILL.md`

For EACH CONFIRMED finding, sweep its primitive across the whole surface map:

- Found SQLi at /login? → test SQLi at EVERY endpoint, EVERY parameter,
  EVERY HTTP method that takes input.
- Found BOLA on /resource_a/{id}? → test the same cross-actor gap on every
  other ID-shaped resource path.
- Found a state-mutation primitive on endpoint A? → same primitive on every
  sibling state-mutation endpoint.
- Found one verb of an N-verb workflow? → same root cause on every sibling
  verb.

Variant briefs are one line: "Test {primitive} on {sibling surface} using
{same technique}." Write to `{TARGET_DIR}/findings/findings-variants.md`.

### Step 5 — Blind-Spot Recheck (after variants)

The variant sweep changed the map — run the blind-spot lens AGAIN:

- Every endpoint observed in recon that still has NO tested hypothesis gets
  its single most likely hypothesis, and a worker.
- Every filed class that never propagated to the new variant surfaces is a
  gap — either test it or mark N/A with a reason.
- Every surface without a coverage attestation cell is a work item, not a
  pass.

### Step 6 — Chain Building (LAST — upgrade low/medium to high/critical)

Load chain building methodology from:
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\chain-building/SKILL.md` — **postcondition-to-precondition matching** (derived from 10,837 real bug bounty reports)

Read skill `chain_building` (postcondition-to-precondition matching). For each surviving Low/Medium finding:

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

**Apply chain results**: Chains that work → upgrade the lead finding's severity. Note the chain in the finding description. This runs LAST so chains are built from the complete, re-scanned, variant-swept finding set — not from first-wave leftovers.

### Step 7 — Sort and Number

Sort by severity: Critical → High → Medium → Low.
Number: C-01, H-01, M-01, L-01.

### Step 8 — TTM Finish Gates (bounded retries — each yields after N refusals)

1. **Variant coverage**: every filed class tested (or marked N/A) on every
   input-bearing surface.
2. **Rescan coverage**: every finding-bearing surface re-examined
   adversarially with an exclusion list ("do not re-report: <finding>").
3. **Hypothesis closure**: no hypothesis left `open` — each confirmed,
   falsified (with reason), or explicitly re-scoped.
4. **Coverage-gap pass**: every observed-but-untested endpoint got its most
   likely single hypothesis.

### Step 9 — Knowledge Commit (always, even on a zero-finding run)

Write to `{TARGET_DIR}/knowledge.md`, keyed `product + topology_id`:
new confirmed facts, falsified paths WITH reason, risk patterns observed,
updated root-cause clusters. A run that leaves this empty did half the job.

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
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\evidence-templates/SKILL.md` — evidence formatting
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\poc-simplicity/SKILL.md` — PoC clarity
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\bounty-feedback-loop/SKILL.md` — platform-specific framing
- `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\reward-prioritization/SKILL.md` — reward optimization

Read skill `report-writing` (replaces report-writer agent spec + reporting rules).

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
| `idor` | IDOR |
| `bola-systematic-enumeration` | BOLA |
| `broken-function-level-authorization` | BFLA |
| `authentication-jwt` | Auth/JWT |
| `inconsistent-authentication` | Auth inconsistency |
| `two-factor-bypass` | 2FA bypass |
| `xss` | XSS |
| `postmessage-security` | postMessage |
| `spa-client-side` | SPA client-side |
| `ssrf` | SSRF |
| `dns-rebinding` | DNS rebinding |
| `business-logic` | Business logic |
| `sql-injection` | SQLi |
| `nosql-injection` | NoSQLi |
| `race-conditions` | Race conditions |
| `oauth-oidc-attacks` | OAuth/OIDC |
| `graphql-attacks` | GraphQL |
| `insecure-file-uploads` | File upload |
| `account-takeover` | ATO |
| `session-security` | Sessions |
| `predictable-token-enumeration` | Token prediction |
| `cache-poisoning` | Cache poisoning |
| `web-cache-deception` | Cache deception |
| `http-request-smuggling` | HTTP smuggling |
| `crlf-injection` | CRLF injection |
| `header-injection` | Header injection |
| `prototype-pollution` | Prototype pollution |
| `ssti` | SSTI |
| `subdomain-takeover` | Subdomain takeover |
| `value-transfer-workflows` | Payment/ecommerce |
| `ai-agent-security` | AI agent |
| `llm-ai-security` | LLM/AI |
| `supply-chain` | Supply chain |
| `dependency-confusion` | Dependency confusion |
| `cicd-security` | CI/CD |
| `rce` | RCE |
| `insecure-deserialization` | Deserialization |
| `path-traversal-lfi-rfi` | Path traversal/LFI/RFI |
| `xxe` | XXE |
| `cors-misconfiguration` | CORS |
| `csrf` | CSRF |
| `websocket-security` | WebSocket |
| `open-redirect` | Open redirect |
| `host-header-injection` | Host header |
| `information-disclosure` | Info disclosure |
| `source-secret-detection` | Secret detection |
| `public-credential-disclosure` | Credential disclosure |
| `cryptographic-weaknesses` | Crypto weakness |
| `email-security` | Email security |
| `email-header-injection` | Email header injection |
| `clickjacking` | Clickjacking |
| `mass-assignment` | Mass assignment |
| `api-security` | API security |
| `rate-limiting-bypass` | Rate limiting |
| `resource-exhaustion-dos` | Resource exhaustion |
| `http-parameter-pollution` | HPP |
| `pdf-svg-injection` | PDF/SVG injection |
| `php-type-juggling` | PHP type juggling |
| `punycode-unicode` | Punycode/Unicode |
| `second-order` | Second-order attacks |
| `search-indexing-acl` | Search/indexing ACL |
| `waf-bypass` | WAF bypass |
| `webhook-callback-security` | Webhook/callback |
| `kubernetes-misconfiguration` | K8s misconfig |

### Methodology Skills (44)

| Skill Directory | Purpose |
|----------------|---------|
| `chain-building` | Postcondition→precondition chain matching |
| `method-exploitability-validation` | Exploitability assessment |
| `kill-signals` | False positive detection |
| `proof-of-impact` | Impact quantification |
| `evidence-templates` | Evidence formatting |
| `variant-hunting` | Variant discovery |
| `adversarial-rescan` | Attention saturation counter |
| `state-machine-traversal` | State machine analysis |
| `invariant-extraction` | Invariant discovery |
| `cross-tenant-isolation` | Multi-tenant testing |
| `business-logic-mapper` | Business flow mapping |
| `auth-matrix-systematic` | Auth matrix testing |
| `race-conditions-methodology` | Race condition methodology |
| `threat-modeling` | Threat model construction |
| `trust-boundary-mapping` | Trust boundary analysis |
| `surface-discovery-pipeline` | Structured surface discovery |
| `deep-recon-loops` | Iterative recon deepening |
| `triage-validity` | Severity triage |
| `bounty-feedback-loop` | Platform-specific optimization |
| `reward-prioritization` | Reward ROI prioritization |
| `poc-simplicity` | PoC clarity |
| `negative-testing` | Negative test case generation |
| `block-bypass-strategies` | Block/filter bypass |
| `waf-bypass-hunter` | WAF-specific bypass |
| `frontend-backend-parity` | Frontend/backend parity |
| `oast-out-of-band` | Out-of-band testing |
| `upload-handler-enumeration` | Upload handler enum |
| `black-box-dynamic-orchestration` | Dynamic black-box testing |
| `boundary-spec-violation` | Boundary/spec violation |
| `method-code-understanding` | Code comprehension |
| `coverage-matrix` | Coverage tracking |
| `method-crash-analysis` | Crash analysis |
| `ctf-solver` | CTF problem solving |
| `exploit-development` | Exploit development |
| `exploit-maturity` | Exploit maturity assessment |
| `exploitation-raptor` | Rapid exploitation |
| `micro-task-decomposition` | Task decomposition |
| `method-oss-forensics` | OSS forensics |
| `program-intelligence` | Program intel gathering |
| `raptor-coverage` | Coverage optimization |
| `research-pivots` | Research pivot strategy |
| `sandbox-network-troubleshooting` | Sandbox networking |
| `shared-context` | Context sharing |
| `bounty-hunting-strategy` | Immunefi-specific hunting |

### Recon Skills (42)

| Skill Directory | Purpose |
|----------------|---------|
| `attack-surface-mapping` | Asset discovery |
| `deep-subdomain-enumeration` | Subdomain enumeration |
| `api-endpoint-discovery` | API surface mapping |
| `js-analysis` | JS endpoint/secret extraction |
| `parameter-discovery` | Parameter mining |
| `url-crawling-historical-mining` | URL crawling |
| `waf-detection` | WAF fingerprinting |
| `github-dorking` | GitHub dorking |
| `google-dorking` | Google dorking |
| `nuclei-workflow` | Nuclei scanning |
| `target-mapping` | Infrastructure mapping |
| `shodan-dorking` | Shodan discovery |
| `cloud-bucket-dorking` | Cloud bucket enum |
| `code-search-dorking` | Code search dorking |
| `postman-workspace-dorking` | Postman collection discovery |
| `wayback-cdx-dorking` | Wayback historical mining |
| `js-deobfuscation` | JS deobfuscation |
| `fast-recon` | Quick recon pass |
| `deep-recon-for-bug-bounties` | Deep bug bounty recon |
| `endpoint-enumeration-scripts` | Endpoint enumeration |
| `dorking-orchestration` | Dork orchestration |
| `fofa-zoomeye-dorking` | FOFA/ZoomEye |
| `gitlab-bitbucket-dorking` | GitLab/Bitbucket |
| `pastebin-dorking` | Pastebin/paste sites |
| `bbrecon-methodology` | BB recon methodology |
| `recon-*` (17 deep-recon modules) | Additional specialized recon modules |

### Web3 Skills (22)

| Skill Directory | Purpose |
|----------------|---------|
| `web3-smart-contract-audit` | General smart contract |
| `evm-attack-vectors` | 100+ EVM attack patterns |
| `solidity-analysis` | Solidity analysis |
| `erc4626-vault-security` | ERC4626 vault |
| `oracle-price-manipulation` | Oracle manipulation |
| `defi-protocol-audit` | DeFi protocol |
| `math-precision-exploits` | Math/precision |
| `mev-sandwich-attacks` | MEV/sandwich |
| `cross-chain-l2-security` | Cross-chain/L2 |
| `bridge-async-state` | Bridge async state |
| `proxy-upgrade-attacks` | Proxy/upgrade |
| `gas-dos-griefing` | Gas/DoS |
| `signature-replay` | Signature replay |
| `permit-approval-abuse` | Permit/approval |
| `relayer-meta-tx` | Relayer/meta-tx |
| `wallet-auth-binding` | Wallet/auth binding |
| `token-integration-risks` | Token integration |
| `invariant-economic-analysis` | Economic analysis |
| `web3-bounty` | Web3 bounty intel |
| `solana-security` | Solana security |
| `solana-anchor-security` | Anchor framework |
| `cairo-starknet-security` | Cairo/StarkNet |

### Framework Skills (11), Technology Skills (55), Tool Skills (15), Playbook Skills (8), Cloud Skills (4), Archetype Skills (6), Mobile Skills (2), Protocol Skills (5), Custom Skills (1)

Loaded dynamically based on tech stack detection. Skills are named by function
with plain kebab names (e.g. `idor`, `chain-building`, `ffuf`, `django`, `aws`).
Nine technology skills that duplicate framework names keep a `tech-` prefix
(e.g. `tech-django`). See directories:
- Framework skills (11): django, flask, fastapi, express, nestjs, laravel, rails, spring-boot, wordpress, dotnet
- Technology skills (55): aws, stripe, cloudflare, react, nginx, tech-django (9 tech-* duplicates), ...
- Tool skills (15): nuclei, sqlmap, nmap, semgrep, ffuf, ...
- Playbook skills (8), Cloud skills (4), Archetype skills (6), Mobile skills (2), Protocol skills (5), Custom skills (1)

All under `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\`.

### Claude Bug Bounty reference skills (opencode equivalents)

The `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\claude-bug-bounty/` tree does not exist here. Equivalents
(live skills in the vendor directory and codex-bug-bounty):

| Reference | opencode skill |
|-----------|----------------|
| recon-agent | `surface-discovery-pipeline` |
| recon-ranker | `threat_modeling` + `trust_boundary_mapping` |
| chain-builder | `chain_building` |
| validator | `triage-validation` + `kill_signals` |
| report-writer | `report-writing` |
| autopilot | this skill (`hunt-deep`) |
| intel command | `program_intelligence` |
| hunting rules | `web2-vuln-classes` |
| reporting rules | `report-writing` + `evidence_templates` |
