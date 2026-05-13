# Strix: full skill load (orchestration)

**Purpose:** You are not allowed to “wing it.” Treat every path below as **required reading** before deep work in that phase. If the host has the file, **open the SKILL.md** and apply it; this section is the **routing table + non‑negotiable rules**, not a substitute for those files.

**Load order (always):** (1) Program-specific scope at top of `instructions.md` → (2) this block → (3) `bb-hunter-full.md` bypass tables and gates below.

---

## North star (from bug-bounty master)

> Can an attacker do this **right now** against a real user who took **no unusual actions**, and does it cause **real harm** (money, PII, ATO, RCE)?  
> If **no** → stop. No report. No “could potentially.”

**Detection ≠ finding:** A header, sink, or pattern is a lead. A finding needs a **reproducible PoC** and **concrete impact**.

---

## Mandatory phases → which skill to load

| Phase | Load this file first (full playbook) | What you must produce before leaving the phase |
|-------|--------------------------------------|-----------------------------------------------|
| Scope / policy | Top of `instructions.md` + program page | Written list: in-scope URLs, exclusions, rate limits, “no automation” rules if any |
| Recon | `~/.claude/skills/web2-recon/SKILL.md` | Subdomains/live hosts/URL corpus; prioritized targets (auth, API, uploads, billing) |
| Recon (deep) | `~/.cursor/skills/bbrecon-subdomain-deep/SKILL.md` | Wildcards, CT edges, permutations if passive enum is thin |
| API / auth discovery | `~/.cursor/skills/bbrecon-api-discovery/SKILL.md` | GraphQL/OpenAPI/OAuth/OIDC/webhook candidates |
| Parameters | `~/.cursor/skills/bbrecon-parameter-discovery/SKILL.md` | High-value params from JS, Wayback, responses |
| Scope expansion | `~/.cursor/skills/bbrecon-scope-expansion/SKILL.md` | Related assets only if **program allows** |
| Map + proxy | `~/.cursor/skills/bb-hunter/SKILL.md` (§ Caido, Playwright) | Annotated flows; roles; trust boundaries; sitemap mental model |
| Vuln classes (reference) | `~/.claude/skills/web2-vuln-classes/SKILL.md` | Pick classes matching the stack; don’t spray all 18 at once |
| Payloads / bypass lists | `~/.claude/skills/security-arsenal/SKILL.md` | Use **after** you know the sink and parser context |
| Validate before report | `~/.claude/skills/triage-validation/SKILL.md` | All 7 questions + 4 gates **pass** |
| Write report | `~/.claude/skills/report-writing/SKILL.md` | Title formula, impact-first, raw HTTP evidence |
| End-to-end methodology | `~/.claude/skills/bug-bounty/SKILL.md` | Chains, AI/LLM testing (ASI01–ASI10), language-specific greps, pre-hunt learning |

**Multi-agent (optional):** If splitting work: recon → `~/.cursor/skills/bb-hunter-agents/recon/SKILL.md`, attack → `.../attacking/`, validation → `.../validation/`, reporting → `.../reporting/`.

---

## Strix vuln-class skills (`~/.codex/skills`) — load by symptom

Read the **named** `SKILL.md` before testing that class. Use sibling endpoints and A→B chaining from `bb-hunter-full.md` after each confirmed signal.

| Symptom / surface | Skill path |
|-------------------|------------|
| Object IDs, UUIDs, `/api/.../users/` | `strix-idor/SKILL.md` |
| Reflected/stored/DOM HTML/JS | `strix-xss/SKILL.md` |
| `url=`, webhooks, PDF/SSRF gadgets | `strix-ssrf/SKILL.md` |
| Search/filter/sort/order parameters | `strix-sql-injection/SKILL.md` |
| JWT/OIDC/session tokens | `strix-authentication-jwt/SKILL.md` |
| Payments, credits, workflow states | `strix-business-logic/SKILL.md` |
| Double-spend, race, concurrent requests | `strix-race-conditions/SKILL.md` |
| Uploads, avatars, imports | `strix-insecure-file-uploads/SKILL.md` + `strix-path-traversal-lfi-rfi/SKILL.md` |
| Template/deserial/cmd/exec hints | `strix-rce/SKILL.md` |
| POST/PUT without CSRF defenses | `strix-csrf/SKILL.md` |
| Hidden JSON fields, role flags | `strix-mass-assignment/SKILL.md` |
| GraphQL | `strix-graphql/SKILL.md` |
| XML/file formats | `strix-xxe/SKILL.md` |
| `redirect_uri`, `next`, `returnUrl` | `strix-open-redirect/SKILL.md` |
| CNAME/dangling host | `strix-subdomain-takeover/SKILL.md` |
| Errors, backups, `.git`, verbose errors | `strix-information-disclosure/SKILL.md` |
| Admin vs user **actions** (not just IDs) | `strix-broken-function-level-authorization/SKILL.md` |
| Stack-specific | `strix-nextjs`, `strix-fastapi`, `strix-supabase`, `strix-firebase-firestore` (each under same dir) |

**Assessment depth:** `strix-quick`, `strix-standard`, `strix-deep`, `strix-root-agent` describe **how hard** to push; they do not replace the vuln-class playbooks above.

---

## Operational stack (from bb-hunter)

- **Proxy:** Caido on `127.0.0.1:8080` — all browser and tool traffic through it when possible.
- **Browser:** Playwright **through** the proxy; multi-context for cross-user tests; export requests from proxy for replay.
- **Replay:** Prefer surgical **edit-and-replay** (same session, swap IDs/paths/bodies) over blind fuzzing.
- **Timeboxing:** 5-minute rule on dead hosts; 20-minute A→B burst after a real signal; rotate instead of grinding.

---

## AI / LLM / “agentic” features

If the target exposes chatbots, copilots, code tools, or plugins: read **`~/.claude/skills/bug-bounty/SKILL.md`** sections on LLM security (prompt injection, indirect injection, tool/RCE, exfil, ASI01–ASI10). Treat as **high priority** on modern SaaS.

---

## Submission discipline (reminder)

Before **any** submission narrative: run **`~/.claude/skills/triage-validation/SKILL.md`** (7 questions + 4 gates). Cross-check **NEVER SUBMIT** and **conditional chain** tables in `bb-hunter-full.md`. Write with **`~/.claude/skills/report-writing/SKILL.md`**.

---

## Paths cheat sheet (copy for your environment)

```text
~/.cursor/skills/bb-hunter/SKILL.md
~/.cursor/skills/bbrecon-api-discovery/SKILL.md
~/.cursor/skills/bbrecon-parameter-discovery/SKILL.md
~/.cursor/skills/bbrecon-scope-expansion/SKILL.md
~/.cursor/skills/bbrecon-subdomain-deep/SKILL.md
~/.cursor/skills/bb-hunter-agents/recon|attacking|validation|reporting/SKILL.md
~/.claude/skills/bug-bounty/SKILL.md
~/.claude/skills/web2-recon/SKILL.md
~/.claude/skills/web2-vuln-classes/SKILL.md
~/.claude/skills/security-arsenal/SKILL.md
~/.claude/skills/triage-validation/SKILL.md
~/.claude/skills/report-writing/SKILL.md
~/.codex/skills/strix-*/SKILL.md
```

---

<!-- STRIX_ALL_SKILLS_LOADED -->
