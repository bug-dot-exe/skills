# Improving Strix with bb-hunter + H1 Brain

Strix runs in a sandbox and **has no MCP access**. All improvement happens through the **instruction file** and optionally **custom skills**. This document outlines how to make Strix smarter using our bb-hunter skills and H1 Brain data.

---

## 1. The Lever: Instruction File

Strix reads `--instruction-file instructions.md` as its primary context. Everything we want Strix to know must be **pre-baked** into that file before launch.

**Current flow (strix-bb / strix-prep):**
1. Call `hack(handle)` → get scope, attack vectors, disclosed reports
2. Merge with `instruction-template.md` (minimal bb-hunter methodology)
3. Write to `~/strix-runs/<target>/instructions.md`

**Gap:** The template is ~20 lines. bb-hunter has 400+ lines of methodology, chain patterns, bounty intel, and report format. H1 Brain returns rich scope + briefing. We're underutilizing both.

---

## 2. What to Inject

### From H1 Brain (MCP → instructions)

| Source | Content | When |
|-------|---------|------|
| `hack(handle)` | Scope, in-scope assets, attack vectors, your past findings, disclosed reports, briefing | Always when target is H1 program |
| `search_disclosed_reports(program, weakness)` | Prior XSS/SSRF/IDOR on this program | Optional: append to instructions for focused testing |
| `search_scopes(program)` | Exact in-scope URLs, bounty eligibility | When scope is complex |

### From bb-hunter (skills → instructions)

| Source | Content | Purpose |
|-------|---------|---------|
| **Chain thinking** | Open Redirect→ATO, SSRF→metadata, XSS→admin, IDOR→PII | Every finding is a pivot; don't stop at standalone |
| **Validation rules** | PoC or GTFO, triage detections vs findings | Avoid false positives |
| **Report format** | Title formula, raw HTTP, impact in business language | Higher payout, fewer "needs more info" |
| **Bounty intel** | Tier 1 playbooks ($10K+), Tier 2 techniques, what pays $0 | Prioritize high-ROI attack paths |
| **Campaign scoring** | `/graphql`, `/auth`, `/admin` = 9; `/api/`, `/webhook` = 8 | Focus recon and testing |
| **Chain patterns** | SSRF→metadata, XSS→admin action, race→financial | Explicit escalation paths |

### From strix-* skills (already in Strix)

Strix bundles `strix/skills/` (IDOR, XSS, SSRF, etc.). The root agent spawns subagents with `skills="idor,xss,ssrf"`. We can add to instructions:

- **Skill selection guidance:** "For this target (Next.js + Supabase), prioritize: strix-nextjs, strix-supabase, strix-idor, strix-xss, strix-ssrf"
- **Tech-specific hints:** If H1 scope mentions "Vercel" → add strix-nextjs focus; "Firebase" → strix-firebase-firestore

---

## 3. Implementation Options

### Option A: Enhanced instruction template (recommended)

Create `instruction-template-enhanced.md` that merges:

1. **H1 hack() output** (inserted by strix-prep when available)
2. **bb-hunter distilled** — chain thinking, validation, report format, top 5 chain patterns, top 5 bounty playbooks
3. **Rate limits / scope** — from policy or hack()

**Size:** ~150–200 lines. Strix's context window can handle it. Quality over brevity.

### Option B: Modular instruction builder

Script or skill that:

1. Calls `hack(handle)` if H1
2. Reads `bounty-intel.md`, `chains.md`, `reporting.md` — extracts relevant sections
3. Assembles `instructions.md` with sections: Scope | H1 Briefing | Methodology | Chains | Report Format | Rate Limits

### Option C: Custom Strix skills (advanced)

Strix loads skills from `strix/skills/` (bundled). If Strix supports `--skills-dir` or `STRIX_SKILLS_PATH`:

- Add `bb-hunter-methodology.md` as a coordination skill
- Add `bounty-intel-chains.md` as a vulnerability skill

**Check:** Strix source/config for custom skill paths. If not supported, Option A/B is the path.

---

## 4. Recommended Next Steps

1. **Create enhanced template** — `instruction-template-enhanced.md` with bb-hunter methodology + chain patterns + report format
2. **Update strix-prep** — Use enhanced template; always call `hack()` when handle looks like H1 program
3. **Add tech hints** — If scope mentions Next.js/Firebase/Supabase, append relevant strix-* focus to instructions
4. **Test** — Run Strix with enhanced instructions on a known target; compare finding quality vs minimal template

---

## 5. Quick Reference: What to Include

**Minimum (current):** Scope + PoC rule + chain thinking + report format + rate limits

**Enhanced:** Above + 
- 5 chain patterns (SSRF→metadata, XSS→admin, IDOR→PII, Open Redirect→OAuth, Race→financial)
- 3 bounty playbooks (URL parsing SSRF, unauthenticated admin SSRF, weaponized patch)
- Campaign scoring for prioritization
- "What pays $0" — avoid broken link hijacking, self-XSS, scanner output without PoC
- Skill selection: "Spawn subagents with skills matching attack surface (idor,xss,ssrf,sql_injection,business_logic)"
