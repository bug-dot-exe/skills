# Global Cursor skills

These skills are available in **all** your projects (every folder). Cursor loads skills from `~/.cursor/skills/` so the agent can use them anywhere.

## Bug bounty (global)

| Skill | When to use |
|-------|-------------|
| **bug-bounty-global** | Bug bounty work in any project: recon, vulns, reports; Caido + Chrome by default; ensure_caido / auto_setup if the project has those scripts; project .cursor/skills (bb-recon, bb-scan, etc.) when present. |
| **bug-bounty-target-signup** | User needs to sign up or log in to a program to get a session; use or create a signup/login script (Playwright, Caido proxy, env credentials, optional coupon) for any target. |
| **bug-bounty-program-policy** | User names a program/target; look for instructions.md, scope.md, or POLICY.md in the project and apply scope, rate limits, out-of-scope. |
| **bug-bounty-agent-like-strix** | **You are the Strix-style agent:** default = execute phased workflow and tool discipline in Cursor (recon → map → proxy+browser → test → chain → report). Do not run the Strix CLI by default; only when the user explicitly asks. |
| **autonomous-bug-bounty-strix** | **Run the Strix binary** only when the user explicitly asks (e.g. "run Strix CLI", "full autonomous Strix run"). Then run the script or strix -n --target. Requires Docker + Strix CLI + LLM API. |
| **strix-bb** | **Launch Strix in tmux** with H1 Brain scope. Say "strix(replit)" or "strix for shopify" — fetches hack(handle), writes instructions, runs Strix in live tmux session. Requires h1-brain MCP. |

## Making the same setup work in new projects

1. **New folder** — Open any project; the global skills already apply. No need to copy skills into the project unless you want project-specific overrides.
2. **Policy file** — Add `instructions.md` or `scope.md` (or `POLICY.md`) with the program’s scope, out-of-scope, and rate limits. The agent will read it when you name that target.
3. **Scripts (optional)** — To get Caido + auto setup + signup in the new project, copy or symlink from a repo that has them, e.g.:
   - `scripts/ensure_caido.sh`
   - `scripts/auto_setup.sh`
   - `scripts/<program>_signup_login.py` (or create one following the pattern in bug-bounty-target-signup).
4. **.env** — Add `PROXY=http://127.0.0.1:8080`, and for signup scripts the credential vars (e.g. `PROGRAM_EMAIL`, `PROGRAM_PASSWORD`, `PROGRAM_COUPON`).

These global skills ensure everything we set up (Caido, Chrome, signup/login, coupon, policy from file) is available for future targets, not only in one folder.
