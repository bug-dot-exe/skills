---
name: state_machine_traversal
category: methodology
description: Map workflow states + transitions, then test illegal transitions, terminal-state shortcuts, and skipped-step bypasses
depends_on: [business_logic]
---

# State Machine Traversal

Most business logic is a state machine: a record moves from state A to B to C
through gated transitions. The vulnerability class: any transition that the
state-machine permits without enforcing its prerequisite is a free shortcut.
Methodology: derive the machine from runtime state, then attack each transition
edge.

## When to Use

- Any target with multi-step workflows (apply → review → approve → finalize)
- Any target with status fields (`status`, `state`, `phase`, `step`, `stage`)
- Any target with reviewer/approver gates
- Any target where one role advances state for another role
- After surface discovery has produced the endpoint inventory

## Inputs (all runtime-derived — never hardcoded)

- **STATE_FIELDS** = response fields that take a small set of string values
  observed across API traces. Discover by:
  - Listing records and grouping by enumerated fields
  - GET on the target record before and after each transition endpoint
  - OpenAPI schemas declaring `enum` types
- **TRANSITION_ENDPOINTS** = endpoints whose path or body suggests state change:
  `/submit`, `/approve`, `/reject`, `/cancel`, `/review`, `/finalize`, `/disburse`,
  `/release`, `/publish`, `/lock`, `/unlock`, `/pause`, `/resume`, `?action=`,
  `?transition=`
- **PRINCIPALS** = `scan_config.credential_inventory.keys()` (each role gets a
  different set of allowed transitions)

## Build the Machine (mandatory first step)

For each STATE_FIELD, populate this table from observation:

| State | Allowed transitions out | Allowed principals per transition |
|-------|-------------------------|-----------------------------------|

Walk one record through every transition endpoint while logging:
- which transitions accept the call
- which roles can call each transition
- what the resulting state becomes
- what side effects fire (events, balance changes, notifications)

Record this in a runtime artifact, not in skill files. The machine is per-target.

## Five Attack Classes Per Machine

### 1. SKIP-STEP — go from state A directly to state C, bypassing B

For every state pair (A, C) where the documented path is A → B → C:
- Create a record at state A
- Call the C-transition endpoint directly
- Expected: 4xx, "must be in state B"
- If accepted → **skip-step** finding

Common manifestations:
- Disburse before review (skip review gate)
- Publish before moderation
- Withdraw before KYC verification
- Finalize before approval

### 2. ROLE-EXTENSION — call a transition from a role not allowed at that state

For each transition T allowed at state A only for role R:
- As principal P ≠ R, call T against a record in state A
- Expected: 403
- If accepted → **broken function-level authorization** finding

This is auth-matrix in state-machine form.

### 3. TERMINAL-COERCION — force a record to a terminal state to lock out future steps

Some terminal states (`closed`, `cancelled`, `archived`, `locked`) prevent
further transitions. If a non-privileged principal can force the terminal:
- Create a record on behalf of victim
- As attacker, call terminal-coercion endpoint
- Observe whether victim's record is now stuck
- → **denial-of-service via state-lock** finding

Common manifestations:
- Cancel another user's record
- Close another user's account
- Lock another user's resource
- Mark another user's record as expired / forfeited / failed

### 4. RE-ENTRY — invoke a one-time transition twice

For each transition that should be one-shot (advance state and prevent re-entry):
- Call it once → state advances
- Call it again from the new state → expected: 409 "already in state X"
- If accepted and side-effects fire twice → **double-execution** finding

Common manifestations:
- Side-effect (notification / credit / grant / event) fires twice for a
  one-shot transition
- Single-use code redeemed twice
- Reward / bonus / allocation awarded twice for the same milestone
- Same vote counted twice

### 5. BACKWARDS-EDGE — reverse a transition that should be one-way

For each transition believed to be one-way (e.g., approve → cannot un-approve):
- Drive record to the post-state
- Look for a transition or admin endpoint that returns it to the prior state
- If accepted, observe whether side-effect rollback also fires
- If side-effects DON'T rollback → **partial-rollback corruption** finding
- If reverse is unauthorized but reachable → **state-rollback authorization** finding

Common manifestations:
- Un-revoke a token after revoke
- Un-cancel a cancelled record while keeping its side-effects in place
- Un-archive a deleted record without restoring permissions

## Cross-Cutting: Parallel Transitions

For state machines with parallel sub-states (e.g., a record requires N
independent reviewers/gates), test:
- Whether marking one parallel gate "approved" advances the parent without the
  other gate (skip-step on a parallel sub-state)
- Whether the parent transition checks ALL parallel gates atomically

## Output Format

For each unexpected transition:

```
State machine: {field name with state values}
Record state before: {state}
Transition called: {METHOD} {path} (action={action})
Principal: {role}
Expected: {documented behavior}
Observed: {actual transition + side effects}
Attack class: {SKIP-STEP|ROLE-EXTENSION|TERMINAL-COERCION|RE-ENTRY|BACKWARDS-EDGE}
Evidence: {request} → {response} → {state after} → {side-effect log}
```

## Anti-Patterns

- **Test only the documented happy path**: documented paths are the well-tested
  paths. The bugs live in the transitions devs didn't think about.
- **Skip side-effect checks**: a transition that "fails" but still emits a
  notification or adjusts a balance is a partial-execution bug — record it.
- **Skip parallel gates**: if a workflow has multiple parallel reviewers, the
  bypass is usually one reviewer's "approved" advancing the parent without the
  other.
- **Hardcode state names**: never assume specific values like `pending` or
  `approved` exist. Derive from runtime observation.
- **Single-record testing**: parallel/concurrent transitions on the same record
  are race conditions — combine this skill with `race_conditions_methodology`.

## Coverage Self-Check

Before declaring state-machine tested:
- [ ] State + transition table built for every observable workflow
- [ ] Every (state, transition) pair tested for skip-step
- [ ] Every transition tested for role-extension across all principals
- [ ] Every terminal state tested for hostile coercion (deny-of-service)
- [ ] Every one-shot transition tested for re-entry
- [ ] Every "one-way" transition tested for reverse / partial-rollback
- [ ] Every parallel-gate workflow tested for sub-state skip

## Composability

This skill composes with:
- `auth_matrix_systematic` — role-extension is auth-matrix in state-machine form
- `race_conditions_methodology` — concurrent transitions on the same record
- `boundary_spec_violation` — transition endpoints often accept extra body
  fields that bypass state checks (mass assignment + skip-step)
- `chain_building` — combine a skip-step finding with a side-effect to escalate
  impact (e.g., skip review + side-effect fires real state change)

## Discovery Signals

Scan for these signals before deep state machine testing:

| # | Signal | Where to Find | What It Means |
|---|--------|--------------|---------------|
| 1 | Status enum fields (`status`, `state`, `phase`, `step`) in API responses | JSON bodies, OpenAPI `enum` types | Explicit state machine — build the transition table (reports #1036999089, #1044920083) |
| 2 | Multi-step workflow URLs (`/submit`, `/approve`, `/finalize`, `/disburse`) | Endpoint inventory, URL patterns | Each step is a separate authz check audit point (report #116404224, $50k) |
| 3 | One-time benefit endpoints (promo codes, referral rewards, free trials) | Payment/promotion features | Race condition candidates — concurrent identical requests (report #1037430) |
| 4 | Password/email/2FA change flows with multiple stages | Authentication settings, recovery flows | Inter-step mutation: change email between token issue and consume (report #300305, $15k ATO) |
| 5 | Session lifecycle events (password change, logout-all, role change) | Security settings, admin panel | Test if other sessions survive each trigger (report #1069392) |
| 6 | CSRF tokens on some endpoints but not others in same flow | Proxy logs, token presence/absence | Multi-step flows often protect entry point but miss intermediate steps (report #1086752) |
| 7 | Rate-limit responses (429) that still return success data in body | Response body parsing vs status code | "Fake" rate limits — blocked status code but action still executed (report #1065186) |
| 8 | Cached/CDN responses on authenticated endpoints (`X-Cache`, `Age` headers) | Response headers | Cache-leak race: poll as unauth immediately after auth triggers cache (report #1043480) |
| 9 | UI-vs-API guard mismatches ("verify email first", "upgrade to Pro") | Browser devtools, direct API calls | State precondition enforced client-side only (report #1018489) |
| 10 | Draft/pending/scheduled resource states | Content management, UGC platforms | Non-published states often have weaker authz gates (report #1044920083, Meta) |
| 11 | Background job / cleanup / GC status endpoints | Admin endpoints, `/jobs`, `/tasks` | Test if background-job state endpoints expose data or accept unauthorized input (report #1026196) |
| 12 | Permanent state corruption vectors (circular refs, infinite recursion in user content) | Rich content editors, nested data structures | Single-shot input that creates unrecoverable state (report #1057484) |

## State Transition Attack Matrix

Patterns extracted from real disclosed reports:

| Transition | Bypass Technique | Impact | Real Example |
|------------|-----------------|--------|--------------|
| Pending → Approved (skip review) | Call approval endpoint directly from pending state | Workflow gate bypass | Facebook verification bypass — skip CAPTCHA step entirely (#1036999089) |
| Unapproved → Self-promoted | PATCH/PUT with `status=approved` or `verified=true` | Privilege escalation | Google $50k — `updateMask` + PATCH to set own application state (#116404224) |
| Active → Cancelled (hostile) | Call cancel/archive endpoint with victim's resource ID | DoS via state-lock | Terminal coercion — attacker locks victim's resource permanently |
| Unverified → Verified (skip 2FA) | Call post-2FA endpoint without completing 2FA step | Auth bypass | State-machine bypass: endpoint N+1 without satisfying endpoint N (#1036999089) |
| Published → Draft (reverse) | Find reverse-transition endpoint, check if side-effects roll back | Partial-rollback corruption | Un-cancel without restoring permissions or rolling back side-effects |
| Redeemed → Unredeemed (replay) | Send concurrent identical requests to one-time redemption | Double-execution / double-spend | Race condition on promo code redemption — 3 extra days per race (#1037430) |
| Permissive ACL → Restrictive ACL | Change ACL, immediately test old URL with different account | Data leak via propagation delay | Google Apps Script $133k — ACL change didn't propagate to serving layer (#489003520) |
| Email A → Email B (mid-flow) | Change email between reset-token issuance and consumption | ATO via identity binding race | Shopify $15k — email changed after token issued, token still consumed (#300305) |

## Race Condition Pattern Matrix

| Pattern | Window | Exploitation Technique | Detection Method |
|---------|--------|----------------------|------------------|
| One-time redemption (promo/trial/reward) | DB check-then-update gap | Turbo Intruder concurrent identical requests | Benefit applied 2+ times for single entitlement (#1037430) |
| Cached auth response (CDN/proxy) | Cache TTL after authenticated request | Poll as unauth immediately after victim triggers cache | Unauth receives victim's cached data (#1043480) |
| ACL propagation delay | Config change → serving layer sync | Change ACL restrictive, test old URL before propagation | Old URL still works after permission revoked (#489003520) |
| Session invalidation lag | Password/2FA change → session store sync | Maintain second browser session, trigger invalidation event, test second session | Second session survives password change (#1069392) |
| Rate-limit race | Response parsed before limit applied | Send burst of requests faster than limit enforcement | Success responses despite 429 status codes (#1065186) |
| Idempotency key absence | Request processing window | Fire parallel requests without idempotency key | Duplicate state mutations / double-charges (#307239) |

## Workflow Bypass Techniques

| Workflow | Step Skipped | Technique | Impact |
|----------|-------------|-----------|--------|
| Signup: register → verify email → activate | Email verification | Call activation endpoint directly after registration | Unverified accounts with full privileges (#1036999089) |
| Payment: cart → checkout → confirm → disburse | Checkout validation | Call disburse endpoint with crafted cart state | Payment without validation (#1145428) |
| KYC: submit → review → approve → access | Review/approval gate | PATCH resource with `approved` field from any state | Access without KYC completion (#116404224) |
| Password reset: request → email → set new | Email verification | Reuse browser cookie set during request phase to reach set-password | ATO via persistent cookie (#1004536) |
| Multi-step CSRF flow: entry → intermediate → final | Intermediate steps | Test CSRF protection on each step independently | CSRF on unprotected intermediate step (#1086752) |
| Content publish: draft → moderate → publish | Moderation gate | Direct-invoke publish endpoint from draft state | Unmoderated content published |
| Role promotion: apply → pending → admin approves | Admin approval | Self-PATCH with `updateMask=status` | Self-promotion to approved role (#116404224, $50k) |
| 2FA setup: generate → scan → verify code | Code verification | Complete flow without submitting valid TOTP code | 2FA enabled without binding to authenticator |

## Pro Tips (Corpus-Evidenced)

1. **Test CSRF on EVERY step of multi-step flows, not just the entry point.** Developers protect login/account-update forms but miss intermediate password-reset or 2FA-setup steps. Enumerate ALL state-changing endpoints in each flow. (report #1086752)

2. **Verify rate limits actually block, not just report.** Send 100 fast requests, trigger the limit, then send a valid request. If it succeeds despite the 429, the limit is cosmetic. Always parse the BODY for the actual outcome, not just the status code. (report #1065186)

3. **Test permission changes in both directions.** Permissive→restrictive (data leak if stale) AND restrictive→permissive (should activate). The first direction is the security bug. (report #489003520, $133k)

4. **Session lifecycle test matrix: password change, email change, 2FA toggle, logout-all, role change.** For each trigger, maintain a second browser session and check if it survives. Any survivor is CWE-613. (report #1069392)

5. **Race one-time endpoints with concurrent identical requests.** Promo codes, referral bonuses, free trials, daily login rewards, first-purchase discounts — any "claim once" endpoint. Use Turbo Intruder or HTTP/2 single-packet attack. (report #1037430)

6. **Draft/pending/scheduled states have weaker authz than published states.** The mental shortcut "this state isn't public-facing so we don't need ACL" is a bug factory. Always test cross-account fetch on each non-published state. (report #1044920083, Meta)

7. **For any multi-step payment flow, test cross-step consistency.** Does step 3 verify that step 2 was performed by the same user? Or just that step 2 happened at all? Authorization must be re-checked at each payment-routing transition. (report #1145428)

8. **Mutate the bound entity between token issuance and consumption.** In email change, password reset, invitation flows — change the email/role/owner between step 1 (token issued) and step 2 (token consumed). If the token still works, that's ATO. (report #300305, $15k Shopify)

9. **Permanent state corruption is higher severity than transient DoS.** Single-shot inputs that create unrecoverable state for a user (infinite recursion, circular refs, quota exhaustion that blocks future ops) elevate from Low DoS to Medium/High. (report #1057484)

## Tool Wiring

After you have built the state machine (this skill describes how), call the registered agent tool `generate_workflow_probes` with the captured workflow steps. The tool emits a battery of skip / replay / reorder / value-mutation probes for every step you provide.

Procedure:

1. Capture each step as a dict with these keys: `name`, `method`, `endpoint`, `headers`, `body`, `required_for_next` (bool), `sensitive_fields` (list of strings), `idempotent` (bool).
2. Call `generate_workflow_probes(steps=[step1, step2, ...], tests=["skip", "replay", "reorder", "mutate"])`.
3. The tool returns a list of probe-request sequences. Execute each sequence in order via `terminal_execute` (or `browser` for UI flows), preserving auth/cookies between calls.
4. Anomaly criterion: a probe whose terminal step returns 2xx where the canonical flow would 4xx is a finding. Report the probe label and the response chain as evidence.

This wiring catches state-machine bypass, idempotency violations, step-reorder priv-esc, and value-mutation bugs (negative amounts, currency swaps, decimal rounding) — exactly the class that pure narrative testing tends to miss.

Tool source: `bugdotexe/tools/workflow_probe/probe.py`. Tool schema: `bugdotexe/tools/workflow_probe/workflow_probe_actions_schema.xml`.
