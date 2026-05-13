---
name: bounty_feedback_loop
category: methodology
description: Learning from rejected and duplicate reports to improve methodology and track program preferences over time
depends_on: []
---

# Bug Bounty Feedback Loop

Systematic learning from report outcomes. Every rejection, duplicate, and downgrade contains signal about what the program values and what your methodology misses.

## When to Use

- After receiving a report verdict (accepted, rejected, duplicate, N/A)
- When starting a new hunt on a program you have history with
- During methodology review to identify recurring blind spots
- When hit rate drops below acceptable threshold across programs

## Tracking Framework

Maintain a per-program outcome log:

| Date | Report | Verdict | Severity Submitted | Severity Awarded | Reason | Lesson |
|------|--------|---------|--------------------|------------------|--------|--------|
| | | accepted/rejected/dup/N-A | | | | |

### Key Metrics

- **Acceptance rate**: accepted / total submitted (target: >60%)
- **Duplicate rate**: duplicates / total submitted (target: <20%)
- **Severity accuracy**: awarded severity matches submitted severity
- **Time-to-duplicate**: how fast after scope change before duplicates flood in

## Methodology

### Step 1: Classify Rejections

Every rejection falls into a category that maps to a specific fix:

| Rejection Type | Root Cause | Methodology Fix |
|----------------|-----------|-----------------|
| Out of scope | Misread scope rules | Re-read scope before every submission |
| Not reproducible | Environment-specific, missing steps | Record full repro with video/HAR |
| Informational / won't fix | Low impact, no business risk | Apply impact-first writing, quantify harm |
| Duplicate | Too slow, obvious finding | Hunt deeper, skip surface-level bugs |
| By design | Documented intended behavior | Check docs and changelogs before reporting |
| N/A | Not a vulnerability | Strengthen kill signals, validate harder |

### Step 2: Pattern Recognition Across Programs

Track which vulnerability classes get accepted vs rejected across programs:

- Which programs consistently reject self-XSS, CSRF on logout, missing headers?
- Which programs pay well for business logic vs technical vulns?
- Which programs value chains over individual findings?
- What severity calibration does each program use?

### Step 3: Adjust Per-Program Strategy

Build a program profile from historical data:

- **Preferred vuln types**: what they pay top dollar for
- **Auto-reject list**: findings they never accept (update from rejections)
- **Severity calibration**: do they consistently downgrade or upgrade?
- **Response patterns**: fast triage = active team = hunt harder

### Step 4: Duplicate Avoidance

When duplicates are frequent:

1. Prioritize deep, chained, or logic bugs over surface-level scanner findings
2. Target newly added scope immediately (first 48 hours matter)
3. Focus on areas requiring source code review or business logic understanding
4. Avoid low-hanging fruit on mature programs with many active hunters

### Step 5: Continuous Calibration

After every 10 reports, review:

- Is acceptance rate trending up or down?
- Are rejections clustering around a specific category?
- Which programs yield best ROI for your skill set?
- Should you drop a program and move to another?

## Corpus-Derived Feedback Patterns

### Pre-Submission Triage Discipline

Before submitting any finding, apply this self-check to avoid informative/N-A verdicts:

1. **What is the actual harm?** Not "this endpoint is exposed" but "an attacker can do X, causing Y loss to Z users"
2. **Is this a known/documented feature?** Check the product docs, API reference, and changelog. If the behavior is documented, it is "by design" unless you can demonstrate unintended harm
3. **Is this a public/intended resource?** Configuration files, health endpoints, and version strings exposed by design are not findings. Ask: would a reasonable developer intentionally expose this?
4. **Can you chain it?** If the standalone impact is low, demonstrate a chain. An open redirect alone may be informative; an open redirect that bypasses OAuth state validation is a valid finding

### Handling Triager Objections

| Triager Response | Counter-Strategy |
|-----------------|-----------------|
| "This is by design" | Demonstrate a harmful consequence the design did not anticipate. Show user impact, not mechanism. |
| "Low impact / informational" | Quantify: how many users affected? What data exposed? What is the blast radius? Show a concrete exploitation scenario with dollar or user-count impact. |
| "Not reproducible" | Provide HAR file, video recording, exact browser/OS version, and step-by-step with timestamps. Offer to screenshare. |
| "Duplicate" | Ask for the duplicate ID to verify. If the triage is wrong (different root cause), explain the difference with code-level detail. |
| "Requires attacker to..." | Demonstrate that the required conditions are realistic: attacker on same network = any coffee shop; social engineering = single phishing link; physical access = any shared device. |
| "We will fix in the next release" | Acknowledge, but ask for bounty timeline. Some programs delay payment until the fix ships -- track these. |

### Severity Escalation with Evidence

When your submitted severity is downgraded, escalate with concrete evidence:

1. **Demonstrate the chain**: if you submitted a High as a standalone and it was downgraded to Medium, chain it with another finding or realistic precondition to show the original impact
2. **Show production data**: use public data (Google dorking, Wayback Machine, Shodan) to demonstrate real-world exposure, not just theoretical possibility
3. **Reference program precedent**: cite a previously disclosed report on the same program that was rated at your claimed severity for a comparable finding
4. **Quantify financial impact**: "This allows draining user balances" is vague. "This allows extracting $X per affected user, with Y users in the affected cohort" is convincing

### Productive Duplicate Handling

Duplicates are not wasted -- they contain intelligence:

1. **If you receive a duplicate verdict**: note the vuln class, the area, and the timing. This tells you what other researchers are finding and how fast.
2. **Differentiate your duplicates**: if the same root cause manifests at a different endpoint or with a different attack vector, some programs pay for the variant. Ask.
3. **Use duplicates to calibrate speed**: if you are consistently duplicated, you are hunting the same surface as everyone else. Pivot to deeper analysis, business logic, or less-traveled scope.
4. **Page-level vs parameter-level dedup**: on large programs, clarify whether the triage team deduplicates per-endpoint or per-root-cause. The same XSS pattern on 10 endpoints may be 1 finding or 10.

### Triage-Friendly PoC Packaging

Triagers process hundreds of reports. Optimize for their workflow:

1. **Structured format**: Title (vuln class + location), Impact (one sentence), Steps to Reproduce (numbered, copy-pasteable), PoC (curl command or screenshot), Fix Suggestion (optional but appreciated)
2. **Reproducibility first**: every PoC should work by copy-pasting the curl command. No setup required, no assumptions about the triager's environment
3. **One finding per report**: combining multiple findings in one report confuses triage and delays payment. Exception: when findings are steps in a single chain.
4. **Sibling-report consistency**: when filing multiple reports on the same bug class at different locations, keep the PoC structure identical -- only vary the endpoint/parameter

### Cluster Crashes by Root Cause

When fuzzing or testing produces multiple crashes or errors:

1. Do not file each crash as a separate finding
2. Group by root cause: 10 crashes from the same missing null check = 1 finding with 10 symptoms
3. Present the root cause with the most impactful symptom as the primary PoC
4. List all affected locations in a table -- this shows thoroughness and helps the fix cover all instances

### SCA/N-Day Report Strategy

When using dependency scanning (SCA) findings:

1. **Verify the trigger conditions**: does the target actually use the vulnerable function, not just the library?
2. **Demonstrate exploitability**: a CVE in a dependency is not a finding unless you can show a path from user input to the vulnerable code path in the target's context
3. **Expect low payouts**: most programs pay minimally for dependency-only findings unless you demonstrate concrete exploitation
4. **Batch strategically**: some programs accept one report covering all instances of the same CVE; others want per-instance reports. Ask.

## Anti-Patterns

- Submitting the same class of rejected finding to the same program
- Ignoring rejection reasons and blaming the triager
- Never reviewing past outcomes before starting a new hunt
- Hunting only surface-level bugs on programs with 500+ active researchers
- Refusing to abandon a program with consistently poor outcomes
- Filing near-duplicate reports hoping one will slip through (programs rate second-and-onwards at $0)
- Over-investing in a single finding's severity dispute when the time could produce a new finding
- Submitting exposed files/endpoints without verifying they contain sensitive data or enable harm
