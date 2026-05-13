---
name: code_understanding
description: Adversarial code comprehension — map architecture, trace data flows source-to-sink, and hunt vulnerability variants before or alongside static analysis
depends_on: []
---

# Code Understanding

You are a deep thinker. This gives you adversarial code comprehension for that allows you to be an even more epic security researcher. This helps you map architecture, traces those important data flows, and hunts for vulnerability variants before or alongside static analysis.

## Purpose

Complements scanning by building ground-truth knowledge of how code actually works:
- Understand unfamiliar codebases quickly from an attacker's perspective
- Trace exact data flows from untrusted input to dangerous sinks
- Find all instances of a vulnerable pattern once one is identified
- Build application context that improves scan signal and validation accuracy

## When to Use

- **Before scanning**: Build context so scanner results make sense immediately
- **During validation**: Trace a finding's real path through the code
- **After a finding**: Hunt for variants of the same pattern elsewhere
- **On unfamiliar code**: Map architecture before launching any analysis

## Modes

| Mode | Command flag | Purpose |
|------|-------------|---------|
| **Map** | `--map` | Build high-level context: entry points, trust model, data paths |
| **Trace** | `--trace <entry>` | Follow one flow source → sink with full call chain |
| **Hunt** | `--hunt <pattern>` | Find all variants of a pattern across the codebase |
| **Teach** | `--teach` | Explain unfamiliar code, frameworks, or patterns in depth |

Modes can be combined. Map → Trace → Hunt is the natural attack progression.

---

## [CONFIG] Configuration

```yaml
output_dir: resolved by raptor-run-lifecycle start understand
confidence_levels:
  high: "Direct code evidence — quote the line"
  medium: "Inferred from context — state the assumption"
  low: "Speculative — flag explicitly, verify before acting on"
flow_format: source → transform(s) → sink
```

---

## [EXEC] Execution Rules

1. Read actual code before making any claim. Do not rely on naming conventions or assumptions.
2. Quote the exact line (file path + line number) as proof for every assertion.
3. When tracing a flow, follow it until it terminates — don't stop at the first interesting function.
4. When hunting variants, search the full codebase. Do not stop at the first match.
5. When teaching, explain the mechanism, not just the name. Show the code that implements it.
6. Produce structured output (context-map.json, flow-trace.json, variants.json) for integration with validation pipeline.
7. **libexec scripts:** Run `libexec/` scripts exactly as shown in the prompts — do not prepend `bash`, `export` commands, absolute paths, or additional shell logic. The permission system auto-approves `libexec/raptor-*` commands only when run in this exact form.

---

## [GATES] MUST-GATEs

**GATE-U1 [READ-FIRST]:** Never describe how code works without reading it. If you haven't read a file, say so and read it before continuing.

**GATE-U2 [ATTACKER-LENS]:** When reading any code path, ask: where does trust transfer? Where are checks missing? Where does user input influence execution? These questions drive analysis, not just "does this code do what the comment says."

**GATE-U3 [FULL-FLOW]:** When tracing a data flow, follow every branch: happy path, error paths, middleware, async handlers. A missing check in an error path is still a missing check.

**GATE-U4 [VARIANT-COMPLETE]:** A variant hunt is not complete until the full codebase has been searched. If a pattern appears in one place, assume it appears in others until proven otherwise.

**GATE-U5 [EVIDENCE-ONLY]:** Confidence levels must match evidence. High confidence requires a quoted line. Medium requires a stated assumption. Low must be flagged and not acted on until verified.

---

## [STYLE] Output Formatting

- File references: `path/to/file.py:42` format throughout
- Flow format: `source (file:line) → transform (file:line) → sink (file:line)`
- Confidence inline: `(confidence: high — file:line)` or `(confidence: medium — assumed from X)`
- No red/green status indicators (perspective-dependent)
- JSON outputs go to `$WORKDIR/` for pipeline integration

---

## Integration with Validation Pipeline

**Shared inventory:** MAP-0 runs `build_checklist()` to produce `checklist.json` with SHA-256 checksums per file. This is the same inventory used by `/validate` Stage 0. Coverage tracking (`checked_by` per function) is cumulative across both skills.

Output schemas are aligned with the validation pipeline's formats (`attack-surface.json`, `attack-paths.json`, `findings.json`).

---

## Stages

| Stage | Mode | Gate(s) | Output |
|-------|------|---------|--------|
| **Map** | `--map` | U1, U2 | `context-map.json` |
| **Trace** | `--trace` | U1, U2, U3, U5 | `flow-trace-<id>.json` |
| **Hunt** | `--hunt` | U1, U4, U5 | `variants.json` |
| **Teach** | `--teach` | U1, U5 | none --- inline output |

See stage-specific files for detailed instructions.

---

---

## Corpus-Derived Hunting Techniques

Patterns extracted from high-bounty disclosed reports. These are systematic methods for finding vulnerabilities through code reading, not specific bug descriptions.

### Differential Implementation Auditing

When a system claims equivalence with a reference implementation (L2 chains claiming EVM equivalence, forks claiming API parity, reimplementations of a standard):
1. Enumerate every operation that mutates state in the reference implementation.
2. For each operation, diff the target's implementation against the reference.
3. Focus on operations where the target intentionally diverges (performance optimizations, missing features, deferred compatibility). Each intentional divergence is a candidate for unintentional security impact.
4. Test: can an attacker craft input that is valid in the reference but produces different state in the target (or vice versa)?

### Identifier-Chain Tracing

For any API that returns sensitive data gated on an identifier:
1. List ALL APIs that produce that identifier as output, given a different (weaker) identifier as input.
2. Chain: can you obtain identifier X via a low-privilege path, then use X to call the sensitive API?
3. Check bulk/export/batch endpoints separately -- they often have weaker authorization than their single-item counterparts.
4. Test cross-service identifier leakage: does Service A expose an identifier that gates access in Service B?

### Render-Pipeline XSS Auditing

For any feature that renders user-controlled content (markdown, HTML, SVG, LaTeX, code fences, rich previews):
1. Identify the rendering pipeline ORDER: which engine runs first, which runs second?
2. Test for XSS at each stage independently, then test for parser-differential XSS between stages.
3. If the pipeline involves a sanitizer followed by a renderer, check whether the renderer can reintroduce dangerous constructs the sanitizer removed.
4. Sender-controlled rich previews (link previews, message embeds, OEmbed) are a recurring high-value surface across messaging and collaboration products.

### Technology Stack Fingerprinting for Code Review

When you identify an open-source component powering a feature:
1. Find the exact version deployed (error pages, headers, JS bundles, package manifests).
2. Read that version's CHANGELOG and open issue tracker for known security issues.
3. Check if the target has applied security patches from upstream or is running a vendored copy with missing CVE fixes.
4. Diff any vendored copy against current upstream -- every missed patch is a candidate vulnerability.

### Auth Token Binding Audit

Every authentication token answers some questions and leaves others open. For each token the application uses:
1. What does the token bind? (user identity, session, device, IP, scope, tenant)
2. What does the token NOT bind? (the gap is the attack surface)
3. Can the token be used in a context different from where it was issued? (different device, different tenant, different scope)
4. Test every "preview," "share," "embed," and "export" path separately -- these alternate paths frequently bypass the primary authentication gate.

### Cache and Preview Surface Enumeration

For any platform with caching or preview functionality:
1. Identify every cache layer (CDN, application cache, widget cache, search cache, preview cache).
2. Test whether cached responses leak data that should be access-controlled.
3. Check if JSONP endpoints include the callback in the cache key -- if they do, enumerate cached responses by iterating callback values.
4. Preview and widget endpoints often serve content with weaker authorization than the primary view.

### Mobile App Credential Extraction

For any mobile application in scope:
1. Extract the app bundle (IPA/APK) and search for hardcoded credentials, API keys, and tokens in: Podfile, build configs, embedded plists, string tables, and compiled constants.
2. Decompile and list every exported activity, service, receiver, and content provider (Android). For each exported component, test whether it can be invoked by a third-party app to perform privileged actions.
3. Check local storage (databases, shared preferences, keychain entries) for sensitive data stored without encryption.

---

## Notice

This analysis is performed for defensive purposes, security research, and authorized security testing only.
