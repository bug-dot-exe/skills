---
name: patch-diff-analyzer
description: Reverse-engineer JAR/DLL pairs to extract vulnerability fixes from security patches via decompile-commit-diff
depends_on: []
---

# Patch Diff Analyzer

Compare a vulnerable binary against its patched successor to learn exactly
what the vendor fixed — and, by inversion, what the underlying vulnerability
was. Useful for n-day research, vendor-advisory verification, and finding
incomplete patches that leave residual exploitable surface.

## Prerequisites

This skill calls external decompilers that are **not pre-installed in the
bug.exe sandbox**. Install in the agent's terminal session before use:

- **Java JAR/WAR** — install one of the following:
  - `jadx` (recommended): `apt-get install -y jadx` (Debian/Ubuntu) or
    download release jar from <https://github.com/skylot/jadx/releases>
  - `cfr` (fallback): `wget https://www.benf.org/other/cfr/cfr-0.152.jar`
  - `jd-cli` (fallback): `apt-get install -y jd-cli`
- **.NET DLL/EXE** — install ILSpy CLI:
  - `apt-get install -y dotnet-sdk-8.0` then `dotnet tool install -g ilspycmd`
  - Fallback (IL only, no C#): `apt-get install -y mono-utils` for `monodis`
- **Diff tooling** — `git` is in the sandbox by default; no install needed

If a decompiler refuses to install in the sandbox (network/permission), report
the blocker and surface the binary pair for offline analysis rather than
fabricating a result.

## When to use

The user, the program scope, or the recon brief mentions any of:

- "this version fixes" / "vendor patched" / a CVE published with vendor binaries
- A pair of binaries with `vulnerable` / `fixed`, `pre-patch` / `post-patch`,
  or `vN.X` / `vN.Y` naming
- A request to "diff these jars" or "find the fix in this DLL"

Skip if the source code is already public — diffing source is
strictly easier than diffing decompiled output. This skill exists for the
binary-only case.

## Workflow Decision Tree

1. **Identify which binary is which**
   - Names like `patched.jar` / `unpatched.jar`, `vulnerable.jar` / `fixed.jar`
     → use as labelled
   - Version numbers (`app-1.2.3.jar` vs `app-1.2.4.jar`) → higher = patched
     under semver
   - File timestamps (`ls -lt *.jar`) → newer is *usually* patched, **not
     reliable** if files were copied between hosts
   - **Ambiguous?** Stop and ask, do not guess. Calling the patched version
     "vulnerable" inverts the entire diff and burns the rest of the analysis
2. **Format dispatch**
   - Java JAR/WAR → JAR workflow below
   - .NET DLL/EXE → .NET workflow below
   - Other (Go binary, Rust, native) → out of scope for this skill; pivot to
     `radare2`/`ghidra` and a manual approach
3. **Context**
   - CVE or vuln description provided → focus diff analysis on related changes
   - Blind analysis → comprehensive review of every meaningful change

## Workspace Setup

```bash
WORKSPACE="patch-analysis-$(date +%s)"
mkdir -p "$WORKSPACE/decompiled" "$WORKSPACE/output"
cd "$WORKSPACE"
git init -q
git config user.email analyzer@local
git config user.name "Patch Analyzer"
```

The workspace is a git repo so we can use `git diff` between two committed
states (unpatched → patched) rather than running an external diff tool.

## Skip Third-Party Libraries (WAR / fat-JAR Optimisation)

For `.war` files or fat JARs, decompiling everything wastes time. Extract
ONLY proprietary code first:

```bash
# 1. Inspect WAR layout
unzip -l unpatched.war | grep "WEB-INF/classes" | grep "\.class$" | head -30
# look for vendor / company / internal package roots

# 2. Extract just the proprietary packages
mkdir -p temp-unpatched
unzip unpatched.war "WEB-INF/classes/com/vendor/*" -d temp-unpatched/
unzip unpatched.war "WEB-INF/classes/com/acme/*"   -d temp-unpatched/

# 3. Repackage as a slim JAR for the decompiler
(cd temp-unpatched/WEB-INF/classes && jar cf ../../../vendor-unpatched.jar .)

# Repeat for the patched WAR.
```

Why this matters:

- Third-party library updates (Jackson, Spring, Hibernate) are documented
  upstream — diffing them adds noise without insight
- Proprietary code changes are where the unique vulnerability lives
- Slim JAR decompiles in seconds rather than minutes

## JAR Workflow

### Step 1: Decompile unpatched

```bash
# jadx (preferred)
jadx -d "$WORKSPACE/decompiled" --no-res --no-imports --comments-level none vendor-unpatched.jar

# or cfr
java -jar cfr-0.152.jar vendor-unpatched.jar --outputdir "$WORKSPACE/decompiled" --caseinsensitivefs true

# or jd-cli
jd-cli -od "$WORKSPACE/decompiled" vendor-unpatched.jar
```

### Step 2: Commit unpatched as the baseline

```bash
cd "$WORKSPACE"
git add -A
git commit -q -m "unpatched"
git tag unpatched
```

The tag name `unpatched` is conventional — `analyze-diff` below relies on it.

### Step 3: Decompile patched (clear the directory first)

```bash
rm -rf "$WORKSPACE/decompiled/"*
jadx -d "$WORKSPACE/decompiled" --no-res --no-imports --comments-level none vendor-patched.jar
```

### Step 4: Commit patched

```bash
cd "$WORKSPACE"
git add -A
git commit -q -m "patched"
git tag patched
```

## .NET Workflow

Identical four-step sequence — only the decompiler call changes:

```bash
# Step 1: unpatched
ilspycmd -o "$WORKSPACE/decompiled" -p vendor-unpatched.dll
git add -A && git commit -q -m "unpatched" && git tag unpatched

# Step 3: patched
rm -rf "$WORKSPACE/decompiled/"*
ilspycmd -o "$WORKSPACE/decompiled" -p vendor-patched.dll
git add -A && git commit -q -m "patched" && git tag patched
```

If only `monodis` is available, you get IL rather than C# — readable but
substantially harder. Note this in the report and downgrade confidence.

## Diff Generation

```bash
cd "$WORKSPACE"
git log --oneline --decorate -10
git diff --stat unpatched patched
git diff --name-status unpatched patched
git diff unpatched patched > output/patch-analysis.diff
git diff --name-only unpatched patched > output/changed-files.txt
```

Now `output/patch-analysis.diff` is the artifact to analyse.

## Security Analysis

**MANDATORY**: read the diff in full, not via grep or pattern matching. The
LLM has to reason about the code change, and grep cannot infer that a
re-ordered check is now defensive vs. that an added bound is loose enough
to bypass.

### Step 1: Filter third-party noise

Before reading every change, separate:

- **Third-party**: library upgrades (Spring, Jackson, Hibernate, Newtonsoft.Json)
  — match against `mvn`/`nuget` upstream changelogs and skip unless flagged in
  the vendor's CVE
- **Proprietary**: vendor-specific packages (`com.vendor.*`, `Acme.Internal.*`)
  — these are where the application-specific fix lives

### Step 2: Read every diff

For each modified file:

1. **Read every change**, even small ones — single-line bug fixes are common
2. **Read surrounding context**, not just the diff window
3. **Distinguish security from refactoring/feature** — a renamed variable or
   reformatted method is not a fix; an added length check is
4. **Reason about the original vulnerability** — what attack was possible
   *before* this change? What does the new code prevent?
5. **Assess completeness** — does the fix close the whole class, or only one
   path? Bypasses often live in sibling code paths the patch missed

### High-priority indicators

- Input validation added where none existed
- Sanitisation/encoding of user-controlled data (HTML escape, URL encode,
  JSON serialiser swap)
- Authentication/authorisation checks introduced (role check, owner check,
  CSRF token)
- Bounds checking before array/buffer access
- Type checking or casting changes (especially `instanceof`/`is` filters)
- Path canonicalisation (calls to `Paths.normalize`, `realpath`, etc.)
- Parameterised queries replacing string-concatenated SQL
- Deserialisation filters or whitelists (`ObjectInputFilter`,
  `SerializationBinder`)
- Resource limits (size, timeout, rate, max collection length)
- Cryptographic primitive swaps (MD5 → SHA-256, ECB → GCM, weak PRNG → CSPRNG)

## Reporting

```markdown
# Patch Analysis Summary

## Overview
<What was analysed: vendor, product, version pair, binary type>

## Vulnerability Identified: <Type / CVE>

**Severity**: Critical/High/Medium/Low

## Detailed Analysis

### File: <path/to/Foo.java>:Lstart-Lend
- **Before**: <quote the unpatched fragment>
- **After**: <quote the patched fragment>
- **Inferred bug**: <one paragraph explaining the original weakness>
- **Patch behaviour**: <what the fix does and why it closes the path>
- **Bypass risk**: <any way around the fix the agent should test next>

(repeat per impacted file)

## Completeness Assessment

<Is the fix comprehensive? Are there sibling code paths the patch missed?
What residual exposure remains?>

## Confidence Level

Overall confidence: HIGH/MEDIUM/LOW (<percent>%)

<Caveats: decompiler artefacts, missing PDB / debug info, IL vs C# fidelity>
```

## Common Failure Modes

- **"No decompiler found"** — install jadx (JAR) or ilspycmd (.NET) per
  Prerequisites; do not retry without the dependency present
- **"Not a git repository"** — re-run the workspace setup; the diff workflow
  needs a git repo
- **"Need at least 2 commits"** — the unpatched OR patched commit was missed;
  re-decompile and commit
- **"No differences found"** — the two binaries are byte-identical (rebuild
  artefact?), or the decompiler emitted identical output despite a real
  source change. Verify by running `sha256sum` on both binaries before giving
  up

## Pro Tips

1. Always tag commits — `git diff unpatched patched` is more legible than
   `git diff HEAD~1 HEAD`, and survives interleaved exploratory commits
2. Decompile to a normalised form (`jadx --no-imports --comments-level none`)
   so cosmetic differences don't pollute the diff
3. If the decompiler emits `// $FF: synthetic` or `/* error */` markers,
   note the affected file in the report — those regions can hide changes
4. For obfuscated jars, run a deobfuscation pass first (`Procyon`, `JEB`)
   or skip — diffing obfuscated output is signal-poor
5. When the patch ships with a security advisory text, read it FIRST. The
   advisory tells you what to look for in the diff; without it you're
   reading 50 files looking for one defensive check

## Corpus-Derived Advanced Workflows

Patterns extracted from 967 disclosed reports ($17.8M total bounty). These show HOW top researchers use patch diffing to find real bugs.

### Patch-Bypass Hunting ($225K+ pattern)

When a vendor publishes a security fix, read the patch and find what it did NOT fix:

1. **Read the patch diff** — identify the exact defensive check added
2. **Enumerate sibling code paths** — find every other path that handles the same input class
3. **Test whether the fix covers ALL paths** — incomplete patches leave the original bug exploitable via an alternate route
4. **Check for fix-then-regress** — the next release may revert or weaken the fix

```bash
# Clone the repo and diff the security commit
git log --oneline --all --grep="CVE-" | head -20
git diff <commit-before>...<security-fix-commit> -- '*.java' '*.py' '*.go'

# Find sibling code paths the patch may have missed
git grep -n "$(grep -oP 'function_name_from_patch' output/patch-analysis.diff)" -- '*.java'
```

### Parser-Differential Auditing ($500K+ pattern)

When two systems parse the same input (CDN + origin, sanitizer + browser, proxy + backend), diff how they interpret edge cases:

1. **Identify the parsing chain** — which systems sit in the request path
2. **Read the relevant RFC** — find every "MAY", "SHOULD", and "implementation-defined" clause
3. **Construct inputs that exploit parser disagreement** — bare CR, chunk extension, empty comments, overlong encodings

This applies to:
- HTTP intermediaries (CDN, LB, WAF, reverse proxy) — request smuggling
- HTML sanitizers vs browser parsers — XSS
- URL parsers across languages/frameworks — SSRF, open redirect
- Serialization formats with multiple implementations — deserialization bugs

### n-Day Development Workflow ($1M+ pattern)

When a CVE drops, read the patch commit (diff reveals what was broken), build from the vendor's regression test as PoC skeleton, fingerprint targets running the vulnerable version via Shodan/Censys, and test the patch against input variations for incomplete fixes.

### Inter-Subsystem Object Lifetime Auditing ($11.3M pattern)

When a new subsystem interacts with existing object management, audit the lifetime handoff: map reference counting, identify cross-subsystem ownership transfers, check lifecycle ordering (can the new subsystem hold a reference after the old one frees it), and test GC/destructor ordering for races.

### Incomplete-Patch Detection Checklist

After reading any security patch, systematically check:

1. **Did the fix only block one tag/input/path?** Enumerate all other tags/inputs/paths that survive
2. **Did the fix add a check in one branch?** Check the else/fallback branch
3. **Did the fix validate on write?** Check if validation is also needed on read
4. **Did the fix cover one encoding?** Test other encodings (URL, Unicode, double-encoding)
5. **Did the fix address one platform?** Test the less-popular platform (Windows when fix targeted Linux)

### Chaining Patch Diff with Other Tools

1. **patch_diff -> semgrep**: write a custom semgrep rule targeting the exact vulnerable pattern from the diff, then scan the full codebase for other instances
2. **patch_diff -> nuclei**: write a custom nuclei template that tests for the pre-patch behavior on live targets
3. **patch_diff -> git blame**: trace when the vulnerable code was introduced to find other commits by the same author with similar patterns
