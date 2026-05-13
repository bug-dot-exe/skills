---
description: Reverse-engineer compiled binaries (JARs, DLLs) to analyze security patches. Decompile, diff, and identify vulnerability fixes. Usage: /patch-diff-analyzer <binary1> <binary2>. Requires jadx (JAR) or ilspycmd (DLL).
---

# Patch Diff Analyzer

**IMPORTANT**: Users may request analysis of security patches in compiled binaries (JARs, DLLs, etc.) to understand what vulnerabilities were fixed. This skill helps decompile binaries, generate diffs, and identify security-relevant changes.

## Helper Scripts

Helper scripts are located at `~/.claude/scripts/patch-diff-analyzer/`:
- `setup-workspace.sh <workspace-name>` — creates workspace with git tracking
- `decompile-jar.sh <jar-file> <output-dir>` — decompile JAR using jadx/jd-cli/cfr
- `decompile-dll.sh <dll-file> <output-dir>` — decompile DLL using ilspycmd/monodis
- `analyze-diff.sh <workspace>` — generate diff between unpatched/patched commits

---

## Workflow Decision Tree

When a user requests patch analysis:

1. **Identifying Binaries**: Do you need to determine which file is patched vs unpatched?
   - **YES** → Go to [Binary Identification](#binary-identification)
   - **NO** → User has specified versions, proceed to [Setup & Decompilation](#setup--decompilation)

2. **File Format**: What type of binary are you analyzing?
   - **Java JAR** → Use [JAR Decompilation Workflow](#jar-decompilation-workflow)
   - **.NET DLL/EXE** → Use [.NET Decompilation Workflow](#net-decompilation-workflow)
   - **Other** → Consult user for appropriate decompiler

3. **Analysis Context**: Does the user provide vulnerability information?
   - **YES (CVE/Description provided)** → Focus analysis on related changes
   - **NO (Blind analysis)** → Perform comprehensive security change analysis

---

## Binary Identification

**CRITICAL**: Before decompilation, correctly identify which binary is the patched version.

### Identification Methods

1. **Explicit Naming**: Files named `patched.jar` / `unpatched.jar` → Use as specified
2. **Version Numbers**: `app-1.2.3.jar` vs `app-1.2.4.jar` → Higher version = patched
3. **File Timestamps**: `ls -lt *.jar` → Newer = likely patched (not reliable if copied)
4. **When Ambiguous**: **ALWAYS** ask the user for clarification

---

## Setup & Decompilation

### Workspace Setup

```bash
bash ~/.claude/scripts/patch-diff-analyzer/setup-workspace.sh <workspace-name>
```

---

## Efficient Extraction (Skip Third-Party Libraries)

**CRITICAL**: For WAR files or large applications, extract ONLY proprietary code before decompiling.

```bash
# List WAR contents to identify proprietary packages
unzip -l unpatched.war | grep "WEB-INF/classes" | grep "\.class$" | head -30

# Extract ONLY proprietary classes
mkdir -p temp-unpatched
unzip unpatched.war "WEB-INF/classes/com/vendor/*" -d temp-unpatched/
cd temp-unpatched/WEB-INF/classes
jar cf ../../../vendor-unpatched.jar .

# Repeat for patched version
```

---

## JAR Decompilation Workflow

### Step 1: Decompile Unpatched Version
```bash
bash ~/.claude/scripts/patch-diff-analyzer/decompile-jar.sh <unpatched.jar> <workspace>/decompiled/
```

### Step 2: Commit Unpatched Version
```bash
cd <workspace> && git add -A && git commit -m "Unpatched version" && git tag unpatched
```

### Step 3: Decompile Patched Version
```bash
rm -rf <workspace>/decompiled/*
bash ~/.claude/scripts/patch-diff-analyzer/decompile-jar.sh <patched.jar> <workspace>/decompiled/
```

### Step 4: Commit Patched Version
```bash
cd <workspace> && git add -A && git commit -m "Patched version" && git tag patched
```

---

## .NET Decompilation Workflow

### Step 1: Decompile Unpatched Version
```bash
bash ~/.claude/scripts/patch-diff-analyzer/decompile-dll.sh <unpatched.dll> <workspace>/decompiled/
```

### Steps 2-4: Same git commit process as JAR workflow.

---

## Diff Generation & Analysis

```bash
bash ~/.claude/scripts/patch-diff-analyzer/analyze-diff.sh <workspace>
```

**MANDATORY**: Read the generated diff file completely. **DO NOT** use grep or pattern matching. Read and reason about the actual code changes.

---

## Security Analysis

### Step 1: Filter Third-Party Libraries

**MANDATORY FIRST STEP**: Separate proprietary code from third-party libraries. Proprietary code changes indicate application-specific security fixes.

### Step 2: Analysis Process

1. **Read Every Change**: Don't skip any modifications, even small ones
2. **Understand Context**: Look at surrounding code, not just the diff lines
3. **Identify Security Changes**: Distinguish security fixes from refactoring/features
4. **Reason About Vulnerability**: What attack was possible before? What does the fix prevent?
5. **Assess Completeness**: Is the fix comprehensive or could there be bypasses?

### What to Look For

**High-Priority Indicators**:
- Input validation added where none existed
- Sanitization/encoding of user-controlled data
- Authentication/authorization checks introduced
- Bounds checking before array/buffer access
- Type checking or casting changes
- Canonicalization of file paths
- Parameterized queries replacing string concatenation
- Deserialization filters or whitelists
- Resource limits (size, timeout, rate)

---

## Reporting Findings

```markdown
# Patch Analysis Summary

## Overview
[Brief description of what was analyzed]

## Vulnerability Identified: [Type/CVE]

**Severity**: [Critical/High/Medium/Low]

## Detailed Analysis

### File: [path/to/file.java:line-range]

[Detailed analysis]

## Completeness Assessment

[Is the fix complete? Any potential bypasses? Additional recommendations?]

## Confidence Level

Overall confidence: [HIGH/MEDIUM/LOW] ([percentage]%)
```

---

## Error Messages & Solutions

| Error | Solution |
|-------|---------|
| "No decompiler found" | Install jadx (`brew install jadx`) or ilspycmd (`dotnet tool install -g ilspycmd`) |
| "Not a git repository" | Run `setup-workspace.sh` first |
| "Need at least 2 commits" | Ensure both versions were committed |
| "No differences found" | Verify you decompiled different versions |
