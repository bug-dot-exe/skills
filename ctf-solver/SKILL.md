---
name: ctf-solver
description: Solve CTF (Capture The Flag) challenges by analyzing challenge descriptions, source code, and interacting with challenge environments to capture flags.
license: MIT (lifted from HacktronAI/skills 78596bb9 :: ctf-solver/SKILL.md)
compatibility: Requires network access to challenge environment. Python3 with requests library recommended.
metadata:
  author: hacktron
  version: "1.0.0"
  category: security
  difficulty: variable
allowed-tools: Bash(*) Read Write Network
---

# CTF Solver

**IMPORTANT**: This skill activates when a user provides a CTF challenge with a description, source code, and/or environment endpoint. Your goal is to act as an expert CTF player and capture the flag.

## Critical Rules

**ALWAYS prefer Python scripts for testing and exploitation:**
- Write standalone Python scripts using `requests` for HTTP interactions
- Use `socket` with timeouts for TCP connections (never interactive)
- Scripts should be non-blocking and output results to stdout

**NEVER use blocking/interactive commands:**
- `nc` / `netcat` (blocks waiting for input)
- `vim` / `nano` / editors (requires interaction)
- `less` / `more` (requires interaction)
- `ssh` without `-o BatchMode=yes`
- Any command that waits for user input

**Instead use:**
- Python scripts with `requests` for HTTP
- Python `socket` with timeouts for TCP
- `curl` for simple HTTP requests
- `cat`, `head`, `tail` for file viewing
- Redirect output: `echo "data" | command`

---

## Core Mindset

Think like a competitive CTF player:
- **Curiosity**: Question every assumption, explore edge cases
- **Persistence**: If one approach fails, try another
- **Creativity**: Combine techniques in unexpected ways
- **Methodical**: Document findings, avoid repeating failed attempts

## Challenge Categories

Recognize and adapt your approach based on challenge type:

| Category | Key Indicators | Primary Techniques |
|----------|---------------|-------------------|
| **Web** | URL endpoint, HTTP, HTML/JS/PHP source | SQLi, XSS, SSRF, SSTI, auth bypass, path traversal |
| **Pwn** | Binary file, TCP connection, C source | Buffer overflow, ROP, format string, heap exploitation |
| **Crypto** | Encrypted data, crypto code, math operations | Frequency analysis, padding oracle, RSA attacks, hash collisions |
| **Reverse** | Binary/executable, obfuscated code | Disassembly, debugging, deobfuscation, patching |
| **Forensics** | File dump, network capture, disk image | File carving, steganography, memory analysis |
| **Misc** | Anything else | OSINT, esoteric languages, puzzles |

---

## Solving Methodology

### Phase 1: Reconnaissance

**Read everything carefully:**

```
┌─────────────────────────────────────────────────────────────┐
│ CHALLENGE INPUTS                                             │
├─────────────────────────────────────────────────────────────┤
│ 1. Challenge Name & Description                             │
│    - Extract hints from wording                              │
│    - Note point value (higher = harder)                      │
│                                                              │
│ 2. Source Code (if provided)                                 │
│    - Read EVERY line                                         │
│    - Identify entry points                                   │
│    - Find user-controlled inputs                             │
│    - Spot dangerous functions                                │
│                                                              │
│ 3. Environment / Attachments                                 │
│    - Map available endpoints                                  │
│    - Identify technologies (headers, errors)                 │
│    - Note versions for known CVEs                            │
└─────────────────────────────────────────────────────────────┘
```

### Phase 2: Vulnerability Identification

**For each input, ask:**

1. **Where does user input go?** (database, filesystem, command, template)
2. **What sanitization exists?** (filters, encoding, validation)
3. **What's the trust boundary?** (client vs server, authenticated vs anonymous)
4. **What assumptions can be broken?** (type confusion, race conditions, logic flaws)

### Phase 3: Exploitation

**Build your exploit iteratively:**

```
Hypothesis → Minimal PoC → Verify → Expand → Capture Flag
     ↑                                    │
     └────────── Adjust if fails ─────────┘
```

### Phase 4: Flag Extraction

**Common flag locations:**
- Response body or headers
- Error messages
- Environment variables
- Files (`/flag`, `/flag.txt`, `/home/*/flag`)
- Database entries

---

## Solution Documentation

**After capturing the flag, document:**

```markdown
## Challenge: [Name]
**Category**: [Web/Pwn/Crypto/Rev/Forensics/Misc]

### Vulnerability
[What was the vulnerability]

### Exploitation
[Step-by-step exploitation]

### Payload
[Final working payload]

### Flag
FLAG{the_captured_flag}
```

---

## Success Criteria

**The challenge is solved when:**
1. Flag is captured from the challenge environment
2. Flag matches expected format
3. Exploit is reproducible
4. Solution is documented

**Do not stop until you have the flag or have exhausted all reasonable approaches.**

---

## Approach Summary

```
1. READ the challenge description carefully
2. ANALYZE all provided source code line by line
3. MAP the attack surface (inputs, endpoints, functions)
4. IDENTIFY potential vulnerabilities
5. WRITE Python scripts to test exploits
6. ITERATE if initial attempts fail
7. EXTRACT the flag
8. DOCUMENT the solution
```

---

## Corpus-Derived CTF and Security Research Techniques

Patterns from high-bounty reports that map directly to CTF-style problem solving.

### Inter-Subsystem Object Lifetime Auditing

When a new subsystem (kernel module, runtime extension, plugin API) interacts with existing object lifecycle management:
1. Identify every place the new subsystem registers or references an object managed by the old subsystem.
2. Trace what happens when the old subsystem frees or recycles the object -- does the new subsystem's reference become dangling?
3. Focus on file descriptors, sockets, memory regions, and handles that are shared between subsystems.
4. The classic pattern: io_uring registers a reference to a file, the file is closed via the normal syscall path, io_uring's reference becomes use-after-free.

### n-Day Exploit Development From Patches

When a CVE patches a memory corruption or logic bug:
1. Read the patch commit and the regression test -- together they define the trigger.
2. Build the vulnerable version and reproduce the crash or misbehavior from the regression test.
3. Develop the exploit from crash to control: triage the corruption primitive, find the heap layout, build the exploitation chain.
4. The patch tells you exactly where the bug is -- the challenge is turning the primitive into impact.

### Parser Differential Exploitation

When a sanitizer uses a different parser than the renderer (HTML sanitizer vs browser parser, YAML validator vs YAML loader):
1. Identify which parser the sanitizer uses and which the consumer uses.
2. Build inputs where the sanitizer's parser produces a safe AST but the consumer's parser produces a dangerous one.
3. Focus on edge cases: empty comments, nested tags, encoding boundaries, null bytes, BOM characters.
4. Systematically test: what does parser A see vs what does parser B see for the same input?

### Argument Injection in CLI Exec

For every codebase that shells out to a binary (git, tar, rsync, find, curl, ffmpeg):
1. List every `exec`/`system`/`popen` call and identify which arguments come from user input.
2. Test whether the user input can inject additional arguments (leading dashes, `--` separator bypass).
3. Focus on commands with dangerous flags: `git -c`, `tar --use-compress-program`, `rsync -e`, `find -exec`, `curl -o`.
4. Even when the value is properly escaped against shell injection, argument injection may still work if the binary interprets the value as a flag.

### Sandbox Escape via Runtime Method Removal

For any embedded language sandbox (mruby, Lua, V8 isolates, WASM runtimes):
1. The sandbox restricts what the script can call -- but the C/native extensions beneath the sandbox assume certain built-in methods always exist.
2. Test what happens when you `undef`, override, or remove methods that the native layer depends on.
3. Trigger native code paths that call back into the scripted layer after the expected method has been replaced with attacker-controlled code.
4. Focus on property accessors (getters/setters), `method_missing`, `__getattr__`, and operator overloads as callback vectors.

### Binary Format Parser Exploitation

For every custom binary format parser whose input can be remotely supplied:
1. Audit every "read length, then read length bytes" operation for bounds validation.
2. Check if all three components of the (filename, extension, content) triple are attacker-controlled -- if so, arbitrary file write is likely.
3. Test with malformed files: truncated headers, oversized length fields, negative lengths, zero-length fields.
4. For game asset formats (NAV, BSP, SAV, VMF): auto-downloaded assets from untrusted servers are a recurring RCE surface.

### Stat-Then-Open TOCTOU

When a privileged binary or library operates on user-controlled file paths:
1. Find every `stat()` + `open()` pair (or `access()` + `open()`, or `lstat()` + `open()`).
2. Between the check and the use, the file can be replaced with a symlink to a target file.
3. Exploit: create the legitimate file, wait for the check to pass, swap it with a symlink before the open.
4. Tools: `inotifywait` on the directory to time the swap precisely.

### Binary Hardening Gap Exploitation

For any shipped binary, desktop app, or CLI tool:
1. Run `checksec` (Linux) or equivalent to check: PIE, RELRO (full), stack canaries, NX, ASLR, Fortify.
2. Missing PIE = no ASLR on the binary itself = predictable addresses for ROP chains.
3. Missing Full RELRO = GOT overwrite is viable.
4. Report missing hardening as a finding, especially on privileged binaries (setuid, Windows services, launch daemons).
