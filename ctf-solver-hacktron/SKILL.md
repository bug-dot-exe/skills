---
name: ctf-solver-hacktron
description: Source-code-driven CTF solver for web, pwn, crypto, reverse, and forensics challenges that ship with sources and a remote endpoint
depends_on: []
---

# CTF Solver (Source-Code-Driven)

> Companion to `ctf_solver_methodology.md`. That playbook targets HackTheBox /
> TryHackMe network boxes (nmap → service enum → privesc → flag). This playbook
> targets **coding-CTF challenges** that ship with source code, a binary, or a
> static endpoint — Web, Pwn, Crypto, Reverse, Forensics, Misc — where the win
> condition is reading the source, finding the bug, and writing a Python exploit.
> Use both: route to the right one based on whether the challenge gives you an
> IP-and-go-find-services or an archive-and-source-code.

## Core Mindset

Think like a competitive CTF player:

- **Curiosity** — question every assumption, explore edge cases
- **Persistence** — if one approach fails, try another (5+ payloads before dismissing)
- **Creativity** — combine techniques in unexpected ways
- **Methodical** — document findings, avoid repeating failed attempts

## Operating Constraints (autonomous-agent edition)

The Hacktron source assumes a Claude-Code-style human/operator. bug.exe's
agent runs unattended in a sandbox, so every probe must be **non-blocking and
script-driven**:

- Prefer Python scripts (`requests` for HTTP, `socket` with timeouts for TCP)
  over interactive tools — write to disk, run, parse stdout
- `curl` is fine for one-shot HTTP, but never `nc`/`netcat`, `vim`/`nano`,
  `less`/`more`, or `ssh` without `-o BatchMode=yes`
- Always set socket and request timeouts (5-10s default) — a hung probe
  burns the agent's iteration budget for no signal
- Keep payloads small; redirect outputs to files in the working dir; surface
  the flag via the reporting tool when captured

## Challenge Categories

Recognize and adapt your approach based on challenge shape:

| Category | Key Indicators | Primary Techniques |
|----------|---------------|-------------------|
| **Web** | URL endpoint, HTTP, HTML/JS/PHP/Python source | SQLi, XSS, SSRF, SSTI, auth bypass, path traversal, prototype pollution, deserialization |
| **Pwn** | Binary file, TCP connection, C source | Buffer overflow, ROP, format string, heap exploitation, integer overflow |
| **Crypto** | Encrypted data, crypto code, math operations | Frequency analysis, padding oracle, RSA attacks (low-e, common modulus), hash collisions, weak PRNG |
| **Reverse** | Binary/executable, obfuscated code | Disassembly, debugging (`gdb`, `radare2`), deobfuscation, patching, dynamic tracing |
| **Forensics** | File dump, network capture, disk image | File carving (`binwalk`, `foremost`), steganography (`zsteg`, LSB tools), memory analysis (`volatility`), pcap reconstruction |
| **Misc** | Anything else | OSINT, esoteric languages, jailed-shell escape, LLM-prompt-injection, puzzles |

## Solving Methodology

### Phase 1 — Reconnaissance

Read everything carefully:

1. **Challenge name and description** — point value hints at difficulty;
   wording often telegraphs the intended technique ("don't trust the
   client", "the admin reviews submissions", etc.)
2. **Source code (if provided)** — read every line. Identify entry points,
   user-controlled inputs, dangerous functions (`eval`, `exec`, `pickle.loads`,
   `Function`, `system`, raw SQL string formatting), trust boundaries, and
   any sanitisation that exists
3. **Environment / attachments** — map endpoints, fingerprint stack
   (response headers, error pages, framework signatures), note specific
   versions for known CVEs

### Phase 2 — Vulnerability Identification

For each input, ask:

1. **Where does it go?** — database, filesystem, command, template, deserialiser
2. **What sanitisation exists?** — filters, encoding, validation, allowlists
3. **What's the trust boundary?** — client vs server, anon vs authed, role A vs B
4. **What assumptions can be broken?** — type confusion, race conditions, logic
   flaws, unicode normalisation, parser differentials

### Phase 3 — Exploitation

Build the exploit iteratively:

```
Hypothesis → Minimal PoC (Python script) → Verify → Expand → Capture Flag
     ↑                                                       │
     └────────────── Adjust if fails ────────────────────────┘
```

**Persistence rule**: a single 400/403 from one payload does not refute the
hypothesis. Run at least 3 payload variants (encoding, scheme, parameter
position) before concluding the path is dead. See `variant_hunting` for the
matrix discipline.

### Phase 4 — Flag Extraction

Common flag locations, in order of likelihood:

- Response body (JSON field, HTML comment, script tag)
- Response headers (custom `X-*` headers, `Location:` on redirects, `Set-Cookie`)
- Error messages and stack traces
- Environment variables (`/proc/self/environ`, `/proc/1/environ`)
- Filesystem (`/flag`, `/flag.txt`, `/root/flag*`, `/home/*/flag*`,
  `/tmp/flag*`, `/srv/flag*`, often readable to anyone once you have an RCE)
- Database entries (especially the `flags` or `secrets` table)

## Solution Documentation

After capturing the flag, record the win:

```markdown
## Challenge: <Name>
**Category**: Web/Pwn/Crypto/Rev/Forensics/Misc

### Vulnerability
<One-paragraph explanation of the bug>

### Exploitation
<Step-by-step path from input to flag>

### Payload
<Final working payload — paste verbatim>

### Flag
FLAG{the_captured_flag}
```

## Success Criteria

The challenge is solved when:

1. Flag is captured from the live environment (not theorised)
2. Flag matches expected format (`FLAG{...}`, `flag{...}`, `HACKTRON{...}`,
   `HTB{...}`, etc.)
3. Exploit is reproducible — running the script again returns the flag
4. Solution is documented

Do not stop until the flag is in hand or all reasonable approaches are exhausted.

## Approach Summary

```
1. READ the description carefully (every word matters)
2. ANALYSE all provided source line by line
3. MAP attack surface (inputs, endpoints, dangerous sinks)
4. IDENTIFY candidate vulnerabilities
5. WRITE a Python script for the most promising candidate
6. ITERATE — variant matrix before dismissal
7. EXTRACT the flag
8. DOCUMENT the solution
```

## Corpus-Derived Exploit Patterns

Distilled from 355 disclosed reports ($15M in bounties). Apply these during
Phase 2 (Vulnerability Identification) and Phase 3 (Exploitation).

### Parser Differential Exploitation

When two components parse the same input differently, the gap is exploitable:

1. Identify any chain where input passes through parser A then parser B
   (CDN + backend, sanitizer + renderer, proxy + app server)
2. Find inputs that parser A considers safe but parser B interprets as
   dangerous (e.g., bare CR in HTTP headers, entity encoding in HTML)
3. Test HTTP request smuggling via `Transfer-Encoding` vs `Content-Length`
   disagreements between layers

### Cache Poisoning via RFC Violations

For any HTTP intermediary (CDN, load balancer, WAF, reverse proxy):

1. Enumerate RFC-violating inputs: bare CR after method, bare LF in headers,
   null bytes, overlong UTF-8, duplicate headers
2. Test whether the intermediary caches a response keyed on a different
   request than the origin processed
3. Test `Host` header variations: port manipulation, absolute-URL in
   request line, `X-Forwarded-Host` injection

### Cryptographic Implementation Asymmetry

For any cryptographic check, the implementer must enumerate every failure
mode. Exploitation targets the uncovered mode:

1. Test DNSSEC validation bypass via record types the validator does not
   check (NSEC3, wildcard expansion, delegation edge cases)
2. Test signature verification with modified algorithm fields, null bytes
   in signed data, or stripped signatures
3. Test E2EE across clients -- key exchange may differ between platforms

### Signed Request Canonicalization Collisions

For every signed payment or API request:

1. Find the signature field and reverse-engineer the canonicalization
2. Test for collisions: can you modify a non-signed field (whitespace,
   encoding, field order) to change the semantic meaning while keeping
   the signature valid?
3. Test parameter pollution: add duplicate parameters where only one
   is included in the signature

### Game Asset Format RCE

For any multiplayer game or engine that auto-loads assets from a server:

1. Enumerate every binary asset format the client parses (maps, models,
   textures, configs, scripts, nav meshes)
2. Fuzz each format with malformed data -- focus on length-prefixed fields,
   array indices, and nested structures
3. Test: can a malicious server send a crafted asset that exploits the client?

### Unchecked Index to Write Primitive

When you find an array write with attacker-controlled index:

1. Determine the write target's memory layout (what is adjacent?)
2. Calculate the relative offset to interesting targets (return addresses,
   function pointers, vtables)
3. Test both positive and negative indices (underflow)

### Markdown Extension DoS

When a platform enables a third-party renderer in user-controllable markdown
(Mermaid, MathJax, LaTeX, code-fence syntax highlighting):

1. Test the renderer for ReDoS (exponential backtracking on crafted input)
2. Test resource exhaustion (deeply nested structures, infinite loops in
   diagram definitions)
3. Test whether the renderer runs client-side (XSS risk) or server-side
   (SSRF/RCE risk)

### Cross-Client Crypto Consistency

For any multi-client E2EE product:

1. Enumerate all clients (desktop, web, mobile-iOS, mobile-Android)
2. Test whether key verification works identically across all clients
3. Test downgrade attacks: can you force a fallback to a weaker protocol
   by manipulating the capability negotiation?
4. Test key rotation: do all clients handle re-keying atomically?

## See also

- `ctf_solver_methodology.md` — network-CTF / HackTheBox-style boxes
- `variant_hunting` — payload-variant matrix and persistence discipline
- `chain_building` — composing partial primitives into full exploits
