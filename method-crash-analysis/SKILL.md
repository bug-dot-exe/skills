---
name: method-crash-analysis
description: Crash triage methodology — function tracing, line-execution coverage, gcov-based coverage, and rr-based record-and-replay debugging for non-deterministic bugs
depends_on: []
---

# Crash Analysis

Methodology for triaging fuzzer/sanitizer crashes from a binary or memory-corruption finding through to a reproducible, understood failure. Four sub-techniques cover the spectrum from "what executed" to "why it diverged each run":

| Technique | When to use |
|---|---|
| **Function tracing** | Identify which functions executed during a crashing run |
| **Line-execution check** | Verify exactly which lines ran inside a hot function |
| **gcov coverage** | Have a gcov-instrumented build, want a code-coverage diff between runs |
| **rr (record-and-replay)** | Bug is non-deterministic; need exact replay with reverse-step debugging |

## Prerequisites

Tooling expected in the sandbox or installed by the agent:
- `gcc -fprofile-arcs -ftest-coverage` (gcov instrumentation, install: `apt install gcc`)
- `gcov` and `lcov` (coverage reporting, install: `apt install gcov lcov`)
- `rr` (Mozilla record-and-replay debugger, install: build from source — kernel `perf_event_paranoid<=1` required)
- `gdb` or `lldb` (interactive debugging, install: `apt install gdb`)

## Function Tracing

Goal: identify the call sequence that led to the crash.
1. Compile target with `-pg` or use `ltrace`/`strace`/`uftrace` for runtime call tracing.
2. Run the crashing input under the tracer. Save trace to `funcs.log`.
3. Walk back from the last few entries — the crash function is usually 1-3 frames above the SIGSEGV/SIGABRT.
4. Cross-reference the trace with the binary's symbol table (`nm`, `objdump -t`) to map addresses to source.

## Line-Execution Check

Goal: confirm which lines executed inside the suspect function before the crash.
1. Compile with debug symbols and gcov instrumentation: `gcc -g -fprofile-arcs -ftest-coverage`.
2. Run the crash input. The process aborts but `.gcda` files are flushed for any function that returned cleanly.
3. For functions that crashed mid-execution, instrument with `__attribute__((destructor))` or use `gcov --use-hotpath` to estimate execution.
4. Compare against the source code line-by-line — the diverging line is the crash precursor.

## gcov Coverage Diffs

Goal: compare coverage between a benign run and a crash run to isolate the unique code path.
1. Run the benign input, collect `gcov` output.
2. Run the crash input, collect a second `gcov` output.
3. Diff the two — lines covered ONLY in the crash run are the suspect path.
4. Use `lcov --capture` and `genhtml` for visualization on multi-source-file projects.

## rr (Record-and-Replay)

Goal: deterministically replay a crash to step backwards from the failure point.
1. Record: `rr record ./target <crash-input>` — produces a recording in `~/.local/share/rr/`.
2. Replay: `rr replay` — drops into gdb-like REPL with reverse-step support.
3. Use `reverse-stepi`, `reverse-continue`, `watch` on the corrupted address.
4. Walk backwards from the crash to the corrupting write — that's the root cause line.

## Cross-references

- After a crash is understood: see `exploitability_validation` for whether it's reachable from untrusted input.
- Once exploitability is proven: see `exploit_development` for weaponization.

---

## Corpus-Derived Crash Hunting Patterns

Techniques from high-bounty crash and memory-corruption reports. These extend the triage methodology above with proactive crash discovery.

### Interpreter and Runtime Crash Hunting

For any language runtime that accepts untrusted code (mruby, Lua, Python embedded, WASM, V8):

1. **Parser-to-runtime trust boundary**: The runtime trusts that the parser only produces well-formed bytecode. The parser has bugs. Search for code paths where parser output (opcodes, immediate values, type tags) is consumed without re-validation by the VM.
2. **Implicit non-null preconditions**: Enumerate all VM-internal pointer fields with implicit non-null assumptions (target_class, target_module, current_block, method_table). Override or null these via the scripting API and observe crashes.
3. **Re-entrant initializer audit**: For any class with a C-implemented `initialize`, test `initialize_copy` with an instance where `initialize` was never called. The backing C data pointer is NULL, and `initialize_copy` dereferences it.
4. **Fallback method crashes**: Enumerate fallback methods the runtime calls when something else fails (`to_s`, `inspect`, `hash`, `<=>`, `method_missing`). Pass objects of unexpected types (NilClass, Symbol, Fixnum) that lack the expected method — the fallback path often has no type guard.

### Boundary-Value Codegen Threshold Fuzzing

Any time a compiler or runtime has a magic constant that switches between two code paths:

1. Identify threshold values: max argument count (mruby: 127), max local variables, max stack depth, max string length for interning.
2. Test at threshold - 1, threshold, threshold + 1. The off-by-one at the boundary often produces a wild pointer, wrong opcode, or buffer overflow.
3. Look for integer width mismatches at boundaries: `size_t` to `int` truncation when field values exceed 2^31 is a recurring crash source in filesystem drivers and parsers.

### Implicit Context Push/Pop Auditing

Any time codegen pushes an implicit scope (loop context, exception handler, register frame):

1. Construct inputs that force unusual nesting: `break` inside `||=` inside a block, `return` inside `ensure` inside a lambda.
2. The codegen may push a context in one path and pop it in another, leaving stale data on the stack.
3. Diff-based approach: take two near-identical programs (one crashes, one does not), run both through verbose mode, and diff the bytecode/IR output.

### C-Extension Uninitialized Data Exploitation

For language runtimes with C-backed objects:

1. Enumerate every class with C-implemented backing data (`DATA_PTR` in Ruby, `tp_init` in Python, `luaL_checkudata` in Lua).
2. For each, override `initialize` to skip the C initialization, then call methods that access the backing data.
3. The uninitialized pointer dereference is a crash; in some cases, attacker-controlled heap layout makes it a controlled read/write.

### HTTP Protocol Implementation Crashes

For HTTP servers, proxies, and parsers:

1. **Multiplexed protocol resource accounting**: In HTTP/2 and HTTP/3, every error path is also a resource accounting path. Audit: does a reset stream free the accounting slot? Does a malformed header frame increment the allocation counter without a matching deallocation?
2. **Internal allocation amplification**: Byte-count limits are necessary but insufficient. A single CONTINUATION frame is small but may trigger unbounded internal header table growth. Test: send maximum-length CONTINUATION sequences.
3. **Bare CR and non-ASCII byte handling**: Send requests with bare `\r` (no `\n`), non-ASCII bytes in headers, and mixed `\r\n` / `\n` line endings. Parser differentials between proxy and origin create smuggling opportunities.

### Game Asset and Binary Format Fuzzing

For any application that auto-loads binary assets (game engines, document viewers, media players):

1. Enumerate every binary asset format the engine loads (nav meshes, textures, models, maps, config files).
2. For each, extract the parsing code, build a standalone harness with ASAN, and fuzz with format-aware mutators.
3. Focus on fields that control allocation sizes: any field that becomes a `malloc(field_value)` or `memcpy` length is a crash candidate.
4. Multiplayer games that load assets from remote servers are RCE targets — a malicious server serves a crafted asset to the client.

### postMessage targetOrigin Auditing

For every `window.postMessage(data, targetOrigin)` call in web applications:

1. Check how `targetOrigin` is sourced. If it comes from `event.origin`, `document.referrer`, or a URL parameter, the attacker controls it.
2. If `targetOrigin` is `"*"` — any window can receive the message. If it contains sensitive data (tokens, codes), this is a data leak.
3. Chain with OAuth: if an OAuth authorization code is sent via postMessage to a controllable origin, the attacker captures the auth code.

### Static Memory Layout Exploitation

When any memory-corruption primitive exists in a system with static memory layout (secure elements, embedded firmware, RTOS):

1. Static memory layouts mean addresses are deterministic — no ASLR to defeat.
2. A single-byte overflow at a known address is sufficient for exploitation when the heap layout never changes.
3. Map the memory layout from the binary or firmware image, identify what sits adjacent to the corruption target, and calculate the overwrite offsets statically.
