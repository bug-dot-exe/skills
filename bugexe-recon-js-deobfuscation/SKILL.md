---
name: js_deobfuscation
category: reconnaissance
description: Reconstruct original JavaScript source from minified / obfuscated / bundled production builds using source maps, AST analysis, webpack unbundlers (webcrack), and AI-assisted un-minification (humanify)
depends_on: []
---

# JavaScript Deobfuscation & Bundle Reconstruction

When `js_analysis.md`'s grep-based triage comes up thin on a heavily-minified
bundle, the signal is still there — just buried under variable-name mangling,
bundle concatenation, and dead-code elimination. This skill walks through
recovering readable source: source maps → webcrack → AST analysis → AI-assisted
renaming.

## When to Use

- Production bundle is one-lined, single-letter variables, no whitespace
- grep finds few endpoints / secrets but the app clearly does a lot
- You need to understand auth logic, crypto routines, or business rules
- A `.js.map` file 404s but you suspect there's an unprotected path
- You want to diff today's build against yesterday's to see what changed

## Methodology

### Phase 1: Exhaustive Source Map Discovery

Source maps are the fastest path to original source. Check every common location.

```bash
# Classic — append .map to every JS URL
while read url; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "${url}.map")
  [ "$code" = "200" ] && echo "[OK] ${url}.map"
done < js_assets.txt

# sourceMappingURL directive inside the bundle (absolute or relative path)
grep -rhoE '//# sourceMappingURL=[^ ]+' js_dump/*.js | sort -u
grep -rhoE '//@ sourceMappingURL=[^ ]+' js_dump/*.js | sort -u  # old syntax

# Common directory patterns for hidden maps
for path in \
  "/static/js/" "/assets/js/" "/static/" "/_next/static/chunks/" \
  "/static/chunks/" "/dist/" "/build/" "/js/" "/bundle/" \
  "/.well-known/sourcemaps/"; do
  curl -s -o /dev/null -w "%{http_code} https://target.com${path}\n" "https://target.com${path}"
done

# Specific build-tool directories
curl -s https://target.com/_next/static/chunks/main.js.map    # Next.js
curl -s https://target.com/assets/index.js.map                 # Vite/Rollup default
curl -s https://target.com/static/js/main.chunk.js.map         # CRA / Webpack 4

# Sometimes maps are behind an auth-free CDN subdomain
curl -s https://static.target.com/sourcemaps/main.js.map
curl -s https://cdn.target.com/latest/main.js.map

# GitHub / public repos — sometimes maps are accidentally committed
# (see github_dorking skill): site:github.com "target.com" filename:.map
```

If a map is found → go straight to Phase 2.

### Phase 2: Reconstruct Source from .map Files

A source map is v3 JSON containing original file paths + contents + mappings.

```bash
# Quick structural peek
curl -s https://target.com/main.js.map | jq 'keys, .version, .sources | length'

# Extract original files — three good tools:

# A. webcrack (best for full project recovery, including without .map)
pipx install webcrack
webcrack js_dump/main.js -o unpacked/         # full Webpack/JSX un-bundling
# With sourcemap:
webcrack js_dump/main.js --sourcemap main.js.map -o unpacked/

# B. smap (pulls sources from .map, writes them to disk)
pipx install smap
smap -o recovered/ https://target.com/main.js.map

# C. unmap (lightweight, Node-based)
npx -y sourcemap-cli https://target.com/main.js.map --output recovered/

# D. source-map-explorer — bundle composition analysis (what takes space)
npm i -g source-map-explorer
source-map-explorer main.js main.js.map
```

Recovered tree gives you:
- Original file paths (`/src/services/AdminAPI.ts`, `/src/auth/tokens.ts`)
- Developer comments, JSDoc annotations
- TypeScript / JSX pre-compilation (types + generics intact)
- `import` graph revealing internal service topology

**Always**: run `js_analysis.md` Phase 3-4 (endpoint + secret extraction) on the
recovered tree — many secrets hide in string literals that survive unminified
compilation.

### Phase 3: Webpack / Rollup Un-bundling (When No Source Map)

Even without `.map`, `webcrack` can reverse modern bundlers to near-original
modules.

```bash
# Install once
pipx install webcrack

# Un-bundle a single chunk
webcrack js_dump/main.js -o unpacked/

# Batch — unbundle everything
for js in js_dump/*.js; do
  webcrack "$js" -o "unpacked/$(basename "$js" .js)/" 2>/dev/null
done

# webcrack does:
# - Resolves webpack module IDs → semantic names via heuristics
# - Undoes common minifier transforms (!0 → true, comma expressions)
# - Splits one-liners into readable multi-line code
# - Removes string-array obfuscation (obfuscator.io style)
# - Recovers React JSX from compiled createElement trees
```

`webcrack` output is dramatically more grep-friendly. Re-run the patterns from
`js_analysis.md` Phase 3-4 against it.

### Phase 4: AST-Based Analysis (Precision Pattern Hunting)

Grep is fragile on minified code (variable names change between builds).
AST-level tools match code structure instead.

```bash
# --- ast-grep (fast structural match, Rust) ---
pipx install ast-grep-cli
# Find every fetch() call regardless of variable names
ast-grep --pattern 'fetch($URL, $$$)' --lang js js_dump/
# All axios method calls
ast-grep --pattern 'axios.$METHOD($URL, $$$)' --lang js js_dump/
# Auth token reads
ast-grep --pattern '$STORE.getItem("$KEY")' --lang js js_dump/
# Role checks
ast-grep --pattern 'if ($USER.role === "$ROLE") $$$' --lang js js_dump/

# --- semgrep (rule-based, hundreds of pre-built rules) ---
pipx install semgrep
semgrep --config auto js_dump/ --json -o semgrep_js.json
# Specific rule categories:
semgrep --config "r/javascript.lang.security" js_dump/
semgrep --config "p/secrets" js_dump/
semgrep --config "p/javascript" js_dump/

# --- Babel parser + custom walk (for programmatic analysis) ---
cat <<'EOF' > extract_calls.js
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;
const fs = require("fs");

const code = fs.readFileSync(process.argv[2], "utf8");
const ast = parser.parse(code, {sourceType: "unambiguous", plugins: ["jsx", "typescript"]});

traverse(ast, {
  CallExpression({node}) {
    if (node.callee.name === "fetch" && node.arguments[0]) {
      console.log(`fetch: ${JSON.stringify(node.arguments[0])}`);
    }
  },
  StringLiteral({node}) {
    if (/^(\/api\/|https?:\/\/|ey[A-Za-z0-9_-]+\.)/.test(node.value)) {
      console.log(`url: ${node.value}`);
    }
  },
});
EOF
npm i -g @babel/parser @babel/traverse 2>/dev/null
node extract_calls.js js_dump/main.js > extracted_calls.txt
```

### Phase 5: AI-Assisted Un-minification (humanify)

Replaces `a, b, c` → meaningful names via local LLM inference. Slow but
produces the most readable output.

```bash
# humanify — AI-powered variable renaming (uses local Ollama or OpenAI API)
npm i -g humanify

# With local model (no API costs, slower)
humanify local js_dump/main.js -o main_humanified.js

# With OpenAI (faster, costs tokens)
humanify openai --apiKey "$OPENAI_API_KEY" js_dump/main.js -o main_humanified.js

# The result has:
# - Meaningful variable names inferred from usage context
# - Function names based on what they do
# - Better grep-ability for subsequent passes

# Pair with webcrack first for best results:
webcrack js_dump/main.js -o unpacked/ && \
  for f in unpacked/*.js; do humanify local "$f" -o "humanified/$(basename "$f")"; done
```

### Phase 6: WASM Decompilation (When JS Logic Is in `.wasm`)

```bash
# Disassemble to textual WAT
wasm2wat input.wasm -o input.wat

# Pseudo-C output (more readable)
wasm-decompile input.wasm -o input.dcmp

# wabt-tools: wasm-objdump shows imports/exports (the JS/WASM interface)
wasm-objdump -x input.wasm

# Extract strings (endpoints, constants, secrets)
strings input.wasm | grep -E '^(https?://|/[a-z]|[A-Z0-9]{20,})' | sort -u

# AI-assisted WASM RE (experimental but useful)
# https://github.com/jikkaku/wasm-humanify style tools
```

For deeper native-like reverse engineering of WASM (Ghidra / IDA Pro), the
scope exits this skill — see `web_binary_analysis.md` if you have one, or
fall back to dynamic analysis in `js_runtime_audit.md`.

### Phase 7: Build-Time Metadata Extraction

Modern bundlers leak useful metadata beyond code:

```bash
# Webpack runtime manifest — maps chunk IDs to hashed filenames
curl -s https://target.com/_next/static/chunks/webpack-*.js | \
  grep -oP '"[0-9]+":"[a-f0-9]+"' | head -30

# Next.js build ID (discloses deploy cadence, sometimes env)
curl -s https://target.com/_next/BUILD_ID

# Vite build info
curl -s https://target.com/assets/index-*.js | grep -oP '"buildTime":[0-9]+'

# License files (sometimes with internal attribution)
curl -s https://target.com/main.js.LICENSE.txt

# Commit hash leakage (from CI templating into bundle)
grep -rhoE '[a-f0-9]{7,40}' js_dump/*.js | head -20
# Pair with `git log` on an open-source part of the project if known
```

## Tool Cheat Sheet

| Tool | Purpose | Install |
|------|---------|---------|
| **webcrack** | Full Webpack / obfuscator.io un-bundling | `pipx install webcrack` |
| **smap** | Extract sources from `.map` files | `pipx install smap` |
| **source-map-explorer** | Bundle composition + source map viz | `npm i -g source-map-explorer` |
| **sourcemap-cli / unmap** | Lightweight `.map` → source | `npx sourcemap-cli <url>` |
| **ast-grep** | Structural AST pattern matching | `pipx install ast-grep-cli` |
| **semgrep** | Rule-based static analysis | `pipx install semgrep` |
| **@babel/parser** | Programmatic AST walk | `npm i -g @babel/parser @babel/traverse` |
| **humanify** | AI variable renaming | `npm i -g humanify` |
| **wabt (wasm2wat, wasm-decompile)** | WASM disassembly | `apt install wabt` |
| **retire.js** | JS library CVE scanner | `npm i -g retire` |
| **js-beautify** | Basic pretty-print | `npm i -g js-beautify` |

## What to Extract

- **Endpoint list** (after unbundling, regrep with `js_analysis.md` patterns)
- **Import graph** (internal service names from `import` statements)
- **Type definitions** (TypeScript/JSDoc types reveal data shapes)
- **Business-logic constants** (feature flag names, role strings, timeout values)
- **Crypto routines** (are keys derived client-side? are IVs hardcoded?)
- **Error message strings** (reveal backend framework / DB schema)
- **Dev-only code paths** (NODE_ENV === "development" branches)

## Tips

1. **webcrack first, everything else second** — dramatically improves every downstream tool's signal.
2. **Never trust the first minified output** — if webcrack fails, try `js-beautify` just for whitespace, then re-grep.
3. **Source-map discovery is worth 30 minutes** — try every subdomain, every build-tool default path.
4. **Humanify costs tokens with OpenAI** — run it on ONLY the chunks that matter (e.g., `auth.js`, `admin.js`), not every bundle.
5. **Diff across releases** — `webcrack` outputs are stable enough to diff between builds, revealing what auth logic changed.
6. **Store the unbundled tree in git** — re-running analyses as new rules come out costs minutes not hours.
7. **When `.map` 404s**, try the `.LICENSE.txt` file next door — it sometimes has the build identifier needed to guess the map path.
8. **WASM with exports + fetch interaction** → worth reverse-engineering. WASM that's pure numeric crunching → usually a dead end.

## Corpus-Derived Hunting Patterns

Techniques from disclosed reports where deobfuscation or deep JS analysis was the critical step.

### Base64/Delimiter Token Field Manipulation

When a token decodes to a delimiter-separated string (e.g., `base64(email|role|timestamp)`):

1. Decode and identify each field's purpose by varying one field at a time
2. Test boundary-shifting: move the delimiter one position to corrupt field parsing
3. Test field substitution: replace the email field with another user's email, re-encode, and submit
4. Many invitation/verification tokens use this pattern — the server splits on the delimiter without HMAC verification

### Multi-Layer Template Composition Injection

When a value flows through MORE THAN ONE template/parser/eval engine (e.g., Handlebars -> HTML -> JS):

1. After deobfuscation, trace which template engines process user input in sequence
2. Craft payloads that are benign in the FIRST engine but become active in the SECOND (e.g., a Handlebars partial that outputs valid JS when rendered into a `<script>` context)
3. The deobfuscated source reveals the template chain that minified bundles hide

### data-Attribute Sink Discovery

When CSP blocks inline JS, search deobfuscated bundles for JS that reads `data-*` attributes:

1. Find `dataset`, `getAttribute('data-')`, or jQuery `$.data()` calls
2. If the consuming JS passes the attribute value to `fetch()`, `eval()`, `innerHTML`, or template rendering, it is exploitable via HTML attribute injection
3. This pattern is common in chart libraries (Mermaid, Chart.js config objects), widget frameworks, and analytics SDKs

### eval/Function/setTimeout String-Form Audit

After deobfuscation, search for dynamic code execution sites:

1. Find every `eval()`, `new Function()`, `setTimeout(string)`, `setInterval(string)` call
2. Trace the data flow to each call site — if ANY user-controlled data reaches these sinks, it is XSS/RCE
3. Minified bundles often hide these in callback chains or promise resolvers that only become visible after unbundling

### Variant-Hunting on Patched CVEs

When a vendor patches a CVE in their web application:

1. Deobfuscate both the pre-patch and post-patch bundles (use Wayback to retrieve the old version)
2. Diff the deobfuscated output to identify exactly what was fixed
3. The same vulnerability class often exists in adjacent code paths that the patch did not cover
