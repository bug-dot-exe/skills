# Stage 01: Bootstrap

Stage ID: `S01_BOOTSTRAP`

## Objective

Initialize the MAIA auditor runtime. Auto-detect the target platform and build the scope manifest.

## Steps

1. Output the banner from `references/banner.md`, followed by `maia_auditor`.
2. Ask the user for the target directory to audit (or use current directory).
3. Parse user input for exclusions:
   - If input contains `--exclude`, extract excluded paths and store in `./.maia_auditor/exclusions.txt` (one path per line)
   - Common exclusions: test directories, mock contracts, scripts, deployment helpers, external libraries
   - All subsequent pipeline stages must skip excluded paths during file discovery
4. Default to `terse` runtime output unless user requests verbosity.
5. Operate in one-shot full audit mode — do not ask the user to run scripts.
6. Detect target platform by scanning files (respecting exclusions):
   - `.sol` files + `hardhat.config.*` / `foundry.toml` / `truffle-config.js` / `remappings.txt` → **EVM**
   - `Move.toml` + `AptosFramework` or `aptos_framework` → **Move-Aptos**
   - `Move.toml` + `Sui` or `sui::` imports → **Move-Sui**
   - If unclear → report what was found and ask user
7. Create the report output directory: `./report_maia_{YYYYMMDD_HHMMSS}/` (e.g., `report_maia_20260317_143022/`). Use the current timestamp.
8. Store detected platform in `./.maia_auditor/platform.txt`
9. Store target path in `./.maia_auditor/target.txt`
10. Store report directory path in `./.maia_auditor/report_dir.txt`

## Build scope manifest

After platform detection, build the scope file `./.maia_auditor/scope.md`.

**Use bash to generate the file list and line counts — do NOT read files individually:**

```bash
echo "## Scope" > ./.maia_auditor/scope.md
echo "" >> ./.maia_auditor/scope.md
echo "**Platform:** {detected_platform}" >> ./.maia_auditor/scope.md
# Generate file table with line counts in one command:
echo "" >> ./.maia_auditor/scope.md
echo "| File | Lines |" >> ./.maia_auditor/scope.md
echo "|------|-------|" >> ./.maia_auditor/scope.md
find {source_dirs} -name "*.{ext}" {exclusion_flags} -exec wc -l {} \; | awk '{printf "| %s | %s |\n", $2, $1}' >> ./.maia_auditor/scope.md
echo "" >> ./.maia_auditor/scope.md
find {source_dirs} -name "*.{ext}" {exclusion_flags} | wc -l | xargs -I{} echo "**Files in scope:** {}" >> ./.maia_auditor/scope.md
find {source_dirs} -name "*.{ext}" {exclusion_flags} -exec cat {} \; | wc -l | xargs -I{} echo "**Total lines:** {}" >> ./.maia_auditor/scope.md
```

Adapt `{source_dirs}`, `{ext}`, and `{exclusion_flags}` based on detected platform and exclusions.

### scope.md format

```markdown
## Scope

**Platform:** {EVM|Move-Aptos|Move-Sui}
**Files in scope:** {count}
**Total lines:** {count}

| File | Lines |
|------|-------|
| contracts/Token.sol | 245 |
| contracts/Vault.sol | 412 |
| ... | ... |

**Excluded:**
- tests/
- contracts/mocks/
```

## Build concatenated source file

Create `./.maia_auditor/packed_source.txt` — a single file containing ALL in-scope source code, each file prefixed with its path.

**CRITICAL: Use a single bash command to create this file. NEVER read files one by one and write them token by token — that wastes minutes of generation time. One shell command, done in under a second:**

For EVM projects:
```bash
find contracts/ src/ . -maxdepth 5 -name "*.sol" ! -path "*/node_modules/*" ! -path "*/out/*" ! -path "*/cache/*" ! -path "*/artifacts/*" ! -path "*/test/*" ! -path "*/tests/*" ! -path "*/lib/*" -exec sh -c 'echo "// === FILE: {} ===" && cat {} && echo ""' \; > ./.maia_auditor/packed_source.txt 2>/dev/null
```

For Move projects:
```bash
find sources/ -name "*.move" ! -path "*/build/*" ! -path "*/deps/*" ! -path "*/tests/*" -exec sh -c 'echo "// === FILE: {} ===" && cat {} && echo ""' \; > ./.maia_auditor/packed_source.txt 2>/dev/null
```

If exclusions exist in `./.maia_auditor/exclusions.txt`, add corresponding `! -path` flags to the find command.

After creation, store the line count:
```bash
wc -l < ./.maia_auditor/packed_source.txt > ./.maia_auditor/source_lines.txt
```

## Remaining setup

11. Store intermediate work in `./.maia_auditor/`
12. Generate final reports into the report directory with platform prefix
13. Perform writeability check: create and remove a probe file in `./.maia_auditor/` and the report directory.
14. If direct file write fails, retry once via shell heredoc syntax.
15. Never abort on first write failure — recover and continue.

## Platform-specific project detection

### Platform: EVM
- Look for `.sol` files in `contracts/`, `src/`, or root
- Confirm with `hardhat.config.js`, `hardhat.config.ts`, `foundry.toml`, `truffle-config.js`, `brownie-config.yaml`, or `remappings.txt`
- Check for `package.json` with hardhat/ethers/foundry dependencies
- Exclude `node_modules/`, `out/`, `cache/`, `artifacts/` from audit scope

### Platform: Move-Aptos
- Look for `Move.toml` and `sources/` directory
- Confirm Aptos by checking for `AptosFramework`, `aptos_framework`, or `aptos_std` in `Move.toml` dependencies
- Exclude `build/`, `deps/`, `tests/`, `.aptos/`

### Platform: Move-Sui
- Look for `Move.toml` and `sources/` directory
- Confirm Sui by checking for `Sui`, `sui::`, or `0x2::` in `Move.toml` dependencies or source imports
- Exclude `build/`, `deps/`, `tests/`

## Progress output

After bootstrap is complete, print:

```
Please wait a moment — you will be able to choose detectors soon.
```

Follow `references/output_budget.md`.

## Constraints

- Hide internal reasoning from output.
- Provide only concise status updates.
- Continue audit even if initial file operations encounter issues.
