---
name: punycode_unicode
category: vulnerabilities
description: Unicode and Punycode attacks including IDN homograph, normalization bypass, RTL override, zero-width characters, case mapping collisions, and LLM prompt injection via invisible characters
depends_on: []
---

# Unicode/Punycode Attacks

Exploiting Unicode text processing to bypass security controls, create visual deception, and evade filters. Unicode provides multiple representations for visually identical or similar characters, and normalization transforms can change the security meaning of input.

## Discovery Signals

| # | Signal | Where to Check | Implication |
|---|--------|---------------|-------------|
| 1 | Username/email uniqueness enforced | Registration, profile settings | Normalization collisions can create duplicate identities |
| 2 | Domain allowlist for redirects/links | OAuth callbacks, link previews, email validation | IDN homograph bypass of allowlist matching |
| 3 | Keyword/word filters on user input | Chat, comments, content moderation | Zero-width chars split keywords: `ad​min` passes filter |
| 4 | File upload with name displayed to users | Attachments, cloud storage | RTL override disguises `.exe` as `.pdf` in displayed name |
| 5 | HTML sanitizer processing user content | Webmail, markdown renderers, rich text | CSS `\NNNNNN` escapes bypass sanitizers (H1 #982291: $5k) |
| 6 | LLM-backed features consuming user text | AI summaries, AI triage, chatbots | Invisible Unicode tags inject prompt instructions (H1 #2372363: $2.5k) |
| 7 | App name / display name registration | OAuth apps, developer portals, bots | Invisible chars create visually identical names (H1 #785243: Twitter) |
| 8 | URL displayed in UI (link preview, address bar) | Chat apps, email clients, browsers | RTL override + homoglyphs spoof displayed URLs |
| 9 | Case-insensitive string comparison | Auth, dedup, search | Turkish dotless i and long s create case-mapping collisions |
| 10 | Source map or error page showing paths | JS bundles, 500 pages | Fullwidth `../` normalizes to path traversal post-filter |
| 11 | Web Components / Shadow DOM email rendering | Webmail products | Closing tag injection escapes shadow isolation (H1 #982291) |
| 12 | CRLF / header injection defenses | Redirect endpoints, cookie setters | Unicode CR/LF equivalents bypass ASCII-only CRLF filters (H1 #191380: $1.7k) |

## Unicode Normalization Attack Matrix

| Normalization | Input | Output | Bypass |
|---------------|-------|--------|--------|
| NFKC | `ａｄｍｉｎ` (fullwidth) | `admin` | Username collision; register fullwidth variant of existing user |
| NFKC | `℀` (account of symbol) | `a/c` | Path traversal if normalized after filter |
| NFKC | `‥` (two dot leader) | `..` | Directory traversal component |
| NFKC | `．．／` (fullwidth `../`) | `../` | Path traversal bypassing ASCII filter then normalizing |
| NFKC | `ſ` (long s) | `S` (on uppercase) | Case-fold collision; `ſ`.upper() == `S` |
| NFKD | `é` (e-acute precomposed) | `e` + `́` (combining) | Length change breaks fixed-size buffers; truncation after combining mark |
| NFC | `e` + `́` (combining) | `é` | Recomposition creates different codepoint; evades codepoint-based filter |
| NFKC | `ﬁ` (fi ligature) | `fi` | Length expansion: 1 char to 2; breaks offset calculations |
| CSS decode | `\00003c` inside `url()` | `<` | Sanitizer treats as opaque CSS; browser decodes to HTML (H1 #982291) |

## Homograph/IDN Attack Patterns

| Technique | Target | Example | Impact |
|-----------|--------|---------|--------|
| Cyrillic `a` (U+0430) for Latin `a` | `apple.com` | `xn--pple-43d.com` displays as `apple.com` | Phishing, domain allowlist bypass |
| Cyrillic `o` (U+043E) for Latin `o` | `google.com` | `xn--ggle-55da.com` | Link preview spoofing |
| Mixed-script | `paypal.com` | Cyrillic `p`, `a` mixed with Latin | Email sender spoofing |
| Latin alpha (U+0251) for `a` | `admin` username | `ɑdmin` | Account impersonation, privilege confusion |
| Turkish dotless i (U+0131) for `i` | `Admin` (case-folded) | `Admın` lowercases to different string | Locale-dependent auth bypass |
| Mongolian vowel separator (U+180E) | App names, usernames | Invisible char in `Twitter Web App` | Source label spoofing (H1 #785243) |
| Hangul filler (U+3164) | Any identifier | Fully invisible character accepted by some filters | Username impersonation |
| Combining marks on ASCII | `admin` | `a` + U+0308 looks like `a` with diaeresis | Visual confusion; filter bypass if marks stripped late |

## Key Vulnerabilities

### IDN Homograph Attacks

Register domains using characters visually identical to target domain characters. Punycode encoding: `apple.com` with Cyrillic `a` becomes `xn--pple-43d.com`.

Attack scenarios: phishing with homograph domains, bypassing domain allowlists that compare display form, link preview spoofing in chat applications, email sender spoofing.

### Unicode Normalization Bypass

1. Application filters `../` from input
2. Attacker sends fullwidth `．．／`
3. Filter passes (not ASCII `../`)
4. Application normalizes to NFKC: becomes `../`
5. Path traversal succeeds

### CSS Numeric Escape Sanitizer Bypass

Most HTML sanitizers treat `<style>` body as opaque CSS. CSS `\NNNNNN` escapes are decoded by the browser but not the sanitizer. H1 #982291 (HEY.com, $5k): `\00003c` decodes to `<`, smuggling HTML through CSS context to break out of Shadow DOM and inject Stimulus.js form gadget for persistent email forwarding compromise.

### Invisible Character Identity Collision

Zero-width and format characters create strings that display identically but differ in bytes:

| Character | Codepoint | Name | Attack |
|-----------|-----------|------|--------|
| `​` | U+200B | Zero-width space | Filter bypass: `ad​min` passes "admin" filter |
| `‌` | U+200C | Zero-width non-joiner | Username impersonation: `admin‌` != `admin` |
| `‍` | U+200D | Zero-width joiner | WAF keyword splitting |
| `﻿` | U+FEFF | BOM / ZWNBSP | Prepend to bypass start-of-string anchors |
| `᠎` | U+180E | Mongolian vowel separator | Incomplete blacklists miss it (H1 #785243) |
| `ᅟ` | U+115F | Hangul Choseong filler | Invisible; rarely blacklisted |
| `1`-`F` | Tag chars | Unicode tag block | LLM invisible prompt injection (H1 #2372363) |

### Right-to-Left Override (U+202E)

```
filename: report‮fdp.exe
Displays as: reportexe.pdf  (appears to be a PDF)
```

Used for file name deception, URL obfuscation, and Trojan Source attacks in code repositories.

### Case Mapping Collisions

| Character | Uppercase | Lowercase | Issue |
|-----------|-----------|-----------|-------|
| `ß` (sharp s) | `SS` | `ß` | Length changes on case conversion |
| `ı` (dotless i) | `I` | `ı` | Turkish locale: `I` lowercases to `ı`, not `i` |
| `ſ` (long s) | `S` | `ſ` | `ſ`.upper() == `S`; matches `s` when uppercased |
| `ﬁ` (fi ligature) | `FI` | `ﬁ` | Length changes during case conversion |

## Defense-Bypass Pairs

| Defense | Bypass | Technique |
|---------|--------|-----------|
| ASCII-only CRLF filter (`%0D%0A` blocked) | Unicode CR/LF equivalents (`%E5%98%8A`, `%E5%98%8D`) | Characters normalize to CR/LF after filter (H1 #191380) |
| HTML sanitizer on tag content | CSS `\NNNNNN` escapes in `<style>` body | Browser decodes CSS escapes; sanitizer treats as opaque |
| Zero-width character blacklist (U+200B) | U+180E Mongolian separator, U+3164 Hangul filler | Incomplete blacklist misses rare whitespace chars |
| Shadow DOM / Web Component isolation | Inject `</template></message-content>` via CSS escape | Break out of shadow root into parent DOM |
| Username uniqueness check (byte comparison) | Normalization-equivalent codepoints | `admin` vs `ɑdmin` (U+0251) pass dedup but display same |
| Keyword filter / content moderation | Zero-width joiner between letters | `p‍o‍r‍n` bypasses word filter for "porn" |
| IDN display restriction (single-script) | Mixed confusable within same script | Latin `l` vs digit `1`; both in ASCII range |
| CSP blocking inline scripts | Framework gadgets (`data-controller`, `data-remote`) | Stimulus.js / jQuery-UJS auto-execute from DOM attributes |

## Chain Patterns

| First Bug | Second Bug | Combined Impact | Example |
|-----------|-----------|----------------|---------|
| Unicode CRLF injection (`%E5%98%8A`) | Cookie injection (`Set-Cookie: auth_token=X`) | Cross-account XSS | H1 #191380: CRLF sets attacker cookie, then loads XSS payload |
| CSS `\NNNNNN` sanitizer bypass | Shadow DOM escape + Stimulus.js gadget | Silent email forwarding takeover | H1 #982291: invisible form submission via framework gadget |
| Zero-width char in app name | Source label impersonation | Brand spoofing, phishing | H1 #785243: fake "Twitter Web App" source label |
| Unicode tag char prompt injection | LLM-generated summary/triage | Manipulate staff decisions via AI output | H1 #2372363: invisible instructions in report body |
| Fullwidth `../` normalization bypass | Path traversal | File disclosure, LFI | Filter passes fullwidth; NFKC normalizes to `../` |
| Normalization username collision | Password reset to attacker email | Account takeover | Register `ɑdmin`, reset password for normalized `admin` |
| RTL override in filename | Social engineering download | Malware delivery disguised as document | `report‮fdp.exe` displays as `reportexe.pdf` |
| Homograph domain registration | OAuth redirect allowlist bypass | Token theft via phishing redirect | `xn--pple-43d.com` matches visual check for `apple.com` |

## Methodology

1. **Identify comparison points**: login, registration, search, filters, URL validation
2. **Test normalization**: send fullwidth, compatibility characters, check if normalized
3. **Test homographs**: register usernames or supply URLs with Cyrillic/Greek look-alikes
4. **Test zero-width**: inject zero-width characters in filtered words and identifiers
5. **Test RTL override**: embed U+202E in file names, URLs, user-supplied text
6. **Test case mapping**: supply characters with asymmetric case conversion
7. **Test CSS escapes**: in webmail/sanitizer contexts, use `\NNNNNN` inside `<style>` to smuggle HTML
8. **Test invisible chars for LLMs**: inject U+E0001-E007F tag characters in any field consumed by AI features

## Pro Tips

1. When a system rejects U+200B with a specific error ("invisible unicode characters"), it has an incomplete blacklist -- test U+180E, U+3164, U+115F, U+FFA0 (H1 #785243 methodology)
2. CSS `\00003c` decodes to `<` in the browser but passes sanitizers -- the highest-paid unicode bypass class for webmail ($5k+ payouts)
3. Framework gadgets (Stimulus, HTMX, Alpine.js) are CSP-compliant XSS primitives -- inject `data-controller` attributes after sanitizer bypass
4. Shadow DOM is NOT a security boundary -- closing `</template></message-content>` tags escapes into parent DOM
5. Unicode tag characters (U+E0000 plane) are invisible to humans but tokenized by LLMs -- the newest high-yield vector (2024-2026)
6. Half-encoded path traversal (`.%2e/`) bypasses filters that block both raw `../` and full `%2e%2e/` (CVE-2021-41773)
7. `Domain=.target.com` on an injected cookie propagates to ALL subdomains -- widens CRLF cookie injection impact
8. Polyglot JPG+HTML files pass image validation but render as HTML when Content-Type is missing or confused

## LLM Rendering-vs-Tokenization Mismatch

The universal LLM Unicode attack primitive: find an encoding where what the human/UI sees differs from what the LLM tokenizer processes. The input LOOKS benign to moderators/reviewers but INSTRUCTS the LLM differently.

| Encoding Trick | Visible To Human | Processed By LLM | Attack |
|----------------|-----------------|-------------------|--------|
| Unicode tag chars (U+E0001-E007F) | Invisible (zero-width) | Tokenized as ASCII instructions | Invisible prompt injection ($2.5K, H1 #2372363) |
| ASCII-tag-encoded payload | Empty/invisible in UI | LLM decodes to full instruction set | Training data poisoning via decoded prompts ($200, H1 #2370955) |
| Combining marks over ASCII | Appears as accented text | Some tokenizers strip marks, revealing different base text | Filter bypass with hidden meaning |
| RTL override around instructions | Text appears reversed/garbled | LLM may process in logical order | Instruction smuggling past human review |

**Testing methodology**: For any LLM-backed feature that consumes user text and produces output consumed by staff/users: (1) inject Unicode tag-encoded instructions in user-controllable fields, (2) check if the LLM output reflects the hidden instructions, (3) verify the hidden text is invisible in the UI/moderation view.

## Windows Best-Fit Conversion Attacks

Windows-specific Unicode-to-ASCII best-fit mapping is a recurring source of cross-platform-asymmetry bugs. The same input safe on Linux becomes dangerous on Windows.

| Input Char | Best-Fit Maps To | Exploit |
|-----------|-----------------|---------|
| `․` (one dot leader) | `.` | Bypass extension filters: `shell․php` -> `shell.php` |
| `‥` (two dot leader) | `..` | Path traversal after best-fit conversion |
| `．` (fullwidth period) | `.` | Same as above, different codepoint |
| `＂` (fullwidth quotation) | `"` | Argument injection in CLI commands |
| `＞` (fullwidth greater-than) | `>` | Output redirection injection |

**Key insight**: Security filters running at Unicode level pass the input; then Windows WideCharToMultiByte best-fit maps it to dangerous ASCII at the byte level. Test EVERY security check that runs on Windows with Unicode equivalents of the filtered characters (H1 #2550951).

## HSTS/CORS/CSP Hostname Bypass via IDN Normalization

For every security check keyed on a hostname (HSTS, CORS origin, CSP, public-suffix-list lookup): verify the lookup key is fully normalized BEFORE comparison.

| Check | Bypass Input | Mechanism | Impact |
|-------|-------------|-----------|--------|
| HSTS lookup | `curl.sё` (Cyrillic `ё`) | IDN Nameprep maps U+0451 to period equivalent | HSTS downgrade to HTTP (CVE-2022-42916, H1 #1730660) |
| CORS origin | Origin with confusable IDN chars | IDN normalization creates different origin string | Cross-origin data theft |
| CSP domain | `script-src` with IDN domain | Normalization mismatch between CSP parser and browser | CSP bypass for XSS |
| Cookie domain | `.target.com` with Unicode period | Period normalization differs between cookie jar and TLS | Cookie injection across subdomains |

## Internationalization Platform Attack Surfaces

i18n/l10n platforms have unique Unicode attack surfaces beyond general web apps:

| Surface | Attack | Why Different |
|---------|--------|--------------|
| Translation string input | Directional override, zero-width injection | Translators paste from external sources; validation assumes trusted input |
| Locale/language selectors | Locale injection affecting string comparison | Turkish locale changes `I`->`ı` behavior system-wide |
| ICU message format strings | Format string injection via Unicode | `{0,choice,...}` patterns parsed differently with Unicode |
| Pluralization rules | Rule injection via CLDR data | Custom plural rules execute as expressions in some frameworks |
| Font fallback chains | Homograph rendering differences | Different fonts render confusables differently (H1 #278718) |

## Fix-Scope Escalation Methodology

When a Unicode/encoding fix is applied: (1) test ALL fields on the same form, (2) test ALL forms in the app, (3) test ALL endpoints accepting the same data type. Fixes applied per-field or per-endpoint miss sibling surfaces. A fix deployed to one input consistently leaves 2-5 other inputs vulnerable to the same bypass (H1 #241596, #243611, #243635 -- same bug reported 3 times as fix was incomplete).

## Unicode Complexity Escalation Ladder

Test in order of increasing complexity -- each layer catches fixes that blocked the previous layer:

| Layer | Test Input | What It Catches |
|-------|-----------|----------------|
| 1. ASCII edge cases | `../`, `%00`, control chars | Basic filter |
| 2. Accented Latin | `é`, `ñ`, `ü` | NFC/NFD normalization gaps |
| 3. CJK characters | `一`, fullwidth ASCII | NFKC normalization gaps |
| 4. Combining marks | `a` + U+0308 + U+0327 | Mark stripping/reordering |
| 5. Rare whitespace | U+180E, U+3164, U+FFA0 | Incomplete blacklists |
| 6. Bidirectional | U+202E, U+2066-2069 | Display-vs-storage mismatch |
| 7. Tag characters | U+E0001-E007F | LLM-specific invisible injection |

## Byte-vs-Character Layer Mismatch

When filtering for dangerous bytes in text input, ensure the filter operates at the SAME layer as the eventual output. If output is byte-level (HTTP headers, filesystem), but the filter is character-level (Unicode string comparison), Unicode chars that normalize to dangerous bytes at the output layer will bypass the filter. Node.js HTTP client header injection via high Unicode codepoints that map to CR/LF bytes at the Latin1 output layer is the canonical example (H1 #409943).

## Validation Requirements

- Normalization bypass: filter evasion demonstrated with pre/post normalization difference
- Homograph: visual impersonation of a legitimate domain or username
- Zero-width: filter bypass or identity collision using invisible characters
- RTL override: file name or URL deception changing the apparent content
- Case collision: two different inputs resolving to the same identity after case conversion
- CSS escape: sanitizer bypass demonstrated with decoded HTML executing in browser
