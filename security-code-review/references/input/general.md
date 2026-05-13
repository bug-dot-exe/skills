# Input Validation — Non-Obvious Patterns

Patterns that are easy to miss. Claude knows "validate input server-side" — this
covers what actually goes wrong.

## File Upload: Check Content Bytes, Not Content-Type

The `Content-Type` header is user-controlled — attackers set it to anything.
Detect MIME type from the actual file content (magic bytes). Check both the
detected MIME and the file extension, and generate a new filename (UUID) instead
of using the user-provided one.

## Path Traversal: Resolve Symlinks Before Prefix Check

Checking `startsWith(uploadDir)` is insufficient if the path contains symlinks.
Resolve the full path (symlinks included) and then verify the resolved path is
inside the allowed directory. Also strip directory components — use only the
basename of user-provided filenames.

## Null Byte Injection in Filenames

Some languages/libraries truncate strings at null bytes. `malicious.php\x00.jpg`
may pass an extension check for `.jpg` but be saved as `malicious.php`. Use
languages/APIs that don't truncate at null bytes, or explicitly reject filenames
containing null bytes.

## Unicode Normalization Attacks

Different Unicode representations of the same character (`é` vs `e\u0301`) can
bypass allowlists or create distinct-looking but identical paths. Normalize
Unicode input (NFC/NFKC) before validation.

## Allowlists Over Blocklists

Blocklists are incomplete by definition — there's always another encoding,
bypass, or edge case. Validate against a known-good set of allowed values.
This applies to file types, URL schemes, sort columns, and any enumerable input.

## Integer Overflow and Negative Values

Check numeric ranges server-side. A negative quantity times a positive price
yields a negative total (refund to attacker). Unsigned integers can wrap around.
Validate `min` and `max` bounds for all numeric inputs.
