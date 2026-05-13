# General Format Principles

Regardless of vulnerability class:

1. **Show, don't just tell.** Every PoC must produce observable evidence.
2. **Diff expected vs actual.** Clearly state what *should* happen and what *does* happen.
3. **One vulnerability per PoC.** Keep demonstrations focused. Chain demonstrations
   belong in a separate "exploit chain" document.
4. **Version-pin the target.** State the exact version, commit hash, or configuration
   that is vulnerable.
5. **Include cleanup.** If the PoC creates artifacts (files, database entries, user accounts),
   document how to clean them up.
