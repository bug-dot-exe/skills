#!/usr/bin/env python3
"""Print Strix build_instruction() for a HackerOne handle (structured scopes).

Requires H1_USERNAME + H1_API_TOKEN and an importable strix package.

Usage:
  python3 h1_scope_block.py shopify
  STRIX_REPO=~/strix python3 h1_scope_block.py truist_financial_bbp
"""
from __future__ import annotations

import os
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: h1_scope_block.py <hackerone_handle>", file=sys.stderr)
        return 2
    handle = sys.argv[1].strip()
    if not handle:
        return 2

    repo = os.path.expanduser(os.environ.get("STRIX_REPO", os.path.join(os.path.expanduser("~"), "strix")))
    if repo not in sys.path:
        sys.path.insert(0, repo)

    try:
        from strix.interface.platforms import build_instruction, fetch_program
    except ImportError as e:
        print(
            "Could not import strix. Install editable (pip install -e /path/to/strix) "
            f"or set STRIX_REPO (tried {repo!r}): {e}",
            file=sys.stderr,
        )
        return 1

    try:
        scope = fetch_program("hackerone", handle)
    except Exception as e:
        print(f"fetch_program failed: {e}", file=sys.stderr)
        return 1

    print(build_instruction(scope))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
