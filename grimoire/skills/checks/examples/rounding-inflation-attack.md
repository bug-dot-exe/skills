# Example Check: Rounding Inflation Attack (2 of 2)

This check assesses whether rounding in vault-like contracts could enable an inflation attack.
It pairs with `rounding-direction.md` — that check identifies rounding sites, this one evaluates
a specific exploitation path.

## Check File

```markdown
---
name: rounding inflation attack
description: Assesses whether rounding in share/asset calculations could enable a vault inflation attack.
languages: solidity
severity-default: high
confidence: low
tools: [Grep, Read]
tags: [rounding, inflation, vault, defi, erc4626]
related-checks: [rounding-direction]
---

Look for vault-like patterns where shares are minted or burned in exchange for assets:

- `deposit()` / `mint()` / `withdraw()` / `redeem()` functions
- Share-to-asset or asset-to-share conversion math
- `convertToShares`, `convertToAssets` or equivalent

For each match, assess:
1. Can an attacker manipulate total assets or total shares independently?
2. Is there a minimum deposit or minimum shares requirement?
3. Does the first depositor path have special handling?

If (1) yes and (2) no and (3) no — likely vulnerable. Keep severity at high.
If mitigations exist (minimum deposit, dead shares, virtual shares) — adjust severity to low.
```

## Why This Check Works

- **Focused assessment.** This check does one thing: evaluate inflation attack feasibility.
  It doesn't try to find all rounding issues or assess other exploitation paths.
- **Low confidence is honest.** Vault inflation attacks require deep contextual reasoning.
  The check is a starting point — findings need manual review or PoC validation.
- **Clear decision tree.** Three questions with a direct severity mapping. The agent doesn't
  need to reason about what to do next.
- **Paired with a scanning check.** rounding-direction identifies the sites; this check
  evaluates one specific risk. Other risks (amplification, precision loss in fees) could be
  additional checks in the same `related-checks` family.
