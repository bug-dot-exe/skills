# Severity Policy

Use this policy during `valid_downgraded` decisions.

## Severity scale

- **Critical**: Direct loss of funds, complete access control bypass, infinite minting
- **Major/High**: Significant fund loss under specific conditions, privilege escalation, oracle manipulation
- **Medium**: Admin-only issues, centralization risks, DoS under edge cases, information leaks
- **Low**: Missing best practices, non-critical centralization, gas inefficiency
- **Informational**: Dead code, style issues, missing configurability
- **Gas**: Gas optimization opportunities with no security impact

## Downgrade rules

- Downgrade only when exploitability or impact is materially constrained by observed guards.
- Never downgrade without quoting concrete local evidence.
- Allowed downgrade step is one or more levels down:
  - Critical -> High -> Medium -> Low -> Informational

## Confidence status

- `high-confidence`: confidence >= 0.75
- `needs-manual-review`: confidence < 0.75

## Triage outcome semantics

- `false_positive`: remove finding from final set.
- `valid`: keep finding as-is.
- `valid_downgraded`: keep finding with reduced severity and explanation.
