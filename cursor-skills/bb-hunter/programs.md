# Program Strategy Reference

Program selection and platform strategy from bugbounty.info.

## Expected Value

```
EV/hr = (avg_bounty × probability_unique) / hours_per_finding
```

Track this per program. The highest bounty table ≠ highest EV.

## Platform Comparison

| Platform | Triage | Reputation | Strengths |
|----------|--------|------------|-----------|
| HackerOne | Signal-based | Signal score + reputation | Largest program count, private invites via signal |
| Bugcrowd | VRT-based | Kudos + priority queue | Structured severity via VRT, P1 priority |
| Intigriti | Manual | Researcher tools | EU-heavy programs, smaller pool |
| Direct | Varies | N/A | Least competition, less legal protection |

## Program Selection Criteria

### Green Flags
- Large wildcard scope (`*.target.com`)
- Recently launched (first 48 hours = gold)
- Active response team (fast triage times)
- Reasonable bounty table for the company size
- Clear, detailed scope document

### Red Flags
- Tiny scope (single domain, specific paths only)
- Slow triage (30+ day average response)
- History of closing valid bugs as informational
- "We reserve the right to not pay" language
- No safe harbor clause

## New Program Strategy (First Blood)

The first 48 hours on a new program are the highest-value window:

1. **Hour 0-2:** Rapid recon — subdomains, ports, tech stack
2. **Hour 2-4:** Low-hanging fruit sweep — nuclei defaults, common misconfigs
3. **Hour 4-8:** Deep dive on most interesting asset (unusual tech, large surface)
4. **Hour 8+:** Methodical testing by vuln class

Don't spend the first 48 hours on recon perfection. Speed matters. Submit findings as you go.

## Competition Assessment

- Check program stats: number of researchers, resolved reports, avg bounty
- High resolved count + high researcher count = crowded
- Sweet spot: moderate resolved count + good payouts + <100 active researchers
- Check disclosed reports: if lots of P3/P4 disclosed, the P1s may be untouched

## Reading Scope Documents

Scope docs are contracts. Key things to check:
- **In-scope assets** — exact domains, wildcards, mobile apps, APIs
- **Out-of-scope** — what's explicitly excluded (e.g., social engineering, DoS)
- **Testing restrictions** — rate limits, no automated scanning, no data exfiltration
- **Disclosure policy** — can you disclose? After how long?
- **Safe harbor** — legal protection for good-faith testing

Ambiguous scope → ask the program before testing. A valid critical on an ambiguous asset can become an OOS rejection.

## Business Side

- Triage teams are overwhelmed — make reports easy to assess
- Programs have internal politics — your report helps the security team justify spend
- Bounty amounts have discretionary ranges — report quality affects payout
- Researchers they love: clear reports, reasonable severity, professional tone, willing to retest
- These researchers get triaged faster + benefit of the doubt on borderline calls + private invites

## Source
https://bugbounty.info/Programs/
