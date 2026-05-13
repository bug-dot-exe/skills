---
name: solodit
description: Search Solodit for similar smart contract security findings. Use when reviewing vulnerabilities, comparing to known issues, or researching prior art from real audits.
---

# Solodit — Smart Contract Security Findings Search

You have access to Solodit's database of 20k+ smart contract security findings via MCP tools. Use them to find prior art, research vulnerability patterns, and compare against known issues from real audits.

## Available Tools

### `mcp__solodit__search_findings`
Primary search. Supports keywords, severity, firms, tags, language, protocol, time period, sorting, and advanced filters.

### `mcp__solodit__get_finding`
Get full details for a specific finding by Solodit URL or slug.

### `mcp__solodit__get_filter_options`
Discover valid filter values (firms, tags, categories, languages). Call this first if unsure what values to use.

## When to Use

- **Reviewing a vulnerability**: Search for similar findings to check if it's a known pattern
- **Auditing a protocol**: Search by protocol category, language, or tags relevant to the codebase
- **Researching a bug class**: Search by tags (e.g., "Reentrancy", "Oracle") to find real examples
- **Checking prior art**: Before reporting a finding, search for similar issues to reference
- **Studying an auditor**: Use `advanced_filters.user` to find a specific researcher's findings

## Usage Patterns

### Find similar issues
```
search_findings(keywords="oracle price manipulation", severity=["HIGH", "MEDIUM"], sort_by="Quality")
```

### Research by firm
```
search_findings(firms=["Sherlock"], severity=["HIGH"], reported="90")
```

### Explore a vulnerability tag
```
search_findings(tags=["Reentrancy", "Flash Loan"], severity=["HIGH"], sort_by="Quality")
```

### Protocol-specific research
```
search_findings(protocol="Uniswap", severity=["HIGH", "MEDIUM"])
```

### Language-specific search
```
search_findings(keywords="reentrancy", language="Solidity", sort_by="Quality")
```

### High-quality solo findings (likely novel)
```
search_findings(
  tags=["Oracle"],
  advanced_filters={ quality_score: 4, max_finders: 1 }
)
```

### Auditor research
```
search_findings(advanced_filters={ user: "0x52" }, severity=["HIGH"])
```

## Formatting Results — MANDATORY

You MUST follow this format exactly. Do NOT use tables. Do NOT omit links.

Each finding in the MCP response includes a `**Solodit:**` line with a URL. You MUST include this URL for every finding.

Format each finding as:

```
1. **[HIGH] Title**
   Firm (Protocol) · Quality: X/5 · Finders: N
   → https://solodit.cyfrin.io/issues/...

2. **[MEDIUM] Title**
   Firm (Protocol) · Quality: X/5 · Finders: N
   → https://solodit.cyfrin.io/issues/...
```

NEVER use a table format. NEVER omit the Solodit URL. The URL line starting with → is required for every finding.

For detailed analysis, use `get_finding` to fetch full content for the most relevant results.

## Tips

- Start broad, then narrow with filters
- Use `sort_by="Quality"` to surface the best-written findings first
- Use `sort_by="Rarity"` to find unusual/novel vulnerability patterns
- Combine `tags` with `severity` for targeted searches
- If no results, try broader keywords or remove restrictive filters
- Call `get_filter_options` if you're unsure about valid filter values
