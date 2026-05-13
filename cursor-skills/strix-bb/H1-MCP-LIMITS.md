# H1 Brain MCP — What's Available

## Available via MCP

| Tool | Returns |
|------|---------|
| `hack(handle)` | Scope (in-scope assets), attack vectors, your past findings, briefing |
| `search_scopes(program=handle)` | Full asset list with bounty eligibility |
| `fetch_program_scopes(handle)` | Syncs scopes to local DB |
| `search_programs` | Program handles and names |
| `search_disclosed_reports` | Public disclosed reports |
| `get_disclosed_report(id)` | Full report details |
| `search_reports` | Your rewarded reports |

## NOT Available via MCP

| Data | Source | Workaround |
|------|--------|------------|
| **Full program policy** | H1 program page | User fetches from https://hackerone.com/{handle}?view_policy=true and pastes into instructions |
| **Test credentials** | H1 policy/credentials section | User adds from program page when program provides them |
| **Out-of-scope list** | Often in policy | Include when user pastes policy |

## HackerOne API (if you have token)

The HackerOne API `program` object includes `policy` (string). H1 Brain may use a different API path. If you have direct H1 API access, you could fetch policy via:

```
GET https://api.hackerone.com/v1/hackers/programs/{handle}
```

Response includes `attributes.policy`. Requires HackerOne API token.
