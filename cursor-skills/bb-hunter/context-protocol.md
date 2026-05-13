# Shared Context Protocol (Multi-Agent)

Agents share state via a JSON file. Path: `output/<target>/.agent-context.json`.

## Schema

```json
{
  "target": "string",
  "scope": ["string"],
  "phase": "recon|attack|validate|report",
  "created_at": "ISO8601",
  "updated_at": "ISO8601",
  "recon": {
    "subdomains": ["string"],
    "live_urls": ["string"],
    "tech_stack": {"host": ["tech"]},
    "attack_surface": [
      {"path": "string", "score": 0-10, "reason": "string"}
    ]
  },
  "findings": [
    {
      "endpoint": "string",
      "param": "string",
      "class": "string",
      "status": "detection|possible|confirmed",
      "evidence": "string",
      "needs_validation": true
    }
  ],
  "validated": [
    {
      "title": "string",
      "severity": "string",
      "poc": "string",
      "evidence": "string",
      "chain": "string|null",
      "impact": "string"
    }
  ],
  "reports": [
    {"file": "string", "finding": "string", "severity": "string"}
  ],
  "messages": [
    {
      "from": "recon|attacking|validation|reporting|root",
      "to": "recon|attacking|validation|reporting|root",
      "type": "information|instruction|query",
      "content": "string",
      "timestamp": "ISO8601"
    }
  ]
}
```

## Read/Write Rules

1. **Read at start** — Every agent reads the full file before work.
2. **Merge, don't replace** — Append to arrays. Update only your section.
3. **Write at end** — Save before returning. Include `updated_at`.
4. **Atomic** — If file is locked or missing, create with target + phase.

## Agent Completion Report (Strix-aligned)

When a subagent finishes, it should return:

```
RESULT_SUMMARY: [1-2 sentence summary]
FINDINGS: [list of finding titles/descriptions]
RECOMMENDATIONS: [list of next steps or priorities]
SUCCESS: true|false
```

Root merges these into context and uses them when spawning the next agent.

## Handoff Format

When spawning an agent, include in the prompt:

```
CONTEXT_PATH: output/example.com/.agent-context.json
TARGET: example.com
PHASE: recon
INSTRUCTIONS: [from sub-agent skill]
```

Agent returns:
```
CONTEXT_UPDATED: true
SUMMARY: [what was done]
ADDED: [what was added to context]
```

## cursor-mem Integration

For cross-session persistence:
- `cursor-mem observe` for confirmed findings
- `cursor-mem search` for chain partners before validation
- `cursor-mem session-end` with summary when root agent finishes
