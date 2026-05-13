# cursor-mem: Persistent Memory Skill

Search, recall, and manage persistent session memory across Cursor conversations.

## When to use

- User asks to remember something, recall past work, or search session history
- Starting a new session and need prior context
- User asks "what did we do last time?" or "what do you know about X?"
- Saving findings, credentials, recon data for future sessions
- Compressing/summarizing a session before ending

## Tool location

```
<project>/.cursor/mem/cursor-mem
```

## Quick reference

### Start a session and get prior context
```bash
# Check what we already know
.cursor/mem/cursor-mem context bbrecon

# Start a new session (returns session ID — save it)
SID=$(.cursor/mem/cursor-mem session-start bbrecon)
echo "Session: $SID"
```

### Save observations during work
```bash
# Types: finding, vuln, recon, credential, config, decision, note
.cursor/mem/cursor-mem observe "$SID" finding "XSS in /api/search?q= parameter — reflected, no CSP"
.cursor/mem/cursor-mem observe "$SID" recon "Tech stack: Next.js 14, PostgreSQL, Redis, CloudFront"
.cursor/mem/cursor-mem observe "$SID" credential "Test account: user@test.com / TestPass123"
.cursor/mem/cursor-mem observe "$SID" decision "Focusing on API endpoints first — larger attack surface than web UI"
```

### Search memory
```bash
# Full-text search across all observations
.cursor/mem/cursor-mem search "XSS"
.cursor/mem/cursor-mem search "authentication" 20 finding

# Search summaries
.cursor/mem/cursor-mem search-summaries "recon"

# Get full observation by ID
.cursor/mem/cursor-mem get 1,5,12

# Timeline of recent work on a project
.cursor/mem/cursor-mem timeline bbrecon 30
```

### End session & persist context
```bash
# Summarize and end
.cursor/mem/cursor-mem session-end "$SID" "Completed recon on target.com: found 3 subdomains, mapped 47 endpoints, identified XSS in search param"

# Write a project-level summary (persists across session compaction)
.cursor/mem/cursor-mem summarize bbrecon "Target.com attack surface: Next.js app, 3 API versions, auth via JWT, file upload at /api/upload" project

# Inject context into Cursor rule for next session
.cursor/mem/cursor-mem inject bbrecon
```

### Maintenance
```bash
# Stats
.cursor/mem/cursor-mem stats

# Remove old observations (keeps findings/vulns)
.cursor/mem/cursor-mem compact bbrecon 7

# Export all observations as JSON
.cursor/mem/cursor-mem export bbrecon

# Import a past Cursor agent transcript
.cursor/mem/cursor-mem import-transcript path/to/transcript.jsonl bbrecon

# Delete specific observations
.cursor/mem/cursor-mem forget 3,7,15

# Nuclear option
.cursor/mem/cursor-mem wipe bbrecon
```

## Token economics

| Layer | Cost per item | What it contains |
|-------|--------------|------------------|
| Project summaries | ~50 tokens | High-level compressed knowledge |
| Session summaries | ~100 tokens | What happened in each session |
| Raw observations | ~50-500 tokens | Detailed findings, recon, notes |

Context injection uses progressive disclosure: cheapest first, stops at token budget.
Default budget: 2000 tokens. Set `CMEM_MAX_CONTEXT_TOKENS` to adjust.

## Privacy

- Wrap sensitive content in `<no-mem>` tags — agent must not store it
- Type `credential` observations can be selectively wiped with `forget`
- `wipe` removes all memory for a project
