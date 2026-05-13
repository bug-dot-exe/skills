# Strix Multi-Agent Architecture Analysis

Analysis of [Strix](https://github.com/usestrix/strix) multi-agent design and how it maps to bb-hunter. Source: Strix source code (agents, tools/agents_graph, skills/coordination).

---

## 1. Strix Agent Graph

Strix maintains an **in-memory graph** of all agents:

```python
_agent_graph = {
    "nodes": {},   # agent_id -> {id, name, task, status, parent_id, result, ...}
    "edges": [],   # [{from, to, type: "delegation"|"message"}]
}
_root_agent_id: str | None
_agent_messages: dict[str, list]  # agent_id -> inbox
_agent_instances: dict[str, BaseAgent]
_agent_states: dict[str, AgentState]
```

- **Nodes** = agents. Each has `parent_id` for hierarchy.
- **Edges** = delegation (parent→child) or message (sender→receiver).
- **Root agent** = first agent with `parent_id is None`.

---

## 2. Agent State (Per-Agent)

`AgentState` (Pydantic) holds:

| Field | Purpose |
|-------|---------|
| `agent_id`, `agent_name` | Identity |
| `parent_id` | Hierarchy (None = root) |
| `task` | Current task string |
| `messages` | Conversation history (LLM context) |
| `context` | Arbitrary key-value context |
| `completed`, `final_result` | Completion state |
| `waiting_for_input` | Paused, waiting for messages |
| `sandbox_id`, `sandbox_token` | Runtime isolation |

Agents **do not share state**. They share:
- `/workspace` filesystem
- Proxy (Caido) history
- Message inbox (`_agent_messages`)

---

## 3. Subagent Spawning

**Tool:** `create_agent(task, name, inherit_context=True, skills=None)`

1. Creates `AgentState` with `parent_id = caller.agent_id`
2. Optionally inherits parent's **conversation history** (for background only)
3. Passes up to **5 skills** (comma-separated) — injected into subagent's system prompt
4. Runs subagent in a **thread** (`threading.Thread`), same process
5. Subagent gets task XML stressing: "You are NOT your parent. Focus on your delegated task. Use agent_finish when done."

**Key:** Subagents run **asynchronously** in threads. Parent continues its loop; subagent runs in parallel.

---

## 4. Inter-Agent Communication

### Message Passing

**Tool:** `send_message_to_agent(target_agent_id, message, message_type, priority)`

- Appends to `_agent_messages[target_agent_id]`
- Adds edge `{from, to, type: "message"}`
- Target agent **polls** on each iteration via `_check_agent_messages(state)`

### Message Delivery

In `base_agent.py` agent loop, before each iteration:

```python
def _check_agent_messages(self, state):
    messages = _agent_messages.get(agent_id, [])
    for msg in messages:
        if not msg.get("read"):
            # If agent is waiting_for_input -> resume_from_waiting()
            state.add_message("user", formatted_message)
            msg["read"] = True
```

- **Waiting agents** resume when they receive a message (from user or another agent)
- Message content is injected as a user message with sender info

### Wait for Message

**Tool:** `wait_for_message(reason)`

- Sets `state.enter_waiting_state()`
- Agent pauses until: message received, user input, or timeout
- Used when root needs to coordinate (e.g. wait for subagent report)

---

## 5. Subagent Completion

**Tool:** `agent_finish(result_summary, findings, success, report_to_parent, final_recommendations)`

- Only subagents (parent_id not None) can call this
- Updates node status to `finished` or `failed`
- If `report_to_parent`: **sends message to parent** with:
  - Agent name, id, task
  - Success/failed
  - Result summary
  - Findings (list)
  - Recommendations (list)

Parent receives this as a message and processes it on next iteration.

---

## 6. Root Agent Skill (Coordination)

`strix/skills/coordination/root_agent.md` defines:

- **Role:** Decompose, spawn, aggregate, manage dependencies
- **Scope decomposition:** Attack surfaces, boundaries, approach, prioritization
- **Agent architecture:** Reconnaissance, Vulnerability Assessment, Exploitation/Validation, Reporting
- **Coordination principles:**
  - **Task independence** — minimal dependencies, parallel execution
  - **Clear objectives** — specific, measurable goals
  - **Avoid duplication** — check existing agents before creating
  - **Hierarchical delegation** — discovery → validation → reporting → fix
  - **Resource efficiency** — no duplicate coverage, terminate when done, batched updates

---

## 7. Skill Injection

When creating an agent:

```python
create_agent(task="...", name="...", skills="idor,sql_injection,xss")
```

- Up to 5 skills, comma-separated
- Validated against `get_all_skill_names()`
- Injected into subagent's system prompt via `LLMConfig(skills=skill_list)`
- Skills are Markdown files with YAML frontmatter (`name`, `description`)

---

## 8. Agent Loop (Simplified)

```
while True:
    if force_stop: ...
    _check_agent_messages(state)  # Poll inbox, resume if waiting
    if waiting_for_input: _wait_for_input(); continue
    if should_stop(): return
    increment_iteration()
    response = llm.generate(conversation_history)
    actions = response.tool_invocations
    if actions: process_tool_invocations(actions)
        # May call create_agent, send_message, agent_finish, wait_for_message
```

---

## 9. Strix vs bb-hunter Multi-Agent

| Aspect | Strix | bb-hunter Multi-Agent |
|--------|-------|------------------------|
| **Runtime** | Single process, threads | Separate processes (mcp_task) |
| **State** | In-memory graph + AgentState | File-based `.agent-context.json` |
| **Spawning** | `create_agent` tool (LLM calls it) | Root agent calls `mcp_task` |
| **Communication** | `send_message_to_agent`, `_agent_messages` | Context file + mcp_task result |
| **Skills** | Up to 5 per agent, injected by name | Sub-agent skills in prompt |
| **Completion** | `agent_finish` → message to parent | Subagent returns; root merges result |
| **Parallelism** | Threads, shared /workspace | Parallel mcp_task calls |
| **Wait** | `wait_for_message` (blocking) | Root waits for mcp_task to return |

**bb-hunter advantages:**
- Works in Cursor without Strix runtime
- File-based context survives process restarts
- Simpler: no graph, no message polling

**Strix advantages:**
- True async: parent can do work while subagents run
- Live message passing (no file round-trip)
- Built-in graph visualization, tracer
- Sandbox per agent (when enabled)

---

## 10. Patterns Applied to bb-hunter

1. **Coordination principles** — Task independence, clear objectives, avoid duplication, hierarchical delegation, resource efficiency. Applied in bb-hunter §12.

2. **Skill selection** — When spawning attacking agent, pass up to 5 relevant strix-* skills (e.g. `idor,xss,ssrf`) in the prompt so the subagent loads them.

3. **Message-like handoffs** — `messages` array in context schema for agent-to-agent notes. Root injects when spawning next agent.

4. **Completion report format** — Subagent returns `RESULT_SUMMARY`, `FINDINGS`, `RECOMMENDATIONS`, `SUCCESS` (Strix `agent_finish`-aligned).

5. **Use case** — bb-hunter multi-agent for Cursor-based coordinated assessment with bbrecon/Caido integration. No Strix CLI required.
