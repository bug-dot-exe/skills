<p align="center">
  <img src="grimoire_logo.png" alt="Grimoire" width="300" />
</p>

<h1 align="center">Grimoire</h1>

<p align="center">
  <strong>A security research toolkit that learns.</strong><br/>
    Grimoire takes the raw agent experience and tunes it for security research. Clean, readable and reproducible PoCs, 
    automatic static analysis module distillation, and more. 
</p>

<p align="center">
  <a href="#installation"><img src="https://img.shields.io/badge/Claude_Code-Plugin-8B5CF6?style=flat-square" alt="Claude Code Plugin" /></a>
  <img src="https://img.shields.io/badge/version-0.1.0-blue?style=flat-square" alt="Version 0.1.0" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License MIT" />
</p>

---

## Why Grimoire?

There are many audit agents and vulnerability discovery skills. 

These are great, but the real power of agents is in amplifying operator skill. Grimoire embraces that philosophy and implements 
several skills that make your agent a better co-auditor. 

Some skills (such as the cartography) skill come with a small workflow adaption. However, most features such as the *librarian* 
are designed to just *work* within whatever workflow you follow. 

> The *librarian* is an agent that looks for documentation and references (e.g. previous audit findings, docs, blog posts, etc.) . It is very focussed on providing only information backed up by reference and keeps the main context clear from large mcp descriptions. 
> 
> The *cartography* skill provides instructions to claude on how it can document a mapping from features / flows to code locations. This allows you to say `hey load context on the authentication flow`, claude will review the file and very quickly load the relevant context.

### Philosophy

Grimoire is built on a few hard convictions from real-world security research:

- **Leverage over automation.** Grimoire provides skills that amplify operator skill, though some automation is present this is just to give you space for more research.
- **Ergonomics** Agents are already quite useful, Grimoire provides skills (e.g. cartography) that fine tune agent behaviour to be more adjusted to auditing workflows.
- **Not getting in your way** Grimoire takes the base agent experience and makes it more useful for auditing wihout getting in your way.

### Alpha 

Grimoire is still at a very early stage and under continuous development expect there to be major changes.

## Getting Started

Grimore is set up as a claude plugin that's easy to set up. 

At first you should just use the summon command and get going, grimoire will automatically hop in once you ask 
claude to write a finding, proof of concept, or a similar task.

Once you're ready to dive deep we would suggest having a look at the scribe and cartography skills. 

* **scribe** - automatically analyzes your findings and build detection modules for them (which are automatically ran in your next audit)
* **cartography** - super useful for large codebases. The cartography skill has claude memorize where to find the context related to different flows/ features. That makes it super easy to load different contexts.

### Installation

```bash
git clone https://github.com/JoranHonig/grimoire.git
claude --plugin-dir /path/to/grimoire
```

Skills and agents auto-discover via the plugin manifest. Some features require API keys:

| Service | Key | Purpose |
|---------|-----|---------|
| [Solodit](https://solodit.xyz) | `SOLODIT_API_KEY` | Audit findings search via claudit |
| [Context7](https://context7.com/dashboard) | `CONTEXT7_API_KEY` | Library documentation lookups |

Set these in your Claude Code settings (`~/.claude/settings.json`):

```json
{
  "env": {
    "SOLODIT_API_KEY": "your-key-here",
    "CONTEXT7_API_KEY": "your-key-here"
  }
}
```

Both are optional — the librarian will fall back to web search if they are not set. You can also export them as regular shell environment variables (e.g. in `~/.zshrc`) instead of using `settings.json`.

### Summon

Start any engagement with `summon`:

```
You:      "Summon grimoire on this codebase"
Grimoire: → Analyzes project structure, architecture, integrations
          → Identifies crown jewels and attack surface
          → Writes GRIMOIRE.md contextual map
          → Spawns detection checks across the codebase
          → Surfaces initial findings for triage
```

Then work naturally — Grimoire's skills trigger from context:

```
"Map the authentication flow"              → cartography
"Write a PoC for the reentrancy I found"   → write-poc
"Document this as a finding"               → finding-draft
"Review my findings before submission"     → finding-review
"Check for duplicates"                     → finding-dedup
```

Learn more about grimoire by reading [docs](grimoire/concepts/what%20is%20grimoire.md)

## Project Structure

```
grimoire/                     # Human-written specs (read-only, source of truth)
├── agents/                   # Agent specifications
├── skills/                   # Skill specifications
├── concepts/                 # Design philosophy
├── flows/                    # Multi-step workflow specs
└── ideas/                    # Roadmap and research notes
skills/                       # Implemented skills (where development happens)
agents/                       # Implemented agents
```

Specs and implementation are strictly separated. The `grimoire/` directory is the source of truth — never modified during development. Skills in `skills/` implement those specs.

The `grimoire/` directory is also written as a form of documentation, feel free to browse around if you want to learn more.
