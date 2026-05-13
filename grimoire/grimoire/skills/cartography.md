Context is incredibly important, and loading the right information into context can significantly improve output quality.

I often find myself asking an agent to build context before being able to dive into the task/ question that is really at hand. Though some skills already exists to build context around functions and classes, they still require a relatively verbose prompt.

As an example:
`study file x, y, z and the flow of activity A to where it results in effect B`.

It gets worse when I revisit the same flow a couple of days later and have to re-do the exact same verbose prompt, even though I really want to focus on the particular question I had in mind.

To solve this grimoire provides a flow context skill. It both instructs an agent on how to build context and makes it incredibly easy to revisit previously established flows.

## First Flow
When grimoire is [[summon]]ed it initialises a directory structure and performs an initial analysis of the core flows in the program. 

This is a useful starting point but not exhaustive or complete. Once you inevitably ask your agent to build context on a flow that it does not know about it will need to do some investigation. 

You can chose to seed the investigation by providing a prompt similar to the one in the introduction of this article: e.g. `study file x, y, z and trace how authentication is handled`. You can also opt to have the agent attempt to figure things out on it's own. In that case grimoire will spawn many subagents to look for files with logic related to the flow that you've described.

Once the agent(s) are done exploring a file is created in the `grimoire/cartography` directory. 

The `cartography` directory contains the files which hold documentation on the discovered flows.

## Refine Flow
Agents can miss things on their first attempt, this is fine.

Similar to how `GRIMOIRE.md` is editable and extensible, cartography files do not need to be static. During operation it might become apparent that essential points of reference are missing from a cartography file. In such cases the agent should update the cartography files.

You can also prompt the agent to review a given flow. A supporting skill `review-cartography` allows agents to review cartography files. This skill includes instructions on how many sub-agents might be used to review the existing context and explore the codebase in order to improve and extend the flow.

The review skill also cross references flows adding links for flows that relate to each-other, this way an agent can optionally decide to load context relating to other flows when it is relevant for your question.

## Garbage Collection
It is possible that the `cartography` directory get's a bit out of hand.

To solve this there is a `gc-cartography` skill. This skill has your agent review the `cartography` directory and identify duplication. It will also identify opportunities for merging cartography files. 

Files incorporate conditional directions and sections to prevent context pollution when a large cartography file is used. A cartography file on authentication flow might have a section on oauth and a section on passkeys. The agent should determine based on context whether it is necessary to load the directions in each section.

## Cartography File Structure

Each file in the `cartography` directory has a frontmatter header containing metadata. 

The use of this frontmatter is very similar to how skills are used. Each frontmatter contains metadata on the flow described in the flow (name and description). The flow context skill comes with a script to automatically index and browse these files.

The file itself has one mayor goal: Document which parts of the codebase are relevant w.r.t. the flow. 

Importantly, the files do not hold the actual context themselves. The goal is merely to provide the information necessary to enable agents to build context on their own. 

> [!info]
> There is an extension opportunity where cartography files can also be used to hold notes and conclusions that might be relevant for future runs. However, we'll leave that as future work for now.

## Flow Indexing

The core goal of the `cartography` skill is to enable ergonomic context (re-) building.

It's okay if there is some manual effort involved in establishing a context for the first time, but we need to avoid repeating such work because it's expensive.


## Specification

### Swarm Indexing
The first time a user uses the cartography skill to build a map (cartography file) they provide a high level description of the flow / topic that the map is for, they generally also provide a few pointers to files that should be reviewed for pointers.

The agent should take multiple approaches to build out the map:
1. *control-flow* - study the user provided files and follow the callgraph to find potentially relevant code
2. *swarm* - study the description of the user provided flow, asking clarifying questions if necessary, and use 100 sub-agents to explore the codebase for code related to the map's topic.



