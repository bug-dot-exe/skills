Gnomes are are worker agents that run within an isolated context.

Your agents will leverage gnome's for execution of clearly defined tasks. Gnomes will be provided with context (which files to read) and a plan that they need to execute. Gnomes are smart but stick to the plan. 
 
## Example Uses

The [[scribe]] might leverage gnomes for building a [[sigil]] (analysis module). This way the scribe only needs to load the [[skills/scribe|scribe]] skill, while the skills for the specific sigil type only needs to be loaded by the gnome. Of course this means that the scribe skill should provide sufficient context to know what type of sigil (analysis mode) is best for a given vulnerability class.

Gnomes are also useful for building a [[proof of concept]]. This allows us to keep the planning and orchestration context clean from implementation details.


## Notes
* gnomes use a good tasking model like sonnet
* gnommes report back implementation status when done `in progress| completed | done`, with a comprehensive summary of changes, decisions and potential blockers.