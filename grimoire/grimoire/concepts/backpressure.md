Only allow autonomy with back-pressure methods available. 

Example: Find me all locations where X happens
Back pressure: A semgrep module that actually finds all locations where X happens

You should never, ever, ask a completeness question to an agent that can not be backed up with a back-pressure skill. 

Example: Are all versions of this datastructure parsed correctly

This query lacks back pressure. The agent can not produce an artifact that ensures it actually checks all locations 
where a datastructure is parsed, or that it is parsed correctly. 

Improvement: Find all usages of this datastructure and check whether the version number in the parse function matches 
that of the usage function. 

This is better because the agent can distill this into a static analysis module. 

I've mentioned semgrep and static analysis twice. They're key unlockers in improving the reliability of agent co-auditors.

### Grimoire 

There should be a semgrep, slither and codeql skill. 

There should also be a back-pressure skill. This skill would mostly be about injecting a hook that ensures the agent applies 
back-pressure whenever possible. 

I think it might also be worthwhile to introduce a back-pressure agent that tries to do a soft "fact check" on queries that 
can not be backpressured. As it's simply not always practical to try to achieve back-pressure through static analysis.

Proof of concepts for findings are a great example of a task that naturally induces back-pressure.

