Sigils are agents that review code to automatically find bugs and vulnerabilities..

There are many different kinds of sigils, some leverage [[checks]] while others build on top of static analyses using for example [[semgrep]]. 
### Summon

You'll most often kick off sigils when you [[summon]] grimoire. 

A swarm of sigils will sift through a codebase and apply all your learnings and findings to identify potential issues. Every issue will be triaged by your [[familiar]] to make sure you do not lose any time filtering false positives.
### Variants

You'll also sometimes encounter bugs that are likely to re-occur in the codebase that you're reviewing.

Once you've produced a finding the [[agents/scribe|scribe]] will automatically figure out if there are any opportunities to extend your [[personal grimoire]]. It will also identify whether it is possible and useful to do a [[variant analysis]] within your current review. If it finds that that is the case it will automatically perform a variant analysis and provide you with the results.

You can obviously always ask the scribe to produce a *sigil* to perform a variant analysis.
### Super Sigils

Sigils are single context agents. 

Each sigil only hunts down one bug, one potential vector. However, tools like slither are better ran once. So we have super sigils. A sigil which runs a tool like slither or semgrep with a set of detection modules loaded. The sigil then spawns a new sigil to validate each finding.
